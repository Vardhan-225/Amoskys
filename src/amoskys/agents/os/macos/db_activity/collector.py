"""macOS Database Activity Collector — gathers database process info and logs.

Data sources:
    1. psutil — detect local database processes (postgres, mysqld, mongod, redis-server)
    2. Unified Logging — query database process messages

Returns shared_data dict with:
    db_processes: List[DBProcess] — detected database processes
    db_logs: List[DBLogEntry] — recent database log entries
    db_count: int — total database processes detected
    log_count: int — total log entries collected
    collection_time_ms: float — collection duration
"""

from __future__ import annotations

import logging
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class DBProcess:
    """A detected local database process."""

    pid: int  # Process ID
    name: str  # Process name (e.g., postgres, mysqld)
    port: int  # Listening port
    user: str  # OS user running the process
    db_type: str  # Database type (postgresql, mysql, mongodb, redis)
    status: str  # Process status (running, sleeping, etc.)


@dataclass
class DBLogEntry:
    """A single database log entry from Unified Logging."""

    timestamp: float  # Unix epoch seconds
    db_type: str  # Database type that generated the log
    message: str  # Log message content
    log_level: str  # Log level (INFO, WARNING, ERROR, etc.)
    user: str = ""  # Database user (if available)
    database: str = ""  # Target database name (if available)
    query: str = ""  # SQL/command query (if available)


# Mapping from process name to database type
_PROCESS_DB_MAP = {
    "postgres": "postgresql",
    "postmaster": "postgresql",
    "mysqld": "mysql",
    "mariadbd": "mysql",
    "mongod": "mongodb",
    "mongos": "mongodb",
    "redis-server": "redis",
    "redis-sentinel": "redis",
}

# Default ports for database types
_DEFAULT_PORTS = {
    "postgresql": 5432,
    "mysql": 3306,
    "mongodb": 27017,
    "redis": 6379,
}


class MacOSDBActivityCollector:
    """Collects database process data and logs from macOS.

    Returns shared_data dict for ProbeContext with keys:
        db_processes: List[DBProcess]
        db_logs: List[DBLogEntry]
        db_count: int
        log_count: int
        collection_time_ms: float
    """

    # Unified Logging predicate for database processes
    _LOG_PREDICATE = (
        '(process == "postgres" OR process == "mysqld" OR '
        'process == "mongod" OR process == "redis-server") AND '
        '(eventMessage CONTAINS "query" OR eventMessage CONTAINS "connection" OR '
        'eventMessage CONTAINS "authentication" OR eventMessage CONTAINS "error")'
    )
    _LOG_WINDOW_SECONDS = 30  # Look back 30s for recent logs
    _LOG_TIMEOUT = 15  # Subprocess timeout

    # Regex patterns for parsing database log lines
    _LOG_LINE_PATTERN = re.compile(
        r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)"  # timestamp
        r"\s+\S+"  # thread/host
        r"\s+(\w+)"  # process name
        r"\[(\d+)]"  # PID
        r"\s+(?:\<(\w+)\>)?"  # log level
        r"\s*(.*)"  # message
    )
    _PG_QUERY_PATTERN = re.compile(
        r"(?:statement|execute|query):\s*(.*)",
        re.IGNORECASE,
    )
    _MYSQL_QUERY_PATTERN = re.compile(
        r"(?:Query|Execute)\s+(.*)",
        re.IGNORECASE,
    )
    _PG_USER_PATTERN = re.compile(
        r"(?:user=|connection authorized:\s*user=)(\w+)",
        re.IGNORECASE,
    )
    _PG_DB_PATTERN = re.compile(
        r"(?:database=|db=)(\w+)",
        re.IGNORECASE,
    )

    def __init__(self, device_id: str = "", log_window: int = 30) -> None:
        self.device_id = device_id or _get_hostname()
        self._log_window = log_window

    def collect(self) -> Dict[str, Any]:
        """Collect database processes and logs.

        Returns dict for ProbeContext.shared_data.
        """
        start = time.monotonic()

        db_processes = self._collect_db_processes()
        db_logs = self._collect_db_logs()

        elapsed_ms = (time.monotonic() - start) * 1000

        return {
            "db_processes": db_processes,
            "db_logs": db_logs,
            "db_count": len(db_processes),
            "log_count": len(db_logs),
            "collection_time_ms": round(elapsed_ms, 2),
        }

    def _collect_db_processes(self) -> List[DBProcess]:
        """Detect running database processes via psutil."""
        processes: List[DBProcess] = []

        try:
            import psutil
        except ImportError:
            logger.warning("psutil not available — cannot detect database processes")
            return processes

        try:
            for proc in psutil.process_iter(["pid", "name", "username", "status"]):
                try:
                    pinfo = proc.info
                    proc_name = pinfo.get("name", "").lower()

                    db_type = _PROCESS_DB_MAP.get(proc_name)
                    if not db_type:
                        continue

                    # Attempt to find listening port
                    port = _DEFAULT_PORTS.get(db_type, 0)
                    try:
                        connections = proc.net_connections(kind="inet")
                        for conn in connections:
                            if conn.status == "LISTEN" and conn.laddr:
                                port = conn.laddr.port
                                break
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass

                    processes.append(
                        DBProcess(
                            pid=pinfo.get("pid", 0),
                            name=proc_name,
                            port=port,
                            user=pinfo.get("username", "unknown"),
                            db_type=db_type,
                            status=pinfo.get("status", "unknown"),
                        )
                    )

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        except Exception as e:
            logger.error("Database process detection failed: %s", e)

        logger.debug("Detected %d database processes", len(processes))
        return processes

    def _collect_db_logs(self) -> List[DBLogEntry]:
        """Parse database process logs via Unified Logging."""
        logs: List[DBLogEntry] = []

        try:
            result = subprocess.run(
                [
                    "log",
                    "show",
                    "--predicate",
                    self._LOG_PREDICATE,
                    "--last",
                    f"{self._log_window}s",
                    "--style",
                    "compact",
                    "--info",
                ],
                capture_output=True,
                text=True,
                timeout=self._LOG_TIMEOUT,
            )

            if result.returncode != 0:
                logger.warning(
                    "log show returned %d: %s",
                    result.returncode,
                    result.stderr[:200],
                )
                return logs

            for line in result.stdout.strip().split("\n"):
                entry = self._parse_log_line(line)
                if entry:
                    logs.append(entry)

        except subprocess.TimeoutExpired:
            logger.warning(
                "Database log query timed out after %ds",
                self._LOG_TIMEOUT,
            )
        except FileNotFoundError:
            logger.error("'log' command not found — cannot collect database logs")
        except Exception as e:
            logger.error("Database log collection failed: %s", e)

        logger.debug("Collected %d database log entries", len(logs))
        return logs

    def _parse_log_line(self, line: str) -> Optional[DBLogEntry]:
        """Parse a single database process log line into DBLogEntry."""
        if not line or line.startswith("---") or line.startswith("Filtering"):
            return None

        match = self._LOG_LINE_PATTERN.search(line)
        if not match:
            # Fallback: try to extract any recognizable database content
            return self._parse_fallback(line)

        proc_name = match.group(2).lower()
        log_level = match.group(4) or "INFO"
        message = match.group(5).strip()

        db_type = _PROCESS_DB_MAP.get(proc_name, "unknown")

        # Extract query if present
        query = ""
        query_match = self._PG_QUERY_PATTERN.search(message)
        if not query_match:
            query_match = self._MYSQL_QUERY_PATTERN.search(message)
        if query_match:
            query = query_match.group(1).strip()

        # Extract user if present
        user = ""
        user_match = self._PG_USER_PATTERN.search(message)
        if user_match:
            user = user_match.group(1)

        # Extract database name if present
        database = ""
        db_match = self._PG_DB_PATTERN.search(message)
        if db_match:
            database = db_match.group(1)

        return DBLogEntry(
            timestamp=time.time(),
            db_type=db_type,
            message=message,
            log_level=log_level.upper(),
            user=user,
            database=database,
            query=query,
        )

    def _parse_fallback(self, line: str) -> Optional[DBLogEntry]:
        """Fallback parser for log lines that don't match the primary pattern."""
        line_lower = line.lower()

        # Check if it contains any database process name
        db_type = "unknown"
        for proc_name, dtype in _PROCESS_DB_MAP.items():
            if proc_name in line_lower:
                db_type = dtype
                break

        if db_type == "unknown":
            return None

        return DBLogEntry(
            timestamp=time.time(),
            db_type=db_type,
            message=line.strip(),
            log_level="INFO",
        )

    def get_capabilities(self) -> Dict[str, str]:
        """Report collector capabilities."""
        caps = {}

        # Check psutil
        try:
            import psutil

            caps["psutil"] = "REAL"
        except ImportError:
            caps["psutil"] = "BLIND"

        # Check Unified Logging
        try:
            result = subprocess.run(
                [
                    "log",
                    "show",
                    "--predicate",
                    'process == "postgres"',
                    "--last",
                    "1s",
                    "--style",
                    "compact",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            caps["unified_logging"] = "REAL" if result.returncode == 0 else "DEGRADED"
        except Exception:
            caps["unified_logging"] = "BLIND"

        return caps


def _get_hostname() -> str:
    import socket

    return socket.gethostname()
