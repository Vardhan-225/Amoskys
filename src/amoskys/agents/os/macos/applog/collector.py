"""macOS Application Log Collector — gathers application logs from Unified Logging.

Data sources:
    1. Unified Logging — process-filtered logs for web servers (httpd, nginx),
       databases (postgres, mysqld), and application frameworks (python, node,
       ruby, java)

Returns shared_data dict with:
    app_logs: List[AppLogEntry] — recent log entries from target processes
    log_count: int — total entries collected
    processes_seen: Set[str] — unique process names observed
    collection_time_ms: float — collection duration
"""

from __future__ import annotations

import logging
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class AppLogEntry:
    """Single application log entry captured from Unified Logging."""

    timestamp: float  # Unix epoch seconds
    process: str  # Process name (httpd, nginx, postgres, etc.)
    pid: int  # Process ID
    message: str  # Log message content
    log_level: str = "Default"  # Log level (Default, Info, Debug, Error, Fault)
    subsystem: str = ""  # Subsystem identifier


class MacOSAppLogCollector:
    """Collects application log data from macOS Unified Logging.

    Returns shared_data dict for ProbeContext with keys:
        app_logs: List[AppLogEntry]
        log_count: int
        processes_seen: Set[str]
        collection_time_ms: float
    """

    # Unified Logging predicate for application processes
    _LOG_PREDICATE = (
        'process IN {"httpd","nginx","postgres","mysqld","python","node","ruby","java"}'
    )
    _LOG_WINDOW_SECONDS = 30  # Look back 30s for recent entries
    _LOG_TIMEOUT = 15  # Subprocess timeout

    # Regex pattern for parsing compact log lines
    # Format: 2024-01-15 10:30:45.123456-0800  0x1a2b  Default  0x0  123  0  httpd: (subsystem) message
    _LOG_LINE_PATTERN = re.compile(
        r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)"  # timestamp
        r"\S*"  # timezone offset
        r"\s+\S+"  # thread id
        r"\s+(\w+)"  # log level
        r"\s+\S+"  # activity
        r"\s+(\d+)"  # pid
        r"\s+\d+"  # TTL
        r"\s+(\w+)"  # process name
        r":\s+"  # separator
        r"(?:\(([^)]*)\)\s+)?"  # optional subsystem
        r"(.*)"  # message
    )

    # Fallback simpler pattern for lines that don't match the full format
    _SIMPLE_PATTERN = re.compile(
        r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)"  # timestamp
        r".*?\s+"
        r"(\w+)"  # process
        r"\[(\d+)]"  # pid in brackets
        r"[:\s]+"
        r"(.*)"  # message
    )

    _TARGET_PROCESSES = frozenset(
        {
            "httpd",
            "nginx",
            "postgres",
            "mysqld",
            "python",
            "node",
            "ruby",
            "java",
        }
    )

    def __init__(self, device_id: str = "", log_window: int = 30) -> None:
        self.device_id = device_id or _get_hostname()
        self._log_window = log_window

    def collect(self) -> Dict[str, Any]:
        """Collect application logs from Unified Logging.

        Returns dict for ProbeContext.shared_data.
        """
        start = time.monotonic()

        app_logs = self._collect_app_logs()
        processes_seen = {entry.process for entry in app_logs}

        elapsed_ms = (time.monotonic() - start) * 1000

        return {
            "app_logs": app_logs,
            "log_count": len(app_logs),
            "processes_seen": processes_seen,
            "collection_time_ms": round(elapsed_ms, 2),
        }

    def _collect_app_logs(self) -> List[AppLogEntry]:
        """Parse application logs via Unified Logging."""
        entries: List[AppLogEntry] = []

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
                return entries

            for line in result.stdout.strip().split("\n"):
                entry = self._parse_log_line(line)
                if entry:
                    entries.append(entry)

        except subprocess.TimeoutExpired:
            logger.warning(
                "Application log query timed out after %ds",
                self._LOG_TIMEOUT,
            )
        except FileNotFoundError:
            logger.error("'log' command not found — cannot collect application logs")
        except Exception as e:
            logger.error("Application log collection failed: %s", e)

        logger.debug("Collected %d application log entries", len(entries))
        return entries

    def _parse_log_line(self, line: str) -> Optional[AppLogEntry]:
        """Parse a single log line into AppLogEntry."""
        if not line or line.startswith("---") or line.startswith("Filtering"):
            return None

        # Try full format pattern
        match = self._LOG_LINE_PATTERN.search(line)
        if match:
            process = match.group(4).lower()
            if process not in self._TARGET_PROCESSES:
                return None

            return AppLogEntry(
                timestamp=_parse_timestamp(match.group(1)) or time.time(),
                log_level=match.group(2),
                pid=int(match.group(3)),
                process=process,
                subsystem=match.group(5) or "",
                message=match.group(6).strip(),
            )

        # Try simpler fallback pattern
        match = self._SIMPLE_PATTERN.search(line)
        if match:
            process = match.group(2).lower()
            if process not in self._TARGET_PROCESSES:
                return None

            return AppLogEntry(
                timestamp=_parse_timestamp(match.group(1)) or time.time(),
                process=process,
                pid=int(match.group(3)),
                message=match.group(4).strip(),
            )

        return None

    def get_capabilities(self) -> Dict[str, str]:
        """Report collector capabilities."""
        caps = {}

        # Check Unified Logging access
        try:
            result = subprocess.run(
                [
                    "log",
                    "show",
                    "--predicate",
                    self._LOG_PREDICATE,
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


def _parse_timestamp(ts_str: str) -> Optional[float]:
    """Parse a timestamp string into Unix epoch seconds.

    Expected format: '2024-01-15 10:30:45.123456'
    Returns ``None`` when parsing fails so callers can flag the
    event rather than silently fabricating a timestamp.
    """
    try:
        from datetime import datetime

        # Handle microsecond precision
        dt = datetime.strptime(ts_str[:26], "%Y-%m-%d %H:%M:%S.%f")
        return dt.timestamp()
    except (ValueError, IndexError):
        logger.warning("applog: unparseable timestamp %r", ts_str)
        return None
