#!/usr/bin/env python3
"""AMOSKYS Database Activity Agent - Micro-Probe Architecture.

This is the database activity monitoring agent using the "swarm of eyes" pattern.
8 micro-probes each watch one specific database threat vector.

Probes:
    1. PrivilegeEscalationQueryProbe - GRANT/ALTER USER/CREATE ROLE
    2. BulkDataExtractionProbe - SELECT * without WHERE, dumps
    3. SchemaEnumerationProbe - information_schema enumeration
    4. StoredProcAbuseProbe - xp_cmdshell, OS commands
    5. CredentialQueryProbe - Credential table queries
    6. SQLInjectionPayloadProbe - UNION SELECT, OR 1=1, SLEEP()
    7. UnauthorizedDBAccessProbe - New source_ip+user combos
    8. DatabaseDDLChangeProbe - DROP/ALTER/TRUNCATE detection

MITRE ATT&CK Coverage:
    - T1078: Valid Accounts
    - T1005: Data from Local System
    - T1087: Account Discovery
    - T1059: Command and Scripting Interpreter
    - T1555: Credentials from Password Stores
    - T1190: Exploit Public-Facing Application
    - T1078.004: Valid Accounts: Cloud Accounts
    - T1485: Data Destruction

Usage:
    >>> agent = DBActivityAgent()
    >>> agent.run_forever()
"""

from __future__ import annotations

import json
import logging
import platform
import re
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import grpc

from amoskys.agents.common.base import HardenedAgentBase, ValidationResult
from amoskys.agents.common.probes import MicroProbeAgentMixin, TelemetryEvent
from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.agents.db_activity.agent_types import (
    DB_PORTS,
    QUERY_TYPE_MAP,
    DatabaseQuery,
)
from amoskys.agents.db_activity.probes import create_db_activity_probes
from amoskys.config import get_config
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.proto import universal_telemetry_pb2_grpc as universal_pbrpc

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("DBActivityAgent")

config = get_config()
EVENTBUS_ADDRESS = config.agent.bus_address
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = getattr(
    config.agent, "db_activity_queue_path", "data/queue/db_activity.db"
)


# =============================================================================
# EventBus Publisher
# =============================================================================


class EventBusPublisher:
    """Wrapper for EventBus gRPC client."""

    def __init__(self, address: str, cert_dir: str):
        self.address = address
        self.cert_dir = cert_dir
        self._channel = None
        self._stub = None

    def _ensure_channel(self):
        """Create gRPC channel if needed."""
        if self._channel is None:
            try:
                with open(f"{self.cert_dir}/ca.crt", "rb") as f:
                    ca_cert = f.read()
                with open(f"{self.cert_dir}/agent.crt", "rb") as f:
                    client_cert = f.read()
                with open(f"{self.cert_dir}/agent.key", "rb") as f:
                    client_key = f.read()

                credentials = grpc.ssl_channel_credentials(
                    root_certificates=ca_cert,
                    private_key=client_key,
                    certificate_chain=client_cert,
                )
                self._channel = grpc.secure_channel(self.address, credentials)
                self._stub = universal_pbrpc.UniversalEventBusStub(self._channel)
                logger.info("Created secure gRPC channel with mTLS")
            except FileNotFoundError as e:
                raise RuntimeError(f"Certificate not found: {e}")
            except Exception as e:
                raise RuntimeError(f"Failed to create gRPC channel: {e}")

    def publish(self, events: list) -> None:
        """Publish events to EventBus."""
        self._ensure_channel()

        for event in events:
            # Already-wrapped envelopes (e.g. from drain path) go directly
            if isinstance(event, telemetry_pb2.UniversalEnvelope):
                envelope = event
            else:
                timestamp_ns = int(time.time() * 1e9)
                idempotency_key = f"{event.device_id}_{timestamp_ns}"
                envelope = telemetry_pb2.UniversalEnvelope(
                    version="v1",
                    ts_ns=timestamp_ns,
                    idempotency_key=idempotency_key,
                    device_telemetry=event,
                    priority="NORMAL",
                    requires_acknowledgment=True,
                    schema_version=1,
                )

            ack = self._stub.PublishTelemetry(envelope, timeout=5.0)

            if ack.status != telemetry_pb2.UniversalAck.OK:
                raise Exception(f"EventBus returned status: {ack.status}")

    def close(self):
        """Close gRPC channel."""
        if self._channel:
            self._channel.close()
            self._channel = None
            self._stub = None


# =============================================================================
# Platform-Specific Database Collectors
# =============================================================================


class DBCollector:
    """Base class for platform-specific database activity collection."""

    def collect(self) -> List[DatabaseQuery]:
        """Collect database queries from system.

        Returns:
            List of DatabaseQuery objects
        """
        raise NotImplementedError

    @staticmethod
    def classify_query_type(query_text: str) -> str:
        """Classify SQL query type from query text.

        Args:
            query_text: SQL query string

        Returns:
            Query type string (SELECT, INSERT, UPDATE, DELETE, DDL, DCL)
        """
        stripped = query_text.strip().upper()
        for keyword, qtype in QUERY_TYPE_MAP.items():
            if stripped.startswith(keyword):
                return qtype
        return "SELECT"  # Default

    @staticmethod
    def _get_db_connections(ports: List[int]) -> List[Dict[str, str]]:
        """Get active database connections using lsof.

        Args:
            ports: List of database ports to check

        Returns:
            List of dicts with connection details
        """
        connections = []

        for port in ports:
            try:
                cmd = ["lsof", "-i", f":{port}", "-n", "-P"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

                if result.returncode == 0 and result.stdout:
                    lines = result.stdout.strip().split("\n")
                    for line in lines[1:]:  # Skip header
                        parts = line.split()
                        if len(parts) >= 9:
                            connections.append(
                                {
                                    "process_name": parts[0],
                                    "pid": parts[1],
                                    "user": parts[2],
                                    "port": str(port),
                                    "connection": parts[8] if len(parts) > 8 else "",
                                }
                            )

            except subprocess.TimeoutExpired:
                logger.debug("lsof timed out for port %d", port)
            except FileNotFoundError:
                logger.debug("lsof not available")
            except Exception as e:
                logger.debug("Failed to check port %d: %s", port, e)

        return connections


class MacOSDBCollector(DBCollector):
    """Collects database activity on macOS.

    Methods:
        - Monitor SQLite WAL activity via fs_usage
        - Scan for PostgreSQL/MySQL logs in common paths
        - Track DB port connections via lsof
    """

    # Common macOS paths for database logs
    POSTGRES_LOG_PATHS = [
        "/usr/local/var/log/postgresql.log",
        "/opt/homebrew/var/log/postgresql.log",
        "/usr/local/var/postgres/server.log",
        "/opt/homebrew/var/postgres/server.log",
    ]

    MYSQL_LOG_PATHS = [
        "/usr/local/var/mysql/general.log",
        "/opt/homebrew/var/mysql/general.log",
        "/usr/local/var/log/mysql/general.log",
    ]

    # PostgreSQL log pattern:
    # "2024-01-01 12:00:00.000 UTC [1234] user@db LOG: statement: SELECT ..."
    _PG_LOG_RE = re.compile(
        r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+\S+)\s+"
        r"\[(\d+)\]\s+"
        r"(?:(\S+)@(\S+)\s+)?"
        r"\w+:\s+(?:statement|execute\s+\S+):\s+(.+)$"
    )

    # MySQL general log pattern:
    # "2024-01-01T12:00:00.000000Z  1234 Query  SELECT ..."
    _MYSQL_LOG_RE = re.compile(
        r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z?)\s+"
        r"\d+\s+"
        r"(\w+)\s+"
        r"(.+)$"
    )

    def __init__(self):
        self._last_position: Dict[str, int] = {}

    def collect(self) -> List[DatabaseQuery]:
        """Collect database queries from macOS."""
        queries = []

        # Collect from PostgreSQL logs
        queries.extend(self._collect_postgres_logs())

        # Collect from MySQL logs
        queries.extend(self._collect_mysql_logs())

        # Collect SQLite WAL activity
        queries.extend(self._collect_sqlite_wal())

        # Collect DB connections
        queries.extend(self._collect_db_connections())

        return queries

    def _collect_postgres_logs(self) -> List[DatabaseQuery]:
        """Parse PostgreSQL server logs."""
        queries = []

        for log_path in self.POSTGRES_LOG_PATHS:
            if not Path(log_path).exists():
                continue

            try:
                current_size = Path(log_path).stat().st_size
                last_pos = self._last_position.get(log_path, 0)

                if current_size < last_pos:
                    last_pos = 0

                if current_size <= last_pos:
                    continue

                with open(log_path, "r", errors="replace") as f:
                    f.seek(last_pos)
                    for line in f:
                        line = line.rstrip("\n")
                        match = self._PG_LOG_RE.match(line)
                        if match:
                            ts_str, pid, user, db, query_text = match.groups()

                            try:
                                ts = datetime.fromisoformat(
                                    ts_str.strip()
                                    .replace(" UTC", "+00:00")
                                    .replace(" ", "T")
                                )
                            except ValueError:
                                ts = datetime.now(timezone.utc)

                            queries.append(
                                DatabaseQuery(
                                    timestamp=ts,
                                    db_type="postgresql",
                                    database_name=db or "unknown",
                                    query_text=query_text.strip().rstrip(";"),
                                    query_type=self.classify_query_type(query_text),
                                    user=user,
                                    process_name="postgres",
                                    file_path=log_path,
                                )
                            )

                    self._last_position[log_path] = f.tell()

            except PermissionError:
                logger.debug("Permission denied reading %s", log_path)
            except Exception as e:
                logger.error("Failed to read %s: %s", log_path, e)

        return queries

    def _collect_mysql_logs(self) -> List[DatabaseQuery]:
        """Parse MySQL general log."""
        queries = []

        for log_path in self.MYSQL_LOG_PATHS:
            if not Path(log_path).exists():
                continue

            try:
                current_size = Path(log_path).stat().st_size
                last_pos = self._last_position.get(log_path, 0)

                if current_size < last_pos:
                    last_pos = 0

                if current_size <= last_pos:
                    continue

                with open(log_path, "r", errors="replace") as f:
                    f.seek(last_pos)
                    for line in f:
                        line = line.rstrip("\n")
                        match = self._MYSQL_LOG_RE.match(line)
                        if match:
                            ts_str, cmd_type, query_text = match.groups()

                            if cmd_type not in ("Query", "Execute"):
                                continue

                            try:
                                ts = datetime.fromisoformat(
                                    ts_str.replace("Z", "+00:00")
                                )
                            except ValueError:
                                ts = datetime.now(timezone.utc)

                            queries.append(
                                DatabaseQuery(
                                    timestamp=ts,
                                    db_type="mysql",
                                    database_name="unknown",
                                    query_text=query_text.strip().rstrip(";"),
                                    query_type=self.classify_query_type(query_text),
                                    process_name="mysqld",
                                    file_path=log_path,
                                )
                            )

                    self._last_position[log_path] = f.tell()

            except PermissionError:
                logger.debug("Permission denied reading %s", log_path)
            except Exception as e:
                logger.error("Failed to read %s: %s", log_path, e)

        return queries

    def _collect_sqlite_wal(self) -> List[DatabaseQuery]:
        """Monitor SQLite WAL activity using fs_usage.

        Uses fs_usage to detect filesystem operations on .db-wal files,
        indicating active SQLite write activity.
        """
        queries = []

        try:
            # Use fs_usage to detect SQLite WAL writes (requires root)
            cmd = [
                "fs_usage",
                "-w",
                "-f",
                "diskio",
                "-t",
                "1",  # 1 second sample
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)

            if result.returncode == 0 and result.stdout:
                for line in result.stdout.strip().split("\n"):
                    if ".db-wal" in line or ".sqlite-wal" in line:
                        # Extract process name and file path
                        parts = line.split()
                        if len(parts) >= 2:
                            process = parts[-1] if parts else "unknown"
                            # Find the WAL file path in the line
                            wal_path = ""
                            for part in parts:
                                if ".db-wal" in part or ".sqlite-wal" in part:
                                    wal_path = part.replace("-wal", "")
                                    break

                            if wal_path:
                                queries.append(
                                    DatabaseQuery(
                                        timestamp=datetime.now(timezone.utc),
                                        db_type="sqlite",
                                        database_name=Path(wal_path).name,
                                        query_text="WAL_WRITE_ACTIVITY",
                                        query_type="UPDATE",
                                        process_name=process,
                                        file_path=wal_path,
                                    )
                                )

        except subprocess.TimeoutExpired:
            pass  # Expected - fs_usage runs until timeout
        except PermissionError:
            if not getattr(self, "_fs_usage_warned", False):
                logger.warning(
                    "fs_usage requires root privileges — SQLite WAL monitoring "
                    "will be degraded. Run agent as root for full coverage."
                )
                self._fs_usage_warned = True
        except FileNotFoundError:
            if not getattr(self, "_fs_usage_warned", False):
                logger.warning("fs_usage not available — SQLite WAL monitoring disabled")
                self._fs_usage_warned = True
        except Exception as e:
            logger.debug("SQLite WAL collection failed: %s", e)

        return queries

    def _collect_db_connections(self) -> List[DatabaseQuery]:
        """Track active database port connections."""
        queries = []
        db_ports = [3306, 5432, 27017]

        connections = self._get_db_connections(db_ports)

        for conn in connections:
            port = int(conn["port"])
            db_type = DB_PORTS.get(port, "unknown")

            # Parse source IP from connection string (e.g., "10.0.0.1:12345->127.0.0.1:5432")
            source_ip = None
            conn_str = conn.get("connection", "")
            if "->" in conn_str:
                source_part = conn_str.split("->")[0]
                source_ip = (
                    source_part.rsplit(":", 1)[0] if ":" in source_part else source_part
                )

            queries.append(
                DatabaseQuery(
                    timestamp=datetime.now(timezone.utc),
                    db_type=db_type,
                    database_name="unknown",
                    query_text="ACTIVE_CONNECTION",
                    query_type="SELECT",
                    user=conn.get("user"),
                    source_ip=source_ip,
                    process_name=conn.get("process_name"),
                )
            )

        return queries


class LinuxDBCollector(DBCollector):
    """Collects database activity on Linux.

    Methods:
        - Parse /var/log/postgresql/*.log
        - Parse /var/log/mysql/general.log
        - Monitor /proc/net/tcp for DB port connections
        - Track DB port connections via lsof
    """

    POSTGRES_LOG_DIRS = [
        "/var/log/postgresql",
        "/var/lib/pgsql/data/log",
        "/var/lib/postgresql/data/log",
    ]

    MYSQL_LOG_PATHS = [
        "/var/log/mysql/general.log",
        "/var/log/mysql/mysql.log",
        "/var/lib/mysql/general.log",
    ]

    # PostgreSQL log pattern
    _PG_LOG_RE = re.compile(
        r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+\S+)\s+"
        r"\[(\d+)\]\s+"
        r"(?:(\S+)@(\S+)\s+)?"
        r"\w+:\s+(?:statement|execute\s+\S+):\s+(.+)$"
    )

    # MySQL general log pattern
    _MYSQL_LOG_RE = re.compile(
        r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z?)\s+"
        r"\d+\s+"
        r"(\w+)\s+"
        r"(.+)$"
    )

    def __init__(self):
        self._last_position: Dict[str, int] = {}

    def collect(self) -> List[DatabaseQuery]:
        """Collect database queries from Linux."""
        queries = []

        # Collect from PostgreSQL logs
        queries.extend(self._collect_postgres_logs())

        # Collect from MySQL logs
        queries.extend(self._collect_mysql_logs())

        # Collect from /proc/net/tcp
        queries.extend(self._collect_proc_net_tcp())

        # Collect DB connections via lsof
        queries.extend(self._collect_db_connections())

        return queries

    def _collect_postgres_logs(self) -> List[DatabaseQuery]:
        """Parse PostgreSQL server logs from standard Linux paths."""
        queries = []

        for log_dir in self.POSTGRES_LOG_DIRS:
            log_dir_path = Path(log_dir)
            if not log_dir_path.exists():
                continue

            try:
                # Find most recent log files
                log_files = sorted(
                    log_dir_path.glob("*.log"),
                    key=lambda p: p.stat().st_mtime,
                    reverse=True,
                )

                for log_file in log_files[:3]:  # Check latest 3 log files
                    log_path = str(log_file)

                    current_size = log_file.stat().st_size
                    last_pos = self._last_position.get(log_path, 0)

                    if current_size < last_pos:
                        last_pos = 0

                    if current_size <= last_pos:
                        continue

                    with open(log_path, "r", errors="replace") as f:
                        f.seek(last_pos)
                        for line in f:
                            line = line.rstrip("\n")
                            match = self._PG_LOG_RE.match(line)
                            if match:
                                ts_str, pid, user, db, query_text = match.groups()

                                try:
                                    ts = datetime.fromisoformat(
                                        ts_str.strip()
                                        .replace(" UTC", "+00:00")
                                        .replace(" ", "T")
                                    )
                                except ValueError:
                                    ts = datetime.now(timezone.utc)

                                queries.append(
                                    DatabaseQuery(
                                        timestamp=ts,
                                        db_type="postgresql",
                                        database_name=db or "unknown",
                                        query_text=query_text.strip().rstrip(";"),
                                        query_type=self.classify_query_type(query_text),
                                        user=user,
                                        process_name="postgres",
                                        file_path=log_path,
                                    )
                                )

                        self._last_position[log_path] = f.tell()

            except PermissionError:
                logger.debug("Permission denied reading %s", log_dir)
            except Exception as e:
                logger.error("Failed to read PostgreSQL logs from %s: %s", log_dir, e)

        return queries

    def _collect_mysql_logs(self) -> List[DatabaseQuery]:
        """Parse MySQL general log."""
        queries = []

        for log_path in self.MYSQL_LOG_PATHS:
            if not Path(log_path).exists():
                continue

            try:
                current_size = Path(log_path).stat().st_size
                last_pos = self._last_position.get(log_path, 0)

                if current_size < last_pos:
                    last_pos = 0

                if current_size <= last_pos:
                    continue

                with open(log_path, "r", errors="replace") as f:
                    f.seek(last_pos)
                    for line in f:
                        line = line.rstrip("\n")
                        match = self._MYSQL_LOG_RE.match(line)
                        if match:
                            ts_str, cmd_type, query_text = match.groups()

                            if cmd_type not in ("Query", "Execute"):
                                continue

                            try:
                                ts = datetime.fromisoformat(
                                    ts_str.replace("Z", "+00:00")
                                )
                            except ValueError:
                                ts = datetime.now(timezone.utc)

                            queries.append(
                                DatabaseQuery(
                                    timestamp=ts,
                                    db_type="mysql",
                                    database_name="unknown",
                                    query_text=query_text.strip().rstrip(";"),
                                    query_type=self.classify_query_type(query_text),
                                    process_name="mysqld",
                                    file_path=log_path,
                                )
                            )

                    self._last_position[log_path] = f.tell()

            except PermissionError:
                logger.debug("Permission denied reading %s", log_path)
            except Exception as e:
                logger.error("Failed to read %s: %s", log_path, e)

        return queries

    def _collect_proc_net_tcp(self) -> List[DatabaseQuery]:
        """Monitor /proc/net/tcp for database port connections."""
        queries = []
        proc_path = "/proc/net/tcp"

        if not Path(proc_path).exists():
            return queries

        db_port_hex = {
            format(port, "04X"): db_type for port, db_type in DB_PORTS.items()
        }

        try:
            with open(proc_path, "r") as f:
                lines = f.readlines()

            for line in lines[1:]:  # Skip header
                parts = line.strip().split()
                if len(parts) < 4:
                    continue

                # Parse local address (hex IP:port)
                local_addr = parts[1]
                if ":" not in local_addr:
                    continue

                local_ip_hex, local_port_hex = local_addr.split(":")

                if local_port_hex in db_port_hex:
                    db_type = db_port_hex[local_port_hex]

                    # Parse remote address
                    remote_addr = parts[2]
                    remote_ip_hex, remote_port_hex = remote_addr.split(":")

                    # Convert hex IP to dotted notation
                    try:
                        ip_int = int(remote_ip_hex, 16)
                        remote_ip = ".".join(
                            [str((ip_int >> (8 * i)) & 0xFF) for i in range(4)]
                        )
                    except ValueError:
                        remote_ip = "unknown"

                    # State 01 = ESTABLISHED
                    state = parts[3]
                    if state == "01":
                        queries.append(
                            DatabaseQuery(
                                timestamp=datetime.now(timezone.utc),
                                db_type=db_type,
                                database_name="unknown",
                                query_text="ESTABLISHED_CONNECTION",
                                query_type="SELECT",
                                source_ip=remote_ip,
                            )
                        )

        except PermissionError:
            logger.debug("Permission denied reading %s", proc_path)
        except Exception as e:
            logger.debug("Failed to read %s: %s", proc_path, e)

        return queries

    def _collect_db_connections(self) -> List[DatabaseQuery]:
        """Track active database port connections via lsof."""
        queries = []
        db_ports = [3306, 5432, 27017]

        connections = self._get_db_connections(db_ports)

        for conn in connections:
            port = int(conn["port"])
            db_type = DB_PORTS.get(port, "unknown")

            source_ip = None
            conn_str = conn.get("connection", "")
            if "->" in conn_str:
                source_part = conn_str.split("->")[0]
                source_ip = (
                    source_part.rsplit(":", 1)[0] if ":" in source_part else source_part
                )

            queries.append(
                DatabaseQuery(
                    timestamp=datetime.now(timezone.utc),
                    db_type=db_type,
                    database_name="unknown",
                    query_text="ACTIVE_CONNECTION",
                    query_type="SELECT",
                    user=conn.get("user"),
                    source_ip=source_ip,
                    process_name=conn.get("process_name"),
                )
            )

        return queries


def get_db_collector() -> DBCollector:
    """Get platform-appropriate database collector."""
    system = platform.system()
    if system == "Darwin":
        return MacOSDBCollector()
    elif system == "Linux":
        return LinuxDBCollector()
    else:
        logger.warning("Unsupported platform: %s", system)
        return MacOSDBCollector()  # Default


# =============================================================================
# Database Activity Agent
# =============================================================================


class DBActivityAgent(MicroProbeAgentMixin, HardenedAgentBase):
    """Database Activity Agent with micro-probe architecture.

    This agent hosts 8 micro-probes that each monitor a specific
    database threat vector. The agent handles:
        - Database query collection (platform-specific)
        - Probe lifecycle management
        - Event aggregation and publishing
        - Circuit breaker and retry logic
        - Offline queue management

    Probes are responsible only for detection - no networking or state
    management.
    """

    def __init__(self, collection_interval: float = 15.0):
        """Initialize Database Activity Agent.

        Args:
            collection_interval: Seconds between collection cycles
        """
        device_id = socket.gethostname()

        # Create EventBus publisher
        publisher = EventBusPublisher(EVENTBUS_ADDRESS, CERT_DIR)

        # Create local queue
        Path(QUEUE_PATH).parent.mkdir(parents=True, exist_ok=True)
        queue_adapter = LocalQueueAdapter(
            queue_path=QUEUE_PATH,
            agent_name="db_activity",
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,
            max_retries=10,
            signing_key_path="certs/agents/db_activity.ed25519",
        )

        # Initialize base classes
        super().__init__(
            agent_name="db_activity",
            device_id=device_id,
            collection_interval=collection_interval,
            eventbus_publisher=publisher,
            local_queue=queue_adapter,
        )

        # Platform-specific database collector
        self.db_collector = get_db_collector()

        # Register all Database Activity probes
        self.register_probes(create_db_activity_probes())

        logger.info("DBActivityAgent initialized with %d probes", len(self._probes))

    def setup(self) -> bool:
        """Initialize agent resources.

        Verifies:
            - Certificates exist
            - Database collector works
            - Probes initialize successfully

        Returns:
            True if setup succeeded
        """
        try:
            import os

            # Verify certificates (warn but don't fail -- dev mode may lack certs)
            required_certs = ["ca.crt", "agent.crt", "agent.key"]
            for cert in required_certs:
                cert_path = f"{CERT_DIR}/{cert}"
                if not os.path.exists(cert_path):
                    logger.warning(
                        "Certificate not found: %s (EventBus publishing will fail)",
                        cert_path,
                    )

            # Test database collector
            try:
                test_queries = self.db_collector.collect()
                logger.info("Database collector test: %d queries", len(test_queries))
            except Exception as e:
                logger.warning("Database collector test failed: %s", e)
                # Continue anyway - collector may work later

            # Setup probes
            if not self.setup_probes(collector_shared_data_keys=["database_queries"]):
                logger.error("No probes initialized successfully")
                return False

            logger.info("DBActivityAgent setup complete")
            return True

        except Exception as e:
            logger.error("Setup failed: %s", e)
            return False

    def collect_data(self) -> Sequence[Any]:
        """Collect database queries and run all probes.

        Returns:
            List of DeviceTelemetry protobuf messages
        """
        timestamp_ns = int(time.time() * 1e9)

        # Collect database queries
        database_queries = self.db_collector.collect()
        logger.info("Collected %d database queries", len(database_queries))

        # Create context with database queries
        context = self._create_probe_context()
        context.shared_data["database_queries"] = database_queries

        # Run all probes and collect events
        events: List[TelemetryEvent] = []
        for probe in self._probes:
            if not probe.enabled:
                continue

            try:
                probe_events = probe.scan(context)
                events.extend(probe_events)
                probe.last_scan = datetime.now(timezone.utc)
                probe.scan_count += 1
            except Exception as e:
                probe.error_count += 1
                probe.last_error = str(e)
                logger.error("Probe %s failed: %s", probe.name, e)

        logger.info(
            "Probes generated %d events from %d database queries",
            len(events),
            len(database_queries),
        )

        # Build proto events
        proto_events = []

        # Always emit a collection summary metric (heartbeat)
        proto_events.append(
            telemetry_pb2.TelemetryEvent(
                event_id=f"db_activity_collection_summary_{timestamp_ns}",
                event_type="METRIC",
                severity="INFO",
                event_timestamp_ns=timestamp_ns,
                source_component="db_activity_collector",
                tags=["db_activity", "metric"],
                metric_data=telemetry_pb2.MetricData(
                    metric_name="db_queries_collected",
                    metric_type="GAUGE",
                    numeric_value=float(len(database_queries)),
                    unit="queries",
                ),
            )
        )

        # Probe event count metric
        if events:
            proto_events.append(
                telemetry_pb2.TelemetryEvent(
                    event_id=f"db_activity_probe_events_{timestamp_ns}",
                    event_type="METRIC",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="db_activity_agent",
                    tags=["db_activity", "metric"],
                    metric_data=telemetry_pb2.MetricData(
                        metric_name="db_activity_probe_events",
                        metric_type="GAUGE",
                        numeric_value=float(len(events)),
                        unit="events",
                    ),
                )
            )

        # Convert probe events to SecurityEvent-based telemetry
        severity_map = {
            "DEBUG": "DEBUG",
            "INFO": "INFO",
            "LOW": "LOW",
            "MEDIUM": "MEDIUM",
            "HIGH": "HIGH",
            "CRITICAL": "CRITICAL",
        }

        for event in events:
            # Build SecurityEvent sub-message
            security_event = telemetry_pb2.SecurityEvent(
                event_category=event.event_type,
                risk_score=0.8 if event.severity.value in ("HIGH", "CRITICAL") else 0.4,
                analyst_notes=f"Probe: {event.probe_name}, "
                f"Severity: {event.severity.value}",
            )
            security_event.mitre_techniques.extend(event.mitre_techniques)

            tel_event = telemetry_pb2.TelemetryEvent(
                event_id=f"{event.event_type}_{timestamp_ns}",
                event_type="SECURITY",
                severity=severity_map.get(event.severity.value, "INFO"),
                event_timestamp_ns=timestamp_ns,
                source_component=event.probe_name or "db_activity_agent",
                tags=["db_activity", "threat"],
                security_event=security_event,
                confidence_score=event.confidence,
            )

            # Populate attributes map with evidence
            if event.data:
                for key, value in event.data.items():
                    if value is not None:
                        tel_event.attributes[key] = str(value)

            proto_events.append(tel_event)

        # Create DeviceTelemetry
        telemetry = telemetry_pb2.DeviceTelemetry(
            device_id=self.device_id,
            device_type="HOST",
            protocol="DB_ACTIVITY",
            events=proto_events,
            timestamp_ns=timestamp_ns,
            collection_agent="db_activity",
            agent_version="2.0.0",
        )

        return [telemetry]

    def validate_event(self, event: Any) -> ValidationResult:
        """Validate telemetry before publishing.

        Args:
            event: DeviceTelemetry protobuf message

        Returns:
            ValidationResult
        """
        errors = []
        if not hasattr(event, "device_id") or not event.device_id:
            errors.append("Missing device_id")
        if not hasattr(event, "timestamp_ns") or event.timestamp_ns <= 0:
            errors.append("Missing or invalid timestamp_ns")
        if not event.events:
            errors.append("events list is empty")
        return ValidationResult(is_valid=len(errors) == 0, errors=errors)

    def shutdown(self) -> None:
        """Graceful shutdown."""
        logger.info("DBActivityAgent shutting down...")

        # Close EventBus connection
        if self.eventbus_publisher:
            self.eventbus_publisher.close()

        logger.info("DBActivityAgent shutdown complete")

    def get_health(self) -> Dict[str, Any]:
        """Get agent health status.

        Returns:
            Dict with health metrics
        """
        return {
            "agent_name": self.agent_name,
            "device_id": self.device_id,
            "is_running": self.is_running,
            "collection_count": self.collection_count,
            "error_count": self.error_count,
            "last_error": self.last_error,
            "probes": self.get_probe_health(),
            "circuit_breaker_state": self.circuit_breaker.state,
        }


# =============================================================================
# CLI Entry Point
# =============================================================================


def main():
    """Run Database Activity Agent."""
    import argparse

    parser = argparse.ArgumentParser(description="AMOSKYS Database Activity Agent")
    parser.add_argument(
        "--interval",
        type=float,
        default=15.0,
        help="Collection interval in seconds",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (overrides --debug)",
    )

    args = parser.parse_args()

    if args.log_level:
        logging.getLogger().setLevel(getattr(logging, args.log_level))
    elif args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info("=" * 70)
    logger.info("AMOSKYS Database Activity Agent (Micro-Probe Architecture)")
    logger.info("=" * 70)

    agent = DBActivityAgent(collection_interval=args.interval)

    try:
        agent.run_forever()
    except KeyboardInterrupt:
        logger.info("Received interrupt, shutting down...")
        agent.shutdown()


if __name__ == "__main__":
    main()
