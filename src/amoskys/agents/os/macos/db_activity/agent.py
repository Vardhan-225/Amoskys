"""macOS Database Activity Observatory Agent — database threat detection.

Monitors local database processes and logs for:
    - Bulk data extraction (SELECT * without WHERE, large LIMIT)
    - Schema enumeration (INFORMATION_SCHEMA, SHOW TABLES, pg_catalog)
    - Privilege escalation (GRANT, ALTER USER, CREATE ROLE)
    - SQL injection patterns (UNION SELECT, OR 1=1, error-based)
    - Credential table access (users, passwords, auth_tokens)
    - Data destruction (DROP TABLE, TRUNCATE, DELETE without WHERE)
    - Unauthorized access (auth failures, unknown users)
    - Exfiltration via database (INTO OUTFILE, COPY TO, exports)

Data flow:
    MacOSDBActivityCollector.collect() → shared_data
    → 8 probes scan(context) → TelemetryEvent[]
    → _events_to_telemetry() → DeviceTelemetry
    → LocalQueueAdapter → EventBus
"""

from __future__ import annotations

import logging
import platform
import socket
import time
from pathlib import Path
from typing import Any, Dict, List, Sequence

from amoskys.agents.common.base import HardenedAgentBase, ValidationResult
from amoskys.agents.common.probes import MicroProbeAgentMixin, Severity, TelemetryEvent
from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.agents.os.macos.db_activity.collector import MacOSDBActivityCollector
from amoskys.agents.os.macos.db_activity.probes import create_db_activity_probes
from amoskys.config import get_config

logger = logging.getLogger(__name__)
config = get_config()
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = "data/queue/macos_db_activity.db"


class MacOSDBActivityAgent(MicroProbeAgentMixin, HardenedAgentBase):
    """macOS Database Activity Observatory — 8 probes, 8 MITRE techniques.

    Probes:
        macos_db_bulk_extraction    — T1005     Bulk data extraction
        macos_db_schema_enum        — T1087     Schema enumeration
        macos_db_priv_escalation    — T1078     Privilege escalation
        macos_db_sql_injection      — T1190     SQL injection
        macos_db_credential_query   — T1555     Credential access
        macos_db_data_destruction   — T1485     Data destruction
        macos_db_unauthorized_access — T1078.003 Unauthorized access (local accounts)
        macos_db_exfiltration       — T1048     Exfiltration via DB
    """

    MANDATE_DATA_FIELDS = ("pid", "process_name")

    def __init__(self, collection_interval: float = 30.0) -> None:
        device_id = socket.gethostname()

        Path(QUEUE_PATH).parent.mkdir(parents=True, exist_ok=True)
        queue_adapter = LocalQueueAdapter(
            queue_path=QUEUE_PATH,
            agent_name="macos_db_activity",
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,
            max_retries=10,
            signing_key_path=f"{CERT_DIR}/agent.ed25519",
        )

        super().__init__(
            agent_name="macos_db_activity",
            device_id=device_id,
            collection_interval=collection_interval,
            queue_adapter=queue_adapter,
        )

        self.collector = MacOSDBActivityCollector(device_id=device_id)
        self.register_probes(create_db_activity_probes())

        logger.info(
            "MacOSDBActivityAgent initialized: %d probes, device=%s",
            len(self._probes),
            device_id,
        )

    def setup(self) -> bool:
        """Verify macOS platform and database data sources."""
        if platform.system() != "Darwin":
            logger.error("MacOSDBActivityAgent requires macOS (Darwin)")
            return False

        # Verify psutil availability
        try:
            import psutil

            logger.info("psutil OK: database process detection available")
        except ImportError:
            logger.warning("psutil not available — process detection degraded")

        # Verify Unified Logging access
        try:
            import subprocess

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
            if result.returncode == 0:
                logger.info("Unified Logging OK: database logs accessible")
            else:
                logger.warning(
                    "Unified Logging degraded: returncode=%d", result.returncode
                )
        except Exception as e:
            logger.warning("Unified Logging check failed: %s", e)

        if not self.setup_probes(
            collector_shared_data_keys=[
                "db_processes",
                "db_logs",
                "db_count",
                "log_count",
                "collection_time_ms",
            ]
        ):
            logger.error("No probes initialized")
            return False

        logger.info("MacOSDBActivityAgent setup complete — 8 probes active")
        return True

    def collect_data(self) -> Sequence[Any]:
        """Run database collector + probes, emit raw observations + detections."""
        snapshot = self.collector.collect()

        # Build OBSERVATION events for every raw DB process and log entry
        obs_events = self._make_observation_events(
            snapshot.get("db_processes", []),
            domain="db_activity",
            field_mapper=self._db_process_to_obs,
        )
        obs_events += self._make_observation_events(
            snapshot.get("db_logs", []),
            domain="db_activity",
            field_mapper=self._db_log_to_obs,
        )

        # Run probes (detection events, unchanged)
        context = self._create_probe_context()
        context.shared_data = snapshot
        probe_events = self.run_probes(context)

        all_events = obs_events + probe_events
        all_events.append(
            TelemetryEvent(
                event_type="collection_metadata",
                severity=Severity.DEBUG,
                probe_name="macos_db_activity_collector",
                data={
                    "db_count": snapshot["db_count"],
                    "log_count": snapshot["log_count"],
                    "collection_time_ms": snapshot["collection_time_ms"],
                    "observation_events": len(obs_events),
                    "probe_events": len(probe_events),
                },
            )
        )

        logger.info(
            "DB activity collected in %.1fms: %d processes, %d logs, "
            "%d observations, %d probe events",
            snapshot["collection_time_ms"],
            snapshot["db_count"],
            snapshot["log_count"],
            len(obs_events),
            len(probe_events),
        )

        if all_events:
            return [self._events_to_telemetry(all_events)]
        return []

    @staticmethod
    def _db_process_to_obs(proc) -> Dict[str, Any]:
        """Map a DBProcess to observation data dict."""
        return {
            "pid": str(proc.pid),
            "name": proc.name,
            "port": str(proc.port),
            "user": proc.user,
            "db_type": proc.db_type,
            "status": proc.status,
        }

    @staticmethod
    def _db_log_to_obs(entry) -> Dict[str, Any]:
        """Map a DBLogEntry to observation data dict."""
        return {
            "timestamp": str(entry.timestamp),
            "db_type": entry.db_type,
            "message": entry.message,
            "log_level": entry.log_level,
            "user": entry.user,
            "database": entry.database,
            "query": entry.query,
        }

    def _events_to_telemetry(self, events: List[TelemetryEvent]) -> Any:
        """Convert TelemetryEvents to protobuf DeviceTelemetry."""
        from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2

        timestamp_ns = int(time.time() * 1e9)
        proto_events = []

        for idx, event in enumerate(events):
            if event.event_type == "collection_metadata":
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"macos_db_activity_meta_{timestamp_ns}",
                    event_type="METRIC",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="macos_db_activity_collector",
                    metric_data=telemetry_pb2.MetricData(
                        metric_name="db_activity_collection",
                        metric_type="GAUGE",
                        numeric_value=float(event.data.get("db_count", 0)),
                        unit="processes",
                    ),
                )
            elif event.event_type.startswith("obs_"):
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"macos_db_activity_obs_{idx}_{timestamp_ns}",
                    event_type="OBSERVATION",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="db_activity_collector",
                    confidence_score=0.0,
                )
                for k, v in event.data.items():
                    proto_event.attributes[k] = str(v)
            else:
                security_event = telemetry_pb2.SecurityEvent(
                    event_category=event.event_type,
                    risk_score=event.confidence,
                    analyst_notes=str(event.data),
                )
                if event.mitre_techniques:
                    security_event.mitre_techniques.extend(event.mitre_techniques)

                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"{event.probe_name}_{event.event_type}_{timestamp_ns}",
                    event_type="SECURITY",
                    severity=event.severity.value,
                    event_timestamp_ns=timestamp_ns,
                    source_component=event.probe_name,
                    security_event=security_event,
                    confidence_score=event.confidence,
                    tags=event.tags,
                )
                for k, v in event.data.items():
                    proto_event.attributes[k] = str(v)

            proto_events.append(proto_event)

        return telemetry_pb2.DeviceTelemetry(
            device_id=self.device_id,
            device_type="HOST",
            protocol="MACOS_DB_ACTIVITY",
            events=proto_events,
            timestamp_ns=timestamp_ns,
            collection_agent="macos_db_activity",
            agent_version="2.0.0",
        )

    def validate_event(self, event: Any) -> ValidationResult:
        """Validate DeviceTelemetry before publishing."""
        errors = []
        if not hasattr(event, "device_id") or not event.device_id:
            errors.append("Missing device_id")
        if not hasattr(event, "timestamp_ns") or event.timestamp_ns == 0:
            errors.append("Missing timestamp_ns")
        return ValidationResult(is_valid=len(errors) == 0, errors=errors)

    def shutdown(self) -> None:
        """Graceful shutdown."""
        logger.info("MacOSDBActivityAgent shutting down")
