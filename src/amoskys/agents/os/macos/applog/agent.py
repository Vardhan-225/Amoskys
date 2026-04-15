"""macOS Application Log Observatory Agent — app log threat detection via Unified Logging.

Monitors application logs for web servers, databases, and frameworks for:
    - Web shell access patterns (cmd, eval, exec, passthru)
    - Log tampering (timestamp gaps, deletion patterns)
    - Application error rate anomalies (spike detection)
    - Credential harvesting (passwords, API keys, tokens in logs)
    - Privilege escalation (sudo, su, AuthorizationRef)
    - SQL injection patterns (UNION SELECT, OR 1=1, syntax errors)
    - Authentication bypass (null tokens, override patterns)

Data flow:
    MacOSAppLogCollector.collect() → shared_data
    → 7 probes scan(context) → TelemetryEvent[]
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
from amoskys.agents.os.macos.applog.collector import MacOSAppLogCollector
from amoskys.agents.os.macos.applog.probes import create_applog_probes
from amoskys.config import get_config

logger = logging.getLogger(__name__)
config = get_config()
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = "data/queue/macos_applog.db"


class MacOSAppLogAgent(MicroProbeAgentMixin, HardenedAgentBase):
    """macOS Application Log Observatory — 7 probes, 7 MITRE techniques.

    Probes:
        macos_applog_webshell          — T1505.003 Web shell access
        macos_applog_log_tampering     — T1070.002 Log tampering
        macos_applog_error_spike       — T1499     Error rate anomalies
        macos_applog_credential_harvest — T1552.001 Credential harvesting
        macos_applog_privesc           — T1548     Privilege escalation
        macos_applog_sqli              — T1190     SQL injection
        macos_applog_auth_bypass       — T1556     Authentication bypass
    """

    MANDATE_DATA_FIELDS = ("pid", "process_name")

    def __init__(self, collection_interval: float = 30.0) -> None:
        device_id = socket.gethostname()

        Path(QUEUE_PATH).parent.mkdir(parents=True, exist_ok=True)
        queue_adapter = LocalQueueAdapter(
            queue_path=QUEUE_PATH,
            agent_name="macos_applog",
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,
            max_retries=10,
            signing_key_path=f"{CERT_DIR}/agent.ed25519",
        )

        super().__init__(
            agent_name="macos_applog",
            device_id=device_id,
            collection_interval=collection_interval,
            queue_adapter=queue_adapter,
        )

        self.collector = MacOSAppLogCollector(device_id=device_id)
        self.register_probes(create_applog_probes())

        logger.info(
            "MacOSAppLogAgent initialized: %d probes, device=%s",
            len(self._probes),
            device_id,
        )

    def setup(self) -> bool:
        """Verify macOS platform and application log data sources."""
        if platform.system() != "Darwin":
            logger.error("MacOSAppLogAgent requires macOS (Darwin)")
            return False

        # Verify Unified Logging access for application processes
        try:
            import subprocess

            result = subprocess.run(
                [
                    "log",
                    "show",
                    "--predicate",
                    'process IN {"httpd","nginx","postgres","mysqld","python","node","ruby","java"}',
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
                logger.info("Unified Logging OK: application process logs accessible")
            else:
                logger.warning(
                    "Unified Logging degraded: returncode=%d", result.returncode
                )
        except Exception as e:
            logger.warning("Unified Logging check failed: %s", e)

        if not self.setup_probes(
            collector_shared_data_keys=[
                "app_logs",
                "log_count",
                "processes_seen",
                "collection_time_ms",
            ]
        ):
            logger.error("No probes initialized")
            return False

        logger.info("MacOSAppLogAgent setup complete — 7 probes active")
        return True

    def collect_data(self) -> Sequence[Any]:
        """Run application log collector + probes, emit raw observations + detections."""
        snapshot = self.collector.collect()

        # Build OBSERVATION events for every raw app log entry
        obs_events = self._make_observation_events(
            snapshot.get("app_logs", []),
            domain="applog",
            field_mapper=self._applog_to_obs,
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
                probe_name="macos_applog_collector",
                data={
                    "log_count": snapshot["log_count"],
                    "processes_seen": sorted(snapshot["processes_seen"]),
                    "collection_time_ms": snapshot["collection_time_ms"],
                    "observation_events": len(obs_events),
                    "probe_events": len(probe_events),
                },
            )
        )

        logger.info(
            "AppLog collected in %.1fms: %d entries, %d processes, "
            "%d observations, %d probe events",
            snapshot["collection_time_ms"],
            snapshot["log_count"],
            len(snapshot["processes_seen"]),
            len(obs_events),
            len(probe_events),
        )

        if all_events:
            return [self._events_to_telemetry(all_events)]
        return []

    @staticmethod
    def _applog_to_obs(entry) -> Dict[str, Any]:
        """Map an AppLogEntry to observation data dict."""
        return {
            "timestamp": str(entry.timestamp),
            "process": entry.process,
            "pid": str(entry.pid),
            "message": entry.message,
            "log_level": entry.log_level,
            "subsystem": entry.subsystem,
        }

    def _events_to_telemetry(self, events: List[TelemetryEvent]) -> Any:
        """Convert TelemetryEvents to protobuf DeviceTelemetry."""
        from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2

        timestamp_ns = int(time.time() * 1e9)
        proto_events = []

        for idx, event in enumerate(events):
            if event.event_type == "collection_metadata":
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"macos_applog_meta_{timestamp_ns}",
                    event_type="METRIC",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="macos_applog_collector",
                    metric_data=telemetry_pb2.MetricData(
                        metric_name="applog_collection",
                        metric_type="GAUGE",
                        numeric_value=float(event.data.get("log_count", 0)),
                        unit="entries",
                    ),
                )
            elif event.event_type.startswith("obs_"):
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"macos_applog_obs_{idx}_{timestamp_ns}",
                    event_type="OBSERVATION",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="applog_collector",
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
            protocol="MACOS_APPLOG",
            events=proto_events,
            timestamp_ns=timestamp_ns,
            collection_agent="macos_applog",
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
        logger.info("MacOSAppLogAgent shutting down")
