"""macOS Unified Log Agent — Unified Logging Observatory for Darwin.

Purpose-built Unified Logging agent for macOS. Uses the AMOSKYS canonical
agent pattern (MicroProbeAgentMixin + HardenedAgentBase) with a predicate-
based collector and 6 detection probes covering securityd, Gatekeeper, TCC,
XPC, installer, and sharing subsystems.

Data flow:
    1. MacOSUnifiedLogCollector.collect() → log entries (log show --style json)
    2. Probes.scan(context) → TelemetryEvents (detections)
    3. Agent converts events → DeviceTelemetry protobuf
    4. LocalQueueAdapter → WAL → EventBus

Constraint: TCC probe is DEGRADED without Full Disk Access. All other
subsystems are fully visible to uid=501 non-root processes.

Usage:
    agent = MacOSUnifiedLogAgent()
    agent.run()  # Enters main loop
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
from amoskys.agents.os.macos.unified_log.collector import MacOSUnifiedLogCollector
from amoskys.agents.os.macos.unified_log.probes import create_unified_log_probes
from amoskys.config import get_config

logger = logging.getLogger(__name__)

config = get_config()
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = "data/queue/macos_unified_log.db"


class MacOSUnifiedLogAgent(MicroProbeAgentMixin, HardenedAgentBase):
    """macOS Unified Log Observatory agent.

    Monitors the macOS Unified Logging system across 6 subsystems with
    6 detection probes. Uses targeted predicates to avoid log flooding.

    Probes:
        1. macos_security_framework — PKI/cert/trust events (T1553)
        2. macos_gatekeeper — Gatekeeper bypass/anomaly (T1553.001)
        3. macos_installer_activity — installer package activity (T1204.002)
        4. macos_xpc_anomaly — suspicious XPC activity (T1559)
        5. macos_tcc_event — TCC permission changes (T1548, degraded w/o FDA)
        6. macos_sharing_service — AirDrop/sharing activity (T1105)
    """

    def __init__(self, collection_interval: float = 30.0) -> None:
        device_id = socket.gethostname()

        # Local queue for offline resilience
        Path(QUEUE_PATH).parent.mkdir(parents=True, exist_ok=True)
        queue_adapter = LocalQueueAdapter(
            queue_path=QUEUE_PATH,
            agent_name="macos_unified_log",
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,
            max_retries=10,
            signing_key_path=f"{CERT_DIR}/agent.ed25519",
        )

        super().__init__(
            agent_name="macos_unified_log",
            device_id=device_id,
            collection_interval=collection_interval,
            queue_adapter=queue_adapter,
        )

        self.collector = MacOSUnifiedLogCollector(
            lookback_seconds=int(collection_interval) + 5,
        )
        self.register_probes(create_unified_log_probes())

        logger.info(
            "MacOSUnifiedLogAgent initialized: %d probes, device=%s",
            len(self._probes),
            device_id,
        )

    def setup(self) -> bool:
        """Verify macOS platform, `log` command, and initialize probes."""
        if platform.system() != "Darwin":
            logger.error("MacOSUnifiedLogAgent requires macOS (Darwin)")
            return False

        # Verify `log` command works
        try:
            import subprocess

            result = subprocess.run(
                [
                    "log",
                    "show",
                    "--predicate",
                    'subsystem == "com.apple.securityd"',
                    "--last",
                    "1s",
                    "--style",
                    "json",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            # returncode 0 or 1 (no matches) are both acceptable
            logger.info(
                "log command OK: returncode=%d, output_bytes=%d",
                result.returncode,
                len(result.stdout),
            )
        except FileNotFoundError:
            logger.error("'log' command not found — not macOS?")
            return False
        except Exception as e:
            logger.error("log command verification failed: %s", e)
            return False

        # Setup probes with collector's shared_data keys
        if not self.setup_probes(
            collector_shared_data_keys=[
                "log_entries",
                "entry_count",
                "subsystems",
                "collection_time_ms",
            ]
        ):
            logger.error("No probes initialized")
            return False

        logger.info("MacOSUnifiedLogAgent setup complete")
        return True

    def collect_data(self) -> Sequence[Any]:
        """Run collector + probes, emit raw observations + detections."""
        snapshot = self.collector.collect()

        # Build OBSERVATION events for every raw log entry
        obs_events = self._make_observation_events(
            snapshot.get("log_entries", []),
            domain="unified_log",
            field_mapper=self._log_entry_to_obs,
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
                probe_name="macos_unified_log_collector",
                data={
                    "entry_count": snapshot["entry_count"],
                    "subsystems": snapshot["subsystems"],
                    "collection_time_ms": snapshot["collection_time_ms"],
                    "observation_events": len(obs_events),
                    "probe_events": len(probe_events),
                },
            )
        )

        logger.info(
            "Collected: %d log entries from %d subsystems in %.1fms, "
            "%d observations, %d probe events",
            snapshot["entry_count"],
            len(snapshot["subsystems"]),
            snapshot["collection_time_ms"],
            len(obs_events),
            len(probe_events),
        )

        if all_events:
            return [self._events_to_telemetry(all_events)]
        return []

    @staticmethod
    def _log_entry_to_obs(entry) -> Dict[str, Any]:
        """Map a LogEntry to observation data dict."""
        return {
            "timestamp": entry.timestamp,
            "subsystem": entry.subsystem,
            "process": entry.process,
            "category": entry.category,
            "message": entry.message,
            "event_type": entry.event_type,
            "process_id": str(entry.process_id),
            "sender": entry.sender,
            "activity_id": str(entry.activity_id),
            "trace_id": str(entry.trace_id),
        }

    def _events_to_telemetry(self, events: List[TelemetryEvent]) -> Any:
        """Convert TelemetryEvents to protobuf DeviceTelemetry."""
        from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2

        timestamp_ns = int(time.time() * 1e9)
        proto_events = []

        for idx, event in enumerate(events):
            if event.event_type == "collection_metadata":
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"macos_unified_log_meta_{timestamp_ns}",
                    event_type="METRIC",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="macos_unified_log_collector",
                    metric_data=telemetry_pb2.MetricData(
                        metric_name="unified_log_collection",
                        metric_type="GAUGE",
                        numeric_value=float(event.data.get("entry_count", 0)),
                        unit="entries",
                    ),
                )
            elif event.event_type.startswith("obs_"):
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"macos_unified_log_obs_{idx}_{timestamp_ns}",
                    event_type="OBSERVATION",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="unified_log_collector",
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

                source_ip = event.data.get("source_ip")
                if source_ip:
                    security_event.source_ip = str(source_ip)

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
            protocol="MACOS_UNIFIED_LOG",
            events=proto_events,
            timestamp_ns=timestamp_ns,
            collection_agent="macos_unified_log",
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
        logger.info("MacOSUnifiedLogAgent shutting down")
