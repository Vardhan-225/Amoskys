"""macOS File Agent — File Observatory for Darwin.

Purpose-built filesystem integrity monitoring agent for macOS. Uses the AMOSKYS
canonical agent pattern (MicroProbeAgentMixin + HardenedAgentBase) with a
macOS-specific collector and 8 detection probes.

Data flow:
    1. MacOSFileCollector.collect() → file entries, SIP status, SUID list
    2. Probes.scan(context) → TelemetryEvents (detections)
    3. Agent converts events → DeviceTelemetry protobuf
    4. LocalQueueAdapter → WAL → EventBus

Usage:
    agent = MacOSFileAgent()
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
from amoskys.agents.common.probes import (
    MicroProbeAgentMixin,
    Severity,
    TelemetryEvent,
)
from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.agents.os.macos.filesystem.collector import MacOSFileCollector
from amoskys.agents.os.macos.filesystem.probes import create_filesystem_probes
from amoskys.config import get_config

logger = logging.getLogger(__name__)

config = get_config()
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = "data/queue/macos_filesystem.db"


class MacOSFileAgent(MicroProbeAgentMixin, HardenedAgentBase):
    """macOS File Observatory agent.

    Monitors filesystem integrity on macOS with 8 detection probes.

    Probes:
        1. macos_critical_file — baseline-diff on critical system files
        2. macos_suid_change — new/modified SUID binaries
        3. macos_config_backdoor — suspicious config modifications
        4. macos_webshell — webshell files in web directories
        5. macos_quarantine_bypass — xattr quarantine flag removal
        6. macos_sip_status — SIP disabled alert
        7. macos_hidden_file — new hidden files in sensitive locations
        8. macos_downloads_monitor — new files in ~/Downloads
    """

    def __init__(self, collection_interval: float = 60.0) -> None:
        device_id = socket.gethostname()

        Path(QUEUE_PATH).parent.mkdir(parents=True, exist_ok=True)
        queue_adapter = LocalQueueAdapter(
            queue_path=QUEUE_PATH,
            agent_name="macos_filesystem",
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,
            max_retries=10,
            signing_key_path=f"{CERT_DIR}/agent.ed25519",
        )

        super().__init__(
            agent_name="macos_filesystem",
            device_id=device_id,
            collection_interval=collection_interval,
            queue_adapter=queue_adapter,
        )

        self.collector = MacOSFileCollector(device_id=device_id)
        self.register_probes(create_filesystem_probes())

        logger.info(
            "MacOSFileAgent initialized: %d probes, device=%s",
            len(self._probes),
            device_id,
        )

    def setup(self) -> bool:
        """Verify macOS platform and initialize probes."""
        if platform.system() != "Darwin":
            logger.error("MacOSFileAgent requires macOS (Darwin)")
            return False

        if not self.setup_probes(
            collector_shared_data_keys=[
                "files",
                "sip_status",
                "suid_binaries",
                "collection_time_ms",
            ]
        ):
            logger.error("No probes initialized")
            return False

        logger.info("MacOSFileAgent setup complete")
        return True

    def collect_data(self) -> Sequence[Any]:
        """Run collector + probes, emit raw observations + detections."""
        snapshot = self.collector.collect()

        # Build OBSERVATION events for every file entry
        obs_events = self._make_observation_events(
            snapshot.get("files", []),
            domain="filesystem",
            field_mapper=self._file_to_obs,
        )

        # Run probes (detection events)
        context = self._create_probe_context()
        context.shared_data = snapshot
        probe_events = self.run_probes(context)

        all_events = obs_events + probe_events
        all_events.append(
            TelemetryEvent(
                event_type="collection_metadata",
                severity=Severity.DEBUG,
                probe_name="macos_filesystem_collector",
                data={
                    "total_files": len(snapshot["files"]),
                    "sip_status": snapshot["sip_status"],
                    "suid_count": len(snapshot["suid_binaries"]),
                    "collection_time_ms": snapshot["collection_time_ms"],
                    "observation_events": len(obs_events),
                    "probe_events": len(probe_events),
                },
            )
        )

        logger.info(
            "FIM collected in %.1fms: %d files, SIP=%s, "
            "%d observations, %d probe events",
            snapshot["collection_time_ms"],
            len(snapshot["files"]),
            snapshot["sip_status"],
            len(obs_events),
            len(probe_events),
        )

        if all_events:
            return [self._events_to_telemetry(all_events)]
        return []

    @staticmethod
    def _file_to_obs(entry) -> Dict[str, Any]:
        """Map a FileEntry to observation data dict."""
        return {
            "path": entry.path,
            "name": entry.name,
            "sha256": entry.sha256,
            "mtime": str(entry.mtime),
            "size": str(entry.size),
            "mode": str(entry.mode),
            "uid": str(entry.uid),
            "is_suid": str(entry.is_suid),
        }

    def _events_to_telemetry(self, events: List[TelemetryEvent]) -> Any:
        """Convert TelemetryEvents to protobuf DeviceTelemetry."""
        from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2

        timestamp_ns = int(time.time() * 1e9)
        proto_events = []

        for idx, event in enumerate(events):
            if event.event_type == "collection_metadata":
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"macos_filesystem_meta_{timestamp_ns}",
                    event_type="METRIC",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="macos_filesystem_collector",
                    metric_data=telemetry_pb2.MetricData(
                        metric_name="filesystem_collection",
                        metric_type="GAUGE",
                        numeric_value=float(event.data.get("total_files", 0)),
                        unit="files",
                    ),
                )
            elif event.event_type.startswith("obs_"):
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"macos_filesystem_obs_{idx}_{timestamp_ns}",
                    event_type="OBSERVATION",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="filesystem_collector",
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
            protocol="MACOS_FILESYSTEM",
            events=proto_events,
            timestamp_ns=timestamp_ns,
            collection_agent="macos_filesystem",
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
        logger.info("MacOSFileAgent shutting down")
