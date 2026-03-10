"""macOS Persistence Agent — Persistence Observatory for Darwin.

Monitors all macOS persistence mechanisms with 10 baseline-diff probes.
Each probe maintains its own baseline and alerts on additions, modifications,
and removals.

Data flow:
    1. MacOSPersistenceCollector.collect() → PersistenceEntry list
    2. Probes.scan(context) → TelemetryEvents (change detections)
    3. Agent converts events → DeviceTelemetry protobuf
    4. LocalQueueAdapter → WAL → EventBus
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
    ProbeContext,
    Severity,
    TelemetryEvent,
)
from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.agents.os.macos.persistence.collector import MacOSPersistenceCollector
from amoskys.agents.os.macos.persistence.probes import create_persistence_probes
from amoskys.config import get_config

logger = logging.getLogger(__name__)

config = get_config()
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = "data/queue/macos_persistence.db"


class MacOSPersistenceAgent(MicroProbeAgentMixin, HardenedAgentBase):
    """macOS Persistence Observatory agent.

    Monitors all persistence mechanisms with baseline-diff approach.
    First scan establishes baseline. Subsequent scans detect changes.
    """

    def __init__(self, collection_interval: float = 30.0) -> None:
        device_id = socket.gethostname()

        Path(QUEUE_PATH).parent.mkdir(parents=True, exist_ok=True)
        queue_adapter = LocalQueueAdapter(
            queue_path=QUEUE_PATH,
            agent_name="macos_persistence",
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,
            max_retries=10,
            signing_key_path=f"{CERT_DIR}/agent.ed25519",
        )

        super().__init__(
            agent_name="macos_persistence",
            device_id=device_id,
            collection_interval=collection_interval,
            queue_adapter=queue_adapter,
        )

        self.collector = MacOSPersistenceCollector()
        self.register_probes(create_persistence_probes())

        logger.info(
            "MacOSPersistenceAgent initialized: %d probes",
            len(self._probes),
        )

    def setup(self) -> bool:
        if platform.system() != "Darwin":
            logger.error("MacOSPersistenceAgent requires macOS")
            return False

        if not self.setup_probes(
            collector_shared_data_keys=[
                "entries",
                "categories",
                "total_count",
                "collection_time_ms",
            ]
        ):
            logger.error("No probes initialized")
            return False

        logger.info("MacOSPersistenceAgent setup complete")
        return True

    def collect_data(self) -> Sequence[Any]:
        """Run collector + probes, emit raw observations + detections."""
        snapshot = self.collector.collect()

        # Build OBSERVATION events for every persistence entry
        obs_events = self._make_observation_events(
            snapshot.get("entries", []),
            domain="persistence",
            field_mapper=self._persistence_to_obs,
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
                probe_name="macos_persistence_collector",
                data={
                    "total_entries": snapshot["total_count"],
                    "categories": snapshot["categories"],
                    "collection_time_ms": snapshot["collection_time_ms"],
                    "observation_events": len(obs_events),
                    "probe_events": len(probe_events),
                },
            )
        )

        logger.info(
            "Persistence collected in %.1fms: %d entries, "
            "%d observations, %d probe events",
            snapshot["collection_time_ms"],
            snapshot["total_count"],
            len(obs_events),
            len(probe_events),
        )

        if all_events:
            return [self._events_to_telemetry(all_events)]
        return []

    @staticmethod
    def _persistence_to_obs(entry) -> Dict[str, Any]:
        """Map a PersistenceEntry to observation data dict."""
        return {
            "category": entry.category,
            "path": entry.path,
            "name": entry.name,
            "content_hash": entry.content_hash,
            "program": entry.program,
            "label": entry.label,
            "run_at_load": str(entry.run_at_load),
            "keep_alive": str(entry.keep_alive),
        }

    def _events_to_telemetry(self, events: List[TelemetryEvent]) -> Any:
        from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2

        timestamp_ns = int(time.time() * 1e9)
        proto_events = []

        for idx, event in enumerate(events):
            if event.event_type == "collection_metadata":
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"macos_persistence_meta_{timestamp_ns}",
                    event_type="METRIC",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="macos_persistence_collector",
                )
            elif event.event_type.startswith("obs_"):
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"macos_persistence_obs_{idx}_{timestamp_ns}",
                    event_type="OBSERVATION",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="persistence_collector",
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
            protocol="MACOS_PERSISTENCE",
            events=proto_events,
            timestamp_ns=timestamp_ns,
            collection_agent="macos_persistence",
            agent_version="2.0.0",
        )

    def validate_event(self, event: Any) -> ValidationResult:
        errors = []
        if not hasattr(event, "device_id") or not event.device_id:
            errors.append("Missing device_id")
        if not hasattr(event, "timestamp_ns") or event.timestamp_ns == 0:
            errors.append("Missing timestamp_ns")
        return ValidationResult(is_valid=len(errors) == 0, errors=errors)

    def shutdown(self) -> None:
        logger.info("MacOSPersistenceAgent shutting down")
