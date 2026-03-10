"""macOS Auth Agent -- Auth Observatory for Darwin.

Purpose-built authentication monitoring agent for macOS. Uses the AMOSKYS
canonical agent pattern (MicroProbeAgentMixin + HardenedAgentBase) with a
macOS Unified Logging collector and 6 detection probes.

Data flow:
    1. MacOSAuthCollector.collect() -> auth events (log show --predicate)
    2. Probes.scan(context) -> TelemetryEvents (detections)
    3. Agent converts events -> DeviceTelemetry protobuf
    4. LocalQueueAdapter -> WAL -> EventBus

Usage:
    agent = MacOSAuthAgent()
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
    ProbeContext,
    Severity,
    TelemetryEvent,
)
from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.agents.os.macos.auth.collector import MacOSAuthCollector
from amoskys.agents.os.macos.auth.probes import create_auth_probes
from amoskys.config import get_config

logger = logging.getLogger(__name__)

config = get_config()
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = "data/queue/macos_auth.db"


class MacOSAuthAgent(MicroProbeAgentMixin, HardenedAgentBase):
    """macOS Auth Observatory agent.

    Monitors authentication activity on macOS via Unified Logging with
    6 detection probes.

    Probes:
        1. macos_ssh_brute_force   -- SSH brute-force detection
        2. macos_sudo_escalation   -- sudo privilege escalation
        3. macos_off_hours_login   -- login outside business hours
        4. macos_impossible_travel -- SSH from different IPs rapidly
        5. macos_account_lockout   -- repeated auth failures
        6. macos_credential_access -- Keychain credential access
    """

    def __init__(self, collection_interval: float = 30.0) -> None:
        device_id = socket.gethostname()

        # Local queue for offline resilience
        Path(QUEUE_PATH).parent.mkdir(parents=True, exist_ok=True)
        queue_adapter = LocalQueueAdapter(
            queue_path=QUEUE_PATH,
            agent_name="macos_auth",
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,
            max_retries=10,
            signing_key_path=f"{CERT_DIR}/agent.ed25519",
        )

        super().__init__(
            agent_name="macos_auth",
            device_id=device_id,
            collection_interval=collection_interval,
            queue_adapter=queue_adapter,
        )

        self.collector = MacOSAuthCollector(
            window_seconds=int(collection_interval),
            device_id=device_id,
        )
        self.register_probes(create_auth_probes())

        logger.info(
            "MacOSAuthAgent initialized: %d probes, device=%s",
            len(self._probes),
            device_id,
        )

    def setup(self) -> bool:
        """Verify macOS platform and initialize probes."""
        if platform.system() != "Darwin":
            logger.error("MacOSAuthAgent requires macOS (Darwin)")
            return False

        # Verify log command is available
        import subprocess

        try:
            result = subprocess.run(
                [
                    "log",
                    "show",
                    "--last",
                    "1s",
                    "--style",
                    "json",
                    "--predicate",
                    'process == "sshd"',
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            logger.info("macOS 'log show' OK (returncode=%d)", result.returncode)
        except FileNotFoundError:
            logger.error("'log' command not found -- cannot collect auth events")
            return False
        except Exception as e:
            logger.warning("log show verification had issue: %s (continuing)", e)

        # Setup probes with collector's shared_data keys
        if not self.setup_probes(
            collector_shared_data_keys=[
                "auth_events",
                "event_count",
                "collection_time_ms",
            ]
        ):
            logger.error("No probes initialized")
            return False

        logger.info("MacOSAuthAgent setup complete")
        return True

    def collect_data(self) -> Sequence[Any]:
        """Run collector + probes, emit raw observations + detections."""
        snapshot = self.collector.collect()

        # Build OBSERVATION events for every raw auth event
        obs_events = self._make_observation_events(
            snapshot.get("auth_events", []),
            domain="auth",
            field_mapper=self._auth_to_obs,
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
                probe_name="macos_auth_collector",
                data={
                    "auth_events": snapshot["event_count"],
                    "collection_time_ms": snapshot["collection_time_ms"],
                    "observation_events": len(obs_events),
                    "probe_events": len(probe_events),
                },
            )
        )

        logger.info(
            "Auth collected in %.1fms: %d events, %d observations, %d probe events",
            snapshot["collection_time_ms"],
            snapshot["event_count"],
            len(obs_events),
            len(probe_events),
        )

        if all_events:
            return [self._events_to_telemetry(all_events)]
        return []

    @staticmethod
    def _auth_to_obs(event) -> Dict[str, Any]:
        """Map an AuthEvent to observation data dict."""
        return {
            "timestamp": str(event.timestamp),
            "process": event.process,
            "message": event.message,
            "category": event.category,
            "source_ip": event.source_ip or "",
            "username": event.username or "",
            "event_type": event.event_type,
        }

    def _events_to_telemetry(self, events: List[TelemetryEvent]) -> Any:
        """Convert TelemetryEvents to protobuf DeviceTelemetry."""
        from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2

        timestamp_ns = int(time.time() * 1e9)
        proto_events = []

        for idx, event in enumerate(events):
            if event.event_type == "collection_metadata":
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"macos_auth_meta_{timestamp_ns}",
                    event_type="METRIC",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="macos_auth_collector",
                    metric_data=telemetry_pb2.MetricData(
                        metric_name="auth_collection",
                        metric_type="GAUGE",
                        numeric_value=float(event.data.get("auth_events", 0)),
                        unit="events",
                    ),
                )
            elif event.event_type.startswith("obs_"):
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"macos_auth_obs_{idx}_{timestamp_ns}",
                    event_type="OBSERVATION",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="auth_collector",
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

                username = event.data.get("username")
                if username:
                    security_event.user_name = str(username)

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
            protocol="MACOS_AUTH",
            events=proto_events,
            timestamp_ns=timestamp_ns,
            collection_agent="macos_auth",
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
        logger.info("MacOSAuthAgent shutting down")
