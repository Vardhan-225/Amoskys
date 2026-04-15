"""macOS InfostealerGuard Agent — AMOS/Poseidon/Banshee Kill Chain Detector.

Purpose-built infostealer detection agent for macOS. Uses the AMOSKYS canonical
agent pattern (MicroProbeAgentMixin + HardenedAgentBase) with a macOS-specific
collector and 10 detection probes targeting the complete infostealer kill chain.

Data flow:
    1. MacOSInfostealerGuardCollector.collect() -> sensitive accesses, suspicious
       processes, PID connections (lsof + psutil)
    2. Probes.scan(context) -> TelemetryEvents (detections)
    3. Agent converts events -> DeviceTelemetry protobuf
    4. LocalQueueAdapter -> WAL -> EventBus

Kill chain coverage:
    - Credential harvesting: Keychain (T1555.001), Browsers (T1555.003), Wallets (T1005)
    - Input capture: Fake password dialogs (T1056.002)
    - Collection: Session cookies (T1539), Clipboard (T1115), Screen capture (T1113)
    - Staging: Credential archiving (T1560.001)
    - Exfiltration: Outbound connections from credential PIDs (T1041)
    - Behavioral: Multi-category access sequence detection (T1005)

Usage:
    agent = MacOSInfostealerGuardAgent()
    agent.run()  # Enters main loop
"""

from __future__ import annotations

import json
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
from amoskys.agents.os.macos.infostealer_guard.collector import (
    MacOSInfostealerGuardCollector,
)
from amoskys.agents.os.macos.infostealer_guard.probes import (
    create_infostealer_guard_probes,
)
from amoskys.config import get_config

logger = logging.getLogger(__name__)

config = get_config()
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = "data/queue/macos_infostealer_guard.db"


class MacOSInfostealerGuardAgent(MicroProbeAgentMixin, HardenedAgentBase):
    """macOS InfostealerGuard Observatory agent.

    Monitors for the AMOS/Poseidon/Banshee infostealer kill chain on macOS
    via 10 detection probes covering credential theft, fake dialogs, archiving,
    and exfiltration.

    Probes:
        1.  macos_infostealer_keychain_access      — non-expected keychain access
        2.  macos_infostealer_browser_cred_theft    — browser credential store theft
        3.  macos_infostealer_crypto_wallet_theft   — crypto wallet file theft
        4.  macos_infostealer_fake_dialog           — osascript password phishing
        5.  macos_infostealer_stealer_sequence      — multi-category sweep detection
        6.  macos_infostealer_credential_archive    — credential staging via archive
        7.  macos_infostealer_session_cookie_theft  — Chrome session cookie theft
        8.  macos_infostealer_clipboard_harvest     — clipboard data collection
        9.  macos_infostealer_screen_capture_abuse  — non-standard screen capture
        10. macos_infostealer_sensitive_file_exfil  — credential PID with outbound conn
    """

    MANDATE_DATA_FIELDS = ("file_path", "file_name", "pid", "process_name")

    def __init__(self, collection_interval: float = 15.0) -> None:
        device_id = socket.gethostname()

        # Local queue for offline resilience
        Path(QUEUE_PATH).parent.mkdir(parents=True, exist_ok=True)
        queue_adapter = LocalQueueAdapter(
            queue_path=QUEUE_PATH,
            agent_name="macos_infostealer_guard",
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,
            max_retries=10,
            signing_key_path=f"{CERT_DIR}/agent.ed25519",
        )

        super().__init__(
            agent_name="macos_infostealer_guard",
            device_id=device_id,
            collection_interval=collection_interval,
            queue_adapter=queue_adapter,
        )

        self.collector = MacOSInfostealerGuardCollector(device_id=device_id)
        self.register_probes(create_infostealer_guard_probes())

        logger.info(
            "MacOSInfostealerGuardAgent initialized: %d probes, device=%s",
            len(self._probes),
            device_id,
        )

    def setup(self) -> bool:
        """Verify macOS platform, psutil, and initialize probes."""
        if platform.system() != "Darwin":
            logger.error("MacOSInfostealerGuardAgent requires macOS (Darwin)")
            return False

        # Verify psutil works
        try:
            import psutil

            count = len(list(psutil.process_iter(["pid"])))
            logger.info("psutil OK: %d processes visible", count)
        except Exception as e:
            logger.error("psutil verification failed: %s", e)
            return False

        # Setup probes with collector's shared_data keys
        if not self.setup_probes(
            collector_shared_data_keys=[
                "sensitive_accesses",
                "suspicious_processes",
                "pid_connections",
                "process_snapshot",
                "staging_archives",
                "access_count",
                "collection_time_ms",
            ]
        ):
            logger.error("No probes initialized")
            return False

        logger.info("MacOSInfostealerGuardAgent setup complete")
        return True

    def collect_data(self) -> Sequence[Any]:
        """Run collector + probes, emit raw observations + detections."""
        # Step 1: Collect infostealer telemetry
        snapshot = self.collector.collect()

        # Step 2: Build OBSERVATION events for every sensitive file access
        obs_events = self._make_observation_events(
            snapshot["sensitive_accesses"],
            domain="infostealer",
            field_mapper=self._access_to_obs,
        )

        # Step 3: Run probes (detection events)
        context = self._create_probe_context()
        context.shared_data = snapshot
        probe_events = self.run_probes(context)

        # Step 3.5: Publish WATCH_PID for any PID that triggered a detection
        self._publish_tactical_watches(probe_events)

        # Step 4: Combine observations + probe detections + metadata
        all_events = obs_events + probe_events
        all_events.append(
            TelemetryEvent(
                event_type="collection_metadata",
                severity=Severity.DEBUG,
                probe_name="macos_infostealer_guard_collector",
                data={
                    "access_count": snapshot["access_count"],
                    "suspicious_process_count": len(snapshot["suspicious_processes"]),
                    "pid_connection_count": len(snapshot["pid_connections"]),
                    "process_snapshot_count": len(snapshot["process_snapshot"]),
                    "collection_time_ms": snapshot["collection_time_ms"],
                    "probe_events": len(probe_events),
                    "observation_events": len(obs_events),
                },
            )
        )

        logger.info(
            "Collected: %d sensitive accesses, %d suspicious processes, "
            "%d PID connections in %.1fms, %d observations, %d probe events",
            snapshot["access_count"],
            len(snapshot["suspicious_processes"]),
            len(snapshot["pid_connections"]),
            snapshot["collection_time_ms"],
            len(obs_events),
            len(probe_events),
        )

        # Step 5: Convert to protobuf
        if all_events:
            return [self._events_to_telemetry(all_events)]
        return []

    # --------------- Tactical Bus Integration --------------------------------

    # Probes whose detections should trigger WATCH_PID on peer agents.
    _WATCH_WORTHY_TECHNIQUES = frozenset(
        {
            "T1555.001",  # Keychain access
            "T1555.003",  # Browser credential theft
            "T1005",  # Crypto wallet / data from local system
            "T1056.002",  # Fake password dialog
            "T1539",  # Session cookie theft
            "T1552.004",  # SSH private key theft
            "T1560.001",  # Credential archiving
            "T1041",  # Exfiltration over C2
        }
    )

    def _publish_tactical_watches(self, probe_events: List[TelemetryEvent]) -> None:
        """Publish WATCH_PID for PIDs that triggered credential-access probes.

        This is the lateral nervous system activation: when InfostealerGuard
        detects credential theft by PID 4523, it publishes WATCH_PID so that
        Network, DNS, and Process agents immediately focus on that PID.
        """
        seen_pids: set[str] = set()
        for event in probe_events:
            pid = str(event.data.get("pid", ""))
            if not pid or pid in seen_pids:
                continue
            # Only publish for watch-worthy MITRE techniques
            techniques = set(event.mitre_techniques or [])
            matching = techniques & self._WATCH_WORTHY_TECHNIQUES
            if not matching:
                continue
            seen_pids.add(pid)
            technique_str = ",".join(sorted(matching))
            self.coordination_publish_watch(
                topic="WATCH_PID",
                value=pid,
                reason=f"{event.probe_name}_{technique_str}",
                urgency=(
                    "HIGH" if event.severity.value in ("HIGH", "CRITICAL") else "MEDIUM"
                ),
                mitre_technique=technique_str,
                ttl_seconds=300.0,
            )

    @staticmethod
    def _access_to_obs(access) -> Dict[str, Any]:
        """Map a SensitiveFileAccess to observation data dict."""
        return {
            "pid": str(access.pid),
            "process_name": access.process_name,
            "file_path": access.file_path,
            "access_category": access.access_category,
            "process_guid": access.process_guid,
        }

    def _events_to_telemetry(self, events: List[TelemetryEvent]) -> Any:
        """Convert TelemetryEvents to protobuf DeviceTelemetry."""
        from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2

        timestamp_ns = int(time.time() * 1e9)
        proto_events = []

        for idx, event in enumerate(events):
            if event.event_type == "collection_metadata":
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"macos_infostealer_guard_meta_{timestamp_ns}",
                    event_type="METRIC",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="macos_infostealer_guard_collector",
                    metric_data=telemetry_pb2.MetricData(
                        metric_name="infostealer_collection",
                        metric_type="GAUGE",
                        numeric_value=float(event.data.get("access_count", 0)),
                        unit="accesses",
                    ),
                )
            elif event.event_type.startswith("obs_"):
                # Raw observation — no SecurityEvent sub-message
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"macos_infostealer_guard_obs_{idx}_{timestamp_ns}",
                    event_type="OBSERVATION",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="infostealer_collector",
                    confidence_score=0.0,
                )
                for k, v in event.data.items():
                    proto_event.attributes[k] = str(v)
            else:
                # Probe detection — SecurityEvent
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
            protocol="MACOS_INFOSTEALER_GUARD",
            events=proto_events,
            timestamp_ns=timestamp_ns,
            collection_agent="macos_infostealer_guard",
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
        logger.info("MacOSInfostealerGuardAgent shutting down")


# =============================================================================
# CLI Entry Point
# =============================================================================


def main():
    """Run macOS InfostealerGuard Agent."""
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    parser = argparse.ArgumentParser(description="AMOSKYS macOS InfostealerGuard Agent")
    parser.add_argument("--interval", type=float, default=15.0)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info("=" * 60)
    logger.info("AMOSKYS macOS InfostealerGuard Observatory")
    logger.info("Kill chain: AMOS / Poseidon / Banshee")
    logger.info("=" * 60)

    agent = MacOSInfostealerGuardAgent(collection_interval=args.interval)
    try:
        agent.run()
    except KeyboardInterrupt:
        agent.shutdown()


if __name__ == "__main__":
    main()
