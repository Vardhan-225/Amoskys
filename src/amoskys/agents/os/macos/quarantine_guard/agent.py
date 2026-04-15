"""macOS Quarantine Guard Agent — Download Provenance Observatory for Darwin.

Purpose-built download provenance and Gatekeeper bypass detection agent for
macOS. Uses the AMOSKYS canonical agent pattern (MicroProbeAgentMixin +
HardenedAgentBase) with a macOS-specific collector and 8 detection probes.

Data flow:
    1. MacOSQuarantineGuardCollector.collect() -> quarantine DB, xattr scan,
       DMG mounts, terminal children, process snapshot
    2. Probes.scan(context) -> TelemetryEvents (detections)
    3. Agent converts events -> DeviceTelemetry protobuf
    4. LocalQueueAdapter -> WAL -> EventBus

Detection probes:
    1. quarantine_bypass          - xattr removal (T1553.001)
    2. dmg_mount_execute          - DMG-based execution (T1204.002)
    3. clickfix_detection         - messaging app paste attack (T1204.001)
    4. unsigned_download_exec     - unsigned binary from Downloads (T1553)
    5. cli_download_execute       - CLI download bypass (T1105)
    6. suspicious_download_source - unknown download domain (T1566)
    7. installer_script_abuse     - installer spawns suspicious child (T1059.002)
    8. quarantine_evasion_pattern - no xattr + process running (T1553.001)

Usage:
    agent = MacOSQuarantineGuardAgent()
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
from amoskys.agents.os.macos.quarantine_guard.collector import (
    MacOSQuarantineGuardCollector,
)
from amoskys.agents.os.macos.quarantine_guard.probes import (
    create_quarantine_guard_probes,
)
from amoskys.config import get_config

logger = logging.getLogger(__name__)

config = get_config()
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = "data/queue/macos_quarantine_guard.db"


class MacOSQuarantineGuardAgent(MicroProbeAgentMixin, HardenedAgentBase):
    """macOS Quarantine Guard Observatory agent.

    Monitors download provenance, Gatekeeper bypass attempts, DMG-based
    delivery, ClickFix social engineering, and CLI download evasion on
    macOS via 8 detection probes.

    Probes:
        1. quarantine_bypass          — xattr removal detection
        2. dmg_mount_execute          — DMG mount-point execution
        3. clickfix_detection         — messaging + terminal paste attack
        4. unsigned_download_exec     — unsigned binary from Downloads/tmp
        5. cli_download_execute       — CLI download bypasses quarantine
        6. suspicious_download_source — download from unknown domain
        7. installer_script_abuse     — installer spawns suspicious child
        8. quarantine_evasion_pattern — no xattr + process running from path
    """

    MANDATE_DATA_FIELDS = ("file_path", "file_name", "pid", "process_name")

    def __init__(self, collection_interval: float = 30.0) -> None:
        device_id = socket.gethostname()

        # Local queue for offline resilience
        Path(QUEUE_PATH).parent.mkdir(parents=True, exist_ok=True)
        queue_adapter = LocalQueueAdapter(
            queue_path=QUEUE_PATH,
            agent_name="macos_quarantine_guard",
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,
            max_retries=10,
            signing_key_path=f"{CERT_DIR}/agent.ed25519",
        )

        super().__init__(
            agent_name="macos_quarantine_guard",
            device_id=device_id,
            collection_interval=collection_interval,
            queue_adapter=queue_adapter,
        )

        self.collector = MacOSQuarantineGuardCollector(device_id=device_id)
        self.register_probes(create_quarantine_guard_probes())

        logger.info(
            "MacOSQuarantineGuardAgent initialized: %d probes, device=%s",
            len(self._probes),
            device_id,
        )

    def setup(self) -> bool:
        """Verify macOS platform, sqlite3, Downloads directory, and initialize probes."""
        if platform.system() != "Darwin":
            logger.error("MacOSQuarantineGuardAgent requires macOS (Darwin)")
            return False

        # Verify sqlite3 works (needed for quarantine DB)
        try:
            import sqlite3

            logger.info("sqlite3 OK: version %s", sqlite3.sqlite_version)
        except Exception as e:
            logger.error("sqlite3 verification failed: %s", e)
            return False

        # Check ~/Downloads existence (non-fatal — collector handles absence)
        downloads_dir = Path.home() / "Downloads"
        if downloads_dir.exists():
            logger.info("~/Downloads OK: %s", downloads_dir)
        else:
            logger.warning("~/Downloads not found — download xattr scan will be empty")

        # Setup probes with collector's shared_data keys
        if not self.setup_probes(
            collector_shared_data_keys=[
                "quarantine_entries",
                "downloaded_files",
                "mounted_dmgs",
                "terminal_children",
                "messaging_apps_running",
                "xattr_removal_processes",
                "xattr_removals",
                "installer_processes",
                "process_snapshot",
                "collection_time_ms",
            ]
        ):
            logger.error("No probes initialized")
            return False

        logger.info("MacOSQuarantineGuardAgent setup complete")
        return True

    def collect_data(self) -> Sequence[Any]:
        """Run collector + probes, emit raw observations + detections."""
        # Step 1: Collect quarantine and process data
        snapshot = self.collector.collect()

        # Step 2: Build OBSERVATION events for quarantine entries
        obs_events = self._make_observation_events(
            snapshot["quarantine_entries"],
            domain="quarantine",
            field_mapper=self._quarantine_entry_to_obs,
        )

        # Also emit observations for downloaded files
        obs_events += self._make_observation_events(
            snapshot["downloaded_files"],
            domain="quarantine",
            field_mapper=self._downloaded_file_to_obs,
        )

        # Step 3: Run probes (detection events)
        context = self._create_probe_context()
        context.shared_data = snapshot
        probe_events = self.run_probes(context)

        # Step 4: Combine observations + probe detections + metadata
        all_events = obs_events + probe_events
        all_events.append(
            TelemetryEvent(
                event_type="collection_metadata",
                severity=Severity.DEBUG,
                probe_name="macos_quarantine_guard_collector",
                data={
                    "quarantine_entries": len(snapshot["quarantine_entries"]),
                    "downloaded_files": len(snapshot["downloaded_files"]),
                    "mounted_dmgs": len(snapshot["mounted_dmgs"]),
                    "terminal_children": len(snapshot["terminal_children"]),
                    "messaging_apps_running": snapshot["messaging_apps_running"],
                    "xattr_removal_processes": len(snapshot["xattr_removal_processes"]),
                    "installer_processes": len(snapshot["installer_processes"]),
                    "process_snapshot_count": len(snapshot["process_snapshot"]),
                    "collection_time_ms": snapshot["collection_time_ms"],
                    "probe_events": len(probe_events),
                    "observation_events": len(obs_events),
                },
            )
        )

        logger.info(
            "Collected: %d quarantine entries, %d downloads, %d DMGs, "
            "%d terminal children in %.1fms, %d observations, %d probe events",
            len(snapshot["quarantine_entries"]),
            len(snapshot["downloaded_files"]),
            len(snapshot["mounted_dmgs"]),
            len(snapshot["terminal_children"]),
            snapshot["collection_time_ms"],
            len(obs_events),
            len(probe_events),
        )

        # Step 5: Convert to protobuf
        if all_events:
            return [self._events_to_telemetry(all_events)]
        return []

    @staticmethod
    def _quarantine_entry_to_obs(entry) -> Dict[str, Any]:
        """Map a QuarantineEntry to observation data dict."""
        return {
            "timestamp": str(entry.timestamp),
            "agent_bundle_id": entry.agent_bundle_id,
            "data_url": entry.data_url,
            "origin_url": entry.origin_url,
            "sender_name": entry.sender_name,
            "type_number": str(entry.type_number),
        }

    @staticmethod
    def _downloaded_file_to_obs(f) -> Dict[str, Any]:
        """Map a DownloadedFile to observation data dict."""
        return {
            "path": f.path,
            "filename": f.filename,
            "has_quarantine_xattr": str(f.has_quarantine_xattr),
            "quarantine_value": f.quarantine_value,
            "modify_time": str(f.modify_time),
            "size": str(f.size),
        }

    def _events_to_telemetry(self, events: List[TelemetryEvent]) -> Any:
        """Convert TelemetryEvents to protobuf DeviceTelemetry."""
        from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2

        timestamp_ns = int(time.time() * 1e9)
        proto_events = []

        for idx, event in enumerate(events):
            if event.event_type == "collection_metadata":
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"macos_quarantine_guard_meta_{timestamp_ns}",
                    event_type="METRIC",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="macos_quarantine_guard_collector",
                    metric_data=telemetry_pb2.MetricData(
                        metric_name="quarantine_guard_collection",
                        metric_type="GAUGE",
                        numeric_value=float(event.data.get("quarantine_entries", 0)),
                        unit="entries",
                    ),
                )
            elif event.event_type.startswith("obs_"):
                # Raw observation — no SecurityEvent sub-message
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"macos_quarantine_guard_obs_{idx}_{timestamp_ns}",
                    event_type="OBSERVATION",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="quarantine_guard_collector",
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
            protocol="MACOS_QUARANTINE_GUARD",
            events=proto_events,
            timestamp_ns=timestamp_ns,
            collection_agent="macos_quarantine_guard",
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
        logger.info("MacOSQuarantineGuardAgent shutting down")


# =============================================================================
# CLI Entry Point
# =============================================================================


def main():
    """Run macOS Quarantine Guard Agent."""
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    parser = argparse.ArgumentParser(description="AMOSKYS macOS Quarantine Guard Agent")
    parser.add_argument("--interval", type=float, default=30.0)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info("=" * 60)
    logger.info("AMOSKYS macOS Quarantine Guard Observatory")
    logger.info("=" * 60)

    agent = MacOSQuarantineGuardAgent(collection_interval=args.interval)
    try:
        agent.run()
    except KeyboardInterrupt:
        agent.shutdown()


if __name__ == "__main__":
    main()
