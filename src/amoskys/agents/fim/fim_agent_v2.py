#!/usr/bin/env python3
"""AMOSKYS FIM Agent v2 - File Integrity Monitoring with Micro-Probe Architecture.

This is the modernized FIM agent using the "swarm of eyes" pattern.
8 micro-probes each watch one specific file tampering / persistence vector.

Probes:
    1. CriticalSystemFileChangeProbe - Binary/config modifications
    2. SUIDBitChangeProbe - SUID/SGID privilege escalation
    3. ServiceCreationProbe - LaunchAgent/systemd persistence
    4. WebShellDropProbe - Webshell detection
    5. ConfigBackdoorProbe - Backdoored SSH/sudo/PAM configs
    6. LibraryHijackProbe - LD_PRELOAD rootkit detection
    7. BootloaderTamperProbe - Bootkit/kernel tampering
    8. WorldWritableSensitiveProbe - Dangerous permission changes

MITRE ATT&CK Coverage:
    - T1036: Masquerading
    - T1547: Boot or Logon Autostart Execution
    - T1574: Hijack Execution Flow
    - T1505.003: Web Shell
    - T1548: Abuse Elevation Control Mechanism
    - T1556: Modify Authentication Process
    - T1014: Rootkit
    - T1542: Pre-OS Boot
    - T1565: Data Manipulation
    - T1070: Indicator Removal

Usage:
    >>> # First run: create baseline
    >>> agent = FIMAgentV2(baseline_mode="create")
    >>> agent.run_forever()

    >>> # Normal monitoring mode
    >>> agent = FIMAgentV2(baseline_mode="monitor")
    >>> agent.run_forever()
"""

from __future__ import annotations

import json
import logging
import os
import platform
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

import grpc

from amoskys.agents.common.base import HardenedAgentBase, ValidationResult
from amoskys.agents.common.probes import MicroProbeAgentMixin, TelemetryEvent
from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.agents.fim.probes import (
    ChangeType,
    FileChange,
    FileState,
    create_fim_probes,
)
from amoskys.config import get_config
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.proto import universal_telemetry_pb2_grpc as universal_pbrpc

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("FIMAgentV2")

config = get_config()
EVENTBUS_ADDRESS = config.agent.bus_address
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = getattr(config.agent, "fim_queue_path", "data/queue/fim_agent_v2.db")
BASELINE_PATH = getattr(config.agent, "fim_baseline_path", "data/fim_baseline.json")


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

        for device_telemetry in events:
            timestamp_ns = int(time.time() * 1e9)
            idempotency_key = f"{device_telemetry.device_id}_{timestamp_ns}"
            envelope = telemetry_pb2.UniversalEnvelope(
                version="v1",
                ts_ns=timestamp_ns,
                idempotency_key=idempotency_key,
                device_telemetry=device_telemetry,
                signing_algorithm="Ed25519",
                priority="NORMAL",
                requires_acknowledgment=True,
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
# Baseline Engine
# =============================================================================


class BaselineEngine:
    """Manages file integrity baseline (expected state of monitored files)."""

    def __init__(self, baseline_path: str):
        self.baseline_path = baseline_path
        self.baseline: Dict[str, FileState] = {}

    def load(self) -> bool:
        """Load baseline from disk.

        Returns:
            True if loaded successfully, False if baseline doesn't exist
        """
        if not Path(self.baseline_path).exists():
            logger.warning(f"Baseline not found: {self.baseline_path}")
            return False

        try:
            with open(self.baseline_path, "r") as f:
                data = json.load(f)

            # Convert JSON back to FileState objects
            for path, state_dict in data.items():
                self.baseline[path] = FileState(**state_dict)

            logger.info(f"Loaded baseline: {len(self.baseline)} files")
            return True

        except Exception as e:
            logger.error(f"Failed to load baseline: {e}")
            return False

    def save(self) -> None:
        """Save baseline to disk."""
        try:
            # Convert FileState objects to dicts
            data = {}
            for path, state in self.baseline.items():
                data[path] = {
                    "path": state.path,
                    "sha256": state.sha256,
                    "size": state.size,
                    "mode": state.mode,
                    "uid": state.uid,
                    "gid": state.gid,
                    "mtime_ns": state.mtime_ns,
                    "is_dir": state.is_dir,
                    "is_symlink": state.is_symlink,
                }

            # Ensure directory exists
            Path(self.baseline_path).parent.mkdir(parents=True, exist_ok=True)

            with open(self.baseline_path, "w") as f:
                json.dump(data, f, indent=2)

            logger.info(f"Saved baseline: {len(self.baseline)} files")

        except Exception as e:
            logger.error(f"Failed to save baseline: {e}")

    def create_from_paths(self, paths: List[str]) -> None:
        """Create baseline by scanning provided paths.

        Args:
            paths: List of directories to scan
        """
        self.baseline = {}

        for root_path in paths:
            if not os.path.exists(root_path):
                logger.warning(f"Path not found: {root_path}")
                continue

            logger.info(f"Scanning: {root_path}")

            # Walk directory tree
            for dirpath, dirnames, filenames in os.walk(root_path):
                # Add directory itself
                state = FileState.from_path(dirpath)
                if state:
                    self.baseline[dirpath] = state

                # Add files
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    state = FileState.from_path(filepath)
                    if state:
                        self.baseline[filepath] = state

        logger.info(f"Created baseline: {len(self.baseline)} files")
        self.save()

    def compare(self, current_state: Dict[str, FileState]) -> List[FileChange]:
        """Compare current state against baseline.

        Args:
            current_state: Current filesystem state

        Returns:
            List of detected changes
        """
        changes: List[FileChange] = []
        timestamp_ns = int(time.time() * 1e9)

        # Find modified and deleted files
        for path, baseline_state in self.baseline.items():
            current = current_state.get(path)

            if current is None:
                # File was deleted
                changes.append(
                    FileChange(
                        path=path,
                        change_type=ChangeType.DELETED,
                        old_state=baseline_state,
                        new_state=None,
                        timestamp_ns=timestamp_ns,
                    )
                )
            else:
                # File exists - check for changes
                change_type = self._detect_change_type(baseline_state, current)
                if change_type:
                    changes.append(
                        FileChange(
                            path=path,
                            change_type=change_type,
                            old_state=baseline_state,
                            new_state=current,
                            timestamp_ns=timestamp_ns,
                        )
                    )

        # Find newly created files
        for path, current_state in current_state.items():
            if path not in self.baseline:
                changes.append(
                    FileChange(
                        path=path,
                        change_type=ChangeType.CREATED,
                        old_state=None,
                        new_state=current_state,
                        timestamp_ns=timestamp_ns,
                    )
                )

        return changes

    @staticmethod
    def _detect_change_type(old: FileState, new: FileState) -> Optional[ChangeType]:
        """Detect specific type of change between two states.

        Returns:
            ChangeType if changed, None if identical
        """
        # Check hash (content) change
        if old.sha256 and new.sha256 and old.sha256 != new.sha256:
            return ChangeType.HASH_CHANGED

        # Check permissions
        if old.mode != new.mode:
            return ChangeType.PERM_CHANGED

        # Check ownership
        if old.uid != new.uid or old.gid != new.gid:
            return ChangeType.OWNER_CHANGED

        # Check modification time (for directories or when hash unavailable)
        if old.mtime_ns != new.mtime_ns:
            return ChangeType.MODIFIED

        return None


# =============================================================================
# FIM Agent V2
# =============================================================================


class FIMAgentV2(MicroProbeAgentMixin, HardenedAgentBase):
    """File Integrity Monitoring Agent with micro-probe architecture.

    This agent hosts 8 micro-probes that each monitor a specific file
    tampering / persistence vector. The agent handles:
        - Baseline creation and management
        - Filesystem scanning
        - Change detection
        - Probe lifecycle management
        - Event aggregation and publishing
        - Circuit breaker and retry logic
        - Offline queue management

    Probes are responsible only for detection - no file I/O or state management.
    """

    # Default paths to monitor
    DEFAULT_MONITOR_PATHS = [
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/etc",
        "/boot",
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
        "/var/www",
        "/srv/www",
        # macOS specific
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        "/System/Library/LaunchAgents",
        "/System/Library/LaunchDaemons",
    ]

    def __init__(
        self,
        collection_interval: float = 300.0,  # 5 minutes
        baseline_mode: str = "monitor",  # "create" or "monitor"
        monitor_paths: Optional[List[str]] = None,
    ):
        """Initialize FIM Agent v2.

        Args:
            collection_interval: Seconds between collection cycles
            baseline_mode: "create" to create baseline, "monitor" to detect changes
            monitor_paths: Paths to monitor (defaults to system critical paths)
        """
        device_id = socket.gethostname()

        # Create EventBus publisher
        publisher = EventBusPublisher(EVENTBUS_ADDRESS, CERT_DIR)

        # Create local queue
        Path(QUEUE_PATH).parent.mkdir(parents=True, exist_ok=True)
        queue_adapter = LocalQueueAdapter(
            queue_path=QUEUE_PATH,
            agent_name="fim_agent_v2",
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,
            max_retries=10,
        )

        # Initialize base classes
        super().__init__(
            agent_name="fim_agent_v2",
            device_id=device_id,
            collection_interval=collection_interval,
            eventbus_publisher=publisher,
            local_queue=queue_adapter,
        )

        # FIM-specific state
        self.baseline_mode = baseline_mode
        self.monitor_paths = monitor_paths or self._get_platform_paths()
        self.baseline_engine = BaselineEngine(BASELINE_PATH)

        # Register all FIM probes
        self.register_probes(create_fim_probes())

        logger.info(f"FIMAgentV2 initialized with {len(self._probes)} probes")
        logger.info(f"Baseline mode: {baseline_mode}")
        logger.info(f"Monitoring {len(self.monitor_paths)} paths")

    def _get_platform_paths(self) -> List[str]:
        """Get platform-appropriate monitoring paths."""
        paths = []
        for path in self.DEFAULT_MONITOR_PATHS:
            if os.path.exists(path):
                paths.append(path)
        return paths

    def setup(self) -> bool:
        """Initialize agent resources.

        Verifies:
            - Certificates exist
            - Baseline exists (or creates if in create mode)
            - Probes initialize successfully

        Returns:
            True if setup succeeded
        """
        try:
            import os

            # Verify certificates
            required_certs = ["ca.crt", "agent.crt", "agent.key"]
            for cert in required_certs:
                cert_path = f"{CERT_DIR}/{cert}"
                if not os.path.exists(cert_path):
                    logger.error(f"Certificate not found: {cert_path}")
                    return False

            # Handle baseline
            if self.baseline_mode == "create":
                logger.info("Creating baseline...")
                self.baseline_engine.create_from_paths(self.monitor_paths)
                logger.info("Baseline created. Switch to 'monitor' mode for detection.")
                return False  # Don't continue in create mode

            elif self.baseline_mode == "monitor":
                if not self.baseline_engine.load():
                    logger.error("Baseline not found. Run with baseline_mode='create' first.")
                    return False

            # Setup probes
            if not self.setup_probes():
                logger.error("No probes initialized successfully")
                return False

            logger.info("FIMAgentV2 setup complete")
            return True

        except Exception as e:
            logger.error(f"Setup failed: {e}")
            return False

    def collect_data(self) -> Sequence[Any]:
        """Scan filesystem and run all probes.

        Returns:
            List of DeviceTelemetry protobuf messages
        """
        # Scan current filesystem state
        current_state = self._scan_filesystem()
        logger.debug(f"Scanned {len(current_state)} files")

        # Compare against baseline
        changes = self.baseline_engine.compare(current_state)
        logger.info(f"Detected {len(changes)} file changes")

        if not changes:
            return []  # No changes, no events

        # Create context with file changes
        context = self._create_probe_context()
        context.shared_data["file_changes"] = changes
        context.shared_data["current_state"] = current_state
        context.shared_data["baseline"] = self.baseline_engine.baseline

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
                logger.error(f"Probe {probe.name} failed: {e}")

        logger.info(f"Probes generated {len(events)} events")

        # Convert to protobuf
        if events:
            return [self._events_to_telemetry(events, changes)]
        return []

    def _scan_filesystem(self) -> Dict[str, FileState]:
        """Scan monitored paths and build current state map.

        Returns:
            Dict mapping path -> FileState
        """
        current_state: Dict[str, FileState] = {}

        for root_path in self.monitor_paths:
            if not os.path.exists(root_path):
                continue

            # Walk directory tree
            for dirpath, dirnames, filenames in os.walk(root_path):
                # Add directory
                state = FileState.from_path(dirpath)
                if state:
                    current_state[dirpath] = state

                # Add files
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    state = FileState.from_path(filepath)
                    if state:
                        current_state[filepath] = state

        return current_state

    def _events_to_telemetry(
        self, events: List[TelemetryEvent], changes: List[FileChange]
    ) -> telemetry_pb2.DeviceTelemetry:
        """Convert TelemetryEvents to protobuf DeviceTelemetry.

        Args:
            events: List of TelemetryEvent objects from probes
            changes: List of FileChange objects

        Returns:
            DeviceTelemetry protobuf message
        """
        timestamp_ns = int(time.time() * 1e9)

        # Create telemetry events from probe output
        telemetry_events = []

        # Add basic metrics
        telemetry_events.append(
            telemetry_pb2.TelemetryEvent(
                event_id=f"fim_change_count_{timestamp_ns}",
                event_type="METRIC",
                severity="INFO",
                event_timestamp_ns=timestamp_ns,
                metric_data=telemetry_pb2.MetricData(
                    metric_name="fim_file_changes",
                    metric_type="GAUGE",
                    numeric_value=float(len(changes)),
                    unit="files",
                ),
                source_component="fim_agent",
                tags=["fim", "metric"],
            )
        )

        # Convert probe events to telemetry
        severity_map = {
            "DEBUG": "DEBUG",
            "INFO": "INFO",
            "LOW": "LOW",
            "MEDIUM": "MEDIUM",
            "HIGH": "HIGH",
            "CRITICAL": "CRITICAL",
        }

        for event in events:
            tel_event = telemetry_pb2.TelemetryEvent(
                event_id=f"{event.event_type}_{timestamp_ns}",
                event_type="ALERT" if event.severity.value in ("HIGH", "CRITICAL") else "METRIC",
                severity=severity_map.get(event.severity.value, "INFO"),
                event_timestamp_ns=timestamp_ns,
                source_component="fim_agent",
                tags=["fim", "threat"] + event.mitre_techniques,
            )

            # Add metric data
            tel_event.metric_data.CopyFrom(
                telemetry_pb2.MetricData(
                    metric_name=event.event_type,
                    metric_type="GAUGE",
                    numeric_value=1.0,
                    unit="threat_indicator",
                )
            )

            telemetry_events.append(tel_event)

        # Create device telemetry
        telemetry = telemetry_pb2.DeviceTelemetry(
            device_id=self.device_id,
            device_type="HOST",
            protocol="FIM",
            events=telemetry_events,
            timestamp_ns=timestamp_ns,
            collection_agent="fim-agent",
            agent_version="2.0.0",
        )

        return telemetry

    def validate_event(self, event: Any) -> ValidationResult:
        """Validate telemetry before publishing.

        Args:
            event: DeviceTelemetry protobuf message

        Returns:
            ValidationResult
        """
        errors = []

        if not event.device_id:
            errors.append("device_id required")
        if event.timestamp_ns <= 0:
            errors.append("timestamp_ns must be positive")
        if not event.events:
            errors.append("events list is empty")

        return ValidationResult(is_valid=len(errors) == 0, errors=errors)

    def shutdown(self) -> None:
        """Graceful shutdown."""
        logger.info("FIMAgentV2 shutting down...")

        # Close EventBus connection
        if self.eventbus_publisher:
            self.eventbus_publisher.close()

        logger.info("FIMAgentV2 shutdown complete")

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
            "baseline_files": len(self.baseline_engine.baseline),
        }


# =============================================================================
# CLI Entry Point
# =============================================================================


def main():
    """Run FIM Agent v2."""
    import argparse

    parser = argparse.ArgumentParser(description="AMOSKYS FIM Agent v2")
    parser.add_argument(
        "--interval",
        type=float,
        default=300.0,
        help="Collection interval in seconds",
    )
    parser.add_argument(
        "--mode",
        choices=["create", "monitor"],
        default="monitor",
        help="Baseline mode: create or monitor",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info("=" * 70)
    logger.info("AMOSKYS FIM Agent v2 (Micro-Probe Architecture)")
    logger.info("=" * 70)

    agent = FIMAgentV2(
        collection_interval=args.interval,
        baseline_mode=args.mode,
    )

    if args.mode == "create":
        logger.info("Baseline creation complete. Exiting.")
        return

    try:
        agent.run_forever()
    except KeyboardInterrupt:
        logger.info("Received interrupt, shutting down...")
        agent.shutdown()


if __name__ == "__main__":
    main()
