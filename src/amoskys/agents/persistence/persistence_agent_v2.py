#!/usr/bin/env python3
"""PersistenceGuardV2 - Persistence Mechanism Monitoring with Micro-Probe Architecture.

Monitors autostart mechanisms and persistence techniques for threat detection:
    - macOS LaunchAgents/LaunchDaemons
    - Linux systemd services
    - Cron jobs and anacron @reboot
    - SSH authorized_keys backdoors
    - Shell profile hijacking
    - Browser extension persistence
    - GUI startup items
    - Hidden executable loaders

Architecture:
    - PersistenceCollector: Platform-specific persistence enumeration
    - PersistenceBaselineEngine: Snapshot & diff management
    - 8 Micro-Probes: Specialized threat detectors
    - HardenedAgentBase: Circuit breaker + offline resilience

CLI Usage:
    ```bash
    # Create baseline
    python persistence_agent_v2.py --mode create

    # Monitor for changes
    python persistence_agent_v2.py --mode monitor --interval 300
    ```

MITRE ATT&CK Coverage:
    - T1037: Logon Scripts / Autostart
    - T1053.003: Cron
    - T1098.004: SSH Authorized Keys
    - T1176: Browser Extensions
    - T1543: Create or Modify System Process
    - T1546.004: Shell Profiles
    - T1547: Boot or Logon Autostart Execution
    - T1564: Hide Artifacts
"""

from __future__ import annotations

import argparse
import logging
import socket
import time
from typing import Any, Dict, Optional, Sequence

from amoskys.agents.common.base import HardenedAgentBase
from amoskys.agents.common.probes import MicroProbeAgentMixin, ProbeContext
from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.agents.persistence.probes import (
    PersistenceBaselineEngine,
    PersistenceEntry,
    create_persistence_probes,
)
from amoskys.messaging_pb2 import DeviceTelemetry, TelemetryEvent as ProtoEvent

logger = logging.getLogger(__name__)


# =============================================================================
# Persistence Collector (Platform-Specific)
# =============================================================================


class PersistenceCollector:
    """Platform-specific persistence mechanism collector.

    Collects snapshot of all persistence mechanisms:
        - systemd: systemctl list-unit-files, parse ExecStart from unit files
        - cron: parse /etc/crontab, /etc/cron.d/*, crontab -l per user
        - shell profiles: hash ~/.bashrc, ~/.profile, etc.
        - SSH keys: hash & count authorized_keys
        - launchd (macOS): enumerate LaunchAgents/LaunchDaemons
        - startup items: .desktop files (Linux), login items (macOS)

    For now, this is a stub that returns empty snapshot.
    TODO: Implement actual persistence enumeration for each platform.
    """

    def __init__(self):
        """Initialize persistence collector."""
        self.entries_collected = 0

    def collect_snapshot(self) -> Dict[str, PersistenceEntry]:
        """Enumerate all persistence mechanisms on this host.

        Returns:
            Dictionary mapping entry_id to PersistenceEntry
        """
        # TODO: Implement actual persistence collection
        # Options:
        #   1. systemd: systemctl list-unit-files --type=service
        #   2. cron: parse /etc/crontab, /etc/cron.d/*, crontab -l
        #   3. launchd: enumerate /Library/LaunchAgents, /Library/LaunchDaemons
        #   4. SSH keys: parse ~/.ssh/authorized_keys for all users
        #   5. Shell profiles: hash ~/.bashrc, ~/.bash_profile, ~/.zshrc, etc.
        #   6. Browser extensions: enumerate Chrome/Firefox extension dirs
        #   7. Startup items: parse ~/.config/autostart/*.desktop (Linux)
        #   8. Hidden files: find hidden executables referenced by other mechanisms

        logger.debug("Collecting persistence snapshot")

        # Placeholder: return empty snapshot
        # In production, this would return actual PersistenceEntry objects
        snapshot: Dict[str, PersistenceEntry] = {}

        self.entries_collected += len(snapshot)
        return snapshot


# =============================================================================
# PersistenceGuardV2 - Main Agent
# =============================================================================


class PersistenceGuardV2(MicroProbeAgentMixin, HardenedAgentBase):
    """Persistence monitoring agent with micro-probe architecture.

    Monitors persistence mechanisms using 8 specialized threat detectors:
        1. LaunchAgentDaemonProbe - macOS launchd persistence
        2. SystemdServicePersistenceProbe - Linux systemd services
        3. CronJobPersistenceProbe - cron/anacron @reboot
        4. SSHKeyBackdoorProbe - authorized_keys tampering
        5. ShellProfileHijackProbe - bashrc/zshrc hijacking
        6. BrowserExtensionPersistenceProbe - malicious extensions
        7. StartupFolderLoginItemProbe - GUI autostart items
        8. HiddenFilePersistenceProbe - hidden executable loaders
    """

    AGENT_NAME = "persistence_guard_v2"
    COLLECTION_INTERVAL_SECONDS = 300.0  # 5 minutes default

    def __init__(
        self,
        device_id: Optional[str] = None,
        queue_path: str = "data/queue/persistence_guard_v2.db",
        baseline_mode: str = "monitor",  # "create" or "monitor"
        baseline_path: str = "data/persistence_baseline.json",
        collection_interval: float = COLLECTION_INTERVAL_SECONDS,
    ):
        """Initialize PersistenceGuardV2.

        Args:
            device_id: Unique device identifier (defaults to hostname)
            queue_path: Path to local queue database
            baseline_mode: "create" to create baseline, "monitor" to detect changes
            baseline_path: Path to baseline JSON file
            collection_interval: Persistence check interval in seconds
        """
        # Get device ID
        if device_id is None:
            device_id = socket.gethostname()

        # Initialize base classes
        HardenedAgentBase.__init__(
            self,
            agent_name=self.AGENT_NAME,
            device_id=device_id,
            collection_interval=collection_interval,
            queue_adapter=LocalQueueAdapter(queue_path),
        )

        MicroProbeAgentMixin.__init__(self, probes=create_persistence_probes())

        # Initialize collector and baseline engine
        self.collector = PersistenceCollector()
        self.baseline_engine = PersistenceBaselineEngine(baseline_path)
        self.baseline_mode = baseline_mode

        # Load baseline if in monitor mode
        if self.baseline_mode == "monitor":
            if not self.baseline_engine.load():
                logger.warning(
                    "Failed to load baseline - run with --mode create first"
                )

        logger.info(
            f"PersistenceGuardV2 initialized: device={device_id}, "
            f"mode={baseline_mode}, baseline={baseline_path}, "
            f"interval={collection_interval}s, probes={len(self.probes)}"
        )

    def setup(self) -> bool:
        """Setup hook - called once at agent startup.

        Returns:
            True if setup successful, False otherwise
        """
        logger.info(f"{self.AGENT_NAME} setup starting...")

        # TODO: Validate collector capabilities
        # - Check permissions for reading persistence mechanisms
        # - Verify baseline path is writable
        # - Test collector enumeration

        logger.info(f"{self.AGENT_NAME} setup complete")
        return True

    def collect_data(self) -> Sequence[Any]:
        """Collect persistence snapshot and run threat detection probes.

        Returns:
            List of DeviceTelemetry protobuf messages
        """
        now_ns = int(time.time() * 1e9)

        # Collect current persistence state
        snapshot = self.collector.collect_snapshot()

        logger.debug(f"Collected {len(snapshot)} persistence entries in this cycle")

        # Create baseline mode - just save and exit
        if self.baseline_mode == "create":
            self.baseline_engine.create_from_snapshot(snapshot)
            self.baseline_engine.save()
            logger.info(
                f"Baseline created with {len(snapshot)} persistence entries"
            )
            return []

        # Monitor mode - compare against baseline
        changes = self.baseline_engine.compare(snapshot)

        # No changes, no events
        if not changes:
            logger.debug("No persistence changes detected in this cycle")
            return []

        # Build probe context
        context = ProbeContext(
            device_id=self.device_id,
            agent_name=self.AGENT_NAME,
            now_ns=now_ns,
            shared_data={"persistence_changes": changes},
        )

        # Run all probes
        probe_events = self.run_probes(context)

        if not probe_events:
            logger.debug("No threat events detected in this cycle")
            return []

        # Package as DeviceTelemetry
        telemetry = DeviceTelemetry(
            device_id=self.device_id,
            device_type="HOST",
            protocol="PERSISTENCE",
            timestamp_ns=now_ns,
            collection_agent=self.AGENT_NAME,
            agent_version="2.0.0",
        )

        # Convert TelemetryEvent to protobuf
        for event in probe_events:
            proto_event = ProtoEvent(
                event_id=f"{event.event_type}_{event.timestamp_ns}",
                event_type=event.event_type,
                severity=event.severity.value,
                timestamp_ns=event.timestamp_ns,
            )

            # Add event data as metadata
            for key, value in event.data.items():
                proto_event.metadata[key] = str(value)

            telemetry.events.append(proto_event)

        logger.info(
            f"Detected {len(probe_events)} persistence threat events: "
            f"{[e.event_type for e in probe_events]}"
        )

        return [telemetry]

    def validate_event(self, event: DeviceTelemetry) -> bool:
        """Validate telemetry event before publishing.

        Args:
            event: DeviceTelemetry protobuf message

        Returns:
            True if valid, False otherwise
        """
        # Basic validation
        if not event.device_id:
            logger.warning("Validation failed: device_id is empty")
            return False

        if not event.events:
            logger.warning("Validation failed: no events in telemetry")
            return False

        # Timestamp sanity check (within 1 hour of current time)
        now_ns = int(time.time() * 1e9)
        time_diff_hours = abs(event.timestamp_ns - now_ns) / (3600 * 1e9)

        if time_diff_hours > 1:
            logger.warning(
                f"Validation failed: timestamp too far from current time "
                f"(diff={time_diff_hours:.2f}h)"
            )
            return False

        return True

    def enrich_event(self, event: DeviceTelemetry) -> DeviceTelemetry:
        """Enrich telemetry with additional metadata.

        Args:
            event: DeviceTelemetry protobuf message

        Returns:
            Enriched DeviceTelemetry
        """
        # Add device IP address
        try:
            ip_address = socket.gethostbyname(socket.gethostname())
            event.metadata["ip_address"] = ip_address
        except OSError:
            pass

        # Add collector stats
        event.metadata["entries_collected_total"] = str(
            self.collector.entries_collected
        )

        return event

    def shutdown(self) -> None:
        """Cleanup hook - called at agent shutdown."""
        logger.info(f"{self.AGENT_NAME} shutting down...")

        # Cleanup collector resources
        # (e.g., close file handles, cleanup temp files)

        logger.info(f"{self.AGENT_NAME} shutdown complete")


# =============================================================================
# CLI Entry Point
# =============================================================================


def main():
    """CLI entry point for PersistenceGuardV2."""
    parser = argparse.ArgumentParser(
        description="PersistenceGuardV2 - Persistence Mechanism Monitoring with Micro-Probe Architecture"
    )
    parser.add_argument(
        "--device-id",
        type=str,
        default=None,
        help="Device identifier (default: hostname)",
    )
    parser.add_argument(
        "--queue-path",
        type=str,
        default="data/queue/persistence_guard_v2.db",
        help="Local queue database path",
    )
    parser.add_argument(
        "--mode",
        type=str,
        default="monitor",
        choices=["create", "monitor"],
        help="Mode: create baseline or monitor for changes (default: monitor)",
    )
    parser.add_argument(
        "--baseline-path",
        type=str,
        default="data/persistence_baseline.json",
        help="Baseline JSON file path (default: data/persistence_baseline.json)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=PersistenceGuardV2.COLLECTION_INTERVAL_SECONDS,
        help="Collection interval in seconds (default: 300)",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level",
    )

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Create and run agent
    agent = PersistenceGuardV2(
        device_id=args.device_id,
        queue_path=args.queue_path,
        baseline_mode=args.mode,
        baseline_path=args.baseline_path,
        collection_interval=args.interval,
    )

    try:
        if args.mode == "create":
            logger.info("Creating persistence baseline...")
            agent.setup()
            # Run one collection cycle to create baseline
            agent.collect_data()
            logger.info(f"Baseline created and saved to {args.baseline_path}")
        else:
            logger.info("Starting PersistenceGuardV2 in monitor mode...")
            agent.run()
    except KeyboardInterrupt:
        logger.info("Received interrupt signal, shutting down...")
        agent.shutdown()
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        agent.shutdown()
        raise


if __name__ == "__main__":
    main()
