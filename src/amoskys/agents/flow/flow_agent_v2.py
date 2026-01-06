#!/usr/bin/env python3
"""FlowAgentV2 - Network Flow Monitoring with Micro-Probe Architecture.

Monitors network traffic (TCP/UDP flows) for threat detection:
    - Port scanning and reconnaissance
    - Lateral movement via admin protocols
    - Data exfiltration patterns
    - C2 beaconing
    - Cleartext credential leaks
    - Suspicious tunnels
    - DNS-based reconnaissance
    - New external service connections

Architecture:
    - FlowCollector: Platform-specific flow collection (eBPF, pcap, NetFlow, etc.)
    - 8 Micro-Probes: Specialized threat detectors
    - HardenedAgentBase: Circuit breaker + offline resilience

CLI Usage:
    ```bash
    # Run with default interface
    python flow_agent_v2.py

    # Specify network interface
    python flow_agent_v2.py --interface eth0

    # Adjust collection interval
    python flow_agent_v2.py --interval 30
    ```

MITRE ATT&CK Coverage:
    - T1046: Network Service Discovery
    - T1021: Remote Services
    - T1041/T1048: Exfiltration
    - T1071: Application Layer Protocol (C2)
    - T1090/T1572: Proxy & Tunneling
    - T1552: Unsecured Credentials
"""

from __future__ import annotations

import argparse
import logging
import socket
import time
from typing import Any, List, Optional, Sequence

from amoskys.agents.common.base import HardenedAgentBase
from amoskys.agents.common.probes import MicroProbeAgentMixin, ProbeContext
from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.agents.flow.probes import FlowEvent, create_flow_probes
from amoskys.messaging_pb2 import DeviceTelemetry, TelemetryEvent as ProtoEvent

logger = logging.getLogger(__name__)


# =============================================================================
# Flow Collector (Platform-Specific)
# =============================================================================


class FlowCollector:
    """Platform-specific network flow collector.

    Collects flow metadata from various sources:
        - eBPF (Linux)
        - pcap/libpcap (cross-platform)
        - NetFlow/sFlow exports
        - OS-specific APIs (macOS Network Extension, Windows ETW)

    For now, this is a stub that returns empty flows.
    TODO: Integrate with existing FlowAgent collector or implement eBPF-based collection.
    """

    def __init__(self, interface: Optional[str] = None):
        """Initialize flow collector.

        Args:
            interface: Network interface to monitor (e.g., "eth0", "en0").
                      If None, monitors all interfaces.
        """
        self.interface = interface
        self.flows_collected = 0

    def collect(self, window_seconds: int) -> List[FlowEvent]:
        """Collect network flows from the last window.

        Args:
            window_seconds: Collection window duration in seconds

        Returns:
            List of FlowEvent objects representing network flows
        """
        # TODO: Implement actual flow collection
        # Options:
        #   1. Read from existing FlowAgent WAL/queue
        #   2. Use eBPF via bcc/bpftrace (Linux)
        #   3. Use libpcap for packet capture and flow aggregation
        #   4. Parse NetFlow/sFlow exports
        #   5. Use OS-specific APIs (macOS NKE, Windows ETW)

        logger.debug(
            f"Collecting flows for last {window_seconds}s on interface={self.interface}"
        )

        # Placeholder: return empty list
        # In production, this would return actual FlowEvent objects
        flows: List[FlowEvent] = []

        self.flows_collected += len(flows)
        return flows


# =============================================================================
# FlowAgentV2 - Main Agent
# =============================================================================


class FlowAgentV2(MicroProbeAgentMixin, HardenedAgentBase):
    """Network flow monitoring agent with micro-probe architecture.

    Monitors network traffic using 8 specialized threat detectors:
        1. PortScanSweepProbe - Port scanning detection
        2. LateralSMBWinRMProbe - Lateral movement
        3. DataExfilVolumeSpikeProbe - Data exfiltration
        4. C2BeaconFlowProbe - C2 beaconing patterns
        5. CleartextCredentialLeakProbe - Cleartext credentials
        6. SuspiciousTunnelProbe - Suspicious tunnels
        7. InternalReconDNSFlowProbe - DNS reconnaissance
        8. NewExternalServiceProbe - New external connections
    """

    AGENT_NAME = "flow_agent_v2"
    COLLECTION_INTERVAL_SECONDS = 60.0  # 1 minute default

    def __init__(
        self,
        device_id: Optional[str] = None,
        queue_path: str = "data/queue/flow_agent_v2.db",
        interface: Optional[str] = None,
        collection_interval: float = COLLECTION_INTERVAL_SECONDS,
    ):
        """Initialize FlowAgentV2.

        Args:
            device_id: Unique device identifier (defaults to hostname)
            queue_path: Path to local queue database
            interface: Network interface to monitor
            collection_interval: Flow collection interval in seconds
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

        MicroProbeAgentMixin.__init__(self, probes=create_flow_probes())

        # Initialize collector
        self.collector = FlowCollector(interface=interface)

        logger.info(
            f"FlowAgentV2 initialized: device={device_id}, "
            f"interface={interface}, interval={collection_interval}s, "
            f"probes={len(self.probes)}"
        )

    def setup(self) -> bool:
        """Setup hook - called once at agent startup.

        Returns:
            True if setup successful, False otherwise
        """
        logger.info(f"{self.AGENT_NAME} setup starting...")

        # TODO: Validate collector capabilities
        # - Check if interface exists (if specified)
        # - Verify permissions for packet capture (CAP_NET_RAW on Linux)
        # - Test flow collection

        logger.info(f"{self.AGENT_NAME} setup complete")
        return True

    def collect_data(self) -> Sequence[Any]:
        """Collect network flows and run threat detection probes.

        Returns:
            List of DeviceTelemetry protobuf messages
        """
        now_ns = int(time.time() * 1e9)

        # Collect flows from network
        flows = self.collector.collect(
            window_seconds=int(self.collection_interval)
        )

        logger.debug(f"Collected {len(flows)} flows in this cycle")

        # No flows, no events
        if not flows:
            return []

        # Build probe context
        context = ProbeContext(
            device_id=self.device_id,
            agent_name=self.AGENT_NAME,
            now_ns=now_ns,
            shared_data={
                "flows": flows,
                "window_end_ns": now_ns,
                "window_start_ns": now_ns - int(self.collection_interval * 1e9),
            },
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
            protocol="FLOW",
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
            f"Detected {len(probe_events)} threat events: "
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
        event.metadata["flows_collected_total"] = str(self.collector.flows_collected)

        return event

    def shutdown(self) -> None:
        """Cleanup hook - called at agent shutdown."""
        logger.info(f"{self.AGENT_NAME} shutting down...")

        # Cleanup collector resources
        # (e.g., close pcap handles, stop eBPF programs)

        logger.info(f"{self.AGENT_NAME} shutdown complete")


# =============================================================================
# CLI Entry Point
# =============================================================================


def main():
    """CLI entry point for FlowAgentV2."""
    parser = argparse.ArgumentParser(
        description="FlowAgentV2 - Network Flow Monitoring with Micro-Probe Architecture"
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
        default="data/queue/flow_agent_v2.db",
        help="Local queue database path",
    )
    parser.add_argument(
        "--interface",
        type=str,
        default=None,
        help="Network interface to monitor (default: all interfaces)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=FlowAgentV2.COLLECTION_INTERVAL_SECONDS,
        help="Collection interval in seconds (default: 60)",
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
    agent = FlowAgentV2(
        device_id=args.device_id,
        queue_path=args.queue_path,
        interface=args.interface,
        collection_interval=args.interval,
    )

    try:
        logger.info("Starting FlowAgentV2...")
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
