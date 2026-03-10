#!/usr/bin/env python3
"""DeviceDiscovery Agent - Micro-Probe Based Network Discovery.

This is the implementation using the micro-probe architecture.
Each probe focuses on a specific discovery/risk vector:

    1. ARPDiscoveryProbe - ARP table enumeration (T1018)
    2. ActivePortScanFingerprintProbe - Service fingerprinting (T1046)
    3. NewDeviceRiskProbe - Risk scoring for new devices (T1200)
    4. RogueDHCPDNSProbe - Rogue DHCP/DNS server detection (T1557.001)
    5. ShadowITProbe - Unauthorized devices on network (T1200)
    6. VulnerabilityBannerProbe - Vulnerable service banners (T1595)

Architecture:
    - Uses ARP cache / network scanning to discover devices
    - Maintains device inventory in context.shared_data["devices"]
    - Each probe runs against discovered devices
    - Inherits metrics/observability from HardenedAgentBase

Usage:
    >>> from amoskys.agents.device_discovery import DeviceDiscovery
    >>> agent = DeviceDiscovery(device_id="host-001")
    >>> agent.run_forever()
"""

from __future__ import annotations

import logging
import socket
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

import grpc

from amoskys.agents.common.base import HardenedAgentBase
from amoskys.agents.common.probes import (
    MicroProbe,
    MicroProbeAgentMixin,
    ProbeContext,
    TelemetryEvent,
)
from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.config import get_config
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.proto import universal_telemetry_pb2_grpc as universal_pbrpc

from .probes import DEVICE_DISCOVERY_PROBES

logger = logging.getLogger(__name__)

config = get_config()
EVENTBUS_ADDRESS = config.agent.bus_address
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = getattr(
    config.agent, "device_discovery_queue_path", "data/queue/device_discovery.db"
)


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

        for event in events:
            # Already-wrapped envelopes (e.g. from drain path) go directly
            if isinstance(event, telemetry_pb2.UniversalEnvelope):
                envelope = event
            else:
                timestamp_ns = int(time.time() * 1e9)
                idempotency_key = f"{event.device_id}_{timestamp_ns}"
                envelope = telemetry_pb2.UniversalEnvelope(
                    version="v1",
                    ts_ns=timestamp_ns,
                    idempotency_key=idempotency_key,
                    device_telemetry=event,
                    priority="NORMAL",
                    requires_acknowledgment=True,
                    schema_version=1,
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


class DeviceDiscovery(MicroProbeAgentMixin, HardenedAgentBase):
    """Network asset discovery using micro-probe architecture.

    Discovers devices on the network via ARP, port scanning, and
    banner grabbing. Assesses risk and detects shadow IT, rogue
    servers, and vulnerable services.

    Attributes:
        known_ips: Set of known/baseline IP addresses
        authorized_dhcp: Set of authorized DHCP server IPs
        authorized_dns: Set of authorized DNS server IPs
    """

    def __init__(
        self,
        collection_interval: float = 30.0,
        *,
        device_id: Optional[str] = None,
        agent_name: str = "device_discovery",
        known_ips: Optional[Set[str]] = None,
        authorized_dhcp: Optional[Set[str]] = None,
        authorized_dns: Optional[Set[str]] = None,
        queue_adapter: Optional[Any] = None,
        metrics_interval: float = 60.0,
        probes: Optional[Sequence[MicroProbe]] = None,
    ):
        """Initialize DeviceDiscovery agent.

        Args:
            collection_interval: Seconds between discovery cycles (default 30s)
            device_id: Unique device identifier (defaults to hostname)
            agent_name: Agent name for logging/metrics
            known_ips: Set of known/baseline IP addresses
            authorized_dhcp: Set of authorized DHCP server IPs
            authorized_dns: Set of authorized DNS server IPs
            queue_adapter: Queue adapter for event persistence
            metrics_interval: Seconds between metrics emissions
            probes: Custom probes (overrides defaults)
        """
        # Auto-create infra when called via cli.run_agent() (zero-args path)
        _auto_infra = device_id is None
        device_id = device_id or socket.gethostname()

        # Store configuration
        self.known_ips = known_ips or set()
        self.authorized_dhcp = authorized_dhcp or set()
        self.authorized_dns = authorized_dns or set()

        # Use custom probes if provided, otherwise default
        if probes is None:
            probes = self._create_default_probes()

        if _auto_infra and queue_adapter is None:
            Path(QUEUE_PATH).parent.mkdir(parents=True, exist_ok=True)
            queue_adapter = LocalQueueAdapter(
                queue_path=QUEUE_PATH,
                agent_name=agent_name,
                device_id=device_id,
                max_bytes=50 * 1024 * 1024,
                max_retries=10,
                signing_key_path=f"{CERT_DIR}/agent.ed25519",
            )

        eventbus_publisher = None
        if _auto_infra:
            eventbus_publisher = EventBusPublisher(EVENTBUS_ADDRESS, CERT_DIR)

        # Initialize using super() for proper MRO handling
        super().__init__(
            agent_name=agent_name,
            device_id=device_id,
            collection_interval=collection_interval,
            probes=probes,
            eventbus_publisher=eventbus_publisher,
            local_queue=queue_adapter,
            queue_adapter=queue_adapter,
            metrics_interval=metrics_interval,
        )

        logger.info(
            f"DeviceDiscovery initialized: {len(self.probes)} probes, "
            f"{len(self.known_ips)} known IPs, "
            f"interval={collection_interval}s"
        )

    def _create_default_probes(self) -> List[MicroProbe]:
        """Create default probes with configuration."""
        from .probes import (
            ActivePortScanFingerprintProbe,
            ARPDiscoveryProbe,
            NewDeviceRiskProbe,
            RogueDHCPDNSProbe,
            ShadowITProbe,
            VulnerabilityBannerProbe,
        )

        return [
            ARPDiscoveryProbe(),
            ActivePortScanFingerprintProbe(),
            NewDeviceRiskProbe(),
            RogueDHCPDNSProbe(
                authorized_dhcp=self.authorized_dhcp,
                authorized_dns=self.authorized_dns,
            ),
            ShadowITProbe(),
            VulnerabilityBannerProbe(),
        ]

    def collect_data(self) -> List[Dict[str, Any]]:
        """Run all probes and collect discovery events.

        Returns:
            List of event dictionaries for queue serialization
        """
        results: List[Dict[str, Any]] = []

        # Create probe context with persistent device data
        context = ProbeContext(
            device_id=self.device_id,
            agent_name=self.agent_name,
            shared_data=self._shared_data,
        )

        # Run all probes
        telemetry_events = self.run_probes(context)

        # Convert to dictionaries
        # NOTE: Do not enqueue here — base class run() handles queue_adapter.enqueue()
        for event in telemetry_events:
            event_dict = event.to_dict()
            event_dict["device_id"] = self.device_id
            event_dict["agent"] = self.agent_name
            results.append(event_dict)

        return results

    def get_probe_count(self) -> int:
        """Return number of active probes."""
        return len(self.probes)

    def add_known_ip(self, ip: str) -> None:
        """Add an IP to the known baseline."""
        self.known_ips.add(ip)

    def add_authorized_dhcp(self, ip: str) -> None:
        """Add an authorized DHCP server."""
        self.authorized_dhcp.add(ip)

    def add_authorized_dns(self, ip: str) -> None:
        """Add an authorized DNS server."""
        self.authorized_dns.add(ip)

    def setup(self) -> bool:
        """Initialize agent resources.

        Returns:
            True if setup succeeded
        """
        logger.info(f"DeviceDiscovery setup: {len(self.probes)} probes ready")

        # Initialize shared_data for devices storage
        # This persists across collection cycles
        self._shared_data = {
            "devices": {},
            "known_ips": self.known_ips,
        }

        # Setup all probes
        for probe in self.probes:
            if hasattr(probe, "setup"):
                probe.setup()

        return True
