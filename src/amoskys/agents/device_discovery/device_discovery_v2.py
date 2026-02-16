#!/usr/bin/env python3
"""DeviceDiscovery Agent v2 - Micro-Probe Based Network Discovery.

This is the v2 implementation using the micro-probe architecture.
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
    >>> from amoskys.agents.device_discovery import DeviceDiscoveryV2
    >>> agent = DeviceDiscoveryV2(device_id="host-001")
    >>> agent.run_forever()
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Sequence, Set

from amoskys.agents.common.base import HardenedAgentBase
from amoskys.agents.common.probes import (
    MicroProbe,
    MicroProbeAgentMixin,
    ProbeContext,
    TelemetryEvent,
)

from .probes import DEVICE_DISCOVERY_PROBES

logger = logging.getLogger(__name__)


class DeviceDiscoveryV2(MicroProbeAgentMixin, HardenedAgentBase):
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
        device_id: str,
        agent_name: str = "device_discovery_v2",
        collection_interval: float = 30.0,
        known_ips: Optional[Set[str]] = None,
        authorized_dhcp: Optional[Set[str]] = None,
        authorized_dns: Optional[Set[str]] = None,
        queue_adapter: Optional[Any] = None,
        metrics_interval: float = 60.0,
        probes: Optional[Sequence[MicroProbe]] = None,
    ):
        """Initialize DeviceDiscoveryV2.
        
        Args:
            device_id: Unique device identifier
            agent_name: Agent name for logging/metrics
            collection_interval: Seconds between discovery cycles (default 30s)
            known_ips: Set of known/baseline IP addresses
            authorized_dhcp: Set of authorized DHCP server IPs
            authorized_dns: Set of authorized DNS server IPs
            queue_adapter: Queue adapter for event persistence
            metrics_interval: Seconds between metrics emissions
            probes: Custom probes (overrides defaults)
        """
        # Store configuration
        self.known_ips = known_ips or set()
        self.authorized_dhcp = authorized_dhcp or set()
        self.authorized_dns = authorized_dns or set()

        # Use custom probes if provided, otherwise default
        if probes is None:
            probes = self._create_default_probes()

        # Initialize using super() for proper MRO handling
        super().__init__(
            agent_name=agent_name,
            device_id=device_id,
            collection_interval=collection_interval,
            probes=probes,
            queue_adapter=queue_adapter,
            metrics_interval=metrics_interval,
        )

        logger.info(
            f"DeviceDiscoveryV2 initialized: {len(self.probes)} probes, "
            f"{len(self.known_ips)} known IPs, "
            f"interval={collection_interval}s"
        )

    def _create_default_probes(self) -> List[MicroProbe]:
        """Create default probes with configuration."""
        from .probes import (
            ARPDiscoveryProbe,
            ActivePortScanFingerprintProbe,
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
        logger.info(f"DeviceDiscoveryV2 setup: {len(self.probes)} probes ready")
        
        # Initialize shared_data for devices storage
        # This persists across collection cycles
        self._shared_data = {
            "devices": {},
            "known_ips": self.known_ips,
        }
        
        # Setup all probes
        for probe in self.probes:
            if hasattr(probe, 'setup'):
                probe.setup()
        
        return True
