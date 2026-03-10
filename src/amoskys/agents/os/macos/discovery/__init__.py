"""AMOSKYS macOS Device Discovery Observatory.

Purpose-built network device discovery and threat detection for macOS
(Darwin 25.0.0+, Apple Silicon). Monitors ARP tables, Bonjour/mDNS services,
hardware ports, and routing tables for network topology changes and threats.

Probes:
    - ARP table change detection (new hosts, baseline-diff)
    - Bonjour/mDNS service discovery (unexpected services)
    - Rogue DHCP server detection (multiple gateways)
    - Network topology change detection (interfaces, routes)
    - New device risk scoring (unknown MAC vendors)
    - Inbound port scan detection (many connections from single IP)

Coverage: T1018, T1046, T1557.001, T1016, T1200
"""

from amoskys.agents.os.macos.discovery.agent import MacOSDiscoveryAgent

__all__ = ["MacOSDiscoveryAgent"]
