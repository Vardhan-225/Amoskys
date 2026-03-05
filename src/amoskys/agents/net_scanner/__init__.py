"""AMOSKYS Network Scanner Agent - Network Topology & Service Monitoring.

Micro-probe architecture with 7 specialized detectors for network
topology changes, service discovery, and security assessment.

Uses lazy imports to avoid circular import issues.
"""

# Types - no dependencies, safe to import directly
from amoskys.agents.net_scanner.agent_types import (
    COMMON_SCAN_PORTS,
    STANDARD_SERVICE_PORTS,
    HostScanResult,
    PortInfo,
    ScanDiff,
    ScanResult,
)


def __getattr__(name: str):
    """Lazy import for components that depend on common.probes."""
    if name == "NetScannerAgent":
        from amoskys.agents.net_scanner.net_scanner_agent import NetScannerAgent

        return NetScannerAgent

    if name in (
        "NetworkScanner",
        "MacOSNetworkCollector",
        "LinuxNetworkCollector",
        "BaseNetworkCollector",
    ):
        from amoskys.agents.net_scanner import net_scanner_agent as _agent

        return getattr(_agent, name)

    if name in (
        "NewServiceDetectionProbe",
        "OpenPortChangeProbe",
        "RogueServiceProbe",
        "SSLCertIssueProbe",
        "VulnerableBannerProbe",
        "UnauthorizedListenerProbe",
        "NetworkTopologyChangeProbe",
        "create_net_scanner_probes",
        "NET_SCANNER_PROBES",
    ):
        from amoskys.agents.net_scanner import probes as _probes

        return getattr(_probes, name)

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    # Agent
    "NetScannerAgent",
    # Collectors
    "NetworkScanner",
    "MacOSNetworkCollector",
    "LinuxNetworkCollector",
    "BaseNetworkCollector",
    # Types
    "PortInfo",
    "HostScanResult",
    "ScanResult",
    "ScanDiff",
    "COMMON_SCAN_PORTS",
    "STANDARD_SERVICE_PORTS",
    # Probes
    "NewServiceDetectionProbe",
    "OpenPortChangeProbe",
    "RogueServiceProbe",
    "SSLCertIssueProbe",
    "VulnerableBannerProbe",
    "UnauthorizedListenerProbe",
    "NetworkTopologyChangeProbe",
    "create_net_scanner_probes",
    "NET_SCANNER_PROBES",
]
