"""AMOSKYS Shared Network Scanner Agent."""

from amoskys.agents.shared.net_scanner.agent_types import (
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
        from amoskys.agents.shared.net_scanner.agent import NetScannerAgent

        return NetScannerAgent

    if name in (
        "NetworkScanner",
        "MacOSNetworkCollector",
        "LinuxNetworkCollector",
        "BaseNetworkCollector",
    ):
        from amoskys.agents.shared.net_scanner import agent as _agent

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
        from amoskys.agents.shared.net_scanner import probes as _probes

        return getattr(_probes, name)

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "NetScannerAgent",
    "NetworkScanner",
    "MacOSNetworkCollector",
    "LinuxNetworkCollector",
    "BaseNetworkCollector",
    "PortInfo",
    "HostScanResult",
    "ScanResult",
    "ScanDiff",
    "COMMON_SCAN_PORTS",
    "STANDARD_SERVICE_PORTS",
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
