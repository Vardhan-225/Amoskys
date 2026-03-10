# filepath: src/amoskys/agents/__init__.py
"""
AMOSKYS Agent Registry — Platform-Aware Canonical Agents

Central registry for all security agents in the AMOSKYS neural network.
Agents are platform-routed: on macOS, Observatory agents are canonical;
on Linux/Windows, shared cross-platform agents serve as the default.

Architecture:
    agents/common/   — Shared base classes, utilities (HardenedAgentBase, MicroProbe)
    agents/shared/   — Platform-agnostic agent implementations
    agents/os/macos/ — macOS Observatory agents (ground-truth verified)
    agents/os/linux/ — Linux-specific agents (kernel_audit + stubs)
    agents/os/windows/ — Windows agent stubs

Usage:
    from amoskys.agents import ProcAgent, AuthGuardAgent, FIMAgent

    # On macOS: ProcAgent IS MacOSProcessAgent (Observatory)
    # On Linux/Windows: ProcAgent is the shared cross-platform implementation
    proc = ProcAgent(agent_id="proc-001", device_id="host-001")
"""

import sys as _sys
from typing import Any, Dict, Optional

# Common base classes
from amoskys.agents.common.base import HardenedAgentBase
from amoskys.agents.common.probes import MicroProbe, MicroProbeAgentMixin

# ── Platform-routed agents ──────────────────────────────────────────────
# On macOS: Observatory agents (ground-truth verified, higher probe counts)
# On Linux/Windows: shared cross-platform agents (fallback)
if _sys.platform == "darwin":
    from amoskys.agents.os.macos.auth.agent import (  # noqa: F401
        MacOSAuthAgent as AuthGuardAgent,
    )
    from amoskys.agents.os.macos.filesystem.agent import (  # noqa: F401
        MacOSFileAgent as FIMAgent,
    )
    from amoskys.agents.os.macos.network.agent import (  # noqa: F401
        MacOSNetworkAgent as FlowAgent,
    )
    from amoskys.agents.os.macos.peripheral.agent import (  # noqa: F401
        MacOSPeripheralAgent as PeripheralAgent,
    )
    from amoskys.agents.os.macos.persistence.agent import (  # noqa: F401
        MacOSPersistenceAgent as PersistenceGuard,
    )
    from amoskys.agents.os.macos.process.agent import (  # noqa: F401
        MacOSProcessAgent as ProcAgent,
    )
else:
    from amoskys.agents.shared.auth.agent import AuthGuardAgent  # noqa: F401
    from amoskys.agents.shared.filesystem.agent import FIMAgent  # noqa: F401
    from amoskys.agents.shared.network.agent import FlowAgent  # noqa: F401
    from amoskys.agents.shared.peripheral.agent import PeripheralAgent  # noqa: F401
    from amoskys.agents.shared.persistence.agent import PersistenceGuard  # noqa: F401
    from amoskys.agents.shared.process.agent import ProcAgent  # noqa: F401

# ── Cross-platform agents (same implementation on all platforms) ─────────
# ── Platform-specific agents ────────────────────────────────────────────
from amoskys.agents.os.linux.kernel_audit.kernel_audit_agent import KernelAuditAgent
from amoskys.agents.os.macos.applog.agent import MacOSAppLogAgent

# ── Direct Observatory imports (macOS only, explicit use) ────────────────
from amoskys.agents.os.macos.auth.agent import MacOSAuthAgent
from amoskys.agents.os.macos.db_activity.agent import MacOSDBActivityAgent
from amoskys.agents.os.macos.discovery.agent import MacOSDiscoveryAgent

# ── Wave 2 Observatory Agents (macOS-specific, ground-truth verified) ────
from amoskys.agents.os.macos.dns.agent import MacOSDNSAgent
from amoskys.agents.os.macos.filesystem.agent import MacOSFileAgent
from amoskys.agents.os.macos.http_inspector.agent import MacOSHTTPInspectorAgent
from amoskys.agents.os.macos.internet_activity.agent import MacOSInternetActivityAgent
from amoskys.agents.os.macos.network.agent import MacOSNetworkAgent
from amoskys.agents.os.macos.peripheral.agent import MacOSPeripheralAgent
from amoskys.agents.os.macos.persistence.agent import MacOSPersistenceAgent
from amoskys.agents.os.macos.process.agent import MacOSProcessAgent
from amoskys.agents.os.macos.security_monitor.security_monitor_agent import (
    MacOSSecurityMonitorAgent,
)
from amoskys.agents.os.macos.unified_log.agent import MacOSUnifiedLogAgent
from amoskys.agents.shared.applog.agent import AppLogAgent
from amoskys.agents.shared.db_activity.agent import DBActivityAgent
from amoskys.agents.shared.device_discovery.agent import DeviceDiscovery
from amoskys.agents.shared.dns.agent import DNSAgent
from amoskys.agents.shared.http_inspector.agent import HTTPInspectorAgent
from amoskys.agents.shared.internet_activity.agent import InternetActivityAgent
from amoskys.agents.shared.net_scanner.agent import NetScannerAgent
from amoskys.agents.shared.protocol_collectors.protocol_collectors import (
    ProtocolCollectors,
)
from amoskys.agents.shared.network_sentinel.agent import NetworkSentinelAgent
from amoskys.agents.shared.protocols.universal_collector import (
    HL7FHIRCollector,
    ModbusCollector,
    MQTTCollector,
    SyslogCollector,
    UniversalTelemetryCollector,
)

__all__ = [
    # Base classes
    "HardenedAgentBase",
    "MicroProbe",
    "MicroProbeAgentMixin",
    # Canonical agent names (platform-routed on Darwin)
    "AuthGuardAgent",
    "ProcAgent",
    "PersistenceGuard",
    "FIMAgent",
    "DNSAgent",
    "KernelAuditAgent",
    "MacOSSecurityMonitorAgent",
    "FlowAgent",
    "PeripheralAgent",
    "DeviceDiscovery",
    # Protocol Collectors
    "UniversalTelemetryCollector",
    "MQTTCollector",
    "ModbusCollector",
    "HL7FHIRCollector",
    "SyslogCollector",
    "ProtocolCollectors",
    # L7 Gap-Closure Agents
    "AppLogAgent",
    "DBActivityAgent",
    "HTTPInspectorAgent",
    "InternetActivityAgent",
    "NetScannerAgent",
    "NetworkSentinelAgent",
    # Direct Observatory access (explicit use only)
    "MacOSProcessAgent",
    "MacOSPersistenceAgent",
    "MacOSNetworkAgent",
    "MacOSFileAgent",
    "MacOSAuthAgent",
    "MacOSUnifiedLogAgent",
    "MacOSPeripheralAgent",
    # Wave 2 Observatory Agents
    "MacOSDNSAgent",
    "MacOSAppLogAgent",
    "MacOSDiscoveryAgent",
    "MacOSInternetActivityAgent",
    "MacOSDBActivityAgent",
    "MacOSHTTPInspectorAgent",
]

# ── Agent Registry — single source of truth for dynamic discovery ──
#
# On macOS, the 6 overlapping entries (proc, auth, fim, flow, peripheral,
# persistence) already resolve to Observatory agents via platform routing above.
AGENT_REGISTRY: Dict[str, Dict[str, Any]] = {
    # ── Endpoint Agents (platform-routed via imports above) ──
    "proc": {
        "class": ProcAgent,
        "name": "Process Agent",
        "description": "Process behavior, resource abuse, and privilege escalation detection",
        "platforms": ["darwin", "linux"],
        "probes": 10,
        "category": "endpoint",
        "icon": "cpu",
    },
    "auth": {
        "class": AuthGuardAgent,
        "name": "AuthGuard Agent",
        "description": "Authentication and authorization monitoring via unified logging",
        "platforms": ["darwin", "linux"],
        "probes": 7,
        "category": "endpoint",
        "icon": "lock",
    },
    "persistence": {
        "class": PersistenceGuard,
        "name": "Persistence Guard",
        "description": "Persistence mechanism detection (LaunchAgents, cron, SSH keys, login items)",
        "platforms": ["darwin", "linux"],
        "probes": 10,
        "category": "endpoint",
        "icon": "anchor",
    },
    "fim": {
        "class": FIMAgent,
        "name": "File Integrity Monitor",
        "description": "File modification detection for critical system paths with baseline engine",
        "platforms": ["darwin", "linux"],
        "probes": 8,
        "category": "endpoint",
        "icon": "file-shield",
    },
    "flow": {
        "class": FlowAgent,
        "name": "Flow Agent",
        "description": "Network flow analysis, C2 beaconing, lateral movement detection",
        "platforms": ["darwin", "linux"],
        "probes": 8,
        "category": "network",
        "icon": "network",
    },
    "peripheral": {
        "class": PeripheralAgent,
        "name": "Peripheral Agent",
        "description": "USB, Bluetooth, and Thunderbolt device monitoring",
        "platforms": ["darwin", "linux"],
        "probes": 7,
        "category": "endpoint",
        "icon": "usb",
    },
    # ── Platform-specific agents (no cross-platform equivalent) ──
    "kernel_audit": {
        "class": KernelAuditAgent,
        "name": "Kernel Audit Agent",
        "description": "Linux kernel-level syscall monitoring (auditd: exec, privesc, ptrace, module load)",
        "platforms": ["linux"],
        "probes": 8,
        "category": "platform",
        "icon": "terminal",
    },
    "macos_security_monitor": {
        "class": MacOSSecurityMonitorAgent,
        "name": "macOS Security Monitor",
        "description": "macOS security framework monitoring (Gatekeeper, PKI/trust, certificate anomalies)",
        "platforms": ["darwin"],
        "probes": 4,
        "category": "platform",
        "icon": "shield-check",
    },
    "macos_unified_log": {
        "class": MacOSUnifiedLogAgent,
        "name": "macOS Unified Log Observatory",
        "description": "macOS Unified Logging — security framework, Gatekeeper, installer, XPC, TCC, AirDrop",
        "platforms": ["darwin"],
        "probes": 6,
        "category": "platform",
        "icon": "scroll",
    },
    # ── Network & Discovery Agents ──
    "dns": {
        "class": DNSAgent,
        "name": "DNS Agent",
        "description": "DNS threat detection (C2 beaconing, DGA, tunneling, cache poisoning)",
        "platforms": ["darwin", "linux"],
        "probes": 9,
        "category": "network",
        "icon": "globe",
    },
    "device_discovery": {
        "class": DeviceDiscovery,
        "name": "Device Discovery",
        "description": "Network device enumeration and asset tracking",
        "platforms": ["darwin", "linux"],
        "probes": 6,
        "category": "network",
        "icon": "radar",
    },
    "protocol_collectors": {
        "class": ProtocolCollectors,
        "name": "Protocol Threat Collector",
        "description": "Protocol-level threat detection for HTTP, TLS, SSH, DNS, SQL injection",
        "platforms": ["darwin", "linux"],
        "probes": 10,
        "category": "network",
        "icon": "layers",
    },
    # ── L7 Gap-Closure Agents ──
    "applog": {
        "class": AppLogAgent,
        "name": "AppLog Agent",
        "description": "Application log analysis with webshell, tampering, and credential detection",
        "platforms": ["darwin", "linux"],
        "probes": 8,
        "category": "application",
        "icon": "file-text",
    },
    "db_activity": {
        "class": DBActivityAgent,
        "name": "Database Activity Agent",
        "description": "Database query monitoring for SQL injection, privilege escalation, bulk extraction",
        "platforms": ["darwin", "linux"],
        "probes": 8,
        "category": "application",
        "icon": "database",
    },
    "http_inspector": {
        "class": HTTPInspectorAgent,
        "name": "HTTP Inspector Agent",
        "description": "Deep HTTP payload analysis for XSS, SSRF, path traversal, API abuse",
        "platforms": ["darwin", "linux"],
        "probes": 8,
        "category": "application",
        "icon": "search",
    },
    "internet_activity": {
        "class": InternetActivityAgent,
        "name": "Internet Activity Agent",
        "description": "Outbound connection monitoring for cloud exfil, TOR/VPN, crypto mining",
        "platforms": ["darwin", "linux"],
        "probes": 8,
        "category": "application",
        "icon": "activity",
    },
    "net_scanner": {
        "class": NetScannerAgent,
        "name": "Network Scanner Agent",
        "description": "Active network probing with diff-based service/port/topology change detection",
        "platforms": ["darwin", "linux"],
        "probes": 7,
        "category": "network",
        "icon": "scan",
    },
    # ── Network Sentinel (HTTP log analysis, scan detection, payload inspection) ──
    "network_sentinel": {
        "class": NetworkSentinelAgent,
        "name": "Network Sentinel",
        "description": "HTTP access log analysis, scan detection, payload inspection, rate anomaly detection",
        "platforms": ["darwin", "linux"],
        "probes": 10,
        "category": "network",
        "icon": "shield-alert",
    },
    # ── Wave 2 macOS Observatory Agents (ground-truth, 45 new probes) ──
    "macos_dns": {
        "class": MacOSDNSAgent,
        "name": "macOS DNS Observatory",
        "description": "DNS threat detection — DGA, tunneling, beaconing, fast-flux, DoH bypass",
        "platforms": ["darwin"],
        "probes": 8,
        "category": "platform",
        "icon": "globe",
    },
    "macos_applog": {
        "class": MacOSAppLogAgent,
        "name": "macOS AppLog Observatory",
        "description": "Application log analysis — webshell, tampering, error spikes, credential harvest",
        "platforms": ["darwin"],
        "probes": 7,
        "category": "platform",
        "icon": "file-text",
    },
    "macos_discovery": {
        "class": MacOSDiscoveryAgent,
        "name": "macOS Discovery Observatory",
        "description": "Network discovery — ARP changes, Bonjour services, rogue DHCP, topology shifts",
        "platforms": ["darwin"],
        "probes": 6,
        "category": "platform",
        "icon": "radar",
    },
    "macos_internet_activity": {
        "class": MacOSInternetActivityAgent,
        "name": "macOS Internet Activity Observatory",
        "description": "Internet activity — cloud exfil, TOR/VPN, crypto mining, CDN masquerade",
        "platforms": ["darwin"],
        "probes": 8,
        "category": "platform",
        "icon": "activity",
    },
    "macos_db_activity": {
        "class": MacOSDBActivityAgent,
        "name": "macOS DB Activity Observatory",
        "description": "Database monitoring — SQL injection, bulk extraction, priv escalation, exfil",
        "platforms": ["darwin"],
        "probes": 8,
        "category": "platform",
        "icon": "database",
    },
    "macos_http_inspector": {
        "class": MacOSHTTPInspectorAgent,
        "name": "macOS HTTP Inspector Observatory",
        "description": "HTTP inspection — XSS, SSRF, path traversal, API abuse, C2 beaconing",
        "platforms": ["darwin"],
        "probes": 8,
        "category": "platform",
        "icon": "search",
    },
}


def get_available_agents(platform: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """Get agents available for a given platform.

    Args:
        platform: Target platform (darwin/linux/windows). If None, uses current.

    Returns:
        Dictionary of available agents with metadata
    """
    import sys

    if platform is None:
        platform = sys.platform

    return {
        name: meta
        for name, meta in AGENT_REGISTRY.items()
        if platform in meta["platforms"]
    }
