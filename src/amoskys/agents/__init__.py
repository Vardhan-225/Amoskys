# filepath: src/amoskys/agents/__init__.py
"""
AMOSKYS Agent Registry — macOS-First Observatory Architecture

Central registry for all security agents in the AMOSKYS neural network.
Every agent is a macOS Observatory implementation with real collectors,
probes, and telemetry — no stubs, no NotImplementedError.

Architecture:
    agents/common/   — Shared base classes, utilities (HardenedAgentBase, MicroProbe)
    agents/os/macos/ — macOS Observatory agents (production, ground-truth verified)
    agents/os/linux/ — Linux agents (kernel_audit — future expansion via Igris)

Usage:
    from amoskys.agents import ProcAgent, AuthGuardAgent, FIMAgent
    from amoskys.agents import AGENT_REGISTRY

Future:
    Linux/Windows platform support will be handled by Igris, the multi-platform
    correlation engine. See docs/Engineering/ for the Igris architecture plan.
"""

from typing import Any, Dict, Optional

# Common base classes
from amoskys.agents.common.base import HardenedAgentBase
from amoskys.agents.common.probes import MicroProbe, MicroProbeAgentMixin
from amoskys.agents.os.macos.applog.agent import MacOSAppLogAgent
from amoskys.agents.os.macos.auth.agent import MacOSAuthAgent as AuthGuardAgent
from amoskys.agents.os.macos.db_activity.agent import MacOSDBActivityAgent
from amoskys.agents.os.macos.discovery.agent import MacOSDiscoveryAgent

# ── Wave 2 Observatory Agents ─────────────────────────────────────────
from amoskys.agents.os.macos.dns.agent import MacOSDNSAgent
from amoskys.agents.os.macos.filesystem.agent import MacOSFileAgent as FIMAgent
from amoskys.agents.os.macos.http_inspector.agent import MacOSHTTPInspectorAgent

# ── macOS Shield Agents ───────────────────────────────────────────────
from amoskys.agents.os.macos.infostealer_guard.agent import MacOSInfostealerGuardAgent
from amoskys.agents.os.macos.internet_activity.agent import MacOSInternetActivityAgent
from amoskys.agents.os.macos.network.agent import MacOSNetworkAgent as FlowAgent

# ── Network & Infrastructure Agents ──────────────────────────────────
from amoskys.agents.os.macos.network_sentinel.agent import NetworkSentinelAgent
from amoskys.agents.os.macos.peripheral.agent import (
    MacOSPeripheralAgent as PeripheralAgent,
)
from amoskys.agents.os.macos.persistence.agent import (
    MacOSPersistenceAgent as PersistenceGuard,
)

# ── macOS Observatory Agents (canonical implementations) ──────────────
from amoskys.agents.os.macos.process.agent import MacOSProcessAgent as ProcAgent
from amoskys.agents.os.macos.protocol_collectors.protocol_collectors import (
    ProtocolCollectors,
)
from amoskys.agents.os.macos.provenance.agent import MacOSProvenanceAgent
from amoskys.agents.os.macos.quarantine_guard.agent import MacOSQuarantineGuardAgent

# ── Platform-specific agents ─────────────────────────────────────────
from amoskys.agents.os.macos.security_monitor.security_monitor_agent import (
    MacOSSecurityMonitorAgent,
)
from amoskys.agents.os.macos.unified_log.agent import MacOSUnifiedLogAgent

# ── Direct Observatory name exports (for explicit use) ────────────────
MacOSProcessAgent = ProcAgent  # noqa: F811 — alias for explicit import
MacOSAuthAgent = AuthGuardAgent  # noqa: F811
MacOSFileAgent = FIMAgent  # noqa: F811
MacOSNetworkAgent = FlowAgent  # noqa: F811
MacOSPeripheralAgent = PeripheralAgent  # noqa: F811
MacOSPersistenceAgent = PersistenceGuard  # noqa: F811

# ── Linux (future — Igris multi-platform engine) ─────────────────────
from amoskys.agents.os.linux.kernel_audit.kernel_audit_agent import KernelAuditAgent

__all__ = [
    # Base classes
    "HardenedAgentBase",
    "MicroProbe",
    "MicroProbeAgentMixin",
    # Canonical agent names
    "ProcAgent",
    "AuthGuardAgent",
    "PersistenceGuard",
    "FIMAgent",
    "FlowAgent",
    "PeripheralAgent",
    # Platform agents
    "MacOSSecurityMonitorAgent",
    "MacOSUnifiedLogAgent",
    "KernelAuditAgent",
    # Wave 2 Observatory
    "MacOSDNSAgent",
    "MacOSAppLogAgent",
    "MacOSDiscoveryAgent",
    "MacOSInternetActivityAgent",
    "MacOSDBActivityAgent",
    "MacOSHTTPInspectorAgent",
    # macOS Shield
    "MacOSInfostealerGuardAgent",
    "MacOSQuarantineGuardAgent",
    "MacOSProvenanceAgent",
    # Network & Infrastructure
    "NetworkSentinelAgent",
    "ProtocolCollectors",
    # Direct Observatory access
    "MacOSProcessAgent",
    "MacOSPersistenceAgent",
    "MacOSNetworkAgent",
    "MacOSFileAgent",
    "MacOSAuthAgent",
    "MacOSPeripheralAgent",
]

# ── Agent Registry — single source of truth for dynamic discovery ──
AGENT_REGISTRY: Dict[str, Dict[str, Any]] = {
    # ── Core Endpoint Agents ──
    "proc": {
        "class": ProcAgent,
        "name": "Process Agent",
        "description": "Process behavior, resource abuse, and privilege escalation detection",
        "platforms": ["darwin"],
        "probes": 10,
        "category": "endpoint",
        "icon": "cpu",
        "collection_agent": "macos_process",
    },
    "auth": {
        "class": AuthGuardAgent,
        "name": "AuthGuard Agent",
        "description": "Authentication and authorization monitoring via unified logging",
        "platforms": ["darwin"],
        "probes": 6,
        "category": "endpoint",
        "icon": "lock",
        "collection_agent": "macos_auth",
    },
    "persistence": {
        "class": PersistenceGuard,
        "name": "Persistence Guard",
        "description": "Persistence mechanism detection (LaunchAgents, cron, SSH keys, login items)",
        "platforms": ["darwin"],
        "probes": 10,
        "category": "endpoint",
        "icon": "anchor",
        "collection_agent": "macos_persistence",
    },
    "fim": {
        "class": FIMAgent,
        "name": "File Integrity Monitor",
        "description": "File modification detection for critical system paths with baseline engine",
        "platforms": ["darwin"],
        "probes": 8,
        "category": "endpoint",
        "icon": "file-shield",
        "collection_agent": "macos_filesystem",
    },
    "flow": {
        "class": FlowAgent,
        "name": "Flow Agent",
        "description": "Network flow analysis, C2 beaconing, lateral movement detection",
        "platforms": ["darwin"],
        "probes": 8,
        "category": "network",
        "icon": "network",
        "collection_agent": "macos_network",
    },
    "peripheral": {
        "class": PeripheralAgent,
        "name": "Peripheral Agent",
        "description": "USB, Bluetooth, and Thunderbolt device monitoring",
        "platforms": ["darwin"],
        "probes": 4,
        "category": "endpoint",
        "icon": "usb",
        "collection_agent": "macos_peripheral",
    },
    # ── Platform-specific agents ──
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
    # ── Wave 2 Observatory Agents ──
    "macos_dns": {
        "class": MacOSDNSAgent,
        "name": "macOS DNS Observatory",
        "description": "DNS threat detection — DGA, tunneling, beaconing, fast-flux, DoH bypass",
        "platforms": ["darwin"],
        "probes": 8,
        "category": "network",
        "icon": "globe",
    },
    "macos_applog": {
        "class": MacOSAppLogAgent,
        "name": "macOS AppLog Observatory",
        "description": "Application log analysis — webshell, tampering, error spikes, credential harvest",
        "platforms": ["darwin"],
        "probes": 7,
        "category": "application",
        "icon": "file-text",
    },
    "macos_discovery": {
        "class": MacOSDiscoveryAgent,
        "name": "macOS Discovery Observatory",
        "description": "Network discovery — ARP changes, Bonjour services, rogue DHCP, topology shifts",
        "platforms": ["darwin"],
        "probes": 6,
        "category": "network",
        "icon": "radar",
    },
    "macos_internet_activity": {
        "class": MacOSInternetActivityAgent,
        "name": "macOS Internet Activity Observatory",
        "description": "Internet activity — cloud exfil, TOR/VPN, crypto mining, CDN masquerade",
        "platforms": ["darwin"],
        "probes": 8,
        "category": "application",
        "icon": "activity",
    },
    "macos_db_activity": {
        "class": MacOSDBActivityAgent,
        "name": "macOS DB Activity Observatory",
        "description": "Database monitoring — SQL injection, bulk extraction, priv escalation, exfil",
        "platforms": ["darwin"],
        "probes": 8,
        "category": "application",
        "icon": "database",
    },
    "macos_http_inspector": {
        "class": MacOSHTTPInspectorAgent,
        "name": "macOS HTTP Inspector Observatory",
        "description": "HTTP inspection — XSS, SSRF, path traversal, API abuse, C2 beaconing",
        "platforms": ["darwin"],
        "probes": 8,
        "category": "application",
        "icon": "search",
    },
    # ── Network & Infrastructure ──
    "network_sentinel": {
        "class": NetworkSentinelAgent,
        "name": "Network Sentinel",
        "description": "HTTP access log analysis, scan detection, payload inspection, rate anomaly detection",
        "platforms": ["darwin"],
        "probes": 10,
        "category": "network",
        "icon": "shield-alert",
    },
    "protocol_collectors": {
        "class": ProtocolCollectors,
        "name": "Protocol Threat Collector",
        "description": "Protocol-level threat detection for HTTP, TLS, SSH, DNS, SQL injection",
        "platforms": ["darwin"],
        "probes": 10,
        "category": "network",
        "icon": "layers",
    },
    # ── macOS Shield Agents ──
    "macos_infostealer_guard": {
        "class": MacOSInfostealerGuardAgent,
        "name": "macOS InfostealerGuard Observatory",
        "description": "AMOS/Poseidon/Banshee kill chain — keychain, browser, wallet theft, fake dialogs, exfil",
        "platforms": ["darwin"],
        "probes": 10,
        "category": "platform",
        "icon": "shield-alert",
    },
    "macos_quarantine_guard": {
        "class": MacOSQuarantineGuardAgent,
        "name": "macOS QuarantineGuard Observatory",
        "description": "Quarantine bypass, DMG delivery, ClickFix paste-and-run, Gatekeeper evasion",
        "platforms": ["darwin"],
        "probes": 8,
        "category": "platform",
        "icon": "shield-check",
    },
    "macos_provenance": {
        "class": MacOSProvenanceAgent,
        "name": "macOS Provenance Observatory",
        "description": "Cross-application attack chain correlation — message, download, execute, exfiltrate kill chains",
        "platforms": ["darwin"],
        "probes": 8,
        "category": "platform",
        "icon": "git-merge",
    },
}


def get_available_agents(platform: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """Get agents available for a given platform.

    Args:
        platform: Target platform (darwin/linux). If None, uses current.

    Returns:
        Dictionary of available agents with metadata.
    """
    import sys

    if platform is None:
        platform = sys.platform

    return {
        name: meta
        for name, meta in AGENT_REGISTRY.items()
        if platform in meta["platforms"]
    }
