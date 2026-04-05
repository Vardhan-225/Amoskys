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
import platform as _platform

if _platform.system() == "Linux":
    from amoskys.agents.os.linux.kernel_audit.kernel_audit_agent import KernelAuditAgent
else:
    KernelAuditAgent = None  # type: ignore[assignment,misc]

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
#
# Hierarchy:
#   CORE (8)        — Always running. Fundamental data collection.
#   SPECIALIST (5)  — Activated by Correlation when threat context detected.
#   SITUATIONAL (3) — Only on servers with web/DB services, not endpoints.
#   MERGED (3)      — Probes absorbed into parent CORE agent. Not standalone.
#
AGENT_REGISTRY: Dict[str, Dict[str, Any]] = {
    # ═══ TIER 1: CORE — Always Running (8 agents) ═══
    "proc": {
        "class": ProcAgent,
        "name": "Process Agent",
        "description": "Process trees, code signing, DYLD injection, resource abuse",
        "platforms": ["darwin"],
        "probes": 10,
        "category": "endpoint",
        "icon": "cpu",
        "tier": "core",
        "collection_agent": "macos_process",
    },
    "auth": {
        "class": AuthGuardAgent,
        "name": "AuthGuard Agent",
        "description": "SSH brute force, sudo escalation, impossible travel, off-hours login",
        "platforms": ["darwin"],
        "probes": 6,
        "category": "endpoint",
        "icon": "lock",
        "tier": "core",
        "collection_agent": "macos_auth",
    },
    "persistence": {
        "class": PersistenceGuard,
        "name": "Persistence Guard",
        "description": "LaunchAgents, cron, SSH keys, login items — baseline-diff detection",
        "platforms": ["darwin"],
        "probes": 10,
        "category": "endpoint",
        "icon": "anchor",
        "tier": "core",
        "collection_agent": "macos_persistence",
    },
    "fim": {
        "class": FIMAgent,
        "name": "File Integrity Monitor",
        "description": "SUID tracking, SIP status, Downloads monitoring, critical file hashing",
        "platforms": ["darwin"],
        "probes": 8,
        "category": "endpoint",
        "icon": "file-shield",
        "tier": "core",
        "collection_agent": "macos_filesystem",
    },
    "flow": {
        "class": FlowAgent,
        "name": "Network Agent",
        "description": "Network flows + internet activity — 18 probes: C2, exfil, TOR/VPN, mining, shadow IT",
        "platforms": ["darwin"],
        "probes": 18,
        "category": "network",
        "icon": "network",
        "tier": "core",
        "collection_agent": "macos_network",
        "merged_from": ["macos_internet_activity"],
    },
    "peripheral": {
        "class": PeripheralAgent,
        "name": "Peripheral Agent",
        "description": "USB, Bluetooth, removable media baseline-diff monitoring",
        "platforms": ["darwin"],
        "probes": 4,
        "category": "endpoint",
        "icon": "usb",
        "tier": "core",
        "collection_agent": "macos_peripheral",
    },
    "macos_unified_log": {
        "class": MacOSUnifiedLogAgent,
        "name": "Unified Log Agent",
        "description": "10 probes: securityd, Gatekeeper, TCC, XPC, installer, sharing, cert anomalies",
        "platforms": ["darwin"],
        "probes": 10,
        "category": "platform",
        "icon": "scroll",
        "tier": "core",
        "merged_from": ["macos_security_monitor"],
    },
    "correlation": {
        "class": None,  # Loaded dynamically
        "name": "Correlation Agent",
        "description": "Cross-agent kill chain tracking, AgentBus aggregation, MITRE tactic correlation",
        "platforms": ["darwin"],
        "probes": 18,
        "category": "correlation",
        "icon": "git-merge",
        "tier": "core",
    },
    # ═══ TIER 2: SPECIALIST — Activated on Threat Context (5 agents) ═══
    "macos_dns": {
        "class": MacOSDNSAgent,
        "name": "DNS Observatory",
        "description": "DGA, tunneling, beaconing, fast-flux, DoH bypass detection",
        "platforms": ["darwin"],
        "probes": 8,
        "category": "network",
        "icon": "globe",
        "tier": "specialist",
        "activation_signals": ["dns_anomaly", "c2_beacon_suspect"],
    },
    "macos_discovery": {
        "class": MacOSDiscoveryAgent,
        "name": "Discovery Observatory",
        "description": "ARP changes, Bonjour services, rogue DHCP, topology shifts",
        "platforms": ["darwin"],
        "probes": 6,
        "category": "network",
        "icon": "radar",
        "tier": "specialist",
        "activation_signals": ["lateral_movement", "new_device"],
    },
    "macos_infostealer_guard": {
        "class": MacOSInfostealerGuardAgent,
        "name": "InfostealerGuard",
        "description": "AMOS/Poseidon/Banshee kill chain — keychain, browser, wallet, fake dialogs",
        "platforms": ["darwin"],
        "probes": 10,
        "category": "platform",
        "icon": "shield-alert",
        "tier": "specialist",
        "activation_signals": ["credential_access", "keychain_access", "browser_cred_theft"],
    },
    "macos_quarantine_guard": {
        "class": MacOSQuarantineGuardAgent,
        "name": "QuarantineGuard",
        "description": "Quarantine bypass, DMG delivery, ClickFix, Gatekeeper evasion",
        "platforms": ["darwin"],
        "probes": 8,
        "category": "platform",
        "icon": "shield-check",
        "tier": "specialist",
        "activation_signals": ["gatekeeper_anomaly", "quarantine_bypass", "dmg_mount"],
    },
    "macos_provenance": {
        "class": MacOSProvenanceAgent,
        "name": "Provenance Observatory",
        "description": "Cross-app kill chain: message → download → execute → exfiltrate",
        "platforms": ["darwin"],
        "probes": 8,
        "category": "platform",
        "icon": "git-merge",
        "tier": "specialist",
        "activation_signals": ["kill_chain_stage", "download_execute", "exfil_spike"],
    },
    # ═══ TIER 3: SITUATIONAL — Server-Only Deployments (3 agents) ═══
    "macos_http_inspector": {
        "class": MacOSHTTPInspectorAgent,
        "name": "HTTP Inspector",
        "description": "18 probes: XSS, SSRF, SQLi, path traversal, scan storm, tool fingerprint",
        "platforms": ["darwin"],
        "probes": 18,
        "category": "application",
        "icon": "search",
        "tier": "situational",
        "requires": "web_server",
        "merged_from": ["network_sentinel"],
    },
    "macos_applog": {
        "class": MacOSAppLogAgent,
        "name": "AppLog Observatory",
        "description": "Web/DB application log analysis — webshell, tampering, credential harvest",
        "platforms": ["darwin"],
        "probes": 7,
        "category": "application",
        "icon": "file-text",
        "tier": "situational",
        "requires": "web_server",
    },
    "macos_db_activity": {
        "class": MacOSDBActivityAgent,
        "name": "DB Activity Observatory",
        "description": "SQL injection, bulk extraction, privilege escalation, exfiltration",
        "platforms": ["darwin"],
        "probes": 8,
        "category": "application",
        "icon": "database",
        "tier": "situational",
        "requires": "database_server",
    },
    # ═══ MERGED — Probes absorbed into parent agent, not standalone ═══
    "macos_internet_activity": {
        "class": MacOSInternetActivityAgent,
        "name": "Internet Activity (merged → flow)",
        "description": "8 probes merged into Network Agent: cloud exfil, TOR/VPN, crypto mining, CDN masquerade",
        "platforms": ["darwin"],
        "probes": 8,
        "category": "network",
        "icon": "activity",
        "tier": "merged",
        "merged_into": "flow",
    },
    "macos_security_monitor": {
        "class": MacOSSecurityMonitorAgent,
        "name": "Security Monitor (merged → unified_log)",
        "description": "4 probes merged into Unified Log Agent: cert anomaly, Gatekeeper, framework health",
        "platforms": ["darwin"],
        "probes": 4,
        "category": "platform",
        "icon": "shield-check",
        "tier": "merged",
        "merged_into": "macos_unified_log",
    },
    "network_sentinel": {
        "class": NetworkSentinelAgent,
        "name": "Network Sentinel (merged → http_inspector)",
        "description": "10 probes merged into HTTP Inspector: scan storm, brute force, tool fingerprint",
        "platforms": ["darwin"],
        "probes": 10,
        "category": "network",
        "icon": "shield-alert",
        "tier": "merged",
        "merged_into": "macos_http_inspector",
    },
    # ═══ PLATFORM — Linux-only ═══
    "kernel_audit": {
        "class": KernelAuditAgent,
        "name": "Kernel Audit Agent",
        "description": "Linux kernel-level syscall monitoring (auditd: exec, privesc, ptrace)",
        "platforms": ["linux"],
        "probes": 8,
        "category": "platform",
        "icon": "terminal",
        "tier": "core",
    },
    # ═══ PROTOCOL — Requires pcap/proxy, not runnable on stock macOS ═══
    "protocol_collectors": {
        "class": ProtocolCollectors,
        "name": "Protocol Threat Collector",
        "description": "Deep protocol inspection: HTTP, TLS, SSH, DNS, SQL at packet level",
        "platforms": ["darwin"],
        "probes": 10,
        "category": "network",
        "icon": "layers",
        "tier": "situational",
        "requires": "packet_capture",
    },
}


def get_available_agents(platform: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """Get agents available for a given platform (excludes merged agents)."""
    import sys

    if platform is None:
        platform = sys.platform

    return {
        name: meta
        for name, meta in AGENT_REGISTRY.items()
        if platform in meta["platforms"] and meta.get("tier") != "merged"
    }


def get_agents_by_tier(tier: str) -> Dict[str, Dict[str, Any]]:
    """Get all agents for a specific tier (core/specialist/situational/merged)."""
    return {
        name: meta
        for name, meta in AGENT_REGISTRY.items()
        if meta.get("tier") == tier
    }


def get_active_probe_count() -> int:
    """Total probe count across all non-merged agents."""
    return sum(
        meta["probes"]
        for meta in AGENT_REGISTRY.values()
        if meta.get("tier") != "merged"
    )
