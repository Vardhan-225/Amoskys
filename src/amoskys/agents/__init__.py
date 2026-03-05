# filepath: src/amoskys/agents/__init__.py
"""
AMOSKYS Agent Registry — Canonical Agents

Central registry for all security agents (Axons) in the AMOSKYS neural network.
Each agent uses the MicroProbeAgentMixin + HardenedAgentBase pattern with
independent micro-probes for comprehensive threat detection.

Agent Categories:
    - Endpoint Agents: Process, persistence, file integrity, kernel audit, auth
    - Network Agents: DNS, flow, device discovery
    - Peripheral Agents: USB, Bluetooth device monitoring
    - Protocol Collectors: MQTT, Modbus, HL7/FHIR, Syslog

Usage:
    from amoskys.agents import AuthGuardAgent, ProcAgent, FIMAgent

    # Initialize agents
    proc = ProcAgent(agent_id="proc-001", device_id="mac-001")
    fim = FIMAgent(agent_id="fim-001", device_id="mac-001")
"""

from typing import Any, Dict, Optional

from amoskys.agents.applog.applog_agent import AppLogAgent
from amoskys.agents.auth.auth_guard_agent import AuthGuardAgent

# Common base classes (canonical — from common/base.py)
from amoskys.agents.common.base import HardenedAgentBase

# Micro-probe architecture
from amoskys.agents.common.probes import MicroProbe, MicroProbeAgentMixin
from amoskys.agents.db_activity.db_activity_agent import DBActivityAgent
from amoskys.agents.device_discovery.device_discovery import DeviceDiscovery
from amoskys.agents.dns.dns_agent import DNSAgent
from amoskys.agents.fim.fim_agent import FIMAgent
from amoskys.agents.flow.flow_agent import FlowAgent
from amoskys.agents.http_inspector.http_inspector_agent import HTTPInspectorAgent
from amoskys.agents.internet_activity.internet_activity_agent import (
    InternetActivityAgent,
)
from amoskys.agents.linux.kernel_audit.kernel_audit_agent import KernelAuditAgent
from amoskys.agents.macos.security_monitor.security_monitor_agent import (
    MacOSSecurityMonitorAgent,
)
from amoskys.agents.net_scanner.net_scanner_agent import NetScannerAgent
from amoskys.agents.peripheral.peripheral_agent import PeripheralAgent
from amoskys.agents.persistence.persistence_agent import PersistenceGuard
from amoskys.agents.proc.proc_agent import ProcAgent
from amoskys.agents.protocol_collectors.protocol_collectors import ProtocolCollectors
from amoskys.agents.protocols.universal_collector import (
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
    # Endpoint Agents (canonical names)
    "AuthGuardAgent",
    "ProcAgent",
    "PersistenceGuard",
    "FIMAgent",
    "DNSAgent",
    "KernelAuditAgent",
    "MacOSSecurityMonitorAgent",
    "FlowAgent",
    # Peripheral Agents
    "PeripheralAgent",
    # Discovery
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
]

# Agent type metadata for dynamic discovery
AGENT_REGISTRY: Dict[str, Dict[str, Any]] = {
    "auth": {
        "class": AuthGuardAgent,
        "name": "AuthGuard Agent",
        "description": "Authentication and authorization monitoring via unified logging",
        "platforms": ["darwin", "linux"],
        "probes": 8,
    },
    "proc": {
        "class": ProcAgent,
        "name": "Process Agent",
        "description": "Process behavior, resource abuse, and privilege escalation detection",
        "platforms": ["darwin", "linux"],
        "probes": 8,
    },
    "persistence": {
        "class": PersistenceGuard,
        "name": "Persistence Guard",
        "description": "Persistence mechanism detection (LaunchAgents, cron, SSH keys, login items)",
        "platforms": ["darwin", "linux"],
        "probes": 8,
    },
    "fim": {
        "class": FIMAgent,
        "name": "File Integrity Monitor",
        "description": "File modification detection for critical system paths with baseline engine",
        "platforms": ["darwin", "linux"],
        "probes": 9,
    },
    "dns": {
        "class": DNSAgent,
        "name": "DNS Agent",
        "description": "DNS threat detection (C2 beaconing, DGA, tunneling, cache poisoning)",
        "platforms": ["darwin", "linux"],
        "probes": 9,
    },
    "kernel_audit": {
        "class": KernelAuditAgent,
        "name": "Kernel Audit Agent",
        "description": "Linux kernel-level syscall monitoring (auditd: exec, privesc, ptrace, module load)",
        "platforms": ["linux"],
        "probes": 8,
    },
    "macos_security_monitor": {
        "class": MacOSSecurityMonitorAgent,
        "name": "macOS Security Monitor",
        "description": "macOS security framework monitoring (Gatekeeper, PKI/trust, certificate anomalies)",
        "platforms": ["darwin"],
        "probes": 4,
    },
    "peripheral": {
        "class": PeripheralAgent,
        "name": "Peripheral Agent",
        "description": "USB, Bluetooth, and Thunderbolt device monitoring",
        "platforms": ["darwin", "linux"],
        "probes": 7,
    },
    "flow": {
        "class": FlowAgent,
        "name": "Flow Agent",
        "description": "Network flow analysis, C2 beaconing, lateral movement detection",
        "platforms": ["darwin", "linux"],
        "probes": 8,
    },
    "device_discovery": {
        "class": DeviceDiscovery,
        "name": "Device Discovery",
        "description": "Network device enumeration and asset tracking",
        "platforms": ["darwin", "linux"],
        "probes": 6,
    },
    "protocol_collectors": {
        "class": ProtocolCollectors,
        "name": "Protocol Threat Collector",
        "description": "Protocol-level threat detection for HTTP, TLS, SSH, DNS, SQL injection",
        "platforms": ["darwin", "linux"],
        "probes": 10,
    },
    # L7 Gap-Closure Agents
    "applog": {
        "class": AppLogAgent,
        "name": "AppLog Agent",
        "description": "Application log analysis with webshell, tampering, and credential detection",
        "platforms": ["darwin", "linux"],
        "probes": 8,
    },
    "db_activity": {
        "class": DBActivityAgent,
        "name": "Database Activity Agent",
        "description": "Database query monitoring for SQL injection, privilege escalation, bulk extraction",
        "platforms": ["darwin", "linux"],
        "probes": 8,
    },
    "http_inspector": {
        "class": HTTPInspectorAgent,
        "name": "HTTP Inspector Agent",
        "description": "Deep HTTP payload analysis for XSS, SSRF, path traversal, API abuse",
        "platforms": ["darwin", "linux"],
        "probes": 8,
    },
    "internet_activity": {
        "class": InternetActivityAgent,
        "name": "Internet Activity Agent",
        "description": "Outbound connection monitoring for cloud exfil, TOR/VPN, crypto mining",
        "platforms": ["darwin", "linux"],
        "probes": 8,
    },
    "net_scanner": {
        "class": NetScannerAgent,
        "name": "Network Scanner Agent",
        "description": "Active network probing with diff-based service/port/topology change detection",
        "platforms": ["darwin", "linux"],
        "probes": 7,
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
