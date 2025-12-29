# filepath: /Users/athanneeru/Downloads/GitHub/Amoskys/src/amoskys/agents/__init__.py
"""
AMOSKYS Agent Registry

Central registry for all security agents (Axons) in the AMOSKYS neural network.
Each agent is a specialized sensor for a specific security domain.

Agent Categories:
    - Endpoint Agents: Process, persistence, file integrity, kernel audit
    - Network Agents: DNS, flow, SNMP
    - Peripheral Agents: USB, Bluetooth device monitoring
    - Protocol Agents: MQTT, Modbus, HL7/FHIR, Syslog

Usage:
    from amoskys.agents import AuthGuardAgent, ProcAgent, FIMAgent
    
    # Initialize agents
    proc = ProcAgent()
    fim = FIMAgent()
"""

from typing import Dict, Optional

# Common base classes
from amoskys.agents.common.hardened_base import (
    HardenedAgentBase,
    AgentOperationalMode,
    EvasionTechnique,
)

# Endpoint Agents (class-based)
from amoskys.agents.auth.auth_agent import AuthGuardAgent
from amoskys.agents.proc.proc_agent import ProcAgent
from amoskys.agents.persistence.persistence_agent import PersistenceGuardAgent
from amoskys.agents.file_integrity.file_integrity_agent import FIMAgent
from amoskys.agents.dns.dns_agent import DNSAgent
from amoskys.agents.kernel_audit.kernel_audit_agent import KernelAuditAgent

# Peripheral Agents
from amoskys.agents.peripheral.peripheral_agent import PeripheralAgent

# Discovery Engine
from amoskys.agents.discovery.device_scanner import DeviceDiscoveryEngine

# Protocol Collectors
from amoskys.agents.protocols.universal_collector import (
    UniversalTelemetryCollector,
    MQTTCollector,
    ModbusCollector,
    HL7FHIRCollector,
    SyslogCollector,
)

__all__ = [
    # Base classes
    "HardenedAgentBase",
    "AgentOperationalMode",
    "EvasionTechnique",
    # Endpoint Agents
    "AuthGuardAgent",
    "ProcAgent",
    "PersistenceGuardAgent",
    "FIMAgent",
    "DNSAgent",
    "KernelAuditAgent",
    # Peripheral Agents
    "PeripheralAgent",
    # Discovery
    "DeviceDiscoveryEngine",
    # Protocol Collectors
    "UniversalTelemetryCollector",
    "MQTTCollector",
    "ModbusCollector",
    "HL7FHIRCollector",
    "SyslogCollector",
]

# Agent type metadata for dynamic discovery
AGENT_REGISTRY = {
    "auth": {
        "class": AuthGuardAgent,
        "name": "AuthGuard Agent",
        "description": "Authentication and authorization monitoring",
        "platforms": ["darwin", "linux", "windows"],
    },
    "proc": {
        "class": ProcAgent,
        "name": "Process Agent",
        "description": "Process behavior and resource monitoring",
        "platforms": ["darwin", "linux", "windows"],
    },
    "persistence": {
        "class": PersistenceGuardAgent,
        "name": "Persistence Guard Agent",
        "description": "Persistence mechanism detection (launchd, cron, etc.)",
        "platforms": ["darwin", "linux"],
    },
    "fim": {
        "class": FIMAgent,
        "name": "File Integrity Monitor",
        "description": "File modification detection for critical system paths",
        "platforms": ["darwin", "linux", "windows"],
    },
    "dns": {
        "class": DNSAgent,
        "name": "DNS Agent",
        "description": "DNS threat detection (C2, DGA, tunneling)",
        "platforms": ["darwin", "linux", "windows"],
    },
    "kernel_audit": {
        "class": KernelAuditAgent,
        "name": "Kernel Audit Agent",
        "description": "Kernel-level monitoring (privilege escalation, container escape)",
        "platforms": ["darwin", "linux"],
    },
    "peripheral": {
        "class": PeripheralAgent,
        "name": "Peripheral Agent",
        "description": "USB and Bluetooth device monitoring",
        "platforms": ["darwin", "linux"],
    },
    # Script-based agents (not class-based)
    "snmp": {
        "module": "amoskys.agents.snmp.snmp_agent",
        "name": "SNMP Agent",
        "description": "Network device monitoring via SNMP",
        "platforms": ["darwin", "linux", "windows"],
    },
    "flow": {
        "module": "amoskys.agents.flowagent.main",
        "name": "Flow Agent",
        "description": "Network flow analysis with WAL persistence",
        "platforms": ["darwin", "linux", "windows"],
    },
}


def get_available_agents(platform: Optional[str] = None) -> Dict:
    """Get agents available for a given platform
    
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
