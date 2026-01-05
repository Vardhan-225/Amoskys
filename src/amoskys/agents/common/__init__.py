"""Common utilities for AMOSKYS agents.

This package provides shared functionality used across all agent implementations:
- Local queue for offline resilience
- Retry logic
- Common metrics
- Hardened agent base with tamper detection
- Advanced threat detection primitives
- Standardized CLI framework
- Micro-probe architecture for "swarm of eyes" detection
"""

# CLI Framework
from amoskys.agents.common.cli import (
    agent_main,
    build_agent_parser,
    configure_logging,
    run_agent,
    write_heartbeat,
)
from amoskys.agents.common.hardened_base import (
    EvasionTechnique,
    HardenedAgentBase,
    IntegrityState,
    ThreatContext,
    ThreatLevel,
)
from amoskys.agents.common.local_queue import LocalQueue

# Micro-Probe Architecture
from amoskys.agents.common.probes import (
    MicroProbe,
    MicroProbeAgentMixin,
    ProbeContext,
    ProbeRegistry,
    Severity,
    TelemetryEvent,
)
from amoskys.agents.common.threat_detection import (
    AttackPhase,
    C2Detector,
    CredentialAccessDetector,
    ExfiltrationDetector,
    LOLBinDetector,
    NetworkContext,
    PersistenceDetector,
    ProcessContext,
    ReverseShellDetector,
    SuspiciousPathDetector,
    ThreatAnalyzer,
    ThreatIndicator,
)

__all__ = [
    # CLI Framework
    "build_agent_parser",
    "run_agent",
    "agent_main",
    "configure_logging",
    "write_heartbeat",
    # Queue
    "LocalQueue",
    # Hardened base
    "HardenedAgentBase",
    "ThreatLevel",
    "EvasionTechnique",
    "IntegrityState",
    "ThreatContext",
    # Threat detection
    "ThreatAnalyzer",
    "ThreatIndicator",
    "ProcessContext",
    "NetworkContext",
    "AttackPhase",
    "SuspiciousPathDetector",
    "LOLBinDetector",
    "ReverseShellDetector",
    "PersistenceDetector",
    "C2Detector",
    "CredentialAccessDetector",
    "ExfiltrationDetector",
    # Micro-Probe Architecture
    "MicroProbe",
    "MicroProbeAgentMixin",
    "ProbeContext",
    "ProbeRegistry",
    "Severity",
    "TelemetryEvent",
]
