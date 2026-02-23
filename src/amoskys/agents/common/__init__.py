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

from amoskys.agents.common.base import HardenedAgentBase

# CLI Framework
from amoskys.agents.common.cli import (
    agent_main,
    build_agent_parser,
    configure_logging,
    run_agent,
    write_heartbeat,
)
from amoskys.agents.common.local_queue import LocalQueue

# AOC-1 / EAC-1 Contracts (Phase 0 — Foundation Hardening)
from amoskys.agents.common.metrics import (
    SCHEMA_VERSION,
    CircuitBreakerState,
    ProbeStatus,
    QueueAction,
    SubprocessOutcome,
)

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
    # AOC-1 / EAC-1 Contracts
    "CircuitBreakerState",
    "ProbeStatus",
    "QueueAction",
    "SubprocessOutcome",
    "SCHEMA_VERSION",
]
