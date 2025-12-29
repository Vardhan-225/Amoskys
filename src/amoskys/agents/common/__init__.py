"""Common utilities for AMOSKYS agents.

This package provides shared functionality used across all agent implementations:
- Local queue for offline resilience
- Retry logic
- Common metrics
- Hardened agent base with tamper detection
- Advanced threat detection primitives
"""

from amoskys.agents.common.local_queue import LocalQueue
from amoskys.agents.common.hardened_base import (
    HardenedAgentBase,
    ThreatLevel,
    EvasionTechnique,
    IntegrityState,
    ThreatContext,
)
from amoskys.agents.common.threat_detection import (
    ThreatAnalyzer,
    ThreatIndicator,
    ProcessContext,
    NetworkContext,
    AttackPhase,
    SuspiciousPathDetector,
    LOLBinDetector,
    ReverseShellDetector,
    PersistenceDetector,
    C2Detector,
    CredentialAccessDetector,
    ExfiltrationDetector,
)

__all__ = [
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
]
