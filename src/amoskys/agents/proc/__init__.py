"""AMOSKYS Process Agent (ProcAgent)

Native process monitoring for Linux/macOS systems with micro-probe architecture.

Probes:
    - ProcessSpawnProbe: New process creation
    - LOLBinExecutionProbe: Living-off-the-land binary abuse
    - ProcessTreeAnomalyProbe: Unusual parent-child relationships
    - HighCPUAndMemoryProbe: Resource abuse detection
    - LongLivedProcessProbe: Persistent suspicious processes
    - SuspiciousUserProcessProbe: Wrong user for process type
    - BinaryFromTempProbe: Execution from temp directories
    - ScriptInterpreterProbe: Suspicious script execution
"""

from .probes import (
    PROC_PROBES,
    BinaryFromTempProbe,
    HighCPUAndMemoryProbe,
    LOLBinExecutionProbe,
    LongLivedProcessProbe,
    ProcessSpawnProbe,
    ProcessTreeAnomalyProbe,
    ScriptInterpreterProbe,
    SuspiciousUserProcessProbe,
    create_proc_probes,
)
from .proc_agent import ProcAgent
from .proc_agent_v3 import ProcAgentV3

__all__ = [
    # Original agent
    "ProcAgent",
    # V3 agent (micro-probe architecture)
    "ProcAgentV3",
    # Probes
    "BinaryFromTempProbe",
    "create_proc_probes",
    "HighCPUAndMemoryProbe",
    "LOLBinExecutionProbe",
    "LongLivedProcessProbe",
    "PROC_PROBES",
    "ProcessSpawnProbe",
    "ProcessTreeAnomalyProbe",
    "ScriptInterpreterProbe",
    "SuspiciousUserProcessProbe",
]
