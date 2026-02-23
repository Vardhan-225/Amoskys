"""AMOSKYS Process Agent (ProcAgent)

Native process monitoring for Linux/macOS systems with micro-probe architecture.
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

# B5.1: Deprecated alias
ProcAgentV3 = ProcAgent

__all__ = [
    "ProcAgent",
    "ProcAgentV3",
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
