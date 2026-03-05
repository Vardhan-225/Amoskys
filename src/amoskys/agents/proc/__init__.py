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

__all__ = [
    "ProcAgent",
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
