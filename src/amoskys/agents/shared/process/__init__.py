"""AMOSKYS Shared Process Agent — Platform-agnostic implementation.

Cross-platform ProcAgent using psutil for process monitoring.
8 micro-probes watch specific process threat vectors.

This is the shared (non-platform-routed) implementation. For platform-aware
routing (macOS Observatory, Linux-specific agents), use amoskys.agents.proc.

All symbols:
    from amoskys.agents.shared.process import ProcAgent
    from amoskys.agents.shared.process.probes import ProcessSpawnProbe
"""

from .agent import ProcAgent  # noqa: F401
from .probes import (  # noqa: F401
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
