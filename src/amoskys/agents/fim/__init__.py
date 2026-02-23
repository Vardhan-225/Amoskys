"""File Integrity Monitoring (FIM) agent.

Micro-probe architecture with 8 specialized detectors.
"""

from amoskys.agents.fim.fim_agent import BaselineEngine, FIMAgent
from amoskys.agents.fim.probes import (
    BootloaderTamperProbe,
    ChangeType,
    ConfigBackdoorProbe,
    CriticalSystemFileChangeProbe,
    FileChange,
    FileState,
    LibraryHijackProbe,
    ServiceCreationProbe,
    SUIDBitChangeProbe,
    WebShellDropProbe,
    WorldWritableSensitiveProbe,
    create_fim_probes,
)

# B5.1: Deprecated alias
FIMAgentV2 = FIMAgent

__all__ = [
    "FIMAgent",
    "FIMAgentV2",
    "BaselineEngine",
    "FileState",
    "FileChange",
    "ChangeType",
    "create_fim_probes",
    "CriticalSystemFileChangeProbe",
    "SUIDBitChangeProbe",
    "ServiceCreationProbe",
    "WebShellDropProbe",
    "ConfigBackdoorProbe",
    "LibraryHijackProbe",
    "BootloaderTamperProbe",
    "WorldWritableSensitiveProbe",
]
