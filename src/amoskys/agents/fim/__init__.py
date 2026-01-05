"""File Integrity Monitoring (FIM) agent.

This module provides two implementations:
    - FIMAgent: Original monolithic implementation
    - FIMAgentV2: Micro-probe architecture with 8 specialized detectors

The v2 agent uses the "swarm of eyes" pattern with probes for:
    - Critical system file tampering (binaries, configs)
    - SUID/SGID bit privilege escalation
    - Service persistence (LaunchAgents, systemd, cron)
    - Webshell detection (PHP/JSP/ASP obfuscation patterns)
    - Configuration backdoors (SSH/sudo/PAM)
    - Library hijacking (LD_PRELOAD rootkits)
    - Bootloader tampering (/boot monitoring)
    - World-writable sensitive files (permission abuse)
"""

from amoskys.agents.fim.fim_agent_v2 import FIMAgentV2, BaselineEngine
from amoskys.agents.fim.probes import (
    FileState,
    FileChange,
    ChangeType,
    create_fim_probes,
    CriticalSystemFileChangeProbe,
    SUIDBitChangeProbe,
    ServiceCreationProbe,
    WebShellDropProbe,
    ConfigBackdoorProbe,
    LibraryHijackProbe,
    BootloaderTamperProbe,
    WorldWritableSensitiveProbe,
)

__all__ = [
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
