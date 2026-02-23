"""Persistence mechanism monitoring agent.

Micro-probe architecture with 8 specialized detectors.
"""

from amoskys.agents.persistence.persistence_agent import (
    PersistenceCollector,
    PersistenceGuard,
)
from amoskys.agents.persistence.probes import (
    BrowserExtensionPersistenceProbe,
    CronJobPersistenceProbe,
    HiddenFilePersistenceProbe,
    LaunchAgentDaemonProbe,
    PersistenceBaselineEngine,
    PersistenceChange,
    PersistenceChangeType,
    PersistenceEntry,
    ShellProfileHijackProbe,
    SSHKeyBackdoorProbe,
    StartupFolderLoginItemProbe,
    SystemdServicePersistenceProbe,
    create_persistence_probes,
)

# B5.1: Deprecated alias
PersistenceGuardV2 = PersistenceGuard

__all__ = [
    "PersistenceGuard",
    "PersistenceGuardV2",
    "PersistenceCollector",
    "PersistenceEntry",
    "PersistenceChangeType",
    "PersistenceChange",
    "PersistenceBaselineEngine",
    "create_persistence_probes",
    "LaunchAgentDaemonProbe",
    "SystemdServicePersistenceProbe",
    "CronJobPersistenceProbe",
    "SSHKeyBackdoorProbe",
    "ShellProfileHijackProbe",
    "BrowserExtensionPersistenceProbe",
    "StartupFolderLoginItemProbe",
    "HiddenFilePersistenceProbe",
]
