"""Persistence mechanism monitoring agent.

This module provides persistence detection with micro-probe architecture:
    - PersistenceGuardV2: Micro-probe architecture with 8 specialized detectors

The v2 agent uses the "swarm of eyes" pattern with probes for:
    - macOS LaunchAgents/LaunchDaemons
    - Linux systemd services
    - Cron jobs and anacron @reboot
    - SSH authorized_keys backdoors
    - Shell profile hijacking (bashrc/zshrc)
    - Browser extension persistence
    - GUI startup items
    - Hidden executable loaders
"""

from amoskys.agents.persistence.persistence_agent_v2 import (
    PersistenceCollector,
    PersistenceGuardV2,
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
    SSHKeyBackdoorProbe,
    ShellProfileHijackProbe,
    StartupFolderLoginItemProbe,
    SystemdServicePersistenceProbe,
    create_persistence_probes,
)

__all__ = [
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
