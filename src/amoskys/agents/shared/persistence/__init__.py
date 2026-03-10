"""Shared Persistence Agent — Platform-agnostic implementation.

Cross-platform persistence monitoring using baseline-and-diff detection
with 10 micro-probes. This module contains the shared (non-platform-routed)
implementation. Platform-specific routing lives in
``amoskys.agents.persistence.__init__``.

Usage:
    from amoskys.agents.shared.persistence import PersistenceGuard
    from amoskys.agents.shared.persistence.probes import create_persistence_probes
"""

from amoskys.agents.shared.persistence.agent import (  # noqa: F401
    PersistenceCollector,
    PersistenceGuard,
)
from amoskys.agents.shared.persistence.probes import (  # noqa: F401
    AuthPluginProbe,
    BrowserExtensionPersistenceProbe,
    ConfigProfileProbe,
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

__all__ = [
    "PersistenceGuard",
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
    "ConfigProfileProbe",
    "AuthPluginProbe",
]
