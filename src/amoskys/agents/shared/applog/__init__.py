"""AMOSKYS Shared AppLog Monitoring Agent."""

from amoskys.agents.shared.applog.agent import AppLogAgent
from amoskys.agents.shared.applog.probes import (
    APPLOG_PROBES,
    ContainerBreakoutLogProbe,
    CredentialHarvestProbe,
    ErrorSpikeAnomalyProbe,
    LogInjectionProbe,
    LogTamperingProbe,
    PrivilegeEscalationLogProbe,
    Suspicious4xx5xxProbe,
    WebShellAccessProbe,
    create_applog_probes,
)

__all__ = [
    "AppLogAgent",
    "APPLOG_PROBES",
    "ContainerBreakoutLogProbe",
    "create_applog_probes",
    "CredentialHarvestProbe",
    "ErrorSpikeAnomalyProbe",
    "LogInjectionProbe",
    "LogTamperingProbe",
    "PrivilegeEscalationLogProbe",
    "Suspicious4xx5xxProbe",
    "WebShellAccessProbe",
]
