"""AMOSKYS AppLog Monitoring Agent

Provides application log threat detection via micro-probe architecture.
"""

from amoskys.agents.applog.applog_agent import AppLogAgent
from amoskys.agents.applog.probes import (
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
