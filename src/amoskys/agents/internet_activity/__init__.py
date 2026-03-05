"""AMOSKYS Internet Activity Agent - Outbound Connection & Browsing Security Analysis.

Micro-probe architecture with 8 specialized detectors for internet activity threat vectors.
"""

from amoskys.agents.internet_activity.agent_types import (
    BrowsingEntry,
    OutboundConnection,
)
from amoskys.agents.internet_activity.internet_activity_agent import (
    InternetActivityAgent,
)
from amoskys.agents.internet_activity.probes import (
    INTERNET_ACTIVITY_PROBES,
    CloudExfilProbe,
    CryptoMiningProbe,
    DNSOverHTTPSProbe,
    LongLivedConnectionProbe,
    ShadowITSaaSProbe,
    SuspiciousDownloadProbe,
    TORVPNUsageProbe,
    UnusualGeoConnectionProbe,
    create_internet_activity_probes,
)

__all__ = [
    "InternetActivityAgent",
    "OutboundConnection",
    "BrowsingEntry",
    "CloudExfilProbe",
    "TORVPNUsageProbe",
    "CryptoMiningProbe",
    "SuspiciousDownloadProbe",
    "ShadowITSaaSProbe",
    "UnusualGeoConnectionProbe",
    "LongLivedConnectionProbe",
    "DNSOverHTTPSProbe",
    "INTERNET_ACTIVITY_PROBES",
    "create_internet_activity_probes",
]
