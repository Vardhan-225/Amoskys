"""AMOSKYS DNS Monitoring Agent

Provides DNS threat detection via micro-probe architecture.
"""

from amoskys.agents.dns.dns_agent import DNSAgent
from amoskys.agents.dns.probes import (
    DNS_PROBES,
    BeaconingPatternProbe,
    BlockedDomainHitProbe,
    DGAScoreProbe,
    FastFluxRebindingProbe,
    LargeTXTTunnelingProbe,
    NewDomainForProcessProbe,
    NXDomainBurstProbe,
    RawDNSQueryProbe,
    SuspiciousTLDProbe,
    create_dns_probes,
)

__all__ = [
    "DNSAgent",
    "BeaconingPatternProbe",
    "BlockedDomainHitProbe",
    "create_dns_probes",
    "DGAScoreProbe",
    "DNS_PROBES",
    "FastFluxRebindingProbe",
    "LargeTXTTunnelingProbe",
    "NewDomainForProcessProbe",
    "NXDomainBurstProbe",
    "RawDNSQueryProbe",
    "SuspiciousTLDProbe",
]
