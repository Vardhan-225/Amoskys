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

# B5.1: Deprecated alias
DNSAgentV2 = DNSAgent

__all__ = [
    "DNSAgent",
    "DNSAgentV2",
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
