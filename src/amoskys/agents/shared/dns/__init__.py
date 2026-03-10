"""AMOSKYS Shared DNS Monitoring Agent."""

from amoskys.agents.shared.dns.agent import DNSAgent
from amoskys.agents.shared.dns.probes import (
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
