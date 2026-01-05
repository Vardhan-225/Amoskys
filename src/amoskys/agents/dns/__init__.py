"""AMOSKYS DNS Monitoring Agent

Provides DNS threat detection via micro-probe architecture.

Probes:
    - RawDNSQueryProbe: Baseline DNS capture
    - DGAScoreProbe: Domain Generation Algorithm detection
    - BeaconingPatternProbe: C2 callback detection
    - SuspiciousTLDProbe: High-risk TLD flagging
    - NXDomainBurstProbe: Domain probing detection
    - LargeTXTTunnelingProbe: DNS tunneling detection
    - FastFluxRebindingProbe: Fast-flux and rebinding attacks
    - NewDomainForProcessProbe: First-time domain per process
    - BlockedDomainHitProbe: Threat intel blocklist
"""

from amoskys.agents.dns.dns_agent import DNSAgent, DNSQuery, DNSThreat
from amoskys.agents.dns.dns_agent_v2 import DNSAgentV2
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
    # Original agent
    "DNSAgent",
    "DNSQuery",
    "DNSThreat",
    # V2 agent (micro-probe architecture)
    "DNSAgentV2",
    # Probes
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
