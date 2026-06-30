"""Argos Race & Business-Logic kit.

Two attack-surface classes commodity scanners miss:

  single_packet.py   PortSwigger's "single-packet attack" —
                     bundle N HTTP/2 request frames into one TCP
                     segment so they arrive at the origin within
                     the same network-buffer flush. Eliminates
                     ~90% of network-jitter race-window noise and
                     reliably wins coupon, registration, and
                     purchase-flow TOCTOU races.

                     Where HTTP/2 isn't available, we fall back to
                     the classic "last-byte synchronization" pipeline
                     over HTTP/1.1 keep-alive.

  toctou.py          Identify time-of-check / time-of-use flaws by
                     detecting state-read operations bracketed by
                     state-write operations without a lock.
                     High-value targets:
                       - coupon redemption (check "is valid" → mark used)
                       - registration (check "email available" → insert)
                       - purchase (check "balance ≥ price" → debit)
                       - vote (check "not voted" → record vote)
"""

from amoskys.agents.Web.argos.race.single_packet import (
    SinglePacketProbe,
    SinglePacketReport,
    build_coupon_race,
    build_parallel_purchase_race,
    build_registration_race,
    execute_single_packet,
)
from amoskys.agents.Web.argos.race.toctou import (
    TOCTOUCandidate,
    TOCTOUReport,
    analyze_endpoint_pair,
    scan_for_toctou_candidates,
)

__all__ = [
    "SinglePacketProbe",
    "SinglePacketReport",
    "build_coupon_race",
    "build_registration_race",
    "build_parallel_purchase_race",
    "execute_single_packet",
    "TOCTOUCandidate",
    "TOCTOUReport",
    "analyze_endpoint_pair",
    "scan_for_toctou_candidates",
]
