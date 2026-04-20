"""Argos Adaptive Offense — architecture-aware attack tactic selection.

A world-class attacker doesn't fire the same playbook at every
target. They fingerprint the stack end-to-end — CDN, WAF, origin
web server, PHP version, database flavor, cache layer, OS — and
select tactics each layer is KNOWN to be weak against.

Modules:
    fingerprint.py  Deep architecture profiling via response-shape
                    analysis, error-message parsing, header forensics,
                    timing signatures, and standard-endpoint probing.
    strategy.py     Given an ArchitectureProfile, select per-class
                    attack tactics, encoding stacks, and timing
                    parameters optimized for that stack.
    origin.py       CDN/WAF bypass via origin-IP discovery: DNS
                    history, Certificate Transparency SAN leaks,
                    SPF/DMARC records, HTTP default-error-page leaks.
"""

from amoskys.agents.Web.argos.adapt.fingerprint import (
    ArchitectureProfile,
    fingerprint_architecture,
)
from amoskys.agents.Web.argos.adapt.strategy import (
    AdaptedStrategy,
    TacticSpec,
    pick_strategy,
)
from amoskys.agents.Web.argos.adapt.origin import (
    OriginCandidate,
    discover_origin,
)

__all__ = [
    "ArchitectureProfile", "fingerprint_architecture",
    "AdaptedStrategy", "TacticSpec", "pick_strategy",
    "OriginCandidate", "discover_origin",
]
