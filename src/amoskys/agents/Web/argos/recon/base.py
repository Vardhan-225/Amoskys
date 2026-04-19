"""Recon source primitives.

A ReconSource is one strategy for discovering assets. Sources declare:

    - name            unique identifier for the source
    - stealth_class   passive | resolver | active (ordering signal)
    - run(context)    yields ReconEvents

The orchestrator is responsible for:
    - Calling sources in stealth-class order (passive before active)
    - Persisting every emitted event to AssetsDB
    - Auditing every outbound network operation
    - Enforcing rate limits on active sources
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterator, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from amoskys.agents.Web.argos.storage import AssetKind


class StealthClass(str, Enum):
    """Ordering hint for the orchestrator."""

    PASSIVE = "passive"     # zero traffic to target; reads public DBs
    RESOLVER = "resolver"   # queries public resolvers (DNS), not target NS
    ACTIVE = "active"       # touches the target; must be rate-limited


@dataclass
class ReconEvent:
    """One discovered asset emitted by a ReconSource.

    The orchestrator converts these to SurfaceAsset records and upserts
    them to the DB. Keep fields small and typed — no raw tool output.
    """

    kind: "AssetKind"
    value: str
    source: str              # source name, e.g. "ct_logs.crtsh"
    confidence: float        # 0.0 – 1.0
    parent_value: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReconSourceResult:
    """Summary of one source's full execution."""

    source_name: str
    events_emitted: int
    requests_made: int
    errors: List[str] = field(default_factory=list)
    duration_s: float = 0.0


@dataclass
class ReconContext:
    """Shared state the orchestrator hands each source.

    The source reads `seed` to know where to start, uses `run_id` +
    `customer_id` for audit entries, and uses any enrichment data
    already discovered by earlier sources (e.g. subdomains from CT logs)
    via `known_subdomains` / `known_ips`.
    """

    customer_id: str
    run_id: str
    seed: str                        # the root domain or IP
    known_subdomains: List[str] = field(default_factory=list)
    known_ips: List[str] = field(default_factory=list)

    def absorb(self, event: ReconEvent) -> None:
        """Let sources peek at prior events (keeps helpers simple)."""
        from amoskys.agents.Web.argos.storage import AssetKind as _K
        if event.kind == _K.SUBDOMAIN or event.kind == _K.DOMAIN:
            if event.value not in self.known_subdomains:
                self.known_subdomains.append(event.value)
        elif event.kind in (_K.IPV4, _K.IPV6):
            if event.value not in self.known_ips:
                self.known_ips.append(event.value)


class ReconSource(ABC):
    """ABC — one recon strategy."""

    name: str = ""
    stealth_class: StealthClass = StealthClass.PASSIVE
    description: str = ""

    @abstractmethod
    def run(self, context: ReconContext) -> Iterator[ReconEvent]:
        """Emit discovered assets.

        Implementations SHOULD be generators — the orchestrator streams
        events into the DB incrementally so a mid-run failure still
        leaves partial surface data behind.

        Implementations MUST NOT retry on target-side block signals —
        the orchestrator handles retry policy via stealth.RateLimiter.
        """

    def result(
        self,
        events_emitted: int,
        requests_made: int,
        errors: List[str],
        duration_s: float,
    ) -> ReconSourceResult:
        return ReconSourceResult(
            source_name=self.name,
            events_emitted=events_emitted,
            requests_made=requests_made,
            errors=errors,
            duration_s=duration_s,
        )
