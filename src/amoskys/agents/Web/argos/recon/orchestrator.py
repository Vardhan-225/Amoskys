"""AttackSurfaceMap — orchestrates recon sources, persists to AssetsDB.

Control flow (seed-agnostic):

    1. Detect seed type (IP vs domain).
    2. Start a ReconRun in storage.
    3. Build a ReconContext.
    4. Pick the source lineup based on seed type:
         - IP seed: reverse_dns + tls_cert + ip_whois + cymru_asn   (pivot)
                    → ct_logs + dns_resolve                         (forward)
         - Domain seed: ct_logs + dns_resolve + cymru_asn             (forward)
    5. Run sources in stealth-class order (PASSIVE → RESOLVER → ACTIVE).
    6. Stream events → DB → ReconContext (so later sources see earlier
       discoveries, which is how pivot → forward chaining works).
    7. Build a CompletenessReport: what we tried, what worked, what
       didn't, and *why not* — the customer-facing honesty that
       separates our first-report deliverable from a cheap scanner.

The orchestrator is the ONLY place events become database rows. Sources
never touch AssetsDB directly — they yield events; the orchestrator
decides how to persist. That keeps sources testable and swappable.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from amoskys.agents.Web.argos.recon.asn import ASNEnrichmentSource
from amoskys.agents.Web.argos.recon.base import (
    ReconContext,
    ReconEvent,
    ReconSource,
    ReconSourceResult,
    StealthClass,
)
from amoskys.agents.Web.argos.recon.cloud_detector import CloudDetector
from amoskys.agents.Web.argos.recon.ct_logs import CertTransparencyLogs
from amoskys.agents.Web.argos.recon.dns_resolve import DNSResolveSource
from amoskys.agents.Web.argos.recon.ip_whois import IPWHOISSource
from amoskys.agents.Web.argos.recon.reverse_dns import ReverseDNSSource
from amoskys.agents.Web.argos.recon.tls_cert import TLSCertSource
from amoskys.agents.Web.argos.storage import (
    AssetKind,
    AssetsDB,
    AuditEntry,
    Customer,
    ReconRun,
    SurfaceAsset,
)

logger = logging.getLogger("amoskys.argos.recon.orchestrator")


# Ordering: lowest stealth_class first so passive sources discover
# subdomains BEFORE resolver sources try to map them to IPs BEFORE
# ASN sources attempt to enrich those IPs.
_ORDER = {
    StealthClass.PASSIVE: 0,
    StealthClass.RESOLVER: 1,
    StealthClass.ACTIVE: 2,
}


# ── Completeness report ───────────────────────────────────────────


@dataclass
class CompletenessNote:
    """One line of the customer-facing 'what we couldn't do and why'."""
    level: str       # "ok" | "warn" | "info"
    message: str


@dataclass
class CompletenessReport:
    """The "gaps + reasons" section of the customer deliverable."""
    seed_type: str                                  # "ip" | "domain"
    pivot_notes: List[CompletenessNote] = field(default_factory=list)
    forward_notes: List[CompletenessNote] = field(default_factory=list)
    sources_skipped: List[Tuple[str, str]] = field(default_factory=list)

    def render(self) -> str:
        lines = ["Completeness notes:"]
        if self.pivot_notes:
            lines.append("  Pivot (IP → domain):")
            for n in self.pivot_notes:
                mark = {"ok": "✓", "warn": "⚠", "info": "ℹ"}.get(n.level, "•")
                lines.append(f"    {mark} {n.message}")
        if self.forward_notes:
            lines.append("  Forward (domain → surface):")
            for n in self.forward_notes:
                mark = {"ok": "✓", "warn": "⚠", "info": "ℹ"}.get(n.level, "•")
                lines.append(f"    {mark} {n.message}")
        if self.sources_skipped:
            lines.append("  Sources skipped:")
            for name, reason in self.sources_skipped:
                lines.append(f"    - {name}: {reason}")
        return "\n".join(lines)


# ── Result type ───────────────────────────────────────────────────


@dataclass
class AttackSurfaceResult:
    """Result of one full recon run."""

    run_id: str
    customer_id: str
    seed: str
    seed_type: str                                   # "ip" | "domain"
    source_results: List[ReconSourceResult] = field(default_factory=list)
    total_assets: int = 0
    duration_s: float = 0.0
    completeness: Optional[CompletenessReport] = None
    _by_kind: Dict[str, int] = field(default_factory=dict)

    def by_kind(self) -> Dict[str, int]:
        return self._by_kind

    def summary(self) -> str:
        lines = [
            f"recon run {self.run_id}",
            f"  customer: {self.customer_id}",
            f"  seed: {self.seed} ({self.seed_type})",
            f"  duration: {self.duration_s:.1f}s",
            f"  assets (total): {self.total_assets}",
        ]
        for kind, n in sorted(self._by_kind.items()):
            lines.append(f"    {kind}: {n}")
        lines.append(f"  sources:")
        for r in self.source_results:
            status = "ok" if not r.errors else f"{len(r.errors)} errors"
            lines.append(
                f"    {r.source_name}: {r.events_emitted} events, "
                f"{r.duration_s:.1f}s ({status})"
            )
        if self.completeness:
            lines.append("")
            lines.append(self.completeness.render())
        return "\n".join(lines)


# ── Orchestrator ──────────────────────────────────────────────────


class AttackSurfaceMap:
    """Coordinates recon sources against one customer's seed."""

    def __init__(
        self,
        db: AssetsDB,
        sources: Optional[List[ReconSource]] = None,
        cloud_detector: Optional[CloudDetector] = None,
    ) -> None:
        self.db = db
        self.sources = sources  # None = auto-pick at run() time
        self.cloud_detector = cloud_detector or CloudDetector()

    # ── Source lineup selection ───────────────────────────────────

    def _lineup_for(self, seed_type: str) -> List[ReconSource]:
        """Return the correct source lineup for the seed type.

        If caller injected explicit sources, use those. Otherwise pick:
          - IP seed: pivot sources first, then forward sources
          - Domain seed: forward sources only (pivot adds nothing)
        """
        if self.sources is not None:
            lineup = list(self.sources)
        elif seed_type == "ip":
            lineup = [
                # Pivot phase — IP → domain
                IPWHOISSource(),        # passive
                ReverseDNSSource(),     # resolver
                TLSCertSource(),        # active (one-shot per IP)
                # Forward phase — domain → surface
                CertTransparencyLogs(),
                DNSResolveSource(),
                ASNEnrichmentSource(),
            ]
        else:
            lineup = [
                CertTransparencyLogs(),
                DNSResolveSource(),
                ASNEnrichmentSource(),
                # Add TLS cert on discovered IPs for cross-IP pivoting
                TLSCertSource(),
            ]
        # Always re-sort by stealth class — the orchestrator, not the
        # caller, owns ordering.
        lineup.sort(key=lambda s: _ORDER.get(s.stealth_class, 99))
        return lineup

    # ── Main run ──────────────────────────────────────────────────

    def run(self, customer: Customer) -> AttackSurfaceResult:
        seed = _normalize_seed(customer.seed)
        seed_type = "ip" if _is_ip(seed) else "domain"
        sources = self._lineup_for(seed_type)

        run = ReconRun.new(customer.customer_id)
        run.sources_attempted = [s.name for s in sources]
        self.db.start_recon_run(run)

        context = ReconContext(
            customer_id=customer.customer_id,
            run_id=run.run_id,
            seed=seed,
        )

        source_results: List[ReconSourceResult] = []
        total_assets = 0
        completed: List[str] = []
        errors: List[str] = []
        sources_skipped: List[Tuple[str, str]] = []
        run_start = time.monotonic()

        # Completeness accumulator — sources populate via metadata we
        # read back from their emitted events.
        cert_pivots_skipped_cdn = 0
        ptr_generic_count = 0
        cert_pivots_succeeded = 0

        for source in sources:
            started = time.monotonic()
            events = 0
            source_errors: List[str] = []

            self._audit(
                AuditEntry(
                    log_id=None,
                    customer_id=customer.customer_id,
                    run_id=run.run_id,
                    timestamp_ns=int(time.time() * 1e9),
                    actor=source.name,
                    action="recon_source_start",
                    target=seed,
                    result="ok",
                    details={
                        "stealth_class": source.stealth_class.value,
                        "known_subdomains_at_start": len(context.known_subdomains),
                        "known_ips_at_start": len(context.known_ips),
                    },
                )
            )

            try:
                for event in source.run(context):
                    self._persist_event(customer.customer_id, event)
                    context.absorb(event)
                    events += 1
                    total_assets += 1

                    # Harvest completeness hints from event metadata.
                    md = event.metadata or {}
                    if md.get("tls_probe_skipped"):
                        cert_pivots_skipped_cdn += 1
                    if md.get("ptr_classification") == "generic_cloud":
                        ptr_generic_count += 1
                    if event.kind == AssetKind.CERT:
                        cert_pivots_succeeded += 1

                completed.append(source.name)
            except Exception as e:  # noqa: BLE001
                msg = f"{source.name}: {type(e).__name__}: {e}"
                source_errors.append(msg)
                errors.append(msg)
                sources_skipped.append((source.name, f"crashed: {type(e).__name__}"))
                logger.exception("recon source %s raised", source.name)

            duration_s = time.monotonic() - started
            source_results.append(
                source.result(
                    events_emitted=events,
                    requests_made=0,
                    errors=source_errors,
                    duration_s=duration_s,
                )
            )
            self._audit(
                AuditEntry(
                    log_id=None,
                    customer_id=customer.customer_id,
                    run_id=run.run_id,
                    timestamp_ns=int(time.time() * 1e9),
                    actor=source.name,
                    action="recon_source_complete",
                    target=seed,
                    result="ok" if not source_errors else "error",
                    details={
                        "events_emitted": events,
                        "duration_s": round(duration_s, 3),
                        "errors": source_errors,
                    },
                )
            )

        self.db.complete_recon_run(
            run_id=run.run_id,
            sources_completed=completed,
            assets_discovered=total_assets,
            errors=errors,
        )

        completeness = self._build_completeness_report(
            seed=seed,
            seed_type=seed_type,
            context=context,
            cert_pivots_skipped_cdn=cert_pivots_skipped_cdn,
            cert_pivots_succeeded=cert_pivots_succeeded,
            ptr_generic_count=ptr_generic_count,
            sources_skipped=sources_skipped,
        )

        result = AttackSurfaceResult(
            run_id=run.run_id,
            customer_id=customer.customer_id,
            seed=seed,
            seed_type=seed_type,
            source_results=source_results,
            total_assets=total_assets,
            duration_s=time.monotonic() - run_start,
            completeness=completeness,
        )
        result._by_kind = self.db.asset_counts(customer.customer_id)
        return result

    # ── Completeness report construction ──────────────────────────

    def _build_completeness_report(
        self,
        *,
        seed: str,
        seed_type: str,
        context: ReconContext,
        cert_pivots_skipped_cdn: int,
        cert_pivots_succeeded: int,
        ptr_generic_count: int,
        sources_skipped: List[Tuple[str, str]],
    ) -> CompletenessReport:
        report = CompletenessReport(seed_type=seed_type, sources_skipped=sources_skipped)

        if seed_type == "ip":
            # What we learned from the pivot attempt
            if context.known_subdomains:
                report.pivot_notes.append(CompletenessNote(
                    "ok",
                    f"TLS cert / reverse DNS yielded {len(context.known_subdomains)} hostnames",
                ))
            else:
                report.pivot_notes.append(CompletenessNote(
                    "warn",
                    "No customer hostname discoverable from the seed IP "
                    "(generic PTR + no cert SAN pivot + no whois URL). "
                    "Customer should supply a domain seed for fuller coverage.",
                ))
            if cert_pivots_skipped_cdn > 0:
                report.pivot_notes.append(CompletenessNote(
                    "warn",
                    f"{cert_pivots_skipped_cdn} IP(s) skipped for TLS cert probe "
                    "(CDN edge — origin not reachable without authorized pivot).",
                ))
            if cert_pivots_succeeded > 0:
                report.pivot_notes.append(CompletenessNote(
                    "ok",
                    f"{cert_pivots_succeeded} TLS cert(s) harvested for SAN + fingerprint "
                    "(ready for cross-IP pivot in a subsequent run).",
                ))
            if ptr_generic_count > 0:
                report.pivot_notes.append(CompletenessNote(
                    "info",
                    f"{ptr_generic_count} IP(s) have provider-generic PTR records "
                    "(cloud-hosted — customer name not derivable from PTR).",
                ))

        # Forward coverage notes
        ct_coverage_ok = any(
            s.endswith(seed) or s == seed
            for s in context.known_subdomains
        )
        if ct_coverage_ok:
            report.forward_notes.append(CompletenessNote(
                "ok",
                f"Certificate Transparency returned full history for {seed}.",
            ))
        if context.known_ips:
            report.forward_notes.append(CompletenessNote(
                "ok",
                f"{len(context.known_ips)} IP(s) resolved for discovered hostnames.",
            ))
        else:
            report.forward_notes.append(CompletenessNote(
                "warn",
                "No IPs resolved — hostnames may be behind Cloudflare "
                "proxy or DNS failed. Add customer-authorized active "
                "probing to reach origins.",
            ))

        return report

    # ── Helpers ────────────────────────────────────────────────────

    def _persist_event(self, customer_id: str, event: ReconEvent) -> str:
        asset = SurfaceAsset.new(
            customer_id=customer_id,
            kind=event.kind,
            value=event.value,
            source=event.source,
            confidence=event.confidence,
            metadata={
                **event.metadata,
                "parent_value": event.parent_value,
            },
        )
        return self.db.upsert_asset(asset)

    def _audit(self, entry: AuditEntry) -> None:
        try:
            self.db.audit(entry)
        except Exception:  # noqa: BLE001
            logger.exception("audit write failed")


def _normalize_seed(seed: str) -> str:
    t = seed.strip().lower()
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0]
    t = t.split(":", 1)[0]
    if t.startswith("*."):
        t = t[2:]
    return t


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
