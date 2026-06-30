"""Chain reasoning: probe ordering + dependency resolution.

An APT-grade attacker reasons about probe sequencing:

    A.  First, probes that give us information (low risk, low impact,
        high intel value) — plugin-inventory reads, route enumeration,
        version strings, author IDs.

    B.  Second, probes whose payload is informed by A's results —
        e.g., a SQLi probe that uses a specific parameter name we
        learned from enumerating the plugin's REST routes.

    C.  Last, probes that ONLY make sense conditional on earlier
        findings — e.g., a post-meta POI probe that requires a post
        ID we learned exists.

This module models the DAG of probe dependencies and produces a
topologically-sorted PrecisionPlan — the order the operator should
fire probes so that each is maximally informed by its predecessors.

Ranking tiers
-------------
    intel.enum       (no-risk enumeration that sharpens later probes)
    confirm.passive  (one-shot passive confirmation of a vuln)
    confirm.active   (minimal payload that forces interaction)
    escalate         (off by default; only with explicit operator flag)

The plan NEVER includes `escalate` tier probes automatically. The
operator opt-ins per-probe. This is the line between "confirmation
pentest" and "active exploitation" that separates legal engagements
from legally risky ones.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from amoskys.agents.Web.argos.precision.payload_synth import PayloadProbe

# ---- Tiering ------------------------------------------------------


_TIER_RANK = {
    "intel.enum": 0,
    "confirm.passive": 1,
    "confirm.active": 2,
    "escalate": 3,
}


def _tier_for(probe: PayloadProbe) -> str:
    """Classify a probe into the four tiers.

    Tiering is a property of the PROBE we'd send, not of the underlying
    vulnerability class. E.g. for a rest_authz finding we synthesize a
    namespace-enum GET — that's intel, regardless of whether the
    underlying finding was "missing permission" or "return_true".
    """
    rule = (probe.source_rule_id or "").lower()
    # REST-authz probe is always namespace enumeration (see payload_synth).
    if rule.startswith("rest_authz."):
        return "intel.enum"
    # SSRF canary is passive confirmation (no target-side side effect
    # beyond one outbound DNS query).
    if rule.startswith("ssrf."):
        return "confirm.passive"
    # Time-based blind SQLi is passive confirmation (no data exfil).
    if rule.startswith("sql.") and probe.risk_tier == "low":
        return "confirm.passive"
    # File upload PoC is active confirmation (writes to target).
    if rule.startswith("upload."):
        return "confirm.active"
    # POI inert payload: active (sink fires) but minimal impact.
    if rule.startswith("poi."):
        return "confirm.active"
    # CSRF: state change happens if vuln.  Active.
    if rule.startswith("csrf."):
        return "confirm.active"
    return "confirm.active"


# ---- Dependency graph --------------------------------------------


@dataclass
class ChainContext:
    """What we've learned from probes so far."""

    target_host: str = ""
    plugin_namespaces: List[str] = field(default_factory=list)
    known_post_ids: List[int] = field(default_factory=list)
    known_usernames: List[str] = field(default_factory=list)
    known_plugin_versions: Dict[str, str] = field(default_factory=dict)
    # Each entry: finding_id -> most recent probe result
    probe_results: Dict[str, Dict[str, Any]] = field(default_factory=dict)


@dataclass
class PrecisionPlan:
    """The ordered probe plan for one engagement.

    Each entry is a PayloadProbe + its assigned tier + a 'depends_on'
    list of other probe finding_ids the operator should have fired
    and reviewed first.
    """

    target: str
    probes: List[PayloadProbe] = field(default_factory=list)
    tiers: Dict[str, str] = field(default_factory=dict)
    depends: Dict[str, List[str]] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def summary(self) -> Dict[str, int]:
        c = {"intel.enum": 0, "confirm.passive": 0, "confirm.active": 0, "escalate": 0}
        for t in self.tiers.values():
            if t in c:
                c[t] += 1
        return c

    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "summary": self.summary(),
            "probes": [p.to_dict() for p in self.probes],
            "tiers": self.tiers,
            "depends": self.depends,
            "notes": self.notes,
        }


def _depends_on(probe: PayloadProbe, other_probes: List[PayloadProbe]) -> List[str]:
    """Identify which earlier-tier probes this one depends on."""
    rule = probe.source_rule_id
    deps: List[str] = []
    # Every non-enum probe benefits from REST-authz enumeration against
    # the same plugin first (so we know which routes exist).
    for op in other_probes:
        if op.plugin_slug != probe.plugin_slug:
            continue
        if _tier_for(op) == "intel.enum" and _tier_for(probe) != "intel.enum":
            deps.append(op.finding_id)
    return deps


def build_precision_plan(
    target_url: str,
    probes: List[PayloadProbe],
    include_escalate: bool = False,
) -> PrecisionPlan:
    """Take a set of synthesized probes + produce the ordered plan.

    Parameters
    ----------
    target_url        Full URL of target (for plan metadata).
    probes            Candidate probes from payload_synth.synthesize_probe.
    include_escalate  If False (default), any probe classified as
                      'escalate' is excluded from the plan with a note.

    The order of probes in the returned plan is tier-ascending:
    intel.enum first, confirm.passive next, then confirm.active,
    then (only if include_escalate) escalate. Within each tier,
    order is by plugin_slug then source_rule_id for determinism.
    """
    plan = PrecisionPlan(target=target_url)
    kept: List[PayloadProbe] = []
    for p in probes:
        tier = _tier_for(p)
        if tier == "escalate" and not include_escalate:
            plan.notes.append(
                f"excluded escalate-tier probe {p.finding_id} "
                f"({p.source_rule_id}) — operator must explicitly enable"
            )
            continue
        kept.append(p)
        plan.tiers[p.finding_id] = tier

    kept.sort(
        key=lambda p: (
            _TIER_RANK.get(_tier_for(p), 99),
            p.plugin_slug,
            p.source_rule_id,
            p.finding_id,
        )
    )
    plan.probes = kept
    for p in kept:
        plan.depends[p.finding_id] = _depends_on(p, kept)

    return plan
