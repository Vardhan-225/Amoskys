"""Pitch-quality scoring — rank prospects by fit for outbound.

A "good" prospect:
  + Confirmed WordPress
  + Has reachable contact (mailto, contact form, security.txt)
  + No active bug bounty program (they'd take first-refusal)
  + Visible "could use help" signals (old core, plugin leaks, exposed
    dev artifacts)
  + Appears to be small-to-medium sized (not on an enterprise CDN
    with dedicated security staff)

Each signal maps to a weight; total score is 0-100.

We're deliberately conservative: a mediocre target scores around 40,
a great one around 80, a no-go (bug bounty / government / enterprise)
ranks below 20 or is dropped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from amoskys.agents.Web.argos.prospecting.wp_indicator import (
    WPIndicatorResult,
)


@dataclass
class Prospect:
    """A scored, ranked candidate ready for Stage-1."""
    host:            str
    score:           int
    breakdown:       Dict[str, int] = field(default_factory=dict)
    is_wordpress:    bool = False
    wp_version_hint: Optional[str] = None
    contact_hints:   List[str] = field(default_factory=list)
    on_bug_bounty:   bool = False
    bounty_evidence: Optional[str] = None
    why_this_score:  str = ""
    indicator:       Optional[WPIndicatorResult] = None

    def to_dict(self) -> Dict:
        return {
            "host":             self.host,
            "score":            self.score,
            "breakdown":        self.breakdown,
            "is_wordpress":     self.is_wordpress,
            "wp_version_hint":  self.wp_version_hint,
            "contact_hints":    self.contact_hints,
            "on_bug_bounty":    self.on_bug_bounty,
            "bounty_evidence":  self.bounty_evidence,
            "why_this_score":   self.why_this_score,
        }


# ── Weights ────────────────────────────────────────────────────────

_W = {
    "wp_confirmed":            30,   # base — no WP, no fit
    "contact_reachable":       20,   # can we actually reach them?
    "security_txt_present":    15,   # explicit "we accept reports"
    "bug_bounty_PENALTY":     -60,   # hard penalty — effectively drops
    "plugin_inventory_leak":   15,   # public plugin leak = easy pitch
    "wp_generator_exposed":     5,   # minor extra
    "wp_version_old":          10,   # outdated core = strong pitch
    "enterprise_cdn_PENALTY": -15,   # probably has a dedicated security team
    "no_cdn_bonus":             5,   # smaller ops, more likely to need help
}


_KNOWN_CDN_ENTERPRISE = {"Akamai"}   # Cloudflare/Fastly are fine for SMBs


def score_prospect(indicator: WPIndicatorResult,
                   now_wp_major_minor: str = "6.9") -> Prospect:
    """Produce a Prospect score from a WP-indicator result."""
    p = Prospect(host=indicator.host, score=0, indicator=indicator,
                 is_wordpress=indicator.is_wordpress,
                 wp_version_hint=indicator.wp_version_hint,
                 contact_hints=list(indicator.contact_hints),
                 on_bug_bounty=indicator.on_bug_bounty,
                 bounty_evidence=indicator.bounty_evidence)

    breakdown = {}
    reasons: List[str] = []

    if indicator.is_wordpress:
        breakdown["wp_confirmed"] = _W["wp_confirmed"]
        reasons.append(f"WordPress confirmed (confidence {indicator.wp_confidence}%)")
    else:
        # Not WP — drop the score hard. This is not a fit for us.
        p.score = 0
        p.breakdown = breakdown
        p.why_this_score = "Not WordPress — out of scope."
        return p

    if indicator.contact_hints:
        breakdown["contact_reachable"] = _W["contact_reachable"]
        reasons.append(
            f"{len(indicator.contact_hints)} reachable contact(s) found"
        )

    if indicator.has_security_txt:
        breakdown["security_txt_present"] = _W["security_txt_present"]
        reasons.append(
            "security.txt published — explicitly welcomes disclosure"
        )

    if indicator.on_bug_bounty:
        breakdown["bug_bounty_PENALTY"] = _W["bug_bounty_PENALTY"]
        reasons.append(
            f"active bug bounty program detected — NOT a fit "
            f"({indicator.bounty_evidence})"
        )

    if indicator.plugin_inventory_leaks >= 3:
        breakdown["plugin_inventory_leak"] = _W["plugin_inventory_leak"]
        reasons.append(
            f"{indicator.plugin_inventory_leaks} plugins + versions leak "
            "publicly — strong pitch material"
        )

    if indicator.wp_generator_exposed:
        breakdown["wp_generator_exposed"] = _W["wp_generator_exposed"]
        reasons.append("WP generator meta-tag exposed")

    if indicator.wp_version_hint:
        # Is version older than current? Compare major.minor only.
        try:
            cur = tuple(int(x) for x in now_wp_major_minor.split(".")[:2])
            tgt = tuple(int(x) for x in indicator.wp_version_hint.split(".")[:2])
            if tgt < cur:
                breakdown["wp_version_old"] = _W["wp_version_old"]
                reasons.append(
                    f"WP {indicator.wp_version_hint} is older than current "
                    f"{now_wp_major_minor} — actionable outdated signal"
                )
        except Exception:
            pass

    if indicator.cdn_name in _KNOWN_CDN_ENTERPRISE:
        breakdown["enterprise_cdn_PENALTY"] = _W["enterprise_cdn_PENALTY"]
        reasons.append(
            f"fronted by {indicator.cdn_name} — likely has a dedicated "
            "security team"
        )

    if not indicator.uses_cdn:
        breakdown["no_cdn_bonus"] = _W["no_cdn_bonus"]
        reasons.append(
            "no detectable CDN — likely a smaller operator with fewer "
            "security resources"
        )

    score = sum(breakdown.values())
    # Clamp to 0-100.
    p.score = max(0, min(100, score))
    p.breakdown = breakdown
    p.why_this_score = "  · ".join(reasons)
    return p
