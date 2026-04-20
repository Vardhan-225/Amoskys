"""Orchestrator — end-to-end: seed → CT discovery → WP indicator →
scoring → ranked Prospect list.

Usage (programmatic)
────────────────────
    from amoskys.agents.Web.argos.prospecting import find_wp_prospects
    run = find_wp_prospects(seed="yoga studio", want=20)
    for p in run.prospects:
        print(p.score, p.host, p.contact_hints)

Usage (CLI — to be added via __main__.py)
─────────────────────────────────────────
    python -m amoskys.agents.Web.argos.prospecting.wp_leads --seed "bakery" --want 20

Stealth budget
──────────────
Per run: N x 2 GETs (one per candidate) + 1 crt.sh query. All polite-
paced (2-5 s between candidate-qualification rounds). A 50-prospect
sweep takes ~3-6 minutes; the crt.sh query and qualification sweep
run at a rate that would pass any reasonable rate-limit.

Caller MUST review the prospects list before any Stage-1 scan runs.
This module returns RANKED CANDIDATES; it does not auto-scan.
"""

from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass, field
from typing import List, Optional

from amoskys.agents.Web.argos.legitimacy import LegitimacyProfile
from amoskys.agents.Web.argos.prospecting.ct_discovery import (
    discover_domains_via_ct,
)
from amoskys.agents.Web.argos.prospecting.scoring import (
    Prospect,
    score_prospect,
)
from amoskys.agents.Web.argos.prospecting.wp_indicator import (
    check_wp_indicator,
)

logger = logging.getLogger("amoskys.argos.prospecting")


@dataclass
class ProspectingRun:
    seed:            str
    ran_at:          float
    duration_s:      float
    ct_domains_seen: int
    ct_domains_queried: int
    http_requests:   int
    prospects:       List[Prospect] = field(default_factory=list)
    skipped:         List[str] = field(default_factory=list)

    def top(self, n: int = 10) -> List[Prospect]:
        return sorted(self.prospects, key=lambda p: -p.score)[:n]

    def to_dict(self) -> dict:
        return {
            "seed":               self.seed,
            "ran_at":             self.ran_at,
            "duration_s":         self.duration_s,
            "ct_domains_seen":    self.ct_domains_seen,
            "ct_domains_queried": self.ct_domains_queried,
            "http_requests":      self.http_requests,
            "prospects":          [p.to_dict() for p in self.top(50)],
            "skipped_count":      len(self.skipped),
        }


# ── Orchestration ─────────────────────────────────────────────────

# Hard-exclude list — always skipped even if they score well.
_EXCLUDED_SUFFIXES = (
    ".gov", ".mil", ".edu",  # government / academic — not our ICP
    "hackerone.com", "bugcrowd.com", "intigriti.com",  # bug bounty hosts
)
_EXCLUDED_DOMAINS = {
    "wordpress.org", "wordpress.com", "w.org",
    "automattic.com", "wp.com", "wp.org",
    "wpengine.com", "kinsta.com", "cloudways.com",
    "wpbeginner.com", "wpmudev.com",
    "woocommerce.com",
    # WP-ecosystem leaders — explicitly out of our ICP.
}


def _is_excluded(host: str) -> bool:
    hl = host.lower()
    if hl in _EXCLUDED_DOMAINS:
        return True
    for suf in _EXCLUDED_SUFFIXES:
        if hl.endswith(suf):
            return True
    return False


def find_wp_prospects(seed: str,
                      want: int = 20,
                      min_score: int = 40,
                      max_candidates: int = 80,
                      legitimacy: Optional[LegitimacyProfile] = None,
                      http_get_crtsh=None,
                      http_fetch_indicator=None,
                      pacing_s: float = 2.5) -> ProspectingRun:
    """End-to-end discovery → qualification → ranking.

    Args:
        seed:                  crt.sh search term (industry keyword, org
                               name, region). See module docstring for
                               examples.
        want:                  desired minimum prospect count at `min_score`+.
                               We'll keep qualifying candidates until we hit
                               this OR exhaust max_candidates, whichever first.
        min_score:             floor for inclusion in `prospects` list.
        max_candidates:        hard cap on HTTP-qualification rounds so the
                               run doesn't run forever.
        legitimacy:            LegitimacyProfile; creates a default if None.
        http_get_crtsh:        test injection for crt.sh fetch.
        http_fetch_indicator:  test injection for per-candidate HTTP.
        pacing_s:              seconds between candidate checks; we add
                               ±40% jitter.

    Returns:
        ProspectingRun with `prospects` ranked descending by score.
    """
    t0 = time.time()
    lp = legitimacy or LegitimacyProfile()
    rng = random.Random()

    # 1. Discovery.
    logger.info("prospecting: CT search for seed=%r", seed)
    ct = discover_domains_via_ct(seed, http_get=http_get_crtsh)
    ct_seen = len(ct.unique_domains)
    candidates = [d for d in ct.unique_domains if not _is_excluded(d)]

    prospects: List[Prospect] = []
    skipped: List[str] = []
    http_used = 0

    if not candidates:
        logger.warning("prospecting: no candidates after exclusion filter")
        return ProspectingRun(
            seed=seed, ran_at=t0, duration_s=round(time.time() - t0, 2),
            ct_domains_seen=ct_seen, ct_domains_queried=0,
            http_requests=0, prospects=[], skipped=[],
        )

    # 2. Per-candidate qualification.
    queried = 0
    good_count = 0
    for host in candidates[:max_candidates]:
        queried += 1
        try:
            ind = check_wp_indicator(host, legitimacy=lp,
                                     http_fetch=http_fetch_indicator)
            http_used += ind.http_requests_used
            if ind.errors:
                logger.debug("skip %s: %s", host, ind.errors)
                skipped.append(f"{host}: {ind.errors[0]}")
                continue
            if not ind.is_wordpress:
                skipped.append(f"{host}: not WordPress")
                continue
            p = score_prospect(ind)
            if p.on_bug_bounty:
                skipped.append(f"{host}: active bug bounty program")
                continue
            if p.score >= min_score:
                prospects.append(p)
                good_count += 1
                if good_count >= want:
                    break
            else:
                skipped.append(f"{host}: low score {p.score}")
        except Exception as e:  # noqa: BLE001
            logger.warning("qualification crash for %s: %s", host, e)
            skipped.append(f"{host}: {type(e).__name__}")

        # Pace between candidates.
        if queried < len(candidates):
            dur = pacing_s * rng.uniform(0.6, 1.4)
            time.sleep(dur)

    prospects.sort(key=lambda p: -p.score)

    return ProspectingRun(
        seed=seed, ran_at=t0, duration_s=round(time.time() - t0, 2),
        ct_domains_seen=ct_seen, ct_domains_queried=queried,
        http_requests=http_used, prospects=prospects, skipped=skipped,
    )


def find_wp_prospects_from_domain_list(
    domains: List[str],
    want: int = 20,
    min_score: int = 40,
    max_candidates: int = 80,
    legitimacy: Optional[LegitimacyProfile] = None,
    http_fetch_indicator=None,
    pacing_s: float = 2.5,
) -> ProspectingRun:
    """Same as find_wp_prospects() but bypasses CT discovery.

    Useful when:
      - crt.sh is rate-limiting or 5xx-ing
      - You have a pre-existing seed list (e.g., from a conference
        attendee list, BuiltWith export, a previous run, or manual
        curation)
      - You want to re-qualify an existing list

    Every other guarantee (at most 2 HTTP GETs per candidate, exclusion
    filter, bug-bounty skip, scoring) still applies.
    """
    t0 = time.time()
    lp = legitimacy or LegitimacyProfile()
    rng = random.Random()

    candidates = [d.strip().lower() for d in domains if d.strip()]
    candidates = [d for d in candidates if not _is_excluded(d)]
    ct_seen = len(domains)

    prospects: List[Prospect] = []
    skipped: List[str] = []
    http_used = 0
    queried = 0
    good_count = 0

    for host in candidates[:max_candidates]:
        queried += 1
        try:
            ind = check_wp_indicator(host, legitimacy=lp,
                                     http_fetch=http_fetch_indicator)
            http_used += ind.http_requests_used
            if ind.errors:
                skipped.append(f"{host}: {ind.errors[0]}")
                continue
            if not ind.is_wordpress:
                skipped.append(f"{host}: not WordPress")
                continue
            p = score_prospect(ind)
            if p.on_bug_bounty:
                skipped.append(f"{host}: active bug bounty program")
                continue
            if p.score >= min_score:
                prospects.append(p)
                good_count += 1
                if good_count >= want:
                    break
            else:
                skipped.append(f"{host}: low score {p.score}")
        except Exception as e:  # noqa: BLE001
            skipped.append(f"{host}: {type(e).__name__}: {e}")

        if queried < len(candidates):
            dur = pacing_s * rng.uniform(0.6, 1.4)
            time.sleep(dur)

    prospects.sort(key=lambda p: -p.score)

    return ProspectingRun(
        seed=f"domain-list[{len(domains)}]",
        ran_at=t0, duration_s=round(time.time() - t0, 2),
        ct_domains_seen=ct_seen, ct_domains_queried=queried,
        http_requests=http_used, prospects=prospects, skipped=skipped,
    )
