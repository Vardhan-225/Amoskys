"""Argos prospecting — build ranked WordPress-target lists from public
data sources, ready for Stage-1 OSINT scans.

Goal
────
Given a seed (keyword, industry, CT-search term), produce a ranked
candidate list of 50+ WordPress sites where:
  - WP is confirmed (not guessed)
  - A public contact path exists (security.txt, /contact, about page)
  - There are visible "could use help" signals (old core, plugin leaks)
  - No active bug bounty program covers the target (we'd be stepping
    on their program's toes)

Stealth discipline
──────────────────
Discovery NEVER hits a candidate target more than 2 HTTP requests:
  1. GET / (fetch homepage, extract WP fingerprints + contact hints)
  2. GET /.well-known/security.txt (single polite check)

Both go through the LegitimacyProfile so our UA/pacing matches a
human browser. We never probe /.git, /.env, or any "loud" path during
discovery — loud paths are for the subsequent Stage-1 scan (which is
ALSO public-only, but is explicitly the scan phase, not the discovery
phase).

Data sources
────────────
  - Certificate Transparency via crt.sh (RFC 6962 public logs)
  - WP-indicator HTTP signals on the homepage
  - security.txt / RFC 9116 for receptive-disclosure targets
  - Heuristic industry/size signals from the homepage HTML

What we DON'T use
─────────────────
  - Paid APIs (BuiltWith, Wappalyzer) — we want the tool self-contained
  - Google dorking at scale — we'd get rate-limited fast; legally grey
  - Residential proxies — explicitly forbidden by OPERATOR_MANDATE.md
  - Any database we cannot re-query freely (keeps the module offline-testable)
"""

from amoskys.agents.Web.argos.prospecting.ct_discovery import discover_domains_via_ct
from amoskys.agents.Web.argos.prospecting.scoring import Prospect, score_prospect
from amoskys.agents.Web.argos.prospecting.wp_indicator import (
    WPIndicatorResult,
    check_wp_indicator,
)
from amoskys.agents.Web.argos.prospecting.wp_leads import (
    ProspectingRun,
    find_wp_prospects,
    find_wp_prospects_from_domain_list,
)

__all__ = [
    "discover_domains_via_ct",
    "WPIndicatorResult",
    "check_wp_indicator",
    "Prospect",
    "score_prospect",
    "ProspectingRun",
    "find_wp_prospects",
    "find_wp_prospects_from_domain_list",
]
