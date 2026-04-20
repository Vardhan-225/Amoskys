"""Argos Precision Mode — APT-grade exploitation orchestrator.

The difference between commodity scanners (nuclei, wpscan) and an
APT-grade actor is not "what tools they run" — it's discipline:

  1. READ FIRST.  Before touching the target, download every installed
     plugin's source and study it. Know the exact parameter names, the
     exact sanitizer functions, the exact privileged paths.

  2. ONE PROBE PER FINDING.  An AST scanner found SQLi in
     `plugin-foo/ajax.php?action=lookup&id=...`?  Fire exactly one
     HTTP request with a minimal payload that confirms or denies
     exploitability. Not 50 variants. Not all 800 nuclei templates.

  3. NEVER PROBE A BLIND HYPOTHESIS.  If we don't know what we're
     looking for, we don't touch the target.  Every probe must have
     a specific expected response if vulnerable, and a specific
     expected response if not.

  4. SPREAD OVER TIME.  Low-and-slow: probes scheduled with 1-6 hour
     intervals, aligned to the target's business-hours timezone.
     One week of observation is worth more than one minute of noise.

  5. CHAIN-REASON.  Probe A's result informs probe B's payload.
     A 200 on /?p=1 means posts exist; try IDOR on post-meta next.
     A 401 on admin-ajax nonce=X means we need an unauth path.
     Never fire probes in parallel that we haven't reasoned about
     serially.

  6. LIVE OFF THE LAND.  Our probe looks like a pingback, an oEmbed
     request, a feed reader, a search engine crawl. The payload is
     in the payload-looking part of a feature the target already
     expects to receive.

Module layout
─────────────
    precision.py         The orchestrator. Stage1 → plugin-AST →
                         ranked probe plan → (optionally) fire.
    payload_synth.py     AST finding → minimal working HTTP probe.
                         Knows the exact parameter shape that plugin
                         accepts, the exact sanitizer bypass, the
                         exact expected vulnerable-response signature.
    temporal.py          Schedule discipline: timezone-aligned,
                         gaussian-jittered, multi-day-spread.
    chain.py             Chain-reasoning: finding dependencies,
                         probe ordering, result → next-probe
                         selection.

Pair with defense
─────────────────
For every primitive here, there is (or should be) an Aegis sensor
that catches it. This file documents that pairing so the arms race
stays honest:

    · `low-and-slow probing` ↔ `aegis.attacker.slow_drip`
      (baseline-deviation on single-request-per-hour patterns)
    · `targeted precision probe` ↔ `aegis.attacker.precision_probe`
      (request matches a specific plugin's known-vuln parameter shape
       BUT comes from a client that's never touched this site before)
    · `LOL (living off the land)` ↔ `aegis.attacker.lol_abuse`
      (oEmbed / pingback / REST with payloads that resemble
       exploitation, not legit feature usage)
    · `multi-origin temporal correlation` ↔
      `aegis.attacker.identity_cluster`
      (across different IPs, same pacing fingerprint / referer chain
       shape / targeted-path sequencing)

Ethics
──────
Precision Mode is STAGE 2 only. Its entire premise requires source
analysis + targeted probing — nothing passive. Requires a signed
engagement or AMOSKYS_CONSENT_DOMAIN match.
"""

from amoskys.agents.Web.argos.precision.payload_synth import (
    PayloadProbe,
    synthesize_probe,
)
from amoskys.agents.Web.argos.precision.temporal import (
    SchedulePlan,
    TargetTimezone,
    low_slow_schedule,
)
from amoskys.agents.Web.argos.precision.chain import (
    ChainContext,
    PrecisionPlan,
    build_precision_plan,
)
from amoskys.agents.Web.argos.precision.precision import (
    PrecisionEngagement,
    run_precision,
)

__all__ = [
    "PayloadProbe",
    "synthesize_probe",
    "SchedulePlan",
    "TargetTimezone",
    "low_slow_schedule",
    "ChainContext",
    "PrecisionPlan",
    "build_precision_plan",
    "PrecisionEngagement",
    "run_precision",
]
