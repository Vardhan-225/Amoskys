"""Aegis event-type semantics.

Every `aegis.*` event emitted by the WordPress plugin is an opaque
string to an operator ("aegis.capability.denied" — is that bad?). This
module is the single source of truth for translating those strings into
phrases a human can act on, annotated with:

  * ``concern`` — 0 (routine/informational) to 5 (active attack indicator)
  * ``audience`` — "user" events are shown in the dashboard feed;
    "internal" events are hidden behind a toggle because they are just
    heartbeats (per-request DB summaries, own-pipeline ticks, etc.)
  * ``category`` — the operator-facing bucket (Access, Code, Site, …)
    used to group events in the UI instead of the raw sensor family
  * ``verdict`` — an emoji-ish cue that's fast to scan: "👁" watching,
    "🛑" active defense just fired, "⚠" suspicious, "🟢" caught &
    handled, "ℹ︎" informational
  * ``action`` — optional one-line suggestion for what the operator
    might do, shown as a subtle hint next to the event

The taxonomy is deliberately exhaustive for the *current* Aegis emitter
vocabulary. A missing event_type falls back to a sensible default
rather than rendering a scary mystery string.

This file is pure data + a tiny accessor; no imports, no I/O, cheap to
load. Used by both the dashboard template (via humanize_event) and the
IGRIS chat backend (via active_concerns).
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Dict, Iterable, List, Optional, Tuple


@dataclass(frozen=True)
class EventMeaning:
    phrase: str  # short human title
    detail: Optional[str]  # one-line elaboration if useful
    concern: int  # 0..5
    category: str  # Access | Code | Site | Data | Probe | System
    audience: str  # "user" | "internal"
    verdict: str  # emoji-class cue
    action: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ─────────────────────────────────────────────────────────────────────
# The taxonomy.
#
# Ordering within each category: most-concerning first. This isn't load-
# bearing (callers look up by event_type, not iteration order), but it
# makes the table easier to read during code review.
#
# Concern-level scale:
#   5 = active attack indicator (attacker succeeded at *something*)
#   4 = plausible attack (repeated suspicious behavior; likely hostile)
#   3 = suspicious single event (probe, misuse, odd-but-not-obviously-malicious)
#   2 = elevated but-probably-normal (WP complaint-loud behavior with benign root)
#   1 = informational (state changes a thoughtful operator wants to see)
#   0 = heartbeat / infrastructural (should be aggregated away)
# ─────────────────────────────────────────────────────────────────────

_MEANINGS: Dict[str, EventMeaning] = {
    # ── Access / Auth ──────────────────────────────────────────────
    "aegis.auth.login_failed": EventMeaning(
        phrase="Failed admin login",
        detail="Someone tried to sign in as an existing WP user and got the password wrong",
        concern=3,
        category="Access",
        audience="user",
        verdict="⚠",
        action="Cluster by IP — 10+ in 10 min from one IP is a brute-force",
    ),
    "aegis.auth.login_success": EventMeaning(
        phrase="Admin signed in",
        detail="A WP user successfully authenticated",
        concern=1,
        category="Access",
        audience="user",
        verdict="ℹ︎",
    ),
    "aegis.auth.logout": EventMeaning(
        phrase="Admin signed out",
        detail=None,
        concern=0,
        category="Access",
        audience="internal",
        verdict="ℹ︎",
    ),
    "aegis.auth.password_changed": EventMeaning(
        phrase="Password changed",
        detail="A user's password was reset — expected only after you asked",
        concern=2,
        category="Access",
        audience="user",
        verdict="⚠",
        action="If this wasn't you, the account is compromised",
    ),
    "aegis.auth.user_created": EventMeaning(
        phrase="New WP user created",
        concern=3,
        category="Access",
        audience="user",
        verdict="⚠",
        action="Unexpected new admin = backdoor attempt",
        detail=None,
    ),
    "aegis.nonce.failed": EventMeaning(
        phrase="CSRF token rejected",
        detail="A request's WP nonce didn't match — usually a stale tab, occasionally a CSRF probe",
        concern=2,
        category="Access",
        audience="user",
        verdict="⚠",
    ),
    "aegis.capability.denied": EventMeaning(
        phrase="WP permission check firing",
        detail="Routine — WP asked 'is this user allowed?' and the answer was 'no'",
        concern=0,
        category="Access",
        audience="internal",
        verdict="ℹ︎",
    ),
    # ── Active Defense (Aegis's own blocks) ────────────────────────
    "aegis.block.started": EventMeaning(
        phrase="Aegis blocked an attacker",
        detail="Burst rate-limit tripped; offender sent to a 10-min penalty box",
        concern=4,
        category="Probe",
        audience="user",
        verdict="🛑",
        action="Celebrate — Aegis just stopped something",
    ),
    "aegis.block.enforced": EventMeaning(
        phrase="Blocked IP tried again (403)",
        detail="A still-blocked IP keeps coming back; Aegis keeps saying no",
        concern=3,
        category="Probe",
        audience="user",
        verdict="🛑",
    ),
    # ── Code / Plugin / Theme ──────────────────────────────────────
    "aegis.plugin.install": EventMeaning(
        phrase="Plugin installed",
        concern=2,
        category="Code",
        audience="user",
        verdict="⚠",
        action="Was this expected? Unknown plugin = risk",
        detail=None,
    ),
    "aegis.plugin.update": EventMeaning(
        phrase="Plugin updated",
        concern=1,
        category="Code",
        audience="user",
        verdict="ℹ︎",
        detail=None,
    ),
    "aegis.plugin.activate": EventMeaning(
        phrase="Plugin activated",
        concern=1,
        category="Code",
        audience="user",
        verdict="ℹ︎",
        detail=None,
    ),
    "aegis.plugin.deactivate": EventMeaning(
        phrase="Plugin deactivated",
        concern=1,
        category="Code",
        audience="user",
        verdict="ℹ︎",
        detail=None,
    ),
    "aegis.plugin.delete": EventMeaning(
        phrase="Plugin deleted",
        concern=2,
        category="Code",
        audience="user",
        verdict="⚠",
        detail=None,
    ),
    "aegis.theme.switched": EventMeaning(
        phrase="Theme switched",
        concern=2,
        category="Code",
        audience="user",
        verdict="⚠",
        action="Sudden theme swaps can introduce malicious templates",
        detail=None,
    ),
    "aegis.supply_chain.drift": EventMeaning(
        phrase="Supply-chain drift detected",
        detail="An installed plugin's remote version or author fingerprint changed",
        concern=3,
        category="Code",
        audience="user",
        verdict="⚠",
    ),
    "aegis.supply_chain.cycle": EventMeaning(
        phrase="Supply-chain scan completed",
        detail="Daily author/version-drift check across all installed plugins",
        concern=0,
        category="Code",
        audience="internal",
        verdict="ℹ︎",
    ),
    # ── File integrity ─────────────────────────────────────────────
    "aegis.fim.wp_config_change": EventMeaning(
        phrase="wp-config.php was modified",
        detail="The deepest trust file on a WP install changed",
        concern=5,
        category="Site",
        audience="user",
        verdict="🛑",
        action="Verify you made this change; unexpected edits are compromise",
    ),
    # ── REST / routes / probes ─────────────────────────────────────
    "aegis.rest.unauth_routes_detected": EventMeaning(
        phrase="Public REST endpoint probe",
        detail="Someone hit a /wp-json/ route known to leak info when unauthenticated",
        concern=3,
        category="Probe",
        audience="user",
        verdict="⚠",
    ),
    "aegis.rest.routes_registered": EventMeaning(
        phrase="REST routes inventory refreshed",
        concern=0,
        category="Code",
        audience="internal",
        verdict="ℹ︎",
        detail=None,
    ),
    "aegis.redirect.triggered": EventMeaning(
        phrase="Forced redirect (admin/login)",
        detail="Usually routine WP navigation; pattern-spike can mean scripted traversal",
        concern=1,
        category="Site",
        audience="user",
        verdict="ℹ︎",
    ),
    "aegis.404.observed": EventMeaning(
        phrase="Missing-resource probe (404)",
        detail="Someone hit a path that doesn't exist — scanners do this by the hundred",
        concern=2,
        category="Probe",
        audience="user",
        verdict="⚠",
        action="Cluster by IP; bursts of 404s = scanner map-out",
    ),
    # ── HTTP / request pipeline ────────────────────────────────────
    "aegis.http.request": EventMeaning(
        phrase="Inbound HTTP request",
        detail="Every inbound request — heartbeat",
        concern=0,
        category="Probe",
        audience="internal",
        verdict="ℹ︎",
    ),
    "aegis.request.poi_sensor_tick": EventMeaning(
        phrase="Request pipeline sensor tick",
        concern=0,
        category="System",
        audience="internal",
        verdict="ℹ︎",
        detail=None,
    ),
    "aegis.outbound.http": EventMeaning(
        phrase="Outbound HTTP call",
        detail="Site called an external URL — watch for calls to Ethereum RPC or known-C2 hosts",
        concern=1,
        category="Site",
        audience="user",
        verdict="ℹ︎",
    ),
    # ── Data / posts / options ─────────────────────────────────────
    "aegis.post.saved": EventMeaning(
        phrase="Post created or saved",
        concern=1,
        category="Data",
        audience="user",
        verdict="ℹ︎",
        detail=None,
    ),
    "aegis.post.status_change": EventMeaning(
        phrase="Post status changed (e.g. publish ↔ draft)",
        concern=1,
        category="Data",
        audience="user",
        verdict="ℹ︎",
        detail=None,
    ),
    "aegis.post.deleted": EventMeaning(
        phrase="Post deleted",
        concern=2,
        category="Data",
        audience="user",
        verdict="⚠",
        detail=None,
    ),
    "aegis.options.added": EventMeaning(
        phrase="WP option added",
        concern=1,
        category="Data",
        audience="user",
        verdict="ℹ︎",
        detail=None,
    ),
    "aegis.options.updated": EventMeaning(
        phrase="WP option updated",
        concern=1,
        category="Data",
        audience="user",
        verdict="ℹ︎",
        detail=None,
    ),
    "aegis.comment.created": EventMeaning(
        phrase="Comment posted",
        detail=None,
        concern=1,
        category="Data",
        audience="user",
        verdict="ℹ︎",
    ),
    "aegis.media.uploaded": EventMeaning(
        phrase="Media uploaded",
        detail=None,
        concern=1,
        category="Data",
        audience="user",
        verdict="ℹ︎",
    ),
    # ── Admin / browser ────────────────────────────────────────────
    "aegis.admin.page_view": EventMeaning(
        phrase="Admin page view",
        detail=None,
        concern=0,
        category="Access",
        audience="internal",
        verdict="ℹ︎",
    ),
    "aegis.browser.beacon": EventMeaning(
        phrase="Admin browser telemetry",
        detail=None,
        concern=0,
        category="System",
        audience="internal",
        verdict="ℹ︎",
    ),
    # ── DB / queries ───────────────────────────────────────────────
    "aegis.db.summary": EventMeaning(
        phrase="Per-request DB summary",
        detail=None,
        concern=0,
        category="Data",
        audience="internal",
        verdict="ℹ︎",
    ),
    "aegis.query.event": EventMeaning(
        phrase="Notable DB query",
        detail="Slow or anomalous query flagged by Aegis",
        concern=1,
        category="Data",
        audience="user",
        verdict="ℹ︎",
    ),
    # ── Cron / mail / lifecycle ────────────────────────────────────
    "aegis.cron.run": EventMeaning(
        phrase="Cron tick",
        detail=None,
        concern=0,
        category="System",
        audience="internal",
        verdict="ℹ︎",
    ),
    "aegis.mail.sent": EventMeaning(
        phrase="wp_mail sent",
        detail=None,
        concern=1,
        category="System",
        audience="user",
        verdict="ℹ︎",
    ),
    "aegis.mail.failed": EventMeaning(
        phrase="wp_mail failed",
        detail="Outbound transactional mail didn't deliver",
        concern=2,
        category="System",
        audience="user",
        verdict="⚠",
    ),
    "aegis.lifecycle.activate": EventMeaning(
        phrase="Aegis activated on site",
        detail=None,
        concern=0,
        category="System",
        audience="internal",
        verdict="ℹ︎",
    ),
    "aegis.lifecycle.deactivate": EventMeaning(
        phrase="Aegis deactivated on site",
        detail=None,
        concern=2,
        category="System",
        audience="user",
        verdict="⚠",
        action="Did you mean to disable the defender?",
    ),
}


# ── Fallback for types we haven't catalogued yet ──────────────────

_DEFAULT = EventMeaning(
    phrase="Unknown event",
    detail="Uncatalogued Aegis event — taxonomy update needed",
    concern=1,
    category="System",
    audience="internal",
    verdict="ℹ︎",
)


_CATEGORY_ORDER = ("Access", "Probe", "Code", "Site", "Data", "System")

# Severity cues: what an event's concern maps to for UI coloring.
_CONCERN_TO_SEV = {
    0: "info",
    1: "info",
    2: "warn",
    3: "warn",
    4: "high",
    5: "critical",
}


# ─────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────


def meaning_for(event_type: str) -> EventMeaning:
    """Return the EventMeaning for an event_type, or a sensible default."""
    return _MEANINGS.get(event_type or "", _DEFAULT)


def humanize_event(ev: Dict[str, Any]) -> Dict[str, Any]:
    """Enrich a raw Aegis event dict (as in LiveSnapshot.recent) with
    human-readable annotation — in-place semantics are not modified, a
    new dict is returned that the template can consume directly.
    """
    et = ev.get("event_type") or ""
    m = meaning_for(et)
    out = dict(ev)
    out["meaning"] = {
        "phrase": m.phrase,
        "detail": m.detail,
        "concern": m.concern,
        "category": m.category,
        "audience": m.audience,
        "verdict": m.verdict,
        "action": m.action,
        "severity_cue": _CONCERN_TO_SEV.get(m.concern, "info"),
    }
    return out


def humanize_events(
    events: Iterable[Dict[str, Any]],
    *,
    hide_internal: bool = True,
    min_concern: int = 0,
    limit: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Annotate + filter a list of events for the dashboard feed.

    Args:
        events:         iterable of raw events (from LiveSnapshot.recent)
        hide_internal:  suppress events whose audience=="internal"
        min_concern:    drop events below this concern level
        limit:          cap the output at this many most-recent events
    """
    out: List[Dict[str, Any]] = []
    for ev in events:
        h = humanize_event(ev)
        m = h["meaning"]
        if hide_internal and m["audience"] == "internal":
            continue
        if m["concern"] < min_concern:
            continue
        out.append(h)
        if limit is not None and len(out) >= limit:
            break
    return out


def category_rollup(event_types: Dict[str, int]) -> List[Dict[str, Any]]:
    """Given an event_type -> count map (from LiveSnapshot.event_types),
    return a list of category rollups suitable for a summary card:

        [{"category":"Access","count":120,"top":[("aegis.auth.login_failed", 47), …]}, …]

    Internal events are excluded. Result is ordered by _CATEGORY_ORDER,
    then by count within each. Categories with zero user-facing events
    are omitted entirely."""
    buckets: Dict[str, Dict[str, Any]] = {}
    for et, count in event_types.items():
        m = meaning_for(et)
        if m.audience == "internal":
            continue
        b = buckets.setdefault(
            m.category, {"category": m.category, "count": 0, "top_types": {}}
        )
        b["count"] += count
        b["top_types"][et] = count

    out: List[Dict[str, Any]] = []
    for cat in _CATEGORY_ORDER:
        if cat not in buckets:
            continue
        b = buckets[cat]
        top = sorted(b["top_types"].items(), key=lambda kv: kv[1], reverse=True)[:3]
        out.append(
            {
                "category": cat,
                "count": b["count"],
                "top": [
                    {"event_type": et, "phrase": meaning_for(et).phrase, "count": c}
                    for et, c in top
                ],
            }
        )
    return out


def active_concerns(
    event_types: Dict[str, int],
    severities: Dict[str, int],
    recent_events: List[Dict[str, Any]],
    active_blocks_count: int = 0,
    chain_breaks: int = 0,
) -> Dict[str, Any]:
    """Build a structured 'right-now posture' summary that the dashboard
    narrative banner and the IGRIS chat backend can both consume.

    The output is JSON-serialisable and stable — it's intended to be
    handed to both a template and an LLM as context.
    """
    # Tally concern levels across the tail (not all cumulative events —
    # we want fresh concerns, not historical).
    recent_tally = [0, 0, 0, 0, 0, 0]  # concern 0..5
    categories_hot: Dict[str, int] = {}
    top_types: Dict[str, int] = {}
    for ev in recent_events or []:
        m = meaning_for(ev.get("event_type") or "")
        recent_tally[m.concern] += 1
        if m.audience == "user" and m.concern >= 2:
            categories_hot[m.category] = categories_hot.get(m.category, 0) + 1
            top_types[m.phrase] = top_types.get(m.phrase, 0) + 1

    # Posture decision:
    #   ATTACK     -> any concern>=5 OR (concern>=4 count >= 3) OR active_blocks>=1
    #   WATCHING   -> any concern>=3 OR chain breaks > 0
    #   NORMAL     -> otherwise
    if recent_tally[5] > 0 or recent_tally[4] >= 3 or active_blocks_count >= 1:
        posture = "attack"
    elif recent_tally[3] > 0 or chain_breaks > 0:
        posture = "watching"
    else:
        posture = "normal"

    return {
        "posture": posture,
        "concern_tally": recent_tally,
        "categories_hot": categories_hot,
        "top_concerns": sorted(top_types.items(), key=lambda kv: kv[1], reverse=True)[
            :5
        ],
        "active_blocks_count": active_blocks_count,
        "chain_breaks": chain_breaks,
    }


__all__ = [
    "EventMeaning",
    "meaning_for",
    "humanize_event",
    "humanize_events",
    "category_rollup",
    "active_concerns",
]
