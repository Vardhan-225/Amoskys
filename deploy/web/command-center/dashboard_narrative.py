"""Dashboard narrative banner — 'what's happening right now'.

Takes the AegisTail snapshot and the event-semantics active_concerns
payload and produces a short, specific sentence that belongs at the top
of the dashboard. Replaces the 'total events' vanity counter as the
operator's first glance.

Three postures drive three visual treatments in the template:

  normal    — "Quiet. 12 humans, 4 search bots, 0 probes in the last 10 min."
              (green ambient bar, minimal copy)

  watching  — "Elevated chatter. 139.87.112.106 scanned 47 paths in 5 min."
              (amber ambient bar, 1-2 facts, link to investigate)

  attack    — "Active defense engaged. 139.87.112.106 blocked after 34 failed
               logins; still retrying."
              (red pulsing bar, biggest numbers, CTA to the block detail)

Everything in here is pure functions. No I/O. Unit-testable. Called on
every dashboard render (cheap).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class Narrative:
    posture: str        # "normal" | "watching" | "attack"
    headline: str       # one short sentence, operator-facing
    detail: str         # one longer sentence with numbers
    cta_text: Optional[str] = None
    cta_href: Optional[str] = None
    # Color cues for the template; keeps all style choices in one place.
    accent_class: str = "norm"   # norm | warn | alert
    pulse: bool = False          # animate on attack posture

    def to_dict(self) -> Dict[str, Any]:
        return {
            "posture":      self.posture,
            "headline":     self.headline,
            "detail":       self.detail,
            "cta_text":     self.cta_text,
            "cta_href":     self.cta_href,
            "accent_class": self.accent_class,
            "pulse":        self.pulse,
        }


def _fmt(n: int) -> str:
    return f"{n:,}"


def _top_ip(ips: List[Tuple[str, int]]) -> Optional[Tuple[str, int]]:
    return ips[0] if ips else None


def build(snap, concerns_payload: Dict[str, Any], crawlers_totals: Optional[Dict[str, int]] = None) -> Narrative:
    """Build a Narrative from the current snapshot + concerns payload."""
    posture = concerns_payload.get("posture", "normal")
    recent = getattr(snap, "recent", []) or []

    # External IPs list (sorted by count, desc) — stored as dict on snap.
    ips_dict = getattr(snap, "external_ips", {}) or {}
    ips = sorted(ips_dict.items(), key=lambda kv: kv[1], reverse=True)

    # Recent concern tally for the "last few minutes" framing.
    tally = concerns_payload.get("concern_tally", [0, 0, 0, 0, 0, 0])
    recent_user_concerns = sum(tally[2:])  # concern >= 2 = warn+

    active_blocks = concerns_payload.get("active_blocks_count", 0)
    chain_breaks = concerns_payload.get("chain_breaks", 0)

    # ────────────── ATTACK ──────────────
    if posture == "attack":
        top = _top_ip(ips)
        top_phrase = f"`{top[0]}` ({_fmt(top[1])} events)" if top else "an attacker"
        if active_blocks > 0:
            headline = f"🛑 Active defense engaged · {active_blocks} blocked IP{'s' if active_blocks != 1 else ''}"
            detail = (
                f"Aegis auto-blocked attackers in the last 10 minutes. "
                f"Loudest caller: {top_phrase}."
            )
        else:
            headline = "🛑 Attack indicators — no block yet"
            detail = (
                f"{top_phrase} triggered high-concern events but hasn't tripped the rate-limit. "
                f"Consider manual intervention."
            )
        return Narrative(
            posture="attack",
            headline=headline,
            detail=detail,
            cta_text="Open investigate →",
            cta_href="/web/investigate?q=severity:critical,high+since:1h",
            accent_class="alert",
            pulse=True,
        )

    # ────────────── WATCHING ──────────────
    if posture == "watching":
        top = _top_ip(ips)
        top_phrase = f"`{top[0]}` ({_fmt(top[1])} events)" if top else None
        parts: List[str] = []
        if top_phrase:
            parts.append(f"Loudest caller: {top_phrase}")
        if recent_user_concerns:
            parts.append(f"{recent_user_concerns} suspicious event(s) in current tail")
        if chain_breaks:
            parts.append(f"{chain_breaks} chain break(s)")

        headline = "👁 Elevated chatter — watching"
        detail = "; ".join(parts) if parts else "Signal above baseline but nothing has crossed the line."
        return Narrative(
            posture="watching",
            headline=headline,
            detail=detail,
            cta_text="Investigate →",
            cta_href="/web/investigate?q=severity:warn,high+since:1h",
            accent_class="warn",
            pulse=False,
        )

    # ────────────── NORMAL ──────────────
    ct = crawlers_totals or {}
    humans = ct.get("human", 0)
    search = ct.get("search", 0)
    seo    = ct.get("seo", 0)
    bots   = ct.get("ai", 0) + ct.get("bot_other", 0) + ct.get("unknown", 0)
    bits: List[str] = []
    if humans: bits.append(f"{_fmt(humans)} human{'s' if humans != 1 else ''}")
    if search: bits.append(f"{_fmt(search)} search crawler{'s' if search != 1 else ''}")
    if seo:    bits.append(f"{_fmt(seo)} SEO tool{'s' if seo != 1 else ''}")
    if bots:   bits.append(f"{_fmt(bots)} other bot{'s' if bots != 1 else ''}")

    if bits:
        detail = "Traffic mix: " + ", ".join(bits) + "."
    else:
        detail = "No traffic in the current tail."

    headline = "🟢 Quiet — no active threats"
    return Narrative(
        posture="normal",
        headline=headline,
        detail=detail,
        cta_text="Open event log →",
        cta_href="/web/investigate",
        accent_class="norm",
        pulse=False,
    )


__all__ = ["Narrative", "build"]
