"""IGRIS-Web chat backend (lab edition).

Two modes, auto-selected at request time:

  1. LIVE mode — if ``ANTHROPIC_API_KEY`` is set in the environment.
     Real multi-turn chat with Claude, grounded in a system prompt
     that names IGRIS's role and scope, and primed with a live
     snapshot of the current Aegis state (so IGRIS can answer
     "what's happening right now?" without us having to build RAG).

  2. GROUND mode — if no API key is present. A rule-based responder
     that still feels helpful because it reads the same live Aegis
     state and answers a fixed set of useful questions with real
     numbers. This keeps the chat surface usable from day one, and
     operators get a coherent experience even when we're saving on
     API spend during development.

Design constraints:
  * Chat is *scoped to the current user's site* — IGRIS never answers
    questions about fleet-wide data in this context. Keeps the
    multi-tenant story honest even in a single-tenant lab.
  * No conversation state is persisted server-side (yet). The client
    maintains turn history and sends it back on each message. This is
    good enough for the lab and avoids DB-design decisions we'd want
    to revisit once we have a real tenant/session model.
  * Responses are short by construction. Every mode is instructed /
    rule-bound to answer in Slack-style prose, not essays.

IGRIS-Web is deliberately distinct from the endpoint IGRIS brain in
the macOS product — different training vocabulary (HTTP methods, WP
hooks, plugin lifecycle, CVEs vs process trees, kernel events, DNS).
See src/amoskys/igris/chat.py in the main repo for the endpoint
version.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("amoskys.web.igris")


# ─────────────────────────────────────────────────────────────────────
# System prompt used in LIVE mode.
# Short & specific. Tone matches IGRIS-Web's existing copywriting voice
# ("neural security command platform"). Length bounds enforced both by
# prompt and client-side truncation.
# ─────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are IGRIS-Web, the reasoning layer that sits between the Aegis
WordPress plugin and the operator of a single customer site. You read
live telemetry (logins, probes, plugin lifecycle, file-integrity, HTTP
requests) and translate it into short, actionable answers.

Style:
  • Slack-style short prose. 1-3 sentences by default. No markdown
    headers. Use inline code `like_this` only for event types or IPs.
  • Name numbers precisely: "3 failed logins from 139.87.112.106 in the
    last 10 min" beats "there were some failed logins".
  • Never invent data. If the snapshot doesn't cover the question,
    say so plainly and suggest what you'd need.
  • Never mention fleet data or other tenants — you only see this
    customer's site.

Scope:
  • You are advisor, not autopilot. Never claim to have taken action
    unless the user asks you to trigger something and you receive a
    tool-call back confirming it.
  • If asked about Aegis internals (event taxonomy, chain linking,
    supply-chain drift mechanics), give the short version.

The live Aegis snapshot for this request is attached in the user's
first message as <aegis_snapshot>JSON</aegis_snapshot>. Read it as
authoritative ground truth for questions about "right now".
"""


# Safety caps
_MAX_HISTORY_TURNS = 8          # user+assistant pairs
_MAX_USER_LEN = 2000
_MAX_RESPONSE_TOKENS = 512
_LIVE_MODEL = os.environ.get("IGRIS_WEB_MODEL", "claude-sonnet-4-5")


# ─────────────────────────────────────────────────────────────────────
# Snapshot → context blob.
# The LIVE backend gets this verbatim in a <aegis_snapshot> fence.
# The GROUND backend also reads it to answer rule-based questions.
# ─────────────────────────────────────────────────────────────────────


def build_context(snap, active_concerns_payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Distill an AegisTail.snapshot() result into a minimal JSON blob
    suitable for system-priming the LLM or rule-matching in GROUND mode.

    We pick only fields that are *stable* and *bounded* — never pass
    the full ring buffer or every event_type count; an LLM doesn't
    need that volume to answer the kinds of questions operators ask.
    """
    recent = snap.recent[:20] if hasattr(snap, "recent") else []
    top_types = list((snap.event_types or {}).items())[:10]
    top_ips = list((snap.external_ips or {}).items())[:5]
    active_blocks = getattr(snap, "active_blocks", []) or []

    return {
        "total_events": getattr(snap, "total_events", 0),
        "ingest_caught_up": getattr(snap, "ingest_caught_up", True),
        "top_event_types": [{"type": t, "count": c} for t, c in top_types],
        "top_external_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
        "severities_total": dict(getattr(snap, "severities", {}) or {}),
        "active_blocks_count": getattr(snap, "blocks_started_count", 0),
        "active_blocks": [
            {"ip": b.get("ip"), "rule": b.get("rule"), "strikes": b.get("strikes")}
            for b in active_blocks[:5]
        ],
        "chain_ok":     getattr(snap, "chain_ok", 0),
        "chain_breaks": getattr(snap, "chain_breaks", 0),
        "recent": [
            {
                "event_type": e.get("event_type"),
                "severity":   e.get("severity"),
                "ts_ns":      e.get("ts_ns"),
                "ip":         (e.get("request") or {}).get("ip"),
                "attrs":      {k: v for k, v in (e.get("attributes") or {}).items() if k in
                               {"ip", "rule", "strikes", "slug", "drift_type", "user_login", "role"}},
            }
            for e in recent
        ],
        "concerns": active_concerns_payload or {},
    }


# ─────────────────────────────────────────────────────────────────────
# LIVE mode — Anthropic API.
# ─────────────────────────────────────────────────────────────────────


def _have_anthropic_key() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())


def _have_anthropic_sdk() -> bool:
    try:
        import anthropic  # noqa: F401
        return True
    except ImportError:
        return False


def _reply_live(
    user_text: str,
    history: List[Dict[str, str]],
    context: Dict[str, Any],
) -> Tuple[str, str]:
    """Call Claude. Returns (reply_text, backend_label).

    Raises exceptions only on hard network/auth failures; rate-limit /
    content-block surfaces as a human string.
    """
    import anthropic  # lazy import so GROUND mode has no dependency

    client = anthropic.Anthropic()  # uses ANTHROPIC_API_KEY from env

    # Format history for the API. System message stays separate.
    msgs: List[Dict[str, Any]] = []

    # First user turn carries the snapshot; subsequent turns are plain.
    first = True
    for turn in history[-(_MAX_HISTORY_TURNS * 2):]:
        role = turn.get("role")
        if role not in ("user", "assistant"):
            continue
        content = (turn.get("content") or "")[:_MAX_USER_LEN]
        if not content.strip():
            continue
        msgs.append({"role": role, "content": content})

    # Append the new user message, with snapshot as priming on EACH turn
    # (cheap — stays inside prompt-cache semantics since the snapshot
    # changes slowly for a given polling interval).
    primed_user = (
        f"<aegis_snapshot>\n{json.dumps(context, ensure_ascii=False)}\n</aegis_snapshot>\n\n"
        f"{user_text.strip()}"
    )
    msgs.append({"role": "user", "content": primed_user})

    resp = client.messages.create(
        model=_LIVE_MODEL,
        max_tokens=_MAX_RESPONSE_TOKENS,
        system=SYSTEM_PROMPT,
        messages=msgs,
    )

    # Extract text parts
    reply_parts: List[str] = []
    for block in resp.content or []:
        if getattr(block, "type", None) == "text":
            reply_parts.append(block.text or "")
    reply = "\n".join(p for p in reply_parts if p).strip()
    if not reply:
        reply = "(IGRIS had no reply — try rephrasing.)"

    return reply, f"live/{_LIVE_MODEL}"


# ─────────────────────────────────────────────────────────────────────
# GROUND mode — rule-based, still-useful responder.
#
# Covers the 80% of operator questions the lab actually gets:
#   - "what's happening right now?"
#   - "who's attacking me?" / "top IPs"
#   - "any blocks?"
#   - "chain integrity" / "is the log clean?"
#   - "show me failed logins"
#   - "what events have you seen?" / "aegis event types"
#   - "help" / "what can you do?"
#
# Anything else -> a polite "I'm in ground mode; ANTHROPIC_API_KEY not
# set so I can only answer factual questions about the current state".
# ─────────────────────────────────────────────────────────────────────


def _fmt_int(n: int) -> str:
    return f"{n:,}"


def _reply_ground(user_text: str, context: Dict[str, Any]) -> Tuple[str, str]:
    q = (user_text or "").lower().strip()

    # HELP
    if any(k in q for k in ("help", "what can you", "capabilities", "what do you do")):
        return (
            "I'm IGRIS-Web in ground mode (no `ANTHROPIC_API_KEY` yet). I answer "
            "factual questions about your Aegis telemetry: "
            "`what's happening right now`, `top IPs`, `any blocks`, `chain integrity`, "
            "`failed logins`, or `event types`. "
            "Wire `ANTHROPIC_API_KEY` into `/etc/amoskys/amoskys-web.env` and I'll reason instead of look up.",
            "ground/help",
        )

    # RIGHT NOW / STATUS / POSTURE
    if any(k in q for k in ("right now", "what's happening", "status", "posture", "everything ok", "all good")):
        posture = (context.get("concerns") or {}).get("posture", "normal")
        blocks = context.get("active_blocks_count", 0)
        top_ip = (context.get("top_external_ips") or [{}])[0]
        if posture == "attack":
            return (
                f"🛑 Active defense engaged. {blocks} blocks in effect. "
                f"Top caller: `{top_ip.get('ip','?')}` ({_fmt_int(top_ip.get('count',0))} events). "
                f"Open the investigate view to drill in.",
                "ground/status",
            )
        if posture == "watching":
            breaks = context.get("chain_breaks", 0)
            chain_note = f" · chain breaks={breaks}" if breaks else ""
            return (
                f"👁 Watching. No active attack, but suspicious signal above noise floor{chain_note}. "
                f"Top caller `{top_ip.get('ip','?')}` ({_fmt_int(top_ip.get('count',0))}).",
                "ground/status",
            )
        return (
            f"🟢 Normal. {_fmt_int(context.get('total_events',0))} events indexed; "
            f"top caller `{top_ip.get('ip','?')}` — not above baseline.",
            "ground/status",
        )

    # TOP IPs / ATTACKERS
    if any(k in q for k in ("top ip", "top callers", "attacker", "who's hitting", "who is hitting", "loudest")):
        ips = context.get("top_external_ips") or []
        if not ips:
            return ("No external IPs recorded yet.", "ground/top_ips")
        lines = "\n".join(f"• `{x['ip']}` — {_fmt_int(x['count'])} events" for x in ips[:5])
        return (f"Top IPs hitting your site:\n{lines}", "ground/top_ips")

    # BLOCKS
    if "block" in q:
        blocks = context.get("active_blocks_count", 0)
        if blocks == 0:
            return ("No IPs in Aegis's penalty box right now.", "ground/blocks")
        blist = context.get("active_blocks") or []
        detail = "; ".join(f"`{b.get('ip')}` ({b.get('rule')}, {b.get('strikes')} strikes)" for b in blist[:3])
        return (f"{blocks} IP(s) currently blocked: {detail}", "ground/blocks")

    # CHAIN
    if any(k in q for k in ("chain", "integrity", "tamper", "log clean")):
        ok = context.get("chain_ok", 0)
        breaks = context.get("chain_breaks", 0)
        total = ok + breaks
        pct = (100.0 * ok / total) if total else 0.0
        if breaks == 0:
            return (f"Chain 100% intact — {_fmt_int(ok)} events cryptographically linked.", "ground/chain")
        return (
            f"{pct:.2f}% chain-ok · {breaks} break(s) out of {_fmt_int(total)}. "
            f"Usually benign (interleaved writes from a burst), but worth a look if it grows.",
            "ground/chain",
        )

    # FAILED LOGINS
    if any(k in q for k in ("failed login", "brute force", "password attempts", "login failures")):
        by_type = {t["type"]: t["count"] for t in context.get("top_event_types", [])}
        n = by_type.get("aegis.auth.login_failed", 0)
        if n == 0:
            return ("No failed-login events in the current tail.", "ground/auth")
        return (
            f"{_fmt_int(n)} failed-login events visible. Group by IP in Investigate "
            "to see whether it's one attacker or scattered noise.",
            "ground/auth",
        )

    # EVENT TYPES
    if any(k in q for k in ("event type", "what events", "what do you see")):
        types = context.get("top_event_types") or []
        if not types:
            return ("No events in the tail yet.", "ground/event_types")
        lines = "\n".join(f"• `{t['type']}` — {_fmt_int(t['count'])}" for t in types[:8])
        return (f"Top event types in the current tail:\n{lines}", "ground/event_types")

    # RUDE BUT HONEST DEFAULT
    return (
        "I'm in ground mode and didn't match that to a rule. Try `what's happening right now`, "
        "`top IPs`, `any blocks`, `chain integrity`, `failed logins`, or `event types`. "
        "Once `ANTHROPIC_API_KEY` is set I'll reason like a real assistant.",
        "ground/default",
    )


# ─────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────


@dataclass
class ChatReply:
    text: str
    backend: str
    mode: str             # "live" | "ground"
    posture: Optional[str] = None
    took_ms: int = 0
    warning: Optional[str] = None


def chat(
    user_message: str,
    history: Optional[List[Dict[str, str]]] = None,
    *,
    snap=None,
    active_concerns_payload: Optional[Dict[str, Any]] = None,
) -> ChatReply:
    """Entry point. Returns a ChatReply regardless of backend availability.

    Args:
        user_message: the latest user message (already trimmed by caller)
        history:      list of {"role":"user"|"assistant","content":str}
        snap:         AegisTail.snapshot() result (recent state)
        active_concerns_payload: pre-computed output of
            event_semantics.active_concerns() — passed through to context
            so LIVE mode can reason about posture without re-deriving.
    """
    t0 = time.perf_counter()
    user_message = (user_message or "").strip()[:_MAX_USER_LEN]
    if not user_message:
        return ChatReply(text="(empty message)", backend="none", mode="ground")

    history = history or []

    context = build_context(snap, active_concerns_payload) if snap is not None else {}
    posture = (context.get("concerns") or {}).get("posture")

    mode = "live" if (_have_anthropic_key() and _have_anthropic_sdk()) else "ground"

    try:
        if mode == "live":
            text, backend = _reply_live(user_message, history, context)
            took_ms = int((time.perf_counter() - t0) * 1000)
            return ChatReply(text=text, backend=backend, mode="live", posture=posture, took_ms=took_ms)
        text, backend = _reply_ground(user_message, context)
    except Exception as exc:  # noqa: BLE001
        log.exception("igris_chat failure")
        # Fall back to ground mode on any live failure — better to serve a
        # useful rule-based answer than to 500 in the user's face.
        text, backend = _reply_ground(user_message, context)
        took_ms = int((time.perf_counter() - t0) * 1000)
        return ChatReply(
            text=text,
            backend=backend,
            mode="ground",
            posture=posture,
            took_ms=took_ms,
            warning=f"live backend failed: {type(exc).__name__}",
        )

    took_ms = int((time.perf_counter() - t0) * 1000)
    return ChatReply(text=text, backend=backend, mode="ground", posture=posture, took_ms=took_ms)


__all__ = ["chat", "ChatReply", "build_context"]
