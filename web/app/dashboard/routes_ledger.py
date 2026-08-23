"""The Ledger routes — one queue, and the button that makes AMOSKYS learn.

``POST /dashboard/api/ledger/verdict`` is the control this product was missing.
The reliability machinery behind it already existed in full — a Beta-Bernoulli
tracker per probe with drift detection and quarantine tiers, fed by a ground
truth oracle in which manual analyst feedback outranks cross-agent consensus —
and nothing in the UI could reach it.

The endpoint does two things and reports on both separately, because they can
succeed independently:

  1. **Local** — records the verdict in ``verdict_store`` on this tier. This is
     what changes the ledger the next time the user looks, and it works even on
     a presentation server whose telemetry store is a read-only snapshot.
  2. **Upstream** — forwards to the reliability tracker and writes an event
     label for training. On a read-only tier this legitimately cannot land, so
     the response says ``upstream: "unavailable"`` rather than claiming the
     system learned something it did not.
"""

from __future__ import annotations

import logging

from flask import jsonify, render_template, request

from ..middleware import get_current_user, require_login
from . import actions, coverage, dashboard_bp, kernel, ledger
from . import verdict as verdict_mod
from . import verdict_store
from .org_scope import get_allowed_device_ids

logger = logging.getLogger(__name__)

# Event category prefix -> the probe/agent whose reliability the verdict moves.
# Anything unmapped still writes labels; it just cannot re-weight a named probe.
_CATEGORY_AGENT = {
    "dns": "dns_agent",
    "flow": "flow_agent",
    "network": "flow_agent",
    "c2": "flow_agent",
    "cloud": "flow_agent",
    "exfil": "flow_agent",
    "macos_process": "proc_agent",
    "process": "proc_agent",
    "lolbin": "proc_agent",
    "execute": "proc_agent",
    "full_kill_chain": "proc_agent",
    "macos_launchagent": "persistence_agent",
    "macos_cron": "persistence_agent",
    "persistence": "persistence_agent",
    "macos_shell_profile": "persistence_agent",
    "auth": "auth_agent",
    "browser_credential": "auth_agent",
    "credential": "auth_agent",
    "fim": "fim_agent",
    "file": "fim_agent",
    "peripheral": "peripheral_agent",
}


def _scope() -> tuple[list[str] | None, str]:
    """(allowed_device_ids, scope_key). None = admin/unrestricted; fail closed."""
    user = get_current_user()
    allowed, admin = get_allowed_device_ids(user)
    if admin:
        return None, "admin"
    org_id = getattr(user, "org_id", None) if user else None
    return allowed, (org_id or "__none__")


def _agents_for(categories: list[str]) -> list[str]:
    agents = []
    for cat in categories or []:
        for prefix, agent in _CATEGORY_AGENT.items():
            if cat.startswith(prefix) or prefix in cat:
                if agent not in agents:
                    agents.append(agent)
                break
    return agents


def _forward_upstream(item: dict, verdict: str) -> tuple[str, str]:
    """Best-effort push into the AMRDR loop. Returns (status, detail).

    status is one of: applied · unavailable · error · nothing_to_label
    """
    from ..api import reliability as rel

    # A kernel-witnessed binary carries its judgement to a different store:
    # esf_binary_ledger.verdict, whose NULL was built to mean "nobody has looked
    # at this yet" rather than "cleared". This press is what closes that gap.
    cdhash = item.get("cdhash")
    if cdhash:
        binary_verdict = "benign" if verdict == verdict_store.MINE else "suspicious"
        written = kernel.record_binary_verdict(
            cdhash, binary_verdict, note=f"marked via ledger by {verdict}"
        )
        if written.get("written"):
            return (
                "applied",
                f"recorded on the binary ledger as {binary_verdict} — this "
                "cdhash is now reviewed, wherever it runs from next",
            )
        return "unavailable", written.get(
            "detail", "The binary ledger did not accept it."
        )

    # Label writeback matches security_events.id, not the event_id hash — a
    # mismatch here is silent (0 rows updated) and would make the button lie.
    row_ids = item.get("row_ids") or []
    agents = _agents_for(item.get("categories") or [])
    if not row_ids and not agents:
        return (
            "nothing_to_label",
            "This item is derived from flow aggregates, not individual events.",
        )

    ground_truth_match = verdict == verdict_store.NOT_MINE
    classification = "malicious" if ground_truth_match else "legitimate"

    try:
        tracker = rel._get_tracker()
        tracker_active = tracker.__class__.__name__ != "NoOpReliabilityTracker"
        for agent_id in agents:
            tracker.update(agent_id, ground_truth_match=ground_truth_match)

        labelled = 0
        for row_id in row_ids:
            if rel._write_event_label(row_id, classification):
                labelled += 1
    except Exception as exc:
        logger.warning("upstream feedback forward failed", exc_info=True)
        return "error", str(exc)[:200]

    if tracker_active or labelled:
        bits = []
        if agents:
            bits.append(f"re-weighted {', '.join(agents)}")
        if labelled:
            bits.append(f"labelled {labelled} event{'s' if labelled != 1 else ''}")
        return "applied", "; ".join(bits) or "recorded"

    return (
        "unavailable",
        "The reliability loop is not active on this tier — your decision is kept here "
        "and applied to what you see, but no probe weight changed.",
    )


# ── Page ─────────────────────────────────────────────────────────────────────
@dashboard_bp.route("/ledger")
@require_login
def ledger_page():
    """The single queue: what needs you, and what AMOSKYS already recognised."""
    return render_template("dashboard/ledger.html", user=get_current_user())


# ── Data ─────────────────────────────────────────────────────────────────────
@dashboard_bp.route("/api/ledger")
@require_login
def api_ledger():
    allowed, scope_key = _scope()
    payload = ledger.build(
        allowed_device_ids=allowed,
        cache_key=scope_key,
        org_scope=scope_key,
        force=request.args.get("force") == "1",
    )
    # row_ids are an internal join key for label writeback. The browser never
    # needs them, and the feedback endpoint deliberately re-derives the item
    # server-side rather than trusting ids posted back by a client.
    for bucket in (payload["needs_you"], payload["recognised"]["items"]):
        for item in bucket:
            item.pop("row_ids", None)
    return jsonify(payload), 200


@dashboard_bp.route("/api/verdict")
@require_login
def api_verdict():
    """The canonical verdict. Every surface reads this instead of computing one."""
    allowed, scope_key = _scope()
    device_id = request.args.get("device_id") or None
    if device_id:
        return (
            jsonify(
                verdict_mod.device_verdict(
                    device_id, allowed_device_ids=allowed, cache_key=scope_key
                )
            ),
            200,
        )
    if request.args.get("include") == "devices":
        payload = verdict_mod.fleet_and_devices(
            allowed_device_ids=allowed, cache_key=scope_key
        )
        # The sentence counts the ledger's grouped items, so the front page and
        # the ledger cannot disagree about how much is waiting on you.
        book = ledger.build(
            allowed_device_ids=allowed, cache_key=scope_key, org_scope=scope_key
        )
        payload["narrative"] = verdict_mod.narrative(
            payload["fleet"],
            device_names=verdict_mod.device_names(allowed),
            item_count=len(book["needs_you"]),
        )
        payload["needs_you_count"] = len(book["needs_you"])
        payload["recognised_count"] = book["recognised"]["count"]
        return jsonify(payload), 200
    return (
        jsonify(
            verdict_mod.fleet_verdict(allowed_device_ids=allowed, cache_key=scope_key)
        ),
        200,
    )


@dashboard_bp.route("/api/ledger/evidence")
@require_login
def api_ledger_evidence():
    """The rows behind one ledger item — the "Show me" drawer."""
    allowed, scope_key = _scope()
    key = request.args.get("key") or ""
    item = ledger.find_item(
        key, allowed_device_ids=allowed, cache_key=scope_key, org_scope=scope_key
    )
    if item is None:
        return jsonify({"error": "unknown item", "key": key, "rows": []}), 404
    rows = ledger.evidence_for(item.get("event_ids") or [], allowed_device_ids=allowed)
    return (
        jsonify(
            {
                "key": key,
                "title": item["title"],
                "evidence_count": item.get("evidence_count", 0),
                "returned": len(rows),
                "rows": rows,
                "note": (
                    None
                    if rows
                    else "This story is built from flow aggregates rather than individual "
                    "security events, so there are no rows to open."
                ),
            }
        ),
        200,
    )


@dashboard_bp.route("/api/ledger/verdict", methods=["POST"])
@require_login
def api_ledger_verdict():
    """That's me / Not me — and an honest account of where it landed."""
    data = request.get_json(silent=True) or {}
    key = (data.get("key") or "").strip()
    decision = (data.get("verdict") or "").strip()

    if not key:
        return jsonify({"error": "key required"}), 400
    if decision not in (verdict_store.MINE, verdict_store.NOT_MINE, "clear"):
        return jsonify({"error": "verdict must be 'mine', 'not_mine' or 'clear'"}), 400

    allowed, scope_key = _scope()
    user = get_current_user()
    who = getattr(user, "email", None) or getattr(user, "username", None) or "unknown"

    if decision == "clear":
        removed = verdict_store.clear(key, scope_key)
        return (
            jsonify(
                {
                    "status": "ok",
                    "key": key,
                    "verdict": None,
                    "removed": removed,
                    "message": (
                        "Decision cleared — this is back in the queue."
                        if removed
                        else "There was no decision to clear."
                    ),
                }
            ),
            200,
        )

    item = ledger.find_item(
        key, allowed_device_ids=allowed, cache_key=scope_key, org_scope=scope_key
    )
    if item is None:
        return jsonify({"error": "unknown item", "key": key}), 404

    upstream_status, upstream_detail = _forward_upstream(item, decision)
    stored = verdict_store.record(
        key,
        scope_key,
        decision,
        title=item["title"],
        device_ids=item.get("device_ids"),
        event_ids=item.get("event_ids"),
        categories=item.get("categories"),
        decided_by=who,
        upstream_status=upstream_status,
        upstream_detail=upstream_detail,
    )

    if decision == verdict_store.MINE:
        headline = "Noted — AMOSKYS will treat this as yours."
    else:
        headline = "Noted — AMOSKYS will keep surfacing this."

    return (
        jsonify(
            {
                "status": "ok",
                "key": key,
                "verdict": decision,
                "stored": True,
                "upstream": upstream_status,
                "upstream_detail": upstream_detail,
                "message": headline,
                "learned": upstream_status == "applied",
            }
        ),
        200,
    )


@dashboard_bp.route("/api/ledger/taught")
@require_login
def api_ledger_taught():
    """What you've taught it — the record of your own decisions."""
    _, scope_key = _scope()
    return (
        jsonify(
            {
                "summary": verdict_store.summary(scope_key),
                "recent": verdict_store.recent(scope_key, limit=50),
            }
        ),
        200,
    )


# ── Response actions ─────────────────────────────────────────────────────────
# Dispatch is admin-only, gated by AMOSKYS_RESPONSE_ENABLED on this tier and by
# CC_OPERATOR_KEY on the fleet backend. Both default to off. The analyst loop
# cannot reach any of it: IGRIS proposes, a person presses.
def _require_admin():
    user = get_current_user()
    _, is_admin = get_allowed_device_ids(user)
    return is_admin, user


@dashboard_bp.route("/api/ledger/actions")
@require_login
def api_ledger_actions():
    """What could be done about one ledger item, and whether it can be done here."""
    allowed, scope_key = _scope()
    key = request.args.get("key") or ""
    item = ledger.find_item(
        key, allowed_device_ids=allowed, cache_key=scope_key, org_scope=scope_key
    )
    if item is None:
        return jsonify({"error": "unknown item", "key": key}), 404

    is_admin, _ = _require_admin()
    state = actions.availability()
    rows = ledger.evidence_for(item.get("event_ids") or [], allowed_device_ids=allowed)
    proposed = actions.propose(item, rows) if (state["available"] and is_admin) else []

    if not is_admin and state["available"]:
        state = {
            "available": False,
            "reason": "Response actions are limited to administrators.",
        }
    return (
        jsonify(
            {
                "key": key,
                "availability": state,
                "actions": proposed,
                "targets": actions.derive_targets(rows),
            }
        ),
        200,
    )


@dashboard_bp.route("/api/ledger/act", methods=["POST"])
@require_login
def api_ledger_act():
    """Queue a response action. Requires an admin, a target seen in the evidence,
    and a reason — all three are stored on the command."""
    is_admin, user = _require_admin()
    if not is_admin:
        return (
            jsonify(
                {
                    "error": "forbidden",
                    "detail": "Response actions are limited to administrators.",
                }
            ),
            403,
        )

    data = request.get_json(silent=True) or {}
    key = (data.get("key") or "").strip()
    command_type = (data.get("command_type") or "").strip().upper()
    device_id = (data.get("device_id") or "").strip()
    target = data.get("target")
    reason = (data.get("reason") or "").strip()

    allowed, scope_key = _scope()
    item = ledger.find_item(
        key, allowed_device_ids=allowed, cache_key=scope_key, org_scope=scope_key
    )
    if item is None:
        return jsonify({"error": "unknown item", "key": key}), 404
    if allowed is not None and device_id not in allowed:
        return jsonify({"error": "unknown device"}), 404
    if device_id not in (item.get("device_ids") or []):
        return (
            jsonify(
                {
                    "error": "device_not_in_item",
                    "detail": "That device is not part of this item's evidence.",
                }
            ),
            400,
        )

    rows = ledger.evidence_for(item.get("event_ids") or [], allowed_device_ids=allowed)
    who = getattr(user, "email", None) or getattr(user, "username", None) or "unknown"
    payload, status = actions.dispatch(
        device_id=device_id,
        command_type=command_type,
        param_value=target,
        reason=reason,
        requested_by=f"console:{who}",
        allowed_targets=actions.derive_targets(rows),
    )
    if status in (200, 201):
        logger.info(
            "ACTION_DISPATCHED type=%s device=%s by=%s item=%s",
            command_type,
            device_id,
            who,
            key,
        )
    return jsonify(payload), status


@dashboard_bp.route("/api/actions")
@require_login
def api_actions_ledger():
    """Every action ever taken: who asked, why, and what the device reported."""
    is_admin, _ = _require_admin()
    if not is_admin:
        return jsonify({"commands": [], "unavailable": "Administrators only."}), 200
    payload, status = actions.ledger(
        limit=request.args.get("limit", 100, type=int),
        device_id=request.args.get("device_id") or None,
    )
    return jsonify(payload), status


@dashboard_bp.route("/api/actions/<command_id>/cancel", methods=["POST"])
@require_login
def api_actions_cancel(command_id):
    """Withdraw a queued action the device has not claimed yet."""
    is_admin, _ = _require_admin()
    if not is_admin:
        return jsonify({"error": "forbidden"}), 403
    payload, status = actions.cancel(command_id)
    return jsonify(payload), status


@dashboard_bp.route("/api/coverage")
@require_login
def api_coverage():
    """What AMOSKYS could not see — the honest counterpart to any all-clear.

    ``device_id`` narrows the report, so it must be checked against the org
    allowlist first: coverage.report() treats an explicit device_id as THE
    scope, which would otherwise let any authenticated user read another
    tenant's sensor coverage by guessing an id.
    """
    allowed, _ = _scope()
    device_id = request.args.get("device_id") or None
    if device_id and allowed is not None and device_id not in allowed:
        return jsonify({"error": "unknown device"}), 404
    return (
        jsonify(coverage.report(allowed_device_ids=allowed, device_id=device_id)),
        200,
    )


@dashboard_bp.route("/api/kernel")
@require_login
def api_kernel():
    """Is the kernel witnessing, and what has never run here before?

    The product's claim is that you cannot hide from it. This endpoint is where
    that claim is either backed by a live exec stream or honestly withdrawn.
    """
    return jsonify(kernel.summary_for_ledger()), 200
