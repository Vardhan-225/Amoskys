"""
AMOSKYS Command — the honest, world-class dashboard front door.

Serves the redesigned single-pane-of-glass view and its data API. The API
returns the model computed by insight_service.get_model(), which reads the real
fleet_cache telemetry, suppresses expected activity, correlates incidents and
produces ONE truthful verdict (never a permanent CRITICAL/100).

Tenant isolation: every data route resolves the caller's org → allowed
device_ids (org_scope.get_allowed_device_ids) and scopes the model to that
allowlist. Admins are unrestricted; an unresolvable org FAILS CLOSED.
"""
from __future__ import annotations

from flask import jsonify, render_template, request

from ..middleware import get_current_user, require_login
from . import dashboard_bp
from .org_scope import get_allowed_device_ids

try:
    from . import insight_service
except Exception:  # pragma: no cover - defensive import
    insight_service = None


def _scope() -> tuple[list[str] | None, str]:
    """(allowed_device_ids, cache_key) for the current user.

    allowed None = unrestricted (admin). The cache key is (org_id or 'admin');
    a non-admin without an org gets a distinct fail-closed key so they can
    never be served the admin-cached model."""
    user = get_current_user()
    allowed, admin = get_allowed_device_ids(user)
    if admin:
        return None, "admin"
    org_id = getattr(user, "org_id", None) if user else None
    return allowed, (org_id or "__none__")


@dashboard_bp.route("/command")
@require_login
def command_dashboard():
    """The redesigned Command dashboard (verdict + live globe + incident queue)."""
    user = get_current_user()
    return render_template("dashboard/command.html", user=user)


@dashboard_bp.route("/api/insight")
@require_login
def api_insight():
    """Honest model for the Command dashboard. Degrades gracefully, never 500s."""
    if insight_service is None:
        return jsonify({"error": "unavailable", "message": "insight service not loaded"}), 200
    force = request.args.get("force") == "1"
    allowed, cache_key = _scope()
    return jsonify(insight_service.get_model(
        force=force, allowed_device_ids=allowed, cache_key=cache_key)), 200


@dashboard_bp.route("/incidents-view")
@require_login
def incidents_view():
    """The full, filterable incident queue (primary triage view)."""
    user = get_current_user()
    return render_template("dashboard/incidents_v2.html", user=user)


@dashboard_bp.route("/device-view")
@require_login
def device_view():
    """Device drill-down — the cross-domain 'story' view (the moat)."""
    user = get_current_user()
    device_id = request.args.get("id") or None
    if device_id:
        allowed, _ = _scope()
        if allowed is not None and device_id not in allowed:
            return jsonify({"error": "unknown device"}), 404
    return render_template("dashboard/device.html", user=user)


@dashboard_bp.route("/api/device")
@require_login
def api_device():
    """Cross-domain device model. Degrades gracefully, never 500s."""
    if insight_service is None:
        return jsonify({"error": "unavailable", "message": "insight service not loaded"}), 200
    device_id = request.args.get("id") or None
    force = request.args.get("force") == "1"
    allowed, cache_key = _scope()
    if device_id and allowed is not None and device_id not in allowed:
        return jsonify({"error": "unknown device"}), 404
    return jsonify(insight_service.get_device_model(
        device_id=device_id, force=force,
        allowed_device_ids=allowed, cache_key=cache_key)), 200
