"""
AMOSKYS Command — the honest, world-class dashboard front door.

Serves the redesigned single-pane-of-glass view and its data API. The API
returns the model computed by insight_service.get_model(), which reads the real
fleet_cache telemetry, suppresses expected activity, correlates incidents and
produces ONE truthful verdict (never a permanent CRITICAL/100).
"""
from __future__ import annotations

from flask import jsonify, render_template, request

from ..middleware import get_current_user, require_login
from . import dashboard_bp

try:
    from . import insight_service
except Exception:  # pragma: no cover - defensive import
    insight_service = None


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
    return jsonify(insight_service.get_model(force=force)), 200


@dashboard_bp.route("/device-view")
@require_login
def device_view():
    """Device drill-down — the cross-domain 'story' view (the moat)."""
    user = get_current_user()
    return render_template("dashboard/device.html", user=user)


@dashboard_bp.route("/api/device")
@require_login
def api_device():
    """Cross-domain device model. Degrades gracefully, never 500s."""
    if insight_service is None:
        return jsonify({"error": "unavailable", "message": "insight service not loaded"}), 200
    device_id = request.args.get("id") or None
    force = request.args.get("force") == "1"
    return jsonify(insight_service.get_device_model(device_id=device_id, force=force)), 200
