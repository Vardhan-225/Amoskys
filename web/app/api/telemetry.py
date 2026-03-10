"""
AMOSKYS API Telemetry Module
Canonical telemetry read API backed by TelemetryStore query service.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

from ..dashboard.query_service import get_dashboard_query_service

logger = logging.getLogger(__name__)

telemetry_bp = Blueprint("telemetry", __name__, url_prefix="/telemetry")
_MSG_STORE_UNAVAILABLE = "Telemetry store not available yet"


def _safe_int(value: str, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    if parsed < minimum:
        return default
    return min(parsed, maximum)


@telemetry_bp.route("/recent", methods=["GET"])
def get_recent_telemetry():
    """Get recent telemetry events from canonical store."""
    service = get_dashboard_query_service()
    if not service.available:
        return jsonify(
            {
                "status": "no_data",
                "events": [],
                "message": _MSG_STORE_UNAVAILABLE,
            }
        )

    limit = _safe_int(request.args.get("limit", "50"), 50, 1, 500)
    hours = _safe_int(request.args.get("hours", "24"), 24, 1, 24 * 14)

    try:
        events = service.recent_telemetry(limit=limit, hours=hours)
        return jsonify({"status": "success", "count": len(events), "events": events})
    except Exception as exc:
        logger.exception("Failed to fetch recent telemetry")
        return jsonify({"status": "error", "error": str(exc)}), 500


@telemetry_bp.route("/agents", methods=["GET"])
def get_agent_summary():
    """Get per-agent summary from canonical telemetry tables."""
    service = get_dashboard_query_service()
    if not service.available:
        return jsonify(
            {
                "status": "no_data",
                "agents": [],
                "total_events": 0,
                "agent_count": 0,
                "message": _MSG_STORE_UNAVAILABLE,
            }
        )

    limit = _safe_int(request.args.get("limit", "100"), 100, 1, 1000)
    try:
        payload = service.agent_summary(limit=limit)
        payload["status"] = "success"
        return jsonify(payload)
    except Exception as exc:
        logger.exception("Failed to fetch agent telemetry summary")
        return jsonify({"status": "error", "error": str(exc)}), 500


@telemetry_bp.route("/metrics/<device_id>", methods=["GET"])
def get_device_metrics(device_id: str):
    """Get recent metrics timeseries for a specific device."""
    service = get_dashboard_query_service()
    if not service.available:
        return jsonify(
            {
                "status": "no_data",
                "device_id": device_id,
                "metrics": [],
                "message": _MSG_STORE_UNAVAILABLE,
            }
        )

    limit = _safe_int(request.args.get("limit", "50"), 50, 1, 500)
    try:
        metrics = service.device_metrics(device_id=device_id, limit=limit)
        return jsonify(
            {
                "status": "success",
                "device_id": device_id,
                "count": len(metrics),
                "metrics": metrics,
            }
        )
    except Exception as exc:
        logger.exception("Failed to fetch device metrics")
        return jsonify({"status": "error", "error": str(exc)}), 500


@telemetry_bp.route("/stats", methods=["GET"])
def get_telemetry_stats():
    """Get telemetry statistics from canonical store."""
    service = get_dashboard_query_service()
    if not service.available:
        return jsonify(
            {
                "status": "no_data",
                "stats": {
                    "total_events": 0,
                    "earliest_event": None,
                    "latest_event": None,
                    "time_span_seconds": 0,
                },
                "message": _MSG_STORE_UNAVAILABLE,
            }
        )

    try:
        stats = service.telemetry_stats()
        return jsonify(
            {
                "status": "success",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "stats": stats,
            }
        )
    except Exception as exc:
        logger.exception("Failed to fetch telemetry statistics")
        return jsonify({"status": "error", "error": str(exc)}), 500


@telemetry_bp.route("/consistency", methods=["GET"])
def get_consistency_check():
    """Cross-check canonical counts for dashboard/API truth consistency."""
    service = get_dashboard_query_service()
    if not service.available:
        return jsonify(
            {
                "status": "no_data",
                "message": _MSG_STORE_UNAVAILABLE,
                "consistent": True,
            }
        )

    hours = _safe_int(request.args.get("hours", "24"), 24, 1, 24 * 30)
    try:
        result = service.consistency_check(hours=hours)
        return jsonify({"status": "success", **result})
    except Exception as exc:
        logger.exception("Failed to run telemetry consistency check")
        return jsonify({"status": "error", "error": str(exc)}), 500


@telemetry_bp.route("/attributes/catalog", methods=["GET"])
def get_attribute_catalog():
    """Attribute showcase catalog built from canonical table schemas + distributions."""
    service = get_dashboard_query_service()
    if not service.available:
        return jsonify(
            {
                "status": "no_data",
                "catalog": {"tables": []},
                "message": _MSG_STORE_UNAVAILABLE,
            }
        )

    max_tables = _safe_int(request.args.get("max_tables", "20"), 20, 1, 50)
    max_top_values = _safe_int(request.args.get("max_values", "10"), 10, 1, 50)
    try:
        catalog = service.attribute_catalog(
            max_tables=max_tables, max_top_values=max_top_values
        )
        return jsonify({"status": "success", "catalog": catalog})
    except Exception as exc:
        logger.exception("Failed to build attribute catalog")
        return jsonify({"status": "error", "error": str(exc)}), 500
