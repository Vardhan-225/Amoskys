"""
AMOSKYS Peripheral Telemetry API
Canonical peripheral telemetry endpoints backed by DashboardQueryService.
"""

from __future__ import annotations

import logging
from datetime import datetime

from flask import Blueprint, jsonify, request

from ..dashboard.query_service import get_dashboard_query_service
from .rate_limiter import require_rate_limit

logger = logging.getLogger(__name__)

peripheral_bp = Blueprint(
    "peripheral_telemetry", __name__, url_prefix="/peripheral-telemetry"
)


def safe_int(value, default=0, min_val=None, max_val=None):
    """Safely parse integer from request parameter."""
    try:
        result = int(value)
        if min_val is not None and result < min_val:
            return default
        if max_val is not None and result > max_val:
            return max_val
        return result
    except (ValueError, TypeError):
        return default


@peripheral_bp.route("/recent", methods=["GET"])
@require_rate_limit(max_requests=100, window_seconds=60)
def get_recent_events():
    """Get recent peripheral events."""
    limit = safe_int(
        request.args.get("limit", 100), default=100, min_val=1, max_val=500
    )
    service = get_dashboard_query_service()
    if not service.available:
        return jsonify({"events": [], "message": "No data available yet"}), 200

    try:
        events = service.recent_peripheral_events(limit=limit)
        return jsonify(
            {
                "events": events,
                "count": len(events),
                "timestamp": datetime.now().isoformat(),
            }
        )
    except Exception as exc:
        logger.exception("Failed to fetch recent peripheral events")
        return jsonify({"error": str(exc)}), 500


@peripheral_bp.route("/connected", methods=["GET"])
@require_rate_limit(max_requests=100, window_seconds=60)
def get_connected_devices():
    """Get currently connected peripheral devices."""
    service = get_dashboard_query_service()
    if not service.available:
        return jsonify({"devices": [], "message": "No data available"}), 200

    try:
        devices = service.connected_peripherals()
        return jsonify(
            {
                "devices": devices,
                "count": len(devices),
                "timestamp": datetime.now().isoformat(),
            }
        )
    except Exception as exc:
        logger.exception("Failed to fetch connected peripheral devices")
        return jsonify({"error": str(exc)}), 500


@peripheral_bp.route("/stats", methods=["GET"])
@require_rate_limit(max_requests=100, window_seconds=60)
def get_peripheral_stats():
    """Get aggregated peripheral statistics."""
    service = get_dashboard_query_service()
    if not service.available:
        return jsonify({"error": "Database not available"}), 500

    try:
        payload = service.peripheral_stats()
        payload["timestamp"] = datetime.now().isoformat()
        return jsonify(payload)
    except Exception as exc:
        logger.exception("Failed to aggregate peripheral statistics")
        return jsonify({"error": str(exc)}), 500


@peripheral_bp.route("/timeline", methods=["GET"])
@require_rate_limit(max_requests=100, window_seconds=60)
def get_connection_timeline():
    """Get timeline of device connections/disconnections."""
    hours = safe_int(request.args.get("hours", 24), default=24, min_val=1, max_val=168)
    service = get_dashboard_query_service()
    if not service.available:
        return jsonify({"events": [], "message": "No data available"}), 200

    try:
        events = service.peripheral_timeline(hours=hours)
        return jsonify(
            {
                "events": events,
                "count": len(events),
                "time_window_hours": hours,
                "timestamp": datetime.now().isoformat(),
            }
        )
    except Exception as exc:
        logger.exception("Failed to fetch peripheral connection timeline")
        return jsonify({"error": str(exc)}), 500


@peripheral_bp.route("/high-risk", methods=["GET"])
@require_rate_limit(max_requests=100, window_seconds=60)
def get_high_risk_devices():
    """Get high-risk peripheral devices (risk_score > 0.5)."""
    limit = safe_int(request.args.get("limit", 50), default=50, min_val=1, max_val=200)
    service = get_dashboard_query_service()
    if not service.available:
        return jsonify({"devices": [], "message": "No data available"}), 200

    try:
        devices = service.high_risk_peripherals(limit=limit)
        return jsonify(
            {
                "devices": devices,
                "count": len(devices),
                "timestamp": datetime.now().isoformat(),
            }
        )
    except Exception as exc:
        logger.exception("Failed to fetch high-risk peripheral devices")
        return jsonify({"error": str(exc)}), 500


@peripheral_bp.route("/unauthorized", methods=["GET"])
@require_rate_limit(max_requests=100, window_seconds=60)
def get_unauthorized_devices():
    """Get unauthorized peripheral devices."""
    limit = safe_int(request.args.get("limit", 50), default=50, min_val=1, max_val=200)
    service = get_dashboard_query_service()
    if not service.available:
        return jsonify({"devices": [], "message": "No data available"}), 200

    try:
        devices = service.unauthorized_peripherals(limit=limit)
        return jsonify(
            {
                "devices": devices,
                "count": len(devices),
                "timestamp": datetime.now().isoformat(),
            }
        )
    except Exception as exc:
        logger.exception("Failed to fetch unauthorized peripheral devices")
        return jsonify({"error": str(exc)}), 500


@peripheral_bp.route("/device/<device_id>", methods=["GET"])
@require_rate_limit(max_requests=100, window_seconds=60)
def get_device_history(device_id):
    """Get event history for a specific device."""
    service = get_dashboard_query_service()
    if not service.available:
        return jsonify({"events": [], "message": "No data available"}), 200

    try:
        events = service.peripheral_device_history(device_id=device_id)
        return jsonify(
            {
                "device_id": device_id,
                "events": events,
                "event_count": len(events),
                "timestamp": datetime.now().isoformat(),
            }
        )
    except Exception as exc:
        logger.exception("Failed to fetch peripheral device history for %s", device_id)
        return jsonify({"error": str(exc)}), 500


@peripheral_bp.route("/search", methods=["GET"])
@require_rate_limit(max_requests=100, window_seconds=60)
def search_devices():
    """Search peripheral devices by name, type, or manufacturer."""
    device_name = request.args.get("name", "")
    device_type = request.args.get("type", "")
    manufacturer = request.args.get("manufacturer", "")
    limit = safe_int(
        request.args.get("limit", 100), default=100, min_val=1, max_val=500
    )

    service = get_dashboard_query_service()
    if not service.available:
        return jsonify({"events": [], "message": "No data available"}), 200

    try:
        events = service.search_peripherals(
            name=device_name,
            device_type=device_type,
            manufacturer=manufacturer,
            limit=limit,
        )
        return jsonify(
            {
                "events": events,
                "count": len(events),
                "filters_applied": {
                    "name": device_name or None,
                    "type": device_type or None,
                    "manufacturer": manufacturer or None,
                },
                "timestamp": datetime.now().isoformat(),
            }
        )
    except Exception as exc:
        logger.exception("Failed to search peripheral devices")
        return jsonify({"error": str(exc)}), 500
