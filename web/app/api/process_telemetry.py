"""
AMOSKYS Process Telemetry API
Canonical process telemetry endpoints backed by DashboardQueryService.
"""

from __future__ import annotations

import logging
from datetime import datetime

from flask import Blueprint, jsonify, request

from ..dashboard.query_service import get_dashboard_query_service
from .rate_limiter import require_rate_limit

logger = logging.getLogger(__name__)

process_bp = Blueprint("process_telemetry", __name__, url_prefix="/process-telemetry")


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


@process_bp.route("/recent", methods=["GET"])
@require_rate_limit(max_requests=100, window_seconds=60)
def get_recent_processes():
    """Get recent process events from canonical store."""
    limit = safe_int(
        request.args.get("limit", 100), default=100, min_val=1, max_val=500
    )
    service = get_dashboard_query_service()
    if not service.available:
        return jsonify({"processes": [], "message": "No data available yet"}), 200

    try:
        processes = service.recent_processes(limit=limit)
        return jsonify(
            {
                "processes": processes,
                "count": len(processes),
                "timestamp": datetime.now().isoformat(),
            }
        )
    except Exception as exc:
        logger.exception("Failed to fetch recent processes")
        return jsonify({"error": str(exc)}), 500


@process_bp.route("/stats", methods=["GET"])
@require_rate_limit(max_requests=100, window_seconds=60)
def get_process_stats():
    """Get aggregated process statistics."""
    service = get_dashboard_query_service()
    if not service.available:
        return jsonify({"error": "Database not available"}), 500

    try:
        payload = service.process_stats()
        payload["timestamp"] = datetime.now().isoformat()
        return jsonify(payload)
    except Exception as exc:
        logger.exception("Failed to aggregate process statistics")
        return jsonify({"error": str(exc)}), 500


@process_bp.route("/top-executables", methods=["GET"])
@require_rate_limit(max_requests=100, window_seconds=60)
def get_top_executables():
    """Get most frequently seen executables."""
    limit = safe_int(request.args.get("limit", 20), default=20, min_val=1, max_val=100)
    service = get_dashboard_query_service()
    if not service.available:
        return jsonify({"executables": [], "message": "No data available"}), 200

    try:
        result = service.process_top_executables(limit=limit)
        executables = result.get("executables", [])
        return jsonify(
            {
                "executables": executables,
                "count": len(executables),
                "total_events": result.get("total_events", 0),
                "timestamp": datetime.now().isoformat(),
            }
        )
    except Exception as exc:
        logger.exception("Failed to fetch top executables")
        return jsonify({"error": str(exc)}), 500


@process_bp.route("/search", methods=["GET"])
@require_rate_limit(max_requests=100, window_seconds=60)
def search_processes():
    """Search processes by executable, user type, or process category."""
    exe_filter = request.args.get("exe", "")
    user_type = request.args.get("user_type", "")
    category = request.args.get("category", "")
    limit = safe_int(
        request.args.get("limit", 100), default=100, min_val=1, max_val=500
    )

    service = get_dashboard_query_service()
    if not service.available:
        return jsonify({"processes": [], "message": "No data available"}), 200

    try:
        processes = service.process_search(
            exe_filter=exe_filter,
            user_type=user_type,
            category=category,
            limit=limit,
        )
        return jsonify(
            {
                "processes": processes,
                "count": len(processes),
                "filters_applied": {
                    "exe": exe_filter or None,
                    "user_type": user_type or None,
                    "category": category or None,
                },
                "timestamp": datetime.now().isoformat(),
            }
        )
    except Exception as exc:
        logger.exception("Failed to search processes")
        return jsonify({"error": str(exc)}), 500


@process_bp.route("/device-telemetry", methods=["GET"])
@require_rate_limit(max_requests=100, window_seconds=60)
def get_device_telemetry():
    """Get device-level aggregated telemetry snapshots."""
    limit = safe_int(
        request.args.get("limit", 100), default=100, min_val=1, max_val=500
    )
    service = get_dashboard_query_service()
    if not service.available:
        return jsonify({"telemetry": [], "message": "No data available"}), 200

    try:
        telemetry = service.device_telemetry_snapshots(limit=limit)
        return jsonify(
            {
                "telemetry": telemetry,
                "count": len(telemetry),
                "timestamp": datetime.now().isoformat(),
            }
        )
    except Exception as exc:
        logger.exception("Failed to fetch device telemetry")
        return jsonify({"error": str(exc)}), 500


@process_bp.route("/database-stats", methods=["GET"])
@require_rate_limit(max_requests=100, window_seconds=60)
def get_database_stats():
    """Get overall database statistics."""
    service = get_dashboard_query_service()
    if not service.available:
        return jsonify({"error": "Database not available"}), 500

    try:
        stats = service.database_stats()
        return jsonify({"statistics": stats, "timestamp": datetime.now().isoformat()})
    except Exception as exc:
        logger.exception("Failed to fetch database statistics")
        return jsonify({"error": str(exc)}), 500


@process_bp.route("/canonical-summary", methods=["GET"])
@require_rate_limit(max_requests=100, window_seconds=60)
def get_canonical_summary():
    """Get summary of canonical process table (ML pipeline stage 1)."""
    service = get_dashboard_query_service()
    if not service.available:
        return jsonify(
            {
                "total_rows": 0,
                "status": "no_data",
                "message": "Database not available",
            }
        )

    try:
        summary = service.canonical_summary()
        summary.setdefault("time_range", {"start": None, "end": None})
        summary["timestamp"] = datetime.now().isoformat()
        return jsonify(summary)
    except Exception as exc:
        logger.exception("Canonical summary query failed")
        return jsonify({"total_rows": 0, "status": "error", "error": str(exc)}), 500


@process_bp.route("/features-summary", methods=["GET"])
@require_rate_limit(max_requests=100, window_seconds=60)
def get_features_summary():
    """Get summary of ML features table (ML pipeline stage 2)."""
    service = get_dashboard_query_service()
    if not service.available:
        return jsonify(
            {
                "total_windows": 0,
                "total_features": 0,
                "status": "no_data",
                "message": "Database not available",
            }
        )

    try:
        summary = service.features_summary()
        summary["timestamp"] = datetime.now().isoformat()
        return jsonify(summary)
    except Exception as exc:
        logger.exception("ML features summary query failed")
        return (
            jsonify(
                {
                    "total_windows": 0,
                    "total_features": 0,
                    "status": "error",
                    "error": str(exc),
                }
            ),
            500,
        )
