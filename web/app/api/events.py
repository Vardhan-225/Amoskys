"""
AMOSKYS API Events Module
Security event ingestion and management — wired to TelemetryStore.
"""

import hashlib
import json
import time
from datetime import datetime, timezone

from flask import Blueprint, g, jsonify, request

from ..dashboard.query_service import get_dashboard_query_service
from .agent_auth import require_auth
from .rate_limiter import require_rate_limit

events_bp = Blueprint("events", __name__, url_prefix="/events")
_MSG_DB_UNAVAILABLE = "Database unavailable"

# Backward-compatible in-memory mirrors used by /api/system/status.
EVENT_STORE = []
EVENT_STATS = {
    "total_events": 0,
    "by_severity": {"low": 0, "medium": 0, "high": 0, "critical": 0},
}


def _get_store():
    """Get TelemetryStore instance (lazy import)."""
    try:
        from ..dashboard.telemetry_bridge import get_telemetry_store

        return get_telemetry_store()
    except Exception:
        return None


def validate_event_schema(event_data):
    """Validate incoming event data structure"""
    required_fields = ["event_type", "severity", "source_ip", "description"]

    for field in required_fields:
        if field not in event_data:
            return False, f"Missing required field: {field}"

    # Validate severity levels
    valid_severities = ["low", "medium", "high", "critical"]
    if event_data["severity"] not in valid_severities:
        return False, f"Invalid severity. Must be one of: {valid_severities}"

    return True, None


_SEVERITY_TO_RISK = {"low": 0.1, "medium": 0.35, "high": 0.6, "critical": 0.85}


@events_bp.route("/submit", methods=["POST"])
@require_auth(permissions=["event.submit"])
@require_rate_limit(max_requests=100, window_seconds=60)
def submit_event():
    """Submit a security event to AMOSKYS — persisted to TelemetryStore."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON payload"}), 400

    # Validate event schema
    is_valid, error_msg = validate_event_schema(data)
    if not is_valid:
        return jsonify({"error": error_msg}), 400

    agent_id = g.current_user["agent_id"]
    now_ns = int(time.time() * 1e9)
    now_dt = datetime.now(timezone.utc).isoformat()
    event_id = hashlib.sha256(
        f"{agent_id}-{now_dt}-{json.dumps(data, sort_keys=True)}".encode()
    ).hexdigest()[:16]

    store = _get_store()
    if store is None:
        return jsonify({"error": _MSG_DB_UNAVAILABLE}), 503

    risk_score = _SEVERITY_TO_RISK.get(data["severity"], 0.25)
    indicators = {
        "source_ip": data["source_ip"],
        "agent": agent_id,
    }
    if data.get("destination_ip"):
        indicators["dst_ip"] = data["destination_ip"]
    if data.get("metadata"):
        indicators.update(data["metadata"])

    store.insert_security_event(
        {
            "timestamp_ns": now_ns,
            "timestamp_dt": now_dt,
            "device_id": agent_id,
            "event_category": data["event_type"],
            "event_action": "external_submit",
            "risk_score": risk_score,
            "confidence": 0.5,
            "description": data["description"],
            "indicators": json.dumps(indicators),
            "collection_agent": agent_id,
            "event_id": event_id,
        }
    )

    EVENT_STORE.append(
        {
            "event_id": event_id,
            "timestamp": now_dt,
            "event_type": data["event_type"],
            "severity": data["severity"],
            "agent_id": agent_id,
        }
    )
    EVENT_STATS["total_events"] += 1
    EVENT_STATS["by_severity"][data["severity"]] = (
        EVENT_STATS["by_severity"].get(data["severity"], 0) + 1
    )

    return jsonify(
        {
            "status": "success",
            "message": "Event submitted successfully",
            "event_id": event_id,
            "timestamp": now_dt,
        }
    )


@events_bp.route("/list", methods=["GET"])
@require_auth()
def list_events():
    """List recent security events from TelemetryStore."""
    limit = min(int(request.args.get("limit", 100)), 1000)
    severity = request.args.get("severity")

    store = _get_store()
    if store is None:
        return jsonify({"status": "success", "event_count": 0, "events": []})

    rows = store.get_recent_security_events(limit=limit, hours=8760, severity=severity)

    return jsonify(
        {
            "status": "success",
            "event_count": len(rows),
            "events": rows,
        }
    )


@events_bp.route("/<event_id>", methods=["GET"])
@require_auth()
def get_event(event_id):
    """Get details of a specific event by event_id."""
    service = get_dashboard_query_service()
    if not service.available:
        return jsonify({"error": _MSG_DB_UNAVAILABLE}), 503

    try:
        event = service.security_event_by_id(event_id)
        if not event:
            return jsonify({"error": "Event not found"}), 404
        return jsonify({"status": "success", "event": event})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@events_bp.route("/<event_id>/status", methods=["PUT"])
@require_auth(permissions=["event.update"])
def update_event_status(event_id):
    """Update event status (new, investigating, resolved, false_positive)"""
    data = request.get_json()
    if not data or "status" not in data:
        return jsonify({"error": "Status field required"}), 400

    valid_statuses = ["new", "investigating", "resolved", "false_positive"]
    if data["status"] not in valid_statuses:
        return (
            jsonify({"error": f"Invalid status. Must be one of: {valid_statuses}"}),
            400,
        )

    service = get_dashboard_query_service()
    if not service.available:
        return jsonify({"error": _MSG_DB_UNAVAILABLE}), 503

    try:
        if not service.security_event_by_id(event_id):
            return jsonify({"error": "Event not found"}), 404

        updated = service.update_security_event_status(event_id, data["status"])
        if not updated:
            return jsonify({"error": "Event not found"}), 404

        return jsonify(
            {
                "status": "success",
                "message": f'Event {event_id} status updated to {data["status"]}',
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@events_bp.route("/stats", methods=["GET"])
@require_auth()
def event_statistics():
    """Get event statistics from TelemetryStore."""
    store = _get_store()
    if store is None:
        return jsonify({"status": "success", "stats": {"total_events": 0}})

    counts = store.get_unified_event_counts(hours=24)

    return jsonify(
        {
            "status": "success",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "stats": {
                "total_events": counts.get("total", 0),
                "by_source": counts.get("by_source", {}),
                "by_category": counts.get("by_category", {}),
            },
        }
    )


@events_bp.route("/schema", methods=["GET"])
def event_schema():
    """Get the event submission schema"""
    schema = {
        "required_fields": ["event_type", "severity", "source_ip", "description"],
        "optional_fields": [
            "destination_ip",
            "source_port",
            "destination_port",
            "protocol",
            "metadata",
        ],
        "field_descriptions": {
            "event_type": "Type of security event (e.g., network_anomaly, malware_detection, intrusion_attempt)",
            "severity": "Event severity level: low, medium, high, critical",
            "source_ip": "Source IP address of the event",
            "destination_ip": "Destination IP address (if applicable)",
            "source_port": "Source port number (if applicable)",
            "destination_port": "Destination port number (if applicable)",
            "protocol": "Network protocol (TCP, UDP, ICMP, etc.)",
            "description": "Human-readable description of the event",
            "metadata": "Additional event-specific data as key-value pairs",
        },
        "severity_levels": ["low", "medium", "high", "critical"],
        "example_event": {
            "event_type": "network_anomaly",
            "severity": "medium",
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "source_port": 443,
            "destination_port": 22,
            "protocol": "TCP",
            "description": "Unusual SSH connection attempt from HTTPS port",
            "metadata": {
                "bytes_transferred": 1024,
                "connection_duration": 30,
                "user_agent": "curl/7.68.0",
            },
        },
    }

    return jsonify({"status": "success", "schema": schema})
