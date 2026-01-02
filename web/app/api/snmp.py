"""
AMOSKYS SNMP Telemetry API
Fetches and displays SNMP device metrics from EventBus
"""

import os
import sqlite3
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request

snmp_bp = Blueprint("snmp", __name__, url_prefix="/api/snmp")

# Path to EventBus WAL database
WAL_DB_PATH = os.path.join(os.path.dirname(__file__), "../../../data/wal/flowagent.db")


def get_db_connection():
    """Create connection to WAL database"""
    if not os.path.exists(WAL_DB_PATH):
        return None
    conn = sqlite3.connect(WAL_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@snmp_bp.route("/devices", methods=["GET"])
def list_devices():
    """List all devices that have sent SNMP telemetry"""
    conn = get_db_connection()
    if not conn:
        return jsonify({"devices": [], "message": "No data available"}), 200

    try:
        cursor = conn.cursor()

        # Query for unique source IPs from SNMP telemetry
        # FlowAgent wraps SNMP data with protocol="SNMP-TELEMETRY"
        cursor.execute(
            """
            SELECT DISTINCT src_ip as device_id,
                   MAX(ts_ns) as last_seen,
                   COUNT(*) as event_count
            FROM events
            WHERE protocol = 'SNMP-TELEMETRY'
            GROUP BY src_ip
            ORDER BY last_seen DESC
        """
        )

        devices = []
        for row in cursor.fetchall():
            devices.append(
                {
                    "device_id": row["device_id"],
                    "last_seen": datetime.fromtimestamp(
                        row["last_seen"] / 1e9
                    ).isoformat(),
                    "event_count": row["event_count"],
                    "status": (
                        "online"
                        if (datetime.now().timestamp() * 1e9 - row["last_seen"]) < 120e9
                        else "offline"
                    ),
                }
            )

        return jsonify(
            {
                "devices": devices,
                "count": len(devices),
                "timestamp": datetime.now().isoformat(),
            }
        )

    finally:
        conn.close()


@snmp_bp.route("/metrics/<device_id>", methods=["GET"])
def get_device_metrics(device_id):
    """Get latest SNMP metrics for a specific device"""
    conn = get_db_connection()
    if not conn:
        return jsonify({"metrics": [], "message": "No data available"}), 200

    # Get time range from query params
    hours = int(request.args.get("hours", 1))
    since_ns = int((datetime.now() - timedelta(hours=hours)).timestamp() * 1e9)

    try:
        cursor = conn.cursor()

        # Get recent events for this device
        cursor.execute(
            """
            SELECT ts_ns, src_ip, bytes_sent, start_time
            FROM events
            WHERE src_ip = ?
              AND protocol = 'SNMP-TELEMETRY'
              AND ts_ns > ?
            ORDER BY ts_ns DESC
            LIMIT 100
        """
        )

        metrics = []
        for row in cursor.fetchall():
            metrics.append(
                {
                    "timestamp": datetime.fromtimestamp(row["ts_ns"] / 1e9).isoformat(),
                    "device_id": row["src_ip"],
                    "payload_size": row["bytes_sent"],
                    "collection_time": (
                        datetime.fromtimestamp(row["start_time"] / 1e9).isoformat()
                        if row["start_time"]
                        else None
                    ),
                }
            )

        return jsonify(
            {
                "device_id": device_id,
                "metrics": metrics,
                "count": len(metrics),
                "time_range_hours": hours,
                "timestamp": datetime.now().isoformat(),
            }
        )

    finally:
        conn.close()


@snmp_bp.route("/stats", methods=["GET"])
def get_stats():
    """Get overall SNMP telemetry statistics"""
    conn = get_db_connection()
    if not conn:
        return (
            jsonify(
                {"total_events": 0, "total_devices": 0, "message": "No data available"}
            ),
            200,
        )

    try:
        cursor = conn.cursor()

        # Total SNMP events
        cursor.execute(
            """
            SELECT COUNT(*) as count
            FROM events
            WHERE protocol = 'SNMP-TELEMETRY'
        """
        )
        total_events = cursor.fetchone()["count"]

        # Unique devices
        cursor.execute(
            """
            SELECT COUNT(DISTINCT src_ip) as count
            FROM events
            WHERE protocol = 'SNMP-TELEMETRY'
        """
        )
        total_devices = cursor.fetchone()["count"]

        # Events in last hour
        hour_ago_ns = int((datetime.now() - timedelta(hours=1)).timestamp() * 1e9)
        cursor.execute(
            """
            SELECT COUNT(*) as count
            FROM events
            WHERE protocol = 'SNMP-TELEMETRY'
              AND ts_ns > ?
        """,
            (hour_ago_ns,),
        )
        events_last_hour = cursor.fetchone()["count"]

        # Average payload size
        cursor.execute(
            """
            SELECT AVG(bytes_sent) as avg_size
            FROM events
            WHERE protocol = 'SNMP-TELEMETRY'
        """
        )
        avg_payload = cursor.fetchone()["avg_size"] or 0

        return jsonify(
            {
                "total_events": total_events,
                "total_devices": total_devices,
                "events_last_hour": events_last_hour,
                "avg_payload_bytes": int(avg_payload),
                "timestamp": datetime.now().isoformat(),
            }
        )

    finally:
        conn.close()


@snmp_bp.route("/recent", methods=["GET"])
def get_recent_events():
    """Get most recent SNMP telemetry events"""
    limit = min(int(request.args.get("limit", 10)), 100)

    conn = get_db_connection()
    if not conn:
        return jsonify({"events": [], "message": "No data available"}), 200

    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT ts_ns, src_ip, dst_ip, protocol, bytes_sent, start_time
            FROM events
            WHERE protocol = 'SNMP-TELEMETRY'
            ORDER BY ts_ns DESC
            LIMIT ?
        """,
            (limit,),
        )

        events = []
        for row in cursor.fetchall():
            events.append(
                {
                    "timestamp": datetime.fromtimestamp(row["ts_ns"] / 1e9).isoformat(),
                    "device_id": row["src_ip"],
                    "protocol": row["protocol"],
                    "payload_size": row["bytes_sent"],
                    "age_seconds": int(datetime.now().timestamp() - row["ts_ns"] / 1e9),
                }
            )

        return jsonify(
            {
                "events": events,
                "count": len(events),
                "timestamp": datetime.now().isoformat(),
            }
        )

    finally:
        conn.close()
