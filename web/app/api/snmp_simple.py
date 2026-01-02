"""
Simple SNMP Telemetry API - Queries WAL database directly
"""

from flask import Blueprint, jsonify
from datetime import datetime
import sqlite3
import os

snmp_simple_bp = Blueprint("snmp_simple", __name__, url_prefix="/snmp")

# Path to EventBus WAL database
WAL_DB_PATH = os.path.join(os.path.dirname(__file__), "../../../data/wal/flowagent.db")


def get_db():
    """Get database connection"""
    if not os.path.exists(WAL_DB_PATH):
        return None
    return sqlite3.connect(WAL_DB_PATH, timeout=2.0)


@snmp_simple_bp.route("/stats", methods=["GET"])
def get_stats():
    """Get basic statistics from WAL"""
    conn = get_db()
    if not conn:
        return jsonify({"error": "Database not found", "total_events": 0}), 200

    try:
        cursor = conn.cursor()

        # Count total events
        cursor.execute("SELECT COUNT(*) FROM wal")
        total = cursor.fetchone()[0]

        # Get time range
        cursor.execute("SELECT MIN(ts_ns), MAX(ts_ns) FROM wal")
        row = cursor.fetchone()

        first_ts = None
        last_ts = None
        if row and row[0]:
            first_ts = datetime.fromtimestamp(row[0] / 1e9).isoformat()
            last_ts = datetime.fromtimestamp(row[1] / 1e9).isoformat()

        return jsonify(
            {
                "total_events": total,
                "first_event": first_ts,
                "last_event": last_ts,
                "database_path": WAL_DB_PATH,
                "timestamp": datetime.now().isoformat(),
            }
        )
    except Exception as e:
        return jsonify({"error": str(e), "total_events": 0}), 500
    finally:
        conn.close()


@snmp_simple_bp.route("/recent", methods=["GET"])
def get_recent():
    """Get recent events from WAL"""
    conn = get_db()
    if not conn:
        return jsonify({"events": [], "count": 0}), 200

    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, idem, ts_ns, length(bytes) as size
            FROM wal
            ORDER BY ts_ns DESC
            LIMIT 10
        """
        )

        events = []
        for row in cursor.fetchall():
            events.append(
                {
                    "id": row[0],
                    "idem": row[1],
                    "timestamp": datetime.fromtimestamp(row[2] / 1e9).isoformat(),
                    "size_bytes": row[3],
                    "age_seconds": int(datetime.now().timestamp() - row[2] / 1e9),
                }
            )

        return jsonify(
            {
                "events": events,
                "count": len(events),
                "timestamp": datetime.now().isoformat(),
            }
        )
    except Exception as e:
        return jsonify({"error": str(e), "events": []}), 500
    finally:
        conn.close()


@snmp_simple_bp.route("/devices", methods=["GET"])
def list_devices():
    """Extract device list from idempotency keys"""
    conn = get_db()
    if not conn:
        return jsonify({"devices": [], "count": 0}), 200

    try:
        cursor = conn.cursor()
        # Extract device_id from idem format: "device_id_timestamp"
        cursor.execute(
            """
            SELECT DISTINCT substr(idem, 1, instr(idem, '_') - 1) as device_id,
                   MAX(ts_ns) as last_seen,
                   COUNT(*) as event_count
            FROM wal
            WHERE idem LIKE '%_%'
            GROUP BY device_id
            ORDER BY last_seen DESC
        """
        )

        devices = []
        now_ns = datetime.now().timestamp() * 1e9
        for row in cursor.fetchall():
            devices.append(
                {
                    "device_id": row[0],
                    "last_seen": datetime.fromtimestamp(row[1] / 1e9).isoformat(),
                    "event_count": row[2],
                    "status": "online" if (now_ns - row[1]) < 120e9 else "offline",
                }
            )

        return jsonify(
            {
                "devices": devices,
                "count": len(devices),
                "timestamp": datetime.now().isoformat(),
            }
        )
    except Exception as e:
        return jsonify({"error": str(e), "devices": []}), 500
    finally:
        conn.close()
