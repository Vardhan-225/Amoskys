"""
AMOSKYS Process Telemetry API
Fetches and displays process telemetry from permanent storage
"""

from flask import Blueprint, jsonify, request
from datetime import datetime
from .rate_limiter import require_rate_limit
import sqlite3
import os

process_bp = Blueprint("process_telemetry", __name__, url_prefix="/process-telemetry")

# Path to permanent telemetry database
TELEMETRY_DB_PATH = os.path.join(
    os.path.dirname(__file__), "../../../data/telemetry.db"
)


def safe_int(value, default=0, min_val=None, max_val=None):
    """Safely parse integer from request parameter"""
    try:
        result = int(value)
        if min_val is not None and result < min_val:
            return default
        if max_val is not None and result > max_val:
            return max_val
        return result
    except (ValueError, TypeError):
        return default


def get_db_connection():
    """Create connection to telemetry database"""
    if not os.path.exists(TELEMETRY_DB_PATH):
        return None
    conn = sqlite3.connect(TELEMETRY_DB_PATH, timeout=5.0)
    conn.row_factory = sqlite3.Row
    return conn


@process_bp.route("/recent", methods=["GET"])
@require_rate_limit(max_requests=100, window_seconds=60)
def get_recent_processes():
    """Get recent process events from permanent storage"""
    limit = safe_int(
        request.args.get("limit", 100), default=100, min_val=1, max_val=500
    )

    conn = get_db_connection()
    if not conn:
        return jsonify({"processes": [], "message": "No data available yet"}), 200

    try:
        cursor = conn.execute(
            """
            SELECT *,
                   CAST((julianday('now') - julianday(timestamp_dt)) * 86400 AS INTEGER) as age_seconds,
                   process_category as process_class
            FROM process_events
            ORDER BY timestamp_ns DESC
            LIMIT ?
        """,
            (limit,),
        )

        processes = []
        for row in cursor.fetchall():
            proc = dict(row)
            # Add exe_basename for display
            if proc.get("exe"):
                proc["exe_basename"] = proc["exe"].split("/")[-1]
            else:
                proc["exe_basename"] = "unknown"
            processes.append(proc)

        return jsonify(
            {
                "processes": processes,
                "count": len(processes),
                "timestamp": datetime.now().isoformat(),
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()


@process_bp.route("/stats", methods=["GET"])
@require_rate_limit(max_requests=100, window_seconds=60)
def get_process_stats():
    """Get aggregated process statistics"""
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Database not available"}), 500

    try:
        # Total events
        cursor = conn.execute("SELECT COUNT(*) as count FROM process_events")
        total_events = cursor.fetchone()["count"]

        # Unique PIDs
        cursor = conn.execute("SELECT COUNT(DISTINCT pid) as count FROM process_events")
        unique_pids = cursor.fetchone()["count"]

        # Unique executables
        cursor = conn.execute(
            "SELECT COUNT(DISTINCT exe) as count FROM process_events WHERE exe IS NOT NULL"
        )
        unique_exes = cursor.fetchone()["count"]

        # User type distribution
        cursor = conn.execute(
            """
            SELECT user_type, COUNT(*) as count
            FROM process_events
            WHERE user_type IS NOT NULL
            GROUP BY user_type
        """
        )
        user_dist = {row["user_type"]: row["count"] for row in cursor.fetchall()}

        # Process class distribution
        cursor = conn.execute(
            """
            SELECT process_category, COUNT(*) as count
            FROM process_events
            WHERE process_category IS NOT NULL
            GROUP BY process_category
        """
        )
        class_dist = {
            row["process_category"]: row["count"] for row in cursor.fetchall()
        }

        # Top executables
        cursor = conn.execute(
            """
            SELECT exe, COUNT(*) as count
            FROM process_events
            WHERE exe IS NOT NULL
            GROUP BY exe
            ORDER BY count DESC
            LIMIT 10
        """
        )
        top_exes = [
            {"name": os.path.basename(row["exe"]), "count": row["count"]}
            for row in cursor.fetchall()
        ]

        # Time range
        cursor = conn.execute(
            """
            SELECT MIN(timestamp_dt) as start, MAX(timestamp_dt) as end
            FROM process_events
        """
        )
        time_range = cursor.fetchone()

        return jsonify(
            {
                "total_process_events": total_events,
                "unique_pids": unique_pids,
                "unique_executables": unique_exes,
                "user_type_distribution": user_dist,
                "process_class_distribution": class_dist,
                "top_executables": top_exes,
                "collection_period": {
                    "start": time_range["start"],
                    "end": time_range["end"],
                },
                "timestamp": datetime.now().isoformat(),
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()


@process_bp.route("/top-executables", methods=["GET"])
@require_rate_limit(max_requests=100, window_seconds=60)
def get_top_executables():
    """Get most frequently seen executables"""
    limit = safe_int(request.args.get("limit", 20), default=20, min_val=1, max_val=100)

    conn = get_db_connection()
    if not conn:
        return jsonify({"executables": [], "message": "No data available"}), 200

    try:
        cursor = conn.execute(
            """
            SELECT exe, COUNT(*) as count
            FROM process_events
            WHERE exe IS NOT NULL
            GROUP BY exe
            ORDER BY count DESC
            LIMIT ?
        """,
            (limit,),
        )

        total_cursor = conn.execute(
            "SELECT COUNT(*) as total FROM process_events WHERE exe IS NOT NULL"
        )
        total = total_cursor.fetchone()["total"]

        executables = [
            {
                "name": os.path.basename(row["exe"]),
                "full_path": row["exe"],
                "count": row["count"],
                "percentage": round(row["count"] / total * 100, 2) if total > 0 else 0,
            }
            for row in cursor.fetchall()
        ]

        return jsonify(
            {
                "executables": executables,
                "count": len(executables),
                "total_events": total,
                "timestamp": datetime.now().isoformat(),
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()


@process_bp.route("/search", methods=["GET"])
@require_rate_limit(max_requests=100, window_seconds=60)
def search_processes():
    """Search processes by executable, user type, or process category"""
    exe_filter = request.args.get("exe", "")
    user_type = request.args.get("user_type", "")
    category = request.args.get("category", "")
    limit = safe_int(
        request.args.get("limit", 100), default=100, min_val=1, max_val=500
    )

    conn = get_db_connection()
    if not conn:
        return jsonify({"processes": [], "message": "No data available"}), 200

    try:
        query = "SELECT * FROM process_events WHERE 1=1"
        params = []

        if exe_filter:
            query += " AND exe LIKE ?"
            params.append(f"%{exe_filter}%")

        if user_type:
            query += " AND user_type = ?"
            params.append(user_type)

        if category:
            query += " AND process_category = ?"
            params.append(category)

        query += " ORDER BY timestamp_ns DESC LIMIT ?"
        params.append(limit)

        cursor = conn.execute(query, params)
        processes = [dict(row) for row in cursor.fetchall()]

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
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()


@process_bp.route("/device-telemetry", methods=["GET"])
@require_rate_limit(max_requests=100, window_seconds=60)
def get_device_telemetry():
    """Get device-level aggregated telemetry"""
    limit = safe_int(
        request.args.get("limit", 100), default=100, min_val=1, max_val=500
    )

    conn = get_db_connection()
    if not conn:
        return jsonify({"telemetry": [], "message": "No data available"}), 200

    try:
        cursor = conn.execute(
            """
            SELECT *
            FROM device_telemetry
            ORDER BY timestamp_ns DESC
            LIMIT ?
        """,
            (limit,),
        )

        telemetry = [dict(row) for row in cursor.fetchall()]

        return jsonify(
            {
                "telemetry": telemetry,
                "count": len(telemetry),
                "timestamp": datetime.now().isoformat(),
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()


@process_bp.route("/database-stats", methods=["GET"])
@require_rate_limit(max_requests=100, window_seconds=60)
def get_database_stats():
    """Get overall database statistics"""
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Database not available"}), 500

    try:
        stats = {}

        # Get counts for all tables
        for table in [
            "process_events",
            "device_telemetry",
            "flow_events",
            "security_events",
        ]:
            cursor = conn.execute(f"SELECT COUNT(*) as count FROM {table}")
            stats[f"{table}_count"] = cursor.fetchone()["count"]

        # Get database size
        cursor = conn.execute(
            "SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()"
        )
        stats["database_size_bytes"] = cursor.fetchone()["size"]
        stats["database_size_mb"] = round(
            stats["database_size_bytes"] / (1024 * 1024), 2
        )

        return jsonify({"statistics": stats, "timestamp": datetime.now().isoformat()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()


@process_bp.route("/canonical-summary", methods=["GET"])
@require_rate_limit(max_requests=100, window_seconds=60)
def get_canonical_summary():
    """Get summary of canonical process table (ML pipeline stage 1)"""
    conn = get_db_connection()
    if not conn:
        return jsonify(
            {"total_rows": 0, "status": "no_data", "message": "Database not available"}
        )

    try:
        # Check if canonical table exists
        cursor = conn.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type='table' AND name='canonical_processes'
        """
        )

        if not cursor.fetchone():
            return jsonify(
                {
                    "total_rows": 0,
                    "status": "not_generated",
                    "message": "Canonical table not yet generated",
                }
            )

        # Get row count
        cursor = conn.execute("SELECT COUNT(*) as count FROM canonical_processes")
        total_rows = cursor.fetchone()["count"]

        # Get time range if available
        time_range = {"start": None, "end": None}
        try:
            cursor = conn.execute(
                """
                SELECT MIN(timestamp) as start, MAX(timestamp) as end
                FROM canonical_processes
            """
            )
            row = cursor.fetchone()
            if row:
                time_range = {"start": row["start"], "end": row["end"]}
        except sqlite3.OperationalError:
            pass  # Column may not exist

        return jsonify(
            {
                "total_rows": total_rows,
                "status": "ready" if total_rows > 0 else "empty",
                "time_range": time_range,
                "timestamp": datetime.now().isoformat(),
            }
        )
    except Exception as e:
        return jsonify({"total_rows": 0, "status": "error", "error": str(e)}), 500
    finally:
        conn.close()


@process_bp.route("/features-summary", methods=["GET"])
@require_rate_limit(max_requests=100, window_seconds=60)
def get_features_summary():
    """Get summary of ML features table (ML pipeline stage 2)"""
    conn = get_db_connection()
    if not conn:
        return jsonify(
            {
                "total_windows": 0,
                "total_features": 0,
                "status": "no_data",
                "message": "Database not available",
            }
        )

    try:
        # Check if features table exists
        cursor = conn.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type='table' AND name='ml_features'
        """
        )

        if not cursor.fetchone():
            return jsonify(
                {
                    "total_windows": 0,
                    "total_features": 0,
                    "status": "not_generated",
                    "message": "ML features table not yet generated",
                }
            )

        # Get window count (rows in features table)
        cursor = conn.execute("SELECT COUNT(*) as count FROM ml_features")
        total_windows = cursor.fetchone()["count"]

        # Get feature count (columns minus metadata columns)
        cursor = conn.execute("PRAGMA table_info(ml_features)")
        columns = cursor.fetchall()
        # Assume metadata columns are: id, timestamp, window_start, window_end
        metadata_cols = {"id", "timestamp", "window_start", "window_end", "created_at"}
        total_features = len([c for c in columns if c["name"] not in metadata_cols])

        return jsonify(
            {
                "total_windows": total_windows,
                "total_features": total_features,
                "status": "ready" if total_windows > 0 else "empty",
                "timestamp": datetime.now().isoformat(),
            }
        )
    except Exception as e:
        return (
            jsonify(
                {
                    "total_windows": 0,
                    "total_features": 0,
                    "status": "error",
                    "error": str(e),
                }
            ),
            500,
        )
    finally:
        conn.close()
