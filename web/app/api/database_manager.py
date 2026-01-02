"""
AMOSKYS Database Manager API
Zero-Trust Database Management with Audit Logging

Provides read-only access to database contents and controlled
data management operations with full audit trail.
"""

import sqlite3
import os
from flask import Blueprint, jsonify, request
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# Blueprint registration
database_manager_bp = Blueprint(
    "database_manager", __name__, url_prefix="/database-manager"
)

# Database paths (relative to web/ directory)
DB_PATH = "../data/telemetry.db"
WAL_PATH = "../data/wal/flowagent.db"

# Audit log (in-memory for this session, could be persisted)
audit_log = []


def log_audit_event(action: str, details: dict):
    """Log database management action for audit trail"""
    entry = {
        "timestamp": datetime.now().isoformat(),
        "action": action,
        "details": details,
        "operator": "system",  # Could be extended to include user identity
    }
    audit_log.append(entry)
    logger.warning(f"DATABASE AUDIT: {action} - {details}")


def get_db_connection(db_path: str):
    """Get database connection"""
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Database not found: {db_path}")

    conn = sqlite3.connect(db_path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    return conn


@database_manager_bp.route("/statistics", methods=["GET"])
def get_statistics():
    """Get overall database statistics"""
    try:
        stats = {
            "database_path": DB_PATH,
            "database_size": 0,
            "wal_size": 0,
            "total_records": 0,
            "table_count": 0,
            "wal_pending_events": 0,
            "oldest_record": None,
            "newest_record": None,
        }

        # Get database file size
        if os.path.exists(DB_PATH):
            stats["database_size"] = os.path.getsize(DB_PATH)

        # Get WAL file size and pending events
        if os.path.exists(WAL_PATH):
            stats["wal_size"] = os.path.getsize(WAL_PATH)
            try:
                wal_conn = get_db_connection(WAL_PATH)
                cursor = wal_conn.execute("SELECT COUNT(*) FROM wal")
                stats["wal_pending_events"] = cursor.fetchone()[0]
                wal_conn.close()
            except Exception as e:
                logger.error(f"Failed to query WAL: {e}")

        # Get table statistics
        conn = get_db_connection(DB_PATH)

        # Count tables
        cursor = conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
        stats["table_count"] = cursor.fetchone()[0]

        # Count total records across all tables
        tables = [
            "process_events",
            "device_telemetry",
            "peripheral_events",
            "flow_events",
            "security_events",
        ]
        total = 0
        for table in tables:
            try:
                cursor = conn.execute(f"SELECT COUNT(*) FROM {table}")
                count = cursor.fetchone()[0]
                total += count
            except Exception:
                pass  # Table may not exist

        stats["total_records"] = total

        # Get time range from process_events (largest table)
        try:
            cursor = conn.execute(
                "SELECT MIN(timestamp_dt) as oldest, MAX(timestamp_dt) as newest FROM process_events"
            )
            row = cursor.fetchone()
            if row and row["oldest"]:
                stats["oldest_record"] = row["oldest"]
                stats["newest_record"] = row["newest"]
        except Exception:
            pass  # Table may not exist or be empty

        conn.close()

        return jsonify(stats), 200

    except Exception as e:
        logger.error(f"Failed to get statistics: {e}")
        return jsonify({"error": str(e)}), 500


@database_manager_bp.route("/table-stats", methods=["GET"])
def get_table_stats():
    """Get statistics for each table"""
    try:
        conn = get_db_connection(DB_PATH)

        tables = []
        table_names = [
            "process_events",
            "device_telemetry",
            "peripheral_events",
            "flow_events",
            "security_events",
            "metrics_timeseries",
        ]

        for table_name in table_names:
            try:
                # Get row count
                cursor = conn.execute(f"SELECT COUNT(*) FROM {table_name}")
                row_count = cursor.fetchone()[0]

                # Get approximate table size from database page count
                # This is more efficient than calculating actual row sizes
                estimated_size = row_count * 1000  # Rough estimate: 1KB per row average

                # Get time range if timestamp_dt column exists
                time_range = None
                try:
                    cursor = conn.execute(
                        f"SELECT MIN(timestamp_dt) as oldest, MAX(timestamp_dt) as newest FROM {table_name}"
                    )
                    row = cursor.fetchone()
                    if row and row["oldest"]:
                        oldest = row["oldest"][:10]  # YYYY-MM-DD
                        newest = row["newest"][:10]
                        if oldest == newest:
                            time_range = oldest
                        else:
                            time_range = f"{oldest} to {newest}"
                except Exception:
                    pass  # Table may not have timestamp column

                tables.append(
                    {
                        "name": table_name,
                        "row_count": row_count,
                        "size_bytes": int(estimated_size),
                        "time_range": time_range,
                    }
                )

            except Exception as e:
                logger.error(f"Failed to get stats for {table_name}: {e}")

        conn.close()

        return jsonify({"tables": tables, "timestamp": datetime.now().isoformat()}), 200

    except Exception as e:
        logger.error(f"Failed to get table stats: {e}")
        return jsonify({"error": str(e)}), 500


@database_manager_bp.route("/view-table/<table_name>", methods=["GET"])
def view_table(table_name):
    """View raw table data (read-only)"""
    try:
        # Validate table name to prevent SQL injection
        allowed_tables = [
            "process_events",
            "device_telemetry",
            "peripheral_events",
            "flow_events",
            "security_events",
            "metrics_timeseries",
        ]

        if table_name not in allowed_tables:
            return jsonify({"error": "Invalid table name"}), 400

        limit = request.args.get("limit", 100, type=int)
        limit = min(limit, 1000)  # Max 1000 records

        conn = get_db_connection(DB_PATH)

        # Get column names
        cursor = conn.execute(f"PRAGMA table_info({table_name})")
        columns = [row["name"] for row in cursor.fetchall()]

        # Get total count
        cursor = conn.execute(f"SELECT COUNT(*) FROM {table_name}")
        total_count = cursor.fetchone()[0]

        # Get records
        cursor = conn.execute(
            f"SELECT * FROM {table_name} ORDER BY id DESC LIMIT ?", (limit,)
        )
        records = [dict(row) for row in cursor.fetchall()]

        conn.close()

        return (
            jsonify(
                {
                    "table": table_name,
                    "columns": columns,
                    "records": records,
                    "total_count": total_count,
                    "returned_count": len(records),
                    "timestamp": datetime.now().isoformat(),
                }
            ),
            200,
        )

    except Exception as e:
        logger.error(f"Failed to view table {table_name}: {e}")
        return jsonify({"error": str(e)}), 500


@database_manager_bp.route("/truncate-table/<table_name>", methods=["POST"])
def truncate_table(table_name):
    """
    Truncate a table (delete all records)
    Zero-Trust: Only complete table truncation allowed, no individual record deletion
    """
    try:
        # Validate table name
        allowed_tables = [
            "process_events",
            "device_telemetry",
            "peripheral_events",
            "flow_events",
            "security_events",
            "metrics_timeseries",
        ]

        if table_name not in allowed_tables:
            return jsonify({"error": "Invalid table name"}), 400

        conn = get_db_connection(DB_PATH)

        # Get row count before deletion
        cursor = conn.execute(f"SELECT COUNT(*) FROM {table_name}")
        rows_before = cursor.fetchone()[0]

        # Truncate table
        conn.execute(f"DELETE FROM {table_name}")
        conn.commit()

        # Get row count after (should be 0)
        cursor = conn.execute(f"SELECT COUNT(*) FROM {table_name}")
        rows_after = cursor.fetchone()[0]

        conn.close()

        # Log audit event
        log_audit_event(
            "TRUNCATE_TABLE",
            {
                "table": table_name,
                "rows_deleted": rows_before,
                "rows_remaining": rows_after,
            },
        )

        return (
            jsonify(
                {
                    "status": "success",
                    "table": table_name,
                    "rows_deleted": rows_before,
                    "timestamp": datetime.now().isoformat(),
                }
            ),
            200,
        )

    except Exception as e:
        logger.error(f"Failed to truncate table {table_name}: {e}")
        return jsonify({"error": str(e)}), 500


@database_manager_bp.route("/reset-database", methods=["POST"])
def reset_database():
    """
    Reset entire database (truncate all tables)
    Zero-Trust: Complete wipe, preserves schema
    """
    try:
        conn = get_db_connection(DB_PATH)

        tables = [
            "process_events",
            "device_telemetry",
            "peripheral_events",
            "flow_events",
            "security_events",
            "metrics_timeseries",
        ]

        total_deleted = 0

        for table in tables:
            try:
                cursor = conn.execute(f"SELECT COUNT(*) FROM {table}")
                count = cursor.fetchone()[0]

                conn.execute(f"DELETE FROM {table}")
                total_deleted += count
            except Exception as e:
                logger.error(f"Failed to truncate {table}: {e}")

        conn.commit()
        conn.close()

        # Log audit event
        log_audit_event(
            "RESET_DATABASE",
            {"tables_truncated": len(tables), "total_rows_deleted": total_deleted},
        )

        return (
            jsonify(
                {
                    "status": "success",
                    "total_deleted": total_deleted,
                    "tables_reset": len(tables),
                    "timestamp": datetime.now().isoformat(),
                }
            ),
            200,
        )

    except Exception as e:
        logger.error(f"Failed to reset database: {e}")
        return jsonify({"error": str(e)}), 500


@database_manager_bp.route("/clear-wal", methods=["POST"])
def clear_wal():
    """Clear WAL queue (delete processed events)"""
    try:
        if not os.path.exists(WAL_PATH):
            return jsonify({"error": "WAL database not found"}), 404

        conn = get_db_connection(WAL_PATH)

        # Get count before
        cursor = conn.execute("SELECT COUNT(*) FROM wal")
        count_before = cursor.fetchone()[0]

        # Clear WAL
        conn.execute("DELETE FROM wal")
        conn.commit()

        # Get count after
        cursor = conn.execute("SELECT COUNT(*) FROM wal")
        count_after = cursor.fetchone()[0]

        conn.close()

        # Log audit event
        log_audit_event(
            "CLEAR_WAL",
            {"events_deleted": count_before, "events_remaining": count_after},
        )

        return (
            jsonify(
                {
                    "status": "success",
                    "rows_deleted": count_before,
                    "timestamp": datetime.now().isoformat(),
                }
            ),
            200,
        )

    except Exception as e:
        logger.error(f"Failed to clear WAL: {e}")
        return jsonify({"error": str(e)}), 500


@database_manager_bp.route("/audit-log", methods=["GET"])
def get_audit_log():
    """Get audit log of database operations"""
    return (
        jsonify(
            {
                "audit_log": audit_log,
                "count": len(audit_log),
                "timestamp": datetime.now().isoformat(),
            }
        ),
        200,
    )
