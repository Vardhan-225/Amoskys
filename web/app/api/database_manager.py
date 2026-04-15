"""
AMOSKYS Database Manager API
Zero-Trust Database Management with Audit Logging

Provides read-only access to database contents and controlled
data management operations with full audit trail.
"""

import csv
import io
import json as _json
import logging
import os
import sqlite3
from datetime import datetime

from flask import Blueprint, Response, jsonify, request

from . import escape_like

logger = logging.getLogger(__name__)

# Blueprint registration
database_manager_bp = Blueprint(
    "database_manager", __name__, url_prefix="/database-manager"
)

# Resolve paths relative to the project root (3 levels up from this file)
_PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
DB_PATH = os.path.join(_PROJECT_ROOT, "data", "telemetry.db")
WAL_PATH = os.path.join(_PROJECT_ROOT, "data", "wal", "flowagent.db")

# Known core tables (used for quick stats fallback)
CORE_TABLES = [
    "process_events",
    "device_telemetry",
    "peripheral_events",
    "flow_events",
    "security_events",
    "metrics_timeseries",
]


def _discover_tables(conn: sqlite3.Connection) -> list[str]:
    """Auto-discover all user tables in the database."""
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    )
    return [row["name"] for row in cursor.fetchall()]


def _is_valid_table(table_name: str, conn: sqlite3.Connection) -> bool:
    """Validate table exists (prevents SQL injection)."""
    cursor = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table_name,)
    )
    return cursor.fetchone() is not None


def _ensure_audit_table(conn: sqlite3.Connection):
    """Create the persistent audit_log table if it doesn't exist."""
    conn.execute(
        """CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            operator TEXT DEFAULT 'system'
        )"""
    )
    conn.commit()


def log_audit_event(action: str, details: dict):
    """Log database management action to persistent audit_log table."""
    logger.warning(f"DATABASE AUDIT: {action} - {details}")
    try:
        conn = get_db_connection(DB_PATH)
        _ensure_audit_table(conn)
        conn.execute(
            "INSERT INTO audit_log (timestamp, action, details, operator) VALUES (?, ?, ?, ?)",
            (
                datetime.now().isoformat(),
                action,
                _json.dumps(details, default=str),
                "system",
            ),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to persist audit event: {e}")


def get_db_connection(db_path: str):
    """Get database connection"""
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Database not found: {db_path}")

    conn = sqlite3.connect(db_path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    return conn


@database_manager_bp.route("/tables", methods=["GET"])
def list_tables():
    """List all tables in the database (auto-discovery)."""
    try:
        conn = get_db_connection(DB_PATH)
        tables = _discover_tables(conn)
        conn.close()
        return jsonify({"tables": tables, "count": len(tables)}), 200
    except Exception as e:
        logger.error(f"Failed to list tables: {e}")
        return jsonify({"error": str(e)}), 500


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

        # Count total records across all discovered tables
        all_tables = _discover_tables(conn)
        total = 0
        for table in all_tables:
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
        table_names = _discover_tables(conn)

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
    """View raw table data with pagination, search, and sorting."""
    try:
        conn = get_db_connection(DB_PATH)
    except FileNotFoundError:
        return jsonify({"error": "Database not available"}), 404
    try:
        if not _is_valid_table(table_name, conn):
            conn.close()
            return jsonify({"error": "Invalid table name"}), 400

        page = request.args.get("page", 1, type=int)
        per_page = min(request.args.get("per_page", 50, type=int), 500)
        search = request.args.get("search", "").strip()
        search_column = request.args.get("search_column", "").strip()
        sort = request.args.get("sort", "id").strip()
        order = request.args.get("order", "desc").strip().upper()

        # Get column names (conn already opened above for validation)
        cursor = conn.execute(f"PRAGMA table_info({table_name})")
        columns = [row["name"] for row in cursor.fetchall()]

        # Validate sort column
        if sort not in columns:
            sort = "id" if "id" in columns else columns[0]
        if order not in ("ASC", "DESC"):
            order = "DESC"

        # Build WHERE clause for search
        where_clause = ""
        params: list = []
        if search and search_column and search_column in columns:
            where_clause = f"WHERE [{search_column}] LIKE ? ESCAPE '\\'"
            params.append(f"%{escape_like(search)}%")
        elif search:
            # Search across all text-like columns
            like_parts = []
            for col in columns:
                like_parts.append(f"CAST([{col}] AS TEXT) LIKE ? ESCAPE '\\'")
                params.append(f"%{escape_like(search)}%")
            where_clause = "WHERE " + " OR ".join(like_parts)

        # Get filtered count
        cursor = conn.execute(
            f"SELECT COUNT(*) FROM {table_name} {where_clause}", params
        )
        total_count = cursor.fetchone()[0]

        # Get total (unfiltered) count
        cursor = conn.execute(f"SELECT COUNT(*) FROM {table_name}")
        unfiltered_count = cursor.fetchone()[0]

        # Pagination
        total_pages = max(1, (total_count + per_page - 1) // per_page)
        page = max(1, min(page, total_pages))
        offset = (page - 1) * per_page

        # Fetch records
        query = f"SELECT * FROM {table_name} {where_clause} ORDER BY [{sort}] {order} LIMIT ? OFFSET ?"
        cursor = conn.execute(query, params + [per_page, offset])
        records = [dict(row) for row in cursor.fetchall()]

        conn.close()

        return jsonify(
            {
                "table": table_name,
                "columns": columns,
                "records": records,
                "total_count": unfiltered_count,
                "filtered_count": total_count,
                "returned_count": len(records),
                "pagination": {
                    "page": page,
                    "per_page": per_page,
                    "total_count": total_count,
                    "total_pages": total_pages,
                    "has_next": page < total_pages,
                    "has_prev": page > 1,
                },
                "timestamp": datetime.now().isoformat(),
            }
        )

    except Exception as e:
        logger.error(f"Failed to view table {table_name}: {e}")
        return jsonify({"error": str(e)}), 500


@database_manager_bp.route("/export/<table_name>", methods=["GET"])
def export_table(table_name):
    """Export table data as CSV or JSON."""
    try:
        conn = get_db_connection(DB_PATH)
    except FileNotFoundError:
        return jsonify({"error": "Database not available"}), 404
    try:
        if not _is_valid_table(table_name, conn):
            conn.close()
            return jsonify({"error": "Invalid table name"}), 400

        fmt = request.args.get("format", "csv").lower()
        limit = min(request.args.get("limit", 10000, type=int), 50000)

        cursor = conn.execute(f"PRAGMA table_info({table_name})")
        columns = [row["name"] for row in cursor.fetchall()]

        cursor = conn.execute(
            f"SELECT * FROM {table_name} ORDER BY id DESC LIMIT ?", (limit,)
        )
        records = [dict(row) for row in cursor.fetchall()]
        conn.close()

        log_audit_event(
            "EXPORT_TABLE",
            {"table": table_name, "format": fmt, "rows": len(records)},
        )

        if fmt == "json":
            return Response(
                _json.dumps(records, indent=2, default=str),
                mimetype="application/json",
                headers={
                    "Content-Disposition": f"attachment; filename={table_name}.json"
                },
            )

        # Default: CSV
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=columns)
        writer.writeheader()
        writer.writerows(records)

        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={table_name}.csv"},
        )

    except Exception as e:
        logger.error(f"Failed to export table {table_name}: {e}")
        return jsonify({"error": str(e)}), 500


@database_manager_bp.route("/truncate-table/<table_name>", methods=["POST"])
def truncate_table(table_name):
    """
    Truncate a table (delete all records)
    Zero-Trust: Only complete table truncation allowed, no individual record deletion
    """
    try:
        conn = get_db_connection(DB_PATH)
        if not _is_valid_table(table_name, conn):
            conn.close()
            return jsonify({"error": "Invalid table name"}), 400

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

        total_deleted = 0

        all_tables = _discover_tables(conn)
        for table in all_tables:
            if table == "audit_log":
                continue  # Preserve audit log during reset
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
            {
                "tables_truncated": len(all_tables),
                "total_rows_deleted": total_deleted,
            },
        )

        return (
            jsonify(
                {
                    "status": "success",
                    "total_deleted": total_deleted,
                    "tables_reset": len(all_tables),
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
    """Get persistent audit log of database operations."""
    try:
        conn = get_db_connection(DB_PATH)
        _ensure_audit_table(conn)

        limit = min(request.args.get("limit", 100, type=int), 500)
        cursor = conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        )
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()

        return jsonify(
            {
                "audit_log": rows,
                "count": len(rows),
                "timestamp": datetime.now().isoformat(),
            }
        )
    except Exception as e:
        logger.error(f"Failed to get audit log: {e}")
        return jsonify({"error": str(e)}), 500
