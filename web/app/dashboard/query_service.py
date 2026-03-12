"""Canonical dashboard query service.

All API handlers should use this service instead of opening ad-hoc
SQLite connections or querying WAL tables directly.
"""

from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional

from .telemetry_bridge import get_telemetry_store


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _quote_ident(value: str) -> str:
    return f"\"{value.replace('\"', '\"\"')}\""


def _cutoff_ns(hours: int) -> int:
    return int((time.time() - hours * 3600) * 1e9)


class DashboardQueryService:
    """One query-path service backed by TelemetryStore."""

    def __init__(self, store: Any) -> None:
        self.store = store

    @property
    def available(self) -> bool:
        return self.store is not None

    @contextmanager
    def _read_conn(self) -> Iterator[Any]:
        if self.store is None:
            raise RuntimeError("TelemetryStore unavailable")
        if hasattr(self.store, "_read_pool"):
            with self.store._read_pool.connection() as conn:
                yield conn
            return
        yield self.store.db

    def _discover_timestamp_event_tables(self, conn: Any) -> List[str]:
        """Discover canonical event tables that carry timestamp_ns."""
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        candidates = {
            row["name"] if isinstance(row, sqlite3.Row) else row[0] for row in rows
        }
        event_candidates = {
            name
            for name in candidates
            if name.endswith("_events")
            or name in {"telemetry_events", "device_telemetry"}
        }
        tables: List[str] = []
        for name in sorted(event_candidates):
            cols = conn.execute(f"PRAGMA table_info({name})").fetchall()
            col_names = {
                col["name"] if isinstance(col, sqlite3.Row) else col[1] for col in cols
            }
            if "timestamp_ns" in col_names:
                tables.append(name)
        return tables

    # ── Telemetry API ───────────────────────────────────────────────────

    def recent_telemetry(
        self, limit: int = 50, hours: int = 24
    ) -> List[Dict[str, Any]]:
        if not self.available:
            return []
        rows = self.store.get_cross_domain_timeline(hours=hours, limit=limit)
        events: List[Dict[str, Any]] = []
        for idx, row in enumerate(rows):
            events.append(
                {
                    "id": idx + 1,
                    "idempotency_key": "",
                    "timestamp_ns": row.get("timestamp_ns"),
                    "timestamp": row.get("timestamp_dt"),
                    "type": row.get("domain", "unknown"),
                    "event_type": row.get("event_type"),
                    "summary": row.get("summary"),
                    "risk_score": row.get("risk_score", 0.0),
                }
            )
        return events

    def agent_summary(self, limit: int = 100) -> Dict[str, Any]:
        if not self.available:
            return {"total_events": 0, "agent_count": 0, "agents": []}

        with self._read_conn() as conn:
            latest_rows = conn.execute(
                """
                SELECT dt.device_id, dt.device_type, dt.collection_agent,
                       dt.total_processes, dt.total_cpu_percent, dt.total_memory_percent,
                       dt.timestamp_ns, dt.timestamp_dt
                FROM device_telemetry dt
                JOIN (
                    SELECT device_id, MAX(timestamp_ns) AS max_ts
                    FROM device_telemetry
                    GROUP BY device_id
                ) latest
                ON dt.device_id = latest.device_id AND dt.timestamp_ns = latest.max_ts
                ORDER BY dt.timestamp_ns DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

            count_rows = conn.execute(
                """
                SELECT device_id, COUNT(*) AS event_count
                FROM device_telemetry
                GROUP BY device_id
                """
            ).fetchall()

        event_counts = {row["device_id"]: row["event_count"] for row in count_rows}
        agents = []
        for row in latest_rows:
            agents.append(
                {
                    "device_id": row["device_id"],
                    "device_type": row["device_type"] or "UNKNOWN",
                    "event_count": event_counts.get(row["device_id"], 0),
                    "last_seen": row["timestamp_dt"],
                    "collection_agent": row["collection_agent"],
                    "latest_metrics": {
                        "total_processes": row["total_processes"] or 0,
                        "total_cpu_percent": row["total_cpu_percent"] or 0.0,
                        "total_memory_percent": row["total_memory_percent"] or 0.0,
                    },
                }
            )

        counts = self.store.get_unified_event_counts(hours=24)
        return {
            "total_events": counts.get("total", 0),
            "agent_count": len(agents),
            "agents": agents,
        }

    def device_metrics(self, device_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        if not self.available:
            return []
        with self._read_conn() as conn:
            rows = conn.execute(
                """
                SELECT timestamp_dt, metric_name, value, unit
                FROM metrics_timeseries
                WHERE device_id = ?
                ORDER BY timestamp_ns DESC
                LIMIT ?
                """,
                (device_id, limit),
            ).fetchall()
        return [
            {
                "timestamp": row["timestamp_dt"],
                "name": row["metric_name"],
                "value": row["value"],
                "unit": row["unit"],
            }
            for row in rows
        ]

    def telemetry_stats(self) -> Dict[str, Any]:
        if not self.available:
            return {
                "total_events": 0,
                "earliest_event": None,
                "latest_event": None,
                "time_span_seconds": 0,
            }

        counts = self.store.get_unified_event_counts(hours=24 * 365)
        with self._read_conn() as conn:
            event_tables = self._discover_timestamp_event_tables(conn)
            if not event_tables:
                row = None
            else:
                union_sql = " UNION ALL ".join(
                    f"SELECT MIN(timestamp_ns) AS min_ts, MAX(timestamp_ns) AS max_ts FROM {t}"
                    for t in event_tables
                )
                row = conn.execute(
                    f"SELECT MIN(min_ts), MAX(max_ts) FROM ({union_sql})"
                ).fetchone()
            min_ts = row[0] if row else None
            max_ts = row[1] if row else None

        stats = {
            "total_events": counts.get("total", 0),
            "earliest_event": None,
            "latest_event": None,
            "time_span_seconds": 0,
        }
        if min_ts and max_ts:
            stats["earliest_event"] = datetime.fromtimestamp(
                min_ts / 1e9, tz=timezone.utc
            ).isoformat()
            stats["latest_event"] = datetime.fromtimestamp(
                max_ts / 1e9, tz=timezone.utc
            ).isoformat()
            stats["time_span_seconds"] = int((max_ts - min_ts) / 1e9)
        return stats

    def security_event_by_id(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Fetch one security event by canonical event_id."""
        if not self.available:
            return None
        with self._read_conn() as conn:
            row = conn.execute(
                "SELECT * FROM security_events WHERE event_id = ?",
                (event_id,),
            ).fetchone()
        return dict(row) if row else None

    def update_security_event_status(self, event_id: str, status: str) -> bool:
        """Update final_classification for one event."""
        if not self.available:
            return False
        lock = self.store._lock if hasattr(self.store, "_lock") else nullcontext()
        with lock:
            cursor = self.store.db.execute(
                "UPDATE security_events SET final_classification = ? WHERE event_id = ?",
                (status, event_id),
            )
            if cursor.rowcount <= 0:
                return False
            self.store.db.commit()
            if hasattr(self.store, "_cache"):
                self.store._cache.invalidate()
        return True

    def consistency_check(self, hours: int = 24) -> Dict[str, Any]:
        """Compare aggregate counts with direct canonical-table totals."""
        if not self.available:
            return {"consistent": True, "message": "TelemetryStore unavailable"}

        canonical_tables = [
            "security_events",
            "persistence_events",
            "process_events",
            "fim_events",
            "flow_events",
            "dns_events",
            "audit_events",
            "peripheral_events",
            "observation_events",
        ]
        cutoff_ns = _cutoff_ns(hours)
        with self._read_conn() as conn:
            direct_counts: Dict[str, int] = {}
            for table in canonical_tables:
                exists = conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                    (table,),
                ).fetchone()
                if not exists:
                    continue
                row = conn.execute(
                    f"SELECT COUNT(*) AS count FROM {table} WHERE timestamp_ns > ?",
                    (cutoff_ns,),
                ).fetchone()
                direct_counts[table] = int(row["count"] if row else 0)

        service_counts = self.store.get_unified_event_counts(hours=hours)
        by_source = service_counts.get("by_source", {})
        source_consistent = True
        for table, direct in direct_counts.items():
            source_key = table.replace("_events", "")
            if int(by_source.get(source_key, 0)) != direct:
                source_consistent = False
                break

        direct_total = sum(direct_counts.values())
        service_total = int(service_counts.get("total", 0))
        return {
            "hours": hours,
            "consistent": source_consistent and (direct_total == service_total),
            "service_total": service_total,
            "direct_total": direct_total,
            "by_source_service": by_source,
            "by_table_direct": direct_counts,
        }

    def attribute_catalog(
        self,
        *,
        max_tables: int = 20,
        max_top_values: int = 10,
    ) -> Dict[str, Any]:
        """Expose schema + observed attribute distributions for dashboard UX."""
        if not self.available:
            return {"tables": []}

        with self._read_conn() as conn:
            tables = self._discover_timestamp_event_tables(conn)[:max_tables]
            payload: List[Dict[str, Any]] = []
            for table in tables:
                cols = conn.execute(f"PRAGMA table_info({table})").fetchall()
                column_meta: List[Dict[str, Any]] = []
                for col in cols:
                    name = col["name"] if isinstance(col, sqlite3.Row) else col[1]
                    ctype = col["type"] if isinstance(col, sqlite3.Row) else col[2]
                    if name in {"raw_attributes_json", "attributes"}:
                        continue
                    qname = _quote_ident(name)
                    row = conn.execute(
                        f"SELECT COUNT(*) AS nn FROM {table} WHERE {qname} IS NOT NULL"
                    ).fetchone()
                    non_null = int(row["nn"] if row else 0)
                    card_row = conn.execute(
                        f"SELECT COUNT(DISTINCT {qname}) AS card FROM {table} WHERE {qname} IS NOT NULL"
                    ).fetchone()
                    cardinality = int(card_row["card"] if card_row else 0)
                    top_values: List[Dict[str, Any]] = []
                    if 0 < cardinality <= max_top_values:
                        top_rows = conn.execute(
                            f"""
                            SELECT {qname} AS value, COUNT(*) AS count
                            FROM {table}
                            WHERE {qname} IS NOT NULL
                            GROUP BY {qname}
                            ORDER BY count DESC
                            LIMIT ?
                            """,
                            (max_top_values,),
                        ).fetchall()
                        top_values = [
                            {
                                "value": (
                                    r["value"] if isinstance(r, sqlite3.Row) else r[0]
                                ),
                                "count": (
                                    r["count"] if isinstance(r, sqlite3.Row) else r[1]
                                ),
                            }
                            for r in top_rows
                        ]
                    column_meta.append(
                        {
                            "name": name,
                            "type": ctype,
                            "non_null_count": non_null,
                            "distinct_count": cardinality,
                            "top_values": top_values,
                        }
                    )

                table_count_row = conn.execute(
                    f"SELECT COUNT(*) AS count FROM {table}"
                ).fetchone()
                payload.append(
                    {
                        "table": table,
                        "row_count": int(
                            table_count_row["count"] if table_count_row else 0
                        ),
                        "columns": column_meta,
                    }
                )
        return {"tables": payload}

    # ── Process API ─────────────────────────────────────────────────────

    def recent_processes(self, limit: int = 100) -> List[Dict[str, Any]]:
        if not self.available:
            return []
        rows = self.store.get_recent_processes(limit=limit)
        for proc in rows:
            proc["exe_basename"] = (
                proc.get("exe", "").split("/")[-1] if proc.get("exe") else "unknown"
            )
        return rows

    def process_stats(self) -> Dict[str, Any]:
        if not self.available:
            return {}
        with self._read_conn() as conn:
            total_events = conn.execute(
                "SELECT COUNT(*) AS count FROM process_events"
            ).fetchone()["count"]
            unique_pids = conn.execute(
                "SELECT COUNT(DISTINCT pid) AS count FROM process_events"
            ).fetchone()["count"]
            unique_exes = conn.execute(
                "SELECT COUNT(DISTINCT exe) AS count FROM process_events WHERE exe IS NOT NULL"
            ).fetchone()["count"]

            user_rows = conn.execute(
                """
                SELECT user_type, COUNT(*) AS count
                FROM process_events
                WHERE user_type IS NOT NULL
                GROUP BY user_type
                """
            ).fetchall()
            class_rows = conn.execute(
                """
                SELECT process_category, COUNT(*) AS count
                FROM process_events
                WHERE process_category IS NOT NULL
                GROUP BY process_category
                """
            ).fetchall()
            top_rows = conn.execute(
                """
                SELECT exe, COUNT(*) AS count
                FROM process_events
                WHERE exe IS NOT NULL
                GROUP BY exe
                ORDER BY count DESC
                LIMIT 10
                """
            ).fetchall()
            time_range = conn.execute(
                """
                SELECT MIN(timestamp_dt) AS start, MAX(timestamp_dt) AS end
                FROM process_events
                """
            ).fetchone()

        return {
            "total_process_events": total_events,
            "unique_pids": unique_pids,
            "unique_executables": unique_exes,
            "user_type_distribution": {r["user_type"]: r["count"] for r in user_rows},
            "process_class_distribution": {
                r["process_category"]: r["count"] for r in class_rows
            },
            "top_executables": [
                {"name": (row["exe"] or "").split("/")[-1], "count": row["count"]}
                for row in top_rows
            ],
            "collection_period": {
                "start": time_range["start"],
                "end": time_range["end"],
            },
        }

    def process_top_executables(self, limit: int = 20) -> Dict[str, Any]:
        if not self.available:
            return {"executables": [], "total_events": 0}
        with self._read_conn() as conn:
            rows = conn.execute(
                """
                SELECT exe, COUNT(*) AS count
                FROM process_events
                WHERE exe IS NOT NULL
                GROUP BY exe
                ORDER BY count DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            total = conn.execute(
                "SELECT COUNT(*) AS total FROM process_events WHERE exe IS NOT NULL"
            ).fetchone()["total"]
        return {
            "executables": [
                {
                    "name": (row["exe"] or "").split("/")[-1],
                    "full_path": row["exe"],
                    "count": row["count"],
                    "percentage": (
                        round((row["count"] / total) * 100, 2) if total else 0
                    ),
                }
                for row in rows
            ],
            "total_events": total,
        }

    def process_search(
        self,
        *,
        exe_filter: str = "",
        user_type: str = "",
        category: str = "",
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        if not self.available:
            return []
        query = "SELECT * FROM process_events WHERE 1=1"
        params: List[Any] = []
        if exe_filter:
            query += " AND exe LIKE ? ESCAPE '\\'"
            params.append(f"%{_escape_like(exe_filter)}%")
        if user_type:
            query += " AND user_type = ?"
            params.append(user_type)
        if category:
            query += " AND process_category = ?"
            params.append(category)
        query += " ORDER BY timestamp_ns DESC LIMIT ?"
        params.append(limit)
        with self._read_conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def device_telemetry_snapshots(self, limit: int = 100) -> List[Dict[str, Any]]:
        if not self.available:
            return []
        with self._read_conn() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM device_telemetry
                ORDER BY timestamp_ns DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def database_stats(self) -> Dict[str, Any]:
        if not self.available:
            return {}
        tables = [
            "process_events",
            "device_telemetry",
            "flow_events",
            "security_events",
        ]
        stats: Dict[str, Any] = {}
        with self._read_conn() as conn:
            for table in tables:
                stats[f"{table}_count"] = conn.execute(
                    f"SELECT COUNT(*) AS count FROM {table}"
                ).fetchone()["count"]
            size_row = conn.execute(
                "SELECT page_count * page_size AS size FROM pragma_page_count(), pragma_page_size()"
            ).fetchone()
        stats["database_size_bytes"] = size_row["size"] if size_row else 0
        stats["database_size_mb"] = round(
            stats["database_size_bytes"] / (1024 * 1024), 2
        )
        return stats

    def canonical_summary(self) -> Dict[str, Any]:
        if not self.available:
            return {"total_rows": 0, "status": "no_data"}
        with self._read_conn() as conn:
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='canonical_processes'"
            ).fetchone()
            if not exists:
                return {"total_rows": 0, "status": "not_generated"}
            total_rows = conn.execute(
                "SELECT COUNT(*) AS count FROM canonical_processes"
            ).fetchone()["count"]
            time_row = conn.execute(
                "SELECT MIN(timestamp) AS start, MAX(timestamp) AS end FROM canonical_processes"
            ).fetchone()
        return {
            "total_rows": total_rows,
            "status": "ready" if total_rows > 0 else "empty",
            "time_range": {
                "start": time_row["start"] if time_row else None,
                "end": time_row["end"] if time_row else None,
            },
        }

    def features_summary(self) -> Dict[str, Any]:
        if not self.available:
            return {"total_windows": 0, "total_features": 0, "status": "no_data"}
        with self._read_conn() as conn:
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='ml_features'"
            ).fetchone()
            if not exists:
                return {
                    "total_windows": 0,
                    "total_features": 0,
                    "status": "not_generated",
                }
            total_windows = conn.execute(
                "SELECT COUNT(*) AS count FROM ml_features"
            ).fetchone()["count"]
            columns = conn.execute("PRAGMA table_info(ml_features)").fetchall()
        metadata_cols = {"id", "timestamp", "window_start", "window_end", "created_at"}
        total_features = len([c for c in columns if c["name"] not in metadata_cols])
        return {
            "total_windows": total_windows,
            "total_features": total_features,
            "status": "ready" if total_windows > 0 else "empty",
        }

    # ── Peripheral API ──────────────────────────────────────────────────

    def recent_peripheral_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        if not self.available:
            return []
        with self._read_conn() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM peripheral_events
                ORDER BY timestamp_ns DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def connected_peripherals(self) -> List[Dict[str, Any]]:
        if not self.available:
            return []
        with self._read_conn() as conn:
            rows = conn.execute(
                """
                SELECT
                    peripheral_device_id,
                    device_name,
                    device_type,
                    vendor_id,
                    product_id,
                    manufacturer,
                    connection_status,
                    is_authorized,
                    risk_score,
                    MAX(timestamp_ns) AS last_seen_ns,
                    timestamp_dt AS last_seen_dt
                FROM peripheral_events
                GROUP BY peripheral_device_id
                HAVING connection_status = 'CONNECTED'
                ORDER BY last_seen_ns DESC
                """
            ).fetchall()
        now = datetime.now(timezone.utc)
        devices: List[Dict[str, Any]] = []
        for row in rows:
            record = dict(row)
            try:
                last_seen = datetime.fromisoformat(record["last_seen_dt"])
                if last_seen.tzinfo is None:
                    last_seen = last_seen.replace(tzinfo=timezone.utc)
                record["seconds_since_seen"] = int((now - last_seen).total_seconds())
            except Exception:
                record["seconds_since_seen"] = None
            devices.append(record)
        return devices

    def peripheral_stats(self) -> Dict[str, Any]:
        if not self.available:
            return {}
        with self._read_conn() as conn:
            total_events = conn.execute(
                "SELECT COUNT(*) AS count FROM peripheral_events"
            ).fetchone()["count"]
            unique_devices = conn.execute(
                "SELECT COUNT(DISTINCT peripheral_device_id) AS count FROM peripheral_events"
            ).fetchone()["count"]
            type_rows = conn.execute(
                """
                SELECT device_type, COUNT(*) AS count
                FROM peripheral_events
                WHERE device_type IS NOT NULL
                GROUP BY device_type
                """
            ).fetchall()
            status_rows = conn.execute(
                """
                SELECT connection_status, COUNT(*) AS count
                FROM peripheral_events
                WHERE connection_status IS NOT NULL
                GROUP BY connection_status
                """
            ).fetchall()
            unauthorized_count = conn.execute(
                """
                SELECT COUNT(DISTINCT peripheral_device_id) AS count
                FROM peripheral_events
                WHERE is_authorized = 0
                """
            ).fetchone()["count"]
            high_risk_count = conn.execute(
                """
                SELECT COUNT(DISTINCT peripheral_device_id) AS count
                FROM peripheral_events
                WHERE risk_score > 0.7
                """
            ).fetchone()["count"]
            one_hour_ago = int((time.time() - 3600) * 1e9)
            recent_connections = conn.execute(
                """
                SELECT COUNT(*) AS count
                FROM peripheral_events
                WHERE timestamp_ns > ? AND connection_status = 'CONNECTED'
                """,
                (one_hour_ago,),
            ).fetchone()["count"]
            time_range = conn.execute(
                "SELECT MIN(timestamp_dt) AS start, MAX(timestamp_dt) AS end FROM peripheral_events"
            ).fetchone()

        return {
            "total_events": total_events,
            "unique_devices": unique_devices,
            "unauthorized_devices": unauthorized_count,
            "high_risk_devices": high_risk_count,
            "recent_connections_1h": recent_connections,
            "device_type_distribution": {
                r["device_type"]: r["count"] for r in type_rows
            },
            "connection_status_distribution": {
                r["connection_status"]: r["count"] for r in status_rows
            },
            "collection_period": {
                "start": time_range["start"] if time_range else None,
                "end": time_range["end"] if time_range else None,
            },
        }

    def peripheral_timeline(self, hours: int = 24) -> List[Dict[str, Any]]:
        if not self.available:
            return []
        cutoff_time = _cutoff_ns(hours)
        with self._read_conn() as conn:
            rows = conn.execute(
                """
                SELECT timestamp_ns, timestamp_dt, device_name, device_type,
                       connection_status, previous_status, is_authorized, risk_score
                FROM peripheral_events
                WHERE timestamp_ns > ?
                ORDER BY timestamp_ns DESC
                """,
                (cutoff_time,),
            ).fetchall()
        now = datetime.now(timezone.utc)
        timeline: List[Dict[str, Any]] = []
        for row in rows:
            event = dict(row)
            try:
                event_time = datetime.fromisoformat(event["timestamp_dt"])
                if event_time.tzinfo is None:
                    event_time = event_time.replace(tzinfo=timezone.utc)
                event["hours_ago"] = round((now - event_time).total_seconds() / 3600, 1)
            except Exception:
                event["hours_ago"] = None
            timeline.append(event)
        return timeline

    def high_risk_peripherals(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self._query_peripheral_aggregate(
            where_clause="risk_score > 0.5",
            limit=limit,
            include_authorized=True,
        )

    def unauthorized_peripherals(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self._query_peripheral_aggregate(
            where_clause="is_authorized = 0",
            limit=limit,
            include_authorized=False,
        )

    def _query_peripheral_aggregate(
        self,
        *,
        where_clause: str,
        limit: int,
        include_authorized: bool,
    ) -> List[Dict[str, Any]]:
        if not self.available:
            return []
        authorized_col = ", is_authorized" if include_authorized else ""
        with self._read_conn() as conn:
            rows = conn.execute(
                f"""
                SELECT
                    peripheral_device_id,
                    device_name,
                    device_type,
                    vendor_id,
                    product_id,
                    manufacturer,
                    MAX(risk_score) AS max_risk_score
                    {authorized_col},
                    COUNT(*) AS event_count,
                    MAX(timestamp_dt) AS last_seen
                FROM peripheral_events
                WHERE {where_clause}
                GROUP BY peripheral_device_id
                ORDER BY max_risk_score DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def peripheral_device_history(self, device_id: str) -> List[Dict[str, Any]]:
        if not self.available:
            return []
        with self._read_conn() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM peripheral_events
                WHERE peripheral_device_id = ?
                ORDER BY timestamp_ns DESC
                """,
                (device_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def search_peripherals(
        self,
        *,
        name: str = "",
        device_type: str = "",
        manufacturer: str = "",
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        if not self.available:
            return []
        query = "SELECT * FROM peripheral_events WHERE 1=1"
        params: List[Any] = []
        if name:
            query += " AND device_name LIKE ? ESCAPE '\\'"
            params.append(f"%{_escape_like(name)}%")
        if device_type:
            query += " AND device_type = ?"
            params.append(device_type)
        if manufacturer:
            query += " AND manufacturer LIKE ? ESCAPE '\\'"
            params.append(f"%{_escape_like(manufacturer)}%")
        query += " ORDER BY timestamp_ns DESC LIMIT ?"
        params.append(limit)
        with self._read_conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]


def get_dashboard_query_service() -> DashboardQueryService:
    """Construct query service backed by TelemetryStore singleton."""
    return DashboardQueryService(get_telemetry_store())
