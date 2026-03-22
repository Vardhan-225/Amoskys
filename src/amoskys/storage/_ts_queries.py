"""General query methods mixin for TelemetryStore."""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger("TelemetryStore")


class QueryMixin:
    """Query methods for cross-domain and security event tables."""

    def get_recent_processes(
        self, limit: int = 100, device_id: Optional[str] = None
    ) -> list[dict[str, Any]]:
        """Get recent process events

        Args:
            limit: Maximum number of events to return
            device_id: Filter by device ID (optional)

        Returns:
            List of process event dictionaries
        """
        if device_id:
            query = """
                SELECT * FROM process_events
                WHERE device_id = ?
                ORDER BY timestamp_ns DESC
                LIMIT ?
            """
            cursor = self.db.execute(query, (device_id, limit))
        else:
            query = """
                SELECT * FROM process_events
                ORDER BY timestamp_ns DESC
                LIMIT ?
            """
            cursor = self.db.execute(query, (limit,))

        return [dict(row) for row in cursor.fetchall()]

    def get_statistics(self) -> dict[str, Any]:
        """Get database statistics

        Returns:
            Dictionary with table counts and time ranges
        """
        stats = {}

        with self._lock:
            cursor = self.db.execute("SELECT COUNT(*) FROM process_events")
            stats["process_events_count"] = cursor.fetchone()[0]

            cursor = self.db.execute("SELECT COUNT(*) FROM device_telemetry")
            stats["device_telemetry_count"] = cursor.fetchone()[0]

            cursor = self.db.execute("SELECT COUNT(*) FROM flow_events")
            stats["flow_events_count"] = cursor.fetchone()[0]

            cursor = self.db.execute("SELECT COUNT(*) FROM security_events")
            stats["security_events_count"] = cursor.fetchone()[0]

            for tbl in (
                "dns_events",
                "audit_events",
                "persistence_events",
                "fim_events",
                "peripheral_events",
            ):
                try:
                    cursor = self.db.execute(f"SELECT COUNT(*) FROM {tbl}")
                    stats[f"{tbl}_count"] = cursor.fetchone()[0]
                except sqlite3.Error:
                    stats[f"{tbl}_count"] = 0

            cursor = self.db.execute(
                """
                SELECT
                    MIN(timestamp_dt) as oldest,
                    MAX(timestamp_dt) as newest
                FROM process_events
            """
            )
            row = cursor.fetchone()
            stats["time_range"] = {"oldest": row[0], "newest": row[1]}

        return stats

    def get_recent_security_events(
        self,
        limit: int = 50,
        hours: int = 24,
        severity: Optional[str] = None,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Query security_events with time window and optional filter."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        params: list = [cutoff_ns]
        query = "SELECT * FROM security_events WHERE timestamp_ns > ?"

        if severity:
            query += " AND final_classification = ?"
            params.append(severity)

        query += " ORDER BY timestamp_ns DESC LIMIT ? OFFSET ?"
        params.append(limit)
        params.append(offset)

        with self._lock:
            try:
                cursor = self.db.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]
            except sqlite3.Error as e:
                logger.error("Failed to query security events: %s", e)
                return []

    def get_unified_threat_events(
        self,
        limit: int = 50,
        hours: int = 24,
        offset: int = 0,
        min_risk: float = 0.0,
    ) -> List[Dict[str, Any]]:
        """Query all domain tables via UNION ALL for a unified threat view."""
        # 10s cache for identical params (dashboard polls every 5-15s)
        cache_key = f"unified_threats:{hours}:{limit}:{offset}:{min_risk}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        risk_clause = f"AND risk_score > {min_risk}" if min_risk > 0 else ""
        risk_clause_anom = f"AND anomaly_score > {min_risk}" if min_risk > 0 else ""
        risk_clause_threat = f"AND threat_score > {min_risk}" if min_risk > 0 else ""
        sub_limit = limit + offset
        query = f"""
            SELECT * FROM (
            SELECT id, 'security' as source, event_category as type,
                   description, risk_score, confidence,
                   timestamp_ns, timestamp_dt, mitre_techniques, indicators,
                   collection_agent, device_id, final_classification,
                   requires_investigation, event_action
            FROM security_events WHERE timestamp_ns > ? {risk_clause}
            ORDER BY timestamp_ns DESC LIMIT {sub_limit}
            ) UNION ALL SELECT * FROM (
            SELECT id, 'persistence', event_type, reason, risk_score,
                   confidence, timestamp_ns, timestamp_dt, mitre_techniques,
                   NULL, collection_agent, device_id, NULL, 1, change_type
            FROM persistence_events WHERE timestamp_ns > ? {risk_clause}
            ORDER BY timestamp_ns DESC LIMIT {sub_limit}
            ) UNION ALL SELECT * FROM (
            SELECT id, 'process', process_category, exe, anomaly_score,
                   confidence_score, timestamp_ns, timestamp_dt, NULL,
                   NULL, collection_agent, device_id, NULL,
                   CAST(is_suspicious AS INT), NULL
            FROM process_events WHERE timestamp_ns > ? {risk_clause_anom}
            ORDER BY timestamp_ns DESC LIMIT {sub_limit}
            ) UNION ALL SELECT * FROM (
            SELECT id, 'fim', event_type, reason, risk_score,
                   confidence, timestamp_ns, timestamp_dt, mitre_techniques,
                   NULL, collection_agent, device_id, NULL, 0, change_type
            FROM fim_events WHERE timestamp_ns > ? {risk_clause}
            ORDER BY timestamp_ns DESC LIMIT {sub_limit}
            ) UNION ALL SELECT * FROM (
            SELECT id, 'flow', protocol,
                   'Flow: ' || COALESCE(src_ip,'?') || ':' || COALESCE(src_port,0)
                   || ' -> ' || COALESCE(dst_ip,'?') || ':' || COALESCE(dst_port,0),
                   threat_score, 0.5, timestamp_ns, timestamp_dt, NULL,
                   NULL, NULL, device_id, NULL,
                   CAST(is_suspicious AS INT), NULL
            FROM flow_events WHERE timestamp_ns > ? {risk_clause_threat}
            ORDER BY timestamp_ns DESC LIMIT {sub_limit}
            ) UNION ALL SELECT * FROM (
            SELECT id, 'dns', event_type, 'DNS: ' || domain, risk_score,
                   confidence, timestamp_ns, timestamp_dt, mitre_techniques,
                   NULL, collection_agent, device_id, NULL, 0, NULL
            FROM dns_events WHERE timestamp_ns > ? {risk_clause}
            ORDER BY timestamp_ns DESC LIMIT {sub_limit}
            ) UNION ALL SELECT * FROM (
            SELECT id, 'audit', event_type, reason, risk_score,
                   confidence, timestamp_ns, timestamp_dt, mitre_techniques,
                   NULL, collection_agent, device_id, NULL, 0, NULL
            FROM audit_events WHERE timestamp_ns > ? {risk_clause}
            ORDER BY timestamp_ns DESC LIMIT {sub_limit}
            )
            ORDER BY timestamp_ns DESC LIMIT ? OFFSET ?
        """
        params = [cutoff_ns] * 7 + [limit, offset]
        with self._read_pool.connection() as rdb:
            try:
                cursor = rdb.execute(query, params)
                cols = [d[0] for d in cursor.description]
                rows = [dict(zip(cols, row)) for row in cursor.fetchall()]
                self._cache.put(cache_key, rows, ttl=10)
                return rows
            except sqlite3.Error as e:
                logger.error("Failed unified threat query: %s", e)
                return []

    def get_threat_count(self, hours: int = 24, min_risk: float = 0.1) -> int:
        """Fast count of events exceeding min_risk across scored tables."""
        cache_key = f"threat_count:{hours}:{min_risk}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        query = """
            SELECT SUM(cnt) FROM (
                SELECT COUNT(*) as cnt FROM security_events
                    WHERE timestamp_ns > ? AND risk_score > ?
                UNION ALL
                SELECT COUNT(*) FROM persistence_events
                    WHERE timestamp_ns > ? AND risk_score > ?
                UNION ALL
                SELECT COUNT(*) FROM process_events
                    WHERE timestamp_ns > ? AND anomaly_score > ?
                UNION ALL
                SELECT COUNT(*) FROM fim_events
                    WHERE timestamp_ns > ? AND risk_score > ?
                UNION ALL
                SELECT COUNT(*) FROM flow_events
                    WHERE timestamp_ns > ? AND threat_score > ?
                UNION ALL
                SELECT COUNT(*) FROM dns_events
                    WHERE timestamp_ns > ? AND risk_score > ?
                UNION ALL
                SELECT COUNT(*) FROM audit_events
                    WHERE timestamp_ns > ? AND risk_score > ?
            )
        """
        with self._read_pool.connection() as rdb:
            try:
                row = rdb.execute(query, (cutoff_ns, min_risk) * 7).fetchone()
                count = row[0] or 0 if row else 0
                self._cache.put(cache_key, count, ttl=30)
                return count
            except sqlite3.Error:
                return 0

    def get_unified_event_counts(self, hours: int = 24) -> Dict[str, Any]:
        """Aggregate event counts across all domain tables."""
        cache_key = f"unified_counts:{hours}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        tables = {
            "security_events": "event_category",
            "persistence_events": "event_type",
            "process_events": "process_category",
            "fim_events": "event_type",
            "flow_events": "protocol",
            "dns_events": "event_type",
            "audit_events": "event_type",
            "peripheral_events": "event_type",
        }
        count_only_tables = ["observation_events"]
        result: Dict[str, Any] = {"total": 0, "by_source": {}, "by_category": {}}
        with self._read_pool.connection() as rdb:
            for table, cat_col in tables.items():
                try:
                    row = rdb.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE timestamp_ns > ?",
                        (cutoff_ns,),
                    ).fetchone()
                    count = row[0] if row else 0
                    result["by_source"][table.replace("_events", "")] = count
                    result["total"] += count

                    cats = rdb.execute(
                        f"SELECT {cat_col}, COUNT(*) FROM {table} "
                        f"WHERE timestamp_ns > ? GROUP BY {cat_col}",
                        (cutoff_ns,),
                    ).fetchall()
                    for cat_row in cats:
                        if cat_row[0]:
                            result["by_category"][cat_row[0]] = (
                                result["by_category"].get(cat_row[0], 0) + cat_row[1]
                            )
                except sqlite3.Error:
                    continue
            for table in count_only_tables:
                try:
                    row = rdb.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE timestamp_ns > ?",
                        (cutoff_ns,),
                    ).fetchone()
                    count = row[0] if row else 0
                    result["by_source"][table.replace("_events", "")] = count
                    result["total"] += count
                except sqlite3.Error:
                    continue
        self._cache.put(cache_key, result, ttl=30)
        return result

    def get_security_event_counts(self, hours: int = 24) -> Dict[str, Any]:
        """Aggregate counts by category and classification."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        result: Dict[str, Any] = {
            "total": 0,
            "by_category": {},
            "by_classification": {},
        }

        with self._lock:
            try:
                cursor = self.db.execute(
                    "SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ?",
                    (cutoff_ns,),
                )
                result["total"] = cursor.fetchone()[0]

                cursor = self.db.execute(
                    """SELECT event_category, COUNT(*) as cnt
                       FROM security_events WHERE timestamp_ns > ?
                       GROUP BY event_category""",
                    (cutoff_ns,),
                )
                for row in cursor.fetchall():
                    if row[0]:
                        result["by_category"][row[0]] = row[1]

                cursor = self.db.execute(
                    """SELECT final_classification, COUNT(*) as cnt
                       FROM security_events WHERE timestamp_ns > ?
                       GROUP BY final_classification""",
                    (cutoff_ns,),
                )
                for row in cursor.fetchall():
                    if row[0]:
                        result["by_classification"][row[0]] = row[1]

            except sqlite3.Error as e:
                logger.error("Failed to count security events: %s", e)

        return result

    def get_threat_score_data(self, hours: int = 1) -> Dict[str, Any]:
        """Calculate threat score across ALL domain tables."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)

        try:
            query = """
                SELECT COUNT(*) as cnt,
                       COALESCE(AVG(rs), 0) as avg_risk,
                       COALESCE(MAX(rs), 0) as max_risk,
                       COALESCE(SUM(CASE WHEN rs > 0.7 THEN 1 ELSE 0 END), 0) as critical_count
                FROM (
                    SELECT risk_score as rs FROM security_events WHERE timestamp_ns > ?
                    UNION ALL
                    SELECT risk_score FROM persistence_events WHERE timestamp_ns > ?
                    UNION ALL
                    SELECT anomaly_score FROM process_events WHERE timestamp_ns > ?
                    UNION ALL
                    SELECT risk_score FROM fim_events WHERE timestamp_ns > ?
                    UNION ALL
                    SELECT threat_score FROM flow_events WHERE timestamp_ns > ?
                    UNION ALL
                    SELECT risk_score FROM dns_events WHERE timestamp_ns > ?
                )
            """
            with self._lock:
                cursor = self.db.execute(query, (cutoff_ns,) * 6)
                row = cursor.fetchone()
            cnt = row[0]
            avg_risk = row[1]
            max_risk = row[2]
            critical_count = row[3]

            if cnt == 0:
                score = 0.0
            else:
                score = min(
                    100.0,
                    (avg_risk * 50) + (critical_count * 10) + (max_risk * 20),
                )

            if score >= 75:
                level = "critical"
            elif score >= 50:
                level = "high"
            elif score >= 25:
                level = "medium"
            elif score > 0:
                level = "low"
            else:
                level = "none"

            return {
                "threat_score": round(score, 1),
                "threat_level": level,
                "event_count": cnt,
                "avg_risk": round(avg_risk, 3),
                "max_risk": round(max_risk, 3),
                "critical_count": critical_count,
            }

        except sqlite3.Error as e:
            logger.error("Failed to calculate threat score: %s", e)
            return {
                "threat_score": 0,
                "threat_level": "none",
                "event_count": 0,
            }

    def get_security_event_clustering(self, hours: int = 24) -> Dict[str, Any]:
        """Cluster security events by category/severity/hour."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        result: Dict[str, Any] = {
            "by_category": {},
            "by_severity": {"low": 0, "medium": 0, "high": 0, "critical": 0},
            "by_hour": {},
        }

        with self._lock:
            try:
                cursor = self.db.execute(
                    """SELECT event_category, COUNT(*) as cnt
                       FROM security_events WHERE timestamp_ns > ?
                       GROUP BY event_category ORDER BY cnt DESC""",
                    (cutoff_ns,),
                )
                for row in cursor.fetchall():
                    if row[0]:
                        result["by_category"][row[0]] = row[1]

                cursor = self.db.execute(
                    """SELECT
                           SUM(CASE WHEN risk_score < 0.25 THEN 1 ELSE 0 END) as low_cnt,
                           SUM(CASE WHEN risk_score >= 0.25 AND risk_score < 0.5 THEN 1 ELSE 0 END) as med_cnt,
                           SUM(CASE WHEN risk_score >= 0.5 AND risk_score < 0.75 THEN 1 ELSE 0 END) as high_cnt,
                           SUM(CASE WHEN risk_score >= 0.75 THEN 1 ELSE 0 END) as crit_cnt
                       FROM security_events WHERE timestamp_ns > ?""",
                    (cutoff_ns,),
                )
                row = cursor.fetchone()
                if row:
                    result["by_severity"] = {
                        "low": row[0] or 0,
                        "medium": row[1] or 0,
                        "high": row[2] or 0,
                        "critical": row[3] or 0,
                    }

                cursor = self.db.execute(
                    """SELECT SUBSTR(timestamp_dt, 12, 2) as hour, COUNT(*) as cnt
                       FROM security_events WHERE timestamp_ns > ?
                       GROUP BY hour ORDER BY hour""",
                    (cutoff_ns,),
                )
                for row in cursor.fetchall():
                    if row[0]:
                        result["by_hour"][row[0]] = row[1]

            except sqlite3.Error as e:
                logger.error("Failed to cluster security events: %s", e)

        return result

    def get_unified_event_clustering(self, hours: int = 24) -> Dict[str, Any]:
        """Cluster events across ALL domain tables by severity, agent, and hour."""
        cache_key = f"unified_clustering:{hours}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        result: Dict[str, Any] = {
            "by_severity": {"low": 0, "medium": 0, "high": 0, "critical": 0},
            "by_agent": {},
            "by_hour": {},
            "by_source": {},
        }

        sev_query = """
            SELECT
                SUM(CASE WHEN rs < 0.25 THEN 1 ELSE 0 END),
                SUM(CASE WHEN rs >= 0.25 AND rs < 0.5 THEN 1 ELSE 0 END),
                SUM(CASE WHEN rs >= 0.5 AND rs < 0.75 THEN 1 ELSE 0 END),
                SUM(CASE WHEN rs >= 0.75 THEN 1 ELSE 0 END)
            FROM (
                SELECT risk_score as rs FROM security_events WHERE timestamp_ns > ?
                UNION ALL
                SELECT risk_score FROM persistence_events WHERE timestamp_ns > ?
                UNION ALL
                SELECT anomaly_score FROM process_events WHERE timestamp_ns > ?
                UNION ALL
                SELECT risk_score FROM fim_events WHERE timestamp_ns > ?
                UNION ALL
                SELECT threat_score FROM flow_events WHERE timestamp_ns > ?
                UNION ALL
                SELECT risk_score FROM dns_events WHERE timestamp_ns > ?
            )
        """
        hour_query = """
            SELECT hr, SUM(cnt) FROM (
                SELECT SUBSTR(timestamp_dt, 12, 2) as hr, COUNT(*) as cnt
                FROM security_events WHERE timestamp_ns > ? GROUP BY hr
                UNION ALL
                SELECT SUBSTR(timestamp_dt, 12, 2), COUNT(*)
                FROM persistence_events WHERE timestamp_ns > ? GROUP BY 1
                UNION ALL
                SELECT SUBSTR(timestamp_dt, 12, 2), COUNT(*)
                FROM process_events WHERE timestamp_ns > ? GROUP BY 1
                UNION ALL
                SELECT SUBSTR(timestamp_dt, 12, 2), COUNT(*)
                FROM fim_events WHERE timestamp_ns > ? GROUP BY 1
                UNION ALL
                SELECT SUBSTR(timestamp_dt, 12, 2), COUNT(*)
                FROM flow_events WHERE timestamp_ns > ? GROUP BY 1
                UNION ALL
                SELECT SUBSTR(timestamp_dt, 12, 2), COUNT(*)
                FROM dns_events WHERE timestamp_ns > ? GROUP BY 1
            ) GROUP BY hr ORDER BY hr
        """

        with self._read_pool.connection() as rdb:
            try:
                row = rdb.execute(sev_query, (cutoff_ns,) * 6).fetchone()
                if row:
                    result["by_severity"] = {
                        "low": row[0] or 0,
                        "medium": row[1] or 0,
                        "high": row[2] or 0,
                        "critical": row[3] or 0,
                    }

                for hr_row in rdb.execute(hour_query, (cutoff_ns,) * 6).fetchall():
                    if hr_row[0]:
                        result["by_hour"][hr_row[0]] = hr_row[1]

                tables = {
                    "security": "security_events",
                    "persistence": "persistence_events",
                    "process": "process_events",
                    "fim": "fim_events",
                    "flow": "flow_events",
                    "dns": "dns_events",
                    "observation": "observation_events",
                    "audit": "audit_events",
                    "peripheral": "peripheral_events",
                }
                for label, table in tables.items():
                    cnt = rdb.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE timestamp_ns > ?",
                        (cutoff_ns,),
                    ).fetchone()[0]
                    result["by_source"][label] = cnt

                for table in [
                    "security_events",
                    "persistence_events",
                    "process_events",
                    "fim_events",
                    "dns_events",
                    "audit_events",
                ]:
                    rows = rdb.execute(
                        f"SELECT collection_agent, COUNT(*) FROM {table} "
                        f"WHERE timestamp_ns > ? AND collection_agent IS NOT NULL "
                        f"GROUP BY collection_agent",
                        (cutoff_ns,),
                    ).fetchall()
                    for r in rows:
                        if r[0]:
                            result["by_agent"][r[0]] = (
                                result["by_agent"].get(r[0], 0) + r[1]
                            )

            except sqlite3.Error as e:
                logger.error("Failed unified event clustering: %s", e)

        self._cache.put(cache_key, result, ttl=30)
        return result

    def search_events(
        self,
        query: str = "",
        table: str = "security_events",
        hours: int = 24,
        limit: int = 100,
        offset: int = 0,
        min_risk: Optional[float] = None,
        category: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Full-text search across event tables for threat hunting."""
        allowed_tables = {
            "security_events",
            "process_events",
            "flow_events",
            "peripheral_events",
            "dns_events",
            "audit_events",
            "persistence_events",
            "fim_events",
            "observation_events",
        }
        if table not in allowed_tables:
            table = "security_events"

        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        params: list = [cutoff_ns]
        where_clauses = ["timestamp_ns > ?"]

        if query:
            if table == "security_events":
                where_clauses.append(
                    "(description LIKE ? OR indicators LIKE ? OR event_category LIKE ?)"
                )
                q = f"%{query}%"
                params.extend([q, q, q])
            elif table == "process_events":
                where_clauses.append(
                    "(exe LIKE ? OR cmdline LIKE ? OR username LIKE ?)"
                )
                q = f"%{query}%"
                params.extend([q, q, q])
            elif table == "flow_events":
                where_clauses.append(
                    "(src_ip LIKE ? OR dst_ip LIKE ? OR protocol LIKE ?)"
                )
                q = f"%{query}%"
                params.extend([q, q, q])
            elif table == "peripheral_events":
                where_clauses.append(
                    "(device_name LIKE ? OR device_type LIKE ? OR manufacturer LIKE ?)"
                )
                q = f"%{query}%"
                params.extend([q, q, q])
            elif table == "dns_events":
                where_clauses.append(
                    "(domain LIKE ? OR event_type LIKE ? OR process_name LIKE ?)"
                )
                q = f"%{query}%"
                params.extend([q, q, q])
            elif table == "audit_events":
                where_clauses.append(
                    "(syscall LIKE ? OR exe LIKE ? OR comm LIKE ? OR reason LIKE ?)"
                )
                q = f"%{query}%"
                params.extend([q, q, q, q])
            elif table == "persistence_events":
                where_clauses.append(
                    "(mechanism LIKE ? OR path LIKE ? OR command LIKE ? OR reason LIKE ?)"
                )
                q = f"%{query}%"
                params.extend([q, q, q, q])
            elif table == "fim_events":
                where_clauses.append(
                    "(path LIKE ? OR event_type LIKE ? OR reason LIKE ?)"
                )
                q = f"%{query}%"
                params.extend([q, q, q])
            elif table == "observation_events":
                where_clauses.append("(attributes LIKE ? OR domain LIKE ?)")
                q = f"%{query}%"
                params.extend([q, q])

        if min_risk is not None and table in (
            "security_events",
            "peripheral_events",
            "dns_events",
            "audit_events",
            "persistence_events",
            "fim_events",
        ):
            where_clauses.append("risk_score >= ?")
            params.append(min_risk)

        if category and table == "security_events":
            where_clauses.append("event_category = ?")
            params.append(category)

        where_sql = " AND ".join(where_clauses)

        try:
            count_cursor = self.db.execute(
                f"SELECT COUNT(*) FROM {table} WHERE {where_sql}", params
            )
            total = count_cursor.fetchone()[0]

            fetch_params = params + [limit, offset]
            cursor = self.db.execute(
                f"SELECT * FROM {table} WHERE {where_sql} ORDER BY timestamp_ns DESC LIMIT ? OFFSET ?",
                fetch_params,
            )
            rows = [dict(r) for r in cursor.fetchall()]

            return {
                "results": rows,
                "total_count": total,
                "page_size": limit,
                "offset": offset,
                "has_more": (offset + limit) < total,
            }
        except sqlite3.Error as e:
            logger.error("Search failed: %s", e)
            return {
                "results": [],
                "total_count": 0,
                "page_size": limit,
                "offset": 0,
                "has_more": False,
            }

    def get_mitre_coverage(self) -> Dict[str, Any]:
        """Get MITRE ATT&CK technique coverage from security events."""
        try:
            cursor = self.db.execute(
                "SELECT mitre_techniques, event_category "
                "FROM security_events WHERE mitre_techniques IS NOT NULL"
            )
            coverage: Dict[str, Dict] = {}
            for row in cursor.fetchall():
                try:
                    techniques = json.loads(row[0]) if row[0] else []
                except (json.JSONDecodeError, TypeError):
                    continue
                if not isinstance(techniques, list):
                    continue
                cat = row[1] or "unknown"
                for tech in techniques:
                    if tech not in coverage:
                        coverage[tech] = {"count": 0, "categories": {}}
                    coverage[tech]["count"] += 1
                    coverage[tech]["categories"][cat] = (
                        coverage[tech]["categories"].get(cat, 0) + 1
                    )
            return coverage
        except sqlite3.Error as e:
            logger.error("Failed to get MITRE coverage: %s", e)
            return {}

    def get_cross_domain_timeline(
        self, hours: int = 24, limit: int = 200
    ) -> List[Dict]:
        """Unified timeline across ALL domain tables."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        query = """
            SELECT timestamp_ns, timestamp_dt, 'process' as domain, 'process' as event_type,
                   COALESCE(exe, '') as summary, COALESCE(anomaly_score, 0) as risk_score
            FROM process_events WHERE timestamp_ns > ?1
            UNION ALL
            SELECT timestamp_ns, timestamp_dt, 'network' as domain, 'flow' as event_type,
                   COALESCE(dst_ip || ':' || CAST(dst_port AS TEXT), '') as summary,
                   COALESCE(threat_score, 0) as risk_score
            FROM flow_events WHERE timestamp_ns > ?1
            UNION ALL
            SELECT timestamp_ns, timestamp_dt, 'dns' as domain, COALESCE(event_type, 'query'),
                   COALESCE(domain, ''), COALESCE(risk_score, 0)
            FROM dns_events WHERE timestamp_ns > ?1
            UNION ALL
            SELECT timestamp_ns, timestamp_dt, 'auth' as domain, COALESCE(event_type, 'audit'),
                   COALESCE(exe, ''), COALESCE(risk_score, 0)
            FROM audit_events WHERE timestamp_ns > ?1
            UNION ALL
            SELECT timestamp_ns, timestamp_dt, 'files' as domain, COALESCE(change_type, 'change'),
                   COALESCE(path, ''), COALESCE(risk_score, 0)
            FROM fim_events WHERE timestamp_ns > ?1
            UNION ALL
            SELECT timestamp_ns, timestamp_dt, 'persistence' as domain, COALESCE(mechanism, 'unknown'),
                   COALESCE(path, ''), COALESCE(risk_score, 0)
            FROM persistence_events WHERE timestamp_ns > ?1
            UNION ALL
            SELECT timestamp_ns, timestamp_dt, 'security' as domain, COALESCE(event_category, 'detection'),
                   COALESCE(description, ''), COALESCE(risk_score, 0)
            FROM security_events WHERE timestamp_ns > ?1
            ORDER BY timestamp_ns DESC LIMIT ?2
        """
        with self._lock:
            try:
                rows = self.db.execute(query, (cutoff_ns, limit)).fetchall()
                return [
                    {
                        "timestamp_ns": r[0],
                        "timestamp_dt": r[1],
                        "domain": r[2],
                        "event_type": r[3],
                        "summary": r[4],
                        "risk_score": r[5],
                    }
                    for r in rows
                ]
            except sqlite3.Error as e:
                logger.error("Cross-domain timeline failed: %s", e)
                return []

    def get_metrics_history(
        self, metric_name: str, hours: int = 24, device_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get historical metrics for time-series charts."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        try:
            if device_id:
                cursor = self.db.execute(
                    "SELECT * FROM metrics_timeseries WHERE metric_name = ? AND device_id = ? AND timestamp_ns > ? ORDER BY timestamp_ns",
                    (metric_name, device_id, cutoff_ns),
                )
            else:
                cursor = self.db.execute(
                    "SELECT * FROM metrics_timeseries WHERE metric_name = ? AND timestamp_ns > ? ORDER BY timestamp_ns",
                    (metric_name, cutoff_ns),
                )
            return [dict(r) for r in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error("Failed to get metrics history: %s", e)
            return []

    def get_rollup_event_counts(self, hours: int = 24) -> dict:
        """Read pre-computed event counts by domain from dashboard_rollups."""
        from amoskys.storage._ts_schema import _HOUR_FMT

        now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
        buckets = []
        for h in range(hours):
            dt = now - __import__("datetime").timedelta(hours=h)
            buckets.append(dt.strftime(_HOUR_FMT))
        placeholders = ",".join("?" for _ in buckets)

        result: dict = {}
        try:
            with self._read_pool.connection() as conn:
                rows = conn.execute(
                    f"SELECT bucket_key, SUM(value) FROM dashboard_rollups "
                    f"WHERE rollup_type='events_by_domain' "
                    f"AND bucket_hour IN ({placeholders}) "
                    f"GROUP BY bucket_key",
                    buckets,
                ).fetchall()
                for row in rows:
                    result[row[0]] = row[1]
        except Exception:
            logger.debug("Rollup event domain query failed", exc_info=True)
        return result

    def get_rollup_threat_severity(self, hours: int = 24) -> dict:
        """Read pre-computed threat counts by severity from dashboard_rollups."""
        from amoskys.storage._ts_schema import _HOUR_FMT

        now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
        buckets = []
        for h in range(hours):
            dt = now - __import__("datetime").timedelta(hours=h)
            buckets.append(dt.strftime(_HOUR_FMT))
        placeholders = ",".join("?" for _ in buckets)

        result: dict = {}
        try:
            with self._read_pool.connection() as conn:
                rows = conn.execute(
                    f"SELECT bucket_key, SUM(value) FROM dashboard_rollups "
                    f"WHERE rollup_type='threats_by_severity' "
                    f"AND bucket_hour IN ({placeholders}) "
                    f"GROUP BY bucket_key",
                    buckets,
                ).fetchall()
                for row in rows:
                    result[row[0]] = row[1]
        except Exception:
            logger.debug("Rollup threat severity query failed", exc_info=True)
        return result
