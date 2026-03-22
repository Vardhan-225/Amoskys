"""Domain-specific query methods mixin for TelemetryStore."""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger("TelemetryStore")


class DomainQueryMixin:
    """Domain-specific query methods: DNS, Flow, FIM, Persistence, Audit, Observation."""

    # ── DNS Intelligence ──

    def get_dns_stats(self, hours: int = 24) -> Dict[str, Any]:
        """DNS query analytics."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._lock:
            try:
                row = self.db.execute(
                    """SELECT COUNT(*), COUNT(DISTINCT domain),
                       SUM(CASE WHEN dga_score > 0.7 THEN 1 ELSE 0 END),
                       SUM(CASE WHEN is_beaconing = 1 THEN 1 ELSE 0 END)
                    FROM dns_events WHERE timestamp_ns > ?""",
                    (cutoff_ns,),
                ).fetchone()
                qt_rows = self.db.execute(
                    "SELECT query_type, COUNT(*) FROM dns_events WHERE timestamp_ns > ? "
                    "GROUP BY query_type ORDER BY COUNT(*) DESC",
                    (cutoff_ns,),
                ).fetchall()
                rc_rows = self.db.execute(
                    "SELECT response_code, COUNT(*) FROM dns_events WHERE timestamp_ns > ? "
                    "GROUP BY response_code ORDER BY COUNT(*) DESC",
                    (cutoff_ns,),
                ).fetchall()
                return {
                    "total_queries": row[0] or 0,
                    "unique_domains": row[1] or 0,
                    "dga_suspects": row[2] or 0,
                    "beaconing_domains": row[3] or 0,
                    "by_query_type": {r[0]: r[1] for r in qt_rows if r[0]},
                    "by_response_code": {r[0]: r[1] for r in rc_rows if r[0]},
                }
            except sqlite3.Error as e:
                logger.error("DNS stats failed: %s", e)
                return {
                    "total_queries": 0,
                    "unique_domains": 0,
                    "dga_suspects": 0,
                    "beaconing_domains": 0,
                }

    def get_dns_top_domains(self, hours: int = 24, limit: int = 20) -> List[Dict]:
        """Top queried domains."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._lock:
            try:
                rows = self.db.execute(
                    """SELECT domain, COUNT(*) as cnt, query_type, process_name,
                       MAX(dga_score) as max_dga, MAX(CASE WHEN is_beaconing THEN 1 ELSE 0 END) as beacon
                    FROM dns_events WHERE timestamp_ns > ? AND domain IS NOT NULL
                    GROUP BY domain ORDER BY cnt DESC LIMIT ?""",
                    (cutoff_ns, limit),
                ).fetchall()
                return [
                    {
                        "domain": r[0],
                        "count": r[1],
                        "query_type": r[2],
                        "process_name": r[3],
                        "dga_score": r[4] or 0,
                        "is_beaconing": bool(r[5]),
                    }
                    for r in rows
                ]
            except sqlite3.Error as e:
                logger.error("DNS top domains failed: %s", e)
                return []

    def get_dns_dga_suspects(
        self, hours: int = 24, min_score: float = 0.5, limit: int = 50
    ) -> List[Dict]:
        """Domains with high DGA scores."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._lock:
            try:
                rows = self.db.execute(
                    """SELECT domain, dga_score, process_name, source_ip, timestamp_dt, query_type
                    FROM dns_events WHERE timestamp_ns > ? AND dga_score >= ?
                    ORDER BY dga_score DESC LIMIT ?""",
                    (cutoff_ns, min_score, limit),
                ).fetchall()
                return [
                    {
                        "domain": r[0],
                        "dga_score": r[1],
                        "process_name": r[2],
                        "source_ip": r[3],
                        "timestamp": r[4],
                        "query_type": r[5],
                    }
                    for r in rows
                ]
            except sqlite3.Error as e:
                logger.error("DNS DGA query failed: %s", e)
                return []

    def get_dns_beaconing(self, hours: int = 24, limit: int = 50) -> List[Dict]:
        """Domains exhibiting beaconing behavior."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._lock:
            try:
                rows = self.db.execute(
                    """SELECT domain, beacon_interval_seconds, COUNT(*) as cnt, process_name
                    FROM dns_events WHERE timestamp_ns > ? AND is_beaconing = 1
                    GROUP BY domain ORDER BY cnt DESC LIMIT ?""",
                    (cutoff_ns, limit),
                ).fetchall()
                return [
                    {
                        "domain": r[0],
                        "interval_seconds": r[1],
                        "query_count": r[2],
                        "process_name": r[3],
                    }
                    for r in rows
                ]
            except sqlite3.Error as e:
                logger.error("DNS beaconing query failed: %s", e)
                return []

    def get_dns_timeline(self, hours: int = 24) -> List[Dict]:
        """DNS query counts bucketed by time."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._lock:
            try:
                rows = self.db.execute(
                    """SELECT SUBSTR(timestamp_dt, 1, 13) as hour, COUNT(*) as cnt,
                       SUM(CASE WHEN dga_score > 0.5 THEN 1 ELSE 0 END) as suspicious
                    FROM dns_events WHERE timestamp_ns > ?
                    GROUP BY hour ORDER BY hour""",
                    (cutoff_ns,),
                ).fetchall()
                return [
                    {"hour": r[0], "count": r[1], "suspicious": r[2] or 0} for r in rows
                ]
            except sqlite3.Error as e:
                logger.error("DNS timeline failed: %s", e)
                return []

    # ── Network Intelligence ──

    def get_flow_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Network flow summary."""
        cache_key = f"flow_stats:{hours}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._read_pool.connection() as rdb:
            try:
                row = rdb.execute(
                    """SELECT COUNT(*), COUNT(DISTINCT dst_ip),
                       SUM(COALESCE(bytes_tx, 0)), SUM(COALESCE(bytes_rx, 0)),
                       COUNT(DISTINCT geo_dst_country),
                       SUM(CASE WHEN threat_intel_match = 1 THEN 1 ELSE 0 END),
                       SUM(CASE WHEN is_suspicious = 1 THEN 1 ELSE 0 END)
                    FROM flow_events WHERE timestamp_ns > ?""",
                    (cutoff_ns,),
                ).fetchone()
                proto_rows = rdb.execute(
                    "SELECT protocol, COUNT(*) FROM flow_events WHERE timestamp_ns > ? "
                    "GROUP BY protocol ORDER BY COUNT(*) DESC",
                    (cutoff_ns,),
                ).fetchall()
                result = {
                    "total_flows": row[0] or 0,
                    "unique_destinations": row[1] or 0,
                    "bytes_sent": row[2] or 0,
                    "bytes_received": row[3] or 0,
                    "countries_reached": row[4] or 0,
                    "threat_intel_hits": row[5] or 0,
                    "suspicious_flows": row[6] or 0,
                    "by_protocol": {r[0]: r[1] for r in proto_rows if r[0]},
                }
                self._cache.put(cache_key, result, ttl=30)
                return result
            except sqlite3.Error as e:
                logger.error("Flow stats failed: %s", e)
                return {"total_flows": 0}

    def get_flow_geo_stats(self, hours: int = 24) -> Dict[str, Any]:
        """GeoIP destination aggregation."""
        cache_key = f"flow_geo:{hours}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._read_pool.connection() as rdb:
            try:
                countries = rdb.execute(
                    "SELECT geo_dst_country, COUNT(*) as cnt, SUM(COALESCE(bytes_tx,0)+COALESCE(bytes_rx,0)) as total_bytes "
                    "FROM flow_events INDEXED BY idx_flow_geo_country_covering "
                    "WHERE timestamp_ns > ? AND geo_dst_country IS NOT NULL AND geo_dst_country != '' "
                    "GROUP BY geo_dst_country ORDER BY cnt DESC LIMIT 20",
                    (cutoff_ns,),
                ).fetchall()
                cities = rdb.execute(
                    "SELECT geo_dst_country, geo_dst_city, COUNT(*) as cnt "
                    "FROM flow_events INDEXED BY idx_flow_geo_city_covering "
                    "WHERE timestamp_ns > ? AND geo_dst_city IS NOT NULL AND geo_dst_city != '' "
                    "GROUP BY geo_dst_country, geo_dst_city ORDER BY cnt DESC LIMIT 20",
                    (cutoff_ns,),
                ).fetchall()
                result = {
                    "countries": [
                        {"country": r[0], "count": r[1], "bytes": r[2] or 0}
                        for r in countries
                    ],
                    "cities": [
                        {"country": r[0], "city": r[1], "count": r[2]} for r in cities
                    ],
                }
                self._cache.put(cache_key, result)
                return result
            except sqlite3.Error as e:
                logger.error("Flow geo stats failed: %s", e)
                return {"countries": [], "cities": []}

    def get_flow_asn_breakdown(self, hours: int = 24) -> List[Dict]:
        """Top destination ASN organizations."""
        cache_key = f"flow_asn:{hours}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._read_pool.connection() as rdb:
            try:
                rows = rdb.execute(
                    "SELECT asn_dst_org, asn_dst_network_type, COUNT(*) as cnt, "
                    "SUM(COALESCE(bytes_tx,0)+COALESCE(bytes_rx,0)) as total_bytes "
                    "FROM flow_events INDEXED BY idx_flow_asn_covering "
                    "WHERE timestamp_ns > ? AND asn_dst_org IS NOT NULL AND asn_dst_org != '' "
                    "GROUP BY asn_dst_org ORDER BY cnt DESC LIMIT 20",
                    (cutoff_ns,),
                ).fetchall()
                result = [
                    {
                        "org": r[0],
                        "network_type": r[1] or "unknown",
                        "count": r[2],
                        "bytes": r[3] or 0,
                    }
                    for r in rows
                ]
                self._cache.put(cache_key, result)
                return result
            except sqlite3.Error as e:
                logger.error("Flow ASN breakdown failed: %s", e)
                return []

    def get_flow_geo_points(self, hours: int = 24, limit: int = 500) -> List[Dict]:
        """Lat/lon points for world map visualization."""
        cache_key = f"flow_geopts:{hours}:{limit}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._read_pool.connection() as rdb:
            try:
                rows = rdb.execute(
                    "SELECT geo_dst_latitude, geo_dst_longitude, geo_dst_country, geo_dst_city, "
                    "COUNT(*) as cnt, SUM(COALESCE(bytes_tx,0)+COALESCE(bytes_rx,0)) as total_bytes, "
                    "asn_dst_org, MAX(CASE WHEN threat_intel_match=1 THEN 1 ELSE 0 END) as threat "
                    "FROM flow_events INDEXED BY idx_flow_geopoints_covering "
                    "WHERE timestamp_ns > ? "
                    "AND geo_dst_latitude IS NOT NULL AND geo_dst_latitude != 0 "
                    "GROUP BY geo_dst_latitude, geo_dst_longitude "
                    "ORDER BY cnt DESC LIMIT ?",
                    (cutoff_ns, limit),
                ).fetchall()
                result = [
                    {
                        "lat": r[0],
                        "lon": r[1],
                        "country": r[2],
                        "city": r[3],
                        "count": r[4],
                        "bytes": r[5] or 0,
                        "asn_org": r[6],
                        "threat": bool(r[7]),
                    }
                    for r in rows
                ]
                self._cache.put(cache_key, result)
                return result
            except sqlite3.Error as e:
                logger.error("Flow geo points failed: %s", e)
                return []

    def get_flow_top_destinations(self, hours: int = 24, limit: int = 20) -> List[Dict]:
        """Top destination IPs with enrichment."""
        cache_key = f"flow_topdst:{hours}:{limit}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._read_pool.connection() as rdb:
            try:
                rows = rdb.execute(
                    "SELECT dst_ip, dst_port, protocol, geo_dst_country, geo_dst_city, "
                    "asn_dst_org, asn_dst_network_type, "
                    "COUNT(*) as cnt, SUM(COALESCE(bytes_tx,0)) as tx, SUM(COALESCE(bytes_rx,0)) as rx, "
                    "MAX(CASE WHEN threat_intel_match=1 THEN 1 ELSE 0 END) as threat "
                    "FROM flow_events INDEXED BY idx_flow_topdst_covering "
                    "WHERE timestamp_ns > ? "
                    "GROUP BY dst_ip ORDER BY cnt DESC LIMIT ?",
                    (cutoff_ns, limit),
                ).fetchall()
                result = [
                    {
                        "dst_ip": r[0],
                        "dst_port": r[1],
                        "protocol": r[2],
                        "country": r[3],
                        "city": r[4],
                        "asn_org": r[5],
                        "network_type": r[6] or "unknown",
                        "flows": r[7],
                        "bytes_tx": r[8] or 0,
                        "bytes_rx": r[9] or 0,
                        "threat": bool(r[10]),
                    }
                    for r in rows
                ]
                self._cache.put(cache_key, result)
                return result
            except sqlite3.Error as e:
                logger.error("Flow top destinations failed: %s", e)
                return []

    def get_flow_by_process(self, hours: int = 24, limit: int = 20) -> List[Dict]:
        """Network usage grouped by process."""
        cache_key = f"flow_byproc:{hours}:{limit}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._read_pool.connection() as rdb:
            try:
                rows = rdb.execute(
                    "SELECT process_name, COUNT(*) as cnt, "
                    "SUM(COALESCE(bytes_tx,0)) as tx, SUM(COALESCE(bytes_rx,0)) as rx, "
                    "COUNT(DISTINCT dst_ip) as unique_dsts "
                    "FROM flow_events INDEXED BY idx_flow_byprocess_covering "
                    "WHERE timestamp_ns > ? AND process_name IS NOT NULL AND process_name != '' "
                    "GROUP BY process_name ORDER BY cnt DESC LIMIT ?",
                    (cutoff_ns, limit),
                ).fetchall()
                result = [
                    {
                        "process": r[0],
                        "flows": r[1],
                        "bytes_tx": r[2] or 0,
                        "bytes_rx": r[3] or 0,
                        "unique_destinations": r[4],
                    }
                    for r in rows
                ]
                self._cache.put(cache_key, result)
                return result
            except sqlite3.Error as e:
                logger.error("Flow by process failed: %s", e)
                return []

    # ── File Integrity ──

    def get_fim_stats(self, hours: int = 24) -> Dict[str, Any]:
        """File integrity monitoring summary."""
        cache_key = f"fim_stats:{hours}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._read_pool.connection() as rdb:
            try:
                row = rdb.execute(
                    """SELECT COUNT(*),
                       SUM(CASE WHEN change_type='created' THEN 1 ELSE 0 END),
                       SUM(CASE WHEN change_type='modified' THEN 1 ELSE 0 END),
                       SUM(CASE WHEN change_type='deleted' THEN 1 ELSE 0 END),
                       SUM(CASE WHEN risk_score > 0.3 THEN 1 ELSE 0 END)
                    FROM fim_events WHERE timestamp_ns > ?""",
                    (cutoff_ns,),
                ).fetchone()
                ext_rows = rdb.execute(
                    "SELECT file_extension, COUNT(*) FROM fim_events WHERE timestamp_ns > ? "
                    "AND file_extension IS NOT NULL GROUP BY file_extension ORDER BY COUNT(*) DESC LIMIT 15",
                    (cutoff_ns,),
                ).fetchall()
                result = {
                    "total_changes": row[0] or 0,
                    "created": row[1] or 0,
                    "modified": row[2] or 0,
                    "deleted": row[3] or 0,
                    "high_risk": row[4] or 0,
                    "by_extension": {r[0]: r[1] for r in ext_rows if r[0]},
                }
                self._cache.put(cache_key, result, ttl=30)
                return result
            except sqlite3.Error as e:
                logger.error("FIM stats failed: %s", e)
                return {"total_changes": 0}

    def get_fim_critical_changes(
        self, hours: int = 24, min_risk: float = 0.3, limit: int = 100
    ) -> List[Dict]:
        """High-risk file changes."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._lock:
            try:
                rows = self.db.execute(
                    """SELECT path, change_type, old_hash, new_hash, risk_score,
                       patterns_matched, file_extension, timestamp_dt, event_type
                    FROM fim_events WHERE timestamp_ns > ? AND risk_score >= ?
                    ORDER BY risk_score DESC LIMIT ?""",
                    (cutoff_ns, min_risk, limit),
                ).fetchall()
                return [
                    {
                        "path": r[0],
                        "change_type": r[1],
                        "old_hash": r[2],
                        "new_hash": r[3],
                        "risk_score": r[4] or 0,
                        "patterns_matched": r[5],
                        "extension": r[6],
                        "timestamp": r[7],
                        "event_type": r[8],
                    }
                    for r in rows
                ]
            except sqlite3.Error as e:
                logger.error("FIM critical changes failed: %s", e)
                return []

    def get_fim_directory_summary(self, hours: int = 24, limit: int = 50) -> List[Dict]:
        """File changes grouped by parent directory."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._lock:
            try:
                rows = self.db.execute(
                    """SELECT
                       CASE WHEN INSTR(path, '/') > 0
                            THEN SUBSTR(path, 1, LENGTH(path) - LENGTH(REPLACE(RTRIM(path, REPLACE(path, '/', '')), '', '')))
                            ELSE '/' END as dir,
                       COUNT(*) as cnt, ROUND(AVG(COALESCE(risk_score, 0)), 3) as avg_risk,
                       SUM(CASE WHEN risk_score > 0.3 THEN 1 ELSE 0 END) as risky
                    FROM fim_events WHERE timestamp_ns > ?
                    GROUP BY dir ORDER BY cnt DESC LIMIT ?""",
                    (cutoff_ns, limit),
                ).fetchall()
                return [
                    {
                        "directory": r[0],
                        "count": r[1],
                        "avg_risk": r[2],
                        "high_risk_count": r[3] or 0,
                    }
                    for r in rows
                ]
            except sqlite3.Error as e:
                logger.error("FIM directory summary failed: %s", e)
                return []

    def get_fim_timeline(self, hours: int = 24) -> List[Dict]:
        """Hourly FIM event counts by change type."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._lock:
            try:
                rows = self.db.execute(
                    """SELECT SUBSTR(timestamp_dt, 1, 13) as hour,
                       SUM(CASE WHEN change_type='created' THEN 1 ELSE 0 END) as created,
                       SUM(CASE WHEN change_type='modified' THEN 1 ELSE 0 END) as modified,
                       SUM(CASE WHEN change_type='deleted' THEN 1 ELSE 0 END) as deleted,
                       COUNT(*) as total
                    FROM fim_events WHERE timestamp_ns > ?
                    GROUP BY hour ORDER BY hour""",
                    (cutoff_ns,),
                ).fetchall()
                return [
                    {
                        "hour": r[0],
                        "created": r[1],
                        "modified": r[2],
                        "deleted": r[3],
                        "total": r[4],
                    }
                    for r in rows
                ]
            except sqlite3.Error as e:
                logger.error("FIM timeline failed: %s", e)
                return []

    # ── Persistence Landscape ──

    def get_persistence_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Persistence mechanism summary."""
        cache_key = f"persistence_stats:{hours}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._read_pool.connection() as rdb:
            try:
                row = rdb.execute(
                    "SELECT COUNT(*), SUM(CASE WHEN risk_score > 0.3 THEN 1 ELSE 0 END) "
                    "FROM persistence_events WHERE timestamp_ns > ?",
                    (cutoff_ns,),
                ).fetchone()
                mech_rows = rdb.execute(
                    "SELECT mechanism, COUNT(*) FROM persistence_events "
                    "INDEXED BY idx_persistence_mechanism_covering "
                    "WHERE timestamp_ns > ? "
                    "GROUP BY mechanism ORDER BY COUNT(*) DESC",
                    (cutoff_ns,),
                ).fetchall()
                ct_rows = rdb.execute(
                    "SELECT change_type, COUNT(*) FROM persistence_events "
                    "INDEXED BY idx_persistence_changetype_covering "
                    "WHERE timestamp_ns > ? "
                    "GROUP BY change_type ORDER BY COUNT(*) DESC",
                    (cutoff_ns,),
                ).fetchall()
                result = {
                    "total_entries": row[0] or 0,
                    "high_risk": row[1] or 0,
                    "by_mechanism": {r[0]: r[1] for r in mech_rows if r[0]},
                    "by_change_type": {r[0]: r[1] for r in ct_rows if r[0]},
                }
                self._cache.put(cache_key, result, ttl=30)
                return result
            except sqlite3.Error as e:
                logger.error("Persistence stats failed: %s", e)
                return {"total_entries": 0}

    def get_persistence_inventory(
        self, mechanism: Optional[str] = None, limit: int = 200
    ) -> List[Dict]:
        """Persistence entries, optionally filtered by mechanism."""
        with self._lock:
            try:
                if mechanism:
                    rows = self.db.execute(
                        """SELECT mechanism, entry_id, path, command, user, change_type,
                           risk_score, timestamp_dt, event_type
                        FROM persistence_events WHERE mechanism = ?
                        ORDER BY timestamp_ns DESC LIMIT ?""",
                        (mechanism, limit),
                    ).fetchall()
                else:
                    rows = self.db.execute(
                        """SELECT mechanism, entry_id, path, command, user, change_type,
                           risk_score, timestamp_dt, event_type
                        FROM persistence_events
                        ORDER BY timestamp_ns DESC LIMIT ?""",
                        (limit,),
                    ).fetchall()
                return [
                    {
                        "mechanism": r[0],
                        "entry_id": r[1],
                        "path": r[2],
                        "command": r[3],
                        "user": r[4],
                        "change_type": r[5],
                        "risk_score": r[6] or 0,
                        "timestamp": r[7],
                        "event_type": r[8],
                    }
                    for r in rows
                ]
            except sqlite3.Error as e:
                logger.error("Persistence inventory failed: %s", e)
                return []

    def get_persistence_changes(self, hours: int = 24) -> List[Dict]:
        """Recent persistence modifications."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._lock:
            try:
                rows = self.db.execute(
                    """SELECT SUBSTR(timestamp_dt, 1, 13) as hour, mechanism,
                       COUNT(*) as cnt
                    FROM persistence_events WHERE timestamp_ns > ?
                    GROUP BY hour, mechanism ORDER BY hour""",
                    (cutoff_ns,),
                ).fetchall()
                return [{"hour": r[0], "mechanism": r[1], "count": r[2]} for r in rows]
            except sqlite3.Error as e:
                logger.error("Persistence changes failed: %s", e)
                return []

    # ── Auth / Audit ──

    def get_audit_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Kernel audit / auth event summary."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._lock:
            try:
                row = self.db.execute(
                    "SELECT COUNT(*), SUM(CASE WHEN risk_score > 0.5 THEN 1 ELSE 0 END) "
                    "FROM audit_events WHERE timestamp_ns > ?",
                    (cutoff_ns,),
                ).fetchone()
                type_rows = self.db.execute(
                    "SELECT event_type, COUNT(*) FROM audit_events WHERE timestamp_ns > ? "
                    "GROUP BY event_type ORDER BY COUNT(*) DESC",
                    (cutoff_ns,),
                ).fetchall()
                return {
                    "total_events": row[0] or 0,
                    "high_risk": row[1] or 0,
                    "by_event_type": {r[0]: r[1] for r in type_rows if r[0]},
                }
            except sqlite3.Error as e:
                logger.error("Audit stats failed: %s", e)
                return {"total_events": 0}

    def get_audit_high_risk(
        self, hours: int = 24, min_risk: float = 0.5, limit: int = 100
    ) -> List[Dict]:
        """High-risk audit events."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._lock:
            try:
                rows = self.db.execute(
                    """SELECT event_type, exe, comm, cmdline, pid, uid, risk_score,
                       reason, mitre_techniques, timestamp_dt
                    FROM audit_events WHERE timestamp_ns > ? AND risk_score >= ?
                    ORDER BY risk_score DESC LIMIT ?""",
                    (cutoff_ns, min_risk, limit),
                ).fetchall()
                return [
                    {
                        "event_type": r[0],
                        "exe": r[1],
                        "comm": r[2],
                        "cmdline": r[3],
                        "pid": r[4],
                        "uid": r[5],
                        "risk_score": r[6] or 0,
                        "reason": r[7],
                        "mitre_techniques": r[8],
                        "timestamp": r[9],
                    }
                    for r in rows
                ]
            except sqlite3.Error as e:
                logger.error("Audit high risk failed: %s", e)
                return []

    # ── Observation Domains (P3) ──

    def get_observation_domain_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Per-domain counts for observation_events."""
        cache_key = f"observation_domain_stats:{hours}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._read_pool.connection() as rdb:
            try:
                rows = rdb.execute(
                    "SELECT domain, COUNT(*) FROM observation_events "
                    "INDEXED BY idx_observation_domain_ts_covering "
                    "WHERE timestamp_ns > ? "
                    "GROUP BY domain ORDER BY COUNT(*) DESC",
                    (cutoff_ns,),
                ).fetchall()
                total = sum(r[1] for r in rows)
                result = {
                    "total": total,
                    "by_domain": {r[0]: r[1] for r in rows if r[0]},
                }
                self._cache.put(cache_key, result, ttl=30)
                return result
            except sqlite3.Error as e:
                logger.error("Observation domain stats failed: %s", e)
                return {"total": 0, "by_domain": {}}

    def get_observations_by_domain(
        self, domain: str, hours: int = 24, limit: int = 100, offset: int = 0
    ) -> Dict[str, Any]:
        """Paginated observations for a specific domain."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._lock:
            try:
                total = self.db.execute(
                    "SELECT COUNT(*) FROM observation_events WHERE domain = ? AND timestamp_ns > ?",
                    (domain, cutoff_ns),
                ).fetchone()[0]
                rows = self.db.execute(
                    """SELECT timestamp_dt, domain, event_type, attributes, risk_score,
                       collection_agent
                    FROM observation_events WHERE domain = ? AND timestamp_ns > ?
                    ORDER BY timestamp_ns DESC LIMIT ? OFFSET ?""",
                    (domain, cutoff_ns, limit, offset),
                ).fetchall()
                results = []
                for r in rows:
                    attrs = {}
                    try:
                        attrs = json.loads(r[3]) if r[3] else {}
                    except (json.JSONDecodeError, TypeError):
                        attrs = {"raw": r[3]}
                    results.append(
                        {
                            "timestamp": r[0],
                            "domain": r[1],
                            "event_type": r[2],
                            "attributes": attrs,
                            "risk_score": r[4] or 0,
                            "collection_agent": r[5],
                        }
                    )
                return {
                    "results": results,
                    "total_count": total,
                    "offset": offset,
                    "has_more": (offset + limit) < total,
                }
            except sqlite3.Error as e:
                logger.error("Observations by domain failed: %s", e)
                return {"results": [], "total_count": 0, "offset": 0, "has_more": False}

    def search_observations(
        self,
        query: str = "",
        domain: Optional[str] = None,
        hours: int = 24,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Search across observation_events attributes."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        where = ["timestamp_ns > ?"]
        params: list = [cutoff_ns]
        if domain:
            where.append("domain = ?")
            params.append(domain)
        if query:
            where.append("attributes LIKE ?")
            params.append(f"%{query}%")
        where_sql = " AND ".join(where)
        with self._lock:
            try:
                total = self.db.execute(
                    f"SELECT COUNT(*) FROM observation_events WHERE {where_sql}", params
                ).fetchone()[0]
                rows = self.db.execute(
                    f"SELECT timestamp_dt, domain, event_type, attributes, risk_score, collection_agent "
                    f"FROM observation_events WHERE {where_sql} ORDER BY timestamp_ns DESC LIMIT ?",
                    params + [limit],
                ).fetchall()
                results = []
                for r in rows:
                    attrs = {}
                    try:
                        attrs = json.loads(r[3]) if r[3] else {}
                    except (json.JSONDecodeError, TypeError):
                        attrs = {"raw": r[3]}
                    results.append(
                        {
                            "timestamp": r[0],
                            "domain": r[1],
                            "event_type": r[2],
                            "attributes": attrs,
                            "risk_score": r[4] or 0,
                            "collection_agent": r[5],
                        }
                    )
                return {
                    "results": results,
                    "total_count": total,
                    "has_more": total > limit,
                }
            except sqlite3.Error as e:
                logger.error("Observation search failed: %s", e)
                return {"results": [], "total_count": 0, "has_more": False}
