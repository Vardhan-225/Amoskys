"""Posture computation mixin for TelemetryStore."""

from __future__ import annotations

import logging
import math
import sqlite3
import time
from typing import Any, Dict

logger = logging.getLogger("TelemetryStore")


class PostureMixin:
    """Device posture and Nerve Signal posture engine methods."""

    @staticmethod
    def _risk_to_status(risk: float, count: int) -> str:
        """Map risk score + count to a status label."""
        if risk > 0.7:
            return "critical"
        if risk > 0.3:
            return "warning"
        return "healthy" if count > 0 else "inactive"

    @staticmethod
    def _risk_to_threat_level(risk: float) -> str:
        """Map max risk score to threat level."""
        if risk > 0.7:
            return "critical"
        if risk > 0.3:
            return "elevated"
        return "clear"

    def _query_domain_posture(self, table: str, risk_col: str, cutoff_ns: int) -> Dict:
        """Query a single domain table for posture stats. Caller holds self._lock."""
        try:
            row = self.db.execute(
                f"SELECT COUNT(*), MAX(timestamp_ns), COALESCE(MAX({risk_col}), 0), "
                f"COALESCE(AVG({risk_col}), 0) "
                f"FROM {table} WHERE timestamp_ns > ?",
                (cutoff_ns,),
            ).fetchone()
            count = row[0] or 0
            domain_max = row[2] or 0.0
            return {
                "count": count,
                "latest_ns": row[1] or 0,
                "max_risk": round(domain_max, 3),
                "avg_risk": round(row[3] or 0, 3),
                "status": self._risk_to_status(domain_max, count),
            }
        except sqlite3.Error:
            return {
                "count": 0,
                "latest_ns": 0,
                "max_risk": 0,
                "avg_risk": 0,
                "status": "inactive",
            }

    def get_device_posture(self, hours: int = 24) -> Dict[str, Any]:
        """Cross-domain device health summary."""
        cache_key = f"device_posture:{hours}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        cutoff_ns = int((time.time() - hours * 3600) * 1e9)

        # Domain table volumes (observation counts from raw collector data)
        volume_query = """
            SELECT 'process' as label, COUNT(*), MAX(timestamp_ns)
            FROM process_events WHERE timestamp_ns > ?1
            UNION ALL
            SELECT 'network', COUNT(*), MAX(timestamp_ns)
            FROM flow_events WHERE timestamp_ns > ?1
            UNION ALL
            SELECT 'dns', COUNT(*), MAX(timestamp_ns)
            FROM dns_events WHERE timestamp_ns > ?1
            UNION ALL
            SELECT 'auth', COUNT(*), MAX(timestamp_ns)
            FROM audit_events WHERE timestamp_ns > ?1
            UNION ALL
            SELECT 'files', COUNT(*), MAX(timestamp_ns)
            FROM fim_events WHERE timestamp_ns > ?1
            UNION ALL
            SELECT 'persistence', COUNT(*), MAX(timestamp_ns)
            FROM persistence_events WHERE timestamp_ns > ?1
            UNION ALL
            SELECT 'peripherals', COUNT(*), MAX(timestamp_ns)
            FROM peripheral_events WHERE timestamp_ns > ?1
            UNION ALL
            SELECT 'observations', COUNT(*), MAX(timestamp_ns)
            FROM observation_events WHERE timestamp_ns > ?1
            UNION ALL
            SELECT '_security_count', COUNT(*), 0
            FROM security_events WHERE timestamp_ns > ?1
        """

        # Risk scores from security_events (probes detect threats, not observations).
        # Query per agent, then map to domains in Python — avoids SQLite CASE+GROUP BY
        # quirk in WAL read-only connections.
        _AGENT_TO_DOMAIN = {
            "macos_process": "process",
            "macos_realtime_sensor": "process",
            "macos_network": "network",
            "network_sentinel": "network",
            "macos_dns": "dns",
            "macos_auth": "auth",
            "macos_unified_log": "auth",
            "macos_filesystem": "files",
            "macos_quarantine_guard": "files",
            "macos_persistence": "persistence",
            "macos_peripheral": "peripherals",
            "macos_infostealer_guard": "observations",
            "macos_provenance": "observations",
            "macos_internet_activity": "observations",
            "macos_discovery": "observations",
        }
        risk_query = """
            SELECT collection_agent,
                   COALESCE(MAX(risk_score), 0),
                   COALESCE(AVG(risk_score), 0)
            FROM security_events
            WHERE timestamp_ns > ?1
            GROUP BY collection_agent
        """
        result: Dict[str, Any] = {
            "domains": {},
            "total_events": 0,
            "threat_level": "clear",
        }
        max_risk = 0.0
        # Per-domain risk from security_events (probe detections)
        domain_risks: Dict[str, Dict] = {}

        with self._read_pool.connection() as rdb:
            try:
                # 1. Get risk per agent, map to domains in Python
                risk_rows = rdb.execute(risk_query, (cutoff_ns,)).fetchall()
                for r in risk_rows:
                    agent = r[0] or ""
                    domain = _AGENT_TO_DOMAIN.get(agent, "observations")
                    agent_max = r[1] or 0.0
                    agent_avg = r[2] or 0.0
                    existing = domain_risks.get(domain, {"max_risk": 0.0, "avg_risk": 0.0})
                    domain_risks[domain] = {
                        "max_risk": round(max(existing["max_risk"], agent_max), 3),
                        "avg_risk": round(max(existing["avg_risk"], agent_avg), 3),
                    }

                # 2. Get volume counts from domain tables
                rows = rdb.execute(volume_query, (cutoff_ns,)).fetchall()
                for r in rows:
                    label, count, latest = r[0], r[1] or 0, r[2] or 0
                    if label == "_security_count":
                        result["security_detections"] = count
                        continue

                    # Merge risk from security_events with volume from domain table
                    risk_data = domain_risks.get(label, {})
                    domain_max = risk_data.get("max_risk", 0.0)
                    avg_risk = risk_data.get("avg_risk", 0.0)

                    result["domains"][label] = {
                        "count": count,
                        "latest_ns": latest,
                        "max_risk": domain_max,
                        "avg_risk": avg_risk,
                        "status": self._risk_to_status(domain_max, count),
                    }
                    result["total_events"] += count
                    max_risk = max(max_risk, domain_max)
            except sqlite3.Error as e:
                logger.error("Device posture query failed: %s", e)
                result["security_detections"] = 0
        result["threat_level"] = self._risk_to_threat_level(max_risk)
        result["posture_score"] = max(0, round(100 - (max_risk * 100), 1))
        self._cache.put(cache_key, result, ttl=30)
        return result

    # ── Nerve Signal Posture Engine (v1) ─────────────────────────────────────

    _POSTURE_HALF_LIFE_HOURS = 4.0
    _POSTURE_DECAY_LAMBDA = math.log(2) / _POSTURE_HALF_LIFE_HOURS
    _POSTURE_SAFE_HEAL_CAP = 0.5

    _POSTURE_LEVELS = [
        (80, "CLEAR"),
        (60, "ELEVATED"),
        (40, "GUARDED"),
        (20, "HIGH"),
        (0, "CRITICAL"),
    ]

    @staticmethod
    def _classify_signal(
        risk_score: float,
        threat_intel_match: bool,
        mitre_techniques: str,
        event_category: str,
    ) -> tuple[str, float]:
        """Classify a security event into PAMP, DANGER, or SAFE."""
        if threat_intel_match or risk_score >= 0.8:
            return ("PAMP", 1.0)
        if risk_score >= 0.3:
            return ("DANGER", 0.6)
        if risk_score > 0:
            return ("DANGER", 0.3)
        return ("SAFE", -0.3)

    def compute_nerve_posture(self, hours: int = 24) -> Dict[str, Any]:
        """Compute posture score using the Nerve Signal Model."""
        cache_key = f"nerve_posture:{hours}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        now_s = time.time()
        now_ns = int(now_s * 1e9)
        cutoff_ns = int((now_s - hours * 3600) * 1e9)

        sec_query = """
            SELECT timestamp_ns, risk_score, threat_intel_match,
                   mitre_techniques, event_category, collection_agent
            FROM security_events
            WHERE timestamp_ns > ?
            ORDER BY timestamp_ns DESC
        """
        signal_counts = {"PAMP": 0, "DANGER": 0, "SAFE": 0}
        danger_sum = 0.0
        safe_sum = 0.0

        with self._read_pool.connection() as rdb:
            try:
                rows = rdb.execute(sec_query, (cutoff_ns,)).fetchall()
            except sqlite3.Error:
                rows = []

        for row in rows:
            ts_ns = row[0] or now_ns
            risk = row[1] or 0.0
            ti_match = bool(row[2])
            mitre = row[3] or ""
            category = row[4] or ""

            sig_type, sig_weight = self._classify_signal(
                risk, ti_match, mitre, category
            )
            signal_counts[sig_type] += 1

            hours_ago = max(0, (now_ns - ts_ns) / 3.6e12)
            decay = math.exp(-self._POSTURE_DECAY_LAMBDA * hours_ago)

            contribution = abs(sig_weight) * risk * decay if sig_type != "SAFE" else 0
            if sig_type == "SAFE":
                safe_sum += abs(sig_weight) * decay * 0.1
            else:
                danger_sum += contribution

        domain_risk_query = """
            SELECT timestamp_ns, {risk_col}
            FROM {table}
            WHERE timestamp_ns > ? AND {risk_col} > 0
        """
        domain_risk_tables = [
            ("process_events", "anomaly_score"),
            ("flow_events", "threat_score"),
            ("dns_events", "risk_score"),
            ("fim_events", "risk_score"),
            ("persistence_events", "risk_score"),
            ("audit_events", "risk_score"),
        ]
        with self._read_pool.connection() as rdb:
            for table, risk_col in domain_risk_tables:
                try:
                    drows = rdb.execute(
                        domain_risk_query.format(risk_col=risk_col, table=table),
                        (cutoff_ns,),
                    ).fetchall()
                    for dr in drows:
                        ts_ns = dr[0] or now_ns
                        risk = dr[1] or 0.0
                        if risk > 0:
                            hours_ago = max(0, (now_ns - ts_ns) / 3.6e12)
                            decay = math.exp(-self._POSTURE_DECAY_LAMBDA * hours_ago)
                            danger_sum += 0.6 * risk * decay
                            signal_counts["DANGER"] += 1
                except sqlite3.Error:
                    pass

        max_healing = danger_sum * self._POSTURE_SAFE_HEAL_CAP
        effective_healing = min(safe_sum, max_healing)

        net_risk = max(0, danger_sum - effective_healing)
        total_risky = signal_counts["PAMP"] + signal_counts["DANGER"]
        if total_risky > 0:
            scale = math.sqrt(total_risky)
            normalized_risk = net_risk / scale
        else:
            normalized_risk = 0.0

        posture_score = round(100 * (1.0 - math.tanh(normalized_risk * 0.5)), 1)
        posture_score = max(0.0, min(100.0, posture_score))

        threat_level = "CRITICAL"
        for threshold, level in self._POSTURE_LEVELS:
            if posture_score >= threshold:
                threat_level = level
                break

        domain_posture = self.get_device_posture(hours)

        result = {
            "posture_score": posture_score,
            "threat_level": threat_level,
            "model": "nerve_signal_v1",
            "signal_breakdown": {
                "pamp_count": signal_counts["PAMP"],
                "danger_count": signal_counts["DANGER"],
                "safe_count": signal_counts["SAFE"],
                "raw_danger_sum": round(danger_sum, 4),
                "effective_healing": round(effective_healing, 4),
                "net_risk": round(net_risk, 4),
                "normalized_risk": round(normalized_risk, 4),
            },
            "decay": {
                "half_life_hours": self._POSTURE_HALF_LIFE_HOURS,
                "lambda": round(self._POSTURE_DECAY_LAMBDA, 6),
            },
            "domains": domain_posture.get("domains", {}),
            "total_events": domain_posture.get("total_events", 0),
            "security_detections": domain_posture.get("security_detections", 0),
        }

        self._cache.put(cache_key, result, ttl=30)
        return result
