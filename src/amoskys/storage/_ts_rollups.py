"""Rollup computation mixin for TelemetryStore."""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Dict

from amoskys.storage._ts_schema import _HOUR_FMT

logger = logging.getLogger("TelemetryStore")


class RollupMixin:
    """Prewarm loop, hourly rollup writes, observation rollups, backfill."""

    # ── Cache Prewarm ──

    def _prewarm_loop(self) -> None:
        """Background thread that refreshes caches + writes dashboard rollups."""
        time.sleep(2)
        _keys = [
            ("device_posture:24", lambda: self.get_device_posture(hours=24)),
            ("nerve_posture:24", lambda: self.compute_nerve_posture(hours=24)),
            (
                "observation_domain_stats:24",
                lambda: self.get_observation_domain_stats(hours=24),
            ),
            ("fim_stats:24", lambda: self.get_fim_stats(hours=24)),
            ("persistence_stats:24", lambda: self.get_persistence_stats(hours=24)),
            ("flow_stats:24", lambda: self.get_flow_stats(hours=24)),
            (
                "unified_clustering:24",
                lambda: self.get_unified_event_clustering(hours=24),
            ),
            ("unified_counts:24", lambda: self.get_unified_event_counts(hours=24)),
            (
                "threat_count:24:0.1",
                lambda: self.get_threat_count(hours=24, min_risk=0.1),
            ),
        ]
        _optimize_counter = 0
        _amrdr_counter = 0
        while True:
            try:
                for cache_key, fn in _keys:
                    self._cache.invalidate(cache_key)
                    fn()
                try:
                    self._write_hourly_rollups()
                except Exception:
                    logger.debug("Hourly rollup write failed", exc_info=True)
                try:
                    self.evaluate_auto_signals()
                except Exception:
                    logger.debug("Auto-signal evaluation failed", exc_info=True)
                _amrdr_counter += 1
                if _amrdr_counter >= 5:
                    try:
                        self._update_agent_trust()
                    except Exception:
                        logger.debug("AMRDR trust update failed", exc_info=True)
                    _amrdr_counter = 0
                _optimize_counter += 1
                if _optimize_counter >= 24:
                    self.db.execute("PRAGMA optimize")
                    _optimize_counter = 0
            except Exception:
                logger.debug("Prewarm cycle failed, will retry", exc_info=True)
            time.sleep(20)

    def _write_hourly_rollups(self) -> None:
        """Compute and upsert hourly rollups into dashboard_rollups."""
        now_ns = int(time.time() * 1e9)
        now_dt = datetime.now(timezone.utc)
        bucket_hour = now_dt.strftime(_HOUR_FMT)
        hour_start_ns = int(
            now_dt.replace(minute=0, second=0, microsecond=0).timestamp() * 1e9
        )

        _domain_tables = [
            ("security", "security_events"),
            ("process", "process_events"),
            ("flow", "flow_events"),
            ("dns", "dns_events"),
            ("audit", "audit_events"),
            ("fim", "fim_events"),
            ("persistence", "persistence_events"),
            ("peripheral", "peripheral_events"),
            ("observation", "observation_events"),
        ]
        with self._read_pool.connection() as conn:
            for domain, table in _domain_tables:
                try:
                    row = conn.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE timestamp_ns >= ?",
                        (hour_start_ns,),
                    ).fetchone()
                    count = row[0] if row else 0
                    self.db.execute(
                        "INSERT INTO dashboard_rollups "
                        "(rollup_type, bucket_key, bucket_hour, value, updated_ns) "
                        "VALUES ('events_by_domain', ?, ?, ?, ?) "
                        "ON CONFLICT(rollup_type, bucket_key, bucket_hour) DO UPDATE SET "
                        "value=excluded.value, updated_ns=excluded.updated_ns",
                        (domain, bucket_hour, count, now_ns),
                    )
                except Exception:
                    logger.debug("Rollup query failed for %s", domain, exc_info=True)

            risk_col_map = {
                "security_events": "risk_score",
                "flow_events": "threat_score",
                "dns_events": "risk_score",
                "fim_events": "risk_score",
                "persistence_events": "risk_score",
                "process_events": "anomaly_score",
            }
            severity_counts: dict = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for table, col in risk_col_map.items():
                try:
                    row = conn.execute(
                        f"""SELECT
                            SUM(CASE WHEN {col} >= 0.8 THEN 1 ELSE 0 END),
                            SUM(CASE WHEN {col} >= 0.5 AND {col} < 0.8 THEN 1 ELSE 0 END),
                            SUM(CASE WHEN {col} >= 0.3 AND {col} < 0.5 THEN 1 ELSE 0 END),
                            SUM(CASE WHEN {col} > 0 AND {col} < 0.3 THEN 1 ELSE 0 END)
                        FROM {table} WHERE timestamp_ns >= ?""",
                        (hour_start_ns,),
                    ).fetchone()
                    if row:
                        severity_counts["critical"] += row[0] or 0
                        severity_counts["high"] += row[1] or 0
                        severity_counts["medium"] += row[2] or 0
                        severity_counts["low"] += row[3] or 0
                except Exception:
                    logger.debug(
                        "Severity rollup query failed for %s", table, exc_info=True
                    )

            for sev, cnt in severity_counts.items():
                self.db.execute(
                    "INSERT INTO dashboard_rollups "
                    "(rollup_type, bucket_key, bucket_hour, value, updated_ns) "
                    "VALUES ('threats_by_severity', ?, ?, ?, ?) "
                    "ON CONFLICT(rollup_type, bucket_key, bucket_hour) DO UPDATE SET "
                    "value=excluded.value, updated_ns=excluded.updated_ns",
                    (sev, bucket_hour, cnt, now_ns),
                )

        try:
            posture = self.compute_nerve_posture(hours=24)
            self.db.execute(
                "INSERT INTO dashboard_rollups "
                "(rollup_type, bucket_key, bucket_hour, value, updated_ns) "
                "VALUES ('posture_snapshot', 'score', ?, ?, ?) "
                "ON CONFLICT(rollup_type, bucket_key, bucket_hour) DO UPDATE SET "
                "value=excluded.value, updated_ns=excluded.updated_ns",
                (bucket_hour, int(posture["posture_score"] * 10), now_ns),
            )
        except Exception:
            logger.debug("Posture snapshot rollup failed", exc_info=True)

        try:
            self._write_observation_rollups(hour_start_ns, now_ns, bucket_hour)
        except Exception:
            logger.debug("Observation rollup write failed", exc_info=True)

        self.db.commit()

    # ── Observation Rollup Configuration ──────────────────────────────────
    _OBSERVATION_RAW_RETENTION_HOURS = 2
    _ROLLUP_DOMAINS = frozenset(
        {
            "unified_log",
            "applog",
            "infostealer",
            "quarantine",
            "provenance",
            "discovery",
            "internet_activity",
            "db_activity",
            "http",
            "security_monitor",
        }
    )

    @staticmethod
    def _observation_fingerprint(domain: str, attrs_json: str) -> str:
        """Generate a stable fingerprint from observation attributes."""
        import hashlib
        import re

        try:
            attrs = (
                json.loads(attrs_json) if isinstance(attrs_json, str) else attrs_json
            )
        except (json.JSONDecodeError, TypeError):
            attrs = {}

        _SKIP_KEYS = {
            "quality_state",
            "contract_violation_code",
            "missing_fields",
            "training_exclude",
            "_domain",
        }

        _VARIABLE_KEYS = {
            "pid",
            "process_guid",
            "timestamp",
            "file_path",
            "source_ip",
            "dest_ip",
            "port",
        }

        parts = [domain]
        for key in sorted(attrs.keys()):
            if key in _SKIP_KEYS:
                continue
            if key in _VARIABLE_KEYS:
                parts.append(f"{key}=<VAR>")
                continue
            val = str(attrs[key])
            template = re.sub(
                r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
                "<UUID>",
                val,
            )
            template = re.sub(r"[0-9a-fA-F]{16,}", "<HEX>", template)
            template = re.sub(r"\b\d+\b", "<N>", template)
            parts.append(f"{key}={template}")

        fingerprint_input = "|".join(parts)
        return hashlib.md5(
            fingerprint_input.encode(), usedforsecurity=False
        ).hexdigest()

    def _write_observation_rollups(
        self, hour_start_ns: int, now_ns: int, bucket_hour: str
    ) -> None:
        """Roll up observation_events for the current hour into fingerprinted buckets."""
        with self._read_pool.connection() as rdb:
            try:
                rows = rdb.execute(
                    """SELECT id, timestamp_ns, domain, attributes,
                              device_id, collection_agent
                       FROM observation_events
                       WHERE timestamp_ns >= ? AND timestamp_ns < ?
                       ORDER BY domain, timestamp_ns""",
                    (hour_start_ns, hour_start_ns + int(3600 * 1e9)),
                ).fetchall()
            except sqlite3.Error:
                return

        if not rows:
            return

        buckets: Dict[tuple, dict] = {}
        for row in rows:
            _id, ts_ns, domain, attrs_json, device_id, agent = row
            if domain not in self._ROLLUP_DOMAINS:
                continue

            fp = self._observation_fingerprint(domain, attrs_json)
            key = (domain, fp)

            if key not in buckets:
                buckets[key] = {
                    "count": 0,
                    "first_seen_ns": ts_ns,
                    "last_seen_ns": ts_ns,
                    "sample_attributes": attrs_json,
                    "device_id": device_id,
                    "collection_agent": agent,
                }
            bucket = buckets[key]
            bucket["count"] += 1
            bucket["last_seen_ns"] = max(bucket["last_seen_ns"], ts_ns)

        for (domain, fp), bucket in buckets.items():
            self.upsert_observation_rollup(
                {
                    "window_start_ns": hour_start_ns,
                    "window_end_ns": now_ns,
                    "domain": domain,
                    "fingerprint": fp,
                    "sample_attributes": (
                        json.loads(bucket["sample_attributes"])
                        if isinstance(bucket["sample_attributes"], str)
                        else bucket["sample_attributes"]
                    ),
                    "total_count": bucket["count"],
                    "first_seen_ns": bucket["first_seen_ns"],
                    "last_seen_ns": bucket["last_seen_ns"],
                    "device_id": bucket["device_id"],
                    "collection_agent": bucket["collection_agent"],
                }
            )

        retention_cutoff_ns = int(
            (time.time() - self._OBSERVATION_RAW_RETENTION_HOURS * 3600) * 1e9
        )
        try:
            has_active_incidents = False
            try:
                row = self.db.execute(
                    "SELECT COUNT(*) FROM incidents WHERE status IN ('open','investigating','contained')"
                ).fetchone()
                has_active_incidents = (row[0] or 0) > 0
            except sqlite3.Error:
                pass

            if not has_active_incidents:
                pruned = self.db.execute(
                    """DELETE FROM observation_events
                       WHERE timestamp_ns < ? AND domain IN ({})""".format(
                        ",".join(f"'{d}'" for d in self._ROLLUP_DOMAINS)
                    ),
                    (retention_cutoff_ns,),
                ).rowcount
                if pruned:
                    logger.debug("Pruned %d old observation rows", pruned)
        except sqlite3.Error:
            pass

    def backfill_rollups(self, hours: int = 72) -> int:
        """Backfill dashboard_rollups for the last N hours of historical data."""
        now = datetime.now(timezone.utc)
        now_ns = int(time.time() * 1e9)
        total = 0

        _domain_tables = [
            ("security", "security_events"),
            ("process", "process_events"),
            ("flow", "flow_events"),
            ("dns", "dns_events"),
            ("audit", "audit_events"),
            ("fim", "fim_events"),
            ("persistence", "persistence_events"),
            ("peripheral", "peripheral_events"),
            ("observation", "observation_events"),
        ]

        for h in range(hours):
            hour_dt = now - timedelta(hours=h)
            bucket_hour = hour_dt.strftime(_HOUR_FMT)
            hour_start = hour_dt.replace(minute=0, second=0, microsecond=0)
            hour_end = hour_start + timedelta(hours=1)
            start_ns = int(hour_start.timestamp() * 1e9)
            end_ns = int(hour_end.timestamp() * 1e9)

            for domain, table in _domain_tables:
                try:
                    row = self.db.execute(
                        f"SELECT COUNT(*) FROM {table} "
                        f"WHERE timestamp_ns >= ? AND timestamp_ns < ?",
                        (start_ns, end_ns),
                    ).fetchone()
                    count = row[0] if row else 0
                    if count > 0:
                        self.db.execute(
                            "INSERT OR REPLACE INTO dashboard_rollups "
                            "(rollup_type, bucket_key, bucket_hour, value, updated_ns) "
                            "VALUES ('events_by_domain', ?, ?, ?, ?)",
                            (domain, bucket_hour, count, now_ns),
                        )
                        total += 1
                except Exception:
                    logger.debug("Backfill query failed for %s", domain, exc_info=True)

        self.db.commit()
        logger.info("Backfilled %d rollup entries for %d hours", total, hours)
        return total
