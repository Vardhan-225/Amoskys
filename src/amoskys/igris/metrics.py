"""
IGRIS Metric Collector

Polls all AMOSKYS subsystems every observation cycle.
Each metric collection is isolated — failure in one never blocks others.
Read-only. Modifies nothing.
"""

import json
import logging
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("igris.metrics")

# Resolve project root from this file's location (src/amoskys/igris/metrics.py)
_PROJECT_ROOT = str(Path(__file__).resolve().parents[3])


def _data_path(*parts: str) -> str:
    """Resolve a data path relative to the project root."""
    return os.path.join(_PROJECT_ROOT, "data", *parts)


class MetricCollector:
    """Collects metrics from all AMOSKYS subsystems via direct reads."""

    def __init__(
        self,
        telemetry_db: str | None = None,
        wal_db: str | None = None,
        fusion_db: str | None = None,
        evidence_db: str | None = None,
        reliability_db: str | None = None,
        model_dir: str | None = None,
    ):
        self._telemetry_db = telemetry_db or _data_path("telemetry.db")
        self._wal_db = wal_db or _data_path("wal", "flowagent.db")
        self._fusion_db = fusion_db or _data_path("intel", "fusion.db")
        self._evidence_db = evidence_db or _data_path("intel", "evidence_chain.db")
        self._reliability_db = reliability_db or _data_path("intel", "reliability.db")
        self._model_dir = model_dir or _data_path("intel", "models")
        self._cycle_count = 0
        self._cached_total_events: int | None = None

        # IGRIS Auditor — integrity verification subsystem
        from .auditor import Auditor

        self._auditor = Auditor(
            telemetry_db=self._telemetry_db,
            wal_db=self._wal_db,
            evidence_db=self._evidence_db,
        )

    def collect_all(self) -> dict[str, Any]:
        """Single pass: poll all subsystems, return flat metrics dict."""
        self._cycle_count += 1
        metrics: dict[str, Any] = {}

        # Collect each subsystem independently
        self._collect_fleet(metrics)
        self._collect_transport(metrics)
        self._collect_ingestion(metrics)
        self._collect_intelligence(metrics)
        self._collect_amrdr(metrics)
        self._collect_soma(metrics)
        self._collect_enrichment(metrics)
        self._collect_evidence(metrics)
        self._collect_integrity(metrics)

        return metrics

    # ── Fleet Health ──────────────────────────────────────────────

    def _collect_fleet(self, m: dict) -> None:
        """Agent fleet status via heartbeat files in data/heartbeats/."""
        try:
            hb_dir = Path(_PROJECT_ROOT) / "data" / "heartbeats"
            if not hb_dir.is_dir():
                m["fleet.total"] = 0
                m["fleet.healthy"] = 0
                m["fleet.offline"] = 0
                m["fleet.degraded"] = 0
                m["fleet.agents"] = {}
                return

            now = time.time()
            stale_threshold = 120  # seconds
            agents_info: dict[str, dict] = {}
            healthy = 0
            offline = 0
            total_errors = 0
            agents_with_errors = 0

            for hb_file in sorted(hb_dir.glob("*.json")):
                try:
                    with open(hb_file) as f:
                        hb = json.load(f)
                    agent_id = hb.get("agent_name", hb_file.stem)
                    ts_raw = hb.get("timestamp", 0)
                    # Heartbeats may store ISO-8601 or epoch float
                    if isinstance(ts_raw, str):
                        from datetime import datetime, timezone

                        dt = datetime.fromisoformat(ts_raw)
                        ts = dt.timestamp()
                    else:
                        ts = float(ts_raw) if ts_raw else 0
                    age = now - ts if ts else float("inf")
                    status = "running" if age < stale_threshold else "offline"
                    if status == "running":
                        healthy += 1
                    else:
                        offline += 1

                    # Extract error metrics from heartbeat
                    error_count = hb.get("error_count", 0) or 0
                    last_error = hb.get("last_error") or hb.get("error")
                    hb_status = hb.get("status", "healthy")
                    if hb_status == "error":
                        error_count = max(error_count, 1)
                    total_errors += error_count
                    if error_count > 0:
                        agents_with_errors += 1

                    agents_info[agent_id] = {
                        "status": status,
                        "pid": hb.get("pid"),
                        "cpu_percent": 0,
                        "memory_mb": 0,
                        "uptime_seconds": int(age) if age < float("inf") else 0,
                        "error_count": error_count,
                        "last_error": last_error,
                    }
                except (json.JSONDecodeError, OSError, KeyError):
                    continue

            m["fleet.total"] = len(agents_info)
            m["fleet.healthy"] = healthy
            m["fleet.offline"] = offline
            m["fleet.degraded"] = 0
            m["fleet.total_errors"] = total_errors
            m["fleet.agents_with_errors"] = agents_with_errors
            m["fleet.agents"] = agents_info
        except Exception as e:
            logger.debug("Fleet collection failed: %s", e)
            m["fleet.total"] = None
            m["fleet.healthy"] = None
            m["fleet.offline"] = None
            m["fleet.degraded"] = None
            m["fleet.agents"] = {}

    # ── Transport Health ──────────────────────────────────────────

    def _collect_transport(self, m: dict) -> None:
        """EventBus alive check + WAL queue metrics."""
        # EventBus port check — direct socket probe (no Flask dependency)
        try:
            import socket

            sock = socket.create_connection(("127.0.0.1", 50051), timeout=2)
            sock.close()
            m["transport.eventbus_alive"] = True
        except OSError:
            m["transport.eventbus_alive"] = False

        # WAL queue depth
        m["transport.wal_queue_depth"] = self._sql_scalar(
            self._wal_db, "SELECT COUNT(*) FROM wal"
        )

        # Dead letter queue
        m["transport.dead_letter_depth"] = self._sql_scalar(
            self._telemetry_db, "SELECT COUNT(*) FROM wal_dead_letter"
        )

        # WAL file size
        wal_file = self._wal_db + "-wal" if self._wal_db else None
        try:
            if wal_file and os.path.exists(wal_file):
                m["transport.wal_file_size_mb"] = round(
                    os.path.getsize(wal_file) / (1024 * 1024), 2
                )
            else:
                m["transport.wal_file_size_mb"] = 0
        except OSError:
            m["transport.wal_file_size_mb"] = None

    # ── Ingestion Health ──────────────────────────────────────────

    def _collect_ingestion(self, m: dict) -> None:
        """Event ingestion rates and freshness."""
        now_ns = int(time.time() * 1e9)
        hour_ns = now_ns - int(3600 * 1e9)
        five_min_ns = now_ns - int(300 * 1e9)

        m["ingestion.events_last_hour"] = self._sql_scalar(
            self._telemetry_db,
            "SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ?",
            (hour_ns,),
        )

        m["ingestion.events_last_5min"] = self._sql_scalar(
            self._telemetry_db,
            "SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ?",
            (five_min_ns,),
        )

        # Heavy total: only every 10 cycles to avoid unnecessary full-table scans
        if self._cycle_count % 10 == 1 or self._cached_total_events is None:
            self._cached_total_events = self._sql_scalar(
                self._telemetry_db, "SELECT COUNT(*) FROM security_events"
            )
        m["ingestion.total_events"] = self._cached_total_events

        # Freshness: seconds since most recent event
        max_ts = self._sql_scalar(
            self._telemetry_db,
            "SELECT MAX(timestamp_ns) FROM security_events",
        )
        if max_ts and max_ts > 0:
            m["ingestion.freshness_seconds"] = round((now_ns - max_ts) / 1e9, 1)
        else:
            m["ingestion.freshness_seconds"] = None

    # ── Intelligence Health ───────────────────────────────────────

    def _collect_intelligence(self, m: dict) -> None:
        """FusionEngine incident rates and risk scores."""
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)
        day_ago = (now - timedelta(hours=24)).isoformat()
        hour_ago = (now - timedelta(hours=1)).isoformat()

        m["intelligence.incidents_24h"] = self._sql_scalar(
            self._fusion_db,
            "SELECT COUNT(*) FROM incidents WHERE created_at > ?",
            (day_ago,),
        )

        m["intelligence.incidents_1h"] = self._sql_scalar(
            self._fusion_db,
            "SELECT COUNT(*) FROM incidents WHERE created_at > ?",
            (hour_ago,),
        )

        m["intelligence.device_risk_max"] = self._sql_scalar(
            self._fusion_db, "SELECT MAX(score) FROM device_risk"
        )

        m["intelligence.device_risk_avg"] = self._sql_scalar(
            self._fusion_db, "SELECT AVG(score) FROM device_risk"
        )
        if m["intelligence.device_risk_avg"] is not None:
            m["intelligence.device_risk_avg"] = round(
                m["intelligence.device_risk_avg"], 1
            )

    # ── AMRDR Reliability ─────────────────────────────────────────

    def _collect_amrdr(self, m: dict) -> None:
        """Agent reliability states from AMRDR store."""
        try:
            from amoskys.intel.reliability_store import ReliabilityStore

            store = ReliabilityStore(db_path=self._reliability_db)
            states = store.load_all_states()

            agent_data = {}
            min_weight = 1.0
            quarantined = 0
            drifting = 0

            for agent_id, state in states.items():
                w = getattr(state, "fusion_weight", 1.0)
                drift = getattr(state, "drift_type", "none")
                tier = getattr(state, "tier", "nominal")
                if hasattr(drift, "value"):
                    drift = drift.value
                if hasattr(tier, "value"):
                    tier = tier.value

                agent_data[agent_id] = {
                    "alpha": round(getattr(state, "alpha", 1.0), 3),
                    "beta": round(getattr(state, "beta", 1.0), 3),
                    "fusion_weight": round(w, 3),
                    "drift_type": str(drift),
                    "tier": str(tier),
                }
                min_weight = min(min_weight, w)
                if str(tier).lower() == "quarantine":
                    quarantined += 1
                if str(drift).lower() != "none":
                    drifting += 1

            m["amrdr.agents"] = agent_data
            m["amrdr.min_weight"] = round(min_weight, 3) if states else 1.0
            m["amrdr.quarantined_count"] = quarantined
            m["amrdr.drifting_count"] = drifting
        except Exception as e:
            logger.debug("AMRDR collection failed: %s", e)
            m["amrdr.agents"] = {}
            m["amrdr.min_weight"] = None
            m["amrdr.quarantined_count"] = None
            m["amrdr.drifting_count"] = None

    # ── SOMA Brain Health ─────────────────────────────────────────

    def _collect_soma(self, m: dict) -> None:
        """SOMA Brain training status and model freshness."""
        brain_metrics_path = os.path.join(self._model_dir, "brain_metrics.json")
        model_path = os.path.join(self._model_dir, "isolation_forest.joblib")

        # Read brain metrics
        try:
            if os.path.exists(brain_metrics_path):
                with open(brain_metrics_path) as f:
                    bm = json.load(f)
                m["soma.status"] = bm.get("status", "unknown")
                m["soma.training_count"] = bm.get("training_count", 0)
                m["soma.anomaly_rate"] = bm.get("anomaly_rate")
                m["soma.event_count"] = bm.get("event_count", 0)

                # Age since last training
                last_train = bm.get("last_train_time") or bm.get("timestamp")
                if last_train:
                    if isinstance(last_train, (int, float)):
                        age_hours = (time.time() - last_train) / 3600
                    else:
                        from datetime import datetime, timezone

                        dt = datetime.fromisoformat(str(last_train))
                        age_hours = (
                            datetime.now(timezone.utc) - dt
                        ).total_seconds() / 3600
                    m["soma.last_train_age_hours"] = round(age_hours, 2)
                else:
                    m["soma.last_train_age_hours"] = None
            else:
                m["soma.status"] = "no_metrics"
                m["soma.training_count"] = 0
                m["soma.anomaly_rate"] = None
                m["soma.event_count"] = 0
                m["soma.last_train_age_hours"] = None
        except Exception as e:
            logger.debug("SOMA metrics read failed: %s", e)
            m["soma.status"] = "error"
            m["soma.training_count"] = None
            m["soma.anomaly_rate"] = None
            m["soma.event_count"] = None
            m["soma.last_train_age_hours"] = None

        # Model file age
        try:
            if os.path.exists(model_path):
                mtime = os.path.getmtime(model_path)
                m["soma.model_age_hours"] = round((time.time() - mtime) / 3600, 2)
            else:
                m["soma.model_age_hours"] = None
        except OSError:
            m["soma.model_age_hours"] = None

    # ── Enrichment Health ─────────────────────────────────────────

    def _collect_enrichment(self, m: dict) -> None:
        """Enrichment pipeline availability."""
        try:
            from amoskys.enrichment import EnrichmentPipeline

            pipeline = EnrichmentPipeline()
            status = pipeline.status()

            available = 0
            for stage in ("geoip", "asn", "threat_intel", "mitre"):
                is_avail = status.get(stage, {}).get("available", False)
                m[f"enrichment.{stage}_available"] = is_avail
                if is_avail:
                    available += 1

            m["enrichment.available_count"] = available
        except Exception as e:
            logger.debug("Enrichment collection failed: %s", e)
            for stage in ("geoip", "asn", "threat_intel", "mitre"):
                m[f"enrichment.{stage}_available"] = None
            m["enrichment.available_count"] = None

    # ── Integrity (via Auditor) ───────────────────────────────────

    def _collect_integrity(self, m: dict) -> None:
        """Data integrity checks via IGRIS Auditor."""
        try:
            self._auditor.collect(m)
        except Exception as e:
            logger.debug("Integrity collection failed: %s", e)

    # ── Evidence Chain Health ─────────────────────────────────────

    def _collect_evidence(self, m: dict) -> None:
        """Evidence chain record count."""
        m["evidence.total_records"] = self._sql_scalar(
            self._evidence_db, "SELECT COUNT(*) FROM evidence_chain"
        )

    # ── SQL Helper ────────────────────────────────────────────────

    def _sql_scalar(
        self,
        db_path: str,
        query: str,
        params: tuple = (),
    ) -> Optional[Any]:
        """Execute a read-only SQL query and return the scalar result."""
        if not db_path or not os.path.exists(db_path):
            return None
        try:
            conn = sqlite3.connect(db_path, timeout=5, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA query_only=ON")
            cursor = conn.execute(query, params)
            row = cursor.fetchone()
            conn.close()
            return row[0] if row else None
        except (sqlite3.Error, OSError) as e:
            logger.debug("SQL query failed on %s: %s", db_path, e)
            return None
