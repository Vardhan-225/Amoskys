"""
IGRIS Auditor — Data Integrity Verification

Verifies the organism isn't lying to itself.
Checks WAL chain integrity, dead letter classification, schema consistency,
and evidence chain health. Read-only. Deterministic. Evidence-backed.

Called by MetricCollector each observation cycle to produce integrity.* metrics.
"""

import logging
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("igris.auditor")

# Resolve project root from this file's location (src/amoskys/igris/auditor.py)
_PROJECT_ROOT = str(Path(__file__).resolve().parents[3])


def _data_path(*parts: str) -> str:
    return os.path.join(_PROJECT_ROOT, "data", *parts)


# Dead letter error categories — matches WAL processor quarantine reasons
DEAD_LETTER_CATEGORIES = (
    "BLAKE2b checksum mismatch",
    "hash chain signature mismatch",
    "invalid checksum size",
)

# Expected schema migration count
EXPECTED_SCHEMA_VERSION = 6


class Auditor:
    """Integrity auditor for AMOSKYS data pipeline.

    All methods are read-only SQL queries. Never modifies any database.
    Returns None for any metric that cannot be collected (DB missing, etc).
    """

    def __init__(
        self,
        telemetry_db: str | None = None,
        wal_db: str | None = None,
        evidence_db: str | None = None,
    ):
        self._telemetry_db = telemetry_db or _data_path("telemetry.db")
        self._wal_db = wal_db or _data_path("wal", "flowagent.db")
        self._evidence_db = evidence_db or _data_path("intel", "evidence_chain.db")

    def collect(self, metrics: dict[str, Any]) -> None:
        """Collect all integrity metrics into the metrics dict.

        Called by MetricCollector._collect_integrity() each cycle.
        """
        self._check_dead_letter(metrics)
        self._check_wal_chain_health(metrics)
        self._check_schema_consistency(metrics)
        self._check_evidence_chain(metrics)
        self._check_enrichment_effectiveness(metrics)

    # ── Dead Letter Classification ─────────────────────────────

    def _check_dead_letter(self, m: dict) -> None:
        """Classify dead letter entries by error type."""
        try:
            if not os.path.exists(self._telemetry_db):
                self._set_dead_letter_defaults(m, None)
                return

            conn = self._ro_connect(self._telemetry_db)
            if not conn:
                self._set_dead_letter_defaults(m, None)
                return

            now = int(time.time())
            hour_ago_iso = time.strftime(
                "%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(now - 3600)
            )

            # Total dead letter count
            row = conn.execute("SELECT COUNT(*) FROM wal_dead_letter").fetchone()
            m["integrity.dead_letter_total"] = row[0] if row else 0

            # Count by error category
            for category in DEAD_LETTER_CATEGORIES:
                key = category.replace(" ", "_").lower()
                row = conn.execute(
                    "SELECT COUNT(*) FROM wal_dead_letter WHERE error_msg = ?",
                    (category,),
                ).fetchone()
                m[f"integrity.dl_{key}"] = row[0] if row else 0

            # Dead letters in last hour (recent integrity failures)
            row = conn.execute(
                "SELECT COUNT(*) FROM wal_dead_letter WHERE quarantined_at > ?",
                (hour_ago_iso,),
            ).fetchone()
            m["integrity.dead_letter_last_hour"] = row[0] if row else 0

            conn.close()
        except Exception as e:
            logger.debug("Dead letter audit failed: %s", e)
            self._set_dead_letter_defaults(m, None)

    def _set_dead_letter_defaults(self, m: dict, val: Any) -> None:
        m["integrity.dead_letter_total"] = val
        m["integrity.dead_letter_last_hour"] = val
        for category in DEAD_LETTER_CATEGORIES:
            key = category.replace(" ", "_").lower()
            m[f"integrity.dl_{key}"] = val

    # ── WAL Chain Health ───────────────────────────────────────

    def _check_wal_chain_health(self, m: dict) -> None:
        """Check WAL queue for chain column presence and pending depth."""
        try:
            if not os.path.exists(self._wal_db):
                m["integrity.wal_has_chain_columns"] = None
                m["integrity.wal_pending_count"] = None
                return

            conn = self._ro_connect(self._wal_db)
            if not conn:
                m["integrity.wal_has_chain_columns"] = None
                m["integrity.wal_pending_count"] = None
                return

            # Check chain columns exist
            cols = {row[1] for row in conn.execute("PRAGMA table_info(wal)").fetchall()}
            has_chain = "sig" in cols and "prev_sig" in cols
            m["integrity.wal_has_chain_columns"] = has_chain

            # Pending count (should match transport.wal_queue_depth)
            row = conn.execute("SELECT COUNT(*) FROM wal").fetchone()
            m["integrity.wal_pending_count"] = row[0] if row else 0

            conn.close()
        except Exception as e:
            logger.debug("WAL chain health check failed: %s", e)
            m["integrity.wal_has_chain_columns"] = None
            m["integrity.wal_pending_count"] = None

    # ── Schema Consistency ─────────────────────────────────────

    def _check_schema_consistency(self, m: dict) -> None:
        """Verify schema migrations are complete and consistent."""
        try:
            if not os.path.exists(self._telemetry_db):
                m["integrity.schema_version"] = None
                m["integrity.schema_complete"] = None
                return

            conn = self._ro_connect(self._telemetry_db)
            if not conn:
                m["integrity.schema_version"] = None
                m["integrity.schema_complete"] = None
                return

            # Current max version
            row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
            current_version = row[0] if row else 0
            m["integrity.schema_version"] = current_version

            # All expected versions present?
            row = conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()
            migration_count = row[0] if row else 0
            m["integrity.schema_complete"] = (
                current_version >= EXPECTED_SCHEMA_VERSION
                and migration_count >= EXPECTED_SCHEMA_VERSION
            )

            conn.close()
        except Exception as e:
            logger.debug("Schema consistency check failed: %s", e)
            m["integrity.schema_version"] = None
            m["integrity.schema_complete"] = None

    # ── Evidence Chain Health ──────────────────────────────────

    def _check_evidence_chain(self, m: dict) -> None:
        """Check evidence chain database health."""
        try:
            if not os.path.exists(self._evidence_db):
                m["integrity.evidence_chain_exists"] = False
                m["integrity.evidence_records"] = 0
                return

            conn = self._ro_connect(self._evidence_db)
            if not conn:
                m["integrity.evidence_chain_exists"] = False
                m["integrity.evidence_records"] = 0
                return

            m["integrity.evidence_chain_exists"] = True

            # Total records
            row = conn.execute("SELECT COUNT(*) FROM evidence_chain").fetchone()
            m["integrity.evidence_records"] = row[0] if row else 0

            conn.close()
        except Exception as e:
            logger.debug("Evidence chain check failed: %s", e)
            m["integrity.evidence_chain_exists"] = None
            m["integrity.evidence_records"] = None

    # ── Enrichment Effectiveness ──────────────────────────────

    def _check_enrichment_effectiveness(self, m: dict) -> None:
        """Track enrichment pipeline data flow into security_events."""
        try:
            if not os.path.exists(self._telemetry_db):
                m["integrity.enrichment_raw_count"] = None
                m["integrity.enrichment_enriched_count"] = None
                return

            conn = self._ro_connect(self._telemetry_db)
            if not conn:
                m["integrity.enrichment_raw_count"] = None
                m["integrity.enrichment_enriched_count"] = None
                return

            # Count events by enrichment status
            for status in ("raw", "enriched", "partial"):
                row = conn.execute(
                    "SELECT COUNT(*) FROM security_events WHERE enrichment_status = ?",
                    (status,),
                ).fetchone()
                m[f"integrity.enrichment_{status}_count"] = row[0] if row else 0

            # NULL = pre-backfill events (migration not yet applied)
            row = conn.execute(
                "SELECT COUNT(*) FROM security_events WHERE enrichment_status IS NULL",
            ).fetchone()
            m["integrity.enrichment_null_count"] = row[0] if row else 0

            conn.close()
        except Exception as e:
            logger.debug("Enrichment effectiveness check failed: %s", e)
            m["integrity.enrichment_raw_count"] = None
            m["integrity.enrichment_enriched_count"] = None

    # ── SQL Helper ─────────────────────────────────────────────

    def _ro_connect(self, db_path: str) -> Optional[sqlite3.Connection]:
        """Open a read-only SQLite connection."""
        try:
            conn = sqlite3.connect(db_path, timeout=5, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA query_only=ON")
            return conn
        except sqlite3.Error as e:
            logger.debug("Cannot open %s: %s", db_path, e)
            return None
