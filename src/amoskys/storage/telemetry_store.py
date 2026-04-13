#!/usr/bin/env python3
"""
Permanent Telemetry Storage for AMOSKYS Dashboard

This module creates and manages the permanent telemetry database that stores
processed events from the WAL for dashboard queries and ML analysis.

Database Design:
- process_events: Individual process telemetry events
- device_telemetry: Aggregated device-level telemetry
- flow_events: Network flow events
- security_events: Security-relevant events for threat analysis

Supports the 3-layer ML architecture:
- Geometric features: Process trees, connection patterns
- Temporal features: Time series, event sequences
- Behavioral features: Anomaly scores, confidence metrics
"""

import logging
import sqlite3
import threading
from pathlib import Path

from amoskys.storage._ts_caching import _ReadPool, _TTLCache
from amoskys.storage._ts_domain_queries import DomainQueryMixin
from amoskys.storage._ts_inserts import InsertMixin
from amoskys.storage._ts_lifecycle import LifecycleMixin
from amoskys.storage._ts_posture import PostureMixin
from amoskys.storage._ts_queries import QueryMixin
from amoskys.storage._ts_rollups import RollupMixin
from amoskys.storage._ts_schema import SCHEMA, SchemaMixin
from amoskys.storage._ts_signals import SignalMixin

logger = logging.getLogger("TelemetryStore")


class TelemetryStore(
    SchemaMixin,
    InsertMixin,
    QueryMixin,
    DomainQueryMixin,
    PostureMixin,
    SignalMixin,
    RollupMixin,
    LifecycleMixin,
):
    """Permanent storage for processed telemetry data"""

    def __init__(self, db_path: str = "data/telemetry.db", readonly: bool = False):
        """Initialize telemetry store with schema

        Args:
            db_path: Path to SQLite database file
            readonly: If True, open in lightweight read-only mode.
                      Skips integrity check, schema creation, migrations,
                      and baselines.  Used by fleet_cache on the
                      presentation server where the sync thread owns writes.
        """
        self.db_path = db_path

        if readonly:
            # Lightweight init — fleet_cache / read-only dashboard mode
            self.db = sqlite3.connect(
                db_path, check_same_thread=False, timeout=5.0
            )
            self.db.row_factory = sqlite3.Row
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA query_only=ON")
            self.db.execute("PRAGMA temp_store=MEMORY")
            self.db.execute("PRAGMA mmap_size=268435456")
            self.db.execute("PRAGMA busy_timeout=5000")
            self._lock = threading.Lock()
            self._read_pool = _ReadPool(db_path, size=4)
            self._batch_mode = False
            self._batch_count = 0
            self._reliability = None
            self._cache = _TTLCache(ttl_seconds=5.0)
            logger.info("TelemetryStore READONLY at %s", db_path)
            return

        # Create parent directory
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

        # ── Boot integrity check: detect and recover corrupted DB ──
        if Path(db_path).exists():
            try:
                _check_db = sqlite3.connect(db_path, timeout=5.0)
                result = _check_db.execute("PRAGMA integrity_check(1)").fetchone()
                _check_db.close()
                if result[0] != "ok":
                    logger.error(
                        "DATABASE CORRUPTED: %s — %s. "
                        "Backing up and creating fresh DB.",
                        db_path, result[0],
                    )
                    import shutil
                    backup = f"{db_path}.corrupted.{int(time.time())}"
                    shutil.move(db_path, backup)
                    logger.info("Corrupted DB backed up to %s", backup)
                    # Remove WAL/SHM files too
                    for suffix in ("-wal", "-shm"):
                        wal_path = Path(f"{db_path}{suffix}")
                        if wal_path.exists():
                            wal_path.unlink()
            except Exception as e:
                logger.warning(
                    "Integrity check failed (%s) — attempting fresh DB", e
                )
                try:
                    import shutil
                    backup = f"{db_path}.corrupted.{int(time.time())}"
                    shutil.move(db_path, backup)
                    for suffix in ("-wal", "-shm"):
                        wal_path = Path(f"{db_path}{suffix}")
                        if wal_path.exists():
                            wal_path.unlink()
                except Exception:
                    pass

        # Initialize database
        self.db = sqlite3.connect(db_path, check_same_thread=False, timeout=10.0)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")  # safe with WAL, reduces fsync
        self.db.execute("PRAGMA temp_store=MEMORY")  # temp indices in RAM
        self.db.execute("PRAGMA mmap_size=268435456")  # 256MB mmap for read perf
        self.db.execute(
            "PRAGMA wal_autocheckpoint=1000"
        )  # checkpoint every 1000 pages (~4MB); prevents unbounded WAL growth and mid-write corruption on concurrent writers
        self.db.execute(
            "PRAGMA busy_timeout=15000"
        )  # 15s retry on locked DB instead of immediate SQLITE_BUSY error
        self.db.execute("PRAGMA optimize")  # update query planner statistics

        # Create schema
        self.db.executescript(SCHEMA)
        self.db.commit()
        self._migrate_wal_dead_letter_schema()

        # A3.3: Auto-apply pending schema migrations on startup
        try:
            from amoskys.storage.migrations.migrate import auto_migrate

            applied = auto_migrate(db_path)
            if applied > 0:
                logger.info("Applied %d pending schema migration(s)", applied)
        except Exception:
            logger.warning(
                "Schema migration check failed — continuing with existing schema",
                exc_info=True,
            )
        self._migrate_convergence_schema()

        # Self-heal snapshot dedup baselines — ensures dedup works even
        # after DB rebuild or if migration 013 seeding missed new entries.
        try:
            stats = self.populate_baselines()
            seeded = sum(stats.values())
            if seeded > 0:
                logger.info("Seeded %d snapshot dedup baselines: %s", seeded, stats)
        except Exception:
            logger.debug("Baseline population skipped", exc_info=True)

        logger.info(f"Initialized TelemetryStore at {db_path}")

        # Thread-safety: serialize all SQLite operations through a lock.
        # The dashboard WebSocket updater thread and Flask request threads
        # share this singleton — concurrent access causes SQLITE_MISUSE.
        self._lock = threading.Lock()

        # Pool of read-only connections for dashboard queries.
        # WAL mode allows unlimited concurrent readers — the pool
        # eliminates the serialisation bottleneck that a single
        # _read_lock caused on parallel dashboard API calls.
        self._read_pool = _ReadPool(db_path, size=4)

        # Batch mode: when active, inserts skip per-row commits.
        # WALProcessor calls begin_batch() before a batch and end_batch() after.
        self._batch_mode: bool = False
        self._batch_count: int = 0

        # AMRDR: reliability tracker for agent trust cross-validation
        try:
            from amoskys.intel.reliability import BayesianReliabilityTracker

            self._reliability = BayesianReliabilityTracker(
                store_path="data/intel/reliability.db"
            )
        except Exception:
            self._reliability = None

        # Dashboard query cache — coalesces bursts of identical queries
        # within a 5-second window (typical WebSocket push interval).
        self._cache = _TTLCache(ttl_seconds=5.0)

        # Background prewarm: keep expensive summary caches hot so users
        # never hit a cold 1-2 s query.  Runs every 25 s (TTL is 30 s).
        self._prewarm_thread = threading.Thread(
            target=self._prewarm_loop, daemon=True, name="cache-prewarm"
        )
        self._prewarm_thread.start()
