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

    def __init__(self, db_path: str = "data/telemetry.db"):
        """Initialize telemetry store with schema

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path

        # Create parent directory
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

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
            "PRAGMA busy_timeout=5000"
        )  # 5s retry on locked DB instead of immediate SQLITE_BUSY error
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
