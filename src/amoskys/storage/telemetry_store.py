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
import os
import sqlite3
import threading
import time
from pathlib import Path

from amoskys.storage._ts_caching import _ReadPool, _TTLCache
from amoskys.storage._ts_domain_queries import DomainQueryMixin
from amoskys.storage._ts_esf_forensics import ESFForensicsMixin
from amoskys.storage._ts_hybrid_coverage import HybridCoverageMixin
from amoskys.storage._ts_inserts import InsertMixin
from amoskys.storage._ts_lifecycle import LifecycleMixin
from amoskys.storage._ts_posture import PostureMixin
from amoskys.storage._ts_queries import QueryMixin
from amoskys.storage._ts_rollups import RollupMixin
from amoskys.storage._ts_schema import SCHEMA, SchemaMixin
from amoskys.storage._ts_signals import SignalMixin

logger = logging.getLogger("TelemetryStore")


class _RepeatSuppressFilter(logging.Filter):
    """Collapse identical repeated records into one line plus a periodic tally.

    A stuck condition here is emitted once per event, so a lock storm wrote
    21.5M identical "database is locked" lines into a 2.1GB log and filled
    the volume — which took the collector offline. Storage failures must not
    be able to consume the storage they are reporting on.
    """

    def __init__(self, window_seconds: float = 60.0, burst: int = 5):
        super().__init__()
        self._window = window_seconds
        self._burst = burst
        self._seen: dict = {}
        self._lock = threading.Lock()

    def filter(self, record: logging.LogRecord) -> bool:
        if record.levelno < logging.WARNING:
            return True
        key = (record.name, record.levelno, record.msg)
        now = time.monotonic()
        with self._lock:
            count, window_start = self._seen.get(key, (0, now))
            elapsed = now - window_start
            if elapsed >= self._window:
                self._seen[key] = (1, now)
                dropped = max(0, count - self._burst)
                if dropped:
                    record.msg = (
                        f"{record.msg}  [+{dropped} identical suppressed "
                        f"in {int(elapsed)}s]"
                    )
                return True
            self._seen[key] = (count + 1, window_start)
            return count < self._burst


logger.addFilter(_RepeatSuppressFilter())


class TelemetryStore(
    ESFForensicsMixin,
    HybridCoverageMixin,
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

    # ── One store per (resolved path, mode), per process ────────────────────
    # Measured on the live analyzer: `lsof data/telemetry.db` showed PID 71235
    # holding FOUR read-write fds (3u, 6u, 28u, 37u) to the same file, because
    # analyzer_main.py:367 and wal_processor.py:91 each construct their own
    # TelemetryStore — each with its own connection AND its own threading.Lock.
    # Two independent locks guarding one file is not mutual exclusion, so the
    # analyzer was contending with *itself*: a WALProcessor batch and an
    # analyzer write could interleave mid-transaction. This is a large part of
    # the 698,015 "database is locked" errors the codebase records, every one
    # of which discarded an event.
    #
    # Interning on (realpath, readonly) collapses them to one object, one
    # connection, one lock — without touching a single call site. The realpath
    # matters: "data/telemetry.db" and an absolute path to the same file must
    # not produce two stores. readonly is part of the key because a read-only
    # handle is a genuinely different object and must not be handed to a writer.
    #
    # Escape hatch for rollback / tests: AMOSKYS_STORE_SINGLETON=0.
    _instances: dict = {}
    _instances_lock = threading.Lock()

    def __new__(cls, db_path: str = "data/telemetry.db", readonly: bool = False):
        if os.environ.get("AMOSKYS_STORE_SINGLETON") == "0":
            return super().__new__(cls)
        try:
            key = (os.path.realpath(db_path), bool(readonly))
        except (TypeError, ValueError):
            return super().__new__(cls)
        with cls._instances_lock:
            inst = cls._instances.get(key)
            if inst is None:
                inst = super().__new__(cls)
                inst._singleton_key = key
                cls._instances[key] = inst
            return inst

    def __init__(self, db_path: str = "data/telemetry.db", readonly: bool = False):
        # __init__ runs on every construction, including the interned returns —
        # re-running it would rebuild the connection and defeat the point.
        if getattr(self, "_initialized", False):
            return
        self._initialized = True
        # Monotonic count of inserts that failed with a real sqlite3.Error.
        #
        # This exists because insert_*() returning None is OVERLOADED: 13 sites
        # return None after `logger.error("Failed to insert ...")` (genuine
        # loss — the event must be retried), but 9 OTHER sites return None for
        # deliberate suppression ("suppressed duplicate", "identical duplicate",
        # "Not a real connection — socket inventory"). Those are correctly
        # consumed. So the obvious ack fix — "only ack when the insert returned
        # a rowid" — would redeliver every deduped snapshot forever, an infinite
        # loop that looks like progress. The drain must key on THIS counter
        # advancing, which only real write failures do.
        self.write_failures = 0
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
            self.db = sqlite3.connect(db_path, check_same_thread=False, timeout=5.0)
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
        # quick_check does page/structure validation (catches real corruption)
        # WITHOUT the full per-cell + index cross-checks of integrity_check,
        # which scanned the entire multi-GB store on EVERY startup and blocked
        # the analyzer for minutes. Opt back into the exhaustive check with
        # AMOSKYS_FULL_INTEGRITY_CHECK=1 when deep-verifying a suspect DB.
        #
        # Even quick_check reads the whole file, so it is skipped for stores
        # above AMOSKYS_INTEGRITY_CHECK_MAX_BYTES (default 1.5GB) — on a bloated
        # backlog DB the multi-minute scan blocks every restart, and WAL +
        # synchronous=NORMAL already guard against torn writes. Force it anyway
        # with AMOSKYS_FULL_INTEGRITY_CHECK=1.
        # Default 50MB: only cheap checks run automatically. Any real telemetry
        # store is larger and would block the daemon restart on a full-file scan
        # (even quick_check reads every page) — WAL + synchronous=NORMAL guard it.
        # Raise the ceiling or set AMOSKYS_FULL_INTEGRITY_CHECK=1 to force.
        _integrity_max = int(
            os.environ.get("AMOSKYS_INTEGRITY_CHECK_MAX_BYTES", str(50_000_000))
        )
        _force_check = bool(os.environ.get("AMOSKYS_FULL_INTEGRITY_CHECK"))
        _too_big = (
            Path(db_path).exists()
            and not _force_check
            and Path(db_path).stat().st_size > _integrity_max
        )
        if _too_big:
            logger.warning(
                "Skipping boot integrity check: %s is %.1fGB (> %.1fGB limit); "
                "set AMOSKYS_FULL_INTEGRITY_CHECK=1 to force.",
                db_path,
                Path(db_path).stat().st_size / 1e9,
                _integrity_max / 1e9,
            )
        if Path(db_path).exists() and not _too_big:
            try:
                _check_db = sqlite3.connect(db_path, timeout=5.0)
                _check_pragma = (
                    "integrity_check(1)"
                    if os.environ.get("AMOSKYS_FULL_INTEGRITY_CHECK")
                    else "quick_check(1)"
                )
                result = _check_db.execute(f"PRAGMA {_check_pragma}").fetchone()
                _check_db.close()
                if result[0] != "ok":
                    logger.error(
                        "DATABASE CORRUPTED: %s — %s. "
                        "Backing up and creating fresh DB.",
                        db_path,
                        result[0],
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
                logger.warning("Integrity check failed (%s) — attempting fresh DB", e)
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

        # Return deleted pages to the filesystem instead of only to SQLite's
        # freelist. Without this, PRAGMA incremental_vacuum in cleanup_old_data()
        # is a SILENT no-op — it does not error, it simply does nothing — so
        # retention deletes rows and the file never shrinks. Measured on the
        # store that filled this disk: 4,309,435 free pages, 17.7GB, 73% of a
        # 23GB file, all already deleted and none of it returned to the OS.
        #
        # This MUST run before PRAGMA journal_mode=WAL, not in SCHEMA below.
        # auto_vacuum is only settable while the database is empty, and setting
        # journal_mode first is enough to make the change silently fail:
        #   WAL then auto_vacuum -> auto_vacuum=0   (measured)
        #   auto_vacuum then WAL -> auto_vacuum=2   (measured)
        # Which is exactly why the version of this fix that lived in SCHEMA
        # (executed at line ~215, after WAL) did nothing at all.
        self.db.execute("PRAGMA auto_vacuum=INCREMENTAL")

        self.db.execute("PRAGMA journal_mode=WAL")
        # Ceiling on the WAL file itself. wal_autocheckpoint bounds how often a
        # checkpoint is ATTEMPTED, not how large the file may get: a passive
        # checkpoint that loses to a busy reader leaves the log at its
        # high-water mark, which is how this tree produced a 23GB telemetry WAL
        # and a 10.09GB igris WAL. journal_size_limit truncates the file back to
        # this bound after any successful checkpoint, partial ones included.
        self.db.execute("PRAGMA journal_size_limit=268435456")  # 256MB
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

        # Cache prewarm no longer runs on its own thread by default.
        #
        # _write_hourly_rollups() ends in self.db.commit() while _ts_inserts.py
        # takes self._lock ZERO times, so a background prewarm could commit
        # WALProcessor's open begin_batch() transaction mid-flight, splitting one
        # logical batch into two partial ones. Interning the store (Stage 1a)
        # made that sharper, not safer: both halves now provably share one
        # connection. The analyzer instead calls store.prewarm_once() from its
        # own loop, so warming is sequential with ingest rather than racing it.
        #
        # Set AMOSKYS_PREWARM_THREAD=1 to restore the old background thread.
        self._prewarm_stop = threading.Event()
        self._prewarm_thread = None
        if os.environ.get("AMOSKYS_PREWARM_THREAD") == "1":
            self._prewarm_thread = threading.Thread(
                target=self._prewarm_loop, daemon=True, name="cache-prewarm"
            )
            self._prewarm_thread.start()
