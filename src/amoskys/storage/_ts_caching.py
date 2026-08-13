"""Caching and connection pooling helpers for TelemetryStore."""

from __future__ import annotations

import queue
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Any, Dict, Optional


class _ReadPool:
    """Per-request read-only SQLite connections for dashboard queries.

    Opens a fresh connection per request and closes it immediately after.
    This prevents WAL reader snapshots from blocking checkpointing — the
    root cause of the 23GB WAL bloat that locked the pipeline.

    Tradeoff: ~0.5ms overhead per connection open vs unbounded WAL growth.
    With WAL mode + mmap, connection open is nearly free.
    """

    def __init__(self, db_path: str, size: int = 4):
        self._db_path = db_path
        self._last_checkpoint = time.monotonic()

    @contextmanager
    def connection(self):
        # Open genuinely read-only at the URI level, not via the advisory
        # query_only PRAGMA. query_only is a per-connection flag any later
        # statement can flip back off; mode=ro is enforced by the engine, so a
        # write attempt fails with SQLITE_READONLY no matter what the caller
        # does. This is a read pool — it must not be able to write, and until
        # now it demonstrably could (see the checkpoint removal below).
        #
        # immutable=0 is explicit: the file IS being modified by the writer
        # process, so SQLite must not assume a stable snapshot.
        conn = sqlite3.connect(
            f"file:{self._db_path}?mode=ro&immutable=0",
            uri=True,
            check_same_thread=False,
            timeout=5.0,
        )
        conn.row_factory = sqlite3.Row
        # journal_mode is a property of the DATABASE, not the connection, and
        # setting it needs write access — issuing it here was a no-op at best
        # on a read-only handle. The writer establishes WAL mode.
        conn.execute("PRAGMA query_only=ON")
        conn.execute("PRAGMA cache_size=-8000")  # 8 MB
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA mmap_size=268435456")  # 256MB mmap
        conn.execute("PRAGMA busy_timeout=5000")
        try:
            yield conn
        finally:
            conn.close()  # Fully release — no WAL snapshot leak

            # The 60s TRUNCATE checkpoint that used to live here is GONE.
            #
            # It opened a SECOND, read-WRITE connection (no query_only, no
            # mode=ro) purely to checkpoint — which is why readonly=True was a
            # lie: TelemetryStore builds a _ReadPool even in its readonly branch,
            # so a "read-only" store still held a writable handle and issued the
            # single most contended statement in SQLite from the reader side,
            # against the writer.
            #
            # Checkpointing is now the writer's job: analyzer_main runs PASSIVE
            # every 60s and escalates to TRUNCATE past a 256MB WAL. That
            # compensating checkpoint had to land FIRST — wal_autocheckpoint is
            # passive and loses to a busy writer, so deleting this without a
            # writer-side replacement would trade a lock storm for a WAL storm
            # on a tree that has already produced a 23GB telemetry WAL and a
            # 10.09GB igris WAL.

    def close(self):
        pass  # No persistent connections to close


class _TTLCache:
    """Thread-safe TTL cache for dashboard query results.

    Keyed by (method_name, hours) tuples.  Each entry expires after
    ``ttl_seconds`` (default 5 s) — long enough to coalesce the burst
    of WebSocket pushes that hit the same endpoint within one dashboard
    refresh cycle, short enough that the data stays fresh.
    """

    def __init__(self, ttl_seconds: float = 5.0):
        self._ttl = ttl_seconds
        self._store: Dict[str, tuple] = {}  # key → (result, expiry_monotonic)
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            result, expiry = entry
            if time.monotonic() > expiry:
                del self._store[key]
                return None
            return result

    def put(self, key: str, value: Any, ttl: float = 0) -> None:
        with self._lock:
            self._store[key] = (value, time.monotonic() + (ttl or self._ttl))

    def invalidate(self, prefix: str = "") -> None:
        """Drop all entries whose key starts with *prefix* (or all if empty)."""
        with self._lock:
            if not prefix:
                self._store.clear()
            else:
                self._store = {
                    k: v for k, v in self._store.items() if not k.startswith(prefix)
                }
