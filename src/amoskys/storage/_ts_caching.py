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
        conn = sqlite3.connect(self._db_path, check_same_thread=False, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA query_only=ON")
        conn.execute("PRAGMA cache_size=-8000")  # 8 MB
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA mmap_size=268435456")  # 256MB mmap
        conn.execute("PRAGMA busy_timeout=5000")
        try:
            yield conn
        finally:
            conn.close()  # Fully release — no WAL snapshot leak

            # Periodic passive checkpoint every 60s
            now = time.monotonic()
            if now - self._last_checkpoint > 60:
                self._last_checkpoint = now
                try:
                    ck = sqlite3.connect(self._db_path, timeout=2.0)
                    ck.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                    ck.close()
                except Exception:
                    pass

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
