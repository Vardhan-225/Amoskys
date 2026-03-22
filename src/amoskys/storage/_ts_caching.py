"""Caching and connection pooling helpers for TelemetryStore."""

from __future__ import annotations

import queue
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Any, Dict, Optional


class _ReadPool:
    """Pool of read-only SQLite connections for parallel dashboard queries.

    WAL mode supports unlimited concurrent readers.  By giving each request
    thread its own connection we eliminate the serialisation bottleneck that
    a single ``_read_lock`` caused (posture endpoint: 1.6 s → <200 ms).
    """

    def __init__(self, db_path: str, size: int = 4):
        self._pool: queue.Queue = queue.Queue()
        for _ in range(size):
            conn = sqlite3.connect(db_path, check_same_thread=False, timeout=5.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA query_only=ON")
            conn.execute("PRAGMA cache_size=-16000")  # 16 MB per conn
            conn.execute("PRAGMA temp_store=MEMORY")
            conn.execute("PRAGMA mmap_size=268435456")  # 256MB mmap
            conn.execute("PRAGMA busy_timeout=5000")  # match writer timeout
            self._pool.put(conn)

    @contextmanager
    def connection(self):
        conn = self._pool.get()
        try:
            yield conn
        finally:
            self._pool.put(conn)

    def close(self):
        while not self._pool.empty():
            try:
                self._pool.get_nowait().close()
            except queue.Empty:
                break


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
