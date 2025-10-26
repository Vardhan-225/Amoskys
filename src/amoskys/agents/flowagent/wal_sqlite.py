"""SQLite-backed Write-Ahead Log for Reliable Event Delivery.

This module implements a durable write-ahead log (WAL) using SQLite to provide
at-least-once delivery guarantees for flow events. The WAL serves as a persistent
queue that survives agent crashes and network failures.

Key Features:
    - Idempotency: Duplicate events (same idem key) are automatically deduplicated
    - Durability: Uses SQLite WAL mode with synchronous=FULL for crash safety
    - Backpressure: Automatically drops oldest events when backlog exceeds max_bytes
    - Ordered Drain: Events are drained in FIFO order (oldest first)

Design:
    The WAL uses SQLite's native WAL mode (journal_mode=WAL) which provides:
    - Better concurrency than rollback journal
    - Atomic commits
    - Fast appends

    This is "WAL for the WAL" - SQLite's WAL feature ensures our message WAL
    is durable and crash-resistant.
"""

import sqlite3, time, os
from typing import Callable
from amoskys.proto import messaging_schema_pb2 as pb

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
CREATE TABLE IF NOT EXISTS wal (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  idem TEXT NOT NULL,
  ts_ns INTEGER NOT NULL,
  bytes BLOB NOT NULL,
  checksum BLOB NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS wal_idem ON wal(idem);
CREATE INDEX IF NOT EXISTS wal_ts ON wal(ts_ns);
"""

class SQLiteWAL:
    """Write-ahead log for durable envelope storage.

    Provides persistent queue for flow event envelopes with automatic
    deduplication and backpressure management. Thread-safe for single
    writer, multiple readers.

    Attributes:
        path (str): Path to SQLite database file
        max_bytes (int): Maximum WAL size before oldest events are dropped
        db (sqlite3.Connection): Database connection with auto-commit
    """

    def __init__(self, path="wal.db", max_bytes=200*1024*1024):
        """Initialize SQLite WAL with durability guarantees.

        Creates database file and schema if not exists. Sets up WAL mode
        and full synchronization for crash safety.

        Args:
            path: Filesystem path for WAL database (default: "wal.db")
            max_bytes: Maximum backlog size in bytes (default: 200MB)

        Notes:
            - Parent directories are created automatically
            - Timeout is set to 5 seconds for lock contention
            - isolation_level=None enables auto-commit mode
        """
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.path = path
        self.max_bytes = max_bytes
        self.db = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        self.db.executescript(SCHEMA)

    def append(self, env: pb.Envelope) -> None:
        """Append envelope to WAL with idempotency guarantees.

        Serializes and stores the envelope. Duplicate idempotency keys are
        silently ignored (returns without error). After successful insert,
        enforces backlog size limit by dropping oldest events if needed.

        Args:
            env: Protobuf envelope to persist

        Behavior:
            - Duplicate idem keys: Silently skipped (no error)
            - Backlog overflow: Automatically drops oldest events
            - Database locked: Waits up to 5 seconds (per connection timeout)

        Raises:
            sqlite3.DatabaseError: On database corruption or disk full
        """
        data = env.SerializeToString()
        checksum = sqlite3.Binary(bytes(memoryview(data)))
        try:
            self.db.execute(
                "INSERT INTO wal(idem, ts_ns, bytes, checksum) VALUES(?,?,?,?)",
                (env.idempotency_key, env.ts_ns, sqlite3.Binary(data), checksum)
            )
        except sqlite3.IntegrityError:
            return
        self._enforce_backlog()

    def backlog_bytes(self) -> int:
        """Calculate total size of pending events in WAL.

        Sums the serialized size of all envelope blobs currently in the WAL.
        Used for metrics and backpressure monitoring.

        Returns:
            int: Total bytes of all pending envelopes (0 if empty)
        """
        row = self.db.execute("SELECT IFNULL(SUM(length(bytes)),0) FROM wal").fetchone()
        return int(row[0] or 0)

    def drain(self, publish_fn: Callable[[pb.Envelope], object], limit: int = 1000) -> int:
        """Drain pending envelopes by publishing them via callback.

        Fetches up to `limit` envelopes in FIFO order and attempts to publish
        each via the provided callback. Successfully published envelopes are
        deleted from the WAL.

        Args:
            publish_fn: Callback that publishes envelope and returns PublishAck
            limit: Maximum number of envelopes to drain in one call

        Returns:
            int: Number of envelopes successfully drained and removed from WAL

        Behavior:
            - OK (status=0): Delete from WAL, continue draining
            - RETRY (status=1): Stop draining, leave all remaining in WAL
            - ERROR (status=2,3,...): Delete from WAL, continue draining
            - No status/None: Stop draining (likely RPC failure)

        Example:
            >>> def publish(env):
            ...     return stub.Publish(env, timeout=2.0)
            >>> drained = wal.drain(publish, limit=500)
        """
        cur = self.db.execute("SELECT id, bytes FROM wal ORDER BY id LIMIT ?", (limit,))
        rows = cur.fetchall()
        drained = 0
        for rowid, blob in rows:
            env = pb.Envelope()
            env.ParseFromString(bytes(blob))
            ack = publish_fn(env)
            status = getattr(ack, "status", None)
            if status is None:
                break

            if status == 1:  # RETRY - stop processing
                break

            # For OK (0) or error statuses (2, 3, etc.), delete the record
            self.db.execute("DELETE FROM wal WHERE id = ?", (rowid,))
            drained += 1
        return drained

    def _enforce_backlog(self):
        """Enforce maximum backlog size by dropping oldest events.

        Called automatically after append(). If backlog exceeds max_bytes,
        deletes oldest events (lowest id) until under limit. This implements
        tail-drop backpressure - recent events are preserved.

        Note:
            This is a silent operation - dropped events do not generate
            errors or metrics. They are simply deleted from the WAL.
        """
        total = self.backlog_bytes()
        if total <= self.max_bytes: return
        to_free = total - self.max_bytes
        freed = 0
        cur = self.db.execute("SELECT id, length(bytes) FROM wal ORDER BY id")
        for rowid, sz in cur:
            self.db.execute("DELETE FROM wal WHERE id=?", (rowid,))
            freed += sz
            if freed >= to_free: break
