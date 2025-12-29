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

import logging
import os
import sqlite3
import time
from typing import Callable

from amoskys.proto import messaging_schema_pb2 as pb

logger = logging.getLogger(__name__)

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

    def __init__(
        self, path="wal.db", max_bytes=200 * 1024 * 1024, vacuum_threshold=0.3
    ):
        """Initialize SQLite WAL with durability guarantees.

        Creates database file and schema if not exists. Sets up WAL mode
        and full synchronization for crash safety.

        Args:
            path: Filesystem path for WAL database (default: "wal.db")
            max_bytes: Maximum backlog size in bytes (default: 200MB)
            vacuum_threshold: Fraction of database to reclaim before VACUUM (default: 0.3 = 30%)

        Notes:
            - Parent directories are created automatically
            - Timeout is set to 5 seconds for lock contention
            - isolation_level=None enables auto-commit mode
            - VACUUM runs automatically to reclaim disk space
        """
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.path = path
        self.max_bytes = max_bytes
        self.vacuum_threshold = vacuum_threshold
        self.last_vacuum_time = 0
        self.deleted_since_vacuum = 0
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
                (env.idempotency_key, env.ts_ns, sqlite3.Binary(data), checksum),
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

    def file_size_bytes(self) -> int:
        """Get actual file size on disk (including WAL journal files).

        Returns:
            int: Total size in bytes of database files on disk
        """
        total = 0
        for suffix in ["", "-wal", "-shm"]:
            file_path = self.path + suffix
            if os.path.exists(file_path):
                total += os.path.getsize(file_path)
        return total

    def drain(
        self, publish_fn: Callable[[pb.Envelope], object], limit: int = 1000
    ) -> int:
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

        Also triggers VACUUM when enough space has been freed to reclaim
        disk space from deleted records.

        Note:
            Dropped events are logged at WARNING level for monitoring.
        """
        total = self.backlog_bytes()
        if total <= self.max_bytes:
            return

        to_free = total - self.max_bytes
        freed = 0
        dropped_count = 0

        cur = self.db.execute("SELECT id, length(bytes), idem FROM wal ORDER BY id")
        for rowid, sz, idem in cur:
            self.db.execute("DELETE FROM wal WHERE id=?", (rowid,))
            freed += sz
            dropped_count += 1
            self.deleted_since_vacuum += 1
            if freed >= to_free:
                break

        if dropped_count > 0:
            logger.warning(
                f"Backpressure: dropped {dropped_count} events "
                f"({freed} bytes) to stay under {self.max_bytes} limit"
            )

        # Trigger VACUUM if we've freed significant space
        self._maybe_vacuum()

    def _maybe_vacuum(self):
        """Run VACUUM if enough space has been freed to warrant it.

        VACUUM rebuilds the database file to reclaim disk space from
        deleted records. It's expensive, so only run when:
        1. Enough deletions have occurred (> vacuum_threshold * file size)
        2. Enough time has passed (> 5 minutes since last VACUUM)
        """
        current_time = time.time()

        # Don't vacuum more than once per 5 minutes
        if current_time - self.last_vacuum_time < 300:
            return

        # Only vacuum if we've deleted a significant amount
        file_size = self.file_size_bytes()
        if file_size == 0:
            return

        deleted_fraction = self.deleted_since_vacuum / file_size
        if deleted_fraction < self.vacuum_threshold:
            return

        # Run VACUUM
        logger.info(
            f"Running VACUUM to reclaim disk space "
            f"(deleted {self.deleted_since_vacuum} bytes, {deleted_fraction:.1%} of file)"
        )

        try:
            # VACUUM requires regular connection (not isolation_level=None)
            self.db.execute("VACUUM")
            self.last_vacuum_time = current_time
            self.deleted_since_vacuum = 0

            new_size = self.file_size_bytes()
            logger.info(f"VACUUM complete: {file_size} -> {new_size} bytes")

        except Exception as e:
            logger.error(f"VACUUM failed: {e}")

    def vacuum(self):
        """Manually trigger VACUUM to reclaim disk space.

        Call this during maintenance windows or when WAL is empty.
        VACUUM rebuilds the database file, which can take time for large files.
        """
        logger.info("Manual VACUUM requested")
        try:
            start_size = self.file_size_bytes()
            self.db.execute("VACUUM")
            end_size = self.file_size_bytes()
            self.last_vacuum_time = time.time()
            self.deleted_since_vacuum = 0
            logger.info(
                f"VACUUM complete: {start_size} -> {end_size} bytes "
                f"({start_size - end_size} bytes reclaimed)"
            )
        except Exception as e:
            logger.error(f"VACUUM failed: {e}")
            raise
