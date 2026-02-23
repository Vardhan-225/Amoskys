"""Local Queue for Agent Offline Resilience.

This module implements a lightweight SQLite-backed queue for agent telemetry
events. When the EventBus is unavailable, events are stored locally and
automatically retried when connectivity is restored.

Key Features:
    - Durability: Events survive agent crashes
    - Automatic Retry: Background drain attempts reconnection
    - Backpressure: Drops oldest events when queue exceeds limit
    - Deduplication: Prevents duplicate event submission
    - Integrity: Optional Ed25519 signature + SHA-256 content hash per row

Design Philosophy:
    Unlike the FlowAgent WAL (which handles high-volume streaming data),
    this queue is designed for periodic telemetry from agents. It prioritizes
    simplicity and resilience over throughput.

Usage:
    >>> queue = LocalQueue("proc_agent.db", max_bytes=50*1024*1024)
    >>> queue.enqueue(device_telemetry, idempotency_key="proc:123:456")
    >>>
    >>> # Later, when EventBus is available:
    >>> def publish(telemetry):
    ...     return stub.PublishTelemetry(telemetry)
    >>> drained = queue.drain(publish, limit=100)
"""

import logging
import os
import sqlite3
import threading
import time
from typing import Callable, Optional

from amoskys.proto import universal_telemetry_pb2 as pb

logger = logging.getLogger(__name__)

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
CREATE TABLE IF NOT EXISTS queue (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  idem TEXT NOT NULL,
  ts_ns INTEGER NOT NULL,
  bytes BLOB NOT NULL,
  retries INTEGER DEFAULT 0,
  content_hash BLOB DEFAULT NULL,
  sig BLOB DEFAULT NULL,
  prev_sig BLOB DEFAULT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS queue_idem ON queue(idem);
CREATE INDEX IF NOT EXISTS queue_ts ON queue(ts_ns);
"""

# Columns added in the signing update.  Used by _migrate_schema().
_SIGNING_COLUMNS = {
    "content_hash": "BLOB DEFAULT NULL",
    "sig": "BLOB DEFAULT NULL",
    "prev_sig": "BLOB DEFAULT NULL",
}


class LocalQueue:
    """SQLite-backed queue for agent telemetry during EventBus downtime.

    Provides persistent storage for DeviceTelemetry messages when the
    EventBus is unreachable. Automatically retries publishing with
    exponential backoff.

    Attributes:
        path (str): Path to SQLite database file
        max_bytes (int): Maximum queue size before dropping oldest events
        max_retries (int): Maximum retry attempts before dropping event
        db (sqlite3.Connection): Database connection
    """

    def __init__(
        self,
        path: str = "agent_queue.db",
        max_bytes: int = 50 * 1024 * 1024,  # 50MB default
        max_retries: int = 10,
    ):
        """Initialize local queue with SQLite backend.

        Args:
            path: Filesystem path for queue database
            max_bytes: Maximum queue size in bytes (default: 50MB)
            max_retries: Maximum retry attempts per event (default: 10)
        """
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.path = path
        self.max_bytes = max_bytes
        self.max_retries = max_retries
        self._lock = threading.RLock()
        self.db = sqlite3.connect(
            self.path, timeout=5.0, isolation_level=None, check_same_thread=False
        )
        self.db.executescript(SCHEMA)
        self._migrate_schema()
        logger.info(f"LocalQueue initialized: path={path}, max_bytes={max_bytes}")

        # AOC-1 observability callbacks (P0-10, P0-11, P0-12)
        # Set by LocalQueueAdapter to wire into AgentMetrics.
        self._on_backpressure_drop: Optional[Callable[[int], None]] = None
        self._on_max_retry_drop: Optional[Callable[[str], None]] = None
        self._on_drain_success: Optional[Callable[[int], None]] = None
        self._on_drain_failure: Optional[Callable[[str, Exception], None]] = None

    def enqueue(
        self,
        telemetry: pb.DeviceTelemetry,
        idempotency_key: str,
        content_hash: Optional[bytes] = None,
        sig: Optional[bytes] = None,
        prev_sig: Optional[bytes] = None,
    ) -> bool:
        """Add telemetry to queue with deduplication and optional signing.

        Serializes and stores telemetry. Duplicate idempotency keys are
        silently ignored. Enforces backlog size limit.

        Args:
            telemetry: DeviceTelemetry protobuf message
            idempotency_key: Unique key for deduplication
            content_hash: SHA-256 digest of serialized payload (optional)
            sig: Ed25519 signature over content_hash (optional)
            prev_sig: Previous row's signature for hash chain (optional)

        Returns:
            bool: True if enqueued, False if duplicate

        Raises:
            sqlite3.DatabaseError: On database corruption or disk full
        """
        data = telemetry.SerializeToString()
        ts_ns = int(time.time() * 1e9)

        with self._lock:
            try:
                self.db.execute(
                    "INSERT INTO queue(idem, ts_ns, bytes, content_hash, sig, prev_sig) "
                    "VALUES(?,?,?,?,?,?)",
                    (
                        idempotency_key,
                        ts_ns,
                        sqlite3.Binary(data),
                        sqlite3.Binary(content_hash) if content_hash else None,
                        sqlite3.Binary(sig) if sig else None,
                        sqlite3.Binary(prev_sig) if prev_sig else None,
                    ),
                )
                logger.debug(f"Enqueued: {idempotency_key}")
                self._enforce_backlog()
                return True
            except sqlite3.IntegrityError:
                logger.debug(f"Duplicate skipped: {idempotency_key}")
                return False

    def drain(
        self, publish_fn: Callable[[pb.DeviceTelemetry], object], limit: int = 100
    ) -> int:
        """Drain queued telemetry by publishing via callback.

        Fetches up to ``limit`` events in FIFO order and attempts to publish
        each via the provided callback.  Successfully published events are
        deleted from the queue.

        The ``publish_fn`` receives a :class:`~pb.DeviceTelemetry` message.
        Signature metadata (``content_hash``, ``sig``, ``prev_sig``) is
        available via :meth:`drain_signed` for callers that need to wrap
        events in a ``UniversalEnvelope``.

        Args:
            publish_fn: Callback that publishes telemetry (should return PublishAck)
            limit: Maximum number of events to drain in one call

        Returns:
            int: Number of events successfully drained

        Behavior:
            - Successful publish: Delete from queue
            - RPC failure: Stop draining, increment retry counter
            - Max retries exceeded: Delete from queue (drop event)
        """

        def _compat_publish(telemetry, _idem, _ts_ns, _content_hash, _sig, _prev_sig):
            return publish_fn(telemetry)

        return self._drain_impl(_compat_publish, limit)

    def drain_signed(
        self,
        publish_fn: Callable[
            [
                pb.DeviceTelemetry,
                str,
                int,
                Optional[bytes],
                Optional[bytes],
                Optional[bytes],
            ],
            object,
        ],
        limit: int = 100,
    ) -> int:
        """Drain with full signature metadata.

        Like :meth:`drain`, but ``publish_fn`` receives additional arguments::

            publish_fn(telemetry, idem_key, ts_ns, content_hash, sig, prev_sig)

        This allows callers (e.g. :class:`LocalQueueAdapter`) to wrap each
        event in a signed ``UniversalEnvelope`` before publishing to the
        EventBus.
        """
        return self._drain_impl(publish_fn, limit)

    def _drain_impl(
        self,
        publish_fn: Callable,
        limit: int,
    ) -> int:
        """Internal drain implementation shared by drain() and drain_signed()."""
        with self._lock:
            cur = self.db.execute(
                "SELECT id, bytes, retries, idem, ts_ns, content_hash, sig, prev_sig "
                "FROM queue ORDER BY id LIMIT ?",
                (limit,),
            )
            rows = cur.fetchall()
        drained = 0

        for rowid, blob, retries, idem, ts_ns, content_hash, sig, prev_sig in rows:
            telemetry = pb.DeviceTelemetry()
            telemetry.ParseFromString(bytes(blob))

            try:
                ack = publish_fn(
                    telemetry,
                    idem,
                    ts_ns,
                    bytes(content_hash) if content_hash else None,
                    bytes(sig) if sig else None,
                    bytes(prev_sig) if prev_sig else None,
                )

                # Check if publish was successful
                if hasattr(ack, "status"):
                    if ack.status == 0:  # OK
                        with self._lock:
                            self.db.execute("DELETE FROM queue WHERE id = ?", (rowid,))
                        drained += 1
                        logger.debug(f"Drained: {idem}")
                    elif ack.status == 1:  # RETRY - EventBus overloaded
                        logger.debug(f"EventBus RETRY: {idem}")
                        break  # Stop draining, try again later
                    else:  # ERROR - permanent failure
                        logger.warning(f"EventBus ERROR: {idem}, status={ack.status}")
                        with self._lock:
                            self.db.execute("DELETE FROM queue WHERE id = ?", (rowid,))
                else:
                    # No ack or unexpected response - treat as failure
                    raise Exception("No valid ack received")

            except Exception as e:
                # RPC failure or network error
                logger.warning(f"Publish failed: {idem}, error={e}")

                # P0-11: Notify drain failure
                if self._on_drain_failure:
                    self._on_drain_failure(idem, e)

                # Increment retry counter
                new_retries = retries + 1
                with self._lock:
                    if new_retries > self.max_retries:
                        # P0-12: Track max-retry drops
                        logger.error(
                            "MAX_RETRY_DROP: %s exceeded %d retries, "
                            "event permanently lost",
                            idem,
                            self.max_retries,
                        )
                        self.db.execute("DELETE FROM queue WHERE id = ?", (rowid,))
                        if self._on_max_retry_drop:
                            self._on_max_retry_drop(idem)
                    else:
                        self.db.execute(
                            "UPDATE queue SET retries = ? WHERE id = ?",
                            (new_retries, rowid),
                        )

                # Stop draining on first failure
                break

        # P0-11: Notify drain success
        if drained > 0 and self._on_drain_success:
            self._on_drain_success(drained)

        return drained

    def size(self) -> int:
        """Get number of events in queue.

        Returns:
            int: Count of pending events
        """
        with self._lock:
            row = self.db.execute("SELECT COUNT(*) FROM queue").fetchone()
        return int(row[0] or 0)

    def size_bytes(self) -> int:
        """Get total size of queue in bytes.

        Returns:
            int: Total bytes of all pending events
        """
        with self._lock:
            row = self.db.execute(
                "SELECT IFNULL(SUM(length(bytes)),0) FROM queue"
            ).fetchone()
        return int(row[0] or 0)

    def clear(self) -> int:
        """Clear all events from queue.

        Returns:
            int: Number of events deleted
        """
        cur = self.db.execute("DELETE FROM queue")
        return cur.rowcount

    def _migrate_schema(self):
        """Add signing columns to existing databases that lack them.

        Safe to call multiple times — uses ``ALTER TABLE ... ADD COLUMN``
        which is a no-op if the column already exists (caught via
        OperationalError).
        """
        for col_name, col_type in _SIGNING_COLUMNS.items():
            try:
                self.db.execute(f"ALTER TABLE queue ADD COLUMN {col_name} {col_type}")
                logger.info(f"Schema migration: added column queue.{col_name}")
            except sqlite3.OperationalError:
                pass  # Column already exists

    def _enforce_backlog(self) -> int:
        """Enforce maximum queue size by dropping oldest events.

        Called automatically after enqueue(). If queue exceeds max_bytes,
        deletes oldest events until under limit.

        Returns:
            int: Number of events dropped (P0-10: must be visible).
        """
        total = self.size_bytes()
        if total <= self.max_bytes:
            return 0

        to_free = total - self.max_bytes
        freed = 0
        dropped_count = 0

        cur = self.db.execute("SELECT id, length(bytes) FROM queue ORDER BY id")
        for rowid, sz in cur:
            self.db.execute("DELETE FROM queue WHERE id=?", (rowid,))
            freed += sz
            dropped_count += 1
            if freed >= to_free:
                break

        if dropped_count > 0:
            logger.error(
                "BACKPRESSURE_DROP: queue=%s dropped %d events "
                "(freed %d bytes, limit=%d bytes)",
                self.path,
                dropped_count,
                freed,
                self.max_bytes,
            )
            if self._on_backpressure_drop:
                self._on_backpressure_drop(dropped_count)

        return dropped_count
