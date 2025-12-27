"""Local Queue for Agent Offline Resilience.

This module implements a lightweight SQLite-backed queue for agent telemetry
events. When the EventBus is unavailable, events are stored locally and
automatically retried when connectivity is restored.

Key Features:
    - Durability: Events survive agent crashes
    - Automatic Retry: Background drain attempts reconnection
    - Backpressure: Drops oldest events when queue exceeds limit
    - Deduplication: Prevents duplicate event submission

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

import sqlite3
import time
import os
import logging
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
  retries INTEGER DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS queue_idem ON queue(idem);
CREATE INDEX IF NOT EXISTS queue_ts ON queue(ts_ns);
"""

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
        max_retries: int = 10
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
        self.db = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        self.db.executescript(SCHEMA)
        logger.info(f"LocalQueue initialized: path={path}, max_bytes={max_bytes}")

    def enqueue(self, telemetry: pb.DeviceTelemetry, idempotency_key: str) -> bool:
        """Add telemetry to queue with deduplication.

        Serializes and stores telemetry. Duplicate idempotency keys are
        silently ignored. Enforces backlog size limit.

        Args:
            telemetry: DeviceTelemetry protobuf message
            idempotency_key: Unique key for deduplication

        Returns:
            bool: True if enqueued, False if duplicate

        Raises:
            sqlite3.DatabaseError: On database corruption or disk full
        """
        data = telemetry.SerializeToString()
        ts_ns = int(time.time() * 1e9)

        try:
            self.db.execute(
                "INSERT INTO queue(idem, ts_ns, bytes) VALUES(?,?,?)",
                (idempotency_key, ts_ns, sqlite3.Binary(data))
            )
            logger.debug(f"Enqueued: {idempotency_key}")
            self._enforce_backlog()
            return True
        except sqlite3.IntegrityError:
            logger.debug(f"Duplicate skipped: {idempotency_key}")
            return False

    def drain(
        self,
        publish_fn: Callable[[pb.DeviceTelemetry], object],
        limit: int = 100
    ) -> int:
        """Drain queued telemetry by publishing via callback.

        Fetches up to `limit` events in FIFO order and attempts to publish
        each via the provided callback. Successfully published events are
        deleted from the queue.

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
        cur = self.db.execute(
            "SELECT id, bytes, retries, idem FROM queue ORDER BY id LIMIT ?",
            (limit,)
        )
        rows = cur.fetchall()
        drained = 0

        for rowid, blob, retries, idem in rows:
            telemetry = pb.DeviceTelemetry()
            telemetry.ParseFromString(bytes(blob))

            try:
                ack = publish_fn(telemetry)

                # Check if publish was successful
                if hasattr(ack, 'status'):
                    if ack.status == 0:  # OK
                        self.db.execute("DELETE FROM queue WHERE id = ?", (rowid,))
                        drained += 1
                        logger.debug(f"Drained: {idem}")
                    elif ack.status == 1:  # RETRY - EventBus overloaded
                        logger.debug(f"EventBus RETRY: {idem}")
                        break  # Stop draining, try again later
                    else:  # ERROR - permanent failure
                        logger.warning(f"EventBus ERROR: {idem}, status={ack.status}")
                        self.db.execute("DELETE FROM queue WHERE id = ?", (rowid,))
                else:
                    # No ack or unexpected response - treat as failure
                    raise Exception("No valid ack received")

            except Exception as e:
                # RPC failure or network error
                logger.warning(f"Publish failed: {idem}, error={e}")

                # Increment retry counter
                new_retries = retries + 1
                if new_retries > self.max_retries:
                    logger.error(f"Max retries exceeded, dropping: {idem}")
                    self.db.execute("DELETE FROM queue WHERE id = ?", (rowid,))
                else:
                    self.db.execute(
                        "UPDATE queue SET retries = ? WHERE id = ?",
                        (new_retries, rowid)
                    )

                # Stop draining on first failure
                break

        return drained

    def size(self) -> int:
        """Get number of events in queue.

        Returns:
            int: Count of pending events
        """
        row = self.db.execute("SELECT COUNT(*) FROM queue").fetchone()
        return int(row[0] or 0)

    def size_bytes(self) -> int:
        """Get total size of queue in bytes.

        Returns:
            int: Total bytes of all pending events
        """
        row = self.db.execute("SELECT IFNULL(SUM(length(bytes)),0) FROM queue").fetchone()
        return int(row[0] or 0)

    def clear(self) -> int:
        """Clear all events from queue.

        Returns:
            int: Number of events deleted
        """
        cur = self.db.execute("DELETE FROM queue")
        return cur.rowcount

    def _enforce_backlog(self):
        """Enforce maximum queue size by dropping oldest events.

        Called automatically after enqueue(). If queue exceeds max_bytes,
        deletes oldest events until under limit.
        """
        total = self.size_bytes()
        if total <= self.max_bytes:
            return

        to_free = total - self.max_bytes
        freed = 0

        cur = self.db.execute("SELECT id, length(bytes), idem FROM queue ORDER BY id")
        for rowid, sz, idem in cur:
            self.db.execute("DELETE FROM queue WHERE id=?", (rowid,))
            freed += sz
            logger.warning(f"Backpressure: dropped {idem}")
            if freed >= to_free:
                break
