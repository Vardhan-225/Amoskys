"""
MeshBus — In-process pub/sub event bus for the Agent Mesh.

Design:
  - Zero external dependencies (pure Python + SQLite)
  - Thread-safe (agents may publish from different threads)
  - SQLite-backed for durability and forensic replay
  - <10us dispatch latency for in-process subscribers
  - Fail-safe: if the bus dies, agents revert to polling mode

Usage:
    bus = MeshBus(db_path="data/mesh_events.db")
    bus.subscribe(EventType.CREDENTIAL_FILE_ACCESS, handler_fn)
    bus.publish(event)
    bus.shutdown()
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from collections import defaultdict
from typing import Callable, Dict, List, Optional, Set

from .events import EventType, SecurityEvent, Severity

logger = logging.getLogger("amoskys.mesh.bus")

EventHandler = Callable[[SecurityEvent], None]


class MeshBus:
    """In-process pub/sub event bus with SQLite persistence."""

    def __init__(self, db_path: str = "data/mesh_events.db"):
        self._db_path = db_path
        self._subscribers: Dict[EventType, List[EventHandler]] = defaultdict(list)
        self._global_subscribers: List[EventHandler] = []
        self._lock = threading.Lock()
        self._event_count = 0
        self._running = True

        # Initialize SQLite storage
        self._init_db()
        logger.info("MeshBus initialized: %s", db_path)

    def _init_db(self) -> None:
        """Create mesh_events table if it doesn't exist."""
        conn = sqlite3.connect(self._db_path)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mesh_events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                source_agent TEXT NOT NULL,
                severity TEXT NOT NULL,
                payload TEXT,
                timestamp_ns INTEGER NOT NULL,
                related_pid INTEGER,
                related_ip TEXT,
                related_domain TEXT,
                related_path TEXT,
                mitre_technique TEXT,
                confidence REAL DEFAULT 0.0,
                processed INTEGER DEFAULT 0
            )
        """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_mesh_events_type
            ON mesh_events(event_type)
        """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_mesh_events_ts
            ON mesh_events(timestamp_ns)
        """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_mesh_events_severity
            ON mesh_events(severity)
        """
        )
        conn.commit()
        conn.close()

    def subscribe(
        self,
        event_type: EventType,
        handler: EventHandler,
    ) -> None:
        """Subscribe to a specific event type.

        Args:
            event_type: The event type to subscribe to.
            handler: Callable that receives SecurityEvent. Must be thread-safe.
        """
        with self._lock:
            self._subscribers[event_type].append(handler)
        logger.debug(
            "Subscriber added for %s: %s",
            event_type.value,
            handler.__qualname__,
        )

    def subscribe_all(self, handler: EventHandler) -> None:
        """Subscribe to ALL event types (used by IGRIS Orchestrator)."""
        with self._lock:
            self._global_subscribers.append(handler)
        logger.debug("Global subscriber added: %s", handler.__qualname__)

    def publish(self, event: SecurityEvent) -> None:
        """Publish an event to the mesh.

        1. Persist to SQLite (durability)
        2. Dispatch to type-specific subscribers
        3. Dispatch to global subscribers
        """
        if not self._running:
            logger.warning("MeshBus is shut down, dropping event: %s", event)
            return

        # 1. Persist
        self._persist(event)

        # 2. Dispatch to subscribers
        with self._lock:
            handlers = list(self._subscribers.get(event.event_type, []))
            global_handlers = list(self._global_subscribers)

        self._event_count += 1

        for handler in handlers + global_handlers:
            try:
                handler(event)
            except Exception:
                logger.exception(
                    "Handler %s failed for event %s",
                    handler.__qualname__,
                    event.event_id,
                )

        if event.severity in (Severity.HIGH, Severity.CRITICAL):
            logger.warning("MESH [%s] %s", event.severity.value.upper(), event)
        else:
            logger.debug("MESH %s", event)

    def _persist(self, event: SecurityEvent) -> None:
        """Store event in SQLite for durability and replay."""
        try:
            conn = sqlite3.connect(self._db_path)
            conn.execute(
                """INSERT OR IGNORE INTO mesh_events
                   (event_id, event_type, source_agent, severity, payload,
                    timestamp_ns, related_pid, related_ip, related_domain,
                    related_path, mitre_technique, confidence)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.event_id,
                    event.event_type.value,
                    event.source_agent,
                    event.severity.value,
                    json.dumps(event.payload),
                    event.timestamp_ns,
                    event.related_pid,
                    event.related_ip,
                    event.related_domain,
                    event.related_path,
                    event.mitre_technique,
                    event.confidence,
                ),
            )
            conn.commit()
            conn.close()
        except Exception:
            logger.exception("Failed to persist mesh event %s", event.event_id)

    def query_recent(
        self,
        event_type: Optional[EventType] = None,
        severity_min: Optional[Severity] = None,
        seconds: int = 300,
        limit: int = 100,
    ) -> List[SecurityEvent]:
        """Query recent mesh events for correlation.

        Args:
            event_type: Filter by type (None = all types)
            severity_min: Minimum severity level
            seconds: Look back window in seconds
            limit: Maximum results
        """
        cutoff_ns = time.time_ns() - (seconds * 1_000_000_000)
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row

        query = "SELECT * FROM mesh_events WHERE timestamp_ns > ?"
        params: list = [cutoff_ns]

        if event_type:
            query += " AND event_type = ?"
            params.append(event_type.value)
        if severity_min:
            severities = [
                s.value for s in Severity if s.numeric >= severity_min.numeric
            ]
            query += f" AND severity IN ({','.join('?' * len(severities))})"
            params.extend(severities)

        query += " ORDER BY timestamp_ns DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        conn.close()

        events = []
        for row in rows:
            payload = {}
            try:
                payload = json.loads(row["payload"]) if row["payload"] else {}
            except (json.JSONDecodeError, TypeError):
                pass
            events.append(
                SecurityEvent(
                    event_id=row["event_id"],
                    event_type=EventType(row["event_type"]),
                    source_agent=row["source_agent"],
                    severity=Severity(row["severity"]),
                    payload=payload,
                    timestamp_ns=row["timestamp_ns"],
                    related_pid=row["related_pid"],
                    related_ip=row["related_ip"],
                    related_domain=row["related_domain"],
                    related_path=row["related_path"],
                    mitre_technique=row["mitre_technique"],
                    confidence=row["confidence"] or 0.0,
                )
            )
        return events

    def get_event_counts(self, seconds: int = 300) -> Dict[str, int]:
        """Get event counts by type for the last N seconds."""
        cutoff_ns = time.time_ns() - (seconds * 1_000_000_000)
        conn = sqlite3.connect(self._db_path)
        rows = conn.execute(
            """SELECT event_type, COUNT(*) as cnt
               FROM mesh_events WHERE timestamp_ns > ?
               GROUP BY event_type ORDER BY cnt DESC""",
            (cutoff_ns,),
        ).fetchall()
        conn.close()
        return {r[0]: r[1] for r in rows}

    @property
    def event_count(self) -> int:
        """Total events dispatched since bus start."""
        return self._event_count

    def shutdown(self) -> None:
        """Gracefully shut down the bus."""
        self._running = False
        logger.info("MeshBus shutdown. Total events dispatched: %d", self._event_count)
