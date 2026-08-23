"""Canonical blindness-event ledger.

Blindness events are not threat detections. They are evidence that AMOSKYS
could not see, could not enrich, or intentionally suppressed an action.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from typing import Any

BLINDNESS_TABLE = "blindness_events"
BLINDNESS_BLOCKING_STATUSES = {"blind", "unauthorized"}
BLINDNESS_DEGRADED_STATUSES = {"degraded", "suppressed", "unknown"}


def _json_dumps(value: Any) -> str:
    try:
        return json.dumps(value or {}, sort_keys=True, default=str)
    except Exception:
        return json.dumps({"repr": repr(value)})


def _default_event_key(
    device_id: str | None,
    sensor: str,
    kind: str,
    reason: str,
    source: str,
) -> str:
    raw = "\x1f".join(
        [
            str(source or ""),
            str(device_id or ""),
            str(sensor or ""),
            str(kind or ""),
            str(reason or ""),
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def ensure_blindness_table(db: sqlite3.Connection) -> None:
    """Create or migrate the blindness ledger."""
    db.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {BLINDNESS_TABLE} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_key TEXT NOT NULL UNIQUE,
            device_id TEXT,
            sensor TEXT NOT NULL,
            kind TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'degraded',
            reason TEXT NOT NULL,
            since REAL NOT NULL,
            last_seen REAL NOT NULL,
            evidence TEXT NOT NULL DEFAULT '{{}}',
            source TEXT NOT NULL DEFAULT 'amoskys',
            active BOOLEAN NOT NULL DEFAULT 1,
            count INTEGER NOT NULL DEFAULT 1
        )
        """
    )
    for column, ddl in (
        ("event_key", "TEXT NOT NULL DEFAULT ''"),
        ("device_id", "TEXT"),
        ("sensor", "TEXT NOT NULL DEFAULT 'unknown'"),
        ("kind", "TEXT NOT NULL DEFAULT 'unknown'"),
        ("status", "TEXT NOT NULL DEFAULT 'degraded'"),
        ("reason", "TEXT NOT NULL DEFAULT ''"),
        ("since", "REAL NOT NULL DEFAULT 0"),
        ("last_seen", "REAL NOT NULL DEFAULT 0"),
        ("evidence", "TEXT NOT NULL DEFAULT '{}'"),
        ("source", "TEXT NOT NULL DEFAULT 'amoskys'"),
        ("active", "BOOLEAN NOT NULL DEFAULT 1"),
        ("count", "INTEGER NOT NULL DEFAULT 1"),
    ):
        try:
            db.execute(f"ALTER TABLE {BLINDNESS_TABLE} ADD COLUMN {column} {ddl}")
        except sqlite3.OperationalError:
            pass
    db.execute(
        f"""
        CREATE INDEX IF NOT EXISTS idx_blindness_recent
        ON {BLINDNESS_TABLE}(active, last_seen DESC, status)
        """
    )
    db.execute(
        f"""
        CREATE INDEX IF NOT EXISTS idx_blindness_device
        ON {BLINDNESS_TABLE}(device_id, active, last_seen DESC)
        """
    )


def record_blindness_event(
    db: sqlite3.Connection,
    *,
    device_id: str | None,
    sensor: str,
    kind: str,
    reason: str,
    status: str = "degraded",
    evidence: dict[str, Any] | None = None,
    source: str = "amoskys",
    event_key: str | None = None,
    now: float | None = None,
) -> str:
    """Upsert one active blindness event and return its stable key."""
    ensure_blindness_table(db)
    seen_at = float(now or time.time())
    key = event_key or _default_event_key(device_id, sensor, kind, reason, source)
    db.execute(
        f"""
        INSERT INTO {BLINDNESS_TABLE} (
            event_key, device_id, sensor, kind, status, reason, since,
            last_seen, evidence, source, active, count
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1)
        ON CONFLICT(event_key) DO UPDATE SET
            device_id = excluded.device_id,
            sensor = excluded.sensor,
            kind = excluded.kind,
            status = excluded.status,
            reason = excluded.reason,
            last_seen = excluded.last_seen,
            evidence = excluded.evidence,
            source = excluded.source,
            active = 1,
            count = {BLINDNESS_TABLE}.count + 1
        """,
        (
            key,
            device_id,
            sensor,
            kind,
            status,
            reason,
            seen_at,
            seen_at,
            _json_dumps(evidence),
            source,
        ),
    )
    return key


def list_blindness_events(
    db: sqlite3.Connection,
    *,
    since: float | None = None,
    device_id: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Read active blindness events from a DB if the ledger exists."""
    try:
        table = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (BLINDNESS_TABLE,),
        ).fetchone()
        if not table:
            return []

        clauses = ["active = 1"]
        params: list[Any] = []
        if since is not None:
            clauses.append("last_seen >= ?")
            params.append(float(since))
        if device_id:
            clauses.append("device_id = ?")
            params.append(device_id)
        params.append(int(limit))
        rows = db.execute(
            f"""
            SELECT event_key, device_id, sensor, kind, status, reason, since,
                   last_seen, evidence, source, active, count
            FROM {BLINDNESS_TABLE}
            WHERE {' AND '.join(clauses)}
            ORDER BY last_seen DESC
            LIMIT ?
            """,
            params,
        ).fetchall()
    except Exception:
        return []

    events: list[dict[str, Any]] = []
    for row in rows:
        item = (
            dict(row)
            if isinstance(row, sqlite3.Row)
            else dict(
                zip(
                    (
                        "event_key",
                        "device_id",
                        "sensor",
                        "kind",
                        "status",
                        "reason",
                        "since",
                        "last_seen",
                        "evidence",
                        "source",
                        "active",
                        "count",
                    ),
                    row,
                )
            )
        )
        try:
            item["evidence"] = json.loads(item.get("evidence") or "{}")
        except Exception:
            item["evidence"] = {"raw": item.get("evidence")}
        item["active"] = bool(item.get("active"))
        item["count"] = int(item.get("count") or 0)
        events.append(item)
    return events


def summarize_blindness_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize active blindness events into a dashboard health contract."""
    active = [event for event in events if event.get("active", True)]
    if not active:
        return {
            "status": "healthy",
            "message": "No active blindness events",
            "active_count": 0,
            "events": [],
            "by_sensor": {},
        }

    by_sensor: dict[str, int] = {}
    statuses = {str(event.get("status") or "unknown") for event in active}
    for event in active:
        sensor = str(event.get("sensor") or "unknown")
        by_sensor[sensor] = by_sensor.get(sensor, 0) + 1

    if statuses & BLINDNESS_BLOCKING_STATUSES:
        status = "blind"
    elif statuses & BLINDNESS_DEGRADED_STATUSES:
        status = "degraded"
    else:
        status = "unknown"

    return {
        "status": status,
        "message": f"{len(active)} active blindness event(s)",
        "active_count": len(active),
        "events": active,
        "by_sensor": by_sensor,
    }
