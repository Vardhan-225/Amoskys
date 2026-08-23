"""User verdict store — the persistence path behind "That's me" / "Not me".

Why this exists as its own SQLite file rather than a SQLAlchemy model or a write
to the telemetry store:

  * On the presentation tier the TelemetryStore is a READ-ONLY fleet_cache
    snapshot, so ``/api/reliability/feedback``'s label writeback cannot land
    (it says so honestly: ``label_written: false``). A button whose only effect
    is a toast that admits it did nothing is worse than no button.
  * The user's judgement is worth keeping on *this* tier regardless of whether
    the upstream Bayesian tracker is reachable: it changes what the ledger shows
    them next time, which is the effect they actually asked for.
  * Upstream forwarding is then best-effort and *recorded* — we store whether
    the reliability loop accepted it, so the UI can tell the truth about which
    half landed.

Journal mode is DELETE, deliberately. This database holds a handful of rows per
user and is read by long-lived Flask workers; WAL on a file like this bought
nothing and cost 10 GB elsewhere in this codebase (see igris/memory.py).
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Iterable

logger = logging.getLogger(__name__)

MINE = "mine"
NOT_MINE = "not_mine"
_VALID = (MINE, NOT_MINE)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS user_verdicts (
    ledger_key      TEXT NOT NULL,
    org_scope       TEXT NOT NULL,
    verdict         TEXT NOT NULL,
    title           TEXT,
    device_ids      TEXT,
    event_ids       TEXT,
    categories      TEXT,
    decided_by      TEXT,
    decided_at      REAL NOT NULL,
    upstream_status TEXT,
    upstream_detail TEXT,
    PRIMARY KEY (ledger_key, org_scope)
);
CREATE INDEX IF NOT EXISTS idx_user_verdicts_scope ON user_verdicts(org_scope, decided_at DESC);
"""


def _db_path() -> str:
    explicit = os.getenv("AMOSKYS_VERDICT_DB")
    if explicit:
        return explicit
    web_db = os.getenv("AMOSKYS_WEB_DB_PATH")
    if web_db:
        return str(Path(web_db).resolve().parent / "verdicts.db")
    root = Path(__file__).resolve().parents[3]
    return str(root / "data" / "verdicts.db")


def _connect() -> sqlite3.Connection:
    path = _db_path()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=5.0)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA busy_timeout=5000")
    db.execute("PRAGMA journal_mode=DELETE")
    db.executescript(_SCHEMA)
    return db


def _dump(value: Iterable[Any] | None) -> str:
    try:
        return json.dumps(list(value or []))
    except (TypeError, ValueError):
        return "[]"


def _load(raw: Any) -> list:
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, list) else []
    except (TypeError, ValueError):
        return []


def record(
    ledger_key: str,
    org_scope: str,
    verdict: str,
    *,
    title: str | None = None,
    device_ids: Iterable[str] | None = None,
    event_ids: Iterable[Any] | None = None,
    categories: Iterable[str] | None = None,
    decided_by: str | None = None,
    upstream_status: str = "not_attempted",
    upstream_detail: str = "",
) -> dict:
    """Persist one user verdict. Re-deciding the same item overwrites it."""
    if verdict not in _VALID:
        raise ValueError(f"verdict must be one of {_VALID}, got {verdict!r}")
    now = time.time()
    with _connect() as db:
        db.execute(
            """INSERT INTO user_verdicts
                 (ledger_key, org_scope, verdict, title, device_ids, event_ids,
                  categories, decided_by, decided_at, upstream_status, upstream_detail)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(ledger_key, org_scope) DO UPDATE SET
                 verdict=excluded.verdict,
                 title=excluded.title,
                 device_ids=excluded.device_ids,
                 event_ids=excluded.event_ids,
                 categories=excluded.categories,
                 decided_by=excluded.decided_by,
                 decided_at=excluded.decided_at,
                 upstream_status=excluded.upstream_status,
                 upstream_detail=excluded.upstream_detail""",
            (
                ledger_key,
                org_scope,
                verdict,
                title,
                _dump(device_ids),
                _dump(event_ids),
                _dump(categories),
                decided_by,
                now,
                upstream_status,
                upstream_detail,
            ),
        )
    return {
        "ledger_key": ledger_key,
        "verdict": verdict,
        "decided_at": now,
        "decided_by": decided_by,
        "upstream_status": upstream_status,
        "upstream_detail": upstream_detail,
    }


def clear(ledger_key: str, org_scope: str) -> bool:
    """Undo a verdict. Returns True if a row was actually removed."""
    with _connect() as db:
        cur = db.execute(
            "DELETE FROM user_verdicts WHERE ledger_key=? AND org_scope=?",
            (ledger_key, org_scope),
        )
        return cur.rowcount > 0


def get_all(org_scope: str) -> dict[str, dict]:
    """All verdicts for a scope, keyed by ledger_key."""
    try:
        with _connect() as db:
            rows = db.execute(
                "SELECT * FROM user_verdicts WHERE org_scope=?", (org_scope,)
            ).fetchall()
    except sqlite3.Error:
        logger.warning("verdict store unreadable", exc_info=True)
        return {}
    out = {}
    for r in rows:
        out[r["ledger_key"]] = {
            "verdict": r["verdict"],
            "title": r["title"],
            "device_ids": _load(r["device_ids"]),
            "event_ids": _load(r["event_ids"]),
            "categories": _load(r["categories"]),
            "decided_by": r["decided_by"],
            "decided_at": r["decided_at"],
            "upstream_status": r["upstream_status"],
            "upstream_detail": r["upstream_detail"],
        }
    return out


def recent(org_scope: str, limit: int = 50) -> list[dict]:
    """Most recent decisions, newest first — the 'what I've taught it' view."""
    try:
        with _connect() as db:
            rows = db.execute(
                "SELECT * FROM user_verdicts WHERE org_scope=? "
                "ORDER BY decided_at DESC LIMIT ?",
                (org_scope, max(1, min(limit, 500))),
            ).fetchall()
    except sqlite3.Error:
        logger.warning("verdict store unreadable", exc_info=True)
        return []
    return [
        {
            "ledger_key": r["ledger_key"],
            "verdict": r["verdict"],
            "title": r["title"],
            "categories": _load(r["categories"]),
            "event_count": len(_load(r["event_ids"])),
            "decided_by": r["decided_by"],
            "decided_at": r["decided_at"],
            "upstream_status": r["upstream_status"],
            "upstream_detail": r["upstream_detail"],
        }
        for r in rows
    ]


def summary(org_scope: str) -> dict:
    """Counts for the ledger header."""
    verdicts = get_all(org_scope)
    mine = sum(1 for v in verdicts.values() if v["verdict"] == MINE)
    not_mine = sum(1 for v in verdicts.values() if v["verdict"] == NOT_MINE)
    landed = sum(1 for v in verdicts.values() if v["upstream_status"] == "applied")
    return {
        "total": len(verdicts),
        "mine": mine,
        "not_mine": not_mine,
        "upstream_applied": landed,
    }
