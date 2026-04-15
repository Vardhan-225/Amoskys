"""Fleet database access layer — read-only queries against fleet.db.

All MCP tools use this module instead of opening SQLite directly.
Connections are short-lived, WAL-mode, and read-only by default.
The write path is only used for the device_commands table.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from contextlib import contextmanager
from typing import Any, Generator, Optional

from .config import cfg

logger = logging.getLogger("amoskys.mcp.db")

# ── Helpers ────────────────────────────────────────────────────────


@contextmanager
def read_conn(db_path: str | None = None) -> Generator[sqlite3.Connection, None, None]:
    """Short-lived read-only connection with WAL and busy timeout."""
    path = db_path or cfg.fleet_db
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA query_only=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def write_conn(db_path: str | None = None) -> Generator[sqlite3.Connection, None, None]:
    """Short-lived read-write connection for command queue."""
    path = db_path or cfg.fleet_db
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def query(sql: str, params: tuple = (), db_path: str | None = None) -> list[dict]:
    """Execute a read-only query, return list of dicts."""
    with read_conn(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]


def query_one(sql: str, params: tuple = (), db_path: str | None = None) -> dict | None:
    """Execute a read-only query, return first row or None."""
    with read_conn(db_path) as conn:
        row = conn.execute(sql, params).fetchone()
        return dict(row) if row else None


def scalar(sql: str, params: tuple = (), db_path: str | None = None) -> Any:
    """Execute a read-only query, return single scalar value."""
    with read_conn(db_path) as conn:
        row = conn.execute(sql, params).fetchone()
        return row[0] if row else None


def execute(sql: str, params: tuple = (), db_path: str | None = None) -> int:
    """Execute a write query, return lastrowid."""
    with write_conn(db_path) as conn:
        cur = conn.execute(sql, params)
        return cur.lastrowid or 0


# ── Cutoff helpers ─────────────────────────────────────────────────

def hours_ago_ns(hours: int) -> int:
    """Nanosecond timestamp for N hours ago."""
    return int((time.time() - hours * 3600) * 1e9)


def hours_ago_epoch(hours: int) -> float:
    """Epoch float for N hours ago."""
    return time.time() - hours * 3600
