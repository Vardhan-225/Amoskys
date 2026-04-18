"""SQLite storage for AMOSKYS Web events.

v0 uses SQLite so bring-up is friction-free (no Postgres to provision).
For production multi-tenant scale, migrate to Postgres with row-level
security (see docs/web/LESSONS_FROM_ENDPOINT.md — Lesson 2).

Schema philosophy:
  - Everything JSON-encodable fits in the row
  - One event = one row
  - Tenant isolation enforced at the query layer (WHERE tenant_id = :t)
  - Chain state cached separately so the ingest doesn't do a LIMIT 1
    lookup on every insert
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Iterator, Optional


SCHEMA = """
CREATE TABLE IF NOT EXISTS web_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id        TEXT    NOT NULL UNIQUE,
    tenant_id       TEXT    NOT NULL,
    site_id         TEXT    NOT NULL,
    origin          TEXT    NOT NULL,
    event_type      TEXT    NOT NULL,
    severity        TEXT    NOT NULL,
    event_timestamp_ns INTEGER NOT NULL,
    persisted_at_ns INTEGER NOT NULL,
    sig             TEXT    NOT NULL,
    prev_sig        TEXT,
    envelope_json   TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_web_events_tenant_site_origin_ts
    ON web_events (tenant_id, site_id, origin, event_timestamp_ns);
CREATE INDEX IF NOT EXISTS idx_web_events_event_type
    ON web_events (tenant_id, event_type);

CREATE TABLE IF NOT EXISTS chain_state (
    tenant_id   TEXT NOT NULL,
    site_id     TEXT NOT NULL,
    origin      TEXT NOT NULL,
    last_sig    TEXT NOT NULL,
    last_event_ns INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, site_id, origin)
);

CREATE TABLE IF NOT EXISTS chain_breaks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   TEXT NOT NULL,
    site_id     TEXT NOT NULL,
    origin      TEXT NOT NULL,
    event_id    TEXT NOT NULL,
    expected_prev TEXT,
    submitted_prev TEXT,
    noted_at_ns INTEGER NOT NULL,
    reason      TEXT
);

-- Simple tenant + token table. One token per tenant in v0.
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id   TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    token_sha256 TEXT NOT NULL UNIQUE,
    created_at_ns INTEGER NOT NULL
);
"""


class EventStore:
    """Thread-safe SQLite event store."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        with self._conn() as c:
            c.executescript(SCHEMA)
            c.commit()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, isolation_level=None, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        try:
            yield conn
        finally:
            conn.close()

    def insert_event(
        self,
        *,
        event_id: str,
        tenant_id: str,
        site_id: str,
        origin: str,
        event_type: str,
        severity: str,
        event_timestamp_ns: int,
        sig: str,
        prev_sig: Optional[str],
        envelope: Dict[str, Any],
    ) -> int:
        """Insert event, return persisted_at_ns. Idempotent on event_id."""
        persisted_at_ns = int(time.time() * 1e9)
        with self._lock, self._conn() as c:
            try:
                c.execute(
                    """
                    INSERT INTO web_events (
                      event_id, tenant_id, site_id, origin, event_type,
                      severity, event_timestamp_ns, persisted_at_ns,
                      sig, prev_sig, envelope_json
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        event_id, tenant_id, site_id, origin, event_type,
                        severity, event_timestamp_ns, persisted_at_ns,
                        sig, prev_sig, json.dumps(envelope, sort_keys=True),
                    ),
                )
                # Update chain state
                c.execute(
                    """
                    INSERT INTO chain_state (tenant_id, site_id, origin, last_sig, last_event_ns)
                    VALUES (?,?,?,?,?)
                    ON CONFLICT(tenant_id, site_id, origin)
                    DO UPDATE SET last_sig=excluded.last_sig, last_event_ns=excluded.last_event_ns
                      WHERE excluded.last_event_ns > chain_state.last_event_ns
                    """,
                    (tenant_id, site_id, origin, sig, event_timestamp_ns),
                )
                c.commit()
            except sqlite3.IntegrityError:
                # Duplicate event_id — idempotent success
                pass
        return persisted_at_ns

    def expected_prev_sig(self, tenant_id: str, site_id: str, origin: str) -> Optional[str]:
        """What the next event's prev_sig should be (or None = no prior)."""
        with self._conn() as c:
            row = c.execute(
                "SELECT last_sig FROM chain_state WHERE tenant_id=? AND site_id=? AND origin=?",
                (tenant_id, site_id, origin),
            ).fetchone()
            return row["last_sig"] if row else None

    def note_chain_break(
        self, *, tenant_id: str, site_id: str, origin: str, event_id: str,
        expected_prev: Optional[str], submitted_prev: Optional[str], reason: str,
    ) -> None:
        with self._lock, self._conn() as c:
            c.execute(
                """INSERT INTO chain_breaks
                   (tenant_id, site_id, origin, event_id, expected_prev,
                    submitted_prev, noted_at_ns, reason)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (tenant_id, site_id, origin, event_id, expected_prev,
                 submitted_prev, int(time.time() * 1e9), reason),
            )
            c.commit()

    def event_counts(self, tenant_id: Optional[str] = None) -> Dict[str, int]:
        """Quick stats for a health endpoint."""
        with self._conn() as c:
            if tenant_id:
                rows = c.execute(
                    "SELECT event_type, COUNT(*) c FROM web_events "
                    "WHERE tenant_id=? GROUP BY event_type ORDER BY c DESC",
                    (tenant_id,),
                ).fetchall()
            else:
                rows = c.execute(
                    "SELECT event_type, COUNT(*) c FROM web_events "
                    "GROUP BY event_type ORDER BY c DESC",
                ).fetchall()
            return {r["event_type"]: r["c"] for r in rows}

    def ensure_dev_tenant(self, token: str) -> str:
        """Create (if not exists) the single dev tenant + bind the bearer token."""
        import hashlib
        tenant_id = "dev-tenant"
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with self._lock, self._conn() as c:
            c.execute(
                """INSERT INTO tenants (tenant_id, name, token_sha256, created_at_ns)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(tenant_id) DO UPDATE SET token_sha256=excluded.token_sha256""",
                (tenant_id, "Development tenant", token_hash, int(time.time() * 1e9)),
            )
            c.commit()
        return tenant_id

    def tenant_from_token(self, token: str) -> Optional[str]:
        """Look up tenant_id from bearer token. Returns None if unknown."""
        import hashlib
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with self._conn() as c:
            row = c.execute(
                "SELECT tenant_id FROM tenants WHERE token_sha256=?",
                (token_hash,),
            ).fetchone()
            return row["tenant_id"] if row else None
