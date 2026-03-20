"""IGRIS Persistent Memory — tactical state that survives restarts.

IGRIS now remembers across sessions. Tactical state, watched targets,
hunt mode history, posture transitions, and directive outcomes are all
stored in SQLite and restored on startup.

This is IGRIS's hippocampus. Without it, every restart is amnesia.

Tables:
    tactical_state     — current posture, threat level, hunt mode, reason
    watched_targets    — PIDs, paths, domains under active surveillance
    directive_history  — every directive ever issued, with outcome
    posture_transitions — timeline of posture changes for trend analysis
    investigation_results — what agents reported back from INSPECT commands
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("igris.memory")

DATA_DIR = Path("data")
MEMORY_DB = DATA_DIR / "igris" / "memory.db"


class IGRISMemory:
    """Persistent tactical memory for IGRIS.

    Stores:
        - Last known tactical state (restored on startup)
        - Watched target history with reasons and outcomes
        - Directive history with effectiveness tracking
        - Posture transition log for trend analysis
        - Investigation results from INSPECT commands
    """

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS tactical_state (
        key         TEXT PRIMARY KEY,
        value       TEXT NOT NULL,
        updated_at  REAL NOT NULL
    );

    CREATE TABLE IF NOT EXISTS watched_targets (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        target_type TEXT NOT NULL,          -- PID, PATH, DOMAIN
        target      TEXT NOT NULL,
        reason      TEXT NOT NULL,
        urgency     TEXT NOT NULL,
        mitre_technique TEXT DEFAULT '',
        first_seen  REAL NOT NULL,
        last_seen   REAL NOT NULL,
        times_seen  INTEGER DEFAULT 1,
        resolved    INTEGER DEFAULT 0,      -- 0=active, 1=resolved
        resolution  TEXT DEFAULT '',        -- how it was resolved
        UNIQUE(target_type, target)
    );

    CREATE TABLE IF NOT EXISTS directive_history (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        directive_type  TEXT NOT NULL,
        target          TEXT NOT NULL,
        reason          TEXT NOT NULL,
        urgency         TEXT NOT NULL,
        mitre_technique TEXT DEFAULT '',
        issued_at       REAL NOT NULL,
        ttl_seconds     INTEGER NOT NULL,
        acknowledged    INTEGER DEFAULT 0,  -- did an agent respond?
        outcome         TEXT DEFAULT '',     -- what the agent found
        useful          INTEGER DEFAULT -1   -- -1=unknown, 0=noise, 1=useful
    );

    CREATE TABLE IF NOT EXISTS posture_transitions (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        from_posture TEXT NOT NULL,
        to_posture   TEXT NOT NULL,
        reason      TEXT NOT NULL,
        threat_level REAL NOT NULL,
        event_count INTEGER NOT NULL,
        timestamp   REAL NOT NULL
    );

    CREATE TABLE IF NOT EXISTS investigation_results (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        action_type     TEXT NOT NULL,       -- INSPECT_CODESIGN, etc.
        target          TEXT NOT NULL,
        requested_at    REAL NOT NULL,
        completed_at    REAL DEFAULT 0,
        result_json     TEXT DEFAULT '{}',
        verdict         TEXT DEFAULT '',     -- clean, suspicious, malicious, error
        requested_by    TEXT DEFAULT 'igris'
    );

    CREATE TABLE IF NOT EXISTS soma_observations (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        event_category  TEXT NOT NULL,
        process_name    TEXT DEFAULT '',
        path            TEXT DEFAULT '',
        domain          TEXT DEFAULT '',
        risk_score      REAL NOT NULL,
        is_normal       INTEGER DEFAULT -1,  -- -1=unknown, 0=abnormal, 1=normal
        seen_count      INTEGER DEFAULT 1,
        first_seen      REAL NOT NULL,
        last_seen       REAL NOT NULL,
        UNIQUE(event_category, process_name, path)
    );

    CREATE INDEX IF NOT EXISTS idx_watched_active
        ON watched_targets(resolved, last_seen);
    CREATE INDEX IF NOT EXISTS idx_directive_time
        ON directive_history(issued_at);
    CREATE INDEX IF NOT EXISTS idx_posture_time
        ON posture_transitions(timestamp);
    CREATE INDEX IF NOT EXISTS idx_soma_category
        ON soma_observations(event_category);
    """

    def __init__(self):
        MEMORY_DB.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(MEMORY_DB), timeout=5)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(self._SCHEMA)
        self._conn.commit()
        logger.info("IGRIS memory initialized: %s", MEMORY_DB)

    def close(self):
        if self._conn:
            self._conn.close()

    # ── Tactical State ───────────────────────────────────────────────────

    def save_state(self, state_dict: dict):
        """Persist the current tactical state."""
        now = time.time()
        for key, value in state_dict.items():
            self._conn.execute(
                "INSERT OR REPLACE INTO tactical_state (key, value, updated_at) "
                "VALUES (?, ?, ?)",
                (key, json.dumps(value), now),
            )
        self._conn.commit()

    def load_state(self) -> dict:
        """Restore the last known tactical state."""
        rows = self._conn.execute("SELECT key, value FROM tactical_state").fetchall()
        state = {}
        for row in rows:
            try:
                state[row["key"]] = json.loads(row["value"])
            except (json.JSONDecodeError, TypeError):
                state[row["key"]] = row["value"]
        return state

    # ── Watched Targets ──────────────────────────────────────────────────

    def upsert_watched_target(
        self,
        target_type: str,
        target: str,
        reason: str,
        urgency: str,
        mitre_technique: str = "",
    ):
        """Add or update a watched target."""
        now = time.time()
        existing = self._conn.execute(
            "SELECT id, times_seen FROM watched_targets "
            "WHERE target_type = ? AND target = ?",
            (target_type, target),
        ).fetchone()
        if existing:
            self._conn.execute(
                "UPDATE watched_targets SET last_seen = ?, times_seen = ?, "
                "reason = ?, urgency = ?, resolved = 0 WHERE id = ?",
                (now, existing["times_seen"] + 1, reason, urgency, existing["id"]),
            )
        else:
            self._conn.execute(
                "INSERT INTO watched_targets "
                "(target_type, target, reason, urgency, mitre_technique, "
                "first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (target_type, target, reason, urgency, mitre_technique, now, now),
            )
        self._conn.commit()

    def get_active_watches(self) -> List[dict]:
        """Get all active (unresolved) watched targets."""
        rows = self._conn.execute(
            "SELECT * FROM watched_targets WHERE resolved = 0 "
            "ORDER BY last_seen DESC LIMIT 50"
        ).fetchall()
        return [dict(r) for r in rows]

    def resolve_target(self, target_type: str, target: str, resolution: str):
        """Mark a watched target as resolved."""
        self._conn.execute(
            "UPDATE watched_targets SET resolved = 1, resolution = ? "
            "WHERE target_type = ? AND target = ?",
            (resolution, target_type, target),
        )
        self._conn.commit()

    def get_target_history(self, target: str) -> List[dict]:
        """Get full history for a specific target."""
        rows = self._conn.execute(
            "SELECT * FROM watched_targets WHERE target = ? "
            "ORDER BY first_seen DESC",
            (target,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Directive History ────────────────────────────────────────────────

    def record_directive(self, directive_dict: dict):
        """Record a directive that was issued."""
        self._conn.execute(
            "INSERT INTO directive_history "
            "(directive_type, target, reason, urgency, mitre_technique, "
            "issued_at, ttl_seconds) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                directive_dict.get("directive_type", ""),
                directive_dict.get("target", ""),
                directive_dict.get("reason", ""),
                directive_dict.get("urgency", ""),
                directive_dict.get("mitre_technique", ""),
                directive_dict.get("issued_at", time.time()),
                directive_dict.get("ttl_seconds", 300),
            ),
        )
        self._conn.commit()

    def record_directive_outcome(self, directive_id: int, outcome: str, useful: int):
        """Record what happened after a directive was issued."""
        self._conn.execute(
            "UPDATE directive_history SET acknowledged = 1, outcome = ?, "
            "useful = ? WHERE id = ?",
            (outcome, useful, directive_id),
        )
        self._conn.commit()

    def get_directive_stats(self) -> dict:
        """Get effectiveness statistics for directives."""
        total = self._conn.execute("SELECT COUNT(*) FROM directive_history").fetchone()[
            0
        ]
        acked = self._conn.execute(
            "SELECT COUNT(*) FROM directive_history WHERE acknowledged = 1"
        ).fetchone()[0]
        useful = self._conn.execute(
            "SELECT COUNT(*) FROM directive_history WHERE useful = 1"
        ).fetchone()[0]
        noise = self._conn.execute(
            "SELECT COUNT(*) FROM directive_history WHERE useful = 0"
        ).fetchone()[0]
        recent = self._conn.execute(
            "SELECT COUNT(*) FROM directive_history " "WHERE issued_at > ?",
            (time.time() - 3600,),
        ).fetchone()[0]
        return {
            "total": total,
            "acknowledged": acked,
            "useful": useful,
            "noise": noise,
            "recent_1h": recent,
            "effectiveness": useful / max(acked, 1),
        }

    def get_recent_directives(self, limit: int = 20) -> List[dict]:
        """Get recent directives with outcomes."""
        rows = self._conn.execute(
            "SELECT * FROM directive_history ORDER BY issued_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Posture Transitions ──────────────────────────────────────────────

    def record_posture_transition(
        self,
        from_posture: str,
        to_posture: str,
        reason: str,
        threat_level: float,
        event_count: int,
    ):
        """Record a posture change."""
        self._conn.execute(
            "INSERT INTO posture_transitions "
            "(from_posture, to_posture, reason, threat_level, "
            "event_count, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            (from_posture, to_posture, reason, threat_level, event_count, time.time()),
        )
        self._conn.commit()

    def get_posture_history(self, limit: int = 20) -> List[dict]:
        """Get posture transition history."""
        rows = self._conn.execute(
            "SELECT * FROM posture_transitions ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_posture_trend(self, window_seconds: int = 3600) -> str:
        """Determine posture trend: improving, stable, degrading."""
        cutoff = time.time() - window_seconds
        rows = self._conn.execute(
            "SELECT to_posture, threat_level FROM posture_transitions "
            "WHERE timestamp > ? ORDER BY timestamp ASC",
            (cutoff,),
        ).fetchall()
        if len(rows) < 2:
            return "stable"
        levels = [r["threat_level"] for r in rows]
        if levels[-1] > levels[0] + 0.1:
            return "degrading"
        if levels[-1] < levels[0] - 0.1:
            return "improving"
        return "stable"

    # ── Investigation Results ────────────────────────────────────────────

    def request_investigation(self, action_type: str, target: str) -> int:
        """Record an investigation request. Returns the request ID."""
        cur = self._conn.execute(
            "INSERT INTO investigation_results "
            "(action_type, target, requested_at) VALUES (?, ?, ?)",
            (action_type, target, time.time()),
        )
        self._conn.commit()
        return cur.lastrowid

    def complete_investigation(self, request_id: int, result: dict, verdict: str):
        """Record the result of an investigation."""
        self._conn.execute(
            "UPDATE investigation_results SET completed_at = ?, "
            "result_json = ?, verdict = ? WHERE id = ?",
            (time.time(), json.dumps(result), verdict, request_id),
        )
        self._conn.commit()

    def get_investigation_results(
        self, target: str = "", limit: int = 10
    ) -> List[dict]:
        """Get investigation results, optionally filtered by target."""
        if target:
            rows = self._conn.execute(
                "SELECT * FROM investigation_results "
                "WHERE target LIKE ? ORDER BY requested_at DESC LIMIT ?",
                (f"%{target}%", limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM investigation_results "
                "ORDER BY requested_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ── SOMA Observations ────────────────────────────────────────────────

    def record_soma_observation(
        self,
        event_category: str,
        process_name: str = "",
        path: str = "",
        domain: str = "",
        risk_score: float = 0.0,
    ):
        """Record what IGRIS observes for SOMA baseline building."""
        now = time.time()
        existing = self._conn.execute(
            "SELECT id, seen_count FROM soma_observations "
            "WHERE event_category = ? AND process_name = ? AND path = ?",
            (event_category, process_name, path),
        ).fetchone()
        if existing:
            self._conn.execute(
                "UPDATE soma_observations SET seen_count = ?, last_seen = ?, "
                "risk_score = ? WHERE id = ?",
                (existing["seen_count"] + 1, now, risk_score, existing["id"]),
            )
        else:
            self._conn.execute(
                "INSERT INTO soma_observations "
                "(event_category, process_name, path, domain, risk_score, "
                "first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (event_category, process_name, path, domain, risk_score, now, now),
            )
        self._conn.commit()

    def soma_is_known(
        self, event_category: str, process_name: str = "", path: str = ""
    ) -> Optional[dict]:
        """Check if SOMA has seen this pattern before.

        Returns observation dict if known, None if novel.
        """
        row = self._conn.execute(
            "SELECT * FROM soma_observations "
            "WHERE event_category = ? AND process_name = ? AND path = ?",
            (event_category, process_name, path),
        ).fetchone()
        return dict(row) if row else None

    def soma_get_baseline(self, event_category: str, limit: int = 20) -> List[dict]:
        """Get SOMA baseline observations for a category."""
        rows = self._conn.execute(
            "SELECT * FROM soma_observations "
            "WHERE event_category = ? ORDER BY seen_count DESC LIMIT ?",
            (event_category, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def soma_novel_events(self, window_seconds: int = 3600) -> List[dict]:
        """Get events that SOMA has never seen before (novel patterns)."""
        cutoff = time.time() - window_seconds
        rows = self._conn.execute(
            "SELECT * FROM soma_observations "
            "WHERE first_seen > ? AND seen_count = 1 "
            "ORDER BY risk_score DESC LIMIT 20",
            (cutoff,),
        ).fetchall()
        return [dict(r) for r in rows]
