"""Ground Truth Oracle — determines event truth for AMRDR reliability updates.

Simplified v1 implementation with two methods:
  1. Cross-agent consensus: ≥2 agents reporting same event → match
  2. Manual feedback: analysts confirm or dismiss events/incidents

See AMRDR_Mechanism_Specification_v0.1 Section 9 (Ground Truth Oracle).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import time
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS event_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_hash TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    timestamp_ns INTEGER NOT NULL,
    UNIQUE(event_hash, agent_id)
);

CREATE INDEX IF NOT EXISTS idx_reports_hash ON event_reports(event_hash);
CREATE INDEX IF NOT EXISTS idx_reports_agent ON event_reports(agent_id);

CREATE TABLE IF NOT EXISTS manual_feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL,
    confirmed_by TEXT NOT NULL,
    is_match INTEGER NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    timestamp_ns INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_feedback_event ON manual_feedback(event_id);
"""

# Minimum agents that must report the same event for consensus
CONSENSUS_THRESHOLD = 2


class GroundTruthOracle:
    """Simplified ground truth determination (v1).

    v1 Methods:
        1. Cross-agent consensus: If ≥2 agents report same event_hash → match
        2. Manual feedback: API allows analysts to submit ground truth

    Args:
        db_path: Path to SQLite database for persistence.
        consensus_threshold: Minimum agents for consensus (default 2).
    """

    def __init__(
        self,
        db_path: str = "data/intel/ground_truth.db",
        consensus_threshold: int = CONSENSUS_THRESHOLD,
    ):
        self.db_path = db_path
        self.consensus_threshold = consensus_threshold
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self._db = sqlite3.connect(
            db_path,
            timeout=5.0,
            isolation_level=None,
            check_same_thread=False,
        )
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(SCHEMA)
        logger.info("GroundTruthOracle initialized: %s", db_path)

    def report_event(
        self,
        event_hash: str,
        agent_id: str,
        event_type: str,
    ) -> None:
        """Record that an agent reported this event.

        Args:
            event_hash: BLAKE2b hash of event content (for dedup).
            agent_id: Which agent reported it.
            event_type: Type of event (e.g., SSH_LOGIN, PROCESS_EXEC).
        """
        try:
            self._db.execute(
                "INSERT OR IGNORE INTO event_reports "
                "(event_hash, agent_id, event_type, timestamp_ns) "
                "VALUES (?, ?, ?, ?)",
                (event_hash, agent_id, event_type, time.time_ns()),
            )
        except Exception as e:
            logger.error("Failed to record event report: %s", e)

    def confirm_event(
        self,
        event_id: str,
        confirmed_by: str,
        is_match: bool,
        reason: str = "",
    ) -> None:
        """Record analyst feedback on event truth.

        Args:
            event_id: Event or incident identifier.
            confirmed_by: Analyst name/ID.
            is_match: True if event is confirmed real/correct.
            reason: Why the analyst made this determination.
        """
        self._db.execute(
            "INSERT INTO manual_feedback "
            "(event_id, confirmed_by, is_match, reason, timestamp_ns) "
            "VALUES (?, ?, ?, ?, ?)",
            (event_id, confirmed_by, 1 if is_match else 0, reason, time.time_ns()),
        )
        logger.info(
            "Ground truth feedback: event=%s match=%s by=%s",
            event_id,
            is_match,
            confirmed_by,
        )

    def determine_truth(self, event_hash: str) -> Optional[bool]:
        """Determine ground truth for an event.

        Checks cross-agent consensus first, then manual feedback.

        Returns:
            True if event is confirmed real (consensus or manual).
            False if event is confirmed false (manual dismissal).
            None if ground truth not yet determined.
        """
        # Check manual feedback first (takes priority)
        feedback = self._db.execute(
            "SELECT is_match FROM manual_feedback "
            "WHERE event_id = ? ORDER BY id DESC LIMIT 1",
            (event_hash,),
        ).fetchone()
        if feedback is not None:
            return bool(feedback[0])

        # Check cross-agent consensus
        consensus = self.get_consensus(event_hash)
        agent_count = len(consensus)
        if agent_count >= self.consensus_threshold:
            return True

        return None

    def get_consensus(self, event_hash: str) -> Dict[str, int]:
        """Get consensus counts: {agent_id: report_count}.

        Args:
            event_hash: Hash identifying the event.

        Returns:
            Dict mapping agent_id → number of reports for this hash.
        """
        rows = self._db.execute(
            "SELECT agent_id, COUNT(*) FROM event_reports "
            "WHERE event_hash = ? GROUP BY agent_id",
            (event_hash,),
        ).fetchall()
        return {row[0]: row[1] for row in rows}

    def get_agent_report_count(self, agent_id: str) -> int:
        """Get total number of event reports from an agent.

        Args:
            agent_id: Agent identifier.

        Returns:
            Total number of distinct events reported.
        """
        row = self._db.execute(
            "SELECT COUNT(DISTINCT event_hash) FROM event_reports "
            "WHERE agent_id = ?",
            (agent_id,),
        ).fetchone()
        return row[0] if row else 0

    def get_feedback_history(
        self,
        event_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict]:
        """Get feedback history.

        Args:
            event_id: Optional filter by event.
            limit: Maximum records to return.

        Returns:
            List of feedback dicts (newest first).
        """
        if event_id:
            rows = self._db.execute(
                "SELECT event_id, confirmed_by, is_match, reason, timestamp_ns "
                "FROM manual_feedback WHERE event_id = ? "
                "ORDER BY id DESC LIMIT ?",
                (event_id, limit),
            ).fetchall()
        else:
            rows = self._db.execute(
                "SELECT event_id, confirmed_by, is_match, reason, timestamp_ns "
                "FROM manual_feedback "
                "ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()

        return [
            {
                "event_id": r[0],
                "confirmed_by": r[1],
                "is_match": bool(r[2]),
                "reason": r[3],
                "timestamp_ns": r[4],
            }
            for r in rows
        ]

    @staticmethod
    def compute_event_hash(event_content: bytes) -> str:
        """Compute BLAKE2b-256 hash of event content for deduplication.

        Args:
            event_content: Raw event bytes.

        Returns:
            Hex-encoded hash string.
        """
        return hashlib.blake2b(event_content, digest_size=32).hexdigest()

    def close(self) -> None:
        """Close database connection."""
        self._db.close()
