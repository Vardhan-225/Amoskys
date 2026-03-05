"""Reliability Store — SQLite persistence for agent reliability state.

Persists and reloads AMRDR reliability state (α, β, fusion_weight,
drift_type, recalibration_tier) across system restarts.

See AMRDR_Mechanism_Specification_v0.1 Section 7 (Reliability Store).
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from typing import Dict, List, Optional

from amoskys.intel.reliability import DriftType, RecalibrationTier, ReliabilityState

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS agent_reliability (
    agent_id TEXT PRIMARY KEY,
    alpha REAL NOT NULL DEFAULT 1.0,
    beta REAL NOT NULL DEFAULT 1.0,
    fusion_weight REAL NOT NULL DEFAULT 1.0,
    drift_type TEXT NOT NULL DEFAULT 'none',
    recalibration_tier TEXT NOT NULL DEFAULT 'nominal',
    last_updated_ns INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS observation_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    timestamp_ns INTEGER NOT NULL,
    ground_truth_match INTEGER NOT NULL,
    reason TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_obs_agent ON observation_log(agent_id);
CREATE INDEX IF NOT EXISTS idx_obs_ts ON observation_log(timestamp_ns);
"""


class ReliabilityStore:
    """SQLite-backed persistence for agent reliability state.

    Stores per-agent Beta-Binomial parameters, fusion weights, and
    drift/recalibration state. Also maintains an audit log of all
    ground truth observations for debugging and analysis.

    Args:
        db_path: Path to SQLite database file.
    """

    def __init__(self, db_path: str = "data/intel/reliability.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self._db = sqlite3.connect(
            db_path, timeout=5.0, isolation_level=None, check_same_thread=False
        )
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.executescript(SCHEMA)
        logger.info("ReliabilityStore initialized: %s", db_path)

    def save_state(self, agent_id: str, state: ReliabilityState) -> None:
        """Persist agent reliability state (upsert).

        Args:
            agent_id: Agent identifier.
            state: Current reliability state to persist.
        """
        self._db.execute(
            """
            INSERT INTO agent_reliability
                (agent_id, alpha, beta, fusion_weight, drift_type,
                 recalibration_tier, last_updated_ns)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(agent_id) DO UPDATE SET
                alpha = excluded.alpha,
                beta = excluded.beta,
                fusion_weight = excluded.fusion_weight,
                drift_type = excluded.drift_type,
                recalibration_tier = excluded.recalibration_tier,
                last_updated_ns = excluded.last_updated_ns
            """,
            (
                agent_id,
                state.alpha,
                state.beta,
                state.fusion_weight,
                state.drift_type.value,
                state.tier.value,
                state.last_update_ns,
            ),
        )

    def load_state(self, agent_id: str) -> Optional[ReliabilityState]:
        """Load agent reliability state.

        Args:
            agent_id: Agent identifier.

        Returns:
            ReliabilityState if found, None otherwise.
        """
        row = self._db.execute(
            "SELECT agent_id, alpha, beta, fusion_weight, drift_type, "
            "recalibration_tier, last_updated_ns "
            "FROM agent_reliability WHERE agent_id = ?",
            (agent_id,),
        ).fetchone()

        if not row:
            return None

        return ReliabilityState(
            agent_id=row[0],
            alpha=row[1],
            beta=row[2],
            fusion_weight=row[3],
            drift_type=DriftType(row[4]),
            tier=RecalibrationTier(row[5]),
            last_update_ns=row[6],
        )

    def load_all_states(self) -> Dict[str, ReliabilityState]:
        """Load all tracked agents' states.

        Returns:
            Dict mapping agent_id → ReliabilityState.
        """
        rows = self._db.execute(
            "SELECT agent_id, alpha, beta, fusion_weight, drift_type, "
            "recalibration_tier, last_updated_ns "
            "FROM agent_reliability"
        ).fetchall()

        states = {}
        for row in rows:
            states[row[0]] = ReliabilityState(
                agent_id=row[0],
                alpha=row[1],
                beta=row[2],
                fusion_weight=row[3],
                drift_type=DriftType(row[4]),
                tier=RecalibrationTier(row[5]),
                last_update_ns=row[6],
            )
        return states

    def log_observation(
        self,
        agent_id: str,
        match: bool,
        reason: str = "",
    ) -> None:
        """Log a ground truth observation to the audit table.

        Args:
            agent_id: Agent identifier.
            match: True if observation matched ground truth.
            reason: Optional reason string (drift detected, recalibration, etc.)
        """
        self._db.execute(
            "INSERT INTO observation_log "
            "(agent_id, timestamp_ns, ground_truth_match, reason) "
            "VALUES (?, ?, ?, ?)",
            (agent_id, time.time_ns(), 1 if match else 0, reason),
        )

    def get_observation_count(self, agent_id: str) -> int:
        """Get total observation count for an agent.

        Args:
            agent_id: Agent identifier.

        Returns:
            Number of logged observations.
        """
        row = self._db.execute(
            "SELECT COUNT(*) FROM observation_log WHERE agent_id = ?",
            (agent_id,),
        ).fetchone()
        return row[0] if row else 0

    def get_recent_observations(
        self,
        agent_id: str,
        limit: int = 100,
    ) -> List[Dict]:
        """Get recent observations for an agent.

        Args:
            agent_id: Agent identifier.
            limit: Maximum observations to return.

        Returns:
            List of observation dicts (newest first).
        """
        rows = self._db.execute(
            "SELECT agent_id, timestamp_ns, ground_truth_match, reason "
            "FROM observation_log WHERE agent_id = ? "
            "ORDER BY id DESC LIMIT ?",
            (agent_id, limit),
        ).fetchall()

        return [
            {
                "agent_id": r[0],
                "timestamp_ns": r[1],
                "ground_truth_match": bool(r[2]),
                "reason": r[3],
            }
            for r in rows
        ]

    def delete_agent(self, agent_id: str) -> None:
        """Remove all data for an agent.

        Args:
            agent_id: Agent identifier.
        """
        self._db.execute(
            "DELETE FROM agent_reliability WHERE agent_id = ?", (agent_id,)
        )
        self._db.execute("DELETE FROM observation_log WHERE agent_id = ?", (agent_id,))

    def close(self) -> None:
        """Close database connection."""
        self._db.close()
