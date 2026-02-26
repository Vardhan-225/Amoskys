"""Evidence Chain module for linking correlations to source telemetry segments.

This module provides the EvidenceChain class for recording and verifying the
integrity of correlation outputs (incidents, risk snapshots) against their
source telemetry segments and checkpoint hashes.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

logger = logging.getLogger(__name__)


class EvidenceChain:
    """Manages evidence chain linking correlations to source telemetry segments.

    The Evidence Chain records the complete provenance of correlation outputs,
    including source segment IDs, checkpoint hashes at correlation time, and
    AMRDR weights. It supports verification of data integrity by comparing
    stored checkpoint hashes against current ones to detect tampering.

    Attributes:
        db_path: Path to the SQLite database file.
    """

    def __init__(self, db_path: str | Path = "data/intel/evidence_chain.db") -> None:
        """Initialize the Evidence Chain with database path.

        Args:
            db_path: Path to the SQLite database file. Defaults to
                'data/intel/evidence_chain.db'.
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the database schema if it doesn't exist."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS evidence_chain (
                    evidence_id TEXT PRIMARY KEY,
                    correlation_id TEXT NOT NULL,
                    correlation_type TEXT NOT NULL,
                    source_segment_ids TEXT NOT NULL,
                    source_checkpoint_hashes TEXT NOT NULL,
                    amrdr_weights TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    created_at_ns INTEGER NOT NULL
                )
                """)
            conn.commit()
            logger.debug(f"Evidence Chain database initialized at {self.db_path}")
        finally:
            conn.close()

    def record_evidence(
        self,
        correlation_id: str,
        correlation_type: str,
        source_segment_ids: list[int],
        source_checkpoint_hashes: list[str],
        amrdr_weights: dict[str, float],
        rule_name: str,
    ) -> str:
        """Record evidence linking a correlation to its source telemetry.

        Args:
            correlation_id: ID of the correlation (incident_id or device_id
                for risk snapshots).
            correlation_type: Type of correlation: 'incident' or 'risk_snapshot'.
            source_segment_ids: List of segment IDs that contributed to the
                correlation.
            source_checkpoint_hashes: List of checkpoint hashes (hex strings) at
                the time of correlation, one per source segment.
            amrdr_weights: Dictionary mapping agent_id to weight at correlation
                time.
            rule_name: Name of the rule that triggered the correlation.

        Returns:
            The generated evidence_id (UUID).

        Raises:
            ValueError: If source_segment_ids and source_checkpoint_hashes have
                mismatched lengths.
            sqlite3.Error: If database operation fails.
        """
        if len(source_segment_ids) != len(source_checkpoint_hashes):
            raise ValueError(
                f"Mismatched lengths: {len(source_segment_ids)} segment IDs vs "
                f"{len(source_checkpoint_hashes)} checkpoint hashes"
            )

        evidence_id = str(uuid4())
        created_at_ns = int(datetime.utcnow().timestamp() * 1e9)

        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO evidence_chain
                (evidence_id, correlation_id, correlation_type,
                 source_segment_ids, source_checkpoint_hashes,
                 amrdr_weights, rule_name, created_at_ns)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evidence_id,
                    correlation_id,
                    correlation_type,
                    json.dumps(source_segment_ids),
                    json.dumps(source_checkpoint_hashes),
                    json.dumps(amrdr_weights),
                    rule_name,
                    created_at_ns,
                ),
            )
            conn.commit()
            logger.info(
                f"Recorded evidence {evidence_id} for correlation {correlation_id}"
            )
            return evidence_id
        finally:
            conn.close()

    def verify_evidence(
        self, correlation_id: str, current_checkpoint_hashes: dict[int, str]
    ) -> tuple[bool, list[dict[str, Any]]]:
        """Verify the integrity of evidence against current checkpoint hashes.

        Compares stored checkpoint hashes at correlation time against current
        hashes. Mismatches indicate potential tampering of telemetry data
        after the correlation was recorded.

        Args:
            correlation_id: ID of the correlation to verify.
            current_checkpoint_hashes: Dictionary mapping segment_id to current
                checkpoint hash (hex string).

        Returns:
            Tuple of (ok, mismatches) where:
            - ok: bool indicating whether all hashes match (True) or not (False)
            - mismatches: list of dicts with keys 'segment_id', 'stored_hash',
              'current_hash' for each mismatch. Empty if ok=True.
        """
        evidence = self.get_evidence(correlation_id)
        if not evidence:
            logger.warning(f"No evidence found for correlation {correlation_id}")
            return False, []

        source_segment_ids: list[int] = json.loads(evidence["source_segment_ids"])
        stored_hashes: list[str] = json.loads(evidence["source_checkpoint_hashes"])

        mismatches: list[dict[str, Any]] = []
        for segment_id, stored_hash in zip(source_segment_ids, stored_hashes):
            current_hash = current_checkpoint_hashes.get(segment_id)
            if current_hash is None:
                mismatches.append(
                    {
                        "segment_id": segment_id,
                        "stored_hash": stored_hash,
                        "current_hash": None,
                        "status": "missing",
                    }
                )
            elif current_hash != stored_hash:
                mismatches.append(
                    {
                        "segment_id": segment_id,
                        "stored_hash": stored_hash,
                        "current_hash": current_hash,
                        "status": "mismatch",
                    }
                )

        ok = len(mismatches) == 0
        if not ok:
            logger.warning(
                f"Evidence verification failed for {correlation_id}: "
                f"{len(mismatches)} mismatches"
            )
        else:
            logger.info(f"Evidence verification passed for {correlation_id}")

        return ok, mismatches

    def get_evidence(self, correlation_id: str) -> dict[str, Any] | None:
        """Retrieve evidence record by correlation ID.

        Args:
            correlation_id: ID of the correlation.

        Returns:
            Dictionary with evidence data or None if not found. Keys include
            'evidence_id', 'correlation_id', 'correlation_type',
            'source_segment_ids', 'source_checkpoint_hashes', 'amrdr_weights',
            'rule_name', 'created_at_ns'.
        """
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM evidence_chain WHERE correlation_id = ?",
                (correlation_id,),
            )
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None
        finally:
            conn.close()

    def get_evidence_by_segment(self, segment_id: int) -> list[dict[str, Any]]:
        """Retrieve all evidence records referencing a specific segment.

        Args:
            segment_id: ID of the segment.

        Returns:
            List of evidence dictionaries that reference this segment ID.
        """
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM evidence_chain")
            rows = cursor.fetchall()

            results: list[dict[str, Any]] = []
            for row in rows:
                row_dict = dict(row)
                source_segment_ids: list[int] = json.loads(
                    row_dict["source_segment_ids"]
                )
                if segment_id in source_segment_ids:
                    results.append(row_dict)

            logger.info(
                f"Found {len(results)} evidence records referencing segment {segment_id}"
            )
            return results
        finally:
            conn.close()

    def count(self) -> int:
        """Count total evidence records in the database.

        Returns:
            Total number of evidence records.
        """
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM evidence_chain")
            count = cursor.fetchone()[0]
            return count
        finally:
            conn.close()
