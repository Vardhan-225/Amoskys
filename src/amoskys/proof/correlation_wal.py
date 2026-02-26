"""Append-only WAL for correlation outputs with BLAKE2b hash chain linking.

This module implements a durable write-ahead log (WAL) using SQLite to store
correlation outputs (incidents and risk snapshots) with cryptographic integrity.
The WAL provides a tamper-evident log of all correlation decisions.

Key Features:
    - Idempotency: Duplicate writes (same idem key) are automatically deduplicated
    - Hash Chain: BLAKE2b-based chain signature linking all entries
    - Integrity: Full chain verification with break-point detection
    - Durability: Uses SQLite WAL mode with synchronous=FULL for crash safety
    - Metadata: Stores source segment IDs, rule names, and correlation parameters

Design:
    Each correlation output (incident or risk snapshot) is serialized as canonical
    JSON bytes, stored with a BLAKE2b checksum, and chain-linked using the formula:
        sig = BLAKE2b(prev_sig || output_bytes)

    The GENESIS_SIG (64 zero bytes) serves as the chain start. The chain can be
    verified at any time to detect tampering or deletion.

    SQLite's native WAL mode ensures our correlation WAL is durable and provides
    crash resistance and better concurrency.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
from typing import Any

logger = logging.getLogger(__name__)

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
CREATE TABLE IF NOT EXISTS correlation_wal (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  idem TEXT NOT NULL,
  ts_ns INTEGER NOT NULL,
  output_type TEXT NOT NULL,
  output_bytes BLOB NOT NULL,
  checksum TEXT NOT NULL,
  sig TEXT NOT NULL,
  prev_sig TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS correlation_wal_idem ON correlation_wal(idem);
CREATE INDEX IF NOT EXISTS correlation_wal_ts ON correlation_wal(ts_ns);
CREATE INDEX IF NOT EXISTS correlation_wal_type ON correlation_wal(output_type);
"""

# Genesis signature: 64 zero bytes (well-known chain start)
GENESIS_SIG = b"\x00" * 64


def _compute_chain_sig(output_bytes: bytes, prev_sig: bytes) -> bytes:
    """Compute hash chain signature: BLAKE2b(output_bytes || prev_sig).

    Each WAL row's signature chains to the previous, creating a tamper-evident
    log. If any row is modified, deleted, or reordered, the chain breaks.

    Args:
        output_bytes: Serialized correlation output (canonical JSON bytes)
        prev_sig: Previous entry's signature (or GENESIS_SIG for first entry)

    Returns:
        bytes: 64-byte BLAKE2b digest (digest_size=64)
    """
    return hashlib.blake2b(output_bytes + prev_sig, digest_size=64).digest()


def _canonical_json(obj: dict[str, Any]) -> bytes:
    """Serialize object to canonical JSON bytes (sorted keys, no whitespace).

    Ensures deterministic serialization for integrity checking.

    Args:
        obj: Python dictionary to serialize

    Returns:
        bytes: UTF-8 encoded canonical JSON
    """
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


class CorrelationWALWriter:
    """Write-ahead log for durable correlation output storage.

    Provides persistent append-only log for incidents and risk snapshots with
    BLAKE2b hash chain linking for integrity verification. Thread-safe for
    single writer, multiple readers.

    Attributes:
        path (str): Path to SQLite database file
        db (sqlite3.Connection): Database connection with auto-commit
    """

    def __init__(self, path: str = "data/intel/correlation_wal.db") -> None:
        """Initialize Correlation WAL with durability guarantees.

        Creates database file and schema if not exists. Sets up WAL mode
        and full synchronization for crash safety.

        Args:
            path: Filesystem path for WAL database
                (default: "data/intel/correlation_wal.db")

        Notes:
            - Parent directories are created automatically
            - Timeout is set to 5 seconds for lock contention
            - isolation_level=None enables auto-commit mode
            - BLAKE2b chain signatures use 64-byte digests
        """
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.path = path
        self._lock = threading.RLock()
        self.db = sqlite3.connect(
            self.path, timeout=5.0, isolation_level=None, check_same_thread=False
        )
        self.db.executescript(SCHEMA)

    def _get_last_sig(self) -> bytes:
        """Return the sig of the most recent WAL entry, or GENESIS_SIG if empty.

        Returns:
            bytes: 64-byte signature from last entry, or GENESIS_SIG
        """
        row = self.db.execute(
            "SELECT sig FROM correlation_wal ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row and row[0]:
            sig_str = row[0]
            # Handle both binary and hex-string storage
            if isinstance(sig_str, bytes):
                return sig_str
            else:
                return bytes.fromhex(sig_str)
        return GENESIS_SIG

    def append_incident(
        self,
        incident_dict: dict[str, Any],
        source_segment_ids: list[str],
        rule_name: str,
        rule_params: dict[str, Any],
    ) -> str:
        """Append incident to WAL with metadata and hash chain.

        Serializes incident along with metadata (source segments, rule info)
        as canonical JSON, computes BLAKE2b checksum, and chain-signs.

        Args:
            incident_dict: Incident data (e.g., detector name, confidence, etc.)
            source_segment_ids: List of segment IDs that triggered this incident
            rule_name: Name of correlation rule that produced this incident
            rule_params: Rule parameters (e.g., thresholds, time windows)

        Returns:
            str: Idempotency key (UUID-like) for this incident

        Behavior:
            - Duplicate idem keys: Silently skipped (returns same key)
            - Chain integrity: Each entry links to previous via BLAKE2b
            - Idempotency: Caller should use incident timestamp + rule as key

        Raises:
            sqlite3.DatabaseError: On database corruption or disk full
        """
        # Build complete output object with metadata
        output = {
            "type": "incident",
            "incident": incident_dict,
            "source_segment_ids": source_segment_ids,
            "rule_name": rule_name,
            "rule_params": rule_params,
        }

        # Generate idempotency key from incident timestamp and rule name
        # Caller should ensure incident_dict contains 'ts_ns'
        ts_ns = incident_dict.get("ts_ns", int(time.time() * 1e9))
        idem = f"incident_{rule_name}_{ts_ns}"

        # Serialize to canonical JSON and compute checksum
        output_bytes = _canonical_json(output)
        checksum = hashlib.blake2b(output_bytes, digest_size=64).hexdigest()

        with self._lock:
            prev_sig = self._get_last_sig()
            sig = _compute_chain_sig(output_bytes, prev_sig)
            sig_hex = sig.hex()
            prev_sig_hex = prev_sig.hex()

            try:
                self.db.execute(
                    "INSERT INTO correlation_wal"
                    "(idem, ts_ns, output_type, output_bytes, checksum, sig, prev_sig) "
                    "VALUES(?, ?, ?, ?, ?, ?, ?)",
                    (
                        idem,
                        ts_ns,
                        "incident",
                        output_bytes,
                        checksum,
                        sig_hex,
                        prev_sig_hex,
                    ),
                )
                logger.info(
                    "Appended incident to correlation WAL: rule=%s, idem=%s",
                    rule_name,
                    idem,
                )
                return idem
            except sqlite3.IntegrityError:
                logger.debug("Duplicate incident (idem=%s), skipped", idem)
                return idem

    def append_risk_snapshot(
        self,
        snapshot_dict: dict[str, Any],
        source_segment_ids: list[str],
    ) -> str:
        """Append risk snapshot to WAL with metadata and hash chain.

        Serializes risk snapshot along with metadata (source segments)
        as canonical JSON, computes BLAKE2b checksum, and chain-signs.

        Args:
            snapshot_dict: Risk snapshot data (e.g., asset_id, risk_score, etc.)
            source_segment_ids: List of segment IDs used to compute this snapshot

        Returns:
            str: Idempotency key (UUID-like) for this snapshot

        Behavior:
            - Duplicate idem keys: Silently skipped (returns same key)
            - Chain integrity: Each entry links to previous via BLAKE2b
            - Idempotency: Caller should use asset + timestamp as key

        Raises:
            sqlite3.DatabaseError: On database corruption or disk full
        """
        # Build complete output object with metadata
        output = {
            "type": "risk_snapshot",
            "snapshot": snapshot_dict,
            "source_segment_ids": source_segment_ids,
        }

        # Generate idempotency key from asset ID and snapshot timestamp
        ts_ns = snapshot_dict.get("ts_ns", int(time.time() * 1e9))
        asset_id = snapshot_dict.get("asset_id", "unknown")
        idem = f"risk_{asset_id}_{ts_ns}"

        # Serialize to canonical JSON and compute checksum
        output_bytes = _canonical_json(output)
        checksum = hashlib.blake2b(output_bytes, digest_size=64).hexdigest()

        with self._lock:
            prev_sig = self._get_last_sig()
            sig = _compute_chain_sig(output_bytes, prev_sig)
            sig_hex = sig.hex()
            prev_sig_hex = prev_sig.hex()

            try:
                self.db.execute(
                    "INSERT INTO correlation_wal"
                    "(idem, ts_ns, output_type, output_bytes, checksum, sig, prev_sig) "
                    "VALUES(?, ?, ?, ?, ?, ?, ?)",
                    (
                        idem,
                        ts_ns,
                        "risk_snapshot",
                        output_bytes,
                        checksum,
                        sig_hex,
                        prev_sig_hex,
                    ),
                )
                logger.info(
                    "Appended risk snapshot to correlation WAL: asset=%s, idem=%s",
                    asset_id,
                    idem,
                )
                return idem
            except sqlite3.IntegrityError:
                logger.debug("Duplicate risk snapshot (idem=%s), skipped", idem)
                return idem

    def get_entries(
        self, start_id: int | None = None, limit: int = 1000
    ) -> list[dict[str, Any]]:
        """Read entries from WAL in insertion order.

        Fetches up to `limit` entries from the WAL, optionally starting after
        a specific entry ID. Entries are returned in FIFO order (oldest first).

        Args:
            start_id: If provided, only return entries with id > start_id
            limit: Maximum number of entries to return (default: 1000)

        Returns:
            list[dict]: List of WAL entries with keys:
                - id: Entry ID
                - idem: Idempotency key
                - ts_ns: Timestamp in nanoseconds
                - output_type: "incident" or "risk_snapshot"
                - output_bytes: Serialized JSON bytes
                - checksum: BLAKE2b checksum (hex string)
                - sig: Chain signature (hex string)
                - prev_sig: Previous signature (hex string)

        Example:
            >>> entries = wal.get_entries(limit=100)
            >>> for entry in entries:
            ...     print(f"ID {entry['id']}: {entry['idem']}")
        """
        with self._lock:
            if start_id is None:
                rows = self.db.execute(
                    "SELECT id, idem, ts_ns, output_type, output_bytes, checksum, sig, prev_sig "
                    "FROM correlation_wal ORDER BY id LIMIT ?",
                    (limit,),
                ).fetchall()
            else:
                rows = self.db.execute(
                    "SELECT id, idem, ts_ns, output_type, output_bytes, checksum, sig, prev_sig "
                    "FROM correlation_wal WHERE id > ? ORDER BY id LIMIT ?",
                    (start_id, limit),
                ).fetchall()

        entries = []
        for row in rows:
            entries.append(
                {
                    "id": row[0],
                    "idem": row[1],
                    "ts_ns": row[2],
                    "output_type": row[3],
                    "output_bytes": bytes(row[4]) if row[4] else b"",
                    "checksum": row[5],
                    "sig": row[6],
                    "prev_sig": row[7],
                }
            )
        return entries

    def count(self) -> int:
        """Return total number of entries in WAL.

        Returns:
            int: Number of entries in correlation_wal table
        """
        with self._lock:
            row = self.db.execute("SELECT COUNT(*) FROM correlation_wal").fetchone()
        return int(row[0] or 0)

    def verify_chain(self) -> tuple[bool, int | None]:
        """Verify BLAKE2b hash chain integrity.

        Walks the entire WAL and verifies that each entry's signature
        correctly chains to the previous entry. Returns success status
        and the ID of the first broken link (if any).

        Chain verification formula:
            For each entry: sig == BLAKE2b(output_bytes || prev_sig)

        Returns:
            tuple[bool, int | None]:
                - (True, None): Chain is intact from genesis to current end
                - (False, break_id): Chain breaks at entry with id=break_id

        Example:
            >>> ok, break_id = wal.verify_chain()
            >>> if not ok:
            ...     print(f"Chain break detected at entry {break_id}")

        Notes:
            - Uses GENESIS_SIG as chain start
            - Verifies all entries (no limit)
            - Thread-safe (uses lock)
        """
        with self._lock:
            entries = self.db.execute(
                "SELECT id, output_bytes, sig, prev_sig FROM correlation_wal ORDER BY id"
            ).fetchall()

        expected_prev_sig = GENESIS_SIG
        for entry_id, output_bytes, sig_hex, prev_sig_hex in entries:
            # Convert hex strings back to bytes
            try:
                sig = bytes.fromhex(sig_hex)
                prev_sig = bytes.fromhex(prev_sig_hex)
            except (ValueError, TypeError) as e:
                logger.error(
                    "Chain verification failed at id=%d: invalid hex format: %s",
                    entry_id,
                    e,
                )
                return False, entry_id

            # Verify prev_sig matches expected
            if prev_sig != expected_prev_sig:
                logger.error(
                    "Chain verification failed at id=%d: prev_sig mismatch",
                    entry_id,
                )
                return False, entry_id

            # Recompute signature and verify
            output_bytes_bin = bytes(output_bytes) if output_bytes else b""
            expected_sig = _compute_chain_sig(output_bytes_bin, prev_sig)
            if sig != expected_sig:
                logger.error(
                    "Chain verification failed at id=%d: signature mismatch", entry_id
                )
                return False, entry_id

            expected_prev_sig = sig

        logger.info(
            "Chain verification complete: %d entries, chain intact",
            self.count(),
        )
        return True, None
