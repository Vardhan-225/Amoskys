"""Checkpoint Signer — seals segments with Ed25519-signed checkpoint records.

Each checkpoint contains the Merkle root, event count, chain signature
boundaries, and a back-link to the previous checkpoint hash.  Checkpoints
form their own chain: tampering with any historical checkpoint invalidates
all subsequent checkpoints.

Storage: checkpoints are appended to a JSONL manifest file (one JSON
object per line, append-only).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from amoskys.proof.wal_segments import SegmentInfo

logger = logging.getLogger(__name__)

# Genesis checkpoint hash: 32 zero bytes
GENESIS_CHECKPOINT_HASH = b"\x00" * 32


@dataclass
class Checkpoint:
    """A signed checkpoint record for a sealed segment."""

    segment_id: int
    start_seq: int
    end_seq: int
    event_count: int
    first_ts_ns: int
    last_ts_ns: int
    root_hash_hex: str
    first_chain_sig_hex: str
    last_chain_sig_hex: str
    prev_checkpoint_hash_hex: str
    checkpoint_sig_hex: str  # Ed25519 signature over canonical checkpoint bytes
    sealed_at_ns: int


def _checkpoint_canonical_bytes(cp_dict: Dict[str, Any]) -> bytes:
    """Produce deterministic bytes for signing a checkpoint.

    Canonical form is the JSON encoding of all fields *except*
    ``checkpoint_sig_hex`` (which would be circular), sorted by key.
    """
    d = {k: v for k, v in sorted(cp_dict.items()) if k != "checkpoint_sig_hex"}
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hash_checkpoint(cp_dict: Dict[str, Any]) -> bytes:
    """BLAKE2b-256 hash of the full checkpoint record (including its sig)."""
    raw = json.dumps(cp_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.blake2b(raw, digest_size=32).digest()


class CheckpointSigner:
    """Creates and persists Ed25519-signed checkpoint records.

    Args:
        manifest_path: Path to the JSONL checkpoint manifest file.
        signing_key_path: Path to Ed25519 private key (32-byte raw).
            If None or file missing, checkpoints are unsigned
            (checkpoint_sig_hex will be empty string).
    """

    def __init__(
        self,
        manifest_path: str = "data/checkpoints.jsonl",
        signing_key_path: Optional[str] = None,
    ):
        self.manifest_path = manifest_path
        self._signing_key = None
        if signing_key_path:
            try:
                from amoskys.common.crypto.signing import load_private_key

                self._signing_key = load_private_key(signing_key_path)
                logger.info("Checkpoint signing enabled (key: %s)", signing_key_path)
            except Exception as exc:
                logger.warning("Checkpoint signing disabled: %s", exc)

        # Ensure parent directory exists
        os.makedirs(os.path.dirname(self.manifest_path) or ".", exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def seal_segment(
        self,
        segment: SegmentInfo,
        prev_checkpoint_hash: Optional[bytes] = None,
    ) -> Checkpoint:
        """Seal a segment by creating a signed checkpoint record.

        Args:
            segment: SegmentInfo from SegmentManager.scan_segments()
            prev_checkpoint_hash: Hash of previous checkpoint, or None for genesis.

        Returns:
            Checkpoint record (also appended to manifest file).
        """
        prev_hash = prev_checkpoint_hash or GENESIS_CHECKPOINT_HASH

        cp_dict: Dict[str, Any] = {
            "segment_id": segment.segment_id,
            "start_seq": segment.start_seq,
            "end_seq": segment.end_seq,
            "event_count": segment.event_count,
            "first_ts_ns": segment.first_ts_ns,
            "last_ts_ns": segment.last_ts_ns,
            "root_hash_hex": segment.root_hash.hex(),
            "first_chain_sig_hex": segment.first_chain_sig.hex(),
            "last_chain_sig_hex": segment.last_chain_sig.hex(),
            "prev_checkpoint_hash_hex": prev_hash.hex(),
            "checkpoint_sig_hex": "",
            "sealed_at_ns": time.time_ns(),
        }

        # Sign the checkpoint
        if self._signing_key is not None:
            from amoskys.common.crypto.signing import sign

            canonical = _checkpoint_canonical_bytes(cp_dict)
            sig = sign(self._signing_key, canonical)
            cp_dict["checkpoint_sig_hex"] = sig.hex()

        # Append to manifest
        self._append_manifest(cp_dict)

        return Checkpoint(**cp_dict)

    def seal_all(self, segments: List[SegmentInfo]) -> List[Checkpoint]:
        """Seal all segments in order, chaining checkpoint hashes."""
        checkpoints: List[Checkpoint] = []
        prev_hash: Optional[bytes] = None

        for seg in segments:
            cp = self.seal_segment(seg, prev_checkpoint_hash=prev_hash)
            prev_hash = _hash_checkpoint(
                {k: v for k, v in vars(cp).items() if not k.startswith("_")}
            )
            checkpoints.append(cp)

        return checkpoints

    def load_manifest(self) -> List[Dict[str, Any]]:
        """Load all checkpoint records from the manifest file."""
        if not os.path.exists(self.manifest_path):
            return []

        records: List[Dict[str, Any]] = []
        with open(self.manifest_path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records

    def get_last_checkpoint_hash(self) -> bytes:
        """Return the hash of the most recent checkpoint, or genesis hash."""
        records = self.load_manifest()
        if not records:
            return GENESIS_CHECKPOINT_HASH
        return _hash_checkpoint(records[-1])

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _append_manifest(self, cp_dict: Dict[str, Any]) -> None:
        """Append one checkpoint record to the JSONL manifest (atomic)."""
        line = json.dumps(cp_dict, sort_keys=True, separators=(",", ":"))
        with open(self.manifest_path, "a") as f:
            f.write(line + "\n")
        logger.info(
            "Checkpoint sealed: segment=%d events=%d root=%s",
            cp_dict["segment_id"],
            cp_dict["event_count"],
            cp_dict["root_hash_hex"][:16] + "...",
        )


def checkpoint_hash(cp_dict: Dict[str, Any]) -> bytes:
    """Public alias for computing checkpoint hash."""
    return _hash_checkpoint(cp_dict)


def checkpoint_canonical_bytes(cp_dict: Dict[str, Any]) -> bytes:
    """Public alias for computing canonical checkpoint bytes for verification."""
    return _checkpoint_canonical_bytes(cp_dict)


# ---------------------------------------------------------------------------
# Correlation Checkpoints (Sprint 3 — Proof Spine Extension)
# ---------------------------------------------------------------------------


@dataclass
class CorrelationCheckpoint:
    """A signed checkpoint for a batch of correlation outputs.

    Links back to source telemetry checkpoints so tampering at
    any layer is detectable.
    """

    correlation_segment_id: int
    entry_count: int
    first_entry_id: int
    last_entry_id: int
    correlation_root_hash_hex: str  # BLAKE2b root of correlation entries
    telemetry_checkpoint_hashes: List[str]  # hex hashes of source telemetry CPs
    amrdr_weights_snapshot: Dict[str, float]  # weights at checkpoint time
    prev_correlation_cp_hash_hex: str
    checkpoint_sig_hex: str
    sealed_at_ns: int


# Genesis for the correlation checkpoint chain
GENESIS_CORRELATION_CP_HASH = b"\x00" * 32


class CorrelationCheckpointSigner:
    """Creates and persists signed correlation checkpoints.

    Mirrors CheckpointSigner but for correlation WAL entries.
    Stores in a separate JSONL manifest to keep telemetry and
    correlation proof chains independent.

    Args:
        manifest_path: Path to correlation checkpoint JSONL manifest.
        signing_key_path: Path to Ed25519 private key (shared with telemetry signer).
    """

    def __init__(
        self,
        manifest_path: str = "data/correlation_checkpoints.jsonl",
        signing_key_path: Optional[str] = None,
    ):
        self.manifest_path = manifest_path
        self._signing_key = None
        if signing_key_path:
            try:
                from amoskys.common.crypto.signing import load_private_key

                self._signing_key = load_private_key(signing_key_path)
                logger.info(
                    "Correlation checkpoint signing enabled (key: %s)",
                    signing_key_path,
                )
            except Exception as exc:
                logger.warning("Correlation checkpoint signing disabled: %s", exc)

        os.makedirs(os.path.dirname(self.manifest_path) or ".", exist_ok=True)

    def seal_correlation_segment(
        self,
        segment_id: int,
        entry_count: int,
        first_entry_id: int,
        last_entry_id: int,
        root_hash: bytes,
        telemetry_checkpoint_hashes: List[str],
        amrdr_weights: Dict[str, float],
        prev_cp_hash: Optional[bytes] = None,
    ) -> CorrelationCheckpoint:
        """Seal a batch of correlation WAL entries.

        Args:
            segment_id: Correlation segment identifier.
            entry_count: Number of entries in this segment.
            first_entry_id: First WAL entry ID in segment.
            last_entry_id: Last WAL entry ID in segment.
            root_hash: BLAKE2b Merkle root of entries.
            telemetry_checkpoint_hashes: Hex hashes of source telemetry CPs.
            amrdr_weights: Agent reliability weights at checkpoint time.
            prev_cp_hash: Hash of previous correlation checkpoint (or genesis).

        Returns:
            CorrelationCheckpoint record (also appended to manifest).
        """
        prev_hash = prev_cp_hash or GENESIS_CORRELATION_CP_HASH

        cp_dict: Dict[str, Any] = {
            "correlation_segment_id": segment_id,
            "entry_count": entry_count,
            "first_entry_id": first_entry_id,
            "last_entry_id": last_entry_id,
            "correlation_root_hash_hex": root_hash.hex(),
            "telemetry_checkpoint_hashes": telemetry_checkpoint_hashes,
            "amrdr_weights_snapshot": amrdr_weights,
            "prev_correlation_cp_hash_hex": prev_hash.hex(),
            "checkpoint_sig_hex": "",
            "sealed_at_ns": time.time_ns(),
        }

        # Sign
        if self._signing_key is not None:
            from amoskys.common.crypto.signing import sign

            canonical = _checkpoint_canonical_bytes(cp_dict)
            sig = sign(self._signing_key, canonical)
            cp_dict["checkpoint_sig_hex"] = sig.hex()

        # Persist
        self._append_manifest(cp_dict)

        return CorrelationCheckpoint(**cp_dict)

    def load_manifest(self) -> List[Dict[str, Any]]:
        """Load all correlation checkpoint records."""
        if not os.path.exists(self.manifest_path):
            return []

        records: List[Dict[str, Any]] = []
        with open(self.manifest_path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records

    def get_last_checkpoint_hash(self) -> bytes:
        """Return hash of most recent correlation checkpoint, or genesis."""
        records = self.load_manifest()
        if not records:
            return GENESIS_CORRELATION_CP_HASH
        return _hash_checkpoint(records[-1])

    def _append_manifest(self, cp_dict: Dict[str, Any]) -> None:
        """Append one correlation checkpoint to JSONL manifest."""
        line = json.dumps(cp_dict, sort_keys=True, separators=(",", ":"))
        with open(self.manifest_path, "a") as f:
            f.write(line + "\n")
        logger.info(
            "Correlation checkpoint sealed: segment=%d entries=%d",
            cp_dict["correlation_segment_id"],
            cp_dict["entry_count"],
        )
