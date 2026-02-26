"""Inclusion proof generator — prove an event exists in a sealed segment.

Given an event and a checkpoint, generates a Merkle path from the leaf
to the root and verifies it against the checkpoint's root_hash.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Any, Dict, List, Optional, Tuple

from amoskys.proof.merkle import inclusion_proof, leaf_hash, verify_inclusion
from amoskys.proof.wal_segments import GENESIS_SIG, SegmentManager


def prove_event_inclusion(
    env_bytes: bytes,
    row_index: int,
    prev_sig: bytes,
    segment_leaves: List[bytes],
    expected_root: bytes,
) -> Dict[str, Any]:
    """Generate and verify an inclusion proof for a single event.

    Args:
        env_bytes: Canonical serialized envelope bytes.
        row_index: 0-based index of the event within its segment.
        prev_sig: The prev_sig field from the WAL row.
        segment_leaves: All leaf hashes for the segment.
        expected_root: The Merkle root from the checkpoint.

    Returns:
        dict with:
            - valid (bool): True if the event is provably in the segment.
            - leaf_hex (str): Hex of the computed leaf hash.
            - proof (list): List of (sibling_hex, side) tuples.
            - root_hex (str): Hex of the expected root.
    """
    lh = leaf_hash(env_bytes, row_index, prev_sig)
    proof = inclusion_proof(segment_leaves, row_index)
    valid = verify_inclusion(lh, proof, expected_root)

    return {
        "valid": valid,
        "leaf_hex": lh.hex(),
        "proof": [(sib.hex(), side) for sib, side in proof],
        "root_hex": expected_root.hex(),
    }


def prove_from_wal(
    wal_path: str,
    target_row_id: int,
    segment_size: int = 1000,
) -> Dict[str, Any]:
    """High-level: prove a specific WAL row_id is included in its segment.

    Scans the WAL, finds the segment containing the target row, and
    generates an inclusion proof.

    Args:
        wal_path: Path to the WAL SQLite database.
        target_row_id: The WAL row id to prove.
        segment_size: Events per segment (must match checkpoint config).

    Returns:
        dict with: valid, segment_id, leaf_hex, proof, root_hex, event_count.

    Raises:
        ValueError: If the row_id is not found in any segment.
    """
    mgr = SegmentManager(wal_path, segment_size=segment_size)
    segments = mgr.scan_segments()

    for seg in segments:
        events = mgr.get_segment_events(seg.segment_id)
        for local_idx, evt in enumerate(events):
            if evt["row_id"] == target_row_id:
                result = prove_event_inclusion(
                    env_bytes=evt["env_bytes"],
                    row_index=local_idx,
                    prev_sig=evt["prev_sig"] or GENESIS_SIG,
                    segment_leaves=seg.leaf_hashes,
                    expected_root=seg.root_hash,
                )
                result["segment_id"] = seg.segment_id
                result["event_count"] = seg.event_count
                return result

    raise ValueError(f"Row {target_row_id} not found in any segment")
