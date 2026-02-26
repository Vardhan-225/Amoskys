"""Absence proof — detect missing events in a sealed segment.

Compares a checkpoint's declared event_count and chain signature
boundaries against the actual WAL rows to detect deletions, insertions,
or modifications.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from amoskys.proof.merkle import leaf_hash, root_hash
from amoskys.proof.wal_segments import GENESIS_SIG, SegmentManager


def detect_absence(
    checkpoint: Dict[str, Any],
    actual_events: List[Dict],
) -> Dict[str, Any]:
    """Compare a checkpoint against actual WAL events to detect tampering.

    Args:
        checkpoint: Checkpoint dict with root_hash_hex, event_count,
            first_chain_sig_hex, last_chain_sig_hex.
        actual_events: List of event dicts from SegmentManager.get_segment_events().

    Returns:
        dict with:
            - intact (bool): True if no tampering detected.
            - count_match (bool): event_count matches actual row count.
            - root_match (bool): Recomputed Merkle root matches checkpoint.
            - first_sig_match (bool): First chain sig matches.
            - last_sig_match (bool): Last chain sig matches.
            - expected_count (int): Checkpoint's declared event count.
            - actual_count (int): Number of rows found.
            - issues (list[str]): Human-readable list of problems.
    """
    issues: List[str] = []
    expected_count = checkpoint["event_count"]
    actual_count = len(actual_events)

    # --- Count check ---
    count_match = expected_count == actual_count
    if not count_match:
        issues.append(
            f"Count mismatch: checkpoint declares {expected_count} events, "
            f"found {actual_count}"
        )

    # --- Merkle root check ---
    root_match = False
    if actual_events:
        leaves = []
        for local_idx, evt in enumerate(actual_events):
            prev_sig = evt.get("prev_sig") or GENESIS_SIG
            if isinstance(prev_sig, str):
                prev_sig = bytes.fromhex(prev_sig)
            env_bytes = evt.get("env_bytes", b"")
            if isinstance(env_bytes, str):
                env_bytes = bytes.fromhex(env_bytes)
            leaves.append(leaf_hash(env_bytes, local_idx, prev_sig))

        recomputed_root = root_hash(leaves)
        expected_root = bytes.fromhex(checkpoint["root_hash_hex"])
        root_match = recomputed_root == expected_root
        if not root_match:
            issues.append(
                f"Merkle root mismatch: checkpoint={checkpoint['root_hash_hex'][:16]}... "
                f"recomputed={recomputed_root.hex()[:16]}..."
            )
    elif expected_count > 0:
        issues.append("No events found but checkpoint declares non-zero count")

    # --- Chain signature boundary checks ---
    first_sig_match = True
    last_sig_match = True

    if actual_events:
        first_sig = actual_events[0].get("sig") or GENESIS_SIG
        if isinstance(first_sig, str):
            first_sig = bytes.fromhex(first_sig)
        expected_first = bytes.fromhex(checkpoint["first_chain_sig_hex"])
        first_sig_match = first_sig == expected_first
        if not first_sig_match:
            issues.append("First chain signature does not match checkpoint")

        last_sig = actual_events[-1].get("sig") or GENESIS_SIG
        if isinstance(last_sig, str):
            last_sig = bytes.fromhex(last_sig)
        expected_last = bytes.fromhex(checkpoint["last_chain_sig_hex"])
        last_sig_match = last_sig == expected_last
        if not last_sig_match:
            issues.append("Last chain signature does not match checkpoint")

    intact = count_match and root_match and first_sig_match and last_sig_match

    return {
        "intact": intact,
        "count_match": count_match,
        "root_match": root_match,
        "first_sig_match": first_sig_match,
        "last_sig_match": last_sig_match,
        "expected_count": expected_count,
        "actual_count": actual_count,
        "issues": issues,
    }
