"""Merkle tree construction and proof generation.

Binary Merkle tree over BLAKE2b-256 leaf hashes.  Odd leaf counts are
padded by duplicating the last leaf (standard Merkle padding).
"""

from __future__ import annotations

import hashlib
import struct
from typing import List, Optional, Tuple


def _b2b(data: bytes) -> bytes:
    """BLAKE2b-256 helper."""
    return hashlib.blake2b(data, digest_size=32).digest()


def leaf_hash(canonical_bytes: bytes, row_index: int, prev_sig: bytes) -> bytes:
    """Compute leaf hash for a single event.

    leaf = BLAKE2b-256(canonical_bytes || row_index_be8 || prev_sig)
    """
    idx_bytes = struct.pack(">Q", row_index)  # 8-byte big-endian
    return _b2b(canonical_bytes + idx_bytes + prev_sig)


def _internal_hash(left: bytes, right: bytes) -> bytes:
    return _b2b(left + right)


def build_tree(leaves: List[bytes]) -> List[List[bytes]]:
    """Build a full binary Merkle tree from leaf hashes.

    Returns list of levels (level 0 = leaves, last level = [root]).
    Odd leaf count at any level is handled by duplicating the last node.
    """
    if not leaves:
        raise ValueError("Cannot build Merkle tree from empty leaf list")

    levels: List[List[bytes]] = [list(leaves)]

    current = list(leaves)
    while len(current) > 1:
        if len(current) % 2 == 1:
            current.append(current[-1])  # duplicate last
        next_level = []
        for i in range(0, len(current), 2):
            next_level.append(_internal_hash(current[i], current[i + 1]))
        levels.append(next_level)
        current = next_level

    return levels


def root_hash(leaves: List[bytes]) -> bytes:
    """Compute the Merkle root from leaf hashes."""
    tree = build_tree(leaves)
    return tree[-1][0]


def inclusion_proof(leaves: List[bytes], index: int) -> List[Tuple[bytes, str]]:
    """Generate a Merkle inclusion proof for the leaf at *index*.

    Returns a list of (sibling_hash, side) tuples where side is 'L' or 'R',
    indicating whether the sibling is on the left or right.
    """
    if index < 0 or index >= len(leaves):
        raise IndexError(f"Leaf index {index} out of range [0, {len(leaves)})")

    tree = build_tree(leaves)
    proof: List[Tuple[bytes, str]] = []

    idx = index
    for level in tree[:-1]:  # skip root level
        padded = list(level)
        if len(padded) % 2 == 1:
            padded.append(padded[-1])

        if idx % 2 == 0:
            sibling = padded[idx + 1]
            proof.append((sibling, "R"))
        else:
            sibling = padded[idx - 1]
            proof.append((sibling, "L"))
        idx //= 2

    return proof


def verify_inclusion(
    leaf: bytes,
    proof: List[Tuple[bytes, str]],
    expected_root: bytes,
) -> bool:
    """Verify a Merkle inclusion proof against an expected root."""
    current = leaf
    for sibling, side in proof:
        if side == "L":
            current = _internal_hash(sibling, current)
        else:
            current = _internal_hash(current, sibling)
    return current == expected_root
