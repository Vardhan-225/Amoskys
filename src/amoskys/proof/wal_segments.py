"""WAL Segment Manager — partitions WAL events into fixed segments.

Each segment contains a bounded number of events (default: 1000) or spans
a bounded time window (default: 5 minutes).  When a segment is sealed it
becomes immutable and a Merkle root is computed over its canonical events.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from amoskys.proof.merkle import build_tree, leaf_hash, root_hash

logger = logging.getLogger(__name__)

# Genesis previous-signature: 32 zero bytes
GENESIS_SIG = b"\x00" * 32

DEFAULT_SEGMENT_SIZE = 1000  # events per segment
DEFAULT_SEGMENT_WINDOW_NS = 5 * 60 * 10**9  # 5 minutes in nanoseconds


@dataclass
class SegmentInfo:
    """Metadata for a sealed segment."""

    segment_id: int
    start_seq: int
    end_seq: int
    event_count: int
    first_ts_ns: int
    last_ts_ns: int
    root_hash: bytes
    first_chain_sig: bytes
    last_chain_sig: bytes
    leaf_hashes: List[bytes] = field(default_factory=list)


class SegmentManager:
    """Manages WAL segmentation and Merkle root computation.

    Reads the WAL SQLite database, partitions rows into segments of
    *segment_size* events, and computes per-segment Merkle trees.

    The manager is **read-only** — it never modifies the WAL database.
    """

    def __init__(
        self,
        wal_path: str,
        segment_size: int = DEFAULT_SEGMENT_SIZE,
        segment_window_ns: int = DEFAULT_SEGMENT_WINDOW_NS,
    ):
        self.wal_path = wal_path
        self.segment_size = segment_size
        self.segment_window_ns = segment_window_ns

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_segments(self) -> List[SegmentInfo]:
        """Scan the WAL and partition rows into segments.

        Returns a list of SegmentInfo objects, one per segment.
        Segments are computed from WAL rows ordered by ``id``.
        """
        rows = self._read_wal_rows()
        if not rows:
            return []

        segments: List[SegmentInfo] = []
        seg_start = 0

        while seg_start < len(rows):
            seg_end = min(seg_start + self.segment_size, len(rows))

            # Also respect time window: if the segment spans > window, cut earlier
            first_ts = rows[seg_start][2]  # ts_ns
            for i in range(seg_start, seg_end):
                if rows[i][2] - first_ts > self.segment_window_ns:
                    seg_end = i
                    break

            if seg_end <= seg_start:
                seg_end = seg_start + 1  # at least one event per segment

            segment_rows = rows[seg_start:seg_end]
            seg_info = self._build_segment(len(segments), segment_rows, seg_start)
            segments.append(seg_info)
            seg_start = seg_end

        return segments

    def get_segment_events(self, segment_id: int) -> List[Dict]:
        """Return raw event data for a specific segment.

        Each dict contains: row_id, idem, ts_ns, env_bytes, sig, prev_sig.
        """
        rows = self._read_wal_rows()
        segments = self.scan_segments()

        if segment_id < 0 or segment_id >= len(segments):
            raise IndexError(f"Segment {segment_id} not found")

        seg = segments[segment_id]
        events = []
        for row in rows:
            row_id = row[0]
            if row_id < seg.start_seq or row_id > seg.end_seq:
                continue
            events.append(
                {
                    "row_id": row[0],
                    "idem": row[1],
                    "ts_ns": row[2],
                    "env_bytes": row[3],
                    "sig": row[4],
                    "prev_sig": row[5],
                }
            )
        return events

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _read_wal_rows(
        self,
    ) -> List[Tuple[int, str, int, bytes, bytes, bytes]]:
        """Read all WAL rows as (id, idem, ts_ns, bytes, sig, prev_sig)."""
        conn = sqlite3.connect(self.wal_path, timeout=5.0)
        try:
            cols = {row[1] for row in conn.execute("PRAGMA table_info(wal)").fetchall()}
            has_chain = "sig" in cols and "prev_sig" in cols

            if has_chain:
                cursor = conn.execute(
                    "SELECT id, idem, ts_ns, bytes, sig, prev_sig "
                    "FROM wal ORDER BY id"
                )
            else:
                cursor = conn.execute(
                    "SELECT id, idem, ts_ns, bytes, NULL, NULL " "FROM wal ORDER BY id"
                )
            rows = cursor.fetchall()
            # Normalise memoryview / buffer → bytes
            normalised = []
            for r in rows:
                normalised.append(
                    (
                        r[0],
                        r[1],
                        r[2],
                        bytes(r[3]) if r[3] else b"",
                        bytes(r[4]) if r[4] else GENESIS_SIG,
                        bytes(r[5]) if r[5] else GENESIS_SIG,
                    )
                )
            return normalised
        finally:
            conn.close()

    def _build_segment(
        self,
        segment_id: int,
        rows: List[Tuple],
        global_offset: int,
    ) -> SegmentInfo:
        """Build Merkle tree for a segment of rows."""
        leaves: List[bytes] = []
        for local_idx, row in enumerate(rows):
            row_id, idem, ts_ns, env_bytes, sig, prev_sig = row
            lh = leaf_hash(env_bytes, local_idx, prev_sig)
            leaves.append(lh)

        merkle_root = root_hash(leaves)

        first_row = rows[0]
        last_row = rows[-1]

        return SegmentInfo(
            segment_id=segment_id,
            start_seq=first_row[0],  # row id of first event
            end_seq=last_row[0],  # row id of last event
            event_count=len(rows),
            first_ts_ns=first_row[2],
            last_ts_ns=last_row[2],
            root_hash=merkle_root,
            first_chain_sig=first_row[4],
            last_chain_sig=last_row[4],
            leaf_hashes=leaves,
        )
