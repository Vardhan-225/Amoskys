"""Temporal Index — sorted-timestamp cross-domain event index.

Built each collection cycle from all 7 macOS domain collectors. Enables
O(log n) temporal range queries: "find all events within N seconds of
anchor event" across any combination of domains.

This is the key data structure for temporal correlation probes. Instead of
asking "what is true NOW?", temporal probes ask "what happened BEFORE/AFTER
this event?" — detecting sequences, causation, and timing patterns.

Memory: ~48 bytes per entry. At 2000 entries/cycle = ~96KB.
Lookup: O(log n) via bisect.

Usage:
    idx = TemporalIndex()
    idx.add(proc.create_time, "process", "created", proc)
    idx.add(file.mtime, "file", "modified", file_entry)

    # Find everything within 60s after a file modification
    after = idx.events_after(file.mtime, within_seconds=60.0)

    # Find processes created within 30s before a network connection
    procs = idx.events_before(conn_ts, within_seconds=30.0, domain="process")
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from typing import Any, List, Optional, Sequence


@dataclass(order=True)
class TemporalEntry:
    """A single timestamped event in the temporal index.

    Sorted by timestamp for O(log n) bisect-based range queries.

    Attributes:
        timestamp: Epoch seconds (float for sub-second precision).
        domain: Source domain — "process", "file", "auth", "network",
                "persistence", "log", "peripheral".
        event_type: What happened — "created", "modified", "connected",
                    "auth_success", "auth_failure", etc.
        data: Reference to the original dataclass (ProcessSnapshot,
              FileEntry, Connection, etc.) — not copied, zero overhead.
    """

    timestamp: float
    domain: str = field(compare=False)
    event_type: str = field(compare=False)
    data: Any = field(compare=False, repr=False)


class TemporalIndex:
    """Cross-domain temporal index for correlation probes.

    Built fresh each collection cycle from all 7 domain collectors.
    Entries are maintained in sorted order by timestamp for efficient
    range queries via bisect.

    Example:
        idx = TemporalIndex()

        # Populate from collector snapshot
        for proc in processes:
            idx.add(proc.create_time, "process", "created", proc)
        for f in files:
            idx.add(f.mtime, "file", "modified", f)

        # Query: what happened within 60s after this file was modified?
        events = idx.events_after(file.mtime, 60.0)

        # Query: any processes created within 30s before this connection?
        procs = idx.events_before(conn_ts, 30.0, domain="process")
    """

    def __init__(self) -> None:
        self._entries: List[TemporalEntry] = []
        self._timestamps: List[float] = []  # parallel array for bisect
        self._sorted = True

    def add(self, timestamp: float, domain: str, event_type: str, data: Any) -> None:
        """Add an event to the index.

        Entries should ideally be added in timestamp order for best performance,
        but out-of-order adds are handled by deferring sort to query time.
        """
        entry = TemporalEntry(
            timestamp=timestamp,
            domain=domain,
            event_type=event_type,
            data=data,
        )
        self._entries.append(entry)
        self._timestamps.append(timestamp)

        # Check if still sorted
        if len(self._timestamps) > 1 and timestamp < self._timestamps[-2]:
            self._sorted = False

    def _ensure_sorted(self) -> None:
        """Sort entries by timestamp if needed (lazy)."""
        if not self._sorted:
            self._entries.sort()
            self._timestamps = [e.timestamp for e in self._entries]
            self._sorted = True

    @property
    def size(self) -> int:
        """Number of entries in the index."""
        return len(self._entries)

    def range_query(
        self,
        start_ts: float,
        end_ts: float,
        domain: Optional[str] = None,
        event_type: Optional[str] = None,
    ) -> List[TemporalEntry]:
        """Find all events in [start_ts, end_ts] with optional filters.

        Args:
            start_ts: Lower bound timestamp (inclusive).
            end_ts: Upper bound timestamp (inclusive).
            domain: If set, only return entries from this domain.
            event_type: If set, only return entries of this type.

        Returns:
            List of matching TemporalEntry objects, sorted by timestamp.
        """
        self._ensure_sorted()

        left = bisect.bisect_left(self._timestamps, start_ts)
        right = bisect.bisect_right(self._timestamps, end_ts)

        results = self._entries[left:right]

        if domain is not None:
            results = [e for e in results if e.domain == domain]
        if event_type is not None:
            results = [e for e in results if e.event_type == event_type]

        return results

    def events_after(
        self,
        anchor_ts: float,
        within_seconds: float,
        domain: Optional[str] = None,
        event_type: Optional[str] = None,
    ) -> List[TemporalEntry]:
        """Find events within N seconds AFTER an anchor timestamp.

        Args:
            anchor_ts: The reference timestamp.
            within_seconds: How far ahead to look.
            domain: Optional domain filter.
            event_type: Optional event type filter.

        Returns:
            Events in (anchor_ts, anchor_ts + within_seconds].
        """
        return self.range_query(
            anchor_ts,
            anchor_ts + within_seconds,
            domain=domain,
            event_type=event_type,
        )

    def events_before(
        self,
        anchor_ts: float,
        within_seconds: float,
        domain: Optional[str] = None,
        event_type: Optional[str] = None,
    ) -> List[TemporalEntry]:
        """Find events within N seconds BEFORE an anchor timestamp.

        Args:
            anchor_ts: The reference timestamp.
            within_seconds: How far back to look.
            domain: Optional domain filter.
            event_type: Optional event type filter.

        Returns:
            Events in [anchor_ts - within_seconds, anchor_ts).
        """
        return self.range_query(
            anchor_ts - within_seconds,
            anchor_ts,
            domain=domain,
            event_type=event_type,
        )
