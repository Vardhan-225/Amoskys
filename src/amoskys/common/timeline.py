"""Cross-Source Timeline Buffer — shared event correlation substrate.

All collectors write events to this buffer. The correlation engine and
provenance probes read from it to detect multi-source attack chains like:
  FSEvents file_created + process spawned from that path + DNS query

Thread-safe. Lock-free reads via snapshot copies.

Usage:
    from amoskys.common.timeline import timeline_buffer

    # Collector writes:
    timeline_buffer.add("fsevents", "file_created", path="/tmp/payload.sh")
    timeline_buffer.add("psutil", "process_spawned", pid=1234, path="/tmp/payload.sh")
    timeline_buffer.add("logstream", "dns_query", domain="evil.com", pid=1234)

    # Probe reads:
    chain = timeline_buffer.correlate_by_pid(1234, window_seconds=60)
    chain = timeline_buffer.correlate_by_path("/tmp/payload.sh", window_seconds=30)
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional


@dataclass
class TimelineEntry:
    """A single event in the cross-source timeline."""

    source: str  # "fsevents", "psutil", "logstream", "lsof", "kqueue", "nettop"
    event_type: str  # "file_created", "process_spawned", "dns_query", etc.
    timestamp_ns: int
    pid: int = 0
    path: str = ""
    domain: str = ""
    remote_ip: str = ""
    bundle_id: str = ""
    process_name: str = ""
    data: Dict[str, Any] = field(default_factory=dict)


class TimelineBuffer:
    """Thread-safe rolling window buffer for cross-source correlation.

    Designed for high write throughput from multiple collector threads
    and fast reads from correlation probes.
    """

    def __init__(self, window_seconds: float = 300.0, max_events: int = 10000) -> None:
        self._events: Deque[TimelineEntry] = deque(maxlen=max_events)
        self._lock = threading.Lock()
        self._window_ns = int(window_seconds * 1e9)

    def add(
        self,
        source: str,
        event_type: str,
        pid: int = 0,
        path: str = "",
        domain: str = "",
        remote_ip: str = "",
        bundle_id: str = "",
        process_name: str = "",
        timestamp_ns: int = 0,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Add an event from any source. Thread-safe."""
        entry = TimelineEntry(
            source=source,
            event_type=event_type,
            timestamp_ns=timestamp_ns or time.time_ns(),
            pid=pid,
            path=path,
            domain=domain,
            remote_ip=remote_ip,
            bundle_id=bundle_id,
            process_name=process_name,
            data=data or {},
        )
        with self._lock:
            self._events.append(entry)

    def query(
        self,
        window_seconds: float = 60.0,
        pid: int = 0,
        path: str = "",
        domain: str = "",
        remote_ip: str = "",
        source: str = "",
        event_type: str = "",
    ) -> List[TimelineEntry]:
        """Query events matching criteria within time window."""
        cutoff_ns = time.time_ns() - int(window_seconds * 1e9)
        with self._lock:
            snapshot = list(self._events)

        results = []
        for e in snapshot:
            if e.timestamp_ns < cutoff_ns:
                continue
            if pid and e.pid != pid:
                continue
            if path and path not in e.path:
                continue
            if domain and domain not in e.domain:
                continue
            if remote_ip and e.remote_ip != remote_ip:
                continue
            if source and e.source != source:
                continue
            if event_type and e.event_type != event_type:
                continue
            results.append(e)
        return results

    def correlate_by_pid(
        self, pid: int, window_seconds: float = 60.0
    ) -> List[TimelineEntry]:
        """Get all events for a PID within a time window."""
        return self.query(window_seconds=window_seconds, pid=pid)

    def correlate_by_path(
        self, path: str, window_seconds: float = 60.0
    ) -> List[TimelineEntry]:
        """Get all events involving a path within a time window."""
        return self.query(window_seconds=window_seconds, path=path)

    def correlate_chain(
        self,
        steps: List[Dict[str, str]],
        window_seconds: float = 60.0,
    ) -> Optional[List[TimelineEntry]]:
        """Find a sequence of events matching a chain definition.

        Each step is a dict of field→value filters. Steps must occur
        in order within the time window.

        Example:
            chain = buffer.correlate_chain([
                {"source": "fsevents", "event_type": "file_created"},
                {"source": "psutil", "event_type": "process_spawned"},
                {"source": "lsof", "event_type": "connection"},
            ], window_seconds=30)

        Returns matched events or None if chain not found.
        """
        cutoff_ns = time.time_ns() - int(window_seconds * 1e9)
        with self._lock:
            snapshot = [e for e in self._events if e.timestamp_ns > cutoff_ns]

        if not steps or not snapshot:
            return None

        # Find chain in order
        matched: List[TimelineEntry] = []
        step_idx = 0
        for entry in sorted(snapshot, key=lambda e: e.timestamp_ns):
            step = steps[step_idx]
            if self._matches_step(entry, step):
                matched.append(entry)
                step_idx += 1
                if step_idx >= len(steps):
                    return matched

        return None  # Incomplete chain

    @staticmethod
    def _matches_step(entry: TimelineEntry, step: Dict[str, str]) -> bool:
        for field_name, value in step.items():
            entry_val = getattr(entry, field_name, "")
            if isinstance(entry_val, str):
                if value not in entry_val:
                    return False
            elif entry_val != value:
                return False
        return True

    def recent(self, count: int = 50) -> List[TimelineEntry]:
        """Get the N most recent events."""
        with self._lock:
            return list(self._events)[-count:]

    def stats(self) -> Dict[str, Any]:
        """Get buffer statistics."""
        with self._lock:
            total = len(self._events)
            if total == 0:
                return {"total": 0, "sources": {}, "window_seconds": 0}

            by_source: Dict[str, int] = {}
            oldest_ns = self._events[0].timestamp_ns
            newest_ns = self._events[-1].timestamp_ns
            for e in self._events:
                by_source[e.source] = by_source.get(e.source, 0) + 1

        return {
            "total": total,
            "sources": by_source,
            "window_seconds": (newest_ns - oldest_ns) / 1e9,
        }

    def clear(self) -> None:
        with self._lock:
            self._events.clear()


# ── Singleton instance ───────────────────────────────────────────────────────
# All collectors and probes use this shared instance.
timeline_buffer = TimelineBuffer()
