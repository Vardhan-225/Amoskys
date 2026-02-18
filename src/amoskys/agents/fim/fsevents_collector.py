"""FSEvents Real-Time File Change Collector for macOS.

Supplements the baseline polling engine with near-real-time file change
detection via macOS FSEvents (through the ``watchdog`` library).

Between 5-minute baseline scans, the FSEvents watcher pushes FileChange
objects into a thread-safe buffer that the FIM agent drains on each
collection cycle.  This catches ephemeral mutations (e.g. webshell drop
then delete within the poll window) that periodic scanning would miss.

Design:
    - Thread-safe deque shared between watchdog thread and agent thread
    - Dedup within 1-second window to suppress FSEvents coalescing noise
    - FileState.from_path() called per event for sha256 consistency
    - Graceful fallback: import guarded so agent works without watchdog
"""

from __future__ import annotations

import logging
import os
import time
from collections import deque
from threading import Lock
from typing import Deque, Dict, List, Optional, Set, Tuple

from watchdog.events import (
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

from amoskys.agents.fim.probes import ChangeType, FileChange, FileState

logger = logging.getLogger(__name__)


class _FSEventsHandler(FileSystemEventHandler):
    """Converts watchdog filesystem events to AMOSKYS FileChange objects.

    Deduplicates (path, change_type) pairs within a 1-second window to
    suppress the rapid-fire events FSEvents produces during bulk operations.
    """

    def __init__(self, buffer: Deque[FileChange]) -> None:
        super().__init__()
        self._buffer = buffer
        self._recent: Dict[Tuple[str, str], float] = {}
        self._lock = Lock()

    def _should_emit(self, path: str, change_type: ChangeType) -> bool:
        """Check dedup window. Returns True if event should be emitted."""
        now = time.monotonic()
        key = (path, change_type.value)
        with self._lock:
            last = self._recent.get(key, 0.0)
            if now - last < 1.0:
                return False
            self._recent[key] = now
            # Prune stale entries (older than 5s)
            if len(self._recent) > 5000:
                cutoff = now - 5.0
                self._recent = {
                    k: v for k, v in self._recent.items() if v > cutoff
                }
            return True

    def on_created(self, event: FileCreatedEvent) -> None:
        if event.is_directory:
            return
        self._emit(event.src_path, ChangeType.CREATED)

    def on_modified(self, event: FileModifiedEvent) -> None:
        if event.is_directory:
            return
        self._emit(event.src_path, ChangeType.MODIFIED)

    def on_deleted(self, event: FileDeletedEvent) -> None:
        if event.is_directory:
            return
        self._emit_deleted(event.src_path)

    def on_moved(self, event: FileMovedEvent) -> None:
        if event.is_directory:
            return
        # Treat as delete of old + create of new
        self._emit_deleted(event.src_path)
        self._emit(event.dest_path, ChangeType.CREATED)

    def _emit(self, path: str, change_type: ChangeType) -> None:
        """Build FileChange with current FileState and append to buffer."""
        if not self._should_emit(path, change_type):
            return
        state = FileState.from_path(path)
        if state is None and change_type != ChangeType.DELETED:
            return  # File vanished before we could stat it

        ts_ns = int(time.time() * 1e9)

        if change_type == ChangeType.CREATED:
            fc = FileChange(
                path=path,
                change_type=ChangeType.CREATED,
                old_state=None,
                new_state=state,
                timestamp_ns=ts_ns,
            )
        else:
            # MODIFIED — we don't have old_state from FSEvents, so set None.
            # Probes that need old_state (e.g. WorldWritableSensitiveProbe)
            # will get it from the baseline on the next poll cycle.
            fc = FileChange(
                path=path,
                change_type=change_type,
                old_state=None,
                new_state=state,
                timestamp_ns=ts_ns,
            )

        self._buffer.append(fc)

    def _emit_deleted(self, path: str) -> None:
        """Emit a DELETE event (no new_state since file is gone)."""
        if not self._should_emit(path, ChangeType.DELETED):
            return
        ts_ns = int(time.time() * 1e9)
        fc = FileChange(
            path=path,
            change_type=ChangeType.DELETED,
            old_state=None,
            new_state=None,
            timestamp_ns=ts_ns,
        )
        self._buffer.append(fc)


class MacOSFSEventsCollector:
    """Real-time file change collector using macOS FSEvents via watchdog.

    Usage::

        buffer = deque(maxlen=10000)
        collector = MacOSFSEventsCollector(monitor_paths, buffer)
        collector.start()

        # On each FIM collection cycle:
        changes = collector.drain()
        # ... merge with baseline-detected changes ...

        collector.stop()
    """

    def __init__(
        self,
        monitor_paths: List[str],
        change_buffer: Deque[FileChange],
    ) -> None:
        """Initialize FSEvents collector.

        Args:
            monitor_paths: Directories to watch (same as FIM agent paths)
            change_buffer: Thread-safe deque where FileChange objects accumulate
        """
        self._monitor_paths = monitor_paths
        self._buffer = change_buffer
        self._handler = _FSEventsHandler(change_buffer)
        self._observer: Optional[Observer] = None

    def start(self) -> None:
        """Start watching all monitor paths. Call from FIMAgentV2.setup()."""
        self._observer = Observer()
        scheduled = 0
        for path in self._monitor_paths:
            if os.path.exists(path) and os.path.isdir(path):
                self._observer.schedule(self._handler, path, recursive=True)
                scheduled += 1
            else:
                logger.debug("Skipping non-existent path: %s", path)

        if scheduled > 0:
            self._observer.daemon = True
            self._observer.start()
            logger.info(
                "FSEvents watcher started for %d directories", scheduled
            )
        else:
            logger.warning("No valid directories to watch via FSEvents")
            self._observer = None

    def drain(self) -> List[FileChange]:
        """Drain accumulated changes since last call.

        Returns:
            List of FileChange objects collected between calls.
            Buffer is cleared after drain.
        """
        changes: List[FileChange] = []
        while self._buffer:
            try:
                changes.append(self._buffer.popleft())
            except IndexError:
                break  # Deque emptied by another thread
        return changes

    def stop(self) -> None:
        """Stop watching. Call from FIMAgentV2.shutdown()."""
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None
            logger.info("FSEvents watcher stopped")

    @property
    def is_running(self) -> bool:
        """Check if the observer thread is alive."""
        return self._observer is not None and self._observer.is_alive()


__all__ = ["MacOSFSEventsCollector"]
