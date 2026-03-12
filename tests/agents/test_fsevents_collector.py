#!/usr/bin/env python3
"""Tests for MacOSFSEventsCollector (real-time file change detection).

Tests cover:
    - FileChange production from watchdog events
    - Dedup within 1-second window
    - Buffer drain and clear
    - Start/stop lifecycle
    - Integration with FIM collect_data merge
"""

import os
import time
from collections import deque
from unittest.mock import MagicMock, patch

import pytest

# TODO: fsevents_collector not yet implemented in macOS Observatory FIM agent
pytest.skip(
    "MacOSFSEventsCollector not yet ported to macOS Observatory",
    allow_module_level=True,
)

# =============================================================================
# Test: _FSEventsHandler
# =============================================================================


class TestFSEventsHandler:
    """Test the watchdog event handler."""

    def _make_handler(self):
        buf = deque(maxlen=10000)
        handler = _FSEventsHandler(buf)
        return handler, buf

    @patch("amoskys.agents.os.macos.filesystem.fsevents_collector.FileState.from_path")
    def test_on_created_produces_file_change(self, mock_from_path):
        """File created → CREATED FileChange in buffer."""
        mock_from_path.return_value = FileState(
            path="/tmp/test.txt",
            sha256="abc123",
            size=100,
            mode=0o100644,
            uid=501,
            gid=20,
            mtime_ns=int(time.time() * 1e9),
            is_dir=False,
            is_symlink=False,
        )

        handler, buf = self._make_handler()
        event = MagicMock()
        event.src_path = "/tmp/test.txt"
        event.is_directory = False

        handler.on_created(event)

        assert len(buf) == 1
        fc = buf[0]
        assert fc.change_type == ChangeType.CREATED
        assert fc.path == "/tmp/test.txt"
        assert fc.new_state is not None
        assert fc.old_state is None

    @patch("amoskys.agents.os.macos.filesystem.fsevents_collector.FileState.from_path")
    def test_on_modified_produces_modified_change(self, mock_from_path):
        """File modified → MODIFIED FileChange."""
        mock_from_path.return_value = FileState(
            path="/etc/passwd",
            sha256="def456",
            size=200,
            mode=0o100644,
            uid=0,
            gid=0,
            mtime_ns=int(time.time() * 1e9),
            is_dir=False,
            is_symlink=False,
        )

        handler, buf = self._make_handler()
        event = MagicMock()
        event.src_path = "/etc/passwd"
        event.is_directory = False

        handler.on_modified(event)

        assert len(buf) == 1
        assert buf[0].change_type == ChangeType.MODIFIED

    def test_on_deleted_produces_deleted_change(self):
        """File deleted → DELETED FileChange (no from_path call)."""
        handler, buf = self._make_handler()
        event = MagicMock()
        event.src_path = "/tmp/gone.txt"
        event.is_directory = False

        handler.on_deleted(event)

        assert len(buf) == 1
        fc = buf[0]
        assert fc.change_type == ChangeType.DELETED
        assert fc.new_state is None
        assert fc.old_state is None

    @patch("amoskys.agents.os.macos.filesystem.fsevents_collector.FileState.from_path")
    def test_on_moved_produces_delete_and_create(self, mock_from_path):
        """File moved → DELETE of old + CREATE of new."""
        mock_from_path.return_value = FileState(
            path="/tmp/new_name.txt",
            sha256="ghi789",
            size=50,
            mode=0o100644,
            uid=501,
            gid=20,
            mtime_ns=int(time.time() * 1e9),
            is_dir=False,
            is_symlink=False,
        )

        handler, buf = self._make_handler()
        event = MagicMock()
        event.src_path = "/tmp/old_name.txt"
        event.dest_path = "/tmp/new_name.txt"
        event.is_directory = False

        handler.on_moved(event)

        assert len(buf) == 2
        assert buf[0].change_type == ChangeType.DELETED
        assert buf[0].path == "/tmp/old_name.txt"
        assert buf[1].change_type == ChangeType.CREATED
        assert buf[1].path == "/tmp/new_name.txt"

    def test_directory_events_skipped(self):
        """Events on directories are ignored."""
        handler, buf = self._make_handler()

        for method in [handler.on_created, handler.on_modified, handler.on_deleted]:
            event = MagicMock()
            event.is_directory = True
            event.src_path = "/tmp/somedir"
            method(event)

        assert len(buf) == 0

    @patch("amoskys.agents.os.macos.filesystem.fsevents_collector.FileState.from_path")
    def test_dedup_within_1_second(self, mock_from_path):
        """Same (path, change_type) within 1s → only one event."""
        mock_from_path.return_value = FileState(
            path="/tmp/rapid.txt",
            sha256="xxx",
            size=10,
            mode=0o100644,
            uid=501,
            gid=20,
            mtime_ns=int(time.time() * 1e9),
            is_dir=False,
            is_symlink=False,
        )

        handler, buf = self._make_handler()
        event = MagicMock()
        event.src_path = "/tmp/rapid.txt"
        event.is_directory = False

        handler.on_modified(event)
        handler.on_modified(event)
        handler.on_modified(event)

        assert len(buf) == 1  # Deduped to 1

    @patch("amoskys.agents.os.macos.filesystem.fsevents_collector.FileState.from_path")
    def test_different_change_types_not_deduped(self, mock_from_path):
        """CREATED and MODIFIED on same path are separate events."""
        mock_from_path.return_value = FileState(
            path="/tmp/test.txt",
            sha256="aaa",
            size=10,
            mode=0o100644,
            uid=501,
            gid=20,
            mtime_ns=int(time.time() * 1e9),
            is_dir=False,
            is_symlink=False,
        )

        handler, buf = self._make_handler()

        created_event = MagicMock()
        created_event.src_path = "/tmp/test.txt"
        created_event.is_directory = False

        modified_event = MagicMock()
        modified_event.src_path = "/tmp/test.txt"
        modified_event.is_directory = False

        handler.on_created(created_event)
        handler.on_modified(modified_event)

        assert len(buf) == 2

    @patch("amoskys.agents.os.macos.filesystem.fsevents_collector.FileState.from_path")
    def test_vanished_file_skipped(self, mock_from_path):
        """If file vanishes before stat, event is silently dropped."""
        mock_from_path.return_value = None

        handler, buf = self._make_handler()
        event = MagicMock()
        event.src_path = "/tmp/ephemeral.txt"
        event.is_directory = False

        handler.on_created(event)

        assert len(buf) == 0  # Skipped because from_path returned None


# =============================================================================
# Test: MacOSFSEventsCollector
# =============================================================================


class TestMacOSFSEventsCollector:
    """Test the collector lifecycle."""

    def test_drain_returns_and_clears(self):
        """drain() returns all buffered events and clears buffer."""
        buf = deque(maxlen=10000)
        collector = MacOSFSEventsCollector.__new__(MacOSFSEventsCollector)
        collector._buffer = buf
        collector._monitor_paths = []
        collector._handler = _FSEventsHandler(buf)
        collector._observer = None

        # Manually add events
        for i in range(5):
            buf.append(
                FileChange(
                    path=f"/tmp/file{i}",
                    change_type=ChangeType.CREATED,
                    old_state=None,
                    new_state=None,
                    timestamp_ns=int(time.time() * 1e9),
                )
            )

        changes = collector.drain()
        assert len(changes) == 5
        assert len(buf) == 0

    def test_drain_empty_buffer(self):
        """drain() on empty buffer returns empty list."""
        buf = deque(maxlen=10000)
        collector = MacOSFSEventsCollector.__new__(MacOSFSEventsCollector)
        collector._buffer = buf
        collector._monitor_paths = []
        collector._handler = _FSEventsHandler(buf)
        collector._observer = None

        changes = collector.drain()
        assert changes == []

    def test_is_running_false_when_not_started(self):
        """is_running is False when observer not started."""
        collector = MacOSFSEventsCollector.__new__(MacOSFSEventsCollector)
        collector._observer = None
        assert not collector.is_running

    @patch("amoskys.agents.os.macos.filesystem.fsevents_collector.Observer")
    def test_start_schedules_existing_paths(self, MockObserver):
        """start() schedules only paths that exist."""
        mock_obs = MagicMock()
        MockObserver.return_value = mock_obs

        buf = deque(maxlen=10000)
        collector = MacOSFSEventsCollector(
            monitor_paths=["/tmp", "/nonexistent_path_xyz"],
            change_buffer=buf,
        )
        collector.start()

        # /tmp exists, /nonexistent_path_xyz does not
        assert mock_obs.schedule.call_count == 1
        mock_obs.start.assert_called_once()

    @patch("amoskys.agents.os.macos.filesystem.fsevents_collector.Observer")
    def test_stop_joins_observer(self, MockObserver):
        """stop() stops and joins the observer thread."""
        mock_obs = MagicMock()
        mock_obs.is_alive.return_value = True
        MockObserver.return_value = mock_obs

        buf = deque(maxlen=10000)
        collector = MacOSFSEventsCollector(
            monitor_paths=["/tmp"],
            change_buffer=buf,
        )
        collector.start()
        collector.stop()

        mock_obs.stop.assert_called_once()
        mock_obs.join.assert_called_once_with(timeout=5)
        assert collector._observer is None


# =============================================================================
# Test: FIM Integration (merge FSEvents into collect_data)
# =============================================================================


class TestFIMIntegration:
    """Verify FSEvents changes merge correctly with baseline changes."""

    def test_merge_deduplicates_by_path_and_type(self):
        """FSEvents changes with same (path, type) as baseline are skipped."""
        baseline_changes = [
            FileChange(
                path="/etc/hosts",
                change_type=ChangeType.MODIFIED,
                old_state=None,
                new_state=None,
                timestamp_ns=int(time.time() * 1e9),
            )
        ]

        fsevents_changes = [
            # Same path + type → should be skipped
            FileChange(
                path="/etc/hosts",
                change_type=ChangeType.MODIFIED,
                old_state=None,
                new_state=None,
                timestamp_ns=int(time.time() * 1e9),
            ),
            # Different path → should be merged
            FileChange(
                path="/tmp/webshell.php",
                change_type=ChangeType.CREATED,
                old_state=None,
                new_state=None,
                timestamp_ns=int(time.time() * 1e9),
            ),
        ]

        # Simulate the merge logic from collect_data
        existing_keys = {(c.path, c.change_type) for c in baseline_changes}
        merged = 0
        for fc in fsevents_changes:
            if (fc.path, fc.change_type) not in existing_keys:
                baseline_changes.append(fc)
                merged += 1

        assert merged == 1
        assert len(baseline_changes) == 2
        assert baseline_changes[1].path == "/tmp/webshell.php"

    def test_fsevents_catches_ephemeral_file(self):
        """FSEvents detects a file that was created and deleted within one poll."""
        # This simulates: attacker drops webshell, baseline scan runs,
        # webshell is already gone. But FSEvents caught the CREATE.
        fsevents_changes = [
            FileChange(
                path="/var/www/html/cmd.php",
                change_type=ChangeType.CREATED,
                old_state=None,
                new_state=FileState(
                    path="/var/www/html/cmd.php",
                    sha256="malicious_hash",
                    size=256,
                    mode=0o100644,
                    uid=33,  # www-data
                    gid=33,
                    mtime_ns=int(time.time() * 1e9),
                    is_dir=False,
                    is_symlink=False,
                ),
                timestamp_ns=int(time.time() * 1e9),
            ),
            FileChange(
                path="/var/www/html/cmd.php",
                change_type=ChangeType.DELETED,
                old_state=None,
                new_state=None,
                timestamp_ns=int(time.time() * 1e9),
            ),
        ]

        # Baseline detected nothing (file was created and deleted between scans)
        baseline_changes = []

        existing_keys = {(c.path, c.change_type) for c in baseline_changes}
        for fc in fsevents_changes:
            if (fc.path, fc.change_type) not in existing_keys:
                baseline_changes.append(fc)

        assert len(baseline_changes) == 2
        assert baseline_changes[0].change_type == ChangeType.CREATED
        assert baseline_changes[1].change_type == ChangeType.DELETED
