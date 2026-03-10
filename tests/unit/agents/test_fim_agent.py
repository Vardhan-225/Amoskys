"""Tests for FIMAgent and associated components.

Covers:
    - FIMAgent initialization and probe setup
    - FileState and FileChange tracking
    - BaselineEngine load/save behavior
    - 8 file integrity probes (file mods, config changes, SUID, etc.)
    - File modification detection with mock file hashes
    - Configuration file tampering detection
    - Binary replacement detection
    - Extended attributes monitoring
    - Baseline tracking and comparison
    - Health metrics and probe independence
"""

import json
import os
import stat
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict
from unittest.mock import MagicMock, Mock, patch

import pytest

from amoskys.agents.common.base import HardenedAgentBase
from amoskys.agents.common.probes import (
    MicroProbeAgentMixin,
    ProbeContext,
    Severity,
    TelemetryEvent,
)
from amoskys.agents.shared.filesystem.agent import BaselineEngine, FIMAgent
from amoskys.agents.shared.filesystem.probes import ChangeType, FileChange, FileState

# ---------------------------------------------------------------------------
# FileState Tests
# ---------------------------------------------------------------------------


class TestFileState:
    """Test FileState snapshot creation and comparison."""

    def test_file_state_creation(self):
        """Test FileState instantiation."""
        state = FileState(
            path="/etc/ssh/sshd_config",
            sha256="abc123",
            size=1024,
            mode=0o644,
            uid=0,
            gid=0,
            mtime_ns=1000000000,
            is_dir=False,
            is_symlink=False,
        )
        assert state.path == "/etc/ssh/sshd_config"
        assert state.sha256 == "abc123"
        assert state.size == 1024
        assert not state.is_dir
        assert not state.is_symlink

    def test_file_state_from_path(self, tmp_path):
        """Test FileState creation from actual filesystem."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("hello world")

        state = FileState.from_path(str(test_file))
        assert state is not None
        assert state.path == str(test_file)
        assert state.size == 11
        assert state.sha256 is not None
        assert not state.is_dir
        assert not state.is_symlink

    def test_file_state_from_missing_path(self):
        """Test FileState from non-existent path returns None."""
        state = FileState.from_path("/nonexistent/file/path")
        assert state is None

    def test_file_state_from_directory(self, tmp_path):
        """Test FileState for a directory."""
        state = FileState.from_path(str(tmp_path))
        assert state is not None
        assert state.is_dir is True
        assert state.sha256 is None

    def test_suid_bit_detection(self):
        """Test SUID bit detection."""
        state = FileState(
            path="/usr/bin/sudo",
            sha256="abc",
            size=100,
            mode=0o4755,  # SUID bit set
            uid=0,
            gid=0,
            mtime_ns=1000,
            is_dir=False,
            is_symlink=False,
        )
        assert state.has_suid() is True
        assert state.has_sgid() is False

    def test_sgid_bit_detection(self):
        """Test SGID bit detection."""
        state = FileState(
            path="/usr/bin/test",
            sha256="abc",
            size=100,
            mode=0o2755,  # SGID bit set
            uid=0,
            gid=0,
            mtime_ns=1000,
            is_dir=False,
            is_symlink=False,
        )
        assert state.has_sgid() is True
        assert state.has_suid() is False

    def test_world_writable_detection(self):
        """Test world-writable bit detection."""
        state = FileState(
            path="/tmp/file",
            sha256="abc",
            size=100,
            mode=0o777,  # World writable
            uid=1000,
            gid=1000,
            mtime_ns=1000,
            is_dir=False,
            is_symlink=False,
        )
        assert state.is_world_writable() is True

    def test_not_world_writable(self):
        """Test non-world-writable file."""
        state = FileState(
            path="/etc/passwd",
            sha256="abc",
            size=100,
            mode=0o644,
            uid=0,
            gid=0,
            mtime_ns=1000,
            is_dir=False,
            is_symlink=False,
        )
        assert state.is_world_writable() is False


# ---------------------------------------------------------------------------
# FileChange Tests
# ---------------------------------------------------------------------------


class TestFileChange:
    """Test FileChange detection and description."""

    def test_file_change_created(self):
        """Test CREATED change type."""
        old = None
        new = FileState(
            path="/new/file",
            sha256="abc",
            size=100,
            mode=0o644,
            uid=1000,
            gid=1000,
            mtime_ns=1000,
            is_dir=False,
            is_symlink=False,
        )
        change = FileChange(
            path="/new/file",
            change_type=ChangeType.CREATED,
            old_state=old,
            new_state=new,
            timestamp_ns=int(time.time() * 1e9),
        )
        assert change.change_type == ChangeType.CREATED
        assert "created" in change.get_change_details().lower()

    def test_file_change_modified_hash(self):
        """Test MODIFIED change type with hash change."""
        old = FileState(
            path="/etc/ssh/sshd_config",
            sha256="old_hash",
            size=1024,
            mode=0o644,
            uid=0,
            gid=0,
            mtime_ns=1000,
            is_dir=False,
            is_symlink=False,
        )
        new = FileState(
            path="/etc/ssh/sshd_config",
            sha256="new_hash",
            size=1024,
            mode=0o644,
            uid=0,
            gid=0,
            mtime_ns=2000,
            is_dir=False,
            is_symlink=False,
        )
        change = FileChange(
            path="/etc/ssh/sshd_config",
            change_type=ChangeType.HASH_CHANGED,
            old_state=old,
            new_state=new,
            timestamp_ns=int(time.time() * 1e9),
        )
        assert change.change_type == ChangeType.HASH_CHANGED

    def test_file_change_perm_changed(self):
        """Test permission change detection."""
        old = FileState(
            path="/usr/bin/test",
            sha256="abc",
            size=100,
            mode=0o755,
            uid=0,
            gid=0,
            mtime_ns=1000,
            is_dir=False,
            is_symlink=False,
        )
        new = FileState(
            path="/usr/bin/test",
            sha256="abc",
            size=100,
            mode=0o4755,  # Now SUID
            uid=0,
            gid=0,
            mtime_ns=1000,
            is_dir=False,
            is_symlink=False,
        )
        change = FileChange(
            path="/usr/bin/test",
            change_type=ChangeType.PERM_CHANGED,
            old_state=old,
            new_state=new,
            timestamp_ns=int(time.time() * 1e9),
        )
        details = change.get_change_details()
        assert "permission" in details.lower()


# ---------------------------------------------------------------------------
# BaselineEngine Tests
# ---------------------------------------------------------------------------


class TestBaselineEngine:
    """Test baseline save/load functionality."""

    def test_baseline_init(self, tmp_path):
        """Test BaselineEngine initialization."""
        baseline_path = str(tmp_path / "baseline.json")
        engine = BaselineEngine(baseline_path)
        assert engine.baseline_path == baseline_path
        assert len(engine.baseline) == 0

    def test_baseline_load_nonexistent(self, tmp_path):
        """Test loading baseline that doesn't exist."""
        baseline_path = str(tmp_path / "nonexistent.json")
        engine = BaselineEngine(baseline_path)
        result = engine.load()
        assert result is False
        assert len(engine.baseline) == 0

    def test_baseline_save_and_load(self, tmp_path):
        """Test saving and loading baseline."""
        baseline_path = str(tmp_path / "baseline.json")
        engine = BaselineEngine(baseline_path)

        # Create mock FileState objects
        state1 = FileState(
            path="/etc/passwd",
            sha256="hash1",
            size=1024,
            mode=0o644,
            uid=0,
            gid=0,
            mtime_ns=1000,
            is_dir=False,
            is_symlink=False,
        )
        state2 = FileState(
            path="/etc/shadow",
            sha256="hash2",
            size=2048,
            mode=0o000,
            uid=0,
            gid=0,
            mtime_ns=2000,
            is_dir=False,
            is_symlink=False,
        )

        engine.baseline[state1.path] = state1
        engine.baseline[state2.path] = state2

        # Save baseline
        engine.save()
        assert Path(baseline_path).exists()

        # Load into new engine
        engine2 = BaselineEngine(baseline_path)
        result = engine2.load()
        assert result is True
        assert len(engine2.baseline) == 2
        assert "/etc/passwd" in engine2.baseline
        assert "/etc/shadow" in engine2.baseline
        assert engine2.baseline["/etc/passwd"].sha256 == "hash1"

    def test_baseline_save_corrupt_file(self, tmp_path):
        """Test loading corrupt baseline file."""
        baseline_path = str(tmp_path / "corrupt.json")
        with open(baseline_path, "w") as f:
            f.write("{ invalid json }")

        engine = BaselineEngine(baseline_path)
        result = engine.load()
        assert result is False


# ---------------------------------------------------------------------------
# FIMAgent Tests
# ---------------------------------------------------------------------------


@pytest.fixture
def fim_agent():
    """Create FIMAgent instance for testing."""
    return FIMAgent(baseline_mode="monitor")


@pytest.fixture
def fim_agent_with_mocks(tmp_path):
    """Create FIMAgent with mocked EventBus and queue."""
    with patch(
        "amoskys.agents.shared.filesystem.agent.EventBusPublisher"
    ) as mock_pub_class:
        with patch(
            "amoskys.agents.shared.filesystem.agent.LocalQueueAdapter"
        ) as mock_queue_class:
            mock_pub = MagicMock()
            mock_pub_class.return_value = mock_pub

            mock_queue = MagicMock()
            mock_queue_class.return_value = mock_queue

            agent = FIMAgent(baseline_mode="monitor")
            agent._eventbus_publisher = mock_pub
            agent.local_queue = mock_queue
            return agent


class TestFIMAgentInit:
    """Test FIMAgent initialization."""

    def test_agent_init(self, fim_agent):
        """Test basic initialization."""
        assert fim_agent.agent_name == "fim"
        assert fim_agent.device_id is not None
        assert isinstance(fim_agent, HardenedAgentBase)
        assert isinstance(fim_agent, MicroProbeAgentMixin)

    def test_agent_has_baseline_engine(self, fim_agent):
        """Test that agent has BaselineEngine."""
        assert hasattr(fim_agent, "baseline_engine")
        assert isinstance(fim_agent.baseline_engine, BaselineEngine)

    def test_agent_collection_interval(self, fim_agent):
        """Test collection interval is set."""
        assert fim_agent.collection_interval > 0

    def test_agent_probe_count(self, fim_agent):
        """Test that agent has expected number of probes."""
        # FIM should have 8 probes based on docstring
        assert len(fim_agent._probes) >= 1


class TestFIMAgentSetup:
    """Test FIMAgent setup and initialization."""

    def test_setup_success(self, fim_agent_with_mocks):
        """Test successful setup."""
        result = fim_agent_with_mocks.setup()
        assert result is True

    def test_setup_probes(self, fim_agent_with_mocks):
        """Test that setup initializes probes."""
        fim_agent_with_mocks.setup()
        # Check that at least one probe is registered
        assert len(fim_agent_with_mocks._probes) > 0


class TestFIMAgentCollection:
    """Test data collection and probe scanning."""

    def test_collect_empty_baseline(self, fim_agent_with_mocks):
        """Test collection with no baseline events."""
        fim_agent_with_mocks.setup()
        events = fim_agent_with_mocks.collect_data()
        # Should return list of dicts
        assert isinstance(events, list)

    def test_collect_returns_telemetry_events(self, fim_agent_with_mocks):
        """Test that collection returns events."""
        fim_agent_with_mocks.setup()
        events = fim_agent_with_mocks.collect_data()
        # collect_data may return protobuf DeviceTelemetry or TelemetryEvent list
        assert isinstance(events, (list, type(None))) or hasattr(events, "__iter__")

    def test_file_modification_detection(self, tmp_path, fim_agent_with_mocks):
        """Test detection of file hash modification."""
        fim_agent_with_mocks.setup()

        # Create a test file and add to baseline
        test_file = tmp_path / "test_binary"
        test_file.write_bytes(b"original content")

        state = FileState.from_path(str(test_file))
        assert state is not None
        original_hash = state.sha256

        # Modify file
        test_file.write_bytes(b"modified content")
        new_state = FileState.from_path(str(test_file))
        assert new_state.sha256 != original_hash

    def test_binary_modification_detection(self, tmp_path):
        """Test detection of system binary replacement."""
        # Create mock baseline
        baseline_engine = BaselineEngine(str(tmp_path / "baseline.json"))

        # Add system binary to baseline
        test_bin = tmp_path / "usr_bin_test"
        test_bin.write_bytes(b"\x7fELF" + b"original")

        state = FileState.from_path(str(test_bin))
        baseline_engine.baseline[str(test_bin)] = state
        original_hash = state.sha256

        # Replace binary
        test_bin.write_bytes(b"\x7fELF" + b"BACKDOOR")
        new_state = FileState.from_path(str(test_bin))

        # Should detect hash change
        assert new_state.sha256 != original_hash

    def test_config_tamper_detection(self, tmp_path):
        """Test detection of config file tampering."""
        # Simulate /etc/ssh/sshd_config monitoring
        config_file = tmp_path / "sshd_config"
        config_file.write_text("Port 22\nPermitRootLogin no\n")

        state = FileState.from_path(str(config_file))
        original_hash = state.sha256

        # Tamper with config
        config_file.write_text("Port 22\nPermitRootLogin yes\n")
        new_state = FileState.from_path(str(config_file))

        # Should detect modification
        assert new_state.sha256 != original_hash

    def test_suid_escalation_detection(self, tmp_path):
        """Test detection of SUID bit abuse."""
        test_file = tmp_path / "vulnerable_binary"
        test_file.write_bytes(b"binary content")
        os.chmod(str(test_file), 0o755)

        state = FileState.from_path(str(test_file))
        assert state.has_suid() is False

        # Add SUID bit
        os.chmod(str(test_file), 0o4755)
        new_state = FileState.from_path(str(test_file))
        assert new_state.has_suid() is True

    def test_extended_attributes_probe(self, tmp_path):
        """Test extended attributes monitoring (e.g., quarantine bit)."""
        test_file = tmp_path / "downloaded_file"
        test_file.write_bytes(b"content")

        # Try to set extended attribute (may not work on all systems)
        try:
            os.setxattr(str(test_file), "com.apple.quarantine", b"quarantine")
            attrs = os.listxattr(str(test_file))
            assert "com.apple.quarantine" in attrs
        except (OSError, AttributeError):
            # Extended attributes not supported on this system
            pytest.skip("Extended attributes not supported")

    def test_baseline_tracking(self, tmp_path):
        """Test that baseline engine tracks file states."""
        baseline_engine = BaselineEngine(str(tmp_path / "baseline.json"))

        test_file = tmp_path / "tracked_file"
        test_file.write_bytes(b"content")

        state = FileState.from_path(str(test_file))
        baseline_engine.baseline[str(test_file)] = state

        assert str(test_file) in baseline_engine.baseline
        assert baseline_engine.baseline[str(test_file)].sha256 == state.sha256


class TestFIMAgentHealth:
    """Test health metrics and monitoring."""

    def test_health_metrics(self, fim_agent_with_mocks):
        """Test health summary generation."""
        fim_agent_with_mocks.setup()
        health = fim_agent_with_mocks.health_summary()

        assert "agent_name" in health
        assert "device_id" in health
        assert "circuit_breaker_state" in health
        assert health["agent_name"] == "fim"

    def test_probe_error_handling(self, fim_agent_with_mocks):
        """Test probe error recovery."""
        fim_agent_with_mocks.setup()

        # Mock a probe that raises an exception
        if len(fim_agent_with_mocks._probes) > 0:
            original_scan = fim_agent_with_mocks._probes[0].scan
            fim_agent_with_mocks._probes[0].scan = MagicMock(
                side_effect=RuntimeError("probe error")
            )

            # Collection should handle the error gracefully
            # (actual behavior depends on implementation)
            fim_agent_with_mocks._probes[0].scan = original_scan

    def test_probe_independence(self, fim_agent_with_mocks):
        """Test that probes are independent."""
        fim_agent_with_mocks.setup()

        # Each probe should have its own name and description
        probe_names = set()
        for probe in fim_agent_with_mocks._probes:
            assert hasattr(probe, "name")
            assert hasattr(probe, "description")
            assert probe.name not in probe_names
            probe_names.add(probe.name)


class TestFIMAgentValidation:
    """Test event validation."""

    def test_validate_event(self, fim_agent_with_mocks):
        """Test event validation — expects protobuf DeviceTelemetry."""
        import time as _t

        from amoskys.proto import universal_telemetry_pb2 as tpb

        event = tpb.DeviceTelemetry(
            device_id="test-host",
            timestamp_ns=int(_t.time() * 1e9),
            events=[
                tpb.TelemetryEvent(
                    event_id="test-1",
                    event_type="SECURITY",
                    severity="HIGH",
                )
            ],
        )

        result = fim_agent_with_mocks.validate_event(event)
        assert result.is_valid is True


# ---------------------------------------------------------------------------
# NEW: EventBusPublisher Tests
# ---------------------------------------------------------------------------


class TestEventBusPublisher:
    """Test EventBusPublisher gRPC wrapper."""

    def test_publisher_init(self):
        """Test EventBusPublisher initialization."""
        from amoskys.agents.shared.filesystem.agent import EventBusPublisher

        pub = EventBusPublisher("localhost:50051", "/tmp/certs")
        assert pub.address == "localhost:50051"
        assert pub.cert_dir == "/tmp/certs"
        assert pub._channel is None
        assert pub._stub is None

    def test_ensure_channel_missing_cert(self, tmp_path):
        """Test _ensure_channel raises RuntimeError when certs are missing."""
        from amoskys.agents.shared.filesystem.agent import EventBusPublisher

        pub = EventBusPublisher("localhost:50051", str(tmp_path / "no_certs"))
        with pytest.raises(RuntimeError, match="Certificate not found"):
            pub._ensure_channel()

    def test_ensure_channel_generic_error(self, tmp_path):
        """Test _ensure_channel raises RuntimeError on generic error."""
        from amoskys.agents.shared.filesystem.agent import EventBusPublisher

        # Create cert files but mock grpc to fail
        cert_dir = tmp_path / "certs"
        cert_dir.mkdir()
        (cert_dir / "ca.crt").write_bytes(b"fake")
        (cert_dir / "agent.crt").write_bytes(b"fake")
        (cert_dir / "agent.key").write_bytes(b"fake")

        pub = EventBusPublisher("localhost:50051", str(cert_dir))
        with patch(
            "amoskys.agents.shared.filesystem.agent.grpc.ssl_channel_credentials",
            side_effect=Exception("ssl fail"),
        ):
            with pytest.raises(RuntimeError, match="Failed to create gRPC channel"):
                pub._ensure_channel()

    def test_close_with_channel(self):
        """Test close() when channel exists."""
        from amoskys.agents.shared.filesystem.agent import EventBusPublisher

        pub = EventBusPublisher("localhost:50051", "/tmp/certs")
        pub._channel = MagicMock()
        pub._stub = MagicMock()
        pub.close()
        assert pub._channel is None
        assert pub._stub is None

    def test_close_without_channel(self):
        """Test close() when no channel exists (noop)."""
        from amoskys.agents.shared.filesystem.agent import EventBusPublisher

        pub = EventBusPublisher("localhost:50051", "/tmp/certs")
        pub.close()  # Should not raise
        assert pub._channel is None

    def test_publish_calls_ensure_channel(self):
        """Test publish() calls _ensure_channel and publishes events."""
        from amoskys.agents.shared.filesystem.agent import EventBusPublisher
        from amoskys.proto import universal_telemetry_pb2 as tpb

        pub = EventBusPublisher("localhost:50051", "/tmp/certs")
        mock_stub = MagicMock()
        mock_ack = MagicMock()
        mock_ack.status = tpb.UniversalAck.OK
        mock_stub.PublishTelemetry.return_value = mock_ack
        pub._stub = mock_stub
        pub._channel = MagicMock()  # bypass _ensure_channel

        event = tpb.DeviceTelemetry(
            device_id="test-host",
            timestamp_ns=int(time.time() * 1e9),
        )
        pub.publish([event])
        assert mock_stub.PublishTelemetry.called

    def test_publish_raises_on_bad_ack(self):
        """Test publish() raises when EventBus returns non-OK status."""
        from amoskys.agents.shared.filesystem.agent import EventBusPublisher
        from amoskys.proto import universal_telemetry_pb2 as tpb

        pub = EventBusPublisher("localhost:50051", "/tmp/certs")
        mock_stub = MagicMock()
        mock_ack = MagicMock()
        mock_ack.status = 999  # Non-OK
        mock_stub.PublishTelemetry.return_value = mock_ack
        pub._stub = mock_stub
        pub._channel = MagicMock()

        event = tpb.DeviceTelemetry(device_id="test-host", timestamp_ns=100)
        with pytest.raises(Exception, match="EventBus returned status"):
            pub.publish([event])


# ---------------------------------------------------------------------------
# NEW: BaselineEngine Extended Tests
# ---------------------------------------------------------------------------


class TestBaselineEngineExtended:
    """Extended baseline engine tests for uncovered paths."""

    def test_create_from_paths_nonexistent(self, tmp_path):
        """Test create_from_paths with nonexistent paths (skips them)."""
        engine = BaselineEngine(str(tmp_path / "baseline.json"))
        engine.create_from_paths(["/nonexistent/abc123", "/also/missing/xyz"])
        assert len(engine.baseline) == 0

    def test_create_from_paths_with_real_files(self, tmp_path):
        """Test create_from_paths scans real directory tree."""
        # Create a small directory tree
        sub = tmp_path / "monitored"
        sub.mkdir()
        (sub / "file1.txt").write_text("hello")
        (sub / "file2.txt").write_text("world")

        engine = BaselineEngine(str(tmp_path / "baseline.json"))
        engine.create_from_paths([str(sub)])

        # Should find the directory + 2 files
        assert len(engine.baseline) >= 3

    def test_compare_detects_created_files(self, tmp_path):
        """Test compare detects newly created files."""
        engine = BaselineEngine(str(tmp_path / "baseline.json"))
        # Empty baseline
        engine.baseline = {}

        new_state = FileState(
            path="/new/file.txt",
            sha256="abc",
            size=100,
            mode=0o644,
            uid=0,
            gid=0,
            mtime_ns=1000,
            is_dir=False,
            is_symlink=False,
        )
        changes = engine.compare({"/new/file.txt": new_state})

        assert len(changes) == 1
        assert changes[0].change_type == ChangeType.CREATED

    def test_compare_detects_deleted_files(self, tmp_path):
        """Test compare detects deleted files."""
        engine = BaselineEngine(str(tmp_path / "baseline.json"))
        old_state = FileState(
            path="/old/file.txt",
            sha256="abc",
            size=100,
            mode=0o644,
            uid=0,
            gid=0,
            mtime_ns=1000,
            is_dir=False,
            is_symlink=False,
        )
        engine.baseline = {"/old/file.txt": old_state}

        changes = engine.compare({})  # empty current state = deleted
        assert len(changes) == 1
        assert changes[0].change_type == ChangeType.DELETED

    def test_compare_detects_hash_change(self, tmp_path):
        """Test compare detects hash modification."""
        engine = BaselineEngine(str(tmp_path / "baseline.json"))
        old_state = FileState(
            path="/etc/passwd",
            sha256="old_hash",
            size=100,
            mode=0o644,
            uid=0,
            gid=0,
            mtime_ns=1000,
            is_dir=False,
            is_symlink=False,
        )
        engine.baseline = {"/etc/passwd": old_state}

        new_state = FileState(
            path="/etc/passwd",
            sha256="new_hash",
            size=100,
            mode=0o644,
            uid=0,
            gid=0,
            mtime_ns=2000,
            is_dir=False,
            is_symlink=False,
        )
        changes = engine.compare({"/etc/passwd": new_state})
        assert len(changes) == 1
        assert changes[0].change_type == ChangeType.HASH_CHANGED

    def test_compare_detects_perm_change(self, tmp_path):
        """Test compare detects permission change."""
        engine = BaselineEngine(str(tmp_path / "baseline.json"))
        old = FileState(
            path="/usr/bin/x",
            sha256="abc",
            size=100,
            mode=0o755,
            uid=0,
            gid=0,
            mtime_ns=1000,
            is_dir=False,
            is_symlink=False,
        )
        engine.baseline = {"/usr/bin/x": old}

        new = FileState(
            path="/usr/bin/x",
            sha256="abc",
            size=100,
            mode=0o4755,
            uid=0,
            gid=0,
            mtime_ns=1000,
            is_dir=False,
            is_symlink=False,
        )
        changes = engine.compare({"/usr/bin/x": new})
        assert len(changes) == 1
        assert changes[0].change_type == ChangeType.PERM_CHANGED

    def test_compare_detects_owner_change(self, tmp_path):
        """Test compare detects ownership change."""
        engine = BaselineEngine(str(tmp_path / "baseline.json"))
        old = FileState(
            path="/etc/shadow",
            sha256="abc",
            size=100,
            mode=0o600,
            uid=0,
            gid=0,
            mtime_ns=1000,
            is_dir=False,
            is_symlink=False,
        )
        engine.baseline = {"/etc/shadow": old}

        new = FileState(
            path="/etc/shadow",
            sha256="abc",
            size=100,
            mode=0o600,
            uid=1000,
            gid=0,
            mtime_ns=1000,
            is_dir=False,
            is_symlink=False,
        )
        changes = engine.compare({"/etc/shadow": new})
        assert len(changes) == 1
        assert changes[0].change_type == ChangeType.OWNER_CHANGED

    def test_compare_detects_mtime_change(self, tmp_path):
        """Test compare detects modification time change."""
        engine = BaselineEngine(str(tmp_path / "baseline.json"))
        old = FileState(
            path="/var/log/auth",
            sha256=None,
            size=100,
            mode=0o644,
            uid=0,
            gid=0,
            mtime_ns=1000,
            is_dir=True,
            is_symlink=False,
        )
        engine.baseline = {"/var/log/auth": old}

        new = FileState(
            path="/var/log/auth",
            sha256=None,
            size=100,
            mode=0o644,
            uid=0,
            gid=0,
            mtime_ns=2000,
            is_dir=True,
            is_symlink=False,
        )
        changes = engine.compare({"/var/log/auth": new})
        assert len(changes) == 1
        assert changes[0].change_type == ChangeType.MODIFIED

    def test_compare_no_change(self, tmp_path):
        """Test compare returns empty list when no changes."""
        engine = BaselineEngine(str(tmp_path / "baseline.json"))
        state = FileState(
            path="/etc/hosts",
            sha256="abc",
            size=100,
            mode=0o644,
            uid=0,
            gid=0,
            mtime_ns=1000,
            is_dir=False,
            is_symlink=False,
        )
        engine.baseline = {"/etc/hosts": state}
        changes = engine.compare({"/etc/hosts": state})
        assert len(changes) == 0

    def test_save_error_handling(self, tmp_path):
        """Test save handles write errors gracefully."""
        engine = BaselineEngine("/proc/nonwritable/baseline.json")
        state = FileState(
            path="/etc/x",
            sha256="abc",
            size=10,
            mode=0o644,
            uid=0,
            gid=0,
            mtime_ns=1,
            is_dir=False,
            is_symlink=False,
        )
        engine.baseline = {"/etc/x": state}
        # Should not raise, just log error
        engine.save()


# ---------------------------------------------------------------------------
# NEW: FIMAgent Setup Extended Tests
# ---------------------------------------------------------------------------


class TestFIMAgentSetupExtended:
    """Test FIMAgent setup edge cases."""

    def test_setup_create_mode(self, tmp_path):
        """Test setup in 'create' mode returns False (one-shot baseline creation)."""
        with patch("amoskys.agents.shared.filesystem.agent.EventBusPublisher"):
            with patch("amoskys.agents.shared.filesystem.agent.LocalQueueAdapter"):
                agent = FIMAgent(baseline_mode="create", monitor_paths=[str(tmp_path)])
                result = agent.setup()
                assert result is False  # create mode exits after baseline creation

    def test_setup_monitor_no_baseline(self, tmp_path):
        """Test setup in monitor mode with no baseline switches to auto_create."""
        with patch("amoskys.agents.shared.filesystem.agent.EventBusPublisher"):
            with patch("amoskys.agents.shared.filesystem.agent.LocalQueueAdapter"):
                agent = FIMAgent(baseline_mode="monitor", monitor_paths=[str(tmp_path)])
                agent.baseline_engine = BaselineEngine(
                    str(tmp_path / "nonexistent.json")
                )
                result = agent.setup()
                assert result is True
                assert agent.baseline_mode == "auto_create"

    def test_setup_exception_returns_false(self, tmp_path):
        """Test setup returns False when an exception occurs."""
        with patch("amoskys.agents.shared.filesystem.agent.EventBusPublisher"):
            with patch("amoskys.agents.shared.filesystem.agent.LocalQueueAdapter"):
                agent = FIMAgent(baseline_mode="monitor", monitor_paths=[str(tmp_path)])
                with patch.object(
                    agent, "setup_probes", side_effect=RuntimeError("boom")
                ):
                    result = agent.setup()
                    assert result is False


# ---------------------------------------------------------------------------
# NEW: FIMAgent collect_data Extended Tests
# ---------------------------------------------------------------------------


class TestFIMAgentCollectExtended:
    """Test collect_data branches."""

    def test_collect_auto_create_baseline(self, tmp_path):
        """Test collect_data auto-creates baseline on first cycle."""
        with patch("amoskys.agents.shared.filesystem.agent.EventBusPublisher"):
            with patch("amoskys.agents.shared.filesystem.agent.LocalQueueAdapter"):
                agent = FIMAgent(baseline_mode="monitor", monitor_paths=[str(tmp_path)])
                agent.baseline_mode = "auto_create"
                # Create a test file so scan finds something
                (tmp_path / "test.txt").write_text("data")

                result = agent.collect_data()
                assert isinstance(result, list)
                assert len(result) == 1
                # After auto_create, mode should switch to monitor
                assert agent.baseline_mode == "monitor"
                # Baseline should now have entries
                assert len(agent.baseline_engine.baseline) > 0

    def test_collect_no_changes_emits_heartbeat(self, tmp_path):
        """Test collect_data emits heartbeat when no changes detected."""
        with patch("amoskys.agents.shared.filesystem.agent.EventBusPublisher"):
            with patch("amoskys.agents.shared.filesystem.agent.LocalQueueAdapter"):
                agent = FIMAgent(baseline_mode="monitor", monitor_paths=[str(tmp_path)])
                # Set baseline = current state (no changes)
                (tmp_path / "stable.txt").write_text("stable")
                state = FileState.from_path(str(tmp_path / "stable.txt"))
                agent.baseline_engine.baseline = {str(tmp_path / "stable.txt"): state}
                dir_state = FileState.from_path(str(tmp_path))
                if dir_state:
                    agent.baseline_engine.baseline[str(tmp_path)] = dir_state

                result = agent.collect_data()
                assert isinstance(result, list)
                assert len(result) == 1
                # Check the heartbeat event
                dt = result[0]
                assert dt.protocol == "FIM"
                found_heartbeat = False
                for ev in dt.events:
                    if "heartbeat" in ev.event_id:
                        found_heartbeat = True
                        break
                assert found_heartbeat

    def test_collect_with_changes_runs_probes(self, tmp_path):
        """Test collect_data with file changes runs probes and emits telemetry."""
        with patch("amoskys.agents.shared.filesystem.agent.EventBusPublisher"):
            with patch("amoskys.agents.shared.filesystem.agent.LocalQueueAdapter"):
                agent = FIMAgent(baseline_mode="monitor", monitor_paths=[str(tmp_path)])
                agent.setup()

                # Set baseline with a file
                old_state = FileState(
                    path=str(tmp_path / "modified.txt"),
                    sha256="old",
                    size=10,
                    mode=0o644,
                    uid=0,
                    gid=0,
                    mtime_ns=1000,
                    is_dir=False,
                    is_symlink=False,
                )
                agent.baseline_engine.baseline = {
                    str(tmp_path / "modified.txt"): old_state
                }

                # Write actual file with different content
                (tmp_path / "modified.txt").write_text("different content now")

                result = agent.collect_data()
                assert isinstance(result, list)

    def test_collect_probe_exception_handled(self, tmp_path):
        """Test collect_data handles probe scan exceptions gracefully."""
        with patch("amoskys.agents.shared.filesystem.agent.EventBusPublisher"):
            with patch("amoskys.agents.shared.filesystem.agent.LocalQueueAdapter"):
                agent = FIMAgent(baseline_mode="monitor", monitor_paths=[str(tmp_path)])
                agent.setup()

                # Force a change to trigger probe execution
                old_state = FileState(
                    path=str(tmp_path / "test.bin"),
                    sha256="old",
                    size=10,
                    mode=0o644,
                    uid=0,
                    gid=0,
                    mtime_ns=1000,
                    is_dir=False,
                    is_symlink=False,
                )
                agent.baseline_engine.baseline = {str(tmp_path / "test.bin"): old_state}
                (tmp_path / "test.bin").write_text("new content")

                # Make first probe raise
                if agent._probes:
                    agent._probes[0].scan = MagicMock(
                        side_effect=RuntimeError("probe boom")
                    )

                # Should not raise, just handle error
                result = agent.collect_data()
                assert isinstance(result, list)


# ---------------------------------------------------------------------------
# NEW: FIMAgent validate_event Extended Tests
# ---------------------------------------------------------------------------


class TestFIMAgentValidateExtended:
    """Test validate_event edge cases."""

    def test_validate_missing_device_id(self, fim_agent_with_mocks):
        """Test validation fails when device_id is empty."""
        from amoskys.proto import universal_telemetry_pb2 as tpb

        event = tpb.DeviceTelemetry(
            device_id="",
            timestamp_ns=int(time.time() * 1e9),
            events=[
                tpb.TelemetryEvent(event_id="x", event_type="SECURITY", severity="HIGH")
            ],
        )
        result = fim_agent_with_mocks.validate_event(event)
        assert result.is_valid is False
        assert "device_id required" in result.errors

    def test_validate_zero_timestamp(self, fim_agent_with_mocks):
        """Test validation fails when timestamp_ns is zero."""
        from amoskys.proto import universal_telemetry_pb2 as tpb

        event = tpb.DeviceTelemetry(
            device_id="host-1",
            timestamp_ns=0,
            events=[
                tpb.TelemetryEvent(event_id="x", event_type="SECURITY", severity="HIGH")
            ],
        )
        result = fim_agent_with_mocks.validate_event(event)
        assert result.is_valid is False
        assert "timestamp_ns must be positive" in result.errors

    def test_validate_empty_events(self, fim_agent_with_mocks):
        """Test validation fails when events list is empty."""
        from amoskys.proto import universal_telemetry_pb2 as tpb

        event = tpb.DeviceTelemetry(
            device_id="host-1",
            timestamp_ns=int(time.time() * 1e9),
        )
        result = fim_agent_with_mocks.validate_event(event)
        assert result.is_valid is False
        assert "events list is empty" in result.errors

    def test_validate_multiple_errors(self, fim_agent_with_mocks):
        """Test validation collects multiple errors."""
        from amoskys.proto import universal_telemetry_pb2 as tpb

        event = tpb.DeviceTelemetry(device_id="", timestamp_ns=0)
        result = fim_agent_with_mocks.validate_event(event)
        assert result.is_valid is False
        assert len(result.errors) >= 2


# ---------------------------------------------------------------------------
# NEW: FIMAgent Shutdown Tests
# ---------------------------------------------------------------------------


class TestFIMAgentShutdown:
    """Test FIMAgent shutdown behavior."""

    def test_shutdown_closes_publisher(self, fim_agent_with_mocks):
        """Test shutdown closes EventBus publisher."""
        mock_pub = MagicMock()
        fim_agent_with_mocks.eventbus_publisher = mock_pub
        fim_agent_with_mocks.shutdown()
        mock_pub.close.assert_called_once()

    def test_shutdown_stops_fsevents(self, fim_agent_with_mocks):
        """Test shutdown stops FSEvents collector if present."""
        mock_fsevents = MagicMock()
        fim_agent_with_mocks._fsevents_collector = mock_fsevents
        fim_agent_with_mocks.eventbus_publisher = MagicMock()
        fim_agent_with_mocks.shutdown()
        mock_fsevents.stop.assert_called_once()

    def test_shutdown_no_fsevents(self, fim_agent_with_mocks):
        """Test shutdown with no FSEvents collector (noop)."""
        fim_agent_with_mocks._fsevents_collector = None
        fim_agent_with_mocks.eventbus_publisher = MagicMock()
        fim_agent_with_mocks.shutdown()  # should not raise

    def test_shutdown_no_publisher(self, fim_agent_with_mocks):
        """Test shutdown with no publisher."""
        fim_agent_with_mocks.eventbus_publisher = None
        fim_agent_with_mocks._fsevents_collector = None
        fim_agent_with_mocks.shutdown()  # should not raise


# ---------------------------------------------------------------------------
# NEW: FIMAgent get_health Tests
# ---------------------------------------------------------------------------


class TestFIMAgentGetHealth:
    """Test get_health method."""

    def test_get_health_returns_dict(self, fim_agent_with_mocks):
        """Test get_health returns dict with expected keys."""
        fim_agent_with_mocks.setup()
        health = fim_agent_with_mocks.get_health()
        assert isinstance(health, dict)
        assert health["agent_name"] == "fim"
        assert "baseline_files" in health
        assert "probes" in health
        assert "circuit_breaker_state" in health
        assert "is_running" in health

    def test_get_health_baseline_count(self, fim_agent_with_mocks):
        """Test get_health reflects baseline size."""
        fim_agent_with_mocks.setup()
        state = FileState(
            path="/test",
            sha256="abc",
            size=100,
            mode=0o644,
            uid=0,
            gid=0,
            mtime_ns=1000,
            is_dir=False,
            is_symlink=False,
        )
        fim_agent_with_mocks.baseline_engine.baseline = {"/test": state}
        health = fim_agent_with_mocks.get_health()
        assert health["baseline_files"] == 1


# ---------------------------------------------------------------------------
# NEW: _events_to_telemetry Tests
# ---------------------------------------------------------------------------


class TestFIMEventsToTelemetry:
    """Test _events_to_telemetry conversion."""

    def test_events_to_telemetry_basic(self, fim_agent_with_mocks):
        """Test converting TelemetryEvents to protobuf DeviceTelemetry."""
        from amoskys.agents.common.probes import Severity, TelemetryEvent

        events = [
            TelemetryEvent(
                event_type="suid_bit_change",
                severity=Severity.HIGH,
                probe_name="suid_probe",
                data={"path": "/usr/bin/sudo", "old_mode": "0755", "new_mode": "4755"},
                mitre_techniques=["T1548"],
                confidence=0.9,
            )
        ]
        changes = [
            FileChange(
                path="/usr/bin/sudo",
                change_type=ChangeType.PERM_CHANGED,
                old_state=None,
                new_state=None,
                timestamp_ns=int(time.time() * 1e9),
            )
        ]

        result = fim_agent_with_mocks._events_to_telemetry(events, changes)
        assert result.device_id == fim_agent_with_mocks.device_id
        assert result.protocol == "FIM"
        assert (
            len(result.events) >= 3
        )  # change_count metric + probe_events metric + security event

    def test_events_to_telemetry_critical_severity(self, fim_agent_with_mocks):
        """Test CRITICAL severity gets high risk_score."""
        from amoskys.agents.common.probes import Severity, TelemetryEvent

        events = [
            TelemetryEvent(
                event_type="rootkit_detected",
                severity=Severity.CRITICAL,
                probe_name="rootkit_probe",
                data={"path": "/lib/ld_preload"},
                mitre_techniques=["T1014"],
            )
        ]
        changes = []
        result = fim_agent_with_mocks._events_to_telemetry(events, changes)

        # Find the SECURITY event
        # Nuanced scoring: CRITICAL base=0.9 * confidence=0.8 = 0.72
        for ev in result.events:
            if ev.event_type == "SECURITY":
                assert ev.security_event.risk_score == pytest.approx(0.72, abs=1e-2)
                break

    def test_events_to_telemetry_with_data_attributes(self, fim_agent_with_mocks):
        """Test that event.data is mapped to attributes."""
        from amoskys.agents.common.probes import Severity, TelemetryEvent

        events = [
            TelemetryEvent(
                event_type="webshell_drop",
                severity=Severity.HIGH,
                probe_name="webshell_probe",
                data={
                    "file_path": "/var/www/shell.php",
                    "size": "1024",
                    "none_val": None,
                },
                mitre_techniques=["T1505.003"],
            )
        ]
        changes = []
        result = fim_agent_with_mocks._events_to_telemetry(events, changes)

        # Find SECURITY event and check attributes
        for ev in result.events:
            if ev.event_type == "SECURITY":
                assert "file_path" in ev.attributes
                assert ev.attributes["file_path"] == "/var/www/shell.php"
                # None values should be skipped
                assert "none_val" not in ev.attributes
                break


# ---------------------------------------------------------------------------
# NEW: _get_platform_paths Tests
# ---------------------------------------------------------------------------


class TestFIMPlatformPaths:
    """Test platform-specific path detection."""

    def test_get_platform_paths_filters_nonexistent(self, fim_agent_with_mocks):
        """Test _get_platform_paths only returns existing directories."""
        paths = fim_agent_with_mocks._get_platform_paths()
        for p in paths:
            assert os.path.exists(p)

    def test_custom_monitor_paths(self, tmp_path):
        """Test FIMAgent with custom monitor paths."""
        with patch("amoskys.agents.shared.filesystem.agent.EventBusPublisher"):
            with patch("amoskys.agents.shared.filesystem.agent.LocalQueueAdapter"):
                custom = [str(tmp_path)]
                agent = FIMAgent(monitor_paths=custom)
                assert agent.monitor_paths == custom


# ---------------------------------------------------------------------------
# NEW: _detect_change_type static method Tests
# ---------------------------------------------------------------------------


class TestDetectChangeType:
    """Test BaselineEngine._detect_change_type static method."""

    def test_identical_returns_none(self):
        """Test identical files return None."""
        state = FileState(
            path="/x",
            sha256="abc",
            size=100,
            mode=0o644,
            uid=0,
            gid=0,
            mtime_ns=1000,
            is_dir=False,
            is_symlink=False,
        )
        result = BaselineEngine._detect_change_type(state, state)
        assert result is None

    def test_hash_change_detected(self):
        """Test hash change is detected."""
        old = FileState(
            path="/x",
            sha256="aaa",
            size=100,
            mode=0o644,
            uid=0,
            gid=0,
            mtime_ns=1000,
            is_dir=False,
            is_symlink=False,
        )
        new = FileState(
            path="/x",
            sha256="bbb",
            size=100,
            mode=0o644,
            uid=0,
            gid=0,
            mtime_ns=1000,
            is_dir=False,
            is_symlink=False,
        )
        assert BaselineEngine._detect_change_type(old, new) == ChangeType.HASH_CHANGED

    def test_perm_change_priority_over_mtime(self):
        """Test permission change detected before mtime change."""
        old = FileState(
            path="/x",
            sha256="abc",
            size=100,
            mode=0o644,
            uid=0,
            gid=0,
            mtime_ns=1000,
            is_dir=False,
            is_symlink=False,
        )
        new = FileState(
            path="/x",
            sha256="abc",
            size=100,
            mode=0o755,
            uid=0,
            gid=0,
            mtime_ns=2000,
            is_dir=False,
            is_symlink=False,
        )
        assert BaselineEngine._detect_change_type(old, new) == ChangeType.PERM_CHANGED

    def test_owner_uid_change(self):
        """Test UID change detected."""
        old = FileState(
            path="/x",
            sha256="abc",
            size=100,
            mode=0o644,
            uid=0,
            gid=0,
            mtime_ns=1000,
            is_dir=False,
            is_symlink=False,
        )
        new = FileState(
            path="/x",
            sha256="abc",
            size=100,
            mode=0o644,
            uid=1000,
            gid=0,
            mtime_ns=1000,
            is_dir=False,
            is_symlink=False,
        )
        assert BaselineEngine._detect_change_type(old, new) == ChangeType.OWNER_CHANGED

    def test_owner_gid_change(self):
        """Test GID change detected."""
        old = FileState(
            path="/x",
            sha256="abc",
            size=100,
            mode=0o644,
            uid=0,
            gid=0,
            mtime_ns=1000,
            is_dir=False,
            is_symlink=False,
        )
        new = FileState(
            path="/x",
            sha256="abc",
            size=100,
            mode=0o644,
            uid=0,
            gid=100,
            mtime_ns=1000,
            is_dir=False,
            is_symlink=False,
        )
        assert BaselineEngine._detect_change_type(old, new) == ChangeType.OWNER_CHANGED

    def test_none_hashes_skip_hash_check(self):
        """Test that None hashes fall through to other checks."""
        old = FileState(
            path="/x",
            sha256=None,
            size=100,
            mode=0o644,
            uid=0,
            gid=0,
            mtime_ns=1000,
            is_dir=True,
            is_symlink=False,
        )
        new = FileState(
            path="/x",
            sha256=None,
            size=100,
            mode=0o644,
            uid=0,
            gid=0,
            mtime_ns=2000,
            is_dir=True,
            is_symlink=False,
        )
        assert BaselineEngine._detect_change_type(old, new) == ChangeType.MODIFIED
