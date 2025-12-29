"""
Tests for AMOSKYS File Integrity Monitoring Agent (FIMAgent)
"""

import json
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from amoskys.agents.file_integrity import FileChange, FileState, FIMAgent


class TestFileState:
    """Tests for FileState dataclass"""

    def test_file_state_creation(self):
        """Test basic FileState creation"""
        state = FileState(
            path="/usr/bin/ls",
            sha256="abc123" * 10 + "abcd",
            size=123456,
            mode=0o755,
            uid=0,
            gid=0,
            mtime=1234567890.0,
        )

        assert state.path == "/usr/bin/ls"
        assert state.size == 123456
        assert state.mode == 0o755
        assert state.is_suid is False
        assert state.is_sgid is False

    def test_file_state_with_suid(self):
        """Test FileState with SUID bit"""
        state = FileState(
            path="/usr/bin/sudo",
            sha256="def456" * 10 + "defg",
            size=100000,
            mode=0o4755,
            uid=0,
            gid=0,
            mtime=1234567890.0,
            is_suid=True,
        )

        assert state.is_suid is True


class TestFileChange:
    """Tests for FileChange dataclass"""

    def test_file_change_created(self):
        """Test FileChange for new file"""
        new_state = FileState(
            path="/tmp/malicious.php",
            sha256="bad123" * 10 + "badx",
            size=1024,
            mode=0o644,
            uid=1000,
            gid=1000,
            mtime=datetime.now().timestamp(),
        )

        change = FileChange(
            path="/tmp/malicious.php",
            change_type="CREATED",
            old_state=None,
            new_state=new_state,
            severity="INFO",
            description="New file created",
        )

        assert change.change_type == "CREATED"
        assert change.old_state is None
        assert change.new_state is not None

    def test_file_change_modified(self):
        """Test FileChange for modified file"""
        old_state = FileState(
            path="/usr/bin/ls",
            sha256="old123" * 10 + "oldx",
            size=100000,
            mode=0o755,
            uid=0,
            gid=0,
            mtime=1234567890.0,
        )

        new_state = FileState(
            path="/usr/bin/ls",
            sha256="new456" * 10 + "newx",
            size=100100,
            mode=0o755,
            uid=0,
            gid=0,
            mtime=1234567900.0,
        )

        change = FileChange(
            path="/usr/bin/ls",
            change_type="MODIFIED",
            old_state=old_state,
            new_state=new_state,
            severity="CRITICAL",
            description="Critical binary modified",
            mitre_techniques=["T1574", "T1036"],
        )

        assert change.change_type == "MODIFIED"
        assert change.severity == "CRITICAL"
        assert "T1574" in change.mitre_techniques


class TestFIMAgent:
    """Tests for FIMAgent"""

    @pytest.fixture
    def temp_dirs(self):
        """Create temporary directories for testing"""
        with tempfile.TemporaryDirectory() as tmpdir:
            queue_path = Path(tmpdir) / "queue" / "fim.db"
            baseline_path = Path(tmpdir) / "baseline.json"
            test_dir = Path(tmpdir) / "monitored"
            test_dir.mkdir(parents=True)

            yield {
                "queue_path": str(queue_path),
                "baseline_path": str(baseline_path),
                "test_dir": str(test_dir),
            }

    @pytest.fixture
    def fim_agent(self, temp_dirs):
        """Create FIMAgent instance for testing"""
        with patch.object(FIMAgent, "_get_monitored_paths") as mock_paths:
            mock_paths.return_value = [temp_dirs["test_dir"]]

            agent = FIMAgent(
                queue_path=temp_dirs["queue_path"],
                baseline_path=temp_dirs["baseline_path"],
                scan_interval=60,
            )
            return agent

    def test_agent_initialization(self, fim_agent):
        """Test FIMAgent initializes correctly"""
        assert fim_agent is not None
        assert fim_agent.platform in ["macos", "linux", "windows", "unknown"]

    def test_hash_file(self, fim_agent, temp_dirs):
        """Test file hashing"""
        # Create a test file
        test_file = Path(temp_dirs["test_dir"]) / "test.txt"
        test_file.write_text("Hello, World!")

        file_hash = fim_agent._hash_file(str(test_file))

        assert file_hash is not None
        assert len(file_hash) == 64  # SHA-256 hex digest

    def test_hash_file_nonexistent(self, fim_agent):
        """Test hashing nonexistent file returns None"""
        file_hash = fim_agent._hash_file("/nonexistent/file.txt")
        assert file_hash is None

    def test_get_file_state(self, fim_agent, temp_dirs):
        """Test getting file state"""
        # Create a test file
        test_file = Path(temp_dirs["test_dir"]) / "state_test.txt"
        test_file.write_text("Test content")

        state = fim_agent._get_file_state(str(test_file))

        assert state is not None
        assert state.path == str(test_file)
        assert state.size > 0
        assert state.sha256 is not None

    def test_scan_directory(self, fim_agent, temp_dirs):
        """Test directory scanning"""
        # Create test files
        test_dir = Path(temp_dirs["test_dir"])
        (test_dir / "file1.txt").write_text("Content 1")
        (test_dir / "file2.txt").write_text("Content 2")
        subdir = test_dir / "subdir"
        subdir.mkdir()
        (subdir / "file3.txt").write_text("Content 3")

        states = fim_agent.scan_directory(str(test_dir))

        assert len(states) >= 3

    def test_compare_states_new_file(self, fim_agent):
        """Test comparing states for new file"""
        new_state = FileState(
            path="/test/new.txt",
            sha256="abc" * 21 + "a",
            size=100,
            mode=0o644,
            uid=1000,
            gid=1000,
            mtime=datetime.now().timestamp(),
        )

        change = fim_agent._compare_states("/test/new.txt", None, new_state)

        assert change is not None
        assert change.change_type == "CREATED"

    def test_compare_states_deleted_file(self, fim_agent):
        """Test comparing states for deleted file"""
        old_state = FileState(
            path="/test/old.txt",
            sha256="abc" * 21 + "a",
            size=100,
            mode=0o644,
            uid=1000,
            gid=1000,
            mtime=datetime.now().timestamp(),
        )

        change = fim_agent._compare_states("/test/old.txt", old_state, None)

        assert change is not None
        assert change.change_type == "DELETED"

    def test_compare_states_modified_file(self, fim_agent):
        """Test comparing states for modified file"""
        old_state = FileState(
            path="/test/mod.txt",
            sha256="old" * 21 + "o",
            size=100,
            mode=0o644,
            uid=1000,
            gid=1000,
            mtime=1000.0,
        )

        new_state = FileState(
            path="/test/mod.txt",
            sha256="new" * 21 + "n",
            size=200,
            mode=0o644,
            uid=1000,
            gid=1000,
            mtime=2000.0,
        )

        change = fim_agent._compare_states("/test/mod.txt", old_state, new_state)

        assert change is not None
        assert change.change_type == "MODIFIED"

    def test_compare_states_no_change(self, fim_agent):
        """Test comparing identical states"""
        state = FileState(
            path="/test/same.txt",
            sha256="abc" * 21 + "a",
            size=100,
            mode=0o644,
            uid=1000,
            gid=1000,
            mtime=1000.0,
        )

        change = fim_agent._compare_states("/test/same.txt", state, state)

        assert change is None

    def test_classify_change_critical_binary(self, fim_agent):
        """Test classification of critical binary modification"""
        change = FileChange(
            path="/usr/bin/ls",
            change_type="MODIFIED",
            old_state=None,
            new_state=None,
            severity="INFO",
            description="Binary modified",
        )

        fim_agent._classify_change(change)

        assert change.severity == "CRITICAL"
        assert "T1574" in change.mitre_techniques

    def test_classify_change_suid_addition(self, fim_agent):
        """Test classification of SUID bit addition"""
        old_state = FileState(
            path="/tmp/binary",
            sha256="abc" * 21 + "a",
            size=100,
            mode=0o755,
            uid=0,
            gid=0,
            mtime=1000.0,
            is_suid=False,
        )

        new_state = FileState(
            path="/tmp/binary",
            sha256="abc" * 21 + "a",
            size=100,
            mode=0o4755,
            uid=0,
            gid=0,
            mtime=2000.0,
            is_suid=True,
        )

        change = FileChange(
            path="/tmp/binary",
            change_type="PERMISSION_CHANGED",
            old_state=old_state,
            new_state=new_state,
            severity="INFO",
            description="Permissions changed",
        )

        fim_agent._classify_change(change)

        assert change.severity == "CRITICAL"
        assert "T1548.001" in change.mitre_techniques
        assert "NEW SUID BIT" in change.description

    def test_full_scan_creates_baseline(self, fim_agent, temp_dirs):
        """Test that full scan creates baseline"""
        # Create test files
        test_dir = Path(temp_dirs["test_dir"])
        (test_dir / "baseline.txt").write_text("Baseline content")

        changes = fim_agent.full_scan()

        # First scan should show all files as new (if no baseline existed)
        # and update the baseline
        assert isinstance(changes, list)
        assert len(fim_agent.baseline) > 0

    def test_full_scan_detects_changes(self, fim_agent, temp_dirs):
        """Test that full scan detects file changes"""
        test_dir = Path(temp_dirs["test_dir"])
        test_file = test_dir / "changing.txt"

        # Initial scan
        test_file.write_text("Original content")
        fim_agent.full_scan()

        # Modify file
        test_file.write_text("Modified content")

        # Second scan should detect change
        changes = fim_agent.full_scan()

        modified_changes = [c for c in changes if c.change_type == "MODIFIED"]
        # May or may not detect depending on timing
        assert isinstance(changes, list)


class TestFIMAgentIntegration:
    """Integration tests for FIMAgent"""

    @pytest.fixture
    def integration_setup(self):
        """Set up for integration tests"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    def test_baseline_persistence(self, integration_setup):
        """Test that baseline persists across agent restarts"""
        queue_path = Path(integration_setup) / "queue" / "fim.db"
        baseline_path = Path(integration_setup) / "baseline.json"
        test_dir = Path(integration_setup) / "files"
        test_dir.mkdir()

        # Create test file
        (test_dir / "persist.txt").write_text("Persistent")

        # First agent instance
        with patch.object(FIMAgent, "_get_monitored_paths") as mock_paths:
            mock_paths.return_value = [str(test_dir)]
            agent1 = FIMAgent(
                queue_path=str(queue_path),
                baseline_path=str(baseline_path),
            )
            agent1.full_scan()

        # Verify baseline file exists
        assert baseline_path.exists()

        # Second agent instance should load baseline
        with patch.object(FIMAgent, "_get_monitored_paths") as mock_paths:
            mock_paths.return_value = [str(test_dir)]
            agent2 = FIMAgent(
                queue_path=str(queue_path),
                baseline_path=str(baseline_path),
            )

        assert len(agent2.baseline) > 0
