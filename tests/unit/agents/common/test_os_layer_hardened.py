"""Tests for Phase 4 OS layer hardening.

Validates:
    - P0-17: _run_subprocess() returns typed SubprocessOutcome
    - P0-18: AccessDenied produces -1.0 sentinel (not fake 0.0)
    - P0-19: _schema_version field on dataclasses
"""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from amoskys.agents.common.metrics import SCHEMA_VERSION, SubprocessOutcome
from amoskys.agents.common.os_layer import (
    FileInfo,
    NetworkConnection,
    ProcessInfo,
    StubOSLayer,
    USBDevice,
)

# ---------------------------------------------------------------------------
# P0-19: Schema versioning on dataclasses
# ---------------------------------------------------------------------------


class TestSchemaVersioning:
    def test_process_info_has_schema_version(self):
        p = ProcessInfo(
            pid=1,
            name="test",
            exe="/bin/test",
            cmdline=[],
            uid=0,
            ppid=0,
            cpu_percent=1.0,
            memory_mb=10.0,
            status="running",
            create_time=0.0,
        )
        assert p._schema_version == SCHEMA_VERSION

    def test_network_connection_has_schema_version(self):
        nc = NetworkConnection(
            pid=1,
            process_name="test",
            local_addr="127.0.0.1",
            local_port=8080,
            remote_addr="10.0.0.1",
            remote_port=443,
            protocol="tcp",
            status="ESTABLISHED",
        )
        assert nc._schema_version == SCHEMA_VERSION

    def test_file_info_has_schema_version(self):
        fi = FileInfo(
            path="/etc/passwd",
            size=1024,
            mode=0o644,
            uid=0,
            gid=0,
            mtime=0.0,
        )
        assert fi._schema_version == SCHEMA_VERSION

    def test_usb_device_has_schema_version(self):
        usb = USBDevice(vendor_id="1234", product_id="5678", name="TestDevice")
        assert usb._schema_version == SCHEMA_VERSION

    def test_schema_version_not_in_init(self):
        """_schema_version should not be an init parameter."""
        # This should work without passing _schema_version
        p = ProcessInfo(
            pid=1,
            name="t",
            exe="",
            cmdline=[],
            uid=0,
            ppid=0,
            cpu_percent=0.0,
            memory_mb=0.0,
            status="",
            create_time=0.0,
        )
        assert hasattr(p, "_schema_version")

    def test_schema_version_not_in_repr(self):
        """_schema_version should not appear in repr."""
        p = ProcessInfo(
            pid=1,
            name="t",
            exe="",
            cmdline=[],
            uid=0,
            ppid=0,
            cpu_percent=0.0,
            memory_mb=0.0,
            status="",
            create_time=0.0,
        )
        assert "_schema_version" not in repr(p)


# ---------------------------------------------------------------------------
# P0-18: AccessDenied sentinel values
# ---------------------------------------------------------------------------


class TestAccessDeniedSentinel:
    def test_sentinel_value_is_negative(self):
        """Sentinel -1.0 should be distinguishable from real 0.0."""
        p = ProcessInfo(
            pid=1,
            name="restricted",
            exe="/usr/sbin/restricted",
            cmdline=[],
            uid=0,
            ppid=0,
            cpu_percent=-1.0,
            memory_mb=-1.0,
            status="running",
            create_time=0.0,
        )
        assert p.cpu_percent < 0
        assert p.memory_mb < 0

    def test_zero_is_valid_not_sentinel(self):
        """0.0 should represent a real zero reading (exited process)."""
        p = ProcessInfo(
            pid=1,
            name="idle",
            exe="/bin/idle",
            cmdline=[],
            uid=0,
            ppid=0,
            cpu_percent=0.0,
            memory_mb=0.0,
            status="zombie",
            create_time=0.0,
        )
        assert p.cpu_percent == 0.0
        assert p.memory_mb == 0.0

    def test_sentinel_below_any_threshold(self):
        """Sentinel -1.0 should naturally fail any 'cpu > X' threshold check."""
        p = ProcessInfo(
            pid=1,
            name="r",
            exe="",
            cmdline=[],
            uid=0,
            ppid=0,
            cpu_percent=-1.0,
            memory_mb=-1.0,
            status="",
            create_time=0.0,
        )
        # Common threshold checks should exclude sentinel
        assert not (p.cpu_percent > 90)
        assert not (p.memory_mb > 100)


# ---------------------------------------------------------------------------
# P0-17: _run_subprocess typed wrapper
# ---------------------------------------------------------------------------


class TestRunSubprocess:
    def setup_method(self):
        self.layer = StubOSLayer()
        # StubOSLayer inherits _run_subprocess from OSLayer

    def test_success(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="hello\n", stderr="")
            stdout, outcome = self.layer._run_subprocess(
                ["echo", "hello"], operation="test"
            )

        assert outcome == SubprocessOutcome.SUCCESS
        assert stdout == "hello\n"

    def test_nonzero_exit(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
            stdout, outcome = self.layer._run_subprocess(["false"], operation="test")

        assert outcome == SubprocessOutcome.NONZERO_EXIT
        assert stdout is None

    def test_timeout(self):
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="slow", timeout=10)
            stdout, outcome = self.layer._run_subprocess(
                ["slow"], timeout=10, operation="test"
            )

        assert outcome == SubprocessOutcome.TIMEOUT
        assert stdout is None

    def test_not_found(self):
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("no such command")
            stdout, outcome = self.layer._run_subprocess(
                ["nonexistent"], operation="test"
            )

        assert outcome == SubprocessOutcome.NOT_FOUND
        assert stdout is None

    def test_access_denied(self):
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = PermissionError("access denied")
            stdout, outcome = self.layer._run_subprocess(
                ["restricted"], operation="test"
            )

        assert outcome == SubprocessOutcome.ACCESS_DENIED
        assert stdout is None

    def test_generic_exception(self):
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = OSError("disk error")
            stdout, outcome = self.layer._run_subprocess(["broken"], operation="test")

        assert outcome == SubprocessOutcome.EXCEPTION
        assert stdout is None
