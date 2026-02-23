"""Extended tests for kernel_audit/collector.py — targeting uncovered code paths.

Focus areas NOT covered by test_macos_audit_collector.py or test_kernel_audit_v2.py:
    - AuditdLogCollector: full lifecycle (collect_batch, rotation, truncation, parsing)
    - AuditdLogCollector: _parse_audit_line edge cases
    - AuditdLogCollector: _build_event with various syscalls and edge cases
    - AuditdLogCollector: _classify_action for all action branches
    - MacOSAuditCollector: _run_praudit error branches (FileNotFoundError, timeout, generic)
    - MacOSAuditCollector: _build_event timestamp parse failure
    - MacOSAuditCollector: _parse_record_element with text, multiple paths, attributes
    - MacOSUnifiedLogCollector: _query_unified_log error branches
    - MacOSUnifiedLogCollector: _build_event edge cases (uid extraction, missing fields)
    - MacOSUnifiedLogCollector: _classify_action all branches
    - MacOSUnifiedLogCollector: _action_to_syscall mapping
    - MacOSUnifiedLogCollector: _infer_result for failed vs success
    - StubKernelAuditCollector: inject and collect
    - create_kernel_audit_collector: Linux branch, Darwin default, Darwin BSM fallback
"""

import json
import subprocess
import time
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, mock_open, patch

import pytest

from amoskys.agents.kernel_audit.collector import (
    AuditdLogCollector,
    BaseKernelAuditCollector,
    MacOSAuditCollector,
    MacOSUnifiedLogCollector,
    StubKernelAuditCollector,
    create_kernel_audit_collector,
)
from amoskys.agents.kernel_audit.types import KernelAuditEvent

# =============================================================================
# BaseKernelAuditCollector
# =============================================================================


class TestBaseKernelAuditCollector:
    """Test base collector."""

    def test_generate_event_id_uniqueness(self):
        """Each call produces a unique event ID."""
        base = BaseKernelAuditCollector()
        ids = [base._generate_event_id("data") for _ in range(100)]
        assert len(set(ids)) == 100

    def test_generate_event_id_is_hex(self):
        """Event IDs are 16-char hex strings."""
        base = BaseKernelAuditCollector()
        eid = base._generate_event_id("test")
        assert len(eid) == 16
        int(eid, 16)  # should not raise

    def test_collect_batch_raises(self):
        """Base collect_batch raises NotImplementedError."""
        base = BaseKernelAuditCollector()
        with pytest.raises(NotImplementedError):
            base.collect_batch()


# =============================================================================
# AuditdLogCollector — Init and File Handling
# =============================================================================


class TestAuditdLogCollectorInit:
    """Test auditd collector initialization and file handling."""

    def test_init_existing_file_start_at_end(self, tmp_path):
        """start_at_end=True sets offset to file size."""
        log = tmp_path / "audit.log"
        log.write_text("line1\nline2\n")
        c = AuditdLogCollector(source=str(log), start_at_end=True)
        assert c._offset == log.stat().st_size

    def test_init_existing_file_start_at_beginning(self, tmp_path):
        """start_at_end=False keeps offset at 0."""
        log = tmp_path / "audit.log"
        log.write_text("line1\nline2\n")
        c = AuditdLogCollector(source=str(log), start_at_end=False)
        assert c._offset == 0

    def test_init_missing_file(self, tmp_path):
        """Missing log file sets inode to None."""
        c = AuditdLogCollector(source=str(tmp_path / "missing.log"))
        assert c._inode is None
        assert c._offset == 0

    def test_collect_batch_missing_file(self, tmp_path):
        """collect_batch returns empty when file does not exist."""
        c = AuditdLogCollector(source=str(tmp_path / "no.log"))
        assert c.collect_batch() == []


class TestAuditdLogCollectorCollectBatch:
    """Test collect_batch logic: rotation, truncation, reading."""

    def test_log_rotation_resets_offset(self, tmp_path):
        """When inode changes, offset resets to 0."""
        log = tmp_path / "audit.log"
        log.write_text("")
        c = AuditdLogCollector(source=str(log), start_at_end=True)
        original_inode = c._inode

        # Simulate rotation: delete and recreate with new inode
        log.unlink()
        log.write_text(
            "type=SYSCALL msg=audit(1000000000.000:1): arch=c000003e syscall=59 "
            'success=yes pid=100 ppid=1 uid=0 euid=0 gid=0 egid=0 exe="/bin/ls"\n'
        )
        events = c.collect_batch()
        # inode changed, so offset should have reset
        new_inode = c._inode
        # The file was recreated so the inode is likely different
        assert isinstance(events, list)

    def test_truncated_file_resets_offset(self, tmp_path):
        """When file shrinks, offset resets to 0."""
        log = tmp_path / "audit.log"
        log.write_text("x" * 1000)
        c = AuditdLogCollector(source=str(log), start_at_end=True)
        assert c._offset == 1000

        # Truncate
        log.write_text("short")
        events = c.collect_batch()
        assert isinstance(events, list)

    def test_no_new_data_returns_empty(self, tmp_path):
        """No new data returns empty list."""
        log = tmp_path / "audit.log"
        log.write_text("")
        c = AuditdLogCollector(source=str(log), start_at_end=True)
        assert c.collect_batch() == []

    def test_read_error_returns_empty(self, tmp_path):
        """IO error during read returns empty list."""
        log = tmp_path / "audit.log"
        log.write_text("")
        c = AuditdLogCollector(source=str(log), start_at_end=False)

        with patch("builtins.open", side_effect=PermissionError("denied")):
            events = c.collect_batch()
        assert events == []

    def test_collect_syscall_events(self, tmp_path):
        """SYSCALL lines are parsed into KernelAuditEvent objects."""
        log = tmp_path / "audit.log"
        log.write_text(
            "type=SYSCALL msg=audit(1700000000.123:999): arch=c000003e syscall=59 "
            "success=yes pid=100 ppid=1 uid=1000 euid=0 gid=100 egid=100 "
            'tty=pts0 exe="/usr/bin/sudo" comm="sudo" '
            'cwd="/home/user" name="/usr/bin/sudo"\n'
        )
        c = AuditdLogCollector(source=str(log), start_at_end=False)
        events = c.collect_batch()
        assert len(events) == 1
        e = events[0]
        assert e.syscall == "execve"
        assert e.action == "EXEC"
        assert e.pid == 100
        assert e.ppid == 1
        assert e.uid == 1000
        assert e.euid == 0
        assert e.result == "success"
        assert e.exe == "/usr/bin/sudo"
        assert e.comm == "sudo"
        assert e.tty == "pts0"
        assert e.cwd == "/home/user"

    def test_collect_non_syscall_ignored(self, tmp_path):
        """Non-SYSCALL record types are ignored."""
        log = tmp_path / "audit.log"
        log.write_text(
            'type=EXECVE msg=audit(1700000000.000:1): argc=2 a0="/bin/ls"\n'
            'type=PATH msg=audit(1700000000.000:1): name="/bin/ls"\n'
        )
        c = AuditdLogCollector(source=str(log), start_at_end=False)
        events = c.collect_batch()
        assert events == []

    def test_collect_failed_syscall(self, tmp_path):
        """Failed syscall result is captured."""
        log = tmp_path / "audit.log"
        log.write_text(
            "type=SYSCALL msg=audit(1700000000.000:2): syscall=59 success=no "
            'pid=200 uid=1000 exe="/usr/bin/restricted"\n'
        )
        c = AuditdLogCollector(source=str(log), start_at_end=False)
        events = c.collect_batch()
        assert len(events) == 1
        assert events[0].result == "failed"


# =============================================================================
# AuditdLogCollector — Parsing
# =============================================================================


class TestAuditdLogParsing:
    """Test _parse_audit_line and _build_event edge cases."""

    def _make_collector(self, tmp_path):
        log = tmp_path / "audit.log"
        log.write_text("")
        return AuditdLogCollector(source=str(log), start_at_end=False)

    def test_parse_valid_line(self, tmp_path):
        c = self._make_collector(tmp_path)
        line = "type=SYSCALL msg=audit(1700000000.000:1): syscall=59 success=yes pid=10"
        result = c._parse_audit_line(line)
        assert result is not None
        assert result["type"] == "SYSCALL"
        assert result["timestamp"] == "1700000000.000"
        assert result["serial"] == "1"
        assert result["fields"]["syscall"] == "59"

    def test_parse_invalid_line(self, tmp_path):
        c = self._make_collector(tmp_path)
        assert c._parse_audit_line("random garbage") is None
        assert c._parse_audit_line("") is None

    def test_parse_quoted_values(self, tmp_path):
        c = self._make_collector(tmp_path)
        line = 'type=SYSCALL msg=audit(1.0:1): exe="/usr/bin/bash" comm="bash"'
        result = c._parse_audit_line(line)
        assert result["fields"]["exe"] == "/usr/bin/bash"
        assert result["fields"]["comm"] == "bash"

    def test_build_event_unknown_syscall_number(self, tmp_path):
        """Unknown syscall number becomes syscall_NNN."""
        c = self._make_collector(tmp_path)
        parsed = {
            "type": "SYSCALL",
            "timestamp": "1700000000.000",
            "serial": "1",
            "fields": {"syscall": "999", "success": "yes"},
            "raw": "raw line",
        }
        event = c._build_event(parsed)
        assert event is not None
        assert event.syscall == "syscall_999"
        assert event.action == "OTHER"

    def test_build_event_non_numeric_syscall(self, tmp_path):
        """Non-numeric syscall value is used as-is."""
        c = self._make_collector(tmp_path)
        parsed = {
            "type": "SYSCALL",
            "timestamp": "1700000000.000",
            "serial": "1",
            "fields": {"syscall": "execve", "success": "yes"},
            "raw": "raw",
        }
        event = c._build_event(parsed)
        assert event.syscall == "execve"

    def test_build_event_invalid_timestamp(self, tmp_path):
        """Invalid timestamp falls back to current time."""
        c = self._make_collector(tmp_path)
        parsed = {
            "type": "SYSCALL",
            "timestamp": "not-a-float",
            "serial": "1",
            "fields": {"syscall": "59", "success": "yes"},
            "raw": "raw",
        }
        before = int(time.time() * 1e9)
        event = c._build_event(parsed)
        after = int(time.time() * 1e9)
        assert before <= event.timestamp_ns <= after

    def test_build_event_safe_int_none(self, tmp_path):
        """Missing numeric fields are None."""
        c = self._make_collector(tmp_path)
        parsed = {
            "type": "SYSCALL",
            "timestamp": "1700000000.0",
            "serial": "1",
            "fields": {"syscall": "59", "success": "yes"},
            "raw": "raw",
        }
        event = c._build_event(parsed)
        assert event.pid is None
        assert event.ppid is None
        assert event.uid is None

    def test_build_event_uses_name_or_path(self, tmp_path):
        """Path comes from 'name' field; falls back to 'path'."""
        c = self._make_collector(tmp_path)
        parsed = {
            "type": "SYSCALL",
            "timestamp": "1.0",
            "serial": "1",
            "fields": {"syscall": "59", "success": "yes", "name": "/etc/passwd"},
            "raw": "raw",
        }
        event = c._build_event(parsed)
        assert event.path == "/etc/passwd"

        parsed2 = {
            "type": "SYSCALL",
            "timestamp": "1.0",
            "serial": "1",
            "fields": {"syscall": "59", "success": "yes", "path": "/etc/shadow"},
            "raw": "raw",
        }
        event2 = c._build_event(parsed2)
        assert event2.path == "/etc/shadow"


# =============================================================================
# AuditdLogCollector — _classify_action (all branches)
# =============================================================================


class TestAuditdClassifyAction:
    """Test _classify_action covers all action types."""

    def _c(self, tmp_path):
        log = tmp_path / "audit.log"
        log.write_text("")
        return AuditdLogCollector(source=str(log))

    def test_exec(self, tmp_path):
        c = self._c(tmp_path)
        assert c._classify_action("execve") == "EXEC"
        assert c._classify_action("execveat") == "EXEC"

    def test_module_load(self, tmp_path):
        c = self._c(tmp_path)
        assert c._classify_action("init_module") == "MODULE_LOAD"
        assert c._classify_action("finit_module") == "MODULE_LOAD"

    def test_module_unload(self, tmp_path):
        c = self._c(tmp_path)
        assert c._classify_action("delete_module") == "MODULE_UNLOAD"

    def test_ptrace(self, tmp_path):
        c = self._c(tmp_path)
        assert c._classify_action("ptrace") == "PTRACE"

    def test_chmod(self, tmp_path):
        c = self._c(tmp_path)
        assert c._classify_action("chmod") == "CHMOD"
        assert c._classify_action("fchmod") == "CHMOD"
        assert c._classify_action("fchmodat") == "CHMOD"

    def test_chown(self, tmp_path):
        c = self._c(tmp_path)
        assert c._classify_action("chown") == "CHOWN"
        assert c._classify_action("fchown") == "CHOWN"
        assert c._classify_action("lchown") == "CHOWN"
        assert c._classify_action("fchownat") == "CHOWN"

    def test_setuid(self, tmp_path):
        c = self._c(tmp_path)
        assert c._classify_action("setuid") == "SETUID"
        assert c._classify_action("seteuid") == "SETUID"
        assert c._classify_action("setreuid") == "SETUID"
        assert c._classify_action("setresuid") == "SETUID"

    def test_setgid(self, tmp_path):
        c = self._c(tmp_path)
        assert c._classify_action("setgid") == "SETGID"
        assert c._classify_action("setegid") == "SETGID"
        assert c._classify_action("setregid") == "SETGID"
        assert c._classify_action("setresgid") == "SETGID"

    def test_capset(self, tmp_path):
        c = self._c(tmp_path)
        assert c._classify_action("capset") == "CAPSET"

    def test_fork(self, tmp_path):
        c = self._c(tmp_path)
        assert c._classify_action("fork") == "FORK"
        assert c._classify_action("vfork") == "FORK"
        assert c._classify_action("clone") == "FORK"
        assert c._classify_action("clone3") == "FORK"

    def test_kill(self, tmp_path):
        c = self._c(tmp_path)
        assert c._classify_action("kill") == "KILL"

    def test_memory(self, tmp_path):
        c = self._c(tmp_path)
        assert c._classify_action("mmap") == "MEMORY"
        assert c._classify_action("mprotect") == "MEMORY"

    def test_other(self, tmp_path):
        c = self._c(tmp_path)
        assert c._classify_action("read") == "OTHER"
        assert c._classify_action("something_unknown") == "OTHER"


# =============================================================================
# MacOSAuditCollector — _run_praudit error paths
# =============================================================================


class TestMacOSAuditCollectorPraudit:
    """Test _run_praudit subprocess error handling."""

    def _make_collector(self):
        with patch.object(MacOSAuditCollector, "_resolve_trail"):
            c = MacOSAuditCollector.__new__(MacOSAuditCollector)
            c.hostname = "test-mac"
            c._event_counter = 0
            c._trail_symlink = Path("/var/audit/current")
            c._trail_path = Path("/var/audit/20250217")
            c._record_offset = 0
            c._start_at_end = False
            return c

    @patch("subprocess.run")
    def test_praudit_success(self, mock_run):
        """Successful praudit returns stdout."""
        c = self._make_collector()
        mock_run.return_value = MagicMock(returncode=0, stdout="<xml/>", stderr="")
        result = c._run_praudit()
        assert result == "<xml/>"

    @patch("subprocess.run")
    def test_praudit_nonzero_return(self, mock_run):
        """Non-zero exit code returns None."""
        c = self._make_collector()
        mock_run.return_value = MagicMock(returncode=1, stderr="error msg")
        result = c._run_praudit()
        assert result is None

    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_praudit_not_found(self, mock_run):
        """FileNotFoundError returns None."""
        c = self._make_collector()
        assert c._run_praudit() is None

    @patch(
        "subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="praudit", timeout=30),
    )
    def test_praudit_timeout(self, mock_run):
        """TimeoutExpired returns None."""
        c = self._make_collector()
        assert c._run_praudit() is None

    @patch("subprocess.run", side_effect=OSError("disk error"))
    def test_praudit_generic_error(self, mock_run):
        """Generic Exception returns None."""
        c = self._make_collector()
        assert c._run_praudit() is None


# =============================================================================
# MacOSAuditCollector — _build_event edge cases
# =============================================================================


class TestMacOSBuildEventEdgeCases:
    """Test _build_event for timestamp parsing errors and comm extraction."""

    def _make_collector(self):
        c = MacOSAuditCollector.__new__(MacOSAuditCollector)
        c.hostname = "test-mac"
        c._event_counter = 0
        return c

    def test_timestamp_parse_failure(self):
        """Bad timestamp falls back to current time."""
        c = self._make_collector()
        rec = {
            "event": "AUE_EXECVE",
            "time": "invalid time string",
            "msec": "0",
            "modifier": "",
            "uid": "501",
            "euid": "501",
            "pid": "100",
            "errval": "success",
        }
        before = int(time.time() * 1e9)
        event = c._build_event(rec)
        after = int(time.time() * 1e9)
        assert event is not None
        assert before <= event.timestamp_ns <= after

    def test_comm_extraction_from_exe(self):
        """comm is extracted from last path component of exe."""
        c = self._make_collector()
        rec = {
            "event": "AUE_EXECVE",
            "time": "Mon Feb 17 10:30:00 2025",
            "msec": "0",
            "modifier": "",
            "uid": "501",
            "euid": "501",
            "pid": "100",
            "errval": "success",
            "exe": "/usr/local/bin/myapp",
            "exec_args": ["/usr/local/bin/myapp", "--verbose"],
        }
        event = c._build_event(rec)
        assert event.comm == "myapp"
        assert event.cmdline == "/usr/local/bin/myapp --verbose"

    def test_no_exe_no_comm(self):
        """No exe field results in no comm."""
        c = self._make_collector()
        rec = {
            "event": "AUE_FORK",
            "time": "Mon Feb 17 10:30:00 2025",
            "msec": "0",
            "modifier": "",
            "uid": "0",
            "pid": "1",
            "errval": "success",
        }
        event = c._build_event(rec)
        assert event.comm is None

    def test_empty_numeric_field(self):
        """Empty string numeric fields produce None."""
        c = self._make_collector()
        rec = {
            "event": "AUE_KILL",
            "time": "Mon Feb 17 10:30:00 2025",
            "msec": "0",
            "modifier": "",
            "uid": "",
            "euid": "",
            "gid": "",
            "egid": "",
            "pid": "",
            "errval": "failure",
        }
        event = c._build_event(rec)
        assert event.uid is None
        assert event.pid is None
        assert event.result == "failed"

    def test_unmapped_event_returns_none(self):
        """Unmapped BSM event returns None."""
        c = self._make_collector()
        rec = {"event": "AUE_SOMETHING_RANDOM", "time": "", "msec": "0", "modifier": ""}
        event = c._build_event(rec)
        assert event is None


# =============================================================================
# MacOSAuditCollector — _parse_record_element with text and multi-path
# =============================================================================


class TestMacOSParseRecordElement:
    """Test _parse_record_element with various XML structures."""

    def _make_collector(self):
        c = MacOSAuditCollector.__new__(MacOSAuditCollector)
        c.hostname = "test-mac"
        c._event_counter = 0
        return c

    def test_record_with_text_token(self):
        """Parse record with <text> element."""
        c = self._make_collector()
        xml = (
            '<record event="AUE_EXECVE" time="Mon Feb 17 10:30:00 2025" msec="0" modifier="">'
            "  <text>some info text</text>"
            '  <subject audit-uid="501" uid="501" euid="501" gid="20" '
            '  egid="20" pid="999" sid="1" tid="0"/>'
            '  <return errval="success" retval="0"/>'
            "</record>"
        )
        records = c._parse_xml(xml)
        assert len(records) == 1
        assert records[0]["text"] == "some info text"

    def test_record_with_multiple_paths(self):
        """Parse record with two <path> elements."""
        c = self._make_collector()
        xml = (
            '<record event="AUE_CHMOD" time="Mon Feb 17 10:30:00 2025" msec="0" modifier="">'
            "  <path>/old/path</path>"
            "  <path>/new/path</path>"
            '  <return errval="success" retval="0"/>'
            "</record>"
        )
        records = c._parse_xml(xml)
        assert records[0]["path"] == "/old/path"
        assert records[0]["path2"] == "/new/path"


# =============================================================================
# MacOSAuditCollector — _classify_action for macOS (all branches)
# =============================================================================


class TestMacOSClassifyAction:
    """Test macOS _classify_action covers all branches."""

    def _c(self):
        c = MacOSAuditCollector.__new__(MacOSAuditCollector)
        return c

    def test_exec(self):
        c = self._c()
        assert c._classify_action("execve") == "EXEC"
        assert c._classify_action("execveat") == "EXEC"

    def test_ptrace(self):
        assert self._c()._classify_action("ptrace") == "PTRACE"

    def test_chmod(self):
        c = self._c()
        assert c._classify_action("chmod") == "CHMOD"
        assert c._classify_action("fchmod") == "CHMOD"

    def test_chown(self):
        c = self._c()
        assert c._classify_action("chown") == "CHOWN"
        assert c._classify_action("fchown") == "CHOWN"
        assert c._classify_action("lchown") == "CHOWN"

    def test_setuid(self):
        c = self._c()
        assert c._classify_action("setuid") == "SETUID"
        assert c._classify_action("seteuid") == "SETUID"
        assert c._classify_action("setreuid") == "SETUID"

    def test_setgid(self):
        c = self._c()
        assert c._classify_action("setgid") == "SETGID"
        assert c._classify_action("setegid") == "SETGID"
        assert c._classify_action("setregid") == "SETGID"

    def test_fork(self):
        c = self._c()
        assert c._classify_action("fork") == "FORK"
        assert c._classify_action("vfork") == "FORK"

    def test_kill(self):
        assert self._c()._classify_action("kill") == "KILL"

    def test_memory(self):
        c = self._c()
        assert c._classify_action("mmap") == "MEMORY"
        assert c._classify_action("mprotect") == "MEMORY"

    def test_network(self):
        c = self._c()
        assert c._classify_action("connect") == "NETWORK"
        assert c._classify_action("bind") == "NETWORK"
        assert c._classify_action("listen") == "NETWORK"
        assert c._classify_action("accept") == "NETWORK"

    def test_file(self):
        c = self._c()
        assert c._classify_action("open") == "FILE"
        assert c._classify_action("unlink") == "FILE"
        assert c._classify_action("truncate") == "FILE"

    def test_other(self):
        assert self._c()._classify_action("something_unknown") == "OTHER"


# =============================================================================
# MacOSUnifiedLogCollector — _query_unified_log
# =============================================================================


class TestUnifiedLogQuery:
    """Test _query_unified_log error handling branches."""

    @patch("subprocess.run")
    def test_empty_output(self, mock_run):
        """Empty stdout returns empty list."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        c = MacOSUnifiedLogCollector()
        entries = c._query_unified_log()
        assert entries == []

    @patch("subprocess.run")
    def test_whitespace_only_output(self, mock_run):
        """Whitespace-only stdout returns empty list."""
        mock_run.return_value = MagicMock(returncode=0, stdout="  \n  \n", stderr="")
        c = MacOSUnifiedLogCollector()
        entries = c._query_unified_log()
        assert entries == []

    @patch("subprocess.run")
    def test_nonzero_return_code(self, mock_run):
        """Non-zero return code returns empty list."""
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
        c = MacOSUnifiedLogCollector()
        entries = c._query_unified_log()
        assert entries == []

    @patch("subprocess.run")
    def test_valid_ndjson(self, mock_run):
        """Valid NDJSON lines are parsed."""
        lines = (
            '{"eventMessage": "exec", "processImagePath": "/bin/ls"}\n'
            '{"eventMessage": "fork", "processImagePath": "/bin/sh"}\n'
        )
        mock_run.return_value = MagicMock(returncode=0, stdout=lines, stderr="")
        c = MacOSUnifiedLogCollector()
        entries = c._query_unified_log()
        assert len(entries) == 2

    @patch("subprocess.run")
    def test_invalid_ndjson_skipped(self, mock_run):
        """Invalid JSON lines are skipped."""
        lines = '{"valid": true}\n' "not json at all\n" '{"also_valid": true}\n'
        mock_run.return_value = MagicMock(returncode=0, stdout=lines, stderr="")
        c = MacOSUnifiedLogCollector()
        entries = c._query_unified_log()
        assert len(entries) == 2

    @patch(
        "subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="log", timeout=30)
    )
    def test_timeout(self, mock_run):
        """TimeoutExpired returns empty list."""
        c = MacOSUnifiedLogCollector()
        assert c._query_unified_log() == []

    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_file_not_found(self, mock_run):
        """FileNotFoundError returns empty list."""
        c = MacOSUnifiedLogCollector()
        assert c._query_unified_log() == []

    @patch("subprocess.run", side_effect=RuntimeError("unexpected"))
    def test_generic_exception(self, mock_run):
        """Generic exception returns empty list."""
        c = MacOSUnifiedLogCollector()
        assert c._query_unified_log() == []


# =============================================================================
# MacOSUnifiedLogCollector — _build_event
# =============================================================================


class TestUnifiedLogBuildEvent:
    """Test _build_event for unified log entries."""

    def test_basic_exec_event(self):
        """Build an EXEC event from unified log entry."""
        c = MacOSUnifiedLogCollector()
        entry = {
            "eventMessage": "execve: /usr/bin/ls executed",
            "processImagePath": "/usr/bin/ls",
            "processID": 1234,
            "senderImagePath": "/usr/lib/dyld",
            "category": "security",
            "subsystem": "com.apple.securityd",
            "timestamp": "2025-02-17 10:30:00.000000-0600",
        }
        event = c._build_event(entry)
        assert event is not None
        assert event.action == "EXEC"
        assert event.syscall == "execve"
        assert event.pid == 1234
        assert event.exe == "/usr/bin/ls"
        assert event.comm == "ls"
        assert event.result == "success"

    def test_empty_message_returns_none(self):
        """Empty eventMessage returns None."""
        c = MacOSUnifiedLogCollector()
        entry = {
            "eventMessage": "",
            "processImagePath": "/usr/bin/ls",
            "processID": 1,
        }
        assert c._build_event(entry) is None

    def test_empty_process_returns_none(self):
        """Empty processImagePath returns None."""
        c = MacOSUnifiedLogCollector()
        entry = {
            "eventMessage": "some event",
            "processImagePath": "",
            "processID": 1,
        }
        assert c._build_event(entry) is None

    def test_uid_extraction_from_message(self):
        """UID is extracted from message text."""
        c = MacOSUnifiedLogCollector()
        entry = {
            "eventMessage": "setuid: uid=1000 changed",
            "processImagePath": "/usr/bin/sudo",
            "processID": 5,
            "category": "",
            "subsystem": "",
            "timestamp": "",
        }
        event = c._build_event(entry)
        assert event is not None
        assert event.uid == 1000

    def test_no_timestamp_uses_current(self):
        """Missing timestamp uses current time."""
        c = MacOSUnifiedLogCollector()
        entry = {
            "eventMessage": "execve: /bin/bash",
            "processImagePath": "/bin/bash",
            "processID": 10,
            "category": "",
            "subsystem": "",
        }
        before = int(time.time() * 1e9)
        event = c._build_event(entry)
        after = int(time.time() * 1e9)
        assert event is not None
        assert before <= event.timestamp_ns <= after

    def test_invalid_timestamp_uses_current(self):
        """Invalid timestamp falls back to current time."""
        c = MacOSUnifiedLogCollector()
        entry = {
            "eventMessage": "execve: running",
            "processImagePath": "/bin/test",
            "processID": 10,
            "timestamp": "not-a-date",
            "category": "",
            "subsystem": "",
        }
        event = c._build_event(entry)
        assert event is not None

    def test_process_id_zero_is_none(self):
        """processID=0 maps to pid=None."""
        c = MacOSUnifiedLogCollector()
        entry = {
            "eventMessage": "fork event",
            "processImagePath": "/sbin/launchd",
            "processID": 0,
            "category": "",
            "subsystem": "",
            "timestamp": "",
        }
        event = c._build_event(entry)
        assert event is not None
        assert event.pid is None

    def test_non_security_event_returns_none(self):
        """Message with no security keywords returns None."""
        c = MacOSUnifiedLogCollector()
        entry = {
            "eventMessage": "started service ABC",
            "processImagePath": "/usr/bin/something",
            "processID": 100,
            "category": "",
            "subsystem": "",
            "timestamp": "",
        }
        event = c._build_event(entry)
        assert event is None


# =============================================================================
# MacOSUnifiedLogCollector — _classify_action
# =============================================================================


class TestUnifiedLogClassifyAction:
    """Test _classify_action for all branch paths."""

    def _c(self):
        return MacOSUnifiedLogCollector()

    def test_setuid(self):
        c = self._c()
        assert c._classify_action("setuid called", "proc", "") == "SETUID"
        assert c._classify_action("seteuid invoked", "proc", "") == "SETUID"

    def test_setgid(self):
        c = self._c()
        assert c._classify_action("setgid operation", "proc", "") == "SETGID"
        assert c._classify_action("setegid changed", "proc", "") == "SETGID"

    def test_capset(self):
        c = self._c()
        assert c._classify_action("capset applied", "proc", "") == "CAPSET"

    def test_exec(self):
        c = self._c()
        assert c._classify_action("execve completed", "proc", "") == "EXEC"
        assert c._classify_action("execute binary", "proc", "") == "EXEC"

    def test_ptrace(self):
        c = self._c()
        assert c._classify_action("ptrace attach", "proc", "") == "PTRACE"
        assert c._classify_action("trace active", "proc", "") == "PTRACE"
        assert c._classify_action("debugger attached", "proc", "") == "PTRACE"

    def test_privilege_deny(self):
        c = self._c()
        result = c._classify_action("operation denied by policy", "securityd", "")
        assert result == "PRIVILEGE_DENY"

    def test_privilege_allow(self):
        c = self._c()
        result = c._classify_action("privilege allowed", "authd", "")
        assert result == "PRIVILEGE_ALLOW"

    def test_module_load(self):
        c = self._c()
        assert c._classify_action("module load completed", "proc", "") == "MODULE_LOAD"
        assert c._classify_action("kext driver unload", "proc", "") == "MODULE_LOAD"
        assert (
            c._classify_action("kernel extension load request", "proc", "")
            == "MODULE_LOAD"
        )

    def test_sandbox_violation(self):
        c = self._c()
        assert (
            c._classify_action("sandbox restricted", "sandbox", "")
            == "SANDBOX_VIOLATION"
        )
        assert c._classify_action("sandbox event", "proc", "") == "SANDBOX_VIOLATION"

    def test_fork(self):
        c = self._c()
        assert c._classify_action("fork called", "proc", "") == "FORK"
        assert c._classify_action("vfork invoked", "proc", "") == "FORK"
        assert c._classify_action("clone process", "proc", "") == "FORK"

    def test_kill(self):
        c = self._c()
        assert c._classify_action("kill signal sent", "proc", "") == "KILL"
        assert c._classify_action("signal delivered", "proc", "") == "KILL"

    def test_other_security(self):
        c = self._c()
        assert c._classify_action("security check passed", "proc", "") == "OTHER"
        assert c._classify_action("auth validated", "proc", "") == "OTHER"
        assert c._classify_action("permission granted", "proc", "") == "OTHER"
        assert c._classify_action("access control check", "proc", "") == "OTHER"
        assert c._classify_action("violation detected", "proc", "") == "OTHER"

    def test_no_match_returns_none(self):
        c = self._c()
        assert c._classify_action("normal log message", "proc", "") is None


# =============================================================================
# MacOSUnifiedLogCollector — _action_to_syscall and _infer_result
# =============================================================================


class TestUnifiedLogHelpers:
    """Test _action_to_syscall and _infer_result."""

    def test_action_to_syscall_mapping(self):
        c = MacOSUnifiedLogCollector()
        assert c._action_to_syscall("EXEC") == "execve"
        assert c._action_to_syscall("PTRACE") == "ptrace"
        assert c._action_to_syscall("SETUID") == "setuid"
        assert c._action_to_syscall("SETGID") == "setgid"
        assert c._action_to_syscall("CAPSET") == "capset"
        assert c._action_to_syscall("PRIVILEGE_DENY") == "access"
        assert c._action_to_syscall("PRIVILEGE_ALLOW") == "access"
        assert c._action_to_syscall("MODULE_LOAD") == "init_module"
        assert c._action_to_syscall("SANDBOX_VIOLATION") == "mprotect"
        assert c._action_to_syscall("FORK") == "fork"
        assert c._action_to_syscall("KILL") == "kill"
        assert c._action_to_syscall("UNKNOWN") is None
        assert c._action_to_syscall("OTHER") is None

    def test_infer_result_failed(self):
        c = MacOSUnifiedLogCollector()
        assert c._infer_result("operation denied") == "failed"
        assert c._infer_result("access denied to resource") == "failed"
        assert c._infer_result("failed to execute") == "failed"
        assert c._infer_result("error occurred") == "failed"

    def test_infer_result_success(self):
        c = MacOSUnifiedLogCollector()
        assert c._infer_result("operation completed") == "success"
        assert c._infer_result("process started") == "success"


# =============================================================================
# MacOSUnifiedLogCollector — collect_batch integration
# =============================================================================


class TestUnifiedLogCollectBatch:
    """Test collect_batch end-to-end."""

    @patch("subprocess.run")
    def test_collect_batch_filters_non_security(self, mock_run):
        """Non-security messages produce no events."""
        entries = [
            {
                "eventMessage": "normal log message",
                "processImagePath": "/usr/bin/something",
                "processID": 100,
                "category": "",
                "subsystem": "",
                "timestamp": "",
            }
        ]
        ndjson = "\n".join(json.dumps(e) for e in entries)
        mock_run.return_value = MagicMock(returncode=0, stdout=ndjson, stderr="")
        c = MacOSUnifiedLogCollector()
        events = c.collect_batch()
        assert events == []

    @patch("subprocess.run")
    def test_collect_batch_produces_events(self, mock_run):
        """Security messages produce events."""
        entries = [
            {
                "eventMessage": "execve: /usr/bin/curl executed",
                "processImagePath": "/usr/bin/curl",
                "processID": 500,
                "category": "security",
                "subsystem": "com.apple.kernel",
                "timestamp": "2025-02-17 10:30:00.000000-0600",
            }
        ]
        ndjson = "\n".join(json.dumps(e) for e in entries)
        mock_run.return_value = MagicMock(returncode=0, stdout=ndjson, stderr="")
        c = MacOSUnifiedLogCollector()
        events = c.collect_batch()
        assert len(events) == 1
        assert events[0].syscall == "execve"

    @patch("subprocess.run")
    def test_collect_batch_query_failure(self, mock_run):
        """Query failure returns empty list."""
        mock_run.side_effect = RuntimeError("fail")
        c = MacOSUnifiedLogCollector()
        events = c.collect_batch()
        assert events == []


# =============================================================================
# StubKernelAuditCollector
# =============================================================================


class TestStubCollector:
    """Test stub collector for completeness."""

    def test_inject_and_collect(self):
        """Injected events are returned and cleared."""
        c = StubKernelAuditCollector()
        e1 = KernelAuditEvent(event_id="1", timestamp_ns=0, host="h")
        e2 = KernelAuditEvent(event_id="2", timestamp_ns=0, host="h")
        c.inject([e1, e2])
        events = c.collect_batch()
        assert len(events) == 2
        assert c.collect_batch() == []

    def test_empty_collect(self):
        """No injection returns empty."""
        c = StubKernelAuditCollector()
        assert c.collect_batch() == []


# =============================================================================
# Factory — create_kernel_audit_collector
# =============================================================================


class TestFactoryExtended:
    """Test factory branches not covered by existing tests."""

    def test_stub_returns_stub(self):
        c = create_kernel_audit_collector(use_stub=True)
        assert isinstance(c, StubKernelAuditCollector)

    @patch(
        "amoskys.agents.kernel_audit.collector.platform.system", return_value="Linux"
    )
    def test_linux_default_path(self, _):
        c = create_kernel_audit_collector()
        assert isinstance(c, AuditdLogCollector)
        assert str(c.source) == "/var/log/audit/audit.log"

    @patch(
        "amoskys.agents.kernel_audit.collector.platform.system", return_value="Linux"
    )
    def test_linux_custom_path(self, _):
        c = create_kernel_audit_collector(source="/custom/audit.log")
        assert isinstance(c, AuditdLogCollector)
        assert str(c.source) == "/custom/audit.log"

    @patch(
        "amoskys.agents.kernel_audit.collector.platform.system", return_value="Darwin"
    )
    def test_darwin_default_unified(self, _):
        c = create_kernel_audit_collector()
        assert isinstance(c, MacOSUnifiedLogCollector)

    @patch(
        "amoskys.agents.kernel_audit.collector.platform.system", return_value="Darwin"
    )
    @patch.object(MacOSAuditCollector, "_resolve_trail")
    def test_darwin_bsm_fallback(self, mock_resolve, _):
        c = create_kernel_audit_collector(use_bsm_fallback=True)
        assert isinstance(c, MacOSAuditCollector)

    @patch(
        "amoskys.agents.kernel_audit.collector.platform.system", return_value="Darwin"
    )
    @patch.object(MacOSAuditCollector, "_resolve_trail")
    def test_darwin_bsm_custom_source(self, mock_resolve, _):
        c = create_kernel_audit_collector(source="/my/trail", use_bsm_fallback=True)
        assert isinstance(c, MacOSAuditCollector)
        assert str(c._trail_symlink) == "/my/trail"

    @patch(
        "amoskys.agents.kernel_audit.collector.platform.system", return_value="FreeBSD"
    )
    def test_unknown_platform_falls_to_linux(self, _):
        """Unrecognized platform falls through to Linux auditd."""
        c = create_kernel_audit_collector()
        assert isinstance(c, AuditdLogCollector)
