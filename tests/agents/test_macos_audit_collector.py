#!/usr/bin/env python3
"""Tests for MacOSAuditCollector (OpenBSM).

Tests cover:
    - XML parsing of praudit -x output
    - BSM event → KernelAuditEvent mapping
    - Incremental record tracking (start_at_end behaviour)
    - Trail rotation detection
    - Factory platform auto-detection
    - Error handling (missing praudit, bad XML, missing trail)
"""

import time
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from amoskys.agents.os.linux.kernel_audit.agent_types import KernelAuditEvent
from amoskys.agents.os.linux.kernel_audit.collector import (
    BaseKernelAuditCollector,
    MacOSAuditCollector,
    MacOSUnifiedLogCollector,
    StubKernelAuditCollector,
    create_kernel_audit_collector,
)

# =============================================================================
# Sample praudit -x XML output
# =============================================================================

SAMPLE_PRAUDIT_XML = """\
<record version="11" event="AUE_EXECVE" modifier="0" time="Mon Feb 17 10:30:00 2025" msec="123">
  <subject audit-uid="501" uid="501" euid="501" gid="20" egid="20" pid="12345" sid="100100" tid="0"/>
  <exec_args>
    <arg>/usr/bin/curl</arg>
    <arg>http://example.com</arg>
  </exec_args>
  <path>/usr/bin/curl</path>
  <return errval="success" retval="0"/>
</record>
<record version="11" event="AUE_SETUID" modifier="0" time="Mon Feb 17 10:30:01 2025" msec="456">
  <subject audit-uid="501" uid="501" euid="0" gid="20" egid="20" pid="12346" sid="100101" tid="0"/>
  <return errval="success" retval="0"/>
</record>
<record version="11" event="AUE_CHMOD" modifier="0" time="Mon Feb 17 10:30:02 2025" msec="789">
  <subject audit-uid="501" uid="501" euid="501" gid="20" egid="20" pid="12347" sid="100102" tid="0"/>
  <path>/etc/shadow</path>
  <attribute mode="0644" uid="0" gid="0"/>
  <return errval="success" retval="0"/>
</record>
"""

SAMPLE_EXECVE_TEMP = """\
<record version="11" event="AUE_EXECVE" modifier="0" time="Mon Feb 17 10:31:00 2025" msec="0">
  <subject audit-uid="501" uid="501" euid="0" gid="20" egid="20" pid="9999" sid="100200" tid="0"/>
  <exec_args>
    <arg>/tmp/malware</arg>
    <arg>--payload</arg>
  </exec_args>
  <path>/tmp/malware</path>
  <return errval="success" retval="0"/>
</record>
"""

SAMPLE_PTRACE = """\
<record version="11" event="AUE_PTRACE" modifier="0" time="Mon Feb 17 10:32:00 2025" msec="0">
  <subject audit-uid="501" uid="501" euid="501" gid="20" egid="20" pid="5555" sid="100300" tid="0"/>
  <return errval="success" retval="0"/>
</record>
"""

SAMPLE_UNKNOWN_EVENT = """\
<record version="11" event="AUE_SOME_UNKNOWN_EVENT" modifier="0" time="Mon Feb 17 10:33:00 2025" msec="0">
  <subject audit-uid="501" uid="501" euid="501" gid="20" egid="20" pid="8888" sid="100400" tid="0"/>
  <return errval="success" retval="0"/>
</record>
"""

SAMPLE_FAILED_EVENT = """\
<record version="11" event="AUE_EXECVE" modifier="0" time="Mon Feb 17 10:34:00 2025" msec="0">
  <subject audit-uid="501" uid="501" euid="501" gid="20" egid="20" pid="7777" sid="100500" tid="0"/>
  <exec_args>
    <arg>/usr/bin/restricted</arg>
  </exec_args>
  <path>/usr/bin/restricted</path>
  <return errval="Operation not permitted" retval="-1"/>
</record>
"""


# =============================================================================
# Test: XML Parsing
# =============================================================================


class TestXMLParsing:
    """Test _parse_xml and _parse_record_element."""

    def _make_collector(self):
        """Create collector with mocked trail."""
        with patch.object(MacOSAuditCollector, "_resolve_trail"):
            c = MacOSAuditCollector.__new__(MacOSAuditCollector)
            c.hostname = "test-mac"
            c._event_counter = 0
            c._trail_symlink = Path("/var/audit/current")
            c._trail_path = Path("/var/audit/20250217")
            c._record_offset = 0
            c._start_at_end = False
            return c

    def test_parse_three_records(self):
        """Parse 3 records: execve, setuid, chmod."""
        c = self._make_collector()
        records = c._parse_xml(SAMPLE_PRAUDIT_XML)
        assert len(records) == 3

    def test_execve_fields(self):
        """Verify execve record parses subject, exec_args, path, return."""
        c = self._make_collector()
        records = c._parse_xml(SAMPLE_PRAUDIT_XML)
        rec = records[0]
        assert rec["event"] == "AUE_EXECVE"
        assert rec["uid"] == "501"
        assert rec["euid"] == "501"
        assert rec["pid"] == "12345"
        assert rec["exe"] == "/usr/bin/curl"
        assert rec["exec_args"] == ["/usr/bin/curl", "http://example.com"]
        assert rec["path"] == "/usr/bin/curl"
        assert rec["errval"] == "success"

    def test_setuid_fields(self):
        """Verify setuid record parses euid=0."""
        c = self._make_collector()
        records = c._parse_xml(SAMPLE_PRAUDIT_XML)
        rec = records[1]
        assert rec["event"] == "AUE_SETUID"
        assert rec["euid"] == "0"

    def test_chmod_with_attribute(self):
        """Verify chmod record includes attribute token."""
        c = self._make_collector()
        records = c._parse_xml(SAMPLE_PRAUDIT_XML)
        rec = records[2]
        assert rec["event"] == "AUE_CHMOD"
        assert rec["path"] == "/etc/shadow"
        assert rec["attr_mode"] == "0644"

    def test_bad_xml_returns_empty(self):
        """Malformed XML returns empty list, no crash."""
        c = self._make_collector()
        records = c._parse_xml("<<< not xml at all >>>")
        assert records == []

    def test_empty_xml_returns_empty(self):
        """Empty string returns empty list."""
        c = self._make_collector()
        records = c._parse_xml("")
        assert records == []


# =============================================================================
# Test: Event Building
# =============================================================================


class TestEventBuilding:
    """Test _build_event: BSM record → KernelAuditEvent."""

    def _make_collector(self):
        c = MacOSAuditCollector.__new__(MacOSAuditCollector)
        c.hostname = "test-mac"
        c._event_counter = 0
        return c

    def test_execve_event(self):
        """AUE_EXECVE maps to syscall=execve, action=EXEC."""
        c = self._make_collector()
        records = c._parse_xml(SAMPLE_PRAUDIT_XML)
        event = c._build_event(records[0])
        assert event is not None
        assert event.syscall == "execve"
        assert event.action == "EXEC"
        assert event.exe == "/usr/bin/curl"
        assert event.pid == 12345
        assert event.uid == 501
        assert event.euid == 501
        assert event.result == "success"
        assert event.comm == "curl"
        assert event.cmdline == "/usr/bin/curl http://example.com"

    def test_setuid_event(self):
        """AUE_SETUID maps to syscall=setuid, action=SETUID."""
        c = self._make_collector()
        records = c._parse_xml(SAMPLE_PRAUDIT_XML)
        event = c._build_event(records[1])
        assert event is not None
        assert event.syscall == "setuid"
        assert event.action == "SETUID"
        assert event.euid == 0

    def test_chmod_event(self):
        """AUE_CHMOD maps to syscall=chmod, action=CHMOD."""
        c = self._make_collector()
        records = c._parse_xml(SAMPLE_PRAUDIT_XML)
        event = c._build_event(records[2])
        assert event is not None
        assert event.syscall == "chmod"
        assert event.action == "CHMOD"
        assert event.path == "/etc/shadow"

    def test_unknown_event_skipped(self):
        """Unmapped BSM event returns None."""
        c = self._make_collector()
        records = c._parse_xml(SAMPLE_UNKNOWN_EVENT)
        assert len(records) == 1
        event = c._build_event(records[0])
        assert event is None

    def test_failed_result(self):
        """Non-success errval maps to result='failed'."""
        c = self._make_collector()
        records = c._parse_xml(SAMPLE_FAILED_EVENT)
        event = c._build_event(records[0])
        assert event is not None
        assert event.result == "failed"

    def test_event_id_uniqueness(self):
        """Each event gets a unique event_id."""
        c = self._make_collector()
        records = c._parse_xml(SAMPLE_PRAUDIT_XML)
        ids = [c._build_event(r).event_id for r in records]
        assert len(set(ids)) == 3

    def test_ptrace_event(self):
        """AUE_PTRACE maps to syscall=ptrace, action=PTRACE."""
        c = self._make_collector()
        records = c._parse_xml(SAMPLE_PTRACE)
        event = c._build_event(records[0])
        assert event is not None
        assert event.syscall == "ptrace"
        assert event.action == "PTRACE"


# =============================================================================
# Test: Collect Batch (Incremental)
# =============================================================================


class TestCollectBatch:
    """Test collect_batch with incremental record tracking."""

    def _make_collector(self, start_at_end: bool = False):
        c = MacOSAuditCollector.__new__(MacOSAuditCollector)
        c.hostname = "test-mac"
        c._event_counter = 0
        c._trail_symlink = Path("/var/audit/current")
        c._trail_path = Path("/var/audit/20250217")
        c._record_offset = 0
        c._start_at_end = start_at_end
        return c

    @patch.object(MacOSAuditCollector, "_resolve_trail")
    @patch.object(MacOSAuditCollector, "_run_praudit")
    def test_first_batch_returns_all(self, mock_praudit, mock_resolve):
        """First call returns all events when start_at_end=False."""
        c = self._make_collector(start_at_end=False)
        c._trail_path = Path("/var/audit/20250217")
        mock_praudit.return_value = SAMPLE_PRAUDIT_XML

        with patch.object(Path, "exists", return_value=True):
            events = c.collect_batch()

        assert len(events) == 3  # execve, setuid, chmod all mappable

    @patch.object(MacOSAuditCollector, "_resolve_trail")
    @patch.object(MacOSAuditCollector, "_run_praudit")
    def test_start_at_end_skips_first(self, mock_praudit, mock_resolve):
        """With start_at_end=True, first call returns empty."""
        c = self._make_collector(start_at_end=True)
        c._trail_path = Path("/var/audit/20250217")
        mock_praudit.return_value = SAMPLE_PRAUDIT_XML

        with patch.object(Path, "exists", return_value=True):
            events = c.collect_batch()

        assert events == []
        assert c._record_offset == 3

    @patch.object(MacOSAuditCollector, "_resolve_trail")
    @patch.object(MacOSAuditCollector, "_run_praudit")
    def test_incremental_second_batch(self, mock_praudit, mock_resolve):
        """Second call only returns new events."""
        c = self._make_collector(start_at_end=False)
        c._trail_path = Path("/var/audit/20250217")

        # First batch: 3 records
        mock_praudit.return_value = SAMPLE_PRAUDIT_XML
        with patch.object(Path, "exists", return_value=True):
            first = c.collect_batch()
        assert len(first) == 3
        assert c._record_offset == 3

        # Second batch: 3 old + 1 new = 4 total records
        mock_praudit.return_value = SAMPLE_PRAUDIT_XML + SAMPLE_EXECVE_TEMP
        with patch.object(Path, "exists", return_value=True):
            second = c.collect_batch()
        assert len(second) == 1  # Only the new execve from /tmp
        assert second[0].exe == "/tmp/malware"
        assert c._record_offset == 4

    @patch.object(MacOSAuditCollector, "_resolve_trail")
    @patch.object(MacOSAuditCollector, "_run_praudit")
    def test_no_trail_returns_empty(self, mock_praudit, mock_resolve):
        """Missing trail file returns empty list."""
        c = self._make_collector()
        c._trail_path = None

        events = c.collect_batch()
        assert events == []
        mock_praudit.assert_not_called()

    @patch.object(MacOSAuditCollector, "_resolve_trail")
    @patch.object(MacOSAuditCollector, "_run_praudit")
    def test_praudit_returns_none(self, mock_praudit, mock_resolve):
        """If praudit fails, returns empty list."""
        c = self._make_collector()
        c._trail_path = Path("/var/audit/20250217")
        mock_praudit.return_value = None

        with patch.object(Path, "exists", return_value=True):
            events = c.collect_batch()
        assert events == []


# =============================================================================
# Test: Trail Rotation
# =============================================================================


class TestTrailRotation:
    """Test trail file rotation detection."""

    @patch("pathlib.Path.resolve")
    @patch("pathlib.Path.exists", return_value=True)
    def test_rotation_resets_offset(self, mock_exists, mock_resolve):
        """When symlink target changes, offset resets to 0."""
        c = MacOSAuditCollector.__new__(MacOSAuditCollector)
        c.hostname = "test-mac"
        c._event_counter = 0
        c._trail_symlink = Path("/var/audit/current")
        c._trail_path = Path("/var/audit/20250217_old")
        c._record_offset = 100
        c._start_at_end = False

        # Symlink now resolves to a new file
        mock_resolve.return_value = Path("/var/audit/20250217_new")

        c._resolve_trail()

        assert c._trail_path == Path("/var/audit/20250217_new")
        assert c._record_offset == 0

    @patch("pathlib.Path.resolve")
    @patch("pathlib.Path.exists", return_value=False)
    def test_missing_symlink_sets_none(self, mock_exists, mock_resolve):
        """If symlink doesn't exist, trail_path set to None."""
        c = MacOSAuditCollector.__new__(MacOSAuditCollector)
        c.hostname = "test-mac"
        c._event_counter = 0
        c._trail_symlink = Path("/var/audit/current")
        c._trail_path = Path("/var/audit/20250217")
        c._record_offset = 50
        c._start_at_end = False

        c._resolve_trail()
        assert c._trail_path is None


# =============================================================================
# Test: Factory Platform Detection
# =============================================================================


class TestFactory:
    """Test create_kernel_audit_collector factory."""

    @patch(
        "amoskys.agents.os.linux.kernel_audit.collector.platform.system",
        return_value="Darwin",
    )
    def test_darwin_returns_macos_collector(self, mock_system):
        """On Darwin, factory returns MacOSUnifiedLogCollector by default."""
        collector = create_kernel_audit_collector()
        assert isinstance(collector, MacOSUnifiedLogCollector)

    @patch(
        "amoskys.agents.os.linux.kernel_audit.collector.platform.system",
        return_value="Linux",
    )
    def test_linux_returns_auditd_collector(self, mock_system):
        """On Linux, factory returns AuditdLogCollector."""
        from amoskys.agents.os.linux.kernel_audit.collector import AuditdLogCollector

        collector = create_kernel_audit_collector()
        assert isinstance(collector, AuditdLogCollector)

    def test_stub_flag(self):
        """use_stub=True returns StubKernelAuditCollector regardless of platform."""
        collector = create_kernel_audit_collector(use_stub=True)
        assert isinstance(collector, StubKernelAuditCollector)

    @patch(
        "amoskys.agents.os.linux.kernel_audit.collector.platform.system",
        return_value="Darwin",
    )
    @patch.object(MacOSAuditCollector, "_resolve_trail")
    def test_custom_source_darwin_bsm_fallback(self, mock_resolve, mock_system):
        """Custom source with BSM fallback returns MacOSAuditCollector."""
        collector = create_kernel_audit_collector(
            source="/custom/trail", use_bsm_fallback=True
        )
        assert isinstance(collector, MacOSAuditCollector)
        assert str(collector._trail_symlink) == "/custom/trail"


# =============================================================================
# Test: Probe Platform Support
# =============================================================================


class TestProbePlatforms:
    """Verify all 7 kernel audit probes support darwin."""

    def test_all_probes_support_linux(self):
        """Every kernel audit probe lists 'linux' in platforms (Linux-only agent)."""
        from amoskys.agents.os.linux.kernel_audit.probes import (
            create_kernel_audit_probes,
        )

        probes = create_kernel_audit_probes()
        assert len(probes) == 8
        for probe in probes:
            assert (
                "linux" in probe.platforms
            ), f"{probe.name} missing 'linux' in platforms: {probe.platforms}"

    def test_all_probes_still_support_linux(self):
        """Ensure linux wasn't removed."""
        from amoskys.agents.os.linux.kernel_audit.probes import (
            create_kernel_audit_probes,
        )

        probes = create_kernel_audit_probes()
        for probe in probes:
            assert "linux" in probe.platforms


# =============================================================================
# Test: BSM Event Map Coverage
# =============================================================================


class TestBSMEventMap:
    """Verify BSM_EVENT_MAP completeness."""

    def test_execve_variants_mapped(self):
        """AUE_EXECVE, AUE_EXEC, AUE_MAC_EXECVE, AUE_POSIX_SPAWN → execve."""
        m = MacOSAuditCollector.BSM_EVENT_MAP
        for bsm in ("AUE_EXECVE", "AUE_EXEC", "AUE_MAC_EXECVE", "AUE_POSIX_SPAWN"):
            assert m[bsm] == "execve", f"{bsm} should map to execve"

    def test_privesc_events_mapped(self):
        """setuid/setgid family mapped."""
        m = MacOSAuditCollector.BSM_EVENT_MAP
        assert m["AUE_SETUID"] == "setuid"
        assert m["AUE_SETEUID"] == "seteuid"
        assert m["AUE_SETGID"] == "setgid"

    def test_permission_events_mapped(self):
        """chmod/chown family mapped."""
        m = MacOSAuditCollector.BSM_EVENT_MAP
        assert m["AUE_CHMOD"] == "chmod"
        assert m["AUE_CHOWN"] == "chown"
        assert m["AUE_FCHMOD"] == "fchmod"

    def test_ptrace_mapped(self):
        """AUE_PTRACE → ptrace."""
        assert MacOSAuditCollector.BSM_EVENT_MAP["AUE_PTRACE"] == "ptrace"

    def test_network_events_mapped(self):
        """Network syscalls mapped."""
        m = MacOSAuditCollector.BSM_EVENT_MAP
        assert m["AUE_CONNECT"] == "connect"
        assert m["AUE_BIND"] == "bind"

    def test_action_classification(self):
        """_classify_action covers key syscall → action mappings."""
        c = MacOSAuditCollector.__new__(MacOSAuditCollector)
        assert c._classify_action("execve") == "EXEC"
        assert c._classify_action("ptrace") == "PTRACE"
        assert c._classify_action("chmod") == "CHMOD"
        assert c._classify_action("setuid") == "SETUID"
        assert c._classify_action("fork") == "FORK"
        assert c._classify_action("connect") == "NETWORK"
        assert c._classify_action("open") == "FILE"
        assert c._classify_action("unknown_thing") == "OTHER"


# =============================================================================
# Test: Integration with KernelAudit Probes
# =============================================================================


class TestProbeIntegration:
    """Verify MacOS-collected events flow through probes correctly."""

    def _collect_from_xml(self, xml: str) -> List[KernelAuditEvent]:
        """Helper: parse XML → build events."""
        c = MacOSAuditCollector.__new__(MacOSAuditCollector)
        c.hostname = "test-mac"
        c._event_counter = 0
        records = c._parse_xml(xml)
        return [e for r in records if (e := c._build_event(r)) is not None]

    def test_execve_high_risk_fires(self):
        """ExecveHighRiskProbe fires on /tmp execution from BSM data."""
        from amoskys.agents.common.probes import ProbeContext
        from amoskys.agents.os.linux.kernel_audit.probes import ExecveHighRiskProbe

        events = self._collect_from_xml(SAMPLE_EXECVE_TEMP)
        assert len(events) == 1
        assert events[0].exe == "/tmp/malware"

        ctx = ProbeContext(
            device_id="test-mac",
            agent_name="kernel_audit",
            now_ns=int(time.time() * 1e9),
            shared_data={"kernel_events": events},
        )
        probe = ExecveHighRiskProbe()
        alerts = probe.scan(ctx)
        assert len(alerts) >= 1
        assert alerts[0].event_type == "kernel_execve_high_risk"

    def test_privesc_fires_on_setuid(self):
        """PrivEscSyscallProbe fires on setuid from BSM data."""
        from amoskys.agents.common.probes import ProbeContext, Severity
        from amoskys.agents.os.linux.kernel_audit.probes import PrivEscSyscallProbe

        events = self._collect_from_xml(SAMPLE_PRAUDIT_XML)
        # The setuid event has uid=501, euid=0
        setuid_events = [e for e in events if e.syscall == "setuid"]
        assert len(setuid_events) == 1

        ctx = ProbeContext(
            device_id="test-mac",
            agent_name="kernel_audit",
            now_ns=int(time.time() * 1e9),
            shared_data={"kernel_events": setuid_events},
        )
        probe = PrivEscSyscallProbe()
        alerts = probe.scan(ctx)
        assert len(alerts) >= 1
        assert alerts[0].severity in (Severity.HIGH, Severity.CRITICAL)
