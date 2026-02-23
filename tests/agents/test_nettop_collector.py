#!/usr/bin/env python3
"""Tests for MacOSNettopCollector (per-process byte counts).

Tests cover:
    - CSV output parsing (header, data lines, edge cases)
    - PID extraction from ProcessName.PID format
    - Multi-entry PID aggregation
    - Subprocess error handling (timeout, missing binary)
    - Integration: nettop bytes merge into FlowEvent
    - Probes fire with real byte values
"""

import time
from unittest.mock import MagicMock, patch

import pytest

from amoskys.agents.common.probes import ProbeContext, Severity
from amoskys.agents.flow.nettop_collector import MacOSNettopCollector, NettopRecord
from amoskys.agents.flow.probes import (
    C2BeaconFlowProbe,
    DataExfilVolumeSpikeProbe,
    FlowEvent,
    SuspiciousTunnelProbe,
)

# =============================================================================
# Sample nettop outputs
# =============================================================================

SAMPLE_NETTOP_OUTPUT = """\
,bytes_in,bytes_out,
launchd.1,0,0,
snmpd.347,319,812,
mDNSResponder.514,43284870,26438227,
Google Chrome H.1019,47787,92643,
Safari.2345,1048576,52428800,
"""

SAMPLE_NETTOP_MULTIENTRY = """\
,bytes_in,bytes_out,
chrome.1019,100,200,
chrome.1019,300,400,
"""

SAMPLE_NETTOP_EMPTY = """\
,bytes_in,bytes_out,
"""

SAMPLE_NETTOP_MALFORMED = """\
,bytes_in,bytes_out,
badline_no_pid,100,200,
,100,200,
launchd.1,not_a_number,200,
good.999,500,600,
"""


# =============================================================================
# Test: NettopRecord
# =============================================================================


class TestNettopRecord:
    """Test the NettopRecord dataclass."""

    def test_total_bytes(self):
        rec = NettopRecord(pid=1, process_name="test", bytes_in=100, bytes_out=200)
        assert rec.total_bytes == 300

    def test_zero_bytes(self):
        rec = NettopRecord(pid=1, process_name="idle", bytes_in=0, bytes_out=0)
        assert rec.total_bytes == 0


# =============================================================================
# Test: Output Parsing
# =============================================================================


class TestNettopParsing:
    """Test CSV output parsing logic."""

    def test_parse_standard_output(self):
        """Standard nettop output with multiple processes."""
        records = MacOSNettopCollector._parse_output(SAMPLE_NETTOP_OUTPUT)

        assert len(records) == 5
        assert 1 in records
        assert 347 in records
        assert 514 in records
        assert 1019 in records
        assert 2345 in records

    def test_parse_pid_extraction(self):
        """PID is correctly extracted from ProcessName.PID format."""
        records = MacOSNettopCollector._parse_output(SAMPLE_NETTOP_OUTPUT)

        assert records[1].process_name == "launchd"
        assert records[1].pid == 1
        assert records[347].process_name == "snmpd"
        assert records[514].process_name == "mDNSResponder"

    def test_parse_process_name_with_spaces(self):
        """Process names with spaces are handled correctly."""
        records = MacOSNettopCollector._parse_output(SAMPLE_NETTOP_OUTPUT)

        assert records[1019].process_name == "Google Chrome H"
        assert records[1019].bytes_in == 47787
        assert records[1019].bytes_out == 92643

    def test_parse_byte_values(self):
        """Byte counts are parsed as integers."""
        records = MacOSNettopCollector._parse_output(SAMPLE_NETTOP_OUTPUT)

        assert records[514].bytes_in == 43284870
        assert records[514].bytes_out == 26438227

        assert records[1].bytes_in == 0
        assert records[1].bytes_out == 0

    def test_parse_empty_output(self):
        """Header-only output returns empty dict."""
        records = MacOSNettopCollector._parse_output(SAMPLE_NETTOP_EMPTY)
        assert len(records) == 0

    def test_parse_completely_empty(self):
        """Empty string returns empty dict."""
        records = MacOSNettopCollector._parse_output("")
        assert len(records) == 0

    def test_parse_multi_entry_aggregation(self):
        """Multiple entries for same PID are summed."""
        records = MacOSNettopCollector._parse_output(SAMPLE_NETTOP_MULTIENTRY)

        assert len(records) == 1
        assert records[1019].bytes_in == 400  # 100 + 300
        assert records[1019].bytes_out == 600  # 200 + 400

    def test_parse_malformed_lines_skipped(self):
        """Malformed lines are skipped, valid lines still parsed."""
        records = MacOSNettopCollector._parse_output(SAMPLE_NETTOP_MALFORMED)

        assert len(records) == 1
        assert 999 in records
        assert records[999].bytes_in == 500
        assert records[999].bytes_out == 600

    def test_parse_line_no_dot(self):
        """Line without dot separator returns None."""
        result = MacOSNettopCollector._parse_line("nodot,100,200")
        assert result is None

    def test_parse_line_trailing_dot(self):
        """Line with trailing dot (no PID) returns None."""
        result = MacOSNettopCollector._parse_line("process.,100,200")
        assert result is None

    def test_parse_line_wrong_field_count(self):
        """Line with wrong number of comma-separated fields returns None."""
        assert MacOSNettopCollector._parse_line("a.1,100") is None
        assert MacOSNettopCollector._parse_line("a.1,100,200,300") is None

    def test_parse_line_valid(self):
        """Valid line parses correctly."""
        rec = MacOSNettopCollector._parse_line("Safari.2345,1048576,52428800,")
        assert rec is not None
        assert rec.pid == 2345
        assert rec.process_name == "Safari"
        assert rec.bytes_in == 1048576
        assert rec.bytes_out == 52428800


# =============================================================================
# Test: Subprocess Handling
# =============================================================================


class TestNettopCollection:
    """Test subprocess execution and error handling."""

    @patch("amoskys.agents.flow.nettop_collector.subprocess.run")
    def test_collect_success(self, mock_run):
        """Successful nettop run returns parsed records."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=SAMPLE_NETTOP_OUTPUT,
            stderr="",
        )

        collector = MacOSNettopCollector()
        records = collector.collect()

        assert len(records) == 5
        mock_run.assert_called_once()

    @patch("amoskys.agents.flow.nettop_collector.subprocess.run")
    def test_collect_timeout(self, mock_run):
        """Timeout returns empty dict and increments error count."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="nettop", timeout=10)

        collector = MacOSNettopCollector()
        records = collector.collect()

        assert records == {}
        assert collector._collection_errors == 1

    @patch("amoskys.agents.flow.nettop_collector.subprocess.run")
    def test_collect_not_found(self, mock_run):
        """FileNotFoundError returns empty dict."""
        mock_run.side_effect = FileNotFoundError("nettop")

        collector = MacOSNettopCollector()
        records = collector.collect()

        assert records == {}
        assert collector._collection_errors == 1

    @patch("amoskys.agents.flow.nettop_collector.subprocess.run")
    def test_collect_nonzero_exit_no_output(self, mock_run):
        """Non-zero exit with no stdout returns empty dict."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="permission denied",
        )

        collector = MacOSNettopCollector()
        records = collector.collect()

        assert records == {}

    @patch("amoskys.agents.flow.nettop_collector.subprocess.run")
    def test_collect_nonzero_exit_with_output(self, mock_run):
        """Non-zero exit but with stdout still parses output."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout=SAMPLE_NETTOP_OUTPUT,
            stderr="warning",
        )

        collector = MacOSNettopCollector()
        records = collector.collect()

        assert len(records) == 5  # Still parsed


# =============================================================================
# Test: FlowEvent Integration
# =============================================================================


class TestFlowNettopIntegration:
    """Test nettop byte counts merge into FlowEvent objects."""

    def test_flow_event_has_pid_fields(self):
        """FlowEvent supports pid and process_name fields."""
        flow = FlowEvent(
            src_ip="10.0.0.1",
            dst_ip="93.184.216.34",
            src_port=54321,
            dst_port=443,
            protocol="TCP",
            bytes_tx=0,
            bytes_rx=0,
            packet_count=1,
            first_seen_ns=0,
            last_seen_ns=0,
            pid=1234,
            process_name="curl",
        )
        assert flow.pid == 1234
        assert flow.process_name == "curl"

    def test_merge_bytes_by_pid(self):
        """Simulate nettop merge: match FlowEvent.pid → NettopRecord.pid."""
        flows = [
            FlowEvent(
                src_ip="10.0.0.1",
                dst_ip="93.184.216.34",
                src_port=54321,
                dst_port=443,
                protocol="TCP",
                bytes_tx=0,
                bytes_rx=0,
                packet_count=1,
                first_seen_ns=0,
                last_seen_ns=0,
                pid=1019,
                process_name="Chrome",
            ),
            FlowEvent(
                src_ip="10.0.0.1",
                dst_ip="8.8.8.8",
                src_port=55555,
                dst_port=53,
                protocol="UDP",
                bytes_tx=0,
                bytes_rx=0,
                packet_count=1,
                first_seen_ns=0,
                last_seen_ns=0,
                pid=514,
                process_name="mDNSResponder",
            ),
            FlowEvent(
                src_ip="10.0.0.1",
                dst_ip="1.1.1.1",
                src_port=60000,
                dst_port=80,
                protocol="TCP",
                bytes_tx=0,
                bytes_rx=0,
                packet_count=1,
                first_seen_ns=0,
                last_seen_ns=0,
                pid=None,  # No PID — should be skipped
            ),
        ]

        nettop_records = MacOSNettopCollector._parse_output(SAMPLE_NETTOP_OUTPUT)

        # Simulate the merge logic from MacOSFlowCollector.collect()
        merged = 0
        for flow in flows:
            if flow.pid and flow.pid in nettop_records:
                rec = nettop_records[flow.pid]
                flow.bytes_rx = rec.bytes_in
                flow.bytes_tx = rec.bytes_out
                if not flow.process_name:
                    flow.process_name = rec.process_name
                merged += 1

        assert merged == 2
        assert flows[0].bytes_rx == 47787  # Chrome bytes_in
        assert flows[0].bytes_tx == 92643  # Chrome bytes_out
        assert flows[1].bytes_rx == 43284870  # mDNSResponder bytes_in
        assert flows[1].bytes_tx == 26438227  # mDNSResponder bytes_out
        assert flows[2].bytes_tx == 0  # No PID → unchanged
        assert flows[2].bytes_rx == 0


# =============================================================================
# Test: Probes Fire with Real Byte Values
# =============================================================================


class TestProbesWithBytes:
    """Verify probes that depend on byte counts fire after nettop merge."""

    def test_exfil_probe_fires_with_nettop_bytes(self):
        """DataExfilVolumeSpikeProbe fires when bytes_tx ≥ 50MB threshold."""
        probe = DataExfilVolumeSpikeProbe()
        now_ns = int(time.time() * 1e9)

        # 52 MB outbound transfer (from nettop)
        flows = [
            FlowEvent(
                src_ip="10.0.0.5",
                dst_ip="203.0.113.99",
                src_port=54321,
                dst_port=443,
                protocol="TCP",
                bytes_tx=52 * 1024 * 1024,  # 52 MB — nettop populated
                bytes_rx=1024,
                packet_count=100,
                first_seen_ns=now_ns,
                last_seen_ns=now_ns,
                direction="OUTBOUND",
                pid=5555,
                process_name="suspicious_app",
            )
        ]

        context = ProbeContext(
            agent_name="flow_agent_v2",
            device_id="test-host",
            now_ns=now_ns,
            shared_data={"flows": flows},
        )

        events = probe.scan(context)
        assert len(events) >= 1
        assert events[0].event_type == "flow_exfil_volume_spike"
        assert events[0].severity == Severity.CRITICAL

    def test_exfil_probe_silent_with_zero_bytes(self):
        """DataExfilVolumeSpikeProbe does NOT fire when bytes_tx is 0."""
        probe = DataExfilVolumeSpikeProbe()
        now_ns = int(time.time() * 1e9)

        flows = [
            FlowEvent(
                src_ip="10.0.0.5",
                dst_ip="203.0.113.99",
                src_port=54321,
                dst_port=443,
                protocol="TCP",
                bytes_tx=0,  # No nettop — still zero
                bytes_rx=0,
                packet_count=1,
                first_seen_ns=now_ns,
                last_seen_ns=now_ns,
                direction="OUTBOUND",
            )
        ]

        context = ProbeContext(
            agent_name="flow_agent_v2",
            device_id="test-host",
            now_ns=now_ns,
            shared_data={"flows": flows},
        )

        events = probe.scan(context)
        assert len(events) == 0

    def test_c2_beacon_avg_bytes_check(self):
        """C2BeaconFlowProbe uses avg bytes per flow (needs nettop data)."""
        probe = C2BeaconFlowProbe()
        now_ns = int(time.time() * 1e9)

        # 6 flows with regular 60s intervals, small bytes (beacon-like)
        flows = [
            FlowEvent(
                src_ip="10.0.0.5",
                dst_ip="198.51.100.1",
                src_port=54321,
                dst_port=443,
                protocol="TCP",
                bytes_tx=256,  # Small — nettop populated
                bytes_rx=128,
                packet_count=1,
                first_seen_ns=now_ns + i * 60_000_000_000,  # 60s intervals
                last_seen_ns=now_ns + i * 60_000_000_000,
                direction="OUTBOUND",
                pid=9999,
                process_name="beacon",
            )
            for i in range(6)
        ]

        context = ProbeContext(
            agent_name="flow_agent_v2",
            device_id="test-host",
            now_ns=now_ns,
            shared_data={"flows": flows},
        )

        events = probe.scan(context)
        assert len(events) >= 1
        assert events[0].event_type == "flow_c2_beaconing_pattern"

    def test_tunnel_probe_uses_packet_size(self):
        """SuspiciousTunnelProbe checks avg packet size (total_bytes / packets)."""
        probe = SuspiciousTunnelProbe()
        now_ns = int(time.time() * 1e9)

        # Long-lived connection, many packets, small avg size
        flows = [
            FlowEvent(
                src_ip="10.0.0.5",
                dst_ip="198.51.100.50",
                src_port=54321,
                dst_port=4444,  # Non-standard port
                protocol="TCP",
                bytes_tx=25000,  # nettop populated
                bytes_rx=25000,
                packet_count=200,
                first_seen_ns=now_ns - 700_000_000_000,  # 700s ago
                last_seen_ns=now_ns,
                direction="OUTBOUND",
                pid=7777,
                process_name="tunnel",
            )
        ]

        context = ProbeContext(
            agent_name="flow_agent_v2",
            device_id="test-host",
            now_ns=now_ns,
            shared_data={"flows": flows},
        )

        events = probe.scan(context)
        assert len(events) >= 1
        assert events[0].event_type == "flow_suspicious_tunnel_detected"
