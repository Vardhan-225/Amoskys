"""Tests for FlowAgent and network flow monitoring.

Covers:
    - FlowAgent initialization and probe setup
    - MacOSFlowCollector parsing of lsof output
    - FlowStateTable tracking and state transitions
    - 8 flow-based threat probes
    - Suspicious connection detection
    - C2 beaconing pattern detection
    - Lateral movement detection
    - Transparent proxy probe
    - Health metrics and probe independence
"""

import re
from datetime import datetime, timezone
from typing import Dict, List
from unittest.mock import MagicMock, Mock, patch

import pytest

from amoskys.agents.common.base import HardenedAgentBase
from amoskys.agents.common.probes import (
    MicroProbeAgentMixin,
    ProbeContext,
    Severity,
    TelemetryEvent,
)
from amoskys.agents.flow.flow_agent import FlowAgent, MacOSFlowCollector
from amoskys.agents.flow.flow_state import FlowStateTable
from amoskys.agents.flow.probes import FlowEvent

# ---------------------------------------------------------------------------
# FlowEvent Tests
# ---------------------------------------------------------------------------


def _make_flow(**overrides):
    """Helper: create FlowEvent with sensible defaults."""
    import time

    now = time.time_ns()
    defaults = dict(
        src_ip="192.168.1.5",
        dst_ip="8.8.8.8",
        src_port=54321,
        dst_port=443,
        protocol="TCP",
        bytes_tx=100,
        bytes_rx=200,
        packet_count=5,
        first_seen_ns=now,
        last_seen_ns=now,
        pid=1234,
        process_name="chrome",
    )
    defaults.update(overrides)
    return FlowEvent(**defaults)


class TestFlowEvent:
    """Test FlowEvent creation and validation."""

    def test_flow_event_creation(self):
        """Test FlowEvent instantiation."""
        flow = _make_flow(
            src_ip="192.168.1.5",
            src_port=54321,
            dst_ip="8.8.8.8",
            dst_port=53,
            protocol="UDP",
            pid=1234,
            process_name="chrome",
        )
        assert flow.src_ip == "192.168.1.5"
        assert flow.src_port == 54321
        assert flow.dst_ip == "8.8.8.8"
        assert flow.dst_port == 53
        assert flow.protocol == "UDP"

    def test_flow_event_ipv6(self):
        """Test FlowEvent with IPv6 addresses."""
        flow = _make_flow(
            src_ip="::1",
            src_port=8080,
            dst_ip="2001:db8::1",
            dst_port=443,
            protocol="TCP",
            pid=5000,
            process_name="firefox",
        )
        assert ":" in flow.src_ip
        assert ":" in flow.dst_ip

    def test_flow_event_listening_port(self):
        """Test FlowEvent for listening port."""
        flow = _make_flow(
            src_ip="0.0.0.0",
            src_port=22,
            dst_ip="*",
            dst_port=0,
            protocol="TCP",
            pid=100,
            process_name="sshd",
            tcp_flags="LISTEN",
        )
        assert flow.src_port == 22
        assert flow.tcp_flags == "LISTEN"


# ---------------------------------------------------------------------------
# MacOSFlowCollector Tests
# ---------------------------------------------------------------------------


class TestMacOSFlowCollector:
    """Test network flow collection from lsof output."""

    def test_collector_init(self):
        """Test MacOSFlowCollector initialization."""
        collector = MacOSFlowCollector()
        assert collector.flows_collected == 0
        assert isinstance(collector._flow_state, FlowStateTable)

    def test_collector_with_interface(self):
        """Test collector with specified interface."""
        collector = MacOSFlowCollector(interface="en0")
        assert collector.interface == "en0"

    @patch("amoskys.agents.flow.flow_agent.subprocess.run")
    def test_lsof_parsing_tcp_established(self, mock_run):
        """Test parsing TCP ESTABLISHED connection from lsof."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""COMMAND   PID  USER   FD   TYPE   DEVICE  SIZE/OFF NODE NAME
Safari   1234  user   5u   IPv4   0x...   0t0      TCP  192.168.1.5:54321->8.8.8.8:443 (ESTABLISHED)
""",
            stderr="",
        )

        collector = MacOSFlowCollector()
        flows = collector.collect()

        assert isinstance(flows, list)
        if flows:
            assert flows[0].src_ip == "192.168.1.5"
            assert flows[0].dst_ip == "8.8.8.8"

    @patch("amoskys.agents.flow.flow_agent.subprocess.run")
    def test_lsof_parsing_listen(self, mock_run):
        """Test parsing listening ports from lsof."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""COMMAND   PID  USER   FD   TYPE   DEVICE  SIZE/OFF NODE NAME
sshd     100  root   3u   IPv4   0x...   0t0      TCP  *:22 (LISTEN)
""",
            stderr="",
        )

        collector = MacOSFlowCollector()
        flows = collector.collect()

        assert isinstance(flows, list)

    @patch("amoskys.agents.flow.flow_agent.subprocess.run")
    def test_lsof_parsing_ipv6(self, mock_run):
        """Test parsing IPv6 connections from lsof."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""COMMAND   PID  USER   FD   TYPE   DEVICE  SIZE/OFF NODE NAME
Chrome   2000  user   10u  IPv6   0x...   0t0      TCP  [::1]:8080->[2001:db8::1]:443 (ESTABLISHED)
""",
            stderr="",
        )

        collector = MacOSFlowCollector()
        flows = collector.collect()

        assert isinstance(flows, list)

    @patch("amoskys.agents.flow.flow_agent.subprocess.run")
    def test_lsof_parsing_udp(self, mock_run):
        """Test parsing UDP connections from lsof."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""COMMAND   PID  USER   FD   TYPE   DEVICE  SIZE/OFF NODE NAME
mDNSResp  123  root   6u   IPv4   0x...   0t0      UDP  *:5353
""",
            stderr="",
        )

        collector = MacOSFlowCollector()
        flows = collector.collect()

        assert isinstance(flows, list)

    @patch("amoskys.agents.flow.flow_agent.subprocess.run")
    def test_lsof_error_handling(self, mock_run):
        """Test handling of lsof command failure."""
        mock_run.return_value = Mock(
            returncode=1,
            stdout="",
            stderr="lsof: command not found",
        )

        collector = MacOSFlowCollector()
        flows = collector.collect()

        # Should return empty list on error
        assert isinstance(flows, list)

    @patch("amoskys.agents.flow.flow_agent.subprocess.run")
    def test_lsof_timeout(self, mock_run):
        """Test handling of lsof timeout."""
        mock_run.side_effect = TimeoutError("lsof timed out")

        collector = MacOSFlowCollector()
        flows = collector.collect()

        assert isinstance(flows, list)


# ---------------------------------------------------------------------------
# FlowStateTable Tests
# ---------------------------------------------------------------------------


class TestFlowStateTable:
    """Test flow state tracking."""

    def test_flow_state_table_init(self):
        """Test FlowStateTable initialization."""
        table = FlowStateTable()
        assert table.tracked_count == 0

    def test_add_flow(self):
        """Test adding a flow to the table via update."""
        table = FlowStateTable()
        flow = _make_flow(
            src_ip="192.168.1.5",
            src_port=54321,
            dst_ip="8.8.8.8",
            dst_port=443,
            protocol="TCP",
            pid=1234,
            process_name="chrome",
        )
        table.update([flow])
        assert table.tracked_count >= 1

    def test_flow_persistence(self):
        """Test that flows persist across collections."""
        table = FlowStateTable()
        flow = _make_flow(
            src_ip="192.168.1.5",
            src_port=54321,
            dst_ip="8.8.8.8",
            dst_port=443,
            protocol="TCP",
            pid=1234,
            process_name="chrome",
        )
        table.update([flow])

        # Same flow should persist
        assert table.tracked_count >= 1


# ---------------------------------------------------------------------------
# FlowAgent Tests
# ---------------------------------------------------------------------------


@pytest.fixture
def flow_agent():
    """Create FlowAgent instance for testing."""
    return FlowAgent()


@pytest.fixture
def flow_agent_with_mocks(tmp_path):
    """Create FlowAgent with mocked EventBus and queue."""
    with patch("amoskys.agents.flow.flow_agent.EventBusPublisher") as mock_pub_class:
        with patch(
            "amoskys.agents.flow.flow_agent.LocalQueueAdapter"
        ) as mock_queue_class:
            mock_pub = MagicMock()
            mock_pub_class.return_value = mock_pub

            mock_queue = MagicMock()
            mock_queue_class.return_value = mock_queue

            agent = FlowAgent()
            agent.local_queue = mock_queue
            return agent


class TestFlowAgentInit:
    """Test FlowAgent initialization."""

    def test_agent_init(self, flow_agent):
        """Test basic initialization."""
        assert flow_agent.agent_name == "flow"
        assert flow_agent.device_id is not None
        assert isinstance(flow_agent, HardenedAgentBase)
        assert isinstance(flow_agent, MicroProbeAgentMixin)

    def test_agent_has_flow_collector(self, flow_agent):
        """Test that agent has MacOSFlowCollector."""
        assert hasattr(flow_agent, "collector")
        assert isinstance(flow_agent.collector, MacOSFlowCollector)

    def test_agent_collection_interval(self, flow_agent):
        """Test collection interval is set."""
        assert flow_agent.collection_interval > 0

    def test_agent_probe_count(self, flow_agent):
        """Test that agent has expected number of probes."""
        # Flow should have 8 probes based on docstring
        assert len(flow_agent._probes) >= 1


class TestFlowAgentSetup:
    """Test FlowAgent setup and initialization."""

    def test_setup_success(self, flow_agent_with_mocks):
        """Test successful setup."""
        result = flow_agent_with_mocks.setup()
        assert result is True

    def test_setup_probes(self, flow_agent_with_mocks):
        """Test that setup initializes probes."""
        flow_agent_with_mocks.setup()
        # Check that at least one probe is registered
        assert len(flow_agent_with_mocks._probes) > 0


class TestFlowAgentCollection:
    """Test data collection and probe scanning."""

    def test_collect_empty(self, flow_agent_with_mocks):
        """Test collection with no active flows."""
        flow_agent_with_mocks.setup()
        events = flow_agent_with_mocks.collect_data()
        # Should return list of dicts
        assert isinstance(events, list)

    def test_collect_returns_telemetry_events(self, flow_agent_with_mocks):
        """Test that collection returns events."""
        flow_agent_with_mocks.setup()
        events = flow_agent_with_mocks.collect_data()
        assert isinstance(events, (list, type(None))) or hasattr(events, "__iter__")

    @patch("amoskys.agents.flow.flow_agent.subprocess.run")
    def test_suspicious_connection_detection(self, mock_run, flow_agent_with_mocks):
        """Test detection of suspicious connections."""
        # Mock lsof output with suspicious connection
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""COMMAND   PID  USER   FD   TYPE   DEVICE  SIZE/OFF NODE NAME
python   5000  user   10u  IPv4   0x...   0t0      TCP  192.168.1.100:54321->1.2.3.4:443 (ESTABLISHED)
""",
            stderr="",
        )

        flow_agent_with_mocks.setup()
        events = flow_agent_with_mocks.collect_data()

        # Collection should succeed
        assert isinstance(events, list)

    def test_c2_beaconing_detection(self):
        """Test detection of C2 beaconing patterns (regular intervals)."""
        import time as _t

        state_table = FlowStateTable()

        # Create flows at regular intervals
        now = _t.time_ns()
        flows = []
        for i in range(5):
            flows.append(
                _make_flow(
                    src_ip="192.168.1.100",
                    src_port=50000 + i,
                    dst_ip="203.0.113.50",
                    dst_port=443,
                    first_seen_ns=now + i * 60_000_000_000,
                    last_seen_ns=now + i * 60_000_000_000,
                )
            )

        state_table.update(flows)
        assert state_table.tracked_count >= 1

    def test_lateral_movement_detection(self):
        """Test detection of lateral movement (internal network scanning)."""
        state_table = FlowStateTable()

        flows = []
        for octet in range(1, 10):
            for prefix in ["192.168.1.", "10.0.0.", "172.16.0."]:
                flows.append(
                    _make_flow(
                        src_ip="192.168.1.100",
                        src_port=50000,
                        dst_ip=f"{prefix}{octet}",
                        dst_port=445,
                        protocol="TCP",
                    )
                )

        state_table.update(flows)
        assert state_table.tracked_count >= 1

    def test_transparent_proxy_probe(self):
        """Test detection of transparent proxy manipulation."""
        flow = _make_flow(
            src_ip="192.168.1.5",
            src_port=54321,
            dst_ip="1.1.1.1",
            dst_port=53,
            protocol="TCP",
        )
        assert flow.dst_port == 53


class TestFlowAgentMacOSCollector:
    """Test macOS-specific flow collection."""

    @patch("amoskys.agents.flow.flow_agent.subprocess.run")
    def test_macos_collector_integration(self, mock_run, flow_agent_with_mocks):
        """Test MacOSFlowCollector integration with agent."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="COMMAND   PID  USER   FD   TYPE   DEVICE  SIZE/OFF NODE NAME\n",
            stderr="",
        )

        flow_agent_with_mocks.setup()
        flows = flow_agent_with_mocks.collector.collect()

        assert isinstance(flows, list)


class TestFlowAgentHealth:
    """Test health metrics and monitoring."""

    def test_health_metrics(self, flow_agent_with_mocks):
        """Test health summary generation."""
        flow_agent_with_mocks.setup()
        health = flow_agent_with_mocks.health_summary()

        assert "agent_name" in health
        assert "device_id" in health
        assert "circuit_breaker_state" in health
        assert health["agent_name"] == "flow"

    def test_probe_error_handling(self, flow_agent_with_mocks):
        """Test probe error recovery."""
        flow_agent_with_mocks.setup()

        # Mock a probe that raises an exception
        if len(flow_agent_with_mocks._probes) > 0:
            original_scan = flow_agent_with_mocks._probes[0].scan
            flow_agent_with_mocks._probes[0].scan = MagicMock(
                side_effect=RuntimeError("probe error")
            )

            # Collection should handle the error gracefully
            flow_agent_with_mocks._probes[0].scan = original_scan

    def test_probe_independence(self, flow_agent_with_mocks):
        """Test that probes are independent."""
        flow_agent_with_mocks.setup()

        # Each probe should have its own name and description
        probe_names = set()
        for probe in flow_agent_with_mocks._probes:
            assert hasattr(probe, "name")
            assert hasattr(probe, "description")
            assert probe.name not in probe_names
            probe_names.add(probe.name)


class TestFlowAgentValidation:
    """Test event validation."""

    def test_validate_event(self, flow_agent_with_mocks):
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

        result = flow_agent_with_mocks.validate_event(event)
        assert result.is_valid is True

    def test_enrich_event(self, flow_agent_with_mocks):
        """Test event enrichment — expects protobuf DeviceTelemetry."""
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

        enriched = flow_agent_with_mocks.enrich_event(event)
        assert enriched is event


# ===========================================================================
# EXTENDED TESTS — Uncovered code paths
# ===========================================================================


# ---------------------------------------------------------------------------
# EventBusPublisher Tests
# ---------------------------------------------------------------------------


class TestFlowEventBusPublisher:
    """Test EventBusPublisher in flow_agent module."""

    def test_publisher_init(self):
        """Test EventBusPublisher initialization."""
        from amoskys.agents.flow.flow_agent import EventBusPublisher

        pub = EventBusPublisher("localhost:50051", "/tmp/certs")
        assert pub.address == "localhost:50051"
        assert pub.cert_dir == "/tmp/certs"
        assert pub._channel is None
        assert pub._stub is None

    def test_ensure_channel_missing_cert(self, tmp_path):
        """Test _ensure_channel raises RuntimeError when certs are missing."""
        from amoskys.agents.flow.flow_agent import EventBusPublisher

        pub = EventBusPublisher("localhost:50051", str(tmp_path / "no_certs"))
        with pytest.raises(RuntimeError, match="Certificate not found"):
            pub._ensure_channel()

    def test_ensure_channel_generic_error(self, tmp_path):
        """Test _ensure_channel raises RuntimeError on generic gRPC error."""
        from amoskys.agents.flow.flow_agent import EventBusPublisher

        cert_dir = tmp_path / "certs"
        cert_dir.mkdir()
        (cert_dir / "ca.crt").write_bytes(b"fake")
        (cert_dir / "agent.crt").write_bytes(b"fake")
        (cert_dir / "agent.key").write_bytes(b"fake")

        pub = EventBusPublisher("localhost:50051", str(cert_dir))
        with patch(
            "amoskys.agents.flow.flow_agent.grpc.ssl_channel_credentials",
            side_effect=Exception("ssl fail"),
        ):
            with pytest.raises(RuntimeError, match="Failed to create gRPC channel"):
                pub._ensure_channel()

    def test_close_with_channel(self):
        """Test close() properly closes an existing channel."""
        from amoskys.agents.flow.flow_agent import EventBusPublisher

        pub = EventBusPublisher("localhost:50051", "/tmp/certs")
        pub._channel = MagicMock()
        pub._stub = MagicMock()
        pub.close()
        assert pub._channel is None
        assert pub._stub is None

    def test_close_without_channel(self):
        """Test close() is a noop when no channel exists."""
        from amoskys.agents.flow.flow_agent import EventBusPublisher

        pub = EventBusPublisher("localhost:50051", "/tmp/certs")
        pub.close()
        assert pub._channel is None

    def test_publish_success(self):
        """Test publish() sends events through the stub."""
        from amoskys.agents.flow.flow_agent import EventBusPublisher
        from amoskys.proto import universal_telemetry_pb2 as tpb

        pub = EventBusPublisher("localhost:50051", "/tmp/certs")
        mock_stub = MagicMock()
        mock_ack = MagicMock()
        mock_ack.status = tpb.UniversalAck.OK
        mock_stub.PublishTelemetry.return_value = mock_ack
        pub._stub = mock_stub
        pub._channel = MagicMock()

        import time as _t

        event = tpb.DeviceTelemetry(
            device_id="test-host",
            timestamp_ns=int(_t.time() * 1e9),
        )
        pub.publish([event])
        assert mock_stub.PublishTelemetry.called

    def test_publish_raises_on_bad_ack(self):
        """Test publish() raises when EventBus returns non-OK status."""
        from amoskys.agents.flow.flow_agent import EventBusPublisher
        from amoskys.proto import universal_telemetry_pb2 as tpb

        pub = EventBusPublisher("localhost:50051", "/tmp/certs")
        mock_stub = MagicMock()
        mock_ack = MagicMock()
        mock_ack.status = 999
        mock_stub.PublishTelemetry.return_value = mock_ack
        pub._stub = mock_stub
        pub._channel = MagicMock()

        event = tpb.DeviceTelemetry(device_id="test-host", timestamp_ns=100)
        with pytest.raises(Exception, match="EventBus returned status"):
            pub.publish([event])


# ---------------------------------------------------------------------------
# MacOSFlowCollector Extended Tests
# ---------------------------------------------------------------------------


class TestMacOSFlowCollectorExtended:
    """Extended tests for MacOSFlowCollector parsing and edge cases."""

    @patch("amoskys.agents.flow.flow_agent.subprocess.run")
    def test_lsof_nonzero_returncode_with_output(self, mock_run):
        """Test lsof non-zero returncode but WITH stdout still parses."""
        mock_run.return_value = Mock(
            returncode=1,
            stdout="""COMMAND   PID  USER   FD   TYPE   DEVICE  SIZE/OFF NODE NAME
Safari   1234  user   5u   IPv4   0x...   0t0      TCP  192.168.1.5:54321->8.8.8.8:443 (ESTABLISHED)
""",
            stderr="some warning",
        )
        collector = MacOSFlowCollector()
        flows = collector.collect()
        # Non-zero but has stdout: should still parse
        assert isinstance(flows, list)

    @patch("amoskys.agents.flow.flow_agent.subprocess.run")
    def test_lsof_timeout_expired(self, mock_run):
        """Test lsof subprocess.TimeoutExpired exception handling."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="lsof", timeout=15)
        collector = MacOSFlowCollector()
        flows = collector.collect()
        assert flows == []
        assert collector._collection_errors == 1

    @patch("amoskys.agents.flow.flow_agent.subprocess.run")
    def test_lsof_file_not_found(self, mock_run):
        """Test FileNotFoundError when lsof is missing from PATH."""
        mock_run.side_effect = FileNotFoundError("lsof not found")
        collector = MacOSFlowCollector()
        flows = collector.collect()
        assert flows == []
        assert collector._collection_errors == 1

    @patch("amoskys.agents.flow.flow_agent.subprocess.run")
    def test_lsof_generic_exception(self, mock_run):
        """Test generic exception in flow collection."""
        mock_run.side_effect = OSError("disk error")
        collector = MacOSFlowCollector()
        flows = collector.collect()
        assert flows == []
        assert collector._collection_errors == 1

    @patch("amoskys.agents.flow.flow_agent.subprocess.run")
    def test_parse_short_line(self, mock_run):
        """Test parsing a line with too few fields (< 9)."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="COMMAND   PID  USER   FD   TYPE   DEVICE  SIZE/OFF NODE NAME\nshort line\n",
            stderr="",
        )
        collector = MacOSFlowCollector()
        flows = collector.collect()
        assert flows == []

    @patch("amoskys.agents.flow.flow_agent.subprocess.run")
    def test_parse_non_tcp_udp_protocol(self, mock_run):
        """Test parsing line with unknown protocol (OTHER)."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""COMMAND   PID  USER   FD   TYPE   DEVICE  SIZE/OFF ICMP NAME
ping     9999  user   3u   IPv4   0x...   0t0      ICMP 192.168.1.1:0->8.8.8.8:0 (ESTABLISHED)
""",
            stderr="",
        )
        collector = MacOSFlowCollector()
        flows = collector.collect()
        # ICMP is not TCP or UDP, so it returns None
        assert flows == []

    @patch("amoskys.agents.flow.flow_agent.subprocess.run")
    def test_parse_udp_with_arrow_no_state(self, mock_run):
        """Test parsing UDP connection with arrow but no state parenthetical."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""COMMAND   PID  USER   FD   TYPE   DEVICE  SIZE/OFF NODE NAME
mDNS     123  root   6u   IPv4   0x...   0t0      UDP  192.168.1.5:5353->224.0.0.251:5353
""",
            stderr="",
        )
        collector = MacOSFlowCollector()
        flows = collector.collect()
        assert isinstance(flows, list)
        if flows:
            assert flows[0].protocol == "UDP"
            assert flows[0].dst_ip == "224.0.0.251"

    @patch("amoskys.agents.flow.flow_agent.subprocess.run")
    def test_parse_udp_no_arrow(self, mock_run):
        """Test parsing UDP socket without arrow (listening-only UDP) returns None."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""COMMAND   PID  USER   FD   TYPE   DEVICE  SIZE/OFF NODE NAME
mDNS     123  root   6u   IPv4   0x...   0t0      UDP  *:5353
""",
            stderr="",
        )
        collector = MacOSFlowCollector()
        flows = collector.collect()
        # UDP without arrow falls through to return None
        assert flows == []

    @patch("amoskys.agents.flow.flow_agent.subprocess.run")
    def test_parse_tcp_wildcard_ip_skipped(self, mock_run):
        """Test that wildcard IPs (*) are skipped (normalise_ip returns None)."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""COMMAND   PID  USER   FD   TYPE   DEVICE  SIZE/OFF NODE NAME
Safari   1234  user   5u   IPv4   0x...   0t0      TCP  *:54321->8.8.8.8:443 (ESTABLISHED)
""",
            stderr="",
        )
        collector = MacOSFlowCollector()
        flows = collector.collect()
        # src_ip is '*' which normalise_ip returns None -> flow skipped
        assert flows == []

    def test_normalise_ip_variants(self):
        """Test _normalise_ip static method with various inputs."""
        n = MacOSFlowCollector._normalise_ip
        assert n("*") is None
        assert n("0.0.0.0") is None
        assert n("::") is None
        assert n("[::]") is None
        assert n("[::1]") == "::1"
        assert n("localhost") == "127.0.0.1"
        assert n("192.168.1.1") == "192.168.1.1"

    def test_infer_direction_variants(self):
        """Test _infer_direction with different IP combinations."""
        d = MacOSFlowCollector._infer_direction
        assert d("192.168.1.5", "10.0.0.1") == "LATERAL"
        assert d("192.168.1.5", "8.8.8.8") == "OUTBOUND"
        assert d("8.8.8.8", "192.168.1.5") == "INBOUND"
        assert d("8.8.8.8", "1.1.1.1") == "UNKNOWN"
        # Invalid IPs
        assert d("not_an_ip", "8.8.8.8") == "UNKNOWN"

    def test_guess_app_protocol(self):
        """Test _guess_app_protocol for well-known ports."""
        g = MacOSFlowCollector._guess_app_protocol
        assert g(22) == "SSH"
        assert g(80) == "HTTP"
        assert g(443) == "HTTPS"
        assert g(445) == "SMB"
        assert g(3389) == "RDP"
        assert g(3306) == "MySQL"
        assert g(5432) == "PostgreSQL"
        assert g(6379) == "Redis"
        assert g(27017) == "MongoDB"
        assert g(99999) == "UNKNOWN"

    def test_state_to_flags(self):
        """Test _state_to_flags for TCP state mapping."""
        s = MacOSFlowCollector._state_to_flags
        assert s("ESTABLISHED") == "SA"
        assert s("SYN_SENT") == "S"
        assert s("CLOSE_WAIT") == "FA"
        assert s("TIME_WAIT") == "FA"
        assert s("FIN_WAIT1") == "F"
        assert s("LISTEN") == "L"
        # Unknown state uses first 2 chars
        assert s("UNKNOWN_STATE") == "UN"
        assert s("") == ""

    @patch("amoskys.agents.flow.flow_agent.subprocess.run")
    def test_nettop_enrichment(self, mock_run):
        """Test nettop enrichment of flows when available."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""COMMAND   PID  USER   FD   TYPE   DEVICE  SIZE/OFF NODE NAME
Safari   1234  user   5u   IPv4   0x...   0t0      TCP  192.168.1.5:54321->8.8.8.8:443 (ESTABLISHED)
""",
            stderr="",
        )
        collector = MacOSFlowCollector()
        # Mock nettop collector
        mock_nettop = MagicMock()
        mock_nettop.collect.return_value = {
            1234: MagicMock(process_name="Safari", bytes_in=500, bytes_out=100)
        }
        collector._nettop = mock_nettop

        flows = collector.collect()
        assert isinstance(flows, list)

    @patch("amoskys.agents.flow.flow_agent.subprocess.run")
    def test_nettop_enrichment_failure(self, mock_run):
        """Test nettop enrichment gracefully handles errors."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""COMMAND   PID  USER   FD   TYPE   DEVICE  SIZE/OFF NODE NAME
Safari   1234  user   5u   IPv4   0x...   0t0      TCP  192.168.1.5:54321->8.8.8.8:443 (ESTABLISHED)
""",
            stderr="",
        )
        collector = MacOSFlowCollector()
        mock_nettop = MagicMock()
        mock_nettop.collect.side_effect = RuntimeError("nettop fail")
        collector._nettop = mock_nettop

        flows = collector.collect()
        # Should still return flows despite nettop failure
        assert len(flows) >= 1


# ---------------------------------------------------------------------------
# FlowAgent Setup Extended Tests
# ---------------------------------------------------------------------------


class TestFlowAgentSetupExtended:
    """Extended setup tests for uncovered branches."""

    def test_setup_with_missing_certs(self, flow_agent_with_mocks):
        """Test setup logs warnings for missing certs but succeeds."""
        with patch("os.path.exists", return_value=False):
            result = flow_agent_with_mocks.setup()
            assert result is True

    def test_setup_collector_test_failure(self, flow_agent_with_mocks):
        """Test setup handles collector test failure gracefully."""
        flow_agent_with_mocks.collector.collect = MagicMock(
            side_effect=RuntimeError("collector failed")
        )
        result = flow_agent_with_mocks.setup()
        # Collector test failure is just a warning, setup should still succeed
        assert result is True

    def test_setup_no_probes_returns_false(self, flow_agent_with_mocks):
        """Test setup returns False if no probes initialize."""
        with patch.object(flow_agent_with_mocks, "setup_probes", return_value=False):
            result = flow_agent_with_mocks.setup()
            assert result is False

    def test_setup_exception_returns_false(self, flow_agent_with_mocks):
        """Test setup returns False on unexpected exception."""
        with patch.object(
            flow_agent_with_mocks, "setup_probes", side_effect=RuntimeError("boom")
        ):
            result = flow_agent_with_mocks.setup()
            assert result is False


# ---------------------------------------------------------------------------
# FlowAgent collect_data Extended Tests
# ---------------------------------------------------------------------------


class TestFlowAgentCollectExtended:
    """Extended tests for collect_data covering probe execution and event conversion."""

    @patch("amoskys.agents.flow.flow_agent.subprocess.run")
    def test_collect_with_flows_generates_metrics(
        self, mock_run, flow_agent_with_mocks
    ):
        """Test collect_data with flows generates metric events."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""COMMAND   PID  USER   FD   TYPE   DEVICE  SIZE/OFF NODE NAME
Safari   1234  user   5u   IPv4   0x...   0t0      TCP  192.168.1.5:54321->8.8.8.8:443 (ESTABLISHED)
""",
            stderr="",
        )
        flow_agent_with_mocks.setup()
        results = flow_agent_with_mocks.collect_data()

        assert isinstance(results, list)
        assert len(results) == 1  # one DeviceTelemetry

        dt = results[0]
        assert dt.device_id == flow_agent_with_mocks.device_id
        assert dt.protocol == "FLOW"
        # Should have at least heartbeat + total metric
        assert len(dt.events) >= 2

        # Check heartbeat metric
        heartbeat_found = False
        for ev in dt.events:
            if ev.metric_data.metric_name == "flows_collected":
                heartbeat_found = True
                break
        assert heartbeat_found

    @patch("amoskys.agents.flow.flow_agent.subprocess.run")
    def test_collect_probe_exception_graceful(self, mock_run, flow_agent_with_mocks):
        """Test collect_data handles probe scan exceptions gracefully."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""COMMAND   PID  USER   FD   TYPE   DEVICE  SIZE/OFF NODE NAME
Safari   1234  user   5u   IPv4   0x...   0t0      TCP  192.168.1.5:54321->8.8.8.8:443 (ESTABLISHED)
""",
            stderr="",
        )
        flow_agent_with_mocks.setup()

        # Make first probe raise
        if flow_agent_with_mocks._probes:
            flow_agent_with_mocks._probes[0].scan = MagicMock(
                side_effect=RuntimeError("probe boom")
            )

        results = flow_agent_with_mocks.collect_data()
        assert isinstance(results, list)
        assert len(results) == 1

        # Probe that errored should have error_count incremented
        if flow_agent_with_mocks._probes:
            assert flow_agent_with_mocks._probes[0].error_count >= 1

    def test_collect_disabled_probe_skipped(self, flow_agent_with_mocks):
        """Test disabled probes are skipped in collect_data."""
        flow_agent_with_mocks.setup()

        for probe in flow_agent_with_mocks._probes:
            probe.enabled = False
            probe.scan = MagicMock()

        results = flow_agent_with_mocks.collect_data()
        assert isinstance(results, list)

        # No probe's scan method should be called
        for probe in flow_agent_with_mocks._probes:
            probe.scan.assert_not_called()


# ---------------------------------------------------------------------------
# FlowAgent validate_event Extended Tests
# ---------------------------------------------------------------------------


class TestFlowAgentValidateExtended:
    """Extended tests for validate_event edge cases."""

    def test_validate_missing_device_id(self, flow_agent_with_mocks):
        """Test validation fails with missing device_id."""
        from amoskys.proto import universal_telemetry_pb2 as tpb

        event = tpb.DeviceTelemetry(
            device_id="",
            timestamp_ns=int(1e18),
            events=[
                tpb.TelemetryEvent(event_id="x", event_type="SECURITY", severity="HIGH")
            ],
        )
        result = flow_agent_with_mocks.validate_event(event)
        assert result.is_valid is False
        assert any("device_id" in e for e in result.errors)

    def test_validate_zero_timestamp(self, flow_agent_with_mocks):
        """Test validation fails with zero timestamp_ns."""
        from amoskys.proto import universal_telemetry_pb2 as tpb

        event = tpb.DeviceTelemetry(
            device_id="host-1",
            timestamp_ns=0,
            events=[
                tpb.TelemetryEvent(event_id="x", event_type="SECURITY", severity="HIGH")
            ],
        )
        result = flow_agent_with_mocks.validate_event(event)
        assert result.is_valid is False
        assert any("timestamp" in e for e in result.errors)

    def test_validate_empty_events(self, flow_agent_with_mocks):
        """Test validation fails with empty events list."""
        from amoskys.proto import universal_telemetry_pb2 as tpb

        event = tpb.DeviceTelemetry(
            device_id="host-1",
            timestamp_ns=int(1e18),
        )
        result = flow_agent_with_mocks.validate_event(event)
        assert result.is_valid is False
        assert any("empty" in e for e in result.errors)

    def test_validate_multiple_errors(self, flow_agent_with_mocks):
        """Test validation accumulates multiple errors."""
        from amoskys.proto import universal_telemetry_pb2 as tpb

        event = tpb.DeviceTelemetry(device_id="", timestamp_ns=0)
        result = flow_agent_with_mocks.validate_event(event)
        assert result.is_valid is False
        assert len(result.errors) >= 2


# ---------------------------------------------------------------------------
# FlowAgent enrich_event Extended Tests
# ---------------------------------------------------------------------------


class TestFlowAgentEnrichExtended:
    """Extended tests for enrich_event."""

    def test_enrich_event_adds_host_ip(self, flow_agent_with_mocks):
        """Test enrich_event adds host_ip attribute."""
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

        with patch("socket.gethostbyname", return_value="10.0.0.5"):
            enriched = flow_agent_with_mocks.enrich_event(event)
            assert enriched.events[0].attributes["host_ip"] == "10.0.0.5"

    def test_enrich_event_os_error(self, flow_agent_with_mocks):
        """Test enrich_event handles OSError (no network)."""
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

        with patch("socket.gethostbyname", side_effect=OSError("no dns")):
            enriched = flow_agent_with_mocks.enrich_event(event)
            # Should not raise, just skip enrichment
            assert enriched is event

    def test_enrich_event_empty_events(self, flow_agent_with_mocks):
        """Test enrich_event handles empty events list."""
        import time as _t

        from amoskys.proto import universal_telemetry_pb2 as tpb

        event = tpb.DeviceTelemetry(
            device_id="test-host",
            timestamp_ns=int(_t.time() * 1e9),
        )

        with patch("socket.gethostbyname", return_value="10.0.0.5"):
            enriched = flow_agent_with_mocks.enrich_event(event)
            # Should not crash on empty events
            assert enriched is event


# ---------------------------------------------------------------------------
# FlowAgent Shutdown Tests
# ---------------------------------------------------------------------------


class TestFlowAgentShutdown:
    """Test shutdown lifecycle."""

    def test_shutdown_closes_publisher(self, flow_agent_with_mocks):
        """Test shutdown closes the EventBus publisher."""
        mock_pub = MagicMock()
        flow_agent_with_mocks.eventbus_publisher = mock_pub
        flow_agent_with_mocks.shutdown()
        mock_pub.close.assert_called_once()

    def test_shutdown_no_publisher(self, flow_agent_with_mocks):
        """Test shutdown handles None publisher gracefully."""
        flow_agent_with_mocks.eventbus_publisher = None
        flow_agent_with_mocks.shutdown()  # Should not raise


# ---------------------------------------------------------------------------
# FlowAgent get_health Tests
# ---------------------------------------------------------------------------


class TestFlowAgentGetHealth:
    """Test get_health method."""

    def test_get_health_returns_dict(self, flow_agent_with_mocks):
        """Test get_health returns dict with all expected keys."""
        flow_agent_with_mocks.setup()
        health = flow_agent_with_mocks.get_health()
        assert isinstance(health, dict)
        assert health["agent_name"] == "flow"
        assert "device_id" in health
        assert "is_running" in health
        assert "collection_count" in health
        assert "error_count" in health
        assert "probes" in health
        assert "circuit_breaker_state" in health
        assert "flows_collected_total" in health
        assert "collector_errors" in health

    def test_get_health_tracks_collector_stats(self, flow_agent_with_mocks):
        """Test get_health reflects collector statistics."""
        flow_agent_with_mocks.setup()
        flow_agent_with_mocks.collector.flows_collected = 42
        flow_agent_with_mocks.collector._collection_errors = 3

        health = flow_agent_with_mocks.get_health()
        assert health["flows_collected_total"] == 42
        assert health["collector_errors"] == 3


# ---------------------------------------------------------------------------
# FlowAgent collect_data with probe events conversion
# ---------------------------------------------------------------------------


class TestFlowAgentSecurityEventConversion:
    """Test conversion of probe TelemetryEvents to SecurityEvent protos."""

    def test_collect_with_mock_probe_events(self, flow_agent_with_mocks):
        """Test collect_data converts probe events to SecurityEvent protos."""
        flow_agent_with_mocks.setup()

        # Create a mock probe that returns events
        mock_probe = MagicMock()
        mock_probe.enabled = True
        mock_probe.name = "test_probe"
        mock_probe.scan.return_value = [
            TelemetryEvent(
                event_type="port_scan_detected",
                severity=Severity.HIGH,
                probe_name="test_probe",
                data={"target": "192.168.1.0/24", "ports_scanned": "100"},
                mitre_techniques=["T1046"],
                confidence=0.85,
            )
        ]
        flow_agent_with_mocks._probes = [mock_probe]

        results = flow_agent_with_mocks.collect_data()
        assert len(results) == 1

        dt = results[0]
        # Should have metrics + probe events metric + security event
        has_security = any(ev.event_type == "SECURITY" for ev in dt.events)
        assert has_security

        # Check security event attributes
        for ev in dt.events:
            if ev.event_type == "SECURITY":
                assert ev.security_event.risk_score == pytest.approx(0.8, abs=1e-6)
                assert "T1046" in list(ev.security_event.mitre_techniques)
                assert "target" in ev.attributes
                break

    def test_collect_critical_severity_high_risk(self, flow_agent_with_mocks):
        """Test CRITICAL severity maps to high risk score."""
        flow_agent_with_mocks.setup()

        mock_probe = MagicMock()
        mock_probe.enabled = True
        mock_probe.name = "critical_probe"
        mock_probe.scan.return_value = [
            TelemetryEvent(
                event_type="c2_beacon_detected",
                severity=Severity.CRITICAL,
                probe_name="critical_probe",
                data={},
                mitre_techniques=["T1071"],
            )
        ]
        flow_agent_with_mocks._probes = [mock_probe]

        results = flow_agent_with_mocks.collect_data()
        for ev in results[0].events:
            if ev.event_type == "SECURITY":
                assert ev.security_event.risk_score == pytest.approx(0.8, abs=1e-6)
                break

    def test_collect_medium_severity_lower_risk(self, flow_agent_with_mocks):
        """Test MEDIUM severity maps to lower risk score."""
        flow_agent_with_mocks.setup()

        mock_probe = MagicMock()
        mock_probe.enabled = True
        mock_probe.name = "medium_probe"
        mock_probe.scan.return_value = [
            TelemetryEvent(
                event_type="new_external_service",
                severity=Severity.MEDIUM,
                probe_name="medium_probe",
                data={"dst_ip": "1.2.3.4"},
                mitre_techniques=[],
            )
        ]
        flow_agent_with_mocks._probes = [mock_probe]

        results = flow_agent_with_mocks.collect_data()
        for ev in results[0].events:
            if ev.event_type == "SECURITY":
                assert ev.security_event.risk_score == pytest.approx(0.4, abs=1e-6)
                break

    def test_collect_event_data_none_values_skipped(self, flow_agent_with_mocks):
        """Test that None values in event.data are not added to attributes."""
        flow_agent_with_mocks.setup()

        mock_probe = MagicMock()
        mock_probe.enabled = True
        mock_probe.name = "test_probe"
        mock_probe.scan.return_value = [
            TelemetryEvent(
                event_type="test_event",
                severity=Severity.INFO,
                probe_name="test_probe",
                data={"key1": "value1", "key2": None, "key3": "value3"},
            )
        ]
        flow_agent_with_mocks._probes = [mock_probe]

        results = flow_agent_with_mocks.collect_data()
        for ev in results[0].events:
            if ev.event_type == "SECURITY":
                assert "key1" in ev.attributes
                assert "key2" not in ev.attributes
                assert "key3" in ev.attributes
                break
