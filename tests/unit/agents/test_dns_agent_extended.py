"""Extended unit tests for DNSAgent — targeting uncovered lines.

The existing test_dns_agent.py covers initialization, basic setup, stub probes,
and collector init.  This file targets the 103 uncovered lines:

- EventBusPublisher (_ensure_channel, publish, close)
- DNSCollector base class
- MacOSDNSCollector._parse_log_entry (query_type extraction, response_code extraction,
  domain extraction, timestamp parsing)
- MacOSDNSCollector._extract_domain
- LinuxDNSCollector.collect (systemd-resolved and log fallback)
- get_dns_collector factory
- DNSAgent.collect_data (full pipeline with probes producing security events)
- DNSAgent.validate_event (all error branches)
- DNSAgent.shutdown
- DNSAgent.get_health
- DNSAgent.setup (certificate warnings, setup_probes failure branch)
"""

from __future__ import annotations

import json
import subprocess
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)
from amoskys.agents.shared.dns.agent import (
    DNSAgent,
    DNSCollector,
    EventBusPublisher,
    LinuxDNSCollector,
    MacOSDNSCollector,
    get_dns_collector,
)
from amoskys.agents.shared.dns.probes import DNSQuery

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def dns_agent():
    """Create DNSAgent with mocked dependencies."""
    with patch("amoskys.agents.shared.dns.agent.EventBusPublisher"):
        with patch("amoskys.agents.shared.dns.agent.LocalQueueAdapter"):
            with patch(
                "amoskys.agents.shared.dns.agent.create_dns_probes",
                return_value=[],
            ):
                agent = DNSAgent(collection_interval=10.0)
                yield agent


# =============================================================================
# EventBusPublisher
# =============================================================================


class TestDNSEventBusPublisher:
    """Test the DNS-module EventBusPublisher."""

    def test_init(self):
        pub = EventBusPublisher("localhost:50051", "/tmp/certs")
        assert pub.address == "localhost:50051"
        assert pub._channel is None
        assert pub._stub is None

    def test_close_with_channel(self):
        pub = EventBusPublisher("addr", "/certs")
        pub._channel = MagicMock()
        pub._stub = MagicMock()
        pub.close()
        assert pub._channel is None
        assert pub._stub is None

    def test_close_without_channel(self):
        pub = EventBusPublisher("addr", "/certs")
        pub.close()  # no-op, should not raise

    def test_ensure_channel_cert_not_found(self):
        pub = EventBusPublisher("addr", "/nonexistent/path")
        with pytest.raises(RuntimeError, match="Certificate not found"):
            pub._ensure_channel()


# =============================================================================
# DNSCollector base class
# =============================================================================


class TestDNSCollectorBase:
    """Test DNSCollector abstract base."""

    def test_collect_raises(self):
        collector = DNSCollector()
        with pytest.raises(NotImplementedError):
            collector.collect()


# =============================================================================
# get_dns_collector factory
# =============================================================================


class TestGetDNSCollector:
    """Test platform-specific DNS collector factory."""

    @patch("amoskys.agents.shared.dns.agent.platform")
    def test_darwin(self, mock_platform):
        mock_platform.system.return_value = "Darwin"
        collector = get_dns_collector()
        assert isinstance(collector, MacOSDNSCollector)

    @patch("amoskys.agents.shared.dns.agent.platform")
    def test_linux(self, mock_platform):
        mock_platform.system.return_value = "Linux"
        collector = get_dns_collector()
        assert isinstance(collector, LinuxDNSCollector)

    @patch("amoskys.agents.shared.dns.agent.platform")
    def test_unsupported(self, mock_platform):
        mock_platform.system.return_value = "Windows"
        collector = get_dns_collector()
        # Falls back to macOS
        assert isinstance(collector, MacOSDNSCollector)


# =============================================================================
# MacOSDNSCollector._extract_domain
# =============================================================================


class TestMacOSExtractDomain:
    """Test static domain extraction."""

    def test_extract_domain_standard(self):
        domain = MacOSDNSCollector._extract_domain('Query for "example.com."')
        assert domain is not None
        # Strips trailing dot and quotes
        assert domain == "example.com"

    def test_extract_domain_for_keyword(self):
        domain = MacOSDNSCollector._extract_domain("QueryRecord for test.org type A")
        assert domain is not None
        assert domain == "test.org"

    def test_extract_domain_no_for_keyword(self):
        domain = MacOSDNSCollector._extract_domain("Query something else")
        assert domain is None

    def test_extract_domain_for_at_end(self):
        """'for' as last word with nothing after it."""
        domain = MacOSDNSCollector._extract_domain("Query for")
        assert domain is None


# =============================================================================
# MacOSDNSCollector._parse_log_entry
# =============================================================================


class TestMacOSParseLogEntry:
    """Test macOS log entry parsing with query type and response code extraction."""

    def _make_entry(self, message, timestamp=None):
        return {
            "eventMessage": message,
            "timestamp": timestamp or "2026-02-17 17:17:13.534573+0000",
        }

    def test_parse_entry_no_query_keyword(self):
        """Entries without 'Query' are skipped."""
        c = MacOSDNSCollector()
        result = c._parse_log_entry(self._make_entry("some random message"))
        assert result is None

    def test_parse_entry_no_domain(self):
        """Query message without extractable domain returns None."""
        c = MacOSDNSCollector()
        result = c._parse_log_entry(self._make_entry("Query started"))
        assert result is None

    def test_parse_entry_default_query_type(self):
        """When no type= found, default to A."""
        c = MacOSDNSCollector()
        result = c._parse_log_entry(self._make_entry("Query for example.com."))
        assert result is not None
        assert result.query_type == "A"
        assert result.domain == "example.com"

    def test_parse_entry_txt_query_type(self):
        """Extracts TXT query type."""
        c = MacOSDNSCollector()
        result = c._parse_log_entry(
            self._make_entry("Query for tunnel.evil.com. type TXT")
        )
        assert result is not None
        assert result.query_type == "TXT"

    def test_parse_entry_aaaa_query_type(self):
        """Extracts AAAA query type."""
        c = MacOSDNSCollector()
        result = c._parse_log_entry(
            self._make_entry("Query for ipv6.example.com. type AAAA")
        )
        assert result is not None
        assert result.query_type == "AAAA"

    def test_parse_entry_nxdomain_response(self):
        """Extracts NXDOMAIN response code."""
        c = MacOSDNSCollector()
        result = c._parse_log_entry(
            self._make_entry("Query for bad.domain. type A NXDOMAIN")
        )
        assert result is not None
        assert result.response_code == "NXDOMAIN"

    def test_parse_entry_servfail_response(self):
        """Extracts SERVFAIL response code."""
        c = MacOSDNSCollector()
        result = c._parse_log_entry(
            self._make_entry("Query for broken.dns. type A SERVFAIL")
        )
        assert result is not None
        assert result.response_code == "SERVFAIL"

    def test_parse_entry_noerror_default(self):
        """Default response code is NOERROR."""
        c = MacOSDNSCollector()
        result = c._parse_log_entry(self._make_entry("Query for ok.com. type A"))
        assert result is not None
        assert result.response_code == "NOERROR"

    def test_parse_entry_invalid_timestamp(self):
        """Invalid timestamp falls back to now()."""
        c = MacOSDNSCollector()
        result = c._parse_log_entry(
            self._make_entry("Query for ok.com.", timestamp="not-a-date")
        )
        assert result is not None
        # Still parses successfully, just uses current time
        assert result.domain == "ok.com"

    def test_parse_entry_no_timestamp(self):
        """No timestamp field falls back to now()."""
        c = MacOSDNSCollector()
        result = c._parse_log_entry({"eventMessage": "Query for ok.com."})
        assert result is not None


# =============================================================================
# LinuxDNSCollector
# =============================================================================


class TestLinuxDNSCollectorExtended:
    """Extended Linux DNS collector tests."""

    @patch("subprocess.run")
    def test_collect_with_resolvectl_failure(self, mock_run):
        """resolvectl failure is handled gracefully."""
        mock_run.side_effect = FileNotFoundError("resolvectl not found")
        collector = LinuxDNSCollector()
        queries = collector.collect()
        assert isinstance(queries, list)

    def test_collect_no_log_files(self):
        """No existing log files returns empty list."""
        with patch("pathlib.Path.exists", return_value=False):
            with patch("subprocess.run", side_effect=Exception("no cmd")):
                collector = LinuxDNSCollector()
                queries = collector.collect()
                assert queries == []


# =============================================================================
# DNSAgent.validate_event - all branches
# =============================================================================


class TestDNSValidateEvent:
    """Test validate_event covering all error branches."""

    def test_valid_event(self, dns_agent):
        from amoskys.proto import universal_telemetry_pb2 as tpb

        ts = int(time.time() * 1e9)
        event = tpb.DeviceTelemetry(
            device_id="host-001",
            timestamp_ns=ts,
            events=[
                tpb.TelemetryEvent(
                    event_id="e1",
                    event_type="METRIC",
                    severity="INFO",
                    event_timestamp_ns=ts,
                )
            ],
        )
        result = dns_agent.validate_event(event)
        assert result.is_valid is True

    def test_missing_device_id(self, dns_agent):
        from amoskys.proto import universal_telemetry_pb2 as tpb

        event = tpb.DeviceTelemetry(
            device_id="",
            timestamp_ns=int(time.time() * 1e9),
            events=[tpb.TelemetryEvent(event_id="e1", event_type="M", severity="INFO")],
        )
        result = dns_agent.validate_event(event)
        assert result.is_valid is False
        assert any("device_id" in e for e in result.errors)

    def test_zero_timestamp(self, dns_agent):
        from amoskys.proto import universal_telemetry_pb2 as tpb

        event = tpb.DeviceTelemetry(
            device_id="host-001",
            timestamp_ns=0,
            events=[tpb.TelemetryEvent(event_id="e1", event_type="M", severity="INFO")],
        )
        result = dns_agent.validate_event(event)
        assert result.is_valid is False
        assert any("timestamp_ns" in e for e in result.errors)

    def test_empty_events(self, dns_agent):
        from amoskys.proto import universal_telemetry_pb2 as tpb

        event = tpb.DeviceTelemetry(
            device_id="host-001",
            timestamp_ns=int(time.time() * 1e9),
            events=[],
        )
        result = dns_agent.validate_event(event)
        assert result.is_valid is False
        assert any("events" in e for e in result.errors)

    def test_multiple_errors(self, dns_agent):
        """All three errors at once."""
        from amoskys.proto import universal_telemetry_pb2 as tpb

        event = tpb.DeviceTelemetry(
            device_id="",
            timestamp_ns=0,
            events=[],
        )
        result = dns_agent.validate_event(event)
        assert result.is_valid is False
        assert len(result.errors) == 3


# =============================================================================
# DNSAgent.collect_data - full pipeline
# =============================================================================


class TestDNSCollectDataExtended:
    """Test collect_data with probes producing security events."""

    def test_collect_data_returns_device_telemetry(self, dns_agent):
        """collect_data returns list with one DeviceTelemetry."""
        result = dns_agent.collect_data()
        assert len(result) == 1
        dt = result[0]
        assert dt.device_id == dns_agent.device_id
        assert dt.protocol == "DNS"
        # Should have at least 1 metric (collection summary)
        metric_events = [e for e in dt.events if e.event_type == "METRIC"]
        assert len(metric_events) >= 1

    def test_collect_data_with_probe_security_events(self, dns_agent):
        """Probes generating events produce SECURITY telemetry events."""

        class AlertDNSProbe(MicroProbe):
            name = "alert_dns"
            description = "Produces alert"
            requires_fields = []

            def scan(self, context):
                return [
                    TelemetryEvent(
                        event_type="test_dns_alert",
                        severity=Severity.HIGH,
                        probe_name=self.name,
                        data={"domain": "evil.com", "null_attr": None},
                        mitre_techniques=["T1071.004"],
                    )
                ]

        probe = AlertDNSProbe()
        dns_agent.register_probe(probe)
        probe.enabled = True

        # Mock the DNS collector to return queries
        dns_agent.dns_collector = MagicMock()
        dns_agent.dns_collector.collect.return_value = [
            DNSQuery(
                timestamp=datetime.now(timezone.utc),
                domain="evil.com",
                query_type="A",
                source_ip="127.0.0.1",
            )
        ]

        result = dns_agent.collect_data()
        assert len(result) == 1
        dt = result[0]

        security_events = [e for e in dt.events if e.event_type == "SECURITY"]
        assert len(security_events) >= 1

        # Probe event count metric should exist
        metric_events = [e for e in dt.events if e.event_type == "METRIC"]
        probe_metric = [
            e for e in metric_events if e.metric_data.metric_name == "dns_probe_events"
        ]
        assert len(probe_metric) == 1

        # Check that null attributes are excluded
        sec_ev = security_events[0]
        assert "domain" in sec_ev.attributes
        assert "null_attr" not in sec_ev.attributes

    def test_collect_data_probe_exception_handled(self, dns_agent):
        """Probe exception does not crash collect_data."""

        class FailDNSProbe(MicroProbe):
            name = "fail_dns"
            description = "Always fails"
            requires_fields = []

            def scan(self, context):
                raise RuntimeError("dns probe error")

        probe = FailDNSProbe()
        dns_agent.register_probe(probe)
        probe.enabled = True

        result = dns_agent.collect_data()
        assert len(result) == 1
        # Agent still produced telemetry despite probe failure

    def test_collect_data_critical_severity_risk_score(self, dns_agent):
        """CRITICAL severity events get risk_score 0.8."""

        class CriticalProbe(MicroProbe):
            name = "crit_probe"
            description = "Critical event"
            requires_fields = []

            def scan(self, context):
                return [
                    TelemetryEvent(
                        event_type="critical_dns",
                        severity=Severity.CRITICAL,
                        probe_name=self.name,
                        data={},
                        mitre_techniques=["T1568"],
                    )
                ]

        probe = CriticalProbe()
        dns_agent.register_probe(probe)
        probe.enabled = True

        result = dns_agent.collect_data()
        dt = result[0]
        security_events = [e for e in dt.events if e.event_type == "SECURITY"]
        assert len(security_events) == 1
        assert security_events[0].security_event.risk_score == pytest.approx(0.8)

    def test_collect_data_low_severity_risk_score(self, dns_agent):
        """LOW severity events get risk_score 0.4."""

        class LowProbe(MicroProbe):
            name = "low_probe"
            description = "Low event"
            requires_fields = []

            def scan(self, context):
                return [
                    TelemetryEvent(
                        event_type="low_dns",
                        severity=Severity.LOW,
                        probe_name=self.name,
                        data={},
                    )
                ]

        probe = LowProbe()
        dns_agent.register_probe(probe)
        probe.enabled = True

        result = dns_agent.collect_data()
        dt = result[0]
        security_events = [e for e in dt.events if e.event_type == "SECURITY"]
        assert len(security_events) == 1
        assert security_events[0].security_event.risk_score == pytest.approx(0.4)


# =============================================================================
# DNSAgent.shutdown
# =============================================================================


class TestDNSShutdown:
    """Test shutdown method."""

    def test_shutdown_closes_publisher(self, dns_agent):
        mock_pub = MagicMock()
        dns_agent.eventbus_publisher = mock_pub
        dns_agent.shutdown()
        mock_pub.close.assert_called_once()

    def test_shutdown_no_publisher(self, dns_agent):
        dns_agent.eventbus_publisher = None
        dns_agent.shutdown()  # no-op, should not raise


# =============================================================================
# DNSAgent.setup - extended
# =============================================================================


class TestDNSSetupExtended:
    """Test setup method branches."""

    def test_setup_probes_fail_returns_false(self, dns_agent):
        """When setup_probes returns False, setup returns False."""
        with patch.object(dns_agent, "setup_probes", return_value=False):
            result = dns_agent.setup()
            assert result is False

    def test_setup_exception_returns_false(self, dns_agent):
        """Exception during setup returns False."""
        with patch("os.path.exists", side_effect=Exception("boom")):
            result = dns_agent.setup()
            assert result is False

    def test_setup_collector_test_failure(self, dns_agent):
        """Collector test failure still allows setup to continue."""
        dns_agent.dns_collector = MagicMock()
        dns_agent.dns_collector.collect.side_effect = Exception("collector fail")

        with patch.object(dns_agent, "setup_probes", return_value=True):
            result = dns_agent.setup()
            assert result is True


# =============================================================================
# DNSAgent.get_health
# =============================================================================


class TestDNSGetHealth:
    """Test get_health method returns all expected fields."""

    def test_health_fields(self, dns_agent):
        health = dns_agent.get_health()
        assert health["agent_name"] == "dns"
        assert "device_id" in health
        assert "is_running" in health
        assert "collection_count" in health
        assert "error_count" in health
        assert "last_error" in health
        assert "probes" in health
        assert "circuit_breaker_state" in health
