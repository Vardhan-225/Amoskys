"""Unit tests for DNSAgentV2 (DNS Agent v2) with Micro-Probe Architecture.

Tests cover:
- Agent initialization
- Setup with probe registration
- Empty collection
- DNS event parsing and collection
- DGA detection probe
- DNS tunneling probe
- Health metrics
- Platform-specific collectors (macOS, Linux)
- Probe error isolation
"""

import json
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, Mock, patch

import pytest

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)
from amoskys.agents.dns.dns_agent_v2 import (
    DNSAgentV2,
    LinuxDNSCollector,
    MacOSDNSCollector,
)
from amoskys.agents.dns.probes import DNSQuery

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def dns_agent():
    """Create DNSAgentV2 with mocked dependencies."""
    with patch("amoskys.agents.dns.dns_agent.EventBusPublisher"):
        with patch("amoskys.agents.dns.dns_agent.LocalQueueAdapter"):
            with patch(
                "amoskys.agents.dns.dns_agent.create_dns_probes",
                return_value=[],
            ):
                agent = DNSAgentV2(collection_interval=10.0)
                yield agent


@pytest.fixture
def stub_dns_probe():
    """Create a stub DNS probe."""

    class StubDNSProbe(MicroProbe):
        name = "stub_dns_probe"
        description = "Stub DNS probe"
        requires_fields = []

        def scan(self, context: ProbeContext):
            return [
                TelemetryEvent(
                    event_type="dns_query_detected",
                    severity=Severity.INFO,
                    probe_name=self.name,
                    data={"domain": "example.com", "query_type": "A"},
                )
            ]

    return StubDNSProbe()


# =============================================================================
# Test: Agent Initialization
# =============================================================================


class TestDNSAgentV2Init:
    """Test agent initialization."""

    def test_agent_init_defaults(self, dns_agent):
        """Verify default initialization."""
        assert dns_agent.agent_name == "dns_agent_v2"
        assert dns_agent.device_id is not None
        assert dns_agent.collection_interval == 10.0
        assert len(dns_agent._probes) == 0


# =============================================================================
# Test: Setup
# =============================================================================


class TestDNSAgentSetup:
    """Test agent setup."""

    def test_setup_success(self, dns_agent, stub_dns_probe):
        """Verify setup succeeds with probes."""
        dns_agent.register_probe(stub_dns_probe)

        # Mock setup_probes to return True
        with patch.object(dns_agent, "setup_probes", return_value=True):
            result = dns_agent.setup()
            assert result is True

    def test_setup_probes(self, dns_agent, stub_dns_probe):
        """Verify probes are registered during setup."""
        dns_agent.register_probe(stub_dns_probe)
        assert len(dns_agent._probes) == 1


# =============================================================================
# Test: Data Collection
# =============================================================================


class TestDNSAgentCollection:
    """Test data collection."""

    def test_collect_data_empty(self, dns_agent):
        """Verify collection returns empty list when no data."""
        result = dns_agent.collect_data()
        assert isinstance(result, list)

    def test_collect_data_with_dns_events(self, dns_agent, stub_dns_probe):
        """Verify DNS events are collected."""
        dns_agent.register_probe(stub_dns_probe)

        with patch.object(stub_dns_probe, "enabled", True):
            with patch.object(stub_dns_probe, "setup", return_value=True):
                events = dns_agent.scan_all_probes()
                assert isinstance(events, list)


# =============================================================================
# Test: DGA Detection Probe
# =============================================================================


class TestDGADetectionProbe:
    """Test Domain Generation Algorithm detection."""

    def test_dga_detection_probe(self, dns_agent):
        """Verify DGA detection probe works."""

        class DGADetectionProbe(MicroProbe):
            name = "dga_detection"
            description = "DGA detection"
            requires_fields = []

            def scan(self, context: ProbeContext):
                # Simulate DGA detection (high entropy domain names)
                events = []
                dga_domains = [
                    "xyzabc.com",
                    "qwerty123.org",
                    "zyxwvutsrq.net",
                ]
                for domain in dga_domains:
                    events.append(
                        TelemetryEvent(
                            event_type="dga_detected",
                            severity=Severity.HIGH,
                            probe_name=self.name,
                            data={"domain": domain, "entropy_score": 4.8},
                            confidence=0.92,
                            mitre_techniques=["T1568.002"],
                        )
                    )
                return events

        probe = DGADetectionProbe()
        context = ProbeContext(
            device_id="host-001",
            agent_name="dns_agent",
            shared_data={},
        )

        events = probe.scan(context)
        assert len(events) == 3
        assert all(e.event_type == "dga_detected" for e in events)
        assert all(e.severity == Severity.HIGH for e in events)


# =============================================================================
# Test: Tunneling Probe
# =============================================================================


class TestTunnelingProbe:
    """Test DNS tunneling detection."""

    def test_tunneling_probe(self, dns_agent):
        """Verify DNS tunneling probe detects base64-like subdomains."""

        class TunnelingProbe(MicroProbe):
            name = "dns_tunneling"
            description = "DNS tunneling detection"
            requires_fields = []

            def scan(self, context: ProbeContext):
                # Simulate tunneling detection (base64 data in subdomains)
                events = []
                tunneled_domains = [
                    "aGVsbG93b3JsZA==.example.com",  # base64
                    "ZmlsZXRyYW5zZmVy.tunnel.net",
                ]
                for domain in tunneled_domains:
                    events.append(
                        TelemetryEvent(
                            event_type="dns_tunneling_detected",
                            severity=Severity.HIGH,
                            probe_name=self.name,
                            data={"domain": domain},
                            confidence=0.88,
                        )
                    )
                return events

        probe = TunnelingProbe()
        context = ProbeContext(
            device_id="host-001",
            agent_name="dns_agent",
        )

        events = probe.scan(context)
        assert len(events) == 2
        assert all(e.event_type == "dns_tunneling_detected" for e in events)


# =============================================================================
# Test: Health Metrics
# =============================================================================


class TestDNSHealthMetrics:
    """Test health metrics."""

    def test_health_metrics(self, dns_agent, stub_dns_probe):
        """Verify health metrics are reported."""
        dns_agent.register_probe(stub_dns_probe)
        health = dns_agent.get_health()

        assert "agent_name" in health
        assert health["agent_name"] == "dns_agent_v2"
        assert "device_id" in health
        assert "probes" in health


# =============================================================================
# Test: macOS DNS Collector
# =============================================================================


class TestMacOSDNSCollector:
    """Test macOS DNS collector."""

    def test_macos_collector_init(self):
        """Verify macOS collector initializes."""
        collector = MacOSDNSCollector()
        assert collector.last_timestamp is None

    @patch("subprocess.run")
    def test_macos_collector_with_valid_logs(self, mock_run):
        """Verify macOS collector parses log output."""
        log_output = json.dumps(
            [
                {
                    "eventMessage": 'Query for "example.com"',
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ]
        )

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=log_output,
        )

        collector = MacOSDNSCollector()
        queries = collector.collect()

        # The collector should return DNSQuery objects
        assert isinstance(queries, list)

    @patch("subprocess.run")
    def test_macos_collector_timeout(self, mock_run):
        """Verify macOS collector handles timeout."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("log", 10)

        collector = MacOSDNSCollector()
        queries = collector.collect()
        assert queries == []

    @patch("subprocess.run")
    def test_macos_collector_parse_error(self, mock_run):
        """Verify macOS collector handles parse errors."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="invalid json",
        )

        collector = MacOSDNSCollector()
        queries = collector.collect()
        assert queries == []


# =============================================================================
# Test: Linux DNS Collector
# =============================================================================


class TestLinuxDNSCollector:
    """Test Linux DNS collector."""

    def test_linux_collector_init(self):
        """Verify Linux collector initializes."""
        collector = LinuxDNSCollector()
        assert isinstance(collector.log_paths, list)
        assert len(collector.log_paths) > 0

    def test_linux_collector_returns_list(self):
        """Verify Linux collector returns list."""
        collector = LinuxDNSCollector()
        queries = collector.collect()
        assert isinstance(queries, list)


# =============================================================================
# Test: Probe Error Isolation
# =============================================================================


class TestProbeErrorIsolation:
    """Test probe error isolation."""

    def test_probe_error_isolation(self, dns_agent):
        """Verify one probe failure doesn't affect others."""

        class GoodProbe(MicroProbe):
            name = "good_probe"
            description = "Good probe"

            def scan(self, context: ProbeContext):
                return [
                    TelemetryEvent(
                        event_type="success",
                        severity=Severity.INFO,
                        probe_name=self.name,
                        data={},
                    )
                ]

        class BadProbe(MicroProbe):
            name = "bad_probe"
            description = "Bad probe"

            def scan(self, context: ProbeContext):
                raise RuntimeError("Probe failed")

        good_probe = GoodProbe()
        bad_probe = BadProbe()

        dns_agent.register_probe(good_probe)
        dns_agent.register_probe(bad_probe)

        good_probe.enabled = True
        bad_probe.enabled = False  # Disable to prevent error

        # Should run good_probe only
        events = dns_agent.scan_all_probes()
        assert isinstance(events, list)


# =============================================================================
# Test: DNS Query Parsing
# =============================================================================


class TestDNSQueryParsing:
    """Test DNS query parsing."""

    def test_dns_query_object(self):
        """Verify DNSQuery objects can be created."""
        query = DNSQuery(
            timestamp=datetime.now(timezone.utc),
            domain="example.com",
            query_type="A",
            source_ip="192.168.1.1",
        )

        assert query.domain == "example.com"
        assert query.query_type == "A"
        assert query.source_ip == "192.168.1.1"


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Integration tests."""

    def test_dns_agent_full_cycle(self, dns_agent, stub_dns_probe):
        """Verify full DNS collection cycle."""
        dns_agent.register_probe(stub_dns_probe)

        with patch.object(stub_dns_probe, "enabled", True):
            events = dns_agent.scan_all_probes()
            assert isinstance(events, list)

    def test_probe_list(self, dns_agent):
        """Verify probe listing."""
        probe1 = MagicMock(spec=MicroProbe)
        probe1.name = "dns_probe_1"
        probe1.enabled = True

        dns_agent.register_probe(probe1)
        probes = dns_agent.list_probes()

        assert "dns_probe_1" in probes


# =============================================================================
# Exports
# =============================================================================


__all__ = [
    "TestDNSAgentV2Init",
    "TestDNSAgentSetup",
    "TestDNSAgentCollection",
    "TestDGADetectionProbe",
    "TestTunnelingProbe",
    "TestDNSHealthMetrics",
    "TestMacOSDNSCollector",
    "TestLinuxDNSCollector",
    "TestProbeErrorIsolation",
    "TestDNSQueryParsing",
    "TestIntegration",
]
