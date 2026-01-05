"""Tests for the Micro-Probe Architecture.

Tests the MicroProbe base class, TelemetryEvent, and probe implementations
for DNS, Proc, and Peripheral agents.
"""

from datetime import datetime, timezone

import pytest

from amoskys.agents.common.probes import (
    MicroProbe,
    MicroProbeAgentMixin,
    ProbeContext,
    ProbeRegistry,
    Severity,
    TelemetryEvent,
)


class TestTelemetryEvent:
    """Test TelemetryEvent dataclass."""

    def test_create_event(self):
        """Test basic event creation."""
        event = TelemetryEvent(
            event_type="test_event",
            severity=Severity.HIGH,
            probe_name="test_probe",
            data={"key": "value"},
        )

        assert event.event_type == "test_event"
        assert event.severity == Severity.HIGH
        assert event.probe_name == "test_probe"
        assert event.data == {"key": "value"}
        assert event.confidence == 0.8  # Default
        assert isinstance(event.timestamp, datetime)

    def test_event_to_dict(self):
        """Test event serialization."""
        event = TelemetryEvent(
            event_type="test",
            severity=Severity.CRITICAL,
            probe_name="probe1",
            data={"test": True},
            mitre_techniques=["T1059"],
        )

        d = event.to_dict()
        assert d["event_type"] == "test"
        assert d["severity"] == "CRITICAL"
        assert d["probe_name"] == "probe1"
        assert d["mitre_techniques"] == ["T1059"]


class TestProbeContext:
    """Test ProbeContext dataclass."""

    def test_create_context(self):
        """Test context creation."""
        context = ProbeContext(
            device_id="host-001",
            agent_name="test_agent",
        )

        assert context.device_id == "host-001"
        assert context.agent_name == "test_agent"
        assert isinstance(context.collection_time, datetime)
        assert context.previous_state == {}


class TestMicroProbe:
    """Test MicroProbe base class."""

    def test_probe_must_implement_scan(self):
        """Test that scan() is abstract."""
        with pytest.raises(TypeError):
            # Cannot instantiate abstract class
            MicroProbe()

    def test_concrete_probe(self):
        """Test a concrete probe implementation."""

        class TestProbe(MicroProbe):
            name = "test_probe"
            description = "A test probe"
            mitre_techniques = ["T1059"]

            def scan(self, context: ProbeContext):
                return [
                    self._create_event(
                        event_type="test_detection",
                        severity=Severity.MEDIUM,
                        data={"found": True},
                    )
                ]

        probe = TestProbe()

        assert probe.name == "test_probe"
        assert probe.enabled is True
        assert "T1059" in probe.mitre_techniques

        # Test scan
        context = ProbeContext(device_id="test", agent_name="test")
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "test_detection"
        assert events[0].severity == Severity.MEDIUM

    def test_probe_health(self):
        """Test probe health reporting."""

        class HealthProbe(MicroProbe):
            name = "health_probe"

            def scan(self, context):
                return []

        probe = HealthProbe()
        probe.scan_count = 10
        probe.error_count = 2

        health = probe.get_health()
        assert health["name"] == "health_probe"
        assert health["scan_count"] == 10
        assert health["error_count"] == 2
        assert health["enabled"] is True


class TestProbeRegistry:
    """Test ProbeRegistry for discovering probes."""

    def test_register_and_list(self):
        """Test probe registration."""

        class Probe1(MicroProbe):
            name = "probe_1"

            def scan(self, context):
                return []

        class Probe2(MicroProbe):
            name = "probe_2"
            default_enabled = False

            def scan(self, context):
                return []

        registry = ProbeRegistry()
        registry.register(Probe1)
        registry.register(Probe2)

        assert "probe_1" in registry.list_probes()
        assert "probe_2" in registry.list_probes()

    def test_create_all_enabled_only(self):
        """Test creating only enabled probes."""

        class EnabledProbe(MicroProbe):
            name = "enabled"
            default_enabled = True

            def scan(self, context):
                return []

        class DisabledProbe(MicroProbe):
            name = "disabled"
            default_enabled = False

            def scan(self, context):
                return []

        registry = ProbeRegistry()
        registry.register(EnabledProbe)
        registry.register(DisabledProbe)

        probes = registry.create_all(enabled_only=True)
        assert len(probes) == 1
        assert probes[0].name == "enabled"

        all_probes = registry.create_all(enabled_only=False)
        assert len(all_probes) == 2


class TestDNSProbes:
    """Test DNS probe implementations."""

    def test_dns_probes_exist(self):
        """Verify all 9 DNS probes are available."""
        from amoskys.agents.dns.probes import DNS_PROBES

        assert len(DNS_PROBES) == 9

    def test_create_dns_probes(self):
        """Test creating DNS probe instances."""
        from amoskys.agents.dns.probes import create_dns_probes

        probes = create_dns_probes()
        assert len(probes) == 9

        # Verify names
        names = {p.name for p in probes}
        assert "raw_dns_query" in names
        assert "dga_score" in names
        assert "beaconing_pattern" in names
        assert "suspicious_tld" in names
        assert "nxdomain_burst" in names
        assert "txt_tunneling" in names
        assert "fast_flux_rebinding" in names
        assert "new_domain_for_process" in names
        assert "blocked_domain_hit" in names

    def test_dga_probe_entropy(self):
        """Test DGA probe entropy calculation."""
        from amoskys.agents.dns.probes import DGAScoreProbe

        probe = DGAScoreProbe()

        # Normal domain should have lower entropy
        normal_entropy = probe._calculate_entropy("google")
        # Random-looking domain should have higher entropy
        random_entropy = probe._calculate_entropy("xkcd7f9a2b")

        assert random_entropy > normal_entropy


class TestProcProbes:
    """Test Process probe implementations."""

    def test_proc_probes_exist(self):
        """Verify all 8 process probes are available."""
        from amoskys.agents.proc.probes import PROC_PROBES

        assert len(PROC_PROBES) == 8

    def test_create_proc_probes(self):
        """Test creating process probe instances."""
        from amoskys.agents.proc.probes import create_proc_probes

        probes = create_proc_probes()
        assert len(probes) == 8

        names = {p.name for p in probes}
        assert "process_spawn" in names
        assert "lolbin_execution" in names
        assert "process_tree_anomaly" in names
        assert "high_cpu_memory" in names


class TestPeripheralProbes:
    """Test Peripheral probe implementations."""

    def test_peripheral_probes_exist(self):
        """Verify all 7 peripheral probes are available."""
        from amoskys.agents.peripheral.probes import PERIPHERAL_PROBES

        assert len(PERIPHERAL_PROBES) == 7

    def test_create_peripheral_probes(self):
        """Test creating peripheral probe instances."""
        from amoskys.agents.peripheral.probes import create_peripheral_probes

        probes = create_peripheral_probes()
        assert len(probes) == 7

        names = {p.name for p in probes}
        assert "usb_inventory" in names
        assert "usb_connection_edge" in names
        assert "usb_storage" in names
        assert "hid_anomaly" in names


class TestMicroProbeAgentMixin:
    """Test MicroProbeAgentMixin for agent integration."""

    def test_mixin_registers_probes(self):
        """Test that mixin can register probes."""

        class DummyProbe(MicroProbe):
            name = "dummy"

            def scan(self, context):
                return []

        # Create a minimal class that uses the mixin
        class TestAgent(MicroProbeAgentMixin):
            def __init__(self):
                self._probes = []
                self._probe_state = {}
                self.device_id = "test"
                self.agent_name = "test_agent"

        agent = TestAgent()
        probe = DummyProbe()
        agent.register_probe(probe)

        assert len(agent._probes) == 1
        assert "dummy" in agent.list_probes()

    def test_probe_health_tracking(self):
        """Test probe health tracking via mixin."""

        class HealthProbe(MicroProbe):
            name = "health"

            def scan(self, context):
                return []

        class TestAgent(MicroProbeAgentMixin):
            def __init__(self):
                self._probes = []
                self._probe_state = {}
                self.device_id = "test"
                self.agent_name = "test"

        agent = TestAgent()
        agent.register_probe(HealthProbe())

        health = agent.get_probe_health()
        assert len(health) == 1
        assert health[0]["name"] == "health"
