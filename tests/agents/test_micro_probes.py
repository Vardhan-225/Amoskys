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
        """Verify all 8 DNS probes are available."""
        from amoskys.agents.os.macos.dns.probes import create_dns_probes

        probes = create_dns_probes()
        assert len(probes) == 8

    def test_create_dns_probes(self):
        """Test creating DNS probe instances."""
        from amoskys.agents.os.macos.dns.probes import create_dns_probes

        probes = create_dns_probes()
        assert len(probes) == 8

        names = {p.name for p in probes}
        assert "macos_dns_dga" in names
        assert "macos_dns_tunneling" in names
        assert "macos_dns_beaconing" in names
        assert "macos_dns_new_domain" in names
        assert "macos_dns_fast_flux" in names

    def test_dga_probe_exists(self):
        """Test DGA probe is instantiated."""
        from amoskys.agents.os.macos.dns.probes import create_dns_probes

        probes = create_dns_probes()
        dga = [p for p in probes if "dga" in p.name]
        assert len(dga) == 1


class TestProcProbes:
    """Test Process probe implementations."""

    def test_proc_probes_exist(self):
        """Verify all 15 process probes are available."""
        from amoskys.agents.os.macos.process.probes import create_process_probes

        probes = create_process_probes()
        assert len(probes) == 15

    def test_create_proc_probes(self):
        """Test creating process probe instances."""
        from amoskys.agents.os.macos.process.probes import create_process_probes

        probes = create_process_probes()
        assert len(probes) == 15

        names = {p.name for p in probes}
        assert "macos_process_spawn" in names
        assert "macos_lolbin" in names
        assert "macos_process_tree" in names
        assert "macos_resource_abuse" in names


@pytest.mark.skip(
    reason="ProcessInfo/_make_process_guid not in macOS Observatory probes"
)
class TestProcessGuid:
    """Test process_guid correlation key generation and propagation."""

    def test_make_process_guid_deterministic(self):
        """Same inputs always produce the same GUID."""
        from amoskys.agents.os.macos.process.probes import _make_process_guid

        g1 = _make_process_guid("host1", 1234, 1708123456.789)
        g2 = _make_process_guid("host1", 1234, 1708123456.789)
        assert g1 == g2

    def test_make_process_guid_format(self):
        """GUID is 16-char lowercase hex."""
        from amoskys.agents.os.macos.process.probes import _make_process_guid

        guid = _make_process_guid("host1", 42, 1700000000.0)
        assert len(guid) == 16
        assert all(c in "0123456789abcdef" for c in guid)

    def test_make_process_guid_different_pids(self):
        """Different PIDs with same create_time produce different GUIDs."""
        from amoskys.agents.os.macos.process.probes import _make_process_guid

        g1 = _make_process_guid("host1", 100, 1700000000.0)
        g2 = _make_process_guid("host1", 101, 1700000000.0)
        assert g1 != g2

    def test_make_process_guid_different_create_times(self):
        """Same PID recycled at different times produces different GUIDs."""
        from amoskys.agents.os.macos.process.probes import _make_process_guid

        g1 = _make_process_guid("host1", 100, 1700000000.0)
        g2 = _make_process_guid("host1", 100, 1700000001.0)
        assert g1 != g2

    def test_make_process_guid_different_hosts(self):
        """Same PID on different hosts produces different GUIDs."""
        from amoskys.agents.os.macos.process.probes import _make_process_guid

        g1 = _make_process_guid("host1", 100, 1700000000.0)
        g2 = _make_process_guid("host2", 100, 1700000000.0)
        assert g1 != g2

    def test_process_spawn_probe_emits_guid(self):
        """ProcessSpawnProbe includes process_guid in event data."""
        from unittest.mock import MagicMock, patch

        import psutil as real_psutil

        from amoskys.agents.os.macos.process.probes import ProcessSpawnProbe

        probe = ProcessSpawnProbe()
        probe.first_run = False
        probe.known_pids = set()

        mock_proc = MagicMock()
        mock_proc.info = {
            "pid": 999,
            "name": "test_bin",
            "exe": "/usr/bin/test_bin",
            "cmdline": ["/usr/bin/test_bin", "--flag"],
            "username": "user1",
            "ppid": 1,
            "create_time": 1700000000.0,
        }

        context = ProbeContext(device_id="test-host", agent_name="proc")

        with (
            patch("amoskys.agents.os.macos.process.probes.psutil") as mock_psutil,
            patch("amoskys.agents.os.macos.process.probes.PSUTIL_AVAILABLE", True),
        ):
            mock_psutil.process_iter.return_value = [mock_proc]
            mock_psutil.NoSuchProcess = real_psutil.NoSuchProcess
            mock_psutil.AccessDenied = real_psutil.AccessDenied
            mock_psutil.Process.side_effect = real_psutil.NoSuchProcess(1)

            events = probe.scan(context)

        assert len(events) >= 1
        event = events[0]
        assert "process_guid" in event.data
        assert len(event.data["process_guid"]) == 16
        assert event.correlation_id == event.data["process_guid"]

    def test_guid_consistent_across_probes(self):
        """Same process observed by different probes gets the same GUID."""
        from amoskys.agents.os.macos.process.probes import _make_process_guid

        # Simulate the same process seen by two different probes
        pid, create_time, device_id = 1234, 1700000000.5, "my-host"

        guid_from_spawn = _make_process_guid(device_id, pid, create_time)
        guid_from_lolbin = _make_process_guid(device_id, pid, create_time)
        guid_from_temp = _make_process_guid(device_id, pid, create_time)

        assert guid_from_spawn == guid_from_lolbin == guid_from_temp

    def test_processinfo_has_guid_field(self):
        """ProcessInfo dataclass includes process_guid field."""
        from amoskys.agents.os.macos.process.probes import ProcessInfo

        info = ProcessInfo(
            pid=1,
            name="test",
            exe="/bin/test",
            cmdline=[],
            username="root",
            ppid=0,
            parent_name="init",
            create_time=0.0,
            cpu_percent=0.0,
            memory_percent=0.0,
            status="running",
            process_guid="abc123",
        )
        assert info.process_guid == "abc123"


class TestPeripheralProbes:
    """Test Peripheral probe implementations."""

    def test_peripheral_probes_exist(self):
        """Verify peripheral probes are available."""
        from amoskys.agents.os.macos.peripheral.probes import create_peripheral_probes

        probes = create_peripheral_probes()
        assert len(probes) == 5

    def test_create_peripheral_probes(self):
        """Test creating peripheral probe instances."""
        from amoskys.agents.os.macos.peripheral.probes import create_peripheral_probes

        probes = create_peripheral_probes()
        assert len(probes) == 5

        names = {p.name for p in probes}
        assert "macos_usb_inventory" in names
        assert "macos_bluetooth_inventory" in names
        assert "macos_new_peripheral" in names
        assert "macos_removable_media" in names


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
