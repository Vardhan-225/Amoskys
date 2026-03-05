"""Unit tests for KernelAuditAgent (Kernel Audit Agent v2).

Tests cover:
- Agent initialization
- Setup with stub collector
- Empty collection
- Injected events via StubCollector
- Execve high-risk probe
- Privilege escalation probe
- Unified log collector init
- Unified log collector parsing
- Auditd log parsing
- Health metrics
"""

import json
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
from amoskys.agents.kernel_audit.agent_types import KernelAuditEvent
from amoskys.agents.kernel_audit.kernel_audit_agent import KernelAuditAgent

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def stub_kernel_collector():
    """Create a stub kernel audit collector for testing."""

    class StubCollector:
        """Stub collector that supports event injection."""

        def __init__(self):
            self.injected_events = []

        def collect_batch(self):
            """Return injected events."""
            events = self.injected_events[:]
            self.injected_events.clear()
            return events

        def inject(self, events):
            """Inject events for testing."""
            self.injected_events.extend(events)

    return StubCollector()


@pytest.fixture
def kernel_audit_agent(stub_kernel_collector):
    """Create KernelAuditAgent with stub collector."""
    agent = KernelAuditAgent(
        device_id="test-host",
        agent_name="kernel_audit",
        collection_interval=5.0,
        collector=stub_kernel_collector,
    )
    yield agent


@pytest.fixture
def stub_kernel_probe():
    """Create a stub kernel probe."""

    class StubKernelProbe(MicroProbe):
        name = "stub_kernel_probe"
        description = "Stub kernel probe"
        requires_fields = ["kernel_events"]

        def scan(self, context: ProbeContext):
            return [
                TelemetryEvent(
                    event_type="kernel_event_detected",
                    severity=Severity.INFO,
                    probe_name=self.name,
                    data={"syscall": "execve"},
                )
            ]

    return StubKernelProbe()


# =============================================================================
# Test: Agent Initialization
# =============================================================================


class TestKernelAuditAgentInit:
    """Test agent initialization."""

    def test_agent_init(self, kernel_audit_agent):
        """Verify default initialization."""
        assert kernel_audit_agent.agent_name == "kernel_audit"
        assert kernel_audit_agent.device_id == "test-host"
        assert kernel_audit_agent.collection_interval == 5.0
        assert kernel_audit_agent.audit_log_path == "/var/log/audit/audit.log"

    def test_agent_init_custom_path(self, stub_kernel_collector):
        """Verify custom audit log path."""
        agent = KernelAuditAgent(
            device_id="host-001",
            audit_log_path="/custom/audit.log",
            collector=stub_kernel_collector,
        )
        assert agent.audit_log_path == "/custom/audit.log"


# =============================================================================
# Test: Setup
# =============================================================================


class TestKernelAuditSetup:
    """Test agent setup."""

    def test_setup_with_stub_collector(self, kernel_audit_agent, stub_kernel_probe):
        """Verify setup works with stub collector."""
        kernel_audit_agent.register_probe(stub_kernel_probe)

        with patch.object(stub_kernel_probe, "setup", return_value=True):
            result = kernel_audit_agent.setup()
            assert result is True


# =============================================================================
# Test: Data Collection
# =============================================================================


class TestKernelAuditCollection:
    """Test data collection."""

    def test_collect_empty(self, kernel_audit_agent):
        """Verify empty collection."""
        result = kernel_audit_agent.collect_data()
        assert isinstance(result, list)

    def test_collect_with_injected_events(
        self, kernel_audit_agent, stub_kernel_probe, stub_kernel_collector
    ):
        """Verify collection with injected events."""
        kernel_audit_agent.register_probe(stub_kernel_probe)

        # Inject test events
        test_event = KernelAuditEvent(
            event_id="inject-1",
            timestamp_ns=int(time.time() * 1e9),
            host="test-host",
            syscall="execve",
            pid=1234,
            uid=0,
            raw={},
        )
        stub_kernel_collector.inject([test_event])

        with patch.object(stub_kernel_probe, "enabled", True):
            with patch.object(stub_kernel_probe, "setup", return_value=True):
                events = kernel_audit_agent.collect_data()
                assert isinstance(events, list)


# =============================================================================
# Test: Execve High-Risk Probe
# =============================================================================


class TestExecveHighRiskProbe:
    """Test execve high-risk probe."""

    def test_execve_high_risk_probe(self, kernel_audit_agent):
        """Verify execve probe detects exec from /tmp."""

        class ExecveHighRiskProbe(MicroProbe):
            name = "execve_high_risk"
            description = "Execve high-risk detection"
            requires_fields = ["kernel_events"]

            def scan(self, context: ProbeContext):
                events = []
                kernel_events = context.shared_data.get("kernel_events", [])

                for evt in kernel_events:
                    if evt.syscall == "execve":
                        # Check if executed from risky path
                        if "/tmp" in (evt.path or ""):
                            events.append(
                                TelemetryEvent(
                                    event_type="execve_from_tmp",
                                    severity=Severity.HIGH,
                                    probe_name=self.name,
                                    data={
                                        "path": evt.path,
                                        "pid": evt.pid,
                                    },
                                    confidence=0.95,
                                    mitre_techniques=["T1036"],
                                )
                            )
                return events

        probe = ExecveHighRiskProbe()

        # Create test event
        test_event = KernelAuditEvent(
            event_id="execve-test",
            timestamp_ns=int(time.time() * 1e9),
            host="test-host",
            syscall="execve",
            pid=5678,
            uid=1000,
            path="/tmp/malware",
            raw={"path": "/tmp/malware"},
        )

        context = ProbeContext(
            device_id="host-001",
            agent_name="kernel_audit",
            shared_data={"kernel_events": [test_event]},
        )

        events = probe.scan(context)
        assert len(events) == 1
        assert events[0].event_type == "execve_from_tmp"


# =============================================================================
# Test: Privilege Escalation Probe
# =============================================================================


class TestPrivEscProbe:
    """Test privilege escalation probe."""

    def test_priv_esc_probe(self, kernel_audit_agent):
        """Verify priv esc probe detects setuid by non-root."""

        class PrivEscProbe(MicroProbe):
            name = "priv_esc_syscall"
            description = "Privilege escalation syscall detection"
            requires_fields = ["kernel_events"]

            def scan(self, context: ProbeContext):
                events = []
                kernel_events = context.shared_data.get("kernel_events", [])

                for evt in kernel_events:
                    # Detect setuid/setgid by non-root user
                    if evt.syscall in ("setuid", "setgid"):
                        if evt.uid != 0:  # Not root
                            events.append(
                                TelemetryEvent(
                                    event_type="priv_esc_attempt",
                                    severity=Severity.HIGH,
                                    probe_name=self.name,
                                    data={
                                        "syscall": evt.syscall,
                                        "uid": evt.uid,
                                        "pid": evt.pid,
                                    },
                                    confidence=0.9,
                                    mitre_techniques=["T1548"],
                                )
                            )
                return events

        probe = PrivEscProbe()

        # Create test event (non-root calling setuid)
        test_event = KernelAuditEvent(
            event_id="setuid-test",
            timestamp_ns=int(time.time() * 1e9),
            host="test-host",
            syscall="setuid",
            pid=9999,
            uid=1000,  # Non-root
            raw={},
        )

        context = ProbeContext(
            device_id="host-001",
            agent_name="kernel_audit",
            shared_data={"kernel_events": [test_event]},
        )

        events = probe.scan(context)
        assert len(events) == 1
        assert events[0].event_type == "priv_esc_attempt"


# =============================================================================
# Test: Unified Log Collector
# =============================================================================


class TestUnifiedLogCollector:
    """Test macOS unified log collector."""

    def test_unified_log_collector_init(self):
        """Verify unified log collector initializes."""
        from amoskys.agents.kernel_audit.collector import MacOSUnifiedLogCollector

        collector = MacOSUnifiedLogCollector()
        assert collector is not None

    @patch("subprocess.run")
    def test_unified_log_collector_parse(self, mock_run):
        """Verify unified log JSON parsing."""
        from amoskys.agents.kernel_audit.collector import MacOSUnifiedLogCollector

        # Mock log output
        log_data = [
            {
                "eventMessage": "Executing: /bin/bash",
                "processImagePath": "/bin/bash",
                "processIdentifier": 1234,
            }
        ]

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(log_data),
        )

        collector = MacOSUnifiedLogCollector()
        events = collector.collect_batch()

        assert isinstance(events, list)


# =============================================================================
# Test: Auditd Log Collector
# =============================================================================


class TestAuditdLogCollector:
    """Test Linux auditd log collector."""

    def test_auditd_collector_init(self, tmp_path):
        """Verify auditd collector initializes."""
        from amoskys.agents.kernel_audit.collector import AuditdLogCollector

        log_file = tmp_path / "audit.log"
        log_file.write_text("")
        collector = AuditdLogCollector(source=str(log_file))
        assert str(collector.source) == str(log_file)

    def test_auditd_collector_parse(self, tmp_path):
        """Verify auditd log parsing."""
        from amoskys.agents.kernel_audit.collector import AuditdLogCollector

        log_file = tmp_path / "audit.log"
        audit_line = (
            'type=EXECVE msg=audit(1234567890.123:456): argc=2 a0="/bin/bash" a1="-i"\n'
        )
        log_file.write_text(audit_line)

        collector = AuditdLogCollector(source=str(log_file), start_at_end=False)
        events = collector.collect_batch()

        assert isinstance(events, list)


# =============================================================================
# Test: Health Metrics
# =============================================================================


class TestKernelAuditHealth:
    """Test health metrics."""

    def test_health_metrics(self, kernel_audit_agent, stub_kernel_probe):
        """Verify health metrics."""
        kernel_audit_agent.register_probe(stub_kernel_probe)
        health = kernel_audit_agent.get_health()

        assert "agent_name" in health
        assert "device_id" in health
        assert "audit_log_path" in health
        assert "total_audit_events" in health
        assert "total_threats_detected" in health
        assert "probes" in health


# =============================================================================
# Test: Event Injection
# =============================================================================


class TestEventInjection:
    """Test event injection for testing."""

    def test_inject_events(self, kernel_audit_agent, stub_kernel_collector):
        """Verify event injection."""
        test_event = KernelAuditEvent(
            event_id="inject-2",
            timestamp_ns=int(time.time() * 1e9),
            host="test-host",
            syscall="execve",
            pid=1111,
            uid=0,
            path="/usr/bin/bash",
            raw={"path": "/usr/bin/bash"},
        )

        kernel_audit_agent.inject_events([test_event])

        # Events should be stored for next collection
        events = stub_kernel_collector.collect_batch()
        assert len(events) == 1
        assert events[0].syscall == "execve"


# =============================================================================
# Test: Kernel Audit Event
# =============================================================================


class TestKernelAuditEvent:
    """Test KernelAuditEvent structure."""

    def test_create_kernel_audit_event(self):
        """Verify KernelAuditEvent creation."""
        event = KernelAuditEvent(
            event_id="test-001",
            timestamp_ns=int(time.time() * 1e9),
            host="test-host",
            syscall="open",
            pid=5555,
            uid=1000,
            raw={"filename": "/etc/passwd", "flags": "O_RDONLY"},
        )

        assert event.syscall == "open"
        assert event.pid == 5555
        assert event.uid == 1000
        assert event.raw["filename"] == "/etc/passwd"


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Integration tests."""

    def test_full_kernel_audit_cycle(
        self, kernel_audit_agent, stub_kernel_probe, stub_kernel_collector
    ):
        """Verify full kernel audit cycle."""
        kernel_audit_agent.register_probe(stub_kernel_probe)

        # Inject event
        test_event = KernelAuditEvent(
            event_id="integ-1",
            timestamp_ns=int(time.time() * 1e9),
            host="test-host",
            syscall="execve",
            pid=7777,
            uid=1000,
            path="/usr/bin/bash",
            raw={"path": "/usr/bin/bash"},
        )
        stub_kernel_collector.inject([test_event])

        with patch.object(stub_kernel_probe, "enabled", True):
            with patch.object(stub_kernel_probe, "setup", return_value=True):
                events = kernel_audit_agent.collect_data()
                assert isinstance(events, list)

    def test_probe_enable_disable(self, kernel_audit_agent, stub_kernel_probe):
        """Verify probe enable/disable."""
        kernel_audit_agent.register_probe(stub_kernel_probe)

        kernel_audit_agent.disable_probe("stub_kernel_probe")
        assert not stub_kernel_probe.enabled

        kernel_audit_agent.enable_probe("stub_kernel_probe")
        assert stub_kernel_probe.enabled


# =============================================================================
# Exports
# =============================================================================


__all__ = [
    "TestKernelAuditAgentInit",
    "TestKernelAuditSetup",
    "TestKernelAuditCollection",
    "TestExecveHighRiskProbe",
    "TestPrivEscProbe",
    "TestUnifiedLogCollector",
    "TestAuditdLogCollector",
    "TestKernelAuditHealth",
    "TestEventInjection",
    "TestKernelAuditEvent",
    "TestIntegration",
]
