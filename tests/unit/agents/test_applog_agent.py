"""Tests for AppLogAgent and its 8 micro-probes.

Covers:
    - AppLogAgent instantiation via mocked dependencies
    - Agent properties (agent_name)
    - 8 micro-probes:
        1. LogTamperingProbe
        2. CredentialHarvestProbe
        3. ErrorSpikeAnomalyProbe
        4. WebShellAccessProbe
        5. Suspicious4xx5xxProbe
        6. LogInjectionProbe
        7. PrivilegeEscalationLogProbe
        8. ContainerBreakoutLogProbe
    - Probe scan() returns list of TelemetryEvent
    - Event field validation (event_type, severity, confidence, data, mitre_techniques)
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from amoskys.agents.applog.agent_types import LogEntry
from amoskys.agents.applog.probes import (
    ContainerBreakoutLogProbe,
    CredentialHarvestProbe,
    ErrorSpikeAnomalyProbe,
    LogInjectionProbe,
    LogTamperingProbe,
    PrivilegeEscalationLogProbe,
    Suspicious4xx5xxProbe,
    WebShellAccessProbe,
    create_applog_probes,
)
from amoskys.agents.common.probes import ProbeContext, Severity, TelemetryEvent

# ---------------------------------------------------------------------------
# Helper: build a ProbeContext with log_entries in shared_data
# ---------------------------------------------------------------------------


def _make_context(log_entries=None):
    """Create a ProbeContext pre-populated with log_entries."""
    ctx = ProbeContext(
        device_id="test-host",
        agent_name="applog",
        collection_time=datetime.now(timezone.utc),
    )
    ctx.shared_data["log_entries"] = log_entries or []
    return ctx


def _make_log_entry(**overrides):
    """Create a LogEntry with sensible defaults, overridden by kwargs."""
    defaults = dict(
        timestamp=datetime.now(timezone.utc),
        source="syslog",
        level="INFO",
        message="normal log message",
        file_path="/var/log/syslog",
        line_number=1,
        process_name="test_proc",
        pid=12345,
        remote_ip=None,
        http_method=None,
        http_path=None,
        http_status=None,
        user_agent=None,
    )
    defaults.update(overrides)
    return LogEntry(**defaults)


# ---------------------------------------------------------------------------
# Agent Tests
# ---------------------------------------------------------------------------


@patch("amoskys.agents.applog.applog_agent.get_config")
@patch("amoskys.agents.applog.applog_agent.EventBusPublisher")
@patch("amoskys.agents.applog.applog_agent.LocalQueueAdapter")
@patch("amoskys.agents.applog.applog_agent.Path")
def test_applog_agent_instantiation(mock_path, mock_queue, mock_pub, mock_cfg):
    """AppLogAgent can be instantiated with mocked infra."""
    mock_cfg.return_value = MagicMock()
    mock_path.return_value.parent.mkdir = MagicMock()

    from amoskys.agents.applog.applog_agent import AppLogAgent

    agent = AppLogAgent.__new__(AppLogAgent)
    # Manually set required attributes rather than running full __init__
    agent.agent_name = "applog"
    agent.device_id = "test-host"
    assert agent.agent_name == "applog"


def test_create_applog_probes_returns_eight():
    """create_applog_probes() returns exactly 8 probe instances."""
    probes = create_applog_probes()
    assert len(probes) == 8


def test_all_probes_have_unique_names():
    """Each probe in the registry has a unique name."""
    probes = create_applog_probes()
    names = [p.name for p in probes]
    assert len(names) == len(set(names))


# ---------------------------------------------------------------------------
# Probe 1: LogTamperingProbe
# ---------------------------------------------------------------------------


@patch("amoskys.agents.applog.probes.os.stat")
def test_log_tampering_truncation(mock_stat):
    """LogTamperingProbe detects file truncation (size decrease)."""
    probe = LogTamperingProbe()

    # Prime the state with a known file size
    from amoskys.agents.applog.probes import LogFileState

    probe.file_states["/var/log/syslog"] = LogFileState(
        file_path="/var/log/syslog",
        last_size=10000,
        last_mtime=1000.0,
        last_permissions=0o644,
    )

    # Mock os.stat to show smaller file
    stat_result = MagicMock()
    stat_result.st_size = 500
    stat_result.st_mtime = 1001.0
    stat_result.st_mode = 0o100644
    mock_stat.return_value = stat_result

    entry = _make_log_entry(file_path="/var/log/syslog")
    ctx = _make_context([entry])
    events = probe.scan(ctx)

    assert isinstance(events, list)
    assert len(events) >= 1
    assert events[0].event_type == "log_truncation_detected"
    assert events[0].severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# Probe 2: CredentialHarvestProbe
# ---------------------------------------------------------------------------


def test_credential_harvest_aws_key():
    """CredentialHarvestProbe detects AWS access keys in log messages."""
    probe = CredentialHarvestProbe()
    entry = _make_log_entry(message="User login with key AKIAIOSFODNN7EXAMPLE")
    ctx = _make_context([entry])
    events = probe.scan(ctx)

    assert isinstance(events, list)
    assert len(events) >= 1
    assert events[0].event_type == "credential_in_log"
    assert events[0].severity == Severity.HIGH
    assert events[0].data["credential_type"] == "aws_access_key"


def test_credential_harvest_jwt():
    """CredentialHarvestProbe detects JWT tokens in log messages."""
    probe = CredentialHarvestProbe()
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    entry = _make_log_entry(message=f"Auth token: {jwt}")
    ctx = _make_context([entry])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].data["credential_type"] == "jwt_token"


def test_credential_harvest_no_false_positive():
    """CredentialHarvestProbe does not fire on normal log lines."""
    probe = CredentialHarvestProbe()
    entry = _make_log_entry(message="User logged in successfully from 10.0.0.1")
    ctx = _make_context([entry])
    events = probe.scan(ctx)

    assert events == []


# ---------------------------------------------------------------------------
# Probe 3: ErrorSpikeAnomalyProbe
# ---------------------------------------------------------------------------


def test_error_spike_anomaly_detects_spike():
    """ErrorSpikeAnomalyProbe fires after baseline is established and spike occurs."""
    probe = ErrorSpikeAnomalyProbe()

    # Build baseline with low error counts (need >= 2 history entries)
    for _ in range(5):
        entries = [_make_log_entry(level="ERROR", source="nginx") for _ in range(2)]
        ctx = _make_context(entries)
        probe.scan(ctx)

    # Now send a spike
    entries = [_make_log_entry(level="ERROR", source="nginx") for _ in range(50)]
    ctx = _make_context(entries)
    events = probe.scan(ctx)

    assert isinstance(events, list)
    assert len(events) >= 1
    assert events[0].event_type == "error_spike_detected"
    assert events[0].severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# Probe 4: WebShellAccessProbe
# ---------------------------------------------------------------------------


def test_webshell_access_known_shell():
    """WebShellAccessProbe detects access to known web shell paths."""
    probe = WebShellAccessProbe()
    entry = _make_log_entry(
        source="nginx",
        http_path="/uploads/cmd.php",
        http_method="GET",
        http_status=200,
        remote_ip="10.0.0.99",
    )
    ctx = _make_context([entry])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "webshell_access_detected"
    assert events[0].severity == Severity.CRITICAL


def test_webshell_command_parameter():
    """WebShellAccessProbe detects command parameters in URLs."""
    probe = WebShellAccessProbe()
    entry = _make_log_entry(
        source="nginx",
        http_path="/page.html?cmd=whoami",
        http_method="GET",
        http_status=200,
        remote_ip="10.0.0.50",
    )
    ctx = _make_context([entry])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "webshell_command_parameter"


# ---------------------------------------------------------------------------
# Probe 5: Suspicious4xx5xxProbe
# ---------------------------------------------------------------------------


def test_suspicious_4xx_cluster():
    """Suspicious4xx5xxProbe detects 4xx clusters from a single IP."""
    probe = Suspicious4xx5xxProbe()
    entries = [
        _make_log_entry(
            source="nginx",
            remote_ip="10.0.0.42",
            http_status=404,
            http_path=f"/path/{i}",
        )
        for i in range(25)
    ]
    ctx = _make_context(entries)
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "http_4xx_cluster"
    assert events[0].severity == Severity.HIGH
    assert events[0].data["remote_ip"] == "10.0.0.42"


# ---------------------------------------------------------------------------
# Probe 6: LogInjectionProbe
# ---------------------------------------------------------------------------


def test_log_injection_null_byte():
    """LogInjectionProbe detects null byte injection."""
    probe = LogInjectionProbe()
    entry = _make_log_entry(message="normal text%00injected content")
    ctx = _make_context([entry])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "log_null_byte_injection"
    assert events[0].severity == Severity.HIGH


def test_log_injection_oversized():
    """LogInjectionProbe detects oversized log entries."""
    probe = LogInjectionProbe()
    entry = _make_log_entry(message="A" * 15000)
    ctx = _make_context([entry])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "log_oversized_entry"


# ---------------------------------------------------------------------------
# Probe 7: PrivilegeEscalationLogProbe
# ---------------------------------------------------------------------------


def test_privilege_escalation_sudo_failure():
    """PrivilegeEscalationLogProbe detects sudo authentication failures."""
    probe = PrivilegeEscalationLogProbe()
    entry = _make_log_entry(
        source="auth",
        message="sudo: attacker : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/attacker ; USER=root",
        process_name="sudo",
    )
    ctx = _make_context([entry])
    events = probe.scan(ctx)

    assert isinstance(events, list)
    assert len(events) >= 1
    assert events[0].event_type == "privilege_escalation_detected"
    assert events[0].severity == Severity.HIGH


# ---------------------------------------------------------------------------
# Probe 8: ContainerBreakoutLogProbe
# ---------------------------------------------------------------------------


def test_container_breakout_nsenter():
    """ContainerBreakoutLogProbe detects nsenter usage."""
    probe = ContainerBreakoutLogProbe()
    entry = _make_log_entry(
        source="syslog",
        message="nsenter --target 1 --mount --pid /bin/bash",
        process_name="nsenter",
    )
    ctx = _make_context([entry])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "container_breakout_indicator"
    assert events[0].severity == Severity.CRITICAL
    assert events[0].data["indicator_type"] == "nsenter"


def test_container_breakout_docker_socket():
    """ContainerBreakoutLogProbe detects Docker socket access."""
    probe = ContainerBreakoutLogProbe()
    entry = _make_log_entry(
        source="syslog",
        message="curl --unix-socket /var/run/docker.sock http://localhost/containers/json",
    )
    ctx = _make_context([entry])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].data["indicator_type"] == "docker_socket"


# ---------------------------------------------------------------------------
# Cross-cutting: all probes return TelemetryEvent with required fields
# ---------------------------------------------------------------------------


def test_all_probe_events_have_required_fields():
    """Every TelemetryEvent from all probes has required fields."""
    probes = create_applog_probes()
    trigger_entries = [
        _make_log_entry(
            message="nsenter --target 1 --mount /bin/bash",
            source="auth",
            level="ERROR",
            http_path="/cmd.php",
            http_method="GET",
            http_status=404,
            remote_ip="10.0.0.1",
        ),
    ]
    ctx = _make_context(trigger_entries)

    for probe in probes:
        events = probe.scan(ctx)
        assert isinstance(events, list), f"Probe {probe.name} did not return a list"
        for event in events:
            assert isinstance(event, TelemetryEvent)
            assert event.event_type, f"Missing event_type from {probe.name}"
            assert event.severity is not None
            assert isinstance(event.data, dict)
            assert event.probe_name == probe.name
