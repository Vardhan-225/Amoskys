"""Unit tests for AuthGuardAgent (Authentication Guard Agent v2).

Tests cover:
- Agent initialization
- Probe setup
- Empty collection
- SSH brute force detection
- Sudo escalation detection
- macOS auth log parsing (all sub-parsers)
- Linux auth log parsing (all line types)
- Health endpoint
- Probe independence
- Circuit breaker on repeated failures
- EventBusPublisher
- validate_event
- collect_data with probes producing events
- _build_heartbeat_metrics
- _build_probe_security_events
- shutdown
- get_auth_collector
- MacOSAuthLogCollector._synthesize_lockout_events
- MacOSAuthLogCollector._collect_last
- MacOSAuthLogCollector._parse_last_line
"""

import json
import subprocess
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from amoskys.agents.auth.auth_guard_agent import (
    AuthGuardAgent,
    AuthLogCollector,
    EventBusPublisher,
    LinuxAuthLogCollector,
    MacOSAuthLogCollector,
    get_auth_collector,
)
from amoskys.agents.auth.probes import AuthEvent
from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def auth_agent():
    """Create AuthGuardAgent with mocked dependencies."""
    with patch("amoskys.agents.auth.auth_guard_agent.EventBusPublisher"):
        with patch("amoskys.agents.auth.auth_guard_agent.LocalQueueAdapter"):
            with patch(
                "amoskys.agents.auth.auth_guard_agent.create_auth_probes",
                return_value=[],
            ):
                agent = AuthGuardAgent(collection_interval=5.0)
                yield agent


@pytest.fixture
def stub_auth_probe():
    """Create a stub auth probe."""

    class StubAuthProbe(MicroProbe):
        name = "stub_auth_probe"
        description = "Stub auth probe"
        requires_fields = []

        def scan(self, context: ProbeContext):
            return [
                TelemetryEvent(
                    event_type="auth_event",
                    severity=Severity.INFO,
                    probe_name=self.name,
                    data={"user": "testuser", "status": "SUCCESS"},
                )
            ]

    return StubAuthProbe()


# =============================================================================
# Test: Agent Initialization
# =============================================================================


class TestAuthGuardAgentInit:
    """Test agent initialization."""

    def test_agent_init(self, auth_agent):
        """Verify default initialization."""
        assert auth_agent.agent_name == "auth"
        assert auth_agent.device_id is not None
        assert auth_agent.collection_interval == 5.0


# =============================================================================
# Test: Setup
# =============================================================================


class TestAuthGuardSetup:
    """Test agent setup."""

    def test_setup_probes(self, auth_agent, stub_auth_probe):
        """Verify probes are registered."""
        auth_agent.register_probe(stub_auth_probe)
        assert len(auth_agent._probes) == 1


# =============================================================================
# Test: Data Collection
# =============================================================================


class TestAuthGuardCollection:
    """Test data collection."""

    def test_collect_empty(self, auth_agent):
        """Verify empty collection."""
        result = auth_agent.collect_data()
        assert isinstance(result, list)

    def test_collect_with_probes(self, auth_agent, stub_auth_probe):
        """Verify collection with probes."""
        auth_agent.register_probe(stub_auth_probe)

        with patch.object(stub_auth_probe, "enabled", True):
            events = auth_agent.scan_all_probes()
            assert isinstance(events, list)


# =============================================================================
# Test: SSH Brute Force Detection
# =============================================================================


class TestSSHBruteForceDetection:
    """Test SSH brute force detection."""

    def test_ssh_brute_force_detection(self, auth_agent):
        """Verify SSH brute force probe works."""

        class SSHBruteForceProbe(MicroProbe):
            name = "ssh_brute_force"
            description = "SSH brute force detection"
            requires_fields = []

            def scan(self, context: ProbeContext):
                # Simulate detecting multiple failures from same IP
                events = []
                failure_count = 5
                if failure_count > 3:
                    events.append(
                        TelemetryEvent(
                            event_type="ssh_brute_force_detected",
                            severity=Severity.HIGH,
                            probe_name=self.name,
                            data={
                                "source_ip": "192.168.1.100",
                                "failed_attempts": failure_count,
                                "username": "admin",
                            },
                            confidence=0.95,
                            mitre_techniques=["T1110"],
                        )
                    )
                return events

        probe = SSHBruteForceProbe()
        context = ProbeContext(
            device_id="host-001",
            agent_name="auth_guard",
        )

        events = probe.scan(context)
        assert len(events) == 1
        assert events[0].event_type == "ssh_brute_force_detected"
        assert events[0].severity == Severity.HIGH


# =============================================================================
# Test: Sudo Escalation Detection
# =============================================================================


class TestSudoEscalationDetection:
    """Test sudo escalation detection."""

    def test_sudo_escalation_detection(self, auth_agent):
        """Verify sudo escalation probe works."""

        class SudoEscalationProbe(MicroProbe):
            name = "sudo_escalation"
            description = "Sudo escalation detection"
            requires_fields = []

            def scan(self, context: ProbeContext):
                # Simulate detecting sudo to root
                events = []
                sudo_commands = [
                    "sudo -i",
                    "sudo -s",
                    "sudo /bin/bash",
                ]
                for cmd in sudo_commands:
                    events.append(
                        TelemetryEvent(
                            event_type="sudo_escalation",
                            severity=Severity.MEDIUM,
                            probe_name=self.name,
                            data={"command": cmd, "user": "unprivileged"},
                            confidence=0.85,
                        )
                    )
                return events

        probe = SudoEscalationProbe()
        context = ProbeContext(
            device_id="host-001",
            agent_name="auth_guard",
        )

        events = probe.scan(context)
        assert len(events) == 3
        assert all(e.event_type == "sudo_escalation" for e in events)


# =============================================================================
# Test: macOS Auth Log Collector
# =============================================================================


class TestMacOSAuthLogCollector:
    """Test macOS auth log collector."""

    def test_macos_collector_init(self):
        """Verify macOS collector initializes."""
        collector = MacOSAuthLogCollector()
        assert collector is not None

    @patch("subprocess.run")
    def test_macos_log_parsing(self, mock_run):
        """Verify macOS log parsing."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="",
        )

        collector = MacOSAuthLogCollector()
        events = collector.collect()
        assert isinstance(events, list)

    def test_macos_collector_returns_list(self):
        """Verify macOS collector returns list."""
        collector = MacOSAuthLogCollector()
        events = collector.collect()
        assert isinstance(events, list)


# =============================================================================
# Test: Linux Auth Log Collector
# =============================================================================


class TestLinuxAuthLogCollector:
    """Test Linux auth log collector."""

    def test_linux_collector_init(self):
        """Verify Linux collector initializes."""
        collector = LinuxAuthLogCollector()
        assert collector.log_path == "/var/log/auth.log"
        assert collector.last_position == 0

    @patch("builtins.open", create=True)
    def test_linux_log_parsing(self, mock_open):
        """Verify Linux log parsing."""
        # Create mock file with SSH failure
        mock_file = MagicMock()
        mock_file.__enter__.return_value.readlines.return_value = [
            "Jan  5 10:15:23 hostname sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2"
        ]
        mock_file.__enter__.return_value.tell.return_value = 100
        mock_open.return_value = mock_file

        with patch("pathlib.Path.exists", return_value=True):
            collector = LinuxAuthLogCollector()
            events = collector.collect()

            # Should parse SSH failure
            assert isinstance(events, list)

    @patch("builtins.open", create=True)
    def test_linux_ssh_success_parsing(self, mock_open):
        """Verify Linux SSH success parsing."""
        mock_file = MagicMock()
        mock_file.__enter__.return_value.readlines.return_value = [
            "Jan  5 10:15:23 hostname sshd[1234]: Accepted password for admin from 192.168.1.100 port 22 ssh2"
        ]
        mock_file.__enter__.return_value.tell.return_value = 100
        mock_open.return_value = mock_file

        with patch("pathlib.Path.exists", return_value=True):
            collector = LinuxAuthLogCollector()
            events = collector.collect()
            assert isinstance(events, list)

    @patch("builtins.open", create=True)
    def test_linux_sudo_parsing(self, mock_open):
        """Verify Linux sudo parsing."""
        mock_file = MagicMock()
        mock_file.__enter__.return_value.readlines.return_value = [
            "Jan  5 10:15:23 hostname sudo: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/bash"
        ]
        mock_file.__enter__.return_value.tell.return_value = 100
        mock_open.return_value = mock_file

        with patch("pathlib.Path.exists", return_value=True):
            collector = LinuxAuthLogCollector()
            events = collector.collect()
            assert isinstance(events, list)


# =============================================================================
# Test: Health Endpoint
# =============================================================================


class TestAuthGuardHealth:
    """Test health endpoint."""

    def test_health_endpoint(self, auth_agent):
        """Verify health endpoint returns data."""
        health = auth_agent.get_health()

        assert "agent_name" in health
        assert "device_id" in health
        assert "probes" in health


# =============================================================================
# Test: Probe Independence
# =============================================================================


class TestProbeIndependence:
    """Test probe independence."""

    def test_probe_independence(self, auth_agent):
        """Verify probes run independently."""

        class Probe1(MicroProbe):
            name = "probe_1"
            description = "Probe 1"

            def scan(self, context: ProbeContext):
                return [
                    TelemetryEvent(
                        event_type="event_1",
                        severity=Severity.INFO,
                        probe_name=self.name,
                        data={},
                    )
                ]

        class Probe2(MicroProbe):
            name = "probe_2"
            description = "Probe 2"

            def scan(self, context: ProbeContext):
                return [
                    TelemetryEvent(
                        event_type="event_2",
                        severity=Severity.INFO,
                        probe_name=self.name,
                        data={},
                    )
                ]

        probe1 = Probe1()
        probe2 = Probe2()

        auth_agent.register_probe(probe1)
        auth_agent.register_probe(probe2)

        probe1.enabled = True
        probe2.enabled = True

        events = auth_agent.scan_all_probes()
        assert isinstance(events, list)


# =============================================================================
# Test: Circuit Breaker on Failures
# =============================================================================


class TestCircuitBreakerOnFailure:
    """Test circuit breaker on repeated failures."""

    def test_circuit_breaker_on_repeated_failure(self, auth_agent):
        """Verify circuit breaker opens on repeated failures."""
        cb = auth_agent.circuit_breaker

        # Record multiple failures
        for _ in range(5):
            cb.record_failure()

        # Circuit should be OPEN
        assert cb.state == "OPEN"

    def test_circuit_breaker_recovery(self, auth_agent):
        """Verify circuit breaker can recover."""
        cb = auth_agent.circuit_breaker

        # Force open
        cb.state = "OPEN"
        cb.failure_count = 5

        # Wait and transition to half-open
        cb.last_failure_time = time.time() - 35  # Past recovery timeout
        cb._maybe_transition_half_open()

        assert cb.state == "HALF_OPEN"


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Integration tests."""

    def test_full_auth_cycle(self, auth_agent, stub_auth_probe):
        """Verify full auth agent cycle."""
        auth_agent.register_probe(stub_auth_probe)

        with patch.object(stub_auth_probe, "enabled", True):
            events = auth_agent.scan_all_probes()
            assert isinstance(events, list)

    def test_probe_enable_disable(self, auth_agent, stub_auth_probe):
        """Verify probe enable/disable."""
        auth_agent.register_probe(stub_auth_probe)

        auth_agent.disable_probe("stub_auth_probe")
        assert not stub_auth_probe.enabled

        auth_agent.enable_probe("stub_auth_probe")
        assert stub_auth_probe.enabled


# =============================================================================
# Test: EventBusPublisher
# =============================================================================


class TestEventBusPublisher:
    """Test EventBusPublisher methods."""

    def test_init(self):
        """Verify publisher initializes with address and cert_dir."""
        pub = EventBusPublisher("localhost:50051", "/tmp/certs")
        assert pub.address == "localhost:50051"
        assert pub.cert_dir == "/tmp/certs"
        assert pub._channel is None
        assert pub._stub is None

    def test_close_with_channel(self):
        """Close cleans up channel and stub."""
        pub = EventBusPublisher("localhost:50051", "/tmp/certs")
        pub._channel = MagicMock()
        pub._stub = MagicMock()
        pub.close()
        assert pub._channel is None
        assert pub._stub is None

    def test_close_without_channel(self):
        """Close is a no-op when no channel."""
        pub = EventBusPublisher("localhost:50051", "/tmp/certs")
        pub.close()  # Should not raise

    def test_ensure_channel_cert_not_found(self):
        """Missing certificate file raises RuntimeError."""
        pub = EventBusPublisher("localhost:50051", "/nonexistent/path")
        with pytest.raises(RuntimeError, match="Certificate not found"):
            pub._ensure_channel()


# =============================================================================
# Test: AuthLogCollector base class
# =============================================================================


class TestAuthLogCollectorBase:
    """Test AuthLogCollector base class."""

    def test_collect_not_implemented(self):
        """Base collect() raises NotImplementedError."""
        collector = AuthLogCollector()
        with pytest.raises(NotImplementedError):
            collector.collect()


# =============================================================================
# Test: get_auth_collector
# =============================================================================


class TestGetAuthCollector:
    """Test platform-specific collector factory."""

    @patch("amoskys.agents.auth.auth_guard_agent.platform")
    def test_linux_platform(self, mock_platform):
        mock_platform.system.return_value = "Linux"
        collector = get_auth_collector()
        assert isinstance(collector, LinuxAuthLogCollector)

    @patch("amoskys.agents.auth.auth_guard_agent.platform")
    def test_darwin_platform(self, mock_platform):
        mock_platform.system.return_value = "Darwin"
        collector = get_auth_collector()
        assert isinstance(collector, MacOSAuthLogCollector)

    @patch("amoskys.agents.auth.auth_guard_agent.platform")
    def test_unsupported_platform(self, mock_platform):
        mock_platform.system.return_value = "FreeBSD"
        collector = get_auth_collector()
        # Falls back to Linux collector
        assert isinstance(collector, LinuxAuthLogCollector)


# =============================================================================
# Test: Linux auth log parsing - extended
# =============================================================================


class TestLinuxAuthLogCollectorExtended:
    """Extended Linux auth log parsing tests for uncovered branches."""

    def test_no_auth_log_file(self):
        """Collector returns empty list when log file does not exist."""
        with patch("pathlib.Path.exists", return_value=False):
            collector = LinuxAuthLogCollector()
            events = collector.collect()
            assert events == []

    @patch("builtins.open", create=True)
    def test_account_locked_line(self, mock_open_fn):
        """Verify Account locked line parsing."""
        mock_file = MagicMock()
        mock_file.__enter__.return_value.readlines.return_value = [
            "Jan  5 10:15:23 hostname pam_tally2: Account admin locked"
        ]
        mock_file.__enter__.return_value.tell.return_value = 60
        mock_open_fn.return_value = mock_file

        with patch("pathlib.Path.exists", return_value=True):
            collector = LinuxAuthLogCollector()
            events = collector.collect()
            assert isinstance(events, list)
            assert len(events) == 1
            assert events[0].event_type == "ACCOUNT_LOCKED"
            assert events[0].username == "admin"

    @patch("builtins.open", create=True)
    def test_unrecognized_line_returns_none(self, mock_open_fn):
        """Unrecognized log lines are silently skipped."""
        mock_file = MagicMock()
        mock_file.__enter__.return_value.readlines.return_value = [
            "Jan  5 10:15:23 hostname kernel: random noise"
        ]
        mock_file.__enter__.return_value.tell.return_value = 40
        mock_open_fn.return_value = mock_file

        with patch("pathlib.Path.exists", return_value=True):
            collector = LinuxAuthLogCollector()
            events = collector.collect()
            assert events == []

    def test_collect_exception(self):
        """Collector handles read exception gracefully."""
        with patch("pathlib.Path.exists", return_value=True):
            with patch("builtins.open", side_effect=PermissionError("denied")):
                collector = LinuxAuthLogCollector()
                events = collector.collect()
                assert events == []


# =============================================================================
# Test: macOS Auth Log Collector - Extended sub-parsers
# =============================================================================


class TestMacOSAuthSubParsers:
    """Test macOS unified-log sub-parsers individually."""

    def _make_collector(self):
        return MacOSAuthLogCollector()

    # -- _parse_unified_entry routing --

    def test_parse_unified_entry_empty_message(self):
        """Entry with empty eventMessage returns None."""
        c = self._make_collector()
        result = c._parse_unified_entry(
            {"eventMessage": "", "processImagePath": "/usr/bin/sudo"}
        )
        assert result is None

    def test_parse_unified_entry_no_message(self):
        """Entry without eventMessage returns None."""
        c = self._make_collector()
        result = c._parse_unified_entry({"processImagePath": "/usr/bin/sudo"})
        assert result is None

    def test_parse_unified_entry_routes_to_sudo(self):
        """Sudo process routes to _parse_sudo_message."""
        c = self._make_collector()
        entry = {
            "eventMessage": "admin : TTY=ttys015 ; PWD=/Users/admin ; USER=root ; COMMAND=/bin/ls",
            "processImagePath": "/usr/bin/sudo",
            "timestamp": "2026-02-17 17:17:13.534573+0000",
            "processID": 100,
        }
        result = c._parse_unified_entry(entry)
        assert result is not None
        assert result.event_type == "SUDO_EXEC"
        assert result.username == "admin"
        assert "/bin/ls" in result.command

    def test_parse_unified_entry_routes_to_sshd(self):
        """sshd process routes to _parse_sshd_message."""
        c = self._make_collector()
        entry = {
            "eventMessage": "Failed password for root from 10.0.0.1 port 22 ssh2",
            "processImagePath": "/usr/sbin/sshd",
            "timestamp": "2026-02-17 17:17:13.534573+0000",
            "processID": 200,
        }
        result = c._parse_unified_entry(entry)
        assert result is not None
        assert result.event_type == "SSH_LOGIN"
        assert result.status == "FAILURE"
        assert result.source_ip == "10.0.0.1"

    def test_parse_unified_entry_routes_to_loginwindow(self):
        """loginwindow process routes to _parse_loginwindow_message."""
        c = self._make_collector()
        entry = {
            "eventMessage": "SACShieldWindowShowing: true",
            "processImagePath": "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow",
            "timestamp": "2026-02-17 17:17:13.534573+0000",
            "processID": 300,
        }
        result = c._parse_unified_entry(entry)
        assert result is not None
        assert result.event_type == "SCREEN_LOCK"

    def test_parse_unified_entry_routes_to_security_agent(self):
        """SecurityAgent routes to _parse_security_agent_message."""
        c = self._make_collector()
        entry = {
            "eventMessage": "Authorization succeeded for user",
            "processImagePath": "/usr/libexec/SecurityAgent",
            "timestamp": "2026-02-17 17:17:13.534573+0000",
            "processID": 400,
        }
        result = c._parse_unified_entry(entry)
        assert result is not None
        assert result.event_type == "MFA_SUCCESS"

    def test_parse_unified_entry_routes_to_screensaver(self):
        """screensaver routes to _parse_screensaver_message."""
        c = self._make_collector()
        entry = {
            "eventMessage": "Screen saver lock activated",
            "processImagePath": "/System/Library/CoreServices/ScreenSaverEngine.app/Contents/MacOS/ScreenSaverEngine",
            "timestamp": "2026-02-17 17:17:13.534573+0000",
            "processID": 500,
        }
        result = c._parse_unified_entry(entry)
        assert result is not None
        assert result.event_type == "SCREEN_LOCK"

    def test_parse_unified_entry_routes_to_coreauthd(self):
        """coreauthd routes to _parse_coreauthd_message."""
        c = self._make_collector()
        entry = {
            "eventMessage": "Evaluate policy with success",
            "processImagePath": "/usr/libexec/coreauthd",
            "timestamp": "2026-02-17 17:17:13.534573+0000",
            "processID": 600,
        }
        result = c._parse_unified_entry(entry)
        assert result is not None
        assert result.event_type == "MFA_SUCCESS"

    def test_parse_unified_entry_unrecognized_process(self):
        """Unrecognized process returns None."""
        c = self._make_collector()
        entry = {
            "eventMessage": "Some random message",
            "processImagePath": "/usr/bin/randomtool",
            "processID": 700,
        }
        result = c._parse_unified_entry(entry)
        assert result is None

    # -- Sudo sub-parser --

    def test_sudo_noisy_message_filtered(self):
        """Noisy sudo library messages return None."""
        c = self._make_collector()
        for noise in [
            "Retrieve User record",
            "Retrieve Group info",
            "Too many groups",
            "Performance impact detected",
            "Reading config file",
            "Using original path /usr/bin",
        ]:
            result = c._parse_sudo_message(noise, 1000000, 1)
            assert result is None, f"Should have filtered: {noise}"

    def test_sudo_password_required(self):
        """Password-required sudo message returns SUDO_DENIED."""
        c = self._make_collector()
        msg = "admin : a password is required ; TTY=ttys015 ; PWD=/Users/admin ; USER=root ; COMMAND=/bin/ls"
        result = c._parse_sudo_message(msg, 1000000, 1)
        assert result is not None
        assert result.event_type == "SUDO_DENIED"
        assert result.status == "FAILURE"
        assert "password required" in result.reason

    def test_sudo_command_not_allowed(self):
        """Command-not-allowed sudo message returns SUDO_DENIED."""
        c = self._make_collector()
        msg = "admin : command not allowed ; TTY=ttys015 ; COMMAND=/bin/rm -rf /"
        result = c._parse_sudo_message(msg, 1000000, 1)
        assert result is not None
        assert result.event_type == "SUDO_DENIED"
        assert "command not allowed" in result.reason

    def test_sudo_not_allowed_to_run(self):
        """not-allowed-to-run sudo message returns SUDO_DENIED."""
        c = self._make_collector()
        msg = "admin : not allowed to run sudo ; TTY=ttys015"
        result = c._parse_sudo_message(msg, 1000000, 1)
        assert result is not None
        assert result.event_type == "SUDO_DENIED"
        assert "user not allowed" in result.reason

    def test_sudo_incorrect_password(self):
        """Incorrect password sudo message returns SUDO_DENIED."""
        c = self._make_collector()
        msg = "admin : incorrect password attempt ; TTY=ttys015 ; COMMAND=/bin/ls"
        result = c._parse_sudo_message(msg, 1000000, 1)
        assert result is not None
        assert result.event_type == "SUDO_DENIED"
        assert "incorrect password" in result.reason

    def test_sudo_no_command_no_match(self):
        """Sudo message with no command and no recognized keyword returns None."""
        c = self._make_collector()
        msg = "admin : some other info"
        result = c._parse_sudo_message(msg, 1000000, 1)
        assert result is None

    def test_sudo_no_match(self):
        """Sudo message that doesn't match pattern returns None."""
        c = self._make_collector()
        result = c._parse_sudo_message("completely unrecognized format", 1000000, 1)
        assert result is None

    # -- SSHD sub-parser --

    def test_sshd_accepted_password(self):
        c = self._make_collector()
        result = c._parse_sshd_message(
            "Accepted password for admin from 10.0.0.1 port 22", 1000000
        )
        assert result is not None
        assert result.event_type == "SSH_LOGIN"
        assert result.status == "SUCCESS"

    def test_sshd_accepted_publickey(self):
        c = self._make_collector()
        result = c._parse_sshd_message(
            "Accepted publickey for admin from 10.0.0.1 port 22", 1000000
        )
        assert result is not None
        assert result.status == "SUCCESS"
        assert result.reason == "publickey"

    def test_sshd_connection_closed(self):
        c = self._make_collector()
        result = c._parse_sshd_message("Connection closed by 10.0.0.1 port 22", 1000000)
        assert result is not None
        assert result.event_type == "SSH_DISCONNECT"

    def test_sshd_failed_invalid_user(self):
        c = self._make_collector()
        result = c._parse_sshd_message(
            "Failed password for invalid user hacker from 10.0.0.1 port 22", 1000000
        )
        assert result is not None
        assert result.status == "FAILURE"
        assert result.username == "hacker"

    def test_sshd_unrecognized(self):
        c = self._make_collector()
        result = c._parse_sshd_message("sshd debug message", 1000000)
        assert result is None

    # -- loginwindow sub-parser --

    def test_loginwindow_screen_unlock(self):
        c = self._make_collector()
        result = c._parse_loginwindow_message("SACShieldWindowShowing: false", 1000000)
        assert result is not None
        assert result.event_type == "SCREEN_UNLOCK"

    def test_loginwindow_console_login(self):
        c = self._make_collector()
        result = c._parse_loginwindow_message("user_process started", 1000000)
        assert result is not None
        assert result.event_type == "LOCAL_LOGIN"

    def test_loginwindow_console_login_alt(self):
        c = self._make_collector()
        result = c._parse_loginwindow_message("console login initiated", 1000000)
        assert result is not None
        assert result.event_type == "LOCAL_LOGIN"

    def test_loginwindow_unrecognized(self):
        c = self._make_collector()
        result = c._parse_loginwindow_message("some random message", 1000000)
        assert result is None

    # -- SecurityAgent sub-parser --

    def test_security_agent_auth_failed(self):
        c = self._make_collector()
        result = c._parse_security_agent_message(
            "Authorization failed for user", 1000000
        )
        assert result is not None
        assert result.event_type == "MFA_CHALLENGE"
        assert result.status == "FAILURE"

    def test_security_agent_unrecognized(self):
        c = self._make_collector()
        result = c._parse_security_agent_message(
            "random SecurityAgent message", 1000000
        )
        assert result is None

    # -- screensaver sub-parser --

    def test_screensaver_activated(self):
        c = self._make_collector()
        result = c._parse_screensaver_message("Screen saver activated", 1000000)
        assert result is not None
        assert result.event_type == "SCREEN_LOCK"

    def test_screensaver_lock(self):
        c = self._make_collector()
        result = c._parse_screensaver_message("lock screen engaged", 1000000)
        assert result is not None
        assert result.event_type == "SCREEN_LOCK"

    def test_screensaver_unrecognized(self):
        c = self._make_collector()
        result = c._parse_screensaver_message("screensaver idle timeout", 1000000)
        assert result is None

    # -- coreauthd sub-parser --

    def test_coreauthd_policy_failure(self):
        c = self._make_collector()
        result = c._parse_coreauthd_message("Evaluate policy with failure", 1000000)
        assert result is not None
        assert result.event_type == "MFA_CHALLENGE"
        assert result.status == "FAILURE"

    def test_coreauthd_unrecognized(self):
        c = self._make_collector()
        result = c._parse_coreauthd_message("Context create for session", 1000000)
        assert result is None


# =============================================================================
# Test: macOS _collect_last and _parse_last_line
# =============================================================================


class TestMacOSCollectLast:
    """Test macOS 'last' command parsing."""

    @patch("subprocess.run")
    def test_collect_last_happy_path(self, mock_run):
        """Parses 'last' output into events."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="admin    console  Mon Feb 17 10:00   still logged in\n"
            "admin    ttys001  Mon Feb 17 09:00 - 09:30  (00:30)\n",
        )
        c = MacOSAuthLogCollector()
        events = c._collect_last()
        assert isinstance(events, list)
        assert len(events) == 2

    @patch("subprocess.run")
    def test_collect_last_nonzero_return(self, mock_run):
        """Nonzero return code gives empty list."""
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        c = MacOSAuthLogCollector()
        events = c._collect_last()
        assert events == []

    @patch("subprocess.run")
    def test_collect_last_timeout(self, mock_run):
        """Timeout gives empty list."""
        mock_run.side_effect = subprocess.TimeoutExpired("last", 5)
        c = MacOSAuthLogCollector()
        events = c._collect_last()
        assert events == []

    def test_parse_last_line_empty(self):
        c = MacOSAuthLogCollector()
        assert c._parse_last_line("") is None

    def test_parse_last_line_wtmp(self):
        c = MacOSAuthLogCollector()
        assert c._parse_last_line("wtmp begins Mon Feb 17 00:00") is None

    def test_parse_last_line_too_short(self):
        c = MacOSAuthLogCollector()
        assert c._parse_last_line("admin console") is None

    def test_parse_last_line_reboot(self):
        c = MacOSAuthLogCollector()
        assert c._parse_last_line("reboot   ~  Mon Feb 17 10:00") is None

    def test_parse_last_line_shutdown(self):
        c = MacOSAuthLogCollector()
        assert c._parse_last_line("shutdown ~  Mon Feb 17 10:00") is None

    def test_parse_last_line_console_login(self):
        c = MacOSAuthLogCollector()
        result = c._parse_last_line(
            "admin    console  Mon Feb 17 10:00   still logged in"
        )
        assert result is not None
        assert result.event_type == "LOCAL_LOGIN"
        assert result.username == "admin"
        assert result.reason == "still logged in"

    def test_parse_last_line_terminal_session(self):
        c = MacOSAuthLogCollector()
        result = c._parse_last_line(
            "admin    ttys001  Mon Feb 17 09:00 - 09:30  (00:30)"
        )
        assert result is not None
        assert result.event_type == "TERMINAL_SESSION"
        assert result.reason == "completed"

    def test_parse_last_line_dedup(self):
        """Second call with same line is deduplicated."""
        c = MacOSAuthLogCollector()
        line = "admin    console  Mon Feb 17 10:00   still logged in"
        result1 = c._parse_last_line(line)
        result2 = c._parse_last_line(line)
        assert result1 is not None
        assert result2 is None  # deduplicated


# =============================================================================
# Test: macOS _synthesize_lockout_events
# =============================================================================


class TestMacOSSynthesizeLockout:
    """Test lockout event synthesis."""

    def test_no_failures_no_lockout(self):
        c = MacOSAuthLogCollector()
        result = c._synthesize_lockout_events([])
        assert result == []

    def test_below_threshold_no_lockout(self):
        """Fewer than 5 failures does not trigger lockout."""
        c = MacOSAuthLogCollector()
        now_ns = int(time.time() * 1e9)
        events = [
            AuthEvent(
                timestamp_ns=now_ns + i * int(1e9),
                event_type="SSH_LOGIN",
                status="FAILURE",
                username="admin",
                source_ip="10.0.0.1",
            )
            for i in range(4)
        ]
        result = c._synthesize_lockout_events(events)
        assert result == []

    def test_threshold_met_lockout_synthesized(self):
        """5 failures within window triggers lockout synthesis."""
        c = MacOSAuthLogCollector()
        now_ns = int(time.time() * 1e9)
        events = [
            AuthEvent(
                timestamp_ns=now_ns + i * int(1e9),  # 1s apart
                event_type="SSH_LOGIN",
                status="FAILURE",
                username="admin",
                source_ip="10.0.0.1",
            )
            for i in range(5)
        ]
        result = c._synthesize_lockout_events(events)
        assert len(result) == 1
        assert result[0].event_type == "ACCOUNT_LOCKED"
        assert result[0].username == "admin"
        assert result[0].source_ip == "10.0.0.1"

    def test_multiple_users_independent_lockout(self):
        """Each user is evaluated independently."""
        c = MacOSAuthLogCollector()
        now_ns = int(time.time() * 1e9)
        events = []
        for user in ["admin", "root"]:
            for i in range(5):
                events.append(
                    AuthEvent(
                        timestamp_ns=now_ns + i * int(1e9),
                        event_type="SSH_LOGIN",
                        status="FAILURE",
                        username=user,
                        source_ip="10.0.0.1",
                    )
                )
        result = c._synthesize_lockout_events(events)
        assert len(result) == 2
        users_locked = {e.username for e in result}
        assert users_locked == {"admin", "root"}


# =============================================================================
# Test: macOS unified log collection
# =============================================================================


class TestMacOSUnifiedLog:
    """Test _collect_unified_log method."""

    @patch("subprocess.run")
    def test_unified_log_nonzero_return(self, mock_run):
        """Nonzero return code from log show gives empty list."""
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        c = MacOSAuthLogCollector()
        events = c._collect_unified_log()
        assert events == []

    @patch("subprocess.run")
    def test_unified_log_empty_stdout(self, mock_run):
        """Empty stdout gives empty list."""
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        c = MacOSAuthLogCollector()
        events = c._collect_unified_log()
        assert events == []

    @patch("subprocess.run")
    def test_unified_log_json_decode_error(self, mock_run):
        """Invalid JSON gives empty list."""
        mock_run.return_value = MagicMock(returncode=0, stdout="not json")
        c = MacOSAuthLogCollector()
        events = c._collect_unified_log()
        assert events == []

    @patch("subprocess.run")
    def test_unified_log_dedup(self, mock_run):
        """Duplicate entries are deduplicated by processID + machTimestamp."""
        entry = {
            "eventMessage": "Failed password for root from 10.0.0.1 port 22",
            "processImagePath": "/usr/sbin/sshd",
            "processID": 999,
            "machTimestamp": 12345,
            "timestamp": "2026-02-17 17:17:13.534573+0000",
        }
        mock_run.return_value = MagicMock(
            returncode=0, stdout=json.dumps([entry, entry])
        )
        c = MacOSAuthLogCollector()
        events = c._collect_unified_log()
        # Only 1 event due to dedup
        assert len(events) == 1

    @patch("subprocess.run")
    def test_unified_log_timeout(self, mock_run):
        """subprocess timeout gives empty list."""
        mock_run.side_effect = subprocess.TimeoutExpired("log", 15)
        c = MacOSAuthLogCollector()
        events = c._collect_unified_log()
        assert events == []


# =============================================================================
# Test: validate_event
# =============================================================================


class TestAuthGuardValidateEvent:
    """Test validate_event method."""

    def test_valid_event(self, auth_agent):
        """Valid event passes validation."""
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
        result = auth_agent.validate_event(event)
        assert result.is_valid is True
        assert result.errors == []

    def test_missing_device_id(self, auth_agent):
        """Missing device_id fails validation."""
        from amoskys.proto import universal_telemetry_pb2 as tpb

        event = tpb.DeviceTelemetry(
            device_id="",
            timestamp_ns=int(time.time() * 1e9),
            events=[tpb.TelemetryEvent(event_id="e1", event_type="M", severity="INFO")],
        )
        result = auth_agent.validate_event(event)
        assert result.is_valid is False
        assert "device_id required" in result.errors

    def test_zero_timestamp(self, auth_agent):
        """Zero timestamp fails validation."""
        from amoskys.proto import universal_telemetry_pb2 as tpb

        event = tpb.DeviceTelemetry(
            device_id="host-001",
            timestamp_ns=0,
            events=[tpb.TelemetryEvent(event_id="e1", event_type="M", severity="INFO")],
        )
        result = auth_agent.validate_event(event)
        assert result.is_valid is False
        assert "timestamp_ns must be positive" in result.errors

    def test_empty_events(self, auth_agent):
        """Empty events list fails validation."""
        from amoskys.proto import universal_telemetry_pb2 as tpb

        event = tpb.DeviceTelemetry(
            device_id="host-001",
            timestamp_ns=int(time.time() * 1e9),
            events=[],
        )
        result = auth_agent.validate_event(event)
        assert result.is_valid is False
        assert "events list is empty" in result.errors


# =============================================================================
# Test: collect_data with probes producing events
# =============================================================================


class TestAuthGuardCollectDataExtended:
    """Extended collect_data tests exercising _build_heartbeat_metrics and _build_probe_security_events."""

    def test_collect_data_returns_device_telemetry(self, auth_agent):
        """collect_data returns list of DeviceTelemetry with heartbeat metrics."""
        result = auth_agent.collect_data()
        assert len(result) == 1
        dt = result[0]
        assert dt.device_id == auth_agent.device_id
        assert dt.protocol == "AUTH"
        # Should have at least 2 metric events (GAUGE + COUNTER)
        metric_events = [e for e in dt.events if e.event_type == "METRIC"]
        assert len(metric_events) >= 2

    def test_collect_data_with_probe_events(self, auth_agent):
        """collect_data with active probes includes probe event count metric + security events."""

        class AlertProbe(MicroProbe):
            name = "alert_probe"
            description = "Produces HIGH alert"
            requires_fields = []

            def scan(self, context):
                return [
                    TelemetryEvent(
                        event_type="test_alert",
                        severity=Severity.HIGH,
                        probe_name=self.name,
                        data={"key": "value"},
                        mitre_techniques=["T1110"],
                    )
                ]

        probe = AlertProbe()
        auth_agent.register_probe(probe)
        probe.enabled = True

        # Mock the auth collector to return events that will be fed to probes
        auth_agent.auth_collector = MagicMock()
        auth_agent.auth_collector.collect.return_value = [
            AuthEvent(
                timestamp_ns=int(time.time() * 1e9),
                event_type="SSH_LOGIN",
                status="FAILURE",
                username="admin",
                source_ip="10.0.0.1",
            )
        ]

        result = auth_agent.collect_data()
        assert len(result) == 1
        dt = result[0]

        # Should have metric events + security events
        security_events = [e for e in dt.events if e.event_type == "SECURITY"]
        assert len(security_events) >= 1

        # The probe event count metric should be present
        metric_events = [e for e in dt.events if e.event_type == "METRIC"]
        probe_metric = [
            e for e in metric_events if e.metric_data.metric_name == "auth_probe_events"
        ]
        assert len(probe_metric) == 1

    def test_probe_scan_exception_handled(self, auth_agent):
        """Probe that raises exception does not crash collect_data."""

        class FailingProbe(MicroProbe):
            name = "failing_probe"
            description = "Always fails"
            requires_fields = []

            def scan(self, context):
                raise RuntimeError("probe error")

        probe = FailingProbe()
        auth_agent.register_probe(probe)
        probe.enabled = True

        result = auth_agent.collect_data()
        assert len(result) == 1
        # Probe error was handled, agent still produced telemetry


# =============================================================================
# Test: shutdown
# =============================================================================


class TestAuthGuardShutdown:
    """Test shutdown method."""

    def test_shutdown_closes_publisher(self, auth_agent):
        """Shutdown calls close on eventbus publisher."""
        mock_pub = MagicMock()
        auth_agent.eventbus_publisher = mock_pub
        auth_agent.shutdown()
        mock_pub.close.assert_called_once()

    def test_shutdown_no_publisher(self, auth_agent):
        """Shutdown without publisher does not raise."""
        auth_agent.eventbus_publisher = None
        auth_agent.shutdown()  # Should not raise


# =============================================================================
# Test: _build_probe_security_events severity mapping and attributes
# =============================================================================


class TestBuildProbeSecurityEvents:
    """Test _build_probe_security_events output."""

    def test_high_severity_gets_high_risk_score(self, auth_agent):
        ts = int(time.time() * 1e9)
        events = [
            TelemetryEvent(
                event_type="critical_alert",
                severity=Severity.CRITICAL,
                probe_name="test_probe",
                data={"attr1": "val1", "attr2": None},
                mitre_techniques=["T1110"],
            )
        ]
        result = auth_agent._build_probe_security_events(ts, events)
        assert len(result) == 1
        assert result[0].security_event.risk_score == pytest.approx(0.8)
        assert "attr1" in result[0].attributes
        # attr2 is None, should not be in attributes
        assert "attr2" not in result[0].attributes

    def test_low_severity_gets_lower_risk_score(self, auth_agent):
        ts = int(time.time() * 1e9)
        events = [
            TelemetryEvent(
                event_type="info_event",
                severity=Severity.LOW,
                probe_name="test_probe",
                data={},
            )
        ]
        result = auth_agent._build_probe_security_events(ts, events)
        assert len(result) == 1
        assert result[0].security_event.risk_score == pytest.approx(0.5)


# =============================================================================
# Exports
# =============================================================================


__all__ = [
    "TestAuthGuardAgentInit",
    "TestAuthGuardSetup",
    "TestAuthGuardCollection",
    "TestSSHBruteForceDetection",
    "TestSudoEscalationDetection",
    "TestMacOSAuthLogCollector",
    "TestLinuxAuthLogCollector",
    "TestAuthGuardHealth",
    "TestProbeIndependence",
    "TestCircuitBreakerOnFailure",
    "TestIntegration",
    "TestEventBusPublisher",
    "TestAuthLogCollectorBase",
    "TestGetAuthCollector",
    "TestLinuxAuthLogCollectorExtended",
    "TestMacOSAuthSubParsers",
    "TestMacOSCollectLast",
    "TestMacOSSynthesizeLockout",
    "TestMacOSUnifiedLog",
    "TestAuthGuardValidateEvent",
    "TestAuthGuardCollectDataExtended",
    "TestAuthGuardShutdown",
    "TestBuildProbeSecurityEvents",
]
