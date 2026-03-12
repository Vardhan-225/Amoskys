"""
Unit tests for amoskys.intel.rules — correlation rules for incident detection.

Covers all 7 rules plus the evaluate_rules orchestrator and _get_persistence_techniques helper.
Each rule is tested for:
  - Detection (happy path)
  - Negative cases (no match -> None)
  - Edge cases (timing windows, thresholds, IP grouping, severity mapping)

All timestamps and event data are synthetic.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional

import pytest

from amoskys.intel.models import Incident, MitreTactic, Severity, TelemetryEventView
from amoskys.intel.rules import (
    ALL_RULES,
    _get_persistence_techniques,
    evaluate_rules,
    rule_data_exfiltration_spike,
    rule_multi_tactic_attack,
    rule_persistence_after_auth,
    rule_ssh_brute_force,
    rule_ssh_lateral_movement,
    rule_suspicious_process_tree,
    rule_suspicious_sudo,
)

# ============================================================================
# Helpers -- event factories
# ============================================================================

_BASE_TIME = datetime(2025, 7, 1, 10, 0, 0)
_DEVICE = "dev-rules-01"
_SEQ = 0


def _next_id() -> str:
    global _SEQ
    _SEQ += 1
    return f"r-evt-{_SEQ:06d}"


def _reset_seq():
    global _SEQ
    _SEQ = 0


def _ssh_event(
    outcome: str,
    source_ip: str = "10.0.0.99",
    user_name: str = "admin",
    offset_sec: int = 0,
) -> TelemetryEventView:
    return TelemetryEventView(
        event_id=_next_id(),
        device_id=_DEVICE,
        event_type="SECURITY",
        severity="WARN" if outcome == "FAILURE" else "INFO",
        timestamp=_BASE_TIME + timedelta(seconds=offset_sec),
        security_event={
            "event_action": "SSH",
            "event_outcome": outcome,
            "source_ip": source_ip,
            "user_name": user_name,
        },
    )


def _sudo_event(
    command: str = "",
    user_name: str = "admin",
    offset_sec: int = 0,
) -> TelemetryEventView:
    return TelemetryEventView(
        event_id=_next_id(),
        device_id=_DEVICE,
        event_type="SECURITY",
        severity="WARN",
        timestamp=_BASE_TIME + timedelta(seconds=offset_sec),
        attributes={"sudo_command": command},
        security_event={
            "event_action": "SUDO",
            "event_outcome": "SUCCESS",
            "user_name": user_name,
        },
    )


def _audit_event(
    action: str,
    object_type: str,
    file_path: str = "",
    offset_sec: int = 0,
) -> TelemetryEventView:
    return TelemetryEventView(
        event_id=_next_id(),
        device_id=_DEVICE,
        event_type="AUDIT",
        severity="MEDIUM",
        timestamp=_BASE_TIME + timedelta(seconds=offset_sec),
        attributes={"file_path": file_path},
        audit_event={
            "action_performed": action,
            "object_type": object_type,
        },
    )


def _process_event(
    exe_path: str = "/usr/bin/test",
    parent_name: str = "",
    pid: int = 1234,
    offset_sec: int = 0,
) -> TelemetryEventView:
    return TelemetryEventView(
        event_id=_next_id(),
        device_id=_DEVICE,
        event_type="PROCESS",
        severity="INFO",
        timestamp=_BASE_TIME + timedelta(seconds=offset_sec),
        process_event={
            "executable_path": exe_path,
            "parent_executable_name": parent_name,
            "pid": pid,
        },
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


@pytest.fixture(autouse=True)
def reset_event_ids():
    _reset_seq()


# ============================================================================
# rule_ssh_brute_force
# ============================================================================


class TestRuleSSHBruteForce:

    def test_fires_on_3_failures_plus_success(self):
        events = [
            _ssh_event("FAILURE", offset_sec=0),
            _ssh_event("FAILURE", offset_sec=10),
            _ssh_event("FAILURE", offset_sec=20),
            _ssh_event("SUCCESS", offset_sec=30),
        ]
        inc = rule_ssh_brute_force(events, _DEVICE)
        assert inc is not None
        assert inc.rule_name == "ssh_brute_force"
        assert inc.severity == Severity.HIGH
        assert "T1110" in inc.techniques
        assert MitreTactic.INITIAL_ACCESS.value in inc.tactics
        assert inc.start_ts is not None
        assert inc.end_ts is not None
        assert "admin" in inc.summary

    def test_no_fire_fewer_than_3_failures(self):
        events = [
            _ssh_event("FAILURE", offset_sec=0),
            _ssh_event("FAILURE", offset_sec=10),
            _ssh_event("SUCCESS", offset_sec=20),
        ]
        assert rule_ssh_brute_force(events, _DEVICE) is None

    def test_no_fire_fewer_than_4_events(self):
        events = [
            _ssh_event("FAILURE", offset_sec=0),
            _ssh_event("FAILURE", offset_sec=10),
            _ssh_event("FAILURE", offset_sec=20),
        ]
        assert rule_ssh_brute_force(events, _DEVICE) is None

    def test_no_fire_success_outside_30min(self):
        events = [
            _ssh_event("FAILURE", offset_sec=0),
            _ssh_event("FAILURE", offset_sec=10),
            _ssh_event("FAILURE", offset_sec=20),
            _ssh_event("SUCCESS", offset_sec=2000),  # > 1800s
        ]
        assert rule_ssh_brute_force(events, _DEVICE) is None

    def test_no_fire_only_failures(self):
        events = [
            _ssh_event("FAILURE", offset_sec=0),
            _ssh_event("FAILURE", offset_sec=10),
            _ssh_event("FAILURE", offset_sec=20),
            _ssh_event("FAILURE", offset_sec=30),
        ]
        assert rule_ssh_brute_force(events, _DEVICE) is None

    def test_no_fire_non_ssh_events(self):
        events = [
            TelemetryEventView(
                event_id=_next_id(),
                device_id=_DEVICE,
                event_type="SECURITY",
                severity="INFO",
                timestamp=_BASE_TIME,
                security_event={"event_action": "LOGIN", "event_outcome": "FAILURE"},
            ),
        ] * 5
        assert rule_ssh_brute_force(events, _DEVICE) is None

    def test_empty_events(self):
        assert rule_ssh_brute_force([], _DEVICE) is None

    def test_fires_per_ip(self):
        """Brute force from IP A, success from IP A: should detect."""
        events = [
            _ssh_event("FAILURE", source_ip="1.2.3.4", offset_sec=0),
            _ssh_event("FAILURE", source_ip="1.2.3.4", offset_sec=10),
            _ssh_event("FAILURE", source_ip="1.2.3.4", offset_sec=20),
            _ssh_event("SUCCESS", source_ip="1.2.3.4", offset_sec=30),
        ]
        inc = rule_ssh_brute_force(events, _DEVICE)
        assert inc is not None
        assert "1.2.3.4" in inc.metadata["source_ip"]

    def test_metadata_fields(self):
        events = [
            _ssh_event("FAILURE", offset_sec=0),
            _ssh_event("FAILURE", offset_sec=10),
            _ssh_event("FAILURE", offset_sec=20),
            _ssh_event("SUCCESS", offset_sec=30),
        ]
        inc = rule_ssh_brute_force(events, _DEVICE)
        assert "failed_attempts" in inc.metadata
        assert "time_to_compromise_seconds" in inc.metadata
        assert "target_user" in inc.metadata


# ============================================================================
# rule_persistence_after_auth
# ============================================================================


class TestRulePersistenceAfterAuth:

    def test_fires_on_ssh_then_launch_agent(self):
        events = [
            _ssh_event("SUCCESS", offset_sec=0),
            _audit_event(
                "CREATED",
                "LAUNCH_AGENT",
                file_path="/Users/admin/Library/LaunchAgents/evil.plist",
                offset_sec=60,
            ),
        ]
        inc = rule_persistence_after_auth(events, _DEVICE)
        assert inc is not None
        assert inc.rule_name == "persistence_after_auth"
        assert inc.severity == Severity.CRITICAL  # in /Users/ dir
        assert MitreTactic.PERSISTENCE.value in inc.tactics

    def test_fires_on_sudo_then_cron(self):
        events = [
            _sudo_event("some command", offset_sec=0),
            _audit_event("CREATED", "CRON", offset_sec=120),
        ]
        inc = rule_persistence_after_auth(events, _DEVICE)
        assert inc is not None

    def test_high_severity_non_user_dir(self):
        events = [
            _ssh_event("SUCCESS", offset_sec=0),
            _audit_event(
                "CREATED",
                "LAUNCH_DAEMON",
                file_path="/Library/LaunchDaemons/evil.plist",
                offset_sec=60,
            ),
        ]
        inc = rule_persistence_after_auth(events, _DEVICE)
        assert inc is not None
        assert inc.severity == Severity.HIGH

    def test_no_fire_persistence_before_auth(self):
        events = [
            _audit_event("CREATED", "LAUNCH_AGENT", offset_sec=0),
            _ssh_event("SUCCESS", offset_sec=60),
        ]
        assert rule_persistence_after_auth(events, _DEVICE) is None

    def test_no_fire_persistence_outside_10min(self):
        events = [
            _ssh_event("SUCCESS", offset_sec=0),
            _audit_event("CREATED", "LAUNCH_AGENT", offset_sec=700),
        ]
        assert rule_persistence_after_auth(events, _DEVICE) is None

    def test_no_fire_no_auth(self):
        events = [
            _audit_event("CREATED", "LAUNCH_AGENT", offset_sec=0),
        ]
        assert rule_persistence_after_auth(events, _DEVICE) is None

    def test_no_fire_no_persistence(self):
        events = [_ssh_event("SUCCESS", offset_sec=0)]
        assert rule_persistence_after_auth(events, _DEVICE) is None

    def test_no_fire_failed_auth(self):
        events = [
            _ssh_event("FAILURE", offset_sec=0),
            _audit_event("CREATED", "LAUNCH_AGENT", offset_sec=60),
        ]
        assert rule_persistence_after_auth(events, _DEVICE) is None

    def test_empty_events(self):
        assert rule_persistence_after_auth([], _DEVICE) is None

    def test_ssh_keys_persistence_type(self):
        events = [
            _ssh_event("SUCCESS", offset_sec=0),
            _audit_event("CREATED", "SSH_KEYS", offset_sec=30),
        ]
        inc = rule_persistence_after_auth(events, _DEVICE)
        assert inc is not None
        assert "T1098.004" in inc.techniques


# ============================================================================
# rule_suspicious_sudo
# ============================================================================


class TestRuleSuspiciousSudo:

    def test_fires_on_rm_rf_root(self):
        events = [_sudo_event("rm -rf /", offset_sec=0)]
        inc = rule_suspicious_sudo(events, _DEVICE)
        assert inc is not None
        assert inc.severity == Severity.CRITICAL
        assert inc.rule_name == "suspicious_sudo"

    def test_fires_on_sudoers_modification(self):
        events = [
            _sudo_event(
                "echo 'user ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers", offset_sec=0
            )
        ]
        inc = rule_suspicious_sudo(events, _DEVICE)
        assert inc is not None
        assert inc.severity == Severity.CRITICAL

    def test_fires_on_visudo(self):
        # "visudo -f /etc/sudoers.d/extra" matches "/etc/sudoers" (CRITICAL) first
        events = [_sudo_event("visudo -f /etc/sudoers.d/extra", offset_sec=0)]
        inc = rule_suspicious_sudo(events, _DEVICE)
        assert inc is not None
        assert inc.severity == Severity.CRITICAL

    def test_fires_on_visudo_alone(self):
        # plain "visudo" matches the visudo pattern → HIGH
        events = [_sudo_event("visudo", offset_sec=0)]
        inc = rule_suspicious_sudo(events, _DEVICE)
        assert inc is not None
        assert inc.severity == Severity.HIGH

    def test_fires_on_launch_agents(self):
        events = [_sudo_event("cp evil.plist /Library/LaunchAgents/", offset_sec=0)]
        inc = rule_suspicious_sudo(events, _DEVICE)
        assert inc is not None

    def test_fires_on_launch_daemons(self):
        events = [_sudo_event("cp evil.plist /Library/LaunchDaemons/", offset_sec=0)]
        inc = rule_suspicious_sudo(events, _DEVICE)
        assert inc is not None

    def test_fires_on_kextload(self):
        events = [_sudo_event("kextload /Library/Extensions/evil.kext", offset_sec=0)]
        inc = rule_suspicious_sudo(events, _DEVICE)
        assert inc is not None

    def test_fires_on_kernel_extension_install(self):
        events = [
            _sudo_event("cp evil.kext /Library/Extensions/evil.kext", offset_sec=0)
        ]
        inc = rule_suspicious_sudo(events, _DEVICE)
        assert inc is not None

    def test_no_fire_on_normal_sudo(self):
        events = [_sudo_event("apt-get update", offset_sec=0)]
        assert rule_suspicious_sudo(events, _DEVICE) is None

    def test_no_fire_without_sudo_events(self):
        events = [_ssh_event("SUCCESS", offset_sec=0)]
        assert rule_suspicious_sudo(events, _DEVICE) is None

    def test_empty_events(self):
        assert rule_suspicious_sudo([], _DEVICE) is None

    def test_metadata_contains_command(self):
        # "rm -rf /etc" matches "rm -rf /" first in pattern list
        events = [_sudo_event("rm -rf /etc", offset_sec=0)]
        inc = rule_suspicious_sudo(events, _DEVICE)
        assert inc.metadata["command"] == "rm -rf /etc"
        assert inc.metadata["pattern_matched"] == "rm -rf /"


# ============================================================================
# rule_multi_tactic_attack
# ============================================================================


class TestRuleMultiTacticAttack:

    def test_fires_on_flow_process_persist_within_15min(self):
        events = [
            _flow_event(dst_ip="93.184.216.34", dst_port=443, offset_sec=0),
            _process_event(exe_path="/tmp/malware", offset_sec=120),
            _audit_event("CREATED", "LAUNCH_AGENT", offset_sec=240),
        ]
        inc = rule_multi_tactic_attack(events, _DEVICE)
        assert inc is not None
        assert inc.rule_name == "multi_tactic_attack"
        assert inc.severity == Severity.CRITICAL
        assert MitreTactic.COMMAND_AND_CONTROL.value in inc.tactics
        assert MitreTactic.EXECUTION.value in inc.tactics
        assert MitreTactic.PERSISTENCE.value in inc.tactics

    def test_no_fire_missing_flow(self):
        events = [
            _process_event(exe_path="/tmp/malware", offset_sec=0),
            _audit_event("CREATED", "LAUNCH_AGENT", offset_sec=60),
        ]
        assert rule_multi_tactic_attack(events, _DEVICE) is None

    def test_no_fire_missing_suspicious_process(self):
        events = [
            _flow_event(offset_sec=0),
            _process_event(
                exe_path="/usr/bin/safe", offset_sec=60
            ),  # Not suspicious path
            _audit_event("CREATED", "LAUNCH_AGENT", offset_sec=120),
        ]
        assert rule_multi_tactic_attack(events, _DEVICE) is None

    def test_no_fire_missing_persistence(self):
        events = [
            _flow_event(offset_sec=0),
            _process_event(exe_path="/tmp/malware", offset_sec=60),
        ]
        assert rule_multi_tactic_attack(events, _DEVICE) is None

    def test_no_fire_outside_15min_window(self):
        events = [
            _flow_event(offset_sec=0),
            _process_event(exe_path="/tmp/malware", offset_sec=500),
            _audit_event("CREATED", "LAUNCH_AGENT", offset_sec=1000),  # > 900s
        ]
        assert rule_multi_tactic_attack(events, _DEVICE) is None

    def test_empty_events(self):
        assert rule_multi_tactic_attack([], _DEVICE) is None

    def test_detects_downloads_path(self):
        events = [
            _flow_event(offset_sec=0),
            _process_event(exe_path="/Users/admin/Downloads/payload", offset_sec=60),
            _audit_event("CREATED", "SSH_KEYS", offset_sec=120),
        ]
        inc = rule_multi_tactic_attack(events, _DEVICE)
        assert inc is not None


# ============================================================================
# rule_ssh_lateral_movement
# ============================================================================


class TestRuleSSHLateralMovement:

    def test_fires_on_inbound_ssh_then_outbound_ssh(self):
        events = [
            _ssh_event("SUCCESS", source_ip="1.2.3.4", offset_sec=0),
            _flow_event(
                dst_ip="10.0.0.5", dst_port=22, direction="OUTBOUND", offset_sec=60
            ),
        ]
        inc = rule_ssh_lateral_movement(events, _DEVICE)
        assert inc is not None
        assert inc.rule_name == "ssh_lateral_movement"
        assert inc.severity == Severity.HIGH
        assert MitreTactic.LATERAL_MOVEMENT.value in inc.tactics
        assert "1.2.3.4" in inc.summary
        assert "10.0.0.5" in inc.summary

    def test_no_fire_same_ip(self):
        events = [
            _ssh_event("SUCCESS", source_ip="10.0.0.5", offset_sec=0),
            _flow_event(
                dst_ip="10.0.0.5", dst_port=22, direction="OUTBOUND", offset_sec=60
            ),
        ]
        assert rule_ssh_lateral_movement(events, _DEVICE) is None

    def test_no_fire_outbound_before_inbound(self):
        events = [
            _flow_event(
                dst_ip="10.0.0.5", dst_port=22, direction="OUTBOUND", offset_sec=0
            ),
            _ssh_event("SUCCESS", source_ip="1.2.3.4", offset_sec=60),
        ]
        assert rule_ssh_lateral_movement(events, _DEVICE) is None

    def test_no_fire_outside_5min(self):
        events = [
            _ssh_event("SUCCESS", source_ip="1.2.3.4", offset_sec=0),
            _flow_event(
                dst_ip="10.0.0.5", dst_port=22, direction="OUTBOUND", offset_sec=400
            ),
        ]
        assert rule_ssh_lateral_movement(events, _DEVICE) is None

    def test_no_fire_non_ssh_port(self):
        events = [
            _ssh_event("SUCCESS", source_ip="1.2.3.4", offset_sec=0),
            _flow_event(
                dst_ip="10.0.0.5", dst_port=443, direction="OUTBOUND", offset_sec=60
            ),
        ]
        assert rule_ssh_lateral_movement(events, _DEVICE) is None

    def test_no_fire_non_outbound(self):
        events = [
            _ssh_event("SUCCESS", source_ip="1.2.3.4", offset_sec=0),
            _flow_event(
                dst_ip="10.0.0.5", dst_port=22, direction="INBOUND", offset_sec=60
            ),
        ]
        assert rule_ssh_lateral_movement(events, _DEVICE) is None

    def test_no_fire_without_ssh_success(self):
        events = [
            _flow_event(
                dst_ip="10.0.0.5", dst_port=22, direction="OUTBOUND", offset_sec=0
            ),
        ]
        assert rule_ssh_lateral_movement(events, _DEVICE) is None

    def test_no_fire_without_ssh_flows(self):
        events = [
            _ssh_event("SUCCESS", source_ip="1.2.3.4", offset_sec=0),
        ]
        assert rule_ssh_lateral_movement(events, _DEVICE) is None

    def test_empty_events(self):
        assert rule_ssh_lateral_movement([], _DEVICE) is None


# ============================================================================
# rule_data_exfiltration_spike
# ============================================================================


class TestRuleDataExfiltrationSpike:

    def test_fires_on_large_transfer(self):
        # 10MB+ in < 5 minutes to single IP
        events = [
            _flow_event(
                dst_ip="93.184.216.34",
                direction="OUTBOUND",
                bytes_out=6 * 1024 * 1024,
                offset_sec=0,
            ),
            _flow_event(
                dst_ip="93.184.216.34",
                direction="OUTBOUND",
                bytes_out=5 * 1024 * 1024,
                offset_sec=60,
            ),
        ]
        inc = rule_data_exfiltration_spike(events, _DEVICE)
        assert inc is not None
        assert inc.rule_name == "data_exfiltration_spike"
        assert inc.severity == Severity.CRITICAL
        assert MitreTactic.EXFILTRATION.value in inc.tactics
        assert "T1041" in inc.techniques

    def test_no_fire_below_threshold(self):
        events = [
            _flow_event(
                dst_ip="93.184.216.34",
                direction="OUTBOUND",
                bytes_out=1 * 1024 * 1024,
                offset_sec=0,
            ),
        ]
        assert rule_data_exfiltration_spike(events, _DEVICE) is None

    def test_no_fire_spread_over_long_time(self):
        events = [
            _flow_event(
                dst_ip="93.184.216.34",
                direction="OUTBOUND",
                bytes_out=6 * 1024 * 1024,
                offset_sec=0,
            ),
            _flow_event(
                dst_ip="93.184.216.34",
                direction="OUTBOUND",
                bytes_out=5 * 1024 * 1024,
                offset_sec=400,
            ),  # > 300s
        ]
        assert rule_data_exfiltration_spike(events, _DEVICE) is None

    def test_no_fire_no_outbound(self):
        events = [
            _flow_event(
                dst_ip="10.0.0.1", direction="INBOUND", bytes_out=0, offset_sec=0
            ),
        ]
        assert rule_data_exfiltration_spike(events, _DEVICE) is None

    def test_no_fire_zero_bytes(self):
        events = [
            _flow_event(
                dst_ip="10.0.0.1", direction="OUTBOUND", bytes_out=0, offset_sec=0
            ),
        ]
        assert rule_data_exfiltration_spike(events, _DEVICE) is None

    def test_empty_events(self):
        assert rule_data_exfiltration_spike([], _DEVICE) is None

    def test_metadata_fields(self):
        events = [
            _flow_event(
                dst_ip="1.2.3.4",
                direction="OUTBOUND",
                bytes_out=11 * 1024 * 1024,
                offset_sec=0,
            ),
        ]
        inc = rule_data_exfiltration_spike(events, _DEVICE)
        assert inc is not None
        assert "destination_ip" in inc.metadata
        assert "bytes_transferred" in inc.metadata
        assert "megabytes_transferred" in inc.metadata
        assert "flow_count" in inc.metadata


# ============================================================================
# rule_suspicious_process_tree
# ============================================================================


class TestRuleSuspiciousProcessTree:

    def test_fires_on_terminal_spawning_tmp_process(self):
        events = [
            _process_event(
                exe_path="/tmp/malware", parent_name="Terminal", offset_sec=0
            ),
        ]
        inc = rule_suspicious_process_tree(events, _DEVICE)
        assert inc is not None
        assert inc.rule_name == "suspicious_process_tree"
        assert inc.severity == Severity.HIGH
        assert MitreTactic.EXECUTION.value in inc.tactics

    def test_critical_with_network_activity(self):
        events = [
            _process_event(exe_path="/tmp/malware", parent_name="bash", offset_sec=0),
            _flow_event(dst_ip="93.184.216.34", offset_sec=10),
        ]
        inc = rule_suspicious_process_tree(events, _DEVICE)
        assert inc is not None
        assert inc.severity == Severity.CRITICAL
        assert "network activity" in inc.summary
        assert inc.metadata["has_network_activity"] == "True"

    def test_fires_on_sshd_spawning_downloads(self):
        events = [
            _process_event(
                exe_path="/Users/admin/Downloads/payload",
                parent_name="sshd",
                offset_sec=0,
            ),
        ]
        inc = rule_suspicious_process_tree(events, _DEVICE)
        assert inc is not None

    def test_no_fire_normal_parent_normal_path(self):
        events = [
            _process_event(exe_path="/usr/bin/ls", parent_name="Finder", offset_sec=0),
        ]
        assert rule_suspicious_process_tree(events, _DEVICE) is None

    def test_no_fire_suspicious_parent_normal_path(self):
        events = [
            _process_event(
                exe_path="/usr/bin/python3", parent_name="Terminal", offset_sec=0
            ),
        ]
        assert rule_suspicious_process_tree(events, _DEVICE) is None

    def test_no_fire_normal_parent_suspicious_path(self):
        events = [
            _process_event(exe_path="/tmp/script", parent_name="Finder", offset_sec=0),
        ]
        assert rule_suspicious_process_tree(events, _DEVICE) is None

    def test_no_fire_non_process_events(self):
        events = [_ssh_event("SUCCESS", offset_sec=0)]
        assert rule_suspicious_process_tree(events, _DEVICE) is None

    def test_empty_events(self):
        assert rule_suspicious_process_tree([], _DEVICE) is None

    def test_var_tmp_path(self):
        events = [
            _process_event(exe_path="/var/tmp/evil", parent_name="zsh", offset_sec=0),
        ]
        inc = rule_suspicious_process_tree(events, _DEVICE)
        assert inc is not None

    def test_private_tmp_path(self):
        events = [
            _process_event(
                exe_path="/private/tmp/evil", parent_name="sh", offset_sec=0
            ),
        ]
        inc = rule_suspicious_process_tree(events, _DEVICE)
        assert inc is not None


# ============================================================================
# _get_persistence_techniques
# ============================================================================


class TestGetPersistenceTechniques:

    def test_launch_agent(self):
        assert _get_persistence_techniques("LAUNCH_AGENT") == ["T1543.001"]

    def test_launch_daemon(self):
        assert _get_persistence_techniques("LAUNCH_DAEMON") == ["T1543.004"]

    def test_cron(self):
        assert _get_persistence_techniques("CRON") == ["T1053.003"]

    def test_ssh_keys(self):
        assert _get_persistence_techniques("SSH_KEYS") == ["T1098.004"]

    def test_unknown_type(self):
        assert _get_persistence_techniques("UNKNOWN_TYPE") == ["T1543"]


# ============================================================================
# evaluate_rules and ALL_RULES
# ============================================================================


class TestEvaluateRules:

    def test_registry_has_13_rules(self):
        assert len(ALL_RULES) == 13

    def test_all_rules_in_registry(self):
        expected = [
            rule_ssh_brute_force,
            rule_persistence_after_auth,
            rule_suspicious_sudo,
            rule_multi_tactic_attack,
            rule_ssh_lateral_movement,
            rule_data_exfiltration_spike,
            rule_suspicious_process_tree,
        ]
        for fn in expected:
            assert fn in ALL_RULES, f"{fn.__name__} missing from ALL_RULES"

    def test_evaluate_returns_incidents(self):
        events = [_sudo_event("rm -rf /", offset_sec=0)]
        incidents = evaluate_rules(events, _DEVICE)
        rule_names = [i.rule_name for i in incidents]
        assert "suspicious_sudo" in rule_names

    def test_evaluate_returns_empty_on_benign(self):
        events = [
            TelemetryEventView(
                event_id=_next_id(),
                device_id=_DEVICE,
                event_type="METRIC",
                severity="INFO",
                timestamp=_BASE_TIME,
            ),
        ]
        assert evaluate_rules(events, _DEVICE) == []

    def test_evaluate_empty_events(self):
        assert evaluate_rules([], _DEVICE) == []

    def test_evaluate_handles_rule_exception(self):
        """If one rule raises, other rules still execute."""
        from unittest.mock import patch

        events = [_sudo_event("rm -rf /", offset_sec=0)]
        with patch(
            "amoskys.intel.rules.rule_ssh_brute_force",
            side_effect=RuntimeError("boom"),
        ):
            incidents = evaluate_rules(events, _DEVICE)
        rule_names = [i.rule_name for i in incidents]
        assert "suspicious_sudo" in rule_names

    def test_multiple_rules_fire(self):
        """Multiple rules can fire on the same event set."""
        events = [
            # SSH brute force
            _ssh_event("FAILURE", offset_sec=0),
            _ssh_event("FAILURE", offset_sec=10),
            _ssh_event("FAILURE", offset_sec=20),
            _ssh_event("SUCCESS", offset_sec=30),
            # Suspicious sudo
            _sudo_event("rm -rf /etc", offset_sec=40),
        ]
        incidents = evaluate_rules(events, _DEVICE)
        rule_names = [i.rule_name for i in incidents]
        assert "ssh_brute_force" in rule_names
        assert "suspicious_sudo" in rule_names
