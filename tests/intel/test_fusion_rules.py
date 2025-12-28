"""
Unit tests for Fusion Engine correlation rules.

Tests all four detection rules with positive (should fire) and negative
(should not fire) cases to ensure accurate detection and minimal false positives.

Rules tested:
1. ssh_brute_force - SSH brute force followed by successful login
2. persistence_after_auth - Persistence created after authentication
3. suspicious_sudo - Dangerous sudo command patterns
4. multi_tactic_attack - Full kill chain (process + network + persistence)
"""

import pytest
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

from amoskys.intel.fusion_engine import FusionEngine
from amoskys.intel.models import TelemetryEventView


@pytest.fixture
def fusion(tmp_path):
    """
    Fresh FusionEngine per test with isolated database.

    Args:
        tmp_path: pytest temp directory fixture

    Returns:
        FusionEngine instance with clean state
    """
    db_path = tmp_path / "fusion_test.db"
    engine = FusionEngine(db_path=str(db_path), window_minutes=30)
    return engine


@pytest.fixture
def device_id():
    """Normalized device ID for all tests"""
    return "test-macbook-pro"


def fetch_incidents(db_path: str):
    """
    Fetch all incidents from fusion database for assertion.

    Args:
        db_path: Path to fusion SQLite database

    Returns:
        List of tuples: (device_id, rule_name, severity, summary)
    """
    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT device_id, rule_name, severity, summary FROM incidents"
    ).fetchall()
    conn.close()
    return rows


# =============================================================================
# Test Helpers - Event Creation
# =============================================================================

def make_ssh_event(
    event_id: str,
    device_id: str,
    outcome: str,
    src_ip: str = "203.0.113.42",
    username: str = "admin",
    offset_seconds: int = 0
) -> TelemetryEventView:
    """
    Create SSH authentication event.

    Args:
        event_id: Unique event identifier
        device_id: Device where event occurred
        outcome: 'SUCCESS' or 'FAILURE'
        src_ip: Source IP address
        username: Username attempting login
        offset_seconds: Offset from now in seconds

    Returns:
        TelemetryEventView for SSH auth event
    """
    timestamp = datetime.now() + timedelta(seconds=offset_seconds)

    return TelemetryEventView(
        event_id=event_id,
        device_id=device_id,
        event_type="SECURITY",
        severity="INFO",
        timestamp=timestamp,
        security_event={
            'event_category': 'AUTHENTICATION',
            'event_action': 'SSH',
            'event_outcome': outcome,
            'user_name': username,
            'source_ip': src_ip,
            'risk_score': 0.3 if outcome == 'SUCCESS' else 0.6,
            'mitre_techniques': ['T1021.004'],
            'requires_investigation': (outcome == 'FAILURE')
        }
    )


def make_sudo_event(
    event_id: str,
    device_id: str,
    command: str,
    username: str = "admin",
    offset_seconds: int = 0
) -> TelemetryEventView:
    """
    Create sudo command execution event.

    Args:
        event_id: Unique event identifier
        device_id: Device where event occurred
        command: Sudo command executed
        username: User who ran sudo
        offset_seconds: Offset from now in seconds

    Returns:
        TelemetryEventView for sudo event
    """
    timestamp = datetime.now() + timedelta(seconds=offset_seconds)

    # Detect dangerous patterns for risk scoring
    dangerous = any(pattern in command for pattern in ['rm -rf', '/etc/sudoers', 'kext'])
    risk_score = 0.8 if dangerous else 0.3

    return TelemetryEventView(
        event_id=event_id,
        device_id=device_id,
        event_type="SECURITY",
        severity="CRITICAL" if dangerous else "INFO",
        timestamp=timestamp,
        attributes={
            'sudo_command': command,
            'auth_method': 'password'
        },
        security_event={
            'event_category': 'AUTHENTICATION',
            'event_action': 'SUDO',
            'event_outcome': 'SUCCESS',
            'user_name': username,
            'source_ip': '127.0.0.1',
            'risk_score': risk_score,
            'mitre_techniques': ['T1548.003'],
            'requires_investigation': dangerous
        }
    )


def make_persistence_event(
    event_id: str,
    device_id: str,
    persist_type: str = "LAUNCH_AGENT",
    file_path: str = "/Users/admin/Library/LaunchAgents/com.evil.backdoor.plist",
    offset_seconds: int = 120
) -> TelemetryEventView:
    """
    Create persistence mechanism creation event.

    Args:
        event_id: Unique event identifier
        device_id: Device where event occurred
        persist_type: Type (LAUNCH_AGENT, LAUNCH_DAEMON, SSH_KEYS, CRON)
        file_path: Path to persistence artifact
        offset_seconds: Offset from now in seconds

    Returns:
        TelemetryEventView for persistence creation
    """
    timestamp = datetime.now() + timedelta(seconds=offset_seconds)

    # Higher risk for user-level persistence
    in_user_dir = '/Users/' in file_path
    risk_score = 0.7 if in_user_dir else 0.5

    return TelemetryEventView(
        event_id=event_id,
        device_id=device_id,
        event_type="AUDIT",
        severity="WARN",
        timestamp=timestamp,
        attributes={
            'persistence_type': persist_type,
            'file_path': file_path,
            'risk_score': str(risk_score)
        },
        audit_event={
            'audit_category': 'CHANGE',
            'action_performed': 'CREATED',
            'object_type': persist_type,
            'object_id': file_path,
            'before_value': '',
            'after_value': '{"Program": "/tmp/backdoor", "RunAtLoad": true}'
        }
    )


def make_process_event(
    event_id: str,
    device_id: str,
    executable_path: str = "/tmp/.evil",
    offset_seconds: int = 30
) -> TelemetryEventView:
    """
    Create suspicious process execution event.

    Args:
        event_id: Unique event identifier
        device_id: Device where event occurred
        executable_path: Path to executable
        offset_seconds: Offset from now in seconds

    Returns:
        TelemetryEventView for process execution
    """
    timestamp = datetime.now() + timedelta(seconds=offset_seconds)

    return TelemetryEventView(
        event_id=event_id,
        device_id=device_id,
        event_type="PROCESS",
        severity="WARN",
        timestamp=timestamp,
        process_event={
            'process_name': Path(executable_path).name,
            'pid': 12345,
            'ppid': 1,
            'uid': 501,
            'command_line': f'{executable_path} --connect 198.51.100.99',
            'executable_path': executable_path
        }
    )


def make_flow_event(
    event_id: str,
    device_id: str,
    dst_ip: str = "198.51.100.99",
    dst_port: int = 443,
    offset_seconds: int = 60
) -> TelemetryEventView:
    """
    Create network flow event.

    Args:
        event_id: Unique event identifier
        device_id: Device where event occurred
        dst_ip: Destination IP address
        dst_port: Destination port
        offset_seconds: Offset from now in seconds

    Returns:
        TelemetryEventView for network flow
    """
    timestamp = datetime.now() + timedelta(seconds=offset_seconds)

    return TelemetryEventView(
        event_id=event_id,
        device_id=device_id,
        event_type="FLOW",
        severity="INFO",
        timestamp=timestamp,
        flow_event={
            'src_ip': '192.168.1.100',
            'src_port': 54321,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'protocol': 'TCP',
            'bytes_sent': 1024,
            'bytes_received': 4096
        }
    )


# =============================================================================
# Rule 1: SSH Brute Force
# =============================================================================

def test_ssh_brute_force_fires(fusion, device_id):
    """
    POSITIVE: 3 failed SSH + 1 success from same IP should create incident.

    Pattern:
        - 3+ failed SSH attempts from 203.0.113.42
        - Successful SSH from same IP within 30 minutes

    Expected:
        - Incident: ssh_brute_force
        - Severity: HIGH
        - Techniques: T1110, T1021.004
    """
    events = [
        make_ssh_event("ssh_fail_1", device_id, "FAILURE", offset_seconds=0),
        make_ssh_event("ssh_fail_2", device_id, "FAILURE", offset_seconds=5),
        make_ssh_event("ssh_fail_3", device_id, "FAILURE", offset_seconds=10),
        make_ssh_event("ssh_success", device_id, "SUCCESS", offset_seconds=15),
    ]

    for ev in events:
        fusion.add_event(ev)

    fusion.evaluate_all_devices()

    rows = fetch_incidents(fusion.db_path)
    rules = {r[1] for r in rows}  # rule_name

    assert "ssh_brute_force" in rules, f"Expected ssh_brute_force incident, got: {rows}"

    # Verify severity
    incident = [r for r in rows if r[1] == "ssh_brute_force"][0]
    assert incident[2] == "HIGH", "SSH brute force should be HIGH severity"


def test_ssh_brute_force_not_fired_without_success(fusion, device_id):
    """
    NEGATIVE: Failed SSH attempts without success should NOT fire rule.

    Pattern:
        - 3 failed SSH attempts
        - No successful login

    Expected:
        - No ssh_brute_force incident
    """
    events = [
        make_ssh_event("ssh_fail_1", device_id, "FAILURE", offset_seconds=0),
        make_ssh_event("ssh_fail_2", device_id, "FAILURE", offset_seconds=5),
        make_ssh_event("ssh_fail_3", device_id, "FAILURE", offset_seconds=10),
    ]

    for ev in events:
        fusion.add_event(ev)

    fusion.evaluate_all_devices()

    rows = fetch_incidents(fusion.db_path)
    rules = {r[1] for r in rows}

    assert "ssh_brute_force" not in rules, f"Unexpected ssh_brute_force incident: {rows}"


def test_ssh_brute_force_not_fired_with_only_two_failures(fusion, device_id):
    """
    NEGATIVE: Only 2 failures + success should NOT fire (threshold is 3+).

    Pattern:
        - 2 failed SSH attempts
        - 1 successful login

    Expected:
        - No ssh_brute_force incident (below threshold)
    """
    events = [
        make_ssh_event("ssh_fail_1", device_id, "FAILURE", offset_seconds=0),
        make_ssh_event("ssh_fail_2", device_id, "FAILURE", offset_seconds=5),
        make_ssh_event("ssh_success", device_id, "SUCCESS", offset_seconds=10),
    ]

    for ev in events:
        fusion.add_event(ev)

    fusion.evaluate_all_devices()

    rows = fetch_incidents(fusion.db_path)
    rules = {r[1] for r in rows}

    assert "ssh_brute_force" not in rules, "Should not fire with only 2 failures"


# =============================================================================
# Rule 2: Persistence After Authentication
# =============================================================================

def test_persistence_after_auth_fires(fusion, device_id):
    """
    POSITIVE: SSH success + LaunchAgent creation within 10min should fire.

    Pattern:
        - Successful SSH login
        - LaunchAgent created 120s later

    Expected:
        - Incident: persistence_after_auth
        - Severity: CRITICAL (user directory)
        - Techniques: T1543.001
    """
    events = [
        make_ssh_event("ssh_success", device_id, "SUCCESS", offset_seconds=0),
        make_persistence_event("la_create", device_id, offset_seconds=120),
    ]

    for ev in events:
        fusion.add_event(ev)

    fusion.evaluate_all_devices()

    rows = fetch_incidents(fusion.db_path)
    rules = {r[1] for r in rows}

    assert "persistence_after_auth" in rules, f"Expected persistence_after_auth, got: {rows}"

    incident = [r for r in rows if r[1] == "persistence_after_auth"][0]
    assert incident[2] == "CRITICAL", "User-dir persistence should be CRITICAL"


def test_persistence_after_auth_fires_for_sudo_too(fusion, device_id):
    """
    POSITIVE: Sudo + persistence creation should also trigger rule.

    Pattern:
        - Sudo command execution
        - LaunchAgent created shortly after

    Expected:
        - Incident: persistence_after_auth
    """
    events = [
        make_sudo_event("sudo_cmd", device_id, "sudo ls /tmp", offset_seconds=0),
        make_persistence_event("la_create", device_id, offset_seconds=120),
    ]

    for ev in events:
        fusion.add_event(ev)

    fusion.evaluate_all_devices()

    rows = fetch_incidents(fusion.db_path)
    rules = {r[1] for r in rows}

    assert "persistence_after_auth" in rules, "Should fire for sudo + persistence"


def test_persistence_after_auth_not_fired_without_auth(fusion, device_id):
    """
    NEGATIVE: Persistence creation without prior auth should NOT fire.

    Pattern:
        - LaunchAgent created
        - No prior SSH/sudo

    Expected:
        - No persistence_after_auth incident
    """
    ev = make_persistence_event("la_create", device_id, offset_seconds=120)
    fusion.add_event(ev)
    fusion.evaluate_all_devices()

    rows = fetch_incidents(fusion.db_path)
    rules = {r[1] for r in rows}

    assert "persistence_after_auth" not in rules, "Should not fire without prior auth"


# =============================================================================
# Rule 3: Suspicious Sudo
# =============================================================================

def test_suspicious_sudo_fires_for_sudoers_edit(fusion, device_id):
    """
    POSITIVE: Editing /etc/sudoers should trigger rule.

    Pattern:
        - Sudo command containing '/etc/sudoers'

    Expected:
        - Incident: suspicious_sudo
        - Severity: CRITICAL
        - Technique: T1548.003
    """
    ev = make_sudo_event(
        "sudo_edit_sudoers",
        device_id,
        "vim /etc/sudoers",
        offset_seconds=0
    )

    fusion.add_event(ev)
    fusion.evaluate_all_devices()

    rows = fetch_incidents(fusion.db_path)
    rules = {r[1] for r in rows}

    assert "suspicious_sudo" in rules, f"Expected suspicious_sudo, got: {rows}"

    incident = [r for r in rows if r[1] == "suspicious_sudo"][0]
    assert incident[2] == "CRITICAL", "Sudoers edit should be CRITICAL"


def test_suspicious_sudo_fires_for_rm_rf(fusion, device_id):
    """
    POSITIVE: Dangerous rm -rf command should trigger rule.

    Pattern:
        - Sudo command with 'rm -rf /'

    Expected:
        - Incident: suspicious_sudo
        - Severity: CRITICAL
    """
    ev = make_sudo_event(
        "sudo_rm_rf",
        device_id,
        "sudo rm -rf /var",
        offset_seconds=0
    )

    fusion.add_event(ev)
    fusion.evaluate_all_devices()

    rows = fetch_incidents(fusion.db_path)
    rules = {r[1] for r in rows}

    assert "suspicious_sudo" in rules, "rm -rf should trigger suspicious_sudo"


def test_suspicious_sudo_not_fired_for_benign_command(fusion, device_id):
    """
    NEGATIVE: Harmless sudo command should NOT trigger rule.

    Pattern:
        - Sudo command: 'sudo ls /tmp'

    Expected:
        - No suspicious_sudo incident
    """
    ev = make_sudo_event(
        "sudo_ls",
        device_id,
        "sudo ls /tmp",
        offset_seconds=0
    )

    fusion.add_event(ev)
    fusion.evaluate_all_devices()

    rows = fetch_incidents(fusion.db_path)
    rules = {r[1] for r in rows}

    assert "suspicious_sudo" not in rules, "Benign sudo should not trigger rule"


# =============================================================================
# Rule 4: Multi-Tactic Attack
# =============================================================================

def test_multi_tactic_attack_fires(fusion, device_id):
    """
    POSITIVE: Full kill chain should create CRITICAL incident.

    Pattern:
        - Suspicious process (/tmp/.evil)
        - Outbound network flow to uncommon IP/port
        - Persistence mechanism created
        All within 15 minutes

    Expected:
        - Incident: multi_tactic_attack
        - Severity: CRITICAL
        - Techniques: T1071, T1059, T1543.001
    """
    events = [
        make_process_event("proc_evil", device_id, "/tmp/.evil", offset_seconds=0),
        make_flow_event("flow_c2", device_id, "198.51.100.99", 443, offset_seconds=60),
        make_persistence_event("la_create", device_id, offset_seconds=180),
    ]

    for ev in events:
        fusion.add_event(ev)

    fusion.evaluate_all_devices()

    rows = fetch_incidents(fusion.db_path)
    rules = {r[1] for r in rows}

    assert "multi_tactic_attack" in rules, f"Expected multi_tactic_attack, got: {rows}"

    incident = [r for r in rows if r[1] == "multi_tactic_attack"][0]
    assert incident[2] == "CRITICAL", "Multi-tactic attack should be CRITICAL"


def test_multi_tactic_attack_not_fired_without_persistence(fusion, device_id):
    """
    NEGATIVE: Missing persistence stage should prevent rule from firing.

    Pattern:
        - Suspicious process
        - Outbound flow
        - No persistence

    Expected:
        - No multi_tactic_attack incident
    """
    events = [
        make_process_event("proc_evil", device_id, "/tmp/.evil", offset_seconds=0),
        make_flow_event("flow_c2", device_id, "198.51.100.99", 443, offset_seconds=60),
        # Missing persistence
    ]

    for ev in events:
        fusion.add_event(ev)

    fusion.evaluate_all_devices()

    rows = fetch_incidents(fusion.db_path)
    rules = {r[1] for r in rows}

    assert "multi_tactic_attack" not in rules, "Should not fire without persistence"


def test_multi_tactic_attack_not_fired_without_process(fusion, device_id):
    """
    NEGATIVE: Missing process execution should prevent rule from firing.

    Pattern:
        - Outbound flow
        - Persistence
        - No suspicious process

    Expected:
        - No multi_tactic_attack incident
    """
    events = [
        # Missing process
        make_flow_event("flow_c2", device_id, "198.51.100.99", 443, offset_seconds=60),
        make_persistence_event("la_create", device_id, offset_seconds=180),
    ]

    for ev in events:
        fusion.add_event(ev)

    fusion.evaluate_all_devices()

    rows = fetch_incidents(fusion.db_path)
    rules = {r[1] for r in rows}

    assert "multi_tactic_attack" not in rules, "Should not fire without process execution"


# =============================================================================
# Integration Tests - Multiple Rules Firing
# =============================================================================

def test_multiple_rules_can_fire_simultaneously(fusion, device_id):
    """
    Integration test: Multiple correlation rules can fire in same evaluation.

    Scenario:
        - SSH brute force → success
        - Sudo sudoers edit
        - Persistence creation

    Expected:
        - ssh_brute_force incident
        - suspicious_sudo incident
        - persistence_after_auth incident
    """
    events = [
        # SSH brute force
        make_ssh_event("ssh_fail_1", device_id, "FAILURE", offset_seconds=0),
        make_ssh_event("ssh_fail_2", device_id, "FAILURE", offset_seconds=5),
        make_ssh_event("ssh_fail_3", device_id, "FAILURE", offset_seconds=10),
        make_ssh_event("ssh_success", device_id, "SUCCESS", offset_seconds=15),

        # Suspicious sudo
        make_sudo_event("sudo_sudoers", device_id, "vim /etc/sudoers", offset_seconds=60),

        # Persistence after auth
        make_persistence_event("la_create", device_id, offset_seconds=120),
    ]

    for ev in events:
        fusion.add_event(ev)

    fusion.evaluate_all_devices()

    rows = fetch_incidents(fusion.db_path)
    rules = {r[1] for r in rows}

    # All three rules should fire
    assert "ssh_brute_force" in rules, "SSH brute force should fire"
    assert "suspicious_sudo" in rules, "Suspicious sudo should fire"
    assert "persistence_after_auth" in rules, "Persistence after auth should fire"

    assert len(rules) == 3, f"Expected 3 different incidents, got {len(rules)}: {rules}"


def test_device_risk_increases_with_incidents(fusion, device_id):
    """
    Integration test: Device risk score should increase as incidents accumulate.

    Scenario:
        - Start with base risk (10)
        - SSH brute force → +25 points
        - Persistence creation → +25 points
        - Sudo abuse → +30 points

    Expected:
        - Device risk > 80 (CRITICAL)
    """
    events = [
        # SSH brute force
        make_ssh_event("ssh_fail_1", device_id, "FAILURE", offset_seconds=0),
        make_ssh_event("ssh_fail_2", device_id, "FAILURE", offset_seconds=5),
        make_ssh_event("ssh_fail_3", device_id, "FAILURE", offset_seconds=10),
        make_ssh_event("ssh_success", device_id, "SUCCESS", offset_seconds=15),

        # Persistence
        make_persistence_event("la_create", device_id, offset_seconds=120),

        # Sudo abuse
        make_sudo_event("sudo_rm", device_id, "sudo rm -rf /var", offset_seconds=180),
    ]

    for ev in events:
        fusion.add_event(ev)

    fusion.evaluate_all_devices()

    # Query device risk
    risk = fusion.get_device_risk(device_id)

    assert risk is not None, "Device risk should be calculated"
    assert risk['score'] >= 80, f"Device risk should be CRITICAL (>=80), got {risk['score']}"
    assert risk['level'] == "CRITICAL", "Device should be at CRITICAL risk level"


# =============================================================================
# Edge Cases
# =============================================================================

def test_events_outside_correlation_window_ignored(fusion, device_id):
    """
    Edge case: Events outside 30-minute correlation window should not correlate.

    Pattern:
        - SSH success at T=0
        - Persistence at T=31 minutes (outside window)

    Expected:
        - No persistence_after_auth incident
    """
    events = [
        make_ssh_event("ssh_success", device_id, "SUCCESS", offset_seconds=0),
        make_persistence_event("la_create", device_id, offset_seconds=31 * 60),  # 31 min
    ]

    for ev in events:
        fusion.add_event(ev)

    fusion.evaluate_all_devices()

    rows = fetch_incidents(fusion.db_path)
    rules = {r[1] for r in rows}

    assert "persistence_after_auth" not in rules, "Events outside window should not correlate"


def test_empty_device_state_does_not_crash(fusion, device_id):
    """
    Edge case: Evaluating device with no events should not crash.

    Expected:
        - No incidents
        - No exceptions
    """
    # Don't add any events, just evaluate
    fusion.evaluate_all_devices()

    rows = fetch_incidents(fusion.db_path)
    assert len(rows) == 0, "No incidents should be created for empty state"
