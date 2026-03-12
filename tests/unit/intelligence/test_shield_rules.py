"""
Unit tests for macOS Shield + NetworkSentinel fusion rules.

Covers the 6 new rules added in the Observatory phase:
  - rule_coordinated_reconnaissance
  - rule_web_attack_chain
  - rule_infostealer_kill_chain
  - rule_clickfix_attack
  - rule_download_execute_persist
  - rule_credential_harvest_exfil

Each rule is tested for:
  - Detection (happy path)
  - Negative cases (no match -> None)
  - Edge cases (thresholds, severity mapping)

All timestamps and event data are synthetic.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional

import pytest

from amoskys.intel.models import Incident, MitreTactic, Severity, TelemetryEventView
from amoskys.intel.rules import (
    rule_clickfix_attack,
    rule_coordinated_reconnaissance,
    rule_credential_harvest_exfil,
    rule_download_execute_persist,
    rule_infostealer_kill_chain,
    rule_web_attack_chain,
)

# ============================================================================
# Helpers -- event factories
# ============================================================================

_BASE_TIME = datetime(2025, 7, 1, 10, 0, 0)
_DEVICE = "dev-shield-01"
_SEQ = 0


def _next_id() -> str:
    global _SEQ
    _SEQ += 1
    return f"s-evt-{_SEQ:06d}"


def _reset_seq():
    global _SEQ
    _SEQ = 0


def _network_sentinel_event(
    event_category: str,
    attacker_ip: str = "203.0.113.50",
    offset_sec: int = 0,
    mitre_techniques: str = "",
    verdict: str = "",
) -> TelemetryEventView:
    """Create a NetworkSentinel-style security event."""
    attrs: Dict[str, str] = {"attacker_ip": attacker_ip}
    if mitre_techniques:
        attrs["mitre_techniques"] = mitre_techniques
    if verdict:
        attrs["verdict"] = verdict
    return TelemetryEventView(
        event_id=_next_id(),
        device_id=_DEVICE,
        event_type="SECURITY",
        severity="HIGH",
        timestamp=_BASE_TIME + timedelta(seconds=offset_sec),
        attributes=attrs,
        security_event={
            "event_category": event_category,
        },
    )


def _stealer_event(
    event_category: str,
    offset_sec: int = 0,
    mitre_techniques: str = "",
) -> TelemetryEventView:
    """Create an infostealer / credential-access event."""
    se: Dict = {"event_category": event_category}
    if mitre_techniques:
        se["mitre_techniques"] = mitre_techniques
    return TelemetryEventView(
        event_id=_next_id(),
        device_id=_DEVICE,
        event_type="SECURITY",
        severity="HIGH",
        timestamp=_BASE_TIME + timedelta(seconds=offset_sec),
        security_event=se,
    )


def _clickfix_event(
    event_category: str,
    offset_sec: int = 0,
    mitre_techniques: str = "",
) -> TelemetryEventView:
    """Create a ClickFix-style event."""
    se: Dict = {"event_category": event_category}
    if mitre_techniques:
        se["mitre_techniques"] = mitre_techniques
    return TelemetryEventView(
        event_id=_next_id(),
        device_id=_DEVICE,
        event_type="SECURITY",
        severity="HIGH",
        timestamp=_BASE_TIME + timedelta(seconds=offset_sec),
        security_event=se,
    )


def _download_event(
    event_category: str,
    offset_sec: int = 0,
) -> TelemetryEventView:
    """Create a download/quarantine event."""
    return TelemetryEventView(
        event_id=_next_id(),
        device_id=_DEVICE,
        event_type="SECURITY",
        severity="MEDIUM",
        timestamp=_BASE_TIME + timedelta(seconds=offset_sec),
        security_event={"event_category": event_category},
    )


def _persistence_event(
    event_category: str,
    offset_sec: int = 0,
) -> TelemetryEventView:
    """Create a persistence event."""
    return TelemetryEventView(
        event_id=_next_id(),
        device_id=_DEVICE,
        event_type="SECURITY",
        severity="MEDIUM",
        timestamp=_BASE_TIME + timedelta(seconds=offset_sec),
        security_event={"event_category": event_category},
    )


@pytest.fixture(autouse=True)
def reset_event_ids():
    _reset_seq()


# ============================================================================
# rule_coordinated_reconnaissance
# ============================================================================


class TestRuleCoordinatedReconnaissance:

    def test_fires_on_3_distinct_categories_same_ip(self):
        events = [
            _network_sentinel_event("http_scan_storm", offset_sec=0),
            _network_sentinel_event("directory_brute_force", offset_sec=30),
            _network_sentinel_event("sqli_payload_detected", offset_sec=60),
        ]
        inc = rule_coordinated_reconnaissance(events, _DEVICE)
        assert inc is not None
        assert inc.rule_name == "coordinated_reconnaissance"
        assert inc.severity == Severity.MEDIUM
        assert MitreTactic.DISCOVERY.value in inc.tactics
        assert MitreTactic.INITIAL_ACCESS.value in inc.tactics
        assert "203.0.113.50" in inc.summary
        assert inc.start_ts is not None
        assert inc.end_ts is not None

    def test_severity_high_on_4_categories(self):
        events = [
            _network_sentinel_event("http_scan_storm", offset_sec=0),
            _network_sentinel_event("directory_brute_force", offset_sec=10),
            _network_sentinel_event("sqli_payload_detected", offset_sec=20),
            _network_sentinel_event("xss_payload_detected", offset_sec=30),
        ]
        inc = rule_coordinated_reconnaissance(events, _DEVICE)
        assert inc is not None
        assert inc.severity == Severity.HIGH

    def test_severity_critical_on_6_categories(self):
        events = [
            _network_sentinel_event("http_scan_storm", offset_sec=0),
            _network_sentinel_event("directory_brute_force", offset_sec=10),
            _network_sentinel_event("sqli_payload_detected", offset_sec=20),
            _network_sentinel_event("xss_payload_detected", offset_sec=30),
            _network_sentinel_event("path_traversal_detected", offset_sec=40),
            _network_sentinel_event("admin_path_enumeration", offset_sec=50),
        ]
        inc = rule_coordinated_reconnaissance(events, _DEVICE)
        assert inc is not None
        assert inc.severity == Severity.CRITICAL

    def test_no_fire_fewer_than_3_categories(self):
        events = [
            _network_sentinel_event("http_scan_storm", offset_sec=0),
            _network_sentinel_event("directory_brute_force", offset_sec=30),
        ]
        assert rule_coordinated_reconnaissance(events, _DEVICE) is None

    def test_no_fire_different_ips(self):
        events = [
            _network_sentinel_event("http_scan_storm", attacker_ip="1.1.1.1", offset_sec=0),
            _network_sentinel_event("directory_brute_force", attacker_ip="2.2.2.2", offset_sec=30),
            _network_sentinel_event("sqli_payload_detected", attacker_ip="3.3.3.3", offset_sec=60),
        ]
        assert rule_coordinated_reconnaissance(events, _DEVICE) is None

    def test_no_fire_non_sentinel_events(self):
        events = [
            TelemetryEventView(
                event_id=_next_id(),
                device_id=_DEVICE,
                event_type="METRIC",
                severity="INFO",
                timestamp=_BASE_TIME,
            ),
        ]
        assert rule_coordinated_reconnaissance(events, _DEVICE) is None

    def test_empty_events(self):
        assert rule_coordinated_reconnaissance([], _DEVICE) is None

    def test_metadata_fields(self):
        events = [
            _network_sentinel_event("http_scan_storm", offset_sec=0),
            _network_sentinel_event("directory_brute_force", offset_sec=30),
            _network_sentinel_event("sqli_payload_detected", offset_sec=60),
        ]
        inc = rule_coordinated_reconnaissance(events, _DEVICE)
        assert inc is not None
        assert "attacker_ip" in inc.metadata
        assert "category_count" in inc.metadata
        assert "total_events" in inc.metadata
        assert inc.metadata["attacker_ip"] == "203.0.113.50"

    def test_mitre_techniques_extracted(self):
        events = [
            _network_sentinel_event(
                "http_scan_storm", offset_sec=0,
                mitre_techniques='["T1595.002"]',
            ),
            _network_sentinel_event("directory_brute_force", offset_sec=10),
            _network_sentinel_event("sqli_payload_detected", offset_sec=20),
        ]
        inc = rule_coordinated_reconnaissance(events, _DEVICE)
        assert inc is not None
        assert "T1595.002" in inc.techniques


# ============================================================================
# rule_web_attack_chain
# ============================================================================


class TestRuleWebAttackChain:

    def test_fires_on_recon_then_exploit(self):
        events = [
            _network_sentinel_event("http_scan_storm", offset_sec=0),
            _network_sentinel_event("sqli_payload_detected", offset_sec=60),
        ]
        inc = rule_web_attack_chain(events, _DEVICE)
        assert inc is not None
        assert inc.rule_name == "web_attack_chain"
        assert inc.severity == Severity.HIGH
        assert MitreTactic.DISCOVERY.value in inc.tactics
        assert MitreTactic.INITIAL_ACCESS.value in inc.tactics
        assert "203.0.113.50" in inc.summary

    def test_critical_with_post_exploit(self):
        events = [
            _network_sentinel_event("directory_brute_force", offset_sec=0),
            _network_sentinel_event("xss_payload_detected", offset_sec=30),
            _network_sentinel_event("admin_path_enumeration", offset_sec=60),
        ]
        inc = rule_web_attack_chain(events, _DEVICE)
        assert inc is not None
        assert inc.severity == Severity.CRITICAL

    def test_no_fire_only_recon(self):
        events = [
            _network_sentinel_event("http_scan_storm", offset_sec=0),
            _network_sentinel_event("directory_brute_force", offset_sec=30),
        ]
        assert rule_web_attack_chain(events, _DEVICE) is None

    def test_no_fire_only_exploit(self):
        events = [
            _network_sentinel_event("sqli_payload_detected", offset_sec=0),
            _network_sentinel_event("xss_payload_detected", offset_sec=30),
        ]
        assert rule_web_attack_chain(events, _DEVICE) is None

    def test_no_fire_different_ips(self):
        events = [
            _network_sentinel_event("http_scan_storm", attacker_ip="1.1.1.1", offset_sec=0),
            _network_sentinel_event("sqli_payload_detected", attacker_ip="2.2.2.2", offset_sec=30),
        ]
        assert rule_web_attack_chain(events, _DEVICE) is None

    def test_empty_events(self):
        assert rule_web_attack_chain([], _DEVICE) is None

    def test_metadata_fields(self):
        events = [
            _network_sentinel_event("attack_tool_detected", offset_sec=0),
            _network_sentinel_event("path_traversal_detected", offset_sec=30),
        ]
        inc = rule_web_attack_chain(events, _DEVICE)
        assert inc is not None
        assert "chain_stages" in inc.metadata
        assert "chain_depth" in inc.metadata
        assert "attacker_ip" in inc.metadata

    def test_fires_with_credential_spray_as_post_exploit(self):
        events = [
            _network_sentinel_event("http_scan_storm", offset_sec=0),
            _network_sentinel_event("sqli_payload_detected", offset_sec=30),
            _network_sentinel_event("credential_spray_detected", offset_sec=60),
        ]
        inc = rule_web_attack_chain(events, _DEVICE)
        assert inc is not None
        assert inc.severity == Severity.CRITICAL


# ============================================================================
# rule_infostealer_kill_chain
# ============================================================================


class TestRuleInfostealerKillChain:

    def test_fires_on_dialog_and_credential_access(self):
        events = [
            _stealer_event("fake_password_dialog", offset_sec=0),
            _stealer_event("keychain_access", offset_sec=30),
        ]
        inc = rule_infostealer_kill_chain(events, _DEVICE)
        assert inc is not None
        assert inc.rule_name == "infostealer_kill_chain"
        assert inc.severity == Severity.HIGH
        assert MitreTactic.CREDENTIAL_ACCESS.value in inc.tactics
        assert MitreTactic.COLLECTION.value in inc.tactics

    def test_critical_on_3_stages(self):
        events = [
            _stealer_event("fake_password_dialog", offset_sec=0),
            _stealer_event("browser_cred_theft", offset_sec=30),
            _stealer_event("credential_archive", offset_sec=60),
        ]
        inc = rule_infostealer_kill_chain(events, _DEVICE)
        assert inc is not None
        assert inc.severity == Severity.CRITICAL

    def test_fires_on_credential_and_exfil(self):
        events = [
            _stealer_event("crypto_wallet_theft", offset_sec=0),
            _stealer_event("sensitive_file_exfil", offset_sec=60),
        ]
        inc = rule_infostealer_kill_chain(events, _DEVICE)
        assert inc is not None
        assert inc.severity == Severity.HIGH

    def test_no_fire_single_stage(self):
        events = [
            _stealer_event("keychain_access", offset_sec=0),
            _stealer_event("browser_cred_theft", offset_sec=30),
        ]
        # Both are in "credential_access" stage => only 1 stage
        assert rule_infostealer_kill_chain(events, _DEVICE) is None

    def test_no_fire_unrelated_events(self):
        events = [
            TelemetryEventView(
                event_id=_next_id(),
                device_id=_DEVICE,
                event_type="PROCESS",
                severity="INFO",
                timestamp=_BASE_TIME,
                process_event={"process_name": "ls", "pid": 100},
            ),
        ]
        assert rule_infostealer_kill_chain(events, _DEVICE) is None

    def test_empty_events(self):
        assert rule_infostealer_kill_chain([], _DEVICE) is None

    def test_full_kill_chain(self):
        events = [
            _stealer_event("fake_password_dialog", offset_sec=0),
            _stealer_event("keychain_access", offset_sec=20),
            _stealer_event("session_cookie_theft", offset_sec=40),
            _stealer_event("credential_archive", offset_sec=60),
            _stealer_event("exfil_detected", offset_sec=80),
        ]
        inc = rule_infostealer_kill_chain(events, _DEVICE)
        assert inc is not None
        assert inc.severity == Severity.CRITICAL
        assert "4 stages" in inc.summary

    def test_mitre_techniques_from_events(self):
        events = [
            _stealer_event(
                "fake_password_dialog", offset_sec=0,
                mitre_techniques='["T1056.002"]',
            ),
            _stealer_event("keychain_access", offset_sec=30),
        ]
        inc = rule_infostealer_kill_chain(events, _DEVICE)
        assert inc is not None
        assert "T1056.002" in inc.techniques

    def test_metadata_fields(self):
        events = [
            _stealer_event("fake_password_dialog", offset_sec=0),
            _stealer_event("crypto_wallet_theft", offset_sec=30),
        ]
        inc = rule_infostealer_kill_chain(events, _DEVICE)
        assert inc is not None
        assert "stages_hit" in inc.metadata
        assert "kill_chain_type" in inc.metadata
        assert inc.metadata["kill_chain_type"] == "macos_infostealer"


# ============================================================================
# rule_clickfix_attack
# ============================================================================


class TestRuleClickfixAttack:

    def test_fires_on_clickfix_detected(self):
        events = [
            _clickfix_event("clickfix_detected", offset_sec=0),
        ]
        inc = rule_clickfix_attack(events, _DEVICE)
        assert inc is not None
        assert inc.rule_name == "clickfix_attack"
        assert inc.severity == Severity.CRITICAL
        assert MitreTactic.EXECUTION.value in inc.tactics
        assert MitreTactic.INITIAL_ACCESS.value in inc.tactics

    def test_fires_on_browser_to_terminal(self):
        events = [
            _clickfix_event("browser_to_terminal", offset_sec=0),
        ]
        inc = rule_clickfix_attack(events, _DEVICE)
        assert inc is not None
        assert inc.rule_name == "clickfix_attack"

    def test_fires_on_msg_to_download_chain(self):
        events = [
            _clickfix_event("msg_to_download", offset_sec=0),
            _clickfix_event("download_to_execute", offset_sec=30),
        ]
        inc = rule_clickfix_attack(events, _DEVICE)
        assert inc is not None
        assert inc.rule_name == "clickfix_attack"

    def test_no_fire_only_rapid_app_switch(self):
        """rapid_app_switch alone is not clickfix_detected nor a chain indicator."""
        events = [
            _clickfix_event("rapid_app_switch", offset_sec=0),
        ]
        assert rule_clickfix_attack(events, _DEVICE) is None

    def test_no_fire_unrelated_events(self):
        events = [
            TelemetryEventView(
                event_id=_next_id(),
                device_id=_DEVICE,
                event_type="FLOW",
                severity="INFO",
                timestamp=_BASE_TIME,
                flow_event={"dst_ip": "10.0.0.1", "dst_port": 443},
            ),
        ]
        assert rule_clickfix_attack(events, _DEVICE) is None

    def test_empty_events(self):
        assert rule_clickfix_attack([], _DEVICE) is None

    def test_multiple_indicators(self):
        events = [
            _clickfix_event("clickfix_detected", offset_sec=0),
            _clickfix_event("browser_to_terminal", offset_sec=10),
            _clickfix_event("download_to_execute", offset_sec=30),
        ]
        inc = rule_clickfix_attack(events, _DEVICE)
        assert inc is not None
        assert "3 indicators" in inc.summary

    def test_metadata_fields(self):
        events = [
            _clickfix_event("clickfix_detected", offset_sec=0),
            _clickfix_event("rapid_app_switch", offset_sec=10),
        ]
        inc = rule_clickfix_attack(events, _DEVICE)
        assert inc is not None
        assert "indicator_count" in inc.metadata
        assert "categories" in inc.metadata

    def test_mitre_techniques_extracted(self):
        events = [
            _clickfix_event(
                "clickfix_detected", offset_sec=0,
                mitre_techniques='["T1204.001", "T1059"]',
            ),
        ]
        inc = rule_clickfix_attack(events, _DEVICE)
        assert inc is not None
        assert "T1204.001" in inc.techniques
        assert "T1059" in inc.techniques


# ============================================================================
# rule_download_execute_persist
# ============================================================================


class TestRuleDownloadExecutePersist:

    def test_fires_on_download_and_persistence(self):
        events = [
            _download_event("quarantine_bypass", offset_sec=0),
            _persistence_event("launch_agent_created", offset_sec=60),
        ]
        inc = rule_download_execute_persist(events, _DEVICE)
        assert inc is not None
        assert inc.rule_name == "download_execute_persist"
        assert inc.severity == Severity.HIGH
        assert MitreTactic.INITIAL_ACCESS.value in inc.tactics
        assert MitreTactic.EXECUTION.value in inc.tactics
        assert MitreTactic.PERSISTENCE.value in inc.tactics
        assert "T1204.002" in inc.techniques
        assert "T1543" in inc.techniques

    def test_fires_on_dmg_mount_and_cron(self):
        events = [
            _download_event("dmg_mount_execute", offset_sec=0),
            _persistence_event("cron_modified", offset_sec=120),
        ]
        inc = rule_download_execute_persist(events, _DEVICE)
        assert inc is not None

    def test_fires_on_cli_download_and_ssh_key(self):
        events = [
            _download_event("cli_download_execute", offset_sec=0),
            _persistence_event("ssh_key_added", offset_sec=30),
        ]
        inc = rule_download_execute_persist(events, _DEVICE)
        assert inc is not None

    def test_no_fire_download_only(self):
        events = [
            _download_event("quarantine_bypass", offset_sec=0),
            _download_event("unsigned_download_exec", offset_sec=30),
        ]
        assert rule_download_execute_persist(events, _DEVICE) is None

    def test_no_fire_persistence_only(self):
        events = [
            _persistence_event("launch_agent_created", offset_sec=0),
            _persistence_event("cron_modified", offset_sec=30),
        ]
        assert rule_download_execute_persist(events, _DEVICE) is None

    def test_no_fire_unrelated_events(self):
        events = [
            TelemetryEventView(
                event_id=_next_id(),
                device_id=_DEVICE,
                event_type="METRIC",
                severity="INFO",
                timestamp=_BASE_TIME,
            ),
        ]
        assert rule_download_execute_persist(events, _DEVICE) is None

    def test_empty_events(self):
        assert rule_download_execute_persist([], _DEVICE) is None

    def test_metadata_fields(self):
        events = [
            _download_event("quarantine_bypass", offset_sec=0),
            _download_event("dmg_mount_execute", offset_sec=10),
            _persistence_event("launch_agent_created", offset_sec=60),
        ]
        inc = rule_download_execute_persist(events, _DEVICE)
        assert inc is not None
        assert inc.metadata["download_count"] == "2"
        assert inc.metadata["persistence_count"] == "1"

    def test_multiple_persistence_types(self):
        events = [
            _download_event("installer_script_abuse", offset_sec=0),
            _persistence_event("launch_daemon_created", offset_sec=30),
            _persistence_event("login_item_added", offset_sec=60),
            _persistence_event("shell_profile_modified", offset_sec=90),
        ]
        inc = rule_download_execute_persist(events, _DEVICE)
        assert inc is not None
        assert inc.metadata["persistence_count"] == "3"


# ============================================================================
# rule_credential_harvest_exfil
# ============================================================================


class TestRuleCredentialHarvestExfil:

    def test_fires_on_2_credential_categories(self):
        events = [
            _stealer_event("keychain_access", offset_sec=0),
            _stealer_event("browser_cred_theft", offset_sec=30),
        ]
        inc = rule_credential_harvest_exfil(events, _DEVICE)
        assert inc is not None
        assert inc.rule_name == "credential_harvest_exfil"
        assert inc.severity == Severity.HIGH
        assert MitreTactic.CREDENTIAL_ACCESS.value in inc.tactics
        assert MitreTactic.EXFILTRATION.value in inc.tactics
        assert "T1555" in inc.techniques
        assert "T1041" in inc.techniques

    def test_critical_with_exfil(self):
        events = [
            _stealer_event("keychain_access", offset_sec=0),
            _stealer_event("crypto_wallet_theft", offset_sec=30),
            _stealer_event("sensitive_file_exfil", offset_sec=60),
        ]
        inc = rule_credential_harvest_exfil(events, _DEVICE)
        assert inc is not None
        assert inc.severity == Severity.CRITICAL

    def test_fires_with_exfil_detected(self):
        events = [
            _stealer_event("session_cookie_theft", offset_sec=0),
            _stealer_event("browser_cred_theft", offset_sec=30),
            _stealer_event("exfil_detected", offset_sec=60),
        ]
        inc = rule_credential_harvest_exfil(events, _DEVICE)
        assert inc is not None
        assert inc.severity == Severity.CRITICAL

    def test_no_fire_single_credential_category(self):
        events = [
            _stealer_event("keychain_access", offset_sec=0),
            _stealer_event("keychain_access", offset_sec=30),
        ]
        assert rule_credential_harvest_exfil(events, _DEVICE) is None

    def test_no_fire_only_exfil(self):
        events = [
            _stealer_event("sensitive_file_exfil", offset_sec=0),
        ]
        assert rule_credential_harvest_exfil(events, _DEVICE) is None

    def test_no_fire_unrelated_events(self):
        events = [
            TelemetryEventView(
                event_id=_next_id(),
                device_id=_DEVICE,
                event_type="PROCESS",
                severity="INFO",
                timestamp=_BASE_TIME,
                process_event={"process_name": "Safari", "pid": 200},
            ),
        ]
        assert rule_credential_harvest_exfil(events, _DEVICE) is None

    def test_empty_events(self):
        assert rule_credential_harvest_exfil([], _DEVICE) is None

    def test_metadata_fields(self):
        events = [
            _stealer_event("keychain_access", offset_sec=0),
            _stealer_event("crypto_wallet_theft", offset_sec=30),
            _stealer_event("session_cookie_theft", offset_sec=60),
        ]
        inc = rule_credential_harvest_exfil(events, _DEVICE)
        assert inc is not None
        assert "credential_categories" in inc.metadata
        assert "category_count" in inc.metadata
        assert "total_access_events" in inc.metadata
        assert "exfil_events" in inc.metadata
        assert inc.metadata["category_count"] == "3"
        assert inc.metadata["exfil_events"] == "0"

    def test_all_credential_types_with_exfil(self):
        events = [
            _stealer_event("keychain_access", offset_sec=0),
            _stealer_event("browser_cred_theft", offset_sec=10),
            _stealer_event("crypto_wallet_theft", offset_sec=20),
            _stealer_event("session_cookie_theft", offset_sec=30),
            _stealer_event("stealer_sequence", offset_sec=40),
            _stealer_event("exfil_detected", offset_sec=60),
        ]
        inc = rule_credential_harvest_exfil(events, _DEVICE)
        assert inc is not None
        assert inc.severity == Severity.CRITICAL
        assert inc.metadata["category_count"] == "5"
        assert inc.metadata["total_access_events"] == "5"
        assert inc.metadata["exfil_events"] == "1"

    def test_high_severity_without_exfil(self):
        events = [
            _stealer_event("keychain_access", offset_sec=0),
            _stealer_event("browser_cred_theft", offset_sec=30),
        ]
        inc = rule_credential_harvest_exfil(events, _DEVICE)
        assert inc is not None
        assert inc.severity == Severity.HIGH
