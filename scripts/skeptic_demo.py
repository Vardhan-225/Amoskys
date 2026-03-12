#!/usr/bin/env python3
"""AMOSKYS Skeptic Demo — OPERATION OBSIDIAN TEMPEST

A 9-stage macOS APT kill chain executed against the full Observatory
sensor array.  Each stage injects realistic attacker data into the
probes and collects detection events.  The demo proves:

  1. Multi-agent coordination — 5 Observatory agents detect different
     facets of the same attack.
  2. MITRE ATT&CK coverage — 16 techniques mapped across 9 tactics.
  3. Behavioral correctness — every stage fires the expected detections.
  4. Correlation — a single attacker narrative links all events.

Usage:
    PYTHONPATH=src:. .venv/bin/python3 scripts/skeptic_demo.py
    PYTHONPATH=src:. .venv/bin/python3 scripts/skeptic_demo.py --json   # JSON report
    PYTHONPATH=src:. .venv/bin/python3 scripts/skeptic_demo.py --quiet  # CI mode
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

# ── project imports ─────────────────────────────────────────────────────
from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)

# Collectors (data structures)
from amoskys.agents.os.macos.auth.collector import AuthEvent

# Probes (the detectors)
from amoskys.agents.os.macos.auth.probes import (
    CredentialAccessProbe,
    SudoEscalationProbe,
)
from amoskys.agents.os.macos.filesystem.collector import FileEntry
from amoskys.agents.os.macos.filesystem.probes import (
    DownloadsMonitorProbe,
    HiddenFileProbe,
)
from amoskys.agents.os.macos.network.collector import Connection, ProcessBandwidth
from amoskys.agents.os.macos.network.probes import (
    C2BeaconProbe,
    ExfilSpikeProbe,
    LateralSSHProbe,
    NonStandardPortProbe,
)
from amoskys.agents.os.macos.persistence.collector import PersistenceEntry
from amoskys.agents.os.macos.persistence.probes import (
    CronProbe,
    LaunchAgentProbe,
    ShellProfileProbe,
)
from amoskys.agents.os.macos.process.collector import ProcessSnapshot
from amoskys.agents.os.macos.process.probes import (
    BinaryFromTempProbe,
    LOLBinProbe,
    ProcessMasqueradeProbe,
    ProcessTreeProbe,
    ScriptInterpreterProbe,
)

# ═══════════════════════════════════════════════════════════════════════
# ANSI terminal helpers
# ═══════════════════════════════════════════════════════════════════════

_USE_COLOR = sys.stdout.isatty() and "--no-color" not in sys.argv


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text


def _bold(t: str) -> str:
    return _c("1", t)


def _dim(t: str) -> str:
    return _c("2", t)


def _red(t: str) -> str:
    return _c("91", t)


def _green(t: str) -> str:
    return _c("92", t)


def _yellow(t: str) -> str:
    return _c("93", t)


def _cyan(t: str) -> str:
    return _c("96", t)


def _white(t: str) -> str:
    return _c("97", t)


def _bg_red(t: str) -> str:
    return _c("41;97", t)


def _bg_green(t: str) -> str:
    return _c("42;97", t)


# ═══════════════════════════════════════════════════════════════════════
# Attack narrative — OPERATION OBSIDIAN TEMPEST
# ═══════════════════════════════════════════════════════════════════════

_HOME = str(Path.home())
_NOW = datetime(2024, 11, 15, 2, 30, 0, tzinfo=timezone.utc)  # 2:30 AM (off-hours)
_ATTACKER_IP = "185.220.101.42"  # Known Tor exit / C2
_LATERAL_IP = "192.168.1.50"  # Internal dev server
_C2_PORT = 8443
_IMPLANT_GUID = "obsidian-implant-001"


@dataclass
class StageResult:
    """Result of running one kill chain stage."""

    stage_num: int
    name: str
    phase: str
    techniques: List[str]
    agents: List[str]
    events: List[TelemetryEvent]
    expected_min: int
    passed: bool
    detail: str = ""


@dataclass
class KillChainStage:
    """One stage of the APT kill chain."""

    num: int
    name: str
    phase: str  # MITRE tactic
    techniques: List[str]  # MITRE technique IDs
    description: str  # What the attacker does
    agents: List[str]  # Observatory agents involved
    probes: List[Tuple[MicroProbe, str]]  # (probe, shared_data_key) pairs
    data_factory: Callable  # Returns Dict[str, Any] shared_data
    expected_min: int  # Minimum expected events


# ═══════════════════════════════════════════════════════════════════════
# Stage definitions
# ═══════════════════════════════════════════════════════════════════════


def _make_stages() -> List[KillChainStage]:
    """Build the 9-stage kill chain.

    Each stage creates fresh probe instances.  Baseline-diff probes
    (downloads, hidden files, persistence) get a two-phase scan:
    the first call in _run_stage handles the baseline, then the attack
    data triggers detection.
    """

    # ── Stage 1: Initial Access ─────────────────────────────────
    # Trojanized .dmg downloaded via watering hole
    dl_probe = DownloadsMonitorProbe()

    def _stage1_data() -> Dict[str, Any]:
        return {
            "files": [
                FileEntry(
                    path=f"{_HOME}/Downloads/XcodePlugin-v2.1.dmg",
                    name="XcodePlugin-v2.1.dmg",
                    sha256="a" * 64,
                    mtime=_NOW.timestamp(),
                    size=48_000_000,
                    mode=0o644,
                    uid=501,
                    is_suid=False,
                ),
            ],
        }

    stage1 = KillChainStage(
        num=1,
        name="INITIAL ACCESS",
        phase="initial_access",
        techniques=["T1189", "T1204.002"],
        description=(
            "Watering hole delivers trojanized XcodePlugin-v2.1.dmg. "
            "curl downloads the payload to ~/Downloads. "
            "(curl from zsh is benign-parent filtered — download itself is the signal.)"
        ),
        agents=["filesystem"],
        probes=[(dl_probe, "files")],
        data_factory=_stage1_data,
        expected_min=1,  # download detection (curl from zsh is benign-parent)
    )

    # ── Stage 2: Execution ──────────────────────────────────────
    # LOLBin chain: osascript runs AppleScript, spawns python3 implant
    lolbin_probe_s2 = LOLBinProbe()
    script_probe = ScriptInterpreterProbe()
    tree_probe = ProcessTreeProbe()
    temp_probe = BinaryFromTempProbe()

    def _stage2_data() -> Dict[str, Any]:
        return {
            "processes": [
                # osascript running the dropper
                ProcessSnapshot(
                    pid=40010,
                    name="osascript",
                    exe="/usr/bin/osascript",
                    cmdline=[
                        "osascript",
                        "-e",
                        'do shell script "/tmp/.payload stage2"',
                    ],
                    username="developer",
                    ppid=40001,
                    parent_name="curl",
                    create_time=_NOW.timestamp() + 2,
                    cpu_percent=1.0,
                    memory_percent=0.2,
                    status="running",
                    cwd="/tmp",
                    environ=None,
                    is_own_user=True,
                    process_guid="stage2-osascript-001",
                ),
                # python3 implant spawned by osascript
                ProcessSnapshot(
                    pid=40011,
                    name="python3",
                    exe="/usr/bin/python3",
                    cmdline=[
                        "python3",
                        "/tmp/.payload/agent.py",
                        "--c2",
                        f"{_ATTACKER_IP}:{_C2_PORT}",
                    ],
                    username="developer",
                    ppid=40010,
                    parent_name="osascript",
                    create_time=_NOW.timestamp() + 3,
                    cpu_percent=2.0,
                    memory_percent=0.5,
                    status="running",
                    cwd="/tmp/.payload",
                    environ=None,
                    is_own_user=True,
                    process_guid=_IMPLANT_GUID,
                ),
                # Binary executing from /tmp
                ProcessSnapshot(
                    pid=40012,
                    name="beacon",
                    exe="/tmp/.payload/beacon",
                    cmdline=["/tmp/.payload/beacon", "--interval", "30"],
                    username="developer",
                    ppid=40011,
                    parent_name="python3",
                    create_time=_NOW.timestamp() + 4,
                    cpu_percent=0.5,
                    memory_percent=0.1,
                    status="running",
                    cwd="/tmp/.payload",
                    environ=None,
                    is_own_user=True,
                    process_guid="stage2-beacon-001",
                ),
            ],
        }

    stage2 = KillChainStage(
        num=2,
        name="EXECUTION",
        phase="execution",
        techniques=["T1059.002", "T1059.006", "T1218"],
        description=(
            "osascript runs AppleScript dropper -> python3 implant starts -> "
            "beacon binary executes from /tmp/.payload/"
        ),
        agents=["process"],
        probes=[
            (lolbin_probe_s2, "processes"),
            (script_probe, "processes"),
            (tree_probe, "processes"),
            (temp_probe, "processes"),
        ],
        data_factory=_stage2_data,
        expected_min=3,
    )

    # ── Stage 3: Persistence ────────────────────────────────────
    # LaunchAgent + .zshrc backdoor + cron job
    la_probe = LaunchAgentProbe()
    sp_probe = ShellProfileProbe()
    cron_probe = CronProbe()

    def _stage3_data() -> Dict[str, Any]:
        return {
            "entries": [
                PersistenceEntry(
                    category="launchagent_user",
                    path=f"{_HOME}/Library/LaunchAgents/com.xcode.helper.plist",
                    name="com.xcode.helper.plist",
                    content_hash="b" * 64,
                    program="/tmp/.payload/beacon",
                    label="com.xcode.helper",
                    run_at_load=True,
                    keep_alive=True,
                ),
                PersistenceEntry(
                    category="shell_profile",
                    path=f"{_HOME}/.zshrc",
                    name=".zshrc",
                    content_hash="c" * 64,
                ),
                PersistenceEntry(
                    category="cron",
                    path="/var/at/tabs/developer",
                    name="developer",
                    content_hash="d" * 64,
                    program="/tmp/.payload/beacon",
                ),
            ],
        }

    stage3 = KillChainStage(
        num=3,
        name="PERSISTENCE",
        phase="persistence",
        techniques=["T1543.001", "T1546.004", "T1053.003"],
        description=(
            "Triple persistence: LaunchAgent (com.xcode.helper) with RunAtLoad + "
            "KeepAlive, .zshrc backdoor (shell profile), cron job."
        ),
        agents=["persistence"],
        probes=[
            (la_probe, "entries"),
            (sp_probe, "entries"),
            (cron_probe, "entries"),
        ],
        data_factory=_stage3_data,
        expected_min=3,
    )

    # ── Stage 4: Privilege Escalation ───────────────────────────
    sudo_probe = SudoEscalationProbe()

    def _stage4_data() -> Dict[str, Any]:
        return {
            "auth_events": [
                AuthEvent(
                    timestamp=_NOW,
                    process="sudo",
                    message=(
                        "developer : TTY=ttys001 ; PWD=/tmp/.payload ; "
                        "USER=root ; COMMAND=/bin/cp beacon /usr/local/bin/xcode-helper"
                    ),
                    category="sudo",
                    username="developer",
                    event_type="success",
                ),
                AuthEvent(
                    timestamp=_NOW,
                    process="sudo",
                    message=(
                        "developer : TTY=ttys001 ; PWD=/tmp/.payload ; "
                        "USER=root ; COMMAND=/bin/chmod 4755 /usr/local/bin/xcode-helper"
                    ),
                    category="sudo",
                    username="developer",
                    event_type="success",
                ),
            ],
        }

    stage4 = KillChainStage(
        num=4,
        name="PRIVILEGE ESCALATION",
        phase="privilege_escalation",
        techniques=["T1548.003"],
        description=(
            "Abuses sudo to copy beacon to /usr/local/bin/xcode-helper "
            "and set SUID bit (chmod 4755)."
        ),
        agents=["auth"],
        probes=[(sudo_probe, "auth_events")],
        data_factory=_stage4_data,
        expected_min=2,
    )

    # ── Stage 5: Credential Access ──────────────────────────────
    cred_probe = CredentialAccessProbe()

    def _stage5_data() -> Dict[str, Any]:
        return {
            "auth_events": [
                AuthEvent(
                    timestamp=_NOW,
                    process="security",
                    message=(
                        "security find-generic-password -ga 'Chrome' "
                        "-s 'Chrome Safe Storage'"
                    ),
                    category="keychain",
                    username="developer",
                    event_type="success",
                ),
                AuthEvent(
                    timestamp=_NOW,
                    process="security",
                    message="security dump-keychain -d login.keychain",
                    category="keychain",
                    username="developer",
                    event_type="success",
                ),
                AuthEvent(
                    timestamp=_NOW,
                    process="security",
                    message="security find-internet-password -ga 'github.com'",
                    category="keychain",
                    username="developer",
                    event_type="success",
                ),
            ],
        }

    stage5 = KillChainStage(
        num=5,
        name="CREDENTIAL ACCESS",
        phase="credential_access",
        techniques=["T1555.001"],
        description=(
            "Dumps Keychain via security CLI: Chrome Safe Storage, "
            "login.keychain full dump, GitHub internet password."
        ),
        agents=["auth"],
        probes=[(cred_probe, "auth_events")],
        data_factory=_stage5_data,
        expected_min=3,
    )

    # ── Stage 6: Defense Evasion ────────────────────────────────
    masq_probe = ProcessMasqueradeProbe()
    hidden_probe = HiddenFileProbe()

    def _stage6_data() -> Dict[str, Any]:
        return {
            "processes": [
                ProcessSnapshot(
                    pid=40020,
                    name="sshd",
                    exe="/tmp/.payload/sshd",
                    cmdline=["/tmp/.payload/sshd", "--beacon"],
                    username="developer",
                    ppid=1,
                    parent_name="launchd",
                    create_time=_NOW.timestamp(),
                    cpu_percent=0.3,
                    memory_percent=0.2,
                    status="running",
                    cwd="/",
                    environ=None,
                    is_own_user=True,
                    process_guid="stage6-masq-001",
                ),
            ],
            "files": [
                FileEntry(
                    path="/tmp/.payload",
                    name=".payload",
                    sha256="e" * 64,
                    mtime=_NOW.timestamp(),
                    size=8192,
                    mode=0o755,
                    uid=501,
                    is_suid=False,
                ),
                FileEntry(
                    path=f"{_HOME}/Library/.cache_update",
                    name=".cache_update",
                    sha256="f" * 64,
                    mtime=_NOW.timestamp(),
                    size=4096,
                    mode=0o755,
                    uid=501,
                    is_suid=False,
                ),
            ],
        }

    stage6 = KillChainStage(
        num=6,
        name="DEFENSE EVASION",
        phase="defense_evasion",
        techniques=["T1036", "T1036.005", "T1564.001"],
        description=(
            "Implant masquerades as sshd (running from /tmp/.payload/sshd). "
            "Hidden files planted in /tmp/.payload and ~/Library/.cache_update."
        ),
        agents=["process", "filesystem"],
        probes=[
            (masq_probe, "processes"),
            (hidden_probe, "files"),
        ],
        data_factory=_stage6_data,
        expected_min=2,
    )

    # ── Stage 7: Lateral Movement ───────────────────────────────
    lateral_probe = LateralSSHProbe()

    def _stage7_data() -> Dict[str, Any]:
        return {
            "connections": [
                Connection(
                    pid=40020,
                    process_name="ssh",
                    user="developer",
                    protocol="TCP",
                    local_addr="192.168.1.10:52341",
                    remote_addr=f"{_LATERAL_IP}:22",
                    state="ESTABLISHED",
                    local_ip="192.168.1.10",
                    local_port=52341,
                    remote_ip=_LATERAL_IP,
                    remote_port=22,
                ),
                Connection(
                    pid=40021,
                    process_name="ssh",
                    user="developer",
                    protocol="TCP",
                    local_addr="192.168.1.10:52342",
                    remote_addr="192.168.1.51:22",
                    state="ESTABLISHED",
                    local_ip="192.168.1.10",
                    local_port=52342,
                    remote_ip="192.168.1.51",
                    remote_port=22,
                ),
            ],
        }

    stage7 = KillChainStage(
        num=7,
        name="LATERAL MOVEMENT",
        phase="lateral_movement",
        techniques=["T1021.004", "T1570"],
        description=(
            "SSH from compromised workstation to internal dev servers "
            f"({_LATERAL_IP}, 192.168.1.51) using stolen credentials."
        ),
        agents=["network"],
        probes=[(lateral_probe, "connections")],
        data_factory=_stage7_data,
        expected_min=2,
    )

    # ── Stage 8: C2 Communication ───────────────────────────────
    c2_probe = C2BeaconProbe()
    nsp_probe = NonStandardPortProbe()

    def _stage8_data() -> Dict[str, Any]:
        return {
            "connections": [
                Connection(
                    pid=40012,
                    process_name="beacon",
                    user="developer",
                    protocol="TCP",
                    local_addr="192.168.1.10:52400",
                    remote_addr=f"{_ATTACKER_IP}:{_C2_PORT}",
                    state="ESTABLISHED",
                    local_ip="192.168.1.10",
                    local_port=52400,
                    remote_ip=_ATTACKER_IP,
                    remote_port=_C2_PORT,
                ),
                Connection(
                    pid=40020,
                    process_name="sshd",
                    user="developer",
                    protocol="TCP",
                    local_addr="0.0.0.0:4444",
                    remote_addr="",
                    state="LISTEN",
                    local_ip="0.0.0.0",
                    local_port=4444,
                    remote_ip="",
                    remote_port=0,
                ),
            ],
        }

    stage8 = KillChainStage(
        num=8,
        name="COMMAND & CONTROL",
        phase="command_and_control",
        techniques=["T1071", "T1571", "T1573"],
        description=(
            f"Beacon contacts C2 at {_ATTACKER_IP}:{_C2_PORT} (HTTPS on non-standard port). "
            "Fake sshd listens on port 4444 (reverse shell backdoor)."
        ),
        agents=["network"],
        probes=[
            (c2_probe, "connections"),
            (nsp_probe, "connections"),
        ],
        data_factory=_stage8_data,
        expected_min=1,  # NonStandardPort fires; C2Beacon needs 3 scans
    )

    # ── Stage 9: Exfiltration ───────────────────────────────────
    exfil_probe = ExfilSpikeProbe()

    def _stage9_data() -> Dict[str, Any]:
        return {
            "connections": [],  # Required field
            "bandwidth": [
                ProcessBandwidth(
                    pid=40012,
                    process_name="beacon",
                    bytes_in=1_024,
                    bytes_out=47_000_000,  # 47MB outbound
                ),
            ],
        }

    stage9 = KillChainStage(
        num=9,
        name="EXFILTRATION",
        phase="exfiltration",
        techniques=["T1048", "T1048.002"],
        description=(
            "Beacon exfiltrates 47MB of source code and credentials "
            f"to {_ATTACKER_IP} via HTTPS. Exfil spike > 10MB threshold."
        ),
        agents=["network"],
        probes=[(exfil_probe, "connections")],
        data_factory=_stage9_data,
        expected_min=1,
    )

    return [stage1, stage2, stage3, stage4, stage5, stage6, stage7, stage8, stage9]


# ═══════════════════════════════════════════════════════════════════════
# Execution engine
# ═══════════════════════════════════════════════════════════════════════


def _run_baseline(stage: KillChainStage) -> None:
    """Run baseline scan for all baseline-diff probes in a stage."""
    for probe, sdk in stage.probes:
        if hasattr(probe, "_first_run") and probe._first_run:
            empty_ctx = ProbeContext(
                device_id="obsidian-host",
                agent_name="obsidian_demo",
                shared_data={sdk: []},
            )
            probe.scan(empty_ctx)


def _run_stage(stage: KillChainStage) -> StageResult:
    """Execute one kill chain stage and collect events."""
    _run_baseline(stage)
    data = stage.data_factory()
    all_events: List[TelemetryEvent] = []

    for probe, sdk in stage.probes:
        shared_data = {sdk: data.get(sdk, [])}
        for key, val in data.items():
            if key != sdk:
                shared_data[key] = val

        ctx = ProbeContext(
            device_id="obsidian-host",
            agent_name="obsidian_demo",
            shared_data=shared_data,
        )
        events = probe.scan(ctx)
        all_events.extend(events)

    passed = len(all_events) >= stage.expected_min
    detail = ""
    if not passed:
        detail = f"expected >={stage.expected_min} events, got {len(all_events)}"

    return StageResult(
        stage_num=stage.num,
        name=stage.name,
        phase=stage.phase,
        techniques=stage.techniques,
        agents=stage.agents,
        events=all_events,
        expected_min=stage.expected_min,
        passed=passed,
        detail=detail,
    )


def _run_c2_beacon_multi_scan(stage: KillChainStage) -> StageResult:
    """Special handler for C2 beacon stage — needs 3 scans for MIN_HITS."""
    _run_baseline(stage)
    data = stage.data_factory()
    all_events: List[TelemetryEvent] = []

    for probe, sdk in stage.probes:
        shared_data = {sdk: data.get(sdk, [])}
        for key, val in data.items():
            if key != sdk:
                shared_data[key] = val

        ctx = ProbeContext(
            device_id="obsidian-host",
            agent_name="obsidian_demo",
            shared_data=shared_data,
        )

        if isinstance(probe, C2BeaconProbe):
            c2_events: List[TelemetryEvent] = []
            for _ in range(3):
                c2_events = probe.scan(ctx)
            all_events.extend(c2_events)
        else:
            events = probe.scan(ctx)
            all_events.extend(events)

    passed = len(all_events) >= stage.expected_min
    detail = ""
    if not passed:
        detail = f"expected >={stage.expected_min} events, got {len(all_events)}"

    return StageResult(
        stage_num=stage.num,
        name=stage.name,
        phase=stage.phase,
        techniques=stage.techniques,
        agents=stage.agents,
        events=all_events,
        expected_min=stage.expected_min,
        passed=passed,
        detail=detail,
    )


# ═══════════════════════════════════════════════════════════════════════
# Output formatting
# ═══════════════════════════════════════════════════════════════════════

_SEVERITY_COLOR = {
    "CRITICAL": _red,
    "HIGH": _yellow,
    "MEDIUM": _cyan,
    "LOW": _dim,
    "INFO": _dim,
}

_PHASE_LABELS = {
    "initial_access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege_escalation": "Privilege Escalation",
    "credential_access": "Credential Access",
    "defense_evasion": "Defense Evasion",
    "lateral_movement": "Lateral Movement",
    "command_and_control": "Command & Control",
    "exfiltration": "Exfiltration",
}


def _print_header() -> None:
    w = 64
    print()
    print(_bold("=" * w))
    print(_bold("  AMOSKYS SKEPTIC DEMO"))
    print(_bold("  OPERATION OBSIDIAN TEMPEST"))
    print(_dim("  9-Stage macOS APT Kill Chain"))
    print(_bold("=" * w))
    print()
    print(_dim("  Target:     ") + "macOS developer workstation (uid=501)")
    print(_dim("  Attacker:   ") + f"{_ATTACKER_IP} (Tor exit / C2 server)")
    print(_dim("  Vector:     ") + "Trojanized Xcode plugin via watering hole")
    print(_dim("  Time:       ") + f"{_NOW.isoformat()} (off-hours)")
    print(_dim("  Sensors:    ") + "5 Observatory agents, 15 probes active")
    print()


def _print_stage_result(sr: StageResult) -> None:
    phase_label = _PHASE_LABELS.get(sr.phase, sr.phase)
    status = _bg_green(" DETECTED ") if sr.passed else _bg_red(" MISSED ")

    print(
        f"  {_bold(f'Stage {sr.stage_num}/9')} {_white(sr.name)} "
        f"{_dim(f'[{phase_label}]')}  {status}"
    )
    print(f"  {_dim('Techniques:')} {', '.join(sr.techniques)}")
    print(f"  {_dim('Agents:')} {', '.join(sr.agents)}")

    if sr.events:
        for ev in sr.events:
            sev = ev.severity.value
            color_fn = _SEVERITY_COLOR.get(sev, _dim)
            probe = ev.probe_name
            etype = ev.event_type
            conf = f"{ev.confidence:.0%}"
            summary = _extract_summary(ev)

            print(
                f"    {color_fn(f'[{sev}]')} {probe}::{etype} "
                f"{_dim(f'({conf})')}  {summary}"
            )
    else:
        print(f"    {_dim('(no events)')}")

    if not sr.passed:
        print(f"    {_red(f'FAIL: {sr.detail}')}")

    print()


def _extract_summary(ev: TelemetryEvent) -> str:
    """Extract the most informative one-liner from event data."""
    d = ev.data
    parts = []

    if "process_name" in d:
        parts.append(f"process={d['process_name']}")
    elif "name" in d and "pid" in d:
        parts.append(f"pid={d['pid']} name={d['name']}")

    if "path" in d:
        parts.append(f"path={d['path']}")
    elif "exe" in d:
        parts.append(f"exe={d['exe']}")
    elif "suspect_path" in d:
        parts.append(f"path={d['suspect_path']}")

    if "remote_ip" in d:
        port = d.get("remote_port", "")
        parts.append(
            f"remote={d['remote_ip']}:{port}" if port else f"remote={d['remote_ip']}"
        )

    if "username" in d and "process_name" not in d and "name" not in d:
        parts.append(f"user={d['username']}")
    if "subcommand" in d and d["subcommand"]:
        parts.append(f"subcmd={d['subcommand']}")

    if "bytes_out" in d:
        mb = d["bytes_out"] / (1024 * 1024)
        parts.append(f"bytes_out={mb:.1f}MB")

    if "change_type" in d:
        parts.append(f"change={d['change_type']}")

    return _dim(" | ").join(parts) if parts else ""


def _print_verdict(results: List[StageResult], elapsed: float) -> None:
    total_events = sum(len(r.events) for r in results)
    detected_stages = sum(1 for r in results if r.passed)
    all_techniques = sorted(set(t for r in results for t in r.techniques))
    all_agents = sorted(set(a for r in results for a in r.agents))
    severities: Dict[str, int] = {}
    for r in results:
        for ev in r.events:
            s = ev.severity.value
            severities[s] = severities.get(s, 0) + 1

    confidences = [ev.confidence for r in results for ev in r.events]
    avg_conf = sum(confidences) / len(confidences) if confidences else 0

    w = 64
    print(_bold("=" * w))
    print(_bold("  VERDICT"))
    print(_bold("=" * w))
    print()

    if detected_stages == len(results):
        badge = _bg_green(" ALL STAGES DETECTED ")
    else:
        badge = _bg_red(f" {len(results) - detected_stages} STAGES MISSED ")

    print(f"  {badge}")
    print()
    print(
        f"  Kill Chain Coverage:  {_bold(f'{detected_stages}/{len(results)}')} stages"
    )
    print(f"  Total Alerts:         {_bold(str(total_events))}")
    print(f"  MITRE Techniques:     {_bold(str(len(all_techniques)))} unique")
    print(
        f"  Agents Contributing:  {_bold(str(len(all_agents)))} "
        f"({', '.join(all_agents)})"
    )
    print(f"  Mean Confidence:      {_bold(f'{avg_conf:.0%}')}")
    print(f"  Execution Time:       {_bold(f'{elapsed:.3f}s')}")
    print()

    # Severity breakdown
    print(_dim("  Severity Breakdown:"))
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severities.get(sev, 0)
        if count > 0:
            color_fn = _SEVERITY_COLOR.get(sev, _dim)
            bar = color_fn("#" * min(count, 30))
            print(f"    {sev:>8} {bar} {count}")
    print()

    # MITRE coverage
    print(_dim("  MITRE ATT&CK Kill Chain:"))
    for r in results:
        phase_label = _PHASE_LABELS.get(r.phase, r.phase)
        check = _green("v") if r.passed else _red("x")
        techs = ", ".join(r.techniques)
        count = len(r.events)
        print(f"    {check} {phase_label:<22} {_dim(techs):<40} [{count} events]")
    print()

    # Correlation chain
    print(_dim("  Attack Chain (first detection per stage):"))
    chain = []
    for r in results:
        if r.events:
            chain.append(r.events[0].event_type)
    print(f"    {_cyan(' -> '.join(chain))}")
    print()


def _to_json(results: List[StageResult], elapsed: float) -> str:
    """Serialise results to JSON for CI integration."""
    stages = []
    for r in results:
        events = []
        for ev in r.events:
            events.append(
                {
                    "event_type": ev.event_type,
                    "severity": ev.severity.value,
                    "probe_name": ev.probe_name,
                    "confidence": ev.confidence,
                    "mitre_techniques": ev.mitre_techniques,
                    "data_keys": sorted(ev.data.keys()),
                }
            )
        stages.append(
            {
                "stage": r.stage_num,
                "name": r.name,
                "phase": r.phase,
                "techniques": r.techniques,
                "agents": r.agents,
                "passed": r.passed,
                "event_count": len(r.events),
                "events": events,
            }
        )

    total_events = sum(len(r.events) for r in results)
    detected = sum(1 for r in results if r.passed)

    return json.dumps(
        {
            "operation": "OBSIDIAN_TEMPEST",
            "stages_detected": detected,
            "stages_total": len(results),
            "total_events": total_events,
            "execution_time_s": round(elapsed, 3),
            "all_passed": all(r.passed for r in results),
            "stages": stages,
        },
        indent=2,
    )


# ═══════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════


def main() -> int:
    quiet = "--quiet" in sys.argv
    json_mode = "--json" in sys.argv

    stages = _make_stages()
    results: List[StageResult] = []

    if not quiet:
        _print_header()
        print(_bold("  THE ATTACK"))
        print(_bold("  " + "-" * 62))
        print()

    t0 = time.monotonic()

    for stage in stages:
        if stage.num == 8:
            sr = _run_c2_beacon_multi_scan(stage)
        else:
            sr = _run_stage(stage)
        results.append(sr)

        if not quiet:
            _print_stage_result(sr)

    elapsed = time.monotonic() - t0

    if json_mode:
        print(_to_json(results, elapsed))
        return 0 if all(r.passed for r in results) else 1

    if not quiet:
        _print_verdict(results, elapsed)

    all_passed = all(r.passed for r in results)

    if quiet:
        detected = sum(1 for r in results if r.passed)
        total_events = sum(len(r.events) for r in results)
        print(
            f"{detected}/{len(results)} stages detected, "
            f"{total_events} events, {elapsed:.3f}s"
        )

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
