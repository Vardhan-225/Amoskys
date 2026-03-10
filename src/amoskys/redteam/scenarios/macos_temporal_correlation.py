"""macOS Temporal Correlation Red-Team Scenarios.

6 scenarios covering all 6 temporal correlation probes. Each scenario tests
timestamp-driven detection patterns that close the 11 evasion gaps missed
by snapshot-based correlation.

Scenarios:
    1. macos_corr_temporal_drop_execute — file drop → execute → connect timing
    2. macos_corr_temporal_persistence_activation — install → activate timing
    3. macos_corr_temporal_kill_chain — ordered tactic progression
    4. macos_corr_temporal_auth_velocity — burst + acceleration + velocity
    5. macos_corr_temporal_beaconing — periodic C2 callback detection
    6. macos_corr_temporal_exfil_acceleration — rate spike + acceleration

Each scenario has >=3 positive, >=1 evasion, >=1 benign cases.
"""

from __future__ import annotations

import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from amoskys.agents.common.probes import Severity
from amoskys.agents.os.macos.auth.collector import AuthEvent
from amoskys.agents.os.macos.correlation.rolling_window import RollingWindowAggregator
from amoskys.agents.os.macos.correlation.temporal_probes import (
    AuthVelocityProbe,
    BeaconingProbe,
    DropExecuteTimingProbe,
    ExfilAccelerationProbe,
    KillChainSequenceProbe,
    PersistenceActivationTimingProbe,
)
from amoskys.agents.os.macos.filesystem.collector import FileEntry
from amoskys.agents.os.macos.network.collector import Connection, ProcessBandwidth
from amoskys.agents.os.macos.persistence.collector import PersistenceEntry
from amoskys.agents.os.macos.process.collector import ProcessSnapshot
from amoskys.redteam.harness import AdversarialCase, Scenario
from amoskys.redteam.scenarios import register

# ─── Timestamp anchors ──────────────────────────────────────────────────────

_T0 = int(1_700_000_000 * 1e9)
_NOW = datetime(2024, 11, 15, 2, 30, 0, tzinfo=timezone.utc)
_COLLECTION_TS = 1_700_000_060.0  # 60 seconds after base epoch


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


def _file(
    path: str = "/tmp/test.txt",
    name: str = "test.txt",
    sha256: str = "deadbeef" * 8,
    mtime: float = 1700000000.0,
    size: int = 1024,
    mode: int = 0o100644,
    uid: int = 501,
    is_suid: bool = False,
) -> FileEntry:
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


def _auth(
    timestamp: Optional[datetime] = None,
    process: str = "sudo",
    message: str = "testuser : COMMAND=/bin/ls",
    category: str = "sudo",
    source_ip: Optional[str] = None,
    username: Optional[str] = "testuser",
    event_type: str = "success",
) -> AuthEvent:
    return AuthEvent(
        timestamp=timestamp or _NOW,
        process=process,
        message=message,
        category=category,
        source_ip=source_ip,
        username=username,
        event_type=event_type,
    )


def _bw(
    pid: int = 2000,
    process_name: str = "curl",
    bytes_in: int = 0,
    bytes_out: int = 0,
) -> ProcessBandwidth:
    return ProcessBandwidth(
        pid=pid,
        process_name=process_name,
        bytes_in=bytes_in,
        bytes_out=bytes_out,
    )


def _pid_connections(
    processes: List[ProcessSnapshot], connections: List[Connection]
) -> Dict[int, List[Connection]]:
    result: Dict[int, List[Connection]] = defaultdict(list)
    for c in connections:
        result[c.pid].append(c)
    return dict(result)


def _rolling_with_timed(*entries: tuple) -> RollingWindowAggregator:
    """Build a rolling window with explicit timestamps.

    Each entry is (key, value, timestamp_offset) where offset is seconds
    relative to a base time of now - 200s (so entries are within the 300s window).
    """
    r = RollingWindowAggregator(window_seconds=300.0)
    base = time.time() - 200.0
    for item in entries:
        if len(item) == 3:
            key, value, offset = item
            r.add(key, value, base + offset)
        else:
            key, value = item
            r.add(key, value, base)
    return r


# =============================================================================
# 1. DropExecuteTimingProbe — file drop → execute → connect timing
# =============================================================================

register(
    Scenario(
        probe_id="macos_corr_temporal_drop_execute",
        agent="macos_correlation",
        name="macos_corr_temporal_drop_execute",
        title="Temporal: file dropped, executed, and connected within seconds",
        description=(
            "Tests timestamp-based detection of the drop→execute→connect chain. "
            "Scores by temporal proximity between file.mtime and proc.create_time."
        ),
        mitre_techniques=["T1204", "T1059"],
        mitre_tactics=["initial-access", "execution"],
        probe_factory=DropExecuteTimingProbe,
        cases=[
            # ── Positive: tight chain (< 5s) ──
            AdversarialCase(
                id="tde_tight_chain_curl",
                title="curl dropped to /tmp and executed within 3 seconds",
                category="positive",
                description="File mtime and process create_time are 3 seconds apart",
                why="Tight temporal chain proves causation, not coincidence",
                events=[
                    _file(
                        path="/tmp/payload",
                        name="payload",
                        mtime=_COLLECTION_TS - 5.0,
                        size=50000,
                    ),
                ],
                shared_data_key="files",
                expect_count=1,
                expect_event_types=["temporal_drop_execute"],
                expect_severity=Severity.CRITICAL,
                extra_context={
                    "processes": [
                        _proc(
                            pid=5001,
                            name="payload",
                            exe="/tmp/payload",
                            create_time=_COLLECTION_TS - 2.0,
                        ),
                    ],
                    "pid_connections": {
                        5001: [
                            _conn(
                                pid=5001,
                                process_name="payload",
                                state="ESTABLISHED",
                                remote_ip="45.33.32.156",
                                remote_port=443,
                            )
                        ],
                    },
                    "collection_ts": _COLLECTION_TS,
                },
            ),
            # ── Positive: medium chain (< 30s) ──
            AdversarialCase(
                id="tde_medium_chain_nc",
                title="nc dropped to /var/tmp and executed within 20 seconds",
                category="positive",
                description="File mtime and process create_time are 20 seconds apart",
                why="20-second gap still indicates drop-and-execute pattern",
                events=[
                    _file(
                        path="/var/tmp/backdoor",
                        name="backdoor",
                        mtime=_COLLECTION_TS - 30.0,
                        size=8192,
                    ),
                ],
                shared_data_key="files",
                expect_count=1,
                expect_event_types=["temporal_drop_execute"],
                expect_severity=Severity.HIGH,
                extra_context={
                    "processes": [
                        _proc(
                            pid=5002,
                            name="backdoor",
                            exe="/var/tmp/backdoor",
                            create_time=_COLLECTION_TS - 10.0,
                        ),
                    ],
                    "pid_connections": {},
                    "collection_ts": _COLLECTION_TS,
                },
            ),
            # ── Positive: wide chain (< 120s) with outbound ──
            AdversarialCase(
                id="tde_wide_chain_with_outbound",
                title="Binary dropped 90s ago, running, and calling home",
                category="positive",
                description="File 90 seconds old, process running, has external connections",
                why="Even a 90-second gap with outbound connections is suspicious",
                events=[
                    _file(
                        path="/private/tmp/agent",
                        name="agent",
                        mtime=_COLLECTION_TS - 100.0,
                        size=65536,
                    ),
                ],
                shared_data_key="files",
                expect_count=1,
                expect_event_types=["temporal_drop_execute"],
                extra_context={
                    "processes": [
                        _proc(
                            pid=5003,
                            name="agent",
                            exe="/private/tmp/agent",
                            create_time=_COLLECTION_TS - 10.0,
                        ),
                    ],
                    "pid_connections": {
                        5003: [
                            _conn(
                                pid=5003,
                                process_name="agent",
                                state="ESTABLISHED",
                                remote_ip="198.51.100.1",
                                remote_port=8443,
                            )
                        ],
                    },
                    "collection_ts": _COLLECTION_TS,
                },
            ),
            # ── Benign: file too old ──
            AdversarialCase(
                id="tde_old_file_benign",
                title="Binary in /tmp but mtime was 5 minutes ago",
                category="benign",
                description="File mtime is far older than collection_ts window",
                why="Old files are not part of a recent drop-execute chain",
                events=[
                    _file(
                        path="/tmp/old_tool",
                        name="old_tool",
                        mtime=_COLLECTION_TS - 600.0,
                        size=8192,
                    ),
                ],
                shared_data_key="files",
                expect_count=0,
                expect_evades=True,
                extra_context={
                    "processes": [
                        _proc(
                            pid=5010,
                            name="old_tool",
                            exe="/tmp/old_tool",
                            create_time=_COLLECTION_TS - 500.0,
                        ),
                    ],
                    "pid_connections": {},
                    "collection_ts": _COLLECTION_TS,
                },
            ),
            # ── Benign: file in non-watched directory ──
            AdversarialCase(
                id="tde_safe_directory",
                title="Binary in /usr/local/bin (not a drop directory)",
                category="benign",
                description="File is not in any watched drop directory",
                why="Files in standard system paths are not flagged as drops",
                events=[
                    _file(
                        path="/usr/local/bin/mytool",
                        name="mytool",
                        mtime=_COLLECTION_TS - 5.0,
                        size=8192,
                    ),
                ],
                shared_data_key="files",
                expect_count=0,
                expect_evades=True,
                extra_context={
                    "processes": [
                        _proc(
                            pid=5011,
                            name="mytool",
                            exe="/usr/local/bin/mytool",
                            create_time=_COLLECTION_TS - 2.0,
                        ),
                    ],
                    "pid_connections": {},
                    "collection_ts": _COLLECTION_TS,
                },
            ),
            # ── Evasion: drop and execute with huge time gap ──
            AdversarialCase(
                id="tde_delayed_execution",
                title="File dropped but executed 3 minutes later (outside window)",
                category="evasion",
                description="Attacker waits 180s between drop and execution",
                why="Delta > 120s evades the temporal proximity check",
                events=[
                    _file(
                        path="/tmp/sleeper",
                        name="sleeper",
                        mtime=_COLLECTION_TS - 200.0,
                        size=8192,
                    ),
                ],
                shared_data_key="files",
                expect_count=0,
                expect_evades=True,
                extra_context={
                    "processes": [
                        _proc(
                            pid=5012,
                            name="sleeper",
                            exe="/tmp/sleeper",
                            create_time=_COLLECTION_TS - 10.0,
                        ),
                    ],
                    "pid_connections": {},
                    "collection_ts": _COLLECTION_TS,
                },
            ),
        ],
    )
)


# =============================================================================
# 2. PersistenceActivationTimingProbe — install → activate timing
# =============================================================================


def _persistence_activation_factory() -> PersistenceActivationTimingProbe:
    """Factory that returns a probe pre-warmed with baseline."""
    probe = PersistenceActivationTimingProbe()
    # Warm up with baseline — first run learns known programs
    from amoskys.agents.common.probes import ProbeContext

    baseline_ctx = ProbeContext(
        device_id="victim-host",
        agent_name=probe.name,
        now_ns=_T0,
        shared_data={
            "entries": [
                _pentry(
                    program="/usr/sbin/sshd",
                    label="com.openssh.sshd",
                    path="/System/Library/LaunchDaemons/ssh.plist",
                ),
            ],
            "processes": [
                _proc(
                    pid=100,
                    name="sshd",
                    exe="/usr/sbin/sshd",
                    create_time=1700000000.0 - 86400,
                ),
            ],
            "collection_ts": _COLLECTION_TS - 15.0,
        },
    )
    probe.scan(baseline_ctx)
    return probe


register(
    Scenario(
        probe_id="macos_corr_temporal_persistence_activation",
        agent="macos_correlation",
        name="macos_corr_temporal_persistence_activation",
        title="Temporal: persistence mechanism activated since last scan",
        description=(
            "Tests detection of recently-activated persistence mechanisms by "
            "comparing process create_time with scan interval."
        ),
        mitre_techniques=["T1543", "T1547"],
        mitre_tactics=["persistence", "execution"],
        probe_factory=_persistence_activation_factory,
        cases=[
            # ── Positive: new persistence program just started ──
            AdversarialCase(
                id="tpa_new_agent_just_started",
                title="New LaunchAgent program started 5 seconds ago",
                category="positive",
                description="Persistence entry is new AND program create_time is recent",
                why="New persistence + recent activation = confirmed malware activation",
                events=[
                    _pentry(
                        program="/tmp/malware",
                        label="com.evil.agent",
                        path="/Library/LaunchAgents/com.evil.agent.plist",
                    ),
                ],
                shared_data_key="entries",
                expect_count=1,
                expect_event_types=["temporal_persistence_activation"],
                expect_severity=Severity.CRITICAL,
                extra_context={
                    "processes": [
                        _proc(
                            pid=7001,
                            name="malware",
                            exe="/tmp/malware",
                            create_time=_COLLECTION_TS - 5.0,
                        ),
                    ],
                    "collection_ts": _COLLECTION_TS,
                },
            ),
            # ── Positive: known program restarted ──
            AdversarialCase(
                id="tpa_known_program_restarted",
                title="Known sshd restarted (create_time within scan interval)",
                category="positive",
                description="Already-known persistence program was restarted recently",
                why="Even known programs restarting within a scan interval is notable",
                events=[
                    _pentry(
                        program="/usr/sbin/sshd",
                        label="com.openssh.sshd",
                        path="/System/Library/LaunchDaemons/ssh.plist",
                    ),
                ],
                shared_data_key="entries",
                expect_count=1,
                expect_event_types=["temporal_persistence_activation"],
                expect_severity=Severity.HIGH,
                extra_context={
                    "processes": [
                        _proc(
                            pid=7002,
                            name="sshd",
                            exe="/usr/sbin/sshd",
                            create_time=_COLLECTION_TS - 3.0,
                        ),
                    ],
                    "collection_ts": _COLLECTION_TS,
                },
            ),
            # ── Positive: daemon with keep_alive just activated ──
            AdversarialCase(
                id="tpa_keepalive_daemon_activated",
                title="LaunchDaemon with KeepAlive activated 10s ago",
                category="positive",
                description="Persistence daemon activated very recently",
                why="KeepAlive daemon recently started = potential persistence activation",
                events=[
                    _pentry(
                        program="/usr/local/bin/backdoor",
                        label="com.backdoor.daemon",
                        path="/Library/LaunchDaemons/com.backdoor.daemon.plist",
                        keep_alive=True,
                        category="launchdaemon",
                    ),
                ],
                shared_data_key="entries",
                expect_count=1,
                expect_event_types=["temporal_persistence_activation"],
                extra_context={
                    "processes": [
                        _proc(
                            pid=7003,
                            name="backdoor",
                            exe="/usr/local/bin/backdoor",
                            create_time=_COLLECTION_TS - 10.0,
                        ),
                    ],
                    "collection_ts": _COLLECTION_TS,
                },
            ),
            # ── Benign: old process, long-running ──
            AdversarialCase(
                id="tpa_old_process_benign",
                title="sshd running for hours (create_time far in past)",
                category="benign",
                description="Process create_time is hours before collection",
                why="Long-running processes were not recently activated",
                events=[
                    _pentry(
                        program="/usr/sbin/sshd",
                        label="com.openssh.sshd",
                        path="/System/Library/LaunchDaemons/ssh.plist",
                    ),
                ],
                shared_data_key="entries",
                expect_count=0,
                expect_evades=True,
                extra_context={
                    "processes": [
                        _proc(
                            pid=7010,
                            name="sshd",
                            exe="/usr/sbin/sshd",
                            create_time=_COLLECTION_TS - 86400,
                        ),
                    ],
                    "collection_ts": _COLLECTION_TS,
                },
            ),
            # ── Benign: persistence entry but program not running ──
            AdversarialCase(
                id="tpa_not_running",
                title="Persistence entry exists but program is not running",
                category="benign",
                description="Persistence is installed but process is not active",
                why="No running process means no activation to detect",
                events=[
                    _pentry(
                        program="/tmp/dormant",
                        label="com.dormant.agent",
                        path="/Library/LaunchAgents/com.dormant.agent.plist",
                    ),
                ],
                shared_data_key="entries",
                expect_count=0,
                expect_evades=True,
                extra_context={
                    "processes": [],
                    "collection_ts": _COLLECTION_TS,
                },
            ),
            # ── Evasion: delayed activation ──
            AdversarialCase(
                id="tpa_delayed_activation",
                title="Persistence activated 5 minutes after install (outside window)",
                category="evasion",
                description="Process started long enough ago to be outside scan interval",
                why="If create_time is far before scan interval, it looks long-running",
                events=[
                    _pentry(
                        program="/tmp/delayed_mal",
                        label="com.delayed.agent",
                        path="/Library/LaunchAgents/com.delayed.plist",
                    ),
                ],
                shared_data_key="entries",
                expect_count=0,
                expect_evades=True,
                extra_context={
                    "processes": [
                        _proc(
                            pid=7012,
                            name="delayed_mal",
                            exe="/tmp/delayed_mal",
                            create_time=_COLLECTION_TS - 300.0,
                        ),
                    ],
                    "collection_ts": _COLLECTION_TS,
                },
            ),
        ],
    )
)


# =============================================================================
# 3. KillChainSequenceProbe — ordered tactic progression
# =============================================================================


def _kill_chain_sequence_factory() -> KillChainSequenceProbe:
    """Factory that pre-seeds the timeline with initial-access and execution."""
    probe = KillChainSequenceProbe()
    from amoskys.agents.common.probes import ProbeContext

    # Scan 1: initial-access (file in /tmp)
    ctx1 = ProbeContext(
        device_id="victim-host",
        agent_name=probe.name,
        now_ns=_T0,
        shared_data={
            "files": [
                _file(path="/tmp/dropper", name="dropper", mtime=_COLLECTION_TS - 600)
            ],
            "processes": [],
            "connections": [],
            "entries": [],
            "auth_events": [],
            "bandwidth": [],
            "collection_ts": _COLLECTION_TS - 600,
        },
    )
    probe.scan(ctx1)

    # Scan 2: execution (LOLBin running)
    ctx2 = ProbeContext(
        device_id="victim-host",
        agent_name=probe.name,
        now_ns=_T0,
        shared_data={
            "files": [],
            "processes": [_proc(pid=8001, name="curl", exe="/usr/bin/curl")],
            "connections": [],
            "entries": [],
            "auth_events": [],
            "bandwidth": [],
            "collection_ts": _COLLECTION_TS - 300,
        },
    )
    probe.scan(ctx2)

    return probe


register(
    Scenario(
        probe_id="macos_corr_temporal_kill_chain",
        agent="macos_correlation",
        name="macos_corr_temporal_kill_chain",
        title="Temporal: ordered tactic progression over time",
        description=(
            "Tests detection of kill chain sequences where tactics appear "
            "in chronological order across multiple scans."
        ),
        mitre_techniques=["T1059", "T1071", "T1543", "T1078", "T1048"],
        mitre_tactics=[
            "initial-access",
            "execution",
            "persistence",
            "credential-access",
            "lateral-movement",
            "exfiltration",
            "command-and-control",
        ],
        probe_factory=_kill_chain_sequence_factory,
        cases=[
            # ── Positive: 3rd tactic arrives → fires ──
            AdversarialCase(
                id="tkc_third_tactic_persistence",
                title="Persistence added (3rd tactic after initial-access + execution)",
                category="positive",
                description="Timeline has initial-access → execution → now persistence",
                why="3 ordered tactics in 30-minute window = kill chain progression",
                events=[
                    _pentry(
                        program="/tmp/malware",
                        label="com.evil",
                        path="/Library/LaunchAgents/com.evil.plist",
                        run_at_load=True,
                    ),
                ],
                shared_data_key="entries",
                stateful=True,
                expect_count=1,
                expect_event_types=["temporal_kill_chain_sequence"],
                expect_severity=Severity.HIGH,
                extra_context={
                    "files": [],
                    "processes": [],
                    "connections": [],
                    "auth_events": [],
                    "bandwidth": [],
                    "collection_ts": _COLLECTION_TS,
                },
            ),
            # ── Positive: 4th tactic → CRITICAL ──
            AdversarialCase(
                id="tkc_fourth_tactic_c2",
                title="C2 activity (4th tactic) → CRITICAL",
                category="positive",
                description="Command-and-control detected as 4th tactic",
                why="4+ ordered tactics escalates to CRITICAL",
                events=[],
                shared_data_key="entries",
                stateful=True,
                expect_count=1,
                expect_event_types=["temporal_kill_chain_sequence"],
                expect_severity=Severity.CRITICAL,
                extra_context={
                    "files": [],
                    "processes": [],
                    "connections": [
                        _conn(
                            pid=9001,
                            process_name="agent",
                            state="ESTABLISHED",
                            remote_ip="45.33.32.1",
                            remote_port=443,
                        ),
                        _conn(
                            pid=9001,
                            process_name="agent",
                            state="ESTABLISHED",
                            remote_ip="45.33.32.2",
                            remote_port=443,
                        ),
                        _conn(
                            pid=9001,
                            process_name="agent",
                            state="ESTABLISHED",
                            remote_ip="45.33.32.3",
                            remote_port=443,
                        ),
                    ],
                    "entries": [
                        _pentry(
                            program="/tmp/malware",
                            label="com.evil",
                            path="/Library/LaunchAgents/com.evil.plist",
                            run_at_load=True,
                        ),
                    ],
                    "auth_events": [],
                    "bandwidth": [],
                    "collection_ts": _COLLECTION_TS + 60,
                },
            ),
            # ── Positive: 5th tactic — exfiltration ──
            AdversarialCase(
                id="tkc_fifth_tactic_exfil",
                title="Exfiltration (5th tactic) completes full kill chain",
                category="positive",
                description="Exfiltration detected as 5th tactic in sequence",
                why="Full kill chain with 5 ordered tactics = confirmed APT",
                events=[],
                shared_data_key="entries",
                stateful=True,
                expect_count=1,
                expect_event_types=["temporal_kill_chain_sequence"],
                expect_severity=Severity.CRITICAL,
                extra_context={
                    "files": [],
                    "processes": [],
                    "connections": [
                        _conn(
                            pid=9001,
                            process_name="agent",
                            state="ESTABLISHED",
                            remote_ip="45.33.32.1",
                            remote_port=443,
                        ),
                        _conn(
                            pid=9001,
                            process_name="agent",
                            state="ESTABLISHED",
                            remote_ip="45.33.32.2",
                            remote_port=443,
                        ),
                        _conn(
                            pid=9001,
                            process_name="agent",
                            state="ESTABLISHED",
                            remote_ip="45.33.32.3",
                            remote_port=443,
                        ),
                    ],
                    "entries": [
                        _pentry(
                            program="/tmp/malware",
                            label="com.evil",
                            path="/Library/LaunchAgents/com.evil.plist",
                            run_at_load=True,
                        ),
                    ],
                    "auth_events": [],
                    "bandwidth": [
                        _bw(pid=9001, process_name="agent", bytes_out=50_000_000)
                    ],
                    "collection_ts": _COLLECTION_TS + 120,
                },
            ),
            # ── Benign: only 1 tactic (fresh probe) ──
            AdversarialCase(
                id="tkc_single_tactic_benign",
                title="Only execution detected (1 tactic = no chain)",
                category="benign",
                description="LOLBin running but no other tactics in timeline",
                why="A single tactic doesn't constitute a kill chain",
                events=[],
                shared_data_key="entries",
                stateful=False,
                expect_count=0,
                expect_evades=True,
                extra_context={
                    "files": [],
                    "processes": [_proc(pid=8100, name="curl", exe="/usr/bin/curl")],
                    "connections": [],
                    "entries": [],
                    "auth_events": [],
                    "bandwidth": [],
                    "collection_ts": _COLLECTION_TS,
                },
            ),
            # ── Evasion: tactics out of order ──
            AdversarialCase(
                id="tkc_out_of_order_evasion",
                title="Tactics appear in reverse order (exfil before execution)",
                category="evasion",
                description="Attacker front-loads exfiltration before establishing persistence",
                why="Reverse-order tactics don't match kill chain progression",
                events=[],
                shared_data_key="entries",
                stateful=False,
                expect_count=0,
                expect_evades=True,
                extra_context={
                    "files": [],
                    "processes": [],
                    "connections": [],
                    "entries": [],
                    "auth_events": [],
                    "bandwidth": [],
                    "collection_ts": _COLLECTION_TS,
                },
            ),
        ],
    )
)


# =============================================================================
# 4. AuthVelocityProbe — burst + acceleration + velocity
# =============================================================================

register(
    Scenario(
        probe_id="macos_corr_temporal_auth_velocity",
        agent="macos_correlation",
        name="macos_corr_temporal_auth_velocity",
        title="Temporal: auth failure burst, acceleration, and velocity",
        description=(
            "Tests burst detection (>10 failures in 10s), acceleration "
            "(failure rate increasing), and velocity (sustained high rate)."
        ),
        mitre_techniques=["T1110"],
        mitre_tactics=["credential-access"],
        probe_factory=AuthVelocityProbe,
        cases=[
            # ── Positive: burst — 15 failures in 5 seconds ──
            AdversarialCase(
                id="tav_burst_hydra",
                title="Hydra burst: 15 SSH failures in 5 seconds",
                category="positive",
                description="Automated tool firing rapid auth attempts",
                why="burst_score > 1.0 (15 events in 10s window = 1.5/sec)",
                events=[],
                shared_data_key="auth_events",
                expect_count=1,
                expect_event_types=["temporal_auth_burst"],
                expect_severity=Severity.CRITICAL,
                extra_context={
                    "rolling": _rolling_with_timed(
                        *[("ssh_fail:10.0.0.50", 1.0, i * 0.33) for i in range(15)]
                    ),
                },
            ),
            # ── Positive: velocity — sustained 0.6/sec ──
            AdversarialCase(
                id="tav_velocity_sustained",
                title="Sustained SSH failures at 0.6/sec for 60 seconds",
                category="positive",
                description="Slower but sustained brute force attack",
                why="rate() > 0.5 = sustained brute force velocity",
                events=[],
                shared_data_key="auth_events",
                expect_count=1,
                expect_event_types=["temporal_auth_velocity"],
                expect_severity=Severity.HIGH,
                extra_context={
                    "rolling": _rolling_with_timed(
                        *[("ssh_fail:10.0.0.51", 1.0, i * 1.67) for i in range(36)]
                    ),
                },
            ),
            # ── Positive: acceleration — failure rate doubling ──
            AdversarialCase(
                id="tav_acceleration_escalating",
                title="Auth failures accelerating: 1/min → 5/min → 15/min",
                category="positive",
                description="Attacker escalating brute force speed",
                why="acceleration > 0.5 = rate is increasing rapidly",
                events=[],
                shared_data_key="auth_events",
                expect_count=1,
                expect_event_types=["temporal_auth_acceleration"],
                expect_severity=Severity.HIGH,
                extra_context={
                    "rolling": _rolling_with_timed(
                        # Phase 1: slow (1 every 30s for 60s)
                        ("ssh_fail:10.0.0.52", 1.0, 0),
                        ("ssh_fail:10.0.0.52", 1.0, 30),
                        # Phase 2: medium (1 every 10s for 30s)
                        ("ssh_fail:10.0.0.52", 1.0, 60),
                        ("ssh_fail:10.0.0.52", 1.0, 70),
                        ("ssh_fail:10.0.0.52", 1.0, 80),
                        # Phase 3: fast (1 every 2s for 20s)
                        ("ssh_fail:10.0.0.52", 1.0, 90),
                        ("ssh_fail:10.0.0.52", 1.0, 92),
                        ("ssh_fail:10.0.0.52", 1.0, 94),
                        ("ssh_fail:10.0.0.52", 1.0, 96),
                        ("ssh_fail:10.0.0.52", 1.0, 98),
                        ("ssh_fail:10.0.0.52", 1.0, 100),
                        ("ssh_fail:10.0.0.52", 1.0, 102),
                        ("ssh_fail:10.0.0.52", 1.0, 104),
                        ("ssh_fail:10.0.0.52", 1.0, 106),
                        ("ssh_fail:10.0.0.52", 1.0, 108),
                    ),
                },
            ),
            # ── Benign: 2 failures, well spaced ──
            AdversarialCase(
                id="tav_low_rate_benign",
                title="2 SSH failures in 5 minutes (normal mistype)",
                category="benign",
                description="Two failures spaced far apart = user error",
                why="rate < 0.5, burst_score < 1.0, acceleration ≈ 0",
                events=[],
                shared_data_key="auth_events",
                expect_count=0,
                expect_evades=True,
                extra_context={
                    "rolling": _rolling_with_timed(
                        ("ssh_fail:10.0.0.60", 1.0, 0),
                        ("ssh_fail:10.0.0.60", 1.0, 120),
                    ),
                },
            ),
            # ── Evasion: just below burst threshold ──
            AdversarialCase(
                id="tav_slow_spray_evasion",
                title="9 failures evenly spaced over 100s (below all thresholds)",
                category="evasion",
                description="Attacker spaces failures to stay below burst and velocity",
                why="rate ≈ 0.09, burst < 1.0 — careful spacing evades detection",
                events=[],
                shared_data_key="auth_events",
                expect_count=0,
                expect_evades=True,
                extra_context={
                    "rolling": _rolling_with_timed(
                        *[("ssh_fail:10.0.0.61", 1.0, i * 11) for i in range(9)]
                    ),
                },
            ),
        ],
    )
)


def _build_slow_beacon_rolling() -> RollingWindowAggregator:
    """Build a rolling window with a longer window to fit a ~500s period beacon."""
    r = RollingWindowAggregator(window_seconds=2000.0)
    base = time.time() - 1800.0
    for i in range(5):
        r.add("beacon:198.51.100.10:443", 1.0, base + i * 500)
    return r


# =============================================================================
# 5. BeaconingProbe — periodic C2 callback detection
# =============================================================================

register(
    Scenario(
        probe_id="macos_corr_temporal_beaconing",
        agent="macos_correlation",
        name="macos_corr_temporal_beaconing",
        title="Temporal: periodic C2 beaconing via connection timing",
        description=(
            "Tests detection of periodic callback patterns using jitter_score "
            "and dominant_period from the rolling window."
        ),
        mitre_techniques=["T1071"],
        mitre_tactics=["command-and-control"],
        probe_factory=BeaconingProbe,
        cases=[
            # ── Positive: fast beacon, low jitter (60s interval) ──
            AdversarialCase(
                id="tb_fast_beacon_60s",
                title="C2 beacon every 60 seconds (perfect periodicity)",
                category="positive",
                description="Connection to same IP every 60s = classic beacon",
                why="jitter_score > 0.7 + period 60s = CRITICAL fast beacon",
                events=[],
                shared_data_key="connections",
                expect_count=1,
                expect_event_types=["temporal_beaconing"],
                expect_severity=Severity.CRITICAL,
                extra_context={
                    "rolling": _rolling_with_timed(
                        *[("beacon:45.33.32.100:443", 1.0, i * 60) for i in range(5)]
                    ),
                },
            ),
            # ── Positive: slow beacon (500s interval) with longer window ──
            AdversarialCase(
                id="tb_slow_beacon_500s",
                title="Slow C2 beacon every ~500 seconds",
                category="positive",
                description="Connection every 500 seconds to same destination",
                why="Period 500s in slow-beacon range (300-3600), jitter > 0.7 = HIGH",
                events=[],
                shared_data_key="connections",
                expect_count=1,
                expect_event_types=["temporal_beaconing"],
                extra_context={
                    "rolling": _build_slow_beacon_rolling(),
                },
            ),
            # ── Positive: jittered beacon (±5s around 60s) ──
            AdversarialCase(
                id="tb_jittered_beacon_60s",
                title="Jittered C2 beacon: 60s ± 5s intervals",
                category="positive",
                description="Slightly jittered but still periodic callback",
                why="jitter_score still > 0.6 with small ±5s jitter around 60s period",
                events=[],
                shared_data_key="connections",
                expect_count=1,
                expect_event_types=["temporal_beaconing"],
                extra_context={
                    "rolling": _rolling_with_timed(
                        ("beacon:198.51.100.5:8443", 1.0, 0),
                        ("beacon:198.51.100.5:8443", 1.0, 58),
                        ("beacon:198.51.100.5:8443", 1.0, 121),
                        ("beacon:198.51.100.5:8443", 1.0, 183),
                    ),
                },
            ),
            # ── Benign: CDN IP (Apple infrastructure) ──
            AdversarialCase(
                id="tb_cdn_apple_benign",
                title="Periodic connections to Apple CDN (17.253.x.x)",
                category="benign",
                description="Apple push notifications are periodic but benign",
                why="CDN IPs are filtered out to prevent false positives",
                events=[],
                shared_data_key="connections",
                expect_count=0,
                expect_evades=True,
                extra_context={
                    "rolling": _rolling_with_timed(
                        *[("beacon:17.253.1.1:443", 1.0, i * 60) for i in range(5)]
                    ),
                },
            ),
            # ── Benign: random connection times ──
            AdversarialCase(
                id="tb_random_timing_benign",
                title="Connections at random intervals (no periodicity)",
                category="benign",
                description="Human browsing patterns are not periodic",
                why="jitter_score < 0.6 with highly variable intervals",
                events=[],
                shared_data_key="connections",
                expect_count=0,
                expect_evades=True,
                extra_context={
                    "rolling": _rolling_with_timed(
                        ("beacon:203.0.113.1:443", 1.0, 0),
                        ("beacon:203.0.113.1:443", 1.0, 5),
                        ("beacon:203.0.113.1:443", 1.0, 80),
                        ("beacon:203.0.113.1:443", 1.0, 82),
                        ("beacon:203.0.113.1:443", 1.0, 190),
                    ),
                },
            ),
            # ── Evasion: high jitter C2 (±50% randomization) ──
            AdversarialCase(
                id="tb_high_jitter_evasion",
                title="C2 with 50% jitter randomization",
                category="evasion",
                description="Beacon interval randomized by ±50% destroys periodicity",
                why="jitter_score < 0.6 when intervals vary by 50%+",
                events=[],
                shared_data_key="connections",
                expect_count=0,
                expect_evades=True,
                extra_context={
                    "rolling": _rolling_with_timed(
                        ("beacon:203.0.113.50:443", 1.0, 0),
                        ("beacon:203.0.113.50:443", 1.0, 30),
                        ("beacon:203.0.113.50:443", 1.0, 100),
                        ("beacon:203.0.113.50:443", 1.0, 120),
                        ("beacon:203.0.113.50:443", 1.0, 195),
                    ),
                },
            ),
        ],
    )
)


# =============================================================================
# 6. ExfilAccelerationProbe — rate spike + acceleration
# =============================================================================

register(
    Scenario(
        probe_id="macos_corr_temporal_exfil_acceleration",
        agent="macos_correlation",
        name="macos_corr_temporal_exfil_acceleration",
        title="Temporal: exfiltration rate spike and acceleration",
        description=(
            "Tests rate-based exfiltration detection that catches attacks "
            "spreading data across window boundaries."
        ),
        mitre_techniques=["T1048"],
        mitre_tactics=["exfiltration"],
        probe_factory=ExfilAccelerationProbe,
        cases=[
            # ── Positive: rate spike — 1MB/sec sustained ──
            AdversarialCase(
                id="tea_rate_spike_1mbps",
                title="curl sustaining 1MB/sec outbound for 60 seconds",
                category="positive",
                description="Sustained high-rate exfiltration via curl",
                why="rate > 500KB/sec from non-browser process = exfil spike",
                events=[],
                shared_data_key="bandwidth",
                expect_count=1,
                expect_event_types=["temporal_exfil_rate_spike"],
                expect_severity=Severity.HIGH,
                extra_context={
                    "rolling": _rolling_with_timed(
                        *[("bytes_out:curl", 1_000_000, i * 1) for i in range(60)]
                    ),
                },
            ),
            # ── Positive: acceleration — rate doubling ──
            AdversarialCase(
                id="tea_acceleration_doubling",
                title="Exfil rate accelerating: 100KB/s → 500KB/s → 2MB/s",
                category="positive",
                description="Outbound rate increasing over time",
                why="acceleration > 100KB/sec/min = escalating exfiltration",
                events=[],
                shared_data_key="bandwidth",
                expect_count=1,
                expect_event_types=["temporal_exfil_acceleration"],
                expect_severity=Severity.HIGH,
                extra_context={
                    "rolling": _rolling_with_timed(
                        # Phase 1: slow
                        ("bytes_out:rsync", 100_000, 0),
                        ("bytes_out:rsync", 100_000, 10),
                        # Phase 2: medium
                        ("bytes_out:rsync", 500_000, 30),
                        ("bytes_out:rsync", 500_000, 40),
                        ("bytes_out:rsync", 500_000, 50),
                        # Phase 3: fast
                        ("bytes_out:rsync", 2_000_000, 60),
                        ("bytes_out:rsync", 2_000_000, 65),
                        ("bytes_out:rsync", 2_000_000, 70),
                        ("bytes_out:rsync", 2_000_000, 75),
                        ("bytes_out:rsync", 2_000_000, 80),
                    ),
                },
            ),
            # ── Positive: nc exfiltration at 600KB/sec ──
            AdversarialCase(
                id="tea_nc_sustained_exfil",
                title="nc piping data outbound at 600KB/sec",
                category="positive",
                description="nc is sending data at sustained high rate",
                why="nc at > 500KB/sec is almost certainly exfiltration",
                events=[],
                shared_data_key="bandwidth",
                expect_count=1,
                expect_event_types=["temporal_exfil_rate_spike"],
                extra_context={
                    "rolling": _rolling_with_timed(
                        *[("bytes_out:nc", 600_000, i * 1) for i in range(30)]
                    ),
                },
            ),
            # ── Benign: Safari browsing (whitelisted) ──
            AdversarialCase(
                id="tea_safari_browsing_benign",
                title="Safari uploading at 2MB/sec (whitelisted browser)",
                category="benign",
                description="High bandwidth from a known browser is normal",
                why="Safari is in _KNOWN_HIGH_BANDWIDTH, so it's filtered",
                events=[],
                shared_data_key="bandwidth",
                expect_count=0,
                expect_evades=True,
                extra_context={
                    "rolling": _rolling_with_timed(
                        *[("bytes_out:safari", 2_000_000, i * 1) for i in range(60)]
                    ),
                },
            ),
            # ── Benign: low rate ──
            AdversarialCase(
                id="tea_low_rate_benign",
                title="curl at 10KB/sec (normal API calls)",
                category="benign",
                description="Low outbound rate is normal background traffic",
                why="rate < 500KB/sec = within normal range",
                events=[],
                shared_data_key="bandwidth",
                expect_count=0,
                expect_evades=True,
                extra_context={
                    "rolling": _rolling_with_timed(
                        *[("bytes_out:curl", 10_000, i * 1) for i in range(60)]
                    ),
                },
            ),
            # ── Evasion: trickle exfil below rate threshold ──
            AdversarialCase(
                id="tea_trickle_evasion",
                title="Exfil at 400KB/sec (just below 500KB threshold)",
                category="evasion",
                description="Attacker throttles to stay below rate threshold",
                why="Rate < 500KB/sec evades rate spike detection",
                events=[],
                shared_data_key="bandwidth",
                expect_count=0,
                expect_evades=True,
                extra_context={
                    "rolling": _rolling_with_timed(
                        *[("bytes_out:scp", 400_000, i * 1) for i in range(60)]
                    ),
                },
            ),
        ],
    )
)
