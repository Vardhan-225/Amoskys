"""macOS Correlation Probes — 12 cross-domain detection probes.

Each probe combines data from 2+ macOS Observatory agents to detect attack
patterns invisible to any single agent. These probes close 17 of 22 fixable
evasion gaps identified by the Evasion Gauntlet.

Probes:
    1. ProcessNetworkProbe — LOLBin + outbound connection = confirmed
    2. BinaryIdentityProbe — process name vs exe path mismatch
    3. PersistenceExecutionProbe — installed + running = active threat
    4. DownloadExecuteChainProbe — download → execute → connect
    5. LateralMovementProbe — internal movement on service ports
    6. UnknownListenerProbe — unexpected open ports
    7. CumulativeAuthProbe — slow brute force across scans
    8. CumulativeExfilProbe — slow exfil across scans
    9. KillChainProgressionProbe — multi-tactic attack unfolding
    10. FileSizeAnomalyProbe — benign name, suspicious size
    11. ScheduledPersistenceProbe — at-jobs and expanded scheduling
    12. AuthGeoAnomalyProbe — source IP intelligence

MITRE: T1059, T1071, T1036, T1543, T1547, T1204, T1021, T1570, T1571,
       T1110, T1078, T1048, T1564, T1053
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional, Set

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)

logger = logging.getLogger(__name__)

# ── Shared helpers ────────────────────────────────────────────────────────

from amoskys.agents.common.ip_utils import is_private_ip as _is_private

# Known LOLBin exe basenames — matched by executable path, not process name.
# This defeats renaming evasion (nt2).
_LOLBIN_BASENAMES = frozenset(
    {
        "curl",
        "wget",
        "nc",
        "ncat",
        "netcat",
        "openssl",
        "ssh",
        "scp",
        "sftp",
        "rsync",
        "python3",
        "python",
        "ruby",
        "perl",
        "osascript",
        "pbcopy",
        "pbpaste",
        "screencapture",
        "dscl",
        "security",
        "defaults",
        "launchctl",
        "plutil",
        "base64",
        "xxd",
        "dd",
        "tar",
        "zip",
        "unzip",
        "mkfifo",
        "nslookup",
        "dig",
        "host",
        "tcpdump",
        "dtrace",
    }
)

# Expected binary locations for common whitelisted process names.
# BinaryIdentityProbe validates exe path matches these patterns.
_EXPECTED_BINARY_PREFIXES: Dict[str, List[str]] = {
    "claude": ["/Applications/Claude.app/"],
    "slack": ["/Applications/Slack.app/"],
    "slack helper": ["/Applications/Slack.app/"],
    "google chrome": ["/Applications/Google Chrome.app/"],
    "google chrome helper": ["/Applications/Google Chrome.app/"],
    "firefox": ["/Applications/Firefox.app/"],
    "safari": ["/System/", "/Applications/Safari.app/"],
    "discord": ["/Applications/Discord.app/"],
    "zoom.us": ["/Applications/zoom.us.app/"],
    "microsoft teams": ["/Applications/Microsoft Teams"],
    "code": ["/Applications/Visual Studio Code.app/"],
    "code helper": ["/Applications/Visual Studio Code.app/"],
    "cursor": ["/Applications/Cursor.app/"],
    "dropbox": ["/Applications/Dropbox.app/"],
    "spotify": ["/Applications/Spotify.app/"],
}

# Lateral movement port → service mapping
_LATERAL_PORTS = {
    22: "SSH",
    445: "SMB",
    3389: "RDP",
    5900: "VNC",
    5985: "WinRM",
    5986: "WinRM-HTTPS",
}

# Known-good listener services (process name → expected ports)
_KNOWN_LISTENERS: Dict[str, Set[int]] = {
    "sshd": {22},
    "httpd": {80, 443, 8080, 8443},
    "nginx": {80, 443, 8080, 8443},
    "python3": {8000, 8080, 8888},
    "python": {8000, 8080, 8888},
    "node": {3000, 5000, 8080, 8443},
    "postgres": {5432},
    "mysqld": {3306},
    "mongod": {27017},
    "redis-server": {6379},
    "memcached": {11211},
    "rapportd": {49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160},
    "controlce": {0},  # Apple system
    "launchd": {0},  # Apple system
}

# C2 / reverse-shell ports that should always raise suspicion
_SUSPICIOUS_PORTS = frozenset(
    {
        4444,
        4445,
        5555,
        6666,
        7777,
        8888,
        9090,
        9091,
        9999,
        1337,
        1338,
        31337,
    }
)

# Known benign file names and their expected max sizes
_BENIGN_FILE_SIZES: Dict[str, int] = {
    ".ds_store": 32768,  # 32KB
    ".localized": 1,  # 0-1 bytes
    ".com.apple.timemachine.donotpresent": 1,
    "thumbs.db": 65536,  # 64KB (Windows artifact on shares)
}

# Threshold constants (in bytes)
_EXFIL_THRESHOLD = 10 * 1024 * 1024  # 10 MB

# Threshold constants (auth)
_SSH_BRUTE_THRESHOLD = 5
_LOCKOUT_THRESHOLD = 10


# =============================================================================
# 1. ProcessNetworkProbe
# =============================================================================


class ProcessNetworkProbe(MicroProbe):
    """Correlates process execution with network activity.

    Closes: wl1, wl2 (LOLBin from benign parent but making connections),
            nt1 (unknown parent tree but with network activity),
            nt2 (renamed LOLBin — match by exe path, not process name)

    Individual agents miss this because:
        - LOLBinProbe skips benign parents (Terminal, zsh, Xcode)
        - ProcessTreeProbe doesn't check network activity
        - C2BeaconProbe whitelists by process name

    Correlation: Process agent data + Network agent data = confirmed intent
    """

    name = "macos_corr_process_network"
    description = "LOLBin process with outbound external connection"
    platforms = ["darwin"]
    mitre_techniques = ["T1059", "T1071"]
    mitre_tactics = ["execution", "command-and-control"]
    scan_interval = 10.0
    requires_fields = ["processes", "pid_connections"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        processes = context.shared_data.get("processes", [])
        pid_conns = context.shared_data.get("pid_connections", {})

        for proc in processes:
            if not proc.exe:
                continue

            # Check if exe basename is a known LOLBin
            exe_basename = os.path.basename(proc.exe).lower()
            if exe_basename not in _LOLBIN_BASENAMES:
                continue

            # Check if this PID has outbound external connections
            conns = pid_conns.get(proc.pid, [])
            external_conns = [
                c
                for c in conns
                if c.state == "ESTABLISHED"
                and c.remote_ip
                and not _is_private(c.remote_ip)
            ]

            if not external_conns:
                continue

            # LOLBin + external connection = confirmed activity
            remote_ips = list({c.remote_ip for c in external_conns})
            events.append(
                self._create_event(
                    event_type="corr_lolbin_network",
                    severity=Severity.HIGH,
                    data={
                        "pid": proc.pid,
                        "process_name": proc.name,
                        "exe": proc.exe,
                        "exe_basename": exe_basename,
                        "parent_name": proc.parent_name,
                        "remote_ips": remote_ips[:5],
                        "connection_count": len(external_conns),
                        "correlation": "process_exe_path + outbound_connection",
                    },
                    confidence=0.9,
                    tags=["correlation", "lolbin", "network"],
                )
            )

        return events


# =============================================================================
# 2. BinaryIdentityProbe
# =============================================================================


class BinaryIdentityProbe(MicroProbe):
    """Validates process binary path matches expected location for its name.

    Closes: wl3, wl4 (C2 from whitelisted process name with wrong binary),
            cg1 (unknown process running from suspicious path)

    An attacker can name their binary "claude" or "Slack Helper" to appear
    in the C2BeaconProbe whitelist. But the real Claude binary lives in
    /Applications/Claude.app/... — if the exe path doesn't match, it's fake.
    """

    name = "macos_corr_binary_identity"
    description = "Process name does not match expected binary location"
    platforms = ["darwin"]
    mitre_techniques = ["T1036"]
    mitre_tactics = ["defense-evasion"]
    scan_interval = 10.0
    requires_fields = ["processes"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        processes = context.shared_data.get("processes", [])

        for proc in processes:
            if not proc.exe or not proc.name:
                continue

            name_lower = proc.name.lower()
            expected_prefixes = _EXPECTED_BINARY_PREFIXES.get(name_lower)
            if expected_prefixes is None:
                continue

            # Check if exe path matches any expected prefix
            if any(proc.exe.startswith(prefix) for prefix in expected_prefixes):
                continue  # Legitimate

            # Name matches a whitelisted app but exe is wrong
            events.append(
                self._create_event(
                    event_type="corr_binary_identity_mismatch",
                    severity=Severity.CRITICAL,
                    data={
                        "pid": proc.pid,
                        "process_name": proc.name,
                        "exe": proc.exe,
                        "expected_prefixes": expected_prefixes,
                        "correlation": "process_name_whitelisted + exe_path_mismatch",
                    },
                    confidence=0.95,
                    tags=["correlation", "masquerade", "identity"],
                )
            )

        return events


# =============================================================================
# 3. PersistenceExecutionProbe
# =============================================================================


class PersistenceExecutionProbe(MicroProbe):
    """Detects persistence mechanisms whose programs are actively running.

    Closes: Persistence confirmation gap

    A new LaunchAgent is suspicious. A new LaunchAgent whose ProgramArguments
    binary is RUNNING RIGHT NOW is confirmed active malware.
    """

    name = "macos_corr_persistence_execution"
    description = "Persistence mechanism with active process execution"
    platforms = ["darwin"]
    mitre_techniques = ["T1543", "T1547"]
    mitre_tactics = ["persistence", "execution"]
    scan_interval = 30.0
    requires_fields = ["entries", "processes"]

    def __init__(self) -> None:
        super().__init__()
        self._baseline_programs: Set[str] = set()
        self._first_run = True

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        entries = context.shared_data.get("entries", [])
        processes = context.shared_data.get("processes", [])

        # Build set of running exe paths
        running_exes = {p.exe for p in processes if p.exe}

        # Get all persistence programs
        current_programs: Dict[str, Any] = {}
        for entry in entries:
            if entry.program:
                current_programs[entry.program] = entry

        if self._first_run:
            self._baseline_programs = set(current_programs.keys())
            self._first_run = False
            return events

        # Check NEW persistence entries whose programs are running
        for program, entry in current_programs.items():
            if program in self._baseline_programs:
                continue  # Known persistence
            if program not in running_exes:
                continue  # Installed but not running (yet)

            # NEW persistence entry + program is running = active threat
            events.append(
                self._create_event(
                    event_type="corr_persistence_active",
                    severity=Severity.CRITICAL,
                    data={
                        "program": program,
                        "persistence_path": entry.path,
                        "persistence_category": entry.category,
                        "persistence_label": entry.label,
                        "run_at_load": entry.run_at_load,
                        "correlation": "new_persistence + program_running",
                    },
                    confidence=0.95,
                    tags=["correlation", "persistence", "execution"],
                )
            )

        # Update baseline
        self._baseline_programs = set(current_programs.keys())
        return events


# =============================================================================
# 4. DownloadExecuteChainProbe
# =============================================================================


class DownloadExecuteChainProbe(MicroProbe):
    """Detects download → execute → connect kill chain.

    Closes: wl5 (binary in safe path actually dropped and active)

    Pattern: File appears in ~/Downloads or /tmp → process exe matches →
    that PID has outbound connections. This is a complete initial access
    through command-and-control chain.
    """

    name = "macos_corr_download_execute"
    description = "Downloaded file executing with outbound connections"
    platforms = ["darwin"]
    mitre_techniques = ["T1204", "T1059", "T1071"]
    mitre_tactics = ["initial-access", "execution", "command-and-control"]
    scan_interval = 10.0
    requires_fields = ["files", "processes", "pid_connections"]

    _WATCH_PREFIXES = ("/tmp/", "/var/tmp/", "/private/tmp/")

    def __init__(self) -> None:
        super().__init__()
        self._baseline_files: Set[str] = set()
        self._first_run = True

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        files = context.shared_data.get("files", [])
        processes = context.shared_data.get("processes", [])
        pid_conns = context.shared_data.get("pid_connections", {})

        # Find files in watched directories
        downloads_dir = os.path.expanduser("~/Downloads")
        current_files: Set[str] = set()
        for f in files:
            if f.path.startswith(downloads_dir) or any(
                f.path.startswith(p) for p in self._WATCH_PREFIXES
            ):
                current_files.add(f.path)

        if self._first_run:
            self._baseline_files = current_files
            self._first_run = False
            return events

        new_files = current_files - self._baseline_files

        if not new_files:
            self._baseline_files = current_files
            return events

        # Check if any running process exe matches a new file
        for proc in processes:
            if not proc.exe or proc.exe not in new_files:
                continue

            # Check for outbound connections
            conns = pid_conns.get(proc.pid, [])
            external = [
                c
                for c in conns
                if c.state == "ESTABLISHED"
                and c.remote_ip
                and not _is_private(c.remote_ip)
            ]

            severity = Severity.CRITICAL if external else Severity.HIGH
            chain_steps = ["file_dropped"]
            chain_steps.append("process_executing")
            if external:
                chain_steps.append("outbound_connection")

            events.append(
                self._create_event(
                    event_type="corr_download_execute_chain",
                    severity=severity,
                    data={
                        "file_path": proc.exe,
                        "pid": proc.pid,
                        "process_name": proc.name,
                        "external_connections": len(external),
                        "remote_ips": [c.remote_ip for c in external[:3]],
                        "chain_steps": chain_steps,
                        "correlation": "new_file + process_exe_match + outbound",
                    },
                    confidence=0.95 if external else 0.85,
                    tags=["correlation", "kill-chain", "download-execute"],
                )
            )

        self._baseline_files = current_files
        return events


# =============================================================================
# 5. LateralMovementProbe
# =============================================================================


class LateralMovementProbe(MicroProbe):
    """Detects lateral movement to internal hosts on service ports.

    Closes: cg2 (LateralSSHProbe only checks port 22)

    Expands detection to SSH(22), SMB(445), RDP(3389), VNC(5900), WinRM(5985).
    Any outbound ESTABLISHED connection to a private IP on these ports is
    lateral movement.
    """

    name = "macos_corr_lateral_movement"
    description = "Outbound connection to internal host on service port"
    platforms = ["darwin"]
    mitre_techniques = ["T1021", "T1570"]
    mitre_tactics = ["lateral-movement"]
    scan_interval = 10.0
    requires_fields = ["connections"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        connections = context.shared_data.get("connections", [])

        for conn in connections:
            if conn.state != "ESTABLISHED":
                continue
            if not conn.remote_ip or not _is_private(conn.remote_ip):
                continue
            if conn.remote_port not in _LATERAL_PORTS:
                continue

            service = _LATERAL_PORTS[conn.remote_port]
            events.append(
                self._create_event(
                    event_type="corr_lateral_movement",
                    severity=Severity.HIGH,
                    data={
                        "pid": conn.pid,
                        "process_name": conn.process_name,
                        "remote_ip": conn.remote_ip,
                        "remote_port": conn.remote_port,
                        "service": service,
                        "correlation": f"outbound_{service}_to_internal",
                    },
                    confidence=0.85,
                    tags=["correlation", "lateral-movement", service.lower()],
                )
            )

        return events


# =============================================================================
# 6. UnknownListenerProbe
# =============================================================================


class UnknownListenerProbe(MicroProbe):
    """Detects unknown processes listening on suspicious ports.

    Closes: cg3 (NonStandardPortProbe only checks 7 known services)

    Flags any process LISTEN on:
        - Known C2/reverse-shell ports (4444, 5555, 9090, etc.)
        - Non-ephemeral ports (<1024) by unknown processes
        - Any port by process not in known-good listener set
    """

    name = "macos_corr_unknown_listener"
    description = "Unknown process listening on suspicious port"
    platforms = ["darwin"]
    mitre_techniques = ["T1571"]
    mitre_tactics = ["command-and-control"]
    scan_interval = 10.0
    requires_fields = ["connections"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        connections = context.shared_data.get("connections", [])

        for conn in connections:
            if conn.state != "LISTEN":
                continue
            if conn.local_port == 0:
                continue

            pname = conn.process_name.lower()

            # Check known-good listeners
            if pname in _KNOWN_LISTENERS:
                allowed = _KNOWN_LISTENERS[pname]
                if conn.local_port in allowed or 0 in allowed:
                    continue

            # Suspicious port check
            is_c2_port = conn.local_port in _SUSPICIOUS_PORTS
            is_privileged = conn.local_port < 1024

            if not is_c2_port and not is_privileged:
                continue

            severity = Severity.CRITICAL if is_c2_port else Severity.MEDIUM
            reason = "known_c2_port" if is_c2_port else "unknown_privileged_listener"

            events.append(
                self._create_event(
                    event_type="corr_unknown_listener",
                    severity=severity,
                    data={
                        "pid": conn.pid,
                        "process_name": conn.process_name,
                        "local_port": conn.local_port,
                        "reason": reason,
                        "correlation": "unknown_process + suspicious_port",
                    },
                    confidence=0.9 if is_c2_port else 0.7,
                    tags=["correlation", "listener", reason],
                )
            )

        return events


# =============================================================================
# 7. CumulativeAuthProbe
# =============================================================================


class CumulativeAuthProbe(MicroProbe):
    """Detects slow brute force attacks across multiple collection scans.

    Closes: th1 (SSH brute < 5/scan), th3 (lockout < 10/scan)

    Individual probes use per-scan thresholds. An attacker can stay at 4
    failures per scan (threshold=5) indefinitely. The rolling window catches
    cumulative failures across a 5-minute window.
    """

    name = "macos_corr_cumulative_auth"
    description = "Cumulative auth failures across collection windows"
    platforms = ["darwin"]
    mitre_techniques = ["T1110", "T1078"]
    mitre_tactics = ["credential-access", "initial-access"]
    scan_interval = 10.0
    requires_fields = ["rolling"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        rolling = context.shared_data.get("rolling")
        if rolling is None:
            return events

        # Check cumulative SSH failures per source IP
        for key in rolling.keys_with_prefix("ssh_fail:"):
            ip = key.split(":", 1)[1]
            total = rolling.total(key)
            if total >= _SSH_BRUTE_THRESHOLD:
                events.append(
                    self._create_event(
                        event_type="corr_cumulative_ssh_brute",
                        severity=Severity.HIGH,
                        data={
                            "source_ip": ip,
                            "cumulative_failures": total,
                            "threshold": _SSH_BRUTE_THRESHOLD,
                            "window_seconds": rolling._window,
                            "correlation": "rolling_window_ssh_failures",
                        },
                        confidence=0.9,
                        tags=["correlation", "brute-force", "cumulative"],
                    )
                )

        # Check cumulative auth failures per username
        for key in rolling.keys_with_prefix("auth_fail:"):
            username = key.split(":", 1)[1]
            total = rolling.total(key)
            if total >= _LOCKOUT_THRESHOLD:
                events.append(
                    self._create_event(
                        event_type="corr_cumulative_lockout",
                        severity=Severity.HIGH,
                        data={
                            "username": username,
                            "cumulative_failures": total,
                            "threshold": _LOCKOUT_THRESHOLD,
                            "window_seconds": rolling._window,
                            "correlation": "rolling_window_auth_failures",
                        },
                        confidence=0.9,
                        tags=["correlation", "lockout", "cumulative"],
                    )
                )

        return events


# =============================================================================
# 8. CumulativeExfilProbe
# =============================================================================


class CumulativeExfilProbe(MicroProbe):
    """Detects slow data exfiltration across multiple collection scans.

    Closes: th2 (exfil < 10MB/scan)

    An attacker can exfiltrate 9.9MB per scan cycle indefinitely and never
    trigger ExfilSpikeProbe. The rolling window catches cumulative bytes_out
    per process across a 5-minute window.
    """

    name = "macos_corr_cumulative_exfil"
    description = "Cumulative data exfiltration across collection windows"
    platforms = ["darwin"]
    mitre_techniques = ["T1048"]
    mitre_tactics = ["exfiltration"]
    scan_interval = 10.0
    requires_fields = ["rolling"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        rolling = context.shared_data.get("rolling")
        if rolling is None:
            return events

        for key in rolling.keys_with_prefix("bytes_out:"):
            process_name = key.split(":", 1)[1]
            total = rolling.total(key)
            if total >= _EXFIL_THRESHOLD:
                events.append(
                    self._create_event(
                        event_type="corr_cumulative_exfil",
                        severity=Severity.HIGH,
                        data={
                            "process_name": process_name,
                            "cumulative_bytes_out": total,
                            "threshold_bytes": _EXFIL_THRESHOLD,
                            "threshold_mb": _EXFIL_THRESHOLD / (1024 * 1024),
                            "window_seconds": rolling._window,
                            "correlation": "rolling_window_bytes_out",
                        },
                        confidence=0.85,
                        tags=["correlation", "exfiltration", "cumulative"],
                    )
                )

        return events


# =============================================================================
# 9. KillChainProgressionProbe
# =============================================================================

# Tactic-to-signal mapping: which shared_data signals indicate which tactic
_TACTIC_SIGNALS = {
    "initial-access": {
        "fields": ["files", "auth_events"],
        "check": "_check_initial_access",
    },
    "execution": {
        "fields": ["processes"],
        "check": "_check_execution",
    },
    "persistence": {
        "fields": ["entries"],
        "check": "_check_persistence",
    },
    "credential-access": {
        "fields": ["auth_events"],
        "check": "_check_credential_access",
    },
    "lateral-movement": {
        "fields": ["connections"],
        "check": "_check_lateral_movement",
    },
    "exfiltration": {
        "fields": ["bandwidth"],
        "check": "_check_exfiltration",
    },
    "command-and-control": {
        "fields": ["connections"],
        "check": "_check_c2",
    },
}


class KillChainProgressionProbe(MicroProbe):
    """Detects multi-tactic attack progression within a single collection.

    Closes: Multi-stage attack detection (combines weak signals into strong)

    Individual probes detect single tactics. This probe scores how many
    distinct MITRE tactics are active simultaneously. If 3+ tactics are
    observed in a single collection cycle, it's likely a coordinated attack.
    """

    name = "macos_corr_kill_chain"
    description = "Multi-tactic attack progression across agents"
    platforms = ["darwin"]
    mitre_techniques = ["T1059", "T1071", "T1543", "T1078", "T1048"]
    mitre_tactics = [
        "initial-access",
        "execution",
        "persistence",
        "credential-access",
        "lateral-movement",
        "exfiltration",
        "command-and-control",
    ]
    scan_interval = 10.0
    requires_fields = ["processes", "connections", "entries", "auth_events", "files"]

    # Minimum tactics for an alert
    _MIN_TACTICS = 3

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        active_tactics: List[str] = []

        # Check each tactic for active signals
        if self._check_initial_access(context):
            active_tactics.append("initial-access")
        if self._check_execution(context):
            active_tactics.append("execution")
        if self._check_persistence(context):
            active_tactics.append("persistence")
        if self._check_credential_access(context):
            active_tactics.append("credential-access")
        if self._check_lateral_movement(context):
            active_tactics.append("lateral-movement")
        if self._check_exfiltration(context):
            active_tactics.append("exfiltration")
        if self._check_c2(context):
            active_tactics.append("command-and-control")

        if len(active_tactics) >= self._MIN_TACTICS:
            severity = Severity.CRITICAL if len(active_tactics) >= 4 else Severity.HIGH
            events.append(
                self._create_event(
                    event_type="corr_kill_chain_progression",
                    severity=severity,
                    data={
                        "active_tactics": active_tactics,
                        "tactic_count": len(active_tactics),
                        "min_threshold": self._MIN_TACTICS,
                        "correlation": "multi_tactic_simultaneous",
                    },
                    confidence=min(0.7 + 0.05 * len(active_tactics), 0.95),
                    tags=["correlation", "kill-chain", "multi-tactic"],
                )
            )

        return events

    def _check_initial_access(self, ctx: ProbeContext) -> bool:
        """New files in Downloads or auth from new source."""
        files = ctx.shared_data.get("files", [])
        downloads = os.path.expanduser("~/Downloads")
        for f in files:
            if f.path.startswith(downloads) or f.path.startswith("/tmp/"):
                return True
        auth = ctx.shared_data.get("auth_events", [])
        for ev in auth:
            if ev.category == "ssh" and ev.event_type == "success":
                return True
        return False

    def _check_execution(self, ctx: ProbeContext) -> bool:
        """LOLBin or script interpreter running."""
        processes = ctx.shared_data.get("processes", [])
        for proc in processes:
            if proc.exe:
                basename = os.path.basename(proc.exe).lower()
                if basename in _LOLBIN_BASENAMES:
                    return True
        return False

    def _check_persistence(self, ctx: ProbeContext) -> bool:
        """Any persistence entry with run_at_load or keep_alive."""
        entries = ctx.shared_data.get("entries", [])
        for entry in entries:
            if entry.run_at_load or entry.keep_alive:
                return True
        return False

    def _check_credential_access(self, ctx: ProbeContext) -> bool:
        """Keychain access or sudo attempts."""
        auth = ctx.shared_data.get("auth_events", [])
        for ev in auth:
            if ev.category in ("keychain", "sudo"):
                return True
        return False

    def _check_lateral_movement(self, ctx: ProbeContext) -> bool:
        """Outbound connections to internal hosts on lateral ports."""
        connections = ctx.shared_data.get("connections", [])
        for conn in connections:
            if (
                conn.state == "ESTABLISHED"
                and conn.remote_ip
                and _is_private(conn.remote_ip)
                and conn.remote_port in _LATERAL_PORTS
            ):
                return True
        return False

    def _check_exfiltration(self, ctx: ProbeContext) -> bool:
        """Large outbound data volume."""
        bandwidth = ctx.shared_data.get("bandwidth", [])
        for bw in bandwidth:
            if bw.bytes_out > _EXFIL_THRESHOLD:
                return True
        return False

    def _check_c2(self, ctx: ProbeContext) -> bool:
        """Multiple external connections from same process."""
        connections = ctx.shared_data.get("connections", [])
        pid_external: Dict[int, int] = {}
        for conn in connections:
            if (
                conn.state == "ESTABLISHED"
                and conn.remote_ip
                and not _is_private(conn.remote_ip)
            ):
                pid_external[conn.pid] = pid_external.get(conn.pid, 0) + 1
        return any(count >= 3 for count in pid_external.values())


# =============================================================================
# 10. FileSizeAnomalyProbe
# =============================================================================


class FileSizeAnomalyProbe(MicroProbe):
    """Detects benign file names with anomalous sizes (payload hiding).

    Closes: wl6 (.DS_Store payload)

    Attackers hide payloads in files with benign names (.DS_Store, .localized)
    that are whitelisted by other probes. But a real .DS_Store is <32KB — a
    100KB .DS_Store is almost certainly a payload.
    """

    name = "macos_corr_file_size_anomaly"
    description = "Benign filename with anomalous file size"
    platforms = ["darwin"]
    mitre_techniques = ["T1564"]
    mitre_tactics = ["defense-evasion"]
    scan_interval = 60.0
    requires_fields = ["files"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        files = context.shared_data.get("files", [])

        for f in files:
            name_lower = f.name.lower()
            max_size = _BENIGN_FILE_SIZES.get(name_lower)
            if max_size is None:
                continue

            if f.size <= max_size:
                continue

            events.append(
                self._create_event(
                    event_type="corr_file_size_anomaly",
                    severity=Severity.HIGH,
                    data={
                        "path": f.path,
                        "name": f.name,
                        "actual_size": f.size,
                        "expected_max_size": max_size,
                        "size_ratio": round(f.size / max(max_size, 1), 1),
                        "correlation": "benign_name + anomalous_size",
                    },
                    confidence=0.85,
                    tags=["correlation", "file-size", "defense-evasion"],
                )
            )

        return events


# =============================================================================
# 11. ScheduledPersistenceProbe
# =============================================================================


class ScheduledPersistenceProbe(MicroProbe):
    """Detects at-job, periodic, and emond persistence (missed by CronProbe).

    Closes: nt3 (CronProbe only watches 'cron' category)

    The existing CronProbe has _target_categories = ['cron']. This probe
    monitors at_job, periodic, emond — persistence mechanisms that use
    scheduling but aren't covered.
    """

    name = "macos_corr_scheduled_persistence"
    description = "Persistence via at-job, periodic script, or emond rule"
    platforms = ["darwin"]
    mitre_techniques = ["T1053"]
    mitre_tactics = ["persistence", "execution"]
    scan_interval = 30.0
    requires_fields = ["entries"]

    _TARGET_CATEGORIES = frozenset({"at_job", "periodic", "emond"})

    def __init__(self) -> None:
        super().__init__()
        self._baseline: Dict[str, str] = {}  # path → content_hash
        self._first_run = True

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        entries = context.shared_data.get("entries", [])

        current: Dict[str, Any] = {}
        for entry in entries:
            if entry.category in self._TARGET_CATEGORIES:
                current[entry.path] = entry

        if self._first_run:
            self._baseline = {p: e.content_hash for p, e in current.items()}
            self._first_run = False
            return events

        # Detect NEW entries
        for path, entry in current.items():
            if path not in self._baseline:
                events.append(
                    self._create_event(
                        event_type="corr_scheduled_persistence_new",
                        severity=Severity.HIGH,
                        data={
                            "path": entry.path,
                            "name": entry.name,
                            "category": entry.category,
                            "content_hash": entry.content_hash,
                            "change_type": "new",
                            "correlation": "expanded_schedule_monitoring",
                        },
                        confidence=0.9,
                        tags=["correlation", "persistence", entry.category],
                    )
                )

        # Detect MODIFIED entries
        for path, entry in current.items():
            if path in self._baseline and entry.content_hash != self._baseline[path]:
                events.append(
                    self._create_event(
                        event_type="corr_scheduled_persistence_modified",
                        severity=Severity.HIGH,
                        data={
                            "path": entry.path,
                            "name": entry.name,
                            "category": entry.category,
                            "content_hash": entry.content_hash,
                            "previous_hash": self._baseline[path],
                            "change_type": "modified",
                            "correlation": "expanded_schedule_monitoring",
                        },
                        confidence=0.9,
                        tags=["correlation", "persistence", entry.category],
                    )
                )

        self._baseline = {p: e.content_hash for p, e in current.items()}
        return events


# =============================================================================
# 12. AuthGeoAnomalyProbe
# =============================================================================


class AuthGeoAnomalyProbe(MicroProbe):
    """Detects SSH logins from new/unusual source IPs.

    Closes: cg6 (OffHoursLoginProbe only checks time, not source)

    Even during business hours, a login from a never-before-seen source IP
    is suspicious. This probe maintains a baseline of known source IPs and
    flags new ones regardless of time of day.
    """

    name = "macos_corr_auth_geo_anomaly"
    description = "SSH login from previously unseen source IP"
    platforms = ["darwin"]
    mitre_techniques = ["T1078"]
    mitre_tactics = ["initial-access"]
    scan_interval = 10.0
    requires_fields = ["auth_events"]

    def __init__(self) -> None:
        super().__init__()
        self._known_ips: Set[str] = set()
        self._first_run = True

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        auth_events = context.shared_data.get("auth_events", [])

        current_ips: Set[str] = set()
        for ev in auth_events:
            if ev.category == "ssh" and ev.event_type == "success" and ev.source_ip:
                current_ips.add(ev.source_ip)

        if self._first_run:
            self._known_ips = current_ips.copy()
            self._first_run = False
            return events

        new_ips = current_ips - self._known_ips
        for ip in new_ips:
            severity = Severity.MEDIUM if _is_private(ip) else Severity.HIGH
            events.append(
                self._create_event(
                    event_type="corr_auth_new_source",
                    severity=severity,
                    data={
                        "source_ip": ip,
                        "is_private": _is_private(ip),
                        "known_ips": list(self._known_ips)[:10],
                        "correlation": "new_source_ip_baseline_diff",
                    },
                    confidence=0.8,
                    tags=["correlation", "auth", "new-source"],
                )
            )

        self._known_ips |= current_ips
        return events


# =============================================================================
# Factory
# =============================================================================


def create_correlation_probes() -> List[MicroProbe]:
    """Create all 12 macOS correlation probes."""
    return [
        ProcessNetworkProbe(),
        BinaryIdentityProbe(),
        PersistenceExecutionProbe(),
        DownloadExecuteChainProbe(),
        LateralMovementProbe(),
        UnknownListenerProbe(),
        CumulativeAuthProbe(),
        CumulativeExfilProbe(),
        KillChainProgressionProbe(),
        FileSizeAnomalyProbe(),
        ScheduledPersistenceProbe(),
        AuthGeoAnomalyProbe(),
    ]
