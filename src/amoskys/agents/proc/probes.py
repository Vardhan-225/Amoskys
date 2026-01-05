"""ProcAgent Micro-Probes - 8 Eyes Watching Process Activity.

Each probe monitors ONE specific process threat vector:

    1. ProcessSpawnProbe - Detects new process creation
    2. LOLBinExecutionProbe - Living-off-the-land binary abuse
    3. ProcessTreeAnomalyProbe - Unusual parent-child relationships
    4. HighCPUAndMemoryProbe - Resource abuse detection
    5. LongLivedProcessProbe - Persistent suspicious processes
    6. SuspiciousUserProcessProbe - Wrong user for process type
    7. BinaryFromTempProbe - Execution from temp directories
    8. ScriptInterpreterProbe - Suspicious script execution

MITRE ATT&CK Coverage:
    - T1059: Command and Scripting Interpreter
    - T1218: System Binary Proxy Execution
    - T1055: Process Injection
    - T1496: Resource Hijacking
    - T1036: Masquerading
    - T1204: User Execution
"""

from __future__ import annotations

import logging
import os
import platform
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)

logger = logging.getLogger(__name__)


# Try to import psutil
try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logger.warning("psutil not available - process probes will be limited")


# =============================================================================
# Shared Data Structures
# =============================================================================


@dataclass
class ProcessInfo:
    """Information about a running process."""

    pid: int
    name: str
    exe: str
    cmdline: List[str]
    username: str
    ppid: int
    parent_name: str
    create_time: float
    cpu_percent: float
    memory_percent: float
    status: str
    cwd: str = ""


# =============================================================================
# 1. ProcessSpawnProbe
# =============================================================================


class ProcessSpawnProbe(MicroProbe):
    """Detects new process creation.

    Tracks process IDs and reports newly spawned processes. This is the
    foundational probe for process monitoring.

    MITRE: T1059 (Command and Scripting Interpreter)
    """

    name = "process_spawn"
    description = "Detects new process creation"
    mitre_techniques = ["T1059", "T1204"]
    mitre_tactics = ["execution"]
    scan_interval = 5.0

    def __init__(self) -> None:
        super().__init__()
        self.known_pids: Set[int] = set()
        self.first_run = True

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect new processes."""
        events = []

        if not PSUTIL_AVAILABLE:
            return events

        current_pids = set()

        for proc in psutil.process_iter(
            ["pid", "name", "exe", "cmdline", "username", "ppid", "create_time"]
        ):
            try:
                info = proc.info
                pid = info["pid"]
                current_pids.add(pid)

                # Skip known processes
                if pid in self.known_pids:
                    continue

                # Skip on first run (learning baseline)
                if self.first_run:
                    continue

                # New process detected
                parent_name = ""
                try:
                    parent = psutil.Process(info.get("ppid", 0))
                    parent_name = parent.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

                events.append(
                    self._create_event(
                        event_type="process_spawned",
                        severity=Severity.INFO,
                        data={
                            "pid": pid,
                            "name": info.get("name", ""),
                            "exe": info.get("exe", ""),
                            "cmdline": info.get("cmdline", []),
                            "username": info.get("username", ""),
                            "ppid": info.get("ppid", 0),
                            "parent_name": parent_name,
                        },
                        confidence=1.0,
                    )
                )

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Update known PIDs
        self.known_pids = current_pids
        self.first_run = False

        return events


# =============================================================================
# 2. LOLBinExecutionProbe
# =============================================================================


class LOLBinExecutionProbe(MicroProbe):
    """Detects Living-off-the-Land Binary (LOLBin) execution.

    LOLBins are legitimate system binaries that attackers abuse for
    malicious purposes (download, execute, bypass).

    MITRE: T1218 (System Binary Proxy Execution)
    """

    name = "lolbin_execution"
    description = "Detects abuse of living-off-the-land binaries"
    mitre_techniques = ["T1218", "T1218.010", "T1218.011"]
    mitre_tactics = ["defense_evasion", "execution"]
    scan_interval = 5.0

    # LOLBins by platform
    LOLBINS_MACOS = {
        "curl": "File download",
        "wget": "File download",
        "osascript": "AppleScript execution",
        "python": "Script execution",
        "python3": "Script execution",
        "perl": "Script execution",
        "ruby": "Script execution",
        "bash": "Shell execution",
        "sh": "Shell execution",
        "zsh": "Shell execution",
        "open": "File/URL opening",
        "xattr": "Extended attribute manipulation",
        "launchctl": "Service manipulation",
        "security": "Keychain access",
        "screencapture": "Screen capture",
        "sqlite3": "Database access",
        "zip": "Archive creation",
        "tar": "Archive creation",
        "base64": "Encoding/decoding",
        "nc": "Network utility",
        "netcat": "Network utility",
        "nscurl": "URL fetch (signed Apple)",
    }

    LOLBINS_LINUX = {
        "curl": "File download",
        "wget": "File download",
        "python": "Script execution",
        "python3": "Script execution",
        "perl": "Script execution",
        "ruby": "Script execution",
        "bash": "Shell execution",
        "sh": "Shell execution",
        "nc": "Network utility",
        "netcat": "Network utility",
        "ncat": "Network utility",
        "socat": "Network utility",
        "base64": "Encoding/decoding",
        "xxd": "Hex dump",
        "certutil": "Certificate utility",
        "at": "Task scheduling",
        "crontab": "Task scheduling",
        "systemctl": "Service manipulation",
        "ld.so": "Dynamic linker",
        "awk": "Text processing",
        "sed": "Text processing",
        "chmod": "Permission change",
        "chown": "Ownership change",
    }

    LOLBINS_WINDOWS = {
        "certutil.exe": "Certificate utility (download)",
        "mshta.exe": "HTML Application host",
        "rundll32.exe": "DLL execution",
        "regsvr32.exe": "COM registration",
        "cscript.exe": "Script execution",
        "wscript.exe": "Script execution",
        "powershell.exe": "PowerShell",
        "pwsh.exe": "PowerShell Core",
        "cmd.exe": "Command prompt",
        "msiexec.exe": "Installer",
        "bitsadmin.exe": "Background transfer",
        "esentutl.exe": "Database utility",
        "expand.exe": "Archive extraction",
        "extrac32.exe": "Archive extraction",
        "findstr.exe": "String search",
        "forfiles.exe": "File iteration",
        "ftp.exe": "FTP client",
        "hh.exe": "HTML Help",
        "installutil.exe": ".NET installation",
        "msbuild.exe": "Build tool",
        "msconfig.exe": "System configuration",
        "odbcconf.exe": "ODBC configuration",
        "pcwrun.exe": "Program Compatibility",
        "reg.exe": "Registry tool",
        "regasm.exe": ".NET assembly registration",
        "regsvcs.exe": ".NET services registration",
        "schtasks.exe": "Task scheduler",
        "wmic.exe": "WMI command-line",
        "xwizard.exe": "Extensible wizard",
    }

    def __init__(self) -> None:
        super().__init__()
        system = platform.system()
        if system == "Darwin":
            self.lolbins = self.LOLBINS_MACOS
        elif system == "Linux":
            self.lolbins = self.LOLBINS_LINUX
        else:
            self.lolbins = self.LOLBINS_WINDOWS

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect LOLBin execution."""
        events = []

        if not PSUTIL_AVAILABLE:
            return events

        for proc in psutil.process_iter(
            ["pid", "name", "exe", "cmdline", "username", "ppid"]
        ):
            try:
                info = proc.info
                name = info.get("name", "").lower()
                cmdline = info.get("cmdline", [])

                # Check if this is a LOLBin
                if name in self.lolbins:
                    category = self.lolbins[name]

                    # Analyze command line for suspicious patterns
                    cmdline_str = " ".join(cmdline or [])
                    suspicious_patterns = self._check_suspicious_usage(
                        name, cmdline_str
                    )

                    if suspicious_patterns:
                        severity = Severity.HIGH
                    else:
                        severity = Severity.LOW

                    events.append(
                        self._create_event(
                            event_type="lolbin_execution",
                            severity=severity,
                            data={
                                "pid": info.get("pid"),
                                "binary": name,
                                "category": category,
                                "cmdline": cmdline,
                                "suspicious_patterns": suspicious_patterns,
                                "username": info.get("username", ""),
                            },
                            confidence=0.7 if suspicious_patterns else 0.4,
                        )
                    )

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return events

    def _check_suspicious_usage(self, binary: str, cmdline: str) -> List[str]:
        """Check for suspicious LOLBin usage patterns."""
        patterns = []

        cmdline_lower = cmdline.lower()

        # Download patterns
        if binary in ("curl", "wget", "certutil.exe", "bitsadmin.exe"):
            if any(
                x in cmdline_lower
                for x in ["-o ", "> ", "| ", "http://", "https://", "ftp://"]
            ):
                if any(
                    x in cmdline_lower for x in [".exe", ".dll", ".ps1", ".bat", ".sh"]
                ):
                    patterns.append("downloading_executable")

        # Encoded command patterns
        if binary in ("powershell.exe", "pwsh.exe", "python", "python3"):
            if any(x in cmdline_lower for x in ["-enc", "-e ", "base64", "-c "]):
                patterns.append("encoded_command")

        # Hidden execution
        if any(
            x in cmdline_lower
            for x in ["-windowstyle hidden", "-w hidden", "nohup", "&>/dev/null"]
        ):
            patterns.append("hidden_execution")

        # Network activity from unexpected binaries
        if binary in ("certutil.exe", "mshta.exe", "rundll32.exe"):
            if any(x in cmdline_lower for x in ["http", "ftp", "//"]):
                patterns.append("network_activity")

        return patterns


# =============================================================================
# 3. ProcessTreeAnomalyProbe
# =============================================================================


class ProcessTreeAnomalyProbe(MicroProbe):
    """Detects unusual parent-child process relationships.

    Certain process hierarchies are red flags (e.g., Word spawning PowerShell).

    MITRE: T1055 (Process Injection), T1059 (Scripting Interpreter)
    """

    name = "process_tree_anomaly"
    description = "Detects unusual parent-child process relationships"
    mitre_techniques = ["T1055", "T1059"]
    mitre_tactics = ["execution", "defense_evasion"]
    scan_interval = 10.0

    # Suspicious parent-child combinations
    SUSPICIOUS_TREES = {
        # Office apps spawning shells/scripts
        ("word", "powershell"): "Office macro execution",
        ("word", "cmd"): "Office macro execution",
        ("excel", "powershell"): "Office macro execution",
        ("excel", "cmd"): "Office macro execution",
        ("outlook", "powershell"): "Email attachment execution",
        ("outlook", "cmd"): "Email attachment execution",
        # Browsers spawning shells
        ("chrome", "powershell"): "Browser exploit",
        ("chrome", "cmd"): "Browser exploit",
        ("firefox", "bash"): "Browser exploit",
        ("safari", "bash"): "Browser exploit",
        # Unexpected service spawns
        ("svchost", "powershell"): "Service exploitation",
        ("services", "cmd"): "Service exploitation",
        # PDF readers
        ("acrord32", "cmd"): "PDF exploit",
        ("acrord32", "powershell"): "PDF exploit",
        ("preview", "bash"): "PDF exploit",
    }

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect process tree anomalies."""
        events = []

        if not PSUTIL_AVAILABLE:
            return events

        for proc in psutil.process_iter(["pid", "name", "ppid", "cmdline"]):
            try:
                info = proc.info
                child_name = info.get("name", "").lower()

                # Get parent info
                try:
                    parent = psutil.Process(info.get("ppid", 0))
                    parent_name = parent.name().lower()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

                # Check for suspicious combinations
                for (
                    suspicious_parent,
                    suspicious_child,
                ), reason in self.SUSPICIOUS_TREES.items():
                    if (
                        suspicious_parent in parent_name
                        and suspicious_child in child_name
                    ):
                        events.append(
                            self._create_event(
                                event_type="suspicious_process_tree",
                                severity=Severity.HIGH,
                                data={
                                    "child_pid": info.get("pid"),
                                    "child_name": child_name,
                                    "child_cmdline": info.get("cmdline", []),
                                    "parent_name": parent_name,
                                    "parent_pid": info.get("ppid"),
                                    "reason": reason,
                                },
                                confidence=0.85,
                            )
                        )
                        break

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return events


# =============================================================================
# 4. HighCPUAndMemoryProbe
# =============================================================================


class HighCPUAndMemoryProbe(MicroProbe):
    """Detects processes consuming excessive resources.

    High resource usage may indicate:
    - Cryptocurrency mining
    - Data processing/exfiltration
    - Denial of service

    MITRE: T1496 (Resource Hijacking)
    """

    name = "high_cpu_memory"
    description = "Detects resource abuse (cryptomining, etc.)"
    mitre_techniques = ["T1496"]
    mitre_tactics = ["impact"]
    scan_interval = 30.0

    CPU_THRESHOLD = 80.0  # Percent
    MEMORY_THRESHOLD = 50.0  # Percent
    SUSTAINED_SECONDS = 60  # Must be high for this long

    def __init__(self) -> None:
        super().__init__()
        self.high_resource_pids: Dict[int, float] = {}  # pid -> first_seen_time

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect high resource usage."""
        events = []

        if not PSUTIL_AVAILABLE:
            return events

        import time

        now = time.time()
        current_high_pids = set()

        for proc in psutil.process_iter(
            ["pid", "name", "cpu_percent", "memory_percent", "username"]
        ):
            try:
                info = proc.info
                pid = info["pid"]
                cpu = info.get("cpu_percent", 0) or 0
                mem = info.get("memory_percent", 0) or 0

                is_high = cpu > self.CPU_THRESHOLD or mem > self.MEMORY_THRESHOLD

                if is_high:
                    current_high_pids.add(pid)

                    if pid not in self.high_resource_pids:
                        self.high_resource_pids[pid] = now
                    elif now - self.high_resource_pids[pid] > self.SUSTAINED_SECONDS:
                        events.append(
                            self._create_event(
                                event_type="high_resource_process",
                                severity=Severity.MEDIUM,
                                data={
                                    "pid": pid,
                                    "name": info.get("name", ""),
                                    "cpu_percent": round(cpu, 1),
                                    "memory_percent": round(mem, 1),
                                    "duration_seconds": int(
                                        now - self.high_resource_pids[pid]
                                    ),
                                    "username": info.get("username", ""),
                                },
                                confidence=0.7,
                            )
                        )

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Cleanup old entries
        self.high_resource_pids = {
            pid: t
            for pid, t in self.high_resource_pids.items()
            if pid in current_high_pids
        }

        return events


# =============================================================================
# 5. LongLivedProcessProbe
# =============================================================================


class LongLivedProcessProbe(MicroProbe):
    """Detects persistent processes that may be suspicious.

    Some malware runs persistently but tries to hide by using common names.

    MITRE: T1036 (Masquerading)
    """

    name = "long_lived_process"
    description = "Tracks long-running processes for anomaly detection"
    mitre_techniques = ["T1036"]
    mitre_tactics = ["persistence", "defense_evasion"]
    scan_interval = 300.0  # Check every 5 minutes

    # Process names that shouldn't run for long periods
    EXPECTED_SHORT_LIVED = {
        "grep",
        "awk",
        "sed",
        "cat",
        "ls",
        "ps",
        "find",
        "xargs",
        "cut",
        "sort",
        "uniq",
        "wc",
        "head",
        "tail",
    }

    LONG_LIVED_THRESHOLD = 3600  # 1 hour

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect unexpectedly long-lived processes."""
        events = []

        if not PSUTIL_AVAILABLE:
            return events

        import time

        now = time.time()

        for proc in psutil.process_iter(["pid", "name", "create_time", "username"]):
            try:
                info = proc.info
                name = info.get("name", "").lower()
                create_time = info.get("create_time", now)

                runtime = now - create_time

                # Check if process should be short-lived
                if name in self.EXPECTED_SHORT_LIVED:
                    if runtime > self.LONG_LIVED_THRESHOLD:
                        events.append(
                            self._create_event(
                                event_type="unexpectedly_long_process",
                                severity=Severity.MEDIUM,
                                data={
                                    "pid": info.get("pid"),
                                    "name": name,
                                    "runtime_seconds": int(runtime),
                                    "username": info.get("username", ""),
                                },
                                confidence=0.6,
                            )
                        )

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return events


# =============================================================================
# 6. SuspiciousUserProcessProbe
# =============================================================================


class SuspiciousUserProcessProbe(MicroProbe):
    """Detects processes running as unexpected users.

    Certain processes should only run as specific users.

    MITRE: T1078 (Valid Accounts)
    """

    name = "suspicious_user_process"
    description = "Detects processes running as unexpected users"
    mitre_techniques = ["T1078"]
    mitre_tactics = ["privilege_escalation", "defense_evasion"]
    scan_interval = 60.0

    # Processes that should only run as root/SYSTEM
    ROOT_ONLY_PROCESSES = {
        "sshd",
        "httpd",
        "nginx",
        "mysqld",
        "postgres",
        "dockerd",
        "containerd",
        "systemd",
        "init",
        "cron",
        "rsyslogd",
        "auditd",
    }

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect processes with suspicious user context."""
        events = []

        if not PSUTIL_AVAILABLE:
            return events

        for proc in psutil.process_iter(["pid", "name", "username"]):
            try:
                info = proc.info
                name = info.get("name", "").lower()
                username = info.get("username", "").lower()

                # Check for root-only processes running as non-root
                if name in self.ROOT_ONLY_PROCESSES:
                    if username and username not in (
                        "root",
                        "system",
                        "nt authority\\system",
                    ):
                        events.append(
                            self._create_event(
                                event_type="process_wrong_user",
                                severity=Severity.HIGH,
                                data={
                                    "pid": info.get("pid"),
                                    "name": name,
                                    "username": username,
                                    "expected_user": "root/SYSTEM",
                                },
                                confidence=0.8,
                            )
                        )

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return events


# =============================================================================
# 7. BinaryFromTempProbe
# =============================================================================


class BinaryFromTempProbe(MicroProbe):
    """Detects execution from temporary directories.

    Malware often drops and executes from temp directories.

    MITRE: T1204 (User Execution), T1059 (Scripting)
    """

    name = "binary_from_temp"
    description = "Detects execution from temp directories"
    mitre_techniques = ["T1204", "T1059"]
    mitre_tactics = ["execution"]
    scan_interval = 10.0

    TEMP_PATTERNS = [
        r"/tmp/",
        r"/var/tmp/",
        r"/dev/shm/",
        r"\\temp\\",
        r"\\tmp\\",
        r"\\appdata\\local\\temp\\",
        r"/private/var/folders/",  # macOS temp
    ]

    def __init__(self) -> None:
        super().__init__()
        self.reported_pids: Set[int] = set()

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect execution from temp directories."""
        events = []

        if not PSUTIL_AVAILABLE:
            return events

        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "username"]):
            try:
                info = proc.info
                pid = info["pid"]

                if pid in self.reported_pids:
                    continue

                exe = info.get("exe", "") or ""
                exe_lower = exe.lower()

                for pattern in self.TEMP_PATTERNS:
                    if re.search(pattern, exe_lower, re.IGNORECASE):
                        self.reported_pids.add(pid)

                        events.append(
                            self._create_event(
                                event_type="execution_from_temp",
                                severity=Severity.HIGH,
                                data={
                                    "pid": pid,
                                    "name": info.get("name", ""),
                                    "exe": exe,
                                    "cmdline": info.get("cmdline", []),
                                    "username": info.get("username", ""),
                                },
                                confidence=0.85,
                            )
                        )
                        break

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return events


# =============================================================================
# 8. ScriptInterpreterProbe
# =============================================================================


class ScriptInterpreterProbe(MicroProbe):
    """Detects suspicious script interpreter usage.

    Monitors Python, PowerShell, bash, etc. for suspicious patterns.

    MITRE: T1059 (Command and Scripting Interpreter)
    """

    name = "script_interpreter"
    description = "Monitors script interpreter usage for suspicious patterns"
    mitre_techniques = ["T1059", "T1059.001", "T1059.003", "T1059.004", "T1059.006"]
    mitre_tactics = ["execution"]
    scan_interval = 10.0

    INTERPRETERS = {
        "python",
        "python3",
        "python2",
        "powershell",
        "pwsh",
        "bash",
        "sh",
        "zsh",
        "cmd",
        "perl",
        "ruby",
        "node",
        "php",
        "lua",
        "osascript",
    }

    # Suspicious command patterns
    SUSPICIOUS_PATTERNS = [
        r"-enc\s+[A-Za-z0-9+/=]{20,}",  # Encoded command
        r"import\s+(socket|subprocess|os|urllib|requests)",  # Python networking
        r"eval\s*\(",  # Dynamic execution
        r"exec\s*\(",  # Dynamic execution
        r"Invoke-Expression",  # PowerShell IEX
        r"IEX\s*\(",  # PowerShell IEX short
        r"DownloadString",  # PowerShell download
        r"DownloadFile",  # PowerShell download
        r"WebClient",  # PowerShell web
        r"curl.*\|\s*(bash|sh)",  # Curl pipe to shell
        r"wget.*\|\s*(bash|sh)",  # Wget pipe to shell
        r"base64\s+-d",  # Base64 decode
        r"\\x[0-9a-fA-F]{2}",  # Hex encoding
        r"nc\s+-[el]",  # Netcat listener
        r"/dev/tcp/",  # Bash network redirect
    ]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect suspicious script execution."""
        events = []

        if not PSUTIL_AVAILABLE:
            return events

        for proc in psutil.process_iter(["pid", "name", "cmdline", "username"]):
            try:
                info = proc.info
                name = info.get("name", "").lower()

                if name not in self.INTERPRETERS:
                    continue

                cmdline = info.get("cmdline", [])
                cmdline_str = " ".join(cmdline or [])

                # Check for suspicious patterns
                matches = []
                for pattern in self.SUSPICIOUS_PATTERNS:
                    if re.search(pattern, cmdline_str, re.IGNORECASE):
                        matches.append(pattern)

                if matches:
                    events.append(
                        self._create_event(
                            event_type="suspicious_script_execution",
                            severity=Severity.HIGH,
                            data={
                                "pid": info.get("pid"),
                                "interpreter": name,
                                "cmdline": cmdline,
                                "matched_patterns": matches[:5],  # Limit
                                "username": info.get("username", ""),
                            },
                            confidence=0.8,
                        )
                    )

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return events


# =============================================================================
# Probe Registry
# =============================================================================

PROC_PROBES = [
    ProcessSpawnProbe,
    LOLBinExecutionProbe,
    ProcessTreeAnomalyProbe,
    HighCPUAndMemoryProbe,
    LongLivedProcessProbe,
    SuspiciousUserProcessProbe,
    BinaryFromTempProbe,
    ScriptInterpreterProbe,
]


def create_proc_probes() -> List[MicroProbe]:
    """Create instances of all process probes.

    Returns:
        List of initialized process probe instances
    """
    return [probe_class() for probe_class in PROC_PROBES]


__all__ = [
    "BinaryFromTempProbe",
    "create_proc_probes",
    "HighCPUAndMemoryProbe",
    "LOLBinExecutionProbe",
    "LongLivedProcessProbe",
    "PROC_PROBES",
    "ProcessInfo",
    "ProcessSpawnProbe",
    "ProcessTreeAnomalyProbe",
    "ScriptInterpreterProbe",
    "SuspiciousUserProcessProbe",
]
