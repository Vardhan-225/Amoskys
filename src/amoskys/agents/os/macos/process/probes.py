"""macOS Process Probes — 10 detection probes for Darwin process activity.

Each probe consumes ProcessSnapshot data from MacOSProcessCollector via
shared_data["processes"]. Every probe is macOS-only (platforms=["darwin"]).

Probes:
    1. ProcessSpawnProbe — new process creation (baseline-diff)
    2. LOLBinProbe — living-off-the-land binary abuse
    3. ProcessTreeProbe — anomalous parent-child relationships
    4. ResourceAbuseProbe — CPU/memory abuse (own-user only)
    5. DylibInjectionProbe — DYLD_INSERT_LIBRARIES in environ
    6. CodeSigningProbe — unsigned/tampered binary detection
    7. ScriptInterpreterProbe — suspicious script execution patterns
    8. BinaryFromTempProbe — execution from temp/download paths
    9. SuspiciousUserProbe — wrong user running privileged processes
   10. ProcessMasqueradeProbe — name vs exe path mismatch

Lessons learned (from existing proc agent ground truth):
    - AppTranslocation paths (/private/var/folders/*/T/AppTranslocation/) are NOT malicious
    - mysqld/postgres running as root is normal (removed from ROOT_ONLY)
    - codesign returns "Permission denied" for some binaries — not an alert
    - cmdline is only available for own-user processes (60.8% coverage)
    - Scripts run via interpreter show up as python3/bash, check cmdline[1:3] for temp paths
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from typing import Any, Dict, List, Optional, Set

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)

logger = logging.getLogger(__name__)

# Shared import — ProcessSnapshot is in collector but we only need its fields
# via dict access on shared_data, so no hard import needed.


# =============================================================================
# 1. ProcessSpawnProbe
# =============================================================================


class ProcessSpawnProbe(MicroProbe):
    """Detects new process creation via PID baseline diff.

    First scan establishes the baseline. Subsequent scans report new PIDs.
    Uses create_time to avoid false alerts from PID recycling.

    MITRE: T1059 (Command and Scripting Interpreter), T1204 (User Execution)
    """

    name = "macos_process_spawn"
    description = "Detects new process creation on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1059", "T1204"]
    mitre_tactics = ["execution"]
    scan_interval = 5.0
    requires_fields = ["processes"]

    def __init__(self) -> None:
        super().__init__()
        self._known: Dict[int, float] = {}  # pid -> create_time
        self._first_run = True

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        from amoskys.agents.common.apple_allowlist import is_apple_system_process
        from amoskys.agents.common.self_identity import self_identity

        events: List[TelemetryEvent] = []
        processes = context.shared_data.get("processes", [])
        current: Dict[int, float] = {}

        for proc in processes:
            pid = proc.pid
            ct = proc.create_time
            current[pid] = ct

            if self._first_run:
                continue

            # New PID, or same PID but different create_time (recycled)
            if pid not in self._known or self._known[pid] != ct:
                # Skip AMOSKYS's own processes
                if self_identity.is_self_process(pid=pid, name=proc.name, exe=proc.exe):
                    continue

                # Check Apple allowlist for trust disposition
                allowlist = is_apple_system_process(proc.name, proc.exe)
                trust_disposition = allowlist.disposition

                events.append(
                    self._create_event(
                        event_type="process_spawned",
                        severity=Severity.INFO,
                        data={
                            "pid": pid,
                            "name": proc.name,
                            "exe": proc.exe,
                            "cmdline": proc.cmdline,
                            "username": proc.username,
                            "ppid": proc.ppid,
                            "parent_name": proc.parent_name,
                            "process_guid": proc.process_guid,
                            "trust_disposition": trust_disposition,
                        },
                        confidence=0.2 if trust_disposition == "apple_system" else 1.0,
                        correlation_id=proc.process_guid,
                    )
                )

        self._known = current
        self._first_run = False
        return events


# =============================================================================
# 2. LOLBinProbe
# =============================================================================


# macOS-specific LOLBins — binaries attackers abuse on Darwin
_MACOS_LOLBINS: Dict[str, str] = {
    # Network tools
    "curl": "file_download",
    "wget": "file_download",
    "nc": "network_utility",
    "ncat": "network_utility",
    "nscurl": "signed_url_fetch",
    # Script interpreters (when spawned suspiciously)
    "osascript": "applescript_execution",
    "python3": "script_execution",
    "python": "script_execution",
    "perl": "script_execution",
    "ruby": "script_execution",
    "swift": "script_execution",
    # Credential / security
    "security": "keychain_access",
    "sqlite3": "database_access",
    # System manipulation
    "launchctl": "service_manipulation",
    "xattr": "xattr_manipulation",
    "defaults": "plist_manipulation",
    "plutil": "plist_manipulation",
    "dscl": "directory_service",
    "ditto": "file_copy",
    "scp": "file_transfer",
    "sftp": "file_transfer",
    # Encoding / obfuscation
    "base64": "encoding",
    "openssl": "crypto_utility",
    # Screen / clipboard
    "screencapture": "screen_capture",
    "pbcopy": "clipboard_write",
    "pbpaste": "clipboard_read",
    # Archive
    "tar": "archive",
    "zip": "archive",
    "unzip": "archive",
    # ── Extended LOLBins (fileless/evasion coverage) ──
    # Reconnaissance
    "pmset": "power_management",
    "mdls": "metadata_query",
    "mdfind": "spotlight_search",
    "ioreg": "hardware_query",
    # Network configuration
    "networksetup": "network_config",
    "systemsetup": "system_config",
    "scutil": "system_config",
    # Disk / image
    "hdiutil": "disk_image",
    "diskutil": "disk_utility",
    # Security manipulation
    "tccutil": "tcc_manipulation",
    "sysadminctl": "admin_management",
    "profiles": "profile_install",
    # Log manipulation (evidence destruction)
    "log": "log_manipulation",
    # Anti-forensics
    "caffeinate": "sleep_prevention",
    "srm": "secure_delete",
}

# Parent processes that commonly spawn LOLBins legitimately
_BENIGN_PARENTS = frozenset(
    {
        "Finder",
        "Terminal",
        "iTerm2",
        "sshd",
        "login",
        "zsh",
        "bash",
        "launchd",
        "Spotlight",
        "mdworker",
        "mds_stores",
        "Xcode",
        "xcodebuild",
        "clang",
        "swift-frontend",
    }
)


class LOLBinProbe(MicroProbe):
    """Detects living-off-the-land binary execution on macOS.

    Watches for system binaries commonly abused by attackers. Filters out
    known-benign parent chains to reduce false positives.

    MITRE: T1218 (System Binary Proxy Execution)
    """

    name = "macos_lolbin"
    description = "Detects LOLBin abuse on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1218", "T1059.002"]
    mitre_tactics = ["defense_evasion", "execution"]
    scan_interval = 5.0
    requires_fields = ["processes"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        processes = context.shared_data.get("processes", [])

        for proc in processes:
            name_lower = proc.name.lower()
            if name_lower not in _MACOS_LOLBINS:
                continue

            # Skip if parent is a known-benign launcher
            if proc.parent_name in _BENIGN_PARENTS:
                continue

            category = _MACOS_LOLBINS[name_lower]
            severity = Severity.MEDIUM
            # Elevate for high-risk LOLBins
            if category in (
                "keychain_access",
                "service_manipulation",
                "xattr_manipulation",
                "network_utility",
            ):
                severity = Severity.HIGH

            events.append(
                self._create_event(
                    event_type="lolbin_execution",
                    severity=severity,
                    data={
                        "pid": proc.pid,
                        "name": proc.name,
                        "exe": proc.exe,
                        "cmdline": proc.cmdline,
                        "category": category,
                        "parent_name": proc.parent_name,
                        "ppid": proc.ppid,
                        "username": proc.username,
                        "process_guid": proc.process_guid,
                    },
                    confidence=0.7,
                    correlation_id=proc.process_guid,
                )
            )

        return events


# =============================================================================
# 3. ProcessTreeProbe
# =============================================================================

# macOS-specific suspicious parent-child patterns
_SUSPICIOUS_TREES = [
    # Web browser spawning shell
    {
        "parents": {"Safari", "Google Chrome", "Firefox", "Arc", "Brave Browser"},
        "children": {"bash", "sh", "zsh", "python3", "osascript", "curl"},
        "reason": "browser_shell_spawn",
    },
    # Finder spawning script tools
    {
        "parents": {"Finder"},
        "children": {"python3", "osascript", "curl", "nc", "security"},
        "reason": "finder_script_spawn",
    },
    # System daemon spawning user tools
    {
        "parents": {"launchd"},
        "children": {"curl", "wget", "nc", "base64", "openssl"},
        "reason": "launchd_suspicious_child",
    },
    # Preview/QuickLook exploitation
    {
        "parents": {"Preview", "QuickLookSatellite", "qlmanage"},
        "children": {"bash", "sh", "python3", "curl"},
        "reason": "quicklook_exploitation",
    },
]


class ProcessTreeProbe(MicroProbe):
    """Detects anomalous parent-child process relationships on macOS.

    Known patterns: browser → shell, Finder → script tools, launchd → netutils.

    MITRE: T1059 (Command and Scripting Interpreter)
    """

    name = "macos_process_tree"
    description = "Detects anomalous parent-child process relationships on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1059", "T1059.002", "T1059.004"]
    mitre_tactics = ["execution"]
    scan_interval = 10.0
    requires_fields = ["processes"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        processes = context.shared_data.get("processes", [])

        for proc in processes:
            child_name = proc.name
            parent_name = proc.parent_name

            for pattern in _SUSPICIOUS_TREES:
                if (
                    parent_name in pattern["parents"]
                    and child_name in pattern["children"]
                ):
                    events.append(
                        self._create_event(
                            event_type="process_tree_anomaly",
                            severity=Severity.HIGH,
                            data={
                                "pid": proc.pid,
                                "child_name": child_name,
                                "child_exe": proc.exe,
                                "parent_name": parent_name,
                                "ppid": proc.ppid,
                                "reason": pattern["reason"],
                                "cmdline": proc.cmdline,
                                "process_guid": proc.process_guid,
                            },
                            confidence=0.85,
                            correlation_id=proc.process_guid,
                        )
                    )
                    break  # One match per process

        return events


# =============================================================================
# 4. ResourceAbuseProbe
# =============================================================================


class ResourceAbuseProbe(MicroProbe):
    """Detects CPU/memory abuse (cryptomining, DoS, resource exhaustion).

    Only fires for own-user processes where cpu_percent/memory_percent are
    available. System processes (other-user) report None and are skipped.
    This is an honest constraint: cryptominer running as root is invisible.

    MITRE: T1496 (Resource Hijacking)
    """

    name = "macos_resource_abuse"
    description = "Detects CPU/memory resource abuse on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1496"]
    mitre_tactics = ["impact"]
    scan_interval = 30.0
    requires_fields = ["processes"]

    CPU_THRESHOLD = 80.0  # Percent
    MEMORY_THRESHOLD = 50.0  # Percent

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        processes = context.shared_data.get("processes", [])

        for proc in processes:
            # Only own-user processes have resource metrics
            if not proc.is_own_user:
                continue

            cpu = proc.cpu_percent
            mem = proc.memory_percent

            if cpu is not None and cpu > self.CPU_THRESHOLD:
                events.append(
                    self._create_event(
                        event_type="high_cpu",
                        severity=Severity.MEDIUM,
                        data={
                            "pid": proc.pid,
                            "name": proc.name,
                            "exe": proc.exe,
                            "cpu_percent": cpu,
                            "threshold": self.CPU_THRESHOLD,
                            "username": proc.username,
                            "process_guid": proc.process_guid,
                        },
                        confidence=0.7,
                        correlation_id=proc.process_guid,
                    )
                )

            if mem is not None and mem > self.MEMORY_THRESHOLD:
                events.append(
                    self._create_event(
                        event_type="high_memory",
                        severity=Severity.MEDIUM,
                        data={
                            "pid": proc.pid,
                            "name": proc.name,
                            "exe": proc.exe,
                            "memory_percent": mem,
                            "threshold": self.MEMORY_THRESHOLD,
                            "username": proc.username,
                            "process_guid": proc.process_guid,
                        },
                        confidence=0.7,
                        correlation_id=proc.process_guid,
                    )
                )

        return events


# =============================================================================
# 5. DylibInjectionProbe
# =============================================================================


class DylibInjectionProbe(MicroProbe):
    """Detects DYLD_INSERT_LIBRARIES injection on macOS.

    Checks process environment for DYLD_INSERT_LIBRARIES and
    DYLD_FRAMEWORK_PATH — both used for dylib injection attacks.

    Constraint: environ is only available for own-user processes.
    Root-level injection into system processes is INVISIBLE from uid=501.

    MITRE: T1574.004 (Hijack Execution Flow: Dylib Hijacking)
    Note: T1055.001 (DLL Injection) is Windows-only. macOS dylib injection
    maps to T1574.004 (Dylib Hijacking) and T1574.006 (Dynamic Linker Hijacking).
    """

    name = "macos_dylib_injection"
    description = "Detects DYLD_INSERT_LIBRARIES injection on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1574.004", "T1574.006"]
    mitre_tactics = ["privilege_escalation", "defense_evasion"]
    scan_interval = 10.0
    requires_fields = ["processes"]

    _DYLD_VARS = (
        "DYLD_INSERT_LIBRARIES",
        "DYLD_FRAMEWORK_PATH",
        "DYLD_LIBRARY_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
    )

    # Known-safe DYLD injections (developer tools, etc.)
    _SAFE_DYLIBS = frozenset(
        {
            "/usr/lib/libgmalloc.dylib",  # Apple debug malloc
            "/usr/lib/libMallocStackLogging.dylib",
        }
    )

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        processes = context.shared_data.get("processes", [])

        for proc in processes:
            if proc.environ is None:
                continue  # No access to environ (other-user process)

            for var in self._DYLD_VARS:
                value = proc.environ.get(var)
                if not value:
                    continue

                # Filter known-safe dylibs
                if all(lib.strip() in self._SAFE_DYLIBS for lib in value.split(":")):
                    continue

                events.append(
                    self._create_event(
                        event_type="dylib_injection",
                        severity=Severity.CRITICAL,
                        data={
                            "pid": proc.pid,
                            "name": proc.name,
                            "exe": proc.exe,
                            "dyld_variable": var,
                            "dyld_value": value,
                            "username": proc.username,
                            "process_guid": proc.process_guid,
                        },
                        confidence=0.9,
                        correlation_id=proc.process_guid,
                    )
                )

        return events


# =============================================================================
# 6. CodeSigningProbe
# =============================================================================

# Critical macOS binaries that should always be Apple-signed
_CRITICAL_BINARIES = [
    "/usr/sbin/sshd",
    "/usr/bin/sudo",
    "/bin/bash",
    "/bin/sh",
    "/bin/zsh",
    "/usr/bin/python3",
    "/usr/bin/login",
    "/usr/sbin/httpd",
    "/usr/bin/ssh",
    "/usr/bin/open",
]

_PERMISSION_ERRORS = ("Permission denied", "Operation not permitted")


class CodeSigningProbe(MicroProbe):
    """Verifies code signing on critical macOS binaries.

    Runs `codesign --verify --deep` on a fixed list of critical binaries.
    Reports tampered or unsigned binaries. Gracefully handles permission
    denied (some binaries like sudo return this as non-root).

    MITRE: T1553.002 (Subvert Trust Controls: Code Signing)
    """

    name = "macos_code_signing"
    description = "Verifies code signing integrity on critical macOS binaries"
    platforms = ["darwin"]
    mitre_techniques = ["T1553.002"]
    mitre_tactics = ["defense_evasion"]
    scan_interval = 300.0  # Every 5 minutes
    requires_fields = []  # Doesn't need process data, runs independently

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []

        for binary in _CRITICAL_BINARIES:
            if not os.path.exists(binary):
                continue

            try:
                result = subprocess.run(
                    ["codesign", "--verify", "--deep", binary],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

                if result.returncode != 0:
                    stderr = result.stderr.strip()

                    # Permission denied is expected for some binaries as non-root
                    if any(err in stderr for err in _PERMISSION_ERRORS):
                        logger.debug("codesign permission denied for %s", binary)
                        continue

                    events.append(
                        self._create_event(
                            event_type="code_signing_failure",
                            severity=Severity.CRITICAL,
                            data={
                                "binary": binary,
                                "error": stderr,
                                "returncode": result.returncode,
                            },
                            confidence=0.95,
                        )
                    )

            except subprocess.TimeoutExpired:
                logger.warning("codesign timeout for %s", binary)
            except Exception as e:
                logger.error("codesign check failed for %s: %s", binary, e)

        return events


# =============================================================================
# 7. ScriptInterpreterProbe
# =============================================================================

_SCRIPT_INTERPRETERS = frozenset(
    {
        "python3",
        "python",
        "perl",
        "ruby",
        "osascript",
        "swift",
        "node",
        "php",
        "lua",
        # Shells — detect bash -c 'echo X|base64 -d|sh' chains
        "bash",
        "sh",
        "zsh",
    }
)

# Suspicious script patterns in cmdline arguments
_SUSPICIOUS_SCRIPT_PATTERNS = [
    # Inline execution flags (-c for python/bash, -e for perl/ruby/node)
    (
        r"-[ce]\s+['\"].*?(curl|wget|nc |bash|eval|exec|system\(|socket)",
        "inline_code_execution",
    ),
    (r"(http://|https://|ftp://)", "remote_url_in_args"),
    (r"\|\s*(bash|sh|zsh|python)", "pipe_to_shell"),
    (r"base64\s+(--decode|-d|-D)", "base64_decode"),
    (r"echo\s+[A-Za-z0-9+/=]{20,}", "base64_payload_echo"),
    (r"openssl\s+enc\s+-d", "openssl_decrypt_chain"),
    (r"(\/tmp\/|\/var\/tmp\/|\/private\/tmp\/)", "temp_path_script"),
    # JXA (JavaScript for Automation) — modern macOS attack scripting
    (r"-l\s+JavaScript", "jxa_execution"),
    (r"\$\.NSTask|\$\.NSFileManager|ObjC\.import|ObjC\.unwrap", "jxa_objc_bridge"),
    (r"Application\(['\"]System Events", "jxa_system_events"),
    # Reverse shell patterns
    (r"socket\.socket|TCPSocket|SOCK_STREAM|Socket\.", "reverse_shell_indicator"),
    (r"subprocess\.call|subprocess\.Popen|subprocess\.run", "subprocess_spawn"),
]


class ScriptInterpreterProbe(MicroProbe):
    """Detects suspicious script interpreter usage on macOS.

    Monitors python3, osascript, perl, ruby, etc. for suspicious patterns
    like inline code execution, remote URL arguments, and pipe-to-shell.

    MITRE: T1059 (Command and Scripting Interpreter)
    """

    name = "macos_script_interpreter"
    description = "Detects suspicious script interpreter usage on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1059", "T1059.002", "T1059.004", "T1059.006"]
    mitre_tactics = ["execution"]
    scan_interval = 5.0
    requires_fields = ["processes"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        processes = context.shared_data.get("processes", [])

        for proc in processes:
            if proc.name not in _SCRIPT_INTERPRETERS:
                continue

            # Need cmdline for pattern matching (own-user only)
            cmdline_str = " ".join(proc.cmdline) if proc.cmdline else ""
            if not cmdline_str:
                continue

            for pattern, reason in _SUSPICIOUS_SCRIPT_PATTERNS:
                if re.search(pattern, cmdline_str, re.IGNORECASE):
                    events.append(
                        self._create_event(
                            event_type="suspicious_script",
                            severity=Severity.HIGH,
                            data={
                                "pid": proc.pid,
                                "interpreter": proc.name,
                                "exe": proc.exe,
                                "cmdline": proc.cmdline,
                                "pattern": reason,
                                "parent_name": proc.parent_name,
                                "username": proc.username,
                                "process_guid": proc.process_guid,
                            },
                            confidence=0.8,
                            correlation_id=proc.process_guid,
                        )
                    )
                    break  # One match per process

        return events


# =============================================================================
# 8. BinaryFromTempProbe
# =============================================================================

_TEMP_PATTERNS = [
    r"/tmp/",
    r"/var/tmp/",
    r"/private/tmp/",
    r"/private/var/folders/.*/T/",
    r"\.Trash/",
]

# Known-safe temp-like paths that are NOT malicious
_BENIGN_TEMP_PATHS = [
    r"\.claude/",  # Claude Code shell snapshots
    r"shell-snapshots/",  # Claude Code internal
    r"/nix/store/",  # Nix package manager
    r"\.vscode/",  # VS Code extensions
    r"com\.apple\.",  # macOS system temp operations
    r"/Users/[^/]+/Downloads/",
]

# macOS App Translocation: Gatekeeper moves quarantined apps here
# This is NORMAL behavior, not malicious.
_APP_TRANSLOCATION = "AppTranslocation"


class BinaryFromTempProbe(MicroProbe):
    """Detects execution of binaries from temporary/download directories.

    Watches for exe paths and cmdline arguments pointing to /tmp, /var/tmp,
    ~/Downloads, .Trash, etc. Filters out macOS App Translocation paths
    (Gatekeeper-quarantined apps moved to /private/var/folders/*/T/AppTranslocation/).

    MITRE: T1204 (User Execution), T1036 (Masquerading)
    """

    name = "macos_binary_from_temp"
    description = "Detects execution from temp/download paths on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1204", "T1036"]
    mitre_tactics = ["execution", "defense_evasion"]
    scan_interval = 5.0
    requires_fields = ["processes"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        processes = context.shared_data.get("processes", [])

        for proc in processes:
            suspect = self._find_temp_execution(proc)
            if suspect:
                events.append(
                    self._create_event(
                        event_type="binary_from_temp",
                        severity=Severity.HIGH,
                        data={
                            "pid": proc.pid,
                            "name": proc.name,
                            "exe": proc.exe,
                            "suspect_path": suspect,
                            "cmdline": proc.cmdline,
                            "username": proc.username,
                            "parent_name": proc.parent_name,
                            "process_guid": proc.process_guid,
                        },
                        confidence=0.85,
                        correlation_id=proc.process_guid,
                    )
                )

        return events

    def _find_temp_execution(self, proc) -> Optional[str]:
        """Check exe and cmdline[1:3] for temp paths.

        Returns the suspect path if found, None otherwise.
        Excludes AppTranslocation paths and known-safe temp paths.
        """
        # Check exe path first
        exe = proc.exe or ""
        if exe and self._is_temp(exe) and not self._is_safe(exe):
            return exe

        # Check first few cmdline args (script path often in [1] or [2])
        cmdline = proc.cmdline or []
        for arg in cmdline[1:3]:
            if isinstance(arg, str) and self._is_temp(arg) and not self._is_safe(arg):
                return arg

        return None

    @staticmethod
    def _is_temp(path: str) -> bool:
        for pattern in _TEMP_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                return True
        return False

    @staticmethod
    def _is_safe(path: str) -> bool:
        """Check if path is AppTranslocation or a known-benign temp path."""
        if _APP_TRANSLOCATION in path:
            return True
        for pattern in _BENIGN_TEMP_PATHS:
            if re.search(pattern, path, re.IGNORECASE):
                return True
        return False


# =============================================================================
# 9. SuspiciousUserProbe
# =============================================================================

# System daemons that should ONLY run as root or _system user
_ROOT_ONLY_PROCESSES = frozenset(
    {
        "sshd",
        "httpd",
        "nginx",
        "dockerd",
        "containerd",
        "launchd",
        "cron",
        "rsyslogd",
        "auditd",
        # Do NOT include mysqld, postgres — they legitimately run as own user
    }
)


class SuspiciousUserProbe(MicroProbe):
    """Detects processes running as unexpected users on macOS.

    Flags system daemons (sshd, httpd, etc.) running as non-root — indicates
    possible privilege confusion or persistence attempt.

    MITRE: T1078 (Valid Accounts)
    """

    name = "macos_suspicious_user"
    description = "Detects processes running as unexpected users on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1078"]
    mitre_tactics = ["persistence", "privilege_escalation"]
    scan_interval = 30.0
    requires_fields = ["processes"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        processes = context.shared_data.get("processes", [])

        for proc in processes:
            name_lower = proc.name.lower()
            if name_lower not in _ROOT_ONLY_PROCESSES:
                continue

            # These should run as root or _system users
            username = proc.username
            if username in (
                "root",
                "_www",
                "_windowserver",
                "_securityagent",
                "_networkd",
                "_mdnsresponder",
                "_appleevents",
            ):
                continue

            # If username starts with _, it's a system user — likely fine
            if username.startswith("_"):
                continue

            events.append(
                self._create_event(
                    event_type="suspicious_user_process",
                    severity=Severity.HIGH,
                    data={
                        "pid": proc.pid,
                        "name": proc.name,
                        "exe": proc.exe,
                        "expected_user": "root/_system",
                        "actual_user": username,
                        "process_guid": proc.process_guid,
                    },
                    confidence=0.8,
                    correlation_id=proc.process_guid,
                )
            )

        return events


# =============================================================================
# 10. ProcessMasqueradeProbe
# =============================================================================

# Map of expected exe paths for well-known process names on macOS
_EXPECTED_PATHS: Dict[str, Set[str]] = {
    "sshd": {"/usr/sbin/sshd"},
    "sudo": {"/usr/bin/sudo"},
    "bash": {"/bin/bash", "/usr/local/bin/bash", "/opt/homebrew/bin/bash"},
    "zsh": {"/bin/zsh"},
    "sh": {"/bin/sh"},
    "python3": {"/usr/bin/python3", "/Library/Frameworks/Python.framework"},
    "login": {"/usr/bin/login"},
    "ssh": {"/usr/bin/ssh"},
    "curl": {"/usr/bin/curl"},
    "launchd": {"/sbin/launchd"},
    "cron": {"/usr/sbin/cron"},
}


class ProcessMasqueradeProbe(MicroProbe):
    """Detects process name masquerading on macOS.

    Compares process name against expected exe paths. A process named "sshd"
    running from /tmp/sshd is masquerading.

    MITRE: T1036 (Masquerading), T1036.005 (Match Legitimate Name)
    """

    name = "macos_process_masquerade"
    description = "Detects process name vs exe path mismatch on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1036", "T1036.005"]
    mitre_tactics = ["defense_evasion"]
    scan_interval = 30.0
    requires_fields = ["processes"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        processes = context.shared_data.get("processes", [])

        for proc in processes:
            name_lower = proc.name.lower()
            if name_lower not in _EXPECTED_PATHS:
                continue

            expected = _EXPECTED_PATHS[name_lower]

            # Resolve effective path: prefer exe, fall back to cmdline[0]
            exe = proc.exe
            if not exe and proc.cmdline:
                exe = proc.cmdline[0]

            if not exe:
                continue  # No path info at all — can't verify

            # Check if exe starts with any expected path (handles framework paths)
            if any(exe.startswith(exp) for exp in expected):
                continue

            confidence = 0.9 if proc.exe else 0.7  # Lower if from cmdline

            events.append(
                self._create_event(
                    event_type="process_masquerade",
                    severity=Severity.CRITICAL,
                    data={
                        "pid": proc.pid,
                        "name": proc.name,
                        "exe": proc.exe,
                        "resolved_path": exe,
                        "expected_paths": list(expected),
                        "username": proc.username,
                        "parent_name": proc.parent_name,
                        "process_guid": proc.process_guid,
                        "from_cmdline": not bool(proc.exe),
                    },
                    confidence=confidence,
                    correlation_id=proc.process_guid,
                )
            )

        return events


# =============================================================================
# Factory
# =============================================================================


# =============================================================================
# 11. SystemDiscoveryProbe
# =============================================================================


class SystemDiscoveryProbe(MicroProbe):
    """Detects system information discovery commands used in post-exploitation.

    Fires when multiple fingerprinting commands run from the same parent PID
    (burst detection) or individually for high-value commands.

    MITRE: T1082 (System Information Discovery)
    """

    name = "macos_system_discovery"
    description = "Detects system fingerprinting command patterns on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1082"]
    mitre_tactics = ["discovery"]
    scan_interval = 15.0
    requires_fields = ["processes"]

    _DISCOVERY_COMMANDS = {
        # System identification
        "sw_vers": "macOS version query",
        "system_profiler": "Hardware/software inventory",
        "uname": "Kernel version query",
        "sysctl": "Kernel parameter enumeration",
        "hostinfo": "Host information query",
        "ioreg": "I/O registry dump (VM detection)",
        # Security posture
        "csrutil": "SIP status check",
        "fdesetup": "FileVault status check",
        "spctl": "Gatekeeper status check",
        "systemsetup": "System configuration query",
        # User / identity
        "dscl": "Directory service enumeration",
        "id": "User identity query",
        "whoami": "Current user identity",
        "groups": "Group membership query",
        # Network
        "ifconfig": "Network interface enumeration",
        "networksetup": "Network configuration query",
        "scutil": "System configuration query",
        "netstat": "Network statistics",
        # Filesystem / metadata
        "mdls": "Spotlight metadata query",
        "mdfind": "Spotlight search (file discovery)",
        "diskutil": "Disk utility enumeration",
        "pmset": "Power management query",
    }

    _BURST_THRESHOLD = 3

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        processes = context.shared_data.get("processes", [])

        hits_by_ppid: Dict[int, List[str]] = {}
        for proc in processes:
            binary = os.path.basename(proc.exe) if proc.exe else proc.name
            if binary in self._DISCOVERY_COMMANDS:
                ppid = proc.ppid
                if ppid not in hits_by_ppid:
                    hits_by_ppid[ppid] = []
                hits_by_ppid[ppid].append(binary)

        for ppid, commands in hits_by_ppid.items():
            if len(commands) >= self._BURST_THRESHOLD:
                events.append(
                    self._create_event(
                        event_type="system_discovery_burst",
                        severity=Severity.MEDIUM,
                        data={
                            "parent_pid": ppid,
                            "discovery_commands": commands,
                            "command_count": len(commands),
                        },
                        confidence=min(0.90, 0.40 + len(commands) * 0.10),
                        tags=["discovery", "system-info"],
                    )
                )

        return events


# =============================================================================
# 12. SecurityToolDisableProbe
# =============================================================================


class SecurityToolDisableProbe(MicroProbe):
    """Detects attempts to disable macOS security mechanisms.

    Watches for commands like spctl --master-disable, csrutil disable,
    pfctl -d, and XProtect unloading.

    MITRE: T1562.001 (Impair Defenses: Disable or Modify Tools)
    """

    name = "macos_security_tool_disable"
    description = "Detects commands that disable Gatekeeper, SIP, firewall, or other security tools"
    platforms = ["darwin"]
    mitre_techniques = ["T1562.001"]
    mitre_tactics = ["defense_evasion"]
    scan_interval = 10.0
    requires_fields = ["processes"]

    # (pattern, description, severity)
    _DISABLE_PATTERNS = [
        # ── Gatekeeper / SIP ──
        ("spctl --master-disable", "Gatekeeper disabled", Severity.CRITICAL),
        ("spctl --global-disable", "Gatekeeper globally disabled", Severity.CRITICAL),
        ("csrutil disable", "SIP disable attempted", Severity.CRITICAL),
        ("csrutil clear", "SIP configuration cleared", Severity.CRITICAL),
        (
            "csrutil authenticated-root disable",
            "SIP authenticated-root disabled (Big Sur+)",
            Severity.CRITICAL,
        ),
        # ── AMFI bypass ──
        (
            "nvram boot-args",
            "NVRAM boot-args modification (potential AMFI bypass)",
            Severity.CRITICAL,
        ),
        # ── FileVault / encryption ──
        ("fdesetup disable", "FileVault disable attempted", Severity.HIGH),
        # ── Firewall ──
        ("pfctl -d", "Packet filter firewall disabled", Severity.HIGH),
        (
            "socketfilterfw --setglobalstate off",
            "Application firewall disabled",
            Severity.HIGH,
        ),
        # ── Quarantine ──
        (
            "xattr -d com.apple.quarantine",
            "Quarantine attribute stripped",
            Severity.MEDIUM,
        ),
        ("xattr -c", "All extended attributes cleared", Severity.MEDIUM),
        # ── Log evidence destruction ──
        ("log erase", "Unified log erased (evidence destruction)", Severity.CRITICAL),
        # ── TCC manipulation ──
        ("tccutil reset", "TCC permissions bulk reset", Severity.HIGH),
        # ── Security daemon disruption ──
        (
            "launchctl bootout system/com.apple",
            "System daemon killed via launchctl",
            Severity.CRITICAL,
        ),
        ("launchctl unload", "Daemon unloaded via launchctl", Severity.HIGH),
        # ── Backup / recovery disruption ──
        ("tmutil disable", "Time Machine disabled", Severity.MEDIUM),
    ]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        processes = context.shared_data.get("processes", [])

        for proc in processes:
            cmdline_str = " ".join(proc.cmdline) if proc.cmdline else ""
            if not cmdline_str:
                continue

            cmd_lower = cmdline_str.lower()
            for pattern, description, severity in self._DISABLE_PATTERNS:
                if pattern.lower() in cmd_lower:
                    events.append(
                        self._create_event(
                            event_type="security_tool_disabled",
                            severity=severity,
                            data={
                                "pid": proc.pid,
                                "process_name": proc.name,
                                "exe": proc.exe,
                                "cmdline": cmdline_str[:500],
                                "pattern_matched": pattern,
                                "security_impact": description,
                            },
                            confidence=0.95,
                            correlation_id=proc.process_guid,
                        )
                    )
                    break

        return events


# =============================================================================
# 13. ProcessMasqueradeEnhancedProbe
# =============================================================================


class ProcessMasqueradeEnhancedProbe(MicroProbe):
    """Enhanced masquerade detection: system-named binaries from /tmp + homoglyphs.

    Complements the existing ProcessMasqueradeProbe by catching:
    - Any process from /tmp, /var/tmp whose name matches a system binary
    - Unicode homoglyph names (non-ASCII chars in process names)
    - Process names with suspicious whitespace

    MITRE: T1036.005 (Masquerading: Match Legitimate Name or Location)
    """

    name = "macos_masquerade_enhanced"
    description = (
        "Detects system-named binaries from suspicious locations and homoglyphs"
    )
    platforms = ["darwin"]
    mitre_techniques = ["T1036.005", "T1036"]
    mitre_tactics = ["defense_evasion"]
    scan_interval = 15.0
    requires_fields = ["processes"]

    _SYSTEM_NAMES = {
        "sshd",
        "bash",
        "zsh",
        "sh",
        "python3",
        "sudo",
        "login",
        "cron",
        "launchd",
        "kernel_task",
        "WindowServer",
        "loginwindow",
        "Finder",
        "Dock",
        "Safari",
        "Terminal",
        "ssh",
        "curl",
    }

    _SUSPICIOUS_DIRS = {"/tmp", "/var/tmp", "/private/tmp", "/dev/shm"}

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        processes = context.shared_data.get("processes", [])

        for proc in processes:
            if not proc.name or not proc.exe:
                continue

            reasons: List[str] = []

            # 1. System-named binary from suspicious directory
            exe_dir = os.path.dirname(proc.exe).rstrip("/")
            if exe_dir in self._SUSPICIOUS_DIRS and proc.name in self._SYSTEM_NAMES:
                reasons.append(f"System binary '{proc.name}' running from {exe_dir}")

            # 2. Unicode homoglyph detection
            try:
                proc.name.encode("ascii")
            except UnicodeEncodeError:
                reasons.append(
                    f"Process name '{proc.name}' contains non-ASCII (homoglyph?)"
                )

            # 3. Suspicious whitespace
            if "  " in proc.name or proc.name != proc.name.strip():
                reasons.append(f"Process name has suspicious whitespace")

            if reasons:
                events.append(
                    self._create_event(
                        event_type="process_masquerade_enhanced",
                        severity=(
                            Severity.HIGH if len(reasons) >= 2 else Severity.MEDIUM
                        ),
                        data={
                            "pid": proc.pid,
                            "ppid": proc.ppid,
                            "process_name": proc.name,
                            "exe": proc.exe,
                            "reasons": reasons,
                        },
                        confidence=min(0.95, 0.60 + len(reasons) * 0.15),
                        correlation_id=proc.process_guid,
                    )
                )

        return events


def create_process_probes() -> List[MicroProbe]:
    """Create all macOS process probes."""
    return [
        ProcessSpawnProbe(),
        LOLBinProbe(),
        ProcessTreeProbe(),
        ResourceAbuseProbe(),
        DylibInjectionProbe(),
        CodeSigningProbe(),
        ScriptInterpreterProbe(),
        BinaryFromTempProbe(),
        SuspiciousUserProbe(),
        ProcessMasqueradeProbe(),
        SystemDiscoveryProbe(),
        SecurityToolDisableProbe(),
        ProcessMasqueradeEnhancedProbe(),
    ]
