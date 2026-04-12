"""macOS Quarantine Guard Probes — 8 detection probes for download provenance.

Each probe consumes data from MacOSQuarantineGuardCollector via shared_data.
Every probe is macOS-only (platforms=["darwin"]).

Probes:
    1. QuarantineBypassProbe       — xattr removal of quarantine flag
    2. DMGMountExecuteProbe        — process running from mounted DMG
    3. ClickFixDetectionProbe      — messaging app + terminal paste attack
    4. UnsignedDownloadExecProbe   — unsigned binary from Downloads/tmp
    5. CLIDownloadExecuteProbe     — CLI download bypasses quarantine
    6. SuspiciousDownloadSrcProbe  — download from unknown domain
    7. InstallerScriptAbuseProbe   — installer spawns suspicious child
    8. QuarantineEvasionPatternProbe — no xattr + process running from path

Key design decisions:
    - ClickFix is the most novel probe: detects social engineering where an
      attacker sends a victim a command to paste into Terminal via a messaging
      app. Correlation: messaging_apps_running + terminal_children with
      suspicious commands (curl, wget, bash -c, base64, etc.).
    - Quarantine xattr presence/absence is the primary signal for CLI vs
      browser downloads. Browsers set com.apple.quarantine; curl/wget do not.
    - DMG execution is detected by cross-referencing mounted DMG mount_points
      with running process exe paths.
    - codesign verification runs with subprocess timeout=3 to avoid hangs.
"""

from __future__ import annotations

import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)

logger = logging.getLogger(__name__)


# =============================================================================
# 1. QuarantineBypassProbe
# =============================================================================


class QuarantineBypassProbe(MicroProbe):
    """Detects active quarantine xattr removal via xattr -d/-c.

    Fires when a process is running 'xattr -d com.apple.quarantine' or
    'xattr -c' on any file. This is the most direct Gatekeeper bypass:
    removing the quarantine flag allows unsigned code to run without
    the "this app was downloaded from the internet" warning.

    MITRE: T1553.001 (Subvert Trust Controls: Gatekeeper Bypass)
    """

    name = "quarantine_bypass"
    description = "Detects quarantine xattr removal on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1553.001"]
    mitre_tactics = ["defense_evasion"]
    scan_interval = 10.0
    requires_fields = ["xattr_removal_processes", "xattr_removals"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        xattr_procs = context.shared_data.get("xattr_removal_processes", [])
        xattr_removals = context.shared_data.get("xattr_removals", [])

        # Strategy 1: Catch running xattr process (rare — runs in <5ms)
        for proc in xattr_procs:
            cmdline = proc.get("cmdline", [])
            cmdline_str = " ".join(cmdline)
            target_file = proc.get("target_file", "")

            events.append(
                self._create_event(
                    event_type="quarantine_bypass",
                    severity=Severity.CRITICAL,
                    data={
                        "pid": proc.get("pid"),
                        "cmdline": cmdline,
                        "cmdline_str": cmdline_str,
                        "target_file": target_file,
                        "ppid": proc.get("ppid"),
                        "detection_method": "process_capture",
                        "description": (
                            f"Quarantine xattr removal detected: {cmdline_str}"
                        ),
                    },
                    confidence=0.95,
                )
            )

        # Strategy 2: Stateful diff — file previously had xattr, now doesn't
        for removal in xattr_removals:
            events.append(
                self._create_event(
                    event_type="quarantine_bypass",
                    severity=Severity.CRITICAL,
                    data={
                        "target_file": removal["path"],
                        "filename": removal["filename"],
                        "file_size": removal.get("size", 0),
                        "detection_method": "stateful_xattr_diff",
                        "description": (
                            f"Quarantine xattr removed from file: "
                            f"{removal['filename']}"
                        ),
                    },
                    confidence=0.9,
                )
            )

        return events


# =============================================================================
# 2. DMGMountExecuteProbe
# =============================================================================


class DMGMountExecuteProbe(MicroProbe):
    """Detects processes executing from mounted DMG images.

    Cross-references mounted_dmgs mount_points with process_snapshot exe paths.
    DMG-based delivery is a common macOS malware vector: the attacker delivers
    a .dmg file containing a malicious app that executes from the mount point.

    MITRE: T1204.002 (User Execution: Malicious File)
    """

    name = "dmg_mount_execute"
    description = "Detects process execution from mounted DMG images"
    platforms = ["darwin"]
    mitre_techniques = ["T1204.002"]
    mitre_tactics = ["execution"]
    scan_interval = 15.0
    requires_fields = ["mounted_dmgs", "process_snapshot"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        dmgs = context.shared_data.get("mounted_dmgs", [])
        processes = context.shared_data.get("process_snapshot", [])

        if not dmgs:
            return events

        # Build set of mount points for fast lookup
        mount_points = [(dmg.mount_point, dmg.image_path) for dmg in dmgs]

        for proc in processes:
            exe = proc.get("exe", "")
            if not exe:
                continue

            for mount_point, image_path in mount_points:
                if exe.startswith(mount_point):
                    events.append(
                        self._create_event(
                            event_type="dmg_mount_execute",
                            severity=Severity.HIGH,
                            data={
                                "pid": proc.get("pid"),
                                "name": proc.get("name"),
                                "exe": exe,
                                "dmg_image_path": image_path,
                                "dmg_mount_point": mount_point,
                                "username": proc.get("username"),
                                "ppid": proc.get("ppid"),
                                "description": (
                                    f"Process {proc.get('name')} (PID {proc.get('pid')}) "
                                    f"executing from DMG mount: {mount_point}"
                                ),
                            },
                            confidence=0.8,
                        )
                    )
                    break  # One match per process

        return events


# =============================================================================
# 3. ClickFixDetectionProbe
# =============================================================================

# Messaging apps that deliver ClickFix attack instructions
_CLICKFIX_MESSAGING_APPS = frozenset(
    {
        "Messages",
        "Slack",
        "Microsoft Teams",
        "Teams",
        "Discord",
        "WhatsApp",
        "Telegram",
        "Signal",
    }
)

# Suspicious commands pasted into terminal from messaging apps
_CLICKFIX_SUSPICIOUS_COMMANDS = frozenset(
    {
        "curl",
        "wget",
        "bash",
        "sh",
        "python3",
        "python",
        "base64",
        "nc",
        "ncat",
        "osascript",
    }
)

# Patterns in cmdline args that indicate a ClickFix paste-and-run
_CLICKFIX_CMDLINE_PATTERNS = [
    "-c",  # bash -c, sh -c, python3 -c
    "| bash",
    "| sh",
    "| zsh",  # pipe to shell
    "base64",
    "eval",
]


class ClickFixDetectionProbe(MicroProbe):
    """Detects ClickFix social engineering attacks on macOS.

    ClickFix is a social engineering technique where an attacker sends a
    victim a command to copy-paste into Terminal via a messaging app.
    The victim is told to "fix" something by running a command that
    actually downloads and executes malware.

    Two detection strategies:
        1. Primary: messaging app running AND terminal has suspicious child
           processes (curl, wget, bash -c, python3 -c, base64).
        2. Secondary: messaging app running AND terminal running AND a file
           appeared in ~/Downloads without quarantine xattr (= CLI download
           from pasted command). Catches ClickFix even when curl exits before
           the psutil snapshot.

    MITRE: T1204.001 (User Execution: Malicious Link)
    """

    name = "clickfix_detection"
    description = "Detects ClickFix paste-and-run social engineering attacks"
    platforms = ["darwin"]
    mitre_techniques = ["T1204.001"]
    mitre_tactics = ["execution", "initial_access"]
    scan_interval = 10.0
    requires_fields = ["messaging_apps_running", "terminal_children"]

    _TERMINAL_EMULATORS = frozenset(
        {
            "Terminal",
            "iTerm2",
            "Warp",
            "Alacritty",
            "kitty",
            "Hyper",
        }
    )

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        messaging_apps = context.shared_data.get("messaging_apps_running", [])

        if not messaging_apps:
            return events

        terminal_children = context.shared_data.get("terminal_children", [])

        # Strategy 1: messaging app + suspicious terminal child process
        for child in terminal_children:
            child_name = child.name if hasattr(child, "name") else child.get("name", "")
            child_cmdline = (
                child.cmdline if hasattr(child, "cmdline") else child.get("cmdline", [])
            )
            child_pid = child.pid if hasattr(child, "pid") else child.get("pid", 0)
            terminal_pid = (
                child.terminal_pid
                if hasattr(child, "terminal_pid")
                else child.get("terminal_pid", 0)
            )

            cmdline_str = " ".join(child_cmdline) if child_cmdline else ""

            # Require BOTH suspicious command name AND suspicious cmdline pattern.
            # A bare "bash" while Slack is open is normal developer activity.
            # ClickFix requires a piped/eval pattern (bash -c, curl | sh, etc.)
            name_match = child_name in _CLICKFIX_SUSPICIOUS_COMMANDS
            pattern_match = any(p in cmdline_str for p in _CLICKFIX_CMDLINE_PATTERNS)
            is_suspicious = name_match and pattern_match

            if is_suspicious:
                events.append(
                    self._create_event(
                        event_type="clickfix_attack",
                        severity=Severity.HIGH,  # HIGH not CRITICAL — needs corroboration to escalate
                        data={
                            "child_pid": child_pid,
                            "child_name": child_name,
                            "child_cmdline": child_cmdline,
                            "terminal_pid": terminal_pid,
                            "messaging_apps": messaging_apps,
                            "cmdline_str": cmdline_str,
                            "detection_method": "terminal_child_capture",
                            "description": (
                                f"Possible ClickFix attack: {child_name} "
                                f"(PID {child_pid}) spawned in terminal while "
                                f"messaging apps running: {', '.join(messaging_apps)}"
                            ),
                        },
                        confidence=0.9,
                    )
                )

        # Strategy 2: messaging app + terminal running + recent CLI download
        # (catches ClickFix when curl/wget exits before psutil snapshot)
        if not events:
            downloaded_files = context.shared_data.get("downloaded_files", [])
            process_snapshot = context.shared_data.get("process_snapshot", [])

            # Check if a terminal emulator is running
            terminal_running = any(
                proc.get("name") in self._TERMINAL_EMULATORS
                for proc in process_snapshot
            )

            if terminal_running and downloaded_files:
                now = time.time()
                for f in downloaded_files:
                    has_xattr = (
                        f.has_quarantine_xattr
                        if hasattr(f, "has_quarantine_xattr")
                        else f.get("has_quarantine_xattr", True)
                    )
                    modify_time = (
                        f.modify_time
                        if hasattr(f, "modify_time")
                        else f.get("modify_time", 0)
                    )
                    filename = (
                        f.filename if hasattr(f, "filename") else f.get("filename", "")
                    )

                    # Recently modified file without quarantine = CLI download
                    if not has_xattr and (now - modify_time) < 60:
                        events.append(
                            self._create_event(
                                event_type="clickfix_attack",
                                severity=Severity.HIGH,
                                data={
                                    "filename": filename,
                                    "messaging_apps": messaging_apps,
                                    "file_age_s": round(now - modify_time, 1),
                                    "has_quarantine_xattr": False,
                                    "detection_method": "cli_download_correlation",
                                    "description": (
                                        f"Possible ClickFix: CLI-downloaded file "
                                        f"{filename} appeared while messaging apps "
                                        f"({', '.join(messaging_apps)}) and Terminal "
                                        f"are running"
                                    ),
                                },
                                confidence=0.75,
                            )
                        )

        return events


# =============================================================================
# 4. UnsignedDownloadExecutionProbe
# =============================================================================

_PERMISSION_ERRORS = ("Permission denied", "Operation not permitted")


class UnsignedDownloadExecutionProbe(MicroProbe):
    """Detects unsigned binaries executing from ~/Downloads/ or /tmp/.

    Finds processes in process_snapshot whose exe is in ~/Downloads/ or /tmp/,
    then runs codesign --verify --deep to check signature validity. Unsigned
    or invalidly signed binaries in download paths are high-risk.

    MITRE: T1553 (Subvert Trust Controls)
    """

    name = "unsigned_download_exec"
    description = "Detects unsigned binary execution from download/temp paths"
    platforms = ["darwin"]
    mitre_techniques = ["T1553"]
    mitre_tactics = ["defense_evasion"]
    scan_interval = 30.0
    requires_fields = ["process_snapshot"]

    # Paths that indicate a downloaded/temp binary
    _SUSPECT_PREFIXES = (
        str(Path.home() / "Downloads") + "/",
        "/tmp/",
        "/var/tmp/",
        "/private/tmp/",
    )

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        processes = context.shared_data.get("process_snapshot", [])

        for proc in processes:
            exe = proc.get("exe", "")
            if not exe:
                continue

            # Check if exe is in a suspect path
            if not any(exe.startswith(prefix) for prefix in self._SUSPECT_PREFIXES):
                continue

            # Verify code signature
            if not os.path.exists(exe):
                continue

            try:
                result = subprocess.run(
                    ["codesign", "--verify", "--deep", exe],
                    capture_output=True,
                    text=True,
                    timeout=3,
                )

                if result.returncode != 0:
                    stderr = result.stderr.strip()

                    # Permission denied is not an alert
                    if any(err in stderr for err in _PERMISSION_ERRORS):
                        continue

                    events.append(
                        self._create_event(
                            event_type="unsigned_download_execution",
                            severity=Severity.HIGH,
                            data={
                                "pid": proc.get("pid"),
                                "name": proc.get("name"),
                                "exe": exe,
                                "codesign_error": stderr,
                                "codesign_returncode": result.returncode,
                                "username": proc.get("username"),
                                "ppid": proc.get("ppid"),
                                "description": (
                                    f"Unsigned binary executing from download path: {exe}"
                                ),
                            },
                            confidence=0.75,
                        )
                    )

            except subprocess.TimeoutExpired:
                logger.warning("codesign timeout for %s", exe)
            except Exception as e:
                logger.debug("codesign check failed for %s: %s", exe, e)

        return events


# =============================================================================
# 5. CLIDownloadExecuteProbe
# =============================================================================


class CLIDownloadExecuteProbe(MicroProbe):
    """Detects CLI-downloaded files being executed (bypassing quarantine).

    CLI tools (curl, wget) do not set the com.apple.quarantine xattr on
    downloaded files. This means Gatekeeper never checks them. This probe
    detects files in ~/Downloads that lack the quarantine xattr AND have a
    corresponding running process, or detects curl/wget parent-child chains
    where the child is executing from /tmp or ~/Downloads.

    MITRE: T1105 (Ingress Tool Transfer)
    """

    name = "cli_download_execute"
    description = "Detects CLI download + execution bypassing quarantine"
    platforms = ["darwin"]
    mitre_techniques = ["T1105"]
    mitre_tactics = ["command_and_control"]
    scan_interval = 15.0
    requires_fields = ["downloaded_files", "process_snapshot"]

    # CLI download tools
    _CLI_DOWNLOADERS = frozenset({"curl", "wget", "fetch", "ftp"})

    # Execution paths to watch
    _EXEC_PATHS = (
        str(Path.home() / "Downloads") + "/",
        "/tmp/",
        "/var/tmp/",
        "/private/tmp/",
    )

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        downloaded_files = context.shared_data.get("downloaded_files", [])
        processes = context.shared_data.get("process_snapshot", [])

        # Strategy 1: downloaded_files without quarantine xattr + running process
        no_xattr_files = {}
        for f in downloaded_files:
            path = f.path if hasattr(f, "path") else f.get("path", "")
            has_xattr = (
                f.has_quarantine_xattr
                if hasattr(f, "has_quarantine_xattr")
                else f.get("has_quarantine_xattr", True)
            )
            if not has_xattr:
                no_xattr_files[path] = f

        if no_xattr_files:
            for proc in processes:
                exe = proc.get("exe", "")
                if exe in no_xattr_files:
                    df = no_xattr_files[exe]
                    filename = (
                        df.filename
                        if hasattr(df, "filename")
                        else df.get("filename", "")
                    )
                    events.append(
                        self._create_event(
                            event_type="cli_download_execute",
                            severity=Severity.HIGH,
                            data={
                                "pid": proc.get("pid"),
                                "name": proc.get("name"),
                                "exe": exe,
                                "filename": filename,
                                "has_quarantine_xattr": False,
                                "username": proc.get("username"),
                                "description": (
                                    f"CLI-downloaded file executing without quarantine: "
                                    f"{filename}"
                                ),
                            },
                            confidence=0.8,
                        )
                    )

        # Strategy 2: curl/wget parent → child executing from suspect paths
        # Build PID lookup
        pid_map = {proc.get("pid"): proc for proc in processes}

        for proc in processes:
            exe = proc.get("exe", "")
            if not exe:
                continue

            if not any(exe.startswith(prefix) for prefix in self._EXEC_PATHS):
                continue

            # Check if parent is a CLI downloader
            ppid = proc.get("ppid", 0)
            parent = pid_map.get(ppid)
            if parent and parent.get("name") in self._CLI_DOWNLOADERS:
                events.append(
                    self._create_event(
                        event_type="cli_download_chain",
                        severity=Severity.HIGH,
                        data={
                            "pid": proc.get("pid"),
                            "name": proc.get("name"),
                            "exe": exe,
                            "parent_pid": ppid,
                            "parent_name": parent.get("name"),
                            "parent_cmdline": parent.get("cmdline"),
                            "description": (
                                f"Download-execute chain: {parent.get('name')} "
                                f"(PID {ppid}) -> {proc.get('name')} from {exe}"
                            ),
                        },
                        confidence=0.8,
                    )
                )

        return events


# =============================================================================
# 6. SuspiciousDownloadSourceProbe
# =============================================================================

_KNOWN_SAFE_DOMAINS = frozenset(
    {
        "apple.com",
        "cdn.apple.com",
        "github.com",
        "githubusercontent.com",
        "google.com",
        "googleapis.com",
        "mozilla.org",
        "mozilla.net",
        "microsoft.com",
        "npmjs.org",
        "pypi.org",
        "brew.sh",
        "cloudflare.com",
        "akamaized.net",
        "amazonaws.com",
    }
)


class SuspiciousDownloadSourceProbe(MicroProbe):
    """Detects downloads from unknown or suspicious domains.

    Examines quarantine_entries from the macOS quarantine database. If the
    download URL domain is not in a curated known-safe set, the download
    is flagged for analyst review. This is a low-confidence signal — many
    legitimate downloads come from uncommon domains.

    MITRE: T1566 (Phishing)
    """

    name = "suspicious_download_source"
    description = "Detects downloads from unknown or suspicious domains"
    platforms = ["darwin"]
    mitre_techniques = ["T1566"]
    mitre_tactics = ["initial_access"]
    scan_interval = 30.0
    requires_fields = ["quarantine_entries"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        entries = context.shared_data.get("quarantine_entries", [])

        for entry in entries:
            data_url = (
                entry.data_url
                if hasattr(entry, "data_url")
                else entry.get("data_url", "")
            )
            if not data_url:
                continue

            domain = self._extract_domain(data_url)
            if not domain:
                continue

            # Check if domain or any parent domain is in the safe set
            if self._is_safe_domain(domain):
                continue

            agent_bundle = (
                entry.agent_bundle_id
                if hasattr(entry, "agent_bundle_id")
                else entry.get("agent_bundle_id", "")
            )
            origin_url = (
                entry.origin_url
                if hasattr(entry, "origin_url")
                else entry.get("origin_url", "")
            )
            timestamp = (
                entry.timestamp
                if hasattr(entry, "timestamp")
                else entry.get("timestamp", 0)
            )

            events.append(
                self._create_event(
                    event_type="suspicious_download_source",
                    severity=Severity.MEDIUM,
                    data={
                        "data_url": data_url,
                        "domain": domain,
                        "origin_url": origin_url,
                        "agent_bundle_id": agent_bundle,
                        "timestamp": timestamp,
                        "description": (f"Download from unrecognized domain: {domain}"),
                    },
                    confidence=0.6,
                )
            )

        return events

    @staticmethod
    def _extract_domain(url: str) -> str:
        """Extract the registerable domain from a URL."""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                return ""
            return hostname.lower()
        except Exception:
            return ""

    @staticmethod
    def _is_safe_domain(domain: str) -> bool:
        """Check if domain or any parent domain is in the known-safe set."""
        # Direct match
        if domain in _KNOWN_SAFE_DOMAINS:
            return True

        # Check parent domains: sub.example.com -> example.com
        parts = domain.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in _KNOWN_SAFE_DOMAINS:
                return True

        return False


# =============================================================================
# 7. InstallerScriptAbuseProbe
# =============================================================================

# Suspicious commands spawned by installer/pkgutil
_INSTALLER_SUSPICIOUS_CHILDREN = frozenset(
    {
        "curl",
        "wget",
        "bash",
        "sh",
        "nc",
        "ncat",
        "python3",
        "python",
        "osascript",
        "base64",
        "openssl",
    }
)


class InstallerScriptAbuseProbe(MicroProbe):
    """Detects macOS installer packages spawning suspicious child processes.

    Malicious .pkg files can contain pre/post-install scripts that execute
    arbitrary commands. This probe watches for installer/pkgutil processes
    with children running curl, wget, bash -c, nc, python3 -c, etc.

    MITRE: T1059.002 (Command and Scripting Interpreter: AppleScript)
    """

    name = "installer_script_abuse"
    description = "Detects installer packages spawning suspicious commands"
    platforms = ["darwin"]
    mitre_techniques = ["T1059.002"]
    mitre_tactics = ["execution"]
    scan_interval = 15.0
    requires_fields = ["installer_processes"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        installer_procs = context.shared_data.get("installer_processes", [])

        for installer in installer_procs:
            children = installer.get("children", [])

            for child in children:
                child_name = child.get("name", "")
                child_cmdline = child.get("cmdline", [])

                is_suspicious = child_name in _INSTALLER_SUSPICIOUS_CHILDREN
                if not is_suspicious and child_cmdline:
                    # Check for bash -c, sh -c, python3 -c patterns
                    cmdline_str = " ".join(child_cmdline)
                    if "-c" in child_cmdline:
                        for cmd in ("bash", "sh", "zsh", "python3"):
                            if cmd in cmdline_str:
                                is_suspicious = True
                                break

                if is_suspicious:
                    events.append(
                        self._create_event(
                            event_type="installer_script_abuse",
                            severity=Severity.HIGH,
                            data={
                                "installer_pid": installer.get("pid"),
                                "installer_name": installer.get("name"),
                                "installer_cmdline": installer.get("cmdline"),
                                "child_pid": child.get("pid"),
                                "child_name": child_name,
                                "child_cmdline": child_cmdline,
                                "description": (
                                    f"Installer (PID {installer.get('pid')}) "
                                    f"spawned suspicious child: {child_name} "
                                    f"(PID {child.get('pid')})"
                                ),
                            },
                            confidence=0.8,
                        )
                    )

        return events


# =============================================================================
# 8. QuarantineEvasionPatternProbe
# =============================================================================


class QuarantineEvasionPatternProbe(MicroProbe):
    """Detects quarantine evasion: file without xattr + executing process.

    Finds files in ~/Downloads that lack the quarantine xattr (indicating
    they were downloaded via CLI, not a browser) AND a process in the
    snapshot is running from that file's path. This is a strong signal of
    deliberate quarantine bypass.

    MITRE: T1553.001 (Subvert Trust Controls: Gatekeeper Bypass)
    """

    name = "quarantine_evasion_pattern"
    description = "Detects files without quarantine xattr being executed"
    platforms = ["darwin"]
    mitre_techniques = ["T1553.001"]
    mitre_tactics = ["defense_evasion"]
    scan_interval = 15.0
    requires_fields = ["downloaded_files", "process_snapshot"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        downloaded_files = context.shared_data.get("downloaded_files", [])
        processes = context.shared_data.get("process_snapshot", [])

        # Build set of files without quarantine xattr
        no_xattr_paths: Dict[str, Any] = {}
        for f in downloaded_files:
            path = f.path if hasattr(f, "path") else f.get("path", "")
            has_xattr = (
                f.has_quarantine_xattr
                if hasattr(f, "has_quarantine_xattr")
                else f.get("has_quarantine_xattr", True)
            )
            if not has_xattr and path:
                no_xattr_paths[path] = f

        if not no_xattr_paths:
            return events

        # Check if any process is running from a file without quarantine xattr
        for proc in processes:
            exe = proc.get("exe", "")
            if not exe:
                continue

            if exe in no_xattr_paths:
                df = no_xattr_paths[exe]
                filename = (
                    df.filename if hasattr(df, "filename") else df.get("filename", "")
                )
                size = df.size if hasattr(df, "size") else df.get("size", 0)

                events.append(
                    self._create_event(
                        event_type="quarantine_evasion_pattern",
                        severity=Severity.HIGH,
                        data={
                            "pid": proc.get("pid"),
                            "name": proc.get("name"),
                            "exe": exe,
                            "filename": filename,
                            "file_size": size,
                            "has_quarantine_xattr": False,
                            "username": proc.get("username"),
                            "description": (
                                f"Process {proc.get('name')} (PID {proc.get('pid')}) "
                                f"executing from {filename} which lacks quarantine xattr"
                            ),
                        },
                        confidence=0.8,
                    )
                )

        return events


# =============================================================================
# Factory
# =============================================================================


def create_quarantine_guard_probes() -> List[MicroProbe]:
    """Create all macOS quarantine guard probes."""
    return [
        QuarantineBypassProbe(),
        DMGMountExecuteProbe(),
        ClickFixDetectionProbe(),
        UnsignedDownloadExecutionProbe(),
        CLIDownloadExecuteProbe(),
        SuspiciousDownloadSourceProbe(),
        InstallerScriptAbuseProbe(),
        QuarantineEvasionPatternProbe(),
    ]
