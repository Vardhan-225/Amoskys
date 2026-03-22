"""macOS File Observatory Probes — 8 detection probes for filesystem integrity.

Each probe consumes FileEntry data from MacOSFileCollector via shared_data.
Uses baseline-diff pattern: stores previous hashes to detect new, modified,
and removed files.

Probes:
    1. CriticalFileProbe — baseline-diff on critical system files
    2. SuidChangeProbe — new/modified SUID binaries
    3. ConfigBackdoorProbe — suspicious config file modifications
    4. WebshellProbe — webshell files in web directories
    5. QuarantineBypassProbe — xattr quarantine flag bypass
    6. SipStatusProbe — SIP disabled alert
    7. HiddenFileProbe — new hidden files in sensitive locations
    8. DownloadsMonitorProbe — new files in ~/Downloads

MITRE: T1565, T1548.001, T1070, T1505.003, T1553.001, T1562.001, T1564.001, T1204
"""

from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)
from amoskys.agents.common.process_resolver import resolve_file_owner_process

logger = logging.getLogger(__name__)


def _attribute_file_change(file_path: str) -> Dict[str, Any]:
    """Resolve process context for a file change and add file metadata."""
    enrichment: Dict[str, Any] = {"detection_source": "filesystem_monitor"}
    # File context fields
    enrichment["file_name"] = os.path.basename(file_path)
    enrichment["file_extension"] = os.path.splitext(file_path)[1]
    # Process attribution via lsof
    snap = resolve_file_owner_process(file_path)
    if snap and snap.is_alive:
        enrichment.update(snap.to_event_fields())
    return enrichment


# =============================================================================
# Base: _BaselineDiffProbe (file hash tracking)
# =============================================================================


class _BaselineDiffProbe(MicroProbe):
    """Base class for baseline-diff file probes.

    Tracks sha256 per path. Detects:
        - NEW: path not in baseline
        - MODIFIED: path exists but hash changed
        - REMOVED: path was in baseline but not in current scan
    """

    _target_paths: List[str] = []  # Override: specific paths to watch
    _target_prefixes: List[str] = []  # Override: path prefixes to match
    platforms = ["darwin"]
    requires_fields = ["files"]

    def __init__(self) -> None:
        super().__init__()
        self._baseline: Dict[str, str] = {}  # path -> sha256
        self._baseline_mtime: Dict[str, float] = (
            {}
        )  # path -> mtime (timestomping detection)
        self._first_run = True

    def _matches(self, entry: Any) -> bool:
        """Check if a FileEntry matches this probe's target scope."""
        path = entry.path
        if self._target_paths and path in self._target_paths:
            return True
        for prefix in self._target_prefixes:
            if path.startswith(prefix):
                return True
        return False

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        files = context.shared_data.get("files", [])

        # Filter to our targets
        current: Dict[str, Any] = {}
        for entry in files:
            if self._matches(entry):
                current[entry.path] = entry

        if self._first_run:
            self._baseline = {path: e.sha256 for path, e in current.items()}
            self._baseline_mtime = {path: e.mtime for path, e in current.items()}
            self._first_run = False
            return events

        # Detect NEW files
        for path, entry in current.items():
            if path not in self._baseline:
                events.append(
                    self._make_file_event(
                        "new",
                        entry,
                        Severity.HIGH,
                    )
                )

        # Detect MODIFIED files
        for path, entry in current.items():
            if path in self._baseline and entry.sha256:
                prev_hash = self._baseline[path]
                prev_mtime = self._baseline_mtime.get(path, 0)

                if entry.sha256 != prev_hash:
                    events.append(
                        self._make_file_event(
                            "modified",
                            entry,
                            Severity.HIGH,
                        )
                    )
                    # Timestomping detection: hash changed but mtime went backwards
                    if prev_mtime > 0 and entry.mtime < prev_mtime:
                        events.append(
                            self._create_event(
                                event_type=f"{self.name}_timestomping",
                                severity=Severity.HIGH,
                                data={
                                    **_attribute_file_change(entry.path),
                                    "path": entry.path,
                                    "current_mtime": entry.mtime,
                                    "previous_mtime": prev_mtime,
                                    "sha256": entry.sha256,
                                    "detection": "mtime_regression",
                                },
                                confidence=0.85,
                                mitre_techniques=["T1070.006"],
                            )
                        )

        # Detect REMOVED files
        for path in self._baseline:
            if path not in current:
                events.append(
                    self._create_event(
                        event_type=f"{self.name}_removed",
                        severity=Severity.MEDIUM,
                        data={
                            "detection_source": "filesystem_monitor",
                            "file_name": os.path.basename(path),
                            "file_extension": os.path.splitext(path)[1],
                            "path": path,
                            "change_type": "removed",
                        },
                        confidence=0.9,
                    )
                )

        # Update baseline (hash + mtime for timestomping detection)
        self._baseline = {path: e.sha256 for path, e in current.items()}
        self._baseline_mtime = {path: e.mtime for path, e in current.items()}

        return events

    def _make_file_event(
        self, change_type: str, entry: Any, severity: Severity
    ) -> TelemetryEvent:
        """Create event for a file change."""
        data: Dict[str, Any] = {
            **_attribute_file_change(entry.path),
            "path": entry.path,
            "name": entry.name,
            "sha256": entry.sha256,
            "mtime": entry.mtime,
            "size": entry.size,
            "mode": oct(entry.mode),
            "uid": entry.uid,
            "change_type": change_type,
        }
        if entry.is_suid:
            data["is_suid"] = True

        return self._create_event(
            event_type=f"{self.name}_{change_type}",
            severity=severity,
            data=data,
            confidence=0.9,
        )


# =============================================================================
# 1. CriticalFileProbe
# =============================================================================


class CriticalFileProbe(_BaselineDiffProbe):
    """Detects changes to critical macOS system files.

    Monitors /etc/hosts, /etc/resolv.conf, /etc/sudoers, /etc/passwd,
    /etc/group, /etc/shells, sshd_config, pam.d/sudo, etc.
    Any modification to these files outside of a known update is suspicious.

    MITRE: T1565 (Data Manipulation)
    """

    name = "macos_critical_file"
    description = "Detects changes to critical macOS system files"
    mitre_techniques = ["T1565"]
    mitre_tactics = ["impact"]
    scan_interval = 60.0

    _target_paths = [
        "/etc/hosts",
        "/etc/resolv.conf",
        "/etc/sudoers",
        "/etc/passwd",
        "/etc/group",
        "/etc/shells",
        "/etc/pam.d/sudo",
        "/etc/ssh/sshd_config",
        "/etc/auto_master",
        "/etc/fstab",
        "/etc/newsyslog.conf",
        "/etc/syslog.conf",
    ]

    def _make_file_event(
        self, change_type: str, entry: Any, severity: Severity
    ) -> TelemetryEvent:
        # sudoers and passwd changes are CRITICAL
        if entry.name in ("sudoers", "passwd", "sshd_config"):
            severity = Severity.CRITICAL
        return super()._make_file_event(change_type, entry, severity)


# =============================================================================
# 2. SuidChangeProbe
# =============================================================================


class SuidChangeProbe(MicroProbe):
    """Detects new or modified SUID binaries.

    SUID binaries run with the file owner's privileges (often root).
    A new SUID binary is a strong privilege escalation indicator.

    MITRE: T1548.001 (Abuse Elevation Control: Setuid and Setgid)
    """

    name = "macos_suid_change"
    description = "Detects new/modified SUID binaries"
    mitre_techniques = ["T1548.001"]
    mitre_tactics = ["privilege_escalation", "defense_evasion"]
    platforms = ["darwin"]
    requires_fields = ["suid_binaries"]
    scan_interval = 60.0

    def __init__(self) -> None:
        super().__init__()
        self._baseline: Dict[str, str] = {}  # path -> sha256
        self._first_run = True

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        suid_binaries = context.shared_data.get("suid_binaries", [])

        current = {e.path: e.sha256 for e in suid_binaries}

        if self._first_run:
            self._baseline = dict(current)
            self._first_run = False
            return events

        # New SUID binaries
        for path, sha in current.items():
            if path not in self._baseline:
                entry = next((e for e in suid_binaries if e.path == path), None)
                events.append(
                    self._create_event(
                        event_type="macos_suid_new",
                        severity=Severity.CRITICAL,
                        data={
                            **_attribute_file_change(path),
                            "path": path,
                            "name": entry.name if entry else os.path.basename(path),
                            "sha256": sha,
                            "change_type": "new_suid",
                        },
                        confidence=0.95,
                    )
                )

        # Modified SUID binaries
        for path, sha in current.items():
            if path in self._baseline and sha and sha != self._baseline[path]:
                events.append(
                    self._create_event(
                        event_type="macos_suid_modified",
                        severity=Severity.CRITICAL,
                        data={
                            **_attribute_file_change(path),
                            "path": path,
                            "sha256": sha,
                            "previous_sha256": self._baseline[path],
                            "change_type": "modified_suid",
                        },
                        confidence=0.95,
                    )
                )

        # Removed SUID binaries (could indicate cleanup)
        for path in self._baseline:
            if path not in current:
                events.append(
                    self._create_event(
                        event_type="macos_suid_removed",
                        severity=Severity.MEDIUM,
                        data={
                            "detection_source": "filesystem_monitor",
                            "file_name": os.path.basename(path),
                            "file_extension": os.path.splitext(path)[1],
                            "path": path,
                            "change_type": "removed_suid",
                        },
                        confidence=0.8,
                    )
                )

        self._baseline = dict(current)
        return events


# =============================================================================
# 3. ConfigBackdoorProbe
# =============================================================================


class ConfigBackdoorProbe(_BaselineDiffProbe):
    """Detects suspicious modifications to system configuration files.

    Monitors config files in /etc and /Library/Preferences for changes
    that could indicate backdoor installation or defense evasion.

    MITRE: T1070 (Indicator Removal)
    """

    name = "macos_config_backdoor"
    description = "Detects suspicious config file modifications"
    mitre_techniques = ["T1070"]
    mitre_tactics = ["defense_evasion"]
    scan_interval = 60.0

    _target_prefixes = [
        "/etc/",
        "/Library/Preferences/",
    ]

    # Exclude noisy files that change frequently
    _EXCLUDE_NAMES: Set[str] = {
        ".DS_Store",
        "com.apple.preferences.plist",
    }

    def _matches(self, entry: Any) -> bool:
        if entry.name in self._EXCLUDE_NAMES:
            return False
        return super()._matches(entry)

    def _make_file_event(
        self, change_type: str, entry: Any, severity: Severity
    ) -> TelemetryEvent:
        # Audit/security config changes are CRITICAL
        if any(kw in entry.name.lower() for kw in ("audit", "security", "pam", "sudo")):
            severity = Severity.CRITICAL
        elif change_type == "new":
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM
        return super()._make_file_event(change_type, entry, severity)


# =============================================================================
# 4. WebshellProbe
# =============================================================================


class WebshellProbe(MicroProbe):
    """Detects webshell files in common web server directories.

    Scans for script files (php, jsp, aspx, py, pl, cgi, sh) in
    macOS web directories: /Library/WebServer, ~/Sites, /var/www.

    MITRE: T1505.003 (Server Software Component: Web Shell)
    """

    name = "macos_webshell"
    description = "Detects webshell files in web directories"
    mitre_techniques = ["T1505.003"]
    mitre_tactics = ["persistence"]
    platforms = ["darwin"]
    requires_fields = ["files"]
    scan_interval = 60.0

    _WEB_DIRS = [
        "/Library/WebServer",
        "/var/www",
    ]

    _WEBSHELL_EXTENSIONS = {
        ".php",
        ".jsp",
        ".jspx",
        ".aspx",
        ".asp",
        ".py",
        ".pl",
        ".cgi",
        ".sh",
        ".rb",
    }

    def __init__(self) -> None:
        super().__init__()
        self._home = str(Path.home())
        self._baseline: Set[str] = set()
        self._first_run = True

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        files = context.shared_data.get("files", [])

        web_dirs = self._WEB_DIRS + [os.path.join(self._home, "Sites")]

        # Find script files in web directories
        current: Set[str] = set()
        for entry in files:
            _, ext = os.path.splitext(entry.name.lower())
            if ext not in self._WEBSHELL_EXTENSIONS:
                continue
            for web_dir in web_dirs:
                if entry.path.startswith(web_dir):
                    current.add(entry.path)
                    break

        if self._first_run:
            self._baseline = current
            self._first_run = False
            return events

        # New script files in web directories
        for path in current - self._baseline:
            entry = next((e for e in files if e.path == path), None)
            events.append(
                self._create_event(
                    event_type="macos_webshell_detected",
                    severity=Severity.CRITICAL,
                    data={
                        **_attribute_file_change(path),
                        "path": path,
                        "name": entry.name if entry else os.path.basename(path),
                        "sha256": entry.sha256 if entry else "",
                        "size": entry.size if entry else 0,
                    },
                    confidence=0.85,
                )
            )

        self._baseline = current
        return events


# =============================================================================
# 5. QuarantineBypassProbe
# =============================================================================


class QuarantineBypassProbe(MicroProbe):
    """Detects quarantine flag bypass on downloaded files.

    macOS tags downloaded files with com.apple.quarantine xattr.
    Removal of this flag bypasses Gatekeeper checks. Runs degraded
    if xattr command is unavailable.

    MITRE: T1553.001 (Subvert Trust Controls: Gatekeeper Bypass)
    """

    name = "macos_quarantine_bypass"
    description = "Detects quarantine flag bypass on downloaded files"
    mitre_techniques = ["T1553.001"]
    mitre_tactics = ["defense_evasion"]
    platforms = ["darwin"]
    requires_fields = ["files"]
    degraded_without = ["files"]  # Can degrade gracefully
    scan_interval = 60.0

    # Extensions commonly checked for quarantine
    _EXECUTABLE_EXTENSIONS = {
        ".app",
        ".dmg",
        ".pkg",
        ".command",
        ".sh",
        ".py",
        ".rb",
        ".pl",
        ".scpt",
        ".workflow",
    }

    def __init__(self) -> None:
        super().__init__()
        self._home = str(Path.home())
        self._xattr_available = self._check_xattr()
        self._seen_unquarantined: Set[str] = set()

    def _check_xattr(self) -> bool:
        """Verify xattr command is available."""
        try:
            subprocess.run(
                ["xattr", "--help"],
                capture_output=True,
                timeout=3,
            )
            return True
        except Exception:
            return False

    def _has_quarantine(self, path: str) -> Optional[bool]:
        """Check if file has com.apple.quarantine xattr.

        Returns True/False, or None if xattr check failed.
        """
        if not self._xattr_available:
            return None
        try:
            result = subprocess.run(
                ["xattr", "-l", path],
                capture_output=True,
                text=True,
                timeout=3,
            )
            return "com.apple.quarantine" in result.stdout
        except Exception:
            return None

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []

        if not self._xattr_available:
            return events

        files = context.shared_data.get("files", [])
        downloads_dir = os.path.join(self._home, "Downloads")

        for entry in files:
            if not entry.path.startswith(downloads_dir):
                continue

            _, ext = os.path.splitext(entry.name.lower())
            if ext not in self._EXECUTABLE_EXTENSIONS:
                continue

            # Skip already-seen unquarantined files
            if entry.path in self._seen_unquarantined:
                continue

            has_q = self._has_quarantine(entry.path)
            if has_q is False:
                self._seen_unquarantined.add(entry.path)
                events.append(
                    self._create_event(
                        event_type="macos_quarantine_bypass",
                        severity=Severity.HIGH,
                        data={
                            **_attribute_file_change(entry.path),
                            "path": entry.path,
                            "name": entry.name,
                            "extension": ext,
                            "size": entry.size,
                        },
                        confidence=0.8,
                    )
                )

        return events


# =============================================================================
# 6. SipStatusProbe
# =============================================================================


class SipStatusProbe(MicroProbe):
    """Detects SIP (System Integrity Protection) disabled state.

    SIP protects critical system paths from modification. If SIP is
    disabled, the system is vulnerable to rootkit installation.

    MITRE: T1562.001 (Impair Defenses: Disable or Modify Tools)
    """

    name = "macos_sip_status"
    description = "Detects SIP disabled state"
    mitre_techniques = ["T1562.001"]
    mitre_tactics = ["defense_evasion"]
    platforms = ["darwin"]
    requires_fields = ["sip_status"]
    scan_interval = 300.0  # Every 5 minutes — SIP doesn't change often

    def __init__(self) -> None:
        super().__init__()
        self._last_status: Optional[str] = None

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        sip_status = context.shared_data.get("sip_status", "unknown")

        if sip_status == "disabled":
            events.append(
                self._create_event(
                    event_type="macos_sip_disabled",
                    severity=Severity.CRITICAL,
                    data={
                        "detection_source": "filesystem_monitor",
                        "sip_status": sip_status,
                        "previous_status": self._last_status or "unknown",
                    },
                    confidence=1.0,
                )
            )
        elif self._last_status == "enabled" and sip_status == "unknown":
            events.append(
                self._create_event(
                    event_type="macos_sip_status_unknown",
                    severity=Severity.MEDIUM,
                    data={
                        "detection_source": "filesystem_monitor",
                        "sip_status": sip_status,
                        "previous_status": self._last_status,
                    },
                    confidence=0.7,
                )
            )

        self._last_status = sip_status
        return events


# =============================================================================
# 7. HiddenFileProbe
# =============================================================================


class HiddenFileProbe(MicroProbe):
    """Detects new hidden files (dot-files) in sensitive locations.

    Attackers create hidden files to stash tools, scripts, or data.
    Monitors /tmp, /var/tmp, ~/Library, /usr/local for new dot-files.

    MITRE: T1564.001 (Hide Artifacts: Hidden Files and Directories)
    """

    name = "macos_hidden_file"
    description = "Detects new hidden files in sensitive locations"
    mitre_techniques = ["T1564.001"]
    mitre_tactics = ["defense_evasion"]
    platforms = ["darwin"]
    requires_fields = ["files"]
    scan_interval = 60.0

    _SENSITIVE_PREFIXES = [
        "/tmp/",
        "/var/tmp/",
        "/usr/local/",
    ]

    # Ignore well-known hidden files
    _IGNORE_NAMES: Set[str] = {
        ".DS_Store",
        ".localized",
        ".gitignore",
        ".gitkeep",
        ".CFUserTextEncoding",
        ".Trash",
    }

    def __init__(self) -> None:
        super().__init__()
        self._home = str(Path.home())
        self._baseline: Set[str] = set()
        self._first_run = True

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        files = context.shared_data.get("files", [])

        prefixes = self._SENSITIVE_PREFIXES + [
            os.path.join(self._home, "Library") + "/",
            os.path.join(self._home, "Downloads") + "/",
            os.path.join(self._home, "Desktop") + "/",
        ]

        # Find hidden files in sensitive locations
        current: Set[str] = set()
        for entry in files:
            if not entry.name.startswith("."):
                continue
            if entry.name in self._IGNORE_NAMES:
                continue
            for prefix in prefixes:
                if entry.path.startswith(prefix):
                    current.add(entry.path)
                    break

        if self._first_run:
            self._baseline = current
            self._first_run = False
            return events

        # New hidden files
        for path in current - self._baseline:
            entry = next((e for e in files if e.path == path), None)
            events.append(
                self._create_event(
                    event_type="macos_hidden_file_new",
                    severity=Severity.MEDIUM,
                    data={
                        **_attribute_file_change(path),
                        "path": path,
                        "name": entry.name if entry else os.path.basename(path),
                        "sha256": entry.sha256 if entry else "",
                        "size": entry.size if entry else 0,
                        "uid": entry.uid if entry else -1,
                    },
                    confidence=0.7,
                )
            )

        self._baseline = current
        return events


# =============================================================================
# 8. DownloadsMonitorProbe
# =============================================================================


class DownloadsMonitorProbe(MicroProbe):
    """Detects new files in ~/Downloads (potential initial access).

    Monitors for new files appearing in the user's Downloads folder,
    especially executables and archives. Not every download is malicious,
    but this creates a forensic trail for incident response.

    MITRE: T1204 (User Execution)
    """

    name = "macos_downloads_monitor"
    description = "Detects new files in ~/Downloads"
    mitre_techniques = ["T1204"]
    mitre_tactics = ["execution"]
    platforms = ["darwin"]
    requires_fields = ["files"]
    scan_interval = 30.0

    _HIGH_RISK_EXTENSIONS = {
        ".dmg",
        ".pkg",
        ".app",
        ".command",
        ".sh",
        ".py",
        ".rb",
        ".pl",
        ".scpt",
        ".workflow",
        ".zip",
        ".tar",
        ".gz",
        ".rar",
        ".7z",
        ".iso",
        ".img",
    }

    def __init__(self) -> None:
        super().__init__()
        self._home = str(Path.home())
        self._baseline: Set[str] = set()
        self._first_run = True

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        files = context.shared_data.get("files", [])

        downloads_dir = os.path.join(self._home, "Downloads")

        current: Set[str] = set()
        for entry in files:
            if entry.path.startswith(downloads_dir + "/"):
                current.add(entry.path)

        if self._first_run:
            self._baseline = current
            self._first_run = False
            return events

        # New files in Downloads
        for path in current - self._baseline:
            entry = next((e for e in files if e.path == path), None)
            name = entry.name if entry else os.path.basename(path)
            _, ext = os.path.splitext(name.lower())

            severity = (
                Severity.HIGH if ext in self._HIGH_RISK_EXTENSIONS else Severity.LOW
            )

            events.append(
                self._create_event(
                    event_type="macos_download_new",
                    severity=severity,
                    data={
                        **_attribute_file_change(path),
                        "path": path,
                        "name": name,
                        "extension": ext,
                        "sha256": entry.sha256 if entry else "",
                        "size": entry.size if entry else 0,
                        "high_risk": ext in self._HIGH_RISK_EXTENSIONS,
                    },
                    confidence=0.6,
                )
            )

        self._baseline = current
        return events


# =============================================================================
# Factory
# =============================================================================


def create_filesystem_probes() -> List[MicroProbe]:
    """Create all macOS filesystem probes."""
    return [
        CriticalFileProbe(),
        SuidChangeProbe(),
        ConfigBackdoorProbe(),
        WebshellProbe(),
        QuarantineBypassProbe(),
        SipStatusProbe(),
        HiddenFileProbe(),
        DownloadsMonitorProbe(),
    ]
