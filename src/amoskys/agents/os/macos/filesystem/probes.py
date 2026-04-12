"""macOS File Observatory Probes — 10 detection probes for filesystem integrity.

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
    9. AirDropFileArrivalProbe — AirDrop-delivered files with quarantine xattr
   10. LogTamperingProbe — log truncation, deletion, and permission changes

MITRE: T1565, T1548.001, T1070, T1070.002, T1505.003, T1553.001, T1562.001,
       T1564.001, T1204, T1105, T1204.002
"""

from __future__ import annotations

import glob as _glob
import logging
import os
import sqlite3
import stat
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)
from amoskys.agents.common.process_resolver import resolve_file_owner_process

logger = logging.getLogger(__name__)

# Default base directory for baseline databases
_BASELINE_DB_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..",
    "..",
    "..",
    "..",
    "..",
    "data",
    "baselines",
)


class BaselineStore:
    """SQLite-backed baseline persistence for _BaselineDiffProbe.

    Stores path -> content_hash mappings so baselines survive restarts.
    Without this, malware planted before a restart is silently absorbed
    as baseline and goes undetected.
    """

    _SCHEMA = """
        CREATE TABLE IF NOT EXISTS baseline (
            path TEXT PRIMARY KEY,
            content_hash TEXT NOT NULL,
            category TEXT NOT NULL,
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL
        )
    """

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._conn = sqlite3.connect(db_path, timeout=5.0)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(self._SCHEMA)
        self._conn.commit()

    def load(self) -> Dict[str, str]:
        """Load persisted baseline into memory. Returns path -> content_hash."""
        rows = self._conn.execute("SELECT path, content_hash FROM baseline").fetchall()
        return {row[0]: row[1] for row in rows}

    def has_baseline(self) -> bool:
        """Return True if the DB has any baseline rows (not first-ever run)."""
        row = self._conn.execute("SELECT COUNT(*) FROM baseline").fetchone()
        return row[0] > 0

    def persist(self, entries: Dict[str, tuple]) -> None:
        """Persist current baseline to DB.

        Args:
            entries: Dict of path -> (content_hash, category) tuples.
        """
        now = time.time()
        # Load existing first_seen times so we preserve them
        existing = {}
        for row in self._conn.execute(
            "SELECT path, first_seen FROM baseline"
        ).fetchall():
            existing[row[0]] = row[1]

        self._conn.execute("DELETE FROM baseline")
        for path, (content_hash, category) in entries.items():
            first_seen = existing.get(path, now)
            self._conn.execute(
                "INSERT INTO baseline (path, content_hash, category, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?)",
                (path, content_hash, category, first_seen, now),
            )
        self._conn.commit()

    def close(self) -> None:
        """Close the database connection."""
        try:
            self._conn.close()
        except Exception:
            pass


# Shared constant: executable file extensions used by QuarantineBypassProbe
# and AirDropFileArrivalProbe to avoid duplication.
_EXECUTABLE_FILE_EXTENSIONS = frozenset(
    {
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
)


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

    Baseline is persisted to SQLite so that malware planted before a
    restart is NOT silently absorbed. Only the very first run (empty DB)
    absorbs silently.
    """

    _target_paths: List[str] = []  # Override: specific paths to watch
    _target_prefixes: List[str] = []  # Override: path prefixes to match
    platforms = ["darwin"]
    requires_fields = ["files"]

    def __init__(self, baseline_db_path: Optional[str] = None) -> None:
        super().__init__()
        # Resolve DB path: explicit arg, or derive from probe name
        if baseline_db_path is None:
            db_dir = os.path.normpath(_BASELINE_DB_DIR)
            baseline_db_path = os.path.join(db_dir, f"filesystem_{self.name}.db")

        self._store = BaselineStore(baseline_db_path)

        # Load persisted baseline — if DB has rows, this is NOT first run
        if self._store.has_baseline():
            self._baseline: Dict[str, str] = self._store.load()
            self._first_run = False
        else:
            self._baseline = {}
            self._first_run = True

        self._baseline_mtime: Dict[str, float] = (
            {}
        )  # path -> mtime (timestomping detection, memory-only)

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
            # Truly first-ever run (empty DB) — absorb silently
            self._baseline = {path: e.sha256 for path, e in current.items()}
            self._baseline_mtime = {path: e.mtime for path, e in current.items()}
            self._first_run = False
            self._persist_baseline(current)
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

        # Update baseline in memory and persist to DB
        self._baseline = {path: e.sha256 for path, e in current.items()}
        self._baseline_mtime = {path: e.mtime for path, e in current.items()}
        self._persist_baseline(current)

        return events

    def _persist_baseline(self, current: Dict[str, Any]) -> None:
        """Persist current baseline entries to the SQLite store."""
        try:
            # Use "filesystem" as category since file entries don't have a category field
            entries = {
                path: (entry.sha256, getattr(entry, "category", "file"))
                for path, entry in current.items()
            }
            self._store.persist(entries)
        except Exception:
            logger.warning(
                "%s: failed to persist baseline to DB", self.name, exc_info=True
            )

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
        # System-wide shell profiles
        "/etc/profile",
        "/etc/zshrc",
        "/etc/zshenv",
        "/etc/bashrc",
    ]

    def __init__(self, baseline_db_path: Optional[str] = None) -> None:
        # Expand user-home shell profile paths before calling super
        home = str(Path.home())
        self._target_paths = list(self.__class__._target_paths) + [
            os.path.join(home, ".zshrc"),
            os.path.join(home, ".bashrc"),
            os.path.join(home, ".bash_profile"),
            os.path.join(home, ".zprofile"),
            os.path.join(home, ".zshenv"),
        ]
        super().__init__(baseline_db_path)

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

    # Exclude noisy files that change frequently during normal macOS operation
    _EXCLUDE_NAMES: Set[str] = {
        ".DS_Store",
        "com.apple.preferences.plist",
    }

    # Apple system binaries/paths that legitimately modify /etc/ configs.
    # These fire on every boot, daemon restart, and OS update — not backdoors.
    _BENIGN_SYSTEM_NAMES: Set[str] = {
        # System binaries that appear as file entries in /etc/
        "notifyd",
        "UserEventAgent",
        "passwd",
        "master.passwd",
        "group",
        "sudo",
        # Config files that change during normal OS operation
        "sudoers",
        "hosts",
        "resolv.conf",
        "newsyslog.conf",
        "ntp.conf",
        "periodic",
        "syslog.conf",
        "localtime",
        "shells",
    }

    # Process exe prefixes that are always benign when modifying /etc/.
    # Matched against the exe path in the file entry description.
    _BENIGN_EXE_PREFIXES = (
        "/usr/sbin/",
        "/usr/libexec/",
        "/System/Library/",
        "/usr/bin/sudo",
    )

    # Apple/vendor plist prefixes that change during normal OS operation
    _BENIGN_PLIST_PREFIXES = (
        "com.apple.",
        "com.microsoft.",
        "com.google.",
        "com.docker.",
        "org.mozilla.",
    )

    def _matches(self, entry: Any) -> bool:
        if entry.name in self._EXCLUDE_NAMES:
            return False
        if entry.name in self._BENIGN_SYSTEM_NAMES:
            return False
        # Vendor system plists in /Library/Preferences change on boot, wake,
        # preference sync, and OS updates — not indicators of backdoor activity
        path = getattr(entry, "path", "") or ""
        if "/Library/Preferences/" in path and entry.name.endswith(".plist"):
            if any(entry.name.startswith(p) for p in self._BENIGN_PLIST_PREFIXES):
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
    _EXECUTABLE_EXTENSIONS = _EXECUTABLE_FILE_EXTENSIONS

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

            # Skip files owned by the current user in dev/project directories —
            # locally created files never had quarantine in the first place
            try:
                st = os.stat(entry.path)
                if st.st_uid == os.getuid():
                    # Check if file was created recently (within last 7 days)
                    # and has no quarantine — likely locally created, not bypassed
                    import time as _time

                    age_days = (_time.time() - st.st_mtime) / 86400
                    if age_days > 7:
                        # Old file without quarantine — already known, suppress
                        self._seen_unquarantined.add(entry.path)
                        continue
            except OSError:
                pass

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

    _HIGH_RISK_EXTENSIONS = _EXECUTABLE_FILE_EXTENSIONS | frozenset(
        {".zip", ".tar", ".gz", ".rar", ".7z", ".iso", ".img"}
    )

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
# 9. AirDropFileArrivalProbe
# =============================================================================

# AirDrop quarantine agent identifier
_AIRDROP_AGENT_ID = "com.apple.share.AirDrop.SendFileService"

# Extensions considered executable / high-risk when received via AirDrop
# Extends the shared _EXECUTABLE_FILE_EXTENSIONS with AirDrop-specific types
_AIRDROP_EXECUTABLE_EXTENSIONS = _EXECUTABLE_FILE_EXTENSIONS | frozenset(
    {".terminal", ".action"}
)

# AirDrop staging directory prefix
_AIRDROP_STAGING_PREFIX = "/private/var/folders/"


def _read_quarantine_xattr(path: str) -> Optional[str]:
    """Read the com.apple.quarantine xattr value for a file.

    Returns the raw xattr string or None if not present / error.
    """
    try:
        result = subprocess.run(
            ["xattr", "-p", "com.apple.quarantine", path],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def _is_airdrop_quarantine(quarantine_val: str) -> bool:
    """Check if a quarantine xattr value indicates AirDrop delivery."""
    return _AIRDROP_AGENT_ID in quarantine_val or "AirDrop" in quarantine_val


class AirDropFileArrivalProbe(MicroProbe):
    """Detects files received via AirDrop, especially executables.

    Monitors ~/Downloads for new files whose com.apple.quarantine xattr
    contains the AirDrop agent identifier. Executable files received via
    AirDrop are high severity — social engineering vector for malware delivery.

    Also monitors /private/var/folders/ for AirDrop staging files that
    indicate an active transfer.

    MITRE: T1105 (Ingress Tool Transfer), T1204.002 (Malicious File)
    """

    name = "macos_airdrop_file_arrival"
    description = "Detects files received via AirDrop on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1105", "T1204.002"]
    mitre_tactics = ["command_and_control", "execution"]
    scan_interval = 15.0
    requires_fields = ["files"]

    def __init__(self) -> None:
        super().__init__()
        self._home = str(Path.home())
        self._seen_airdrop_files: Set[str] = set()
        self._seen_staging_files: Set[str] = set()
        self._xattr_available = self._check_xattr()

    @staticmethod
    def _check_xattr() -> bool:
        """Verify xattr command is available."""
        try:
            subprocess.run(["xattr", "--help"], capture_output=True, timeout=3)
            return True
        except Exception:
            return False

    def _scan_downloads(self, files: list) -> List[TelemetryEvent]:
        """Scan ~/Downloads for AirDrop-delivered files."""
        events: List[TelemetryEvent] = []
        if not self._xattr_available:
            return events

        downloads_dir = os.path.join(self._home, "Downloads")

        for entry in files:
            if not entry.path.startswith(downloads_dir + "/"):
                continue
            if entry.path in self._seen_airdrop_files:
                continue

            quarantine_val = _read_quarantine_xattr(entry.path)
            if not quarantine_val or not _is_airdrop_quarantine(quarantine_val):
                continue

            self._seen_airdrop_files.add(entry.path)

            _, ext = os.path.splitext(entry.name.lower())
            is_executable = ext in _AIRDROP_EXECUTABLE_EXTENSIONS
            severity = Severity.HIGH if is_executable else Severity.MEDIUM
            confidence = 0.9 if is_executable else 0.7

            events.append(
                self._create_event(
                    event_type="airdrop_file_received",
                    severity=severity,
                    data={
                        **_attribute_file_change(entry.path),
                        "path": entry.path,
                        "name": entry.name,
                        "extension": ext,
                        "sha256": entry.sha256,
                        "size": entry.size,
                        "is_executable": is_executable,
                        "quarantine_value": quarantine_val[:200],
                        "delivery_method": "AirDrop",
                    },
                    confidence=confidence,
                )
            )

        return events

    def _scan_staging(self) -> List[TelemetryEvent]:
        """Scan /private/var/folders/ for AirDrop staging files."""
        events: List[TelemetryEvent] = []
        try:
            # AirDrop stages files in com.apple.AirDrop within var/folders
            staging_files = subprocess.run(
                [
                    "find",
                    _AIRDROP_STAGING_PREFIX,
                    "-path",
                    "*com.apple.AirDrop*",
                    "-type",
                    "f",
                    "-newer",
                    "/tmp/.amoskys_airdrop_marker",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            # Fallback: just scan for any com.apple.AirDrop entries
            if staging_files.returncode != 0:
                staging_files = subprocess.run(
                    [
                        "find",
                        _AIRDROP_STAGING_PREFIX,
                        "-path",
                        "*com.apple.AirDrop*",
                        "-type",
                        "f",
                        "-maxdepth",
                        "6",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
        except (subprocess.TimeoutExpired, OSError):
            return events

        if not staging_files.stdout.strip():
            return events

        for line in staging_files.stdout.strip().splitlines():
            fpath = line.strip()
            if not fpath or fpath in self._seen_staging_files:
                continue
            self._seen_staging_files.add(fpath)

            events.append(
                self._create_event(
                    event_type="airdrop_staging_detected",
                    severity=Severity.MEDIUM,
                    data={
                        "probe_name": self.name,
                        "detection_source": "filesystem_monitor",
                        "file_name": os.path.basename(fpath),
                        "file_extension": os.path.splitext(fpath)[1],
                        "path": fpath,
                        "staging_location": _AIRDROP_STAGING_PREFIX,
                        "delivery_method": "AirDrop",
                    },
                    confidence=0.65,
                )
            )

        # Prune seen-set to avoid unbounded growth
        if len(self._seen_staging_files) > 500:
            self._seen_staging_files = set(list(self._seen_staging_files)[-250:])

        return events

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        files = context.shared_data.get("files", [])

        events.extend(self._scan_downloads(files))
        events.extend(self._scan_staging())

        return events


# =============================================================================
# 10. LogTamperingProbe
# =============================================================================


class _LogBaselineStore:
    """SQLite-backed state store for LogTamperingProbe.

    Tracks per-file size, mtime, and permissions so that truncation,
    deletion, and permission changes survive agent restarts.
    """

    _SCHEMA = """
        CREATE TABLE IF NOT EXISTS log_baseline (
            path TEXT PRIMARY KEY,
            size INTEGER NOT NULL,
            mtime REAL NOT NULL,
            permissions TEXT NOT NULL,
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL
        )
    """

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._conn = sqlite3.connect(db_path, timeout=5.0)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(self._SCHEMA)
        self._conn.commit()

    def load(self) -> Dict[str, Tuple[int, float, str]]:
        """Return path -> (size, mtime, permissions) for all tracked files."""
        rows = self._conn.execute(
            "SELECT path, size, mtime, permissions FROM log_baseline"
        ).fetchall()
        return {row[0]: (row[1], row[2], row[3]) for row in rows}

    def has_baseline(self) -> bool:
        row = self._conn.execute("SELECT COUNT(*) FROM log_baseline").fetchone()
        return row[0] > 0

    def persist(self, entries: Dict[str, Tuple[int, float, str]]) -> None:
        """Persist current snapshot. entries: path -> (size, mtime, perms)."""
        now = time.time()
        existing_first: Dict[str, float] = {}
        for row in self._conn.execute(
            "SELECT path, first_seen FROM log_baseline"
        ).fetchall():
            existing_first[row[0]] = row[1]

        self._conn.execute("DELETE FROM log_baseline")
        for path, (size, mtime, perms) in entries.items():
            first_seen = existing_first.get(path, now)
            self._conn.execute(
                "INSERT INTO log_baseline (path, size, mtime, permissions, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (path, size, mtime, perms, first_seen, now),
            )
        self._conn.commit()

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass


class LogTamperingProbe(MicroProbe):
    """Detects log file tampering — truncation, deletion, and permission changes.

    Monitors critical macOS log files and directories for signs of an attacker
    covering their tracks. On each scan cycle the probe records file size,
    mtime, and permissions. On subsequent scans it compares against the
    previous state and flags:

        - Size decrease  → log truncation (HIGH)
        - File gone      → log deletion   (HIGH)
        - Perms changed  → suspicious     (MEDIUM)

    State is persisted to SQLite via _LogBaselineStore so that detection
    survives agent restarts.

    MITRE: T1070.002 (Indicator Removal: Clear Linux or Mac System Logs)
    """

    name = "macos_log_tampering"
    description = "Detects log file truncation, deletion, and permission changes"
    mitre_techniques = ["T1070.002"]
    mitre_tactics = ["defense-evasion"]
    platforms = ["darwin"]
    scan_interval = 30.0

    # Static monitored paths (files)
    _WATCHED_FILES = [
        "/var/log/system.log",
        "/var/log/install.log",
        "/var/log/wifi.log",
    ]

    # Directories whose *.log children are monitored
    _WATCHED_LOG_DIRS = [
        "/var/log",
    ]

    # Directories monitored recursively
    _WATCHED_RECURSIVE_DIRS = [
        "/private/var/log/asl",
    ]

    # Does not require shared_data["files"] — the probe stats the
    # filesystem directly so it works regardless of collector scope.
    requires_fields: List[str] = []

    def __init__(self, baseline_db_path: Optional[str] = None) -> None:
        super().__init__()
        if baseline_db_path is None:
            db_dir = os.path.normpath(_BASELINE_DB_DIR)
            baseline_db_path = os.path.join(db_dir, f"filesystem_{self.name}.db")

        self._store = _LogBaselineStore(baseline_db_path)

        if self._store.has_baseline():
            self._baseline: Dict[str, Tuple[int, float, str]] = self._store.load()
            self._first_run = False
        else:
            self._baseline = {}
            self._first_run = True

        # Expand ~/Library/Logs at init time
        self._user_logs_dir = os.path.join(str(Path.home()), "Library", "Logs")

    # ------------------------------------------------------------------
    # Path enumeration
    # ------------------------------------------------------------------

    def _enumerate_log_paths(self) -> Set[str]:
        """Return the current set of log file paths to monitor."""
        paths: Set[str] = set(self._WATCHED_FILES)
        self._collect_glob_dirs(paths, self._WATCHED_LOG_DIRS)
        self._collect_recursive_dirs(paths, self._WATCHED_RECURSIVE_DIRS)
        self._collect_glob_dirs(paths, [self._user_logs_dir])
        return paths

    @staticmethod
    def _collect_glob_dirs(paths: Set[str], dirs: List[str]) -> None:
        """Add *.log files from each directory (non-recursive)."""
        for d in dirs:
            if os.path.isdir(d):
                paths.update(_glob.glob(os.path.join(d, "*.log")))

    @staticmethod
    def _collect_recursive_dirs(paths: Set[str], dirs: List[str]) -> None:
        """Add all files from each directory (recursive)."""
        for d in dirs:
            if os.path.isdir(d):
                for root, _dirs, files in os.walk(d):
                    for f in files:
                        paths.add(os.path.join(root, f))

    # ------------------------------------------------------------------
    # File stat helper
    # ------------------------------------------------------------------

    @staticmethod
    def _stat_file(path: str) -> Optional[Tuple[int, float, str]]:
        """Return (size, mtime, octal_permissions) or None if inaccessible."""
        try:
            st = os.stat(path)
            perms = oct(stat.S_IMODE(st.st_mode))
            return (st.st_size, st.st_mtime, perms)
        except OSError:
            return None

    # ------------------------------------------------------------------
    # Event builders
    # ------------------------------------------------------------------

    def _make_truncation_event(
        self, path: str, prev_size: int, cur_size: int
    ) -> TelemetryEvent:
        return self._create_event(
            event_type="log_tampering_detected",
            severity=Severity.HIGH,
            data={
                "detection_source": "filesystem_monitor",
                "category": "log_tampering_detected",
                "path": path,
                "file_name": os.path.basename(path),
                "file_extension": os.path.splitext(path)[1],
                "change_type": "truncation",
                "previous_size": prev_size,
                "current_size": cur_size,
                "size_delta": cur_size - prev_size,
                "detail": (
                    f"Log file shrank from {prev_size} to "
                    f"{cur_size} bytes ({prev_size - cur_size} bytes removed)"
                ),
            },
            confidence=0.92,
        )

    def _make_permission_event(
        self, path: str, prev_perms: str, cur_perms: str
    ) -> TelemetryEvent:
        return self._create_event(
            event_type="log_tampering_detected",
            severity=Severity.MEDIUM,
            data={
                "detection_source": "filesystem_monitor",
                "category": "log_tampering_detected",
                "path": path,
                "file_name": os.path.basename(path),
                "file_extension": os.path.splitext(path)[1],
                "change_type": "permission_change",
                "previous_permissions": prev_perms,
                "current_permissions": cur_perms,
                "detail": (
                    f"Log file permissions changed from " f"{prev_perms} to {cur_perms}"
                ),
            },
            confidence=0.80,
        )

    def _make_deletion_event(self, path: str, prev_size: int) -> TelemetryEvent:
        return self._create_event(
            event_type="log_tampering_detected",
            severity=Severity.HIGH,
            data={
                "detection_source": "filesystem_monitor",
                "category": "log_tampering_detected",
                "path": path,
                "file_name": os.path.basename(path),
                "file_extension": os.path.splitext(path)[1],
                "change_type": "deletion",
                "previous_size": prev_size,
                "detail": f"Log file deleted: {path}",
            },
            confidence=0.95,
        )

    # ------------------------------------------------------------------
    # Core scan
    # ------------------------------------------------------------------

    def _snapshot_current(self) -> Dict[str, Tuple[int, float, str]]:
        """Stat all monitored log paths, return those that exist."""
        current: Dict[str, Tuple[int, float, str]] = {}
        for path in self._enumerate_log_paths():
            info = self._stat_file(path)
            if info is not None:
                current[path] = info
        return current

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        current = self._snapshot_current()

        # First-ever run — absorb silently, persist, return
        if self._first_run:
            self._baseline = dict(current)
            self._first_run = False
            self._persist(current)
            return events

        # Detect TRUNCATION and PERMISSION CHANGE on existing files
        for path, (cur_size, _cur_mtime, cur_perms) in current.items():
            if path not in self._baseline:
                continue
            prev_size, _prev_mtime, prev_perms = self._baseline[path]
            if cur_size < prev_size:
                events.append(self._make_truncation_event(path, prev_size, cur_size))
            if cur_perms != prev_perms:
                events.append(self._make_permission_event(path, prev_perms, cur_perms))

        # Detect DELETION (was in baseline, now gone)
        for path in self._baseline:
            if path not in current and not os.path.exists(path):
                prev_size = self._baseline[path][0]
                events.append(self._make_deletion_event(path, prev_size))

        # Update baseline
        self._baseline = dict(current)
        self._persist(current)

        return events

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _persist(self, current: Dict[str, Tuple[int, float, str]]) -> None:
        try:
            self._store.persist(current)
        except Exception:
            logger.warning(
                "%s: failed to persist log baseline to DB",
                self.name,
                exc_info=True,
            )


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
        AirDropFileArrivalProbe(),
        LogTamperingProbe(),
    ]
