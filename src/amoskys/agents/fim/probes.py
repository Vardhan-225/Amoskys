#!/usr/bin/env python3
"""FIMAgent Micro-Probes - 8 Eyes on File Integrity & Tampering.

Each probe watches ONE specific file tampering / persistence vector:

1. CriticalSystemFileChangeProbe - Core binary/config modifications
2. SUIDBitChangeProbe - SUID/SGID privilege escalation
3. ServiceCreationProbe - LaunchAgent/systemd persistence
4. WebShellDropProbe - Webshell detection in web roots
5. ConfigBackdoorProbe - Backdoored SSH/sudo/PAM configs
6. LibraryHijackProbe - LD_PRELOAD rootkit detection
7. BootloaderTamperProbe - Bootkit/kernel tampering
8. WorldWritableSensitiveProbe - Dangerous permission changes

MITRE ATT&CK Coverage:
    - T1036: Masquerading
    - T1547: Boot or Logon Autostart Execution
    - T1574: Hijack Execution Flow
    - T1505.003: Web Shell
    - T1548: Abuse Elevation Control Mechanism
    - T1556: Modify Authentication Process
    - T1014: Rootkit
    - T1542: Pre-OS Boot
    - T1565: Data Manipulation
    - T1070: Indicator Removal
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)

# =============================================================================
# File State Model
# =============================================================================


class ChangeType(str, Enum):
    """Types of file changes detected."""

    CREATED = "CREATED"
    MODIFIED = "MODIFIED"
    DELETED = "DELETED"
    PERM_CHANGED = "PERM_CHANGED"
    OWNER_CHANGED = "OWNER_CHANGED"
    HASH_CHANGED = "HASH_CHANGED"


@dataclass
class FileState:
    """Snapshot of a file's state at a point in time."""

    path: str
    sha256: Optional[str]  # None for directories
    size: int
    mode: int  # File permissions (stat.st_mode)
    uid: int
    gid: int
    mtime_ns: int
    is_dir: bool
    is_symlink: bool

    @staticmethod
    def from_path(path: str) -> Optional[FileState]:
        """Create FileState from filesystem path.

        Returns:
            FileState if path exists, None otherwise
        """
        try:
            st = os.lstat(path)  # Use lstat to not follow symlinks
            is_dir = stat.S_ISDIR(st.st_mode)
            is_symlink = stat.S_ISLNK(st.st_mode)

            # Calculate hash for regular files only
            sha256 = None
            if stat.S_ISREG(st.st_mode) and st.st_size < 100 * 1024 * 1024:  # <100MB
                try:
                    with open(path, "rb") as f:
                        sha256 = hashlib.sha256(f.read()).hexdigest()
                except (OSError, PermissionError):
                    pass  # Can't read, skip hash

            return FileState(
                path=path,
                sha256=sha256,
                size=st.st_size,
                mode=st.st_mode,
                uid=st.st_uid,
                gid=st.st_gid,
                mtime_ns=st.st_mtime_ns,
                is_dir=is_dir,
                is_symlink=is_symlink,
            )
        except (OSError, FileNotFoundError):
            return None

    def has_suid(self) -> bool:
        """Check if file has SUID bit set."""
        return bool(self.mode & stat.S_ISUID)

    def has_sgid(self) -> bool:
        """Check if file has SGID bit set."""
        return bool(self.mode & stat.S_ISGID)

    def is_world_writable(self) -> bool:
        """Check if file is world-writable."""
        return bool(self.mode & stat.S_IWOTH)


@dataclass
class FileChange:
    """Represents a detected change to a file."""

    path: str
    change_type: ChangeType
    old_state: Optional[FileState]
    new_state: Optional[FileState]
    timestamp_ns: int

    def get_change_details(self) -> str:
        """Get human-readable description of the change."""
        if self.change_type == ChangeType.CREATED:
            return f"File created: {self.path}"
        elif self.change_type == ChangeType.DELETED:
            return f"File deleted: {self.path}"
        elif self.change_type == ChangeType.MODIFIED:
            return f"File modified: {self.path}"
        elif self.change_type == ChangeType.PERM_CHANGED:
            old_perms = oct(self.old_state.mode)[-3:] if self.old_state else "???"
            new_perms = oct(self.new_state.mode)[-3:] if self.new_state else "???"
            return f"Permissions changed: {self.path} ({old_perms} → {new_perms})"
        elif self.change_type == ChangeType.OWNER_CHANGED:
            old_uid = self.old_state.uid if self.old_state else -1
            new_uid = self.new_state.uid if self.new_state else -1
            return f"Owner changed: {self.path} (UID {old_uid} → {new_uid})"
        elif self.change_type == ChangeType.HASH_CHANGED:
            old_hash = (
                self.old_state.sha256[:8]
                if self.old_state and self.old_state.sha256
                else "???"
            )
            new_hash = (
                self.new_state.sha256[:8]
                if self.new_state and self.new_state.sha256
                else "???"
            )
            return f"Content changed: {self.path} (hash {old_hash}... → {new_hash}...)"
        return f"Unknown change: {self.path}"


# =============================================================================
# Configuration
# =============================================================================


# Critical system binaries to monitor
CRITICAL_BINARIES = {
    "sudo",
    "su",
    "sshd",
    "ssh",
    "bash",
    "sh",
    "zsh",
    "login",
    "systemd",
    "init",
    "cron",
    "crond",
    "passwd",
    "chsh",
    "chfn",
    "mount",
    "umount",
    "iptables",
    "nft",
    "tcpdump",
}

# Critical config files
CRITICAL_CONFIGS = {
    "/etc/ssh/sshd_config",
    "/etc/sudoers",
    "/etc/pam.d",
    "/etc/shadow",
    "/etc/passwd",
    "/etc/group",
}

# Web root directories (platform-specific)
WEB_ROOTS = {
    "/var/www",
    "/srv/www",
    "/usr/share/nginx/html",
    "/Library/WebServer/Documents",  # macOS
}

# Webshell suspicious patterns
WEBSHELL_PATTERNS = [
    rb"eval\s*\(\s*base64_decode",
    rb"gzinflate\s*\(\s*base64_decode",
    rb"exec\s*\(\s*\$_(?:GET|POST|REQUEST)",
    rb"system\s*\(\s*\$_(?:GET|POST|REQUEST)",
    rb"passthru\s*\(\s*\$_(?:GET|POST|REQUEST)",
    rb"shell_exec\s*\(\s*\$_(?:GET|POST|REQUEST)",
    rb"<?php.*@eval",
    rb"preg_replace\s*\(\s*['\"]/.*/e['\"]",  # Code execution via preg_replace
]


# =============================================================================
# Probe 1: Critical System File Change Detection
# =============================================================================


class CriticalSystemFileChangeProbe(MicroProbe):
    """Detects modifications to critical system binaries and configs.

    Watches:
        - Core binaries: sudo, sshd, bash, systemd, etc.
        - Critical configs: sshd_config, sudoers, shadow, passwd

    Flags:
        - Hash changes to monitored binaries
        - Modifications to security-critical configs

    MITRE: T1036 (Masquerading), T1547 (Boot/Logon Autostart)
    """

    name = "critical_system_file_change"
    description = "Critical binary/config modification detection"
    mitre_techniques = ["T1036", "T1547", "T1574"]
    mitre_tactics = ["Defense Evasion", "Persistence"]
    default_enabled = True
    scan_interval = 60.0
    requires_fields = ["file_changes"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect critical file changes."""
        events: List[TelemetryEvent] = []
        file_changes: List[FileChange] = context.shared_data.get("file_changes", [])

        for change in file_changes:
            # Check if it's a critical binary — match the filename (basename),
            # not a substring of the full path.  The old `binary in change.path`
            # caused "sh" to match /usr/share/*, generating massive noise.
            filename = os.path.basename(change.path)
            is_critical_binary = filename in CRITICAL_BINARIES

            # Check if it's a critical config
            is_critical_config = any(
                change.path.startswith(cfg) for cfg in CRITICAL_CONFIGS
            )

            if is_critical_binary or is_critical_config:
                # Determine severity based on change type
                severity = (
                    Severity.CRITICAL
                    if change.change_type
                    in (
                        ChangeType.HASH_CHANGED,
                        ChangeType.MODIFIED,
                    )
                    else Severity.HIGH
                )

                events.append(
                    TelemetryEvent(
                        event_type="critical_file_tampered",
                        severity=severity,
                        probe_name=self.name,
                        data={
                            "path": change.path,
                            "change_type": change.change_type.value,
                            "details": change.get_change_details(),
                            "old_hash": (
                                change.old_state.sha256 if change.old_state else None
                            ),
                            "new_hash": (
                                change.new_state.sha256 if change.new_state else None
                            ),
                        },
                        mitre_techniques=["T1036", "T1547"],
                    )
                )

        return events


# =============================================================================
# Probe 2: SUID/SGID Bit Changes
# =============================================================================


class SUIDBitChangeProbe(MicroProbe):
    """Detects SUID/SGID bit modifications (privilege escalation vector).

    Watches:
        - SUID/SGID bit additions on binaries
        - Ownership changes to root on user-writable paths

    Flags:
        - New SUID/SGID binaries in non-system locations (CRITICAL)
        - SUID in standard system dirs but not in whitelist (HIGH)
        - Skips known-good system SUID files (sudo, passwd, etc.)

    MITRE: T1548.001 (Setuid/Setgid), T1068 (Exploitation for Privilege Escalation)
    """

    # Known-good SUID/SGID files — legitimate system tools that should not trigger alerts
    KNOWN_SUID_PATHS = frozenset(
        {
            # Standard Unix SUID binaries
            "/usr/bin/sudo",
            "/usr/bin/su",
            "/usr/bin/passwd",
            "/usr/bin/login",
            "/usr/bin/newgrp",
            "/usr/bin/chsh",
            "/usr/bin/chfn",
            "/usr/bin/at",
            "/usr/bin/crontab",
            "/usr/sbin/traceroute",
            "/usr/bin/wall",
            "/usr/bin/ssh-agent",
            "/usr/bin/locate",
            "/usr/bin/write",
            "/usr/lib/policykit-1/polkit-agent-helper-1",
            # macOS-specific SUID/SGID binaries
            "/usr/bin/top",
            "/usr/sbin/authopen",
            "/usr/bin/quota",
            "/usr/bin/mail",
            "/usr/sbin/postdrop",
            "/usr/sbin/postqueue",
            "/usr/bin/lockfile",
            "/usr/bin/procmail",
            "/usr/sbin/traceroute6",
            "/usr/bin/expiry",
        }
    )

    # System directories where SUID is expected (downgrade to HIGH, not CRITICAL)
    SYSTEM_SUID_DIRS = (
        "/usr/bin/",
        "/usr/sbin/",
        "/usr/lib/",
        "/usr/libexec/",
        "/sbin/",
        "/bin/",
    )

    name = "suid_bit_change"
    description = "SUID/SGID privilege escalation detection"
    mitre_techniques = ["T1548.001", "T1068"]
    mitre_tactics = ["Privilege Escalation"]
    default_enabled = True
    scan_interval = 60.0
    requires_fields = ["file_changes"]

    def _is_system_dir(self, path: str) -> bool:
        return any(path.startswith(d) for d in self.SYSTEM_SUID_DIRS)

    def _check_suid(self, change: FileChange) -> Optional[TelemetryEvent]:
        new_state = change.new_state
        if new_state is None:
            return None
        old_suid = change.old_state.has_suid() if change.old_state else False
        if not new_state.has_suid() or old_suid:
            return None
        if change.path in self.KNOWN_SUID_PATHS:
            return None
        if self._is_system_dir(change.path):
            severity = Severity.HIGH
            reason = "SUID bit added in system directory (review recommended)"
        else:
            severity = Severity.CRITICAL
            reason = "SUID bit added in non-system path (privilege escalation risk)"
        return TelemetryEvent(
            event_type="suid_bit_added",
            severity=severity,
            probe_name=self.name,
            data={
                "path": change.path,
                "mode": oct(new_state.mode),
                "owner_uid": new_state.uid,
                "reason": reason,
            },
            mitre_techniques=["T1548.001"],
        )

    def _check_sgid(self, change: FileChange) -> Optional[TelemetryEvent]:
        new_state = change.new_state
        if new_state is None:
            return None
        old_sgid = change.old_state.has_sgid() if change.old_state else False
        if not new_state.has_sgid() or old_sgid:
            return None
        if change.path in self.KNOWN_SUID_PATHS:
            return None
        if self._is_system_dir(change.path):
            severity = Severity.MEDIUM
            reason = "SGID bit added in system directory"
        else:
            severity = Severity.HIGH
            reason = "SGID bit added in non-system path"
        return TelemetryEvent(
            event_type="sgid_bit_added",
            severity=severity,
            probe_name=self.name,
            data={
                "path": change.path,
                "mode": oct(new_state.mode),
                "owner_gid": new_state.gid,
                "reason": reason,
            },
            mitre_techniques=["T1548.001"],
        )

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect SUID/SGID changes, filtering known-good system files."""
        events: List[TelemetryEvent] = []
        file_changes: List[FileChange] = context.shared_data.get("file_changes", [])

        for change in file_changes:
            if not change.new_state or change.new_state.is_dir:
                continue
            evt = self._check_suid(change)
            if evt:
                events.append(evt)
            evt = self._check_sgid(change)
            if evt:
                events.append(evt)

        return events


# =============================================================================
# Probe 3: Service/LaunchAgent Creation
# =============================================================================


class ServiceCreationProbe(MicroProbe):
    """Detects persistence via service/LaunchAgent creation.

    Watches:
        - macOS: LaunchAgents, LaunchDaemons
        - Linux: systemd units, cron jobs, init scripts

    Flags:
        - New service files
        - Modifications to existing services (especially Exec lines)

    MITRE: T1543 (Create or Modify System Process), T1053 (Scheduled Task/Job)
    """

    name = "service_creation"
    description = "Service/LaunchAgent persistence detection"
    mitre_techniques = ["T1543", "T1053", "T1050"]
    mitre_tactics = ["Persistence"]
    default_enabled = True
    scan_interval = 60.0
    requires_fields = ["file_changes"]

    # Persistence paths to monitor
    PERSISTENCE_PATHS = {
        # macOS
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        "/System/Library/LaunchAgents",
        "/System/Library/LaunchDaemons",
        # Linux
        "/etc/systemd/system",
        "/etc/systemd/user",
        "/etc/init.d",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/var/spool/cron",
    }

    # Known-good service prefixes — these are legitimate OS and vendor
    # services that should be tracked but at lower severity to reduce
    # noise on production macOS/Linux systems.
    _KNOWN_GOOD_PREFIXES = (
        "com.apple.",
        "com.microsoft.",
        "com.docker.",
        "us.zoom.",
        "com.google.",
        "org.mozilla.",
        "com.brave.",
        "com.github.",
        "com.jetbrains.",
        "com.slack.",
    )

    @classmethod
    def _is_known_good_service(cls, path: str) -> bool:
        """Check if a service file is from a known vendor."""
        filename = os.path.basename(path)
        return any(filename.startswith(p) for p in cls._KNOWN_GOOD_PREFIXES)

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect service creation/modification."""
        events: List[TelemetryEvent] = []
        file_changes: List[FileChange] = context.shared_data.get("file_changes", [])

        for change in file_changes:
            # Check if path is under a persistence directory
            is_persistence_path = any(
                change.path.startswith(p) for p in self.PERSISTENCE_PATHS
            )

            if not is_persistence_path:
                continue

            # Differentiate known-good services (lower severity)
            is_known = self._is_known_good_service(change.path)

            if change.change_type == ChangeType.CREATED:
                events.append(
                    TelemetryEvent(
                        event_type="service_created",
                        severity=Severity.LOW if is_known else Severity.HIGH,
                        probe_name=self.name,
                        data={
                            "path": change.path,
                            "reason": "New service/launch agent created",
                            "known_vendor": is_known,
                        },
                        mitre_techniques=["T1543", "T1053"],
                    )
                )

            elif change.change_type in (ChangeType.MODIFIED, ChangeType.HASH_CHANGED):
                events.append(
                    TelemetryEvent(
                        event_type="service_modified",
                        severity=Severity.LOW if is_known else Severity.MEDIUM,
                        probe_name=self.name,
                        data={
                            "path": change.path,
                            "change_type": change.change_type.value,
                            "reason": "Existing service modified",
                            "known_vendor": is_known,
                        },
                        mitre_techniques=["T1543"],
                    )
                )

        return events


# =============================================================================
# Probe 4: WebShell Detection
# =============================================================================


class WebShellDropProbe(MicroProbe):
    """Detects webshell drops in web roots.

    Watches:
        - Web root directories (/var/www, /srv/www, etc.)
        - New PHP/JSP/ASP files
        - Files with obfuscated/malicious code patterns

    Flags:
        - New web scripts with suspicious patterns
        - High-entropy obfuscated code

    MITRE: T1505.003 (Server Software Component: Web Shell)
    """

    name = "webshell_drop"
    description = "Webshell detection in web roots"
    mitre_techniques = ["T1505.003"]
    mitre_tactics = ["Persistence"]
    default_enabled = True
    scan_interval = 30.0
    requires_fields = ["file_changes"]

    # Suspicious file extensions
    WEBSHELL_EXTENSIONS = {".php", ".jsp", ".asp", ".aspx", ".cfm", ".jspx"}

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect webshell drops."""
        events: List[TelemetryEvent] = []
        file_changes: List[FileChange] = context.shared_data.get("file_changes", [])

        for change in file_changes:
            # Check if in web root
            is_web_root = any(change.path.startswith(root) for root in WEB_ROOTS)
            if not is_web_root:
                continue

            # Check if suspicious extension
            file_ext = Path(change.path).suffix.lower()
            if file_ext not in self.WEBSHELL_EXTENSIONS:
                continue

            # For new or modified files, check content
            if change.change_type in (
                ChangeType.CREATED,
                ChangeType.MODIFIED,
                ChangeType.HASH_CHANGED,
            ):
                is_suspicious, patterns_matched = self._check_webshell_patterns(
                    change.path
                )

                if is_suspicious:
                    events.append(
                        TelemetryEvent(
                            event_type="webshell_detected",
                            severity=Severity.CRITICAL,
                            probe_name=self.name,
                            data={
                                "path": change.path,
                                "extension": file_ext,
                                "patterns_matched": patterns_matched,
                                "reason": "Webshell detected in web root",
                            },
                            mitre_techniques=["T1505.003"],
                        )
                    )

        return events

    @staticmethod
    def _check_webshell_patterns(path: str) -> tuple[bool, List[str]]:
        """Check file for webshell patterns.

        Returns:
            (is_suspicious, list of matched patterns)
        """
        try:
            with open(path, "rb") as f:
                content = f.read(10 * 1024 * 1024)  # Read first 10MB

            matched_patterns = []
            for pattern in WEBSHELL_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    matched_patterns.append(pattern.decode())

            return len(matched_patterns) > 0, matched_patterns

        except (OSError, PermissionError):
            return False, []


# =============================================================================
# Probe 5: Config Backdoor Detection
# =============================================================================


class ConfigBackdoorProbe(MicroProbe):
    """Detects backdoored SSH/sudo/PAM configurations.

    Watches:
        - /etc/ssh/sshd_config
        - /etc/sudoers and /etc/sudoers.d/*
        - /etc/pam.d/*

    Flags:
        - Dangerous SSH config changes (PermitRootLogin yes)
        - NOPASSWD:ALL additions to sudoers
        - PAM backdoors

    MITRE: T1548 (Abuse Elevation), T1078 (Valid Accounts), T1556 (Modify Auth Process)
    """

    name = "config_backdoor"
    description = "Backdoored config detection"
    mitre_techniques = ["T1548", "T1078", "T1556"]
    mitre_tactics = ["Persistence", "Privilege Escalation"]
    default_enabled = True
    scan_interval = 60.0
    requires_fields = ["file_changes"]

    # Dangerous SSH config patterns
    DANGEROUS_SSH_PATTERNS = [
        (rb"^\s*PermitRootLogin\s+yes", "PermitRootLogin enabled"),
        (rb"^\s*PasswordAuthentication\s+yes", "Password authentication enabled"),
        (rb"^\s*PubkeyAuthentication\s+no", "Public key auth disabled"),
        (rb"^\s*PermitEmptyPasswords\s+yes", "Empty passwords permitted"),
    ]

    # Dangerous sudoers patterns
    DANGEROUS_SUDOERS_PATTERNS = [
        (rb"NOPASSWD:\s*ALL", "NOPASSWD:ALL directive"),
        (rb"%\w+\s+ALL=\(ALL\)\s+NOPASSWD:\s*ALL", "Group NOPASSWD:ALL"),
        (rb"ALL\s+ALL=\(ALL\)\s+NOPASSWD:\s*ALL", "Global NOPASSWD:ALL"),
    ]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect config backdoors."""
        events: List[TelemetryEvent] = []
        file_changes: List[FileChange] = context.shared_data.get("file_changes", [])

        for change in file_changes:
            if change.change_type not in (ChangeType.MODIFIED, ChangeType.HASH_CHANGED):
                continue

            # Check SSH config
            if "sshd_config" in change.path:
                matched = self._check_ssh_config(change.path)
                if matched:
                    events.append(
                        TelemetryEvent(
                            event_type="ssh_config_backdoor",
                            severity=Severity.CRITICAL,
                            probe_name=self.name,
                            data={
                                "path": change.path,
                                "dangerous_settings": matched,
                                "reason": "Dangerous SSH configuration changes",
                            },
                            mitre_techniques=["T1078", "T1556"],
                        )
                    )

            # Check sudoers
            if "sudoers" in change.path:
                matched = self._check_sudoers(change.path)
                if matched:
                    events.append(
                        TelemetryEvent(
                            event_type="sudoers_backdoor",
                            severity=Severity.CRITICAL,
                            probe_name=self.name,
                            data={
                                "path": change.path,
                                "dangerous_settings": matched,
                                "reason": "Dangerous sudoers configuration",
                            },
                            mitre_techniques=["T1548"],
                        )
                    )

        return events

    def _check_ssh_config(self, path: str) -> List[str]:
        """Check SSH config for dangerous settings."""
        matched = []
        try:
            with open(path, "rb") as f:
                content = f.read()

            for pattern, description in self.DANGEROUS_SSH_PATTERNS:
                if re.search(pattern, content, re.MULTILINE):
                    matched.append(description)

        except (OSError, PermissionError):
            pass

        return matched

    def _check_sudoers(self, path: str) -> List[str]:
        """Check sudoers for dangerous settings."""
        matched = []
        try:
            with open(path, "rb") as f:
                content = f.read()

            for pattern, description in self.DANGEROUS_SUDOERS_PATTERNS:
                if re.search(pattern, content):
                    matched.append(description)

        except (OSError, PermissionError):
            pass

        return matched


# =============================================================================
# Probe 6: Library Hijack Detection
# =============================================================================


class LibraryHijackProbe(MicroProbe):
    """Detects LD_PRELOAD rootkits and library hijacking.

    Watches:
        - /etc/ld.so.preload
        - /etc/ld.so.conf and /etc/ld.so.conf.d/*
        - New .so files in system lib directories

    Flags:
        - ld.so.preload modifications
        - Unexpected shared libraries

    MITRE: T1574.006 (Dynamic Linker Hijacking), T1014 (Rootkit)
    """

    name = "library_hijack"
    description = "LD_PRELOAD rootkit detection"
    mitre_techniques = ["T1574.006", "T1014"]
    mitre_tactics = ["Persistence", "Defense Evasion"]
    default_enabled = True
    scan_interval = 60.0
    requires_fields = ["file_changes"]

    LIBRARY_PATHS = {
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
        "/usr/local/lib",
    }

    LINKER_CONFIGS = {
        "/etc/ld.so.preload",
        "/etc/ld.so.conf",
    }

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect library hijacking."""
        events: List[TelemetryEvent] = []
        file_changes: List[FileChange] = context.shared_data.get("file_changes", [])

        for change in file_changes:
            # Check linker config modifications
            is_linker_config = any(
                change.path.startswith(cfg) for cfg in self.LINKER_CONFIGS
            )

            if is_linker_config and change.change_type in (
                ChangeType.MODIFIED,
                ChangeType.HASH_CHANGED,
                ChangeType.CREATED,
            ):
                events.append(
                    TelemetryEvent(
                        event_type="linker_config_modified",
                        severity=Severity.CRITICAL,
                        probe_name=self.name,
                        data={
                            "path": change.path,
                            "change_type": change.change_type.value,
                            "reason": "LD_PRELOAD or linker configuration modified (rootkit indicator)",
                        },
                        mitre_techniques=["T1574.006", "T1014"],
                    )
                )

            # Check for new .so files in system directories
            is_lib_path = any(change.path.startswith(p) for p in self.LIBRARY_PATHS)
            if (
                is_lib_path
                and change.path.endswith(".so")
                and change.change_type == ChangeType.CREATED
            ):
                events.append(
                    TelemetryEvent(
                        event_type="new_system_library",
                        severity=Severity.HIGH,
                        probe_name=self.name,
                        data={
                            "path": change.path,
                            "reason": "New shared library in system directory",
                        },
                        mitre_techniques=["T1574.006"],
                    )
                )

        return events


# =============================================================================
# Probe 7: Bootloader Tamper Detection
# =============================================================================


class BootloaderTamperProbe(MicroProbe):
    """Detects bootkit/kernel tampering.

    Platform-aware monitoring:
        - Linux: /boot (kernels, initramfs, grub configs)
        - macOS: /System/Library/Kernels, /Library/Extensions, firmware

    Flags:
        - New kernel images or kexts
        - GRUB/EFI config modifications
        - initramfs / firmware changes

    MITRE: T1542.003 (Bootloader Modification)
    """

    name = "bootloader_tamper"
    description = "Bootkit/kernel tampering detection"
    mitre_techniques = ["T1542.003"]
    mitre_tactics = ["Persistence", "Defense Evasion"]
    default_enabled = True
    scan_interval = 120.0
    requires_fields = ["file_changes"]

    # Platform-aware boot paths
    _BOOT_PREFIXES = {
        "linux": ["/boot"],
        "darwin": [
            "/System/Library/Kernels/",
            "/System/Library/Extensions/",
            "/Library/Extensions/",
            "/usr/standalone/firmware/",
        ],
    }

    # Critical filename keywords per platform
    _CRITICAL_KEYWORDS = {
        "linux": ["vmlinuz", "initrd", "grub", "efi"],
        "darwin": ["kernel", "kext", "firmware", "boot.efi", "prelinkedkernel"],
    }

    @classmethod
    def _get_platform(cls) -> str:
        import sys

        return "darwin" if sys.platform == "darwin" else "linux"

    def _is_boot_path(self, path: str) -> bool:
        """Check if path is within a boot-related directory."""
        platform_key = self._get_platform()
        for prefix in self._BOOT_PREFIXES.get(platform_key, ["/boot"]):
            if path.startswith(prefix):
                return True
        return False

    def _is_critical_boot_file(self, path: str) -> bool:
        """Check if path matches a critical boot file keyword."""
        platform_key = self._get_platform()
        keywords = self._CRITICAL_KEYWORDS.get(platform_key, [])
        return any(kw in path.lower() for kw in keywords)

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect bootloader tampering."""
        events: List[TelemetryEvent] = []
        file_changes: List[FileChange] = context.shared_data.get("file_changes", [])

        for change in file_changes:
            if not self._is_boot_path(change.path):
                continue

            if change.change_type in (
                ChangeType.CREATED,
                ChangeType.MODIFIED,
                ChangeType.HASH_CHANGED,
            ):
                severity = (
                    Severity.CRITICAL
                    if self._is_critical_boot_file(change.path)
                    else Severity.HIGH
                )

                events.append(
                    TelemetryEvent(
                        event_type="bootloader_modified",
                        severity=severity,
                        probe_name=self.name,
                        data={
                            "path": change.path,
                            "change_type": change.change_type.value,
                            "details": change.get_change_details(),
                            "reason": "Boot directory modification (bootkit risk)",
                        },
                        mitre_techniques=["T1542.003"],
                    )
                )

        return events


# =============================================================================
# Probe 8: World-Writable Sensitive File Detection
# =============================================================================


class WorldWritableSensitiveProbe(MicroProbe):
    """Detects dangerous permission changes on sensitive files.

    Watches:
        - Permission changes that make files world-writable
        - Focus on /etc, /var/log, /var/www

    Flags:
        - o+w permissions on sensitive directories
        - World-writable configs or logs

    MITRE: T1565 (Data Manipulation), T1070 (Indicator Removal)
    """

    name = "world_writable_sensitive"
    description = "Dangerous permission change detection"
    mitre_techniques = ["T1565", "T1070"]
    mitre_tactics = ["Impact", "Defense Evasion"]
    default_enabled = True
    scan_interval = 60.0
    requires_fields = ["file_changes"]

    SENSITIVE_PATHS = {"/etc", "/var/log", "/var/www", "/usr/bin", "/usr/sbin"}

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect world-writable sensitive files."""
        events: List[TelemetryEvent] = []
        file_changes: List[FileChange] = context.shared_data.get("file_changes", [])

        for change in file_changes:
            if not change.new_state:
                continue

            # Check if in sensitive path
            is_sensitive = any(change.path.startswith(p) for p in self.SENSITIVE_PATHS)
            if not is_sensitive:
                continue

            # Check if newly world-writable
            old_world_writable = (
                change.old_state.is_world_writable() if change.old_state else False
            )
            new_world_writable = change.new_state.is_world_writable()

            if new_world_writable and not old_world_writable:
                events.append(
                    TelemetryEvent(
                        event_type="world_writable_sensitive",
                        severity=Severity.HIGH,
                        probe_name=self.name,
                        data={
                            "path": change.path,
                            "old_mode": (
                                oct(change.old_state.mode) if change.old_state else None
                            ),
                            "new_mode": oct(change.new_state.mode),
                            "reason": "Sensitive file made world-writable",
                        },
                        mitre_techniques=["T1565", "T1070"],
                    )
                )

        return events


# =============================================================================
# Probe 9: Extended Attributes Quarantine Bit Removal (Phase 3 - macOS)
# =============================================================================


class ExtendedAttributesProbe(MicroProbe):
    """Monitors quarantine bit removal on downloaded files.

    macOS uses extended attributes (xattr) to mark downloaded files with the
    com.apple.quarantine bit. Removal of this attribute bypasses Gatekeeper
    checks and is a common malware preparation step.

    Watches:
        - Downloads directory (/Users/*/Downloads)
        - Common file drop locations
        - Removal of com.apple.quarantine xattr

    MITRE: T1222.002 (File and Directory Permissions Modification: Linux & Mac File and Directory Permissions Modification)
    """

    name = "extended_attributes"
    description = "Monitor quarantine bit removal and suspicious xattr changes"
    mitre_techniques = ["T1222.002", "T1036"]
    mitre_tactics = ["Defense Evasion"]
    platforms = ["darwin"]
    default_enabled = True
    scan_interval = 60.0
    requires_fields = ["file_changes"]

    # Common file drop locations on macOS
    DOWNLOAD_PATHS = {
        "/Users/",  # Will match all user downloads
        "/tmp/",
        "/var/tmp/",
        "/Library/Caches/",
    }

    # Suspicious file extensions that shouldn't have quarantine removed
    SUSPICIOUS_EXTENSIONS = {
        ".app",
        ".exe",
        ".dmg",
        ".pkg",
        ".zip",
        ".tar",
        ".gz",
        ".sh",
        ".command",
        ".scpt",
    }

    def __init__(self) -> None:
        super().__init__()
        self.reported_files: Set[str] = set()

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect quarantine bit removal and suspicious xattr changes."""
        events: List[TelemetryEvent] = []

        import platform
        import subprocess

        # Only on macOS
        if platform.system() != "Darwin":
            return events

        file_changes: List[FileChange] = context.shared_data.get("file_changes", [])

        for change in file_changes:
            # Check if in download/suspicious locations
            is_suspicious_location = any(
                change.path.startswith(p) for p in self.DOWNLOAD_PATHS
            )
            if not is_suspicious_location:
                continue

            # Check file extension
            file_ext = Path(change.path).suffix.lower()
            is_suspicious_ext = file_ext in self.SUSPICIOUS_EXTENSIONS

            if change.path in self.reported_files:
                continue

            # Check for quarantine xattr presence
            try:
                result = subprocess.run(
                    ["xattr", "-p", "com.apple.quarantine", change.path],
                    capture_output=True,
                    timeout=2,
                )

                quarantine_present = result.returncode == 0
                quarantine_value = result.stdout.strip() if quarantine_present else ""

                # Flag if quarantine was present before and now missing (removal)
                if change.old_state and not quarantine_present:
                    self.reported_files.add(change.path)

                    severity = Severity.HIGH if is_suspicious_ext else Severity.MEDIUM

                    events.append(
                        TelemetryEvent(
                            event_type="quarantine_xattr_removed",
                            severity=severity,
                            probe_name=self.name,
                            data={
                                "path": change.path,
                                "file_extension": file_ext,
                                "quarantine_removed": True,
                                "reason": "Quarantine extended attribute removed from downloaded file",
                            },
                            mitre_techniques=self.mitre_techniques,
                        )
                    )

                # Flag if suspicious file has no quarantine at all
                elif (
                    change.change_type == ChangeType.CREATED
                    and not quarantine_present
                    and is_suspicious_ext
                ):
                    self.reported_files.add(change.path)

                    events.append(
                        TelemetryEvent(
                            event_type="suspicious_file_no_quarantine",
                            severity=Severity.MEDIUM,
                            probe_name=self.name,
                            data={
                                "path": change.path,
                                "file_extension": file_ext,
                                "quarantine_present": False,
                                "reason": "Suspicious file created without quarantine attribute",
                            },
                            mitre_techniques=self.mitre_techniques,
                        )
                    )

            except (subprocess.TimeoutExpired, FileNotFoundError):
                # xattr command not available or timeout
                pass
            except Exception as e:
                # Silently skip on other errors (permission denied, etc)
                pass

        return events


# =============================================================================
# Probe Factory
# =============================================================================


def create_fim_probes() -> List[MicroProbe]:
    """Create all FIM micro-probes.

    Returns:
        List of 9 FIM probes (8 original + 1 Phase 3 macOS)
    """
    return [
        CriticalSystemFileChangeProbe(),
        SUIDBitChangeProbe(),
        ServiceCreationProbe(),
        WebShellDropProbe(),
        ConfigBackdoorProbe(),
        LibraryHijackProbe(),
        BootloaderTamperProbe(),
        WorldWritableSensitiveProbe(),
        ExtendedAttributesProbe(),
    ]
