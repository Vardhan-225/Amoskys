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
            old_hash = self.old_state.sha256[:8] if self.old_state and self.old_state.sha256 else "???"
            new_hash = self.new_state.sha256[:8] if self.new_state and self.new_state.sha256 else "???"
            return f"Content changed: {self.path} (hash {old_hash}... → {new_hash}...)"
        return f"Unknown change: {self.path}"


# =============================================================================
# Configuration
# =============================================================================


# Critical system binaries to monitor
CRITICAL_BINARIES = {
    "sudo", "su", "sshd", "ssh", "bash", "sh", "zsh", "login",
    "systemd", "init", "cron", "crond", "passwd", "chsh", "chfn",
    "mount", "umount", "iptables", "nft", "tcpdump"
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

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect critical file changes."""
        events: List[TelemetryEvent] = []
        file_changes: List[FileChange] = context.shared_data.get("file_changes", [])

        for change in file_changes:
            # Check if it's a critical binary
            is_critical_binary = any(
                binary in change.path for binary in CRITICAL_BINARIES
            )

            # Check if it's a critical config
            is_critical_config = any(
                change.path.startswith(cfg) for cfg in CRITICAL_CONFIGS
            )

            if is_critical_binary or is_critical_config:
                # Determine severity based on change type
                severity = Severity.CRITICAL if change.change_type in (
                    ChangeType.HASH_CHANGED,
                    ChangeType.MODIFIED,
                ) else Severity.HIGH

                events.append(
                    TelemetryEvent(
                        event_type="critical_file_tampered",
                        severity=severity,
                        probe_name=self.name,
                        data={
                            "path": change.path,
                            "change_type": change.change_type.value,
                            "details": change.get_change_details(),
                            "old_hash": change.old_state.sha256 if change.old_state else None,
                            "new_hash": change.new_state.sha256 if change.new_state else None,
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
        - New SUID/SGID binaries
        - Removed SUID from legitimate binaries

    MITRE: T1548.001 (Setuid/Setgid), T1068 (Exploitation for Privilege Escalation)
    """

    name = "suid_bit_change"
    description = "SUID/SGID privilege escalation detection"
    mitre_techniques = ["T1548.001", "T1068"]
    mitre_tactics = ["Privilege Escalation"]
    default_enabled = True
    scan_interval = 60.0

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect SUID/SGID changes."""
        events: List[TelemetryEvent] = []
        file_changes: List[FileChange] = context.shared_data.get("file_changes", [])

        for change in file_changes:
            if not change.new_state or change.new_state.is_dir:
                continue

            # Check for SUID/SGID bit changes
            old_suid = change.old_state.has_suid() if change.old_state else False
            new_suid = change.new_state.has_suid() if change.new_state else False
            old_sgid = change.old_state.has_sgid() if change.old_state else False
            new_sgid = change.new_state.has_sgid() if change.new_state else False

            if new_suid and not old_suid:
                events.append(
                    TelemetryEvent(
                        event_type="suid_bit_added",
                        severity=Severity.CRITICAL,
                        probe_name=self.name,
                        data={
                            "path": change.path,
                            "mode": oct(change.new_state.mode),
                            "owner_uid": change.new_state.uid,
                            "reason": "SUID bit added (privilege escalation risk)",
                        },
                        mitre_techniques=["T1548.001"],
                    )
                )

            if new_sgid and not old_sgid:
                events.append(
                    TelemetryEvent(
                        event_type="sgid_bit_added",
                        severity=Severity.HIGH,
                        probe_name=self.name,
                        data={
                            "path": change.path,
                            "mode": oct(change.new_state.mode),
                            "owner_gid": change.new_state.gid,
                            "reason": "SGID bit added",
                        },
                        mitre_techniques=["T1548.001"],
                    )
                )

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

            if change.change_type == ChangeType.CREATED:
                events.append(
                    TelemetryEvent(
                        event_type="service_created",
                        severity=Severity.HIGH,
                        probe_name=self.name,
                        data={
                            "path": change.path,
                            "reason": "New service/launch agent created",
                        },
                        mitre_techniques=["T1543", "T1053"],
                    )
                )

            elif change.change_type in (ChangeType.MODIFIED, ChangeType.HASH_CHANGED):
                events.append(
                    TelemetryEvent(
                        event_type="service_modified",
                        severity=Severity.MEDIUM,
                        probe_name=self.name,
                        data={
                            "path": change.path,
                            "change_type": change.change_type.value,
                            "reason": "Existing service modified",
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
            if change.change_type in (ChangeType.CREATED, ChangeType.MODIFIED, ChangeType.HASH_CHANGED):
                is_suspicious, patterns_matched = self._check_webshell_patterns(change.path)

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
            if is_lib_path and change.path.endswith(".so") and change.change_type == ChangeType.CREATED:
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

    Watches:
        - /boot directory (kernels, initramfs, grub configs)
        - EFI boot entries

    Flags:
        - New kernel images
        - GRUB config modifications
        - initramfs changes

    MITRE: T1542.003 (Bootloader Modification)
    """

    name = "bootloader_tamper"
    description = "Bootkit/kernel tampering detection"
    mitre_techniques = ["T1542.003"]
    mitre_tactics = ["Persistence", "Defense Evasion"]
    default_enabled = True
    scan_interval = 120.0

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect bootloader tampering."""
        events: List[TelemetryEvent] = []
        file_changes: List[FileChange] = context.shared_data.get("file_changes", [])

        for change in file_changes:
            # Check if in /boot
            if not change.path.startswith("/boot"):
                continue

            # Flag any changes to boot directory
            if change.change_type in (
                ChangeType.CREATED,
                ChangeType.MODIFIED,
                ChangeType.HASH_CHANGED,
            ):
                # Determine severity based on file type
                severity = Severity.CRITICAL if any(
                    x in change.path for x in ["vmlinuz", "initrd", "grub", "efi"]
                ) else Severity.HIGH

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

    SENSITIVE_PATHS = {"/etc", "/var/log", "/var/www", "/usr/bin", "/usr/sbin"}

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect world-writable sensitive files."""
        events: List[TelemetryEvent] = []
        file_changes: List[FileChange] = context.shared_data.get("file_changes", [])

        for change in file_changes:
            if not change.new_state:
                continue

            # Check if in sensitive path
            is_sensitive = any(
                change.path.startswith(p) for p in self.SENSITIVE_PATHS
            )
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
                            "old_mode": oct(change.old_state.mode) if change.old_state else None,
                            "new_mode": oct(change.new_state.mode),
                            "reason": "Sensitive file made world-writable",
                        },
                        mitre_techniques=["T1565", "T1070"],
                    )
                )

        return events


# =============================================================================
# Probe Factory
# =============================================================================


def create_fim_probes() -> List[MicroProbe]:
    """Create all FIM micro-probes.

    Returns:
        List of 8 FIM probes
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
    ]
