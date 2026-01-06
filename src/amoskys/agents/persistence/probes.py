#!/usr/bin/env python3
"""PersistenceGuard Micro-Probes - Autostart & Backdoor Detection.

This module provides 8 specialized micro-probes for detecting persistence mechanisms:
    1. LaunchAgentDaemonProbe - macOS launchd persistence
    2. SystemdServicePersistenceProbe - Linux systemd services
    3. CronJobPersistenceProbe - cron/anacron @reboot
    4. SSHKeyBackdoorProbe - authorized_keys tampering
    5. ShellProfileHijackProbe - bashrc/zshrc hijacking
    6. BrowserExtensionPersistenceProbe - malicious extensions
    7. StartupFolderLoginItemProbe - GUI autostart items
    8. HiddenFilePersistenceProbe - hidden executable loaders

Architecture:
    - PersistenceEntry: Snapshot of a persistence mechanism
    - PersistenceChange: Diff between baseline and current state
    - PersistenceBaselineEngine: Snapshot & diff management
    - Probes: Detect threats in PersistenceChange objects
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from dataclasses import asdict, dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional

from amoskys.agents.common.probes import MicroProbe, ProbeContext, Severity, TelemetryEvent

logger = logging.getLogger(__name__)


# =============================================================================
# Data Models
# =============================================================================


@dataclass
class PersistenceEntry:
    """Snapshot of a persistence mechanism at a point in time."""

    id: str  # stable ID (path or logical identifier)
    mechanism_type: str  # LAUNCH_AGENT, SYSTEMD_SERVICE, CRON_JOB, SSH_KEY, etc.
    user: Optional[str]  # owner / user context (root, alice, etc.)
    path: Optional[str]  # filesystem path if applicable
    command: Optional[str]  # command that will execute
    args: Optional[str]  # arguments or plist ProgramArguments equivalent
    enabled: bool  # is it active/enabled?
    hash: Optional[str]  # sha256 of underlying file/command/config
    metadata: Dict[str, str]  # extra: run_level, frequency, browser, etc.
    last_seen_ns: int  # when we last observed this


class PersistenceChangeType(Enum):
    """Types of changes to persistence mechanisms."""

    CREATED = auto()
    MODIFIED = auto()
    DELETED = auto()
    ENABLED = auto()
    DISABLED = auto()


@dataclass
class PersistenceChange:
    """Represents a change in persistence configuration."""

    entry_id: str
    mechanism_type: str
    change_type: PersistenceChangeType
    old_entry: Optional[PersistenceEntry]
    new_entry: Optional[PersistenceEntry]
    timestamp_ns: int


# =============================================================================
# Baseline Engine
# =============================================================================


class PersistenceBaselineEngine:
    """Manages baseline snapshots and change detection for persistence mechanisms."""

    def __init__(self, baseline_path: str):
        """Initialize baseline engine.

        Args:
            baseline_path: Path to baseline JSON file
        """
        self.baseline_path = baseline_path
        self.entries: Dict[str, PersistenceEntry] = {}

    def load(self) -> bool:
        """Load baseline from disk.

        Returns:
            True if loaded successfully, False otherwise
        """
        if not os.path.exists(self.baseline_path):
            logger.warning(f"Baseline file not found: {self.baseline_path}")
            return False

        try:
            with open(self.baseline_path, "r") as f:
                data = json.load(f)

            # Reconstruct PersistenceEntry objects
            self.entries = {}
            for entry_id, entry_dict in data.items():
                self.entries[entry_id] = PersistenceEntry(**entry_dict)

            logger.info(
                f"Loaded baseline: {len(self.entries)} persistence entries from {self.baseline_path}"
            )
            return True

        except (OSError, json.JSONDecodeError) as e:
            logger.error(f"Failed to load baseline: {e}")
            return False

    def save(self) -> None:
        """Save baseline to disk."""
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.baseline_path), exist_ok=True)

            # Convert to JSON-serializable dict
            data = {entry_id: asdict(entry) for entry_id, entry in self.entries.items()}

            with open(self.baseline_path, "w") as f:
                json.dump(data, f, indent=2)

            logger.info(
                f"Saved baseline: {len(self.entries)} persistence entries to {self.baseline_path}"
            )

        except OSError as e:
            logger.error(f"Failed to save baseline: {e}")

    def create_from_snapshot(
        self, snapshot: Dict[str, PersistenceEntry]
    ) -> None:
        """Initialize baseline from a snapshot.

        Args:
            snapshot: Current persistence state
        """
        self.entries = snapshot.copy()
        logger.info(f"Created baseline with {len(self.entries)} entries")

    def compare(
        self, current: Dict[str, PersistenceEntry]
    ) -> List[PersistenceChange]:
        """Compare current snapshot against baseline and detect changes.

        Args:
            current: Current persistence state

        Returns:
            List of detected changes
        """
        changes: List[PersistenceChange] = []
        now_ns = int(1e9 * __import__("time").time())

        # 1. CREATED: in current, not in baseline
        for entry_id, new_entry in current.items():
            if entry_id not in self.entries:
                changes.append(
                    PersistenceChange(
                        entry_id=entry_id,
                        mechanism_type=new_entry.mechanism_type,
                        change_type=PersistenceChangeType.CREATED,
                        old_entry=None,
                        new_entry=new_entry,
                        timestamp_ns=now_ns,
                    )
                )

        # 2. DELETED: in baseline, not in current
        for entry_id, old_entry in self.entries.items():
            if entry_id not in current:
                changes.append(
                    PersistenceChange(
                        entry_id=entry_id,
                        mechanism_type=old_entry.mechanism_type,
                        change_type=PersistenceChangeType.DELETED,
                        old_entry=old_entry,
                        new_entry=None,
                        timestamp_ns=now_ns,
                    )
                )

        # 3. MODIFIED/ENABLED/DISABLED: in both but different
        for entry_id in set(self.entries.keys()) & set(current.keys()):
            old_entry = self.entries[entry_id]
            new_entry = current[entry_id]

            # Check for enable/disable transitions
            if old_entry.enabled != new_entry.enabled:
                if new_entry.enabled:
                    changes.append(
                        PersistenceChange(
                            entry_id=entry_id,
                            mechanism_type=new_entry.mechanism_type,
                            change_type=PersistenceChangeType.ENABLED,
                            old_entry=old_entry,
                            new_entry=new_entry,
                            timestamp_ns=now_ns,
                        )
                    )
                else:
                    changes.append(
                        PersistenceChange(
                            entry_id=entry_id,
                            mechanism_type=new_entry.mechanism_type,
                            change_type=PersistenceChangeType.DISABLED,
                            old_entry=old_entry,
                            new_entry=new_entry,
                            timestamp_ns=now_ns,
                        )
                    )

            # Check for command/hash modifications
            elif (
                old_entry.command != new_entry.command
                or old_entry.hash != new_entry.hash
                or old_entry.args != new_entry.args
            ):
                changes.append(
                    PersistenceChange(
                        entry_id=entry_id,
                        mechanism_type=new_entry.mechanism_type,
                        change_type=PersistenceChangeType.MODIFIED,
                        old_entry=old_entry,
                        new_entry=new_entry,
                        timestamp_ns=now_ns,
                    )
                )

        logger.debug(f"Detected {len(changes)} persistence changes")
        return changes


# =============================================================================
# Detection Patterns
# =============================================================================

# Suspicious command patterns (shell spawning, interpreters, downloaders)
SUSPICIOUS_COMMAND_PATTERNS = [
    rb"bash",
    rb"sh\s",
    rb"/bin/sh",
    rb"/bin/bash",
    rb"zsh",
    rb"python",
    rb"perl",
    rb"ruby",
    rb"curl.*\|",
    rb"wget.*\|",
    rb"curl.*sh",
    rb"wget.*sh",
    rb"nc\s",  # netcat
    rb"ncat",
    rb"/tmp/",
    rb"/var/tmp/",
    rb"eval\s*\(",
    rb"exec\s*\(",
]

# Suspicious paths for executables
SUSPICIOUS_PATHS = [
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/Users/Shared",
    "/.local",
    "/.cache",
]

# Shell profile paths
SHELL_PROFILE_PATHS = [
    "/.bashrc",
    "/.bash_profile",
    "/.profile",
    "/.zshrc",
    "/etc/profile",
    "/etc/bash.bashrc",
]

# Dangerous browser extension permissions
DANGEROUS_EXTENSION_PERMISSIONS = [
    "tabs",
    "webRequest",
    "webRequestBlocking",
    "<all_urls>",
    "proxy",
    "cookies",
]


def is_suspicious_command(command: Optional[str]) -> bool:
    """Check if command contains suspicious patterns.

    Args:
        command: Command string to check

    Returns:
        True if suspicious, False otherwise
    """
    if not command:
        return False

    command_bytes = command.encode("utf-8", errors="ignore")
    for pattern in SUSPICIOUS_COMMAND_PATTERNS:
        if re.search(pattern, command_bytes, re.IGNORECASE):
            return True
    return False


def is_suspicious_path(path: Optional[str]) -> bool:
    """Check if path is in suspicious location.

    Args:
        path: File path to check

    Returns:
        True if suspicious, False otherwise
    """
    if not path:
        return False

    for suspicious_dir in SUSPICIOUS_PATHS:
        if path.startswith(suspicious_dir):
            return True
    return False


# =============================================================================
# Micro-Probes
# =============================================================================


class LaunchAgentDaemonProbe(MicroProbe):
    """Detects macOS launchd persistence mechanisms (LaunchAgents/LaunchDaemons)."""

    name = "launchd_persistence"
    description = "Detect new or modified macOS LaunchAgents/LaunchDaemons"
    mitre_techniques = ["T1543.001", "T1037.005"]
    mitre_tactics = ["Persistence", "Privilege Escalation"]
    platforms = ["darwin"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan for launchd persistence changes."""
        changes: List[PersistenceChange] = context.shared_data.get(
            "persistence_changes", []
        )
        events = []

        for change in changes:
            if change.mechanism_type not in ["LAUNCH_AGENT", "LAUNCH_DAEMON"]:
                continue

            entry = change.new_entry if change.new_entry else change.old_entry
            if not entry:
                continue

            # CREATED - new launchd entry
            if change.change_type == PersistenceChangeType.CREATED:
                severity = Severity.MEDIUM
                reason = "New launchd entry created"

                # Escalate if suspicious
                if is_suspicious_command(entry.command):
                    severity = Severity.HIGH
                    reason = "New launchd entry with suspicious command"
                elif is_suspicious_path(entry.path):
                    severity = Severity.HIGH
                    reason = "New launchd entry in suspicious location"
                elif entry.user and entry.user != "root":
                    severity = Severity.HIGH
                    reason = "New user-owned launchd entry"

                events.append(
                    TelemetryEvent(
                        event_type="persistence_launchd_created",
                        severity=severity,
                        probe_name=self.name,
                        timestamp_ns=change.timestamp_ns,
                        data={
                            "entry_id": entry.id,
                            "mechanism": entry.mechanism_type,
                            "path": entry.path or "",
                            "command": entry.command or "",
                            "user": entry.user or "",
                            "reason": reason,
                        },
                        mitre_techniques=self.mitre_techniques,
                        mitre_tactics=self.mitre_tactics,
                    )
                )

            # MODIFIED - command/args changed
            elif change.change_type == PersistenceChangeType.MODIFIED:
                severity = Severity.MEDIUM
                reason = "LaunchAgent/Daemon modified"

                if is_suspicious_command(entry.command):
                    severity = Severity.HIGH
                    reason = "LaunchAgent/Daemon modified to suspicious command"

                events.append(
                    TelemetryEvent(
                        event_type="persistence_launchd_modified",
                        severity=severity,
                        probe_name=self.name,
                        timestamp_ns=change.timestamp_ns,
                        data={
                            "entry_id": entry.id,
                            "mechanism": entry.mechanism_type,
                            "path": entry.path or "",
                            "old_command": change.old_entry.command if change.old_entry else "",
                            "new_command": entry.command or "",
                            "reason": reason,
                        },
                        mitre_techniques=self.mitre_techniques,
                        mitre_tactics=self.mitre_tactics,
                    )
                )

        return events


class SystemdServicePersistenceProbe(MicroProbe):
    """Detects Linux systemd service persistence mechanisms."""

    name = "systemd_persistence"
    description = "Detect new or modified systemd services"
    mitre_techniques = ["T1543.002"]
    mitre_tactics = ["Persistence", "Privilege Escalation"]
    platforms = ["linux"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan for systemd service changes."""
        changes: List[PersistenceChange] = context.shared_data.get(
            "persistence_changes", []
        )
        events = []

        for change in changes:
            if change.mechanism_type != "SYSTEMD_SERVICE":
                continue

            entry = change.new_entry if change.new_entry else change.old_entry
            if not entry:
                continue

            # CREATED - new systemd service
            if change.change_type == PersistenceChangeType.CREATED:
                severity = Severity.MEDIUM
                reason = "New systemd service created"

                # Escalate if suspicious
                if is_suspicious_command(entry.command):
                    severity = Severity.HIGH
                    reason = "New systemd service with suspicious ExecStart"
                elif is_suspicious_path(entry.path):
                    severity = Severity.HIGH
                    reason = "New systemd service in user directory"
                elif entry.user and entry.user != "root":
                    severity = Severity.HIGH
                    reason = "New user-owned systemd service"

                events.append(
                    TelemetryEvent(
                        event_type="persistence_systemd_service_created",
                        severity=severity,
                        probe_name=self.name,
                        timestamp_ns=change.timestamp_ns,
                        data={
                            "entry_id": entry.id,
                            "path": entry.path or "",
                            "command": entry.command or "",
                            "user": entry.user or "",
                            "enabled": entry.enabled,
                            "reason": reason,
                        },
                        mitre_techniques=self.mitre_techniques,
                        mitre_tactics=self.mitre_tactics,
                    )
                )

            # MODIFIED - ExecStart changed
            elif change.change_type == PersistenceChangeType.MODIFIED:
                severity = Severity.MEDIUM
                reason = "Systemd service modified"

                if is_suspicious_command(entry.command):
                    severity = Severity.HIGH
                    reason = "Systemd service modified to suspicious ExecStart"

                events.append(
                    TelemetryEvent(
                        event_type="persistence_systemd_service_modified",
                        severity=severity,
                        probe_name=self.name,
                        timestamp_ns=change.timestamp_ns,
                        data={
                            "entry_id": entry.id,
                            "path": entry.path or "",
                            "old_command": change.old_entry.command if change.old_entry else "",
                            "new_command": entry.command or "",
                            "reason": reason,
                        },
                        mitre_techniques=self.mitre_techniques,
                        mitre_tactics=self.mitre_tactics,
                    )
                )

            # ENABLED - service enabled
            elif change.change_type == PersistenceChangeType.ENABLED:
                events.append(
                    TelemetryEvent(
                        event_type="persistence_systemd_service_enabled",
                        severity=Severity.MEDIUM,
                        probe_name=self.name,
                        timestamp_ns=change.timestamp_ns,
                        data={
                            "entry_id": entry.id,
                            "path": entry.path or "",
                            "command": entry.command or "",
                        },
                        mitre_techniques=self.mitre_techniques,
                        mitre_tactics=self.mitre_tactics,
                    )
                )

            # DISABLED - service disabled (informational)
            elif change.change_type == PersistenceChangeType.DISABLED:
                events.append(
                    TelemetryEvent(
                        event_type="persistence_systemd_service_disabled",
                        severity=Severity.INFO,
                        probe_name=self.name,
                        timestamp_ns=change.timestamp_ns,
                        data={
                            "entry_id": entry.id,
                            "path": entry.path or "",
                        },
                        mitre_techniques=self.mitre_techniques,
                        mitre_tactics=self.mitre_tactics,
                    )
                )

        return events


class CronJobPersistenceProbe(MicroProbe):
    """Detects cron/anacron persistence mechanisms."""

    name = "cron_persistence"
    description = "Detect new or modified cron jobs, especially @reboot entries"
    mitre_techniques = ["T1053.003"]
    mitre_tactics = ["Persistence", "Privilege Escalation", "Execution"]
    platforms = ["linux", "darwin"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan for cron job changes."""
        changes: List[PersistenceChange] = context.shared_data.get(
            "persistence_changes", []
        )
        events = []

        for change in changes:
            if change.mechanism_type != "CRON_JOB":
                continue

            entry = change.new_entry if change.new_entry else change.old_entry
            if not entry:
                continue

            # CREATED - new cron entry
            if change.change_type == PersistenceChangeType.CREATED:
                severity = Severity.MEDIUM
                reason = "New cron job created"

                # Escalate if @reboot or suspicious command
                is_reboot = entry.metadata.get("schedule") == "@reboot"
                if is_reboot and is_suspicious_command(entry.command):
                    severity = Severity.HIGH
                    reason = "New @reboot cron with suspicious command"
                elif is_reboot:
                    severity = Severity.HIGH
                    reason = "New @reboot cron entry"
                elif is_suspicious_command(entry.command):
                    severity = Severity.HIGH
                    reason = "New cron job with suspicious command"

                events.append(
                    TelemetryEvent(
                        event_type="persistence_cron_created",
                        severity=severity,
                        probe_name=self.name,
                        timestamp_ns=change.timestamp_ns,
                        data={
                            "entry_id": entry.id,
                            "command": entry.command or "",
                            "schedule": entry.metadata.get("schedule", "unknown"),
                            "user": entry.user or "",
                            "reason": reason,
                        },
                        mitre_techniques=self.mitre_techniques,
                        mitre_tactics=self.mitre_tactics,
                    )
                )

            # MODIFIED - command changed
            elif change.change_type == PersistenceChangeType.MODIFIED:
                severity = Severity.MEDIUM
                reason = "Cron job modified"

                if is_suspicious_command(entry.command):
                    severity = Severity.HIGH
                    reason = "Cron job modified to suspicious command"

                events.append(
                    TelemetryEvent(
                        event_type="persistence_cron_modified",
                        severity=severity,
                        probe_name=self.name,
                        timestamp_ns=change.timestamp_ns,
                        data={
                            "entry_id": entry.id,
                            "old_command": change.old_entry.command if change.old_entry else "",
                            "new_command": entry.command or "",
                            "reason": reason,
                        },
                        mitre_techniques=self.mitre_techniques,
                        mitre_tactics=self.mitre_tactics,
                    )
                )

        return events


class SSHKeyBackdoorProbe(MicroProbe):
    """Detects SSH authorized_keys backdoor persistence."""

    name = "ssh_key_backdoor"
    description = "Detect unauthorized SSH keys in authorized_keys files"
    mitre_techniques = ["T1098.004"]
    mitre_tactics = ["Persistence", "Privilege Escalation"]
    platforms = ["linux", "darwin"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan for SSH key changes."""
        changes: List[PersistenceChange] = context.shared_data.get(
            "persistence_changes", []
        )
        events = []

        for change in changes:
            if change.mechanism_type != "SSH_AUTHORIZED_KEY":
                continue

            entry = change.new_entry if change.new_entry else change.old_entry
            if not entry:
                continue

            # CREATED - new SSH key added
            if change.change_type == PersistenceChangeType.CREATED:
                severity = Severity.HIGH
                reason = "New SSH authorized key added"

                # Escalate to CRITICAL for root or system accounts
                if entry.user in ["root", "admin", "administrator"]:
                    severity = Severity.CRITICAL
                    reason = f"New SSH key for {entry.user} account"

                # Check for forced command backdoor
                has_forced_command = entry.metadata.get("has_forced_command", False)
                if has_forced_command:
                    severity = Severity.HIGH
                    reason = "New SSH key with forced command directive"

                events.append(
                    TelemetryEvent(
                        event_type="persistence_ssh_key_added",
                        severity=severity,
                        probe_name=self.name,
                        timestamp_ns=change.timestamp_ns,
                        data={
                            "entry_id": entry.id,
                            "user": entry.user or "",
                            "path": entry.path or "",
                            "key_fingerprint": entry.hash or "",
                            "forced_command": has_forced_command,
                            "reason": reason,
                        },
                        mitre_techniques=self.mitre_techniques,
                        mitre_tactics=self.mitre_tactics,
                    )
                )

            # DELETED - SSH key removed (informational)
            elif change.change_type == PersistenceChangeType.DELETED:
                events.append(
                    TelemetryEvent(
                        event_type="persistence_ssh_key_removed",
                        severity=Severity.INFO,
                        probe_name=self.name,
                        timestamp_ns=change.timestamp_ns,
                        data={
                            "entry_id": entry.id,
                            "user": entry.user or "",
                            "path": entry.path or "",
                        },
                        mitre_techniques=self.mitre_techniques,
                        mitre_tactics=self.mitre_tactics,
                    )
                )

        return events


class ShellProfileHijackProbe(MicroProbe):
    """Detects shell profile hijacking (bashrc, zshrc, profile)."""

    name = "shell_profile_hijack"
    description = "Detect malicious modifications to shell profiles"
    mitre_techniques = ["T1037.004", "T1546.004"]
    mitre_tactics = ["Persistence", "Privilege Escalation"]
    platforms = ["linux", "darwin"]

    # Patterns that indicate malicious shell profile modifications
    MALICIOUS_PATTERNS = [
        rb"alias\s+sudo=",  # sudo override
        rb"eval\s*\$\(curl",  # curl | eval
        rb"eval\s*\$\(wget",  # wget | eval
        rb"curl.*\|\s*bash",
        rb"wget.*\|\s*bash",
        rb"python\s*-c",  # python one-liner
        rb"perl\s*-e",  # perl one-liner
        rb"export\s+PATH=.*\/tmp",  # PATH to /tmp
        rb"nc\s+-l",  # netcat listener
    ]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan for shell profile changes."""
        changes: List[PersistenceChange] = context.shared_data.get(
            "persistence_changes", []
        )
        events = []

        for change in changes:
            if change.mechanism_type != "SHELL_PROFILE":
                continue

            entry = change.new_entry if change.new_entry else change.old_entry
            if not entry:
                continue

            # MODIFIED - shell profile changed
            if change.change_type in [
                PersistenceChangeType.CREATED,
                PersistenceChangeType.MODIFIED,
            ]:
                severity = Severity.MEDIUM
                reason = "Shell profile modified"
                matched_patterns = []

                # Check for malicious patterns
                if entry.command:
                    command_bytes = entry.command.encode("utf-8", errors="ignore")
                    for pattern in self.MALICIOUS_PATTERNS:
                        if re.search(pattern, command_bytes, re.IGNORECASE):
                            matched_patterns.append(pattern.decode("utf-8", errors="ignore"))

                if matched_patterns:
                    severity = Severity.HIGH
                    reason = f"Shell profile modified with suspicious patterns: {', '.join(matched_patterns[:3])}"

                events.append(
                    TelemetryEvent(
                        event_type="persistence_shell_profile_modified",
                        severity=severity,
                        probe_name=self.name,
                        timestamp_ns=change.timestamp_ns,
                        data={
                            "entry_id": entry.id,
                            "path": entry.path or "",
                            "user": entry.user or "",
                            "suspicious_patterns": ", ".join(matched_patterns),
                            "reason": reason,
                        },
                        mitre_techniques=self.mitre_techniques,
                        mitre_tactics=self.mitre_tactics,
                    )
                )

        return events


class BrowserExtensionPersistenceProbe(MicroProbe):
    """Detects malicious browser extension persistence."""

    name = "browser_extension_persistence"
    description = "Detect suspicious browser extensions"
    mitre_techniques = ["T1176"]
    mitre_tactics = ["Persistence"]
    platforms = ["linux", "darwin", "windows"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan for browser extension changes."""
        changes: List[PersistenceChange] = context.shared_data.get(
            "persistence_changes", []
        )
        events = []

        for change in changes:
            if change.mechanism_type != "BROWSER_EXTENSION":
                continue

            entry = change.new_entry if change.new_entry else change.old_entry
            if not entry:
                continue

            # CREATED - new browser extension installed
            if change.change_type == PersistenceChangeType.CREATED:
                severity = Severity.MEDIUM
                reason = "New browser extension installed"

                # Check for dangerous permissions
                permissions = entry.metadata.get("permissions", "").split(",")
                dangerous_perms = [p for p in permissions if p in DANGEROUS_EXTENSION_PERMISSIONS]

                is_unknown_publisher = entry.metadata.get("unknown_publisher", False)

                if dangerous_perms and is_unknown_publisher:
                    severity = Severity.HIGH
                    reason = f"Unknown browser extension with dangerous permissions: {', '.join(dangerous_perms)}"

                events.append(
                    TelemetryEvent(
                        event_type="persistence_browser_extension_installed",
                        severity=severity,
                        probe_name=self.name,
                        timestamp_ns=change.timestamp_ns,
                        data={
                            "entry_id": entry.id,
                            "browser": entry.metadata.get("browser", "unknown"),
                            "extension_name": entry.metadata.get("name", "unknown"),
                            "permissions": ", ".join(dangerous_perms),
                            "unknown_publisher": is_unknown_publisher,
                            "reason": reason,
                        },
                        mitre_techniques=self.mitre_techniques,
                        mitre_tactics=self.mitre_tactics,
                    )
                )

            # MODIFIED - extension modified
            elif change.change_type == PersistenceChangeType.MODIFIED:
                events.append(
                    TelemetryEvent(
                        event_type="persistence_browser_extension_modified",
                        severity=Severity.MEDIUM,
                        probe_name=self.name,
                        timestamp_ns=change.timestamp_ns,
                        data={
                            "entry_id": entry.id,
                            "browser": entry.metadata.get("browser", "unknown"),
                            "extension_name": entry.metadata.get("name", "unknown"),
                        },
                        mitre_techniques=self.mitre_techniques,
                        mitre_tactics=self.mitre_tactics,
                    )
                )

        return events


class StartupFolderLoginItemProbe(MicroProbe):
    """Detects GUI startup items and autostart folder entries."""

    name = "startup_folder_login_item"
    description = "Detect suspicious startup items in autostart folders"
    mitre_techniques = ["T1547.001", "T1037.001"]
    mitre_tactics = ["Persistence"]
    platforms = ["linux", "darwin", "windows"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan for startup item changes."""
        changes: List[PersistenceChange] = context.shared_data.get(
            "persistence_changes", []
        )
        events = []

        for change in changes:
            if change.mechanism_type != "STARTUP_ITEM":
                continue

            entry = change.new_entry if change.new_entry else change.old_entry
            if not entry:
                continue

            # CREATED - new startup item
            if change.change_type == PersistenceChangeType.CREATED:
                severity = Severity.MEDIUM
                reason = "New startup item created"

                # Escalate if suspicious command or path
                if is_suspicious_command(entry.command) or is_suspicious_path(entry.path):
                    severity = Severity.HIGH
                    reason = "New startup item with suspicious command/path"

                events.append(
                    TelemetryEvent(
                        event_type="persistence_startup_item_created",
                        severity=severity,
                        probe_name=self.name,
                        timestamp_ns=change.timestamp_ns,
                        data={
                            "entry_id": entry.id,
                            "path": entry.path or "",
                            "command": entry.command or "",
                            "user": entry.user or "",
                            "reason": reason,
                        },
                        mitre_techniques=self.mitre_techniques,
                        mitre_tactics=self.mitre_tactics,
                    )
                )

            # MODIFIED - startup item changed
            elif change.change_type == PersistenceChangeType.MODIFIED:
                severity = Severity.MEDIUM
                if is_suspicious_command(entry.command):
                    severity = Severity.HIGH

                events.append(
                    TelemetryEvent(
                        event_type="persistence_startup_item_modified",
                        severity=severity,
                        probe_name=self.name,
                        timestamp_ns=change.timestamp_ns,
                        data={
                            "entry_id": entry.id,
                            "path": entry.path or "",
                            "old_command": change.old_entry.command if change.old_entry else "",
                            "new_command": entry.command or "",
                        },
                        mitre_techniques=self.mitre_techniques,
                        mitre_tactics=self.mitre_tactics,
                    )
                )

        return events


class HiddenFilePersistenceProbe(MicroProbe):
    """Detects hidden file persistence mechanisms (hidden executables, loaders)."""

    name = "hidden_file_persistence"
    description = "Detect hidden executable files used for persistence"
    mitre_techniques = ["T1564", "T1053", "T1547"]
    mitre_tactics = ["Persistence", "Defense Evasion"]
    platforms = ["linux", "darwin"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan for hidden file persistence."""
        changes: List[PersistenceChange] = context.shared_data.get(
            "persistence_changes", []
        )
        events = []

        for change in changes:
            if change.mechanism_type != "HIDDEN_FILE_PERSISTENCE":
                continue

            entry = change.new_entry if change.new_entry else change.old_entry
            if not entry:
                continue

            # CREATED - new hidden file
            if change.change_type == PersistenceChangeType.CREATED:
                severity = Severity.MEDIUM
                reason = "New hidden file created"

                # Escalate if executable in suspicious dir
                is_executable = entry.metadata.get("is_executable", False)
                if is_executable and is_suspicious_path(entry.path):
                    severity = Severity.HIGH
                    reason = "New hidden executable in suspicious directory"
                elif is_executable:
                    severity = Severity.HIGH
                    reason = "New hidden executable file"

                events.append(
                    TelemetryEvent(
                        event_type="persistence_hidden_loader_created",
                        severity=severity,
                        probe_name=self.name,
                        timestamp_ns=change.timestamp_ns,
                        data={
                            "entry_id": entry.id,
                            "path": entry.path or "",
                            "is_executable": is_executable,
                            "referenced_by": entry.metadata.get("referenced_by", ""),
                            "reason": reason,
                        },
                        mitre_techniques=self.mitre_techniques,
                        mitre_tactics=self.mitre_tactics,
                    )
                )

        return events


# =============================================================================
# Factory
# =============================================================================


def create_persistence_probes() -> List[MicroProbe]:
    """Create all persistence micro-probes.

    Returns:
        List of 8 persistence probes
    """
    return [
        LaunchAgentDaemonProbe(),
        SystemdServicePersistenceProbe(),
        CronJobPersistenceProbe(),
        SSHKeyBackdoorProbe(),
        ShellProfileHijackProbe(),
        BrowserExtensionPersistenceProbe(),
        StartupFolderLoginItemProbe(),
        HiddenFilePersistenceProbe(),
    ]
