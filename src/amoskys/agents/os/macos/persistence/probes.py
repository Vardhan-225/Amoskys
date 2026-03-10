"""macOS Persistence Probes — 10 detection probes for persistence mechanisms.

Each probe consumes PersistenceEntry data from MacOSPersistenceCollector
via shared_data["entries"]. Uses baseline-diff: stores previous hashes
to detect additions, modifications, and removals.

Probes:
    1. LaunchAgentProbe — new/modified user LaunchAgents
    2. LaunchDaemonProbe — new/modified system LaunchDaemons
    3. LoginItemProbe — new Login Items
    4. CronProbe — new/modified cron jobs
    5. ShellProfileProbe — shell profile modification
    6. SSHKeyProbe — authorized_keys / config changes
    7. AuthPluginProbe — authorization plugin changes
    8. FolderActionProbe — Folder Action additions
    9. SystemExtensionProbe — new system extensions
   10. PeriodicScriptProbe — periodic script changes

MITRE: T1543, T1053, T1546, T1547, T1098
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)

logger = logging.getLogger(__name__)


class _BaselineDiffProbe(MicroProbe):
    """Base class for baseline-diff persistence probes.

    Tracks content_hash per path. Detects:
        - NEW: path not in baseline
        - MODIFIED: path exists but hash changed
        - REMOVED: path was in baseline but not in current scan
    """

    _target_categories: List[str] = []  # Override in subclass
    platforms = ["darwin"]
    requires_fields = ["entries"]

    def __init__(self) -> None:
        super().__init__()
        self._baseline: Dict[str, str] = {}  # path -> content_hash
        self._first_run = True

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        entries = context.shared_data.get("entries", [])

        # Filter to our target categories
        current: Dict[str, Any] = {}
        for entry in entries:
            if entry.category in self._target_categories:
                current[entry.path] = entry

        if self._first_run:
            # Establish baseline
            self._baseline = {path: e.content_hash for path, e in current.items()}
            self._first_run = False
            return events

        # Detect NEW entries
        for path, entry in current.items():
            if path not in self._baseline:
                events.append(
                    self._make_event(
                        "new",
                        entry,
                        Severity.HIGH,
                    )
                )

        # Detect MODIFIED entries
        for path, entry in current.items():
            if path in self._baseline and entry.content_hash != self._baseline[path]:
                events.append(
                    self._make_event(
                        "modified",
                        entry,
                        Severity.HIGH,
                    )
                )

        # Detect REMOVED entries
        for path in self._baseline:
            if path not in current:
                events.append(
                    self._create_event(
                        event_type=f"{self.name}_removed",
                        severity=Severity.MEDIUM,
                        data={
                            "path": path,
                            "change_type": "removed",
                        },
                        confidence=0.9,
                    )
                )

        # Update baseline
        self._baseline = {path: e.content_hash for path, e in current.items()}

        return events

    def _make_event(
        self, change_type: str, entry: Any, severity: Severity
    ) -> TelemetryEvent:
        """Create event for a persistence change."""
        data: Dict[str, Any] = {
            "path": entry.path,
            "name": entry.name,
            "category": entry.category,
            "content_hash": entry.content_hash,
            "change_type": change_type,
        }
        # Add plist-specific fields if available
        if entry.program:
            data["program"] = entry.program
        if entry.label:
            data["label"] = entry.label
        if entry.run_at_load:
            data["run_at_load"] = True
        if entry.keep_alive:
            data["keep_alive"] = True
        if entry.metadata:
            data["metadata"] = entry.metadata

        return self._create_event(
            event_type=f"{self.name}_{change_type}",
            severity=severity,
            data=data,
            confidence=0.9,
        )


# =============================================================================
# 1. LaunchAgentProbe
# =============================================================================


class LaunchAgentProbe(_BaselineDiffProbe):
    """Detects new/modified LaunchAgents on macOS.

    LaunchAgents are the #1 macOS persistence mechanism. Monitors:
        - ~/Library/LaunchAgents/ (user)
        - /Library/LaunchAgents/ (system)
        - /System/Library/LaunchAgents/ (Apple — should never change)

    MITRE: T1543.001 (Create/Modify System Process: Launch Agent)
    """

    name = "macos_launchagent"
    description = "Detects new/modified LaunchAgents on macOS"
    mitre_techniques = ["T1543.001"]
    mitre_tactics = ["persistence", "privilege_escalation"]
    scan_interval = 30.0

    _target_categories = ["launchagent_user", "launchagent_system", "launchagent_apple"]

    def _make_event(
        self, change_type: str, entry: Any, severity: Severity
    ) -> TelemetryEvent:
        # Apple LaunchAgent changes are CRITICAL (SIP should protect these)
        if entry.category == "launchagent_apple":
            severity = Severity.CRITICAL
        # RunAtLoad agents are higher priority
        elif entry.run_at_load and change_type == "new":
            severity = Severity.HIGH

        return super()._make_event(change_type, entry, severity)


# =============================================================================
# 2. LaunchDaemonProbe
# =============================================================================


class LaunchDaemonProbe(_BaselineDiffProbe):
    """Detects new/modified LaunchDaemons on macOS.

    LaunchDaemons run as root and persist across reboots.
    Any new daemon is highly suspicious.

    MITRE: T1543.004 (Create/Modify System Process: Launch Daemon)
    """

    name = "macos_launchdaemon"
    description = "Detects new/modified LaunchDaemons on macOS"
    mitre_techniques = ["T1543.004"]
    mitre_tactics = ["persistence", "privilege_escalation"]
    scan_interval = 30.0

    _target_categories = ["launchdaemon_system", "launchdaemon_apple"]

    def _make_event(
        self, change_type: str, entry: Any, severity: Severity
    ) -> TelemetryEvent:
        # Any new daemon is CRITICAL
        if change_type == "new":
            severity = Severity.CRITICAL
        return super()._make_event(change_type, entry, severity)


# =============================================================================
# 3. LoginItemProbe
# =============================================================================


class LoginItemProbe(_BaselineDiffProbe):
    """Detects new Login Items on macOS.

    Login Items launch at user login. Monitored via BTM agent database.

    MITRE: T1547.015 (Boot/Logon Autostart: Login Items)
    """

    name = "macos_login_item"
    description = "Detects new Login Items on macOS"
    mitre_techniques = ["T1547.015"]
    mitre_tactics = ["persistence"]
    scan_interval = 60.0

    _target_categories = ["login_item"]


# =============================================================================
# 4. CronProbe
# =============================================================================


class CronProbe(_BaselineDiffProbe):
    """Detects new/modified cron jobs on macOS.

    Monitors user crontab and system cron directories.
    @reboot cron entries are a persistence vector.

    MITRE: T1053.003 (Scheduled Task/Job: Cron)
    """

    name = "macos_cron"
    description = "Detects cron job changes on macOS"
    mitre_techniques = ["T1053.003"]
    mitre_tactics = ["persistence", "execution"]
    scan_interval = 60.0

    _target_categories = ["cron"]


# =============================================================================
# 5. ShellProfileProbe
# =============================================================================


class ShellProfileProbe(_BaselineDiffProbe):
    """Detects shell profile modifications on macOS.

    Monitors .zshrc, .bashrc, .zprofile, .bash_profile, /etc/profile.
    Attackers inject malicious commands into these for persistence.

    MITRE: T1546.004 (Event Triggered Execution: Unix Shell Configuration)
    """

    name = "macos_shell_profile"
    description = "Detects shell profile modifications on macOS"
    mitre_techniques = ["T1546.004"]
    mitre_tactics = ["persistence"]
    scan_interval = 60.0

    _target_categories = ["shell_profile"]


# =============================================================================
# 6. SSHKeyProbe
# =============================================================================


class SSHKeyProbe(_BaselineDiffProbe):
    """Detects SSH authorized_keys and config changes on macOS.

    Monitors ~/.ssh/authorized_keys (key addition = backdoor) and
    ~/.ssh/config (ProxyCommand injection).

    MITRE: T1098.004 (Account Manipulation: SSH Authorized Keys)
    """

    name = "macos_ssh_key"
    description = "Detects SSH key and config changes on macOS"
    mitre_techniques = ["T1098.004"]
    mitre_tactics = ["persistence", "lateral_movement"]
    scan_interval = 60.0

    _target_categories = ["ssh"]

    def _make_event(
        self, change_type: str, entry: Any, severity: Severity
    ) -> TelemetryEvent:
        # authorized_keys changes are CRITICAL
        if "authorized_keys" in entry.name:
            severity = Severity.CRITICAL
        return super()._make_event(change_type, entry, severity)


# =============================================================================
# 7. AuthPluginProbe
# =============================================================================


class AuthPluginProbe(_BaselineDiffProbe):
    """Detects authorization plugin changes on macOS.

    Monitors /Library/Security/SecurityAgentPlugins/ — plugins can intercept
    the login process for credential harvesting or bypass.

    MITRE: T1547.002 (Boot/Logon Autostart: Authentication Package)
    """

    name = "macos_auth_plugin"
    description = "Detects authorization plugin changes on macOS"
    mitre_techniques = ["T1547.002"]
    mitre_tactics = ["persistence", "credential_access"]
    scan_interval = 300.0  # Every 5 minutes

    _target_categories = ["auth_plugin"]

    def _make_event(
        self, change_type: str, entry: Any, severity: Severity
    ) -> TelemetryEvent:
        # Any auth plugin change is CRITICAL
        severity = Severity.CRITICAL
        return super()._make_event(change_type, entry, severity)


# =============================================================================
# 8. FolderActionProbe
# =============================================================================


class FolderActionProbe(_BaselineDiffProbe):
    """Detects Folder Action additions on macOS.

    Folder Actions execute scripts when files are added to watched folders.
    Rarely used legitimately — any new entry is suspicious.

    MITRE: T1546.015 (Event Triggered Execution: Folder Actions)
    """

    name = "macos_folder_action"
    description = "Detects Folder Action additions on macOS"
    mitre_techniques = ["T1546.015"]
    mitre_tactics = ["persistence", "execution"]
    scan_interval = 300.0

    _target_categories = ["folder_action"]


# =============================================================================
# 9. SystemExtensionProbe
# =============================================================================


class SystemExtensionProbe(_BaselineDiffProbe):
    """Detects new system extensions on macOS.

    System Extensions replaced kernel extensions. New extensions require
    user approval but can provide deep system access.

    MITRE: T1547 (Boot/Logon Autostart Execution)
    """

    name = "macos_system_extension"
    description = "Detects new system extensions on macOS"
    mitre_techniques = ["T1547"]
    mitre_tactics = ["persistence"]
    scan_interval = 300.0

    _target_categories = ["system_extension"]

    def _make_event(
        self, change_type: str, entry: Any, severity: Severity
    ) -> TelemetryEvent:
        if change_type == "new":
            severity = Severity.CRITICAL
        return super()._make_event(change_type, entry, severity)


# =============================================================================
# 10. PeriodicScriptProbe
# =============================================================================


class PeriodicScriptProbe(_BaselineDiffProbe):
    """Detects periodic script changes on macOS.

    Monitors /etc/periodic/{daily,weekly,monthly} — scripts here run
    automatically via launchd periodic scheduling.

    MITRE: T1053 (Scheduled Task/Job)
    """

    name = "macos_periodic_script"
    description = "Detects periodic script changes on macOS"
    mitre_techniques = ["T1053"]
    mitre_tactics = ["persistence", "execution"]
    scan_interval = 300.0

    _target_categories = ["periodic"]


# =============================================================================
# Factory
# =============================================================================


def create_persistence_probes() -> List[MicroProbe]:
    """Create all macOS persistence probes."""
    return [
        LaunchAgentProbe(),
        LaunchDaemonProbe(),
        LoginItemProbe(),
        CronProbe(),
        ShellProfileProbe(),
        SSHKeyProbe(),
        AuthPluginProbe(),
        FolderActionProbe(),
        SystemExtensionProbe(),
        PeriodicScriptProbe(),
    ]
