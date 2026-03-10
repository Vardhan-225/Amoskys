"""macOS Persistence Collector — enumerates all persistence locations.

Scans every known macOS persistence mechanism and returns structured data.
Uses baseline-diff approach: stores previous state to detect changes.

Persistence locations scanned:
    1. LaunchAgents (user): ~/Library/LaunchAgents/
    2. LaunchAgents (system): /Library/LaunchAgents/
    3. LaunchDaemons: /Library/LaunchDaemons/
    4. Login Items: ~/Library/Application Support/com.apple.backgroundtaskmanagementagent/
    5. Cron jobs: crontab -l
    6. Shell profiles: ~/.zshrc, ~/.bashrc, ~/.zprofile, ~/.bash_profile, /etc/profile
    7. SSH keys: ~/.ssh/authorized_keys, ~/.ssh/config
    8. Auth plugins: /Library/Security/SecurityAgentPlugins/
    9. System extensions: /Library/SystemExtensions/
   10. Periodic scripts: /etc/periodic/{daily,weekly,monthly}
   11. Folder actions: ~/Library/Workflows/Applications/Folder Actions/
   12. Emond rules: /etc/emond.d/rules/
   13. At jobs: /var/at/jobs/
"""

from __future__ import annotations

import hashlib
import logging
import os
import plistlib
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class PersistenceEntry:
    """A single persistence mechanism found on the system."""

    category: str  # launchagent, launchdaemon, cron, shell_profile, etc.
    path: str  # Full path to the file
    name: str  # Filename or identifier
    content_hash: str  # SHA-256 of file content (for change detection)
    metadata: Dict[str, Any] = field(default_factory=dict)
    # Plist-specific fields (for LaunchAgent/Daemon)
    program: str = ""  # ProgramArguments[0] or Program
    label: str = ""  # Label field from plist
    run_at_load: bool = False
    keep_alive: bool = False


def _sha256(path: str) -> str:
    """SHA-256 hash of file content."""
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except (OSError, PermissionError):
        return ""


def _parse_plist(path: str) -> Dict[str, Any]:
    """Parse a macOS plist file safely."""
    try:
        with open(path, "rb") as f:
            return plistlib.load(f)
    except Exception:
        return {}


class MacOSPersistenceCollector:
    """Enumerates all macOS persistence mechanisms.

    Returns shared_data dict with keys:
        entries: List[PersistenceEntry] — all persistence entries found
        categories: Dict[str, int] — count per category
        total_count: int
        collection_time_ms: float
    """

    # All LaunchAgent/Daemon paths on macOS
    _LAUNCH_PATHS = {
        "launchagent_user": "{home}/Library/LaunchAgents",
        "launchagent_system": "/Library/LaunchAgents",
        "launchagent_apple": "/System/Library/LaunchAgents",
        "launchdaemon_system": "/Library/LaunchDaemons",
        "launchdaemon_apple": "/System/Library/LaunchDaemons",
    }

    _SHELL_PROFILES = [
        "~/.zshrc",
        "~/.zprofile",
        "~/.zshenv",
        "~/.zlogin",
        "~/.bashrc",
        "~/.bash_profile",
        "~/.profile",
        "/etc/profile",
        "/etc/zshrc",
        "/etc/bashrc",
    ]

    _SSH_FILES = [
        "~/.ssh/authorized_keys",
        "~/.ssh/authorized_keys2",
        "~/.ssh/config",
        "~/.ssh/environment",
    ]

    def __init__(self) -> None:
        self._home = str(Path.home())

    def collect(self) -> Dict[str, Any]:
        """Collect all persistence entries."""
        start = time.monotonic()
        entries: List[PersistenceEntry] = []

        entries.extend(self._collect_launch_agents_daemons())
        entries.extend(self._collect_login_items())
        entries.extend(self._collect_cron())
        entries.extend(self._collect_shell_profiles())
        entries.extend(self._collect_ssh())
        entries.extend(self._collect_auth_plugins())
        entries.extend(self._collect_system_extensions())
        entries.extend(self._collect_periodic())
        entries.extend(self._collect_folder_actions())
        entries.extend(self._collect_emond())

        elapsed_ms = (time.monotonic() - start) * 1000

        # Category counts
        categories: Dict[str, int] = {}
        for e in entries:
            categories[e.category] = categories.get(e.category, 0) + 1

        return {
            "entries": entries,
            "categories": categories,
            "total_count": len(entries),
            "collection_time_ms": round(elapsed_ms, 2),
        }

    def _collect_launch_agents_daemons(self) -> List[PersistenceEntry]:
        """Scan all LaunchAgent and LaunchDaemon directories."""
        entries = []
        for category, path_template in self._LAUNCH_PATHS.items():
            dir_path = path_template.replace("{home}", self._home)
            if not os.path.isdir(dir_path):
                continue

            try:
                for fname in os.listdir(dir_path):
                    if not fname.endswith(".plist"):
                        continue
                    full_path = os.path.join(dir_path, fname)
                    plist = _parse_plist(full_path)
                    content_hash = _sha256(full_path)

                    # Extract key plist fields
                    program_args = plist.get("ProgramArguments", [])
                    program = plist.get("Program", "")
                    if not program and program_args:
                        program = program_args[0] if program_args else ""

                    entries.append(
                        PersistenceEntry(
                            category=category,
                            path=full_path,
                            name=fname,
                            content_hash=content_hash,
                            program=program,
                            label=plist.get("Label", ""),
                            run_at_load=plist.get("RunAtLoad", False),
                            keep_alive=bool(plist.get("KeepAlive", False)),
                            metadata={
                                "program_arguments": program_args,
                                "watch_paths": plist.get("WatchPaths", []),
                                "start_interval": plist.get("StartInterval", 0),
                                "start_calendar_interval": plist.get(
                                    "StartCalendarInterval"
                                ),
                            },
                        )
                    )
            except PermissionError:
                logger.debug("Permission denied: %s", dir_path)

        return entries

    def _collect_login_items(self) -> List[PersistenceEntry]:
        """Scan Login Items (BTM agent)."""
        entries = []
        btm_dir = os.path.join(
            self._home,
            "Library/Application Support/com.apple.backgroundtaskmanagementagent",
        )
        if os.path.isdir(btm_dir):
            for fname in os.listdir(btm_dir):
                full_path = os.path.join(btm_dir, fname)
                entries.append(
                    PersistenceEntry(
                        category="login_item",
                        path=full_path,
                        name=fname,
                        content_hash=_sha256(full_path),
                    )
                )

        # Also check loginitems.plist
        loginitems = os.path.join(
            self._home,
            "Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm",
        )
        if os.path.exists(loginitems):
            entries.append(
                PersistenceEntry(
                    category="login_item",
                    path=loginitems,
                    name="backgrounditems.btm",
                    content_hash=_sha256(loginitems),
                )
            )

        return entries

    def _collect_cron(self) -> List[PersistenceEntry]:
        """Collect crontab entries."""
        entries = []
        try:
            result = subprocess.run(
                ["crontab", "-l"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                content = result.stdout.strip()
                entries.append(
                    PersistenceEntry(
                        category="cron",
                        path="crontab",
                        name="user_crontab",
                        content_hash=hashlib.sha256(content.encode()).hexdigest(),
                        metadata={"lines": content.split("\n")},
                    )
                )
        except Exception:
            pass

        # System cron directories
        for cron_dir in ["/etc/cron.d", "/var/at/tabs"]:
            if os.path.isdir(cron_dir):
                try:
                    for fname in os.listdir(cron_dir):
                        full_path = os.path.join(cron_dir, fname)
                        if os.path.isfile(full_path):
                            entries.append(
                                PersistenceEntry(
                                    category="cron",
                                    path=full_path,
                                    name=fname,
                                    content_hash=_sha256(full_path),
                                )
                            )
                except PermissionError:
                    pass

        return entries

    def _collect_shell_profiles(self) -> List[PersistenceEntry]:
        """Monitor shell profile files."""
        entries = []
        for profile in self._SHELL_PROFILES:
            path = os.path.expanduser(profile)
            if os.path.exists(path):
                entries.append(
                    PersistenceEntry(
                        category="shell_profile",
                        path=path,
                        name=os.path.basename(path),
                        content_hash=_sha256(path),
                    )
                )
        return entries

    def _collect_ssh(self) -> List[PersistenceEntry]:
        """Monitor SSH configuration and authorized keys."""
        entries = []
        for ssh_file in self._SSH_FILES:
            path = os.path.expanduser(ssh_file)
            if os.path.exists(path):
                entries.append(
                    PersistenceEntry(
                        category="ssh",
                        path=path,
                        name=os.path.basename(path),
                        content_hash=_sha256(path),
                    )
                )
        return entries

    def _collect_auth_plugins(self) -> List[PersistenceEntry]:
        """Scan authorization plugins."""
        entries = []
        plugin_dir = "/Library/Security/SecurityAgentPlugins"
        if os.path.isdir(plugin_dir):
            try:
                for fname in os.listdir(plugin_dir):
                    full_path = os.path.join(plugin_dir, fname)
                    entries.append(
                        PersistenceEntry(
                            category="auth_plugin",
                            path=full_path,
                            name=fname,
                            content_hash=(
                                _sha256(full_path) if os.path.isfile(full_path) else ""
                            ),
                        )
                    )
            except PermissionError:
                pass
        return entries

    def _collect_system_extensions(self) -> List[PersistenceEntry]:
        """Scan system extensions."""
        entries = []
        ext_dir = "/Library/SystemExtensions"
        if os.path.isdir(ext_dir):
            try:
                for root, dirs, files in os.walk(ext_dir):
                    for fname in files:
                        full_path = os.path.join(root, fname)
                        entries.append(
                            PersistenceEntry(
                                category="system_extension",
                                path=full_path,
                                name=fname,
                                content_hash=_sha256(full_path),
                            )
                        )
            except PermissionError:
                pass
        return entries

    def _collect_periodic(self) -> List[PersistenceEntry]:
        """Scan periodic scripts (daily/weekly/monthly)."""
        entries = []
        for period in ["daily", "weekly", "monthly"]:
            dir_path = f"/etc/periodic/{period}"
            if os.path.isdir(dir_path):
                try:
                    for fname in os.listdir(dir_path):
                        full_path = os.path.join(dir_path, fname)
                        if os.path.isfile(full_path):
                            entries.append(
                                PersistenceEntry(
                                    category="periodic",
                                    path=full_path,
                                    name=f"{period}/{fname}",
                                    content_hash=_sha256(full_path),
                                )
                            )
                except PermissionError:
                    pass
        return entries

    def _collect_folder_actions(self) -> List[PersistenceEntry]:
        """Scan Folder Actions."""
        entries = []
        fa_dir = os.path.join(
            self._home, "Library/Workflows/Applications/Folder Actions"
        )
        if os.path.isdir(fa_dir):
            try:
                for fname in os.listdir(fa_dir):
                    full_path = os.path.join(fa_dir, fname)
                    entries.append(
                        PersistenceEntry(
                            category="folder_action",
                            path=full_path,
                            name=fname,
                            content_hash=(
                                _sha256(full_path) if os.path.isfile(full_path) else ""
                            ),
                        )
                    )
            except PermissionError:
                pass
        return entries

    def _collect_emond(self) -> List[PersistenceEntry]:
        """Scan emond rules."""
        entries = []
        emond_dir = "/etc/emond.d/rules"
        if os.path.isdir(emond_dir):
            try:
                for fname in os.listdir(emond_dir):
                    full_path = os.path.join(emond_dir, fname)
                    if os.path.isfile(full_path):
                        entries.append(
                            PersistenceEntry(
                                category="emond",
                                path=full_path,
                                name=fname,
                                content_hash=_sha256(full_path),
                            )
                        )
            except PermissionError:
                pass
        return entries
