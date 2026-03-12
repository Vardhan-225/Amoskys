"""macOS Quarantine Guard Collector — download provenance and xattr tracking.

Collects data from five macOS-specific sources to build a comprehensive
picture of download activity, quarantine state, and potential bypass attempts:

    1. QuarantineEventsV2 SQLite database — browser download provenance
    2. ~/Downloads/ xattr scan — quarantine attribute presence/absence
    3. hdiutil info — mounted DMG images
    4. Terminal process tree — child processes of terminal emulators
    5. Process snapshot — xattr removal, installer abuse, codesign checks

The collector returns a structured dict that probes consume via shared_data.
It never makes detection decisions — that is the probes' job.

Ground truth (macOS 26.0, uid=501, Apple Silicon):
    - QuarantineEventsV2 is owner-readable SQLite (~3ms query)
    - xattr scan covers ~/Downloads with timeout protection
    - hdiutil info returns in <50ms typically
    - Terminal child walk via psutil recursive children
    - Core Data timestamps: seconds since 2001-01-01 00:00:00 UTC
      Conversion: unix_ts = core_data_ts + 978307200
"""

from __future__ import annotations

import logging
import os
import sqlite3
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logger.error("psutil not installed — quarantine guard collector cannot function")

# Core Data epoch offset: seconds between 1970-01-01 and 2001-01-01
_CORE_DATA_EPOCH_OFFSET = 978307200

# Terminal emulator process names
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

# Messaging app process names for ClickFix detection
_MESSAGING_APPS = frozenset(
    {
        "Messages",
        "Slack",
        "Microsoft Teams",
        "Teams",
        "Discord",
        "WhatsApp",
        "Telegram",
        "Signal",
        "Zoom",
    }
)

# Suspicious commands that indicate ClickFix or paste-and-run attacks
_SUSPICIOUS_TERMINAL_COMMANDS = frozenset(
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
        "openssl",
    }
)


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class QuarantineEntry:
    """A single entry from the macOS quarantine events database."""

    timestamp: float  # Unix timestamp (converted from Core Data)
    agent_bundle_id: str  # e.g. "com.apple.Safari", "com.google.Chrome"
    data_url: str  # download URL
    origin_url: str  # referrer URL
    sender_name: str  # sender (for AirDrop, Messages, etc.)
    type_number: int  # quarantine type identifier


@dataclass
class DownloadedFile:
    """A file in ~/Downloads/ with quarantine xattr status."""

    path: str
    filename: str
    has_quarantine_xattr: bool
    quarantine_value: str  # raw xattr value, empty if no xattr
    modify_time: float
    size: int


@dataclass
class MountedDMG:
    """A currently mounted DMG image."""

    image_path: str
    mount_point: str


@dataclass
class TerminalChild:
    """A child process of a terminal emulator."""

    pid: int
    name: str
    cmdline: List[str]
    ppid: int
    terminal_pid: int
    create_time: float


# =============================================================================
# Collector
# =============================================================================


class MacOSQuarantineGuardCollector:
    """Collects quarantine provenance, download state, and process context.

    Returns shared_data dict with keys:
        quarantine_entries: List[QuarantineEntry]
        downloaded_files: List[DownloadedFile]
        mounted_dmgs: List[MountedDMG]
        terminal_children: List[TerminalChild]
        messaging_apps_running: List[str]
        xattr_removal_processes: List[Dict]
        installer_processes: List[Dict]
        process_snapshot: List[Dict]
        collection_time_ms: float
    """

    def __init__(
        self,
        device_id: str = "",
        window_seconds: float = 300.0,
    ) -> None:
        self.device_id = device_id or _get_hostname()
        self.window_seconds = window_seconds
        self._home = Path.home()
        self._downloads_dir = self._home / "Downloads"
        self._quarantine_db = (
            self._home
            / "Library"
            / "Preferences"
            / "com.apple.LaunchServices.QuarantineEventsV2"
        )
        # Stateful xattr tracking for diff-based quarantine removal detection
        self._previous_xattr_state: Dict[str, bool] = {}  # path -> had_quarantine_xattr

    def collect(self) -> Dict[str, Any]:
        """Collect all quarantine-related data sources.

        Returns dict for ProbeContext.shared_data.
        """
        start = time.monotonic()

        quarantine_entries = self._collect_quarantine_db()
        downloaded_files = self._collect_downloads_xattr()
        mounted_dmgs = self._collect_mounted_dmgs()
        terminal_children = self._collect_terminal_children()
        messaging_apps = self._collect_messaging_apps()
        xattr_procs = self._collect_xattr_removal_processes()
        installer_procs = self._collect_installer_processes()
        process_snapshot = self._collect_process_snapshot()

        # Stateful diff: detect files that lost quarantine xattr between scans
        xattr_removals = self._compute_xattr_removals(downloaded_files)

        elapsed_ms = (time.monotonic() - start) * 1000

        return {
            "quarantine_entries": quarantine_entries,
            "downloaded_files": downloaded_files,
            "mounted_dmgs": mounted_dmgs,
            "terminal_children": terminal_children,
            "messaging_apps_running": messaging_apps,
            "xattr_removal_processes": xattr_procs,
            "xattr_removals": xattr_removals,
            "installer_processes": installer_procs,
            "process_snapshot": process_snapshot,
            "collection_time_ms": round(elapsed_ms, 2),
        }

    # -------------------------------------------------------------------------
    # 1. Quarantine database
    # -------------------------------------------------------------------------

    def _collect_quarantine_db(self) -> List[QuarantineEntry]:
        """Read recent entries from QuarantineEventsV2 SQLite database."""
        if not self._quarantine_db.exists():
            logger.debug("Quarantine DB not found: %s", self._quarantine_db)
            return []

        entries: List[QuarantineEntry] = []
        # Calculate Core Data timestamp threshold
        now_unix = time.time()
        threshold_unix = now_unix - self.window_seconds
        threshold_coredata = threshold_unix - _CORE_DATA_EPOCH_OFFSET

        try:
            # Open read-only to avoid locking issues
            db_uri = f"file:{self._quarantine_db}?mode=ro"
            conn = sqlite3.connect(db_uri, uri=True, timeout=3)
            conn.row_factory = sqlite3.Row
            try:
                cursor = conn.execute(
                    "SELECT LSQuarantineTimeStamp, "
                    "       LSQuarantineAgentBundleIdentifier, "
                    "       LSQuarantineDataURLString, "
                    "       LSQuarantineOriginURLString, "
                    "       LSQuarantineSenderName, "
                    "       LSQuarantineTypeNumber "
                    "FROM LSQuarantineEvent "
                    "WHERE LSQuarantineTimeStamp > ? "
                    "ORDER BY LSQuarantineTimeStamp DESC "
                    "LIMIT 100",
                    (threshold_coredata,),
                )
                for row in cursor:
                    coredata_ts = row["LSQuarantineTimeStamp"] or 0.0
                    unix_ts = coredata_ts + _CORE_DATA_EPOCH_OFFSET

                    entries.append(
                        QuarantineEntry(
                            timestamp=unix_ts,
                            agent_bundle_id=row["LSQuarantineAgentBundleIdentifier"]
                            or "",
                            data_url=row["LSQuarantineDataURLString"] or "",
                            origin_url=row["LSQuarantineOriginURLString"] or "",
                            sender_name=row["LSQuarantineSenderName"] or "",
                            type_number=row["LSQuarantineTypeNumber"] or 0,
                        )
                    )
            finally:
                conn.close()
        except sqlite3.OperationalError as e:
            logger.warning("Failed to read quarantine DB: %s", e)
        except Exception as e:
            logger.error("Quarantine DB error: %s", e)

        return entries

    # -------------------------------------------------------------------------
    # 2. Download directory xattr scan
    # -------------------------------------------------------------------------

    def _collect_downloads_xattr(self) -> List[DownloadedFile]:
        """Scan ~/Downloads/ for files with quarantine xattr status."""
        if not self._downloads_dir.exists():
            logger.debug("Downloads directory not found: %s", self._downloads_dir)
            return []

        files: List[DownloadedFile] = []
        now = time.time()
        cutoff = now - self.window_seconds

        try:
            for entry_name in os.listdir(self._downloads_dir):
                filepath = self._downloads_dir / entry_name
                if not filepath.is_file():
                    continue

                try:
                    stat = filepath.stat()
                except OSError:
                    continue

                # Only scan files modified within the collection window
                if stat.st_mtime < cutoff:
                    continue

                # Check quarantine xattr
                has_xattr = False
                xattr_value = ""
                try:
                    result = subprocess.run(
                        ["xattr", "-p", "com.apple.quarantine", str(filepath)],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    if result.returncode == 0:
                        has_xattr = True
                        xattr_value = result.stdout.strip()
                except subprocess.TimeoutExpired:
                    logger.warning("xattr timeout for %s", filepath)
                except Exception as e:
                    logger.debug("xattr check failed for %s: %s", filepath, e)

                files.append(
                    DownloadedFile(
                        path=str(filepath),
                        filename=entry_name,
                        has_quarantine_xattr=has_xattr,
                        quarantine_value=xattr_value,
                        modify_time=stat.st_mtime,
                        size=stat.st_size,
                    )
                )
        except PermissionError:
            logger.warning("Permission denied scanning ~/Downloads/")
        except Exception as e:
            logger.error("Downloads scan error: %s", e)

        return files

    # -------------------------------------------------------------------------
    # 2b. Stateful xattr diff — detect quarantine removal between scans
    # -------------------------------------------------------------------------

    def _compute_xattr_removals(
        self, downloaded_files: List[DownloadedFile]
    ) -> List[Dict[str, Any]]:
        """Detect files that lost quarantine xattr since the previous scan.

        Compares the current xattr state of ~/Downloads files against the
        previous scan's state. If a file previously had com.apple.quarantine
        and now does not, someone removed it — the smoking gun of Gatekeeper
        bypass, even if the xattr process exited in <5ms.
        """
        removals: List[Dict[str, Any]] = []
        current_state: Dict[str, bool] = {}

        for f in downloaded_files:
            current_state[f.path] = f.has_quarantine_xattr

            # File previously had xattr, now it doesn't → removal detected
            if (
                f.path in self._previous_xattr_state
                and self._previous_xattr_state[f.path]
                and not f.has_quarantine_xattr
            ):
                removals.append(
                    {
                        "path": f.path,
                        "filename": f.filename,
                        "modify_time": f.modify_time,
                        "size": f.size,
                    }
                )

        self._previous_xattr_state = current_state
        return removals

    # -------------------------------------------------------------------------
    # 3. Mounted DMGs
    # -------------------------------------------------------------------------

    def _collect_mounted_dmgs(self) -> List[MountedDMG]:
        """Parse hdiutil info output for mounted DMG images."""
        dmgs: List[MountedDMG] = []

        try:
            result = subprocess.run(
                ["hdiutil", "info"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return dmgs

            current_image: Optional[str] = None
            for line in result.stdout.splitlines():
                stripped = line.strip()

                if stripped.startswith("="):
                    # Separator line — reset for next image block
                    current_image = None
                    continue

                if stripped.startswith("image-path"):
                    # Extract image path after colon
                    parts = stripped.split(":", 1)
                    if len(parts) == 2:
                        current_image = parts[1].strip()

                elif "/dev/" not in stripped and stripped.startswith("/"):
                    # This is a mount point line
                    if current_image:
                        dmgs.append(
                            MountedDMG(
                                image_path=current_image,
                                mount_point=stripped,
                            )
                        )

        except subprocess.TimeoutExpired:
            logger.warning("hdiutil info timed out")
        except FileNotFoundError:
            logger.debug("hdiutil not found")
        except Exception as e:
            logger.error("hdiutil info error: %s", e)

        return dmgs

    # -------------------------------------------------------------------------
    # 4. Terminal process tree (ClickFix detection)
    # -------------------------------------------------------------------------

    def _collect_terminal_children(self) -> List[TerminalChild]:
        """Walk children of terminal emulators looking for suspicious commands."""
        if not PSUTIL_AVAILABLE:
            return []

        children: List[TerminalChild] = []

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                info = proc.info
                if info["name"] not in _TERMINAL_EMULATORS:
                    continue

                terminal_pid = info["pid"]

                # Recursively walk children of this terminal
                try:
                    for child in psutil.Process(terminal_pid).children(recursive=True):
                        try:
                            child_name = child.name()
                            child_cmdline = child.cmdline()

                            # Check if this child or its cmdline is suspicious
                            is_suspicious = child_name in _SUSPICIOUS_TERMINAL_COMMANDS
                            if not is_suspicious and child_cmdline:
                                # Check for bash -c, sh -c, python3 -c patterns
                                cmdline_str = " ".join(child_cmdline)
                                for cmd in _SUSPICIOUS_TERMINAL_COMMANDS:
                                    if cmd in cmdline_str:
                                        is_suspicious = True
                                        break

                            if is_suspicious:
                                children.append(
                                    TerminalChild(
                                        pid=child.pid,
                                        name=child_name,
                                        cmdline=child_cmdline,
                                        ppid=child.ppid(),
                                        terminal_pid=terminal_pid,
                                        create_time=child.create_time(),
                                    )
                                )
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return children

    # -------------------------------------------------------------------------
    # 5a. Messaging apps running (for ClickFix correlation)
    # -------------------------------------------------------------------------

    def _collect_messaging_apps(self) -> List[str]:
        """Check which messaging apps are currently running."""
        if not PSUTIL_AVAILABLE:
            return []

        running: List[str] = []
        seen: set = set()

        for proc in psutil.process_iter(["name"]):
            try:
                name = proc.info["name"]
                if name in _MESSAGING_APPS and name not in seen:
                    running.append(name)
                    seen.add(name)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return running

    # -------------------------------------------------------------------------
    # 5b. xattr removal processes
    # -------------------------------------------------------------------------

    def _collect_xattr_removal_processes(self) -> List[Dict[str, Any]]:
        """Find running xattr processes that remove quarantine attributes."""
        if not PSUTIL_AVAILABLE:
            return []

        procs: List[Dict[str, Any]] = []

        for proc in psutil.process_iter(
            ["pid", "name", "cmdline", "ppid", "create_time"]
        ):
            try:
                info = proc.info
                if info["name"] != "xattr":
                    continue

                cmdline = info.get("cmdline") or []
                cmdline_str = " ".join(cmdline)

                # Check for quarantine removal patterns:
                #   xattr -d com.apple.quarantine <file>
                #   xattr -c <file>  (clears all xattrs)
                is_removal = (
                    "-d" in cmdline and "com.apple.quarantine" in cmdline_str
                ) or ("-c" in cmdline)

                if is_removal:
                    procs.append(
                        {
                            "pid": info["pid"],
                            "name": info["name"],
                            "cmdline": cmdline,
                            "ppid": info.get("ppid", 0),
                            "create_time": info.get("create_time", 0),
                            "target_file": self._extract_xattr_target(cmdline),
                        }
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return procs

    @staticmethod
    def _extract_xattr_target(cmdline: List[str]) -> str:
        """Extract target file path from xattr command line.

        Handles:
            xattr -d com.apple.quarantine /path/to/file
            xattr -c /path/to/file
        """
        if not cmdline:
            return ""

        # The target file is typically the last argument
        # Skip the xattr binary name and flags
        for i, arg in enumerate(cmdline):
            if arg.startswith("/") or arg.startswith("~") or arg.startswith("."):
                # Skip if this is the xattr binary path itself
                if i == 0:
                    continue
                # Skip "com.apple.quarantine" — not a file path
                if "com.apple." in arg:
                    continue
                return arg

        # Fallback: return last argument if it looks like a path
        if len(cmdline) > 1 and not cmdline[-1].startswith("-"):
            last = cmdline[-1]
            if last != "com.apple.quarantine":
                return last

        return ""

    # -------------------------------------------------------------------------
    # 5c. Installer processes
    # -------------------------------------------------------------------------

    def _collect_installer_processes(self) -> List[Dict[str, Any]]:
        """Find running installer/pkgutil processes and their children."""
        if not PSUTIL_AVAILABLE:
            return []

        procs: List[Dict[str, Any]] = []
        _INSTALLER_NAMES = frozenset({"installer", "pkgutil", "Installer"})

        for proc in psutil.process_iter(
            ["pid", "name", "cmdline", "ppid", "create_time"]
        ):
            try:
                info = proc.info
                if info["name"] not in _INSTALLER_NAMES:
                    continue

                # Collect the installer process itself
                entry: Dict[str, Any] = {
                    "pid": info["pid"],
                    "name": info["name"],
                    "cmdline": info.get("cmdline") or [],
                    "ppid": info.get("ppid", 0),
                    "create_time": info.get("create_time", 0),
                    "children": [],
                }

                # Walk children looking for suspicious spawns
                try:
                    for child in psutil.Process(info["pid"]).children(recursive=True):
                        try:
                            entry["children"].append(
                                {
                                    "pid": child.pid,
                                    "name": child.name(),
                                    "cmdline": child.cmdline(),
                                }
                            )
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

                procs.append(entry)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return procs

    # -------------------------------------------------------------------------
    # 5d. Process snapshot (minimal, for cross-referencing)
    # -------------------------------------------------------------------------

    def _collect_process_snapshot(self) -> List[Dict[str, Any]]:
        """Collect a minimal process snapshot for cross-referencing.

        Used by probes to check if processes are running from DMG mounts,
        ~/Downloads, /tmp, etc. Keeps only fields needed for detection.
        """
        if not PSUTIL_AVAILABLE:
            return []

        snapshot: List[Dict[str, Any]] = []

        for proc in psutil.process_iter(
            ["pid", "name", "exe", "cmdline", "ppid", "username", "create_time"]
        ):
            try:
                info = proc.info
                snapshot.append(
                    {
                        "pid": info["pid"],
                        "name": info.get("name") or "",
                        "exe": info.get("exe") or "",
                        "cmdline": info.get("cmdline") or [],
                        "ppid": info.get("ppid", 0),
                        "username": info.get("username") or "",
                        "create_time": info.get("create_time", 0),
                    }
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return snapshot


# =============================================================================
# Helpers
# =============================================================================


def _get_hostname() -> str:
    """Get hostname for device_id."""
    import socket

    return socket.gethostname()
