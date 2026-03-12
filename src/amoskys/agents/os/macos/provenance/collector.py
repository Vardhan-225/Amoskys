"""macOS Provenance Collector — Stateful cross-application event tracking.

Collects process, download, network, and active-app data with full awareness
of macOS permission boundaries.  The collector is STATEFUL: it maintains
process and download baselines across scans so it can report *new* events
(delta-based detection).

First scan establishes the baseline and returns empty deltas.  Subsequent
scans return only the diff — new processes spawned, new files downloaded,
and currently active applications.

Data sources:
    1. psutil process enumeration (pid, name, exe, cmdline, ppid, create_time)
    2. ~/Downloads directory listing + os.stat() per file
    3. lsof -i -n -P -sTCP:ESTABLISHED for per-PID network connections
    4. Active app detection derived from current process list

Ground truth (macOS 26.0, uid=501, Apple Silicon):
    - Process enumeration: ~5ms for 650 processes
    - Downloads scan: <1ms for typical ~/Downloads
    - lsof parse: ~50ms for established TCP connections
    - Total collection: <60ms per cycle
"""

from __future__ import annotations

import ipaddress
import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

logger = logging.getLogger(__name__)

try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logger.error("psutil not installed — provenance collector cannot function")


# =============================================================================
# Dataclasses
# =============================================================================


@dataclass
class TimelineEvent:
    """A single event in the provenance timeline."""

    timestamp: float  # epoch seconds
    event_type: str  # "process_spawned", "file_created", "app_active", "network_connect"
    pid: int
    app_name: str
    detail: str  # file path, command, IP:port, etc.


@dataclass
class NewProcess:
    """A process that appeared since the last scan."""

    pid: int
    name: str
    exe: str
    cmdline: List[str]
    ppid: int
    parent_name: str
    create_time: float


@dataclass
class NewDownload:
    """A file that appeared in ~/Downloads since the last scan."""

    filename: str
    path: str
    size: int
    create_time: float
    modify_time: float


@dataclass
class PIDConnection:
    """An established TCP connection associated with a PID."""

    pid: int
    process_name: str
    remote_ip: str
    remote_port: int
    state: str


# =============================================================================
# Known application categories
# =============================================================================

_MESSAGING_APPS: FrozenSet[str] = frozenset({
    "Messages", "Slack", "Slack Helper", "Microsoft Teams",
    "Discord", "Discord Helper", "WhatsApp", "Telegram",
    "Signal", "Element", "Mattermost",
})

_BROWSERS: FrozenSet[str] = frozenset({
    "Safari", "Google Chrome", "Google Chrome Helper",
    "Firefox", "Brave Browser", "Microsoft Edge", "Arc",
})

_TERMINALS: FrozenSet[str] = frozenset({
    "Terminal", "iTerm2", "Warp", "Alacritty", "kitty",
    "Hyper", "WezTerm",
})

_SUSPICIOUS_COMMANDS: FrozenSet[str] = frozenset({
    "curl", "wget", "nc", "ncat", "bash", "sh", "zsh",
    "python3", "python", "osascript", "base64",
})


# =============================================================================
# Collector
# =============================================================================


class MacOSProvenanceCollector:
    """Stateful cross-application provenance collector.

    Tracks process and download baselines across scans.  The first scan
    populates the baseline and returns empty deltas.  Subsequent scans
    report only new processes and new downloads.

    Returns shared_data dict with keys:
        timeline: List[TimelineEvent]          — chronological event stream
        new_processes: List[NewProcess]         — processes spawned since last scan
        new_downloads: List[NewDownload]        — files created in ~/Downloads
        pid_connections: Dict[int, List[PIDConnection]] — per-PID network map
        active_messaging_apps: List[str]        — currently running messaging apps
        active_browsers: List[str]              — currently running browsers
        active_terminals: List[str]             — currently running terminals
        is_baseline_scan: bool                  — True on first run
        collection_time_ms: float               — total collection time
    """

    def __init__(self) -> None:
        self._known_pids: Dict[int, float] = {}  # pid -> create_time
        self._known_downloads: Dict[str, float] = {}  # filename -> mtime
        self._first_run = True
        self._downloads_dir = os.path.expanduser("~/Downloads")

    def collect(self) -> Dict[str, Any]:
        """Collect provenance snapshot with delta detection.

        Returns dict for ProbeContext.shared_data.
        """
        if not PSUTIL_AVAILABLE:
            return self._empty_result()

        start = time.monotonic()
        is_baseline = self._first_run

        # Step 1: Enumerate all processes
        current_procs = self._enumerate_processes()

        # Step 2: Diff processes against baseline
        new_processes = self._diff_processes(current_procs)

        # Step 3: Diff downloads against baseline
        new_downloads = self._diff_downloads()

        # Step 4: Detect active apps by category
        active_messaging = self._find_active_apps(current_procs, _MESSAGING_APPS)
        active_browsers = self._find_active_apps(current_procs, _BROWSERS)
        active_terminals = self._find_active_apps(current_procs, _TERMINALS)

        # Step 5: Collect network connections
        pid_connections = self._collect_network_connections()

        # Step 6: Build chronological timeline
        timeline = self._build_timeline(
            new_processes,
            new_downloads,
            active_messaging,
            active_browsers,
            active_terminals,
        )

        # Mark first run complete
        if self._first_run:
            self._first_run = False

        elapsed_ms = (time.monotonic() - start) * 1000

        return {
            "timeline": timeline,
            "new_processes": new_processes,
            "new_downloads": new_downloads,
            "pid_connections": pid_connections,
            "active_messaging_apps": active_messaging,
            "active_browsers": active_browsers,
            "active_terminals": active_terminals,
            "is_baseline_scan": is_baseline,
            "collection_time_ms": round(elapsed_ms, 2),
        }

    # ── Process enumeration & diffing ────────────────────────────────────

    def _enumerate_processes(self) -> Dict[int, Dict[str, Any]]:
        """Enumerate all processes via psutil.

        Returns dict of pid -> process info dict.
        """
        procs: Dict[int, Dict[str, Any]] = {}

        for proc in psutil.process_iter([
            "pid", "name", "exe", "cmdline", "ppid", "create_time",
        ]):
            try:
                info = proc.info
                pid = info["pid"]
                ppid = info.get("ppid", 0) or 0

                # Parent name — best effort
                parent_name = ""
                if ppid:
                    try:
                        parent_name = psutil.Process(ppid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                procs[pid] = {
                    "pid": pid,
                    "name": info.get("name") or "",
                    "exe": info.get("exe") or "",
                    "cmdline": info.get("cmdline") or [],
                    "ppid": ppid,
                    "parent_name": parent_name,
                    "create_time": info.get("create_time", 0) or 0,
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return procs

    def _diff_processes(
        self, current_procs: Dict[int, Dict[str, Any]]
    ) -> List[NewProcess]:
        """Find processes that are new since the last scan.

        First run populates baseline and returns empty list.
        Subsequent runs detect new PIDs and recycled PIDs (same PID,
        different create_time).
        """
        new_processes: List[NewProcess] = []
        current_pids: Dict[int, float] = {}

        for pid, info in current_procs.items():
            ct = info["create_time"]
            current_pids[pid] = ct

            if not self._first_run:
                # New PID, or same PID but different create_time (recycled)
                if pid not in self._known_pids or self._known_pids[pid] != ct:
                    new_processes.append(NewProcess(
                        pid=pid,
                        name=info["name"],
                        exe=info["exe"],
                        cmdline=info["cmdline"],
                        ppid=info["ppid"],
                        parent_name=info["parent_name"],
                        create_time=ct,
                    ))

        self._known_pids = current_pids
        return new_processes

    # ── Downloads diffing ────────────────────────────────────────────────

    def _diff_downloads(self) -> List[NewDownload]:
        """Find new files in ~/Downloads since last scan.

        First run populates baseline and returns empty list.
        """
        new_downloads: List[NewDownload] = []
        current_downloads: Dict[str, float] = {}

        if not os.path.isdir(self._downloads_dir):
            return new_downloads

        try:
            entries = os.listdir(self._downloads_dir)
        except OSError as e:
            logger.warning("Cannot list ~/Downloads: %s", e)
            return new_downloads

        for filename in entries:
            # Skip hidden files and partial downloads
            if filename.startswith(".") or filename.endswith(".crdownload"):
                continue

            filepath = os.path.join(self._downloads_dir, filename)

            try:
                st = os.stat(filepath)
            except OSError:
                continue

            mtime = st.st_mtime
            current_downloads[filename] = mtime

            if not self._first_run:
                # New file, or existing file with changed mtime
                if filename not in self._known_downloads or self._known_downloads[filename] != mtime:
                    new_downloads.append(NewDownload(
                        filename=filename,
                        path=filepath,
                        size=st.st_size,
                        create_time=st.st_birthtime if hasattr(st, "st_birthtime") else st.st_ctime,
                        modify_time=mtime,
                    ))

        self._known_downloads = current_downloads
        return new_downloads

    # ── Active app detection ─────────────────────────────────────────────

    @staticmethod
    def _find_active_apps(
        current_procs: Dict[int, Dict[str, Any]],
        app_set: FrozenSet[str],
    ) -> List[str]:
        """Find which apps from a category are currently running."""
        active: List[str] = []
        seen: set = set()

        for info in current_procs.values():
            name = info["name"]
            if name in app_set and name not in seen:
                active.append(name)
                seen.add(name)

        return sorted(active)

    # ── Network connections ──────────────────────────────────────────────

    def _collect_network_connections(self) -> Dict[int, List[PIDConnection]]:
        """Collect per-PID network connections via lsof.

        Parses `lsof -i -n -P -sTCP:ESTABLISHED` to find established TCP
        connections.  Only includes connections with non-private remote IPs.
        """
        pid_connections: Dict[int, List[PIDConnection]] = {}

        try:
            result = subprocess.run(
                ["lsof", "-i", "-n", "-P", "-sTCP:ESTABLISHED"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            logger.debug("lsof failed: %s", e)
            return pid_connections

        if result.returncode != 0:
            return pid_connections

        for line in result.stdout.splitlines()[1:]:  # Skip header
            parsed = self._parse_lsof_line(line)
            if parsed is None:
                continue

            conn = parsed
            # Filter to non-private remote IPs only
            try:
                if ipaddress.ip_address(conn.remote_ip).is_private:
                    continue
            except ValueError:
                continue

            if conn.pid not in pid_connections:
                pid_connections[conn.pid] = []
            pid_connections[conn.pid].append(conn)

        return pid_connections

    @staticmethod
    def _parse_lsof_line(line: str) -> Optional[PIDConnection]:
        """Parse a single lsof output line into a PIDConnection.

        lsof format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
        NAME for TCP: local_ip:port->remote_ip:port (STATE)
        """
        parts = line.split()
        if len(parts) < 9:
            return None

        try:
            process_name = parts[0]
            pid = int(parts[1])
            # NAME field starts at index 8; state "(ESTABLISHED)" may follow
            name_field = " ".join(parts[8:])

            if "->" not in name_field:
                return None

            # Extract the address portion (before any state info)
            addr_part = name_field.split()[0]
            _, remote = addr_part.split("->", 1)
            # Handle IPv6: [::1]:port
            if remote.startswith("["):
                bracket_end = remote.index("]")
                remote_ip = remote[1:bracket_end]
                remote_port = int(remote[bracket_end + 2:])
            else:
                ip_port = remote.rsplit(":", 1)
                if len(ip_port) != 2:
                    return None
                remote_ip = ip_port[0]
                remote_port = int(ip_port[1])

            return PIDConnection(
                pid=pid,
                process_name=process_name,
                remote_ip=remote_ip,
                remote_port=remote_port,
                state="ESTABLISHED",
            )
        except (ValueError, IndexError):
            return None

    # ── Timeline construction ────────────────────────────────────────────

    @staticmethod
    def _build_timeline(
        new_processes: List[NewProcess],
        new_downloads: List[NewDownload],
        active_messaging: List[str],
        active_browsers: List[str],
        active_terminals: List[str],
    ) -> List[TimelineEvent]:
        """Build chronological timeline from all event sources."""
        now = time.time()
        timeline: List[TimelineEvent] = []

        # New process spawns
        for proc in new_processes:
            timeline.append(TimelineEvent(
                timestamp=proc.create_time,
                event_type="process_spawned",
                pid=proc.pid,
                app_name=proc.name,
                detail=f"exe={proc.exe} ppid={proc.ppid} parent={proc.parent_name}",
            ))

        # New downloads
        for dl in new_downloads:
            timeline.append(TimelineEvent(
                timestamp=dl.modify_time,
                event_type="file_created",
                pid=0,
                app_name="Downloads",
                detail=f"file={dl.filename} size={dl.size} path={dl.path}",
            ))

        # Active messaging apps
        for app in active_messaging:
            timeline.append(TimelineEvent(
                timestamp=now,
                event_type="app_active",
                pid=0,
                app_name=app,
                detail=f"category=messaging app={app}",
            ))

        # Active browsers
        for app in active_browsers:
            timeline.append(TimelineEvent(
                timestamp=now,
                event_type="app_active",
                pid=0,
                app_name=app,
                detail=f"category=browser app={app}",
            ))

        # Active terminals
        for app in active_terminals:
            timeline.append(TimelineEvent(
                timestamp=now,
                event_type="app_active",
                pid=0,
                app_name=app,
                detail=f"category=terminal app={app}",
            ))

        # Sort by timestamp (chronological order)
        timeline.sort(key=lambda e: e.timestamp)
        return timeline

    # ── Utility ──────────────────────────────────────────────────────────

    @staticmethod
    def _empty_result() -> Dict[str, Any]:
        """Return empty result when psutil is unavailable."""
        return {
            "timeline": [],
            "new_processes": [],
            "new_downloads": [],
            "pid_connections": {},
            "active_messaging_apps": [],
            "active_browsers": [],
            "active_terminals": [],
            "is_baseline_scan": True,
            "collection_time_ms": 0.0,
        }
