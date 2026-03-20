"""macOS Process Collector — psutil-based process snapshot.

Collects process data with full awareness of macOS permission boundaries:
    - pid, name, exe: available for ALL processes (100%)
    - cmdline, cpu_percent, memory_percent, environ, cwd: own-user only (~60%)
    - parent info: available for all visible PIDs

The collector returns a structured snapshot that probes consume via shared_data.
It never makes detection decisions — that's the probes' job.

Ground truth (macOS 26.0, uid=501, Apple Silicon):
    - 652 processes in 5ms
    - 398 own-user with full detail
    - 254 other-user with pid/name/exe only
    - AccessDenied for cpu_percent/memory_percent on other-user procs
"""

from __future__ import annotations

import hashlib
import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logger.error("psutil not installed — process collector cannot function")


@dataclass
class ProcessSnapshot:
    """Single process state at collection time."""

    pid: int
    name: str
    exe: str
    cmdline: List[str]
    username: str
    ppid: int
    parent_name: str
    create_time: float
    cpu_percent: Optional[float]  # None if permission denied
    memory_percent: Optional[float]  # None if permission denied
    num_threads: Optional[int]  # None if permission denied
    num_fds: Optional[int]  # None if permission denied
    status: str
    cwd: str
    environ: Optional[Dict[str, str]]  # None if permission denied
    is_own_user: bool  # True if we have full visibility
    process_guid: str  # Stable GUID for correlation


def _make_guid(device_id: str, pid: int, create_time: float) -> str:
    """Stable process GUID surviving PID recycling."""
    raw = f"{device_id}:{pid}:{int(create_time * 1e9)}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class MacOSProcessCollector:
    """Collects process snapshots from macOS via psutil.

    Returns shared_data dict with keys:
        processes: List[ProcessSnapshot] — all visible processes
        own_user_count: int — processes with full visibility
        total_count: int — total process count
        collection_time_ms: float — how long collection took
        current_uid: int — our UID
    """

    def __init__(self, device_id: str = "") -> None:
        self.device_id = device_id or _get_hostname()
        self._current_uid = os.getuid()
        self._current_user = _get_current_user()

    def collect(self) -> Dict[str, Any]:
        """Collect full process snapshot.

        Returns dict for ProbeContext.shared_data.
        """
        if not PSUTIL_AVAILABLE:
            return {
                "processes": [],
                "own_user_count": 0,
                "total_count": 0,
                "collection_time_ms": 0.0,
                "current_uid": self._current_uid,
            }

        start = time.monotonic()
        processes: List[ProcessSnapshot] = []

        # Single pass: collect everything psutil gives us
        for proc in psutil.process_iter(
            [
                "pid",
                "name",
                "exe",
                "cmdline",
                "username",
                "ppid",
                "create_time",
                "status",
            ]
        ):
            try:
                info = proc.info
                pid = info["pid"]
                username = info.get("username") or ""
                is_own = username == self._current_user

                # Parent name — best effort
                parent_name = ""
                ppid = info.get("ppid", 0)
                if ppid:
                    try:
                        parent_name = psutil.Process(ppid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                # Fields that require own-user permission on macOS
                cpu_pct = None
                mem_pct = None
                cwd = ""
                environ = None

                num_threads = None
                num_fds = None

                if is_own:
                    try:
                        cpu_pct = proc.cpu_percent(interval=0)
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    try:
                        mem_pct = proc.memory_percent()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    try:
                        num_threads = proc.num_threads()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    try:
                        num_fds = proc.num_fds()
                    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                        pass
                    try:
                        cwd = proc.cwd()
                    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                        pass
                    try:
                        environ = dict(proc.environ())
                    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                        pass

                create_time = info.get("create_time", 0) or 0
                guid = _make_guid(self.device_id, pid, create_time)

                snap = ProcessSnapshot(
                    pid=pid,
                    name=info.get("name") or "",
                    exe=info.get("exe") or "",
                    cmdline=info.get("cmdline") or [],
                    username=username,
                    ppid=ppid,
                    parent_name=parent_name,
                    create_time=create_time,
                    cpu_percent=cpu_pct,
                    memory_percent=mem_pct,
                    num_threads=num_threads,
                    num_fds=num_fds,
                    status=info.get("status") or "",
                    cwd=cwd,
                    environ=environ,
                    is_own_user=is_own,
                    process_guid=guid,
                )
                processes.append(snap)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        elapsed_ms = (time.monotonic() - start) * 1000
        own_count = sum(1 for p in processes if p.is_own_user)

        return {
            "processes": processes,
            "own_user_count": own_count,
            "total_count": len(processes),
            "collection_time_ms": round(elapsed_ms, 2),
            "current_uid": self._current_uid,
        }


def _get_hostname() -> str:
    """Get hostname for device_id."""
    import socket

    return socket.gethostname()


def _get_current_user() -> str:
    """Get current username."""
    import getpass

    try:
        return getpass.getuser()
    except Exception:
        return str(os.getuid())
