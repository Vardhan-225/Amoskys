"""Real-Time Event Collectors — FSEvents + kqueue + Log Stream.

Three independent event sources that feed into a unified event queue,
converting macOS from polling-based to event-driven detection.

No entitlements required. No kernel extensions. No SIP bypass.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import json
import logging
import os
import re
import select
import struct
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Deque, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# ── FSEvents Constants (from CoreServices/FSEvents.h) ────────────────────────

# FSEventStreamEventFlags
kFSEventStreamEventFlagNone = 0x00000000
kFSEventStreamEventFlagItemCreated = 0x00000100
kFSEventStreamEventFlagItemRemoved = 0x00000200
kFSEventStreamEventFlagItemModified = 0x00001000
kFSEventStreamEventFlagItemRenamed = 0x00000800
kFSEventStreamEventFlagItemIsFile = 0x00010000
kFSEventStreamEventFlagItemIsDir = 0x00020000
kFSEventStreamEventFlagItemIsSymlink = 0x00040000

# kqueue constants
KQ_FILTER_PROC = -5  # select.KQ_FILTER_PROC
NOTE_EXIT = 0x80000000
NOTE_FORK = 0x00000001
NOTE_EXEC = 0x00000004
NOTE_EXITSTATUS = 0x04000000


@dataclass
class RealTimeEvent:
    """A single real-time event from any source."""

    source: str  # "fsevents" | "kqueue" | "logstream"
    event_type: str  # "file_created" | "process_exit" | "tcc_grant" etc.
    timestamp_ns: int
    path: str = ""
    pid: int = 0
    process_name: str = ""
    uid: int = -1
    details: Dict[str, Any] = field(default_factory=dict)
    flags: int = 0


# ── FSEvents Collector ───────────────────────────────────────────────────────


class FSEventsCollector:
    """Real-time filesystem change monitoring via macOS FSEvents API.

    Watches critical paths for changes. When a file is created, modified,
    or deleted in a watched path, an event is immediately available.

    Uses the CoreFoundation run loop internally (in a background thread).
    Events are collected via a callback and placed in a thread-safe queue.
    """

    # Paths to watch for security-relevant filesystem changes
    DEFAULT_WATCH_PATHS = [
        # ── Persistence locations ──
        str(Path.home() / "Library/LaunchAgents"),
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        str(Path.home() / ".ssh"),
        str(Path.home() / ".zshrc"),
        str(Path.home() / ".zshenv"),
        str(Path.home() / ".bash_profile"),
        str(Path.home() / ".zprofile"),
        # ── User activity surfaces ──
        str(Path.home() / "Downloads"),
        str(Path.home() / "Documents"),
        str(Path.home() / "Desktop"),
        # ── System binaries ──
        "/usr/local/bin",
        "/usr/local/sbin",
        # ── Temp / staging areas ──
        "/tmp",
        "/var/tmp",
        # ── Critical config ──
        "/etc",
        # ── Applications ──
        "/Applications",
    ]

    def __init__(
        self,
        watch_paths: Optional[List[str]] = None,
        latency: float = 0.5,
    ) -> None:
        self._watch_paths = watch_paths or self.DEFAULT_WATCH_PATHS
        self._latency = latency
        self._events: Deque[RealTimeEvent] = deque(maxlen=10000)
        self._running = False
        self._observer = None

        # Try watchdog library (real kernel FSEvents)
        try:
            from watchdog.observers import Observer

            self._available = True
            self._use_watchdog = True
        except ImportError:
            self._use_watchdog = False
            # Fallback: ctypes CoreServices (stat-based polling)
            try:
                cs_path = ctypes.util.find_library("CoreServices")
                cf_path = ctypes.util.find_library("CoreFoundation")
                if cs_path and cf_path:
                    self._cs = ctypes.cdll.LoadLibrary(cs_path)
                    self._cf = ctypes.cdll.LoadLibrary(cf_path)
                    self._available = True
                else:
                    self._available = False
            except OSError:
                self._available = False

        if not self._available:
            logger.warning("FSEvents: no backend available (install watchdog)")

    @property
    def available(self) -> bool:
        return self._available

    def start(self) -> None:
        """Start watching filesystem paths."""
        if not self._available or self._running:
            return

        self._running = True

        if self._use_watchdog:
            self._start_watchdog()
        else:
            self._thread = threading.Thread(
                target=self._poll_loop,
                name="fsevents-collector",
                daemon=True,
            )
            self._thread.start()

        logger.info(
            "FSEvents collector started: watching %d paths (backend=%s)",
            len(self._watch_paths),
            "watchdog" if self._use_watchdog else "stat-poll",
        )

    def _start_watchdog(self) -> None:
        """Start real kernel FSEvents monitoring via watchdog library."""
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer

        events_deque = self._events

        class _Handler(FileSystemEventHandler):
            def on_any_event(self, event):
                if event.is_directory and event.event_type not in (
                    "created",
                    "deleted",
                ):
                    return  # Skip dir modification noise
                now_ns = int(time.time() * 1e9)
                etype_map = {
                    "created": "file_created",
                    "modified": "file_modified",
                    "deleted": "file_deleted",
                    "moved": "file_renamed",
                }
                etype = etype_map.get(event.event_type, event.event_type)
                events_deque.append(
                    RealTimeEvent(
                        source="fsevents",
                        event_type=etype,
                        timestamp_ns=now_ns,
                        path=event.src_path,
                        details={
                            "is_directory": event.is_directory,
                            "change_type": event.event_type,
                        },
                    )
                )

        self._observer = Observer()
        handler = _Handler()

        for watch_path in self._watch_paths:
            p = Path(watch_path)
            if p.is_dir():
                self._observer.schedule(handler, str(p), recursive=True)
            elif p.exists():
                # Watch parent directory for single-file paths like ~/.zshrc
                self._observer.schedule(handler, str(p.parent), recursive=False)

        self._observer.daemon = True
        self._observer.start()

    def stop(self) -> None:
        self._running = False
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)
        if hasattr(self, "_thread") and self._thread:
            self._thread.join(timeout=5)

    def drain(self) -> List[RealTimeEvent]:
        """Drain all collected events."""
        events = []
        while self._events:
            try:
                events.append(self._events.popleft())
            except IndexError:
                break
        return events

    def _poll_loop(self) -> None:
        """Poll filesystem paths for changes using os.scandir snapshots.

        FSEvents via ctypes requires complex CFRunLoop setup. For reliability,
        we use a fast stat-based approach with 1-second intervals — still 60x
        faster than the original 60-second polling cycle.
        """
        # Build initial snapshot of file mtimes
        snapshots: Dict[str, Dict[str, float]] = {}
        for watch_path in self._watch_paths:
            snapshots[watch_path] = self._snapshot_dir(watch_path)

        while self._running:
            time.sleep(self._latency)
            now_ns = int(time.time() * 1e9)

            for watch_path in self._watch_paths:
                try:
                    current = self._snapshot_dir(watch_path)
                    previous = snapshots.get(watch_path, {})

                    # New files
                    for path, mtime in current.items():
                        if path not in previous:
                            self._events.append(
                                RealTimeEvent(
                                    source="fsevents",
                                    event_type="file_created",
                                    timestamp_ns=now_ns,
                                    path=path,
                                    details={
                                        "watch_dir": watch_path,
                                        "size": self._safe_size(path),
                                        "change_type": "created",
                                    },
                                )
                            )
                        elif mtime > previous[path]:
                            self._events.append(
                                RealTimeEvent(
                                    source="fsevents",
                                    event_type="file_modified",
                                    timestamp_ns=now_ns,
                                    path=path,
                                    details={
                                        "watch_dir": watch_path,
                                        "size": self._safe_size(path),
                                        "change_type": "modified",
                                    },
                                )
                            )

                    # Deleted files
                    for path in previous:
                        if path not in current:
                            self._events.append(
                                RealTimeEvent(
                                    source="fsevents",
                                    event_type="file_deleted",
                                    timestamp_ns=now_ns,
                                    path=path,
                                    details={
                                        "watch_dir": watch_path,
                                        "change_type": "deleted",
                                    },
                                )
                            )

                    snapshots[watch_path] = current
                except Exception:
                    pass

    @staticmethod
    def _snapshot_dir(path: str) -> Dict[str, float]:
        """Get {filepath: mtime} snapshot of a directory."""
        result = {}
        try:
            p = Path(path)
            if p.is_dir():
                for entry in p.iterdir():
                    try:
                        result[str(entry)] = entry.stat().st_mtime
                    except (OSError, PermissionError):
                        pass
            elif p.exists():
                result[str(p)] = p.stat().st_mtime
        except (OSError, PermissionError):
            pass
        return result

    @staticmethod
    def _safe_size(path: str) -> int:
        try:
            return os.path.getsize(path)
        except OSError:
            return -1


# ── Process Lifecycle Collector (kqueue) ─────────────────────────────────────


class ProcessLifecycleCollector:
    """Real-time process monitoring using kqueue EVFILT_PROC.

    Watches for process exit events on known PIDs. When combined with
    periodic psutil snapshots, this detects:
    - Short-lived processes that start and exit between poll cycles
    - Process exit timing (forensic timeline)
    - Rapid process spawning patterns (LOLBin chains)
    """

    def __init__(self, max_watched: int = 500) -> None:
        self._max_watched = max_watched
        self._events: Deque[RealTimeEvent] = deque(maxlen=10000)
        self._watched_pids: Set[int] = set()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._kq: Optional[Any] = None

        try:
            self._kq = select.kqueue()
            self._available = True
        except (AttributeError, OSError):
            self._available = False
            logger.warning("kqueue: not available on this platform")

    @property
    def available(self) -> bool:
        return self._available

    def start(self) -> None:
        if not self._available or self._running:
            return

        self._running = True
        # Seed with current process list
        self._seed_process_list()

        self._thread = threading.Thread(
            target=self._event_loop,
            name="kqueue-proc-collector",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "kqueue process collector started: watching %d PIDs",
            len(self._watched_pids),
        )

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        if self._kq:
            self._kq.close()

    def drain(self) -> List[RealTimeEvent]:
        events = []
        while self._events:
            try:
                events.append(self._events.popleft())
            except IndexError:
                break
        return events

    def refresh_pids(self) -> None:
        """Refresh watched PID list from current processes."""
        self._seed_process_list()

    def _seed_process_list(self) -> None:
        """Discover current PIDs and watch them for exit."""
        try:
            import psutil

            current_pids = set(psutil.pids())
        except ImportError:
            # Fallback: read /proc or use sysctl
            try:
                output = subprocess.check_output(["ps", "-axo", "pid"], text=True)
                current_pids = set()
                for line in output.strip().split("\n")[1:]:
                    try:
                        current_pids.add(int(line.strip()))
                    except ValueError:
                        pass
            except Exception:
                return

        # Watch new PIDs (up to limit)
        new_pids = current_pids - self._watched_pids
        to_watch = list(new_pids)[: self._max_watched - len(self._watched_pids)]

        changelist = []
        for pid in to_watch:
            if pid <= 0:
                continue
            ev = select.kevent(
                pid,
                filter=select.KQ_FILTER_PROC,
                flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_ONESHOT,
                fflags=NOTE_EXIT,
            )
            changelist.append(ev)
            self._watched_pids.add(pid)

        if changelist and self._kq:
            try:
                self._kq.control(changelist, 0, 0)
            except OSError:
                # Some PIDs may have exited between discovery and registration
                pass

    def _event_loop(self) -> None:
        """Main kqueue event loop — blocks until events arrive."""
        refresh_interval = 10  # Re-seed PID list every 10s
        last_refresh = time.time()

        while self._running:
            try:
                # Wait for events with 1s timeout
                events = self._kq.control(None, 10, 1.0)
                now_ns = int(time.time() * 1e9)

                for ev in events:
                    pid = ev.ident
                    self._watched_pids.discard(pid)

                    # Get process name if possible
                    proc_name = self._get_process_name(pid)

                    if ev.fflags & NOTE_EXIT:
                        exit_status = (
                            (ev.fflags >> 8) & 0xFF
                            if ev.fflags & NOTE_EXITSTATUS
                            else -1
                        )
                        self._events.append(
                            RealTimeEvent(
                                source="kqueue",
                                event_type="process_exit",
                                timestamp_ns=now_ns,
                                pid=pid,
                                process_name=proc_name,
                                details={
                                    "exit_status": exit_status,
                                    "fflags": ev.fflags,
                                },
                            )
                        )

            except OSError:
                time.sleep(0.1)
            except Exception:
                logger.debug("kqueue event loop error", exc_info=True)
                time.sleep(0.5)

            # Periodic PID refresh
            if time.time() - last_refresh > refresh_interval:
                self._seed_process_list()
                last_refresh = time.time()

    @staticmethod
    def _get_process_name(pid: int) -> str:
        try:
            import psutil

            p = psutil.Process(pid)
            return p.name()
        except Exception:
            return ""


# ── Critical File Watcher (kqueue VNODE) ─────────────────────────────────────


class CriticalFileWatcher:
    """Zero-latency kqueue watcher for high-value files.

    Unlike FSEvents (directory-level, 0.5s coalesce), kqueue VNODE events
    fire immediately when a watched file is written, deleted, or renamed.
    Used for files where any modification is a security event.
    """

    CRITICAL_FILES = [
        "/etc/hosts",
        "/etc/sudoers",
        "/etc/pam.d/sudo",
        "/etc/ssh/sshd_config",
        "/etc/resolv.conf",
        str(Path.home() / ".ssh/authorized_keys"),
        str(Path.home() / ".ssh/config"),
        str(Path.home() / ".zshrc"),
        str(Path.home() / ".bash_profile"),
        str(Path.home() / ".zprofile"),
    ]

    def __init__(self) -> None:
        self._events: Deque[RealTimeEvent] = deque(maxlen=1000)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._kq: Optional[Any] = None
        self._fd_to_path: Dict[int, str] = {}
        self._available = True

        try:
            self._kq = select.kqueue()
        except (AttributeError, OSError):
            self._available = False

    @property
    def available(self) -> bool:
        return self._available

    def start(self) -> None:
        if not self._available or self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._watch_loop, name="kqueue-file-watcher", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        for fd in list(self._fd_to_path):
            try:
                os.close(fd)
            except OSError:
                pass
        self._fd_to_path.clear()
        if self._kq:
            self._kq.close()

    def drain(self) -> List[RealTimeEvent]:
        events = []
        while self._events:
            try:
                events.append(self._events.popleft())
            except IndexError:
                break
        return events

    def _watch_loop(self) -> None:
        kevents = self._register_files()
        if not kevents:
            logger.warning("CriticalFileWatcher: no files to watch")
            return

        logger.info(
            "CriticalFileWatcher started: watching %d files", len(self._fd_to_path)
        )

        while self._running:
            try:
                events = self._kq.control(None, 8, 1.0)
                now_ns = int(time.time() * 1e9)
                for ev in events:
                    path = self._fd_to_path.get(ev.ident, "unknown")
                    changes = []
                    if ev.fflags & select.KQ_NOTE_WRITE:
                        changes.append("written")
                    if ev.fflags & select.KQ_NOTE_DELETE:
                        changes.append("deleted")
                    if ev.fflags & select.KQ_NOTE_RENAME:
                        changes.append("renamed")
                    if ev.fflags & select.KQ_NOTE_ATTRIB:
                        changes.append("attrib_changed")

                    self._events.append(
                        RealTimeEvent(
                            source="kqueue_vnode",
                            event_type="critical_file_modified",
                            timestamp_ns=now_ns,
                            path=path,
                            details={
                                "changes": changes,
                                "fflags": ev.fflags,
                            },
                        )
                    )

                    # Re-register if deleted (new inode)
                    if ev.fflags & select.KQ_NOTE_DELETE:
                        try:
                            os.close(ev.ident)
                        except OSError:
                            pass
                        self._fd_to_path.pop(ev.ident, None)
                        time.sleep(0.1)  # Brief wait for file recreation
                        self._register_single(path)

            except OSError:
                time.sleep(0.5)

    def _register_files(self) -> List:
        kevents = []
        for path in self.CRITICAL_FILES:
            kev = self._register_single(path)
            if kev:
                kevents.append(kev)
        if kevents and self._kq:
            try:
                self._kq.control(kevents, 0, 0)
            except OSError:
                pass
        return kevents

    def _register_single(self, path: str):
        if not os.path.exists(path):
            return None
        try:
            fd = os.open(path, os.O_RDONLY)
            self._fd_to_path[fd] = path
            return select.kevent(
                fd,
                filter=select.KQ_FILTER_VNODE,
                flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                fflags=(
                    select.KQ_NOTE_WRITE
                    | select.KQ_NOTE_DELETE
                    | select.KQ_NOTE_RENAME
                    | select.KQ_NOTE_ATTRIB
                    | select.KQ_NOTE_EXTEND
                ),
            )
        except OSError:
            return None


# ── Unified Log Stream Collector ─────────────────────────────────────────────


class UnifiedLogStreamCollector:
    """Real-time macOS Unified Log event monitoring.

    Streams security-relevant log events via `log stream` subprocess.
    Captures TCC permission changes, authentication events, security
    framework events, and process execution logs in real-time.

    This replaces the UnifiedLog agent's polling-based approach with
    a persistent stream that catches events as they happen.
    """

    # Predicate filters for security-relevant events.
    # Single log stream process covers ALL security subsystems.
    # Filtering happens kernel-side — negligible CPU impact.
    SECURITY_PREDICATES = [
        # ── Privacy & Permissions ──
        'subsystem == "com.apple.TCC"',
        # ── Auth & Identity ──
        'subsystem == "com.apple.Authorization"',
        'subsystem == "com.apple.authd"',
        'subsystem == "com.apple.opendirectoryd"',
        # ── Security Framework ──
        'subsystem == "com.apple.securityd"',
        # ── Code Signing Enforcement ──
        'subsystem == "com.apple.MobileFileIntegrity"',
        # ── Malware Detection (XProtect + MRT) ──
        'subsystem == "com.apple.XProtect"',
        'subsystem == "com.apple.MRT"',
        # ── App Lifecycle (real-time launch/quit) ──
        'subsystem == "com.apple.runningboard"',
        # ── Gatekeeper ──
        'process == "syspolicyd"',
        'process == "GatekeeperXPC"',
        # ── Network Stack ──
        'subsystem == "com.apple.networkd"',
        # ── Firewall ──
        'subsystem == "com.apple.alf"',
        # ── Disk & USB ──
        'subsystem == "com.apple.diskarbitration"',
        'subsystem == "com.apple.usb"',
        # ── XPC Services ──
        'subsystem == "com.apple.xpc"',
        # ── DNS ──
        'process == "mDNSResponder"',
        # ── Auth processes ──
        'process == "sshd"',
        'process == "sudo"',
        'process == "loginwindow"',
        'process == "screensaverengine"',
        'process == "SecurityAgent"',
        # ── Installer ──
        'process == "installer"',
    ]

    def __init__(self) -> None:
        self._events: Deque[RealTimeEvent] = deque(maxlen=10000)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._process: Optional[subprocess.Popen] = None
        self._available = True

    @property
    def available(self) -> bool:
        return self._available

    def start(self) -> None:
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._stream_loop,
            name="logstream-collector",
            daemon=True,
        )
        self._thread.start()
        logger.info("Unified Log stream collector started")

    def stop(self) -> None:
        self._running = False
        if self._process:
            self._process.terminate()
            try:
                self._process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._process.kill()
        if self._thread:
            self._thread.join(timeout=5)

    def drain(self) -> List[RealTimeEvent]:
        events = []
        while self._events:
            try:
                events.append(self._events.popleft())
            except IndexError:
                break
        return events

    def _stream_loop(self) -> None:
        """Run `log stream` and parse JSON output."""
        # Build compound predicate
        predicate = " OR ".join(f"({p})" for p in self.SECURITY_PREDICATES)

        cmd = [
            "log",
            "stream",
            "--predicate",
            predicate,
            "--style",
            "ndjson",
            "--level",
            "info",
        ]

        while self._running:
            try:
                self._process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    bufsize=1,
                )

                for line in self._process.stdout:
                    if not self._running:
                        break
                    line = line.strip()
                    if not line or line.startswith("Filtering") or line == "[":
                        continue

                    # ndjson: one complete JSON object per line
                    # json: pretty-printed array, strip trailing commas
                    clean = line.rstrip(",")
                    try:
                        entry = json.loads(clean)
                        self._parse_log_entry(entry)
                    except json.JSONDecodeError:
                        pass

            except FileNotFoundError:
                logger.warning("'log' command not found — log stream unavailable")
                self._available = False
                return
            except Exception:
                logger.debug("Log stream error, restarting", exc_info=True)
                time.sleep(2)

    # PID → bundle_id mapping, populated from runningboard events.
    # Format in logs: <type<bundle_id(uid_or_pid)>:session_id>
    # We extract bundle_id and session_id (which correlates to process group).
    _pid_bundle_map: Dict[int, str] = {}
    _BUNDLE_PID_PATTERN = re.compile(r"<([\w.]+)\(\d+\)>:(\d+)")
    # Simpler pattern: <bundle>:pid (no uid)
    _BUNDLE_SIMPLE_PATTERN = re.compile(r"<([\w.]+)>:(\d+)")

    @classmethod
    def get_bundle_id(cls, pid: int) -> str:
        """Look up bundle_id for a PID from runningboard events."""
        return cls._pid_bundle_map.get(pid, "")

    def _parse_log_entry(self, entry: Dict[str, Any]) -> None:
        """Convert a log stream JSON entry to a RealTimeEvent."""
        # Prefer the log entry's own timestamp over collection time
        event_ts = entry.get("timestamp")
        if event_ts:
            try:
                from datetime import datetime, timezone

                # macOS log stream ndjson: "2026-03-21 10:15:30.123456-0700"
                dt = datetime.fromisoformat(str(event_ts))
                now_ns = int(dt.timestamp() * 1e9)
            except (ValueError, TypeError, OSError):
                now_ns = int(time.time() * 1e9)
        else:
            now_ns = int(time.time() * 1e9)
        subsystem = entry.get("subsystem", "")
        category = entry.get("category", "")
        message = entry.get("eventMessage", "")
        process = entry.get("processImagePath", "")
        process_name = os.path.basename(process) if process else ""
        pid = entry.get("processID", 0)

        # ── Extract PID→bundle_id from runningboard messages ──
        if subsystem == "com.apple.runningboard":
            for match in self._BUNDLE_PID_PATTERN.finditer(message):
                bid = match.group(1)
                session_id = int(match.group(2))
                if "." in bid:  # Only reverse-DNS identifiers
                    self._pid_bundle_map[session_id] = bid
            for match in self._BUNDLE_SIMPLE_PATTERN.finditer(message):
                bid = match.group(1)
                session_id = int(match.group(2))
                if "." in bid and session_id not in self._pid_bundle_map:
                    self._pid_bundle_map[session_id] = bid

            # Cap map size
            if len(self._pid_bundle_map) > 5000:
                entries = sorted(
                    self._pid_bundle_map.items(), key=lambda x: x[0], reverse=True
                )
                self._pid_bundle_map = dict(entries[:2500])

        # ── Classify by subsystem ──
        event_type = self._classify_event(subsystem, process_name, message)

        # ── Enrich with bundle_id if available ──
        bundle_id = self._pid_bundle_map.get(pid, "")

        details = {
            "subsystem": subsystem,
            "category": category,
            "message": message[:500],
            "process_path": process,
        }
        if bundle_id:
            details["bundle_id"] = bundle_id

        self._events.append(
            RealTimeEvent(
                source="logstream",
                event_type=event_type,
                timestamp_ns=now_ns,
                pid=pid,
                process_name=process_name,
                details=details,
            )
        )

    @staticmethod
    def _classify_event(subsystem: str, process_name: str, message: str) -> str:
        """Classify a Unified Log entry into a semantic event type."""
        msg_lower = message.lower()

        # ── TCC (Privacy permissions) ──
        if subsystem == "com.apple.TCC":
            if "granting" in msg_lower:
                return "tcc_permission_granted"
            if "request" in msg_lower:
                return "tcc_permission_request"
            if "deny" in msg_lower:
                return "tcc_permission_denied"
            return "tcc_event"

        # ── Auth ──
        if subsystem in (
            "com.apple.Authorization",
            "com.apple.authd",
            "com.apple.opendirectoryd",
        ):
            if "succeed" in msg_lower or "allow" in msg_lower:
                return "auth_success"
            if "fail" in msg_lower or "deny" in msg_lower:
                return "auth_failure"
            return "auth_event"

        # ── Code Signing Enforcement (AMFI) ──
        if subsystem == "com.apple.MobileFileIntegrity":
            if "deny" in msg_lower or "not valid" in msg_lower:
                return "amfi_code_signing_denied"
            return "amfi_event"

        # ── XProtect / Malware Removal Tool ──
        if subsystem in ("com.apple.XProtect", "com.apple.MRT"):
            if "block" in msg_lower or "malware" in msg_lower or "threat" in msg_lower:
                return "xprotect_malware_blocked"
            if "scan" in msg_lower or "update" in msg_lower:
                return "xprotect_scan"
            return "xprotect_event"

        # ── App Lifecycle (RunningBoard) ──
        if subsystem == "com.apple.runningboard":
            if "launch" in msg_lower or "acquiring" in msg_lower:
                return "app_launched"
            if "terminat" in msg_lower or "exit" in msg_lower:
                return "app_terminated"
            if "foreground" in msg_lower or "role" in msg_lower:
                return "app_focus_changed"
            return "app_lifecycle"

        # ── Network daemon ──
        if subsystem == "com.apple.networkd":
            if "dns" in msg_lower or "query" in msg_lower or "resolv" in msg_lower:
                return "network_dns_event"
            if "connect" in msg_lower:
                return "network_connection_event"
            if "tls" in msg_lower or "ssl" in msg_lower:
                return "network_tls_event"
            return "network_event"

        # ── Firewall (ALF) ──
        if subsystem == "com.apple.alf":
            if "deny" in msg_lower or "block" in msg_lower:
                return "firewall_blocked"
            if "allow" in msg_lower:
                return "firewall_allowed"
            return "firewall_event"

        # ── Disk / USB ──
        if subsystem == "com.apple.diskarbitration":
            if "mount" in msg_lower:
                return "disk_mounted"
            if "unmount" in msg_lower:
                return "disk_unmounted"
            if "eject" in msg_lower:
                return "disk_ejected"
            return "disk_event"
        if subsystem == "com.apple.usb":
            return "usb_event"

        # ── Gatekeeper ──
        if process_name in ("syspolicyd", "GatekeeperXPC"):
            if "allow" in msg_lower or "pass" in msg_lower:
                return "gatekeeper_allowed"
            if "deny" in msg_lower or "block" in msg_lower:
                return "gatekeeper_blocked"
            return "gatekeeper_event"

        # ── DNS (mDNSResponder) ──
        if process_name == "mDNSResponder":
            if "query" in msg_lower:
                return "dns_query"
            return "dns_event"

        # ── SSH / sudo / login ──
        if process_name == "sshd":
            if "accepted" in msg_lower:
                return "ssh_login_success"
            if "failed" in msg_lower or "invalid" in msg_lower:
                return "ssh_login_failure"
            return "ssh_event"
        if process_name == "sudo":
            return "sudo_event"
        if process_name in ("loginwindow", "screensaverengine", "SecurityAgent"):
            return "login_event"

        # ── Installer ──
        if process_name in ("installer", "Installer"):
            return "installer_event"

        # ── Security framework ──
        if subsystem == "com.apple.securityd":
            return "security_framework_event"

        # ── XPC ──
        if subsystem == "com.apple.xpc":
            return "xpc_event"

        return "log_event"


# ── Unified Real-Time Collector ──────────────────────────────────────────────


class RealtimeSensorCollector:
    """Unified collector that combines all real-time event sources.

    Provides a single interface for the agent to drain events from
    FSEvents, kqueue, and Unified Log in one call.
    """

    def __init__(self) -> None:
        self._fs = FSEventsCollector()
        self._proc = ProcessLifecycleCollector()
        self._log = UnifiedLogStreamCollector()
        self._crit = CriticalFileWatcher()

        self._sources = [self._fs, self._proc, self._log, self._crit]
        self._started = False

    def start(self) -> None:
        """Start all available event sources."""
        if self._started:
            return

        for source in self._sources:
            if source.available:
                source.start()

        self._started = True
        active = sum(1 for s in self._sources if s.available)
        logger.info(
            "RealtimeSensorCollector started: %d/%d sources active",
            active,
            len(self._sources),
        )

    def stop(self) -> None:
        for source in self._sources:
            source.stop()
        self._started = False

    def collect(self) -> List[RealTimeEvent]:
        """Drain all events from all sources."""
        events = []
        events.extend(self._fs.drain())
        events.extend(self._proc.drain())
        events.extend(self._log.drain())
        events.extend(self._crit.drain())
        return events

    def status(self) -> Dict[str, Any]:
        return {
            "fsevents": {"available": self._fs.available},
            "kqueue_proc": {"available": self._proc.available},
            "logstream": {"available": self._log.available},
            "kqueue_files": {"available": self._crit.available},
            "started": self._started,
        }
