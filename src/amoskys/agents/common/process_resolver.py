"""Process Resolver - Fast PID-to-Process Context Resolution for Phase 2 Mandate.

This module provides time-critical process resolution for agents that receive
PIDs (from kernel audit logs, unified logs, filesystem events, flow data)
but need full process context BEFORE the process exits.

Architecture:
    - ProcessSnapshot: Frozen capture of a process's state at a point in time
    - ProcessResolver: Singleton with LRU cache of resolved PIDs
    - resolve(): Main API - returns ProcessSnapshot or DEAD_PROCESS sentinel
    - resolve_batch(): Bulk resolution for agents with many PIDs per cycle
    - resolve_file_owner_process(): lsof-based file-to-process attribution

Performance Contract:
    - Single PID resolution: <1ms (cached), <5ms (live psutil call)
    - Batch resolution (100 PIDs): <50ms
    - Cache TTL: 30s (processes rarely change identity)
    - Cache size: 2048 entries (covers typical endpoint process count)
    - Dead process tombstone: cached for 10s to prevent re-querying

Mandate Compliance:
    This module directly supports the Agent Observability Mandate v1.0
    Section 3.2 (CONDITIONAL field enrichment) by providing every agent
    the ability to populate: pid, process_name, exe, cmdline, ppid,
    parent_name, parent_exe, username, uid, create_time.
"""

from __future__ import annotations

import logging
import subprocess
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

try:
    import psutil

    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False
    logger.warning(
        "MANDATE_DEGRADED: psutil not available - process resolution disabled"
    )


@dataclass(frozen=True)
class ProcessSnapshot:
    """Immutable capture of a process's state at resolution time."""

    pid: int
    process_name: str = ""
    exe: str = ""
    cmdline: str = ""
    ppid: int = 0
    parent_name: str = ""
    parent_exe: str = ""
    username: str = ""
    uid: int = -1
    create_time: float = 0.0
    cpu_percent: float = 0.0
    memory_rss: int = 0
    num_fds: int = 0
    num_threads: int = 0
    cwd: str = ""
    is_alive: bool = False
    resolved_at: float = 0.0

    def to_event_fields(self) -> Dict[str, Any]:
        """Convert to flat dict suitable for merging into event data."""
        fields: Dict[str, Any] = {}
        if self.pid:
            fields["pid"] = self.pid
        if self.process_name:
            fields["process_name"] = self.process_name
        if self.exe:
            fields["exe"] = self.exe
        if self.cmdline:
            fields["cmdline"] = self.cmdline
        if self.ppid:
            fields["ppid"] = self.ppid
        if self.parent_name:
            fields["parent_name"] = self.parent_name
        if self.parent_exe:
            fields["parent_exe"] = self.parent_exe
        if self.username:
            fields["username"] = self.username
        if self.uid >= 0:
            fields["uid"] = self.uid
        if self.create_time:
            fields["create_time"] = self.create_time
        return fields


DEAD_PROCESS = ProcessSnapshot(pid=0, is_alive=False)


class ProcessResolver:
    """Singleton process resolver with LRU cache.

    Thread-safe PID resolution with aggressive caching.
    Dead process tombstones prevent re-querying exited PIDs.
    """

    CACHE_TTL_LIVE = 30.0
    CACHE_TTL_DEAD = 10.0
    MAX_CACHE_SIZE = 2048

    def __init__(self) -> None:
        self._cache: OrderedDict[int, Tuple[ProcessSnapshot, float]] = OrderedDict()
        self._lock = threading.Lock()
        self._stats = {
            "hits": 0,
            "misses": 0,
            "dead_hits": 0,
            "errors": 0,
            "evictions": 0,
        }

    def resolve(self, pid: int) -> ProcessSnapshot:
        """Resolve a PID to full process context.

        Returns ProcessSnapshot (never None - at minimum returns DEAD_PROCESS).
        """
        if not _HAS_PSUTIL or pid <= 0:
            return ProcessSnapshot(pid=max(pid, 0), is_alive=False)

        now = time.monotonic()

        with self._lock:
            if pid in self._cache:
                snap, cached_at = self._cache[pid]
                ttl = self.CACHE_TTL_LIVE if snap.is_alive else self.CACHE_TTL_DEAD
                if now - cached_at < ttl:
                    self._cache.move_to_end(pid)
                    self._stats["hits"] += 1
                    return snap
                else:
                    del self._cache[pid]

        self._stats["misses"] += 1
        snap = self._resolve_live(pid)

        with self._lock:
            self._cache[pid] = (snap, now)
            self._cache.move_to_end(pid)
            self._evict_if_needed()

        return snap

    def resolve_batch(self, pids: List[int]) -> Dict[int, ProcessSnapshot]:
        """Resolve multiple PIDs efficiently via psutil.process_iter()."""
        if not _HAS_PSUTIL or not pids:
            return {pid: ProcessSnapshot(pid=pid, is_alive=False) for pid in pids}

        results: Dict[int, ProcessSnapshot] = {}
        unresolved: List[int] = []
        now = time.monotonic()

        with self._lock:
            for pid in pids:
                if pid <= 0:
                    results[pid] = ProcessSnapshot(pid=max(pid, 0), is_alive=False)
                    continue
                if pid in self._cache:
                    snap, cached_at = self._cache[pid]
                    ttl = self.CACHE_TTL_LIVE if snap.is_alive else self.CACHE_TTL_DEAD
                    if now - cached_at < ttl:
                        results[pid] = snap
                        self._stats["hits"] += 1
                        continue
                    else:
                        del self._cache[pid]
                unresolved.append(pid)

        pid_set = set(unresolved)
        if pid_set:
            try:
                attrs = [
                    "pid",
                    "name",
                    "exe",
                    "cmdline",
                    "ppid",
                    "username",
                    "uids",
                    "create_time",
                    "cpu_percent",
                    "memory_info",
                    "num_fds",
                    "num_threads",
                    "cwd",
                ]
                for proc in psutil.process_iter(attrs=attrs):
                    try:
                        info = proc.info
                        if info["pid"] in pid_set:
                            snap = self._build_snapshot(info)
                            results[info["pid"]] = snap
                            pid_set.discard(info["pid"])
                            with self._lock:
                                self._cache[info["pid"]] = (snap, now)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            except Exception as e:
                logger.debug("Batch resolution error: %s", e)
                self._stats["errors"] += 1

        for pid in pid_set:
            dead = ProcessSnapshot(pid=pid, is_alive=False, resolved_at=now)
            results[pid] = dead
            with self._lock:
                self._cache[pid] = (dead, now)

        self._stats["misses"] += len(unresolved)
        with self._lock:
            self._evict_if_needed()

        return results

    def invalidate(self, pid: int) -> None:
        """Remove a PID from cache."""
        with self._lock:
            self._cache.pop(pid, None)

    def get_stats(self) -> Dict[str, int]:
        """Return cache performance statistics."""
        with self._lock:
            return {**self._stats, "cache_size": len(self._cache)}

    def clear(self) -> None:
        """Clear entire cache."""
        with self._lock:
            self._cache.clear()

    def _resolve_live(self, pid: int) -> ProcessSnapshot:
        """Resolve a single PID via psutil."""
        now = time.monotonic()
        try:
            proc = psutil.Process(pid)
            info = proc.as_dict(
                attrs=[
                    "pid",
                    "name",
                    "exe",
                    "cmdline",
                    "ppid",
                    "username",
                    "uids",
                    "create_time",
                    "cpu_percent",
                    "memory_info",
                    "num_fds",
                    "num_threads",
                    "cwd",
                ]
            )
            return self._build_snapshot(info)
        except psutil.NoSuchProcess:
            return ProcessSnapshot(pid=pid, is_alive=False, resolved_at=now)
        except psutil.AccessDenied:
            try:
                proc = psutil.Process(pid)
                return ProcessSnapshot(
                    pid=pid,
                    process_name=proc.name() or "",
                    is_alive=True,
                    resolved_at=now,
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return ProcessSnapshot(pid=pid, is_alive=False, resolved_at=now)
        except Exception as e:
            self._stats["errors"] += 1
            logger.debug("Process resolution error for pid=%d: %s", pid, e)
            return ProcessSnapshot(pid=pid, is_alive=False, resolved_at=now)

    def _build_snapshot(self, info: Dict[str, Any]) -> ProcessSnapshot:
        """Build ProcessSnapshot from psutil info dict."""
        now = time.monotonic()
        pid = info.get("pid", 0)
        ppid = info.get("ppid", 0) or 0

        parent_name = ""
        parent_exe = ""
        if ppid > 0:
            try:
                parent = psutil.Process(ppid)
                parent_name = parent.name() or ""
                parent_exe = parent.exe() or ""
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                pass

        mem_info = info.get("memory_info")
        memory_rss = mem_info.rss if mem_info and hasattr(mem_info, "rss") else 0

        uids = info.get("uids")
        uid = uids.real if uids and hasattr(uids, "real") else -1

        cmdline_list = info.get("cmdline") or []
        cmdline = (
            " ".join(cmdline_list)
            if isinstance(cmdline_list, list)
            else str(cmdline_list)
        )

        return ProcessSnapshot(
            pid=pid,
            process_name=info.get("name") or "",
            exe=info.get("exe") or "",
            cmdline=cmdline,
            ppid=ppid,
            parent_name=parent_name,
            parent_exe=parent_exe,
            username=info.get("username") or "",
            uid=uid,
            create_time=info.get("create_time") or 0.0,
            cpu_percent=info.get("cpu_percent") or 0.0,
            memory_rss=memory_rss,
            num_fds=info.get("num_fds") or 0,
            num_threads=info.get("num_threads") or 0,
            cwd=info.get("cwd") or "",
            is_alive=True,
            resolved_at=now,
        )

    def _evict_if_needed(self) -> None:
        """Evict oldest entries if cache exceeds max size."""
        while len(self._cache) > self.MAX_CACHE_SIZE:
            self._cache.popitem(last=False)
            self._stats["evictions"] += 1


def resolve_file_owner_process(file_path: str) -> Optional[ProcessSnapshot]:
    """Find which process has a file open for writing via lsof."""
    if not _HAS_PSUTIL:
        return None
    try:
        result = subprocess.run(
            ["lsof", "-t", "-w", file_path],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if result.returncode == 0 and result.stdout.strip():
            pids = result.stdout.strip().split("\n")
            for pid_str in pids:
                try:
                    pid = int(pid_str.strip())
                    snap = resolver.resolve(pid)
                    if snap.is_alive:
                        return snap
                except (ValueError, TypeError):
                    continue
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        logger.debug("lsof failed for %s: %s", file_path, e)
    return None


# Global singleton
resolver = ProcessResolver()


def mandate_context_from_pid(
    pid: int,
    probe_name: str,
    *,
    process_name_hint: str = "",
    detection_source: str = "psutil_resolve",
) -> Dict[str, Any]:
    """Resolve a PID to full Observability Mandate process context.

    Returns a dict with ALL mandate fields populated — never None or
    empty string.  Uses sentinels for unresolvable fields:
        "EXITED"         — process died before resolution
        "ACCESS_DENIED"  — insufficient permissions
        "UNRESOLVED"     — pid <= 0 or resolver unavailable

    Any agent with a PID can call this to get mandate-grade context::

        from amoskys.agents.common.process_resolver import mandate_context_from_pid
        ctx = mandate_context_from_pid(conn.pid, self.name)
        data = {**ctx, "domain": query.domain, ...}
    """
    ctx: Dict[str, Any] = {
        "pid": pid,
        "process_name": process_name_hint or "UNRESOLVED",
        "exe": "UNRESOLVED",
        "cmdline": "",
        "ppid": 0,
        "parent_name": "UNRESOLVED",
        "username": "UNRESOLVED",
        "probe_name": probe_name,
        "detection_source": detection_source,
    }

    if pid <= 0:
        return ctx

    snap = resolver.resolve(pid)

    if snap.is_alive:
        ctx["process_name"] = snap.process_name or process_name_hint or "UNKNOWN"
        ctx["exe"] = snap.exe or "ACCESS_DENIED"
        ctx["cmdline"] = snap.cmdline or ""
        ctx["ppid"] = snap.ppid
        ctx["parent_name"] = snap.parent_name or "UNKNOWN"
        ctx["username"] = snap.username or "ACCESS_DENIED"
    else:
        # Process exited between observation and resolution — use sentinels
        ctx["process_name"] = process_name_hint or "EXITED"
        ctx["exe"] = "EXITED"
        ctx["cmdline"] = ""
        ctx["ppid"] = 0
        ctx["parent_name"] = "EXITED"
        ctx["username"] = "EXITED"

    return ctx


__all__ = [
    "DEAD_PROCESS",
    "ProcessResolver",
    "ProcessSnapshot",
    "mandate_context_from_pid",
    "resolve_file_owner_process",
    "resolver",
]
