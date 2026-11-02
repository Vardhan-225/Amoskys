#!/usr/bin/env python3
"""Record, per worker, whether the running process predates the code on disk.

WHY THIS IS NOT A SHELL LOOP ANY MORE
-------------------------------------
The supervisor's original check_stale_code() compared each worker's start time
against a stamp file, and touched that stamp at the end of every pass:

    newest=$(find src -name '*.py' -newer "$STALE_STAMP" -print -quit)
    [ -z "$newest" ] && return 0
    ...
    touch "$STALE_STAMP"

So a worker was reported stale only during the window between a source edit and
the next pass. After the stamp moved forward, `find -newer` matched nothing, the
function returned early, and a process that was STILL running old code went
quiet. Staleness is a persistent condition and the check was edge-triggered --
it answered "did the source change recently" while appearing to answer "is this
worker current". On 2026-08-30 the ESF collector had been stale for ~23 hours
and the last warning about it was hours old.

The comparison here is against the newest SOURCE MTIME itself, which stays true
for as long as the condition does.

WHAT COUNTS AS SOURCE
---------------------
Not just src/**/*.py. The Sentinel is a compiled Swift binary, and a rebuilt
binary that was never reloaded is the same failure wearing different clothes --
the ESF tier has now been caught with both. The compiled artifact is checked by
its own mtime, because for a compiled component the binary IS the deployed code.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Worker -> the source that, if newer than the process, makes it stale.
# The Sentinel is deliberately absent: it is a separate long-lived daemon whose
# staleness is a compiled-artifact question, handled by SENTINEL_BINARY below.
WORKERS = {
    "amoskys.collector_main": ("src",),
    "amoskys.analyzer_main": ("src",),
    "amoskys.shipper": ("src",),
    "amoskys.agents.os.macos.esf": ("src",),
    # IGRIS supervises the other workers; nothing was supervising IT.
    "amoskys.igris.cli": ("src",),
}
SENTINEL_PROC = "amoskys-sentinel"
SENTINEL_BINARY = REPO / "macos-esf-shim/AmoskysSentinel.app/Contents/MacOS/amoskys-sentinel"

NS = 1_000_000_000


def newest_python_mtime() -> float:
    """Newest mtime across the tracked Python trees.

    Walks rather than globs so a new package directory is covered the day it is
    added -- a glob pattern that has to be maintained is one more thing that can
    silently stop matching.
    """
    newest = 0.0
    for root, dirs, files in os.walk(REPO / "src"):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for f in files:
            if f.endswith(".py"):
                try:
                    newest = max(newest, os.path.getmtime(os.path.join(root, f)))
                except OSError:
                    continue
    return newest


def pid_of(pattern: str) -> int | None:
    """Resolve a worker's pid, excluding this process and its own shell.

    pgrep -f matches any command line CONTAINING the pattern, which includes a
    shell that merely mentions it. That is not hypothetical: it previously left
    the supervisor believing all four workers were alive for 32 minutes while
    the machine had no sensors at all.
    """
    try:
        out = subprocess.run(
            ["pgrep", "-f", pattern], capture_output=True, text=True, timeout=10
        ).stdout.split()
    except Exception:
        return None
    me = {os.getpid(), os.getppid()}
    for raw in out:
        try:
            pid = int(raw)
        except ValueError:
            continue
        if pid in me:
            continue
        try:
            cmd = subprocess.run(
                ["ps", "-o", "command=", "-p", str(pid)],
                capture_output=True, text=True, timeout=10,
            ).stdout.strip()
        except Exception:
            continue
        # A real worker is launched as `python -m <module>`; a shell that merely
        # names it is not. Requiring the -m form is what separates them.
        if f"-m {pattern}" in cmd or cmd.endswith(pattern) or pattern == SENTINEL_PROC:
            return pid
    return None


def started_epoch(pid: int) -> float | None:
    try:
        out = subprocess.run(
            ["ps", "-o", "lstart=", "-p", str(pid)],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip()
        if not out:
            return None
        stamp = subprocess.run(
            ["date", "-j", "-f", "%a %b %d %T %Y", out, "+%s"],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip()
        return float(stamp) if stamp else None
    except Exception:
        return None


def collect() -> list[dict]:
    py_mtime = newest_python_mtime()
    try:
        sentinel_mtime = os.path.getmtime(SENTINEL_BINARY)
    except OSError:
        sentinel_mtime = 0.0

    rows = []
    targets = [(w, py_mtime) for w in WORKERS] + [(SENTINEL_PROC, sentinel_mtime)]
    for worker, source_mtime in targets:
        pid = pid_of(worker)
        started = started_epoch(pid) if pid else None
        # NOT RUNNING is a third state. A boolean would have collapsed it into
        # "not stale", which reads as healthy for a worker that is simply gone.
        if pid is None or started is None or source_mtime <= 0:
            rows.append({
                "worker": worker, "pid": pid,
                "started_ns": int(started * NS) if started else None,
                "newest_source_ns": int(source_mtime * NS) if source_mtime else None,
                "is_stale": 0, "stale_seconds": None,
            })
            continue
        stale = started < source_mtime
        rows.append({
            "worker": worker, "pid": pid,
            "started_ns": int(started * NS),
            "newest_source_ns": int(source_mtime * NS),
            "is_stale": 1 if stale else 0,
            "stale_seconds": int(source_mtime - started) if stale else None,
        })
    return rows


def main() -> int:
    sys.path.insert(0, str(REPO / "src"))
    rows = collect()
    now_ns = time.time_ns()
    try:
        from amoskys.storage.telemetry_store import TelemetryStore
        store = TelemetryStore()
        store._executemany(
            "INSERT INTO worker_code_health "
            "(observed_at_ns, worker, pid, started_ns, newest_source_ns, is_stale, stale_seconds) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(now_ns, r["worker"], r["pid"], r["started_ns"], r["newest_source_ns"],
              r["is_stale"], r["stale_seconds"]) for r in rows],
        )
        store._commit()
    except Exception as exc:  # noqa: BLE001
        # Never let health recording take down the supervisor. But say so on
        # stderr rather than swallowing it -- a health writer that fails
        # silently is the exact failure this whole file exists to end.
        print(f"worker_code_health write failed: {exc}", file=sys.stderr)

    for r in rows:
        if r["is_stale"]:
            hrs = (r["stale_seconds"] or 0) / 3600.0
            print(f"STALE CODE: {r['worker']} (pid {r['pid']}) is {hrs:.1f}h behind "
                  f"the source on disk. It will behave like the old build — silently. "
                  f"Restart it.")
        elif r["pid"] is None:
            print(f"NOT RUNNING: {r['worker']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
