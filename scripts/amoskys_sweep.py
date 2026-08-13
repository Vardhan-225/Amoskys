#!/usr/bin/env python3
"""Sweep orphaned AMOSKYS agent processes (ppid == 1).

Why this exists
---------------
Orphaning here is chronic, not transient. Agents are spawned with
``start_new_session=True`` (launcher.py:464) and ``preexec_fn=os.setsid``
(agent_control.py:141), so they survive their parent and are reparented to
init. Twelve such processes were observed running simultaneously, all writing
to the queue DBs and the telemetry store.

Worse, they are self-perpetuating: the supervisor gates restart on
``pgrep -f 'amoskys.collector_main'`` (amoskys_live_supervisor.sh), and a
cmdline match cannot tell "my child" from "a ghost" — so a live orphan actively
SUPPRESSES the restart of a healthy child. Sweeping is therefore a precondition
for any measurement or any lifecycle change, not just tidying.

Safety
------
- Dry-run by default. ``--apply`` is required to signal anything.
- Only touches processes whose ppid is exactly 1 AND whose argv matches an
  AMOSKYS agent/limb module. A supervised child (ppid != 1) is never touched.
- Never signals its own process, its parent, or a process group leader that
  still has a live parent.
- SIGTERM first, then SIGKILL only after a grace period, so an agent gets the
  chance to flush its queue and close SQLite cleanly.
"""

from __future__ import annotations

import argparse
import os
import re
import signal
import subprocess
import sys
import time

# Matches the module paths agents are actually exec'd with, e.g.
#   python -m amoskys.agents.os.macos.process
#   python -m amoskys.limb.discovery
_AGENT_ARGV = re.compile(r"amoskys\.(agents\.|limb\b)")

GRACE_SECONDS = 5.0


def _iter_processes():
    """Yield (pid, ppid, command) for every process, via ps."""
    out = subprocess.run(
        ["ps", "-eo", "pid=,ppid=,command="],
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout
    for line in out.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) < 3:
            continue
        try:
            yield int(parts[0]), int(parts[1]), parts[2]
        except ValueError:
            continue


def find_orphans() -> list[tuple[int, str]]:
    me, parent = os.getpid(), os.getppid()
    found = []
    for pid, ppid, cmd in _iter_processes():
        if ppid != 1:
            continue  # supervised — not ours to kill
        if pid in (me, parent):
            continue
        if not _AGENT_ARGV.search(cmd):
            continue
        found.append((pid, cmd))
    return found


def sweep(apply: bool) -> int:
    orphans = find_orphans()
    if not orphans:
        print("No orphaned AMOSKYS agents (ppid=1). Nothing to do.")
        return 0

    print(f"Found {len(orphans)} orphaned AMOSKYS agent process(es):")
    for pid, cmd in orphans:
        short = cmd.split("amoskys.")[-1][:60] if "amoskys." in cmd else cmd[:60]
        print(f"  pid {pid:<8} {short}")

    if not apply:
        print("\nDry run. Re-run with --apply to terminate these.")
        return 0

    for pid, _ in orphans:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except PermissionError:
            print(f"  pid {pid}: permission denied (owned by another user?)")

    print(f"\nSIGTERM sent; waiting {GRACE_SECONDS:.0f}s for clean shutdown...")
    time.sleep(GRACE_SECONDS)

    survivors = [pid for pid, _ in orphans if _alive(pid)]
    for pid in survivors:
        try:
            os.kill(pid, signal.SIGKILL)
            print(f"  pid {pid}: did not exit on SIGTERM — SIGKILLed")
        except ProcessLookupError:
            pass

    time.sleep(1.0)
    remaining = len(find_orphans())
    print(f"\nSwept. Orphans remaining: {remaining}")
    return 0 if remaining == 0 else 1


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--apply",
        action="store_true",
        help="actually signal the orphans (default is a dry run)",
    )
    args = ap.parse_args()
    return sweep(args.apply)


if __name__ == "__main__":
    sys.exit(main())
