#!/usr/bin/env python3
"""
AMOSKYS Doctor — the observability + control plane. IGRIS's eyes and hands.

Turns the raw noise of a distributed detection system (local agent + ops fleet)
into a small set of SIGNALS — each with a severity, a plain-English what+why, and
a remediation — and can HEAL the critical ones autonomously.

Design principles (per the AMOSKYS mandate):
  * Noise -> Signal: never dump metrics; emit a ranked verdict.
  * IGRIS supreme: structured --json output + --heal actions = a control surface
    IGRIS drives on a timer, so no human hand-runs probes.
  * Stdlib only: runs as a root LaunchDaemon or via sudo, anywhere, forever.

Usage:
  amoskys_doctor.py                 # human signal report
  amoskys_doctor.py --json          # machine verdict (for IGRIS)
  amoskys_doctor.py --heal          # remediate CRIT signals (asks per action)
  amoskys_doctor.py --heal --auto   # remediate without prompting (IGRIS mode)
  amoskys_doctor.py --watch 60      # loop every 60s
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Callable, Optional

# ── Coordinates ────────────────────────────────────────────────────────────────
DATA = os.getenv("AMOSKYS_DATA", "/var/lib/amoskys/data")
LOGS = os.getenv("AMOSKYS_LOGS", "/var/log/amoskys")
INSTALL = os.getenv("AMOSKYS_HOME", "/Library/Amoskys")
TELEMETRY_DB = f"{DATA}/telemetry.db"
THREAT_DB = os.getenv("AMOSKYS_THREAT_INTEL_DB", f"{DATA}/threat_intel.db")
QUEUE_DIR = f"{DATA}/queue"
ANALYZER_LOG = f"{INSTALL}/logs/analyzer.err.log"
WATCHDOG_PLIST = "/Library/LaunchDaemons/com.amoskys.watchdog.plist"
OPS_HOST = os.getenv("AMOSKYS_OPS_HOST", "18.223.110.15")
OPS_KEY = os.getenv("AMOSKYS_OPS_KEY", os.path.expanduser("~/.ssh/amoskys-deploy"))
FLEET_DB = "/var/lib/amoskys/fleet.db"
DEVICE_ID = os.getenv("AMOSKYS_DEVICE_ID", "b45045f5e1a0c15e")

# ── Thresholds (the line between noise and signal) ─────────────────────────────
STORE_BLOAT_WARN_GB = 5
STORE_BLOAT_CRIT_GB = 15
QUEUE_BACKLOG_WARN_MB = 300
QUEUE_BACKLOG_CRIT_MB = 800
TI_MIN_INDICATORS = 50
STREAM_STALE_MIN = 30

OK, WARN, CRIT = "OK", "WARN", "CRIT"
_RANK = {CRIT: 0, WARN: 1, OK: 2}
_ICON = {OK: "\033[32m✓\033[0m", WARN: "\033[33m▲\033[0m", CRIT: "\033[31m✗\033[0m"}


@dataclass
class Signal:
    level: str
    code: str
    title: str
    detail: str = ""
    remedy: str = ""
    healable: bool = False


# ── Probes: each returns one Signal (raw facts -> meaning) ──────────────────────
def _sh(cmd: list[str], timeout: int = 20) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


def probe_agent() -> Signal:
    procs = [l for l in _sh(["pgrep", "-fl", "amoskys.watchdog"]).splitlines() if l.strip()]
    if not procs:
        return Signal(CRIT, "AGENT_DOWN", "Agent not running",
                      "No amoskys.watchdog process found.",
                      "Restart the watchdog LaunchDaemon.", healable=True)
    return Signal(OK, "AGENT_UP", "Agent running", f"{len(procs)} watchdog processes alive.")


def probe_local_store() -> Signal:
    if not os.path.exists(TELEMETRY_DB):
        return Signal(OK, "STORE_FRESH", "Telemetry store absent (rebuilding)",
                      "No telemetry.db yet — analyzer will recreate it.")
    sz_gb = os.path.getsize(TELEMETRY_DB) / 1e9
    # corruption: cheap header check + recent malformed log lines
    malformed = False
    try:
        c = sqlite3.connect(f"file:{TELEMETRY_DB}?mode=ro", uri=True, timeout=5)
        if c.execute("PRAGMA quick_check(1)").fetchone()[0] != "ok":
            malformed = True
        c.close()
    except sqlite3.DatabaseError:
        malformed = True
    if not malformed and os.path.exists(ANALYZER_LOG):
        tail = _sh(["tail", "-50", ANALYZER_LOG])
        recent = [l for l in tail.splitlines() if "malformed" in l.lower()]
        # only flag if the malformed lines are after the newest analyzer start
        if recent and "starting" not in tail.split(recent[-1])[-1].lower():
            malformed = True
    if malformed:
        return Signal(CRIT, "STORE_CORRUPT", "Telemetry store corrupt",
                      f"telemetry.db ({sz_gb:.1f}GB) is malformed — analyzer cannot write, "
                      "shipping stalls.", "Delete store + restart; queues replay it.",
                      healable=True)
    if sz_gb >= STORE_BLOAT_CRIT_GB:
        return Signal(CRIT, "STORE_BLOAT", "Telemetry store bloated",
                      f"telemetry.db is {sz_gb:.1f}GB (local retention not pruning).",
                      "Compact/rebuild store; fix local retention.", healable=True)
    if sz_gb >= STORE_BLOAT_WARN_GB:
        return Signal(WARN, "STORE_GROWING", "Telemetry store growing",
                      f"telemetry.db is {sz_gb:.1f}GB — watch local retention.")
    return Signal(OK, "STORE_OK", "Telemetry store healthy", f"{sz_gb*1000:.0f}MB, integrity ok.")


def probe_queues() -> Signal:
    if not os.path.isdir(QUEUE_DIR):
        return Signal(WARN, "QUEUE_MISSING", "Queue dir missing", QUEUE_DIR)
    total = sum(os.path.getsize(os.path.join(QUEUE_DIR, f))
                for f in os.listdir(QUEUE_DIR) if f.endswith(".db"))
    mb = total / 1e6
    if mb >= QUEUE_BACKLOG_CRIT_MB:
        return Signal(CRIT, "QUEUE_BACKLOG", "Shipping stalled — queue backlog",
                      f"{mb:.0f}MB unsent across agent queues.",
                      "Diagnose shipper/store; events are safe but not reaching ops.",
                      healable=False)
    if mb >= QUEUE_BACKLOG_WARN_MB:
        return Signal(WARN, "QUEUE_HIGH", "Queue backlog elevated", f"{mb:.0f}MB queued.")
    return Signal(OK, "QUEUE_OK", "Queues draining", f"{mb:.0f}MB queued (normal).")


def probe_threat_intel() -> Signal:
    if not os.path.exists(THREAT_DB):
        return Signal(CRIT, "TI_MISSING", "Threat intel store missing",
                      f"{THREAT_DB} absent — enricher is blind.",
                      "Run threat_intel_autoupdate.py.", healable=True)
    try:
        c = sqlite3.connect(f"file:{THREAT_DB}?mode=ro", uri=True, timeout=5)
        n = c.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
        newest = c.execute("SELECT MAX(added_at) FROM indicators").fetchone()[0]
        c.close()
    except Exception as e:
        return Signal(CRIT, "TI_UNREADABLE", "Threat intel unreadable", str(e),
                      "Rebuild threat intel DB.", healable=True)
    if n == 0:
        return Signal(CRIT, "TI_EMPTY", "Threat intel empty — false-clean risk",
                      "0 indicators: every threat_intel_match returns False.",
                      "Run threat_intel_autoupdate.py.", healable=True)
    stale = ""
    if newest:
        age_d = (time.time() - _iso_epoch(newest)) / 86400
        if age_d > 3:
            stale = f" (stale {age_d:.1f}d)"
    if n < TI_MIN_INDICATORS:
        return Signal(WARN, "TI_THIN", "Threat intel thin", f"{n} indicators{stale}.",
                      "Refresh feeds.", healable=True)
    return Signal(OK, "TI_OK", "Threat intel armed", f"{n} indicators{stale}.")


def probe_ops_fleet() -> list[Signal]:
    if not os.path.exists(OPS_KEY):
        return [Signal(WARN, "OPS_NOKEY", "Ops view unavailable",
                       f"SSH key {OPS_KEY} not found — skipping fleet probe.")]
    script = (
        "import sqlite3,time,json\n"
        f"c=sqlite3.connect('file:{FLEET_DB}?mode=ro',uri=True)\n"
        "now=time.time()\n"
        f"d=c.execute('SELECT status,(?-last_seen)/60.0 FROM devices WHERE device_id=?',(now,'{DEVICE_ID}')).fetchone()\n"
        "out={'dev':d}\n"
        "for t in ('flow_events','dns_events','security_events'):\n"
        f"  r=c.execute('SELECT (?-MAX(received_at))/60.0 FROM '+t+' WHERE device_id=?',(now,'{DEVICE_ID}')).fetchone()\n"
        "  out[t]=r[0]\n"
        "print(json.dumps(out))\n"
    )
    try:
        p = subprocess.run(["ssh", "-i", OPS_KEY, "-o", "BatchMode=yes",
                            "-o", "StrictHostKeyChecking=accept-new",
                            "-o", "ConnectTimeout=10", f"ubuntu@{OPS_HOST}", "python3 -"],
                           input=script, capture_output=True, text=True, timeout=25)
        jlines = [l for l in p.stdout.splitlines() if l.startswith("{")]
        if not jlines:
            err = (p.stderr.strip().splitlines() or ["no output"])[-1]
            return [Signal(WARN, "OPS_UNREACH", "Ops server unreachable", err[:90])]
        data = json.loads(jlines[-1])
    except Exception as e:
        return [Signal(WARN, "OPS_UNREACH", "Ops server unreachable", str(e)[:90])]
    sigs = []
    dev = data.get("dev")
    if not dev:
        sigs.append(Signal(WARN, "OPS_NODEV", "Device not in fleet", DEVICE_ID))
    else:
        status, age = dev[0], dev[1]
        if status != "online":
            sigs.append(Signal(CRIT, "DEVICE_OFFLINE", "Device offline at ops",
                               f"status={status}, last_seen {age:.1f}m ago.",
                               "Check agent shipping/heartbeat.", healable=False))
        else:
            sigs.append(Signal(OK, "DEVICE_ONLINE", "Device online at ops",
                               f"last_seen {age:.1f}m ago."))
    for t in ("flow_events", "dns_events", "security_events"):
        age = data.get(t)
        if age is None:
            sigs.append(Signal(WARN, f"STREAM_DRY_{t}", f"{t} not shipping",
                               "No rows in fleet recently."))
        elif age > STREAM_STALE_MIN:
            sigs.append(Signal(WARN, f"STREAM_STALE_{t}", f"{t} stale",
                               f"newest {age:.0f}m ago."))
        else:
            sigs.append(Signal(OK, f"STREAM_OK_{t}", f"{t} fresh", f"newest {age:.1f}m ago."))
    return sigs


def _iso_epoch(s: str) -> float:
    try:
        from datetime import datetime
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except Exception:
        return time.time()


# ── Heal handlers (control: signal -> action) ──────────────────────────────────
def heal_store(_: Signal) -> str:
    subprocess.run(["launchctl", "bootout", "system", WATCHDOG_PLIST])
    time.sleep(4)
    subprocess.run(["pkill", "-9", "-f", "amoskys.watchdog"])
    for ext in ("", "-wal", "-shm"):
        try:
            os.remove(TELEMETRY_DB + ext)
        except FileNotFoundError:
            pass
    subprocess.run(["launchctl", "bootstrap", "system", WATCHDOG_PLIST])
    return "Stopped agent, removed corrupt/bloated store, restarted (queues will replay)."


def heal_threat_intel(_: Signal) -> str:
    script = f"{INSTALL}/scripts/threat_intel_autoupdate.py"
    if not os.path.exists(script):
        script = os.path.join(os.path.dirname(__file__), "..", "scripts",
                              "threat_intel_autoupdate.py")
    env = dict(os.environ, AMOSKYS_THREAT_INTEL_DB=THREAT_DB)
    r = subprocess.run([sys.executable, script], env=env, capture_output=True, text=True)
    return "Refreshed threat intel feeds. " + (r.stderr.strip().splitlines() or [""])[-1]


def heal_agent(_: Signal) -> str:
    subprocess.run(["launchctl", "bootstrap", "system", WATCHDOG_PLIST])
    return "Bootstrapped watchdog LaunchDaemon."


HEALERS: dict[str, Callable[[Signal], str]] = {
    "STORE_CORRUPT": heal_store, "STORE_BLOAT": heal_store,
    "TI_EMPTY": heal_threat_intel, "TI_MISSING": heal_threat_intel,
    "TI_UNREADABLE": heal_threat_intel, "TI_THIN": heal_threat_intel,
    "AGENT_DOWN": heal_agent,
}


# ── Orchestration ──────────────────────────────────────────────────────────────
def collect() -> list[Signal]:
    sigs = [probe_agent(), probe_local_store(), probe_queues(), probe_threat_intel()]
    sigs += probe_ops_fleet()
    sigs.sort(key=lambda s: _RANK[s.level])
    return sigs


def render_human(sigs: list[Signal]) -> str:
    crit = sum(s.level == CRIT for s in sigs)
    warn = sum(s.level == WARN for s in sigs)
    verdict = ("\033[31mCRITICAL\033[0m" if crit else
               "\033[33mDEGRADED\033[0m" if warn else "\033[32mHEALTHY\033[0m")
    lines = [f"AMOSKYS posture: {verdict}   ({crit} crit, {warn} warn, "
             f"{len(sigs)-crit-warn} ok)", "─" * 64]
    for s in sigs:
        lines.append(f"{_ICON[s.level]} {s.title}")
        if s.detail:
            lines.append(f"    {s.detail}")
        if s.level != OK and s.remedy:
            tag = " [auto-healable]" if s.healable else ""
            lines.append(f"    → {s.remedy}{tag}")
    return "\n".join(lines)


def do_heal(sigs: list[Signal], auto: bool) -> None:
    targets = [s for s in sigs if s.level == CRIT and s.healable and s.code in HEALERS]
    if not targets:
        print("\nNo auto-healable critical signals.")
        return
    for s in targets:
        if not auto:
            ans = input(f"\nHeal '{s.title}' via {HEALERS[s.code].__name__}? [y/N] ")
            if ans.strip().lower() != "y":
                print("  skipped")
                continue
        print(f"  healing {s.code} ...")
        try:
            print("  →", HEALERS[s.code](s))
        except Exception as e:
            print(f"  heal FAILED: {e}")


def main() -> int:
    ap = argparse.ArgumentParser(description="AMOSKYS Doctor — observability + control plane")
    ap.add_argument("--json", action="store_true", help="machine verdict for IGRIS")
    ap.add_argument("--heal", action="store_true", help="remediate critical signals")
    ap.add_argument("--auto", action="store_true", help="heal without prompting")
    ap.add_argument("--watch", type=int, metavar="SEC", help="loop every SEC seconds")
    args = ap.parse_args()

    def once() -> int:
        sigs = collect()
        if args.json:
            crit = sum(s.level == CRIT for s in sigs)
            print(json.dumps({"posture": "CRITICAL" if crit else
                              ("DEGRADED" if any(s.level == WARN for s in sigs) else "HEALTHY"),
                              "signals": [asdict(s) for s in sigs]}))
        else:
            print(render_human(sigs))
        if args.heal:
            do_heal(sigs, args.auto)
        return 1 if any(s.level == CRIT for s in sigs) else 0

    if args.watch:
        while True:
            once()
            if not args.json:
                print(f"\n… next check in {args.watch}s\n")
            time.sleep(args.watch)
    return once()


if __name__ == "__main__":
    sys.exit(main())
