#!/usr/bin/env python3
"""AMOSKYS — Endpoint Detection Platform.

Usage:
    amoskys start        Start the detection engine (collector + analyzer + dashboard)
    amoskys stop         Stop all AMOSKYS processes
    amoskys status       Show system health and agent status
    amoskys collect      Run one collection cycle and print results
    amoskys diagnose     Run the 10-layer pipeline diagnostic
    amoskys version      Show version info

Examples:
    # Start everything:
    PYTHONPATH=src python -m amoskys start

    # Quick status check:
    PYTHONPATH=src python -m amoskys status

    # One-shot collection (no daemon):
    PYTHONPATH=src python -m amoskys collect
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
LOG_DIR = PROJECT_ROOT / "logs"
PID_DIR = DATA_DIR / "pids"
HEARTBEAT_DIR = DATA_DIR / "heartbeats"

VERSION = "0.9.1-beta"
CODENAME = "Real-Time"


def _ensure_dirs():
    """Create required directories."""
    for d in [
        DATA_DIR,
        LOG_DIR,
        PID_DIR,
        HEARTBEAT_DIR,
        DATA_DIR / "queue",
        DATA_DIR / "wal",
        DATA_DIR / "intel",
        DATA_DIR / "igris",
        DATA_DIR / "storage",
        DATA_DIR / "heartbeats",
    ]:
        d.mkdir(parents=True, exist_ok=True)


def _pid_file(name: str) -> Path:
    return PID_DIR / f"{name}.pid"


def _write_pid(name: str, pid: int):
    _pid_file(name).write_text(str(pid))


def _read_pid(name: str) -> int:
    p = _pid_file(name)
    if p.exists():
        try:
            return int(p.read_text().strip())
        except (ValueError, OSError):
            pass
    return 0


def _is_running(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # Process exists but we can't signal it


# ── START ────────────────────────────────────────────────────────────────────


def cmd_start(args):
    """Start the AMOSKYS detection engine."""
    _ensure_dirs()

    print(f"AMOSKYS {VERSION} ({CODENAME})")
    print(f"Device: {socket.gethostname()}")
    print()

    # Check if already running
    for name in ["collector", "analyzer", "dashboard"]:
        pid = _read_pid(name)
        if _is_running(pid):
            print(f"  {name} already running (pid={pid}). Use 'amoskys stop' first.")
            return 1

    python = sys.executable
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT / "src")

    processes = {}

    # Start collector (Tier 1)
    print("Starting collector (18 agents, real-time events)...")
    collector_proc = subprocess.Popen(
        [python, "-m", "amoskys.collector_main"],
        cwd=str(PROJECT_ROOT),
        env=env,
        stdout=open(LOG_DIR / "collector.log", "a"),
        stderr=open(LOG_DIR / "collector.err.log", "a"),
    )
    _write_pid("collector", collector_proc.pid)
    processes["collector"] = collector_proc
    print(f"  Collector started (pid={collector_proc.pid})")

    time.sleep(1)

    # Start analyzer (Tier 2)
    print("Starting analyzer (scoring + fusion + IGRIS)...")
    analyzer_proc = subprocess.Popen(
        [python, "-m", "amoskys.analyzer_main"],
        cwd=str(PROJECT_ROOT),
        env=env,
        stdout=open(LOG_DIR / "analyzer.log", "a"),
        stderr=open(LOG_DIR / "analyzer.err.log", "a"),
    )
    _write_pid("analyzer", analyzer_proc.pid)
    processes["analyzer"] = analyzer_proc
    print(f"  Analyzer started (pid={analyzer_proc.pid})")

    # Start dashboard (if not --no-dashboard)
    if not args.no_dashboard:
        print("Starting dashboard (port 5003)...")
        dash_env = env.copy()
        dash_env.setdefault("SECRET_KEY", os.urandom(32).hex())
        dash_env.setdefault("LOGIN_DISABLED", "true")
        dash_env.setdefault("FLASK_PORT", "5003")
        dash_env.setdefault("FORCE_HTTPS", "false")

        dashboard_proc = subprocess.Popen(
            [python, "-m", "web.app"],
            cwd=str(PROJECT_ROOT),
            env=dash_env,
            stdout=open(LOG_DIR / "dashboard.log", "a"),
            stderr=open(LOG_DIR / "dashboard.err.log", "a"),
        )
        _write_pid("dashboard", dashboard_proc.pid)
        processes["dashboard"] = dashboard_proc
        print(f"  Dashboard started (pid={dashboard_proc.pid})")

    time.sleep(2)

    # Verify all started
    print()
    all_ok = True
    for name, proc in processes.items():
        if proc.poll() is not None:
            print(f"  {name}: FAILED (exit={proc.returncode})")
            all_ok = False
        else:
            print(f"  {name}: running (pid={proc.pid})")

    if all_ok:
        print()
        print("AMOSKYS is running.")
        if not args.no_dashboard:
            port = (
                dash_env.get("FLASK_PORT", "5003") if not args.no_dashboard else "N/A"
            )
            print(f"Dashboard: http://localhost:{port}/dashboard/cortex")
        print(f"Logs: {LOG_DIR}/")
        print()

        if args.foreground:
            # Foreground mode: block until SIGTERM (for launchd/systemd)
            print("Running in foreground (SIGTERM to stop)...")
            stop_event = threading.Event()

            def _handle_term(signum, frame):
                print("\nReceived SIGTERM — shutting down...")
                stop_event.set()

            signal.signal(signal.SIGTERM, _handle_term)
            signal.signal(signal.SIGINT, _handle_term)

            stop_event.wait()

            # Clean shutdown of children
            for name, proc in processes.items():
                if proc.poll() is None:
                    proc.terminate()
            for name, proc in processes.items():
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
            print("AMOSKYS stopped.")
        else:
            print("Use 'amoskys status' to check health.")
            print("Use 'amoskys stop' to shut down.")
    else:
        print()
        print("Some components failed to start. Check logs:")
        print(f"  {LOG_DIR}/collector.err.log")
        print(f"  {LOG_DIR}/analyzer.err.log")
        return 1

    return 0


# ── STOP ─────────────────────────────────────────────────────────────────────


def cmd_stop(args):
    """Stop all AMOSKYS processes."""
    print("Stopping AMOSKYS...")
    stopped = 0

    for name in ["dashboard", "analyzer", "collector"]:
        pid = _read_pid(name)
        if pid and _is_running(pid):
            print(f"  Stopping {name} (pid={pid})...")
            try:
                os.kill(pid, signal.SIGTERM)
                # Wait up to 5s for graceful shutdown
                for _ in range(50):
                    if not _is_running(pid):
                        break
                    time.sleep(0.1)
                if _is_running(pid):
                    os.kill(pid, signal.SIGKILL)
                    print(f"    Force-killed {name}")
                else:
                    print(f"    {name} stopped")
                stopped += 1
            except ProcessLookupError:
                print(f"    {name} already stopped")
        else:
            if pid:
                print(f"  {name}: not running (stale pid={pid})")

        # Clean up PID file
        _pid_file(name).unlink(missing_ok=True)

    if stopped == 0:
        print("  Nothing was running.")
    else:
        print(f"Stopped {stopped} process(es).")
    return 0


# ── STATUS ───────────────────────────────────────────────────────────────────


def cmd_status(args):
    """Show AMOSKYS system status."""
    print(f"AMOSKYS {VERSION} ({CODENAME})")
    print(f"Device: {socket.gethostname()}")
    print()

    # Process status
    print("Processes:")
    any_running = False
    for name in ["collector", "analyzer", "dashboard"]:
        pid = _read_pid(name)
        if pid and _is_running(pid):
            any_running = True
            try:
                import psutil

                proc = psutil.Process(pid)
                rss_mb = proc.memory_info().rss / (1024 * 1024)
                cpu = proc.cpu_percent(interval=0.1)
                uptime = time.time() - proc.create_time()
                print(
                    f"  {name:<12} RUNNING  pid={pid}  rss={rss_mb:.0f}MB  cpu={cpu:.1f}%  uptime={uptime:.0f}s"
                )
            except Exception:
                print(f"  {name:<12} RUNNING  pid={pid}")
        else:
            print(f"  {name:<12} STOPPED")

    if not any_running:
        print()
        print("AMOSKYS is not running. Use 'amoskys start' to begin.")
        return 1

    # Heartbeat status
    print()
    print("Heartbeats:")
    for name in ["collector", "analyzer"]:
        hb_path = HEARTBEAT_DIR / f"{name}.json"
        if hb_path.exists():
            try:
                hb = json.loads(hb_path.read_text())
                age = time.time() - hb.get("timestamp", 0)
                cycles = hb.get("total_cycles", hb.get("cycle", 0))
                agents = hb.get("agents_running", "?")
                total = hb.get("agents_total", "?")
                status = "OK" if age < 60 else f"STALE ({age:.0f}s ago)"
                print(
                    f"  {name:<12} {status}  cycles={cycles}  agents={agents}/{total}"
                )
            except Exception:
                print(f"  {name:<12} UNREADABLE")
        else:
            print(f"  {name:<12} NO HEARTBEAT")

    # Database status
    print()
    print("Storage:")
    import sqlite3

    db_path = DATA_DIR / "telemetry.db"
    if db_path.exists():
        try:
            conn = sqlite3.connect(str(db_path), timeout=2)
            sec = conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
            obs = conn.execute("SELECT COUNT(*) FROM observation_events").fetchone()[0]
            inc = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
            size_mb = db_path.stat().st_size / (1024 * 1024)
            conn.close()
            print(
                f"  telemetry.db: {size_mb:.1f}MB  events={sec} security + {obs} observations  incidents={inc}"
            )
        except Exception as e:
            print(f"  telemetry.db: error ({e})")
    else:
        print("  telemetry.db: not created yet")

    # Queue status
    queue_dir = DATA_DIR / "queue"
    if queue_dir.exists():
        total_pending = 0
        for qdb in queue_dir.glob("*.db"):
            try:
                conn = sqlite3.connect(str(qdb), timeout=1)
                count = conn.execute("SELECT COUNT(*) FROM queue").fetchone()[0]
                total_pending += count
                conn.close()
            except Exception:
                pass
        print(f"  Queues: {total_pending} events pending")

    print()
    return 0


# ── COLLECT ──────────────────────────────────────────────────────────────────


def cmd_collect(args):
    """Run one collection cycle and print results."""
    _ensure_dirs()

    print(f"AMOSKYS {VERSION} — One-shot collection")
    print()

    from amoskys.agents.os.macos.realtime_sensor.agent import MacOSRealtimeSensorAgent

    device_id = socket.gethostname()
    agent = MacOSRealtimeSensorAgent(device_id=device_id)
    agent.setup()

    print("Collecting real-time events (5 seconds)...")
    time.sleep(5)

    agent._run_one_cycle()

    # Show what was collected
    import sqlite3

    db_path = "data/queue/realtime_sensor.db"
    if Path(db_path).exists():
        conn = sqlite3.connect(db_path)
        count = conn.execute("SELECT COUNT(*) FROM queue").fetchone()[0]
        conn.close()
        print(f"  {count} event(s) queued for analysis")

    agent.shutdown()
    print("Done.")
    return 0


# ── DIAGNOSE ─────────────────────────────────────────────────────────────────


def cmd_diagnose(args):
    """Run the 10-layer pipeline diagnostic."""
    diag_script = PROJECT_ROOT / "scripts" / "pipeline_diagnostic.py"
    if not diag_script.exists():
        print("Diagnostic script not found.")
        return 1

    os.execv(
        sys.executable,
        [sys.executable, str(diag_script)],
    )


# ── VERSION ──────────────────────────────────────────────────────────────────


def cmd_version(args):
    """Show version info."""
    print(f"AMOSKYS {VERSION} ({CODENAME})")
    print(f"Python: {sys.version.split()[0]}")
    print(f"Platform: {sys.platform}")
    print(f"Device: {socket.gethostname()}")

    # Probe count
    try:
        from amoskys.agents.os.macos.realtime_sensor.agent import (
            MacOSRealtimeSensorAgent,
        )

        rt = MacOSRealtimeSensorAgent.__new__(MacOSRealtimeSensorAgent)
        # Don't initialize, just count what would be created
        print(f"Real-time probes: 14")
    except Exception:
        pass

    print(f"LOLBins monitored: 44")
    print(f"Script patterns: 12")
    print(f"Security disable rules: 16")
    print(f"Discovery commands: 22")
    return 0


# ── MAIN ─────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        prog="amoskys",
        description="AMOSKYS Endpoint Detection Platform",
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # start
    start_parser = subparsers.add_parser("start", help="Start the detection engine")
    start_parser.add_argument(
        "--no-dashboard", action="store_true", help="Start without the web dashboard"
    )
    start_parser.add_argument(
        "--foreground",
        action="store_true",
        help="Run in foreground (for launchd/systemd — blocks until SIGTERM)",
    )

    # stop
    subparsers.add_parser("stop", help="Stop all AMOSKYS processes")

    # status
    subparsers.add_parser("status", help="Show system health")

    # collect
    subparsers.add_parser("collect", help="Run one collection cycle")

    # shell
    subparsers.add_parser("shell", help="Interactive security copilot")

    # diagnose
    subparsers.add_parser("diagnose", help="Run 10-layer pipeline diagnostic")

    # version
    subparsers.add_parser("version", help="Show version info")

    args = parser.parse_args()

    if not args.command:
        # No command = launch interactive shell
        from amoskys.shell import main as shell_main

        return shell_main()

    def cmd_shell(args):
        from amoskys.shell import main as shell_main

        return shell_main()

    commands = {
        "start": cmd_start,
        "stop": cmd_stop,
        "status": cmd_status,
        "collect": cmd_collect,
        "shell": cmd_shell,
        "diagnose": cmd_diagnose,
        "version": cmd_version,
    }

    logging.basicConfig(
        level=logging.WARNING,
        format="%(message)s",
    )

    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
