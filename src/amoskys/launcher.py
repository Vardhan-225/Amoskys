"""AMOSKYS Fleet Launcher — orchestrated startup of all platform components.

Usage:
    amoskys-launch start [--agents-only] [--include-dashboard]
    amoskys-launch stop
    amoskys-launch status
    amoskys-launch install    # Install macOS launchd plists
    amoskys-launch uninstall  # Remove macOS launchd plists
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
import time
from pathlib import Path

logger = logging.getLogger("amoskys.launcher")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PID_FILE = PROJECT_ROOT / "data" / "launcher.pids"
LOG_DIR = PROJECT_ROOT / "logs"

# ── Component Definitions ────────────────────────────────────────────────
# (name, module, extra_args, is_infrastructure)
INFRASTRUCTURE = [
    ("eventbus", "amoskys.eventbus.server", []),
    ("wal-processor", "amoskys.storage.wal_processor", []),
]

AGENTS = [
    ("proc-agent", "amoskys.agents.proc", []),
    ("auth-agent", "amoskys.agents.auth", []),
    ("fim-agent", "amoskys.agents.fim", []),
    ("flow-agent", "amoskys.agents.flow", []),
    ("dns-agent", "amoskys.agents.dns", []),
    ("peripheral-agent", "amoskys.agents.peripheral", []),
    ("persistence-agent", "amoskys.agents.persistence", []),
    ("kernel-audit-agent", "amoskys.agents.kernel_audit", []),
    ("protocol-collectors", "amoskys.agents.protocol_collectors", []),
    ("device-discovery", "amoskys.agents.device_discovery", []),
    # L7 Gap-Closure Agents
    ("applog-agent", "amoskys.agents.applog", []),
    ("db-activity-agent", "amoskys.agents.db_activity", []),
    ("http-inspector-agent", "amoskys.agents.http_inspector", []),
    ("internet-activity-agent", "amoskys.agents.internet_activity", []),
    ("net-scanner-agent", "amoskys.agents.net_scanner", []),
]

DASHBOARD = [
    ("dashboard", "web.app", []),
]


# ── Helpers ──────────────────────────────────────────────────────────────


def _ensure_dirs() -> None:
    """Create all required data directories (idempotent)."""
    for d in [
        "data",
        "data/queue",
        "data/intel",
        "data/intel/models",
        "data/igris",
        "data/wal",
        "data/storage",
        "data/heartbeats",
        "logs",
    ]:
        (PROJECT_ROOT / d).mkdir(parents=True, exist_ok=True)


def _build_env() -> dict:
    """Build subprocess environment with PYTHONPATH."""
    env = os.environ.copy()
    src = str(PROJECT_ROOT / "src")
    root = str(PROJECT_ROOT)
    existing = env.get("PYTHONPATH", "")
    paths = [src, root]
    if existing:
        paths.append(existing)
    env["PYTHONPATH"] = ":".join(paths)
    env.setdefault("FLASK_DEBUG", "true")
    env.setdefault("TESTING", "false")
    return env


def _port_open(port: int, host: str = "127.0.0.1") -> bool:
    """Check if a TCP port is accepting connections."""
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def _wait_port(port: int, timeout: float = 15.0) -> bool:
    """Wait for a TCP port to become available."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _port_open(port):
            return True
        time.sleep(0.3)
    return False


def _read_pids() -> dict:
    """Read PID file. Returns {name: pid}."""
    if PID_FILE.exists():
        try:
            return json.loads(PID_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _write_pids(pids: dict) -> None:
    """Write PID file."""
    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(json.dumps(pids, indent=2))


def _pid_alive(pid: int) -> bool:
    """Check if a PID is still running."""
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def _start_component(
    name: str, module: str, extra_args: list, env: dict
) -> subprocess.Popen | None:
    """Start a single component as a subprocess."""
    log_out = LOG_DIR / f"{name}.log"
    log_err = LOG_DIR / f"{name}.err.log"

    cmd = [sys.executable, "-m", module] + extra_args

    try:
        with open(log_out, "a") as fout, open(log_err, "a") as ferr:
            proc = subprocess.Popen(
                cmd,
                cwd=str(PROJECT_ROOT),
                env=env,
                stdout=fout,
                stderr=ferr,
                start_new_session=True,
            )
        logger.info("  [+] %s started (PID %d)", name, proc.pid)
        return proc
    except Exception as e:
        logger.error("  [!] %s failed to start: %s", name, e)
        return None


# ── Actions ──────────────────────────────────────────────────────────────


def do_start(args: argparse.Namespace) -> None:
    """Start platform components in dependency order."""
    _ensure_dirs()
    env = _build_env()
    pids = _read_pids()

    # Check for already-running components
    running = {n for n, p in pids.items() if _pid_alive(p)}
    if running:
        logger.warning("Already running: %s", ", ".join(sorted(running)))
        logger.warning("Run 'amoskys-launch stop' first, or 'amoskys-launch status'.")
        return

    print("AMOSKYS Platform Launcher")
    print("=" * 50)

    new_pids: dict[str, int] = {}

    # 1. Infrastructure
    if not args.agents_only:
        print("\n[1/3] Starting infrastructure...")
        for name, module, extra in INFRASTRUCTURE:
            proc = _start_component(name, module, extra, env)
            if proc:
                new_pids[name] = proc.pid

        # Wait for EventBus to be ready
        if "eventbus" in new_pids:
            print("      Waiting for EventBus (port 50051)...", end=" ", flush=True)
            if _wait_port(50051, timeout=15.0):
                print("ready")
            else:
                print("timeout (agents may retry via circuit breaker)")

    # 2. Agent fleet
    print("\n[2/3] Starting agent fleet...")
    for name, module, extra in AGENTS:
        proc = _start_component(name, module, extra, env)
        if proc:
            new_pids[name] = proc.pid

    # 3. Dashboard (optional)
    if args.include_dashboard:
        print("\n[3/3] Starting dashboard...")
        for name, module, extra in DASHBOARD:
            proc = _start_component(name, module, extra, env)
            if proc:
                new_pids[name] = proc.pid

    _write_pids(new_pids)

    print(f"\n{'=' * 50}")
    print(f"Started {len(new_pids)} components. PIDs saved to {PID_FILE}")
    print("Run 'amoskys-launch status' to check health.")


def do_stop(_args: argparse.Namespace) -> None:
    """Stop all components (reverse order: agents -> WAL -> EventBus)."""
    pids = _read_pids()
    if not pids:
        print("No running components found.")
        return

    print("Stopping AMOSKYS platform...")

    # Reverse order: agents first, then infrastructure
    agent_names = {n for n, _, _ in AGENTS} | {n for n, _, _ in DASHBOARD}
    infra_names = {n for n, _, _ in INFRASTRUCTURE}

    # Stop agents first
    for name, pid in pids.items():
        if name in agent_names and _pid_alive(pid):
            logger.info("  [-] Stopping %s (PID %d)...", name, pid)
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass

    # Brief pause for agents to drain queues
    time.sleep(2)

    # Stop infrastructure
    for name, pid in pids.items():
        if name in infra_names and _pid_alive(pid):
            logger.info("  [-] Stopping %s (PID %d)...", name, pid)
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass

    # Wait for processes to exit
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        still_alive = [n for n, p in pids.items() if _pid_alive(p)]
        if not still_alive:
            break
        time.sleep(0.5)
    else:
        # Force kill any stragglers
        for name, pid in pids.items():
            if _pid_alive(pid):
                logger.warning("  [!] Force-killing %s (PID %d)", name, pid)
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass

    # Clean PID file
    if PID_FILE.exists():
        PID_FILE.unlink()

    print("All components stopped.")


def do_status(_args: argparse.Namespace) -> None:
    """Show status of all components."""
    pids = _read_pids()
    if not pids:
        print("No components registered. Run 'amoskys-launch start' first.")
        return

    print(f"{'Component':<25} {'PID':>7}  {'Status':<10}")
    print("-" * 50)

    alive_count = 0
    for name, pid in pids.items():
        alive = _pid_alive(pid)
        status = "running" if alive else "stopped"
        marker = "[+]" if alive else "[-]"
        print(f"  {marker} {name:<22} {pid:>7}  {status}")
        if alive:
            alive_count += 1

    print("-" * 50)
    print(f"  {alive_count}/{len(pids)} components running")

    # Check key service ports
    print("\nService ports:")
    for label, port in [
        ("EventBus gRPC", 50051),
        ("Dashboard HTTP", 5001),
        ("Prometheus", 9102),
    ]:
        status = "open" if _port_open(port) else "closed"
        marker = "[+]" if status == "open" else "[-]"
        print(f"  {marker} {label:<20} :{port} {status}")

    # Check heartbeats
    hb_dir = PROJECT_ROOT / "data" / "heartbeats"
    if hb_dir.exists():
        hb_files = list(hb_dir.glob("*.json"))
        if hb_files:
            print(f"\nHeartbeats ({len(hb_files)} agents):")
            for hb in sorted(hb_files):
                try:
                    data = json.loads(hb.read_text())
                    agent = data.get("agent_name", hb.stem)
                    ts = data.get("timestamp", "")
                    cycle = data.get("cycle", "?")
                    print(f"  [+] {agent:<20} cycle #{cycle}  {ts}")
                except (json.JSONDecodeError, OSError):
                    print(f"  [?] {hb.stem:<20} (corrupt heartbeat)")


def do_install(_args: argparse.Namespace) -> None:
    """Generate and install macOS launchd plists."""
    launch_agents_dir = Path.home() / "Library" / "LaunchAgents"
    launch_agents_dir.mkdir(parents=True, exist_ok=True)

    python = sys.executable
    cwd = str(PROJECT_ROOT)
    src = str(PROJECT_ROOT / "src")

    services = [
        (
            "com.amoskys.eventbus",
            [python, "-m", "amoskys.eventbus.server"],
        ),
        (
            "com.amoskys.wal-processor",
            [python, "-m", "amoskys.storage.wal_processor"],
        ),
        (
            "com.amoskys.agent-fleet",
            [python, "-m", "amoskys.launcher", "start", "--agents-only"],
        ),
        (
            "com.amoskys.dashboard",
            [python, str(PROJECT_ROOT / "web" / "wsgi.py"), "--dev"],
        ),
    ]

    for label, prog_args in services:
        plist_path = launch_agents_dir / f"{label}.plist"
        args_xml = "\n        ".join(f"<string>{a}</string>" for a in prog_args)
        plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        {args_xml}
    </array>
    <key>WorkingDirectory</key>
    <string>{cwd}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PYTHONPATH</key>
        <string>{src}</string>
    </dict>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{cwd}/logs/{label.split(".")[-1]}.log</string>
    <key>StandardErrorPath</key>
    <string>{cwd}/logs/{label.split(".")[-1]}.err.log</string>
</dict>
</plist>
"""
        plist_path.write_text(plist)
        print(f"  [+] Wrote {plist_path}")

    print(f"\nInstall with:")
    print(f"  launchctl load ~/Library/LaunchAgents/com.amoskys.*.plist")


def do_uninstall(_args: argparse.Namespace) -> None:
    """Unload and remove macOS launchd plists."""
    launch_agents_dir = Path.home() / "Library" / "LaunchAgents"
    removed = 0
    for plist in launch_agents_dir.glob("com.amoskys.*.plist"):
        label = plist.stem
        os.system(f"launchctl unload {plist} 2>/dev/null")
        plist.unlink()
        print(f"  [-] Removed {label}")
        removed += 1

    if removed:
        print(f"\nRemoved {removed} launchd plists.")
    else:
        print("No AMOSKYS launchd plists found.")


# ── Main ─────────────────────────────────────────────────────────────────


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="AMOSKYS Fleet Launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "actions:\n"
            "  start      Start all platform components\n"
            "  stop       Stop all running components\n"
            "  status     Show component status and health\n"
            "  install    Generate macOS launchd plists\n"
            "  uninstall  Remove macOS launchd plists\n"
        ),
    )
    parser.add_argument(
        "action",
        choices=["start", "stop", "status", "install", "uninstall"],
    )
    parser.add_argument(
        "--agents-only",
        action="store_true",
        help="Skip infrastructure (EventBus, WAL processor)",
    )
    parser.add_argument(
        "--include-dashboard",
        action="store_true",
        help="Also start the web dashboard",
    )
    args = parser.parse_args()

    dispatch = {
        "start": do_start,
        "stop": do_stop,
        "status": do_status,
        "install": do_install,
        "uninstall": do_uninstall,
    }
    dispatch[args.action](args)


if __name__ == "__main__":
    main()
