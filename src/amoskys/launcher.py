"""AMOSKYS Fleet Launcher — orchestrated startup of every platform component.

Handles environment setup, preflight validation, dependency-ordered startup,
health verification, graceful shutdown, and one-shot data collection.

Usage:
    amoskys-launch start   [--include-dashboard] [--agents-only] [--skip-preflight]
    amoskys-launch stop
    amoskys-launch restart [--include-dashboard]
    amoskys-launch status  [--verbose]
    amoskys-launch health
    amoskys-launch collect [--clear] [--agents N]
    amoskys-launch install     # macOS launchd plists
    amoskys-launch uninstall
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("amoskys.launcher")

# ── Paths ───────────────────────────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
LOG_DIR = PROJECT_ROOT / "logs"
PID_FILE = DATA_DIR / "launcher.pids"
CERTS_DIR = PROJECT_ROOT / "certs"
GEOIP_DIR = DATA_DIR / "geoip"
_GEOIP_CITY_NAME = "GeoLite2-City.mmdb"
_GEOIP_ASN_NAME = "GeoLite2-ASN.mmdb"
GEOIP_CITY = GEOIP_DIR / _GEOIP_CITY_NAME
GEOIP_ASN = GEOIP_DIR / _GEOIP_ASN_NAME
DB_PATH = DATA_DIR / "telemetry.db"

PLATFORM = sys.platform  # "darwin", "linux", "win32"

# ── Required Directories ────────────────────────────────────────────────────

REQUIRED_DIRS = [
    "data",
    "data/queue",
    "data/intel",
    "data/intel/models",
    "data/igris",
    "data/wal",
    "data/storage",
    "data/heartbeats",
    "data/geoip",
    "logs",
]

# ── Ports ───────────────────────────────────────────────────────────────────

PORT_EVENTBUS = int(os.environ.get("BUS_SERVER_PORT", "50051"))
PORT_DASHBOARD = int(os.environ.get("FLASK_PORT", "5003"))
PORT_PROMETHEUS = 9102

# ── Component Registry ──────────────────────────────────────────────────────
# Each entry: (name, module, extra_args, platform, category, wait_port)
# platform: "all" | "darwin" | "linux"
# category: "infra" | "agent" | "dashboard"
# wait_port: port number to wait for after start, or None

ComponentDef = Tuple[str, str, List[str], str, str, Optional[int]]

INFRASTRUCTURE: List[ComponentDef] = [
    ("eventbus", "amoskys.eventbus.server", [], "all", "infra", PORT_EVENTBUS),
    ("wal-processor", "amoskys.storage.wal_processor", [], "all", "infra", None),
]

# ── Agent Registry: Platform-specific routing ─────────────────────────────
# On macOS (darwin): use Observatory agents directly for full observability.
# On Linux/Windows: fall back to shared cross-platform agents.

if PLATFORM == "darwin":
    # macOS Observatory agents — purpose-built collectors with full raw
    # telemetry emission and platform-specific probes.
    CORE_AGENTS: List[ComponentDef] = [
        ("proc-agent", "amoskys.agents.os.macos.process", [], "darwin", "agent", None),
        ("auth-agent", "amoskys.agents.os.macos.auth", [], "darwin", "agent", None),
        (
            "fim-agent",
            "amoskys.agents.os.macos.filesystem",
            [],
            "darwin",
            "agent",
            None,
        ),
        ("flow-agent", "amoskys.agents.os.macos.network", [], "darwin", "agent", None),
        ("dns-agent", "amoskys.agents.os.macos.dns", [], "darwin", "agent", None),
        (
            "peripheral-agent",
            "amoskys.agents.os.macos.peripheral",
            [],
            "darwin",
            "agent",
            None,
        ),
        (
            "persistence-agent",
            "amoskys.agents.os.macos.persistence",
            [],
            "darwin",
            "agent",
            None,
        ),
    ]

    EXTENDED_AGENTS: List[ComponentDef] = [
        ("applog-agent", "amoskys.agents.os.macos.applog", [], "darwin", "agent", None),
        (
            "db-activity-agent",
            "amoskys.agents.os.macos.db_activity",
            [],
            "darwin",
            "agent",
            None,
        ),
        (
            "http-inspector-agent",
            "amoskys.agents.os.macos.http_inspector",
            [],
            "darwin",
            "agent",
            None,
        ),
        (
            "internet-activity-agent",
            "amoskys.agents.os.macos.internet_activity",
            [],
            "darwin",
            "agent",
            None,
        ),
        (
            "discovery-agent",
            "amoskys.agents.os.macos.discovery",
            [],
            "darwin",
            "agent",
            None,
        ),
        (
            "security-monitor-agent",
            "amoskys.agents.os.macos.security_monitor",
            [],
            "darwin",
            "agent",
            None,
        ),
        (
            "unified-log-agent",
            "amoskys.agents.os.macos.unified_log",
            [],
            "darwin",
            "agent",
            None,
        ),
    ]
else:
    # TODO: Linux/Windows support via Igris multi-platform engine (future)
    # For now, fallback to macOS agents — they use psutil which works on Linux too.
    # Full Linux-native agents will be built when Igris is implemented.
    CORE_AGENTS: List[ComponentDef] = [
        ("proc-agent", "amoskys.agents.os.macos.process", [], "all", "agent", None),
        ("auth-agent", "amoskys.agents.os.macos.auth", [], "all", "agent", None),
        ("fim-agent", "amoskys.agents.os.macos.filesystem", [], "all", "agent", None),
        ("flow-agent", "amoskys.agents.os.macos.network", [], "all", "agent", None),
        ("dns-agent", "amoskys.agents.os.macos.dns", [], "all", "agent", None),
        (
            "peripheral-agent",
            "amoskys.agents.os.macos.peripheral",
            [],
            "all",
            "agent",
            None,
        ),
        (
            "persistence-agent",
            "amoskys.agents.os.macos.persistence",
            [],
            "all",
            "agent",
            None,
        ),
    ]

    EXTENDED_AGENTS: List[ComponentDef] = [
        ("applog-agent", "amoskys.agents.os.macos.applog", [], "all", "agent", None),
        (
            "db-activity-agent",
            "amoskys.agents.os.macos.db_activity",
            [],
            "all",
            "agent",
            None,
        ),
        (
            "http-inspector-agent",
            "amoskys.agents.os.macos.http_inspector",
            [],
            "all",
            "agent",
            None,
        ),
        (
            "internet-activity-agent",
            "amoskys.agents.os.macos.internet_activity",
            [],
            "all",
            "agent",
            None,
        ),
        (
            "discovery-agent",
            "amoskys.agents.os.macos.discovery",
            [],
            "all",
            "agent",
            None,
        ),
        (
            "protocol-collectors",
            "amoskys.agents.os.macos.protocol_collectors",
            [],
            "all",
            "agent",
            None,
        ),
    ]

PLATFORM_AGENTS: List[ComponentDef] = [
    # Linux-only
    (
        "kernel-audit-agent",
        "amoskys.agents.os.linux.kernel_audit",
        [],
        "linux",
        "agent",
        None,
    ),
]

DASHBOARD_COMPONENTS: List[ComponentDef] = [
    ("dashboard", "web.app", [], "all", "dashboard", PORT_DASHBOARD),
]


def _get_platform_agents() -> List[ComponentDef]:
    """Return agent list filtered for current platform."""
    all_components = CORE_AGENTS + EXTENDED_AGENTS + PLATFORM_AGENTS
    return [c for c in all_components if c[3] in ("all", PLATFORM)]


# ── Environment Setup ───────────────────────────────────────────────────────


def _ensure_dirs() -> None:
    """Create all required data/log directories (idempotent)."""
    for d in REQUIRED_DIRS:
        (PROJECT_ROOT / d).mkdir(parents=True, exist_ok=True)


def _build_env() -> dict:
    """Build subprocess environment with correct PYTHONPATH and defaults."""
    env = os.environ.copy()
    src = str(PROJECT_ROOT / "src")
    root = str(PROJECT_ROOT)
    web = str(PROJECT_ROOT / "web")
    existing = env.get("PYTHONPATH", "")

    # src for amoskys.*, root for scripts, web for dashboard imports
    paths = [src, root, web]
    if existing:
        paths.append(existing)
    env["PYTHONPATH"] = os.pathsep.join(paths)

    # Sensible defaults
    env.setdefault("FLASK_DEBUG", "true")
    env.setdefault("FLASK_PORT", str(PORT_DASHBOARD))
    env.setdefault("TESTING", "false")
    env.setdefault("EVENTBUS_ALLOW_UNSIGNED", "true")
    env.setdefault("EVENTBUS_REQUIRE_CLIENT_AUTH", "false")

    return env


# ── Preflight Checks ───────────────────────────────────────────────────────


def _check_python() -> Tuple[bool, str]:
    """Verify Python version >= 3.11."""
    v = sys.version_info
    ok = v >= (3, 11)
    msg = f"Python {v.major}.{v.minor}.{v.micro}"
    return ok, msg


def _check_packages() -> Tuple[bool, str]:
    """Check critical Python packages are importable."""
    missing = []
    for pkg in ["flask", "psutil", "google.protobuf"]:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        return False, f"Missing: {', '.join(missing)}"
    return True, "All critical packages available"


def _check_directories() -> Tuple[bool, str]:
    """Check data directories exist (create them if not)."""
    _ensure_dirs()
    return True, f"{len(REQUIRED_DIRS)} directories verified"


def _check_geoip() -> Tuple[bool, str]:
    """Check GeoIP databases exist for enrichment."""
    if GEOIP_CITY.exists() and GEOIP_ASN.exists():
        return True, "GeoIP City + ASN databases found"
    missing = [
        n
        for n, p in [(_GEOIP_CITY_NAME, GEOIP_CITY), (_GEOIP_ASN_NAME, GEOIP_ASN)]
        if not p.exists()
    ]
    return False, f"Missing: {', '.join(missing)} in data/geoip/"


def _check_certs() -> Tuple[bool, str]:
    """Check TLS certificates for EventBus."""
    required = ["server.crt", "server.key", "ca.crt", "agent.ed25519"]
    missing = [f for f in required if not (CERTS_DIR / f).exists()]
    if not missing:
        return True, f"All {len(required)} certificate files present"
    return False, f"Missing: {', '.join(missing)} in certs/"


def _check_ports() -> Tuple[bool, str]:
    """Check required ports are available."""
    in_use = []
    for label, port in [
        ("EventBus", PORT_EVENTBUS),
        ("Dashboard", PORT_DASHBOARD),
    ]:
        if _port_open(port):
            in_use.append(f"{label}:{port}")
    if in_use:
        return False, f"Ports in use: {', '.join(in_use)}"
    return True, "All required ports available"


def _check_stale_pids() -> Tuple[bool, str]:
    """Check for stale PID file from previous run."""
    pids = _read_pids()
    if not pids:
        return True, "No stale processes"
    alive = [n for n, p in pids.items() if _pid_alive(p)]
    if alive:
        return False, f"Still running: {', '.join(alive)} (run 'stop' first)"
    # Stale PID file, clean it up
    PID_FILE.unlink(missing_ok=True)
    return True, "Cleaned stale PID file"


def run_preflight() -> bool:
    """Run all preflight checks. Returns True if all critical checks pass."""
    checks = [
        ("Python version", _check_python),
        ("Python packages", _check_packages),
        ("Data directories", _check_directories),
        ("GeoIP databases", _check_geoip),
        ("TLS certificates", _check_certs),
        ("Port availability", _check_ports),
        ("Stale processes", _check_stale_pids),
    ]

    print("Preflight checks:")
    all_ok = True
    for label, check_fn in checks:
        ok, msg = check_fn()
        marker = "[OK]" if ok else "[!!]"
        print(f"  {marker} {label:<20} {msg}")
        if not ok and label in (
            "Python version",
            "Python packages",
            "Port availability",
            "Stale processes",
        ):
            all_ok = False  # Critical failures

    # Non-critical warnings don't block startup
    return all_ok


# ── Process Management ──────────────────────────────────────────────────────


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


def _read_pids() -> Dict[str, int]:
    """Read PID file. Returns {name: pid}."""
    if PID_FILE.exists():
        try:
            return json.loads(PID_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _write_pids(pids: Dict[str, int]) -> None:
    """Write PID file atomically."""
    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = PID_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(pids, indent=2))
    tmp.replace(PID_FILE)


def _pid_alive(pid: int) -> bool:
    """Check if a PID is still running."""
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _start_component(
    name: str,
    module: str,
    extra_args: list,
    env: dict,
) -> Optional[subprocess.Popen]:
    """Start a single component as a background subprocess."""
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
        # Verify process didn't die immediately
        time.sleep(0.3)
        if proc.poll() is not None:
            # Read last error
            err_tail = ""
            if log_err.exists():
                lines = log_err.read_text().strip().splitlines()
                err_tail = lines[-1] if lines else "unknown error"
            print(f"  [!!] {name} exited immediately: {err_tail}")
            return None

        print(f"  [OK] {name:<28} PID {proc.pid}")
        return proc
    except Exception as e:
        print(f"  [!!] {name} failed to start: {e}")
        return None


def _stop_pids(pids: Dict[str, int], label: str, sig: int = signal.SIGTERM):
    """Send signal to a set of PIDs."""
    for name, pid in pids.items():
        if _pid_alive(pid):
            print(f"  [-] {label} {name} (PID {pid})")
            try:
                os.kill(pid, sig)
            except OSError:
                pass


def _wait_pids_exit(pids: Dict[str, int], timeout: float = 10.0) -> List[str]:
    """Wait for PIDs to exit. Returns list of still-alive names."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        alive = [n for n, p in pids.items() if _pid_alive(p)]
        if not alive:
            return []
        time.sleep(0.5)
    return [n for n, p in pids.items() if _pid_alive(p)]


# ── Actions ─────────────────────────────────────────────────────────────────


def _start_component_list(
    components: List[ComponentDef],
    env: dict,
    pids: Dict[str, int],
) -> None:
    """Start a list of components, updating pids dict in place."""
    for name, module, extra, _plat, _cat, wait_port in components:
        proc = _start_component(name, module, extra, env)
        if proc:
            pids[name] = proc.pid
            if wait_port:
                _wait_and_report(name, wait_port)


def _print_start_summary(new_pids: Dict[str, int]) -> None:
    """Print final summary after starting components."""
    print(f"\n{'=' * 55}")
    print(f"Started {len(new_pids)} components")
    print(f"PIDs:      {PID_FILE}")
    print(f"Logs:      {LOG_DIR}/")
    if "eventbus" in new_pids:
        print(f"EventBus:  localhost:{PORT_EVENTBUS}")
    if "dashboard" in new_pids:
        print(f"Dashboard: http://127.0.0.1:{PORT_DASHBOARD}")
    print("\nRun 'amoskys-launch status' to verify health.")


def do_start(args: argparse.Namespace) -> None:
    """Start platform components in dependency order."""
    _ensure_dirs()

    if not getattr(args, "skip_preflight", False):
        print()
        if not run_preflight():
            print(
                "\nCritical preflight check failed. Fix issues above or "
                "use --skip-preflight to override."
            )
            return
        print()

    env = _build_env()
    print(f"AMOSKYS Platform Launcher  [{PLATFORM}]")
    print("=" * 55)

    new_pids: Dict[str, int] = {}

    if not getattr(args, "agents_only", False):
        print("\n[1/3] Infrastructure")
        _start_component_list(INFRASTRUCTURE, env, new_pids)

    agents = _get_platform_agents()
    print(f"\n[2/3] Agent fleet ({len(agents)} agents on {PLATFORM})")
    _start_component_list(agents, env, new_pids)

    if getattr(args, "include_dashboard", False):
        print("\n[3/3] Dashboard")
        _start_component_list(DASHBOARD_COMPONENTS, env, new_pids)

    _write_pids(new_pids)
    _print_start_summary(new_pids)


def _wait_and_report(name: str, port: int) -> None:
    """Wait for a component's port and report status."""
    print(f"       Waiting for {name} (:{port})...", end=" ", flush=True)
    if _wait_port(port, timeout=15.0):
        print("ready")
    else:
        print("timeout (may still be starting)")


def do_stop(_args: argparse.Namespace) -> None:
    """Stop all components in reverse dependency order."""
    pids = _read_pids()
    if not pids:
        print("No running components found.")
        return

    print(f"Stopping AMOSKYS platform ({len(pids)} components)...")

    # Classify PIDs
    infra_names = {c[0] for c in INFRASTRUCTURE}
    infra_pids = {n: p for n, p in pids.items() if n in infra_names}
    other_pids = {n: p for n, p in pids.items() if n not in infra_names}

    # Phase 1: Stop agents + dashboard (SIGTERM)
    if other_pids:
        _stop_pids(other_pids, "Stopping")

    # Brief pause for agents to drain queues to local SQLite
    time.sleep(2)

    # Phase 2: Stop infrastructure (SIGTERM)
    if infra_pids:
        _stop_pids(infra_pids, "Stopping")

    # Wait for graceful shutdown
    stragglers = _wait_pids_exit(pids, timeout=10.0)

    # Force kill stragglers
    if stragglers:
        print(f"\n  Force-killing {len(stragglers)} unresponsive components...")
        straggler_pids = {n: pids[n] for n in stragglers}
        _stop_pids(straggler_pids, "Killing", signal.SIGKILL)
        time.sleep(1)

    # Clean PID file
    PID_FILE.unlink(missing_ok=True)

    final_alive = [n for n, p in pids.items() if _pid_alive(p)]
    if final_alive:
        print(f"\n  WARNING: Still running: {', '.join(final_alive)}")
    else:
        print(f"\nAll {len(pids)} components stopped.")


def do_restart(args: argparse.Namespace) -> None:
    """Stop then start all components."""
    do_stop(args)
    time.sleep(1)
    do_start(args)


def do_status(args: argparse.Namespace) -> None:
    """Show status of all components."""
    pids = _read_pids()
    verbose = getattr(args, "verbose", False)

    print(f"AMOSKYS Platform Status  [{PLATFORM}]")
    print("=" * 55)

    # Component status
    if not pids:
        print("\nNo components registered. Run 'amoskys-launch start' first.")
    else:
        _print_component_status(pids)

    # Service ports
    print("\nService ports:")
    for label, port in [
        ("EventBus gRPC", PORT_EVENTBUS),
        ("Dashboard HTTP", PORT_DASHBOARD),
        ("Prometheus", PORT_PROMETHEUS),
    ]:
        up = _port_open(port)
        marker = "[OK]" if up else "[--]"
        print(f"  {marker} {label:<20} :{port}")

    # Heartbeats
    _print_heartbeats(verbose)

    # Database stats
    if verbose:
        _print_db_stats()


def _print_component_status(pids: Dict[str, int]) -> None:
    """Print process status table."""
    print(f"\n{'Component':<28} {'PID':>7}  {'Status':<10}")
    print("-" * 55)

    alive_count = 0
    for name, pid in pids.items():
        alive = _pid_alive(pid)
        status = "running" if alive else "STOPPED"
        marker = "[OK]" if alive else "[!!]"
        print(f"  {marker} {name:<25} {pid:>7}  {status}")
        if alive:
            alive_count += 1

    print("-" * 55)
    total = len(pids)
    health = "healthy" if alive_count == total else "degraded"
    print(f"  {alive_count}/{total} components running ({health})")


def _format_age(seconds: float) -> str:
    """Format a duration in seconds to a human-readable string."""
    if seconds < 60:
        return f"{int(seconds)}s ago"
    if seconds < 3600:
        return f"{int(seconds / 60)}m ago"
    return f"{int(seconds / 3600)}h ago"


def _format_heartbeat(hb: Path, now: datetime, verbose: bool) -> str:
    """Format a single heartbeat file as a status line."""
    data = json.loads(hb.read_text())
    agent = data.get("agent_name", hb.stem)
    cycle = data.get("cycle", "?")
    status = data.get("status", "?")
    marker = "[OK]" if status == "healthy" else "[!!]"
    line = f"  {marker} {agent:<20} cycle #{cycle}"
    if verbose:
        ts_str = data.get("timestamp", "")
        age_str = (
            _format_age((now - datetime.fromisoformat(ts_str)).total_seconds())
            if ts_str
            else ""
        )
        line += f"  {age_str:>8}  {status}"
    return line


def _print_heartbeats(verbose: bool) -> None:
    """Print agent heartbeat status."""
    hb_dir = DATA_DIR / "heartbeats"
    if not hb_dir.exists():
        return
    hb_files = sorted(hb_dir.glob("*.json"))
    if not hb_files:
        return

    now = datetime.now(timezone.utc)
    print(f"\nAgent heartbeats ({len(hb_files)}):")
    for hb in hb_files:
        try:
            print(_format_heartbeat(hb, now, verbose))
        except (json.JSONDecodeError, OSError):
            print(f"  [??] {hb.stem:<20} (corrupt heartbeat)")


def _print_db_stats() -> None:
    """Print telemetry database statistics."""
    if not DB_PATH.exists():
        print("\nDatabase: not created yet")
        return

    print(f"\nTelemetry database ({DB_PATH.name}):")
    try:
        conn = sqlite3.connect(str(DB_PATH))
        total = 0
        for table in [
            "security_events",
            "process_events",
            "flow_events",
            "persistence_events",
            "fim_events",
            "dns_events",
            "peripheral_events",
            "device_telemetry",
            "incidents",
        ]:
            try:
                cnt = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            except Exception:
                cnt = 0
            if cnt > 0:
                print(f"  {table:<25} {cnt:>6} rows")
            total += cnt
        print(f"  {'TOTAL':<25} {total:>6} rows")
        conn.close()
    except Exception as e:
        print(f"  Error reading database: {e}")


def do_health(_args: argparse.Namespace) -> None:
    """Deep health check — verify each component is functional."""
    print("AMOSKYS Health Check")
    print("=" * 55)

    checks = [
        ("EventBus", _health_eventbus),
        ("WAL Processor", _health_wal_processor),
        ("Agent Fleet", _health_agents),
        ("Dashboard", _health_dashboard),
        ("Enrichment Pipeline", _health_enrichment),
        ("Telemetry Database", _health_database),
    ]

    ok_count = 0
    for label, check_fn in checks:
        ok, msg = check_fn()
        marker = "[OK]" if ok else "[!!]"
        print(f"  {marker} {label:<25} {msg}")
        if ok:
            ok_count += 1

    print(f"\n{ok_count}/{len(checks)} health checks passed")


def _health_eventbus() -> Tuple[bool, str]:
    if _port_open(PORT_EVENTBUS):
        return True, f"gRPC server listening on :{PORT_EVENTBUS}"
    return False, f"Port {PORT_EVENTBUS} not responding"


def _health_wal_processor() -> Tuple[bool, str]:
    pids = _read_pids()
    pid = pids.get("wal-processor")
    if pid and _pid_alive(pid):
        return True, f"Running (PID {pid})"
    return False, "Not running"


def _health_agents() -> Tuple[bool, str]:
    hb_dir = DATA_DIR / "heartbeats"
    if not hb_dir.exists():
        return False, "No heartbeat directory"
    hb_files = list(hb_dir.glob("*.json"))
    if not hb_files:
        return False, "No heartbeat files"

    now = datetime.now(timezone.utc)
    stale = 0
    for hb in hb_files:
        try:
            data = json.loads(hb.read_text())
            ts = datetime.fromisoformat(data.get("timestamp", ""))
            if (now - ts).total_seconds() > 120:
                stale += 1
        except Exception:
            stale += 1

    healthy = len(hb_files) - stale
    if stale == 0:
        return True, f"{healthy} agents reporting"
    return False, f"{healthy} healthy, {stale} stale (>2min)"


def _health_dashboard() -> Tuple[bool, str]:
    if _port_open(PORT_DASHBOARD):
        return True, f"HTTP server on :{PORT_DASHBOARD}"
    return False, "Not running"


def _health_enrichment() -> Tuple[bool, str]:
    if GEOIP_CITY.exists() and GEOIP_ASN.exists():
        return True, "GeoIP + ASN databases available"
    return False, "GeoIP databases missing"


def _health_database() -> Tuple[bool, str]:
    if not DB_PATH.exists():
        return False, "telemetry.db does not exist"
    try:
        conn = sqlite3.connect(str(DB_PATH))
        cnt = conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
        conn.close()
        return True, f"{cnt} security events in database"
    except Exception as e:
        return False, f"Database error: {e}"


def do_collect(args: argparse.Namespace) -> None:
    """One-shot data collection through the full enrichment pipeline.

    Runs all macOS Observatory collectors + probes, routes through
    WAL Processor (enrichment -> scoring -> fusion -> SOMA), and
    inserts into TelemetryStore domain tables.
    """
    script = PROJECT_ROOT / "scripts" / "collect_and_store.py"
    if not script.exists():
        print(f"Collection script not found: {script}")
        return

    cmd = [sys.executable, str(script)]
    if getattr(args, "clear", False):
        cmd.append("--clear")
    agent_count = getattr(args, "agents", 0)
    if agent_count:
        cmd.extend(["--agents", str(agent_count)])

    env = _build_env()
    print("Running full pipeline collection...")
    print("=" * 55)

    try:
        result = subprocess.run(
            cmd,
            cwd=str(PROJECT_ROOT),
            env=env,
            timeout=300,
        )
        if result.returncode != 0:
            print(f"\nCollection failed with exit code {result.returncode}")
    except subprocess.TimeoutExpired:
        print("\nCollection timed out after 5 minutes")
    except Exception as e:
        print(f"\nCollection error: {e}")


def do_install(_args: argparse.Namespace) -> None:
    """Generate and install macOS launchd plists."""
    if PLATFORM != "darwin":
        print("launchd install is macOS-only.")
        return

    launch_agents_dir = Path.home() / "Library" / "LaunchAgents"
    launch_agents_dir.mkdir(parents=True, exist_ok=True)

    python = sys.executable
    cwd = str(PROJECT_ROOT)
    src = str(PROJECT_ROOT / "src")

    services = [
        ("com.amoskys.eventbus", [python, "-m", "amoskys.eventbus.server"]),
        ("com.amoskys.wal-processor", [python, "-m", "amoskys.storage.wal_processor"]),
        (
            "com.amoskys.agent-fleet",
            [
                python,
                "-m",
                "amoskys.launcher",
                "start",
                "--agents-only",
                "--skip-preflight",
            ],
        ),
        ("com.amoskys.dashboard", [python, "-m", "web.app"]),
    ]

    for label, prog_args in services:
        plist_path = launch_agents_dir / f"{label}.plist"
        _write_launchd_plist(plist_path, label, prog_args, cwd, src)
        print(f"  [OK] {plist_path}")

    print("\nLoad with:")
    print("  launchctl load ~/Library/LaunchAgents/com.amoskys.*.plist")


def _write_launchd_plist(
    path: Path,
    label: str,
    prog_args: list,
    cwd: str,
    src: str,
) -> None:
    """Write a single launchd plist file."""
    args_xml = "\n        ".join(f"<string>{a}</string>" for a in prog_args)
    log_name = label.split(".")[-1]
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
        <string>{src}:{cwd}</string>
    </dict>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{cwd}/logs/{log_name}.log</string>
    <key>StandardErrorPath</key>
    <string>{cwd}/logs/{log_name}.err.log</string>
</dict>
</plist>
"""
    path.write_text(plist)


def do_uninstall(_args: argparse.Namespace) -> None:
    """Unload and remove macOS launchd plists."""
    if PLATFORM != "darwin":
        print("launchd uninstall is macOS-only.")
        return

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


# ── Main ────────────────────────────────────────────────────────────────────


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="AMOSKYS Fleet Launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "commands:\n"
            "  start      Start all platform components\n"
            "  stop       Stop all running components\n"
            "  restart    Stop then start all components\n"
            "  status     Show component status and health\n"
            "  health     Deep health check of all subsystems\n"
            "  collect    One-shot data collection through full pipeline\n"
            "  install    Generate macOS launchd plists\n"
            "  uninstall  Remove macOS launchd plists\n"
        ),
    )
    parser.add_argument(
        "action",
        choices=[
            "start",
            "stop",
            "restart",
            "status",
            "health",
            "collect",
            "install",
            "uninstall",
        ],
    )
    parser.add_argument(
        "--agents-only",
        action="store_true",
        help="Skip infrastructure (EventBus, WAL Processor)",
    )
    parser.add_argument(
        "--include-dashboard",
        action="store_true",
        help="Also start the web dashboard",
    )
    parser.add_argument(
        "--skip-preflight",
        action="store_true",
        help="Skip environment validation checks",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed status information",
    )
    # Collect options
    parser.add_argument(
        "--clear",
        action="store_true",
        help="Clear database before collecting (collect only)",
    )
    parser.add_argument(
        "--agents",
        type=int,
        default=0,
        help="Limit to first N agents (collect only)",
    )

    args = parser.parse_args()

    dispatch = {
        "start": do_start,
        "stop": do_stop,
        "restart": do_restart,
        "status": do_status,
        "health": do_health,
        "collect": do_collect,
        "install": do_install,
        "uninstall": do_uninstall,
    }
    dispatch[args.action](args)


if __name__ == "__main__":
    main()
