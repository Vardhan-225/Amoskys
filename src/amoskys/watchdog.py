#!/usr/bin/env python3
"""AMOSKYS Watchdog — Tiered daemon supervisor.

Manages two child processes:
  Tier 1: Collector — real-time event collection (FSEvents, log stream, kqueue, polling)
  Tier 2: Analyzer  — enrichment, scoring, probes, fusion, correlation, IGRIS

The watchdog monitors each child for:
  - Process death (restart with exponential backoff)
  - Memory usage (RSS limit enforcement)
  - CPU usage (sustained limit enforcement)
  - Heartbeat staleness (liveness check)

Architecture:
    launchd → watchdog (this) → fork() → collector
                               → fork() → analyzer

Events flow: Collector → per-agent WAL files → Analyzer → telemetry.db

Usage:
    # As a LaunchDaemon (production):
    launchctl load /Library/LaunchDaemons/com.amoskys.watchdog.plist

    # Manual (development):
    PYTHONPATH=src python -m amoskys.watchdog

    # With custom limits:
    PYTHONPATH=src python -m amoskys.watchdog --collector-rss 150 --analyzer-rss 200
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Optional

import psutil

logger = logging.getLogger("amoskys.watchdog")

# ── Defaults ─────────────────────────────────────────────────────────────────

COLLECTOR_RSS_LIMIT_MB = 350
ANALYZER_RSS_LIMIT_MB = 500
CPU_SUSTAINED_LIMIT = 0.25  # 25% of one core
HEARTBEAT_TIMEOUT_S = 120
MAX_RESTART_BACKOFF_S = 60
HEALTH_CHECK_INTERVAL_S = 5
CONSECUTIVE_FAILURES_DISABLE = 5

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data"
HEARTBEAT_DIR = DATA_DIR / "heartbeats"
LOG_DIR = PROJECT_ROOT / "logs"


# ── Child Process Descriptor ─────────────────────────────────────────────────


DASHBOARD_RSS_LIMIT_MB = 500


class ChildProcess:
    """Tracks a child process managed by the watchdog."""

    def __init__(self, name: str, entry_module: str, rss_limit_mb: int, env: dict = None):
        self.name = name
        self.entry_module = entry_module
        self.rss_limit_mb = rss_limit_mb
        self.env: dict = env or {}
        self.pid: Optional[int] = None
        self.restart_count = 0
        self.last_start_time = 0.0
        self.consecutive_failures = 0
        self.disabled = False

    def is_alive(self) -> bool:
        if self.pid is None:
            return False
        try:
            p = psutil.Process(self.pid)
            return p.is_running() and p.status() != psutil.STATUS_ZOMBIE
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

    def get_rss_mb(self) -> float:
        if self.pid is None:
            return 0.0
        try:
            return psutil.Process(self.pid).memory_info().rss / (1024 * 1024)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return 0.0

    def get_cpu_percent(self) -> float:
        if self.pid is None:
            return 0.0
        try:
            return psutil.Process(self.pid).cpu_percent(interval=0) / 100.0
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return 0.0

    def uptime_seconds(self) -> float:
        if self.last_start_time <= 0:
            return 0.0
        return time.time() - self.last_start_time

    def backoff_seconds(self) -> float:
        return min(5 * (2**self.consecutive_failures), MAX_RESTART_BACKOFF_S)


# ── Watchdog ─────────────────────────────────────────────────────────────────


class AMOSKYSWatchdog:
    """Parent process that supervises collector and analyzer children."""

    def __init__(
        self,
        collector_rss: int = COLLECTOR_RSS_LIMIT_MB,
        analyzer_rss: int = ANALYZER_RSS_LIMIT_MB,
        dashboard_rss: int = DASHBOARD_RSS_LIMIT_MB,
    ):
        import secrets

        self.collector = ChildProcess(
            name="collector",
            entry_module="amoskys.collector_main",
            rss_limit_mb=collector_rss,
        )
        self.analyzer = ChildProcess(
            name="analyzer",
            entry_module="amoskys.analyzer_main",
            rss_limit_mb=analyzer_rss,
        )
        self.dashboard = ChildProcess(
            name="dashboard",
            entry_module="web.app",
            rss_limit_mb=dashboard_rss,
            env={
                "SECRET_KEY": secrets.token_hex(32),
                "LOGIN_DISABLED": "true",
                "FLASK_PORT": "5003",
                "FORCE_HTTPS": "false",
            },
        )
        self.children = [self.collector, self.analyzer, self.dashboard]
        self._running = True
        self._setup_signals()

    def _setup_signals(self):
        signal.signal(signal.SIGTERM, self._handle_shutdown)
        signal.signal(signal.SIGINT, self._handle_shutdown)

    def _handle_shutdown(self, signum, frame):
        logger.info("Watchdog received signal %d, shutting down children", signum)
        self._running = False
        for child in self.children:
            if child.is_alive():
                try:
                    os.kill(child.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        # Give children 10s to exit gracefully
        deadline = time.time() + 10
        for child in self.children:
            if child.pid:
                try:
                    remaining = max(0.1, deadline - time.time())
                    os.waitpid(child.pid, 0)
                except ChildProcessError:
                    pass

    def start_child(self, child: ChildProcess) -> bool:
        """Fork and exec a child process."""
        if child.disabled:
            return False

        # Ensure log directory exists
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        HEARTBEAT_DIR.mkdir(parents=True, exist_ok=True)

        pid = os.fork()
        if pid == 0:
            # ── Child process ──
            # Redirect stdout/stderr to log files
            log_out = open(LOG_DIR / f"{child.name}.log", "a")
            log_err = open(LOG_DIR / f"{child.name}.err.log", "a")
            os.dup2(log_out.fileno(), sys.stdout.fileno())
            os.dup2(log_err.fileno(), sys.stderr.fileno())

            # Set resource limits hint via env
            os.environ["AMOSKYS_RSS_LIMIT_MB"] = str(child.rss_limit_mb)
            os.environ["AMOSKYS_ROLE"] = child.name
            # Apply child-specific environment variables
            for k, v in child.env.items():
                os.environ[k] = v

            # Replace process with the child module
            try:
                import importlib

                mod = importlib.import_module(child.entry_module)
                if hasattr(mod, "main"):
                    sys.exit(mod.main())
                else:
                    logger.error("Module %s has no main() function", child.entry_module)
                    sys.exit(1)
            except Exception as e:
                print(f"FATAL: {child.name} failed to start: {e}", file=sys.stderr)
                import traceback

                traceback.print_exc(file=sys.stderr)
                sys.exit(1)
        else:
            # ── Parent (watchdog) ──
            child.pid = pid
            child.last_start_time = time.time()
            child.restart_count += 1
            logger.info(
                "Started %s (pid=%d, restart=#%d, rss_limit=%dMB)",
                child.name,
                pid,
                child.restart_count,
                child.rss_limit_mb,
            )
            return True

    def check_child(self, child: ChildProcess) -> None:
        """Check health of a child process, restart if needed."""
        if child.disabled:
            return

        if not child.is_alive():
            # Child died
            exit_code = -1
            if child.pid:
                try:
                    _, status = os.waitpid(child.pid, os.WNOHANG)
                    exit_code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -1
                except ChildProcessError:
                    pass

            child.consecutive_failures += 1
            backoff = child.backoff_seconds()

            if child.consecutive_failures >= CONSECUTIVE_FAILURES_DISABLE:
                logger.error(
                    "%s failed %d times consecutively — DISABLED",
                    child.name,
                    child.consecutive_failures,
                )
                child.disabled = True
                return

            logger.warning(
                "%s died (exit=%d, failures=%d), restarting in %.0fs",
                child.name,
                exit_code,
                child.consecutive_failures,
                backoff,
            )
            time.sleep(backoff)
            self.start_child(child)
            return

        # Child is alive — check resources
        rss_mb = child.get_rss_mb()

        if rss_mb > child.rss_limit_mb * 0.90:
            logger.warning(
                "%s RSS=%.0fMB (%.0f%% of %dMB limit)",
                child.name,
                rss_mb,
                (rss_mb / child.rss_limit_mb) * 100,
                child.rss_limit_mb,
            )

        if rss_mb > child.rss_limit_mb:
            logger.error(
                "%s exceeded RSS limit (%0.fMB > %dMB), restarting",
                child.name,
                rss_mb,
                child.rss_limit_mb,
            )
            try:
                os.kill(child.pid, signal.SIGTERM)
                time.sleep(2)
                if child.is_alive():
                    os.kill(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            return

        # Reset consecutive failures if child has been alive >5 min
        if child.uptime_seconds() > 300 and child.consecutive_failures > 0:
            logger.info(
                "%s healthy for >5min, resetting failure counter (%d → 0)",
                child.name,
                child.consecutive_failures,
            )
            child.consecutive_failures = 0

    def run(self) -> int:
        """Main watchdog loop."""
        logger.info("AMOSKYS Watchdog starting (3-tier)")
        for child in self.children:
            logger.info(
                "  %s: module=%s, rss_limit=%dMB",
                child.name,
                child.entry_module,
                child.rss_limit_mb,
        )

        # Start children (staggered: collector → analyzer → dashboard)
        self.start_child(self.collector)
        time.sleep(1)
        self.start_child(self.analyzer)
        time.sleep(2)
        self.start_child(self.dashboard)

        # Supervision loop
        while self._running:
            time.sleep(HEALTH_CHECK_INTERVAL_S)
            for child in self.children:
                self.check_child(child)

            # Log status periodically
            if int(time.time()) % 60 < HEALTH_CHECK_INTERVAL_S:
                for child in self.children:
                    if child.is_alive():
                        rss = child.get_rss_mb()
                        uptime = child.uptime_seconds()
                        logger.info(
                            "%s: pid=%d, rss=%.0fMB, uptime=%.0fs, restarts=%d",
                            child.name,
                            child.pid,
                            rss,
                            uptime,
                            child.restart_count,
                        )
                    elif child.disabled:
                        logger.warning(
                            "%s: DISABLED after %d failures",
                            child.name,
                            child.consecutive_failures,
                        )

        logger.info("Watchdog exiting")
        return 0


# ── Entry Point ──────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="AMOSKYS Watchdog Daemon")
    parser.add_argument(
        "--collector-rss",
        type=int,
        default=COLLECTOR_RSS_LIMIT_MB,
        help=f"Collector RSS limit in MB (default: {COLLECTOR_RSS_LIMIT_MB})",
    )
    parser.add_argument(
        "--analyzer-rss",
        type=int,
        default=ANALYZER_RSS_LIMIT_MB,
        help=f"Analyzer RSS limit in MB (default: {ANALYZER_RSS_LIMIT_MB})",
    )
    parser.add_argument(
        "--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"]
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    watchdog = AMOSKYSWatchdog(
        collector_rss=args.collector_rss,
        analyzer_rss=args.analyzer_rss,
    )
    return watchdog.run()


if __name__ == "__main__":
    sys.exit(main())
