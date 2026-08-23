#!/usr/bin/env python3
"""AMOSKYS Collector Daemon — Tier 1.

Runs all collection sources in a single process:
  Real-time (event-driven):
    - UnifiedLogStreamCollector (23 macOS subsystems)
    - FSEventsCollector (17 filesystem paths)
    - CriticalFileWatcher (kqueue VNODE on 10 critical files)
    - ProcessLifecycleCollector (kqueue process exit events)

  Snapshot (polling at benchmark-optimized intervals):
    Tier 1 (5s):  ProcessAgent, NetworkAgent
    Tier 1b (10s): AuthAgent, DNSAgent
    Tier 2 (10s): InfostealerGuard, QuarantineGuard, Provenance, NetSentinel
    Tier 3 (30s): AppLog, InternetActivity, HTTPInspector, ProtocolCollectors
    Tier 4 (60s): Filesystem, Persistence, Peripheral, Discovery, DBActivity

All events flow to per-agent WAL queues → Analyzer (Tier 2) reads them.

Usage:
    PYTHONPATH=src python -m amoskys.collector_main
"""

from __future__ import annotations

import json
import logging
import os
import platform
import signal
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("amoskys.collector")


# ── Agent Thread Runner ──────────────────────────────────────────────────────


class AgentThread:
    """Runs a single agent in a background thread with crash isolation."""

    def __init__(self, agent_cls, agent_name: str, interval: float, device_id: str):
        self.agent_cls = agent_cls
        self.agent_name = agent_name
        self.interval = interval
        self.device_id = device_id
        self.agent = None
        self.thread: Optional[threading.Thread] = None
        self.shutdown_event = threading.Event()
        self.status = "pending"
        self.cycle_count = 0
        self.last_error: Optional[str] = None
        # Liveness, tracked per agent. A thread wedged INSIDE _run_one_cycle
        # logs neither success nor failure, so the only evidence it is stuck is
        # the absence of evidence — which nothing was watching for.
        self.last_cycle_start: float = 0.0
        self.last_cycle_end: float = 0.0
        self.stall_reported: bool = False

    def start(self, shutdown_event: threading.Event) -> bool:
        """Initialize agent and start collection thread."""
        self.shutdown_event = shutdown_event
        try:
            try:
                self.agent = self.agent_cls(collection_interval=self.interval)
            except TypeError:
                self.agent = self.agent_cls()
            if not self.agent.setup():
                self.status = "setup_failed"
                logger.warning("Agent %s setup failed", self.agent_name)
                return False
            self.status = "running"
        except Exception as e:
            self.status = "init_failed"
            self.last_error = str(e)
            logger.warning("Agent %s init failed: %s", self.agent_name, e)
            return False

        self.thread = threading.Thread(
            target=self._run_loop,
            name=f"agent-{self.agent_name}",
            daemon=True,
        )
        self.thread.start()
        return True

    def _run_loop(self):
        """Collection loop with per-cycle error isolation."""
        while not self.shutdown_event.is_set():
            try:
                self.cycle_count += 1
                self.last_cycle_start = time.time()
                self.agent._run_one_cycle()
                self.last_cycle_end = time.time()
                self.stall_reported = False
            except Exception as e:
                self.last_error = str(e)
                logger.error(
                    "Agent %s cycle %d failed: %s",
                    self.agent_name,
                    self.cycle_count,
                    e,
                )
            self.shutdown_event.wait(timeout=self.interval)

    def stop(self):
        if self.agent and hasattr(self.agent, "shutdown"):
            try:
                self.agent.shutdown()
            except Exception as e:
                logger.warning(
                    "Agent %s shutdown failed: %s", getattr(self.agent, "name", "?"), e
                )



def _report_stalled_agents(agent_threads, logger) -> list:
    """Name agents whose cycle has not returned in several intervals.

    The collection loop already isolates and LOGS a cycle that raises. It
    cannot say anything about a cycle that never returns: the thread simply
    stops producing, and both the success line and the failure line go missing
    together. Absence of output is indistinguishable from a quiet sensor, so a
    wedged agent looks exactly like a healthy one with nothing to report.

    This was not hypothetical. macos_filesystem started cleanly — setup
    complete, 10 probes enabled, interval=60s — and then logged NOTHING for
    three hours, roughly 180 missed cycles, while macos_peripheral (started in
    the same second, same base class, same loop) cycled every 60s throughout.
    No error was raised and none was logged, because none happened.

    Threshold is 5 intervals: long enough that a slow cycle or a burst of lock
    contention does not cry wolf, short enough that a genuinely stuck sensor is
    named within minutes rather than discovered by noticing an empty table days
    later.
    """
    stalled = []
    now = time.time()
    for at in agent_threads:
        if at.status != "running" or not at.last_cycle_start:
            continue
        # A cycle that started and never ended, for more than 5 intervals.
        in_flight = at.last_cycle_start > at.last_cycle_end
        overdue_s = now - at.last_cycle_start
        if in_flight and overdue_s > max(at.interval * 5, 60):
            stalled.append((at.agent_name, overdue_s, at.cycle_count))
    if stalled:
        for name, overdue, count in stalled:
            logger.error(
                "AGENT STALLED: %s has been inside a single collection cycle "
                "for %.0fs (%d cycles completed before it hung). It is emitting "
                "neither results nor errors, which is why nothing else notices.",
                name, overdue, count - 1,
            )
    return [s[0] for s in stalled]

# ── Agent Registry ───────────────────────────────────────────────────────────


def _load_agents() -> List[Dict[str, Any]]:
    """Load all macOS agents with their configurations.

    Returns list of dicts: {cls, name, interval}.
    Agents that fail to import are skipped with a warning.
    """
    agents = []

    # Every sensor _try_load is ASKED for, so a registration that never becomes
    # a running agent can be named rather than merely subtracted.
    #
    # This exists because the failure it catches is invisible by construction:
    # _try_load swallows the exception, logs one WARNING, and the collector then
    # announces "Loaded N agent configurations" — a number with nothing to
    # compare against. protocol_collectors was skipped on every start for an
    # AttributeError (the class is ProtocolCollectors, not
    # ProtocolCollectorsAgent) and the only symptom was 17 where 18 was
    # expected, which nobody can notice without knowing the expected figure.
    #
    # On an EDR a sensor that silently fails to load is a blind spot that
    # reports as health. The reconciliation below makes that impossible.
    requested: list = []
    # Package names, tracked separately from registered names because the two
    # legitimately differ (network -> "flow", process -> "proc"). Comparing
    # registered names against directory names would report those two as
    # unwired forever and train the operator to ignore the warning.
    _requested_packages: set = set()

    def _try_load(module_path: str, class_name: str, name: str, interval: float):
        requested.append(name)
        parts = module_path.split(".")
        if len(parts) >= 2:
            _requested_packages.add(parts[-2])
        try:
            import importlib

            mod = importlib.import_module(module_path)
            cls = getattr(mod, class_name)
            agents.append({"cls": cls, "name": name, "interval": interval})
        except Exception as e:
            logger.warning("Skipping %s: %s", name, e)

    if platform.system() != "Darwin":
        logger.error("Collector requires macOS (Darwin)")
        return agents

    # ── Real-time sensor (runs at 2s, handles log stream + FSEvents + kqueue) ──
    _try_load(
        "amoskys.agents.os.macos.realtime_sensor.agent",
        "MacOSRealtimeSensorAgent",
        "realtime_sensor",
        2.0,
    )

    # ── TIER 1: Critical Fast (5s) — process, network ──
    # Benchmark: psutil=32ms, lsof=29ms → 5s gives 100x headroom
    _try_load(
        "amoskys.agents.os.macos.process.agent",
        "MacOSProcessAgent",
        "proc",
        5.0,  # [10→5] Every process spawn visible in 5s
    )
    _try_load(
        "amoskys.agents.os.macos.network.agent",
        "MacOSNetworkAgent",
        "flow",
        5.0,  # [10→5] C2 connections caught in 5s
    )

    # ── TIER 1b: Critical (10s) — auth, dns (log show costs ~680ms) ──
    _try_load(
        "amoskys.agents.os.macos.auth.agent",
        "MacOSAuthAgent",
        "auth",
        10.0,  # [30→10] Auth events within 10s
    )
    _try_load(
        "amoskys.agents.os.macos.dns.agent",
        "MacOSDNSAgent",
        "dns",
        10.0,  # [30→10] DNS beaconing caught in 10s
    )

    # ── TIER 2: Threat Response (10s) — shield + correlation ──
    _try_load(
        "amoskys.agents.os.macos.infostealer_guard.agent",
        "MacOSInfostealerGuardAgent",
        "infostealer_guard",
        10.0,  # [30→10] Credential theft caught in 10s
    )
    _try_load(
        "amoskys.agents.os.macos.quarantine_guard.agent",
        "MacOSQuarantineGuardAgent",
        "quarantine_guard",
        10.0,  # [30→10] ClickFix caught in 10s
    )
    _try_load(
        "amoskys.agents.os.macos.provenance.agent",
        "MacOSProvenanceAgent",
        "provenance",
        10.0,  # [15→10] Kill chain tracking
    )
    _try_load(
        "amoskys.agents.os.macos.network_sentinel.agent",
        "NetworkSentinelAgent",
        "network_sentinel",
        10.0,  # [15→10] HTTP attacks caught in 10s
    )

    # ── TIER 3: Monitoring (30s) — extended observatory ──
    _try_load(
        "amoskys.agents.os.macos.applog.agent",
        "MacOSAppLogAgent",
        "applog",
        30.0,
    )
    _try_load(
        "amoskys.agents.os.macos.internet_activity.agent",
        "MacOSInternetActivityAgent",
        "internet_activity",
        30.0,
    )
    _try_load(
        "amoskys.agents.os.macos.http_inspector.agent",
        "MacOSHTTPInspectorAgent",
        "http_inspector",
        30.0,
    )
    # Class is ProtocolCollectors, NOT ProtocolCollectorsAgent — every other
    # sensor in this list ends in "Agent", and this one silently did not.
    # _try_load caught the resulting AttributeError and logged
    # "Skipping protocol_collectors: module ... has no attribute
    # ProtocolCollectorsAgent" at WARNING, so the collector reported "Loaded 17
    # agent configurations" against 18 registrations and nothing looked wrong.
    # Verified before changing: ProtocolCollectors subclasses HardenedAgentBase
    # and implements setup/collect_data/run, so it is a real agent that was
    # simply never reachable by name.
    _try_load(
        "amoskys.agents.os.macos.protocol_collectors.protocol_collectors",
        "ProtocolCollectors",
        "protocol_collectors",
        30.0,
    )
    # ── Registered here 2026-08-03 as a BLOCKING PRECONDITION for retiring the
    # launcher/collect_and_store execution models. ──────────────────────────
    # These two sensors existed ONLY in the other two spawn paths
    # (launcher.py:150,158 and scripts/collect_and_store.py:138,191) and had no
    # _try_load entry here at all. Deleting those paths first — the obvious
    # cleanup order — would therefore have silently removed kernel-audit /
    # syscall / CSR-SIP monitoring and all unified-log detection, with no error
    # anywhere: _try_load only warns when an import FAILS, never when an agent
    # is simply never registered. Verified absent before adding.
    #
    # Note the module path: security_monitor's class lives in
    # security_monitor/security_monitor_agent.py, not the agent.py that every
    # other sensor in this list uses.
    _try_load(
        "amoskys.agents.os.macos.security_monitor.security_monitor_agent",
        "MacOSSecurityMonitorAgent",
        "security_monitor",
        30.0,
    )
    _try_load(
        "amoskys.agents.os.macos.unified_log.agent",
        "MacOSUnifiedLogAgent",
        "unified_log",
        30.0,
    )

    # ── TIER 4: Baseline (60s) — expensive or low-urgency ──
    # fim (filesystem poller) RETIRED 2026-07-06 — superseded by the native ESF sensor's
    # kernel file events. Its os.scandir sweeps of ~/Library & ~/Downloads triggered
    # recurring TCC "python3.13 would like to access data from other apps" prompts.
    # Restore this _try_load to re-enable. See docs/_local/amoskys_redesign/ESF_LOAD_PATH.md.
    # _try_load(
    #     "amoskys.agents.os.macos.filesystem.agent",
    #     "MacOSFileAgent",
    #     "fim",
    #     60.0,  # SHA256 hashing is CPU-bound
    # )
    _try_load(
        "amoskys.agents.os.macos.persistence.agent",
        "MacOSPersistenceAgent",
        "persistence",
        60.0,  # LaunchAgent changes are rare
    )
    # peripheral RETIRED 2026-07-06 — media/photo access triggered TCC prompts.
    # USB/peripheral monitoring should be reimplemented via IOKit (no TCC). Restore to re-enable.
    # _try_load(
    #     "amoskys.agents.os.macos.peripheral.agent",
    #     "MacOSPeripheralAgent",
    #     "peripheral",
    #     60.0,  # USB events are rare
    # )
    _try_load(
        "amoskys.agents.os.macos.discovery.agent",
        "MacOSDiscoveryAgent",
        "discovery",
        60.0,  # arp -a takes 5s (!) — keep at 60s
    )
    _try_load(
        "amoskys.agents.os.macos.db_activity.agent",
        "MacOSDBActivityAgent",
        "db_activity",
        60.0,
    )

    # Reconcile: every sensor asked for must have become a loadable agent.
    #
    # Logged at ERROR and named, because on an EDR a sensor that fails to load
    # is a blind spot that reports as health, and the operator otherwise has no
    # way to know: the only prior signal was a count with nothing to compare it
    # against. This is deliberately not fatal — 17 working sensors are worth
    # more than none — but it can never again be silent.
    # WIRED 2026-08-23. These three packages existed, imported cleanly, and
    # produced valid telemetry on the first call — and had never been requested
    # by the collector, so they had NEVER RUN. fim_events and peripheral_events
    # held zero rows for the lifetime of the database: file integrity
    # monitoring and USB device monitoring were absent capabilities that read
    # as present ones, because the code was right there.
    #
    # Intervals are deliberately at the SLOW end of the existing range (60s,
    # matching persistence and discovery, against 2s for realtime_sensor).
    # Unbounded telemetry from this collector filled the SSD to 99% and
    # panicked the kernel six times in 2026-08; three new producers earn their
    # volume before they get a faster cadence, not before.
    _try_load(
        "amoskys.agents.os.macos.filesystem.agent",
        "MacOSFileAgent",
        "filesystem",
        60.0,
    )
    _try_load(
        "amoskys.agents.os.macos.peripheral.agent",
        "MacOSPeripheralAgent",
        "peripheral",
        60.0,
    )
    _try_load(
        "amoskys.agents.os.macos.correlation.agent",
        "MacOSCorrelationAgent",
        "correlation",
        60.0,
    )

    loaded_names = {a["name"] for a in agents}
    missing = [n for n in requested if n not in loaded_names]
    if missing:
        logger.error(
            "SENSOR LOAD GAP: %d of %d registered sensors failed to load and "
            "are NOT monitoring: %s — see the 'Skipping <name>' warnings above "
            "for the cause of each",
            len(missing),
            len(requested),
            ", ".join(missing),
        )
    else:
        logger.info(
            "All %d registered sensors loaded", len(requested)
        )

    # SECOND RECONCILIATION: what exists on disk but was never ASKED FOR.
    #
    # The check above compares requested against loaded, which cannot see an
    # agent that was never requested in the first place — and it announced
    # "All 18 registered sensors loaded — no blind spots" while THREE agent
    # packages sat on disk, wired to nothing:
    #
    #     correlation   3,021 lines      never requested
    #     filesystem    2,300 lines      never requested -> fim_events: 0 rows EVER
    #     peripheral    1,387 lines      never requested -> peripheral_events: 0 rows EVER
    #
    # File integrity monitoring and USB device monitoring have never produced a
    # single event on this machine, and the blind-spot detector reported no
    # blind spots. It had the exact flaw it was written to catch, one level up:
    # a subtraction can only find what someone remembered to put in the
    # minuend.
    #
    # Names are aliased on purpose in some cases (network -> "flow",
    # process -> "proc"), so the comparison is by MODULE PATH, which cannot
    # drift from the package that actually exists.
    try:
        import os as _os

        agents_dir = _os.path.join(
            _os.path.dirname(_os.path.abspath(__file__)),
            "agents", "os", "macos",
        )
        on_disk = {
            d for d in _os.listdir(agents_dir)
            if _os.path.isdir(_os.path.join(agents_dir, d))
            and not d.startswith("__")
            and _os.path.exists(_os.path.join(agents_dir, d, "agent.py"))
        }
        # esf is deliberately out of this registry: it is fed by the Sentinel's
        # own stream and collected separately, not polled on an interval.
        unwired = sorted(on_disk - _requested_packages - {"esf"})
        if unwired:
            logger.error(
                "UNWIRED AGENTS: %d agent package(s) exist but are never "
                "requested by the collector, so they have NEVER run: %s. Code "
                "that is present but unreachable is worse than absent code — "
                "it reads as coverage.",
                len(unwired), ", ".join(unwired),
            )
        else:
            logger.info(
                "Sensor registry complete: %d packages on disk, all wired",
                len(on_disk),
            )
    except Exception:
        logger.warning("Could not reconcile agents on disk", exc_info=True)

    return agents


# ── Main ─────────────────────────────────────────────────────────────────────


def main() -> int:
    """Collector process entry point."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    logger.info("AMOSKYS Collector Daemon starting (pid=%d)", os.getpid())

    device_id = socket.gethostname()
    shutdown_event = threading.Event()

    def handle_signal(signum, frame):
        logger.info("Collector received signal %d, shutting down", signum)
        shutdown_event.set()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    # ── Load and start all agents ──
    agent_configs = _load_agents()
    logger.info("Loaded %d agent configurations", len(agent_configs))

    agent_threads: List[AgentThread] = []
    for cfg in agent_configs:
        at = AgentThread(
            agent_cls=cfg["cls"],
            agent_name=cfg["name"],
            interval=cfg["interval"],
            device_id=device_id,
        )
        if at.start(shutdown_event):
            agent_threads.append(at)
            logger.info("  Started %s (interval=%.0fs)", cfg["name"], cfg["interval"])
        else:
            logger.warning("  Failed to start %s: %s", cfg["name"], at.last_error)

    logger.info(
        "Collector running: %d/%d agents active",
        len(agent_threads),
        len(agent_configs),
    )

    # ── Supervision loop with IGRIS directive reading ──
    dead_agents: set = set()
    last_igris_posture = "NOMINAL"

    while not shutdown_event.is_set():
        shutdown_event.wait(timeout=10)  # Check directives every 10s (was 30s)

        if shutdown_event.is_set():
            break

        # ── Read IGRIS directives ──
        try:
            from amoskys.igris.tactical import read_directives

            directives = read_directives()
            if directives:
                posture = directives.get("posture", "NOMINAL")
                hunt = directives.get("hunt_mode", False)

                if posture != last_igris_posture:
                    logger.info(
                        "IGRIS directive: posture %s -> %s (%s)",
                        last_igris_posture,
                        posture,
                        directives.get("assessment_reason", ""),
                    )
                    last_igris_posture = posture

                if hunt:
                    logger.warning(
                        "IGRIS HUNT MODE: watching PIDs=%s paths=%d domains=%s",
                        directives.get("watched_pids", [])[:5],
                        len(directives.get("watched_paths", [])),
                        directives.get("watched_domains", [])[:3],
                    )

                # Publish WATCH directives to agent coordination bus
                for d in directives.get("directives", []):
                    dtype = d.get("directive_type", "")
                    target = d.get("target", "")
                    if dtype in ("WATCH_PID", "WATCH_PATH", "WATCH_DOMAIN") and target:
                        # Push to any agent that has a coordination bus
                        for at in agent_threads:
                            if at.agent and hasattr(at.agent, "_coordination_bus"):
                                bus = at.agent._coordination_bus
                                if bus:
                                    try:
                                        bus.publish(
                                            dtype,
                                            {
                                                "target": target,
                                                "reason": d.get("reason", ""),
                                                "urgency": d.get("urgency", "HIGH"),
                                                "source_agent": "igris",
                                                "mitre_technique": d.get(
                                                    "mitre_technique", ""
                                                ),
                                            },
                                        )
                                    except Exception as e:
                                        logger.debug(
                                            "Failed to publish directive %s: %s",
                                            dtype,
                                            e,
                                        )
                                break  # LocalBus is shared, publish once
        except Exception as e:
            logger.debug("IGRIS directive integration failed: %s", e)

        # ── Agent health check ──
        running = 0
        total_cycles = 0
        for at in agent_threads:
            total_cycles += at.cycle_count
            if at.thread and at.thread.is_alive():
                running += 1
            elif at.agent_name not in dead_agents:
                dead_agents.add(at.agent_name)
                logger.warning(
                    "DEGRADED: Agent %s thread died after %d cycles (last_error: %s). "
                    "Collector continues with %d/%d agents.",
                    at.agent_name,
                    at.cycle_count,
                    at.last_error or "unknown",
                    running,
                    len(agent_threads),
                )

        # The check above tests whether the THREAD is alive. A thread wedged
        # inside _run_one_cycle is very much alive — it is simply not making
        # progress — so it passes that check while producing nothing at all.
        # Liveness and progress are different questions, and only one of them
        # was being asked.
        _report_stalled_agents(agent_threads, logger)

        _write_heartbeat(device_id, total_cycles, running, len(agent_threads))

        # Write per-agent heartbeats so IGRIS fleet discovery sees them as alive
        _write_agent_heartbeats(agent_threads, device_id)

        logger.info(
            "Collector: %d/%d agents, %d cycles, posture=%s%s",
            running,
            len(agent_threads),
            total_cycles,
            last_igris_posture,
            f" HUNT" if last_igris_posture == "CRITICAL" else "",
        )

    # ── Shutdown ──
    logger.info("Collector shutting down %d agents", len(agent_threads))
    for at in agent_threads:
        at.stop()
    return 0


def _get_data_dir() -> Path:
    """Resolve the data directory.

    Priority:
      1. AMOSKYS_DATA_DIR env var (explicit override)
      2. CWD/data (production: launchd sets CWD=/var/lib/amoskys)
      3. Source-relative: <project>/data (dev fallback)
    """
    env_dir = os.environ.get("AMOSKYS_DATA_DIR")
    if env_dir:
        return Path(env_dir)
    cwd_data = Path("data")
    if cwd_data.is_dir():
        return cwd_data
    return Path(__file__).resolve().parents[2] / "data"


_DATA_DIR = _get_data_dir()


def _write_heartbeat(device_id: str, total_cycles: int, running: int, total: int):
    """Write heartbeat file for watchdog liveness check."""
    heartbeat_dir = _DATA_DIR / "heartbeats"
    heartbeat_dir.mkdir(parents=True, exist_ok=True)
    heartbeat = {
        "agent": "collector",
        "device_id": device_id,
        "total_cycles": total_cycles,
        "agents_running": running,
        "agents_total": total,
        "timestamp": time.time(),
        "pid": os.getpid(),
    }
    try:
        (heartbeat_dir / "collector.json").write_text(json.dumps(heartbeat))
    except OSError as e:
        logger.warning("Failed to write collector heartbeat: %s", e)


def _write_agent_heartbeats(agent_threads: list, device_id: str) -> None:
    """Write per-agent heartbeat files so IGRIS fleet discovery sees them alive.

    Without this, IGRIS reads stale heartbeats from data/heartbeats/ and
    reports 16/18 agents as 'offline' even though they're all running
    inside the collector process.
    """
    heartbeat_dir = _DATA_DIR / "heartbeats"
    now = time.time()
    for at in agent_threads:
        alive = at.thread and at.thread.is_alive()
        hb = {
            "agent_name": at.agent_name,
            "device_id": device_id,
            "status": "running" if alive else "stopped",
            "timestamp": now,
            "pid": os.getpid(),
            "cycle_count": at.cycle_count,
            "last_error": at.last_error,
        }
        try:
            (heartbeat_dir / f"{at.agent_name}.json").write_text(json.dumps(hb))
        except OSError as e:
            logger.warning("Failed to write heartbeat for %s: %s", at.agent_name, e)


if __name__ == "__main__":
    sys.exit(main())
