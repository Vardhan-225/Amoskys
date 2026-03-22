#!/usr/bin/env python3
"""AMOSKYS Collector Daemon — Tier 1.

Runs all collection sources in a single process:
  Real-time (event-driven):
    - UnifiedLogStreamCollector (23 macOS subsystems)
    - FSEventsCollector (17 filesystem paths)
    - CriticalFileWatcher (kqueue VNODE on 10 critical files)
    - ProcessLifecycleCollector (kqueue process exit events)

  Snapshot (polling at per-agent intervals):
    - ProcessAgent (10s)    - NetworkAgent (10s)
    - AuthAgent (30s)       - PersistenceAgent (60s)
    - FilesystemAgent (60s) - PeripheralAgent (60s)
    - DNSAgent (30s)        - InfostealerGuardAgent (30s)
    - DiscoveryAgent (60s)  - ProvenanceAgent (15s)
    + 10 more Observatory agents

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
                self.agent._run_one_cycle()
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


# ── Agent Registry ───────────────────────────────────────────────────────────


def _load_agents() -> List[Dict[str, Any]]:
    """Load all macOS agents with their configurations.

    Returns list of dicts: {cls, name, interval}.
    Agents that fail to import are skipped with a warning.
    """
    agents = []

    def _try_load(module_path: str, class_name: str, name: str, interval: float):
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

    # ── Core Observatory agents ──
    _try_load(
        "amoskys.agents.os.macos.process.agent",
        "MacOSProcessAgent",
        "proc",
        10.0,
    )
    _try_load(
        "amoskys.agents.os.macos.network.agent",
        "MacOSNetworkAgent",
        "flow",
        10.0,
    )
    _try_load(
        "amoskys.agents.os.macos.auth.agent",
        "MacOSAuthAgent",
        "auth",
        30.0,
    )
    _try_load(
        "amoskys.agents.os.macos.persistence.agent",
        "MacOSPersistenceAgent",
        "persistence",
        60.0,
    )
    _try_load(
        "amoskys.agents.os.macos.filesystem.agent",
        "MacOSFileAgent",
        "fim",
        60.0,
    )
    _try_load(
        "amoskys.agents.os.macos.peripheral.agent",
        "MacOSPeripheralAgent",
        "peripheral",
        60.0,
    )
    _try_load(
        "amoskys.agents.os.macos.dns.agent",
        "MacOSDNSAgent",
        "dns",
        30.0,
    )

    # ── Shield agents ──
    _try_load(
        "amoskys.agents.os.macos.infostealer_guard.agent",
        "MacOSInfostealerGuardAgent",
        "infostealer_guard",
        30.0,
    )
    _try_load(
        "amoskys.agents.os.macos.quarantine_guard.agent",
        "MacOSQuarantineGuardAgent",
        "quarantine_guard",
        30.0,
    )
    _try_load(
        "amoskys.agents.os.macos.provenance.agent",
        "MacOSProvenanceAgent",
        "provenance",
        15.0,
    )

    # ── Discovery (slower interval due to Bonjour timeout) ──
    _try_load(
        "amoskys.agents.os.macos.discovery.agent",
        "MacOSDiscoveryAgent",
        "discovery",
        60.0,
    )

    # ── Extended Observatory agents ──
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
        "amoskys.agents.os.macos.db_activity.agent",
        "MacOSDBActivityAgent",
        "db_activity",
        60.0,
    )
    _try_load(
        "amoskys.agents.os.macos.http_inspector.agent",
        "MacOSHTTPInspectorAgent",
        "http_inspector",
        30.0,
    )
    _try_load(
        "amoskys.agents.os.macos.network_sentinel.agent",
        "NetworkSentinelAgent",
        "network_sentinel",
        15.0,
    )
    _try_load(
        "amoskys.agents.os.macos.protocol_collectors.protocol_collectors",
        "ProtocolCollectorsAgent",
        "protocol_collectors",
        30.0,
    )

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


def _write_heartbeat(device_id: str, total_cycles: int, running: int, total: int):
    """Write heartbeat file for watchdog liveness check."""
    heartbeat_dir = Path("data/heartbeats")
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
    except OSError:
        pass


def _write_agent_heartbeats(agent_threads: list, device_id: str) -> None:
    """Write per-agent heartbeat files so IGRIS fleet discovery sees them alive.

    Without this, IGRIS reads stale heartbeats from data/heartbeats/ and
    reports 16/18 agents as 'offline' even though they're all running
    inside the collector process.
    """
    heartbeat_dir = Path("data/heartbeats")
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
        except OSError:
            pass


if __name__ == "__main__":
    sys.exit(main())
