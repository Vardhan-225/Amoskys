#!/usr/bin/env python3
"""AMOSKYS Live Demo — Multi-Agent Observatory in Action.

Runs all macOS Observatory agents live on this machine, showing:
  1. Real data collection from macOS subsystems
  2. Probe detections with MITRE ATT&CK mapping
  3. Sigma rule evaluation against live events
  4. AgentBus cross-agent context sharing
  5. KillChainTracker multi-stage progression
  6. Per-agent health and coverage metrics

Usage:
    python scripts/live_demo.py              # Full demo
    python scripts/live_demo.py --agents 3   # First 3 agents only
    python scripts/live_demo.py --verbose     # Show all events, not just detections
"""

from __future__ import annotations

import logging
import socket
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# ── Path setup ──────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from amoskys.agents.common.agent_bus import (
    AgentBus,
    PeerAlert,
    ThreatContext,
    get_agent_bus,
    reset_agent_bus,
)
from amoskys.agents.common.kill_chain import (
    KILL_CHAIN_STAGES,
    TACTIC_TO_STAGE,
    KillChainTracker,
)
from amoskys.agents.common.probes import ProbeContext, Severity, TelemetryEvent

# Suppress noisy loggers
logging.basicConfig(level=logging.WARNING, format="%(message)s")
for name in [
    "amoskys",
    "urllib3",
    "google",
    "grpc",
    "protobuf",
    "amoskys.agents.common.queue_adapter",
    "amoskys.agents.common.base",
]:
    logging.getLogger(name).setLevel(logging.ERROR)


# ── ANSI Colors ─────────────────────────────────────────────────────────────
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_BLUE = "\033[44m"


SEVERITY_COLORS = {
    "DEBUG": C.DIM,
    "INFO": C.WHITE,
    "LOW": C.CYAN,
    "MEDIUM": C.YELLOW,
    "HIGH": C.RED,
    "CRITICAL": f"{C.BG_RED}{C.WHITE}{C.BOLD}",
}

SEVERITY_ICONS = {
    "DEBUG": ".",
    "INFO": "-",
    "LOW": "~",
    "MEDIUM": "!",
    "HIGH": "!!",
    "CRITICAL": "!!!",
}


# ── Data Structures ─────────────────────────────────────────────────────────
@dataclass
class AgentResult:
    name: str
    display_name: str
    collect_time_ms: float = 0.0
    raw_item_count: int = 0
    probe_count: int = 0
    events: List[TelemetryEvent] = field(default_factory=list)
    detections: List[TelemetryEvent] = field(default_factory=list)
    error: Optional[str] = None
    mitre_techniques: Set[str] = field(default_factory=set)
    mitre_tactics: Set[str] = field(default_factory=set)
    shared_data: Dict[str, Any] = field(default_factory=dict)


# ── Agent Definitions ────────────────────────────────────────────────────────

AGENTS = [
    {
        "name": "process",
        "display": "Process Observatory",
        "collector_module": "amoskys.agents.os.macos.process.collector",
        "collector_class": "MacOSProcessCollector",
        "probe_module": "amoskys.agents.os.macos.process.probes",
        "probe_factory": "create_process_probes",
        "item_key": "processes",
    },
    {
        "name": "network",
        "display": "Network Observatory",
        "collector_module": "amoskys.agents.os.macos.network.collector",
        "collector_class": "MacOSNetworkCollector",
        "probe_module": "amoskys.agents.os.macos.network.probes",
        "probe_factory": "create_network_probes",
        "item_key": "connections",
    },
    {
        "name": "persistence",
        "display": "Persistence Guard",
        "collector_module": "amoskys.agents.os.macos.persistence.collector",
        "collector_class": "MacOSPersistenceCollector",
        "probe_module": "amoskys.agents.os.macos.persistence.probes",
        "probe_factory": "create_persistence_probes",
        "item_key": "entries",
    },
    {
        "name": "filesystem",
        "display": "Filesystem Monitor",
        "collector_module": "amoskys.agents.os.macos.filesystem.collector",
        "collector_class": "MacOSFileCollector",
        "probe_module": "amoskys.agents.os.macos.filesystem.probes",
        "probe_factory": "create_filesystem_probes",
        "item_key": "files",
    },
    {
        "name": "auth",
        "display": "Auth Observatory",
        "collector_module": "amoskys.agents.os.macos.auth.collector",
        "collector_class": "MacOSAuthCollector",
        "probe_module": "amoskys.agents.os.macos.auth.probes",
        "probe_factory": "create_auth_probes",
        "item_key": "auth_events",
    },
    {
        "name": "peripheral",
        "display": "Peripheral Monitor",
        "collector_module": "amoskys.agents.os.macos.peripheral.collector",
        "collector_class": "MacOSPeripheralCollector",
        "probe_module": "amoskys.agents.os.macos.peripheral.probes",
        "probe_factory": "create_peripheral_probes",
        "item_key": "devices",
    },
    {
        "name": "unified_log",
        "display": "Unified Log Observer",
        "collector_module": "amoskys.agents.os.macos.unified_log.collector",
        "collector_class": "MacOSUnifiedLogCollector",
        "probe_module": "amoskys.agents.os.macos.unified_log.probes",
        "probe_factory": "create_unified_log_probes",
        "item_key": "log_entries",
    },
    {
        "name": "dns",
        "display": "DNS Observatory",
        "collector_module": "amoskys.agents.os.macos.dns.collector",
        "collector_class": "MacOSDNSCollector",
        "probe_module": "amoskys.agents.os.macos.dns.probes",
        "probe_factory": "create_dns_probes",
        "item_key": "dns_queries",
    },
    {
        "name": "applog",
        "display": "AppLog Observer",
        "collector_module": "amoskys.agents.os.macos.applog.collector",
        "collector_class": "MacOSAppLogCollector",
        "probe_module": "amoskys.agents.os.macos.applog.probes",
        "probe_factory": "create_applog_probes",
        "item_key": "log_entries",
    },
    {
        "name": "discovery",
        "display": "Discovery Agent",
        "collector_module": "amoskys.agents.os.macos.discovery.collector",
        "collector_class": "MacOSDiscoveryCollector",
        "probe_module": "amoskys.agents.os.macos.discovery.probes",
        "probe_factory": "create_discovery_probes",
        "item_key": "arp_entries",
    },
    {
        "name": "internet_activity",
        "display": "Internet Activity Monitor",
        "collector_module": "amoskys.agents.os.macos.internet_activity.collector",
        "collector_class": "MacOSInternetActivityCollector",
        "probe_module": "amoskys.agents.os.macos.internet_activity.probes",
        "probe_factory": "create_internet_activity_probes",
        "item_key": "connections",
    },
    {
        "name": "db_activity",
        "display": "Database Activity Monitor",
        "collector_module": "amoskys.agents.os.macos.db_activity.collector",
        "collector_class": "MacOSDBActivityCollector",
        "probe_module": "amoskys.agents.os.macos.db_activity.probes",
        "probe_factory": "create_db_activity_probes",
        "item_key": "queries",
    },
    {
        "name": "http_inspector",
        "display": "HTTP Inspector",
        "collector_module": "amoskys.agents.os.macos.http_inspector.collector",
        "collector_class": "MacOSHTTPInspectorCollector",
        "probe_module": "amoskys.agents.os.macos.http_inspector.probes",
        "probe_factory": "create_http_inspector_probes",
        "item_key": "requests",
    },
]


# ── Runner ───────────────────────────────────────────────────────────────────


def run_agent(
    agent_def: dict,
    device_id: str,
    bus: AgentBus,
    verbose: bool = False,
) -> AgentResult:
    """Run a single agent: collect data, run probes, post to AgentBus."""
    import importlib

    name = agent_def["name"]
    result = AgentResult(name=name, display_name=agent_def["display"])

    # Import collector
    try:
        col_mod = importlib.import_module(agent_def["collector_module"])
        CollectorClass = getattr(col_mod, agent_def["collector_class"])
    except Exception as e:
        result.error = f"Collector import: {e}"
        return result

    # Import probes
    try:
        probe_mod = importlib.import_module(agent_def["probe_module"])
        probe_factory = getattr(probe_mod, agent_def["probe_factory"])
        probes = probe_factory()
        result.probe_count = len(probes)
    except Exception as e:
        result.error = f"Probe import: {e}"
        return result

    # Collect — handle different constructor signatures
    try:
        import inspect

        sig = inspect.signature(CollectorClass.__init__)
        params = list(sig.parameters.keys())
        if "device_id" in params:
            collector = CollectorClass(device_id=device_id)
        else:
            collector = CollectorClass()

        t0 = time.monotonic()
        shared_data = collector.collect()
        result.collect_time_ms = round((time.monotonic() - t0) * 1000, 1)
    except Exception as e:
        result.error = f"Collection: {e}"
        return result

    result.shared_data = shared_data

    # Count raw items
    item_key = agent_def["item_key"]
    items = shared_data.get(item_key, [])
    if isinstance(items, list):
        result.raw_item_count = len(items)
    elif isinstance(items, dict):
        result.raw_item_count = len(items)
    elif isinstance(items, int):
        result.raw_item_count = items

    # Run probes
    context = ProbeContext(
        device_id=device_id,
        agent_name=f"macos_{name}",
        shared_data=shared_data,
    )

    all_events: List[TelemetryEvent] = []
    for probe in probes:
        try:
            events = probe.scan(context)
            all_events.extend(events)
        except Exception as e:
            if verbose:
                print(f"    {C.DIM}Probe {probe.name} error: {e}{C.RESET}")

    result.events = all_events
    result.detections = [
        e for e in all_events if e.severity not in (Severity.DEBUG, Severity.INFO)
    ]

    # Collect MITRE coverage
    for event in all_events:
        if event.mitre_techniques:
            result.mitre_techniques.update(event.mitre_techniques)
        if event.mitre_tactics:
            result.mitre_tactics.update(event.mitre_tactics)

    # Post to AgentBus
    suspicious_ips: Set[str] = set()
    active_techniques: Set[str] = set()
    active_pids: Set[int] = set()
    persistence_paths: Set[str] = set()
    risk_indicators: Dict[str, float] = {}

    for event in all_events:
        if event.mitre_techniques:
            active_techniques.update(event.mitre_techniques)
        pid = event.data.get("pid")
        if pid and isinstance(pid, int):
            active_pids.add(pid)
        ip = event.data.get("remote_ip") or event.data.get("source_ip")
        if ip and isinstance(ip, str):
            suspicious_ips.add(ip)
        path = event.data.get("path") or event.data.get("persistence_path")
        if path and isinstance(path, str):
            persistence_paths.add(path)
        if event.confidence and event.confidence > 0.5:
            risk_indicators[event.event_type] = max(
                risk_indicators.get(event.event_type, 0), event.confidence
            )

    bus.post_context(
        f"macos_{name}",
        ThreatContext(
            agent_name=f"macos_{name}",
            timestamp_ns=int(time.time() * 1e9),
            active_pids=active_pids,
            suspicious_ips=suspicious_ips,
            persistence_paths=persistence_paths,
            active_techniques=active_techniques,
            risk_indicators=risk_indicators,
        ),
    )

    # Post high-severity alerts
    for event in result.detections:
        if event.severity in (Severity.HIGH, Severity.CRITICAL):
            bus.post_alert(
                PeerAlert(
                    source_agent=f"macos_{name}",
                    alert_type=event.event_type,
                    timestamp_ns=int(time.time() * 1e9),
                    data=event.data,
                )
            )

    return result


def run_sigma_evaluation(all_events: List[TelemetryEvent]) -> Tuple[int, List[dict]]:
    """Run Sigma rules against all collected events."""
    try:
        from amoskys.detection.sigma_engine import SigmaEngine

        engine = SigmaEngine()
        rules_dir = str(
            PROJECT_ROOT / "src" / "amoskys" / "detection" / "rules" / "sigma"
        )
        loaded = engine.load_rules(rules_dir)

        matches = []
        for event in all_events:
            event_dict = {
                "event_type": event.event_type,
                **event.data,
            }
            if event.mitre_techniques:
                event_dict["mitre_techniques"] = list(event.mitre_techniques)

            sigma_matches = engine.evaluate(event_dict)
            for m in sigma_matches:
                matches.append(
                    {
                        "rule_id": m.rule_id,
                        "rule_title": m.rule_title,
                        "level": m.level,
                        "confidence": m.confidence,
                        "techniques": list(m.mitre_techniques),
                        "event_type": event.event_type,
                        "probe": event.probe_name,
                    }
                )

        return loaded, matches
    except Exception as e:
        print(f"  {C.RED}Sigma engine error: {e}{C.RESET}")
        return 0, []


# ── Display ──────────────────────────────────────────────────────────────────


def print_banner():
    hostname = socket.gethostname()
    import platform

    mac_ver = platform.mac_ver()[0]
    print()
    print(f"{C.BOLD}{C.CYAN}{'=' * 72}{C.RESET}")
    print(
        f"{C.BOLD}{C.CYAN}   AMOSKYS Neural Observatory — Live Multi-Agent Demo{C.RESET}"
    )
    print(f"{C.BOLD}{C.CYAN}{'=' * 72}{C.RESET}")
    print(
        f"  {C.DIM}Host: {hostname}  |  macOS {mac_ver}  |  {time.strftime('%Y-%m-%d %H:%M:%S')}{C.RESET}"
    )
    print(f"{C.CYAN}{'─' * 72}{C.RESET}")
    print()


def print_agent_result(result: AgentResult, idx: int, verbose: bool = False):
    if result.error:
        print(
            f"  {C.RED}[{idx:2d}] {result.display_name:30s}  ERROR: {result.error}{C.RESET}"
        )
        return

    det_count = len(result.detections)
    total_events = len(result.events)

    # Status color
    if det_count == 0:
        status = f"{C.GREEN}CLEAN{C.RESET}"
    elif any(
        e.severity in (Severity.HIGH, Severity.CRITICAL) for e in result.detections
    ):
        status = f"{C.RED}{C.BOLD}{det_count} DETECTIONS{C.RESET}"
    else:
        status = f"{C.YELLOW}{det_count} detections{C.RESET}"

    # Probe bar
    probe_bar = f"{C.DIM}{result.probe_count} probes{C.RESET}"

    print(
        f"  {C.BOLD}[{idx:2d}]{C.RESET} {result.display_name:30s}"
        f"  {result.raw_item_count:5d} items"
        f"  {result.collect_time_ms:7.1f}ms"
        f"  {probe_bar}"
        f"  {status}"
    )

    # Show detections
    for event in result.detections:
        sev = (
            event.severity.value
            if isinstance(event.severity, Severity)
            else str(event.severity)
        )
        color = SEVERITY_COLORS.get(sev, "")
        icon = SEVERITY_ICONS.get(sev, "?")
        tech_str = ""
        if event.mitre_techniques:
            tech_str = f" [{', '.join(sorted(event.mitre_techniques))}]"
        conf_str = f" ({event.confidence:.0%})" if event.confidence else ""

        # Extract the most useful detail
        detail = ""
        d = event.data
        if "process_name" in d:
            detail = f" -- {d['process_name']}"
            if "exe" in d:
                detail += f" ({d['exe']})"
        elif "path" in d:
            detail = f" -- {d['path']}"
        elif "domain" in d:
            detail = f" -- {d['domain']}"
        elif "remote_ip" in d:
            detail = f" -- {d['remote_ip']}"
        elif "name" in d:
            detail = f" -- {d['name']}"

        # Truncate detail
        if len(detail) > 60:
            detail = detail[:57] + "..."

        print(
            f"       {color}[{icon:>3s}]{C.RESET} "
            f"{color}{event.event_type}{C.RESET}"
            f"{C.DIM}{tech_str}{conf_str}{detail}{C.RESET}"
        )

    # Show all events if verbose
    if verbose and total_events > det_count:
        info_count = total_events - det_count
        print(f"       {C.DIM}+ {info_count} info/debug events{C.RESET}")


def print_bus_summary(bus: AgentBus, results: List[AgentResult]):
    print()
    print(f"  {C.BOLD}{C.BLUE}AgentBus Cross-Agent Context{C.RESET}")
    print(f"  {C.BLUE}{'─' * 50}{C.RESET}")

    contexts = bus.get_all_contexts()
    all_ips = bus.get_all_suspicious_ips()
    all_techs = bus.get_all_active_techniques()
    alerts = bus.get_alerts(since_ns=0)

    print(f"  Agents reporting:     {C.BOLD}{len(contexts)}{C.RESET}")
    print(f"  Suspicious IPs:       {C.BOLD}{len(all_ips)}{C.RESET}", end="")
    if all_ips:
        shown = sorted(all_ips)[:5]
        print(
            f"  {C.DIM}({', '.join(shown)}{'...' if len(all_ips) > 5 else ''}){C.RESET}",
            end="",
        )
    print()
    print(f"  Active techniques:    {C.BOLD}{len(all_techs)}{C.RESET}", end="")
    if all_techs:
        shown = sorted(all_techs)[:8]
        print(
            f"  {C.DIM}({', '.join(shown)}{'...' if len(all_techs) > 8 else ''}){C.RESET}",
            end="",
        )
    print()
    print(f"  Peer alerts:          {C.BOLD}{len(alerts)}{C.RESET}", end="")
    if alerts:
        types = set(a.alert_type for a in alerts)
        print(f"  {C.DIM}({', '.join(sorted(types)[:5])}){C.RESET}", end="")
    print()

    # Show per-agent risk indicators
    risk_agents = []
    for ctx_name, ctx in contexts.items():
        if ctx.risk_indicators:
            top_risk = max(ctx.risk_indicators.values())
            risk_agents.append((ctx_name, top_risk, ctx.risk_indicators))

    if risk_agents:
        risk_agents.sort(key=lambda x: x[1], reverse=True)
        print()
        print(f"  {C.BOLD}Risk Indicators (top agents):{C.RESET}")
        for agent_name, top_risk, indicators in risk_agents[:5]:
            bar_len = int(top_risk * 20)
            bar = f"{'#' * bar_len}{'.' * (20 - bar_len)}"
            color = C.RED if top_risk > 0.7 else C.YELLOW if top_risk > 0.4 else C.GREEN
            top_indicator = max(indicators, key=indicators.get)
            print(
                f"    {agent_name:30s} "
                f"{color}[{bar}]{C.RESET} "
                f"{top_risk:.0%}"
                f"  {C.DIM}({top_indicator}){C.RESET}"
            )


def print_kill_chain(tracker: KillChainTracker, device_id: str):
    state = tracker.get_progression(device_id)
    if not state or state.stages_reached == 0:
        return

    print()
    print(f"  {C.BOLD}{C.MAGENTA}Kill Chain Progression{C.RESET}")
    print(f"  {C.MAGENTA}{'─' * 50}{C.RESET}")

    for stage in KILL_CHAIN_STAGES:
        if stage in state.unique_stages:
            # Find observations for this stage
            obs = [o for o in state.observations if o.stage == stage]
            agents = set(o.agent_name for o in obs)
            techs = set(o.mitre_technique for o in obs if o.mitre_technique)
            max_conf = max((o.confidence for o in obs), default=0)

            color = C.RED if max_conf > 0.7 else C.YELLOW
            tech_str = f" [{', '.join(sorted(techs))}]" if techs else ""
            agent_str = f" via {', '.join(sorted(agents))}"

            print(
                f"    {color}[X]{C.RESET} {stage:25s}"
                f"  {C.DIM}{tech_str}{agent_str}{C.RESET}"
            )
        else:
            print(f"    {C.DIM}[ ] {stage}{C.RESET}")

    if state.is_multi_stage:
        print(
            f"\n  {C.RED}{C.BOLD}MULTI-STAGE ATTACK DETECTED{C.RESET}"
            f" — {state.stages_reached} stages reached"
        )


def print_sigma_results(loaded: int, matches: List[dict]):
    print()
    print(f"  {C.BOLD}{C.YELLOW}Sigma Detection Rules{C.RESET}")
    print(f"  {C.YELLOW}{'─' * 50}{C.RESET}")
    print(f"  Rules loaded:         {C.BOLD}{loaded}{C.RESET}")
    print(f"  Rules matched:        {C.BOLD}{len(matches)}{C.RESET}")

    if matches:
        # Deduplicate by rule_id
        seen = set()
        unique = []
        for m in matches:
            if m["rule_id"] not in seen:
                seen.add(m["rule_id"])
                unique.append(m)

        for m in unique[:10]:
            level = m["level"]
            color = (
                C.RED
                if level in ("high", "critical")
                else C.YELLOW if level == "medium" else C.CYAN
            )
            tech_str = f" [{', '.join(m['techniques'][:3])}]" if m["techniques"] else ""
            print(
                f"    {color}[{level:>8s}]{C.RESET} "
                f"{m['rule_id']:25s} "
                f"{C.DIM}{m['rule_title'][:40]}{tech_str}{C.RESET}"
            )
        if len(unique) > 10:
            print(f"    {C.DIM}... and {len(unique) - 10} more{C.RESET}")


def print_mitre_coverage(results: List[AgentResult]):
    print()
    print(f"  {C.BOLD}{C.GREEN}MITRE ATT&CK Coverage (Live Detections){C.RESET}")
    print(f"  {C.GREEN}{'─' * 50}{C.RESET}")

    # Collect all techniques per tactic
    all_techniques: Set[str] = set()
    by_agent: Dict[str, Set[str]] = defaultdict(set)

    for r in results:
        for t in r.mitre_techniques:
            all_techniques.add(t)
            by_agent[r.name].add(t)

    # Also count available techniques (from probe declarations)
    declared_techniques: Set[str] = set()
    import importlib

    for agent_def in AGENTS:
        try:
            probe_mod = importlib.import_module(agent_def["probe_module"])
            factory = getattr(probe_mod, agent_def["probe_factory"])
            probes = factory()
            for p in probes:
                if hasattr(p, "mitre_techniques"):
                    declared_techniques.update(p.mitre_techniques)
        except Exception:
            pass

    print(f"  Techniques detected (live):     {C.BOLD}{len(all_techniques)}{C.RESET}")
    print(
        f"  Techniques declared (probes):   {C.BOLD}{len(declared_techniques)}{C.RESET}"
    )

    # Show per-agent technique count
    if by_agent:
        print()
        sorted_agents = sorted(by_agent.items(), key=lambda x: len(x[1]), reverse=True)
        for agent_name, techs in sorted_agents:
            if techs:
                bar_len = min(len(techs), 30)
                bar = "#" * bar_len
                print(
                    f"    {agent_name:25s} "
                    f"{C.GREEN}{bar}{C.RESET} "
                    f"{len(techs)} techniques"
                )


def print_raw_snapshot(results: List[AgentResult]):
    """Show a sample of raw collected data from each agent."""
    print()
    print(f"  {C.BOLD}{C.WHITE}Raw Data Snapshot (what agents actually see){C.RESET}")
    print(f"  {C.WHITE}{'─' * 50}{C.RESET}")

    for r in results:
        if r.error or not r.shared_data:
            continue

        sd = r.shared_data
        print(
            f"\n  {C.BOLD}{r.display_name}{C.RESET} {C.DIM}({r.raw_item_count} items, {r.collect_time_ms:.0f}ms){C.RESET}"
        )

        if r.name == "process":
            procs = sd.get("processes", [])
            if procs:
                # Show top 5 by CPU
                by_cpu = sorted(
                    procs, key=lambda p: getattr(p, "cpu_percent", 0) or 0, reverse=True
                )[:5]
                for p in by_cpu:
                    name = getattr(p, "name", "?")
                    pid = getattr(p, "pid", 0)
                    cpu = getattr(p, "cpu_percent", 0) or 0
                    mem = getattr(p, "memory_percent", 0) or 0
                    user = getattr(p, "username", "?")
                    print(
                        f"    {C.DIM}PID {pid:<6d} {name:25s} CPU:{cpu:5.1f}%  MEM:{mem:5.1f}%  user:{user}{C.RESET}"
                    )

        elif r.name == "network":
            conns = sd.get("connections", [])
            if conns:
                shown = conns[:5] if isinstance(conns, list) else list(conns)[:5]
                for conn in shown:
                    if hasattr(conn, "process_name"):
                        rip = getattr(conn, "remote_ip", "?")
                        rport = getattr(conn, "remote_port", "?")
                        pname = getattr(conn, "process_name", "?")
                        state = getattr(conn, "state", "?")
                        print(
                            f"    {C.DIM}{pname:20s} -> {rip}:{rport}  ({state}){C.RESET}"
                        )
                    elif isinstance(conn, dict):
                        print(
                            f"    {C.DIM}{conn.get('process_name', '?'):20s} -> {conn.get('remote_ip', '?')}:{conn.get('remote_port', '?')}{C.RESET}"
                        )

        elif r.name == "persistence":
            entries = sd.get("entries", [])
            if entries:
                for e in entries[:5]:
                    etype = getattr(e, "entry_type", None) or (
                        e.get("entry_type") if isinstance(e, dict) else "?"
                    )
                    path = getattr(e, "path", None) or (
                        e.get("path") if isinstance(e, dict) else "?"
                    )
                    if path and len(str(path)) > 60:
                        path = str(path)[:57] + "..."
                    print(f"    {C.DIM}{str(etype):25s} {path}{C.RESET}")
                if len(entries) > 5:
                    print(
                        f"    {C.DIM}... and {len(entries) - 5} more entries{C.RESET}"
                    )

        elif r.name == "filesystem":
            files = sd.get("files", [])
            count = sd.get("total_files", len(files) if isinstance(files, list) else 0)
            dirs_watched = sd.get("directories_watched", sd.get("watched_paths", []))
            if dirs_watched and isinstance(dirs_watched, list):
                print(
                    f"    {C.DIM}Watching {len(dirs_watched)} directories, {count} files tracked{C.RESET}"
                )
                for d in dirs_watched[:3]:
                    print(f"    {C.DIM}  {d}{C.RESET}")
            elif count:
                print(f"    {C.DIM}{count} files tracked across system paths{C.RESET}")

        elif r.name == "auth":
            events = sd.get("auth_events", [])
            if events:
                for e in events[:5]:
                    if hasattr(e, "event_type"):
                        print(
                            f"    {C.DIM}{getattr(e, 'event_type', '?'):25s} user:{getattr(e, 'username', '?')}{C.RESET}"
                        )
                    elif isinstance(e, dict):
                        print(
                            f"    {C.DIM}{e.get('event_type', '?'):25s} user:{e.get('username', '?')}{C.RESET}"
                        )
            else:
                print(f"    {C.DIM}No auth events in last collection window{C.RESET}")

        elif r.name == "discovery":
            arp = sd.get("arp_entries", [])
            if arp:
                print(f"    {C.DIM}ARP table ({len(arp)} hosts):{C.RESET}")
                for entry in arp[:5]:
                    if hasattr(entry, "ip"):
                        print(
                            f"      {C.DIM}{getattr(entry, 'ip', '?'):16s} {getattr(entry, 'mac', '?'):18s} {getattr(entry, 'interface', '?')}{C.RESET}"
                        )
                    elif isinstance(entry, dict):
                        print(
                            f"      {C.DIM}{entry.get('ip', '?'):16s} {entry.get('mac', '?'):18s} {entry.get('interface', '?')}{C.RESET}"
                        )

        elif r.name == "internet_activity":
            conns = sd.get("connections", [])
            if conns:
                print(f"    {C.DIM}Outbound connections ({len(conns)}):{C.RESET}")
                for conn in conns[:5]:
                    if hasattr(conn, "remote_ip"):
                        pname = getattr(conn, "process_name", "?")
                        rip = getattr(conn, "remote_ip", "?")
                        rport = getattr(conn, "remote_port", "?")
                        print(f"      {C.DIM}{pname:20s} -> {rip}:{rport}{C.RESET}")
                    elif isinstance(conn, dict):
                        print(
                            f"      {C.DIM}{conn.get('process_name', '?'):20s} -> {conn.get('remote_ip', '?')}:{conn.get('remote_port', '?')}{C.RESET}"
                        )

        elif r.name == "dns":
            queries = sd.get("dns_queries", [])
            servers = sd.get("dns_servers", [])
            if queries:
                print(f"    {C.DIM}{len(queries)} DNS queries captured{C.RESET}")
            if servers:
                for s in servers[:3]:
                    addr = getattr(s, "address", s) if not isinstance(s, str) else s
                    print(f"    {C.DIM}DNS server: {addr}{C.RESET}")
            unique = sd.get("unique_domains", 0)
            if unique:
                print(f"    {C.DIM}{unique} unique domains queried{C.RESET}")

        elif r.name == "unified_log":
            entries = sd.get("log_entries", [])
            if entries:
                print(
                    f"    {C.DIM}{len(entries)} log entries from macOS Unified Logging{C.RESET}"
                )
                # Show category breakdown
                categories: Dict[str, int] = defaultdict(int)
                for e in entries:
                    cat = getattr(e, "category", None) or (
                        e.get("category") if isinstance(e, dict) else "unknown"
                    )
                    categories[str(cat)] += 1
                for cat, count in sorted(
                    categories.items(), key=lambda x: x[1], reverse=True
                )[:5]:
                    print(f"      {C.DIM}{cat:30s} {count:5d} entries{C.RESET}")

        else:
            # Generic: show shared_data keys and sizes
            for key, val in sd.items():
                if key.startswith("_") or key == "collection_time_ms":
                    continue
                if isinstance(val, list):
                    print(f"    {C.DIM}{key}: {len(val)} items{C.RESET}")
                elif isinstance(val, (int, float)):
                    print(f"    {C.DIM}{key}: {val}{C.RESET}")
                elif isinstance(val, str) and len(val) < 80:
                    print(f"    {C.DIM}{key}: {val}{C.RESET}")


def print_summary(results: List[AgentResult], total_time: float):
    print()
    print(f"{C.CYAN}{'=' * 72}{C.RESET}")
    print(f"  {C.BOLD}Summary{C.RESET}")
    print(f"{C.CYAN}{'─' * 72}{C.RESET}")

    total_items = sum(r.raw_item_count for r in results)
    total_events = sum(len(r.events) for r in results)
    total_detections = sum(len(r.detections) for r in results)
    total_probes = sum(r.probe_count for r in results)
    agents_ok = sum(1 for r in results if not r.error)
    agents_err = sum(1 for r in results if r.error)
    total_collect_ms = sum(r.collect_time_ms for r in results)
    all_techniques = set()
    for r in results:
        all_techniques.update(r.mitre_techniques)

    print(f"  Agents run:        {agents_ok} OK, {agents_err} errors")
    print(f"  Total probes:      {total_probes}")
    print(f"  Raw items:         {total_items:,}")
    print(f"  Probe events:      {total_events}")
    print(f"  Detections:        {total_detections}")
    print(f"  MITRE techniques:  {len(all_techniques)} (live)")
    print(
        f"  Collection time:   {total_collect_ms:.0f}ms (sum) / {total_time:.1f}s (wall)"
    )
    print(f"{C.CYAN}{'=' * 72}{C.RESET}")
    print()


# ── Main ─────────────────────────────────────────────────────────────────────


def main():
    import argparse

    parser = argparse.ArgumentParser(description="AMOSKYS Live Multi-Agent Demo")
    parser.add_argument(
        "--agents",
        type=int,
        default=len(AGENTS),
        help="Number of agents to run (default: all)",
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Show info/debug events too"
    )
    parser.add_argument(
        "--no-sigma", action="store_true", help="Skip Sigma rule evaluation"
    )
    parser.add_argument(
        "--persist",
        action="store_true",
        help="Write collected events to data/telemetry.db for dashboard",
    )
    args = parser.parse_args()

    print_banner()

    device_id = socket.gethostname()
    reset_agent_bus()
    bus = get_agent_bus()
    tracker = KillChainTracker(ttl_seconds=300.0)
    agents_to_run = AGENTS[: args.agents]

    # ── Phase 1: Run All Agents ──
    print(f"  {C.BOLD}Phase 1: Live Collection & Detection{C.RESET}")
    print(
        f"  Running {len(agents_to_run)} agents with {C.BOLD}live macOS data{C.RESET}..."
    )
    print()

    results: List[AgentResult] = []
    all_events: List[TelemetryEvent] = []
    t_start = time.monotonic()

    for i, agent_def in enumerate(agents_to_run, 1):
        result = run_agent(agent_def, device_id, bus, verbose=args.verbose)
        results.append(result)
        all_events.extend(result.events)
        print_agent_result(result, i, verbose=args.verbose)

    total_time = time.monotonic() - t_start

    # ── Raw Data Snapshot ──
    print()
    print(f"  {C.BOLD}Phase 1b: Raw Data Snapshot{C.RESET}")
    print_raw_snapshot(results)

    # ── Phase 2: Feed Kill-Chain ──
    print()
    print(f"  {C.BOLD}Phase 2: Kill Chain Analysis{C.RESET}")

    for event in all_events:
        if event.mitre_tactics:
            for tactic in event.mitre_tactics:
                tactic_key = tactic.lower().replace(" ", "_")
                if tactic_key in TACTIC_TO_STAGE:
                    tracker.record_from_tactic(
                        device_id=device_id,
                        mitre_tactic=tactic_key,
                        agent_name=event.probe_name,
                        mitre_technique=(
                            list(event.mitre_techniques)[0]
                            if event.mitre_techniques
                            else None
                        ),
                        confidence=event.confidence or 0.5,
                    )
        # Also try mapping from techniques directly
        if event.mitre_techniques and not event.mitre_tactics:
            for tech in event.mitre_techniques:
                # Record as generic observation
                tracker.record_stage(
                    device_id=device_id,
                    stage=_technique_to_stage(tech),
                    agent_name=event.probe_name,
                    mitre_technique=tech,
                    confidence=event.confidence or 0.5,
                )

    print_kill_chain(tracker, device_id)

    # ── Phase 3: AgentBus Summary ──
    print()
    print(f"  {C.BOLD}Phase 3: Cross-Agent Intelligence{C.RESET}")
    print_bus_summary(bus, results)

    # ── Phase 4: Sigma Rules ──
    if not args.no_sigma:
        print()
        print(f"  {C.BOLD}Phase 4: Sigma Rule Evaluation{C.RESET}")
        loaded, matches = run_sigma_evaluation(all_events)
        print_sigma_results(loaded, matches)

    # ── Phase 5: MITRE Coverage ──
    print()
    print(f"  {C.BOLD}Phase 5: MITRE ATT&CK Coverage{C.RESET}")
    print_mitre_coverage(results)

    # ── Phase 6: Persist to TelemetryStore ──
    if args.persist:
        print()
        print(f"  {C.BOLD}Phase 6: Persisting to TelemetryStore{C.RESET}")
        persisted = persist_to_telemetry_store(results, device_id)
        print(f"  {C.GREEN}Persisted {persisted} events to data/telemetry.db{C.RESET}")

    # ── Summary ──
    print_summary(results, total_time)


# ── Persistence ──────────────────────────────────────────────────────────────


def persist_to_telemetry_store(results: List[AgentResult], device_id: str) -> int:
    """Write all collected events to data/telemetry.db for dashboard consumption."""
    from amoskys.storage.telemetry_store import TelemetryStore

    db_path = str(PROJECT_ROOT / "data" / "telemetry.db")
    store = TelemetryStore(db_path)
    persisted = 0
    now_ns = int(time.time() * 1e9)
    now_dt = datetime.now(timezone.utc).isoformat()

    for result in results:
        if result.error:
            continue
        agent_name = f"macos_{result.name}"

        # 1. All probe events → security_events table
        for event in result.events:
            sev = (
                event.severity.value
                if isinstance(event.severity, Severity)
                else str(event.severity)
            )
            store.insert_security_event(
                {
                    "timestamp_ns": now_ns,
                    "timestamp_dt": now_dt,
                    "device_id": device_id,
                    "event_category": event.event_type,
                    "event_action": event.probe_name,
                    "event_outcome": sev,
                    "risk_score": event.confidence or 0.0,
                    "confidence": event.confidence or 0.0,
                    "mitre_techniques": (
                        list(event.mitre_techniques) if event.mitre_techniques else []
                    ),
                    "final_classification": (
                        "malicious"
                        if sev in ("HIGH", "CRITICAL")
                        else "suspicious" if sev == "MEDIUM" else "legitimate"
                    ),
                    "description": (
                        event.description
                        if hasattr(event, "description")
                        else event.event_type
                    ),
                    "indicators": event.data,
                    "requires_investigation": sev in ("HIGH", "CRITICAL"),
                    "collection_agent": agent_name,
                    "agent_version": "0.9.0",
                    "event_timestamp_ns": now_ns,
                    "event_id": f"{agent_name}:{event.event_type}:{persisted}",
                }
            )
            persisted += 1

        # 2. Domain-specific raw data → domain tables
        sd = result.shared_data
        if result.name == "process":
            for proc in sd.get("processes", [])[:200]:
                store.insert_process_event(
                    {
                        "timestamp_ns": now_ns,
                        "timestamp_dt": now_dt,
                        "device_id": device_id,
                        "pid": getattr(proc, "pid", 0),
                        "ppid": getattr(proc, "ppid", None),
                        "exe": getattr(proc, "exe", None),
                        "cmdline": " ".join(getattr(proc, "cmdline", []) or []) or None,
                        "username": getattr(proc, "username", None),
                        "cpu_percent": getattr(proc, "cpu_percent", None),
                        "memory_percent": getattr(proc, "memory_percent", None),
                        "num_threads": getattr(proc, "num_threads", None),
                        "num_fds": getattr(proc, "num_fds", None),
                        "is_suspicious": False,
                        "collection_agent": agent_name,
                        "agent_version": "0.9.0",
                    }
                )
                persisted += 1

        elif result.name == "network":
            for conn in sd.get("connections", [])[:200]:
                store.insert_flow_event(
                    {
                        "timestamp_ns": now_ns,
                        "timestamp_dt": now_dt,
                        "device_id": device_id,
                        "src_ip": getattr(conn, "local_ip", None),
                        "dst_ip": getattr(conn, "remote_ip", None),
                        "src_port": getattr(conn, "local_port", None),
                        "dst_port": getattr(conn, "remote_port", None),
                        "protocol": getattr(conn, "protocol", None),
                        "is_suspicious": False,
                    }
                )
                persisted += 1

        elif result.name == "dns":
            for q in sd.get("dns_queries", [])[:200]:
                domain = getattr(q, "domain", None) or (
                    q.get("domain") if isinstance(q, dict) else ""
                )
                store.insert_dns_event(
                    {
                        "timestamp_ns": now_ns,
                        "timestamp_dt": now_dt,
                        "device_id": device_id,
                        "domain": domain,
                        "query_type": getattr(q, "query_type", None),
                        "response_code": getattr(q, "response_code", None),
                        "event_type": "dns_query",
                        "collection_agent": agent_name,
                        "agent_version": "0.9.0",
                    }
                )
                persisted += 1

        elif result.name == "peripheral":
            for dev in sd.get("devices", []):
                store.insert_peripheral_event(
                    {
                        "timestamp_ns": now_ns,
                        "timestamp_dt": now_dt,
                        "device_id": device_id,
                        "peripheral_device_id": getattr(dev, "device_id", "unknown"),
                        "event_type": "CONNECTED",
                        "device_name": getattr(dev, "name", None),
                        "device_type": getattr(dev, "device_type", None),
                        "vendor_id": getattr(dev, "vendor_id", None),
                        "product_id": getattr(dev, "product_id", None),
                        "collection_agent": agent_name,
                        "agent_version": "0.9.0",
                    }
                )
                persisted += 1

        elif result.name == "persistence":
            for entry in sd.get("entries", []):
                store.insert_persistence_event(
                    {
                        "timestamp_ns": now_ns,
                        "timestamp_dt": now_dt,
                        "device_id": device_id,
                        "event_type": getattr(entry, "entry_type", "")
                        or (
                            entry.get("entry_type", "")
                            if isinstance(entry, dict)
                            else ""
                        ),
                        "mechanism": getattr(entry, "entry_type", None),
                        "path": str(
                            getattr(entry, "path", "")
                            or (
                                entry.get("path", "") if isinstance(entry, dict) else ""
                            )
                        ),
                        "collection_agent": agent_name,
                        "agent_version": "0.9.0",
                    }
                )
                persisted += 1

        elif result.name == "filesystem":
            for f in sd.get("files", [])[:200]:
                store.insert_fim_event(
                    {
                        "timestamp_ns": now_ns,
                        "timestamp_dt": now_dt,
                        "device_id": device_id,
                        "event_type": "baseline_scan",
                        "path": str(
                            getattr(f, "path", "")
                            or (f.get("path", "") if isinstance(f, dict) else "")
                        ),
                        "collection_agent": agent_name,
                        "agent_version": "0.9.0",
                    }
                )
                persisted += 1

        # 3. Device telemetry summary
        store.insert_device_telemetry(
            {
                "timestamp_ns": now_ns,
                "timestamp_dt": now_dt,
                "device_id": device_id,
                "device_type": "workstation",
                "protocol": "local",
                "ip_address": "127.0.0.1",
                "total_processes": result.raw_item_count,
                "total_cpu_percent": 0.0,
                "total_memory_percent": 0.0,
                "metric_events": len(result.events),
                "collection_agent": agent_name,
                "agent_version": "0.9.0",
            }
        )
        persisted += 1

    return persisted


# ── Helpers ──────────────────────────────────────────────────────────────────

# Rough technique-to-stage heuristic (when tactic isn't available)
_TECHNIQUE_STAGE_MAP = {
    "T1018": "reconnaissance",
    "T1046": "reconnaissance",
    "T1016": "reconnaissance",
    "T1082": "reconnaissance",
    "T1083": "reconnaissance",
    "T1057": "reconnaissance",
    "T1087": "reconnaissance",
    "T1566": "delivery",
    "T1190": "delivery",
    "T1195": "delivery",
    "T1059": "exploitation",
    "T1106": "exploitation",
    "T1204": "exploitation",
    "T1110": "exploitation",
    "T1003": "exploitation",
    "T1543": "installation",
    "T1547": "installation",
    "T1053": "installation",
    "T1136": "installation",
    "T1071": "command_and_control",
    "T1090": "command_and_control",
    "T1095": "command_and_control",
    "T1105": "command_and_control",
    "T1568": "command_and_control",
    "T1571": "command_and_control",
    "T1572": "command_and_control",
    "T1041": "actions_on_objectives",
    "T1048": "actions_on_objectives",
    "T1567": "actions_on_objectives",
    "T1485": "actions_on_objectives",
    "T1486": "actions_on_objectives",
    "T1496": "actions_on_objectives",
    "T1005": "actions_on_objectives",
    "T1113": "actions_on_objectives",
}


def _technique_to_stage(technique: str) -> str:
    """Map a MITRE technique to a kill-chain stage (best effort)."""
    base = technique.split(".")[0]
    return _TECHNIQUE_STAGE_MAP.get(base, "exploitation")


if __name__ == "__main__":
    main()
