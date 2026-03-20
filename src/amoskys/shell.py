#!/usr/bin/env python3
"""AMOSKYS Interactive Shell — terminal-native security copilot.

Engine decides. Shell explains. Human acts.

The shell is a read-only conversational layer over the detection engine.
It queries posture, incidents, signals, timelines, and kill chains,
then presents results in plain English.

Phase 1: Read-only investigation
Phase 2: Guided actions (quarantine, remove, block)
Phase 3: Policy-bounded automation

Usage:
    PYTHONPATH=src python -m amoskys.shell
    PYTHONPATH=src python -m amoskys shell
"""

from __future__ import annotations

import json
import os
import readline
import socket
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from amoskys.igris.shell_commands import handle_igris_command

# ── Paths ────────────────────────────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
TELEMETRY_DB = DATA_DIR / "telemetry.db"
FUSION_DB = DATA_DIR / "intel" / "fusion.db"
IGRIS_SIGNALS = DATA_DIR / "igris" / "signals.jsonl"

VERSION = "0.9.1-beta"


# ── Colors ───────────────────────────────────────────────────────────────────


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GREY = "\033[90m"

    @staticmethod
    def sev(s: str) -> str:
        s = (s or "").lower()
        if s == "critical":
            return C.RED + C.BOLD
        if s == "high":
            return C.RED
        if s == "medium":
            return C.YELLOW
        if s == "low":
            return C.CYAN
        return C.DIM


# ── DB Helpers ───────────────────────────────────────────────────────────────


def _db(path: Path) -> Optional[sqlite3.Connection]:
    if not path.exists():
        return None
    conn = sqlite3.connect(str(path), timeout=2)
    conn.row_factory = sqlite3.Row
    return conn


def _query(path: Path, sql: str, params: tuple = ()) -> List[dict]:
    conn = _db(path)
    if not conn:
        return []
    try:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()


# ── Engine Queries ───────────────────────────────────────────────────────────
# These are the "engine speaks" functions. They query the detection engine
# and return structured data. The shell layer formats it for humans.


def get_posture() -> Dict[str, Any]:
    """Get current device security posture from the engine."""
    result = {
        "device": socket.gethostname(),
        "security_events": 0,
        "observations": 0,
        "incidents": 0,
        "threats_high": 0,
        "threats_critical": 0,
        "agents_queued": 0,
    }

    conn = _db(TELEMETRY_DB)
    if conn:
        try:
            result["security_events"] = conn.execute(
                "SELECT COUNT(*) FROM security_events"
            ).fetchone()[0]
        except Exception:
            pass
        try:
            result["observations"] = conn.execute(
                "SELECT COUNT(*) FROM observation_events"
            ).fetchone()[0]
        except Exception:
            pass
        try:
            result["incidents"] = conn.execute(
                "SELECT COUNT(*) FROM incidents"
            ).fetchone()[0]
        except Exception:
            pass
        try:
            result["threats_high"] = conn.execute(
                "SELECT COUNT(*) FROM security_events WHERE risk_score >= 0.7"
            ).fetchone()[0]
        except Exception:
            pass
        try:
            result["threats_critical"] = conn.execute(
                "SELECT COUNT(*) FROM security_events WHERE risk_score >= 0.85"
            ).fetchone()[0]
        except Exception:
            pass
        conn.close()

    # Fusion incidents
    conn = _db(FUSION_DB)
    if conn:
        try:
            result["fusion_incidents"] = conn.execute(
                "SELECT COUNT(*) FROM incidents"
            ).fetchone()[0]
        except Exception:
            result["fusion_incidents"] = 0
        conn.close()

    # Queue pending
    import glob

    for qdb in glob.glob(str(DATA_DIR / "queue" / "*.db")):
        try:
            c = sqlite3.connect(qdb, timeout=1)
            result["agents_queued"] += c.execute(
                "SELECT COUNT(*) FROM queue"
            ).fetchone()[0]
            c.close()
        except Exception:
            pass

    # Determine posture level
    if result["threats_critical"] > 0:
        result["level"] = "CRITICAL"
    elif result["threats_high"] > 0:
        result["level"] = "ELEVATED"
    elif result["security_events"] > 0:
        result["level"] = "GUARDED"
    else:
        result["level"] = "NOMINAL"

    return result


def get_recent_threats(limit: int = 10) -> List[dict]:
    """Get recent high-risk security events."""
    return _query(
        TELEMETRY_DB,
        """SELECT event_category, event_action, risk_score, mitre_techniques,
                  confidence, event_timestamp_ns
           FROM security_events
           WHERE risk_score >= 0.5
           ORDER BY event_timestamp_ns DESC LIMIT ?""",
        (limit,),
    )


def get_recent_events(limit: int = 20, category: str = "") -> List[dict]:
    """Get recent security events, optionally filtered by category."""
    if category:
        return _query(
            TELEMETRY_DB,
            """SELECT event_category, event_action, risk_score, mitre_techniques,
                      confidence, event_timestamp_ns
               FROM security_events
               WHERE event_category LIKE ?
               ORDER BY event_timestamp_ns DESC LIMIT ?""",
            (f"%{category}%", limit),
        )
    return _query(
        TELEMETRY_DB,
        """SELECT event_category, event_action, risk_score, mitre_techniques,
                  confidence, event_timestamp_ns
           FROM security_events
           ORDER BY event_timestamp_ns DESC LIMIT ?""",
        (limit,),
    )


def get_fusion_incidents(limit: int = 10) -> List[dict]:
    """Get correlated incidents from the fusion engine."""
    return _query(
        FUSION_DB,
        """SELECT rule_name, severity, summary, techniques, event_ids,
                  created_at, duration_seconds
           FROM incidents ORDER BY created_at DESC LIMIT ?""",
        (limit,),
    )


def get_signals(limit: int = 10) -> List[dict]:
    """Get IGRIS signals."""
    signals = []
    if IGRIS_SIGNALS.exists():
        try:
            lines = IGRIS_SIGNALS.read_text().strip().split("\n")
            for line in reversed(lines[-limit:]):
                try:
                    signals.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass
    return signals


def search_events(query: str, limit: int = 15) -> List[dict]:
    """Search security events by keyword."""
    return _query(
        TELEMETRY_DB,
        """SELECT event_category, event_action, risk_score, mitre_techniques,
                  raw_attributes_json, event_timestamp_ns
           FROM security_events
           WHERE event_category LIKE ? OR event_action LIKE ?
                 OR mitre_techniques LIKE ? OR raw_attributes_json LIKE ?
           ORDER BY event_timestamp_ns DESC LIMIT ?""",
        (f"%{query}%", f"%{query}%", f"%{query}%", f"%{query}%", limit),
    )


def get_process_context(name: str) -> List[dict]:
    """Search for events related to a process name."""
    return search_events(name, limit=20)


# ── MITRE Reference ─────────────────────────────────────────────────────────

MITRE = {
    "T1005": "Data from Local System",
    "T1021.004": "SSH Lateral Movement",
    "T1036": "Masquerading",
    "T1041": "Exfil Over C2",
    "T1046": "Network Service Discovery",
    "T1048": "Exfil Over Alt Protocol",
    "T1053.003": "Cron Persistence",
    "T1059": "Scripting Interpreter",
    "T1059.004": "Unix Shell",
    "T1059.007": "JavaScript",
    "T1071": "App Layer Protocol",
    "T1071.001": "Web Protocols",
    "T1078": "Valid Accounts",
    "T1082": "System Info Discovery",
    "T1098.004": "SSH Authorized Keys",
    "T1110": "Brute Force",
    "T1204": "User Execution",
    "T1218": "System Binary Proxy Exec",
    "T1543.001": "Launch Agent",
    "T1546.004": "Shell Config Mod",
    "T1548": "Abuse Elevation",
    "T1548.003": "Sudo Abuse",
    "T1553.001": "Gatekeeper Bypass",
    "T1555.001": "Keychain",
    "T1562.001": "Disable Security Tools",
    "T1566.002": "Spearphishing Link",
}


def _mitre_name(tech_id: str) -> str:
    return MITRE.get(tech_id, tech_id)


# ── Display Functions ────────────────────────────────────────────────────────


def _risk_bar(risk: float) -> str:
    filled = int(risk * 10)
    bar = "█" * filled + "░" * (10 - filled)
    if risk >= 0.85:
        return C.RED + bar + C.RESET
    if risk >= 0.7:
        return C.RED + bar + C.RESET
    if risk >= 0.4:
        return C.YELLOW + bar + C.RESET
    return C.GREEN + bar + C.RESET


def _ts_ago(ns: int) -> str:
    if not ns:
        return "?"
    age = time.time() - (ns / 1e9)
    if age < 60:
        return f"{age:.0f}s ago"
    if age < 3600:
        return f"{age / 60:.0f}m ago"
    if age < 86400:
        return f"{age / 3600:.1f}h ago"
    return f"{age / 86400:.1f}d ago"


def _parse_techs(raw: str) -> List[str]:
    if not raw:
        return []
    try:
        if raw.startswith("["):
            return json.loads(raw)
        return [raw]
    except Exception:
        return [raw] if raw else []


def show_posture():
    """Display current posture — the first thing the user sees."""
    p = get_posture()

    level_colors = {
        "NOMINAL": C.GREEN,
        "GUARDED": C.BLUE,
        "ELEVATED": C.YELLOW,
        "CRITICAL": C.RED + C.BOLD,
    }
    lc = level_colors.get(p["level"], C.WHITE)

    print()
    print(f"  {C.BOLD}AMOSKYS{C.RESET} {C.DIM}{VERSION}{C.RESET}")
    print(f"  {C.DIM}{p['device']}{C.RESET}")
    print()
    print(f"  Posture: {lc}{p['level']}{C.RESET}")
    print()
    print(f"  {p['security_events']:>6}  security events")
    print(f"  {p['observations']:>6}  observations")
    print(f"  {p['threats_high']:>6}  high-risk threats")
    print(f"  {p['threats_critical']:>6}  critical threats")
    print(f"  {p.get('fusion_incidents', 0):>6}  correlated incidents")
    if p["agents_queued"] > 0:
        print(f"  {p['agents_queued']:>6}  events pending in queue")
    print()


def show_threats(limit: int = 10):
    """Show recent high-risk events in narrative form."""
    threats = get_recent_threats(limit)
    if not threats:
        print(f"  {C.GREEN}No high-risk threats detected.{C.RESET}")
        return

    print(f"  {C.BOLD}Recent threats{C.RESET} ({len(threats)} shown)")
    print()
    for t in threats:
        risk = t.get("risk_score", 0)
        cat = t.get("event_category", "?")
        action = t.get("event_action", "")
        techs = _parse_techs(t.get("mitre_techniques", ""))
        ago = _ts_ago(t.get("event_timestamp_ns", 0))

        sev = "CRIT" if risk >= 0.85 else "HIGH" if risk >= 0.7 else "MED"
        sc = C.sev(sev.lower() if sev != "CRIT" else "critical")

        tech_str = ""
        if techs:
            tech_names = [_mitre_name(t) for t in techs[:2]]
            tech_str = f" {C.DIM}({', '.join(tech_names)}){C.RESET}"

        print(f"  {sc}{sev:4s}{C.RESET}  {_risk_bar(risk)}  {cat}")
        if action and action != cat:
            print(f"        {C.DIM}{action}{C.RESET}{tech_str}")
        elif tech_str:
            print(f"        {tech_str}")
        print(f"        {C.DIM}{ago}{C.RESET}")
        print()


def show_incidents(limit: int = 5):
    """Show fusion incidents as narratives."""
    incidents = get_fusion_incidents(limit)
    if not incidents:
        print(f"  {C.GREEN}No correlated incidents.{C.RESET}")
        return

    print(f"  {C.BOLD}Correlated incidents{C.RESET} ({len(incidents)} shown)")
    print()
    for inc in incidents:
        sev = inc.get("severity", "medium")
        rule = inc.get("rule_name", "?")
        summary = inc.get("summary", "")
        techs = _parse_techs(inc.get("techniques", ""))
        created = inc.get("created_at", "")[:19]

        sc = C.sev(sev)
        print(f"  {sc}{sev.upper():8s}{C.RESET}  {rule}")
        if summary:
            # Wrap summary nicely
            words = summary.split()
            line = "           "
            for w in words:
                if len(line) + len(w) > 78:
                    print(line)
                    line = "           "
                line += w + " "
            if line.strip():
                print(line)
        if techs:
            tech_names = [_mitre_name(t) for t in techs[:4]]
            print(f"           {C.DIM}Techniques: {', '.join(tech_names)}{C.RESET}")
        print(f"           {C.DIM}{created}{C.RESET}")
        print()


def show_signals(limit: int = 5):
    """Show IGRIS signals."""
    signals = get_signals(limit)
    if not signals:
        print(f"  {C.DIM}No IGRIS signals.{C.RESET}")
        return

    print(f"  {C.BOLD}IGRIS Signals{C.RESET}")
    print()
    for sig in signals:
        stype = sig.get("signal_type", "?")
        severity = sig.get("severity", "medium")
        msg = sig.get("message", "")
        status = sig.get("status", "active")

        sc = C.sev(severity)
        icon = "●" if status == "active" else "○"
        print(f"  {sc}{icon}{C.RESET} {stype}")
        if msg:
            print(f"    {C.DIM}{msg[:80]}{C.RESET}")
        print()


def show_igris():
    """Show IGRIS tactical briefing — what the minister is thinking."""
    try:
        from amoskys.igris.tactical import TACTICAL_LOG, read_directives
    except ImportError:
        print(f"  {C.DIM}IGRIS tactical module not available.{C.RESET}")
        return

    directives = read_directives()

    print(f"  {C.BOLD}IGRIS Tactical Briefing{C.RESET}")
    print()

    if not directives:
        print(f"  {C.DIM}No active directives. IGRIS is observing.{C.RESET}")

        # Check if tactical log exists for historical context
        if TACTICAL_LOG.exists():
            try:
                lines = TACTICAL_LOG.read_text().strip().split("\n")
                if lines:
                    last = json.loads(lines[-1])
                    print(
                        f"  {C.DIM}Last assessment: {last.get('posture', '?')} "
                        f"(threat={last.get('threat_level', 0):.0%}) "
                        f"— {last.get('reason', '')}{C.RESET}"
                    )
            except Exception:
                pass
        print()
        return

    # Posture
    posture = directives.get("posture", "NOMINAL")
    threat = directives.get("threat_level", 0)
    reason = directives.get("assessment_reason", "")
    hunt = directives.get("hunt_mode", False)

    posture_colors = {
        "NOMINAL": C.GREEN,
        "GUARDED": C.BLUE,
        "ELEVATED": C.YELLOW,
        "CRITICAL": C.RED + C.BOLD,
    }
    pc = posture_colors.get(posture, C.WHITE)

    print(f"  Posture:  {pc}{posture}{C.RESET} (threat: {_risk_bar(threat)})")
    print(f"  Reason:   {reason}")
    if hunt:
        print(
            f"  Mode:     {C.RED}{C.BOLD}HUNT{C.RESET} — all agents at maximum collection"
        )
    print()

    # Watched targets
    pids = directives.get("watched_pids", [])
    paths = directives.get("watched_paths", [])
    domains = directives.get("watched_domains", [])

    if pids or paths or domains:
        print(f"  {C.BOLD}Watched targets{C.RESET}")
        if pids:
            print(f"    PIDs:    {', '.join(pids[:10])}")
        if paths:
            for p in paths[:5]:
                print(f"    Path:    {p}")
        if domains:
            print(f"    Domains: {', '.join(domains[:5])}")
        print()

    # Active directives
    dirs = directives.get("directives", [])
    if dirs:
        print(f"  {C.BOLD}Active directives{C.RESET} ({len(dirs)})")
        for d in dirs[:8]:
            dtype = d.get("directive_type", "?")
            target = d.get("target", "?")
            urgency = d.get("urgency", "MEDIUM")
            reason_d = d.get("reason", "")

            uc = C.sev(urgency.lower())
            print(f"    {uc}{urgency:8s}{C.RESET} {dtype} → {target}")
            if reason_d:
                print(f"             {C.DIM}{reason_d[:70]}{C.RESET}")
        print()

    # Tactical log — last few decisions
    if TACTICAL_LOG.exists():
        try:
            lines = TACTICAL_LOG.read_text().strip().split("\n")
            recent = [json.loads(line) for line in lines[-5:]]
            if recent:
                print(f"  {C.BOLD}Recent tactical decisions{C.RESET}")
                for entry in reversed(recent):
                    ts = entry.get("timestamp", "")[:19]
                    p = entry.get("posture", "?")
                    _ = entry.get("threat_level", 0)
                    n_dirs = entry.get("directives_issued", 0)
                    assessed = entry.get("events_assessed", 0)
                    pc_r = posture_colors.get(p, C.DIM)
                    hunt_str = (
                        f" {C.RED}HUNT{C.RESET}" if entry.get("hunt_mode") else ""
                    )
                    print(
                        f"    {C.DIM}{ts}{C.RESET} {pc_r}{p:8s}{C.RESET} "
                        f"assessed={assessed} directives={n_dirs}{hunt_str}"
                    )
                print()
        except Exception:
            pass


def show_igris_why(target: str):
    """Explain WHY IGRIS is watching a specific target."""
    try:
        from amoskys.igris.tactical import read_directives
    except ImportError:
        print(f"  {C.DIM}IGRIS tactical module not available.{C.RESET}")
        return

    directives = read_directives()
    if not directives:
        print(f"  {C.DIM}No active directives.{C.RESET}")
        return

    if not target:
        # Show all watched targets with reasons
        print(f"  {C.BOLD}Why is IGRIS watching these targets?{C.RESET}")
        print()
        for d in directives.get("directives", []):
            dtype = d.get("directive_type", "?")
            tgt = d.get("target", "?")
            reason = d.get("reason", "no reason recorded")
            urgency = d.get("urgency", "MEDIUM")
            mitre = d.get("mitre_technique", "")

            uc = C.sev(urgency.lower())
            print(f"  {uc}{urgency:8s}{C.RESET} {dtype} → {tgt}")
            print(f"           {C.DIM}Why: {reason}{C.RESET}")
            if mitre:
                print(f"           {C.DIM}MITRE: {_mitre_name(mitre)}{C.RESET}")
            print()
        return

    # Search for specific target
    found = False
    for d in directives.get("directives", []):
        tgt = d.get("target", "")
        if target in tgt or tgt in target:
            found = True
            dtype = d.get("directive_type", "?")
            reason = d.get("reason", "no reason recorded")
            urgency = d.get("urgency", "MEDIUM")
            mitre = d.get("mitre_technique", "")
            source = d.get("source_event", "")

            uc = C.sev(urgency.lower())
            print(f"  {uc}{urgency}{C.RESET} {dtype} → {tgt}")
            print(f"  {C.BOLD}Why:{C.RESET} {reason}")
            if mitre:
                print(f"  MITRE: {_mitre_name(mitre)} ({mitre})")
            if source:
                print(f"  {C.DIM}Source event: {source[:60]}{C.RESET}")
            print()

    if not found:
        print(f"  {C.DIM}No active directive for '{target}'.{C.RESET}")


def show_search(query: str):
    """Search and display matching events."""
    results = search_events(query)
    if not results:
        print(f"  {C.DIM}No events matching '{query}'.{C.RESET}")
        return

    print(f"  {C.BOLD}Events matching '{query}'{C.RESET} ({len(results)} found)")
    print()
    for r in results:
        risk = r.get("risk_score", 0)
        cat = r.get("event_category", "?")
        action = r.get("event_action", "")
        ago = _ts_ago(r.get("event_timestamp_ns", 0))

        sev = (
            "CRIT"
            if risk >= 0.85
            else "HIGH" if risk >= 0.7 else "MED" if risk >= 0.4 else "LOW"
        )
        sc = C.sev(sev.lower() if sev != "CRIT" else "critical")

        # Try to extract useful details from raw_attributes
        details = ""
        raw = r.get("raw_attributes_json", "")
        if raw:
            try:
                attrs = json.loads(raw)
                desc = attrs.get("description", "")
                path = attrs.get("path", "")
                proc = attrs.get("process_name", "")
                if desc:
                    details = desc[:60]
                elif path:
                    details = path
                elif proc:
                    details = proc
            except Exception:
                pass

        print(f"  {sc}{sev:4s}{C.RESET}  {cat:30s} {C.DIM}{ago}{C.RESET}")
        if details:
            print(f"        {details}")
        print()


# ── Command Router ───────────────────────────────────────────────────────────

HELP_TEXT = f"""
  {C.BOLD}AMOSKYS Shell Commands{C.RESET}

  {C.CYAN}posture{C.RESET}              Current security posture
  {C.CYAN}threats{C.RESET}              Recent high-risk detections
  {C.CYAN}incidents{C.RESET}            Correlated attack incidents
  {C.CYAN}signals{C.RESET}             IGRIS supervisory signals
  {C.CYAN}events{C.RESET} [category]    Recent security events
  {C.CYAN}search{C.RESET} <keyword>     Search events by keyword
  {C.CYAN}process{C.RESET} <name>       Events related to a process
  {C.CYAN}keychain{C.RESET}            Keychain access events
  {C.CYAN}persistence{C.RESET}          Persistence mechanism events
  {C.CYAN}network{C.RESET}             Network/C2 events
  {C.CYAN}ssh{C.RESET}                 SSH authentication events

  {C.CYAN}igris{C.RESET}               IGRIS tactical briefing (what is the minister thinking?)
  {C.CYAN}status{C.RESET}              System status (agents, queues)
  {C.CYAN}igris{C.RESET}               IGRIS tactical briefing
  {C.CYAN}igris chain{C.RESET}         Kill chain state and progression
  {C.CYAN}igris why{C.RESET} [target]   Why a target is being watched
  {C.CYAN}igris inspect{C.RESET} <a> <t> On-demand investigation
  {C.CYAN}igris memory{C.RESET}        What IGRIS remembers
  {C.CYAN}igris novel{C.RESET}         SOMA: novel patterns

  {C.CYAN}help{C.RESET}                This help
  {C.CYAN}quit{C.RESET}                Exit shell

  {C.DIM}Or type a question in plain English:{C.RESET}
  {C.DIM}  "what happened?"       "show me suspicious processes"{C.RESET}
  {C.DIM}  "what touched keychain" "explain the last incident"{C.RESET}
"""


def _handle_natural_language(text: str):
    """Route natural language queries to the right engine query."""
    t = text.lower().strip()

    # Posture questions
    if any(w in t for w in ["posture", "how am i", "am i safe", "status", "overview"]):
        show_posture()
        return True

    # What happened
    if any(
        w in t for w in ["what happened", "what's going on", "whats going on", "recent"]
    ):
        show_posture()
        show_threats(5)
        return True

    # Threats
    if any(w in t for w in ["threat", "danger", "suspicious", "malicious"]):
        show_threats(10)
        return True

    # Incidents
    if any(w in t for w in ["incident", "attack", "chain", "kill chain"]):
        show_incidents(5)
        return True

    # Keychain
    if any(w in t for w in ["keychain", "credential", "password", "keychain"]):
        show_search("keychain")
        return True

    # Persistence
    if any(
        w in t for w in ["persist", "launchagent", "launchdaemon", "cron", "startup"]
    ):
        show_search("persistence")
        return True

    # Network/C2
    if any(w in t for w in ["network", "c2", "beacon", "connection", "exfil"]):
        show_search("c2_beacon")
        return True

    # SSH
    if any(w in t for w in ["ssh", "login", "brute"]):
        show_search("ssh")
        return True

    # Process
    if any(w in t for w in ["process", "running", "executed", "spawned"]):
        show_search("process")
        return True

    # Signals
    if any(w in t for w in ["signal", "igris", "health", "drift"]):
        show_signals()
        return True

    # Generic search — use the whole query
    show_search(text)
    return True


def handle_command(line: str) -> bool:
    """Process a single command. Returns False to exit."""
    parts = line.strip().split(None, 1)
    if not parts:
        return True

    cmd = parts[0].lower()
    arg = parts[1] if len(parts) > 1 else ""

    if cmd in ("quit", "exit", "q"):
        return False
    if cmd in ("help", "?", "h"):
        print(HELP_TEXT)
        return True
    if cmd == "posture":
        show_posture()
        return True
    if cmd == "threats":
        show_threats(int(arg) if arg.isdigit() else 10)
        return True
    if cmd == "incidents":
        show_incidents(int(arg) if arg.isdigit() else 5)
        return True
    if cmd == "signals":
        show_signals(int(arg) if arg.isdigit() else 5)
        return True
    if cmd == "events":
        if arg:
            results = get_recent_events(15, category=arg)
            if results:
                print(f"  {C.BOLD}Events: {arg}{C.RESET}")
                for r in results:
                    risk = r.get("risk_score", 0)
                    cat = r.get("event_category", "")
                    ago = _ts_ago(r.get("event_timestamp_ns", 0))
                    sev = (
                        "CRIT"
                        if risk >= 0.85
                        else "HIGH" if risk >= 0.7 else "MED" if risk >= 0.4 else "LOW"
                    )
                    print(
                        f"    {C.sev(sev.lower())}{sev:4s}{C.RESET} {cat:30s} {C.DIM}{ago}{C.RESET}"
                    )
            else:
                print(f"  {C.DIM}No events matching '{arg}'.{C.RESET}")
        else:
            show_threats(15)
        return True
    if cmd == "search":
        show_search(arg or "")
        return True
    if cmd == "process":
        show_search(arg or "process")
        return True
    if cmd in ("keychain", "credential"):
        show_search("keychain")
        return True
    if cmd == "persistence":
        show_search("persistence")
        return True
    if cmd in ("network", "c2"):
        show_search("c2_beacon")
        return True
    if cmd == "ssh":
        show_search("ssh")
        return True
    if cmd == "igris":
        if arg and arg.startswith("why"):
            show_igris_why(arg[3:].strip())
        else:
            show_igris()
        return True
    if cmd == "status":
        os.system(
            f"PYTHONPATH={PROJECT_ROOT / 'src'} {sys.executable} -m amoskys status"
        )
        return True

    # Try natural language
    return _handle_natural_language(line)


# ── Main Loop ────────────────────────────────────────────────────────────────


def main() -> int:
    # Show posture on launch
    show_posture()

    # Quick threat summary
    threats = get_recent_threats(3)
    if threats:
        print(f"  {C.YELLOW}Recent activity:{C.RESET}")
        for t in threats[:3]:
            risk = t.get("risk_score", 0)
            cat = t.get("event_category", "?")
            techs = _parse_techs(t.get("mitre_techniques", ""))
            tech_str = f" ({_mitre_name(techs[0])})" if techs else ""
            sev = "CRIT" if risk >= 0.85 else "HIGH" if risk >= 0.7 else "MED"
            print(
                f"    {C.sev(sev.lower())}{sev}{C.RESET} {cat}{C.DIM}{tech_str}{C.RESET}"
            )
        print()

    print(f"  {C.DIM}Type 'help' for commands, or ask a question.{C.RESET}")
    print()

    # REPL
    try:
        while True:
            try:
                line = input(f"  {C.CYAN}amoskys>{C.RESET} ")
            except EOFError:
                break

            if not line.strip():
                continue

            if not handle_command(line):
                break
    except KeyboardInterrupt:
        pass

    print()
    print(f"  {C.DIM}Session ended.{C.RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
