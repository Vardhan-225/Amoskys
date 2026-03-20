"""Shell commands for IGRIS v3 — wired into the interactive shell.

New commands:
    igris               — full tactical briefing (v3: chain + memory + SOMA)
    igris why [target]  — explain why each target is watched
    igris chain         — kill chain state and progression
    igris memory        — what IGRIS remembers across restarts
    igris inspect <action> <target>  — run on-demand investigation
    igris novel         — SOMA: show novel/never-seen patterns
    igris history       — posture transition history
    igris stats         — directive effectiveness statistics
    igris investigations — recent investigation results

These functions are imported by shell.py and registered as commands.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional


# ── Colors (same as shell.py) ────────────────────────────────────────────────


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

    @staticmethod
    def sev(s: str) -> str:
        s = (s or "").lower()
        if s in ("critical", "crit"):
            return C.RED + C.BOLD
        if s == "high":
            return C.RED
        if s in ("medium", "med"):
            return C.YELLOW
        return C.DIM


DATA_DIR = Path("data")
DIRECTIVES_FILE = DATA_DIR / "igris" / "directives.json"
TACTICAL_LOG = DATA_DIR / "igris" / "tactical.jsonl"


def _read_directives() -> Optional[dict]:
    if not DIRECTIVES_FILE.exists():
        return None
    try:
        data = json.loads(DIRECTIVES_FILE.read_text())
        age = time.time() - data.get("timestamp", 0)
        if age > 600:
            return None
        return data
    except Exception:
        return None


def _risk_bar(risk: float) -> str:
    filled = int(risk * 10)
    bar = "\u2588" * filled + "\u2591" * (10 - filled)
    if risk >= 0.85:
        return C.RED + bar + C.RESET
    if risk >= 0.7:
        return C.RED + bar + C.RESET
    if risk >= 0.4:
        return C.YELLOW + bar + C.RESET
    return C.GREEN + bar + C.RESET


def _ts_ago(ts: float) -> str:
    if not ts:
        return "?"
    age = time.time() - ts
    if age < 60:
        return f"{age:.0f}s ago"
    if age < 3600:
        return f"{age / 60:.0f}m ago"
    if age < 86400:
        return f"{age / 3600:.1f}h ago"
    return f"{age / 86400:.1f}d ago"


# ── Main Briefing ────────────────────────────────────────────────────────────


def show_igris_briefing():
    """Full IGRIS tactical briefing (v3)."""
    data = _read_directives()
    if not data:
        print(f"  {C.DIM}IGRIS is not running or has no recent assessment.{C.RESET}")
        return

    posture = data.get("posture", "?")
    threat = data.get("threat_level", 0)
    hunt = data.get("hunt_mode", False)
    reason = data.get("assessment_reason", "")
    chain_depth = data.get("chain_depth", 0)
    chain_narrative = data.get("chain_narrative", "")
    next_stage = data.get("next_predicted_stage", "")
    multiplier = data.get("threat_multiplier", 1.0)
    trend = data.get("posture_trend", "stable")
    novel = data.get("novel_events", 0)

    posture_colors = {
        "NOMINAL": C.GREEN,
        "GUARDED": C.BLUE,
        "ELEVATED": C.YELLOW,
        "CRITICAL": C.RED + C.BOLD,
    }
    pc = posture_colors.get(posture, C.DIM)
    trend_icons = {"improving": "\u2193", "stable": "\u2192", "degrading": "\u2191"}
    ti = trend_icons.get(trend, "?")

    print()
    print(f"  {C.BOLD}IGRIS Tactical Briefing{C.RESET}")
    print()
    print(f"  Posture:  {pc}{posture}{C.RESET} (threat: {_risk_bar(threat)}) {C.DIM}{ti} {trend}{C.RESET}")
    print(f"  Reason:   {reason}")

    if hunt:
        print(f"  Mode:     {C.RED}{C.BOLD}HUNT{C.RESET} \u2014 all agents at maximum collection")

    # Kill chain
    if chain_narrative:
        print()
        print(f"  {C.BOLD}Kill Chain{C.RESET}")
        for line in chain_narrative.split("\n"):
            print(f"    {line}")
        if multiplier > 1.0:
            print(f"    Threat multiplier: {C.RED}{multiplier}x{C.RESET}")

    if next_stage:
        print(f"    {C.YELLOW}Next predicted: {next_stage}{C.RESET}")

    # Novelty
    if novel > 0:
        print(f"\n  {C.MAGENTA}Novel patterns: {novel}{C.RESET} (never seen before)")

    # Watched targets
    directives = data.get("directives", [])
    pids = data.get("watched_pids", [])
    paths = data.get("watched_paths", [])
    domains = data.get("watched_domains", [])

    if pids or paths or domains:
        print()
        print(f"  {C.BOLD}Watched Targets{C.RESET}")
        if pids:
            print(f"    PIDs:    {', '.join(pids[:10])}")
        for p in paths[:5]:
            print(f"    Path:    {p}")
        if domains:
            print(f"    Domains: {', '.join(domains[:5])}")

    # Directives with chain stage and novelty
    if directives:
        print()
        print(f"  {C.BOLD}Active Directives{C.RESET} ({len(directives)})")
        for d in directives[:8]:
            urgency = d.get("urgency", "?")
            dtype = d.get("directive_type", "?")
            target = d.get("target", "?")
            dreason = d.get("reason", "")
            stage = d.get("chain_stage", "")
            novelty_val = d.get("novelty", 0)

            uc = C.sev(urgency)
            stage_str = f" {C.CYAN}[{stage}]{C.RESET}" if stage else ""
            novel_str = f" {C.MAGENTA}(NOVEL){C.RESET}" if novelty_val > 0.5 else ""

            print(f"    {uc}{urgency:8s}{C.RESET} {dtype} {target}{stage_str}{novel_str}")
            print(f"             {C.DIM}{dreason[:70]}{C.RESET}")

    # Memory stats from tactical log
    _show_tactical_log_summary()
    print()


def _show_tactical_log_summary():
    """Show recent tactical log summary."""
    if not TACTICAL_LOG.exists():
        return
    try:
        lines = TACTICAL_LOG.read_text().strip().split("\n")
        recent = []
        for line in lines[-5:]:
            try:
                recent.append(json.loads(line))
            except Exception:
                pass
        if recent:
            print()
            print(f"  {C.BOLD}Recent Decisions{C.RESET}")
            for entry in recent:
                ts = entry.get("timestamp", "")[:19]
                posture = entry.get("posture", "?")
                chain_stages = entry.get("chain_stages", 0)
                novel_val = entry.get("novel_events", 0)
                dirs = entry.get("directives_issued", 0)
                print(
                    f"    {C.DIM}{ts}{C.RESET} "
                    f"posture={posture} chain={chain_stages}/7 "
                    f"novel={novel_val} directives={dirs}"
                )
    except Exception:
        pass


# ── Kill Chain ───────────────────────────────────────────────────────────────


def show_igris_chain():
    """Show kill chain state and progression."""
    data = _read_directives()
    if not data:
        print(f"  {C.DIM}IGRIS is not running.{C.RESET}")
        return

    chain_narrative = data.get("chain_narrative", "")
    chain_depth = data.get("chain_depth", 0)
    next_stage = data.get("next_predicted_stage", "")
    multiplier = data.get("threat_multiplier", 1.0)

    stages = [
        "reconnaissance",
        "weaponization",
        "delivery",
        "exploitation",
        "installation",
        "command_and_control",
        "actions_on_objectives",
    ]

    print()
    print(f"  {C.BOLD}Kill Chain Status{C.RESET} (depth: {_risk_bar(chain_depth)})")
    print()

    # Visual chain
    for i, stage in enumerate(stages):
        icon = "\u25cf" if stage in chain_narrative.lower() else "\u25cb"
        color = C.RED if stage in chain_narrative.lower() else C.DIM
        arrow = " \u2192 " if stage == next_stage else "   "
        next_indicator = f" {C.YELLOW}\u2190 PREDICTED NEXT{C.RESET}" if stage == next_stage else ""
        print(f"    {color}{icon}{C.RESET} {i + 1}. {stage}{next_indicator}")

    if chain_narrative:
        print()
        for line in chain_narrative.split("\n"):
            print(f"    {line}")

    if multiplier > 1.0:
        print(f"\n    Threat multiplier: {C.RED}{multiplier}x{C.RESET}")
    print()


# ── Why ──────────────────────────────────────────────────────────────────────


def show_igris_why(target: str = ""):
    """Explain why targets are being watched."""
    data = _read_directives()
    if not data:
        print(f"  {C.DIM}IGRIS is not running.{C.RESET}")
        return

    directives = data.get("directives", [])
    if not directives:
        print(f"  {C.GREEN}No active watch directives.{C.RESET}")
        return

    # Filter by target if specified
    if target:
        directives = [
            d for d in directives if target in str(d.get("target", ""))
        ]
        if not directives:
            print(f"  {C.DIM}No directives matching '{target}'.{C.RESET}")
            return

    print()
    print(f"  {C.BOLD}Why is IGRIS watching these targets?{C.RESET}")
    print()

    for d in directives[:15]:
        dtype = d.get("directive_type", "?")
        dtarget = d.get("target", "?")
        dreason = d.get("reason", "")
        urgency = d.get("urgency", "?")
        tech = d.get("mitre_technique", "")
        stage = d.get("chain_stage", "")
        novelty_val = d.get("novelty", 0)
        issued = d.get("issued_at", 0)

        uc = C.sev(urgency)
        print(f"  {uc}{dtype}{C.RESET} {C.BOLD}{dtarget}{C.RESET}")
        print(f"    Why:      {dreason}")
        if tech:
            print(f"    MITRE:    {tech}")
        if stage:
            print(f"    Chain:    {stage}")
        if novelty_val > 0.5:
            print(f"    Novelty:  {C.MAGENTA}NOVEL — never seen before{C.RESET}")
        else:
            print(f"    Novelty:  {C.DIM}Known pattern{C.RESET}")
        print(f"    Issued:   {_ts_ago(issued)}")
        print()


# ── Inspect ──────────────────────────────────────────────────────────────────


def show_igris_inspect(args: str):
    """Run an on-demand investigation.

    Usage:
        igris inspect codesign /path/to/binary
        igris inspect connections 1234
        igris inspect children 1234
        igris inspect xattr /path/to/file
        igris inspect plist /path/to/file.plist
        igris inspect hash /path/to/file
        igris inspect lsof 1234
        igris inspect environ 1234
    """
    parts = args.strip().split(None, 1)
    if len(parts) < 2:
        print(f"  {C.DIM}Usage: igris inspect <action> <target>{C.RESET}")
        print(f"  {C.DIM}Actions: codesign, connections, children, xattr, plist, hash, lsof, environ{C.RESET}")
        return

    action_map = {
        "codesign": "INSPECT_CODESIGN",
        "connections": "INSPECT_CONNECTIONS",
        "children": "INSPECT_CHILDREN",
        "xattr": "INSPECT_XATTR",
        "plist": "INSPECT_PLIST",
        "hash": "INSPECT_FILE_HASH",
        "lsof": "INSPECT_LSOF",
        "environ": "INSPECT_ENVIRON",
    }

    action_key = parts[0].lower()
    target = parts[1]
    action = action_map.get(action_key)

    if not action:
        print(f"  {C.DIM}Unknown action: {action_key}{C.RESET}")
        return

    try:
        from amoskys.igris.inspector import IGRISInspector

        inspector = IGRISInspector()
        print(f"  {C.DIM}Inspecting...{C.RESET}")
        result = inspector.inspect(action, target)

        # Display result
        vc = C.sev(result.verdict)
        print()
        print(f"  {C.BOLD}{action}{C.RESET} on {target}")
        print(f"  Verdict: {vc}{result.verdict.upper()}{C.RESET}")
        print(f"  Duration: {result.duration_ms:.0f}ms")
        print()

        # Pretty-print key data
        for key, value in result.data.items():
            if key in ("error",):
                print(f"  {C.RED}{key}: {value}{C.RESET}")
            elif key in ("suspicious_indicators", "suspicious_vars") and value:
                print(f"  {C.YELLOW}{key}:{C.RESET}")
                for item in value:
                    print(f"    {C.YELLOW}\u26a0 {item}{C.RESET}")
            elif key in ("authorities", "connections", "children", "open_files", "parent_chain"):
                if isinstance(value, list) and value:
                    print(f"  {key}: ({len(value)} items)")
                    for item in value[:10]:
                        if isinstance(item, dict):
                            summary = " ".join(f"{k}={v}" for k, v in item.items())
                            print(f"    {C.DIM}{summary[:80]}{C.RESET}")
                        else:
                            print(f"    {C.DIM}{item}{C.RESET}")
                    if len(value) > 10:
                        print(f"    {C.DIM}... and {len(value) - 10} more{C.RESET}")
            elif isinstance(value, (str, int, float, bool)):
                print(f"  {key}: {value}")
        print()

    except ImportError:
        print(f"  {C.RED}Inspector module not available.{C.RESET}")
    except Exception as e:
        print(f"  {C.RED}Inspection failed: {e}{C.RESET}")


# ── Memory ───────────────────────────────────────────────────────────────────


def show_igris_memory():
    """Show what IGRIS remembers across restarts."""
    try:
        from amoskys.igris.memory import IGRISMemory

        mem = IGRISMemory()

        print()
        print(f"  {C.BOLD}IGRIS Memory{C.RESET}")

        # State
        state = mem.load_state()
        if state:
            print(f"\n  {C.CYAN}Restored State{C.RESET}")
            print(f"    Posture:  {state.get('posture', '?')}")
            print(f"    Threat:   {state.get('threat_level', 0):.0%}")
            print(f"    Hunt:     {state.get('hunt_mode', False)}")
            print(f"    Chain:    {state.get('chain_depth', 0):.0%} depth")
        else:
            print(f"\n  {C.DIM}No saved state (fresh start).{C.RESET}")

        # Watched targets
        watches = mem.get_active_watches()
        if watches:
            print(f"\n  {C.CYAN}Active Watches{C.RESET} ({len(watches)})")
            for w in watches[:10]:
                times = w.get("times_seen", 1)
                reason_str = w.get("reason", "")[:60]
                print(
                    f"    {w['target_type']:6s} {w['target']:30s} "
                    f"seen={times}x {C.DIM}{reason_str}{C.RESET}"
                )

        # Directive stats
        stats = mem.get_directive_stats()
        if stats["total"] > 0:
            print(f"\n  {C.CYAN}Directive Statistics{C.RESET}")
            print(f"    Total issued:  {stats['total']}")
            print(f"    Acknowledged:  {stats['acknowledged']}")
            print(f"    Useful:        {stats['useful']}")
            print(f"    Noise:         {stats['noise']}")
            print(f"    Last hour:     {stats['recent_1h']}")
            print(f"    Effectiveness: {stats['effectiveness']:.0%}")

        # Posture history
        history = mem.get_posture_history(5)
        if history:
            print(f"\n  {C.CYAN}Posture History{C.RESET}")
            for h in history:
                print(
                    f"    {_ts_ago(h['timestamp'])} "
                    f"{h['from_posture']} \u2192 {h['to_posture']} "
                    f"({h['reason'][:50]})"
                )

        # Investigations
        investigations = mem.get_investigation_results(limit=5)
        if investigations:
            print(f"\n  {C.CYAN}Recent Investigations{C.RESET}")
            for inv in investigations:
                vc = C.sev(inv.get("verdict", ""))
                print(
                    f"    {inv['action_type']:22s} {inv['target']:30s} "
                    f"{vc}{inv.get('verdict', '?').upper()}{C.RESET}"
                )

        mem.close()
        print()

    except ImportError:
        print(f"  {C.RED}Memory module not available.{C.RESET}")
    except Exception as e:
        print(f"  {C.RED}Memory read failed: {e}{C.RESET}")


# ── SOMA Novel ───────────────────────────────────────────────────────────────


def show_igris_novel():
    """Show SOMA: novel/never-seen patterns."""
    try:
        from amoskys.igris.memory import IGRISMemory

        mem = IGRISMemory()
        novel = mem.soma_novel_events(3600)
        mem.close()

        if not novel:
            print(f"  {C.GREEN}No novel patterns in the last hour.{C.RESET}")
            return

        print()
        print(f"  {C.BOLD}{C.MAGENTA}SOMA: Novel Patterns{C.RESET} ({len(novel)} in last hour)")
        print()
        for n in novel:
            risk = n.get("risk_score", 0)
            rc = C.sev("high" if risk >= 0.7 else "medium" if risk >= 0.4 else "low")
            print(
                f"  {rc}{n['event_category']:30s}{C.RESET} "
                f"risk={risk:.2f} "
                f"{C.DIM}{n.get('process_name', '')}{C.RESET}"
            )
            if n.get("path"):
                print(f"    path: {n['path'][:60]}")
        print()

    except ImportError:
        print(f"  {C.RED}Memory module not available.{C.RESET}")
    except Exception as e:
        print(f"  {C.RED}SOMA query failed: {e}{C.RESET}")


# ── Command Router ───────────────────────────────────────────────────────────


def handle_igris_command(args: str) -> bool:
    """Route igris subcommands."""
    parts = args.strip().split(None, 1)
    subcmd = parts[0].lower() if parts else ""
    subargs = parts[1] if len(parts) > 1 else ""

    if not subcmd or subcmd == "briefing":
        show_igris_briefing()
    elif subcmd == "chain":
        show_igris_chain()
    elif subcmd == "why":
        show_igris_why(subargs)
    elif subcmd == "inspect":
        show_igris_inspect(subargs)
    elif subcmd == "memory":
        show_igris_memory()
    elif subcmd == "novel":
        show_igris_novel()
    elif subcmd == "history":
        show_igris_memory()  # includes history
    elif subcmd == "stats":
        show_igris_memory()  # includes stats
    else:
        print(f"  {C.DIM}Unknown igris command: {subcmd}{C.RESET}")
        print(f"  {C.DIM}Available: chain, why, inspect, memory, novel, history, stats{C.RESET}")

    return True
