#!/usr/bin/env python3
"""
AMOSKYS Continuous Security Daemon
====================================
IGRIS-supervised endpoint security daemon with full pipeline visibility.

Four threads run simultaneously:
  1. CollectionRunner — calls collect_and_store.py on interval (10-30s)
  2. AlertMonitor     — polls ALL DB tables for new detections, streams alerts
  3. AutoResponder    — confidence-gated response actions (quarantine, kill, block)
  4. IGRIS Supervisor — 60s observation cycles, organism coherence, signal governance

Usage:
    # Start daemon with 10-second collection cycles, dry-run response:
    PYTHONPATH=src python -m amoskys.daemon --interval 10 --respond

    # Live response (actually kills processes, quarantines files):
    PYTHONPATH=src python -m amoskys.daemon --interval 10 --respond-live

    # Detection only (no auto-response):
    PYTHONPATH=src python -m amoskys.daemon --interval 15

    # Minimum severity filter (only HIGH and CRITICAL):
    PYTHONPATH=src python -m amoskys.daemon --interval 10 --min-severity high
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

ROOT = Path(__file__).resolve().parent.parent.parent
DB_PATH = ROOT / "data" / "telemetry.db"
FUSION_DB_PATH = ROOT / "data" / "intel" / "fusion.db"
COLLECT_SCRIPT = ROOT / "scripts" / "collect_and_store.py"

# Severity ordering for filtering
SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# ─── ANSI Colors ────────────────────────────────────────────────


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
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_YELLOW = "\033[43m"
    GREY = "\033[90m"

    @staticmethod
    def sev(s: str) -> str:
        s = (s or "info").lower()
        if s == "critical":
            return f"{C.BG_RED}{C.WHITE}{C.BOLD}"
        elif s == "high":
            return C.RED
        elif s == "medium":
            return C.YELLOW
        elif s == "low":
            return C.CYAN
        return C.DIM


# ─── MITRE Reference ─────────────────────────────────────────────

MITRE = {
    "T1005": "Data from Local System",
    "T1016": "System Network Config",
    "T1018": "Remote System Discovery",
    "T1021.004": "SSH Lateral Movement",
    "T1036.005": "Masquerading",
    "T1040": "Network Sniffing",
    "T1041": "Exfil Over C2",
    "T1046": "Network Service Discovery",
    "T1048": "Exfil Over Alt Protocol",
    "T1053.003": "Cron",
    "T1056.002": "GUI Input Capture",
    "T1059.002": "AppleScript",
    "T1059.004": "Unix Shell",
    "T1059.007": "JavaScript",
    "T1071": "Application Layer Protocol",
    "T1071.001": "Web Protocols",
    "T1071.004": "DNS",
    "T1078": "Valid Accounts",
    "T1082": "System Info Discovery",
    "T1083": "File & Dir Discovery",
    "T1098.004": "SSH Authorized Keys",
    "T1105": "Ingress Tool Transfer",
    "T1110": "Brute Force",
    "T1110.001": "Password Guessing",
    "T1113": "Screen Capture",
    "T1115": "Clipboard Data",
    "T1190": "Exploit Public-Facing App",
    "T1200": "Hardware Additions",
    "T1204.002": "Malicious File",
    "T1218": "System Binary Proxy Exec",
    "T1496": "Resource Hijacking",
    "T1498": "Network DoS",
    "T1539": "Steal Session Cookie",
    "T1543.001": "Launch Agent",
    "T1543.004": "Launch Daemon",
    "T1546.004": "Shell Config Mod",
    "T1548": "Abuse Elevation",
    "T1548.003": "Sudo Abuse",
    "T1553": "Subvert Trust Controls",
    "T1553.001": "Gatekeeper Bypass",
    "T1555.001": "Keychain",
    "T1555.003": "Browser Credentials",
    "T1557.002": "ARP Cache Poisoning",
    "T1560.001": "Archive Collected Data",
    "T1562.001": "Disable Security Tools",
    "T1564.001": "Hidden Files",
    "T1566": "Phishing",
    "T1567.002": "Exfil to Cloud",
    "T1568.001": "Fast Flux DNS",
    "T1568.002": "DGA",
    "T1571": "Non-Standard Port",
    "T1572": "Protocol Tunneling",
    "T1574.004": "Dylib Hijacking",
    "T1574.006": "Dylib Injection",
    "T1595": "Active Scanning",
    "T1595.002": "Vulnerability Scanning",
}


# ─── DB Helpers ─────────────────────────────────────────────────


def _query(sql: str, params: tuple = (), db_path: Path = DB_PATH) -> List[dict]:
    if not db_path.exists():
        return []
    conn = sqlite3.connect(str(db_path), timeout=5)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()


def _table_count(table: str, db_path: Path = DB_PATH) -> int:
    rows = _query(f"SELECT COUNT(*) as cnt FROM {table}", db_path=db_path)
    return rows[0]["cnt"] if rows else 0


def _parse_techniques(raw: str) -> List[str]:
    """Parse MITRE techniques from JSON or plain string."""
    if not raw:
        return []
    try:
        if raw.startswith("["):
            return json.loads(raw)
        return [raw]
    except (json.JSONDecodeError, TypeError):
        return [raw] if raw else []


def _risk_to_severity(risk: float) -> str:
    """Map risk score to severity label."""
    if risk >= 0.85:
        return "critical"
    elif risk >= 0.7:
        return "high"
    elif risk >= 0.4:
        return "medium"
    elif risk >= 0.2:
        return "low"
    return "info"


# ─── Collection Runner ─────────────────────────────────────────


class CollectionRunner(threading.Thread):
    """Runs collect_and_store.py on a fixed interval."""

    def __init__(self, interval: float, stop_event: threading.Event):
        super().__init__(daemon=True, name="collector")
        self.interval = interval
        self.stop = stop_event
        self.cycle_count = 0
        self.last_duration = 0.0
        self.last_error: Optional[str] = None
        self.consecutive_failures = 0

    def run(self):
        env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
        while not self.stop.is_set():
            t0 = time.time()
            try:
                result = subprocess.run(
                    [sys.executable, str(COLLECT_SCRIPT)],
                    cwd=str(ROOT),
                    env=env,
                    capture_output=True,
                    timeout=180,
                )
                self.cycle_count += 1
                self.last_duration = time.time() - t0
                if result.returncode != 0:
                    stderr = result.stderr.decode("utf-8", errors="replace")[-200:]
                    self.last_error = f"exit={result.returncode}: {stderr}"
                    self.consecutive_failures += 1
                    _log("WARN", f"Collection exit {result.returncode}")
                else:
                    self.last_error = None
                    self.consecutive_failures = 0
            except subprocess.TimeoutExpired:
                self.last_error = "Timeout (180s)"
                self.consecutive_failures += 1
                _log("WARN", "Collection cycle timed out (180s)")
            except Exception as e:
                self.last_error = str(e)
                self.consecutive_failures += 1
                _log("ERROR", f"Collection failed: {e}")

            self.stop.wait(self.interval)


# ─── Alert Monitor (Full Vision) ────────────────────────────────


class AlertMonitor(threading.Thread):
    """Polls ALL critical DB tables for new detections."""

    def __init__(
        self,
        stop_event: threading.Event,
        responder: Optional["AutoResponder"] = None,
        min_severity: str = "info",
    ):
        super().__init__(daemon=True, name="alert-monitor")
        self.stop = stop_event
        self.responder = responder
        self.min_severity = SEV_ORDER.get(min_severity.lower(), 0)
        self.alert_count = 0
        self.incident_count = 0

        # Watermarks for each table (row counts or max IDs)
        self._wm: Dict[str, int] = {}
        # Dedup: (table, event_category, first_technique) -> last_alert_ts
        self._dedup: Dict[str, float] = {}
        self._dedup_cooldown = 30.0  # seconds between duplicate alerts

        # Story mode state
        self._story_engine = None
        self._narrator = None
        self._last_story_check = 0.0
        self._story_interval = 30  # Check for new stories every 30s
        self._seen_story_ids: Set[str] = set()

    def run(self):
        # Initialize watermarks from existing data
        for table in [
            "security_events",
            "persistence_events",
            "flow_events",
            "dns_events",
            "fim_events",
            "audit_events",
        ]:
            self._wm[table] = _table_count(table)
        self._wm["process_suspicious"] = self._count_suspicious()
        self._wm["incidents"] = _table_count("incidents")
        # Fusion DB incidents
        self._wm["fusion_incidents"] = _table_count("incidents", db_path=FUSION_DB_PATH)

        while not self.stop.is_set():
            self._check_security_events()
            self._check_persistence_events()
            self._check_suspicious_processes()
            self._check_flow_events()
            self._check_dns_events()
            self._check_fim_events()
            self._check_fusion_incidents()
            self._check_telemetry_incidents()
            self._check_stories()
            self.stop.wait(1.0)

    def _count_suspicious(self) -> int:
        rows = _query(
            "SELECT COUNT(*) as cnt FROM process_events WHERE is_suspicious = 1"
        )
        return rows[0]["cnt"] if rows else 0

    # ── Security Events ──

    def _check_security_events(self):
        current = _table_count("security_events")
        prev = self._wm.get("security_events", 0)
        if current <= prev:
            return
        new_rows = _query(
            "SELECT * FROM security_events ORDER BY rowid DESC LIMIT ?",
            (current - prev,),
        )
        for ev in reversed(new_rows):
            risk = ev.get("risk_score", 0) or 0
            severity = _risk_to_severity(risk)
            if SEV_ORDER.get(severity, 0) < self.min_severity:
                continue

            techs = _parse_techniques(ev.get("mitre_techniques", ""))
            tech = techs[0] if techs else ""
            cat = ev.get("event_category", "")

            if not self._should_alert("sec", cat, tech):
                continue

            self._emit(
                tag="ALERT",
                bg=C.BG_RED,
                severity=severity,
                tech=tech,
                tech_name=MITRE.get(tech, ""),
                detail=f"agent={ev.get('collection_agent', '?')} "
                f"risk={risk:.2f} cat={cat}",
            )
            if self.responder:
                self.responder.handle(ev, severity)
        self._wm["security_events"] = current

    # ── Persistence Events ──

    def _check_persistence_events(self):
        current = _table_count("persistence_events")
        prev = self._wm.get("persistence_events", 0)
        if current <= prev:
            return
        new_rows = _query(
            "SELECT * FROM persistence_events ORDER BY rowid DESC LIMIT ?",
            (current - prev,),
        )
        mech_to_mitre = {
            "launchagent_user": "T1543.001",
            "launchagent_system": "T1543.001",
            "launchdaemon": "T1543.004",
            "cron": "T1053.003",
            "shell_profile": "T1546.004",
            "ssh": "T1098.004",
            "folder_action": "T1546.015",
        }
        for ev in reversed(new_rows):
            mechanism = ev.get("mechanism", "?")
            path = ev.get("path", ev.get("entry_path", "?"))
            tech = mech_to_mitre.get(mechanism, "")
            self._emit(
                tag="PERSIST",
                bg=C.BG_MAGENTA,
                severity="high",
                tech=tech,
                tech_name=MITRE.get(tech, mechanism),
                detail=f"mechanism={mechanism} path={str(path)[:60]}",
            )
            if self.responder:
                self.responder.handle_persistence(ev, mechanism, path)
        self._wm["persistence_events"] = current

    # ── Suspicious Processes ──

    def _check_suspicious_processes(self):
        current = self._count_suspicious()
        prev = self._wm.get("process_suspicious", 0)
        if current <= prev:
            return
        new_rows = _query(
            "SELECT * FROM process_events WHERE is_suspicious = 1 "
            "ORDER BY rowid DESC LIMIT ?",
            (current - prev,),
        )
        for ev in reversed(new_rows):
            name = ev.get("name", "?")
            exe = ev.get("exe", "?")
            pid = ev.get("pid", "?")
            self._emit(
                tag="PROC",
                bg=C.BG_BLUE,
                severity="medium",
                tech="",
                tech_name=f"Suspicious: {name}",
                detail=f"pid={pid} exe={str(exe)[:50]}",
            )
        self._wm["process_suspicious"] = current

    # ── Flow Events (Network) ──

    def _check_flow_events(self):
        current = _table_count("flow_events")
        prev = self._wm.get("flow_events", 0)
        if current <= prev:
            return
        # Only alert on high-risk flows
        new_rows = _query(
            "SELECT * FROM flow_events WHERE risk_score >= 0.6 "
            "ORDER BY rowid DESC LIMIT ?",
            (current - prev,),
        )
        for ev in reversed(new_rows):
            risk = ev.get("risk_score", 0) or 0
            severity = _risk_to_severity(risk)
            if SEV_ORDER.get(severity, 0) < self.min_severity:
                continue
            direction = ev.get("direction", "?")
            remote = ev.get("remote_ip", ev.get("dst_ip", "?"))
            port = ev.get("remote_port", ev.get("dst_port", "?"))
            proto = ev.get("protocol", "?")
            cat = ev.get("event_category", "flow")

            if not self._should_alert("flow", cat, remote):
                continue

            self._emit(
                tag="FLOW",
                bg=C.BG_CYAN,
                severity=severity,
                tech="T1071",
                tech_name="Network Activity",
                detail=f"{direction} {remote}:{port}/{proto} risk={risk:.2f} cat={cat}",
            )
        self._wm["flow_events"] = current

    # ── DNS Events ──

    def _check_dns_events(self):
        current = _table_count("dns_events")
        prev = self._wm.get("dns_events", 0)
        if current <= prev:
            return
        new_rows = _query(
            "SELECT * FROM dns_events WHERE risk_score >= 0.5 "
            "ORDER BY rowid DESC LIMIT ?",
            (current - prev,),
        )
        for ev in reversed(new_rows):
            risk = ev.get("risk_score", 0) or 0
            severity = _risk_to_severity(risk)
            if SEV_ORDER.get(severity, 0) < self.min_severity:
                continue
            domain = ev.get("query_name", ev.get("domain", "?"))
            cat = ev.get("event_category", "dns")

            if not self._should_alert("dns", cat, domain):
                continue

            techs = _parse_techniques(ev.get("mitre_techniques", ""))
            tech = techs[0] if techs else "T1071.004"
            self._emit(
                tag="DNS",
                bg=C.BG_BLUE,
                severity=severity,
                tech=tech,
                tech_name=MITRE.get(tech, "DNS"),
                detail=f"domain={str(domain)[:40]} risk={risk:.2f} cat={cat}",
            )
        self._wm["dns_events"] = current

    # ── FIM Events ──

    def _check_fim_events(self):
        current = _table_count("fim_events")
        prev = self._wm.get("fim_events", 0)
        if current <= prev:
            return
        new_rows = _query(
            "SELECT * FROM fim_events WHERE risk_score >= 0.6 "
            "ORDER BY rowid DESC LIMIT ?",
            (current - prev,),
        )
        for ev in reversed(new_rows):
            risk = ev.get("risk_score", 0) or 0
            severity = _risk_to_severity(risk)
            if SEV_ORDER.get(severity, 0) < self.min_severity:
                continue
            path = ev.get("path", ev.get("file_path", "?"))
            action = ev.get("action", ev.get("event_action", "?"))

            if not self._should_alert("fim", action, str(path)):
                continue

            self._emit(
                tag="FIM",
                bg=C.BG_YELLOW,
                severity=severity,
                tech="T1565",
                tech_name="File Integrity",
                detail=f"action={action} path={str(path)[:50]} risk={risk:.2f}",
            )
        self._wm["fim_events"] = current

    # ── Fusion Incidents (CRITICAL — correlated multi-stage attacks) ──

    def _check_fusion_incidents(self):
        current = _table_count("incidents", db_path=FUSION_DB_PATH)
        prev = self._wm.get("fusion_incidents", 0)
        if current <= prev:
            return
        new_rows = _query(
            "SELECT * FROM incidents ORDER BY rowid DESC LIMIT ?",
            (current - prev,),
            db_path=FUSION_DB_PATH,
        )
        for inc in reversed(new_rows):
            self.incident_count += 1
            severity = (inc.get("severity", "high") or "high").lower()
            rule = inc.get("rule_name", "?")
            summary = inc.get("summary", "")
            tactics = inc.get("tactics", "")
            techniques = inc.get("techniques", "")
            confidence = inc.get("weighted_confidence", 0) or 0
            techs = _parse_techniques(techniques)
            tech = techs[0] if techs else ""

            self._emit_incident(severity, rule, summary, tech, tactics, confidence)

            if self.responder and severity in ("critical", "high"):
                self.responder.handle_incident(inc)
        self._wm["fusion_incidents"] = current

    # ── Telemetry DB Incidents ──

    def _check_telemetry_incidents(self):
        current = _table_count("incidents")
        prev = self._wm.get("incidents", 0)
        if current <= prev:
            return
        # These are bridged from fusion — avoid double-alerting on
        # incidents we already saw from fusion.db
        self._wm["incidents"] = current

    # ── Story Mode ──

    def _init_story_mode(self):
        """Initialize story mode — template narration of fusion incidents."""
        try:
            from amoskys.igris.narrator import Narrator
            from amoskys.intel.story_engine import StoryEngine

            self._story_engine = StoryEngine(
                telemetry_db=str(DB_PATH),
                fusion_db=str(FUSION_DB_PATH),
            )
            self._narrator = Narrator(use_claude=False)
            _log("INFO", "Story mode enabled (template narration)")
        except Exception as e:
            _log("WARN", f"Story mode unavailable: {e}")
            self._story_engine = None
            self._narrator = None

    def _check_stories(self):
        """Build and display IGRIS briefings for new fusion incidents."""
        if not self._story_engine or not self._narrator:
            return

        now = time.time()
        if now - self._last_story_check < self._story_interval:
            return
        self._last_story_check = now

        try:
            stories = self._story_engine.build_stories(
                hours=1,
                min_severity="high",
            )
            for story in stories:
                if story.story_id not in self._seen_story_ids:
                    self._emit_story(story)
        except Exception as e:
            _log("WARN", f"Story check failed: {e}")

    def _emit_story(self, story):
        """Narrate and display a single attack story."""
        self._seen_story_ids.add(story.story_id)
        briefing = self._narrator.narrate(story)
        print(briefing.to_terminal())

        if self.responder:
            for stage in story.kill_chain:
                for ev in stage.events[:1]:
                    self.responder.handle(ev, story.severity)

        self.incident_count += 1

    # ── Emit helpers ──

    def _should_alert(self, source: str, category: str, key: str) -> bool:
        """Dedup gate: suppress duplicate alerts within cooldown window."""
        dedup_key = f"{source}:{category}:{key}"
        now = time.time()
        last = self._dedup.get(dedup_key, 0)
        if now - last < self._dedup_cooldown:
            return False
        self._dedup[dedup_key] = now
        # Prevent unbounded growth
        if len(self._dedup) > 5000:
            cutoff = now - self._dedup_cooldown * 2
            self._dedup = {k: v for k, v in self._dedup.items() if v > cutoff}
        return True

    def _emit(
        self,
        tag: str,
        bg: str,
        severity: str,
        tech: str,
        tech_name: str,
        detail: str,
    ):
        self.alert_count += 1
        ts = datetime.now().strftime("%H:%M:%S")
        sev_c = C.sev(severity)
        print(
            f"  {C.DIM}{ts}{C.RESET} "
            f"{bg}{C.WHITE} {tag:^7s} {C.RESET} "
            f"{sev_c}{severity.upper():>8s}{C.RESET} "
            f"{C.BOLD}{tech}{C.RESET} {tech_name}"
        )
        print(f"           {C.DIM}{detail}{C.RESET}")

    def _emit_incident(
        self,
        severity: str,
        rule: str,
        summary: str,
        tech: str,
        tactics: str,
        confidence: float,
    ):
        self.alert_count += 1
        ts = datetime.now().strftime("%H:%M:%S")
        sev_c = C.sev(severity)
        tac_str = ""
        try:
            tac_list = (
                json.loads(tactics) if tactics and tactics.startswith("[") else []
            )
            if tac_list:
                tac_str = " > ".join(tac_list)
        except (json.JSONDecodeError, TypeError):
            tac_str = str(tactics)[:40]

        print()
        print(
            f"  {C.DIM}{ts}{C.RESET} "
            f"{C.BG_RED}{C.WHITE}{C.BOLD} INCIDENT {C.RESET} "
            f"{sev_c}{severity.upper():>8s}{C.RESET} "
            f"{C.BOLD}{rule}{C.RESET}"
        )
        print(f"           {C.WHITE}{summary[:80]}{C.RESET}")
        if tac_str:
            print(f"           {C.DIM}kill-chain: {tac_str}{C.RESET}")
        print(f"           {C.DIM}confidence={confidence:.2f} " f"tech={tech}{C.RESET}")
        print()


# ─── Auto Responder (Real Actions) ──────────────────────────────


class AutoResponder:
    """Confidence-gated response actions.

    DRY-RUN mode: logs what it would do.
    LIVE mode: actually executes quarantine/kill/block.
    """

    QUARANTINE_DIR = ROOT / "data" / "quarantine"

    def __init__(self, live: bool = False):
        self.live = live
        self.actions_taken: List[str] = []
        self.QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

    def handle(self, ev: dict, severity: str):
        """Handle security_events based on MITRE technique."""
        techs = _parse_techniques(ev.get("mitre_techniques", ""))
        risk = ev.get("risk_score", 0) or 0

        for tech in techs:
            # Credential theft — kill process if risk >= 0.85
            if tech in ("T1555.001", "T1555.003", "T1539", "T1005"):
                if risk >= 0.85:
                    self._respond_kill_process(ev, tech, "credential theft")
                else:
                    self._log_action(f"FLAG credential access", tech)

            # Fake password dialog — immediate kill
            elif tech == "T1056.002":
                self._respond_kill_process(ev, tech, "fake password dialog")

            # Persistence — quarantine the file
            elif tech == "T1543.001":
                self._respond_quarantine_plist(ev, tech)

            # Cron backdoor — review
            elif tech == "T1053.003":
                self._log_action("REVIEW crontab entries", tech)

            # Security tools disabled — re-enable
            elif tech == "T1562.001" and severity == "critical":
                self._respond_reenable_security(tech)

            # Tunneling — flag for review
            elif tech in ("T1572", "T1090"):
                self._log_action("FLAG tunnel/proxy detected", tech)

            # DGA — block domain
            elif tech == "T1568.002" and risk >= 0.8:
                self._log_action("FLAG DGA domain for blocking", tech)

            # Active scanning — block source IP
            elif tech in ("T1595", "T1595.002") and risk >= 0.8:
                src_ip = ev.get("indicators", "")
                self._log_action(f"FLAG scanner IP for blocking: {src_ip[:20]}", tech)

    def handle_persistence(self, ev: dict, mechanism: str, path: str):
        """Handle persistence events."""
        if mechanism in ("launchagent_user", "launchagent_system"):
            self._respond_quarantine_plist(ev, "T1543.001")
        elif mechanism == "cron":
            self._log_action("REVIEW crontab for backdoor entries", "T1053.003")
        elif mechanism == "ssh":
            self._log_action(f"REVIEW SSH key: {path}", "T1098.004")
        elif mechanism == "shell_profile":
            self._log_action(f"REVIEW shell profile: {path}", "T1546.004")

    def handle_incident(self, inc: dict):
        """Handle fusion incidents — correlated multi-stage attacks."""
        severity = (inc.get("severity", "high") or "high").lower()
        rule = inc.get("rule_name", "unknown")
        self._log_action(
            f"ESCALATE incident: {rule} [{severity.upper()}]",
            "INCIDENT",
        )

    def _respond_kill_process(self, ev: dict, tech: str, reason: str):
        """Kill a malicious process by PID."""
        pid = None
        # Try to extract PID from raw_attributes_json or indicators
        for field in ("raw_attributes_json", "indicators", "data"):
            raw = ev.get(field, "")
            if isinstance(raw, str) and "pid" in raw:
                try:
                    d = json.loads(raw)
                    pid = d.get("pid")
                    if pid:
                        break
                except (json.JSONDecodeError, TypeError):
                    pass

        if pid:
            action = f"KILL process pid={pid} ({reason})"
            if self.live:
                try:
                    os.kill(int(pid), 9)
                    action += " [KILLED]"
                except (ProcessLookupError, PermissionError) as e:
                    action += f" [FAILED: {e}]"
            self._log_action(action, tech)
        else:
            self._log_action(f"FLAG {reason} (no PID available)", tech)

    def _respond_quarantine_plist(self, ev: dict, tech: str):
        """Move malicious plist to quarantine directory."""
        path = ev.get("path", ev.get("entry_path", ""))
        if not path:
            self._log_action("FLAG persistence (no path)", tech)
            return

        p = Path(path).expanduser()
        if not p.exists():
            self._log_action(f"FLAG persistence (file gone): {path}", tech)
            return

        action = f"QUARANTINE {p.name}"
        if self.live:
            dest = self.QUARANTINE_DIR / f"{p.name}.{int(time.time())}"
            try:
                shutil.move(str(p), str(dest))
                action += f" -> {dest}"
            except (PermissionError, OSError) as e:
                action += f" [FAILED: {e}]"
        self._log_action(action, tech)

    def _respond_reenable_security(self, tech: str):
        """Re-enable Gatekeeper."""
        action = "RE-ENABLE Gatekeeper (spctl --master-enable)"
        if self.live:
            try:
                subprocess.run(
                    ["spctl", "--master-enable"],
                    capture_output=True,
                    timeout=5,
                )
                action += " [DONE]"
            except Exception as e:
                action += f" [FAILED: {e}]"
        self._log_action(action, tech)

    def _log_action(self, action: str, tech: str):
        mode = "LIVE" if self.live else "DRY RUN"
        ts = datetime.now().strftime("%H:%M:%S")
        print(
            f"  {C.DIM}{ts}{C.RESET} "
            f"{C.BG_GREEN}{C.WHITE} RESPOND {C.RESET} "
            f"{C.GREEN}{action}{C.RESET} "
            f"{C.DIM}[{tech}] [{mode}]{C.RESET}"
        )
        self.actions_taken.append(f"{action} [{tech}] [{mode}]")


# ─── Logging ────────────────────────────────────────────────────


def _log(level: str, msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    color = {"INFO": C.BLUE, "WARN": C.YELLOW, "ERROR": C.RED}.get(level, C.DIM)
    print(f"  {C.DIM}{ts}{C.RESET} {color}[{level}]{C.RESET} {msg}")


# ─── Main Daemon ────────────────────────────────────────────────


class AmoskysDaemon:
    """IGRIS-supervised daemon orchestrator."""

    def __init__(
        self,
        interval: float,
        respond: bool = False,
        respond_live: bool = False,
        min_severity: str = "info",
    ):
        self.interval = interval
        self.stop_event = threading.Event()
        self.min_severity = min_severity
        self.igris = None

        self.responder = None
        if respond or respond_live:
            self.responder = AutoResponder(live=respond_live)

        self.collector = CollectionRunner(interval, self.stop_event)
        self.monitor = AlertMonitor(
            self.stop_event,
            self.responder,
            min_severity=min_severity,
        )

    def start(self):
        """Start the daemon with IGRIS supervision."""
        self._print_banner()

        # Register signal handlers
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

        # Start IGRIS supervisor
        try:
            from amoskys.igris import start_igris

            self.igris = start_igris(
                telemetry_db=str(DB_PATH),
                interval=60,
            )
            _log("INFO", "IGRIS supervisor started (60s observation cycles)")
        except Exception as e:
            _log("WARN", f"IGRIS unavailable: {e}")

        # Start collection
        self.collector.start()
        _log("INFO", f"Collection runner started (interval={self.interval}s)")

        # Initialize story mode (template narration of attack stories)
        self.monitor._init_story_mode()

        # Start alert monitor
        self.monitor.start()
        tables_watched = (
            "security_events, persistence_events, process_events, "
            "flow_events, dns_events, fim_events, fusion_incidents"
        )
        _log("INFO", f"Alert monitor watching: {tables_watched}")

        if self.responder:
            mode = "LIVE" if self.responder.live else "DRY-RUN"
            _log("INFO", f"Auto-responder active ({mode})")

        if self.min_severity != "info":
            _log("INFO", f"Severity filter: >= {self.min_severity.upper()}")

        print()
        print(f"  {C.DIM}{'─'*64}{C.RESET}")
        print(f"  {C.DIM}Watching... (Ctrl+C to stop){C.RESET}")
        print(f"  {C.DIM}{'─'*64}{C.RESET}")
        print()

        # Main loop — status + IGRIS coherence every 30s
        try:
            while not self.stop_event.is_set():
                self.stop_event.wait(30)
                if not self.stop_event.is_set():
                    self._print_status()
        except KeyboardInterrupt:
            pass
        finally:
            self._shutdown()

    def _handle_signal(self, signum, frame):
        _log("INFO", f"Signal {signum} received, shutting down...")
        self.stop_event.set()

    def _shutdown(self):
        self.stop_event.set()
        print()

        # Stop IGRIS gracefully
        if self.igris:
            try:
                self.igris.stop()
                _log("INFO", "IGRIS stopped, baselines preserved")
            except Exception:
                pass

        _log("INFO", f"Collection cycles: {self.collector.cycle_count}")
        _log("INFO", f"Alerts emitted: {self.monitor.alert_count}")
        _log("INFO", f"Incidents detected: {self.monitor.incident_count}")
        if self.responder:
            _log("INFO", f"Response actions: {len(self.responder.actions_taken)}")

        # Final device risk snapshot
        risk_rows = _query(
            "SELECT score, level FROM device_risk ORDER BY updated_at DESC LIMIT 1",
            db_path=FUSION_DB_PATH,
        )
        if risk_rows:
            r = risk_rows[0]
            _log("INFO", f"Device risk at shutdown: {r['score']} ({r['level']})")

        print()

    def _print_status(self):
        ts = datetime.now().strftime("%H:%M:%S")

        # Core counters
        sec = _table_count("security_events")
        pers = _table_count("persistence_events")
        flow = _table_count("flow_events")
        dns = _table_count("dns_events")
        fim = _table_count("fim_events")
        incidents = _table_count("incidents", db_path=FUSION_DB_PATH)

        # Device risk
        risk_str = ""
        risk_rows = _query(
            "SELECT score, level FROM device_risk ORDER BY updated_at DESC LIMIT 1",
            db_path=FUSION_DB_PATH,
        )
        if risk_rows:
            r = risk_rows[0]
            score = r["score"]
            level = r["level"]
            if score >= 70:
                risk_str = f" {C.RED}risk={score}({level}){C.RESET}"
            elif score >= 40:
                risk_str = f" {C.YELLOW}risk={score}({level}){C.RESET}"
            else:
                risk_str = f" {C.GREEN}risk={score}({level}){C.RESET}"

        # IGRIS coherence
        coherence_str = ""
        if self.igris and self.igris.is_running:
            try:
                coh = self.igris.get_coherence()
                verdict = coh.get("verdict", "?")
                signals = coh.get("signal_pressure", 0)
                if verdict == "coherent":
                    coherence_str = f" {C.GREEN}IGRIS={verdict}{C.RESET}"
                elif verdict == "alive but degraded":
                    coherence_str = f" {C.YELLOW}IGRIS=degraded({signals}){C.RESET}"
                elif verdict in ("compromised", "blind"):
                    coherence_str = (
                        f" {C.RED}{C.BOLD}IGRIS={verdict}({signals}){C.RESET}"
                    )
                else:
                    coherence_str = f" {C.DIM}IGRIS={verdict}{C.RESET}"
            except Exception:
                coherence_str = f" {C.DIM}IGRIS=?{C.RESET}"

        # Collection health
        collect_str = f"collect={self.collector.last_duration:.0f}s"
        if self.collector.consecutive_failures > 0:
            collect_str = (
                f"{C.RED}collect=FAIL({self.collector.consecutive_failures}){C.RESET}"
            )

        print(
            f"  {C.DIM}{ts} [STATUS]{C.RESET} "
            f"c={self.collector.cycle_count} "
            f"alerts={self.monitor.alert_count} "
            f"sec={sec} pers={pers} flow={flow} dns={dns} fim={fim} "
            f"inc={incidents} "
            f"{collect_str}"
            f"{risk_str}"
            f"{coherence_str}"
        )

    def _print_banner(self):
        print()
        print(
            f"  {C.BOLD}{C.BG_BLUE}{C.WHITE}                                              {C.RESET}"
        )
        print(
            f"  {C.BOLD}{C.BG_BLUE}{C.WHITE}   AMOSKYS SECURITY DAEMON v0.9.0-beta.1      {C.RESET}"
        )
        print(
            f"  {C.BOLD}{C.BG_BLUE}{C.WHITE}   IGRIS-Supervised Endpoint Protection        {C.RESET}"
        )
        print(
            f"  {C.BOLD}{C.BG_BLUE}{C.WHITE}                                              {C.RESET}"
        )
        print()
        print(
            f"  {C.DIM}Platform:   macOS {os.uname().release} ({os.uname().machine}){C.RESET}"
        )
        print(f"  {C.DIM}Hostname:   {os.uname().nodename}{C.RESET}")
        print(f"  {C.DIM}Interval:   {self.interval}s{C.RESET}")
        print(f"  {C.DIM}DB:         {DB_PATH}{C.RESET}")
        print(f"  {C.DIM}Fusion DB:  {FUSION_DB_PATH}{C.RESET}")
        print(f"  {C.DIM}Probes:     73 across 8 observatory agents{C.RESET}")
        print(
            f"  {C.DIM}Tables:     7 monitored (sec, pers, proc, flow, dns, fim, incidents){C.RESET}"
        )
        print(
            f"  {C.DIM}Supervisor: IGRIS (60s coherence cycles, 40+ metrics){C.RESET}"
        )
        print(
            f"  {C.DIM}Narrator:   IGRIS Story Mode (template narration, Claude on demand){C.RESET}"
        )
        print()


# ─── CLI ────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="AMOSKYS Continuous Security Daemon — IGRIS-supervised",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=15,
        help="Collection interval in seconds (default: 15)",
    )
    parser.add_argument(
        "--respond",
        action="store_true",
        help="Enable auto-response in DRY-RUN mode (logs actions, doesn't execute)",
    )
    parser.add_argument(
        "--respond-live",
        action="store_true",
        help="Enable auto-response in LIVE mode (actually kills/quarantines)",
    )
    parser.add_argument(
        "--min-severity",
        default="info",
        choices=["info", "low", "medium", "high", "critical"],
        help="Minimum severity to display (default: info)",
    )

    args = parser.parse_args()

    daemon = AmoskysDaemon(
        interval=args.interval,
        respond=args.respond,
        respond_live=args.respond_live,
        min_severity=args.min_severity,
    )
    daemon.start()


if __name__ == "__main__":
    main()
