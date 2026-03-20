"""IGRIS Tactical Engine — the minister directing the soldiers.

IGRIS reads the telemetry stream, understands what is happening on the device,
and issues tactical directives to agents. It doesn't just watch — it commands.

Responsibilities:
    1. READ security events from telemetry.db (the ground truth)
    2. ASSESS threat level and identify active targets (PIDs, paths, domains)
    3. ISSUE directives: WATCH_PID, WATCH_PATH, WATCH_DOMAIN, TIGHTEN, LOOSEN
    4. ADAPT scoring thresholds based on device posture
    5. ESCALATE/DE-ESCALATE posture automatically

What IGRIS is NOT:
    - Not a decision-maker for response actions (human decides)
    - Not an autonomous operator (bounded, explainable)
    - Not a replacement for probes (probes detect, IGRIS directs)

Architecture:
    Analyzer process runs IGRIS tactical loop every 10 seconds.
    IGRIS writes directives to data/igris/directives.json.
    Collector process reads directives and adjusts agent behavior.
    This is IPC via filesystem — simple, debuggable, crash-safe.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("igris.tactical")

DATA_DIR = Path("data")
TELEMETRY_DB = DATA_DIR / "telemetry.db"
FUSION_DB = DATA_DIR / "intel" / "fusion.db"
DIRECTIVES_FILE = DATA_DIR / "igris" / "directives.json"
TACTICAL_LOG = DATA_DIR / "igris" / "tactical.jsonl"


# ── Directive Types ──────────────────────────────────────────────────────────


@dataclass
class TacticalDirective:
    """A single directive from IGRIS to the collector."""

    directive_type: str  # WATCH_PID, WATCH_PATH, WATCH_DOMAIN, TIGHTEN, LOOSEN, HUNT
    target: str  # PID number, file path, domain name, or agent name
    reason: str  # Why IGRIS issued this directive
    urgency: str  # LOW, MEDIUM, HIGH, CRITICAL
    source_event: str  # Event that triggered this directive
    mitre_technique: str  # MITRE ATT&CK technique if applicable
    ttl_seconds: int  # How long this directive stays active
    issued_at: float  # time.time() when issued


@dataclass
class TacticalState:
    """IGRIS's current tactical assessment of the device."""

    posture: str  # NOMINAL, GUARDED, ELEVATED, CRITICAL
    threat_level: float  # 0.0-1.0
    active_directives: List[TacticalDirective]
    watched_pids: List[str]
    watched_paths: List[str]
    watched_domains: List[str]
    hunt_mode: bool  # True when IGRIS is actively hunting
    last_assessment: float  # time.time()
    assessment_reason: str
    active_kill_chains: int
    top_threats: List[Dict[str, Any]]

    def to_dict(self) -> dict:
        d = {
            "posture": self.posture,
            "threat_level": self.threat_level,
            "active_directives": [asdict(d) for d in self.active_directives],
            "watched_pids": self.watched_pids,
            "watched_paths": self.watched_paths,
            "watched_domains": self.watched_domains,
            "hunt_mode": self.hunt_mode,
            "last_assessment": self.last_assessment,
            "assessment_reason": self.assessment_reason,
            "active_kill_chains": self.active_kill_chains,
            "top_threats": self.top_threats,
        }
        return d


# ── Tactical Engine ──────────────────────────────────────────────────────────


class IGRISTacticalEngine:
    """The minister. Reads the battlefield. Directs the soldiers.

    Every 10 seconds, IGRIS:
        1. Reads recent security events from telemetry.db
        2. Identifies PIDs, paths, domains that need focused collection
        3. Assesses overall threat posture
        4. Issues directives to agents via directives.json
        5. Logs its reasoning to tactical.jsonl
    """

    # Thresholds for posture escalation
    _CRITICAL_THRESHOLD = 3  # N critical events → CRITICAL posture
    _ELEVATED_THRESHOLD = 5  # N high events → ELEVATED
    _GUARDED_THRESHOLD = 3  # N medium events → GUARDED

    # Hunt mode: requires CORROBORATION — not just one signal
    _HUNT_TRIGGER_RISK = 0.85
    _HUNT_MIN_INDEPENDENT_SOURCES = 2  # Need 2+ distinct agent sources
    _HUNT_EXIT_QUIET_SECONDS = 300  # 5 min quiet → exit hunt

    # ── Self-awareness: IGRIS does not watch its own spine ──
    _SELF_PROCESS_NAMES = frozenset(
        {
            "python",
            "python3",
            "python3.13",  # AMOSKYS runs as Python
            "amoskys",
            "collector_main",
            "analyzer_main",
        }
    )
    _SELF_PATHS = frozenset(
        {
            "/opt/anaconda3/",  # Common Python env
            "/usr/local/bin/python",
            "amoskys-venv/",
            "src/amoskys/",
        }
    )
    _NOISE_CATEGORIES = frozenset(
        {
            "app_launch",  # runningboard noise
            "process_exit",  # kqueue noise
            "tcc_tcc_permission_request",  # TCC noise
            "tcc_tcc_event",  # TCC noise
        }
    )

    def __init__(self):
        self._state = TacticalState(
            posture="NOMINAL",
            threat_level=0.0,
            active_directives=[],
            watched_pids=[],
            watched_paths=[],
            watched_domains=[],
            hunt_mode=False,
            last_assessment=0.0,
            assessment_reason="initializing",
            active_kill_chains=0,
            top_threats=[],
        )
        self._seen_event_ids: Set[str] = set()
        self._directive_history: List[TacticalDirective] = []
        self._hunt_entered_at: float = 0.0
        self._last_critical_event_at: float = 0.0

        # Self-awareness: our own PID and parent PID
        self._self_pids = {str(os.getpid()), str(os.getppid())}

        # Ensure directories
        DIRECTIVES_FILE.parent.mkdir(parents=True, exist_ok=True)

    @property
    def state(self) -> TacticalState:
        return self._state

    def assess(self) -> TacticalState:
        """Run one tactical assessment cycle. Called every 10 seconds.

        The minister reads the battlefield with discrimination:
        - Filters out self-generated noise (own PIDs, AMOSKYS paths)
        - Filters out known benign categories (TCC noise, app_launch churn)
        - Requires corroboration for hunt mode (not just one signal)
        - Ranks directives by confidence and novelty
        - Explains WHY each target is watched
        """
        now = time.time()

        # ── 1. Read + FILTER events (remove self-noise) ──
        raw_events = self._read_recent_events(window_seconds=300)
        events = [e for e in raw_events if self._is_real_threat(e)]

        # ── 2. Count by severity (after noise removal) ──
        critical_count = sum(1 for e in events if (e.get("risk_score") or 0) >= 0.85)
        high_count = sum(1 for e in events if 0.7 <= (e.get("risk_score") or 0) < 0.85)
        medium_count = sum(1 for e in events if 0.4 <= (e.get("risk_score") or 0) < 0.7)

        noise_filtered = len(raw_events) - len(events)

        # ── 3. Determine posture ──
        if critical_count >= self._CRITICAL_THRESHOLD:
            posture = "CRITICAL"
            threat_level = min(1.0, 0.8 + critical_count * 0.02)
            reason = f"{critical_count} critical threats (filtered {noise_filtered} noise events)"
        elif high_count >= self._ELEVATED_THRESHOLD:
            posture = "ELEVATED"
            threat_level = min(0.8, 0.5 + high_count * 0.03)
            reason = f"{high_count} high-risk threats detected"
        elif medium_count >= self._GUARDED_THRESHOLD:
            posture = "GUARDED"
            threat_level = min(0.5, 0.2 + medium_count * 0.05)
            reason = f"{medium_count} medium-risk events worth watching"
        else:
            posture = "NOMINAL"
            threat_level = 0.1
            reason = f"quiet ({len(events)} events, {noise_filtered} filtered as noise)"

        # ── 4. Identify REAL targets (not self, not noise) ──
        directives = []
        watched_pids = []
        watched_paths = []
        watched_domains = []

        for event in events:
            risk = event.get("risk_score") or 0
            if risk < 0.65:  # Higher threshold than before — be selective
                continue

            event_id = event.get("event_id", "")
            if event_id in self._seen_event_ids:
                continue
            self._seen_event_ids.add(event_id)

            if len(self._seen_event_ids) > 10000:
                self._seen_event_ids = set(list(self._seen_event_ids)[-5000:])

            cat = event.get("event_category", "")
            raw = event.get("raw_attributes_json", "")
            techs = event.get("mitre_techniques", "")

            attrs = {}
            if raw:
                try:
                    attrs = json.loads(raw)
                except Exception:
                    pass

            pid = attrs.get("pid", "")
            path = attrs.get("path", attrs.get("exe", ""))
            domain = attrs.get("domain", attrs.get("query_name", ""))
            process_name = attrs.get("process_name", "")

            # Skip self-PIDs
            if str(pid) in self._self_pids:
                continue
            # Skip self-paths
            if path and any(sp in path for sp in self._SELF_PATHS):
                continue

            priority = "HIGH" if risk >= 0.8 else "MEDIUM"

            # Build tactical reason (WHY this target)
            tech_name = self._first_tech(techs)

            if pid and str(pid) not in watched_pids:
                watched_pids.append(str(pid))
                directives.append(
                    TacticalDirective(
                        directive_type="WATCH_PID",
                        target=str(pid),
                        reason=f"{cat} (risk={risk:.2f}, {tech_name}): process '{process_name or pid}' "
                        f"flagged by detection engine",
                        urgency=priority,
                        source_event=event_id,
                        mitre_technique=tech_name,
                        ttl_seconds=300,
                        issued_at=now,
                    )
                )

            if path and path not in watched_paths:
                watched_paths.append(path)
                directives.append(
                    TacticalDirective(
                        directive_type="WATCH_PATH",
                        target=path,
                        reason=f"{cat} at '{path}' — {tech_name or 'suspicious activity'}",
                        urgency=priority,
                        source_event=event_id,
                        mitre_technique=tech_name,
                        ttl_seconds=600,
                        issued_at=now,
                    )
                )

            if domain and domain not in watched_domains:
                watched_domains.append(domain)
                directives.append(
                    TacticalDirective(
                        directive_type="WATCH_DOMAIN",
                        target=domain,
                        reason=f"{cat} involving '{domain}' — {tech_name or 'needs investigation'}",
                        urgency=priority,
                        source_event=event_id,
                        mitre_technique=tech_name,
                        ttl_seconds=600,
                        issued_at=now,
                    )
                )

        # ── 5. Hunt mode (requires CORROBORATION, not just one signal) ──
        distinct_sources = set()
        for e in events:
            if (e.get("risk_score") or 0) >= self._HUNT_TRIGGER_RISK:
                raw_h = e.get("raw_attributes_json", "")
                src = e.get("event_category", "unknown")
                if raw_h:
                    try:
                        src = json.loads(raw_h).get("detection_source", src)
                    except Exception:
                        pass
                distinct_sources.add(src)

        # Entry: 2+ critical AND from 2+ independent sources
        hunt_entry = (
            critical_count >= 2
            and len(distinct_sources) >= self._HUNT_MIN_INDEPENDENT_SOURCES
        )
        # Exit: no critical events for quiet period
        if critical_count > 0:
            self._last_critical_event_at = now
        quiet = (
            now - self._last_critical_event_at
            if self._last_critical_event_at > 0
            else 999
        )
        hunt_exit = quiet >= self._HUNT_EXIT_QUIET_SECONDS

        if hunt_entry and not self._state.hunt_mode:
            self._hunt_entered_at = now
            logger.warning(
                "IGRIS: HUNT MODE — %d critical from %d independent sources",
                critical_count,
                len(distinct_sources),
            )
            directives.append(
                TacticalDirective(
                    directive_type="TIGHTEN",
                    target="all",
                    reason=f"Hunt: {critical_count} critical from {len(distinct_sources)} sources",
                    urgency="CRITICAL",
                    source_event="",
                    mitre_technique="",
                    ttl_seconds=600,
                    issued_at=now,
                )
            )
            hunt_mode = True
        elif self._state.hunt_mode and hunt_exit:
            logger.info("IGRIS: Exiting hunt — quiet for %.0fs", quiet)
            directives.append(
                TacticalDirective(
                    directive_type="LOOSEN",
                    target="all",
                    reason=f"Quiet: no critical events for {quiet:.0f}s",
                    urgency="LOW",
                    source_event="",
                    mitre_technique="",
                    ttl_seconds=0,
                    issued_at=now,
                )
            )
            hunt_mode = False
        else:
            hunt_mode = self._state.hunt_mode

        # ── 6. Top threats summary ──
        top_threats = []
        for e in sorted(events, key=lambda x: -(x.get("risk_score") or 0))[:5]:
            top_threats.append(
                {
                    "category": e.get("event_category", "?"),
                    "risk": e.get("risk_score", 0),
                    "techniques": e.get("mitre_techniques", ""),
                }
            )

        # ── 7. Expire old directives ──
        active = [d for d in directives if now - d.issued_at < d.ttl_seconds]
        # Also keep non-expired directives from previous cycle
        for old in self._state.active_directives:
            if now - old.issued_at < old.ttl_seconds:
                # Don't duplicate
                if not any(
                    d.target == old.target and d.directive_type == old.directive_type
                    for d in active
                ):
                    active.append(old)

        # ── 8. Update state ──
        self._state = TacticalState(
            posture=posture,
            threat_level=threat_level,
            active_directives=active,
            watched_pids=watched_pids[:20],
            watched_paths=watched_paths[:20],
            watched_domains=watched_domains[:20],
            hunt_mode=hunt_mode,
            last_assessment=now,
            assessment_reason=reason,
            active_kill_chains=0,  # TODO: read from kill chain tracker
            top_threats=top_threats,
        )

        # ── 9. Write directives for collector ──
        self._write_directives()

        # ── 10. Log tactical decision ──
        self._log_decision(events, directives)

        if directives:
            logger.info(
                "IGRIS tactical: posture=%s threat=%.2f directives=%d "
                "watch_pids=%d watch_paths=%d hunt=%s",
                posture,
                threat_level,
                len(directives),
                len(watched_pids),
                len(watched_paths),
                hunt_mode,
            )

        return self._state

    def _read_recent_events(self, window_seconds: int = 300) -> List[dict]:
        """Read recent security events from telemetry.db."""
        if not TELEMETRY_DB.exists():
            return []
        try:
            conn = sqlite3.connect(str(TELEMETRY_DB), timeout=2)
            conn.row_factory = sqlite3.Row
            cutoff_ns = int((time.time() - window_seconds) * 1e9)
            rows = conn.execute(
                """SELECT event_id, event_category, event_action, risk_score,
                          mitre_techniques, raw_attributes_json, event_timestamp_ns
                   FROM security_events
                   WHERE event_timestamp_ns > ?
                   ORDER BY risk_score DESC
                   LIMIT 200""",
                (cutoff_ns,),
            ).fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.debug("IGRIS tactical read failed: %s", e)
            return []

    def _write_directives(self):
        """Write current directives to data/igris/directives.json."""
        try:
            payload = {
                "posture": self._state.posture,
                "threat_level": self._state.threat_level,
                "hunt_mode": self._state.hunt_mode,
                "assessment_reason": self._state.assessment_reason,
                "timestamp": time.time(),
                "directives": [asdict(d) for d in self._state.active_directives],
                "watched_pids": self._state.watched_pids,
                "watched_paths": self._state.watched_paths,
                "watched_domains": self._state.watched_domains,
            }
            DIRECTIVES_FILE.write_text(json.dumps(payload, indent=2))
        except Exception as e:
            logger.debug("IGRIS directive write failed: %s", e)

    def _log_decision(self, events: list, directives: list):
        """Append tactical decision to tactical.jsonl for audit."""
        try:
            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "posture": self._state.posture,
                "threat_level": self._state.threat_level,
                "hunt_mode": self._state.hunt_mode,
                "events_assessed": len(events),
                "directives_issued": len(directives),
                "reason": self._state.assessment_reason,
            }
            if directives:
                entry["directive_summary"] = [
                    {"type": d.directive_type, "target": d.target, "urgency": d.urgency}
                    for d in directives[:10]
                ]
            with open(TACTICAL_LOG, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass

    def _is_real_threat(self, event: dict) -> bool:
        """Filter: is this event a real threat or self-generated noise?

        The minister does not panic at his own reflection.
        """
        cat = event.get("event_category", "")
        risk = event.get("risk_score") or 0

        # Skip known noise categories entirely
        if cat in self._NOISE_CATEGORIES:
            return False

        # Skip low-risk events (not worth tactical attention)
        if risk < 0.4:
            return False

        # Check if this is AMOSKYS watching itself
        raw = event.get("raw_attributes_json", "")
        if raw:
            try:
                attrs = json.loads(raw)
                pid = str(attrs.get("pid", ""))
                path = attrs.get("path", attrs.get("exe", ""))
                proc = attrs.get("process_name", "")

                # Our own PIDs
                if pid in self._self_pids:
                    return False

                # Our own processes by name
                if proc in self._SELF_PROCESS_NAMES:
                    # Only filter if the path also matches self
                    if path and any(sp in path for sp in self._SELF_PATHS):
                        return False

                # Our own paths
                if path and any(sp in path for sp in self._SELF_PATHS):
                    return False
            except Exception:
                pass

        return True

    @staticmethod
    def _first_tech(techs_str: str) -> str:
        if not techs_str:
            return ""
        try:
            parsed = json.loads(techs_str)
            return parsed[0] if parsed else ""
        except Exception:
            return techs_str[:10]

    def get_briefing(self) -> str:
        """Get a plain-English briefing of IGRIS's current assessment."""
        s = self._state
        lines = []
        lines.append(f"Posture: {s.posture} (threat level: {s.threat_level:.0%})")
        lines.append(f"Reason: {s.assessment_reason}")

        if s.hunt_mode:
            lines.append("Mode: HUNT — all agents at maximum collection frequency")

        if s.active_directives:
            lines.append(f"Active directives: {len(s.active_directives)}")
            for d in s.active_directives[:5]:
                lines.append(f"  {d.directive_type} {d.target}: {d.reason}")

        if s.watched_pids:
            lines.append(f"Watching PIDs: {', '.join(s.watched_pids[:10])}")
        if s.watched_paths:
            lines.append(f"Watching paths: {len(s.watched_paths)}")
            for p in s.watched_paths[:3]:
                lines.append(f"  {p}")
        if s.watched_domains:
            lines.append(f"Watching domains: {', '.join(s.watched_domains[:5])}")

        if s.top_threats:
            lines.append("Top threats:")
            for t in s.top_threats[:3]:
                lines.append(f"  {t['category']} (risk={t['risk']:.2f})")

        return "\n".join(lines)


# ── Directive Reader (for collector process) ─────────────────────────────────


def read_directives() -> Optional[dict]:
    """Read current IGRIS directives. Called by the collector."""
    if not DIRECTIVES_FILE.exists():
        return None
    try:
        data = json.loads(DIRECTIVES_FILE.read_text())
        # Check freshness — stale directives are ignored
        age = time.time() - data.get("timestamp", 0)
        if age > 600:  # 10 minutes
            return None
        return data
    except Exception:
        return None
