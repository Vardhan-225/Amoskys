"""IGRIS Tactical Engine v3 — persistent, investigative, chain-aware.

The minister now has:
    - A hippocampus (memory.py) — remembers across restarts
    - Hands (inspector.py) — can ask specific questions
    - A map (chain_reader.py) — sees kill chain topology, not just events
    - A library (SOMA hooks) — knows what's normal vs novel

Architecture:
    Analyzer process runs IGRIS tactical loop every 10 seconds.
    IGRIS writes directives to data/igris/directives.json.
    Collector process reads directives and adjusts agent behavior.

    New in v3:
    - Tactical state persists in data/igris/memory.db
    - Posture assessment weighted by kill chain depth
    - SOMA records observations and detects novel patterns
    - Inspector can run on-demand investigations
    - Directive outcomes are tracked for effectiveness
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

    directive_type: str  # WATCH_PID, WATCH_PATH, WATCH_DOMAIN, TIGHTEN, LOOSEN, INSPECT
    target: str  # PID number, file path, domain name, or agent name
    reason: str  # Why IGRIS issued this directive
    urgency: str  # LOW, MEDIUM, HIGH, CRITICAL
    source_event: str  # Event that triggered this directive
    mitre_technique: str  # MITRE ATT&CK technique if applicable
    ttl_seconds: int  # How long this directive stays active
    issued_at: float  # time.time() when issued
    chain_stage: str = ""  # Kill chain stage this relates to
    novelty: float = 0.0  # 0.0=seen before, 1.0=completely novel


@dataclass
class TacticalState:
    """IGRIS's current tactical assessment of the device."""

    posture: str  # NOMINAL, GUARDED, ELEVATED, CRITICAL
    threat_level: float  # 0.0-1.0
    active_directives: List[TacticalDirective]
    watched_pids: List[str]
    watched_paths: List[str]
    watched_domains: List[str]
    hunt_mode: bool
    last_assessment: float
    assessment_reason: str
    active_kill_chains: int
    top_threats: List[Dict[str, Any]]
    # v3 additions
    chain_depth: float = 0.0
    chain_narrative: str = ""
    next_predicted_stage: str = ""
    threat_multiplier: float = 1.0
    posture_trend: str = "stable"
    novel_events_count: int = 0
    memory_restored: bool = False

    def to_dict(self) -> dict:
        d = {
            "posture": self.posture,
            "threat_level": self.threat_level,
            "active_directives": [asdict(dd) for dd in self.active_directives],
            "watched_pids": self.watched_pids,
            "watched_paths": self.watched_paths,
            "watched_domains": self.watched_domains,
            "hunt_mode": self.hunt_mode,
            "last_assessment": self.last_assessment,
            "assessment_reason": self.assessment_reason,
            "active_kill_chains": self.active_kill_chains,
            "top_threats": self.top_threats,
            "chain_depth": self.chain_depth,
            "chain_narrative": self.chain_narrative,
            "next_predicted_stage": self.next_predicted_stage,
            "threat_multiplier": self.threat_multiplier,
            "posture_trend": self.posture_trend,
            "novel_events_count": self.novel_events_count,
        }
        return d


# ── Self-Awareness ───────────────────────────────────────────────────────────

# Paths that belong to AMOSKYS itself — never watch these
_SELF_PATHS = {
    "amoskys",
    "amoskys-venv",
    ".venv",
    "anaconda3",
    "python3",
    "python",
}

# Event categories that are infrastructure noise, not threats
_NOISE_CATEGORIES = {
    "app_launch",
    "process_exit",
    "app_terminated",
    "tcc_tcc_permission_request",
    "tcc_tcc_permission_granted",
}


def _is_self_process(pid: str, path: str, process_name: str) -> bool:
    """Check if a target belongs to AMOSKYS itself."""
    my_pid = str(os.getpid())
    my_ppid = str(os.getppid())
    if pid in (my_pid, my_ppid):
        return True
    p = (path + " " + process_name).lower()
    return any(sp in p for sp in _SELF_PATHS)


def _is_noise_event(event: dict) -> bool:
    """Check if an event is infrastructure noise."""
    cat = event.get("event_category", "")
    return cat in _NOISE_CATEGORIES


# ── Tactical Engine ──────────────────────────────────────────────────────────


class IGRISTacticalEngine:
    """The minister. Persistent. Investigative. Chain-aware.

    Every 10 seconds, IGRIS:
        1. Reads recent security events from telemetry.db
        2. Filters noise and self-generated events
        3. Assesses kill chain state (chain_reader)
        4. Checks SOMA for novelty (memory)
        5. Computes weighted posture (events × chain × novelty)
        6. Issues directives to agents
        7. Persists state to memory.db
        8. Logs reasoning to tactical.jsonl
    """

    _CRITICAL_THRESHOLD = 5
    _ELEVATED_THRESHOLD = 10
    _GUARDED_THRESHOLD = 3
    _HUNT_TRIGGER_RISK = 0.85
    _HUNT_CORROBORATION_SOURCES = 2
    _HUNT_QUIET_PERIOD = 300

    def __init__(self):
        # Lazy imports to avoid circular dependencies
        from amoskys.igris.chain_reader import IGRISChainReader
        from amoskys.igris.inspector import IGRISInspector
        from amoskys.igris.memory import IGRISMemory

        self._memory = IGRISMemory()
        self._inspector = IGRISInspector()
        self._chain_reader = IGRISChainReader()

        self._seen_event_ids: Set[str] = set()
        self._hunt_exit_time: float = 0.0
        self._last_critical_time: float = 0.0

        # Restore state from memory
        self._state = self._restore_state()

        DIRECTIVES_FILE.parent.mkdir(parents=True, exist_ok=True)
        logger.info(
            "IGRIS tactical v3: memory=%s, inspector=%s, chain_reader=%s",
            "restored" if self._state.memory_restored else "fresh",
            "ready",
            "ready",
        )

    @property
    def state(self) -> TacticalState:
        return self._state

    @property
    def memory(self):
        return self._memory

    @property
    def inspector(self):
        return self._inspector

    @property
    def chain_reader(self):
        return self._chain_reader

    def _restore_state(self) -> TacticalState:
        """Restore tactical state from persistent memory."""
        saved = self._memory.load_state()
        if not saved:
            return TacticalState(
                posture="NOMINAL",
                threat_level=0.0,
                active_directives=[],
                watched_pids=[],
                watched_paths=[],
                watched_domains=[],
                hunt_mode=False,
                last_assessment=0.0,
                assessment_reason="initializing — first boot",
                active_kill_chains=0,
                top_threats=[],
                memory_restored=False,
            )

        logger.info(
            "IGRIS: Restored state — posture=%s, threat=%.2f, hunt=%s",
            saved.get("posture", "?"),
            saved.get("threat_level", 0),
            saved.get("hunt_mode", False),
        )

        return TacticalState(
            posture=saved.get("posture", "NOMINAL"),
            threat_level=saved.get("threat_level", 0.0),
            active_directives=[],  # Don't restore stale directives
            watched_pids=saved.get("watched_pids", []),
            watched_paths=saved.get("watched_paths", []),
            watched_domains=saved.get("watched_domains", []),
            hunt_mode=saved.get("hunt_mode", False),
            last_assessment=saved.get("last_assessment", 0.0),
            assessment_reason=saved.get("assessment_reason", "restored from memory"),
            active_kill_chains=saved.get("active_kill_chains", 0),
            top_threats=saved.get("top_threats", []),
            chain_depth=saved.get("chain_depth", 0.0),
            chain_narrative=saved.get("chain_narrative", ""),
            next_predicted_stage=saved.get("next_predicted_stage", ""),
            threat_multiplier=saved.get("threat_multiplier", 1.0),
            posture_trend=saved.get("posture_trend", "stable"),
            novel_events_count=saved.get("novel_events_count", 0),
            memory_restored=True,
        )

    def assess(self) -> TacticalState:
        """Run one tactical assessment cycle."""
        now = time.time()

        # ── 1. Read recent security events ──
        events = self._read_recent_events(window_seconds=300)

        # ── 2. Filter noise and self ──
        real_events = [
            e for e in events if not _is_noise_event(e) and self._is_real_threat(e)
        ]

        # ── 3. Count by severity ──
        critical_count = sum(
            1 for e in real_events if (e.get("risk_score") or 0) >= 0.85
        )
        high_count = sum(
            1 for e in real_events if 0.7 <= (e.get("risk_score") or 0) < 0.85
        )
        medium_count = sum(
            1 for e in real_events if 0.4 <= (e.get("risk_score") or 0) < 0.7
        )

        # ── 4. Kill chain assessment ──
        chain = self._chain_reader.assess_chain(window_seconds=600)

        # ── 5. SOMA novelty check ──
        novel_count = 0
        for event in real_events:
            cat = event.get("event_category", "")
            raw = event.get("raw_attributes_json", "")
            proc = ""
            path = ""
            if raw:
                try:
                    attrs = json.loads(raw)
                    proc = attrs.get("process_name", "")
                    path = attrs.get("path", "")
                except Exception:
                    pass

            known = self._memory.soma_is_known(cat, proc, path)
            if not known:
                novel_count += 1
            # Record observation for future baseline
            self._memory.record_soma_observation(
                event_category=cat,
                process_name=proc,
                path=path,
                risk_score=event.get("risk_score", 0),
            )

        # ── 6. Weighted posture assessment ──
        # Base posture from event counts
        if critical_count >= self._CRITICAL_THRESHOLD:
            base_posture = "CRITICAL"
            base_threat = min(1.0, 0.8 + critical_count * 0.02)
            reason = f"{critical_count} critical events in 5min"
        elif high_count >= self._ELEVATED_THRESHOLD:
            base_posture = "ELEVATED"
            base_threat = min(0.8, 0.5 + high_count * 0.03)
            reason = f"{high_count} high-risk events in 5min"
        elif medium_count >= self._GUARDED_THRESHOLD:
            base_posture = "GUARDED"
            base_threat = min(0.5, 0.2 + medium_count * 0.05)
            reason = f"{medium_count} medium-risk events in 5min"
        else:
            base_posture = "NOMINAL"
            base_threat = 0.1
            reason = "no significant threats"

        # Apply kill chain multiplier
        threat_level = min(1.0, base_threat * chain.threat_multiplier)

        # Kill chain can UPGRADE posture
        if chain.is_multi_stage and base_posture in ("NOMINAL", "GUARDED"):
            base_posture = "ELEVATED"
            reason += f" + {chain.stage_count}-stage kill chain active"
        if chain.stage_count >= 5:
            base_posture = "CRITICAL"
            reason += f" + deep kill chain ({chain.stage_count}/7 stages)"

        # Novelty bonus: many novel events increase suspicion
        if novel_count > 5:
            threat_level = min(1.0, threat_level + 0.1)
            reason += f" + {novel_count} novel patterns"

        # ── 7. Hunt mode with corroboration ──
        # Entry: need 2+ critical from 2+ independent sources
        critical_sources = set()
        for e in real_events:
            if (e.get("risk_score") or 0) >= self._HUNT_TRIGGER_RISK:
                critical_sources.add(e.get("event_category", "unknown"))
                self._last_critical_time = now

        enter_hunt = (
            critical_count >= 2
            and len(critical_sources) >= self._HUNT_CORROBORATION_SOURCES
        ) or chain.stage_count >= 4

        # Exit: quiet period with no critical events
        exit_hunt = (
            self._state.hunt_mode
            and (now - self._last_critical_time) > self._HUNT_QUIET_PERIOD
        )

        hunt_mode = self._state.hunt_mode
        if enter_hunt and not hunt_mode:
            hunt_mode = True
            logger.warning(
                "IGRIS: HUNT MODE — %d critical from %d sources, chain=%d/7",
                critical_count,
                len(critical_sources),
                chain.stage_count,
            )
        elif exit_hunt:
            hunt_mode = False
            self._hunt_exit_time = now
            logger.info("IGRIS: Exiting hunt mode — quiet period elapsed")

        # ── 8. Issue directives ──
        directives = self._build_directives(real_events, chain, now)

        if hunt_mode and not self._state.hunt_mode:
            directives.append(
                TacticalDirective(
                    directive_type="TIGHTEN",
                    target="all",
                    reason=f"Hunt mode: {len(critical_sources)} sources, "
                    f"chain {chain.stage_count}/7",
                    urgency="CRITICAL",
                    source_event="",
                    mitre_technique="",
                    ttl_seconds=600,
                    issued_at=now,
                    chain_stage=chain.max_stage_name,
                )
            )
        elif not hunt_mode and self._state.hunt_mode:
            directives.append(
                TacticalDirective(
                    directive_type="LOOSEN",
                    target="all",
                    reason="Threat reduced — returning to normal",
                    urgency="LOW",
                    source_event="",
                    mitre_technique="",
                    ttl_seconds=0,
                    issued_at=now,
                )
            )

        # ── 9. Auto-investigate high-priority targets ──
        auto_inspections = self._auto_investigate(real_events, chain)

        # ── 10. Expire old directives ──
        active = [d for d in directives if now - d.issued_at < d.ttl_seconds]
        for old in self._state.active_directives:
            if now - old.issued_at < old.ttl_seconds:
                if not any(
                    d.target == old.target and d.directive_type == old.directive_type
                    for d in active
                ):
                    active.append(old)

        # ── 11. Top threats ──
        top_threats = []
        for e in sorted(real_events, key=lambda x: -(x.get("risk_score") or 0))[:5]:
            top_threats.append(
                {
                    "category": e.get("event_category", "?"),
                    "risk": e.get("risk_score", 0),
                    "techniques": e.get("mitre_techniques", ""),
                }
            )

        # ── 12. Posture trend ──
        posture_trend = self._memory.get_posture_trend(3600)

        # ── 13. Record posture transition ──
        old_posture = self._state.posture
        if old_posture != base_posture:
            self._memory.record_posture_transition(
                from_posture=old_posture,
                to_posture=base_posture,
                reason=reason,
                threat_level=threat_level,
                event_count=len(real_events),
            )

        # ── 14. Update state ──
        self._state = TacticalState(
            posture=base_posture,
            threat_level=threat_level,
            active_directives=active,
            watched_pids=[d.target for d in active if d.directive_type == "WATCH_PID"][
                :20
            ],
            watched_paths=[
                d.target for d in active if d.directive_type == "WATCH_PATH"
            ][:20],
            watched_domains=[
                d.target for d in active if d.directive_type == "WATCH_DOMAIN"
            ][:20],
            hunt_mode=hunt_mode,
            last_assessment=now,
            assessment_reason=reason,
            active_kill_chains=1 if chain.is_multi_stage else 0,
            top_threats=top_threats,
            chain_depth=chain.chain_depth,
            chain_narrative=chain.narrative,
            next_predicted_stage=chain.next_predicted_stage,
            threat_multiplier=chain.threat_multiplier,
            posture_trend=posture_trend,
            novel_events_count=novel_count,
        )

        # ── 15. Persist state ──
        self._persist_state()
        self._write_directives()
        self._log_decision(real_events, directives, chain)

        # ── 16. Record directives in memory ──
        for d in directives:
            self._memory.record_directive(asdict(d))
            if d.directive_type.startswith("WATCH"):
                self._memory.upsert_watched_target(
                    target_type=d.directive_type.replace("WATCH_", ""),
                    target=d.target,
                    reason=d.reason,
                    urgency=d.urgency,
                    mitre_technique=d.mitre_technique,
                )

        if directives or chain.is_multi_stage:
            logger.info(
                "IGRIS: posture=%s threat=%.0f%% chain=%d/7 "
                "directives=%d novel=%d hunt=%s trend=%s",
                base_posture,
                threat_level * 100,
                chain.stage_count,
                len(directives),
                novel_count,
                hunt_mode,
                posture_trend,
            )

        return self._state

    def _is_real_threat(self, event: dict) -> bool:
        """Filter self-generated and noise events."""
        raw = event.get("raw_attributes_json", "")
        if not raw:
            return True
        try:
            attrs = json.loads(raw)
            pid = str(attrs.get("pid", ""))
            path = attrs.get("path", attrs.get("exe", ""))
            proc = attrs.get("process_name", "")
            return not _is_self_process(pid, path or "", proc or "")
        except Exception:
            return True

    def _build_directives(
        self, events: list, chain, now: float
    ) -> List[TacticalDirective]:
        """Build tactical directives from events and chain state."""
        directives = []
        seen_targets = set()

        for event in events:
            risk = event.get("risk_score") or 0
            if risk < 0.65:
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

            pid = str(attrs.get("pid", ""))
            path = attrs.get("path", attrs.get("exe", ""))
            domain = attrs.get("domain", attrs.get("query_name", ""))
            process_name = attrs.get("process_name", "")

            # Determine kill chain stage for this event
            from amoskys.igris.chain_reader import CATEGORY_TO_STAGE

            event_stage = CATEGORY_TO_STAGE.get(cat, "")

            # Check novelty
            known = self._memory.soma_is_known(cat, process_name, path or "")
            novelty = 0.0 if known else 1.0

            if pid and pid not in seen_targets:
                seen_targets.add(pid)
                directives.append(
                    TacticalDirective(
                        directive_type="WATCH_PID",
                        target=pid,
                        reason=f"{cat} (risk={risk:.2f}): {process_name or pid}",
                        urgency="CRITICAL" if risk >= 0.85 else "HIGH",
                        source_event=event_id,
                        mitre_technique=self._first_tech(techs),
                        ttl_seconds=300,
                        issued_at=now,
                        chain_stage=event_stage,
                        novelty=novelty,
                    )
                )

            if path and path not in seen_targets:
                seen_targets.add(path)
                directives.append(
                    TacticalDirective(
                        directive_type="WATCH_PATH",
                        target=path,
                        reason=f"{cat} at {path}",
                        urgency="CRITICAL" if risk >= 0.85 else "HIGH",
                        source_event=event_id,
                        mitre_technique=self._first_tech(techs),
                        ttl_seconds=600,
                        issued_at=now,
                        chain_stage=event_stage,
                        novelty=novelty,
                    )
                )

            if domain and domain not in seen_targets:
                seen_targets.add(domain)
                directives.append(
                    TacticalDirective(
                        directive_type="WATCH_DOMAIN",
                        target=domain,
                        reason=f"{cat} involving {domain}",
                        urgency="CRITICAL" if risk >= 0.85 else "HIGH",
                        source_event=event_id,
                        mitre_technique=self._first_tech(techs),
                        ttl_seconds=600,
                        issued_at=now,
                        chain_stage=event_stage,
                        novelty=novelty,
                    )
                )

        return directives

    def _auto_investigate(self, events: list, chain) -> List[dict]:
        """Automatically investigate high-priority targets.

        IGRIS doesn't just watch — it asks questions when confidence is high.
        """
        investigations = []

        for event in events:
            risk = event.get("risk_score") or 0
            if risk < 0.8:
                continue

            cat = event.get("event_category", "")
            raw = event.get("raw_attributes_json", "")
            attrs = {}
            if raw:
                try:
                    attrs = json.loads(raw)
                except Exception:
                    continue

            path = attrs.get("path", "")
            pid = str(attrs.get("pid", ""))

            # Persistence: inspect the plist
            if "persistence" in cat and path and path.endswith(".plist"):
                req_id = self._memory.request_investigation("INSPECT_PLIST", path)
                result = self._inspector.inspect("INSPECT_PLIST", path)
                self._memory.complete_investigation(
                    req_id,
                    result.data,
                    result.verdict,
                )
                investigations.append(
                    {
                        "action": "INSPECT_PLIST",
                        "target": path,
                        "verdict": result.verdict,
                    }
                )

            # Suspicious binary: check codesign
            if path and (
                path.startswith("/tmp")
                or path.startswith("/var/tmp")
                or "Downloads" in path
            ):
                req_id = self._memory.request_investigation("INSPECT_CODESIGN", path)
                result = self._inspector.inspect("INSPECT_CODESIGN", path)
                self._memory.complete_investigation(
                    req_id,
                    result.data,
                    result.verdict,
                )
                investigations.append(
                    {
                        "action": "INSPECT_CODESIGN",
                        "target": path,
                        "verdict": result.verdict,
                    }
                )

            # High-risk PID: check connections
            if pid and risk >= 0.85:
                req_id = self._memory.request_investigation("INSPECT_CONNECTIONS", pid)
                result = self._inspector.inspect("INSPECT_CONNECTIONS", pid)
                self._memory.complete_investigation(
                    req_id,
                    result.data,
                    result.verdict,
                )
                investigations.append(
                    {
                        "action": "INSPECT_CONNECTIONS",
                        "target": pid,
                        "verdict": result.verdict,
                    }
                )

        if investigations:
            logger.info(
                "IGRIS auto-investigate: %d inspections (%s)",
                len(investigations),
                ", ".join(f"{i['action']}→{i['verdict']}" for i in investigations),
            )
        return investigations

    def _persist_state(self):
        """Save tactical state to memory.db."""
        self._memory.save_state(
            {
                "posture": self._state.posture,
                "threat_level": self._state.threat_level,
                "hunt_mode": self._state.hunt_mode,
                "watched_pids": self._state.watched_pids,
                "watched_paths": self._state.watched_paths,
                "watched_domains": self._state.watched_domains,
                "last_assessment": self._state.last_assessment,
                "assessment_reason": self._state.assessment_reason,
                "active_kill_chains": self._state.active_kill_chains,
                "top_threats": self._state.top_threats,
                "chain_depth": self._state.chain_depth,
                "chain_narrative": self._state.chain_narrative,
                "next_predicted_stage": self._state.next_predicted_stage,
                "threat_multiplier": self._state.threat_multiplier,
                "posture_trend": self._state.posture_trend,
                "novel_events_count": self._state.novel_events_count,
            }
        )

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
                          mitre_techniques, raw_attributes_json,
                          event_timestamp_ns
                   FROM security_events
                   WHERE event_timestamp_ns > ?
                   ORDER BY risk_score DESC
                   LIMIT 200""",
                (cutoff_ns,),
            ).fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.debug("IGRIS read failed: %s", e)
            return []

    def _write_directives(self):
        """Write current directives to data/igris/directives.json."""
        try:
            payload = {
                "posture": self._state.posture,
                "threat_level": self._state.threat_level,
                "hunt_mode": self._state.hunt_mode,
                "assessment_reason": self._state.assessment_reason,
                "chain_depth": self._state.chain_depth,
                "chain_narrative": self._state.chain_narrative,
                "next_predicted_stage": self._state.next_predicted_stage,
                "threat_multiplier": self._state.threat_multiplier,
                "posture_trend": self._state.posture_trend,
                "novel_events": self._state.novel_events_count,
                "timestamp": time.time(),
                "directives": [asdict(d) for d in self._state.active_directives],
                "watched_pids": self._state.watched_pids,
                "watched_paths": self._state.watched_paths,
                "watched_domains": self._state.watched_domains,
            }
            DIRECTIVES_FILE.write_text(json.dumps(payload, indent=2))
        except Exception as e:
            logger.debug("IGRIS directive write failed: %s", e)

    def _log_decision(self, events: list, directives: list, chain):
        """Append tactical decision to tactical.jsonl for audit."""
        try:
            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "posture": self._state.posture,
                "threat_level": self._state.threat_level,
                "hunt_mode": self._state.hunt_mode,
                "events_assessed": len(events),
                "directives_issued": len(directives),
                "chain_stages": chain.stage_count,
                "chain_depth": chain.chain_depth,
                "novel_events": self._state.novel_events_count,
                "posture_trend": self._state.posture_trend,
                "reason": self._state.assessment_reason,
            }
            if directives:
                entry["directive_summary"] = [
                    {
                        "type": d.directive_type,
                        "target": d.target,
                        "urgency": d.urgency,
                        "stage": d.chain_stage,
                        "novelty": d.novelty,
                    }
                    for d in directives[:10]
                ]
            with open(TACTICAL_LOG, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass

    @staticmethod
    def _first_tech(techs_str: str) -> str:
        if not techs_str:
            return ""
        try:
            parsed = json.loads(techs_str)
            return parsed[0] if parsed else ""
        except Exception:
            return techs_str[:10] if techs_str else ""

    def get_briefing(self) -> str:
        """Get a plain-English briefing of IGRIS's current assessment."""
        s = self._state
        lines = []
        lines.append(
            f"Posture: {s.posture} (threat: {s.threat_level:.0%}, "
            f"trend: {s.posture_trend})"
        )
        lines.append(f"Reason: {s.assessment_reason}")

        if s.hunt_mode:
            lines.append("Mode: HUNT — all agents at maximum collection frequency")

        if s.chain_narrative:
            lines.append("")
            lines.append(s.chain_narrative)

        if s.next_predicted_stage:
            lines.append(f"Next predicted: {s.next_predicted_stage}")

        if s.novel_events_count > 0:
            lines.append(f"Novel patterns: {s.novel_events_count}")

        if s.active_directives:
            lines.append(f"\nActive directives: {len(s.active_directives)}")
            for d in s.active_directives[:5]:
                stage_str = f" [{d.chain_stage}]" if d.chain_stage else ""
                novel_str = " (NOVEL)" if d.novelty > 0.5 else ""
                lines.append(
                    f"  {d.directive_type} {d.target}: "
                    f"{d.reason}{stage_str}{novel_str}"
                )

        if s.watched_pids:
            lines.append(f"Watching PIDs: {', '.join(s.watched_pids[:10])}")
        if s.watched_paths:
            lines.append(f"Watching paths: {len(s.watched_paths)}")
            for p in s.watched_paths[:3]:
                lines.append(f"  {p}")
        if s.watched_domains:
            lines.append(f"Watching domains: {', '.join(s.watched_domains[:5])}")

        # Directive effectiveness
        stats = self._memory.get_directive_stats()
        if stats["total"] > 0:
            lines.append(
                f"\nDirective history: {stats['total']} issued, "
                f"{stats['useful']} useful, {stats['noise']} noise "
                f"(effectiveness: {stats['effectiveness']:.0%})"
            )

        return "\n".join(lines)


# ── Directive Reader (for collector process) ─────────────────────────────────


def read_directives() -> Optional[dict]:
    """Read current IGRIS directives. Called by the collector."""
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
