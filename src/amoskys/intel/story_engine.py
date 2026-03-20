"""
AMOSKYS Attack Story Engine
============================
Reconstructs coherent attack stories from fusion incidents by hydrating
event evidence across all telemetry tables, mapping to kill chain stages,
and collapsing related incidents into single narratives.

Install as: src/amoskys/intel/story_engine.py

The StoryEngine is the foundation layer — pure logic, no API calls,
fully testable. The IGRIS Narrator (narrator.py) consumes its output
to produce human-readable briefings.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# ── Kill Chain Stages (Lockheed Martin + MITRE hybrid) ─────────

KILL_CHAIN_STAGES = [
    "reconnaissance",
    "delivery",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
]

# MITRE technique → kill chain stage mapping
TECHNIQUE_TO_STAGE = {
    # Reconnaissance
    "T1595": "reconnaissance",
    "T1595.002": "reconnaissance",
    "T1595.003": "reconnaissance",
    # Delivery / Initial Access
    "T1190": "delivery",
    "T1566": "delivery",
    "T1566.001": "delivery",
    "T1566.002": "delivery",
    "T1204": "delivery",
    "T1204.002": "delivery",
    # Execution
    "T1059": "execution",
    "T1059.002": "execution",
    "T1059.004": "execution",
    "T1059.006": "execution",
    "T1059.007": "execution",
    "T1106": "execution",
    "T1218": "execution",
    # Persistence
    "T1543": "persistence",
    "T1543.001": "persistence",
    "T1543.004": "persistence",
    "T1053": "persistence",
    "T1053.003": "persistence",
    "T1546": "persistence",
    "T1546.004": "persistence",
    "T1546.014": "persistence",
    "T1546.015": "persistence",
    "T1547": "persistence",
    "T1547.006": "persistence",
    "T1547.007": "persistence",
    "T1547.015": "persistence",
    "T1098": "persistence",
    "T1098.004": "persistence",
    "T1037": "persistence",
    "T1037.002": "persistence",
    # Privilege Escalation
    "T1548": "privilege_escalation",
    "T1548.001": "privilege_escalation",
    "T1548.003": "privilege_escalation",
    # Defense Evasion
    "T1036": "defense_evasion",
    "T1036.005": "defense_evasion",
    "T1070": "defense_evasion",
    "T1070.002": "defense_evasion",
    "T1070.003": "defense_evasion",
    "T1070.004": "defense_evasion",
    "T1070.006": "defense_evasion",
    "T1562": "defense_evasion",
    "T1562.001": "defense_evasion",
    "T1564": "defense_evasion",
    "T1564.001": "defense_evasion",
    "T1553": "defense_evasion",
    "T1553.001": "defense_evasion",
    "T1140": "defense_evasion",
    "T1027": "defense_evasion",
    "T1574": "defense_evasion",
    "T1574.004": "defense_evasion",
    "T1574.006": "defense_evasion",
    # Credential Access
    "T1555": "credential_access",
    "T1555.001": "credential_access",
    "T1555.003": "credential_access",
    "T1539": "credential_access",
    "T1110": "credential_access",
    "T1110.001": "credential_access",
    "T1056": "credential_access",
    "T1056.002": "credential_access",
    "T1552": "credential_access",
    "T1552.001": "credential_access",
    "T1552.004": "credential_access",
    # Discovery
    "T1082": "discovery",
    "T1083": "discovery",
    "T1057": "discovery",
    "T1016": "discovery",
    "T1018": "discovery",
    "T1033": "discovery",
    "T1049": "discovery",
    "T1087": "discovery",
    "T1087.001": "discovery",
    "T1046": "discovery",
    "T1007": "discovery",
    "T1518": "discovery",
    "T1518.001": "discovery",
    # Lateral Movement
    "T1021": "lateral_movement",
    "T1021.004": "lateral_movement",
    "T1105": "lateral_movement",
    # Collection
    "T1005": "collection",
    "T1113": "collection",
    "T1115": "collection",
    "T1560": "collection",
    "T1560.001": "collection",
    # Command and Control
    "T1071": "command_and_control",
    "T1071.001": "command_and_control",
    "T1071.004": "command_and_control",
    "T1568": "command_and_control",
    "T1568.002": "command_and_control",
    "T1572": "command_and_control",
    "T1571": "command_and_control",
    "T1090": "command_and_control",
    # Exfiltration
    "T1041": "exfiltration",
    "T1048": "exfiltration",
    "T1567": "exfiltration",
    "T1567.002": "exfiltration",
    # Impact
    "T1485": "impact",
    "T1486": "impact",
    "T1490": "impact",
    "T1496": "impact",
    "T1529": "impact",
}

# MITRE technique human names
TECHNIQUE_NAMES = {
    "T1543.001": "LaunchAgent Persistence",
    "T1543.004": "LaunchDaemon Persistence",
    "T1053.003": "Cron Job Persistence",
    "T1546.004": "Shell Profile Modification",
    "T1098.004": "SSH Authorized Keys",
    "T1546.015": "Folder Action Persistence",
    "T1555.001": "Keychain Credential Theft",
    "T1555.003": "Browser Credential Theft",
    "T1539": "Session Cookie Theft",
    "T1005": "Local Data Collection",
    "T1059.004": "Unix Shell Execution",
    "T1059.002": "AppleScript Execution",
    "T1041": "Exfiltration Over C2",
    "T1071.001": "HTTP C2 Channel",
    "T1071.004": "DNS C2 Channel",
    "T1568.002": "Domain Generation Algorithm",
    "T1572": "Protocol Tunneling",
    "T1046": "Port Scanning",
    "T1110.001": "Password Brute Force",
    "T1078": "Valid Account Login",
    "T1082": "System Fingerprinting",
    "T1036.005": "Process Masquerading",
    "T1574.004": "DYLD Injection",
    "T1562.001": "Security Tool Disabled",
    "T1548.003": "Sudo Abuse",
    "T1070.002": "Log Clearing",
    "T1070.004": "File Deletion",
    "T1564.001": "Hidden Files",
    "T1553.001": "Gatekeeper Bypass",
    "T1560.001": "Data Archiving",
    "T1204": "User Execution",
    "T1204.002": "Malicious File Execution",
    "T1113": "Screen Capture",
    "T1115": "Clipboard Theft",
    "T1105": "Tool Transfer",
    "T1218": "LOLBin Execution",
    "T1056.002": "Fake Password Dialog",
}


# ── Known Attack Patterns (for template-based narration) ────────

# Event category → MITRE technique mapping (for incidents without explicit techniques)
CATEGORY_TO_TECHNIQUE = {
    "browser_credential_theft": "T1555.003",
    "browser_credential": "T1555.003",
    "session_cookie_theft": "T1539",
    "keychain_cli_abuse": "T1555.001",
    "keychain_credential": "T1555.001",
    "credential_access": "T1555",
    "fake_password_dialog": "T1056.002",
    "sensitive_file_exfil": "T1041",
    "exfiltration": "T1041",
    "data_staging": "T1560.001",
    "late_night_connections": "T1071.001",
    "c2_communication": "T1071.001",
    "dns_tunneling": "T1071.004",
    "dga_domain": "T1568.002",
    "launchagent_persistence": "T1543.001",
    "launchdaemon_persistence": "T1543.004",
    "cron_persistence": "T1053.003",
    "shell_profile_modification": "T1546.004",
    "ssh_authorized_keys": "T1098.004",
    "ssh_brute_force": "T1110.001",
    "tcc_developer_tool": "T1059.004",
    "tcc": "T1059.004",
    "screen_capture": "T1113",
    "clipboard_theft": "T1115",
    "process_masquerading": "T1036.005",
    "dyld_injection": "T1574.006",
    "gatekeeper_bypass": "T1553.001",
    "security_tool_disabled": "T1562.001",
    "sudo_abuse": "T1548.003",
    "log_clearing": "T1070.002",
    "hidden_files": "T1564.001",
    "applescript_execution": "T1059.002",
    "folder_action": "T1546.015",
}

KNOWN_PATTERNS = {
    "amos_stealer": {
        "name": "AMOS Stealer",
        "required_stages": {"persistence", "credential_access"},
        "signature_techniques": {
            "T1543.001",
            "T1555.001",
            "T1555.003",
            "T1539",
            "T1056.002",
        },
        "min_match": 1,
        "description": "macOS infostealer targeting keychain, browser credentials, and crypto wallets",
    },
    "credential_harvest": {
        "name": "Credential Harvesting",
        "required_stages": {"credential_access"},
        "signature_techniques": {"T1555", "T1555.001", "T1555.003", "T1539", "T1041"},
        "min_match": 1,
        "description": "Credential theft and exfiltration (browser, keychain, session cookies)",
    },
    "ssh_brute_force": {
        "name": "SSH Brute Force + Persistence",
        "required_stages": {"credential_access"},
        "signature_techniques": {"T1110.001", "T1078", "T1543.001"},
        "min_match": 2,
        "description": "Remote brute force attack followed by persistence installation",
    },
    "dns_c2": {
        "name": "DNS C2 Channel",
        "required_stages": {"command_and_control"},
        "signature_techniques": {"T1071.004", "T1568.002", "T1572"},
        "min_match": 2,
        "description": "Command and control communication via DNS tunneling or DGA",
    },
    "privilege_escalation": {
        "name": "Privilege Escalation + Defense Evasion",
        "required_stages": {"privilege_escalation", "defense_evasion"},
        "signature_techniques": {"T1548.003", "T1562.001", "T1070.002"},
        "min_match": 2,
        "description": "Sudo exploitation followed by security tool disabling and log clearing",
    },
    "clickfix_stealer": {
        "name": "ClickFix Social Engineering",
        "required_stages": {"execution", "credential_access"},
        "signature_techniques": {"T1059.002", "T1056.002", "T1555.001"},
        "min_match": 2,
        "description": "AppleScript-based fake dialog credential theft via Terminal paste",
    },
    "reverse_shell": {
        "name": "Reverse Shell + Discovery",
        "required_stages": {"execution", "discovery"},
        "signature_techniques": {"T1059.004", "T1082", "T1057"},
        "min_match": 2,
        "description": "Shell execution from temp directory followed by system enumeration",
    },
}


# ── Data Classes ────────────────────────────────────────────────


@dataclass
class StageEvidence:
    """Evidence for one kill chain stage."""

    stage: str
    techniques: List[str]
    events: List[Dict[str, Any]]
    first_seen: float  # epoch seconds
    last_seen: float
    summary: str  # One-line summary of what happened at this stage

    @property
    def technique_names(self) -> List[str]:
        return [TECHNIQUE_NAMES.get(t, t) for t in self.techniques]

    @property
    def duration_seconds(self) -> float:
        return max(0, self.last_seen - self.first_seen)


@dataclass
class AttackStory:
    """A complete attack story reconstructed from fusion incidents."""

    story_id: str
    incident_ids: List[str]
    pattern_name: Optional[str]  # e.g., "amos_stealer" or None for unknown
    pattern_label: str  # Human name: "AMOS Stealer" or "Unknown Attack Chain"
    kill_chain: List[StageEvidence]  # Ordered by time
    severity: str
    confidence: float
    techniques: List[str]  # All unique MITRE techniques
    affected_assets: List[str]  # File paths, IPs, users, domains
    first_event: float  # epoch seconds
    last_event: float
    raw_event_count: int
    narrative_context: Dict[str, Any]  # Structured context for IGRIS narrator

    @property
    def duration_seconds(self) -> float:
        return max(0, self.last_event - self.first_event)

    @property
    def stage_count(self) -> int:
        return len(self.kill_chain)

    @property
    def stage_names(self) -> List[str]:
        return [s.stage for s in self.kill_chain]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "story_id": self.story_id,
            "incident_ids": self.incident_ids,
            "pattern_name": self.pattern_name,
            "pattern_label": self.pattern_label,
            "severity": self.severity,
            "confidence": self.confidence,
            "techniques": self.techniques,
            "affected_assets": self.affected_assets,
            "first_event": self.first_event,
            "last_event": self.last_event,
            "duration_seconds": self.duration_seconds,
            "stage_count": self.stage_count,
            "raw_event_count": self.raw_event_count,
            "kill_chain": [
                {
                    "stage": s.stage,
                    "techniques": s.techniques,
                    "technique_names": s.technique_names,
                    "summary": s.summary,
                    "first_seen": s.first_seen,
                    "last_seen": s.last_seen,
                    "event_count": len(s.events),
                }
                for s in self.kill_chain
            ],
        }


# ── Story Engine ────────────────────────────────────────────────


class StoryEngine:
    """Reconstructs attack stories from fusion incidents.

    Usage:
        engine = StoryEngine(telemetry_db="data/telemetry.db", fusion_db="data/intel/fusion.db")
        stories = engine.build_stories(hours=1)
        for story in stories:
            print(story.pattern_label, story.severity, story.stage_count, "stages")
    """

    def __init__(
        self,
        telemetry_db: str = "data/telemetry.db",
        fusion_db: str = "data/intel/fusion.db",
        collapse_window_seconds: float = 3600,  # 1 hour
    ):
        self.telemetry_db = telemetry_db
        self.fusion_db = fusion_db
        self.collapse_window = collapse_window_seconds

    def build_stories(
        self,
        hours: int = 1,
        min_severity: str = "high",
    ) -> List[AttackStory]:
        """Build attack stories from recent fusion incidents.

        Args:
            hours: Look back window
            min_severity: Minimum incident severity to process

        Returns:
            List of AttackStory objects, newest first
        """
        # 1. Fetch fusion incidents
        incidents = self._fetch_incidents(hours, min_severity)
        if not incidents:
            return []

        # 2. Group related incidents (temporal proximity + shared techniques)
        groups = self._group_related_incidents(incidents)

        # 3. Build a story for each group
        stories = []
        for group in groups:
            story = self._build_story(group)
            if story and story.stage_count >= 1:
                stories.append(story)

        # Sort by severity (critical first), then by time (newest first)
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        stories.sort(key=lambda s: (sev_order.get(s.severity, 4), -s.last_event))

        return stories

    def build_story_for_incident(self, incident_id: str) -> Optional[AttackStory]:
        """Build a story for a specific incident ID."""
        incidents = self._fetch_incident_by_id(incident_id)
        if not incidents:
            return None
        return self._build_story(incidents)

    # ── Incident Fetching ──────────────────────────────────────

    def _fetch_incidents(self, hours: int, min_severity: str) -> List[Dict[str, Any]]:
        """Fetch fusion incidents from the last N hours."""
        sev_filter = {"critical", "high"}
        if min_severity.lower() == "medium":
            sev_filter.add("medium")
        elif min_severity.lower() in ("low", "info"):
            sev_filter.update({"medium", "low"})

        rows = self._query(
            "SELECT * FROM incidents ORDER BY created_at DESC",
            db_path=self.fusion_db,
        )

        cutoff = time.time() - (hours * 3600)
        filtered = []
        for r in rows:
            sev = (r.get("severity") or "medium").lower()
            if sev not in sev_filter:
                continue
            # Parse created_at
            created = r.get("created_at", "")
            try:
                dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                if dt.timestamp() < cutoff:
                    continue
            except (ValueError, TypeError):
                pass
            filtered.append(r)

        return filtered

    def _fetch_incident_by_id(self, incident_id: str) -> List[Dict]:
        rows = self._query(
            "SELECT * FROM incidents WHERE incident_id = ?",
            (incident_id,),
            db_path=self.fusion_db,
        )
        return rows

    # ── Incident Grouping ──────────────────────────────────────

    def _group_related_incidents(self, incidents: List[Dict]) -> List[List[Dict]]:
        """Group incidents by rule_name + temporal proximity, then by shared techniques.

        Live data shows most incidents (201/239) are 'high_risk_detections' with
        empty techniques — grouping by rule_name within the collapse window
        prevents 201 identical stories.
        """
        if not incidents:
            return []

        groups: List[List[Dict]] = []
        used: Set[int] = set()

        for i, inc in enumerate(incidents):
            if i in used:
                continue

            group = [inc]
            used.add(i)
            inc_rule = inc.get("rule_name", "")
            inc_techs = set(self._parse_json(inc.get("techniques", "[]")))
            inc_time = self._parse_timestamp(inc.get("created_at", ""))

            for j, other in enumerate(incidents):
                if j not in used and self._should_group(
                    inc_rule,
                    inc_techs,
                    inc_time,
                    other,
                ):
                    group.append(other)
                    used.add(j)

            groups.append(group)

        return groups

    def _should_group(
        self,
        rule: str,
        techs: Set[str],
        ts: float,
        other: Dict,
    ) -> bool:
        """Check if another incident belongs in the same group."""
        other_time = self._parse_timestamp(other.get("created_at", ""))
        if abs(ts - other_time) >= self.collapse_window:
            return False
        other_rule = other.get("rule_name", "")
        if rule and rule == other_rule:
            return True
        other_techs = set(self._parse_json(other.get("techniques", "[]")))
        return bool(techs and other_techs and techs & other_techs)

    # ── Story Building ─────────────────────────────────────────

    def _build_story(self, incidents: List[Dict]) -> Optional[AttackStory]:
        """Build an AttackStory from a group of related incidents."""
        if not incidents:
            return None

        # Collect all event IDs and techniques
        all_event_ids: Set[str] = set()
        all_techniques: Set[str] = set()
        all_tactics: Set[str] = set()
        worst_severity = "low"
        max_confidence = 0.0
        incident_ids = []

        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}

        for inc in incidents:
            incident_ids.append(inc.get("incident_id", str(id(inc))))

            # Parse event IDs
            eids = self._parse_json(inc.get("event_ids", "[]"))
            all_event_ids.update(str(e) for e in eids)

            # Parse techniques (explicit)
            techs = self._parse_json(inc.get("techniques", "[]"))
            all_techniques.update(techs)

            # Extract techniques from mitre_sequence JSON
            all_techniques.update(self._extract_techniques_from_sequence(inc))

            # Infer techniques from summary categories
            all_techniques.update(self._infer_techniques_from_summary(inc))

            # Infer techniques from event ID strings
            all_techniques.update(self._infer_techniques_from_event_ids(eids))

            # Parse tactics
            tacs = self._parse_json(inc.get("tactics", "[]"))
            all_tactics.update(tacs)

            # Track worst severity
            sev = (inc.get("severity") or "medium").lower()
            if sev_rank.get(sev, 0) > sev_rank.get(worst_severity, 0):
                worst_severity = sev

            # Track max confidence
            conf = inc.get("weighted_confidence") or 0
            if conf > max_confidence:
                max_confidence = conf

        # Hydrate events from telemetry DB
        events = self._hydrate_events(all_event_ids, all_techniques)

        # Map events to kill chain stages
        stage_map = self._map_to_stages(events, all_techniques)

        # Build ordered StageEvidence list
        kill_chain = self._build_kill_chain(stage_map)

        # Extract affected assets
        assets = self._extract_assets(events)

        # Determine temporal bounds
        timestamps = [e.get("_ts", 0) for e in events if e.get("_ts")]
        first_event = min(timestamps) if timestamps else time.time()
        last_event = max(timestamps) if timestamps else time.time()

        # Pattern matching
        pattern_name, pattern_label = self._match_pattern(
            all_techniques, {s.stage for s in kill_chain}
        )

        # Generate story ID
        story_id = hashlib.sha256(
            json.dumps(sorted(incident_ids)).encode()
        ).hexdigest()[:16]

        # Build narrative context for IGRIS
        narrative_context = self._build_narrative_context(
            kill_chain, all_techniques, assets, incidents
        )

        return AttackStory(
            story_id=f"STORY-{story_id}",
            incident_ids=incident_ids,
            pattern_name=pattern_name,
            pattern_label=pattern_label,
            kill_chain=kill_chain,
            severity=worst_severity,
            confidence=max_confidence,
            techniques=sorted(all_techniques),
            affected_assets=assets,
            first_event=first_event,
            last_event=last_event,
            raw_event_count=len(events),
            narrative_context=narrative_context,
        )

    # ── Technique Extraction Helpers ──────────────────────────

    def _extract_techniques_from_sequence(self, inc: Dict) -> Set[str]:
        """Extract MITRE techniques from mitre_sequence JSON field."""
        raw = inc.get("mitre_sequence", "")
        if not raw:
            return set()
        try:
            seq = json.loads(raw) if isinstance(raw, str) else raw
            if isinstance(seq, list):
                return {
                    entry["technique"]
                    for entry in seq
                    if isinstance(entry, dict) and "technique" in entry
                }
        except (json.JSONDecodeError, TypeError):
            pass
        return set()

    def _infer_techniques_from_summary(self, inc: Dict) -> Set[str]:
        """Infer MITRE techniques from event categories mentioned in summary."""
        summary = (inc.get("summary") or "").lower()
        result: Set[str] = set()
        for category, technique in CATEGORY_TO_TECHNIQUE.items():
            if category in summary:
                result.add(technique)
        return result

    def _infer_techniques_from_event_ids(self, eids: List[str]) -> Set[str]:
        """Infer MITRE techniques from structured event ID strings.

        Event IDs look like:
        'macos_infostealer_browser_cred_theft_browser_credential_theft_1773...'
        """
        result: Set[str] = set()
        for eid in eids:
            eid_lower = str(eid).lower()
            for category, technique in CATEGORY_TO_TECHNIQUE.items():
                if category in eid_lower:
                    result.add(technique)
        return result

    # ── Event Hydration ────────────────────────────────────────

    def _hydrate_events(
        self, event_ids: Set[str], techniques: Set[str]
    ) -> List[Dict[str, Any]]:
        """Pull events from all telemetry tables."""
        events = []

        # Security events (primary source — has MITRE tags)
        for ev in self._query_telemetry(
            "SELECT * FROM security_events ORDER BY timestamp_ns DESC LIMIT 500"
        ):
            ev_techs = set(self._parse_json(ev.get("mitre_techniques", "")))
            if ev_techs & techniques:
                ev["_source"] = "security_events"
                ev["_ts"] = (ev.get("timestamp_ns") or 0) / 1e9
                events.append(ev)

        # Persistence events
        for ev in self._query_telemetry(
            "SELECT * FROM persistence_events ORDER BY timestamp_ns DESC LIMIT 200"
        ):
            ev["_source"] = "persistence_events"
            ev["_ts"] = (ev.get("timestamp_ns") or 0) / 1e9
            events.append(ev)

        # Flow events (high risk only)
        for ev in self._query_telemetry(
            "SELECT * FROM flow_events WHERE risk_score >= 0.5 "
            "ORDER BY timestamp_ns DESC LIMIT 200"
        ):
            ev["_source"] = "flow_events"
            ev["_ts"] = (ev.get("timestamp_ns") or 0) / 1e9
            events.append(ev)

        # DNS events (high risk only)
        for ev in self._query_telemetry(
            "SELECT * FROM dns_events WHERE risk_score >= 0.5 "
            "ORDER BY timestamp_ns DESC LIMIT 200"
        ):
            ev["_source"] = "dns_events"
            ev["_ts"] = (ev.get("timestamp_ns") or 0) / 1e9
            events.append(ev)

        # FIM events (high risk only)
        for ev in self._query_telemetry(
            "SELECT * FROM fim_events WHERE risk_score >= 0.5 "
            "ORDER BY timestamp_ns DESC LIMIT 200"
        ):
            ev["_source"] = "fim_events"
            ev["_ts"] = (ev.get("timestamp_ns") or 0) / 1e9
            events.append(ev)

        # Sort by timestamp
        events.sort(key=lambda e: e.get("_ts", 0))
        return events

    # ── Kill Chain Mapping ─────────────────────────────────────

    def _map_to_stages(
        self, events: List[Dict], techniques: Set[str]
    ) -> Dict[str, List[Dict]]:
        """Map events to kill chain stages based on MITRE techniques."""
        stage_map: Dict[str, List[Dict]] = {}

        # Map techniques to stages
        tech_stages: Dict[str, str] = {}
        for tech in techniques:
            stage = TECHNIQUE_TO_STAGE.get(tech)
            if stage:
                tech_stages[tech] = stage

        # Map events using their source table as fallback
        source_to_stage = {
            "persistence_events": "persistence",
            "flow_events": "command_and_control",
            "dns_events": "command_and_control",
            "fim_events": "defense_evasion",
        }

        for ev in events:
            stage = None

            # Try MITRE technique first
            ev_techs = self._parse_json(ev.get("mitre_techniques", ""))
            for tech in ev_techs:
                if tech in tech_stages:
                    stage = tech_stages[tech]
                    break

            # Fallback to source table
            if not stage:
                stage = source_to_stage.get(ev.get("_source"), "execution")

            if stage not in stage_map:
                stage_map[stage] = []
            stage_map[stage].append(ev)

        return stage_map

    def _build_kill_chain(
        self, stage_map: Dict[str, List[Dict]]
    ) -> List[StageEvidence]:
        """Build ordered StageEvidence from stage map."""
        chain = []

        for stage_name in KILL_CHAIN_STAGES:
            events = stage_map.get(stage_name, [])
            if not events:
                continue

            # Extract techniques for this stage
            techs: Set[str] = set()
            for ev in events:
                for tech in self._parse_json(ev.get("mitre_techniques", "")):
                    if TECHNIQUE_TO_STAGE.get(tech) == stage_name:
                        techs.add(tech)

            # Temporal bounds
            timestamps = [e.get("_ts", 0) for e in events if e.get("_ts")]
            first = min(timestamps) if timestamps else 0
            last = max(timestamps) if timestamps else 0

            # Generate summary
            summary = self._summarize_stage(stage_name, events, techs)

            chain.append(
                StageEvidence(
                    stage=stage_name,
                    techniques=sorted(techs),
                    events=events,
                    first_seen=first,
                    last_seen=last,
                    summary=summary,
                )
            )

        return chain

    # ── Stage Summarization ────────────────────────────────────

    def _summarize_stage(
        self, stage: str, events: List[Dict], techniques: Set[str]
    ) -> str:
        """Generate a one-line summary for a kill chain stage."""
        tech_names = [TECHNIQUE_NAMES.get(t, t) for t in sorted(techniques)]

        if stage == "persistence":
            paths = self._extract_field(events, "path", "entry_path")
            mechs = self._extract_field(events, "mechanism")
            if mechs:
                return f"Persistence via {', '.join(mechs[:3])}: {', '.join(paths[:2])}"
            return f"Persistence mechanisms installed ({len(events)} events)"

        elif stage == "credential_access":
            return (
                f"Credential theft: {', '.join(tech_names[:3])} ({len(events)} events)"
            )

        elif stage == "execution":
            cmds = self._extract_field(events, "event_category", "event_action")
            return f"Execution: {', '.join(cmds[:3])} ({len(events)} events)"

        elif stage == "command_and_control":
            domains = self._extract_field(events, "query_name", "domain")
            ips = self._extract_field(events, "remote_ip", "dst_ip")
            targets = domains[:2] + ips[:2]
            return f"C2 communication: {', '.join(targets) if targets else 'detected'} ({len(events)} events)"

        elif stage == "exfiltration":
            return f"Data exfiltration detected ({len(events)} events)"

        elif stage == "discovery":
            return f"System enumeration: {', '.join(tech_names[:3])} ({len(events)} events)"

        elif stage == "defense_evasion":
            return f"Evasion: {', '.join(tech_names[:3])} ({len(events)} events)"

        elif stage == "privilege_escalation":
            return f"Privilege escalation: {', '.join(tech_names[:2])} ({len(events)} events)"

        elif stage == "collection":
            return (
                f"Data collection: {', '.join(tech_names[:3])} ({len(events)} events)"
            )

        elif stage == "impact":
            return f"Impact: {', '.join(tech_names[:2])} ({len(events)} events)"

        return f"{stage}: {len(events)} events"

    # ── Pattern Matching ───────────────────────────────────────

    def _match_pattern(
        self, techniques: Set[str], stages: Set[str]
    ) -> Tuple[Optional[str], str]:
        """Match attack story against known patterns."""
        best_match = None
        best_score = 0

        for pattern_id, pattern in KNOWN_PATTERNS.items():
            # Check required stages
            if not pattern["required_stages"].issubset(stages):
                continue

            # Count matching signature techniques
            matches = len(techniques & pattern["signature_techniques"])
            if matches >= pattern["min_match"] and matches > best_score:
                best_match = pattern_id
                best_score = matches

        if best_match:
            return best_match, KNOWN_PATTERNS[best_match]["name"]
        return None, "Unknown Attack Chain"

    # ── Asset Extraction ───────────────────────────────────────

    def _extract_assets(self, events: List[Dict]) -> List[str]:
        """Extract unique affected assets from events."""
        assets: Set[str] = set()

        for ev in events:
            # File paths
            for fld in ("path", "entry_path", "file_path", "exe"):
                val = ev.get(fld, "")
                if val and isinstance(val, str) and "/" in val:
                    assets.add(val)

            # IPs
            for fld in ("remote_ip", "src_ip", "dst_ip"):
                val = ev.get(fld, "")
                if val and isinstance(val, str) and "." in val:
                    assets.add(val)

            # Domains
            for fld in ("query_name", "domain"):
                val = ev.get(fld, "")
                if val and isinstance(val, str) and "." in val:
                    assets.add(val)

            # Users
            for fld in ("username", "user"):
                val = ev.get(fld, "")
                if val and isinstance(val, str):
                    assets.add(f"user:{val}")

        return sorted(assets)[:20]  # Cap at 20 assets

    # ── Narrative Context ──────────────────────────────────────

    def _build_narrative_context(
        self,
        kill_chain: List[StageEvidence],
        techniques: Set[str],
        assets: List[str],
        incidents: List[Dict],
    ) -> Dict[str, Any]:
        """Build structured context for IGRIS narrator."""
        return {
            "stages": [
                {
                    "name": s.stage,
                    "techniques": s.techniques,
                    "technique_names": s.technique_names,
                    "summary": s.summary,
                    "event_count": len(s.events),
                    "duration_seconds": s.duration_seconds,
                }
                for s in kill_chain
            ],
            "all_techniques": sorted(techniques),
            "technique_descriptions": {
                t: TECHNIQUE_NAMES.get(t, t) for t in techniques
            },
            "affected_assets": assets,
            "file_paths": [a for a in assets if "/" in a],
            "ips": [a for a in assets if "." in a and "/" not in a and ":" not in a],
            "domains": [
                a
                for a in assets
                if "." in a and "/" not in a and not a.startswith("user:")
            ],
            "incident_summaries": [inc.get("summary", "") for inc in incidents],
            "contributing_agents": list(
                set(
                    a
                    for inc in incidents
                    for a in self._parse_json(inc.get("contributing_agents", "[]"))
                )
            ),
        }

    # ── Helpers ─────────────────────────────────────────────────

    def _query(self, sql: str, params: tuple = (), db_path: str = "") -> List[Dict]:
        db = db_path or self.telemetry_db
        if not Path(db).exists():
            return []
        conn = sqlite3.connect(db, timeout=5)
        conn.row_factory = sqlite3.Row
        try:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]
        except sqlite3.OperationalError:
            return []
        finally:
            conn.close()

    def _query_telemetry(self, sql: str, params: tuple = ()) -> List[Dict]:
        return self._query(sql, params, db_path=self.telemetry_db)

    def _parse_json(self, raw: Any) -> List[str]:
        if not raw:
            return []
        if isinstance(raw, list):
            return raw
        if isinstance(raw, str):
            try:
                result = json.loads(raw)
                return result if isinstance(result, list) else [result]
            except (json.JSONDecodeError, TypeError):
                return [raw] if raw else []
        return []

    def _parse_timestamp(self, ts_str: str) -> float:
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            return dt.timestamp()
        except (ValueError, TypeError, AttributeError):
            return time.time()

    def _extract_field(self, events: List[Dict], *fields: str) -> List[str]:
        """Extract unique non-empty values from events for given field names."""
        values: Set[str] = set()
        for ev in events:
            for f in fields:
                val = ev.get(f, "")
                if val and isinstance(val, str):
                    values.add(val)
        return sorted(values)[:5]
