"""IGRIS Kill Chain Reader — reads KillChainTracker state for posture assessment.

IGRIS was counting events. Now it reads the battlefield topology.

The kill chain tracker already knows:
    - Which attack stages have been reached
    - How many stages are active
    - Whether multi-stage thresholds are crossed
    - Time progression through the chain

IGRIS uses this to:
    - Weight posture by chain depth (3 stages > 15 events)
    - Identify which stage the attacker is at NOW
    - Predict what comes next
    - Focus investigation actions on the current stage

The 7 stages (Lockheed Martin Cyber Kill Chain):
    1. reconnaissance    — target scanning, info gathering
    2. weaponization     — payload creation (usually off-target)
    3. delivery          — phishing, drive-by, USB drop
    4. exploitation      — vulnerability trigger, user execution
    5. installation      — persistence, backdoor drop
    6. command_and_control — C2 callback, beacon
    7. actions_on_objectives — data theft, destruction, lateral movement
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("igris.chain_reader")

DATA_DIR = Path("data")
TELEMETRY_DB = DATA_DIR / "telemetry.db"
FUSION_DB = DATA_DIR / "intel" / "fusion.db"

# Maps event categories to kill chain stages
CATEGORY_TO_STAGE = {
    # Reconnaissance
    "topology_new_route": "reconnaissance",
    "arp_new_host": "reconnaissance",
    "discovery_burst": "reconnaissance",
    "rogue_dhcp": "reconnaissance",
    # Delivery
    "macos_download_new": "delivery",
    "macos_quarantine_bypass": "delivery",
    "usb_mass_storage": "delivery",
    "sharing_nearby_peer": "delivery",
    # Exploitation / Execution
    "lolbin_execution": "exploitation",
    "suspicious_script": "exploitation",
    "process_spawned": "exploitation",
    "xprotect_malware_blocked": "exploitation",
    "amfi_code_signing_denied": "exploitation",
    # Installation / Persistence
    "macos_launchagent_new": "installation",
    "macos_launchdaemon_new": "installation",
    "macos_shell_profile_modified": "installation",
    "macos_ssh_key_modified": "installation",
    "persistence_creation": "installation",
    "macos_cron_modified": "installation",
    "critical_file_modified": "installation",
    # Command and Control
    "c2_beacon_suspect": "command_and_control",
    "dns_dga_suspect": "command_and_control",
    "dns_tunnel_suspect": "command_and_control",
    # Credential Access (maps to actions_on_objectives)
    "keychain_cli_abuse": "actions_on_objectives",
    "browser_credential_theft": "actions_on_objectives",
    "session_cookie_theft": "actions_on_objectives",
    # Exfiltration (actions on objectives)
    "exfil_spike": "actions_on_objectives",
    "data_staging": "actions_on_objectives",
}

# Stage order for progression tracking
STAGE_ORDER = [
    "reconnaissance",
    "weaponization",
    "delivery",
    "exploitation",
    "installation",
    "command_and_control",
    "actions_on_objectives",
]

# What to expect next given current stage
NEXT_STAGE_PREDICTION = {
    "reconnaissance": ("delivery", "Attacker may deliver payload next"),
    "delivery": ("exploitation", "Payload delivered — expect execution attempt"),
    "exploitation": (
        "installation",
        "Code executed — expect persistence mechanism next",
    ),
    "installation": (
        "command_and_control",
        "Persistence established — expect C2 callback",
    ),
    "command_and_control": (
        "actions_on_objectives",
        "C2 active — expect data theft or lateral movement",
    ),
    "actions_on_objectives": (
        None,
        "Final stage — attacker is achieving objectives NOW",
    ),
}


class KillChainAssessment:
    """Assessment of current kill chain state."""

    def __init__(self):
        self.stages_reached: Dict[str, List[dict]] = {}
        self.stage_count: int = 0
        self.max_stage_index: int = -1
        self.max_stage_name: str = ""
        self.is_multi_stage: bool = False
        self.chain_depth: float = 0.0  # 0.0-1.0
        self.next_predicted_stage: str = ""
        self.next_prediction_reason: str = ""
        self.threat_multiplier: float = 1.0
        self.narrative: str = ""

    def to_dict(self) -> dict:
        return {
            "stages_reached": {k: len(v) for k, v in self.stages_reached.items()},
            "stage_count": self.stage_count,
            "max_stage": self.max_stage_name,
            "is_multi_stage": self.is_multi_stage,
            "chain_depth": self.chain_depth,
            "next_predicted": self.next_predicted_stage,
            "next_reason": self.next_prediction_reason,
            "threat_multiplier": self.threat_multiplier,
            "narrative": self.narrative,
        }


class IGRISChainReader:
    """Reads kill chain state from telemetry and provides tactical assessment.

    Instead of counting events blindly, this reads the kill chain topology
    and tells IGRIS where the attacker is in the progression.
    """

    def assess_chain(self, window_seconds: int = 600) -> KillChainAssessment:
        """Assess current kill chain state from recent security events."""
        assessment = KillChainAssessment()

        events = self._read_events(window_seconds)
        if not events:
            assessment.narrative = "No security events in assessment window."
            return assessment

        # Map events to kill chain stages
        for event in events:
            category = event.get("event_category", "")
            stage = CATEGORY_TO_STAGE.get(category)
            if not stage:
                continue

            if stage not in assessment.stages_reached:
                assessment.stages_reached[stage] = []
            assessment.stages_reached[stage].append(
                {
                    "category": category,
                    "risk": event.get("risk_score", 0),
                    "timestamp_ns": event.get("event_timestamp_ns", 0),
                    "techniques": event.get("mitre_techniques", ""),
                }
            )

        assessment.stage_count = len(assessment.stages_reached)

        # Find the deepest stage reached
        for i, stage_name in enumerate(STAGE_ORDER):
            if stage_name in assessment.stages_reached:
                assessment.max_stage_index = i
                assessment.max_stage_name = stage_name

        # Multi-stage detection
        assessment.is_multi_stage = assessment.stage_count >= 3

        # Chain depth: 0.0 = no chain, 1.0 = all 7 stages
        assessment.chain_depth = assessment.stage_count / len(STAGE_ORDER)

        # Predict next stage
        if assessment.max_stage_name:
            pred = NEXT_STAGE_PREDICTION.get(assessment.max_stage_name)
            if pred:
                assessment.next_predicted_stage = pred[0] or ""
                assessment.next_prediction_reason = pred[1]

        # Threat multiplier: deeper chains multiply the threat level
        if assessment.stage_count >= 5:
            assessment.threat_multiplier = 2.5
        elif assessment.stage_count >= 4:
            assessment.threat_multiplier = 2.0
        elif assessment.stage_count >= 3:
            assessment.threat_multiplier = 1.5
        elif assessment.stage_count >= 2:
            assessment.threat_multiplier = 1.2
        else:
            assessment.threat_multiplier = 1.0

        # Build narrative
        assessment.narrative = self._build_narrative(assessment)

        return assessment

    def get_stage_timeline(self, window_seconds: int = 3600) -> List[Dict[str, Any]]:
        """Get a timeline of kill chain stage progression."""
        events = self._read_events(window_seconds)
        timeline = []
        for event in sorted(events, key=lambda e: e.get("event_timestamp_ns", 0)):
            category = event.get("event_category", "")
            stage = CATEGORY_TO_STAGE.get(category)
            if stage:
                timeline.append(
                    {
                        "stage": stage,
                        "stage_index": STAGE_ORDER.index(stage),
                        "category": category,
                        "risk": event.get("risk_score", 0),
                        "timestamp_ns": event.get("event_timestamp_ns", 0),
                    }
                )
        return timeline

    def _read_events(self, window_seconds: int) -> List[dict]:
        """Read recent security events from telemetry.db."""
        if not TELEMETRY_DB.exists():
            return []
        try:
            conn = sqlite3.connect(str(TELEMETRY_DB), timeout=2)
            conn.row_factory = sqlite3.Row
            cutoff_ns = int((time.time() - window_seconds) * 1e9)
            rows = conn.execute(
                """SELECT event_category, risk_score, mitre_techniques,
                          event_timestamp_ns
                   FROM security_events
                   WHERE event_timestamp_ns > ? AND risk_score >= 0.4
                   ORDER BY event_timestamp_ns ASC
                   LIMIT 500""",
                (cutoff_ns,),
            ).fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.debug("Chain reader query failed: %s", e)
            return []

    def _build_narrative(self, a: KillChainAssessment) -> str:
        """Build a plain-English narrative of the kill chain state."""
        if a.stage_count == 0:
            return "No kill chain activity detected."

        stages_str = ", ".join(
            f"{s} ({len(evts)} events)"
            for s, evts in sorted(
                a.stages_reached.items(),
                key=lambda x: STAGE_ORDER.index(x[0]) if x[0] in STAGE_ORDER else 99,
            )
        )

        lines = []
        lines.append(
            f"Kill chain: {a.stage_count} of 7 stages active "
            f"(depth: {a.chain_depth:.0%})"
        )
        lines.append(f"Stages: {stages_str}")
        lines.append(f"Deepest stage: {a.max_stage_name}")

        if a.is_multi_stage:
            lines.append(
                f"MULTI-STAGE ATTACK: threat multiplier {a.threat_multiplier}x"
            )

        if a.next_predicted_stage:
            lines.append(
                f"Next predicted: {a.next_predicted_stage} — "
                f"{a.next_prediction_reason}"
            )

        return "\n".join(lines)
