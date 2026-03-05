"""
IGRIS Dispatcher — Signal-to-Playbook Mapping

Maps governance signals to deterministic Guardian C2 command playbooks.
Every recommendation is a concrete, executable C2 command — not speculation.

Phase 2: Advisor mode. Dry-run by default. Commands are surfaced as
recommendations, not executed automatically.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

from .signals import SignalType

logger = logging.getLogger("igris.dispatcher")


@dataclass
class Playbook:
    """A deterministic response playbook for a governance signal."""

    name: str
    description: str
    commands: list[str]  # Guardian C2 commands in execution order
    severity_floor: str = "low"  # Minimum severity to recommend this playbook
    requires_confirmation: bool = True  # Phase 3: gated actuation flag


# ── Playbook Registry ──────────────────────────────────────────
# Each signal type maps to one or more playbooks, ordered by relevance.
# Commands use exact Guardian C2 syntax.

PLAYBOOKS: dict[str, list[Playbook]] = {
    # ── Fleet Stability ──
    f"{SignalType.STABILITY_WARNING.value}:fleet": [
        Playbook(
            name="fleet_recovery",
            description="Diagnose and recover offline agents",
            commands=[
                "fleet",  # Check current fleet status
                "status <agent_id>",  # Inspect specific agent
                "start <agent_id>",  # Restart offline agent
                "fleet",  # Verify recovery
            ],
        ),
    ],
    f"{SignalType.STABILITY_WARNING.value}:transport": [
        Playbook(
            name="transport_recovery",
            description="Diagnose EventBus connectivity",
            commands=[
                "fleet",  # Check fleet for context
                "igris metrics",  # Full metric snapshot
            ],
        ),
    ],
    f"{SignalType.STABILITY_WARNING.value}:ingestion": [
        Playbook(
            name="ingestion_investigation",
            description="Investigate abnormal event rates",
            commands=[
                "igris metrics",  # Check ingestion section
                "igris baseline ingestion",  # Compare to learned baseline
                "events 10",  # Sample recent events
            ],
        ),
    ],
    # ── Transport Backpressure ──
    f"{SignalType.TRANSPORT_BACKPRESSURE.value}:transport": [
        Playbook(
            name="backpressure_relief",
            description="Relieve WAL queue backpressure",
            commands=[
                "igris metrics",  # Check WAL depth
                "fleet",  # Verify processor is running
            ],
            severity_floor="medium",
        ),
    ],
    # ── Drift Warning ──
    f"{SignalType.DRIFT_WARNING.value}:amrdr": [
        Playbook(
            name="reliability_review",
            description="Review agent reliability and AMRDR state",
            commands=[
                "igris metrics",  # Check AMRDR section
                "reliability",  # Full reliability table
            ],
        ),
    ],
    # ── Integrity Warning ──
    f"{SignalType.INTEGRITY_WARNING.value}:transport": [
        Playbook(
            name="integrity_investigation",
            description="Investigate data integrity failures",
            commands=[
                "igris metrics",  # Check integrity section
                "events 5",  # Sample recent events
            ],
            severity_floor="medium",
        ),
    ],
    f"{SignalType.INTEGRITY_WARNING.value}:integrity": [
        Playbook(
            name="dead_letter_investigation",
            description="Investigate dead letter queue entries",
            commands=[
                "igris metrics",  # Check integrity metrics
            ],
            severity_floor="medium",
        ),
    ],
    # ── Model Staleness ──
    f"{SignalType.MODEL_STALENESS.value}:soma": [
        Playbook(
            name="soma_refresh",
            description="Refresh SOMA Brain model",
            commands=[
                "soma status",  # Check current SOMA state
                "soma train",  # Trigger retraining
                "soma status",  # Verify training started
            ],
        ),
    ],
    # ── Supervision Deficit ──
    f"{SignalType.SUPERVISION_DEFICIT.value}:enrichment": [
        Playbook(
            name="enrichment_recovery",
            description="Diagnose enrichment pipeline gaps",
            commands=[
                "igris metrics",  # Check enrichment section
            ],
        ),
    ],
}

# Severity rank for floor comparison
_SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class Dispatcher:
    """Maps IGRIS signals to actionable C2 playbooks.

    Deterministic. No speculation. Every command is a real Guardian C2 command.
    """

    def get_playbook(
        self,
        signal_type: str,
        subsystem: str,
        severity: str = "low",
    ) -> Optional[Playbook]:
        """Find the best matching playbook for a signal.

        Looks up by "{signal_type}:{subsystem}", then filters by severity floor.
        Returns the first matching playbook, or None.
        """
        key = f"{signal_type}:{subsystem}"
        candidates = PLAYBOOKS.get(key, [])

        sig_rank = _SEV_RANK.get(severity.lower(), 0)

        for playbook in candidates:
            floor_rank = _SEV_RANK.get(playbook.severity_floor.lower(), 0)
            if sig_rank >= floor_rank:
                return playbook

        return None

    def get_recommendation(
        self,
        signal_type: str,
        subsystem: str,
        severity: str = "low",
        metric_name: str = "",
        agent_id: str | None = None,
    ) -> dict:
        """Generate a structured recommendation for a signal.

        Returns a dict with playbook name, description, commands, and
        whether the recommendation requires confirmation (Phase 3).
        """
        playbook = self.get_playbook(signal_type, subsystem, severity)

        if not playbook:
            return {
                "playbook": None,
                "description": "No playbook mapped for this condition.",
                "commands": [],
                "requires_confirmation": True,
            }

        # Substitute <agent_id> placeholder if we have a specific agent
        commands = []
        for cmd in playbook.commands:
            if agent_id and "<agent_id>" in cmd:
                commands.append(cmd.replace("<agent_id>", agent_id))
            else:
                commands.append(cmd)

        return {
            "playbook": playbook.name,
            "description": playbook.description,
            "commands": commands,
            "requires_confirmation": playbook.requires_confirmation,
        }

    def format_for_c2(
        self,
        signal_type: str,
        subsystem: str,
        severity: str = "low",
        metric_name: str = "",
        agent_id: str | None = None,
    ) -> str:
        """Format a recommendation as a C2 terminal output block."""
        rec = self.get_recommendation(
            signal_type, subsystem, severity, metric_name, agent_id
        )

        if not rec["playbook"]:
            return "No playbook available for this condition."

        lines = [
            f"PLAYBOOK: {rec['playbook']}",
            f"  {rec['description']}",
            "",
            "RECOMMENDED COMMANDS:",
        ]
        for i, cmd in enumerate(rec["commands"], 1):
            lines.append(f"  {i}. {cmd}")

        if rec["requires_confirmation"]:
            lines.append("")
            lines.append("  [requires operator confirmation]")

        return "\n".join(lines)
