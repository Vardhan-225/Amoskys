"""
IGRIS Coherence Assessment — Organism-Level Health

Evaluates cross-subsystem coherence to determine if the organism is:
  - "coherent"           — All subsystems nominal, data flowing, models fresh
  - "alive but degraded" — Some subsystems impaired, compensating
  - "compromised"        — Integrity failures detected, trust undermined
  - "blind"              — Critical supervision gaps, organism cannot see

Every assessment is deterministic and evidence-backed.
No speculation. No fuzzy scores. Clear verdicts with trace-backed reasons.
"""

import logging
from typing import Any

logger = logging.getLogger("igris.coherence")


# ── Coherence Verdicts ──────────────────────────────────────────

COHERENT = "coherent"
DEGRADED = "alive but degraded"
COMPROMISED = "compromised"
BLIND = "blind"

# Verdict priority (higher = worse)
_VERDICT_RANK = {COHERENT: 0, DEGRADED: 1, COMPROMISED: 2, BLIND: 3}


def assess(metrics: dict[str, Any], active_signal_count: int = 0) -> dict:
    """Assess organism coherence from the latest metrics snapshot.

    Returns:
        {
            "verdict": str,
            "reasons": list[str],
            "subsystem_status": dict[str, str],
            "signal_pressure": int,
        }
    """
    reasons: list[str] = []
    subsystem_status: dict[str, str] = {}
    worst_verdict = COHERENT

    def degrade(verdict: str, reason: str) -> None:
        nonlocal worst_verdict
        reasons.append(reason)
        if _VERDICT_RANK.get(verdict, 0) > _VERDICT_RANK.get(worst_verdict, 0):
            worst_verdict = verdict

    # ── Fleet Coherence ──
    fleet_total = metrics.get("fleet.total")
    fleet_healthy = metrics.get("fleet.healthy")
    fleet_offline = metrics.get("fleet.offline")

    if fleet_total is None:
        subsystem_status["fleet"] = "unknown"
        degrade(DEGRADED, "Fleet status unavailable — cannot assess agent health")
    elif fleet_offline and fleet_offline > 0:
        ratio = fleet_healthy / fleet_total if fleet_total > 0 else 0
        if ratio < 0.5:
            subsystem_status["fleet"] = "critical"
            degrade(
                COMPROMISED,
                f"Fleet severely degraded: {fleet_healthy}/{fleet_total} healthy",
            )
        else:
            subsystem_status["fleet"] = "degraded"
            degrade(
                DEGRADED,
                f"{fleet_offline} agent(s) offline ({fleet_healthy}/{fleet_total} healthy)",
            )
    else:
        subsystem_status["fleet"] = "nominal"

    # ── Transport Coherence ──
    eventbus = metrics.get("transport.eventbus_alive")
    wal_depth = metrics.get("transport.wal_queue_depth")

    if eventbus is False:
        subsystem_status["transport"] = "critical"
        degrade(COMPROMISED, "EventBus offline — event transport severed")
    elif eventbus is None:
        subsystem_status["transport"] = "unknown"
        degrade(DEGRADED, "EventBus status unknown")
    elif wal_depth is not None and wal_depth > 1000:
        subsystem_status["transport"] = "degraded"
        degrade(DEGRADED, f"WAL queue backing up: {wal_depth} pending events")
    else:
        subsystem_status["transport"] = "nominal"

    # ── Ingestion Coherence ──
    freshness = metrics.get("ingestion.freshness_seconds")
    events_5min = metrics.get("ingestion.events_last_5min")

    if freshness is not None and freshness > 600:
        subsystem_status["ingestion"] = "critical"
        degrade(
            COMPROMISED, f"No fresh events in {int(freshness)}s — ingestion may be dead"
        )
    elif freshness is not None and freshness > 300:
        subsystem_status["ingestion"] = "degraded"
        degrade(
            DEGRADED, f"Event freshness lagging: {int(freshness)}s since last event"
        )
    elif events_5min is not None and events_5min == 0 and freshness is not None:
        subsystem_status["ingestion"] = "degraded"
        degrade(DEGRADED, "Zero events in last 5 minutes")
    else:
        subsystem_status["ingestion"] = "nominal"

    # ── Intelligence Coherence ──
    risk_max = metrics.get("intelligence.device_risk_max")
    if risk_max is not None and risk_max > 80:
        subsystem_status["intelligence"] = "elevated"
        degrade(DEGRADED, f"Device risk elevated: max score {risk_max}")
    else:
        subsystem_status["intelligence"] = "nominal"

    # ── AMRDR Coherence ──
    min_weight = metrics.get("amrdr.min_weight")
    quarantined = metrics.get("amrdr.quarantined_count")
    drifting = metrics.get("amrdr.drifting_count")

    if quarantined and quarantined > 0:
        subsystem_status["amrdr"] = "critical"
        degrade(COMPROMISED, f"{quarantined} agent(s) quarantined — trust breakdown")
    elif min_weight is not None and min_weight < 0.5:
        subsystem_status["amrdr"] = "degraded"
        degrade(
            DEGRADED, f"Agent reliability degraded: min fusion weight {min_weight:.3f}"
        )
    elif drifting and drifting > 0:
        subsystem_status["amrdr"] = "drifting"
        degrade(DEGRADED, f"{drifting} agent(s) drifting from reliability baseline")
    else:
        subsystem_status["amrdr"] = "nominal"

    # ── SOMA Coherence ──
    soma_status = metrics.get("soma.status")
    model_age = metrics.get("soma.model_age_hours")

    if soma_status == "error":
        subsystem_status["soma"] = "error"
        degrade(DEGRADED, "SOMA Brain in error state")
    elif model_age is not None and model_age > 4:
        subsystem_status["soma"] = "stale"
        degrade(DEGRADED, f"SOMA model stale: {model_age:.1f}h since last training")
    elif soma_status == "no_metrics":
        subsystem_status["soma"] = "uninitialized"
        degrade(DEGRADED, "SOMA Brain not yet trained")
    else:
        subsystem_status["soma"] = "nominal"

    # ── Enrichment Coherence ──
    enrich_count = metrics.get("enrichment.available_count")

    if enrich_count is not None and enrich_count < 2:
        subsystem_status["enrichment"] = "critical"
        degrade(
            BLIND, f"Only {enrich_count}/4 enrichment stages available — organism blind"
        )
    elif enrich_count is not None and enrich_count < 4:
        subsystem_status["enrichment"] = "degraded"
        degrade(DEGRADED, f"{enrich_count}/4 enrichment stages available")
    elif enrich_count is None:
        subsystem_status["enrichment"] = "unknown"
    else:
        subsystem_status["enrichment"] = "nominal"

    # ── Integrity Coherence ──
    dead_letter_hour = metrics.get("integrity.dead_letter_last_hour")
    schema_ok = metrics.get("integrity.schema_complete")
    chain_cols = metrics.get("integrity.wal_has_chain_columns")

    if dead_letter_hour and dead_letter_hour > 0:
        subsystem_status["integrity"] = "warning"
        degrade(COMPROMISED, f"{dead_letter_hour} integrity failure(s) in last hour")
    elif schema_ok is False:
        subsystem_status["integrity"] = "warning"
        degrade(DEGRADED, "Schema migrations incomplete")
    elif chain_cols is False:
        subsystem_status["integrity"] = "degraded"
        degrade(DEGRADED, "WAL hash chain columns missing — legacy mode")
    else:
        subsystem_status["integrity"] = "nominal"

    # ── Final Assessment ──
    if not reasons:
        reasons.append("All subsystems nominal. Data flowing. Models fresh.")

    # If most subsystems are "unknown" (web-only deployment, no local agents),
    # cap the verdict at DEGRADED — "unknown" means we can't assess, not that
    # something is actively compromised.
    unknown_count = sum(1 for v in subsystem_status.values() if v == "unknown")
    critical_count = sum(1 for v in subsystem_status.values() if v == "critical")
    total_subs = len(subsystem_status) or 1
    if unknown_count >= total_subs * 0.5 and critical_count == 0:
        if _VERDICT_RANK.get(worst_verdict, 0) > _VERDICT_RANK.get(DEGRADED, 0):
            worst_verdict = DEGRADED
            reasons.append("Fleet monitoring mode — local subsystems unavailable")

    return {
        "verdict": worst_verdict,
        "reasons": reasons,
        "subsystem_status": subsystem_status,
        "signal_pressure": active_signal_count,
    }


def format_for_c2(assessment: dict) -> str:
    """Format coherence assessment for Guardian C2 terminal."""
    verdict = assessment["verdict"]
    reasons = assessment["reasons"]
    status = assessment["subsystem_status"]

    # Verdict indicator
    verdict_icons = {
        COHERENT: "[OK]",
        DEGRADED: "[!!]",
        COMPROMISED: "[XX]",
        BLIND: "[??]",
    }
    icon = verdict_icons.get(verdict, "[  ]")

    lines = [
        "ORGANISM COHERENCE",
        "=" * 50,
        f"  Verdict: {icon} {verdict.upper()}",
        "",
    ]

    # Subsystem status grid
    lines.append("SUBSYSTEMS")
    for sub, sub_status in sorted(status.items()):
        marker = "+" if sub_status == "nominal" else "-"
        lines.append(f"  [{marker}] {sub.ljust(14)} {sub_status}")

    # Reasons
    if reasons:
        lines.append("")
        lines.append("ASSESSMENT")
        for reason in reasons:
            lines.append(f"  {reason}")

    # Signal pressure
    pressure = assessment.get("signal_pressure", 0)
    if pressure > 0:
        lines.append("")
        lines.append(f"Signal pressure: {pressure} active condition(s)")

    return "\n".join(lines)
