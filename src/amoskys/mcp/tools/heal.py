"""Self-Diagnosis & Self-Healing tools — IGRIS monitors and repairs itself.

The organism doesn't just defend the fleet — it maintains its own health.
When agents go silent, pipelines stall, or coverage gaps appear, IGRIS
detects and remediates autonomously.

Diagnosis:  What's broken, degraded, or missing?
Healing:    Fix it — restart agents, flush queues, trigger collection.
"""

from __future__ import annotations

import json
import time
from typing import Any

from ..db import query, query_one, scalar, execute, hours_ago_ns, hours_ago_epoch
from ..config import cfg
from ..server import mcp


# ── Diagnosis constants ────────────────────────────────────────────

AGENT_STALE_THRESHOLD_S = 7200    # 2h without events = stale
PIPELINE_FRESH_THRESHOLD_S = 300  # 5 min max acceptable freshness
EVENT_RATE_MIN_HOURLY = 10        # Expect at least 10 events/hour
COVERAGE_EXPECTED_AGENTS = {
    "macos_proc", "macos_auth", "macos_fim", "macos_flow",
    "macos_dns", "macos_peripheral", "macos_persistence",
}

# Health status levels
OK = "ok"
DEGRADED = "degraded"
CRITICAL = "critical"
DEAD = "dead"


# ── Diagnosis Tools ────────────────────────────────────────────────


@mcp.tool()
def igris_self_diagnosis() -> dict:
    """Comprehensive self-diagnosis of the entire AMOSKYS organism.

    Checks every layer: fleet connectivity, agent health, pipeline freshness,
    telemetry flow rates, detection coverage, storage health, and brain status.

    Returns a structured health report with severity levels and recommended actions.
    """
    now = time.time()
    report: dict[str, Any] = {
        "timestamp": now,
        "overall_status": OK,
        "layers": {},
        "issues": [],
        "auto_healable": [],
    }

    issues = report["issues"]
    healable = report["auto_healable"]

    # ── Layer 1: Fleet Connectivity ────────────────────────────
    total_devices = scalar("SELECT COUNT(*) FROM devices") or 0
    online = scalar("SELECT COUNT(*) FROM devices WHERE last_seen > ?", (now - 120,)) or 0
    stale = scalar("SELECT COUNT(*) FROM devices WHERE last_seen < ? AND last_seen > 0",
                   (now - 600,)) or 0

    fleet_status = OK
    if total_devices == 0:
        fleet_status = DEAD
        issues.append({"layer": "fleet", "severity": DEAD, "msg": "No devices enrolled"})
    elif online == 0:
        fleet_status = CRITICAL
        issues.append({"layer": "fleet", "severity": CRITICAL,
                       "msg": f"All {total_devices} devices offline"})
    elif stale > 0:
        fleet_status = DEGRADED
        issues.append({"layer": "fleet", "severity": DEGRADED,
                       "msg": f"{stale} device(s) with stale heartbeat (>10min)"})

    report["layers"]["fleet"] = {
        "status": fleet_status,
        "total": total_devices, "online": online, "stale": stale,
    }

    # ── Layer 2: Agent Health (per device) ─────────────────────
    agent_issues = []
    devices = query("SELECT device_id, hostname, last_seen FROM devices")
    for dev in devices:
        did = dev["device_id"]
        cutoff = hours_ago_ns(2)

        # Which agents reported recently?
        active_agents = query("""
            SELECT DISTINCT collection_agent FROM security_events
            WHERE device_id = ? AND timestamp_ns > ?
        """, (did, cutoff))
        active_set = {r["collection_agent"] for r in active_agents}

        # Which are missing?
        missing = COVERAGE_EXPECTED_AGENTS - active_set
        if missing:
            agent_issues.append({
                "device_id": did,
                "hostname": dev.get("hostname", "unknown"),
                "missing_agents": sorted(missing),
                "active_agents": sorted(active_set),
            })
            for ma in missing:
                healable.append({
                    "action": "restart_agent",
                    "device_id": did,
                    "agent": ma,
                    "reason": f"No events from {ma} in 2h on {dev.get('hostname', did[:8])}",
                })

    agent_status = OK
    if len(agent_issues) == len(devices) and devices:
        agent_status = CRITICAL
    elif agent_issues:
        agent_status = DEGRADED

    report["layers"]["agents"] = {
        "status": agent_status,
        "issues": agent_issues[:20],
        "devices_with_gaps": len(agent_issues),
    }
    if agent_issues:
        issues.append({"layer": "agents", "severity": agent_status,
                       "msg": f"{len(agent_issues)} device(s) have silent agents"})

    # ── Layer 3: Pipeline Freshness ────────────────────────────
    latest_ns = scalar("SELECT MAX(timestamp_ns) FROM security_events")
    freshness_s = (now - latest_ns / 1e9) if latest_ns else 99999

    pipeline_status = OK
    if freshness_s > 3600:
        pipeline_status = DEAD
        issues.append({"layer": "pipeline", "severity": DEAD,
                       "msg": f"No telemetry in {freshness_s/3600:.1f}h — pipeline may be dead"})
        healable.append({"action": "trigger_collection_all",
                         "reason": "Pipeline appears dead"})
    elif freshness_s > PIPELINE_FRESH_THRESHOLD_S:
        pipeline_status = DEGRADED
        issues.append({"layer": "pipeline", "severity": DEGRADED,
                       "msg": f"Last telemetry {freshness_s:.0f}s ago (threshold: {PIPELINE_FRESH_THRESHOLD_S}s)"})
        healable.append({"action": "trigger_collection_all",
                         "reason": "Pipeline stale"})

    # Event rate
    events_1h = scalar("SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ?",
                       (hours_ago_ns(1),)) or 0

    report["layers"]["pipeline"] = {
        "status": pipeline_status,
        "freshness_s": round(freshness_s, 1),
        "events_per_hour": events_1h,
        "last_event_ago": f"{freshness_s:.0f}s",
    }

    # ── Layer 4: Detection Quality ─────────────────────────────
    total_recent = scalar("SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ?",
                          (hours_ago_ns(6),)) or 0
    scored = scalar("""
        SELECT COUNT(*) FROM security_events
        WHERE timestamp_ns > ? AND risk_score > 0
    """, (hours_ago_ns(6),)) or 0
    mitre_tagged = scalar("""
        SELECT COUNT(*) FROM security_events
        WHERE timestamp_ns > ? AND mitre_techniques IS NOT NULL
              AND mitre_techniques != '' AND mitre_techniques != '[]'
    """, (hours_ago_ns(6),)) or 0

    score_pct = (scored / total_recent * 100) if total_recent > 0 else 0
    mitre_pct = (mitre_tagged / total_recent * 100) if total_recent > 0 else 0

    detect_status = OK
    if total_recent == 0:
        detect_status = DEAD
    elif score_pct < 10:
        detect_status = CRITICAL
        issues.append({"layer": "detection", "severity": CRITICAL,
                       "msg": f"Only {score_pct:.0f}% of events scored — detection engine may be offline"})
    elif mitre_pct < 5:
        detect_status = DEGRADED
        issues.append({"layer": "detection", "severity": DEGRADED,
                       "msg": f"Only {mitre_pct:.0f}% of events have MITRE tags"})

    report["layers"]["detection"] = {
        "status": detect_status,
        "events_6h": total_recent,
        "scored_pct": round(score_pct, 1),
        "mitre_tagged_pct": round(mitre_pct, 1),
    }

    # ── Layer 5: Storage Health ────────────────────────────────
    table_counts = {}
    for table in ["security_events", "process_events", "flow_events",
                  "dns_events", "persistence_events", "fim_events",
                  "audit_events", "peripheral_events", "devices",
                  "fleet_incidents"]:
        try:
            table_counts[table] = scalar(f"SELECT COUNT(*) FROM {table}") or 0
        except Exception:
            table_counts[table] = -1  # table missing

    storage_status = OK
    missing_tables = [t for t, c in table_counts.items() if c == -1]
    if missing_tables:
        storage_status = CRITICAL
        issues.append({"layer": "storage", "severity": CRITICAL,
                       "msg": f"Missing tables: {missing_tables}"})

    report["layers"]["storage"] = {
        "status": storage_status,
        "table_counts": table_counts,
    }

    # ── Layer 6: Command Queue Health ──────────────────────────
    try:
        pending = scalar("SELECT COUNT(*) FROM device_commands WHERE status = 'pending'") or 0
        expired = scalar("SELECT COUNT(*) FROM device_commands WHERE status = 'expired'") or 0
        completed = scalar("SELECT COUNT(*) FROM device_commands WHERE status = 'completed'") or 0

        cmd_status = OK
        if expired > 10:
            cmd_status = DEGRADED
            issues.append({"layer": "commands", "severity": DEGRADED,
                           "msg": f"{expired} expired commands — devices may not be polling"})

        report["layers"]["command_queue"] = {
            "status": cmd_status,
            "pending": pending, "expired": expired, "completed": completed,
        }
    except Exception:
        report["layers"]["command_queue"] = {"status": "unavailable"}

    # ── Layer 7: Brain Health ──────────────────────────────────
    from ..brain import get_brain_status
    brain = get_brain_status()
    brain_status = OK if brain.get("status") == "online" else CRITICAL
    if brain.get("status") != "online":
        issues.append({"layer": "brain", "severity": CRITICAL,
                       "msg": "IGRIS Cloud Brain is offline"})
        healable.append({"action": "restart_brain", "reason": "Brain offline"})

    report["layers"]["brain"] = {
        "status": brain_status,
        **{k: brain.get(k) for k in ["posture", "cycle_count", "mode", "baselines_learned"]},
    }

    # ── Overall verdict ────────────────────────────────────────
    statuses = [layer["status"] for layer in report["layers"].values()
                if isinstance(layer, dict) and "status" in layer]
    if DEAD in statuses:
        report["overall_status"] = DEAD
    elif CRITICAL in statuses:
        report["overall_status"] = CRITICAL
    elif DEGRADED in statuses:
        report["overall_status"] = DEGRADED
    else:
        report["overall_status"] = OK

    report["total_issues"] = len(issues)
    report["total_healable"] = len(healable)

    return report


@mcp.tool()
def igris_pipeline_trace(device_id: str = "") -> dict:
    """Trace the data pipeline end-to-end — where is data flowing, where is it stuck?

    Checks: agent → event counts → freshness → scoring → MITRE tagging →
    classification → shipping to fleet DB.

    Args:
        device_id: Scope to a specific device (optional, fleet-wide if empty)
    """
    now = time.time()
    dev_clause = "AND device_id = ?" if device_id else ""
    params_6h = (hours_ago_ns(6), device_id) if device_id else (hours_ago_ns(6),)
    params_1h = (hours_ago_ns(1), device_id) if device_id else (hours_ago_ns(1),)

    stages: dict[str, dict] = {}

    # Stage 1: Collection (are agents producing events?)
    agent_events = query(f"""
        SELECT collection_agent, COUNT(*) as count,
               MAX(timestamp_ns) as last_ns
        FROM security_events
        WHERE timestamp_ns > ? {dev_clause}
        GROUP BY collection_agent ORDER BY count DESC
    """, params_6h)

    stages["1_collection"] = {
        "agents_active": len(agent_events),
        "agents": [{
            "agent": r["collection_agent"],
            "events_6h": r["count"],
            "freshness_s": round((now - r["last_ns"] / 1e9), 1) if r["last_ns"] else None,
        } for r in agent_events],
    }

    # Stage 2: Scoring (are events being scored?)
    total = scalar(f"SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ? {dev_clause}",
                   params_1h) or 0
    scored = scalar(f"""
        SELECT COUNT(*) FROM security_events
        WHERE timestamp_ns > ? {dev_clause} AND risk_score > 0
    """, params_1h) or 0
    geometric = scalar(f"""
        SELECT COUNT(*) FROM security_events
        WHERE timestamp_ns > ? {dev_clause} AND geometric_score > 0
    """, params_1h) or 0
    temporal = scalar(f"""
        SELECT COUNT(*) FROM security_events
        WHERE timestamp_ns > ? {dev_clause} AND temporal_score > 0
    """, params_1h) or 0
    behavioral = scalar(f"""
        SELECT COUNT(*) FROM security_events
        WHERE timestamp_ns > ? {dev_clause} AND behavioral_score > 0
    """, params_1h) or 0

    stages["2_scoring"] = {
        "total_events_1h": total,
        "risk_scored": scored,
        "geometric_scored": geometric,
        "temporal_scored": temporal,
        "behavioral_scored": behavioral,
        "scoring_rate": f"{scored/total*100:.1f}%" if total else "N/A",
    }

    # Stage 3: MITRE Tagging
    mitre = scalar(f"""
        SELECT COUNT(*) FROM security_events
        WHERE timestamp_ns > ? {dev_clause}
              AND mitre_techniques IS NOT NULL
              AND mitre_techniques != '' AND mitre_techniques != '[]'
    """, params_1h) or 0

    stages["3_mitre"] = {
        "tagged": mitre,
        "tag_rate": f"{mitre/total*100:.1f}%" if total else "N/A",
    }

    # Stage 4: Classification
    classifications = query(f"""
        SELECT final_classification, COUNT(*) as count
        FROM security_events
        WHERE timestamp_ns > ? {dev_clause}
        GROUP BY final_classification
    """, params_1h)

    stages["4_classification"] = {
        "breakdown": {r["final_classification"] or "unclassified": r["count"]
                      for r in classifications},
    }

    # Stage 5: Incidents Generated
    incidents_1h = scalar("SELECT COUNT(*) FROM fleet_incidents WHERE created_at > ?",
                          (hours_ago_epoch(1),)) or 0

    stages["5_incidents"] = {"generated_1h": incidents_1h}

    # Verdict
    problems = []
    if len(agent_events) == 0:
        problems.append("No agents producing events")
    if total > 0 and scored / total < 0.1:
        problems.append("Scoring engine appears offline (<10% scored)")
    if total > 0 and mitre / total < 0.05:
        problems.append("MITRE enrichment may be offline")

    return {
        "device_id": device_id or "fleet-wide",
        "stages": stages,
        "pipeline_healthy": len(problems) == 0,
        "problems": problems,
    }


@mcp.tool()
def igris_coverage_gaps() -> dict:
    """Identify detection blind spots — what MITRE techniques, agents, or event types
    we're NOT seeing across the fleet.

    Returns gaps that an adversary could exploit.
    """
    cutoff = hours_ago_ns(24)

    # Techniques we've NEVER detected
    observed_raw = query("""
        SELECT DISTINCT mitre_techniques FROM security_events
        WHERE timestamp_ns > ?
              AND mitre_techniques IS NOT NULL
              AND mitre_techniques != '' AND mitre_techniques != '[]'
    """, (cutoff,))

    observed_techniques = set()
    for row in observed_raw:
        raw = row.get("mitre_techniques", "")
        try:
            parsed = json.loads(raw) if raw.startswith("[") else [raw]
            observed_techniques.update(t.strip() for t in parsed if t.strip().startswith("T"))
        except (json.JSONDecodeError, TypeError):
            if raw.startswith("T"):
                observed_techniques.add(raw.strip())

    # Critical techniques that SHOULD be detected
    critical_techniques = {
        "T1059": "Command and Scripting Interpreter",
        "T1053": "Scheduled Task/Job",
        "T1547": "Boot or Logon Autostart Execution",
        "T1548": "Abuse Elevation Control",
        "T1055": "Process Injection",
        "T1003": "OS Credential Dumping",
        "T1071": "Application Layer Protocol (C2)",
        "T1041": "Exfiltration Over C2 Channel",
        "T1105": "Ingress Tool Transfer",
        "T1027": "Obfuscated Files or Information",
        "T1562": "Impair Defenses",
        "T1070": "Indicator Removal",
        "T1021": "Remote Services (Lateral)",
        "T1110": "Brute Force",
        "T1078": "Valid Accounts",
    }

    technique_gaps = {
        tid: name for tid, name in critical_techniques.items()
        if tid not in observed_techniques
    }

    # Agent coverage per device
    devices = query("SELECT device_id, hostname FROM devices")
    agent_gaps = []
    for dev in devices:
        did = dev["device_id"]
        active = query("""
            SELECT DISTINCT collection_agent FROM security_events
            WHERE device_id = ? AND timestamp_ns > ?
        """, (did, cutoff))
        active_set = {r["collection_agent"] for r in active}
        missing = COVERAGE_EXPECTED_AGENTS - active_set
        if missing:
            agent_gaps.append({
                "device_id": did,
                "hostname": dev.get("hostname"),
                "missing": sorted(missing),
                "coverage_pct": round(len(active_set) / len(COVERAGE_EXPECTED_AGENTS) * 100, 0),
            })

    # Event type diversity
    categories = query("""
        SELECT event_category, COUNT(DISTINCT device_id) as devices,
               COUNT(*) as events
        FROM security_events
        WHERE timestamp_ns > ?
        GROUP BY event_category
    """, (cutoff,))

    return {
        "mitre_gaps": {
            "undetected_critical": technique_gaps,
            "total_observed": len(observed_techniques),
            "critical_missing": len(technique_gaps),
        },
        "agent_gaps": agent_gaps,
        "event_diversity": categories,
        "overall_coverage_score": round(
            (len(observed_techniques) / max(len(critical_techniques), 1)) * 100, 1
        ),
    }


# ── Self-Healing Tools ─────────────────────────────────────────────


@mcp.tool()
def igris_self_heal(dry_run: bool = True) -> dict:
    """Autonomous self-healing — IGRIS diagnoses and repairs itself.

    Runs full diagnosis, then executes repairs for every healable issue found.
    Repairs include: restarting silent agents, triggering collection on stale
    devices, restarting the Cloud Brain, flushing expired commands.

    Args:
        dry_run: If True (default), only report what WOULD be healed.
                 Set False to actually execute repairs.
    """
    # Run full diagnosis first
    diagnosis = igris_self_diagnosis()

    healable = diagnosis.get("auto_healable", [])
    if not healable:
        return {
            "status": "healthy",
            "message": "No healable issues found — organism is healthy",
            "diagnosis_summary": diagnosis.get("overall_status"),
        }

    results = []
    for action in healable:
        action_type = action.get("action", "")
        reason = action.get("reason", "")

        if dry_run:
            results.append({
                "action": action_type,
                "would_do": reason,
                "status": "DRY_RUN",
                **{k: v for k, v in action.items() if k not in ("action", "reason")},
            })
            continue

        # Execute the repair
        if action_type == "restart_agent":
            result = _heal_restart_agent(
                action.get("device_id", ""),
                action.get("agent", ""),
                reason,
            )
        elif action_type == "trigger_collection_all":
            result = _heal_trigger_collection_all(reason)
        elif action_type == "restart_brain":
            result = _heal_restart_brain(reason)
        else:
            result = {"status": "unknown_action", "action": action_type}

        results.append(result)

    # Also clean up expired commands
    if not dry_run:
        cleaned = _heal_flush_expired_commands()
        if cleaned > 0:
            results.append({"action": "flush_expired_commands", "cleaned": cleaned})

    return {
        "dry_run": dry_run,
        "issues_found": len(healable),
        "repairs": results,
        "diagnosis_overall": diagnosis.get("overall_status"),
    }


@mcp.tool()
def igris_heal_device(device_id: str) -> dict:
    """Heal a specific device — restart all silent agents and trigger fresh collection.

    Args:
        device_id: The device to heal
    """
    device = query_one("SELECT hostname FROM devices WHERE device_id = ?", (device_id,))
    if not device:
        return {"error": f"Device {device_id} not found"}

    cutoff = hours_ago_ns(2)
    active = query("""
        SELECT DISTINCT collection_agent FROM security_events
        WHERE device_id = ? AND timestamp_ns > ?
    """, (device_id, cutoff))
    active_set = {r["collection_agent"] for r in active}
    missing = COVERAGE_EXPECTED_AGENTS - active_set

    results = []

    # Restart missing agents
    for agent_name in missing:
        result = _heal_restart_agent(device_id, agent_name,
                                     f"Silent for >2h on {device.get('hostname')}")
        results.append(result)

    # Trigger collection
    from .agent import _queue_command
    cmd = _queue_command(device_id, "COLLECT_NOW", priority=2)
    results.append({"action": "trigger_collection", **cmd})

    return {
        "device_id": device_id,
        "hostname": device.get("hostname"),
        "agents_restarted": list(missing),
        "collection_triggered": True,
        "results": results,
    }


@mcp.tool()
def igris_heal_fleet() -> dict:
    """Fleet-wide healing sweep — check every device and repair everything broken.

    Runs diagnosis, heals every device with issues, and reports results.
    """
    devices = query("SELECT device_id, hostname FROM devices")
    cutoff = hours_ago_ns(2)

    healed_devices = []
    total_repairs = 0

    for dev in devices:
        did = dev["device_id"]
        active = query("""
            SELECT DISTINCT collection_agent FROM security_events
            WHERE device_id = ? AND timestamp_ns > ?
        """, (did, cutoff))
        active_set = {r["collection_agent"] for r in active}
        missing = COVERAGE_EXPECTED_AGENTS - active_set

        if not missing:
            continue

        repairs = []
        for agent_name in missing:
            r = _heal_restart_agent(did, agent_name,
                                    f"Fleet heal: silent on {dev.get('hostname', did[:8])}")
            repairs.append(r)
            total_repairs += 1

        # Trigger collection
        from .agent import _queue_command
        _queue_command(did, "COLLECT_NOW", priority=2)
        total_repairs += 1

        healed_devices.append({
            "device_id": did,
            "hostname": dev.get("hostname"),
            "agents_restarted": list(missing),
            "repairs": len(repairs) + 1,
        })

    # Flush expired commands fleet-wide
    cleaned = _heal_flush_expired_commands()

    # Restart brain if offline
    from ..brain import get_brain_status
    brain = get_brain_status()
    brain_restarted = False
    if brain.get("status") != "online":
        _heal_restart_brain("Fleet heal: brain was offline")
        brain_restarted = True

    return {
        "devices_healed": len(healed_devices),
        "total_repairs": total_repairs,
        "expired_commands_flushed": cleaned,
        "brain_restarted": brain_restarted,
        "details": healed_devices,
    }


# ── Healing Internals ──────────────────────────────────────────────


def _heal_restart_agent(device_id: str, agent_name: str, reason: str) -> dict:
    """Queue a RESTART_AGENT command for a device."""
    from .agent import _queue_command
    try:
        cmd = _queue_command(device_id, "RESTART_AGENT",
                             {"agent_name": agent_name}, priority=2)
        return {
            "action": "restart_agent",
            "device_id": device_id,
            "agent": agent_name,
            "reason": reason,
            "status": "queued",
            "command_id": cmd.get("command_id"),
        }
    except Exception as e:
        return {
            "action": "restart_agent",
            "device_id": device_id,
            "agent": agent_name,
            "status": "failed",
            "error": str(e),
        }


def _heal_trigger_collection_all(reason: str) -> dict:
    """Queue COLLECT_NOW on all online devices."""
    from .agent import _queue_command
    devices = query("SELECT device_id FROM devices WHERE status = 'online'")
    queued = 0
    for d in devices:
        try:
            _queue_command(d["device_id"], "COLLECT_NOW", priority=2)
            queued += 1
        except Exception:
            pass
    return {
        "action": "trigger_collection_all",
        "reason": reason,
        "devices_triggered": queued,
        "status": "queued",
    }


def _heal_restart_brain(reason: str) -> dict:
    """Restart the IGRIS Cloud Brain."""
    from ..brain import stop_brain, start_brain
    try:
        stop_brain()
        brain = start_brain()
        return {
            "action": "restart_brain",
            "reason": reason,
            "status": "restarted",
        }
    except Exception as e:
        return {
            "action": "restart_brain",
            "reason": reason,
            "status": "failed",
            "error": str(e),
        }


def _heal_flush_expired_commands() -> int:
    """Delete old expired/completed commands to keep the queue clean."""
    try:
        from ..db import write_conn
        cutoff = time.time() - 86400  # 24h old
        with write_conn() as conn:
            cur = conn.execute(
                "DELETE FROM device_commands WHERE "
                "(status IN ('expired', 'completed') AND created_at < ?)",
                (cutoff,),
            )
            return cur.rowcount
    except Exception:
        return 0
