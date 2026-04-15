"""Detection & threat intelligence tools — incidents, kill chains, MITRE coverage."""

from __future__ import annotations

import json
import time
from typing import Optional

from ..db import query, query_one, scalar, hours_ago_ns, hours_ago_epoch
from ..config import cfg
from ..server import mcp


@mcp.tool()
def detect_threat_posture(device_id: str = "", hours: int = 24) -> dict:
    """Overall threat posture — risk scores, event severity distribution, classification breakdown.

    The single-glance threat assessment for IGRIS decision-making.

    Args:
        device_id: Scope to a specific device (optional, fleet-wide if empty)
        hours:     Lookback window
    """
    dev_clause = "AND device_id = ?" if device_id else ""
    params_base = (hours_ago_ns(hours), device_id) if device_id else (hours_ago_ns(hours),)

    total = scalar(
        f"SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ? {dev_clause}",
        params_base,
    ) or 0

    classifications = query(f"""
        SELECT final_classification, COUNT(*) as count
        FROM security_events
        WHERE timestamp_ns > ? {dev_clause}
              AND final_classification IS NOT NULL
        GROUP BY final_classification
    """, params_base)

    risk_dist = query(f"""
        SELECT
            CASE
                WHEN risk_score >= 0.9 THEN 'critical'
                WHEN risk_score >= 0.7 THEN 'high'
                WHEN risk_score >= 0.4 THEN 'medium'
                WHEN risk_score > 0    THEN 'low'
                ELSE 'clean'
            END as severity,
            COUNT(*) as count
        FROM security_events
        WHERE timestamp_ns > ? {dev_clause}
        GROUP BY severity ORDER BY count DESC
    """, params_base)

    top_categories = query(f"""
        SELECT event_category, COUNT(*) as count,
               AVG(risk_score) as avg_risk, MAX(risk_score) as max_risk
        FROM security_events
        WHERE timestamp_ns > ? {dev_clause}
        GROUP BY event_category ORDER BY avg_risk DESC LIMIT 10
    """, params_base)

    incidents = scalar(
        f"SELECT COUNT(*) FROM fleet_incidents WHERE created_at > ?",
        (hours_ago_epoch(hours),),
    ) or 0

    return {
        "total_events": total,
        "classifications": {r["final_classification"]: r["count"] for r in classifications},
        "risk_distribution": {r["severity"]: r["count"] for r in risk_dist},
        "top_categories": top_categories,
        "incidents": incidents,
        "device_id": device_id or "fleet-wide",
        "hours": hours,
    }


@mcp.tool()
def detect_list_incidents(
    severity: str = "",
    status: str = "",
    device_id: str = "",
    limit: int = 20,
) -> dict:
    """List fleet incidents — correlated multi-event threat detections.

    Args:
        severity:  Filter by severity (low, medium, high, critical)
        status:    Filter by status (open, investigating, resolved)
        device_id: Filter to specific device
        limit:     Max rows
    """
    clauses: list[str] = []
    params: list = []

    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if status:
        clauses.append("status = ?")
        params.append(status)
    if device_id:
        clauses.append("device_ids LIKE ?")
        params.append(f"%{device_id}%")

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(min(limit, cfg.max_query_rows))

    incidents = query(f"""
        SELECT id, severity, title, description, device_ids,
               mitre_techniques, status, created_at, updated_at, resolved_at
        FROM fleet_incidents
        {where}
        ORDER BY created_at DESC LIMIT ?
    """, tuple(params))

    return {"incidents": incidents, "returned": len(incidents)}


@mcp.tool()
def detect_incident_detail(incident_id: int) -> dict:
    """Full incident forensics — events, MITRE mapping, devices, timeline.

    Args:
        incident_id: The incident ID to inspect
    """
    incident = query_one(
        "SELECT * FROM fleet_incidents WHERE id = ?", (incident_id,)
    )
    if not incident:
        return {"error": f"Incident {incident_id} not found"}

    # Parse event_ids to fetch related events
    event_ids_raw = incident.get("event_ids", "[]")
    try:
        event_ids = json.loads(event_ids_raw) if event_ids_raw else []
    except (json.JSONDecodeError, TypeError):
        event_ids = []

    related_events = []
    if event_ids:
        placeholders = ",".join("?" for _ in event_ids[:50])
        related_events = query(f"""
            SELECT event_id, device_id, event_category, event_action,
                   risk_score, mitre_techniques, description,
                   collection_agent, timestamp_dt
            FROM security_events
            WHERE event_id IN ({placeholders})
            ORDER BY timestamp_ns ASC
        """, tuple(str(eid) for eid in event_ids[:50]))

    return {
        "incident": incident,
        "related_events": related_events,
        "event_count": len(event_ids),
    }


@mcp.tool()
def detect_kill_chain_summary(device_id: str = "", hours: int = 24) -> dict:
    """Kill chain analysis — map events to MITRE ATT&CK tactics across the fleet.

    Shows which attack stages have been observed and how deep adversaries have progressed.

    Args:
        device_id: Scope to device (optional)
        hours:     Lookback window
    """
    dev_clause = "AND device_id = ?" if device_id else ""
    params = (hours_ago_ns(hours), device_id) if device_id else (hours_ago_ns(hours),)

    rows = query(f"""
        SELECT mitre_techniques, collection_agent, risk_score,
               device_id, event_category, timestamp_dt
        FROM security_events
        WHERE timestamp_ns > ? {dev_clause}
              AND mitre_techniques IS NOT NULL
              AND mitre_techniques != '' AND mitre_techniques != '[]'
        ORDER BY risk_score DESC
    """, params)

    techniques: dict[str, dict] = {}
    for row in rows:
        raw = row.get("mitre_techniques", "")
        try:
            parsed = json.loads(raw) if raw.startswith("[") else [raw]
        except (json.JSONDecodeError, TypeError):
            parsed = [raw] if raw.startswith("T") else []

        for t in parsed:
            t = t.strip()
            if not t.startswith("T"):
                continue
            if t not in techniques:
                techniques[t] = {
                    "technique": t,
                    "count": 0,
                    "agents": set(),
                    "devices": set(),
                    "max_risk": 0.0,
                    "categories": set(),
                }
            techniques[t]["count"] += 1
            techniques[t]["agents"].add(row.get("collection_agent", ""))
            techniques[t]["devices"].add(row.get("device_id", ""))
            techniques[t]["max_risk"] = max(
                techniques[t]["max_risk"], row.get("risk_score", 0) or 0
            )
            techniques[t]["categories"].add(row.get("event_category", ""))

    # Convert sets to lists for JSON serialization
    for t in techniques.values():
        t["agents"] = sorted(t["agents"])
        t["devices"] = sorted(t["devices"])
        t["categories"] = sorted(t["categories"])

    sorted_techniques = sorted(
        techniques.values(), key=lambda x: x["max_risk"], reverse=True
    )

    return {
        "techniques_observed": len(techniques),
        "techniques": sorted_techniques,
        "hours": hours,
        "device_id": device_id or "fleet-wide",
    }


@mcp.tool()
def detect_mitre_coverage(hours: int = 24) -> dict:
    """MITRE ATT&CK detection coverage — which techniques we can see vs. what's active.

    Args:
        hours: Lookback window
    """
    rows = query("""
        SELECT mitre_techniques, COUNT(*) as hit_count
        FROM security_events
        WHERE timestamp_ns > ?
              AND mitre_techniques IS NOT NULL
              AND mitre_techniques != '' AND mitre_techniques != '[]'
        GROUP BY mitre_techniques
    """, (hours_ago_ns(hours),))

    technique_counts: dict[str, int] = {}
    for row in rows:
        raw = row.get("mitre_techniques", "")
        try:
            parsed = json.loads(raw) if raw.startswith("[") else [raw]
        except (json.JSONDecodeError, TypeError):
            parsed = [raw] if raw.startswith("T") else []
        for t in parsed:
            t = t.strip()
            if t.startswith("T"):
                technique_counts[t] = technique_counts.get(t, 0) + row["hit_count"]

    sorted_techniques = sorted(
        technique_counts.items(), key=lambda x: x[1], reverse=True
    )

    return {
        "total_techniques": len(technique_counts),
        "techniques": [{"id": t, "count": c} for t, c in sorted_techniques],
        "hours": hours,
    }


@mcp.tool()
def detect_sigma_hits(device_id: str = "", hours: int = 24) -> dict:
    """Sigma rule hit summary — which detection rules fired and how often.

    Args:
        device_id: Scope to device (optional)
        hours:     Lookback window
    """
    dev_clause = "AND device_id = ?" if device_id else ""
    params = (hours_ago_ns(hours), device_id) if device_id else (hours_ago_ns(hours),)

    rows = query(f"""
        SELECT event_category, collection_agent, detection_source,
               COUNT(*) as count,
               AVG(risk_score) as avg_risk,
               MAX(risk_score) as max_risk
        FROM security_events
        WHERE timestamp_ns > ? {dev_clause}
              AND risk_score > 0.3
        GROUP BY event_category, collection_agent
        ORDER BY avg_risk DESC
    """, params)

    return {"sigma_hits": rows, "hours": hours}
