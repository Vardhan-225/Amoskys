"""Fleet device management tools — see every device, their health, posture."""

from __future__ import annotations

import json
import time
from typing import Optional

from ..db import query, query_one, scalar, hours_ago_ns, hours_ago_epoch
from ..server import mcp


# ── Tools ──────────────────────────────────────────────────────────


@mcp.tool()
def fleet_list_devices() -> dict:
    """List all enrolled devices with status, OS, last heartbeat, and event counts.

    Returns a fleet roster — every device IGRIS can see.
    """
    devices = query("""
        SELECT d.device_id, d.hostname, d.os, d.os_version, d.arch,
               d.agent_version, d.status, d.last_seen, d.first_seen,
               d.public_ip,
               (SELECT COUNT(*) FROM security_events WHERE device_id = d.device_id) as event_count
        FROM devices d
        ORDER BY d.last_seen DESC
    """)
    now = time.time()
    for d in devices:
        age = now - (d.get("last_seen") or 0)
        d["online"] = age < 120
        d["last_seen_ago"] = f"{int(age)}s" if age < 3600 else f"{age / 3600:.1f}h"
    return {"devices": devices, "total": len(devices), "timestamp": time.time()}


@mcp.tool()
def fleet_device_detail(device_id: str) -> dict:
    """Deep profile of a single device — hardware, agent version, event breakdown, risk posture.

    Args:
        device_id: The device identifier (SHA256 of hardware serial)
    """
    device = query_one(
        "SELECT * FROM devices WHERE device_id = ?", (device_id,)
    )
    if not device:
        return {"error": f"Device {device_id} not found"}

    # Event breakdown by category
    categories = query("""
        SELECT event_category, COUNT(*) as count,
               AVG(risk_score) as avg_risk, MAX(risk_score) as max_risk
        FROM security_events
        WHERE device_id = ? AND timestamp_ns > ?
        GROUP BY event_category ORDER BY count DESC
    """, (device_id, hours_ago_ns(24)))

    # Agent activity
    agents = query("""
        SELECT collection_agent, COUNT(*) as events,
               MAX(timestamp_ns) as last_event_ns
        FROM security_events
        WHERE device_id = ? AND timestamp_ns > ?
        GROUP BY collection_agent ORDER BY events DESC
    """, (device_id, hours_ago_ns(24)))

    # Recent high-risk events
    high_risk = query("""
        SELECT event_id, event_category, event_action, risk_score,
               mitre_techniques, description, collection_agent, timestamp_dt
        FROM security_events
        WHERE device_id = ? AND risk_score >= 0.5
        ORDER BY timestamp_ns DESC LIMIT 20
    """, (device_id,))

    return {
        "device": device,
        "categories_24h": categories,
        "agents_24h": agents,
        "high_risk_events": high_risk,
    }


@mcp.tool()
def fleet_status() -> dict:
    """Fleet-wide posture snapshot — online/offline counts, total events, threat summary.

    The 30-second strategic briefing for IGRIS.
    """
    total = scalar("SELECT COUNT(*) FROM devices") or 0
    now = time.time()

    online = scalar(
        "SELECT COUNT(*) FROM devices WHERE last_seen > ?",
        (now - 120,),
    ) or 0

    events_24h = scalar(
        "SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ?",
        (hours_ago_ns(24),),
    ) or 0

    high_risk_24h = scalar(
        "SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ? AND risk_score >= 0.7",
        (hours_ago_ns(24),),
    ) or 0

    critical_events = scalar(
        "SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ? AND risk_score >= 0.9",
        (hours_ago_ns(24),),
    ) or 0

    incidents_24h = scalar(
        "SELECT COUNT(*) FROM fleet_incidents WHERE created_at > ?",
        (hours_ago_epoch(24),),
    ) or 0

    # MITRE technique diversity
    mitre_raw = query("""
        SELECT DISTINCT mitre_techniques FROM security_events
        WHERE timestamp_ns > ? AND mitre_techniques IS NOT NULL
              AND mitre_techniques != '' AND mitre_techniques != '[]'
    """, (hours_ago_ns(24),))
    techniques = set()
    for row in mitre_raw:
        raw = row.get("mitre_techniques", "")
        if raw:
            try:
                parsed = json.loads(raw) if raw.startswith("[") else [raw]
                techniques.update(t for t in parsed if t.startswith("T"))
            except (json.JSONDecodeError, TypeError):
                if raw.startswith("T"):
                    techniques.add(raw.split(",")[0].strip())

    # Per-device summaries
    per_device = query("""
        SELECT d.device_id, d.hostname, d.status,
               COUNT(se.id) as event_count,
               MAX(se.risk_score) as max_risk,
               MAX(se.timestamp_ns) as last_event_ns
        FROM devices d
        LEFT JOIN security_events se ON se.device_id = d.device_id
            AND se.timestamp_ns > ?
        GROUP BY d.device_id
        ORDER BY max_risk DESC NULLS LAST
    """, (hours_ago_ns(24),))

    return {
        "fleet": {
            "total_devices": total,
            "online": online,
            "offline": total - online,
            "events_24h": events_24h,
            "high_risk_24h": high_risk_24h,
            "critical_24h": critical_events,
            "incidents_24h": incidents_24h,
            "mitre_techniques_observed": len(techniques),
            "mitre_techniques": sorted(techniques),
        },
        "devices": per_device,
        "timestamp": time.time(),
    }


@mcp.tool()
def fleet_device_agents(device_id: str, hours: int = 24) -> dict:
    """Show which agents are active on a device and their recent telemetry volume.

    Args:
        device_id: Target device
        hours:     Lookback window (default 24)
    """
    agents = query("""
        SELECT collection_agent,
               COUNT(*) as events,
               AVG(risk_score) as avg_risk,
               MAX(risk_score) as max_risk,
               MAX(timestamp_ns) as last_event_ns,
               MIN(timestamp_ns) as first_event_ns
        FROM security_events
        WHERE device_id = ? AND timestamp_ns > ?
        GROUP BY collection_agent
        ORDER BY events DESC
    """, (device_id, hours_ago_ns(hours)))

    now_ns = int(time.time() * 1e9)
    for a in agents:
        last = a.get("last_event_ns") or 0
        a["stale"] = (now_ns - last) > 7200 * 1e9  # >2h = stale

    return {"device_id": device_id, "agents": agents, "hours": hours}
