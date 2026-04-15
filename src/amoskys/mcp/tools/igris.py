"""IGRIS intelligence tools — the brain's own introspection and assessment capabilities."""

from __future__ import annotations

import json
import time
from typing import Optional

from ..db import query, query_one, scalar, hours_ago_ns, hours_ago_epoch
from ..config import cfg
from ..server import mcp


@mcp.tool()
def igris_fleet_posture() -> dict:
    """IGRIS fleet-wide posture assessment — synthesizes all signals into a single verdict.

    Combines device risk scores, active incidents, event velocity, MITRE depth,
    and fleet health into: NOMINAL | GUARDED | ELEVATED | CRITICAL.
    """
    now = time.time()
    cutoff_24h = hours_ago_ns(24)
    cutoff_1h = hours_ago_ns(1)

    # Device risk aggregation
    total_devices = scalar("SELECT COUNT(*) FROM devices") or 0
    online = scalar("SELECT COUNT(*) FROM devices WHERE last_seen > ?", (now - 120,)) or 0

    # Event velocity
    events_1h = scalar(
        "SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ?",
        (cutoff_1h,),
    ) or 0
    critical_1h = scalar(
        "SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ? AND risk_score >= 0.9",
        (cutoff_1h,),
    ) or 0
    high_1h = scalar(
        "SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ? AND risk_score >= 0.7",
        (cutoff_1h,),
    ) or 0

    # Active incidents
    open_incidents = scalar(
        "SELECT COUNT(*) FROM fleet_incidents WHERE status != 'resolved'",
    ) or 0
    critical_incidents = scalar(
        "SELECT COUNT(*) FROM fleet_incidents WHERE severity = 'critical' AND status != 'resolved'",
    ) or 0

    # Determine posture
    if critical_incidents > 0 or critical_1h >= 5:
        posture = "CRITICAL"
        threat_level = min(1.0, 0.85 + critical_incidents * 0.05)
    elif high_1h >= 10 or open_incidents >= 3:
        posture = "ELEVATED"
        threat_level = min(0.84, 0.55 + high_1h * 0.02)
    elif high_1h >= 3 or open_incidents >= 1:
        posture = "GUARDED"
        threat_level = min(0.54, 0.25 + high_1h * 0.05)
    else:
        posture = "NOMINAL"
        threat_level = max(0.0, min(0.24, events_1h * 0.001))

    # Fleet health
    offline_pct = ((total_devices - online) / total_devices * 100) if total_devices else 0

    return {
        "posture": posture,
        "threat_level": round(threat_level, 3),
        "fleet_health": {
            "total_devices": total_devices,
            "online": online,
            "offline_pct": round(offline_pct, 1),
        },
        "event_velocity": {
            "events_1h": events_1h,
            "critical_1h": critical_1h,
            "high_risk_1h": high_1h,
        },
        "incidents": {
            "open": open_incidents,
            "critical": critical_incidents,
        },
        "assessment_time": time.time(),
    }


@mcp.tool()
def igris_device_risk(device_id: str) -> dict:
    """Deep risk assessment for a single device — what's happening and why.

    Args:
        device_id: The device to assess
    """
    device = query_one("SELECT * FROM devices WHERE device_id = ?", (device_id,))
    if not device:
        return {"error": f"Device {device_id} not found"}

    cutoff = hours_ago_ns(24)

    # Risk factors
    high_risk_events = query("""
        SELECT event_category, event_action, risk_score, mitre_techniques,
               description, collection_agent, timestamp_dt
        FROM security_events
        WHERE device_id = ? AND timestamp_ns > ? AND risk_score >= 0.5
        ORDER BY risk_score DESC LIMIT 20
    """, (device_id, cutoff))

    # Classification breakdown
    classifications = query("""
        SELECT final_classification, COUNT(*) as count
        FROM security_events
        WHERE device_id = ? AND timestamp_ns > ?
        GROUP BY final_classification
    """, (device_id, cutoff))

    # Active persistence mechanisms
    persistence = query("""
        SELECT mechanism, path, risk_score, timestamp_dt
        FROM persistence_events
        WHERE device_id = ? AND timestamp_ns > ?
        ORDER BY risk_score DESC LIMIT 10
    """, (device_id, cutoff))

    # Suspicious outbound connections
    sus_flows = query("""
        SELECT dst_ip, dst_port, process_name, bytes_tx, bytes_rx,
               geo_dst_country, asn_dst_org, threat_intel_match
        FROM flow_events
        WHERE device_id = ? AND timestamp_ns > ? AND threat_intel_match = 1
        ORDER BY timestamp_ns DESC LIMIT 10
    """, (device_id, cutoff))

    # Compute composite risk
    malicious = sum(1 for r in classifications if r.get("final_classification") == "malicious")
    suspicious = sum(1 for r in classifications if r.get("final_classification") == "suspicious")
    total_events = sum(r["count"] for r in classifications) if classifications else 0

    if malicious > 0 or len(sus_flows) > 0:
        risk_level = "HIGH"
    elif suspicious > 5:
        risk_level = "MEDIUM"
    elif total_events > 0:
        risk_level = "LOW"
    else:
        risk_level = "CLEAN"

    return {
        "device": {
            "device_id": device_id,
            "hostname": device.get("hostname"),
            "os": device.get("os"),
            "status": device.get("status"),
        },
        "risk_level": risk_level,
        "event_summary": {
            "total_24h": total_events,
            "malicious": malicious,
            "suspicious": suspicious,
        },
        "high_risk_events": high_risk_events,
        "persistence_mechanisms": persistence,
        "threat_intel_flows": sus_flows,
    }


@mcp.tool()
def igris_hunt(
    query_text: str,
    hours: int = 24,
    limit: int = 50,
) -> dict:
    """Threat hunting — free-text search across all security event fields.

    IGRIS proactively searches for indicators of compromise. Searches
    description, process_name, domain, remote_ip, path, exe, cmdline, sha256.

    Args:
        query_text: Search term (IP, domain, hash, process name, keyword)
        hours:      Lookback window
        limit:      Max results
    """
    limit = min(limit, cfg.max_query_rows)
    pattern = f"%{query_text}%"

    events = query("""
        SELECT event_id, device_id, event_category, event_action,
               risk_score, mitre_techniques, description,
               collection_agent, process_name, pid, username,
               domain, remote_ip, path, exe, cmdline, sha256,
               timestamp_dt
        FROM security_events
        WHERE timestamp_ns > ?
              AND (description LIKE ? OR process_name LIKE ?
                   OR domain LIKE ? OR remote_ip LIKE ?
                   OR path LIKE ? OR exe LIKE ?
                   OR cmdline LIKE ? OR sha256 LIKE ?)
        ORDER BY risk_score DESC, timestamp_ns DESC
        LIMIT ?
    """, (hours_ago_ns(hours), pattern, pattern, pattern, pattern,
          pattern, pattern, pattern, pattern, limit))

    # Also check DNS
    dns_hits = query("""
        SELECT device_id, domain, record_type, risk_score,
               process_name, timestamp_dt
        FROM dns_events
        WHERE timestamp_ns > ? AND domain LIKE ?
        ORDER BY timestamp_ns DESC LIMIT 20
    """, (hours_ago_ns(hours), pattern))

    # Also check network flows
    flow_hits = query("""
        SELECT device_id, dst_ip, dst_port, process_name,
               geo_dst_country, asn_dst_org, bytes_tx, bytes_rx,
               threat_intel_match, timestamp_dt
        FROM flow_events
        WHERE timestamp_ns > ?
              AND (dst_ip LIKE ? OR process_name LIKE ? OR asn_dst_org LIKE ?)
        ORDER BY timestamp_ns DESC LIMIT 20
    """, (hours_ago_ns(hours), pattern, pattern, pattern))

    return {
        "query": query_text,
        "security_events": events,
        "dns_hits": dns_hits,
        "flow_hits": flow_hits,
        "total_hits": len(events) + len(dns_hits) + len(flow_hits),
    }


@mcp.tool()
def igris_cross_device_correlation(hours: int = 6) -> dict:
    """Cross-device attack correlation — find adversaries moving laterally across the fleet.

    Looks for the same IOCs (IPs, domains, techniques, processes) appearing
    on multiple devices within the time window.

    Args:
        hours: Correlation window
    """
    cutoff = hours_ago_ns(hours)

    # IPs seen on multiple devices
    shared_ips = query("""
        SELECT remote_ip, COUNT(DISTINCT device_id) as device_count,
               COUNT(*) as event_count, MAX(risk_score) as max_risk,
               GROUP_CONCAT(DISTINCT device_id) as devices
        FROM security_events
        WHERE timestamp_ns > ? AND remote_ip IS NOT NULL AND remote_ip != ''
        GROUP BY remote_ip
        HAVING device_count > 1
        ORDER BY max_risk DESC LIMIT 20
    """, (cutoff,))

    # Domains seen on multiple devices
    shared_domains = query("""
        SELECT domain, COUNT(DISTINCT device_id) as device_count,
               COUNT(*) as event_count
        FROM dns_events
        WHERE timestamp_ns > ? AND domain IS NOT NULL AND domain != ''
        GROUP BY domain
        HAVING device_count > 1
        ORDER BY event_count DESC LIMIT 20
    """, (cutoff,))

    # Same MITRE technique on multiple devices (potential campaign)
    shared_techniques = query("""
        SELECT mitre_techniques, COUNT(DISTINCT device_id) as device_count,
               COUNT(*) as event_count, MAX(risk_score) as max_risk,
               GROUP_CONCAT(DISTINCT device_id) as devices
        FROM security_events
        WHERE timestamp_ns > ?
              AND mitre_techniques IS NOT NULL
              AND mitre_techniques != '' AND mitre_techniques != '[]'
              AND risk_score >= 0.5
        GROUP BY mitre_techniques
        HAVING device_count > 1
        ORDER BY max_risk DESC LIMIT 20
    """, (cutoff,))

    lateral = len(shared_ips) > 0 or any(
        r.get("max_risk", 0) >= 0.7 for r in shared_techniques
    )

    return {
        "lateral_movement_detected": lateral,
        "shared_ips": shared_ips,
        "shared_domains": shared_domains,
        "shared_techniques": shared_techniques,
        "hours": hours,
    }


@mcp.tool()
def igris_brain_status() -> dict:
    """IGRIS Cloud Brain status — is the autonomous loop running, what has it found.

    Returns brain cycle count, last assessment, active signals, and mode.
    """
    from ..brain import get_brain_status
    return get_brain_status()
