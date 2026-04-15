"""Telemetry query tools — search, filter, and analyze events across the fleet."""

from __future__ import annotations

import json
import time
from typing import Optional

from ..db import query, scalar, hours_ago_ns
from ..config import cfg
from ..server import mcp


@mcp.tool()
def telemetry_query_events(
    hours: int = 24,
    device_id: str = "",
    category: str = "",
    agent: str = "",
    min_risk: float = 0.0,
    limit: int = 50,
) -> dict:
    """Search security events across the entire fleet with filters.

    Args:
        hours:     Lookback window (default 24)
        device_id: Filter to specific device (optional)
        category:  Filter by event_category (e.g. 'process_spawn', 'dns_tunnel')
        agent:     Filter by collection_agent (e.g. 'macos_proc')
        min_risk:  Minimum risk_score threshold (0.0-1.0)
        limit:     Max rows returned (capped at 500)
    """
    limit = min(limit, cfg.max_query_rows)
    clauses = ["timestamp_ns > ?"]
    params: list = [hours_ago_ns(hours)]

    if device_id:
        clauses.append("device_id = ?")
        params.append(device_id)
    if category:
        clauses.append("event_category = ?")
        params.append(category)
    if agent:
        clauses.append("collection_agent = ?")
        params.append(agent)
    if min_risk > 0:
        clauses.append("risk_score >= ?")
        params.append(min_risk)

    where = " AND ".join(clauses)
    params.append(limit)

    events = query(f"""
        SELECT event_id, device_id, event_category, event_action,
               risk_score, confidence, mitre_techniques, description,
               collection_agent, final_classification, timestamp_dt,
               process_name, pid, username, domain, remote_ip, path,
               detection_source, probe_name
        FROM security_events
        WHERE {where}
        ORDER BY timestamp_ns DESC
        LIMIT ?
    """, tuple(params))

    total = scalar(f"SELECT COUNT(*) FROM security_events WHERE {where}",
                   tuple(params[:-1]))

    return {"events": events, "returned": len(events), "total": total}


@mcp.tool()
def telemetry_query_processes(
    device_id: str = "",
    exe: str = "",
    user: str = "",
    hours: int = 24,
    limit: int = 50,
) -> dict:
    """Search process events — what's running on fleet devices.

    Args:
        device_id: Filter to specific device
        exe:       Filter by executable path (partial match)
        user:      Filter by username
        hours:     Lookback window
        limit:     Max rows
    """
    limit = min(limit, cfg.max_query_rows)
    clauses = ["timestamp_ns > ?"]
    params: list = [hours_ago_ns(hours)]

    if device_id:
        clauses.append("device_id = ?")
        params.append(device_id)
    if exe:
        clauses.append("exe LIKE ?")
        params.append(f"%{exe}%")
    if user:
        clauses.append("username = ?")
        params.append(user)

    where = " AND ".join(clauses)
    params.append(limit)

    rows = query(f"""
        SELECT device_id, pid, name, exe, cmdline, ppid, username,
               parent_name, cpu_percent, memory_percent, timestamp_dt
        FROM process_events
        WHERE {where}
        ORDER BY timestamp_ns DESC LIMIT ?
    """, tuple(params))

    return {"processes": rows, "returned": len(rows)}


@mcp.tool()
def telemetry_query_network(
    device_id: str = "",
    dst_ip: str = "",
    dst_port: int = 0,
    process_name: str = "",
    hours: int = 24,
    limit: int = 50,
) -> dict:
    """Search network flow events — who's talking to whom.

    Args:
        device_id:    Filter to specific device
        dst_ip:       Filter by destination IP
        dst_port:     Filter by destination port
        process_name: Filter by process making the connection
        hours:        Lookback window
        limit:        Max rows
    """
    limit = min(limit, cfg.max_query_rows)
    clauses = ["timestamp_ns > ?"]
    params: list = [hours_ago_ns(hours)]

    if device_id:
        clauses.append("device_id = ?")
        params.append(device_id)
    if dst_ip:
        clauses.append("dst_ip = ?")
        params.append(dst_ip)
    if dst_port:
        clauses.append("dst_port = ?")
        params.append(dst_port)
    if process_name:
        clauses.append("process_name LIKE ?")
        params.append(f"%{process_name}%")

    where = " AND ".join(clauses)
    params.append(limit)

    rows = query(f"""
        SELECT device_id, src_ip, dst_ip, src_port, dst_port, protocol,
               bytes_tx, bytes_rx, pid, process_name,
               geo_dst_country, geo_dst_city, asn_dst_org,
               threat_intel_match, timestamp_dt
        FROM flow_events
        WHERE {where}
        ORDER BY timestamp_ns DESC LIMIT ?
    """, tuple(params))

    return {"flows": rows, "returned": len(rows)}


@mcp.tool()
def telemetry_query_dns(
    device_id: str = "",
    domain: str = "",
    hours: int = 24,
    limit: int = 50,
) -> dict:
    """Search DNS resolution events — what domains are being queried.

    Args:
        device_id: Filter to specific device
        domain:    Filter by domain (partial match)
        hours:     Lookback window
        limit:     Max rows
    """
    limit = min(limit, cfg.max_query_rows)
    clauses = ["timestamp_ns > ?"]
    params: list = [hours_ago_ns(hours)]

    if device_id:
        clauses.append("device_id = ?")
        params.append(device_id)
    if domain:
        clauses.append("domain LIKE ?")
        params.append(f"%{domain}%")

    where = " AND ".join(clauses)
    params.append(limit)

    rows = query(f"""
        SELECT device_id, domain, record_type, response_code,
               risk_score, process_name, timestamp_dt
        FROM dns_events
        WHERE {where}
        ORDER BY timestamp_ns DESC LIMIT ?
    """, tuple(params))

    return {"dns_events": rows, "returned": len(rows)}


@mcp.tool()
def telemetry_query_persistence(
    device_id: str = "",
    mechanism: str = "",
    hours: int = 72,
    limit: int = 50,
) -> dict:
    """Search persistence mechanism events — LaunchAgents, crontabs, login items.

    Args:
        device_id: Filter to specific device
        mechanism: Filter by persistence type (e.g. 'LaunchAgent')
        hours:     Lookback window (default 72h — persistence is slow-moving)
        limit:     Max rows
    """
    limit = min(limit, cfg.max_query_rows)
    clauses = ["timestamp_ns > ?"]
    params: list = [hours_ago_ns(hours)]

    if device_id:
        clauses.append("device_id = ?")
        params.append(device_id)
    if mechanism:
        clauses.append("mechanism LIKE ?")
        params.append(f"%{mechanism}%")

    where = " AND ".join(clauses)
    params.append(limit)

    rows = query(f"""
        SELECT device_id, mechanism, path, change_type, label,
               sha256, risk_score, timestamp_dt
        FROM persistence_events
        WHERE {where}
        ORDER BY timestamp_ns DESC LIMIT ?
    """, tuple(params))

    return {"persistence_events": rows, "returned": len(rows)}


@mcp.tool()
def telemetry_query_file_integrity(
    device_id: str = "",
    path: str = "",
    hours: int = 24,
    limit: int = 50,
) -> dict:
    """Search file integrity monitoring events — what files changed.

    Args:
        device_id: Filter to specific device
        path:      Filter by file path (partial match)
        hours:     Lookback window
        limit:     Max rows
    """
    limit = min(limit, cfg.max_query_rows)
    clauses = ["timestamp_ns > ?"]
    params: list = [hours_ago_ns(hours)]

    if device_id:
        clauses.append("device_id = ?")
        params.append(device_id)
    if path:
        clauses.append("path LIKE ?")
        params.append(f"%{path}%")

    where = " AND ".join(clauses)
    params.append(limit)

    rows = query(f"""
        SELECT device_id, path, file_extension, change_type,
               new_hash, owner_uid, is_suid, size,
               risk_score, event_type, timestamp_dt
        FROM fim_events
        WHERE {where}
        ORDER BY timestamp_ns DESC LIMIT ?
    """, tuple(params))

    return {"fim_events": rows, "returned": len(rows)}


@mcp.tool()
def telemetry_geo_summary(hours: int = 24) -> dict:
    """Geographic summary of outbound connections — where is traffic going.

    Args:
        hours: Lookback window
    """
    rows = query("""
        SELECT geo_dst_country, asn_dst_org,
               COUNT(*) as flow_count,
               SUM(bytes_tx) as total_bytes_tx,
               SUM(bytes_rx) as total_bytes_rx,
               COUNT(DISTINCT device_id) as devices_affected,
               SUM(CASE WHEN threat_intel_match THEN 1 ELSE 0 END) as threat_matches
        FROM flow_events
        WHERE timestamp_ns > ?
              AND geo_dst_country IS NOT NULL
              AND geo_dst_country != ''
        GROUP BY geo_dst_country, asn_dst_org
        ORDER BY flow_count DESC
        LIMIT 50
    """, (hours_ago_ns(hours),))

    return {"geo_summary": rows, "hours": hours}


@mcp.tool()
def telemetry_event_timeline(
    device_id: str = "",
    hours: int = 1,
    limit: int = 100,
) -> dict:
    """Chronological event timeline — the raw story of what happened.

    Args:
        device_id: Filter to specific device (recommended for readability)
        hours:     Lookback window (default 1h for detail)
        limit:     Max events
    """
    limit = min(limit, cfg.max_query_rows)
    clauses = ["timestamp_ns > ?"]
    params: list = [hours_ago_ns(hours)]

    if device_id:
        clauses.append("device_id = ?")
        params.append(device_id)

    where = " AND ".join(clauses)
    params.append(limit)

    events = query(f"""
        SELECT event_id, device_id, event_category, event_action,
               risk_score, mitre_techniques, description,
               collection_agent, process_name, pid, username,
               domain, remote_ip, path, timestamp_dt
        FROM security_events
        WHERE {where}
        ORDER BY timestamp_ns ASC
        LIMIT ?
    """, tuple(params))

    return {"timeline": events, "returned": len(events), "hours": hours}
