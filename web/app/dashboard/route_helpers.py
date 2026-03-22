"""Shared helper functions for dashboard route modules.

Constants, parsers, normalizers, and query builders used across
multiple route files.  Extracted from __init__.py to avoid duplication.
"""

import json
import logging
import socket as _socket

logger = logging.getLogger("web.app.dashboard")

# ── Agent ID Normalisation ────────────────────────────────────────────────────

# Legacy agent name mapping
_AGENT_NAME_MAP = {
    "proc-agent": "proc",
    "amoskys-snmp-agent": "snmp",
}

# Comprehensive agent ID normalization: all known aliases → canonical short ID
_AGENT_ID_MAP = {
    # Canonical short IDs
    "proc": "proc",
    "proc_agent": "proc",
    "ProcAgent": "proc",
    "process": "proc",
    "dns": "dns",
    "dns_agent": "dns",
    "DNS": "dns",
    "DNSAgent": "dns",
    "auth": "auth",
    "auth_agent": "auth",
    "AuthGuard": "auth",
    "fim": "fim",
    "fim_agent": "fim",
    "FIM": "fim",
    "flow": "flow",
    "flow_agent": "flow",
    "FlowAgent": "flow",
    "network": "flow",
    "persistence": "persistence",
    "persistence_agent": "persistence",
    "PersistenceGuard": "persistence",
    "peripheral": "peripheral",
    "peripheral_agent": "peripheral",
    "Peripheral": "peripheral",
    "kernel_audit": "kernel_audit",
    "kernel_audit_agent": "kernel_audit",
    "KernelAudit": "kernel_audit",
    "device_discovery": "device_discovery",
    "device_discovery_agent": "device_discovery",
    "Discovery": "device_discovery",
    "protocol_collectors": "protocol_collectors",
    "protocol_collectors_agent": "protocol_collectors",
    "ProtocolCollector": "protocol_collectors",
    "applog": "applog",
    "applog_agent": "applog",
    "AppLog": "applog",
    "db_activity": "db_activity",
    "db_activity_agent": "db_activity",
    "DBActivity": "db_activity",
    "http_inspector": "http_inspector",
    "http_inspector_agent": "http_inspector",
    "HTTPInspector": "http_inspector",
    "internet_activity": "internet_activity",
    "internet_activity_agent": "internet_activity",
    "InternetActivity": "internet_activity",
    "net_scanner": "net_scanner",
    "net_scanner_agent": "net_scanner",
    "NetScanner": "net_scanner",
    # Hyphenated forms from WAL processor
    "proc-agent": "proc",
    "dns-agent": "dns",
    "auth-agent": "auth",
    "fim-agent": "fim",
    "flow-agent": "flow",
    "persistence-agent": "persistence",
    "peripheral-agent": "peripheral",
    "kernel-audit-agent": "kernel_audit",
    # macOS Observatory aliases → canonical short IDs
    "macos_process": "proc",
    "macos_auth": "auth",
    "macos_filesystem": "fim",
    "macos_network": "flow",
    "macos_peripheral": "peripheral",
    "macos_persistence": "persistence",
    # macOS-only agents (map to themselves)
    "macos_security_monitor": "macos_security_monitor",
    "macos_unified_log": "macos_unified_log",
    "macos_dns": "macos_dns",
    "macos_applog": "macos_applog",
    "macos_discovery": "macos_discovery",
    "macos_internet_activity": "macos_internet_activity",
    "macos_db_activity": "macos_db_activity",
    "macos_http_inspector": "macos_http_inspector",
    "macos_correlation": "macos_correlation",
    # macOS Shield agents
    "macos_infostealer_guard": "infostealer_guard",
    "MACOS_INFOSTEALER_GUARD": "infostealer_guard",
    "macos_quarantine_guard": "quarantine_guard",
    "MACOS_QUARANTINE_GUARD": "quarantine_guard",
    "macos_provenance": "provenance",
    "MACOS_PROVENANCE": "provenance",
    "macos_network_sentinel": "network_sentinel",
    "MACOS_NETWORK_SENTINEL": "network_sentinel",
}


def _normalize_agent_id(raw: str) -> str:
    """Map any known agent alias to its canonical short ID."""
    if not raw:
        return ""
    # Try exact match first, then lowercased
    result = _AGENT_ID_MAP.get(raw) or _AGENT_ID_MAP.get(raw.lower())
    if result:
        return result
    return raw.lower().replace("_agent", "").replace("agent", "")


# ── Risk / Severity ──────────────────────────────────────────────────────────


def _risk_to_severity(risk_score: float) -> str:
    """Map a 0.0-1.0 risk score to a severity string."""
    if risk_score >= 0.75:
        return "critical"
    elif risk_score >= 0.5:
        return "high"
    elif risk_score >= 0.25:
        return "medium"
    return "low"


# ── JSON Parsing ─────────────────────────────────────────────────────────────


def _parse_nested_json(raw, fallback, max_depth: int = 3):
    """Parse JSON fields that may be encoded more than once."""
    parsed = raw
    for _ in range(max_depth):
        if parsed is None:
            return [] if isinstance(fallback, list) else {}
        if isinstance(parsed, str):
            text = parsed.strip()
            if not text:
                return [] if isinstance(fallback, list) else {}
            try:
                parsed = json.loads(text)
            except (json.JSONDecodeError, TypeError):
                return [] if isinstance(fallback, list) else {}
            continue
        return parsed
    return parsed


def _parse_mitre(raw):
    """Parse mitre_techniques from DB value."""
    parsed = _parse_nested_json(raw, [])
    if isinstance(parsed, str):
        parsed = parsed.strip()
        return [parsed] if parsed else []
    if not isinstance(parsed, list):
        return []
    return [item.strip() for item in parsed if isinstance(item, str) and item.strip()]


def _parse_indicators(raw):
    """Parse indicators JSON into a dict, unwrapping double-encoded payloads."""
    parsed = _parse_nested_json(raw, {})
    return parsed if isinstance(parsed, dict) else {}


def _parse_json_list(raw):
    """Best-effort parse of a JSON list field."""
    if raw in (None, "", b""):
        return []
    if isinstance(raw, list):
        return raw
    if isinstance(raw, tuple):
        return list(raw)
    try:
        value = json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        return []
    return value if isinstance(value, list) else []


# ── Query Builders ───────────────────────────────────────────────────────────


def _time_conditions(cutoff_ns, hour_start_ns, hour_end_ns):
    """Build common time filter conditions and params."""
    conds = ["timestamp_ns > ?"]
    params = [cutoff_ns]
    if hour_start_ns is not None:
        conds.append("timestamp_ns >= ? AND timestamp_ns < ?")
        params.extend([hour_start_ns, hour_end_ns])
    return conds, params


def _query_table_security(
    store,
    cutoff_ns,
    norm_agent,
    sev_lo,
    sev_hi,
    search_filter,
    hour_start_ns,
    hour_end_ns,
):
    """Query security_events table."""
    conds, params = _time_conditions(cutoff_ns, hour_start_ns, hour_end_ns)

    if norm_agent:
        conds.append("(collection_agent = ? OR indicators LIKE ?)")
        params.extend([norm_agent, f'%"agent": "{norm_agent}"%'])
    if sev_lo > 0.0 or sev_hi < 1.01:
        conds.append("risk_score >= ? AND risk_score < ?")
        params.extend([sev_lo, sev_hi])
    if search_filter:
        conds.append("(event_category LIKE ? OR description LIKE ?)")
        params.extend([f"%{search_filter}%", f"%{search_filter}%"])

    where = " AND ".join(conds)
    try:
        rows = store.db.execute(
            f"SELECT * FROM security_events WHERE {where} ORDER BY timestamp_ns DESC LIMIT 2000",
            params,
        ).fetchall()
        columns = [
            d[0]
            for d in store.db.execute(
                "SELECT * FROM security_events LIMIT 0"
            ).description
        ]
    except Exception:
        return []

    events = []
    for row in rows:
        ev = dict(zip(columns, row))
        indicators = _parse_indicators(ev.get("indicators"))
        mitre_list = _parse_mitre(ev.get("mitre_techniques"))
        agent_name = indicators.get("agent") or ev.get("collection_agent") or ""
        agent_name = _normalize_agent_id(agent_name) if agent_name else ""
        risk_score = round(ev.get("risk_score", 0) or 0, 3)

        events.append(
            {
                "id": ev.get("id"),
                "timestamp_dt": ev.get("timestamp_dt", ""),
                "event_category": ev.get("event_category", "unknown"),
                "severity": _risk_to_severity(risk_score),
                "risk_score": risk_score,
                "confidence": round(ev.get("confidence", 0) or 0, 3),
                "source_ip": indicators.get("source_ip")
                or indicators.get("src_ip")
                or ev.get("device_id", ""),
                "description": ev.get("description", ""),
                "agent": agent_name,
                "device_id": ev.get("device_id", ""),
                "final_classification": ev.get("final_classification", ""),
                "mitre_techniques": mitre_list,
                "mitre_technique": ", ".join(mitre_list),
                "indicators": indicators,
                "source_table": "security",
                "_sort_ts": ev.get("timestamp_ns", 0),
            }
        )
    return events


def _query_table_process(
    store, cutoff_ns, sev_lo, sev_hi, search_filter, hour_start_ns, hour_end_ns
):
    """Query process_events table."""
    conds, params = _time_conditions(cutoff_ns, hour_start_ns, hour_end_ns)

    # anomaly_score serves as risk_score for process events
    if sev_lo > 0.0 or sev_hi < 1.01:
        conds.append("anomaly_score >= ? AND anomaly_score < ?")
        params.extend([sev_lo, sev_hi])
    if search_filter:
        conds.append("(exe LIKE ? OR cmdline LIKE ? OR username LIKE ?)")
        params.extend(
            [f"%{search_filter}%", f"%{search_filter}%", f"%{search_filter}%"]
        )

    where = " AND ".join(conds)
    try:
        rows = store.db.execute(
            f"SELECT * FROM process_events WHERE {where} ORDER BY timestamp_ns DESC LIMIT 2000",
            params,
        ).fetchall()
        columns = [
            d[0]
            for d in store.db.execute(
                "SELECT * FROM process_events LIMIT 0"
            ).description
        ]
    except Exception:
        return []

    events = []
    for row in rows:
        ev = dict(zip(columns, row))
        risk = round(ev.get("anomaly_score", 0) or 0, 3)
        exe = ev.get("exe", "") or ""
        cmdline = ev.get("cmdline", "") or ""
        desc = f"{exe}" + (f" — {cmdline[:120]}" if cmdline and cmdline != exe else "")
        agent = _normalize_agent_id(ev.get("collection_agent") or "proc")

        events.append(
            {
                "id": ev.get("id"),
                "timestamp_dt": ev.get("timestamp_dt", ""),
                "event_category": "process_event",
                "severity": _risk_to_severity(risk),
                "risk_score": risk,
                "confidence": round(ev.get("confidence_score", 0) or 0, 3),
                "source_ip": ev.get("device_id", ""),
                "description": desc,
                "agent": agent,
                "device_id": ev.get("device_id", ""),
                "final_classification": (
                    "suspicious" if ev.get("is_suspicious") else "benign"
                ),
                "mitre_techniques": [],
                "mitre_technique": "",
                "indicators": {
                    "pid": ev.get("pid"),
                    "ppid": ev.get("ppid"),
                    "exe": exe,
                    "username": ev.get("username", ""),
                    "cpu_percent": ev.get("cpu_percent"),
                },
                "source_table": "process",
                "_sort_ts": ev.get("timestamp_ns", 0),
            }
        )
    return events


def _query_table_flow(
    store, cutoff_ns, sev_lo, sev_hi, search_filter, hour_start_ns, hour_end_ns
):
    """Query flow_events table."""
    conds, params = _time_conditions(cutoff_ns, hour_start_ns, hour_end_ns)

    # threat_score serves as risk_score for flow events
    if sev_lo > 0.0 or sev_hi < 1.01:
        conds.append("COALESCE(threat_score, 0) >= ? AND COALESCE(threat_score, 0) < ?")
        params.extend([sev_lo, sev_hi])
    if search_filter:
        conds.append("(src_ip LIKE ? OR dst_ip LIKE ? OR protocol LIKE ?)")
        params.extend(
            [f"%{search_filter}%", f"%{search_filter}%", f"%{search_filter}%"]
        )

    where = " AND ".join(conds)
    try:
        rows = store.db.execute(
            f"SELECT * FROM flow_events WHERE {where} ORDER BY timestamp_ns DESC LIMIT 2000",
            params,
        ).fetchall()
        columns = [
            d[0]
            for d in store.db.execute("SELECT * FROM flow_events LIMIT 0").description
        ]
    except Exception:
        return []

    events = []
    for row in rows:
        ev = dict(zip(columns, row))
        risk = round(ev.get("threat_score", 0) or 0, 3)
        protocol = ev.get("protocol", "TCP") or "TCP"
        dst = ev.get("dst_ip", "") or ""
        port = ev.get("dst_port", "") or ""
        desc = f"{protocol} → {dst}:{port}"

        events.append(
            {
                "id": ev.get("id"),
                "timestamp_dt": ev.get("timestamp_dt", ""),
                "event_category": f"network_flow_{protocol.lower()}",
                "severity": _risk_to_severity(risk),
                "risk_score": risk,
                "confidence": 0.5,
                "source_ip": ev.get("src_ip", ""),
                "description": desc,
                "agent": "flow",
                "device_id": ev.get("device_id", ""),
                "final_classification": (
                    "suspicious" if ev.get("is_suspicious") else "benign"
                ),
                "mitre_techniques": [],
                "mitre_technique": "",
                "indicators": {
                    "src_ip": ev.get("src_ip"),
                    "dst_ip": dst,
                    "src_port": ev.get("src_port"),
                    "dst_port": port,
                    "protocol": protocol,
                    "bytes_tx": ev.get("bytes_tx"),
                    "bytes_rx": ev.get("bytes_rx"),
                },
                "source_table": "flow",
                "_sort_ts": ev.get("timestamp_ns", 0),
            }
        )
    return events


def _query_table_dns(
    store, cutoff_ns, sev_lo, sev_hi, search_filter, hour_start_ns, hour_end_ns
):
    """Query dns_events table."""
    conds, params = _time_conditions(cutoff_ns, hour_start_ns, hour_end_ns)

    if sev_lo > 0.0 or sev_hi < 1.01:
        conds.append("COALESCE(risk_score, 0) >= ? AND COALESCE(risk_score, 0) < ?")
        params.extend([sev_lo, sev_hi])
    if search_filter:
        conds.append("(domain LIKE ? OR query_type LIKE ? OR event_type LIKE ?)")
        params.extend(
            [f"%{search_filter}%", f"%{search_filter}%", f"%{search_filter}%"]
        )

    where = " AND ".join(conds)
    try:
        rows = store.db.execute(
            f"SELECT * FROM dns_events WHERE {where} ORDER BY timestamp_ns DESC LIMIT 2000",
            params,
        ).fetchall()
        columns = [
            d[0]
            for d in store.db.execute("SELECT * FROM dns_events LIMIT 0").description
        ]
    except Exception:
        return []

    events = []
    for row in rows:
        ev = dict(zip(columns, row))
        risk = round(ev.get("risk_score", 0) or 0, 3)
        domain = ev.get("domain", "") or ""
        qtype = ev.get("query_type", "") or ""
        desc = f"DNS {qtype} → {domain}"
        mitre_list = _parse_mitre(ev.get("mitre_techniques"))
        agent = _normalize_agent_id(ev.get("collection_agent") or "dns")

        events.append(
            {
                "id": ev.get("id"),
                "timestamp_dt": ev.get("timestamp_dt", ""),
                "event_category": ev.get("event_type", "dns_query") or "dns_query",
                "severity": _risk_to_severity(risk),
                "risk_score": risk,
                "confidence": round(ev.get("confidence", 0) or 0, 3),
                "source_ip": ev.get("source_ip", ""),
                "description": desc,
                "agent": agent,
                "device_id": ev.get("device_id", ""),
                "final_classification": (
                    "suspicious"
                    if ev.get("is_beaconing") or ev.get("is_tunneling")
                    else "benign"
                ),
                "mitre_techniques": mitre_list,
                "mitre_technique": ", ".join(mitre_list),
                "indicators": {
                    "domain": domain,
                    "query_type": qtype,
                    "dga_score": ev.get("dga_score"),
                    "is_beaconing": ev.get("is_beaconing"),
                    "response_code": ev.get("response_code"),
                },
                "source_table": "dns",
                "_sort_ts": ev.get("timestamp_ns", 0),
            }
        )
    return events


def _query_table_persistence(
    store, cutoff_ns, sev_lo, sev_hi, search_filter, hour_start_ns, hour_end_ns
):
    """Query persistence_events table."""
    conds, params = _time_conditions(cutoff_ns, hour_start_ns, hour_end_ns)

    if sev_lo > 0.0 or sev_hi < 1.01:
        conds.append("COALESCE(risk_score, 0) >= ? AND COALESCE(risk_score, 0) < ?")
        params.extend([sev_lo, sev_hi])
    if search_filter:
        conds.append("(mechanism LIKE ? OR path LIKE ? OR command LIKE ?)")
        params.extend(
            [f"%{search_filter}%", f"%{search_filter}%", f"%{search_filter}%"]
        )

    where = " AND ".join(conds)
    try:
        rows = store.db.execute(
            f"SELECT * FROM persistence_events WHERE {where} ORDER BY timestamp_ns DESC LIMIT 2000",
            params,
        ).fetchall()
        columns = [
            d[0]
            for d in store.db.execute(
                "SELECT * FROM persistence_events LIMIT 0"
            ).description
        ]
    except Exception:
        return []

    events = []
    for row in rows:
        ev = dict(zip(columns, row))
        risk = round(ev.get("risk_score", 0) or 0, 3)
        mechanism = ev.get("mechanism", "") or ""
        path = ev.get("path", "") or ""
        desc = f"{mechanism}: {path}" if path else mechanism
        mitre_list = _parse_mitre(ev.get("mitre_techniques"))
        agent = _normalize_agent_id(ev.get("collection_agent") or "persistence")

        events.append(
            {
                "id": ev.get("id"),
                "timestamp_dt": ev.get("timestamp_dt", ""),
                "event_category": mechanism or "persistence_event",
                "severity": _risk_to_severity(risk),
                "risk_score": risk,
                "confidence": round(ev.get("confidence", 0) or 0, 3),
                "source_ip": ev.get("device_id", ""),
                "description": desc,
                "agent": agent,
                "device_id": ev.get("device_id", ""),
                "final_classification": "suspicious" if risk >= 0.5 else "benign",
                "mitre_techniques": mitre_list,
                "mitre_technique": ", ".join(mitre_list),
                "indicators": {
                    "mechanism": mechanism,
                    "path": path,
                    "command": ev.get("command", ""),
                    "change_type": ev.get("change_type", ""),
                    "user": ev.get("user", ""),
                },
                "source_table": "persistence",
                "_sort_ts": ev.get("timestamp_ns", 0),
            }
        )
    return events


def _query_table_fim(
    store, cutoff_ns, sev_lo, sev_hi, search_filter, hour_start_ns, hour_end_ns
):
    """Query fim_events table."""
    conds, params = _time_conditions(cutoff_ns, hour_start_ns, hour_end_ns)

    if sev_lo > 0.0 or sev_hi < 1.01:
        conds.append("COALESCE(risk_score, 0) >= ? AND COALESCE(risk_score, 0) < ?")
        params.extend([sev_lo, sev_hi])
    if search_filter:
        conds.append("(path LIKE ? OR change_type LIKE ? OR reason LIKE ?)")
        params.extend(
            [f"%{search_filter}%", f"%{search_filter}%", f"%{search_filter}%"]
        )

    where = " AND ".join(conds)
    try:
        rows = store.db.execute(
            f"SELECT * FROM fim_events WHERE {where} ORDER BY timestamp_ns DESC LIMIT 2000",
            params,
        ).fetchall()
        columns = [
            d[0]
            for d in store.db.execute("SELECT * FROM fim_events LIMIT 0").description
        ]
    except Exception:
        return []

    events = []
    for row in rows:
        ev = dict(zip(columns, row))
        risk = round(ev.get("risk_score", 0) or 0, 3)
        path = ev.get("path", "") or ""
        change = ev.get("change_type", "") or ""
        desc = f"{change}: {path}" if change else path
        mitre_list = _parse_mitre(ev.get("mitre_techniques"))

        events.append(
            {
                "id": ev.get("id"),
                "timestamp_dt": ev.get("timestamp_dt", ""),
                "event_category": "file_modification",
                "severity": _risk_to_severity(risk),
                "risk_score": risk,
                "confidence": round(ev.get("confidence", 0) or 0, 3),
                "source_ip": ev.get("device_id", ""),
                "description": desc,
                "agent": "fim",
                "device_id": ev.get("device_id", ""),
                "final_classification": "suspicious" if risk >= 0.5 else "benign",
                "mitre_techniques": mitre_list,
                "mitre_technique": ", ".join(mitre_list),
                "indicators": {
                    "path": path,
                    "change_type": change,
                    "old_hash": ev.get("old_hash", ""),
                    "new_hash": ev.get("new_hash", ""),
                    "reason": ev.get("reason", ""),
                },
                "source_table": "fim",
                "_sort_ts": ev.get("timestamp_ns", 0),
            }
        )
    return events


# ── Utility ──────────────────────────────────────────────────────────────────


def _get_store():
    """Get TelemetryStore singleton, return None if unavailable."""
    try:
        from .telemetry_bridge import get_telemetry_store

        return get_telemetry_store()
    except Exception:
        return None


def _get_local_ip():
    """Get the local IP address."""
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"
