"""Observatory API routes for the AMOSKYS Dashboard.

Extracted from __init__.py — contains posture, signals, incidents,
DNS, network, FIM, persistence, audit, and observation domain endpoints.
"""

import json
import logging
import re
import sqlite3
import time
from collections import OrderedDict

from flask import jsonify, request

from ..api.rate_limiter import require_rate_limit
from ..middleware import require_login
from . import dashboard_bp
from .route_helpers import _get_store, _parse_indicators, _parse_json_list, _parse_mitre

logger = logging.getLogger("web.app.dashboard")

_MSG_DB_UNAVAILABLE = "Database unavailable"


# ═══════════════════════════════════════════════════════════════════════════════
# Helper functions — used only within this module
# ═══════════════════════════════════════════════════════════════════════════════


def _normalize_replay_event(row, source="security"):
    """Flatten an event row into the contract expected by timeline replay."""
    event = dict(row)
    indicators = _parse_indicators(event.get("indicators"))
    event["indicators"] = indicators
    event["mitre_techniques"] = _parse_mitre(event.get("mitre_techniques"))
    event["source"] = source
    event.setdefault("event_type", event.get("event_category") or source)
    event.setdefault(
        "agent_id",
        event.get("collection_agent")
        or event.get("agent_id")
        or event.get("device_id"),
    )

    indicator_aliases = {
        "source_ip": ("source_ip", "src_ip"),
        "dest_ip": ("dest_ip", "dst_ip", "remote_ip"),
        "process_name": ("process_name", "process", "exe"),
        "file_path": ("file_path", "path", "target_path"),
    }
    for target_key, aliases in indicator_aliases.items():
        if event.get(target_key):
            continue
        for alias in aliases:
            value = indicators.get(alias)
            if value:
                event[target_key] = value
                break

    return event


def _expand_signal_event_ids(store, signal_ids):
    """Resolve signal IDs to contributing numeric security event row IDs."""
    if not signal_ids:
        return []

    placeholders = ",".join("?" for _ in signal_ids)
    try:
        rows = store.db.execute(
            f"SELECT contributing_event_ids FROM signals WHERE signal_id IN ({placeholders})",
            list(signal_ids),
        ).fetchall()
    except Exception:
        return []

    event_ids = []
    for row in rows:
        payload = (
            row[0]
            if not isinstance(row, sqlite3.Row)
            else row["contributing_event_ids"]
        )
        for event_id in _parse_json_list(payload):
            if isinstance(event_id, int):
                event_ids.append(event_id)
            elif isinstance(event_id, str) and event_id.isdigit():
                event_ids.append(int(event_id))
    return event_ids


def _load_incident_replay_events(store, incident):
    """Resolve linked incident evidence into flat replay events."""
    source_event_ids = _parse_json_list(incident.get("source_event_ids"))
    signal_ids = _parse_json_list(incident.get("signal_ids"))

    numeric_ids = []
    string_event_ids = []

    for event_ref in source_event_ids:
        if isinstance(event_ref, int):
            numeric_ids.append(event_ref)
        elif isinstance(event_ref, str):
            if event_ref.isdigit():
                numeric_ids.append(int(event_ref))
            elif event_ref:
                string_event_ids.append(event_ref)

    numeric_ids.extend(_expand_signal_event_ids(store, signal_ids))

    clauses = []
    params = []
    if numeric_ids:
        unique_numeric_ids = list(dict.fromkeys(numeric_ids))
        clauses.append(f"id IN ({','.join('?' for _ in unique_numeric_ids)})")
        params.extend(unique_numeric_ids)
    if string_event_ids:
        unique_string_ids = list(dict.fromkeys(string_event_ids))
        clauses.append(f"event_id IN ({','.join('?' for _ in unique_string_ids)})")
        params.extend(unique_string_ids)

    if not clauses:
        return []

    try:
        cursor = store.db.execute(
            "SELECT * FROM security_events WHERE "
            + " OR ".join(clauses)
            + " ORDER BY timestamp_ns ASC",
            params,
        )
        rows = [dict(row) for row in cursor.fetchall()]
    except Exception:
        logger.exception("Failed to resolve incident-linked security events")
        return []

    deduped = []
    seen = set()
    for row in rows:
        key = row.get("id") or row.get("event_id")
        if key in seen:
            continue
        seen.add(key)
        deduped.append(_normalize_replay_event(row, source="security"))
    return deduped


def _flatten_incident_timeline_entries(entries):
    """Flatten TelemetryStore incident timeline entries for replay."""
    flattened = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        data = entry.get("data") if isinstance(entry.get("data"), dict) else {}
        if data.get("_collapsed"):
            continue
        base = dict(data)
        if "timestamp_ns" not in base and entry.get("ts") is not None:
            base["timestamp_ns"] = entry.get("ts")
        flattened.append(
            _normalize_replay_event(base, source=str(entry.get("source") or "unknown"))
        )
    return flattened


# ═══════════════════════════════════════════════════════════════════════════════
# Observatory API Endpoints — Wire observability pipeline data to dashboard
# ═══════════════════════════════════════════════════════════════════════════════


# ── Device Posture ──


@dashboard_bp.route("/api/posture/summary")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def posture_summary():
    """Device posture — Nerve Signal Model (v1).

    Returns posture_score (0-100) computed via signal classification,
    time-decay, and tanh mapping.  Backwards compatible: includes
    domain breakdown, total_events, security_detections.
    """
    store = _get_store()
    if not store:
        return jsonify({"status": "error", "message": _MSG_DB_UNAVAILABLE})
    hours = request.args.get("hours", 24, type=int)
    return jsonify(store.compute_nerve_posture(hours))


@dashboard_bp.route("/api/posture/timeline")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def posture_timeline():
    """Unified cross-domain event timeline."""
    store = _get_store()
    if not store:
        return jsonify([])
    hours = request.args.get("hours", 24, type=int)
    limit = request.args.get("limit", 200, type=int)
    return jsonify(store.get_cross_domain_timeline(hours, min(limit, 500)))


# ── Signals (Directive 3) ──


@dashboard_bp.route("/api/signals")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def list_signals():
    """List signals with optional status filter."""
    store = _get_store()
    if not store:
        return jsonify([])
    status = request.args.get("status")
    limit = request.args.get("limit", 50, type=int)
    return jsonify(store.get_signals(status=status, limit=min(limit, 200)))


@dashboard_bp.route("/api/signals", methods=["POST"])
@require_login
def create_signal_api():
    """Manually create a signal (analyst-initiated)."""
    store = _get_store()
    if not store:
        return jsonify({"status": "error", "message": _MSG_DB_UNAVAILABLE}), 500
    data = request.get_json(silent=True) or {}
    required = ("device_id", "signal_type", "trigger_summary")
    for field in required:
        if not data.get(field):
            return (
                jsonify({"status": "error", "message": f"Missing: {field}"}),
                400,
            )
    signal_id = store.create_signal(
        device_id=data["device_id"],
        signal_type=data.get("signal_type", "manual"),
        trigger_summary=data["trigger_summary"],
        contributing_event_ids=data.get("contributing_event_ids", []),
        risk_score=data.get("risk_score", 0.5),
    )
    return jsonify({"status": "ok", "signal_id": signal_id}), 201


@dashboard_bp.route("/api/signals/<signal_id>/promote", methods=["POST"])
@require_login
def promote_signal(signal_id):
    """Promote a signal to an incident."""
    store = _get_store()
    if not store:
        return jsonify({"status": "error", "message": _MSG_DB_UNAVAILABLE}), 500
    incident_id = store.promote_signal(signal_id)
    if incident_id:
        return jsonify({"status": "ok", "incident_id": incident_id})
    return jsonify({"status": "error", "message": "Signal not found or not open"}), 404


@dashboard_bp.route("/api/signals/<signal_id>/dismiss", methods=["POST"])
@require_login
def dismiss_signal(signal_id):
    """Dismiss a signal with reason."""
    store = _get_store()
    if not store:
        return jsonify({"status": "error", "message": _MSG_DB_UNAVAILABLE}), 500
    data = request.get_json(silent=True) or {}
    ok = store.dismiss_signal(
        signal_id,
        dismissed_by=data.get("dismissed_by", "analyst"),
        reason=data.get("reason", ""),
    )
    if ok:
        return jsonify({"status": "ok"})
    return jsonify({"status": "error", "message": "Signal not found or not open"}), 404


@dashboard_bp.route("/api/incidents/<int:incident_id>/timeline")
@require_login
@require_rate_limit(max_requests=30, window_seconds=60)
def incident_timeline(incident_id):
    """Get cross-agent investigation timeline for an incident."""
    store = _get_store()
    if not store:
        return jsonify([])
    incident = store.get_incident(incident_id)
    if not incident:
        return jsonify({"status": "error", "message": "Incident not found"}), 404

    evidence_events = _load_incident_replay_events(store, incident)
    if evidence_events:
        return jsonify(evidence_events)

    device_id = incident.get("device_id") or incident.get("assignee", "")
    # Use incident time window or default to last 24h
    end_ns = int(time.time() * 1e9)
    start_ns = end_ns - int(24 * 3600 * 1e9)
    if incident.get("created_at"):
        try:
            from datetime import datetime as _dt

            created = _dt.fromisoformat(incident["created_at"].replace("Z", "+00:00"))
            start_ns = int(created.timestamp() * 1e9) - int(3600 * 1e9)  # 1h before
        except (ValueError, TypeError):
            pass
    # Extract device_id from title/description (fusion incidents embed it)
    # Format: "[rule] DESCRIPTION on DEVICE_ID: ..."
    if not device_id:
        for field in ("title", "description"):
            text = incident.get(field, "")
            m = re.search(r" on ([A-Za-z0-9._-]+\.local)\b", text)
            if not m:
                m = re.search(r" on ([A-Za-z0-9._-]+):", text)
            if m:
                device_id = m.group(1)
                break
    # Fallback: try device_id from linked security events
    if not device_id:
        try:
            event_ids = json.loads(incident.get("source_event_ids", "[]"))
            if event_ids:
                # source_event_ids may be probe string IDs, try integer lookup first
                row = store.db.execute(
                    "SELECT device_id FROM security_events WHERE id = ?",
                    (event_ids[0],),
                ).fetchone()
                if row:
                    device_id = row[0]
        except Exception:
            pass
    if not device_id:
        return jsonify([])
    timeline = store.build_incident_timeline(device_id, start_ns, end_ns)
    return jsonify(_flatten_incident_timeline_entries(timeline))


# ── DNS Intelligence ──


@dashboard_bp.route("/api/dns/stats")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def dns_stats():
    """DNS query analytics."""
    store = _get_store()
    if not store:
        return jsonify({"total_queries": 0})
    hours = request.args.get("hours", 24, type=int)
    stats = store.get_dns_stats(hours)
    # JS expects 'response_codes' (not 'by_response_code') and 'nxdomain_count'
    rc = stats.pop("by_response_code", {})
    stats["response_codes"] = rc
    stats.setdefault("nxdomain_count", rc.get("NXDOMAIN", 0))
    return jsonify(stats)


@dashboard_bp.route("/api/dns/top-domains")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def dns_top_domains():
    """Top queried domains."""
    store = _get_store()
    if not store:
        return jsonify([])
    hours = request.args.get("hours", 24, type=int)
    limit = request.args.get("limit", 20, type=int)
    return jsonify(store.get_dns_top_domains(hours, min(limit, 100)))


@dashboard_bp.route("/api/dns/dga")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def dns_dga():
    """DGA suspect domains."""
    store = _get_store()
    if not store:
        return jsonify([])
    hours = request.args.get("hours", 24, type=int)
    min_score = request.args.get("min_score", 0.5, type=float)
    limit = request.args.get("limit", 50, type=int)
    return jsonify(store.get_dns_dga_suspects(hours, min_score, min(limit, 200)))


@dashboard_bp.route("/api/dns/beaconing")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def dns_beaconing():
    """Beaconing domain detection."""
    store = _get_store()
    if not store:
        return jsonify([])
    hours = request.args.get("hours", 24, type=int)
    limit = request.args.get("limit", 50, type=int)
    return jsonify(store.get_dns_beaconing(hours, min(limit, 200)))


@dashboard_bp.route("/api/dns/timeline")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def dns_timeline():
    """DNS query timeline."""
    store = _get_store()
    if not store:
        return jsonify([])
    hours = request.args.get("hours", 24, type=int)
    return jsonify(store.get_dns_timeline(hours))


@dashboard_bp.route("/api/dns/recent")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def dns_recent():
    """Recent DNS events with search."""
    store = _get_store()
    if not store:
        return jsonify({"results": [], "total_count": 0})
    hours = request.args.get("hours", 24, type=int)
    limit = request.args.get("limit", 100, type=int)
    offset = request.args.get("offset", 0, type=int)
    search = request.args.get("search", "")
    return jsonify(
        store.search_events(search, "dns_events", hours, min(limit, 500), offset)
    )


# ── Network Intelligence ──


@dashboard_bp.route("/api/network/stats")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def network_flow_stats():
    """Network flow summary."""
    store = _get_store()
    if not store:
        return jsonify({"total_flows": 0})
    hours = request.args.get("hours", 24, type=int)
    return jsonify(store.get_flow_stats(hours))


@dashboard_bp.route("/api/network/geo")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def network_geo():
    """GeoIP destination aggregation."""
    store = _get_store()
    if not store:
        return jsonify({"countries": [], "cities": []})
    hours = request.args.get("hours", 24, type=int)
    return jsonify(store.get_flow_geo_stats(hours))


@dashboard_bp.route("/api/network/asn")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def network_asn():
    """ASN breakdown."""
    store = _get_store()
    if not store:
        return jsonify([])
    hours = request.args.get("hours", 24, type=int)
    return jsonify(store.get_flow_asn_breakdown(hours))


@dashboard_bp.route("/api/network/device-location")
@require_login
@require_rate_limit(max_requests=10, window_seconds=60)
def network_device_location():
    """Resolve device's public IP to geo-coordinates via ipinfo.io."""
    import urllib.request

    cache_key = "_device_location"
    cached = getattr(network_device_location, cache_key, None)
    if cached:
        return jsonify(cached)
    try:
        req = urllib.request.Request(
            "https://ipinfo.io/json",
            headers={"Accept": "application/json", "User-Agent": "AMOSKYS/1.0"},
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            import json as _json

            data = _json.loads(resp.read())
        loc = data.get("loc", "0,0").split(",")
        result = {
            "lat": float(loc[0]),
            "lon": float(loc[1]),
            "city": data.get("city", ""),
            "region": data.get("region", ""),
            "country": data.get("country", ""),
            "org": data.get("org", ""),
            "ip": data.get("ip", ""),
        }
        setattr(network_device_location, cache_key, result)
        return jsonify(result)
    except Exception:
        return jsonify(
            {"lat": 38.2542, "lon": -85.7594, "city": "Louisville", "country": "US"}
        )


@dashboard_bp.route("/api/network/geo-points")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def network_geo_points():
    """Lat/lon points for world map."""
    store = _get_store()
    if not store:
        return jsonify([])
    hours = request.args.get("hours", 24, type=int)
    limit = request.args.get("limit", 500, type=int)
    return jsonify(store.get_flow_geo_points(hours, min(limit, 1000)))


@dashboard_bp.route("/api/network/top-destinations")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def network_top_destinations():
    """Top destination IPs."""
    store = _get_store()
    if not store:
        return jsonify([])
    hours = request.args.get("hours", 24, type=int)
    limit = request.args.get("limit", 20, type=int)
    return jsonify(store.get_flow_top_destinations(hours, min(limit, 100)))


@dashboard_bp.route("/api/network/by-process")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def network_by_process():
    """Network usage by process."""
    store = _get_store()
    if not store:
        return jsonify([])
    hours = request.args.get("hours", 24, type=int)
    limit = request.args.get("limit", 20, type=int)
    return jsonify(store.get_flow_by_process(hours, min(limit, 100)))


@dashboard_bp.route("/api/network/flows")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def network_flows():
    """Recent flow events with search."""
    store = _get_store()
    if not store:
        return jsonify({"results": [], "total_count": 0})
    hours = request.args.get("hours", 24, type=int)
    limit = request.args.get("limit", 100, type=int)
    offset = request.args.get("offset", 0, type=int)
    search = request.args.get("search", "")
    return jsonify(
        store.search_events(search, "flow_events", hours, min(limit, 500), offset)
    )


# ── File Integrity ──


@dashboard_bp.route("/api/fim/stats")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def fim_stats():
    """File integrity monitoring summary."""
    store = _get_store()
    if not store:
        return jsonify({"total_changes": 0})
    hours = request.args.get("hours", 24, type=int)
    stats = store.get_fim_stats(hours)
    # JS expects 'total' (not 'total_changes')
    stats["total"] = stats.get("total_changes", 0)
    return jsonify(stats)


@dashboard_bp.route("/api/fim/critical")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def fim_critical():
    """High-risk file changes."""
    store = _get_store()
    if not store:
        return jsonify([])
    hours = request.args.get("hours", 24, type=int)
    min_risk = request.args.get("min_risk", 0.3, type=float)
    limit = request.args.get("limit", 100, type=int)
    return jsonify(store.get_fim_critical_changes(hours, min_risk, min(limit, 500)))


@dashboard_bp.route("/api/fim/directories")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def fim_directories():
    """File changes by directory."""
    store = _get_store()
    if not store:
        return jsonify([])
    hours = request.args.get("hours", 24, type=int)
    return jsonify(store.get_fim_directory_summary(hours))


@dashboard_bp.route("/api/fim/timeline")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def fim_timeline():
    """FIM event timeline."""
    store = _get_store()
    if not store:
        return jsonify([])
    hours = request.args.get("hours", 24, type=int)
    return jsonify(store.get_fim_timeline(hours))


@dashboard_bp.route("/api/fim/recent")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def fim_recent():
    """Recent FIM events with search."""
    store = _get_store()
    if not store:
        return jsonify({"results": [], "total_count": 0})
    hours = request.args.get("hours", 24, type=int)
    limit = request.args.get("limit", 100, type=int)
    offset = request.args.get("offset", 0, type=int)
    search = request.args.get("search", "")
    return jsonify(
        store.search_events(search, "fim_events", hours, min(limit, 500), offset)
    )


# ── Persistence Landscape ──


@dashboard_bp.route("/api/persistence/stats")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def persistence_stats():
    """Persistence mechanism summary."""
    store = _get_store()
    if not store:
        return jsonify({"total_entries": 0})
    hours = request.args.get("hours", 24, type=int)
    stats = store.get_persistence_stats(hours)
    # JS expects 'mechanism_counts' (not 'by_mechanism'),
    # 'change_type_counts' (not 'by_change_type'), and 'total_changes'
    stats["mechanism_counts"] = stats.pop("by_mechanism", {})
    stats["change_type_counts"] = stats.pop("by_change_type", {})
    stats.setdefault("total_changes", sum(stats["change_type_counts"].values()))
    return jsonify(stats)


@dashboard_bp.route("/api/persistence/inventory")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def persistence_inventory():
    """Persistence entry inventory."""
    store = _get_store()
    if not store:
        return jsonify([])
    mechanism = request.args.get("mechanism")
    limit = request.args.get("limit", 200, type=int)
    entries = store.get_persistence_inventory(mechanism, min(limit, 500))
    # JS expects {inventory: [...]} or {entries: [...]}, not a flat list
    return jsonify({"inventory": entries})


@dashboard_bp.route("/api/persistence/changes")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def persistence_changes():
    """Persistence modification timeline."""
    store = _get_store()
    if not store:
        return jsonify([])
    hours = request.args.get("hours", 24, type=int)
    raw = store.get_persistence_changes(hours)
    # JS expects {buckets: [{label, mechanisms: {mech: count}}, ...]}
    # Store returns flat [{hour, mechanism, count}, ...]
    buckets_map = OrderedDict()
    for row in raw:
        h = row.get("hour", "")
        if h not in buckets_map:
            buckets_map[h] = {"label": h, "mechanisms": {}}
        buckets_map[h]["mechanisms"][row.get("mechanism", "")] = row.get("count", 0)
    return jsonify({"buckets": list(buckets_map.values())})


# ── Auth / Audit ──


@dashboard_bp.route("/api/audit/stats")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def audit_stats():
    """Kernel audit / auth summary."""
    store = _get_store()
    if not store:
        return jsonify({"total_events": 0})
    hours = request.args.get("hours", 24, type=int)
    return jsonify(store.get_audit_stats(hours))


@dashboard_bp.route("/api/audit/high-risk")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def audit_high_risk():
    """High-risk audit events."""
    store = _get_store()
    if not store:
        return jsonify([])
    hours = request.args.get("hours", 24, type=int)
    min_risk = request.args.get("min_risk", 0.5, type=float)
    limit = request.args.get("limit", 100, type=int)
    return jsonify(store.get_audit_high_risk(hours, min_risk, min(limit, 500)))


@dashboard_bp.route("/api/audit/recent")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def audit_recent():
    """Recent audit events with search."""
    store = _get_store()
    if not store:
        return jsonify({"results": [], "total_count": 0})
    hours = request.args.get("hours", 24, type=int)
    limit = request.args.get("limit", 100, type=int)
    offset = request.args.get("offset", 0, type=int)
    search = request.args.get("search", "")
    return jsonify(
        store.search_events(search, "audit_events", hours, min(limit, 500), offset)
    )


# ── Observation Domains ──


@dashboard_bp.route("/api/observations/stats")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def observation_stats():
    """Per-domain observation counts."""
    store = _get_store()
    if not store:
        return jsonify({"total": 0, "by_domain": {}})
    hours = request.args.get("hours", 24, type=int)
    return jsonify(store.get_observation_domain_stats(hours))


@dashboard_bp.route("/api/observations/<domain>")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def observation_by_domain(domain):
    """Paginated observations for a domain."""
    store = _get_store()
    if not store:
        return jsonify({"results": [], "total_count": 0})
    hours = request.args.get("hours", 24, type=int)
    limit = request.args.get("limit", 100, type=int)
    offset = request.args.get("offset", 0, type=int)
    return jsonify(
        store.get_observations_by_domain(domain, hours, min(limit, 500), offset)
    )


@dashboard_bp.route("/api/observations/search")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def observation_search():
    """Search observation attributes."""
    store = _get_store()
    if not store:
        return jsonify({"results": [], "total_count": 0})
    query = request.args.get("query", "")
    domain = request.args.get("domain")
    hours = request.args.get("hours", 24, type=int)
    limit = request.args.get("limit", 100, type=int)
    return jsonify(store.search_observations(query, domain, hours, min(limit, 500)))
