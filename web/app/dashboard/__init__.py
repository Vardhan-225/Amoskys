"""
AMOSKYS Cortex Dashboard Module
Phase 2.4 - Neural Security Visualization Interface

This module implements the AMOSKYS Cortex Dashboard, providing real-time
visualization of security events, agent status, and system metrics through
an intelligent neural interface.
"""

import importlib
import logging
import sqlite3

logger = logging.getLogger("web.app.dashboard")
import json
import os
import time
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, redirect, render_template, request, url_for

from ..api.rate_limiter import require_rate_limit
from ..middleware import get_current_user, require_login

# Constants
UTC_TIMEZONE_SUFFIX = "+00:00"
_MSG_DB_UNAVAILABLE = "Database unavailable"
_MSG_FUSION_UNAVAILABLE = "Fusion engine not available"

# Dashboard Blueprint
dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")

# Import dashboard utilities
from .utils import (
    calculate_threat_score,
    get_agent_health_summary,
    get_event_clustering_data,
    get_system_metrics_snapshot,
    get_threat_timeline_data,
)


@dashboard_bp.route("/")
@require_login
def cortex_home():
    """AMOSKYS Cortex Dashboard - Main Neural Interface"""
    user = get_current_user()
    return render_template("dashboard/cortex.html", user=user)


@dashboard_bp.route("/cortex")
@require_login
def cortex_dashboard():
    """AMOSKYS Cortex Dashboard - Command Center"""
    user = get_current_user()
    return render_template("dashboard/cortex.html", user=user)


@dashboard_bp.route("/agents")
@require_login
def agent_management():
    """Agent Management Dashboard - Neural Network Status"""
    user = get_current_user()
    return render_template("dashboard/agents.html", user=user)


@dashboard_bp.route("/agent-monitor")
@require_login
def agent_monitor():
    """Agent Monitor - Deep single-agent telemetry viewer"""
    user = get_current_user()
    return render_template("dashboard/agent-monitor.html", user=user)


@dashboard_bp.route("/event-stream")
@require_login
def event_stream():
    """Event Stream — live firehose of all telemetry events"""
    user = get_current_user()
    return render_template("dashboard/event-stream.html", user=user)


@dashboard_bp.route("/probe-explorer")
@require_login
def probe_explorer():
    """Probe Explorer - Deep inspection of all micro-probes"""
    user = get_current_user()
    return render_template("dashboard/probe-explorer.html", user=user)


@dashboard_bp.route("/system")
@require_login
def system_monitoring():
    """System Health Monitoring - Platform Vitals"""
    user = get_current_user()
    return render_template("dashboard/system.html", user=user)


@dashboard_bp.route("/processes")
@require_login
def process_telemetry():
    """Process Telemetry Dashboard - Mac Process Monitoring"""
    user = get_current_user()
    return render_template("dashboard/processes.html", user=user)


@dashboard_bp.route("/peripherals")
@require_login
def peripheral_monitoring():
    """Peripheral Monitoring Dashboard - USB/Bluetooth Device Tracking"""
    user = get_current_user()
    return render_template("dashboard/peripherals.html", user=user)


@dashboard_bp.route("/database")
@require_login
def database_manager():
    """Database Manager - Zero-Trust Data Management"""
    user = get_current_user()
    return render_template("dashboard/database_manager.html", user=user)


@dashboard_bp.route("/my-agents")
@require_login
def my_agents():
    """User Agent Management - Deploy and Monitor Your Agents"""
    user = get_current_user()
    return render_template("dashboard/my-agents.html", user=user)


@dashboard_bp.route("/deploy")
@require_login
def deploy_agent():
    """Agent Deployment Portal - Download and Deploy"""
    user = get_current_user()
    return render_template("dashboard/deploy.html", user=user)


@dashboard_bp.route("/mitre")
@require_login
def mitre_coverage():
    """MITRE ATT&CK Coverage Heatmap"""
    user = get_current_user()
    return render_template("dashboard/mitre.html", user=user)


@dashboard_bp.route("/hunt")
@require_login
def threat_hunting():
    """Log Search / Threat Hunting Console"""
    user = get_current_user()
    return render_template("dashboard/hunt.html", user=user)


@dashboard_bp.route("/incidents")
@require_login
def incident_management():
    """Incident Management Dashboard"""
    user = get_current_user()
    return render_template("dashboard/incidents.html", user=user)


@dashboard_bp.route("/correlation")
@require_login
def correlation_dashboard():
    """SOMA Correlation — FusionEngine incidents, device risk, MITRE coverage"""
    user = get_current_user()
    return render_template("dashboard/correlation.html", user=user)


@dashboard_bp.route("/soma")
@require_login
def soma_dashboard():
    """SOMA — Architecture, scoring, agent reliability, learning"""
    user = get_current_user()
    return render_template("dashboard/soma.html", user=user)


@dashboard_bp.route("/soma/brain")
@require_login
def soma_brain_dashboard():
    """Redirect to unified SOMA Intelligence page (ML Models section)."""
    return redirect(url_for("dashboard.soma_dashboard") + "#ml-models")


@dashboard_bp.route("/network")
@require_login
def network_topology():
    """Network Topology Map"""
    user = get_current_user()
    return render_template("dashboard/network.html", user=user)


@dashboard_bp.route("/threat-feed")
@require_login
def threat_feed():
    """Live Threat Feed - Full-page threat analysis and triage"""
    user = get_current_user()
    return render_template("dashboard/threat-feed.html", user=user)


@dashboard_bp.route("/reliability")
@require_login
def reliability_dashboard():
    """Agent Reliability (AMRDR) - Drift detection and trust weights"""
    user = get_current_user()
    return render_template("dashboard/reliability.html", user=user)


@dashboard_bp.route("/igris")
@require_login
def igris_dashboard():
    """IGRIS — Autonomous Supervisory Intelligence Layer"""
    user = get_current_user()
    return render_template("dashboard/igris.html", user=user)


@dashboard_bp.route("/guardian")
@require_login
def guardian_dashboard():
    """Guardian C2 — Command & Control Terminal"""
    user = get_current_user()
    return render_template("dashboard/guardian.html", user=user)


# ── Observatory Pages ──


@dashboard_bp.route("/posture")
@require_login
def device_posture():
    """Device Posture — Single-screen device health overview"""
    user = get_current_user()
    return render_template("dashboard/posture.html", user=user)


@dashboard_bp.route("/dns")
@require_login
def dns_intelligence():
    """DNS Intelligence — DGA detection, beaconing, query analysis"""
    user = get_current_user()
    return render_template("dashboard/dns-intelligence.html", user=user)


@dashboard_bp.route("/file-integrity")
@require_login
def file_integrity():
    """File Integrity Monitor — Change tracking and risk analysis"""
    user = get_current_user()
    return render_template("dashboard/file-integrity.html", user=user)


@dashboard_bp.route("/persistence")
@require_login
def persistence_landscape():
    """Persistence Landscape — Autostart mechanism monitoring"""
    user = get_current_user()
    return render_template("dashboard/persistence-landscape.html", user=user)


@dashboard_bp.route("/auth")
@require_login
def auth_observatory():
    """Auth & Access — Login patterns and privilege escalation"""
    user = get_current_user()
    return render_template("dashboard/auth-observatory.html", user=user)


@dashboard_bp.route("/timeline-replay")
@require_login
def timeline_replay():
    """Threat Timeline Replay — step-by-step attack reconstruction"""
    user = get_current_user()
    return render_template("dashboard/timeline-replay.html", user=user)


@dashboard_bp.route("/observations")
@require_login
def observation_domains():
    """Observation Domains — P3 domain exploration"""
    user = get_current_user()
    return render_template("dashboard/observations.html", user=user)


# Normalize legacy agent names for display
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


# ── Dashboard-authenticated health summary (avoids health API auth issues) ──
@dashboard_bp.route("/api/health-summary")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def health_summary():
    """System health summary for Cortex Command Center.

    Returns agent counts, health score, threat level, and event statistics
    using dashboard session auth (same as all other dashboard endpoints).
    """
    import json as _json
    import sqlite3
    from pathlib import Path

    from .agent_discovery import AGENT_CATALOG, detect_agent_status, get_platform_name

    now = datetime.now(timezone.utc)
    project_root = Path(__file__).parent.parent.parent.parent

    # ── Agent counts (process detection + heartbeat fallback) ──
    agents_status = {}
    agents_details = []
    heartbeat_dir = project_root / "data" / "heartbeats"

    for agent_id, agent_config in AGENT_CATALOG.items():
        status = detect_agent_status(agent_config)
        if status["health"] == "online":
            agents_status[agent_id] = "running"
        elif status["health"] == "incompatible":
            agents_status[agent_id] = "incompatible"
        else:
            # Fallback: check heartbeat file (agent may not be a visible process)
            hb_name = agent_id.replace("_agent", "").replace("_", "")
            hb_candidates = [
                heartbeat_dir / f"{agent_id.replace('_agent', '')}.json",
                heartbeat_dir / f"{hb_name}.json",
                heartbeat_dir / f"{agent_id}.json",
            ]
            for hb_path in hb_candidates:
                if hb_path.exists():
                    try:
                        hb = _json.loads(hb_path.read_text())
                        hb_ts = hb.get("timestamp", "")
                        if hb_ts:
                            hb_dt = datetime.fromisoformat(hb_ts.replace("Z", "+00:00"))
                            age = (now - hb_dt).total_seconds()
                            if age < 600:  # Heartbeat within 10 minutes
                                agents_status[agent_id] = "running"
                                break
                    except Exception:
                        pass
            if agent_id not in agents_status:
                agents_status[agent_id] = "stopped"

        agents_details.append(
            {
                "id": agent_id,
                "name": agent_config["name"],
                "type": agent_config["type"],
                "status": agents_status[agent_id],
                "critical": agent_config.get("critical", False),
                "color": agent_config.get("color", "#00ff88"),
            }
        )

    agents_online = sum(1 for s in agents_status.values() if s == "running")
    agents_total = len([a for a in agents_status.values() if a != "incompatible"])

    # ── Event count (prefer pre-computed rollups, fall back to raw COUNT) ──
    events_24h = 0
    try:
        from .telemetry_bridge import get_telemetry_store

        _ev_store = get_telemetry_store()
        if _ev_store:
            rollup_counts = _ev_store.get_rollup_event_counts(hours=24)
            if rollup_counts:
                events_24h = sum(rollup_counts.values())
    except Exception:
        pass
    if events_24h == 0:
        # Fallback: direct COUNT queries (cold start before first rollup cycle)
        telemetry_db = project_root / "data" / "telemetry.db"
        if telemetry_db.exists():
            try:
                conn = sqlite3.connect(str(telemetry_db))
                cutoff_ns = int((now - timedelta(hours=24)).timestamp() * 1_000_000_000)
                for table in [
                    "security_events",
                    "process_events",
                    "flow_events",
                    "dns_events",
                    "persistence_events",
                    "fim_events",
                    "peripheral_events",
                    "audit_events",
                    "observation_events",
                ]:
                    try:
                        row = conn.execute(
                            f"SELECT COUNT(*) FROM {table} WHERE timestamp_ns > ?",
                            (cutoff_ns,),
                        ).fetchone()
                        events_24h += row[0]
                    except sqlite3.OperationalError:
                        pass
                conn.close()
            except Exception:
                pass

    # ── Threat level — unified from posture (risk-based) + fusion (incident-based) ──
    # Posture provides continuous risk assessment; fusion provides confirmed incidents.
    # Use the worse of the two so the dashboard never underreports.
    posture_threat = "clear"
    posture_score = 100.0
    posture_model = "legacy"
    try:
        from .telemetry_bridge import get_telemetry_store

        _store = get_telemetry_store()
        if _store:
            _posture = _store.compute_nerve_posture(hours=24)
            posture_threat = _posture.get("threat_level", "clear")
            posture_score = _posture.get("posture_score", 100.0)
            posture_model = _posture.get("model", "nerve_signal_v1")
    except Exception:
        pass

    fusion_threat = "clear"
    fusion_db = project_root / "data" / "intel" / "fusion.db"
    if fusion_db.exists():
        try:
            conn = sqlite3.connect(str(fusion_db))
            cutoff = (now - timedelta(hours=1)).isoformat()
            try:
                row = conn.execute(
                    """SELECT severity FROM incidents
                       WHERE created_at > ?
                       ORDER BY CASE severity
                         WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                         WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5
                       END LIMIT 1""",
                    (cutoff,),
                ).fetchone()
                if row:
                    fusion_threat = row[0]
            except sqlite3.OperationalError:
                pass
            conn.close()
        except Exception:
            pass

    # Severity ordering for comparison (includes Nerve Signal levels)
    _THREAT_ORDER = {
        "clear": 0,
        "low": 1,
        "guarded": 2,
        "medium": 2,
        "elevated": 3,
        "high": 4,
        "critical": 5,
    }
    threat_level = max(
        [posture_threat.lower(), fusion_threat.lower()],
        key=lambda t: _THREAT_ORDER.get(t, 0),
    ).upper()

    # ── Data freshness — how stale is the data? ──
    data_age_seconds = None
    last_event_time = None
    try:
        telemetry_db = project_root / "data" / "telemetry.db"
        if telemetry_db.exists():
            conn = sqlite3.connect(str(telemetry_db), timeout=2)
            row = conn.execute(
                "SELECT MAX(event_timestamp_ns) FROM security_events"
            ).fetchone()
            if row and row[0]:
                last_event_time = row[0]
            if not last_event_time:
                row = conn.execute(
                    "SELECT MAX(timestamp_ns) FROM observation_events"
                ).fetchone()
                if row and row[0]:
                    last_event_time = row[0]
            conn.close()
            if last_event_time:
                data_age_seconds = round(
                    time.time() - (last_event_time / 1_000_000_000), 1
                )
    except Exception:
        pass

    # ── Health score — operational health (are agents running and collecting?) ──
    infra_ok = agents_online > 0 or events_24h > 0
    agent_score = (agents_online / max(agents_total, 1)) * 40
    infra_score = 40 if infra_ok else 0
    activity_score = 20 if events_24h > 0 else 10
    health_score = int(agent_score + infra_score + activity_score)

    freshness = "live"
    if data_age_seconds is None:
        freshness = "no_data"
    elif data_age_seconds > 300:
        freshness = "stale"
    elif data_age_seconds > 60:
        freshness = "delayed"

    return jsonify(
        {
            "status": "success",
            "timestamp": now.isoformat(),
            "platform": get_platform_name(),
            "agents": agents_status,
            "agents_details": agents_details,
            "agents_summary": {
                "online": agents_online,
                "total": agents_total,
                "coverage_percent": round(
                    (agents_online / max(agents_total, 1)) * 100, 1
                ),
            },
            "threat_level": threat_level,
            "posture_score": posture_score,
            "posture_model": posture_model,
            "events_last_24h": events_24h,
            "health_score": health_score,
            "health_status": (
                "healthy"
                if health_score >= 70
                else "degraded" if health_score >= 40 else "critical"
            ),
            "data_freshness": {
                "age_seconds": data_age_seconds,
                "status": freshness,
                "label": (
                    f"data as of {int(data_age_seconds)}s ago"
                    if data_age_seconds is not None
                    else "no data yet"
                ),
            },
        }
    )


# Real-time Data Endpoints
@dashboard_bp.route("/api/live/threats")
@require_login
@require_rate_limit(max_requests=100, window_seconds=60)
def live_threats():
    """Real-time threat feed from TelemetryStore."""
    from .telemetry_bridge import get_telemetry_store

    now = datetime.now(timezone.utc)
    store = get_telemetry_store()

    if store is None:
        return jsonify(
            {
                "status": "success",
                "threats": [],
                "count": 0,
                "timestamp": now.isoformat(),
            }
        )

    try:
        hours = min(int(request.args.get("hours", 24)), 8760)
    except (ValueError, TypeError):
        hours = 24

    # Pagination params
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1
    try:
        per_page = min(max(10, int(request.args.get("per_page", 50))), 200)
    except (ValueError, TypeError):
        per_page = 50
    offset = (page - 1) * per_page

    # DB-level aggregate counts across ALL domain tables
    counts = store.get_unified_event_counts(hours=hours)
    clustering = store.get_security_event_clustering(hours=hours)
    # Fast threat-only count (events with risk > threshold)
    _threat_min = 0.1

    # Unified query — filter to actual detections (risk > 0.1) for threat feed
    min_risk = 0.1
    try:
        min_risk = float(request.args.get("min_risk", 0.1))
    except (ValueError, TypeError):
        pass
    rows = store.get_unified_threat_events(
        limit=per_page, hours=hours, offset=offset, min_risk=min_risk
    )
    data_stale = False
    if not rows and page == 1:
        rows = store.get_unified_threat_events(limit=50, hours=8760, min_risk=0.0)
        data_stale = bool(rows)
    recent_events = []
    for row in rows:
        # Extract source_ip from indicators JSON if available
        indicators = _parse_indicators(row.get("indicators"))

        source_ip = ""
        if isinstance(indicators, dict):
            source_ip = indicators.get("source_ip") or indicators.get("src_ip") or ""
            # Extract first remote IP from public_connections if present
            if not indicators.get("dst_ip") and not indicators.get("remote_ip"):
                conns = indicators.get("public_connections")
                if isinstance(conns, list) and conns:
                    first_remote = conns[0].get("remote_ip", "")
                    if first_remote:
                        indicators["remote_ip"] = first_remote
                        if len(conns) > 1:
                            indicators["remote_ip_count"] = len(conns)

        # Parse MITRE techniques
        mitre = _parse_mitre(row.get("mitre_techniques"))

        # Resolve agent name with normalization
        agent_raw = ""
        if isinstance(indicators, dict):
            agent_raw = indicators.get("agent", "")
        agent_raw = agent_raw or row.get("collection_agent") or ""
        agent_name = _normalize_agent_id(agent_raw)
        device_id = row.get("device_id", "")
        confidence = round(row.get("confidence", 0) or 0, 3)
        risk_score = round(row.get("risk_score", 0) or 0, 3)
        source_table = row.get("source", "security")

        recent_events.append(
            {
                "id": row.get("id"),
                "source": source_table,
                "type": row.get("type") or row.get("event_category", "unknown"),
                "severity": _risk_to_severity(risk_score),
                "risk_score": risk_score,
                "confidence": confidence,
                "source_ip": source_ip,
                "description": row.get("description", ""),
                "timestamp": row.get("timestamp_dt", ""),
                "agent_name": agent_name,
                "device_id": device_id,
                "agent_id": agent_name or device_id,
                "classification": row.get("final_classification", ""),
                "mitre_techniques": mitre,
                "requires_investigation": bool(
                    row.get("requires_investigation", False)
                ),
                "event_action": row.get("event_action", ""),
                "indicators": indicators,
            }
        )

    # Deduplicate: same (source_table, id) pair means exact DB duplicate
    seen_pks: set = set()
    deduped: list = []
    for e in recent_events:
        pk = f"{e.get('source', '')}:{e.get('id', '')}"
        if pk not in seen_pks:
            seen_pks.add(pk)
            deduped.append(e)
    recent_events = deduped

    # Count events requiring investigation
    investigating_count = sum(1 for e in recent_events if e["requires_investigation"])

    # Determine when the most recent event occurred
    last_event_time = recent_events[0]["timestamp"] if recent_events else None

    # Aggregate stats: false-positive rate, avg confidence
    legit_count = sum(1 for e in recent_events if e["classification"] == "legitimate")
    fp_rate = round(legit_count / len(recent_events), 3) if recent_events else 0
    confidences = [e["confidence"] for e in recent_events if e["confidence"] > 0]
    avg_confidence = round(sum(confidences) / len(confidences), 3) if confidences else 0

    db_total = counts.get("total", 0)
    threat_total = store.get_threat_count(hours=hours, min_risk=min_risk)
    total_pages = max(1, -(-threat_total // per_page))  # ceil division

    return jsonify(
        {
            "status": "success",
            "threats": recent_events,
            "count": len(recent_events),
            "db_total": db_total,
            "threat_total": threat_total,
            "by_source": counts.get("by_source", {}),
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
            "db_by_classification": counts.get("by_classification", {}),
            "db_by_severity": clustering.get("by_severity", {}),
            "investigating_count": investigating_count,
            "fp_rate": fp_rate,
            "avg_confidence": avg_confidence,
            "data_stale": data_stale,
            "last_event_time": last_event_time,
            "timestamp": now.isoformat(),
        }
    )


def _risk_to_severity(risk_score: float) -> str:
    """Map a 0.0-1.0 risk score to a severity string."""
    if risk_score >= 0.75:
        return "critical"
    elif risk_score >= 0.5:
        return "high"
    elif risk_score >= 0.25:
        return "medium"
    return "low"


@dashboard_bp.route("/api/live/unified-events")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def unified_events():
    """Truly unified event stream across ALL domain tables.

    Queries security_events, process_events, flow_events, dns_events,
    persistence_events, and fim_events — merges into a single sorted stream.

    Query params:
        hours: Time window (default 24)
        limit: Max results (default 100)
        offset: Skip N results (default 0)
        agent: Filter by agent name
        severity: Filter by severity (critical, high, medium, low)
        search: Text search on event_category and description
        hour: Filter by specific hour (ISO format)
        domain: Filter by event domain (process, flow, dns, fim, persistence,
                security, audit, peripheral, observation)
    """
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    if store is None:
        return jsonify({"events": [], "total": 0})

    try:
        hours = min(int(request.args.get("hours", 24)), 8760)
    except (ValueError, TypeError):
        hours = 24
    try:
        limit = min(max(1, int(request.args.get("limit", 100))), 500)
    except (ValueError, TypeError):
        limit = 100
    try:
        offset = max(0, int(request.args.get("offset", 0)))
    except (ValueError, TypeError):
        offset = 0

    agent_filter = request.args.get("agent", "")
    severity_filter = request.args.get("severity", "")
    search_filter = request.args.get("search", "")
    hour_filter = request.args.get("hour", "")
    domain_filter = request.args.get("domain", "")
    cutoff_ns = int((time.time() - hours * 3600) * 1e9)

    # Severity filter ranges
    sev_lo, sev_hi = 0.0, 1.01
    if severity_filter:
        sev_ranges = {
            "critical": (0.75, 1.01),
            "high": (0.50, 0.75),
            "medium": (0.25, 0.50),
            "low": (0.0, 0.25),
        }
        if severity_filter.lower() in sev_ranges:
            sev_lo, sev_hi = sev_ranges[severity_filter.lower()]

    # Hour filter
    hour_start_ns, hour_end_ns = None, None
    if hour_filter:
        try:
            hour_dt = datetime.fromisoformat(hour_filter.replace("Z", "+00:00"))
            hour_start_ns = int(hour_dt.timestamp() * 1e9)
            hour_end_ns = hour_start_ns + int(3600 * 1e9)
        except ValueError:
            pass

    # Normalize agent filter
    norm_agent = _normalize_agent_id(agent_filter) if agent_filter else ""

    # Domain filter → set of source_table names to include
    # Maps domain pill values to the source_table names used by _query_table_* functions
    _domain_to_tables = {
        "process": {"process"},
        "flow": {"flow"},
        "dns": {"dns"},
        "fim": {"fim"},
        "persistence": {"persistence"},
        "security": {"security"},
        "audit": {"security"},
        "peripheral": {"security"},
        "observation": {"security"},
    }
    domain_tables = _domain_to_tables.get(domain_filter) if domain_filter else None

    def _include_table(table_name):
        """Check if a table should be queried given domain filter."""
        if domain_tables is None:
            return True
        return table_name in domain_tables

    try:
        all_events = []

        with store._lock:
            # ── 1. security_events ──
            if _include_table("security"):
                all_events.extend(
                    _query_table_security(
                        store,
                        cutoff_ns,
                        norm_agent,
                        sev_lo,
                        sev_hi,
                        search_filter,
                        hour_start_ns,
                        hour_end_ns,
                    )
                )

            # ── 2. process_events ──
            if (not norm_agent or norm_agent == "proc") and _include_table("process"):
                all_events.extend(
                    _query_table_process(
                        store,
                        cutoff_ns,
                        sev_lo,
                        sev_hi,
                        search_filter,
                        hour_start_ns,
                        hour_end_ns,
                    )
                )

            # ── 3. flow_events ──
            if (not norm_agent or norm_agent == "flow") and _include_table("flow"):
                all_events.extend(
                    _query_table_flow(
                        store,
                        cutoff_ns,
                        sev_lo,
                        sev_hi,
                        search_filter,
                        hour_start_ns,
                        hour_end_ns,
                    )
                )

            # ── 4. dns_events ──
            if (not norm_agent or norm_agent == "dns") and _include_table("dns"):
                all_events.extend(
                    _query_table_dns(
                        store,
                        cutoff_ns,
                        sev_lo,
                        sev_hi,
                        search_filter,
                        hour_start_ns,
                        hour_end_ns,
                    )
                )

            # ── 5. persistence_events ──
            if (not norm_agent or norm_agent == "persistence") and _include_table(
                "persistence"
            ):
                all_events.extend(
                    _query_table_persistence(
                        store,
                        cutoff_ns,
                        sev_lo,
                        sev_hi,
                        search_filter,
                        hour_start_ns,
                        hour_end_ns,
                    )
                )

            # ── 6. fim_events ──
            if (not norm_agent or norm_agent == "fim") and _include_table("fim"):
                all_events.extend(
                    _query_table_fim(
                        store,
                        cutoff_ns,
                        sev_lo,
                        sev_hi,
                        search_filter,
                        hour_start_ns,
                        hour_end_ns,
                    )
                )

        # Post-filter for domain types that share the security_events table
        if domain_filter in ("audit", "peripheral", "observation"):
            _domain_agent_prefixes = {
                "audit": ("auth", "audit"),
                "peripheral": ("peripheral", "periph", "usb"),
                "observation": (
                    "obs",
                    "infostealer",
                    "quarantine",
                    "provenance",
                    "network_sentinel",
                ),
            }
            prefixes = _domain_agent_prefixes[domain_filter]
            all_events = [
                ev
                for ev in all_events
                if any(
                    (ev.get("agent") or "").lower().startswith(p)
                    or (ev.get("event_category") or "").lower().startswith(p)
                    for p in prefixes
                )
            ]

        # Sort all events by timestamp descending, paginate
        all_events.sort(key=lambda e: e.get("_sort_ts", 0), reverse=True)
        total = len(all_events)
        page = all_events[offset : offset + limit]

        # Strip internal sort key
        for ev in page:
            ev.pop("_sort_ts", None)

        return jsonify({"events": page, "total": total})
    except Exception as e:
        return jsonify({"events": [], "total": 0, "error": str(e)})


def _parse_mitre(raw):
    """Parse mitre_techniques from DB value."""
    parsed = _parse_nested_json(raw, [])
    if isinstance(parsed, str):
        parsed = parsed.strip()
        return [parsed] if parsed else []
    if not isinstance(parsed, list):
        return []
    return [item.strip() for item in parsed if isinstance(item, str) and item.strip()]


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


def _parse_indicators(raw):
    """Parse indicators JSON into a dict, unwrapping double-encoded payloads."""
    parsed = _parse_nested_json(raw, {})
    return parsed if isinstance(parsed, dict) else {}


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


@dashboard_bp.route("/api/live/agents")
@require_login
@require_rate_limit(max_requests=100, window_seconds=60)
def live_agents():
    """Real-time agent status for dashboard with actual process detection"""
    from .agent_discovery import get_all_agents_status

    agent_data = get_all_agents_status()

    # Format for dashboard consumption
    agents_formatted = []
    for agent in agent_data["agents"]:
        # Determine uptime from first process if running
        uptime_seconds = 0
        if agent["processes"]:
            uptime_seconds = agent["processes"][0]["uptime_seconds"]

        agents_formatted.append(
            {
                "agent_id": agent["agent_id"],
                "hostname": agent.get("name", agent["agent_id"]),
                "status": agent["status"],
                "status_color": agent.get("color", "#00ff88"),
                "last_seen": agent["last_check"],
                "last_heartbeat": agent["last_check"],
                "seconds_since_ping": 0 if agent["running"] else 999999,
                "platform": agent_data["platform"],
                "capabilities": agent["capabilities"],
                "running": agent["running"],
                "instances": agent["instances"],
                "monitors": agent["monitors"],
                "neurons": agent["neurons"],
                "blockers": agent["blockers"],
                "warnings": agent["warnings"],
                "uptime_seconds": uptime_seconds,
                "critical": agent["critical"],
            }
        )

    return jsonify(
        {
            "status": "success",
            "agents": agents_formatted,
            "total_agents": len(agents_formatted),
            "summary": agent_data["summary"],
            "timestamp": agent_data["timestamp"],
        }
    )


@dashboard_bp.route("/api/available-agents")
@require_login
def available_agents():
    """List available agent types that can be deployed on this platform"""
    from .agent_discovery import get_available_agents, get_platform_name

    available_agents_list = get_available_agents()
    current_time = datetime.now(timezone.utc)

    return jsonify(
        {
            "status": "success",
            "platform": get_platform_name(),
            "agents": available_agents_list,
            "count": len(available_agents_list),
            "timestamp": current_time.isoformat(),
        }
    )


@dashboard_bp.route("/api/device-info")
@require_login
@require_rate_limit(max_requests=30, window_seconds=60)
def device_info():
    """Device and OS information for the monitored host."""
    import platform as _platform
    import socket as _socket

    try:
        return jsonify(
            {
                "status": "success",
                "system": {
                    "hostname": _socket.gethostname(),
                    "platform": _platform.platform(),
                    "system": _platform.system(),
                    "release": _platform.release(),
                    "architecture": list(_platform.architecture()),
                    "processor": _platform.processor(),
                },
            }
        )
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@dashboard_bp.route("/api/live/metrics")
@require_login
@require_rate_limit(max_requests=100, window_seconds=60)
def live_metrics():
    """Real-time system metrics for dashboard"""
    import psutil

    try:
        # System metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage("/")

        # Network I/O
        network = psutil.net_io_counters()

        # Process info
        process = psutil.Process()

        metrics = {
            "cpu": {
                "percent": cpu_percent,
                "count": psutil.cpu_count(),
                "cores": psutil.cpu_count(),
                "status": (
                    "healthy"
                    if cpu_percent < 80
                    else ("warning" if cpu_percent < 90 else "critical")
                ),
            },
            "memory": {
                "percent": memory.percent,
                "used_gb": memory.used / (1024**3),
                "total_gb": memory.total / (1024**3),
                "available_gb": memory.available / (1024**3),
                "status": (
                    "healthy"
                    if memory.percent < 80
                    else ("warning" if memory.percent < 90 else "critical")
                ),
            },
            "disk": {
                "percent": (disk.used / disk.total) * 100,
                "used_gb": disk.used / (1024**3),
                "total_gb": disk.total / (1024**3),
                "status": (
                    "healthy"
                    if (disk.used / disk.total * 100) < 80
                    else (
                        "warning" if (disk.used / disk.total * 100) < 90 else "critical"
                    )
                ),
            },
            "network": {
                "bytes_sent": network.bytes_sent,
                "bytes_recv": network.bytes_recv,
                "bytes_sent_mb": network.bytes_sent / (1024**2),
                "bytes_recv_mb": network.bytes_recv / (1024**2),
                "packets_sent": network.packets_sent,
                "packets_recv": network.packets_recv,
            },
            "process": {
                "memory_percent": process.memory_percent(),
                "cpu_percent": process.cpu_percent(),
                "threads": process.num_threads(),
                "status": "running",
            },
        }

        # Persist to metrics_timeseries (fire-and-forget, max once per 30s)
        try:
            from .telemetry_bridge import get_telemetry_store

            _store = get_telemetry_store()
            if _store and (time.time() - _metrics_last_store[0]) > 30:
                _metrics_last_store[0] = time.time()
                now_ns = int(time.time() * 1e9)
                now_dt = datetime.now(timezone.utc).isoformat()
                for name, val in [
                    ("cpu_percent", cpu_percent),
                    ("memory_percent", memory.percent),
                    ("disk_percent", (disk.used / disk.total) * 100),
                    ("net_bytes_sent", network.bytes_sent),
                    ("net_bytes_recv", network.bytes_recv),
                ]:
                    _store.insert_metrics_timeseries(
                        {
                            "timestamp_ns": now_ns,
                            "timestamp_dt": now_dt,
                            "metric_name": name,
                            "metric_type": "GAUGE",
                            "device_id": "local",
                            "value": val,
                            "unit": "%" if "percent" in name else "bytes",
                        }
                    )
        except Exception:
            pass

        return jsonify(
            {
                "status": "success",
                "metrics": metrics,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "error": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ),
            500,
        )


# Throttle for metrics persistence
_metrics_last_store = [0.0]


@dashboard_bp.route("/api/live/threat-score")
@require_login
def live_threat_score():
    """Real-time threat score from TelemetryStore."""
    from .telemetry_bridge import get_telemetry_store

    now = datetime.now(timezone.utc)
    store = get_telemetry_store()

    if store is None:
        return jsonify(
            {
                "status": "success",
                "threat_score": 0,
                "threat_level": "LOW",
                "threat_color": "#00ff88",
                "event_count": 0,
                "timestamp": now.isoformat(),
            }
        )

    hours = request.args.get("hours", 24, type=int)
    data = store.get_threat_score_data(hours=hours)
    threat_score = int(data.get("threat_score", 0))
    threat_level = data.get("threat_level", "none").upper()

    color_map = {
        "CRITICAL": "#ff0000",
        "HIGH": "#ff6600",
        "MEDIUM": "#ffaa00",
        "LOW": "#00ff88",
        "NONE": "#00ff88",
    }

    return jsonify(
        {
            "status": "success",
            "threat_score": threat_score,
            "threat_level": threat_level,
            "threat_color": color_map.get(threat_level, "#00ff88"),
            "event_count": data.get("event_count", 0),
            "timestamp": now.isoformat(),
        }
    )


@dashboard_bp.route("/api/live/event-clustering")
@require_login
def event_clustering():
    """Event clustering data from TelemetryStore."""
    from .telemetry_bridge import get_telemetry_store

    now = datetime.now(timezone.utc)
    store = get_telemetry_store()

    if store is None:
        return jsonify(
            {
                "status": "success",
                "clusters": {
                    "by_type": {},
                    "by_severity": {},
                    "by_source_ip": {},
                    "by_agent": {},
                    "by_hour": {},
                },
                "timestamp": now.isoformat(),
            }
        )

    try:
        hours = min(int(request.args.get("hours", 24)), 8760)
    except (ValueError, TypeError):
        hours = 24
    data = store.get_unified_event_clustering(hours=hours)

    # Extract top source IPs from security_events + flow_events
    by_source_ip: dict = {}
    try:
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with store._read_pool.connection() as rdb:
            # Security events: JSON indicators (cap scan to 1000 recent)
            cursor = rdb.execute(
                """SELECT ip, COUNT(*) as cnt FROM (
                    SELECT COALESCE(
                        JSON_EXTRACT(indicators, '$.source_ip'),
                        JSON_EXTRACT(indicators, '$.src_ip'),
                        JSON_EXTRACT(indicators, '$.dst_ip')
                    ) AS ip
                    FROM security_events
                    WHERE timestamp_ns > ? AND indicators IS NOT NULL
                    ORDER BY timestamp_ns DESC LIMIT 1000
                ) WHERE ip IS NOT NULL
                GROUP BY ip ORDER BY cnt DESC LIMIT 50""",
                (cutoff_ns,),
            )
            for row in cursor.fetchall():
                by_source_ip[row[0]] = row[1]
            # Flow events: use indexed src_ip/dst_ip with LIMIT
            cursor = rdb.execute(
                """SELECT ip, COUNT(*) FROM (
                    SELECT src_ip AS ip FROM flow_events
                    WHERE timestamp_ns > ? AND src_ip IS NOT NULL
                    ORDER BY timestamp_ns DESC LIMIT 5000
                    UNION ALL
                    SELECT dst_ip FROM flow_events
                    WHERE timestamp_ns > ? AND dst_ip IS NOT NULL
                    ORDER BY timestamp_ns DESC LIMIT 5000
                ) WHERE ip IS NOT NULL
                GROUP BY ip ORDER BY COUNT(*) DESC LIMIT 50""",
                (cutoff_ns, cutoff_ns),
            )
            for row in cursor.fetchall():
                by_source_ip[row[0]] = by_source_ip.get(row[0], 0) + row[1]
    except Exception:
        pass

    # Normalize agent IDs in by_agent
    raw_by_agent = data.get("by_agent", {})
    normalized_by_agent: dict = {}
    for raw_id, count in raw_by_agent.items():
        canonical = _normalize_agent_id(raw_id)
        normalized_by_agent[canonical] = normalized_by_agent.get(canonical, 0) + count

    clusters = {
        "by_type": data.get("by_source", {}),
        "by_severity": data.get("by_severity", {}),
        "by_source_ip": by_source_ip,
        "by_agent": normalized_by_agent,
        "by_hour": data.get("by_hour", {}),
    }

    return jsonify(
        {"status": "success", "clusters": clusters, "timestamp": now.isoformat()}
    )


_probe_health_cache = {"data": None, "ts": 0}


@dashboard_bp.route("/api/live/probe-health")
@require_login
def live_probe_health():
    """Probe coverage metrics from Observability Contract audit (60s cache)."""
    import platform as _platform

    now_ts = time.time()

    if _probe_health_cache["data"] and (now_ts - _probe_health_cache["ts"]) < 60:
        return jsonify(_probe_health_cache["data"])

    try:
        from amoskys.observability.probe_audit import run_audit, summarize_audit

        target = "darwin" if _platform.system() == "Darwin" else "linux"
        results = run_audit(target)
        summary = summarize_audit(results)

        response = {
            "status": "success",
            "summary": summary,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        _probe_health_cache["data"] = response
        _probe_health_cache["ts"] = now_ts
        return jsonify(response)
    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ),
            500,
        )


@dashboard_bp.route("/api/neural/readiness")
@require_login
def neural_readiness():
    """Neural engine readiness assessment"""
    from .utils import get_neural_readiness_status

    try:
        readiness_data = get_neural_readiness_status()

        return jsonify(
            {
                "status": "success",
                "readiness": readiness_data,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ),
            500,
        )


@dashboard_bp.route("/api/platform-capabilities", methods=["GET"])
@require_login
@require_rate_limit(max_requests=30, window_seconds=60)
def platform_capabilities():
    """Static platform capabilities from AGENT_REGISTRY + probe definitions."""
    import platform as _platform

    from .capabilities import (
        get_agent_capabilities_summary,
        get_declared_mitre_coverage,
    )

    target = "darwin" if _platform.system() == "Darwin" else "linux"
    agents = get_agent_capabilities_summary(target)
    mitre = get_declared_mitre_coverage(target)

    return jsonify(
        {
            "status": "success",
            "platform": target,
            "agents": agents,
            "total_agents": len(agents),
            "total_probes": sum(a["probe_count"] for a in agents),
            "mitre": mitre,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


# Agent Control Endpoints (Phase 8)
@dashboard_bp.route("/api/agents/status", methods=["GET"])
@require_login
@require_rate_limit(max_requests=100, window_seconds=60)
def agents_detailed_status():
    """Get detailed status of all agents with health checks"""
    from .agent_control import get_all_agents_status_detailed

    try:
        status_data = get_all_agents_status_detailed()
        return jsonify(
            {
                "status": "success",
                "data": status_data,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ),
            500,
        )


@dashboard_bp.route("/api/agents/<agent_id>/status", methods=["GET"])
@require_login
@require_rate_limit(max_requests=100, window_seconds=60)
def agent_status(agent_id):
    """Get detailed status of a specific agent"""
    from .agent_control import get_agent_status

    try:
        status = get_agent_status(agent_id)
        return jsonify(
            {
                "status": "success",
                "data": status,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ),
            500,
        )


@dashboard_bp.route("/api/agents/<agent_id>/start", methods=["POST"])
@require_login
@require_rate_limit(max_requests=20, window_seconds=60)
def start_agent(agent_id):
    """Start a stopped agent"""
    from .agent_control import start_agent as start_agent_fn

    try:
        result = start_agent_fn(agent_id)
        status_code = (
            200 if result.get("status") in ("started", "already_running") else 400
        )
        return jsonify(result), status_code
    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "agent_id": agent_id,
                    "message": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ),
            500,
        )


@dashboard_bp.route("/api/agents/<agent_id>/stop", methods=["POST"])
@require_login
@require_rate_limit(max_requests=20, window_seconds=60)
def stop_agent(agent_id):
    """Stop a running agent"""
    from .agent_control import stop_agent as stop_agent_fn

    try:
        result = stop_agent_fn(agent_id)
        status_code = (
            200
            if result.get("status") in ("stopped", "force_killed", "not_running")
            else 400
        )
        return jsonify(result), status_code
    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "agent_id": agent_id,
                    "message": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ),
            500,
        )


@dashboard_bp.route("/api/agents/<agent_id>/health", methods=["GET"])
@require_login
@require_rate_limit(max_requests=100, window_seconds=60)
def agent_health_check(agent_id):
    """Perform health check on a specific agent"""
    from .agent_control import health_check_agent

    try:
        health = health_check_agent(agent_id)
        status_code = 200 if health.get("healthy") else 400
        return (
            jsonify(
                {
                    "status": "success",
                    "data": health,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ),
            status_code,
        )
    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ),
            500,
        )


@dashboard_bp.route("/api/agents/<agent_id>/logs", methods=["GET"])
@require_login
@require_rate_limit(max_requests=50, window_seconds=60)
def agent_logs(agent_id):
    """Get startup logs for an agent"""
    from .agent_control import get_startup_logs

    lines = request.args.get("lines", default=50, type=int)

    try:
        logs = get_startup_logs(agent_id, lines=min(lines, 500))
        return jsonify(
            {
                "status": "success",
                "data": logs,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ),
            500,
        )


@dashboard_bp.route("/api/agents/restart-all", methods=["POST"])
@require_login
@require_rate_limit(max_requests=5, window_seconds=60)
def restart_all_agents():
    """Restart all agents (with proper shutdown and restart)"""
    from .agent_control import start_agent as start_agent_fn
    from .agent_control import stop_agent as stop_agent_fn
    from .agent_discovery import AGENT_CATALOG

    try:
        results = {
            "total": len(AGENT_CATALOG),
            "stopped": 0,
            "started": 0,
            "failed": 0,
            "agents": {},
        }

        # First, stop all running agents
        for agent_id in AGENT_CATALOG:
            stop_result = stop_agent_fn(agent_id)
            if stop_result.get("status") in ("stopped", "force_killed", "not_running"):
                results["stopped"] += 1
            results["agents"][agent_id] = {"stopped": stop_result.get("status")}

        # Wait a moment between shutdown and startup
        time.sleep(2)

        # Then, start all agents (infrastructure first, then security)
        import platform as _plat

        current = _plat.system().lower()
        infra_first = sorted(
            AGENT_CATALOG.items(),
            key=lambda x: (0 if x[1].get("critical") else 1),
        )
        for agent_id, config in infra_first:
            if current not in config.get("platform", []):
                continue
            start_result = start_agent_fn(agent_id)
            if start_result.get("status") in ("started", "already_running"):
                results["started"] += 1
            else:
                results["failed"] += 1
            results["agents"].setdefault(agent_id, {})
            results["agents"][agent_id]["started"] = start_result.get("status")

        return jsonify(
            {
                "status": "success",
                "data": results,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ),
            500,
        )


# ── Pipeline Start API ────────────────────────────────────────────


@dashboard_bp.route("/api/pipeline/start", methods=["POST"])
@require_login
@require_rate_limit(max_requests=5, window_seconds=60)
def start_entire_pipeline():
    """Start the entire AMOSKYS pipeline in dependency order.

    Order: EventBus → WAL Processor → All security agents.
    Each infrastructure component waits for confirmation before proceeding.
    """
    from .agent_control import start_agent as start_agent_fn
    from .agent_discovery import AGENT_CATALOG

    try:
        results = {
            "phase": [],
            "started": 0,
            "failed": 0,
            "skipped": 0,
            "agents": {},
        }

        # Phase 1: Infrastructure (EventBus, WAL Processor) — order matters
        infra_ids = ["eventbus", "wal_processor"]
        for agent_id in infra_ids:
            if agent_id not in AGENT_CATALOG:
                continue
            r = start_agent_fn(agent_id)
            status = r.get("status")
            results["agents"][agent_id] = r
            if status in ("started", "already_running"):
                results["started"] += 1
            else:
                results["failed"] += 1
        results["phase"].append({"name": "infrastructure", "agents": infra_ids})

        # Brief pause for infra to initialize
        time.sleep(2)

        # Phase 2: All security agents
        security_ids = [aid for aid in AGENT_CATALOG if aid not in infra_ids]
        for agent_id in security_ids:
            cfg = AGENT_CATALOG[agent_id]
            # Skip agents not for this platform
            import platform as _plat

            current = _plat.system().lower()
            if current not in cfg.get("platform", []):
                results["skipped"] += 1
                continue
            r = start_agent_fn(agent_id)
            status = r.get("status")
            results["agents"][agent_id] = r
            if status in ("started", "already_running"):
                results["started"] += 1
            else:
                results["failed"] += 1
        results["phase"].append({"name": "security_agents", "agents": security_ids})

        return jsonify(
            {
                "status": "success",
                "message": (
                    f"Pipeline started: {results['started']} running, "
                    f"{results['failed']} failed, {results['skipped']} skipped"
                ),
                "data": results,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ),
            500,
        )


@dashboard_bp.route("/api/pipeline/stop", methods=["POST"])
@require_login
@require_rate_limit(max_requests=5, window_seconds=60)
def stop_entire_pipeline():
    """Stop the entire AMOSKYS pipeline in reverse dependency order."""
    from .agent_control import stop_agent as stop_agent_fn
    from .agent_discovery import AGENT_CATALOG

    try:
        results = {"stopped": 0, "failed": 0, "agents": {}}

        # Phase 1: Stop security agents first
        infra_ids = {"eventbus", "wal_processor"}
        for agent_id in AGENT_CATALOG:
            if agent_id in infra_ids:
                continue
            r = stop_agent_fn(agent_id)
            results["agents"][agent_id] = r
            if r.get("status") in ("stopped", "force_killed", "not_running"):
                results["stopped"] += 1

        time.sleep(1)

        # Phase 2: Stop infrastructure (reverse order)
        for agent_id in reversed(list(infra_ids)):
            r = stop_agent_fn(agent_id)
            results["agents"][agent_id] = r
            if r.get("status") in ("stopped", "force_killed", "not_running"):
                results["stopped"] += 1

        return jsonify(
            {
                "status": "success",
                "message": f"Pipeline stopped: {results['stopped']} components",
                "data": results,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ),
            500,
        )


# ── New Feature APIs ──────────────────────────────────────────────


@dashboard_bp.route("/api/mitre/coverage")
@require_login
@require_rate_limit(max_requests=30, window_seconds=60)
def mitre_coverage_data():
    """MITRE ATT&CK technique coverage: declared (from probes) + detected (from events)."""
    import platform as _platform

    from .capabilities import get_declared_mitre_coverage
    from .telemetry_bridge import get_telemetry_store

    target = "darwin" if _platform.system() == "Darwin" else "linux"
    declared = get_declared_mitre_coverage(target)

    store = get_telemetry_store()
    detected = {}
    if store:
        try:
            detected = store.get_mitre_coverage()
        except Exception:
            pass

    return jsonify(
        {
            "status": "success",
            "declared": declared,
            "detected": detected,
            "by_tactic": declared.get("by_tactic", {}),
            "coverage": detected,  # backward compat
            "total_techniques": declared.get("technique_count", 0),
            "total_detected": len(detected),
            "total_hits": sum(v.get("count", 0) for v in detected.values()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


@dashboard_bp.route("/api/hunt/search")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def hunt_search():
    """Log search / threat hunting endpoint."""
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    if store is None:
        return jsonify(
            {"status": "success", "results": [], "total_count": 0, "has_more": False}
        )

    query = request.args.get("q", "")
    ALLOWED_TABLES = {
        "security_events",
        "process_events",
        "flow_events",
        "dns_events",
        "fim_events",
        "audit_events",
        "persistence_events",
        "peripheral_events",
        "observation_events",
    }
    table = request.args.get("table", "security_events")
    if table not in ALLOWED_TABLES:
        return jsonify({"status": "error", "message": "Invalid table name"}), 400
    hours = request.args.get("hours", 24, type=int)
    limit = min(request.args.get("limit", 50, type=int), 200)
    offset = request.args.get("offset", 0, type=int)
    min_risk = request.args.get("min_risk", type=float)
    category = request.args.get("category")

    data = store.search_events(
        query=query,
        table=table,
        hours=hours,
        limit=limit,
        offset=offset,
        min_risk=min_risk,
        category=category,
    )
    data["status"] = "success"
    data["timestamp"] = datetime.now(timezone.utc).isoformat()
    return jsonify(data)


@dashboard_bp.route("/api/incidents", methods=["GET"])
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def list_incidents():
    """List security incidents with optional pagination and status filter."""
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    if store is None:
        return jsonify(
            {
                "status": "success",
                "incidents": [],
                "count": 0,
                "total": 0,
                "page": 1,
                "per_page": 20,
                "total_pages": 0,
                "status_counts": {},
                "severity_counts": {},
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    status_filter = request.args.get("status") or None
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1
    try:
        per_page = min(max(1, int(request.args.get("per_page", 20))), 100)
    except (ValueError, TypeError):
        per_page = 20

    total = store.get_incidents_count(status=status_filter)
    total_pages = max(1, (total + per_page - 1) // per_page) if total else 1
    page = min(page, total_pages)
    offset = (page - 1) * per_page

    incidents = store.get_incidents(status=status_filter, limit=per_page, offset=offset)
    status_counts = store.get_incidents_status_counts()
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    severity_counts.update(store.get_incidents_severity_counts() or {})

    return jsonify(
        {
            "status": "success",
            "incidents": incidents,
            "count": len(incidents),
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
            "status_counts": status_counts,
            "severity_counts": severity_counts,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


@dashboard_bp.route("/api/incidents", methods=["POST"])
@require_login
@require_rate_limit(max_requests=20, window_seconds=60)
def create_incident():
    """Create a new security incident."""
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    if store is None:
        return jsonify({"status": "error", "message": _MSG_DB_UNAVAILABLE}), 500

    data = request.get_json(silent=True) or {}
    incident_id = store.create_incident(data)
    if incident_id:
        return jsonify({"status": "success", "incident_id": incident_id}), 201
    return jsonify({"status": "error", "message": "Failed to create"}), 500


@dashboard_bp.route("/api/incidents/<int:incident_id>", methods=["GET"])
@require_login
def get_incident_route(incident_id):
    """Get a single incident."""
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    if store is None:
        return jsonify({"status": "error", "message": "DB unavailable"}), 500

    incident = store.get_incident(incident_id)
    if incident:
        return jsonify({"status": "success", "incident": incident})
    return jsonify({"status": "error", "message": "Not found"}), 404


@dashboard_bp.route("/api/incidents/<int:incident_id>", methods=["PATCH"])
@require_login
@require_rate_limit(max_requests=30, window_seconds=60)
def update_incident_route(incident_id):
    """Update an incident."""
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    if store is None:
        return jsonify({"status": "error", "message": "DB unavailable"}), 500

    data = request.get_json(silent=True) or {}
    ok = store.update_incident(incident_id, data)
    if ok:
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "message": "Update failed"}), 500


@dashboard_bp.route("/api/network/topology")
@require_login
@require_rate_limit(max_requests=30, window_seconds=60)
def network_topology_data():
    """Network topology from device_telemetry and flow_events."""
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    if store is None:
        return jsonify({"status": "success", "nodes": [], "edges": []})

    nodes = []
    edges = []
    try:
        # Devices — deduplicate via GROUP BY instead of fetching all rows
        cursor = store.db.execute(
            "SELECT device_id, MAX(ip_address), MAX(device_type), MAX(manufacturer) "
            "FROM device_telemetry GROUP BY device_id LIMIT 200"
        )
        seen_ids = set()
        for row in cursor.fetchall():
            did = row[0]
            if did not in seen_ids:
                seen_ids.add(did)
                nodes.append(
                    {
                        "id": did,
                        "label": did,
                        "ip": row[1] or "",
                        "type": row[2] or "host",
                        "manufacturer": row[3] or "",
                    }
                )
        # Flow edges — limit to recent 24h and top 200 connections
        flow_cutoff = int((time.time() - 24 * 3600) * 1e9)
        cursor = store.db.execute(
            "SELECT src_ip, dst_ip, protocol, SUM(bytes_tx), COUNT(*) "
            "FROM flow_events WHERE timestamp_ns > ? "
            "GROUP BY src_ip, dst_ip, protocol "
            "ORDER BY COUNT(*) DESC LIMIT 200",
            (flow_cutoff,),
        )
        for row in cursor.fetchall():
            if row[0] and row[1]:
                edges.append(
                    {
                        "source": row[0],
                        "target": row[1],
                        "protocol": row[2] or "TCP",
                        "bytes": row[3] or 0,
                        "count": row[4],
                    }
                )
        # Security device IDs — use index, limit to 200
        cursor = store.db.execute(
            "SELECT DISTINCT device_id FROM security_events LIMIT 200"
        )
        for row in cursor.fetchall():
            did = row[0]
            if did and did not in seen_ids:
                seen_ids.add(did)
                nodes.append(
                    {
                        "id": did,
                        "label": did,
                        "ip": "",
                        "type": "endpoint",
                        "manufacturer": "",
                    }
                )
    except Exception:
        pass

    return jsonify(
        {
            "status": "success",
            "nodes": nodes,
            "edges": edges,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


@dashboard_bp.route("/api/correlate")
@require_login
@require_rate_limit(max_requests=30, window_seconds=60)
def correlate_events():
    """Correlate events around a seed event for timeline replay and evidence chain."""
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    event_id = request.args.get("event_id", type=int)
    window_minutes = request.args.get("window_minutes", 30, type=int)
    max_results = request.args.get("max_results", 100, type=int)

    if store is None:
        return jsonify({"status": "error", "message": _MSG_DB_UNAVAILABLE}), 500

    if not event_id:
        return jsonify({"status": "error", "message": "event_id required"}), 400

    source_table = request.args.get("source", "security")

    # Table-specific queries for seed event lookup
    _SEED_QUERIES = {
        "security": (
            "SELECT id, timestamp_ns, timestamp_dt, device_id, collection_agent, "
            "event_category, event_action, risk_score, confidence, description, "
            "mitre_techniques, final_classification, indicators, requires_investigation "
            "FROM security_events WHERE id = ?"
        ),
        "fim": (
            "SELECT id, timestamp_ns, timestamp_dt, device_id, collection_agent, "
            "event_type AS event_category, change_type AS event_action, "
            "risk_score, confidence, reason AS description, "
            "mitre_techniques, NULL AS final_classification, NULL AS indicators, "
            "0 AS requires_investigation "
            "FROM fim_events WHERE id = ?"
        ),
        "persistence": (
            "SELECT id, timestamp_ns, timestamp_dt, device_id, collection_agent, "
            "event_type AS event_category, change_type AS event_action, "
            "risk_score, confidence, reason AS description, "
            "mitre_techniques, NULL AS final_classification, NULL AS indicators, "
            "1 AS requires_investigation "
            "FROM persistence_events WHERE id = ?"
        ),
        "flow": (
            "SELECT id, timestamp_ns, timestamp_dt, device_id, NULL AS collection_agent, "
            "protocol AS event_category, NULL AS event_action, "
            "threat_score AS risk_score, 0.5 AS confidence, "
            "'Flow: ' || COALESCE(src_ip,'?') || ' -> ' || COALESCE(dst_ip,'?') AS description, "
            "NULL AS mitre_techniques, NULL AS final_classification, NULL AS indicators, "
            "CAST(is_suspicious AS INT) AS requires_investigation "
            "FROM flow_events WHERE id = ?"
        ),
        "process": (
            "SELECT id, timestamp_ns, timestamp_dt, device_id, collection_agent, "
            "process_category AS event_category, NULL AS event_action, "
            "anomaly_score AS risk_score, confidence_score AS confidence, "
            "exe AS description, NULL AS mitre_techniques, NULL AS final_classification, "
            "NULL AS indicators, CAST(is_suspicious AS INT) AS requires_investigation "
            "FROM process_events WHERE id = ?"
        ),
    }

    try:
        # 1) Load seed event — try specified source table, then fall back
        seed = None
        tables_to_try = [source_table] if source_table in _SEED_QUERIES else []
        tables_to_try += [t for t in _SEED_QUERIES if t != source_table]

        for tbl in tables_to_try:
            cursor = store.db.execute(_SEED_QUERIES[tbl], (event_id,))
            row = cursor.fetchone()
            if row:
                cols = [d[0] for d in cursor.description]
                seed = dict(zip(cols, row))
                break

        if not seed:
            return jsonify({"status": "error", "message": "Event not found"}), 404

        # Parse JSON fields
        seed["mitre_techniques"] = _parse_mitre(seed.get("mitre_techniques"))
        seed["indicators"] = _parse_indicators(seed.get("indicators"))

        # 2) Extract correlation keys
        seed_ts_ns = seed.get("timestamp_ns", 0)
        seed_device = seed.get("device_id", "")
        seed_indicators = seed.get("indicators", {})
        seed_ip = (
            seed_indicators.get("source_ip")
            or seed_indicators.get("src_ip")
            or seed_indicators.get("dst_ip")
            or ""
        )
        seed_mitre = seed.get("mitre_techniques", [])

        # Time window
        window_ns = window_minutes * 60 * int(1e9)
        start_ns = seed_ts_ns - window_ns
        end_ns = seed_ts_ns + window_ns

        # 3) Find correlated events across all domain tables
        correlated = []
        _CORR_QUERIES = [
            (
                "SELECT id, timestamp_ns, timestamp_dt, device_id, collection_agent, "
                "event_category, event_action, risk_score, confidence, description, "
                "mitre_techniques, final_classification, indicators "
                "FROM security_events "
                "WHERE id != ? AND timestamp_ns BETWEEN ? AND ? "
                "ORDER BY timestamp_ns ASC LIMIT ?",
                (event_id, start_ns, end_ns, max_results),
            ),
            (
                "SELECT id, timestamp_ns, timestamp_dt, device_id, collection_agent, "
                "event_type AS event_category, change_type AS event_action, "
                "risk_score, confidence, reason AS description, "
                "mitre_techniques, NULL AS final_classification, NULL AS indicators "
                "FROM fim_events "
                "WHERE timestamp_ns BETWEEN ? AND ? "
                "ORDER BY timestamp_ns ASC LIMIT ?",
                (start_ns, end_ns, max_results),
            ),
            (
                "SELECT id, timestamp_ns, timestamp_dt, device_id, collection_agent, "
                "event_type AS event_category, change_type AS event_action, "
                "risk_score, confidence, reason AS description, "
                "mitre_techniques, NULL AS final_classification, NULL AS indicators "
                "FROM persistence_events "
                "WHERE timestamp_ns BETWEEN ? AND ? "
                "ORDER BY timestamp_ns ASC LIMIT ?",
                (start_ns, end_ns, max_results),
            ),
        ]
        for query, params in _CORR_QUERIES:
            try:
                cursor = store.db.execute(query, params)
            except Exception:
                continue
            cols2 = [d[0] for d in cursor.description]
            for r in cursor.fetchall():
                evt = dict(zip(cols2, r))
                evt["mitre_techniques"] = _parse_mitre(evt.get("mitre_techniques"))
                evt["indicators"] = _parse_indicators(evt.get("indicators"))

                # Score correlation strength
                score = 0
                evt_device = evt.get("device_id", "")
                evt_indicators = (
                    evt.get("indicators", {})
                    if isinstance(evt.get("indicators"), dict)
                    else {}
                )
                evt_ip = (
                    evt_indicators.get("source_ip")
                    or evt_indicators.get("src_ip")
                    or evt_indicators.get("dst_ip")
                    or ""
                )
                evt_mitre = evt.get("mitre_techniques", [])

                if seed_device and evt_device == seed_device:
                    score += 3
                if seed_ip and evt_ip and seed_ip == evt_ip:
                    score += 2
                if seed_mitre and evt_mitre:
                    shared = set(seed_mitre) & set(evt_mitre)
                    score += len(shared)

                if score > 0:
                    evt["correlation_score"] = score
                    correlated.append(evt)

        # Sort by timestamp
        correlated.sort(key=lambda e: e.get("timestamp_ns", 0))

        # 4) Build phases (group by 60-second gaps)
        phases = []
        if correlated:
            all_events = [seed] + correlated
            all_events.sort(key=lambda e: e.get("timestamp_ns", 0))
            current_phase = {"name": "Phase 1", "events": [all_events[0]]}
            phase_count = 1
            for i in range(1, len(all_events)):
                gap = (
                    all_events[i].get("timestamp_ns", 0)
                    - all_events[i - 1].get("timestamp_ns", 0)
                ) / 1e9
                if gap > 60:
                    phases.append(current_phase)
                    phase_count += 1
                    current_phase = {
                        "name": f"Phase {phase_count}",
                        "events": [all_events[i]],
                    }
                else:
                    current_phase["events"].append(all_events[i])
            phases.append(current_phase)

            # Label phases by category
            _PHASE_LABELS = {
                "persistence": "Persistence",
                "ssh_bruteforce": "Brute Force",
                "off_hours_login": "Unauthorized Access",
                "execution": "Execution",
                "lolbin": "Defense Evasion",
                "dns": "Command & Control",
                "flow": "Network Activity",
                "usb": "Physical Access",
                "critical_file": "File Tampering",
                "suid": "Privilege Escalation",
            }
            for phase in phases:
                cats = [e.get("event_category", "") for e in phase["events"]]
                label = phase["name"]
                for prefix, name in _PHASE_LABELS.items():
                    if any(c.startswith(prefix) for c in cats):
                        label = name
                        break
                phase["label"] = label
                phase["event_count"] = len(phase["events"])
                phase["start_time"] = phase["events"][0].get("timestamp_dt", "")
                phase["end_time"] = phase["events"][-1].get("timestamp_dt", "")

        # 5) Build MITRE chain
        mitre_chain = []
        seen_mitre = set()
        for evt in [seed] + correlated:
            for tech in evt.get("mitre_techniques", []):
                if tech not in seen_mitre:
                    seen_mitre.add(tech)
                    mitre_chain.append(tech)

        # 6) Timeline span
        all_ts = [seed.get("timestamp_ns", 0)] + [
            e.get("timestamp_ns", 0) for e in correlated
        ]
        span_seconds = (max(all_ts) - min(all_ts)) / 1e9 if all_ts else 0

        return jsonify(
            {
                "status": "success",
                "seed_event": seed,
                "correlated_events": correlated,
                "total_correlated": len(correlated),
                "phases": phases,
                "mitre_chain": mitre_chain,
                "timeline_span_seconds": span_seconds,
                "window_minutes": window_minutes,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@dashboard_bp.route("/api/metrics/history")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def metrics_history_api():
    """Historical metrics for time-series charts."""
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    metric = request.args.get("metric", "cpu_percent")
    hours = request.args.get("hours", 24, type=int)

    if store is None:
        return jsonify({"status": "success", "data": [], "metric": metric})

    data = store.get_metrics_history(metric, hours=hours)
    return jsonify(
        {
            "status": "success",
            "data": data,
            "metric": metric,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


# ── Agent Deep Overview ──────────────────────────────────────────

# Static agent metadata for the 10 v2 security agents
_AGENT_COLORS = {
    "proc": "#4ECDC4",
    "flow": "#F38181",
    "dns": "#AA96DA",
    "auth": "#FF6B35",
    "fim": "#00ff88",
    "persistence": "#FCBAD3",
    "peripheral": "#FF6B9D",
    "kernel_audit": "#FFD93D",
    "device_discovery": "#6BCB77",
    "protocol_collectors": "#00B4D8",
    "applog": "#E8A87C",
    "db_activity": "#20B2AA",
    "http_inspector": "#7B68EE",
    "internet_activity": "#DA70D6",
    "net_scanner": "#FF7F50",
    "macos_security_monitor": "#FFD700",
    "macos_unified_log": "#87CEEB",
    "macos_dns": "#AA96DA",
    "macos_applog": "#E8A87C",
    "macos_discovery": "#6BCB77",
    "macos_internet_activity": "#DA70D6",
    "macos_db_activity": "#20B2AA",
    "macos_http_inspector": "#7B68EE",
}

_AGENT_CATEGORY_DISPLAY = {
    "endpoint": "Endpoint",
    "network": "Network",
    "application": "Application",
    "platform": "Platform",
    "physical": "Physical",
    "kernel": "Kernel",
    "identity": "Identity",
}


_AGENT_DEEP_META_CACHE = None


def _get_agent_deep_meta():
    """Build agent metadata lazily from AGENT_REGISTRY (single source of truth).

    Lazy because AGENT_REGISTRY imports agent classes which may fail at module
    import time (e.g., missing certs directory).
    """
    global _AGENT_DEEP_META_CACHE
    if _AGENT_DEEP_META_CACHE is not None:
        return _AGENT_DEEP_META_CACHE

    try:
        from amoskys.agents import AGENT_REGISTRY
    except Exception:
        return {}

    import sys as _sys

    is_darwin = _sys.platform == "darwin"
    # On macOS, these 6 agents resolve to Observatory implementations via platform routing
    _PLATFORM_ROUTED = {"proc", "auth", "persistence", "fim", "flow", "peripheral"}

    meta = {}
    for aid, reg in AGENT_REGISTRY.items():
        cat = reg.get("category", "endpoint")
        platforms = reg.get("platforms", [])

        # Determine agent source/provenance
        if aid.startswith("macos_"):
            source = "Observatory"
        elif aid == "kernel_audit":
            source = "Linux"
        elif aid in _PLATFORM_ROUTED and is_darwin:
            source = "Observatory"
        else:
            source = "Shared"

        meta[aid] = {
            "name": reg["name"],
            "short": aid,
            "description": reg["description"],
            "color": _AGENT_COLORS.get(aid, "#00d9ff"),
            "icon": reg.get("icon", aid),
            "category": _AGENT_CATEGORY_DISPLAY.get(cat, cat.title()),
            "platforms": platforms,
            "source": source,
        }

    _AGENT_DEEP_META_CACHE = meta
    return meta


# Map agent short names to event category prefixes for counting
_AGENT_EVENT_CATEGORIES = {
    "proc": [
        "process_spawned",
        "lolbin_execution",
        "suspicious_process_tree",
        "high_resource_process",
        "unexpectedly_long_process",
        "process_wrong_user",
        "execution_from_temp",
        "suspicious_script_execution",
        "dylib_injection",
        "code_signature_invalid",
    ],
    "flow": [
        "flow_portscan",
        "flow_lateral",
        "flow_exfil",
        "flow_c2",
        "flow_cleartext",
        "flow_suspicious_tunnel",
        "flow_internal_dns",
        "flow_new_external",
        "flow_network_extension",
    ],
    "dns": [
        "dns_query",
        "dga_domain",
        "dns_beaconing",
        "suspicious_tld",
        "nxdomain_burst",
        "dns_tunneling",
        "fast_flux",
        "dns_rebinding",
        "new_domain_for_process",
        "blocked_domain",
        "suspicious_domain",
    ],
    "auth": [
        "ssh_bruteforce",
        "ssh_password_spray",
        "impossible_travel",
        "sudo_",
        "off_hours_login",
        "mfa_bypass",
        "mfa_fatigue",
        "account_lockout",
        "first_time_sudo",
        "lockout_storm",
    ],
    "fim": [
        "critical_file_tampered",
        "suid_bit_added",
        "sgid_bit_added",
        "service_created",
        "service_modified",
        "webshell_detected",
        "ssh_config_backdoor",
        "sudoers_backdoor",
        "linker_config",
        "new_system_library",
        "bootloader_modified",
        "world_writable",
        "quarantine_xattr",
    ],
    "persistence": [
        "persistence_launchd",
        "persistence_systemd",
        "persistence_cron",
        "persistence_ssh_key",
        "persistence_shell_profile",
        "persistence_browser_extension",
        "persistence_startup_item",
        "persistence_hidden_loader",
        "persistence_config_profile",
        "persistence_auth_plugin",
        "persistence_user_launch_agent",
    ],
    "peripheral": [
        "usb_inventory",
        "usb_device_connected",
        "usb_device_disconnected",
        "usb_storage",
        "usb_network_adapter",
        "new_keyboard",
        "bluetooth_device",
        "peripheral_risk",
    ],
    "kernel_audit": [
        "kernel_execve",
        "kernel_privesc",
        "kernel_module",
        "kernel_ptrace",
        "kernel_file_permission",
        "kernel_audit_tamper",
        "kernel_syscall_flood",
        "suid_bit_added",
        "sgid_bit_added",
    ],
    "device_discovery": [
        "device_discovered",
        "port_scan_result",
        "device_risk_assessment",
        "rogue_dhcp",
        "rogue_dns",
        "shadow_it",
        "vulnerable_banner",
    ],
    "protocol_collectors": ["protocol_threat"],
    # L7 Gap-Closure Agents
    "applog": [
        "applog_log_tampering",
        "applog_credential_harvest",
        "applog_error_spike",
        "applog_webshell_access",
        "applog_suspicious_4xx_5xx",
        "applog_log_injection",
        "applog_privesc_log",
        "applog_container_breakout",
    ],
    "db_activity": [
        "db_privilege_escalation",
        "db_bulk_extraction",
        "db_schema_enumeration",
        "db_stored_proc_abuse",
        "db_credential_query",
        "db_sql_injection",
        "db_unauthorized_access",
        "db_ddl_change",
    ],
    "http_inspector": [
        "http_xss_detected",
        "http_ssrf_detected",
        "http_path_traversal",
        "http_api_abuse",
        "http_data_exfil",
        "http_suspicious_upload",
        "http_websocket_abuse",
        "http_csrf_missing",
    ],
    "internet_activity": [
        "internet_cloud_exfiltration",
        "internet_tor_vpn_detected",
        "internet_crypto_mining",
        "internet_suspicious_download",
        "internet_shadow_it",
        "internet_unusual_geo",
        "internet_long_lived_connection",
        "internet_doh_detected",
    ],
    "net_scanner": [
        "netscan_new_service",
        "netscan_port_change",
        "netscan_rogue_service",
        "netscan_ssl_cert_issue",
        "netscan_vulnerable_banner",
        "netscan_unauthorized_listener",
        "netscan_topology_change",
    ],
}


_deep_overview_cache = {"data": None, "ts": 0}


@dashboard_bp.route("/api/agents/deep-overview")
@require_login
@require_rate_limit(max_requests=30, window_seconds=60)
def agents_deep_overview():
    """Comprehensive agent overview with probes, MITRE, events, and health."""
    import os
    import platform as _platform

    now_ts = time.time()
    # 60-second cache aligned with probe health cache
    if _deep_overview_cache["data"] and (now_ts - _deep_overview_cache["ts"]) < 60:
        return jsonify(_deep_overview_cache["data"])

    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    target = "darwin" if _platform.system() == "Darwin" else "linux"

    # 1) Run probe audit for health status
    probe_results = []
    try:
        from amoskys.observability.probe_audit import run_audit

        probe_results = run_audit(target)
    except Exception:
        pass

    # 2) Get event counts per agent across ALL domain tables (last 7 days)
    event_counts_by_cat = {}
    event_counts_by_agent = {}  # canonical agent_id → count
    if store:
        cutoff_ns = int((time.time() - 7 * 24 * 3600) * 1e9)
        # Use read pool for all queries (avoids serialisation with writes)
        with store._read_pool.connection() as rdb:
            # Query each domain table for collection_agent counts
            _EVENT_TABLES_WITH_AGENT = [
                ("security_events", "collection_agent"),
                ("process_events", "collection_agent"),
                ("dns_events", "collection_agent"),
                ("persistence_events", "collection_agent"),
                ("peripheral_events", "collection_agent"),
            ]
            for table, col in _EVENT_TABLES_WITH_AGENT:
                try:
                    cursor = rdb.execute(
                        f"SELECT {col}, COUNT(*) FROM {table} "
                        f"WHERE timestamp_ns > ? GROUP BY {col}",
                        (cutoff_ns,),
                    )
                    for row in cursor.fetchall():
                        raw_agent = row[0] or ""
                        canonical = _normalize_agent_id(raw_agent)
                        event_counts_by_agent[canonical] = (
                            event_counts_by_agent.get(canonical, 0) + row[1]
                        )
                except Exception:
                    pass
            # observation_events: count by domain → agent mapping
            _OBS_DOMAIN_TO_AGENT = {
                "security": "macos_security_monitor",
                "unified_log": "macos_unified_log",
                "dns": "macos_dns",
                "applog": "macos_applog",
                "discovery": "macos_discovery",
                "internet_activity": "macos_internet_activity",
                "db_activity": "macos_db_activity",
                "http_inspector": "macos_http_inspector",
                "net_scanner": "net_scanner",
            }
            try:
                cursor = rdb.execute(
                    "SELECT domain, COUNT(*) FROM observation_events "
                    "WHERE timestamp_ns > ? GROUP BY domain",
                    (cutoff_ns,),
                )
                for row in cursor.fetchall():
                    domain_val = row[0] or ""
                    mapped_agent = _OBS_DOMAIN_TO_AGENT.get(domain_val, domain_val)
                    event_counts_by_agent[mapped_agent] = (
                        event_counts_by_agent.get(mapped_agent, 0) + row[1]
                    )
            except Exception:
                pass
            # Tables without collection_agent: count totals
            for table, agent_id in [
                ("flow_events", "flow"),
                ("fim_events", "fim"),
                ("audit_events", "kernel_audit"),
            ]:
                try:
                    row = rdb.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE timestamp_ns > ?",
                        (cutoff_ns,),
                    ).fetchone()
                    if row and row[0]:
                        event_counts_by_agent[agent_id] = (
                            event_counts_by_agent.get(agent_id, 0) + row[0]
                        )
                except Exception:
                    pass
            # Also get event_category counts for backward compat
            try:
                cursor = rdb.execute(
                    "SELECT event_category, COUNT(*) FROM security_events "
                    "WHERE timestamp_ns > ? GROUP BY event_category",
                    (cutoff_ns,),
                )
                for row in cursor.fetchall():
                    event_counts_by_cat[row[0]] = row[1]
            except Exception:
                pass

    # 3) Build per-agent deep data
    agents = []
    total_probes = 0
    total_events = 0
    total_mitre = set()

    # Pre-load probe objects for MITRE/description extraction
    _probe_objects_by_agent = {}
    try:
        from amoskys.observability.probe_audit import AGENT_PROBE_MAP

        for aid, mod_info in AGENT_PROBE_MAP.items():
            try:
                mod = importlib.import_module(mod_info["module"])
                factory = getattr(mod, mod_info["factory"])
                _probe_objects_by_agent[aid] = {
                    getattr(p, "name", ""): p for p in factory()
                }
            except Exception:
                pass
    except Exception:
        pass

    for agent_id, meta in _get_agent_deep_meta().items():
        # Get probes for this agent from audit results
        agent_probes = [r for r in probe_results if r.get("agent") == agent_id]
        probe_list = []
        agent_mitre = set()
        probe_objs = _probe_objects_by_agent.get(agent_id, {})

        for p in agent_probes:
            probe_name = p.get("probe", "unknown")
            probe_obj = probe_objs.get(probe_name)

            mitre_techs = (
                list(getattr(probe_obj, "mitre_techniques", [])) if probe_obj else []
            )
            description = getattr(probe_obj, "description", "") if probe_obj else ""
            fields = (
                list(getattr(probe_obj, "requires_fields", []))
                if probe_obj
                else p.get("requires_fields", [])
            )

            agent_mitre.update(mitre_techs)
            probe_list.append(
                {
                    "name": probe_name,
                    "description": description,
                    "status": p.get("verdict", "UNKNOWN"),
                    "mitre": mitre_techs,
                    "fields": fields if fields else [],
                    "issues": p.get("issues", []),
                }
            )

        # Count events for this agent (multi-table unified counts)
        agent_event_count = event_counts_by_agent.get(agent_id, 0)
        # Fallback: also check event_category prefix matching
        if agent_event_count == 0:
            cat_prefixes = _AGENT_EVENT_CATEGORIES.get(agent_id, [])
            for cat, count in event_counts_by_cat.items():
                for prefix in cat_prefixes:
                    if cat.startswith(prefix) or cat == prefix:
                        agent_event_count += count
                        break

        # Probe health summary
        real = sum(1 for p in probe_list if p["status"] == "REAL")
        degraded = sum(1 for p in probe_list if p["status"] == "DEGRADED")
        broken = sum(1 for p in probe_list if p["status"] == "BROKEN")
        disabled = sum(1 for p in probe_list if p["status"] == "DISABLED")

        total_probes += sum(1 for p in probe_list if p["status"] not in ("SKIPPED",))
        total_events += agent_event_count
        total_mitre.update(agent_mitre)

        agents.append(
            {
                "id": agent_id,
                "name": meta["name"],
                "short": meta["short"],
                "description": meta["description"],
                "color": meta["color"],
                "icon": meta["icon"],
                "category": meta["category"],
                "platforms": meta.get("platforms", []),
                "source": meta.get("source", "Shared"),
                "probes": probe_list,
                "probe_summary": {
                    "total": len(probe_list),
                    "real": real,
                    "degraded": degraded,
                    "broken": broken,
                    "disabled": disabled,
                },
                "event_count": agent_event_count,
                "mitre_techniques": sorted(agent_mitre),
                "mitre_count": len(agent_mitre),
                "signing_enabled": os.path.exists("certs/agent.ed25519"),
            }
        )

    # Sort agents by event count descending
    agents.sort(key=lambda a: a["event_count"], reverse=True)

    response = {
        "status": "success",
        "agents": agents,
        "summary": {
            "total_agents": len(agents),
            "total_probes": total_probes,
            "total_events": total_events,
            "total_mitre": len(total_mitre),
            "active_probes": sum(
                a["probe_summary"]["real"] + a["probe_summary"]["degraded"]
                for a in agents
            ),
            "signing_enabled": os.path.exists("certs/agent.ed25519"),
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    _deep_overview_cache["data"] = response
    _deep_overview_cache["ts"] = now_ts
    return jsonify(response)


# ── Per-Agent Live Events API ────────────────────────────────────


@dashboard_bp.route("/api/agents/<agent_id>/live-data")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def agent_live_data(agent_id):
    """Live telemetry data for a specific agent — events, process info, logs."""
    import os
    import socket as _socket
    from pathlib import Path

    from .agent_control import get_agent_status
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    limit = min(request.args.get("limit", 25, type=int), 100)

    # Map deep-overview IDs (proc, dns) to AGENT_CATALOG IDs (proc_agent, dns_agent)
    _id_map = {
        "proc": "proc_agent",
        "dns": "dns_agent",
        "auth": "auth_agent",
        "fim": "fim_agent",
        "flow": "flow_agent",
        "persistence": "persistence_agent",
        "peripheral": "peripheral_agent",
        "kernel_audit": "kernel_audit_agent",
        "device_discovery": "device_discovery_agent",
        "protocol_collectors": "protocol_collectors_agent",
        # L7 Gap-Closure Agents
        "applog": "applog_agent",
        "db_activity": "db_activity_agent",
        "http_inspector": "http_inspector_agent",
        "internet_activity": "internet_activity_agent",
        "net_scanner": "net_scanner_agent",
        # macOS Observatory Agents (catalog ID = registry ID)
        "macos_security_monitor": "macos_security_monitor",
        "macos_unified_log": "macos_unified_log",
        "macos_dns": "macos_dns",
        "macos_applog": "macos_applog",
        "macos_discovery": "macos_discovery",
        "macos_internet_activity": "macos_internet_activity",
        "macos_db_activity": "macos_db_activity",
        "macos_http_inspector": "macos_http_inspector",
    }
    catalog_id = _id_map.get(agent_id) or agent_id

    # 1) Process status (PID, CPU, memory, uptime)
    process_info = {}
    try:
        status = get_agent_status(catalog_id)
        process_info = status if isinstance(status, dict) else {}
    except Exception:
        pass

    # 2) Recent events — query BOTH security_events AND domain-specific tables
    recent_events = []
    cat_prefixes = _AGENT_EVENT_CATEGORIES.get(agent_id, [])

    # 2a) Security events (high-level detections)
    if store and cat_prefixes:
        try:
            placeholders = " OR ".join([f"event_category LIKE ?" for _ in cat_prefixes])
            params = [f"{p}%" for p in cat_prefixes]
            query = (
                f"SELECT id, timestamp_dt, device_id, event_category, "
                f"event_action, risk_score, confidence, description, "
                f"mitre_techniques, final_classification, indicators "
                f"FROM security_events WHERE ({placeholders}) "
                f"ORDER BY id DESC LIMIT ?"
            )
            params.append(limit)
            cursor = store.db.execute(query, params)
            cols = [d[0] for d in cursor.description]
            for row in cursor.fetchall():
                evt = dict(zip(cols, row))
                evt["source_table"] = "security_events"
                mt = evt.get("mitre_techniques", "")
                if isinstance(mt, str) and mt.startswith("["):
                    try:
                        import json as _json

                        evt["mitre_techniques"] = _json.loads(mt)
                    except Exception:
                        evt["mitre_techniques"] = []
                recent_events.append(evt)
        except Exception:
            pass

    # 2b) Domain-specific events (raw observables from the agent's own table)
    _AGENT_DOMAIN_QUERIES = {
        "proc": (
            "process_events",
            "SELECT id, timestamp_dt, device_id, pid, exe, cmdline, username, "
            "cpu_percent, memory_percent, is_suspicious, anomaly_score, "
            "collection_agent "
            "FROM process_events ORDER BY id DESC LIMIT ?",
        ),
        "dns": (
            "dns_events",
            "SELECT id, timestamp_dt, device_id, domain, query_type, "
            "response_code, risk_score, dga_score, is_beaconing, "
            "collection_agent, mitre_techniques "
            "FROM dns_events ORDER BY id DESC LIMIT ?",
        ),
        "flow": (
            "flow_events",
            "SELECT id, timestamp_dt, device_id, src_ip, dst_ip, "
            "src_port, dst_port, protocol, bytes_tx, bytes_rx, "
            "threat_score, is_suspicious "
            "FROM flow_events ORDER BY id DESC LIMIT ?",
        ),
        "fim": (
            "fim_events",
            "SELECT id, timestamp_dt, device_id, path, change_type, "
            "risk_score, mitre_techniques, collection_agent "
            "FROM fim_events ORDER BY id DESC LIMIT ?",
        ),
        "persistence": (
            "persistence_events",
            "SELECT id, timestamp_dt, device_id, mechanism, path, "
            "command, risk_score, mitre_techniques, collection_agent "
            "FROM persistence_events ORDER BY id DESC LIMIT ?",
        ),
        "peripheral": (
            "peripheral_events",
            "SELECT id, timestamp_dt, device_id, event_type, device_type, "
            "vendor_id, product_id, serial_number, is_authorized, risk_score, "
            "collection_agent "
            "FROM peripheral_events ORDER BY id DESC LIMIT ?",
        ),
        "kernel_audit": (
            "audit_events",
            "SELECT id, timestamp_dt, device_id, syscall, event_type, "
            "pid, uid, exe, target_path, risk_score, mitre_techniques "
            "FROM audit_events ORDER BY id DESC LIMIT ?",
        ),
    }
    domain_q = _AGENT_DOMAIN_QUERIES.get(agent_id)
    recent_processes = []
    if store and domain_q:
        table_name, sql = domain_q
        try:
            cursor = store.db.execute(sql, (limit,))
            cols = [d[0] for d in cursor.description]
            for row in cursor.fetchall():
                evt = dict(zip(cols, row))
                evt["source_table"] = table_name
                # Build a description for display
                if agent_id == "proc":
                    evt["event_category"] = "process_event"
                    evt["description"] = (
                        f"{evt.get('exe', '?')} (PID {evt.get('pid', '?')}) — {evt.get('username', '?')}"
                    )
                    recent_processes.append(dict(evt))
                elif agent_id == "dns":
                    evt["event_category"] = "dns_query"
                    evt["description"] = (
                        f"{evt.get('domain', '?')} ({evt.get('query_type', '?')})"
                    )
                elif agent_id == "flow":
                    evt["event_category"] = "network_flow"
                    evt["description"] = (
                        f"{evt.get('protocol', '?')} → {evt.get('dst_ip', '?')}:{evt.get('dst_port', '?')}"
                    )
                elif agent_id == "fim":
                    evt["event_category"] = "file_modification"
                    evt["description"] = (
                        f"{evt.get('path', '?')} ({evt.get('change_type', '?')})"
                    )
                elif agent_id == "persistence":
                    evt["event_category"] = evt.get("mechanism", "persistence")
                    evt["description"] = (
                        f"{evt.get('mechanism', '?')}: {evt.get('path', '?')}"
                    )
                elif agent_id == "peripheral":
                    evt["event_category"] = evt.get("event_type", "peripheral")
                    evt["description"] = (
                        f"{evt.get('device_type', '?')} — {evt.get('vendor_id', '?')}:{evt.get('product_id', '?')}"
                    )
                elif agent_id == "kernel_audit":
                    evt["event_category"] = evt.get("event_type", "kernel_audit")
                    evt["description"] = (
                        f"syscall:{evt.get('syscall', '?')} — {evt.get('exe', '?')}"
                    )

                # Parse MITRE techniques
                mt = evt.get("mitre_techniques", "")
                if isinstance(mt, str) and mt.startswith("["):
                    try:
                        import json as _json

                        evt["mitre_techniques"] = _json.loads(mt)
                    except Exception:
                        evt["mitre_techniques"] = []

                recent_events.append(evt)
        except Exception:
            pass

    # 3) observation_events — primary data source for Observatory agents
    #    Also covers agents without dedicated domain tables
    _AGENT_OBS_DOMAIN = {
        "macos_security_monitor": "security",
        "macos_unified_log": "unified_log",
        "macos_dns": "dns",
        "macos_applog": "applog",
        "macos_discovery": "discovery",
        "macos_internet_activity": "internet_activity",
        "macos_db_activity": "db_activity",
        "macos_http_inspector": "http_inspector",
        # Shared agents also write to observation_events
        "applog": "applog",
        "db_activity": "db_activity",
        "http_inspector": "http_inspector",
        "internet_activity": "internet_activity",
        "device_discovery": "discovery",
        "net_scanner": "net_scanner",
    }
    obs_domain = _AGENT_OBS_DOMAIN.get(agent_id)
    if store and obs_domain:
        try:
            cursor = store.db.execute(
                "SELECT id, timestamp_dt, device_id, domain, event_type, "
                "attributes, risk_score, collection_agent "
                "FROM observation_events WHERE domain = ? "
                "ORDER BY id DESC LIMIT ?",
                (obs_domain, limit),
            )
            cols = [d[0] for d in cursor.description]
            for row in cursor.fetchall():
                evt = dict(zip(cols, row))
                evt["source_table"] = "observation_events"
                evt["event_category"] = evt.get("event_type") or obs_domain
                # Extract description from attributes JSON
                attrs = evt.get("attributes", "")
                if isinstance(attrs, str) and attrs.startswith("{"):
                    try:
                        import json as _json

                        parsed = _json.loads(attrs)
                        # Build a meaningful description from attributes
                        desc = parsed.get("description") or parsed.get("summary")
                        if not desc:
                            # Fallback: compose from common fields
                            parts = []
                            for k in (
                                "event_type",
                                "process",
                                "sender",
                                "domain",
                                "path",
                                "exe",
                                "src_ip",
                                "dst_ip",
                            ):
                                if k in parsed and parsed[k]:
                                    parts.append(f"{k}={parsed[k]}")
                            msg = parsed.get("message", "")
                            if msg:
                                parts.append(str(msg)[:80])
                            desc = " | ".join(parts) if parts else obs_domain + " event"
                        evt["description"] = desc
                        evt["mitre_techniques"] = parsed.get("mitre_techniques", [])
                    except Exception:
                        evt["description"] = obs_domain + " observation"
                recent_events.append(evt)
        except Exception:
            pass

    # 4) Device info
    device_info = {
        "hostname": _socket.gethostname(),
        "ip_address": _get_local_ip(),
        "platform": os.uname().sysname if hasattr(os, "uname") else "Unknown",
    }
    if store:
        try:
            row = store.db.execute(
                "SELECT device_id, ip_address, device_type "
                "FROM device_telemetry ORDER BY id DESC LIMIT 1"
            ).fetchone()
            if row:
                device_info["device_id"] = row[0]
                if row[1]:
                    device_info["ip_address"] = row[1]
                device_info["device_type"] = row[2]
        except Exception:
            pass

    # 5) Agent log tail (last 30 lines)
    log_lines = []
    repo_root = Path(__file__).resolve().parents[3]
    # Map agent IDs to log file names
    log_name_map = {
        "proc": "proc_agent",
        "dns": "dns_agent",
        "auth": "auth_agent",
        "fim": "fim_agent",
        "flow": "flow_agent",
        "persistence": "persistence_agent",
        "peripheral": "peripheral_agent",
        "kernel_audit": "kernel_audit_agent",
        "device_discovery": "device_discovery_agent",
        "protocol_collectors": "protocol_collectors_agent",
        # L7 Gap-Closure Agents
        "applog": "applog_agent",
        "db_activity": "db_activity_agent",
        "http_inspector": "http_inspector_agent",
        "internet_activity": "internet_activity_agent",
        "net_scanner": "net_scanner_agent",
        # macOS Observatory Agents
        "macos_security_monitor": "macos_security_monitor",
        "macos_unified_log": "macos_unified_log",
        "macos_dns": "macos_dns",
        "macos_applog": "macos_applog",
        "macos_discovery": "macos_discovery",
        "macos_internet_activity": "macos_internet_activity",
        "macos_db_activity": "macos_db_activity",
        "macos_http_inspector": "macos_http_inspector",
    }
    log_file = repo_root / "logs" / f"{log_name_map.get(agent_id, agent_id)}.err.log"
    if log_file.exists():
        try:
            lines = log_file.read_text().strip().split("\n")
            log_lines = lines[-30:]
        except Exception:
            pass

    # 6) Event timeline stats (hourly distribution over last 24h)
    #    Query BOTH security_events AND the agent's domain table
    hourly_buckets = {}  # hour_str → count

    # 6a) security_events hourly
    if store and cat_prefixes:
        try:
            placeholders = " OR ".join([f"event_category LIKE ?" for _ in cat_prefixes])
            params = [f"{p}%" for p in cat_prefixes]
            cursor = store.db.execute(
                f"SELECT substr(timestamp_dt, 1, 13) as hour, COUNT(*) as cnt "
                f"FROM security_events WHERE ({placeholders}) "
                f"GROUP BY hour ORDER BY hour DESC LIMIT 24",
                params,
            )
            for row in cursor.fetchall():
                hourly_buckets[row[0]] = hourly_buckets.get(row[0], 0) + row[1]
        except Exception:
            pass

    # 6b) domain table hourly
    if store and domain_q:
        table_name = domain_q[0]
        try:
            cursor = store.db.execute(
                f"SELECT substr(timestamp_dt, 1, 13) as hour, COUNT(*) as cnt "
                f"FROM {table_name} "
                f"GROUP BY hour ORDER BY hour DESC LIMIT 24",
            )
            for row in cursor.fetchall():
                hourly_buckets[row[0]] = hourly_buckets.get(row[0], 0) + row[1]
        except Exception:
            pass

    # 6c) observation_events hourly (for Observatory agents)
    if store and obs_domain:
        try:
            cursor = store.db.execute(
                "SELECT substr(timestamp_dt, 1, 13) as hour, COUNT(*) as cnt "
                "FROM observation_events WHERE domain = ? "
                "GROUP BY hour ORDER BY hour DESC LIMIT 24",
                (obs_domain,),
            )
            for row in cursor.fetchall():
                hourly_buckets[row[0]] = hourly_buckets.get(row[0], 0) + row[1]
        except Exception:
            pass

    hourly_stats = sorted(
        [{"hour": h, "count": c} for h, c in hourly_buckets.items()],
        key=lambda x: x["hour"],
        reverse=True,
    )[:24]

    return jsonify(
        {
            "status": "success",
            "agent_id": agent_id,
            "process": process_info,
            "device": device_info,
            "recent_events": recent_events,
            "recent_processes": recent_processes,
            "log_tail": log_lines,
            "hourly_stats": hourly_stats,
            "event_count": len(recent_events),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


def _get_local_ip():
    """Get the local IP address."""
    import socket as _socket

    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ── Agent Activity & Domain Data APIs ────────────────────────────


@dashboard_bp.route("/api/agents/activity")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def agents_activity():
    """Per-agent event rates for last 1 min and last 60 min.

    Queries ALL event tables, not just security_events.
    """
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    result = {}

    if store:
        now_ns = int(time.time() * 1e9)
        one_min_ns = now_ns - 60 * int(1e9)
        sixty_min_ns = now_ns - 3600 * int(1e9)

        def _add_activity(agent_id, last_min, last_hour):
            aid = _normalize_agent_id(agent_id)
            if aid not in result:
                result[aid] = {"last_min": 0, "last_hour": 0}
            result[aid]["last_min"] += last_min
            result[aid]["last_hour"] += last_hour

        with store._read_pool.connection() as rdb:
            try:
                # 1. security_events — use event_category prefix matching
                cursor = rdb.execute(
                    """SELECT event_category,
                       SUM(CASE WHEN timestamp_ns > ? THEN 1 ELSE 0 END) as last_min,
                       COUNT(*) as last_hour
                       FROM security_events
                       WHERE timestamp_ns > ?
                       GROUP BY event_category""",
                    (one_min_ns, sixty_min_ns),
                )
                for row in cursor.fetchall():
                    cat, last_min, last_hour = row[0], row[1], row[2]
                    for agent_id, prefixes in _AGENT_EVENT_CATEGORIES.items():
                        for prefix in prefixes:
                            if cat and (cat.startswith(prefix) or cat == prefix):
                                _add_activity(agent_id, last_min, last_hour)
                                break
            except Exception:
                pass

            # 2. Domain tables with collection_agent column
            for table, default_agent in [
                ("process_events", "proc"),
                ("dns_events", "dns"),
                ("persistence_events", "persistence"),
            ]:
                try:
                    cursor = rdb.execute(
                        f"""SELECT COALESCE(collection_agent, ?) as agent,
                           SUM(CASE WHEN timestamp_ns > ? THEN 1 ELSE 0 END) as last_min,
                           COUNT(*) as last_hour
                           FROM {table}
                           WHERE timestamp_ns > ?
                           GROUP BY agent""",
                        (default_agent, one_min_ns, sixty_min_ns),
                    )
                    for row in cursor.fetchall():
                        _add_activity(row[0] or default_agent, row[1], row[2])
                except Exception:
                    pass

            # 3. Tables without collection_agent (fixed agent assignment)
            for table, agent_id in [("flow_events", "flow"), ("fim_events", "fim")]:
                try:
                    row = rdb.execute(
                        f"""SELECT
                           SUM(CASE WHEN timestamp_ns > ? THEN 1 ELSE 0 END) as last_min,
                           COUNT(*) as last_hour
                           FROM {table}
                           WHERE timestamp_ns > ?""",
                        (one_min_ns, sixty_min_ns),
                    ).fetchone()
                    if row and (row[0] or row[1]):
                        _add_activity(agent_id, row[0] or 0, row[1] or 0)
                except Exception:
                    pass

    return jsonify(
        {
            "status": "success",
            "activity": result,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


@dashboard_bp.route("/api/agents/<agent_id>/domain-data")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def agent_domain_data(agent_id):
    """Domain-specific structured data for Agent Monitor page."""
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    limit = min(request.args.get("limit", 50, type=int), 200)
    rows = []
    schema = "generic"

    if store:
        try:
            if agent_id == "dns":
                schema = "dns_events"
                cursor = store.db.execute(
                    "SELECT timestamp_dt, domain, query_type, response_code, "
                    "risk_score, dga_score, is_beaconing FROM dns_events "
                    "ORDER BY id DESC LIMIT ?",
                    (limit,),
                )
                cols = [d[0] for d in cursor.description]
                rows = [dict(zip(cols, r)) for r in cursor.fetchall()]

            elif agent_id == "fim":
                schema = "fim_events"
                cursor = store.db.execute(
                    "SELECT timestamp_dt, path, event_type, change_type, "
                    "old_hash, new_hash, risk_score FROM fim_events "
                    "ORDER BY id DESC LIMIT ?",
                    (limit,),
                )
                cols = [d[0] for d in cursor.description]
                rows = [dict(zip(cols, r)) for r in cursor.fetchall()]

            elif agent_id == "flow":
                schema = "flow_events"
                cursor = store.db.execute(
                    "SELECT timestamp_dt, src_ip, dst_ip, dst_port, protocol, "
                    "bytes_tx, bytes_rx, threat_score, is_suspicious FROM flow_events "
                    "ORDER BY id DESC LIMIT ?",
                    (limit,),
                )
                cols = [d[0] for d in cursor.description]
                rows = [dict(zip(cols, r)) for r in cursor.fetchall()]

            elif agent_id == "proc":
                schema = "process_events"
                cursor = store.db.execute(
                    "SELECT timestamp_dt, pid, exe, username, "
                    "cpu_percent, memory_percent, is_suspicious FROM process_events "
                    "ORDER BY id DESC LIMIT ?",
                    (limit,),
                )
                cols = [d[0] for d in cursor.description]
                rows = [dict(zip(cols, r)) for r in cursor.fetchall()]

            elif agent_id == "kernel_audit":
                schema = "audit_events"
                cursor = store.db.execute(
                    "SELECT timestamp_dt, syscall, event_type, pid, uid, "
                    "exe, target_path, risk_score FROM audit_events "
                    "ORDER BY id DESC LIMIT ?",
                    (limit,),
                )
                cols = [d[0] for d in cursor.description]
                rows = [dict(zip(cols, r)) for r in cursor.fetchall()]

            elif agent_id == "peripheral":
                schema = "peripheral_events"
                cursor = store.db.execute(
                    "SELECT timestamp_dt, event_type, device_type, vendor_id, "
                    "product_id, serial_number, is_authorized, risk_score "
                    "FROM peripheral_events ORDER BY id DESC LIMIT ?",
                    (limit,),
                )
                cols = [d[0] for d in cursor.description]
                rows = [dict(zip(cols, r)) for r in cursor.fetchall()]

            elif agent_id == "persistence":
                schema = "persistence_events"
                cursor = store.db.execute(
                    "SELECT timestamp_dt, event_type, mechanism, path, "
                    "command, change_type, risk_score FROM persistence_events "
                    "ORDER BY id DESC LIMIT ?",
                    (limit,),
                )
                cols = [d[0] for d in cursor.description]
                rows = [dict(zip(cols, r)) for r in cursor.fetchall()]

        except Exception:
            pass

    return jsonify(
        {
            "status": "success",
            "agent_id": agent_id,
            "schema": schema,
            "data": rows,
            "count": len(rows),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


# ── Agent Deployment API ─────────────────────────────────────────


@dashboard_bp.route("/api/agents/deploy/token", methods=["POST"])
@require_login
@require_rate_limit(max_requests=20, window_seconds=60)
def deploy_create_token():
    """Create a deployment token for agent provisioning."""
    from amoskys.agents.distribution import AgentDistributionService
    from amoskys.db.web_db import get_web_session_context

    user = get_current_user()
    data = request.get_json(silent=True) or {}
    label = data.get("label", "My Device")
    platform = data.get("platform", "macos")

    try:
        with get_web_session_context() as db:
            service = AgentDistributionService(db)
            result = service.create_deployment_token(
                user_id=user.id,
                label=label,
                platform=platform,
            )
            if result.success:
                return jsonify(
                    {
                        "status": "success",
                        "token": result.token,
                        "token_id": result.token_id,
                    }
                )
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": result.error or "Failed to create token",
                    }
                ),
                400,
            )
    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": str(e),
                }
            ),
            500,
        )


@dashboard_bp.route("/api/agents/deploy/tokens", methods=["GET"])
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def deploy_list_tokens():
    """List deployment tokens for the current user."""
    from amoskys.agents.distribution import AgentDistributionService
    from amoskys.db.web_db import get_web_session_context

    user = get_current_user()

    try:
        with get_web_session_context() as db:
            service = AgentDistributionService(db)
            result = service.list_user_tokens(user.id)
            if result.success:
                tokens = [
                    {
                        "id": t.id,
                        "label": t.label,
                        "platform": t.platform,
                        "is_consumed": t.is_consumed,
                        "expires_at": t.expires_at,
                        "created_at": t.created_at,
                        "consumed_by_agent_id": t.consumed_by_agent_id,
                    }
                    for t in result.tokens
                ]
                return jsonify(
                    {
                        "status": "success",
                        "tokens": tokens,
                        "total": result.total,
                        "active_count": result.active_count,
                        "consumed_count": result.consumed_count,
                    }
                )
            return jsonify({"status": "error", "message": result.error}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@dashboard_bp.route("/api/agents/deploy/tokens/<token_id>/revoke", methods=["POST"])
@require_login
@require_rate_limit(max_requests=20, window_seconds=60)
def deploy_revoke_token(token_id):
    """Revoke a deployment token."""
    from amoskys.agents.distribution import AgentDistributionService
    from amoskys.db.web_db import get_web_session_context

    user = get_current_user()

    try:
        with get_web_session_context() as db:
            service = AgentDistributionService(db)
            ok = service.revoke_token(user.id, token_id)
            if ok:
                return jsonify({"status": "success"})
            return jsonify({"status": "error", "message": "Token not found"}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@dashboard_bp.route("/api/agents/deploy/agents", methods=["GET"])
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def deploy_list_agents():
    """List deployed agents for the current user."""
    from amoskys.agents.distribution import AgentDistributionService
    from amoskys.db.web_db import get_web_session_context

    user = get_current_user()

    try:
        with get_web_session_context() as db:
            service = AgentDistributionService(db)
            result = service.list_user_agents(user.id)
            if result.success:
                agents = [
                    {
                        "id": a.id,
                        "hostname": a.hostname,
                        "ip_address": a.ip_address,
                        "platform": a.platform,
                        "version": a.version,
                        "status": a.status,
                        "capabilities": a.capabilities,
                        "last_heartbeat_at": a.last_heartbeat_at,
                        "created_at": a.created_at,
                        "heartbeat_count": a.heartbeat_count,
                    }
                    for a in result.agents
                ]
                return jsonify(
                    {
                        "status": "success",
                        "agents": agents,
                        "total": result.total,
                        "by_status": result.by_status,
                    }
                )
            return jsonify({"status": "error", "message": result.error}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@dashboard_bp.route("/api/agents/deploy/agents/<agent_id>/revoke", methods=["POST"])
@require_login
@require_rate_limit(max_requests=20, window_seconds=60)
def deploy_revoke_agent(agent_id):
    """Revoke a deployed agent."""
    from amoskys.agents.distribution import AgentDistributionService
    from amoskys.db.web_db import get_web_session_context

    user = get_current_user()

    try:
        with get_web_session_context() as db:
            service = AgentDistributionService(db)
            ok = service.revoke_agent(user.id, agent_id)
            if ok:
                return jsonify({"status": "success"})
            return jsonify({"status": "error", "message": "Agent not found"}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@dashboard_bp.route("/api/agents/deploy/stats", methods=["GET"])
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def deploy_stats():
    """Get deployment statistics for the current user."""
    from amoskys.agents.distribution import AgentDistributionService
    from amoskys.db.web_db import get_web_session_context

    user = get_current_user()

    try:
        with get_web_session_context() as db:
            service = AgentDistributionService(db)
            stats = service.get_user_stats(user.id)
            return jsonify(
                {
                    "status": "success",
                    "stats": stats,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── SOMA: Fusion Intelligence API ──


def _get_fusion_engine():
    """Get a FusionEngine instance for read-only queries."""
    from pathlib import Path

    fusion_db = Path("data/intel/fusion.db")
    if not fusion_db.exists():
        return None
    try:
        from amoskys.intel.fusion_engine import FusionEngine

        return FusionEngine(db_path=str(fusion_db))
    except Exception:
        return None


@dashboard_bp.route("/api/fusion/risk", methods=["GET"])
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def fusion_device_risk():
    """Get device risk snapshot from FusionEngine correlation.

    Query params:
        device_id: Optional device ID filter (defaults to all devices)
    """
    engine = _get_fusion_engine()
    if engine is None:
        return jsonify(
            {"status": "success", "risk": None, "message": _MSG_FUSION_UNAVAILABLE}
        )

    device_id = request.args.get("device_id")
    try:
        if device_id:
            risk = engine.get_device_risk(device_id)
            return jsonify({"status": "success", "risk": risk})
        else:
            risks = []
            for row in engine.db.execute(
                "SELECT * FROM device_risk ORDER BY score DESC"
            ).fetchall():
                risks.append(
                    {
                        "device_id": row[0],
                        "score": row[1],
                        "level": row[2],
                        "reason_tags": json.loads(row[3]),
                        "supporting_events": json.loads(row[4]),
                        "metadata": json.loads(row[5]),
                        "updated_at": row[6],
                    }
                )
            return jsonify({"status": "success", "risks": risks})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@dashboard_bp.route("/api/fusion/incidents", methods=["GET"])
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def fusion_incidents():
    """Get correlated incidents from FusionEngine with full AMRDR detail.

    Query params:
        severity: Optional severity filter (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        device_id: Optional device ID filter
        limit: Max results (default 50)
    """
    engine = _get_fusion_engine()
    if engine is None:
        return jsonify(
            {"status": "success", "incidents": [], "message": _MSG_FUSION_UNAVAILABLE}
        )

    try:
        limit = min(int(request.args.get("limit", 50)), 200)
    except (ValueError, TypeError):
        return jsonify({"status": "error", "message": "Invalid limit parameter"}), 400

    device_id = request.args.get("device_id")
    severity_filter = request.args.get("severity")

    try:
        incidents = engine.get_recent_incidents(device_id=device_id, limit=limit)
        if severity_filter:
            incidents = [i for i in incidents if i["severity"] == severity_filter]
        return jsonify(
            {
                "status": "success",
                "incidents": incidents,
                "total": len(incidents),
            }
        )
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── Brain / Intelligence APIs ──────────────────────────────────────────


_classification_cache = {"data": None, "ts": 0}


def _get_classification_stats(store):
    """Compute signal/noise distribution from composite scores.

    Uses SQL aggregation to classify events without fetching rows into Python.
    Cached for 30 seconds to avoid repeated full-table scans.
    """
    classification = {"legitimate": 0, "suspicious": 0, "malicious": 0}
    total = 0
    if store is None:
        return classification, total

    now = time.time()
    if _classification_cache["data"] and (now - _classification_cache["ts"]) < 30:
        cached = _classification_cache["data"]
        return cached[0], cached[1]

    try:
        row = store.db.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN composite >= 0.70 THEN 1 ELSE 0 END) AS malicious,
                SUM(CASE WHEN composite >= 0.40 AND composite < 0.70 THEN 1 ELSE 0 END) AS suspicious,
                SUM(CASE WHEN composite < 0.40 THEN 1 ELSE 0 END) AS legitimate
            FROM (
                SELECT
                    CASE
                        WHEN geometric_score > 0.001
                        THEN 0.35*geometric_score + 0.25*temporal_score
                             + 0.40*behavioral_score
                        ELSE 0.38*temporal_score + 0.62*behavioral_score
                    END AS composite
                FROM security_events
                WHERE geometric_score IS NOT NULL
                ORDER BY timestamp_ns DESC LIMIT 100000
            )
            """
        ).fetchone()
        if row:
            total = row[0] or 0
            classification["malicious"] = row[1] or 0
            classification["suspicious"] = row[2] or 0
            classification["legitimate"] = row[3] or 0
        _classification_cache["data"] = (classification, total)
        _classification_cache["ts"] = now
    except Exception:
        pass
    return classification, total


def _get_agent_explanations(engine):
    """Get AMRDR agent reliability explanations from FusionEngine."""
    if engine is None:
        return []
    try:
        from amoskys.intel.explanation import AgentExplainer

        explainer = AgentExplainer()
        return [
            explainer.explain_agent(aid, engine.reliability_tracker.get_state(aid))
            for aid in engine.reliability_tracker.list_agents()
        ]
    except Exception:
        return []


@dashboard_bp.route("/api/soma/overview", methods=["GET"])
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def soma_overview():
    """Full SOMA dashboard data: pipeline, classification, agents, learning."""
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    engine = _get_fusion_engine()

    pipeline_stages = [
        {"name": "Agents", "status": "active"},
        {"name": "WAL Processor", "status": "active"},
        {"name": "Enrichment", "status": "active"},
        {"name": "Scoring Engine", "status": "active"},
        {"name": "FusionEngine", "status": "active" if engine else "inactive"},
        {"name": "Incidents", "status": "active"},
    ]

    classification, events_processed = _get_classification_stats(store)
    agents = _get_agent_explanations(engine)

    total_flagged = classification["suspicious"] + classification["malicious"]
    confirmed_malicious = classification["malicious"]
    if confirmed_malicious > 0:
        fp_rate = round(classification["suspicious"] / total_flagged, 3)
    elif total_flagged > 0:
        fp_rate = None  # No confirmed threats yet — FP rate not meaningful
    else:
        fp_rate = 0.0

    # Read brain metrics for learning context
    brain_metrics = {}
    try:
        brain_path = os.path.join("data", "intel", "models", "brain_metrics.json")
        if os.path.exists(brain_path):
            with open(brain_path) as bf:
                brain_metrics = json.load(bf)
    except Exception:
        pass

    gbc = brain_metrics.get("gradient_boost", {})
    embedder = brain_metrics.get("embedder", {})
    high_trust = brain_metrics.get("high_trust_label_count", 0)

    return jsonify(
        {
            "status": "success",
            "pipeline": {
                "stages": pipeline_stages,
                "events_processed": events_processed,
            },
            "classification": classification,
            "agents": agents,
            "learning": {
                "total_feedback": 0,
                "fp_rate": fp_rate,
                "confirmed_malicious": confirmed_malicious,
                "total_flagged": total_flagged,
                "calibrations": [],
                "gbc_status": gbc.get("status", "cold_start"),
                "gbc_reason": gbc.get("reason"),
                "high_trust_labels": high_trust,
                "gbc_label_threshold": 50,
                "embedder_status": embedder.get("status", "cold_start"),
                "embedder_vocab_size": embedder.get("vocab_size", 0),
                "embedder_dim": embedder.get("embedding_dim", 0),
                "embedder_variance": embedder.get("explained_variance"),
            },
        }
    )


@dashboard_bp.route("/api/soma/agents", methods=["GET"])
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def soma_agents():
    """Get agent reliability states from AMRDR."""
    engine = _get_fusion_engine()
    if engine is None:
        return jsonify({"status": "success", "agents": []})

    try:
        from amoskys.intel.explanation import AgentExplainer

        explainer = AgentExplainer()
        agents = []
        for agent_id in engine.reliability_tracker.list_agents():
            state = engine.reliability_tracker.get_state(agent_id)
            agents.append(explainer.explain_agent(agent_id, state))
        return jsonify({"status": "success", "agents": agents})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@dashboard_bp.route("/api/agents/trust", methods=["GET"])
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def agent_trust():
    """Get cross-validated agent trust scores from AMRDR.

    Returns trust data from TelemetryStore's reliability tracker which
    performs cross-validation (FIM↔process, network↔DNS, auth↔process).
    """
    store = _get_store()
    if not store or not getattr(store, "_reliability", None):
        return jsonify({"status": "success", "agents": [], "source": "unavailable"})
    try:
        tracker = store._reliability
        agents = []
        weights = tracker.get_fusion_weights()
        for agent_id in sorted(tracker.list_agents()):
            state = tracker.get_state(agent_id)
            agents.append(
                {
                    "agent_id": agent_id,
                    "alpha": round(state.alpha, 2),
                    "beta": round(state.beta, 2),
                    "reliability_score": round(state.reliability_score, 3),
                    "fusion_weight": round(weights.get(agent_id, 1.0), 3),
                    "tier": state.tier.name,
                    "drift_type": state.drift_type.name,
                }
            )
        return jsonify(
            {"status": "success", "agents": agents, "source": "cross_validation"}
        )
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@dashboard_bp.route("/api/soma/status", methods=["GET"])
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def soma_baseline_status():
    """Get SOMA baseline learning/detection status + IGRIS tactical memory."""
    result = {"status": "success"}

    # Strategic SOMA (ML models)
    try:
        from amoskys.intel.scoring import ScoringEngine

        scorer = ScoringEngine()
        device_id = request.args.get("device_id")
        result["baseline"] = scorer.get_baseline_status(device_id)
    except Exception as e:
        result["baseline"] = {"error": str(e)}

    # Strategic SOMA brain status
    try:
        from amoskys.intel.soma_brain import SomaBrain

        brain = SomaBrain()
        result["brain"] = brain.status()
    except Exception:
        result["brain"] = {"status": "unavailable"}

    # Tactical SOMA (IGRIS observations)
    try:
        import sqlite3 as _sqlite3

        mem_db = os.path.join("data", "igris", "memory.db")
        if os.path.exists(mem_db):
            conn = _sqlite3.connect(mem_db, timeout=2)
            conn.row_factory = _sqlite3.Row

            total = conn.execute("SELECT COUNT(*) FROM soma_observations").fetchone()[0]
            known = conn.execute(
                "SELECT COUNT(*) FROM soma_observations WHERE seen_count > 3"
            ).fetchone()[0]
            novel = conn.execute(
                "SELECT COUNT(*) FROM soma_observations WHERE seen_count = 1"
            ).fetchone()[0]
            top_patterns = [
                dict(r)
                for r in conn.execute(
                    "SELECT event_category, process_name, seen_count, risk_score "
                    "FROM soma_observations ORDER BY seen_count DESC LIMIT 10"
                ).fetchall()
            ]
            recent_novel = [
                dict(r)
                for r in conn.execute(
                    "SELECT event_category, process_name, path, risk_score "
                    "FROM soma_observations WHERE seen_count = 1 "
                    "ORDER BY risk_score DESC LIMIT 5"
                ).fetchall()
            ]
            conn.close()
            result["tactical_memory"] = {
                "total_patterns": total,
                "known_patterns": known,
                "novel_patterns": novel,
                "learning_progress": round(known / max(total, 1) * 100, 1),
                "top_patterns": top_patterns,
                "recent_novel": recent_novel,
            }
    except Exception:
        result["tactical_memory"] = {"status": "unavailable"}

    return jsonify(result)


@dashboard_bp.route("/api/soma/mode", methods=["POST"])
@require_login
@require_rate_limit(max_requests=10, window_seconds=60)
def soma_set_mode():
    """Manually override SOMA baseline mode (learning/detection).

    Body: {
        "mode": "learning" | "detection",
        "device_id": optional str,
        "learning_hours": optional int (default 24, for learning mode)
    }
    """
    try:
        data = request.get_json(silent=True) or {}
        mode = data.get("mode", "").strip().lower()
        if mode not in ("learning", "detection"):
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "mode must be 'learning' or 'detection'",
                    }
                ),
                400,
            )

        device_id = data.get("device_id")
        learning_hours = min(int(data.get("learning_hours", 24)), 168)

        from amoskys.intel.scoring import ScoringEngine

        scorer = ScoringEngine(
            learning_hours=learning_hours if mode == "learning" else 0
        )
        success = scorer.set_baseline_mode(mode, device_id)
        if not success and mode == "learning":
            # No baselines exist yet — will be created on next event ingestion
            return jsonify(
                {
                    "status": "success",
                    "mode": mode,
                    "device_id": device_id,
                    "message": f"Learning mode activated ({learning_hours}h). Baselines will be created on next event ingestion.",
                }
            )

        return jsonify({"status": "success", "mode": mode, "device_id": device_id})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@dashboard_bp.route("/api/explain/event/<int:event_id>", methods=["GET"])
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def explain_event(event_id):
    """Explain why a security event was classified the way it was."""
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    if store is None:
        return jsonify({"status": "error", "message": _MSG_DB_UNAVAILABLE}), 500

    source_table = request.args.get("source", "security")

    # Map source to table names
    _TABLE_MAP = {
        "security": "security_events",
        "fim": "fim_events",
        "persistence": "persistence_events",
        "flow": "flow_events",
        "process": "process_events",
    }

    try:
        # Try specified table first, then fall back through all tables
        tables_to_try = [_TABLE_MAP.get(source_table, "security_events")]
        tables_to_try += [t for t in _TABLE_MAP.values() if t != tables_to_try[0]]

        row = None
        used_table = None
        for tbl in tables_to_try:
            try:
                row = store.db.execute(
                    f"SELECT * FROM {tbl} WHERE id = ?", (event_id,)
                ).fetchone()
                if row:
                    used_table = tbl
                    break
            except Exception:
                continue

        if not row:
            return jsonify({"status": "error", "message": "Event not found"}), 404

        columns = [
            desc[0]
            for desc in store.db.execute(
                f"SELECT * FROM {used_table} LIMIT 0"
            ).description
        ]
        event_dict = dict(zip(columns, row))

        # Normalize column names for non-security tables
        if used_table != "security_events":
            if "event_type" in event_dict and "event_category" not in event_dict:
                event_dict["event_category"] = event_dict["event_type"]
            if "anomaly_score" in event_dict and "risk_score" not in event_dict:
                event_dict["risk_score"] = event_dict["anomaly_score"]
            if "threat_score" in event_dict and "risk_score" not in event_dict:
                event_dict["risk_score"] = event_dict["threat_score"]
            if "confidence_score" in event_dict and "confidence" not in event_dict:
                event_dict["confidence"] = event_dict["confidence_score"]
            if "reason" in event_dict and "description" not in event_dict:
                event_dict["description"] = event_dict["reason"]

        # Parse JSON fields with null-safe defaults
        event_dict["mitre_techniques"] = _parse_mitre(
            event_dict.get("mitre_techniques")
        )
        event_dict["indicators"] = _parse_indicators(event_dict.get("indicators"))

        # Ensure indicators has meaningful content for the explainer
        if not event_dict.get("indicators"):
            event_dict["indicators"] = {
                "note": "No indicator data recorded for this event"
            }

        from amoskys.intel.explanation import EventExplainer

        explainer = EventExplainer()
        explanation = explainer.explain_event(event_dict)
        return jsonify({"status": "success", "explanation": explanation})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@dashboard_bp.route("/api/explain/incident/<incident_id>", methods=["GET"])
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def explain_incident(incident_id):
    """Explain an incident with narrative, confidence, and TP/FP indicators."""
    engine = _get_fusion_engine()
    if engine is None:
        return jsonify({"status": "error", "message": _MSG_FUSION_UNAVAILABLE}), 500

    try:
        incidents = engine.get_recent_incidents(limit=500)
        incident = next(
            (inc for inc in incidents if inc.get("incident_id") == incident_id),
            None,
        )
        if incident is None:
            return jsonify({"status": "error", "message": "Incident not found"}), 404

        # Fetch contributing events for richer explanation
        from .telemetry_bridge import get_telemetry_store

        events = []
        event_ids = incident.get("event_ids", [])
        if isinstance(event_ids, str):
            try:
                event_ids = json.loads(event_ids)
            except (json.JSONDecodeError, TypeError):
                event_ids = []
        store = get_telemetry_store()
        if store and event_ids:
            try:
                placeholders = ",".join("?" for _ in event_ids)
                rows = store.db.execute(
                    f"SELECT * FROM security_events WHERE id IN ({placeholders})",
                    event_ids,
                ).fetchall()
                cols = [
                    d[0]
                    for d in store.db.execute(
                        "SELECT * FROM security_events LIMIT 0"
                    ).description
                ]
                events = [dict(zip(cols, row)) for row in rows]
            except Exception:
                pass  # Proceed without events — explainer handles None

        from amoskys.intel.explanation import IncidentExplainer

        explainer = IncidentExplainer()
        explanation = explainer.explain_incident(incident, events or None)
        return jsonify({"status": "success", "explanation": explanation})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@dashboard_bp.route("/api/feedback", methods=["POST"])
@require_login
@require_rate_limit(max_requests=20, window_seconds=60)
def submit_feedback():
    """Record analyst triage decision for AMRDR learning.

    Body: {"incident_id": str, "verdict": "confirmed"|"dismissed"}
    """
    engine = _get_fusion_engine()
    if engine is None:
        return jsonify({"status": "error", "message": _MSG_FUSION_UNAVAILABLE}), 500

    data = request.get_json(silent=True) or {}
    incident_id = data.get("incident_id")
    verdict = data.get("verdict")

    if not incident_id or verdict not in ("confirmed", "dismissed"):
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Required: incident_id and verdict (confirmed|dismissed)",
                }
            ),
            400,
        )

    try:
        user = get_current_user()
        if isinstance(user, dict):
            analyst = user.get("username") or user.get("email") or "unknown"
        elif user:
            analyst = getattr(user, "email", "unknown")
        else:
            analyst = "unknown"
        result = engine.provide_incident_feedback(
            incident_id=incident_id,
            is_confirmed=(verdict == "confirmed"),
            analyst=analyst,
        )
        if result:
            return jsonify({"status": "success", "message": "Feedback recorded"})
        return jsonify({"status": "error", "message": "Incident not found"}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@dashboard_bp.route("/api/feedback/stats", methods=["GET"])
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def feedback_stats():
    """Get learning metrics: feedback counts, FP rates, reliability trends."""
    from .telemetry_bridge import get_telemetry_store

    engine = _get_fusion_engine()
    store = get_telemetry_store()

    stats = {
        "total_feedback": 0,
        "fp_rate": 0.0,
        "agent_reliability": {},
    }

    if engine:
        try:
            for agent_id in engine.reliability_tracker.list_agents():
                state = engine.reliability_tracker.get_state(agent_id)
                stats["agent_reliability"][agent_id] = {
                    "reliability": round(state.reliability_score, 3),
                    "tier": state.tier.name if state.tier else "NOMINAL",
                    "weight": round(state.fusion_weight, 3),
                }
        except Exception:
            pass

    if store:
        try:
            # Limit to last 7 days for performance on large tables
            cutoff_ns = int((time.time() - 7 * 24 * 3600) * 1e9)
            row = store.db.execute(
                "SELECT "
                "  SUM(CASE WHEN final_classification = 'suspicious' THEN 1 ELSE 0 END), "
                "  SUM(CASE WHEN final_classification != 'legitimate' THEN 1 ELSE 0 END) "
                "FROM security_events WHERE timestamp_ns > ?",
                (cutoff_ns,),
            ).fetchone()
            if row:
                suspicious = row[0] or 0
                flagged = row[1] or 0
                if flagged > 0:
                    stats["fp_rate"] = round(suspicious / flagged, 3)
        except Exception:
            pass

    return jsonify({"status": "success", "stats": stats})


# ── IGRIS Supervisory API Endpoints ──────────────────────────────────────────


@dashboard_bp.route("/api/igris/baselines")
@require_login
@require_rate_limit(max_requests=30, window_seconds=60)
def igris_baselines():
    """IGRIS baseline metrics snapshot."""
    try:
        from amoskys.igris import get_igris

        return jsonify({"status": "success", "baselines": get_igris().get_baselines()})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@dashboard_bp.route("/api/igris/logs")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def igris_logs():
    """Centralized IGRIS log stream — IGRIS + all in-process subsystems + agent tails."""
    from pathlib import Path

    lines_requested = request.args.get("lines", default=150, type=int)
    lines_requested = min(lines_requested, 800)
    log_dir = Path(__file__).resolve().parents[3] / "logs"

    all_log_lines: list[str] = []

    # 1. Main centralized log (in-process subsystems routed via _setup_log_file)
    igris_log = log_dir / "igris.log"
    if igris_log.exists():
        try:
            raw = igris_log.read_text().strip().split("\n")
            all_log_lines.extend(raw[-(lines_requested * 2) :])
        except Exception:
            pass

    # 2. Agent process logs (separate processes write to .err.log files)
    _AGENT_LOGS = [
        "proc_agent",
        "dns_agent",
        "auth_agent",
        "fim_agent",
        "flow_agent",
        "persistence_agent",
        "peripheral_agent",
        "kernel_audit_agent",
        "device_discovery_agent",
        "protocol_collectors_agent",
        # L7 Gap-Closure Agents
        "applog_agent",
        "db_activity_agent",
        "http_inspector_agent",
        "internet_activity_agent",
        "net_scanner_agent",
    ]
    for agent_name in _AGENT_LOGS:
        agent_log = log_dir / f"{agent_name}.err.log"
        if agent_log.exists():
            try:
                raw = agent_log.read_text().strip().split("\n")
                all_log_lines.extend(raw[-15:])
            except Exception:
                pass

    # 3. Sort by timestamp prefix for unified chronological view
    def _sort_key(line: str) -> str:
        if len(line) >= 19 and line[4] == "-" and line[10] == " ":
            return line[:19]
        return "9999"

    all_log_lines.sort(key=_sort_key)
    tail = all_log_lines[-lines_requested:]

    return jsonify({"status": "success", "log_tail": tail, "available": len(tail) > 0})


# ── Guardian C2 API Endpoints ─────────────────────────────────────────────


def _get_igris():
    """Import and return the IGRIS singleton, or None if unavailable."""
    try:
        from amoskys.igris import get_igris

        return get_igris()
    except Exception:
        return None


def _fleet_summary():
    """Build fleet summary from agent discovery (lightweight process scan)."""
    try:
        from .agent_discovery import AGENT_CATALOG, detect_agent_status

        agents = []
        for aid, cfg in AGENT_CATALOG.items():
            st = detect_agent_status(cfg)
            agents.append(
                {
                    "id": aid,
                    "name": cfg["name"],
                    "status": "healthy" if st["health"] == "online" else st["health"],
                    "type": cfg["type"],
                }
            )
        healthy = sum(1 for a in agents if a["status"] == "healthy")
        return {
            "total": len(agents),
            "healthy": healthy,
            "offline": len(agents) - healthy,
            "agents": agents,
        }
    except Exception:
        return {"total": 0, "healthy": 0, "offline": 0, "agents": []}


def _anomaly_summary():
    """Gather active anomalies from IGRIS signals."""
    igris = _get_igris()
    if not igris:
        return []
    try:
        signals = igris.get_signals(limit=20)
        anomalies = []
        for sig in signals:
            if sig.get("cleared"):
                continue
            anomalies.append(
                {
                    "id": sig.get("id", ""),
                    "agent": sig.get("subsystem", ""),
                    "agent_name": sig.get("subsystem", "unknown").title(),
                    "message": sig.get("reason", sig.get("signal_type", "")),
                    "severity": sig.get("severity", "medium"),
                }
            )
        return anomalies
    except Exception:
        return []


def _igris_status_summary():
    """IGRIS status for Guardian header indicator."""
    igris = _get_igris()
    if not igris:
        return {
            "status": "stopped",
            "active_signal_count": 0,
            "cycle_count": 0,
            "cycle_duration_ms": 0,
        }
    try:
        return igris.get_status()
    except Exception:
        return {
            "status": "error",
            "active_signal_count": 0,
            "cycle_count": 0,
            "cycle_duration_ms": 0,
        }


@dashboard_bp.route("/api/pipeline/status")
@require_login
@require_rate_limit(max_requests=30, window_seconds=60)
def pipeline_status():
    """Full ingest pipeline health: enrichment, scoring, fusion, SOMA."""
    status = {}

    # Enrichment stages
    try:
        from amoskys.enrichment import EnrichmentPipeline

        p = EnrichmentPipeline()
        status["enrichment"] = p.status()
        p.close()
    except Exception as e:
        status["enrichment"] = {"error": str(e)}

    # Scoring engine
    try:
        from amoskys.intel.scoring import ScoringEngine

        ScoringEngine()  # verifies it can be instantiated
        status["scoring"] = {"available": True}
    except Exception as e:
        status["scoring"] = {"error": str(e)}

    # SOMA brain
    try:
        from amoskys.intel.soma_brain import ModelScorerAdapter

        adapter = ModelScorerAdapter()
        status["soma"] = {
            "model_available": adapter.available(),
        }
    except Exception as e:
        status["soma"] = {"error": str(e)}

    # Fusion engine (incident count)
    try:
        import sqlite3
        from pathlib import Path

        fusion_db = Path(__file__).resolve().parents[3] / "data" / "intel" / "fusion.db"
        if fusion_db.exists():
            conn = sqlite3.connect(str(fusion_db), timeout=3)
            row = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()
            status["fusion"] = {"incidents": row[0] if row else 0}
            conn.close()
        else:
            status["fusion"] = {"incidents": 0, "note": "no fusion database yet"}
    except Exception as e:
        status["fusion"] = {"error": str(e)}

    # IGRIS
    igris = _get_igris()
    if igris:
        status["igris"] = {
            "running": igris.is_running,
        }
    else:
        status["igris"] = {"running": False}

    return jsonify({"status": "success", "pipeline": status})


@dashboard_bp.route("/api/c2/poll")
@require_login
@require_rate_limit(max_requests=30, window_seconds=60)
def c2_poll():
    """Coalesced Guardian C2 poll — fleet + anomalies + IGRIS in one response."""
    return jsonify(
        {
            "status": "success",
            "fleet": _fleet_summary(),
            "anomalies": _anomaly_summary(),
            "igris": _igris_status_summary(),
        }
    )


@dashboard_bp.route("/api/guardian/overview")
@require_login
@require_rate_limit(max_requests=30, window_seconds=60)
def guardian_overview():
    """Guardian fleet overview."""
    return jsonify({"status": "success", "fleet": _fleet_summary()})


@dashboard_bp.route("/api/guardian/anomalies")
@require_login
@require_rate_limit(max_requests=30, window_seconds=60)
def guardian_anomalies():
    """Active anomalies from IGRIS signals."""
    return jsonify({"status": "success", "anomalies": _anomaly_summary()})


@dashboard_bp.route("/api/igris/status")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def igris_status():
    """IGRIS operational status + tactical state."""
    result = _igris_status_summary()

    # Add tactical state from directives.json
    try:
        directives_path = os.path.join("data", "igris", "directives.json")
        if os.path.exists(directives_path):
            with open(directives_path) as f:
                directives = json.load(f)
            result["tactical"] = {
                "posture": directives.get("posture", "UNKNOWN"),
                "threat_level": directives.get("threat_level", 0),
                "hunt_mode": directives.get("hunt_mode", False),
                "directive_count": len(directives.get("directives", [])),
                "watched_pids": directives.get("watched_pids", []),
                "watched_paths": directives.get("watched_paths", []),
                "watched_domains": directives.get("watched_domains", []),
                "timestamp": directives.get("timestamp"),
            }
    except Exception:
        result["tactical"] = {"status": "unavailable"}

    return jsonify(result)


@dashboard_bp.route("/api/igris/coherence")
@require_login
@require_rate_limit(max_requests=30, window_seconds=60)
def igris_coherence():
    """IGRIS organism coherence assessment."""
    igris = _get_igris()
    if not igris:
        return (
            jsonify({"status": "error", "verdict": "unknown", "subsystem_status": {}}),
            503,
        )
    try:
        return jsonify(igris.get_coherence())
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


# ── IGRIS Chat (AI-powered security analyst) ────────────────────
_igris_chat_instance = None


def _get_igris_chat():
    global _igris_chat_instance
    if _igris_chat_instance is None:
        try:
            from flask import current_app

            from amoskys.igris.chat import IgrisChat

            action_executor = current_app.config.get("ACTION_EXECUTOR")
            _igris_chat_instance = IgrisChat(
                action_executor=action_executor,
            )
        except Exception as e:
            logger.error("Failed to initialize IGRIS chat: %s", e)
            return None
    return _igris_chat_instance


@dashboard_bp.route("/api/igris/chat", methods=["POST"])
@require_login
@require_rate_limit(max_requests=30, window_seconds=60)
def igris_chat():
    """IGRIS AI chat endpoint — security analyst copilot."""
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    if not message:
        return jsonify({"status": "error", "message": "No message provided"}), 400

    chat = _get_igris_chat()
    if chat is None:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "IGRIS chat unavailable. Check ANTHROPIC_API_KEY.",
                }
            ),
            503,
        )

    try:
        response = chat.chat(message)
        return jsonify(
            {
                "status": "success",
                "response": response,
                "history_length": len(chat.get_history()),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
    except Exception as e:
        logger.error("IGRIS chat error: %s", e)
        return jsonify({"status": "error", "message": str(e)}), 500


@dashboard_bp.route("/api/igris/chat/reset", methods=["POST"])
@require_login
def igris_chat_reset():
    """Reset IGRIS chat conversation history."""
    chat = _get_igris_chat()
    if chat:
        chat.reset()
    return jsonify({"status": "success", "message": "Conversation reset"})


@dashboard_bp.route("/api/igris/chat/brief", methods=["POST"])
@require_login
@require_rate_limit(max_requests=5, window_seconds=60)
def igris_proactive_brief():
    """IGRIS proactive security briefing — it tells you what matters."""
    chat = _get_igris_chat()
    if chat is None:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "IGRIS unavailable. Check ANTHROPIC_API_KEY.",
                }
            ),
            503,
        )

    try:
        response = chat.proactive_brief()
        return jsonify(
            {
                "status": "success",
                "response": response,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
    except Exception as e:
        logger.error("IGRIS proactive brief failed: %s", e)
        return jsonify({"status": "error", "message": str(e)}), 500


@dashboard_bp.route("/api/igris/chat/backend", methods=["GET"])
@require_login
def igris_chat_backend():
    """Get IGRIS LLM backend status."""
    import os

    claude_ok = bool(os.environ.get("ANTHROPIC_API_KEY", ""))
    return jsonify(
        {
            "status": "success",
            "current": "claude",
            "model": os.environ.get("IGRIS_MODEL", "claude-sonnet-4-20250514"),
            "backends": {
                "claude": {
                    "available": claude_ok,
                    "label": "Claude API",
                    "model": "claude-sonnet-4-20250514",
                },
            },
        }
    )


@dashboard_bp.route("/api/igris/chat/history")
@require_login
def igris_chat_history():
    """Get IGRIS chat conversation history."""
    chat = _get_igris_chat()
    if not chat:
        return jsonify({"status": "success", "history": []})
    return jsonify({"status": "success", "history": chat.get_history()})


@dashboard_bp.route("/api/guardian/execute", methods=["POST"])
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def guardian_execute():
    """Execute a Guardian C2 command and return formatted output."""
    data = request.get_json(silent=True) or {}
    cmd = (data.get("command") or "").strip()
    if not cmd:
        return jsonify({"output": "No command provided.", "cmd_type": "error"})

    igris = _get_igris()

    # ── Command router ──
    parts = cmd.split()
    root = parts[0].lower() if parts else ""

    try:
        # help
        if root == "help":
            output = (
                "Guardian C2 — Available Commands\n"
                "──────────────────────────────────\n"
                "  status [agent]   Fleet / agent status\n"
                "  fleet / scan     Full fleet scan\n"
                "  threats          Active threat signals\n"
                "  report           System overview report\n"
                "  sysinfo          Platform & resource info\n"
                "  soma status      SOMA Brain status\n"
                "  soma train       Trigger SOMA retraining\n"
                "  reliability      Agent reliability scores\n"
                "  events [N]       Recent security events\n"
                "  igris            IGRIS supervisor overview\n"
                "  igris status     IGRIS status detail\n"
                "  igris metrics    Full metric snapshot\n"
                "  igris coherence  Organism coherence check\n"
                "  igris signals    Active governance signals\n"
                "  igris baseline   Learned baselines\n"
                "  igris explain ID Explain a specific signal\n"
                "  igris reset      Reset baselines (warmup)\n"
                "  clear            Clear terminal\n"
            )
            return jsonify({"output": output, "cmd_type": "system"})

        # clear
        if root == "clear":
            return jsonify({"output": "", "cmd_type": "clear"})

        # fleet / scan
        if root in ("fleet", "scan"):
            fleet = _fleet_summary()
            lines = [
                f"Fleet Status — {fleet['total']} agents, {fleet['healthy']} healthy, {fleet['offline']} offline",
                "",
            ]
            for a in fleet["agents"]:
                marker = "[+]" if a["status"] == "healthy" else "[-]"
                lines.append(f"  {marker} {a['name']:<30s} {a['status']}")
            return jsonify({"output": "\n".join(lines), "cmd_type": "success"})

        # status [agent_id]
        if root == "status":
            if len(parts) > 1:
                agent_id = parts[1]
                from .agent_discovery import AGENT_CATALOG, detect_agent_status

                cfg = AGENT_CATALOG.get(agent_id)
                if not cfg:
                    return jsonify(
                        {"output": f"Unknown agent: {agent_id}", "cmd_type": "error"}
                    )
                st = detect_agent_status(cfg)
                lines = [
                    f"Agent: {cfg['name']} ({agent_id})",
                    f"Health: {st['health']}",
                    f"Instances: {st['instances']}",
                    f"Blockers: {', '.join(st['blockers']) or 'none'}",
                    f"Warnings: {', '.join(st['warnings']) or 'none'}",
                ]
                return jsonify({"output": "\n".join(lines), "cmd_type": "info"})
            # No agent specified — show fleet
            fleet = _fleet_summary()
            lines = [f"Fleet — {fleet['healthy']}/{fleet['total']} online"]
            for a in fleet["agents"]:
                marker = "[+]" if a["status"] == "healthy" else "[-]"
                lines.append(f"  {marker} {a['name']}")
            return jsonify({"output": "\n".join(lines), "cmd_type": "info"})

        # threats
        if root == "threats":
            anomalies = _anomaly_summary()
            if not anomalies:
                return jsonify(
                    {"output": "No active threat signals.", "cmd_type": "success"}
                )
            lines = [f"Active Threats — {len(anomalies)} signal(s)", ""]
            for a in anomalies:
                sev = a["severity"].upper()
                lines.append(f"  [{sev}] {a['agent_name']}: {a['message']}")
            return jsonify({"output": "\n".join(lines), "cmd_type": "warning"})

        # report
        if root == "report":
            fleet = _fleet_summary()
            anomalies = _anomaly_summary()
            st = _igris_status_summary()
            lines = [
                "AMOSKYS System Report",
                "═" * 40,
                f"Fleet: {fleet['healthy']}/{fleet['total']} agents online",
                f"Active threats: {len(anomalies)}",
                f"IGRIS: {st.get('status', 'unknown')} | Cycle #{st.get('cycle_count', 0)} | {st.get('cycle_duration_ms', 0)}ms",
                f"Coherence: {st.get('coherence', 'unknown')}",
            ]
            return jsonify({"output": "\n".join(lines), "cmd_type": "system"})

        # sysinfo
        if root == "sysinfo":
            import platform as plat

            import psutil

            mem = psutil.virtual_memory()
            lines = [
                f"Platform: {plat.system()} {plat.release()}",
                f"Machine: {plat.machine()}",
                f"CPU: {psutil.cpu_count()} cores @ {psutil.cpu_percent()}%",
                f"Memory: {mem.used // (1024**3)}GB / {mem.total // (1024**3)}GB ({mem.percent}%)",
                f"Python: {plat.python_version()}",
            ]
            return jsonify({"output": "\n".join(lines), "cmd_type": "info"})

        # soma status / soma train
        if root == "soma":
            sub = parts[1].lower() if len(parts) > 1 else "status"
            if sub == "status":
                try:
                    from amoskys.intel.soma_brain import SomaBrain

                    brain = SomaBrain()
                    stats = brain.get_stats()
                    lines = [
                        "SOMA Brain Status",
                        f"  Isolation Forest: {'available' if stats.get('model_adapter', {}).get('available') else 'not trained'}",
                        f"  Training events: {stats.get('training', {}).get('total_events', 0)}",
                        f"  Mode: {stats.get('mode', 'unknown')}",
                    ]
                    return jsonify({"output": "\n".join(lines), "cmd_type": "info"})
                except Exception as exc:
                    return jsonify(
                        {"output": f"SOMA unavailable: {exc}", "cmd_type": "error"}
                    )
            if sub == "train":
                return jsonify(
                    {
                        "output": "SOMA retraining queued. This may take a few minutes.",
                        "cmd_type": "system",
                    }
                )
            return jsonify(
                {"output": f"Unknown soma command: {sub}", "cmd_type": "error"}
            )

        # reliability
        if root == "reliability":
            try:
                from amoskys.intel.reliability_store import ReliabilityStore

                rs = ReliabilityStore()
                states = rs.get_all_states()
                if not states:
                    return jsonify(
                        {"output": "No reliability data yet.", "cmd_type": "info"}
                    )
                lines = ["Agent Reliability Scores", ""]
                for aid, st in sorted(states.items()):
                    score = (
                        round(st.reliability_score, 3)
                        if hasattr(st, "reliability_score")
                        else "?"
                    )
                    tier = st.tier.name if hasattr(st, "tier") and st.tier else "?"
                    lines.append(f"  {aid:<25s} score={score}  tier={tier}")
                return jsonify({"output": "\n".join(lines), "cmd_type": "info"})
            except Exception as exc:
                return jsonify(
                    {
                        "output": f"Reliability store unavailable: {exc}",
                        "cmd_type": "error",
                    }
                )

        # events [N]
        if root == "events":
            limit = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 10
            limit = min(limit, 50)
            try:
                store = importlib.import_module("amoskys.storage.telemetry_store")
                ts = store.TelemetryStore()
                rows = ts.db.execute(
                    "SELECT timestamp_dt, event_type, severity, device_id "
                    "FROM security_events ORDER BY timestamp_ns DESC LIMIT ?",
                    (limit,),
                ).fetchall()
                ts.close()
                if not rows:
                    return jsonify(
                        {
                            "output": "No security events recorded yet.",
                            "cmd_type": "info",
                        }
                    )
                lines = [f"Last {len(rows)} Security Events", ""]
                for r in rows:
                    lines.append(f"  [{r[2] or '?':>8s}] {r[0][:19]}  {r[1]}  ({r[3]})")
                return jsonify({"output": "\n".join(lines), "cmd_type": "info"})
            except Exception as exc:
                return jsonify(
                    {"output": f"Event query failed: {exc}", "cmd_type": "error"}
                )

        # igris *
        if root == "igris":
            if not igris:
                return jsonify(
                    {"output": "IGRIS supervisor is not running.", "cmd_type": "error"}
                )
            sub = parts[1].lower() if len(parts) > 1 else "status"

            if sub == "status":
                st = igris.get_status()
                lines = [
                    "IGRIS Supervisor Status",
                    f"  Status: {st.get('status', 'unknown')}",
                    f"  Cycle: #{st.get('cycle_count', 0)}",
                    f"  Duration: {st.get('cycle_duration_ms', 0)}ms",
                    f"  Signals: {st.get('active_signal_count', 0)} active / {st.get('signal_count_since_start', 0)} total",
                    f"  Coherence: {st.get('coherence', 'unknown')}",
                ]
                return jsonify({"output": "\n".join(lines), "cmd_type": "info"})

            if sub == "metrics":
                metrics = igris.get_metrics()
                if not metrics:
                    return jsonify(
                        {
                            "output": "No metrics collected yet (warmup?).",
                            "cmd_type": "info",
                        }
                    )
                lines = ["IGRIS Metrics Snapshot", ""]
                for k, v in sorted(metrics.items()):
                    lines.append(f"  {k}: {v}")
                return jsonify({"output": "\n".join(lines), "cmd_type": "info"})

            if sub == "coherence":
                co = igris.get_coherence()
                formatted = co.get("formatted")
                if formatted:
                    return jsonify({"output": formatted, "cmd_type": "info"})
                return jsonify(
                    {
                        "output": f"Verdict: {co.get('verdict', 'unknown')}",
                        "cmd_type": "info",
                    }
                )

            if sub == "signals":
                sigs = igris.get_signals(limit=20)
                if not sigs:
                    return jsonify(
                        {"output": "No governance signals.", "cmd_type": "success"}
                    )
                lines = [f"IGRIS Signals — {len(sigs)} recent", ""]
                for s in sigs:
                    cleared = " (cleared)" if s.get("cleared") else ""
                    lines.append(
                        f"  [{s.get('severity', '?'):>8s}] {s.get('id', '?')[:8]}  {s.get('reason', '')}{cleared}"
                    )
                return jsonify({"output": "\n".join(lines), "cmd_type": "info"})

            if sub == "baseline":
                metric = parts[2] if len(parts) > 2 else None
                baselines = igris.get_baselines()
                if metric:
                    bl = baselines.get(metric)
                    if not bl:
                        return jsonify(
                            {
                                "output": f"No baseline for metric: {metric}",
                                "cmd_type": "error",
                            }
                        )
                    lines = [f"Baseline: {metric}", ""]
                    for k, v in bl.items():
                        lines.append(f"  {k}: {v}")
                    return jsonify({"output": "\n".join(lines), "cmd_type": "info"})
                if not baselines:
                    return jsonify(
                        {
                            "output": "No baselines learned yet (warmup?).",
                            "cmd_type": "info",
                        }
                    )
                lines = [f"IGRIS Baselines — {len(baselines)} metrics", ""]
                for name in sorted(baselines.keys()):
                    bl = baselines[name]
                    ema = bl.get("ema", "?")
                    lines.append(f"  {name}: ema={ema}")
                return jsonify({"output": "\n".join(lines), "cmd_type": "info"})

            if sub == "explain":
                sig_id = parts[2] if len(parts) > 2 else None
                if not sig_id:
                    return jsonify(
                        {
                            "output": "Usage: igris explain <signal_id>",
                            "cmd_type": "error",
                        }
                    )
                formatted = igris.explain_signal_formatted(sig_id)
                if formatted:
                    return jsonify({"output": formatted, "cmd_type": "info"})
                return jsonify(
                    {"output": f"Signal not found: {sig_id}", "cmd_type": "error"}
                )

            if sub == "reset":
                result = igris.reset_baselines()
                return jsonify(
                    {
                        "output": result.get("message", "Reset complete."),
                        "cmd_type": "system",
                    }
                )

            return jsonify(
                {"output": f"Unknown igris command: {sub}", "cmd_type": "error"}
            )

        # start <agent_id>
        if root == "start" and len(parts) > 1:
            from .agent_control import start_agent

            result = start_agent(parts[1])
            return jsonify(
                {"output": result.get("message", str(result)), "cmd_type": "info"}
            )

        return jsonify(
            {
                "output": f"Unknown command: {cmd}\nType 'help' for available commands.",
                "cmd_type": "error",
            }
        )

    except Exception as exc:
        return jsonify({"output": f"Command error: {exc}", "cmd_type": "error"})


# ═══════════════════════════════════════════════════════════════════════════════
# Observatory API Endpoints — Wire observability pipeline data to dashboard
# ═══════════════════════════════════════════════════════════════════════════════


def _get_store():
    """Get TelemetryStore singleton, return None if unavailable."""
    try:
        from .telemetry_bridge import get_telemetry_store

        return get_telemetry_store()
    except Exception:
        return None


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
        import re

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
    from collections import OrderedDict

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
