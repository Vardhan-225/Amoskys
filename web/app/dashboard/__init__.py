"""
AMOSKYS Cortex Dashboard Module
Phase 2.4 - Neural Security Visualization Interface

This module implements the AMOSKYS Cortex Dashboard, providing real-time
visualization of security events, agent status, and system metrics through
an intelligent neural interface.
"""

import importlib
import json
import time
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, redirect, render_template, request, url_for

from ..api.rate_limiter import require_rate_limit
from ..middleware import get_current_user, require_login

# Constants
UTC_TIMEZONE_SUFFIX = "+00:00"

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


@dashboard_bp.route("/marketplace")
@require_login
def agent_marketplace():
    """Agent Marketplace - Perspective Selection and Deployment"""
    user = get_current_user()
    return render_template("dashboard/marketplace.html", user=user)


@dashboard_bp.route("/evidence-chain")
@require_login
def evidence_chain_viewer():
    """Evidence Chain Viewer - Attack Reconstruction and Correlation"""
    user = get_current_user()
    return render_template("dashboard/evidence-chain.html", user=user)


@dashboard_bp.route("/timeline-replay")
@require_login
def timeline_replay():
    """Threat Timeline Replay - Step-by-step Attack Reconstruction"""
    user = get_current_user()
    return render_template("dashboard/timeline-replay.html", user=user)


@dashboard_bp.route("/query-builder")
@require_login
def query_builder():
    """Query Builder - Complex Security Event Query Interface"""
    user = get_current_user()
    return render_template("dashboard/query-builder.html", user=user)


@dashboard_bp.route("/perspective-selector")
@require_login
def perspective_selector():
    """Agent Perspective Selector - Multi-viewpoint Analysis Configuration"""
    user = get_current_user()
    return render_template("dashboard/perspective-selector.html", user=user)


@dashboard_bp.route("/soc")
@require_login
def security_operations_center():
    """Security Operations Center - Live Threat Monitoring"""
    user = get_current_user()
    return render_template("dashboard/soc.html", user=user)


@dashboard_bp.route("/agents")
@require_login
def agent_management():
    """Agent Management Dashboard - Neural Network Status"""
    user = get_current_user()
    return render_template("dashboard/agents.html", user=user)


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


@dashboard_bp.route("/neural")
@require_login
def neural_insights():
    """Redirect legacy neural page to Cortex command center."""
    return redirect(url_for("dashboard.cortex_dashboard"))


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


# Real-time Data Endpoints
@dashboard_bp.route("/api/live/threats")
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

    rows = store.get_recent_security_events(limit=50, hours=24)
    data_stale = False
    if not rows:
        # Fallback: show most recent events regardless of age
        rows = store.get_recent_security_events(limit=50, hours=8760)
        data_stale = bool(rows)
    recent_events = []
    for row in rows:
        # Extract source_ip from indicators JSON if available
        indicators = row.get("indicators", "{}")
        if isinstance(indicators, str):
            try:
                indicators = json.loads(indicators)
            except (json.JSONDecodeError, TypeError):
                indicators = {}
        source_ip = (
            indicators.get("source_ip")
            or indicators.get("src_ip")
            or row.get("device_id", "")
        )

        # Parse MITRE techniques
        mitre_raw = row.get("mitre_techniques", "[]")
        try:
            mitre = json.loads(mitre_raw) if isinstance(mitre_raw, str) else mitre_raw
        except (json.JSONDecodeError, TypeError):
            mitre = []

        recent_events.append(
            {
                "id": row.get("id"),
                "type": row.get("event_category", "unknown"),
                "severity": _risk_to_severity(row.get("risk_score", 0)),
                "risk_score": round(row.get("risk_score", 0), 3),
                "source_ip": source_ip,
                "description": row.get("description", ""),
                "timestamp": row.get("timestamp_dt", ""),
                "agent_id": indicators.get("agent", row.get("device_id", "")),
                "classification": row.get("final_classification", ""),
                "mitre_techniques": mitre if isinstance(mitre, list) else [],
                "requires_investigation": bool(
                    row.get("requires_investigation", False)
                ),
                "indicators": indicators,
            }
        )

    # Count events requiring investigation
    investigating_count = sum(1 for e in recent_events if e["requires_investigation"])

    # Determine when the most recent event occurred
    last_event_time = recent_events[0]["timestamp"] if recent_events else None

    return jsonify(
        {
            "status": "success",
            "threats": recent_events,
            "count": len(recent_events),
            "investigating_count": investigating_count,
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


@dashboard_bp.route("/api/live/agents")
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


@dashboard_bp.route("/api/live/metrics")
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

    data = store.get_security_event_clustering(hours=24)

    # Extract source_ip counts from security_events indicators
    # Use targeted SQL query instead of scanning all events
    by_source_ip = {}
    try:
        cutoff_ns = int((time.time() - 24 * 3600) * 1e9)
        cursor = store.db.execute(
            """SELECT indicators FROM security_events
               WHERE timestamp_ns > ? AND indicators LIKE '%_ip%'""",
            (cutoff_ns,),
        )
        for row in cursor.fetchall():
            try:
                indicators = json.loads(row[0]) if row[0] else {}
            except (json.JSONDecodeError, TypeError):
                continue
            ip = (
                indicators.get("source_ip")
                or indicators.get("src_ip")
                or indicators.get("dst_ip")
            )
            if ip:
                by_source_ip[ip] = by_source_ip.get(ip, 0) + 1
    except Exception:
        pass

    # Derive agent from event_category (no collection_agent column in schema)
    _CATEGORY_TO_AGENT = {
        "service_created": "PersistenceGuard",
        "persistence_browser_extension": "PersistenceGuard",
        "persistence_shell_profile": "PersistenceGuard",
        "persistence_user_launch_agent": "PersistenceGuard",
        "critical_file_tampered": "FIM",
        "new_system_library": "FIM",
        "world_writable_sensitive": "FIM",
        "code_signature_invalid": "FIM",
        "execution_from_temp": "ProcAgent",
        "lolbin_execution": "ProcAgent",
        "process_wrong_user": "ProcAgent",
        "suid_bit_added": "KernelAudit",
        "sgid_bit_added": "KernelAudit",
        "off_hours_login": "AuthGuard",
        "dns_query": "DNS",
        "usb_inventory_snapshot": "Peripheral",
        "flow_new_external_service_seen": "FlowAgent",
        "flow_network_extension_detected": "FlowAgent",
    }
    by_agent = {}
    for cat, count in data.get("by_category", {}).items():
        agent = _CATEGORY_TO_AGENT.get(cat, "Other")
        by_agent[agent] = by_agent.get(agent, 0) + count

    # Reshape to match expected frontend schema
    clusters = {
        "by_type": data.get("by_category", {}),
        "by_severity": data.get("by_severity", {}),
        "by_source_ip": by_source_ip,
        "by_agent": by_agent,
        "by_hour": data.get("by_hour", {}),
    }

    return jsonify(
        {"status": "success", "clusters": clusters, "timestamp": now.isoformat()}
    )


_probe_health_cache = {"data": None, "ts": 0}


@dashboard_bp.route("/api/live/probe-health")
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


# Agent Control Endpoints (Phase 8)
@dashboard_bp.route("/api/agents/status", methods=["GET"])
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

        # Then, start critical agents
        for agent_id, config in AGENT_CATALOG.items():
            if config.get("critical", False):
                start_result = start_agent_fn(agent_id)
                if start_result.get("status") in ("started", "already_running"):
                    results["started"] += 1
                else:
                    results["failed"] += 1
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


# ── New Feature APIs ──────────────────────────────────────────────


@dashboard_bp.route("/api/mitre/coverage")
@require_rate_limit(max_requests=30, window_seconds=60)
def mitre_coverage_data():
    """MITRE ATT&CK technique coverage from real security events."""
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    if store is None:
        return jsonify({"status": "success", "coverage": {}, "total_techniques": 0})

    coverage = store.get_mitre_coverage()
    return jsonify(
        {
            "status": "success",
            "coverage": coverage,
            "total_techniques": len(coverage),
            "total_hits": sum(v["count"] for v in coverage.values()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


@dashboard_bp.route("/api/hunt/search")
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
    table = request.args.get("table", "security_events")
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
@require_rate_limit(max_requests=60, window_seconds=60)
def list_incidents():
    """List security incidents."""
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    if store is None:
        return jsonify({"status": "success", "incidents": [], "count": 0})

    status_filter = request.args.get("status")
    incidents = store.get_incidents(status=status_filter)
    return jsonify(
        {
            "status": "success",
            "incidents": incidents,
            "count": len(incidents),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


@dashboard_bp.route("/api/incidents", methods=["POST"])
@require_rate_limit(max_requests=20, window_seconds=60)
def create_incident():
    """Create a new security incident."""
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    if store is None:
        return jsonify({"status": "error", "message": "Database unavailable"}), 500

    data = request.get_json(silent=True) or {}
    incident_id = store.create_incident(data)
    if incident_id:
        return jsonify({"status": "success", "incident_id": incident_id}), 201
    return jsonify({"status": "error", "message": "Failed to create"}), 500


@dashboard_bp.route("/api/incidents/<int:incident_id>", methods=["GET"])
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
        cursor = store.db.execute(
            "SELECT DISTINCT device_id, ip_address, device_type, manufacturer "
            "FROM device_telemetry ORDER BY timestamp_ns DESC"
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
        cursor = store.db.execute(
            "SELECT src_ip, dst_ip, protocol, SUM(bytes_tx), COUNT(*) "
            "FROM flow_events GROUP BY src_ip, dst_ip, protocol"
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
        cursor = store.db.execute("SELECT DISTINCT device_id FROM security_events")
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
@require_rate_limit(max_requests=30, window_seconds=60)
def correlate_events():
    """Correlate events around a seed event for timeline replay and evidence chain."""
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    event_id = request.args.get("event_id", type=int)
    window_minutes = request.args.get("window_minutes", 30, type=int)
    max_results = request.args.get("max_results", 100, type=int)

    if store is None:
        return jsonify({"status": "error", "message": "Database unavailable"}), 500

    if not event_id:
        return jsonify({"status": "error", "message": "event_id required"}), 400

    try:
        # 1) Load seed event
        cursor = store.db.execute(
            "SELECT id, timestamp_ns, timestamp_dt, device_id, event_category, "
            "event_action, risk_score, confidence, description, mitre_techniques, "
            "final_classification, indicators, requires_investigation "
            "FROM security_events WHERE id = ?",
            (event_id,),
        )
        row = cursor.fetchone()
        if not row:
            return jsonify({"status": "error", "message": "Event not found"}), 404

        cols = [d[0] for d in cursor.description]
        seed = dict(zip(cols, row))

        # Parse JSON fields
        for field in ("mitre_techniques", "indicators"):
            val = seed.get(field, "")
            if isinstance(val, str):
                try:
                    seed[field] = json.loads(val)
                except (json.JSONDecodeError, TypeError):
                    seed[field] = [] if field == "mitre_techniques" else {}

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

        # 3) Find correlated security events
        correlated = []
        cursor = store.db.execute(
            "SELECT id, timestamp_ns, timestamp_dt, device_id, event_category, "
            "event_action, risk_score, confidence, description, mitre_techniques, "
            "final_classification, indicators "
            "FROM security_events "
            "WHERE id != ? AND timestamp_ns BETWEEN ? AND ? "
            "ORDER BY timestamp_ns ASC LIMIT ?",
            (event_id, start_ns, end_ns, max_results),
        )
        cols2 = [d[0] for d in cursor.description]
        for r in cursor.fetchall():
            evt = dict(zip(cols2, r))
            # Parse JSON
            for f in ("mitre_techniques", "indicators"):
                v = evt.get(f, "")
                if isinstance(v, str):
                    try:
                        evt[f] = json.loads(v)
                    except (json.JSONDecodeError, TypeError):
                        evt[f] = [] if f == "mitre_techniques" else {}

            # Score correlation strength
            score = 0
            evt_device = evt.get("device_id", "")
            evt_indicators = evt.get("indicators", {})
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
_AGENT_DEEP_META = {
    "proc": {
        "name": "Process Monitor",
        "short": "ProcAgent",
        "description": "Native process monitoring with behavioral analysis, LOLBin detection, code signing verification, and anomaly detection",
        "color": "#4ECDC4",
        "icon": "proc",
        "category": "Endpoint",
    },
    "flow": {
        "name": "Network Flow Analyzer",
        "short": "FlowAgent",
        "description": "Network traffic analysis with C2 beaconing detection, lateral movement, data exfiltration, and tunnel detection",
        "color": "#F38181",
        "icon": "flow",
        "category": "Network",
    },
    "dns": {
        "name": "DNS Threat Detector",
        "short": "DNSAgent",
        "description": "DNS-based threat detection including DGA, tunneling, fast-flux, beaconing patterns, and blocklist enforcement",
        "color": "#AA96DA",
        "icon": "dns",
        "category": "Network",
    },
    "auth": {
        "name": "Authentication Guard",
        "short": "AuthGuard",
        "description": "Authentication monitoring with brute-force detection, impossible travel, sudo escalation, MFA bypass, and off-hours login detection",
        "color": "#FF6B35",
        "icon": "auth",
        "category": "Identity",
    },
    "fim": {
        "name": "File Integrity Monitor",
        "short": "FIM",
        "description": "File integrity monitoring for SUID escalation, webshell drops, config backdoors, library hijacking, and bootloader tampering",
        "color": "#00ff88",
        "icon": "fim",
        "category": "Endpoint",
    },
    "persistence": {
        "name": "Persistence Guard",
        "short": "PersistenceGuard",
        "description": "Persistence mechanism detection across LaunchAgents, systemd, cron, SSH keys, shell profiles, browser extensions, and auth plugins",
        "color": "#FCBAD3",
        "icon": "persistence",
        "category": "Endpoint",
    },
    "peripheral": {
        "name": "Peripheral Monitor",
        "short": "Peripheral",
        "description": "USB/Bluetooth device monitoring with BadUSB detection, unauthorized device tracking, and composite risk scoring",
        "color": "#FF6B9D",
        "icon": "peripheral",
        "category": "Physical",
    },
    "kernel_audit": {
        "name": "Kernel Audit Engine",
        "short": "KernelAudit",
        "description": "Kernel-level syscall monitoring for privilege escalation, ptrace abuse, kernel module loads, and audit subsystem tampering",
        "color": "#FFD93D",
        "icon": "kernel",
        "category": "Kernel",
    },
    "device_discovery": {
        "name": "Device Discovery",
        "short": "Discovery",
        "description": "Network asset discovery with ARP enumeration, port scanning, rogue DHCP/DNS detection, shadow IT, and vulnerability bannering",
        "color": "#6BCB77",
        "icon": "discovery",
        "category": "Network",
    },
    "protocol_collectors": {
        "name": "Protocol Threat Collector",
        "short": "ProtocolCollector",
        "description": "Protocol-level threat detection for HTTP anomalies, TLS issues, SSH brute-force, DNS tunneling, SQL injection, and RDP abuse",
        "color": "#00B4D8",
        "icon": "protocol",
        "category": "Network",
    },
}

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
}


_deep_overview_cache = {"data": None, "ts": 0}


@dashboard_bp.route("/api/agents/deep-overview")
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

    # 2) Get event counts per category from DB
    event_counts_by_cat = {}
    if store:
        try:
            cursor = store.db.execute(
                "SELECT event_category, COUNT(*) FROM security_events GROUP BY event_category"
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

    for agent_id, meta in _AGENT_DEEP_META.items():
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

        # Count events for this agent
        agent_event_count = 0
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

        total_probes += len(probe_list)
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
    }
    catalog_id = _id_map.get(agent_id) or agent_id

    # 1) Process status (PID, CPU, memory, uptime)
    process_info = {}
    try:
        status = get_agent_status(catalog_id)
        process_info = status if isinstance(status, dict) else {}
    except Exception:
        pass

    # 2) Recent events from security_events matching this agent's categories
    recent_events = []
    cat_prefixes = _AGENT_EVENT_CATEGORIES.get(agent_id, [])
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
                # Parse mitre_techniques JSON if stored as string
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

    # 3) Recent process events (for proc agent specifically)
    recent_processes = []
    if agent_id == "proc" and store:
        try:
            cursor = store.db.execute(
                "SELECT timestamp_dt, device_id, pid, exe, cmdline, username, "
                "cpu_percent, memory_percent, is_suspicious, anomaly_score "
                "FROM process_events ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            cols = [d[0] for d in cursor.description]
            for row in cursor.fetchall():
                recent_processes.append(dict(zip(cols, row)))
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
    }
    log_file = repo_root / "logs" / f"{log_name_map.get(agent_id, agent_id)}.err.log"
    if log_file.exists():
        try:
            lines = log_file.read_text().strip().split("\n")
            log_lines = lines[-30:]
        except Exception:
            pass

    # 6) Event timeline stats (hourly distribution over last 24h)
    hourly_stats = []
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
                hourly_stats.append({"hour": row[0], "count": row[1]})
        except Exception:
            pass

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
