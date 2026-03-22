"""
AMOSKYS Cortex Dashboard — Live Data API Routes

Extracted from dashboard/__init__.py.
Provides real-time agent status, system metrics, threat scoring,
event clustering, probe health, neural readiness, and platform capabilities.
"""

import time
from datetime import datetime, timezone

from flask import jsonify, request

from ..api.rate_limiter import require_rate_limit
from ..middleware import require_login
from . import dashboard_bp
from .route_helpers import _normalize_agent_id

# ── Throttle state for metrics persistence ──────────────────────────────
_metrics_last_store = [0.0]

# ── Probe-health response cache (60s TTL) ───────────────────────────────
_probe_health_cache: dict = {"data": None, "ts": 0}


# ── /api/live/agents ────────────────────────────────────────────────────
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


# ── /api/available-agents ───────────────────────────────────────────────
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


# ── /api/device-info ────────────────────────────────────────────────────
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


# ── /api/live/metrics ───────────────────────────────────────────────────
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


# ── /api/live/threat-score ──────────────────────────────────────────────
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


# ── /api/live/event-clustering ──────────────────────────────────────────
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


# ── /api/live/probe-health ──────────────────────────────────────────────
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


# ── /api/neural/readiness ──────────────────────────────────────────────
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


# ── /api/platform-capabilities ──────────────────────────────────────────
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
