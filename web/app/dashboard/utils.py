"""
AMOSKYS Cortex Dashboard Utilities
Phase 2.4 - Neural Security Data Processing

This module provides utility functions for the AMOSKYS Cortex Dashboard,
including data aggregation, visualization helpers, and real-time processing.
"""

import statistics
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

# Constants
UTC_TIMEZONE_SUFFIX = "+00:00"


def get_threat_timeline_data(hours: int = 24) -> Dict[str, Any]:
    """
    Generate threat timeline data from TelemetryStore.

    Args:
        hours: Number of hours to look back

    Returns:
        Dict containing timeline data and statistics
    """
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}

    if store is None:
        return {
            "timeline": [],
            "hourly_counts": {},
            "severity_distribution": severity_counts,
            "total_events": 0,
            "time_range": f"Last {hours} hours",
        }

    rows = store.get_recent_security_events(limit=500, hours=hours)
    if not rows:
        # Fallback: show most recent events regardless of age
        rows = store.get_recent_security_events(limit=500, hours=8760)
    timeline_data = []
    hourly_counts: Dict[str, int] = {}

    for row in rows:
        risk = row.get("risk_score", 0)
        sev = _risk_to_severity_label(risk)
        ts_dt = row.get("timestamp_dt", "")

        timeline_data.append(
            {
                "timestamp": ts_dt,
                "type": row.get("event_category", "unknown"),
                "severity": sev,
                "source": row.get("device_id", ""),
                "description": row.get("description", ""),
            }
        )

        # Count by hour
        try:
            parsed = datetime.fromisoformat(
                str(ts_dt).replace("Z", UTC_TIMEZONE_SUFFIX)
            )
            hour_key = parsed.strftime("%Y-%m-%d %H:00")
            hourly_counts[hour_key] = hourly_counts.get(hour_key, 0) + 1
        except (ValueError, TypeError):
            pass

        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "timeline": sorted(timeline_data, key=lambda x: x["timestamp"]),
        "hourly_counts": hourly_counts,
        "severity_distribution": severity_counts,
        "total_events": len(timeline_data),
        "time_range": f"Last {hours} hours",
    }


def _risk_to_severity_label(risk_score: float) -> str:
    """Map a 0.0-1.0 risk score to a severity string."""
    if risk_score >= 0.75:
        return "critical"
    elif risk_score >= 0.5:
        return "high"
    elif risk_score >= 0.25:
        return "medium"
    return "low"


def get_agent_health_summary() -> Dict[str, Any]:
    """
    Generate comprehensive agent health summary

    Returns:
        Dict containing agent status and health metrics
    """
    from ..api.agents import AGENT_REGISTRY

    current_time = datetime.now(timezone.utc)
    status_counts = {"online": 0, "active": 0, "stale": 0, "offline": 0}
    agent_details = []
    response_times = []

    for agent_id, info in AGENT_REGISTRY.items():
        last_seen = datetime.fromisoformat(
            info["last_seen"].replace("Z", UTC_TIMEZONE_SUFFIX)
        )
        seconds_since_ping = (current_time - last_seen).total_seconds()

        # Determine status
        if seconds_since_ping <= 60:
            status = "online"
        elif seconds_since_ping <= 300:
            status = "active"
        elif seconds_since_ping <= 600:
            status = "stale"
        else:
            status = "offline"

        status_counts[status] += 1
        response_times.append(seconds_since_ping)

        agent_details.append(
            {
                "agent_id": agent_id,
                "status": status,
                "hostname": info.get("hostname", "unknown"),
                "platform": info.get("platform", "unknown"),
                "last_seen": info["last_seen"],
                "response_time": seconds_since_ping,
                "capabilities": info.get("capabilities", []),
            }
        )

    # Calculate health score (0-100)
    total_agents = len(agent_details)
    if total_agents > 0:
        health_score = int(
            (
                status_counts["online"] * 1.0
                + status_counts["active"] * 0.8
                + status_counts["stale"] * 0.4
            )
            / total_agents
            * 100
        )
    else:
        health_score = 0

    return {
        "total_agents": total_agents,
        "status_distribution": status_counts,
        "health_score": health_score,
        "agent_details": sorted(agent_details, key=lambda x: x["response_time"]),
        "avg_response_time": statistics.mean(response_times) if response_times else 0,
        "max_response_time": max(response_times) if response_times else 0,
    }


def get_system_metrics_snapshot() -> Dict[str, Any]:
    """
    Generate system metrics snapshot for monitoring

    Returns:
        Dict containing current system performance metrics
    """
    import psutil

    try:
        # CPU metrics
        cpu_percent = psutil.cpu_percent(interval=0.1)
        cpu_count = psutil.cpu_count()

        # Memory metrics
        memory = psutil.virtual_memory()

        # Disk metrics
        disk = psutil.disk_usage("/")

        # Network metrics
        network = psutil.net_io_counters()

        # Process metrics
        current_process = psutil.Process()

        return {
            "cpu": {
                "percent": round(cpu_percent, 1),
                "cores": cpu_count,
                "status": (
                    "critical"
                    if cpu_percent > 85
                    else "warning" if cpu_percent > 70 else "healthy"
                ),
            },
            "memory": {
                "percent": round(memory.percent, 1),
                "used_gb": round(memory.used / (1024**3), 2),
                "total_gb": round(memory.total / (1024**3), 2),
                "status": (
                    "critical"
                    if memory.percent > 90
                    else "warning" if memory.percent > 75 else "healthy"
                ),
            },
            "disk": {
                "percent": round((disk.used / disk.total) * 100, 1),
                "used_gb": round(disk.used / (1024**3), 2),
                "total_gb": round(disk.total / (1024**3), 2),
                "status": (
                    "critical"
                    if disk.used / disk.total > 0.9
                    else "warning" if disk.used / disk.total > 0.8 else "healthy"
                ),
            },
            "network": {
                "bytes_sent_mb": round(network.bytes_sent / (1024**2), 2),
                "bytes_recv_mb": round(network.bytes_recv / (1024**2), 2),
                "packets_sent": network.packets_sent,
                "packets_recv": network.packets_recv,
            },
            "process": {
                "memory_percent": round(current_process.memory_percent(), 2),
                "cpu_percent": round(current_process.cpu_percent(), 1),
                "threads": current_process.num_threads(),
                "status": "healthy",
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        return {
            "error": f"Failed to collect metrics: {str(e)}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


def calculate_threat_score(time_window_hours: int = 1) -> Dict[str, Any]:
    """
    Calculate current threat score from TelemetryStore.

    Args:
        time_window_hours: Time window for threat calculation

    Returns:
        Dict containing threat score and analysis
    """
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()

    if store is None:
        return {
            "threat_score": 0,
            "threat_level": "LOW",
            "threat_color": "#00ff88",
            "recommended_action": "Normal monitoring",
            "event_count": 0,
            "time_window_hours": time_window_hours,
            "event_breakdown": {},
            "calculation_details": {"raw_score": 0, "normalized_score": 0},
        }

    data = store.get_threat_score_data(hours=time_window_hours)
    threat_score = int(data.get("threat_score", 0))
    event_count = data.get("event_count", 0)

    # Determine threat level and color
    if threat_score >= 75:
        threat_level = "CRITICAL"
        threat_color = "#ff0000"
        recommended_action = "Immediate response required"
    elif threat_score >= 50:
        threat_level = "HIGH"
        threat_color = "#ff6600"
        recommended_action = "Investigate and respond"
    elif threat_score >= 25:
        threat_level = "MEDIUM"
        threat_color = "#ffaa00"
        recommended_action = "Monitor closely"
    else:
        threat_level = "LOW"
        threat_color = "#00ff88"
        recommended_action = "Normal monitoring"

    return {
        "threat_score": threat_score,
        "threat_level": threat_level,
        "threat_color": threat_color,
        "recommended_action": recommended_action,
        "event_count": event_count,
        "time_window_hours": time_window_hours,
        "event_breakdown": {},
        "calculation_details": {
            "raw_score": threat_score,
            "normalized_score": threat_score,
        },
    }


def get_event_clustering_data() -> Dict[str, Any]:
    """
    Generate event clustering data from TelemetryStore.

    Returns:
        Dict containing various event clustering analyses
    """
    from .telemetry_bridge import get_telemetry_store

    empty_clusters = {
        "by_type": {},
        "by_severity": {},
        "by_source_ip": {},
        "by_hour": {},
        "by_agent": {},
    }

    store = get_telemetry_store()

    if store is None:
        return {
            "clusters": empty_clusters,
            "statistics": {
                "total_events": 0,
                "unique_types": 0,
                "unique_ips": 0,
                "unique_agents": 0,
                "most_active_type": ("none", 0),
                "most_active_ip": ("none", 0),
            },
            "time_range": "Last 24 hours",
        }

    data = store.get_security_event_clustering(hours=24)

    # Extract source IP counts from indicators using targeted SQL query
    import json
    import time as _time

    by_source_ip: Dict[str, int] = {}
    try:
        cutoff_ns = int((_time.time() - 24 * 3600) * 1e9)
        with store._lock:
            cursor = store.db.execute(
                """SELECT indicators FROM security_events
                   WHERE timestamp_ns > ? AND indicators LIKE '%_ip%'""",
                (cutoff_ns,),
            )
            rows = cursor.fetchall()
        for row in rows:
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

    clusters = {
        "by_type": data.get("by_category", {}),
        "by_severity": data.get("by_severity", {}),
        "by_source_ip": by_source_ip,
        "by_hour": data.get("by_hour", {}),
        "by_agent": {},
    }

    total_events = sum(clusters["by_type"].values())
    most_active_type = (
        max(clusters["by_type"].items(), key=lambda x: x[1])
        if clusters["by_type"]
        else ("none", 0)
    )
    most_active_ip = (
        max(by_source_ip.items(), key=lambda x: x[1]) if by_source_ip else ("none", 0)
    )

    return {
        "clusters": clusters,
        "statistics": {
            "total_events": total_events,
            "unique_types": len(clusters["by_type"]),
            "unique_ips": len(by_source_ip),
            "unique_agents": 0,
            "most_active_type": most_active_type,
            "most_active_ip": most_active_ip,
        },
        "time_range": "Last 24 hours",
    }


def format_bytes(bytes_value: float) -> str:
    """
    Format bytes into human-readable format

    Args:
        bytes_value: Number of bytes

    Returns:
        Formatted string (e.g., "1.2 GB")
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"


def format_time_duration(seconds: float) -> str:
    """
    Format seconds into human-readable duration

    Args:
        seconds: Duration in seconds

    Returns:
        Formatted string (e.g., "2m 30s")
    """
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        remaining_seconds = int(seconds % 60)
        return f"{minutes}m {remaining_seconds}s"
    else:
        hours = int(seconds // 3600)
        remaining_minutes = int((seconds % 3600) // 60)
        return f"{hours}h {remaining_minutes}m"


def get_neural_readiness_status() -> Dict[str, Any]:
    """
    Assess system readiness for Phase 2.5 Neural Engine integration

    Returns:
        Dict containing neural readiness assessment
    """
    # Check data pipeline health
    agent_data = get_agent_health_summary()
    system_data = get_system_metrics_snapshot()

    # Get real probe health data
    probe_score = 0
    probe_status = "unknown"
    try:
        import platform as _platform

        from amoskys.observability.probe_audit import run_audit, summarize_audit

        target = "darwin" if _platform.system() == "Darwin" else "linux"
        results = run_audit(target)
        summary = summarize_audit(results)
        total = summary.get("total", 1) or 1
        real = summary.get("real", 0)
        degraded = summary.get("degraded", 0)
        probe_score = round(((real + degraded) / total) * 100, 1)
        probe_status = (
            "ready"
            if probe_score >= 90
            else "degraded" if probe_score >= 70 else "critical"
        )
    except Exception:
        probe_score = 0
        probe_status = "unknown"

    # Get real event counts from DB
    db_event_count = 0
    db_table_coverage = 0
    try:
        from .telemetry_bridge import get_telemetry_store

        _store = get_telemetry_store()
        if _store:
            stats = _store.get_statistics()
            db_event_count = (
                stats.get("security_events_count", 0)
                + stats.get("process_events_count", 0)
                + stats.get("flow_events_count", 0)
            )
            # Count tables with data
            for key in [
                "security_events_count",
                "process_events_count",
                "flow_events_count",
                "device_telemetry_count",
            ]:
                if stats.get(key, 0) > 0:
                    db_table_coverage += 1
    except Exception:
        pass

    # Neural readiness criteria (using REAL data)
    criteria = {
        "data_flow": {
            "description": "Sufficient event data for training",
            "status": "ready" if db_event_count >= 100 else "limited",
            "score": min(db_event_count / 500, 1.0) * 100,
            "detail": f"{db_event_count} events across {db_table_coverage} tables",
        },
        "probe_coverage": {
            "description": "Observability probe coverage",
            "status": probe_status,
            "score": probe_score,
            "detail": f"{probe_score}% probes active",
        },
        "agent_connectivity": {
            "description": "Agent network operational",
            "status": (
                "ready"
                if agent_data["health_score"] >= 80
                else "degraded" if agent_data["health_score"] >= 50 else "critical"
            ),
            "score": agent_data["health_score"],
        },
        "system_performance": {
            "description": "System resources adequate",
            "status": (
                "ready"
                if system_data.get("cpu", {}).get("status") == "healthy"
                and system_data.get("memory", {}).get("status") == "healthy"
                else "warning"
            ),
            "score": 100
            - max(
                system_data.get("cpu", {}).get("percent", 0),
                system_data.get("memory", {}).get("percent", 0),
            ),
        },
    }

    # Calculate overall readiness score
    overall_score = sum(c["score"] for c in criteria.values()) / len(criteria)

    # Determine readiness level
    if overall_score >= 85:
        readiness_level = "OPTIMAL"
        readiness_color = "#00ff88"
    elif overall_score >= 70:
        readiness_level = "READY"
        readiness_color = "#ffaa00"
    elif overall_score >= 50:
        readiness_level = "LIMITED"
        readiness_color = "#ff6600"
    else:
        readiness_level = "NOT_READY"
        readiness_color = "#ff0000"

    return {
        "overall_score": round(overall_score, 1),
        "readiness_level": readiness_level,
        "readiness_color": readiness_color,
        "criteria": criteria,
        "recommendations": _get_neural_recommendations(criteria),
        "next_phase_eta": (
            "Phase 2.5 Neural Engine integration possible"
            if overall_score >= 70
            else "Optimization needed before Phase 2.5"
        ),
    }


def _get_neural_recommendations(criteria: Dict[str, Any]) -> List[str]:
    """
    Generate recommendations for improving neural readiness

    Args:
        criteria: Neural readiness criteria assessment

    Returns:
        List of recommendation strings
    """
    recommendations = []

    if criteria["data_flow"]["score"] < 80:
        recommendations.append(
            "Increase event data collection to improve training dataset"
        )

    if criteria["agent_connectivity"]["score"] < 80:
        recommendations.append("Improve agent connectivity and reduce response times")

    if criteria["system_performance"]["score"] < 80:
        recommendations.append(
            "Optimize system resources for neural processing workloads"
        )

    if not recommendations:
        recommendations.append(
            "System ready for Phase 2.5 Neural Engine implementation"
        )

    return recommendations


# Live Data Functions for Dashboard APIs
# These functions provide real-time data for dashboard endpoints


def get_live_threats_data() -> Dict[str, Any]:
    """Get live threats data for real-time dashboard updates"""
    timeline_data = get_threat_timeline_data(hours=24)

    return {
        "recent_events": timeline_data["timeline"][-10:],  # Last 10 events
        "hourly_stats": timeline_data["hourly_counts"],
        "severity_distribution": timeline_data["severity_distribution"],
        "total_events": len(timeline_data["timeline"]),
        "threat_trend": "stable",  # Default trend value
        "last_updated": datetime.now(timezone.utc).isoformat(),
    }


def get_live_agents_data() -> Dict[str, Any]:
    """Get live agent data for real-time dashboard updates"""
    agent_summary = get_agent_health_summary()

    return {
        "agent_count": agent_summary["total_agents"],
        "online_agents": agent_summary["status_distribution"]["online"],
        "offline_agents": agent_summary["status_distribution"]["offline"],
        "agent_list": agent_summary["agent_details"],
        "network_health": agent_summary["health_score"],
        "performance_metrics": {
            "avg_response_time": agent_summary["avg_response_time"],
            "max_response_time": agent_summary["max_response_time"],
        },
        "last_updated": datetime.now(timezone.utc).isoformat(),
    }


def get_live_metrics_data() -> Dict[str, Any]:
    """Get live system metrics for real-time dashboard updates"""
    metrics = get_system_metrics_snapshot()

    # get_system_metrics_snapshot returns {"error": ...} on failure
    if "error" in metrics:
        return {
            "cpu_usage": 0,
            "memory_usage": 0,
            "disk_usage": 0,
            "network_io": {},
            "process_count": 0,
            "uptime": 0,
            "last_updated": datetime.now(timezone.utc).isoformat(),
        }

    return {
        "cpu_usage": metrics["cpu"]["percent"],
        "memory_usage": metrics["memory"]["percent"],
        "disk_usage": metrics["disk"]["percent"],
        "network_io": metrics["network"],
        "process_count": metrics.get("processes", {}).get("total", 0),
        "uptime": 0,
        "last_updated": datetime.now(timezone.utc).isoformat(),
    }
