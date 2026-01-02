"""
AMOSKYS Health API v1
Comprehensive system health endpoint for Command Center dashboard

This module provides real-time health status for:
- All registered agents (from AGENT_CATALOG)
- Core infrastructure (EventBus, WAL Processor)
- Threat level (from fusion engine)
- Event statistics (from telemetry database)
"""

import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List

import psutil
from flask import Blueprint, jsonify

from ..dashboard.agent_discovery import (
    AGENT_CATALOG,
    detect_agent_status,
    get_platform_name,
)

health_bp = Blueprint("health", __name__, url_prefix="/v1/health")

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data"
TELEMETRY_DB = DATA_DIR / "telemetry.db"
FUSION_DB = DATA_DIR / "intel" / "fusion.db"


def _get_component_status(component_name: str) -> str:
    """Get status of a named component by checking running processes

    Returns: 'running', 'stopped', or 'unknown'
    """
    patterns = {
        "eventbus": ["eventbus/server.py", "amoskys-eventbus"],
        "wal_processor": ["wal_processor", "wal-processor"],
        "fusion_engine": ["fusion_engine", "FusionEngine"],
        "web_dashboard": ["flask", "gunicorn", "web/app"],
    }

    search_patterns = patterns.get(component_name, [component_name])

    try:
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                cmdline = " ".join(proc.info.get("cmdline") or [])
                for pattern in search_patterns:
                    if pattern.lower() in cmdline.lower():
                        return "running"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        return "unknown"

    return "stopped"


def _get_events_last_24h() -> int:
    """Count events in the last 24 hours from telemetry database"""
    if not TELEMETRY_DB.exists():
        return 0

    try:
        conn = sqlite3.connect(str(TELEMETRY_DB))
        cursor = conn.cursor()

        # Calculate 24 hours ago in epoch nanoseconds
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        cutoff_ns = int(cutoff.timestamp() * 1_000_000_000)

        # Try different table structures
        for table in ["telemetry_events", "events", "telemetry"]:
            try:
                cursor.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE timestamp_ns > ?", (cutoff_ns,)
                )
                count = cursor.fetchone()[0]
                conn.close()
                return count
            except sqlite3.OperationalError:
                continue

        conn.close()
        return 0
    except Exception:
        return 0


def _get_current_threat_level() -> str:
    """Get current threat level from fusion engine state

    Returns: BENIGN, LOW, MEDIUM, HIGH, CRITICAL, or UNDER_ATTACK
    """
    # Try to get from fusion database
    if FUSION_DB.exists():
        try:
            conn = sqlite3.connect(str(FUSION_DB))
            cursor = conn.cursor()

            # Check for recent high-severity incidents
            cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
            cutoff_str = cutoff.isoformat()

            try:
                cursor.execute(
                    """SELECT severity FROM incidents
                       WHERE created_at > ?
                       ORDER BY
                         CASE severity
                           WHEN 'CRITICAL' THEN 1
                           WHEN 'HIGH' THEN 2
                           WHEN 'MEDIUM' THEN 3
                           WHEN 'LOW' THEN 4
                           ELSE 5
                         END
                       LIMIT 1""",
                    (cutoff_str,),
                )
                row = cursor.fetchone()
                if row:
                    severity = row[0]
                    # Map incident severity to threat level
                    severity_map = {
                        "CRITICAL": "CRITICAL",
                        "HIGH": "HIGH",
                        "MEDIUM": "MEDIUM",
                        "LOW": "LOW",
                        "INFO": "BENIGN",
                    }
                    conn.close()
                    return severity_map.get(severity, "LOW")
            except sqlite3.OperationalError:
                pass

            conn.close()
        except Exception:
            pass

    # Default to BENIGN if no recent incidents
    return "BENIGN"


def _calculate_health_score(
    agents_online: int, agents_total: int, infrastructure_ok: bool, events_24h: int
) -> int:
    """Calculate overall system health score (0-100)

    Weights:
    - Agent coverage: 40%
    - Infrastructure status: 40%
    - Activity (events exist): 20%
    """
    # Agent coverage score
    agent_score = (agents_online / max(agents_total, 1)) * 40

    # Infrastructure score (EventBus is critical)
    infra_score = 40 if infrastructure_ok else 0

    # Activity score (having events means the system is working)
    activity_score = 20 if events_24h > 0 else 10  # 10 points for fresh install

    return int(agent_score + infra_score + activity_score)


@health_bp.route("/system", methods=["GET"])
def system_health():
    """
    Comprehensive system health endpoint for Command Center

    Returns JSON with:
    - agents: Status of each agent (running/stopped)
    - infrastructure: Status of core components
    - threat_level: Current threat assessment
    - events_last_24h: Event count
    - health_score: Overall system health percentage
    - empty_state: True if no data yet (fresh install)
    """
    # Get agent statuses
    agents_status: Dict[str, str] = {}
    agents_details: List[Dict[str, Any]] = []

    for agent_id, agent_config in AGENT_CATALOG.items():
        status = detect_agent_status(agent_config)

        # Map health to running/stopped
        if status["health"] == "online":
            agents_status[agent_id] = "running"
        elif status["health"] == "incompatible":
            agents_status[agent_id] = "incompatible"
        else:
            agents_status[agent_id] = "stopped"

        # Detailed info for each agent
        agents_details.append(
            {
                "id": agent_id,
                "name": agent_config["name"],
                "type": agent_config["type"],
                "status": agents_status[agent_id],
                "instances": status["instances"],
                "port": agent_config.get("port"),
                "critical": agent_config.get("critical", False),
                "color": agent_config.get("color", "#00ff88"),
            }
        )

    # Infrastructure status
    eventbus_status = _get_component_status("eventbus")
    wal_processor_status = _get_component_status("wal_processor")
    web_dashboard_status = "running"  # We're serving this, so it's running

    infrastructure = {
        "eventbus": eventbus_status,
        "wal_processor": wal_processor_status,
        "web_dashboard": web_dashboard_status,
        "fusion_engine": _get_component_status("fusion_engine"),
    }

    # Threat level
    threat_level = _get_current_threat_level()

    # Event statistics
    events_24h = _get_events_last_24h()

    # Summary calculations
    agents_online = sum(1 for s in agents_status.values() if s == "running")
    agents_total = len([a for a in agents_status.values() if a != "incompatible"])
    infrastructure_ok = eventbus_status == "running"

    health_score = _calculate_health_score(
        agents_online, agents_total, infrastructure_ok, events_24h
    )

    # Determine if this is a fresh install (empty state)
    is_empty_state = events_24h == 0 and agents_online == 0

    return jsonify(
        {
            "status": "success",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "platform": get_platform_name(),
            # Agent summary
            "agents": agents_status,
            "agents_details": agents_details,
            "agents_summary": {
                "online": agents_online,
                "total": agents_total,
                "coverage_percent": round(
                    (agents_online / max(agents_total, 1)) * 100, 1
                ),
            },
            # Infrastructure
            "infrastructure": infrastructure,
            "infrastructure_healthy": infrastructure_ok,
            # Threat & Events
            "threat_level": threat_level,
            "events_last_24h": events_24h,
            # Overall health
            "health_score": health_score,
            "health_status": (
                "healthy"
                if health_score >= 70
                else "degraded" if health_score >= 40 else "critical"
            ),
            # Empty state flag for UI
            "empty_state": is_empty_state,
            "empty_state_message": (
                "No data yet. Deploy agents to start monitoring."
                if is_empty_state
                else None
            ),
        }
    )


@health_bp.route("/agents", methods=["GET"])
def agents_health():
    """Detailed health status for all agents"""
    from ..dashboard.agent_discovery import get_all_agents_status

    return jsonify(get_all_agents_status())


@health_bp.route("/ping", methods=["GET"])
def ping():
    """Simple ping endpoint for load balancer health checks"""
    return jsonify(
        {
            "status": "ok",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )
