"""
AMOSKYS API Agents Module
Agent registration, heartbeat, and status management
"""

from flask import Blueprint, request, jsonify, g
from datetime import datetime, timezone
from .agent_auth import require_auth
from .rate_limiter import require_rate_limit
import psutil
import platform

agents_bp = Blueprint("agents", __name__, url_prefix="/agents")

# In-memory agent registry (replace with database in production)
AGENT_REGISTRY = {}

# Constants
UTC_TIMEZONE_SUFFIX = "+00:00"


@agents_bp.route("/register", methods=["POST"])
@require_rate_limit(max_requests=50, window_seconds=60)
@require_auth(permissions=["agent.register"])
def register_agent():
    """Register a new agent with the AMOSKYS platform"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON payload"}), 400

    agent_id = g.current_user["agent_id"]

    # Collect agent metadata
    agent_info = {
        "agent_id": agent_id,
        "hostname": data.get("hostname", "unknown"),
        "ip_address": request.remote_addr,
        "platform": data.get("platform", platform.platform()),
        "version": data.get("version", "1.0.0"),
        "capabilities": data.get("capabilities", []),
        "registered_at": datetime.now(timezone.utc).isoformat(),
        "last_seen": datetime.now(timezone.utc).isoformat(),
        "status": "active",
    }

    AGENT_REGISTRY[agent_id] = agent_info

    return jsonify(
        {
            "status": "success",
            "message": f"Agent {agent_id} registered successfully",
            "agent_info": agent_info,
        }
    )


@agents_bp.route("/ping", methods=["POST"])
@require_auth(permissions=["agent.ping"])
def agent_ping():
    """Agent heartbeat endpoint"""
    data = request.get_json() or {}
    agent_id = g.current_user["agent_id"]

    # Update agent last seen
    if agent_id in AGENT_REGISTRY:
        AGENT_REGISTRY[agent_id]["last_seen"] = datetime.now(timezone.utc).isoformat()
        AGENT_REGISTRY[agent_id]["status"] = "active"

    # Collect system metrics
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
    except (psutil.Error, OSError):
        cpu_percent = 0
        memory = None
        disk = None

    response_data = {
        "status": "pong",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_id": agent_id,
        "server_time": datetime.now(timezone.utc).isoformat(),
        "system_metrics": {
            "cpu_percent": cpu_percent,
            "memory_percent": memory.percent if memory else 0,
            "disk_percent": (disk.used / disk.total * 100) if disk else 0,
        },
    }

    # Include any server instructions
    if data.get("request_config"):
        response_data["config_update"] = {
            "send_rate": 100,  # events per second
            "retry_max": 6,
            "log_level": "INFO",
        }

    return jsonify(response_data)


@agents_bp.route("/status/<agent_id>", methods=["GET"])
@require_auth(permissions=["agent.status"])
def get_agent_status(agent_id):
    """Get status of a specific agent"""
    if agent_id not in AGENT_REGISTRY:
        return jsonify({"error": "Agent not found"}), 404

    agent_info = AGENT_REGISTRY[agent_id].copy()

    # Calculate uptime
    registered = datetime.fromisoformat(
        agent_info["registered_at"].replace("Z", UTC_TIMEZONE_SUFFIX)
    )
    uptime_seconds = (datetime.now(timezone.utc) - registered).total_seconds()
    agent_info["uptime_seconds"] = uptime_seconds

    return jsonify({"status": "success", "agent_info": agent_info})


@agents_bp.route("/list", methods=["GET"])
@require_auth(permissions=["agent.list"])
def list_agents():
    """List all registered agents"""
    agents = []
    current_time = datetime.now(timezone.utc)

    for agent_id, info in AGENT_REGISTRY.items():
        agent_copy = info.copy()

        # Determine if agent is stale (no ping in last 5 minutes)
        last_seen = datetime.fromisoformat(
            info["last_seen"].replace("Z", UTC_TIMEZONE_SUFFIX)
        )
        seconds_since_ping = (current_time - last_seen).total_seconds()

        if seconds_since_ping > 300:  # 5 minutes
            agent_copy["status"] = "stale"
        elif seconds_since_ping > 600:  # 10 minutes
            agent_copy["status"] = "offline"

        agent_copy["seconds_since_ping"] = seconds_since_ping
        agents.append(agent_copy)

    return jsonify({"status": "success", "agent_count": len(agents), "agents": agents})


@agents_bp.route("/stats", methods=["GET"])
@require_auth()
def agent_stats():
    """Get aggregate agent statistics"""
    current_time = datetime.now(timezone.utc)

    stats = {
        "total_agents": len(AGENT_REGISTRY),
        "active_agents": 0,
        "stale_agents": 0,
        "offline_agents": 0,
    }

    for info in AGENT_REGISTRY.values():
        last_seen = datetime.fromisoformat(
            info["last_seen"].replace("Z", UTC_TIMEZONE_SUFFIX)
        )
        seconds_since_ping = (current_time - last_seen).total_seconds()

        if seconds_since_ping <= 300:  # 5 minutes
            stats["active_agents"] += 1
        elif seconds_since_ping <= 600:  # 10 minutes
            stats["stale_agents"] += 1
        else:
            stats["offline_agents"] += 1

    return jsonify(
        {"status": "success", "timestamp": current_time.isoformat(), "stats": stats}
    )
