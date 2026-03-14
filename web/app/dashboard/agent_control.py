"""
AMOSKYS Agent Control and Auto-Start Management
Provides lifecycle management for discovered agents with health monitoring
"""

import logging
import os
import platform
import signal
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil

from .agent_discovery import AGENT_CATALOG, get_platform_name

logger = logging.getLogger(__name__)

# Agent process tracking
RUNNING_PROCESSES = {}


def find_process_by_pattern(pattern: str) -> Optional[psutil.Process]:
    """Find a process matching the given pattern"""
    try:
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                if (
                    pattern.lower() in str(proc.cmdline()).lower()
                    or pattern.lower() in proc.name().lower()
                ):
                    return proc
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        logger.warning("Process search failed for pattern %s", pattern, exc_info=True)
    return None


def is_port_open(port: int) -> bool:
    """Check if a port is listening"""
    if port is None:
        return False
    try:
        sock = __import__("socket").socket()
        sock.settimeout(1)
        result = sock.connect_ex(("127.0.0.1", port))
        sock.close()
        return result == 0
    except Exception:
        logger.debug("Port check failed for port %d", port, exc_info=True)
        return False


def start_agent(agent_id: str) -> Dict[str, Any]:
    """
    Start an agent with proper error handling and logging

    Args:
        agent_id: The agent ID to start

    Returns:
        Status dict with success/error information
    """
    if agent_id not in AGENT_CATALOG:
        return {
            "status": "error",
            "agent_id": agent_id,
            "message": f"Unknown agent: {agent_id}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    agent_config = AGENT_CATALOG[agent_id]
    current_platform = platform.system().lower()

    # Check platform compatibility
    if current_platform not in agent_config["platform"]:
        return {
            "status": "error",
            "agent_id": agent_id,
            "message": f"Agent {agent_id} not compatible with {current_platform}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # Check if already running (try all patterns)
    existing = None
    for _pat in agent_config["process_patterns"]:
        existing = find_process_by_pattern(_pat)
        if existing:
            break
    if existing:
        return {
            "status": "already_running",
            "agent_id": agent_id,
            "pid": existing.pid,
            "message": f"Agent {agent_id} already running",
            "uptime_seconds": int(time.time() - existing.create_time()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # Determine startup command based on agent type
    try:
        cmd = _build_startup_command(agent_id, agent_config)
        if not cmd:
            return {
                "status": "error",
                "agent_id": agent_id,
                "message": f"Unable to determine startup command for {agent_id}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        # Start the process — redirect output to log files instead of PIPE
        # (PIPE without reader causes buffer fill → process death)
        # Set cwd to repo root so agents find certs/ and config/
        repo_root = Path(__file__).parent.parent.parent.parent
        log_dir = repo_root / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_out = open(log_dir / f"{agent_id}.log", "a")
        log_err = open(log_dir / f"{agent_id}.err.log", "a")

        # Build environment with PYTHONPATH so subprocesses find amoskys.*
        env = os.environ.copy()
        src_dir = str(repo_root / "src")
        web_dir = str(repo_root / "web")
        existing = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = os.pathsep.join(
            [p for p in [src_dir, str(repo_root), web_dir, existing] if p]
        )
        env.setdefault("EVENTBUS_ALLOW_UNSIGNED", "true")
        env.setdefault("EVENTBUS_REQUIRE_CLIENT_AUTH", "false")

        proc = subprocess.Popen(
            cmd,
            stdout=log_out,
            stderr=log_err,
            cwd=str(repo_root),
            env=env,
            preexec_fn=os.setsid if hasattr(os, "setsid") else None,
        )

        RUNNING_PROCESSES[agent_id] = proc

        # Give it a moment to start
        time.sleep(1)

        return {
            "status": "started",
            "agent_id": agent_id,
            "pid": proc.pid,
            "message": f"Agent {agent_id} started successfully",
            "command": " ".join(cmd) if isinstance(cmd, list) else cmd,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except FileNotFoundError as e:
        logger.error("Startup script not found for agent %s: %s", agent_id, e)
        return {
            "status": "error",
            "agent_id": agent_id,
            "message": f"Startup script not found: {str(e)}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        logger.exception("Failed to start agent %s", agent_id)
        return {
            "status": "error",
            "agent_id": agent_id,
            "message": f"Failed to start agent: {str(e)}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


def stop_agent(agent_id: str) -> Dict[str, Any]:
    """
    Stop a running agent gracefully

    Args:
        agent_id: The agent ID to stop

    Returns:
        Status dict with success/error information
    """
    if agent_id not in AGENT_CATALOG:
        return {
            "status": "error",
            "agent_id": agent_id,
            "message": f"Unknown agent: {agent_id}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    agent_config = AGENT_CATALOG[agent_id]

    # Try to find running process (check all configured patterns)
    proc = None
    for _pat in agent_config["process_patterns"]:
        proc = find_process_by_pattern(_pat)
        if proc:
            break

    if not proc:
        return {
            "status": "not_running",
            "agent_id": agent_id,
            "message": f"Agent {agent_id} is not running",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    try:
        # Graceful shutdown
        if hasattr(signal, "SIGTERM"):
            proc.send_signal(signal.SIGTERM)
        else:
            proc.terminate()

        # Wait for graceful shutdown
        proc.wait(timeout=5)

        if agent_id in RUNNING_PROCESSES:
            del RUNNING_PROCESSES[agent_id]

        return {
            "status": "stopped",
            "agent_id": agent_id,
            "pid": proc.pid,
            "message": f"Agent {agent_id} stopped gracefully",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except psutil.TimeoutExpired:
        # Force kill if graceful shutdown fails
        logger.warning(
            "Agent %s did not stop gracefully, force killing (pid=%d)",
            agent_id,
            proc.pid,
        )
        try:
            proc.kill()
            if agent_id in RUNNING_PROCESSES:
                del RUNNING_PROCESSES[agent_id]

            return {
                "status": "force_killed",
                "agent_id": agent_id,
                "pid": proc.pid,
                "message": f"Agent {agent_id} force killed (graceful shutdown timeout)",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            logger.exception("Failed to force kill agent %s", agent_id)
            return {
                "status": "error",
                "agent_id": agent_id,
                "message": f"Failed to kill agent: {str(e)}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    except Exception as e:
        logger.exception("Failed to stop agent %s", agent_id)
        return {
            "status": "error",
            "agent_id": agent_id,
            "message": f"Failed to stop agent: {str(e)}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


def get_agent_status(agent_id: str) -> Dict[str, Any]:
    """Get detailed status of a specific agent"""
    if agent_id not in AGENT_CATALOG:
        return {
            "status": "error",
            "agent_id": agent_id,
            "message": f"Unknown agent: {agent_id}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    agent_config = AGENT_CATALOG[agent_id]

    # Try to find running process (check all configured patterns)
    proc = None
    for _pat in agent_config["process_patterns"]:
        proc = find_process_by_pattern(_pat)
        if proc:
            break

    if proc:
        try:
            uptime = time.time() - proc.create_time()
            memory = proc.memory_info()

            return {
                "agent_id": agent_id,
                "name": agent_config["name"],
                "status": "running",
                "pid": proc.pid,
                "uptime_seconds": int(uptime),
                "cpu_percent": proc.cpu_percent(interval=0.1),
                "memory_mb": memory.rss / (1024 * 1024),
                "threads": proc.num_threads(),
                "port": agent_config["port"],
                "port_open": (
                    is_port_open(agent_config["port"]) if agent_config["port"] else None
                ),
                "platform": get_platform_name(),
                "capabilities": agent_config["capabilities"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            logger.debug("Agent %s process vanished during status check", agent_id)

    # Not running
    return {
        "agent_id": agent_id,
        "name": agent_config["name"],
        "status": "stopped",
        "pid": None,
        "uptime_seconds": 0,
        "cpu_percent": 0.0,
        "memory_mb": 0.0,
        "threads": 0,
        "port": agent_config["port"],
        "port_open": False,
        "platform": get_platform_name(),
        "capabilities": agent_config["capabilities"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def get_all_agents_status_detailed() -> Dict[str, Any]:
    """Get detailed status of all agents"""
    agents_status = []

    for agent_id in AGENT_CATALOG:
        agents_status.append(get_agent_status(agent_id))

    # Calculate summary
    running_count = sum(1 for a in agents_status if a["status"] == "running")
    stopped_count = len(agents_status) - running_count

    return {
        "agents": agents_status,
        "total": len(agents_status),
        "running": running_count,
        "stopped": stopped_count,
        "platform": get_platform_name(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def health_check_agent(agent_id: str) -> Dict[str, Any]:
    """
    Perform health check on an agent
    Returns detailed health metrics
    """
    status = get_agent_status(agent_id)

    health_result = {
        "agent_id": agent_id,
        "healthy": True,
        "issues": [],
        "warnings": [],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    if status["status"] != "running":
        health_result["healthy"] = False
        health_result["issues"].append("Agent is not running")
        return health_result

    agent_config = AGENT_CATALOG[agent_id]

    # Check port if applicable
    if agent_config["port"] and not status["port_open"]:
        health_result["issues"].append(f'Port {agent_config["port"]} is not listening')
        health_result["healthy"] = False

    # Check resource usage
    if status["cpu_percent"] > 90:
        health_result["warnings"].append(
            f'High CPU usage: {status["cpu_percent"]:.1f}%'
        )

    if status["memory_mb"] > 500:  # 500MB threshold
        health_result["warnings"].append(
            f'High memory usage: {status["memory_mb"]:.1f}MB'
        )

    if status["threads"] > 100:
        health_result["warnings"].append(f'High thread count: {status["threads"]}')

    health_result["details"] = status
    return health_result


def _build_startup_command(
    _agent_id: str, config: Dict[str, Any]
) -> Optional[List[str]]:
    """Build the appropriate startup command for an agent.

    Uses the 'module' field from AGENT_CATALOG to run agents via
    ``python -m <module>``.  All agents (including EventBus) follow
    the same pattern.
    """
    import sys

    python_exe = sys.executable

    module = config.get("module")
    if module:
        return [python_exe, "-m", module]

    return None


def get_startup_logs(agent_id: str, lines: int = 50) -> Dict[str, Any]:
    """Get recent startup logs for an agent"""
    log_dir = Path(__file__).parent.parent.parent.parent / "logs"
    log_file = log_dir / f"{agent_id}.log"

    if not log_file.exists():
        return {
            "agent_id": agent_id,
            "available": False,
            "message": "No logs available",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    try:
        with open(log_file, "r") as f:
            log_lines = f.readlines()[-lines:]
            log_content = "".join(log_lines)

        return {
            "agent_id": agent_id,
            "available": True,
            "lines": len(log_lines),
            "content": log_content,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        logger.exception("Failed to read startup logs for agent %s", agent_id)
        return {
            "agent_id": agent_id,
            "available": False,
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
