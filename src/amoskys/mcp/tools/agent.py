"""Agent control tools — remote lifecycle management of agents on fleet devices."""

from __future__ import annotations

import time
from typing import Optional

from ..db import execute, hours_ago_ns, query, query_one, scalar
from ..server import mcp
from ..command_queue import (
    _ensure_commands_table,
    _queue_command,
    _record_command_decision,
)

# ── Command Queue ──────────────────────────────────────────────────


# ── Tools ──────────────────────────────────────────────────────────


@mcp.tool()
def agent_start(device_id: str, agent_name: str) -> dict:
    """Start a specific agent on a remote device.

    Queues a START_AGENT command — the device's shipper will pick it up
    on its next poll cycle (~10s) and execute locally.

    Args:
        device_id:  Target device
        agent_name: Agent to start (e.g. 'proc-agent', 'dns-agent', 'fim-agent')
    """
    device = query_one("SELECT hostname FROM devices WHERE device_id = ?", (device_id,))
    if not device:
        return {"error": f"Device {device_id} not found"}

    return _queue_command(
        device_id, "START_AGENT", {"agent_name": agent_name}, priority=3
    )


@mcp.tool()
def agent_stop(device_id: str, agent_name: str) -> dict:
    """Stop a specific agent on a remote device.

    Args:
        device_id:  Target device
        agent_name: Agent to stop
    """
    device = query_one("SELECT hostname FROM devices WHERE device_id = ?", (device_id,))
    if not device:
        return {"error": f"Device {device_id} not found"}

    return _queue_command(
        device_id, "STOP_AGENT", {"agent_name": agent_name}, priority=3
    )


@mcp.tool()
def agent_restart(device_id: str, agent_name: str) -> dict:
    """Restart a specific agent on a remote device.

    Args:
        device_id:  Target device
        agent_name: Agent to restart
    """
    device = query_one("SELECT hostname FROM devices WHERE device_id = ?", (device_id,))
    if not device:
        return {"error": f"Device {device_id} not found"}

    return _queue_command(
        device_id, "RESTART_AGENT", {"agent_name": agent_name}, priority=3
    )


@mcp.tool()
def agent_collect_now(device_id: str) -> dict:
    """Trigger an immediate collection cycle on a device — don't wait for the normal interval.

    Args:
        device_id: Target device
    """
    device = query_one("SELECT hostname FROM devices WHERE device_id = ?", (device_id,))
    if not device:
        return {"error": f"Device {device_id} not found"}

    return _queue_command(device_id, "COLLECT_NOW", priority=2)


@mcp.tool()
def agent_update_config(device_id: str, config_key: str, config_value: str) -> dict:
    """Push a configuration change to a device's agent.

    Args:
        device_id:    Target device
        config_key:   Configuration key (e.g. 'SHIP_INTERVAL_S', 'LOG_LEVEL')
        config_value: New value
    """
    return _queue_command(
        device_id,
        "UPDATE_CONFIG",
        {"key": config_key, "value": config_value},
        priority=4,
    )


@mcp.tool()
def agent_list_commands(
    device_id: str = "",
    status: str = "",
    limit: int = 20,
) -> dict:
    """List queued/executed commands for a device.

    Args:
        device_id: Filter to device (optional)
        status:    Filter by status (pending, claimed, completed, expired)
        limit:     Max rows
    """
    _ensure_commands_table()
    clauses: list[str] = []
    params: list = []

    if device_id:
        clauses.append("device_id = ?")
        params.append(device_id)
    if status:
        clauses.append("status = ?")
        params.append(status)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)

    commands = query(
        f"""
        SELECT id, device_id, command_type, payload, status, priority,
               created_at, expires_at, claimed_at, completed_at, result,
               requested_by, reason, policy_decision, dedup_key,
               rollback_plan, source
        FROM device_commands
        {where}
        ORDER BY created_at DESC LIMIT ?
    """,
        tuple(params),
    )

    return {"commands": commands, "returned": len(commands)}


@mcp.tool()
def agent_fleet_health() -> dict:
    """Agent health across the entire fleet — which agents are active on which devices.

    Cross-references device registration with recent telemetry to determine
    which agents are actually producing data vs. registered but silent.
    """
    cutoff = hours_ago_ns(6)

    # Agents producing data in last 6 hours
    active = query(
        """
        SELECT device_id, collection_agent,
               COUNT(*) as events,
               MAX(timestamp_ns) as last_event_ns
        FROM security_events
        WHERE timestamp_ns > ?
        GROUP BY device_id, collection_agent
    """,
        (cutoff,),
    )

    # Group by device
    devices: dict = {}
    now_ns = int(time.time() * 1e9)
    for row in active:
        did = row["device_id"]
        if did not in devices:
            dev = query_one(
                "SELECT hostname, os, status FROM devices WHERE device_id = ?",
                (did,),
            )
            devices[did] = {
                "device_id": did,
                "hostname": (dev or {}).get("hostname", "unknown"),
                "agents": [],
            }
        age_s = (now_ns - (row["last_event_ns"] or 0)) / 1e9
        devices[did]["agents"].append(
            {
                "agent": row["collection_agent"],
                "events_6h": row["events"],
                "stale": age_s > 7200,
                "last_event_ago": f"{int(age_s)}s",
            }
        )

    return {
        "devices": list(devices.values()),
        "total_devices_with_agents": len(devices),
    }
