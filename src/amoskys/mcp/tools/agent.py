"""Agent control tools — remote lifecycle management of agents on fleet devices."""

from __future__ import annotations

import json
import time
import uuid
from typing import Optional

from ..db import query, query_one, scalar, execute, hours_ago_ns
from ..config import cfg
from ..server import mcp


# ── Command Queue ──────────────────────────────────────────────────


def _ensure_commands_table():
    """Create the device_commands table if it doesn't exist."""
    from ..db import write_conn
    with write_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS device_commands (
                id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                command_type TEXT NOT NULL,
                payload TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL DEFAULT 'pending',
                priority INTEGER NOT NULL DEFAULT 5,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                claimed_at REAL,
                completed_at REAL,
                result TEXT,
                source TEXT NOT NULL DEFAULT 'mcp'
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_commands_device_status
            ON device_commands(device_id, status)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_commands_expires
            ON device_commands(expires_at)
        """)


def _queue_command(
    device_id: str,
    command_type: str,
    payload: dict | None = None,
    priority: int = 5,
    ttl: int | None = None,
) -> dict:
    """Queue a command for a device to pick up on next poll."""
    _ensure_commands_table()
    cmd_id = uuid.uuid4().hex[:16]
    now = time.time()
    expires = now + (ttl or cfg.command_ttl)

    execute("""
        INSERT INTO device_commands (id, device_id, command_type, payload,
                                     priority, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (cmd_id, device_id, command_type, json.dumps(payload or {}),
          priority, now, expires))

    return {
        "command_id": cmd_id,
        "device_id": device_id,
        "command_type": command_type,
        "status": "pending",
        "expires_at": expires,
    }


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

    return _queue_command(device_id, "START_AGENT", {"agent_name": agent_name}, priority=3)


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

    return _queue_command(device_id, "STOP_AGENT", {"agent_name": agent_name}, priority=3)


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

    return _queue_command(device_id, "RESTART_AGENT", {"agent_name": agent_name}, priority=3)


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
        device_id, "UPDATE_CONFIG",
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

    commands = query(f"""
        SELECT id, device_id, command_type, payload, status, priority,
               created_at, expires_at, claimed_at, completed_at, result, source
        FROM device_commands
        {where}
        ORDER BY created_at DESC LIMIT ?
    """, tuple(params))

    return {"commands": commands, "returned": len(commands)}


@mcp.tool()
def agent_fleet_health() -> dict:
    """Agent health across the entire fleet — which agents are active on which devices.

    Cross-references device registration with recent telemetry to determine
    which agents are actually producing data vs. registered but silent.
    """
    cutoff = hours_ago_ns(6)

    # Agents producing data in last 6 hours
    active = query("""
        SELECT device_id, collection_agent,
               COUNT(*) as events,
               MAX(timestamp_ns) as last_event_ns
        FROM security_events
        WHERE timestamp_ns > ?
        GROUP BY device_id, collection_agent
    """, (cutoff,))

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
        devices[did]["agents"].append({
            "agent": row["collection_agent"],
            "events_6h": row["events"],
            "stale": age_s > 7200,
            "last_event_ago": f"{int(age_s)}s",
        })

    return {
        "devices": list(devices.values()),
        "total_devices_with_agents": len(devices),
    }
