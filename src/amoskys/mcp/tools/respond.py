"""Response action tools — IGRIS's teeth. Isolate, block, contain, remediate."""

from __future__ import annotations

import json
import time
import uuid
from typing import Optional

from ..db import query, query_one, execute, scalar
from ..config import cfg
from ..server import mcp


def _queue_response(
    device_id: str,
    command_type: str,
    payload: dict,
    priority: int = 1,
    ttl: int = 600,
) -> dict:
    """Queue a high-priority response command."""
    from .agent import _ensure_commands_table
    _ensure_commands_table()
    cmd_id = uuid.uuid4().hex[:16]
    now = time.time()

    execute("""
        INSERT INTO device_commands (id, device_id, command_type, payload,
                                     priority, created_at, expires_at, source)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'igris_response')
    """, (cmd_id, device_id, command_type, json.dumps(payload),
          priority, now, now + ttl))

    return {
        "command_id": cmd_id,
        "device_id": device_id,
        "command_type": command_type,
        "status": "queued",
        "priority": priority,
        "ttl": ttl,
    }


@mcp.tool()
def respond_isolate_device(device_id: str, reason: str) -> dict:
    """Network-isolate a device — block all traffic except AMOSKYS telemetry channel.

    EXTREME action. The device can still report to AMOSKYS but nothing else.
    Use when a device is confirmed compromised and must be contained immediately.

    Args:
        device_id: Device to isolate
        reason:    Why — logged for audit trail
    """
    device = query_one("SELECT hostname FROM devices WHERE device_id = ?", (device_id,))
    if not device:
        return {"error": f"Device {device_id} not found"}

    result = _queue_response(
        device_id, "ISOLATE",
        {"reason": reason, "allow_amoskys": True},
        priority=0,  # Highest possible
        ttl=3600,
    )
    result["action"] = "NETWORK_ISOLATION"
    result["hostname"] = device.get("hostname")
    result["warning"] = "Device will lose all network access except AMOSKYS telemetry"
    return result


@mcp.tool()
def respond_unisolate_device(device_id: str) -> dict:
    """Remove network isolation from a device — restore normal connectivity.

    Args:
        device_id: Device to unisolate
    """
    device = query_one("SELECT hostname FROM devices WHERE device_id = ?", (device_id,))
    if not device:
        return {"error": f"Device {device_id} not found"}

    return _queue_response(
        device_id, "UNISOLATE", {"reason": "manual_release"},
        priority=0, ttl=3600,
    )


@mcp.tool()
def respond_kill_process(device_id: str, pid: int, reason: str) -> dict:
    """Kill a process on a remote device.

    Args:
        device_id: Target device
        pid:       Process ID to terminate
        reason:    Justification — logged for audit
    """
    device = query_one("SELECT hostname FROM devices WHERE device_id = ?", (device_id,))
    if not device:
        return {"error": f"Device {device_id} not found"}

    result = _queue_response(
        device_id, "KILL_PROCESS",
        {"pid": pid, "reason": reason, "signal": "SIGKILL"},
        priority=1,
    )
    result["action"] = f"KILL PID {pid}"
    return result


@mcp.tool()
def respond_block_ip(device_id: str, ip: str, reason: str, duration_minutes: int = 60) -> dict:
    """Block an IP address on a device's firewall.

    Args:
        device_id:        Target device (or 'fleet' for all devices)
        ip:               IP address to block
        reason:           Justification
        duration_minutes: Block duration in minutes (default 60)
    """
    if device_id == "fleet":
        # Fleet-wide block — queue on all online devices
        devices = query("SELECT device_id FROM devices WHERE status = 'online'")
        results = []
        for d in devices:
            r = _queue_response(
                d["device_id"], "BLOCK_IP",
                {"ip": ip, "reason": reason, "duration_s": duration_minutes * 60},
                priority=1,
            )
            results.append(r)
        return {
            "action": f"FLEET-WIDE BLOCK {ip}",
            "devices_targeted": len(results),
            "commands": results,
        }

    device = query_one("SELECT hostname FROM devices WHERE device_id = ?", (device_id,))
    if not device:
        return {"error": f"Device {device_id} not found"}

    return _queue_response(
        device_id, "BLOCK_IP",
        {"ip": ip, "reason": reason, "duration_s": duration_minutes * 60},
        priority=1,
    )


@mcp.tool()
def respond_block_domain(device_id: str, domain: str, reason: str) -> dict:
    """Block DNS resolution of a domain on a device (sinkhole to 127.0.0.1).

    Args:
        device_id: Target device (or 'fleet' for all)
        domain:    Domain to block
        reason:    Justification
    """
    if device_id == "fleet":
        devices = query("SELECT device_id FROM devices WHERE status = 'online'")
        results = []
        for d in devices:
            r = _queue_response(
                d["device_id"], "BLOCK_DOMAIN",
                {"domain": domain, "reason": reason},
                priority=1,
            )
            results.append(r)
        return {
            "action": f"FLEET-WIDE DNS BLOCK {domain}",
            "devices_targeted": len(results),
            "commands": results,
        }

    return _queue_response(
        device_id, "BLOCK_DOMAIN",
        {"domain": domain, "reason": reason},
        priority=1,
    )


@mcp.tool()
def respond_quarantine_file(device_id: str, path: str, reason: str) -> dict:
    """Quarantine a file on a device — move to secure location, strip execute bits.

    Args:
        device_id: Target device
        path:      File path to quarantine
        reason:    Justification
    """
    device = query_one("SELECT hostname FROM devices WHERE device_id = ?", (device_id,))
    if not device:
        return {"error": f"Device {device_id} not found"}

    return _queue_response(
        device_id, "QUARANTINE_FILE",
        {"path": path, "reason": reason},
        priority=1,
    )


@mcp.tool()
def respond_create_incident(
    title: str,
    severity: str,
    description: str,
    device_ids: list[str],
    mitre_techniques: list[str] | None = None,
) -> dict:
    """Create a fleet incident — a correlated threat that spans devices/events.

    Args:
        title:            Short incident title
        severity:         low | medium | high | critical
        description:      Detailed description of what happened
        device_ids:       List of affected device IDs
        mitre_techniques: List of MITRE technique IDs (optional)
    """
    now = time.time()
    execute("""
        INSERT INTO fleet_incidents (severity, title, description, device_ids,
                                     mitre_techniques, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 'open', ?, ?)
    """, (severity, title, description,
          json.dumps(device_ids),
          json.dumps(mitre_techniques or []),
          now, now))

    return {
        "action": "INCIDENT_CREATED",
        "title": title,
        "severity": severity,
        "devices": device_ids,
    }


@mcp.tool()
def respond_update_incident(
    incident_id: int,
    status: str = "",
    severity: str = "",
    description: str = "",
) -> dict:
    """Update an existing incident — change status, escalate severity, add notes.

    Args:
        incident_id: Incident to update
        status:      New status (open, investigating, contained, resolved)
        severity:    New severity (low, medium, high, critical)
        description: Additional notes to append
    """
    incident = query_one("SELECT * FROM fleet_incidents WHERE id = ?", (incident_id,))
    if not incident:
        return {"error": f"Incident {incident_id} not found"}

    updates = []
    params: list = []
    if status:
        updates.append("status = ?")
        params.append(status)
        if status == "resolved":
            updates.append("resolved_at = ?")
            params.append(time.time())
    if severity:
        updates.append("severity = ?")
        params.append(severity)
    if description:
        old_desc = incident.get("description", "")
        updates.append("description = ?")
        params.append(f"{old_desc}\n\n[UPDATE {time.strftime('%Y-%m-%d %H:%M')}] {description}")

    updates.append("updated_at = ?")
    params.append(time.time())
    params.append(incident_id)

    if updates:
        from ..db import write_conn
        with write_conn() as conn:
            conn.execute(
                f"UPDATE fleet_incidents SET {', '.join(updates)} WHERE id = ?",
                tuple(params),
            )

    return {"action": "INCIDENT_UPDATED", "incident_id": incident_id}
