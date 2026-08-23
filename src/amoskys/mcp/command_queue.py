"""Server-free device command queue and policy ledger helpers."""

from __future__ import annotations

import json
import time
import uuid

from .config import cfg
from .db import execute, query_one


def _record_budget_blindness(
    device_id: str,
    command_type: str,
    payload: dict | None,
    *,
    reason: str,
    policy_decision: str,
    dedup_key: str,
    source: str,
) -> None:
    """Project action-budget suppressions into the blindness ledger."""
    if policy_decision != "suppressed_by_budget":
        return
    try:
        from amoskys.observability.blindness import record_blindness_event

        from .db import write_conn

        with write_conn() as conn:
            record_blindness_event(
                conn,
                device_id=device_id,
                sensor=f"igris:{command_type}",
                kind="action_budget_suppressed",
                status="degraded",
                reason=reason,
                evidence={
                    "command_type": command_type,
                    "payload": payload or {},
                    "policy_decision": policy_decision,
                    "dedup_key": dedup_key,
                },
                source=source or "igris_command_queue",
                event_key=(
                    f"command:{device_id}:{command_type}:"
                    f"{policy_decision}:{dedup_key}"
                ),
            )
    except Exception:
        # Command governance must never fail closed because the visibility
        # ledger could not be updated. The command receipt remains canonical.
        pass


def _ensure_commands_table():
    """Create or migrate the device_commands ledger table."""
    from .db import write_conn

    with write_conn() as conn:
        conn.execute(
            """
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
                requested_by TEXT NOT NULL DEFAULT 'mcp',
                reason TEXT NOT NULL DEFAULT '',
                policy_decision TEXT NOT NULL DEFAULT 'allowed',
                dedup_key TEXT NOT NULL DEFAULT '',
                rollback_plan TEXT NOT NULL DEFAULT '{}',
                source TEXT NOT NULL DEFAULT 'mcp'
            )
        """
        )
        for column, ddl in (
            ("requested_by", "TEXT NOT NULL DEFAULT 'mcp'"),
            ("reason", "TEXT NOT NULL DEFAULT ''"),
            ("policy_decision", "TEXT NOT NULL DEFAULT 'allowed'"),
            ("dedup_key", "TEXT NOT NULL DEFAULT ''"),
            ("rollback_plan", "TEXT NOT NULL DEFAULT '{}'"),
            ("source", "TEXT NOT NULL DEFAULT 'mcp'"),
        ):
            try:
                conn.execute(f"ALTER TABLE device_commands ADD COLUMN {column} {ddl}")
            except Exception:
                pass
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_commands_device_status
            ON device_commands(device_id, status)
        """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_commands_expires
            ON device_commands(expires_at)
        """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_commands_policy_dedup
            ON device_commands(device_id, command_type, policy_decision, dedup_key, created_at)
        """
        )


def _queue_command(
    device_id: str,
    command_type: str,
    payload: dict | None = None,
    priority: int = 5,
    ttl: int | None = None,
    requested_by: str = "mcp",
    reason: str = "",
    policy_decision: str = "allowed",
    dedup_key: str = "",
    rollback: dict | None = None,
    source: str = "mcp",
) -> dict:
    """Queue a command for a device to pick up on next poll."""
    _ensure_commands_table()
    cmd_id = uuid.uuid4().hex[:16]
    now = time.time()
    expires = now + (ttl or cfg.command_ttl)
    result = {"status": "pending", "policy_decision": policy_decision}

    execute(
        """
        INSERT INTO device_commands (id, device_id, command_type, payload,
                                     priority, created_at, expires_at, result,
                                     requested_by, reason, policy_decision,
                                     dedup_key, rollback_plan, source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
        (
            cmd_id,
            device_id,
            command_type,
            json.dumps(payload or {}),
            priority,
            now,
            expires,
            json.dumps(result),
            requested_by,
            reason,
            policy_decision,
            dedup_key,
            json.dumps(rollback or {}),
            source,
        ),
    )

    return {
        "command_id": cmd_id,
        "device_id": device_id,
        "command_type": command_type,
        "status": "pending",
        "expires_at": expires,
        "requested_by": requested_by,
        "reason": reason,
        "policy_decision": policy_decision,
        "dedup_key": dedup_key,
        "rollback": rollback or {},
    }


def _record_command_decision(
    device_id: str,
    command_type: str,
    payload: dict | None = None,
    priority: int = 5,
    requested_by: str = "mcp",
    reason: str = "",
    policy_decision: str = "suppressed",
    dedup_key: str = "",
    rollback: dict | None = None,
    source: str = "mcp",
    status: str = "suppressed",
    ttl: int | None = None,
) -> dict:
    """Record a non-queued command decision in the command ledger."""
    _ensure_commands_table()
    now = time.time()
    expires = now + (ttl or cfg.command_ttl)

    if status == "suppressed" and dedup_key:
        existing = query_one(
            """
            SELECT id, created_at FROM device_commands
            WHERE device_id = ? AND command_type = ? AND status = 'suppressed'
              AND dedup_key = ? AND policy_decision = ?
              AND created_at >= ?
            ORDER BY created_at DESC LIMIT 1
            """,
            (
                device_id,
                command_type,
                dedup_key,
                policy_decision,
                now - (ttl or cfg.command_ttl),
            ),
        )
        if existing:
            _record_budget_blindness(
                device_id,
                command_type,
                payload,
                reason=reason,
                policy_decision=policy_decision,
                dedup_key=dedup_key,
                source=source,
            )
            return {
                "command_id": existing["id"],
                "device_id": device_id,
                "command_type": command_type,
                "status": status,
                "requested_by": requested_by,
                "reason": reason,
                "policy_decision": policy_decision,
                "dedup_key": dedup_key,
                "rollback": rollback or {},
                "deduped": True,
            }

    cmd_id = uuid.uuid4().hex[:16]
    result = {
        "status": status,
        "success": False,
        "suppressed": status == "suppressed",
        "policy_decision": policy_decision,
        "reason": reason,
    }
    execute(
        """
        INSERT INTO device_commands (id, device_id, command_type, payload,
                                     status, priority, created_at, expires_at,
                                     completed_at, result, requested_by, reason,
                                     policy_decision, dedup_key, rollback_plan, source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            cmd_id,
            device_id,
            command_type,
            json.dumps(payload or {}),
            status,
            priority,
            now,
            expires,
            now,
            json.dumps(result),
            requested_by,
            reason,
            policy_decision,
            dedup_key,
            json.dumps(rollback or {}),
            source,
        ),
    )
    _record_budget_blindness(
        device_id,
        command_type,
        payload,
        reason=reason,
        policy_decision=policy_decision,
        dedup_key=dedup_key,
        source=source,
    )
    return {
        "command_id": cmd_id,
        "device_id": device_id,
        "command_type": command_type,
        "status": status,
        "requested_by": requested_by,
        "reason": reason,
        "policy_decision": policy_decision,
        "dedup_key": dedup_key,
        "rollback": rollback or {},
    }
