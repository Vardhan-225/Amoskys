from __future__ import annotations

import json
import sqlite3

from amoskys.mcp import db as mcp_db
from amoskys.mcp.brain import ACTION_BUDGETS, BrainSignal, IGRISCloudBrain


EXPECTED_AGENTS = {
    "macos_proc",
    "macos_auth",
    "macos_fim",
    "macos_flow",
    "macos_dns",
    "macos_peripheral",
    "macos_persistence",
}


def _use_fleet_db(request, tmp_path):
    path = tmp_path / "fleet.db"
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE devices (
            device_id TEXT PRIMARY KEY,
            hostname TEXT,
            status TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE security_events (
            device_id TEXT,
            collection_agent TEXT,
            timestamp_ns INTEGER
        )
        """
    )
    conn.commit()
    conn.close()
    original = mcp_db.cfg.fleet_db
    object.__setattr__(mcp_db.cfg, "fleet_db", str(path))
    request.addfinalizer(lambda: object.__setattr__(mcp_db.cfg, "fleet_db", original))
    return path


def _rows(path, sql, params=()):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def test_stale_agent_restart_budget_caps_loop_and_records_suppression(
    request, tmp_path
):
    db_path = _use_fleet_db(request, tmp_path)
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO devices (device_id, hostname, status) VALUES (?, ?, ?)",
        ("dev-1", "Akash-Mac", "online"),
    )
    conn.commit()
    conn.close()

    brain = IGRISCloudBrain()
    for _ in range(5):
        brain._self_heal_cycle({"events.freshness_s": 0})

    commands = _rows(
        db_path,
        """
        SELECT command_type, status, requested_by, reason, policy_decision,
               dedup_key, result, rollback_plan
        FROM device_commands
        WHERE command_type = 'RESTART_AGENT'
        ORDER BY created_at ASC
        """,
    )
    pending = [row for row in commands if row["status"] == "pending"]
    suppressed = [row for row in commands if row["status"] == "suppressed"]

    assert len(pending) == len(EXPECTED_AGENTS)
    assert len(suppressed) == len(EXPECTED_AGENTS)
    assert all(row["requested_by"] == "igris_brain" for row in commands)
    assert all(row["reason"] for row in commands)
    assert all(row["dedup_key"] for row in commands)
    assert all(row["policy_decision"].startswith("allowed:") for row in pending)
    assert all(row["policy_decision"] == "suppressed_by_budget" for row in suppressed)
    assert all(json.loads(row["result"]).get("status") for row in commands)

    blindness = _rows(
        db_path,
        """
        SELECT sensor, kind, status, reason, count, evidence
        FROM blindness_events
        WHERE kind = 'action_budget_suppressed'
        ORDER BY sensor ASC
        """,
    )
    assert len(blindness) == len(EXPECTED_AGENTS)
    assert all(row["status"] == "degraded" for row in blindness)
    assert all(row["count"] == 4 for row in blindness)
    assert all("Suppressed by budget" in row["reason"] for row in blindness)
    assert {
        json.loads(row["evidence"])["payload"]["agent_name"] for row in blindness
    } == EXPECTED_AGENTS


def test_restart_budget_releases_after_window(request, tmp_path):
    db_path = _use_fleet_db(request, tmp_path)
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO devices (device_id, hostname, status) VALUES (?, ?, ?)",
        ("dev-1", "Akash-Mac", "online"),
    )
    conn.commit()
    conn.close()

    brain = IGRISCloudBrain()
    payload = {"agent_name": "macos_proc"}
    condition = "agent_silent:macos_proc"
    first = brain._queue_governed_command(
        "dev-1",
        "RESTART_AGENT",
        payload,
        priority=2,
        reason="IGRIS self-heal: macos_proc has not reported recently",
        condition=condition,
    )
    assert first["status"] == "pending"

    window_s = ACTION_BUDGETS["RESTART_AGENT"]["window_s"]
    original = _rows(
        db_path,
        "SELECT created_at, expires_at FROM device_commands WHERE id = ?",
        (first["command_id"],),
    )[0]
    command_ttl = original["expires_at"] - original["created_at"]
    aged_created_at = original["created_at"] - window_s - 1
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        UPDATE device_commands
        SET created_at = ?, expires_at = ?
        WHERE id = ?
        """,
        (
            aged_created_at,
            aged_created_at + command_ttl,
            first["command_id"],
        ),
    )
    conn.commit()
    conn.close()

    second = brain._queue_governed_command(
        "dev-1",
        "RESTART_AGENT",
        payload,
        priority=2,
        reason="IGRIS self-heal: macos_proc has not reported recently",
        condition=condition,
    )

    assert second["status"] == "pending"
    assert second["policy_decision"].startswith("allowed:")
    commands = _rows(
        db_path,
        """
        SELECT status, policy_decision
        FROM device_commands
        WHERE command_type = 'RESTART_AGENT'
        ORDER BY created_at ASC
        """,
    )
    assert [row["status"] for row in commands] == ["pending", "pending"]
    assert all(row["policy_decision"].startswith("allowed:") for row in commands)


def test_block_ip_requires_corroboration_and_allowed_action_has_rollback(
    request, tmp_path
):
    db_path = _use_fleet_db(request, tmp_path)
    brain = IGRISCloudBrain()
    payload = {
        "ip": "203.0.113.10",
        "reason": "IGRIS Brain: lateral movement",
        "duration_s": ACTION_BUDGETS["BLOCK_IP"]["ttl_s"],
    }
    weak_signal = BrainSignal(
        signal_id="sig-1",
        signal_type="LATERAL_MOVEMENT",
        severity="critical",
        message="single-device lateral movement candidate",
        confidence=0.8,
        evidence=[{"ip": "203.0.113.10", "max_risk": 0.9}],
        device_ids=["dev-1"],
    )

    denied = brain._queue_governed_command(
        "dev-1",
        "BLOCK_IP",
        payload,
        priority=1,
        ttl=ACTION_BUDGETS["BLOCK_IP"]["ttl_s"],
        reason=payload["reason"],
        condition="lateral_movement:203.0.113.10",
        signal=weak_signal,
        evidence=weak_signal.evidence[0],
    )

    assert denied["status"] == "suppressed"
    assert denied["policy_decision"] == "suppressed_by_policy"

    strong_signal = BrainSignal(
        signal_id="sig-2",
        signal_type="LATERAL_MOVEMENT",
        severity="critical",
        message="corroborated lateral movement",
        confidence=0.9,
        evidence=[{"ip": "203.0.113.10", "max_risk": 0.9}],
        device_ids=["dev-1", "dev-2"],
    )
    allowed = brain._queue_governed_command(
        "dev-2",
        "BLOCK_IP",
        payload,
        priority=1,
        ttl=ACTION_BUDGETS["BLOCK_IP"]["ttl_s"],
        reason=payload["reason"],
        condition="lateral_movement:203.0.113.10",
        signal=strong_signal,
        evidence=strong_signal.evidence[0],
    )

    assert allowed["status"] == "pending"
    assert allowed["policy_decision"].startswith("allowed:")

    row = _rows(
        db_path,
        """
        SELECT created_at, expires_at, requested_by, reason, policy_decision,
               rollback_plan, result
        FROM device_commands
        WHERE id = ?
        """,
        (allowed["command_id"],),
    )[0]
    rollback = json.loads(row["rollback_plan"])
    receipt = json.loads(row["result"])

    assert row["expires_at"] - row["created_at"] <= ACTION_BUDGETS["BLOCK_IP"]["ttl_s"]
    assert row["requested_by"] == "igris_brain"
    assert row["reason"]
    assert row["policy_decision"].startswith("allowed:")
    assert rollback["command_type"] == "UNBLOCK_IP"
    assert rollback["payload"]["ip"] == "203.0.113.10"
    assert receipt["status"] == "pending"


def test_mcp_agent_and_response_tools_write_command_receipts(request, tmp_path):
    db_path = _use_fleet_db(request, tmp_path)
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO devices (device_id, hostname, status) VALUES (?, ?, ?)",
        ("dev-1", "Akash-Mac", "online"),
    )
    conn.commit()
    conn.close()

    from amoskys.mcp.tools import agent, respond

    restart = agent.agent_restart("dev-1", "macos_proc")
    block = respond.respond_block_ip(
        "dev-1", "203.0.113.10", "manual containment smoke", 1
    )

    assert restart["status"] == "pending"
    assert block["status"] == "queued"

    rows = _rows(
        db_path,
        """
        SELECT command_type, requested_by, reason, policy_decision, source, result
        FROM device_commands
        ORDER BY created_at ASC
        """,
    )

    assert rows[0]["command_type"] == "RESTART_AGENT"
    assert rows[0]["requested_by"] == "mcp"
    assert rows[0]["policy_decision"] == "allowed"
    assert rows[0]["source"] == "mcp"
    assert json.loads(rows[0]["result"])["status"] == "pending"

    assert rows[1]["command_type"] == "BLOCK_IP"
    assert rows[1]["requested_by"] == "igris_response"
    assert rows[1]["reason"] == "manual containment smoke"
    assert rows[1]["policy_decision"] == "allowed:manual_response"
    assert rows[1]["source"] == "igris_response"
    assert json.loads(rows[1]["result"])["status"] == "pending"
