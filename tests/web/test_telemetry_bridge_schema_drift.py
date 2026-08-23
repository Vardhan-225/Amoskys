from __future__ import annotations

import importlib.util
import sqlite3
from pathlib import Path


def _load_bridge():
    repo_root = Path(__file__).resolve().parents[2]
    bridge_path = repo_root / "web" / "app" / "dashboard" / "telemetry_bridge.py"
    spec = importlib.util.spec_from_file_location(
        "telemetry_bridge_under_test", bridge_path
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _memory_cache(bridge):
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    bridge._create_minimal_schema(db)
    bridge._ensure_fleet_cache_contract(db)
    return db


def test_fleet_lineage_and_verdict_fields_round_trip_without_dropped_drift():
    bridge = _load_bridge()
    db = _memory_cache(bridge)
    now_ns = 1_700_000_000_000_000_000

    inserted_security = bridge._upsert_rows(
        db,
        "security_events",
        [
            {
                "source_id": "src-1",
                "device_id": "dev-1",
                "org_id": "org-1",
                "event_timestamp_ns": now_ns,
                "event_category": "PROCESS",
                "event_action": "exec",
                "risk_score": 0.91,
                "received_at": 1_700_000_000.0,
                "event_id": "evt-1",
                "quality_state": "valid",
                "verdict": "look",
                "final_classification": "suspicious",
                "composite_score": 0.42,
                "risk_score_raw": 0.91,
                "last_scored": 1_700_000_001,
                "raw_attributes_json": {"exe": "/bin/zsh"},
            }
        ],
    )
    inserted_process = bridge._upsert_rows(
        db,
        "process_events",
        [
            {
                "timestamp_ns": now_ns,
                "device_id": "dev-1",
                "pid": 4242,
                "org_id": "org-1",
                "source_id": "src-1",
                "received_at": 1_700_000_000.0,
                "name": "zsh",
                "parent_name": "Terminal",
                "status": "running",
                "quality_state": "valid",
            }
        ],
    )

    assert inserted_security == 1
    assert inserted_process == 1

    security = db.execute(
        """
        SELECT org_id, source_id, received_at, event_id, quality_state, verdict,
               final_classification, composite_score, risk_score_raw, last_scored,
               raw_attributes_json
        FROM security_events
        """
    ).fetchone()
    process = db.execute(
        """
        SELECT org_id, source_id, received_at, name, parent_name, status,
               quality_state
        FROM process_events
        """
    ).fetchone()

    assert dict(security) == {
        "org_id": "org-1",
        "source_id": "src-1",
        "received_at": 1_700_000_000.0,
        "event_id": "evt-1",
        "quality_state": "valid",
        "verdict": "look",
        "final_classification": "suspicious",
        "composite_score": 0.42,
        "risk_score_raw": 0.91,
        "last_scored": 1_700_000_001,
        "raw_attributes_json": '{"exe": "/bin/zsh"}',
    }
    assert dict(process) == {
        "org_id": "org-1",
        "source_id": "src-1",
        "received_at": 1_700_000_000.0,
        "name": "zsh",
        "parent_name": "Terminal",
        "status": "running",
        "quality_state": "valid",
    }

    dropped = db.execute(
        """
        SELECT table_name, column_name, action
        FROM schema_drift_events
        WHERE action IN ('dropped', 'failed')
        """
    ).fetchall()
    assert dropped == []


def test_unstorable_ops_key_records_schema_drift_event():
    bridge = _load_bridge()
    db = _memory_cache(bridge)

    inserted = bridge._upsert_rows(
        db,
        "process_events",
        [
            {
                "timestamp_ns": 1_700_000_000_000_000_000,
                "device_id": "dev-1",
                "pid": 4242,
                "bad-key": "cannot be a sqlite column",
            }
        ],
    )

    assert inserted == 1
    assert "bad-key" not in bridge._get_table_columns(db, "process_events")

    drift = db.execute(
        """
        SELECT table_name, column_name, action, reason
        FROM schema_drift_events
        WHERE action IN ('dropped', 'failed')
        """
    ).fetchall()
    assert [dict(row) for row in drift] == [
        {
            "table_name": "process_events",
            "column_name": "bad-key",
            "action": "dropped",
            "reason": "unsafe table or column identifier",
        }
    ]
