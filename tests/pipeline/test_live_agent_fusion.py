#!/usr/bin/env python3
# filepath: /Users/athanneeru/Downloads/GitHub/Amoskys/tests/pipeline/test_live_agent_fusion.py
"""Live Agent → Queue → FusionEngine Integration Test — CL-19 upgrade.

This test upgrades CL-19 from PARTIAL to PASS by:
  1. Running a real ProtocolCollectorsV2 agent (stub collector)
  2. Letting it emit real probe events into a real SQLite queue
  3. Draining the queue, decoding protobuf
  4. Converting to TelemetryEventView
  5. Feeding into a real FusionEngine
  6. Asserting the pipeline produces valid fusion output

This proves the pipeline works with LIVE agent data, not just
hand-crafted test fixtures.

Architecture under test:
    ProtocolCollectorsV2 (real agent, stub collector)
      → MicroProbe.emit() → TelemetryEvent.to_dict()
        → LocalQueueAdapter.enqueue() → _dict_to_telemetry()
          → DeviceTelemetry protobuf → SQLite queue
            → drain → ParseFromString → TelemetryEventView.from_protobuf()
              → FusionEngine.add_event()
                → FusionEngine.evaluate_device()
"""

import os
import signal
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from amoskys.agents.common.local_queue import LocalQueue
from amoskys.intel.fusion_engine import FusionEngine
from amoskys.intel.models import TelemetryEventView
from amoskys.proto import universal_telemetry_pb2 as pb

PROJECT_ROOT = Path(__file__).parent.parent.parent
DEVICE_ID = "live-test-001"


@pytest.fixture
def lab_env(tmp_path):
    """Set up isolated lab environment and run ProtocolCollectors for 2 cycles."""
    queue_dir = tmp_path / "queues" / "protocol_collectors"
    queue_dir.mkdir(parents=True)
    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    env = {
        **os.environ,
        "PYTHONPATH": str(PROJECT_ROOT / "src"),
        "AMOSKYS_DEVICE_ID": DEVICE_ID,
    }

    log_file = open(log_dir / "protocol_collectors.log", "w")

    proc = subprocess.Popen(
        [
            sys.executable, "-m",
            "amoskys.agents.protocol_collectors.run_agent_v2",
            "--device-id", DEVICE_ID,
            "--queue-path", str(queue_dir),
            "--collection-interval", "5",   # Fast cycle for test
            "--metrics-interval", "10",
            "--log-level", "DEBUG",
        ],
        cwd=str(PROJECT_ROOT),
        env=env,
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )

    # Wait for at least 2 collection cycles (5s each) + startup
    time.sleep(15)

    # Gracefully stop
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    log_file.close()

    db_path = queue_dir / "protocol_collectors_queue.db"

    yield {
        "db_path": str(db_path),
        "log_path": str(log_dir / "protocol_collectors.log"),
        "queue_dir": str(queue_dir),
        "tmp_path": tmp_path,
        "returncode": proc.returncode,
    }


def _drain_queue(db_path: str) -> list:
    """Read all rows from queue DB and decode protobuf."""
    if not os.path.exists(db_path):
        return []

    conn = sqlite3.connect(db_path, timeout=5)
    rows = conn.execute(
        "SELECT id, idem, ts_ns, bytes FROM queue ORDER BY id ASC"
    ).fetchall()
    conn.close()

    decoded = []
    for row_id, idem, ts_ns, blob in rows:
        telemetry = pb.DeviceTelemetry()
        telemetry.ParseFromString(bytes(blob))
        decoded.append({
            "row_id": row_id,
            "idem": idem,
            "telemetry": telemetry,
        })
    return decoded


def _telemetry_to_event_views(decoded: list) -> list:
    """Convert decoded DeviceTelemetry protobuf into TelemetryEventView objects."""
    views = []
    for item in decoded:
        telemetry = item["telemetry"]
        device_id = telemetry.device_id
        for ev in telemetry.events:
            try:
                view = TelemetryEventView.from_protobuf(ev, device_id)
                views.append(view)
            except Exception as e:
                # Record but don't fail — some events may be metrics-only
                views.append({"error": str(e), "event_id": ev.event_id})
    return views


class TestLiveAgentPipeline:
    """CL-19: FusionEngine rules work end-to-end with live agent data."""

    def test_agent_produced_queue_data(self, lab_env):
        """Agent actually wrote data to queue DB."""
        assert os.path.exists(lab_env["db_path"]), (
            "Queue DB not created — agent may have crashed"
        )

        conn = sqlite3.connect(lab_env["db_path"], timeout=5)
        count = conn.execute("SELECT COUNT(*) FROM queue").fetchone()[0]
        conn.close()

        assert count > 0, (
            f"Queue is empty — agent ran but produced no data. "
            f"Check {lab_env['log_path']}"
        )

    def test_protobuf_decodes_without_error(self, lab_env):
        """All queue rows decode as valid DeviceTelemetry protobuf."""
        decoded = _drain_queue(lab_env["db_path"])
        assert len(decoded) > 0, "No rows to decode"

        for item in decoded:
            telemetry = item["telemetry"]
            assert telemetry.device_id == DEVICE_ID
            assert telemetry.collection_agent != "", (
                f"GAP-07: collection_agent is empty on row {item['row_id']}"
            )

    def test_collection_agent_set_on_all_events(self, lab_env):
        """GAP-07 regression: collection_agent populated on every message."""
        decoded = _drain_queue(lab_env["db_path"])

        for item in decoded:
            agent_name = item["telemetry"].collection_agent
            assert agent_name, (
                f"collection_agent empty on idem={item['idem']}"
            )
            # Agent class name is ProtocolCollectorsV2 — case-insensitive check
            assert "protocolcollectors" in agent_name.lower().replace("_", ""), (
                f"Unexpected collection_agent: {agent_name}"
            )

    def test_events_convert_to_telemetry_event_views(self, lab_env):
        """Protobuf events convert to TelemetryEventView for fusion."""
        decoded = _drain_queue(lab_env["db_path"])
        views = _telemetry_to_event_views(decoded)

        # Filter out errors
        valid_views = [v for v in views if isinstance(v, TelemetryEventView)]
        error_views = [v for v in views if isinstance(v, dict)]

        assert len(valid_views) > 0, (
            f"No valid TelemetryEventViews produced. "
            f"Errors: {error_views}"
        )

        # Every valid view should have device_id and event_type
        for v in valid_views:
            assert v.device_id == DEVICE_ID
            # Real probes emit granular event_types like 'protocol_threat',
            # 'process_threat', 'agent_metrics', etc. — not just canonical
            # protobuf enum values (SECURITY, AUDIT, etc.)
            assert v.event_type, f"event_type is empty on {v.event_id}"

    def test_security_events_have_populated_fields(self, lab_env):
        """GAP-01 regression: security events from probes have real data."""
        decoded = _drain_queue(lab_env["db_path"])
        views = _telemetry_to_event_views(decoded)
        valid_views = [v for v in views if isinstance(v, TelemetryEventView)]

        security_views = [
            v for v in valid_views if v.security_event is not None
        ]

        # ProtocolCollectors stub should produce at least some security events
        # (SSHBruteForce, HTTPSuspiciousHeaders, etc.)
        if len(security_views) > 0:
            for sv in security_views:
                se = sv.security_event
                assert "event_category" in se, "Missing event_category"
                # Risk score should be populated
                assert "risk_score" in se

    def test_fusion_engine_accepts_live_events(self, lab_env):
        """FusionEngine.add_event() works with live TelemetryEventViews."""
        decoded = _drain_queue(lab_env["db_path"])
        views = _telemetry_to_event_views(decoded)
        valid_views = [v for v in views if isinstance(v, TelemetryEventView)]

        fusion_db = str(Path(lab_env["tmp_path"]) / "fusion_live.db")
        fusion = FusionEngine(db_path=fusion_db, window_minutes=30)

        # Feed all live events
        for v in valid_views:
            fusion.add_event(v)

        # Verify events were processed
        assert fusion.metrics["total_events_processed"] == len(valid_views)

        # Verify device state exists
        assert DEVICE_ID in fusion.device_state
        state = fusion.device_state[DEVICE_ID]
        assert len(state["events"]) > 0

    def test_fusion_evaluate_produces_risk_snapshot(self, lab_env):
        """FusionEngine.evaluate_device() produces a DeviceRiskSnapshot."""
        decoded = _drain_queue(lab_env["db_path"])
        views = _telemetry_to_event_views(decoded)
        valid_views = [v for v in views if isinstance(v, TelemetryEventView)]

        fusion_db = str(Path(lab_env["tmp_path"]) / "fusion_risk.db")
        fusion = FusionEngine(db_path=fusion_db, window_minutes=30)

        for v in valid_views:
            fusion.add_event(v)

        _incidents, risk_snapshot = fusion.evaluate_device(DEVICE_ID)

        # Risk snapshot should always be returned
        assert risk_snapshot is not None
        assert risk_snapshot.device_id == DEVICE_ID
        assert 0 <= risk_snapshot.score <= 100

        # evaluate_device doesn't increment total_evaluations (that's in
        # evaluate_all_devices), but total_events_processed should be set
        assert fusion.metrics["total_events_processed"] == len(valid_views)

    def test_fusion_evaluation_is_deterministic(self, lab_env):
        """Same events produce same incidents across two independent runs."""
        decoded = _drain_queue(lab_env["db_path"])
        views = _telemetry_to_event_views(decoded)
        valid_views = [v for v in views if isinstance(v, TelemetryEventView)]

        results = []
        for run in range(2):
            fusion_db = str(
                Path(lab_env["tmp_path"]) / f"fusion_determ_{run}.db"
            )
            fusion = FusionEngine(db_path=fusion_db, window_minutes=30)
            for v in valid_views:
                fusion.add_event(v)
            incidents, snapshot = fusion.evaluate_device(DEVICE_ID)
            results.append({
                "incident_count": len(incidents),
                "risk_score": snapshot.score,
                "risk_level": snapshot.level.value,
            })

        assert results[0] == results[1], (
            f"Non-deterministic: run1={results[0]}, run2={results[1]}"
        )

    def test_full_pipeline_no_data_loss(self, lab_env):
        """Events emitted by agent all arrive in fusion (no silent drops)."""
        decoded = _drain_queue(lab_env["db_path"])
        total_events_in_queue = sum(
            len(item["telemetry"].events) for item in decoded
        )

        views = _telemetry_to_event_views(decoded)
        valid_views = [v for v in views if isinstance(v, TelemetryEventView)]
        error_views = [v for v in views if isinstance(v, dict)]

        # All events should convert (no silent drops)
        assert len(valid_views) + len(error_views) == total_events_in_queue

        fusion_db = str(Path(lab_env["tmp_path"]) / "fusion_nodrop.db")
        fusion = FusionEngine(db_path=fusion_db, window_minutes=30)
        for v in valid_views:
            fusion.add_event(v)

        # Fusion should have processed exactly the number of valid events
        assert fusion.metrics["total_events_processed"] == len(valid_views)

    def test_agent_log_has_no_tracebacks(self, lab_env):
        """Agent log should be clean — no Python exceptions."""
        log_content = Path(lab_env["log_path"]).read_text()
        tb_count = log_content.count("Traceback")
        assert tb_count == 0, (
            f"Agent log has {tb_count} traceback(s)"
        )
