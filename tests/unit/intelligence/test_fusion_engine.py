"""
Tests for amoskys.intel.fusion_engine

Covers:
  - FusionEngine initialization and database schema creation
  - Event ingestion and device buffer management
  - Device risk score calculation (all scoring rules)
  - Incident persistence and retrieval
  - Risk snapshot persistence and retrieval
  - evaluate_all_devices orchestration
  - Error handling and edge cases
"""

import json
import os
import sqlite3
import tempfile
import time
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from amoskys.intel.models import (
    DeviceRiskSnapshot,
    Incident,
    RiskLevel,
    Severity,
    TelemetryEventView,
)

# ── Helpers ──────────────────────────────────────────────────────────


def _make_event(
    event_id: str = "evt-001",
    device_id: str = "macbook-test",
    event_type: str = "METRIC",
    severity: str = "INFO",
    timestamp: datetime | None = None,
    attributes: dict | None = None,
    security_event: dict | None = None,
    audit_event: dict | None = None,
    process_event: dict | None = None,
    flow_event: dict | None = None,
) -> TelemetryEventView:
    return TelemetryEventView(
        event_id=event_id,
        device_id=device_id,
        event_type=event_type,
        severity=severity,
        timestamp=timestamp or datetime.now(),
        attributes=attributes or {},
        security_event=security_event,
        audit_event=audit_event,
        process_event=process_event,
        flow_event=flow_event,
    )


def _make_ssh_failure(
    event_id: str, source_ip: str = "10.0.0.99", ts: datetime | None = None
) -> TelemetryEventView:
    return _make_event(
        event_id=event_id,
        event_type="SECURITY",
        severity="WARN",
        timestamp=ts or datetime.now(),
        security_event={
            "event_action": "SSH",
            "event_outcome": "FAILURE",
            "source_ip": source_ip,
            "user_name": "admin",
        },
    )


def _make_ssh_success(
    event_id: str, source_ip: str = "10.0.0.99", ts: datetime | None = None
) -> TelemetryEventView:
    return _make_event(
        event_id=event_id,
        event_type="SECURITY",
        severity="INFO",
        timestamp=ts or datetime.now(),
        security_event={
            "event_action": "SSH",
            "event_outcome": "SUCCESS",
            "source_ip": source_ip,
            "user_name": "admin",
        },
    )


@pytest.fixture
def tmp_db_path(tmp_path):
    """Provide a temporary database path for FusionEngine."""
    return str(tmp_path / "test_fusion.db")


@pytest.fixture
def engine(tmp_db_path):
    """Create a FusionEngine instance with temporary database."""
    from amoskys.intel.fusion_engine import FusionEngine

    return FusionEngine(db_path=tmp_db_path, window_minutes=30, eval_interval=60)


# ═══════════════════════════════════════════════════════════════════
# FusionEngine Initialization
# ═══════════════════════════════════════════════════════════════════


class TestFusionEngineInit:
    """Test FusionEngine construction and database setup."""

    def test_init_creates_db_directory(self, tmp_path):
        from amoskys.intel.fusion_engine import FusionEngine

        db_path = str(tmp_path / "subdir" / "fusion.db")
        engine = FusionEngine(db_path=db_path, window_minutes=15)
        assert os.path.exists(str(tmp_path / "subdir"))

    def test_init_default_params(self, tmp_db_path):
        from amoskys.intel.fusion_engine import FusionEngine

        engine = FusionEngine(db_path=tmp_db_path)
        assert engine.window_minutes == 30
        assert engine.eval_interval == 60

    def test_init_custom_params(self, tmp_db_path):
        from amoskys.intel.fusion_engine import FusionEngine

        engine = FusionEngine(db_path=tmp_db_path, window_minutes=60, eval_interval=120)
        assert engine.window_minutes == 60
        assert engine.eval_interval == 120

    def test_init_creates_tables(self, engine):
        """Verify incidents and device_risk tables are created."""
        cursor = engine.db.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}
        assert "incidents" in tables
        assert "device_risk" in tables

    def test_init_creates_indexes(self, engine):
        """Verify indexes are created on the tables."""
        cursor = engine.db.execute("SELECT name FROM sqlite_master WHERE type='index'")
        indexes = {row[0] for row in cursor.fetchall()}
        assert "idx_incidents_device" in indexes
        assert "idx_incidents_created" in indexes

    def test_init_metrics_default(self, engine):
        """Metrics start at zero."""
        assert engine.metrics["total_events_processed"] == 0
        assert engine.metrics["total_incidents_created"] == 0
        assert engine.metrics["total_evaluations"] == 0

    def test_init_device_state_empty(self, engine):
        """No devices tracked initially."""
        assert len(engine.device_state) == 0


# ═══════════════════════════════════════════════════════════════════
# Event Ingestion (add_event)
# ═══════════════════════════════════════════════════════════════════


class TestAddEvent:
    """Test event ingestion into device buffers."""

    def test_add_single_event(self, engine):
        event = _make_event()
        engine.add_event(event)
        assert len(engine.device_state["macbook-test"]["events"]) == 1
        assert engine.metrics["total_events_processed"] == 1

    def test_add_multiple_events_same_device(self, engine):
        for i in range(5):
            engine.add_event(_make_event(event_id=f"evt-{i}"))
        assert len(engine.device_state["macbook-test"]["events"]) == 5
        assert engine.metrics["total_events_processed"] == 5

    def test_add_events_different_devices(self, engine):
        engine.add_event(_make_event(device_id="dev-A", event_id="e1"))
        engine.add_event(_make_event(device_id="dev-B", event_id="e2"))
        assert len(engine.device_state["dev-A"]["events"]) == 1
        assert len(engine.device_state["dev-B"]["events"]) == 1

    def test_old_events_trimmed(self, engine):
        """Events outside the correlation window get removed."""
        old_ts = datetime.now() - timedelta(minutes=60)
        engine.add_event(_make_event(event_id="old", timestamp=old_ts))
        # The old event should have been trimmed
        assert len(engine.device_state["macbook-test"]["events"]) == 0

    def test_recent_events_kept(self, engine):
        """Events within the correlation window are kept."""
        recent_ts = datetime.now() - timedelta(minutes=5)
        engine.add_event(_make_event(event_id="recent", timestamp=recent_ts))
        assert len(engine.device_state["macbook-test"]["events"]) == 1

    def test_tracks_known_ips(self, engine):
        """Security events with source_ip are tracked."""
        event = _make_ssh_failure("evt-1", source_ip="192.168.1.100")
        engine.add_event(event)
        assert "192.168.1.100" in engine.device_state["macbook-test"]["known_ips"]

    def test_no_ip_tracked_for_non_security(self, engine):
        """Non-security events don't add to known_ips."""
        event = _make_event(event_type="METRIC")
        engine.add_event(event)
        assert len(engine.device_state["macbook-test"]["known_ips"]) == 0


# ═══════════════════════════════════════════════════════════════════
# Device Risk Calculation
# ═══════════════════════════════════════════════════════════════════


class TestCalculateDeviceRisk:
    """Test the risk scoring model in _calculate_device_risk."""

    def test_base_score_with_no_events(self, engine):
        """Device with no events should get base score."""
        # Access device state to initialize it
        engine.device_state["test-dev"]["events"] = []
        incidents, risk = engine.evaluate_device("test-dev")
        assert risk.score == 10  # Base score
        assert risk.level == RiskLevel.LOW

    def test_failed_ssh_increases_score(self, engine):
        """Failed SSH attempts should increase risk score."""
        now = datetime.now()
        for i in range(3):
            engine.add_event(_make_ssh_failure(f"fail-{i}", ts=now))
        # Need to mock evaluate_rules to avoid rule dependencies
        with patch("amoskys.intel.fusion_engine.evaluate_rules", return_value=[]):
            with patch(
                "amoskys.intel.fusion_engine.evaluate_advanced_rules", return_value=[]
            ):
                incidents, risk = engine.evaluate_device("macbook-test")
        assert risk.score > 10  # Should be 10 + 15 (3*5, capped at 20) = 25
        assert any("ssh_brute_force" in tag for tag in risk.reason_tags)

    def test_failed_ssh_capped_at_20(self, engine):
        """Failed SSH contribution capped at +20."""
        now = datetime.now()
        for i in range(10):
            engine.add_event(_make_ssh_failure(f"fail-{i}", ts=now))
        with patch("amoskys.intel.fusion_engine.evaluate_rules", return_value=[]):
            with patch(
                "amoskys.intel.fusion_engine.evaluate_advanced_rules", return_value=[]
            ):
                incidents, risk = engine.evaluate_device("macbook-test")
        # 10 + 20 (capped) = 30
        assert risk.score == 30

    def test_ssh_success_new_ip_increases_score(self, engine):
        """Successful SSH from external IP increases score."""
        now = datetime.now()
        engine.add_event(_make_ssh_success("success-1", source_ip="10.0.0.50", ts=now))
        with patch("amoskys.intel.fusion_engine.evaluate_rules", return_value=[]):
            with patch(
                "amoskys.intel.fusion_engine.evaluate_advanced_rules", return_value=[]
            ):
                incidents, risk = engine.evaluate_device("macbook-test")
        # 10 + 15 = 25
        assert risk.score == 25

    def test_ssh_success_localhost_no_increase(self, engine):
        """SSH from localhost should not increase score."""
        now = datetime.now()
        engine.add_event(_make_ssh_success("success-1", source_ip="127.0.0.1", ts=now))
        with patch("amoskys.intel.fusion_engine.evaluate_rules", return_value=[]):
            with patch(
                "amoskys.intel.fusion_engine.evaluate_advanced_rules", return_value=[]
            ):
                incidents, risk = engine.evaluate_device("macbook-test")
        assert risk.score == 10

    def test_new_ssh_key_increases_score(self, engine):
        """SSH key changes should add +30 per key."""
        now = datetime.now()
        engine.add_event(
            _make_event(
                event_id="key-1",
                event_type="AUDIT",
                timestamp=now,
                audit_event={"object_type": "SSH_KEYS", "action_performed": "CREATED"},
            )
        )
        with patch("amoskys.intel.fusion_engine.evaluate_rules", return_value=[]):
            with patch(
                "amoskys.intel.fusion_engine.evaluate_advanced_rules", return_value=[]
            ):
                incidents, risk = engine.evaluate_device("macbook-test")
        # 10 + 30 = 40
        assert risk.score == 40

    def test_launch_agent_in_users_increases_score(self, engine):
        """New LaunchAgent in /Users/ directory should add +25."""
        now = datetime.now()
        engine.add_event(
            _make_event(
                event_id="la-1",
                event_type="AUDIT",
                timestamp=now,
                attributes={
                    "file_path": "/Users/admin/Library/LaunchAgents/evil.plist"
                },
                audit_event={
                    "object_type": "LAUNCH_AGENT",
                    "action_performed": "CREATED",
                },
            )
        )
        with patch("amoskys.intel.fusion_engine.evaluate_rules", return_value=[]):
            with patch(
                "amoskys.intel.fusion_engine.evaluate_advanced_rules", return_value=[]
            ):
                incidents, risk = engine.evaluate_device("macbook-test")
        # 10 + 25 = 35
        assert risk.score == 35

    def test_suspicious_sudo_increases_score(self, engine):
        """Dangerous sudo commands should add +30."""
        now = datetime.now()
        engine.add_event(
            _make_event(
                event_id="sudo-1",
                event_type="SECURITY",
                timestamp=now,
                attributes={"sudo_command": "rm -rf /etc/sudoers"},
                security_event={"event_action": "SUDO", "user_name": "admin"},
            )
        )
        with patch("amoskys.intel.fusion_engine.evaluate_rules", return_value=[]):
            with patch(
                "amoskys.intel.fusion_engine.evaluate_advanced_rules", return_value=[]
            ):
                incidents, risk = engine.evaluate_device("macbook-test")
        # 10 + 30 = 40
        assert risk.score == 40

    def test_critical_incident_adds_40(self, engine):
        """CRITICAL incident adds +40 to device risk."""
        now = datetime.now()
        engine.add_event(_make_event(event_id="e1", timestamp=now))

        critical_incident = Incident(
            incident_id="inc-1",
            device_id="macbook-test",
            severity=Severity.CRITICAL,
            rule_name="test_rule",
            event_ids=["e1"],
        )

        with patch(
            "amoskys.intel.fusion_engine.evaluate_rules",
            return_value=[critical_incident],
        ):
            with patch(
                "amoskys.intel.fusion_engine.evaluate_advanced_rules", return_value=[]
            ):
                incidents, risk = engine.evaluate_device("macbook-test")
        # 10 + 40 = 50
        assert risk.score == 50

    def test_high_incident_adds_20(self, engine):
        """HIGH incident adds +20 to device risk."""
        now = datetime.now()
        engine.add_event(_make_event(event_id="e1", timestamp=now))

        high_incident = Incident(
            incident_id="inc-2",
            device_id="macbook-test",
            severity=Severity.HIGH,
            rule_name="test_rule",
            event_ids=["e1"],
        )

        with patch(
            "amoskys.intel.fusion_engine.evaluate_rules", return_value=[high_incident]
        ):
            with patch(
                "amoskys.intel.fusion_engine.evaluate_advanced_rules", return_value=[]
            ):
                incidents, risk = engine.evaluate_device("macbook-test")
        # 10 + 20 = 30
        assert risk.score == 30

    def test_score_clamped_to_100(self, engine):
        """Risk score never exceeds 100."""
        now = datetime.now()
        # Add many high-risk events
        for i in range(10):
            engine.add_event(
                _make_event(
                    event_id=f"key-{i}",
                    event_type="AUDIT",
                    timestamp=now,
                    audit_event={"object_type": "SSH_KEYS"},
                )
            )
        with patch("amoskys.intel.fusion_engine.evaluate_rules", return_value=[]):
            with patch(
                "amoskys.intel.fusion_engine.evaluate_advanced_rules", return_value=[]
            ):
                incidents, risk = engine.evaluate_device("macbook-test")
        assert risk.score <= 100

    def test_score_clamped_to_0(self, engine):
        """Risk score never goes below 0."""
        # Set a low score and trigger decay
        engine.device_state["macbook-test"]["risk_score"] = 5
        engine.device_state["macbook-test"]["last_eval"] = datetime.now() - timedelta(
            hours=1
        )
        engine.device_state["macbook-test"]["events"] = [
            _make_event(event_id="e1", timestamp=datetime.now())
        ]
        with patch("amoskys.intel.fusion_engine.evaluate_rules", return_value=[]):
            with patch(
                "amoskys.intel.fusion_engine.evaluate_advanced_rules", return_value=[]
            ):
                incidents, risk = engine.evaluate_device("macbook-test")
        assert risk.score >= 0

    def test_score_decay_over_time(self, engine):
        """Score decays when no risky events and time passes."""
        engine.device_state["macbook-test"]["risk_score"] = 50
        engine.device_state["macbook-test"]["last_eval"] = datetime.now() - timedelta(
            minutes=30
        )
        engine.device_state["macbook-test"]["events"] = [
            _make_event(event_id="benign", timestamp=datetime.now())
        ]
        with patch("amoskys.intel.fusion_engine.evaluate_rules", return_value=[]):
            with patch(
                "amoskys.intel.fusion_engine.evaluate_advanced_rules", return_value=[]
            ):
                incidents, risk = engine.evaluate_device("macbook-test")
        # 30 minutes = 3 decay periods (3 * 10 = 30 reduction)
        # 50 - 30 = 20
        assert risk.score == 20

    def test_risk_level_low(self, engine):
        """Score <= 30 maps to LOW."""
        assert DeviceRiskSnapshot.score_to_level(10) == RiskLevel.LOW
        assert DeviceRiskSnapshot.score_to_level(30) == RiskLevel.LOW

    def test_risk_level_medium(self, engine):
        """Score 31-60 maps to MEDIUM."""
        assert DeviceRiskSnapshot.score_to_level(31) == RiskLevel.MEDIUM
        assert DeviceRiskSnapshot.score_to_level(60) == RiskLevel.MEDIUM

    def test_risk_level_high(self, engine):
        """Score 61-80 maps to HIGH."""
        assert DeviceRiskSnapshot.score_to_level(61) == RiskLevel.HIGH
        assert DeviceRiskSnapshot.score_to_level(80) == RiskLevel.HIGH

    def test_risk_level_critical(self, engine):
        """Score > 80 maps to CRITICAL."""
        assert DeviceRiskSnapshot.score_to_level(81) == RiskLevel.CRITICAL
        assert DeviceRiskSnapshot.score_to_level(100) == RiskLevel.CRITICAL


# ═══════════════════════════════════════════════════════════════════
# Incident Persistence
# ═══════════════════════════════════════════════════════════════════


class TestPersistIncident:
    """Test incident storage and retrieval."""

    def test_persist_and_retrieve_incident(self, engine):
        now = datetime.now()
        incident = Incident(
            incident_id="inc-test-001",
            device_id="macbook-test",
            severity=Severity.HIGH,
            tactics=["TA0001"],
            techniques=["T1110"],
            rule_name="ssh_brute_force",
            summary="Test incident",
            start_ts=now - timedelta(minutes=5),
            end_ts=now,
            event_ids=["evt-1", "evt-2"],
            metadata={"source_ip": "10.0.0.1"},
            created_at=now,
        )
        engine.persist_incident(incident)

        incidents = engine.get_recent_incidents()
        assert len(incidents) == 1
        assert incidents[0]["incident_id"] == "inc-test-001"
        assert incidents[0]["device_id"] == "macbook-test"
        assert incidents[0]["severity"] == "HIGH"
        assert incidents[0]["tactics"] == ["TA0001"]
        assert incidents[0]["techniques"] == ["T1110"]
        assert incidents[0]["rule_name"] == "ssh_brute_force"
        assert incidents[0]["event_ids"] == ["evt-1", "evt-2"]
        assert incidents[0]["metadata"] == {"source_ip": "10.0.0.1"}

    def test_persist_incident_upsert(self, engine):
        """INSERT OR REPLACE should overwrite existing incident."""
        now = datetime.now()
        incident = Incident(
            incident_id="inc-upsert",
            device_id="macbook-test",
            severity=Severity.LOW,
            rule_name="original",
            summary="Original summary",
        )
        engine.persist_incident(incident)

        incident.summary = "Updated summary"
        engine.persist_incident(incident)

        incidents = engine.get_recent_incidents()
        assert len(incidents) == 1
        assert incidents[0]["summary"] == "Updated summary"

    def test_persist_incident_with_none_timestamps(self, engine):
        """Incident with no start_ts/end_ts should persist cleanly."""
        incident = Incident(
            incident_id="inc-no-ts",
            device_id="macbook-test",
            severity=Severity.INFO,
            rule_name="test",
        )
        engine.persist_incident(incident)
        incidents = engine.get_recent_incidents()
        assert len(incidents) == 1
        assert incidents[0]["start_ts"] is None
        assert incidents[0]["end_ts"] is None

    def test_get_recent_incidents_by_device(self, engine):
        """Filtering by device_id should work."""
        now = datetime.now()
        for device in ["dev-A", "dev-B", "dev-A"]:
            engine.persist_incident(
                Incident(
                    incident_id=f"inc-{device}-{now.timestamp()}",
                    device_id=device,
                    severity=Severity.LOW,
                    rule_name="test",
                )
            )
            # Small delay for unique timestamps
            now += timedelta(seconds=1)

        all_incidents = engine.get_recent_incidents()
        assert len(all_incidents) == 3

        dev_a_incidents = engine.get_recent_incidents(device_id="dev-A")
        assert len(dev_a_incidents) == 2

    def test_get_recent_incidents_respects_limit(self, engine):
        """Limit parameter should cap returned incidents."""
        for i in range(10):
            engine.persist_incident(
                Incident(
                    incident_id=f"inc-{i}",
                    device_id="macbook-test",
                    severity=Severity.LOW,
                    rule_name="test",
                )
            )
        limited = engine.get_recent_incidents(limit=3)
        assert len(limited) == 3

    def test_persist_incident_error_handling(self, engine):
        """Persistence errors should be logged, not raised."""
        # Close the DB to force an error
        engine.db.close()
        incident = Incident(
            incident_id="inc-error",
            device_id="macbook-test",
            severity=Severity.LOW,
            rule_name="test",
        )
        # Should not raise
        engine.persist_incident(incident)


# ═══════════════════════════════════════════════════════════════════
# Risk Snapshot Persistence
# ═══════════════════════════════════════════════════════════════════


class TestPersistRiskSnapshot:
    """Test device risk snapshot storage and retrieval."""

    def test_persist_and_retrieve_risk(self, engine):
        snapshot = DeviceRiskSnapshot(
            device_id="macbook-test",
            score=75,
            level=RiskLevel.HIGH,
            reason_tags=["ssh_brute_force_attempts_5"],
            supporting_events=["evt-1", "evt-2"],
            metadata={"event_count": "10"},
        )
        engine.persist_risk_snapshot(snapshot)

        risk = engine.get_device_risk("macbook-test")
        assert risk is not None
        assert risk["device_id"] == "macbook-test"
        assert risk["score"] == 75
        assert risk["level"] == "HIGH"
        assert risk["reason_tags"] == ["ssh_brute_force_attempts_5"]
        assert risk["supporting_events"] == ["evt-1", "evt-2"]

    def test_get_device_risk_none(self, engine):
        """Unknown device returns None."""
        assert engine.get_device_risk("nonexistent") is None

    def test_persist_risk_upsert(self, engine):
        """Risk snapshot should overwrite on same device_id."""
        snapshot1 = DeviceRiskSnapshot(
            device_id="macbook-test",
            score=30,
            level=RiskLevel.LOW,
        )
        engine.persist_risk_snapshot(snapshot1)

        snapshot2 = DeviceRiskSnapshot(
            device_id="macbook-test",
            score=80,
            level=RiskLevel.HIGH,
        )
        engine.persist_risk_snapshot(snapshot2)

        risk = engine.get_device_risk("macbook-test")
        assert risk["score"] == 80

    def test_persist_risk_error_handling(self, engine):
        """Persistence errors should be logged, not raised."""
        engine.db.close()
        snapshot = DeviceRiskSnapshot(
            device_id="macbook-test",
            score=50,
            level=RiskLevel.MEDIUM,
        )
        # Should not raise
        engine.persist_risk_snapshot(snapshot)


# ═══════════════════════════════════════════════════════════════════
# Evaluate All Devices
# ═══════════════════════════════════════════════════════════════════


class TestEvaluateAllDevices:
    """Test the evaluate_all_devices orchestration method."""

    def test_evaluate_all_devices_empty(self, engine):
        """No devices to evaluate should complete cleanly."""
        engine.evaluate_all_devices()
        assert engine.metrics["total_evaluations"] == 1
        assert engine.metrics["devices_tracked"] == 0

    def test_evaluate_all_devices_updates_metrics(self, engine):
        """Metrics should be updated after evaluation."""
        now = datetime.now()
        engine.add_event(_make_event(device_id="dev-A", event_id="e1", timestamp=now))
        engine.add_event(_make_event(device_id="dev-B", event_id="e2", timestamp=now))

        with patch("amoskys.intel.fusion_engine.evaluate_rules", return_value=[]):
            with patch(
                "amoskys.intel.fusion_engine.evaluate_advanced_rules", return_value=[]
            ):
                engine.evaluate_all_devices()

        assert engine.metrics["total_evaluations"] == 1
        assert engine.metrics["devices_tracked"] == 2
        assert engine.metrics["last_eval_duration_ms"] >= 0

    def test_evaluate_all_devices_persists_incidents(self, engine):
        """Incidents returned by rules should be persisted."""
        now = datetime.now()
        engine.add_event(_make_event(device_id="dev-A", event_id="e1", timestamp=now))

        mock_incident = Incident(
            incident_id="auto-inc-001",
            device_id="dev-A",
            severity=Severity.HIGH,
            tactics=["TA0001"],
            techniques=["T1110"],
            rule_name="ssh_brute_force",
            summary="Auto-detected",
            event_ids=["e1"],
        )

        with patch(
            "amoskys.intel.fusion_engine.evaluate_rules", return_value=[mock_incident]
        ):
            with patch(
                "amoskys.intel.fusion_engine.evaluate_advanced_rules", return_value=[]
            ):
                engine.evaluate_all_devices()

        incidents = engine.get_recent_incidents()
        assert len(incidents) == 1
        assert incidents[0]["incident_id"] == "auto-inc-001"
        assert engine.metrics["total_incidents_created"] == 1
        assert engine.metrics["incidents_by_severity"]["HIGH"] == 1

    def test_evaluate_device_exception_handled(self, engine):
        """Exceptions during device evaluation should be caught."""
        now = datetime.now()
        engine.add_event(_make_event(device_id="dev-A", event_id="e1", timestamp=now))

        with patch(
            "amoskys.intel.fusion_engine.evaluate_rules",
            side_effect=RuntimeError("boom"),
        ):
            # Should not raise
            engine.evaluate_all_devices()

        assert engine.metrics["total_evaluations"] == 1


# ═══════════════════════════════════════════════════════════════════
# get_current_risk_snapshot
# ═══════════════════════════════════════════════════════════════════


class TestGetCurrentRiskSnapshot:
    """Test the _get_current_risk_snapshot helper."""

    def test_returns_base_score_for_new_device(self, engine):
        snapshot = engine._get_current_risk_snapshot("new-device")
        assert snapshot.device_id == "new-device"
        assert snapshot.score == 10
        assert snapshot.level == RiskLevel.LOW

    def test_returns_current_score(self, engine):
        engine.device_state["dev-X"]["risk_score"] = 75
        snapshot = engine._get_current_risk_snapshot("dev-X")
        assert snapshot.score == 75
        assert snapshot.level == RiskLevel.HIGH


# ═══════════════════════════════════════════════════════════════════
# Evaluate Device
# ═══════════════════════════════════════════════════════════════════


class TestEvaluateDevice:
    """Test evaluate_device method."""

    def test_evaluate_device_no_events(self, engine):
        """Device with no events returns empty incidents and base risk."""
        engine.device_state["empty-dev"]["events"] = []
        incidents, risk = engine.evaluate_device("empty-dev")
        assert incidents == []
        assert risk.score == 10

    def test_evaluate_device_returns_combined_incidents(self, engine):
        """Both standard and advanced rules are evaluated."""
        now = datetime.now()
        engine.add_event(_make_event(device_id="dev-A", event_id="e1", timestamp=now))

        std_incident = Incident(
            incident_id="std-1",
            device_id="dev-A",
            severity=Severity.MEDIUM,
            rule_name="standard_rule",
        )
        adv_incident = Incident(
            incident_id="adv-1",
            device_id="dev-A",
            severity=Severity.HIGH,
            rule_name="advanced_rule",
        )

        with patch(
            "amoskys.intel.fusion_engine.evaluate_rules", return_value=[std_incident]
        ):
            with patch(
                "amoskys.intel.fusion_engine.evaluate_advanced_rules",
                return_value=[adv_incident],
            ):
                incidents, risk = engine.evaluate_device("dev-A")

        assert len(incidents) == 2
        rule_names = {i.rule_name for i in incidents}
        assert "standard_rule" in rule_names
        assert "advanced_rule" in rule_names

    def test_evaluate_device_updates_last_eval(self, engine):
        """last_eval should be updated after evaluation."""
        now = datetime.now()
        engine.add_event(_make_event(device_id="dev-A", event_id="e1", timestamp=now))

        with patch("amoskys.intel.fusion_engine.evaluate_rules", return_value=[]):
            with patch(
                "amoskys.intel.fusion_engine.evaluate_advanced_rules", return_value=[]
            ):
                engine.evaluate_device("dev-A")

        assert engine.device_state["dev-A"]["last_eval"] is not None

    def test_evaluate_device_increments_incident_count(self, engine):
        """incident_count in device_state should be incremented."""
        now = datetime.now()
        engine.add_event(_make_event(device_id="dev-A", event_id="e1", timestamp=now))

        incident = Incident(
            incident_id="inc-1",
            device_id="dev-A",
            severity=Severity.LOW,
            rule_name="test",
        )

        with patch(
            "amoskys.intel.fusion_engine.evaluate_rules", return_value=[incident]
        ):
            with patch(
                "amoskys.intel.fusion_engine.evaluate_advanced_rules", return_value=[]
            ):
                engine.evaluate_device("dev-A")

        assert engine.device_state["dev-A"]["incident_count"] == 1


# ═══════════════════════════════════════════════════════════════════
# Ingest Telemetry From DB
# ═══════════════════════════════════════════════════════════════════


class TestIngestTelemetryFromDB:
    """Test ingest_telemetry_from_db error handling."""

    def test_ingest_nonexistent_db(self, engine):
        """Non-existent path should be handled gracefully."""
        # Should not raise
        engine.ingest_telemetry_from_db("/nonexistent/path.db")

    def test_ingest_valid_db(self, engine, tmp_path):
        """Valid DB path should not raise."""
        test_db = str(tmp_path / "test_agent.db")
        conn = sqlite3.connect(test_db)
        conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY)")
        conn.close()
        # Should not raise
        engine.ingest_telemetry_from_db(test_db)


# ═══════════════════════════════════════════════════════════════════
# run_once
# ═══════════════════════════════════════════════════════════════════


class TestRunOnce:
    """Test the single-pass run_once method."""

    def test_run_once_completes(self, engine):
        """run_once should complete without errors."""
        now = datetime.now()
        engine.add_event(_make_event(device_id="dev-A", event_id="e1", timestamp=now))

        with patch("amoskys.intel.fusion_engine.evaluate_rules", return_value=[]):
            with patch(
                "amoskys.intel.fusion_engine.evaluate_advanced_rules", return_value=[]
            ):
                engine.run_once()

        assert engine.metrics["total_evaluations"] >= 1
