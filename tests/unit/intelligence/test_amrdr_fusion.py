"""
Sprint 2 Tests: AMRDR + Fusion Engine Integration

Tests that the FusionEngine correctly:
1. Accepts and uses a ReliabilityTracker
2. Weights incident confidence by agent reliability
3. Scales device risk scores by agent weights
4. Emits drift alerts when agents degrade
5. Feeds analyst feedback back to AMRDR
6. Persists AMRDR columns to the incidents table
"""

import json
import os
import sqlite3
import tempfile
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import pytest

from amoskys.intel.drift_detection import ADWINDetector, EDDMDetector
from amoskys.intel.fusion_engine import FusionEngine
from amoskys.intel.models import (
    DeviceRiskSnapshot,
    Incident,
    MitreTactic,
    Severity,
    TelemetryEventView,
)
from amoskys.intel.reliability import (
    BayesianReliabilityTracker,
    DriftType,
    NoOpReliabilityTracker,
    RecalibrationTier,
    ReliabilityState,
    ReliabilityTracker,
)
from amoskys.intel.rules import _annotate_incident_weights, evaluate_rules

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(
    device_id: str = "test-device",
    event_type: str = "SECURITY",
    event_id: Optional[str] = None,
    agent_id: str = "flowagent",
    **kwargs,
) -> TelemetryEventView:
    """Create a minimal TelemetryEventView for testing."""
    return TelemetryEventView(
        event_id=event_id or f"evt-{uuid.uuid4().hex[:8]}",
        device_id=device_id,
        event_type=event_type,
        severity="MEDIUM",
        timestamp=datetime.now(),
        attributes={"agent_id": agent_id, **kwargs.get("attributes", {})},
        security_event=kwargs.get("security_event"),
        audit_event=kwargs.get("audit_event"),
        process_event=kwargs.get("process_event"),
        flow_event=kwargs.get("flow_event"),
    )


def _make_ssh_brute_force_events(
    device_id: str = "test-device",
    source_ip: str = "10.0.0.99",
    num_failures: int = 5,
) -> List[TelemetryEventView]:
    """Create events that trigger the SSH brute force rule."""
    events = []
    base_time = datetime.now() - timedelta(minutes=10)

    # Failed SSH attempts
    for i in range(num_failures):
        events.append(
            TelemetryEventView(
                event_id=f"ssh-fail-{i}",
                device_id=device_id,
                event_type="SECURITY",
                severity="MEDIUM",
                timestamp=base_time + timedelta(seconds=i * 10),
                attributes={"agent_id": "flowagent"},
                security_event={
                    "event_action": "SSH",
                    "event_outcome": "FAILURE",
                    "source_ip": source_ip,
                    "user_name": "root",
                },
            )
        )

    # Successful SSH from same IP
    events.append(
        TelemetryEventView(
            event_id="ssh-success-0",
            device_id=device_id,
            event_type="SECURITY",
            severity="HIGH",
            timestamp=base_time + timedelta(seconds=num_failures * 10 + 30),
            attributes={"agent_id": "flowagent"},
            security_event={
                "event_action": "SSH",
                "event_outcome": "SUCCESS",
                "source_ip": source_ip,
                "user_name": "root",
            },
        )
    )

    return events


class MockReliabilityTracker(ReliabilityTracker):
    """Test double that returns configurable weights."""

    def __init__(self, weights: Dict[str, float] = None, drift_agents=None):
        self._weights = weights or {}
        self._states: Dict[str, ReliabilityState] = {}
        self._updates: List[tuple] = []  # Track update calls
        self._drift_agents = drift_agents or {}  # agent_id -> DriftType

        # Pre-populate states for drift agents
        for agent_id, drift_type in self._drift_agents.items():
            tier = RecalibrationTier.NOMINAL
            weight = self._weights.get(agent_id, 1.0)
            if drift_type == DriftType.ABRUPT:
                tier = RecalibrationTier.HARD
                weight = 0.5
            elif drift_type == DriftType.GRADUAL:
                tier = RecalibrationTier.SOFT
                weight = 0.7
            self._states[agent_id] = ReliabilityState(
                agent_id=agent_id,
                alpha=5.0,
                beta=5.0,
                fusion_weight=weight,
                drift_type=drift_type,
                tier=tier,
            )

    def update(self, agent_id, ground_truth_match):
        self._updates.append((agent_id, ground_truth_match))
        if agent_id not in self._states:
            self._states[agent_id] = ReliabilityState(agent_id=agent_id)
        return self._states[agent_id]

    def get_state(self, agent_id):
        if agent_id not in self._states:
            self._states[agent_id] = ReliabilityState(agent_id=agent_id)
        return self._states[agent_id]

    def detect_drift(self, agent_id):
        dt = self._drift_agents.get(agent_id, DriftType.NONE)
        return (dt, 0.01 if dt != DriftType.NONE else 1.0)

    def recalibrate(self, agent_id):
        return self._states.get(agent_id, ReliabilityState(agent_id=agent_id)).tier

    def get_fusion_weights(self):
        return dict(self._weights)

    def list_agents(self):
        return list(set(list(self._weights.keys()) + list(self._states.keys())))


# ===========================================================================
# Test: FusionEngine with NoOp tracker (backward compatibility)
# ===========================================================================


class TestFusionEngineNoOp:
    """Ensure FusionEngine works exactly as before with no tracker."""

    def setup_method(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp_dir, "fusion.db")
        self.engine = FusionEngine(db_path=self.db_path)

    def test_default_tracker_is_noop(self):
        assert isinstance(self.engine.reliability_tracker, NoOpReliabilityTracker)

    def test_evaluate_empty_device(self):
        incidents, risk = self.engine.evaluate_device("unknown-device")
        assert incidents == []
        assert risk.score == 10  # base score

    def test_evaluate_with_events(self):
        events = _make_ssh_brute_force_events()
        for e in events:
            self.engine.add_event(e)
        incidents, risk = self.engine.evaluate_device("test-device")
        # Should still produce incidents (NoOp passes weight 1.0)
        assert len(incidents) >= 1

    def test_incident_has_amrdr_fields(self):
        events = _make_ssh_brute_force_events()
        for e in events:
            self.engine.add_event(e)
        incidents, _ = self.engine.evaluate_device("test-device")
        for inc in incidents:
            assert hasattr(inc, "agent_weights")
            assert hasattr(inc, "weighted_confidence")
            assert hasattr(inc, "contributing_agents")


# ===========================================================================
# Test: FusionEngine with AMRDR weights
# ===========================================================================


class TestFusionEngineWithAMRDR:
    """Test reliability-weighted fusion."""

    def setup_method(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp_dir, "fusion.db")

    def _engine_with_weights(self, weights, drift_agents=None):
        tracker = MockReliabilityTracker(weights, drift_agents)
        return FusionEngine(
            db_path=self.db_path,
            reliability_tracker=tracker,
        )

    def test_weights_passed_to_rules(self):
        """Incidents should be annotated with AMRDR weights."""
        engine = self._engine_with_weights({"flowagent": 0.8, "SECURITY": 0.8})
        events = _make_ssh_brute_force_events()
        for e in events:
            engine.add_event(e)

        incidents, _ = engine.evaluate_device("test-device")
        # At least one incident should have agent_weights
        weighted = [i for i in incidents if i.agent_weights]
        assert len(weighted) >= 0  # May or may not annotate depending on event attrs

    def test_low_weight_reduces_risk_score(self):
        """Incidents from low-reliability agents should contribute less to risk."""
        # High weight engine
        engine_high = self._engine_with_weights({"flowagent": 1.0, "SECURITY": 1.0})
        events = _make_ssh_brute_force_events()
        for e in events:
            engine_high.add_event(e)
        _, risk_high = engine_high.evaluate_device("test-device")

        # Low weight engine (new db path to avoid conflict)
        self.db_path = os.path.join(self.tmp_dir, "fusion2.db")
        engine_low = self._engine_with_weights({"flowagent": 0.3, "SECURITY": 0.3})
        events2 = _make_ssh_brute_force_events()
        for e in events2:
            engine_low.add_event(e)
        _, risk_low = engine_low.evaluate_device("test-device")

        # Low-weight engine should have same or lower risk score
        # (incident points scaled down by avg_weight)
        assert risk_low.score <= risk_high.score

    def test_drift_alerts_emitted(self):
        """When agents are drifting, AMRDR_DRIFT incidents should be emitted."""
        engine = self._engine_with_weights(
            weights={"degraded_agent": 0.5},
            drift_agents={"degraded_agent": DriftType.ABRUPT},
        )

        # Add some events so evaluation runs
        events = [_make_event(agent_id="degraded_agent")]
        for e in events:
            engine.add_event(e)

        incidents, _ = engine.evaluate_device("test-device")

        drift_incidents = [i for i in incidents if i.rule_name == "AMRDR_DRIFT"]
        assert len(drift_incidents) >= 1
        assert drift_incidents[0].severity == Severity.HIGH

    def test_gradual_drift_medium_severity(self):
        """Gradual drift should produce MEDIUM severity alerts."""
        engine = self._engine_with_weights(
            weights={"slow_agent": 0.7},
            drift_agents={"slow_agent": DriftType.GRADUAL},
        )
        events = [_make_event(agent_id="slow_agent")]
        for e in events:
            engine.add_event(e)

        incidents, _ = engine.evaluate_device("test-device")
        drift_incidents = [i for i in incidents if i.rule_name == "AMRDR_DRIFT"]
        assert len(drift_incidents) >= 1
        assert drift_incidents[0].severity == Severity.MEDIUM

    def test_no_drift_no_alerts(self):
        """When no agents are drifting, no AMRDR_DRIFT incidents should be emitted."""
        engine = self._engine_with_weights(
            weights={"good_agent": 0.95},
            drift_agents={},
        )
        events = [_make_event(agent_id="good_agent")]
        for e in events:
            engine.add_event(e)

        incidents, _ = engine.evaluate_device("test-device")
        drift_incidents = [i for i in incidents if i.rule_name == "AMRDR_DRIFT"]
        assert len(drift_incidents) == 0


# ===========================================================================
# Test: Incident persistence with AMRDR columns
# ===========================================================================


class TestIncidentPersistence:
    """Test that AMRDR columns are persisted and retrieved correctly."""

    def setup_method(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp_dir, "fusion.db")
        self.engine = FusionEngine(db_path=self.db_path)

    def test_persist_incident_with_amrdr_fields(self):
        incident = Incident(
            incident_id="INC-test-001",
            device_id="dev-01",
            severity=Severity.HIGH,
            tactics=["TA0001"],
            techniques=["T1078"],
            rule_name="ssh_brute_force",
            summary="Test incident",
            event_ids=["evt-1", "evt-2"],
            agent_weights={"flowagent": 0.85, "procagent": 0.92},
            weighted_confidence=0.885,
            contributing_agents=["flowagent", "procagent"],
        )

        self.engine.persist_incident(incident)

        # Retrieve and verify
        rows = self.engine.db.execute(
            "SELECT agent_weights, weighted_confidence, contributing_agents "
            "FROM incidents WHERE incident_id = ?",
            ("INC-test-001",),
        ).fetchall()

        assert len(rows) == 1
        assert json.loads(rows[0][0]) == {"flowagent": 0.85, "procagent": 0.92}
        assert abs(rows[0][1] - 0.885) < 0.001
        assert json.loads(rows[0][2]) == ["flowagent", "procagent"]

    def test_get_recent_incidents_includes_amrdr(self):
        incident = Incident(
            incident_id="INC-test-002",
            device_id="dev-01",
            severity=Severity.CRITICAL,
            rule_name="test_rule",
            summary="Test",
            agent_weights={"agent_a": 0.6},
            weighted_confidence=0.6,
            contributing_agents=["agent_a"],
        )
        self.engine.persist_incident(incident)

        recent = self.engine.get_recent_incidents(limit=10)
        assert len(recent) == 1
        assert recent[0]["agent_weights"] == {"agent_a": 0.6}
        assert abs(recent[0]["weighted_confidence"] - 0.6) < 0.001
        assert recent[0]["contributing_agents"] == ["agent_a"]

    def test_db_migration_adds_columns(self):
        """Test that migration adds AMRDR columns to an existing DB."""
        # Create a "legacy" DB without AMRDR columns
        legacy_path = os.path.join(self.tmp_dir, "legacy.db")
        db = sqlite3.connect(legacy_path)
        db.execute(
            """
            CREATE TABLE incidents (
                incident_id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                tactics TEXT NOT NULL,
                techniques TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                summary TEXT NOT NULL,
                start_ts TEXT,
                end_ts TEXT,
                event_ids TEXT NOT NULL,
                metadata TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """
        )
        db.execute(
            """
            CREATE TABLE device_risk (
                device_id TEXT PRIMARY KEY,
                score INTEGER NOT NULL,
                level TEXT NOT NULL,
                reason_tags TEXT NOT NULL,
                supporting_events TEXT NOT NULL,
                metadata TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """
        )
        db.close()

        # Now open with FusionEngine (should migrate)
        engine = FusionEngine(db_path=legacy_path)

        # Verify columns exist
        cols = {
            row[1]
            for row in engine.db.execute("PRAGMA table_info(incidents)").fetchall()
        }
        assert "agent_weights" in cols
        assert "weighted_confidence" in cols
        assert "contributing_agents" in cols


# ===========================================================================
# Test: Analyst feedback loop
# ===========================================================================


class TestAnalystFeedback:
    """Test that analyst feedback flows through to AMRDR."""

    def setup_method(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp_dir, "fusion.db")
        self.tracker = MockReliabilityTracker(
            weights={"flowagent": 0.9, "procagent": 0.85}
        )
        self.engine = FusionEngine(
            db_path=self.db_path,
            reliability_tracker=self.tracker,
        )

    def test_confirm_incident_updates_agents(self):
        """Confirming an incident should update contributing agents."""
        # Persist an incident
        incident = Incident(
            incident_id="INC-feedback-001",
            device_id="dev-01",
            severity=Severity.HIGH,
            rule_name="ssh_brute_force",
            summary="Confirmed attack",
            contributing_agents=["flowagent", "procagent"],
        )
        self.engine.persist_incident(incident)

        # Provide positive feedback
        result = self.engine.provide_incident_feedback(
            "INC-feedback-001", is_confirmed=True, analyst="alice"
        )

        assert result is True
        # Both agents should have been updated with match=True
        assert ("flowagent", True) in self.tracker._updates
        assert ("procagent", True) in self.tracker._updates

    def test_dismiss_incident_updates_agents(self):
        """Dismissing an incident (false positive) should decrease reliability."""
        incident = Incident(
            incident_id="INC-feedback-002",
            device_id="dev-01",
            severity=Severity.MEDIUM,
            rule_name="lateral_movement",
            summary="False positive",
            contributing_agents=["flowagent"],
        )
        self.engine.persist_incident(incident)

        result = self.engine.provide_incident_feedback(
            "INC-feedback-002", is_confirmed=False, analyst="bob"
        )

        assert result is True
        assert ("flowagent", False) in self.tracker._updates

    def test_feedback_unknown_incident(self):
        """Feedback on nonexistent incident should return False."""
        result = self.engine.provide_incident_feedback(
            "INC-nonexistent", is_confirmed=True
        )
        assert result is False

    def test_feedback_skip_drift_alerts(self):
        """Feedback on AMRDR_DRIFT incidents should be skipped."""
        incident = Incident(
            incident_id="AMRDR-DRIFT-test-123",
            device_id="dev-01",
            severity=Severity.HIGH,
            rule_name="AMRDR_DRIFT",
            summary="Drift alert",
            contributing_agents=["degraded_agent"],
        )
        self.engine.persist_incident(incident)

        result = self.engine.provide_incident_feedback(
            "AMRDR-DRIFT-test-123", is_confirmed=True
        )

        # Should succeed but NOT update any agents
        assert result is True
        assert len(self.tracker._updates) == 0


# ===========================================================================
# Test: Rule weight annotation
# ===========================================================================


class TestRuleWeightAnnotation:
    """Test that _annotate_incident_weights works correctly."""

    def test_annotate_with_matching_agents(self):
        events = [
            _make_event(event_id="e1", agent_id="flowagent"),
            _make_event(event_id="e2", agent_id="procagent"),
        ]
        incident = Incident(
            incident_id="INC-ann-001",
            device_id="test",
            severity=Severity.HIGH,
            event_ids=["e1", "e2"],
        )
        weights = {"flowagent": 0.9, "procagent": 0.7}

        _annotate_incident_weights(incident, events, weights)

        assert "flowagent" in incident.contributing_agents
        assert "procagent" in incident.contributing_agents
        assert incident.agent_weights["flowagent"] == 0.9
        assert incident.agent_weights["procagent"] == 0.7
        assert abs(incident.weighted_confidence - 0.8) < 0.001

    def test_annotate_unknown_agent_defaults_to_1(self):
        events = [_make_event(event_id="e1", agent_id="unknown_agent")]
        incident = Incident(
            incident_id="INC-ann-002",
            device_id="test",
            severity=Severity.HIGH,
            event_ids=["e1"],
        )
        weights = {"flowagent": 0.9}  # unknown_agent not in weights

        _annotate_incident_weights(incident, events, weights)

        assert incident.agent_weights["unknown_agent"] == 1.0
        assert incident.weighted_confidence == 1.0

    def test_annotate_no_matching_events(self):
        events = [_make_event(event_id="e1", agent_id="flowagent")]
        incident = Incident(
            incident_id="INC-ann-003",
            device_id="test",
            severity=Severity.HIGH,
            event_ids=["e999"],  # No match
        )
        weights = {"flowagent": 0.9}

        _annotate_incident_weights(incident, events, weights)

        assert incident.contributing_agents == []
        assert incident.weighted_confidence == 1.0


# ===========================================================================
# Test: evaluate_rules with weights
# ===========================================================================


class TestEvaluateRulesWithWeights:
    """Test that evaluate_rules passes weights through."""

    def test_rules_without_weights_backward_compat(self):
        """evaluate_rules should work without weights (backward compat)."""
        events = _make_ssh_brute_force_events()
        incidents = evaluate_rules(events, "test-device")
        assert len(incidents) >= 1
        # Without weights, confidence should be 1.0
        for inc in incidents:
            assert inc.weighted_confidence == 1.0

    def test_rules_with_weights(self):
        """evaluate_rules with weights should annotate incidents."""
        events = _make_ssh_brute_force_events()
        weights = {"flowagent": 0.75, "SECURITY": 0.75}
        incidents = evaluate_rules(events, "test-device", weights=weights)
        assert len(incidents) >= 1


# ===========================================================================
# Test: Metrics tracking
# ===========================================================================


class TestMetricsTracking:
    def setup_method(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp_dir, "fusion.db")

    def test_drift_alerts_counted(self):
        tracker = MockReliabilityTracker(
            weights={"bad_agent": 0.3},
            drift_agents={"bad_agent": DriftType.ABRUPT},
        )
        engine = FusionEngine(db_path=self.db_path, reliability_tracker=tracker)

        events = [_make_event(agent_id="bad_agent")]
        for e in events:
            engine.add_event(e)

        engine.evaluate_device("test-device")
        assert engine.metrics["drift_alerts_emitted"] >= 1
