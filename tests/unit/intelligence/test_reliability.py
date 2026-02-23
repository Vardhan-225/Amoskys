"""
Tests for amoskys.intel.reliability

Covers:
  - DriftType enum values and semantics
  - RecalibrationTier enum values and semantics
  - ReliabilityState dataclass: defaults, reliability_score property, edge cases
  - ReliabilityMetadata dataclass: construction, defaults
  - NoOpReliabilityTracker: update, get_state, detect_drift, recalibrate,
    get_fusion_weights, list_agents, repr
  - ReliabilityTracker abstract interface verification
"""

import time
from unittest.mock import MagicMock

import pytest

from amoskys.intel.reliability import (
    DriftType,
    NoOpReliabilityTracker,
    RecalibrationTier,
    ReliabilityMetadata,
    ReliabilityState,
    ReliabilityTracker,
)

# ═══════════════════════════════════════════════════════════════════
# DriftType Enum
# ═══════════════════════════════════════════════════════════════════


class TestDriftType:
    """Test DriftType enum values."""

    def test_none_value(self):
        assert DriftType.NONE.value == "none"

    def test_abrupt_value(self):
        assert DriftType.ABRUPT.value == "abrupt"

    def test_gradual_value(self):
        assert DriftType.GRADUAL.value == "gradual"

    def test_all_members(self):
        assert len(DriftType) == 3

    def test_from_value(self):
        assert DriftType("none") == DriftType.NONE
        assert DriftType("abrupt") == DriftType.ABRUPT
        assert DriftType("gradual") == DriftType.GRADUAL

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            DriftType("invalid")


# ═══════════════════════════════════════════════════════════════════
# RecalibrationTier Enum
# ═══════════════════════════════════════════════════════════════════


class TestRecalibrationTier:
    """Test RecalibrationTier enum values."""

    def test_nominal_value(self):
        assert RecalibrationTier.NOMINAL.value == "nominal"

    def test_soft_value(self):
        assert RecalibrationTier.SOFT.value == "soft"

    def test_hard_value(self):
        assert RecalibrationTier.HARD.value == "hard"

    def test_quarantine_value(self):
        assert RecalibrationTier.QUARANTINE.value == "quarantine"

    def test_all_members(self):
        assert len(RecalibrationTier) == 4

    def test_from_value(self):
        assert RecalibrationTier("nominal") == RecalibrationTier.NOMINAL
        assert RecalibrationTier("quarantine") == RecalibrationTier.QUARANTINE


# ═══════════════════════════════════════════════════════════════════
# ReliabilityState Dataclass
# ═══════════════════════════════════════════════════════════════════


class TestReliabilityState:
    """Test ReliabilityState dataclass and reliability_score property."""

    def test_default_construction(self):
        state = ReliabilityState(agent_id="proc_agent")
        assert state.agent_id == "proc_agent"
        assert state.alpha == 1.0
        assert state.beta == 1.0
        assert state.fusion_weight == 1.0
        assert state.drift_type == DriftType.NONE
        assert state.tier == RecalibrationTier.NOMINAL
        assert state.last_update_ns == 0

    def test_custom_construction(self):
        state = ReliabilityState(
            agent_id="auth_agent",
            alpha=10.0,
            beta=2.0,
            fusion_weight=0.85,
            drift_type=DriftType.GRADUAL,
            tier=RecalibrationTier.SOFT,
            last_update_ns=123456789,
        )
        assert state.agent_id == "auth_agent"
        assert state.alpha == 10.0
        assert state.beta == 2.0
        assert state.fusion_weight == 0.85
        assert state.drift_type == DriftType.GRADUAL
        assert state.tier == RecalibrationTier.SOFT

    def test_reliability_score_default(self):
        """Default alpha=1, beta=1 gives 0.5."""
        state = ReliabilityState(agent_id="test")
        assert state.reliability_score == pytest.approx(0.5)

    def test_reliability_score_high_alpha(self):
        """High alpha relative to beta gives high reliability."""
        state = ReliabilityState(agent_id="test", alpha=9.0, beta=1.0)
        assert state.reliability_score == pytest.approx(0.9)

    def test_reliability_score_high_beta(self):
        """High beta relative to alpha gives low reliability."""
        state = ReliabilityState(agent_id="test", alpha=1.0, beta=9.0)
        assert state.reliability_score == pytest.approx(0.1)

    def test_reliability_score_zero_denominator(self):
        """Zero alpha and beta returns 0.5 (safe default)."""
        state = ReliabilityState(agent_id="test", alpha=0.0, beta=0.0)
        assert state.reliability_score == pytest.approx(0.5)

    def test_reliability_score_perfect(self):
        """alpha=100, beta=0 gives 1.0."""
        state = ReliabilityState(agent_id="test", alpha=100.0, beta=0.0)
        assert state.reliability_score == pytest.approx(1.0)

    def test_reliability_score_zero(self):
        """alpha=0, beta=100 gives 0.0."""
        state = ReliabilityState(agent_id="test", alpha=0.0, beta=100.0)
        assert state.reliability_score == pytest.approx(0.0)

    def test_reliability_score_is_property(self):
        """reliability_score should be a computed property, not stored."""
        state = ReliabilityState(agent_id="test", alpha=3.0, beta=1.0)
        assert state.reliability_score == pytest.approx(0.75)
        # Modify alpha and score should update
        state.alpha = 1.0
        assert state.reliability_score == pytest.approx(0.5)


# ═══════════════════════════════════════════════════════════════════
# ReliabilityMetadata Dataclass
# ═══════════════════════════════════════════════════════════════════


class TestReliabilityMetadata:
    """Test ReliabilityMetadata dataclass."""

    def test_construction_required_fields(self):
        meta = ReliabilityMetadata(
            agent_id="proc_agent",
            probe_id="cpu_probe",
            confidence_score=0.85,
        )
        assert meta.agent_id == "proc_agent"
        assert meta.probe_id == "cpu_probe"
        assert meta.confidence_score == 0.85

    def test_default_optional_fields(self):
        meta = ReliabilityMetadata(
            agent_id="test",
            probe_id="test_probe",
            confidence_score=0.5,
        )
        assert meta.reliability_score == 1.0
        assert meta.drift_indicator == DriftType.NONE

    def test_custom_optional_fields(self):
        meta = ReliabilityMetadata(
            agent_id="auth_agent",
            probe_id="ssh_probe",
            confidence_score=0.9,
            reliability_score=0.7,
            drift_indicator=DriftType.ABRUPT,
        )
        assert meta.reliability_score == 0.7
        assert meta.drift_indicator == DriftType.ABRUPT

    def test_confidence_score_range(self):
        """Confidence score can be 0 or 1."""
        meta_zero = ReliabilityMetadata(
            agent_id="a",
            probe_id="p",
            confidence_score=0.0,
        )
        assert meta_zero.confidence_score == 0.0

        meta_one = ReliabilityMetadata(
            agent_id="a",
            probe_id="p",
            confidence_score=1.0,
        )
        assert meta_one.confidence_score == 1.0


# ═══════════════════════════════════════════════════════════════════
# NoOpReliabilityTracker
# ═══════════════════════════════════════════════════════════════════


class TestNoOpReliabilityTracker:
    """Test the no-op implementation of ReliabilityTracker."""

    @pytest.fixture
    def tracker(self):
        return NoOpReliabilityTracker()

    # ── update ─────────────────────────────────────────────────

    def test_update_creates_state_for_new_agent(self, tracker):
        state = tracker.update("agent-1", ground_truth_match=True)
        assert state.agent_id == "agent-1"
        assert state.alpha == 1.0  # Unchanged (no-op)
        assert state.beta == 1.0

    def test_update_idempotent(self, tracker):
        """Multiple updates should not change alpha/beta (no-op)."""
        tracker.update("agent-1", ground_truth_match=True)
        tracker.update("agent-1", ground_truth_match=True)
        tracker.update("agent-1", ground_truth_match=False)
        state = tracker.get_state("agent-1")
        assert state.alpha == 1.0
        assert state.beta == 1.0

    def test_update_sets_timestamp(self, tracker):
        before = time.time_ns()
        state = tracker.update("agent-1", ground_truth_match=True)
        after = time.time_ns()
        assert before <= state.last_update_ns <= after

    def test_update_returns_same_state(self, tracker):
        """Successive updates should return the same state object."""
        state1 = tracker.update("agent-1", ground_truth_match=True)
        state2 = tracker.update("agent-1", ground_truth_match=False)
        assert state1 is state2

    def test_update_multiple_agents(self, tracker):
        """Each agent gets its own state."""
        s1 = tracker.update("agent-1", ground_truth_match=True)
        s2 = tracker.update("agent-2", ground_truth_match=False)
        assert s1.agent_id == "agent-1"
        assert s2.agent_id == "agent-2"
        assert s1 is not s2

    # ── get_state ──────────────────────────────────────────────

    def test_get_state_new_agent(self, tracker):
        """Unknown agent should get default state."""
        state = tracker.get_state("unknown-agent")
        assert state.agent_id == "unknown-agent"
        assert state.alpha == 1.0
        assert state.beta == 1.0
        assert state.fusion_weight == 1.0
        assert state.drift_type == DriftType.NONE
        assert state.tier == RecalibrationTier.NOMINAL

    def test_get_state_existing_agent(self, tracker):
        tracker.update("agent-1", ground_truth_match=True)
        state = tracker.get_state("agent-1")
        assert state.agent_id == "agent-1"

    def test_get_state_sets_timestamp(self, tracker):
        """get_state for a new agent should set last_update_ns."""
        state = tracker.get_state("new-agent")
        assert state.last_update_ns > 0

    # ── detect_drift ───────────────────────────────────────────

    def test_detect_drift_always_none(self, tracker):
        """NoOp tracker always returns no drift."""
        tracker.update("agent-1", ground_truth_match=True)
        drift_type, p_value = tracker.detect_drift("agent-1")
        assert drift_type == DriftType.NONE
        assert p_value == 1.0

    def test_detect_drift_unknown_agent(self, tracker):
        """Even unknown agents return NONE drift."""
        drift_type, p_value = tracker.detect_drift("nonexistent")
        assert drift_type == DriftType.NONE
        assert p_value == 1.0

    # ── recalibrate ────────────────────────────────────────────

    def test_recalibrate_always_nominal(self, tracker):
        """NoOp tracker always returns NOMINAL tier."""
        tracker.update("agent-1", ground_truth_match=False)
        tier = tracker.recalibrate("agent-1")
        assert tier == RecalibrationTier.NOMINAL

    def test_recalibrate_unknown_agent(self, tracker):
        tier = tracker.recalibrate("nonexistent")
        assert tier == RecalibrationTier.NOMINAL

    # ── get_fusion_weights ─────────────────────────────────────

    def test_fusion_weights_empty(self, tracker):
        """No agents tracked gives empty weights."""
        weights = tracker.get_fusion_weights()
        assert weights == {}

    def test_fusion_weights_all_ones(self, tracker):
        """All agents get weight 1.0."""
        tracker.update("agent-1", ground_truth_match=True)
        tracker.update("agent-2", ground_truth_match=False)
        tracker.update("agent-3", ground_truth_match=True)
        weights = tracker.get_fusion_weights()
        assert len(weights) == 3
        for agent_id, weight in weights.items():
            assert weight == 1.0

    def test_fusion_weights_includes_all_known(self, tracker):
        """Weights should include all agents seen via update or get_state."""
        tracker.update("agent-1", ground_truth_match=True)
        tracker.get_state("agent-2")  # Also creates state
        weights = tracker.get_fusion_weights()
        assert "agent-1" in weights
        assert "agent-2" in weights

    # ── list_agents ────────────────────────────────────────────

    def test_list_agents_empty(self, tracker):
        assert tracker.list_agents() == []

    def test_list_agents_after_updates(self, tracker):
        tracker.update("agent-A", ground_truth_match=True)
        tracker.update("agent-B", ground_truth_match=False)
        agents = tracker.list_agents()
        assert set(agents) == {"agent-A", "agent-B"}

    def test_list_agents_after_get_state(self, tracker):
        """get_state also creates agent entries."""
        tracker.get_state("agent-C")
        agents = tracker.list_agents()
        assert "agent-C" in agents

    # ── __repr__ ───────────────────────────────────────────────

    def test_repr_empty(self, tracker):
        r = repr(tracker)
        assert "NoOpReliabilityTracker" in r
        assert "agents=0" in r

    def test_repr_with_agents(self, tracker):
        tracker.update("a1", True)
        tracker.update("a2", False)
        r = repr(tracker)
        assert "agents=2" in r


# ═══════════════════════════════════════════════════════════════════
# ReliabilityTracker Abstract Interface
# ═══════════════════════════════════════════════════════════════════


class TestReliabilityTrackerInterface:
    """Test that ReliabilityTracker is a proper abstract class."""

    def test_cannot_instantiate_abstract(self):
        """Cannot instantiate ReliabilityTracker directly."""
        with pytest.raises(TypeError):
            ReliabilityTracker()

    def test_noop_implements_interface(self):
        """NoOpReliabilityTracker correctly implements the interface."""
        tracker = NoOpReliabilityTracker()
        assert isinstance(tracker, ReliabilityTracker)

    def test_abstract_methods_exist(self):
        """Verify all abstract methods are defined."""
        abstract_methods = ReliabilityTracker.__abstractmethods__
        assert "update" in abstract_methods
        assert "get_state" in abstract_methods
        assert "detect_drift" in abstract_methods
        assert "recalibrate" in abstract_methods
        assert "get_fusion_weights" in abstract_methods

    def test_incomplete_implementation_raises(self):
        """Partial implementation should fail to instantiate."""

        class Partial(ReliabilityTracker):
            def update(self, agent_id, ground_truth_match):
                return ReliabilityState(agent_id=agent_id)

            # Missing: get_state, detect_drift, recalibrate, get_fusion_weights

        with pytest.raises(TypeError):
            Partial()


# ═══════════════════════════════════════════════════════════════════
# NoOpReliabilityTracker Thread Safety / State Isolation
# ═══════════════════════════════════════════════════════════════════


class TestNoOpTrackerStateIsolation:
    """Verify agents have isolated state."""

    def test_modifying_one_agent_doesnt_affect_another(self):
        tracker = NoOpReliabilityTracker()
        s1 = tracker.update("agent-1", ground_truth_match=True)
        s2 = tracker.update("agent-2", ground_truth_match=True)

        # Manually modify s1
        s1.fusion_weight = 0.5
        assert s2.fusion_weight == 1.0  # Should be unaffected

    def test_state_persistence_across_operations(self):
        """State should persist across different method calls."""
        tracker = NoOpReliabilityTracker()
        tracker.update("agent-1", ground_truth_match=True)

        # These operations should not affect the tracked agents
        tracker.detect_drift("agent-1")
        tracker.recalibrate("agent-1")

        state = tracker.get_state("agent-1")
        assert state.agent_id == "agent-1"
        assert state.alpha == 1.0
        assert state.beta == 1.0

    def test_tracker_is_independent(self):
        """Two tracker instances should be independent."""
        t1 = NoOpReliabilityTracker()
        t2 = NoOpReliabilityTracker()

        t1.update("agent-X", ground_truth_match=True)
        assert "agent-X" not in [s for s in t2.list_agents()]
