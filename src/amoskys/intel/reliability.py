"""AMRDR — Adaptive Multi-Agent Reliability Drift Recalibration.

This module provides reliability tracking for AMOSKYS agents using
Beta-Binomial posterior distributions with drift detection and
dynamic recalibration.

See: AMRDR_Mechanism_Specification_v0.1.docx

Components:
    - ReliabilityTracker (ABC): Interface contract
    - NoOpReliabilityTracker: Safe default (uniform weights, no drift)
    - BayesianReliabilityTracker: Full AMRDR implementation with
      ADWIN/EDDM drift detection and tier-based recalibration

Mathematical Foundation (Section 3):
    - Each agent's reliability is modeled as a Beta distribution: Beta(α, β)
    - α represents successes + prior belief
    - β represents failures + prior belief
    - Reliability score = E[reliability] = α / (α + β)
    - Drift detection uses ADWIN (Adaptive Windowing) for abrupt changes
    - Drift detection uses EDDM (Early Drift Detection Method) for gradual changes
"""

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class DriftType(Enum):
    """Types of reliability drift that can be detected."""

    NONE = "none"
    ABRUPT = "abrupt"  # Detected by ADWIN (sudden changes)
    GRADUAL = "gradual"  # Detected by EDDM (slow changes over time)


class RecalibrationTier(Enum):
    """Recalibration tiers for fusion weight adjustment.

    Based on AMRDR_Mechanism_Specification_v0.1.docx Section 5 (Recalibration Strategy).
    """

    NOMINAL = "nominal"  # No recalibration needed (full weight)
    SOFT = "soft"  # Apply λ=0.85 forgetting factor (downweight recent data)
    HARD = "hard"  # Reset to weakened prior (α/β ratio reset)
    QUARANTINE = "quarantine"  # Weight set to 0 (agent excluded from fusion)


@dataclass
class ReliabilityState:
    """Per-agent reliability state using Beta-Binomial posterior.

    Represents the current reliability assessment for a single agent.
    The Beta distribution parameters (α, β) encode both observed performance
    and prior beliefs about the agent's reliability.

    Attributes:
        agent_id: Unique identifier for the agent.
        alpha: Beta distribution α parameter (successes + prior). Default 1.0 (uniform prior).
        beta: Beta distribution β parameter (failures + prior). Default 1.0 (uniform prior).
        fusion_weight: Current fusion weight in [0, 1]. Determines how much this agent's
                      reports are weighted when combining with other agents.
        drift_type: Current drift classification (NONE, ABRUPT, GRADUAL).
        tier: Current recalibration tier (NOMINAL, SOFT, HARD, QUARANTINE).
        last_update_ns: Timestamp of last reliability update in nanoseconds.
    """

    agent_id: str
    alpha: float = 1.0  # Beta distribution α (successes + prior)
    beta: float = 1.0  # Beta distribution β (failures + prior)
    fusion_weight: float = 1.0  # Current fusion weight [0, 1]
    drift_type: DriftType = DriftType.NONE
    tier: RecalibrationTier = RecalibrationTier.NOMINAL
    last_update_ns: int = 0

    @property
    def reliability_score(self) -> float:
        """Compute E[reliability] = α / (α + β).

        Returns:
            Expected reliability value in [0, 1]. Returns 0.5 if α + β == 0.
        """
        denominator = self.alpha + self.beta
        if denominator > 0:
            return self.alpha / denominator
        return 0.5


@dataclass
class ReliabilityMetadata:
    """Metadata attached to each telemetry event for future fusion.

    This metadata is used by the AMRDR fusion engine to weight contributions
    from different agents during multi-agent fusion.

    Attributes:
        agent_id: Which agent produced this telemetry.
        probe_id: Which probe/sensor within the agent.
        confidence_score: Agent's self-assessed confidence in the report [0, 1].
        reliability_score: Reliability tracker's assessment of this agent's reliability.
                          Filled by ReliabilityTracker at fusion time.
        drift_indicator: Current drift classification for this agent.
    """

    agent_id: str
    probe_id: str
    confidence_score: float  # [0, 1] — probe's self-assessed confidence
    reliability_score: float = 1.0  # Filled by ReliabilityTracker
    drift_indicator: DriftType = DriftType.NONE


class ReliabilityTracker(ABC):
    """Interface for AMRDR reliability tracking.

    STUB: Implement when ready to integrate AMRDR fusion.
    See AMRDR_Mechanism_Specification_v0.1.docx Section 6 (Core Algorithm).

    This abstract class defines the interface that concrete AMRDR implementations
    must follow. The core responsibilities are:
        1. Update reliability posteriors with ground truth observations
        2. Track historical per-agent accuracy
        3. Detect reliability drift using statistical algorithms
        4. Recommend recalibration actions
        5. Provide fusion weights for multi-agent consensus
    """

    @abstractmethod
    def update(self, agent_id: str, ground_truth_match: bool) -> ReliabilityState:
        """Update reliability posterior with a ground truth observation.

        Called when an agent's report is validated against ground truth.
        Updates the Beta-Binomial posterior distribution for the agent.

        Args:
            agent_id: The agent to update.
            ground_truth_match: True if agent's report matched ground truth, False otherwise.

        Returns:
            Updated ReliabilityState for the agent.

        Implementation notes (from AMRDR spec Section 6.1):
            - Successful match: α += 1
            - Failed match: β += 1
            - Consider exponential smoothing for concept drift
        """
        ...

    @abstractmethod
    def get_state(self, agent_id: str) -> ReliabilityState:
        """Get current reliability state for an agent.

        Args:
            agent_id: The agent to query.

        Returns:
            Current ReliabilityState. Returns nominal state if agent unknown.
        """
        ...

    @abstractmethod
    def detect_drift(self, agent_id: str) -> Tuple[DriftType, float]:
        """Run ADWIN + EDDM drift detection.

        Examines historical performance of an agent to detect reliability changes.

        Args:
            agent_id: The agent to analyze.

        Returns:
            Tuple of (drift_type, p_value):
                - drift_type: DriftType.NONE, ABRUPT, or GRADUAL
                - p_value: Statistical significance (0.0 to 1.0)

        Implementation notes (from AMRDR spec Section 6.2):
            - ADWIN: Detects sudden changes in error rate using adaptive windowing
            - EDDM: Detects gradual changes by monitoring distance between errors
            - Return NONE if no significant drift detected
        """
        ...

    @abstractmethod
    def recalibrate(self, agent_id: str) -> RecalibrationTier:
        """Apply recalibration based on current drift state.

        Determines the appropriate recalibration tier based on detected drift
        and adjusts fusion weights accordingly.

        Args:
            agent_id: The agent to recalibrate.

        Returns:
            New RecalibrationTier for the agent.

        Implementation notes (from AMRDR spec Section 5):
            - NOMINAL: No drift detected, maintain full weight
            - SOFT: Gradual drift, apply λ=0.85 forgetting factor
            - HARD: Significant drift, reset to weakened prior
            - QUARANTINE: Severe drift, weight = 0 (agent excluded)
        """
        ...

    @abstractmethod
    def get_fusion_weights(self) -> Dict[str, float]:
        """Get current fusion weights for all agents.

        Returns:
            Dict mapping agent_id -> fusion_weight [0, 1].
            Used by fusion engine to combine multi-agent reports.
        """
        ...

    @abstractmethod
    def list_agents(self) -> List[str]:
        """List all agents currently tracked.

        Returns:
            List of agent_id strings.
        """
        ...


class NoOpReliabilityTracker(ReliabilityTracker):
    """No-op implementation — passes through all events with weight 1.0.

    Used until AMRDR is implemented. This is a safe default that:
        - Tracks state but does not modify reliability scores
        - Returns uniform weight 1.0 for all agents
        - Never detects drift
        - Never recommends recalibration

    Useful for:
        - Development and testing before AMRDR implementation
        - Baselines for comparing fusion strategies
        - Systems that don't need adaptive weighting
    """

    def __init__(self):
        """Initialize with empty state."""
        self._states: Dict[str, ReliabilityState] = {}
        self._logger = logger

    def update(self, agent_id: str, ground_truth_match: bool) -> ReliabilityState:
        """Record an observation but don't change reliability (no-op).

        Args:
            agent_id: The agent being updated.
            ground_truth_match: Whether the observation matched ground truth.

        Returns:
            The agent's current ReliabilityState (unchanged).
        """
        # Get or create state for this agent
        if agent_id not in self._states:
            self._states[agent_id] = ReliabilityState(
                agent_id=agent_id, last_update_ns=int(time.time_ns())
            )

        state = self._states[agent_id]
        state.last_update_ns = int(time.time_ns())

        self._logger.debug(
            f"NoOpReliabilityTracker.update: agent={agent_id}, "
            f"ground_truth_match={ground_truth_match} (no-op)"
        )

        return state

    def get_state(self, agent_id: str) -> ReliabilityState:
        """Get reliability state for an agent.

        Returns default nominal state if agent hasn't been seen before.

        Args:
            agent_id: The agent to query.

        Returns:
            ReliabilityState with default values (α=1, β=1, weight=1.0).
        """
        if agent_id not in self._states:
            self._states[agent_id] = ReliabilityState(
                agent_id=agent_id, last_update_ns=int(time.time_ns())
            )

        return self._states[agent_id]

    def detect_drift(self, agent_id: str) -> Tuple[DriftType, float]:
        """Drift detection stub — always returns NONE.

        Args:
            agent_id: The agent to analyze.

        Returns:
            (DriftType.NONE, 1.0) — no drift detected, high confidence.
        """
        self._logger.debug(
            f"NoOpReliabilityTracker.detect_drift: agent={agent_id} (returning NONE)"
        )
        return (DriftType.NONE, 1.0)

    def recalibrate(self, agent_id: str) -> RecalibrationTier:
        """Recalibration stub — always returns NOMINAL.

        Args:
            agent_id: The agent to recalibrate.

        Returns:
            RecalibrationTier.NOMINAL — no recalibration needed.
        """
        self._logger.debug(
            f"NoOpReliabilityTracker.recalibrate: agent={agent_id} "
            f"(returning NOMINAL)"
        )
        return RecalibrationTier.NOMINAL

    def get_fusion_weights(self) -> Dict[str, float]:
        """Get fusion weights — returns 1.0 for all agents.

        Returns:
            Dict mapping each known agent_id -> 1.0 (uniform weighting).
        """
        weights = {agent_id: 1.0 for agent_id in self._states.keys()}
        self._logger.debug(
            f"NoOpReliabilityTracker.get_fusion_weights: "
            f"returning uniform weights for {len(weights)} agents"
        )
        return weights

    def list_agents(self) -> List[str]:
        """List all agents that have been tracked.

        Returns:
            List of agent_id strings.
        """
        return list(self._states.keys())

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"NoOpReliabilityTracker(agents={len(self._states)}, "
            f"implementations=['update', 'get_state', 'detect_drift', "
            f"'recalibrate', 'get_fusion_weights'])"
        )


class BayesianReliabilityTracker(ReliabilityTracker):
    """Full AMRDR implementation: Beta-Binomial + ADWIN + EDDM + Recalibration.

    Core algorithm (AMRDR v0.1):
        1. Beta-Binomial posterior updates (α += 1 for match, β += 1 for miss)
        2. Exponential decay on historical observations (λ = 0.995)
        3. Sliding observation window (last 1000 observations)
        4. ADWIN drift detection (abrupt changes)
        5. EDDM drift detection (gradual degradation)
        6. Recalibration tier assignment (NOMINAL → SOFT → HARD → QUARANTINE)
        7. Fusion weight computation: reliability_score × tier_multiplier

    Args:
        store_path: Path to SQLite reliability database.
        decay_lambda: Exponential decay factor for old observations.
        window_size: Maximum observations to keep in memory per agent.
        adwin_epsilon: ADWIN confidence parameter (smaller = more conservative).
        eddm_min_obs: EDDM minimum observations before drift evaluation.
    """

    # Recalibration constants from AMRDR spec Section 5
    SOFT_LAMBDA = 0.85
    HARD_ALPHA_RESET = 2.0
    HARD_BETA_RESET = 2.0
    HARD_WEIGHT = 0.5
    QUARANTINE_THRESHOLD = 3  # consecutive hard recalibrations

    def __init__(
        self,
        store_path: str = "data/intel/reliability.db",
        decay_lambda: float = 0.995,
        window_size: int = 1000,
        adwin_epsilon: float = 0.01,
        eddm_min_obs: int = 30,
    ):
        from amoskys.intel.drift_detection import ADWINDetector, EDDMDetector
        from amoskys.intel.reliability_store import ReliabilityStore

        self._store = ReliabilityStore(store_path)
        self._decay_lambda = decay_lambda
        self._window_size = window_size
        self._adwin_epsilon = adwin_epsilon
        self._eddm_min_obs = eddm_min_obs
        self._logger = logger

        # Per-agent state
        self._states: Dict[str, ReliabilityState] = {}
        self._observations: Dict[str, List[bool]] = {}
        self._adwin: Dict[str, ADWINDetector] = {}
        self._eddm: Dict[str, EDDMDetector] = {}
        self._hard_count: Dict[str, int] = {}

        # Load persisted states
        self._load_stored_states()

    def _load_stored_states(self) -> None:
        """Load all persisted agent states from the store."""
        from amoskys.intel.drift_detection import ADWINDetector, EDDMDetector

        stored = self._store.load_all_states()
        for agent_id, state in stored.items():
            self._states[agent_id] = state
            self._observations[agent_id] = []
            self._adwin[agent_id] = ADWINDetector(epsilon=self._adwin_epsilon)
            self._eddm[agent_id] = EDDMDetector(min_observations=self._eddm_min_obs)
            self._hard_count[agent_id] = 0

        if stored:
            self._logger.info("Loaded %d agent states from store", len(stored))

    def _ensure_agent(self, agent_id: str) -> ReliabilityState:
        """Get or create state and detectors for an agent."""
        from amoskys.intel.drift_detection import ADWINDetector, EDDMDetector

        if agent_id not in self._states:
            self._states[agent_id] = ReliabilityState(
                agent_id=agent_id,
                last_update_ns=int(time.time_ns()),
            )
            self._observations[agent_id] = []
            self._adwin[agent_id] = ADWINDetector(epsilon=self._adwin_epsilon)
            self._eddm[agent_id] = EDDMDetector(min_observations=self._eddm_min_obs)
            self._hard_count[agent_id] = 0

        return self._states[agent_id]

    def update(self, agent_id: str, ground_truth_match: bool) -> ReliabilityState:
        """Update reliability posterior with a ground truth observation.

        Algorithm:
            1. Update α (match) or β (miss)
            2. Add observation to sliding window (trimmed to window_size)
            3. Feed to ADWIN + EDDM drift detectors
            4. If drift → recalibrate tier and fusion weight
            5. Persist updated state

        Args:
            agent_id: The agent to update.
            ground_truth_match: True if agent's report matched ground truth.

        Returns:
            Updated ReliabilityState.
        """
        state = self._ensure_agent(agent_id)

        # 1. Update Beta-Binomial posterior
        if ground_truth_match:
            state.alpha += 1.0
        else:
            state.beta += 1.0

        # 2. Sliding observation window
        obs = self._observations[agent_id]
        obs.append(ground_truth_match)
        if len(obs) > self._window_size:
            obs.pop(0)

        # 3. Feed drift detectors
        is_error = not ground_truth_match
        adwin_drift = self._adwin[agent_id].add_observation(is_error)
        eddm_drift, eddm_level = self._eddm[agent_id].add_observation(is_error)

        # 4. Determine drift type and recalibrate
        prev_drift = state.drift_type
        if adwin_drift:
            state.drift_type = DriftType.ABRUPT
        elif eddm_drift:
            state.drift_type = DriftType.GRADUAL
        else:
            # If no drift, potentially recover from previous drift
            if state.drift_type != DriftType.NONE and len(obs) > 50:
                recent_error_rate = 1.0 - (sum(obs[-50:]) / 50.0)
                if recent_error_rate < 0.1:
                    state.drift_type = DriftType.NONE
                    self._hard_count[agent_id] = 0

        # Apply recalibration based on drift state
        state.tier = self._apply_recalibration(agent_id, state)

        # Update fusion weight
        self._update_fusion_weight(state)

        # 5. Persist
        state.last_update_ns = int(time.time_ns())
        self._store.save_state(agent_id, state)

        reason = ""
        if state.drift_type != DriftType.NONE:
            reason = f"drift={state.drift_type.value}, " f"tier={state.tier.value}"
        self._store.log_observation(agent_id, ground_truth_match, reason)

        self._logger.debug(
            "BayesianTracker.update: agent=%s match=%s "
            "α=%.1f β=%.1f weight=%.3f drift=%s tier=%s",
            agent_id,
            ground_truth_match,
            state.alpha,
            state.beta,
            state.fusion_weight,
            state.drift_type.value,
            state.tier.value,
        )

        return state

    def get_state(self, agent_id: str) -> ReliabilityState:
        """Get current reliability state for an agent.

        Returns nominal state if agent hasn't been seen before.
        """
        return self._ensure_agent(agent_id)

    def detect_drift(self, agent_id: str) -> Tuple[DriftType, float]:
        """Return current drift classification for an agent.

        Returns:
            Tuple of (DriftType, confidence) where confidence is
            the reliability score (higher = more confident in assessment).
        """
        state = self._ensure_agent(agent_id)
        confidence = state.reliability_score
        return (state.drift_type, confidence)

    def recalibrate(self, agent_id: str) -> RecalibrationTier:
        """Apply recalibration based on current drift state.

        Returns the tier that was applied.
        """
        state = self._ensure_agent(agent_id)
        tier = self._apply_recalibration(agent_id, state)
        state.tier = tier
        self._update_fusion_weight(state)
        self._store.save_state(agent_id, state)
        return tier

    def get_fusion_weights(self) -> Dict[str, float]:
        """Get current fusion weights for all tracked agents.

        Returns:
            Dict mapping agent_id → fusion_weight [0, 1].
        """
        return {
            agent_id: state.fusion_weight for agent_id, state in self._states.items()
        }

    def list_agents(self) -> List[str]:
        """List all tracked agents."""
        return list(self._states.keys())

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _apply_recalibration(
        self, agent_id: str, state: ReliabilityState
    ) -> RecalibrationTier:
        """Determine and apply recalibration tier based on drift.

        AMRDR v0.1 Section 5:
            NOMINAL: No drift → weight = reliability_score
            SOFT: Gradual drift → weight = reliability_score × 0.85
            HARD: Abrupt drift → reset α=2, β=2, weight = 0.5
            QUARANTINE: ≥3 consecutive hard → weight = 0.0
        """
        if state.drift_type == DriftType.NONE:
            self._hard_count[agent_id] = 0
            return RecalibrationTier.NOMINAL

        if state.drift_type == DriftType.GRADUAL:
            self._hard_count[agent_id] = 0
            return RecalibrationTier.SOFT

        if state.drift_type == DriftType.ABRUPT:
            self._hard_count[agent_id] = self._hard_count.get(agent_id, 0) + 1

            if self._hard_count[agent_id] >= self.QUARANTINE_THRESHOLD:
                self._logger.warning(
                    "Agent %s quarantined: %d consecutive hard recalibrations",
                    agent_id,
                    self._hard_count[agent_id],
                )
                return RecalibrationTier.QUARANTINE

            # Hard reset
            state.alpha = self.HARD_ALPHA_RESET
            state.beta = self.HARD_BETA_RESET
            self._logger.info(
                "Agent %s hard recalibrated: α=%.1f, β=%.1f (count=%d)",
                agent_id,
                state.alpha,
                state.beta,
                self._hard_count[agent_id],
            )
            return RecalibrationTier.HARD

        return RecalibrationTier.NOMINAL

    def _update_fusion_weight(self, state: ReliabilityState) -> None:
        """Set fusion weight based on current tier and reliability score."""
        score = state.reliability_score

        if state.tier == RecalibrationTier.NOMINAL:
            state.fusion_weight = score
        elif state.tier == RecalibrationTier.SOFT:
            state.fusion_weight = score * self.SOFT_LAMBDA
        elif state.tier == RecalibrationTier.HARD:
            state.fusion_weight = self.HARD_WEIGHT
        elif state.tier == RecalibrationTier.QUARANTINE:
            state.fusion_weight = 0.0

    def __repr__(self) -> str:
        quarantined = sum(
            1 for s in self._states.values() if s.tier == RecalibrationTier.QUARANTINE
        )
        drifting = sum(
            1 for s in self._states.values() if s.drift_type != DriftType.NONE
        )
        return (
            f"BayesianReliabilityTracker("
            f"agents={len(self._states)}, "
            f"drifting={drifting}, "
            f"quarantined={quarantined})"
        )
