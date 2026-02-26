"""Drift Detection Algorithms — ADWIN and EDDM.

Implements two statistical drift detection algorithms from
AMRDR_Mechanism_Specification_v0.1 Sections 6.2-6.3:

- ADWINDetector: Adaptive Windowing for abrupt drift detection.
  Maintains a variable-length window of error observations and splits
  when two sub-windows have statistically different means.

- EDDMDetector: Early Drift Detection Method for gradual drift.
  Tracks distance between consecutive errors and detects when
  the distance distribution shifts significantly.
"""

from __future__ import annotations

import logging
import math
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ADWIN — Adaptive Windowing (Abrupt Drift)
# ---------------------------------------------------------------------------


class ADWINDetector:
    """Adaptive Windowing for abrupt drift detection.

    ADWIN maintains a variable-length window of error observations.
    When the window can be split into two sub-windows with
    statistically different means (Hoeffding bound), abrupt drift
    is declared and the older sub-window is dropped.

    Reference: AMRDR v0.1 Section 6.2; Bifet & Gavaldà (2007).

    Args:
        epsilon: Confidence parameter (default 0.01 = 99% confidence).
            Smaller epsilon → more conservative drift detection.
        min_window: Minimum observations before evaluating drift.
    """

    def __init__(self, epsilon: float = 0.01, min_window: int = 10):
        self.epsilon = epsilon
        self.min_window = min_window
        self._window: Deque[float] = deque()
        self._total: float = 0.0
        self._variance: float = 0.0
        self._width: int = 0
        self._drift_detected: bool = False

    @property
    def window_size(self) -> int:
        """Current number of observations in the window."""
        return self._width

    @property
    def mean(self) -> float:
        """Mean of the current window."""
        if self._width == 0:
            return 0.0
        return self._total / self._width

    def add_observation(self, is_error: bool) -> bool:
        """Process a single observation.

        Args:
            is_error: True if the observation is an error, False if correct.

        Returns:
            True if drift was detected (window was cut), False otherwise.
        """
        value = 1.0 if is_error else 0.0
        self._window.append(value)
        self._total += value
        self._width += 1
        self._drift_detected = False

        if self._width < self.min_window:
            return False

        # Try all possible cut points
        self._drift_detected = self._check_for_drift()
        return self._drift_detected

    def detected_drift(self) -> bool:
        """Check if the most recent observation triggered drift."""
        return self._drift_detected

    def reset(self) -> None:
        """Reset the detector to its initial state."""
        self._window.clear()
        self._total = 0.0
        self._variance = 0.0
        self._width = 0
        self._drift_detected = False

    def _check_for_drift(self) -> bool:
        """Check all possible cut points for statistical divergence.

        Uses Hoeffding bound to determine if two sub-windows
        have significantly different means.

        Returns:
            True if a valid cut was found (drift detected).
        """
        n = self._width
        if n < 2 * self.min_window:
            return False

        # Running statistics for the left sub-window
        left_sum = 0.0
        left_n = 0

        # Total window statistics
        total_sum = self._total
        total_n = n

        best_cut = -1

        for i in range(n - 1):
            left_sum += self._window[i]
            left_n += 1

            right_n = total_n - left_n
            if left_n < self.min_window or right_n < self.min_window:
                continue

            right_sum = total_sum - left_sum

            left_mean = left_sum / left_n
            right_mean = right_sum / right_n

            # Hoeffding bound
            m = 1.0 / (1.0 / left_n + 1.0 / right_n)
            delta = self.epsilon / math.log(n)
            if delta <= 0:
                continue
            epsilon_cut = math.sqrt((1.0 / (2.0 * m)) * math.log(4.0 / delta))

            if abs(left_mean - right_mean) >= epsilon_cut:
                best_cut = i
                break  # Found a valid cut — drop the older sub-window

        if best_cut >= 0:
            # Drop observations up to and including the cut point
            for _ in range(best_cut + 1):
                removed = self._window.popleft()
                self._total -= removed
                self._width -= 1

            logger.debug(
                "ADWIN drift detected: cut at %d, new window size %d",
                best_cut,
                self._width,
            )
            return True

        return False


# ---------------------------------------------------------------------------
# EDDM — Early Drift Detection Method (Gradual Drift)
# ---------------------------------------------------------------------------


class EDDMDetector:
    """Early Drift Detection Method for gradual drift.

    EDDM tracks the distance (number of observations) between
    consecutive errors. When the distance distribution shifts
    significantly from its maximum, gradual drift is detected.

    Warning level: p_i + 2*s_i < p_max + 2*s_max
    Drift level:   p_i + 2*s_i < 0.9 * (p_max + 2*s_max)

    Reference: AMRDR v0.1 Section 6.3; Baena-García et al. (2006).

    Args:
        min_observations: Minimum error-distance samples before evaluating.
        alpha: Drift threshold multiplier (default 0.9).
    """

    # Level constants
    LEVEL_NONE = "NONE"
    LEVEL_WARNING = "WARNING"
    LEVEL_DRIFT = "DRIFT"

    def __init__(
        self,
        min_observations: int = 30,
        alpha: float = 0.9,
    ):
        self.min_observations = min_observations
        self.alpha = alpha

        # Distance tracking
        self._observation_count: int = 0
        self._last_error_index: int = 0
        self._error_count: int = 0

        # Running statistics for distance between errors
        self._distance_sum: float = 0.0
        self._distance_sq_sum: float = 0.0
        self._distance_count: int = 0

        # Maximum p + 2s observed
        self._p_max: float = 0.0
        self._s_max: float = 0.0
        self._max_metric: float = 0.0

        # Current state
        self._level: str = self.LEVEL_NONE
        self._drift_detected: bool = False

    @property
    def level(self) -> str:
        """Current detection level: NONE, WARNING, or DRIFT."""
        return self._level

    def add_observation(self, is_error: bool) -> Tuple[bool, str]:
        """Process a single observation.

        Args:
            is_error: True if the observation is an error.

        Returns:
            Tuple of (drift_detected, level) where level is
            'NONE', 'WARNING', or 'DRIFT'.
        """
        self._observation_count += 1
        self._drift_detected = False

        if not is_error:
            return (False, self._level)

        # This is an error — compute distance from last error
        self._error_count += 1

        if self._error_count == 1:
            # First error — record position, no distance yet
            self._last_error_index = self._observation_count
            return (False, self.LEVEL_NONE)

        distance = float(self._observation_count - self._last_error_index)
        self._last_error_index = self._observation_count

        # Update running statistics
        self._distance_count += 1
        self._distance_sum += distance
        self._distance_sq_sum += distance * distance

        if self._distance_count < 2:
            return (False, self.LEVEL_NONE)

        # Compute current mean and std of distances
        p_i = self._distance_sum / self._distance_count
        variance = (self._distance_sq_sum / self._distance_count) - (p_i * p_i)
        s_i = math.sqrt(max(0.0, variance))

        current_metric = p_i + 2.0 * s_i

        # Update maximum
        if current_metric > self._max_metric:
            self._max_metric = current_metric
            self._p_max = p_i
            self._s_max = s_i

        # Only evaluate after enough samples
        if self._distance_count < self.min_observations:
            self._level = self.LEVEL_NONE
            return (False, self._level)

        # Check drift levels
        if current_metric < self.alpha * self._max_metric:
            self._level = self.LEVEL_DRIFT
            self._drift_detected = True
            logger.debug(
                "EDDM drift detected: metric=%.4f, max=%.4f, " "threshold=%.4f",
                current_metric,
                self._max_metric,
                self.alpha * self._max_metric,
            )
            return (True, self.LEVEL_DRIFT)
        elif current_metric < self._max_metric:
            self._level = self.LEVEL_WARNING
            return (False, self.LEVEL_WARNING)
        else:
            self._level = self.LEVEL_NONE
            return (False, self.LEVEL_NONE)

    def detected_drift(self) -> bool:
        """Check if the most recent observation triggered drift."""
        return self._drift_detected

    def reset(self) -> None:
        """Reset the detector to its initial state."""
        self._observation_count = 0
        self._last_error_index = 0
        self._error_count = 0
        self._distance_sum = 0.0
        self._distance_sq_sum = 0.0
        self._distance_count = 0
        self._p_max = 0.0
        self._s_max = 0.0
        self._max_metric = 0.0
        self._level = self.LEVEL_NONE
        self._drift_detected = False

    @property
    def statistics(self) -> dict:
        """Return current detector statistics for debugging."""
        p_i = (
            self._distance_sum / self._distance_count
            if self._distance_count > 0
            else 0.0
        )
        variance = (
            (self._distance_sq_sum / self._distance_count) - (p_i * p_i)
            if self._distance_count > 0
            else 0.0
        )
        s_i = math.sqrt(max(0.0, variance))

        return {
            "observation_count": self._observation_count,
            "error_count": self._error_count,
            "distance_count": self._distance_count,
            "mean_distance": p_i,
            "std_distance": s_i,
            "current_metric": p_i + 2.0 * s_i,
            "max_metric": self._max_metric,
            "level": self._level,
        }
