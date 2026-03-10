"""Rolling Window Aggregator — cumulative metric tracking across collection cycles.

Individual agents use per-scan thresholds. An attacker can stay just below
the threshold each scan (e.g., 4 SSH failures when threshold is 5). The
rolling window tracks cumulative metrics across a configurable time window
(default: 300 seconds / 5 minutes), catching slow-and-low attacks.

Phase 1 (snapshot):
    th1: SSH brute force < 5 per scan → cumulative >= 5 in 5 minutes
    th2: Exfil < 10MB per scan → cumulative >= 10MB in 5 minutes
    th3: Account lockout < 10 per scan → cumulative >= 10 in 5 minutes
    th4: C2 beacon < 3 hits per scan → cumulative >= 3 in 5 minutes

Phase 2 (temporal):
    rate()            — sustained throughput (bytes/sec, failures/sec)
    acceleration()    — rate-of-change in rate (speeding up / slowing down)
    burst_score()     — max event density in any sub-window (burst detection)
    jitter_score()    — coefficient of variation of inter-event intervals (periodicity)
    dominant_period() — median inter-event interval when periodic (beaconing)
"""

from __future__ import annotations

import math
import statistics
import time
from collections import defaultdict, deque
from typing import Deque, Dict, List, Optional, Tuple


class RollingWindowAggregator:
    """Track cumulative metrics across collection cycles within a time window.

    Thread-safe is NOT required — this lives inside a single agent's collect loop.

    Usage:
        rolling = RollingWindowAggregator(window_seconds=300.0)

        # Each collection cycle, feed metrics
        rolling.add("ssh_fail:10.0.0.1", 3.0)   # 3 failures from this IP
        rolling.add("bytes_out:curl", 5_000_000)  # 5MB this cycle

        # Check cumulative totals across the window
        rolling.total("ssh_fail:10.0.0.1")  # → 3.0 (or more from prior cycles)
        rolling.total("bytes_out:curl")      # → 5000000 (or more)

        # Temporal analysis
        rolling.rate("bytes_out:curl")       # → bytes per second
        rolling.burst_score("ssh_fail:x")    # → max density in burst window
        rolling.jitter_score("beacon:x")     # → 0..1 (1 = perfectly periodic)
    """

    def __init__(self, window_seconds: float = 300.0) -> None:
        self._window = window_seconds
        self._entries: Dict[str, Deque[Tuple[float, float]]] = defaultdict(deque)

    def add(self, key: str, value: float, ts: Optional[float] = None) -> None:
        """Add a measurement. Automatically evicts entries outside the window."""
        now = ts if ts is not None else time.time()
        self._entries[key].append((now, value))
        self._evict(key, now)

    def total(self, key: str) -> float:
        """Sum of all values within the current window."""
        self._evict(key)
        return sum(v for _, v in self._entries[key])

    def count(self, key: str) -> int:
        """Count of entries within the current window."""
        self._evict(key)
        return len(self._entries[key])

    def get_entries(self, key: str) -> List[Tuple[float, float]]:
        """All (timestamp, value) pairs within the current window."""
        self._evict(key)
        return list(self._entries[key])

    def keys(self) -> List[str]:
        """All tracked keys."""
        return list(self._entries.keys())

    def keys_with_prefix(self, prefix: str) -> List[str]:
        """All tracked keys matching a prefix (e.g., 'ssh_fail:')."""
        return [k for k in self._entries if k.startswith(prefix)]

    def reset(self) -> None:
        """Clear all entries."""
        self._entries.clear()

    # ── Temporal analysis methods ────────────────────────────────────────────

    def rate(self, key: str) -> float:
        """Average rate of value accumulation per second within window.

        Returns total_value / elapsed_time_seconds.
        Returns 0.0 if fewer than 2 entries or zero elapsed time.
        Used by: ExfilAccelerationProbe, AuthVelocityProbe.
        """
        entries = self.get_entries(key)
        if len(entries) < 2:
            return 0.0
        elapsed = entries[-1][0] - entries[0][0]
        if elapsed <= 0:
            return 0.0
        total_val = sum(v for _, v in entries)
        return total_val / elapsed

    def acceleration(self, key: str, sub_window_seconds: float = 60.0) -> float:
        """Rate-of-change in rate — detects speeding up or slowing down.

        Splits the window into sub-windows of sub_window_seconds length,
        computes rate in each, then returns the slope of the rate trend
        (linear regression). Positive = accelerating, negative = decelerating.

        Returns 0.0 if insufficient data (< 2 sub-windows with entries).
        Used by: AuthVelocityProbe, ExfilAccelerationProbe.
        """
        entries = self.get_entries(key)
        if len(entries) < 3:
            return 0.0

        t_min = entries[0][0]
        t_max = entries[-1][0]
        span = t_max - t_min
        if span <= 0:
            return 0.0

        # Build sub-window rates
        n_windows = max(2, int(math.ceil(span / sub_window_seconds)))
        actual_sub = span / n_windows
        rates: List[Tuple[float, float]] = []  # (relative_midpoint, rate)

        for i in range(n_windows):
            w_start = t_min + i * actual_sub
            w_end = w_start + actual_sub
            w_entries = [(t, v) for t, v in entries if w_start <= t < w_end]
            if w_entries:
                w_total = sum(v for _, v in w_entries)
                w_rate = w_total / actual_sub if actual_sub > 0 else 0.0
                # Use relative offset from t_min to avoid float precision loss
                # with large epoch timestamps (~1.7e9 squared loses precision)
                midpoint_offset = i * actual_sub + actual_sub / 2
                rates.append((midpoint_offset, w_rate))

        if len(rates) < 2:
            return 0.0

        # Linear regression slope: Δrate / Δtime (using relative offsets)
        n = len(rates)
        sum_t = sum(r[0] for r in rates)
        sum_r = sum(r[1] for r in rates)
        sum_tr = sum(r[0] * r[1] for r in rates)
        sum_t2 = sum(r[0] ** 2 for r in rates)
        denom = n * sum_t2 - sum_t**2
        if abs(denom) < 1e-12:
            return 0.0
        return (n * sum_tr - sum_t * sum_r) / denom

    def burst_score(self, key: str, burst_window_seconds: float = 10.0) -> float:
        """Max event density within any sliding sub-window.

        Returns max(count_in_any_burst_window) / burst_window_seconds.
        A high score means events are clustered, not spread evenly.
        Returns 0.0 if fewer than 2 entries.
        Used by: AuthVelocityProbe for burst brute-force detection.
        """
        entries = self.get_entries(key)
        if len(entries) < 2:
            return 0.0

        max_count = 0
        timestamps = [t for t, _ in entries]

        # Sliding window over sorted timestamps
        left = 0
        for right in range(len(timestamps)):
            while timestamps[right] - timestamps[left] > burst_window_seconds:
                left += 1
            window_count = right - left + 1
            if window_count > max_count:
                max_count = window_count

        return max_count / burst_window_seconds

    def jitter_score(self, key: str) -> float:
        """Periodicity score based on coefficient of variation of inter-event intervals.

        CV = stddev(intervals) / mean(intervals). Low CV = periodic.
        Returns 1.0 - CV (clamped to [0, 1]), so higher = more periodic.
        Returns 0.0 if insufficient data (< 3 entries needed for >= 2 intervals).
        Used by: BeaconingProbe.
        """
        entries = self.get_entries(key)
        if len(entries) < 3:
            return 0.0

        timestamps = sorted(t for t, _ in entries)
        intervals = [
            timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)
        ]

        # Filter out zero intervals (simultaneous events)
        intervals = [iv for iv in intervals if iv > 0]
        if len(intervals) < 2:
            return 0.0

        mean_iv = statistics.mean(intervals)
        if mean_iv <= 0:
            return 0.0
        stdev_iv = statistics.stdev(intervals)
        cv = stdev_iv / mean_iv

        # Score: 1.0 = perfectly periodic, 0.0 = completely random
        return max(0.0, min(1.0, 1.0 - cv))

    def dominant_period(self, key: str) -> Optional[float]:
        """Estimated dominant repetition period in seconds.

        Returns the median inter-event interval if jitter_score > 0.6
        (i.e., the pattern is sufficiently periodic). Returns None if
        no clear periodicity is detected.
        Used by: BeaconingProbe.
        """
        if self.jitter_score(key) < 0.6:
            return None

        entries = self.get_entries(key)
        timestamps = sorted(t for t, _ in entries)
        intervals = [
            timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)
        ]
        intervals = [iv for iv in intervals if iv > 0]
        if not intervals:
            return None
        return statistics.median(intervals)

    # ── Internal ─────────────────────────────────────────────────────────────

    def _evict(self, key: str, now: Optional[float] = None) -> None:
        """Remove entries outside the time window."""
        if now is None:
            now = time.time()
        cutoff = now - self._window
        q = self._entries[key]
        while q and q[0][0] < cutoff:
            q.popleft()
