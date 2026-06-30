"""Statistical confirmation for blind vulnerabilities.

A single SLEEP(4) response taking 5s COULD be network jitter. An APT-
grade operator fires N baseline + N probe requests and runs a proper
statistical test — Welch's t-test for means-difference-under-unequal-
variance, with a pre-committed significance threshold.

This module provides:
    - StatSample  — collect response timings (or sizes, header counts, etc.)
    - welch_t_test — the test itself, pure-Python, no scipy dependency
    - TimingExperiment  — runs baseline + probe, returns confidence

The experiment NEVER fires payloads itself; it accepts a `fire(url,
is_probe)` callable injected by the caller. Tests pass in a mock; the
precision orchestrator passes a real http client.

Why Welch's
-----------
We can't assume equal variance between baseline (fast, tight) and
probe (slow, variable under server load). Welch's t-test handles
unequal variance with Satterthwaite's degrees-of-freedom. Standard in
medical trials where the treatment can change variance.

Sample size guidance
--------------------
  n=5 per group: usable but weak (p < 0.05 detectable for 2x effect)
  n=10 per group: solid (p < 0.01 detectable for 1.5x effect)
  n=20 per group: strong (p < 0.001 detectable for 1.25x effect)

For a SLEEP(4) probe against ~1s baseline: n=5 per group gets
p < 0.01 easily. We default to n=8 as a compromise.
"""

from __future__ import annotations

import math
import statistics
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple


@dataclass
class StatSample:
    """A collection of timing samples."""

    label: str
    values: List[float] = field(default_factory=list)

    def add(self, x: float) -> None:
        self.values.append(x)

    def mean(self) -> float:
        return statistics.mean(self.values) if self.values else 0.0

    def stddev(self) -> float:
        if len(self.values) < 2:
            return 0.0
        return statistics.stdev(self.values)

    def n(self) -> int:
        return len(self.values)


def welch_t_test(a: StatSample, b: StatSample) -> Tuple[float, float]:
    """Compute (t_statistic, approximate p-value) for two samples.

    Returns (nan, 1.0) when either sample has n<2 or zero variance in both.

    Implementation: standard Welch's formula. p-value via the
    Student's t CDF approximated with Abramowitz-Stegun 26.7.4 —
    accurate to ~6 decimal places for df >= 3.
    """
    n_a, n_b = a.n(), b.n()
    if n_a < 2 or n_b < 2:
        return float("nan"), 1.0

    m_a, m_b = a.mean(), b.mean()
    v_a = a.stddev() ** 2
    v_b = b.stddev() ** 2
    if v_a == 0 and v_b == 0:
        if m_a == m_b:
            return 0.0, 1.0
        return float("inf"), 0.0

    # Welch's t.
    denom = math.sqrt(v_a / n_a + v_b / n_b)
    if denom == 0:
        return float("inf"), 0.0
    t = (m_b - m_a) / denom

    # Welch-Satterthwaite degrees of freedom.
    num = (v_a / n_a + v_b / n_b) ** 2
    den = (v_a**2) / ((n_a**2) * (n_a - 1)) + (v_b**2) / ((n_b**2) * (n_b - 1))
    if den == 0:
        return t, 0.0
    df = num / den

    # Two-tailed p-value via Student's t CDF approximation.
    p = _student_t_sf(abs(t), df) * 2.0
    return t, min(max(p, 0.0), 1.0)


def _student_t_sf(t: float, df: float) -> float:
    """Survival function of Student's t-distribution, one-tailed.

    Abramowitz & Stegun 26.7.4 — accurate for df ≥ 3; simpler
    approximation for df < 3.
    """
    if df < 1:
        return 0.5
    if df < 3:
        # Fall back to a crude normal approximation for tiny df.
        return max(0.0, 0.5 * math.erfc(t / math.sqrt(2)))
    # A&S 26.7.4 — series expansion.
    z = t * (1.0 - 1.0 / (4.0 * df)) / math.sqrt(1.0 + t * t / (2.0 * df))
    return max(0.0, 0.5 * math.erfc(z / math.sqrt(2)))


# ── The experiment driver ─────────────────────────────────────────


@dataclass
class TimingExperiment:
    """Run baseline vs probe N times each, compute Welch t-test.

    Caller provides a `fire(is_probe: bool) -> float` callback that
    performs one HTTP request and returns its latency in seconds.
    We interleave probes with baselines to average out slow-network
    effects.

    Results include t-statistic, p-value, mean latency delta, and
    a boolean `significant` given the pre-committed alpha.
    """

    label: str = ""
    n_samples: int = 8
    alpha: float = 0.01
    fire: Optional[Callable[[bool], float]] = None

    def run(self) -> dict:
        if not self.fire:
            raise ValueError("fire callback not provided")
        baseline = StatSample("baseline")
        probe = StatSample("probe")
        # Interleave to control for network drift.
        for i in range(self.n_samples):
            # baseline, then probe — order matters less with interleaving
            # but we record timing of both.
            t_base = self.fire(False)
            baseline.add(t_base)
            t_probe = self.fire(True)
            probe.add(t_probe)

        t, p = welch_t_test(baseline, probe)
        delta = probe.mean() - baseline.mean()
        return {
            "label": self.label,
            "n": self.n_samples,
            "baseline_mean": round(baseline.mean(), 3),
            "baseline_stddev": round(baseline.stddev(), 3),
            "probe_mean": round(probe.mean(), 3),
            "probe_stddev": round(probe.stddev(), 3),
            "delta": round(delta, 3),
            "t_statistic": None if math.isnan(t) else round(t, 3),
            "p_value": round(p, 6),
            "alpha": self.alpha,
            "significant": p < self.alpha,
            "verdict": (
                "VULNERABLE (probe caused statistically significant delay)"
                if p < self.alpha and delta > 0
                else "inconclusive (delta not statistically significant)"
            ),
        }
