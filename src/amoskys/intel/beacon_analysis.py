"""
AMOSKYS — two-axis beacon analysis (RITA/RITA-J style).

Research finding (RITA, Active Countermeasures): real C2 beaconing is regular in
BOTH connection TIMING and payload SIZE. Benign periodic traffic — software
update checks, telemetry, ssh keepalives, rsync — is regular in timing but
IRREGULAR in payload size, so it self-excludes on the size axis. Scoring a single
axis (or "same IP N times") is why AMOSKYS's c2_beacon_suspect over-fires on
Apple daemons and telemetry.

This module scores a series of connections to one destination on both axes and
returns a beacon score in [0,1]; only destinations regular on BOTH axes score
high. Pure-stdlib (no numpy) so it runs anywhere the analyzer runs.

Formulas (Active Countermeasures RITA):
  Bowley skewness  : 1 - |(P25 + P75 - 2*P50) / (P75 - P25)|      (1 = symmetric)
  MADM dispersion  : 1 - (median|x - median(x)|) / P50            (1 = tight)
  count score      : min(1, conn_count / (duration_sec / 90))     (~1/90s cadence)
Timing axis scores the inter-arrival deltas; size axis scores the payload bytes.
Overall = mean(timing_axis, size_axis), each axis = mean(skew, madm[, count]).
"""
from __future__ import annotations

from typing import List, Sequence

# A destination needs at least this many connections before beacon scoring is
# meaningful (RITA default; below this, dispersion stats are noise).
MIN_CONNECTIONS = 20
# Overall score at/above this is a strong beacon candidate.
BEACON_THRESHOLD = 0.70
# Timing jitter tolerated before the timing axis is penalised (seconds).
JITTER_TOLERANCE_S = 30.0


def _percentile(sorted_vals: Sequence[float], q: float) -> float:
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return float(sorted_vals[0])
    idx = q * (len(sorted_vals) - 1)
    lo = int(idx)
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = idx - lo
    return sorted_vals[lo] * (1 - frac) + sorted_vals[hi] * frac


def _median(vals: Sequence[float]) -> float:
    return _percentile(sorted(vals), 0.5)


def _bowley_skew_score(vals: Sequence[float]) -> float:
    """1 = perfectly symmetric distribution (regular), 0 = highly skewed.
    A zero-median series carries no signal (e.g. payload not recorded) and must
    score 0, NOT 1 — treating "no data" as "perfectly regular" is the bug that
    false-flags every destination as a beacon."""
    if len(vals) < 3:
        return 0.0
    s = sorted(vals)
    p25, p50, p75 = _percentile(s, 0.25), _percentile(s, 0.5), _percentile(s, 0.75)
    if p50 == 0:
        return 0.0  # no signal (degenerate / unrecorded)
    denom = p75 - p25
    if denom == 0:
        return 1.0  # nonzero and zero-spread -> genuinely regular
    skew = abs((p25 + p75 - 2 * p50) / denom)
    return max(0.0, 1.0 - skew)


def _madm_score(vals: Sequence[float], tolerance: float = 0.0) -> float:
    """1 = tightly clustered (low median abs deviation), 0 = dispersed or no
    signal. A zero median means no data on this axis -> 0, not 1."""
    if len(vals) < 3:
        return 0.0
    med = _median(vals)
    if med == 0:
        return 0.0  # no signal (unrecorded / degenerate)
    madm = _median([abs(v - med) for v in vals])
    adj = max(0.0, madm - tolerance)
    return max(0.0, 1.0 - (adj / med))


def _count_score(conn_count: int, duration_s: float) -> float:
    if duration_s <= 0:
        return 0.0
    return min(1.0, conn_count / (duration_s / 90.0))


def score_series(timestamps_s: Sequence[float], payload_bytes: Sequence[float]) -> dict:
    """Two-axis beacon score for one destination's connection series.

    Returns a dict with timing_score, size_score, overall, is_beacon, and the
    reason — so callers can EXPLAIN the verdict, not just emit it.
    """
    n = len(timestamps_s)
    if n < MIN_CONNECTIONS:
        return {
            "overall": 0.0, "timing_score": 0.0, "size_score": 0.0,
            "is_beacon": False, "connections": n,
            "reason": f"too few connections ({n} < {MIN_CONNECTIONS}) to assess",
        }

    ts = sorted(timestamps_s)
    deltas = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]
    duration = ts[-1] - ts[0]

    # Timing regularity = symmetry (catches right-skewed/random inter-arrivals)
    # AND tight dispersion (catches jitter). count_score is a cadence GATE, not a
    # regularity component — a busy benign host makes many connections too.
    # Jitter tolerance is PROPORTIONAL to the interval (not a fixed 30s): a fixed
    # absolute tolerance forgives ~random inter-arrivals whose median is small.
    med_delta = _median(deltas)
    jitter_tol = min(JITTER_TOLERANCE_S, max(1.0, 0.12 * med_delta))
    timing = 0.5 * _bowley_skew_score(deltas) + 0.5 * _madm_score(deltas, tolerance=jitter_tol)
    cadence = _count_score(n, duration)

    # Payload coverage: if the telemetry didn't record byte counts for most
    # connections, the SIZE axis is unassessable and we must NOT confirm a beacon
    # on timing alone — that is exactly the single-axis over-fire we're removing.
    nonzero = [b for b in payload_bytes if b and b > 0]
    payload_assessable = len(nonzero) >= max(3, MIN_CONNECTIONS // 2) and _median(payload_bytes) > 0

    if payload_assessable:
        # Size regularity is DISPERSION, not symmetry: real C2 callbacks are all
        # the same size (low CV -> ~1.0); benign polling returns variable sizes
        # (high CV -> low). A wide *symmetric* benign distribution must NOT pass,
        # so size is MADM-driven with only a small symmetry contribution.
        size = 0.8 * _madm_score(payload_bytes) + 0.2 * _bowley_skew_score(payload_bytes)
        overall = (timing + size) / 2.0
        # BOTH axes must be strongly regular. Cadence is informational only —
        # MIN_CONNECTIONS already guarantees enough samples, and gating on it
        # would wrongly reject legitimate SLOW beacons (e.g. 300s intervals).
        is_beacon = timing >= 0.70 and size >= 0.70
        if is_beacon:
            reason = "regular in both timing and payload size — beacon-like"
        elif timing >= 0.7 and size < 0.6:
            reason = "regular timing but VARIABLE payload — benign periodic (update/telemetry/ssh)"
        elif timing < 0.5:
            reason = "irregular timing — not a beacon"
        else:
            reason = "weak/partial regularity — inconclusive"
    else:
        size = 0.0
        overall = 0.0
        is_beacon = False  # honest: cannot confirm a beacon without payload data
        reason = (
            f"payload not recorded on {n - len(nonzero)}/{n} connections — "
            f"size axis unassessable (timing regularity {timing:.2f}); NOT confirmed"
        )

    return {
        "overall": round(overall, 3),
        "timing_score": round(timing, 3),
        "size_score": round(size, 3),
        "is_beacon": is_beacon,
        "payload_assessable": payload_assessable,
        "connections": n,
        "duration_s": round(duration, 1),
        "reason": reason,
    }


def score_connection_rows(rows: List[dict], ts_key: str = "ts", bytes_key: str = "bytes") -> dict:
    """Convenience wrapper for a list of {ts, bytes} dicts."""
    return score_series(
        [float(r.get(ts_key, 0) or 0) for r in rows],
        [float(r.get(bytes_key, 0) or 0) for r in rows],
    )
