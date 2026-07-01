"""Two-axis beacon analysis — ground-truth calibration tests.

Locks the RITA-style detector so it keeps separating real C2 (regular in BOTH
timing and payload size) from benign periodic traffic (regular timing, variable
payload) and honestly declines when payload isn't recorded.
"""
import random

from amoskys.intel import beacon_analysis as ba


def _regular_ts(interval=60, n=60, start=1000.0):
    return [start + i * interval for i in range(n)]


def test_true_c2_fixed_payload_regular_timing():
    r = ba.score_series(_regular_ts(), [512] * 60)
    assert r["is_beacon"] is True
    assert r["timing_score"] >= 0.9 and r["size_score"] >= 0.9


def test_true_c2_with_small_jitter():
    random.seed(1)
    ts = sorted(1000 + i * 60 + random.uniform(-5, 5) for i in range(60))
    pay = [512 + random.randint(-8, 8) for _ in range(60)]
    assert ba.score_series(ts, pay)["is_beacon"] is True


def test_true_c2_slow_beacon():
    # 40 connections at a slow 300s cadence must still confirm.
    r = ba.score_series([1000 + i * 300 for i in range(40)], [4096] * 40)
    assert r["is_beacon"] is True


def test_benign_regular_timing_variable_payload():
    random.seed(1)
    r = ba.score_series(_regular_ts(), [random.randint(200, 90000) for _ in range(60)])
    assert r["is_beacon"] is False  # variable payload -> benign


def test_benign_random_timing_fixed_payload():
    random.seed(2)
    ts = sorted(random.uniform(1000, 5000) for _ in range(60))
    assert ba.score_series(ts, [512] * 60)["is_beacon"] is False  # irregular timing


def test_benign_random_timing_variable_payload():
    random.seed(3)
    ts = sorted(random.uniform(1000, 5000) for _ in range(60))
    r = ba.score_series(ts, [random.randint(200, 90000) for _ in range(60)])
    assert r["is_beacon"] is False


def test_payload_unrecorded_is_not_confirmed():
    # The real-telemetry case: bytes mostly 0 -> size axis unassessable ->
    # must NOT confirm a beacon on timing alone.
    r = ba.score_series(_regular_ts(), [0] * 60)
    assert r["is_beacon"] is False
    assert r["payload_assessable"] is False


def test_too_few_connections():
    r = ba.score_series(_regular_ts(n=5), [512] * 5)
    assert r["is_beacon"] is False
    assert r["connections"] == 5
