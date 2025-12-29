import math

from amoskys.agents.flowagent.main import sleep_with_jitter


def test_sleep_with_jitter_bounds(monkeypatch):
    called = {"t": 0.0}

    def fake_sleep(x):
        called["t"] = x

    monkeypatch.setattr("time.sleep", fake_sleep)
    sleep_with_jitter(200)
    t = called["t"]
    assert 0.24 <= t <= 0.32


def test_sleep_with_jitter_floor(monkeypatch):
    called = {"t": 0.0}
    monkeypatch.setattr("time.sleep", lambda x: called.__setitem__("t", x))
    sleep_with_jitter(0)
    assert 0.06 <= called["t"] <= 0.08
