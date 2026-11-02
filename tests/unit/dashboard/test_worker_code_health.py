"""A stale worker must change the kernel verdict, not sit beside it.

The failure this guards against: on 2026-08-30 the ESF collector had been
running ~23 hours of pre-quarantine code. It dropped the quarantine column from
every exec row while the stream itself was perfectly healthy — events arriving,
inserts succeeding, heartbeat current. stream_health() would have said "the
kernel is witnessing every execution" and "this timeline is complete", which is
true of the stream and false of the record.

The supervisor had detected it and logged it 20 times. Nobody reads a log file.
"""
import pytest

from app.dashboard import kernel


def _fresh():
    return [
        {"worker": "amoskys.analyzer_main", "pid": 1, "stale": False,
         "behind_seconds": None, "running": True},
    ]


def _stale(behind=82800):
    return [
        {"worker": "amoskys.analyzer_main", "pid": 1, "stale": False,
         "behind_seconds": None, "running": True},
        {"worker": "amoskys.agents.os.macos.esf", "pid": 19920, "stale": True,
         "behind_seconds": behind, "running": True},
    ]


def test_stale_worker_downgrades_a_healthy_stream(monkeypatch):
    monkeypatch.setattr(kernel, "_worker_code_health", lambda db: _stale())
    h = kernel.stream_health()
    if not h.get("present"):
        pytest.skip("no ESF store on this tier")
    assert h["status"] == "degraded", (
        "a stale worker must outrank a clean stream — the reassuring headline "
        "is the sentence that stops the investigation"
    )
    assert "older code" in h["headline"]
    # The blast radius must be stated, not just the fact.
    assert "23.0h behind" in h["detail"]
    assert "19920" in h["detail"]


def test_fresh_workers_do_not_downgrade(monkeypatch):
    monkeypatch.setattr(kernel, "_worker_code_health", lambda db: _fresh())
    h = kernel.stream_health()
    if not h.get("present"):
        pytest.skip("no ESF store on this tier")
    assert h["status"] != "degraded"


def test_unmeasurable_is_not_reported_as_clean(monkeypatch):
    """None means the store cannot answer. It must not read as 'all current'."""
    monkeypatch.setattr(kernel, "_worker_code_health", lambda db: None)
    h = kernel.stream_health()
    if not h.get("present"):
        pytest.skip("no ESF store on this tier")
    assert h["workers_measurable"] is False
    assert h["workers"] is None
    assert h["status"] != "degraded"  # absence of evidence is not an alarm either
