"""Coverage reporting never rounds up.

A sensor we cannot prove is working is reported as not working. These tests pin
the four states apart, because collapsing any of them into "fine" reproduces the
exact bug this surface exists to answer: a green badge over missing data.
"""

from __future__ import annotations

import importlib
import sqlite3
import sys
import time
from pathlib import Path

import pytest

WEB_ROOT = Path(__file__).resolve().parents[2] / "web"
if str(WEB_ROOT) not in sys.path:
    sys.path.insert(0, str(WEB_ROOT))

coverage = importlib.import_module("app.dashboard.coverage")


@pytest.fixture()
def store(tmp_path, monkeypatch):
    """A fleet cache with one fresh sensor, one dark, one empty, one missing."""
    path = tmp_path / "fleet_cache.db"
    db = sqlite3.connect(path)
    now = time.time()
    for table in ("process_events", "flow_events", "dns_events", "security_events"):
        db.execute(
            f"CREATE TABLE {table} (id INTEGER PRIMARY KEY, device_id TEXT, timestamp_ns INTEGER)"
        )
    # fresh
    db.execute(
        "INSERT INTO process_events (device_id, timestamp_ns) VALUES (?, ?)",
        ("dev-1", int(now * 1e9)),
    )
    # dark (older than the stale window)
    db.execute(
        "INSERT INTO flow_events (device_id, timestamp_ns) VALUES (?, ?)",
        ("dev-1", int((now - 60 * 60 * 24 * 5) * 1e9)),
    )
    # stale (older than fresh, inside the day)
    db.execute(
        "INSERT INTO dns_events (device_id, timestamp_ns) VALUES (?, ?)",
        ("dev-1", int((now - 60 * 60 * 3) * 1e9)),
    )
    # security_events exists but has no rows -> absent
    db.commit()
    db.close()
    monkeypatch.setattr(coverage.insight_service, "resolve_db_path", lambda: str(path))
    # The kernel witness resolves its own store, so an unpatched test would read
    # whatever the developer's machine happens to be running — and the Sentinel
    # IS running here, which made this test pass or fail by accident.
    kernel = importlib.import_module("app.dashboard.kernel")
    monkeypatch.setattr(kernel, "_candidate_paths", lambda: [])
    return path


def _by_label(report):
    return {s["label"]: s for s in report["sensors"]}


def test_the_four_states_stay_distinct(store):
    report = coverage.report()
    sensors = _by_label(report)
    assert sensors["Processes"]["status"] == "fresh"
    assert sensors["DNS"]["status"] == "stale"
    assert sensors["Network"]["status"] == "dark"
    assert sensors["Detections"]["status"] == "absent"
    # fim/persistence/peripheral tables are not in this schema at all
    assert sensors["Files"]["status"] == "missing"


def test_a_table_absent_from_the_schema_is_reported_not_ignored(store):
    """The fleet sync is known to drop tables and columns silently."""
    sensors = _by_label(coverage.report())
    assert sensors["Peripherals"]["status"] == "missing"
    assert "schema" in sensors["Peripherals"]["age_human"]


def test_headline_counts_only_fresh_sensors(store):
    report = coverage.report()
    assert report["reporting"] == 1
    # The kernel witness is reported alongside the polling sensors, so the
    # denominator is one greater than the polling list.
    assert len(report["sensors"]) == len(coverage.SENSORS) + 1
    assert f"1 of {len(report['sensors'])} sensors reporting" in report["headline"]


def test_worst_sensors_are_listed_first(store):
    statuses = [s["status"] for s in coverage.report()["sensors"]]
    assert statuses.index("missing") < statuses.index("fresh")


def test_unreadable_store_is_a_gap_not_an_all_clear(monkeypatch):
    monkeypatch.setattr(coverage.insight_service, "resolve_db_path", lambda: None)
    report = coverage.report()
    assert report["available"] is False
    assert "not an all-clear" in report["detail"]


def test_no_sensor_reporting_says_what_that_means(tmp_path, monkeypatch):
    path = tmp_path / "empty.db"
    db = sqlite3.connect(path)
    db.execute(
        "CREATE TABLE process_events (id INTEGER PRIMARY KEY, timestamp_ns INTEGER)"
    )
    db.commit()
    db.close()
    monkeypatch.setattr(coverage.insight_service, "resolve_db_path", lambda: str(path))
    kernel = importlib.import_module("app.dashboard.kernel")
    monkeypatch.setattr(kernel, "_candidate_paths", lambda: [])
    report = coverage.report()
    assert report["reporting"] == 0
    assert "missing data" in report["detail"]


# ── The kernel witness ────────────────────────────────────────────────────────
def test_kernel_witness_is_reported_as_its_own_sensor(store, monkeypatch):
    """Witnessing an execution and sampling for it afterwards are different
    claims. The kernel row must never be folded into the polling sensors."""
    kernel = importlib.import_module("app.dashboard.kernel")
    monkeypatch.setattr(
        kernel,
        "stream_health",
        lambda *a, **k: {
            "present": True,
            "watching": True,
            "status": "witnessing",
            "dropped": 0,
            "last_beat_age_seconds": 12,
            "detail": "complete",
        },
    )
    sensors = _by_label(coverage.report())
    assert sensors["Kernel witness"]["status"] == "fresh"


def test_dropped_events_are_reported_as_a_hole_not_a_freshness_colour(
    store, monkeypatch
):
    kernel = importlib.import_module("app.dashboard.kernel")
    monkeypatch.setattr(
        kernel,
        "stream_health",
        lambda *a, **k: {
            "present": True,
            "watching": True,
            "status": "gapped",
            "dropped": 1234,
            "last_beat_age_seconds": 8,
            "detail": "holes",
        },
    )
    row = _by_label(coverage.report())["Kernel witness"]
    assert row["status"] == "stale"
    assert "1,234 events dropped" in row["age_human"]


def test_a_stopped_sentinel_is_dark_not_quiet(store, monkeypatch):
    kernel = importlib.import_module("app.dashboard.kernel")
    monkeypatch.setattr(
        kernel,
        "stream_health",
        lambda *a, **k: {
            "present": True,
            "watching": False,
            "status": "stopped",
            "dropped": 0,
            "last_beat_age_seconds": 4000,
            "detail": "stopped",
        },
    )
    assert _by_label(coverage.report())["Kernel witness"]["status"] == "dark"


def test_a_missing_blindness_ledger_is_not_reported_as_healthy(store):
    """list_blindness_events() returns [] both when the ledger is EMPTY and when
    the table is absent, and summarize() calls [] "healthy". On a synced fleet
    cache the table is simply missing — so the panel whose whole job is to
    report unseen gaps was reporting a missing ledger as a clean one."""
    report = coverage.report()
    assert report["blindness"]["status"] == "unknown"
    assert "not evidence" in report["blindness"]["message"]
