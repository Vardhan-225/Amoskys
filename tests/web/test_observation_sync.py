"""The observation domain that never synced.

Measured on the live fleet backend: 202,000 observation_events, ZERO carrying
event_timestamp_ns and only 2.8% carrying a payload. The fleet cache requires
timestamp_ns, timestamp_dt and attributes NOT NULL, so every exported row was
rejected — "0 of 5000 exported rows accepted", once a minute, for the life of
the deployment. 171k unified_log rows, 9.6k provenance, 5.6k realtime sensor:
an entire telemetry domain that never reached the presentation tier, while the
sync reported success for the other eight tables.
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

WEB_ROOT = Path(__file__).resolve().parents[2] / "web"
if str(WEB_ROOT) not in sys.path:
    sys.path.insert(0, str(WEB_ROOT))

from app.dashboard import telemetry_bridge as tb  # noqa: E402


def _cache() -> sqlite3.Connection:
    """The cache's real observation_events shape, NOT NULL constraints included."""
    db = sqlite3.connect(":memory:")
    db.execute(
        """CREATE TABLE observation_events (
             id INTEGER PRIMARY KEY,
             timestamp_ns INTEGER NOT NULL,
             timestamp_dt TEXT NOT NULL,
             device_id TEXT NOT NULL,
             domain TEXT NOT NULL,
             attributes TEXT NOT NULL,
             event_id TEXT, org_id TEXT, source_id TEXT,
             received_at REAL, quality_state TEXT, raw_attributes_json TEXT)"""
    )
    return db


def _ops_rows(n: int = 3) -> list[dict]:
    """Exactly what the backend exports today — three fields null in every row."""
    return [
        {
            "id": str(39047957 + i),
            "source_id": str(9123913 + i),
            "device_id": "b45045f5e1a0c15e",
            "org_id": "bd045a8b-b570-49b7-8f40-0a7e7179cea8",
            "event_id": None,
            "domain": "unified_log",
            "event_timestamp_ns": None,
            "raw_attributes_json": None,
            "received_at": "1787947473.8009417",
        }
        for i in range(n)
    ]


def test_observations_with_no_event_time_still_land():
    db = _cache()
    assert tb._upsert_rows(db, "observation_events", _ops_rows(5)) == 5


def test_the_inferred_timestamp_is_labelled_as_inferred():
    """received_at is when the BACKEND received it, not when it happened. A
    reader has to be able to tell which timestamps were observed."""
    db = _cache()
    tb._upsert_rows(db, "observation_events", _ops_rows(1))
    state, ts = db.execute(
        "SELECT quality_state, timestamp_ns FROM observation_events"
    ).fetchone()
    assert state == "timestamp_inferred_from_receipt"
    assert ts == int(1787947473.8009417 * 1e9)


def test_a_missing_payload_becomes_an_empty_object_not_a_fabrication():
    db = _cache()
    tb._upsert_rows(db, "observation_events", _ops_rows(1))
    assert db.execute("SELECT attributes FROM observation_events").fetchone()[0] == "{}"


def test_a_real_event_time_is_never_overwritten_by_the_receipt_time():
    """The fallback must only fill a gap, never replace an observation."""
    db = _cache()
    rows = _ops_rows(1)
    rows[0]["event_timestamp_ns"] = 1700000000000000000
    tb._upsert_rows(db, "observation_events", rows)
    ts, state = db.execute(
        "SELECT timestamp_ns, quality_state FROM observation_events"
    ).fetchone()
    assert ts == 1700000000000000000
    assert state != "timestamp_inferred_from_receipt"


def test_a_row_with_neither_a_time_nor_a_receipt_is_still_rejected():
    """The fallback is a bounded approximation of a real moment, not a licence
    to invent one."""
    db = _cache()
    rows = _ops_rows(1)
    rows[0]["received_at"] = None
    assert tb._upsert_rows(db, "observation_events", rows) == 0


@pytest.mark.parametrize("domain", ["unified_log", "provenance", "infostealer"])
def test_every_observation_domain_lands(domain):
    db = _cache()
    rows = _ops_rows(1)
    rows[0]["domain"] = domain
    assert tb._upsert_rows(db, "observation_events", rows) == 1
