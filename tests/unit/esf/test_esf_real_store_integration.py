"""ESF collector against the REAL TelemetryStore, not a stand-in.

WHY THIS FILE EXISTS. test_esf_forensics.py builds a minimal fake store
exposing execute()/executemany(). Every one of its tests passed while the
collector was completely broken in production, because TelemetryStore has
NEITHER method — it exposes _execute/_executemany/_commit, which carry the
lock backoff the rest of the store depends on. The suite was validating the
mock's interface rather than the integration, so the first live run failed with
AttributeError after the tests had reported success.

A mock is a claim about an interface. This file checks the claim.
"""

import json
import os
import tempfile
import time

import pytest

from amoskys.agents.os.macos.esf.collector import ESFStreamCollector
from amoskys.storage.telemetry_store import TelemetryStore


@pytest.fixture
def real_store(tmp_path, monkeypatch):
    db = tmp_path / "telemetry.db"
    monkeypatch.setenv("AMOSKYS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AMOSKYS_TELEMETRY_DB", str(db))
    store = TelemetryStore(str(db))
    mig = "src/amoskys/storage/migrations/sql/015_esf_exec_forensics.sql"
    if os.path.exists(mig):
        with open(mig) as fh:
            store.db.executescript(fh.read())
        store.db.commit()
    return store


def _exec_line(t, pid, ppid, exe, cdhash, **kw):
    rec = {
        "v": 1, "t": t, "pid": pid, "ppid": ppid, "uid": 501, "exe": exe,
        "argv": [os.path.basename(exe)], "cdhash": cdhash, "cs_flags": 0,
        "signed": True, "valid": True, "adhoc": False, "platform": False,
        "signing_id": "", "team_id": "", "decision": "allow", "reason": "allow",
    }
    rec.update(kw)
    return json.dumps(rec)


def test_store_exposes_the_api_the_collector_calls(real_store):
    """Guards the exact AttributeError that reached production.

    Asserted by name rather than exercised indirectly, so the failure message
    says which method is missing instead of surfacing as a mystery traceback
    inside a batch flush.
    """
    for method in ("_execute", "_executemany", "_commit"):
        assert hasattr(real_store, method), (
            f"TelemetryStore is missing {method}; the ESF collector calls it"
        )


def test_executemany_twin_exists_and_batches(real_store):
    """_execute had no batch twin, so callers reached past it and lost retry."""
    real_store._execute(
        "CREATE TABLE IF NOT EXISTS _t (a INTEGER, b TEXT)")
    real_store._executemany(
        "INSERT INTO _t (a, b) VALUES (?, ?)", [(1, "x"), (2, "y"), (3, "z")])
    real_store._commit()
    n = real_store.db.execute("SELECT COUNT(*) FROM _t").fetchone()[0]
    assert n == 3


def test_end_to_end_ingest_persists_and_reconstructs(real_store):
    """The full path: NDJSON -> real store -> forensic query."""
    collector = ESFStreamCollector(real_store, device_id="test-device")
    now = time.time_ns()
    collector.ingest([
        "amoskys-sentinel: guarding exec (mode=MONITOR, fail-open).",
        json.dumps({"v": 1, "t": now, "type": "sentinel_start",
                    "enforce": False, "buffer": 4096}),
        _exec_line(now + 10**8, 900, 1, "/Applications/X.app/Contents/MacOS/X", "aaa"),
        _exec_line(now + 2 * 10**8, 901, 900, "/bin/zsh", "bbb", platform=True),
        _exec_line(now + 3 * 10**8, 902, 901, "/private/tmp/drop", "ccc",
                   signed=False, valid=False, adhoc=True,
                   decision="would_deny", reason="adhoc from /private/tmp/"),
    ])

    persisted = real_store.db.execute(
        "SELECT COUNT(*) FROM esf_exec_events").fetchone()[0]
    assert persisted == 3, "rows must actually reach the real database"

    ledger = real_store.db.execute(
        "SELECT COUNT(*) FROM esf_binary_ledger").fetchone()[0]
    assert ledger == 3

    rc = real_store.esf_reconstruct(pid=902, at_ns=now + 10**9)
    assert rc["process"]["exe"] == "/private/tmp/drop"
    assert rc["process"]["trust"] == "unsigned"
    chain = [a.get("exe") for a in rc["ancestry"] if a.get("exe")]
    assert "/bin/zsh" in chain and any("X.app" in c for c in chain)


def test_drops_reach_the_real_stream_health_table(real_store):
    collector = ESFStreamCollector(real_store, device_id="d")
    now = time.time_ns()
    collector.ingest([
        _exec_line(now, 1, 0, "/bin/ls", "a"),
        json.dumps({"v": 1, "t": now + 10**8, "type": "heartbeat",
                    "dropped": 13, "enforce": False}),
    ])
    row = real_store.db.execute(
        "SELECT dropped FROM esf_stream_health").fetchone()
    assert row is not None and row[0] == 13
    tl = real_store.esf_timeline(start_ns=now - 10**9, end_ns=now + 10**10)
    assert tl["complete"] is False and tl["dropped_in_window"] == 13
