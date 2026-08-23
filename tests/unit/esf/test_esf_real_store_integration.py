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


# ── the composite detector ───────────────────────────────────────────────
def test_composite_fires_only_on_novel_untrusted_nonplatform(real_store):
    """Each factor must be necessary. If any one is droppable it is not earning
    its place in the conjunction, and the alert rate collapses back toward the
    3,655/day of 'non-platform alone' or the 157/day of 'novelty alone'."""
    collector = ESFStreamCollector(real_store, device_id="d")
    now = time.time_ns()
    collector.ingest([
        # fires: novel + non-platform + adhoc
        _exec_line(now, 100, 1, "/private/tmp/dropper", "EVIL",
                   signed=False, valid=False, adhoc=True),
        # suppressed: platform binary, however novel
        _exec_line(now + 10**8, 101, 1, "/bin/newthing", "PLAT", platform=True),
        # suppressed: properly signed
        _exec_line(now + 2 * 10**8, 102, 1, "/Applications/Ok.app/ok", "SIGNED"),
    ])
    res = real_store.esf_composite_alerts(hours=1)
    hashes = {a["cdhash"] for a in res["alerts"]}
    assert hashes == {"EVIL"}, f"expected only EVIL, got {hashes}"
    assert res["bits_per_alert"] is not None


def test_composite_suppresses_a_binary_with_an_old_first_seen(real_store):
    """A long-known binary must not re-alert every time it runs.

    Novelty is a property of the LEDGER's first sighting, not of the current
    event. Comparing against event time would make every execution of a
    familiar tool 'novel' forever.
    """
    collector = ESFStreamCollector(real_store, device_id="d")
    now = time.time_ns()
    collector.ingest([_exec_line(now, 100, 1, "/tmp/tool", "OLD",
                                 signed=False, adhoc=True)])
    real_store._execute(
        "UPDATE esf_binary_ledger SET first_seen_ns = ? WHERE cdhash = 'OLD'",
        (now - 30 * 86400 * 10**9,))
    real_store._commit()
    res = real_store.esf_composite_alerts(hours=1, novelty_window_s=7 * 86400)
    assert res["count"] == 0


def test_verdict_retires_a_binary_from_alerting(real_store):
    """The feedback loop the incident stack never had.

    1,314 incidents were raised in 24h and zero were ever closed, which is
    precisely why severity stayed pinned at 97% critical: a detector with no
    way to learn 'that one was fine' cannot converge, only accumulate.
    """
    collector = ESFStreamCollector(real_store, device_id="d")
    now = time.time_ns()
    collector.ingest([_exec_line(now, 100, 1, "/tmp/mytool", "MINE",
                                 signed=False, adhoc=True)])
    assert real_store.esf_composite_alerts(hours=1)["count"] == 1
    real_store.esf_set_verdict(cdhash="MINE", verdict="benign", note="my build")
    assert real_store.esf_composite_alerts(hours=1)["count"] == 0


def test_quiet_result_refuses_to_self_certify(real_store):
    """Zero alerts from zero execs is arithmetic, not evidence — the same
    error as '0 threat-intel matches against 0 indicators'."""
    res = real_store.esf_composite_alerts(hours=1)
    assert res["count"] == 0
    assert "arithmetic, not evidence" in res["note"]


def test_repeat_executions_collapse_to_one_alert(real_store):
    """A repeat alert for a known cdhash carries zero marginal information.

    Measured on live data before this fix: 8 raw alerts resolved to 3 distinct
    binaries, so 5 of 8 were pure repetition. Emitting them is how a precise
    signal decays into another undifferentiated feed — the exact failure mode
    of the severity field it was built to replace.
    """
    collector = ESFStreamCollector(real_store, device_id="d")
    now = time.time_ns()
    collector.ingest([
        _exec_line(now + i * 10**8, 200 + i, 1, "/tmp/tool", "SAME",
                   signed=False, adhoc=True)
        for i in range(5)
    ])
    res = real_store.esf_composite_alerts(hours=1)
    assert res["count"] == 1, "five executions of one binary is ONE finding"
    alert = res["alerts"][0]
    assert alert["execution_count"] == 5, "executions kept as evidence"
    assert len(alert["executions"]) == 5


def test_relocation_across_paths_is_surfaced_on_the_alert(real_store):
    """Same hash, several paths — the relocation signal a path list can't give."""
    collector = ESFStreamCollector(real_store, device_id="d")
    now = time.time_ns()
    collector.ingest([
        _exec_line(now, 300, 1, "/private/tmp/x", "MOVED", signed=False, adhoc=True),
        _exec_line(now + 10**8, 301, 1, "/Users/a/.cache/x", "MOVED",
                   signed=False, adhoc=True),
    ])
    res = real_store.esf_composite_alerts(hours=1)
    assert res["count"] == 1
    assert res["alerts"][0]["distinct_paths"] == 2
