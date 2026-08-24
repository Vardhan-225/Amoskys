"""The kernel dashboard must not bury rare events or hide kernel-side loss.

Two defects, both of the same species: a function whose docstring described the
correct behaviour while the implementation did the opposite one level up.
"""

import json
import os
import sqlite3
import tempfile
import time

import pytest

MIGS = [
    "src/amoskys/storage/migrations/sql/015_esf_exec_forensics.sql",
    "src/amoskys/storage/migrations/sql/016_esf_kernel_events.sql",
]
NS = 1_000_000_000


@pytest.fixture
def kdb(tmp_path, monkeypatch):
    path = tmp_path / "telemetry.db"
    conn = sqlite3.connect(str(path))
    for m in MIGS:
        with open(m) as fh:
            conn.executescript(fh.read())
    conn.commit()
    conn.close()
    from app.dashboard import kernel as k
    monkeypatch.setattr(k, "_candidate_paths", lambda: [str(path)])
    return str(path), k


def _txn(path, kind, ts, exe="/usr/libexec/xpcproxy", platform=1, detail=None):
    c = sqlite3.connect(path)
    c.execute(
        "INSERT INTO esf_kernel_events "
        "(timestamp_ns, device_id, kind, pid, euid, exe, cdhash, is_platform, detail) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (ts, "d", kind, 1, 501, exe, "H", platform,
         json.dumps(detail) if detail else None))
    c.commit(); c.close()


def test_a_rare_event_outside_the_recency_window_still_surfaces(kdb):
    """The defect this file exists for.

    Fetching the most RECENT n and sorting them by severity only reorders
    within that window — a rare event outside it never becomes a candidate.
    Measured on the live machine: the 40 newest transitions were all
    setuid/setgid, so both kextload events in the same window were invisible.
    """
    path, k = kdb
    now = time.time_ns()
    # One rare event, deliberately OLD.
    _txn(path, "kextload", now - 20 * 3600 * NS, exe="/System/Library/Kernels/kernel")
    # Then a flood of common ones, all newer.
    for i in range(60):
        _txn(path, "setuid", now - i * NS)

    r = k.transitions(hours=24, limit=40)
    kinds = [e["kind"] for e in r["events"]]
    assert "kextload" in kinds, (
        "a rare event older than the recency cut was buried by the flood")
    assert kinds[0] == "kextload", "severity must outrank recency"


def test_severity_order_is_stable_and_descending(kdb):
    path, k = kdb
    now = time.time_ns()
    for kind in ("unmount", "mount", "setgid", "setuid", "kextload", "cs_invalidated"):
        _txn(path, kind, now)
    r = k.transitions(hours=24, limit=40)
    sev = [e["severity"] for e in r["events"]]
    assert sev == sorted(sev, reverse=True)
    assert r["events"][0]["kind"] == "cs_invalidated"


def test_kernel_side_drops_change_the_health_verdict(kdb):
    """Without this the status reads 'watching, record intact' at the exact
    moment the kernel had discarded events."""
    path, k = kdb
    now = time.time_ns()
    c = sqlite3.connect(path)
    c.execute("INSERT INTO esf_exec_events (timestamp_ns, device_id, exe, cdhash) "
              "VALUES (?,?,?,?)", (now, "d", "/bin/ls", "A"))
    c.execute("INSERT INTO esf_stream_health (timestamp_ns, device_id, dropped, enforce_mode) "
              "VALUES (?,?,?,?)", (now, "d", 0, 0))
    c.execute("INSERT INTO esf_kernel_drops "
              "(timestamp_ns, device_id, event_type, dropped, seq_num) "
              "VALUES (?,?,?,?,?)", (now, "d", 9, 41, 100))
    c.commit(); c.close()

    h = k.stream_health(window_hours=24)
    assert h["kernel_dropped"] == 41
    assert h["status"] == "gapped", "kernel-side loss must not read as intact"
    assert "kernel" in h["headline"].lower()


def test_our_drops_and_kernel_drops_are_never_summed(kdb):
    """They have opposite remedies — a bigger buffer versus a lighter
    subscription — so merging them hides which half is failing."""
    path, k = kdb
    now = time.time_ns()
    c = sqlite3.connect(path)
    c.execute("INSERT INTO esf_exec_events (timestamp_ns, device_id, exe, cdhash) "
              "VALUES (?,?,?,?)", (now, "d", "/bin/ls", "A"))
    c.execute("INSERT INTO esf_stream_health (timestamp_ns, device_id, dropped, enforce_mode) "
              "VALUES (?,?,?,?)", (now, "d", 7, 0))
    c.execute("INSERT INTO esf_kernel_drops "
              "(timestamp_ns, device_id, event_type, dropped, seq_num) "
              "VALUES (?,?,?,?,?)", (now, "d", 9, 5, 1))
    c.commit(); c.close()
    h = k.stream_health(window_hours=24)
    assert h["dropped"] == 7 and h["kernel_dropped"] == 5


def test_absent_transition_table_does_not_crash_the_view(tmp_path, monkeypatch):
    """An older schema must degrade, not explode."""
    path = tmp_path / "old.db"
    c = sqlite3.connect(str(path))
    with open(MIGS[0]) as fh:
        c.executescript(fh.read())      # 015 only: no esf_kernel_events
    c.commit(); c.close()
    from app.dashboard import kernel as k
    monkeypatch.setattr(k, "_candidate_paths", lambda: [str(path)])
    r = k.transitions(hours=24)
    assert r["present"] is False and r["count"] == 0
    assert "subscription" in r["detail"].lower()
