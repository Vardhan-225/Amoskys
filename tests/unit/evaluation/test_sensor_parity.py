"""ESF vs polling must be measured SEPARATELY, and replacement must be earned.

The failure this guards against is not a wrong number — it is a comfortable
one. Blending two sensors and reporting combined coverage produces a figure
that is true, flattering, and useless: it hides which source did the work,
makes a permanent hybrid look like a finished migration, and means a
regression in the new sensor is silently absorbed by the old one.
"""

import sqlite3
import time
from contextlib import contextmanager

import pytest

from amoskys.evaluation.sensor_parity import SensorParity

MIG = "src/amoskys/storage/migrations/sql/015_esf_exec_forensics.sql"


@pytest.fixture
def store(tmp_path):
    conn = sqlite3.connect(str(tmp_path / "t.db"))
    with open(MIG) as fh:
        conn.executescript(fh.read())
    # Mirrors the columns the production queries actually SELECT. A stub that
    # omits one passes locally and fails on the real store — the mock-validates-
    # the-mock failure that already bit the ESF collector once this session.
    conn.execute("""CREATE TABLE process_events (
        timestamp_ns INTEGER, pid INTEGER, ppid INTEGER, exe TEXT, cmdline TEXT,
        name TEXT, username TEXT, collection_agent TEXT, create_time REAL)""")
    conn.commit()

    class S:
        db = conn
        class _P:
            @contextmanager
            def connection(self):
                yield conn
        _read_pool = _P()
    return S()


def _esf(store, ts, exe, pid=1, cdhash="H"):
    store.db.execute(
        "INSERT INTO esf_exec_events (timestamp_ns, device_id, exe, cdhash, pid, ppid) "
        "VALUES (?,?,?,?,?,?)", (ts, "d", exe, cdhash, pid, 1))
    store.db.commit()


def _poll(store, ts, exe, pid=1, create_time=None):
    store.db.execute(
        "INSERT INTO process_events (timestamp_ns, pid, ppid, exe, collection_agent, create_time) "
        "VALUES (?,?,?,?,?,?)", (ts, pid, 1, exe, "macos_process", create_time))
    store.db.commit()


def test_no_overlap_is_reported_not_papered_over(store):
    """Disjoint windows measure uptime, not capability."""
    now = time.time_ns()
    _esf(store, now, "/bin/a")
    _poll(store, now - 10 * 86400 * 10**9, "/bin/b", create_time=1.0)
    r = SensorParity(store).compare()
    assert r["verdict"] == "no_overlap"
    assert "uptime" in r["note"] or "disjoint" in r["note"]


def test_short_window_refuses_to_recommend_replacement(store):
    """A sensor that looks better for two hours has proven nothing."""
    now = time.time_ns()
    for i in range(5):
        _esf(store, now + i * 10**9, f"/bin/e{i}")
        _poll(store, now + i * 10**9, f"/bin/e{i}", create_time=(now / 1e9) + i)
    v = SensorParity(store).compare()["verdict"]
    assert v["decision"] == "insufficient_evidence"
    assert v["hours_required"] == 168.0


def test_prestart_processes_are_excluded_from_the_head_to_head(store):
    """ESF witnesses execs, so it CANNOT see something already running.

    Counting those against it measures the Sentinel's uptime, not its
    capability, and would understate it permanently — a restart does not fix
    a process that started yesterday.
    """
    now = time.time_ns()
    start = now
    # Both sensors must actually SPAN the window, or overlap_window() correctly
    # reports no_overlap — a single event at one instant overlaps nothing.
    _esf(store, start, "/bin/shared")
    _esf(store, start + 5 * 10**9, "/bin/shared2")
    _poll(store, start + 10**9, "/bin/shared", create_time=start / 1e9)
    _poll(store, start + 4 * 10**9, "/bin/shared", create_time=start / 1e9)
    # started long before the window — must not count against ESF
    _poll(store, start + 2 * 10**9, "/Applications/Old.app/Old",
          create_time=(start / 1e9) - 86400)
    r = SensorParity(store).compare()
    assert "/Applications/Old.app/Old" not in r["only_polling_saw"]
    assert r["polling_only_prestart"] >= 1


def test_dropped_events_block_replacement(store, monkeypatch):
    """A sensor that loses evidence under load cannot replace one that doesn't."""
    p = SensorParity(store)
    v = p._verdict(esf_n=100, poll_n=100, only_esf=50, only_poll=1,
                   dropped=7, duration_s=200 * 3600)
    assert v["decision"] == "esf_not_ready"
    assert "dropped 7" in v["reason"]


def test_replacement_recommended_only_when_all_conditions_hold(store):
    p = SensorParity(store)
    v = p._verdict(esf_n=10000, poll_n=10000, only_esf=80, only_poll=10,
                   dropped=0, duration_s=200 * 3600)
    assert v["decision"] == "esf_supersedes"
    v2 = p._verdict(esf_n=10000, poll_n=10000, only_esf=10, only_poll=80,
                    dropped=0, duration_s=200 * 3600)
    assert v2["decision"] == "keep_polling"


def test_esf_resolve_parent_is_pure_by_default(store):
    """Blending by default destroys the measurement the decision rests on."""
    from amoskys.storage._ts_esf_forensics import ESFForensicsMixin

    class S2(ESFForensicsMixin):
        _read_pool = store._read_pool
        db = store.db

    now = time.time_ns()
    _poll(store, now, "/bin/parent", pid=42, create_time=now / 1e9)
    s2 = S2()
    assert s2.esf_resolve_parent(ppid=42, before_ns=now + 10**9) is None, (
        "polling must not answer unless explicitly allowed")
    hybrid = s2.esf_resolve_parent(ppid=42, before_ns=now + 10**9, allow_polling=True)
    assert hybrid is not None
    assert hybrid["source"] == "polling" and hybrid["witnessed"] is False
