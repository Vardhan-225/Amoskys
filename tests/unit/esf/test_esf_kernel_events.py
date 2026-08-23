"""Kernel TRANSITION events, and authoritative loss accounting.

These carry a "type" field exactly like control records do, so without explicit
handling every one of them would be swallowed by is_control() and discarded — a
whole sensing capability wired at the kernel and thrown away at the parser,
with the collector reporting healthy throughout. That failure has a shape this
codebase keeps producing, so it is asserted rather than assumed.
"""

import json
import os
import sqlite3
import tempfile
import time
from contextlib import contextmanager

import pytest

from amoskys.agents.os.macos.esf.collector import ESFStreamCollector

MIGS = [
    "src/amoskys/storage/migrations/sql/015_esf_exec_forensics.sql",
    "src/amoskys/storage/migrations/sql/016_esf_kernel_events.sql",
]


@pytest.fixture
def store(tmp_path):
    conn = sqlite3.connect(str(tmp_path / "t.db"))
    for m in MIGS:
        with open(m) as fh:
            conn.executescript(fh.read())
    conn.commit()

    class S:
        db = conn

        def _execute(self, sql, args=()):
            return conn.execute(sql, args)

        def _executemany(self, sql, rows):
            return conn.executemany(sql, rows)

        def _commit(self):
            conn.commit()

        class _P:
            @contextmanager
            def connection(self):
                yield conn

        _read_pool = _P()

    return S()


@pytest.fixture
def collector(store):
    return ESFStreamCollector(store, device_id="d")


def _ev(kind, t=None, **kw):
    rec = {"v": 1, "t": t or time.time_ns(), "type": kind, "pid": 500,
           "uid": 501, "exe": "/usr/bin/x", "cdhash": "H", "platform": False}
    rec.update(kw)
    return json.dumps(rec)


# ── transitions must not be swallowed as control traffic ─────────────────
@pytest.mark.parametrize("kind", [
    "setuid", "setgid", "kextload", "cs_invalidated", "mount", "unmount",
])
def test_each_transition_kind_is_stored(collector, store, kind):
    collector.ingest([_ev(kind)])
    n = store.db.execute(
        "SELECT COUNT(*) FROM esf_kernel_events WHERE kind = ?", (kind,)
    ).fetchone()[0]
    assert n == 1, f"{kind} was not stored — likely swallowed as a control record"
    assert collector.control_records == 0


def test_control_records_are_still_control(collector, store):
    """sentinel_start and heartbeat must NOT become kernel events."""
    now = time.time_ns()
    collector.ingest([
        json.dumps({"v": 1, "t": now, "type": "sentinel_start",
                    "enforce": False, "buffer": 4096, "subscriptions": 7}),
        json.dumps({"v": 1, "t": now, "type": "heartbeat",
                    "dropped": 0, "kernel_dropped": 0, "enforce": False}),
    ])
    assert store.db.execute(
        "SELECT COUNT(*) FROM esf_kernel_events").fetchone()[0] == 0
    assert collector.control_records == 1 and collector.heartbeats == 1


def test_kind_specific_payload_is_preserved(collector, store):
    """Detail is JSON because these events share almost no fields."""
    collector.ingest([_ev("mount", on="/Volumes/EVIL", **{"from": "/dev/disk4s1"})])
    row = store.db.execute(
        "SELECT detail FROM esf_kernel_events WHERE kind='mount'").fetchone()
    d = json.loads(row[0])
    assert d["on"] == "/Volumes/EVIL" and d["from"] == "/dev/disk4s1"


def test_setuid_records_the_new_uid(collector, store):
    collector.ingest([_ev("setuid", new_uid=0)])
    d = json.loads(store.db.execute(
        "SELECT detail FROM esf_kernel_events WHERE kind='setuid'").fetchone()[0])
    assert d["new_uid"] == 0


# ── kernel-side loss is separate from our own ────────────────────────────
def test_kernel_drop_is_recorded_separately_from_our_own(collector, store):
    """Two counters, deliberately not summed.

    `dropped` is what OUR buffer discarded; `kernel_dropped` is what the KERNEL
    discarded before the Sentinel ever saw it. Merging them would hide which
    half is failing, and the remedies are opposite: a bigger userspace buffer
    versus a lighter subscription.
    """
    now = time.time_ns()
    collector.ingest([
        json.dumps({"v": 1, "t": now, "type": "kernel_drop",
                    "event_type": 9, "dropped": 12, "seq": 400}),
        json.dumps({"v": 1, "t": now, "type": "heartbeat",
                    "dropped": 3, "kernel_dropped": 12, "enforce": False}),
    ])
    kd = store.db.execute(
        "SELECT dropped, event_type, seq_num FROM esf_kernel_drops").fetchone()
    assert kd == (12, 9, 400)
    assert collector.kernel_dropped == 12
    assert collector.dropped_reported == 3, "our-buffer drops must stay distinct"


def test_kernel_drop_is_not_stored_as_an_event(collector, store):
    collector.ingest([json.dumps({"v": 1, "t": time.time_ns(),
                                  "type": "kernel_drop", "event_type": 9,
                                  "dropped": 1, "seq": 2})])
    assert store.db.execute(
        "SELECT COUNT(*) FROM esf_kernel_events").fetchone()[0] == 0


def test_unmapped_notify_types_are_kept_not_discarded(collector, store):
    """A new event type added to the Sentinel before the collector knows it.

    Storing it as `notify_<n>` keeps the evidence and makes the gap visible,
    which is strictly better than dropping data because the parser is behind
    the sensor.
    """
    collector.ingest([_ev("notify_47", unmapped=True)])
    row = store.db.execute(
        "SELECT kind FROM esf_kernel_events").fetchone()
    assert row[0] == "notify_47"


def test_exec_events_still_route_to_their_own_table(collector, store):
    """Transitions must not cannibalise the exec stream."""
    now = time.time_ns()
    collector.ingest([json.dumps({
        "v": 1, "t": now, "pid": 1, "ppid": 0, "uid": 0, "exe": "/bin/ls",
        "argv": ["ls"], "cdhash": "A", "cs_flags": 0, "signed": True,
        "valid": True, "adhoc": False, "platform": True, "signing_id": "",
        "team_id": "", "decision": "allow", "reason": "platform"})])
    assert store.db.execute("SELECT COUNT(*) FROM esf_exec_events").fetchone()[0] == 1
    assert store.db.execute("SELECT COUNT(*) FROM esf_kernel_events").fetchone()[0] == 0
