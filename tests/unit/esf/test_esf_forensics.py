"""ESF forensic ingest and reconstruction.

The property under test throughout is not "does it store rows" but "can an
analyst trust what it says". Specifically: a gap in the stream must be
reported AS a gap, and a claim must carry the evidence it rests on.
"""

import json
import os
import sqlite3
import tempfile
import time
from contextlib import contextmanager

import pytest

from amoskys.agents.os.macos.esf.collector import ESFStreamCollector
from amoskys.storage._ts_esf_forensics import ESFForensicsMixin

MIGRATION = "src/amoskys/storage/migrations/sql/015_esf_exec_forensics.sql"


def _exec(t, pid, ppid, exe, cdhash, *, signed=True, valid=True, adhoc=False,
          platform=False, uid=501, decision="allow", reason="allow", argv=None):
    return json.dumps({
        "v": 1, "t": t, "pid": pid, "ppid": ppid, "uid": uid, "exe": exe,
        "argv": argv or [os.path.basename(exe)], "cdhash": cdhash,
        "cs_flags": 0, "signed": signed, "valid": valid, "adhoc": adhoc,
        "platform": platform, "signing_id": "", "team_id": "",
        "decision": decision, "reason": reason,
    })


@pytest.fixture
def store():
    path = os.path.join(tempfile.mkdtemp(), "esf.db")
    conn = sqlite3.connect(path)
    with open(MIGRATION) as fh:
        conn.executescript(fh.read())
    conn.commit()

    class _Store(ESFForensicsMixin):
        # Mirrors TelemetryStore's ACTUAL interface: _execute / _executemany /
        # _commit. The first version of this fixture invented execute() and
        # executemany(), which TelemetryStore does not have — so every test
        # here passed while the collector was broken in production, and the
        # failure only appeared on the first live run. A mock is a claim about
        # an interface; see test_esf_real_store_integration.py, which checks
        # the claim.
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

    return _Store()


@pytest.fixture
def collector(store):
    return ESFStreamCollector(store, device_id="test-device")


# ── stream integrity ─────────────────────────────────────────────────────
def test_status_banner_is_not_malformed(collector):
    """The Sentinel's human banner is stderr text, not a broken event."""
    collector.ingest(["amoskys-sentinel: guarding exec (mode=MONITOR, fail-open).",
                      "WOULD-DENY exec /tmp/x — adhoc-signed binary from /tmp/"])
    assert collector.malformed == 0, "plain text must not be counted as corruption"
    assert collector.parsed == 0


def test_malformed_json_is_counted_not_swallowed(collector):
    """A parser that silently skips bad input reports health on a broken stream."""
    collector.ingest(['{"broken', '{"also": broken}'])
    assert collector.malformed == 2
    assert collector.parsed == 0


def test_drops_are_recorded_so_a_gap_is_visible(collector, store):
    """The single most important property here.

    The Sentinel drops events rather than stalling the kernel. If a drop were
    not recorded, a hole in the timeline would be indistinguishable from a
    quiet period — and an analyst would read absence of evidence as evidence
    of absence.
    """
    now = time.time_ns()
    collector.ingest([
        _exec(now, 100, 1, "/bin/ls", "aaa"),
        json.dumps({"v": 1, "t": now + 10**9, "type": "heartbeat",
                    "dropped": 42, "enforce": False}),
    ])
    tl = store.esf_timeline(start_ns=now - 10**9, end_ns=now + 10**10)
    assert tl["complete"] is False
    assert tl["dropped_in_window"] == 42
    assert "INCOMPLETE" in tl["completeness_note"]
    assert "not evidence that it did not happen" in tl["completeness_note"]


def test_clean_window_is_reported_complete(collector, store):
    now = time.time_ns()
    collector.ingest([_exec(now, 100, 1, "/bin/ls", "aaa")])
    tl = store.esf_timeline(start_ns=now - 10**9, end_ns=now + 10**9)
    assert tl["complete"] is True and tl["dropped_in_window"] == 0


# ── reconstruction ───────────────────────────────────────────────────────
def test_reconstruct_walks_a_real_attack_chain(collector, store):
    """browser -> shell -> dropped script -> root implant."""
    now = time.time_ns()
    collector.ingest([
        _exec(now, 900, 1, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "aaa"),
        _exec(now + 10**9, 901, 900, "/bin/zsh", "bbb", platform=True),
        _exec(now + 2 * 10**9, 902, 901, "/private/tmp/x.sh", "ccc",
              signed=False, valid=False, adhoc=True, decision="would_deny"),
        _exec(now + 3 * 10**9, 903, 902, "/Users/a/.hidden/impl", "ccc",
              signed=False, valid=False, adhoc=True, uid=0, decision="would_deny"),
    ])
    rc = store.esf_reconstruct(pid=903, at_ns=now + 4 * 10**9)
    assert rc["process"]["exe"].endswith("impl")
    assert rc["process"]["euid"] == 0
    assert rc["process"]["trust"] == "unsigned"
    chain = [a.get("exe") for a in rc["ancestry"] if a.get("exe")]
    assert "/private/tmp/x.sh" in chain
    assert "/bin/zsh" in chain
    assert any("Chrome" in c for c in chain)


def test_missing_ancestor_is_stated_not_guessed(collector, store):
    """An unreachable parent must be reported, never quietly omitted."""
    now = time.time_ns()
    collector.ingest([_exec(now, 500, 499, "/bin/ls", "aaa")])
    rc = store.esf_reconstruct(pid=500, at_ns=now + 10**9)
    assert rc["ancestry_complete"] is False
    assert "no exec record" in rc["ancestry"][-1]["note"]


# ── identity ─────────────────────────────────────────────────────────────
def test_cdhash_tracks_a_binary_across_paths(collector, store):
    """Path is not identity. A relocated binary keeps its cdhash."""
    now = time.time_ns()
    collector.ingest([
        _exec(now, 100, 1, "/private/tmp/dropper", "SAME", signed=False, adhoc=True),
        _exec(now + 10**9, 101, 1, "/Users/a/.cache/dropper", "SAME", signed=False, adhoc=True),
    ])
    h = store.esf_binary_history(cdhash="SAME")
    assert h["moved"] is True and h["path_count"] == 2


def test_first_seen_only_moves_backward(collector, store):
    """Replaying older history must not make a binary look newer.

    The ledger uses MIN() on first_seen_ns for exactly this reason: a backfill
    of old logs would otherwise reset novelty and turn the strongest signal in
    this module into noise.
    """
    now = time.time_ns()
    collector.ingest([_exec(now, 100, 1, "/bin/tool", "H")])
    collector.ingest([_exec(now - 86400 * 10**9, 99, 1, "/bin/tool", "H")])
    row = store.esf_binary_history(cdhash="H")["ledger"]
    assert row["first_seen_ns"] == now - 86400 * 10**9
    assert row["exec_count"] == 2


def test_unreviewed_is_distinct_from_cleared(collector, store):
    """NULL verdict means nobody looked — never 'looked and approved'."""
    now = time.time_ns()
    collector.ingest([_exec(now, 100, 1, "/tmp/new", "NEW", signed=False, adhoc=True)])
    nv = store.esf_novel_binaries(hours=1)
    assert nv["count"] == 1
    assert nv["novel"][0]["reviewed"] is False
    assert nv["novel"][0]["verdict"] is None


def test_novelty_warns_while_the_baseline_is_young(collector, store):
    now = time.time_ns()
    collector.ingest([_exec(now, 100, 1, "/bin/a", "A")])
    nv = store.esf_novel_binaries(hours=1)
    assert "only meaningful once a baseline exists" in nv["note"]


# ── retention ────────────────────────────────────────────────────────────
def test_prune_bounds_events_but_preserves_novelty(collector, store):
    """Retention must not delete the ledger.

    Unbounded telemetry from this agent filled the SSD to 99% and panicked the
    kernel six times, so events are bounded from the first commit. But pruning
    the LEDGER would make every binary look new again on a timer.
    """
    old = time.time_ns() - 30 * 86400 * 10**9
    collector.ingest([_exec(old, 100, 1, "/bin/old", "OLD")])
    collector.retention_days = 14
    collector.prune()
    hist = store.esf_binary_history(cdhash="OLD")
    assert hist["executions"] == []
    assert hist["ledger"] is not None, "novelty baseline must survive retention"


# ── timestamp integrity ──────────────────────────────────────────────────
def test_boot_relative_timestamp_is_rejected_not_stored(collector, store):
    """mach_absolute_time() counts from BOOT, not the epoch.

    The Sentinel's first working build emitted it raw: ~2.4e14 on a machine up
    three days, against ~1.8e18 for a real epoch value. Stored unchecked it is
    quietly catastrophic — and the failure mode is not a wrong chart, it is
    retention deleting the entire evidence table on its first pass.
    """
    boot_relative = 235_043_373_641_458
    collector.ingest([_exec(boot_relative, 100, 1, "/bin/ls", "aaa")])
    assert collector.bad_timestamps == 1
    tl = store.esf_timeline(start_ns=0, end_ns=time.time_ns() + 10**12)
    assert tl["returned"] == 1, "the exec itself must still be kept"
    assert tl["events"][0]["timestamp_ns"] > 1_577_836_800_000_000_000


def test_retention_never_deletes_undateable_rows(collector, store):
    """Retention must not become the thing that destroys the evidence.

    A row whose timestamp is below the epoch floor is 'older' than every
    possible cutoff. Without a lower bound on the DELETE, one bad clock wipes
    the table.
    """
    conn_store = store
    # Insert a boot-relative row directly, bypassing collector normalisation,
    # to simulate rows written before the source was fixed.
    conn_store._execute(
        "INSERT INTO esf_exec_events (timestamp_ns, device_id, exe, cdhash) "
        "VALUES (?, ?, ?, ?)",
        (235_043_373_641_458, "d", "/bin/legacy", "LEGACY"),
    )
    conn_store._commit()
    collector.retention_days = 14
    collector.prune()
    rows = conn_store.esf_binary_history(cdhash="LEGACY")["executions"]
    assert len(rows) == 1, "undateable evidence must survive retention"


def test_plausible_timestamps_still_prune(collector, store):
    old = time.time_ns() - 30 * 86400 * 10**9
    collector.ingest([_exec(old, 100, 1, "/bin/old", "OLDER")])
    collector.retention_days = 14
    collector.prune()
    assert store.esf_binary_history(cdhash="OLDER")["executions"] == []
