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

from tests.unit.esf._migrations import ESF_MIGRATIONS as MIGS


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


# ── baseline maturity ────────────────────────────────────────────────────
def _mixin_store(store):
    from amoskys.storage._ts_esf_forensics import ESFForensicsMixin

    class S(ESFForensicsMixin):
        _read_pool = store._read_pool
        db = store.db

        def _execute(self, sql, args=()):
            return store.db.execute(sql, args)

        def _commit(self):
            store.db.commit()

    return S()


def test_young_baseline_declares_itself_untrustworthy(store):
    """Novelty is worth nothing on a young ledger.

    At 14.8 hours the real ESF corpus was marking 30% of executions novel,
    against 0.5% for a polling corpus that had seen 30,000. A detector that
    reports "3 novel binaries" without saying which regime it is in invites
    action on noise.
    """
    s = _mixin_store(store)
    now = time.time_ns()
    for i in range(50):
        store.db.execute(
            "INSERT INTO esf_exec_events (timestamp_ns, device_id, exe, cdhash) "
            "VALUES (?,?,?,?)",
            (now - (50 - i) * 10**9 * 60, "d", f"/bin/x{i}", f"H{i}"))
    store.db.commit()
    m = s.esf_baseline_maturity()
    assert m["mature"] is False
    assert m["maturity"] < 0.05
    assert "young" in m["note"] and "Do not act on novelty alone" in m["note"]


def test_mature_baseline_says_so(store):
    s = _mixin_store(store)
    now = time.time_ns()
    rows = [(now - (5100 - i) * 10**9, "d", f"/bin/x{i%400}", f"H{i%400}")
            for i in range(5100)]
    store.db.executemany(
        "INSERT INTO esf_exec_events (timestamp_ns, device_id, exe, cdhash) "
        "VALUES (?,?,?,?)", rows)
    store.db.commit()
    m = s.esf_baseline_maturity()
    assert m["mature"] is True and m["maturity"] == 1.0
    assert "reflects the machine" in m["note"]


# ── transitions are not novelty-gated ────────────────────────────────────
def test_the_first_ever_signature_invalidation_scores_high(store, collector):
    """p = 1/1 would give 0 bits, which is exactly backwards.

    The rarest event in the system must not score zero because it is also the
    only one observed. The prior floor holds until there is enough history for
    a measured rate to be trustworthy.
    """
    s = _mixin_store(store)
    collector.ingest([_ev("cs_invalidated")])
    r = s.esf_transition_alerts(hours=24)
    assert r["count"] == 1
    a = r["alerts"][0]
    assert a["bits"] >= 20.0, "a lone cs_invalidated must not score 0 bits"
    assert a["rate_basis"] == "prior_floor"


def test_transitions_rank_by_severity_not_recency(store, collector):
    s = _mixin_store(store)
    now = time.time_ns()
    collector.ingest([
        _ev("cs_invalidated", t=now - 10**10),
        _ev("unmount", t=now),
    ])
    r = s.esf_transition_alerts(hours=24)
    assert r["alerts"][0]["kind"] == "cs_invalidated", (
        "the older but far rarer event must rank first")


def test_quiet_transitions_do_not_self_certify(store):
    """Zero could mean nothing happened, or that the Sentinel is running a
    build with no such subscription. The result must not imply the first."""
    s = _mixin_store(store)
    r = s.esf_transition_alerts(hours=24)
    assert r["count"] == 0
    assert "subscriptions" in r["note"]


def test_alert_surface_keeps_the_two_halves_apart(store, collector):
    """Merging them would let a 6-bit novelty finding on a 13%-built baseline
    sit beside a 20-bit signature invalidation as an equal claim."""
    s = _mixin_store(store)
    collector.ingest([_ev("cs_invalidated")])
    surface = s.esf_alert_surface(hours=24)
    assert "novelty_gated" in surface and "transitions" in surface
    assert surface["novelty_gated"]["trustworthy"] is False
    assert surface["novelty_gated"]["caveat"] is not None
    assert surface["transitions"]["count"] == 1


# ── privilege anomalies ──────────────────────────────────────────────────
def _priv(store, exe, platform=True, new_uid=501, t=None):
    store.db.execute(
        "INSERT INTO esf_kernel_events "
        "(timestamp_ns, device_id, kind, pid, euid, exe, cdhash, is_platform, detail) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (t or time.time_ns(), "d", "setuid", 1, 501, exe, "H", platform,
         json.dumps({"new_uid": new_uid})))
    store.db.commit()


def test_clean_baseline_produces_no_anomalies(store):
    s = _mixin_store(store)
    for _ in range(20):
        _priv(store, "/usr/libexec/xpcproxy")
    r = s.esf_privilege_anomalies(hours=24)
    assert r["count"] == 0
    assert r["known_actors"] == ["xpcproxy"]
    assert r["root_transitions_ever"] is False


def test_non_platform_privilege_change_is_flagged(store):
    s = _mixin_store(store)
    for _ in range(20):
        _priv(store, "/usr/libexec/xpcproxy")
    _priv(store, "/tmp/dropper", platform=False)
    r = s.esf_privilege_anomalies(hours=24)
    assert r["count"] == 1
    assert "non-platform binary changing privilege" in r["anomalies"][0]["reasons"]


def test_first_ever_root_transition_is_flagged(store):
    s = _mixin_store(store)
    for _ in range(20):
        _priv(store, "/usr/libexec/xpcproxy", new_uid=501)
    _priv(store, "/usr/libexec/xpcproxy", new_uid=0)
    r = s.esf_privilege_anomalies(hours=24)
    assert r["count"] == 1
    assert any("uid 0" in x for x in r["anomalies"][0]["reasons"])


def test_evidentiary_strength_grows_with_the_baseline(store):
    """The core property: the same anomaly is worth MORE after more clean history.

    A thing unseen in 22 observations is worth 4.5 bits. Unseen after 10,000,
    it is worth 13.3 — nearly three times the evidence from one identical
    event. A detector that scored it as a constant would throw that away.
    """
    s = _mixin_store(store)
    for _ in range(20):
        _priv(store, "/usr/libexec/xpcproxy")
    small = s.esf_privilege_anomalies(hours=24)["bits_if_unseen"]
    for _ in range(2000):
        _priv(store, "/usr/libexec/xpcproxy")
    large = s.esf_privilege_anomalies(hours=24)["bits_if_unseen"]
    assert large > small + 5, (
        f"a larger clean baseline must make an unseen event more surprising "
        f"({small} -> {large})")


def test_bits_are_bounded_not_infinite(store):
    """Laplace, so an unseen event cannot outrank every real measurement forever."""
    s = _mixin_store(store)
    _priv(store, "/usr/libexec/xpcproxy")
    b = s.esf_privilege_anomalies(hours=24)["bits_if_unseen"]
    assert 0 < b < 64 and b == b  # finite, not inf/nan


def test_empty_baseline_refuses_to_read_as_quiet(store):
    s = _mixin_store(store)
    r = s.esf_privilege_anomalies(hours=24)
    assert r["count"] == 0
    assert "subscriptions" in r["note"]


# ── cross-sensor reconciliation ──────────────────────────────────────────
def _poll_row(store, pid, exe, ts, create_time):
    store.db.execute(
        "CREATE TABLE IF NOT EXISTS process_events ("
        "timestamp_ns INTEGER, pid INTEGER, exe TEXT, collection_agent TEXT, create_time REAL)")
    store.db.execute(
        "INSERT INTO process_events (timestamp_ns, pid, exe, collection_agent, create_time) "
        "VALUES (?,?,?,?,?)", (ts, pid, exe, "macos_process", create_time))
    store.db.commit()


def _esf_row(store, pid, exe, ts):
    store.db.execute(
        "INSERT INTO esf_exec_events (timestamp_ns, device_id, exe, cdhash, pid, ppid) "
        "VALUES (?,?,?,?,?,?)", (ts, "d", exe, "H", pid, 1))
    store.db.commit()


def test_reconciliation_refuses_when_the_clocks_disagree(store):
    """The precondition, and why it is not a detail.

    With the ESF stream running 17.5 hours behind wall-clock after a sleep,
    this reported 10,490 'unwitnessed starts' on the live machine — including
    /bin/sleep and /usr/bin/log, which are AMOSKYS's own probes and
    unquestionably exec. It was measuring clock skew and calling it evidence.
    """
    s = _mixin_store(store)
    now = time.time_ns()
    _esf_row(store, 1, "/bin/ls", now - 18 * 3600 * 10**9)   # stale clock
    _poll_row(store, 2, "/bin/ps", now, now / 1e9)           # current clock
    r = s.esf_reconcile(hours=24)
    assert r["available"] is False
    assert r["clock_skew_seconds"] > 300
    assert "REFUSING TO RECONCILE" in r["note"]


def test_reconciliation_separates_predating_from_unwitnessed(store):
    """The whole value of keeping both sensors.

    A process polling sees running but ESF never saw start is either older than
    the stream (expected, decays with uptime) or started without a witnessed
    exec (extraordinary). Telling those apart needs both tiers, which is why
    neither can be retired.
    """
    s = _mixin_store(store)
    now = time.time_ns()
    for i in range(3):
        _esf_row(store, 100 + i, f"/bin/w{i}", now - (60 - i) * 10**9)
    _poll_row(store, 100, "/bin/w0", now, (now - 60 * 10**9) / 1e9)   # witnessed
    _poll_row(store, 900, "/bin/old", now, (now - 86400 * 10**9) / 1e9)  # predates
    _poll_row(store, 901, "/bin/ghost", now, (now - 30 * 10**9) / 1e9)   # unwitnessed
    r = s.esf_reconcile(hours=24)
    assert r["available"] is True, r.get("note")
    assert r["predates_sentinel"] == 1
    assert r["unwitnessed_count"] == 1
    assert r["unwitnessed_starts"][0]["exe"] == "/bin/ghost"


def test_no_esf_stream_is_not_agreement(store):
    """One sensor is not consensus."""
    s = _mixin_store(store)
    r = s.esf_reconcile(hours=24)
    assert r["available"] is False
    assert "one sensor" in r["note"]


# ── pid reuse ────────────────────────────────────────────────────────────
def test_pid_reuse_does_not_clear_an_unwitnessed_process(store):
    """A bare pid is not an identity — macOS recycles them.

    Pid-only matching is wrong in BOTH directions: a witnessed exec clears an
    unrelated earlier process holding the same number, and an unwitnessed one
    is excused by a later namesake. Seen live: pid 20299 carried a create_time
    23 hours older than the session it was judged against.
    """
    from amoskys.storage._ts_hybrid_coverage import HybridCoverageMixin

    class S(HybridCoverageMixin):
        _read_pool = store._read_pool
        db = store.db

    now = time.time_ns()
    store.db.execute(
        "CREATE TABLE IF NOT EXISTS process_events ("
        "timestamp_ns INTEGER, pid INTEGER, exe TEXT, collection_agent TEXT, create_time REAL)")
    store.db.execute(
        "INSERT INTO esf_stream_health (timestamp_ns, device_id, dropped, note) "
        "VALUES (?,?,0,'session_start subscriptions=8')", (now - 3600 * 10**9, "d"))
    # Witnessed exec for pid 500, now.
    store.db.execute(
        "INSERT INTO esf_exec_events (timestamp_ns, device_id, exe, cdhash, pid, ppid) "
        "VALUES (?,?,?,?,?,?)", (now, "d", "/bin/new", "H", 500, 1))
    # A DIFFERENT process that held pid 500 earlier and was never witnessed.
    store.db.execute(
        "INSERT INTO process_events VALUES (?,?,?,?,?)",
        (now, 500, "/tmp/ghost", "macos_process", (now - 1800 * 10**9) / 1e9))
    # And the legitimate current occupant.
    store.db.execute(
        "INSERT INTO process_events VALUES (?,?,?,?,?)",
        (now, 500, "/bin/new", "macos_process", now / 1e9))
    store.db.commit()

    r = S().esf_unwitnessed_origins(hours=24)
    assert r["available"] is True, r.get("note")
    exes = {v["exe"] for v in r["violations"]}
    assert "/tmp/ghost" in exes, (
        "the earlier occupant of a recycled pid was wrongly cleared by a later "
        "witnessed exec")
    assert "/bin/new" not in exes, "the genuinely witnessed process must not be flagged"


# ── quarantine provenance ────────────────────────────────────────────────
def _exec_q(t, exe, cdhash, quarantine=None, adhoc=True):
    rec = {
        "v": 1, "t": t, "pid": 1, "ppid": 0, "uid": 501, "exe": exe,
        "argv": [exe], "cdhash": cdhash, "cs_flags": 2, "signed": True,
        "valid": True, "adhoc": adhoc, "platform": False, "signing_id": "",
        "team_id": "", "decision": "would_deny", "reason": "adhoc from /Users/",
    }
    if quarantine:
        rec["quarantine"] = quarantine
    return json.dumps(rec)


def test_downloaded_binary_records_its_source_agent(store, collector):
    """The distinction a signature can never make.

    Both binaries below are ad-hoc signed and would_deny. One was compiled
    locally; one arrived via Safari. Only the xattr separates them, and it
    names the source — which is what turns "confirm it's yours" into
    "downloaded via Safari and it ran".
    """
    now = time.time_ns()
    collector.ingest([
        _exec_q(now, "/Users/a/Downloads/payload", "EVIL",
                quarantine="0083;6a7e118c;Safari;ABCD-1234"),
        _exec_q(now + 10**8, "/Users/a/build/mytool", "MINE"),
    ])
    rows = dict(store.db.execute(
        "SELECT cdhash, quarantine FROM esf_exec_events").fetchall())
    assert rows["EVIL"] == "0083;6a7e118c;Safari;ABCD-1234"
    assert rows["MINE"] is None, "a local build must have no quarantine"


def test_source_agent_is_recoverable_from_the_raw_string(store, collector):
    """Stored raw, not parsed to a boolean — field 3 is the agent."""
    now = time.time_ns()
    for agent in ("Safari", "WhatsApp", "sharingd"):
        collector.ingest([_exec_q(now, f"/tmp/{agent}bin", agent,
                                  quarantine=f"0083;6a7e118c;{agent};UUID")])
    for cdhash, q in store.db.execute(
            "SELECT cdhash, quarantine FROM esf_exec_events "
            "WHERE quarantine IS NOT NULL"):
        assert q.split(";")[2] == cdhash


def test_absent_quarantine_is_null_not_empty_string(store, collector):
    """NULL is a definite answer — ENOATTR means locally built. An empty
    string would be indistinguishable from a downloaded file whose attribute
    failed to read."""
    collector.ingest([_exec_q(time.time_ns(), "/Users/a/local", "L")])
    v = store.db.execute(
        "SELECT quarantine FROM esf_exec_events WHERE cdhash='L'").fetchone()[0]
    assert v is None


def test_the_banding_distinction_this_enables(store, collector):
    """The 2D truth: signature AND provenance.

    An adversarial review found 2 of 3 would_deny events were the operator's
    own rustc/rustup. Signature alone bands both the compiler and the dropper
    red; adding provenance separates them.
    """
    now = time.time_ns()
    collector.ingest([
        _exec_q(now, "/Users/a/.cargo/bin/rustc", "RUSTC"),
        _exec_q(now + 10**8, "/Users/a/Downloads/x", "DROP",
                quarantine="0083;6a7e118c;Safari;U"),
    ])
    q = dict(store.db.execute(
        "SELECT cdhash, quarantine FROM esf_exec_events").fetchall())
    # Same signature class, opposite provenance — which is the whole point.
    assert q["RUSTC"] is None and q["DROP"] is not None
