"""The kernel witness: "you can't hide when it's watching" has to be checkable.

Every test here defends one sentence on the box. If the stream is not running,
the UI must say so rather than let a quiet page imply a watched machine.
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

kernel = importlib.import_module("app.dashboard.kernel")

NS = 1_000_000_000


def _make_store(tmp_path, *, beats=(), execs=0, binaries=()):
    path = tmp_path / "telemetry.db"
    db = sqlite3.connect(path)
    db.executescript(
        """
        CREATE TABLE esf_exec_events (id INTEGER PRIMARY KEY, timestamp_ns INTEGER,
            device_id TEXT, exe TEXT, argv TEXT, cdhash TEXT, signing_id TEXT,
            team_id TEXT, cs_flags INTEGER, is_signed BOOLEAN, is_valid BOOLEAN,
            is_adhoc BOOLEAN, is_platform BOOLEAN, pid INTEGER, ppid INTEGER,
            euid INTEGER, username TEXT, decision TEXT, decision_reason TEXT,
            process_guid TEXT, parent_guid TEXT, ingested_at_ns INTEGER);
        CREATE TABLE esf_binary_ledger (cdhash TEXT PRIMARY KEY, first_seen_ns INTEGER,
            last_seen_ns INTEGER, exec_count INTEGER DEFAULT 1, first_exe TEXT,
            distinct_paths INTEGER DEFAULT 1, signing_id TEXT, team_id TEXT,
            is_platform BOOLEAN, is_adhoc BOOLEAN, verdict TEXT, verdict_at_ns INTEGER,
            verdict_note TEXT);
        CREATE TABLE esf_stream_health (id INTEGER PRIMARY KEY, timestamp_ns INTEGER,
            device_id TEXT, dropped INTEGER DEFAULT 0, enforce_mode BOOLEAN,
            collector_lag_ns INTEGER, note TEXT);
        """
    )
    now = time.time_ns()
    for i in range(execs):
        db.execute(
            "INSERT INTO esf_exec_events (timestamp_ns, exe, cdhash) VALUES (?,?,?)",
            (now - i * NS, "/usr/bin/thing", "cd" + str(i)),
        )
    for age_seconds, dropped, enforce in beats:
        db.execute(
            "INSERT INTO esf_stream_health (timestamp_ns, dropped, enforce_mode) VALUES (?,?,?)",
            (now - int(age_seconds * NS), dropped, enforce),
        )
    for cdhash, age_minutes, signed, adhoc, platform, verdict in binaries:
        db.execute(
            "INSERT INTO esf_binary_ledger (cdhash, first_seen_ns, last_seen_ns, "
            "first_exe, is_platform, is_adhoc, verdict) VALUES (?,?,?,?,?,?,?)",
            (
                cdhash,
                now - int(age_minutes * 60 * NS),
                now,
                f"/tmp/{cdhash}",
                platform,
                adhoc,
                verdict,
            ),
        )
        # The ledger table carries no signing columns beyond platform/adhoc, so
        # the trust label for a ledger row is derived from what it does have.
        # _signed_ rows are marked valid here to isolate the ordering question.
    db.commit()
    db.close()
    return path


@pytest.fixture()
def store(tmp_path, monkeypatch):
    def _install(**kwargs):
        path = _make_store(tmp_path, **kwargs)
        monkeypatch.setattr(kernel, "_candidate_paths", lambda: [str(path)])
        return path

    return _install


def test_no_stream_at_all_is_stated_not_implied(monkeypatch):
    monkeypatch.setattr(kernel, "_candidate_paths", lambda: ["/nonexistent.db"])
    health = kernel.stream_health()
    assert health["present"] is False
    assert health["watching"] is False
    assert "polling sensor" in health["detail"]


def test_installed_but_never_run_is_idle_not_clean(store):
    store()
    health = kernel.stream_health()
    assert health["status"] == "idle"
    assert health["watching"] is False
    assert "needs root" in health["detail"]


def test_a_live_heartbeat_with_no_drops_is_a_complete_timeline(store):
    store(beats=[(10, 0, False)], execs=5)
    health = kernel.stream_health()
    assert health["status"] == "witnessing"
    assert health["watching"] is True
    assert "complete" in health["detail"]


def test_drops_are_reported_as_holes_in_the_record(store):
    store(beats=[(10, 42, False)], execs=5)
    health = kernel.stream_health()
    assert health["status"] == "gapped"
    assert health["dropped"] == 42
    assert "does not mean nothing happened" in health["detail"]


def test_a_stale_heartbeat_means_it_stopped_watching(store):
    store(beats=[(600, 0, False)], execs=5)
    health = kernel.stream_health()
    assert health["status"] == "stopped"
    assert health["watching"] is False
    assert "not witnessed" in health["detail"]


def test_enforce_mode_is_carried_through(store):
    store(beats=[(5, 0, True)], execs=1)
    assert kernel.stream_health()["enforce_mode"] is True


# ── Novelty ──────────────────────────────────────────────────────────────────
def test_only_unreviewed_non_platform_binaries_are_offered(store):
    store(
        binaries=[
            ("aaa", 5, 1, 0, 0, None),  # novel, unreviewed  -> offered
            ("bbb", 5, 1, 0, 1, None),  # platform           -> not offered
            ("ccc", 5, 1, 0, 0, "benign"),  # already judged     -> not offered
        ]
    )
    novel = kernel.novel_binaries()
    assert [r["cdhash"] for r in novel["novel"]] == ["aaa"]


def test_a_young_ledger_says_its_count_means_nothing_yet(store):
    store(binaries=[("aaa", 5, 1, 0, 0, None)])
    novel = kernel.novel_binaries()
    assert novel["baseline_ready"] is False
    assert "almost everything still looks new" in novel["note"]


def test_least_trusted_binaries_sort_first(store, monkeypatch):
    """An unsigned first-run outranks an ad-hoc one, which outranks a signed one.

    The ledger table stores platform/adhoc but not the full signing flags, so
    the label is derived; this pins the ORDER, which is what decides what a
    person is asked about first.
    """
    store(
        binaries=[
            ("signed", 5, 1, 0, 0, None),
            ("unsigned", 5, 0, 0, 0, None),
            ("adhoc", 5, 1, 1, 0, None),
        ]
    )
    labels = {"signed": "signed", "unsigned": "unsigned", "adhoc": "adhoc"}
    monkeypatch.setattr(kernel, "_trust", lambda row: labels[row["cdhash"]])
    order = [r["cdhash"] for r in kernel.novel_binaries()["novel"]]
    assert order.index("unsigned") < order.index("adhoc") < order.index("signed")


# ── The verdict write ────────────────────────────────────────────────────────
def test_a_verdict_lands_on_the_binary_ledger(store):
    path = store(binaries=[("aaa", 5, 1, 0, 0, None)])
    result = kernel.record_binary_verdict("aaa", "benign", note="I installed it")
    assert result["written"] is True
    db = sqlite3.connect(path)
    row = db.execute(
        "SELECT verdict, verdict_note FROM esf_binary_ledger WHERE cdhash='aaa'"
    ).fetchone()
    db.close()
    assert row[0] == "benign"
    assert "installed" in row[1]
    # And it drops out of the unreviewed queue, which is the point.
    assert kernel.novel_binaries()["novel"] == []


def test_an_unknown_verdict_is_refused(store):
    store(binaries=[("aaa", 5, 1, 0, 0, None)])
    assert kernel.record_binary_verdict("aaa", "probably-fine")["written"] is False


def test_a_verdict_for_an_unknown_binary_reports_the_miss(store):
    store(binaries=[("aaa", 5, 1, 0, 0, None)])
    result = kernel.record_binary_verdict("zzz", "benign")
    assert result["written"] is False
    assert "No such binary" in result["detail"]
