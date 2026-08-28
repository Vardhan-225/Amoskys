"""The kernel witness, from the laptop to the web tier.

Nine tables shipped from the Mac and none of them carried the exec stream, so
every claim on amoskys.com was backed by the POLLING sensor while the
kernel-witnessed record — the stronger evidence, and the one the product is
named for — stayed on the laptop. The web tier said so honestly ("The kernel
witness is not reaching this view"), which is not the same as the capability
being present where anyone looks.

These tests pin the contract across all three tiers, because a change to any
one of them silently strands the other two.
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
for p in (ROOT / "web", ROOT / "src"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from amoskys.storage._ts_esf_forensics import (  # noqa: E402
    ESF_FLEET_COLUMNS,
    ESF_FLEET_DDL,
)
from app.dashboard import telemetry_bridge as tb  # noqa: E402

ESF_TABLES = ("esf_exec_events", "esf_binary_ledger", "esf_stream_health")


def _fleet_db() -> sqlite3.Connection:
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.executescript(ESF_FLEET_DDL)
    return db


# ── The shipper actually sends them ──────────────────────────────────────────
def test_the_exec_stream_is_in_the_ship_set():
    from amoskys.shipper import SHIP_TABLES

    for table in ESF_TABLES:
        assert table in SHIP_TABLES, f"{table} would never leave the machine"


def test_the_mutable_ledger_ships_as_a_snapshot_not_a_cursor_drain():
    """esf_binary_ledger is a running summary: exec_count and last_seen move,
    and an operator verdict can be written days after first sight. A cursor
    drain sends each binary once and never sends the verdict."""
    from amoskys.shipper import SHIP_TABLES

    assert SHIP_TABLES["esf_binary_ledger"].get("mode") == "snapshot"
    assert SHIP_TABLES["esf_exec_events"].get("mode") != "snapshot"
    assert SHIP_TABLES["esf_stream_health"].get("mode") != "snapshot"


def test_append_only_streams_carry_an_id_for_the_cursor():
    """_ship_table returns early unless 'id' is in the column list."""
    from amoskys.shipper import SHIP_TABLES

    for table in ("esf_exec_events", "esf_stream_health"):
        assert "id" in SHIP_TABLES[table]["columns"]


# ── The three tiers agree on the shape ───────────────────────────────────────
def test_every_shipped_column_exists_in_the_fleet_schema():
    """A column the shipper sends and the fleet cannot store is dropped in
    silence — the failure mode that kept whole fields out of the cache."""
    db = _fleet_db()
    for table, columns in ESF_FLEET_COLUMNS.items():
        actual = {r[1] for r in db.execute(f"PRAGMA table_info({table})")}
        missing = set(columns) - actual
        assert not missing, f"{table} cannot store {missing}"


def test_the_ingest_whitelist_covers_every_shipped_column():
    """A column outside ALLOWED_TABLES is dropped by the ops ingest."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "cc_probe", ROOT / "server" / "command_center.py"
    )
    assert spec and spec.loader
    # Read the whitelist without booting the Flask app.
    source = (ROOT / "server" / "command_center.py").read_text()
    assert (
        "_ESF_FLEET_COLUMNS" in source
    ), "ops must build its whitelist from the shared map"
    for table in ESF_TABLES:
        assert table in source


def test_the_ledger_has_the_source_id_the_ingest_stamps():
    """The fleet ingest writes source_id onto every row it accepts. Without the
    column the whole snapshot was rejected with "no column named source_id",
    which costs the novelty signal outright."""
    db = _fleet_db()
    cols = {r[1] for r in db.execute("PRAGMA table_info(esf_binary_ledger)")}
    assert "source_id" in cols


# ── The presentation cache accepts them ──────────────────────────────────────
def _exec_row(i: int = 1) -> dict:
    return {
        "id": i,
        "timestamp_ns": 1787950000000000000 + i,
        "device_id": "b45045f5e1a0c15e",
        "exe": "/usr/bin/curl",
        "cdhash": f"cd{i}",
        "is_signed": 1,
        "is_valid": 1,
        "is_platform": 1,
        "decision": "allow",
    }


def test_exec_events_land_in_the_cache():
    db = _fleet_db()
    assert tb._upsert_rows(db, "esf_exec_events", [_exec_row(i) for i in range(3)]) == 3


def test_the_binary_ledger_lands_in_the_cache():
    db = _fleet_db()
    row = {
        "cdhash": "abc123",
        "first_seen_ns": 1787950000000000000,
        "last_seen_ns": 1787950000000000000,
        "exec_count": 9,
        "first_exe": "/usr/bin/curl",
        "is_platform": 1,
    }
    assert tb._upsert_rows(db, "esf_binary_ledger", [row]) == 1
    assert db.execute("SELECT exec_count FROM esf_binary_ledger").fetchone()[0] == 9


def test_stream_health_lands_in_the_cache():
    db = _fleet_db()
    row = {
        "id": 1,
        "timestamp_ns": 1787950000000000000,
        "dropped": 0,
        "enforce_mode": 0,
    }
    assert tb._upsert_rows(db, "esf_stream_health", [row]) == 1


# ── And the reader lights up off them ────────────────────────────────────────
def test_the_witness_reads_the_cache_once_the_rows_arrive(tmp_path, monkeypatch):
    """The whole point: kernel.py resolves whichever store carries the stream,
    so the moment rows reach this tier the witness strip and the coverage row
    stop saying "not reaching this view" with no UI change at all."""
    from app.dashboard import kernel

    path = tmp_path / "fleet_cache.db"
    db = sqlite3.connect(path)
    db.executescript(ESF_FLEET_DDL)
    import time

    now = time.time_ns()
    db.execute(
        "INSERT INTO esf_exec_events (timestamp_ns, device_id, exe) VALUES (?,?,?)",
        (now, "dev", "/usr/bin/curl"),
    )
    db.execute(
        "INSERT INTO esf_stream_health (timestamp_ns, dropped, enforce_mode) VALUES (?,?,?)",
        (now, 0, 0),
    )
    db.commit()
    db.close()

    monkeypatch.setattr(kernel, "_candidate_paths", lambda: [str(path)])
    health = kernel.stream_health()
    assert health["present"] is True
    assert health["watching"] is True
    assert health["events_24h"] == 1
