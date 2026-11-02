"""The fleet seam: what the device ships must be what the server accepts.

Prod answers every ESF shipping cycle with

    400 {"error": "Unknown table: esf_exec_events"}

and the message points away from the cause. The server code DOES support these
tables — it builds the whitelist and the DDL from one shared column map in
amoskys.storage._ts_esf_forensics. But that import sits behind

    except Exception:
        _ESF_FLEET_COLUMNS, _ESF_FLEET_DDL = {}, ""

so when the module cannot be loaded the tables silently disappear from ingest
and the operator is told the TABLE is unknown rather than that the SERVER
failed to load it. Those have different fixes.

These tests pin the seam from the device side, where it can be checked without
a server.
"""
import sqlite3

import pytest

ESF_TABLES = ("esf_exec_events", "esf_stream_health", "esf_binary_ledger")


def test_the_shared_definitions_import():
    """The single point of failure behind prod's 'Unknown table'.

    If this fails, every ESF table drops out of the server whitelist and the
    DDL is never applied — which is exactly prod's current state.
    """
    from amoskys.storage._ts_esf_forensics import ESF_FLEET_COLUMNS, ESF_FLEET_DDL

    assert set(ESF_FLEET_COLUMNS) == set(ESF_TABLES)
    assert ESF_FLEET_DDL.strip(), "empty DDL means the tables are never created"


@pytest.fixture()
def fleet_db():
    from amoskys.storage._ts_esf_forensics import ESF_FLEET_DDL

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(ESF_FLEET_DDL)
    yield conn
    conn.close()


@pytest.mark.parametrize("table", ESF_TABLES)
def test_ddl_creates_every_shipped_table(fleet_db, table):
    assert fleet_db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone(), f"{table} is shipped but the fleet DDL does not create it"


@pytest.mark.parametrize("table", ESF_TABLES)
def test_every_shipped_column_exists_server_side(fleet_db, table):
    """A column the shipper sends and the server lacks is dropped SILENTLY.

    The ingest filters to allowed columns rather than rejecting unknown ones,
    so drift here does not raise — rows arrive, inserts succeed, and the field
    is quietly empty forever. That is the same shape as the quarantine column
    reading NULL for 890,555 rows while every component was correct on disk.
    """
    from amoskys.storage._ts_esf_forensics import ESF_FLEET_COLUMNS

    physical = {r[1] for r in fleet_db.execute(f"PRAGMA table_info({table})")}
    # id is mapped to source_id by the ingest before insert.
    sent = set(ESF_FLEET_COLUMNS[table]) - {"id"}
    missing = sent - physical
    assert not missing, f"{table}: shipped but absent server-side: {missing}"


def test_shipper_and_fleet_agree(fleet_db):
    """The shipper's table list and the fleet map must not drift apart."""
    from amoskys.shipper import SHIP_TABLES
    from amoskys.storage._ts_esf_forensics import ESF_FLEET_COLUMNS

    for table in ESF_TABLES:
        assert table in SHIP_TABLES, f"{table} defined for the fleet but never shipped"
        assert set(SHIP_TABLES[table]["columns"]) == set(ESF_FLEET_COLUMNS[table]), (
            f"{table}: shipper and fleet column maps disagree"
        )


def test_quarantine_survives_the_trip(fleet_db):
    """Provenance is the field the downloaded-vs-locally-built call rests on."""
    fleet_db.execute(
        "INSERT INTO esf_exec_events (source_id, device_id, timestamp_ns, exe, "
        "decision, quarantine, received_at) VALUES (?,?,?,?,?,?,?)",
        (1, "mac-1", 1, "/tmp/dropper", "would_deny",
         "0083;6a7e118c;Safari;A1540A0B", 1.0),
    )
    got = fleet_db.execute("SELECT quarantine FROM esf_exec_events").fetchone()[0]
    assert got.split(";")[2] == "Safari", "the source agent is the actionable part"


def test_ledger_upsert_matches_the_declared_conflict_target(fleet_db):
    """_UPSERT_TABLES says cdhash; SQLite requires that to be a unique index.

    A conflict target that does not match one raises on EVERY row, so the
    snapshot would fail entirely after the first cycle.
    """
    sql = ("INSERT INTO esf_binary_ledger (cdhash, device_id, first_seen_ns, "
           "last_seen_ns, exec_count, source_id, received_at) VALUES (?,?,?,?,?,?,?) "
           "ON CONFLICT(cdhash) DO UPDATE SET exec_count=excluded.exec_count")
    fleet_db.execute(sql, ("aa", "mac-1", 1, 2, 5, 1, 1.0))
    fleet_db.execute(sql, ("aa", "mac-1", 1, 3, 9, 1, 1.0))
    rows = fleet_db.execute("SELECT exec_count FROM esf_binary_ledger").fetchall()
    assert len(rows) == 1, "re-shipping the snapshot must not duplicate"
    assert rows[0][0] == 9, "the ledger must move forward, not freeze on day one"
