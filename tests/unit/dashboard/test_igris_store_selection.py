"""IGRIS must not answer from a database that merely exists.

On 2026-09-13 IGRIS reported:

    "All 17 agents are stopped."
    "Zero events, zero incidents, zero signals."
    "No MITRE techniques observed because there are no probes firing."
    "Anything could be happening and I wouldn't see it."

...and recommended restarting the fleet. At that moment the real store was
taking ~24,000 events an hour from 23 running agents.

The cause was one predicate. Fleet mode selected the cache on
`_CACHE_DB_PATH.exists()`, and data/fleet_cache.db was a ZERO-BYTE file. It
exists. It opens. It has no tables. Every count taken from it is a truthful
zero about nothing — and "nothing" is indistinguishable from a clean machine.
"""
import sqlite3

from app.dashboard.routes_igris import _cache_is_usable


def test_a_zero_byte_file_is_not_a_usable_cache(tmp_path):
    """The exact regression. exists() said yes; it holds nothing."""
    p = tmp_path / "fleet_cache.db"
    p.touch()
    assert p.exists(), "precondition: the file exists"
    assert p.stat().st_size == 0
    assert _cache_is_usable(p) is False


def test_a_database_without_security_events_is_not_usable(tmp_path):
    """Non-empty is not the same as populated with what we query."""
    p = tmp_path / "c.db"
    db = sqlite3.connect(p)
    db.execute("CREATE TABLE something_else (x INT)")
    db.commit(); db.close()
    assert _cache_is_usable(p) is False


def test_a_real_cache_is_usable(tmp_path):
    """It must not reject a working cache — that would be the opposite fault."""
    p = tmp_path / "c.db"
    db = sqlite3.connect(p)
    db.execute("CREATE TABLE security_events (timestamp_ns INT)")
    db.commit(); db.close()
    assert _cache_is_usable(p) is True


def test_a_missing_file_is_not_usable(tmp_path):
    assert _cache_is_usable(tmp_path / "nope.db") is False


def test_a_corrupt_file_is_not_usable(tmp_path):
    """Must return False, not raise — the caller has a fallback to reach."""
    p = tmp_path / "c.db"
    p.write_bytes(b"this is not a database")
    assert _cache_is_usable(p) is False


class TestSourceIsPartOfTheAnswer:
    """A count without its source is not a measurement.

    "Zero events" was indistinguishable from a clean machine when it actually
    meant "this file is empty". describe_source() makes the store, its device
    count, and its freshness part of every answer, and attaches an explicit
    caveat when a zero describes the file rather than the machine.
    """

    def test_an_empty_store_says_so_rather_than_reporting_zeros(self, tmp_path):
        from app.dashboard.routes_igris import describe_source

        p = tmp_path / "empty.db"
        p.touch()
        d = describe_source(str(p))
        assert d["usable"] is False
        assert d["events_24h"] is None, "None, not 0 — 0 asserts a measurement"
        assert "describes the file, not the machine" in d["caveat"]

    def test_a_readable_but_stale_store_is_flagged(self, tmp_path):
        """Readable-but-silent looks exactly like a quiet machine."""
        import sqlite3

        from app.dashboard.routes_igris import describe_source

        p = tmp_path / "stale.db"
        db = sqlite3.connect(p)
        db.execute("CREATE TABLE security_events (device_id TEXT, timestamp_ns INT)")
        db.execute("INSERT INTO security_events VALUES ('mac-1', 1)")  # 1970
        db.commit(); db.close()
        d = describe_source(str(p))
        assert d["usable"] is True
        assert d["events_24h"] == 0
        assert "do not read it as a quiet machine" in d["caveat"]

    def test_a_live_store_reports_its_scope_without_a_caveat(self, tmp_path):
        import sqlite3
        import time

        from app.dashboard.routes_igris import describe_source

        p = tmp_path / "live.db"
        db = sqlite3.connect(p)
        db.execute("CREATE TABLE security_events (device_id TEXT, timestamp_ns INT)")
        now = time.time_ns()
        db.executemany("INSERT INTO security_events VALUES (?,?)",
                       [("mac-1", now), ("mac-2", now)])
        db.commit(); db.close()
        d = describe_source(str(p))
        assert d["usable"] is True
        assert d["devices"] == 2
        assert d["events_24h"] == 2
        assert d["caveat"] is None
