"""
Tests for WAL processor dead letter quarantine (P0-S1)
and EventBus WAL connection reuse (P0-S3).
"""

import sqlite3

from amoskys.storage.wal_processor import WALProcessor


def _setup_wal_db(wal_path: str):
    """Create a minimal WAL database with schema."""
    conn = sqlite3.connect(wal_path)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS wal (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            idem TEXT UNIQUE,
            ts_ns INTEGER NOT NULL,
            bytes BLOB NOT NULL,
            checksum BLOB
        )"""
    )
    conn.commit()
    return conn


def _insert_valid_envelope(conn, idem: str, ts_ns: int = 1000):
    """Insert a valid protobuf envelope into WAL."""
    from amoskys.proto import universal_telemetry_pb2 as pb

    env = pb.UniversalEnvelope()
    dt = env.device_telemetry
    dt.device_id = "test-device"
    dt.collection_agent = "test-agent"
    ev = dt.events.add()
    ev.event_id = f"ev-{idem}"
    ev.event_type = "METRIC"
    ev.severity = "INFO"
    ev.event_timestamp_ns = ts_ns

    data = env.SerializeToString()
    conn.execute(
        "INSERT INTO wal (idem, ts_ns, bytes) VALUES (?, ?, ?)",
        (idem, ts_ns, sqlite3.Binary(data)),
    )
    conn.commit()
    return data


def _insert_corrupt_envelope(conn, idem: str, ts_ns: int = 2000):
    """Insert corrupt (non-protobuf) bytes into WAL."""
    bad_data = b"NOT_A_VALID_PROTOBUF_ENVELOPE"
    conn.execute(
        "INSERT INTO wal (idem, ts_ns, bytes) VALUES (?, ?, ?)",
        (idem, ts_ns, sqlite3.Binary(bad_data)),
    )
    conn.commit()
    return bad_data


class TestDeadLetterQuarantine:
    """P0-S1: Corrupt WAL entries are quarantined, not silently deleted."""

    def test_corrupt_event_quarantined_not_deleted(self, tmp_path):
        """A corrupt WAL entry ends up in wal_dead_letter table."""
        wal_path = str(tmp_path / "wal.db")
        store_path = str(tmp_path / "telemetry.db")

        conn = _setup_wal_db(wal_path)
        _insert_corrupt_envelope(conn, "bad-1")
        conn.close()

        proc = WALProcessor(wal_path=wal_path, store_path=store_path)
        proc.process_batch(batch_size=10)

        # Corrupt entry should be in dead letter
        cursor = proc.store.db.execute("SELECT COUNT(*) FROM wal_dead_letter")
        assert cursor.fetchone()[0] == 1

    def test_quarantine_preserves_original_bytes(self, tmp_path):
        """Dead letter row contains the original corrupt bytes."""
        wal_path = str(tmp_path / "wal.db")
        store_path = str(tmp_path / "telemetry.db")

        conn = _setup_wal_db(wal_path)
        bad_data = _insert_corrupt_envelope(conn, "bad-bytes")
        conn.close()

        proc = WALProcessor(wal_path=wal_path, store_path=store_path)
        proc.process_batch(batch_size=10)

        row = proc.store.db.execute(
            "SELECT envelope_bytes FROM wal_dead_letter"
        ).fetchone()
        assert bytes(row[0]) == bad_data

    def test_quarantine_count_incremented(self, tmp_path):
        """Processor quarantine_count tracks quarantined entries."""
        wal_path = str(tmp_path / "wal.db")
        store_path = str(tmp_path / "telemetry.db")

        conn = _setup_wal_db(wal_path)
        _insert_corrupt_envelope(conn, "bad-count")
        conn.close()

        proc = WALProcessor(wal_path=wal_path, store_path=store_path)
        proc.process_batch(batch_size=10)

        assert proc.quarantine_count == 1
        assert proc.error_count == 1

    def test_valid_events_around_corrupt_still_processed(self, tmp_path):
        """Valid events before and after a corrupt entry are processed normally."""
        wal_path = str(tmp_path / "wal.db")
        store_path = str(tmp_path / "telemetry.db")

        conn = _setup_wal_db(wal_path)
        _insert_valid_envelope(conn, "good-1", ts_ns=1000)
        _insert_corrupt_envelope(conn, "bad-middle", ts_ns=2000)
        _insert_valid_envelope(conn, "good-2", ts_ns=3000)
        conn.close()

        proc = WALProcessor(wal_path=wal_path, store_path=store_path)
        count = proc.process_batch(batch_size=10)

        # 2 valid processed + 1 corrupt quarantined = all removed from WAL
        assert count == 2
        assert proc.quarantine_count == 1

        # WAL should be empty
        wal_conn = sqlite3.connect(wal_path)
        remaining = wal_conn.execute("SELECT COUNT(*) FROM wal").fetchone()[0]
        wal_conn.close()
        assert remaining == 0

    def test_dead_letter_has_error_message(self, tmp_path):
        """Dead letter entry includes the error message."""
        wal_path = str(tmp_path / "wal.db")
        store_path = str(tmp_path / "telemetry.db")

        conn = _setup_wal_db(wal_path)
        _insert_corrupt_envelope(conn, "bad-err")
        conn.close()

        proc = WALProcessor(wal_path=wal_path, store_path=store_path)
        proc.process_batch(batch_size=10)

        row = proc.store.db.execute(
            "SELECT error_msg, source FROM wal_dead_letter"
        ).fetchone()
        assert row[0]  # Non-empty error message
        assert row[1] == "wal_processor"

    def test_dead_letter_has_timestamp(self, tmp_path):
        """Dead letter entry has a quarantined_at timestamp."""
        wal_path = str(tmp_path / "wal.db")
        store_path = str(tmp_path / "telemetry.db")

        conn = _setup_wal_db(wal_path)
        _insert_corrupt_envelope(conn, "bad-ts")
        conn.close()

        proc = WALProcessor(wal_path=wal_path, store_path=store_path)
        proc.process_batch(batch_size=10)

        row = proc.store.db.execute(
            "SELECT quarantined_at FROM wal_dead_letter"
        ).fetchone()
        assert row[0]  # Non-empty ISO timestamp
        assert "T" in row[0]  # ISO format check


class TestEventBusWALConnection:
    """P0-S3: EventBus handlers should use wal_storage.db, not open new connections."""

    def test_publish_handler_uses_wal_storage(self):
        """Verify Publish handler uses wal_storage.write_raw, not raw SQL."""
        import inspect

        from amoskys.eventbus import server

        source = inspect.getsource(server)

        # Each "if wal_storage:" block should use write_raw, not sqlite3.connect
        publish_sections = source.split("if wal_storage:")

        for section in publish_sections[1:]:  # Skip the part before first match
            block = section[:1200]
            assert "sqlite3.connect" not in block, (
                "Publish handler still opens its own SQLite connection "
                "instead of using wal_storage"
            )
            assert "wal_storage.write_raw" in block, (
                "Publish handler should use wal_storage.write_raw() "
                "for chain-enforced writes"
            )
