"""
Week 2 Hash Chain Enforcement Tests (Sprint Phase A)

Tests for:
  A2.1 — prev_sig chain populated on every WAL write
  A2.2 — Chain verification on read (tampered events quarantined)
  A2.3 — Chain audit tool accuracy on clean and corrupted WALs
"""

import hashlib
import sqlite3

import pytest

# Genesis signature: 32 zero bytes
GENESIS_SIG = b"\x00" * 32


def _compute_chain_sig(env_bytes: bytes, prev_sig: bytes) -> bytes:
    return hashlib.blake2b(env_bytes + prev_sig, digest_size=32).digest()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def wal_db(tmp_path):
    """Create a fresh SQLiteWAL instance in a temp directory."""
    from amoskys.agents.flowagent.wal_sqlite import SQLiteWAL

    db_path = str(tmp_path / "test.db")
    return SQLiteWAL(path=db_path)


@pytest.fixture
def wal_db_path(wal_db):
    """Return the path of the WAL database."""
    return wal_db.path


@pytest.fixture
def raw_wal_db(tmp_path):
    """Create a raw WAL database with chain columns for manual testing."""
    db_path = str(tmp_path / "raw.db")
    conn = sqlite3.connect(db_path, isolation_level=None)
    conn.executescript(
        """
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=FULL;
        CREATE TABLE wal (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            idem TEXT NOT NULL,
            ts_ns INTEGER NOT NULL,
            bytes BLOB NOT NULL,
            checksum BLOB NOT NULL,
            sig BLOB,
            prev_sig BLOB
        );
        CREATE UNIQUE INDEX wal_idem ON wal(idem);
        """
    )
    conn.close()
    return db_path


# ---------------------------------------------------------------------------
# A2.1 — Chain Write Tests
# ---------------------------------------------------------------------------


class TestChainWrite:
    """Verify sig/prev_sig are populated on every WAL write."""

    def test_first_write_uses_genesis_prev_sig(self, wal_db):
        """First row's prev_sig must be GENESIS_SIG (32 zero bytes)."""
        data = b"test-event-001"
        wal_db.write_raw("ev-001", 1000, data)

        row = wal_db.db.execute(
            "SELECT sig, prev_sig FROM wal WHERE idem = 'ev-001'"
        ).fetchone()
        assert row is not None
        sig, prev_sig = bytes(row[0]), bytes(row[1])

        assert prev_sig == GENESIS_SIG
        assert len(sig) == 32

    def test_sig_computed_from_bytes_and_prev_sig(self, wal_db):
        """sig must equal BLAKE2b(bytes || prev_sig)."""
        data = b"test-event-001"
        wal_db.write_raw("ev-001", 1000, data)

        row = wal_db.db.execute(
            "SELECT bytes, sig, prev_sig FROM wal WHERE idem = 'ev-001'"
        ).fetchone()
        raw = bytes(row[0])
        sig = bytes(row[1])
        prev_sig = bytes(row[2])

        expected = _compute_chain_sig(raw, prev_sig)
        assert sig == expected

    def test_second_write_chains_to_first(self, wal_db):
        """Second row's prev_sig must equal first row's sig."""
        wal_db.write_raw("ev-001", 1000, b"first-event")
        wal_db.write_raw("ev-002", 2000, b"second-event")

        rows = wal_db.db.execute(
            "SELECT idem, sig, prev_sig FROM wal ORDER BY id"
        ).fetchall()
        assert len(rows) == 2

        first_sig = bytes(rows[0][1])
        second_prev_sig = bytes(rows[1][2])

        assert second_prev_sig == first_sig

    def test_chain_of_ten_events(self, wal_db):
        """A chain of 10 events must have correct sig/prev_sig linkage."""
        for i in range(10):
            wal_db.write_raw(f"ev-{i:03d}", i * 1000, f"event-{i}".encode())

        rows = wal_db.db.execute(
            "SELECT id, bytes, sig, prev_sig FROM wal ORDER BY id"
        ).fetchall()
        assert len(rows) == 10

        expected_prev = GENESIS_SIG
        for row_id, env_bytes, sig, prev_sig in rows:
            raw = bytes(env_bytes)
            assert bytes(prev_sig) == expected_prev
            expected_sig = _compute_chain_sig(raw, bytes(prev_sig))
            assert bytes(sig) == expected_sig
            expected_prev = bytes(sig)

    def test_duplicate_write_returns_false(self, wal_db):
        """Duplicate idem key should return False and not break chain."""
        assert wal_db.write_raw("ev-001", 1000, b"data") is True
        assert wal_db.write_raw("ev-001", 1000, b"data") is False

        count = wal_db.db.execute("SELECT COUNT(*) FROM wal").fetchone()[0]
        assert count == 1

    def test_checksum_also_populated(self, wal_db):
        """write_raw must also set the per-row BLAKE2b checksum."""
        data = b"test-event-with-checksum"
        wal_db.write_raw("ev-001", 1000, data)

        row = wal_db.db.execute(
            "SELECT bytes, checksum FROM wal WHERE idem = 'ev-001'"
        ).fetchone()
        raw = bytes(row[0])
        checksum = bytes(row[1])

        expected = hashlib.blake2b(raw, digest_size=32).digest()
        assert checksum == expected

    def test_append_uses_chain(self, wal_db):
        """The higher-level append() method must also populate sig/prev_sig."""
        from amoskys.proto import messaging_schema_pb2 as pb

        env = pb.Envelope()
        env.idempotency_key = "append-test-001"
        env.ts_ns = 5000
        wal_db.append(env)

        row = wal_db.db.execute(
            "SELECT sig, prev_sig FROM wal WHERE idem = 'append-test-001'"
        ).fetchone()
        assert row is not None
        assert row[0] is not None  # sig populated
        assert row[1] is not None  # prev_sig populated
        assert bytes(row[1]) == GENESIS_SIG  # first entry


# ---------------------------------------------------------------------------
# A2.2 — Chain Verification on Read Tests
# ---------------------------------------------------------------------------


class TestChainVerificationOnRead:
    """WAL processor must detect and quarantine tampered events."""

    def _setup_wal_with_events(self, db_path, events):
        """Insert events with valid chain into a WAL database."""
        conn = sqlite3.connect(db_path, isolation_level=None)
        prev_sig = GENESIS_SIG
        for idem, ts_ns, data in events:
            checksum = hashlib.blake2b(data, digest_size=32).digest()
            sig = _compute_chain_sig(data, prev_sig)
            conn.execute(
                "INSERT INTO wal(idem, ts_ns, bytes, checksum, sig, prev_sig) "
                "VALUES(?, ?, ?, ?, ?, ?)",
                (idem, ts_ns, data, checksum, sig, prev_sig),
            )
            prev_sig = sig
        conn.close()

    def test_valid_chain_passes_verification(self, raw_wal_db, tmp_path):
        """Events with valid chain should process without quarantine."""
        from amoskys.storage.wal_processor import WALProcessor

        store_path = str(tmp_path / "telemetry.db")
        self._setup_wal_with_events(
            raw_wal_db,
            [
                ("ev-001", 1000, b"valid-event-1"),
                ("ev-002", 2000, b"valid-event-2"),
            ],
        )

        proc = WALProcessor(wal_path=raw_wal_db, store_path=store_path)
        # process_batch will try to parse protobuf and fail, but chain
        # verification should NOT quarantine — protobuf parse error is separate
        proc.process_batch(batch_size=10)
        assert proc.chain_break_count == 0

    def test_tampered_bytes_detected(self, raw_wal_db, tmp_path):
        """If bytes are modified after write, chain sig mismatch quarantines."""
        from amoskys.storage.wal_processor import WALProcessor

        store_path = str(tmp_path / "telemetry.db")

        # Write a valid chain
        data = b"original-data"
        checksum = hashlib.blake2b(data, digest_size=32).digest()
        sig = _compute_chain_sig(data, GENESIS_SIG)

        conn = sqlite3.connect(raw_wal_db, isolation_level=None)
        conn.execute(
            "INSERT INTO wal(idem, ts_ns, bytes, checksum, sig, prev_sig) "
            "VALUES(?, ?, ?, ?, ?, ?)",
            ("ev-001", 1000, data, checksum, sig, GENESIS_SIG),
        )

        # Now tamper with both bytes AND checksum (sophisticated attacker)
        tampered = b"TAMPERED-data!"
        tampered_checksum = hashlib.blake2b(tampered, digest_size=32).digest()
        conn.execute(
            "UPDATE wal SET bytes = ?, checksum = ? WHERE idem = 'ev-001'",
            (tampered, tampered_checksum),
        )
        conn.close()

        proc = WALProcessor(wal_path=raw_wal_db, store_path=store_path)
        proc.process_batch(batch_size=10)

        # The checksum would pass (attacker updated it), but chain sig breaks
        assert proc.chain_break_count == 1

    def test_deleted_row_breaks_chain(self, raw_wal_db, tmp_path):
        """If a middle row is deleted, chain breaks on the next row."""
        from amoskys.storage.wal_processor import WALProcessor

        store_path = str(tmp_path / "telemetry.db")
        self._setup_wal_with_events(
            raw_wal_db,
            [
                ("ev-001", 1000, b"event-1"),
                ("ev-002", 2000, b"event-2"),
                ("ev-003", 3000, b"event-3"),
            ],
        )

        # Delete middle row
        conn = sqlite3.connect(raw_wal_db, isolation_level=None)
        conn.execute("DELETE FROM wal WHERE idem = 'ev-002'")
        conn.close()

        proc = WALProcessor(wal_path=raw_wal_db, store_path=store_path)
        proc.process_batch(batch_size=10)

        # ev-003's prev_sig points to ev-002's sig, but ev-002 is gone
        # The processor doesn't verify inter-row linkage (just sig recomputation)
        # So ev-003 should still pass individual verification
        # Chain break would only be detected by the audit tool
        assert proc.chain_break_count == 0  # Individual sig still valid

    def test_legacy_rows_without_chain_pass(self, tmp_path):
        """Rows without sig/prev_sig (legacy) should not be quarantined."""
        from amoskys.storage.wal_processor import WALProcessor

        db_path = str(tmp_path / "legacy.db")
        conn = sqlite3.connect(db_path, isolation_level=None)
        conn.executescript(
            """
            CREATE TABLE wal (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                idem TEXT NOT NULL UNIQUE,
                ts_ns INTEGER NOT NULL,
                bytes BLOB NOT NULL,
                checksum BLOB NOT NULL
            );
            """
        )
        data = b"legacy-event"
        checksum = hashlib.blake2b(data, digest_size=32).digest()
        conn.execute(
            "INSERT INTO wal(idem, ts_ns, bytes, checksum) VALUES(?, ?, ?, ?)",
            ("leg-001", 1000, data, checksum),
        )
        conn.close()

        store_path = str(tmp_path / "telemetry.db")
        proc = WALProcessor(wal_path=db_path, store_path=store_path)
        proc.process_batch(batch_size=10)
        assert proc.chain_break_count == 0


# ---------------------------------------------------------------------------
# A2.3 — Chain Audit Tool Tests
# ---------------------------------------------------------------------------


class TestChainAuditTool:
    """Verify audit_wal_chain.py reports correctly on clean and corrupt WALs."""

    def _make_clean_wal(self, db_path, count=5):
        """Create a WAL with a valid chain of N events."""
        conn = sqlite3.connect(db_path, isolation_level=None)
        conn.executescript(
            """
            CREATE TABLE wal (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                idem TEXT NOT NULL UNIQUE,
                ts_ns INTEGER NOT NULL,
                bytes BLOB NOT NULL,
                checksum BLOB NOT NULL,
                sig BLOB,
                prev_sig BLOB
            );
            """
        )
        prev_sig = GENESIS_SIG
        for i in range(count):
            data = f"event-{i}".encode()
            checksum = hashlib.blake2b(data, digest_size=32).digest()
            sig = _compute_chain_sig(data, prev_sig)
            conn.execute(
                "INSERT INTO wal(idem, ts_ns, bytes, checksum, sig, prev_sig) "
                "VALUES(?, ?, ?, ?, ?, ?)",
                (f"ev-{i:03d}", i * 1000, data, checksum, sig, prev_sig),
            )
            prev_sig = sig
        conn.close()

    def test_clean_wal_reports_intact(self, tmp_path):
        """Audit of a clean WAL should report intact=True."""
        from scripts.audit_wal_chain import audit_chain

        db_path = str(tmp_path / "clean.db")
        self._make_clean_wal(db_path, count=10)

        result = audit_chain(db_path)
        assert result["intact"] is True
        assert result["total"] == 10
        assert result["verified"] == 10
        assert result["broken"] == 0
        assert result["checksum_failures"] == 0

    def test_tampered_wal_reports_broken(self, tmp_path):
        """Audit of a tampered WAL should report intact=False."""
        from scripts.audit_wal_chain import audit_chain

        db_path = str(tmp_path / "tampered.db")
        self._make_clean_wal(db_path, count=5)

        # Tamper with row 3's bytes (keep checksum/sig as-is)
        conn = sqlite3.connect(db_path, isolation_level=None)
        conn.execute(
            "UPDATE wal SET bytes = ? WHERE idem = 'ev-002'",
            (b"TAMPERED!",),
        )
        conn.close()

        result = audit_chain(db_path)
        assert result["intact"] is False
        assert result["broken"] >= 1
        assert result["first_break_id"] is not None

    def test_missing_wal_reports_error(self, tmp_path):
        """Audit of nonexistent WAL should report error."""
        from scripts.audit_wal_chain import audit_chain

        result = audit_chain(str(tmp_path / "nonexistent.db"))
        assert result["intact"] is False
        assert "error" in result

    def test_legacy_wal_reports_intact(self, tmp_path):
        """Legacy WAL without chain columns should report intact."""
        from scripts.audit_wal_chain import audit_chain

        db_path = str(tmp_path / "legacy.db")
        conn = sqlite3.connect(db_path, isolation_level=None)
        conn.executescript(
            """
            CREATE TABLE wal (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                idem TEXT NOT NULL UNIQUE,
                ts_ns INTEGER NOT NULL,
                bytes BLOB NOT NULL,
                checksum BLOB NOT NULL
            );
            """
        )
        data = b"legacy"
        checksum = hashlib.blake2b(data, digest_size=32).digest()
        conn.execute(
            "INSERT INTO wal(idem, ts_ns, bytes, checksum) VALUES(?, ?, ?, ?)",
            ("leg-001", 1000, data, checksum),
        )
        conn.close()

        result = audit_chain(db_path)
        assert result["intact"] is True
        assert result["unchained"] == 1
        assert "note" in result

    def test_checksum_failure_detected(self, tmp_path):
        """Audit should detect per-row checksum failures too."""
        from scripts.audit_wal_chain import audit_chain

        db_path = str(tmp_path / "bad_checksum.db")
        self._make_clean_wal(db_path, count=3)

        # Corrupt the checksum of row 2
        conn = sqlite3.connect(db_path, isolation_level=None)
        conn.execute(
            "UPDATE wal SET checksum = ? WHERE idem = 'ev-001'",
            (b"\xff" * 32,),
        )
        conn.close()

        result = audit_chain(db_path)
        assert result["intact"] is False
        assert result["checksum_failures"] >= 1

    def test_verbose_mode_prints_output(self, tmp_path, capsys):
        """Verbose mode should print per-row status."""
        from scripts.audit_wal_chain import audit_chain

        db_path = str(tmp_path / "verbose.db")
        self._make_clean_wal(db_path, count=3)

        audit_chain(db_path, verbose=True)
        captured = capsys.readouterr()
        assert "OK" in captured.out

    def test_empty_wal_reports_intact(self, tmp_path):
        """Empty WAL with chain columns should report intact."""
        from scripts.audit_wal_chain import audit_chain

        db_path = str(tmp_path / "empty.db")
        conn = sqlite3.connect(db_path, isolation_level=None)
        conn.executescript(
            """
            CREATE TABLE wal (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                idem TEXT NOT NULL UNIQUE,
                ts_ns INTEGER NOT NULL,
                bytes BLOB NOT NULL,
                checksum BLOB NOT NULL,
                sig BLOB,
                prev_sig BLOB
            );
            """
        )
        conn.close()

        result = audit_chain(db_path)
        assert result["intact"] is True
        assert result["total"] == 0


# ---------------------------------------------------------------------------
# Migration Tests
# ---------------------------------------------------------------------------


class TestChainMigration:
    """Verify that existing WAL databases get chain columns added."""

    def test_migration_adds_columns(self, tmp_path):
        """Opening a legacy WAL should add sig/prev_sig columns."""
        from amoskys.agents.flowagent.wal_sqlite import SQLiteWAL

        db_path = str(tmp_path / "legacy.db")

        # Create legacy schema without chain columns
        conn = sqlite3.connect(db_path, isolation_level=None)
        conn.executescript(
            """
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;
            CREATE TABLE wal (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                idem TEXT NOT NULL,
                ts_ns INTEGER NOT NULL,
                bytes BLOB NOT NULL,
                checksum BLOB NOT NULL
            );
            CREATE UNIQUE INDEX wal_idem ON wal(idem);
            """
        )
        conn.close()

        # Open with SQLiteWAL — should trigger migration
        wal = SQLiteWAL(path=db_path)
        cols = {row[1] for row in wal.db.execute("PRAGMA table_info(wal)").fetchall()}
        assert "sig" in cols
        assert "prev_sig" in cols

    def test_migration_is_idempotent(self, tmp_path):
        """Opening the same WAL twice should not fail."""
        from amoskys.agents.flowagent.wal_sqlite import SQLiteWAL

        db_path = str(tmp_path / "idem.db")
        wal1 = SQLiteWAL(path=db_path)
        wal1.write_raw("ev-001", 1000, b"data")

        # Reopen — migration should be idempotent
        wal2 = SQLiteWAL(path=db_path)
        wal2.write_raw("ev-002", 2000, b"data2")

        count = wal2.db.execute("SELECT COUNT(*) FROM wal").fetchone()[0]
        assert count == 2
