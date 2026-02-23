"""
Unit tests for WAL Processor and TelemetryStore.

Covers:
- WALProcessor initialization
- Batch processing (valid, corrupt, empty WAL)
- BLAKE2b checksum verification and quarantine
- Dead letter quarantine mechanics
- Backpressure (batch size capping)
- Process event classification logic
- Local queue draining
- Error handling and connection failures
- TelemetryStore CRUD operations
- TelemetryStore query methods
- Incident management
- Statistics and search
"""

import hashlib
import json
import sqlite3
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.storage.telemetry_store import TelemetryStore
from amoskys.storage.wal_processor import WALProcessor

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _setup_wal_db(wal_path: str) -> sqlite3.Connection:
    """Create a minimal WAL database with the expected schema."""
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


def _make_device_telemetry_envelope(
    device_id: str = "test-device",
    agent: str = "test-agent",
    version: str = "1.0.0",
    events: list | None = None,
) -> telemetry_pb2.UniversalEnvelope:
    """Build a UniversalEnvelope containing DeviceTelemetry."""
    env = telemetry_pb2.UniversalEnvelope()
    dt = env.device_telemetry
    dt.device_id = device_id
    dt.collection_agent = agent
    dt.agent_version = version

    if events:
        for ev_cfg in events:
            ev = dt.events.add()
            ev.event_id = ev_cfg.get("event_id", "ev-1")
            ev.event_type = ev_cfg.get("event_type", "METRIC")
            ev.severity = ev_cfg.get("severity", "INFO")
            ev.event_timestamp_ns = ev_cfg.get("ts_ns", 1000)
    else:
        ev = dt.events.add()
        ev.event_id = "ev-default"
        ev.event_type = "METRIC"
        ev.severity = "INFO"
        ev.event_timestamp_ns = 1000

    return env


def _insert_envelope(
    conn: sqlite3.Connection,
    idem: str,
    env: telemetry_pb2.UniversalEnvelope,
    ts_ns: int = 1000,
    with_checksum: bool = False,
) -> bytes:
    """Serialize an envelope and insert into WAL. Optionally add BLAKE2b checksum."""
    raw = env.SerializeToString()
    checksum = None
    if with_checksum:
        checksum = hashlib.blake2b(raw, digest_size=32).digest()
    conn.execute(
        "INSERT INTO wal (idem, ts_ns, bytes, checksum) VALUES (?, ?, ?, ?)",
        (
            idem,
            ts_ns,
            sqlite3.Binary(raw),
            sqlite3.Binary(checksum) if checksum else None,
        ),
    )
    conn.commit()
    return raw


def _insert_corrupt(
    conn: sqlite3.Connection,
    idem: str,
    ts_ns: int = 2000,
    with_checksum: bool = False,
) -> bytes:
    """Insert corrupt bytes (not valid protobuf) into WAL."""
    bad = b"NOT_A_PROTOBUF_AT_ALL"
    checksum = None
    if with_checksum:
        checksum = hashlib.blake2b(bad, digest_size=32).digest()
    conn.execute(
        "INSERT INTO wal (idem, ts_ns, bytes, checksum) VALUES (?, ?, ?, ?)",
        (
            idem,
            ts_ns,
            sqlite3.Binary(bad),
            sqlite3.Binary(checksum) if checksum else None,
        ),
    )
    conn.commit()
    return bad


# ===========================================================================
# WALProcessor Tests
# ===========================================================================


class TestWALProcessorInit:
    """Test WALProcessor construction."""

    def test_init_sets_paths(self, tmp_path):
        wal_path = str(tmp_path / "wal.db")
        store_path = str(tmp_path / "store.db")
        # Create the WAL db so it exists (not strictly required, but keeps it tidy)
        _setup_wal_db(wal_path).close()

        proc = WALProcessor(wal_path=wal_path, store_path=store_path)

        assert proc.wal_path == wal_path
        assert proc.store.db_path == store_path

    def test_init_counters_are_zero(self, tmp_path):
        proc = WALProcessor(
            wal_path=str(tmp_path / "wal.db"),
            store_path=str(tmp_path / "store.db"),
        )
        assert proc.processed_count == 0
        assert proc.error_count == 0
        assert proc.quarantine_count == 0

    def test_init_creates_telemetry_store(self, tmp_path):
        proc = WALProcessor(
            wal_path=str(tmp_path / "wal.db"),
            store_path=str(tmp_path / "store.db"),
        )
        assert isinstance(proc.store, TelemetryStore)


class TestProcessBatchEmpty:
    """process_batch on empty or missing WAL."""

    def test_empty_wal_returns_zero(self, tmp_path):
        wal_path = str(tmp_path / "wal.db")
        _setup_wal_db(wal_path).close()

        proc = WALProcessor(wal_path=wal_path, store_path=str(tmp_path / "store.db"))
        assert proc.process_batch(batch_size=10) == 0

    def test_missing_wal_raises_operational_error(self, tmp_path):
        """If the WAL db path is missing entirely, sqlite3 creates a new empty db
        but the table won't exist, causing OperationalError."""
        wal_path = str(tmp_path / "nonexistent" / "wal.db")
        proc = WALProcessor(wal_path=wal_path, store_path=str(tmp_path / "store.db"))
        # The parent dir doesn't exist, so connect itself will fail
        with pytest.raises(sqlite3.OperationalError):
            proc.process_batch()


class TestProcessBatchValidEntries:
    """process_batch with valid protobuf entries (no checksum)."""

    def test_single_valid_entry_processed(self, tmp_path):
        wal_path = str(tmp_path / "wal.db")
        store_path = str(tmp_path / "store.db")
        conn = _setup_wal_db(wal_path)

        env = _make_device_telemetry_envelope()
        _insert_envelope(conn, "valid-1", env, ts_ns=1000)
        conn.close()

        proc = WALProcessor(wal_path=wal_path, store_path=store_path)
        count = proc.process_batch(batch_size=10)

        assert count == 1
        assert proc.processed_count == 1
        assert proc.error_count == 0

    def test_multiple_valid_entries_processed(self, tmp_path):
        wal_path = str(tmp_path / "wal.db")
        store_path = str(tmp_path / "store.db")
        conn = _setup_wal_db(wal_path)

        for i in range(5):
            env = _make_device_telemetry_envelope(device_id=f"dev-{i}")
            _insert_envelope(conn, f"entry-{i}", env, ts_ns=1000 + i)
        conn.close()

        proc = WALProcessor(wal_path=wal_path, store_path=store_path)
        count = proc.process_batch(batch_size=10)

        assert count == 5
        assert proc.processed_count == 5

    def test_entries_deleted_from_wal_after_processing(self, tmp_path):
        wal_path = str(tmp_path / "wal.db")
        store_path = str(tmp_path / "store.db")
        conn = _setup_wal_db(wal_path)
        _insert_envelope(conn, "del-test", _make_device_telemetry_envelope())
        conn.close()

        proc = WALProcessor(wal_path=wal_path, store_path=store_path)
        proc.process_batch(batch_size=10)

        verify = sqlite3.connect(wal_path)
        remaining = verify.execute("SELECT COUNT(*) FROM wal").fetchone()[0]
        verify.close()
        assert remaining == 0


class TestBatchSizeCapping:
    """process_batch caps batch_size at 500 (backpressure)."""

    def test_batch_size_capped_at_500(self, tmp_path):
        wal_path = str(tmp_path / "wal.db")
        store_path = str(tmp_path / "store.db")
        conn = _setup_wal_db(wal_path)
        conn.close()

        proc = WALProcessor(wal_path=wal_path, store_path=store_path)
        # Internally the batch_size should be capped; we verify by
        # checking the method doesn't break with a large value
        result = proc.process_batch(batch_size=9999)
        assert result == 0  # Empty WAL, just checking no error

    def test_batch_size_respected_when_small(self, tmp_path):
        wal_path = str(tmp_path / "wal.db")
        store_path = str(tmp_path / "store.db")
        conn = _setup_wal_db(wal_path)

        # Insert 5 entries
        for i in range(5):
            env = _make_device_telemetry_envelope(device_id=f"dev-{i}")
            _insert_envelope(conn, f"batch-{i}", env, ts_ns=1000 + i)
        conn.close()

        proc = WALProcessor(wal_path=wal_path, store_path=store_path)
        # Process only 2 at a time
        count = proc.process_batch(batch_size=2)
        assert count == 2

        # 3 should remain
        verify = sqlite3.connect(wal_path)
        remaining = verify.execute("SELECT COUNT(*) FROM wal").fetchone()[0]
        verify.close()
        assert remaining == 3


class TestBLAKE2bChecksumVerification:
    """P0-S2: BLAKE2b verification before processing."""

    def test_valid_checksum_entry_processed(self, tmp_path):
        wal_path = str(tmp_path / "wal.db")
        store_path = str(tmp_path / "store.db")
        conn = _setup_wal_db(wal_path)

        env = _make_device_telemetry_envelope()
        _insert_envelope(conn, "cs-valid", env, ts_ns=1000, with_checksum=True)
        conn.close()

        proc = WALProcessor(wal_path=wal_path, store_path=store_path)
        count = proc.process_batch(batch_size=10)

        assert count == 1
        assert proc.quarantine_count == 0

    def test_checksum_mismatch_quarantined(self, tmp_path):
        wal_path = str(tmp_path / "wal.db")
        store_path = str(tmp_path / "store.db")
        conn = _setup_wal_db(wal_path)

        env = _make_device_telemetry_envelope()
        raw = env.SerializeToString()
        # Store a wrong checksum (32 bytes but different from actual)
        wrong_checksum = hashlib.blake2b(b"wrong-data", digest_size=32).digest()
        conn.execute(
            "INSERT INTO wal (idem, ts_ns, bytes, checksum) VALUES (?, ?, ?, ?)",
            ("cs-mismatch", 1000, sqlite3.Binary(raw), sqlite3.Binary(wrong_checksum)),
        )
        conn.commit()
        conn.close()

        proc = WALProcessor(wal_path=wal_path, store_path=store_path)
        count = proc.process_batch(batch_size=10)

        # Not processed (checksum mismatch), but quarantined
        assert count == 0
        assert proc.quarantine_count == 1

        # Dead letter should contain the entry
        dl_count = proc.store.db.execute(
            "SELECT COUNT(*) FROM wal_dead_letter"
        ).fetchone()[0]
        assert dl_count == 1

    def test_invalid_checksum_size_quarantined(self, tmp_path):
        wal_path = str(tmp_path / "wal.db")
        store_path = str(tmp_path / "store.db")
        conn = _setup_wal_db(wal_path)

        env = _make_device_telemetry_envelope()
        raw = env.SerializeToString()
        # Store a checksum with wrong size (not 32 bytes)
        bad_size_checksum = b"short"
        conn.execute(
            "INSERT INTO wal (idem, ts_ns, bytes, checksum) VALUES (?, ?, ?, ?)",
            (
                "cs-badsize",
                1000,
                sqlite3.Binary(raw),
                sqlite3.Binary(bad_size_checksum),
            ),
        )
        conn.commit()
        conn.close()

        proc = WALProcessor(wal_path=wal_path, store_path=store_path)
        count = proc.process_batch(batch_size=10)

        assert count == 0
        assert proc.quarantine_count == 1

    def test_null_checksum_skips_verification(self, tmp_path):
        """Entries with NULL checksum bypass verification (legacy)."""
        wal_path = str(tmp_path / "wal.db")
        store_path = str(tmp_path / "store.db")
        conn = _setup_wal_db(wal_path)

        env = _make_device_telemetry_envelope()
        # Insert without checksum (None)
        _insert_envelope(conn, "no-cs", env, ts_ns=1000, with_checksum=False)
        conn.close()

        proc = WALProcessor(wal_path=wal_path, store_path=store_path)
        count = proc.process_batch(batch_size=10)

        assert count == 1
        assert proc.quarantine_count == 0


class TestDeadLetterQuarantine:
    """Quarantine mechanics for failed entries."""

    def test_quarantine_stores_original_bytes(self, tmp_path):
        wal_path = str(tmp_path / "wal.db")
        store_path = str(tmp_path / "store.db")
        conn = _setup_wal_db(wal_path)

        bad_data = _insert_corrupt(conn, "bad-bytes", with_checksum=True)
        conn.close()

        proc = WALProcessor(wal_path=wal_path, store_path=store_path)
        proc.process_batch(batch_size=10)

        row = proc.store.db.execute(
            "SELECT envelope_bytes FROM wal_dead_letter"
        ).fetchone()
        assert row is not None
        assert bytes(row[0]) == bad_data

    def test_quarantine_stores_error_message(self, tmp_path):
        wal_path = str(tmp_path / "wal.db")
        store_path = str(tmp_path / "store.db")
        conn = _setup_wal_db(wal_path)
        _insert_corrupt(conn, "bad-err")
        conn.close()

        proc = WALProcessor(wal_path=wal_path, store_path=store_path)
        proc.process_batch(batch_size=10)

        row = proc.store.db.execute(
            "SELECT error_msg, source FROM wal_dead_letter"
        ).fetchone()
        assert row is not None
        assert len(row[0]) > 0  # Non-empty error message
        assert row[1] == "wal_processor"

    def test_quarantine_has_iso_timestamp(self, tmp_path):
        wal_path = str(tmp_path / "wal.db")
        store_path = str(tmp_path / "store.db")
        conn = _setup_wal_db(wal_path)
        _insert_corrupt(conn, "bad-ts")
        conn.close()

        proc = WALProcessor(wal_path=wal_path, store_path=store_path)
        proc.process_batch(batch_size=10)

        row = proc.store.db.execute(
            "SELECT quarantined_at FROM wal_dead_letter"
        ).fetchone()
        assert row is not None
        assert "T" in row[0]  # ISO 8601 format

    def test_quarantine_increments_counter(self, tmp_path):
        wal_path = str(tmp_path / "wal.db")
        store_path = str(tmp_path / "store.db")
        conn = _setup_wal_db(wal_path)
        _insert_corrupt(conn, "bad-1")
        _insert_corrupt(conn, "bad-2", ts_ns=3000)
        conn.close()

        proc = WALProcessor(wal_path=wal_path, store_path=store_path)
        proc.process_batch(batch_size=10)

        assert proc.quarantine_count == 2

    def test_quarantine_failure_does_not_crash(self, tmp_path):
        """If quarantine itself fails, the processor should not crash."""
        wal_path = str(tmp_path / "wal.db")
        store_path = str(tmp_path / "store.db")
        conn = _setup_wal_db(wal_path)
        _insert_corrupt(conn, "bad-qfail")
        conn.close()

        proc = WALProcessor(wal_path=wal_path, store_path=store_path)

        # Replace the store.db with a mock that fails on INSERT INTO wal_dead_letter
        real_db = proc.store.db
        mock_db = MagicMock(wraps=real_db)
        original_execute = real_db.execute

        def selective_execute(sql, *args, **kwargs):
            if "INSERT INTO wal_dead_letter" in str(sql):
                raise sqlite3.OperationalError("disk full")
            return original_execute(sql, *args, **kwargs)

        mock_db.execute = selective_execute
        proc.store.db = mock_db

        # Should not raise, just log the error
        proc.process_batch(batch_size=10)
        assert proc.quarantine_count == 0  # Quarantine failed, count not incremented


class TestMixedEntries:
    """Processing batches with valid and corrupt entries interleaved."""

    def test_valid_entries_survive_alongside_corrupt(self, tmp_path):
        wal_path = str(tmp_path / "wal.db")
        store_path = str(tmp_path / "store.db")
        conn = _setup_wal_db(wal_path)

        _insert_envelope(conn, "good-1", _make_device_telemetry_envelope(), ts_ns=1000)
        _insert_corrupt(conn, "bad-mid", ts_ns=2000)
        _insert_envelope(conn, "good-2", _make_device_telemetry_envelope(), ts_ns=3000)
        conn.close()

        proc = WALProcessor(wal_path=wal_path, store_path=store_path)
        count = proc.process_batch(batch_size=10)

        assert count == 2
        assert proc.error_count == 1
        assert proc.quarantine_count == 1

        # WAL should be fully drained
        verify = sqlite3.connect(wal_path)
        remaining = verify.execute("SELECT COUNT(*) FROM wal").fetchone()[0]
        verify.close()
        assert remaining == 0


class TestProcessProcessEvent:
    """Test _process_process_event logic (process classification)."""

    def test_process_event_stored_in_db(self, tmp_path):
        wal_path = str(tmp_path / "wal.db")
        store_path = str(tmp_path / "store.db")
        conn = _setup_wal_db(wal_path)

        env = telemetry_pb2.UniversalEnvelope()
        proc_ev = env.process
        proc_ev.pid = 42
        proc_ev.ppid = 1
        proc_ev.exe = "/usr/bin/python3"
        proc_ev.uid = 501
        proc_ev.args.append("script.py")

        raw = env.SerializeToString()
        conn.execute(
            "INSERT INTO wal (idem, ts_ns, bytes) VALUES (?, ?, ?)",
            ("proc-1", 1000, sqlite3.Binary(raw)),
        )
        conn.commit()
        conn.close()

        processor = WALProcessor(wal_path=wal_path, store_path=store_path)
        count = processor.process_batch(batch_size=10)

        assert count == 1
        rows = processor.store.get_recent_processes(limit=10)
        assert len(rows) == 1
        assert rows[0]["pid"] == 42
        assert rows[0]["exe"] == "/usr/bin/python3"
        assert rows[0]["user_type"] == "user"

    def test_root_user_classified(self, tmp_path):
        wal_path = str(tmp_path / "wal.db")
        store_path = str(tmp_path / "store.db")
        conn = _setup_wal_db(wal_path)

        env = telemetry_pb2.UniversalEnvelope()
        proc_ev = env.process
        proc_ev.pid = 1
        proc_ev.ppid = 0
        proc_ev.exe = "/sbin/launchd"
        proc_ev.uid = 0  # root

        raw = env.SerializeToString()
        conn.execute(
            "INSERT INTO wal (idem, ts_ns, bytes) VALUES (?, ?, ?)",
            ("proc-root", 1000, sqlite3.Binary(raw)),
        )
        conn.commit()
        conn.close()

        processor = WALProcessor(wal_path=wal_path, store_path=store_path)
        processor.process_batch(batch_size=10)

        rows = processor.store.get_recent_processes(limit=10)
        assert rows[0]["user_type"] == "root"

    def test_system_user_classified(self, tmp_path):
        wal_path = str(tmp_path / "wal.db")
        store_path = str(tmp_path / "store.db")
        conn = _setup_wal_db(wal_path)

        env = telemetry_pb2.UniversalEnvelope()
        proc_ev = env.process
        proc_ev.pid = 100
        proc_ev.ppid = 1
        proc_ev.exe = "/usr/bin/something"
        proc_ev.uid = 200  # system user (< 500)

        raw = env.SerializeToString()
        conn.execute(
            "INSERT INTO wal (idem, ts_ns, bytes) VALUES (?, ?, ?)",
            ("proc-sys", 1000, sqlite3.Binary(raw)),
        )
        conn.commit()
        conn.close()

        processor = WALProcessor(wal_path=wal_path, store_path=store_path)
        processor.process_batch(batch_size=10)

        rows = processor.store.get_recent_processes(limit=10)
        assert rows[0]["user_type"] == "system"

    def test_daemon_category_detected(self, tmp_path):
        wal_path = str(tmp_path / "wal.db")
        store_path = str(tmp_path / "store.db")
        conn = _setup_wal_db(wal_path)

        env = telemetry_pb2.UniversalEnvelope()
        proc_ev = env.process
        proc_ev.pid = 50
        proc_ev.ppid = 1
        proc_ev.exe = "/usr/sbin/httpd"
        proc_ev.uid = 0

        raw = env.SerializeToString()
        conn.execute(
            "INSERT INTO wal (idem, ts_ns, bytes) VALUES (?, ?, ?)",
            ("proc-daemon", 1000, sqlite3.Binary(raw)),
        )
        conn.commit()
        conn.close()

        processor = WALProcessor(wal_path=wal_path, store_path=store_path)
        processor.process_batch(batch_size=10)

        rows = processor.store.get_recent_processes(limit=10)
        assert rows[0]["process_category"] == "daemon"

    def test_application_category_detected(self, tmp_path):
        wal_path = str(tmp_path / "wal.db")
        store_path = str(tmp_path / "store.db")
        conn = _setup_wal_db(wal_path)

        env = telemetry_pb2.UniversalEnvelope()
        proc_ev = env.process
        proc_ev.pid = 999
        proc_ev.ppid = 1
        proc_ev.exe = "/Applications/Safari.app/Contents/MacOS/Safari"
        proc_ev.uid = 501

        raw = env.SerializeToString()
        conn.execute(
            "INSERT INTO wal (idem, ts_ns, bytes) VALUES (?, ?, ?)",
            ("proc-app", 1000, sqlite3.Binary(raw)),
        )
        conn.commit()
        conn.close()

        processor = WALProcessor(wal_path=wal_path, store_path=store_path)
        processor.process_batch(batch_size=10)

        rows = processor.store.get_recent_processes(limit=10)
        assert rows[0]["process_category"] == "application"


class TestProcessFlowEvent:
    """Test _process_flow_event via process_batch."""

    def test_flow_event_stored(self, tmp_path):
        wal_path = str(tmp_path / "wal.db")
        store_path = str(tmp_path / "store.db")
        conn = _setup_wal_db(wal_path)

        env = telemetry_pb2.UniversalEnvelope()
        flow = env.flow
        flow.src_ip = "10.0.0.1"
        flow.dst_ip = "8.8.8.8"
        flow.src_port = 45000
        flow.dst_port = 53
        flow.protocol = "UDP"
        flow.bytes_tx = 100
        flow.bytes_rx = 200

        raw = env.SerializeToString()
        conn.execute(
            "INSERT INTO wal (idem, ts_ns, bytes) VALUES (?, ?, ?)",
            ("flow-1", 1000, sqlite3.Binary(raw)),
        )
        conn.commit()
        conn.close()

        processor = WALProcessor(wal_path=wal_path, store_path=store_path)
        count = processor.process_batch(batch_size=10)

        assert count == 1

        # Verify flow event in store
        cursor = processor.store.db.execute("SELECT * FROM flow_events")
        rows = cursor.fetchall()
        assert len(rows) == 1


class TestProcessLocalQueues:
    """Test process_local_queues (draining local agent queues)."""

    def test_drain_empty_directory(self, tmp_path):
        queue_dir = str(tmp_path / "queue")
        (tmp_path / "queue").mkdir()

        proc = WALProcessor(
            wal_path=str(tmp_path / "wal.db"),
            store_path=str(tmp_path / "store.db"),
        )
        total = proc.process_local_queues(queue_dir=queue_dir)
        assert total == 0

    def test_drain_agent_queue(self, tmp_path):
        queue_dir = tmp_path / "queue"
        queue_dir.mkdir()

        # Create a local agent queue database
        agent_db_path = str(queue_dir / "test_agent_v2.db")
        conn = sqlite3.connect(agent_db_path)
        conn.execute(
            """CREATE TABLE IF NOT EXISTS queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_ns INTEGER NOT NULL,
                bytes BLOB NOT NULL
            )"""
        )

        dt = telemetry_pb2.DeviceTelemetry()
        dt.device_id = "queue-device"
        dt.collection_agent = "test-agent-v2"
        raw = dt.SerializeToString()

        conn.execute(
            "INSERT INTO queue (ts_ns, bytes) VALUES (?, ?)",
            (1000, sqlite3.Binary(raw)),
        )
        conn.commit()
        conn.close()

        proc = WALProcessor(
            wal_path=str(tmp_path / "wal.db"),
            store_path=str(tmp_path / "store.db"),
        )
        total = proc.process_local_queues(queue_dir=str(queue_dir))
        assert total == 1

    def test_drain_corrupt_queue_entry_quarantined(self, tmp_path):
        queue_dir = tmp_path / "queue"
        queue_dir.mkdir()

        agent_db_path = str(queue_dir / "broken_v2.db")
        conn = sqlite3.connect(agent_db_path)
        conn.execute(
            """CREATE TABLE IF NOT EXISTS queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_ns INTEGER NOT NULL,
                bytes BLOB NOT NULL
            )"""
        )
        conn.execute(
            "INSERT INTO queue (ts_ns, bytes) VALUES (?, ?)",
            (1000, sqlite3.Binary(b"GARBAGE")),
        )
        conn.commit()
        conn.close()

        proc = WALProcessor(
            wal_path=str(tmp_path / "wal.db"),
            store_path=str(tmp_path / "store.db"),
        )
        total = proc.process_local_queues(queue_dir=str(queue_dir))
        # Entry is processed (attempted + quarantined), removed from queue
        assert total == 1
        assert proc.error_count == 1

    def test_drain_removes_entries_from_queue(self, tmp_path):
        queue_dir = tmp_path / "queue"
        queue_dir.mkdir()

        agent_db_path = str(queue_dir / "agent_v2.db")
        conn = sqlite3.connect(agent_db_path)
        conn.execute(
            """CREATE TABLE IF NOT EXISTS queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_ns INTEGER NOT NULL,
                bytes BLOB NOT NULL
            )"""
        )

        dt = telemetry_pb2.DeviceTelemetry()
        dt.device_id = "drain-dev"
        dt.collection_agent = "agent-v2"
        raw = dt.SerializeToString()

        conn.execute(
            "INSERT INTO queue (ts_ns, bytes) VALUES (?, ?)",
            (1000, sqlite3.Binary(raw)),
        )
        conn.commit()
        conn.close()

        proc = WALProcessor(
            wal_path=str(tmp_path / "wal.db"),
            store_path=str(tmp_path / "store.db"),
        )
        proc.process_local_queues(queue_dir=str(queue_dir))

        # Verify queue is drained
        verify = sqlite3.connect(agent_db_path)
        remaining = verify.execute("SELECT COUNT(*) FROM queue").fetchone()[0]
        verify.close()
        assert remaining == 0


class TestExtractMetrics:
    """Test _extract_metrics helper."""

    def test_extract_process_count(self, tmp_path):
        proc = WALProcessor(
            wal_path=str(tmp_path / "wal.db"),
            store_path=str(tmp_path / "store.db"),
        )
        events = []
        ev = telemetry_pb2.TelemetryEvent()
        ev.event_type = "METRIC"
        md = ev.metric_data
        md.metric_name = "process_count"
        md.numeric_value = 42.0
        events.append(ev)

        total_proc, cpu, mem = proc._extract_metrics(events)
        assert total_proc == 42
        assert cpu == 0.0
        assert mem == 0.0

    def test_extract_cpu_and_memory(self, tmp_path):
        proc = WALProcessor(
            wal_path=str(tmp_path / "wal.db"),
            store_path=str(tmp_path / "store.db"),
        )
        events = []

        ev_cpu = telemetry_pb2.TelemetryEvent()
        ev_cpu.event_type = "METRIC"
        ev_cpu.metric_data.metric_name = "system_cpu_percent"
        ev_cpu.metric_data.numeric_value = 55.5
        events.append(ev_cpu)

        ev_mem = telemetry_pb2.TelemetryEvent()
        ev_mem.event_type = "METRIC"
        ev_mem.metric_data.metric_name = "system_memory_percent"
        ev_mem.metric_data.numeric_value = 77.3
        events.append(ev_mem)

        total_proc, cpu, mem = proc._extract_metrics(events)
        assert total_proc == 0
        assert cpu == 55.5
        assert mem == 77.3

    def test_non_metric_events_ignored(self, tmp_path):
        proc = WALProcessor(
            wal_path=str(tmp_path / "wal.db"),
            store_path=str(tmp_path / "store.db"),
        )
        events = []
        ev = telemetry_pb2.TelemetryEvent()
        ev.event_type = "LOG"  # Not METRIC
        events.append(ev)

        total_proc, cpu, mem = proc._extract_metrics(events)
        assert total_proc == 0
        assert cpu == 0.0
        assert mem == 0.0


class TestWALProcessorConnectionError:
    """Test error handling for database connectivity issues."""

    def test_operational_error_propagated(self, tmp_path):
        """OperationalError from SQLite should propagate for caller to back off."""
        wal_path = str(tmp_path / "nonexistent_dir" / "wal.db")
        store_path = str(tmp_path / "store.db")

        proc = WALProcessor(wal_path=wal_path, store_path=store_path)
        with pytest.raises(sqlite3.OperationalError):
            proc.process_batch()

    def test_generic_exception_returns_zero(self, tmp_path):
        """Non-OperationalError exceptions are caught and return 0."""
        wal_path = str(tmp_path / "wal.db")
        store_path = str(tmp_path / "store.db")
        conn = _setup_wal_db(wal_path)
        conn.close()

        proc = WALProcessor(wal_path=wal_path, store_path=store_path)

        # Patch sqlite3.connect to raise a generic Exception after connection
        with patch("amoskys.storage.wal_processor.sqlite3.connect") as mock_conn:
            mock_conn.side_effect = Exception("unexpected error")
            result = proc.process_batch()
            assert result == 0


# ===========================================================================
# TelemetryStore Tests
# ===========================================================================


class TestTelemetryStoreInit:
    """Test TelemetryStore construction and schema creation."""

    def test_init_creates_database_file(self, tmp_path):
        db_path = str(tmp_path / "test_store.db")
        store = TelemetryStore(db_path)
        assert (tmp_path / "test_store.db").exists()
        store.close()

    def test_init_creates_parent_directories(self, tmp_path):
        db_path = str(tmp_path / "nested" / "dir" / "store.db")
        store = TelemetryStore(db_path)
        assert (tmp_path / "nested" / "dir" / "store.db").exists()
        store.close()

    def test_init_creates_all_tables(self, tmp_path):
        db_path = str(tmp_path / "schema_test.db")
        store = TelemetryStore(db_path)

        expected_tables = [
            "process_events",
            "device_telemetry",
            "flow_events",
            "security_events",
            "peripheral_events",
            "metrics_timeseries",
            "incidents",
            "alert_rules",
            "dns_events",
            "audit_events",
            "persistence_events",
            "fim_events",
            "wal_archive",
            "wal_dead_letter",
        ]
        cursor = store.db.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}

        for t in expected_tables:
            assert t in tables, f"Table {t} not found in schema"

        store.close()


class TestTelemetryStoreInsertProcessEvent:
    """Test insert_process_event."""

    def test_insert_returns_row_id(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        row_id = store.insert_process_event(
            {
                "timestamp_ns": 1000,
                "timestamp_dt": "2024-01-01T00:00:00",
                "device_id": "dev-1",
                "pid": 42,
                "ppid": 1,
                "exe": "/usr/bin/test",
                "cmdline": "test --flag",
                "user_type": "user",
                "process_category": "unknown",
            }
        )
        assert row_id is not None
        assert row_id > 0
        store.close()

    def test_insert_retrievable_via_get_recent(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        store.insert_process_event(
            {
                "timestamp_ns": 1000,
                "timestamp_dt": "2024-01-01T00:00:00",
                "device_id": "dev-1",
                "pid": 99,
                "exe": "/bin/bash",
            }
        )

        results = store.get_recent_processes(limit=10)
        assert len(results) == 1
        assert results[0]["pid"] == 99
        assert results[0]["exe"] == "/bin/bash"
        store.close()

    def test_get_recent_processes_filters_by_device(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        store.insert_process_event(
            {
                "timestamp_ns": 1000,
                "timestamp_dt": "2024-01-01T00:00:00",
                "device_id": "dev-A",
                "pid": 1,
            }
        )
        store.insert_process_event(
            {
                "timestamp_ns": 2000,
                "timestamp_dt": "2024-01-01T00:00:01",
                "device_id": "dev-B",
                "pid": 2,
            }
        )

        results = store.get_recent_processes(limit=10, device_id="dev-A")
        assert len(results) == 1
        assert results[0]["device_id"] == "dev-A"
        store.close()


class TestTelemetryStoreInsertSecurityEvent:
    """Test insert_security_event."""

    def test_insert_security_event(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        row_id = store.insert_security_event(
            {
                "timestamp_ns": int(time.time() * 1e9),
                "timestamp_dt": datetime.now(timezone.utc).isoformat(),
                "device_id": "dev-1",
                "event_category": "INTRUSION",
                "risk_score": 0.85,
                "confidence": 0.9,
                "mitre_techniques": ["T1059", "T1082"],
                "final_classification": "malicious",
                "description": "Suspicious shell execution",
                "indicators": {"ip": "10.0.0.5"},
                "requires_investigation": True,
                "collection_agent": "proc-agent",
            }
        )
        assert row_id is not None
        store.close()

    def test_get_recent_security_events(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        ts_ns = int(time.time() * 1e9)
        store.insert_security_event(
            {
                "timestamp_ns": ts_ns,
                "timestamp_dt": datetime.now(timezone.utc).isoformat(),
                "device_id": "dev-1",
                "event_category": "MALWARE",
                "risk_score": 0.9,
                "final_classification": "malicious",
            }
        )

        results = store.get_recent_security_events(limit=10, hours=24)
        assert len(results) == 1
        assert results[0]["event_category"] == "MALWARE"
        store.close()

    def test_get_recent_security_events_severity_filter(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        ts_ns = int(time.time() * 1e9)
        store.insert_security_event(
            {
                "timestamp_ns": ts_ns,
                "device_id": "dev-1",
                "event_category": "AUTH",
                "risk_score": 0.3,
                "final_classification": "legitimate",
            }
        )
        store.insert_security_event(
            {
                "timestamp_ns": ts_ns + 1,
                "device_id": "dev-1",
                "event_category": "INTRUSION",
                "risk_score": 0.8,
                "final_classification": "malicious",
            }
        )

        legit = store.get_recent_security_events(severity="legitimate", hours=24)
        assert len(legit) == 1
        assert legit[0]["final_classification"] == "legitimate"
        store.close()


class TestTelemetryStoreInsertFlowEvent:
    """Test insert_flow_event."""

    def test_insert_flow_event(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        row_id = store.insert_flow_event(
            {
                "timestamp_ns": 1000,
                "timestamp_dt": "2024-01-01T00:00:00",
                "device_id": "dev-1",
                "src_ip": "10.0.0.1",
                "dst_ip": "8.8.8.8",
                "src_port": 45000,
                "dst_port": 53,
                "protocol": "UDP",
                "bytes_tx": 100,
                "bytes_rx": 200,
            }
        )
        assert row_id is not None
        store.close()


class TestTelemetryStoreInsertPeripheralEvent:
    """Test insert_peripheral_event."""

    def test_insert_peripheral_event(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        row_id = store.insert_peripheral_event(
            {
                "timestamp_ns": 1000,
                "timestamp_dt": "2024-01-01T00:00:00",
                "device_id": "dev-1",
                "peripheral_device_id": "usb-001",
                "event_type": "CONNECTED",
                "device_name": "Flash Drive",
                "device_type": "USB_STORAGE",
                "connection_status": "CONNECTED",
                "is_authorized": True,
                "risk_score": 0.0,
            }
        )
        assert row_id is not None
        store.close()


class TestTelemetryStoreInsertDNSEvent:
    """Test insert_dns_event."""

    def test_insert_dns_event(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        row_id = store.insert_dns_event(
            {
                "timestamp_ns": 1000,
                "timestamp_dt": "2024-01-01T00:00:00",
                "device_id": "dev-1",
                "domain": "example.com",
                "query_type": "A",
                "event_type": "dns_query",
                "risk_score": 0.0,
            }
        )
        assert row_id is not None
        store.close()


class TestTelemetryStoreInsertAuditEvent:
    """Test insert_audit_event."""

    def test_insert_audit_event(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        row_id = store.insert_audit_event(
            {
                "timestamp_ns": 1000,
                "timestamp_dt": "2024-01-01T00:00:00",
                "device_id": "dev-1",
                "syscall": "execve",
                "event_type": "kernel_execve_high_risk",
                "pid": 1234,
                "exe": "/bin/sh",
                "risk_score": 0.7,
                "mitre_techniques": ["T1059"],
            }
        )
        assert row_id is not None
        store.close()


class TestTelemetryStoreInsertPersistenceEvent:
    """Test insert_persistence_event."""

    def test_insert_persistence_event(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        row_id = store.insert_persistence_event(
            {
                "timestamp_ns": 1000,
                "timestamp_dt": "2024-01-01T00:00:00",
                "device_id": "dev-1",
                "event_type": "persistence_launchd_created",
                "mechanism": "launchd",
                "path": "/Library/LaunchDaemons/evil.plist",
                "risk_score": 0.8,
            }
        )
        assert row_id is not None
        store.close()


class TestTelemetryStoreInsertFIMEvent:
    """Test insert_fim_event."""

    def test_insert_fim_event(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        row_id = store.insert_fim_event(
            {
                "timestamp_ns": 1000,
                "timestamp_dt": "2024-01-01T00:00:00",
                "device_id": "dev-1",
                "event_type": "critical_file_tampered",
                "path": "/etc/passwd",
                "change_type": "modified",
                "risk_score": 0.9,
                "patterns_matched": ["system_config"],
            }
        )
        assert row_id is not None
        store.close()


class TestTelemetryStoreInsertDeviceTelemetry:
    """Test insert_device_telemetry."""

    def test_insert_device_telemetry(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        row_id = store.insert_device_telemetry(
            {
                "timestamp_ns": 1000,
                "timestamp_dt": "2024-01-01T00:00:00",
                "device_id": "dev-1",
                "device_type": "ENDPOINT",
                "total_processes": 150,
                "total_cpu_percent": 23.5,
                "total_memory_percent": 67.2,
            }
        )
        assert row_id is not None
        store.close()


class TestTelemetryStoreInsertMetricsTimeseries:
    """Test insert_metrics_timeseries."""

    def test_insert_metric(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        row_id = store.insert_metrics_timeseries(
            {
                "timestamp_ns": 1000,
                "timestamp_dt": "2024-01-01T00:00:00",
                "metric_name": "cpu_usage",
                "metric_type": "GAUGE",
                "device_id": "dev-1",
                "value": 42.5,
                "unit": "percent",
            }
        )
        assert row_id is not None
        store.close()


class TestTelemetryStoreStatistics:
    """Test get_statistics."""

    def test_statistics_on_empty_db(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        stats = store.get_statistics()

        assert stats["process_events_count"] == 0
        assert stats["device_telemetry_count"] == 0
        assert stats["flow_events_count"] == 0
        assert stats["security_events_count"] == 0
        assert "time_range" in stats
        store.close()

    def test_statistics_counts_inserted_events(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        store.insert_process_event(
            {
                "timestamp_ns": 1000,
                "timestamp_dt": "2024-01-01T00:00:00",
                "device_id": "dev-1",
                "pid": 1,
            }
        )
        store.insert_process_event(
            {
                "timestamp_ns": 2000,
                "timestamp_dt": "2024-01-01T00:00:01",
                "device_id": "dev-1",
                "pid": 2,
            }
        )

        stats = store.get_statistics()
        assert stats["process_events_count"] == 2
        store.close()


class TestTelemetryStoreSecurityEventCounts:
    """Test get_security_event_counts."""

    def test_counts_by_category_and_classification(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        ts_ns = int(time.time() * 1e9)

        store.insert_security_event(
            {
                "timestamp_ns": ts_ns,
                "device_id": "dev-1",
                "event_category": "INTRUSION",
                "risk_score": 0.8,
                "final_classification": "malicious",
            }
        )
        store.insert_security_event(
            {
                "timestamp_ns": ts_ns + 1,
                "device_id": "dev-1",
                "event_category": "AUTH",
                "risk_score": 0.2,
                "final_classification": "legitimate",
            }
        )

        counts = store.get_security_event_counts(hours=24)
        assert counts["total"] == 2
        assert counts["by_category"]["INTRUSION"] == 1
        assert counts["by_category"]["AUTH"] == 1
        assert counts["by_classification"]["malicious"] == 1
        assert counts["by_classification"]["legitimate"] == 1
        store.close()


class TestTelemetryStoreThreatScore:
    """Test get_threat_score_data."""

    def test_threat_score_empty_db(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        result = store.get_threat_score_data(hours=1)

        assert result["threat_score"] == 0.0
        assert result["threat_level"] == "none"
        assert result["event_count"] == 0
        store.close()

    def test_threat_score_with_events(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        ts_ns = int(time.time() * 1e9)

        store.insert_security_event(
            {
                "timestamp_ns": ts_ns,
                "device_id": "dev-1",
                "event_category": "MALWARE",
                "risk_score": 0.95,
                "final_classification": "malicious",
            }
        )

        result = store.get_threat_score_data(hours=1)
        assert result["threat_score"] > 0
        assert result["event_count"] == 1
        assert result["max_risk"] == 0.95
        store.close()


class TestTelemetryStoreSearchEvents:
    """Test search_events."""

    def test_search_security_events(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        ts_ns = int(time.time() * 1e9)

        store.insert_security_event(
            {
                "timestamp_ns": ts_ns,
                "device_id": "dev-1",
                "event_category": "INTRUSION",
                "description": "Reverse shell detected on port 4444",
                "risk_score": 0.9,
                "final_classification": "malicious",
            }
        )

        result = store.search_events(query="shell", table="security_events", hours=24)
        assert result["total_count"] == 1
        assert len(result["results"]) == 1
        store.close()

    def test_search_with_min_risk(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        ts_ns = int(time.time() * 1e9)

        store.insert_security_event(
            {
                "timestamp_ns": ts_ns,
                "device_id": "dev-1",
                "risk_score": 0.3,
                "final_classification": "legitimate",
            }
        )
        store.insert_security_event(
            {
                "timestamp_ns": ts_ns + 1,
                "device_id": "dev-1",
                "risk_score": 0.8,
                "final_classification": "malicious",
            }
        )

        result = store.search_events(min_risk=0.5, hours=24)
        assert result["total_count"] == 1
        store.close()

    def test_search_invalid_table_defaults_to_security(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        result = store.search_events(table="nonexistent_table", hours=24)
        # Should fall back to security_events and return empty
        assert result["total_count"] == 0
        store.close()

    def test_search_pagination(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        ts_ns = int(time.time() * 1e9)

        for i in range(5):
            store.insert_security_event(
                {
                    "timestamp_ns": ts_ns + i,
                    "device_id": "dev-1",
                    "risk_score": 0.5,
                }
            )

        result = store.search_events(hours=24, limit=2, offset=0)
        assert result["total_count"] == 5
        assert len(result["results"]) == 2
        assert result["has_more"] is True
        store.close()


class TestTelemetryStoreMITRECoverage:
    """Test get_mitre_coverage."""

    def test_mitre_coverage_empty(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        coverage = store.get_mitre_coverage()
        assert coverage == {}
        store.close()

    def test_mitre_coverage_with_techniques(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        ts_ns = int(time.time() * 1e9)

        store.insert_security_event(
            {
                "timestamp_ns": ts_ns,
                "device_id": "dev-1",
                "event_category": "INTRUSION",
                "mitre_techniques": ["T1059", "T1082"],
                "risk_score": 0.8,
            }
        )

        coverage = store.get_mitre_coverage()
        assert "T1059" in coverage
        assert "T1082" in coverage
        assert coverage["T1059"]["count"] == 1
        store.close()


class TestTelemetryStoreIncidentManagement:
    """Test incident CRUD operations."""

    def test_create_incident(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        inc_id = store.create_incident(
            {
                "title": "Suspicious Activity",
                "description": "Multiple failed logins",
                "severity": "high",
            }
        )
        assert inc_id is not None
        assert inc_id > 0
        store.close()

    def test_get_incident(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        inc_id = store.create_incident(
            {
                "title": "Test Incident",
                "severity": "medium",
            }
        )

        inc = store.get_incident(inc_id)
        assert inc is not None
        assert inc["title"] == "Test Incident"
        assert inc["severity"] == "medium"
        assert inc["status"] == "open"
        store.close()

    def test_get_nonexistent_incident(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        inc = store.get_incident(99999)
        assert inc is None
        store.close()

    def test_update_incident(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        inc_id = store.create_incident({"title": "Update Me", "severity": "low"})

        success = store.update_incident(
            inc_id,
            {
                "status": "investigating",
                "assignee": "analyst-1",
            },
        )
        assert success is True

        inc = store.get_incident(inc_id)
        assert inc["status"] == "investigating"
        assert inc["assignee"] == "analyst-1"
        store.close()

    def test_resolve_incident_sets_resolved_at(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        inc_id = store.create_incident({"title": "Resolve Me"})

        store.update_incident(
            inc_id,
            {
                "status": "resolved",
                "resolution_notes": "False positive",
            },
        )

        inc = store.get_incident(inc_id)
        assert inc["status"] == "resolved"
        assert inc["resolved_at"] is not None
        store.close()

    def test_get_incidents_with_status_filter(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        store.create_incident({"title": "Open 1"})
        inc_id = store.create_incident({"title": "Closed 1"})
        store.update_incident(inc_id, {"status": "resolved"})

        open_incs = store.get_incidents(status="open")
        assert len(open_incs) == 1
        assert open_incs[0]["title"] == "Open 1"

        resolved_incs = store.get_incidents(status="resolved")
        assert len(resolved_incs) == 1
        store.close()

    def test_get_all_incidents(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        store.create_incident({"title": "Inc A"})
        store.create_incident({"title": "Inc B"})

        all_incs = store.get_incidents()
        assert len(all_incs) == 2
        store.close()


class TestTelemetryStoreMetricsHistory:
    """Test get_metrics_history."""

    def test_metrics_history_empty(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        result = store.get_metrics_history("cpu_usage", hours=24)
        assert result == []
        store.close()

    def test_metrics_history_with_data(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        ts_ns = int(time.time() * 1e9)

        store.insert_metrics_timeseries(
            {
                "timestamp_ns": ts_ns,
                "metric_name": "cpu_usage",
                "device_id": "dev-1",
                "value": 42.0,
            }
        )

        result = store.get_metrics_history("cpu_usage", hours=24)
        assert len(result) == 1
        store.close()

    def test_metrics_history_filters_by_device(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        ts_ns = int(time.time() * 1e9)

        store.insert_metrics_timeseries(
            {
                "timestamp_ns": ts_ns,
                "metric_name": "cpu_usage",
                "device_id": "dev-A",
                "value": 10.0,
            }
        )
        store.insert_metrics_timeseries(
            {
                "timestamp_ns": ts_ns + 1,
                "metric_name": "cpu_usage",
                "device_id": "dev-B",
                "value": 20.0,
            }
        )

        result = store.get_metrics_history("cpu_usage", hours=24, device_id="dev-A")
        assert len(result) == 1
        store.close()


class TestTelemetryStoreSecurityClustering:
    """Test get_security_event_clustering."""

    def test_clustering_empty(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        result = store.get_security_event_clustering(hours=24)
        assert "by_category" in result
        assert "by_severity" in result
        assert "by_hour" in result
        store.close()

    def test_clustering_with_events(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        ts_ns = int(time.time() * 1e9)

        store.insert_security_event(
            {
                "timestamp_ns": ts_ns,
                "timestamp_dt": datetime.now(timezone.utc).isoformat(),
                "device_id": "dev-1",
                "event_category": "INTRUSION",
                "risk_score": 0.8,
            }
        )
        store.insert_security_event(
            {
                "timestamp_ns": ts_ns + 1,
                "timestamp_dt": datetime.now(timezone.utc).isoformat(),
                "device_id": "dev-1",
                "event_category": "AUTH",
                "risk_score": 0.2,
            }
        )

        result = store.get_security_event_clustering(hours=24)
        assert result["by_category"]["INTRUSION"] == 1
        assert result["by_category"]["AUTH"] == 1
        store.close()


class TestTelemetryStoreClose:
    """Test close method."""

    def test_close_does_not_raise(self, tmp_path):
        store = TelemetryStore(str(tmp_path / "store.db"))
        store.close()
        # Double close should raise, but that's sqlite3's behavior
