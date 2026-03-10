"""Hardening tests for WAL Component (wal_sqlite.py).

Covers P1-EB-2: BLAKE2b checksums verified on drain.
"""

import hashlib
import sqlite3
from types import SimpleNamespace

import pytest

from amoskys.proto import messaging_schema_pb2 as pb
from amoskys.storage.wal_sqlite import SQLiteWAL

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_env(idem="k1", ts=1):
    flow = pb.FlowEvent(
        src_ip="1.1.1.1",
        dst_ip="8.8.8.8",
        src_port=1,
        dst_port=53,
        protocol="UDP",
        bytes_sent=10,
        bytes_recv=20,
        flags=0,
        start_time=1,
        end_time=2,
        bytes_tx=1,
        bytes_rx=2,
        proto="UDP",
        duration_ms=3,
    )
    return pb.Envelope(
        version="v1", ts_ns=ts, idempotency_key=idem, flow=flow, sig=b"", prev_sig=b""
    )


def pub_ok(env):
    return SimpleNamespace(status=pb.PublishAck.OK)


# ---------------------------------------------------------------------------
# Checksum Computation Tests
# ---------------------------------------------------------------------------


class TestChecksumComputation:
    """P1-EB-2: append() must store real BLAKE2b checksum, not raw data."""

    def test_append_stores_blake2b_checksum(self, tmp_path):
        """Checksum in WAL is 32-byte BLAKE2b, not raw data copy."""
        wal = SQLiteWAL(path=str(tmp_path / "wal.db"), max_bytes=10_000_000)
        env = make_env("cs-test", 1)
        wal.append(env)

        # Read raw checksum from database
        row = wal.db.execute(
            "SELECT bytes, checksum FROM wal WHERE idem='cs-test'"
        ).fetchone()
        blob, stored_checksum = row
        stored_bytes = bytes(stored_checksum)

        # Must be exactly 32 bytes (BLAKE2b digest_size=32)
        assert len(stored_bytes) == 32

        # Must match BLAKE2b of the blob
        expected = hashlib.blake2b(bytes(blob), digest_size=32).digest()
        assert stored_bytes == expected

    def test_checksum_is_not_raw_data(self, tmp_path):
        """Checksum must NOT be a copy of the raw serialized data."""
        wal = SQLiteWAL(path=str(tmp_path / "wal.db"), max_bytes=10_000_000)
        env = make_env("raw-check", 1)
        wal.append(env)

        row = wal.db.execute(
            "SELECT bytes, checksum FROM wal WHERE idem='raw-check'"
        ).fetchone()
        blob, stored_checksum = row

        # Checksum should NOT equal the raw bytes (it's a hash, not a copy)
        assert bytes(stored_checksum) != bytes(blob)

    def test_different_data_different_checksums(self, tmp_path):
        """Different envelopes produce different checksums."""
        wal = SQLiteWAL(path=str(tmp_path / "wal.db"), max_bytes=10_000_000)
        wal.append(make_env("a", 1))
        wal.append(make_env("b", 2))

        rows = wal.db.execute("SELECT checksum FROM wal ORDER BY id").fetchall()
        assert len(rows) == 2
        assert bytes(rows[0][0]) != bytes(rows[1][0])


# ---------------------------------------------------------------------------
# Checksum Verification on Drain Tests
# ---------------------------------------------------------------------------


class TestChecksumVerification:
    """P1-EB-2: drain() must verify BLAKE2b before publishing."""

    def test_drain_succeeds_with_valid_checksum(self, tmp_path):
        """Normal append+drain works with correct checksums."""
        wal = SQLiteWAL(path=str(tmp_path / "wal.db"), max_bytes=10_000_000)
        wal.append(make_env("valid1", 1))
        wal.append(make_env("valid2", 2))

        drained = wal.drain(pub_ok, limit=10)
        assert drained == 2
        assert wal.backlog_bytes() == 0

    def test_drain_quarantines_corrupt_entry(self, tmp_path):
        """Corrupt blob detected and quarantined (deleted without publish)."""
        wal = SQLiteWAL(path=str(tmp_path / "wal.db"), max_bytes=10_000_000)
        wal.append(make_env("good", 1))
        wal.append(make_env("bad", 2))

        # Corrupt the second entry's bytes
        row = wal.db.execute("SELECT id FROM wal WHERE idem='bad'").fetchone()
        wal.db.execute(
            "UPDATE wal SET bytes = ? WHERE id = ?",
            (b"CORRUPTED_DATA_HERE", row[0]),
        )

        published = []

        def pub_tracking(env):
            published.append(env.idempotency_key)
            return SimpleNamespace(status=pb.PublishAck.OK)

        drained = wal.drain(pub_tracking, limit=10)
        # "good" was published, "bad" was quarantined (deleted without publish)
        assert drained == 2  # Both removed from WAL
        assert "good" in published
        assert "bad" not in published
        assert wal.backlog_bytes() == 0

    def test_drain_handles_legacy_checksum(self, tmp_path):
        """Legacy entries with non-32-byte checksum are skipped (deleted, not published)."""
        wal = SQLiteWAL(path=str(tmp_path / "wal.db"), max_bytes=10_000_000)
        env = make_env("legacy", 1)
        data = env.SerializeToString()

        # Manually insert with legacy-style "checksum" (raw data, not BLAKE2b)
        wal.db.execute(
            "INSERT INTO wal(idem, ts_ns, bytes, checksum) VALUES(?,?,?,?)",
            ("legacy", 1, sqlite3.Binary(data), sqlite3.Binary(data)),
        )

        published = []

        def pub_tracking(env):
            published.append(env.idempotency_key)
            return SimpleNamespace(status=pb.PublishAck.OK)

        drained = wal.drain(pub_tracking, limit=10)
        # Legacy entries are drained from WAL but NOT published
        assert drained == 1
        assert "legacy" not in published
        assert wal.backlog_bytes() == 0

    def test_multiple_entries_one_corrupt(self, tmp_path):
        """Mix of valid and corrupt: valid published, corrupt quarantined."""
        wal = SQLiteWAL(path=str(tmp_path / "wal.db"), max_bytes=10_000_000)
        wal.append(make_env("first", 1))
        wal.append(make_env("middle", 2))
        wal.append(make_env("last", 3))

        # Corrupt the middle entry
        row = wal.db.execute("SELECT id FROM wal WHERE idem='middle'").fetchone()
        wal.db.execute(
            "UPDATE wal SET bytes = ? WHERE id = ?",
            (b"BAD", row[0]),
        )

        published = []

        def pub_tracking(env):
            published.append(env.idempotency_key)
            return SimpleNamespace(status=pb.PublishAck.OK)

        drained = wal.drain(pub_tracking, limit=10)
        assert drained == 3
        assert "first" in published
        assert "last" in published
        assert "middle" not in published

    def test_drain_selects_checksum_column(self):
        """drain() SELECT includes checksum column (structural check)."""
        import inspect

        source = inspect.getsource(SQLiteWAL.drain)
        assert "checksum" in source
        assert "SELECT id, bytes, checksum" in source


# ---------------------------------------------------------------------------
# Roundtrip Integration Tests
# ---------------------------------------------------------------------------


class TestAppendDrainRoundtrip:
    """Full append→drain cycle with checksum verification."""

    def test_roundtrip_preserves_data(self, tmp_path):
        """Append and drain roundtrip preserves envelope data."""
        wal = SQLiteWAL(path=str(tmp_path / "wal.db"), max_bytes=10_000_000)
        original = make_env("roundtrip", 42)
        wal.append(original)

        received = []

        def pub_capture(env):
            received.append(env)
            return SimpleNamespace(status=pb.PublishAck.OK)

        wal.drain(pub_capture, limit=1)
        assert len(received) == 1
        assert received[0].idempotency_key == "roundtrip"
        assert received[0].ts_ns == 42

    def test_backlog_enforcement_preserves_checksums(self, tmp_path):
        """After backpressure drops, remaining entries have valid checksums."""
        wal = SQLiteWAL(path=str(tmp_path / "wal.db"), max_bytes=1)  # Force tiny cap
        wal.append(make_env("overflow", 1))
        # Backlog enforcement may have dropped it

        # Whatever remains should have valid checksums
        rows = wal.db.execute("SELECT bytes, checksum FROM wal").fetchall()
        for blob, checksum in rows:
            expected = hashlib.blake2b(bytes(blob), digest_size=32).digest()
            assert bytes(checksum) == expected
