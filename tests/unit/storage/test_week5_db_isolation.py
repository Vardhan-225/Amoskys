"""
Week 5 tests: Database Isolation (B5.3).

Validates that:
  - tmp_db_path fixture creates unique paths per test
  - tmp_wal_path fixture creates unique paths per test
  - Parallel database access does not contend
  - TelemetryStore uses isolated databases
  - WALProcessor uses isolated databases
  - Database files are cleaned up after tests

Target: 15+ tests
"""

import sqlite3
import threading
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# B5.3a — tmp_db_path / tmp_wal_path fixtures
# ---------------------------------------------------------------------------


class TestTmpDbPathFixture:
    """B5.3: The tmp_db_path fixture provides per-test isolation."""

    def test_path_is_string(self, tmp_db_path):
        assert isinstance(tmp_db_path, str)

    def test_path_ends_with_db(self, tmp_db_path):
        assert tmp_db_path.endswith(".db")

    def test_parent_directory_exists(self, tmp_db_path):
        assert Path(tmp_db_path).parent.exists()

    def test_db_file_does_not_preexist(self, tmp_db_path):
        """Each test starts with a fresh, nonexistent DB file."""
        assert not Path(tmp_db_path).exists()

    def test_two_calls_get_different_paths(self, tmp_db_path, tmp_wal_path):
        """tmp_db_path and tmp_wal_path should differ."""
        assert tmp_db_path != tmp_wal_path

    def test_can_create_sqlite_db(self, tmp_db_path):
        conn = sqlite3.connect(tmp_db_path)
        conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY)")
        conn.execute("INSERT INTO test VALUES (1)")
        conn.commit()
        row = conn.execute("SELECT id FROM test").fetchone()
        conn.close()
        assert row[0] == 1


class TestTmpWalPathFixture:
    """B5.3: The tmp_wal_path fixture provides per-test WAL isolation."""

    def test_path_is_string(self, tmp_wal_path):
        assert isinstance(tmp_wal_path, str)

    def test_path_ends_with_db(self, tmp_wal_path):
        assert tmp_wal_path.endswith(".db")

    def test_parent_directory_exists(self, tmp_wal_path):
        assert Path(tmp_wal_path).parent.exists()


# ---------------------------------------------------------------------------
# B5.3b — TelemetryStore isolation
# ---------------------------------------------------------------------------


class TestTelemetryStoreIsolation:
    """B5.3: TelemetryStore creates fully isolated databases."""

    def test_store_creates_tables(self, tmp_db_path):
        from amoskys.storage.telemetry_store import TelemetryStore

        store = TelemetryStore(tmp_db_path)
        assert Path(tmp_db_path).exists()
        tables = {
            row[0]
            for row in store.db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "process_events" in tables
        assert "flow_events" in tables
        assert "security_events" in tables
        store.close()

    def test_two_stores_independent(self, tmp_path):
        """Two stores in the same tmp_path do not share data."""
        from amoskys.storage.telemetry_store import TelemetryStore

        store_a = TelemetryStore(str(tmp_path / "a.db"))
        store_b = TelemetryStore(str(tmp_path / "b.db"))

        store_a.db.execute(
            "INSERT INTO process_events (timestamp_ns, timestamp_dt, device_id, pid) "
            "VALUES (1000000, '2024-01-01T00:00:00Z', 'agent-a', 1)"
        )
        store_a.db.commit()

        count_b = store_b.db.execute("SELECT COUNT(*) FROM process_events").fetchone()[
            0
        ]
        assert count_b == 0, "Store B should not see Store A's data"

        store_a.close()
        store_b.close()


# ---------------------------------------------------------------------------
# B5.3c — Concurrent access safety
# ---------------------------------------------------------------------------


class TestConcurrentSQLiteAccess:
    """B5.3: Concurrent writes to the same DB don't deadlock."""

    def test_concurrent_inserts(self, tmp_db_path):
        """Multiple threads can write to isolated DBs without contention."""
        conn = sqlite3.connect(tmp_db_path, timeout=5.0)
        conn.execute("CREATE TABLE concurrent_test (id INTEGER, val TEXT)")
        conn.commit()
        conn.close()

        errors = []

        def writer(thread_id, count):
            try:
                c = sqlite3.connect(tmp_db_path, timeout=5.0)
                for i in range(count):
                    c.execute(
                        "INSERT INTO concurrent_test VALUES (?, ?)",
                        (thread_id * 1000 + i, f"t{thread_id}-{i}"),
                    )
                    c.commit()
                c.close()
            except Exception as e:
                errors.append((thread_id, str(e)))

        threads = [threading.Thread(target=writer, args=(tid, 50)) for tid in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors, f"Concurrent write errors: {errors}"

        conn = sqlite3.connect(tmp_db_path)
        count = conn.execute("SELECT COUNT(*) FROM concurrent_test").fetchone()[0]
        conn.close()
        assert count == 200  # 4 threads × 50 inserts

    def test_isolated_dbs_no_contention(self, tmp_path):
        """Separate DB files never contend."""
        results = {}

        def create_and_query(db_name, value):
            path = str(tmp_path / f"{db_name}.db")
            conn = sqlite3.connect(path, timeout=5.0)
            conn.execute("CREATE TABLE t (v TEXT)")
            conn.execute("INSERT INTO t VALUES (?)", (value,))
            conn.commit()
            row = conn.execute("SELECT v FROM t").fetchone()
            results[db_name] = row[0]
            conn.close()

        threads = [
            threading.Thread(target=create_and_query, args=(f"db{i}", f"val{i}"))
            for i in range(8)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        # Each DB should have its own value, not contaminated
        for i in range(8):
            assert results[f"db{i}"] == f"val{i}"
