"""
Tests for amoskys.intel.ingest

Covers:
  - TelemetryIngestor initialization and configuration
  - _read_events_from_queue: DB polling, deduplication, error handling
  - _read_events_from_wal: WAL polling, envelope parsing, error handling
  - _convert_to_event_views: Protobuf to TelemetryEventView conversion
  - poll_once: Full polling cycle across all sources, metrics, cleanup
  - Source type routing (queue vs WAL based on path)
  - Error handling for missing/corrupt databases
"""

import sqlite3
import struct
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

from amoskys.intel.models import TelemetryEventView

# ── Helpers ──────────────────────────────────────────────────────────


def _now_ns() -> int:
    return int(time.time() * 1e9)


@pytest.fixture
def mock_fusion_engine(tmp_path):
    """Create a mock FusionEngine that won't touch real DB."""
    engine = MagicMock()
    engine.add_event = MagicMock()
    engine.device_state = {}
    return engine


@pytest.fixture
def ingestor(mock_fusion_engine, tmp_path):
    """Create TelemetryIngestor with mock engine and tmp sources."""
    from amoskys.intel.ingest import TelemetryIngestor

    sources = [
        str(tmp_path / "queue" / "proc_agent.db"),
        str(tmp_path / "wal" / "flowagent.db"),
    ]
    return TelemetryIngestor(
        fusion_engine=mock_fusion_engine,
        agent_sources=sources,
        poll_interval=5,
    )


# ═══════════════════════════════════════════════════════════════════
# TelemetryIngestor Initialization
# ═══════════════════════════════════════════════════════════════════


class TestIngestorInit:
    """Test TelemetryIngestor construction and defaults."""

    def test_init_default_sources(self, mock_fusion_engine):
        from amoskys.intel.ingest import TelemetryIngestor

        ingestor = TelemetryIngestor(fusion_engine=mock_fusion_engine)
        assert len(ingestor.agent_sources) == 4
        assert any("proc_agent" in s for s in ingestor.agent_sources)
        assert any("auth_agent" in s for s in ingestor.agent_sources)

    def test_init_custom_sources(self, mock_fusion_engine):
        from amoskys.intel.ingest import TelemetryIngestor

        custom = ["/custom/path1.db", "/custom/path2.db"]
        ingestor = TelemetryIngestor(
            fusion_engine=mock_fusion_engine,
            agent_sources=custom,
        )
        assert ingestor.agent_sources == custom

    def test_init_poll_interval(self, mock_fusion_engine):
        from amoskys.intel.ingest import TelemetryIngestor

        ingestor = TelemetryIngestor(
            fusion_engine=mock_fusion_engine,
            poll_interval=30,
        )
        assert ingestor.poll_interval == 30

    def test_init_default_poll_interval(self, mock_fusion_engine):
        from amoskys.intel.ingest import TelemetryIngestor

        ingestor = TelemetryIngestor(fusion_engine=mock_fusion_engine)
        assert ingestor.poll_interval == 10

    def test_init_tracking_sets(self, ingestor):
        """Per-source tracking sets initialized for each source."""
        assert len(ingestor.last_seen_ids) == 2
        for source_ids in ingestor.last_seen_ids.values():
            assert isinstance(source_ids, set)
            assert len(source_ids) == 0

    def test_init_metrics_zero(self, ingestor):
        assert ingestor.events_ingested == 0
        assert ingestor.last_ingest_time is None


# ═══════════════════════════════════════════════════════════════════
# _read_events_from_queue
# ═══════════════════════════════════════════════════════════════════


class TestReadEventsFromQueue:
    """Test reading telemetry from LocalQueue databases."""

    def test_missing_db_returns_empty(self, ingestor):
        """Non-existent queue DB returns empty list."""
        result = ingestor._read_events_from_queue("/nonexistent/queue.db")
        assert result == []

    def test_empty_queue_returns_empty(self, ingestor, tmp_path):
        """Queue with no rows returns empty."""
        db_path = str(tmp_path / "empty_queue.db")
        conn = sqlite3.connect(db_path)
        conn.execute(
            """
            CREATE TABLE queue (
                id INTEGER PRIMARY KEY,
                idem TEXT UNIQUE,
                ts_ns INTEGER,
                bytes BLOB,
                retries INTEGER
            )
        """
        )
        conn.close()
        # Need to add this path to last_seen_ids
        ingestor.last_seen_ids[db_path] = set()
        result = ingestor._read_events_from_queue(db_path)
        assert result == []

    def test_duplicate_events_skipped(self, ingestor, tmp_path):
        """Events already in last_seen_ids should be skipped."""
        db_path = str(tmp_path / "dedup_queue.db")
        conn = sqlite3.connect(db_path)
        conn.execute(
            """
            CREATE TABLE queue (
                id INTEGER PRIMARY KEY,
                idem TEXT UNIQUE,
                ts_ns INTEGER,
                bytes BLOB,
                retries INTEGER
            )
        """
        )
        now_ns = _now_ns()
        conn.execute(
            "INSERT INTO queue (idem, ts_ns, bytes, retries) VALUES (?, ?, ?, ?)",
            ("already-seen", now_ns, b"\x00", 0),
        )
        conn.commit()
        conn.close()

        # Pre-mark as seen
        ingestor.last_seen_ids[db_path] = {"already-seen"}
        result = ingestor._read_events_from_queue(db_path)
        assert result == []

    def test_corrupt_protobuf_handled(self, ingestor, tmp_path):
        """Corrupt protobuf bytes should be caught and logged, not crash."""
        db_path = str(tmp_path / "corrupt_queue.db")
        conn = sqlite3.connect(db_path)
        conn.execute(
            """
            CREATE TABLE queue (
                id INTEGER PRIMARY KEY,
                idem TEXT UNIQUE,
                ts_ns INTEGER,
                bytes BLOB,
                retries INTEGER
            )
        """
        )
        now_ns = _now_ns()
        conn.execute(
            "INSERT INTO queue (idem, ts_ns, bytes, retries) VALUES (?, ?, ?, ?)",
            ("corrupt-event", now_ns, b"\xff\xfe\xfd\x00invalid", 0),
        )
        conn.commit()
        conn.close()

        ingestor.last_seen_ids[db_path] = set()
        result = ingestor._read_events_from_queue(db_path)
        # The corrupt event should be skipped
        assert result == []

    def test_locked_db_returns_empty(self, ingestor, tmp_path):
        """Locked database should be handled gracefully."""
        db_path = str(tmp_path / "locked_queue.db")
        conn = sqlite3.connect(db_path)
        conn.execute(
            """
            CREATE TABLE queue (
                id INTEGER PRIMARY KEY,
                idem TEXT UNIQUE,
                ts_ns INTEGER,
                bytes BLOB,
                retries INTEGER
            )
        """
        )
        conn.close()

        ingestor.last_seen_ids[db_path] = set()

        # Simulate locked DB by patching sqlite3.connect to raise
        with patch(
            "amoskys.intel.ingest.sqlite3.connect",
            side_effect=sqlite3.OperationalError("database is locked"),
        ):
            result = ingestor._read_events_from_queue(db_path)
        assert result == []


# ═══════════════════════════════════════════════════════════════════
# _read_events_from_wal
# ═══════════════════════════════════════════════════════════════════


class TestReadEventsFromWAL:
    """Test reading telemetry from WAL databases."""

    def test_missing_wal_returns_empty(self, ingestor):
        """Non-existent WAL DB returns empty list."""
        result = ingestor._read_events_from_wal("/nonexistent/wal.db")
        assert result == []

    def test_empty_wal_returns_empty(self, ingestor, tmp_path):
        """WAL with no rows returns empty."""
        db_path = str(tmp_path / "empty_wal.db")
        conn = sqlite3.connect(db_path)
        conn.execute(
            """
            CREATE TABLE wal (
                id INTEGER PRIMARY KEY,
                idem TEXT UNIQUE,
                ts_ns INTEGER,
                bytes BLOB,
                checksum BLOB
            )
        """
        )
        conn.close()
        ingestor.last_seen_ids[db_path] = set()
        result = ingestor._read_events_from_wal(db_path)
        assert result == []

    def test_corrupt_wal_entry_handled(self, ingestor, tmp_path):
        """Corrupt WAL entries should be skipped gracefully."""
        db_path = str(tmp_path / "corrupt_wal.db")
        conn = sqlite3.connect(db_path)
        conn.execute(
            """
            CREATE TABLE wal (
                id INTEGER PRIMARY KEY,
                idem TEXT UNIQUE,
                ts_ns INTEGER,
                bytes BLOB,
                checksum BLOB
            )
        """
        )
        now_ns = _now_ns()
        conn.execute(
            "INSERT INTO wal (idem, ts_ns, bytes, checksum) VALUES (?, ?, ?, ?)",
            ("corrupt-wal", now_ns, b"\xff\xfe\xfd\x00invalid", b""),
        )
        conn.commit()
        conn.close()

        ingestor.last_seen_ids[db_path] = set()
        result = ingestor._read_events_from_wal(db_path)
        assert result == []

    def test_duplicate_wal_events_skipped(self, ingestor, tmp_path):
        """Already-seen WAL events should be skipped."""
        db_path = str(tmp_path / "dedup_wal.db")
        conn = sqlite3.connect(db_path)
        conn.execute(
            """
            CREATE TABLE wal (
                id INTEGER PRIMARY KEY,
                idem TEXT UNIQUE,
                ts_ns INTEGER,
                bytes BLOB,
                checksum BLOB
            )
        """
        )
        now_ns = _now_ns()
        conn.execute(
            "INSERT INTO wal (idem, ts_ns, bytes, checksum) VALUES (?, ?, ?, ?)",
            ("already-seen-wal", now_ns, b"\x00", b""),
        )
        conn.commit()
        conn.close()

        ingestor.last_seen_ids[db_path] = {"already-seen-wal"}
        result = ingestor._read_events_from_wal(db_path)
        assert result == []


# ═══════════════════════════════════════════════════════════════════
# _convert_to_event_views
# ═══════════════════════════════════════════════════════════════════


class TestConvertToEventViews:
    """Test protobuf to TelemetryEventView conversion."""

    def test_convert_empty_device_telemetry(self, ingestor):
        """DeviceTelemetry with no events should return empty list."""
        from amoskys.proto import universal_telemetry_pb2 as tpb

        dt = tpb.DeviceTelemetry()
        dt.device_id = "test-dev"
        result = ingestor._convert_to_event_views(dt)
        assert result == []

    def test_convert_single_metric_event(self, ingestor):
        """Single metric event should convert to one TelemetryEventView."""
        from amoskys.proto import universal_telemetry_pb2 as tpb

        dt = tpb.DeviceTelemetry()
        dt.device_id = "test-dev"
        ev = dt.events.add()
        ev.event_id = "evt-001"
        ev.event_type = "METRIC"
        ev.severity = "INFO"
        ev.event_timestamp_ns = _now_ns()
        ev.metric_data.metric_name = "cpu_usage"
        ev.metric_data.numeric_value = 42.5

        result = ingestor._convert_to_event_views(dt)
        assert len(result) == 1
        assert result[0].event_id == "evt-001"
        assert result[0].device_id == "test-dev"
        assert result[0].event_type == "METRIC"

    def test_convert_multiple_events(self, ingestor):
        """Multiple events should each produce a TelemetryEventView."""
        from amoskys.proto import universal_telemetry_pb2 as tpb

        dt = tpb.DeviceTelemetry()
        dt.device_id = "test-dev"
        for i in range(3):
            ev = dt.events.add()
            ev.event_id = f"evt-{i}"
            ev.event_type = "METRIC"
            ev.severity = "INFO"
            ev.event_timestamp_ns = _now_ns()

        result = ingestor._convert_to_event_views(dt)
        assert len(result) == 3

    def test_convert_error_in_single_event_skips_it(self, ingestor):
        """If one event fails to convert, others should still succeed."""
        from amoskys.proto import universal_telemetry_pb2 as tpb

        dt = tpb.DeviceTelemetry()
        dt.device_id = "test-dev"

        # Good event
        ev1 = dt.events.add()
        ev1.event_id = "good-evt"
        ev1.event_type = "METRIC"
        ev1.severity = "INFO"
        ev1.event_timestamp_ns = _now_ns()

        # Add a second good event
        ev2 = dt.events.add()
        ev2.event_id = "good-evt-2"
        ev2.event_type = "METRIC"
        ev2.severity = "INFO"
        ev2.event_timestamp_ns = _now_ns()

        # Mock from_protobuf to fail on first, succeed on second
        call_count = 0
        original_from_protobuf = TelemetryEventView.from_protobuf

        def side_effect(pb_event, device_id):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ValueError("Bad event")
            return original_from_protobuf(pb_event, device_id)

        with patch.object(TelemetryEventView, "from_protobuf", side_effect=side_effect):
            result = ingestor._convert_to_event_views(dt)
        assert len(result) == 1


# ═══════════════════════════════════════════════════════════════════
# poll_once
# ═══════════════════════════════════════════════════════════════════


class TestPollOnce:
    """Test the main polling cycle."""

    def test_poll_once_no_sources_exist(self, ingestor):
        """Polling non-existent sources should return 0 events."""
        result = ingestor.poll_once()
        assert result == 0
        assert ingestor.events_ingested == 0

    def test_poll_once_routes_by_source_type(self, mock_fusion_engine):
        """Sources with 'wal' in path should use WAL reader, others use queue reader."""
        from amoskys.intel.ingest import TelemetryIngestor

        # Use explicit absolute paths that avoid pytest tmp_path name contamination
        sources = [
            "/data/queue/proc_agent.db",
            "/data/flowagent_log/agent.db",  # No 'wal' -> queue
        ]
        ingestor = TelemetryIngestor(
            fusion_engine=mock_fusion_engine,
            agent_sources=sources,
            poll_interval=5,
        )
        with patch.object(
            ingestor, "_read_events_from_wal", return_value=[]
        ) as mock_read_wal:
            with patch.object(
                ingestor, "_read_events_from_queue", return_value=[]
            ) as mock_read_queue:
                ingestor.poll_once()
                # Both sources have no "wal" in the path, both should use queue
                assert mock_read_queue.call_count == 2
                assert mock_read_wal.call_count == 0

    def test_poll_once_routes_mixed_source_types(self, mock_fusion_engine):
        """Verify WAL vs queue routing based on 'wal' substring in source path."""
        from amoskys.intel.ingest import TelemetryIngestor

        sources = [
            "/data/queue/proc_agent.db",  # No 'wal' -> queue
            "/data/wal/flowagent.db",  # Has 'wal' -> WAL reader
        ]
        ingestor = TelemetryIngestor(
            fusion_engine=mock_fusion_engine,
            agent_sources=sources,
            poll_interval=5,
        )
        with patch.object(
            ingestor, "_read_events_from_wal", return_value=[]
        ) as mock_read_wal:
            with patch.object(
                ingestor, "_read_events_from_queue", return_value=[]
            ) as mock_read_queue:
                ingestor.poll_once()
                assert mock_read_queue.call_count == 1
                assert mock_read_wal.call_count == 1

    def test_poll_once_updates_metrics(self, ingestor):
        """Metrics should be updated after poll."""
        ingestor.poll_once()
        assert ingestor.last_ingest_time is not None

    def test_poll_once_feeds_fusion_engine(self, ingestor, mock_fusion_engine):
        """Events should be fed to the fusion engine."""
        from amoskys.proto import universal_telemetry_pb2 as tpb

        dt = tpb.DeviceTelemetry()
        dt.device_id = "test-dev"
        ev = dt.events.add()
        ev.event_id = "evt-001"
        ev.event_type = "METRIC"
        ev.severity = "INFO"
        ev.event_timestamp_ns = _now_ns()

        with patch.object(ingestor, "_read_events_from_queue", return_value=[dt]):
            with patch.object(ingestor, "_read_events_from_wal", return_value=[]):
                count = ingestor.poll_once()

        assert count == 1
        assert mock_fusion_engine.add_event.call_count == 1
        assert ingestor.events_ingested == 1

    def test_poll_once_exception_per_source(self, ingestor):
        """Exception in one source should not stop processing others."""

        def queue_side_effect(path, limit=1000):
            if "proc_agent" in path:
                raise RuntimeError("DB corruption")
            return []

        with patch.object(
            ingestor, "_read_events_from_queue", side_effect=queue_side_effect
        ):
            with patch.object(ingestor, "_read_events_from_wal", return_value=[]):
                result = ingestor.poll_once()
        assert result == 0  # Should complete without raising

    def test_poll_once_cleanup_large_tracking_sets(self, ingestor):
        """last_seen_ids should be cleaned up when they grow too large."""
        source = ingestor.agent_sources[0]
        # Simulate a large tracking set
        ingestor.last_seen_ids[source] = {f"id-{i}" for i in range(15000)}

        ingestor.poll_once()

        # After cleanup, should be reduced
        assert len(ingestor.last_seen_ids[source]) <= 5000

    def test_poll_once_small_tracking_set_no_cleanup(self, ingestor):
        """Small tracking sets should not be cleaned up."""
        source = ingestor.agent_sources[0]
        ingestor.last_seen_ids[source] = {f"id-{i}" for i in range(100)}

        ingestor.poll_once()

        # Should remain unchanged
        assert len(ingestor.last_seen_ids[source]) == 100
