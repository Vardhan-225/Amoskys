"""Integration tests: Agent → LocalQueueAdapter → LocalQueue → SQLite pipeline.

Tests the end-to-end flow of agent data collection through the local queue,
ensuring proper envelope creation, content hashing, and persistence.

Pipeline:
  Agent.collect() → LocalQueueAdapter.enqueue() → LocalQueue.enqueue() → SQLite
"""

import hashlib
import sqlite3
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from amoskys.agents.common.local_queue import LocalQueue
from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.proto import universal_telemetry_pb2 as pb


@pytest.fixture
def tmp_queue_path(tmp_path):
    """Provide a temporary queue database path."""
    return str(tmp_path / "test_queue.db")


@pytest.fixture
def adapter(tmp_queue_path):
    """Create a fresh LocalQueueAdapter."""
    return LocalQueueAdapter(
        queue_path=tmp_queue_path,
        agent_name="test_agent",
        device_id="device_123",
        max_bytes=50 * 1024 * 1024,
        max_retries=10,
    )


@pytest.fixture
def test_telemetry():
    """Create a test DeviceTelemetry message."""
    return pb.DeviceTelemetry(
        device_id="device_123",
        device_type="HOST",
        protocol="TEST",
        timestamp_ns=int(time.time() * 1e9),
        collection_agent="test_agent",
    )


class TestAgentEnqueueCreatesSQLiteRow:
    """Test agent collection creates SQLite row via queue adapter."""

    def test_enqueue_creates_sqlite_entry(
        self, adapter, test_telemetry, tmp_queue_path
    ):
        """Verify enqueue creates a row in SQLite."""
        # Enqueue via adapter
        result = adapter.enqueue(test_telemetry)
        assert result is True

        # Verify SQLite row exists
        conn = sqlite3.connect(tmp_queue_path)
        cursor = conn.execute("SELECT COUNT(*) FROM queue")
        row_count = cursor.fetchone()[0]
        assert row_count == 1
        conn.close()

    def test_enqueue_stores_serialized_telemetry(
        self, adapter, test_telemetry, tmp_queue_path
    ):
        """Verify enqueued data matches original telemetry."""
        adapter.enqueue(test_telemetry)

        # Retrieve from SQLite
        conn = sqlite3.connect(tmp_queue_path)
        cursor = conn.execute("SELECT bytes FROM queue LIMIT 1")
        stored_bytes = cursor.fetchone()[0]
        conn.close()

        # Deserialize and compare
        retrieved = pb.DeviceTelemetry()
        retrieved.ParseFromString(stored_bytes)

        assert retrieved.device_id == test_telemetry.device_id
        assert retrieved.device_type == test_telemetry.device_type
        assert retrieved.protocol == test_telemetry.protocol


class TestEnvelopeRequiredFields:
    """Test that enqueued envelopes have required fields."""

    def test_envelope_has_agent_id(self, adapter, test_telemetry):
        """Verify envelope idempotency key contains agent_id."""
        adapter.enqueue(test_telemetry)

        # Verify through queue's internal state
        queue = adapter.queue
        cursor = queue.db.execute("SELECT idem FROM queue LIMIT 1")
        idem_key = cursor.fetchone()[0]

        assert "test_agent" in idem_key

    def test_envelope_has_device_id(self, adapter, test_telemetry):
        """Verify envelope idempotency key contains device_id."""
        adapter.enqueue(test_telemetry)

        queue = adapter.queue
        cursor = queue.db.execute("SELECT idem FROM queue LIMIT 1")
        idem_key = cursor.fetchone()[0]

        assert "device_123" in idem_key

    def test_envelope_has_timestamp_ns(self, adapter, test_telemetry):
        """Verify envelope has timestamp_ns set."""
        adapter.enqueue(test_telemetry)

        queue = adapter.queue
        cursor = queue.db.execute("SELECT ts_ns FROM queue LIMIT 1")
        ts_ns = cursor.fetchone()[0]

        assert ts_ns > 0
        assert ts_ns < int(time.time() * 1e9) + 1000000  # Sanity check


class TestContentHashPresent:
    """Test SHA-256 content hash is always computed."""

    def test_content_hash_set(self, adapter, test_telemetry):
        """Verify content_hash is stored for every enqueued event."""
        adapter.enqueue(test_telemetry)

        queue = adapter.queue
        cursor = queue.db.execute("SELECT content_hash FROM queue LIMIT 1")
        stored_hash = cursor.fetchone()[0]

        assert stored_hash is not None
        assert len(stored_hash) == 32  # SHA-256 = 32 bytes

    def test_content_hash_matches_payload(self, adapter, test_telemetry):
        """Verify content_hash is correct SHA-256 of payload."""
        adapter.enqueue(test_telemetry)

        # Get stored hash
        queue = adapter.queue
        cursor = queue.db.execute("SELECT content_hash, bytes FROM queue LIMIT 1")
        stored_hash, payload = cursor.fetchone()

        # Compute expected hash
        expected_hash = hashlib.sha256(payload).digest()

        assert stored_hash == expected_hash

    def test_different_payloads_different_hashes(self, adapter):
        """Verify different events produce different hashes."""
        telemetry1 = pb.DeviceTelemetry(
            device_id="device_1",
            device_type="HOST",
            protocol="TEST",
            timestamp_ns=1000,
        )
        telemetry2 = pb.DeviceTelemetry(
            device_id="device_2",
            device_type="HOST",
            protocol="TEST",
            timestamp_ns=2000,
        )

        adapter.enqueue(telemetry1)
        adapter.enqueue(telemetry2)

        queue = adapter.queue
        cursor = queue.db.execute("SELECT content_hash FROM queue ORDER BY id")
        hashes = [row[0] for row in cursor.fetchall()]

        assert len(hashes) == 2
        assert hashes[0] != hashes[1]


class TestIdempotencyKeyFormat:
    """Test idempotency key follows expected format."""

    def test_idempotency_key_format(self, adapter, test_telemetry):
        """Verify key format is {agent}:{device}:{ts_ns}:{seq}."""
        adapter.enqueue(test_telemetry)

        queue = adapter.queue
        cursor = queue.db.execute("SELECT idem FROM queue LIMIT 1")
        idem_key = cursor.fetchone()[0]

        parts = idem_key.split(":")
        assert len(parts) == 4
        assert parts[0] == "test_agent"
        assert parts[1] == "device_123"
        assert int(parts[2]) > 0  # timestamp_ns
        assert parts[3] == "1"  # sequence number

    def test_idempotency_key_sequence_increments(self, adapter, test_telemetry):
        """Verify sequence number increments with each enqueue."""
        adapter.enqueue(test_telemetry)
        adapter.enqueue(test_telemetry)
        adapter.enqueue(test_telemetry)

        queue = adapter.queue
        cursor = queue.db.execute("SELECT idem FROM queue ORDER BY id")
        idem_keys = [row[0] for row in cursor.fetchall()]

        sequences = [key.split(":")[-1] for key in idem_keys]
        assert sequences == ["1", "2", "3"]


class TestQueuePersistsAcrossRestart:
    """Test queue data survives adapter restarts."""

    def test_queue_survives_adapter_restart(self, tmp_queue_path, test_telemetry):
        """Verify enqueued items persist after creating new adapter instance."""
        # First adapter: enqueue
        adapter1 = LocalQueueAdapter(
            queue_path=tmp_queue_path,
            agent_name="test_agent",
            device_id="device_123",
        )
        adapter1.enqueue(test_telemetry)
        assert adapter1.size() == 1

        # New adapter: should see persisted item
        adapter2 = LocalQueueAdapter(
            queue_path=tmp_queue_path,
            agent_name="test_agent",
            device_id="device_123",
        )
        assert adapter2.size() == 1

    def test_drain_can_retrieve_persisted_items(self, tmp_queue_path, test_telemetry):
        """Verify persisted items can be drained after restart."""
        # Enqueue with first adapter
        adapter1 = LocalQueueAdapter(
            queue_path=tmp_queue_path,
            agent_name="test_agent",
            device_id="device_123",
        )
        adapter1.enqueue(test_telemetry)

        # Drain with second adapter
        adapter2 = LocalQueueAdapter(
            queue_path=tmp_queue_path,
            agent_name="test_agent",
            device_id="device_123",
        )

        drained_count = 0

        def mock_publish(envelopes):
            nonlocal drained_count
            drained_count = len(envelopes)

        adapter2.drain(publish_fn=mock_publish, limit=10)
        assert drained_count == 1


class TestDuplicateRejection:
    """Test deduplication based on idempotency key."""

    def test_duplicate_idempotency_key_rejected(self, adapter, test_telemetry):
        """Verify same event enqueued twice is deduplicated."""
        # Manually set the same idempotency key
        idem_key = "test_agent:device_123:12345:1"

        queue = adapter.queue
        telemetry = test_telemetry

        # First enqueue should succeed
        result1 = queue.enqueue(telemetry, idem_key)
        assert result1 is True

        # Second enqueue with same key should fail
        result2 = queue.enqueue(telemetry, idem_key)
        assert result2 is False

        # Queue should still have only 1 item
        assert queue.size() == 1

    def test_duplicate_via_adapter_rejected(self, adapter):
        """Verify adapter rejects duplicates based on idempotency logic."""
        telemetry = pb.DeviceTelemetry(
            device_id="device_123",
            device_type="HOST",
            protocol="TEST",
            timestamp_ns=1000,
        )

        # Mock time.time() to return same value for both enqueues
        with patch("amoskys.agents.common.queue_adapter.time.time", return_value=1.0):
            result1 = adapter.enqueue(telemetry)
            # Reset sequence manually to trigger duplicate scenario
            adapter._sequence -= 1
            result2 = adapter.enqueue(telemetry)

        # Second should be rejected (duplicate key)
        # Note: adapter doesn't reject per-se, but LocalQueue will
        assert adapter.size() <= 1


class TestQueueOrdering:
    """Test FIFO ordering is maintained."""

    def test_queue_fifo_order(self, adapter):
        """Verify events are drained in FIFO order."""
        events = []

        for i in range(5):
            telemetry = pb.DeviceTelemetry(
                device_id=f"device_{i}",
                device_type="HOST",
                protocol="TEST",
                timestamp_ns=int(time.time() * 1e9) + i,
            )
            events.append(telemetry)
            adapter.enqueue(telemetry)

        # Drain and verify order
        drained_events = []

        def capture_publish(envelopes):
            for env in envelopes:
                drained_events.append(env.device_telemetry.device_id)

        adapter.drain(publish_fn=capture_publish, limit=10)

        assert drained_events == [
            "device_0",
            "device_1",
            "device_2",
            "device_3",
            "device_4",
        ]


class TestBatchEnqueue:
    """Test multiple events in single collection cycle."""

    def test_batch_enqueue_multiple_events(self, adapter):
        """Verify multiple events can be enqueued in one cycle."""
        count = 10

        for i in range(count):
            telemetry = pb.DeviceTelemetry(
                device_id=f"device_{i}",
                device_type="HOST",
                protocol="TEST",
                timestamp_ns=int(time.time() * 1e9) + i,
            )
            adapter.enqueue(telemetry)

        assert adapter.size() == count

    def test_batch_enqueue_preserves_order(self, adapter):
        """Verify batch enqueue maintains order."""
        count = 20

        for i in range(count):
            telemetry = pb.DeviceTelemetry(
                device_id=f"device_{i}",
                device_type="HOST",
                protocol="TEST",
                timestamp_ns=int(time.time() * 1e9) + i,
            )
            adapter.enqueue(telemetry)

        # Drain and check device_id order
        drained_ids = []

        def capture_publish(envelopes):
            for env in envelopes:
                drained_ids.append(env.device_telemetry.device_id)

        adapter.drain(publish_fn=capture_publish, limit=count)

        expected_ids = [f"device_{i}" for i in range(count)]
        assert drained_ids == expected_ids

    def test_batch_enqueue_respects_drain_limit(self, adapter):
        """Verify drain limit is respected with batch enqueue."""
        for i in range(10):
            telemetry = pb.DeviceTelemetry(
                device_id=f"device_{i}",
                device_type="HOST",
                protocol="TEST",
                timestamp_ns=int(time.time() * 1e9) + i,
            )
            adapter.enqueue(telemetry)

        drained_count = 0

        def capture_count(envelopes):
            nonlocal drained_count
            drained_count += len(envelopes)

        # Drain only 3 items
        adapter.drain(publish_fn=capture_count, limit=3)

        assert drained_count == 3
        # 7 items should remain
        assert adapter.size() == 7
