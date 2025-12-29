"""Tests for Agent Local Queue.

Tests the offline resilience queue that prevents data loss when
EventBus is unavailable. Critical for production deployments.
"""

import pytest
import tempfile
import os
from pathlib import Path

from amoskys.agents.common import LocalQueue
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2


class TestQueueBasics:
    """Test basic queue operations"""

    def test_enqueue_and_size(self, tmp_path):
        """Verify enqueue adds events and updates size"""
        queue = LocalQueue(path=str(tmp_path / "test.db"))

        # Create test telemetry
        telemetry = telemetry_pb2.DeviceTelemetry(
            device_id="test-device",
            device_type="HOST",
            protocol="TEST",
            timestamp_ns=1234567890,
        )

        # Enqueue
        result = queue.enqueue(telemetry, "test-key-1")
        assert result is True
        assert queue.size() == 1
        assert queue.size_bytes() > 0

    def test_enqueue_multiple(self, tmp_path):
        """Verify multiple enqueue operations"""
        queue = LocalQueue(path=str(tmp_path / "test.db"))

        for i in range(10):
            telemetry = telemetry_pb2.DeviceTelemetry(
                device_id=f"device-{i}",
                device_type="HOST",
                protocol="TEST",
                timestamp_ns=1234567890 + i,
            )
            queue.enqueue(telemetry, f"key-{i}")

        assert queue.size() == 10

    def test_enqueue_duplicate_key(self, tmp_path):
        """Verify duplicate keys are rejected"""
        queue = LocalQueue(path=str(tmp_path / "test.db"))

        telemetry1 = telemetry_pb2.DeviceTelemetry(
            device_id="device-1",
            device_type="HOST",
            protocol="TEST",
            timestamp_ns=1234567890,
        )

        telemetry2 = telemetry_pb2.DeviceTelemetry(
            device_id="device-2",
            device_type="HOST",
            protocol="TEST",
            timestamp_ns=9999999999,
        )

        # First enqueue succeeds
        result1 = queue.enqueue(telemetry1, "same-key")
        assert result1 is True
        assert queue.size() == 1

        # Duplicate key is rejected (different data, same key)
        result2 = queue.enqueue(telemetry2, "same-key")
        assert result2 is False
        assert queue.size() == 1  # Still only 1 event

    def test_clear(self, tmp_path):
        """Verify clear removes all events"""
        queue = LocalQueue(path=str(tmp_path / "test.db"))

        # Add events
        for i in range(5):
            telemetry = telemetry_pb2.DeviceTelemetry(
                device_id=f"device-{i}", device_type="HOST", protocol="TEST"
            )
            queue.enqueue(telemetry, f"key-{i}")

        assert queue.size() == 5

        # Clear
        deleted = queue.clear()
        assert deleted == 5
        assert queue.size() == 0


class TestDrain:
    """Test queue drain operations"""

    def test_drain_successful_publish(self, tmp_path):
        """Verify drain removes events on successful publish"""
        queue = LocalQueue(path=str(tmp_path / "test.db"))

        # Enqueue 3 events
        for i in range(3):
            telemetry = telemetry_pb2.DeviceTelemetry(
                device_id=f"device-{i}", device_type="HOST", protocol="TEST"
            )
            queue.enqueue(telemetry, f"key-{i}")

        assert queue.size() == 3

        # Mock successful publish
        published = []

        def publish_fn(telemetry):
            published.append(telemetry.device_id)
            # Return OK ack
            return telemetry_pb2.UniversalAck(status=telemetry_pb2.UniversalAck.OK)

        # Drain
        drained = queue.drain(publish_fn, limit=10)
        assert drained == 3
        assert queue.size() == 0
        assert published == ["device-0", "device-1", "device-2"]

    def test_drain_with_retry_status(self, tmp_path):
        """Verify drain stops on RETRY status"""
        queue = LocalQueue(path=str(tmp_path / "test.db"))

        # Enqueue 5 events
        for i in range(5):
            telemetry = telemetry_pb2.DeviceTelemetry(
                device_id=f"device-{i}", device_type="HOST", protocol="TEST"
            )
            queue.enqueue(telemetry, f"key-{i}")

        published = []

        def publish_fn(telemetry):
            published.append(telemetry.device_id)
            # First event OK, second event RETRY (EventBus overloaded)
            if len(published) == 1:
                return telemetry_pb2.UniversalAck(status=telemetry_pb2.UniversalAck.OK)
            else:
                return telemetry_pb2.UniversalAck(
                    status=telemetry_pb2.UniversalAck.RETRY
                )

        # Drain
        drained = queue.drain(publish_fn, limit=10)
        assert drained == 1  # Only first event drained
        assert queue.size() == 4  # 4 events remain
        assert published == [
            "device-0",
            "device-1",
        ]  # Both attempted, only first succeeded

    def test_drain_with_exception(self, tmp_path):
        """Verify drain stops on publish exception"""
        queue = LocalQueue(path=str(tmp_path / "test.db"))

        # Enqueue 5 events
        for i in range(5):
            telemetry = telemetry_pb2.DeviceTelemetry(
                device_id=f"device-{i}", device_type="HOST", protocol="TEST"
            )
            queue.enqueue(telemetry, f"key-{i}")

        published = []

        def publish_fn(telemetry):
            published.append(telemetry.device_id)
            # First event OK, second event raises exception
            if len(published) == 1:
                return telemetry_pb2.UniversalAck(status=telemetry_pb2.UniversalAck.OK)
            else:
                raise Exception("Network error")

        # Drain
        drained = queue.drain(publish_fn, limit=10)
        assert drained == 1  # Only first event drained
        assert (
            queue.size() == 4
        )  # Second event still in queue with retry counter incremented

    def test_drain_limit(self, tmp_path):
        """Verify drain respects limit parameter"""
        queue = LocalQueue(path=str(tmp_path / "test.db"))

        # Enqueue 10 events
        for i in range(10):
            telemetry = telemetry_pb2.DeviceTelemetry(
                device_id=f"device-{i}", device_type="HOST", protocol="TEST"
            )
            queue.enqueue(telemetry, f"key-{i}")

        published = []

        def publish_fn(telemetry):
            published.append(telemetry.device_id)
            return telemetry_pb2.UniversalAck(status=telemetry_pb2.UniversalAck.OK)

        # Drain with limit=3
        drained = queue.drain(publish_fn, limit=3)
        assert drained == 3
        assert queue.size() == 7
        assert len(published) == 3

    def test_drain_empty_queue(self, tmp_path):
        """Verify drain handles empty queue gracefully"""
        queue = LocalQueue(path=str(tmp_path / "test.db"))

        def publish_fn(telemetry):
            pytest.fail("Should not be called for empty queue")

        drained = queue.drain(publish_fn, limit=10)
        assert drained == 0


class TestRetryLogic:
    """Test retry counter and max retries"""

    def test_max_retries_drops_event(self, tmp_path):
        """Verify events are dropped after max retries"""
        queue = LocalQueue(path=str(tmp_path / "test.db"), max_retries=3)

        # Enqueue event
        telemetry = telemetry_pb2.DeviceTelemetry(
            device_id="test-device", device_type="HOST", protocol="TEST"
        )
        queue.enqueue(telemetry, "retry-test")
        assert queue.size() == 1

        # Mock failing publish
        def failing_publish(telemetry):
            raise Exception("Network error")

        # Drain 4 times (should fail 3 times, then drop on 4th)
        for i in range(4):
            drained = queue.drain(failing_publish, limit=1)
            if i < 3:
                assert drained == 0  # Failed, not drained
                assert queue.size() == 1  # Still in queue
            else:
                # On 4th attempt (retries=3), event is dropped
                assert queue.size() == 0  # Event dropped after max retries


class TestBackpressure:
    """Test backpressure and size limits"""

    def test_backpressure_drops_oldest(self, tmp_path):
        """Verify backpressure drops oldest events"""
        # Create queue with very small limit (1KB)
        queue = LocalQueue(path=str(tmp_path / "test.db"), max_bytes=1024)

        # Enqueue events until we exceed limit
        for i in range(20):
            telemetry = telemetry_pb2.DeviceTelemetry(
                device_id=f"device-{i}",
                device_type="HOST",
                protocol="TEST",
                events=[
                    telemetry_pb2.TelemetryEvent(
                        event_id=f"event-{i}",
                        event_type="METRIC",
                        severity="INFO",
                        event_timestamp_ns=1234567890 + i,
                    )
                ],
            )
            queue.enqueue(telemetry, f"key-{i}")

        # Queue should be under limit (oldest events dropped)
        assert queue.size_bytes() <= 1024

        # Verify queue still has some events (not all dropped)
        assert queue.size() > 0

    def test_size_bytes_accuracy(self, tmp_path):
        """Verify size_bytes returns accurate byte count"""
        queue = LocalQueue(path=str(tmp_path / "test.db"))

        # Enqueue known-size event
        telemetry = telemetry_pb2.DeviceTelemetry(
            device_id="test", device_type="HOST", protocol="TEST"
        )
        serialized_size = len(telemetry.SerializeToString())

        queue.enqueue(telemetry, "size-test")
        assert queue.size_bytes() == serialized_size


class TestPersistence:
    """Test queue persistence across restarts"""

    def test_queue_survives_restart(self, tmp_path):
        """Verify queue persists across agent restarts"""
        db_path = str(tmp_path / "persistent.db")

        # Create queue and enqueue events
        queue1 = LocalQueue(path=db_path)
        for i in range(5):
            telemetry = telemetry_pb2.DeviceTelemetry(
                device_id=f"device-{i}", device_type="HOST", protocol="TEST"
            )
            queue1.enqueue(telemetry, f"key-{i}")

        assert queue1.size() == 5
        original_bytes = queue1.size_bytes()

        # Simulate restart by creating new queue with same path
        queue2 = LocalQueue(path=db_path)

        # Verify events persisted
        assert queue2.size() == 5
        assert queue2.size_bytes() == original_bytes

    def test_queue_fifo_order(self, tmp_path):
        """Verify queue drains in FIFO order"""
        queue = LocalQueue(path=str(tmp_path / "test.db"))

        # Enqueue events in order
        for i in range(5):
            telemetry = telemetry_pb2.DeviceTelemetry(
                device_id=f"device-{i}", device_type="HOST", protocol="TEST"
            )
            queue.enqueue(telemetry, f"key-{i}")

        # Drain and verify order
        drained_order = []

        def publish_fn(telemetry):
            drained_order.append(telemetry.device_id)
            return telemetry_pb2.UniversalAck(status=telemetry_pb2.UniversalAck.OK)

        queue.drain(publish_fn, limit=10)

        # Should be in FIFO order
        assert drained_order == [
            "device-0",
            "device-1",
            "device-2",
            "device-3",
            "device-4",
        ]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
