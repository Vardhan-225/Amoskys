"""LocalQueue adapter for HardenedAgentBase compatibility.

This adapter wraps the existing LocalQueue to provide a unified interface
that works with the HardenedAgentBase class while maintaining backward
compatibility with existing agent code.

The adapter handles:
    - Automatic idempotency key generation
    - Event-to-protobuf conversion
    - Simplified enqueue/drain interface
"""

import logging
import time
from typing import Any, Callable

from amoskys.agents.common.local_queue import LocalQueue
from amoskys.proto import universal_telemetry_pb2 as pb

logger = logging.getLogger(__name__)


class LocalQueueAdapter:
    """Adapter for LocalQueue to work with HardenedAgentBase.

    Provides a simplified interface where:
        - enqueue(event) automatically generates idempotency keys
        - drain(publish_fn, limit) handles the publish callback

    Attributes:
        queue: Underlying LocalQueue instance
        agent_name: Agent identifier for key generation
        device_id: Device identifier for key generation
    """

    def __init__(
        self,
        queue_path: str,
        agent_name: str,
        device_id: str,
        max_bytes: int = 50 * 1024 * 1024,
        max_retries: int = 10,
    ):
        """Initialize queue adapter.

        Args:
            queue_path: Path to SQLite queue database
            agent_name: Agent name for idempotency keys
            device_id: Device ID for idempotency keys
            max_bytes: Maximum queue size in bytes
            max_retries: Maximum retry attempts per event
        """
        self.queue = LocalQueue(
            path=queue_path, max_bytes=max_bytes, max_retries=max_retries
        )
        self.agent_name = agent_name
        self.device_id = device_id
        self._sequence = 0

    def enqueue(self, event: Any) -> bool:
        """Enqueue event with automatic key generation.

        Args:
            event: Event to enqueue (dict, DeviceTelemetry, etc.)

        Returns:
            True if enqueued, False if duplicate

        Behavior:
            - Generates idempotency key: {agent}:{device}:{timestamp}:{seq}
            - Converts event to DeviceTelemetry if needed
            - Calls underlying LocalQueue.enqueue()
        """
        # Generate idempotency key
        ts_ns = int(time.time() * 1e9)
        self._sequence += 1
        idem_key = f"{self.agent_name}:{self.device_id}:{ts_ns}:{self._sequence}"

        # Convert event to DeviceTelemetry if needed
        if isinstance(event, pb.DeviceTelemetry):
            telemetry = event
        elif isinstance(event, dict):
            telemetry = self._dict_to_telemetry(event)
        else:
            # Assume it's already a protobuf with SerializeToString
            telemetry = event

        return self.queue.enqueue(telemetry, idem_key)

    def drain(self, publish_fn: Callable, limit: int = 100) -> int:
        """Drain queue using publish callback.

        Args:
            publish_fn: Function that publishes events (takes list of events)
            limit: Maximum events to drain

        Returns:
            Number of events successfully drained

        Note:
            The publish_fn should handle retries internally.
            LocalQueue expects publish_fn(telemetry) -> ack.
            We wrap it to match that interface.
        """

        def wrapped_publish(telemetry: pb.DeviceTelemetry) -> Any:
            """Wrap publish_fn to match LocalQueue expectations."""
            # publish_fn expects a list, but LocalQueue calls per-event
            # We create a simple ack-like object
            try:
                publish_fn([telemetry])
                # Return success-like object
                return type("Ack", (), {"status": 0})()
            except Exception as e:
                logger.warning(f"Publish failed in queue drain: {e}")
                # Return failure-like object
                return type("Ack", (), {"status": 2})()  # ERROR status

        return self.queue.drain(wrapped_publish, limit=limit)

    def size(self) -> int:
        """Get number of events in queue."""
        return self.queue.size()

    def size_bytes(self) -> int:
        """Get total size of queue in bytes."""
        return self.queue.size_bytes()

    def clear(self) -> int:
        """Clear all events from queue."""
        return self.queue.clear()

    def _dict_to_telemetry(self, event: dict) -> pb.DeviceTelemetry:
        """Convert dict event to DeviceTelemetry protobuf.

        Args:
            event: Event dictionary

        Returns:
            DeviceTelemetry protobuf message

        Note:
            This is a basic conversion. Subclass and override for
            more sophisticated event-specific conversions.
        """
        telemetry = pb.DeviceTelemetry()
        telemetry.device_id = event.get("device_id", self.device_id)
        telemetry.device_type = event.get("device_type", "endpoint")

        # Create a telemetry event from the dict
        tel_event = telemetry.events.add()
        tel_event.event_id = event.get("event_id", str(time.time_ns()))
        tel_event.event_type = event.get("event_type", "METRIC")
        tel_event.severity = event.get("severity", "INFO")
        tel_event.event_timestamp_ns = event.get(
            "event_timestamp_ns", int(time.time() * 1e9)
        )
        tel_event.source_component = event.get("source_component", self.agent_name)

        # Add metric data if present
        if "metric_data" in event:
            metric = tel_event.metric_data
            for key, value in event["metric_data"].items():
                if isinstance(value, (int, float)):
                    metric.values[key] = float(value)
                elif isinstance(value, str):
                    metric.labels[key] = value

        # Add tags
        if "tags" in event:
            tel_event.tags.extend(event["tags"])

        return telemetry
