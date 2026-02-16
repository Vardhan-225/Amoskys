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

    # Event types that represent security/threat detections (vs. metrics/status)
    _SECURITY_EVENT_TYPES: frozenset[str] = frozenset(
        {
            "protocol_threat",
            "process_threat",
            "kernel_threat",
            "device_threat",
            "auth_threat",
            "dns_threat",
            "file_threat",
            "peripheral_threat",
            "network_threat",
            "persistence_threat",
            "credential_threat",
            "exfiltration_threat",
        }
    )

    def _dict_to_telemetry(self, event: dict) -> pb.DeviceTelemetry:
        """Convert dict event to DeviceTelemetry protobuf.

        Handles two distinct event shapes:

        1. **Security/threat events** (event_type in _SECURITY_EVENT_TYPES):
           - Populates ``TelemetryEvent.security_event`` sub-message
           - Maps ``mitre_techniques``, ``confidence``, ``data`` fields
           - Sets ``event_category`` from ``data.category`` if available

        2. **Metric / status events** (everything else):
           - Populates ``TelemetryEvent.metric_data`` sub-message if
             ``metric_data`` key is present in the dict

        Both shapes get:
           - ``collection_agent`` set to ``self.agent_name``  (fixes GAP-07)
           - ``source_component`` set to probe_name or agent_name
           - ``data`` dict entries flattened into ``attributes`` map
           - ``tags`` list forwarded

        Args:
            event: Event dictionary (typically from ``TelemetryEvent.to_dict()``)

        Returns:
            Fully-populated DeviceTelemetry protobuf message
        """
        now_ns = int(time.time() * 1e9)

        telemetry = pb.DeviceTelemetry()
        telemetry.device_id = event.get("device_id", self.device_id)
        telemetry.device_type = event.get("device_type", "endpoint")
        telemetry.collection_agent = event.get("collection_agent", self.agent_name)
        telemetry.timestamp_ns = now_ns

        # --- Build the inner TelemetryEvent ---
        tel_event = telemetry.events.add()
        tel_event.event_id = event.get("event_id", str(time.time_ns()))

        event_type = event.get("event_type", "METRIC")
        tel_event.event_type = event_type
        tel_event.severity = event.get("severity", "INFO")
        tel_event.event_timestamp_ns = event.get("event_timestamp_ns", now_ns)

        # source_component: prefer probe_name, fall back to agent_name
        tel_event.source_component = event.get(
            "probe_name",
            event.get("source_component", self.agent_name),
        )

        # confidence → confidence_score (float 0.0–1.0)
        if "confidence" in event:
            try:
                tel_event.confidence_score = float(event["confidence"])
            except (TypeError, ValueError):
                pass

        # --- Populate sub-message based on event type ---
        is_security = event_type in self._SECURITY_EVENT_TYPES

        if is_security:
            self._populate_security_event(tel_event, event)
        elif "metric_data" in event:
            self._populate_metric_data(tel_event, event["metric_data"])

        # --- Flatten ``data`` dict into ``attributes`` ---
        data = event.get("data")
        if isinstance(data, dict):
            for key, value in data.items():
                if value is not None:
                    tel_event.attributes[str(key)] = str(value)

        # --- Tags ---
        if "tags" in event:
            tel_event.tags.extend(event["tags"])

        return telemetry

    # ------------------------------------------------------------------
    # Sub-message helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _populate_security_event(
        tel_event: "pb.TelemetryEvent",
        event: dict,
    ) -> None:
        """Populate the SecurityEvent sub-message from an event dict.

        Maps probe-emitted fields to the protobuf SecurityEvent schema:
            - data.category   → event_category
            - data.description → analyst_notes
            - data.src_ip     → source_ip
            - data.dst_ip     → target_resource
            - severity        → event_action (maps HIGH/CRITICAL→DETECTED)
            - mitre_techniques → mitre_techniques (repeated string)
            - confidence      → risk_score
        """
        sec = tel_event.security_event  # access creates the sub-message
        data = event.get("data") or {}

        # Category (e.g. "SSH_BRUTE_FORCE", "HTTP_SUSPICIOUS")
        sec.event_category = str(data.get("category", event.get("event_type", "")))

        # Action / outcome — derive from severity
        severity = event.get("severity", "INFO")
        if severity in ("HIGH", "CRITICAL"):
            sec.event_action = "DETECTED"
            sec.requires_investigation = True
        else:
            sec.event_action = "OBSERVED"
            sec.requires_investigation = False
        sec.event_outcome = "UNKNOWN"  # agents observe, not block

        # Actor / source
        if "src_ip" in data:
            sec.source_ip = str(data["src_ip"])
        if "user_agent" in data:
            sec.user_agent = str(data["user_agent"])[:200]
        if "username" in data:
            sec.user_name = str(data["username"])

        # Target
        if "dst_ip" in data:
            sec.target_resource = str(data["dst_ip"])
        if "affected_asset" in data:
            sec.affected_asset = str(data["affected_asset"])

        # Threat intelligence
        if "confidence" in event:
            try:
                sec.risk_score = float(event["confidence"])
            except (TypeError, ValueError):
                pass

        if "mitre_techniques" in event:
            techniques = event["mitre_techniques"]
            if isinstance(techniques, (list, tuple)):
                sec.mitre_techniques.extend(str(t) for t in techniques)

        # Description → analyst_notes (preserves human-readable context)
        if "description" in data:
            sec.analyst_notes = str(data["description"])[:1000]

        # Attack vector from data if present
        if "attack_vector" in data:
            sec.attack_vector = str(data["attack_vector"])

    @staticmethod
    def _populate_metric_data(
        tel_event: "pb.TelemetryEvent",
        metric_data: dict,
    ) -> None:
        """Populate the MetricData sub-message from a metric_data dict.

        MetricData has:
            - ``numeric_value`` (double) for a single numeric value
            - ``labels`` (map<string,string>) for key-value labels
            - ``metric_name``, ``metric_type``, ``unit`` scalars

        For a dict of mixed values we store numeric entries as labels
        (stringified) and string entries directly in labels, since the
        proto only supports a single ``numeric_value``.
        """
        metric = tel_event.metric_data
        for key, value in metric_data.items():
            if isinstance(value, (int, float)):
                metric.labels[key] = str(value)
            elif isinstance(value, str):
                metric.labels[key] = value
