"""LocalQueue adapter for HardenedAgentBase compatibility.

This adapter wraps the existing LocalQueue to provide a unified interface
that works with the HardenedAgentBase class while maintaining backward
compatibility with existing agent code.

The adapter handles:
    - Automatic idempotency key generation
    - Event-to-protobuf conversion
    - Simplified enqueue/drain interface
    - Ed25519 envelope signing (when a signing key is provided)
    - UniversalEnvelope wrapping on drain
"""

import hashlib
import logging
import time
from typing import Any, Callable, Optional

from amoskys.agents.common.local_queue import LocalQueue
from amoskys.proto import universal_telemetry_pb2 as pb

logger = logging.getLogger(__name__)


def _load_signing_key(path: str):
    """Try to load an Ed25519 private key.  Returns None on any failure.

    P0-13: Failures are now logged at WARNING with structured details.
    """
    try:
        from amoskys.common.crypto.signing import load_private_key

        key = load_private_key(path)
        logger.info("Envelope signing enabled (Ed25519 key loaded from %s)", path)
        return key
    except FileNotFoundError:
        logger.warning(
            "SIGNING_KEY_MISSING: path=%s — envelope signing disabled, "
            "events will be unauthenticated",
            path,
        )
        return None
    except Exception as exc:
        logger.warning(
            "SIGNING_KEY_LOAD_FAILURE: path=%s error=%s — "
            "envelope signing disabled, events will be unauthenticated",
            path,
            exc,
        )
        return None


class LocalQueueAdapter:
    """Adapter for LocalQueue to work with HardenedAgentBase.

    Provides a simplified interface where:
        - enqueue(event) automatically generates idempotency keys
        - drain(publish_fn, limit) handles the publish callback

    When *signing_key_path* is provided and the key file exists, every
    enqueued event is signed with Ed25519.  A SHA-256 ``content_hash``
    is always computed (even without a signing key) for tamper detection.

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
        signing_key_path: Optional[str] = None,
    ):
        """Initialize queue adapter.

        Args:
            queue_path: Path to SQLite queue database
            agent_name: Agent name for idempotency keys
            device_id: Device ID for idempotency keys
            max_bytes: Maximum queue size in bytes
            max_retries: Maximum retry attempts per event
            signing_key_path: Path to Ed25519 private key (32 bytes raw).
                If None or file missing, signing is silently disabled.
        """
        self.queue = LocalQueue(
            path=queue_path, max_bytes=max_bytes, max_retries=max_retries
        )
        self.agent_name = agent_name
        self.device_id = device_id
        self._sequence = 0

        # AOC-1: Metrics handle — set by HardenedAgentBase after construction
        self._metrics: Optional[Any] = None

        # Signing state
        self._signing_key = (
            _load_signing_key(signing_key_path) if signing_key_path else None
        )
        self._prev_sig: bytes = b""  # Hash chain: starts empty

        # AOC-1: Wire LocalQueue callbacks to metrics (P0-10, P0-11, P0-12)
        self.queue._on_backpressure_drop = self._on_backpressure_drop
        self.queue._on_max_retry_drop = self._on_max_retry_drop
        self.queue._on_drain_success = self._on_drain_success
        self.queue._on_drain_failure = self._on_drain_failure

    @property
    def signing_enabled(self) -> bool:
        """True when an Ed25519 key is loaded and signing is active."""
        return self._signing_key is not None

    def enqueue(self, event: Any) -> bool:
        """Enqueue event with automatic key generation and signing.

        Args:
            event: Event to enqueue (dict, DeviceTelemetry, etc.)

        Returns:
            True if enqueued, False if duplicate

        Behavior:
            - Generates idempotency key: {agent}:{device}:{timestamp}:{seq}
            - Converts event to DeviceTelemetry if needed
            - Computes SHA-256 content_hash of serialized payload
            - Signs content_hash with Ed25519 if key available
            - Maintains prev_sig hash chain across enqueues
        """
        # Generate idempotency key
        ts_ns = int(time.time() * 1e9)
        self._sequence += 1
        idem_key = f"{self.agent_name}:{self.device_id}:{ts_ns}:{self._sequence}"

        # Convert event to DeviceTelemetry if needed
        if isinstance(event, pb.DeviceTelemetry):
            telemetry = event
        elif isinstance(event, pb.UniversalEnvelope):
            # Extract DeviceTelemetry from an already-wrapped envelope
            telemetry = event.device_telemetry
        elif isinstance(event, dict):
            telemetry = self._dict_to_telemetry(event)
        else:
            telemetry = event

        # Compute content hash (always — even without signing key)
        payload_bytes = telemetry.SerializeToString()
        content_hash = hashlib.sha256(payload_bytes).digest()

        # Build UniversalEnvelope for full-envelope signing (D4)
        sig: Optional[bytes] = None
        prev_sig = self._prev_sig or None

        if self._signing_key is not None:
            from amoskys.common.crypto.canonical import universal_canonical_bytes
            from amoskys.common.crypto.signing import sign

            # Construct a temporary envelope to compute canonical bytes
            temp_env = pb.UniversalEnvelope()
            temp_env.version = "1.0"
            temp_env.ts_ns = ts_ns
            temp_env.idempotency_key = idem_key
            temp_env.device_telemetry.CopyFrom(telemetry)
            temp_env.schema_version = 1
            temp_env.signing_algorithm = "Ed25519"
            if prev_sig:
                temp_env.prev_sig = prev_sig
            # sig is left empty — canonical form zeroes it
            canonical = universal_canonical_bytes(temp_env)
            sig = sign(self._signing_key, canonical)

        result = self.queue.enqueue(
            telemetry,
            idem_key,
            content_hash=content_hash,
            sig=sig,
            prev_sig=prev_sig,
            ts_ns=ts_ns,
        )

        # Advance hash chain on successful enqueue
        if result and sig is not None:
            self._prev_sig = sig

        return result

    def drain(self, publish_fn: Callable, limit: int = 100) -> int:
        """Drain queue, wrapping each event in a signed UniversalEnvelope.

        Args:
            publish_fn: Function that publishes events (takes list of events).
                Each event is a ``UniversalEnvelope`` when signing is wired,
                or a raw ``DeviceTelemetry`` for backward compat when no
                signature data exists on the row.
            limit: Maximum events to drain

        Returns:
            Number of events successfully drained
        """

        def _wrap_and_publish(telemetry, idem, ts_ns, content_hash, sig, prev_sig):
            """Wrap DeviceTelemetry in UniversalEnvelope with signature."""
            envelope = pb.UniversalEnvelope()
            envelope.version = "1.0"
            envelope.ts_ns = ts_ns
            envelope.idempotency_key = idem
            envelope.device_telemetry.CopyFrom(telemetry)
            envelope.schema_version = 1

            if sig:
                envelope.sig = sig
                envelope.signing_algorithm = "Ed25519"
            if prev_sig:
                envelope.prev_sig = prev_sig

            publish_fn([envelope])
            return type("Ack", (), {"status": 0})()

        return self.queue.drain_signed(_wrap_and_publish, limit=limit)

    def size(self) -> int:
        """Get number of events in queue."""
        return self.queue.size()

    def size_bytes(self) -> int:
        """Get total size of queue in bytes."""
        return self.queue.size_bytes()

    def clear(self) -> int:
        """Clear all events from queue."""
        return self.queue.clear()

    # ------------------------------------------------------------------
    # AOC-1 callback methods (P0-10, P0-11, P0-12)
    # ------------------------------------------------------------------

    def _on_backpressure_drop(self, count: int) -> None:
        """Called by LocalQueue when backpressure drops oldest events."""
        if self._metrics:
            self._metrics.record_backpressure_drop(count)

    def _on_max_retry_drop(self, _idem_key: str) -> None:
        """Called by LocalQueue when an event exceeds max retries."""
        if self._metrics:
            self._metrics.record_max_retry_drop()

    def _on_drain_success(self, count: int) -> None:
        """Called by LocalQueue after successful drain."""
        if self._metrics:
            self._metrics.record_drain_success(count)

    def _on_drain_failure(self, _idem_key: str, _error: Exception) -> None:
        """Called by LocalQueue on drain publish failure."""
        if self._metrics:
            self._metrics.record_drain_failure()

    # ------------------------------------------------------------------
    # P0-14: Hash chain verification
    # ------------------------------------------------------------------

    def verify_hash_chain(self) -> dict:
        """Walk the signature chain and report integrity.

        Reads all ``(id, sig, prev_sig)`` rows in insertion order and
        checks that each row's ``prev_sig`` matches the previous row's
        ``sig``.

        Returns:
            dict with keys:
                - chain_valid (bool): True if entire chain is intact
                - total_rows (int): Number of rows inspected
                - broken_at (Optional[int]): Row ID where chain broke, or None
                - unsigned_count (int): Rows with no signature
        """
        cur = self.queue.db.execute("SELECT id, sig, prev_sig FROM queue ORDER BY id")
        rows = cur.fetchall()

        total_rows = len(rows)
        unsigned_count = 0
        broken_at = None
        prev_expected_sig: Optional[bytes] = None

        for rowid, sig, prev_sig in rows:
            if sig is None:
                unsigned_count += 1
                prev_expected_sig = None
                continue

            sig_bytes = bytes(sig)
            prev_sig_bytes = bytes(prev_sig) if prev_sig else None

            if prev_expected_sig is not None:
                if prev_sig_bytes != prev_expected_sig:
                    broken_at = rowid
                    break

            prev_expected_sig = sig_bytes

        return {
            "chain_valid": broken_at is None,
            "total_rows": total_rows,
            "broken_at": broken_at,
            "unsigned_count": unsigned_count,
        }

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
