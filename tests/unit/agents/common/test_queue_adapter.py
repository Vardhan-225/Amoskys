"""Tests for LocalQueueAdapter — GAP-01/GAP-07 fixes + full conversion coverage.

Validates that _dict_to_telemetry() correctly populates:
    - DeviceTelemetry.collection_agent (GAP-07)
    - TelemetryEvent.security_event sub-message for threat events (GAP-01)
    - TelemetryEvent.metric_data for metric events
    - TelemetryEvent.attributes from data dict
    - TelemetryEvent.confidence_score
    - TelemetryEvent.source_component from probe_name
    - TelemetryEvent.tags

Also tests the enqueue/drain lifecycle, idempotency key generation,
and protobuf round-trip fidelity.
"""

import os
import tempfile
import time
from unittest.mock import MagicMock, patch

import pytest

from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.proto import universal_telemetry_pb2 as pb


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_queue_dir(tmp_path):
    """Create a temp directory for queue DBs."""
    return str(tmp_path / "test_queue.db")


@pytest.fixture
def adapter(tmp_queue_dir):
    """Create a fresh LocalQueueAdapter."""
    return LocalQueueAdapter(
        queue_path=tmp_queue_dir,
        agent_name="protocol_collectors_v2",
        device_id="host-lab-001",
    )


# ---------------------------------------------------------------------------
# GAP-07: collection_agent populated
# ---------------------------------------------------------------------------


class TestCollectionAgentField:
    """GAP-07: collection_agent must be set on DeviceTelemetry."""

    def test_collection_agent_defaults_to_agent_name(self, adapter):
        """collection_agent should default to self.agent_name."""
        event = {"event_type": "METRIC", "severity": "INFO"}
        telemetry = adapter._dict_to_telemetry(event)
        assert telemetry.collection_agent == "protocol_collectors_v2"

    def test_collection_agent_from_event_dict(self, adapter):
        """If event dict has collection_agent, use it."""
        event = {
            "event_type": "METRIC",
            "severity": "INFO",
            "collection_agent": "custom_agent",
        }
        telemetry = adapter._dict_to_telemetry(event)
        assert telemetry.collection_agent == "custom_agent"

    def test_collection_agent_on_security_event(self, adapter):
        """collection_agent must be set even for security/threat events."""
        event = {
            "event_type": "protocol_threat",
            "severity": "MEDIUM",
            "data": {"category": "SSH_BRUTE_FORCE"},
        }
        telemetry = adapter._dict_to_telemetry(event)
        assert telemetry.collection_agent == "protocol_collectors_v2"


# ---------------------------------------------------------------------------
# GAP-01: SecurityEvent sub-message populated for threat events
# ---------------------------------------------------------------------------


class TestSecurityEventPopulation:
    """GAP-01: security_event sub-message must be populated for threats."""

    def _make_protocol_threat(self, **overrides):
        """Build a typical protocol_threat event dict."""
        event = {
            "event_type": "protocol_threat",
            "severity": "MEDIUM",
            "probe_name": "ssh_brute_force",
            "confidence": 0.85,
            "mitre_techniques": ["T1110", "T1021.004"],
            "tags": ["ssh", "brute_force"],
            "data": {
                "category": "SSH_BRUTE_FORCE",
                "description": "5 failed SSH logins from 192.168.1.42",
                "src_ip": "192.168.1.42",
                "dst_ip": "10.0.0.1",
                "username": "admin",
            },
        }
        event.update(overrides)
        return event

    def test_security_event_is_populated(self, adapter):
        """security_event sub-message must not be empty for threat events."""
        event = self._make_protocol_threat()
        telemetry = adapter._dict_to_telemetry(event)
        tel_event = telemetry.events[0]

        # The security_event should be populated (HasField check)
        assert tel_event.HasField("security_event")

    def test_event_category_from_data(self, adapter):
        """event_category maps from data.category."""
        event = self._make_protocol_threat()
        telemetry = adapter._dict_to_telemetry(event)
        sec = telemetry.events[0].security_event
        assert sec.event_category == "SSH_BRUTE_FORCE"

    def test_event_category_fallback_to_event_type(self, adapter):
        """event_category falls back to event_type when data.category missing."""
        event = self._make_protocol_threat()
        del event["data"]["category"]
        telemetry = adapter._dict_to_telemetry(event)
        sec = telemetry.events[0].security_event
        assert sec.event_category == "protocol_threat"

    def test_mitre_techniques_populated(self, adapter):
        """MITRE techniques must be forwarded to security_event."""
        event = self._make_protocol_threat()
        telemetry = adapter._dict_to_telemetry(event)
        sec = telemetry.events[0].security_event
        assert list(sec.mitre_techniques) == ["T1110", "T1021.004"]

    def test_mitre_techniques_empty_list(self, adapter):
        """Empty mitre_techniques list produces no entries."""
        event = self._make_protocol_threat(mitre_techniques=[])
        telemetry = adapter._dict_to_telemetry(event)
        sec = telemetry.events[0].security_event
        assert len(sec.mitre_techniques) == 0

    def test_risk_score_from_confidence(self, adapter):
        """risk_score should map from confidence."""
        event = self._make_protocol_threat(confidence=0.92)
        telemetry = adapter._dict_to_telemetry(event)
        sec = telemetry.events[0].security_event
        assert abs(sec.risk_score - 0.92) < 0.001

    def test_source_ip_populated(self, adapter):
        """source_ip maps from data.src_ip."""
        event = self._make_protocol_threat()
        telemetry = adapter._dict_to_telemetry(event)
        sec = telemetry.events[0].security_event
        assert sec.source_ip == "192.168.1.42"

    def test_target_resource_from_dst_ip(self, adapter):
        """target_resource maps from data.dst_ip."""
        event = self._make_protocol_threat()
        telemetry = adapter._dict_to_telemetry(event)
        sec = telemetry.events[0].security_event
        assert sec.target_resource == "10.0.0.1"

    def test_user_name_from_data(self, adapter):
        """user_name maps from data.username."""
        event = self._make_protocol_threat()
        telemetry = adapter._dict_to_telemetry(event)
        sec = telemetry.events[0].security_event
        assert sec.user_name == "admin"

    def test_analyst_notes_from_description(self, adapter):
        """analyst_notes maps from data.description."""
        event = self._make_protocol_threat()
        telemetry = adapter._dict_to_telemetry(event)
        sec = telemetry.events[0].security_event
        assert "5 failed SSH logins" in sec.analyst_notes

    def test_high_severity_sets_detected_action(self, adapter):
        """HIGH/CRITICAL severity → event_action=DETECTED, requires_investigation=True."""
        event = self._make_protocol_threat(severity="HIGH")
        telemetry = adapter._dict_to_telemetry(event)
        sec = telemetry.events[0].security_event
        assert sec.event_action == "DETECTED"
        assert sec.requires_investigation is True

    def test_medium_severity_sets_observed_action(self, adapter):
        """MEDIUM severity → event_action=OBSERVED, requires_investigation=False."""
        event = self._make_protocol_threat(severity="MEDIUM")
        telemetry = adapter._dict_to_telemetry(event)
        sec = telemetry.events[0].security_event
        assert sec.event_action == "OBSERVED"
        assert sec.requires_investigation is False

    def test_critical_severity_sets_detected(self, adapter):
        """CRITICAL severity → event_action=DETECTED."""
        event = self._make_protocol_threat(severity="CRITICAL")
        telemetry = adapter._dict_to_telemetry(event)
        sec = telemetry.events[0].security_event
        assert sec.event_action == "DETECTED"
        assert sec.requires_investigation is True

    def test_event_outcome_is_unknown(self, adapter):
        """Agents observe, they don't block — outcome is always UNKNOWN."""
        event = self._make_protocol_threat()
        telemetry = adapter._dict_to_telemetry(event)
        sec = telemetry.events[0].security_event
        assert sec.event_outcome == "UNKNOWN"

    def test_user_agent_truncated(self, adapter):
        """user_agent should be truncated to 200 chars."""
        long_ua = "A" * 500
        event = self._make_protocol_threat()
        event["data"]["user_agent"] = long_ua
        telemetry = adapter._dict_to_telemetry(event)
        sec = telemetry.events[0].security_event
        assert len(sec.user_agent) <= 200

    def test_analyst_notes_truncated(self, adapter):
        """analyst_notes should be truncated to 1000 chars."""
        long_desc = "B" * 2000
        event = self._make_protocol_threat()
        event["data"]["description"] = long_desc
        telemetry = adapter._dict_to_telemetry(event)
        sec = telemetry.events[0].security_event
        assert len(sec.analyst_notes) <= 1000

    def test_attack_vector_from_data(self, adapter):
        """attack_vector maps from data.attack_vector if present."""
        event = self._make_protocol_threat()
        event["data"]["attack_vector"] = "network"
        telemetry = adapter._dict_to_telemetry(event)
        sec = telemetry.events[0].security_event
        assert sec.attack_vector == "network"

    def test_affected_asset_from_data(self, adapter):
        """affected_asset maps from data.affected_asset if present."""
        event = self._make_protocol_threat()
        event["data"]["affected_asset"] = "web-server-01"
        telemetry = adapter._dict_to_telemetry(event)
        sec = telemetry.events[0].security_event
        assert sec.affected_asset == "web-server-01"


# ---------------------------------------------------------------------------
# All recognized security event types trigger SecurityEvent population
# ---------------------------------------------------------------------------


class TestAllSecurityEventTypes:
    """Every event_type in _SECURITY_EVENT_TYPES should populate security_event."""

    @pytest.mark.parametrize(
        "event_type",
        [
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
        ],
    )
    def test_security_event_populated(self, adapter, event_type):
        """security_event must be populated for event_type={event_type}."""
        event = {
            "event_type": event_type,
            "severity": "MEDIUM",
            "data": {"category": "TEST_CATEGORY"},
            "mitre_techniques": ["T1234"],
        }
        telemetry = adapter._dict_to_telemetry(event)
        tel_event = telemetry.events[0]
        assert tel_event.HasField("security_event")
        assert tel_event.security_event.event_category == "TEST_CATEGORY"
        assert list(tel_event.security_event.mitre_techniques) == ["T1234"]


# ---------------------------------------------------------------------------
# Non-security events should NOT populate security_event
# ---------------------------------------------------------------------------


class TestNonSecurityEvents:
    """Metric/status events should NOT have security_event populated."""

    def test_metric_event_no_security_event(self, adapter):
        """METRIC event type → no security_event sub-message."""
        event = {
            "event_type": "METRIC",
            "severity": "INFO",
            "metric_data": {"cpu_percent": 42.5, "label": "host"},
        }
        telemetry = adapter._dict_to_telemetry(event)
        tel_event = telemetry.events[0]
        assert not tel_event.HasField("security_event")

    def test_agent_metrics_no_security_event(self, adapter):
        """agent_metrics event type → no security_event."""
        event = {"event_type": "agent_metrics", "severity": "INFO"}
        telemetry = adapter._dict_to_telemetry(event)
        tel_event = telemetry.events[0]
        assert not tel_event.HasField("security_event")

    def test_metric_data_populated(self, adapter):
        """metric_data sub-message should be populated for METRIC events."""
        event = {
            "event_type": "METRIC",
            "severity": "INFO",
            "metric_data": {
                "cpu_percent": 42.5,
                "memory_mb": 1024,
                "hostname": "lab-host",
            },
        }
        telemetry = adapter._dict_to_telemetry(event)
        tel_event = telemetry.events[0]
        assert tel_event.HasField("metric_data")
        # All values stored in labels as strings (proto MetricData uses labels map)
        assert tel_event.metric_data.labels["cpu_percent"] == "42.5"
        assert tel_event.metric_data.labels["memory_mb"] == "1024"
        assert tel_event.metric_data.labels["hostname"] == "lab-host"


# ---------------------------------------------------------------------------
# Common field mappings (both event shapes)
# ---------------------------------------------------------------------------


class TestCommonFieldMappings:
    """Fields that should be set regardless of event type."""

    def test_device_id_from_event(self, adapter):
        """device_id from event dict."""
        event = {"event_type": "METRIC", "device_id": "custom-device-99"}
        telemetry = adapter._dict_to_telemetry(event)
        assert telemetry.device_id == "custom-device-99"

    def test_device_id_fallback_to_adapter(self, adapter):
        """device_id falls back to adapter's device_id."""
        event = {"event_type": "METRIC"}
        telemetry = adapter._dict_to_telemetry(event)
        assert telemetry.device_id == "host-lab-001"

    def test_device_type_default(self, adapter):
        """device_type defaults to 'endpoint'."""
        event = {"event_type": "METRIC"}
        telemetry = adapter._dict_to_telemetry(event)
        assert telemetry.device_type == "endpoint"

    def test_device_type_custom(self, adapter):
        """device_type from event dict."""
        event = {"event_type": "METRIC", "device_type": "IOT"}
        telemetry = adapter._dict_to_telemetry(event)
        assert telemetry.device_type == "IOT"

    def test_timestamp_ns_set(self, adapter):
        """timestamp_ns should be set on DeviceTelemetry."""
        before = int(time.time() * 1e9)
        event = {"event_type": "METRIC"}
        telemetry = adapter._dict_to_telemetry(event)
        after = int(time.time() * 1e9)
        assert before <= telemetry.timestamp_ns <= after

    def test_source_component_from_probe_name(self, adapter):
        """source_component should prefer probe_name over agent_name."""
        event = {
            "event_type": "protocol_threat",
            "probe_name": "ssh_brute_force",
            "data": {},
        }
        telemetry = adapter._dict_to_telemetry(event)
        assert telemetry.events[0].source_component == "ssh_brute_force"

    def test_source_component_fallback_to_source_component(self, adapter):
        """source_component falls back to source_component field."""
        event = {
            "event_type": "METRIC",
            "source_component": "ProtocolCollectorsV2",
        }
        telemetry = adapter._dict_to_telemetry(event)
        assert telemetry.events[0].source_component == "ProtocolCollectorsV2"

    def test_source_component_fallback_to_agent_name(self, adapter):
        """source_component falls back to adapter.agent_name."""
        event = {"event_type": "METRIC"}
        telemetry = adapter._dict_to_telemetry(event)
        assert telemetry.events[0].source_component == "protocol_collectors_v2"

    def test_confidence_score_mapped(self, adapter):
        """confidence → confidence_score on TelemetryEvent."""
        event = {"event_type": "protocol_threat", "confidence": 0.77, "data": {}}
        telemetry = adapter._dict_to_telemetry(event)
        assert abs(telemetry.events[0].confidence_score - 0.77) < 0.001

    def test_confidence_score_missing_ok(self, adapter):
        """Missing confidence → confidence_score stays at default (0.0)."""
        event = {"event_type": "METRIC"}
        telemetry = adapter._dict_to_telemetry(event)
        assert telemetry.events[0].confidence_score == 0.0

    def test_confidence_score_invalid_ignored(self, adapter):
        """Invalid confidence value doesn't crash."""
        event = {"event_type": "METRIC", "confidence": "not-a-number"}
        telemetry = adapter._dict_to_telemetry(event)
        assert telemetry.events[0].confidence_score == 0.0

    def test_tags_forwarded(self, adapter):
        """tags list forwarded to TelemetryEvent."""
        event = {
            "event_type": "protocol_threat",
            "tags": ["ssh", "brute_force", "external"],
            "data": {},
        }
        telemetry = adapter._dict_to_telemetry(event)
        assert list(telemetry.events[0].tags) == ["ssh", "brute_force", "external"]

    def test_tags_empty_ok(self, adapter):
        """No tags key → no tags on proto."""
        event = {"event_type": "METRIC"}
        telemetry = adapter._dict_to_telemetry(event)
        assert len(telemetry.events[0].tags) == 0

    def test_data_dict_flattened_to_attributes(self, adapter):
        """data dict entries should be flattened into attributes map."""
        event = {
            "event_type": "protocol_threat",
            "data": {
                "category": "DNS_TUNNELING",
                "src_ip": "10.0.0.5",
                "query_count": 42,
                "is_suspicious": True,
            },
        }
        telemetry = adapter._dict_to_telemetry(event)
        attrs = dict(telemetry.events[0].attributes)
        assert attrs["category"] == "DNS_TUNNELING"
        assert attrs["src_ip"] == "10.0.0.5"
        assert attrs["query_count"] == "42"
        assert attrs["is_suspicious"] == "True"

    def test_data_none_values_excluded(self, adapter):
        """None values in data should not appear in attributes."""
        event = {
            "event_type": "protocol_threat",
            "data": {"present": "yes", "absent": None},
        }
        telemetry = adapter._dict_to_telemetry(event)
        attrs = dict(telemetry.events[0].attributes)
        assert "present" in attrs
        assert "absent" not in attrs

    def test_severity_forwarded(self, adapter):
        """severity field forwarded to TelemetryEvent."""
        event = {"event_type": "protocol_threat", "severity": "CRITICAL", "data": {}}
        telemetry = adapter._dict_to_telemetry(event)
        assert telemetry.events[0].severity == "CRITICAL"

    def test_event_type_forwarded(self, adapter):
        """event_type forwarded to TelemetryEvent."""
        event = {"event_type": "protocol_threat", "data": {}}
        telemetry = adapter._dict_to_telemetry(event)
        assert telemetry.events[0].event_type == "protocol_threat"


# ---------------------------------------------------------------------------
# Enqueue lifecycle
# ---------------------------------------------------------------------------


class TestEnqueueLifecycle:
    """Test enqueue with dict conversion end-to-end."""

    def test_enqueue_dict_returns_true(self, adapter):
        """Enqueuing a dict event should return True."""
        event = {
            "event_type": "protocol_threat",
            "severity": "MEDIUM",
            "data": {"category": "TEST"},
        }
        assert adapter.enqueue(event) is True

    def test_enqueue_increments_size(self, adapter):
        """Each enqueue should increase queue size."""
        event = {"event_type": "METRIC", "severity": "INFO"}
        adapter.enqueue(event)
        assert adapter.size() == 1
        adapter.enqueue(event)
        assert adapter.size() == 2

    def test_enqueue_protobuf_directly(self, adapter):
        """Enqueuing a DeviceTelemetry proto should work without conversion."""
        proto = pb.DeviceTelemetry(
            device_id="test-device",
            collection_agent="direct_agent",
        )
        assert adapter.enqueue(proto) is True
        assert adapter.size() == 1

    def test_idempotency_key_unique(self, adapter):
        """Each enqueue should generate a unique idempotency key."""
        event = {"event_type": "METRIC"}
        adapter.enqueue(event)
        adapter.enqueue(event)
        # Both should be enqueued (different keys)
        assert adapter.size() == 2

    def test_clear_empties_queue(self, adapter):
        """clear() should remove all events."""
        event = {"event_type": "METRIC"}
        adapter.enqueue(event)
        adapter.enqueue(event)
        assert adapter.size() == 2
        adapter.clear()
        assert adapter.size() == 0


# ---------------------------------------------------------------------------
# Round-trip fidelity (enqueue dict → dequeue proto → verify fields)
# ---------------------------------------------------------------------------


class TestRoundTripFidelity:
    """Verify data survives the dict→proto→SQLite→proto round trip."""

    def test_threat_event_round_trip(self, adapter):
        """Full threat event should survive enqueue → drain round trip.

        drain() now wraps events in UniversalEnvelope (correct for EventBus).
        The DeviceTelemetry payload is inside envelope.device_telemetry.
        """
        event = {
            "event_type": "protocol_threat",
            "severity": "HIGH",
            "probe_name": "dns_tunneling",
            "confidence": 0.91,
            "mitre_techniques": ["T1048.003"],
            "tags": ["dns", "exfil"],
            "data": {
                "category": "DNS_TUNNELING",
                "description": "High entropy DNS queries detected",
                "src_ip": "192.168.1.100",
                "dst_ip": "8.8.8.8",
            },
        }
        adapter.enqueue(event)

        # Drain and capture the envelope
        captured = []

        def capture_fn(events):
            captured.extend(events)

        adapter.drain(capture_fn, limit=1)

        assert len(captured) == 1
        envelope = captured[0]

        # Verify envelope metadata
        assert envelope.version == "1.0"
        assert envelope.idempotency_key  # non-empty
        assert envelope.ts_ns > 0

        # Unwrap: DeviceTelemetry is inside the envelope
        telemetry = envelope.device_telemetry

        # Verify top-level fields
        assert telemetry.device_id == "host-lab-001"
        assert telemetry.collection_agent == "protocol_collectors_v2"

        # Verify TelemetryEvent
        tel_event = telemetry.events[0]
        assert tel_event.event_type == "protocol_threat"
        assert tel_event.severity == "HIGH"
        assert tel_event.source_component == "dns_tunneling"
        assert abs(tel_event.confidence_score - 0.91) < 0.001
        assert list(tel_event.tags) == ["dns", "exfil"]

        # Verify SecurityEvent (GAP-01 fix)
        assert tel_event.HasField("security_event")
        sec = tel_event.security_event
        assert sec.event_category == "DNS_TUNNELING"
        assert list(sec.mitre_techniques) == ["T1048.003"]
        assert abs(sec.risk_score - 0.91) < 0.001
        assert sec.source_ip == "192.168.1.100"
        assert sec.target_resource == "8.8.8.8"
        assert sec.event_action == "DETECTED"
        assert sec.requires_investigation is True
        assert "High entropy" in sec.analyst_notes

        # Verify attributes (data flattened)
        attrs = dict(tel_event.attributes)
        assert attrs["category"] == "DNS_TUNNELING"
        assert attrs["src_ip"] == "192.168.1.100"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge cases and error resilience."""

    def test_empty_event_dict(self, adapter):
        """Empty dict should produce valid proto with defaults."""
        telemetry = adapter._dict_to_telemetry({})
        assert telemetry.device_id == "host-lab-001"
        assert telemetry.collection_agent == "protocol_collectors_v2"
        assert len(telemetry.events) == 1
        assert telemetry.events[0].event_type == "METRIC"

    def test_no_data_key(self, adapter):
        """Missing 'data' key should not crash."""
        event = {"event_type": "protocol_threat", "severity": "LOW"}
        telemetry = adapter._dict_to_telemetry(event)
        # security_event still populated (with empty data)
        assert telemetry.events[0].HasField("security_event")

    def test_data_not_a_dict(self, adapter):
        """If data is not a dict, attributes should be empty."""
        event = {"event_type": "METRIC", "data": "not-a-dict"}
        telemetry = adapter._dict_to_telemetry(event)
        assert len(telemetry.events[0].attributes) == 0

    def test_mitre_techniques_not_a_list(self, adapter):
        """Non-list mitre_techniques should not crash."""
        event = {
            "event_type": "protocol_threat",
            "mitre_techniques": "T1234",
            "data": {},
        }
        telemetry = adapter._dict_to_telemetry(event)
        # String is not a list/tuple, so mitre_techniques should be empty
        sec = telemetry.events[0].security_event
        assert len(sec.mitre_techniques) == 0

    def test_large_data_dict(self, adapter):
        """Large data dict should be handled without issues."""
        event = {
            "event_type": "protocol_threat",
            "data": {f"key_{i}": f"value_{i}" for i in range(100)},
        }
        telemetry = adapter._dict_to_telemetry(event)
        assert len(telemetry.events[0].attributes) == 100

    def test_nested_data_values_stringified(self, adapter):
        """Nested dicts/lists in data should be str()-ified."""
        event = {
            "event_type": "protocol_threat",
            "data": {
                "indicators": ["a", "b", "c"],
                "metadata": {"nested": True},
            },
        }
        telemetry = adapter._dict_to_telemetry(event)
        attrs = dict(telemetry.events[0].attributes)
        assert attrs["indicators"] == "['a', 'b', 'c']"
        assert "nested" in attrs["metadata"]

    def test_event_timestamp_ns_custom(self, adapter):
        """Custom event_timestamp_ns should be forwarded."""
        custom_ts = 1700000000000000000
        event = {"event_type": "METRIC", "event_timestamp_ns": custom_ts}
        telemetry = adapter._dict_to_telemetry(event)
        assert telemetry.events[0].event_timestamp_ns == custom_ts

    def test_event_id_custom(self, adapter):
        """Custom event_id should be forwarded."""
        event = {"event_type": "METRIC", "event_id": "custom-id-123"}
        telemetry = adapter._dict_to_telemetry(event)
        assert telemetry.events[0].event_id == "custom-id-123"


# ---------------------------------------------------------------------------
# Envelope signing
# ---------------------------------------------------------------------------


class TestEnvelopeSigning:
    """Tests for Ed25519 signing at enqueue + UniversalEnvelope at drain."""

    @pytest.fixture
    def ed25519_key_path(self, tmp_path):
        """Generate a fresh Ed25519 keypair and return the private key path."""
        from cryptography.hazmat.primitives.asymmetric import ed25519 as ed_mod

        sk = ed_mod.Ed25519PrivateKey.generate()
        key_path = str(tmp_path / "agent.ed25519")
        raw = sk.private_bytes_raw()
        with open(key_path, "wb") as f:
            f.write(raw)
        return key_path

    @pytest.fixture
    def signed_adapter(self, tmp_path, ed25519_key_path):
        """Adapter with signing enabled."""
        return LocalQueueAdapter(
            queue_path=str(tmp_path / "signed_queue.db"),
            agent_name="test_agent",
            device_id="test-device",
            signing_key_path=ed25519_key_path,
        )

    def test_signing_enabled_property(self, signed_adapter):
        """signing_enabled should be True when key is loaded."""
        assert signed_adapter.signing_enabled is True

    def test_signing_disabled_without_key(self, adapter):
        """Default adapter (no key) should have signing_enabled=False."""
        assert adapter.signing_enabled is False

    def test_signing_disabled_bad_path(self, tmp_path):
        """Non-existent key path should gracefully disable signing."""
        a = LocalQueueAdapter(
            queue_path=str(tmp_path / "q.db"),
            agent_name="test",
            device_id="test",
            signing_key_path="/nonexistent/key",
        )
        assert a.signing_enabled is False

    def test_enqueue_stores_content_hash(self, signed_adapter):
        """Enqueue should store SHA-256 content_hash in queue row."""
        import hashlib

        event = {"event_type": "METRIC", "severity": "INFO"}
        signed_adapter.enqueue(event)

        # Read raw queue row
        row = signed_adapter.queue.db.execute(
            "SELECT content_hash, sig, prev_sig FROM queue LIMIT 1"
        ).fetchone()
        content_hash, sig, prev_sig = row

        assert content_hash is not None
        assert len(bytes(content_hash)) == 32  # SHA-256 = 32 bytes

    def test_enqueue_stores_signature(self, signed_adapter):
        """Enqueue with signing key should store 64-byte Ed25519 sig."""
        event = {"event_type": "METRIC", "severity": "INFO"}
        signed_adapter.enqueue(event)

        row = signed_adapter.queue.db.execute(
            "SELECT sig FROM queue LIMIT 1"
        ).fetchone()
        sig = row[0]

        assert sig is not None
        assert len(bytes(sig)) == 64  # Ed25519 signature = 64 bytes

    def test_content_hash_without_signing_key(self, adapter):
        """Even without a key, content_hash should be stored."""
        event = {"event_type": "METRIC", "severity": "INFO"}
        adapter.enqueue(event)

        row = adapter.queue.db.execute(
            "SELECT content_hash, sig FROM queue LIMIT 1"
        ).fetchone()
        content_hash, sig = row

        assert content_hash is not None
        assert len(bytes(content_hash)) == 32
        assert sig is None  # No key → no signature

    def test_prev_sig_chain(self, signed_adapter):
        """Each enqueue should chain prev_sig from previous sig."""
        for i in range(3):
            signed_adapter.enqueue({"event_type": "METRIC", "severity": "INFO"})

        rows = signed_adapter.queue.db.execute(
            "SELECT sig, prev_sig FROM queue ORDER BY id"
        ).fetchall()

        # First row: prev_sig should be NULL (empty chain start)
        assert rows[0][1] is None

        # Second row: prev_sig should equal first row's sig
        assert bytes(rows[1][1]) == bytes(rows[0][0])

        # Third row: prev_sig should equal second row's sig
        assert bytes(rows[2][1]) == bytes(rows[1][0])

    def test_signature_verifies(self, signed_adapter, ed25519_key_path):
        """Stored signature should verify against stored content_hash."""
        from amoskys.common.crypto.signing import load_public_key, verify

        # We need the public key — derive from private key
        from cryptography.hazmat.primitives.asymmetric import ed25519 as ed_mod
        from cryptography.hazmat.primitives import serialization

        with open(ed25519_key_path, "rb") as f:
            sk = ed_mod.Ed25519PrivateKey.from_private_bytes(f.read())
        pk = sk.public_key()

        signed_adapter.enqueue({"event_type": "METRIC", "severity": "INFO"})

        row = signed_adapter.queue.db.execute(
            "SELECT content_hash, sig FROM queue LIMIT 1"
        ).fetchone()
        content_hash = bytes(row[0])
        sig = bytes(row[1])

        assert verify(pk, content_hash, sig) is True

    def test_drain_produces_signed_envelope(self, signed_adapter):
        """drain() should produce UniversalEnvelope with sig fields."""
        signed_adapter.enqueue({"event_type": "METRIC", "severity": "INFO"})

        captured = []

        def capture_fn(events):
            captured.extend(events)

        signed_adapter.drain(capture_fn, limit=1)

        assert len(captured) == 1
        envelope = captured[0]

        assert envelope.sig  # non-empty bytes
        assert len(envelope.sig) == 64
        assert envelope.signing_algorithm == "Ed25519"
        assert envelope.version == "1.0"
        assert envelope.HasField("device_telemetry")

    def test_drain_unsigned_still_wraps_envelope(self, adapter):
        """drain() without signing should still produce UniversalEnvelope."""
        adapter.enqueue({"event_type": "METRIC", "severity": "INFO"})

        captured = []

        def capture_fn(events):
            captured.extend(events)

        adapter.drain(capture_fn, limit=1)

        assert len(captured) == 1
        envelope = captured[0]

        assert envelope.version == "1.0"
        assert envelope.HasField("device_telemetry")
        assert envelope.sig == b""  # No signature
        assert envelope.signing_algorithm == ""  # Not set
