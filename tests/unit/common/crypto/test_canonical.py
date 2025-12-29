"""
Tests for Canonical Serialization Module

Security-critical tests for deterministic protobuf serialization.
These tests ensure signature consistency and prevent signature bypass attacks.
"""

import pytest

from amoskys.common.crypto import canonical
from amoskys.proto import messaging_schema_pb2 as pb


class TestCanonicalSerialization:
    """Test canonical byte representation generation."""

    def test_canonical_basic_envelope(self):
        """Verify canonical serialization of basic envelope."""
        env = pb.Envelope()
        env.version = "v1"
        env.ts_ns = 1234567890
        env.idempotency_key = "test-key-123"

        canonical_bytes = canonical.canonical_bytes(env)

        assert isinstance(canonical_bytes, bytes)
        assert len(canonical_bytes) > 0

    def test_canonical_with_flow_event(self):
        """Verify canonical serialization includes flow payload."""
        env = pb.Envelope()
        env.version = "v1"
        env.ts_ns = 1234567890
        env.idempotency_key = "test-key-123"

        # Add flow event
        env.flow.src_ip = "192.168.1.1"
        env.flow.dst_ip = "10.0.0.1"
        env.flow.src_port = 12345
        env.flow.dst_port = 80

        canonical_bytes = canonical.canonical_bytes(env)

        assert isinstance(canonical_bytes, bytes)
        assert len(canonical_bytes) > 0

        # Verify flow data is included by parsing back
        clone = pb.Envelope()
        clone.ParseFromString(canonical_bytes)
        assert clone.flow.src_ip == "192.168.1.1"
        assert clone.flow.dst_ip == "10.0.0.1"

    def test_canonical_deterministic(self):
        """Verify canonical serialization is deterministic."""
        env = pb.Envelope()
        env.version = "v1"
        env.ts_ns = 9999999999
        env.idempotency_key = "determinism-test"
        env.flow.src_ip = "1.2.3.4"
        env.flow.dst_ip = "5.6.7.8"

        # Generate canonical bytes multiple times
        bytes1 = canonical.canonical_bytes(env)
        bytes2 = canonical.canonical_bytes(env)
        bytes3 = canonical.canonical_bytes(env)

        # All should be identical
        assert bytes1 == bytes2
        assert bytes2 == bytes3

    def test_canonical_excludes_signature_field(self):
        """Verify signature field is excluded from canonical form."""
        env = pb.Envelope()
        env.version = "v1"
        env.ts_ns = 1111111111
        env.idempotency_key = "sig-test"

        # Generate canonical without signature
        bytes_without_sig = canonical.canonical_bytes(env)

        # Add signature field
        env.sig = b"fake signature bytes" * 3  # 60 bytes

        # Generate canonical with signature
        bytes_with_sig = canonical.canonical_bytes(env)

        # Should be identical (sig field excluded)
        assert bytes_without_sig == bytes_with_sig

    def test_canonical_excludes_prev_sig_field(self):
        """Verify prev_sig field is excluded from canonical form."""
        env = pb.Envelope()
        env.version = "v1"
        env.ts_ns = 2222222222
        env.idempotency_key = "prev-sig-test"

        # Generate canonical without prev_sig
        bytes_without = canonical.canonical_bytes(env)

        # Add prev_sig field
        env.prev_sig = b"previous signature" * 4

        # Generate canonical with prev_sig
        bytes_with = canonical.canonical_bytes(env)

        # Should be identical (prev_sig excluded)
        assert bytes_without == bytes_with

    def test_canonical_empty_envelope(self):
        """Verify canonical serialization of minimal envelope."""
        env = pb.Envelope()
        env.version = ""
        env.ts_ns = 0
        env.idempotency_key = ""

        canonical_bytes = canonical.canonical_bytes(env)

        assert isinstance(canonical_bytes, bytes)
        # Even empty envelope should serialize
        assert len(canonical_bytes) >= 0

    def test_canonical_different_envelopes_different_bytes(self):
        """Verify different envelopes produce different canonical bytes."""
        env1 = pb.Envelope()
        env1.version = "v1"
        env1.ts_ns = 1000
        env1.idempotency_key = "key1"

        env2 = pb.Envelope()
        env2.version = "v1"
        env2.ts_ns = 2000  # Different timestamp
        env2.idempotency_key = "key1"

        bytes1 = canonical.canonical_bytes(env1)
        bytes2 = canonical.canonical_bytes(env2)

        assert bytes1 != bytes2

    def test_canonical_with_empty_flow(self):
        """Verify empty flow field is handled correctly."""
        env = pb.Envelope()
        env.version = "v1"
        env.ts_ns = 3333333333
        env.idempotency_key = "empty-flow-test"

        # Flow exists but is empty (ByteSize() == 0)
        assert env.flow.ByteSize() == 0

        canonical_bytes = canonical.canonical_bytes(env)

        # Parse back to verify flow is not included when empty
        clone = pb.Envelope()
        clone.ParseFromString(canonical_bytes)
        assert clone.flow.ByteSize() == 0


class TestCanonicalIntegrity:
    """Test canonical form integrity properties."""

    def test_canonical_preserves_semantic_fields(self):
        """Verify all semantic fields are preserved in canonical form."""
        env = pb.Envelope()
        env.version = "v1.2.3"
        env.ts_ns = 1234567890123456789
        env.idempotency_key = "unique-key-12345"
        env.flow.src_ip = "192.168.100.1"
        env.flow.dst_ip = "10.20.30.40"
        env.flow.src_port = 50000
        env.flow.dst_port = 443

        canonical_bytes = canonical.canonical_bytes(env)

        # Parse canonical bytes back to envelope
        clone = pb.Envelope()
        clone.ParseFromString(canonical_bytes)

        # Verify all semantic fields preserved
        assert clone.version == env.version
        assert clone.ts_ns == env.ts_ns
        assert clone.idempotency_key == env.idempotency_key
        assert clone.flow.src_ip == env.flow.src_ip
        assert clone.flow.dst_ip == env.flow.dst_ip
        assert clone.flow.src_port == env.flow.src_port
        assert clone.flow.dst_port == env.flow.dst_port

    def test_canonical_field_order_independent(self):
        """Verify canonical form is independent of field setting order."""
        # Create envelope with fields in one order
        env1 = pb.Envelope()
        env1.ts_ns = 9999
        env1.version = "v1"
        env1.idempotency_key = "order-test"

        # Create envelope with fields in different order
        env2 = pb.Envelope()
        env2.idempotency_key = "order-test"
        env2.version = "v1"
        env2.ts_ns = 9999

        # Canonical bytes should be identical
        bytes1 = canonical.canonical_bytes(env1)
        bytes2 = canonical.canonical_bytes(env2)

        assert bytes1 == bytes2

    def test_canonical_immutability(self):
        """Verify generating canonical bytes doesn't modify original envelope."""
        env = pb.Envelope()
        env.version = "v1"
        env.ts_ns = 5555
        env.idempotency_key = "immutable-test"
        env.sig = b"original signature"
        env.prev_sig = b"original prev_sig"

        # Save original state
        original_sig = env.sig
        original_prev_sig = env.prev_sig

        # Generate canonical bytes
        canonical.canonical_bytes(env)

        # Verify envelope unchanged
        assert env.sig == original_sig
        assert env.prev_sig == original_prev_sig


class TestCanonicalSecurityProperties:
    """Test security properties of canonical serialization."""

    def test_canonical_prevents_signature_bypass(self):
        """Verify adding signature doesn't change canonical representation.

        This prevents attacks where attacker modifies message and claims
        signature was added after canonical form was generated.
        """
        env = pb.Envelope()
        env.version = "v1"
        env.ts_ns = 7777777777
        env.idempotency_key = "bypass-test"

        # Get canonical before signing
        canonical_before = canonical.canonical_bytes(env)

        # Add signature (simulating signing process)
        env.sig = b"x" * 64  # 64-byte Ed25519 signature

        # Get canonical after signing
        canonical_after = canonical.canonical_bytes(env)

        # Should be identical - signature excluded
        assert canonical_before == canonical_after

    def test_canonical_consistent_across_copies(self):
        """Verify canonical form is same for copied envelopes."""
        env = pb.Envelope()
        env.version = "v2"
        env.ts_ns = 8888888888
        env.idempotency_key = "copy-test"
        env.flow.src_ip = "1.1.1.1"

        # Create copy
        env_copy = pb.Envelope()
        env_copy.CopyFrom(env)

        bytes_original = canonical.canonical_bytes(env)
        bytes_copy = canonical.canonical_bytes(env_copy)

        assert bytes_original == bytes_copy

    def test_canonical_timestamp_sensitivity(self):
        """Verify canonical form changes with timestamp (replay protection)."""
        base_env = pb.Envelope()
        base_env.version = "v1"
        base_env.idempotency_key = "replay-test"

        # Same envelope with different timestamps
        env1 = pb.Envelope()
        env1.CopyFrom(base_env)
        env1.ts_ns = 1000000000

        env2 = pb.Envelope()
        env2.CopyFrom(base_env)
        env2.ts_ns = 1000000001  # 1 nanosecond later

        bytes1 = canonical.canonical_bytes(env1)
        bytes2 = canonical.canonical_bytes(env2)

        # Different timestamps = different canonical bytes = different signatures
        assert bytes1 != bytes2

    def test_canonical_idempotency_key_sensitivity(self):
        """Verify canonical form changes with idempotency key (dedup)."""
        base_env = pb.Envelope()
        base_env.version = "v1"
        base_env.ts_ns = 9999999999

        env1 = pb.Envelope()
        env1.CopyFrom(base_env)
        env1.idempotency_key = "request-1"

        env2 = pb.Envelope()
        env2.CopyFrom(base_env)
        env2.idempotency_key = "request-2"

        bytes1 = canonical.canonical_bytes(env1)
        bytes2 = canonical.canonical_bytes(env2)

        # Different idempotency keys = different canonical bytes
        assert bytes1 != bytes2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
