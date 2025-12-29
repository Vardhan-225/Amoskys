"""Canonical Serialization for Cryptographic Signatures.

This module provides deterministic, canonical serialization of protobuf
messages for signature generation and verification. Canonical form ensures
that semantically equivalent messages produce identical byte representations,
which is critical for signature verification.

Why Canonical Form Matters:
    - Protobuf serialization is NOT deterministic by default
    - Unknown fields, field order, and optional fields can vary
    - Signatures must be over a consistent byte representation
    - Canon form excludes signature fields to prevent circular dependency

Fields Excluded from Canonical Form:
    - sig: The signature itself (would create circular dependency)
    - prev_sig: Previous signature (not part of current message semantics)

Fields Included in Canonical Form:
    - version: Protocol version
    - ts_ns: Timestamp (nanoseconds since epoch)
    - idempotency_key: Deduplication key
    - flow: FlowEvent payload (if present)

Security Note:
    Changing canonical form breaks signature compatibility. Any modification
    to field selection or serialization order requires re-signing all data.
"""

from amoskys.proto import messaging_schema_pb2 as pb


def canonical_bytes(env: pb.Envelope) -> bytes:
    """Convert Envelope to canonical byte representation for signing.

    Creates a deterministic serialization of the envelope by copying only
    semantic fields (excluding signature fields) to a clean protobuf instance.
    This ensures consistent byte representation for Ed25519 signing.

    Args:
        env: Source envelope (may contain signature fields)

    Returns:
        bytes: Canonical protobuf serialization suitable for signing

    Canonical Form includes:
        - version, ts_ns, idempotency_key (always)
        - flow payload (if present and non-empty)

    Canonical Form excludes:
        - sig, prev_sig (to prevent circular dependencies)
        - Unknown/extension fields
        - Optional fields with default values

    Example:
        >>> env = make_envelope(flow_event)  # sig field is empty
        >>> canonical = canonical_bytes(env)
        >>> signature = sign(private_key, canonical)
        >>> env.sig = signature  # Now add signature
    """
    clone = pb.Envelope()
    clone.version = env.version
    clone.ts_ns = env.ts_ns
    clone.idempotency_key = env.idempotency_key
    # Only handle flow field as per current protobuf schema
    if hasattr(env, "flow") and env.flow.ByteSize() > 0:
        clone.flow.CopyFrom(env.flow)
    return clone.SerializeToString()
