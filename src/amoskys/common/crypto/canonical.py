"""Canonical Serialization for Cryptographic Signatures.

This module provides deterministic, canonical serialization of protobuf
messages for signature generation and verification. Canonical form ensures
that semantically equivalent messages produce identical byte representations,
which is critical for signature verification.

Two canonical forms are provided:

1. ``canonical_bytes(env)`` — Legacy Envelope (messaging_schema.proto).
   Excludes sig and prev_sig.

2. ``universal_canonical_bytes(env)`` — UniversalEnvelope.
   Clears **only** ``sig`` (field 8).
   ``prev_sig`` is **included** — binding the chain link into the signature.
   See docs/proof/canonical_bytes_spec.md for the full field table.
"""

from typing import cast

from amoskys.proto import messaging_schema_pb2 as pb
from amoskys.proto import universal_telemetry_pb2 as upb


def canonical_bytes(env: pb.Envelope) -> bytes:
    """Legacy Envelope canonical form (excludes sig and prev_sig)."""
    clone = pb.Envelope()
    clone.version = env.version
    clone.ts_ns = env.ts_ns
    clone.idempotency_key = env.idempotency_key
    if hasattr(env, "flow") and env.flow.ByteSize() > 0:
        clone.flow.CopyFrom(env.flow)
    return cast(bytes, clone.SerializeToString())


def universal_canonical_bytes(env: upb.UniversalEnvelope) -> bytes:
    """UniversalEnvelope canonical form — full envelope with sig zeroed.

    Per the Canonical Bytes Spec (docs/proof/canonical_bytes_spec.md):
      - sig (field 8) is cleared to b"" (circular dependency)
      - prev_sig (field 9) is KEPT (binds chain link into signature)
      - All other fields are included as-is

    This means swapping prev_sig between two envelopes invalidates both
    signatures, making chain reordering detectable.
    """
    clone = upb.UniversalEnvelope()
    clone.CopyFrom(env)
    clone.sig = b""  # Only field excluded
    # prev_sig is NOT cleared — it is part of the signed payload
    return clone.SerializeToString()
