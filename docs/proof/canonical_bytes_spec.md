# Canonical Bytes Specification

**Version:** 1.0
**Applies to:** `UniversalEnvelope` (proto field layout in `universal_telemetry.proto`)

## Signed Payload Construction

To sign or verify a `UniversalEnvelope`, construct canonical bytes as follows:

```
envelope_copy = clone(envelope)
envelope_copy.sig = b""          # Clear signature field (circular dependency)
# prev_sig is NOT cleared — it is part of the signed payload
canonical_bytes = envelope_copy.SerializeToString()
```

## Field Coverage

| Envelope Field       | Field # | In Canonical Bytes | Rationale                          |
|----------------------|---------|--------------------|------------------------------------|
| `version`            | 1       | YES                | Protocol version binding           |
| `ts_ns`              | 2       | YES                | Timestamp integrity                |
| `idempotency_key`    | 3       | YES                | Prevents replay with altered idem  |
| `flow`               | 4       | YES (if set)       | Payload binding                    |
| `process`            | 5       | YES (if set)       | Payload binding                    |
| `device_telemetry`   | 6       | YES (if set)       | Payload binding                    |
| `telemetry_batch`    | 7       | YES (if set)       | Payload binding                    |
| **`sig`**            | 8       | **NO (zeroed)**    | Circular dependency                |
| **`prev_sig`**       | 9       | **YES**            | **Chain link bound to signature**  |
| `signing_algorithm`  | 10      | YES                | Algorithm binding                  |
| `certificate_chain`  | 11      | YES (if set)       | Certificate binding                |
| `priority`           | 12      | YES (if set)       | Routing integrity                  |
| `processing_hints`   | 13      | YES (if set)       | Processing integrity               |
| `target_processors`  | 14      | YES (if set)       | Routing integrity                  |
| `retry_count`        | 15      | YES                | Delivery state binding             |
| `max_processing_time`| 16      | YES (if set)       | QoS binding                        |
| `requires_ack`       | 17      | YES                | Delivery guarantee binding         |
| `schema_version`     | 18      | YES                | Schema binding                     |

## Critical Property

`prev_sig` (field 9) is **included** in the signed payload. Swapping `prev_sig`
between two envelopes invalidates both signatures. This binds the hash chain
link into the cryptographic signature, making chain reordering detectable.

## Signing Algorithm

- **Algorithm:** Ed25519
- **Key size:** 256-bit (32-byte private key, 32-byte public key)
- **Signature size:** 64 bytes
- **Signing:** `sig = Ed25519_sign(agent_private_key, canonical_bytes)`
- **Verification:** `Ed25519_verify(agent_public_key, canonical_bytes, sig)`

## Determinism

Protobuf `SerializeToString()` with deterministic=True is used. Fields are
serialized in field number order. Empty/default fields are omitted per proto3
semantics. The only field explicitly zeroed is `sig` (field 8).
