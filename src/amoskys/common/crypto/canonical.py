from amoskys.proto import messaging_schema_pb2 as pb

def canonical_bytes(env: pb.Envelope) -> bytes:
    clone = pb.Envelope()
    clone.version = env.version
    clone.ts_ns = env.ts_ns
    clone.idempotency_key = env.idempotency_key
    # Only handle flow field as per current protobuf schema
    if hasattr(env, 'flow') and env.flow.ByteSize() > 0:
        clone.flow.CopyFrom(env.flow)
    return clone.SerializeToString()
