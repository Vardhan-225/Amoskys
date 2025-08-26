from InfraSpectre.proto_stubs import messaging_schema_pb2 as pb

def canonical_bytes(env: pb.Envelope) -> bytes:
    clone = pb.Envelope()
    clone.version = env.version
    clone.ts_ns = env.ts_ns
    clone.idempotency_key = env.idempotency_key
    which = env.WhichOneof("payload")
    if which == "flow":
        clone.flow.CopyFrom(env.flow)
    elif which == "proc":
        clone.proc.CopyFrom(env.proc)
    return clone.SerializeToString()
