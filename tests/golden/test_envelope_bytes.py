import hashlib
import pathlib

from amoskys.proto import messaging_schema_pb2 as pb

GOLD = pathlib.Path("tests/golden/envelope_v1.bin")
HASH = pathlib.Path("tests/golden/envelope_v1.sha256")


def serialize_sample() -> bytes:
    env = pb.Envelope(
        version="v1",
        ts_ns=123456789,
        idempotency_key="abc",
        flow=pb.FlowEvent(
            src_ip="1.1.1.1",
            dst_ip="8.8.8.8",
            src_port=1111,
            dst_port=53,
            protocol="UDP",
            bytes_sent=10,
            bytes_recv=20,
            flags=0,
            start_time=1,
            end_time=2,
            bytes_tx=1,
            bytes_rx=2,
            proto="UDP",
            duration_ms=3,
        ),
        sig=b"",
        prev_sig=b"",
    )
    return env.SerializeToString()


def test_golden_envelope_bytes():
    data = serialize_sample()
    # first run: write fixtures (uncomment intentionally once)
    GOLD.write_bytes(data)
    HASH.write_text(hashlib.sha256(data).hexdigest())
    assert GOLD.exists() and HASH.exists(), "Golden fixtures missing"
    assert data == GOLD.read_bytes(), "Envelope bytes changed"
    assert hashlib.sha256(data).hexdigest() == HASH.read_text().strip(), "Hash mismatch"
