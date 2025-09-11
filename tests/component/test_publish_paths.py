import os
import time
import socket
import subprocess
from pathlib import Path

import grpc
import pytest

from infraspectre.proto import messaging_schema_pb2 as pb
from infraspectre.proto import messaging_schema_pb2_grpc as pbrpc

CERT_DIR = Path("certs")
SERVER_CMD = ["python", "src/infraspectre/eventbus/server.py"]
BUS_ADDR = "localhost:50051"

def wait_for_port(host: str, port: int, timeout: float = 5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            try:
                s.connect((host, port))
                return True
            except OSError:
                time.sleep(0.1)
    return False

@pytest.fixture(scope="session")
def certs_available():
    need = ["ca.crt", "agent.crt", "agent.key"]
    missing = [p for p in need if not (CERT_DIR / p).exists()]
    if missing:
        pytest.skip(f"certs missing: {missing} (run `make certs` first)")

@pytest.fixture(scope="session")
def bus_process(certs_available):
    proc = subprocess.Popen(SERVER_CMD, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ok = wait_for_port("127.0.0.1", 50051, timeout=6.0)
    if not ok:
        try:
            out, err = proc.communicate(timeout=1.0)
        except Exception:
            out = b""; err = b""
        proc.kill()
        raise RuntimeError(f"EventBus failed to start: {err.decode() or out.decode()}")
    yield proc
    proc.terminate()
    try:
        proc.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        proc.kill()

def mtls_channel():
    with open(CERT_DIR / "ca.crt", "rb") as f:
        ca = f.read()
    with open(CERT_DIR / "agent.crt", "rb") as f:
        crt = f.read()
    with open(CERT_DIR / "agent.key", "rb") as f:
        key = f.read()
    creds = grpc.ssl_channel_credentials(root_certificates=ca, private_key=key, certificate_chain=crt)
    return grpc.secure_channel(BUS_ADDR, creds)

def make_valid_envelope():
    flow = pb.FlowEvent(src_ip="1.1.1.1", dst_ip="8.8.8.8", src_port=1, dst_port=53, proto="UDP", bytes_tx=1, bytes_rx=2, duration_ms=3)
    env = pb.Envelope(version="v1", ts_ns=int(time.time_ns()), idempotency_key="z1", flow=flow, sig=b"", prev_sig=b"")
    return env

def test_publish_ok(bus_process):
    with mtls_channel() as ch:
        stub = pbrpc.EventBusStub(ch)
        ack = stub.Publish(make_valid_envelope(), timeout=3.0)
        assert ack.status == pb.PublishAck.OK
        assert ack.reason in ("accepted", "")

def test_publish_invalid_missing_fields(bus_process):
    env = pb.Envelope(version="v1", ts_ns=int(time.time_ns()))
    with mtls_channel() as ch:
        stub = pbrpc.EventBusStub(ch)
        ack = stub.Publish(env, timeout=3.0)
        assert ack.status == pb.PublishAck.INVALID
        assert "missing" in (ack.reason or "").lower()
