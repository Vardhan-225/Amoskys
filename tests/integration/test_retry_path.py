import os
import socket
import subprocess
import sys
import time

import grpc
import pytest

# Add src to path for clean imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from amoskys.proto import messaging_schema_pb2 as pb
from amoskys.proto import messaging_schema_pb2_grpc as pbrpc

SERVER_SCRIPT = "src/amoskys/eventbus/server.py"
SERVER_ARGS = ["--overload", "on"]


def find_free_port():
    """Find a free port to use for the test."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port


def wait_for_port(port: int, timeout=10.0):
    import socket
    import time

    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket() as s:
            s.settimeout(1.0)
            try:
                s.connect(("127.0.0.1", port))
                # Give the server a moment to fully initialize
                time.sleep(0.5)
                return True
            except OSError:
                time.sleep(0.2)
    return False


@pytest.fixture(scope="session")
def certs():
    import pathlib

    p = pathlib.Path("certs")
    need = ["ca.crt", "agent.crt", "agent.key"]
    if not all((p / f).exists() for f in need):
        pytest.skip("certs missing; run `make certs`")


def mtls_channel(port: int):
    from pathlib import Path

    with open(Path("certs") / "ca.crt", "rb") as f:
        ca = f.read()
    with open(Path("certs") / "agent.crt", "rb") as f:
        crt = f.read()
    with open(Path("certs") / "agent.key", "rb") as f:
        key = f.read()
    creds = grpc.ssl_channel_credentials(
        root_certificates=ca, private_key=key, certificate_chain=crt
    )
    return grpc.secure_channel(f"localhost:{port}", creds)


@pytest.fixture
def bus_overloaded(certs):
    # Find a free port dynamically to avoid conflicts
    server_port = find_free_port()
    
    env = os.environ.copy()
    env["BUS_SERVER_PORT"] = str(server_port)
    env["BUS_METRICS_DISABLE"] = "1"  # Disable metrics to avoid port contention
    # Set up environment to ensure the subprocess can find imports
    if "PYTHONPATH" in env:
        env["PYTHONPATH"] = f"src:{env['PYTHONPATH']}"
    else:
        env["PYTHONPATH"] = "src"

    repo_root = os.path.abspath(os.path.dirname(__file__) + "/../..")
    python_path = sys.executable
    server_path = os.path.join(repo_root, "src", "amoskys", "eventbus", "server.py")

    print("[TEST] Starting server with environment:")
    for k, v in sorted(env.items()):
        if k in ["BUS_SERVER_PORT", "BUS_METRICS_DISABLE"]:
            print(f"[TEST]   {k}={v}")
    print("[TEST] Server path:", server_path)
    sys.stdout.flush()

    p = subprocess.Popen(
        [python_path, "-u", server_path, "--overload", "on"],
        env=env,
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,  # Line buffered
    )

    try:
        if not wait_for_port(server_port):
            out, err = p.communicate(timeout=5)
            print("[SERVER] Startup stdout:", out)
            print("[SERVER] Startup stderr:", err)
            raise AssertionError("bus failed to start")
        yield (p, server_port)
    finally:
        p.terminate()
        try:
            p.wait(timeout=2)
        except subprocess.TimeoutExpired:
            p.kill()
        finally:
            out, err = p.communicate()
            if out:
                print("[SERVER] Final output:", out)
            if err:
                print("[SERVER] Final errors:", err)


def make_valid_env():
    flow = pb.FlowEvent(
        src_ip="1.1.1.1",
        dst_ip="8.8.8.8",
        src_port=1,
        dst_port=53,
        proto="UDP",
        bytes_tx=1,
        bytes_rx=2,
        duration_ms=3,
    )
    env = pb.Envelope(
        version="v1",
        ts_ns=int(time.time_ns()),
        idempotency_key="z1",
        flow=flow,
        sig=b"",
        prev_sig=b"",
    )
    return env


def test_retry_ack_when_overloaded(bus_overloaded):
    _proc, port = bus_overloaded
    with mtls_channel(port) as ch:
        stub = pbrpc.EventBusStub(ch)
        print("[TEST] Sending Publish request...")
        ack = stub.Publish(make_valid_env(), timeout=3.0)
        print(f"[TEST] Received response: status={ack.status}, reason={ack.reason}")
        assert ack.status == pb.PublishAck.RETRY
        assert "overload" in (ack.reason or "").lower()
        assert ack.backoff_hint_ms >= 0
