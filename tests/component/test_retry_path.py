import os, sys, time, socket, subprocess
import grpc, pytest
from InfraSpectre.proto_stubs import messaging_schema_pb2 as pb
from InfraSpectre.proto_stubs import messaging_schema_pb2_grpc as pbrpc
import threading

BUS_ADDR = "localhost:50051"
SERVER_SCRIPT = "InfraSpectre/common/eventbus/server.py"
SERVER_ARGS = ["--overload", "on"]

def wait_for_port(port: int, timeout=10.0):
    import time, socket
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
    if not all((p/f).exists() for f in need):
        pytest.skip("certs missing; run `make certs`")

def mtls_channel():
    from pathlib import Path
    with open(Path("certs")/"ca.crt","rb") as f: ca=f.read()
    with open(Path("certs")/"agent.crt","rb") as f: crt=f.read()
    with open(Path("certs")/"agent.key","rb") as f: key=f.read()
    creds = grpc.ssl_channel_credentials(root_certificates=ca, private_key=key, certificate_chain=crt)
    return grpc.secure_channel(BUS_ADDR, creds)

@pytest.fixture
def bus_overloaded(certs):
    env = os.environ.copy()
    env["BUS_SERVER_PORT"] = "50051"
    env["BUS_METRICS_DISABLE"] = "1"  # Disable metrics to avoid port contention

    repo_root = os.path.abspath(os.path.dirname(__file__) + "/../..")
    python_path = sys.executable
    server_path = os.path.join(repo_root, "InfraSpectre", "common", "eventbus", "server.py")

    print("[TEST] Starting server with environment:")
    for k, v in sorted(env.items()):
        if k in ["BUS_SERVER_PORT", "BUS_METRICS_DISABLE"]:
            print(f"[TEST]   {k}={v}")
    print("[TEST] Server path:", server_path)
    sys.stdout.flush()

    # Reset _OVERLOAD before starting the server
    global _OVERLOAD
    _OVERLOAD = None

    p = subprocess.Popen(
        [python_path, "-u", server_path, "--overload", "on"],
        env=env,
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1  # Line buffered
    )

    try:
        if not wait_for_port(50051):
            out, err = p.communicate(timeout=5)
            print("[SERVER] Startup stdout:", out)
            print("[SERVER] Startup stderr:", err)
            raise AssertionError("bus failed to start")
        yield p
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
    flow = pb.FlowEvent(src_ip="1.1.1.1", dst_ip="8.8.8.8", src_port=1, dst_port=53, proto="UDP", bytes_tx=1, bytes_rx=2, duration_ms=3)
    env = pb.Envelope(version="v1", ts_ns=int(time.time_ns()), idempotency_key="z1", flow=flow, sig=b"", prev_sig=b"")
    return env

def test_retry_ack_when_overloaded(bus_overloaded):
    with mtls_channel() as ch:
        stub = pbrpc.EventBusStub(ch)
        print("[TEST] Sending Publish request...")
        ack = stub.Publish(make_valid_env(), timeout=3.0)
        print(f"[TEST] Received response: status={ack.status}, reason={ack.reason}")
        assert ack.status == pb.PublishAck.RETRY
        assert "overload" in (ack.reason or "").lower()
        assert ack.backoff_hint_ms >= 0
