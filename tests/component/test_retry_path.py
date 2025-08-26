import os, sys, time, socket, subprocess
import grpc, pytest
from InfraSpectre.proto_stubs import messaging_schema_pb2 as pb
from InfraSpectre.proto_stubs import messaging_schema_pb2_grpc as pbrpc

BUS_ADDR = "localhost:50051"

def wait_for_port(port: int, timeout=6.0):
    import time, socket
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket() as s:
            s.settimeout(0.2)
            try:
                s.connect(("127.0.0.1", port))
                return True
            except OSError:
                time.sleep(0.1)
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
    env["BUS_OVERLOAD"] = "1"
    env["PYTHONUNBUFFERED"] = "1"  # Force unbuffered output
    
    # Ensure proper Python path for imports
    repo_root = os.path.abspath(os.path.dirname(__file__) + "/../..")
    env["PYTHONPATH"] = repo_root
    
    # Use absolute paths
    python_path = os.path.join(repo_root, "InfraSpectre/.venv/bin/python")
    server_path = os.path.join(repo_root, "InfraSpectre/common/eventbus/server.py")
    
    print("[DEBUG] Starting server with environment:")
    for k, v in sorted(env.items()):
        print(f"[DEBUG]   {k}={v}")
    print("[DEBUG] Server path:", server_path)
    sys.stdout.flush()
    
    # Start server with environment and capture output
    p = subprocess.Popen(
        [python_path, "-u", server_path],  # -u for unbuffered output
        env=env,
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )

    def log_output():
        while True:
            line = p.stdout.readline()
            if not line and p.poll() is not None:
                break
            if line:
                print("[SERVER]", line.rstrip())
                sys.stdout.flush()

    # Start thread to log server output
    import threading
    log_thread = threading.Thread(target=log_output, daemon=True)
    log_thread.start()
    
    assert wait_for_port(50051), "bus failed to start"
    yield p
    p.terminate()
    try:
        p.wait(timeout=2)
    except subprocess.TimeoutExpired:
        p.kill()
    finally:
        # Print any remaining output
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
        ack = stub.Publish(make_valid_env(), timeout=3.0)
        assert ack.status == pb.PublishAck.RETRY
        assert "overload" in (ack.reason or "").lower()
        assert ack.backoff_hint_ms >= 0
