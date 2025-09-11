import os, time, subprocess, socket, pathlib
import grpc, pytest
from infraspectre.proto import messaging_schema_pb2 as pb
from infraspectre.proto import messaging_schema_pb2_grpc as pbrpc

def wait_port(port, timeout=8):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket() as s:
            s.settimeout(0.2)
            try:
                s.connect(("127.0.0.1", port)); return True
            except OSError: time.sleep(0.1)
    return False

@pytest.fixture(scope="session", autouse=True)
def ensure_certs():
    if not pathlib.Path("certs/ca.crt").exists():
        pytest.skip("generate certs first: make certs && make ed25519")

def mtls_channel():
    with open("certs/ca.crt","rb") as f: ca=f.read()
    with open("certs/agent.crt","rb") as f: crt=f.read()
    with open("certs/agent.key","rb") as f: key=f.read()
    creds = grpc.ssl_channel_credentials(root_certificates=ca, private_key=key, certificate_chain=crt)
    return grpc.secure_channel("localhost:50051", creds)

def make_env(i=0):
    flow = pb.FlowEvent(src_ip="1.1.1.1", dst_ip="8.8.8.8", src_port=1, dst_port=53, proto="UDP", bytes_tx=1, bytes_rx=2, duration_ms=3)
    env = pb.Envelope(version="v1", ts_ns=int(time.time_ns()), idempotency_key=f"k{i}", flow=flow, sig=b"", prev_sig=b"")
    return env

def test_wal_grows_then_drains():
    import sys
    env = os.environ.copy(); env["BUS_OVERLOAD"]="1"
    bus = subprocess.Popen([sys.executable, "src/infraspectre/eventbus/server.py"], env=env)
    assert wait_port(50051)
    agent = subprocess.Popen([sys.executable, "src/infraspectre/agents/flowagent/main.py"])
    assert wait_port(8081)
    time.sleep(1.0)
    with mtls_channel() as ch:
        stub = pbrpc.EventBusStub(ch)
        for i in range(10):
            stub.Publish(make_env(i), timeout=2.0)
    import urllib.request
    body = urllib.request.urlopen("http://localhost:8081/healthz", timeout=2).read().decode()
    assert "wal_bytes=" in body
    bus.terminate(); bus.wait(timeout=2)
    env["BUS_OVERLOAD"]="0"
    bus2 = subprocess.Popen(["python","InfraSpectre/common/eventbus/server.py"], env=env)
    assert wait_port(50051)
    time.sleep(3.0)
    body2 = urllib.request.urlopen("http://localhost:8081/healthz", timeout=2).read().decode()
    assert "wal_bytes=" in body2
    bytes_now = int(body2.split("wal_bytes=")[1])
    assert bytes_now == 0 or bytes_now < int(body.split("wal_bytes=")[1])
    agent.terminate(); agent.wait(timeout=2)
    bus2.terminate(); bus2.wait(timeout=2)
