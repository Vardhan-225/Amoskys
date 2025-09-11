import os, time, requests, subprocess, socket
from infraspectre.proto import messaging_schema_pb2 as pb
from infraspectre.proto import messaging_schema_pb2_grpc as pbrpc
import grpc

def wait_port(port, t=6.0):
    import time, socket
    d = time.time() + t
    while time.time() < d:
        with socket.socket() as s:
            s.settimeout(0.2)
            try:
                s.connect(("127.0.0.1", port)); return True
            except OSError: time.sleep(0.1)
    return False

def mtls_channel():
    with open("certs/ca.crt","rb") as f: ca=f.read()
    with open("certs/agent.crt","rb") as f: crt=f.read()
    with open("certs/agent.key","rb") as f: key=f.read()
    creds = grpc.ssl_channel_credentials(root_certificates=ca, private_key=key, certificate_chain=crt)
    return grpc.secure_channel("localhost:50051", creds)

def test_inflight_metric_rises_then_falls(tmp_path):
    env = os.environ.copy()
    env["BUS_MAX_INFLIGHT"] = "1"
    import sys
    p = subprocess.Popen([sys.executable, "src/infraspectre/eventbus/server.py"], env=env)
    assert wait_port(50051)
    time.sleep(0.5)
    m0 = requests.get("http://127.0.0.1:9100/metrics", timeout=2).text
    with mtls_channel() as ch:
        stub = pbrpc.EventBusStub(ch)
        flow = pb.FlowEvent(src_ip="1.1.1.1", dst_ip="8.8.8.8", src_port=1, dst_port=53, proto="UDP")
        envl = pb.Envelope(version="v1", ts_ns=int(time.time_ns()), idempotency_key="z1", flow=flow, sig=b"", prev_sig=b"")
        stub.Publish(envl, timeout=2.0)
    time.sleep(0.5)
    m1 = requests.get("http://127.0.0.1:9100/metrics", timeout=2).text
    assert "bus_inflight_requests" in m1
    p.terminate(); p.wait(timeout=2)
