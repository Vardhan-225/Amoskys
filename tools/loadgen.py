import time, os, grpc, random, argparse, sys

# Add src directory to path for infraspectre imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from infraspectre.proto import messaging_schema_pb2 as pb, messaging_schema_pb2_grpc as pbrpc

def channel(cert_dir):
    with open(os.path.join(cert_dir,"ca.crt"),"rb") as f: ca=f.read()
    with open(os.path.join(cert_dir,"agent.crt"),"rb") as f: crt=f.read()
    with open(os.path.join(cert_dir,"agent.key"),"rb") as f: key=f.read()
    creds = grpc.ssl_channel_credentials(ca, key, crt)
    return grpc.secure_channel(os.getenv("BUS_ADDR","localhost:50051"), creds)

def flow(i):
    return pb.FlowEvent(src_ip="10.0.0."+str(i%250+1), dst_ip="8.8.8.8",
                        src_port=40000+(i%1000), dst_port=53, proto="UDP",
                        bytes_tx=128, bytes_rx=256, duration_ms=5)

def env(i):
    return pb.Envelope(version="v1", ts_ns=int(time.time_ns()),
                       idempotency_key=f"lg-{i}-{int(time.time()*1000)}",
                       flow=flow(i), sig=b"", prev_sig=b"")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--rate", type=int, default=200, help="events/sec")
    ap.add_argument("--secs", type=int, default=30)
    ap.add_argument("--certs", default="certs")
    args = ap.parse_args()
    with channel(args.certs) as ch:
        stub = pbrpc.EventBusStub(ch)
        period = 1.0/max(1,args.rate)
        n = args.rate*args.secs
        ok=fail=retry=0
        for i in range(n):
            t0=time.time()
            try:
                ack = stub.Publish(env(i), timeout=1.0)
                if ack.status == pb.PublishAck.OK: ok+=1
                elif ack.status == pb.PublishAck.RETRY: retry+=1
                else: fail+=1
            except Exception: fail+=1
            dt=time.time()-t0
            sleep=max(0.0, period-dt)
            time.sleep(sleep)
        print(f"OK={ok} RETRY={retry} FAIL={fail}")
