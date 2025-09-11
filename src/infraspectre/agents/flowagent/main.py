# agents/flowagent/main.py

import os, time, hashlib, logging, grpc, signal, sys, random
from datetime import datetime, timezone
from prometheus_client import start_http_server, Counter, Histogram, Gauge
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading

# Clean imports for new structure
from infraspectre.proto import messaging_schema_pb2 as pb
from infraspectre.proto import messaging_schema_pb2_grpc as pbrpc
from infraspectre.agents.flowagent.wal_sqlite import SQLiteWAL
from infraspectre.common.crypto.canonical import canonical_bytes
from infraspectre.common.crypto.signing import load_private_key, sign
from infraspectre.config import get_config

# Load configuration
config = get_config()
logger = logging.getLogger("FlowAgent")

CERT_DIR = config.agent.cert_dir
ED25519_SK_PATH = config.crypto.ed25519_private_key
WAL_PATH = config.agent.wal_path

# ---- Config from centralized configuration
MAX_ENV_BYTES = config.agent.max_env_bytes
SEND_RATE = config.agent.send_rate
RETRY_MAX = config.agent.retry_max
RETRY_TIMEOUT = config.agent.retry_timeout

# ---- Metrics (distinct names to avoid clashes)
AGENT_DROPPED_OVERSIZE = Counter("agent_dropped_oversize_total", "Dropped locally due to oversize payload")
AGENT_RATE_LIMITED     = Counter("agent_rate_limited_total",     "Publish attempts rate-limited")
AGENT_SEND_LAT_MS      = Histogram("agent_send_latency_ms",      "Client-side publish latency (ms)",
                                   buckets=(1,2,5,10,20,50,100,200,500,1000,2000,5000))

AG_PUB_OK = Counter("agent_publish_ok_total", "OK acks")
AG_PUB_RETRY = Counter("agent_publish_retry_total", "Retry acks")
AG_PUB_FAIL = Counter("agent_publish_fail_total", "RPC failures")
AG_WAL_BYTES = Gauge("agent_wal_backlog_bytes", "Bytes in WAL")
AG_PUB_LAT = Histogram("agent_publish_latency_ms", "Publish latency (ms)")
HEALTH_HITS = Counter("agent_health_hits_total", "Count of /healthz requests")
READINESS_HITS = Counter("agent_ready_hits_total", "Count of /ready requests")
READY_STATE = Gauge("agent_ready_state", "1=ready, 0=not-ready")

_SHOULD_EXIT = False
stop = False
READY = False  # set to True after WAL/gRPC init completes

_last_send_ts = 0.0

def _on_hup(signum, frame):
    global _SHOULD_EXIT
    _SHOULD_EXIT = True

def _graceful(signum, frame):
    global stop, READY
    stop = True
    READY = False
    READY_STATE.set(0)
    logging.info("Shutting down… signal=%s", signum)

signal.signal(signal.SIGHUP, _on_hup)
signal.signal(signal.SIGINT, _graceful)
signal.signal(signal.SIGTERM, _graceful)

def idem_key(flow: pb.FlowEvent, ts_ns: int) -> str:
    h = hashlib.sha256()
    h.update(str(ts_ns).encode())
    h.update(flow.src_ip.encode())
    h.update(flow.dst_ip.encode())
    h.update(str(flow.src_port).encode())
    h.update(str(flow.dst_port).encode())
    h.update(flow.protocol.encode())
    return h.hexdigest()

def make_envelope(flow: pb.FlowEvent) -> pb.Envelope:
    ts_ns = int(time.time_ns())
    env = pb.Envelope(
        version="v1",
        ts_ns=ts_ns,
        idempotency_key=idem_key(flow, ts_ns),
        flow=flow,
        sig=b"",
        prev_sig=b"",
    )
    sk = load_private_key(ED25519_SK_PATH)
    env.sig = sign(sk, canonical_bytes(env))
    return env

def grpc_channel():
    with open(os.path.join(CERT_DIR, "ca.crt"), "rb") as f:
        ca = f.read()
    with open(os.path.join(CERT_DIR, "client.crt"), "rb") as f:
        crt = f.read()
    with open(os.path.join(CERT_DIR, "client.key"), "rb") as f:
        key = f.read()
    creds = grpc.ssl_channel_credentials(root_certificates=ca,
                                         private_key=key,
                                         certificate_chain=crt)
    return grpc.secure_channel(config.agent.bus_address, creds)

def sleep_with_jitter(ms_hint: int):
    base = max(ms_hint, 50) / 1000.0
    jitter = base * random.uniform(0.2, 0.6)
    time.sleep(base + jitter)

def _size_ok(env) -> bool:
    try:
        return len(env.SerializeToString()) <= MAX_ENV_BYTES
    except Exception:
        return False

def _rate_limit():
    global _last_send_ts
    if SEND_RATE <= 0:
        return
    period = 1.0 / SEND_RATE
    now = time.time()
    wait = (_last_send_ts + period) - now
    if wait > 0:
        AGENT_RATE_LIMITED.inc()
        time.sleep(wait)
    _last_send_ts = time.time()

def _backoff_delay(attempt: int) -> float:
    base = min(2.0, 0.05 * (2 ** attempt))
    return base * (0.5 + random.random())

def publish_with_safety(stub: pbrpc.EventBusStub, envelope: pb.Envelope):
    if not _size_ok(envelope):
        AGENT_DROPPED_OVERSIZE.inc()
        return False, "dropped-oversize"
    _rate_limit()
    attempt = 0
    while True:
        t0 = time.time()
        try:
            ack = stub.Publish(envelope, timeout=RETRY_TIMEOUT)
        finally:
            AGENT_SEND_LAT_MS.observe((time.time() - t0) * 1000.0)
        if ack.status == pb.PublishAck.OK:
            return True, "ok"
        if ack.status == pb.PublishAck.RETRY and attempt < RETRY_MAX:
            time.sleep(_backoff_delay(attempt))
            attempt += 1
            continue
        return False, getattr(ack, "reason", "fail")

def publish_with_wal(env: pb.Envelope, wal: SQLiteWAL):
    if not _size_ok(env):
        AGENT_DROPPED_OVERSIZE.inc()
        logging.warning(f"Envelope oversize: {len(env.SerializeToString())} bytes, dropped")
        return
    try:
        with grpc_channel() as ch:
            stub = pbrpc.EventBusStub(ch)
            with AG_PUB_LAT.time():
                ack = stub.Publish(env, timeout=2.0)
    except grpc.RpcError as e:
        AG_PUB_FAIL.inc()
        logging.warning("bus error: %s; WAL append", e.code())
        wal.append(env); AG_WAL_BYTES.set(wal.backlog_bytes())
        sleep_with_jitter(200)
        return

    if ack.status == pb.PublishAck.OK:
        AG_PUB_OK.inc()
    elif ack.status == pb.PublishAck.RETRY:
        AG_PUB_RETRY.inc()
        wal.append(env)
        AG_WAL_BYTES.set(wal.backlog_bytes())
        sleep_with_jitter(ack.backoff_hint_ms or 200)
    else:
        AG_PUB_FAIL.inc()
    AG_WAL_BYTES.set(wal.backlog_bytes())

def drain_once(wal: SQLiteWAL) -> int:
    def _pub(e: pb.Envelope):
        with grpc_channel() as ch:
            stub = pbrpc.EventBusStub(ch)
            return stub.Publish(e, timeout=2.0)
    drained = wal.drain(_pub, limit=500)
    return drained

def start_health():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/healthz":
                HEALTH_HITS.inc()
                body = b"ok wal_bytes=0"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif self.path == "/ready":
                global READY
                READINESS_HITS.inc()
                body = (b"ready" if READY else b"not-ready")
                self.send_response(200 if READY else 503)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()
        def log_message(self, fmt, *args):
            return
    threading.Thread(
        target=lambda: HTTPServer(("0.0.0.0", config.agent.health_port), H).serve_forever(),
        daemon=True,
    ).start()
    logger.info("Agent health on :%d  (GET /healthz)", config.agent.health_port)

def main():
    wal = SQLiteWAL(path=WAL_PATH, max_bytes=config.storage.max_wal_bytes)
    start_health()
    global READY
    try:
        READY = True
        READY_STATE.set(1)
        logger.info("FlowAgent READY")
    except Exception:
        READY_STATE.set(0)
        logger.exception("Startup failed; exiting")
        sys.exit(1)
    last_sent = 0.0
    while not stop:
        if _SHOULD_EXIT:
            logger.info("SIGHUP received; exiting for systemd restart")
            sys.exit(0)
        drained = drain_once(wal)
        if SEND_RATE > 0:
            now = time.time()
            wait = max(0, 1.0/SEND_RATE - (now - last_sent))
            if wait > 0: time.sleep(wait)
            last_sent = time.time()
        elif drained == 0:
            time.sleep(2)
        time.sleep(0.2)
    # clean up servers/threads/resources here

if __name__ == "__main__":
    start_http_server(config.agent.metrics_port)
    logger.info("Agent metrics on :%d", config.agent.metrics_port)
    main()