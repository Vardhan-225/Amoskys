"""AMOSKYS Flow Agent - Network Flow Event Publisher.

This module implements the FlowAgent, which is responsible for:
- Publishing network flow events to the EventBus via gRPC
- Managing a write-ahead log (WAL) for reliability guarantees
- Implementing retry logic with exponential backoff
- Rate limiting and overload protection
- Health and readiness endpoints for orchestration
- Metrics collection for observability

The agent ensures reliable delivery of flow events even in the face of
transient failures, network issues, or EventBus overload conditions.

Architecture:
    FlowAgent -> [WAL] -> gRPC -> EventBus

The WAL provides durability, allowing the agent to recover from crashes
and retry failed publishes without data loss.
"""

import os, time, hashlib, logging, grpc, signal, sys, random
from datetime import datetime, timezone
from prometheus_client import start_http_server, Counter, Histogram, Gauge
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading

# Clean imports for new structure
from amoskys.proto import messaging_schema_pb2 as pb
from amoskys.proto import messaging_schema_pb2_grpc as pbrpc
from amoskys.agents.flowagent.wal_sqlite import SQLiteWAL
from amoskys.common.crypto.canonical import canonical_bytes
from amoskys.common.crypto.signing import load_private_key, sign
from amoskys.config import get_config

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

# ---- Metrics (with collision handling for repeated instantiation in tests)
try:
    AGENT_DROPPED_OVERSIZE = Counter("agent_dropped_oversize_total", "Dropped locally due to oversize payload")
except ValueError:
    AGENT_DROPPED_OVERSIZE = Counter("_dummy", "dummy")  # Placeholder if already registered
    
try:
    AGENT_RATE_LIMITED = Counter("agent_rate_limited_total", "Publish attempts rate-limited")
except ValueError:
    AGENT_RATE_LIMITED = Counter("_dummy2", "dummy")
    
try:
    AGENT_SEND_LAT_MS = Histogram("agent_send_latency_ms", "Client-side publish latency (ms)",
                                       buckets=(1,2,5,10,20,50,100,200,500,1000,2000,5000))
except ValueError:
    AGENT_SEND_LAT_MS = Histogram("_dummy3", "dummy")

try:
    AG_PUB_OK = Counter("agent_publish_ok_total", "OK acks")
except ValueError:
    AG_PUB_OK = Counter("_dummy4", "dummy")
    
try:
    AG_PUB_RETRY = Counter("agent_publish_retry_total", "Retry acks")
except ValueError:
    AG_PUB_RETRY = Counter("_dummy5", "dummy")
    
try:
    AG_PUB_FAIL = Counter("agent_publish_fail_total", "RPC failures")
except ValueError:
    AG_PUB_FAIL = Counter("_dummy6", "dummy")
    
try:
    AG_WAL_BYTES = Gauge("agent_wal_backlog_bytes", "Bytes in WAL")
except ValueError:
    AG_WAL_BYTES = Gauge("_dummy7", "dummy")
    
try:
    AG_PUB_LAT = Histogram("agent_publish_latency_ms", "Publish latency (ms)")
except ValueError:
    AG_PUB_LAT = Histogram("_dummy8", "dummy")
    
try:
    HEALTH_HITS = Counter("agent_health_hits_total", "Count of /healthz requests")
except ValueError:
    HEALTH_HITS = Counter("_dummy9", "dummy")
    
try:
    READINESS_HITS = Counter("agent_ready_hits_total", "Count of /ready requests")
except ValueError:
    READINESS_HITS = Counter("_dummy10", "dummy")
    
try:
    READY_STATE = Gauge("agent_ready_state", "1=ready, 0=not-ready")
except ValueError:
    READY_STATE = Gauge("_dummy11", "dummy")

_SHOULD_EXIT = False
stop = False
READY = False  # set to True after WAL/gRPC init completes

_last_send_ts = 0.0

def _on_hup(signum, frame):
    """Signal handler for SIGHUP - triggers graceful restart.

    Sets the exit flag to allow systemd or other orchestrators to
    restart the agent cleanly. Used for configuration reloads.

    Args:
        signum: Signal number (SIGHUP)
        frame: Current stack frame
    """
    global _SHOULD_EXIT
    _SHOULD_EXIT = True

def _graceful(signum, frame):
    """Signal handler for SIGINT/SIGTERM - triggers graceful shutdown.

    Initiates clean shutdown by setting stop flag and marking the
    agent as not-ready. Allows in-flight operations to complete.

    Args:
        signum: Signal number (SIGINT or SIGTERM)
        frame: Current stack frame
    """
    global stop, READY
    stop = True
    READY = False
    READY_STATE.set(0)
    logging.info("Shutting down… signal=%s", signum)

signal.signal(signal.SIGHUP, _on_hup)
signal.signal(signal.SIGINT, _graceful)
signal.signal(signal.SIGTERM, _graceful)

def idem_key(flow: pb.FlowEvent, ts_ns: int) -> str:
    """Generate idempotency key for a flow event.

    Creates a deterministic hash of the flow 5-tuple plus timestamp
    to ensure duplicate detection. The EventBus uses this key to
    deduplicate retried messages.

    Args:
        flow: Network flow event containing src/dst IPs, ports, and protocol
        ts_ns: Timestamp in nanoseconds since epoch

    Returns:
        SHA256 hex digest string (64 characters) uniquely identifying this event
    """
    h = hashlib.sha256()
    h.update(str(ts_ns).encode())
    h.update(flow.src_ip.encode())
    h.update(flow.dst_ip.encode())
    h.update(str(flow.src_port).encode())
    h.update(str(flow.dst_port).encode())
    h.update(flow.protocol.encode())
    return h.hexdigest()

def make_envelope(flow: pb.FlowEvent) -> pb.Envelope:
    """Wrap a flow event in a signed envelope.

    Creates an Envelope protobuf containing the flow event with:
    - Current timestamp
    - Idempotency key for deduplication
    - Ed25519 signature for authenticity verification

    Args:
        flow: Network flow event to envelope

    Returns:
        Signed Envelope ready for publishing to EventBus
    """
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
    """Create a secure gRPC channel to the EventBus.

    Establishes mutual TLS connection using:
    - CA certificate for server verification
    - Client certificate and key for client authentication

    Returns:
        grpc.Channel: Configured secure channel (use as context manager)

    Raises:
        FileNotFoundError: If certificate files are missing
        grpc.RpcError: If TLS handshake fails
    """
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
    """Sleep with randomized jitter to avoid thundering herd.

    Adds 20-60% random jitter to the base sleep duration to prevent
    synchronized retries from multiple agents. Minimum sleep is 50ms.

    Args:
        ms_hint: Suggested sleep duration in milliseconds
    """
    base = max(ms_hint, 50) / 1000.0
    jitter = base * random.uniform(0.2, 0.6)
    time.sleep(base + jitter)

def _size_ok(env) -> bool:
    """Check if envelope size is within limits.

    Args:
        env: Envelope protobuf to check

    Returns:
        bool: True if serialized size <= MAX_ENV_BYTES, False otherwise
    """
    try:
        return len(env.SerializeToString()) <= MAX_ENV_BYTES
    except Exception:
        return False

def _rate_limit():
    """Enforce send rate limit to prevent overwhelming the EventBus.

    Implements token bucket rate limiting. If SEND_RATE is configured,
    sleeps as needed to maintain the target rate. Increments rate_limited
    metric when throttling occurs.

    Updates:
        _last_send_ts: Global timestamp of last send operation
    """
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
    """Calculate exponential backoff delay with jitter.

    Implements capped exponential backoff: delay = min(2s, 50ms * 2^attempt)
    with 50-100% jitter to prevent synchronized retries.

    Args:
        attempt: Retry attempt number (0-indexed)

    Returns:
        float: Delay in seconds before next retry
    """
    base = min(2.0, 0.05 * (2 ** attempt))
    return base * (0.5 + random.random())

def publish_with_safety(stub: pbrpc.EventBusStub, envelope: pb.Envelope):
    """Publish envelope with automatic retry on transient failures.

    Implements publish with retry loop and exponential backoff. Used for
    synchronous publishing without WAL durability. Rate limiting is enforced.

    Args:
        stub: gRPC stub for EventBus service
        envelope: Signed envelope to publish

    Returns:
        tuple: (success: bool, reason: str)
            - (True, "ok") on successful publish
            - (False, reason) on permanent failure or retry exhaustion

    Note:
        Oversized envelopes are dropped immediately without retry.
    """
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
    """Publish envelope with WAL-backed reliability guarantees.

    Attempts immediate publish to EventBus. On failure or RETRY response,
    appends envelope to WAL for later retry via drain loop. This ensures
    at-least-once delivery even across agent restarts.

    Args:
        env: Signed envelope to publish
        wal: Write-ahead log for durable storage

    Behavior:
        - OK response: Success, no WAL write
        - RETRY response: Append to WAL, respect backoff hint
        - RPC error: Append to WAL, exponential backoff
        - Oversize: Drop without retry

    Updates metrics:
        AG_PUB_OK, AG_PUB_RETRY, AG_PUB_FAIL, AG_WAL_BYTES
    """
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
    """Drain up to 500 envelopes from WAL to EventBus.

    Attempts to publish pending envelopes from the WAL. Successfully
    published envelopes are removed from WAL by the drain callback.

    Args:
        wal: Write-ahead log containing pending envelopes

    Returns:
        int: Number of envelopes successfully drained from WAL
    """
    def _pub(e: pb.Envelope):
        with grpc_channel() as ch:
            stub = pbrpc.EventBusStub(ch)
            return stub.Publish(e, timeout=2.0)
    drained = wal.drain(_pub, limit=500)
    return drained

def start_health():
    """Start HTTP health check server in background thread.

    Exposes two endpoints for Kubernetes/orchestrator probes:
        GET /healthz - Liveness probe (always returns 200)
        GET /ready   - Readiness probe (returns 503 if not ready)

    The health server runs on config.agent.health_port and does not
    log individual requests (silent operation for high-frequency probes).

    Updates metrics:
        HEALTH_HITS, READINESS_HITS, READY_STATE
    """
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
        def log_message(self, format, *args):
            return
    threading.Thread(
        target=lambda: HTTPServer(("0.0.0.0", config.agent.health_port), H).serve_forever(),
        daemon=True,
    ).start()
    logger.info("Agent health on :%d  (GET /healthz)", config.agent.health_port)

def main():
    """Main agent loop - WAL drain and health management.

    Initializes:
        - SQLiteWAL for durable event storage
        - Health/readiness HTTP server
        - Readiness state management

    Main Loop:
        1. Check for SIGHUP (restart signal)
        2. Drain pending events from WAL to EventBus
        3. Apply rate limiting if configured
        4. Sleep briefly to prevent busy-wait

    The agent runs until receiving SIGINT/SIGTERM, then performs
    graceful shutdown by setting READY=False and stopping the loop.

    Exit Codes:
        0: Clean shutdown or SIGHUP restart
        1: Fatal startup error
    """
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