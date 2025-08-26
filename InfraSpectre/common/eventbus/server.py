#!/usr/bin/env python3
import os
import sys
import grpc
import time
import logging
import ssl
import threading
import signal
from http.server import BaseHTTPRequestHandler, HTTPServer
from concurrent import futures
from prometheus_client import start_http_server, Counter, Histogram, Gauge
import yaml
from InfraSpectre.common.crypto.canonical import canonical_bytes
from InfraSpectre.common.crypto.signing import load_public_key, verify
from collections import OrderedDict

# Ensure project root is on sys.path for module imports
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Ensure proto_stubs is importable
proto_stubs_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../agents/flowagent/proto_stubs'))
if proto_stubs_path not in sys.path:
    sys.path.insert(0, proto_stubs_path)

from InfraSpectre.proto_stubs import messaging_schema_pb2 as pb
from InfraSpectre.proto_stubs import messaging_schema_pb2_grpc as pbrpc

# Configure logging with environment-based level
log_level = os.environ.get("LOGLEVEL", "INFO").upper()
logging.basicConfig(
    format='%(asctime)s %(levelname)-8s %(message)s',
    level=getattr(logging, log_level),
    force=True
)
logger = logging.getLogger("EventBus")

# Prometheus metrics
BUS_REQS = Counter("bus_publish_total", "Total Publish RPCs")
BUS_INVALID = Counter("bus_invalid_total", "Invalid envelopes")
BUS_LAT = Histogram("bus_publish_latency_ms", "Publish latency (ms)")
BUS_INFLIGHT = Gauge("bus_inflight_requests", "Current in-flight Publish RPCs")
BUS_RETRY_TOTAL = Counter("bus_retry_total", "Total Publish RETRY acks issued")

# Overload simulation
BUS_MAX_INFLIGHT = int(os.getenv("BUS_MAX_INFLIGHT", "100"))
BUS_HARD_MAX = int(os.getenv("BUS_HARD_MAX", "500"))

def is_overloaded():
    """Check if server is in overload mode."""
    val = os.environ.get("BUS_OVERLOAD", "0")
    logger.info(f"Checking overload status: BUS_OVERLOAD={val}")
    return val == "1"

AGENT_PUBKEY = None
TRUST = {}

_SHOULD_EXIT = False

_inflight_lock = threading.Lock()
_inflight = 0

DEDUPE_TTL_SEC = int(os.getenv("BUS_DEDUPE_TTL_SEC","300"))
DEDUPE_MAX = int(os.getenv("BUS_DEDUPE_MAX","50000"))
_dedupe = OrderedDict()

MAX_ENV_BYTES = int(os.getenv("BUS_MAX_ENV_BYTES","131072"))

def _sizeof_env(env):
    try: return len(env.SerializeToString())
    except Exception: return 0

def _seen(idem):
    now = time.time()
    while _dedupe and (now - next(iter(_dedupe.values())) > DEDUPE_TTL_SEC):
        _dedupe.popitem(last=False)
    if idem in _dedupe:
        _dedupe.move_to_end(idem, last=True)
        return True
    _dedupe[idem] = now
    if len(_dedupe) > DEDUPE_MAX:
        _dedupe.popitem(last=False)
    return False

def _on_hup(signum, frame):
    global _SHOULD_EXIT
    _SHOULD_EXIT = True

signal.signal(signal.SIGHUP, _on_hup)

def _load_keys():
    global AGENT_PUBKEY
    AGENT_PUBKEY = load_public_key("certs/agent.ed25519.pub")

def _load_trust():
    global TRUST
    with open("InfraSpectre/common/eventbus/trust_map.yaml", "r") as f:
        data = yaml.safe_load(f)
    TRUST = {cn: load_public_key(path) for cn, path in data.get("agents", {}).items()}

def _peer_cn_from_context(context):
    ac = context.auth_context()
    for k, v in ac.items():
        if k == 'x509_common_name' and v and v[0]:
            return v[0].decode()
    for k, v in ac.items():
        if k == 'x509_subject_alternative_name' and v and v[0]:
            return v[0].decode()
    return None

def _inc_inflight():
    global _inflight
    with _inflight_lock:
        _inflight += 1
        BUS_INFLIGHT.set(_inflight)
    return _inflight

def _dec_inflight():
    global _inflight
    with _inflight_lock:
        _inflight = max(0, _inflight - 1)
        BUS_INFLIGHT.set(_inflight)

def _flow_from_envelope(env: "pb.Envelope") -> "pb.FlowEvent":
    try:
        # If tests set env.flow, it'll be a non-empty message.
        if hasattr(env, "flow") and env.flow.ByteSize() > 0:
            return env.flow
    except Exception:
        pass
    # Back-compat for old producers that sent serialized FlowEvent bytes
    payload = getattr(env, "payload", b"")
    if payload:
        msg = pb.FlowEvent()
        msg.ParseFromString(payload)
        return msg
    raise ValueError("Envelope missing flow/payload")

def _ack_with_status(name: str, reason: str = "") -> "pb.PublishAck":
    ack = pb.PublishAck()
    status_enum = getattr(pb.PublishAck.Status, name, None)
    if status_enum is None:
        status_enum = pb.PublishAck.Status.ERROR
    try:
        ack.status = status_enum
    except Exception:
        pass
    if hasattr(ack, 'reason'):
        ack.reason = reason or ''
    return ack

def _ack_ok(msg: str = "OK") -> "pb.PublishAck":
    ack = pb.PublishAck()
    ack.status = 0  # OK is 0
    ack.reason = msg
    return ack

def _ack_retry(msg: str = "RETRY", backoff_ms: int = 1000) -> "pb.PublishAck":
    # Create response with numeric enum value
    ack = pb.PublishAck()
    ack.status = 1  # RETRY is 1
    ack.reason = msg
    ack.backoff_hint_ms = backoff_ms
    return ack

def _ack_invalid(msg: str = "INVALID") -> "pb.PublishAck":
    ack = pb.PublishAck()
    ack.status = 2  # INVALID is 2
    ack.reason = msg
    return ack

def _ack_err(msg: str = "ERROR") -> "pb.PublishAck":
    return _ack_with_status("ERROR", msg)

class EventBusServicer(pbrpc.EventBusServicer):
    """Implements the EventBus gRPC service."""

    def Publish(self, request, context):
        t0 = time.time()
        BUS_REQS.inc()

        try:
            is_overloaded = os.environ.get("BUS_OVERLOAD") == "1"
            logger.debug(f"[Publish] Checking environment: BUS_OVERLOAD={os.environ.get('BUS_OVERLOAD')}")

            if is_overloaded:
                logger.info("[Publish] Server is overloaded")
                BUS_RETRY_TOTAL.inc()
                BUS_LAT.observe((time.time() - t0) * 1000.0)
                return _ack_retry("Server is overloaded", 2000)

            # Size check
            if _sizeof_env(request) > MAX_ENV_BYTES:
                logger.info(f"[Publish] Envelope too large: {_sizeof_env(request)} bytes")
                BUS_INVALID.inc()
                response = pb.PublishAck()
                response.status = pb.PublishAck.Status.Value('INVALID')
                response.reason = f"Envelope too large ({_sizeof_env(request)} > {MAX_ENV_BYTES} bytes)"
                return response

            # Track inflight requests  
            inflight = _inc_inflight()
            try:
                # Check if we're over inflight limit
                if inflight > BUS_MAX_INFLIGHT:
                    logger.info(f"[Publish] Server at capacity: {inflight} requests inflight")
                    BUS_RETRY_TOTAL.inc()
                    return _ack_retry(f"Server at capacity ({inflight} requests inflight)", 1000)

                # Process the request
                flow = _flow_from_envelope(request)
                logger.info(f"[Publish] src_ip={flow.src_ip} dst_ip={flow.dst_ip} bytes_tx={flow.bytes_tx}")
                response = pb.PublishAck()
                response.status = pb.PublishAck.Status.Value('OK')
                response.reason = "accepted"
                return response
            finally:
                _dec_inflight()
        except ValueError as e:
            BUS_INVALID.inc()
            return _ack_invalid(str(e))
        except Exception as e:
            logger.exception("[Publish] Error")
            return _ack_err(str(e))

    def Subscribe(self, request, context):
        _ = request  # Mark request as used to avoid linter warning
        logger.warning("Subscribe() called but not implemented.")
        context.abort(grpc.StatusCode.UNIMPLEMENTED, "Subscribe not supported")


def _start_health_server():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/healthz":
                self.send_response(404); self.end_headers(); return
            self.send_response(200); self.end_headers()
            self.wfile.write(b"OK bus")
    t = threading.Thread(target=lambda: HTTPServer(("0.0.0.0", 8080), H).serve_forever(), daemon=True)
    t.start()


def serve():
    """Run the EventBus gRPC server."""
    _load_keys()
    _load_trust()
    
    # Set up logging and verify environment
    logging.basicConfig(
        format='%(asctime)s %(levelname)-8s %(message)s',
        level=logging.INFO,
        force=True
    )
    
    # Log critical environment variables first
    overload_status = is_overloaded()
    logger.info("Starting server with configuration:")
    logger.info(f"  BUS_OVERLOAD={overload_status}")
    logger.info(f"  BUS_MAX_INFLIGHT={BUS_MAX_INFLIGHT}")
    logger.info(f"  BUS_HARD_MAX={BUS_HARD_MAX}")
    
    executor = futures.ThreadPoolExecutor(max_workers=50)
    server = grpc.server(executor)

    # Register the EventBus service
    pbrpc.add_EventBusServicer_to_server(EventBusServicer(), server)

    # Load TLS certs
    with open("certs/server.key", "rb") as f: key = f.read()
    with open("certs/server.crt", "rb") as f: crt = f.read()
    with open("certs/ca.crt", "rb") as f: ca = f.read()

    creds = grpc.ssl_server_credentials(
        [(key, crt)], 
        root_certificates=ca,
        require_client_auth=True,
    )
    server.add_secure_port("[::]:50051", creds)
    
    # Start metrics servers, continue if ports are busy
    try:
        start_http_server(9000)
        logger.info("Started metrics server on :9000")
    except OSError as e:
        logger.warning(f"Could not start metrics on :9000: {e}")
    
    try:
        start_http_server(9100)
        logger.info("Started metrics server on :9100")
    except OSError as e:
        logger.warning(f"Could not start metrics on :9100: {e}")

    server.start()
    logger.info("gRPC server started on :50051")
    logging.info("Health on :8080  (GET /healthz)")

    while True:
        if _SHOULD_EXIT:
            logging.info("SIGHUP received; exiting for systemd restart")
            server.stop(0)
            sys.exit(0)
        time.sleep(1)


if __name__ == "__main__":
    serve()