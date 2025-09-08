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

# Runtime overload control: 'auto' (use env), 'on', 'off'
BUS_OVERLOAD_SETTING = None
BUS_OVERLOAD_SOURCE = "env"
BUS_IS_OVERLOADED = False

_OVERLOAD = None  # Global variable to store overload state

def set_overload_setting(val):
    global BUS_OVERLOAD_SETTING, BUS_OVERLOAD_SOURCE
    if val in ("on", "off", "auto", None):
        BUS_OVERLOAD_SETTING = val or "auto"
        BUS_OVERLOAD_SOURCE = "cli" if val is not None else "env"
    else:
        BUS_OVERLOAD_SETTING = "auto"
        BUS_OVERLOAD_SOURCE = "cli"

def is_overloaded() -> bool:
    """Check if the server is in overload mode."""
    return bool(_OVERLOAD)

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

# Define constants for repeated literals
OVERLOAD_REASON = "Server is overloaded"
OVERLOAD_LOG = "[Publish] Server is overloaded"

class EventBusServicer(pbrpc.EventBusServicer):
    """Implements the EventBus gRPC service."""

    def Publish(self, request, context):
        logger.debug("[Publish] Method called")
        logger.debug(f"[Publish] _OVERLOAD={_OVERLOAD}")
        logger.debug(f"[Publish] is_overloaded()={is_overloaded()}")

        # Early guard for overload
        if is_overloaded():
            logger.info(OVERLOAD_LOG)
            return pb.PublishAck(
                status=pb.PublishAck.Status.RETRY,
                reason=OVERLOAD_REASON,
                backoff_hint_ms=2000
            )

        t0 = time.time()
        BUS_REQS.inc()

        # Early guard for overload
        if is_overloaded():
            logger.info(OVERLOAD_LOG)
            BUS_RETRY_TOTAL.inc()
            return _ack_retry(OVERLOAD_REASON, 2000)

        try:
            logger.debug(f"[Publish] Received request: {request}")
            # Debug log to check overload status
            logger.debug(f"[Publish] BUS_IS_OVERLOADED={BUS_IS_OVERLOADED}")

            # Use startup-evaluated overload flag to ensure deterministic behavior
            if BUS_IS_OVERLOADED:
                logger.info(OVERLOAD_LOG)
                BUS_RETRY_TOTAL.inc()
                BUS_LAT.observe((time.time() - t0) * 1000.0)
                return _ack_retry(OVERLOAD_REASON, 2000)

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
    global _OVERLOAD

    try:
        def parse_overload():
            parser = argparse.ArgumentParser(add_help=False)
            parser.add_argument("--overload", choices=["on", "off", "auto"], default="auto")
            args, _ = parser.parse_known_args()
            if args.overload == "on":
                return True, "cli:on"
            if args.overload == "off":
                return False, "cli:off"
            env = os.getenv("BUS_OVERLOAD", "")
            if env.strip() in ("1", "true", "on", "yes"):
                return True, "env:" + env
            return False, "default"

        _OVERLOAD, source = parse_overload()
        logger.info("Starting server with configuration:")
        logger.info("  BUS_OVERLOAD=%s (source=%s)", _OVERLOAD, source)

        def start_metrics_server(port):
            try:
                start_http_server(port)
                logger.info("Started metrics server on :%d", port)
            except OSError as e:
                logger.warning("Could not start metrics on :%d: %s", port, e)

        METRICS1 = int(os.getenv("BUS_METRICS_PORT_1", "9000"))
        METRICS2 = int(os.getenv("BUS_METRICS_PORT_2", "9100"))
        DISABLE_METRICS = os.getenv("BUS_METRICS_DISABLE", "") in ("1", "true", "on", "yes")

        if not DISABLE_METRICS:
            start_metrics_server(METRICS1)
            start_metrics_server(METRICS2)

        logger.info("Initializing gRPC server...")
        server = grpc.server(futures.ThreadPoolExecutor(max_workers=50))

        # Load TLS certs
        try:
            with open("certs/server.key", "rb") as f: key = f.read()
            with open("certs/server.crt", "rb") as f: crt = f.read()
            with open("certs/ca.crt", "rb") as f: ca = f.read()

            creds = grpc.ssl_server_credentials(
                [(key, crt)], 
                root_certificates=ca,
                require_client_auth=True,
            )
            logger.info("Loaded TLS certificates successfully")
        except Exception as e:
            logger.exception("Failed to load TLS certificates: %s", e)
            raise

        server.add_secure_port("[::]:50051", creds)
        logger.info("gRPC server bound to port 50051 with TLS")

        # Register EventBus service
        try:
            pbrpc.add_EventBusServicer_to_server(EventBusServicer(), server)
            logger.info("Registered EventBusServicer with gRPC server")
        except Exception as e:
            logger.exception("Failed to register EventBusServicer: %s", e)
            raise

        logger.info("Starting gRPC server...")
        server.start()
        logger.info("gRPC server started successfully")

        while True:
            time.sleep(1)

    except Exception as e:
        logger.exception("Unhandled exception during server initialization: %s", e)
        raise


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--overload', choices=['on', 'off', 'auto'], default=None,
                        help="Override overload behavior: on/off/auto (default: use BUS_OVERLOAD env)")
    args = parser.parse_args()
    serve()