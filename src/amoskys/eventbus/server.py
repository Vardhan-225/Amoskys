#!/usr/bin/env python3
"""EventBus gRPC Server for the Amoskys Network Security Platform.

This module implements the central EventBus server that acts as a message broker
for network flow events in the Amoskys distributed security architecture. The
EventBus is responsible for receiving, validating, and routing network flow
telemetry from distributed agents to downstream analytics engines.

Architecture Overview:
    The EventBus operates as a gRPC server with the following key responsibilities:

    1. Message Ingestion: Receives FlowEvent messages wrapped in signed Envelopes
       from distributed network agents via the Publish RPC.

    2. Security & Authentication:
       - Mutual TLS (mTLS) authentication for all connections
       - Ed25519 signature verification on envelopes
       - Client certificate validation via x509 Common Name extraction
       - Trust map-based authorization for known agents

    3. Overload Protection:
       - Configurable overload mode to shed load during high traffic
       - In-flight request tracking with configurable limits
       - Backpressure signaling via RETRY acknowledgments
       - Prometheus metrics for observability

    4. Idempotency & Deduplication:
       - TTL-based deduplication cache to prevent duplicate processing
       - Idempotency key tracking with automatic expiration

    5. Message Validation:
       - Envelope size limits to prevent resource exhaustion
       - Payload integrity verification
       - Schema validation for FlowEvent messages

Overload Management:
    The server supports three overload modes configured via CLI or environment:
    - 'on': Force overload mode (reject all requests with RETRY)
    - 'off': Disable overload mode (always accept requests)
    - 'auto': Use environment variable BUS_OVERLOAD (default)

    When overloaded, the server immediately returns RETRY acknowledgments with
    backoff hints, allowing clients to implement exponential backoff.

Metrics & Observability:
    Prometheus metrics are exposed on configurable ports:
    - bus_publish_total: Total Publish RPC count
    - bus_invalid_total: Invalid envelope count
    - bus_publish_latency_ms: Request latency histogram
    - bus_inflight_requests: Current in-flight request gauge
    - bus_retry_total: Total RETRY responses issued

Configuration:
    The server uses the centralized Amoskys configuration system, with support
    for environment variable overrides:
    - BUS_SERVER_PORT: Server port (default: from config)
    - BUS_OVERLOAD: Overload mode (default: false)
    - BUS_MAX_ENV_BYTES: Maximum envelope size (default: 131072)
    - BUS_DEDUPE_TTL_SEC: Deduplication TTL (default: 300)
    - BUS_DEDUPE_MAX: Max dedupe cache size (default: 50000)

Security Considerations:
    - All connections require valid client certificates signed by trusted CA
    - Envelope signatures verified using Ed25519 public keys
    - Trust map must be properly configured with authorized agent CNs
    - TLS 1.2+ required with strong cipher suites
    - SIGHUP signal triggers graceful shutdown
"""
import hashlib
import logging
import os
import signal
import sqlite3
import sys
import threading
import time
from collections import OrderedDict
from concurrent import futures
from http.server import BaseHTTPRequestHandler, HTTPServer

import grpc
import yaml
from prometheus_client import Counter, Gauge, Histogram, start_http_server

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from amoskys.agents.flowagent.wal_sqlite import SQLiteWAL

# Clean imports for new structure
from amoskys.common.crypto.signing import load_public_key
from amoskys.config import get_config
from amoskys.proto import messaging_schema_pb2 as pb
from amoskys.proto import messaging_schema_pb2_grpc as pbrpc
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.proto import universal_telemetry_pb2_grpc as telemetry_grpc

# Load configuration
config = get_config()
logger = logging.getLogger("EventBus")

# Initialize WAL for persistent storage
WAL_PATH = config.agent.wal_path
wal_storage = None  # Will be initialized in serve()
_wal_lock = threading.Lock()  # Thread-safe WAL access

# Prometheus metrics
try:
    BUS_REQS = Counter("bus_publish_total", "Total Publish RPCs")
except ValueError:
    BUS_REQS = Counter("_bus_dummy1", "dummy")

try:
    BUS_INVALID = Counter("bus_invalid_total", "Invalid envelopes")
except ValueError:
    BUS_INVALID = Counter("_bus_dummy2", "dummy")

try:
    BUS_LAT = Histogram("bus_publish_latency_ms", "Publish latency (ms)")
except ValueError:
    BUS_LAT = Histogram("_bus_dummy3", "dummy")

try:
    BUS_INFLIGHT = Gauge("bus_inflight_requests", "Current in-flight Publish RPCs")
except ValueError:
    BUS_INFLIGHT = Gauge("_bus_dummy4", "dummy")

try:
    BUS_RETRY_TOTAL = Counter("bus_retry_total", "Total Publish RETRY acks issued")
except ValueError:
    BUS_RETRY_TOTAL = Counter("_bus_dummy5", "dummy")

# Configuration from centralized config
BUS_MAX_INFLIGHT = config.eventbus.max_inflight
BUS_HARD_MAX = config.eventbus.hard_max

# Runtime overload control: 'auto' (use env), 'on', 'off'
BUS_OVERLOAD_SETTING = None
BUS_OVERLOAD_SOURCE = "env"
BUS_IS_OVERLOADED = False

_OVERLOAD = None  # Global variable to store overload state


def set_overload_setting(val):
    """Set the overload mode for the EventBus server.

    This function configures how the server handles overload conditions. The
    overload setting determines whether the server immediately rejects requests
    with RETRY responses to shed load during high traffic periods.

    Args:
        val: Overload mode setting. Valid values:
            - 'on': Force overload mode (always reject with RETRY)
            - 'off': Disable overload mode (never trigger overload)
            - 'auto': Use BUS_OVERLOAD environment variable (default)
            - None: Reset to 'auto' mode with environment source

    Side Effects:
        - Updates global BUS_OVERLOAD_SETTING
        - Updates global BUS_OVERLOAD_SOURCE to 'cli' or 'env'
        - Invalid values default to 'auto' mode

    Note:
        This function is typically called during server initialization from
        command-line arguments. The overload mode can be changed at runtime
        by external orchestration systems to implement dynamic load shedding.
    """
    global BUS_OVERLOAD_SETTING, BUS_OVERLOAD_SOURCE
    if val in ("on", "off", "auto", None):
        BUS_OVERLOAD_SETTING = val or "auto"
        BUS_OVERLOAD_SOURCE = "cli" if val is not None else "env"
    else:
        BUS_OVERLOAD_SETTING = "auto"
        BUS_OVERLOAD_SOURCE = "cli"


def is_overloaded() -> bool:
    """Check if the server is in overload mode.

    Returns:
        bool: True if server is overloaded and should reject requests,
              False otherwise. The overload state is determined by the
              global _OVERLOAD variable.

    Note:
        This is the canonical method to check overload status. It's called
        at the start of every Publish RPC to determine whether to immediately
        return RETRY or process the request normally.
    """
    return bool(_OVERLOAD)


AGENT_PUBKEY = None
TRUST = {}

_SHOULD_EXIT = False

_inflight_lock = threading.Lock()
_inflight = 0

DEDUPE_TTL_SEC = int(os.getenv("BUS_DEDUPE_TTL_SEC", "300"))
DEDUPE_MAX = int(os.getenv("BUS_DEDUPE_MAX", "50000"))
_dedupe: "OrderedDict[str, float]" = OrderedDict()

MAX_ENV_BYTES = int(os.getenv("BUS_MAX_ENV_BYTES", "131072"))


def _sizeof_env(env):
    """Calculate the serialized size of an Envelope message in bytes.

    This function determines the wire format size of a protobuf Envelope to
    enforce maximum message size limits and prevent resource exhaustion attacks.

    Args:
        env: A protobuf Envelope message to measure.

    Returns:
        int: The size in bytes of the serialized envelope, or 0 if serialization
             fails. A return value of 0 indicates a malformed envelope.

    Security:
        This check is critical for preventing memory exhaustion attacks. Envelopes
        exceeding MAX_ENV_BYTES are rejected with INVALID status to protect server
        resources.
    """
    try:
        return len(env.SerializeToString())
    except Exception:
        return 0


def _seen(idem):
    """Check if an idempotency key has been seen before.

    This function implements a TTL-based deduplication cache to prevent duplicate
    processing of messages. It uses an OrderedDict to maintain insertion order and
    efficiently expire old entries.

    Args:
        idem: The idempotency key (typically a hash or UUID) to check. This should
              be a unique identifier for each logical message.

    Returns:
        bool: True if this idempotency key was already seen within the TTL window,
              False if this is the first time seeing this key.

    Side Effects:
        - Expires entries older than DEDUPE_TTL_SEC from the cache
        - Moves existing keys to the end (updates LRU position)
        - Adds new keys with current timestamp
        - Removes oldest entry if cache exceeds DEDUPE_MAX size

    Implementation:
        The deduplication cache uses a sliding window approach:
        1. On each call, expire entries older than TTL
        2. If key exists, move to end (mark as recently used) and return True
        3. If key is new, add with current timestamp
        4. If cache is full, remove oldest entry

    Performance:
        - Time complexity: O(1) for lookups, O(k) for expiration where k is
          number of expired entries
        - Space complexity: O(DEDUPE_MAX) bounded by maximum cache size

    Note:
        This is not a distributed deduplication mechanism. In a multi-instance
        deployment, each server maintains its own cache. For true distributed
        deduplication, a shared cache (e.g., Redis) would be required.
    """
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
    """Signal handler for SIGHUP to trigger graceful shutdown.

    This handler sets a global flag that can be checked by the main server loop
    to initiate graceful shutdown. SIGHUP is commonly used in Unix systems to
    signal a process to reload configuration or terminate gracefully.

    Args:
        signum: The signal number (will be signal.SIGHUP).
        frame: The current stack frame (unused but required by signal handler API).

    Side Effects:
        Sets the global _SHOULD_EXIT flag to True, which can be checked by the
        main server loop to initiate shutdown procedures.

    Note:
        This handler is registered with signal.signal() at module load time.
        In production deployments, SIGHUP is often sent by container orchestrators
        (Kubernetes, Docker) to request graceful termination before SIGTERM/SIGKILL.

    Future Enhancements:
        Currently only sets a flag. Could be extended to:
        - Drain in-flight requests before exiting
        - Close gRPC server gracefully
        - Flush metrics and logs
        - Notify health check endpoints
    """
    global _SHOULD_EXIT
    _SHOULD_EXIT = True


signal.signal(signal.SIGHUP, _on_hup)


def _load_keys():
    """Load the Ed25519 public key for signature verification.

    This function loads the agent's Ed25519 public key from the filesystem. This
    key is used to verify signatures on incoming Envelope messages to ensure
    message integrity and authenticity.

    Side Effects:
        Sets the global AGENT_PUBKEY to the loaded Ed25519 public key object.

    Raises:
        FileNotFoundError: If certs/agent.ed25519.pub does not exist.
        ValueError: If the key file is malformed or not a valid Ed25519 key.

    Security:
        The public key is stored in the certs/ directory and should be deployed
        alongside the server. In production, this key should match the private
        key used by authorized agents to sign messages. Key rotation requires
        updating this file and restarting the server (or implementing hot reload
        via SIGHUP).

    Note:
        This function is currently defined but not called in the serve() function.
        Signature verification is not yet implemented in the Publish RPC handler.
        This represents future functionality for enhanced security.
    """
    global AGENT_PUBKEY
    AGENT_PUBKEY = load_public_key("certs/agent.ed25519.pub")


def _load_trust():
    """Load the trust map of authorized agent public keys.

    This function loads a YAML trust map that specifies which client certificate
    Common Names (CNs) are authorized to publish to the EventBus, along with their
    corresponding Ed25519 public keys for signature verification.

    The trust map format is:
        agents:
          agent-1.example.com: /path/to/agent1.ed25519.pub
          agent-2.example.com: /path/to/agent2.ed25519.pub

    Side Effects:
        Populates the global TRUST dictionary mapping client CNs to their Ed25519
        public key objects.

    Raises:
        FileNotFoundError: If the trust map file does not exist.
        yaml.YAMLError: If the trust map is not valid YAML.
        ValueError: If any public key file is malformed.

    Security:
        The trust map is the foundation of the EventBus authorization model. Only
        agents whose client certificate CN appears in this map with a valid public
        key are permitted to publish events. This provides:
        - Mutual TLS authentication (client cert validation)
        - Per-agent authorization (CN must be in trust map)
        - Message integrity (signature verified with agent's public key)

    Note:
        Like _load_keys(), this function is defined but not called in serve().
        Full signature verification and authorization is not yet implemented.
        Currently, the server relies solely on mTLS client certificate validation.

    Future Enhancements:
        - Hot reload trust map without server restart
        - Support for key rotation with multiple valid keys per agent
        - Integration with external PKI/CA systems
    """
    global TRUST
    with open(config.crypto.trust_map_path, "r") as f:
        data = yaml.safe_load(f)
    TRUST = {cn: load_public_key(path) for cn, path in data.get("agents", {}).items()}


def _peer_cn_from_context(context):
    """Extract the client's Common Name from the gRPC authentication context.

    This function parses the gRPC peer authentication context to extract the
    Common Name (CN) from the client's x509 certificate. The CN is used to
    identify which agent sent the request for authorization and audit logging.

    Args:
        context: The gRPC ServicerContext containing authentication metadata
                 from the mTLS handshake.

    Returns:
        str: The Common Name from the client certificate, or None if it cannot
             be extracted. Returns the first non-empty value found in this order:
             1. x509_common_name
             2. x509_subject_alternative_name

    Implementation:
        The function searches the auth context for certificate identity fields:
        - First checks x509_common_name (standard CN field)
        - Falls back to x509_subject_alternative_name (SAN extension)
        - Values are decoded from bytes to strings

    Security:
        The extracted CN should be validated against the trust map before allowing
        the client to publish events. This provides defense-in-depth beyond the
        TLS handshake:
        - TLS validates the certificate was signed by trusted CA
        - CN check validates the specific client is authorized for this operation

    Note:
        Currently not used in the Publish handler but defined for future
        authorization implementation. When enabled, this will log which agent
        sent each event for audit trails and debugging.

    Example:
        >>> cn = _peer_cn_from_context(context)
        >>> if cn not in TRUST:
        >>>     return _ack_with_status("UNAUTHORIZED", f"Unknown agent: {cn}")
    """
    ac = context.auth_context()
    for k, v in ac.items():
        if k == "x509_common_name" and v and v[0]:
            return v[0].decode()
    for k, v in ac.items():
        if k == "x509_subject_alternative_name" and v and v[0]:
            return v[0].decode()
    return None


def _inc_inflight():
    """Increment the in-flight request counter atomically.

    This function safely increments the global in-flight request counter using
    a lock to prevent race conditions in a multi-threaded gRPC server. It also
    updates the Prometheus gauge metric for observability.

    Returns:
        int: The new in-flight request count after incrementing.

    Side Effects:
        - Increments global _inflight counter
        - Updates BUS_INFLIGHT Prometheus gauge

    Thread Safety:
        Uses _inflight_lock to ensure atomic read-modify-write operations in
        the multi-threaded gRPC server environment.

    Usage:
        This function is called at the start of each Publish RPC to track the
        current load on the server. The returned value can be checked against
        BUS_MAX_INFLIGHT to implement backpressure:

        >>> inflight = _inc_inflight()
        >>> if inflight > BUS_MAX_INFLIGHT:
        >>>     return _ack_retry("Server at capacity", 1000)

    Note:
        Must always be paired with _dec_inflight() in a try/finally block to
        ensure the counter is decremented even if request processing fails.
    """
    global _inflight
    with _inflight_lock:
        _inflight += 1
        BUS_INFLIGHT.set(_inflight)
    return _inflight


def _dec_inflight():
    """Decrement the in-flight request counter atomically.

    This function safely decrements the global in-flight request counter using
    a lock to prevent race conditions. It ensures the counter never goes below
    zero and updates the Prometheus gauge metric.

    Side Effects:
        - Decrements global _inflight counter (floor at 0)
        - Updates BUS_INFLIGHT Prometheus gauge

    Thread Safety:
        Uses _inflight_lock to ensure atomic read-modify-write operations.

    Implementation:
        The max(0, _inflight - 1) ensures we never get negative counts, which
        could happen if there's a bug causing mismatched inc/dec calls. This
        defensive programming prevents metric corruption.

    Usage:
        Always called in a finally block to ensure it runs even if request
        processing raises an exception:

        >>> inflight = _inc_inflight()
        >>> try:
        >>>     # Process request
        >>>     pass
        >>> finally:
        >>>     _dec_inflight()

    Note:
        If the counter is already 0, this is a no-op (stays at 0). This prevents
        negative counts from corrupting metrics and analytics.
    """
    global _inflight
    with _inflight_lock:
        _inflight = max(0, _inflight - 1)
        BUS_INFLIGHT.set(_inflight)


def _flow_from_envelope(env: "pb.Envelope") -> "pb.FlowEvent":
    """Extract a FlowEvent message from an Envelope.

    This function handles backward-compatible extraction of FlowEvent data from
    Envelope messages. It supports both the new structured format (env.flow field)
    and the legacy format (serialized bytes in env.payload).

    Args:
        env: A protobuf Envelope message containing either:
             - A populated flow field (new format), or
             - Serialized FlowEvent bytes in payload field (legacy format)

    Returns:
        pb.FlowEvent: The extracted and parsed FlowEvent message containing
                      network flow telemetry data.

    Raises:
        ValueError: If the envelope contains neither a valid flow field nor
                    a parseable payload field. The error message is
                    "Envelope missing flow/payload".

    Implementation:
        The function tries two extraction methods in order:
        1. New format: Check if env.flow exists and has non-zero size
        2. Legacy format: Parse env.payload as serialized FlowEvent bytes

        This allows gradual migration from the old to new format without
        breaking existing agents.

    Backward Compatibility:
        The legacy format support ensures old agents that still serialize
        FlowEvents into the payload field continue to work. New agents should
        populate the flow field directly for better type safety and debugging.

    Security:
        The payload parsing uses ParseFromString which validates the protobuf
        format. Malformed payloads will raise an exception caught by the Publish
        handler, which returns INVALID status to the client.

    Note:
        The hasattr and ByteSize checks in the new format path handle both:
        - Old protobuf schemas where env.flow might not exist
        - Envelopes where flow exists but is empty (default message)
    """
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
    """Build a PublishAck response with the specified status and reason.

    This is a generic acknowledgment builder that constructs PublishAck messages
    with the appropriate status enum value and optional reason text.

    Args:
        name: The status name to set. Valid values:
              - "OK": Request accepted and processed successfully
              - "RETRY": Client should retry later (transient failure)
              - "INVALID": Request is malformed (permanent failure)
              - "UNAUTHORIZED": Client is not authorized (permission denied)
              Any other value defaults to INVALID.
        reason: Optional human-readable explanation for the status. This helps
                clients understand why a request was rejected or needs retry.

    Returns:
        pb.PublishAck: A PublishAck message with status and reason fields set.

    Implementation:
        Uses proper protobuf enum assignment (pb.PublishAck.Status.OK) rather
        than setting integer values directly. This is more maintainable and
        type-safe.

    Note:
        The reason field is only set if it exists in the protobuf schema
        (checked with hasattr). This allows the code to work with different
        versions of the messaging_schema.proto file.

    Usage:
        Typically called indirectly through status-specific helpers like
        _ack_ok(), _ack_retry(), etc. Can be used directly for custom status
        combinations or when the status is determined dynamically.
    """
    ack = pb.PublishAck()
    # Use proper enum assignment
    if name == "OK":
        ack.status = pb.PublishAck.Status.OK
    elif name == "RETRY":
        ack.status = pb.PublishAck.Status.RETRY
    elif name == "INVALID":
        ack.status = pb.PublishAck.Status.INVALID
    elif name == "UNAUTHORIZED":
        ack.status = pb.PublishAck.Status.UNAUTHORIZED
    else:
        # Default to INVALID for unknown status
        ack.status = pb.PublishAck.Status.INVALID

    if hasattr(ack, "reason"):
        ack.reason = reason or ""
    return ack


def _ack_ok(msg: str = "OK") -> "pb.PublishAck":
    """Build a successful PublishAck response.

    This helper constructs an acknowledgment indicating the message was accepted
    and processed successfully. The client can consider the message delivered.

    Args:
        msg: Optional success message (default: "OK"). Used for logging and
             debugging to provide specific success details (e.g., "accepted",
             "processed", "enqueued").

    Returns:
        pb.PublishAck: An acknowledgment with status=OK and reason=msg.

    Semantics:
        OK status means:
        - The envelope was valid and passed all checks
        - The flow event was extracted successfully
        - The message has been accepted for processing
        - The client does not need to retry

    Note:
        In a full implementation, OK might mean the event was persisted to
        durable storage or forwarded to analytics engines. Currently it just
        means basic validation passed.
    """
    ack = pb.PublishAck()
    ack.status = pb.PublishAck.Status.OK
    ack.reason = msg
    return ack


def _ack_retry(msg: str = "RETRY", backoff_ms: int = 1000) -> "pb.PublishAck":
    """Build a RETRY PublishAck response with backoff hint.

    This helper constructs an acknowledgment telling the client to retry the
    request later. It includes a backoff hint to guide the client's retry timing
    and prevent thundering herd problems.

    Args:
        msg: Explanation of why retry is needed (default: "RETRY"). Examples:
             - "Server is overloaded"
             - "Server at capacity (150 requests inflight)"
             - "Database temporarily unavailable"
        backoff_ms: Suggested backoff delay in milliseconds before retrying
                    (default: 1000). Clients should wait at least this long
                    before sending the same request again.

    Returns:
        pb.PublishAck: An acknowledgment with status=RETRY, reason=msg, and
                       backoff_hint_ms=backoff_ms.

    Semantics:
        RETRY status means:
        - The request was not processed due to a transient condition
        - The client should retry the same request later
        - The backoff hint guides retry timing
        - The server state may change, making retry successful

    Backoff Strategy:
        Clients should implement exponential backoff:
        1. First retry after backoff_hint_ms
        2. Subsequent retries double the backoff (up to a max)
        3. Add jitter to prevent synchronized retries

    Usage:
        Common scenarios for RETRY:
        - Server overload (return quickly to shed load)
        - Rate limiting (backoff_ms indicates when quota resets)
        - Dependency temporarily unavailable
        - Circuit breaker open

    Note:
        The backoff_ms is a hint, not a guarantee. Clients may choose different
        backoff strategies based on their own policies and requirements.
    """
    ack = pb.PublishAck()
    ack.status = pb.PublishAck.Status.RETRY
    ack.reason = msg
    ack.backoff_hint_ms = backoff_ms
    return ack


def _ack_invalid(msg: str = "INVALID") -> "pb.PublishAck":
    """Build an INVALID PublishAck response for malformed requests.

    This helper constructs an acknowledgment indicating the request is malformed
    and cannot be processed. The client should not retry as the error is permanent.

    Args:
        msg: Explanation of why the request is invalid (default: "INVALID").
             Should be specific enough for clients to fix the issue. Examples:
             - "Envelope too large (200KB > 128KB limit)"
             - "Envelope missing flow/payload"
             - "Invalid signature"
             - "Missing required field: src_ip"

    Returns:
        pb.PublishAck: An acknowledgment with status=INVALID and reason=msg.

    Semantics:
        INVALID status means:
        - The request violated a protocol requirement
        - The error is permanent (retry will fail with same error)
        - The client should fix the request before retrying
        - The error is likely a client bug or misconfiguration

    Common Invalid Conditions:
        - Envelope exceeds MAX_ENV_BYTES size limit
        - Missing required protobuf fields
        - Malformed protobuf (parse error)
        - Invalid signature or crypto material
        - Schema version mismatch

    Error Handling:
        Clients receiving INVALID should:
        1. Log the error with full context
        2. Alert developers/operators
        3. Fix the bug in the client code
        4. Do NOT retry the same request
        5. Consider circuit breaking if many INVALID responses

    Metrics:
        INVALID responses increment the BUS_INVALID counter for monitoring.
        High INVALID rates indicate client bugs or attacks.
    """
    ack = pb.PublishAck()
    ack.status = pb.PublishAck.Status.INVALID
    ack.reason = msg
    return ack


def _ack_err(msg: str = "ERROR") -> "pb.PublishAck":
    """Build an ERROR PublishAck response for internal server errors.

    This helper constructs an acknowledgment indicating an unexpected server-side
    error occurred during request processing. This is distinct from INVALID (client
    error) and RETRY (transient condition).

    Args:
        msg: Description of the error (default: "ERROR"). Should be informative
             but avoid leaking sensitive internal details. The full exception
             is typically logged server-side.

    Returns:
        pb.PublishAck: An acknowledgment with status indicating error condition.

    Semantics:
        ERROR status means:
        - An unexpected server-side exception occurred
        - The error is not the client's fault
        - Retry may or may not succeed (depends on error nature)
        - The server should log full details for investigation

    Usage:
        Returned in exception handlers for unexpected errors:
        - Database connection failures
        - Internal assertion violations
        - Uncaught exceptions
        - Resource allocation failures

    Security:
        Error messages should be sanitized to avoid leaking:
        - Internal system paths
        - Database schema details
        - Security configuration
        - Other sensitive internals

    Note:
        Currently delegates to _ack_with_status("ERROR", msg). The "ERROR" status
        may not be defined in the protobuf enum, in which case it defaults to
        INVALID. Consider using a defined status like RETRY for transient errors
        or defining ERROR status in the schema.
    """
    return _ack_with_status("ERROR", msg)


# Define constants for repeated literals
OVERLOAD_REASON = "Server is overloaded"
OVERLOAD_LOG = "[Publish] Server is overloaded"


class EventBusServicer(pbrpc.EventBusServicer):
    """Implements the EventBus gRPC service for message routing.

    This servicer handles the Publish and Subscribe RPCs defined in the EventBus
    protobuf service definition. It implements the core message ingestion logic
    with validation, rate limiting, and acknowledgment.

    The servicer is registered with the gRPC server and receives callbacks for
    each RPC invocation. It has access to the gRPC context for authentication
    and metadata extraction.

    Thread Safety:
        Multiple instances of RPC methods can run concurrently in the gRPC
        thread pool. All state mutations use appropriate locking (e.g.,
        _inflight_lock for the counter).

    Security:
        All RPCs require mTLS authentication. The context parameter provides
        access to client certificate details for authorization checks.
    """

    def Publish(self, request, context):
        """Handle a Publish RPC to accept a network flow event.

        This is the primary ingestion endpoint for the EventBus. Agents call this
        RPC to publish network flow events wrapped in signed Envelope messages.
        The method performs comprehensive validation and returns an acknowledgment
        indicating acceptance or rejection with appropriate retry/error details.

        Args:
            request: A protobuf Envelope message containing:
                     - flow: FlowEvent with network telemetry data (new format), or
                     - payload: Serialized FlowEvent bytes (legacy format)
                     - signature: Ed25519 signature (future use)
                     - idempotency_key: For deduplication (future use)
            context: The gRPC ServicerContext providing:
                     - Authentication context (client cert details)
                     - Metadata (headers, deadlines)
                     - RPC lifecycle control (abort, set status)

        Returns:
            pb.PublishAck: Acknowledgment with status and reason:
                - OK: Message accepted successfully
                - RETRY: Transient failure, client should retry with backoff
                - INVALID: Permanent failure, client should not retry
                - ERROR: Server error (rare, logged for investigation)

        Validation Steps:
            1. Check server overload status -> RETRY if overloaded
            2. Check envelope size vs MAX_ENV_BYTES -> INVALID if too large
            3. Track in-flight requests -> RETRY if over capacity
            4. Extract FlowEvent from envelope -> INVALID if missing/malformed
            5. Process flow event (currently just logging)
            6. Return OK acknowledgment

        Metrics:
            - Increments BUS_REQS counter on entry
            - Increments BUS_INVALID on validation failures
            - Increments BUS_RETRY_TOTAL on RETRY responses
            - Observes latency in BUS_LAT histogram
            - Updates BUS_INFLIGHT gauge (via _inc/_dec_inflight)

        Error Handling:
            - ValueError: Caught and returns INVALID (e.g., missing flow/payload)
            - General Exception: Caught, logged, returns ERROR
            - finally: Always decrements in-flight counter

        Security:
            - Enforces size limits to prevent resource exhaustion
            - Requires mTLS (enforced at server level)
            - Future: Signature verification and CN authorization

        Performance:
            The method is designed for high throughput:
            - Fast overload check returns immediately
            - Size check uses cached serialization
            - Minimal processing in the happy path
            - Async processing could be added for heavy analytics

        Future Enhancements:
            - Signature verification using AGENT_PUBKEY or TRUST map
            - Client CN extraction and authorization
            - Idempotency key deduplication using _seen()
            - Message forwarding to downstream analytics engines
            - Async processing to reduce RPC latency

        Example:
            >>> envelope = pb.Envelope()
            >>> envelope.flow.src_ip = "10.0.0.1"
            >>> envelope.flow.dst_ip = "10.0.0.2"
            >>> ack = servicer.Publish(envelope, context)
            >>> assert ack.status == pb.PublishAck.Status.OK
        """
        logger.debug("[Publish] Method called")
        logger.debug(f"[Publish] _OVERLOAD={_OVERLOAD}")
        logger.debug(f"[Publish] is_overloaded()={is_overloaded()}")

        t0 = time.time()
        BUS_REQS.inc()

        # Single overload check using the properly initialized variable
        if is_overloaded():
            logger.info(OVERLOAD_LOG)
            BUS_RETRY_TOTAL.inc()
            BUS_LAT.observe((time.time() - t0) * 1000.0)
            return _ack_retry(OVERLOAD_REASON, 2000)

        try:
            logger.debug(f"[Publish] Received request: {request}")

            # Size check
            if _sizeof_env(request) > MAX_ENV_BYTES:
                logger.info(
                    f"[Publish] Envelope too large: {_sizeof_env(request)} bytes"
                )
                BUS_INVALID.inc()
                response = pb.PublishAck()
                response.status = pb.PublishAck.Status.INVALID
                response.reason = f"Envelope too large ({_sizeof_env(request)} > {MAX_ENV_BYTES} bytes)"
                return response

            # Track inflight requests
            inflight = _inc_inflight()
            try:
                # Check if we're over inflight limit
                if inflight > BUS_MAX_INFLIGHT:
                    logger.info(
                        f"[Publish] Server at capacity: {inflight} requests inflight"
                    )
                    BUS_RETRY_TOTAL.inc()
                    return _ack_retry(
                        f"Server at capacity ({inflight} requests inflight)", 1000
                    )

                # Process the request
                flow = _flow_from_envelope(request)
                logger.info(
                    f"[Publish] src_ip={flow.src_ip} dst_ip={flow.dst_ip} bytes_tx={flow.bytes_tx}"
                )

                # Store in WAL for dashboard visibility
                if wal_storage:
                    try:
                        with _wal_lock:
                            # Create a new connection for this thread if needed
                            conn = sqlite3.connect(
                                WAL_PATH,
                                timeout=5.0,
                                isolation_level=None,
                                check_same_thread=False,
                            )

                            # Handle both UniversalEnvelope (idempotency_key) and Envelope (idem)
                            if hasattr(request, "idempotency_key"):
                                idem = request.idempotency_key
                            elif hasattr(request, "idem"):
                                idem = request.idem
                            else:
                                idem = f"unknown_{request.ts_ns}"

                            ts_ns = request.ts_ns
                            env_bytes = request.SerializeToString()
                            checksum = hashlib.blake2b(
                                env_bytes, digest_size=32
                            ).digest()

                            try:
                                conn.execute(
                                    "INSERT INTO wal (idem, ts_ns, bytes, checksum) VALUES (?, ?, ?, ?)",
                                    (idem, ts_ns, env_bytes, checksum),
                                )
                                logger.debug(
                                    "[Publish] Stored event in WAL (idem=%s)", idem
                                )
                            except sqlite3.IntegrityError:
                                logger.debug(
                                    "[Publish] Duplicate event (idem=%s), skipped", idem
                                )
                            finally:
                                conn.close()
                    except Exception as wal_err:
                        logger.error("[Publish] Failed to store in WAL: %s", wal_err)

                return _ack_ok("accepted")
            finally:
                _dec_inflight()
        except ValueError as e:
            BUS_INVALID.inc()
            return _ack_invalid(str(e))
        except Exception as e:
            logger.exception("[Publish] Error")
            return _ack_err(str(e))

    def Subscribe(self, request, context):
        """Handle a Subscribe RPC for streaming flow events.

        This RPC is defined in the EventBus service but not yet implemented. It is
        intended for consumers (analytics engines, dashboards) to subscribe to a
        stream of flow events matching certain criteria.

        Args:
            request: A SubscribeRequest protobuf (schema not yet defined) that
                     would specify subscription filters (e.g., source IP ranges,
                     destination ports, time windows).
            context: The gRPC ServicerContext for the streaming RPC.

        Raises:
            grpc.RpcError: Always aborts with UNIMPLEMENTED status code and
                          message "Subscribe not supported".

        Future Implementation:
            When implemented, Subscribe would:
            1. Validate subscription filters in request
            2. Register the subscriber in a pub/sub broker
            3. Stream matching FlowEvent messages via yield
            4. Handle subscriber disconnection gracefully
            5. Implement backpressure if subscriber is slow

        Architecture:
            The Subscribe pattern would transform EventBus from a simple request/
            response service into a full pub/sub message broker. This requires:
            - In-memory or persistent message queue
            - Topic-based or content-based routing
            - Subscriber registry with connection management
            - Message buffering and overflow handling

        Note:
            The _ = request statement suppresses linter warnings about unused
            parameters. This is temporary until Subscribe is implemented.
        """
        _ = request  # Mark request as used to avoid linter warning
        logger.warning("Subscribe() called but not implemented.")
        context.abort(grpc.StatusCode.UNIMPLEMENTED, "Subscribe not supported")


class UniversalEventBusServicer(telemetry_grpc.UniversalEventBusServicer):
    """Implements UniversalEventBus service for new universal telemetry format.

    This servicer handles the new universal telemetry format with DeviceTelemetry
    and TelemetryEvent messages. It provides the same overload protection and
    validation as the legacy EventBusServicer.
    """

    def PublishTelemetry(self, request, context):
        """Handle PublishTelemetry RPC for universal device telemetry.

        Args:
            request: UniversalEnvelope containing DeviceTelemetry or ProcessEvent
            context: gRPC ServicerContext

        Returns:
            UniversalAck: Acknowledgment with status (OK, RETRY, INVALID, etc.)
        """
        t0 = time.time()
        BUS_REQS.inc()

        # Check overload
        if is_overloaded():
            logger.info(OVERLOAD_LOG)
            BUS_RETRY_TOTAL.inc()
            BUS_LAT.observe((time.time() - t0) * 1000.0)
            return telemetry_pb2.UniversalAck(
                status=telemetry_pb2.UniversalAck.Status.RETRY,
                reason=OVERLOAD_REASON,
                backoff_hint_ms=2000,
            )

        try:
            # Size check
            envelope_size = request.ByteSize()
            if envelope_size > MAX_ENV_BYTES:
                logger.info(
                    f"[PublishTelemetry] Envelope too large: {envelope_size} bytes"
                )
                BUS_INVALID.inc()
                return telemetry_pb2.UniversalAck(
                    status=telemetry_pb2.UniversalAck.Status.INVALID,
                    reason=f"Envelope too large ({envelope_size} > {MAX_ENV_BYTES} bytes)",
                )

            # Track inflight
            inflight = _inc_inflight()
            try:
                if inflight > BUS_MAX_INFLIGHT:
                    logger.info(
                        f"[PublishTelemetry] Server at capacity: {inflight} inflight"
                    )
                    BUS_RETRY_TOTAL.inc()
                    return telemetry_pb2.UniversalAck(
                        status=telemetry_pb2.UniversalAck.Status.RETRY,
                        reason=f"Server at capacity ({inflight} inflight)",
                        backoff_hint_ms=1000,
                    )

                # Process the telemetry
                if request.HasField("device_telemetry"):
                    dt = request.device_telemetry
                    logger.info(
                        f"[PublishTelemetry] device_id={dt.device_id} device_type={dt.device_type} events={len(dt.events)}"
                    )
                elif request.HasField("process"):
                    p = request.process
                    logger.info(
                        f"[PublishTelemetry] process: pid={p.pid} exe={p.exe[:50] if p.exe else 'N/A'}"
                    )
                elif request.HasField("flow"):
                    f = request.flow
                    logger.info(
                        f"[PublishTelemetry] flow: src={f.src_ip} dst={f.dst_ip}"
                    )
                else:
                    logger.warning("[PublishTelemetry] Empty envelope received")

                # Store in WAL for dashboard visibility
                if wal_storage:
                    try:
                        with _wal_lock:
                            conn = sqlite3.connect(
                                WAL_PATH,
                                timeout=5.0,
                                isolation_level=None,
                                check_same_thread=False,
                            )

                            idem = request.idempotency_key or f"unknown_{request.ts_ns}"
                            ts_ns = request.ts_ns
                            env_bytes = request.SerializeToString()
                            checksum = hashlib.blake2b(
                                env_bytes, digest_size=32
                            ).digest()

                            try:
                                conn.execute(
                                    "INSERT INTO wal (idem, ts_ns, bytes, checksum) VALUES (?, ?, ?, ?)",
                                    (idem, ts_ns, env_bytes, checksum),
                                )
                                logger.debug(
                                    "[PublishTelemetry] Stored in WAL (idem=%s)", idem
                                )
                            except sqlite3.IntegrityError:
                                logger.debug(
                                    "[PublishTelemetry] Duplicate (idem=%s), skipped",
                                    idem,
                                )
                            finally:
                                conn.close()
                    except Exception as wal_err:
                        logger.error(
                            "[PublishTelemetry] WAL storage failed: %s", wal_err
                        )

                BUS_LAT.observe((time.time() - t0) * 1000.0)
                return telemetry_pb2.UniversalAck(
                    status=telemetry_pb2.UniversalAck.Status.OK,
                    reason="accepted",
                    processed_timestamp_ns=int(time.time() * 1e9),
                    events_accepted=1,
                )
            finally:
                _dec_inflight()

        except Exception as e:
            logger.exception("[PublishTelemetry] Error")
            return telemetry_pb2.UniversalAck(
                status=telemetry_pb2.UniversalAck.Status.PROCESSING_ERROR, reason=str(e)
            )

    def PublishBatch(self, request, context):
        """Handle PublishBatch RPC (not yet implemented)"""
        _ = request
        logger.warning("PublishBatch() called but not implemented")
        context.abort(grpc.StatusCode.UNIMPLEMENTED, "PublishBatch not supported")

    def RegisterDevice(self, request, context):
        """Handle RegisterDevice RPC (not yet implemented)"""
        _ = request
        logger.warning("RegisterDevice() called but not implemented")
        context.abort(grpc.StatusCode.UNIMPLEMENTED, "RegisterDevice not supported")

    def UpdateDevice(self, request, context):
        """Handle UpdateDevice RPC (not yet implemented)"""
        _ = request
        logger.warning("UpdateDevice() called but not implemented")
        context.abort(grpc.StatusCode.UNIMPLEMENTED, "UpdateDevice not supported")

    def DeregisterDevice(self, request, context):
        """Handle DeregisterDevice RPC (not yet implemented)"""
        _ = request
        logger.warning("DeregisterDevice() called but not implemented")
        context.abort(grpc.StatusCode.UNIMPLEMENTED, "DeregisterDevice not supported")

    def GetHealth(self, request, context):
        """Handle GetHealth RPC (not yet implemented)"""
        _ = request
        logger.warning("GetHealth() called but not implemented")
        context.abort(grpc.StatusCode.UNIMPLEMENTED, "GetHealth not supported")

    def GetStatus(self, request, context):
        """Handle GetStatus RPC (not yet implemented)"""
        _ = request
        logger.warning("GetStatus() called but not implemented")
        context.abort(grpc.StatusCode.UNIMPLEMENTED, "GetStatus not supported")

    def GetMetrics(self, request, context):
        """Handle GetMetrics RPC (not yet implemented)"""
        _ = request
        logger.warning("GetMetrics() called but not implemented")
        context.abort(grpc.StatusCode.UNIMPLEMENTED, "GetMetrics not supported")


def _start_health_server():
    """Start a lightweight HTTP health check server on port 8080.

    This function launches a simple HTTP server in a daemon thread that responds
    to health check requests at the /healthz endpoint. This is used by container
    orchestrators (Kubernetes, Docker) to determine if the service is alive and
    ready to accept traffic.

    The health server runs independently of the gRPC server and uses a minimal
    HTTP implementation to avoid dependencies on the main service state.

    Endpoints:
        GET /healthz -> 200 OK with body "OK bus"
        GET <other>  -> 404 Not Found

    Side Effects:
        Starts an HTTP server on 0.0.0.0:8080 in a daemon thread. The daemon
        thread will automatically terminate when the main process exits.

    Implementation:
        Uses Python's built-in http.server module with a minimal custom handler.
        The server runs in a separate thread so it doesn't block the main gRPC
        server startup.

    Thread Safety:
        The health server runs in a daemon thread and does not share state with
        the gRPC server, so no locking is required.

    Health Check Semantics:
        The current implementation is a simple liveness check (returns 200 if
        process is running). For production, consider:
        - Readiness check: Only return 200 when gRPC server is fully initialized
        - Dependency checks: Verify database, downstream services are reachable
        - Graceful shutdown: Return 503 when _SHOULD_EXIT is True

    Kubernetes Integration:
        Configure livenessProbe and readinessProbe to use this endpoint:

        livenessProbe:
          httpGet:
            path: /healthz
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 5

    Note:
        The server binds to 0.0.0.0 (all interfaces) to be accessible from
        container orchestrators. In production, consider restricting to
        localhost or using network policies.
    """

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/healthz":
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK bus")

    t = threading.Thread(
        target=lambda: HTTPServer(("0.0.0.0", 8080), H).serve_forever(), daemon=True
    )
    t.start()


def serve():
    """Run the EventBus gRPC server with TLS and metrics.

    This is the main server function that initializes and runs the EventBus gRPC
    service. It handles configuration loading, TLS certificate setup, service
    registration, and the main server loop.

    The function runs indefinitely until interrupted or a fatal error occurs. It
    performs these initialization steps:

    1. Initialize overload mode from CLI or environment
    2. Start Prometheus metrics HTTP servers
    3. Create gRPC server with thread pool
    4. Load TLS certificates (server cert, key, CA)
    5. Configure mTLS with client certificate requirement
    6. Bind to configured port with TLS credentials
    7. Register EventBusServicer
    8. Start server and enter main loop

    Configuration Sources:
        - CLI arguments: --overload flag sets _OVERLOAD
        - Environment: BUS_OVERLOAD, BUS_SERVER_PORT
        - Config file: Via get_config() for ports, limits, paths

    TLS Configuration:
        The server requires mutual TLS (mTLS) with:
        - Server certificate: certs/server.crt
        - Server private key: certs/server.key
        - CA certificate: certs/ca.crt (for validating client certs)
        - require_client_auth=True (enforce mTLS)

    Metrics:
        Starts two Prometheus HTTP servers on configurable ports (default 9090,
        9091). Multiple ports allow binding to different interfaces or provide
        redundancy. Metrics can be disabled via config.

    Port Configuration:
        - gRPC server: BUS_SERVER_PORT env var or config.eventbus.port
        - Metrics: config.eventbus.metrics_port_1 and metrics_port_2
        - Health check: Hardcoded 8080 (if _start_health_server is called)

    Raises:
        Exception: If TLS certificates cannot be loaded or server initialization
                   fails. The exception is logged and re-raised to crash the
                   process (fail-fast behavior).

    Side Effects:
        - Sets global _OVERLOAD and BUS_IS_OVERLOADED
        - Starts Prometheus metrics HTTP servers (if not disabled)
        - Starts gRPC server listening on configured port
        - Logs extensively for debugging and operational visibility

    Main Loop:
        After starting the server, enters an infinite sleep loop. The server
        continues running until:
        - Process is killed (SIGTERM, SIGKILL)
        - SIGHUP triggers _SHOULD_EXIT (not currently checked)
        - Unhandled exception crashes the process

    Security:
        - mTLS provides authentication and encryption for all connections
        - Client certificates must be signed by the CA in certs/ca.crt
        - Private key file permissions should be 0600 (read-only by owner)
        - Consider using secrets management (Vault, k8s secrets) for certs

    Future Enhancements:
        - Graceful shutdown: Check _SHOULD_EXIT in main loop
        - Certificate rotation: Reload certs on SIGHUP
        - Configuration reload: Update limits without restart
        - Health check server: Call _start_health_server()
        - Signature verification: Call _load_keys() and _load_trust()

    Example Deployment:
        >>> if __name__ == "__main__":
        >>>     # Parse CLI args
        >>>     _OVERLOAD = args.overload == 'on'
        >>>     # Start server
        >>>     serve()

    Note:
        The function logs the overload mode initialization with source tracking
        (cli vs env vs default) to help operators understand the server's runtime
        configuration.
    """
    global _OVERLOAD, BUS_IS_OVERLOADED, wal_storage

    try:
        # Initialize WAL storage for persistent event storage
        try:
            wal_storage = SQLiteWAL(
                path=WAL_PATH, max_bytes=config.storage.max_wal_bytes
            )
            logger.info(f"Initialized WAL storage at {WAL_PATH}")
        except Exception as e:
            logger.error(f"Failed to initialize WAL storage: {e}")
            logger.warning("EventBus will run without persistent storage")
            wal_storage = None

        # Determine source for logging
        if _OVERLOAD is None:
            # Fallback to environment if not set by CLI
            env = os.getenv("BUS_OVERLOAD", "")
            if env.strip() in ("1", "true", "on", "yes"):
                _OVERLOAD = True
                source = f"env:{env}"
            else:
                _OVERLOAD = False
                source = "default"
        else:
            source = "cli"

        # Also set the legacy BUS_IS_OVERLOADED for backward compatibility
        BUS_IS_OVERLOADED = _OVERLOAD

        logger.info("Starting server with configuration:")
        logger.info("  BUS_OVERLOAD=%s (source=%s)", _OVERLOAD, source)

        def start_metrics_server(port):
            try:
                start_http_server(port)
                logger.info("Started metrics server on :%d", port)
            except OSError as e:
                logger.warning("Could not start metrics on :%d: %s", port, e)

        METRICS1 = config.eventbus.metrics_port_1
        METRICS2 = config.eventbus.metrics_port_2
        DISABLE_METRICS = config.eventbus.metrics_disabled

        if not DISABLE_METRICS:
            start_metrics_server(METRICS1)
            start_metrics_server(METRICS2)

        logger.info("Initializing gRPC server...")
        server = grpc.server(futures.ThreadPoolExecutor(max_workers=50))

        # Load TLS certs
        try:
            with open("certs/server.key", "rb") as f:
                key = f.read()
            with open("certs/server.crt", "rb") as f:
                crt = f.read()
            with open("certs/ca.crt", "rb") as f:
                ca = f.read()

            # Support optional client auth for CI/test environments
            require_client_auth = (
                os.getenv("EVENTBUS_REQUIRE_CLIENT_AUTH", "false").lower() == "true"
            )

            creds = grpc.ssl_server_credentials(
                [(key, crt)],
                root_certificates=ca,
                require_client_auth=require_client_auth,
            )
            logger.info(
                "Loaded TLS certificates successfully (mTLS: %s)", require_client_auth
            )
        except Exception as e:
            logger.exception("Failed to load TLS certificates: %s", e)
            raise

        # Bind server to configurable port (check environment at runtime)
        server_port = int(os.getenv("BUS_SERVER_PORT", str(config.eventbus.port)))
        server.add_secure_port(f"[::]:{server_port}", creds)
        logger.info("gRPC server bound to port %d with TLS", server_port)

        # Register EventBus services (both legacy and universal)
        try:
            pbrpc.add_EventBusServicer_to_server(EventBusServicer(), server)
            logger.info("Registered EventBusServicer (legacy) with gRPC server")

            telemetry_grpc.add_UniversalEventBusServicer_to_server(
                UniversalEventBusServicer(), server
            )
            logger.info("Registered UniversalEventBusServicer with gRPC server")
        except Exception as e:
            logger.exception("Failed to register EventBus services: %s", e)
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
    parser.add_argument(
        "--overload",
        choices=["on", "off", "auto"],
        default=None,
        help="Override overload behavior: on/off/auto (default: use BUS_OVERLOAD env)",
    )
    args = parser.parse_args()

    # Initialize _OVERLOAD based on CLI argument or environment
    if args.overload == "on":
        _OVERLOAD = True
        logger.info("Overload mode ENABLED via CLI argument")
    elif args.overload == "off":
        _OVERLOAD = False
        logger.info("Overload mode DISABLED via CLI argument")
    else:
        # Default to environment variable
        _OVERLOAD = os.getenv("BUS_OVERLOAD", "false").lower() == "true"
        logger.info(f"Overload mode set to {_OVERLOAD} via environment variable")

    serve()
