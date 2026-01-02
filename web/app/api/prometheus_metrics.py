"""
Prometheus Metrics Endpoint for AMOSKYS Web Application.

Exposes application metrics in Prometheus format for scraping.
Runs on a separate port (9102) to avoid auth requirements.
"""

import os
import threading
import time
from functools import wraps
from http.server import BaseHTTPRequestHandler, HTTPServer

from flask import Blueprint, Response, g, request

try:
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        REGISTRY,
        CollectorRegistry,
        Counter,
        Gauge,
        Histogram,
        Info,
        generate_latest,
    )

    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    REGISTRY = None
    CONTENT_TYPE_LATEST = "text/plain"

prometheus_bp = Blueprint("prometheus", __name__, url_prefix="/api/prometheus")

_metrics_initialized = False
_metrics_lock = threading.Lock()

METRICS_REGISTRY = None
APP_INFO = None
REQUEST_COUNT = None
REQUEST_LATENCY = None
REQUEST_IN_PROGRESS = None
ACTIVE_AGENTS = None
AGENT_CONNECTIONS = None
DB_QUERY_COUNT = None
DB_QUERY_LATENCY = None
TELEMETRY_EVENTS = None
TELEMETRY_QUEUE_SIZE = None
AUTH_ATTEMPTS = None
SECURITY_EVENTS = None
UPTIME_SECONDS = None
STARTUP_TIME = None


def _init_metrics():
    """Initialize Prometheus metrics (called once at first use)."""
    global _metrics_initialized, METRICS_REGISTRY, APP_INFO, REQUEST_COUNT
    global REQUEST_LATENCY, REQUEST_IN_PROGRESS, ACTIVE_AGENTS, AGENT_CONNECTIONS
    global DB_QUERY_COUNT, DB_QUERY_LATENCY, TELEMETRY_EVENTS, TELEMETRY_QUEUE_SIZE
    global AUTH_ATTEMPTS, SECURITY_EVENTS, UPTIME_SECONDS, STARTUP_TIME

    if not PROMETHEUS_AVAILABLE:
        return

    with _metrics_lock:
        if _metrics_initialized:
            return

        _metrics_initialized = True
        METRICS_REGISTRY = REGISTRY
        STARTUP_TIME = time.time()

        try:
            APP_INFO = Info("amoskys_web", "AMOSKYS Web Application Information")
            APP_INFO.info(
                {
                    "version": os.getenv("APP_VERSION", "1.0.0"),
                    "environment": os.getenv("FLASK_ENV", "development"),
                }
            )
        except ValueError:
            pass

        try:
            REQUEST_COUNT = Counter(
                "amoskys_http_requests_total",
                "Total HTTP requests",
                ["method", "endpoint", "status"],
            )
        except ValueError:
            pass

        try:
            REQUEST_LATENCY = Histogram(
                "amoskys_http_request_duration_seconds",
                "HTTP request latency in seconds",
                ["method", "endpoint"],
                buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
            )
        except ValueError:
            pass

        try:
            REQUEST_IN_PROGRESS = Gauge(
                "amoskys_http_requests_in_progress",
                "Number of HTTP requests currently being processed",
                ["method", "endpoint"],
            )
        except ValueError:
            pass

        try:
            ACTIVE_AGENTS = Gauge(
                "amoskys_active_agents", "Number of currently active agents"
            )
        except ValueError:
            pass

        try:
            AGENT_CONNECTIONS = Counter(
                "amoskys_agent_connections_total",
                "Total agent connection attempts",
                ["status"],
            )
        except ValueError:
            pass

        try:
            DB_QUERY_COUNT = Counter(
                "amoskys_db_queries_total",
                "Total database queries",
                ["operation", "table"],
            )
        except ValueError:
            pass

        try:
            DB_QUERY_LATENCY = Histogram(
                "amoskys_db_query_duration_seconds",
                "Database query latency in seconds",
                ["operation"],
                buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
            )
        except ValueError:
            pass

        try:
            TELEMETRY_EVENTS = Counter(
                "amoskys_telemetry_events_total",
                "Total telemetry events received",
                ["event_type"],
            )
        except ValueError:
            pass

        try:
            TELEMETRY_QUEUE_SIZE = Gauge(
                "amoskys_telemetry_queue_size", "Current telemetry queue size"
            )
        except ValueError:
            pass

        try:
            AUTH_ATTEMPTS = Counter(
                "amoskys_auth_attempts_total",
                "Total authentication attempts",
                ["type", "status"],
            )
        except ValueError:
            pass

        try:
            SECURITY_EVENTS = Counter(
                "amoskys_security_events_total",
                "Total security events",
                ["event_type", "severity"],
            )
        except ValueError:
            pass

        try:
            UPTIME_SECONDS = Gauge(
                "amoskys_uptime_seconds", "Application uptime in seconds"
            )
        except ValueError:
            pass


def update_uptime():
    """Update the uptime gauge."""
    if UPTIME_SECONDS is not None and STARTUP_TIME is not None:
        UPTIME_SECONDS.set(time.time() - STARTUP_TIME)


def track_request_metrics(f):
    """Decorator to track request metrics for Flask routes."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not PROMETHEUS_AVAILABLE or REQUEST_COUNT is None:
            return f(*args, **kwargs)

        method = request.method
        endpoint = request.endpoint or "unknown"

        if REQUEST_IN_PROGRESS:
            REQUEST_IN_PROGRESS.labels(method=method, endpoint=endpoint).inc()
        start_time = time.time()

        try:
            response = f(*args, **kwargs)
            status = getattr(response, "status_code", 200)
            REQUEST_COUNT.labels(method=method, endpoint=endpoint, status=status).inc()
            return response
        except Exception:
            REQUEST_COUNT.labels(method=method, endpoint=endpoint, status=500).inc()
            raise
        finally:
            if REQUEST_LATENCY:
                REQUEST_LATENCY.labels(method=method, endpoint=endpoint).observe(
                    time.time() - start_time
                )
            if REQUEST_IN_PROGRESS:
                REQUEST_IN_PROGRESS.labels(method=method, endpoint=endpoint).dec()

    return decorated_function


def record_auth_attempt(auth_type, success):
    """Record an authentication attempt."""
    if AUTH_ATTEMPTS is not None:
        AUTH_ATTEMPTS.labels(
            type=auth_type, status="success" if success else "failure"
        ).inc()


def record_security_event(event_type, severity):
    """Record a security event."""
    if SECURITY_EVENTS is not None:
        SECURITY_EVENTS.labels(event_type=event_type, severity=severity).inc()


def record_telemetry_event(event_type):
    """Record a telemetry event."""
    if TELEMETRY_EVENTS is not None:
        TELEMETRY_EVENTS.labels(event_type=event_type).inc()


def set_active_agents(count):
    """Set the number of active agents."""
    if ACTIVE_AGENTS is not None:
        ACTIVE_AGENTS.set(count)


def record_agent_connection(success):
    """Record an agent connection attempt."""
    if AGENT_CONNECTIONS is not None:
        AGENT_CONNECTIONS.labels(status="success" if success else "failure").inc()


def record_db_query(operation, table, duration):
    """Record a database query."""
    if DB_QUERY_COUNT is not None:
        DB_QUERY_COUNT.labels(operation=operation, table=table).inc()
    if DB_QUERY_LATENCY is not None:
        DB_QUERY_LATENCY.labels(operation=operation).observe(duration)


@prometheus_bp.route("/metrics", methods=["GET"])
def metrics_endpoint():
    """Expose Prometheus metrics."""
    if not PROMETHEUS_AVAILABLE:
        return Response(
            "# prometheus_client not installed\n", mimetype="text/plain", status=503
        )

    _init_metrics()
    update_uptime()

    return Response(generate_latest(METRICS_REGISTRY), mimetype=CONTENT_TYPE_LATEST)


class MetricsHandler(BaseHTTPRequestHandler):
    """HTTP handler for Prometheus metrics endpoint."""

    def do_GET(self):
        if self.path == "/metrics" or self.path == "/":
            if PROMETHEUS_AVAILABLE:
                _init_metrics()
                update_uptime()
                metrics = generate_latest(METRICS_REGISTRY)
                self.send_response(200)
                self.send_header("Content-Type", CONTENT_TYPE_LATEST)
                self.send_header("Content-Length", str(len(metrics)))
                self.end_headers()
                self.wfile.write(metrics)
            else:
                self.send_response(503)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"# prometheus_client not installed\n")
        elif self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")
        elif self.path == "/ready":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")
        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found")

    def log_message(self, format, *args):
        """Suppress access logs for metrics endpoint."""
        pass


_metrics_server_started = False
_metrics_server_lock = threading.Lock()


def start_metrics_server(port=9102):
    """Start a dedicated HTTP server for Prometheus metrics."""
    global _metrics_server_started

    with _metrics_server_lock:
        if _metrics_server_started:
            return None

        try:
            import socket

            server = HTTPServer(("0.0.0.0", port), MetricsHandler)
            server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            _metrics_server_started = True
            _init_metrics()
            print(f"Prometheus metrics server started on port {port}")
            return thread
        except OSError as e:
            print(f"Warning: Could not start metrics server on port {port}: {e}")
            return None


def init_metrics_middleware(app):
    """Initialize metrics middleware for Flask app."""
    if not PROMETHEUS_AVAILABLE:
        return

    _init_metrics()

    @app.before_request
    def before_request():
        g.start_time = time.time()
        if REQUEST_IN_PROGRESS:
            method = request.method
            endpoint = request.endpoint or "unknown"
            REQUEST_IN_PROGRESS.labels(method=method, endpoint=endpoint).inc()

    @app.after_request
    def after_request(response):
        if hasattr(g, "start_time"):
            method = request.method
            endpoint = request.endpoint or "unknown"
            status = response.status_code

            if REQUEST_COUNT:
                REQUEST_COUNT.labels(
                    method=method, endpoint=endpoint, status=status
                ).inc()
            if REQUEST_LATENCY:
                REQUEST_LATENCY.labels(method=method, endpoint=endpoint).observe(
                    time.time() - g.start_time
                )
            if REQUEST_IN_PROGRESS:
                REQUEST_IN_PROGRESS.labels(method=method, endpoint=endpoint).dec()

        return response
