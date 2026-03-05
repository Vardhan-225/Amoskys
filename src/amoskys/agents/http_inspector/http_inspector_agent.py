#!/usr/bin/env python3
"""AMOSKYS HTTP Inspector Agent - Micro-Probe Architecture.

This is the modernized HTTP Inspector agent using the "swarm of eyes" pattern.
8 micro-probes each watch one specific HTTP threat vector.

Probes:
    1. XSSDetectionProbe - Cross-site scripting payload detection
    2. SSRFDetectionProbe - Server-side request forgery detection
    3. PathTraversalProbe - Directory traversal attack detection
    4. APIAbuseProbe - API enumeration and abuse patterns
    5. DataExfilHTTPProbe - Data exfiltration over HTTP
    6. SuspiciousUploadProbe - Malicious file upload detection
    7. WebSocketAbuseProbe - WebSocket protocol abuse
    8. CSRFTokenMissingProbe - Missing CSRF protection detection

MITRE ATT&CK Coverage:
    - T1059.007: Command and Scripting Interpreter: JavaScript
    - T1090: Proxy (SSRF)
    - T1083: File and Directory Discovery
    - T1087: Account Discovery
    - T1567: Exfiltration Over Web Service
    - T1505.003: Server Software Component: Web Shell
    - T1071.001: Application Layer Protocol: Web Protocols
    - T1557: Adversary-in-the-Middle

Usage:
    >>> agent = HTTPInspectorAgent()
    >>> agent.run_forever()
"""

from __future__ import annotations

import json
import logging
import platform
import re
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import parse_qs, urlparse

import grpc

from amoskys.agents.common.base import HardenedAgentBase, ValidationResult
from amoskys.agents.common.probes import MicroProbeAgentMixin, TelemetryEvent
from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.agents.http_inspector.agent_types import HTTPTransaction
from amoskys.agents.http_inspector.probes import create_http_inspector_probes
from amoskys.config import get_config
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.proto import universal_telemetry_pb2_grpc as universal_pbrpc

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("HTTPInspectorAgent")

config = get_config()
EVENTBUS_ADDRESS = config.agent.bus_address
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = getattr(
    config.agent, "http_inspector_queue_path", "data/queue/http_inspector.db"
)


# =============================================================================
# EventBus Publisher
# =============================================================================


class EventBusPublisher:
    """Wrapper for EventBus gRPC client."""

    def __init__(self, address: str, cert_dir: str):
        self.address = address
        self.cert_dir = cert_dir
        self._channel = None
        self._stub = None

    def _ensure_channel(self):
        """Create gRPC channel if needed."""
        if self._channel is None:
            try:
                with open(f"{self.cert_dir}/ca.crt", "rb") as f:
                    ca_cert = f.read()
                with open(f"{self.cert_dir}/agent.crt", "rb") as f:
                    client_cert = f.read()
                with open(f"{self.cert_dir}/agent.key", "rb") as f:
                    client_key = f.read()

                credentials = grpc.ssl_channel_credentials(
                    root_certificates=ca_cert,
                    private_key=client_key,
                    certificate_chain=client_cert,
                )
                self._channel = grpc.secure_channel(self.address, credentials)
                self._stub = universal_pbrpc.UniversalEventBusStub(self._channel)
                logger.info("Created secure gRPC channel with mTLS")
            except FileNotFoundError as e:
                raise RuntimeError(f"Certificate not found: {e}")
            except Exception as e:
                raise RuntimeError(f"Failed to create gRPC channel: {e}")

    def publish(self, events: list) -> None:
        """Publish events to EventBus."""
        self._ensure_channel()

        for event in events:
            # Already-wrapped envelopes (e.g. from drain path) go directly
            if isinstance(event, telemetry_pb2.UniversalEnvelope):
                envelope = event
            else:
                timestamp_ns = int(time.time() * 1e9)
                idempotency_key = f"{event.device_id}_{timestamp_ns}"
                envelope = telemetry_pb2.UniversalEnvelope(
                    version="v1",
                    ts_ns=timestamp_ns,
                    idempotency_key=idempotency_key,
                    device_telemetry=event,
                    priority="NORMAL",
                    requires_acknowledgment=True,
                    schema_version=1,
                )

            ack = self._stub.PublishTelemetry(envelope, timeout=5.0)

            if ack.status != telemetry_pb2.UniversalAck.OK:
                raise Exception(f"EventBus returned status: {ack.status}")

    def close(self):
        """Close gRPC channel."""
        if self._channel:
            self._channel.close()
            self._channel = None
            self._stub = None


# =============================================================================
# Platform-Specific HTTP Collectors
# =============================================================================


class HTTPCollector:
    """Base class for platform-specific HTTP transaction collection."""

    def collect(self) -> List[HTTPTransaction]:
        """Collect HTTP transactions from system.

        Returns:
            List of HTTPTransaction objects
        """
        raise NotImplementedError


class MacOSHTTPCollector(HTTPCollector):
    """Collects HTTP transactions on macOS.

    Data sources:
        - nettop for HTTP flow identification (bytes_in/bytes_out)
        - Unified logging for NSURLSession activity
        - Configurable proxy log paths
    """

    def __init__(self, proxy_log_paths: Optional[List[str]] = None):
        self.proxy_log_paths = proxy_log_paths or []
        self._last_collection: Optional[datetime] = None

    def collect(self) -> List[HTTPTransaction]:
        """Collect HTTP transactions from macOS sources."""
        transactions: List[HTTPTransaction] = []

        # Source 1: nettop for HTTP flow identification
        transactions.extend(self._collect_from_nettop())

        # Source 2: Unified logging for NSURLSession
        transactions.extend(self._collect_from_unified_log())

        # Source 3: Proxy logs (if configured)
        for log_path in self.proxy_log_paths:
            transactions.extend(self._parse_proxy_log(log_path))

        self._last_collection = datetime.now(timezone.utc)
        return transactions

    def _collect_from_nettop(self) -> List[HTTPTransaction]:
        """Collect network flow data via nettop."""
        transactions: List[HTTPTransaction] = []
        try:
            cmd = [
                "nettop",
                "-d",
                "-x",
                "-J",
                "bytes_in,bytes_out,rx_dupe,rx_ooo",
                "-L",
                "1",  # one sample
                "-P",  # parseable
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout:
                for line in result.stdout.strip().split("\n"):
                    txn = self._parse_nettop_line(line)
                    if txn:
                        transactions.append(txn)
        except subprocess.TimeoutExpired:
            logger.warning("nettop collection timed out")
        except FileNotFoundError:
            logger.debug("nettop not available on this system")
        except Exception as e:
            logger.error("Failed to collect from nettop: %s", e)

        return transactions

    def _parse_nettop_line(self, line: str) -> Optional[HTTPTransaction]:
        """Parse a nettop output line into an HTTPTransaction."""
        try:
            # nettop output format: process.pid,bytes_in,bytes_out,...
            parts = line.strip().split(",")
            if len(parts) < 3:
                return None

            proc_info = parts[0].strip()
            bytes_in = int(parts[1]) if parts[1].strip().isdigit() else 0
            bytes_out = int(parts[2]) if parts[2].strip().isdigit() else 0

            # Skip zero-traffic entries
            if bytes_in == 0 and bytes_out == 0:
                return None

            # Extract process name and PID
            proc_parts = proc_info.rsplit(".", 1)
            process_name = proc_parts[0] if proc_parts else proc_info

            # nettop only gives us flow-level data, not full HTTP
            # We create a partial transaction for correlation
            return HTTPTransaction(
                timestamp=datetime.now(timezone.utc),
                method="FLOW",
                url=f"flow://{process_name}",
                host="",
                path="/",
                query_params={},
                request_headers={},
                request_body=None,
                response_status=0,
                content_type="",
                src_ip="127.0.0.1",
                dst_ip="",
                bytes_sent=bytes_out,
                bytes_received=bytes_in,
                process_name=process_name,
                is_tls=False,
            )
        except Exception as e:
            logger.debug("Failed to parse nettop line: %s", e)
            return None

    def _collect_from_unified_log(self) -> List[HTTPTransaction]:
        """Collect HTTP activity from macOS unified logging (NSURLSession)."""
        transactions: List[HTTPTransaction] = []
        try:
            cmd = [
                "log",
                "show",
                "--predicate",
                'subsystem == "com.apple.CFNetwork" AND '
                'eventMessage CONTAINS "HTTP"',
                "--last",
                "1m",
                "--style",
                "json",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode == 0 and result.stdout:
                try:
                    logs = json.loads(result.stdout)
                    for entry in logs:
                        txn = self._parse_cfnetwork_entry(entry)
                        if txn:
                            transactions.append(txn)
                except json.JSONDecodeError:
                    logger.debug("Failed to parse unified log output as JSON")
        except subprocess.TimeoutExpired:
            logger.warning("Unified log collection timed out")
        except Exception as e:
            logger.error("Failed to collect from unified log: %s", e)

        return transactions

    def _parse_cfnetwork_entry(self, entry: Dict) -> Optional[HTTPTransaction]:
        """Parse a CFNetwork unified log entry into an HTTPTransaction."""
        try:
            message = entry.get("eventMessage", "")
            if "HTTP" not in message:
                return None

            timestamp = datetime.now(timezone.utc)
            ts_str = entry.get("timestamp", "")
            if ts_str:
                try:
                    timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                except ValueError:
                    pass

            # Extract HTTP method and URL from log message
            method = "GET"
            url = ""
            status = 0

            # Common patterns in CFNetwork logs
            method_match = re.search(
                r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b", message
            )
            if method_match:
                method = method_match.group(1)

            url_match = re.search(r"(https?://[^\s\"']+)", message)
            if url_match:
                url = url_match.group(1)

            status_match = re.search(r"status\s*[:=]\s*(\d{3})", message, re.IGNORECASE)
            if status_match:
                status = int(status_match.group(1))

            if not url:
                return None

            parsed = urlparse(url)
            query_params = {}
            if parsed.query:
                qs = parse_qs(parsed.query, keep_blank_values=True)
                query_params = {k: v[0] if v else "" for k, v in qs.items()}

            process = entry.get("processImagePath", "")
            process_name = process.split("/")[-1] if process else None

            return HTTPTransaction(
                timestamp=timestamp,
                method=method,
                url=url,
                host=parsed.hostname or "",
                path=parsed.path or "/",
                query_params=query_params,
                request_headers={},
                request_body=None,
                response_status=status,
                content_type="",
                src_ip="127.0.0.1",
                dst_ip="",
                bytes_sent=0,
                bytes_received=0,
                process_name=process_name,
                is_tls=parsed.scheme == "https",
            )
        except Exception as e:
            logger.debug("Failed to parse CFNetwork entry: %s", e)
            return None

    def _parse_proxy_log(self, log_path: str) -> List[HTTPTransaction]:
        """Parse proxy/access log file for HTTP transactions."""
        transactions: List[HTTPTransaction] = []
        path = Path(log_path)
        if not path.exists():
            return transactions

        try:
            # Read last 1000 lines (tail behavior)
            with open(log_path, "r", errors="replace") as f:
                lines = f.readlines()[-1000:]

            for line in lines:
                txn = _parse_access_log_line(line.strip())
                if txn:
                    transactions.append(txn)
        except Exception as e:
            logger.error("Failed to parse proxy log %s: %s", log_path, e)

        return transactions


class LinuxHTTPCollector(HTTPCollector):
    """Collects HTTP transactions on Linux.

    Data sources:
        - nginx/apache access logs with request bodies
        - /proc/net/tcp for connection tracking
        - Configurable reverse proxy log paths
    """

    DEFAULT_LOG_PATHS = [
        "/var/log/nginx/access.log",
        "/var/log/apache2/access.log",
        "/var/log/httpd/access_log",
    ]

    def __init__(self, proxy_log_paths: Optional[List[str]] = None):
        self.proxy_log_paths = proxy_log_paths or []
        self._last_collection: Optional[datetime] = None
        self._last_log_positions: Dict[str, int] = {}

    def collect(self) -> List[HTTPTransaction]:
        """Collect HTTP transactions from Linux sources."""
        transactions: List[HTTPTransaction] = []

        # Source 1: Parse access logs
        log_paths = self.DEFAULT_LOG_PATHS + self.proxy_log_paths
        for log_path in log_paths:
            transactions.extend(self._parse_access_log(log_path))

        # Source 2: /proc/net/tcp for active HTTP connections
        transactions.extend(self._collect_from_proc_net())

        self._last_collection = datetime.now(timezone.utc)
        return transactions

    def _parse_access_log(self, log_path: str) -> List[HTTPTransaction]:
        """Parse nginx/apache access log for new entries."""
        transactions: List[HTTPTransaction] = []
        path = Path(log_path)
        if not path.exists():
            return transactions

        try:
            current_size = path.stat().st_size
            last_pos = self._last_log_positions.get(log_path, 0)

            # Skip if file hasn't grown
            if current_size <= last_pos:
                if current_size < last_pos:
                    last_pos = 0  # File was rotated
                else:
                    return transactions

            with open(log_path, "r", errors="replace") as f:
                f.seek(last_pos)
                for line in f:
                    txn = _parse_access_log_line(line.strip())
                    if txn:
                        transactions.append(txn)

                self._last_log_positions[log_path] = f.tell()

        except PermissionError:
            logger.debug("Permission denied reading %s", log_path)
        except Exception as e:
            logger.error("Failed to parse access log %s: %s", log_path, e)

        return transactions

    def _collect_from_proc_net(self) -> List[HTTPTransaction]:
        """Collect active HTTP connections from /proc/net/tcp."""
        transactions: List[HTTPTransaction] = []
        proc_path = Path("/proc/net/tcp")
        if not proc_path.exists():
            return transactions

        try:
            with open(proc_path, "r") as f:
                lines = f.readlines()[1:]  # Skip header

            for line in lines:
                parts = line.strip().split()
                if len(parts) < 4:
                    continue

                # Parse local and remote addresses
                local_addr = parts[1]
                remote_addr = parts[2]
                state = parts[3]

                # Only track ESTABLISHED connections (state 01)
                if state != "01":
                    continue

                try:
                    local_ip, local_port = self._parse_hex_addr(local_addr)
                    remote_ip, remote_port = self._parse_hex_addr(remote_addr)
                except (ValueError, IndexError):
                    continue

                # Only track HTTP/HTTPS ports
                if remote_port not in (80, 443, 8080, 8443, 3000, 5000, 8000):
                    continue

                transactions.append(
                    HTTPTransaction(
                        timestamp=datetime.now(timezone.utc),
                        method="CONN",
                        url=f"tcp://{remote_ip}:{remote_port}",
                        host=remote_ip,
                        path="/",
                        query_params={},
                        request_headers={},
                        request_body=None,
                        response_status=0,
                        content_type="",
                        src_ip=local_ip,
                        dst_ip=remote_ip,
                        bytes_sent=0,
                        bytes_received=0,
                        process_name=None,
                        is_tls=(remote_port in (443, 8443)),
                    )
                )

        except Exception as e:
            logger.error("Failed to collect from /proc/net/tcp: %s", e)

        return transactions

    @staticmethod
    def _parse_hex_addr(hex_addr: str) -> tuple:
        """Parse hex-encoded IP:port from /proc/net/tcp."""
        ip_hex, port_hex = hex_addr.split(":")
        port = int(port_hex, 16)
        # Convert hex IP (little-endian on x86)
        ip_int = int(ip_hex, 16)
        ip = "{}.{}.{}.{}".format(
            ip_int & 0xFF,
            (ip_int >> 8) & 0xFF,
            (ip_int >> 16) & 0xFF,
            (ip_int >> 24) & 0xFF,
        )
        return ip, port


# Common log format parser (used by both collectors)
# Matches: IP - - [timestamp] "METHOD /path HTTP/x.x" status bytes
_ACCESS_LOG_RE = re.compile(
    r"^(?P<src_ip>\S+)\s+\S+\s+\S+\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r'"(?P<method>\S+)\s+(?P<url>\S+)\s+\S+"\s+'
    r"(?P<status>\d+)\s+"
    r"(?P<bytes>\d+|-)"
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)


def _parse_access_log_line(line: str) -> Optional[HTTPTransaction]:
    """Parse a single access log line into an HTTPTransaction."""
    if not line:
        return None

    match = _ACCESS_LOG_RE.match(line)
    if not match:
        return None

    try:
        groups = match.groupdict()
        src_ip = groups["src_ip"]
        method = groups["method"]
        raw_url = groups["url"]
        status = int(groups["status"])
        bytes_received = int(groups["bytes"]) if groups["bytes"] != "-" else 0

        # Parse timestamp
        ts_str = groups["timestamp"]
        timestamp = datetime.now(timezone.utc)
        try:
            # Common log format: 01/Mar/2026:12:00:00 +0000
            timestamp = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            pass

        # Parse URL
        parsed = urlparse(raw_url)
        host = parsed.hostname or ""
        path = parsed.path or "/"
        query_params = {}
        if parsed.query:
            qs = parse_qs(parsed.query, keep_blank_values=True)
            query_params = {k: v[0] if v else "" for k, v in qs.items()}

        # Build headers from available data
        headers: Dict[str, str] = {}
        referer = groups.get("referer")
        user_agent = groups.get("user_agent")
        if referer and referer != "-":
            headers["referer"] = referer
        if user_agent and user_agent != "-":
            headers["user-agent"] = user_agent

        return HTTPTransaction(
            timestamp=timestamp,
            method=method,
            url=raw_url,
            host=host,
            path=path,
            query_params=query_params,
            request_headers=headers,
            request_body=None,
            response_status=status,
            content_type="",
            src_ip=src_ip,
            dst_ip="127.0.0.1",
            bytes_sent=0,
            bytes_received=bytes_received,
            process_name=None,
            is_tls=False,
        )
    except Exception as e:
        logger.debug("Failed to parse access log line: %s", e)
        return None


def get_http_collector() -> HTTPCollector:
    """Get platform-appropriate HTTP collector."""
    system = platform.system()
    if system == "Darwin":
        return MacOSHTTPCollector()
    elif system == "Linux":
        return LinuxHTTPCollector()
    else:
        logger.warning(
            "Unsupported platform: %s, defaulting to macOS collector", system
        )
        return MacOSHTTPCollector()


# =============================================================================
# HTTP Inspector Agent
# =============================================================================


class HTTPInspectorAgent(MicroProbeAgentMixin, HardenedAgentBase):
    """HTTP Inspector Agent with micro-probe architecture.

    This agent hosts 8 micro-probes that each monitor a specific HTTP
    threat vector. The agent handles:
        - HTTP transaction collection (platform-specific)
        - Probe lifecycle management
        - Event aggregation and publishing
        - Circuit breaker and retry logic
        - Offline queue management

    Probes are responsible only for detection - no networking or state
    management.
    """

    # Agent color for dashboard UI
    COLOR = "#7B68EE"

    def __init__(self, collection_interval: float = 10.0):
        """Initialize HTTP Inspector Agent.

        Args:
            collection_interval: Seconds between collection cycles
        """
        device_id = socket.gethostname()

        # Create EventBus publisher
        publisher = EventBusPublisher(EVENTBUS_ADDRESS, CERT_DIR)

        # Create local queue
        Path(QUEUE_PATH).parent.mkdir(parents=True, exist_ok=True)
        queue_adapter = LocalQueueAdapter(
            queue_path=QUEUE_PATH,
            agent_name="http_inspector",
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,
            max_retries=10,
            signing_key_path="certs/agents/http_inspector.ed25519",
        )

        # Initialize base classes
        super().__init__(
            agent_name="http_inspector",
            device_id=device_id,
            collection_interval=collection_interval,
            eventbus_publisher=publisher,
            local_queue=queue_adapter,
        )

        # Platform-specific HTTP collector
        self.http_collector = get_http_collector()

        # Register all HTTP inspector probes
        self.register_probes(create_http_inspector_probes())

        logger.info("HTTPInspectorAgent initialized with %d probes", len(self._probes))

    def setup(self) -> bool:
        """Initialize agent resources.

        Verifies:
            - Certificates exist
            - HTTP collector works
            - Probes initialize successfully

        Returns:
            True if setup succeeded
        """
        try:
            import os

            # Verify certificates (warn but don't fail)
            required_certs = ["ca.crt", "agent.crt", "agent.key"]
            for cert in required_certs:
                cert_path = f"{CERT_DIR}/{cert}"
                if not os.path.exists(cert_path):
                    logger.warning(
                        "Certificate not found: %s (EventBus publishing will fail)",
                        cert_path,
                    )

            # Test HTTP collector
            try:
                test_txns = self.http_collector.collect()
                logger.info("HTTP collector test: %d transactions", len(test_txns))
            except Exception as e:
                logger.warning("HTTP collector test failed: %s", e)

            # Setup probes
            if not self.setup_probes(
                collector_shared_data_keys=["http_transactions"],
            ):
                logger.error("No probes initialized successfully")
                return False

            logger.info("HTTPInspectorAgent setup complete")
            return True

        except Exception as e:
            logger.error("Setup failed: %s", e)
            return False

    def collect_data(self) -> Sequence[Any]:
        """Collect HTTP transactions and run all probes.

        Returns:
            List of DeviceTelemetry protobuf messages
        """
        timestamp_ns = int(time.time() * 1e9)

        # Collect HTTP transactions
        http_transactions = self.http_collector.collect()
        logger.info("Collected %d HTTP transactions", len(http_transactions))

        # Create context with HTTP transactions
        context = self._create_probe_context()
        context.shared_data["http_transactions"] = http_transactions

        # Run all probes and collect events
        events: List[TelemetryEvent] = []
        for probe in self._probes:
            if not probe.enabled:
                continue

            try:
                probe_events = probe.scan(context)
                events.extend(probe_events)
                probe.last_scan = datetime.now(timezone.utc)
                probe.scan_count += 1
            except Exception as e:
                probe.error_count += 1
                probe.last_error = str(e)
                logger.error("Probe %s failed: %s", probe.name, e)

        logger.info(
            "Probes generated %d events from %d transactions",
            len(events),
            len(http_transactions),
        )

        # Build proto events
        proto_events = []

        # Always emit a collection summary metric (heartbeat)
        proto_events.append(
            telemetry_pb2.TelemetryEvent(
                event_id=f"http_collection_summary_{timestamp_ns}",
                event_type="METRIC",
                severity="INFO",
                event_timestamp_ns=timestamp_ns,
                source_component="http_inspector_collector",
                tags=["http_inspector", "metric"],
                metric_data=telemetry_pb2.MetricData(
                    metric_name="http_transactions_collected",
                    metric_type="GAUGE",
                    numeric_value=float(len(http_transactions)),
                    unit="transactions",
                ),
            )
        )

        # Probe event count metric
        if events:
            proto_events.append(
                telemetry_pb2.TelemetryEvent(
                    event_id=f"http_probe_events_{timestamp_ns}",
                    event_type="METRIC",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="http_inspector_agent",
                    tags=["http_inspector", "metric"],
                    metric_data=telemetry_pb2.MetricData(
                        metric_name="http_probe_events",
                        metric_type="GAUGE",
                        numeric_value=float(len(events)),
                        unit="events",
                    ),
                )
            )

        # Convert probe events to SecurityEvent-based telemetry
        severity_map = {
            "DEBUG": "DEBUG",
            "INFO": "INFO",
            "LOW": "LOW",
            "MEDIUM": "MEDIUM",
            "HIGH": "HIGH",
            "CRITICAL": "CRITICAL",
        }

        _severity_risk = {
            "DEBUG": 0.1,
            "INFO": 0.2,
            "LOW": 0.3,
            "MEDIUM": 0.5,
            "HIGH": 0.7,
            "CRITICAL": 0.9,
        }

        for event in events:
            base_risk = _severity_risk.get(event.severity.value, 0.5)
            risk_score = base_risk * event.confidence

            security_event = telemetry_pb2.SecurityEvent(
                event_category=event.event_type,
                event_action="HTTP_INSPECTION",
                risk_score=round(min(risk_score, 1.0), 3),
                analyst_notes=f"Probe: {event.probe_name}, "
                f"Severity: {event.severity.value}",
            )
            security_event.mitre_techniques.extend(event.mitre_techniques)

            if event.data.get("url"):
                security_event.target_resource = event.data["url"]

            tel_event = telemetry_pb2.TelemetryEvent(
                event_id=f"{event.event_type}_{timestamp_ns}",
                event_type="SECURITY",
                severity=severity_map.get(event.severity.value, "INFO"),
                event_timestamp_ns=timestamp_ns,
                source_component=event.probe_name or "http_inspector_agent",
                tags=["http_inspector", "threat"],
                security_event=security_event,
                confidence_score=event.confidence,
            )

            # Populate attributes map with evidence
            if event.data:
                for key, value in event.data.items():
                    if value is not None:
                        tel_event.attributes[key] = str(value)

            proto_events.append(tel_event)

        # Create DeviceTelemetry
        telemetry = telemetry_pb2.DeviceTelemetry(
            device_id=self.device_id,
            device_type="HOST",
            protocol="HTTP",
            events=proto_events,
            timestamp_ns=timestamp_ns,
            collection_agent="http_inspector",
            agent_version="2.0.0",
        )

        return [telemetry]

    def validate_event(self, event: Any) -> ValidationResult:
        """Validate telemetry before publishing.

        Args:
            event: DeviceTelemetry protobuf message

        Returns:
            ValidationResult
        """
        errors = []
        if not hasattr(event, "device_id") or not event.device_id:
            errors.append("Missing device_id")
        if not hasattr(event, "timestamp_ns") or event.timestamp_ns <= 0:
            errors.append("Missing or invalid timestamp_ns")
        if not event.events:
            errors.append("events list is empty")
        return ValidationResult(is_valid=len(errors) == 0, errors=errors)

    def shutdown(self) -> None:
        """Graceful shutdown."""
        logger.info("HTTPInspectorAgent shutting down...")

        # Close EventBus connection
        if self.eventbus_publisher:
            self.eventbus_publisher.close()

        logger.info("HTTPInspectorAgent shutdown complete")

    def get_health(self) -> Dict[str, Any]:
        """Get agent health status.

        Returns:
            Dict with health metrics
        """
        return {
            "agent_name": self.agent_name,
            "device_id": self.device_id,
            "is_running": self.is_running,
            "collection_count": self.collection_count,
            "error_count": self.error_count,
            "last_error": self.last_error,
            "probes": self.get_probe_health(),
            "circuit_breaker_state": self.circuit_breaker.state,
            "color": self.COLOR,
        }


# =============================================================================
# CLI Entry Point
# =============================================================================


def main():
    """Run HTTP Inspector Agent."""
    import argparse

    parser = argparse.ArgumentParser(description="AMOSKYS HTTP Inspector Agent")
    parser.add_argument(
        "--interval",
        type=float,
        default=10.0,
        help="Collection interval in seconds",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (overrides --debug)",
    )

    args = parser.parse_args()

    if args.log_level:
        logging.getLogger().setLevel(getattr(logging, args.log_level))
    elif args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info("=" * 70)
    logger.info("AMOSKYS HTTP Inspector Agent (Micro-Probe Architecture)")
    logger.info("=" * 70)

    agent = HTTPInspectorAgent(collection_interval=args.interval)

    try:
        agent.run_forever()
    except KeyboardInterrupt:
        logger.info("Received interrupt, shutting down...")
        agent.shutdown()


if __name__ == "__main__":
    main()
