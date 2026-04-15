"""macOS HTTP Inspector Observatory Agent — HTTP threat detection via log analysis.

Monitors web server access logs (Apache/Nginx) and Unified Logging
(URLSession/NSURLConnection) for:
    - XSS injection attempts (script tags, event handlers)
    - SSRF patterns (internal IPs in URL parameters)
    - Path traversal attacks (directory escape sequences)
    - API abuse (rate limiting violations)
    - WebShell uploads (POST + shell file extensions)
    - C2 HTTP beaconing (periodic requests with encoded payloads)
    - Data exfiltration via large POST bodies
    - Cookie theft / session hijacking patterns

Data flow:
    MacOSHTTPInspectorCollector.collect() → shared_data
    → 8 probes scan(context) → TelemetryEvent[]
    → _events_to_telemetry() → DeviceTelemetry
    → LocalQueueAdapter → EventBus
"""

from __future__ import annotations

import logging
import platform
import socket
import time
from pathlib import Path
from typing import Any, Dict, List, Sequence

from amoskys.agents.common.base import HardenedAgentBase, ValidationResult
from amoskys.agents.common.probes import MicroProbeAgentMixin, Severity, TelemetryEvent
from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.agents.os.macos.http_inspector.collector import MacOSHTTPInspectorCollector
from amoskys.agents.os.macos.http_inspector.probes import create_http_inspector_probes

# Merged: network_sentinel probes run inside http_inspector (same HTTP data source)
try:
    from amoskys.agents.os.macos.network_sentinel.probes import (
        create_network_sentinel_probes,
    )

    _HAS_SENTINEL = True
except ImportError:
    _HAS_SENTINEL = False
from amoskys.config import get_config

logger = logging.getLogger(__name__)
config = get_config()
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = "data/queue/macos_http_inspector.db"


class MacOSHTTPInspectorAgent(MicroProbeAgentMixin, HardenedAgentBase):
    """macOS HTTP Inspector Observatory — 8 probes, 8 MITRE techniques.

    Probes:
        macos_http_xss              — T1059.007 XSS detection
        macos_http_ssrf             — T1090     SSRF detection
        macos_http_path_traversal   — T1083     Path traversal
        macos_http_api_abuse        — T1106     API abuse
        macos_http_webshell_upload  — T1505.003 WebShell upload
        macos_http_c2_beacon        — T1071.001 C2 web channel
        macos_http_data_exfil       — T1048     Data exfiltration
        macos_http_cookie_theft     — T1539     Cookie theft
    """

    MANDATE_DATA_FIELDS = ("remote_ip", "remote_port", "local_port", "protocol", "pid", "process_name")

    def __init__(self, collection_interval: float = 30.0) -> None:
        device_id = socket.gethostname()

        Path(QUEUE_PATH).parent.mkdir(parents=True, exist_ok=True)
        queue_adapter = LocalQueueAdapter(
            queue_path=QUEUE_PATH,
            agent_name="macos_http_inspector",
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,
            max_retries=10,
            signing_key_path=f"{CERT_DIR}/agent.ed25519",
        )

        super().__init__(
            agent_name="macos_http_inspector",
            device_id=device_id,
            collection_interval=collection_interval,
            queue_adapter=queue_adapter,
        )

        self.collector = MacOSHTTPInspectorCollector(device_id=device_id)

        # Core HTTP inspector probes (8)
        all_probes = create_http_inspector_probes()
        # Merged network_sentinel probes (+10) — same HTTP data source
        if _HAS_SENTINEL:
            all_probes.extend(create_network_sentinel_probes())
            logger.info("HTTP inspector agent: merged %d network_sentinel probes", 10)

        self.register_probes(all_probes)

        logger.info(
            "MacOSHTTPInspectorAgent initialized: %d probes, device=%s",
            len(self._probes),
            device_id,
        )

    def setup(self) -> bool:
        """Verify macOS platform and HTTP data sources."""
        if platform.system() != "Darwin":
            logger.error("MacOSHTTPInspectorAgent requires macOS (Darwin)")
            return False

        # Verify Apache log access
        try:
            with open("/var/log/apache2/access_log"):
                logger.info("Apache access log OK: readable")
        except FileNotFoundError:
            logger.info("Apache access log not found (Apache not installed)")
        except PermissionError:
            logger.warning("Apache access log: permission denied")
        except Exception as e:
            logger.warning("Apache access log check failed: %s", e)

        # Verify Nginx log access
        try:
            with open("/var/log/nginx/access.log"):
                logger.info("Nginx access log OK: readable")
        except FileNotFoundError:
            logger.info("Nginx access log not found (Nginx not installed)")
        except PermissionError:
            logger.warning("Nginx access log: permission denied")
        except Exception as e:
            logger.warning("Nginx access log check failed: %s", e)

        # Verify Unified Logging access
        try:
            import subprocess

            result = subprocess.run(
                [
                    "log",
                    "show",
                    "--predicate",
                    'process == "nsurlsessiond"',
                    "--last",
                    "1s",
                    "--style",
                    "compact",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                logger.info("Unified Logging OK: URLSession accessible")
            else:
                logger.warning(
                    "Unified Logging degraded: returncode=%d", result.returncode
                )
        except Exception as e:
            logger.warning("Unified Logging check failed: %s", e)

        if not self.setup_probes(
            collector_shared_data_keys=[
                "http_requests",
                "request_count",
                "unique_clients",
                "error_count",
                "collection_time_ms",
            ]
        ):
            logger.error("No probes initialized")
            return False

        logger.info("MacOSHTTPInspectorAgent setup complete — 8 probes active")
        return True

    def collect_data(self) -> Sequence[Any]:
        """Run HTTP collector + probes, emit raw observations + detections."""
        snapshot = self.collector.collect()

        # Build OBSERVATION events for ALL HTTP requests (raw observability)
        obs_events = self._make_observation_events(
            snapshot.get("http_requests", []),
            domain="http",
            field_mapper=self._http_to_obs,
        )

        # Convert HTTPRequest → HTTPTransaction for merged network_sentinel probes
        if _HAS_SENTINEL:
            from datetime import datetime, timezone
            from amoskys.agents.os.macos.http_inspector.agent_types import HTTPTransaction

            transactions = []
            for req in snapshot.get("http_requests", []):
                transactions.append(
                    HTTPTransaction(
                        timestamp=datetime.fromtimestamp(req.timestamp, tz=timezone.utc),
                        method=req.method if hasattr(req, "method") else "GET",
                        url=req.path,
                        host="",
                        path=req.path,
                        query_params={},
                        request_headers={},
                        request_body=None,
                        response_status=req.status_code,
                        content_type="",
                        src_ip=req.client_ip,
                        dst_ip="",
                        bytes_sent=req.body_size,
                        bytes_received=0,
                        process_name=getattr(req, "process_name", None),
                    )
                )
            snapshot["http_transactions"] = transactions

        # Run all probes (http_inspector + network_sentinel)
        context = self._create_probe_context()
        context.shared_data = snapshot
        probe_events = self.run_probes(context)

        all_events = obs_events + probe_events
        all_events.append(
            TelemetryEvent(
                event_type="collection_metadata",
                severity=Severity.DEBUG,
                probe_name="macos_http_inspector_collector",
                data={
                    "request_count": snapshot["request_count"],
                    "unique_clients": snapshot["unique_clients"],
                    "error_count": snapshot["error_count"],
                    "collection_time_ms": snapshot["collection_time_ms"],
                    "observation_events": len(obs_events),
                    "probe_events": len(probe_events),
                },
            )
        )

        logger.info(
            "HTTP collected in %.1fms: %d requests, %d unique clients, "
            "%d errors, %d observations, %d probe events",
            snapshot["collection_time_ms"],
            snapshot["request_count"],
            snapshot["unique_clients"],
            snapshot["error_count"],
            len(obs_events),
            len(probe_events),
        )

        if all_events:
            return [self._events_to_telemetry(all_events)]
        return []

    @staticmethod
    def _http_to_obs(req) -> Dict[str, Any]:
        """Map an HTTPRequest to observation data dict."""
        return {
            "timestamp": str(req.timestamp),
            "method": req.method,
            "path": req.path,
            "status_code": str(req.status_code),
            "client_ip": req.client_ip,
            "user_agent": req.user_agent,
            "body_size": str(req.body_size),
            "response_time_ms": str(req.response_time_ms),
            "protocol": req.protocol,
            "server_type": req.server_type,
        }

    def _events_to_telemetry(self, events: List[TelemetryEvent]) -> Any:
        """Convert TelemetryEvents to protobuf DeviceTelemetry."""
        from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2

        timestamp_ns = int(time.time() * 1e9)
        proto_events = []

        for idx, event in enumerate(events):
            if event.event_type == "collection_metadata":
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"macos_http_inspector_meta_{timestamp_ns}",
                    event_type="METRIC",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="macos_http_inspector_collector",
                    metric_data=telemetry_pb2.MetricData(
                        metric_name="http_inspector_collection",
                        metric_type="GAUGE",
                        numeric_value=float(event.data.get("request_count", 0)),
                        unit="requests",
                    ),
                )
            elif event.event_type.startswith("obs_"):
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"macos_http_inspector_obs_{idx}_{timestamp_ns}",
                    event_type="OBSERVATION",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="http_collector",
                    confidence_score=0.0,
                )
                for k, v in event.data.items():
                    proto_event.attributes[k] = str(v)
            else:
                security_event = telemetry_pb2.SecurityEvent(
                    event_category=event.event_type,
                    risk_score=event.confidence,
                    analyst_notes=str(event.data),
                )
                if event.mitre_techniques:
                    security_event.mitre_techniques.extend(event.mitre_techniques)

                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"{event.probe_name}_{event.event_type}_{timestamp_ns}",
                    event_type="SECURITY",
                    severity=event.severity.value,
                    event_timestamp_ns=timestamp_ns,
                    source_component=event.probe_name,
                    security_event=security_event,
                    confidence_score=event.confidence,
                    tags=event.tags,
                )
                for k, v in event.data.items():
                    proto_event.attributes[k] = str(v)

            proto_events.append(proto_event)

        return telemetry_pb2.DeviceTelemetry(
            device_id=self.device_id,
            device_type="HOST",
            protocol="MACOS_HTTP_INSPECTOR",
            events=proto_events,
            timestamp_ns=timestamp_ns,
            collection_agent="macos_http_inspector",
            agent_version="2.0.0",
        )

    def validate_event(self, event: Any) -> ValidationResult:
        """Validate DeviceTelemetry before publishing."""
        errors = []
        if not hasattr(event, "device_id") or not event.device_id:
            errors.append("Missing device_id")
        if not hasattr(event, "timestamp_ns") or event.timestamp_ns == 0:
            errors.append("Missing timestamp_ns")
        return ValidationResult(is_valid=len(errors) == 0, errors=errors)

    def shutdown(self) -> None:
        """Graceful shutdown."""
        logger.info("MacOSHTTPInspectorAgent shutting down")
