#!/usr/bin/env python3
"""AMOSKYS AppLog Agent - Micro-Probe Architecture.

This is the application log monitoring agent using the "swarm of eyes" pattern.
8 micro-probes each watch one specific application log threat vector.

Probes:
    1. LogTamperingProbe - Log file tampering detection
    2. CredentialHarvestProbe - Leaked credentials in logs
    3. ErrorSpikeAnomalyProbe - Anomalous ERROR rate spikes
    4. WebShellAccessProbe - Web shell access patterns
    5. Suspicious4xx5xxProbe - HTTP 4xx/5xx scanning clusters
    6. LogInjectionProbe - CRLF injection and log poisoning
    7. PrivilegeEscalationLogProbe - sudo/su privilege changes
    8. ContainerBreakoutLogProbe - Container escape indicators

MITRE ATT&CK Coverage:
    - T1070.002: Indicator Removal: Clear Linux or Mac System Logs
    - T1552.001: Unsecured Credentials: Credentials In Files
    - T1499: Endpoint Denial of Service
    - T1505.003: Server Software Component: Web Shell
    - T1595: Active Scanning
    - T1562.006: Impair Defenses: Indicator Blocking
    - T1548.003: Abuse Elevation Control Mechanism: Sudo
    - T1611: Escape to Host

Usage:
    >>> agent = AppLogAgent()
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

import grpc

from amoskys.agents.common.base import HardenedAgentBase, ValidationResult
from amoskys.agents.common.probes import MicroProbeAgentMixin, TelemetryEvent
from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.agents.shared.applog.agent_types import LogEntry
from amoskys.agents.shared.applog.probes import create_applog_probes
from amoskys.config import get_config
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.proto import universal_telemetry_pb2_grpc as universal_pbrpc

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("AppLogAgent")

config = get_config()
EVENTBUS_ADDRESS = config.agent.bus_address
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = getattr(config.agent, "applog_queue_path", "data/queue/applog.db")


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
# Platform-Specific Log Collectors
# =============================================================================


class LogCollector:
    """Base class for platform-specific log collection."""

    def collect(self) -> List[LogEntry]:
        """Collect log entries from system.

        Returns:
            List of LogEntry objects
        """
        raise NotImplementedError


class MacOSLogCollector(LogCollector):
    """Collects log entries on macOS via system.log and unified logging."""

    # Regex for macOS system.log format:
    # "Mon DD HH:MM:SS hostname process[pid]: message"
    _SYSLOG_RE = re.compile(
        r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(\S+)\s+"
        r"(\S+?)(?:\[(\d+)\])?\s*:\s+"
        r"(.+)$"
    )

    # Map keywords to log levels
    _LEVEL_KEYWORDS = {
        "error": "ERROR",
        "fail": "ERROR",
        "crit": "ERROR",
        "warn": "WARNING",
        "debug": "DEBUG",
    }

    def __init__(self):
        self.system_log_path = "/var/log/system.log"
        self._last_position: Dict[str, int] = {}

    def collect(self) -> List[LogEntry]:
        """Collect log entries from macOS system."""
        entries = []

        # Method 1: Parse /var/log/system.log
        entries.extend(self._collect_system_log())

        # Method 2: Use unified logging (log show)
        entries.extend(self._collect_unified_log())

        return entries

    def _collect_system_log(self) -> List[LogEntry]:
        """Parse /var/log/system.log for new entries."""
        entries = []
        log_path = self.system_log_path

        try:
            if not Path(log_path).exists():
                return entries

            current_size = Path(log_path).stat().st_size
            last_pos = self._last_position.get(log_path, 0)

            # Detect truncation (file got smaller)
            if current_size < last_pos:
                last_pos = 0

            # Only read new data
            if current_size <= last_pos:
                return entries

            with open(log_path, "r", errors="replace") as f:
                f.seek(last_pos)
                line_number = 0
                for line in f:
                    line_number += 1
                    line = line.rstrip("\n")
                    if not line:
                        continue

                    entry = self._parse_syslog_line(line, log_path, line_number)
                    if entry:
                        entries.append(entry)

                self._last_position[log_path] = f.tell()

        except PermissionError:
            logger.debug("Permission denied reading %s", log_path)
        except Exception as e:
            logger.error("Failed to read %s: %s", log_path, e)

        return entries

    def _parse_syslog_line(
        self, line: str, file_path: str, line_number: int
    ) -> Optional[LogEntry]:
        """Parse a syslog-format line into a LogEntry."""
        match = self._SYSLOG_RE.match(line)
        if not match:
            return None

        timestamp_str, _hostname, process_name, pid_str, message = match.groups()

        # Parse timestamp (add current year since syslog doesn't include it)
        try:
            now = datetime.now(timezone.utc)
            ts = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
            ts = ts.replace(year=now.year, tzinfo=timezone.utc)
        except ValueError:
            ts = datetime.now(timezone.utc)

        # Determine log level from message content
        level = "INFO"
        msg_lower = message.lower()
        for keyword, lvl in self._LEVEL_KEYWORDS.items():
            if keyword in msg_lower:
                level = lvl
                break

        return LogEntry(
            timestamp=ts,
            source="syslog",
            level=level,
            message=message,
            file_path=file_path,
            line_number=line_number,
            process_name=process_name,
            pid=int(pid_str) if pid_str else None,
        )

    def _collect_unified_log(self) -> List[LogEntry]:
        """Collect entries from macOS unified logging system."""
        entries = []

        try:
            cmd = [
                "log",
                "show",
                "--predicate",
                "eventType == logEvent",
                "--last",
                "1m",
                "--style",
                "json",
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

            if result.returncode == 0 and result.stdout:
                try:
                    logs = json.loads(result.stdout)
                    for log_entry in logs:
                        entry = self._parse_unified_entry(log_entry)
                        if entry:
                            entries.append(entry)
                except json.JSONDecodeError:
                    logger.debug("Failed to parse unified log output as JSON")

        except subprocess.TimeoutExpired:
            logger.warning("Unified log collection timed out")
        except FileNotFoundError:
            logger.warning("'log' command not found — unified log collection disabled")
        except Exception as e:
            logger.error("Failed to collect unified logs: %s", e)

        return entries

    def _parse_unified_entry(self, entry: Dict) -> Optional[LogEntry]:
        """Parse a unified log JSON entry into LogEntry."""
        try:
            message = entry.get("eventMessage", "")
            if not message:
                return None

            timestamp_str = entry.get("timestamp", "")
            timestamp = datetime.now(timezone.utc)
            if timestamp_str:
                try:
                    timestamp = datetime.fromisoformat(
                        timestamp_str.replace("Z", "+00:00")
                    )
                except ValueError:
                    pass

            process = entry.get("processImagePath", "")
            process_name = Path(process).name if process else None
            pid = entry.get("processID")

            # Map unified log level
            log_type = entry.get("messageType", "Default")
            level_map = {
                "Error": "ERROR",
                "Fault": "ERROR",
                "Warning": "WARNING",
                "Debug": "DEBUG",
                "Info": "INFO",
                "Default": "INFO",
            }
            level = level_map.get(log_type, "INFO")

            return LogEntry(
                timestamp=timestamp,
                source="unified_log",
                level=level,
                message=message,
                file_path="unified_log",
                process_name=process_name,
                pid=pid,
            )

        except Exception as e:
            logger.debug("Failed to parse unified log entry: %s", e)
            return None


class LinuxLogCollector(LogCollector):
    """Collects log entries on Linux from syslog, auth.log, and web server logs."""

    # Log files to monitor
    LOG_SOURCES = {
        "/var/log/syslog": "syslog",
        "/var/log/auth.log": "auth",
        "/var/log/messages": "syslog",
        "/var/log/nginx/access.log": "nginx",
        "/var/log/nginx/error.log": "nginx",
        "/var/log/apache2/access.log": "apache",
        "/var/log/apache2/error.log": "apache",
        "/var/log/httpd/access_log": "apache",
        "/var/log/httpd/error_log": "apache",
    }

    # Syslog line pattern: "Mon DD HH:MM:SS hostname process[pid]: message"
    _SYSLOG_RE = re.compile(
        r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(\S+)\s+"
        r"(\S+?)(?:\[(\d+)\])?\s*:\s+"
        r"(.+)$"
    )

    # Nginx/Apache combined log format:
    # $remote_ip - - [$time] "$method $path $proto" $status $bytes "$referer" "$ua"
    _COMBINED_LOG_RE = re.compile(
        r"^(\S+)\s+\S+\s+\S+\s+"
        r"\[([^\]]+)\]\s+"
        r'"(\S+)\s+(\S+)\s+\S+"\s+'
        r"(\d{3})\s+\d+\s+"
        r'"[^"]*"\s+'
        r'"([^"]*)"'
    )

    # Map keywords to log levels
    _LEVEL_KEYWORDS = {
        "error": "ERROR",
        "fail": "ERROR",
        "crit": "ERROR",
        "warn": "WARNING",
        "debug": "DEBUG",
    }

    def __init__(self):
        self._last_position: Dict[str, int] = {}

    def collect(self) -> List[LogEntry]:
        """Collect log entries from Linux log files."""
        entries = []

        for log_path, source in self.LOG_SOURCES.items():
            if not Path(log_path).exists():
                continue

            try:
                new_entries = self._read_log_file(log_path, source)
                entries.extend(new_entries)
            except PermissionError:
                logger.debug("Permission denied reading %s", log_path)
            except Exception as e:
                logger.error("Failed to read %s: %s", log_path, e)

        return entries

    def _read_log_file(self, log_path: str, source: str) -> List[LogEntry]:
        """Read new entries from a log file."""
        entries = []

        try:
            current_size = Path(log_path).stat().st_size
            last_pos = self._last_position.get(log_path, 0)

            # Detect truncation / rotation
            if current_size < last_pos:
                last_pos = 0

            if current_size <= last_pos:
                return entries

            with open(log_path, "r", errors="replace") as f:
                f.seek(last_pos)
                line_number = 0
                for line in f:
                    line_number += 1
                    line = line.rstrip("\n")
                    if not line:
                        continue

                    if source in ("nginx", "apache"):
                        entry = self._parse_combined_log(
                            line, log_path, source, line_number
                        )
                    else:
                        entry = self._parse_syslog_line(
                            line, log_path, source, line_number
                        )

                    if entry:
                        entries.append(entry)

                self._last_position[log_path] = f.tell()

        except Exception as e:
            logger.error("Error reading %s: %s", log_path, e)

        return entries

    def _parse_syslog_line(
        self, line: str, file_path: str, source: str, line_number: int
    ) -> Optional[LogEntry]:
        """Parse a syslog-format line."""
        match = self._SYSLOG_RE.match(line)
        if not match:
            # Return as raw entry if it doesn't match syslog format
            return LogEntry(
                timestamp=datetime.now(timezone.utc),
                source=source,
                level="INFO",
                message=line,
                file_path=file_path,
                line_number=line_number,
            )

        timestamp_str, _hostname, process_name, pid_str, message = match.groups()

        try:
            now = datetime.now(timezone.utc)
            ts = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
            ts = ts.replace(year=now.year, tzinfo=timezone.utc)
        except ValueError:
            ts = datetime.now(timezone.utc)

        # Determine log level
        level = "INFO"
        msg_lower = message.lower()
        for keyword, lvl in self._LEVEL_KEYWORDS.items():
            if keyword in msg_lower:
                level = lvl
                break

        return LogEntry(
            timestamp=ts,
            source=source,
            level=level,
            message=message,
            file_path=file_path,
            line_number=line_number,
            process_name=process_name,
            pid=int(pid_str) if pid_str else None,
        )

    def _parse_combined_log(
        self, line: str, file_path: str, source: str, line_number: int
    ) -> Optional[LogEntry]:
        """Parse nginx/apache combined log format line."""
        match = self._COMBINED_LOG_RE.match(line)
        if not match:
            # Error log format - treat as syslog-style
            return LogEntry(
                timestamp=datetime.now(timezone.utc),
                source=source,
                level="ERROR",
                message=line,
                file_path=file_path,
                line_number=line_number,
            )

        remote_ip, time_str, method, path, status_str, user_agent = match.groups()

        # Parse timestamp: "10/Oct/2023:13:55:36 +0000"
        try:
            ts = datetime.strptime(time_str, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            ts = datetime.now(timezone.utc)

        status = int(status_str)

        # Determine log level from status
        if status >= 500:
            level = "ERROR"
        elif status >= 400:
            level = "WARNING"
        else:
            level = "INFO"

        return LogEntry(
            timestamp=ts,
            source=source,
            level=level,
            message=line,
            file_path=file_path,
            line_number=line_number,
            remote_ip=remote_ip,
            http_method=method,
            http_path=path,
            http_status=status,
            user_agent=user_agent,
        )


def get_log_collector() -> LogCollector:
    """Get platform-appropriate log collector."""
    system = platform.system()
    if system == "Darwin":
        return MacOSLogCollector()
    elif system == "Linux":
        return LinuxLogCollector()
    else:
        logger.warning("Unsupported platform: %s", system)
        return MacOSLogCollector()  # Default


# =============================================================================
# AppLog Agent
# =============================================================================


class AppLogAgent(MicroProbeAgentMixin, HardenedAgentBase):
    """AppLog Agent with micro-probe architecture.

    This agent hosts 8 micro-probes that each monitor a specific
    application log threat vector. The agent handles:
        - Log entry collection (platform-specific)
        - Probe lifecycle management
        - Event aggregation and publishing
        - Circuit breaker and retry logic
        - Offline queue management

    Probes are responsible only for detection - no networking or state
    management.
    """

    def __init__(self, collection_interval: float = 15.0):
        """Initialize AppLog Agent.

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
            agent_name="applog",
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,
            max_retries=10,
            signing_key_path="certs/agents/applog.ed25519",
        )

        # Initialize base classes
        super().__init__(
            agent_name="applog",
            device_id=device_id,
            collection_interval=collection_interval,
            eventbus_publisher=publisher,
            local_queue=queue_adapter,
        )

        # Platform-specific log collector
        self.log_collector = get_log_collector()

        # Register all AppLog probes
        self.register_probes(create_applog_probes())

        logger.info("AppLogAgent initialized with %d probes", len(self._probes))

    def setup(self) -> bool:
        """Initialize agent resources.

        Verifies:
            - Certificates exist
            - Log collector works
            - Probes initialize successfully

        Returns:
            True if setup succeeded
        """
        try:
            import os

            # Verify certificates (warn but don't fail -- dev mode may lack certs)
            required_certs = ["ca.crt", "agent.crt", "agent.key"]
            for cert in required_certs:
                cert_path = f"{CERT_DIR}/{cert}"
                if not os.path.exists(cert_path):
                    logger.warning(
                        "Certificate not found: %s (EventBus publishing will fail)",
                        cert_path,
                    )

            # Test log collector
            try:
                test_entries = self.log_collector.collect()
                logger.info("Log collector test: %d entries", len(test_entries))
            except Exception as e:
                logger.warning("Log collector test failed: %s", e)
                # Continue anyway - collector may work later

            # Setup probes
            if not self.setup_probes(collector_shared_data_keys=["log_entries"]):
                logger.error("No probes initialized successfully")
                return False

            logger.info("AppLogAgent setup complete")
            return True

        except Exception as e:
            logger.error("Setup failed: %s", e)
            return False

    def collect_data(self) -> Sequence[Any]:
        """Collect log entries and run all probes.

        Returns:
            List of DeviceTelemetry protobuf messages
        """
        timestamp_ns = int(time.time() * 1e9)

        # Collect log entries
        log_entries = self.log_collector.collect()
        logger.info("Collected %d log entries", len(log_entries))

        # Create context with log entries
        context = self._create_probe_context()
        context.shared_data["log_entries"] = log_entries

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
            "Probes generated %d events from %d log entries",
            len(events),
            len(log_entries),
        )

        # Build proto events
        proto_events = []

        # Always emit a collection summary metric (heartbeat)
        proto_events.append(
            telemetry_pb2.TelemetryEvent(
                event_id=f"applog_collection_summary_{timestamp_ns}",
                event_type="METRIC",
                severity="INFO",
                event_timestamp_ns=timestamp_ns,
                source_component="applog_collector",
                tags=["applog", "metric"],
                metric_data=telemetry_pb2.MetricData(
                    metric_name="applog_entries_collected",
                    metric_type="GAUGE",
                    numeric_value=float(len(log_entries)),
                    unit="entries",
                ),
            )
        )

        # Probe event count metric
        if events:
            proto_events.append(
                telemetry_pb2.TelemetryEvent(
                    event_id=f"applog_probe_events_{timestamp_ns}",
                    event_type="METRIC",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="applog_agent",
                    tags=["applog", "metric"],
                    metric_data=telemetry_pb2.MetricData(
                        metric_name="applog_probe_events",
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

        for event in events:
            # Build SecurityEvent sub-message
            security_event = telemetry_pb2.SecurityEvent(
                event_category=event.event_type,
                risk_score=0.8 if event.severity.value in ("HIGH", "CRITICAL") else 0.4,
                analyst_notes=f"Probe: {event.probe_name}, "
                f"Severity: {event.severity.value}",
            )
            security_event.mitre_techniques.extend(event.mitre_techniques)

            tel_event = telemetry_pb2.TelemetryEvent(
                event_id=f"{event.event_type}_{timestamp_ns}",
                event_type="SECURITY",
                severity=severity_map.get(event.severity.value, "INFO"),
                event_timestamp_ns=timestamp_ns,
                source_component=event.probe_name or "applog_agent",
                tags=["applog", "threat"],
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
            protocol="APPLOG",
            events=proto_events,
            timestamp_ns=timestamp_ns,
            collection_agent="applog",
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
        logger.info("AppLogAgent shutting down...")

        # Close EventBus connection
        if self.eventbus_publisher:
            self.eventbus_publisher.close()

        logger.info("AppLogAgent shutdown complete")

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
        }


# =============================================================================
# CLI Entry Point
# =============================================================================


def main():
    """Run AppLog Agent."""
    import argparse

    parser = argparse.ArgumentParser(description="AMOSKYS AppLog Agent")
    parser.add_argument(
        "--interval",
        type=float,
        default=15.0,
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
    logger.info("AMOSKYS AppLog Agent (Micro-Probe Architecture)")
    logger.info("=" * 70)

    agent = AppLogAgent(collection_interval=args.interval)

    try:
        agent.run_forever()
    except KeyboardInterrupt:
        logger.info("Received interrupt, shutting down...")
        agent.shutdown()


if __name__ == "__main__":
    main()
