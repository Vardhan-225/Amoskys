#!/usr/bin/env python3
"""AMOSKYS AuthGuard Agent v2 - Micro-Probe Architecture.

This is the modernized authentication monitoring agent using the "swarm of eyes"
pattern. 8 micro-probes each watch one specific auth/privilege threat vector.

Probes:
    1. SSHBruteForceProbe - Multiple failures from single IP/user
    2. SSHPasswordSprayProbe - Low-and-slow across many users
    3. SSHGeoImpossibleTravelProbe - Geographic impossibility
    4. SudoElevationProbe - Privilege escalation patterns
    5. SudoSuspiciousCommandProbe - Dangerous sudo commands
    6. OffHoursLoginProbe - Access outside business hours
    7. MFABypassOrAnomalyProbe - MFA fatigue/bypass attempts
    8. AccountLockoutStormProbe - Mass lockout attacks

MITRE ATT&CK Coverage:
    - T1110: Brute Force
    - T1110.003: Password Spraying
    - T1078: Valid Accounts
    - T1548: Abuse Elevation Control Mechanism
    - T1059: Command and Scripting Interpreter
    - T1621: Multi-Factor Authentication Request Generation

Usage:
    >>> agent = AuthGuardAgentV2()
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

from amoskys.agents.auth.probes import AuthEvent, create_auth_probes
from amoskys.agents.common.base import HardenedAgentBase, ValidationResult
from amoskys.agents.common.probes import MicroProbeAgentMixin, TelemetryEvent
from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.config import get_config
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.proto import universal_telemetry_pb2_grpc as universal_pbrpc

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("AuthGuardAgentV2")

config = get_config()
EVENTBUS_ADDRESS = config.agent.bus_address
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = getattr(config.agent, "auth_queue_path", "data/queue/auth_agent_v2.db")

# Tunables
AUTH_WINDOW_SECONDS = 900  # 15 minutes


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

        for device_telemetry in events:
            timestamp_ns = int(time.time() * 1e9)
            idempotency_key = f"{device_telemetry.device_id}_{timestamp_ns}"
            envelope = telemetry_pb2.UniversalEnvelope(
                version="v1",
                ts_ns=timestamp_ns,
                idempotency_key=idempotency_key,
                device_telemetry=device_telemetry,
                signing_algorithm="Ed25519",
                priority="NORMAL",
                requires_acknowledgment=True,
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
# Platform-Specific Auth Log Collectors
# =============================================================================


class AuthLogCollector:
    """Base class for platform-specific auth log collection."""

    def collect(self) -> List[AuthEvent]:
        """Collect auth events from system.

        Returns:
            List of AuthEvent objects
        """
        raise NotImplementedError


class LinuxAuthLogCollector(AuthLogCollector):
    """Collects authentication events on Linux from /var/log/auth.log."""

    def __init__(self):
        self.log_path = "/var/log/auth.log"
        self.last_position = 0

    def collect(self) -> List[AuthEvent]:
        """Collect auth events from Linux auth.log."""
        events = []

        try:
            if not Path(self.log_path).exists():
                logger.debug(f"Auth log not found: {self.log_path}")
                return events

            with open(self.log_path, "r") as f:
                # Seek to last position
                f.seek(self.last_position)
                new_lines = f.readlines()
                self.last_position = f.tell()

                # Parse each line
                for line in new_lines:
                    event = self._parse_log_line(line)
                    if event:
                        events.append(event)

        except Exception as e:
            logger.error(f"Failed to collect auth logs: {e}")

        return events

    def _parse_log_line(self, line: str) -> Optional[AuthEvent]:
        """Parse a single auth.log line into AuthEvent."""
        try:
            # SSH login attempts
            # Example: "Jan  5 10:15:23 hostname sshd[1234]: Failed password for user from 1.2.3.4 port 22 ssh2"
            ssh_fail = re.search(
                r"sshd\[\d+\]: Failed password for (\S+) from ([\d.]+)",
                line,
            )
            if ssh_fail:
                username = ssh_fail.group(1)
                source_ip = ssh_fail.group(2)
                return AuthEvent(
                    timestamp_ns=int(time.time() * 1e9),  # Approximate
                    event_type="SSH_LOGIN",
                    status="FAILURE",
                    username=username,
                    source_ip=source_ip,
                    reason="invalid password",
                )

            # SSH successful login
            ssh_success = re.search(
                r"sshd\[\d+\]: Accepted password for (\S+) from ([\d.]+)",
                line,
            )
            if ssh_success:
                username = ssh_success.group(1)
                source_ip = ssh_success.group(2)
                return AuthEvent(
                    timestamp_ns=int(time.time() * 1e9),
                    event_type="SSH_LOGIN",
                    status="SUCCESS",
                    username=username,
                    source_ip=source_ip,
                )

            # Sudo execution
            # Example: "Jan  5 10:15:23 hostname sudo: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/bash"
            sudo_exec = re.search(
                r"sudo:\s+(\S+)\s+:.*COMMAND=(.+)$",
                line,
            )
            if sudo_exec:
                username = sudo_exec.group(1)
                command = sudo_exec.group(2).strip()
                return AuthEvent(
                    timestamp_ns=int(time.time() * 1e9),
                    event_type="SUDO_EXEC",
                    status="SUCCESS",
                    username=username,
                    command=command,
                )

            # Account locked
            account_locked = re.search(
                r"Account (\S+) locked",
                line,
            )
            if account_locked:
                username = account_locked.group(1)
                return AuthEvent(
                    timestamp_ns=int(time.time() * 1e9),
                    event_type="ACCOUNT_LOCKED",
                    status="FAILURE",
                    username=username,
                )

        except Exception as e:
            logger.debug(f"Failed to parse auth log line: {e}")

        return None


class MacOSAuthLogCollector(AuthLogCollector):
    """Collects authentication events on macOS via unified log."""

    def __init__(self):
        self.last_timestamp: Optional[datetime] = None

    def collect(self) -> List[AuthEvent]:
        """Collect auth events from macOS unified logging."""
        events = []

        try:
            # Query sshd and sudo logs
            cmd = [
                "log",
                "show",
                "--predicate",
                '(process == "sshd" OR process == "sudo") AND (eventMessage CONTAINS "password" OR eventMessage CONTAINS "COMMAND")',
                "--last",
                "1m",
                "--style",
                "json",
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode == 0 and result.stdout:
                try:
                    logs = json.loads(result.stdout)
                    for entry in logs:
                        event = self._parse_log_entry(entry)
                        if event:
                            events.append(event)
                except json.JSONDecodeError:
                    logger.debug("Failed to parse log output as JSON")

        except subprocess.TimeoutExpired:
            logger.warning("Auth log collection timed out")
        except Exception as e:
            logger.error(f"Failed to collect auth logs: {e}")

        return events

    def _parse_log_entry(self, entry: Dict) -> Optional[AuthEvent]:
        """Parse a log entry into AuthEvent."""
        try:
            message = entry.get("eventMessage", "")
            timestamp_str = entry.get("timestamp", "")
            process = entry.get("process", "")

            # Parse timestamp
            timestamp = datetime.now(timezone.utc)
            if timestamp_str:
                try:
                    timestamp = datetime.fromisoformat(
                        timestamp_str.replace("Z", "+00:00")
                    )
                except ValueError:
                    pass

            timestamp_ns = int(timestamp.timestamp() * 1e9)

            # SSH events
            if process == "sshd":
                if "Failed password" in message:
                    # Extract username and IP
                    match = re.search(r"for (\S+) from ([\d.]+)", message)
                    if match:
                        return AuthEvent(
                            timestamp_ns=timestamp_ns,
                            event_type="SSH_LOGIN",
                            status="FAILURE",
                            username=match.group(1),
                            source_ip=match.group(2),
                        )
                elif "Accepted password" in message:
                    match = re.search(r"for (\S+) from ([\d.]+)", message)
                    if match:
                        return AuthEvent(
                            timestamp_ns=timestamp_ns,
                            event_type="SSH_LOGIN",
                            status="SUCCESS",
                            username=match.group(1),
                            source_ip=match.group(2),
                        )

            # Sudo events
            if process == "sudo" and "COMMAND=" in message:
                match = re.search(r"(\S+)\s+:.*COMMAND=(.+)", message)
                if match:
                    return AuthEvent(
                        timestamp_ns=timestamp_ns,
                        event_type="SUDO_EXEC",
                        status="SUCCESS",
                        username=match.group(1),
                        command=match.group(2),
                    )

        except Exception as e:
            logger.debug(f"Failed to parse log entry: {e}")

        return None


def get_auth_collector() -> AuthLogCollector:
    """Get platform-appropriate auth log collector."""
    system = platform.system()
    if system == "Linux":
        return LinuxAuthLogCollector()
    elif system == "Darwin":
        return MacOSAuthLogCollector()
    else:
        logger.warning(f"Unsupported platform: {system}")
        return LinuxAuthLogCollector()  # Default


# =============================================================================
# AuthGuard Agent V2
# =============================================================================


class AuthGuardAgentV2(MicroProbeAgentMixin, HardenedAgentBase):
    """Authentication security agent with micro-probe architecture.

    This agent hosts 8 micro-probes that each monitor a specific auth/privilege
    threat vector. The agent handles:
        - Auth log collection (platform-specific)
        - Probe lifecycle management
        - Event aggregation and publishing
        - Circuit breaker and retry logic
        - Offline queue management

    Probes are responsible only for detection - no networking or state
    management.
    """

    def __init__(self, collection_interval: float = 30.0):
        """Initialize AuthGuard Agent v2.

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
            agent_name="auth_guard_agent_v2",
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,
            max_retries=10,
        )

        # Initialize base classes
        super().__init__(
            agent_name="auth_guard_agent_v2",
            device_id=device_id,
            collection_interval=collection_interval,
            eventbus_publisher=publisher,
            local_queue=queue_adapter,
        )

        # Platform-specific auth log collector
        self.auth_collector = get_auth_collector()

        # Register all auth probes
        self.register_probes(create_auth_probes())

        logger.info(f"AuthGuardAgentV2 initialized with {len(self._probes)} probes")

    def setup(self) -> bool:
        """Initialize agent resources.

        Verifies:
            - Certificates exist
            - Auth log collector works
            - Probes initialize successfully

        Returns:
            True if setup succeeded
        """
        try:
            import os

            # Verify certificates
            required_certs = ["ca.crt", "agent.crt", "agent.key"]
            for cert in required_certs:
                cert_path = f"{CERT_DIR}/{cert}"
                if not os.path.exists(cert_path):
                    logger.error(f"Certificate not found: {cert_path}")
                    return False

            # Test auth log collector
            try:
                test_events = self.auth_collector.collect()
                logger.info(f"Auth collector test: {len(test_events)} events")
            except Exception as e:
                logger.warning(f"Auth collector test failed: {e}")
                # Continue anyway - collector may work later

            # Setup probes
            if not self.setup_probes():
                logger.error("No probes initialized successfully")
                return False

            logger.info("AuthGuardAgentV2 setup complete")
            return True

        except Exception as e:
            logger.error(f"Setup failed: {e}")
            return False

    def collect_data(self) -> Sequence[Any]:
        """Collect auth events and run all probes.

        Returns:
            List of DeviceTelemetry protobuf messages
        """
        # Collect auth events
        auth_events = self.auth_collector.collect()
        logger.debug(f"Collected {len(auth_events)} auth events")

        # Create context with auth events
        context = self._create_probe_context()
        context.shared_data["auth_events"] = auth_events

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
                logger.error(f"Probe {probe.name} failed: {e}")

        logger.info(f"Probes generated {len(events)} events")

        # Convert to protobuf
        if events:
            return [self._events_to_telemetry(events, auth_events)]
        return []

    def _events_to_telemetry(
        self, events: List[TelemetryEvent], auth_events: List[AuthEvent]
    ) -> telemetry_pb2.DeviceTelemetry:
        """Convert TelemetryEvents to protobuf DeviceTelemetry.

        Args:
            events: List of TelemetryEvent objects from probes
            auth_events: List of raw AuthEvent objects

        Returns:
            DeviceTelemetry protobuf message
        """
        timestamp_ns = int(time.time() * 1e9)

        # Create telemetry events from probe output
        telemetry_events = []

        # Add basic metrics
        telemetry_events.append(
            telemetry_pb2.TelemetryEvent(
                event_id=f"auth_event_count_{timestamp_ns}",
                event_type="METRIC",
                severity="INFO",
                event_timestamp_ns=timestamp_ns,
                metric_data=telemetry_pb2.MetricData(
                    metric_name="auth_event_count",
                    metric_type="GAUGE",
                    numeric_value=float(len(auth_events)),
                    unit="events",
                ),
                source_component="auth_guard_agent",
                tags=["auth", "metric"],
            )
        )

        # Convert probe events to telemetry
        for event in events:
            # Create appropriate telemetry based on event type
            severity_map = {
                "DEBUG": "DEBUG",
                "INFO": "INFO",
                "LOW": "LOW",
                "MEDIUM": "MEDIUM",
                "HIGH": "HIGH",
                "CRITICAL": "CRITICAL",
            }

            tel_event = telemetry_pb2.TelemetryEvent(
                event_id=f"{event.event_type}_{timestamp_ns}",
                event_type="ALERT" if event.severity.value in ("HIGH", "CRITICAL") else "METRIC",
                severity=severity_map.get(event.severity.value, "INFO"),
                event_timestamp_ns=timestamp_ns,
                source_component="auth_guard_agent",
                tags=["auth", "threat"] + event.mitre_techniques,
            )

            # Add metric data
            tel_event.metric_data.CopyFrom(
                telemetry_pb2.MetricData(
                    metric_name=event.event_type,
                    metric_type="GAUGE",
                    numeric_value=1.0,
                    unit="threat_indicator",
                )
            )

            telemetry_events.append(tel_event)

        # Create device telemetry
        telemetry = telemetry_pb2.DeviceTelemetry(
            device_id=self.device_id,
            device_type="HOST",
            protocol="AUTH",
            events=telemetry_events,
            timestamp_ns=timestamp_ns,
            collection_agent="auth-guard-agent",
            agent_version="2.0.0",
        )

        return telemetry

    def validate_event(self, event: Any) -> ValidationResult:
        """Validate telemetry before publishing.

        Args:
            event: DeviceTelemetry protobuf message

        Returns:
            ValidationResult
        """
        errors = []

        if not event.device_id:
            errors.append("device_id required")
        if event.timestamp_ns <= 0:
            errors.append("timestamp_ns must be positive")
        if not event.events:
            errors.append("events list is empty")

        return ValidationResult(is_valid=len(errors) == 0, errors=errors)

    def shutdown(self) -> None:
        """Graceful shutdown."""
        logger.info("AuthGuardAgentV2 shutting down...")

        # Close EventBus connection
        if self.eventbus_publisher:
            self.eventbus_publisher.close()

        logger.info("AuthGuardAgentV2 shutdown complete")

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
    """Run AuthGuard Agent v2."""
    import argparse

    parser = argparse.ArgumentParser(description="AMOSKYS AuthGuard Agent v2")
    parser.add_argument(
        "--interval",
        type=float,
        default=30.0,
        help="Collection interval in seconds",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info("=" * 70)
    logger.info("AMOSKYS AuthGuard Agent v2 (Micro-Probe Architecture)")
    logger.info("=" * 70)

    agent = AuthGuardAgentV2(collection_interval=args.interval)

    try:
        agent.run_forever()
    except KeyboardInterrupt:
        logger.info("Received interrupt, shutting down...")
        agent.shutdown()


if __name__ == "__main__":
    main()
