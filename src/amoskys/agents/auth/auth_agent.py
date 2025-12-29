#!/usr/bin/env python3
"""
AMOSKYS Authentication Guard Agent (AuthGuardAgent)

Monitors authentication and privilege escalation events:
- User logins (console, SSH, remote desktop)
- Sudo command execution
- Failed authentication attempts
- Session lock/unlock events

Purpose: Detect credential attacks, brute force, privilege escalation
"""

import logging
import re
import socket
import subprocess
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import grpc

from amoskys.agents.common import LocalQueue
from amoskys.config import get_config
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.proto import universal_telemetry_pb2_grpc as universal_pbrpc

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AuthGuardAgent")

config = get_config()
EVENTBUS_ADDRESS = config.agent.bus_address
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = getattr(config.agent, "auth_queue_path", "data/queue/auth_agent.db")


class AuthGuardAgent:
    """Authentication and privilege escalation monitoring agent"""

    def __init__(self, queue_path=None, lookback_seconds=60):
        """Initialize agent with local queue for offline resilience

        Args:
            queue_path: Path to queue database (default: from config)
            lookback_seconds: How far back to check logs (default: 60s)
        """
        self.queue_path = queue_path or QUEUE_PATH
        self.lookback_seconds = lookback_seconds
        self.last_check_time = None

        self.queue = LocalQueue(
            path=self.queue_path, max_bytes=50 * 1024 * 1024, max_retries=10  # 50MB
        )
        logger.info(f"AuthGuardAgent initialized: {self.queue_path}")

    def _get_grpc_channel(self):
        """Create gRPC channel to EventBus with mTLS"""
        try:
            with open(f"{CERT_DIR}/ca.crt", "rb") as f:
                ca_cert = f.read()
            with open(f"{CERT_DIR}/agent.crt", "rb") as f:
                client_cert = f.read()
            with open(f"{CERT_DIR}/agent.key", "rb") as f:
                client_key = f.read()

            credentials = grpc.ssl_channel_credentials(
                root_certificates=ca_cert,
                private_key=client_key,
                certificate_chain=client_cert,
            )
            channel = grpc.secure_channel(EVENTBUS_ADDRESS, credentials)
            logger.debug("Created secure gRPC channel with mTLS")
            return channel
        except FileNotFoundError as e:
            logger.error("Certificate not found: %s", e)
            return None
        except Exception as e:
            logger.error("Failed to create gRPC channel: %s", str(e))
            return None

    def _parse_auth_logs(self) -> List[Dict]:
        """Parse macOS unified log for authentication events

        Returns:
            List of auth event dictionaries
        """
        events: List[Dict[str, Any]] = []

        # Calculate time window
        if self.last_check_time:
            # Use last check time
            start_time = self.last_check_time
        else:
            # First run - go back lookback_seconds
            start_time = datetime.now() - timedelta(seconds=self.lookback_seconds)

        # Format time for log show command
        time_str = start_time.strftime("%Y-%m-%d %H:%M:%S")

        try:
            # Query unified log for auth-related events
            # Covers: login, ssh, sudo, screen unlock, etc.
            cmd = [
                "log",
                "show",
                "--style",
                "syslog",
                "--predicate",
                '(process == "sshd" OR process == "sudo" OR process == "loginwindow" OR process == "screensharingd")',
                "--start",
                time_str,
                "--info",
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode != 0:
                logger.warning(f"log show command failed: {result.stderr}")
                return events

            # Parse log lines
            for line in result.stdout.splitlines():
                event = self._parse_log_line(line)
                if event:
                    events.append(event)

        except subprocess.TimeoutExpired:
            logger.error("log show command timed out")
        except Exception as e:
            logger.error(f"Failed to parse auth logs: {e}")

        return events

    def _parse_log_line(self, line: str) -> Optional[Dict]:
        """Parse a single log line for auth events

        Args:
            line: Log line from unified log

        Returns:
            Event dictionary or None
        """
        # SSH login patterns
        ssh_accepted = re.search(
            r"sshd.*Accepted\s+(\w+)\s+for\s+(\S+)\s+from\s+(\S+)", line
        )
        if ssh_accepted:
            return {
                "auth_type": "SSH",
                "result": "SUCCESS",
                "user": ssh_accepted.group(2),
                "source_ip": ssh_accepted.group(3),
                "method": ssh_accepted.group(1),
                "command": None,
                "raw_line": line,
            }

        # SSH failed login
        ssh_failed = re.search(
            r"sshd.*Failed\s+(\w+)\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)",
            line,
        )
        if ssh_failed:
            return {
                "auth_type": "SSH",
                "result": "FAILURE",
                "user": ssh_failed.group(2),
                "source_ip": ssh_failed.group(3),
                "method": ssh_failed.group(1),
                "command": None,
                "raw_line": line,
            }

        # Sudo command execution
        sudo_match = re.search(r"sudo.*USER=(\S+).*COMMAND=(.*)", line)
        if sudo_match:
            return {
                "auth_type": "SUDO",
                "result": "SUCCESS",
                "user": sudo_match.group(1),
                "source_ip": "127.0.0.1",  # Local
                "method": "password",
                "command": sudo_match.group(2).strip(),
                "raw_line": line,
            }

        # Console login (loginwindow)
        login_match = re.search(r"loginwindow.*Login\s+Window.*User\s+(\S+)", line)
        if login_match:
            return {
                "auth_type": "LOGIN",
                "result": "SUCCESS",
                "user": login_match.group(1),
                "source_ip": "127.0.0.1",  # Local console
                "method": "password",
                "command": None,
                "raw_line": line,
            }

        # Screen sharing
        screenshare_match = re.search(
            r"screensharingd.*Authentication.*user\s+(\S+)", line
        )
        if screenshare_match:
            return {
                "auth_type": "SCREEN_SHARE",
                "result": "SUCCESS",
                "user": screenshare_match.group(1),
                "source_ip": "0.0.0.0",  # Unknown without deeper parsing
                "method": "vnc",
                "command": None,
                "raw_line": line,
            }

        return None

    def _create_telemetry(
        self, auth_events: List[Dict]
    ) -> telemetry_pb2.DeviceTelemetry:
        """Create DeviceTelemetry protobuf from auth events

        Args:
            auth_events: List of parsed auth event dictionaries

        Returns:
            DeviceTelemetry protobuf message
        """
        timestamp_ns = int(time.time() * 1e9)
        device_id = socket.gethostname()

        # Convert auth events to SecurityEvent protobuf
        telemetry_events = []
        for idx, auth_event in enumerate(auth_events):
            # Map auth_type to MITRE techniques
            mitre_techniques = []
            if auth_event["auth_type"] == "SSH":
                mitre_techniques = ["T1021.004"]  # Remote Services: SSH
            elif auth_event["auth_type"] == "SUDO":
                mitre_techniques = [
                    "T1548.003"
                ]  # Abuse Elevation Control Mechanism: Sudo
            elif auth_event["auth_type"] == "SCREEN_SHARE":
                mitre_techniques = ["T1021.005"]  # Remote Services: VNC

            # Calculate risk score based on event
            risk_score = 0.1  # Default low
            if auth_event["result"] == "FAILURE":
                risk_score = 0.6  # Failed auth is suspicious
            elif auth_event["auth_type"] == "SUDO" and "rm -rf" in (
                auth_event.get("command") or ""
            ):
                risk_score = 0.8  # Dangerous sudo command

            security_event = telemetry_pb2.SecurityEvent(
                event_category="AUTHENTICATION",
                event_action=auth_event["auth_type"],
                event_outcome=auth_event["result"],
                user_name=auth_event["user"],
                source_ip=auth_event["source_ip"],
                risk_score=risk_score,
                mitre_techniques=mitre_techniques,
                requires_investigation=(risk_score > 0.5),
            )

            # Add command to attributes if present
            attributes = {}
            if auth_event.get("command"):
                attributes["sudo_command"] = auth_event["command"]
            if auth_event.get("method"):
                attributes["auth_method"] = auth_event["method"]

            telemetry_event = telemetry_pb2.TelemetryEvent(
                event_id=f"auth_{device_id}_{timestamp_ns}_{idx}",
                event_type="SECURITY",
                severity="WARN" if risk_score > 0.5 else "INFO",
                event_timestamp_ns=timestamp_ns,
                security_event=security_event,
                source_component="auth_agent",
                attributes=attributes,
                confidence_score=0.95,
            )
            telemetry_events.append(telemetry_event)

        # Device metadata
        try:
            ip_addr = socket.gethostbyname(socket.gethostname())
        except:
            ip_addr = "127.0.0.1"

        metadata = telemetry_pb2.DeviceMetadata(
            manufacturer="Apple",
            model=socket.gethostname(),
            ip_address=ip_addr,
            protocols=["AUTH"],
        )

        # Build DeviceTelemetry
        device_telemetry = telemetry_pb2.DeviceTelemetry(
            device_id=device_id,
            device_type="HOST",
            protocol="AUTH",
            metadata=metadata,
            events=telemetry_events,
            timestamp_ns=timestamp_ns,
            collection_agent="auth-agent",
            agent_version="1.0.0",
        )

        return device_telemetry

    def _publish_telemetry(self, device_telemetry):
        """Publish telemetry to EventBus with queue fallback"""
        try:
            channel = self._get_grpc_channel()
            if not channel:
                logger.warning("No gRPC channel, queueing telemetry")
                return self._queue_telemetry(device_telemetry)

            timestamp_ns = int(time.time() * 1e9)
            idempotency_key = f"{device_telemetry.device_id}_auth_{timestamp_ns}"
            envelope = telemetry_pb2.UniversalEnvelope(
                version="v1",
                ts_ns=timestamp_ns,
                idempotency_key=idempotency_key,
                device_telemetry=device_telemetry,
                signing_algorithm="Ed25519",
                priority="HIGH",  # Auth events are high priority
                requires_acknowledgment=True,
            )

            stub = universal_pbrpc.UniversalEventBusStub(channel)
            ack = stub.PublishTelemetry(envelope, timeout=5.0)

            if ack.status == telemetry_pb2.UniversalAck.OK:
                logger.info(
                    "Published auth telemetry (queue: %d pending)", self.queue.size()
                )
                return True
            else:
                logger.warning("Publish status: %s, queueing", ack.status)
                return self._queue_telemetry(device_telemetry)

        except grpc.RpcError as e:
            logger.warning("RPC failed: %s, queueing telemetry", e.code())
            return self._queue_telemetry(device_telemetry)
        except Exception as e:
            logger.error("Publish failed: %s, queueing telemetry", str(e))
            return self._queue_telemetry(device_telemetry)

    def _queue_telemetry(self, device_telemetry):
        """Queue telemetry for later retry"""
        try:
            timestamp_ns = int(time.time() * 1e9)
            idempotency_key = f"{device_telemetry.device_id}_auth_{timestamp_ns}"
            queued = self.queue.enqueue(device_telemetry, idempotency_key)

            if queued:
                logger.info(
                    "Queued auth telemetry (queue: %d items, %d bytes)",
                    self.queue.size(),
                    self.queue.size_bytes(),
                )

            return True
        except Exception as e:
            logger.error("Failed to queue telemetry: %s", str(e))
            return False

    def _drain_queue(self):
        """Attempt to drain queued telemetry to EventBus"""
        queue_size = self.queue.size()
        if queue_size == 0:
            return 0

        logger.info("Draining auth queue (%d events pending)...", queue_size)

        def publish_fn(telemetry):
            try:
                channel = self._get_grpc_channel()
                if not channel:
                    raise Exception("No gRPC channel")

                timestamp_ns = int(time.time() * 1e9)
                envelope = telemetry_pb2.UniversalEnvelope(
                    version="v1",
                    ts_ns=timestamp_ns,
                    idempotency_key=f"{telemetry.device_id}_auth_{timestamp_ns}_retry",
                    device_telemetry=telemetry,
                    signing_algorithm="Ed25519",
                    priority="HIGH",
                    requires_acknowledgment=True,
                )

                stub = universal_pbrpc.UniversalEventBusStub(channel)
                ack = stub.PublishTelemetry(envelope, timeout=5.0)
                return ack
            except Exception as e:
                logger.debug("Drain publish failed: %s", str(e))
                raise

        try:
            drained = self.queue.drain(publish_fn, limit=100)
            if drained > 0:
                logger.info(
                    "Drained %d auth events from queue (%d remaining)",
                    drained,
                    self.queue.size(),
                )
            return drained
        except Exception as e:
            logger.debug("Auth queue drain error: %s", str(e))
            return 0

    def collect(self):
        """Collect and publish authentication events once"""
        try:
            # Try to drain any queued events first
            self._drain_queue()

            # Collect new auth events
            logger.info("Collecting authentication events...")
            auth_events = self._parse_auth_logs()

            if not auth_events:
                logger.debug("No new auth events")
                self.last_check_time = datetime.now()
                return True

            logger.info(f"Found {len(auth_events)} auth events")

            # Create telemetry
            device_telemetry = self._create_telemetry(auth_events)

            # Publish or queue
            success = self._publish_telemetry(device_telemetry)

            # Update last check time
            self.last_check_time = datetime.now()

            if success:
                logger.info("Auth collection complete (%d events)", len(auth_events))
            else:
                logger.warning("Auth collection failed (queued for retry)")

            return True

        except Exception as e:
            logger.error("Auth collection error: %s", str(e), exc_info=True)
            return False

    def run(self, interval=60):
        """Main collection loop

        Args:
            interval: Seconds between collections (default: 60s)
        """
        logger.info("AMOSKYS Authentication Guard Agent starting...")
        logger.info("EventBus: %s", EVENTBUS_ADDRESS)
        logger.info("Collection interval: %ds", interval)

        cycle = 0
        while True:
            cycle += 1
            logger.info("=" * 60)
            logger.info("Cycle #%d - %s", cycle, datetime.now().isoformat())
            logger.info("=" * 60)

            self.collect()

            logger.info("Next collection in %ds...", interval)
            time.sleep(interval)


def main():
    """Entry point"""
    agent = AuthGuardAgent()
    agent.run(interval=60)


if __name__ == "__main__":
    main()
