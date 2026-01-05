#!/usr/bin/env python3
"""AMOSKYS DNS Agent v2 - Micro-Probe Architecture.

This is the modernized DNS agent using the "swarm of eyes" pattern.
9 micro-probes each watch one specific DNS threat vector.

Probes:
    1. RawDNSQueryProbe - Baseline DNS capture
    2. DGAScoreProbe - Domain Generation Algorithm detection
    3. BeaconingPatternProbe - C2 callback detection
    4. SuspiciousTLDProbe - High-risk TLD flagging
    5. NXDomainBurstProbe - Domain probing detection
    6. LargeTXTTunnelingProbe - DNS tunneling detection
    7. FastFluxRebindingProbe - Fast-flux and rebinding attacks
    8. NewDomainForProcessProbe - First-time domain per process
    9. BlockedDomainHitProbe - Threat intel blocklist

MITRE ATT&CK Coverage:
    - T1071.004: Application Layer Protocol: DNS
    - T1568.002: Dynamic Resolution: DGA
    - T1568.001: Dynamic Resolution: Fast Flux DNS
    - T1048.001: Exfiltration Over Alternative Protocol
    - T1573.002: Encrypted Channel
    - T1566: Phishing
    - T1046: Network Service Discovery

Usage:
    >>> agent = DNSAgentV2()
    >>> agent.run_forever()
"""

from __future__ import annotations

import json
import logging
import platform
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
from amoskys.agents.dns.probes import DNSQuery, create_dns_probes
from amoskys.config import get_config
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.proto import universal_telemetry_pb2_grpc as universal_pbrpc

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("DNSAgentV2")

config = get_config()
EVENTBUS_ADDRESS = config.agent.bus_address
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = getattr(config.agent, "dns_queue_path", "data/queue/dns_agent_v2.db")


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
# Platform-Specific DNS Collectors
# =============================================================================


class DNSCollector:
    """Base class for platform-specific DNS collection."""

    def collect(self) -> List[DNSQuery]:
        """Collect DNS queries from system.

        Returns:
            List of DNSQuery objects
        """
        raise NotImplementedError


class MacOSDNSCollector(DNSCollector):
    """Collects DNS queries on macOS via log show."""

    def __init__(self):
        self.last_timestamp: Optional[datetime] = None

    def collect(self) -> List[DNSQuery]:
        """Collect DNS queries from macOS unified logging."""
        queries = []

        try:
            # Query mDNSResponder logs
            cmd = [
                "log",
                "show",
                "--predicate",
                'process == "mDNSResponder" AND eventMessage CONTAINS "Query"',
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
                        query = self._parse_log_entry(entry)
                        if query:
                            queries.append(query)
                except json.JSONDecodeError:
                    logger.debug("Failed to parse log output as JSON")

        except subprocess.TimeoutExpired:
            logger.warning("DNS log collection timed out")
        except Exception as e:
            logger.error(f"Failed to collect DNS logs: {e}")

        return queries

    def _parse_log_entry(self, entry: Dict) -> Optional[DNSQuery]:
        """Parse a log entry into DNSQuery."""
        try:
            message = entry.get("eventMessage", "")
            timestamp_str = entry.get("timestamp", "")

            # Parse timestamp
            timestamp = datetime.now(timezone.utc)
            if timestamp_str:
                try:
                    timestamp = datetime.fromisoformat(
                        timestamp_str.replace("Z", "+00:00")
                    )
                except ValueError:
                    pass

            # Extract domain from message (simplified)
            # Real implementation would use regex to parse the query
            if "Query" in message:
                parts = message.split()
                for i, part in enumerate(parts):
                    if part == "for":
                        domain = parts[i + 1] if i + 1 < len(parts) else "unknown"
                        return DNSQuery(
                            timestamp=timestamp,
                            domain=domain.strip("'\""),
                            query_type="A",
                            source_ip="127.0.0.1",
                        )

        except Exception as e:
            logger.debug(f"Failed to parse log entry: {e}")

        return None


class LinuxDNSCollector(DNSCollector):
    """Collects DNS queries on Linux."""

    def __init__(self):
        self.log_paths = [
            "/var/log/named/query.log",
            "/var/log/syslog",
            "/var/log/messages",
        ]

    def collect(self) -> List[DNSQuery]:
        """Collect DNS queries from Linux logs."""
        queries = []

        # Try systemd-resolved
        try:
            cmd = ["resolvectl", "query", "--legend=no"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            # Parse output...
        except Exception:
            pass

        # Fall back to log parsing
        for log_path in self.log_paths:
            if Path(log_path).exists():
                # Parse DNS queries from log file
                # Real implementation would tail the log
                pass

        return queries


def get_dns_collector() -> DNSCollector:
    """Get platform-appropriate DNS collector."""
    system = platform.system()
    if system == "Darwin":
        return MacOSDNSCollector()
    elif system == "Linux":
        return LinuxDNSCollector()
    else:
        logger.warning(f"Unsupported platform: {system}")
        return MacOSDNSCollector()  # Default


# =============================================================================
# DNS Agent V2
# =============================================================================


class DNSAgentV2(MicroProbeAgentMixin, HardenedAgentBase):
    """DNS Agent with micro-probe architecture.

    This agent hosts 9 micro-probes that each monitor a specific DNS
    threat vector. The agent handles:
        - DNS query collection (platform-specific)
        - Probe lifecycle management
        - Event aggregation and publishing
        - Circuit breaker and retry logic
        - Offline queue management

    Probes are responsible only for detection - no networking or state
    management.
    """

    def __init__(self, collection_interval: float = 10.0):
        """Initialize DNS Agent v2.

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
            agent_name="dns_agent_v2",
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,
            max_retries=10,
        )

        # Initialize base classes
        super().__init__(
            agent_name="dns_agent_v2",
            device_id=device_id,
            collection_interval=collection_interval,
            eventbus_publisher=publisher,
            local_queue=queue_adapter,
        )

        # Platform-specific DNS collector
        self.dns_collector = get_dns_collector()

        # Register all DNS probes
        self.register_probes(create_dns_probes())

        logger.info(f"DNSAgentV2 initialized with {len(self._probes)} probes")

    def setup(self) -> bool:
        """Initialize agent resources.

        Verifies:
            - Certificates exist
            - DNS collector works
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

            # Test DNS collector
            try:
                test_queries = self.dns_collector.collect()
                logger.info(f"DNS collector test: {len(test_queries)} queries")
            except Exception as e:
                logger.warning(f"DNS collector test failed: {e}")
                # Continue anyway - collector may work later

            # Setup probes
            if not self.setup_probes():
                logger.error("No probes initialized successfully")
                return False

            logger.info("DNSAgentV2 setup complete")
            return True

        except Exception as e:
            logger.error(f"Setup failed: {e}")
            return False

    def collect_data(self) -> Sequence[Any]:
        """Collect DNS queries and run all probes.

        Returns:
            List of DeviceTelemetry protobuf messages
        """
        # Collect DNS queries
        dns_queries = self.dns_collector.collect()
        logger.debug(f"Collected {len(dns_queries)} DNS queries")

        # Prepare shared context for probes
        # Store queries in a way probes can access
        for probe in self._probes:
            if hasattr(probe, "query_buffer"):
                probe.query_buffer = []

        # Create context with DNS queries
        context = self._create_probe_context()
        context.shared_data["dns_queries"] = dns_queries

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
            return [self._events_to_telemetry(events)]
        return []

    def _events_to_telemetry(
        self, events: List[TelemetryEvent]
    ) -> telemetry_pb2.DeviceTelemetry:
        """Convert TelemetryEvents to protobuf DeviceTelemetry.

        Args:
            events: List of TelemetryEvent objects

        Returns:
            DeviceTelemetry protobuf message
        """
        # Create DNS telemetry
        dns_data = telemetry_pb2.DNSTelemetry()

        for event in events:
            # Map events to appropriate protobuf fields
            if event.event_type == "dns_query":
                query = telemetry_pb2.DNSRecord(
                    domain_queried=event.data.get("domain", ""),
                    record_type=event.data.get("query_type", "A"),
                    source_ip=event.data.get("source_ip", ""),
                )
                dns_data.recent_queries.append(query)

            elif event.event_type in (
                "dga_domain_detected",
                "suspicious_domain_entropy",
            ):
                dns_data.dga_score = event.data.get("dga_score", 0.0)
                dns_data.dga_domain = event.data.get("domain", "")

            elif event.event_type == "dns_beaconing_detected":
                dns_data.beaconing_detected = True
                dns_data.beacon_domain = event.data.get("domain", "")
                dns_data.beacon_interval = event.data.get("avg_interval_seconds", 0)

            elif event.event_type == "dns_tunneling_suspected":
                dns_data.tunneling_suspected = True
                dns_data.tunnel_domain = event.data.get("domain", "")

        # Create device telemetry
        telemetry = telemetry_pb2.DeviceTelemetry(
            device_id=self.device_id,
            timestamp=int(time.time()),
            hostname=self.device_id,
            platform=platform.system(),
            dns_telemetry=dns_data,
        )

        # Add alert data for high-severity events
        for event in events:
            if event.severity.value in ("HIGH", "CRITICAL"):
                alert = telemetry_pb2.AlertData(
                    alert_type=event.event_type,
                    severity=event.severity.value,
                    description=str(event.data),
                    mitre_techniques=event.mitre_techniques,
                )
                telemetry.alerts.append(alert)

        return telemetry

    def validate_event(self, event: Any) -> ValidationResult:
        """Validate telemetry before publishing.

        Args:
            event: DeviceTelemetry protobuf message

        Returns:
            ValidationResult
        """
        if not hasattr(event, "device_id") or not event.device_id:
            return ValidationResult(is_valid=False, errors=["Missing device_id"])

        if not hasattr(event, "timestamp") or event.timestamp == 0:
            return ValidationResult(is_valid=False, errors=["Missing timestamp"])

        return ValidationResult(is_valid=True)

    def shutdown(self) -> None:
        """Graceful shutdown."""
        logger.info("DNSAgentV2 shutting down...")

        # Close EventBus connection
        if self.eventbus_publisher:
            self.eventbus_publisher.close()

        logger.info("DNSAgentV2 shutdown complete")

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
    """Run DNS Agent v2."""
    import argparse

    parser = argparse.ArgumentParser(description="AMOSKYS DNS Agent v2")
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

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    agent = DNSAgentV2(collection_interval=args.interval)

    try:
        agent.run_forever()
    except KeyboardInterrupt:
        logger.info("Received interrupt, shutting down...")
        agent.shutdown()


if __name__ == "__main__":
    main()
