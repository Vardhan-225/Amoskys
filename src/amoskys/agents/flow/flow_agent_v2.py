#!/usr/bin/env python3
"""FlowAgentV2 — Network Flow Monitoring with Micro-Probe Architecture.

Monitors network traffic (TCP/UDP flows) for threat detection:
    - Port scanning and reconnaissance
    - Lateral movement via admin protocols
    - Data exfiltration patterns
    - C2 beaconing
    - Cleartext credential leaks
    - Suspicious tunnels
    - DNS-based reconnaissance
    - New external service connections

Architecture:
    - MacOSFlowCollector: Parses `lsof -i -n -P` for live TCP/UDP flows
    - 8 Micro-Probes: Specialized threat detectors
    - HardenedAgentBase: Circuit breaker + offline resilience

CLI Usage:
    python flow_agent_v2.py --interval 15 --log-level DEBUG
    python flow_agent_v2.py --interface en0

MITRE ATT&CK Coverage:
    - T1046: Network Service Discovery
    - T1021: Remote Services
    - T1041/T1048: Exfiltration
    - T1071: Application Layer Protocol (C2)
    - T1090/T1572: Proxy & Tunneling
    - T1552: Unsecured Credentials
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import os
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
from amoskys.agents.flow.probes import FlowEvent, create_flow_probes
from amoskys.config import get_config
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.proto import universal_telemetry_pb2_grpc as universal_pbrpc

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("FlowAgentV2")

config = get_config()
EVENTBUS_ADDRESS = config.agent.bus_address
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = getattr(config.agent, "flow_queue_path", "data/queue/flow_agent_v2.db")


# =============================================================================
# EventBus Publisher (same pattern as DNSAgentV2)
# =============================================================================


class EventBusPublisher:
    """Wrapper for EventBus gRPC client."""

    def __init__(self, address: str, cert_dir: str):
        self.address = address
        self.cert_dir = cert_dir
        self._channel = None
        self._stub = None

    def _ensure_channel(self):
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
        if self._channel:
            self._channel.close()
            self._channel = None
            self._stub = None


# =============================================================================
# MacOS Flow Collector — parses `lsof -i -n -P`
# =============================================================================

# Regex to parse lsof NAME column:
#   192.168.1.5:54321->93.184.216.34:443 (ESTABLISHED)
#   [::1]:631 (LISTEN)
#   *:22 (LISTEN)
_LSOF_TCP_ARROW = re.compile(
    r"^(?P<src_ip>[0-9a-fA-F.:*\[\]]+):(?P<src_port>\d+)"
    r"->(?P<dst_ip>[0-9a-fA-F.:*\[\]]+):(?P<dst_port>\d+)"
    r"\s*\((?P<state>\w+)\)"
)


class MacOSFlowCollector:
    """Collects live TCP/UDP connection metadata on macOS via ``lsof -i -n -P``.

    This is a snapshot-based collector: each call returns a point-in-time
    view of all open network connections.  By running every N seconds the
    agent accumulates flow observations for the probes to analyse.

    lsof output example::

        COMMAND   PID  USER   FD   TYPE   DEVICE  SIZE/OFF NODE NAME
        Safari   1234  user   5u   IPv4   0x...   0t0      TCP  192.168.1.5:54321->93.184.216.34:443 (ESTABLISHED)
        mDNSResp  123  root   6u   IPv4   0x...   0t0      UDP  *:5353

    We parse default (human-readable) mode because it's universal across
    macOS versions and doesn't require root for user-owned connections.
    """

    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        self.flows_collected = 0
        self._collection_errors = 0

    def collect(self, window_seconds: int = 60) -> List[FlowEvent]:
        """Run ``lsof -i -n -P`` and parse output into FlowEvent objects."""
        now_ns = int(time.time() * 1e9)
        flows: List[FlowEvent] = []

        try:
            cmd = ["lsof", "-i", "-n", "-P"]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
            )

            if result.returncode != 0 and not result.stdout:
                logger.warning(
                    "lsof returned code %d: %s",
                    result.returncode,
                    result.stderr[:200] if result.stderr else "(no stderr)",
                )
                self._collection_errors += 1
                return flows

            for line in result.stdout.splitlines()[1:]:  # skip header
                flow = self._parse_lsof_line(line, now_ns)
                if flow is not None:
                    flows.append(flow)

        except subprocess.TimeoutExpired:
            logger.warning("lsof timed out after 15 s")
            self._collection_errors += 1
        except FileNotFoundError:
            logger.error("lsof not found on PATH")
            self._collection_errors += 1
        except Exception as e:
            logger.error("Flow collection error: %s", e, exc_info=True)
            self._collection_errors += 1

        self.flows_collected += len(flows)
        logger.debug("Collected %d flows (%d total)", len(flows), self.flows_collected)
        return flows

    # --------------------------------------------------------------------- #

    def _parse_lsof_line(self, line: str, now_ns: int) -> Optional[FlowEvent]:
        """Parse a single lsof output line into a FlowEvent.

        We emit FlowEvents for ESTABLISHED TCP connections and active
        UDP sockets that show a remote address.  LISTEN sockets are skipped.
        """
        parts = line.split()
        if len(parts) < 9:
            return None

        # NODE is typically at index 7 (TCP/UDP), NAME is everything from index 8+
        node = parts[7] if len(parts) > 7 else ""
        name = " ".join(parts[8:]) if len(parts) > 8 else ""

        protocol = "TCP" if node == "TCP" else ("UDP" if node == "UDP" else "OTHER")
        if protocol == "OTHER":
            return None

        # Skip LISTEN sockets — they don't represent active traffic
        if "(LISTEN)" in name:
            return None

        # Try TCP/UDP connection with arrow (src->dst)
        m = _LSOF_TCP_ARROW.match(name)
        if m:
            src_ip = self._normalise_ip(m.group("src_ip"))
            dst_ip = self._normalise_ip(m.group("dst_ip"))
            src_port = int(m.group("src_port"))
            dst_port = int(m.group("dst_port"))
            state = m.group("state")

            if src_ip is None or dst_ip is None:
                return None

            direction = self._infer_direction(src_ip, dst_ip)
            app_proto = self._guess_app_protocol(dst_port)
            tcp_flags = self._state_to_flags(state) if protocol == "TCP" else None

            return FlowEvent(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                bytes_tx=0,       # lsof doesn't report bytes
                bytes_rx=0,
                packet_count=1,   # snapshot — 1 observation
                first_seen_ns=now_ns,
                last_seen_ns=now_ns,
                direction=direction,
                app_protocol=app_proto,
                tcp_flags=tcp_flags,
            )

        # UDP with arrow but no state parenthetical
        if protocol == "UDP" and "->" in name:
            m2 = re.match(
                r"^([0-9a-fA-F.:*\[\]]+):(\d+)->([0-9a-fA-F.:*\[\]]+):(\d+)",
                name,
            )
            if m2:
                src_ip = self._normalise_ip(m2.group(1))
                dst_ip = self._normalise_ip(m2.group(3))
                if src_ip is None or dst_ip is None:
                    return None
                src_port = int(m2.group(2))
                dst_port = int(m2.group(4))

                return FlowEvent(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol="UDP",
                    bytes_tx=0,
                    bytes_rx=0,
                    packet_count=1,
                    first_seen_ns=now_ns,
                    last_seen_ns=now_ns,
                    direction=self._infer_direction(src_ip, dst_ip),
                    app_protocol=self._guess_app_protocol(dst_port),
                )

        return None

    # -- helpers ----------------------------------------------------------- #

    @staticmethod
    def _normalise_ip(ip: str) -> Optional[str]:
        """Convert wildcard / localhost variants to usable IP strings."""
        if ip in ("*", "0.0.0.0", "::", "[::]"):
            return None  # unresolvable — skip
        # Strip IPv6 brackets
        if ip.startswith("[") and ip.endswith("]"):
            ip = ip[1:-1]
        if ip == "localhost":
            return "127.0.0.1"
        return ip

    @staticmethod
    def _infer_direction(src_ip: str, dst_ip: str) -> str:
        """Rough direction heuristic based on RFC1918."""
        try:
            s = ipaddress.ip_address(src_ip)
            d = ipaddress.ip_address(dst_ip)
        except ValueError:
            return "UNKNOWN"

        if s.is_private and d.is_private:
            return "LATERAL"
        if s.is_private and not d.is_private:
            return "OUTBOUND"
        if not s.is_private and d.is_private:
            return "INBOUND"
        return "UNKNOWN"

    @staticmethod
    def _guess_app_protocol(port: int) -> str:
        """Map well-known ports to application protocol names."""
        mapping = {
            22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
            110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            465: "SMTPS", 587: "SMTP", 993: "IMAPS", 995: "POP3S",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5985: "WinRM-HTTP", 5986: "WinRM-HTTPS", 6379: "Redis",
            8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
        }
        return mapping.get(port, "UNKNOWN")

    @staticmethod
    def _state_to_flags(state: str) -> str:
        """Map lsof TCP state to simplified flag string."""
        state_flags = {
            "ESTABLISHED": "SA", "SYN_SENT": "S", "SYN_RECV": "SA",
            "CLOSE_WAIT": "FA", "TIME_WAIT": "FA", "FIN_WAIT1": "F",
            "FIN_WAIT2": "F", "LAST_ACK": "FA", "CLOSING": "FA",
            "LISTEN": "L",
        }
        return state_flags.get(state, state[:2] if state else "")


# =============================================================================
# FlowAgentV2 — Main Agent
# =============================================================================


class FlowAgentV2(MicroProbeAgentMixin, HardenedAgentBase):
    """Network flow monitoring agent with micro-probe architecture.

    Monitors network traffic using 8 specialised threat detectors:
        1. PortScanSweepProbe     — Port scanning detection
        2. LateralSMBWinRMProbe   — Lateral movement
        3. DataExfilVolumeSpikeProbe — Data exfiltration
        4. C2BeaconFlowProbe      — C2 beaconing patterns
        5. CleartextCredentialLeakProbe — Cleartext credentials
        6. SuspiciousTunnelProbe  — Suspicious tunnels
        7. InternalReconDNSFlowProbe — DNS reconnaissance
        8. NewExternalServiceProbe — New external connections
    """

    AGENT_NAME = "flow_agent_v2"

    def __init__(
        self,
        collection_interval: float = 15.0,
        interface: Optional[str] = None,
        queue_path: str = "",
        device_id: Optional[str] = None,
    ):
        device_id = device_id or socket.gethostname()
        if not queue_path:
            queue_path = QUEUE_PATH

        # EventBus publisher
        publisher = EventBusPublisher(EVENTBUS_ADDRESS, CERT_DIR)

        # Local queue for offline resilience
        Path(queue_path).parent.mkdir(parents=True, exist_ok=True)
        queue_adapter = LocalQueueAdapter(
            queue_path=queue_path,
            agent_name="flow_agent_v2",
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,
            max_retries=10,
        )

        # Initialise base classes — canonical super().__init__() pattern
        super().__init__(
            agent_name=self.AGENT_NAME,
            device_id=device_id,
            collection_interval=collection_interval,
            eventbus_publisher=publisher,
            local_queue=queue_adapter,
        )

        # Platform-specific flow collector
        self.collector = MacOSFlowCollector(interface=interface)

        # Register all 8 flow probes
        self.register_probes(create_flow_probes())

        logger.info(
            "FlowAgentV2 initialised: device=%s, interface=%s, interval=%.0fs, probes=%d",
            device_id, interface or "all", collection_interval, len(self._probes),
        )

    # ------------------------------------------------------------------ #
    # Lifecycle hooks
    # ------------------------------------------------------------------ #

    def setup(self) -> bool:
        """Cert-tolerant setup — warns but does NOT fail if TLS certs missing."""
        try:
            required_certs = ["ca.crt", "agent.crt", "agent.key"]
            for cert in required_certs:
                cert_path = f"{CERT_DIR}/{cert}"
                if not os.path.exists(cert_path):
                    logger.warning("Certificate not found: %s (EventBus will fail)", cert_path)

            # Test collector
            try:
                test_flows = self.collector.collect(window_seconds=5)
                logger.info("Flow collector test: %d connections seen", len(test_flows))
            except Exception as e:
                logger.warning("Flow collector test failed: %s", e)

            # Setup probes
            if not self.setup_probes():
                logger.error("No probes initialised successfully")
                return False

            logger.info("FlowAgentV2 setup complete")
            return True
        except Exception as e:
            logger.error("Setup failed: %s", e)
            return False

    def collect_data(self) -> Sequence[Any]:
        """Collect flows and run probes.

        Always returns ≥1 DeviceTelemetry with heartbeat METRIC (liveness proof).
        """
        timestamp_ns = int(time.time() * 1e9)

        # Collect flows from OS
        flows = self.collector.collect(window_seconds=int(self.collection_interval))
        logger.info("Collected %d flows in this cycle", len(flows))

        # Build probe context
        context = self._create_probe_context()
        context.now_ns = timestamp_ns
        context.shared_data["flows"] = flows
        context.shared_data["window_end_ns"] = timestamp_ns
        context.shared_data["window_start_ns"] = timestamp_ns - int(self.collection_interval * 1e9)

        # Run all probes
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

        logger.info("Probes generated %d events from %d flows", len(events), len(flows))

        # ----- Build proto events -----
        proto_events = []

        # Heartbeat METRIC — always emitted
        proto_events.append(
            telemetry_pb2.TelemetryEvent(
                event_id=f"flow_collection_summary_{timestamp_ns}",
                event_type="METRIC",
                severity="INFO",
                event_timestamp_ns=timestamp_ns,
                source_component="flow_collector",
                tags=["flow", "metric", "heartbeat"],
                metric_data=telemetry_pb2.MetricData(
                    metric_name="flows_collected",
                    metric_type="GAUGE",
                    numeric_value=float(len(flows)),
                    unit="connections",
                ),
            )
        )

        # Collector cumulative metric
        proto_events.append(
            telemetry_pb2.TelemetryEvent(
                event_id=f"flow_collector_total_{timestamp_ns}",
                event_type="METRIC",
                severity="INFO",
                event_timestamp_ns=timestamp_ns,
                source_component="flow_collector",
                tags=["flow", "metric"],
                metric_data=telemetry_pb2.MetricData(
                    metric_name="flows_collected_total",
                    metric_type="COUNTER",
                    numeric_value=float(self.collector.flows_collected),
                    unit="connections",
                ),
            )
        )

        # Probe event count metric
        if events:
            proto_events.append(
                telemetry_pb2.TelemetryEvent(
                    event_id=f"flow_probe_events_{timestamp_ns}",
                    event_type="METRIC",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="flow_agent",
                    tags=["flow", "metric"],
                    metric_data=telemetry_pb2.MetricData(
                        metric_name="flow_probe_events",
                        metric_type="GAUGE",
                        numeric_value=float(len(events)),
                        unit="events",
                    ),
                )
            )

        # Convert probe TelemetryEvents → SecurityEvent-based proto events
        severity_map = {
            "DEBUG": "DEBUG", "INFO": "INFO", "LOW": "LOW",
            "MEDIUM": "MEDIUM", "HIGH": "HIGH", "CRITICAL": "CRITICAL",
        }

        for event in events:
            security_event = telemetry_pb2.SecurityEvent(
                event_category=event.event_type,
                risk_score=0.8 if event.severity.value in ("HIGH", "CRITICAL") else 0.4,
                analyst_notes=f"Probe: {event.probe_name}, Severity: {event.severity.value}",
            )
            security_event.mitre_techniques.extend(event.mitre_techniques)

            tel_event = telemetry_pb2.TelemetryEvent(
                event_id=f"{event.event_type}_{timestamp_ns}",
                event_type="SECURITY",
                severity=severity_map.get(event.severity.value, "INFO"),
                event_timestamp_ns=timestamp_ns,
                source_component=event.probe_name or "flow_agent",
                tags=["flow", "threat"],
                security_event=security_event,
                confidence_score=event.confidence,
            )

            if event.data:
                for key, value in event.data.items():
                    if value is not None:
                        tel_event.attributes[key] = str(value)

            proto_events.append(tel_event)

        # Package as DeviceTelemetry
        telemetry = telemetry_pb2.DeviceTelemetry(
            device_id=self.device_id,
            device_type="HOST",
            protocol="FLOW",
            events=proto_events,
            timestamp_ns=timestamp_ns,
            collection_agent="flow_agent_v2",
            agent_version="2.0.0",
        )

        return [telemetry]

    def validate_event(self, event: Any) -> ValidationResult:
        """Validate telemetry — returns ValidationResult (not bool)."""
        errors = []
        if not hasattr(event, "device_id") or not event.device_id:
            errors.append("Missing device_id")
        if not hasattr(event, "timestamp_ns") or event.timestamp_ns <= 0:
            errors.append("Missing or invalid timestamp_ns")
        if not event.events:
            errors.append("events list is empty")
        return ValidationResult(is_valid=len(errors) == 0, errors=errors)

    def enrich_event(self, event: Any) -> Any:
        """Enrich telemetry with host context."""
        try:
            ip_address = socket.gethostbyname(socket.gethostname())
            if event.events:
                event.events[0].attributes["host_ip"] = ip_address
        except OSError:
            pass
        return event

    def shutdown(self) -> None:
        logger.info("FlowAgentV2 shutting down...")
        if self.eventbus_publisher:
            self.eventbus_publisher.close()
        logger.info("FlowAgentV2 shutdown complete")

    def get_health(self) -> Dict[str, Any]:
        return {
            "agent_name": self.agent_name,
            "device_id": self.device_id,
            "is_running": self.is_running,
            "collection_count": self.collection_count,
            "error_count": self.error_count,
            "last_error": self.last_error,
            "probes": self.get_probe_health(),
            "circuit_breaker_state": self.circuit_breaker.state,
            "flows_collected_total": self.collector.flows_collected,
            "collector_errors": self.collector._collection_errors,
        }


# =============================================================================
# CLI Entry Point
# =============================================================================


def main():
    parser = argparse.ArgumentParser(
        description="FlowAgentV2 — Network Flow Monitoring (Micro-Probe Architecture)"
    )
    parser.add_argument("--device-id", type=str, default=None,
                        help="Device identifier (default: hostname)")
    parser.add_argument("--queue-path", type=str, default="data/queue/flow_agent_v2.db",
                        help="Local queue database path")
    parser.add_argument("--interval", type=float, default=15.0,
                        help="Collection interval in seconds (default: 15)")
    parser.add_argument("--interface", type=str, default=None,
                        help="Network interface to monitor (default: all)")
    parser.add_argument("--log-level", type=str, default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        help="Logging level")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug logging (shortcut for --log-level DEBUG)")

    args = parser.parse_args()

    if args.log_level:
        logging.getLogger().setLevel(getattr(logging, args.log_level))
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info("=" * 70)
    logger.info("AMOSKYS FlowAgent V2 (Micro-Probe Architecture)")
    logger.info("=" * 70)

    agent = FlowAgentV2(
        collection_interval=args.interval,
        interface=args.interface,
        queue_path=args.queue_path,
        device_id=args.device_id,
    )

    try:
        agent.run_forever()
    except KeyboardInterrupt:
        logger.info("Received interrupt, shutting down...")
        agent.shutdown()


if __name__ == "__main__":
    main()
