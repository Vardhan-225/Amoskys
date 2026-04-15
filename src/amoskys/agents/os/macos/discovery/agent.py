"""macOS Device Discovery Observatory Agent — network device threat detection.

Monitors ARP tables, Bonjour services, hardware ports, and routing tables for:
    - ARP table changes (new hosts, MAC spoofing)
    - Bonjour/mDNS new service detection
    - Rogue DHCP server detection (multiple gateways)
    - Network topology changes (new interfaces, route changes)
    - New device risk scoring (unknown MAC vendors)
    - Inbound port scan detection (host burst patterns)

Data flow:
    MacOSDiscoveryCollector.collect() -> shared_data
    -> 6 probes scan(context) -> TelemetryEvent[]
    -> _events_to_telemetry() -> DeviceTelemetry
    -> LocalQueueAdapter -> EventBus
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
from amoskys.agents.os.macos.discovery.collector import MacOSDiscoveryCollector
from amoskys.agents.os.macos.discovery.probes import create_discovery_probes
from amoskys.config import get_config

logger = logging.getLogger(__name__)
config = get_config()
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = "data/queue/macos_discovery.db"


class MacOSDiscoveryAgent(MicroProbeAgentMixin, HardenedAgentBase):
    """macOS Device Discovery Observatory -- 6 probes, 5 MITRE techniques.

    Probes:
        macos_discovery_arp             -- T1018 ARP table changes
        macos_discovery_bonjour         -- T1046 Bonjour service discovery
        macos_discovery_rogue_dhcp      -- T1557.001 Rogue DHCP detection
        macos_discovery_topology        -- T1016 Network topology changes
        macos_discovery_new_device_risk -- T1200 New device risk scoring
        macos_discovery_port_scan       -- T1046 Port scan detection
    """

    # Discovery detects network HOSTS (ARP, Bonjour, DHCP), not processes.
    # The mandatory field is the discovered device's IP, not a local PID.
    MANDATE_DATA_FIELDS = ("remote_ip",)

    def __init__(self, collection_interval: float = 60.0) -> None:
        device_id = socket.gethostname()

        Path(QUEUE_PATH).parent.mkdir(parents=True, exist_ok=True)
        queue_adapter = LocalQueueAdapter(
            queue_path=QUEUE_PATH,
            agent_name="macos_discovery",
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,
            max_retries=10,
            signing_key_path=f"{CERT_DIR}/agent.ed25519",
        )

        super().__init__(
            agent_name="macos_discovery",
            device_id=device_id,
            collection_interval=collection_interval,
            queue_adapter=queue_adapter,
        )

        self.collector = MacOSDiscoveryCollector(device_id=device_id)
        self.register_probes(create_discovery_probes())

        logger.info(
            "MacOSDiscoveryAgent initialized: %d probes, device=%s",
            len(self._probes),
            device_id,
        )

    def setup(self) -> bool:
        """Verify macOS platform and discovery data sources."""
        if platform.system() != "Darwin":
            logger.error("MacOSDiscoveryAgent requires macOS (Darwin)")
            return False

        # Verify arp command
        try:
            import subprocess

            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                logger.info("ARP table OK: arp -a accessible")
            else:
                logger.warning("ARP table degraded: returncode=%d", result.returncode)
        except Exception as e:
            logger.warning("ARP table check failed: %s", e)

        # Verify networksetup
        try:
            import subprocess

            result = subprocess.run(
                ["networksetup", "-listallhardwareports"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                logger.info("networksetup OK: hardware ports accessible")
        except Exception as e:
            logger.warning("networksetup check failed: %s", e)

        # Verify netstat
        try:
            import subprocess

            result = subprocess.run(
                ["netstat", "-rn"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                logger.info("netstat OK: routing table accessible")
        except Exception as e:
            logger.warning("netstat check failed: %s", e)

        if not self.setup_probes(
            collector_shared_data_keys=[
                "arp_entries",
                "bonjour_services",
                "hardware_ports",
                "routes",
                "arp_count",
                "collection_time_ms",
            ]
        ):
            logger.error("No probes initialized")
            return False

        logger.info("MacOSDiscoveryAgent setup complete -- 6 probes active")
        return True

    def collect_data(self) -> Sequence[Any]:
        """Run discovery collector + probes, emit raw observations + detections."""
        snapshot = self.collector.collect()

        # Build OBSERVATION events for ALL discovery items (raw observability)
        obs_events: List[TelemetryEvent] = []
        obs_events += self._make_observation_events(
            snapshot.get("arp_entries", []),
            domain="discovery",
            field_mapper=self._arp_to_obs,
        )
        obs_events += self._make_observation_events(
            snapshot.get("bonjour_services", []),
            domain="discovery",
            field_mapper=self._bonjour_to_obs,
        )
        obs_events += self._make_observation_events(
            snapshot.get("hardware_ports", []),
            domain="discovery",
            field_mapper=self._hwport_to_obs,
        )
        obs_events += self._make_observation_events(
            snapshot.get("routes", []),
            domain="discovery",
            field_mapper=self._route_to_obs,
        )

        # Run probes (detection events, unchanged)
        context = self._create_probe_context()
        context.shared_data = snapshot
        probe_events = self.run_probes(context)

        all_events = obs_events + probe_events
        all_events.append(
            TelemetryEvent(
                event_type="collection_metadata",
                severity=Severity.DEBUG,
                probe_name="macos_discovery_collector",
                data={
                    "arp_count": snapshot["arp_count"],
                    "bonjour_services": len(snapshot["bonjour_services"]),
                    "hardware_ports": len(snapshot["hardware_ports"]),
                    "routes": len(snapshot["routes"]),
                    "collection_time_ms": snapshot["collection_time_ms"],
                    "observation_events": len(obs_events),
                    "probe_events": len(probe_events),
                },
            )
        )

        logger.info(
            "Discovery collected in %.1fms: %d ARP entries, %d services, "
            "%d ports, %d routes, %d observations, %d probe events",
            snapshot["collection_time_ms"],
            snapshot["arp_count"],
            len(snapshot["bonjour_services"]),
            len(snapshot["hardware_ports"]),
            len(snapshot["routes"]),
            len(obs_events),
            len(probe_events),
        )

        if all_events:
            return [self._events_to_telemetry(all_events)]
        return []

    @staticmethod
    def _arp_to_obs(entry) -> Dict[str, Any]:
        """Map an ARPEntry to observation data dict."""
        return {
            "ip": entry.ip,
            "mac": entry.mac,
            "interface": entry.interface,
            "is_permanent": str(entry.is_permanent),
        }

    @staticmethod
    def _bonjour_to_obs(service) -> Dict[str, Any]:
        """Map a BonjourService to observation data dict."""
        return {
            "name": service.name,
            "service_type": service.service_type,
            "domain": service.domain,
            "interface": service.interface,
        }

    @staticmethod
    def _hwport_to_obs(port) -> Dict[str, Any]:
        """Map a HardwarePort to observation data dict."""
        return {
            "name": port.name,
            "device": port.device,
            "mac": port.mac,
        }

    @staticmethod
    def _route_to_obs(route) -> Dict[str, Any]:
        """Map a RouteEntry to observation data dict."""
        return {
            "destination": route.destination,
            "gateway": route.gateway,
            "interface": route.interface,
            "flags": route.flags,
        }

    def _events_to_telemetry(self, events: List[TelemetryEvent]) -> Any:
        """Convert TelemetryEvents to protobuf DeviceTelemetry."""
        from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2

        timestamp_ns = int(time.time() * 1e9)
        proto_events = []

        for idx, event in enumerate(events):
            if event.event_type == "collection_metadata":
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"macos_discovery_meta_{timestamp_ns}",
                    event_type="METRIC",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="macos_discovery_collector",
                    metric_data=telemetry_pb2.MetricData(
                        metric_name="discovery_collection",
                        metric_type="GAUGE",
                        numeric_value=float(event.data.get("arp_count", 0)),
                        unit="entries",
                    ),
                )
            elif event.event_type.startswith("obs_"):
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"macos_discovery_obs_{idx}_{timestamp_ns}",
                    event_type="OBSERVATION",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="discovery_collector",
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
            protocol="MACOS_DISCOVERY",
            events=proto_events,
            timestamp_ns=timestamp_ns,
            collection_agent="macos_discovery",
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
        logger.info("MacOSDiscoveryAgent shutting down")
