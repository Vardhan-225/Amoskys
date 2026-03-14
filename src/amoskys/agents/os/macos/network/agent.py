"""macOS Network Agent — Network Observatory for Darwin.

Monitors network connections and bandwidth using lsof and nettop.
8 probes detect C2 beaconing, exfiltration, lateral movement, and anomalies.
"""

from __future__ import annotations

import logging
import platform
import socket
import time
from pathlib import Path
from typing import Any, Dict, List, Sequence

from amoskys.agents.common.base import HardenedAgentBase, ValidationResult
from amoskys.agents.common.probes import (
    MicroProbeAgentMixin,
    ProbeContext,
    Severity,
    TelemetryEvent,
)
from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.agents.os.macos.network.collector import MacOSNetworkCollector
from amoskys.agents.os.macos.network.probes import create_network_probes
from amoskys.config import get_config

logger = logging.getLogger(__name__)

config = get_config()
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = "data/queue/macos_network.db"


class MacOSNetworkAgent(MicroProbeAgentMixin, HardenedAgentBase):
    """macOS Network Observatory agent."""

    def __init__(self, collection_interval: float = 10.0) -> None:
        device_id = socket.gethostname()

        Path(QUEUE_PATH).parent.mkdir(parents=True, exist_ok=True)
        queue_adapter = LocalQueueAdapter(
            queue_path=QUEUE_PATH,
            agent_name="macos_network",
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,
            max_retries=10,
            signing_key_path=f"{CERT_DIR}/agent.ed25519",
        )

        super().__init__(
            agent_name="macos_network",
            device_id=device_id,
            collection_interval=collection_interval,
            queue_adapter=queue_adapter,
        )

        self.collector = MacOSNetworkCollector()
        self.register_probes(create_network_probes())

    def setup(self) -> bool:
        if platform.system() != "Darwin":
            logger.error("MacOSNetworkAgent requires macOS")
            return False

        if not self.setup_probes(
            collector_shared_data_keys=[
                "connections",
                "bandwidth",
                "connection_count",
                "collection_time_ms",
            ]
        ):
            return False

        logger.info("MacOSNetworkAgent setup complete")
        return True

    # Socket states that represent real traffic (not just listening/binding)
    _ACTIVE_STATES = frozenset({
        "ESTABLISHED", "SYN_SENT", "SYN_RECEIVED", "FIN_WAIT_1",
        "FIN_WAIT_2", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT",
    })

    def collect_data(self) -> Sequence[Any]:
        snapshot = self.collector.collect()

        # Filter: only store real connections as flow observations.
        # LISTEN/bind sockets are socket inventory, not traffic flows.
        # They inflate flow_events (55% blank dst_ip) and mask real patterns.
        all_conns = snapshot.get("connections", [])
        active_conns = [
            c for c in all_conns if c.state in self._ACTIVE_STATES
        ]

        # Build OBSERVATION events for active connections only
        obs_events = self._make_observation_events(
            active_conns,
            domain="flow",
            field_mapper=self._connection_to_obs,
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
                probe_name="macos_network_collector",
                data={
                    "connection_count": snapshot["connection_count"],
                    "collection_time_ms": snapshot["collection_time_ms"],
                    "observation_events": len(obs_events),
                    "probe_events": len(probe_events),
                },
            )
        )

        logger.info(
            "Network: %d connections (%d active, %d listen) in %.1fms, "
            "%d observations, %d probe events",
            snapshot["connection_count"],
            len(active_conns),
            len(all_conns) - len(active_conns),
            snapshot["collection_time_ms"],
            len(obs_events),
            len(probe_events),
        )

        if all_events:
            return [self._events_to_telemetry(all_events)]
        return []

    @staticmethod
    def _connection_to_obs(conn) -> Dict[str, Any]:
        """Map a Connection to observation data dict."""
        return {
            "src_ip": conn.local_ip,
            "dst_ip": conn.remote_ip,
            "src_port": str(conn.local_port),
            "dst_port": str(conn.remote_port),
            "protocol": conn.protocol,
            "process_name": conn.process_name,
            "pid": str(conn.pid),
            "conn_user": conn.user,
            "state": conn.state,
        }

    def _events_to_telemetry(self, events: List[TelemetryEvent]) -> Any:
        from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2

        timestamp_ns = int(time.time() * 1e9)
        proto_events = []

        for idx, event in enumerate(events):
            if event.event_type == "collection_metadata":
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"macos_network_meta_{timestamp_ns}",
                    event_type="METRIC",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="macos_network_collector",
                )
            elif event.event_type.startswith("obs_"):
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"macos_network_obs_{idx}_{timestamp_ns}",
                    event_type="OBSERVATION",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="flow_collector",
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
            protocol="MACOS_NETWORK",
            events=proto_events,
            timestamp_ns=timestamp_ns,
            collection_agent="macos_network",
            agent_version="2.0.0",
        )

    def validate_event(self, event: Any) -> ValidationResult:
        errors = []
        if not hasattr(event, "device_id") or not event.device_id:
            errors.append("Missing device_id")
        return ValidationResult(is_valid=len(errors) == 0, errors=errors)

    def shutdown(self) -> None:
        logger.info("MacOSNetworkAgent shutting down")


def main():
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    parser = argparse.ArgumentParser(description="AMOSKYS macOS Network Agent")
    parser.add_argument("--interval", type=float, default=10.0)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    agent = MacOSNetworkAgent(collection_interval=args.interval)
    try:
        agent.run()
    except KeyboardInterrupt:
        agent.shutdown()


if __name__ == "__main__":
    main()
