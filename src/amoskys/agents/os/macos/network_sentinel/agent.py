#!/usr/bin/env python3
"""NetworkSentinel Agent — The Missing Predator.

Built because 17,273 malicious requests from Kali Linux hit the AMOSKYS
dashboard and zero were detected. This agent tails the web access logs,
snapshots connection state, and runs 10 aggressive probes that catch:

    - Mass path enumeration (nmap, nikto)
    - Directory brute-forcing (gobuster, dirsearch)
    - SQL injection payloads
    - XSS payloads
    - Directory traversal attacks
    - Known attack tool signatures
    - Rate anomalies (100+ req/min from one IP)
    - Admin/config path enumeration
    - Credential spraying (mass 401/403)
    - Connection floods (50+ connections from one IP)

Every detection flows through the same pipeline as all other agents:
    Ed25519 sign → BLAKE2b hash chain → WAL → enrichment → dashboard

No request escapes. Not one.
"""

from __future__ import annotations

import logging
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from pathlib import Path
from typing import Any, Dict, List, Sequence

from amoskys.agents.common.base import HardenedAgentBase, ValidationResult
from amoskys.agents.common.probes import MicroProbeAgentMixin, TelemetryEvent
from amoskys.agents.os.macos.network_sentinel.collector import (
    AccessLogCollector,
    ConnectionStateCollector,
)
from amoskys.agents.os.macos.network_sentinel.probes import (
    create_network_sentinel_probes,
)
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2

logger = logging.getLogger("NetworkSentinel")


class NetworkSentinelAgent(MicroProbeAgentMixin, HardenedAgentBase):
    """NetworkSentinel Agent — 10 eyes on every HTTP request and connection.

    Two collectors feed 10 probes:
        1. AccessLogCollector   → tails AMOSKYS web logs
        2. ConnectionStateCollector → lsof connection snapshot

    Probes analyze aggregate behavior (not just individual requests).
    A single XSS probe catches one payload. HTTPScanStormProbe catches
    the pattern of 10,000 payloads from one IP.
    """

    COLOR = "#FF4444"  # Red — this agent is the alarm

    QUEUE_PATH = "data/queue/network_sentinel.db"
    CERT_DIR = "certs"

    MANDATE_DATA_FIELDS = ("remote_ip", "remote_port", "local_port", "protocol", "pid", "process_name")

    def __init__(
        self,
        collection_interval: float = 10.0,
        log_paths: list | None = None,
    ):
        device_id = socket.gethostname()

        # Create local queue — no agent should ever run without one
        Path(self.QUEUE_PATH).parent.mkdir(parents=True, exist_ok=True)
        from amoskys.agents.common.queue_adapter import LocalQueueAdapter

        queue_adapter = LocalQueueAdapter(
            queue_path=self.QUEUE_PATH,
            agent_name="network_sentinel",
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,
            max_retries=10,
            signing_key_path=f"{self.CERT_DIR}/agent.ed25519",
        )

        super().__init__(
            agent_name="network_sentinel",
            device_id=device_id,
            collection_interval=collection_interval,
            queue_adapter=queue_adapter,
        )

        self.access_log_collector = AccessLogCollector(log_paths=log_paths)
        self.connection_collector = ConnectionStateCollector()
        self.register_probes(create_network_sentinel_probes())

        logger.info(
            "NetworkSentinel initialized: %d probes, %d log paths",
            len(self._probes),
            len(self.access_log_collector.log_paths),
        )

    def setup(self) -> bool:
        """Verify collectors work."""
        try:
            # Test access log collector
            test_txns = self.access_log_collector.collect()
            logger.info("Access log test: %d transactions", len(test_txns))

            # Test connection collector
            test_conns = self.connection_collector.collect()
            logger.info("Connection snapshot test: %d connections", len(test_conns))

            if not self.setup_probes(
                collector_shared_data_keys=["http_transactions", "connections"],
            ):
                logger.error("No probes initialized")
                return False

            logger.info("NetworkSentinel setup complete — hunting enabled")
            return True

        except Exception as e:
            logger.error("Setup failed: %s", e)
            return False

    def collect_data(self) -> Sequence[Any]:
        """Collect from both sources, run all 10 probes."""
        timestamp_ns = int(time.time() * 1e9)

        # Collect from both sources
        http_transactions = self.access_log_collector.collect()
        connections = self.connection_collector.collect()

        logger.info(
            "Collected %d HTTP transactions, %d connections",
            len(http_transactions),
            len(connections),
        )

        # Build probe context with both data sources
        context = self._create_probe_context()
        context.shared_data["http_transactions"] = http_transactions
        context.shared_data["connections"] = connections

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

        if events:
            logger.warning(
                "DETECTIONS: %d events from %d transactions + %d connections",
                len(events),
                len(http_transactions),
                len(connections),
            )
        else:
            logger.info(
                "Clean sweep: 0 events from %d transactions",
                len(http_transactions),
            )

        # Build protobuf events
        proto_events = []

        # Collection heartbeat — emitted as OBSERVATION so WAL routes it to
        # observation_events. Proves the agent is alive even when no attacks fire.
        heartbeat = telemetry_pb2.TelemetryEvent(
            event_id=f"sentinel_collection_{timestamp_ns}",
            event_type="OBSERVATION",
            severity="INFO",
            event_timestamp_ns=timestamp_ns,
            source_component="network_sentinel_collector",
            tags=["network_sentinel", "heartbeat"],
        )
        heartbeat.attributes["_domain"] = "network_sentinel"
        heartbeat.attributes["http_transactions"] = str(len(http_transactions))
        heartbeat.attributes["connections"] = str(len(connections))
        heartbeat.attributes["detections"] = str(len(events))
        proto_events.append(heartbeat)

        # Severity/risk mapping
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
                event_action="NETWORK_SENTINEL",
                risk_score=round(min(risk_score, 1.0), 3),
                analyst_notes=(
                    f"[{event.probe_name}] "
                    f"{event.data.get('verdict', event.event_type)}"
                ),
            )
            security_event.mitre_techniques.extend(event.mitre_techniques)

            attacker_ip = event.data.get("attacker_ip", "")
            if attacker_ip:
                security_event.target_resource = attacker_ip

            tel_event = telemetry_pb2.TelemetryEvent(
                event_id=f"{event.event_type}_{timestamp_ns}_{hash(attacker_ip) & 0xFFFF:04x}",
                event_type="SECURITY",
                severity=event.severity.value,
                event_timestamp_ns=timestamp_ns,
                source_component=event.probe_name or "network_sentinel",
                tags=list(event.tags) if event.tags else ["network_sentinel"],
                security_event=security_event,
                confidence_score=event.confidence,
            )

            if event.data:
                for key, value in event.data.items():
                    if value is not None:
                        tel_event.attributes[key] = str(value)

            proto_events.append(tel_event)

        telemetry = telemetry_pb2.DeviceTelemetry(
            device_id=self.device_id,
            device_type="HOST",
            protocol="HTTP",
            events=proto_events,
            timestamp_ns=timestamp_ns,
            collection_agent="network_sentinel",
            agent_version="1.0.0",
        )

        return [telemetry]

    def validate_event(self, event: Any) -> ValidationResult:
        errors = []
        if not hasattr(event, "device_id") or not event.device_id:
            errors.append("Missing device_id")
        if not hasattr(event, "timestamp_ns") or event.timestamp_ns <= 0:
            errors.append("Invalid timestamp_ns")
        return ValidationResult(is_valid=len(errors) == 0, errors=errors)

    def shutdown(self) -> None:
        logger.info("NetworkSentinel shutting down")

    def get_health(self) -> Dict[str, Any]:
        return {
            "agent_name": self.agent_name,
            "device_id": self.device_id,
            "is_running": self.is_running,
            "collection_count": self.collection_count,
            "error_count": self.error_count,
            "probes": self.get_probe_health(),
            "color": self.COLOR,
        }
