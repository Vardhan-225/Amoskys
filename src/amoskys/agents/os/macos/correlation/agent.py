"""macOS Correlation Agent — Cross-Agent Intelligence Layer for Darwin.

The 8th macOS Observatory agent. Aggregates data from all 7 domain collectors
and runs 18 correlation probes (12 snapshot + 6 temporal) that detect
cross-domain attack patterns invisible to any single agent.

Data flow:
    1. CorrelationCollector.collect() → merged data from all 7 domains
    2. 12 Snapshot probes scan cross-domain patterns
    3. 6 Temporal probes analyze timestamps for sequences and timing
    4. TelemetryEvents → DeviceTelemetry protobuf → LocalQueueAdapter → WAL

Snapshot probes close 17 of 22 fixable evasion gaps from the Evasion Gauntlet.
Temporal probes close 11 additional gaps (T1-T4, E2, E5, F1-F3, S1-S5, ab2).

Usage:
    agent = MacOSCorrelationAgent()
    agent.run()
"""

from __future__ import annotations

import logging
import platform
import socket
import time
from pathlib import Path
from typing import Any, Dict, List, Sequence

from amoskys.agents.common.agent_bus import ThreatContext, get_agent_bus
from amoskys.agents.common.base import HardenedAgentBase, ValidationResult
from amoskys.agents.common.kill_chain import TACTIC_TO_STAGE, KillChainTracker
from amoskys.agents.common.probes import (
    MicroProbeAgentMixin,
    ProbeContext,
    Severity,
    TelemetryEvent,
)
from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.agents.os.macos.correlation.collector import CorrelationCollector
from amoskys.agents.os.macos.correlation.probes import create_correlation_probes
from amoskys.agents.os.macos.correlation.temporal_probes import create_temporal_probes
from amoskys.config import get_config

logger = logging.getLogger(__name__)

config = get_config()
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = "data/queue/macos_correlation.db"


class MacOSCorrelationAgent(MicroProbeAgentMixin, HardenedAgentBase):
    """macOS Cross-Agent Correlation Observatory.

    Aggregates data from all 7 macOS domain agents (process, network,
    persistence, filesystem, auth, unified_log, peripheral) and runs
    12 correlation probes that detect cross-domain attack patterns.

    Probes:
        1. macos_corr_process_network — LOLBin + outbound = confirmed
        2. macos_corr_binary_identity — name vs exe path mismatch
        3. macos_corr_persistence_execution — installed + running
        4. macos_corr_download_execute — download → execute → connect
        5. macos_corr_lateral_movement — expanded lateral ports
        6. macos_corr_unknown_listener — unexpected open ports
        7. macos_corr_cumulative_auth — rolling brute force
        8. macos_corr_cumulative_exfil — rolling exfil
        9. macos_corr_kill_chain — multi-tactic progression
       10. macos_corr_file_size_anomaly — benign name, bad size
       11. macos_corr_scheduled_persistence — at-job/periodic/emond
       12. macos_corr_auth_geo_anomaly — new source IP
    """

    def __init__(self, collection_interval: float = 15.0) -> None:
        device_id = socket.gethostname()

        Path(QUEUE_PATH).parent.mkdir(parents=True, exist_ok=True)
        queue_adapter = LocalQueueAdapter(
            queue_path=QUEUE_PATH,
            agent_name="macos_correlation",
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,
            max_retries=10,
            signing_key_path=f"{CERT_DIR}/agent.ed25519",
        )

        super().__init__(
            agent_name="macos_correlation",
            device_id=device_id,
            collection_interval=collection_interval,
            queue_adapter=queue_adapter,
        )

        self.collector = CorrelationCollector(device_id=device_id)
        self.register_probes(create_correlation_probes())
        self.register_probes(create_temporal_probes())

        # Wave 2: AgentBus + Kill-Chain integration
        self._agent_bus = get_agent_bus()
        self._kill_chain = KillChainTracker(ttl_seconds=3600.0)

        logger.info(
            "MacOSCorrelationAgent initialized: %d probes (%d snapshot + %d temporal), device=%s, agent_bus=connected",
            len(self._probes),
            12,
            6,
            device_id,
        )

    def setup(self) -> bool:
        """Verify macOS platform and initialize probes."""
        if platform.system() != "Darwin":
            logger.error("MacOSCorrelationAgent requires macOS (Darwin)")
            return False

        # Setup probes — correlation probes read from merged shared_data
        if not self.setup_probes(
            collector_shared_data_keys=[
                "processes",
                "connections",
                "bandwidth",
                "entries",
                "files",
                "suid_binaries",
                "sip_status",
                "auth_events",
                "log_entries",
                "usb_devices",
                "bluetooth_devices",
                "volumes",
                "pid_map",
                "pid_connections",
                "pid_bandwidth",
                "name_to_exe",
                "rolling",
                "collection_ts",
            ]
        ):
            logger.error("No correlation probes initialized")
            return False

        logger.info("MacOSCorrelationAgent setup complete")
        return True

    def collect_data(self) -> Sequence[Any]:
        """Run all 7 collectors + correlation probes, return DeviceTelemetry.

        Enhanced with AgentBus: reads peer threat contexts and alerts from
        other agents, injects them into the probe context, and feeds the
        kill-chain tracker with detected MITRE tactics.
        """
        # Step 1: Collect from all 7 domains (merged)
        snapshot = self.collector.collect()

        # Step 2: Enrich with AgentBus data (peer contexts + alerts)
        peer_contexts = self._agent_bus.get_all_contexts()
        peer_alerts = self._agent_bus.get_alerts(
            since_ns=int((time.time() - self.collection_interval) * 1e9)
        )
        snapshot["peer_contexts"] = peer_contexts
        snapshot["peer_alerts"] = peer_alerts
        snapshot["kill_chain"] = self._kill_chain

        # Step 3: Build probe context with merged + enriched data
        context = self._create_probe_context()
        context.shared_data = snapshot

        # Step 4: Run correlation probes
        events = self.run_probes(context)

        # Step 5: Feed kill-chain tracker with detected events
        for event in events:
            if event.event_type == "collection_metadata":
                continue
            for tactic in event.mitre_tactics or []:
                self._kill_chain.record_from_tactic(
                    device_id=self.device_id,
                    mitre_tactic=tactic,
                    agent_name="macos_correlation",
                    event_type=event.event_type,
                    mitre_technique=(event.mitre_techniques or [""])[0],
                    confidence=event.confidence,
                )

        # Step 6: Post our threat context to AgentBus for other agents
        active_pids = set()
        suspicious_ips = set()
        active_techniques = set()
        for event in events:
            if event.event_type == "collection_metadata":
                continue
            pid = event.data.get("pid")
            if pid:
                active_pids.add(int(pid))
            for ip_key in ("remote_ip", "source_ip", "remote_addr"):
                ip = event.data.get(ip_key)
                if ip:
                    suspicious_ips.add(str(ip))
            active_techniques.update(event.mitre_techniques or [])

        self._agent_bus.post_context(
            "macos_correlation",
            ThreatContext(
                agent_name="macos_correlation",
                timestamp_ns=int(time.time() * 1e9),
                active_pids=active_pids,
                suspicious_ips=suspicious_ips,
                persistence_paths=set(),
                active_techniques=active_techniques,
                risk_indicators={
                    "correlation_events": float(len(events) - 1),
                    "kill_chain_stages": float(
                        self._kill_chain.get_progression(self.device_id).stages_reached
                        if self._kill_chain.get_progression(self.device_id)
                        else 0
                    ),
                },
            ),
        )

        # Step 7: Add collection metadata (include AgentBus stats)
        kill_chain_state = self._kill_chain.get_progression(self.device_id)
        events.append(
            TelemetryEvent(
                event_type="collection_metadata",
                severity=Severity.DEBUG,
                probe_name="macos_correlation_collector",
                data={
                    "total_processes": snapshot.get("total_count", 0),
                    "total_connections": snapshot.get("connection_count", 0),
                    "total_entries": len(snapshot.get("entries", [])),
                    "total_files": len(snapshot.get("files", [])),
                    "total_auth_events": len(snapshot.get("auth_events", [])),
                    "correlation_events": len(events),
                    "collection_time_ms": snapshot.get(
                        "correlation_collection_time_ms", 0
                    ),
                    "peer_contexts_count": len(peer_contexts),
                    "peer_alerts_count": len(peer_alerts),
                    "kill_chain_stages": (
                        kill_chain_state.stages_reached if kill_chain_state else 0
                    ),
                },
            )
        )

        logger.info(
            "Correlation: %d events from merged data "
            "(procs=%d, conns=%d, persist=%d, peers=%d, alerts=%d) in %.1fms",
            len(events) - 1,
            snapshot.get("total_count", 0),
            snapshot.get("connection_count", 0),
            len(snapshot.get("entries", [])),
            len(peer_contexts),
            len(peer_alerts),
            snapshot.get("correlation_collection_time_ms", 0),
        )

        if events:
            return [self._events_to_telemetry(events)]
        return []

    def _events_to_telemetry(self, events: List[TelemetryEvent]) -> Any:
        """Convert TelemetryEvents to protobuf DeviceTelemetry."""
        from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2

        timestamp_ns = int(time.time() * 1e9)
        proto_events = []

        for event in events:
            if event.event_type == "collection_metadata":
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"macos_corr_meta_{timestamp_ns}",
                    event_type="METRIC",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="macos_correlation_collector",
                    metric_data=telemetry_pb2.MetricData(
                        metric_name="correlation_collection",
                        metric_type="GAUGE",
                        numeric_value=float(event.data.get("correlation_events", 0)),
                        unit="events",
                    ),
                )
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
            protocol="MACOS_CORRELATION",
            events=proto_events,
            timestamp_ns=timestamp_ns,
            collection_agent="macos_correlation",
            agent_version="1.0.0",
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
        logger.info("MacOSCorrelationAgent shutting down")


# =============================================================================
# CLI Entry Point
# =============================================================================


def main():
    """Run macOS Correlation Agent."""
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    parser = argparse.ArgumentParser(description="AMOSKYS macOS Correlation Agent")
    parser.add_argument("--interval", type=float, default=15.0)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info("=" * 60)
    logger.info("AMOSKYS macOS Correlation Observatory")
    logger.info("=" * 60)

    agent = MacOSCorrelationAgent(collection_interval=args.interval)
    try:
        agent.run()
    except KeyboardInterrupt:
        agent.shutdown()


if __name__ == "__main__":
    main()
