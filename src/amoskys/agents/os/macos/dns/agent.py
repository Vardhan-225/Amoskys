"""macOS DNS Observatory Agent — DNS threat detection via Unified Logging.

Monitors mDNSResponder queries and DNS configuration for:
    - DGA domain detection (entropy + n-gram analysis)
    - DNS tunneling (long labels, TXT floods, base64 encoding)
    - C2 beaconing (periodic query patterns)
    - Cache poisoning indicators (TTL anomalies)
    - DNS-over-HTTPS bypass detection
    - First-seen domain baseline-diff
    - Fast-flux IP rotation
    - Reverse DNS reconnaissance

Data flow:
    MacOSDNSCollector.collect() → shared_data
    → 8 probes scan(context) → TelemetryEvent[]
    → _events_to_telemetry() → DeviceTelemetry
    → LocalQueueAdapter → EventBus
"""

from __future__ import annotations

import json
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
from amoskys.agents.os.macos.dns.collector import MacOSDNSCollector
from amoskys.agents.os.macos.dns.probes import create_dns_probes
from amoskys.config import get_config

logger = logging.getLogger(__name__)
config = get_config()
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = "data/queue/macos_dns.db"


class MacOSDNSAgent(MicroProbeAgentMixin, HardenedAgentBase):
    """macOS DNS Observatory — 8 probes, 8 MITRE techniques.

    Probes:
        macos_dns_dga           — T1568.002 DGA detection
        macos_dns_tunneling     — T1071.004 DNS tunneling
        macos_dns_beaconing     — T1071.004 C2 beaconing
        macos_dns_cache_poison  — T1557.002 Cache poisoning
        macos_dns_doh           — T1572     DoH bypass
        macos_dns_new_domain    — T1583     First-seen domains
        macos_dns_fast_flux     — T1568.001 Fast-flux DNS
        macos_dns_reverse_recon — T1046     Reverse DNS recon
    """

    def __init__(self, collection_interval: float = 30.0) -> None:
        device_id = socket.gethostname()

        Path(QUEUE_PATH).parent.mkdir(parents=True, exist_ok=True)
        queue_adapter = LocalQueueAdapter(
            queue_path=QUEUE_PATH,
            agent_name="macos_dns",
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,
            max_retries=10,
            signing_key_path=f"{CERT_DIR}/agent.ed25519",
        )

        super().__init__(
            agent_name="macos_dns",
            device_id=device_id,
            collection_interval=collection_interval,
            queue_adapter=queue_adapter,
        )

        self.collector = MacOSDNSCollector(device_id=device_id)
        self.register_probes(create_dns_probes())

        logger.info(
            "MacOSDNSAgent initialized: %d probes, device=%s",
            len(self._probes),
            device_id,
        )

    def setup(self) -> bool:
        """Verify macOS platform and DNS data sources."""
        if platform.system() != "Darwin":
            logger.error("MacOSDNSAgent requires macOS (Darwin)")
            return False

        # Verify Unified Logging access
        try:
            import subprocess

            result = subprocess.run(
                [
                    "log",
                    "show",
                    "--predicate",
                    'process == "mDNSResponder"',
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
                logger.info("Unified Logging OK: mDNSResponder accessible")
            else:
                logger.warning(
                    "Unified Logging degraded: returncode=%d", result.returncode
                )
        except Exception as e:
            logger.warning("Unified Logging check failed: %s", e)

        # Verify scutil
        try:
            import subprocess

            result = subprocess.run(
                ["scutil", "--dns"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if result.returncode == 0:
                logger.info("scutil OK: DNS config accessible")
        except Exception as e:
            logger.warning("scutil check failed: %s", e)

        if not self.setup_probes(
            collector_shared_data_keys=[
                "dns_queries",
                "dns_servers",
                "search_domains",
                "query_count",
                "unique_domains",
                "collection_time_ms",
            ]
        ):
            logger.error("No probes initialized")
            return False

        logger.info("MacOSDNSAgent setup complete — 8 probes active")
        return True

    def collect_data(self) -> Sequence[Any]:
        """Run DNS collector + probes, emit raw observations + detections."""
        snapshot = self.collector.collect()

        # Build OBSERVATION events for every raw DNS query
        obs_events = self._make_observation_events(
            snapshot.get("dns_queries", []),
            domain="dns",
            field_mapper=self._dns_to_obs,
        )

        # --- Tactical watch: tag DNS queries from watched PIDs ---
        watched_pids = self.active_watch_pids
        tactical_events = []
        if watched_pids:
            for query in snapshot.get("dns_queries", []):
                if str(getattr(query, "source_pid", "")) in watched_pids:
                    obs = self._dns_to_obs(query)
                    obs["tactical_watch"] = "true"
                    obs["watch_reason"] = self._get_watch_reason(
                        "WATCH_PID", str(query.source_pid)
                    )
                    tactical_events.append(
                        TelemetryEvent(
                            event_type="obs_tactical_dns",
                            severity=Severity.MEDIUM,
                            probe_name="tactical_watch_dns",
                            data=obs,
                            tags=["tactical_watch", "watch_pid"],
                        )
                    )
            if tactical_events:
                logger.info(
                    "Tactical: %d DNS queries from watched PIDs",
                    len(tactical_events),
                )

        # Run probes (detection events, unchanged)
        context = self._create_probe_context()
        context.shared_data = snapshot
        probe_events = self.run_probes(context)

        all_events = obs_events + tactical_events + probe_events
        all_events.append(
            TelemetryEvent(
                event_type="collection_metadata",
                severity=Severity.DEBUG,
                probe_name="macos_dns_collector",
                data={
                    "query_count": snapshot["query_count"],
                    "unique_domains": snapshot["unique_domains"],
                    "collection_time_ms": snapshot["collection_time_ms"],
                    "observation_events": len(obs_events),
                    "tactical_events": len(tactical_events),
                    "probe_events": len(probe_events),
                    "watched_pids": len(watched_pids),
                },
            )
        )

        logger.info(
            "DNS collected in %.1fms: %d queries, %d unique, "
            "%d observations, %d tactical, %d probe events",
            snapshot["collection_time_ms"],
            snapshot["query_count"],
            snapshot["unique_domains"],
            len(obs_events),
            len(tactical_events),
            len(probe_events),
        )

        if all_events:
            return [self._events_to_telemetry(all_events)]
        return []

    def _get_watch_reason(self, topic: str, value: str) -> str:
        """Get the reason string for a watch directive."""
        with self._watch_lock:
            store = {
                "WATCH_PID": self._watch_pids,
                "WATCH_PATH": self._watch_paths,
                "WATCH_DOMAIN": self._watch_domains,
            }.get(topic, {})
            directive = store.get(value)
            return directive.reason if directive else "unknown"

    @staticmethod
    def _dns_to_obs(query) -> Dict[str, Any]:
        """Map a DNSQuery to observation data dict."""
        return {
            "domain": query.domain,
            "query_type": query.record_type,
            "response_code": query.response_code,
            "response_ips": (
                json.dumps(query.response_ips) if query.response_ips else "[]"
            ),
            "ttl": str(query.ttl),
            "source_process": query.source_process,
            "source_pid": str(query.source_pid),
            "response_size": str(query.response_size),
            "is_reverse": str(query.is_reverse),
            "timestamp": str(query.timestamp),
        }

    def _events_to_telemetry(self, events: List[TelemetryEvent]) -> Any:
        """Convert TelemetryEvents to protobuf DeviceTelemetry."""
        from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2

        timestamp_ns = int(time.time() * 1e9)
        proto_events = []

        for idx, event in enumerate(events):
            if event.event_type == "collection_metadata":
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"macos_dns_meta_{timestamp_ns}",
                    event_type="METRIC",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="macos_dns_collector",
                    metric_data=telemetry_pb2.MetricData(
                        metric_name="dns_collection",
                        metric_type="GAUGE",
                        numeric_value=float(event.data.get("query_count", 0)),
                        unit="queries",
                    ),
                )
            elif event.event_type.startswith("obs_"):
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"macos_dns_obs_{idx}_{timestamp_ns}",
                    event_type="OBSERVATION",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="dns_collector",
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
            protocol="MACOS_DNS",
            events=proto_events,
            timestamp_ns=timestamp_ns,
            collection_agent="macos_dns",
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
        logger.info("MacOSDNSAgent shutting down")


def main():
    """Run macOS DNS Agent."""
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    parser = argparse.ArgumentParser(description="AMOSKYS macOS DNS Agent")
    parser.add_argument("--interval", type=float, default=30.0)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info("=" * 60)
    logger.info("AMOSKYS macOS DNS Observatory")
    logger.info("=" * 60)

    agent = MacOSDNSAgent(collection_interval=args.interval)
    try:
        agent.run()
    except KeyboardInterrupt:
        agent.shutdown()


if __name__ == "__main__":
    main()
