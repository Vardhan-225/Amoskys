"""macOS Internet Activity Observatory Agent — network connection threat detection.

Monitors active internet connections via lsof -i with PID-to-process correlation for:
    - Cloud exfiltration (S3/GCS/Azure Blob endpoint detection)
    - TOR/VPN usage (exit node + VPN port detection)
    - Crypto mining (stratum pool port patterns)
    - Geo-anomaly (unusual IP range heuristics)
    - Long-lived connections (persistent non-CDN connections)
    - Data exfil timing (late-night + burst pattern detection)
    - Shadow IT (unauthorized cloud service usage)
    - CDN masquerade (C2 hiding behind CDN infrastructure)

Data flow:
    MacOSInternetActivityCollector.collect() → shared_data
    → 8 probes scan(context) → TelemetryEvent[]
    → _events_to_telemetry() → DeviceTelemetry
    → LocalQueueAdapter → EventBus
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
from amoskys.agents.os.macos.internet_activity.collector import (
    MacOSInternetActivityCollector,
)
from amoskys.agents.os.macos.internet_activity.probes import (
    create_internet_activity_probes,
)
from amoskys.config import get_config

logger = logging.getLogger(__name__)
config = get_config()
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = "data/queue/macos_internet_activity.db"


class MacOSInternetActivityAgent(MicroProbeAgentMixin, HardenedAgentBase):
    """macOS Internet Activity Observatory — 8 probes, 8 MITRE techniques.

    Probes:
        macos_internet_cloud_exfil    — T1567     Cloud storage exfiltration
        macos_internet_tor_vpn        — T1090.003 TOR/VPN usage
        macos_internet_crypto_mining  — T1496     Crypto mining detection
        macos_internet_geo_anomaly    — T1071     Geo-anomaly IP ranges
        macos_internet_long_lived     — T1571     Long-lived connections
        macos_internet_exfil_timing   — T1048     Data exfil timing
        macos_internet_shadow_it      — T1567.002 Shadow IT cloud services
        macos_internet_cdn_masquerade — T1090.002 CDN masquerade C2
    """

    MANDATE_DATA_FIELDS = ("remote_ip", "remote_port", "local_port", "protocol", "pid", "process_name")

    def __init__(self, collection_interval: float = 30.0) -> None:
        device_id = socket.gethostname()

        Path(QUEUE_PATH).parent.mkdir(parents=True, exist_ok=True)
        queue_adapter = LocalQueueAdapter(
            queue_path=QUEUE_PATH,
            agent_name="macos_internet_activity",
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,
            max_retries=10,
            signing_key_path=f"{CERT_DIR}/agent.ed25519",
        )

        super().__init__(
            agent_name="macos_internet_activity",
            device_id=device_id,
            collection_interval=collection_interval,
            queue_adapter=queue_adapter,
        )

        self.collector = MacOSInternetActivityCollector(device_id=device_id)
        self.register_probes(create_internet_activity_probes())

        logger.info(
            "MacOSInternetActivityAgent initialized: %d probes, device=%s",
            len(self._probes),
            device_id,
        )

    def setup(self) -> bool:
        """Verify macOS platform and lsof data source."""
        if platform.system() != "Darwin":
            logger.error("MacOSInternetActivityAgent requires macOS (Darwin)")
            return False

        # Verify lsof access
        try:
            import subprocess

            result = subprocess.run(
                ["lsof", "-i", "-n", "-P"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode in (0, 1):
                logger.info("lsof OK: network connections accessible")
            else:
                logger.warning("lsof degraded: returncode=%d", result.returncode)
        except Exception as e:
            logger.warning("lsof check failed: %s", e)

        if not self.setup_probes(
            collector_shared_data_keys=[
                "connections",
                "connection_count",
                "unique_remote_ips",
                "unique_processes",
                "collection_time_ms",
            ]
        ):
            logger.error("No probes initialized")
            return False

        logger.info("MacOSInternetActivityAgent setup complete — 8 probes active")
        return True

    def enrich_event(self, event: Any) -> Any:
        """Auto-enrich detection events with full process context from PID.

        Probes emit pid from lsof but not exe/cmdline/ppid/parent_name.
        This hook resolves the PID to full mandate-grade context for ALL
        probes without modifying each probe individually.
        """
        from amoskys.agents.common.process_resolver import mandate_context_from_pid

        if not hasattr(event, "data") or not isinstance(event.data, dict):
            return event

        data = event.data
        pid = data.get("pid")
        # Also check "pids" list for aggregate events
        if not pid and "pids" in data:
            pids = data["pids"]
            if isinstance(pids, (list, set)) and pids:
                pid = next(iter(sorted(pids)), 0)

        if not pid:
            return event

        # Only enrich if exe is missing (don't overwrite existing context)
        if data.get("exe") and data["exe"] not in ("", "UNRESOLVED", "EXITED"):
            return event

        ctx = mandate_context_from_pid(
            int(pid),
            probe_name=data.get("probe_name", "internet_activity"),
            process_name_hint=data.get("process_name", ""),
            detection_source="lsof",
        )
        # Merge without overwriting existing non-empty fields
        for k, v in ctx.items():
            if k not in data or data[k] is None or data[k] == "":
                data[k] = v

        return event

    def collect_data(self) -> Sequence[Any]:
        """Run connection collector + probes, emit raw observations + detections."""
        snapshot = self.collector.collect()

        # Build OBSERVATION events for every raw connection
        obs_events = self._make_observation_events(
            snapshot.get("connections", []),
            domain="internet_activity",
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
                probe_name="macos_internet_activity_collector",
                data={
                    "connection_count": snapshot["connection_count"],
                    "unique_remote_ips": snapshot["unique_remote_ips"],
                    "unique_processes": snapshot["unique_processes"],
                    "collection_time_ms": snapshot["collection_time_ms"],
                    "observation_events": len(obs_events),
                    "probe_events": len(probe_events),
                },
            )
        )

        logger.info(
            "Internet activity collected in %.1fms: %d connections, %d unique IPs, "
            "%d unique processes, %d observations, %d probe events",
            snapshot["collection_time_ms"],
            snapshot["connection_count"],
            snapshot["unique_remote_ips"],
            snapshot["unique_processes"],
            len(obs_events),
            len(probe_events),
        )

        if all_events:
            return [self._events_to_telemetry(all_events)]
        return []

    @staticmethod
    def _connection_to_obs(conn) -> Dict[str, Any]:
        """Map an InternetConnection to observation data dict."""
        return {
            "pid": str(conn.pid),
            "process_name": conn.process_name,
            "user": conn.user,
            "protocol": conn.protocol,
            "local_addr": conn.local_addr,
            "local_port": str(conn.local_port),
            "remote_addr": conn.remote_addr,
            "remote_port": str(conn.remote_port),
            "state": conn.state,
            "direction": conn.direction,
            "duration_estimate_s": str(conn.duration_estimate_s),
        }

    def _events_to_telemetry(self, events: List[TelemetryEvent]) -> Any:
        """Convert TelemetryEvents to protobuf DeviceTelemetry."""
        from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2

        timestamp_ns = int(time.time() * 1e9)
        proto_events = []

        for idx, event in enumerate(events):
            if event.event_type == "collection_metadata":
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"macos_internet_activity_meta_{timestamp_ns}",
                    event_type="METRIC",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="macos_internet_activity_collector",
                    metric_data=telemetry_pb2.MetricData(
                        metric_name="internet_activity_collection",
                        metric_type="GAUGE",
                        numeric_value=float(event.data.get("connection_count", 0)),
                        unit="connections",
                    ),
                )
            elif event.event_type.startswith("obs_"):
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"macos_internet_activity_obs_{idx}_{timestamp_ns}",
                    event_type="OBSERVATION",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="internet_activity_collector",
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
            protocol="MACOS_INTERNET_ACTIVITY",
            events=proto_events,
            timestamp_ns=timestamp_ns,
            collection_agent="macos_internet_activity",
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
        logger.info("MacOSInternetActivityAgent shutting down")
