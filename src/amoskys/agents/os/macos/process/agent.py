"""macOS Process Agent — Process Observatory for Darwin.

Purpose-built process monitoring agent for macOS. Uses the AMOSKYS canonical
agent pattern (MicroProbeAgentMixin + HardenedAgentBase) with a macOS-specific
collector and 10 detection probes.

Data flow:
    1. MacOSProcessCollector.collect() → process snapshots (psutil)
    2. Probes.scan(context) → TelemetryEvents (detections)
    3. Agent converts events → DeviceTelemetry protobuf
    4. LocalQueueAdapter → WAL → EventBus

Ground truth: 652 processes, 398 own-user, 60.8% cmdline, 5ms collection,
0 false positives (after AppTranslocation + permission fixes).

Usage:
    agent = MacOSProcessAgent()
    agent.run()  # Enters main loop
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
from amoskys.agents.os.macos.process.collector import MacOSProcessCollector
from amoskys.agents.os.macos.process.probes import create_process_probes
from amoskys.config import get_config

logger = logging.getLogger(__name__)

config = get_config()
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = "data/queue/macos_process.db"


class MacOSProcessAgent(MicroProbeAgentMixin, HardenedAgentBase):
    """macOS Process Observatory agent.

    Monitors all process activity on macOS via psutil with 10 detection probes.
    Aware of macOS permission boundaries (uid=501: own-user detail only).

    Probes:
        1. macos_process_spawn — new process creation
        2. macos_lolbin — living-off-the-land binary abuse
        3. macos_process_tree — anomalous parent-child relationships
        4. macos_resource_abuse — CPU/memory abuse
        5. macos_dylib_injection — DYLD_INSERT_LIBRARIES
        6. macos_code_signing — unsigned/tampered binaries
        7. macos_script_interpreter — suspicious script patterns
        8. macos_binary_from_temp — execution from temp paths
        9. macos_suspicious_user — wrong user for process
       10. macos_process_masquerade — name vs exe mismatch
    """

    def __init__(self, collection_interval: float = 10.0) -> None:
        device_id = socket.gethostname()

        # Local queue for offline resilience
        Path(QUEUE_PATH).parent.mkdir(parents=True, exist_ok=True)
        queue_adapter = LocalQueueAdapter(
            queue_path=QUEUE_PATH,
            agent_name="macos_process",
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,
            max_retries=10,
            signing_key_path=f"{CERT_DIR}/agent.ed25519",
        )

        super().__init__(
            agent_name="macos_process",
            device_id=device_id,
            collection_interval=collection_interval,
            queue_adapter=queue_adapter,
        )

        self.collector = MacOSProcessCollector(device_id=device_id)
        self.register_probes(create_process_probes())
        # Coordination bus is now initialized in HardenedAgentBase.__init__()

        logger.info(
            "MacOSProcessAgent initialized: %d probes, device=%s",
            len(self._probes),
            device_id,
        )

    def setup(self) -> bool:
        """Verify macOS platform, psutil, and initialize probes."""
        if platform.system() != "Darwin":
            logger.error("MacOSProcessAgent requires macOS (Darwin)")
            return False

        # Verify psutil works
        try:
            import psutil

            count = len(list(psutil.process_iter(["pid"])))
            logger.info("psutil OK: %d processes visible", count)
        except Exception as e:
            logger.error("psutil verification failed: %s", e)
            return False

        # Setup probes with collector's shared_data keys
        if not self.setup_probes(
            collector_shared_data_keys=[
                "processes",
                "own_user_count",
                "total_count",
                "collection_time_ms",
            ]
        ):
            logger.error("No probes initialized")
            return False

        logger.info("MacOSProcessAgent setup complete")
        return True

    def collect_data(self) -> Sequence[Any]:
        """Run collector + probes, emit raw observations + detections."""
        # Step 1: Collect process snapshot
        snapshot = self.collector.collect()

        # Step 2: Build OBSERVATION events for every raw process
        obs_events = self._make_observation_events(
            snapshot["processes"],
            domain="process",
            field_mapper=self._process_to_obs,
        )

        # Step 2.5: Tactical watch — emit enriched detail for watched PIDs
        watched_pids = self.active_watch_pids
        tactical_events = []
        if watched_pids:
            for proc in snapshot["processes"]:
                pid_str = str(proc.pid)
                if pid_str in watched_pids:
                    obs = self._process_to_obs(proc)
                    obs["tactical_watch"] = "true"
                    obs["watch_reason"] = self._get_watch_reason("WATCH_PID", pid_str)
                    # Include child processes of watched PIDs
                    children = [
                        p for p in snapshot["processes"] if str(p.ppid) == pid_str
                    ]
                    obs["child_pids"] = ",".join(str(c.pid) for c in children)
                    obs["child_count"] = str(len(children))
                    tactical_events.append(
                        TelemetryEvent(
                            event_type="obs_tactical_process",
                            severity=Severity.MEDIUM,
                            probe_name="tactical_watch_process",
                            data=obs,
                            tags=["tactical_watch", "watch_pid"],
                        )
                    )
            if tactical_events:
                logger.info(
                    "Tactical: %d processes under watch (%d watched PIDs)",
                    len(tactical_events),
                    len(watched_pids),
                )

        # Step 3: Run probes (unchanged — detection events)
        context = self._create_probe_context()
        context.shared_data = snapshot
        probe_events = self.run_probes(context)

        # Step 4: Combine observations + tactical + probe detections + metadata
        all_events = obs_events + tactical_events + probe_events
        all_events.append(
            TelemetryEvent(
                event_type="collection_metadata",
                severity=Severity.DEBUG,
                probe_name="macos_process_collector",
                data={
                    "total_processes": snapshot["total_count"],
                    "own_user_processes": snapshot["own_user_count"],
                    "collection_time_ms": snapshot["collection_time_ms"],
                    "probe_events": len(probe_events),
                    "observation_events": len(obs_events),
                    "tactical_events": len(tactical_events),
                    "watched_pids": len(watched_pids),
                },
            )
        )

        logger.info(
            "Collected: %d processes (%d own-user) in %.1fms, "
            "%d observations, %d tactical, %d probe events",
            snapshot["total_count"],
            snapshot["own_user_count"],
            snapshot["collection_time_ms"],
            len(obs_events),
            len(tactical_events),
            len(probe_events),
        )

        # Step 5: Convert to protobuf
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

    # Coordination methods (init, health, alert, control, shutdown) inherited
    # from HardenedAgentBase — all 20 agents get them automatically.

    @staticmethod
    def _process_to_obs(proc) -> Dict[str, Any]:
        """Map a ProcessSnapshot to observation data dict."""
        return {
            "pid": str(proc.pid),
            "name": proc.name,
            "exe": proc.exe,
            "cmdline": json.dumps(proc.cmdline) if proc.cmdline else "",
            "username": proc.username,
            "ppid": str(proc.ppid),
            "parent_name": proc.parent_name,
            "create_time": str(proc.create_time),
            "cpu_percent": (
                str(proc.cpu_percent) if proc.cpu_percent is not None else ""
            ),
            "memory_percent": (
                str(proc.memory_percent) if proc.memory_percent is not None else ""
            ),
            "num_threads": proc.num_threads if proc.num_threads is not None else 0,
            "num_fds": proc.num_fds if proc.num_fds is not None else 0,
            "status": proc.status,
            "cwd": proc.cwd,
            "is_own_user": str(proc.is_own_user),
            "process_guid": proc.process_guid,
        }

    def _events_to_telemetry(self, events: List[TelemetryEvent]) -> Any:
        """Convert TelemetryEvents to protobuf DeviceTelemetry."""
        from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2

        timestamp_ns = int(time.time() * 1e9)
        proto_events = []

        for idx, event in enumerate(events):
            if event.event_type == "collection_metadata":
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"macos_process_meta_{timestamp_ns}",
                    event_type="METRIC",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="macos_process_collector",
                    metric_data=telemetry_pb2.MetricData(
                        metric_name="process_collection",
                        metric_type="GAUGE",
                        numeric_value=float(event.data.get("total_processes", 0)),
                        unit="processes",
                    ),
                )
            elif event.event_type.startswith("obs_"):
                # Raw observation — no SecurityEvent sub-message
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"macos_process_obs_{idx}_{timestamp_ns}",
                    event_type="OBSERVATION",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="process_collector",
                    confidence_score=0.0,
                )
                for k, v in event.data.items():
                    proto_event.attributes[k] = str(v)
            else:
                # Probe detection — SecurityEvent
                security_event = telemetry_pb2.SecurityEvent(
                    event_category=event.event_type,
                    risk_score=event.confidence,
                    analyst_notes=str(event.data),
                )
                if event.mitre_techniques:
                    security_event.mitre_techniques.extend(event.mitre_techniques)

                source_ip = event.data.get("source_ip")
                if source_ip:
                    security_event.source_ip = str(source_ip)

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
            protocol="MACOS_PROCESS",
            events=proto_events,
            timestamp_ns=timestamp_ns,
            collection_agent="macos_process",
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
        logger.info("MacOSProcessAgent shutting down")


# =============================================================================
# CLI Entry Point
# =============================================================================


def main():
    """Run macOS Process Agent."""
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    parser = argparse.ArgumentParser(description="AMOSKYS macOS Process Agent")
    parser.add_argument("--interval", type=float, default=10.0)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info("=" * 60)
    logger.info("AMOSKYS macOS Process Observatory")
    logger.info("=" * 60)

    agent = MacOSProcessAgent(collection_interval=args.interval)
    try:
        agent.run()
    except KeyboardInterrupt:
        agent.shutdown()


if __name__ == "__main__":
    main()
