"""Correlation Collector — aggregates all 7 macOS domain collectors.

Builds a unified shared_data dict that correlation probes can query across
every observation domain simultaneously. Also builds cross-domain indexes
(PID→process, PID→connections, PID→bandwidth) and feeds the rolling
window aggregator for cumulative threshold tracking.

Data flow:
    7 domain collectors → merged shared_data dict → 12 correlation probes

The correlation collector does NOT modify any domain collector output.
It only READS and INDEXES the data, adding cross-domain join keys.
"""

from __future__ import annotations

import logging
import socket
import time
from collections import defaultdict
from typing import Any, Dict, List

from amoskys.agents.os.macos.correlation.rolling_window import RollingWindowAggregator

logger = logging.getLogger(__name__)


class CorrelationCollector:
    """Aggregates data from all 7 macOS Observatory collectors.

    Each collect() call runs all 7 domain collectors, builds cross-domain
    PID indexes, and feeds cumulative metrics into the rolling window.

    Attributes:
        rolling: RollingWindowAggregator tracking cumulative metrics across scans.
        device_id: Device identifier passed to collectors that need it.
    """

    def __init__(
        self,
        device_id: str = "",
        rolling_window_seconds: float = 300.0,
    ) -> None:
        self.device_id = device_id or socket.gethostname()
        self.rolling = RollingWindowAggregator(window_seconds=rolling_window_seconds)

        # Lazy-init collectors on first collect() — avoids import cost at module load
        self._collectors_initialized = False
        self._process_collector = None
        self._network_collector = None
        self._persistence_collector = None
        self._file_collector = None
        self._auth_collector = None
        self._log_collector = None
        self._peripheral_collector = None

    def _init_collectors(self) -> None:
        """Lazily initialize all 7 domain collectors."""
        from amoskys.agents.os.macos.auth.collector import MacOSAuthCollector
        from amoskys.agents.os.macos.filesystem.collector import MacOSFileCollector
        from amoskys.agents.os.macos.network.collector import MacOSNetworkCollector
        from amoskys.agents.os.macos.peripheral.collector import (
            MacOSPeripheralCollector,
        )
        from amoskys.agents.os.macos.persistence.collector import (
            MacOSPersistenceCollector,
        )
        from amoskys.agents.os.macos.process.collector import MacOSProcessCollector
        from amoskys.agents.os.macos.unified_log.collector import (
            MacOSUnifiedLogCollector,
        )

        self._process_collector = MacOSProcessCollector(device_id=self.device_id)
        self._network_collector = MacOSNetworkCollector(use_nettop=False)
        self._persistence_collector = MacOSPersistenceCollector()
        self._file_collector = MacOSFileCollector(device_id=self.device_id)
        self._auth_collector = MacOSAuthCollector(
            window_seconds=30,
            device_id=self.device_id,
        )
        self._log_collector = MacOSUnifiedLogCollector(lookback_seconds=60)
        self._peripheral_collector = MacOSPeripheralCollector()
        self._collectors_initialized = True
        logger.info("CorrelationCollector: all 7 domain collectors initialized")

    def collect(self) -> Dict[str, Any]:
        """Run all 7 domain collectors and merge into unified shared_data.

        Returns a dict with:
            - All domain collector keys (processes, connections, entries, etc.)
            - Cross-domain indexes (pid_map, pid_connections, pid_bandwidth)
            - Rolling window aggregator reference
            - Collection metadata
        """
        if not self._collectors_initialized:
            self._init_collectors()

        start = time.monotonic()

        # ── Collect from all 7 domains ────────────────────────────────────
        proc_data = self._safe_collect("process", self._process_collector)
        net_data = self._safe_collect("network", self._network_collector)
        pers_data = self._safe_collect("persistence", self._persistence_collector)
        fs_data = self._safe_collect("filesystem", self._file_collector)
        auth_data = self._safe_collect("auth", self._auth_collector)
        log_data = self._safe_collect("unified_log", self._log_collector)
        periph_data = self._safe_collect("peripheral", self._peripheral_collector)

        # ── Build cross-domain PID indexes ────────────────────────────────
        processes = proc_data.get("processes", [])
        connections = net_data.get("connections", [])
        bandwidth = net_data.get("bandwidth", [])

        # PID → ProcessSnapshot (for looking up process details from any domain)
        pid_map = {}
        for p in processes:
            pid_map[p.pid] = p

        # PID → List[Connection] (for checking network activity per process)
        pid_connections: Dict[int, List] = defaultdict(list)
        for conn in connections:
            pid_connections[conn.pid].append(conn)

        # PID → ProcessBandwidth (for checking data volume per process)
        pid_bandwidth = {}
        for bw in bandwidth:
            pid_bandwidth[bw.pid] = bw

        # Process name → exe path (for binary identity validation)
        name_to_exe: Dict[str, str] = {}
        for p in processes:
            if p.exe:
                name_to_exe[p.name.lower()] = p.exe

        # ── Feed rolling window with cumulative metrics ───────────────────
        now = time.time()
        for bw in bandwidth:
            if bw.bytes_out > 0:
                self.rolling.add(f"bytes_out:{bw.process_name}", bw.bytes_out, now)
        for ev in auth_data.get("auth_events", []):
            if ev.event_type == "failure":
                self.rolling.add(
                    f"auth_fail:{ev.username or 'unknown'}",
                    1.0,
                    now,
                )
                if ev.category == "ssh" and ev.source_ip:
                    self.rolling.add(f"ssh_fail:{ev.source_ip}", 1.0, now)

        # Feed beacon metrics: track connection timestamps per external dest
        for conn in connections:
            if (
                conn.state == "ESTABLISHED"
                and conn.remote_ip
                and not conn.remote_ip.startswith("10.")
                and not conn.remote_ip.startswith("172.")
                and not conn.remote_ip.startswith("192.168.")
                and not conn.remote_ip.startswith("127.")
            ):
                dest = f"{conn.remote_ip}:{conn.remote_port}"
                self.rolling.add(f"beacon:{dest}", 1.0, now)

        elapsed_ms = (time.monotonic() - start) * 1000

        # ── Merge into unified shared_data ────────────────────────────────
        return {
            # Raw domain data (unchanged keys from each collector)
            "processes": processes,
            "own_user_count": proc_data.get("own_user_count", 0),
            "total_count": proc_data.get("total_count", 0),
            "connections": connections,
            "bandwidth": bandwidth,
            "connection_count": net_data.get("connection_count", 0),
            "entries": pers_data.get("entries", []),
            "files": fs_data.get("files", []),
            "suid_binaries": fs_data.get("suid_binaries", []),
            "sip_status": fs_data.get("sip_status", "unknown"),
            "auth_events": auth_data.get("auth_events", []),
            "log_entries": log_data.get("log_entries", []),
            "usb_devices": periph_data.get("usb_devices", []),
            "bluetooth_devices": periph_data.get("bluetooth_devices", []),
            "volumes": periph_data.get("volumes", []),
            # Cross-domain indexes (built by this collector)
            "pid_map": pid_map,
            "pid_connections": dict(pid_connections),
            "pid_bandwidth": pid_bandwidth,
            "name_to_exe": name_to_exe,
            # Rolling window state (persists across collection cycles)
            "rolling": self.rolling,
            # Collection metadata
            "collection_ts": now,
            "correlation_collection_time_ms": elapsed_ms,
        }

    def _safe_collect(self, domain: str, collector: Any) -> Dict[str, Any]:
        """Collect from a domain collector with error isolation.

        If one domain fails, the others still run. Returns empty dict on failure.
        """
        try:
            return collector.collect()
        except Exception as e:
            logger.warning(
                "CorrelationCollector: %s collector failed: %s",
                domain,
                e,
            )
            return {}
