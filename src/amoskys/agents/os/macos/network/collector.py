"""macOS Network Collector — lsof + nettop based connection monitoring.

Collects network connections with process attribution using lsof.
Optionally collects per-process bandwidth via nettop.

Data sources:
    - lsof -i -nP: TCP/UDP connections with PID, state, addresses
    - nettop -P -L1: per-process bytes in/out (optional, adds ~1s)

No root required for either tool on macOS.
"""

from __future__ import annotations

import logging
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class Connection:
    """A single network connection.

    Serves as the unified connection model for both the core network agent
    and merged internet_activity probes. The internet_activity probes access
    remote_addr (IP only) — which maps to remote_ip here.
    """

    pid: int
    process_name: str
    user: str
    protocol: str  # TCP, UDP
    local_addr: str  # IP:port (raw lsof format)
    remote_addr: str  # IP:port (raw lsof format) or empty for LISTEN
    state: str  # ESTABLISHED, LISTEN, CLOSE_WAIT, etc.
    local_ip: str = ""
    local_port: int = 0
    remote_ip: str = ""
    remote_port: int = 0
    direction: str = "outbound"  # outbound / inbound (for internet_activity probes)
    duration_estimate_s: float = 0.0  # estimated duration (for long-lived detection)


@dataclass
class ProcessBandwidth:
    """Per-process bandwidth from nettop."""

    pid: int
    process_name: str
    bytes_in: int
    bytes_out: int


class MacOSNetworkCollector:
    """Collects network connection data from macOS.

    Returns shared_data dict with keys:
        connections: List[Connection]
        bandwidth: List[ProcessBandwidth] (if nettop enabled)
        connection_count: int
        collection_time_ms: float
    """

    def __init__(self, use_nettop: bool = False) -> None:
        self._use_nettop = use_nettop

    def collect(self) -> Dict[str, Any]:
        start = time.monotonic()

        connections = self._collect_lsof()
        bandwidth: List[ProcessBandwidth] = []
        if self._use_nettop:
            bandwidth = self._collect_nettop()

        elapsed_ms = (time.monotonic() - start) * 1000

        return {
            "connections": connections,
            "bandwidth": bandwidth,
            "connection_count": len(connections),
            "collection_time_ms": round(elapsed_ms, 2),
        }

    def _collect_lsof(self) -> List[Connection]:
        """Parse lsof -i -nP output into Connection objects."""
        connections: List[Connection] = []

        try:
            result = subprocess.run(
                ["lsof", "-i", "-nP"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                logger.warning("lsof returned %d", result.returncode)
                return connections

            lines = result.stdout.strip().split("\n")
            if len(lines) < 2:
                return connections

            # Skip header
            for line in lines[1:]:
                conn = self._parse_lsof_line(line)
                if conn:
                    connections.append(conn)

        except subprocess.TimeoutExpired:
            logger.warning("lsof timed out")
        except FileNotFoundError:
            logger.error("lsof not found")
        except Exception as e:
            logger.error("lsof collection failed: %s", e)

        return connections

    @staticmethod
    def _parse_lsof_line(line: str) -> Optional[Connection]:
        """Parse a single lsof output line."""
        # lsof -i -nP format:
        # COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
        parts = line.split()
        if len(parts) < 9:
            return None

        try:
            process_name = parts[0]
            pid = int(parts[1])
            user = parts[2]
            protocol = parts[7]  # TCP or UDP
            name = parts[8] if len(parts) > 8 else ""

            # Parse state (last field if present)
            state = ""
            if len(parts) > 9:
                state = parts[9].strip("()")

            # Parse addresses from NAME field
            # Format: local->remote or just local (for LISTEN)
            local_addr = ""
            remote_addr = ""
            local_ip = ""
            local_port = 0
            remote_ip = ""
            remote_port = 0

            if "->" in name:
                local_addr, remote_addr = name.split("->", 1)
            else:
                local_addr = name

            # Parse IP:port
            if local_addr and ":" in local_addr:
                parts_addr = local_addr.rsplit(":", 1)
                local_ip = parts_addr[0]
                try:
                    local_port = int(parts_addr[1])
                except ValueError:
                    pass

            if remote_addr and ":" in remote_addr:
                parts_addr = remote_addr.rsplit(":", 1)
                remote_ip = parts_addr[0]
                try:
                    remote_port = int(parts_addr[1])
                except ValueError:
                    pass

            return Connection(
                pid=pid,
                process_name=process_name,
                user=user,
                protocol=protocol,
                local_addr=local_addr,
                remote_addr=remote_addr,
                state=state,
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
            )

        except (ValueError, IndexError):
            return None

    def _collect_nettop(self) -> List[ProcessBandwidth]:
        """Collect per-process bandwidth from nettop."""
        bandwidth: List[ProcessBandwidth] = []

        try:
            result = subprocess.run(
                ["nettop", "-P", "-L1", "-J", "bytes_in,bytes_out"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return bandwidth

            for line in result.stdout.strip().split("\n"):
                parts = line.split(",")
                if len(parts) >= 3:
                    try:
                        name_pid = parts[0].strip()
                        bytes_in = int(parts[1].strip())
                        bytes_out = int(parts[2].strip())

                        # Parse "process_name.PID" format
                        pid = 0
                        name = name_pid
                        if "." in name_pid:
                            name, pid_str = name_pid.rsplit(".", 1)
                            try:
                                pid = int(pid_str)
                            except ValueError:
                                pass

                        bandwidth.append(
                            ProcessBandwidth(
                                pid=pid,
                                process_name=name,
                                bytes_in=bytes_in,
                                bytes_out=bytes_out,
                            )
                        )
                    except (ValueError, IndexError):
                        continue

        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.debug("nettop not available")
        except Exception as e:
            logger.error("nettop collection failed: %s", e)

        return bandwidth
