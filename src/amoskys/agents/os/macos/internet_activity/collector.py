"""macOS Internet Activity Collector — gathers active network connections.

Data sources:
    1. lsof -i -n -P — active network connections with PID and process info
    2. PID-to-process join — correlate connections to running processes
    3. IP classification — private, cloud provider, CDN, TOR exit node ranges

Returns shared_data dict with:
    connections: List[InternetConnection] — active connections
    connection_count: int — total connections collected
    unique_remote_ips: int — distinct remote IP addresses
    unique_processes: int — distinct processes with connections
    collection_time_ms: float — collection duration
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
class InternetConnection:
    """Single active network connection captured from lsof."""

    pid: int  # Process ID
    process_name: str  # Process name (command)
    user: str  # User owning the process
    protocol: str  # TCP, UDP
    local_addr: str  # Local IP address
    local_port: int  # Local port
    remote_addr: str  # Remote IP address
    remote_port: int  # Remote port
    state: str  # ESTABLISHED, LISTEN, CLOSE_WAIT, etc.
    direction: str = "outbound"  # outbound / inbound
    duration_estimate_s: float = 0.0  # Estimated connection duration


class MacOSInternetActivityCollector:
    """Collects active network connection data from macOS via lsof.

    Returns shared_data dict for ProbeContext with keys:
        connections: List[InternetConnection]
        connection_count: int
        unique_remote_ips: int
        unique_processes: int
        collection_time_ms: float
    """

    _LSOF_TIMEOUT = 15  # Subprocess timeout

    # Well-known cloud provider IP ranges (CIDR-style prefix matching)
    # AWS: 3.x, 13.x, 15.x, 18.x, 34.x, 35.x, 44.x, 50.x, 52.x, 54.x, 99.x
    _AWS_PREFIXES = (
        "3.",
        "13.",
        "15.",
        "18.",
        "34.",
        "35.",
        "44.",
        "50.",
        "52.",
        "54.",
        "99.",
    )
    # GCP: 34.x, 35.x (overlap with AWS), 104.196., 104.199., 130.211., 146.148.
    _GCP_PREFIXES = (
        "104.196.",
        "104.199.",
        "130.211.",
        "146.148.",
        "35.184.",
        "35.186.",
        "35.188.",
        "35.190.",
        "35.192.",
        "35.194.",
        "35.196.",
        "35.198.",
        "35.200.",
        "35.202.",
        "35.204.",
        "35.206.",
        "35.208.",
        "35.210.",
    )
    # Azure: 13.x (overlap), 20.x, 40.x, 51.x, 52.x (overlap), 104.40., 104.42.
    _AZURE_PREFIXES = (
        "20.",
        "40.",
        "51.",
        "104.40.",
        "104.42.",
        "137.116.",
        "137.117.",
        "168.61.",
        "168.62.",
        "168.63.",
    )

    # CDN IP ranges (prefix matching)
    _CDN_PREFIXES = (
        # Cloudflare
        "104.16.",
        "104.17.",
        "104.18.",
        "104.19.",
        "104.20.",
        "104.21.",
        "104.22.",
        "104.23.",
        "104.24.",
        "104.25.",
        "104.26.",
        "104.27.",
        "172.64.",
        "172.65.",
        "172.66.",
        "172.67.",
        "103.21.",
        "103.22.",
        "103.31.",
        "141.101.",
        "108.162.",
        "190.93.",
        "188.114.",
        "197.234.",
        "198.41.",
        # Akamai
        "23.0.",
        "23.1.",
        "23.2.",
        "23.3.",
        "23.4.",
        "23.5.",
        "23.32.",
        "23.33.",
        "23.34.",
        "23.35.",
        "23.36.",
        "23.64.",
        "23.65.",
        "23.66.",
        "23.67.",
        "104.64.",
        "104.65.",
        "104.66.",
        "104.67.",
        "184.24.",
        "184.25.",
        "184.26.",
        "184.27.",
        "184.28.",
        # Fastly
        "151.101.",
        # CloudFront
        "13.32.",
        "13.33.",
        "13.35.",
        "13.224.",
        "13.225.",
        "13.226.",
        "13.227.",
        "52.84.",
        "52.85.",
        "54.182.",
        "54.192.",
        "54.230.",
        "54.239.",
        "99.84.",
        "99.86.",
        "143.204.",
        "205.251.",
    )

    # Known TOR exit node IP prefixes (representative sample)
    # In production, this would be updated from TOR directory authorities
    _TOR_EXIT_PREFIXES = (
        "185.220.100.",
        "185.220.101.",
        "185.220.102.",
        "185.220.103.",
        "199.249.230.",
        "198.98.50.",
        "198.98.51.",
        "198.98.52.",
        "171.25.193.",
        "62.210.105.",
        "195.176.3.",
        "176.10.104.",
        "176.10.99.",
        "77.247.181.",
        "109.70.100.",
        "204.85.191.",
        "5.199.130.",
        "193.218.118.",
        "185.56.80.",
        "51.15.43.",
        "62.102.148.",
    )

    # Private / reserved IP prefixes
    _PRIVATE_PREFIXES = (
        "10.",
        "192.168.",
        "172.16.",
        "172.17.",
        "172.18.",
        "172.19.",
        "172.20.",
        "172.21.",
        "172.22.",
        "172.23.",
        "172.24.",
        "172.25.",
        "172.26.",
        "172.27.",
        "172.28.",
        "172.29.",
        "172.30.",
        "172.31.",
        "127.",
        "169.254.",
        "0.0.0.0",
        "::1",
        "fe80:",
        "fc00:",
        "fd00:",
    )

    # Well-known server ports (inbound if local port matches)
    _SERVER_PORTS = frozenset(
        {
            22,
            53,
            80,
            443,
            993,
            995,
            8080,
            8443,
            3000,
            5000,
            8000,
        }
    )

    # lsof output line pattern: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
    _LSOF_LINE_PATTERN = re.compile(
        r"^(\S+)\s+"  # COMMAND (process name)
        r"(\d+)\s+"  # PID
        r"(\S+)\s+"  # USER
        r"\S+\s+"  # FD (file descriptor)
        r"\S+\s+"  # TYPE
        r"\S+\s+"  # DEVICE
        r"\S+\s+"  # SIZE/OFF
        r"(\S+)\s+"  # NODE (protocol: TCP/UDP)
        r"(\S+)"  # NAME (connection details)
    )

    # Connection name pattern: local->remote (state)
    _CONN_PATTERN = re.compile(
        r"([\[\]0-9a-fA-F.:*]+):(\d+|\*)"  # local addr:port
        r"->"
        r"([\[\]0-9a-fA-F.:*]+):(\d+|\*)"  # remote addr:port
        r"(?:\s+\((\w+)\))?"  # optional state
    )

    # Listen pattern: *:port or addr:port
    _LISTEN_PATTERN = re.compile(r"([\[\]0-9a-fA-F.:*]+):(\d+|\*)")  # local addr:port

    def __init__(self, device_id: str = "", track_duration: bool = True) -> None:
        self.device_id = device_id or _get_hostname()
        self._track_duration = track_duration
        # Track connection first-seen times for duration estimation
        self._connection_first_seen: Dict[str, float] = {}

    def collect(self) -> Dict[str, Any]:
        """Collect active network connections.

        Returns dict for ProbeContext.shared_data.
        """
        start = time.monotonic()

        connections = self._collect_connections()

        elapsed_ms = (time.monotonic() - start) * 1000

        unique_remote_ips = len(
            {c.remote_addr for c in connections if c.remote_addr != "*"}
        )
        unique_processes = len({c.process_name for c in connections})

        return {
            "connections": connections,
            "connection_count": len(connections),
            "unique_remote_ips": unique_remote_ips,
            "unique_processes": unique_processes,
            "collection_time_ms": round(elapsed_ms, 2),
        }

    def _collect_connections(self) -> List[InternetConnection]:
        """Parse lsof -i -n -P for active network connections."""
        connections: List[InternetConnection] = []

        try:
            result = subprocess.run(
                ["lsof", "-i", "-n", "-P"],
                capture_output=True,
                text=True,
                timeout=self._LSOF_TIMEOUT,
            )

            if result.returncode not in (0, 1):
                # lsof returns 1 when some items couldn't be listed (non-fatal)
                logger.warning(
                    "lsof returned %d: %s",
                    result.returncode,
                    result.stderr[:200],
                )

            for line in result.stdout.strip().split("\n"):
                conn = self._parse_lsof_line(line)
                if conn:
                    connections.append(conn)

        except subprocess.TimeoutExpired:
            logger.warning(
                "lsof timed out after %ds",
                self._LSOF_TIMEOUT,
            )
        except FileNotFoundError:
            logger.error("'lsof' command not found — cannot collect connections")
        except Exception as e:
            logger.error("Connection collection failed: %s", e)

        logger.debug("Collected %d connections", len(connections))
        return connections

    def _parse_lsof_line(self, line: str) -> Optional[InternetConnection]:
        """Parse a single lsof output line into InternetConnection."""
        if not line or line.startswith("COMMAND"):
            return None

        match = self._LSOF_LINE_PATTERN.match(line)
        if not match:
            return None

        process_name = match.group(1)
        pid = int(match.group(2))
        user = match.group(3)
        protocol = match.group(4).upper()
        name = match.group(5)

        # Parse connection details
        conn_match = self._CONN_PATTERN.search(name)
        if conn_match:
            local_addr = conn_match.group(1).strip("[]")
            local_port = self._safe_port(conn_match.group(2))
            remote_addr = conn_match.group(3).strip("[]")
            remote_port = self._safe_port(conn_match.group(4))
            state = conn_match.group(5) or "UNKNOWN"
        else:
            # Listen-only or partial
            listen_match = self._LISTEN_PATTERN.search(name)
            if listen_match:
                local_addr = listen_match.group(1).strip("[]")
                local_port = self._safe_port(listen_match.group(2))
                remote_addr = "*"
                remote_port = 0
                state = "LISTEN"
            else:
                return None

        # Determine direction
        direction = self._classify_direction(local_port, remote_port, state)

        # Estimate duration via tracking
        duration = 0.0
        if self._track_duration and remote_addr != "*":
            conn_key = f"{pid}:{local_addr}:{local_port}->{remote_addr}:{remote_port}"
            now = time.time()
            if conn_key in self._connection_first_seen:
                duration = now - self._connection_first_seen[conn_key]
            else:
                self._connection_first_seen[conn_key] = now

        return InternetConnection(
            pid=pid,
            process_name=process_name,
            user=user,
            protocol=protocol,
            local_addr=local_addr,
            local_port=local_port,
            remote_addr=remote_addr,
            remote_port=remote_port,
            state=state,
            direction=direction,
            duration_estimate_s=round(duration, 1),
        )

    def _classify_direction(self, local_port: int, remote_port: int, state: str) -> str:
        """Classify connection direction based on port and state heuristics."""
        if state == "LISTEN":
            return "inbound"
        # If local port is a well-known server port, likely inbound
        if local_port in self._SERVER_PORTS and remote_port not in self._SERVER_PORTS:
            return "inbound"
        # Ephemeral local port (>= 49152) with non-ephemeral remote → outbound
        if local_port >= 49152 and remote_port < 49152:
            return "outbound"
        return "outbound"

    @staticmethod
    def _safe_port(port_str: str) -> int:
        """Safely parse port string, returning 0 for wildcards."""
        if port_str == "*":
            return 0
        try:
            return int(port_str)
        except ValueError:
            return 0

    def get_capabilities(self) -> Dict[str, str]:
        """Report collector capabilities."""
        caps = {}

        # Check lsof
        try:
            result = subprocess.run(
                ["lsof", "-i", "-n", "-P"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            caps["lsof"] = "REAL" if result.returncode in (0, 1) else "DEGRADED"
        except Exception:
            caps["lsof"] = "BLIND"

        return caps

    def cleanup_stale_connections(self, max_age_s: float = 7200.0) -> None:
        """Remove stale entries from duration tracking."""
        now = time.time()
        stale_keys = [
            k for k, v in self._connection_first_seen.items() if now - v > max_age_s
        ]
        for k in stale_keys:
            del self._connection_first_seen[k]


def _is_cloud_provider(ip: str) -> bool:
    """Check if IP belongs to a major cloud provider (AWS, GCP, Azure)."""
    return (
        any(ip.startswith(p) for p in MacOSInternetActivityCollector._AWS_PREFIXES)
        or any(ip.startswith(p) for p in MacOSInternetActivityCollector._GCP_PREFIXES)
        or any(ip.startswith(p) for p in MacOSInternetActivityCollector._AZURE_PREFIXES)
    )


def _is_tor_exit_node(ip: str) -> bool:
    """Check if IP matches known TOR exit node ranges."""
    return any(
        ip.startswith(p) for p in MacOSInternetActivityCollector._TOR_EXIT_PREFIXES
    )


def _is_cdn(ip: str) -> bool:
    """Check if IP belongs to a CDN provider (Cloudflare, Akamai, Fastly, CloudFront)."""
    return any(ip.startswith(p) for p in MacOSInternetActivityCollector._CDN_PREFIXES)


from amoskys.agents.common.ip_utils import is_private_ip as _is_private_ip


def _get_hostname() -> str:
    import socket

    return socket.gethostname()
