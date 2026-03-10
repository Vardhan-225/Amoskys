"""macOS Device Discovery Collector — gathers network device and topology data.

Data sources:
    1. arp -a — ARP table (IP/MAC mappings, interfaces)
    2. dns-sd -B _tcp local. — Bonjour/mDNS service discovery (with timeout)
    3. networksetup -listallhardwareports — hardware port enumeration
    4. netstat -rn — routing table

Returns shared_data dict with:
    arp_entries: List[ARPEntry] — ARP table entries
    bonjour_services: List[BonjourService] — discovered mDNS services
    hardware_ports: List[HardwarePort] — network hardware interfaces
    routes: List[RouteEntry] — routing table entries
    arp_count: int — total ARP entries collected
    collection_time_ms: float — collection duration
"""

from __future__ import annotations

import logging
import re
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ARPEntry:
    """Single ARP table entry mapping IP to MAC address."""

    ip: str  # IP address
    mac: str  # MAC address (aa:bb:cc:dd:ee:ff)
    interface: str  # Network interface (en0, en1, etc.)
    is_permanent: bool  # Permanent/static ARP entry


@dataclass
class BonjourService:
    """Bonjour/mDNS service discovered on the local network."""

    name: str  # Service instance name
    service_type: str  # Service type (e.g., _http._tcp)
    domain: str  # Domain (usually "local.")
    interface: str  # Interface index or name


@dataclass
class HardwarePort:
    """macOS network hardware port (physical or virtual interface)."""

    name: str  # Hardware port name (e.g., "Wi-Fi", "Ethernet")
    device: str  # Device name (e.g., "en0", "en1")
    mac: str  # Ethernet address (MAC)


@dataclass
class RouteEntry:
    """Single routing table entry."""

    destination: str  # Destination network/host
    gateway: str  # Gateway address
    interface: str  # Network interface
    flags: str  # Route flags (UGSc, UHLWIi, etc.)


class MacOSDiscoveryCollector:
    """Collects network device and topology data from macOS system commands.

    Returns shared_data dict for ProbeContext with keys:
        arp_entries: List[ARPEntry]
        bonjour_services: List[BonjourService]
        hardware_ports: List[HardwarePort]
        routes: List[RouteEntry]
        arp_count: int
        collection_time_ms: float
    """

    _ARP_TIMEOUT = 10  # Subprocess timeout for arp -a
    _BONJOUR_TIMEOUT = 5  # Subprocess timeout for dns-sd (short — it streams)
    _NETSETUP_TIMEOUT = 10  # Subprocess timeout for networksetup
    _NETSTAT_TIMEOUT = 10  # Subprocess timeout for netstat

    # arp -a output pattern: hostname (ip) at mac on iface [flags]
    _ARP_PATTERN = re.compile(
        r"^\?\s*\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+(\S+)\s+on\s+(\S+)"
        r"(?:\s+.*?(permanent))?"
    )
    # Also handle entries with hostnames
    _ARP_PATTERN_NAMED = re.compile(
        r"^(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+(\S+)\s+on\s+(\S+)"
        r"(?:\s+.*?(permanent))?"
    )

    # dns-sd -B output pattern: timestamp Flags Ifx Domain ServiceType ServiceName
    _BONJOUR_PATTERN = re.compile(
        r"^\s*\d+:\d+:\d+\.\d+\s+"  # timestamp
        r"(?:Add|Rmv)\s+"  # Flags
        r"(\d+)\s+"  # Interface index
        r"(\S+)\s+"  # Domain
        r"(\S+)\s+"  # Service type
        r"(.+)$"  # Service name
    )

    # networksetup -listallhardwareports output
    _HW_PORT_PATTERN = re.compile(r"Hardware Port:\s+(.+)")
    _HW_DEVICE_PATTERN = re.compile(r"Device:\s+(\S+)")
    _HW_MAC_PATTERN = re.compile(r"Ethernet Address:\s+(\S+)")

    # netstat -rn output pattern
    _ROUTE_PATTERN = re.compile(
        r"^(\S+)\s+"  # Destination
        r"(\S+)\s+"  # Gateway
        r"(\S+)\s+"  # Flags
        r"(?:\S+\s+)?"  # Refs (optional)
        r"(?:\S+\s+)?"  # Use (optional)
        r"(?:\S+\s+)?"  # Netif or Mtu
        r"(\S+)\s*$"  # Interface
    )
    _ROUTE_PATTERN_SIMPLE = re.compile(
        r"^(\S+)\s+"  # Destination
        r"(\S+)\s+"  # Gateway
        r"(\S+)\s+"  # Flags
        r"\S+\s+"  # Refs
        r"\S+\s+"  # Use
        r"(\S+)"  # Netif
    )

    def __init__(self, device_id: str = "") -> None:
        self.device_id = device_id or _get_hostname()

    def collect(self) -> Dict[str, Any]:
        """Collect network device and topology data.

        Returns dict for ProbeContext.shared_data.
        """
        start = time.monotonic()

        arp_entries = self._collect_arp_table()
        bonjour_services = self._collect_bonjour_services()
        hardware_ports = self._collect_hardware_ports()
        routes = self._collect_routing_table()

        elapsed_ms = (time.monotonic() - start) * 1000

        return {
            "arp_entries": arp_entries,
            "bonjour_services": bonjour_services,
            "hardware_ports": hardware_ports,
            "routes": routes,
            "arp_count": len(arp_entries),
            "collection_time_ms": round(elapsed_ms, 2),
        }

    def _collect_arp_table(self) -> List[ARPEntry]:
        """Parse ARP table via `arp -a`."""
        entries: List[ARPEntry] = []

        try:
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                timeout=self._ARP_TIMEOUT,
            )

            if result.returncode != 0:
                logger.warning(
                    "arp -a returned %d: %s",
                    result.returncode,
                    result.stderr[:200],
                )
                return entries

            for line in result.stdout.strip().split("\n"):
                entry = self._parse_arp_line(line)
                if entry:
                    entries.append(entry)

        except subprocess.TimeoutExpired:
            logger.warning("arp -a timed out after %ds", self._ARP_TIMEOUT)
        except FileNotFoundError:
            logger.error("'arp' command not found — cannot collect ARP table")
        except Exception as e:
            logger.error("ARP collection failed: %s", e)

        logger.debug("Collected %d ARP entries", len(entries))
        return entries

    def _parse_arp_line(self, line: str) -> Optional[ARPEntry]:
        """Parse a single ARP table line into ARPEntry."""
        if not line or line.startswith("---"):
            return None

        # Try named pattern first (hostname (ip) at mac on iface)
        match = self._ARP_PATTERN_NAMED.search(line)
        if match:
            ip = match.group(2)
            mac = match.group(3)
            interface = match.group(4)
            is_permanent = match.group(5) is not None

            # Skip incomplete entries
            if mac == "(incomplete)":
                return None

            return ARPEntry(
                ip=ip,
                mac=mac.lower(),
                interface=interface,
                is_permanent=is_permanent,
            )

        # Try unnamed pattern (? (ip) at mac on iface)
        match = self._ARP_PATTERN.search(line)
        if match:
            ip = match.group(1)
            mac = match.group(2)
            interface = match.group(3)
            is_permanent = match.group(4) is not None

            if mac == "(incomplete)":
                return None

            return ARPEntry(
                ip=ip,
                mac=mac.lower(),
                interface=interface,
                is_permanent=is_permanent,
            )

        return None

    def _collect_bonjour_services(self) -> List[BonjourService]:
        """Discover Bonjour/mDNS services via `dns-sd -B _tcp local.`."""
        services: List[BonjourService] = []

        try:
            # dns-sd streams output indefinitely — use timeout to cut it off
            result = subprocess.run(
                ["dns-sd", "-B", "_tcp", "local."],
                capture_output=True,
                text=True,
                timeout=self._BONJOUR_TIMEOUT,
            )
            # dns-sd always "fails" when killed by timeout — parse whatever we got
            self._parse_bonjour_output(result.stdout, services)

        except subprocess.TimeoutExpired as e:
            # Expected — dns-sd streams forever, we kill it after timeout
            stdout = e.stdout
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", errors="replace")
            if stdout:
                self._parse_bonjour_output(stdout, services)
            logger.debug(
                "dns-sd timed out as expected after %ds, captured %d services",
                self._BONJOUR_TIMEOUT,
                len(services),
            )
        except FileNotFoundError:
            logger.error(
                "'dns-sd' command not found — cannot discover Bonjour services"
            )
        except Exception as e:
            logger.error("Bonjour discovery failed: %s", e)

        logger.debug("Discovered %d Bonjour services", len(services))
        return services

    def _parse_bonjour_output(
        self, output: str, services: List[BonjourService]
    ) -> None:
        """Parse dns-sd -B output lines into BonjourService entries."""
        if not output:
            return

        seen: set[tuple[str, str, str]] = set()

        for line in output.strip().split("\n"):
            match = self._BONJOUR_PATTERN.search(line)
            if match:
                interface = match.group(1)
                domain = match.group(2)
                service_type = match.group(3)
                name = match.group(4).strip()

                key = (name, service_type, domain)
                if key not in seen:
                    seen.add(key)
                    services.append(
                        BonjourService(
                            name=name,
                            service_type=service_type,
                            domain=domain,
                            interface=interface,
                        )
                    )

    def _collect_hardware_ports(self) -> List[HardwarePort]:
        """Enumerate hardware ports via `networksetup -listallhardwareports`."""
        ports: List[HardwarePort] = []

        try:
            result = subprocess.run(
                ["networksetup", "-listallhardwareports"],
                capture_output=True,
                text=True,
                timeout=self._NETSETUP_TIMEOUT,
            )

            if result.returncode != 0:
                logger.warning(
                    "networksetup returned %d: %s",
                    result.returncode,
                    result.stderr[:200],
                )
                return ports

            current_name = ""
            current_device = ""
            current_mac = ""

            for line in result.stdout.split("\n"):
                line = line.strip()

                port_match = self._HW_PORT_PATTERN.match(line)
                if port_match:
                    # Save previous entry if complete
                    if current_name and current_device:
                        ports.append(
                            HardwarePort(
                                name=current_name,
                                device=current_device,
                                mac=current_mac.lower(),
                            )
                        )
                    current_name = port_match.group(1)
                    current_device = ""
                    current_mac = ""
                    continue

                device_match = self._HW_DEVICE_PATTERN.match(line)
                if device_match:
                    current_device = device_match.group(1)
                    continue

                mac_match = self._HW_MAC_PATTERN.match(line)
                if mac_match:
                    current_mac = mac_match.group(1)
                    continue

            # Don't forget last entry
            if current_name and current_device:
                ports.append(
                    HardwarePort(
                        name=current_name,
                        device=current_device,
                        mac=current_mac.lower(),
                    )
                )

        except subprocess.TimeoutExpired:
            logger.warning("networksetup timed out after %ds", self._NETSETUP_TIMEOUT)
        except FileNotFoundError:
            logger.error("'networksetup' not found — cannot enumerate hardware ports")
        except Exception as e:
            logger.error("Hardware port collection failed: %s", e)

        logger.debug("Collected %d hardware ports", len(ports))
        return ports

    def _collect_routing_table(self) -> List[RouteEntry]:
        """Parse routing table via `netstat -rn`."""
        routes: List[RouteEntry] = []

        try:
            result = subprocess.run(
                ["netstat", "-rn"],
                capture_output=True,
                text=True,
                timeout=self._NETSTAT_TIMEOUT,
            )

            if result.returncode != 0:
                logger.warning(
                    "netstat -rn returned %d: %s",
                    result.returncode,
                    result.stderr[:200],
                )
                return routes

            in_table = False
            for line in result.stdout.strip().split("\n"):
                # Skip headers until we hit the routing table
                if line.startswith("Destination"):
                    in_table = True
                    continue
                if line.startswith("Internet6:"):
                    in_table = True
                    continue

                if not in_table or not line.strip():
                    continue

                route = self._parse_route_line(line)
                if route:
                    routes.append(route)

        except subprocess.TimeoutExpired:
            logger.warning("netstat -rn timed out after %ds", self._NETSTAT_TIMEOUT)
        except FileNotFoundError:
            logger.error("'netstat' not found — cannot collect routing table")
        except Exception as e:
            logger.error("Routing table collection failed: %s", e)

        logger.debug("Collected %d route entries", len(routes))
        return routes

    def _parse_route_line(self, line: str) -> Optional[RouteEntry]:
        """Parse a single netstat -rn line into RouteEntry."""
        if not line.strip():
            return None

        # macOS netstat -rn format:
        # Destination        Gateway            Flags    Netif  Expire
        match = self._ROUTE_PATTERN_SIMPLE.search(line)
        if match:
            return RouteEntry(
                destination=match.group(1),
                gateway=match.group(2),
                flags=match.group(3),
                interface=match.group(4),
            )

        # Fallback: split by whitespace
        parts = line.split()
        if len(parts) >= 4:
            return RouteEntry(
                destination=parts[0],
                gateway=parts[1],
                flags=parts[2],
                interface=parts[-1] if len(parts) >= 4 else "",
            )

        return None

    def get_capabilities(self) -> Dict[str, str]:
        """Report collector capabilities."""
        caps = {}

        # Check arp
        try:
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            caps["arp"] = "REAL" if result.returncode == 0 else "DEGRADED"
        except Exception:
            caps["arp"] = "BLIND"

        # Check dns-sd
        try:
            result = subprocess.run(
                ["dns-sd", "-B", "_tcp", "local."],
                capture_output=True,
                text=True,
                timeout=3,
            )
            caps["bonjour"] = "REAL"
        except subprocess.TimeoutExpired:
            caps["bonjour"] = "REAL"  # dns-sd always times out — that's expected
        except Exception:
            caps["bonjour"] = "BLIND"

        # Check networksetup
        try:
            result = subprocess.run(
                ["networksetup", "-listallhardwareports"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            caps["networksetup"] = "REAL" if result.returncode == 0 else "DEGRADED"
        except Exception:
            caps["networksetup"] = "BLIND"

        # Check netstat
        try:
            result = subprocess.run(
                ["netstat", "-rn"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            caps["netstat"] = "REAL" if result.returncode == 0 else "DEGRADED"
        except Exception:
            caps["netstat"] = "BLIND"

        return caps


def _get_hostname() -> str:
    import socket

    return socket.gethostname()
