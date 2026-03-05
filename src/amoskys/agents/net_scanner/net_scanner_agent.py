#!/usr/bin/env python3
"""AMOSKYS Network Scanner Agent - Network Topology & Service Monitoring.

This is the implementation of the Network Scanner Agent using the micro-probe
architecture. It discovers hosts on local subnets, scans for open ports,
grabs service banners, inspects SSL certificates, and compares results
against a stored baseline to detect changes.

7 micro-probes each watch a specific network security vector:

    1. NewServiceDetectionProbe - New (ip, port, service) tuples
    2. OpenPortChangeProbe - Port state transitions
    3. RogueServiceProbe - Services on non-standard ports
    4. SSLCertIssueProbe - SSL certificate problems
    5. VulnerableBannerProbe - Known-vulnerable service versions
    6. UnauthorizedListenerProbe - Unauthorized local listeners
    7. NetworkTopologyChangeProbe - Host/MAC topology changes

Architecture:
    - NetworkScanner: Main collector with TCP connect scan, ARP, banner grab
    - MacOSNetworkScanner: macOS-specific interface/ARP discovery
    - LinuxNetworkScanner: Linux-specific /proc/net/route and arp -n
    - Baseline system: JSON-persisted baseline with diff computation
    - Probes operate on the diff, not raw results

Usage:
    >>> from amoskys.agents.net_scanner import NetScannerAgent
    >>> agent = NetScannerAgent()
    >>> agent.run()

MITRE ATT&CK Coverage:
    - T1133: External Remote Services
    - T1046: Network Service Scanning
    - T1090.001: Internal Proxy
    - T1573.002: Asymmetric Cryptography
    - T1595: Active Scanning
    - T1571: Non-Standard Port
    - T1557.002: ARP Cache Poisoning
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import platform
import re
import socket
import ssl
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import grpc

from amoskys.agents.common.base import HardenedAgentBase
from amoskys.agents.common.probes import (
    MicroProbeAgentMixin,
    ProbeContext,
    TelemetryEvent,
)
from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.agents.net_scanner.agent_types import (
    COMMON_SCAN_PORTS,
    HostScanResult,
    PortInfo,
    ScanDiff,
    ScanResult,
)
from amoskys.agents.net_scanner.probes import create_net_scanner_probes
from amoskys.config import get_config
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.proto import universal_telemetry_pb2_grpc as universal_pbrpc

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("NetScannerAgent")

config = get_config()
EVENTBUS_ADDRESS = config.agent.bus_address
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = getattr(
    config.agent, "net_scanner_queue_path", "data/queue/net_scanner.db"
)
BASELINE_PATH = getattr(
    config.agent, "net_scanner_baseline_path", "data/net_scanner/baseline.json"
)


# =============================================================================
# EventBus Publisher
# =============================================================================


class EventBusPublisher:
    """Wrapper for EventBus gRPC client."""

    def __init__(self, address: str, cert_dir: str):
        self.address = address
        self.cert_dir = cert_dir
        self._channel = None
        self._stub = None

    def _ensure_channel(self):
        """Create gRPC channel if needed."""
        if self._channel is None:
            try:
                with open(f"{self.cert_dir}/ca.crt", "rb") as f:
                    ca_cert = f.read()
                with open(f"{self.cert_dir}/agent.crt", "rb") as f:
                    client_cert = f.read()
                with open(f"{self.cert_dir}/agent.key", "rb") as f:
                    client_key = f.read()

                credentials = grpc.ssl_channel_credentials(
                    root_certificates=ca_cert,
                    private_key=client_key,
                    certificate_chain=client_cert,
                )
                self._channel = grpc.secure_channel(self.address, credentials)
                self._stub = universal_pbrpc.UniversalEventBusStub(self._channel)
                logger.info("Created secure gRPC channel with mTLS")
            except FileNotFoundError as e:
                raise RuntimeError(f"Certificate not found: {e}")
            except Exception as e:
                raise RuntimeError(f"Failed to create gRPC channel: {e}")

    def publish(self, events: list) -> None:
        """Publish events to EventBus."""
        self._ensure_channel()

        for event in events:
            # Already-wrapped envelopes (e.g. from drain path) go directly
            if isinstance(event, telemetry_pb2.UniversalEnvelope):
                envelope = event
            else:
                timestamp_ns = int(time.time() * 1e9)
                idempotency_key = f"{event.device_id}_{timestamp_ns}"
                envelope = telemetry_pb2.UniversalEnvelope(
                    version="v1",
                    ts_ns=timestamp_ns,
                    idempotency_key=idempotency_key,
                    device_telemetry=event,
                    priority="NORMAL",
                    requires_acknowledgment=True,
                    schema_version=1,
                )

            ack = self._stub.PublishTelemetry(envelope, timeout=5.0)

            if ack.status != telemetry_pb2.UniversalAck.OK:
                raise Exception(f"EventBus returned status: {ack.status}")

    def close(self):
        """Close gRPC channel."""
        if self._channel:
            self._channel.close()
            self._channel = None
            self._stub = None


# =============================================================================
# Network Collectors
# =============================================================================


class BaseNetworkCollector:
    """Base class for platform-specific network collectors."""

    def discover_subnets(self) -> List[str]:
        """Discover local subnets.

        Returns:
            List of CIDR subnet strings (e.g., ["192.168.1.0/24"])
        """
        raise NotImplementedError

    def discover_hosts(self, subnet: str) -> List[Dict[str, Any]]:
        """Discover alive hosts on a subnet via ARP.

        Args:
            subnet: CIDR subnet to scan

        Returns:
            List of dicts with 'ip', 'mac', 'hostname' keys
        """
        raise NotImplementedError


class MacOSNetworkCollector(BaseNetworkCollector):
    """macOS-specific network discovery using networksetup and arp.

    Uses:
        - networksetup -listallhardwareports for interface discovery
        - ifconfig for IP/subnet extraction
        - arp -a for host discovery
    """

    def discover_subnets(self) -> List[str]:
        """Discover subnets via networksetup and ifconfig on macOS."""
        subnets: List[str] = []
        try:
            # Get active interfaces
            result = subprocess.run(
                ["ifconfig"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return subnets

            # Parse ifconfig output for inet lines
            current_ip = None
            current_mask = None
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("inet ") and "127.0.0.1" not in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip_str = parts[1]
                        # Find netmask
                        for i, p in enumerate(parts):
                            if p == "netmask":
                                mask_hex = parts[i + 1]
                                try:
                                    # macOS uses hex netmask (0xffffff00)
                                    mask_int = int(mask_hex, 16)
                                    prefix_len = bin(mask_int).count("1")
                                    network = ipaddress.IPv4Network(
                                        f"{ip_str}/{prefix_len}",
                                        strict=False,
                                    )
                                    subnet_str = str(network)
                                    if subnet_str not in subnets:
                                        subnets.append(subnet_str)
                                except (ValueError, IndexError):
                                    pass
                                break

        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            logger.warning("macOS subnet discovery failed: %s", e)

        return subnets

    def discover_hosts(self, subnet: str) -> List[Dict[str, Any]]:
        """Discover hosts via arp -a on macOS."""
        hosts: List[Dict[str, Any]] = []
        try:
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return hosts

            network = ipaddress.IPv4Network(subnet, strict=False)

            # Parse arp -a output: hostname (ip) at mac on iface ...
            for line in result.stdout.splitlines():
                match = re.match(
                    r"(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+(\S+)",
                    line,
                )
                if match:
                    hostname = match.group(1)
                    ip_str = match.group(2)
                    mac = match.group(3)

                    try:
                        ip = ipaddress.IPv4Address(ip_str)
                        if ip in network and mac != "(incomplete)":
                            if hostname == "?":
                                hostname = None
                            hosts.append(
                                {
                                    "ip": ip_str,
                                    "mac": mac,
                                    "hostname": hostname,
                                }
                            )
                    except ValueError:
                        continue

        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            logger.warning("macOS ARP discovery failed: %s", e)

        return hosts


class LinuxNetworkCollector(BaseNetworkCollector):
    """Linux-specific network discovery using /proc/net/route and arp.

    Uses:
        - /proc/net/route for interface/subnet discovery
        - arp -n for host discovery
    """

    def discover_subnets(self) -> List[str]:
        """Discover subnets via /proc/net/route on Linux."""
        subnets: List[str] = []
        route_path = "/proc/net/route"

        try:
            if os.path.exists(route_path):
                with open(route_path, "r") as f:
                    lines = f.readlines()[1:]  # Skip header

                for line in lines:
                    parts = line.strip().split("\t")
                    if len(parts) >= 8:
                        dest_hex = parts[1]
                        mask_hex = parts[7]

                        if dest_hex == "00000000":
                            # Default route - skip
                            continue

                        try:
                            # Convert hex to IP (little-endian on Linux)
                            dest_int = int(dest_hex, 16)
                            dest_bytes = dest_int.to_bytes(4, "little")
                            dest_ip = str(ipaddress.IPv4Address(dest_bytes))

                            mask_int = int(mask_hex, 16)
                            mask_bytes = mask_int.to_bytes(4, "little")
                            mask_ip = str(ipaddress.IPv4Address(mask_bytes))

                            # Calculate prefix length
                            prefix_len = bin(int(ipaddress.IPv4Address(mask_ip))).count(
                                "1"
                            )

                            network = ipaddress.IPv4Network(
                                f"{dest_ip}/{prefix_len}", strict=False
                            )
                            subnet_str = str(network)
                            if subnet_str not in subnets:
                                subnets.append(subnet_str)
                        except (ValueError, OverflowError):
                            continue
            else:
                # Fallback: use ip route
                result = subprocess.run(
                    ["ip", "route", "show"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        parts = line.split()
                        if parts and "/" in parts[0]:
                            try:
                                network = ipaddress.IPv4Network(parts[0], strict=False)
                                subnet_str = str(network)
                                if (
                                    subnet_str not in subnets
                                    and not network.is_loopback
                                ):
                                    subnets.append(subnet_str)
                            except ValueError:
                                continue

        except (OSError, IOError) as e:
            logger.warning("Linux subnet discovery failed: %s", e)

        return subnets

    def discover_hosts(self, subnet: str) -> List[Dict[str, Any]]:
        """Discover hosts via arp -n on Linux."""
        hosts: List[Dict[str, Any]] = []
        try:
            result = subprocess.run(
                ["arp", "-n"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return hosts

            network = ipaddress.IPv4Network(subnet, strict=False)

            # Parse arp -n output (skip header)
            for line in result.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 3:
                    ip_str = parts[0]
                    mac = parts[2]

                    try:
                        ip = ipaddress.IPv4Address(ip_str)
                        if ip in network and mac != "(incomplete)":
                            hostname = None
                            try:
                                hostname = socket.gethostbyaddr(ip_str)[0]
                            except (socket.herror, socket.gaierror):
                                pass

                            hosts.append(
                                {
                                    "ip": ip_str,
                                    "mac": mac,
                                    "hostname": hostname,
                                }
                            )
                    except ValueError:
                        continue

        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            logger.warning("Linux ARP discovery failed: %s", e)

        return hosts


class NetworkScanner:
    """Main network scanner combining discovery, port scanning, and analysis.

    Features:
        - Platform-aware subnet discovery
        - ARP-based host discovery
        - TCP connect scanning with configurable rate limiting
        - Banner grabbing via socket.recv()
        - SSL certificate inspection
        - JSON baseline persistence
        - Diff computation against baseline

    Rate Limiting:
        Default max 100 ports/second across all hosts. Configurable via
        max_ports_per_second parameter.
    """

    # SSL-likely ports for certificate inspection
    SSL_PORTS = frozenset({443, 8443, 993, 995, 465, 636, 5986})

    def __init__(
        self,
        scan_ports: Optional[List[int]] = None,
        connect_timeout: float = 2.0,
        banner_timeout: float = 3.0,
        max_ports_per_second: int = 100,
        max_workers: int = 20,
        baseline_path: str = BASELINE_PATH,
    ):
        """Initialize NetworkScanner.

        Args:
            scan_ports: Ports to scan (defaults to COMMON_SCAN_PORTS)
            connect_timeout: TCP connect timeout in seconds
            banner_timeout: Banner read timeout in seconds
            max_ports_per_second: Rate limit for port scanning
            max_workers: Max concurrent scan threads
            baseline_path: Path to baseline JSON file
        """
        self.scan_ports = scan_ports or COMMON_SCAN_PORTS
        self.connect_timeout = connect_timeout
        self.banner_timeout = banner_timeout
        self.max_ports_per_second = max_ports_per_second
        self.max_workers = max_workers
        self.baseline_path = baseline_path

        # Select platform-specific collector
        system = platform.system()
        if system == "Darwin":
            self._collector: BaseNetworkCollector = MacOSNetworkCollector()
        elif system == "Linux":
            self._collector = LinuxNetworkCollector()
        else:
            # Fallback - try macOS-style commands
            self._collector = MacOSNetworkCollector()

        logger.info(
            "NetworkScanner initialized: %d ports, timeout=%.1fs, "
            "rate=%d ports/s, workers=%d",
            len(self.scan_ports),
            self.connect_timeout,
            self.max_ports_per_second,
            self.max_workers,
        )

    def collect(self) -> List[ScanResult]:
        """Perform a full network scan.

        Steps:
            1. Discover local subnets
            2. For each subnet, discover alive hosts via ARP
            3. For each host, TCP connect scan on configured ports
            4. For open ports, grab banners
            5. For SSL ports, inspect certificates

        Returns:
            List of ScanResult objects (one per subnet)
        """
        results: List[ScanResult] = []

        # Step 1: Discover subnets
        subnets = self._collector.discover_subnets()
        if not subnets:
            logger.warning("No subnets discovered - check network configuration")
            return results

        logger.info("Discovered %d subnet(s): %s", len(subnets), subnets)

        for subnet in subnets:
            scan_start = time.time()

            # Step 2: Discover hosts
            host_entries = self._collector.discover_hosts(subnet)
            logger.info("Subnet %s: discovered %d host(s)", subnet, len(host_entries))

            # Step 3-5: Scan each host
            host_results: List[HostScanResult] = []
            for entry in host_entries:
                ip = entry["ip"]
                try:
                    host_result = self._scan_host(
                        ip=ip,
                        mac=entry.get("mac"),
                        hostname=entry.get("hostname"),
                    )
                    host_results.append(host_result)
                except Exception as e:
                    logger.error("Error scanning host %s: %s", ip, e)

            scan_duration = time.time() - scan_start

            results.append(
                ScanResult(
                    timestamp=datetime.now(timezone.utc),
                    target_subnet=subnet,
                    hosts=host_results,
                    scan_duration_seconds=round(scan_duration, 2),
                    scan_type="incremental",
                )
            )

            logger.info(
                "Subnet %s scan complete: %d hosts, %.1fs",
                subnet,
                len(host_results),
                scan_duration,
            )

        return results

    def _scan_host(
        self,
        ip: str,
        mac: Optional[str] = None,
        hostname: Optional[str] = None,
    ) -> HostScanResult:
        """Scan a single host for open ports, banners, and SSL certs.

        Args:
            ip: IP address to scan
            mac: MAC address from ARP (if known)
            hostname: Hostname from ARP/DNS (if known)

        Returns:
            HostScanResult with discovered ports
        """
        open_ports: List[PortInfo] = []

        # Rate limiting: compute delay between port scans
        delay = 1.0 / self.max_ports_per_second if self.max_ports_per_second > 0 else 0

        # Use thread pool for concurrent port scanning
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            for port in self.scan_ports:
                future = executor.submit(self._scan_port, ip, port)
                futures[future] = port

            for future in as_completed(futures):
                port = futures[future]
                try:
                    port_info = future.result()
                    if port_info and port_info.state == "open":
                        open_ports.append(port_info)
                except Exception as e:
                    logger.debug("Port scan error %s:%d: %s", ip, port, e)

        # Resolve hostname if not provided
        if not hostname:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except (socket.herror, socket.gaierror, OSError):
                pass

        return HostScanResult(
            ip=ip,
            hostname=hostname,
            mac=mac,
            is_alive=True,
            open_ports=sorted(open_ports, key=lambda p: p.port),
        )

    def _scan_port(self, ip: str, port: int) -> Optional[PortInfo]:
        """TCP connect scan a single port with banner grab and SSL check.

        Args:
            ip: Target IP address
            port: Target port number

        Returns:
            PortInfo if port is open, None if closed/filtered
        """
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.connect_timeout)

            result = sock.connect_ex((ip, port))
            if result != 0:
                return PortInfo(port=port, state="closed")

            # Port is open - try banner grab
            banner = self._grab_banner(sock, ip, port)

            # Identify service from banner or port
            service = self._identify_service(port, banner)

            # SSL certificate inspection for SSL-likely ports
            ssl_subject = None
            ssl_expiry = None
            if port in self.SSL_PORTS or (banner and "ssl" in banner.lower()):
                ssl_subject, ssl_expiry = self._inspect_ssl(ip, port)

            return PortInfo(
                port=port,
                state="open",
                service=service,
                banner=banner,
                ssl_subject=ssl_subject,
                ssl_expiry=ssl_expiry,
            )

        except socket.timeout:
            return PortInfo(port=port, state="filtered")
        except ConnectionRefusedError:
            return PortInfo(port=port, state="closed")
        except OSError:
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass

    def _grab_banner(
        self,
        sock: socket.socket,
        ip: str,
        port: int,
    ) -> Optional[str]:
        """Attempt to grab a service banner from an open port.

        Sends an empty probe and reads the response. Some services
        (SSH, FTP, SMTP) send banners immediately upon connection.

        Args:
            sock: Connected socket
            ip: Target IP (for logging)
            port: Target port (for logging)

        Returns:
            Banner string or None
        """
        try:
            sock.settimeout(self.banner_timeout)

            # Try reading first (many services send banners unprompted)
            try:
                banner_bytes = sock.recv(1024)
                if banner_bytes:
                    return banner_bytes.decode("utf-8", errors="replace").strip()
            except (socket.timeout, ConnectionResetError):
                pass

            # If no banner, send a minimal probe
            try:
                sock.sendall(b"\r\n")
                banner_bytes = sock.recv(1024)
                if banner_bytes:
                    return banner_bytes.decode("utf-8", errors="replace").strip()
            except (socket.timeout, ConnectionResetError, BrokenPipeError):
                pass

            return None

        except Exception as e:
            logger.debug("Banner grab error %s:%d: %s", ip, port, e)
            return None

    def _identify_service(self, port: int, banner: Optional[str]) -> Optional[str]:
        """Identify service from port number and/or banner.

        Args:
            port: Port number
            banner: Banner string (if available)

        Returns:
            Service name or None
        """
        # Try banner identification first
        if banner:
            banner_lower = banner.lower()
            if "ssh" in banner_lower:
                return "ssh"
            if "http" in banner_lower or "html" in banner_lower:
                return "http"
            if "ftp" in banner_lower:
                return "ftp"
            if "smtp" in banner_lower or "postfix" in banner_lower:
                return "smtp"
            if "mysql" in banner_lower or "mariadb" in banner_lower:
                return "mysql"
            if "postgresql" in banner_lower:
                return "postgresql"
            if "redis" in banner_lower:
                return "redis"
            if "mongodb" in banner_lower:
                return "mongodb"
            if "elasticsearch" in banner_lower:
                return "elasticsearch"
            if "vnc" in banner_lower or "rfb" in banner_lower:
                return "vnc"
            if "socks" in banner_lower:
                return "socks"

        # Fallback to well-known port mapping
        port_service_map = {
            22: "ssh",
            80: "http",
            443: "https",
            21: "ftp",
            25: "smtp",
            53: "dns",
            3306: "mysql",
            5432: "postgresql",
            6379: "redis",
            27017: "mongodb",
            9200: "elasticsearch",
            3389: "rdp",
            5900: "vnc",
            8080: "http",
            8443: "https",
            1080: "socks",
        }
        return port_service_map.get(port)

    def _inspect_ssl(self, ip: str, port: int) -> Tuple[Optional[str], Optional[str]]:
        """Inspect SSL certificate on a given host:port.

        Uses ssl.get_server_certificate() to fetch the certificate
        and extract subject CN and expiry date.

        Args:
            ip: Target IP address
            port: Target port number

        Returns:
            Tuple of (subject_string, expiry_iso_string) or (None, None)
        """
        try:
            # Get PEM certificate
            pem_cert = ssl.get_server_certificate(
                (ip, port), timeout=self.connect_timeout
            )

            # Parse with ssl module
            import tempfile

            # Write PEM to temp file for ssl._ssl._test_decode_cert
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".pem", delete=False
            ) as f:
                f.write(pem_cert)
                temp_path = f.name

            try:
                cert_dict = ssl._ssl._test_decode_cert(temp_path)
            finally:
                os.unlink(temp_path)

            # Extract subject
            subject_parts = []
            subject = cert_dict.get("subject", ())
            for rdn in subject:
                for attr_type, attr_value in rdn:
                    subject_parts.append(f"{attr_type}={attr_value}")
            subject_str = "/".join(subject_parts) if subject_parts else None

            # Extract expiry
            not_after = cert_dict.get("notAfter")
            expiry_str = None
            if not_after:
                try:
                    # OpenSSL date format: "Mar  1 12:00:00 2026 GMT"
                    expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
                    expiry_str = expiry_dt.isoformat()
                except ValueError:
                    expiry_str = not_after

            return subject_str, expiry_str

        except Exception as e:
            logger.debug("SSL inspection failed for %s:%d: %s", ip, port, e)
            return None, None

    # =========================================================================
    # Baseline Management
    # =========================================================================

    def load_baseline(self) -> Optional[List[ScanResult]]:
        """Load baseline scan results from JSON file.

        Returns:
            List of ScanResult from baseline, or None if no baseline
        """
        if not Path(self.baseline_path).exists():
            logger.info("No baseline found at %s", self.baseline_path)
            return None

        try:
            with open(self.baseline_path, "r") as f:
                data = json.load(f)

            results = [ScanResult.from_dict(r) for r in data]
            total_hosts = sum(len(r.hosts) for r in results)
            logger.info(
                "Loaded baseline: %d subnets, %d hosts",
                len(results),
                total_hosts,
            )
            return results

        except Exception as e:
            logger.error("Failed to load baseline: %s", e)
            return None

    def save_baseline(self, results: List[ScanResult]) -> None:
        """Save scan results as the new baseline.

        Args:
            results: Current scan results to persist
        """
        try:
            Path(self.baseline_path).parent.mkdir(parents=True, exist_ok=True)

            data = [r.to_dict() for r in results]
            with open(self.baseline_path, "w") as f:
                json.dump(data, f, indent=2, default=str)

            total_hosts = sum(len(r.hosts) for r in results)
            logger.info(
                "Saved baseline: %d subnets, %d hosts to %s",
                len(results),
                total_hosts,
                self.baseline_path,
            )

        except Exception as e:
            logger.error("Failed to save baseline: %s", e)

    def compute_diff(
        self,
        current: List[ScanResult],
        baseline: List[ScanResult],
    ) -> ScanDiff:
        """Compute difference between current scan and baseline.

        Compares hosts and ports between current and baseline results
        to find new hosts, removed hosts, new ports, removed ports,
        changed banners, and MAC address changes.

        Args:
            current: Current scan results
            baseline: Previous baseline results

        Returns:
            ScanDiff with all detected changes
        """
        diff = ScanDiff()

        # Build lookup maps: ip -> HostScanResult
        current_hosts: Dict[str, HostScanResult] = {}
        for result in current:
            for host in result.hosts:
                current_hosts[host.ip] = host

        baseline_hosts: Dict[str, HostScanResult] = {}
        for result in baseline:
            for host in result.hosts:
                baseline_hosts[host.ip] = host

        current_ips = set(current_hosts.keys())
        baseline_ips = set(baseline_hosts.keys())

        # New hosts
        for ip in current_ips - baseline_ips:
            diff.new_hosts.append(current_hosts[ip])

        # Removed hosts
        for ip in baseline_ips - current_ips:
            diff.removed_hosts.append(baseline_hosts[ip])

        # Hosts in both - check for port/banner/MAC changes
        for ip in current_ips & baseline_ips:
            cur_host = current_hosts[ip]
            base_host = baseline_hosts[ip]

            # MAC change detection (ARP spoofing)
            if cur_host.mac and base_host.mac and cur_host.mac != base_host.mac:
                diff.mac_changes.append(
                    {
                        "ip": ip,
                        "old_mac": base_host.mac,
                        "new_mac": cur_host.mac,
                    }
                )

            # Port comparison
            cur_ports = {p.port: p for p in cur_host.open_ports}
            base_ports = {p.port: p for p in base_host.open_ports}

            # New ports
            for port_num in set(cur_ports.keys()) - set(base_ports.keys()):
                p = cur_ports[port_num]
                diff.new_ports.append(
                    {
                        "ip": ip,
                        "port": p.port,
                        "service": p.service,
                        "banner": p.banner,
                        "state": p.state,
                    }
                )

            # Removed ports
            for port_num in set(base_ports.keys()) - set(cur_ports.keys()):
                p = base_ports[port_num]
                diff.removed_ports.append(
                    {
                        "ip": ip,
                        "port": p.port,
                        "service": p.service,
                        "banner": p.banner,
                        "state": p.state,
                    }
                )

            # Banner changes on existing ports
            for port_num in set(cur_ports.keys()) & set(base_ports.keys()):
                cur_banner = cur_ports[port_num].banner or ""
                base_banner = base_ports[port_num].banner or ""
                if cur_banner != base_banner:
                    diff.changed_banners.append(
                        {
                            "ip": ip,
                            "port": port_num,
                            "old_banner": base_banner,
                            "new_banner": cur_banner,
                        }
                    )

        logger.info(
            "Diff computed: +%d hosts, -%d hosts, +%d ports, -%d ports, "
            "%d banner changes, %d MAC changes",
            len(diff.new_hosts),
            len(diff.removed_hosts),
            len(diff.new_ports),
            len(diff.removed_ports),
            len(diff.changed_banners),
            len(diff.mac_changes),
        )

        return diff


# =============================================================================
# NetScanner Agent
# =============================================================================


class NetScannerAgent(MicroProbeAgentMixin, HardenedAgentBase):
    """Network Scanner Agent with micro-probe architecture.

    Monitors network topology and services by scanning local subnets,
    detecting changes against a stored baseline, and running 7 specialized
    probes for threat detection.

    Attributes:
        scanner: NetworkScanner instance for data collection
        _baseline: Cached baseline scan results
    """

    def __init__(
        self,
        collection_interval: float = 300.0,  # 5 minutes
        *,
        device_id: Optional[str] = None,
        agent_name: str = "net_scanner",
        scan_ports: Optional[List[int]] = None,
        connect_timeout: float = 2.0,
        max_ports_per_second: int = 100,
        max_workers: int = 20,
        eventbus_publisher: Optional[Any] = None,
        local_queue: Optional[Any] = None,
        queue_adapter: Optional[Any] = None,
        metrics_interval: float = 60.0,
    ) -> None:
        """Initialize NetScanner Agent.

        Args:
            collection_interval: Seconds between scan cycles (default 300)
            device_id: Unique device identifier (defaults to hostname)
            agent_name: Agent name for logging/metrics
            scan_ports: Ports to scan (defaults to COMMON_SCAN_PORTS)
            connect_timeout: TCP connect timeout in seconds
            max_ports_per_second: Rate limit for port scanning
            max_workers: Max concurrent scan threads
            eventbus_publisher: EventBus client for publishing
            local_queue: LocalQueue for offline resilience
            queue_adapter: LocalQueueAdapter for simplified queue interface
            metrics_interval: Seconds between metrics emissions
        """
        # Auto-create infra when called via cli.run_agent() (zero-args path)
        _auto_infra = device_id is None
        device_id = device_id or socket.gethostname()

        if _auto_infra and eventbus_publisher is None:
            eventbus_publisher = EventBusPublisher(EVENTBUS_ADDRESS, CERT_DIR)

        if _auto_infra and queue_adapter is None:
            Path(QUEUE_PATH).parent.mkdir(parents=True, exist_ok=True)
            queue_adapter = LocalQueueAdapter(
                queue_path=QUEUE_PATH,
                agent_name=agent_name,
                device_id=device_id,
                max_bytes=50 * 1024 * 1024,
                max_retries=10,
                signing_key_path=f"{CERT_DIR}/agent.ed25519",
            )

        # Initialize MicroProbeAgentMixin + HardenedAgentBase
        super().__init__(
            agent_name=agent_name,
            device_id=device_id,
            collection_interval=collection_interval,
            eventbus_publisher=eventbus_publisher,
            local_queue=local_queue or queue_adapter,
            queue_adapter=queue_adapter,
            metrics_interval=metrics_interval,
        )

        # Create scanner/collector
        self.scanner = NetworkScanner(
            scan_ports=scan_ports,
            connect_timeout=connect_timeout,
            max_ports_per_second=max_ports_per_second,
            max_workers=max_workers,
            baseline_path=BASELINE_PATH,
        )

        # Cached baseline
        self._baseline: Optional[List[ScanResult]] = None

        # Stats
        self._total_scans: int = 0
        self._total_hosts_scanned: int = 0
        self._total_threats_detected: int = 0

    def setup(self) -> bool:
        """Initialize scanner and probes.

        Returns:
            True if setup succeeded, False otherwise
        """
        logger.info("Setting up %s for device %s", self.agent_name, self.device_id)

        # Load existing baseline
        self._baseline = self.scanner.load_baseline()
        if self._baseline:
            total_hosts = sum(len(r.hosts) for r in self._baseline)
            logger.info("Loaded baseline with %d hosts", total_hosts)
        else:
            logger.info("No baseline found - first scan will create baseline")

        # Register default probes
        if not self._probes:
            default_probes = create_net_scanner_probes()
            self.register_probes(default_probes)
            logger.info(
                "Registered %d default network scanner probes",
                len(default_probes),
            )

        # Initialize all probes with contract validation
        if not self.setup_probes(
            collector_shared_data_keys=[
                "scan_results",
                "scan_baseline",
                "scan_diff",
            ],
        ):
            logger.error("Failed to initialize any probes")
            return False

        logger.info(
            "%s setup complete: %d probes active",
            self.agent_name,
            len([p for p in self._probes if p.enabled]),
        )
        return True

    def collect_data(self) -> Sequence[TelemetryEvent]:
        """Perform network scan, compute diff, and run probes.

        Returns:
            List of TelemetryEvents from all probes
        """
        # Step 1: Perform network scan
        scan_results = self.scanner.collect()
        self._total_scans += 1
        total_hosts = sum(len(r.hosts) for r in scan_results)
        self._total_hosts_scanned += total_hosts

        if not scan_results:
            logger.warning("No scan results - network may be unreachable")
            return []

        logger.info(
            "Scan complete: %d subnet(s), %d host(s)",
            len(scan_results),
            total_hosts,
        )

        # Step 2: Compute diff against baseline
        diff = ScanDiff()
        if self._baseline:
            diff = self.scanner.compute_diff(scan_results, self._baseline)
        else:
            # First scan - all hosts/ports are "new"
            for result in scan_results:
                diff.new_hosts.extend(result.hosts)
            logger.info("First scan - %d new hosts detected", len(diff.new_hosts))

        # Step 3: Save current results as new baseline
        self.scanner.save_baseline(scan_results)
        self._baseline = scan_results

        # Step 4: Build probe context
        now_ns = int(time.time() * 1e9)
        context = ProbeContext(
            device_id=self.device_id,
            agent_name=self.agent_name,
            now_ns=now_ns,
            shared_data={
                "scan_results": scan_results,
                "scan_baseline": self._baseline,
                "scan_diff": diff,
            },
        )

        # Step 5: Run all probes
        events = self.run_probes(context)

        if events:
            self._total_threats_detected += len(events)
            logger.info(
                "Detected %d threats from %d hosts",
                len(events),
                total_hosts,
            )

        return events

    def get_health(self) -> Dict[str, Any]:
        """Get agent health status.

        Returns:
            Dict with health metrics
        """
        baseline_hosts = 0
        if self._baseline:
            baseline_hosts = sum(len(r.hosts) for r in self._baseline)

        return {
            "agent_name": self.agent_name,
            "device_id": self.device_id,
            "is_running": self.is_running,
            "uptime_seconds": time.time() - self.start_time,
            "collection_count": self.collection_count,
            "error_count": self.error_count,
            "last_error": self.last_error,
            "circuit_breaker_state": self.circuit_breaker.state,
            "total_scans": self._total_scans,
            "total_hosts_scanned": self._total_hosts_scanned,
            "total_threats_detected": self._total_threats_detected,
            "baseline_hosts": baseline_hosts,
            "scan_ports": len(self.scanner.scan_ports),
            "probes": self.get_probe_health(),
        }

    def shutdown(self) -> None:
        """Clean up resources on shutdown."""
        super().shutdown()
        if self.eventbus_publisher:
            self.eventbus_publisher.close()


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    "NetScannerAgent",
    "NetworkScanner",
    "MacOSNetworkCollector",
    "LinuxNetworkCollector",
    "BaseNetworkCollector",
]
