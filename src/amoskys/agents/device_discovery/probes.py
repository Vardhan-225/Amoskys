"""Micro-probes for DeviceDiscoveryV2 agent.

6 probes for network asset discovery and risk assessment:
    1. ARPDiscoveryProbe - ARP table enumeration (T1018)
    2. ActivePortScanFingerprintProbe - Service fingerprinting (T1046)
    3. NewDeviceRiskProbe - Risk scoring for new devices (T1200)
    4. RogueDHCPDNSProbe - Rogue DHCP/DNS server detection (T1557.001)
    5. ShadowITProbe - Unauthorized devices on network (T1200)
    6. VulnerabilityBannerProbe - Vulnerable service banners (T1595)
"""

from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredDevice:
    """Represents a discovered network device."""

    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    banners: Dict[int, str] = field(default_factory=dict)
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    is_new: bool = False
    risk_score: float = 0.0


class ARPDiscoveryProbe(MicroProbe):
    """Probe 1: ARP table enumeration for device discovery.

    Reads the local ARP cache to discover devices on the network.
    MITRE: T1018 - Remote System Discovery
    """

    name = "arp_discovery"
    description = "ARP table enumeration for device discovery"
    mitre_techniques = ["T1018"]

    def __init__(self):
        super().__init__()

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Read ARP cache and discover devices."""
        events = []
        devices: Dict[str, DiscoveredDevice] = context.shared_data.get("devices", {})
        known_ips: Set[str] = context.shared_data.get("known_ips", set())

        try:
            # Read ARP cache
            result = subprocess.run(
                ["ip", "neigh", "show"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode != 0:
                # Fallback to /proc/net/arp
                arp_entries = self._read_proc_arp()
            else:
                arp_entries = self._parse_ip_neigh(result.stdout)

            # Process entries
            for ip, mac in arp_entries.items():
                if ip not in devices:
                    devices[ip] = DiscoveredDevice(
                        ip=ip, mac=mac, is_new=ip not in known_ips
                    )
                    if ip not in known_ips:
                        events.append(
                            TelemetryEvent(
                                event_type="device_discovered",
                                probe_name=self.name,
                                severity=Severity.INFO,
                                data={
                                    "description": f"New device discovered via ARP: {ip} ({mac})",
                                    "ip": ip,
                                    "mac": mac,
                                    "source": "arp",
                                },
                            )
                        )
                else:
                    devices[ip].last_seen = datetime.utcnow()
                    devices[ip].mac = mac

            # Update shared data
            context.shared_data["devices"] = devices

        except Exception as e:
            logger.debug(f"ARP discovery error: {e}")

        return events

    def _read_proc_arp(self) -> Dict[str, str]:
        """Read /proc/net/arp as fallback."""
        entries = {}
        try:
            with open("/proc/net/arp", "r") as f:
                for line in f:
                    if line.startswith("IP"):
                        continue
                    parts = line.split()
                    if len(parts) >= 4:
                        ip, _, _, mac = parts[:4]
                        if mac != "00:00:00:00:00:00":
                            entries[ip] = mac
        except Exception:
            pass
        return entries

    def _parse_ip_neigh(self, output: str) -> Dict[str, str]:
        """Parse 'ip neigh show' output."""
        entries = {}
        for line in output.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 5 and "lladdr" in parts:
                ip = parts[0]
                mac_idx = parts.index("lladdr") + 1
                if mac_idx < len(parts):
                    entries[ip] = parts[mac_idx]
        return entries


class ActivePortScanFingerprintProbe(MicroProbe):
    """Probe 2: Active port scanning and service fingerprinting.

    Checks common ports on discovered devices for open services.
    MITRE: T1046 - Network Service Scanning
    """

    name = "port_scan_fingerprint"
    description = "Active port scanning and service fingerprinting"
    mitre_techniques = ["T1046"]

    COMMON_PORTS = [22, 80, 443, 8080, 8443, 3389, 5900, 23, 21]

    def __init__(self):
        super().__init__()

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan discovered devices for open ports."""
        events = []
        devices: Dict[str, DiscoveredDevice] = context.shared_data.get("devices", {})

        # Only scan new devices or those not yet scanned
        for ip, device in devices.items():
            if device.is_new or not device.open_ports:
                open_ports = self._quick_scan(ip)
                if open_ports:
                    device.open_ports = open_ports
                    events.append(
                        TelemetryEvent(
                            event_type="port_scan_result",
                            probe_name=self.name,
                            severity=Severity.INFO,
                            data={
                                "description": f"Open ports on {ip}: {open_ports}",
                                "ip": ip,
                                "open_ports": open_ports,
                            },
                        )
                    )

        return events

    def _quick_scan(self, ip: str, timeout: float = 0.5) -> List[int]:
        """Quick TCP connect scan."""
        import socket

        open_ports = []
        for port in self.COMMON_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    open_ports.append(port)
            except Exception:
                pass
        return open_ports


class NewDeviceRiskProbe(MicroProbe):
    """Probe 3: Risk scoring for new devices.

    Calculates risk score based on device characteristics.
    MITRE: T1200 - Hardware Additions
    """

    name = "new_device_risk"
    description = "Risk scoring for new devices on network"
    mitre_techniques = ["T1200"]

    def __init__(self):
        super().__init__()

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Calculate risk scores for new devices."""
        events = []
        devices: Dict[str, DiscoveredDevice] = context.shared_data.get("devices", {})

        for ip, device in devices.items():
            if device.is_new:
                risk_score = self._calculate_risk(device)
                device.risk_score = risk_score

                severity = Severity.LOW
                if risk_score >= 0.7:
                    severity = Severity.HIGH
                elif risk_score >= 0.4:
                    severity = Severity.MEDIUM

                if risk_score > 0.3:
                    events.append(
                        TelemetryEvent(
                            event_type="device_risk_assessment",
                            probe_name=self.name,
                            severity=severity,
                            data={
                                "description": f"New device risk assessment: {ip} (score: {risk_score:.2f})",
                                "ip": ip,
                                "risk_score": risk_score,
                                "open_ports": device.open_ports,
                                "factors": self._get_risk_factors(device),
                            },
                        )
                    )

                # Mark as no longer new after assessment
                device.is_new = False

        return events

    def _calculate_risk(self, device: DiscoveredDevice) -> float:
        """Calculate risk score 0.0-1.0."""
        score = 0.0

        # High-risk ports
        high_risk_ports = {23, 21, 3389, 5900, 445, 139, 2323, 5555}
        if any(p in high_risk_ports for p in device.open_ports):
            score += 0.3

        # Many open ports
        if len(device.open_ports) > 5:
            score += 0.2

        # Unknown/randomized MAC
        if device.mac and (
            device.mac.startswith("02:") or device.mac.startswith("00:00:00")
        ):
            score += 0.2

        # No hostname
        if not device.hostname:
            score += 0.1

        return min(score, 1.0)

    def _get_risk_factors(self, device: DiscoveredDevice) -> List[str]:
        """List risk factors for device."""
        factors = []
        high_risk_ports = {
            23: "telnet",
            21: "ftp",
            3389: "rdp",
            5900: "vnc",
            445: "smb",
        }
        for port in device.open_ports:
            if port in high_risk_ports:
                factors.append(f"high_risk_port_{high_risk_ports[port]}")
        if len(device.open_ports) > 5:
            factors.append("many_open_ports")
        if not device.hostname:
            factors.append("no_hostname")
        return factors


class RogueDHCPDNSProbe(MicroProbe):
    """Probe 4: Rogue DHCP/DNS server detection.

    Detects unauthorized DHCP or DNS servers on the network.
    MITRE: T1557.001 - LLMNR/NBT-NS Poisoning
    """

    name = "rogue_dhcp_dns"
    description = "Rogue DHCP/DNS server detection"
    mitre_techniques = ["T1557.001"]

    def __init__(
        self,
        authorized_dhcp: Optional[Set[str]] = None,
        authorized_dns: Optional[Set[str]] = None,
    ):
        super().__init__()
        self.authorized_dhcp = authorized_dhcp or set()
        self.authorized_dns = authorized_dns or set()

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Check for rogue DHCP/DNS servers."""
        events = []
        devices: Dict[str, DiscoveredDevice] = context.shared_data.get("devices", {})

        for ip, device in devices.items():
            # Check for DHCP server (port 67)
            if 67 in device.open_ports and ip not in self.authorized_dhcp:
                events.append(
                    TelemetryEvent(
                        event_type="rogue_dhcp",
                        probe_name=self.name,
                        severity=Severity.CRITICAL,
                        data={
                            "description": f"ROGUE DHCP SERVER DETECTED: {ip}",
                            "ip": ip,
                            "mac": device.mac,
                            "authorized_servers": list(self.authorized_dhcp),
                        },
                    )
                )

            # Check for DNS server (port 53)
            if 53 in device.open_ports and ip not in self.authorized_dns:
                events.append(
                    TelemetryEvent(
                        event_type="rogue_dns",
                        probe_name=self.name,
                        severity=Severity.HIGH,
                        data={
                            "description": f"Unauthorized DNS server detected: {ip}",
                            "ip": ip,
                            "mac": device.mac,
                            "authorized_servers": list(self.authorized_dns),
                        },
                    )
                )

        return events


class ShadowITProbe(MicroProbe):
    """Probe 5: Shadow IT device detection.

    Identifies unauthorized devices based on MAC prefix (OUI) or behavior.
    MITRE: T1200 - Hardware Additions
    """

    name = "shadow_it"
    description = "Shadow IT device detection"
    mitre_techniques = ["T1200"]

    # Common consumer device OUIs (not enterprise)
    CONSUMER_OUIS = {
        "b8:27:eb": "Raspberry Pi",
        "dc:a6:32": "Raspberry Pi",
        "e4:5f:01": "Raspberry Pi",
        "00:1a:79": "Allied Telesis",
        "44:61:32": "ecobee",
        "18:b4:30": "Nest",
        "ac:bc:32": "Amazon",
        "f0:f6:1c": "Google",
        "00:18:0a": "Linksys",
    }

    def __init__(self, allowed_macs: Optional[Set[str]] = None):
        super().__init__()
        self.allowed_macs = allowed_macs or set()

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect potential shadow IT devices."""
        events = []
        devices: Dict[str, DiscoveredDevice] = context.shared_data.get("devices", {})

        for ip, device in devices.items():
            if device.mac and device.mac.lower() not in self.allowed_macs:
                oui = device.mac[:8].lower()
                if oui in self.CONSUMER_OUIS:
                    events.append(
                        TelemetryEvent(
                            event_type="shadow_it",
                            probe_name=self.name,
                            severity=Severity.HIGH,
                            data={
                                "description": f"Potential Shadow IT: {self.CONSUMER_OUIS[oui]} device at {ip}",
                                "ip": ip,
                                "mac": device.mac,
                                "device_type": self.CONSUMER_OUIS[oui],
                                "oui": oui,
                            },
                        )
                    )

        return events


class VulnerabilityBannerProbe(MicroProbe):
    """Probe 6: Vulnerable service banner detection.

    Grabs service banners and checks for known vulnerable versions.
    MITRE: T1595 - Active Scanning
    """

    name = "vulnerability_banner"
    description = "Vulnerable service banner detection"
    mitre_techniques = ["T1595"]

    # Simplified vulnerable version patterns
    VULNERABLE_PATTERNS = [
        (r"OpenSSH[/_]([0-6]\.|7\.[0-5])", "OpenSSH < 7.6", Severity.HIGH),
        (r"Apache/2\.2\.", "Apache 2.2.x (EOL)", Severity.MEDIUM),
        (
            r"Apache/2\.4\.([0-9]|[12][0-9]|3[0-9])[^0-9]",
            "Apache 2.4.x < 2.4.40",
            Severity.MEDIUM,
        ),
        (r"nginx/1\.(0|1|2|3|4|5|6|7|8|9|1[0-4])\.", "nginx < 1.15", Severity.MEDIUM),
        (r"vsftpd 2\.", "vsftpd 2.x", Severity.HIGH),
        (r"ProFTPD 1\.[0-2]", "ProFTPD < 1.3", Severity.HIGH),
        (r"Telnet", "Telnet (insecure)", Severity.CRITICAL),
    ]

    def __init__(self):
        super().__init__()

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Check service banners for vulnerabilities."""
        events = []
        devices: Dict[str, DiscoveredDevice] = context.shared_data.get("devices", {})

        for ip, device in devices.items():
            for port in device.open_ports:
                if port not in device.banners:
                    banner = self._grab_banner(ip, port)
                    if banner:
                        device.banners[port] = banner

            # Check banners for vulnerabilities
            for port, banner in device.banners.items():
                for pattern, vuln_name, severity in self.VULNERABLE_PATTERNS:
                    if re.search(pattern, banner, re.IGNORECASE):
                        events.append(
                            TelemetryEvent(
                                event_type="vulnerable_banner",
                                probe_name=self.name,
                                severity=severity,
                                data={
                                    "description": f"Vulnerable service: {vuln_name} on {ip}:{port}",
                                    "ip": ip,
                                    "port": port,
                                    "vulnerability": vuln_name,
                                    "banner": banner[:200],
                                },
                            )
                        )
                        break  # One alert per port

        return events

    def _grab_banner(self, ip: str, port: int, timeout: float = 2.0) -> Optional[str]:
        """Grab service banner from port."""
        import socket

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))

            # Send minimal probe for HTTP
            if port in (80, 8080, 8443, 443):
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")

            banner = sock.recv(1024).decode("utf-8", errors="ignore")
            sock.close()
            return banner.strip()[:500]
        except Exception:
            return None


# All probes for export
DEVICE_DISCOVERY_PROBES: List[MicroProbe] = [
    ARPDiscoveryProbe(),
    ActivePortScanFingerprintProbe(),
    NewDeviceRiskProbe(),
    RogueDHCPDNSProbe(),
    ShadowITProbe(),
    VulnerabilityBannerProbe(),
]


def create_device_discovery_probes() -> List[MicroProbe]:
    """Factory function for Observability Contract audit."""
    return list(DEVICE_DISCOVERY_PROBES)
