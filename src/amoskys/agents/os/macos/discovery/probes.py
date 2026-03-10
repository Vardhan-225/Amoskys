"""macOS Device Discovery Observatory probes — network device threat detection.

6 probes covering TA0007 Discovery and related tactics:
    1. ARPDiscoveryProbe      — T1018 Remote System Discovery (ARP changes)
    2. BonjourServiceProbe    — T1046 Network Service Discovery (mDNS)
    3. RogueDHCPProbe         — T1557.001 LLMNR/NBT-NS Poisoning (rogue DHCP)
    4. NetworkTopologyProbe   — T1016 System Network Configuration Discovery
    5. NewDeviceRiskProbe     — T1200 Hardware Additions (unknown MAC vendors)
    6. PortScanDetectorProbe  — T1046 Network Service Discovery (scan patterns)
"""

from __future__ import annotations

import collections
import logging
import time
from typing import Any, Dict, List, Optional, Set

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)

logger = logging.getLogger(__name__)


# -- Shared utilities ---------------------------------------------------------


# Known MAC OUI prefixes for common/trusted vendors (first 3 octets)
_KNOWN_MAC_VENDORS: Dict[str, str] = {
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "00:1c:42": "Parallels",
    "08:00:27": "VirtualBox",
    "00:03:93": "Apple",
    "00:05:02": "Apple",
    "00:0a:27": "Apple",
    "00:0a:95": "Apple",
    "00:0d:93": "Apple",
    "00:10:fa": "Apple",
    "00:11:24": "Apple",
    "00:14:51": "Apple",
    "00:16:cb": "Apple",
    "00:17:f2": "Apple",
    "00:19:e3": "Apple",
    "00:1b:63": "Apple",
    "00:1c:b3": "Apple",
    "00:1d:4f": "Apple",
    "00:1e:52": "Apple",
    "00:1e:c2": "Apple",
    "00:1f:5b": "Apple",
    "00:1f:f3": "Apple",
    "00:21:e9": "Apple",
    "00:22:41": "Apple",
    "00:23:12": "Apple",
    "00:23:32": "Apple",
    "00:23:6c": "Apple",
    "00:23:df": "Apple",
    "00:24:36": "Apple",
    "00:25:00": "Apple",
    "00:25:4b": "Apple",
    "00:25:bc": "Apple",
    "00:26:08": "Apple",
    "00:26:4a": "Apple",
    "00:26:b0": "Apple",
    "00:26:bb": "Apple",
    "00:30:65": "Apple",
    "00:3e:e1": "Apple",
    "00:50:e4": "Apple",
    "00:61:71": "Apple",
    "04:0c:ce": "Apple",
    "04:15:52": "Apple",
    "04:26:65": "Apple",
    "04:48:9a": "Apple",
    "04:54:53": "Apple",
    "04:db:56": "Apple",
    "04:f1:3e": "Apple",
    "08:66:98": "Apple",
    "0c:4d:e9": "Apple",
    "10:40:f3": "Apple",
    "14:10:9f": "Apple",
    "18:af:61": "Apple",
    "20:78:f0": "Apple",
    "24:a0:74": "Apple",
    "28:cf:e9": "Apple",
    "2c:be:08": "Apple",
    "34:36:3b": "Apple",
    "38:c9:86": "Apple",
    "3c:07:54": "Apple",
    "40:33:1a": "Apple",
    "44:2a:60": "Apple",
    "48:60:bc": "Apple",
    "4c:32:75": "Apple",
    "50:ea:d6": "Apple",
    "54:26:96": "Apple",
    "58:55:ca": "Apple",
    "5c:59:48": "Apple",
    "60:03:08": "Apple",
    "64:20:0c": "Apple",
    "68:5b:35": "Apple",
    "6c:40:08": "Apple",
    "70:56:81": "Apple",
    "74:e2:f5": "Apple",
    "78:31:c1": "Apple",
    "7c:c3:a1": "Apple",
    "80:00:6e": "Apple",
    "84:38:35": "Apple",
    "88:66:a5": "Apple",
    "8c:29:37": "Apple",
    "90:84:0d": "Apple",
    "98:01:a7": "Apple",
    "9c:20:7b": "Apple",
    "a0:99:9b": "Apple",
    "a4:5e:60": "Apple",
    "a8:20:66": "Apple",
    "a8:88:08": "Apple",
    "ac:87:a3": "Apple",
    "b0:34:95": "Apple",
    "b4:18:d1": "Apple",
    "b8:17:c2": "Apple",
    "b8:c1:11": "Apple",
    "bc:52:b7": "Apple",
    "c0:9a:d0": "Apple",
    "c4:2c:03": "Apple",
    "c8:2a:14": "Apple",
    "cc:08:e0": "Apple",
    "d0:25:98": "Apple",
    "d4:61:9d": "Apple",
    "d8:30:62": "Apple",
    "dc:2b:2a": "Apple",
    "e0:5f:45": "Apple",
    "e4:25:e7": "Apple",
    "e8:06:88": "Apple",
    "f0:b4:79": "Apple",
    "f4:5c:89": "Apple",
    "f8:1e:df": "Apple",
    "fc:25:3f": "Apple",
    # Common networking vendors
    "00:18:0a": "Cisco",
    "00:1a:a1": "Cisco",
    "00:1b:0d": "Cisco",
    "00:50:0f": "Cisco",
    "b0:b8:67": "Cisco",
    "00:17:88": "Philips Hue",
    "ec:b5:fa": "Philips Hue",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    "30:b5:c2": "TP-Link",
    "50:c7:bf": "TP-Link",
    "60:e3:27": "TP-Link",
    "34:17:eb": "Dell",
    "b8:ac:6f": "Dell",
    "00:0e:c6": "HP",
    "3c:d9:2b": "HP",
    "f4:39:09": "HP",
    "28:16:a8": "Intel",
    "3c:97:0e": "Intel",
    "68:05:ca": "Intel",
    "a4:c4:94": "Intel",
    "b4:96:91": "Intel",
    "48:2c:a0": "Samsung",
    "50:01:bb": "Samsung",
    "ac:36:13": "Samsung",
    "30:07:4d": "Sony",
    "fc:f1:52": "Sony",
    "ff:ff:ff": "Broadcast",
}


def _lookup_mac_vendor(mac: str) -> Optional[str]:
    """Look up vendor from MAC OUI prefix."""
    oui = mac.lower()[:8]  # First 3 octets (aa:bb:cc)
    return _KNOWN_MAC_VENDORS.get(oui)


from amoskys.agents.common.ip_utils import is_private_ip as _is_private_ip

# -- Probe 1: ARP Discovery --------------------------------------------------


class ARPDiscoveryProbe(MicroProbe):
    """Detect ARP table changes — new hosts appearing on the network.

    MITRE: T1018 — Remote System Discovery

    Tracks ARP table over time and alerts when new IP/MAC pairs appear
    that were not in the baseline. New hosts on the network can indicate
    lateral movement, rogue devices, or MITM preparation.
    """

    name = "macos_discovery_arp"
    description = "Detects ARP table changes and new hosts via baseline-diff"
    platforms = ["darwin"]
    mitre_techniques = ["T1018"]
    mitre_tactics = ["discovery"]
    scan_interval = 15.0
    requires_fields = ["arp_entries"]
    maturity = "stable"
    supports_baseline = True
    baseline_window_hours = 168  # 7-day baseline
    false_positive_notes = [
        "DHCP lease renewals can cause MAC address changes for same IP",
        "Guest devices on shared networks trigger frequent new host alerts",
        "Virtual machines with dynamic MACs appear as new devices",
    ]
    evasion_notes = [
        "Attacker spoofing a known MAC address will not trigger new-host alert",
        "Very slow host enumeration (one host per hour) may blend into normal traffic",
    ]

    BASELINE_CYCLES = 3  # Skip first N cycles to build baseline

    def __init__(self) -> None:
        super().__init__()
        # Known IP→MAC mapping baseline
        self._known_hosts: Dict[str, str] = {}  # ip → mac
        self._cycle_count = 0

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        arp_entries = context.shared_data.get("arp_entries", [])
        self._cycle_count += 1

        new_this_cycle: list[tuple[str, str, str]] = []  # (ip, mac, iface)
        changed_this_cycle: list[tuple[str, str, str, str]] = (
            []
        )  # (ip, new_mac, old_mac, iface)

        for entry in arp_entries:
            prev_mac = self._known_hosts.get(entry.ip)

            if prev_mac is None:
                # New host
                new_this_cycle.append((entry.ip, entry.mac, entry.interface))
            elif prev_mac != entry.mac:
                # MAC changed for known IP — potential ARP spoofing
                changed_this_cycle.append(
                    (entry.ip, entry.mac, prev_mac, entry.interface)
                )

            self._known_hosts[entry.ip] = entry.mac

        # Only alert after baseline is established
        if self._cycle_count <= self.BASELINE_CYCLES:
            return events

        # Alert on new hosts
        for ip, mac, iface in new_this_cycle:
            vendor = _lookup_mac_vendor(mac) or "Unknown"
            events.append(
                self._create_event(
                    event_type="arp_new_host",
                    severity=Severity.MEDIUM,
                    data={
                        "ip": ip,
                        "mac": mac,
                        "interface": iface,
                        "vendor": vendor,
                        "baseline_size": len(self._known_hosts),
                        "cycle": self._cycle_count,
                    },
                    confidence=0.65,
                )
            )

        # Alert on MAC changes (potential ARP spoofing)
        for ip, new_mac, old_mac, iface in changed_this_cycle:
            events.append(
                self._create_event(
                    event_type="arp_mac_changed",
                    severity=Severity.HIGH,
                    data={
                        "ip": ip,
                        "new_mac": new_mac,
                        "old_mac": old_mac,
                        "interface": iface,
                        "new_vendor": _lookup_mac_vendor(new_mac) or "Unknown",
                        "old_vendor": _lookup_mac_vendor(old_mac) or "Unknown",
                    },
                    confidence=0.80,
                )
            )

        return events


# -- Probe 2: Bonjour Service Discovery --------------------------------------


class BonjourServiceProbe(MicroProbe):
    """Detect new or unexpected mDNS/Bonjour services on the network.

    MITRE: T1046 — Network Service Discovery

    Monitors Bonjour service advertisements for unexpected services that could
    indicate lateral movement tooling, rogue services, or network reconnaissance.
    Tracks baseline of known services and alerts on new discoveries.
    """

    name = "macos_discovery_bonjour"
    description = "Detects new/unexpected mDNS/Bonjour services on network"
    platforms = ["darwin"]
    mitre_techniques = ["T1046"]
    mitre_tactics = ["discovery"]
    scan_interval = 30.0
    requires_fields = ["bonjour_services"]
    maturity = "stable"
    supports_baseline = True
    baseline_window_hours = 168  # 7-day baseline
    false_positive_notes = [
        "New legitimate devices (printers, AirPlay) trigger service alerts",
        "Software updates may register new Bonjour service types",
        "HomeKit devices frequently appear and disappear",
    ]
    evasion_notes = [
        "Attacker can disable mDNS advertisement while still running services",
        "Using non-standard service types avoids matching known suspicious types",
    ]

    BASELINE_CYCLES = 3

    # Service types that are more suspicious
    _SUSPICIOUS_SERVICES = frozenset(
        {
            "_ssh._tcp",
            "_sftp-ssh._tcp",
            "_rfb._tcp",  # VNC
            "_smb._tcp",  # SMB file sharing
            "_ftp._tcp",
            "_telnet._tcp",
            "_http._tcp",
            "_https._tcp",
            "_nfs._tcp",
            "_afpovertcp._tcp",  # AFP file sharing
            "_vnc._tcp",
            "_rdp._tcp",
            "_netbios-ns._tcp",
        }
    )

    def __init__(self) -> None:
        super().__init__()
        # Known services: (name, service_type, domain) set
        self._known_services: Set[tuple[str, str, str]] = set()
        self._cycle_count = 0

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        services = context.shared_data.get("bonjour_services", [])
        self._cycle_count += 1

        new_this_cycle: list[Any] = []

        for service in services:
            key = (service.name, service.service_type, service.domain)
            if key not in self._known_services:
                new_this_cycle.append(service)
            self._known_services.add(key)

        # Only alert after baseline is established
        if self._cycle_count <= self.BASELINE_CYCLES:
            return events

        for service in new_this_cycle:
            is_suspicious = service.service_type in self._SUSPICIOUS_SERVICES
            severity = Severity.HIGH if is_suspicious else Severity.MEDIUM

            events.append(
                self._create_event(
                    event_type="bonjour_new_service",
                    severity=severity,
                    data={
                        "name": service.name,
                        "service_type": service.service_type,
                        "domain": service.domain,
                        "interface": service.interface,
                        "is_suspicious_type": is_suspicious,
                        "baseline_size": len(self._known_services),
                        "cycle": self._cycle_count,
                    },
                    confidence=0.75 if is_suspicious else 0.50,
                )
            )

        return events


# -- Probe 3: Rogue DHCP Detection -------------------------------------------


class RogueDHCPProbe(MicroProbe):
    """Detect multiple DHCP servers or gateways indicating rogue DHCP.

    MITRE: T1557.001 — Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning
    and SMB Relay (extended to rogue DHCP detection)

    Multiple default gateways or unexpected gateway changes can indicate a
    rogue DHCP server performing MITM attacks. We detect this by analyzing
    the routing table for multiple default routes and gateway anomalies.
    """

    name = "macos_discovery_rogue_dhcp"
    description = "Detects multiple DHCP servers/gateways via routing anomaly"
    platforms = ["darwin"]
    mitre_techniques = ["T1557.001"]
    mitre_tactics = ["credential_access"]
    scan_interval = 30.0
    requires_fields = ["routes", "arp_entries"]
    maturity = "experimental"
    false_positive_notes = [
        "Multi-homed hosts with multiple NICs legitimately have multiple gateways",
        "VPN connections add additional default routes",
        "Load balancing setups may use multiple gateways",
    ]
    evasion_notes = [
        "Rogue DHCP on same subnet with identical gateway IP avoids detection",
        "Attacker taking over existing DHCP server maintains single gateway",
    ]

    def __init__(self) -> None:
        super().__init__()
        self._known_gateways: Set[str] = set()
        self._baseline_built = False

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        routes = context.shared_data.get("routes", [])
        arp_entries = context.shared_data.get("arp_entries", [])

        # Find default gateways (destination = "default" or "0.0.0.0")
        default_gateways: list[tuple[str, str]] = []  # (gateway_ip, interface)
        for route in routes:
            if route.destination in ("default", "0.0.0.0", "0/0"):
                if route.gateway and route.gateway != "*":
                    default_gateways.append((route.gateway, route.interface))

        current_gateway_ips = {gw for gw, _ in default_gateways}

        # Build baseline on first run
        if not self._baseline_built:
            self._known_gateways = current_gateway_ips.copy()
            self._baseline_built = True
            return events

        # Check 1: Multiple default gateways on same interface
        gateways_by_iface: Dict[str, list[str]] = collections.defaultdict(list)
        for gw, iface in default_gateways:
            gateways_by_iface[iface].append(gw)

        for iface, gws in gateways_by_iface.items():
            if len(gws) > 1:
                events.append(
                    self._create_event(
                        event_type="rogue_dhcp_multiple_gateways",
                        severity=Severity.CRITICAL,
                        data={
                            "interface": iface,
                            "gateways": gws,
                            "gateway_count": len(gws),
                            "known_gateways": sorted(self._known_gateways),
                        },
                        confidence=0.85,
                    )
                )

        # Check 2: New gateway not in baseline
        new_gateways = current_gateway_ips - self._known_gateways
        for gw in new_gateways:
            # Look up the gateway's MAC in ARP table
            gw_mac = ""
            for entry in arp_entries:
                if entry.ip == gw:
                    gw_mac = entry.mac
                    break

            events.append(
                self._create_event(
                    event_type="rogue_dhcp_new_gateway",
                    severity=Severity.HIGH,
                    data={
                        "gateway": gw,
                        "gateway_mac": gw_mac,
                        "gateway_vendor": (
                            _lookup_mac_vendor(gw_mac) or "Unknown"
                            if gw_mac
                            else "Unknown"
                        ),
                        "known_gateways": sorted(self._known_gateways),
                    },
                    confidence=0.75,
                )
            )

        # Update known gateways
        self._known_gateways.update(current_gateway_ips)

        return events


# -- Probe 4: Network Topology Changes ---------------------------------------


class NetworkTopologyProbe(MicroProbe):
    """Detect interface and route changes — new interfaces, gateway changes.

    MITRE: T1016 — System Network Configuration Discovery

    Monitors hardware ports and routing table for topology changes. New
    interfaces (USB Ethernet, Thunderbolt) or route changes can indicate
    physical access attacks or network reconfiguration by an adversary.
    """

    name = "macos_discovery_topology"
    description = "Detects interface/route changes (new interfaces, gateway changes)"
    platforms = ["darwin"]
    mitre_techniques = ["T1016"]
    mitre_tactics = ["discovery"]
    scan_interval = 30.0
    requires_fields = ["hardware_ports", "routes"]
    maturity = "stable"
    false_positive_notes = [
        "Plugging in USB Ethernet or Thunderbolt adapters triggers interface alerts",
        "VPN connections create new virtual interfaces",
        "Wi-Fi roaming between access points may change routes",
    ]
    evasion_notes = [
        "Software-defined interfaces may not appear in networksetup",
        "Tunnel interfaces created by kernel modules bypass hardware port listing",
    ]

    def __init__(self) -> None:
        super().__init__()
        self._known_devices: Set[str] = set()  # device names (en0, en1, etc.)
        self._known_routes: Set[tuple[str, str, str]] = set()  # (dest, gw, iface)
        self._baseline_built = False

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        hardware_ports = context.shared_data.get("hardware_ports", [])
        routes = context.shared_data.get("routes", [])

        current_devices = {p.device for p in hardware_ports}
        current_routes = {(r.destination, r.gateway, r.interface) for r in routes}

        if not self._baseline_built:
            self._known_devices = current_devices.copy()
            self._known_routes = current_routes.copy()
            self._baseline_built = True
            return events

        # Check 1: New hardware interfaces
        new_devices = current_devices - self._known_devices
        for device in new_devices:
            # Find the port info
            port_info = next((p for p in hardware_ports if p.device == device), None)
            events.append(
                self._create_event(
                    event_type="topology_new_interface",
                    severity=Severity.HIGH,
                    data={
                        "device": device,
                        "port_name": port_info.name if port_info else "Unknown",
                        "mac": port_info.mac if port_info else "",
                        "vendor": (
                            _lookup_mac_vendor(port_info.mac) or "Unknown"
                            if port_info and port_info.mac
                            else "Unknown"
                        ),
                        "known_devices": sorted(self._known_devices),
                    },
                    confidence=0.70,
                )
            )

        # Check 2: Removed hardware interfaces (potential tampering)
        removed_devices = self._known_devices - current_devices
        for device in removed_devices:
            events.append(
                self._create_event(
                    event_type="topology_interface_removed",
                    severity=Severity.MEDIUM,
                    data={
                        "device": device,
                        "known_devices": sorted(self._known_devices),
                        "current_devices": sorted(current_devices),
                    },
                    confidence=0.55,
                )
            )

        # Check 3: New routes added
        new_routes = current_routes - self._known_routes
        for dest, gw, iface in new_routes:
            # Only alert on significant routes (not link-local noise)
            if dest.startswith("169.254") or dest.startswith("ff"):
                continue
            events.append(
                self._create_event(
                    event_type="topology_new_route",
                    severity=Severity.LOW,
                    data={
                        "destination": dest,
                        "gateway": gw,
                        "interface": iface,
                    },
                    confidence=0.45,
                )
            )

        # Update baselines
        self._known_devices = current_devices.copy()
        self._known_routes = current_routes.copy()

        return events


# -- Probe 5: New Device Risk Scoring ----------------------------------------


class NewDeviceRiskProbe(MicroProbe):
    """Risk score for new network devices based on MAC vendor analysis.

    MITRE: T1200 — Hardware Additions

    New devices from unknown vendors or with suspicious MAC patterns pose
    higher risk. This probe assigns risk scores based on vendor reputation,
    MAC randomization indicators, and device behavior patterns.
    """

    name = "macos_discovery_new_device_risk"
    description = "Risk scores new network devices by MAC vendor analysis"
    platforms = ["darwin"]
    mitre_techniques = ["T1200"]
    mitre_tactics = ["initial_access"]
    scan_interval = 30.0
    requires_fields = ["arp_entries"]
    maturity = "experimental"
    supports_baseline = True
    baseline_window_hours = 168  # 7-day baseline
    false_positive_notes = [
        "Apple devices with Private Wi-Fi Address use randomized MACs",
        "IoT devices from small vendors may have unknown OUI prefixes",
        "Guest devices on shared networks are legitimate unknowns",
    ]
    evasion_notes = [
        "Attacker can spoof a known vendor's MAC OUI prefix",
        "Using locally administered MAC addresses mimics Private Wi-Fi Address",
    ]

    BASELINE_CYCLES = 3
    RISK_THRESHOLD = 0.6  # Only alert above this risk score

    def __init__(self) -> None:
        super().__init__()
        self._known_macs: Set[str] = set()
        self._cycle_count = 0

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        arp_entries = context.shared_data.get("arp_entries", [])
        self._cycle_count += 1

        for entry in arp_entries:
            mac = entry.mac.lower()

            if mac in self._known_macs:
                continue

            # Only score and alert after baseline established
            if self._cycle_count > self.BASELINE_CYCLES:
                risk_score = self._calculate_risk_score(entry)

                if risk_score >= self.RISK_THRESHOLD:
                    vendor = _lookup_mac_vendor(mac) or "Unknown"
                    is_randomized = self._is_randomized_mac(mac)

                    events.append(
                        self._create_event(
                            event_type="new_device_high_risk",
                            severity=(
                                Severity.HIGH if risk_score >= 0.8 else Severity.MEDIUM
                            ),
                            data={
                                "ip": entry.ip,
                                "mac": mac,
                                "interface": entry.interface,
                                "vendor": vendor,
                                "risk_score": round(risk_score, 3),
                                "is_randomized_mac": is_randomized,
                                "is_private_ip": _is_private_ip(entry.ip),
                                "baseline_size": len(self._known_macs),
                                "cycle": self._cycle_count,
                            },
                            confidence=min(0.90, risk_score),
                        )
                    )

            self._known_macs.add(mac)

        return events

    def _calculate_risk_score(self, entry: Any) -> float:
        """Calculate risk score for a new device (0.0 - 1.0)."""
        score = 0.3  # Base risk for any new device

        mac = entry.mac.lower()
        vendor = _lookup_mac_vendor(mac)

        # Unknown vendor — higher risk
        if not vendor:
            score += 0.3

        # Randomized MAC (locally administered bit set) — higher risk
        if self._is_randomized_mac(mac):
            score += 0.15

        # Broadcast or multicast MAC — unusual
        if mac == "ff:ff:ff:ff:ff:ff":
            score += 0.2

        # Private IP range — somewhat expected
        if _is_private_ip(entry.ip):
            score -= 0.1

        # Permanent ARP entry — less suspicious (admin configured)
        if entry.is_permanent:
            score -= 0.2

        return max(0.0, min(1.0, score))

    @staticmethod
    def _is_randomized_mac(mac: str) -> bool:
        """Check if MAC has the locally administered bit set (randomized)."""
        try:
            first_octet = int(mac.split(":")[0], 16)
            return bool(first_octet & 0x02)  # Locally administered bit
        except (ValueError, IndexError):
            return False


# -- Probe 6: Port Scan Detector ---------------------------------------------


class PortScanDetectorProbe(MicroProbe):
    """Detect inbound port scanning patterns from ARP and routing data.

    MITRE: T1046 — Network Service Discovery

    Detects port scanning patterns by analyzing ARP table changes. A single
    IP rapidly appearing in ARP entries across multiple interfaces, or
    many new ARP entries from the same subnet in a short window, suggests
    network scanning activity.
    """

    name = "macos_discovery_port_scan"
    description = (
        "Detects inbound port scanning patterns (many connections from single IP)"
    )
    platforms = ["darwin"]
    mitre_techniques = ["T1046"]
    mitre_tactics = ["discovery"]
    scan_interval = 15.0
    requires_fields = ["arp_entries"]
    maturity = "experimental"
    false_positive_notes = [
        "Network monitoring tools (Nmap, Wireshark) generate legitimate scan patterns",
        "DHCP renewals across a subnet can look like scanning",
        "Network discovery protocols (SSDP, mDNS) generate broad ARP activity",
    ]
    evasion_notes = [
        "Very slow scanning (one port per minute) avoids burst detection",
        "Scanning from multiple source IPs distributes the pattern",
        "Idle scanning (using zombie hosts) hides the true source",
    ]

    # Thresholds
    NEW_HOSTS_BURST_THRESHOLD = 10  # New ARP entries per cycle → scan indicator
    SUBNET_BURST_THRESHOLD = 8  # New hosts in same /24 subnet → targeted scan
    WINDOW_CYCLES = 3  # Number of cycles to aggregate

    def __init__(self) -> None:
        super().__init__()
        self._known_ips: Set[str] = set()
        self._recent_new_ips: List[tuple[str, float]] = []  # (ip, timestamp)
        self._baseline_built = False

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        arp_entries = context.shared_data.get("arp_entries", [])
        now = time.time()

        current_ips = {entry.ip for entry in arp_entries}

        if not self._baseline_built:
            self._known_ips = current_ips.copy()
            self._baseline_built = True
            return events

        # Track new IPs this cycle
        new_ips = current_ips - self._known_ips
        for ip in new_ips:
            self._recent_new_ips.append((ip, now))

        # Trim old entries (keep last 5 minutes)
        cutoff = now - 300
        self._recent_new_ips = [
            (ip, ts) for ip, ts in self._recent_new_ips if ts > cutoff
        ]

        recent_new = [ip for ip, _ in self._recent_new_ips]

        # Check 1: Burst of new hosts across the network
        if len(recent_new) >= self.NEW_HOSTS_BURST_THRESHOLD:
            events.append(
                self._create_event(
                    event_type="port_scan_host_burst",
                    severity=Severity.HIGH,
                    data={
                        "new_host_count": len(recent_new),
                        "threshold": self.NEW_HOSTS_BURST_THRESHOLD,
                        "sample_ips": sorted(recent_new)[:15],
                        "window_seconds": 300,
                        "baseline_size": len(self._known_ips),
                    },
                    confidence=0.75,
                )
            )

        # Check 2: Many new hosts in same /24 subnet (targeted scan)
        subnet_counts: Dict[str, list[str]] = collections.defaultdict(list)
        for ip in recent_new:
            parts = ip.split(".")
            if len(parts) == 4:
                subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                subnet_counts[subnet].append(ip)

        for subnet, ips in subnet_counts.items():
            if len(ips) >= self.SUBNET_BURST_THRESHOLD:
                events.append(
                    self._create_event(
                        event_type="port_scan_subnet_sweep",
                        severity=Severity.CRITICAL,
                        data={
                            "subnet": subnet,
                            "new_host_count": len(ips),
                            "threshold": self.SUBNET_BURST_THRESHOLD,
                            "hosts": sorted(ips)[:20],
                            "window_seconds": 300,
                        },
                        confidence=0.85,
                    )
                )

        # Update known IPs
        self._known_ips.update(current_ips)

        return events


# -- Factory ------------------------------------------------------------------


def create_discovery_probes() -> List[MicroProbe]:
    """Create all macOS Device Discovery Observatory probes."""
    return [
        ARPDiscoveryProbe(),
        BonjourServiceProbe(),
        RogueDHCPProbe(),
        NetworkTopologyProbe(),
        NewDeviceRiskProbe(),
        PortScanDetectorProbe(),
    ]
