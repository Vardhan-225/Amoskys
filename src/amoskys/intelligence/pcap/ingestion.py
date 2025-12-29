"""
Real-time PCAP Ingestion Engine for Microprocessor Agent
Provides comprehensive packet capture and analysis capabilities for all device types.
"""

import asyncio
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Dict, List, Optional, Callable, Any, Set, Union
from queue import Queue, Full
import json

try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.dns import DNS
    from scapy.layers.dhcp import DHCP

    SCAPY_AVAILABLE = True
except ImportError:
    scapy = None
    IP = TCP = UDP = ICMP = Ether = ARP = DNS = DHCP = None
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not available. Install with: pip install scapy")

try:
    import dpkt

    DPKT_AVAILABLE = True
except ImportError:
    dpkt = None
    DPKT_AVAILABLE = False
    logging.warning("dpkt not available. Install with: pip install dpkt")


@dataclass
class PacketMetadata:
    """Comprehensive packet metadata for analysis."""

    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    packet_size: int
    payload_size: int
    flags: Dict[str, bool]
    device_type: Optional[str] = None
    anomaly_score: float = 0.0
    threat_indicators: Optional[List[str]] = None


@dataclass
class FlowRecord:
    """Network flow record for analysis."""

    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    last_seen: float
    packet_count: int
    byte_count: int
    flags: Set[str]
    device_fingerprint: Optional[str] = None


class PacketProcessor:
    """High-performance packet processing engine."""

    def __init__(self, max_queue_size: int = 10000):
        self.logger = logging.getLogger(__name__)
        self.packet_queue = Queue(maxsize=max_queue_size)
        self.processing_enabled = False
        self.stats = {
            "packets_captured": 0,
            "packets_processed": 0,
            "packets_dropped": 0,
            "flows_active": 0,
            "anomalies_detected": 0,
        }

        # Flow tracking
        self.active_flows: Dict[str, FlowRecord] = {}
        self.flow_timeout = 300  # 5 minutes

        # Threat detection patterns
        self.threat_patterns = self._initialize_threat_patterns()

        # Device fingerprinting
        self.device_signatures = self._initialize_device_signatures()

        # Callbacks for different event types
        self.callbacks = {"packet": [], "flow": [], "anomaly": [], "threat": []}

    def _initialize_threat_patterns(self) -> Dict[str, Any]:
        """Initialize threat detection patterns."""
        return {
            "port_scan": {
                "pattern": "multiple_ports_single_src",
                "threshold": 10,
                "timeframe": 60,
            },
            "ddos": {"pattern": "high_packet_rate", "threshold": 1000, "timeframe": 10},
            "lateral_movement": {
                "pattern": "internal_to_internal_new_connection",
                "protocols": ["SSH", "RDP", "SMB"],
            },
            "data_exfiltration": {
                "pattern": "large_outbound_transfer",
                "threshold": 100 * 1024 * 1024,  # 100MB
                "timeframe": 300,
            },
            "iot_anomaly": {
                "pattern": "unexpected_protocol",
                "expected_protocols": ["MQTT", "CoAP", "HTTP"],
            },
        }

    def _initialize_device_signatures(self) -> Dict[str, Dict[str, Any]]:
        """Initialize device fingerprinting signatures."""
        return {
            "windows": {
                "ttl_range": [128, 128],
                "window_sizes": [65535, 8192],
                "tcp_options": ["mss", "nop", "ws", "nop", "nop", "sack"],
            },
            "linux": {
                "ttl_range": [64, 64],
                "window_sizes": [5840, 5792],
                "tcp_options": ["mss", "sack", "ts", "nop", "ws"],
            },
            "iot_device": {
                "ttl_range": [255, 64],
                "small_packets": True,
                "periodic_beacons": True,
            },
            "medical_device": {
                "protocols": ["HL7", "DICOM"],
                "port_ranges": [(2575, 2576), (104, 104)],
                "encrypted": False,
            },
            "industrial_control": {
                "protocols": ["Modbus", "DNP3", "EtherNet/IP"],
                "port_ranges": [(502, 502), (20000, 20000)],
                "real_time": True,
            },
        }

    def add_callback(self, event_type: str, callback: Callable):
        """Add callback for specific event types."""
        if event_type in self.callbacks:
            self.callbacks[event_type].append(callback)

    def start_capture(
        self, interface: Optional[str] = None, filter_expr: Optional[str] = None
    ):
        """Start packet capture on specified interface."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required for packet capture")

        self.processing_enabled = True

        # Start processing thread
        processing_thread = threading.Thread(target=self._process_packets, daemon=True)
        processing_thread.start()

        # Start cleanup thread
        cleanup_thread = threading.Thread(target=self._cleanup_flows, daemon=True)
        cleanup_thread.start()

        try:
            # Start packet capture
            if scapy is not None:
                scapy.sniff(
                    iface=interface,
                    filter=filter_expr,
                    prn=self._packet_handler,
                    stop_filter=lambda p: not self.processing_enabled,
                )
        except Exception as e:
            self.logger.error(f"Capture failed: {e}")
            self.processing_enabled = False

    def stop_capture(self):
        """Stop packet capture and processing."""
        self.processing_enabled = False
        self.logger.info("Packet capture stopped")

    def _packet_handler(self, packet):
        """Handle captured packets."""
        try:
            self.stats["packets_captured"] += 1

            # Extract packet metadata
            metadata = self._extract_packet_metadata(packet)
            if metadata:
                # Try to add to queue, drop if full
                try:
                    self.packet_queue.put((packet, metadata), block=False)
                except Full:
                    self.stats["packets_dropped"] += 1

        except Exception as e:
            self.logger.error(f"Packet handling error: {e}")

    def _extract_packet_metadata(self, packet) -> Optional[PacketMetadata]:
        """Extract comprehensive metadata from packet."""
        try:
            timestamp = time.time()

            # Initialize default values
            src_ip = dst_ip = "unknown"
            src_port = dst_port = None
            protocol = "unknown"
            flags = {}

            # Extract IP layer information
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst

                # Extract transport layer information
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport
                    protocol = "TCP"
                    flags = {
                        "SYN": bool(tcp_layer.flags & 0x02),
                        "ACK": bool(tcp_layer.flags & 0x10),
                        "FIN": bool(tcp_layer.flags & 0x01),
                        "RST": bool(tcp_layer.flags & 0x04),
                        "PSH": bool(tcp_layer.flags & 0x08),
                        "URG": bool(tcp_layer.flags & 0x20),
                    }
                elif packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    src_port = udp_layer.sport
                    dst_port = udp_layer.dport
                    protocol = "UDP"
                elif packet.haslayer(ICMP):
                    protocol = "ICMP"

            # Calculate sizes
            packet_size = len(packet)
            payload_size = len(packet.payload) if hasattr(packet, "payload") else 0

            # Device type detection
            device_type = self._detect_device_type(
                packet, src_ip, dst_ip, src_port, dst_port
            )

            # Anomaly scoring
            anomaly_score = self._calculate_anomaly_score(packet, metadata=None)

            # Threat indicators
            threat_indicators = self._detect_threats(
                packet, src_ip, dst_ip, src_port, dst_port
            )

            return PacketMetadata(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                packet_size=packet_size,
                payload_size=payload_size,
                flags=flags,
                device_type=device_type,
                anomaly_score=anomaly_score,
                threat_indicators=threat_indicators,
            )

        except Exception as e:
            self.logger.error(f"Metadata extraction error: {e}")
            return None

    def _detect_device_type(
        self,
        packet,
        src_ip: str,
        dst_ip: str,
        src_port: Optional[int],
        dst_port: Optional[int],
    ) -> Optional[str]:
        """Detect device type based on traffic patterns."""

        # Check for specific protocols/ports
        if dst_port:
            if dst_port == 1883 or dst_port == 8883:  # MQTT
                return "iot_device"
            elif dst_port == 502:  # Modbus
                return "industrial_control"
            elif dst_port in [2575, 2576]:  # HL7
                return "medical_device"
            elif dst_port in [22, 3389]:  # SSH, RDP
                return "endpoint"
            elif dst_port in [161, 162]:  # SNMP
                return "network_device"

        # TCP fingerprinting
        if packet.haslayer(IP) and packet.haslayer(TCP):
            ttl = packet[IP].ttl
            window = packet[TCP].window

            for device_type, signature in self.device_signatures.items():
                if "ttl_range" in signature:
                    ttl_min, ttl_max = signature["ttl_range"]
                    if ttl_min <= ttl <= ttl_max:
                        if "window_sizes" in signature:
                            if window in signature["window_sizes"]:
                                return device_type

        return None

    def _calculate_anomaly_score(self, packet, metadata) -> float:
        """Calculate anomaly score for packet."""
        score = 0.0

        # Size-based anomalies
        packet_size = len(packet)
        if packet_size > 1500:  # Jumbo frame
            score += 0.3
        elif packet_size < 60:  # Undersized packet
            score += 0.2

        # Protocol anomalies
        if packet.haslayer(IP):
            # Check for unusual TTL values
            ttl = packet[IP].ttl
            if ttl < 10 or ttl > 255:
                score += 0.4

        # TCP flag anomalies
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            # Check for unusual flag combinations
            if tcp_layer.flags == 0:  # Null scan
                score += 0.8
            elif tcp_layer.flags & 0x3F == 0x3F:  # Xmas scan
                score += 0.8

        return min(score, 1.0)

    def _detect_threats(
        self,
        packet,
        src_ip: str,
        dst_ip: str,
        src_port: Optional[int],
        dst_port: Optional[int],
    ) -> List[str]:
        """Detect threat indicators in packet."""
        threats = []

        # Port scanning detection
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            if tcp_layer.flags == 0x02:  # SYN scan
                # Track SYN attempts from same source
                # (Implementation would require state tracking)
                pass

        # Known malicious ports
        malicious_ports = [6667, 6668, 6669, 1337, 31337]
        if dst_port in malicious_ports:
            threats.append("suspicious_port")

        # DNS tunneling detection
        if packet.haslayer(DNS) and packet.haslayer(UDP):
            dns_layer = packet[DNS]
            if dns_layer.qd and len(str(dns_layer.qd.qname)) > 50:
                threats.append("dns_tunneling")

        return threats

    def _process_packets(self):
        """Process packets from queue."""
        while self.processing_enabled:
            try:
                if not self.packet_queue.empty():
                    packet, metadata = self.packet_queue.get(timeout=1)
                    self.stats["packets_processed"] += 1

                    # Update flow tracking
                    self._update_flow_tracking(metadata)

                    # Trigger callbacks
                    for callback in self.callbacks["packet"]:
                        try:
                            callback(packet, metadata)
                        except Exception as e:
                            self.logger.error(f"Packet callback error: {e}")

                    # Check for anomalies
                    if metadata.anomaly_score > 0.5:
                        self.stats["anomalies_detected"] += 1
                        for callback in self.callbacks["anomaly"]:
                            try:
                                callback(metadata)
                            except Exception as e:
                                self.logger.error(f"Anomaly callback error: {e}")

                    # Check for threats
                    if metadata.threat_indicators:
                        for callback in self.callbacks["threat"]:
                            try:
                                callback(metadata)
                            except Exception as e:
                                self.logger.error(f"Threat callback error: {e}")

                else:
                    time.sleep(0.1)

            except Exception as e:
                self.logger.error(f"Packet processing error: {e}")

    def _update_flow_tracking(self, metadata: PacketMetadata):
        """Update flow tracking with new packet."""
        if metadata.src_port and metadata.dst_port:
            # Create flow ID
            flow_id = f"{metadata.src_ip}:{metadata.src_port}-{metadata.dst_ip}:{metadata.dst_port}-{metadata.protocol}"

            now = time.time()

            if flow_id in self.active_flows:
                # Update existing flow
                flow = self.active_flows[flow_id]
                flow.last_seen = now
                flow.packet_count += 1
                flow.byte_count += metadata.packet_size

                if metadata.flags:
                    for flag, value in metadata.flags.items():
                        if value:
                            flow.flags.add(flag)
            else:
                # Create new flow
                flow = FlowRecord(
                    flow_id=flow_id,
                    src_ip=metadata.src_ip,
                    dst_ip=metadata.dst_ip,
                    src_port=metadata.src_port,
                    dst_port=metadata.dst_port,
                    protocol=metadata.protocol,
                    start_time=now,
                    last_seen=now,
                    packet_count=1,
                    byte_count=metadata.packet_size,
                    flags=set(),
                    device_fingerprint=metadata.device_type,
                )

                if metadata.flags:
                    for flag, value in metadata.flags.items():
                        if value:
                            flow.flags.add(flag)

                self.active_flows[flow_id] = flow
                self.stats["flows_active"] = len(self.active_flows)

                # Trigger flow callbacks
                for callback in self.callbacks["flow"]:
                    try:
                        callback(flow)
                    except Exception as e:
                        self.logger.error(f"Flow callback error: {e}")

    def _cleanup_flows(self):
        """Clean up expired flows."""
        while self.processing_enabled:
            try:
                now = time.time()
                expired_flows = []

                for flow_id, flow in self.active_flows.items():
                    if now - flow.last_seen > self.flow_timeout:
                        expired_flows.append(flow_id)

                for flow_id in expired_flows:
                    del self.active_flows[flow_id]

                self.stats["flows_active"] = len(self.active_flows)
                time.sleep(30)  # Check every 30 seconds

            except Exception as e:
                self.logger.error(f"Flow cleanup error: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get processing statistics."""
        return dict(self.stats)

    def export_flows(self) -> List[Dict[str, Any]]:
        """Export current flows for analysis."""
        flows = []
        for flow in self.active_flows.values():
            flows.append(
                {
                    "flow_id": flow.flow_id,
                    "src_ip": flow.src_ip,
                    "dst_ip": flow.dst_ip,
                    "src_port": flow.src_port,
                    "dst_port": flow.dst_port,
                    "protocol": flow.protocol,
                    "start_time": flow.start_time,
                    "duration": flow.last_seen - flow.start_time,
                    "packet_count": flow.packet_count,
                    "byte_count": flow.byte_count,
                    "flags": list(flow.flags),
                    "device_fingerprint": flow.device_fingerprint,
                }
            )
        return flows


class PcapAnalyzer:
    """PCAP file analysis engine."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.processor = PacketProcessor()

    def analyze_file(self, pcap_path: str) -> Dict[str, Any]:
        """Analyze PCAP file and return comprehensive analysis."""
        try:
            if not SCAPY_AVAILABLE:
                raise RuntimeError("Scapy is required for PCAP analysis")

            packets = scapy.rdpcap(pcap_path)
            analysis = {
                "total_packets": len(packets),
                "protocols": {},
                "conversations": {},
                "devices": {},
                "threats": [],
                "anomalies": [],
                "timeline": [],
            }

            for packet in packets:
                metadata = self.processor._extract_packet_metadata(packet)
                if metadata:
                    # Protocol distribution
                    protocol = metadata.protocol
                    analysis["protocols"][protocol] = (
                        analysis["protocols"].get(protocol, 0) + 1
                    )

                    # Device tracking
                    if metadata.device_type:
                        devices = analysis["devices"]
                        devices[metadata.device_type] = (
                            devices.get(metadata.device_type, 0) + 1
                        )

                    # Threat detection
                    if metadata.threat_indicators:
                        analysis["threats"].extend(metadata.threat_indicators)

                    # Anomaly detection
                    if metadata.anomaly_score > 0.5:
                        analysis["anomalies"].append(
                            {
                                "timestamp": metadata.timestamp,
                                "src_ip": metadata.src_ip,
                                "dst_ip": metadata.dst_ip,
                                "score": metadata.anomaly_score,
                            }
                        )

            return analysis

        except Exception as e:
            self.logger.error(f"PCAP analysis failed: {e}")
            return {}


# Example usage and integration
if __name__ == "__main__":
    import sys

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Create processor
    processor = PacketProcessor()

    # Add example callbacks
    def packet_callback(packet, metadata):
        print(f"Packet: {metadata.src_ip} -> {metadata.dst_ip} ({metadata.protocol})")

    def threat_callback(metadata):
        print(f"THREAT DETECTED: {metadata.threat_indicators} from {metadata.src_ip}")

    processor.add_callback("packet", packet_callback)
    processor.add_callback("threat", threat_callback)

    try:
        if len(sys.argv) > 1:
            # Analyze PCAP file
            analyzer = PcapAnalyzer()
            results = analyzer.analyze_file(sys.argv[1])
            print(json.dumps(results, indent=2))
        else:
            # Start live capture
            print("Starting live packet capture (Ctrl+C to stop)...")
            processor.start_capture()
    except KeyboardInterrupt:
        processor.stop_capture()
        print("\nCapture stopped")
