"""
Advanced Network Feature Extraction Engine for Microprocessor Agent
Provides comprehensive network behavior analysis and feature engineering.
"""

import numpy as np
import pandas as pd
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Set
from datetime import datetime, timedelta
import hashlib
import ipaddress


@dataclass
class NetworkFeatures:
    """Comprehensive network feature set for analysis."""

    # Basic flow features
    flow_duration: float
    packet_count: int
    byte_count: int
    packets_per_second: float
    bytes_per_second: float

    # Packet size statistics
    min_packet_size: int
    max_packet_size: int
    mean_packet_size: float
    std_packet_size: float

    # Inter-arrival time statistics
    min_iat: float
    max_iat: float
    mean_iat: float
    std_iat: float

    # Protocol features
    protocol: str
    src_port: int
    dst_port: int
    tcp_flags: Set[str]

    # Behavioral features
    bidirectional_packets: int
    bidirectional_bytes: int
    flow_direction_ratio: float

    # Statistical features
    packet_length_variance: float
    coefficient_of_variation: float
    entropy: float

    # Advanced features
    burst_count: int
    idle_time: float
    activity_ratio: float

    # Device fingerprinting
    device_type: Optional[str] = None
    os_fingerprint: Optional[str] = None
    application_fingerprint: Optional[str] = None

    # Anomaly indicators
    anomaly_score: float = 0.0
    behavioral_score: float = 0.0
    threat_score: float = 0.0


@dataclass
class FlowContext:
    """Context information for flow analysis."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    packets: List[Dict[str, Any]] = field(default_factory=list)
    inter_arrival_times: List[float] = field(default_factory=list)
    packet_sizes: List[int] = field(default_factory=list)
    tcp_flags: Set[str] = field(default_factory=set)
    directions: List[str] = field(default_factory=list)  # 'forward' or 'backward'


class NetworkFeatureExtractor:
    """Advanced network feature extraction engine."""

    def __init__(self, window_size: int = 1000):
        self.logger = logging.getLogger(__name__)
        self.window_size = window_size
        self.flows: Dict[str, FlowContext] = {}
        self.feature_cache: Dict[str, NetworkFeatures] = {}

        # Traffic baselines for anomaly detection
        self.baselines = {
            "packet_sizes": defaultdict(list),
            "flow_durations": defaultdict(list),
            "iat_patterns": defaultdict(list),
            "port_usage": defaultdict(int),
        }

        # Device fingerprinting database
        self.device_signatures = self._initialize_device_signatures()
        self.os_signatures = self._initialize_os_signatures()

        # Application signatures
        self.app_signatures = self._initialize_app_signatures()

    def _initialize_device_signatures(self) -> Dict[str, Dict[str, Any]]:
        """Initialize device fingerprinting signatures."""
        return {
            "iot_camera": {
                "ports": [80, 443, 554, 8080],
                "protocols": ["HTTP", "RTSP"],
                "packet_patterns": ["periodic_small", "video_stream"],
                "typical_sizes": [64, 1500],
            },
            "iot_sensor": {
                "ports": [1883, 8883, 5683],
                "protocols": ["MQTT", "CoAP"],
                "packet_patterns": ["periodic_tiny", "sensor_data"],
                "typical_sizes": [32, 128],
            },
            "medical_device": {
                "ports": [2575, 2576, 104],
                "protocols": ["HL7", "DICOM"],
                "packet_patterns": ["medical_data", "alarm_systems"],
                "typical_sizes": [256, 2048],
            },
            "industrial_plc": {
                "ports": [502, 20000, 44818],
                "protocols": ["Modbus", "EtherNet/IP"],
                "packet_patterns": ["control_commands", "status_updates"],
                "typical_sizes": [64, 256],
            },
            "network_printer": {
                "ports": [515, 631, 9100],
                "protocols": ["LPR", "IPP", "JetDirect"],
                "packet_patterns": ["print_jobs", "status_queries"],
                "typical_sizes": [512, 8192],
            },
            "smart_switch": {
                "ports": [161, 162, 22, 80, 443],
                "protocols": ["SNMP", "SSH", "HTTP"],
                "packet_patterns": ["management_traffic", "monitoring"],
                "typical_sizes": [64, 1024],
            },
        }

    def _initialize_os_signatures(self) -> Dict[str, Dict[str, Any]]:
        """Initialize OS fingerprinting signatures."""
        return {
            "windows": {
                "ttl": [128],
                "window_size": [65535, 8192],
                "tcp_options": ["mss", "nop", "ws", "nop", "nop", "sack"],
                "df_bit": True,
            },
            "linux": {
                "ttl": [64],
                "window_size": [5840, 5792],
                "tcp_options": ["mss", "sack", "ts", "nop", "ws"],
                "df_bit": True,
            },
            "macos": {
                "ttl": [64],
                "window_size": [65535],
                "tcp_options": ["mss", "nop", "ws", "nop", "nop", "ts"],
                "df_bit": True,
            },
            "embedded": {
                "ttl": [255, 32],
                "window_size": [4096, 2048],
                "tcp_options": ["mss"],
                "df_bit": False,
            },
        }

    def _initialize_app_signatures(self) -> Dict[str, Dict[str, Any]]:
        """Initialize application fingerprinting signatures."""
        return {
            "web_browser": {
                "user_agents": ["Mozilla", "Chrome", "Safari", "Edge"],
                "tls_versions": ["1.2", "1.3"],
                "cipher_suites": ["ECDHE", "AES"],
                "packet_patterns": ["http_requests", "web_content"],
            },
            "email_client": {
                "protocols": ["SMTP", "IMAP", "POP3"],
                "ports": [25, 143, 993, 995],
                "packet_patterns": ["email_sync", "attachment_transfer"],
            },
            "file_transfer": {
                "protocols": ["FTP", "SFTP", "SCP"],
                "ports": [20, 21, 22],
                "packet_patterns": ["large_transfers", "directory_listings"],
            },
            "remote_access": {
                "protocols": ["RDP", "VNC", "SSH"],
                "ports": [3389, 5900, 22],
                "packet_patterns": ["screen_updates", "keyboard_mouse"],
            },
            "iot_communication": {
                "protocols": ["MQTT", "CoAP", "XMPP"],
                "ports": [1883, 5683, 5222],
                "packet_patterns": ["sensor_data", "device_commands"],
            },
        }

    def add_packet(self, packet_data: Dict[str, Any]) -> Optional[str]:
        """Add packet to flow tracking and return flow ID."""
        try:
            # Extract flow key
            flow_key = self._generate_flow_key(packet_data)
            if not flow_key:
                return None

            # Initialize or update flow context
            if flow_key not in self.flows:
                self.flows[flow_key] = FlowContext(
                    src_ip=packet_data.get("src_ip", ""),
                    dst_ip=packet_data.get("dst_ip", ""),
                    src_port=packet_data.get("src_port", 0),
                    dst_port=packet_data.get("dst_port", 0),
                    protocol=packet_data.get("protocol", ""),
                    start_time=packet_data.get("timestamp", time.time()),
                )

            flow = self.flows[flow_key]

            # Add packet to flow
            flow.packets.append(packet_data)

            # Calculate inter-arrival time
            if len(flow.packets) > 1:
                iat = packet_data.get("timestamp", time.time()) - flow.packets[-2].get(
                    "timestamp", time.time()
                )
                flow.inter_arrival_times.append(iat)

            # Track packet size
            packet_size = packet_data.get("packet_size", 0)
            flow.packet_sizes.append(packet_size)

            # Track TCP flags
            if packet_data.get("protocol") == "TCP":
                flags = packet_data.get("flags", {})
                for flag, present in flags.items():
                    if present:
                        flow.tcp_flags.add(flag)

            # Determine flow direction
            direction = self._determine_flow_direction(packet_data, flow)
            flow.directions.append(direction)

            # Update baselines
            self._update_baselines(packet_data, flow)

            return flow_key

        except Exception as e:
            self.logger.error(f"Error adding packet: {e}")
            return None

    def extract_features(self, flow_key: str) -> Optional[NetworkFeatures]:
        """Extract comprehensive features from flow."""
        if flow_key not in self.flows:
            return None

        try:
            flow = self.flows[flow_key]

            # Check cache first
            if flow_key in self.feature_cache:
                cached_features = self.feature_cache[flow_key]
                # Update with latest packet data if needed
                if len(flow.packets) > 10:  # Recalculate periodically
                    features = self._calculate_features(flow)
                    self.feature_cache[flow_key] = features
                    return features
                return cached_features

            # Calculate features
            features = self._calculate_features(flow)
            self.feature_cache[flow_key] = features

            return features

        except Exception as e:
            self.logger.error(f"Error extracting features: {e}")
            return None

    def _generate_flow_key(self, packet_data: Dict[str, Any]) -> Optional[str]:
        """Generate unique flow key from packet."""
        try:
            src_ip = packet_data.get("src_ip", "")
            dst_ip = packet_data.get("dst_ip", "")
            src_port = packet_data.get("src_port", 0)
            dst_port = packet_data.get("dst_port", 0)
            protocol = packet_data.get("protocol", "")

            if not all([src_ip, dst_ip, protocol]):
                return None

            # Create bidirectional flow key
            if (src_ip, src_port) < (dst_ip, dst_port):
                flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
            else:
                flow_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"

            return flow_key

        except Exception as e:
            self.logger.error(f"Error generating flow key: {e}")
            return None

    def _determine_flow_direction(
        self, packet_data: Dict[str, Any], flow: FlowContext
    ) -> str:
        """Determine packet direction in flow."""
        src_ip = packet_data.get("src_ip", "")
        src_port = packet_data.get("src_port", 0)

        if src_ip == flow.src_ip and src_port == flow.src_port:
            return "forward"
        else:
            return "backward"

    def _calculate_features(self, flow: FlowContext) -> NetworkFeatures:
        """Calculate comprehensive network features."""
        packets = flow.packets
        if not packets:
            return self._empty_features()

        # Basic flow statistics
        flow_duration = packets[-1].get("timestamp", time.time()) - flow.start_time
        packet_count = len(packets)
        byte_count = sum(p.get("packet_size", 0) for p in packets)

        # Rate calculations
        packets_per_second = packet_count / max(flow_duration, 0.001)
        bytes_per_second = byte_count / max(flow_duration, 0.001)

        # Packet size statistics
        sizes = flow.packet_sizes
        min_size = min(sizes) if sizes else 0
        max_size = max(sizes) if sizes else 0
        mean_size = np.mean(sizes) if sizes else 0
        std_size = np.std(sizes) if len(sizes) > 1 else 0

        # Inter-arrival time statistics
        iats = flow.inter_arrival_times
        min_iat = min(iats) if iats else 0
        max_iat = max(iats) if iats else 0
        mean_iat = np.mean(iats) if iats else 0
        std_iat = np.std(iats) if len(iats) > 1 else 0

        # Bidirectional statistics
        forward_packets = sum(1 for d in flow.directions if d == "forward")
        backward_packets = len(flow.directions) - forward_packets

        forward_bytes = sum(
            p.get("packet_size", 0)
            for i, p in enumerate(packets)
            if i < len(flow.directions) and flow.directions[i] == "forward"
        )
        backward_bytes = byte_count - forward_bytes

        flow_direction_ratio = forward_packets / max(backward_packets, 1)

        # Statistical measures
        packet_length_variance = np.var(sizes) if len(sizes) > 1 else 0
        coefficient_of_variation = std_size / max(mean_size, 0.001)
        entropy = self._calculate_entropy(sizes)

        # Advanced behavioral features
        burst_count = self._calculate_burst_count(iats)
        idle_time = self._calculate_idle_time(iats)
        activity_ratio = (flow_duration - idle_time) / max(flow_duration, 0.001)

        # Device and application fingerprinting
        device_type = self._identify_device_type(flow)
        os_fingerprint = self._identify_os(flow)
        app_fingerprint = self._identify_application(flow)

        # Anomaly scoring
        anomaly_score = self._calculate_anomaly_score(flow)
        behavioral_score = self._calculate_behavioral_score(flow)
        threat_score = self._calculate_threat_score(flow)

        return NetworkFeatures(
            flow_duration=flow_duration,
            packet_count=packet_count,
            byte_count=byte_count,
            packets_per_second=packets_per_second,
            bytes_per_second=bytes_per_second,
            min_packet_size=min_size,
            max_packet_size=max_size,
            mean_packet_size=mean_size,
            std_packet_size=std_size,
            min_iat=min_iat,
            max_iat=max_iat,
            mean_iat=mean_iat,
            std_iat=std_iat,
            protocol=flow.protocol,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            tcp_flags=flow.tcp_flags,
            bidirectional_packets=backward_packets,
            bidirectional_bytes=backward_bytes,
            flow_direction_ratio=flow_direction_ratio,
            packet_length_variance=packet_length_variance,
            coefficient_of_variation=coefficient_of_variation,
            entropy=entropy,
            burst_count=burst_count,
            idle_time=idle_time,
            activity_ratio=activity_ratio,
            device_type=device_type,
            os_fingerprint=os_fingerprint,
            application_fingerprint=app_fingerprint,
            anomaly_score=anomaly_score,
            behavioral_score=behavioral_score,
            threat_score=threat_score,
        )

    def _empty_features(self) -> NetworkFeatures:
        """Return empty feature set."""
        return NetworkFeatures(
            flow_duration=0,
            packet_count=0,
            byte_count=0,
            packets_per_second=0,
            bytes_per_second=0,
            min_packet_size=0,
            max_packet_size=0,
            mean_packet_size=0,
            std_packet_size=0,
            min_iat=0,
            max_iat=0,
            mean_iat=0,
            std_iat=0,
            protocol="",
            src_port=0,
            dst_port=0,
            tcp_flags=set(),
            bidirectional_packets=0,
            bidirectional_bytes=0,
            flow_direction_ratio=0,
            packet_length_variance=0,
            coefficient_of_variation=0,
            entropy=0,
            burst_count=0,
            idle_time=0,
            activity_ratio=0,
        )

    def _calculate_entropy(self, sizes: List[int]) -> float:
        """Calculate Shannon entropy of packet sizes."""
        if not sizes:
            return 0.0

        # Create histogram
        unique_sizes = set(sizes)
        size_counts = {size: sizes.count(size) for size in unique_sizes}
        total = len(sizes)

        # Calculate entropy
        entropy = 0.0
        for count in size_counts.values():
            probability = count / total
            if probability > 0:
                entropy -= probability * np.log2(probability)

        return entropy

    def _calculate_burst_count(self, iats: List[float]) -> int:
        """Calculate number of packet bursts."""
        if len(iats) < 2:
            return 0

        # Define burst threshold (e.g., IAT < mean - std)
        mean_iat = np.mean(iats)
        std_iat = np.std(iats)
        threshold = max(mean_iat - std_iat, 0.001)

        bursts = 0
        in_burst = False

        for iat in iats:
            if iat < threshold:
                if not in_burst:
                    bursts += 1
                    in_burst = True
            else:
                in_burst = False

        return bursts

    def _calculate_idle_time(self, iats: List[float]) -> float:
        """Calculate total idle time in flow."""
        if not iats:
            return 0.0

        # Define idle threshold (e.g., IAT > mean + 2*std)
        mean_iat = np.mean(iats)
        std_iat = np.std(iats)
        threshold = mean_iat + 2 * std_iat

        idle_time = sum(iat for iat in iats if iat > threshold)
        return idle_time

    def _identify_device_type(self, flow: FlowContext) -> Optional[str]:
        """Identify device type based on traffic patterns."""
        port = flow.dst_port
        protocol = flow.protocol

        for device_type, signature in self.device_signatures.items():
            if port in signature.get("ports", []):
                if protocol in signature.get("protocols", []):
                    return device_type

        return None

    def _identify_os(self, flow: FlowContext) -> Optional[str]:
        """Identify operating system based on network fingerprints."""
        # This would require more detailed packet analysis
        # For now, return basic heuristics
        if flow.protocol == "TCP" and flow.tcp_flags:
            if "SYN" in flow.tcp_flags and len(flow.tcp_flags) > 3:
                return "windows"
            elif "SYN" in flow.tcp_flags:
                return "linux"

        return None

    def _identify_application(self, flow: FlowContext) -> Optional[str]:
        """Identify application based on traffic patterns."""
        port = flow.dst_port

        # Web traffic
        if port in [80, 443, 8080, 8443]:
            return "web_browser"

        # Email
        if port in [25, 143, 993, 995]:
            return "email_client"

        # File transfer
        if port in [20, 21, 22] and flow.byte_count > 10000:
            return "file_transfer"

        # Remote access
        if port in [3389, 5900]:
            return "remote_access"

        # IoT communication
        if port in [1883, 5683]:
            return "iot_communication"

        return None

    def _calculate_anomaly_score(self, flow: FlowContext) -> float:
        """Calculate anomaly score for flow."""
        score = 0.0

        # Unusual packet sizes
        if flow.packet_sizes:
            mean_size = np.mean(flow.packet_sizes)
            if mean_size < 40 or mean_size > 1400:
                score += 0.3

        # Unusual ports
        if flow.dst_port > 49152:  # Dynamic/private ports
            score += 0.2

        # Unusual flow duration
        duration = time.time() - flow.start_time
        if duration > 3600:  # Very long flows
            score += 0.4

        # High packet rate
        if len(flow.packets) > 0:
            rate = len(flow.packets) / max(duration, 0.001)
            if rate > 100:  # Very high packet rate
                score += 0.5

        return min(score, 1.0)

    def _calculate_behavioral_score(self, flow: FlowContext) -> float:
        """Calculate behavioral anomaly score."""
        score = 0.0

        # Check for scanning behavior
        if len(flow.tcp_flags) == 1 and "SYN" in flow.tcp_flags:
            score += 0.6  # Potential port scan

        # Check for large data transfers
        if flow.packet_sizes:
            total_bytes = sum(flow.packet_sizes)
            if total_bytes > 100 * 1024 * 1024:  # > 100MB
                score += 0.4

        # Check for unusual timing patterns
        if flow.inter_arrival_times:
            # Very regular timing might indicate automation
            std_iat = np.std(flow.inter_arrival_times)
            mean_iat = np.mean(flow.inter_arrival_times)
            if std_iat / max(mean_iat, 0.001) < 0.1:
                score += 0.3

        return min(score, 1.0)

    def _calculate_threat_score(self, flow: FlowContext) -> float:
        """Calculate threat indicator score."""
        score = 0.0

        # Known malicious ports
        malicious_ports = [6667, 6668, 6669, 1337, 31337]
        if flow.dst_port in malicious_ports:
            score += 0.8

        # Suspicious flag combinations
        if (
            "FIN" in flow.tcp_flags
            and "URG" in flow.tcp_flags
            and "PSH" in flow.tcp_flags
        ):
            score += 0.7  # Xmas scan

        # NULL scan
        if len(flow.tcp_flags) == 0 and flow.protocol == "TCP":
            score += 0.7

        # DNS tunneling indicators
        if flow.dst_port == 53 and flow.packet_sizes:
            large_dns = any(size > 512 for size in flow.packet_sizes)
            if large_dns:
                score += 0.6

        return min(score, 1.0)

    def _update_baselines(self, packet_data: Dict[str, Any], flow: FlowContext):
        """Update baseline statistics for anomaly detection."""
        # Update packet size baselines
        size = packet_data.get("packet_size", 0)
        self.baselines["packet_sizes"][flow.protocol].append(size)

        # Keep only recent data (sliding window)
        if len(self.baselines["packet_sizes"][flow.protocol]) > self.window_size:
            self.baselines["packet_sizes"][flow.protocol].pop(0)

        # Update port usage
        port = packet_data.get("dst_port", 0)
        self.baselines["port_usage"][port] += 1

    def get_baseline_statistics(self) -> Dict[str, Any]:
        """Get current baseline statistics."""
        stats = {}

        for protocol, sizes in self.baselines["packet_sizes"].items():
            if sizes:
                stats[f"{protocol}_packet_size"] = {
                    "mean": np.mean(sizes),
                    "std": np.std(sizes),
                    "min": min(sizes),
                    "max": max(sizes),
                }

        # Top ports
        sorted_ports = sorted(
            self.baselines["port_usage"].items(), key=lambda x: x[1], reverse=True
        )
        stats["top_ports"] = sorted_ports[:10]

        return stats

    def cleanup_old_flows(self, max_age: float = 3600):
        """Clean up old flows to manage memory."""
        current_time = time.time()
        old_flows = []

        for flow_key, flow in self.flows.items():
            if current_time - flow.start_time > max_age:
                old_flows.append(flow_key)

        for flow_key in old_flows:
            del self.flows[flow_key]
            if flow_key in self.feature_cache:
                del self.feature_cache[flow_key]

        self.logger.info(f"Cleaned up {len(old_flows)} old flows")

    def export_features(self, format: str = "dict") -> Any:
        """Export extracted features in specified format."""
        all_features = []

        for flow_key in self.flows.keys():
            features = self.extract_features(flow_key)
            if features:
                if format == "dict":
                    feature_dict = {"flow_key": flow_key, **features.__dict__}
                    all_features.append(feature_dict)
                elif format == "dataframe":
                    all_features.append(features)

        if format == "dataframe" and all_features:
            return pd.DataFrame([f.__dict__ for f in all_features])

        return all_features


# Example usage and integration
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Create feature extractor
    extractor = NetworkFeatureExtractor()

    # Example packet data
    sample_packets = [
        {
            "timestamp": time.time(),
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.1",
            "src_port": 45123,
            "dst_port": 80,
            "protocol": "TCP",
            "packet_size": 1500,
            "flags": {"SYN": True, "ACK": False},
        },
        {
            "timestamp": time.time() + 0.1,
            "src_ip": "192.168.1.1",
            "dst_ip": "192.168.1.10",
            "src_port": 80,
            "dst_port": 45123,
            "protocol": "TCP",
            "packet_size": 64,
            "flags": {"SYN": True, "ACK": True},
        },
    ]

    # Process packets
    for packet in sample_packets:
        flow_key = extractor.add_packet(packet)
        if flow_key:
            features = extractor.extract_features(flow_key)
            if features:
                print(f"Flow: {flow_key}")
                print(f"Device Type: {features.device_type}")
                print(f"Anomaly Score: {features.anomaly_score:.2f}")
                print("---")
