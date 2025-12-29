"""
Microprocessor Integration Layer
Connects all intelligence components with the existing EventBus infrastructure.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from queue import Empty, Queue
from typing import Any, Callable, Dict, List, Optional

# Import our new components
try:
    from ...agents.discovery.device_scanner import DeviceDiscoveryEngine
    from ...agents.protocols.universal_collector import UniversalTelemetryCollector
    from ...edge.edge_optimizer import EdgeOptimizer
    from ..features.network_features import NetworkFeatureExtractor, NetworkFeatures
    from ..fusion.threat_correlator import (
        DeviceType,
        IntelligenceFusionEngine,
        TelemetryEvent,
        ThreatDetection,
    )
    from ..pcap.ingestion import PacketMetadata, PacketProcessor
except ImportError as e:
    logging.warning(f"Import error: {e}. Some components may not be available.")


class MicroprocessorAgentCore:
    """Core integration engine for the microprocessor agent."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.logger = logging.getLogger(__name__)
        self.config = config or {}

        # Initialize components (will be set in initialize())
        self.packet_processor: Optional[Any] = None
        self.feature_extractor: Optional[Any] = None
        self.fusion_engine: Optional[Any] = None
        self.device_scanner: Optional[Any] = None
        self.telemetry_collector: Optional[Any] = None
        self.edge_optimizer: Optional[Any] = None

        # Integration state
        self.running = False
        self.event_queue: Queue[Any] = Queue(maxsize=10000)
        self.integration_threads: List[threading.Thread] = []

        # Callbacks for external systems
        self.external_callbacks: Dict[str, List[Callable[..., Any]]] = {
            "threat_detected": [],
            "device_discovered": [],
            "anomaly_detected": [],
            "compliance_violation": [],
        }

        # Performance metrics
        self.metrics = {
            "total_events_processed": 0,
            "threats_detected": 0,
            "devices_discovered": 0,
            "average_processing_latency": 0.0,
            "system_uptime": 0.0,
        }

        self.start_time = time.time()

    def initialize(self) -> bool:
        """Initialize all agent components."""
        try:
            self.logger.info("Initializing Microprocessor Agent components...")

            # Initialize packet processing
            try:
                self.packet_processor = PacketProcessor()
                self.packet_processor.add_callback("packet", self._handle_packet_event)
                self.packet_processor.add_callback("threat", self._handle_packet_threat)
                self.packet_processor.add_callback(
                    "anomaly", self._handle_packet_anomaly
                )
                self.logger.info("✓ Packet processor initialized")
            except Exception as e:
                self.logger.warning(f"Packet processor initialization failed: {e}")

            # Initialize feature extraction
            try:
                self.feature_extractor = NetworkFeatureExtractor()
                self.logger.info("✓ Network feature extractor initialized")
            except Exception as e:
                self.logger.warning(f"Feature extractor initialization failed: {e}")

            # Initialize intelligence fusion
            try:
                self.fusion_engine = IntelligenceFusionEngine(self.config)
                self.logger.info("✓ Intelligence fusion engine initialized")
            except Exception as e:
                self.logger.warning(f"Fusion engine initialization failed: {e}")

            # Initialize device discovery
            try:
                self.device_scanner = DeviceDiscoveryEngine()
                self.logger.info("✓ Device discovery engine initialized")
            except Exception as e:
                self.logger.warning(f"Device scanner initialization failed: {e}")

            # Initialize telemetry collection
            try:
                self.telemetry_collector = UniversalTelemetryCollector()
                self.logger.info("✓ Universal telemetry collector initialized")
            except Exception as e:
                self.logger.warning(f"Telemetry collector initialization failed: {e}")

            # Initialize edge optimization
            try:
                edge_config = self.config.get("edge_optimization", {})
                self.edge_optimizer = EdgeOptimizer(edge_config)
                self.logger.info("✓ Edge optimizer initialized")
            except Exception as e:
                self.logger.warning(f"Edge optimizer initialization failed: {e}")

            self.logger.info("Microprocessor Agent initialization completed")
            return True

        except Exception as e:
            self.logger.error(f"Failed to initialize Microprocessor Agent: {e}")
            return False

    def start(self) -> bool:
        """Start the microprocessor agent."""
        if not self.initialize():
            return False

        try:
            self.running = True

            # Start fusion engine
            if self.fusion_engine:
                self.fusion_engine.start_processing()

            # Start integration threads
            self.integration_threads = [
                threading.Thread(target=self._event_processing_loop, daemon=True),
                threading.Thread(target=self._device_discovery_loop, daemon=True),
                threading.Thread(target=self._telemetry_collection_loop, daemon=True),
                threading.Thread(target=self._health_monitoring_loop, daemon=True),
            ]

            for thread in self.integration_threads:
                thread.start()

            # Start packet capture if available
            if self.packet_processor and self.config.get(
                "enable_packet_capture", False
            ):
                interface = self.config.get("capture_interface")
                filter_expr = self.config.get("capture_filter")

                capture_thread = threading.Thread(
                    target=self.packet_processor.start_capture,
                    args=(interface, filter_expr),
                    daemon=True,
                )
                capture_thread.start()
                self.integration_threads.append(capture_thread)

            self.logger.info("Microprocessor Agent started successfully")
            return True

        except Exception as e:
            self.logger.error(f"Failed to start Microprocessor Agent: {e}")
            return False

    def stop(self):
        """Stop the microprocessor agent."""
        self.logger.info("Stopping Microprocessor Agent...")

        self.running = False

        # Stop packet processing
        if self.packet_processor:
            self.packet_processor.stop_capture()

        # Stop fusion engine
        if self.fusion_engine:
            self.fusion_engine.stop_processing()

        # Wait for threads to complete
        for thread in self.integration_threads:
            if thread.is_alive():
                thread.join(timeout=5)

        self.logger.info("Microprocessor Agent stopped")

    def add_external_callback(self, event_type: str, callback: Callable):
        """Add callback for external system integration."""
        if event_type in self.external_callbacks:
            self.external_callbacks[event_type].append(callback)

    def _handle_packet_event(self, packet, metadata: PacketMetadata):
        """Handle packet events from packet processor."""
        try:
            # Convert to telemetry event
            telemetry_event = self._packet_to_telemetry(packet, metadata)

            # Add to processing queue
            self.event_queue.put(telemetry_event)

            # Extract network features if available
            if self.feature_extractor:
                packet_data = {
                    "timestamp": metadata.timestamp,
                    "src_ip": metadata.src_ip,
                    "dst_ip": metadata.dst_ip,
                    "src_port": metadata.src_port,
                    "dst_port": metadata.dst_port,
                    "protocol": metadata.protocol,
                    "packet_size": metadata.packet_size,
                    "flags": metadata.flags,
                }

                flow_key = self.feature_extractor.add_packet(packet_data)
                if flow_key:
                    features = self.feature_extractor.extract_features(flow_key)
                    if features:
                        self._handle_network_features(flow_key, features)

        except Exception as e:
            self.logger.error(f"Error handling packet event: {e}")

    def _handle_packet_threat(self, metadata: PacketMetadata):
        """Handle threat detection from packet analysis."""
        try:
            threat_event = TelemetryEvent(
                timestamp=metadata.timestamp,
                device_id=metadata.src_ip,  # Use source IP as device ID
                device_type=self._determine_device_type(metadata.device_type),
                source="packet_analysis",
                event_type="threat_detection",
                data={
                    "threat_indicators": metadata.threat_indicators,
                    "anomaly_score": metadata.anomaly_score,
                    "src_ip": metadata.src_ip,
                    "dst_ip": metadata.dst_ip,
                    "protocol": metadata.protocol,
                },
                risk_score=metadata.anomaly_score,
                threat_indicators=metadata.threat_indicators or [],
            )

            if self.fusion_engine:
                self.fusion_engine.ingest_telemetry(threat_event)

            # Trigger callbacks
            for callback in self.external_callbacks["threat_detected"]:
                try:
                    callback(threat_event)
                except Exception as e:
                    self.logger.error(f"External threat callback error: {e}")

        except Exception as e:
            self.logger.error(f"Error handling packet threat: {e}")

    def _handle_packet_anomaly(self, metadata: PacketMetadata):
        """Handle anomaly detection from packet analysis."""
        try:
            anomaly_event = TelemetryEvent(
                timestamp=metadata.timestamp,
                device_id=metadata.src_ip,
                device_type=self._determine_device_type(metadata.device_type),
                source="packet_analysis",
                event_type="anomaly_detection",
                data={
                    "anomaly_score": metadata.anomaly_score,
                    "packet_size": metadata.packet_size,
                    "protocol": metadata.protocol,
                },
                risk_score=metadata.anomaly_score,
            )

            # Trigger callbacks
            for callback in self.external_callbacks["anomaly_detected"]:
                try:
                    callback(anomaly_event)
                except Exception as e:
                    self.logger.error(f"External anomaly callback error: {e}")

        except Exception as e:
            self.logger.error(f"Error handling packet anomaly: {e}")

    def _handle_network_features(self, flow_key: str, features: NetworkFeatures):
        """Handle extracted network features."""
        try:
            # Create telemetry event from features
            device_id = str(features.src_port) if features.src_port else "unknown"
            feature_event = TelemetryEvent(
                timestamp=time.time(),
                device_id=device_id,  # Use a better device ID scheme
                device_type=self._determine_device_type(features.device_type),
                source="network_features",
                event_type="behavioral_analysis",
                data={
                    "flow_key": flow_key,
                    "packet_count": features.packet_count,
                    "byte_count": features.byte_count,
                    "flow_duration": features.flow_duration,
                    "packets_per_second": features.packets_per_second,
                    "entropy": features.entropy,
                    "burst_count": features.burst_count,
                    "device_type": features.device_type,
                    "os_fingerprint": features.os_fingerprint,
                    "application_fingerprint": features.application_fingerprint,
                },
                risk_score=features.anomaly_score,
                threat_indicators=[],
            )

            if self.fusion_engine:
                self.fusion_engine.ingest_telemetry(feature_event)

        except Exception as e:
            self.logger.error(f"Error handling network features: {e}")

    def _packet_to_telemetry(self, packet, metadata: PacketMetadata) -> TelemetryEvent:
        """Convert packet metadata to telemetry event."""
        return TelemetryEvent(
            timestamp=metadata.timestamp,
            device_id=metadata.src_ip,
            device_type=self._determine_device_type(metadata.device_type),
            source="packet_capture",
            event_type="network_packet",
            data={
                "src_ip": metadata.src_ip,
                "dst_ip": metadata.dst_ip,
                "src_port": metadata.src_port,
                "dst_port": metadata.dst_port,
                "protocol": metadata.protocol,
                "packet_size": metadata.packet_size,
                "flags": metadata.flags,
            },
            risk_score=metadata.anomaly_score,
            threat_indicators=metadata.threat_indicators or [],
        )

    def _determine_device_type(self, device_type_str: Optional[str]) -> DeviceType:
        """Convert device type string to enum."""
        if not device_type_str:
            return DeviceType.UNKNOWN

        mapping = {
            "iot_device": DeviceType.IOT_DEVICE,
            "medical_device": DeviceType.MEDICAL_DEVICE,
            "industrial_control": DeviceType.INDUSTRIAL_CONTROL,
            "network_device": DeviceType.NETWORK_DEVICE,
            "endpoint": DeviceType.ENDPOINT,
            "sensor": DeviceType.SENSOR,
        }

        return mapping.get(device_type_str.lower(), DeviceType.UNKNOWN)

    def _event_processing_loop(self):
        """Main event processing loop."""
        while self.running:
            try:
                # Process events from queue
                try:
                    event = self.event_queue.get(timeout=1)
                    self._process_telemetry_event(event)
                    self.metrics["total_events_processed"] += 1
                except Empty:
                    continue

            except Exception as e:
                self.logger.error(f"Event processing error: {e}")

    def _process_telemetry_event(self, event: TelemetryEvent):
        """Process individual telemetry event."""
        processing_start = time.time()

        try:
            # Edge optimization
            if self.edge_optimizer:
                optimized_event = self.edge_optimizer.optimize_event(event)
                if optimized_event:
                    event = optimized_event

            # Send to fusion engine
            if self.fusion_engine:
                self.fusion_engine.ingest_telemetry(event)

            # Update processing latency metric
            processing_time = time.time() - processing_start
            self._update_latency_metric(processing_time)

        except Exception as e:
            self.logger.error(f"Error processing telemetry event: {e}")

    def _device_discovery_loop(self):
        """Device discovery loop."""
        if not self.device_scanner:
            return

        discovery_interval = self.config.get("discovery_interval", 300)  # 5 minutes

        while self.running:
            try:
                # Run device discovery
                network_ranges = self.config.get(
                    "discovery_networks", ["192.168.1.0/24"]
                )

                for network in network_ranges:
                    devices = self.device_scanner.scan_network(network)

                    for device in devices:
                        # Create device discovery event
                        discovery_event = TelemetryEvent(
                            timestamp=time.time(),
                            device_id=device.get("ip_address", "unknown"),
                            device_type=self._determine_device_type(
                                device.get("device_type")
                            ),
                            source="device_discovery",
                            event_type="device_discovered",
                            data=device,
                            risk_score=device.get("risk_score", 0.0),
                        )

                        self.event_queue.put(discovery_event)
                        self.metrics["devices_discovered"] += 1

                        # Trigger callbacks
                        for callback in self.external_callbacks["device_discovered"]:
                            try:
                                callback(discovery_event)
                            except Exception as e:
                                self.logger.error(
                                    f"Device discovery callback error: {e}"
                                )

                time.sleep(discovery_interval)

            except Exception as e:
                self.logger.error(f"Device discovery error: {e}")
                time.sleep(60)  # Wait before retrying

    def _telemetry_collection_loop(self):
        """Telemetry collection loop."""
        if not self.telemetry_collector:
            return

        collection_interval = self.config.get("collection_interval", 60)  # 1 minute

        while self.running:
            try:
                # Collect telemetry from all configured sources
                telemetry_data = self.telemetry_collector.collect_all()

                for source, data in telemetry_data.items():
                    for item in data:
                        telemetry_event = TelemetryEvent(
                            timestamp=time.time(),
                            device_id=item.get("device_id", "unknown"),
                            device_type=self._determine_device_type(
                                item.get("device_type")
                            ),
                            source=source,
                            event_type="telemetry_data",
                            data=item,
                        )

                        self.event_queue.put(telemetry_event)

                time.sleep(collection_interval)

            except Exception as e:
                self.logger.error(f"Telemetry collection error: {e}")
                time.sleep(30)  # Wait before retrying

    def _health_monitoring_loop(self):
        """System health monitoring loop."""
        monitoring_interval = self.config.get("health_check_interval", 30)  # 30 seconds

        while self.running:
            try:
                # Update system metrics
                self.metrics["system_uptime"] = time.time() - self.start_time

                # Check component health
                health_status = self._check_component_health()

                # Log health status periodically
                if int(time.time()) % 300 == 0:  # Every 5 minutes
                    self.logger.info(f"System health: {health_status}")
                    self.logger.info(f"Metrics: {self.metrics}")

                time.sleep(monitoring_interval)

            except Exception as e:
                self.logger.error(f"Health monitoring error: {e}")

    def _check_component_health(self) -> Dict[str, str]:
        """Check health of all components."""
        health = {}

        # Check packet processor
        if self.packet_processor:
            stats = self.packet_processor.get_statistics()
            if stats.get("packets_captured", 0) > 0:
                health["packet_processor"] = "healthy"
            else:
                health["packet_processor"] = "inactive"
        else:
            health["packet_processor"] = "unavailable"

        # Check fusion engine
        if self.fusion_engine:
            summary = self.fusion_engine.get_threat_summary()
            if summary.get("devices_monitored", 0) > 0:
                health["fusion_engine"] = "healthy"
            else:
                health["fusion_engine"] = "inactive"
        else:
            health["fusion_engine"] = "unavailable"

        # Check event queue
        queue_size = self.event_queue.qsize()
        if queue_size < 1000:
            health["event_queue"] = "healthy"
        elif queue_size < 5000:
            health["event_queue"] = "warning"
        else:
            health["event_queue"] = "critical"

        return health

    def _update_latency_metric(self, processing_time: float):
        """Update processing latency metric with exponential moving average."""
        alpha = 0.1  # Smoothing factor
        if self.metrics["average_processing_latency"] == 0:
            self.metrics["average_processing_latency"] = processing_time
        else:
            self.metrics["average_processing_latency"] = (
                alpha * processing_time
                + (1 - alpha) * self.metrics["average_processing_latency"]
            )

    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive agent status."""
        health = self._check_component_health()

        threat_summary = {}
        if self.fusion_engine:
            threat_summary = self.fusion_engine.get_threat_summary()

        return {
            "running": self.running,
            "uptime": self.metrics["system_uptime"],
            "component_health": health,
            "metrics": self.metrics,
            "threat_summary": threat_summary,
            "queue_size": self.event_queue.qsize(),
        }

    def get_intelligence_report(self) -> Dict[str, Any]:
        """Get comprehensive intelligence report."""
        if self.fusion_engine:
            return self.fusion_engine.export_intelligence_report()
        else:
            return {"error": "Fusion engine not available"}

    def trigger_device_scan(self, network: str) -> List[Dict[str, Any]]:
        """Trigger manual device scan."""
        if self.device_scanner:
            return self.device_scanner.scan_network(network)
        else:
            return []

    def get_device_profiles(self) -> List[Dict[str, Any]]:
        """Get all device profiles."""
        if self.fusion_engine:
            profiles = []
            for profile in self.fusion_engine.device_profiles.values():
                profiles.append(
                    {
                        "device_id": profile.device_id,
                        "device_type": profile.device_type.value,
                        "trust_score": profile.trust_score,
                        "vulnerability_score": profile.vulnerability_score,
                        "compliance_status": profile.compliance_status,
                        "first_seen": profile.first_seen,
                        "last_seen": profile.last_seen,
                    }
                )
            return profiles
        else:
            return []


# EventBus Integration Functions
def create_eventbus_integration(agent: MicroprocessorAgentCore, eventbus_client):
    """Create integration with existing EventBus system."""

    def publish_threat_to_eventbus(threat_event: TelemetryEvent):
        """Publish threat detection to EventBus."""
        try:
            message = {
                "type": "threat_detection",
                "timestamp": threat_event.timestamp,
                "device_id": threat_event.device_id,
                "device_type": threat_event.device_type.value,
                "source": threat_event.source,
                "data": threat_event.data,
                "risk_score": threat_event.risk_score,
                "threat_indicators": threat_event.threat_indicators,
            }

            eventbus_client.publish("threats", json.dumps(message))

        except Exception as e:
            logging.error(f"Failed to publish threat to EventBus: {e}")

    def publish_device_to_eventbus(device_event: TelemetryEvent):
        """Publish device discovery to EventBus."""
        try:
            message = {
                "type": "device_discovered",
                "timestamp": device_event.timestamp,
                "device_id": device_event.device_id,
                "device_type": device_event.device_type.value,
                "data": device_event.data,
            }

            eventbus_client.publish("devices", json.dumps(message))

        except Exception as e:
            logging.error(f"Failed to publish device to EventBus: {e}")

    # Register callbacks
    agent.add_external_callback("threat_detected", publish_threat_to_eventbus)
    agent.add_external_callback("device_discovered", publish_device_to_eventbus)

    return agent


# Example usage
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Configuration
    config = {
        "enable_packet_capture": False,  # Set to True to enable packet capture
        "discovery_networks": ["192.168.1.0/24"],
        "discovery_interval": 300,
        "collection_interval": 60,
        "health_check_interval": 30,
        "edge_optimization": {
            "max_memory_mb": 256,
            "max_cpu_percent": 80,
            "compression_enabled": True,
        },
    }

    # Create and start agent
    agent = MicroprocessorAgentCore(config)

    try:
        if agent.start():
            print("Microprocessor Agent started successfully")
            print("Status:", agent.get_status())

            # Keep running
            while True:
                time.sleep(30)
                status = agent.get_status()
                print(f"Agent Status: {status['component_health']}")

    except KeyboardInterrupt:
        print("Stopping agent...")
        agent.stop()
        print("Agent stopped")
