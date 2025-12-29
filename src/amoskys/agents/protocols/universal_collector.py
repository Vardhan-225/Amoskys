"""
AMOSKYS Multi-Protocol Telemetry Collectors
Universal protocol adapters for diverse device ecosystems
"""

import asyncio
import json
import logging
import socket
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from amoskys.proto import messaging_schema_pb2 as pb

logger = logging.getLogger(__name__)


@dataclass
class TelemetryEvent:
    """Universal telemetry event structure"""

    device_id: str
    timestamp: datetime
    event_type: str  # METRIC, LOG, ALARM, STATUS, SECURITY
    protocol: str
    source_data: Dict[str, Any]
    processed_data: Dict[str, Any]
    severity: str  # INFO, WARN, ERROR, CRITICAL
    tags: List[str]


class BaseProtocolCollector:
    """Base class for all protocol collectors"""

    def __init__(self, device_config: Dict, event_callback: Callable):
        self.device_config = device_config
        self.event_callback = event_callback
        self.is_running = False
        self.logger = logging.getLogger(f"{self.__class__.__name__}")

    async def start(self):
        """Start telemetry collection"""
        self.is_running = True
        await self._connect()

    async def stop(self):
        """Stop telemetry collection"""
        self.is_running = False
        await self._disconnect()

    async def _connect(self):
        """Protocol-specific connection logic"""
        raise NotImplementedError

    async def _disconnect(self):
        """Protocol-specific disconnection logic"""
        raise NotImplementedError

    async def collect_telemetry(self) -> List[TelemetryEvent]:
        """Collect telemetry data"""
        raise NotImplementedError

    def _create_event(
        self, event_type: str, data: Dict, severity: str = "INFO"
    ) -> TelemetryEvent:
        """Create standardized telemetry event"""
        return TelemetryEvent(
            device_id=self.device_config["device_id"],
            timestamp=datetime.now(),
            event_type=event_type,
            protocol=self.__class__.__name__.replace("Collector", ""),
            source_data=data,
            processed_data=self._process_data(data),
            severity=severity,
            tags=self.device_config.get("tags", []),
        )

    def _process_data(self, raw_data: Dict) -> Dict:
        """Process raw data into standardized format"""
        return raw_data


class MQTTCollector(BaseProtocolCollector):
    """MQTT telemetry collector for IoT devices"""

    def __init__(self, device_config: Dict, event_callback: Callable):
        super().__init__(device_config, event_callback)
        self.client = None
        self.subscribed_topics = device_config.get("mqtt_topics", ["#"])

    async def _connect(self):
        """Connect to MQTT broker"""
        try:
            # This would use a real MQTT library like asyncio-mqtt
            mqtt_config = self.device_config.get("mqtt", {})
            broker_host = mqtt_config.get("host", self.device_config["ip_address"])
            broker_port = mqtt_config.get("port", 1883)

            self.logger.info(f"Connecting to MQTT broker {broker_host}:{broker_port}")

            # Simulate MQTT connection
            # In real implementation:
            # self.client = aiomqtt.Client(hostname=broker_host, port=broker_port)
            # await self.client.__aenter__()

            # Subscribe to topics
            for topic in self.subscribed_topics:
                self.logger.info(f"Subscribing to MQTT topic: {topic}")
                # await self.client.subscribe(topic)

        except Exception as e:
            self.logger.error(f"MQTT connection failed: {e}")
            raise

    async def _disconnect(self):
        """Disconnect from MQTT broker"""
        if self.client:
            # await self.client.__aexit__(None, None, None)
            self.client = None

    async def collect_telemetry(self) -> List[TelemetryEvent]:
        """Collect MQTT messages and convert to telemetry events"""
        events = []

        try:
            # In real implementation, this would listen for MQTT messages
            # async for message in self.client.messages:

            # Simulate receiving MQTT messages
            simulated_messages = [
                {
                    "topic": "sensors/temperature",
                    "payload": {
                        "value": 23.5,
                        "unit": "celsius",
                        "sensor_id": "temp_01",
                    },
                    "timestamp": datetime.now(),
                },
                {
                    "topic": "devices/status",
                    "payload": {
                        "device_id": "iot_device_01",
                        "status": "online",
                        "battery": 85,
                    },
                    "timestamp": datetime.now(),
                },
            ]

            for msg in simulated_messages:
                event = self._create_event(
                    event_type="METRIC",
                    data={
                        "topic": msg["topic"],
                        "payload": msg["payload"],
                        "mqtt_timestamp": msg["timestamp"].isoformat(),
                    },
                )
                events.append(event)

        except Exception as e:
            self.logger.error(f"MQTT telemetry collection failed: {e}")

        return events

    def _process_data(self, raw_data: Dict) -> Dict:
        """Process MQTT data into standardized metrics"""
        topic = raw_data.get("topic", "")
        payload = raw_data.get("payload", {})

        processed = {
            "metric_name": topic.replace("/", "_"),
            "value": payload.get("value"),
            "unit": payload.get("unit"),
            "device_specific": payload,
        }

        # Extract security-relevant information
        if "status" in payload:
            processed["device_status"] = payload["status"]
        if "battery" in payload:
            processed["battery_level"] = payload["battery"]

        return processed


class SNMPCollector(BaseProtocolCollector):
    """SNMP telemetry collector for network devices"""

    def __init__(self, device_config: Dict, event_callback: Callable):
        super().__init__(device_config, event_callback)
        self.community = device_config.get("snmp_community", "public")
        self.version = device_config.get("snmp_version", "2c")
        self.oids_to_monitor = device_config.get(
            "snmp_oids",
            [
                "1.3.6.1.2.1.1.1.0",  # sysDescr
                "1.3.6.1.2.1.1.3.0",  # sysUpTime
                "1.3.6.1.2.1.2.1.0",  # ifNumber
                "1.3.6.1.2.1.25.1.1.0",  # hrSystemUptime
            ],
        )

    async def _connect(self):
        """Initialize SNMP session"""
        try:
            # This would use a real SNMP library like pysnmp
            self.logger.info(
                f"Initializing SNMP session for {self.device_config['ip_address']}"
            )

        except Exception as e:
            self.logger.error(f"SNMP initialization failed: {e}")
            raise

    async def _disconnect(self):
        """Close SNMP session"""
        pass

    async def collect_telemetry(self) -> List[TelemetryEvent]:
        """Collect SNMP data"""
        events = []

        try:
            # Simulate SNMP data collection
            snmp_data = {
                "1.3.6.1.2.1.1.1.0": "Cisco IOS Software, Version 15.1",
                "1.3.6.1.2.1.1.3.0": "12345600",  # Uptime in centiseconds
                "1.3.6.1.2.1.2.1.0": "24",  # Number of interfaces
                "1.3.6.1.2.1.25.1.1.0": "12345600",  # System uptime
            }

            for oid, value in snmp_data.items():
                event = self._create_event(
                    event_type="METRIC",
                    data={
                        "oid": oid,
                        "value": value,
                        "snmp_version": self.version,
                        "community": "***",  # Don't log community string
                    },
                )
                events.append(event)

        except Exception as e:
            self.logger.error(f"SNMP data collection failed: {e}")

        return events

    def _process_data(self, raw_data: Dict) -> Dict:
        """Process SNMP data into standardized metrics"""
        oid = raw_data.get("oid", "")
        value = raw_data.get("value", "")

        # Map common OIDs to human-readable names
        oid_mapping = {
            "1.3.6.1.2.1.1.1.0": {"name": "system_description", "type": "string"},
            "1.3.6.1.2.1.1.3.0": {"name": "system_uptime", "type": "counter"},
            "1.3.6.1.2.1.2.1.0": {"name": "interface_count", "type": "gauge"},
        }

        oid_info = oid_mapping.get(
            oid, {"name": f'oid_{oid.replace(".", "_")}', "type": "unknown"}
        )

        processed = {
            "metric_name": oid_info["name"],
            "metric_type": oid_info["type"],
            "raw_value": value,
            "oid": oid,
        }

        # Convert specific metrics
        if oid_info["name"] == "system_uptime":
            processed["uptime_seconds"] = int(value) / 100 if value.isdigit() else 0

        return processed


class ModbusCollector(BaseProtocolCollector):
    """Modbus telemetry collector for industrial devices"""

    def __init__(self, device_config: Dict, event_callback: Callable):
        super().__init__(device_config, event_callback)
        self.modbus_config = device_config.get("modbus", {})
        self.unit_id = self.modbus_config.get("unit_id", 1)
        self.port = self.modbus_config.get("port", 502)
        self.registers_to_read = self.modbus_config.get(
            "registers",
            [
                {"address": 0, "count": 10, "type": "holding"},
                {"address": 10000, "count": 5, "type": "input"},
            ],
        )

    async def _connect(self):
        """Connect to Modbus device"""
        try:
            # This would use a real Modbus library like pymodbus
            self.logger.info(
                f"Connecting to Modbus device {self.device_config['ip_address']}:{self.port}"
            )

        except Exception as e:
            self.logger.error(f"Modbus connection failed: {e}")
            raise

    async def _disconnect(self):
        """Disconnect from Modbus device"""
        pass

    async def collect_telemetry(self) -> List[TelemetryEvent]:
        """Collect Modbus register data"""
        events = []

        try:
            # Simulate Modbus data collection
            for register_config in self.registers_to_read:
                register_data = {
                    "register_type": register_config["type"],
                    "start_address": register_config["address"],
                    "count": register_config["count"],
                    "values": [
                        100 + i for i in range(register_config["count"])
                    ],  # Simulated values
                    "unit_id": self.unit_id,
                }

                event = self._create_event(
                    event_type="METRIC", data=register_data, severity="INFO"
                )
                events.append(event)

        except Exception as e:
            self.logger.error(f"Modbus data collection failed: {e}")

        return events

    def _process_data(self, raw_data: Dict) -> Dict:
        """Process Modbus data into standardized metrics"""
        processed = {
            "metric_name": f"modbus_{raw_data.get('register_type', 'unknown')}",
            "register_address": raw_data.get("start_address"),
            "register_count": raw_data.get("count"),
            "values": raw_data.get("values", []),
            "unit_id": raw_data.get("unit_id"),
        }

        # Calculate statistics
        values = raw_data.get("values", [])
        if values:
            processed["min_value"] = min(values)
            processed["max_value"] = max(values)
            processed["avg_value"] = sum(values) / len(values)

        return processed


class HL7FHIRCollector(BaseProtocolCollector):
    """HL7 FHIR telemetry collector for healthcare devices"""

    def __init__(self, device_config: Dict, event_callback: Callable):
        super().__init__(device_config, event_callback)
        self.fhir_config = device_config.get("fhir", {})
        self.base_url = self.fhir_config.get(
            "base_url", f"http://{device_config['ip_address']}/fhir"
        )
        self.resources_to_monitor = self.fhir_config.get(
            "resources", ["Patient", "Observation", "Device", "DiagnosticReport"]
        )

    async def _connect(self):
        """Initialize FHIR client"""
        try:
            self.logger.info(f"Initializing FHIR client for {self.base_url}")

        except Exception as e:
            self.logger.error(f"FHIR client initialization failed: {e}")
            raise

    async def _disconnect(self):
        """Close FHIR client"""
        pass

    async def collect_telemetry(self) -> List[TelemetryEvent]:
        """Collect FHIR resources"""
        events = []

        try:
            # Simulate FHIR data collection
            for resource_type in self.resources_to_monitor:
                fhir_data = {
                    "resource_type": resource_type,
                    "total_count": 50,  # Simulated count
                    "last_updated": datetime.now().isoformat(),
                    "endpoint": f"{self.base_url}/{resource_type}",
                }

                if resource_type == "Observation":
                    fhir_data["critical_values"] = 3
                    fhir_data["abnormal_values"] = 7
                elif resource_type == "Device":
                    fhir_data["active_devices"] = 45
                    fhir_data["inactive_devices"] = 5

                event = self._create_event(
                    event_type="METRIC",
                    data=fhir_data,
                    severity="INFO" if resource_type != "Observation" else "WARN",
                )
                events.append(event)

        except Exception as e:
            self.logger.error(f"FHIR data collection failed: {e}")

        return events

    def _process_data(self, raw_data: Dict) -> Dict:
        """Process FHIR data into standardized metrics"""
        resource_type = raw_data.get("resource_type", "Unknown")

        processed = {
            "metric_name": f"fhir_{resource_type.lower()}_count",
            "resource_type": resource_type,
            "total_resources": raw_data.get("total_count", 0),
            "endpoint": raw_data.get("endpoint"),
            "last_updated": raw_data.get("last_updated"),
        }

        # Add resource-specific metrics
        if "critical_values" in raw_data:
            processed["critical_observations"] = raw_data["critical_values"]
        if "active_devices" in raw_data:
            processed["device_status"] = {
                "active": raw_data["active_devices"],
                "inactive": raw_data["inactive_devices"],
            }

        return processed


class SyslogCollector(BaseProtocolCollector):
    """Syslog telemetry collector for system logs"""

    def __init__(self, device_config: Dict, event_callback: Callable):
        super().__init__(device_config, event_callback)
        self.syslog_port = device_config.get("syslog_port", 514)
        self.log_buffer = []
        self.server_socket = None

    async def _connect(self):
        """Start syslog server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server_socket.bind(("0.0.0.0", self.syslog_port))
            self.logger.info(f"Syslog server listening on port {self.syslog_port}")

        except Exception as e:
            self.logger.error(f"Syslog server startup failed: {e}")
            raise

    async def _disconnect(self):
        """Stop syslog server"""
        if self.server_socket:
            self.server_socket.close()

    async def collect_telemetry(self) -> List[TelemetryEvent]:
        """Collect syslog messages"""
        events = []

        try:
            # In real implementation, this would receive UDP syslog messages
            # For simulation, create sample log events
            sample_logs = [
                {
                    "facility": 16,  # Local use 0
                    "severity": 6,  # Info
                    "timestamp": datetime.now(),
                    "hostname": self.device_config["ip_address"],
                    "tag": "systemd",
                    "message": "Service started successfully",
                },
                {
                    "facility": 16,
                    "severity": 4,  # Warning
                    "timestamp": datetime.now(),
                    "hostname": self.device_config["ip_address"],
                    "tag": "kernel",
                    "message": "High memory usage detected",
                },
            ]

            for log_entry in sample_logs:
                event = self._create_event(
                    event_type="LOG",
                    data=log_entry,
                    severity=self._map_syslog_severity(log_entry["severity"]),
                )
                events.append(event)

        except Exception as e:
            self.logger.error(f"Syslog collection failed: {e}")

        return events

    def _map_syslog_severity(self, severity: int) -> str:
        """Map syslog severity to standard severity levels"""
        mapping = {
            0: "CRITICAL",  # Emergency
            1: "CRITICAL",  # Alert
            2: "CRITICAL",  # Critical
            3: "ERROR",  # Error
            4: "WARN",  # Warning
            5: "WARN",  # Notice
            6: "INFO",  # Informational
            7: "INFO",  # Debug
        }
        return mapping.get(severity, "INFO")

    def _process_data(self, raw_data: Dict) -> Dict:
        """Process syslog data into standardized format"""
        processed = {
            "log_level": self._map_syslog_severity(raw_data.get("severity", 6)),
            "facility": raw_data.get("facility"),
            "source_host": raw_data.get("hostname"),
            "program": raw_data.get("tag"),
            "message": raw_data.get("message"),
            "log_timestamp": raw_data.get("timestamp", datetime.now()).isoformat(),
        }

        # Extract security-relevant patterns
        message = raw_data.get("message", "").lower()
        if any(
            keyword in message
            for keyword in ["failed", "error", "denied", "unauthorized"]
        ):
            processed["security_relevant"] = True
            processed["potential_threat"] = True

        return processed


class ProtocolCollectorManager:
    """Manages multiple protocol collectors for a device"""

    def __init__(self, device_config: Dict):
        self.device_config = device_config
        self.collectors: Dict[str, BaseProtocolCollector] = {}
        self.event_callback = self._handle_telemetry_event
        self.logger = logging.getLogger(self.__class__.__name__)

    async def initialize_collectors(self):
        """Initialize collectors based on device protocols"""
        protocols = self.device_config.get("supported_protocols", [])

        collector_mapping = {
            "MQTT": MQTTCollector,
            "SNMP": SNMPCollector,
            "Modbus": ModbusCollector,
            "HL7-FHIR": HL7FHIRCollector,
            "Syslog": SyslogCollector,
        }

        for protocol in protocols:
            if protocol in collector_mapping:
                try:
                    collector_class = collector_mapping[protocol]
                    collector = collector_class(self.device_config, self.event_callback)
                    self.collectors[protocol] = collector

                    self.logger.info(
                        f"Initialized {protocol} collector for device {self.device_config['device_id']}"
                    )

                except Exception as e:
                    self.logger.error(f"Failed to initialize {protocol} collector: {e}")

    async def start_collection(self):
        """Start all collectors"""
        for protocol, collector in self.collectors.items():
            try:
                await collector.start()
                self.logger.info(f"Started {protocol} collection")

            except Exception as e:
                self.logger.error(f"Failed to start {protocol} collection: {e}")

        # Start collection loop
        asyncio.create_task(self._collection_loop())

    async def stop_collection(self):
        """Stop all collectors"""
        for protocol, collector in self.collectors.items():
            try:
                await collector.stop()

            except Exception as e:
                self.logger.error(f"Failed to stop {protocol} collection: {e}")

    async def _collection_loop(self):
        """Main collection loop"""
        while self.collectors:
            try:
                collection_tasks = []

                for protocol, collector in self.collectors.items():
                    if collector.is_running:
                        task = asyncio.create_task(collector.collect_telemetry())
                        collection_tasks.append((protocol, task))

                # Wait for all collections to complete
                for protocol, task in collection_tasks:
                    try:
                        events = await task
                        for event in events:
                            await self.event_callback(event)

                    except Exception as e:
                        self.logger.error(f"Collection failed for {protocol}: {e}")

                # Wait before next collection cycle
                await asyncio.sleep(self._get_collection_interval())

            except Exception as e:
                self.logger.error(f"Collection loop error: {e}")
                await asyncio.sleep(60)  # Error recovery delay

    async def _handle_telemetry_event(self, event: TelemetryEvent):
        """Handle collected telemetry event"""
        try:
            # Convert to protobuf format
            device_telemetry = self._convert_to_protobuf(event)

            # Send to EventBus (this would use the existing EventBus client)
            self.logger.debug(
                f"Sending telemetry event: {event.event_type} from {event.device_id}"
            )

        except Exception as e:
            self.logger.error(f"Failed to handle telemetry event: {e}")

    def _convert_to_protobuf(self, event: TelemetryEvent) -> pb.Envelope:
        """Convert telemetry event to protobuf format"""
        # This would create appropriate protobuf messages
        # For now, create a flow event as placeholder

        flow_event = pb.FlowEvent(
            src_ip=self.device_config["ip_address"],
            dst_ip="0.0.0.0",  # Placeholder
            src_port=0,
            dst_port=0,
            protocol=event.protocol,
            bytes_sent=len(json.dumps(event.processed_data)),
            bytes_recv=0,
            start_time=int(event.timestamp.timestamp()),
        )

        # Create envelope (this would use the existing envelope creation logic)
        envelope = pb.Envelope(
            version="v1",
            ts_ns=int(event.timestamp.timestamp() * 1_000_000_000),
            idempotency_key=f"{event.device_id}_{event.timestamp.timestamp()}",
            flow=flow_event,
        )

        return envelope

    def _get_collection_interval(self) -> int:
        """Get collection interval based on device type"""
        device_type = self.device_config.get("device_type", "UNKNOWN")

        intervals = {
            "MEDICAL": 5,  # 5 seconds
            "INDUSTRIAL": 1,  # 1 second
            "IOT": 30,  # 30 seconds
            "NETWORK": 60,  # 1 minute
            "ENDPOINT": 300,  # 5 minutes
        }

        return intervals.get(device_type, 60)


class UniversalTelemetryCollector:
    """
    Simplified telemetry collector interface for testing and basic usage.
    Wraps ProtocolCollectorManager with a simpler API.
    """

    def __init__(self, device_config: Optional[Dict] = None):
        """Initialize collector with optional device configuration"""
        self.device_config = device_config or {}
        self.collectors: Dict[str, BaseProtocolCollector] = {}
        self.collection_schedules: Dict[str, Dict[str, Any]] = {}
        self.logger = logging.getLogger(self.__class__.__name__)

        # Initialize default collectors based on config
        self._initialize_default_collectors()

    def _initialize_default_collectors(self):
        """Initialize default collector configurations"""
        # Default collection schedules
        self.collection_schedules = {
            "snmp": {"interval": 60, "enabled": False},
            "mqtt": {"interval": 30, "enabled": False},
            "modbus": {"interval": 5, "enabled": False},
            "syslog": {"interval": 1, "enabled": False},
            "fhir": {"interval": 300, "enabled": False},
        }

    def add_collector(self, protocol: str, collector: BaseProtocolCollector):
        """Add a protocol collector"""
        self.collectors[protocol.lower()] = collector
        self.logger.info(f"Added {protocol} collector")

    def remove_collector(self, protocol: str):
        """Remove a protocol collector"""
        if protocol.lower() in self.collectors:
            del self.collectors[protocol.lower()]
            self.logger.info(f"Removed {protocol} collector")

    def enable_collection(self, protocol: str, interval: int = 60):
        """Enable collection for a specific protocol"""
        protocol_lower = protocol.lower()
        if protocol_lower in self.collection_schedules:
            self.collection_schedules[protocol_lower]["enabled"] = True
            self.collection_schedules[protocol_lower]["interval"] = interval
            self.logger.info(f"Enabled {protocol} collection (interval: {interval}s)")

    def disable_collection(self, protocol: str):
        """Disable collection for a specific protocol"""
        protocol_lower = protocol.lower()
        if protocol_lower in self.collection_schedules:
            self.collection_schedules[protocol_lower]["enabled"] = False
            self.logger.info(f"Disabled {protocol} collection")

    def collect_all(self) -> Dict[str, List[Dict]]:
        """
        Collect telemetry from all enabled collectors.
        Returns dictionary mapping protocol names to lists of telemetry data.
        """
        results = {}

        for protocol, schedule in self.collection_schedules.items():
            if schedule.get("enabled", False) and protocol in self.collectors:
                try:
                    collector = self.collectors[protocol]
                    # For synchronous interface, we simulate collection
                    # In production, this would call collector.collect_telemetry()
                    results[protocol] = self._simulate_collection(protocol)
                except Exception as e:
                    self.logger.error(f"Collection failed for {protocol}: {e}")
                    results[protocol] = []

        return results

    def _simulate_collection(self, protocol: str) -> List[Dict]:
        """Simulate telemetry collection for testing"""
        # Return sample telemetry data
        sample_data = {
            "snmp": [
                {
                    "device_id": "device_001",
                    "oid": "1.3.6.1.2.1.1.1.0",
                    "value": "Test Device",
                },
                {
                    "device_id": "device_001",
                    "oid": "1.3.6.1.2.1.1.3.0",
                    "value": "12345600",
                },
            ],
            "mqtt": [
                {"device_id": "iot_001", "topic": "sensors/temperature", "value": 23.5},
                {"device_id": "iot_001", "topic": "sensors/humidity", "value": 65.0},
            ],
            "modbus": [
                {"device_id": "plc_001", "register": 0, "value": 100},
                {"device_id": "plc_001", "register": 1, "value": 200},
            ],
        }

        return sample_data.get(protocol, [])

    def get_status(self) -> Dict[str, Any]:
        """Get collector status"""
        return {
            "total_collectors": len(self.collectors),
            "active_collectors": sum(
                1 for s in self.collection_schedules.values() if s.get("enabled", False)
            ),
            "collectors": list(self.collectors.keys()),
            "schedules": self.collection_schedules,
        }


# Usage example
if __name__ == "__main__":

    async def main():
        # Example device configuration
        device_config = {
            "device_id": "iot_device_001",
            "ip_address": "192.168.1.100",
            "device_type": "IOT",
            "supported_protocols": ["MQTT", "SNMP"],
            "mqtt": {
                "host": "192.168.1.100",
                "port": 1883,
                "topics": ["sensors/+", "devices/+/status"],
            },
            "snmp_community": "public",
            "tags": ["production", "iot", "sensors"],
        }

        # Initialize and start collection
        manager = ProtocolCollectorManager(device_config)
        await manager.initialize_collectors()
        await manager.start_collection()

        # Run for demonstration
        await asyncio.sleep(60)

        # Stop collection
        await manager.stop_collection()

    asyncio.run(main())
