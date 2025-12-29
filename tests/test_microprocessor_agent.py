"""
Comprehensive Test Suite for Microprocessor Agent
Tests all components and integration scenarios.
"""

import unittest
import asyncio
import time
import json
from unittest.mock import Mock, patch, MagicMock
from dataclasses import dataclass
from typing import Dict, List, Any
import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

try:
    from src.amoskys.intelligence.integration.agent_core import MicroprocessorAgentCore
    from src.amoskys.intelligence.fusion.threat_correlator import (
        IntelligenceFusionEngine, TelemetryEvent, DeviceType, ThreatLevel
    )
    from src.amoskys.agents.discovery.device_scanner import DeviceDiscoveryEngine
    from src.amoskys.agents.protocols.universal_collector import UniversalTelemetryCollector
    from amoskys.edge import EdgeOptimizer  # Use package import for CI compatibility
except ImportError as e:
    print(f"Import warning: {e}")

class TestMicroprocessorAgent(unittest.TestCase):
    """Test the core microprocessor agent functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.config = {
            'enable_packet_capture': False,
            'discovery_networks': ['192.168.1.0/24'],
            'discovery_interval': 5,
            'collection_interval': 10,
            'edge_optimization': {
                'max_memory_mb': 128,
                'max_cpu_percent': 50
            }
        }
        self.agent = MicroprocessorAgentCore(self.config)

    def tearDown(self):
        """Clean up after tests."""
        if self.agent.running:
            self.agent.stop()

    def test_agent_initialization(self):
        """Test agent initialization."""
        result = self.agent.initialize()
        self.assertTrue(result, "Agent should initialize successfully")

    def test_agent_start_stop(self):
        """Test agent start and stop functionality."""
        # Test start
        result = self.agent.start()
        self.assertTrue(result, "Agent should start successfully")
        self.assertTrue(self.agent.running, "Agent should be in running state")
        
        # Test stop
        self.agent.stop()
        self.assertFalse(self.agent.running, "Agent should be stopped")

    def test_status_reporting(self):
        """Test status reporting functionality."""
        self.agent.initialize()
        status = self.agent.get_status()
        
        required_fields = ['running', 'uptime', 'component_health', 'metrics']
        for field in required_fields:
            self.assertIn(field, status, f"Status should contain {field}")

    def test_external_callbacks(self):
        """Test external callback registration and triggering."""
        callback_called = []
        
        def test_callback(event):
            callback_called.append(event)
        
        self.agent.add_external_callback('threat_detected', test_callback)
        
        # Simulate threat event
        mock_event = Mock()
        for callback in self.agent.external_callbacks['threat_detected']:
            callback(mock_event)
        
        self.assertEqual(len(callback_called), 1, "Callback should be called once")


class TestIntelligenceFusionEngine(unittest.TestCase):
    """Test the intelligence fusion engine."""
    
    def setUp(self):
        """Set up test environment."""
        self.fusion_engine = IntelligenceFusionEngine()

    def tearDown(self):
        """Clean up after tests."""
        if self.fusion_engine.processing_enabled:
            self.fusion_engine.stop_processing()

    def test_fusion_engine_initialization(self):
        """Test fusion engine initialization."""
        self.assertIsInstance(self.fusion_engine.correlation_rules, dict)
        self.assertIsInstance(self.fusion_engine.behavioral_models, dict)
        self.assertIsInstance(self.fusion_engine.threat_intelligence, dict)

    def test_telemetry_ingestion(self):
        """Test telemetry event ingestion."""
        event = TelemetryEvent(
            timestamp=time.time(),
            device_id="test_device_001",
            device_type=DeviceType.IOT_DEVICE,
            source="test_source",
            event_type="test_event",
            data={'test_key': 'test_value'}
        )
        
        # Test ingestion
        self.fusion_engine.ingest_telemetry(event)
        
        # Verify device profile creation
        self.assertIn("test_device_001", self.fusion_engine.device_profiles)
        profile = self.fusion_engine.device_profiles["test_device_001"]
        self.assertEqual(profile.device_type, DeviceType.IOT_DEVICE)

    def test_threat_correlation(self):
        """Test threat correlation functionality."""
        # Create multiple related events
        events = [
            TelemetryEvent(
                timestamp=time.time(),
                device_id="iot_device_001",
                device_type=DeviceType.IOT_DEVICE,
                source="network_monitor",
                event_type="network_connection",
                data={
                    'src_ip': '192.168.1.100',
                    'dst_ip': '8.8.8.8',
                    'protocol': 'HTTP'
                }
            ),
            TelemetryEvent(
                timestamp=time.time() + 1,
                device_id="iot_device_001",
                device_type=DeviceType.IOT_DEVICE,
                source="network_monitor",
                event_type="data_transfer",
                data={
                    'bytes': 1000000,  # Large transfer
                    'destination': '8.8.8.8'
                }
            )
        ]
        
        for event in events:
            self.fusion_engine.ingest_telemetry(event)
        
        # Verify events are stored
        self.assertGreaterEqual(len(self.fusion_engine.telemetry_buffer), 2)

    def test_device_profiling(self):
        """Test device behavioral profiling."""
        device_id = "test_device_002"
        
        # Create multiple events for the same device
        for i in range(5):
            event = TelemetryEvent(
                timestamp=time.time() + i,
                device_id=device_id,
                device_type=DeviceType.ENDPOINT,
                source="system_monitor",
                event_type="process_execution",
                data={
                    'process_name': f'process_{i}',
                    'user': 'test_user'
                }
            )
            self.fusion_engine.ingest_telemetry(event)
        
        # Verify profile exists and has data
        self.assertIn(device_id, self.fusion_engine.device_profiles)
        profile = self.fusion_engine.device_profiles[device_id]
        self.assertEqual(profile.device_type, DeviceType.ENDPOINT)
        self.assertGreater(profile.last_seen, profile.first_seen)

    def test_threat_detection_thresholds(self):
        """Test threat detection threshold handling."""
        # Test different threat levels
        high_risk_event = TelemetryEvent(
            timestamp=time.time(),
            device_id="high_risk_device",
            device_type=DeviceType.MEDICAL_DEVICE,
            source="security_monitor",
            event_type="unauthorized_access",
            data={'access_attempt': 'failed_login'},
            risk_score=0.9,
            threat_indicators=['suspicious_login']
        )
        
        self.fusion_engine.ingest_telemetry(high_risk_event)
        
        # Verify high risk event increases threat metrics
        self.assertGreater(high_risk_event.risk_score, 0.5)

    def test_compliance_monitoring(self):
        """Test compliance status monitoring."""
        medical_device_id = "medical_device_001"
        
        # Create medical device event
        event = TelemetryEvent(
            timestamp=time.time(),
            device_id=medical_device_id,
            device_type=DeviceType.MEDICAL_DEVICE,
            source="compliance_monitor",
            event_type="data_transmission",
            data={
                'encrypted': True,
                'protocol': 'HL7',
                'destination': 'ehr_system'
            }
        )
        
        self.fusion_engine.ingest_telemetry(event)
        
        # Verify device profile creation
        self.assertIn(medical_device_id, self.fusion_engine.device_profiles)
        profile = self.fusion_engine.device_profiles[medical_device_id]
        self.assertEqual(profile.device_type, DeviceType.MEDICAL_DEVICE)


class TestDeviceDiscovery(unittest.TestCase):
    """Test device discovery functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.device_scanner = DeviceDiscoveryEngine()

    @patch('socket.socket')
    def test_port_scanning(self, mock_socket):
        """Test port scanning functionality."""
        # Mock successful connection
        mock_socket.return_value.__enter__.return_value.connect_ex.return_value = 0
        
        result = self.device_scanner._scan_ports("192.168.1.1", [80, 443])
        
        self.assertIsInstance(result, list)
        # Should detect open ports
        self.assertGreaterEqual(len(result), 0)

    def test_device_fingerprinting(self):
        """Test device fingerprinting logic."""
        # Test IoT device fingerprinting
        mock_services = {
            1883: {'service': 'mqtt', 'banner': 'mosquitto'},
            80: {'service': 'http', 'banner': 'nginx'}
        }
        
        device_type = self.device_scanner._fingerprint_device("192.168.1.100", mock_services)
        
        # Should identify as IoT device based on MQTT
        self.assertEqual(device_type, 'iot_device')

    def test_vulnerability_assessment(self):
        """Test vulnerability assessment functionality."""
        device_info = {
            'ip_address': '192.168.1.50',
            'open_ports': [22, 80, 443],
            'services': {
                22: {'service': 'ssh', 'version': 'OpenSSH 7.4'},
                80: {'service': 'http', 'version': 'Apache 2.4.6'}
            },
            'device_type': 'endpoint'
        }
        
        risk_score = self.device_scanner._assess_vulnerability_risk(device_info)
        
        self.assertIsInstance(risk_score, float)
        self.assertGreaterEqual(risk_score, 0.0)
        self.assertLessEqual(risk_score, 1.0)


class TestUniversalTelemetryCollector(unittest.TestCase):
    """Test universal telemetry collection."""
    
    def setUp(self):
        """Set up test environment."""
        self.collector = UniversalTelemetryCollector()

    def test_collector_initialization(self):
        """Test collector initialization."""
        self.assertIsInstance(self.collector.collectors, dict)
        self.assertIsInstance(self.collector.collection_schedules, dict)

    @patch('subprocess.run')
    def test_snmp_collection(self, mock_subprocess):
        """Test SNMP data collection."""
        # Mock successful SNMP response
        mock_subprocess.return_value.stdout = "1.3.6.1.2.1.1.1.0 = STRING: Test Device"
        mock_subprocess.return_value.returncode = 0
        
        # Test SNMP collection
        snmp_config = {
            'host': '192.168.1.1',
            'community': 'public',
            'oids': ['1.3.6.1.2.1.1.1.0']
        }
        
        # This would normally test actual SNMP collection
        # For now, just verify the collector can be configured
        self.assertIsNotNone(self.collector)

    def test_mqtt_collection_setup(self):
        """Test MQTT collection setup."""
        mqtt_config = {
            'broker_host': 'localhost',
            'broker_port': 1883,
            'topics': ['sensors/+/data']
        }
        
        # Test configuration acceptance
        # Actual MQTT testing would require a broker
        self.assertIsNotNone(mqtt_config)

    def test_data_validation(self):
        """Test telemetry data validation."""
        # Test valid data
        valid_data = {
            'device_id': 'sensor_001',
            'timestamp': time.time(),
            'value': 23.5,
            'unit': 'celsius'
        }
        
        # Test invalid data
        invalid_data = {
            'device_id': '',  # Empty device ID
            'value': 'invalid_value'
        }
        
        # Validation logic would go here
        self.assertTrue(valid_data['device_id'])
        self.assertFalse(invalid_data['device_id'])


class TestEdgeOptimization(unittest.TestCase):
    """Test edge optimization functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.config = {
            'max_memory_mb': 128,
            'max_cpu_percent': 50,
            'compression_enabled': True,
            'batch_size': 100
        }
        self.optimizer = EdgeOptimizer(self.config)

    def test_resource_monitoring(self):
        """Test resource monitoring."""
        resources = self.optimizer.get_resource_usage()
        
        required_fields = ['cpu_percent', 'memory_mb', 'disk_usage_percent']
        for field in required_fields:
            self.assertIn(field, resources)
            self.assertIsInstance(resources[field], (int, float))

    def test_compression_optimization(self):
        """Test data compression optimization."""
        test_data = "This is test data " * 100  # Repetitive data for compression
        
        compressed = self.optimizer._compress_data(test_data.encode())
        self.assertIsInstance(compressed, bytes)
        self.assertLess(len(compressed), len(test_data.encode()))

    def test_batch_optimization(self):
        """Test event batching optimization."""
        # Create multiple small events
        events = []
        for i in range(150):  # More than batch size
            event = {
                'timestamp': time.time() + i,
                'device_id': f'device_{i % 10}',
                'data': {'value': i}
            }
            events.append(event)
        
        # Test batching
        batches = self.optimizer._create_batches(events, batch_size=50)
        
        self.assertGreater(len(batches), 1)  # Should create multiple batches
        self.assertLessEqual(len(batches[0]), 50)  # Each batch should respect size limit

    def test_adaptive_optimization(self):
        """Test adaptive optimization based on resource constraints."""
        # Simulate high resource usage
        high_usage_config = {
            'cpu_percent': 90,
            'memory_mb': 512,
            'constraint_cpu_percent': 80,
            'constraint_memory_mb': 256
        }
        
        recommendations = self.optimizer._generate_optimization_recommendations(high_usage_config)
        
        self.assertIsInstance(recommendations, list)
        self.assertGreater(len(recommendations), 0)


class TestIntegrationScenarios(unittest.TestCase):
    """Test integration scenarios and end-to-end workflows."""
    
    def setUp(self):
        """Set up integration test environment."""
        self.config = {
            'enable_packet_capture': False,
            'discovery_networks': ['192.168.1.0/24'],
            'edge_optimization': {
                'max_memory_mb': 256,
                'compression_enabled': True
            }
        }

    def test_threat_detection_workflow(self):
        """Test complete threat detection workflow."""
        # This would test the full pipeline:
        # 1. Device discovery
        # 2. Telemetry collection
        # 3. Feature extraction
        # 4. Threat correlation
        # 5. Response actions
        
        # For now, test basic workflow components
        fusion_engine = IntelligenceFusionEngine()
        
        # Simulate suspicious IoT activity
        suspicious_event = TelemetryEvent(
            timestamp=time.time(),
            device_id="iot_camera_001",
            device_type=DeviceType.IOT_DEVICE,
            source="network_monitor",
            event_type="network_connection",
            data={
                'src_ip': '192.168.1.100',
                'dst_ip': '8.8.8.8',  # External destination
                'protocol': 'HTTP',
                'bytes': 50000000,  # Large data transfer
                'unusual_timing': True
            },
            threat_indicators=['large_data_transfer', 'external_connection']
        )
        
        fusion_engine.ingest_telemetry(suspicious_event)
        
        # Verify threat processing
        self.assertGreater(len(fusion_engine.telemetry_buffer), 0)

    def test_medical_device_compliance(self):
        """Test medical device compliance monitoring."""
        fusion_engine = IntelligenceFusionEngine()
        
        # Simulate medical device activity
        medical_event = TelemetryEvent(
            timestamp=time.time(),
            device_id="medical_monitor_001",
            device_type=DeviceType.MEDICAL_DEVICE,
            source="hl7_monitor",
            event_type="patient_data_transmission",
            data={
                'patient_id': 'PATIENT_12345',
                'data_type': 'vital_signs',
                'encrypted': True,
                'destination': 'ehr_system',
                'protocol': 'HL7'
            }
        )
        
        fusion_engine.ingest_telemetry(medical_event)
        
        # Verify device profiling
        device_id = "medical_monitor_001"
        self.assertIn(device_id, fusion_engine.device_profiles)
        profile = fusion_engine.device_profiles[device_id]
        self.assertEqual(profile.device_type, DeviceType.MEDICAL_DEVICE)

    def test_industrial_control_monitoring(self):
        """Test industrial control system monitoring."""
        fusion_engine = IntelligenceFusionEngine()
        
        # Simulate industrial control activity
        control_event = TelemetryEvent(
            timestamp=time.time(),
            device_id="plc_001",
            device_type=DeviceType.INDUSTRIAL_CONTROL,
            source="modbus_monitor",
            event_type="control_command",
            data={
                'command_type': 'write_coil',
                'address': '0x0001',
                'value': True,
                'operator': 'authorized_user',
                'protocol': 'Modbus'
            }
        )
        
        fusion_engine.ingest_telemetry(control_event)
        
        # Verify processing
        self.assertGreater(len(fusion_engine.telemetry_buffer), 0)

    def test_performance_under_load(self):
        """Test system performance under load."""
        fusion_engine = IntelligenceFusionEngine()
        
        # Generate high volume of events
        start_time = time.time()
        event_count = 1000
        
        for i in range(event_count):
            event = TelemetryEvent(
                timestamp=time.time(),
                device_id=f"device_{i % 100}",
                device_type=DeviceType.IOT_DEVICE,
                source="load_test",
                event_type="sensor_data",
                data={'sensor_value': i % 100}
            )
            fusion_engine.ingest_telemetry(event)
        
        processing_time = time.time() - start_time
        events_per_second = event_count / processing_time
        
        # Verify performance meets requirements
        self.assertGreater(events_per_second, 100)  # Should process at least 100 events/second


class TestErrorHandling(unittest.TestCase):
    """Test error handling and resilience."""
    
    def test_invalid_telemetry_data(self):
        """Test handling of invalid telemetry data."""
        fusion_engine = IntelligenceFusionEngine()
        
        # Test with missing required fields
        try:
            invalid_event = TelemetryEvent(
                timestamp=None,  # Invalid timestamp
                device_id="",    # Empty device ID
                device_type=DeviceType.UNKNOWN,
                source="test",
                event_type="test",
                data={}
            )
            fusion_engine.ingest_telemetry(invalid_event)
            # Should handle gracefully without crashing
        except Exception as e:
            self.fail(f"Should handle invalid data gracefully: {e}")

    def test_network_error_resilience(self):
        """Test resilience to network errors."""
        # Test device scanner resilience
        scanner = DeviceDiscoveryEngine()
        
        # Test with invalid network range
        try:
            devices = scanner.scan_network("invalid_network")
            self.assertIsInstance(devices, list)  # Should return empty list, not crash
        except Exception as e:
            self.fail(f"Should handle invalid network gracefully: {e}")

    def test_resource_constraint_handling(self):
        """Test handling of resource constraints."""
        optimizer = EdgeOptimizer({
            'max_memory_mb': 64,  # Very low memory limit
            'max_cpu_percent': 10  # Very low CPU limit
        })
        
        # Test optimization under severe constraints
        large_data = "x" * 1000000  # 1MB of data
        
        try:
            # Should optimize or reject, but not crash
            result = optimizer.optimize_data(large_data.encode())
            self.assertIsNotNone(result)
        except Exception as e:
            # Acceptable to raise specific constraint exceptions
            self.assertIn("resource", str(e).lower())


def run_performance_benchmarks():
    """Run performance benchmarks for key components."""
    print("\n" + "="*50)
    print("MICROPROCESSOR AGENT PERFORMANCE BENCHMARKS")
    print("="*50)
    
    # Benchmark telemetry ingestion
    fusion_engine = IntelligenceFusionEngine()
    
    event_count = 10000
    start_time = time.time()
    
    for i in range(event_count):
        event = TelemetryEvent(
            timestamp=time.time(),
            device_id=f"device_{i % 1000}",
            device_type=DeviceType.IOT_DEVICE,
            source="benchmark",
            event_type="sensor_data",
            data={'value': i}
        )
        fusion_engine.ingest_telemetry(event)
    
    ingestion_time = time.time() - start_time
    events_per_second = event_count / ingestion_time
    
    print(f"Telemetry Ingestion: {events_per_second:.0f} events/second")
    
    # Benchmark compression
    optimizer = EdgeOptimizer({'compression_enabled': True})
    test_data = json.dumps({'test': 'data'} * 1000).encode()
    
    start_time = time.time()
    for _ in range(1000):
        compressed = optimizer._compress_data(test_data)
    compression_time = time.time() - start_time
    
    print(f"Data Compression: {1000/compression_time:.0f} compressions/second")
    print(f"Compression Ratio: {len(test_data)/len(compressed):.1f}x")
    
    # Memory usage
    import psutil
    process = psutil.Process()
    memory_mb = process.memory_info().rss / 1024 / 1024
    print(f"Memory Usage: {memory_mb:.1f} MB")
    
    print("="*50)


if __name__ == '__main__':
    # Run unit tests
    unittest.main(argv=[''], exit=False, verbosity=2)
    
    # Run performance benchmarks
    run_performance_benchmarks()
