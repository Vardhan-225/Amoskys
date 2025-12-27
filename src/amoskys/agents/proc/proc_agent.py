#!/usr/bin/env python3
"""
AMOSKYS Process Agent (ProcAgent)
Process monitoring with EventBus publishing
"""

import psutil
import time
import logging
import grpc
import socket
from datetime import datetime

from amoskys.proto import messaging_schema_pb2 as pb
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.proto import universal_telemetry_pb2_grpc as universal_pbrpc
from amoskys.config import get_config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ProcAgent")

config = get_config()
EVENTBUS_ADDRESS = config.agent.bus_address
CERT_DIR = config.agent.cert_dir


class ProcAgent:
    """Simple process monitoring agent"""
    
    def __init__(self):
        """Initialize agent"""
        self.last_pids = set()
    
    def _get_grpc_channel(self):
        """Create gRPC channel to EventBus with mTLS"""
        try:
            # Load client certificates for mTLS
            with open(f"{CERT_DIR}/ca.crt", "rb") as f:
                ca_cert = f.read()
            with open(f"{CERT_DIR}/agent.crt", "rb") as f:
                client_cert = f.read()
            with open(f"{CERT_DIR}/agent.key", "rb") as f:
                client_key = f.read()

            credentials = grpc.ssl_channel_credentials(
                root_certificates=ca_cert,
                private_key=client_key,
                certificate_chain=client_cert
            )
            channel = grpc.secure_channel(EVENTBUS_ADDRESS, credentials)
            logger.info("Created secure gRPC channel with mTLS")
            return channel
        except FileNotFoundError as e:
            logger.error("Certificate not found: %s", e)
            return None
        except Exception as e:
            logger.error("Failed to create gRPC channel: %s", str(e))
            return None
    
    def _scan_processes(self):
        """Scan all running processes"""
        processes = {}
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                processes[proc.pid] = {
                    'pid': proc.pid,
                    'name': proc.name(),
                    'username': proc.username(),
                    'cpu_percent': proc.cpu_percent(interval=0),
                    'memory_percent': proc.memory_percent(),
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return processes
    
    def _create_telemetry(self, processes):
        """Create DeviceTelemetry protobuf"""
        timestamp_ns = int(time.time() * 1e9)
        
        events = []
        
        # Process count metric
        events.append(telemetry_pb2.TelemetryEvent(
            event_id=f"proc_count_{timestamp_ns}",
            event_type="METRIC",
            severity="INFO",
            event_timestamp_ns=timestamp_ns,
            metric_data=telemetry_pb2.MetricData(
                metric_name="process_count",
                metric_type="GAUGE",
                numeric_value=float(len(processes)),
                unit="processes"
            ),
            source_component="proc_agent",
            tags=["process", "metric"]
        ))
        
        # CPU usage metric
        cpu_percent = psutil.cpu_percent(interval=0.1)
        events.append(telemetry_pb2.TelemetryEvent(
            event_id=f"system_cpu_{timestamp_ns}",
            event_type="METRIC",
            severity="INFO",
            event_timestamp_ns=timestamp_ns,
            metric_data=telemetry_pb2.MetricData(
                metric_name="system_cpu_percent",
                metric_type="GAUGE",
                numeric_value=cpu_percent,
                unit="percent"
            ),
            source_component="proc_agent",
            tags=["system", "metric"]
        ))
        
        # Memory usage metric
        mem = psutil.virtual_memory()
        events.append(telemetry_pb2.TelemetryEvent(
            event_id=f"system_mem_{timestamp_ns}",
            event_type="METRIC",
            severity="INFO",
            event_timestamp_ns=timestamp_ns,
            metric_data=telemetry_pb2.MetricData(
                metric_name="system_memory_percent",
                metric_type="GAUGE",
                numeric_value=mem.percent,
                unit="percent"
            ),
            source_component="proc_agent",
            tags=["system", "metric"]
        ))
        
        # Device metadata
        try:
            ip_addr = socket.gethostbyname(socket.gethostname())
        except:
            ip_addr = "127.0.0.1"
        
        metadata = telemetry_pb2.DeviceMetadata(
            manufacturer="Unknown",
            model=socket.gethostname(),
            ip_address=ip_addr,
            protocols=["PROC"]
        )
        
        # DeviceTelemetry
        device_telemetry = telemetry_pb2.DeviceTelemetry(
            device_id=socket.gethostname(),
            device_type="HOST",
            protocol="PROC",
            metadata=metadata,
            events=events,
            timestamp_ns=timestamp_ns,
            collection_agent="proc-agent",
            agent_version="1.0.0"
        )
        
        return device_telemetry
    
    def _publish_telemetry(self, device_telemetry):
        """Publish telemetry to EventBus"""
        try:
            channel = self._get_grpc_channel()
            if not channel:
                logger.error("No gRPC channel")
                return False
            
            # Create UniversalEnvelope for UniversalEventBus
            timestamp_ns = int(time.time() * 1e9)
            envelope = telemetry_pb2.UniversalEnvelope(
                version="v1",
                ts_ns=timestamp_ns,
                idempotency_key=f"{device_telemetry.device_id}_{timestamp_ns}",
                device_telemetry=device_telemetry,
                signing_algorithm="Ed25519",
                priority="NORMAL",
                requires_acknowledgment=True
            )
            
            # Publish via UniversalEventBus.PublishTelemetry
            stub = universal_pbrpc.UniversalEventBusStub(channel)
            ack = stub.PublishTelemetry(envelope, timeout=5.0)
            
            if ack.status == telemetry_pb2.UniversalAck.OK:
                logger.info("Published process telemetry")
                return True
            else:
                logger.warning("Publish status: %s", ack.status)
                return False
        except Exception as e:
            logger.error("Publish failed: %s", str(e))
            return False
    
    def collect(self):
        """Collect and publish process telemetry once"""
        try:
            logger.info("Collecting process telemetry...")
            processes = self._scan_processes()
            device_telemetry = self._create_telemetry(processes)
            success = self._publish_telemetry(device_telemetry)
            
            if success:
                logger.info("Collection complete (%d processes)", len(processes))
            else:
                logger.warning("Collection failed")
            
            return success
        except Exception as e:
            logger.error("Collection error: %s", str(e), exc_info=True)
            return False
    
    def run(self, interval=30):
        """Main collection loop"""
        logger.info("AMOSKYS Process Agent starting...")
        logger.info("EventBus: %s", EVENTBUS_ADDRESS)
        logger.info("Collection interval: %ds", interval)
        
        cycle = 0
        while True:
            cycle += 1
            logger.info("=" * 60)
            logger.info("Cycle #%d - %s", cycle, datetime.now().isoformat())
            logger.info("=" * 60)
            
            self.collect()
            
            logger.info("Next collection in %ds...", interval)
            time.sleep(interval)


def main():
    """Entry point"""
    agent = ProcAgent()
    agent.run(interval=30)


if __name__ == '__main__':
    main()
