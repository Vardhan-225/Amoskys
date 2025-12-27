#!/usr/bin/env python3
"""
AMOSKYS Process Agent (ProcAgent) - FIXED VERSION
Native process monitoring for Linux/macOS systems
Sends data to EventBus via gRPC

Monitors:
- Running processes
- Resource usage (CPU, memory)
- Process lifecycle events
"""

import psutil
import time
import logging
import grpc
import socket
from datetime import datetime
from typing import Dict, List, Optional

from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.proto import messaging_schema_pb2_grpc as pbrpc
from amoskys.common.crypto.signing import load_private_key, sign
from amoskys.config import get_config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ProcAgent")

# Load configuration
config = get_config()
EVENTBUS_ADDRESS = config.agent.bus_address
CERT_DIR = config.agent.cert_dir
ED25519_SK_PATH = config.crypto.ed25519_private_key


class ProcAgent:
    """Process monitoring agent for AMOSKYS"""
    
    def __init__(self):
        """Initialize process agent"""
        self.sk = None
        self.previous_pids = set()
        self.process_cache = {}
        
        # Load signing key
        try:
            self.sk = load_private_key(ED25519_SK_PATH)
            logger.info("✅ Loaded Ed25519 private key")
        except Exception as e:
            logger.warning(f"⚠️ Could not load signing key: {e}")
    
    def _get_grpc_channel(self):
        """Create gRPC channel to EventBus"""
        try:
            # TLS credentials
            with open(f"{CERT_DIR}/ca.crt", "rb") as f:
                ca_cert = f.read()
            
            credentials = grpc.ssl_channel_credentials(root_certificates=ca_cert)
            channel = grpc.secure_channel(EVENTBUS_ADDRESS, credentials)
            return channel
        except Exception as e:
            logger.warning(f"⚠️ TLS connection failed, trying insecure: {e}")
            return grpc.insecure_channel(EVENTBUS_ADDRESS)
    
    def _scan_processes(self) -> Dict[int, Dict]:
        """Scan all running processes"""
        processes = {}
        
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                pid = proc.pid
                info = {
                    'pid': pid,
                    'name': proc.name(),
                    'username': proc.username(),
                    'cpu_percent': proc.cpu_percent(interval=0.1),
                    'memory_percent': proc.memory_percent(),
                    'memory_mb': proc.memory_info().rss / (1024 * 1024),
                    'num_threads': proc.num_threads(),
                    'status': proc.status(),
                }
                
                try:
                    info['ppid'] = proc.ppid()
                except:
                    info['ppid'] = None
                
                processes[pid] = info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return processes
    
    def _detect_changes(self, current_procs: Dict[int, Dict]) -> Dict:
        """Detect new and terminated processes"""
        current_pids = set(current_procs.keys())
        
        changes = {
            'new': [current_procs[pid] for pid in (current_pids - self.previous_pids)],
            'terminated': list(self.previous_pids - current_pids),
            'total': len(current_procs)
        }
        
        self.previous_pids = current_pids
        self.process_cache = current_procs
        
        return changes
    
    def _create_telemetry_event(self, timestamp_ns: int) -> telemetry_pb2.DeviceTelemetry:
        """Create DeviceTelemetry protobuf"""
        
        # Scan processes
        processes = self._scan_processes()
        changes = self._detect_changes(processes)
        
        # Create metadata
        metadata = telemetry_pb2.DeviceMetadata(
            manufacturer="Apple" if psutil.LINUX is False else "Linux",
            model=socket.gethostname(),
            ip_address=socket.gethostbyname(socket.gethostname()),
        )
        
        # Create events
        events = []
        
        # 1. Process count metric
        events.append(telemetry_pb2.TelemetryEvent(
            event_id=f"proc_count_{timestamp_ns}",
            event_type="METRIC",
            severity="INFO",
            event_timestamp_ns=timestamp_ns,
            metric_data=telemetry_pb2.MetricData(
                metric_name="process_count",
                metric_type="GAUGE",
                numeric_value=float(changes['total']),
                unit="processes"
            ),
            source_component="proc_agent",
            tags=["process", "metric"]
        ))
        
        # 2. New process events
        for proc in changes['new']:
            events.append(telemetry_pb2.TelemetryEvent(
                event_id=f"proc_new_{proc['pid']}_{timestamp_ns}",
                event_type="EVENT",
                severity="INFO",
                event_timestamp_ns=timestamp_ns,
                log_data=telemetry_pb2.LogData(
                    log_level="INFO",
                    message=f"New process: {proc['name']} (PID {proc['pid']})",
                    process_name=proc['name'],
                ),
                source_component="proc_agent",
                tags=["process", "lifecycle", "new"]
            ))
        
        # 3. System resource usage
        cpu_pct = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        
        events.append(telemetry_pb2.TelemetryEvent(
            event_id=f"system_cpu_{timestamp_ns}",
            event_type="METRIC",
            severity="INFO",
            event_timestamp_ns=timestamp_ns,
            metric_data=telemetry_pb2.MetricData(
                metric_name="system_cpu_percent",
                metric_type="GAUGE",
                numeric_value=float(cpu_pct),
                unit="percent"
            ),
            source_component="proc_agent",
            tags=["system", "cpu"]
        ))
        
        events.append(telemetry_pb2.TelemetryEvent(
            event_id=f"system_memory_{timestamp_ns}",
            event_type="METRIC",
            severity="INFO",
            event_timestamp_ns=timestamp_ns,
            metric_data=telemetry_pb2.MetricData(
                metric_name="system_memory_percent",
                metric_type="GAUGE",
                numeric_value=float(memory.percent),
                unit="percent"
            ),
            source_component="proc_agent",
            tags=["system", "memory"]
        ))
        
        # Create DeviceTelemetry
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
    
    def _create_envelope(self, device_telemetry: telemetry_pb2.DeviceTelemetry) -> telemetry_pb2.UniversalEnvelope:
        """Wrap in signed envelope"""
        timestamp_ns = int(time.time() * 1e9)
        device_id = device_telemetry.device_id
        
        envelope = telemetry_pb2.UniversalEnvelope(
            version="v1",
            ts_ns=timestamp_ns,
            idempotency_key=f"{device_id}_{timestamp_ns}",
            device_telemetry=device_telemetry,
            signing_algorithm="Ed25519",
            priority="NORMAL",
            requires_acknowledgment=True
        )
        
        # Sign if we have key
        if self.sk:
            envelope_bytes = envelope.SerializeToString()
            envelope.sig = sign(self.sk, envelope_bytes)
        
        return envelope
    
    def _publish_envelope(self, envelope: telemetry_pb2.UniversalEnvelope) -> bool:
        """Publish envelope to EventBus"""
        try:
            with self._get_grpc_channel() as ch:
                stub = pbrpc.UniversalEventBusStub(ch)
                ack = stub.PublishTelemetry(envelope, timeout=2.0)
                
                if ack.status == telemetry_pb2.UniversalAck.OK:
                    return True
                else:
                    logger.warning(f"⚠️ Publish returned status {ack.status}: {ack.reason}")
                    return False
        except Exception as e:
            logger.error(f"❌ Publish failed: {e}")
            return False
    
    def collect_once(self):
        """Collect process data and publish once"""
        try:
            timestamp_ns = int(time.time() * 1e9)
            
            # Create telemetry
            device_telemetry = self._create_telemetry_event(timestamp_ns)
            envelope = self._create_envelope(device_telemetry)
            
            # Publish
            size = len(envelope.SerializeToString())
            if self._publish_envelope(envelope):
                logger.info(f"✅ Published {size} bytes ({device_telemetry.events.__len__()} events)")
                return True
            else:
                logger.warning(f"⚠️ Failed to publish {size} bytes")
                return False
        
        except Exception as e:
            logger.error(f"❌ Collection error: {e}", exc_info=True)
            return False
    
    def collection_loop(self, interval: int = 30):
        """Run continuous collection loop"""
        logger.info(f"🚀 Starting ProcAgent collection loop (interval: {interval}s)")
        
        cycle = 0
        while True:
            cycle += 1
            try:
                logger.info(f"\n📊 Collection cycle #{cycle}")
                t0 = time.time()
                
                self.collect_once()
                
                elapsed = time.time() - t0
                logger.info(f"✅ Cycle #{cycle} complete ({elapsed:.1f}s)")
                logger.info(f"⏰ Next collection in {interval} seconds...\n")
                
            except KeyboardInterrupt:
                logger.info("🛑 Shutting down...")
                break
            except Exception as e:
                logger.error(f"❌ Error in collection loop: {e}", exc_info=True)
            
            time.sleep(interval)


def main():
    """Main entry point"""
    agent = ProcAgent()
    agent.collection_loop(interval=30)


if __name__ == "__main__":
    main()
