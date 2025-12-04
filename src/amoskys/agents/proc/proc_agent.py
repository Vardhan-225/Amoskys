"""
AMOSKYS Process Agent (ProcAgent)
Native process monitoring for Linux/macOS systems

Monitors:
- Running processes
- Resource usage (CPU, memory)
- Process lifecycle events
- Suspicious process behavior

Complements SNMPAgent by providing detailed process-level telemetry.
"""

import psutil
import asyncio
import time
import logging
import os
import grpc
from datetime import datetime
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict

from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.proto import universal_telemetry_pb2_grpc as telemetry_grpc
from amoskys.common.crypto.signing import load_private_key, sign
from amoskys.config import get_config

# Load configuration
config = get_config()
logger = logging.getLogger("ProcAgent")


@dataclass
class ProcessInfo:
    """Snapshot of a process at a point in time"""
    pid: int
    name: str
    exe: Optional[str]
    cmdline: List[str]
    username: str
    cpu_percent: float
    memory_percent: float
    memory_rss: int  # Resident Set Size in bytes
    memory_vms: int  # Virtual Memory Size in bytes
    num_threads: int
    status: str
    create_time: float
    parent_pid: Optional[int]
    connections: int  # Number of network connections
    open_files: int   # Number of open files


class ProcessMonitor:
    """Monitor system processes and detect changes"""
    
    def __init__(self):
        self.processes: Dict[int, ProcessInfo] = {}
        self.previous_processes: Set[int] = set()
        self.suspicious_patterns = [
            # Add patterns for suspicious process names/paths
            'mimikatz', 'nc.exe', 'ncat', 'cryptolocker',
            'ransomware', 'keylogger', 'backdoor'
        ]
    
    async def scan_processes(self) -> Dict[int, ProcessInfo]:
        """Scan all running processes
        
        Returns:
            Dictionary of PID -> ProcessInfo
        """
        current_processes = {}
        
        for proc in psutil.process_iter(['pid', 'name', 'username', 'status', 'create_time']):
            try:
                pid = proc.info['pid']
                
                # Get detailed info
                with proc.oneshot():
                    # Basic info
                    name = proc.info['name']
                    username = proc.info['username']
                    status = proc.info['status']
                    create_time = proc.info['create_time']
                    
                    # Resource usage
                    cpu_percent = proc.cpu_percent(interval=0.1)
                    memory_info = proc.memory_info()
                    memory_percent = proc.memory_percent()
                    
                    # Get executable path (may fail for some processes)
                    try:
                        exe = proc.exe()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        exe = None
                    
                    # Get command line
                    try:
                        cmdline = proc.cmdline()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        cmdline = []
                    
                    # Get parent
                    try:
                        parent_pid = proc.ppid()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        parent_pid = None
                    
                    # Count connections and files
                    try:
                        connections = len(proc.connections())
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        connections = 0
                    
                    try:
                        open_files = len(proc.open_files())
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        open_files = 0
                    
                    # Get thread count
                    try:
                        num_threads = proc.num_threads()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        num_threads = 0
                    
                    # Create process info
                    proc_info = ProcessInfo(
                        pid=pid,
                        name=name,
                        exe=exe,
                        cmdline=cmdline,
                        username=username,
                        cpu_percent=cpu_percent,
                        memory_percent=memory_percent,
                        memory_rss=memory_info.rss,
                        memory_vms=memory_info.vms,
                        num_threads=num_threads,
                        status=status,
                        create_time=create_time,
                        parent_pid=parent_pid,
                        connections=connections,
                        open_files=open_files
                    )
                    
                    current_processes[pid] = proc_info
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                # Process ended or access denied
                continue
            except Exception as e:
                logger.error(f"Error collecting process {pid}: {e}")
                continue
        
        return current_processes
    
    def detect_changes(self, current_processes: Dict[int, ProcessInfo]) -> Dict[str, List[ProcessInfo]]:
        """Detect process lifecycle events
        
        Args:
            current_processes: Current process snapshot
            
        Returns:
            Dictionary with 'new', 'terminated', and 'suspicious' processes
        """
        current_pids = set(current_processes.keys())
        
        # Detect new processes
        new_pids = current_pids - self.previous_processes
        new_processes = [current_processes[pid] for pid in new_pids]
        
        # Detect terminated processes
        terminated_pids = self.previous_processes - current_pids
        terminated_processes = [self.processes[pid] for pid in terminated_pids if pid in self.processes]
        
        # Detect suspicious processes
        suspicious_processes = []
        for proc in current_processes.values():
            if self._is_suspicious(proc):
                suspicious_processes.append(proc)
        
        # Update state
        self.previous_processes = current_pids
        self.processes = current_processes
        
        return {
            'new': new_processes,
            'terminated': terminated_processes,
            'suspicious': suspicious_processes
        }
    
    def _is_suspicious(self, proc: ProcessInfo) -> bool:
        """Check if a process matches suspicious patterns
        
        Args:
            proc: Process to check
            
        Returns:
            True if process looks suspicious
        """
        # Check name
        name_lower = proc.name.lower()
        for pattern in self.suspicious_patterns:
            if pattern in name_lower:
                return True
        
        # Check exe path
        if proc.exe:
            exe_lower = proc.exe.lower()
            for pattern in self.suspicious_patterns:
                if pattern in exe_lower:
                    return True
        
        # Check for high resource usage + unusual behavior
        if proc.cpu_percent > 80 and proc.connections > 50:
            return True
        
        return False
    
    def get_top_processes(self, by: str = 'cpu', limit: int = 10) -> List[ProcessInfo]:
        """Get top N processes by resource usage
        
        Args:
            by: Sort by 'cpu' or 'memory'
            limit: Number of processes to return
            
        Returns:
            List of top processes
        """
        if by == 'cpu':
            sorted_procs = sorted(self.processes.values(), key=lambda p: p.cpu_percent, reverse=True)
        elif by == 'memory':
            sorted_procs = sorted(self.processes.values(), key=lambda p: p.memory_percent, reverse=True)
        else:
            raise ValueError(f"Invalid sort key: {by}")
        
        return sorted_procs[:limit]


class ProcAgent:
    """Process monitoring agent for AMOSKYS"""
    
    def __init__(self, collection_interval: int = 30, suspicious_patterns: List[str] = None):
        """Initialize process agent
        
        Args:
            collection_interval: Collection interval in seconds
            suspicious_patterns: List of suspicious process name patterns
        """
        self.monitor = ProcessMonitor()
        if suspicious_patterns:
            self.monitor.suspicious_patterns = suspicious_patterns
        self.collection_interval = collection_interval
        self.sk = None  # Ed25519 signing key
        
        # Load signing key (optional for testing)
        try:
            self._load_signing_key()
        except Exception as e:
            logger.warning(f"Could not load signing key: {e}")
    
    def _load_signing_key(self):
        """Load Ed25519 private key for signing"""
        self.sk = load_private_key('certs/agent.ed25519')
        logger.info("✅ Loaded Ed25519 private key")

    def publish_telemetry(self, envelope: telemetry_pb2.UniversalEnvelope) -> bool:
        """Publish UniversalEnvelope to EventBus via gRPC.

        Args:
            envelope: Signed UniversalEnvelope to publish

        Returns:
            bool: True if publish succeeded, False otherwise
        """
        try:
            # Load certificates
            cert_dir = config.agent.cert_dir
            with open(os.path.join(cert_dir, "ca.crt"), "rb") as f:
                ca = f.read()
            with open(os.path.join(cert_dir, "agent.crt"), "rb") as f:
                crt = f.read()
            with open(os.path.join(cert_dir, "agent.key"), "rb") as f:
                key = f.read()

            creds = grpc.ssl_channel_credentials(
                root_certificates=ca,
                private_key=key,
                certificate_chain=crt
            )

            # Connect and publish
            with grpc.secure_channel(config.agent.bus_address, creds) as ch:
                stub = telemetry_grpc.UniversalEventBusStub(ch)
                ack = stub.PublishTelemetry(envelope, timeout=5.0)

                if ack.status == telemetry_pb2.UniversalAck.Status.OK:
                    logger.info(f"✅ Published process telemetry ({ack.events_accepted} events)")
                    return True
                elif ack.status in (telemetry_pb2.UniversalAck.Status.RETRY,
                                    telemetry_pb2.UniversalAck.Status.OVERLOAD):
                    logger.warning(f"⚠️ EventBus retry: {ack.reason} (backoff: {ack.backoff_hint_ms}ms)")
                    return False
                else:
                    logger.error(f"❌ Publish failed: {ack.reason}")
                    return False

        except grpc.RpcError as e:
            logger.error(f"❌ gRPC error: {e.code()} - {e.details()}")
            return False
        except Exception as e:
            logger.error(f"❌ Publish error: {e}", exc_info=True)
            return False

    async def collect_once(self) -> List[telemetry_pb2.UniversalEnvelope]:
        """Collect process data once and return envelopes
        
        Returns:
            List of UniversalEnvelope messages
        """
        envelopes = []
        
        try:
            # Scan all processes
            processes = await self.monitor.scan_processes()
            
            # Detect changes
            changes = self.monitor.detect_changes(processes)
            
            # Get system stats
            system_stats = {
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent
            }
            
            # Create telemetry
            device_telemetry = self.create_device_telemetry(processes, changes, system_stats)
            envelope = self.create_universal_envelope(device_telemetry)
            
            envelopes.append(envelope)
            
            logger.info(f"✅ Collected process data: {len(processes)} processes, {len(changes['new'])} new, {len(changes['suspicious'])} suspicious")
            
        except Exception as e:
            logger.error(f"Collection error: {e}", exc_info=True)
        
        return envelopes
    
    def create_device_telemetry(self, 
                                processes: Dict[int, ProcessInfo],
                                changes: Dict[str, List[ProcessInfo]],
                                system_stats: Dict[str, float]) -> telemetry_pb2.DeviceTelemetry:
        """Convert process data to DeviceTelemetry protobuf
        
        Args:
            processes: Current process snapshot
            changes: Process lifecycle changes
            system_stats: System-wide statistics
            
        Returns:
            DeviceTelemetry protobuf message
        """
        import socket
        
        # Create metadata
        metadata = telemetry_pb2.DeviceMetadata(
            ip_address=socket.gethostname(),
            protocols=["PROC"],
            os_type="LINUX" if psutil.LINUX else "MACOS"
        )
        
        # Create telemetry events
        events = []
        timestamp_ns = int(datetime.now().timestamp() * 1e9)
        
        # 1. System-wide process statistics
        events.append(telemetry_pb2.TelemetryEvent(
            event_id=f"proc_system_{timestamp_ns}",
            event_type="METRIC",
            severity="INFO",
            event_timestamp_ns=timestamp_ns,
            metric_data=telemetry_pb2.MetricData(
                metric_name="proc_total_count",
                metric_type="GAUGE",
                numeric_value=len(processes),
                unit="processes"
            ),
            tags=["process", "system_stats", "amoskys"],
            source_component="proc_agent"
        ))
        
        # 2. System resource usage
        for metric_name, value in system_stats.items():
            events.append(telemetry_pb2.TelemetryEvent(
                event_id=f"proc_{metric_name}_{timestamp_ns}",
                event_type="METRIC",
                severity="INFO",
                event_timestamp_ns=timestamp_ns,
                metric_data=telemetry_pb2.MetricData(
                    metric_name=f"proc_{metric_name}",
                    metric_type="GAUGE",
                    numeric_value=value,
                    unit="percent" if "percent" in metric_name else "bytes"
                ),
                tags=["process", "system_stats", "amoskys"],
                source_component="proc_agent"
            ))
        
        # 3. New process events
        for proc in changes.get('new', []):
            events.append(telemetry_pb2.TelemetryEvent(
                event_id=f"proc_new_{proc.pid}_{timestamp_ns}",
                event_type="EVENT",
                severity="INFO",
                event_timestamp_ns=timestamp_ns,
                event_data=telemetry_pb2.EventData(
                    event_category="PROCESS_LIFECYCLE",
                    event_action="PROCESS_START",
                    event_message=f"New process: {proc.name} (PID {proc.pid})",
                    additional_context={
                        'pid': str(proc.pid),
                        'name': proc.name,
                        'username': proc.username,
                        'exe': proc.exe or 'unknown'
                    }
                ),
                tags=["process", "lifecycle", "new", "amoskys"],
                source_component="proc_agent"
            ))
        
        # 4. Suspicious process alerts
        for proc in changes.get('suspicious', []):
            events.append(telemetry_pb2.TelemetryEvent(
                event_id=f"proc_suspicious_{proc.pid}_{timestamp_ns}",
                event_type="ALERT",
                severity="WARNING",
                event_timestamp_ns=timestamp_ns,
                alert_data=telemetry_pb2.AlertData(
                    alert_type="SUSPICIOUS_PROCESS",
                    alert_severity="MEDIUM",
                    alert_message=f"Suspicious process detected: {proc.name} (PID {proc.pid})",
                    alert_source="proc_agent",
                    affected_resource=proc.exe or proc.name,
                    additional_context={
                        'pid': str(proc.pid),
                        'cpu_percent': str(proc.cpu_percent),
                        'memory_percent': str(proc.memory_percent),
                        'connections': str(proc.connections)
                    }
                ),
                tags=["process", "suspicious", "security", "amoskys"],
                source_component="proc_agent"
            ))
        
        # Create DeviceTelemetry
        device_telemetry = telemetry_pb2.DeviceTelemetry(
            device_id=socket.gethostname(),
            device_type="HOST",
            protocol="PROC",
            metadata=metadata,
            events=events,
            timestamp_ns=timestamp_ns,
            collection_agent="amoskys-proc-agent",
            agent_version="0.1.0"
        )
        
        return device_telemetry
    
    def create_universal_envelope(self, device_telemetry: telemetry_pb2.DeviceTelemetry) -> telemetry_pb2.UniversalEnvelope:
        """Wrap DeviceTelemetry in signed UniversalEnvelope
        
        Args:
            device_telemetry: DeviceTelemetry protobuf
            
        Returns:
            Signed UniversalEnvelope
        """
        timestamp_ns = int(datetime.now().timestamp() * 1e9)
        idem_key = f"{device_telemetry.device_id}_{timestamp_ns}"
        
        envelope = telemetry_pb2.UniversalEnvelope(
            version="v1",
            ts_ns=timestamp_ns,
            idempotency_key=idem_key,
            device_telemetry=device_telemetry,
            signing_algorithm="Ed25519",
            priority="NORMAL",
            requires_acknowledgment=True
        )
        
        # Sign the envelope
        envelope_bytes = envelope.SerializeToString()
        envelope.sig = sign(self.sk, envelope_bytes)
        
        return envelope
    
    async def collection_loop(self):
        """Main collection loop"""
        logger.info("🚀 ProcAgent collection loop starting")
        logger.info(f"📊 Collection interval: {self.collection_interval} seconds")
        
        cycle = 0
        
        while True:
            cycle += 1
            t0 = time.time()
            
            logger.info(f"\n{'='*70}")
            logger.info(f"🔄 Collection cycle #{cycle} - {datetime.now()}")
            logger.info(f"{'='*70}")
            
            try:
                # Scan all processes
                logger.info("📡 Scanning processes...")
                processes = await self.monitor.scan_processes()
                logger.info(f"✅ Found {len(processes)} processes")
                
                # Detect changes
                changes = self.monitor.detect_changes(processes)
                logger.info(f"📊 Changes: {len(changes['new'])} new, {len(changes['terminated'])} terminated, {len(changes['suspicious'])} suspicious")
                
                # Get system stats
                system_stats = {
                    'cpu_percent': psutil.cpu_percent(interval=1),
                    'memory_percent': psutil.virtual_memory().percent,
                    'disk_percent': psutil.disk_usage('/').percent
                }
                
                # Create telemetry
                device_telemetry = self.create_device_telemetry(processes, changes, system_stats)
                envelope = self.create_universal_envelope(device_telemetry)

                # Publish to EventBus
                envelope_bytes = envelope.SerializeToString()
                logger.info(f"📤 Publishing telemetry envelope ({len(envelope_bytes)} bytes, {len(device_telemetry.events)} events)")

                success = self.publish_telemetry(envelope)
                if success:
                    logger.info(f"✅ Telemetry published successfully")
                else:
                    logger.warning("⚠️ Failed to publish telemetry, will retry next cycle")

                # Show top processes
                top_cpu = self.monitor.get_top_processes(by='cpu', limit=5)
                logger.info("\n🔥 Top 5 CPU consumers:")
                for i, proc in enumerate(top_cpu, 1):
                    logger.info(f"   {i}. {proc.name} (PID {proc.pid}): {proc.cpu_percent:.1f}%")
                
            except Exception as e:
                logger.error(f"❌ Collection error: {e}", exc_info=True)
            
            elapsed = time.time() - t0
            logger.info(f"✅ Collection cycle #{cycle} complete ({elapsed:.1f}s)")
            logger.info(f"⏰ Next collection in {self.collection_interval} seconds...")
            
            await asyncio.sleep(self.collection_interval)


async def main():
    """Entry point for ProcAgent"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)-8s [%(name)s] %(message)s'
    )
    
    logger.info("🧠⚡ AMOSKYS Process Agent Starting...")
    logger.info("="*70)
    
    agent = ProcAgent()
    
    try:
        await agent.collection_loop()
    except KeyboardInterrupt:
        logger.info("\n🛑 Shutting down gracefully...")


if __name__ == '__main__':
    asyncio.run(main())


# Export public API
__all__ = [
    "ProcAgent",
    "ProcessMonitor",
    "ProcessInfo"
]
