#!/usr/bin/env python3
"""
AMOSKYS Process Agent - Simplified Working Version
Collects process information without protobuf dependencies for testing
"""

import psutil
import asyncio
import time
import logging
from datetime import datetime
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict

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
    memory_rss: int
    memory_vms: int
    num_threads: int
    status: str
    create_time: float
    parent_pid: Optional[int]
    connections: int
    open_files: int


class ProcessMonitor:
    """Monitor system processes"""
    
    def __init__(self):
        self.processes: Dict[int, ProcessInfo] = {}
        self.previous_processes: Set[int] = set()
        self.suspicious_patterns = ['malware', 'cryptominer', 'backdoor', 'rootkit']
    
    async def scan_processes(self) -> Dict[int, ProcessInfo]:
        """Scan all running processes
        
        Returns:
            Dictionary of PID -> ProcessInfo
        """
        current_processes = {}
        
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 
                                        'memory_percent', 'status', 'create_time']):
            try:
                pid = proc.pid
                
                # Skip kernel processes
                if pid == 0:
                    continue
                
                # Get basic info
                name = proc.info.get('name', 'unknown')
                username = proc.info.get('username', 'unknown')
                cpu_percent = proc.info.get('cpu_percent', 0.0)
                memory_percent = proc.info.get('memory_percent', 0.0)
                status = proc.info.get('status', 'unknown')
                create_time = proc.info.get('create_time', 0.0)
                
                # Get additional details (may fail for some processes)
                try:
                    exe = proc.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    exe = None
                
                try:
                    cmdline = proc.cmdline()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    cmdline = []
                
                try:
                    memory_info = proc.memory_info()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    memory_info = type('obj', (object,), {'rss': 0, 'vms': 0})()
                
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
                continue
            except Exception as e:
                logger.error(f"Error collecting process {pid}: {e}")
                continue
        
        return current_processes
    
    def detect_changes(self, current_processes: Dict[int, ProcessInfo]) -> Dict[str, List[ProcessInfo]]:
        """Detect process lifecycle events"""
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
        """Check if a process matches suspicious patterns"""
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
        # Handle None values from psutil
        cpu = proc.cpu_percent if proc.cpu_percent is not None else 0
        connections = proc.connections if proc.connections is not None else 0
        
        if cpu > 80 and connections > 50:
            return True
        
        return False
    
    def get_top_processes(self, by: str = 'cpu', limit: int = 10) -> List[ProcessInfo]:
        """Get top N processes by resource usage"""
        if by == 'cpu':
            sorted_procs = sorted(
                self.processes.values(),
                key=lambda p: p.cpu_percent if p.cpu_percent is not None else 0,
                reverse=True
            )
        elif by == 'memory':
            sorted_procs = sorted(
                self.processes.values(),
                key=lambda p: p.memory_percent if p.memory_percent is not None else 0,
                reverse=True
            )
        else:
            raise ValueError(f"Invalid sort key: {by}")
        
        return sorted_procs[:limit]


class ProcAgent:
    """Process monitoring agent for AMOSKYS - Simplified version"""
    
    def __init__(self, collection_interval: int = 30, suspicious_patterns: List[str] = None):
        """Initialize process agent"""
        self.monitor = ProcessMonitor()
        if suspicious_patterns:
            self.monitor.suspicious_patterns = suspicious_patterns
        self.collection_interval = collection_interval
    
    async def collect_once(self) -> Dict:
        """Collect process data once and return as dictionary
        
        Returns:
            Dictionary with process data and statistics
        """
        try:
            # Scan all processes
            processes = await self.monitor.scan_processes()
            
            # Detect changes
            changes = self.monitor.detect_changes(processes)
            
            # Get system stats
            system_stats = {
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent,
                'process_count': len(processes)
            }
            
            # Get top processes
            top_cpu = self.monitor.get_top_processes(by='cpu', limit=10)
            top_memory = self.monitor.get_top_processes(by='memory', limit=10)
            
            result = {
                'timestamp': datetime.now().isoformat(),
                'system_stats': system_stats,
                'process_count': len(processes),
                'new_processes': len(changes['new']),
                'terminated_processes': len(changes['terminated']),
                'suspicious_processes': len(changes['suspicious']),
                'top_cpu': [{'pid': p.pid, 'name': p.name, 'cpu_percent': p.cpu_percent if p.cpu_percent is not None else 0.0} for p in top_cpu[:5]],
                'top_memory': [{'pid': p.pid, 'name': p.name, 'memory_percent': p.memory_percent if p.memory_percent is not None else 0.0} for p in top_memory[:5]],
                'suspicious': [{'pid': p.pid, 'name': p.name, 'exe': p.exe} for p in changes['suspicious']]
            }
            
            logger.info(f"✅ Collected: {len(processes)} processes, {len(changes['new'])} new, {len(changes['suspicious'])} suspicious")
            
            return result
            
        except Exception as e:
            logger.error(f"Collection error: {e}", exc_info=True)
            return {}


# Export public API
__all__ = [
    "ProcAgent",
    "ProcessMonitor",
    "ProcessInfo"
]


async def main():
    """Test the process agent"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)-8s [%(name)s] %(message)s'
    )
    
    logger.info("🧠⚡ AMOSKYS Process Agent - Simplified Test")
    logger.info("="*70)
    
    agent = ProcAgent()
    
    # Collect once
    data = await agent.collect_once()
    
    print("\n📊 System Statistics:")
    for key, value in data.get('system_stats', {}).items():
        print(f"  {key}: {value:.1f}{'%' if 'percent' in key else ''}")
    
    print(f"\n🔍 Process Summary:")
    print(f"  Total processes: {data['process_count']}")
    print(f"  New processes: {data['new_processes']}")
    print(f"  Suspicious: {data['suspicious_processes']}")
    
    print(f"\n🔥 Top 5 CPU consumers:")
    for i, proc in enumerate(data.get('top_cpu', []), 1):
        print(f"  {i}. {proc['name']:<20} PID {proc['pid']:<8} CPU {proc['cpu_percent']:.1f}%")
    
    print(f"\n💾 Top 5 Memory consumers:")
    for i, proc in enumerate(data.get('top_memory', []), 1):
        print(f"  {i}. {proc['name']:<20} PID {proc['pid']:<8} MEM {proc['memory_percent']:.1f}%")


if __name__ == '__main__':
    asyncio.run(main())
