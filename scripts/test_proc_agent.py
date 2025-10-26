#!/usr/bin/env python3
"""
Quick test of ProcAgent - collect process information
"""

import psutil
import sys
import json
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))


def collect_process_info():
    """Collect basic process information"""
    processes = []
    
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'status']):
        try:
            proc_info = proc.info
            proc_info['cpu_percent'] = proc.cpu_percent(interval=0.1)
            processes.append(proc_info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    return processes


def get_system_stats():
    """Get system-wide statistics"""
    return {
        'cpu_percent': psutil.cpu_percent(interval=1),
        'memory_percent': psutil.virtual_memory().percent,
        'disk_percent': psutil.disk_usage('/').percent,
        'process_count': len(psutil.pids())
    }


def main():
    print("="*60)
    print("AMOSKYS Process Agent - Quick Test")
    print("="*60)
    
    # System stats
    print("\n📊 System Statistics:")
    stats = get_system_stats()
    for key, value in stats.items():
        print(f"  {key}: {value:.1f}{'%' if 'percent' in key else ''}")
    
    # Process info
    print("\n🔍 Collecting process information...")
    processes = collect_process_info()
    print(f"✅ Found {len(processes)} processes")
    
    # Top CPU consumers
    top_cpu = sorted(processes, key=lambda p: p.get('cpu_percent', 0), reverse=True)[:10]
    print("\n🔥 Top 10 CPU consumers:")
    for i, proc in enumerate(top_cpu, 1):
        print(f"  {i}. {proc['name']:<20} PID {proc['pid']:<8} CPU {proc.get('cpu_percent', 0):.1f}%")
    
    # Top memory consumers
    top_mem = sorted(processes, key=lambda p: p.get('memory_percent', 0), reverse=True)[:10]
    print("\n💾 Top 10 Memory consumers:")
    for i, proc in enumerate(top_mem, 1):
        print(f"  {i}. {proc['name']:<20} PID {proc['pid']:<8} MEM {proc.get('memory_percent', 0):.1f}%")
    
    print("\n✅ ProcAgent test complete!")
    print("="*60)


if __name__ == '__main__':
    main()
