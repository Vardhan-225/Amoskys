# AMOSKYS OS Porting Guide

## How to port an agent to a new platform

Every macOS Observatory agent follows the same 4-file pattern.
To port agent `{domain}` to `{platform}`:

### 1. Create the directory

```
src/amoskys/agents/os/{platform}/{domain}/
    __init__.py
    agent.py
    collector.py
    probes.py
```

### 2. Implement the collector

The collector is the ONLY file that changes between platforms.
Probes are platform-agnostic — they consume `shared_data` dicts.

```python
# collector.py — platform-specific data gathering
class {Platform}{Domain}Collector:
    def __init__(self, device_id: str = "") -> None:
        self.device_id = device_id or socket.gethostname()

    def collect(self) -> Dict[str, Any]:
        """Return shared_data dict with platform-specific collection."""
        # Linux: read from /proc, journalctl, auditd, inotify
        # Windows: read from ETW, WMI, Event Log, Registry
        # macOS: read from psutil, Unified Logging, lsof, arp
        return {
            "items": [...],          # Main data list
            "item_count": 0,         # Summary counts
            "collection_time_ms": 0, # Performance metric
        }
```

### 3. Copy probes from macOS (usually unchanged)

Probes only read from `context.shared_data`. If the collector
returns the same keys with the same semantics, probes work as-is.

```python
# probes.py — usually identical to macOS version
from amoskys.agents.os.macos.{domain}.probes import create_{domain}_probes
# OR copy and customize if platform-specific thresholds differ
```

### 4. Create the agent

```python
class {Platform}{Domain}Agent(MicroProbeAgentMixin, HardenedAgentBase):
    def __init__(self, collection_interval: float = 10.0) -> None:
        # Same pattern as macOS — just swap collector
        self.collector = {Platform}{Domain}Collector(device_id=device_id)
        self.register_probes(create_{domain}_probes())
```

### 5. Register the shim

Update `src/amoskys/agents/{domain}/__init__.py`:

```python
import sys as _sys

if _sys.platform == "darwin":
    from amoskys.agents.os.macos.{domain}.agent import MacOS{Domain}Agent as {Domain}Agent
elif _sys.platform == "win32":
    from amoskys.agents.os.windows.{domain}.agent import Windows{Domain}Agent as {Domain}Agent
else:
    from amoskys.agents.os.linux.{domain}.agent import Linux{Domain}Agent as {Domain}Agent
```

## Platform-specific data sources

### Linux
| Domain | Data Source | Command/API |
|--------|-----------|-------------|
| process | /proc + psutil | `psutil.process_iter()`, `/proc/{pid}/` |
| auth | journalctl + pam | `journalctl -u sshd --since`, `/var/log/auth.log` |
| persistence | systemd + cron | `systemctl list-unit-files`, `crontab -l` |
| filesystem | inotify + stat | `inotifywait`, `os.stat()` |
| network | ss + conntrack | `ss -tnp`, `/proc/net/tcp` |
| dns | systemd-resolved | `resolvectl query`, `/var/log/syslog` |
| kernel_audit | auditd | `ausearch`, `/var/log/audit/audit.log` |

### Windows
| Domain | Data Source | Command/API |
|--------|-----------|-------------|
| process | ETW + WMI | `Get-Process`, `Win32_Process` WMI class |
| auth | Security Event Log | Event IDs 4624/4625/4648/4672 |
| persistence | Registry + Tasks | `HKLM\...\Run`, `schtasks /query` |
| filesystem | USN Journal + NTFS | `fsutil usn`, `ReadDirectoryChangesW` |
| network | ETW + netstat | `Get-NetTCPConnection`, ETW providers |
| dns | DNS Client ETW | `Microsoft-Windows-DNS-Client` provider |

## Shared code (no porting needed)
- `agents/common/base.py` — HardenedAgentBase
- `agents/common/probes.py` — MicroProbe, ProbeContext, TelemetryEvent
- `agents/common/agent_bus.py` — AgentBus, ThreatContext, PeerAlert
- `agents/common/kill_chain.py` — KillChainTracker
- `agents/common/ip_utils.py` — IP classification, benign domains
- `agents/common/queue_adapter.py` — LocalQueueAdapter
- `agents/common/collector.py` — Collector ABC
- `detection/` — Sigma engine, YARA engine, lifecycle
- `proto/` — Protobuf definitions
