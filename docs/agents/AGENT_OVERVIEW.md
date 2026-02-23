# AMOSKYS Agent Overview
## Comprehensive Guide to Security Agents

This document describes all agents in the AMOSKYS security platform, their purpose, inputs/outputs, and attack surface coverage.

---

## Agent Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         AMOSKYS Agent Network                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│   │ AuthGuard   │  │ ProcAgent   │  │ FIMAgent    │  │ DNSAgent    │   │
│   │   Agent     │  │             │  │             │  │             │   │
│   └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘   │
│          │                │                │                │          │
│          └────────────────┴────────────────┴────────────────┘          │
│                                    │                                    │
│                                    ▼                                    │
│                         ┌─────────────────────┐                        │
│                         │     EventBus        │                        │
│                         │   (gRPC + mTLS)     │                        │
│                         └─────────┬───────────┘                        │
│                                   │                                     │
│                                   ▼                                     │
│                         ┌─────────────────────┐                        │
│                         │   Fusion Engine     │                        │
│                         │  (24 Detection      │                        │
│                         │   Rules)            │                        │
│                         └─────────────────────┘                        │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Agent Registry Summary

| Agent | Type | Platforms | Status |
|-------|------|-----------|--------|
| [AuthGuardAgent](#authguardagent) | Class | macOS, Linux, Windows | ✅ Active |
| [ProcAgent](#procagent) | Class | macOS, Linux, Windows | ✅ Active |
| [PersistenceGuardAgent](#persistenceguardagent) | Class | macOS, Linux | ✅ Active |
| [FIMAgent](#fimagent) | Class | macOS, Linux, Windows | ✅ Active |
| [DNSAgent](#dnsagent) | Class | macOS, Linux, Windows | ✅ Active |
| [KernelAuditAgent](#kernelauditagent) | Class | macOS, Linux | ✅ Active |
| [PeripheralAgent](#peripheralagent) | Class | macOS, Linux | ✅ Active |
| [SNMPAgent](#snmpagent) | Script | macOS, Linux, Windows | ✅ Active |
| [FlowAgent](#flowagent) | Script | macOS, Linux, Windows | ✅ Active |

---

## Detailed Agent Descriptions

### AuthGuardAgent

**Purpose**: Authentication and authorization monitoring to detect credential theft, brute force attacks, and unauthorized access attempts.

**Location**: `src/amoskys/agents/auth/auth_agent.py`

**Inputs**:
- System authentication logs
- SSH/PAM events
- Failed login attempts
- Privilege escalation events

**Outputs** (Telemetry):
- `auth_failure`: Failed authentication attempt
- `brute_force_detected`: Multiple failed attempts from same source
- `privilege_escalation`: Unauthorized privilege change
- `credential_access`: Credential file access

**MITRE ATT&CK Coverage**:
| Technique | Description |
|-----------|-------------|
| T1078 | Valid Accounts |
| T1110 | Brute Force |
| T1552 | Credential Access |
| T1548 | Abuse Elevation Control |

**CLI Usage**:
```bash
# Standard invocation (recommended)
python -m amoskys.agents.auth --config config/amoskys.yaml

# Or with options
python -m amoskys.agents.auth --interval 60 --log-level DEBUG --once
```

---

### ProcAgent

**Purpose**: Real-time process monitoring with behavioral analysis and anomaly detection.

**Location**: `src/amoskys/agents/proc/proc_agent.py`

**Inputs**:
- Running process list
- Process creation events
- Resource usage (CPU, memory)
- Process relationships (parent/child)

**Outputs** (Telemetry):
- `process_created`: New process spawned
- `suspicious_process`: Process matching threat signatures
- `resource_anomaly`: Unusual resource consumption
- `process_injection`: Injection attempt detected

**MITRE ATT&CK Coverage**:
| Technique | Description |
|-----------|-------------|
| T1055 | Process Injection |
| T1059 | Command and Scripting Interpreter |
| T1106 | Native API |
| T1569 | System Services |

**CLI Usage**:
```bash
# Standard invocation (recommended)
python -m amoskys.agents.proc --interval 30

# All standard options available
python -m amoskys.agents.proc --help
```

---

### PersistenceGuardAgent

**Purpose**: Detect and monitor persistence mechanisms used by attackers to maintain access.

**Location**: `src/amoskys/agents/persistence/persistence_agent.py`

**Inputs**:
- LaunchDaemons/LaunchAgents (macOS)
- Systemd units (Linux)
- Cron jobs
- Shell profiles (.bashrc, .zshrc)
- Startup items

**Outputs** (Telemetry):
- `persistence_created`: New persistence mechanism added
- `persistence_modified`: Existing mechanism changed
- `suspicious_persistence`: Known malicious pattern

**MITRE ATT&CK Coverage**:
| Technique | Description |
|-----------|-------------|
| T1543.001 | Launch Agent |
| T1543.004 | Launch Daemon |
| T1053.003 | Cron |
| T1546.004 | Unix Shell Configuration Modification |

**CLI Usage**:
```bash
python -m amoskys.agents.persistence --interval 300
```

---

### FIMAgent

**Purpose**: File Integrity Monitoring for critical system files, detecting rootkits, webshells, and binary replacement.

**Location**: `src/amoskys/agents/file_integrity/file_integrity_agent.py`

**Inputs**:
- File system events (create, modify, delete)
- Critical path monitoring
- Hash verification
- Permission changes

**Monitored Paths**:
- `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`
- `/etc/passwd`, `/etc/shadow`
- Web roots (`/var/www`, `/srv/http`)
- SSH configuration

**Outputs** (Telemetry):
- `file_modified`: Critical file changed
- `binary_replaced`: System binary replaced
- `webshell_detected`: Webshell patterns found
- `suid_change`: SUID/SGID bit modified

**MITRE ATT&CK Coverage**:
| Technique | Description |
|-----------|-------------|
| T1014 | Rootkit |
| T1574.010 | Services File Permissions Weakness |
| T1505.003 | Web Shell |
| T1548.001 | Setuid and Setgid |

**CLI Usage**:
```bash
python -m amoskys.agents.file_integrity --interval 60
```

---

### DNSAgent

**Purpose**: DNS threat detection including C2 beaconing, DGA domains, DNS tunneling, and data exfiltration.

**Location**: `src/amoskys/agents/dns/dns_agent.py`

**Inputs**:
- DNS query logs
- DNS response data
- Query patterns and timing
- Domain entropy analysis

**Outputs** (Telemetry):
- `c2_beacon`: Regular interval queries (C2 communication)
- `dga_domain`: Algorithmically generated domain
- `dns_tunnel`: High-entropy DNS queries (tunneling)
- `dns_exfiltration`: Large TXT record transfers

**MITRE ATT&CK Coverage**:
| Technique | Description |
|-----------|-------------|
| T1071.004 | Application Layer Protocol: DNS |
| T1568.002 | Domain Generation Algorithms |
| T1572 | Protocol Tunneling |
| T1048 | Exfiltration Over Alternative Protocol |

**CLI Usage**:
```bash
python -m amoskys.agents.dns --interval 30
```

---

### KernelAuditAgent

**Purpose**: Kernel-level security monitoring for privilege escalation, container escape, and process injection.

**Location**: `src/amoskys/agents/kernel_audit/kernel_audit_agent.py`

**Inputs**:
- Kernel audit logs (auditd on Linux)
- System call traces
- Capability changes
- Container events

**Outputs** (Telemetry):
- `privilege_escalation`: Unexpected UID transition
- `container_escape`: Container breakout attempt
- `process_injection`: ptrace-based injection
- `capability_abuse`: Dangerous capability granted

**MITRE ATT&CK Coverage**:
| Technique | Description |
|-----------|-------------|
| T1068 | Exploitation for Privilege Escalation |
| T1611 | Escape to Host |
| T1055.008 | Ptrace System Calls |
| T1055 | Process Injection |

**CLI Usage**:
```bash
sudo python -m amoskys.agents.kernel_audit --interval 60
```

---

### PeripheralAgent

**Purpose**: USB and Bluetooth device monitoring with BadUSB detection and unauthorized device tracking.

**Location**: `src/amoskys/agents/peripheral/peripheral_agent.py`

**Inputs**:
- USB device events
- Bluetooth pairing events
- Device fingerprints
- HID device enumeration

**Outputs** (Telemetry):
- `device_connected`: New peripheral attached
- `badusb_detected`: HID keyboard/mouse emulation
- `unauthorized_device`: Unknown device connected
- `data_exfiltration`: Mass storage write activity

**MITRE ATT&CK Coverage**:
| Technique | Description |
|-----------|-------------|
| T1200 | Hardware Additions |
| T1091 | Replication Through Removable Media |
| T1052 | Exfiltration Over Physical Medium |

**CLI Usage**:
```bash
python -m amoskys.agents.peripheral --interval 30
```

---

### SNMPAgent

**Purpose**: Network device monitoring via SNMP for routers, switches, and IoT devices.

**Location**: `src/amoskys/agents/snmp/snmp_agent.py`

**Inputs**:
- SNMP polling responses
- Device health metrics
- Interface statistics
- SNMP traps

**Outputs** (Telemetry):
- `device_telemetry`: Device health metrics
- `interface_stats`: Network interface statistics
- `config_change`: Device configuration modified
- `snmp_trap`: Unsolicited device alert

**Monitored Devices**:
- Routers and switches
- Firewalls
- IoT devices with SNMP support
- Network equipment

**CLI Usage**:
```bash
python -m amoskys.agents.snmp
```

---

### FlowAgent

**Purpose**: Network flow analysis with WAL (Write-Ahead Log) persistence for reliable event processing.

**Location**: `src/amoskys/agents/flowagent/main.py`

**Inputs**:
- Network flow data
- EventBus WAL subscription
- Connection states

**Outputs** (Telemetry):
- `flow_event`: Network connection metadata
- `flow_anomaly`: Unusual traffic pattern
- `connection_state`: TCP state changes

**CLI Usage**:
```bash
python -m amoskys.agents.flowagent
```

---

## Common CLI Arguments

All class-based agents support these arguments:

| Argument | Description | Default |
|----------|-------------|---------|
| `--config` | Path to configuration YAML | `config/amoskys.yaml` |
| `--log-level` | Logging level (DEBUG, INFO, WARNING, ERROR) | `INFO` |
| `--once` | Run single collection cycle, then exit | `False` |
| `--interval` | Collection interval in seconds | Agent-specific |

---

## Adding New Agents

To add a new agent:

1. **Create agent class** extending `HardenedAgentBase`:
   ```python
   from amoskys.agents.common.hardened_base import HardenedAgentBase
   
   class MyNewAgent(HardenedAgentBase):
       def __init__(self):
           super().__init__(agent_name="my_new_agent")
       
       def collect(self) -> List[Any]:
           # Implement collection logic
           pass
   ```

2. **Add to registry** in `src/amoskys/agents/__init__.py`:
   ```python
   from amoskys.agents.myagent.my_agent import MyNewAgent
   
   AGENT_REGISTRY["my_new"] = {
       "class": MyNewAgent,
       "name": "My New Agent",
       "platforms": ["darwin", "linux"],
   }
   ```

3. **Add correlation rules** in `src/amoskys/intel/advanced_rules.py`

4. **Write tests** in `tests/agents/test_my_agent.py`

---

## MITRE ATT&CK Coverage Summary

Total techniques covered by AMOSKYS agents:

| Tactic | Techniques Covered |
|--------|-------------------|
| Initial Access | T1078 |
| Execution | T1059, T1106 |
| Persistence | T1543, T1053, T1546 |
| Privilege Escalation | T1068, T1548 |
| Defense Evasion | T1014, T1055, T1574 |
| Credential Access | T1110, T1552, T1555 |
| Discovery | T1057, T1082 |
| Lateral Movement | T1021, T1091 |
| Collection | T1005, T1039 |
| Command and Control | T1071, T1568, T1572, T1573 |
| Exfiltration | T1041, T1048, T1052 |

---

*Last updated: December 2025*
