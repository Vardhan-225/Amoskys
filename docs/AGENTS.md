# AMOSKYS Agent Fleet - System Map

## Overview

AMOSKYS operates **11 specialized agents** across endpoints to collect security telemetry. Each agent now uses the **Micro-Probe Architecture** - a "swarm of eyes" pattern where each agent hosts multiple micro-probes, each watching ONE specific threat vector.

**Fleet Status** (as of 2026-01-05):
- ✅ **5/11** migrated to Micro-Probe Architecture (ProcAgent, DNSAgent, PeripheralAgent, AuthGuard, FIMAgent)
- 🔄 **6/11** pending migration
- 🎯 **Target**: 100% unbreakable by Week 4
- 👁️ **85+ Micro-Probes** across 11 agents = "If you breathe, we see it"

---

## Micro-Probe Architecture

### Design Philosophy

Each macro-agent (ProcAgent, DNSAgent, etc.) hosts multiple **micro-probes**. Each probe is a lightweight, single-responsibility detector that watches ONE specific "door" or perspective:

```
┌─────────────────────────────────────────────────────────────────┐
│                        MACRO-AGENT                               │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  Responsibilities:                                          │ │
│  │  • EventBus connection & circuit breaker                    │ │
│  │  • Local queue for offline resilience                       │ │
│  │  • Probe lifecycle management                               │ │
│  │  • Event aggregation & publishing                           │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐            │
│  │ Probe 1  │ │ Probe 2  │ │ Probe 3  │ │ Probe N  │   ...      │
│  │ 👁️       │ │ 👁️       │ │ 👁️       │ │ 👁️       │            │
│  │ One Door │ │ One Door │ │ One Door │ │ One Door │            │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

### Key Principles

1. **Probes are DUMB** - They only observe and return TelemetryEvents
2. **Probes do NOT handle networking** - No retries, no queuing
3. **Probes are stateless** - Parent agent manages state
4. **Probes declare capabilities** - Via class attributes (MITRE, platform, etc.)
5. **Probes can be enabled/disabled individually**

### MicroProbe Base Class

```python
class MicroProbe(abc.ABC):
    # Class attributes (override in subclasses)
    name: str = "base_probe"
    description: str = "Base probe class"
    mitre_techniques: List[str] = []
    mitre_tactics: List[str] = []
    default_enabled: bool = True
    scan_interval: float = 10.0
    requires_root: bool = False
    platforms: List[str] = ["linux", "darwin", "windows"]

    @abc.abstractmethod
    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Perform detection and return events."""
        pass
```

---

## 👁️ Complete Micro-Probe Inventory (77 Probes)

### Summary by Agent

| Agent | Probe Count | Status | MITRE Coverage |
|-------|-------------|--------|----------------|
| [ProcAgent](#1-procagent-process-monitoring) | 8 | ✅ Implemented | T1059, T1218, T1055, T1496, T1036, T1078, T1204 |
| [PeripheralAgent](#2-peripheralagent-usbbluetooth-monitoring) | 7 | ✅ Implemented | T1200, T1091, T1052, T1056.001, T1557 |
| [DNSAgent](#4-dnsagent-dns-threat-detection) | 9 | ✅ Implemented | T1071.004, T1568.002, T1568.001, T1048.001, T1566 |
| [AuthGuardAgent](#3-authguardagent-authentication-monitoring) | 8 | ✅ Implemented | T1110, T1110.003, T1078, T1548, T1059, T1621 |
| [FIMAgent](#5-fimagent-file-integrity-monitoring) | 8 | ✅ Implemented | T1036, T1547, T1505.003, T1548, T1574, T1556, T1014, T1565 |
| [PersistenceGuard](#6-persistenceguardagent-persistence-detection) | 8 | 🔄 Planned | T1547, T1053, T1136, T1098 |
| [KernelAuditAgent](#7-kernelaauditagent-kernel-syscall-monitoring) | 7 | 🔄 Planned | T1055, T1014, T1068, T1611 |
| [FlowAgent](#9-flowagent-network-flow-monitoring) | 8 | 🔄 Planned | T1071, T1048, T1090, T1021 |
| [SNMPAgent](#8-snmpagent-network-device-telemetry) | 6 | 🔄 Planned | T1557, T1562, T1200 |
| [Protocol Collectors](#10-protocol-collectors-iot-telemetry) | 10 | 🔄 Planned | T1071, T1565, T1557 |
| [DeviceDiscovery](#11-devicediscoveryengine-network-enumeration) | 6 | 🔄 Planned | T1046, T1018, T1040 |

---

### 1. ProcAgent Probes (8 probes) ✅

| # | Probe | Description | MITRE | Severity |
|---|-------|-------------|-------|----------|
| 1 | `ProcessSpawnProbe` | Detects new process creation | T1059, T1204 | INFO |
| 2 | `LOLBinExecutionProbe` | Living-off-the-land binary abuse | T1218 | HIGH |
| 3 | `ProcessTreeAnomalyProbe` | Unusual parent-child (Word→PowerShell) | T1055, T1059 | HIGH |
| 4 | `HighCPUAndMemoryProbe` | Resource abuse (cryptomining) | T1496 | MEDIUM |
| 5 | `LongLivedProcessProbe` | Persistent suspicious processes | T1036 | MEDIUM |
| 6 | `SuspiciousUserProcessProbe` | Wrong user for process type | T1078 | HIGH |
| 7 | `BinaryFromTempProbe` | Execution from temp directories | T1204, T1059 | HIGH |
| 8 | `ScriptInterpreterProbe` | Suspicious script execution | T1059 | HIGH |

**File**: `src/amoskys/agents/proc/probes.py`

---

### 2. PeripheralAgent Probes (7 probes) ✅

| # | Probe | Description | MITRE | Severity |
|---|-------|-------------|-------|----------|
| 1 | `USBInventoryProbe` | Complete USB device inventory | T1200 | DEBUG |
| 2 | `USBConnectionEdgeProbe` | Device connect/disconnect events | T1200, T1091 | MEDIUM |
| 3 | `USBStorageProbe` | USB storage device monitoring | T1052, T1091 | MEDIUM |
| 4 | `USBNetworkAdapterProbe` | Network adapter detection (MITM) | T1557, T1200 | HIGH |
| 5 | `HIDKeyboardMouseAnomalyProbe` | Keystroke injection (BadUSB) | T1200, T1056.001 | CRITICAL |
| 6 | `BluetoothDeviceProbe` | Bluetooth device monitoring | T1200 | LOW |
| 7 | `HighRiskPeripheralScoreProbe` | Composite risk scoring | T1200, T1091, T1052 | MEDIUM |

**File**: `src/amoskys/agents/peripheral/probes.py`

---

### 3. DNSAgent Probes (9 probes) ✅

| # | Probe | Description | MITRE | Severity |
|---|-------|-------------|-------|----------|
| 1 | `RawDNSQueryProbe` | Baseline DNS capture | T1071.004 | DEBUG |
| 2 | `DGAScoreProbe` | Domain Generation Algorithm detection | T1568.002 | HIGH |
| 3 | `BeaconingPatternProbe` | C2 callback detection | T1071.004, T1573.002 | HIGH |
| 4 | `SuspiciousTLDProbe` | High-risk TLD flagging | T1071.004 | MEDIUM |
| 5 | `NXDomainBurstProbe` | Domain probing/enumeration | T1568.002, T1046 | HIGH |
| 6 | `LargeTXTTunnelingProbe` | DNS tunneling via TXT records | T1048.001, T1071.004 | HIGH |
| 7 | `FastFluxRebindingProbe` | Fast-flux DNS & rebinding attacks | T1568.001 | HIGH/CRITICAL |
| 8 | `NewDomainForProcessProbe` | First-time domain per process | T1071.004 | LOW |
| 9 | `BlockedDomainHitProbe` | Threat intel blocklist hits | T1071.004, T1566 | CRITICAL |

**File**: `src/amoskys/agents/dns/probes.py`

---

### 3. AuthGuardAgent Probes (8 probes) ✅

| # | Probe | Description | MITRE | Severity |
|---|-------|-------------|-------|----------|
| 1 | `SSHBruteForceProbe` | SSH brute force (5+ failures per IP/user) | T1110, T1078 | HIGH |
| 2 | `SSHPasswordSprayProbe` | Low-and-slow across many users | T1110.003 | HIGH |
| 3 | `SSHGeoImpossibleTravelProbe` | Geographic impossibility (>1000km in <1hr) | T1078 | CRITICAL |
| 4 | `SudoElevationProbe` | First-time sudo or 3x spike | T1548.003 | MEDIUM |
| 5 | `SudoSuspiciousCommandProbe` | Dangerous sudo (bash, chmod 4777, etc.) | T1548, T1059 | HIGH/CRITICAL |
| 6 | `OffHoursLoginProbe` | Access outside 6am-8pm | T1078 | MEDIUM |
| 7 | `MFABypassOrAnomalyProbe` | MFA fatigue (push bombing) | T1621 | HIGH/CRITICAL |
| 8 | `AccountLockoutStormProbe` | Mass account lockout (5+ accounts) | T1110, T1499 | HIGH |

**File**: `src/amoskys/agents/auth/probes.py`

---

### 5. FIMAgent Probes (8 probes) ✅

| # | Probe | Description | MITRE | Severity |
|---|-------|-------------|-------|----------|
| 1 | `CriticalSystemFileChangeProbe` | Critical binaries/configs modified | T1565, T1036 | CRITICAL |
| 2 | `SUIDBitChangeProbe` | SUID/SGID bit additions | T1548.001 | HIGH |
| 3 | `ServiceCreationProbe` | New LaunchAgents/systemd/cron services | T1547, T1543 | HIGH |
| 4 | `WebShellDropProbe` | Webshell detection (PHP/JSP/ASP patterns) | T1505.003 | CRITICAL |
| 5 | `ConfigBackdoorProbe` | SSH/sudo/PAM config tampering | T1556, T1548 | HIGH |
| 6 | `LibraryHijackProbe` | LD_PRELOAD rootkits, .so drops | T1574.006, T1014 | CRITICAL |
| 7 | `BootloaderTamperProbe` | /boot kernel/bootloader tampering | T1014, T1542 | CRITICAL |
| 8 | `WorldWritableSensitiveProbe` | World-writable /etc, /var/log | T1565, T1070 | CRITICAL |

**File**: `src/amoskys/agents/fim/probes.py`

---

### 6. PersistenceGuard Probes (8 probes) 🔄 PLANNED

| # | Probe | Description | MITRE | Severity |
|---|-------|-------------|-------|----------|
| 1 | `LaunchAgentDaemonProbe` | macOS LaunchAgent/Daemon | T1543.001 | HIGH |
| 2 | `SystemdServiceProbe` | Linux systemd service files | T1543.002 | HIGH |
| 3 | `CronJobProbe` | Cron job modifications | T1053.003 | HIGH |
| 4 | `SSHAuthorizedKeysProbe` | SSH authorized_keys changes | T1098.004 | CRITICAL |
| 5 | `LoginItemStartupProbe` | Login items and startup scripts | T1547.001 | HIGH |
| 6 | `BrowserExtensionProbe` | Malicious browser extensions | T1176 | MEDIUM |
| 7 | `RegistryAutostartProbe` | Windows registry autostart | T1547.001 | HIGH |
| 8 | `HiddenPersistenceProbe` | Hidden files in home/system | T1564.001 | MEDIUM |

---

### 7. KernelAuditAgent Probes (7 probes) 🔄 PLANNED

| # | Probe | Description | MITRE | Severity |
|---|-------|-------------|-------|----------|
| 1 | `ExecSyscallProbe` | execve() system calls | T1059 | INFO |
| 2 | `SetuidSetgidProbe` | setuid/setgid syscalls | T1548 | HIGH |
| 3 | `PtraceInjectionProbe` | ptrace() for injection | T1055.008 | CRITICAL |
| 4 | `ModuleLoadProbe` | Kernel module loading | T1547.006 | CRITICAL |
| 5 | `FileOpenSensitiveProbe` | Open on /etc/shadow, keys | T1552 | HIGH |
| 6 | `NetworkConnectSyscallProbe` | connect() to suspicious ports | T1071 | MEDIUM |
| 7 | `MountFSSyscallProbe` | mount() syscall abuse | T1611 | HIGH |

---

### 8. FlowAgent Probes (8 probes) 🔄 PLANNED

| # | Probe | Description | MITRE | Severity |
|---|-------|-------------|-------|----------|
| 1 | `NewOutboundConnectionProbe` | First-time outbound destination | T1071 | LOW |
| 2 | `LongLivedFlowProbe` | Connections lasting >1 hour | T1571 | MEDIUM |
| 3 | `HighVolumeTransferProbe` | Large data transfers | T1048 | HIGH |
| 4 | `InternalPortScanProbe` | Lateral movement scanning | T1046 | HIGH |
| 5 | `LateralMovementProtocolProbe` | SMB, WMI, WinRM, SSH internal | T1021 | HIGH |
| 6 | `C2PortPatternProbe` | Common C2 ports (443, 8443) | T1571 | MEDIUM |
| 7 | `DNSOnlyC2HostProbe` | Hosts with only DNS traffic | T1071.004 | HIGH |
| 8 | `TorProxyProbe` | Tor exit node connections | T1090.003 | HIGH |

---

### 9. SNMPAgent Probes (6 probes) 🔄 PLANNED

| # | Probe | Description | MITRE | Severity |
|---|-------|-------------|-------|----------|
| 1 | `DeviceHealthProbe` | CPU, memory, uptime metrics | - | INFO |
| 2 | `ConfigChangeProbe` | Running vs startup config diff | T1565 | HIGH |
| 3 | `InterfaceErrorProbe` | Interface error rate spikes | - | MEDIUM |
| 4 | `NewInterfaceVLANProbe` | New interface or VLAN added | T1200 | HIGH |
| 5 | `ACLFirewallChangeProbe` | ACL or firewall rule changes | T1562 | CRITICAL |
| 6 | `DeviceIdentityChangeProbe` | Hostname or contact changed | T1036 | MEDIUM |

---

### 10. Protocol Collector Probes (10 probes) 🔄 PLANNED

| # | Probe | Description | MITRE | Severity |
|---|-------|-------------|-------|----------|
| 1 | `MQTTTopicAbuseProbe` | Subscription to sensitive topics | T1071 | HIGH |
| 2 | `RetainedMessageProbe` | Retained messages with payloads | T1565 | MEDIUM |
| 3 | `CommandInjectionPayloadProbe` | SQL/shell injection in payload | T1059 | CRITICAL |
| 4 | `HighPrivilegeFunctionProbe` | Modbus write to PLC | T1565 | CRITICAL |
| 5 | `UnauthorizedClientProbe` | Unknown client ID connection | T1078 | HIGH |
| 6 | `ConfigurationWriteProbe` | OPC UA config writes | T1565 | HIGH |
| 7 | `SensitiveFieldAccessProbe` | Read of password/key fields | T1552 | HIGH |
| 8 | `AnomalousSystemReaderProbe` | New process reading system regs | T1012 | MEDIUM |
| 9 | `CriticalSyslogPatternProbe` | Error/failure patterns | - | MEDIUM |
| 10 | `LogFloodingDropProbe` | Log flooding attacks | T1562.002 | HIGH |

---

### 11. DeviceDiscovery Probes (6 probes) 🔄 PLANNED

| # | Probe | Description | MITRE | Severity |
|---|-------|-------------|-------|----------|
| 1 | `ARPDiscoveryProbe` | ARP table enumeration | T1018 | INFO |
| 2 | `ActivePortScanFingerprintProbe` | Service fingerprinting | T1046 | INFO |
| 3 | `NewDeviceRiskProbe` | Risk scoring for new devices | T1200 | MEDIUM |
| 4 | `RogueDHCPDNSProbe` | Rogue DHCP/DNS server | T1557.001 | CRITICAL |
| 5 | `ShadowITProbe` | Unauthorized devices on network | T1200 | HIGH |
| 6 | `VulnerabilityBannerProbe` | Vulnerable service banners | T1595 | HIGH |

---

## MITRE ATT&CK Coverage Summary

The 77 micro-probes provide coverage across **42 unique MITRE techniques**:

| Tactic | Techniques Covered |
|--------|-------------------|
| Initial Access | T1200, T1566, T1091 |
| Execution | T1059, T1204 |
| Persistence | T1547, T1053, T1543, T1176, T1098 |
| Privilege Escalation | T1548, T1078, T1068 |
| Defense Evasion | T1036, T1070, T1562, T1564, T1014 |
| Credential Access | T1110, T1552, T1556 |
| Discovery | T1046, T1018, T1012, T1040 |
| Lateral Movement | T1021, T1091 |
| Collection | T1056.001, T1557 |
| Command and Control | T1071, T1568, T1571, T1573, T1090 |
| Exfiltration | T1048, T1052 |
| Impact | T1496, T1565

---

## Agent Inventory

| # | Agent | Status | Priority | Complexity | Migration Time |
|---|-------|--------|----------|------------|----------------|
| 1 | [ProcAgent](#1-procagent-process-monitoring) | ✅ Migrated | P0 | Low | Reference |
| 2 | [PeripheralAgent](#2-peripheralagent-usbbluetooth-monitoring) | ✅ Migrated | P1 | Low | Complete |
| 3 | [AuthGuardAgent](#3-authguardagent-authentication-monitoring) | ✅ Migrated | P1 | Medium | Complete |
| 4 | [DNSAgent](#4-dnsagent-dns-threat-detection) | ✅ Migrated | P0 | High | Complete |
| 5 | [FIMAgent](#5-fimagent-file-integrity-monitoring) | ✅ Migrated | P0 | High | Complete |
| 6 | [PersistenceGuardAgent](#6-persistenceguardagent-persistence-detection) | 🔄 Pending | P1 | Medium | 3 hours |
| 7 | [KernelAuditAgent](#7-kernelaauditagent-kernel-syscall-monitoring) | 🔄 Pending | P2 | High | 5 hours |
| 8 | [SNMPAgent](#8-snmpagent-network-device-telemetry) | 🔄 Pending | P2 | Low | 2 hours |
| 9 | [FlowAgent](#9-flowagent-network-flow-monitoring) | 🔄 Pending | P1 | Medium | 3 hours |
| 10 | [Protocol Collectors](#10-protocol-collectors-iot-telemetry) | 🔄 Pending | P3 | Low | 1 hour each |
| 11 | [DeviceDiscoveryEngine](#11-devicediscoveryengine-network-enumeration) | 🔄 Pending | P2 | Medium | 3 hours |

**Total Migration Effort**: ~30 hours (distributed across 4 weeks)

---

## 1. ProcAgent (Process Monitoring)

### Purpose
Monitors running processes and system resource utilization for anomaly detection and baseline profiling.

### Collection Method
- **Source**: `psutil` library
- **Interval**: 30 seconds (configurable)
- **Platform**: Cross-platform (Linux, macOS, Windows)

### Signals Collected

| Signal | Type | Unit | Description |
|--------|------|------|-------------|
| `process_count` | Gauge | processes | Total running processes |
| `system_cpu_percent` | Gauge | percent | System-wide CPU usage |
| `system_memory_percent` | Gauge | percent | System-wide memory usage |
| Per-process metrics (future) | N/A | N/A | PID, name, CPU, memory, user |

### Data Contract

```protobuf
DeviceTelemetry {
    device_id: string              # Hostname
    device_type: "HOST"
    protocol: "PROC"
    timestamp_ns: int64
    collection_agent: "proc-agent"
    agent_version: "2.0.0"
    events: [
        TelemetryEvent {
            event_id: "proc_count_{timestamp}"
            event_type: "METRIC"
            severity: "INFO"
            metric_data: {
                metric_name: "process_count"
                numeric_value: 142.0
                unit: "processes"
            }
        },
        # ... system_cpu_percent, system_memory_percent
    ]
}
```

### Validation Rules

- ✅ `device_id` required and non-empty
- ✅ `timestamp_ns` within 1 hour of current time
- ✅ `events` list non-empty
- ✅ Each event has `event_id` and `event_type`
- ✅ Metric values non-negative

### Enrichment

- Adds IP address via `socket.gethostbyname()`
- Adds device metadata (manufacturer="Unknown", model=hostname)

### Current Status

- ✅ **Migrated** to `HardenedAgentBase`
- ✅ Circuit breaker enabled
- ✅ Local queue integration
- ✅ Validation implemented
- ✅ Enrichment implemented

### Files

- Implementation: [proc_agent_v2.py](../src/amoskys/agents/proc/proc_agent_v2.py)
- Original: [proc_agent.py](../src/amoskys/agents/proc/proc_agent.py)
- Tests: `tests/agents/test_proc_agent.py` (pending)

---

## 2. PeripheralAgent (USB/Bluetooth Monitoring)

### Purpose
Monitors USB and Bluetooth device connections for unauthorized hardware and data exfiltration detection.

### Collection Method
- **Source**:
  - macOS: `system_profiler SPUSBDataType`
  - Linux: `lsusb`, `/sys/bus/usb`
- **Interval**: 60 seconds
- **Platform**: macOS, Linux

### Signals Collected

| Signal | Type | Description |
|--------|------|-------------|
| `device_connected` | Event | New USB/BT device attached |
| `device_disconnected` | Event | Device removed |
| `device_inventory` | Metric | Current connected device count |
| Device metadata | Attributes | Vendor, product, serial, capabilities |

### Data Contract

```python
PeripheralEvent {
    device_id: string           # Serial number or unique ID
    device_type: string         # "USB", "BLUETOOTH"
    vendor_id: string           # USB vendor ID
    product_id: string          # USB product ID
    device_name: string         # Human-readable name
    capabilities: [string]      # ["STORAGE", "HID", "NETWORK"]
    connection_status: string   # "CONNECTED", "DISCONNECTED"
    is_authorized: bool         # Against allowlist
    risk_score: float           # 0.0-1.0
    timestamp_ns: int64
}
```

### Validation Rules

- ✅ `device_id` required
- ✅ `device_type` in ["USB", "BLUETOOTH"]
- ✅ `vendor_id` format: 4 hex digits (e.g., "05ac")
- ✅ `product_id` format: 4 hex digits
- ✅ `connection_status` in ["CONNECTED", "DISCONNECTED"]
- ✅ `risk_score` in range [0.0, 1.0]

### Enrichment

- Device type classification (HID, storage, network adapter)
- Risk scoring based on:
  - Unknown vendor
  - Storage capability (exfiltration risk)
  - Network capability (backdoor risk)
  - Not in allowlist

### Threat Detection

- **Unauthorized Device**: Device not in `config/authorized_devices.yaml`
- **Mass Storage**: USB storage device attached (potential data theft)
- **Network Adapter**: Suspicious network device (rogue access point)
- **BadUSB**: HID device with unusual behavior patterns

### Migration Priority

**P1** - High security value, low complexity

**Why migrate early**:
- Simple collection logic (enumerate devices)
- Clear validation rules
- High security impact (insider threats, BadUSB)
- Good test of enrichment pipeline

**Estimated Time**: 2 hours

### Files

- Implementation: `src/amoskys/agents/peripheral/peripheral_agent.py`
- Queue: `data/queue/peripheral_agent.db`

---

## 3. AuthGuardAgent (Authentication Monitoring)

### Purpose
Monitors authentication events (SSH, sudo, screen lock) for brute force, privilege escalation, and suspicious access patterns.

### Collection Method
- **Source**:
  - macOS: Unified log (`log show --predicate`)
  - Linux: `/var/log/auth.log`, `/var/log/secure`
- **Interval**: 60 seconds
- **Lookback**: 60 seconds (configurable)
- **Platform**: macOS, Linux

### Signals Collected

| Signal | Type | Description |
|--------|------|-------------|
| `ssh_login_success` | Event | Successful SSH authentication |
| `ssh_login_failure` | Event | Failed SSH attempt |
| `sudo_execution` | Event | Sudo command executed |
| `screen_lock` | Event | Screen locked |
| `screen_unlock` | Event | Screen unlocked |
| `auth_failure_rate` | Metric | Failed auth attempts per minute |

### Data Contract

```python
AuthEvent {
    event_type: string          # "SSH_LOGIN", "SUDO_EXEC", "SCREEN_LOCK"
    status: string              # "SUCCESS", "FAILURE"
    username: string            # Account used
    source_ip: string           # For SSH (optional)
    command: string             # For sudo (optional)
    timestamp_ns: int64
    severity: string            # "INFO", "WARN", "HIGH"
}
```

### Validation Rules

- ✅ `event_type` in ["SSH_LOGIN", "SSH_FAILURE", "SUDO_EXEC", "SCREEN_LOCK", "SCREEN_UNLOCK"]
- ✅ `status` in ["SUCCESS", "FAILURE"]
- ✅ `username` required and non-empty
- ✅ `source_ip` format (if present): IPv4 or IPv6
- ✅ `timestamp_ns` reasonable

### Enrichment

- GeoIP lookup for `source_ip` (SSH logins)
- Brute force detection (5+ failures in 60s)
- Privilege escalation detection (sudo to root)
- Off-hours access flagging (outside 8am-6pm)

### Threat Detection

- **Brute Force**: 5+ failed SSH logins from same IP
- **Privilege Escalation**: Sudo from non-admin account
- **Lateral Movement**: SSH from internal IP
- **Off-Hours Access**: Login outside business hours

### Migration Priority

**P1** - Critical security signals, medium complexity

**Why migrate early**:
- High-value security events
- Log parsing can be brittle (needs validation)
- Enrichment adds context (GeoIP, time-based)

**Estimated Time**: 3 hours

### Files

- Implementation: `src/amoskys/agents/auth/auth_guard_agent.py`
- Queue: `data/queue/auth_agent.db`

---

## 4. DNSAgent (DNS Threat Detection)

### Purpose
Monitors DNS queries for C2 beaconing, DGA domains, DNS tunneling, and other DNS-based threats.

### Collection Method
- **Source**:
  - macOS: `/var/log/dns.log`, mDNSResponder logs
  - Linux: `/var/log/named`, systemd-resolved, tcpdump
- **Interval**: 60 seconds
- **Analysis Window**: 300 seconds (5 minutes)
- **Platform**: macOS, Linux

### Signals Collected

| Signal | Type | Description |
|--------|------|-------------|
| `dns_query` | Event | Raw DNS query (domain, type, response) |
| `dns_threat` | Alert | Detected threat (C2, DGA, tunneling) |
| `query_rate` | Metric | Queries per second |
| `unique_domains` | Metric | Unique domains queried |

### Data Contract

```python
DNSQuery {
    timestamp_ns: int64
    query_name: string          # "example.com"
    query_type: string          # "A", "AAAA", "TXT", "CNAME"
    source_ip: string
    response_ip: string         # Resolved IP (optional)
    response_code: string       # "NOERROR", "NXDOMAIN"
    ttl: int32
    is_recursive: bool
    process_name: string        # Process that made query (if detectable)
    process_pid: int32
}

DNSThreat {
    threat_type: string         # "C2_BEACON", "DGA", "TUNNELING", "REBINDING"
    severity: string            # "INFO", "WARN", "HIGH", "CRITICAL"
    domain: string
    evidence: string            # Human-readable explanation
    query_count: int32          # Supporting queries
    confidence: float           # 0.0-1.0
    mitre_techniques: [string]  # ["T1071.004", ...]
    first_seen: int64
    last_seen: int64
}
```

### Validation Rules

- ✅ `query_name` required, valid domain format
- ✅ `query_type` in ["A", "AAAA", "TXT", "CNAME", "MX", "NS", "PTR", "SOA"]
- ✅ `response_ip` format (if present): IPv4 or IPv6
- ✅ `response_code` in ["NOERROR", "NXDOMAIN", "SERVFAIL"]
- ✅ `ttl` range: 0-2147483647
- ✅ Threat `confidence` in [0.0, 1.0]

### Enrichment

- GeoIP for `response_ip`
- Threat intel lookup (C2 lists, malware domains)
- DGA score (Shannon entropy)
- Beacon detection (periodic query patterns)

### Threat Detection Algorithms

| Threat Type | Detection Method | Threshold |
|-------------|------------------|-----------|
| **C2 Beacon** | Periodic queries (fixed interval ±10%) | 3+ queries with <5% jitter |
| **DGA Domain** | Shannon entropy > 3.5, random-looking | Entropy > 3.5, no vowels |
| **DNS Tunneling** | Large TXT records, high query rate | TXT >512 bytes, >100 qps |
| **DNS Rebinding** | IP change within short TTL | TTL <60s, IP change |
| **Suspicious TLD** | .xyz, .top, .click, etc. | Known bad TLDs |

### Migration Priority

**P0** - Critical security agent, high complexity

**Why migrate early**:
- High-value threat detection
- Already inherits from old `HardenedAgentBase` (needs update)
- Complex validation (domain formats, threat logic)
- Rich enrichment opportunities

**Estimated Time**: 4 hours

### Files

- Implementation: `src/amoskys/agents/dns/dns_agent.py`
- Queue: `data/queue/dns_agent.db`

---

## 5. FIMAgent (File Integrity Monitoring)

### Purpose
Monitors critical system files for unauthorized modifications, indicating rootkits, malware, or tampering.

### Collection Method
- **Source**: Filesystem stat + SHA-256 hashing
- **Monitored Paths**:
  - macOS: `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/Library/LaunchAgents`, `/Library/LaunchDaemons`, `/etc`
  - Linux: `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/etc`, `/lib`, `/lib64`, `/usr/lib`, `/boot`
- **Interval**: 300 seconds (5 minutes)
- **Baseline**: `data/fim_baseline.json`
- **Platform**: macOS, Linux

### Signals Collected

| Signal | Type | Description |
|--------|------|-------------|
| `file_created` | Event | New file in monitored path |
| `file_modified` | Event | File content changed (hash mismatch) |
| `file_deleted` | Event | File removed |
| `permission_changed` | Event | Mode/owner changed |
| `file_count` | Metric | Total monitored files |

### Data Contract

```python
FileChange {
    path: string                # "/usr/bin/ls"
    change_type: string         # "CREATED", "MODIFIED", "DELETED", "PERMISSION_CHANGED"
    old_state: FileState        # Previous state (optional)
    new_state: FileState        # Current state
    severity: string            # "INFO", "WARN", "HIGH", "CRITICAL"
    mitre_techniques: [string]  # ["T1554", ...]
    timestamp_ns: int64
}

FileState {
    sha256: string              # File hash
    size: int64                 # Bytes
    mode: int32                 # Unix permissions (e.g., 0755)
    uid: int32                  # Owner UID
    gid: int32                  # Owner GID
    mtime: int64                # Modification time (nanoseconds)
    is_suid: bool               # SUID bit set
    is_sgid: bool               # SGID bit set
    is_world_writable: bool     # World writable
}
```

### Validation Rules

- ✅ `path` required, absolute path format
- ✅ `change_type` in ["CREATED", "MODIFIED", "DELETED", "PERMISSION_CHANGED", "OWNER_CHANGED"]
- ✅ `sha256` format: 64 hex characters
- ✅ `mode` range: 0-07777 (Unix permissions)
- ✅ `size` non-negative
- ✅ `severity` in ["INFO", "WARN", "HIGH", "CRITICAL"]

### Enrichment

- MITRE technique mapping:
  - SUID modification → T1548.001 (Setuid and Setgid)
  - `/etc/ld.so.preload` → T1574.006 (Dynamic Linker Hijacking)
  - Webshell in web root → T1505.003 (Web Shell)
- Webshell pattern detection (.php, .jsp, .asp, .aspx in web dirs)
- Rootkit indicator (kernel module changes in `/boot`)

### Threat Detection

- **Webshell**: New `.php`/`.jsp` file in `/var/www`
- **Rootkit**: Kernel module modified in `/boot`
- **Privilege Escalation**: SUID bit added to binary
- **Persistence**: New LaunchAgent/LaunchDaemon

### Migration Priority

**P0** - Critical security agent, high complexity

**Why migrate early**:
- Detects rootkits, malware, tampering
- Already inherits from old `HardenedAgentBase`
- Complex baseline management (needs careful setup)

**Estimated Time**: 4 hours

### Files

- Implementation: `src/amoskys/agents/fim/fim_agent.py`
- Baseline: `data/fim_baseline.json`
- Queue: `data/queue/fim_agent.db`

---

## 6. PersistenceGuardAgent (Persistence Detection)

### Purpose
Monitors persistence mechanisms (LaunchAgents, cron jobs, SSH keys) to detect malware establishing foothold.

### Collection Method
- **Source**:
  - macOS: LaunchD plist files, cron, SSH authorized_keys
  - Linux: systemd units, cron, init.d, SSH authorized_keys
- **Interval**: 300 seconds (5 minutes)
- **Snapshot**: `data/persistence_snapshot.json`
- **Platform**: macOS, Linux

### Signals Collected

| Signal | Type | Description |
|--------|------|-------------|
| `launchd_added` | Event | New LaunchAgent/LaunchDaemon |
| `cron_job_added` | Event | New cron entry |
| `ssh_key_added` | Event | New SSH authorized_key |
| `persistence_count` | Metric | Total persistence mechanisms |

### Data Contract

```python
PersistenceEvent {
    mechanism_type: string      # "LAUNCHD", "CRON", "SYSTEMD", "SSH_KEY"
    action: string              # "ADDED", "MODIFIED", "REMOVED"
    path: string                # Full path to config file
    content_hash: string        # SHA-256 of content
    details: dict               # Mechanism-specific fields
    severity: string            # "INFO", "WARN", "HIGH", "CRITICAL"
    timestamp_ns: int64
}
```

### Validation Rules

- ✅ `mechanism_type` in ["LAUNCHD", "CRON", "SYSTEMD", "SSH_KEY", "LOGIN_ITEM"]
- ✅ `action` in ["ADDED", "MODIFIED", "REMOVED"]
- ✅ `path` required, absolute path
- ✅ `content_hash` format: 64 hex characters
- ✅ `severity` in ["INFO", "WARN", "HIGH", "CRITICAL"]

### Enrichment

- MITRE technique mapping:
  - LaunchAgent → T1543.001 (Launch Agent)
  - Cron → T1053.003 (Cron)
  - SSH key → T1098.004 (SSH Authorized Keys)
- Suspicious pattern detection:
  - Reverse shell commands
  - Download-and-execute
  - Network callback

### Migration Priority

**P1** - Important security signals, medium complexity

**Estimated Time**: 3 hours

### Files

- Implementation: `src/amoskys/agents/persistence/persistence_guard_agent.py`
- Snapshot: `data/persistence_snapshot.json`

---

## 7. KernelAuditAgent (Kernel Syscall Monitoring)

### Purpose
Monitors kernel-level syscalls for privilege escalation, process injection, and container escapes.

### Collection Method
- **Source**:
  - macOS: Endpoint Security Framework (ESF) or OpenBSM audit
  - Linux: auditd, eBPF
- **Interval**: Real-time (event-driven)
- **Platform**: macOS, Linux (Linux only currently implemented)

### Signals Collected

| Signal | Type | Description |
|--------|------|-------------|
| `syscall_exec` | Event | Process execution |
| `syscall_open` | Event | File open |
| `syscall_connect` | Event | Network connection |
| `syscall_ptrace` | Event | Process debugging/injection |
| `syscall_mmap` | Event | Memory mapping |
| `privilege_escalation` | Alert | Suspicious setuid/setgid |

### Data Contract

```python
AuditEvent {
    event_type: string          # "EXEC", "OPEN", "CONNECT", "PTRACE", "MMAP"
    timestamp_ns: int64
    pid: int32
    ppid: int32                 # Parent PID
    uid: int32
    euid: int32                 # Effective UID
    gid: int32
    egid: int32                 # Effective GID
    process_name: string
    process_path: string
    args: [string]              # Command arguments
    target_path: string         # For OPEN
    target_pid: int32           # For PTRACE
    syscall: string             # Syscall name
    return_code: int32          # Syscall return value
}
```

### Validation Rules

- ✅ `event_type` in ["EXEC", "OPEN", "CONNECT", "PTRACE", "MMAP", "SETUID", "MODULE_LOAD"]
- ✅ `pid` > 0
- ✅ `uid`, `gid` >= 0
- ✅ `process_path` non-empty
- ✅ `syscall` non-empty

### Enrichment

- MITRE technique mapping:
  - setuid → T1068 (Privilege Escalation)
  - ptrace → T1055 (Process Injection)
  - Container escape → T1611 (Escape to Host)
  - Module load → T1014 (Rootkit)

### Migration Priority

**P2** - Advanced agent, high complexity, Linux-only

**Estimated Time**: 5 hours

### Files

- Implementation: `src/amoskys/agents/kernel/kernel_audit_agent.py`

---

## 8. SNMPAgent (Network Device Telemetry)

### Purpose
Collects metrics from network devices (routers, switches, firewalls) via SNMP.

### Collection Method
- **Source**: SNMP v1 queries (pysnmp)
- **Interval**: 60 seconds
- **Platform**: Cross-platform

### Signals Collected

| Signal | OID | Description |
|--------|-----|-------------|
| `sysDescr` | 1.3.6.1.2.1.1.1.0 | System description |
| `sysUpTime` | 1.3.6.1.2.1.1.3.0 | Device uptime |
| `sysContact` | 1.3.6.1.2.1.1.4.0 | Contact info |
| `sysName` | 1.3.6.1.2.1.1.5.0 | Hostname |
| `sysLocation` | 1.3.6.1.2.1.1.6.0 | Physical location |

### Validation Rules

- ✅ `device_ip` required, valid IPv4/IPv6
- ✅ `uptime` non-negative
- ✅ All values non-empty strings

### Migration Priority

**P2** - Useful for network visibility, low complexity

**Estimated Time**: 2 hours

### Files

- Implementation: `src/amoskys/agents/snmp/snmp_agent.py`
- Queue: `data/queue/snmp_agent.db`

---

## 9. FlowAgent (Network Flow Monitoring)

### Purpose
Monitors network flows (connections) for threat detection and network visibility.

### Collection Method
- **Source**: Network flow data (5-tuple + byte counts)
- **Interval**: Real-time (event-driven)
- **WAL**: `config.agent.wal_path`
- **Platform**: Cross-platform

### Signals Collected

| Signal | Type | Description |
|--------|------|-------------|
| `flow_start` | Event | New connection established |
| `flow_end` | Event | Connection closed |
| `flow_stats` | Metric | Bytes TX/RX, duration |

### Data Contract

```python
FlowEvent {
    src_ip: string              # Source IP
    dst_ip: string              # Destination IP
    src_port: int32             # Source port
    dst_port: int32             # Destination port
    protocol: string            # "TCP", "UDP", "ICMP"
    bytes_tx: int64             # Bytes transmitted
    bytes_rx: int64             # Bytes received
    timestamp_ns: int64
}
```

### Validation Rules

- ✅ `src_ip`, `dst_ip` required, valid IP format
- ✅ `src_port`, `dst_port` range: 0-65535
- ✅ `protocol` in ["TCP", "UDP", "ICMP", "OTHER"]
- ✅ `bytes_tx`, `bytes_rx` non-negative

### Enrichment

- GeoIP for src/dst IPs
- Port classification (common services vs suspicious)
- Threat intel (known C2 IPs, malware infrastructure)

### Migration Priority

**P1** - Important for network visibility

**Estimated Time**: 3 hours

### Files

- Implementation: `src/amoskys/agents/flowagent/flow_agent.py`
- WAL: Uses SQLiteWAL

---

## 10. Protocol Collectors (IoT Telemetry)

### Purpose
Collect telemetry from specialized protocols (MQTT, Modbus, HL7/FHIR, Syslog).

### Collection Method
- **Source**: Protocol-specific clients
- **Interval**: Real-time (event-driven)
- **Platform**: Cross-platform

### Collectors

| Collector | Protocol | Use Case |
|-----------|----------|----------|
| MQTTCollector | MQTT | IoT devices (sensors, actuators) |
| ModbusCollector | Modbus TCP | Industrial control systems (PLCs, SCADA) |
| HL7FHIRCollector | HL7/FHIR | Medical devices (patient monitors) |
| SyslogCollector | Syslog | Network device logs |

### Migration Priority

**P3** - Specialized use cases, low complexity

**Estimated Time**: 1 hour each

---

## 11. DeviceDiscoveryEngine (Network Enumeration)

### Purpose
Discovers devices on the network and identifies vulnerabilities.

### Collection Method
- **Source**: Network scanning (nmap-like)
- **Interval**: 3600 seconds (1 hour)
- **Platform**: Cross-platform

### Signals Collected

| Signal | Type | Description |
|--------|------|-------------|
| `device_discovered` | Event | New device found |
| `service_detected` | Event | Service running on port |
| `vulnerability_found` | Alert | Known CVE detected |

### Migration Priority

**P2** - Network visibility, medium complexity

**Estimated Time**: 3 hours

---

## Migration Roadmap

### Week 1: Foundation + Reference

**Goals**: Validate pattern, create tooling

- [x] Create `HardenedAgentBase`
- [x] Create `LocalQueueAdapter`
- [x] Migrate `ProcAgent` (reference implementation)
- [ ] Write unit tests for `proc_agent_v2`
- [ ] Create `EventBusPublisher` base class (reusable)
- [ ] Create validation helpers (IP format, domain format, etc.)

**Deliverables**:
- Working reference implementation
- Test framework
- Reusable components

---

### Week 2: Core Security Agents

**Goals**: Migrate high-priority security agents

**Monday**: `PeripheralAgent`
- Simple collection (device enumeration)
- Good validation test case
- Clear enrichment (device classification)

**Tuesday-Wednesday**: `DNSAgent`
- Update old `HardenedAgentBase` to new
- Complex validation (domain formats, threat logic)
- Rich enrichment (GeoIP, threat intel)

**Thursday**: `AuthGuardAgent`
- Log parsing validation
- Enrichment (GeoIP, brute force detection)

**Friday**: Testing & Documentation
- Integration tests
- Update migration guide with learnings

**Deliverables**:
- 3 migrated agents
- Updated migration patterns

---

### Week 3: Specialized Agents

**Monday**: `FIMAgent`
- Update old `HardenedAgentBase`
- Baseline management
- Complex validation (file states)

**Tuesday**: `PersistenceGuardAgent`
- Snapshot management
- Pattern detection

**Wednesday**: `SNMPAgent`
- Simple SNMP query pattern
- Basic validation

**Thursday**: `FlowAgent`
- High-volume considerations
- Sampling strategy

**Friday**: Testing & Optimization
- Load testing
- Performance profiling

**Deliverables**:
- 4 migrated agents
- Performance benchmarks

---

### Week 4: Final Agents + Production

**Monday**: `KernelAuditAgent`
- Platform-specific (Linux)
- Complex syscall parsing

**Tuesday**: Protocol Collectors
- MQTT, Modbus, HL7, Syslog
- Lightweight migrations

**Wednesday**: `DeviceDiscoveryEngine`
- Network scanning
- Vulnerability detection

**Thursday**: Integration Testing
- All 11 agents running simultaneously
- Chaos testing (EventBus failures, network issues)
- Load testing (10x normal load)

**Friday**: Production Deployment
- Staging deployment
- Monitoring setup
- Production rollout

**Deliverables**:
- ✅ 11/11 agents migrated
- Load test results
- Production deployment

---

## Common Patterns

### Validation Helper Functions

Create reusable validators in `src/amoskys/agents/common/validators.py`:

```python
def is_valid_domain(domain: str) -> bool:
    """Check if domain is valid format."""
    # No spaces, has TLD, reasonable length
    if not domain or ' ' in domain:
        return False
    if '.' not in domain:
        return False
    if len(domain) > 253:
        return False
    return True

def is_valid_ipv4(ip: str) -> bool:
    """Check if IPv4 address is valid."""
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            num = int(part)
            if num < 0 or num > 255:
                return False
        return True
    except:
        return False

def is_valid_port(port: int) -> bool:
    """Check if port is in valid range."""
    return 0 <= port <= 65535

def is_valid_sha256(hash: str) -> bool:
    """Check if SHA-256 hash is valid format."""
    return len(hash) == 64 and all(c in '0123456789abcdefABCDEF' for c in hash)
```

---

### Enrichment Helper Functions

Create reusable enrichers in `src/amoskys/agents/common/enrichers.py`:

```python
class GeoIPEnricher:
    """Add geolocation to IP addresses."""
    def __init__(self, db_path="data/geoip.mmdb"):
        self.db = geoip2.database.Reader(db_path)

    def enrich_ip(self, ip: str) -> dict:
        try:
            response = self.db.city(ip)
            return {
                'country': response.country.name,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude,
            }
        except:
            return {}

class ThreatIntelEnricher:
    """Add threat intelligence tags."""
    def __init__(self, feed_path="data/threat_intel.json"):
        self.feed = json.load(open(feed_path))

    def check_domain(self, domain: str) -> dict:
        if domain in self.feed['malware_domains']:
            return {
                'is_malicious': True,
                'categories': ['malware', 'c2'],
                'threat_score': 0.95,
            }
        return {'is_malicious': False}
```

---

## Testing Strategy

### Unit Tests (Per Agent)

```python
def test_proc_agent_validation_success():
    agent = ProcAgent()
    event = create_valid_telemetry()
    result = agent.validate_event(event)
    assert result.is_valid

def test_proc_agent_validation_missing_device_id():
    agent = ProcAgent()
    event = create_telemetry_missing_device_id()
    result = agent.validate_event(event)
    assert not result.is_valid
    assert "device_id" in str(result.errors)

def test_proc_agent_enrichment_adds_metadata():
    agent = ProcAgent()
    event = create_minimal_telemetry()
    enriched = agent.enrich_event(event)
    assert enriched.HasField("metadata")
    assert enriched.metadata.ip_address
```

### Integration Tests (Fleet-Wide)

```python
def test_all_agents_healthy():
    """Verify all 11 agents start and report healthy."""
    agents = [
        ProcAgent(),
        PeripheralAgent(),
        AuthGuardAgent(),
        # ... all 11
    ]

    for agent in agents:
        assert agent.setup()
        health = agent.health_summary()
        assert health['circuit_breaker_state'] == 'CLOSED'
```

### Load Tests

```python
def test_agents_handle_eventbus_downtime():
    """Simulate EventBus failure, verify queue behavior."""
    agent = ProcAgent()
    agent.setup()

    # Stop EventBus
    mock_eventbus.stop()

    # Run 10 collection cycles
    for _ in range(10):
        agent._run_one_cycle()

    # Verify queue filled
    assert agent.local_queue.size() > 0
    assert agent.circuit_breaker.state == 'OPEN'

    # Restart EventBus
    mock_eventbus.start()
    time.sleep(35)  # Wait for recovery timeout

    # Next cycle should drain queue
    agent._run_one_cycle()
    assert agent.local_queue.size() == 0
    assert agent.circuit_breaker.state == 'CLOSED'
```

---

## Metrics Dashboard

Once all agents migrated, Prometheus dashboard will show:

```prometheus
# Agent Health
sum(agent_health_status) by (agent_name)  # 1=healthy, 0=unhealthy

# Collection Rate
rate(agent_events_collected_total[5m]) by (agent_name)

# Validation Failures
rate(agent_events_rejected_total[5m]) by (agent_name, reason)

# Circuit Breaker State
max(agent_circuit_breaker_state) by (agent_name)  # 0=CLOSED, 1=OPEN

# Queue Depth
max(agent_local_queue_size) by (agent_name)

# Error Rate
rate(agent_publish_failure_total[5m]) by (agent_name)
```

---

## Summary

**Fleet Composition**:
- 11 specialized agents
- 5 security-focused (DNS, FIM, Auth, Persistence, Kernel)
- 3 system monitoring (Proc, Peripheral, Flow)
- 3 network/IoT (SNMP, Protocol Collectors, Discovery)

**Migration Status**:
- ✅ 1/11 complete (ProcAgent)
- 🎯 10/11 pending
- 📅 4-week rollout plan

**Key Patterns**:
- All inherit from `HardenedAgentBase`
- All use `LocalQueueAdapter`
- All implement 5 lifecycle hooks
- All have validation and enrichment

**End Goal**: Unbreakable agent fleet with:
- Circuit breaker protection
- Offline resilience
- Data quality guarantees
- Consistent observability
- Easy testing and deployment

Ready to build unbreakable agents. 🔥
