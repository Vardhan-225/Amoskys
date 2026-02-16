# AMOSKYS Telemetry Inventory

> **Status:** Active — Created 2026-02-16 from codebase analysis + Mac Lab empirical run  
> **Purpose:** Agent/probe/event schemas and what is actually emitted  
> **Source of truth:** Code in `src/amoskys/agents/*/probes.py` + queue decode from Mac Lab

---

## 1. Agent Inventory

| # | Agent | Module | V2 Class | Probes | Collector | Mac Status | Linux Status |
|---|-------|--------|----------|--------|-----------|------------|--------------|
| 1 | KernelAudit | `kernel_audit` | `KernelAuditAgentV2` | 7 | `AuditdLogCollector` | Lifecycle only (no audit.log) | Full |
| 2 | ProtocolCollectors | `protocol_collectors` | `ProtocolCollectorsV2` | 10 | `StubProtocolCollector` (Mac) / `NetworkLogCollector` (Linux) | Stub events | Full |
| 3 | DeviceDiscovery | `device_discovery` | `DeviceDiscoveryV2` | 6 | ARP probes (direct) | Lifecycle only (no `ip neigh`) | Full |
| 4 | ProcAgent | `proc` | `ProcAgentV2` (via `proc_agent_v3.py`) | 8 | psutil | Full | Full |
| 5 | FlowAgent | `flow` | `FlowAgentV2` | 8 | Socket/conntrack | Partial | Full |
| 6 | AuthGuard | `auth` | `AuthGuardAgentV2` | 8 | Auth log parser | Partial | Full |
| 7 | DNS | `dns` | `DNSAgentV2` | 9 | DNS query log | Partial | Full |
| 8 | FIM | `fim` | `FIMAgentV2` | 8 | FS watcher | Full | Full |
| 9 | Peripheral | `peripheral` | `PeripheralAgentV2` | 7 | USB/BT scanner | Partial | Full |
| 10 | Persistence | `persistence` | `PersistenceAgentV2` | 8 | Config file scanner | Full | Full |

**Total: 10 agents, 79 probes** (not 67 — corrected after inventory)

---

## 2. Probe-by-Probe Inventory

### 2.1 KernelAudit (7 probes)

| Probe | Class | Event Type | MITRE | Trigger | Expected Rate | Known Gaps |
|-------|-------|-----------|-------|---------|---------------|------------|
| ExecveHighRisk | `ExecveHighRiskProbe` | `kernel_threat` | T1059, T1204.002 | execve from /tmp, /dev/shm, hidden dirs | Low | Linux-only (no macOS audit source) |
| PrivEscSyscall | `PrivEscSyscallProbe` | `kernel_threat` | T1068, T1548.001 | setuid/setgid syscalls | Low | Linux-only |
| KernelModuleLoad | `KernelModuleLoadProbe` | `kernel_threat` | T1014, T1547.006 | init_module, finit_module | Very Low | Linux-only |
| PtraceAbuse | `PtraceAbuseProbe` | `kernel_threat` | T1055, T1055.008 | ptrace attach/inject | Low | Linux-only |
| FilePermissionTamper | `FilePermissionTamperProbe` | `kernel_threat` | T1222, T1222.002 | chmod/chown on sensitive files | Low | Linux-only |
| AuditTamper | `AuditTamperProbe` | `kernel_threat` | T1562.001, T1070.002 | Audit config changes, log deletion | Very Low | Linux-only |
| SyscallFlood | `SyscallFloodProbe` | `kernel_threat` | T1592, T1083 | >N syscalls in M seconds | Medium under brute force | Linux-only |

### 2.2 ProtocolCollectors (10 probes)

| Probe | Class | Event Type | MITRE | Trigger | Expected Rate | Known Gaps |
|-------|-------|-----------|-------|---------|---------------|------------|
| HTTPSuspiciousHeaders | `HTTPSuspiciousHeadersProbe` | `protocol_threat` | T1071.001 | Unusual User-Agent, X-Forwarded-For spoofing | Medium | Stub on Mac |
| TLSSSLAnomaly | `TLSSSLAnomalyProbe` | `protocol_threat` | T1573.002 | Self-signed certs, expired certs, weak ciphers | Low | Stub on Mac |
| SSHBruteForce | `SSHBruteForceProbe` | `protocol_threat` | T1110, T1021.004 | >N failed SSH in M seconds | Medium under attack | Stub on Mac |
| DNSTunneling | `DNSTunnelingProbe` | `protocol_threat` | T1048.003 | Long subdomains, high TXT record volume | Low | Stub on Mac |
| SQLInjection | `SQLInjectionProbe` | `protocol_threat` | T1190 | SQL keywords in HTTP params | Low | Stub on Mac |
| RDPSuspicious | `RDPSuspiciousProbe` | `protocol_threat` | T1021.001 | Unusual RDP patterns | Low | Stub on Mac |
| FTPCleartextCreds | `FTPCleartextCredsProbe` | `protocol_threat` | T1552.001 | Cleartext FTP auth | Medium on FTP traffic | Stub on Mac |
| SMTPSpamPhish | `SMTPSpamPhishProbe` | `protocol_threat` | T1566.001 | Suspicious SMTP patterns | Low | Stub on Mac |
| IRCP2PC2 | `IRCP2PC2Probe` | `protocol_threat` | T1071.001 | IRC/P2P traffic on known C2 ports | Very Low | Stub on Mac |
| ProtocolAnomaly | `ProtocolAnomalyProbe` | `protocol_threat` | T1205 | Protocol mismatch (HTTP on non-80, etc) | Low | Stub on Mac |

### 2.3 DeviceDiscovery (6 probes)

| Probe | Class | Event Type | MITRE | Trigger | Expected Rate | Known Gaps |
|-------|-------|-----------|-------|---------|---------------|------------|
| ARPDiscovery | `ARPDiscoveryProbe` | `device_discovered` | T1018 | New IP in ARP cache | Low | No macOS fallback (`arp -a`) |
| ActivePortScanFingerprint | `ActivePortScanFingerprintProbe` | `service_fingerprint` | T1046 | Open port + banner grab | Medium | Requires network access |
| NewDeviceRisk | `NewDeviceRiskProbe` | `device_risk_assessment` | T1200 | New device appears, risk scored | Low | Depends on ARP probe |
| RogueDHCPDNS | `RogueDHCPDNSProbe` | `rogue_server_detected` | T1557.001 | Unauthorized DHCP/DNS server | Very Low | Requires network monitoring |
| ShadowIT | `ShadowITProbe` | `shadow_it_detected` | T1200 | Device not in known_ips set | Low | Depends on ARP probe |
| VulnerabilityBanner | `VulnerabilityBannerProbe` | `vulnerable_service` | T1595 | Known-vulnerable version in banner | Low | Depends on port scan probe |

### 2.4 ProcAgent (8 probes)

| Probe | Class | Event Type | MITRE | Trigger | Expected Rate | Known Gaps |
|-------|-------|-----------|-------|---------|---------------|------------|
| ProcessSpawn | `ProcessSpawnProbe` | `process_spawn` | T1059, T1204 | New process detected | High | Sampling needed under load |
| LOLBinExecution | `LOLBinExecutionProbe` | `lolbin_execution` | T1218, T1218.010, T1218.011 | Known LOLBin executed | Medium | LOLBin list may be incomplete |
| ProcessTreeAnomaly | `ProcessTreeAnomalyProbe` | `process_tree_anomaly` | T1055, T1059 | Unusual parent-child relationship | Low | Baseline definition needed |
| HighCPUAndMemory | `HighCPUAndMemoryProbe` | `resource_anomaly` | T1496 | CPU/mem above threshold | Medium | Threshold tuning needed |
| LongLivedProcess | `LongLivedProcessProbe` | `long_lived_process` | T1036 | Process running longer than expected | Low | Baseline definition needed |
| SuspiciousUserProcess | `SuspiciousUserProcessProbe` | `suspicious_user_process` | T1078 | Process run by unusual user | Low | User baseline needed |
| BinaryFromTemp | `BinaryFromTempProbe` | `binary_from_temp` | T1204, T1059 | Binary executed from /tmp | Low | Same as ExecveHighRisk intent |
| ScriptInterpreter | `ScriptInterpreterProbe` | `script_interpreter` | T1059, T1059.001, T1059.003, T1059.004, T1059.006 | Script interpreter with suspicious args | Medium | False positive risk |

### 2.5 FlowAgent (8 probes)

| Probe | Class | Event Type | MITRE | Trigger | Expected Rate | Known Gaps |
|-------|-------|-----------|-------|---------|---------------|------------|
| PortScanSweep | `PortScanSweepProbe` | `port_scan` | T1046 | >N unique ports to one host | Low | Threshold tuning |
| LateralSMBWinRM | `LateralSMBWinRMProbe` | `lateral_movement` | T1021.002, T1021.003, T1021.006 | SMB/WinRM to internal hosts | Low | Windows-centric |
| DataExfilVolumeSpike | `DataExfilVolumeSpikeProbe` | `exfil_spike` | T1041, T1048 | Outbound bytes > N× baseline | Low | Baseline needed |
| C2BeaconFlow | `C2BeaconFlowProbe` | `c2_beacon` | T1071.001, T1071.004 | Periodic outbound connections | Low | Beaconing detection tuning |
| CleartextCredentialLeak | `CleartextCredentialLeakProbe` | `cleartext_creds` | T1552.001 | Credentials in plaintext flows | Very Low | DPI needed |
| SuspiciousTunnel | `SuspiciousTunnelProbe` | `suspicious_tunnel` | T1090, T1572 | SSH tunnel, VPN anomaly | Low | Hard to distinguish from legit |
| InternalReconDNSFlow | `InternalReconDNSFlowProbe` | `internal_recon` | T1046, T1590 | DNS queries for internal hosts | Low | Normal DNS noise |
| NewExternalService | `NewExternalServiceProbe` | `new_external_service` | T1041, T1595 | First connection to external IP | Medium | Baseline needed |

### 2.6 AuthGuard (8 probes)

| Probe | Class | Event Type | MITRE | Trigger | Expected Rate | Known Gaps |
|-------|-------|-----------|-------|---------|---------------|------------|
| SSHBruteForce | `SSHBruteForceProbe` | `ssh_brute_force` | T1110, T1078 | >N failed SSH in M seconds | Medium under attack | Same as ProtocolCollectors SSH probe |
| SSHPasswordSpray | `SSHPasswordSprayProbe` | `password_spray` | T1110.003 | Same password, many users | Low | Requires auth log parsing |
| SSHGeoImpossibleTravel | `SSHGeoImpossibleTravelProbe` | `impossible_travel` | T1078 | Login from geographically impossible locations | Very Low | Needs GeoIP DB |
| SudoElevation | `SudoElevationProbe` | `sudo_elevation` | T1548.003 | sudo to root | Medium | Normal admin activity |
| SudoSuspiciousCommand | `SudoSuspiciousCommandProbe` | `suspicious_sudo` | T1548, T1059, T1547 | sudo + suspicious command combo | Low | Command list maintenance |
| OffHoursLogin | `OffHoursLoginProbe` | `off_hours_login` | T1078 | Login outside business hours | Medium | Hours config needed |
| MFABypassOrAnomaly | `MFABypassOrAnomalyProbe` | `mfa_anomaly` | T1621 | MFA bypass or anomaly patterns | Very Low | MFA integration needed |
| AccountLockoutStorm | `AccountLockoutStormProbe` | `lockout_storm` | T1110, T1499 | Mass lockouts | Low under attack | Threshold tuning |

### 2.7 DNS Agent (9 probes)

| Probe | Class | Event Type | MITRE | Trigger | Expected Rate | Known Gaps |
|-------|-------|-----------|-------|---------|---------------|------------|
| RawDNSQuery | `RawDNSQueryProbe` | `dns_query` | T1071.004 | All DNS queries captured | High | Sampling needed |
| DGAScore | `DGAScoreProbe` | `dga_detected` | T1568.002 | Domain generation algorithm patterns | Low | ML model or heuristic |
| BeaconingPattern | `BeaconingPatternProbe` | `dns_beaconing` | T1071.004, T1573.002 | Regular interval DNS queries | Low | Interval detection tuning |
| SuspiciousTLD | `SuspiciousTLDProbe` | `suspicious_tld` | T1071.004 | Queries to risky TLDs (.tk, .xyz, etc) | Medium | TLD list maintenance |
| NXDomainBurst | `NXDomainBurstProbe` | `nxdomain_burst` | T1568.002, T1046 | >N NXDOMAIN in M seconds | Low | DGA or recon indicator |
| LargeTXTTunneling | `LargeTXTTunnelingProbe` | `dns_tunneling` | T1048.001, T1071.004 | Large TXT record responses | Low | Size threshold tuning |
| FastFluxRebinding | `FastFluxRebindingProbe` | `fast_flux` | T1568.001 | IP changes for same domain | Low | Timing window tuning |
| NewDomainForProcess | `NewDomainForProcessProbe` | `new_domain` | T1071.004 | First-seen domain for known process | Medium | Baseline needed |
| BlockedDomainHit | `BlockedDomainHitProbe` | `blocked_domain_hit` | T1071.004, T1566 | Query for known-blocked domain | Low | Blocklist maintenance |

### 2.8 FIM Agent (8 probes)

| Probe | Class | Event Type | MITRE | Trigger | Expected Rate | Known Gaps |
|-------|-------|-----------|-------|---------|---------------|------------|
| CriticalSystemFileChange | `CriticalSystemFileChangeProbe` | `critical_file_change` | T1036, T1547, T1574 | /etc/passwd, /etc/shadow changed | Very Low | Watch list needed |
| SUIDBitChange | `SUIDBitChangeProbe` | `suid_change` | T1548.001, T1068 | SUID/SGID bit set on binary | Very Low | Linux-specific |
| ServiceCreation | `ServiceCreationProbe` | `service_created` | T1543, T1053, T1050 | New systemd/launchd service | Low | OS-dependent |
| WebShellDrop | `WebShellDropProbe` | `webshell_detected` | T1505.003 | PHP/JSP/ASP file in web root | Very Low | Web root config needed |
| ConfigBackdoor | `ConfigBackdoorProbe` | `config_backdoor` | T1548, T1078, T1556 | Backdoor patterns in config files | Very Low | Pattern list needed |
| LibraryHijack | `LibraryHijackProbe` | `library_hijack` | T1574.006, T1014 | Suspicious .so/.dylib in load path | Low | Path list needed |
| BootloaderTamper | `BootloaderTamperProbe` | `bootloader_tamper` | T1542.003 | Changes to boot partition | Very Low | Requires special access |
| WorldWritableSensitive | `WorldWritableSensitiveProbe` | `world_writable` | T1565, T1070 | Sensitive file made world-writable | Low | File list needed |

### 2.9 Peripheral Agent (7 probes)

| Probe | Class | Event Type | MITRE | Trigger | Expected Rate | Known Gaps |
|-------|-------|-----------|-------|---------|---------------|------------|
| USBInventory | `USBInventoryProbe` | `usb_inventory` | T1200 | USB device enumeration | Low | macOS: system_profiler |
| USBConnectionEdge | `USBConnectionEdgeProbe` | `usb_connected` | T1200, T1091 | New USB device connected | Very Low | Requires monitoring |
| USBStorage | `USBStorageProbe` | `usb_storage` | T1052, T1091 | USB storage device mounted | Very Low | Data exfil risk |
| USBNetworkAdapter | `USBNetworkAdapterProbe` | `usb_network` | T1557, T1200 | USB network adapter detected | Very Low | Rogue AP risk |
| HIDKeyboardMouseAnomaly | `HIDKeyboardMouseAnomalyProbe` | `hid_anomaly` | T1200, T1056.001 | BadUSB/rubber ducky patterns | Very Low | HID monitoring needed |
| BluetoothDevice | `BluetoothDeviceProbe` | `bluetooth_device` | T1200 | Bluetooth device discovered | Low | macOS: IOBluetooth |
| HighRiskPeripheralScore | `HighRiskPeripheralScoreProbe` | `peripheral_risk` | T1200, T1091, T1052 | Risk score for peripheral device | Low | Scoring rules needed |

### 2.10 Persistence Agent (8 probes)

| Probe | Class | Event Type | MITRE | Trigger | Expected Rate | Known Gaps |
|-------|-------|-----------|-------|---------|---------------|------------|
| LaunchAgentDaemon | `LaunchAgentDaemonProbe` | `persistence_launchagent` | T1543.001, T1037.005 | New/modified LaunchAgent or Daemon plist | Very Low | macOS-specific |
| SystemdServicePersistence | `SystemdServicePersistenceProbe` | `persistence_systemd` | T1543.002 | New systemd service created | Very Low | Linux-specific |
| CronJobPersistence | `CronJobPersistenceProbe` | `persistence_cron` | T1053.003 | New/modified crontab entry | Low | Both Mac + Linux |
| SSHKeyBackdoor | `SSHKeyBackdoorProbe` | `persistence_sshkey` | T1098.004 | New SSH key added to authorized_keys | Very Low | High-value indicator |
| ShellProfileHijack | `ShellProfileHijackProbe` | `persistence_shellprofile` | T1037.004, T1546.004 | .bashrc/.zshrc modified | Low | Normal on dev machines |
| BrowserExtensionPersistence | `BrowserExtensionPersistenceProbe` | `persistence_browserext` | T1176 | New browser extension installed | Low | Chrome/Firefox paths |
| StartupFolderLoginItem | `StartupFolderLoginItemProbe` | `persistence_startup` | T1547.001, T1037.001 | Login item or startup folder entry | Very Low | OS-dependent |
| HiddenFilePersistence | `HiddenFilePersistenceProbe` | `persistence_hidden` | T1564, T1053, T1547 | Hidden files in suspicious locations | Low | False positive risk |

---

## 3. Event Schema (Protobuf)

### 3.1 Wire Format

All events use `DeviceTelemetry` protobuf (defined in `proto/universal_telemetry.proto`):

```
DeviceTelemetry
├── device_id: string          ← "mac-akash"
├── device_type: string        ← "HOST" or "endpoint"
├── protocol: string           ← "AGENT_METRICS" or ""
├── collection_agent: string   ← class name (e.g., "KernelAuditAgentV2")
├── agent_version: string      ← "v2"
├── timestamp_ns: uint64       ← nanosecond epoch
├── events[]: TelemetryEvent
│   ├── event_id: string
│   ├── event_type: string     ← "agent_metrics", "protocol_threat", etc.
│   ├── severity: string       ← "INFO", "MEDIUM", "HIGH", "CRITICAL"
│   ├── source_component: string
│   ├── tags[]: string
│   ├── attributes: map<string,string>
│   ├── confidence_score: float
│   ├── metric_data: MetricData        ← populated for agent_metrics
│   ├── security_event: SecurityEvent  ← SHOULD be populated for threats (GAP-01)
│   └── ...
└── security: SecurityContext
```

### 3.2 Empirically Observed Event Types

From Mac Lab run (2026-02-16):

| Event Type | Source Agent | Severity | Data Sub-message | Attributes Populated | Notes |
|-----------|-------------|----------|-----------------|---------------------|-------|
| `agent_metrics` | All 3 | INFO | None (attributes map) | ✅ 8 fields: loops_started, loops_succeeded, loops_failed, events_emitted, probe_events_emitted, probe_errors, last_success_ns, last_failure_ns | Real operational metrics |
| `protocol_threat` | ProtocolCollectorsV2 | MEDIUM | None ⚠️ | ❌ Empty | **GAP-01:** No structured security data carried |

### 3.3 Expected but Not Yet Observed

These event types are defined in probes but were not emitted during the Mac Lab run (either because the agent couldn't collect on macOS, or because no threat conditions were met):

- `kernel_threat` — KernelAudit probes (Linux-only)
- `device_discovered` — ARPDiscoveryProbe (Linux-only)
- `process_spawn`, `lolbin_execution` — ProcAgent probes
- `ssh_brute_force`, `password_spray` — AuthGuard probes
- `dns_query`, `dga_detected` — DNS Agent probes
- All FIM, Peripheral, Persistence event types

### 3.4 Schema Contract (Required Fields)

Every event MUST have:

| Field | Requirement | Validated |
|-------|------------|-----------|
| `device_id` | Non-empty string | ✅ All events have "mac-akash" |
| `event_type` | Non-empty string | ✅ All events have type |
| `severity` | One of INFO, LOW, MEDIUM, HIGH, CRITICAL | ✅ Observed INFO, MEDIUM |
| `source_component` | Agent class name or agent_name | ✅ Populated (but empty on some threat events — GAP-07) |
| `event_id` | Unique string per event | ⚠️ Uses timestamp — uniqueness not guaranteed under high rate |

Every `agent_metrics` event MUST have:

| Attribute | Requirement | Validated |
|-----------|------------|-----------|
| `loops_started` | Integer ≥ 0 | ✅ |
| `loops_succeeded` | Integer ≥ 0 | ✅ |
| `loops_failed` | Integer ≥ 0 | ✅ |
| `events_emitted` | Integer ≥ 0 | ✅ |
| `last_success_ns` | Nanosecond timestamp | ✅ |

Every threat event SHOULD have (currently NOT validated — GAP-01):

| Field | Requirement | Validated |
|-------|------------|-----------|
| `security_event.event_category` | Attack category | ❌ Not populated |
| `security_event.mitre_techniques` | MITRE technique IDs | ❌ Not populated |
| `security_event.source_ip` | Source IP if network event | ❌ Not populated |
| `attributes` or `tags` | Evidence details | ❌ Empty |

---

## 4. MITRE ATT&CK Coverage Matrix

### Techniques Claimed by Probes (67 unique technique IDs across 79 probes)

| Tactic | Techniques Mapped | Probes Covering |
|--------|-------------------|-----------------|
| Initial Access (TA0001) | T1190, T1200 | SQLInjection, NewDeviceRisk, USBInventory, ShadowIT |
| Execution (TA0002) | T1059, T1204, T1218 | ProcessSpawn, LOLBin, ExecveHighRisk, ScriptInterpreter |
| Persistence (TA0003) | T1037, T1053, T1098, T1176, T1543, T1546, T1547, T1564 | All 8 Persistence probes + ServiceCreation |
| Privilege Escalation (TA0004) | T1068, T1548 | PrivEscSyscall, SudoElevation, SudoSuspicious, SUIDBitChange |
| Defense Evasion (TA0005) | T1014, T1036, T1070, T1222, T1562 | KernelModuleLoad, LongLivedProcess, AuditTamper, FilePermTamper |
| Credential Access (TA0006) | T1110, T1552, T1556 | SSHBruteForce (×2), PasswordSpray, FTPCleartext, CleartextCreds |
| Discovery (TA0007) | T1018, T1046, T1083, T1590, T1592 | ARP, PortScan, SyscallFlood, InternalRecon |
| Lateral Movement (TA0008) | T1021 | LateralSMBWinRM, SSHBruteForce, RDPSuspicious |
| Collection (TA0009) | T1056 | HIDKeyboardMouseAnomaly |
| Command & Control (TA0011) | T1071, T1090, T1205, T1568, T1572, T1573 | C2Beacon, DNSTunneling, SuspiciousTunnel, DGA, FastFlux, TLSAnomaly |
| Exfiltration (TA0010) | T1041, T1048, T1052 | DataExfilVolumeSpike, DNSTunneling, USBStorage |
| Impact (TA0040) | T1496, T1499, T1565 | HighCPUMemory, AccountLockoutStorm, WorldWritableSensitive |

### Validation Status

- **Unit tested (threat_detection.py patterns):** 6 detector classes covering ~20 techniques
- **Probe-level tested (probes.py):** Partial — probe unit tests exist for auth, dns, fim, flow, kernel_audit, persistence, proc
- **End-to-end validated (agent → queue → decode):** 0 techniques (no threat events with MITRE data observed due to GAP-01)

---

## 5. Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    Agent (V2)                                │
│                                                             │
│  Collector ──→ ProbeContext ──→ MicroProbes ──→ TelemetryEvent │
│                                      │                      │
│                              collect_data() returns list    │
│                                      │                      │
│              run() loop: enqueue via queue_adapter           │
│                                      │                      │
│  _maybe_emit_metrics_telemetry() ──→ queue_adapter.enqueue() │
└──────────────────────────────┬──────────────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │  LocalQueueAdapter   │
                    │  _dict_to_telemetry()│ ← GAP-01: loses probe data
                    │  generate idem_key   │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  LocalQueue (SQLite) │
                    │  WAL mode           │
                    │  Table: queue       │
                    │  Cols: id, idem,    │
                    │    ts_ns, bytes,    │
                    │    retries          │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  EventBus (gRPC)    │ ← drain path (not tested locally)
                    │  Dedup cache        │
                    │  Overload control   │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  FusionEngine       │ ← GAP-04: no e2e test
                    │  Rules + AdvRules   │
                    │  → Incidents        │
                    │  → DeviceRisk       │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  ScoreJunction      │ ← GAP-05: no tests
                    │  → ThreatScore      │
                    │  → Alerts           │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  Explanation Gen    │ ← GAP-06: doesn't exist yet
                    │  → Evidence Bundle  │
                    └─────────────────────┘
```

---

## 6. Storage Format Analysis

### Queue SQLite Schema
```sql
CREATE TABLE queue (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  idem TEXT NOT NULL,          -- idempotency key
  ts_ns INTEGER NOT NULL,     -- nanosecond timestamp
  bytes BLOB NOT NULL,         -- serialized DeviceTelemetry protobuf
  retries INTEGER DEFAULT 0
);
CREATE UNIQUE INDEX queue_idem ON queue(idem);
CREATE INDEX queue_ts ON queue(ts_ns);
```

### Empirical Size Data (from Mac Lab run)

| Queue | Rows | Total Payload Bytes | Avg Bytes/Row | Format |
|-------|------|-------------------|---------------|--------|
| kernel_audit | 3 | 620 | ~207 | Protobuf (metrics only) |
| protocol_collectors | 11 | 1,246 | ~113 | Protobuf (threats + metrics) |
| device_discovery | 3 | 616 | ~205 | Protobuf (metrics only) |

Observation: Protobuf overhead is minimal. Metrics events average ~200 bytes. Threat events are ~113 bytes (smaller because they carry fewer populated fields — ironic evidence of GAP-01).
