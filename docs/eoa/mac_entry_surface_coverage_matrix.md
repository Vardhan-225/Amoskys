# AMOSKYS — Mac Entry Surface Coverage Matrix

> **Date:** 2026-02-17  
> **Platform:** macOS (Darwin / Apple Silicon)  
> **Purpose:** Map every attacker entry surface to the signals AMOSKYS can (and cannot) observe.  
> **Principle:** _"If the nervous system drops signals or can't feel half the body, smart fusion is just poetry on an empty page."_

---

## Non-Negotiable Properties of Robust Observability

| # | Property | Definition | Current Status |
|---|----------|-----------|----------------|
| 1 | **Coverage** | Every major attacker entry surface produces telemetry | ✅ 7/7 core surfaces covered (see map below) |
| 2 | **Continuity** | Heartbeat + change events emitted every cycle | ✅ All 7 agents emit METRIC heartbeats |
| 3 | **Losslessness** | At-least-once durability on-device (SQLite WAL queue) | ✅ LocalQueueAdapter + idempotency keys |
| 4 | **Integrity** | Tamper-evident envelopes (signing + hash chain) | 🟡 Proto has `sig`/`prev_sig`/`signing_algorithm` — **not yet wired** |
| 5 | **Reproducibility** | Every SECURITY event → raw evidence fields, timestamps, provenance | ✅ `attributes` map + `source_component` + `event_timestamp_ns` |

---

## Entry Surface Map

The device is **7 attack surfaces**, not 9 agents. Agents are implementations.

| # | Entry Surface | What Must Be Visible | Agent | Collector | Mac Status | Depth |
|---|---------------|---------------------|-------|-----------|------------|-------|
| 1 | **Execution** | process spawn, cmdline, parent/child, binary path, interpreter | ProcAgent V3 | psutil (live) | ✅ **STRONG** | User-space |
| 2 | **Persistence** | LaunchAgents/Daemons, cron, shell profiles, login items, SSH keys | PersistenceGuard V2 | plistlib + crontab + hashlib | ✅ **STRONG** | User-space |
| 3 | **Filesystem** | file drops, modifications, permission flips, new executables | FIMAgent V2 | os.walk + hashlib (diff) | ✅ **WORKING** | User-space |
| 4 | **Network (DNS)** | DNS queries, resolution, domain intelligence | DNSAgent V2 | `log show` mDNSResponder | ✅ **WORKING** | Unified log |
| 5 | **Network (Flow)** | TCP/UDP connections, listening ports, outbound beacons, lateral movement | FlowAgent V2 | MacOSFlowCollector (`lsof -i -n -P`) | ✅ **WORKING** | User-space |
| 6 | **Auth** | sudo, SSH, local logins, failed attempts, privilege changes | AuthGuard V2.1 | MacOSAuthLogCollector V2.1 (`log show` broad predicate + `last`) | ✅ **WORKING** | Unified log + last |
| 7 | **Peripheral** | USB insertion, HID injection, storage, network adapters, Bluetooth | PeripheralAgent V2 | system_profiler SPUSBDataType | ✅ **WORKING** | User-space |
| 8 | **Kernel** | syscalls, module loads, ptrace/injection, privilege escalation | KernelAudit V2 | AuditdLogCollector (Linux only) | 🔴 **BLIND** | — |
| 9 | **Discovery** | ARP/network device enumeration, rogue DHCP, shadow IT | DeviceDiscovery V2 | ARP cache + port scan | 🟡 **UNTESTED** | User-space |

**Verdict: 7 of 7 core surfaces have working signal on macOS. Kernel (#8) is blind, Discovery (#9) is untested.**

---

## Surface-by-Surface Deep Dive

### Surface 1: Execution — ✅ STRONG

**Agent:** `ProcAgent V3` (`src/amoskys/agents/proc/proc_agent_v3.py`)

| Signal | Collected | Source | Enrichment |
|--------|-----------|--------|------------|
| Process spawn (pid, ppid, cmdline) | ✅ | psutil.process_iter() | ✅ binary path, username, create_time |
| Binary path + hash | ✅ | psutil exe() | ⚠️ Hash not computed (add sha256 of exe) |
| Parent-child tree | ✅ | psutil ppid() | ✅ Parent name, anomaly detection |
| Interpreter usage (python, bash, perl) | ✅ | Script interpreter probe | ✅ T1059 sub-techniques |
| LOLBin abuse | ✅ | Curated LOLBin list | ✅ T1218 sub-techniques |
| User context (uid, username) | ✅ | psutil uids() | ✅ Suspicious user probe |
| Execution from temp dirs | ✅ | Binary path check | ✅ T1204 |
| Resource abuse (crypto mining) | ✅ | CPU/memory thresholds | ✅ T1496 |

**Probes (8/8 macOS-active):**

| Probe | MITRE | EOA Fired | Evidence Fields |
|-------|-------|-----------|-----------------|
| `process_spawn` | T1059, T1204 | ✅ | pid, ppid, name, cmdline, exe, username, create_time |
| `lolbin_execution` | T1218, T1218.010, T1218.011 | ✅ | pid, name, cmdline, exe, lolbin_match |
| `suspicious_user_process` | T1078 | ✅ | pid, username, exe, reason |
| `binary_from_temp` | T1204, T1059 | ✅ | pid, exe, temp_dir |
| `script_interpreter` | T1059.001/.003/.004/.006 | ❌ (silent) | pid, interpreter, script_path |
| `process_tree_anomaly` | T1055, T1059 | ❌ (silent) | pid, ppid, parent_name, child_name, anomaly |
| `high_cpu_memory` | T1496 | ❌ (silent) | pid, cpu_pct, memory_pct |
| `long_lived_process` | T1036 | ❌ (silent) | pid, name, uptime_hours |

**Gaps:**
- No `codesign` verification (macOS code signature status)
- No process GUID (cross-event correlation key)
- No exe SHA-256 hash (binary provenance)
- No working directory capture

**Next sensor hooks:**
```
# Enrichment additions to ProcAgent V3
- subprocess.run(["codesign", "-dvvv", exe_path]) → signed/unsigned/invalid
- hashlib.sha256(open(exe_path, "rb").read()) → binary_hash attribute
- psutil.Process.cwd() → working_dir attribute
- uuid.uuid4() → process_guid (per-spawn correlation key)
```

---

### Surface 2: Persistence — ✅ STRONG

**Agent:** `PersistenceGuard V2` (`src/amoskys/agents/persistence/persistence_agent_v2.py`)

| Signal | Collected | Source | Enrichment |
|--------|-----------|--------|------------|
| LaunchAgents (user) | ✅ | ~/Library/LaunchAgents plist scan | ✅ Label, ProgramArguments, hash |
| LaunchAgents (system) | ✅ | /Library/LaunchAgents scan | ✅ Same |
| LaunchDaemons | ✅ | /Library/LaunchDaemons scan | ✅ Same |
| Cron jobs | ✅ | `crontab -l` | ✅ Content hash, line count |
| Shell profiles | ✅ | ~/.zshrc, ~/.bashrc, etc. hash | ✅ File hash, mtime, size |
| SSH authorized_keys | ✅ | ~/.ssh/authorized_keys | ✅ Key count, hash |
| Login items (GUI) | ⚠️ | Probe exists but not tested | — |
| Browser extensions | ⚠️ | Probe exists but not tested | — |
| Hidden executables | ⚠️ | Probe exists but not tested | — |

**Probes (7/8 macOS-active, systemd is Linux-only):**

| Probe | MITRE | EOA Fired | macOS |
|-------|-------|-----------|-------|
| `launchd_persistence` | T1543.001, T1037.005 | ✅ | ✅ |
| `shell_profile_hijack` | T1037.004, T1546.004 | ✅ | ✅ |
| `cron_persistence` | T1053.003 | ❌ | ✅ |
| `ssh_key_backdoor` | T1098.004 | ❌ | ✅ |
| `browser_extension_persistence` | T1176 | ❌ | ✅ |
| `startup_folder_login_item` | T1547.001, T1037.001 | ❌ | ✅ |
| `hidden_file_persistence` | T1564, T1053, T1547 | ❌ | ✅ |
| `systemd_persistence` | T1543.002 | ❌ | ❌ Linux-only |

**Gaps:**
- No macOS Login Items via `osascript` or `sfltool` (GUI autostart)
- No `launchctl list` runtime comparison (loaded vs. on-disk)
- No at-job monitoring
- No XPC service monitoring

**Next sensor hooks:**
```
# Immediate additions
- launchctl list → compare loaded services vs. plist files on disk
- osascript -e 'tell app "System Events" to get login items' → GUI login items
- ~/Library/Application Support/Google/Chrome/Default/Extensions/ → Chrome ext scan
```

---

### Surface 3: Filesystem — ✅ WORKING

**Agent:** `FIMAgent V2` (`src/amoskys/agents/fim/fim_agent_v2.py`)

| Signal | Collected | Source | Enrichment |
|--------|-----------|--------|------------|
| File creation | ✅ | os.walk + baseline diff | ✅ Path, hash |
| File modification (hash change) | ✅ | SHA-256 diff | ✅ Old hash, new hash |
| File deletion | ✅ | Baseline diff | ✅ Path |
| Permission change | ✅ | stat() mode diff | ✅ Old mode, new mode |
| Owner change | ✅ | stat() uid diff | ✅ Old owner, new owner |
| SUID/SGID bit | ✅ | Mode bit check | ✅ T1548.001 |
| Webshell patterns | ✅ | Content regex | ✅ T1505.003 |
| Config backdoors | ✅ | sshd_config/sudoers parse | ✅ T1556 |

**Probes (6/8 macOS-active):**

| Probe | MITRE | EOA Fired | macOS |
|-------|-------|-----------|-------|
| `critical_system_file_change` | T1036, T1547, T1574 | ✅ | ✅ |
| `suid_bit_change` | T1548.001, T1068 | ❌ | ✅ |
| `service_creation` | T1543, T1053 | ❌ | ✅ |
| `webshell_drop` | T1505.003 | ❌ | ⚠️ (if web roots exist) |
| `config_backdoor` | T1548, T1078, T1556 | ❌ | ✅ |
| `world_writable_sensitive` | T1565, T1070 | ❌ | ✅ |
| `library_hijack` | T1574.006, T1014 | ❌ | ❌ Linux ld.so paths |
| `bootloader_tamper` | T1542.003 | ❌ | ❌ No /boot on macOS |

**Gaps:**
- Polling-based (os.walk every N seconds) — misses rapid create+delete
- No FSEvents / kqueue real-time notification
- No extended attribute (xattr) monitoring (macOS quarantine flags)
- Watch scope must be manually configured (no auto-discovery of sensitive paths)
- No macOS Gatekeeper/quarantine flag tracking

**Next sensor hooks:**
```
# Real-time filesystem monitoring
- FSEvents API (via watchdog library) → real-time file change notification
- xattr -l <file> → quarantine bit, com.apple.provenance
- codesign -dvvv <new_binary> → signature verification for new executables
- mdls <file> → Spotlight metadata (download source, creation app)
```

---

### Surface 4: Network (DNS) — ✅ WORKING

**Agent:** `DNSAgent V2` (`src/amoskys/agents/dns/dns_agent_v2.py`)

| Signal | Collected | Source | Enrichment |
|--------|-----------|--------|------------|
| DNS queries (domain, type) | ✅ | `log show` mDNSResponder | ✅ Domain, query_type |
| Query source process | ⚠️ | Unified log has PID | Not yet extracted |
| Response data (IPs) | ❌ | Not parsed from log | — |
| NXDOMAIN responses | ❌ | Response code not captured | — |
| TXT record content | ❌ | Not captured | — |

**Probes (9/9 declared, 1 fires on baseline traffic):**

| Probe | MITRE | EOA Fired | Trigger Needed |
|-------|-------|-----------|----------------|
| `raw_dns_query` | T1071.004 | ✅ | Any DNS query |
| `dga_score` | T1568.002 | ❌ | High-entropy domain names |
| `beaconing_pattern` | T1071.004, T1573.002 | ❌ | Repeated queries at regular intervals |
| `suspicious_tld` | T1071.004 | ❌ | .tk, .top, .xyz, .buzz queries |
| `nxdomain_burst` | T1568.002, T1046 | ❌ | 50+ NXDOMAIN in short window |
| `txt_tunneling` | T1048.001, T1071.004 | ❌ | Large TXT record queries |
| `fast_flux_rebinding` | T1568.001 | ❌ | Domain resolving to rapidly-changing IPs |
| `new_domain_for_process` | T1071.004 | ❌ | First-time domain per process |
| `blocked_domain_hit` | T1071.004, T1566 | ❌ | Query to blocklisted domain |

**Gaps:**
- Unified log parsing is fragile — `log show` JSON output varies by macOS version
- No response data (IP addresses, TTL, record content)
- No per-process DNS correlation (PID from log not linked to process context)
- No passive DNS capture (pcap-level)
- Blocklist not populated (needs threat intel feed integration)

**Next sensor hooks:**
```
# Richer DNS capture
- Parse PID from unified log → link to ProcAgent process_guid
- lsof -i -n -P | grep UDP.*:53 → identify DNS resolvers in use
- dns.resolver (dnspython) for active probing / response capture
- NetworkExtension DNS proxy (requires entitlement) → full DNS interception
- Populate blocked_domain blocklist from threat intel (abuse.ch, etc.)
```

---

### Surface 5: Network (Flow) — ✅ WORKING

**Agent:** `FlowAgent V2` (`src/amoskys/agents/flow/flow_agent_v2.py`)

**Current state:** `MacOSFlowCollector` implemented using `lsof -i -n -P`. Collects 11–13 TCP/UDP connections per cycle (15s interval). 8 probes active, `new_external_service` fires on non-standard-port external connections. EOA PASS: 18 events (17 METRIC, 1 SECURITY), 2 MITRE techniques (T1041, T1595).

| Signal | Collected | Source | Status |
|--------|-----------|--------|--------|
| TCP/UDP connections | ✅ | `lsof -i -n -P` | ESTABLISHED + active UDP |
| Listening ports | ⚠️ | lsof (filtered out) | Skipped to reduce noise |
| Outbound beacons | ✅ (detection ready) | Flow probes | Needs ≥4 periodic flows |
| Lateral movement (SMB/WinRM/SSH) | ✅ (detection ready) | `lateral_smb_winrm` probe | Fires on internal admin port connections |
| Data exfiltration volume | ⚠️ | `data_exfil_volume_spike` probe | Needs byte counts (lsof limitation) |
| Cleartext credentials | ✅ (detection ready) | `cleartext_credential_leak` probe | Fires on FTP/Telnet/HTTP auth ports |
| Tunnels (SSH, VPN, SOCKS) | ✅ (detection ready) | `suspicious_tunnel` probe | Needs long-lived connections |

**Probes (8 declared, 1 fired in EOA):**

| Probe | MITRE | Status |
|-------|-------|--------|
| `port_scan_sweep` | T1046 | ✅ Ready (needs ≥20 ports to same dst) |
| `lateral_smb_winrm` | T1021.002/.003/.006 | ✅ Ready (fires on internal SSH/SMB/RDP) |
| `data_exfil_volume_spike` | T1041, T1048 | ⚠️ Limited (no byte counts from lsof) |
| `c2_beacon_flow` | T1071.001, T1071.004 | ✅ Ready (needs periodic flow pattern) |
| `cleartext_credential_leak` | T1552.001 | ✅ Ready (detects FTP/Telnet flows) |
| `suspicious_tunnel` | T1090, T1572 | ✅ Ready (needs ≥10min connection) |
| `internal_recon_dns_flow` | T1046, T1590 | ✅ Ready (needs ≥100 DNS hostnames) |
| `new_external_service` | T1041, T1595 | ✅ **FIRED** in EOA |

**Known limitations:**
- **No byte counts** — `lsof` doesn't report bytes transferred. Future: `nettop` enrichment.
- **Snapshot, not flow** — Each call is a point-in-time view, not accumulated flow stats.
- **No PID propagation** — lsof provides PID/command but not yet passed to FlowEvent.

**Future enrichment path:**
```
# Phase 2: Enhanced collection
- nettop -P -L 1 -J bytes_in,bytes_out → per-process byte counts
- Propagate PID/command from lsof into FlowEvent
- libpcap via scapy for packet-level analysis (requires elevated permissions)
```

---

### Surface 6: Auth — ✅ WORKING

**Agent:** `AuthGuard V2.1` (`src/amoskys/agents/auth/auth_guard_agent_v2.py`)

**Current state:** Complete V2.1 rewrite with broadened unified log predicate covering 7 processes (sudo, sshd, loginwindow, SecurityAgent, authd, screensaver, coreauthd) + 3 subsystems (com.apple.Authorization, com.apple.LocalAuthentication, com.apple.loginwindow.logging). Uses `--info` flag for Info-level entries, 2-minute query window with `(processID, machTimestamp)` dedup pool. `last` command as secondary login source. EOA PASS: 25 events (23 METRIC + 2 SECURITY), 1 MITRE technique (T1548.003), 1/8 probes fired.

| Signal | Collected | Source | Status |
|--------|-----------|--------|--------|
| SSH login success/failure | ✅ | `log show` sshd parser | Handles Accepted/Failed password, publickey, disconnect |
| Sudo execution (success) | ✅ | `log show` sudo parser | SUDO_EXEC with user, command, TTY |
| Sudo denied (failure) | ✅ | `log show` sudo parser | SUDO_DENIED with reason (password required, not allowed, incorrect) |
| Local login (console) | ✅ | `log show` loginwindow + `last` | USER_PROCESS for console login, `last` fallback |
| Terminal sessions | ✅ | `last` command | TERMINAL_SESSION with tty, duration |
| Screen lock/unlock | ✅ | `log show` loginwindow + screensaver | SACShieldWindowShowing, screensaver activate/lock |
| Auth prompts | ✅ | `log show` SecurityAgent | authorization succeeded/failed |
| Biometric (Touch ID) | ✅ | `log show` coreauthd | evaluate+policy biometric events |
| SSH disconnect | ✅ | `log show` sshd parser | Connection closed events |
| Keychain access | ❌ | Not collected | — |

**Probes (8/8 declared, 1 fired in EOA):**

| Probe | MITRE | EOA Fired | Trigger Needed |
|-------|-------|-----------|----------------|
| `sudo_elevation` | T1548.003 | ✅ | Interactive sudo (fires first_time_sudo_user + sudo_denied_attempt) |
| `ssh_bruteforce` | T1110, T1078 | ❌ | 5+ SSH failures in 15 min |
| `ssh_password_spray` | T1110.003 | ❌ | Failures across multiple users |
| `ssh_geo_impossible_travel` | T1078 | ❌ | SSH from different geolocations |
| `sudo_suspicious_command` | T1548, T1059 | ❌ | Sudo with dangerous commands |
| `off_hours_login` | T1078 | ❌ | Login outside business hours |
| `mfa_bypass_anomaly` | T1621 | ❌ | MFA fatigue patterns |
| `account_lockout_storm` | T1110, T1499 | ❌ | Mass lockouts |

**V2.1 fixes applied:**
1. JSON key fixed: `processImagePath` (not `process`) for binary name extraction
2. Predicate broadened from sshd+sudo only → 7 processes + 3 subsystems
3. Query window widened from 1m to 2m with dedup pool (max 10K entries)
4. Added `--info` flag to capture Info-level log entries
5. Added `last` command as fallback login source with per-line dedup
6. Fixed `setup()` dedup poisoning — clears `_seen_keys` after test collect
7. 6 dedicated parsers: sudo, sshd, loginwindow, SecurityAgent, screensaver, coreauthd

**Remaining gaps:**
- No Keychain access monitoring
- No opendirectoryd events (local account changes)
- Higher-order probes (brute force, spraying, impossible travel) need sustained attack traffic

**Next sensor hooks:**
```
# Future enrichment
- security list-keychains → keychain access monitoring
- dscl . -list /Users → local account enumeration
- opendirectoryd log events → account create/delete/modify
- GeoIP lookup on SSH source IPs for impossible travel detection
```

---

### Surface 7: Peripheral — ✅ WORKING

**Agent:** `PeripheralAgent V2` (`src/amoskys/agents/peripheral/peripheral_agent_v2.py`)

| Signal | Collected | Source | Status |
|--------|-----------|--------|--------|
| USB device inventory | ✅ | system_profiler SPUSBDataType | ✅ Every cycle |
| USB connect/disconnect | ⚠️ | Diff between snapshots | Polling-based, not event-driven |
| USB storage detection | ⚠️ | Probe exists | Needs real USB device |
| HID anomaly (BadUSB) | ⚠️ | Probe exists | Needs real USB device |
| Bluetooth devices | ⚠️ | Probe exists | Needs real BT device |
| Network adapter USB | ⚠️ | Probe exists | Needs real USB device |
| Thunderbolt/DMA | ❌ | Not collected | — |

**Gaps:**
- Polling-based (system_profiler every N seconds) — misses rapid plug/unplug
- No IOKit notification (real-time USB hotplug events)
- No Thunderbolt monitoring (DMA attack surface)
- No disk mount detection (USB storage → mounted volume)

**Next sensor hooks:**
```
# Real-time peripheral monitoring
- IOKit notifications (via PyObjC) → real-time USB/Thunderbolt hotplug
- diskutil list → mounted volumes correlation
- system_profiler SPBluetoothDataType → Bluetooth inventory
- system_profiler SPThunderboltDataType → Thunderbolt device inventory
```

---

### Surface 8: Kernel — 🔴 BLIND (on macOS)

**Agent:** `KernelAudit V2` (`src/amoskys/agents/kernel_audit/kernel_audit_agent_v2.py`)

**Current state:** All 7 probes are `platforms = ["linux"]`. The only collector is `AuditdLogCollector` which reads `/var/log/audit/audit.log` (Linux auditd). **Zero macOS capability.**

| Signal | Collected | Source | Status |
|--------|-----------|--------|--------|
| Syscall auditing | ❌ | Linux auditd only | No macOS collector |
| Kernel module loads | ❌ | Linux auditd only | No macOS collector |
| ptrace injection | ❌ | Linux auditd only | No macOS collector |
| File permission changes (kernel-level) | ❌ | Linux auditd only | No macOS collector |
| Audit system tampering | ❌ | Linux auditd only | No macOS collector |

**macOS kernel observability options:**

| Method | What It Sees | Requirements | Feasibility |
|--------|-------------|-------------|-------------|
| **EndpointSecurity.framework** | exec, open, fork, mmap, mount, signal, iokit, auth | System extension + Apple notarization | 🟡 High effort, production-grade |
| **OpenBSM audit** (`/var/audit/*`) | syscalls, exec, file access, network | `audit -s` to enable, root | ✅ Available now |
| **dtrace** | Everything (syscalls, probes, function tracing) | Root + SIP disabled (or signed) | ⚠️ Dev only |
| **es_new_client()** (C API) | Same as EndpointSecurity | System extension | 🟡 Same as ES.framework |
| **Sysdiagnose** (`sysdiagnose`) | Process, network, system state dump | Manual or scripted | ❌ Not real-time |

**Recommended path for macOS kernel surface:**
```
# Phase 1: OpenBSM audit (available now, no SIP changes)
class MacOSAuditCollector(BaseKernelAuditCollector):
    """Parse OpenBSM audit trail from /var/audit/"""
    # praudit -x /var/audit/current → XML audit events
    # Captures: execve, open, connect, chown, chmod, setuid, ptrace
    # Requires: sudo audit -s (enable auditing)

# Phase 2: EndpointSecurity.framework (production path)
- Requires system extension (notarized, Apple-approved)
- Provides real-time exec, file, mount, iokit events
- This is what commercial EDR (CrowdStrike, SentinelOne) uses
```

---

### Surface 9: Network Discovery — 🟡 UNTESTED

**Agent:** `DeviceDiscovery V2` (`src/amoskys/agents/device_discovery/device_discovery_v2.py`)

**Current state:** Agent exists with 6 probes, uses ARP cache + port scanning. Not yet EOA-tested on macOS.

| Probe | MITRE | macOS Feasibility |
|-------|-------|-------------------|
| `arp_discovery` | T1018 | ✅ `arp -a` works on macOS |
| `active_port_scan_fingerprint` | T1046 | ✅ Socket connect scan works |
| `new_device_risk` | T1200 | ✅ Risk scoring of new ARP entries |
| `rogue_dhcp_dns` | T1557.001 | ✅ `ipconfig getpacket en0` for DHCP |
| `shadow_it` | T1200 | ✅ Unauthorized device detection |
| `vulnerability_banner` | T1595 | ✅ Banner grabbing works |

**Status:** Likely Mac-ready with minimal fixes. Needs EOA run to confirm.

---

## Enrichment Checklist (per SECURITY event)

Every SECURITY event must carry enough context for an analyst to act without asking "what happened?"

| Dimension | Field | ProcAgent | Persistence | FIM | DNS | Auth | Peripheral |
|-----------|-------|-----------|-------------|-----|-----|------|------------|
| **who** | username/uid | ✅ | ✅ | ⚠️ owner | ❌ | ✅ | ❌ |
| **who** | session/process owner | ✅ pid | ❌ | ❌ | ❌ | ✅ | ❌ |
| **what** | binary/cmdline | ✅ | ✅ command | ❌ | ❌ | ✅ command/tty | ✅ device |
| **what** | hash (sha256) | ❌ **GAP** | ✅ file hash | ✅ | ❌ | ❌ | ❌ |
| **what** | codesign status | ❌ **GAP** | ❌ | ❌ | ❌ | ❌ | ❌ |
| **where** | file path | ✅ exe | ✅ path | ✅ | ❌ | ❌ | ❌ |
| **where** | working dir | ❌ **GAP** | ❌ | ❌ | ❌ | ❌ | ❌ |
| **where** | network endpoint | ❌ | ❌ | ❌ | ✅ domain | ✅ source_ip | ❌ |
| **when** | wall clock (ns) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **provenance** | agent_name | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **provenance** | probe_name | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **provenance** | agent_version | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **links** | process_guid | ❌ **GAP** | ❌ | ❌ | ❌ | ❌ | ❌ |
| **links** | file_id | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **links** | correlation_key | ❌ **GAP** | ❌ | ❌ | ❌ | ❌ | ❌ |

**Key enrichment gaps across all agents:**
1. No `process_guid` for cross-event correlation
2. No `binary_hash` (sha256 of executable) on ProcAgent
3. No `codesign` verification anywhere
4. No `working_directory` capture
5. No cross-agent correlation keys (DNS query → which process made it?)

---

## Lossless + Signed Pipeline Status

### On-Device Durability — ✅ DONE

| Component | Status | Implementation |
|-----------|--------|----------------|
| SQLite WAL queue | ✅ | `LocalQueue` with WAL journal mode |
| Idempotency keys | ✅ | `{agent}_{device_id}_{timestamp_ns}_{seq}` |
| Crash survival | ✅ | SQLite ACID guarantees |
| Max queue size | ✅ | Configurable (default 50 MB) |
| Retry with backoff | ✅ | `max_retries=10` with exponential backoff |
| Circuit breaker | ✅ | HardenedAgentBase built-in |

### Integrity — 🟡 PROTO EXISTS, NOT WIRED

| Component | Proto Field | Status |
|-----------|------------|--------|
| Envelope signature | `UniversalEnvelope.sig` | ❌ Not populated |
| Previous signature (hash chain) | `UniversalEnvelope.prev_sig` | ❌ Not populated |
| Signing algorithm | `UniversalEnvelope.signing_algorithm` | ⚠️ Set to "Ed25519" (string only) |
| Security context | `DeviceTelemetry.security` | ❌ Not populated |
| Audit event digital_signature | `AuditEvent.digital_signature` | ❌ Not populated |
| Audit event content_hash | `AuditEvent.content_hash` | ❌ Not populated |

**Implementation path:**
```
# Per DeviceTelemetry envelope, before queue insertion:
payload_bytes = device_telemetry.SerializeToString()
payload_hash = hashlib.sha256(payload_bytes).digest()
sig = ed25519_sign(agent_private_key, payload_hash)

envelope.sig = sig
envelope.prev_sig = last_sig   # hash chain
envelope.signing_algorithm = "Ed25519"

# Store (sig, prev_sig) alongside queue row
# Verify on EventBus receipt
```

**Key file for signing:** `certs/agent.ed25519` + `certs/agent.ed25519.pub` already exist in the repo.

---

## Mac Scenario Test Suite (12 Entry-Surface Scenarios)

Each scenario validates that an attack surface produces observable telemetry.

| # | Surface | Scenario | Expected Agent | Expected Probe | MITRE |
|---|---------|----------|----------------|----------------|-------|
| 1 | Execution | Binary executed from `/tmp` | ProcAgent | `binary_from_temp` | T1204 |
| 2 | Execution | `curl \| sh` pattern | ProcAgent | `lolbin_execution` + `script_interpreter` | T1059, T1218 |
| 3 | Execution | Python reverse shell string | ProcAgent | `script_interpreter` | T1059.006 |
| 4 | Persistence | New LaunchAgent plist created | PersistenceGuard | `launchd_persistence` | T1543.001 |
| 5 | Persistence | Malicious line appended to `.zshrc` | PersistenceGuard | `shell_profile_hijack` | T1546.004 |
| 6 | Persistence | New cron entry via `crontab` | PersistenceGuard | `cron_persistence` | T1053.003 |
| 7 | Filesystem | Webshell-like file dropped in watched dir | FIMAgent | `webshell_drop` | T1505.003 |
| 8 | Filesystem | `chmod 777` on sensitive file | FIMAgent | `world_writable_sensitive` | T1565 |
| 9 | DNS | 50 NXDOMAIN queries (random subdomains) | DNSAgent | `nxdomain_burst` | T1568.002 |
| 10 | DNS | High-entropy domain lookups | DNSAgent | `dga_score` | T1568.002 |
| 11 | Peripheral | USB storage inserted (if available) | PeripheralAgent | `usb_storage` | T1091 |
| 12 | Auth | Interactive `sudo ls` to generate log entry | AuthGuard | `sudo_elevation` | T1548.003 |

**Each scenario must produce:**
- ✅ Raw event(s) with evidence fields in `attributes` map
- ✅ Stored in queue with idempotency key
- ✅ MITRE technique(s) in `SecurityEvent.mitre_techniques`
- 🔜 Signed envelope with `sig`/`prev_sig` (after integrity wiring)
- 🔜 Correlation key for cross-agent linking (after enrichment)

---

## Priority Roadmap

### Phase 1: Close the Blind Spots (Flow + Auth) — ✅ COMPLETE

| Task | Surface | Status | Result |
|------|---------|--------|--------|
| ~~Implement `MacOSFlowCollector` using `lsof -i`~~ | Flow | ✅ DONE | `lsof -i -n -P`, 11–13 flows/cycle |
| ~~EOA run FlowAgent V2 with real collector~~ | Flow | ✅ DONE | 18 events, 2 MITRE, 1/8 probes |
| ~~Fix AuthGuard log predicate (broaden + fallback)~~ | Auth | ✅ DONE | V2.1: 7 processes + 3 subsystems + `last` fallback |
| ~~EOA re-run AuthGuard with interactive sudo trigger~~ | Auth | ✅ DONE | 25 events, 1 MITRE T1548.003, 1/8 probes |
| EOA run DeviceDiscovery V2 on macOS | Discovery | 🔜 Pending | — |

### Phase 2: Enrichment (Make Events Analyst-Usable)

| Task | Agents Affected | Effort |
|------|----------------|--------|
| Add `binary_hash` (sha256 of exe) to ProcAgent | Proc | 0.5 day |
| Add `codesign` verification to ProcAgent | Proc | 0.5 day |
| Add `process_guid` (UUID per spawn) to ProcAgent | Proc | 0.5 day |
| Add `working_directory` to ProcAgent | Proc | 0.5 day |
| Link DNS queries to PID/process name | DNS | 1 day |
| Add `who` (username) to FIM + Peripheral events | FIM, Peripheral | 0.5 day |

### Phase 3: Integrity (Signed Pipeline)

| Task | Effort |
|------|--------|
| Wire `sig`/`prev_sig` on UniversalEnvelope using agent.ed25519 key | 1 day |
| Add payload_hash to queue row for tamper detection | 0.5 day |
| Verify signatures on EventBus receipt | 0.5 day |
| Hash chain validation (detect dropped/reordered envelopes) | 1 day |

### Phase 4: Kernel Surface (macOS)

| Task | Effort |
|------|--------|
| Implement `MacOSAuditCollector` (OpenBSM `/var/audit/`) | 2-3 days |
| Add macOS platform support to kernel probes | 1 day |
| EOA run KernelAudit V2 on macOS | 1 day |
| (Future) EndpointSecurity.framework integration | 2-4 weeks |

---

## Verdict

AMOSKYS has **strong execution, persistence, and filesystem coverage** on macOS.
**Network flows and authentication are now covered** (Flow via `lsof`, Auth via broadened unified log + `last`).
**All 7 core attack surfaces have live signal.** The system is blind only to kernel-level events (Surface #8).

The right sequence going forward is:
1. ~~**Flow collector**~~ ✅ DONE
2. ~~**Auth fix**~~ ✅ DONE
3. **Enrichment** → make every event analyst-complete
4. **Integrity** → sign every envelope
5. **Kernel** → add depth (OpenBSM first, EndpointSecurity later)

After Phase 2 (enrichment), AMOSKYS covers **7 of 7 core surfaces with analyst-grade evidence**.
After Phase 3, the telemetry pipeline is **tamper-evident and research-defensible**.
After Phase 4, AMOSKYS achieves **full-depth macOS endpoint visibility**.
