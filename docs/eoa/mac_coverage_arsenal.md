# AMOSKYS Mac-Ready Agent Arsenal — EOA Coverage Report

> **Generated:** 2026-02-17  
> **Platform:** macOS (Darwin / Apple Silicon)  
> **EOA Version:** 1.0  
> **Methodology:** Empirical Observability Audit — 90–120s Reality Runs per agent

---

## Executive Summary

All **7 Mac-ready AMOSKYS security agents** have passed EOA Reality Runs.
Every agent uses the correct protobuf API (`SecurityEvent` sub-messages,
`attributes` map, `confidence_score`), emits heartbeat `METRIC` events for
liveness proof, tolerates missing TLS certificates, and accepts `--log-level` CLI.

| Agent | Verdict | Events | SECURITY | METRIC | MITRE | Probes Fired |
|-------|---------|--------|----------|--------|-------|--------------|
| **ProcAgent V3** | ✅ PASS | 222 | 186 | 36 | 6 | 5/8 |
| **PersistenceGuard V2** | ✅ PASS | 16 | 4 | 12 | 3 | 2/8 |
| **FIMAgent V2** | ✅ PASS | 10 | 1 | 9 | 2 | 1/8 |
| **DNSAgent V2** | ✅ PASS | 20 | 6 | 14 | 1 | 1/9 |
| **PeripheralAgent V2** | ✅ PASS | 33 | 11 | 22 | 1 | 1/7 |
| **AuthGuard V2.1** | ✅ PASS | 25 | 2 | 23 | 1 | 1/8 |
| **FlowAgent V2** | ✅ PASS | 18 | 1 | 17 | 2 | 1/8 |
| **TOTAL** | **7/7 PASS** | **344** | **211** | **133** | **15 unique** | **12/56** |

---

## MITRE ATT&CK Coverage Matrix

### Observed in EOA Runs (15 unique techniques)

| Technique | Name | Agent(s) |
|-----------|------|----------|
| T1036 | Masquerading | FIM, Proc |
| T1041 | Exfiltration Over C2 Channel | Flow |
| T1059 | Command and Scripting Interpreter | Proc |
| T1071.004 | Application Layer Protocol: DNS | DNS |
| T1078 | Valid Accounts | Proc |
| T1200 | Hardware Additions | Peripheral |
| T1204 | User Execution | Proc |
| T1218 | System Binary Proxy Execution | Proc |
| T1218.010 | Regsvr32 | Proc |
| T1218.011 | Rundll32 | Proc |
| T1543 | Create or Modify System Process | Persistence |
| T1546.004 | Unix Shell Configuration Modification | Persistence |
| T1547 | Boot or Logon Autostart Execution | FIM, Persistence |
| T1548.003 | Sudo and Sudo Caching | Auth |
| T1595 | Active Scanning | Flow |

### Declared but Not Fired (requires specific conditions)

| Technique | Name | Agent(s) | Trigger Requirement |
|-----------|------|----------|---------------------|
| T1037.004 | Logon Script (Mac) | Persistence | Malicious shell profile patterns |
| T1037.005 | Startup Items | Persistence | New LaunchAgent with suspicious program |
| T1046 | Network Service Discovery | DNS, Flow | NXDOMAIN burst / port scan ≥20 ports |
| T1048 | Exfiltration Over Alternative Protocol | Flow | ≥50MB to single external dst |
| T1048.001 | Exfiltration Over Symmetric Encrypted Non-C2 Protocol | DNS | Large TXT DNS records |
| T1053.003 | Scheduled Task/Job: Cron | Persistence | New cron entry |
| T1055 | Process Injection | Proc | Abnormal parent-child tree |
| T1059.001 | PowerShell | Proc | PowerShell invocation |
| T1059.003 | Windows Command Shell | Proc | cmd.exe-like invocation |
| T1059.004 | Unix Shell | Proc | Suspicious shell spawning |
| T1059.006 | Python | Proc | Python script invocation |
| T1068 | Exploitation for Privilege Escalation | FIM | SUID/SGID bit change |
| T1071 | Application Layer Protocol | Flow | C2 beaconing (periodic small flows) |
| T1090 | Proxy | Flow | Long-lived tunnel ≥10min |
| T1091 | Replication Through Removable Media | Peripheral | USB storage connected |
| T1098.004 | SSH Authorized Keys | Persistence | authorized_keys modified |
| T1110 | Brute Force | Auth | SSH login failures >5 in 15min |
| T1110.003 | Password Spraying | Auth | Failures across many users |
| T1176 | Browser Extensions | Persistence | Suspicious browser extension |
| T1496 | Resource Hijacking | Proc | High CPU+memory process |
| T1499 | Endpoint Denial of Service | Auth | Mass account lockouts |
| T1505.003 | Web Shell | FIM | PHP/JSP file in web root |
| T1021 | Remote Services | Flow | Lateral SSH/SMB/RDP/WinRM |
| T1543.001 | Launch Agent | Persistence | New LaunchAgent plist |
| T1543.002 | Systemd Service | Persistence | ❌ Linux only |
| T1548 | Abuse Elevation Control Mechanism | Auth, FIM | Sudo patterns / sshd config |
| T1548.001 | Setuid and Setgid | FIM | SUID bit added |
| T1552 | Unsecured Credentials | Flow | FTP/Telnet/HTTP cleartext auth |
| T1556 | Modify Authentication Process | FIM | sshd_config backdoor |
| T1557 | Adversary-in-the-Middle | Peripheral | USB network adapter |
| T1564 | Hide Artifacts | Persistence | Hidden file executable |
| T1565 | Data Manipulation | FIM | Sensitive file world-writable |
| T1566 | Phishing | DNS | Blocked domain hit |
| T1568.001 | Fast Flux DNS | DNS | Rapid IP rotation |
| T1568.002 | Domain Generation Algorithms | DNS | High-entropy domain |
| T1572 | Protocol Tunneling | Flow | Long-lived tunnel ≥100 packets |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | DNS | Beaconing pattern |
| T1574.006 | Dynamic Linker Hijacking | FIM | ld.so.preload modified |
| T1590 | Gather Victim Network Information | Flow | ≥100 DNS hostnames in 10min |
| T1621 | Multi-Factor Authentication Request Generation | Auth | MFA fatigue/bypass |
| T1056.001 | Keylogging | Peripheral | New keyboard HID |

**Total MITRE coverage: 56 techniques across 7 agents** (15 observed, 41 declared)

---

## Agent Detail Cards

### 1. ProcAgent V3 — Process Monitoring

| Property | Value |
|----------|-------|
| **Source file** | `src/amoskys/agents/proc/proc_agent_v3.py` |
| **Collector** | psutil (live process enumeration) |
| **Probes** | 8 (all macOS-active) |
| **EOA Duration** | 120s |
| **Events** | 222 (36 METRIC, 186 SECURITY) |
| **MITRE** | T1059, T1078, T1204, T1218, T1218.010, T1218.011 |
| **Probes fired** | process_spawn, lolbin_execution, suspicious_user_process, binary_from_temp, system_metrics |
| **RSS** | 4,000–62,848 KB |
| **Notes** | Highest event volume. LOLBin probe fires frequently on macOS. |

### 2. PersistenceGuard V2 — Autostart Monitoring

| Property | Value |
|----------|-------|
| **Source file** | `src/amoskys/agents/persistence/persistence_agent_v2.py` |
| **Collector** | plistlib + crontab + hashlib (snapshot/diff) |
| **Probes** | 8 (7 macOS-active, systemd is Linux-only) |
| **EOA Duration** | 120s |
| **Events** | 16 (12 METRIC, 4 SECURITY) |
| **MITRE** | T1543, T1546.004, T1547 |
| **Probes fired** | persistence_user_launch_agent, persistence_shell_profile |
| **RSS** | 3,936–52,752 KB |
| **Notes** | Auto-creates baseline on first cycle. Triggers: plist CREATE/DELETE, zshrc MODIFY. |

### 3. FIMAgent V2 — File Integrity Monitoring

| Property | Value |
|----------|-------|
| **Source file** | `src/amoskys/agents/fim/fim_agent_v2.py` |
| **Collector** | os.walk + hashlib (live filesystem scanning) |
| **Probes** | 8 (6 macOS-active, bootloader/linker Linux-centric) |
| **EOA Duration** | 120s |
| **Events** | 10 (9 METRIC, 1 SECURITY) |
| **MITRE** | T1036, T1547 |
| **Probes fired** | critical_system_file_change |
| **RSS** | 3,344–59,552 KB |
| **Notes** | Auto-creates baseline. Monitors /etc and custom paths. Heartbeat shows baseline file count. |

### 4. DNSAgent V2 — DNS Query Monitoring

| Property | Value |
|----------|-------|
| **Source file** | `src/amoskys/agents/dns/dns_agent_v2.py` |
| **Collector** | MacOSDNSCollector (log show mDNSResponder) |
| **Probes** | 9 (all macOS-active) |
| **EOA Duration** | 90s |
| **Events** | 20 (14 METRIC, 6 SECURITY) |
| **MITRE** | T1071.004 |
| **Probes fired** | raw_dns_query |
| **RSS** | 4,816–51,360 KB |
| **Notes** | Higher-order probes (DGA, beaconing, tunneling) need sustained traffic to fire. |

### 5. PeripheralAgent V2 — USB/Bluetooth Monitoring

| Property | Value |
|----------|-------|
| **Source file** | `src/amoskys/agents/peripheral/peripheral_agent_v2.py` |
| **Collector** | system_profiler SPUSBDataType |
| **Probes** | 7 (all macOS-active, but 6 need physical hardware) |
| **EOA Duration** | 120s |
| **Events** | 33 (22 METRIC, 11 SECURITY) |
| **MITRE** | T1200 |
| **Probes fired** | usb_inventory |
| **RSS** | 7,120–56,592 KB |
| **Notes** | Inventory probe fires every cycle. Connect/storage/HID probes need real USB devices. |

### 6. AuthGuard V2.1 — Authentication Monitoring

| Property | Value |
|----------|-------|
| **Source file** | `src/amoskys/agents/auth/auth_guard_agent_v2.py` |
| **Collector** | MacOSAuthLogCollector V2.1 (`log show` broad predicate + `last` fallback) |
| **Probes** | 8 (all macOS-active) |
| **EOA Duration** | 120s |
| **Events** | 25 (23 METRIC, 2 SECURITY) |
| **MITRE** | T1548.003 |
| **Probes fired** | sudo_elevation (first_time_sudo_user + sudo_denied_attempt) |
| **RSS** | 3,600–57,792 KB |
| **Notes** | V2.1 complete rewrite: broad predicate (sudo, sshd, loginwindow, SecurityAgent, authd, screensaver, coreauthd + subsystems), `processImagePath` fix, `--info` flag, 2m window with dedup pool, `last` fallback. Handles SUDO_EXEC, SUDO_DENIED, LOCAL_LOGIN, TERMINAL_SESSION, SCREEN_LOCK/UNLOCK, AUTH_PROMPT, BIOMETRIC_AUTH, SSH_DISCONNECT. |

### 7. FlowAgent V2 — Network Flow Monitoring

| Property | Value |
|----------|-------|
| **Source file** | `src/amoskys/agents/flow/flow_agent_v2.py` |
| **Collector** | MacOSFlowCollector (`lsof -i -n -P`) |
| **Probes** | 8 (all macOS-active) |
| **EOA Duration** | 120s |
| **Events** | 18 (17 METRIC, 1 SECURITY) |
| **MITRE** | T1041, T1595 |
| **Probes fired** | new_external_service |
| **RSS** | 5,808–59,744 KB |
| **Flows per cycle** | 11–13 (105 total over 120s) |
| **Notes** | Previously STUB (returned []). Now live via `lsof`. Detects new external services on non-standard ports. Lateral/exfil/C2/tunnel probes need richer traffic to fire. No byte counts from lsof (future: nettop). |

---

## Common Fixes Applied to All Agents

| Fix | Before | After |
|-----|--------|-------|
| **Proto API** | Non-existent types (`AlertData`, `DNSTelemetry`, `PeripheralTelemetry`, `ALERT`, `CopyFrom`, `tags` for MITRE) | `SecurityEvent` sub-messages + `attributes` map + `confidence_score` |
| **setup() certs** | `return False` if certs missing | `logger.warning()` — dev mode tolerant |
| **Heartbeat** | Empty `[]` when no events | Always emit `METRIC` event (proves liveness) |
| **CLI** | No log-level control | `--log-level DEBUG\|INFO\|WARNING\|ERROR` |
| **validate_event()** | `event.timestamp` (wrong field) | `event.timestamp_ns` (correct proto field) |
| **EOA registry** | Missing `cli_args` | `cli_args` with `--interval`, `--log-level DEBUG` |

---

## Probe Coverage Summary

| Agent | Total Probes | macOS Active | Fired in EOA | Silent | Fire Rate |
|-------|-------------|--------------|--------------|--------|-----------|
| Proc | 8 | 8 | 5 | 3 | 62.5% |
| Persistence | 8 | 7 | 2 | 5 | 28.6% |
| FIM | 8 | 6 | 1 | 5 | 16.7% |
| DNS | 9 | 9 | 1 | 8 | 11.1% |
| Peripheral | 7 | 7 | 1 | 6 | 14.3% |
| Auth | 8 | 8 | 1 | 7 | 12.5% |
| Flow | 8 | 8 | 1 | 7 | 12.5% |
| **TOTAL** | **56** | **53** | **12** | **41** | **22.6%** |

**Notes on silent probes:**
- Most silent probes require specific attack conditions (brute force, DGA traffic, USB insertion)
- 3 probes are platform-incompatible on macOS (systemd, bootloader, linker hijack)
- Auth probes need sustained authentication events (brute force, spraying, off-hours login) beyond basic sudo
- Higher fire rates achievable with richer trigger injection (attack simulation)

---

## Resource Usage Summary

| Agent | RSS Min (KB) | RSS Max (KB) | RSS Final (KB) | CPU Max (%) |
|-------|-------------|-------------|----------------|-------------|
| Proc | 4,000 | 62,848 | 48,496 | 0.0 |
| Persistence | 3,936 | 52,752 | 39,232 | 0.0 |
| FIM | 3,344 | 59,552 | 48,160 | 0.6 |
| DNS | 4,816 | 51,360 | 51,104 | 1.3 |
| Peripheral | 7,120 | 56,592 | 42,496 | 0.0 |
| Auth | 4,832 | 56,640 | 25,616 | 0.0 |
| Flow | 5,808 | 59,744 | 59,744 | 0.0 |

All agents stay under **65 MB RSS** and **2% CPU** — suitable for continuous background operation.

---

## Stability Summary

| Agent | Unexpected Tracebacks | Circuit Breaker Tracebacks | Loop Crashes | Decode Failures |
|-------|----------------------|---------------------------|--------------|-----------------|
| Proc | 0 | 3 | 0 | 0 |
| Persistence | 0 | 0 | 0 | 0 |
| FIM | 0 | 3 | 0 | 0 |
| DNS | 0 | 6 | 0 | 0 |
| Peripheral | 0 | 6 | 0 | 0 |
| Auth | 0 | 4 | 0 | 0 |
| Flow | 0 | 6 | 0 | 0 |
| **TOTAL** | **0** | **28** | **0** | **0** |

Circuit breaker tracebacks are **expected** (EventBus not running during EOA). Zero unexpected tracebacks across all agents.

---

## EOA Artifacts

Each agent has a canonical documentation set under `docs/eoa/<agent>/`:

| Agent | scorecard.json | fields_contract.md | sample_events.ndjson |
|-------|---------------|-------------------|---------------------|
| proc_agent | ✅ | ✅ | ✅ |
| persistence_agent | ✅ | ✅ | ✅ |
| fim_agent | ✅ | ✅ | ✅ |
| dns_agent | ✅ | ✅ | ✅ |
| peripheral_agent | ✅ | ✅ | ✅ |
| auth_agent | ✅ | ✅ | ✅ |
| flow_agent | ✅ | ✅ | ✅ |

Raw EOA results are in `results/eoa/<agent>_<timestamp>/`.

**See also:** [`mac_entry_surface_coverage_matrix.md`](mac_entry_surface_coverage_matrix.md) — full attack-surface-first coverage analysis with gaps, enrichment checklist, and priority roadmap.

---

## Next Steps

1. ~~**Close Flow blind spot**~~ ✅ **DONE** — `MacOSFlowCollector` (lsof -i -n -P), FlowAgent V2 EOA PASS (18 events, 2 MITRE, 1/8 probes)
2. ~~**Fix Auth fragility**~~ ✅ **DONE** — AuthGuard V2.1: broadened predicate (7 processes + 3 subsystems), `processImagePath` fix, `--info` flag, 2m dedup window, `last` fallback, 6 new parsers, 8 new event types. EOA PASS (25 events, 1 MITRE T1548.003, 1/8 probes)
3. **Wire envelope signing** — Populate `sig`/`prev_sig` on UniversalEnvelope at `LocalQueueAdapter.enqueue()` using agent.ed25519 key
4. **Enrichment pass** — Add binary_hash, codesign, process_guid, working_dir to ProcAgent; link DNS → PID
5. **Kernel surface** — Implement MacOSAuditCollector (OpenBSM), port kernel probes to macOS
6. **Flow enrichment** — Add nettop byte counts, propagate PID/command from lsof into FlowEvent
7. **12-scenario test suite** — Validate all entry surfaces produce observable signed telemetry
8. **CI gate** — Add EOA as pre-merge check (agent must pass 90s Reality Run to merge)
9. **Linux EOA** — Port audit to Linux (systemd, /var/log/auth.log, /proc collectors)
