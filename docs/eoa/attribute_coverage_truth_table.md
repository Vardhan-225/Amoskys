# AMOSKYS Attribute Coverage Truth Table

> **Purpose:** For each of the 63 probes, verify whether the macOS collector
> actually populates every field the probe reads. A probe is **REAL** only when
> every field it depends on carries live data. A single phantom field can blind
> the entire probe.

---

## Verdict Key

| Grade | Meaning |
|-------|---------|
| **REAL** | Every field the probe reads is populated by the macOS collector with accurate, live data. Probe can fire in production. |
| **DEGRADED** | Field is populated, but the value is inaccurate or semantically wrong (e.g., per-process bytes assigned to per-flow). Probe fires, but with wrong thresholds. |
| **BROKEN** | A critical field the probe reads is hardcoded/stubbed/None. The probe **can never fire** on macOS. |
| **PARTIAL** | Core detection works, but enrichment fields (process context, etc.) are missing. Detection fires, but investigation is impaired. |

---

## Executive Summary

| Agent | Probes | REAL | DEGRADED | BROKEN | PARTIAL |
|-------|--------|------|----------|--------|---------|
| **Proc** | 8 | **8** | 0 | 0 | 0 |
| **FIM** | 8 | **6** | 0 | 0 | 2 |
| **Flow** | 8 | **5** | 2 | **1** | 0 |
| **DNS** | 9 | **2** | 2 | **4** | 1 |
| **Auth** | 8 | **7** | 0 | 0 | 1 |
| **Persistence** | 7 | **7** | 0 | 0 | 0 |
| **Peripheral** | 4 | **4** | 0 | 0 | 0 |
| **KernelAudit** | 7 | **5** | 0 | 0 | 2 |
| **TOTAL** | **59** | **44** | **4** | **5** | **6** |

**Honest coverage: 44/59 probes (74.6%) are REAL — not 98%.**

The scorecard showed 98.4% "surface coverage" which just counted probes with
`"darwin" in platforms`. That's a lie. This table counts probes where the
data pipeline actually works end-to-end.

---

## 1. PROC AGENT (8/8 REAL)

**Collector:** `psutil.process_iter()` — native, cross-platform, rich fields.

Each probe calls psutil directly inside its `scan()` method — no shared_data
intermediary. All fields (pid, name, exe, cmdline, username, ppid, cpu_percent,
memory_percent, create_time) are natively populated by psutil on macOS.

| Probe | Fields Read | Collector Populates | Verdict |
|-------|------------|-------------------|---------|
| process_spawn | pid, name, exe, cmdline, username, ppid, create_time | All via psutil | **REAL** |
| lolbin_execution | name, exe, cmdline, ppid | All via psutil | **REAL** |
| process_tree_anomaly | name, exe, cmdline, ppid, parent chain | All via psutil | **REAL** |
| high_cpu_memory | pid, name, cpu_percent, memory_percent | All via psutil | **REAL** |
| long_lived_process | pid, name, create_time | All via psutil | **REAL** |
| suspicious_user_process | pid, name, username | All via psutil | **REAL** |
| binary_from_temp | pid, name, exe, cmdline | All via psutil | **REAL** |
| script_interpreter | pid, name, exe, cmdline, ppid | All via psutil | **REAL** |

**No gaps.** psutil is the gold standard for process data on macOS.

---

## 2. FIM AGENT (6 REAL, 2 PARTIAL)

**Collector:** Baseline engine (`os.walk()` + `os.stat()` + `hashlib`) + FSEvents watcher.

`FileState.from_path()` populates: path, size, mode, uid, gid, mtime, sha256, is_dir.
These are all real on macOS via `os.stat()` + `hashlib.sha256()`.

The **FSEvents collector** sets `old_state=None` for newly created/modified files
(it only knows "something changed", not what the old state was).

| Probe | Critical Fields | Collector Status | Verdict |
|-------|----------------|-----------------|---------|
| critical_system_file_change | path, change_type, old_state.sha256, new_state.sha256 | All populated by baseline diff | **REAL** |
| suid_bit_change | new_state.mode (has_suid/has_sgid), old_state.mode | All populated by os.stat() | **REAL** |
| service_creation | path (startswith persistence dirs), change_type | All populated | **REAL** |
| webshell_drop | path (web root check), file content (read binary) | All populated; reads actual file | **REAL** |
| config_backdoor | path (sshd_config/sudoers check), file content | All populated; reads actual file | **REAL** |
| library_hijack | path (ld.so.preload, .so in /lib), change_type | All populated | **REAL** |
| bootloader_tamper | path (/boot/*), change_type, change details | Populated by baseline; **macOS uses /System/Library/CoreServices for bootloader, not /boot** | **PARTIAL** — probe watches /boot (Linux), not macOS boot paths |
| world_writable_sensitive | new_state.mode (is_world_writable), old_state.mode | All populated; **but FSEvents-only changes have old_state=None**, so the "was NOT world-writable before" check can false-negative | **PARTIAL** — FSEvents path lacks old_state for permission delta |

### FIM Gaps:
1. **bootloader_tamper**: Watches `/boot` which doesn't exist on macOS. Should watch `/System/Library/CoreServices/boot.efi` and `/usr/standalone/firmware/`.
2. **world_writable_sensitive via FSEvents**: When a file permission changes between baseline scans, FSEvents catches it but `old_state=None`. The probe checks `old_world_writable = change.old_state.is_world_writable() if change.old_state else False`. This defaults to "wasn't world-writable before" which is correct behavior (will fire), but only if baseline engine also catches it. **Low risk.**

---

## 3. FLOW AGENT (5 REAL, 2 DEGRADED, 1 BROKEN)

**Collector:** `lsof -i -P -n` (connections) + `nettop` (byte counts per process).

lsof provides: src_ip, dst_ip, src_port, dst_port, protocol, connection state, PID.
nettop provides: per-process bytes_in and bytes_out (aggregate, not per-flow).

| Probe | Critical Fields | Collector Status | Verdict |
|-------|----------------|-----------------|---------|
| port_scan_sweep | src_ip, dst_ip, dst_port | lsof: all real | **REAL** |
| lateral_smb_winrm | src_ip, dst_ip, dst_port, is_internal() | lsof: all real | **REAL** |
| data_exfil_volume_spike | dst_ip, direction, **bytes_tx** | nettop gives per-PROCESS total, but probe sums per-FLOW. If Safari has 3 flows, all 3 get Safari's full byte total → 3x inflation | **DEGRADED** |
| c2_beacon_flow | src_ip, dst_ip, first_seen_ns, **bytes_tx+bytes_rx** | Timing: real. **Bytes**: per-process aggregate means avg_bytes_per_flow is always huge → probe's ≤5KB check will almost never pass on real C2 | **DEGRADED** |
| cleartext_credential_leak | dst_port, is_internal() | lsof: all real | **REAL** |
| suspicious_tunnel | protocol, dst_port, **duration_seconds()**, **packet_count**, bytes | **duration=0** (lsof snapshot: first_seen_ns == last_seen_ns). **packet_count=1** (hardcoded). Thresholds require duration≥600s AND packet_count≥100 → **impossible** | **BROKEN** |
| internal_recon_dns_flow | src_ip, dst_port, app_protocol | lsof: all real | **REAL** |
| new_external_service | dst_ip, dst_port, is_internal(), protocol | lsof: all real | **REAL** |

### Flow Gaps:
1. **nettop per-process → per-flow mismatch**: The fundamental issue. nettop reports `Chrome.1234: bytes_in=500MB, bytes_out=200MB` — this is the process total across ALL connections. When merged into individual FlowEvents, every Chrome flow gets 200MB bytes_tx. If Chrome has 10 flows, the exfil probe sees 10 × 200MB = 2GB.
2. **lsof is a snapshot**: No duration, no packet counts, no byte counts. It captures "what connections exist right now", not "what happened between scans".
3. **SuspiciousTunnelProbe**: Architecturally impossible with lsof+nettop. Needs either `pcap` (packet capture), `dtrace`, or the macOS Network Extension framework.

---

## 4. DNS AGENT (2 REAL, 2 DEGRADED, 4 BROKEN, 1 PARTIAL)

**Collector:** `log show --predicate 'process == "mDNSResponder"'` → parse eventMessage.

This is the weakest collector. The mDNSResponder log line is parsed via simple
string splitting looking for the word "for". Critical fields are hardcoded:

| Field | Probe Needs | Collector Provides | Status |
|-------|------------|-------------------|--------|
| domain | FQDN string | Extracted from log | OK (fragile parsing) |
| query_type | A, AAAA, TXT, MX, CNAME | **Hardcoded "A"** | STUBBED |
| response_code | NXDOMAIN, NOERROR, SERVFAIL | **Hardcoded "NOERROR"** | STUBBED |
| response_ips | List of resolved IPs | **Always empty []** | NOT POPULATED |
| process_name | Which process made the query | **Always None** | NOT POPULATED |
| process_pid | PID of querying process | **Always None** | NOT POPULATED |
| timestamp | Query time | From log timestamp (fallback: now()) | UNRELIABLE |
| ttl | DNS TTL value | **Hardcoded 0** | NOT POPULATED |

| Probe | Critical Fields | What's Missing | Verdict |
|-------|----------------|---------------|---------|
| raw_dns_query | domain, query_type, process_name | query_type=A always, process=None | **DEGRADED** — fires but data incomplete |
| dga_score | domain (entropy calculation) | None — only needs domain string | **REAL** |
| beaconing_pattern | domain, timestamp, process_name | timestamp: unreliable (may be now()). process_name: None | **DEGRADED** — timing intervals may be wrong |
| suspicious_tld | domain | None — only needs domain string | **REAL** |
| nxdomain_burst | **response_code** (== "NXDOMAIN") | response_code hardcoded "NOERROR" | **BROKEN** — condition never true |
| large_txt_tunneling | **query_type** (== "TXT" or "NULL") + domain | query_type hardcoded "A" — TXT check fails. Subdomain length check works. | **BROKEN** (TXT detection dead; subdomain check alive) |
| fast_flux_rebinding | domain, **response_ips** | response_ips always empty [] | **BROKEN** — no IPs to compare |
| new_domain_for_process | domain, **process_name** | process_name always None → `if not query.process_name: continue` skips all | **BROKEN** — always short-circuits |
| blocked_domain_hit | domain, process_name, process_pid | domain: OK. process_name/pid: None | **PARTIAL** — detects blocked domains, can't identify which process |

### DNS Gaps — the deepest hole in our coverage:
1. **query_type hardcoded "A"**: Kills TXT tunneling detection entirely. mDNSResponder logs DO contain query type info but the parser ignores it.
2. **response_code never set**: Kills NXDOMAIN burst detection. mDNSResponder doesn't expose response codes in the `log show` format — this data simply isn't available via unified logging.
3. **response_ips empty**: Kills fast-flux detection. DNS response IPs aren't in the mDNSResponder Query logs.
4. **process_name/pid missing**: mDNSResponder is the system resolver — it doesn't log which process made the query. This data requires a different collection method (Network Extension framework, or ES_EVENT_TYPE_NOTIFY_DNS_QUERY from Endpoint Security).

---

## 5. AUTH AGENT (7 REAL, 1 PARTIAL)

**Collector:** macOS unified log (`log show`) with broad predicate covering sudo, sshd, loginwindow, SecurityAgent, authd, coreauthd, screensaver. Plus `last` command for session history.

This is a well-implemented collector with process-specific parsers for sudo messages, sshd messages, loginwindow events, and SecurityAgent authorization dialogs.

| Probe | Critical Fields | Collector Status | Verdict |
|-------|----------------|-----------------|---------|
| ssh_bruteforce | event_type=SSH_LOGIN, status=FAILURE, source_ip, username | sshd logs parsed with specific patterns | **REAL** |
| password_spray | event_type=SSH_LOGIN, status=FAILURE, username (many distinct) | sshd logs parsed | **REAL** |
| geo_impossible_travel | source_ip, timestamp (needs GeoIP lookup) | source_ip from sshd logs; **GeoIP DB not bundled** | **PARTIAL** — data collected, but GeoIP resolution requires external DB |
| sudo_elevation | event_type=SUDO, username, command | sudo log parsing is well-implemented (V2 format) | **REAL** |
| sudo_suspicious_command | event_type=SUDO, command (regex for dangerous patterns) | Command extracted from sudo log | **REAL** |
| off_hours_login | timestamp, event_type | Timestamp from log | **REAL** |
| mfa_fatigue | event_type (MFA-related) | SecurityAgent + coreauthd parsing | **REAL** |
| account_lockout_storm | event_type=FAILURE, username (many failures) | Parsed from auth logs | **REAL** |

**Auth is solid.** The V2 collector was specifically redesigned for macOS unified logging with correct JSON key names (`processImagePath` not `process`) and proper sudo format parsing.

---

## 6. PERSISTENCE AGENT (7/7 REAL)

**Collector:** Scans actual macOS persistence locations:
- `/Library/LaunchAgents/*.plist`, `/Library/LaunchDaemons/*.plist`
- `~/Library/LaunchAgents/*.plist`
- crontab entries (`crontab -l`)
- `~/.ssh/authorized_keys`
- Shell profiles (`.bashrc`, `.zshrc`, `.bash_profile`)

Uses baseline comparison — compares current snapshot against known-good state.

| Probe | Critical Fields | Collector Status | Verdict |
|-------|----------------|-----------------|---------|
| launchd_persistence | plist path, plist content (ProgramArguments), RunAtLoad | Reads actual plists | **REAL** |
| cron_persistence | crontab entries, @reboot patterns | Parses crontab -l output | **REAL** |
| ssh_key_backdoor | authorized_keys content, forced commands | Reads actual file | **REAL** |
| shell_profile_hijack | .bashrc/.zshrc content, suspicious patterns | Reads actual files | **REAL** |
| browser_extension | extension manifest.json, permissions | Reads actual manifests | **REAL** |
| hidden_file_persistence | Hidden executable files (dot-prefix) | File enumeration | **REAL** |
| startup_login_item | Login items, LaunchAgent plists | Reads actual plists | **REAL** |

**No gaps.** Persistence probes read actual filesystem state on macOS.

---

## 7. PERIPHERAL AGENT (4/4 REAL)

**Collector:** `system_profiler SPUSBDataType -json` for USB devices, `system_profiler SPBluetoothDataType -json` for Bluetooth.

| Probe | Critical Fields | Collector Status | Verdict |
|-------|----------------|-----------------|---------|
| usb_storage | USB vendor, product, serial, media type | system_profiler JSON | **REAL** |
| usb_hid | USB device class (HID devices) | system_profiler JSON | **REAL** |
| bluetooth_new_device | BT device name, address, connected status | system_profiler JSON | **REAL** |
| peripheral_policy | All device fields vs policy rules | system_profiler JSON | **REAL** |

**No gaps.** system_profiler provides comprehensive device data on macOS.

---

## 8. KERNEL AUDIT AGENT (5 REAL, 2 PARTIAL)

**Collector:** `praudit -x /var/audit/current` → XML parsing → KernelAuditEvent.

OpenBSM provides: event type, timestamp, uid, euid, gid, egid, pid, exe path,
file paths, exec_args, return values. Missing: ppid, cwd, dest_pid.

| Probe | Critical Fields | Collector Status | Verdict |
|-------|----------------|-----------------|---------|
| execve_high_risk | syscall, exe/path, uid, euid | All from BSM subject + exec_args | **REAL** |
| privesc_syscall | syscall (setuid etc.), result, uid, euid | All from BSM subject + return | **REAL** |
| kernel_module_load | syscall (init_module), path, uid, cwd | path: yes. **cwd: None** (BSM doesn't provide). uid: yes | **PARTIAL** — cwd check for suspicious module paths dead-code |
| ptrace_abuse | syscall (ptrace), pid, comm, **dest_pid** | pid/comm: yes. **dest_pid: None** (BSM doesn't provide target PID in subject token) | **PARTIAL** — can't determine ptrace target |
| file_permission_tamper | syscall (chmod/chown), path, uid, euid | All from BSM path + subject tokens | **REAL** |
| audit_tamper | syscall, path (audit files), comm, uid | All from BSM | **REAL** |
| syscall_flood | pid, syscall count, result (failed/success) | All from BSM | **REAL** |

### KernelAudit Gaps:
1. **ppid=None**: BSM `<subject>` token doesn't include parent PID. Process tree analysis limited.
2. **cwd=None**: BSM doesn't provide current working directory. KernelModuleLoadProbe's `_path_starts_with_any(ke.cwd, SUSPICIOUS_MODULE_PATHS)` is dead code.
3. **dest_pid=None**: BSM doesn't provide the target PID for ptrace. PtraceAbuseProbe can detect that ptrace happened but can't identify what was traced.

---

## Critical Gap Summary — What Must Be Fixed

### Priority 1: DNS Collector Rewrite (4 BROKEN probes)

The DNS collector is the single biggest hole. 4 of 9 probes are completely
non-functional. The root cause: mDNSResponder unified logs don't carry
the fields probes need.

**Fix options (in order of capability):**
1. **NetworkExtension framework** — DNS proxy extension sees all queries with
   full metadata (query type, response, originating process). Requires entitlement.
2. **Endpoint Security ES_EVENT_TYPE_NOTIFY_DNS_QUERY** — Available since macOS 13.
   Provides domain, query type, process info. Requires ES entitlement + root.
3. **pcap on port 53** — Captures raw DNS packets. Parse with dns.message.
   Gets query type, response code, response IPs. No process info.
4. **Enhanced mDNSResponder parsing** — Parse query type from log message
   (partial fix for TXT tunneling). Won't fix response_code or IPs.

### Priority 2: Flow Collector Enhancement (1 BROKEN, 2 DEGRADED)

**SuspiciousTunnelProbe (BROKEN):** Needs duration + packet counts.
- Fix: Track connections across cycles (remember first_seen_ns from previous scan,
  update last_seen_ns on re-observation). Increment packet_count each time the
  same (src, dst, port) tuple is seen.

**DataExfil + C2Beacon (DEGRADED):** nettop per-process bytes ≠ per-flow bytes.
- Fix: Use `nettop -P -L 1 -J bytes_in,bytes_out,interface -x` with per-interface
  breakdown, OR use `dtrace` to get per-socket byte counts, OR track flow-level
  deltas across cycles (current nettop total minus previous total ÷ number of flows).

### Priority 3: KernelAudit Enrichment (2 PARTIAL)

**ppid, cwd, dest_pid**: Not available in BSM.
- Fix: Cross-reference with psutil at event time: when we see a BSM event for PID X,
  look up `psutil.Process(X).ppid()`, `.cwd()`. For ptrace, the target PID may be
  in the `exec_args` or `arg` tokens — need deeper BSM parsing.

### Priority 4: FIM macOS Boot Path (1 PARTIAL)

**bootloader_tamper**: Watches `/boot` (Linux path).
- Fix: Add macOS paths: `/System/Library/CoreServices/boot.efi`,
  `/usr/standalone/firmware/`, `/System/Volumes/Preboot/`.

---

## The Honest Numbers

| Metric | Scorecard Claim | Truth |
|--------|----------------|-------|
| Surface Coverage (darwin-declared probes) | 98.4% | 98.4% (this number is real) |
| **Attribute Coverage (fields actually populated)** | Not measured | **74.6%** (44/59 probes fully functional) |
| **Effective Detection (REAL + PARTIAL)** | Not measured | **84.7%** (50/59 probes fire at all) |
| **BROKEN probes (never fire)** | 0 claimed | **5 probes** are phantom |
| **DEGRADED probes (fire incorrectly)** | 0 claimed | **4 probes** have accuracy issues |

---

## Corrective Action Priority Matrix

| Fix | Probes Unblocked | Effort | Impact |
|-----|-----------------|--------|--------|
| DNS collector rewrite (pcap or ES) | 4 BROKEN → REAL | HIGH | +6.8% coverage |
| Flow connection tracking (stateful) | 1 BROKEN → REAL | MEDIUM | +1.7% coverage |
| nettop per-flow byte estimation | 2 DEGRADED → REAL | MEDIUM | accuracy fix |
| KernelAudit psutil enrichment | 2 PARTIAL → REAL | LOW | enrichment fix |
| FIM macOS boot paths | 1 PARTIAL → REAL | LOW | +1.7% coverage |
| DNS timestamp verification | 1 DEGRADED → REAL | LOW | accuracy fix |

**After all fixes: 59/59 probes REAL = 100% attribute coverage.**
