# AMOSKYS Attribute Coverage Truth Table

> **Purpose:** For each of the 62 macOS-active probes, verify whether the macOS
> collector actually populates every field the probe reads. A probe is **REAL**
> only when every field it depends on carries live data. A single phantom field
> can blind the entire probe.
>
> **Revision 2** — corrected after 5-agent deep audit (Auth, Persistence,
> Peripheral, Kernel findings were too generous in v1).

---

## Verdict Key

| Grade | Meaning |
|-------|---------|
| **REAL** | Every field the probe reads is populated by the macOS collector with accurate, live data. Probe can fire in production. |
| **DEGRADED** | Field is populated, but the value is inaccurate or semantically wrong (e.g., per-process bytes assigned to per-flow, or command=None preventing pattern matching). Probe fires, but with wrong thresholds or reduced fidelity. |
| **BROKEN** | A critical field the probe reads is hardcoded/stubbed/None, OR no collector generates the required mechanism_type/event_type. The probe **can never fire correctly** on macOS. |
| **PARTIAL** | Core detection works, but enrichment fields (process context, geo, etc.) are missing. Detection fires, but investigation is impaired. |

---

## Executive Summary

| Agent | Probes | REAL | DEGRADED | BROKEN | PARTIAL |
|-------|--------|------|----------|--------|---------|
| **Proc** | 8 | **8** | 0 | 0 | 0 |
| **FIM** | 8 | **6** | 0 | 0 | 2 |
| **Flow** | 8 | **5** | 2 | **1** | 0 |
| **DNS** | 9 | **2** | 2 | **4** | 1 |
| **Auth** | 8 | **4** | 0 | **3** | 1 |
| **Persistence** | 7 | **1** | 3 | **3** | 0 |
| **Peripheral** | 7 | **5** | 2 | 0 | 0 |
| **KernelAudit** | 7 | **5** | 0 | 0 | 2 |
| **TOTAL** | **62** | **36** | **9** | **11** | **6** |

**Honest coverage: 36/62 probes (58.1%) are REAL.**

The v1 table claimed 44/59 (74.6%). That was too generous — it undercounted
Peripheral probes (4 vs actual 7), and marked Auth, Persistence probes as REAL
when their collectors don't generate the required event types or fields.

**Effective Detection (REAL + PARTIAL):** 42/62 (67.7%) fire at all.
**BROKEN:** 11/62 (17.7%) — phantom probes that never fire or always false-positive.
**DEGRADED:** 9/62 (14.5%) — fire with wrong data or reduced detection quality.

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

## 5. AUTH AGENT (4 REAL, 3 BROKEN, 1 PARTIAL)

**Collector:** macOS unified log (`log show`) with broad predicate covering sudo,
sshd, loginwindow, SecurityAgent, authd, coreauthd, screensaver. Plus `last`
command for session history.

The collector generates event types: SSH_LOGIN, SUDO_EXEC, SUDO_DENIED,
LOCAL_LOGIN, SCREEN_LOCK, SCREEN_UNLOCK, AUTH_PROMPT, BIOMETRIC_AUTH.

**It does NOT generate:** MFA_CHALLENGE, MFA_SUCCESS, ACCOUNT_LOCKED, VPN_LOGIN.

**Geo fields (src_latitude, src_longitude, src_country, src_city):** Declared in
AuthEvent dataclass but **never populated** by the collector. No GeoIP enrichment
exists.

| Probe | Critical Fields | Collector Status | Verdict |
|-------|----------------|-----------------|---------|
| ssh_bruteforce | event_type=SSH_LOGIN, status=FAILURE, source_ip, username | sshd logs parsed with specific patterns | **REAL** |
| password_spray | event_type=SSH_LOGIN, status=FAILURE, username (many distinct) | sshd logs parsed | **REAL** |
| geo_impossible_travel | source_ip, **src_latitude**, **src_longitude**, timestamp | Guard at probes.py:248: `if ev.src_latitude is not None and ev.src_longitude is not None` — since lat/lon are **always None**, zero logins enter the analysis. Probe **never fires**. | **BROKEN** — geo fields are phantom; guard skips all events |
| sudo_elevation | event_type=SUDO, username, command | sudo log parsing is well-implemented (V2 format) | **REAL** |
| sudo_suspicious_command | event_type=SUDO, command (regex for dangerous patterns) | Command extracted from sudo log | **REAL** |
| off_hours_login | timestamp, event_type (SSH_LOGIN or LOCAL_LOGIN), status, username | SSH logins: all fields real. LOCAL_LOGIN: **username stubbed as ""** in collector. Probe still fires (timestamp-based), but event data lacks identity for local logins. | **PARTIAL** — SSH works fully; local login username missing |
| mfa_bypass_anomaly | event_type=**MFA_CHALLENGE**, event_type=**MFA_SUCCESS** | Collector **never generates** MFA_CHALLENGE or MFA_SUCCESS events. `mfa_successes` set is always empty → every SSH_LOGIN SUCCESS triggers false "mfa_bypass_suspected" alert. | **BROKEN** — false-positive factory (no MFA events exist, so every login appears to bypass MFA) |
| account_lockout_storm | event_type=**ACCOUNT_LOCKED** | Collector **never generates** ACCOUNT_LOCKED events. `locked_accounts` is always empty → threshold never met. | **BROKEN** — event type not implemented in collector |

### Auth Gaps (corrected from v1):
1. **Geo enrichment completely absent**: `src_latitude`, `src_longitude`, `src_country`, `src_city` are declared in the AuthEvent dataclass but never set. The GeoImpossibleTravel probe has a correct guard (`if lat is not None and lon is not None`) that prevents it from crashing — but also prevents it from ever running.
2. **MFA event types not collected**: The macOS unified log from SecurityAgent/coreauthd doesn't map to MFA_CHALLENGE/MFA_SUCCESS event types. The collector generates AUTH_PROMPT and BIOMETRIC_AUTH instead, but the probe looks for MFA_CHALLENGE/MFA_SUCCESS specifically. Worse: since `mfa_successes` is always empty, every successful SSH login triggers a false "MFA bypass" alert.
3. **ACCOUNT_LOCKED not implemented**: macOS doesn't have a native account lockout mechanism in the same way as Active Directory. The collector would need to synthesize this from rapid failure counts, but currently doesn't.

**v1 claimed 7 REAL, 1 PARTIAL. Actual: 4 REAL, 3 BROKEN, 1 PARTIAL.**

---

## 6. PERSISTENCE AGENT (1 REAL, 3 DEGRADED, 3 BROKEN)

**Collector:** Scans actual macOS persistence locations:
- `/Library/LaunchAgents/*.plist`, `/Library/LaunchDaemons/*.plist`
- `~/Library/LaunchAgents/*.plist`
- crontab entries (`crontab -l`)
- `~/.ssh/authorized_keys`
- Shell profiles (`.bashrc`, `.zshrc`, `.bash_profile`) — **hash only, no content**

Uses baseline comparison — compares current snapshot against known-good state.

**NOT collected:** browser extensions, startup/login items, hidden files.

| Probe | Critical Fields | Collector Status | Verdict |
|-------|----------------|-----------------|---------|
| launchd_persistence | plist path, command (ProgramArguments), RunAtLoad, user | Reads XML plists correctly. **Binary plists**: plistlib parse fails silently (exception caught at pass), command field becomes empty/None. Many system plists are binary format. | **DEGRADED** — XML plists work; binary plists produce phantom command field |
| cron_persistence | crontab entries, command, @reboot patterns | Parses `crontab -l` output. Command populated (truncated to 200 chars). Core detection works. | **REAL** |
| ssh_key_backdoor | authorized_keys path, hash, **metadata["has_forced_command"]** | Collector reads file and counts keys but **never extracts forced command** from key content. `has_forced_command` field is never set in metadata. Probe can detect new keys (CREATED) but can't identify forced-command backdoors. | **DEGRADED** — new key detection works; forced-command analysis is phantom |
| shell_profile_hijack | mechanism_type=SHELL_PROFILE, **command** (pattern matching) | Collector sets `command=None` (persistence_agent_v2.py:199). Only records hash. Probe at probes.py:777: `if entry.command:` — always False. Pattern matching against MALICIOUS_PATTERNS is dead code. Probe fires MEDIUM on any change but **can never detect specific attack patterns** (curl\|bash, sudo alias, etc.). | **DEGRADED** — fires on any change (MEDIUM) but can't distinguish malicious from benign |
| browser_extension_persistence | mechanism_type=**BROWSER_EXTENSION**, permissions, publisher | Collector **never generates** BROWSER_EXTENSION entries. No browser extension paths are scanned. Probe iterates zero changes. | **BROKEN** — no collector implementation |
| startup_folder_login_item | mechanism_type=**STARTUP_ITEM**, path, command | Collector **never generates** STARTUP_ITEM entries. No login item or startup folder enumeration exists. macOS login items (SMLoginItemSetEnabled, LSSharedFileList) are not scanned. | **BROKEN** — no collector implementation |
| hidden_file_persistence | mechanism_type=**HIDDEN_FILE**, path, metadata["is_executable"] | Collector **never generates** HIDDEN_FILE entries. No hidden file scanning exists. | **BROKEN** — no collector implementation |

### Persistence Gaps (corrected from v1):
1. **Binary plist parsing fails silently**: Many macOS system plists are in binary format. `plistlib.load()` fails on these, exception is caught with `pass`, and command/args remain empty. The probe fires (CREATED/MODIFIED detected via hash change) but can't analyze the actual persistence mechanism.
2. **Shell profile content never inspected**: The collector only records the SHA256 hash of shell profiles. The `command` field is explicitly set to `None`. The probe's malicious pattern matching (curl|bash, sudo alias override, PATH hijacking to /tmp) is completely dead code.
3. **SSH forced commands not extracted**: The collector reads authorized_keys and counts lines, but never parses individual key entries for `command="..."` prefixes. This is a common SSH backdoor technique.
4. **Three mechanism types have no collector**: BROWSER_EXTENSION, STARTUP_ITEM, HIDDEN_FILE — the probes exist with full detection logic, but no collector generates entries with these mechanism types.

**v1 claimed 7/7 REAL. Actual: 1 REAL, 3 DEGRADED, 3 BROKEN.**

---

## 7. PERIPHERAL AGENT (5 REAL, 2 DEGRADED)

**Collector:** `system_profiler SPUSBDataType -json` for USB devices,
`system_profiler SPBluetoothDataType -json` for Bluetooth.

The USB collector populates: device_id (hash of vid:pid:serial), name, vendor_id,
product_id, serial_number, manufacturer, location_id, device_speed.

**Not populated:** device_class (initialized empty, never set from system_profiler),
is_authorized (always False), first_seen/last_seen (never tracked).

| Probe | Critical Fields | Collector Status | Verdict |
|-------|----------------|-----------------|---------|
| usb_inventory | device_id, name, vendor_id, product_id, manufacturer | All populated from system_profiler | **REAL** |
| usb_connection_edge | device_id, name, vendor_id, product_id, serial (new vs known) | All populated; state tracking works | **REAL** |
| usb_storage | **device_class**, name | `device_class` is **never populated** (phantom). Probe falls back to name pattern matching ("Storage", "Disk", "Flash"). Works for obviously-named devices; misses devices with generic names. | **DEGRADED** — relies on name heuristic instead of USB class code |
| usb_network_adapter | vendor_id, name | Vendor ID + name pattern matching. Both populated. | **REAL** |
| hid_keyboard_mouse_anomaly | vendor_id, product_id, name (count baseline) | All populated; count-based detection works | **REAL** |
| bluetooth_device | address, name, device_type, connected, paired | Bluetooth collector implementation is incomplete (noted in code: "Simplified"). Parsing may miss devices or produce incomplete records. | **DEGRADED** — parser incomplete for full Bluetooth device enumeration |
| high_risk_peripheral_score | name, device counts | Name-based scoring from populated fields | **REAL** |

### Peripheral Gaps:
1. **device_class phantom**: USB device class code (e.g., 0x08 for Mass Storage) is the reliable way to identify device type. system_profiler doesn't directly expose USB class codes in the JSON output. The collector initialized the field but never populates it.
2. **first_seen/last_seen not tracked**: No temporal analysis possible — can't detect "device was connected for only 30 seconds" which is a common exfil indicator.
3. **Bluetooth parser incomplete**: The code explicitly notes simplified implementation. Full parsing of paired devices, connection history, and device capabilities is not implemented.

**v1 claimed 4 probes, 4/4 REAL. Actual: 7 probes, 5 REAL, 2 DEGRADED.**

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

### Priority 2: Persistence Collector Expansion (3 BROKEN + 3 DEGRADED probes)

The persistence collector only scans 4 mechanism types (LaunchAgents, cron, shell
profiles, SSH keys) but the probe set expects 7 mechanism types.

**Missing collectors to build:**
- **Browser extension scanner**: Enumerate `~/Library/Application Support/Google/Chrome/Default/Extensions/`, `~/Library/Application Support/Firefox/Profiles/*/extensions/`. Read manifest.json for permissions.
- **Login item scanner**: Use `LSSharedFileList` or parse `~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`. Also check `osascript -e 'tell application "System Events" to get login items'`.
- **Hidden file scanner**: Walk monitored directories, flag dot-prefixed executables.

**Existing collectors to fix:**
- **Binary plist parsing**: Use `plistlib.load()` with `fmt=plistlib.FMT_BINARY` or shell out to `plutil -convert xml1 -o -`.
- **Shell profile content inspection**: Read file content into `command` field instead of just hashing.
- **SSH forced command extraction**: Parse each authorized_keys line for `command="..."` prefix.

### Priority 3: Auth Collector Gaps (3 BROKEN probes)

**GeoImpossibleTravel (BROKEN):**
- Fix: Integrate GeoIP2 database (MaxMind GeoLite2-City). Look up `source_ip` → lat/lon/city/country. Add to AuthEvent before passing to probes.

**MFABypassAnomaly (BROKEN — false-positive factory):**
- Fix option A: Map SecurityAgent AUTH_PROMPT → MFA_CHALLENGE and BIOMETRIC_AUTH → MFA_SUCCESS. This would make the probe meaningful on macOS with Touch ID.
- Fix option B: Disable the probe on macOS (no native MFA in the AD/Okta sense).

**AccountLockoutStorm (BROKEN):**
- Fix: Synthesize ACCOUNT_LOCKED events from rapid failure counts. If 5+ FAILURE events for same username in 60s, generate synthetic ACCOUNT_LOCKED.

### Priority 4: Flow Collector Enhancement (1 BROKEN, 2 DEGRADED)

**SuspiciousTunnelProbe (BROKEN):** Needs duration + packet counts.
- Fix: Track connections across cycles (remember first_seen_ns from previous scan,
  update last_seen_ns on re-observation). Increment packet_count each time the
  same (src, dst, port) tuple is seen.

**DataExfil + C2Beacon (DEGRADED):** nettop per-process bytes ≠ per-flow bytes.
- Fix: Track flow-level deltas across cycles (current nettop total minus previous
  total ÷ number of flows for that process), OR use `dtrace` for per-socket counts.

### Priority 5: KernelAudit Enrichment (2 PARTIAL)

**ppid, cwd, dest_pid**: Not available in BSM.
- Fix: Cross-reference with psutil at event time: when we see a BSM event for PID X,
  look up `psutil.Process(X).ppid()`, `.cwd()`. For ptrace, the target PID may be
  in the `exec_args` or `arg` tokens — need deeper BSM parsing.

### Priority 6: FIM macOS Boot Path (1 PARTIAL)

**bootloader_tamper**: Watches `/boot` (Linux path).
- Fix: Add macOS paths: `/System/Library/CoreServices/boot.efi`,
  `/usr/standalone/firmware/`, `/System/Volumes/Preboot/`.

---

## The Honest Numbers

| Metric | Scorecard Claim | v1 Truth Table | v2 Truth Table (this) |
|--------|----------------|----------------|----------------------|
| Surface Coverage (darwin-declared probes) | 98.4% | 98.4% | 98.4% (real) |
| **Attribute Coverage (REAL probes)** | Not measured | 74.6% (44/59) | **58.1%** (36/62) |
| **Effective Detection (REAL + PARTIAL)** | Not measured | 84.7% (50/59) | **67.7%** (42/62) |
| **BROKEN probes** | 0 claimed | 5 | **11** |
| **DEGRADED probes** | 0 claimed | 4 | **9** |
| Probes in v1 vs v2 | — | 59 | 62 (v1 undercounted Peripheral) |

### What Changed Between v1 and v2:

| Agent | v1 Assessment | v2 Assessment | Delta |
|-------|--------------|---------------|-------|
| Auth | 7 REAL, 1 PARTIAL | 4 REAL, 3 BROKEN, 1 PARTIAL | -3 REAL, +3 BROKEN |
| Persistence | 7 REAL | 1 REAL, 3 DEGRADED, 3 BROKEN | -6 REAL, +3 DEGRADED, +3 BROKEN |
| Peripheral | 4 REAL (4 probes) | 5 REAL, 2 DEGRADED (7 probes) | +3 probes discovered |

---

## Corrective Action Priority Matrix

| Fix | Probes Unblocked | Effort | Coverage Impact |
|-----|-----------------|--------|-----------------|
| Persistence collector expansion (browser ext, startup, hidden) | 3 BROKEN → REAL | HIGH | +4.8% |
| Auth collector gaps (geo, MFA mapping, lockout synthesis) | 3 BROKEN → REAL | MEDIUM | +4.8% |
| DNS collector rewrite (pcap or ES) | 4 BROKEN → REAL | HIGH | +6.5% |
| Persistence collector fixes (plist, shell content, SSH forced cmd) | 3 DEGRADED → REAL | MEDIUM | accuracy |
| Flow connection tracking (stateful) | 1 BROKEN → REAL | MEDIUM | +1.6% |
| Peripheral device_class + Bluetooth parser | 2 DEGRADED → REAL | LOW | accuracy |
| nettop per-flow byte estimation | 2 DEGRADED → REAL | MEDIUM | accuracy |
| KernelAudit psutil enrichment | 2 PARTIAL → REAL | LOW | enrichment |
| FIM macOS boot paths | 1 PARTIAL → REAL | LOW | +1.6% |
| DNS timestamp verification | 1 DEGRADED → REAL | LOW | accuracy |

**After all fixes: 62/62 probes REAL = 100% attribute coverage.**

**Minimum viable target: Fix all 11 BROKEN probes → 47/62 (75.8%) REAL.**
