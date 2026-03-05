# AMOSKYS Engineering Assessment 0.0
## Root Visibility Audit — System Integration Depth & Probe Reality

**Date:** 2026-03-04
**Auditor:** Code-level inspection + red-team harness
**Scope:** ~17 agents / ~100 probes ⚠️ (count inferred from directory listing; exact registry not enumerated)
**Harness version:** `attacker_touched_the_box.py` — 5-phase kill-chain spine, 225 adversarial cases

> **Purpose:** This document is the first engineering audit of AMOSKYS. It forces every agent and every probe to prove what it can truly see, trust, miss, and explain. No sugar-coating.

---

## Legend

| Marker | Meaning |
|--------|---------|
| ✅ | Verified — confirmed by reading code, tests, or harness output |
| ⚠️ | Inferred — reasonable from code inspection but not proven by a running test |
| ❌ | Not implemented or not tested |

**What "225/225 passing" actually means:** ✅ The red-team harness runs 225 adversarial cases against auth, kernel_audit, and proc probes using **synthetic events** (AuthEvent dicts, KernelAuditEvent dicts, psutil MagicMocks). It does **not** test real log parsers, real auditd record parsing, real FSEvents collection, real network capture, real OS permissions, or any agent outside these three. All other agents have ❌ zero red-team coverage.

**Production-fidelity definition:** An agent has _production fidelity_ when: (1) its collector is confirmed to receive events from the real OS source under real privilege, (2) its probes are validated against real-world field distributions (not just synthetic ideals), and (3) at least one adversarial case uses data captured from a real system (not constructed by hand). No agent in AMOSKYS currently meets all three criteria.

---

## Table of Contents

1. [Section A — System Integration Depth](#section-a--system-integration-depth-per-agent)
2. [Section B — Probe Reality Passports](#section-b--probe-reality-passports)
3. [Section C — Simulation Fidelity](#section-c--how-real-is-the-data-simulation-fidelity)
4. [Section D — Foundation Hardening Drills](#section-d--foundation-hardening-drills)
5. [Section E — Integration Depth Badge Summary](#section-e--integration-depth-badge-summary)
6. [Section F — Collector Truth Contracts](#section-f--collector-truth-contracts)
7. [Section G — Identity Spine Contract](#section-g--identity-spine-contract)
8. [Section H — Evidence Boundary Analysis](#section-h--evidence-boundary-analysis)
9. [Section I — Performance and Resource Contracts](#section-i--performance-and-resource-contracts)
10. [Section J — Adversary Silencing Playbook](#section-j--adversary-silencing-playbook)
11. [Section K — Standard Agent Upgrade Pack](#section-k--standard-agent-upgrade-pack)
12. [Findings Table](#findings-table)
13. [Top 10 Risks](#top-10-risks)
14. [The Honest Summary](#the-honest-summary)

---

## Section A — System Integration Depth (per agent)

### AUTH

**A1 — Attachment point**
Pull from system auth logs (macOS Unified Logging, Linux syslog/PAM). Collector parses log lines into `AuthEvent` objects and injects them at `auth_events`. The probe layer sees a pre-built list — it never touches a log file, socket, or kernel interface directly. Lowest primitive: **log line parser**, not syscall or kernel hook.

`AuthEvent` dataclass fields ✅ (confirmed in `agents/auth/probes.py`):

| Field | Type | Source |
|-------|------|--------|
| `timestamp_ns` | `int` | log timestamp, collector-assigned |
| `event_type` | `str` | `SSH_LOGIN`, `SSH_FAILURE`, `SUDO_EXEC`, `SCREEN_LOCK`, … |
| `status` | `str` | `SUCCESS` or `FAILURE` |
| `username` | `str` | authenticated or attempted username |
| `source_ip` | `str` | remote IP; empty string if local or unavailable |
| `command` | `str` | sudo command string; empty if not applicable |
| `session_id` | `str` | PAM/SSH session ID; empty if not available |
| `reason` | `str` | failure reason (`"invalid password"`, `"account locked"`, …) |
| `tty` | `str` | controlling terminal; empty if daemon login |
| `src_country` | `Optional[str]` | **enriched by agent** from GeoIP lookup — absent in raw log |
| `src_city` | `Optional[str]` | **enriched by agent** — absent in raw log |
| `src_latitude` | `Optional[float]` | **enriched by agent** — absent in raw log |
| `src_longitude` | `Optional[float]` | **enriched by agent** — absent in raw log |

**A2 — Privilege**
Needs log-read access (root or `adm` group on Linux). On macOS, Unified Logging requires a `full-disk-access` TCC entitlement ⚠️ (inferred from Apple documentation; no integration test verifies the actual entitlement check). If missing: collector returns empty `auth_events` list — probes fire 0 events, no degraded health event emitted ✅ (verified by harness: 0 events = no probe output, no health signal). **An attacker can blind this agent by revoking the TCC permission.**

**A3 — Coverage surface**
SSH logins (success/fail), sudo exec/deny, account lockouts, MFA challenges, local logins ✅. Cannot observe: PAM module tampering at the C-library level, eBPF-based credential theft that bypasses PAM, or in-memory auth that never writes a log line.

**A4 — Latency and loss**
Batch-per-cycle (10s default). `SSHPasswordSprayProbe` uses current batch only — no sliding window, no history ✅ (verified: probe counts distinct users per IP in the current `auth_events` list). In production, what arrives in a single batch depends on collector polling rate and log volume; a slow or partial collection cycle could prevent the 10-user threshold from being reached ⚠️. No dedup — duplicate log lines will cause duplicate events.

**A5 — Tamper resistance**
Log files are writable by root. No remote append-only sink ✅ (none configured or referenced in code). No signed checkpoints. An attacker with root can `> /var/log/auth.log` and erase evidence before the next collection cycle.

**A6 — Operator stories**
1. "Someone is password-spraying our SSH from a Tor exit node"
2. "A user is running sudo commands that don't match their baseline"
3. "An account was locked out 5+ times in 60 seconds"

Output: `TelemetryEvent` via WAL → FusionEngine. `correlation_group:privilege_escalation` tag on `SudoElevationProbe` ✅. No correlation tag on spray, lockout, geo-travel, or MFA probes ✅.

**Integration badge: `BRONZE`** — log-level pull, no kernel hook, no tamper resistance, geo enrichment requires a GeoIP step absent from raw logs.

---

### KERNEL_AUDIT

**A1 — Attachment point**
Linux: auditd syscall stream. macOS: BSM (Basic Security Module) via `/dev/audit`. Push model — kernel writes records, collector reads them. Lowest primitive: **audit record (syscall-level)**. This is the most real attachment in the system ✅.

**A2 — Privilege**
Root required ✅. On macOS, SIP may restrict audit rule changes even as root ⚠️. If auditd is stopped or rules are removed: the agent goes dark. An attacker with root can `auditctl -D` (delete all rules) — but `AuditTamperProbe` exists to catch this. Catch-22: it can only catch deletion if auditd is still running when deletion happens.

**A3 — Coverage surface**
Syscall events parsed by probes ✅ (confirmed by probe code): `execve`/`execveat`, `setuid`/`seteuid`/`setgid`/`capset`, `ptrace`/`process_vm_readv`/`process_vm_writev`, `init_module`, `chmod`/`chown` on sensitive paths, `open()` on credential files. ⚠️ The collector record types that are actually parsed (raw BSM vs pre-structured dict vs auditd text format) are **not explicitly specified** in collector code — the probe layer receives pre-structured `KernelAuditEvent` objects and assumes the collector has already parsed the raw kernel records. The parsing fidelity of that step is unverified.

**A4 — Latency and loss**
Event-driven (push). Backpressure: auditd has its own kernel ring buffer — if it fills, the kernel drops oldest events by default ✅ (standard Linux audit behavior). Missing metrics in AMOSKYS ❌:
- Kernel audit ring buffer occupancy
- Lost event count (kernel-side drops)
- Collector lag (wall-clock delay from syscall to probe invocation)
- Per-cycle event rate

Truth window: current scan batch only — no historical reconstruction.

**A5 — Tamper resistance**
Best of all agents. Syscall records are generated in kernel before userspace can intercept ✅. However: a rootkit kernel module can suppress audit records at the kernel level. `KernelModuleLoadProbe` catches module loading, but only if the load event wasn't itself suppressed.

**A6 — Operator stories**
1. "A process executing from /tmp just called seteuid(0)"
2. "Something ptrace-attached to sshd"
3. "A kernel module was loaded from a suspicious path"

Correlation tags — all 8 probes now carry tags ✅ (KA v0.1):

| Probe | Tag |
|-------|-----|
| `ExecveHighRiskProbe` | `correlation_group:execution` |
| `PrivEscSyscallProbe` | `correlation_group:privilege_escalation` |
| `KernelModuleLoadProbe` | `correlation_group:persistence` |
| `PtraceAbuseProbe` | `correlation_group:credential_access` |
| `FilePermissionTamperProbe` | `correlation_group:defense_evasion` |
| `AuditTamperProbe` | `correlation_group:defense_evasion` |
| `SyscallFloodProbe` | `correlation_group:defense_evasion` |
| `CredentialDumpProbe` | `correlation_group:credential_access` |

Drop detection ✅ (KA v0.1): Linux `/proc/audit_lost` polled every cycle; emits `kernel_audit_drop_detected` on increase. Zero-event health signal ✅: emits `agent_health_degraded` after 2 consecutive empty cycles.

**Integration badge: `SILVER`** — kernel-level attachment, real syscall stream, drop detection wired, all probes tagged; gaps remain: no tamper-evident checkpoints, macOS UnifiedLogCollector has no cursor (10s polling gap), `AuditTamperProbe` kill-auditd branch unimplemented.

---

### PROC

**A1 — Attachment point**
`psutil.process_iter()` — pull from `/proc` filesystem (Linux) or Mach task APIs (macOS). **Library abstraction, not a kernel hook ✅.** Pull model at `scan_interval`. Lowest primitive: `/proc/<pid>/exe` symlink + `/proc/<pid>/cmdline`.

**A2 — Privilege**
Standard user for most fields. Root needed for `exe` path on some processes (macOS SIP restrictions). If root is unavailable: `exe` returns `None` for system processes — `BinaryFromTempProbe` gracefully skips ✅ (verified: `spine_degraded_implant_no_exe`). No health event emitted for this degradation ✅.

**A3 — Coverage surface**
Running processes, their exe path, cmdline, username, ppid, CPU/memory ✅. Cannot observe: processes that start and exit between poll cycles (race window = `scan_interval`), processes that spoof their cmdline via `prctl(PR_SET_NAME)`, or in-memory-only shellcode execution with no exe path on disk.

**A4 — Latency and loss**
Pull every `scan_interval` (10s default). A fast process can run, exfiltrate, and exit in < 10s and be completely invisible ✅. `reported_pids` set prevents duplicate alerts but is not persisted across restarts ✅ (verified in probe code).

**A5 — Tamper resistance**
Very low. Rootkits can hide processes from `/proc`. DKOM (Direct Kernel Object Manipulation) renders psutil blind. `DylibInjectionProbe` and `CodeSigningProbe` (macOS) exist as partial mitigations but operate at the same library level. No integrity check on psutil results.

**A6 — Operator stories**
1. "A binary running from /tmp is active in the process table"
2. "Office Word spawned PowerShell (macro execution)"
3. "A script interpreter is running encoded commands"

`correlation_group:execution` on `BinaryFromTempProbe` ✅ (KA v0.1 spine fix). No correlation tags on other proc probes — `SuspiciousCronJobProbe`, `ProcessHollowingProbe`, `EnvironmentVariableProbe`, and remaining probes produce events unlinkable to kernel_audit events by tag.

**Integration badge: `BRONZE`** — library-level pull, 10s blind window, rootkit-defeatable, no correlation tags, no replay support.

---

### DNS

**A1 — Attachment point**
Described as "mDNSResponder, systemd-resolved, tcpdump." **The collector mechanism is underspecified ⚠️** — unclear whether this is passive packet capture (real) or log parsing (weaker). Probes receive pre-built `List[DNSQuery]` at `dns_queries`. No integration test confirms the collector feeds real queries.

**A2 — Privilege**
Root required for packet capture (tcpdump) ⚠️. DoH (DNS over HTTPS, port 443) is opaque to passive packet capture — a host using DoH will have DNS resolution succeed without any visible UDP/53 traffic ✅. A local resolver API (e.g., mDNSResponder on macOS) may surface DoH-resolved hostnames at the application layer, but query timing and content are not accessible ⚠️.

**A3 — Coverage surface**
DNS queries and responses (domain, type, response code, process, response IPs). Cannot observe: DoH (port 443), DoT (port 853), DNS-over-QUIC, queries from within containers/VMs that use separate resolvers.

**A4 — Latency and loss**
Batch-per-cycle. `RawDNSQueryProbe` hard-caps at 100 events per cycle ✅ (confirmed: `MAX_EVENTS_PER_CYCLE = 100`, `queries[:self.MAX_EVENTS_PER_CYCLE]` in `agents/dns/probes.py`). Events above cap are silently dropped with no drop metric. `BeaconingPatternProbe` maintains domain history (stateful) but state is not guaranteed to persist across agent restarts.

**A5 — Tamper resistance**
None. Attacker using DoH bypasses entirely. No signed checkpoints.

**A6 — Operator stories**
1. "A process is generating algorithmically-looking domain names (DGA)"
2. "Something is querying the same domain with < 5% jitter every 60 seconds (C2 beacon)"
3. "We're seeing 10 NXDOMAIN responses in 60 seconds (DGA probing)"

No `correlation_group` tags on any DNS probe ✅.

**Integration badge: `BRONZE`** — collector mechanism underspecified, DoH blind spot, 100-event silent drop cap confirmed, no correlation tags, zero red-team coverage.

---

### FIM

**A1 — Attachment point**
macOS: `FSEvents` API (kernel-level push from `fsevents_collector.py` ✅). Linux: `inotify` ⚠️ (referenced in documentation; Linux inotify path not confirmed in collector code). Lowest primitive: kernel VFS hook.

**A2 — Privilege**
Root required to watch `/etc`, `/usr`, `/boot` ⚠️ (inferred; no privilege check in collector code verified). Without root: cannot watch system paths. No degraded health event if root is missing ❌.

**A3 — Coverage surface**
File creates, modifies, deletes, permission changes, owner changes within monitored directories ✅. Cannot observe: in-memory file operations (`memfd_create`), bind mounts that shadow watched paths, operations before FSEvents initialises.

**A4 — Latency and loss**
Push model — low latency ✅. FSEvents coalesces rapid changes (multiple writes to same file = one event) ⚠️ (FSEvents API behavior; not tested in AMOSKYS). FSEvents maintains an OS-level journal with sequence numbers that allows consumers to catch up after a restart ⚠️ — **AMOSKYS does not implement journal resume** ❌ (no checkpoint or sequence number handling found in `fsevents_collector.py`).

**A5 — Tamper resistance**
Good at the kernel level — FSEvents records cannot be suppressed from userspace ⚠️. An attacker with a kernel extension (macOS) could suppress FSEvents, but this requires SIP bypass. The act of disabling SIP generates its own detectable events ⚠️.

**A6 — Operator stories**
1. "A new LaunchDaemon plist was created in /Library/LaunchDaemons"
2. "sudoers file was modified"
3. "A new .so file appeared in /usr/lib"

No `correlation_group` tags on FIM probes ✅.

**Integration badge: `SILVER`** — kernel-level push attachment (FSEvents/inotify). **Badge reflects attachment depth, not detection correctness.** Zero red-team coverage; journal resume not implemented; no correlation tags; no tamper-evident checkpoints exported to AMOSKYS.

---

### FLOW

**A1 — Attachment point**
macOS: `nettop` (command-line tool, pull ⚠️). Linux: `netstat`/`ss` (pull from kernel socket table ✅). Library-level pull, not packet capture. Lowest primitive: kernel socket table snapshot.

**A2 — Privilege**
Root for full socket table visibility ⚠️. Standard user sees only own-process sockets on macOS. Encrypted traffic is completely opaque — only connection metadata visible, not payload.

**A3 — Coverage surface**
TCP/UDP connections: src/dst IP:port, bytes transferred, packet counts, protocol. Cannot observe: UDP tunnels masquerading as DNS, ICMP tunneling, IPv6 (if not configured), container network namespaces, traffic on unmonitored interfaces.

**A4 — Latency and loss**
Pull model — `nettop` snapshots every `scan_interval`. Short-lived connections (< scan_interval) are invisible ✅. `SuspiciousTunnelProbe` requires >= 600s of observation ✅. A fast exfiltration over a short TCP connection would not be seen.

**A5 — Tamper resistance**
Low. Rootkits can hide socket entries from the kernel socket table. Attacker using legitimate cloud services (HTTPS to S3, Google Drive) is invisible — no payload inspection.

**A6 — Operator stories**
1. "Host is scanning 20+ ports on an internal target"
2. "Outbound bytes to this destination are 5x the baseline"
3. "There's a consistent beaconing pattern to this external IP"

`correlation_group:data_exfiltration` on `DataExfilVolumeSpikeProbe` ✅. No tags on other 8 flow probes ✅.

**Integration badge: `BRONZE`** — poll/polling model, short-lived connection blind spot, payload-blind, only 1/9 probes has correlation tag, zero red-team coverage.

---

### Other Agents — Summary Table

| Agent | Attachment | Lowest Primitive | Badge | Red-Team Coverage |
|-------|-----------|-----------------|-------|------------------|
| peripheral | `system_profiler` + `lsusb` polling ⚠️ | OS device enumeration API | `BRONZE` | ❌ None |
| persistence | Filesystem snapshot polling ⚠️ | File stat() + service list | `BRONZE` | ❌ None |
| device_discovery | ARP table + nmap ⚠️ | Raw socket / ARP cache | `BRONZE` | ❌ None |
| protocol_collectors | Packet capture (if real pcap) ⚠️ | Raw Ethernet frame | `BRONZE`/`SILVER` ⚠️ | ❌ None |
| snmp | SNMP get/walk ⚠️ | UDP/161 responses | `BRONZE` | ❌ None |
| applog | Application log parsing ⚠️ | Log line | `BRONZE` | ❌ None |
| db_activity | SQL query analysis ⚠️ | Query log / audit trail | `BRONZE` | ❌ None |
| http_inspector | HTTP deep inspection ⚠️ | Request/response body | `BRONZE` | ❌ None |
| internet_activity | Outbound connection monitor ⚠️ | Socket metadata | `BRONZE` | ❌ None |
| net_scanner | Inbound scan detection ⚠️ | Packet metadata | `BRONZE` | ❌ None |

All "Other Agent" entries are ⚠️ inferred from code/directory structure — no integration tests confirm live data collection.

---

## Section B — Probe Reality Passports

### SSHPasswordSprayProbe

| Dimension | Detail |
|-----------|--------|
| **Probe ID** | `ssh_password_spray` |
| **Agent** | auth |
| **MITRE** | T1110.003 |
| **Threat story** | One IP, 10+ usernames, spray window ≤ 5 minutes |
| **shared_data_key** | `auth_events` |
| **Assumed identity key** | `username` (attacker's target user list; attacker identity = `source_ip`) |
| **Required fields** | `event_type="SSH_LOGIN"`, `status="FAILURE"`, `source_ip`, `username` |
| **Optional fields** | `timestamp_ns` (not used for windowing — batch-only) |
| **Time semantics** | No sliding window. Uses current batch. Ordering irrelevant. |
| **Detection rule** | `COUNT(distinct username WHERE source_ip=X AND status=FAILURE) >= 10` |
| **Threshold** | `PASSWORD_SPRAY_USER_THRESHOLD = 10` ✅ |
| **Window** | None — batch boundary only ✅ |
| **Grouping key** | `source_ip` |
| **State** | Stateless per scan ✅ |
| **Confidence** | Fixed 0.80 ✅ |
| **Severity** | Always HIGH ✅ |
| **Correlation tag** | ✅ `correlation_group:initial_access` |
| **Test coverage** | positive ✅ · benign ✅ · evasion ✅ · degraded ✅ · replay ✅ |
| **Reality score** | **L3** ✅ — all levels satisfied |

**Evasions (3):**
1. Distribute across ≥ 2 IPs with < 10 users each — proven in `spine_spray_distributed_5_ips`
2. Use `source_ip=""` (empty) — fires with attribution lost — proven in `spine_degraded_spray_no_ip`
3. Spread spray across multiple scan cycles (> 10 seconds apart) — threshold never reached in any single batch

**Degradations (3):**
1. `source_ip=""` → fires with empty attribution (detection preserved, forensics lost) ✅
2. Batch truncated by collector → threshold not reached → missed detection ⚠️
3. All events in batch have same `username` → distinct count = 1 → no spray detected ⚠️

**Benign lookalikes (3):**
1. CI/CD testing SSH across multiple accounts from a build server
2. Monitoring tool that probes all accounts for availability
3. Password manager sync that fails authentication across accounts simultaneously

---

### ExecveHighRiskProbe

| Dimension | Detail |
|-----------|--------|
| **Probe ID** | `execve_high_risk` |
| **Agent** | kernel_audit |
| **MITRE** | T1059, T1204.002 |
| **Threat story** | Process executed from /tmp, /dev/shm, or macOS temp dirs |
| **shared_data_key** | `kernel_events` |
| **Assumed identity key** | `uid` / `euid` (process identity at exec time) |
| **Required fields** | `syscall in ("execve","execveat")` AND (`ke.exe` OR `ke.path`) present |
| **Optional fields** | `uid`, `euid` (severity escalation) |
| **Time semantics** | Uses `ke.timestamp_ns` directly on `TelemetryEvent` ✅ |
| **Normalization** | `exe_path = ke.exe or ke.path` — dual-field fallback ✅ |
| **Detection rule** | `exe_path.startswith(HIGH_RISK_DIRS)` — frozenset prefix match ✅ |
| **Severity logic** | MEDIUM baseline; HIGH if (euid==0 and uid!=0) OR (euid==0) ✅ |
| **Confidence** | Fixed 0.75 ✅ |
| **Correlation tag** | ✅ `correlation_group:execution` |
| **Test coverage** | positive ✅ · benign ✅ · evasion ✅ · degraded ✅ · replay ✅ |
| **Reality score** | **L3** ✅ — all levels satisfied |

**Evasions (3):**
1. Move binary to `/usr/local/bin` before exec — proven in `spine_exec_dropper_moved_to_usr_bin`
2. Use `/proc/self/fd/X` exec path — fd-based exec bypasses path prefix check
3. Execute via `LD_PRELOAD` injection from a clean path — no execve of suspicious binary

**Degradations (3):**
1. `exe=None` and `path=None` → graceful skip ✅ — proven in `spine_degraded_exec_no_exe`
2. `syscall="execveat"` with relative fd — `exe` may be empty or relative ⚠️
3. Collector sends path without leading slash — `startswith()` check fails silently ⚠️

**Benign lookalikes (3):**
1. npm install scripts that unpack to `/tmp` via node-gyp
2. macOS installer temp files in `/private/var/folders/`
3. Docker layer extraction to `/tmp` during `docker pull`

---

### PrivEscSyscallProbe

| Dimension | Detail |
|-----------|--------|
| **Probe ID** | `privesc_syscall` |
| **Agent** | kernel_audit |
| **MITRE** | T1068, T1548 |
| **Threat story** | Non-root calls seteuid(0) or capset and succeeds |
| **shared_data_key** | `kernel_events` |
| **Assumed identity key** | `uid` (before escalation); `euid` (after) |
| **Required fields** | `syscall in PRIVESC_SYSCALLS` AND `result == "success"` |
| **Optional fields** | `uid`, `euid` (severity), `comm` (context) |
| **Detection rule** | `syscall in PRIVESC_SYSCALLS AND result == "success"` ✅ |
| **Severity** | CRITICAL if uid≠0 AND euid=0; MEDIUM if uid=euid (capset) ✅ |
| **Confidence** | Fixed 0.90 ✅ |
| **Correlation tag** | `correlation_group:privilege_escalation` ✅ |
| **Test coverage** | positive ✅ · benign ✅ · evasion ✅ · degraded ✅ · replay ✅ |
| **Reality score** | **L3** ✅ — all levels satisfied |

**Evasions (3):**
1. Use failed attempts to probe (`result="failed"`) — probe ignores — proven in `spine_privesc_seteuid_eperm`
2. Exploit a setuid binary that calls seteuid internally — audit record shows binary's uid, not attacker's
3. Use kernel exploit that bypasses syscall auditing entirely (kernel module rootkit)

**Degradations (3):**
1. `result=None` → graceful skip ✅ — proven in `spine_degraded_privesc_no_result`
2. `syscall` misspelled by collector (e.g., `"set_euid"`) → no match → missed detection ⚠️
3. `uid` field missing → `uid=None`, `uid != 0` is False → severity defaults to MEDIUM instead of CRITICAL ⚠️

**Benign lookalikes (3):**
1. SSH daemon calling seteuid on legitimate user login
2. `su`/`sudo` binary calling setuid as part of normal elevation
3. Homebrew installer that temporarily calls setuid for package installation

---

### PtraceAbuseProbe

| Dimension | Detail |
|-----------|--------|
| **Probe ID** | `ptrace_abuse` |
| **Agent** | kernel_audit |
| **MITRE** | T1055, T1055.008 |
| **Threat story** | Process attaches to another via ptrace to read memory or inject code |
| **shared_data_key** | `kernel_events` |
| **Assumed identity key** | `uid` of attaching process; target identified by `dest_pid` → `pid_to_comm` lookup |
| **Required fields** | `syscall in ("ptrace","process_vm_readv","process_vm_writev")` |
| **Target resolution** | `pid_to_comm` built from preceding execve events in same batch ✅ |
| **Severity** | CRITICAL if target in PROTECTED_PROCESSES or dest_pid==1; HIGH if uid≠0; MEDIUM default ✅ |
| **Confidence** | Fixed 0.85 ✅ |
| **Correlation tag** | ✅ `correlation_group:credential_access` |
| **Test coverage** | positive ✅ · benign ✅ · evasion ✅ · degraded ✅ · replay ✅ |
| **Reality score** | **L3** ✅ — all levels satisfied |

**Evasions (3):**
1. Access via `/proc/<pid>/mem` (`openat`, not ptrace) — proven in `spine_ptrace_proc_mem_evasion`
2. `process_vm_readv` not audited on some kernel configurations ⚠️
3. Intercept target process via shared memory (`shm_open`) — no ptrace call issued

**Degradations (3):**
1. `dest_pid=None` → fires at MEDIUM (no target lookup) ✅ — proven in `spine_degraded_ptrace_no_dest_pid`
2. `pid_to_comm` empty (execve event for target in different batch) → target_comm=None → severity drops from CRITICAL to MEDIUM ⚠️
3. `uid` field missing → `uid != 0` is False → non-root branch skipped → severity drops to MEDIUM ⚠️

**Benign lookalikes (3):**
1. `gdb` debugging a test binary as root during development
2. `strace` attached to a running service for production diagnostics
3. macOS `dtruss` (dtrace wrapper) on any process during performance profiling

---

### BinaryFromTempProbe

| Dimension | Detail |
|-----------|--------|
| **Probe ID** | `binary_from_temp` |
| **Agent** | proc |
| **MITRE** | T1204, T1059 |
| **Threat story** | Running process has exe path in a temp directory |
| **Data source** | `psutil.process_iter()` (mocked via `patch_targets` in tests) |
| **Assumed identity key** | `username` field from psutil process info |
| **Detection rule** | `re.search(pattern, exe_lower)` for any pattern in `TEMP_PATTERNS` ✅ |
| **Dedup** | `reported_pids` set — fires once per PID per probe lifetime ✅ |
| **Confidence** | Fixed 0.85 ✅ |
| **Severity** | Always HIGH ✅ |
| **Correlation tag** | ✅ `correlation_group:execution` |
| **Replay** | ❌ Not supported — psutil cannot be JSONL-captured |
| **Test coverage** | positive ✅ · benign ✅ · evasion ✅ · degraded ✅ · replay ❌ |
| **Reality score** | **L3** ✅ — all levels satisfied |

**Evasions (3):**
1. Copy binary to `/usr/local/bin/` before exec — proven in `spine_implant_moved_to_usr_local_bin`
2. Bind-mount `/tmp` over `/usr/local/bin/` — exe shows as `/usr/local/bin/...`
3. Delete the exe file after launch — exe path becomes `None` on macOS (probe skips, proven in degraded case)

**Degradations (3):**
1. `exe=None` (process exited between scan and attribute fetch) → graceful skip ✅ — proven in `spine_degraded_implant_no_exe`
2. `psutil.AccessDenied` on `.info` dict → unhandled exception → probe crashes ⚠️ (unverified)
3. `reported_pids` lost on agent restart → duplicate alert for long-running implant after reboot ⚠️

**Benign lookalikes (3):**
1. npm install scripts compiled in `/tmp` by `node-gyp`
2. macOS software update unpacking to `/private/var/folders/`
3. JVM JIT-compiled code extracted to temp dir at runtime

---

### DGAScoreProbe (DNS)

| Dimension | Detail |
|-----------|--------|
| **Probe ID** | DNS DGA scoring |
| **Agent** | dns |
| **MITRE** | T1568.002 |
| **Threat story** | Malware generates algorithmically-random domains for C2 |
| **Assumed identity key** | Querying process (if available from collector) |
| **Detection** | Multi-factor scoring: entropy + length + consonant ratio + numeric ratio + vowel check ✅ |
| **Thresholds** | score > 0.7 → HIGH; score > 0.5 → MEDIUM ✅ |
| **Whitelist** | cloudflare.com, akamai.net, fastly.net, cloudfront.net, amazonaws.com, googlevideo.com ✅ |
| **Confidence** | Computed: = score ✅ |
| **Correlation tag** | ❌ NONE |
| **Test coverage** | ❌ None — zero red-team scenarios |
| **Reality score** | **UNVERIFIED by red-team harness** — no adversarial case exists |

**Evasions (3):**
1. Use pronounceable dictionary-word domains (low entropy, low consonant ratio)
2. Use short domains < 20 chars with normal vowel distribution
3. Use CDN-parked subdomains (`a1b2.cloudfront.net` — root domain whitelisted, subdomain label still scores high on entropy)

**False positive risk (HIGH) ⚠️:**
CDN subdomains (e.g., `d1b2c3d4.cloudfront.net`) — root domain is whitelisted but subdomain label will score high on entropy and consonant ratio. This is an unverified FP risk with no benign test case ❌.

---

### BeaconingPatternProbe (DNS)

| Dimension | Detail |
|-----------|--------|
| **Probe ID** | DNS beaconing |
| **Agent** | dns |
| **MITRE** | T1071.004, T1573.002 |
| **Assumed identity key** | Querying process + domain |
| **Detection rule** | `avg_interval in [30s, 600s]` AND `jitter_ratio < 0.15` AND `>= 5 queries` ✅ |
| **Known C2 patterns** | `.cobalt.strike`, `.metasploit.`, `.empire.`, `.sliver.`, `.ngrok.io`, `.serveo.net` ✅ |
| **State** | `domain_history` dict — persisted across cycles within agent lifetime ✅ |
| **Confidence** | Computed: `1.0 - jitter_ratio` ✅ |
| **Correlation tag** | ❌ NONE |
| **Test coverage** | ❌ None — requires multi-cycle real-time state accumulation |
| **Reality score** | **UNVERIFIED by red-team harness** — no adversarial case exists |

**Evasions (3):**
1. Add > 15% jitter to beacon interval ✅ (threshold confirmed)
2. Use DoH — invisible to DNS agent entirely ✅
3. Use CDN-fronted domain — query pattern looks like normal traffic

---

## Section C — "How Real is the Data?" (Simulation Fidelity)

### C1 — Source realism per agent

| Agent | In Production | In Red-Team Tests | Fidelity Gap |
|-------|-------------|------------------|-------------|
| auth | Parsed auth log lines → `AuthEvent` | Synthetic `AuthEvent` dicts | **MEDIUM** — same schema, timestamps anchored not jittered |
| kernel_audit | BSM/auditd records → `KernelAuditEvent` | Synthetic `KernelAuditEvent` dicts | **MEDIUM** — real records have more fields (ppid, cwd, tty) omitted |
| proc | `psutil.process_iter()` | `MagicMock` with `.info` dict | **HIGH** — mock returns exactly what you put in; real psutil returns stale data, `AccessDenied`, `None` fields |
| dns | Packet-captured DNS queries | Not tested | **UNVERIFIED by red-team harness** — zero adversarial coverage |
| fim | FSEvents/inotify push | Not tested | **UNVERIFIED by red-team harness** — zero adversarial coverage |
| flow | nettop/netstat poll | Not tested | **UNVERIFIED by red-team harness** — zero adversarial coverage |
| peripheral | system_profiler output | Not tested | **UNVERIFIED by red-team harness** |
| persistence | Filesystem snapshot | Not tested | **UNVERIFIED by red-team harness** |

### C2 — Field realism gaps

**Fields "too perfect" in tests (never null/malformed):**
- `timestamp_ns` — always set, always in correct nanosecond range
- `host` — always `"victim-host"`, never empty or malformed
- `pid` — always > 0
- `exe` — always a clean absolute path (when set)
- `source_ip` — always valid IPv4 string (when set)
- `username` — always non-empty string

**Fields missing in real life (not yet modeled):**
- `exe=None` for short-lived processes (partially covered by 1 degraded case ✅)
- Truncated cmdlines (Linux 4096-char limit — real cmdlines get cut) ❌
- PID reuse — same PID appearing twice in `reported_pids` ❌
- Timezone drift — timestamps from different sources may differ by seconds ❌
- Missing `ppid` — orphaned processes after parent exits ❌
- `source_ip` in IPv6 format (`::ffff:185.220.101.1`) for dual-stack listeners ❌
- Auth events with empty `username` (password spray with invalid usernames) ❌

### C3 — Noise realism

**Not modeled at all ❌:**
- Normal user behavior mixed into positive test inputs
- Duplicate events from log rotation
- Out-of-order timestamps from buffered collectors
- PID churn (hundreds of short-lived processes per second on a busy host)
- Burst events after system resume from sleep
- Mixed IPv4/IPv6 for the same connection

### C4 — Timing realism

- All test timestamps are perfectly ordered and monotonically increasing ✅ (they're set by the test author)
- No clock skew modeled between auth log and kernel audit timestamps ❌
- Beaconing probes require real elapsed time (10s+ between cycles) — impossible to test correctly in single-scan unit tests ❌
- `BeaconingPatternProbe` state accumulates across multiple `scan()` calls, but tests invoke it once ❌

### C5 — Attack realism

**IS modeled (spine scenarios) ✅:**
- Tor exit node SSH password spray
- /tmp dropper execution (MEDIUM → HIGH via setuid)
- seteuid(0) privilege escalation
- ptrace on sshd with `pid_to_comm` resolution
- macOS `/private/var/folders/` temp dir patterns

**NOT yet modeled ❌:**
- Living-off-the-land (LOLBin) — no `LOLBinExecutionProbe` red-team test
- Signed malware (code signature bypass)
- Distributed spray across 5+ IPs with IP rotation
- Persistence mechanisms (LaunchAgent, cron, systemd)
- DNS C2 (no DNS scenario in red-team)
- Network exfiltration (no flow scenario)
- macOS-specific: DYLD injection, code signing bypass, TCC abuse

---

## Section D — Foundation Hardening Drills

### Drill 1: Degraded Mode is First-Class

**Status: PARTIAL**

**What exists ✅:**
- `MicroProbe.validate_contract()` emits `REAL` / `DEGRADED` / `BROKEN` status
- `degraded_without` field on probes specifies non-fatal missing fields
- `aoc1_probe_degraded_firing` event emitted by base agent
- 5 degraded red-team cases verified at 225/225 pass

**Gaps ❌:**
- No `amoskys health` CLI. `amoskys-redteam score` shows L0-L3 but not live privileges, drop rate, or last event timestamp
- If auth agent's TCC permission is revoked: 0 events fired, no `agent_health_degraded` event emitted — silent blindness
- If kernel audit rules are deleted: 0 events, no health event
- `BinaryFromTempProbe` with `exe=None` fires 0 events with no probe health signal

**Required action:** `amoskys health` CLI showing per-agent: privileges OK/missing, events_seen last 60s, drop_rate, last_event_timestamp, contract_status per probe.

---

### Drill 2: Evidence Chain Integrity

**Status: GAP**

**What exists ✅:**
- `evidence_chain.py` — `correlation_id`, `device_id`, `timestamp_ns`, `tags` on `TelemetryEvent`
- WAL (write-ahead log) for durability confirmed in `wal_processor.py`
- Signed envelopes via `queue_adapter.py`

**Gaps ❌:**
- No cryptographic hash/signature at agent output boundary. Events in WAL are plain JSON — an attacker with filesystem access can modify them before `wal_processor` reads
- `incident_key` (16-char SHA-256 hex) is a content hash, not an integrity proof — it changes if data changes, but nothing verifies it hasn't changed after the fact
- No Merkle chain or checkpoint signatures between WAL entries

**Required action:** HMAC or Ed25519 signature on each WAL entry at write time. Verification at read time in `wal_processor`. Export signed event chain as provable evidence artifact.

---

### Drill 3: Loss and Backpressure Torture Test

**Status: NOT DONE**

**What exists ✅:**
- Circuit breaker (CLOSED → OPEN → HALF_OPEN) with 5-failure threshold
- Local queue fallback for EventBus outages
- `aoc1_heartbeat` every cycle

**Gaps ❌:**
- No soak test for 10x event rate burst
- `RawDNSQueryProbe` has hard cap of 100 events/cycle with silent drop — no drop counter, no health event ✅ (cap confirmed, gap confirmed)
- No disk-full handling — WAL writes fail silently
- No bounded memory policy — `domain_history` in `BeaconingPatternProbe` grows unbounded ⚠️
- No documented drop policy (oldest? newest? random?) for the local queue

**Required action:** Stress test at 10x baseline event rate per agent. Verify bounded memory. Verify drop events are emitted. Verify WAL handles disk-full with `agent_health_degraded`.

---

### Drill 4: Noise Immunity Suite

**Status: PARTIAL**

**What exists ✅:**
- Every spine scenario has 1 benign case
- Auth probe scenarios have 1-2 benign cases each
- 225/225 cases passing including all benign cases

**Gaps ❌:**
- No "nasty benign" cases — all benign cases are clearly benign (curl from `/usr/bin`, Chrome from `/Applications`). No case like: "gdb attached to own process for debugging" or "npm build script in /tmp that is legitimate"
- No noise mixed into positive test inputs — tests use clean isolated events
- No multi-event benign storm (e.g., 100 events per cycle, 99 benign, 1 attack)
- `LOLBinExecutionProbe` has no red-team test at all
- DNS probes have no red-team test — CDN domain misclassification as DGA is a real FP risk

---

### Drill 5: Cross-Probe Story Test

**Status: PARTIAL — best in system**

**What exists ✅:**
- 5-phase kill-chain spine: spray → exec → privesc → implant → ptrace
- `IncidentTimeline` stitches caught positive cases and renders ANSI timeline
- `correlation_group:privilege_escalation` on `PrivEscSyscallProbe`
- Timeline renders coherent narrative with `ATTACK_CAUGHT` verdict

**Timeline semantics note:** The current timeline renders **all caught positive cases across all spine scenarios** (12 phases, including degraded variants). This is not a single canonical incident — it is a union of every positive detection across 5 independent scenarios. For leadership reporting, a filtered view showing only the 5 canonical spine detections (one per phase) would be more legible.

**Gaps ❌:**
- ~~Only `PrivEscSyscallProbe` carries `correlation_group` tag among all 5 spine probes~~ → **RESOLVED (KA v0.1)**: all 4 missing spine probe tags added
- No cross-agent correlation scenario (e.g., spray event linking to subsequent exec by same principal)
- `incident_key` computed per-scenario, not cross-scenario — no global kill-chain hash

---

## Section E — Integration Depth Badge Summary

### Badge Criteria

| Badge | Criteria (all must be met) |
|-------|---------------------------|
| **BRONZE** | Userland library poll or log parse; limited or unverified privileges; no integrity guarantees; no red-team adversarial contract |
| **SILVER** | OS event stream (kernel push or audit stream); confirmed privilege requirement; health events on degradation; at least partial red-team coverage (≥ 1 positive + benign case) |
| **GOLD** | Tamper-evident at collection boundary (signed records); replay fidelity (JSONL capture verified); cross-agent correlation tags on all probe outputs; full red-team contract (positive + benign + evasion + degraded + replay); drop detection with health events |

**No agent currently meets GOLD criteria.**

### Badge Assignments

| Agent | Badge | Primary justification | Red-Team |
|-------|-------|-----------------------|----------|
| kernel_audit | **SILVER** | Kernel-level syscall stream ✅; real privilege escalation detection ✅ | Partial ✅ |
| fim | **SILVER** | FSEvents push (kernel-level attachment) ✅; **Badge = attachment depth, not detection correctness** | ❌ None |
| auth | **BRONZE** | Log-level pull; geo enrichment requires separate GeoIP step; TCC-revocable blind spot | Partial ✅ |
| proc | **BRONZE** | Library-level poll; 10s blind window; rootkit-defeatable; no replay | Partial ✅ |
| dns | **BRONZE** | Collector underspecified; DoH blind spot; 100-event silent drop cap confirmed ✅ | ❌ None |
| flow | **BRONZE** | Poll model; payload-blind; 1/9 probes has correlation tag; short-lived connections invisible | ❌ None |
| peripheral | **BRONZE** | `system_profiler` polling; no event stream | ❌ None |
| persistence | **BRONZE** | Filesystem polling; no event stream | ❌ None |
| protocol_collectors | **BRONZE** ⚠️ | Collector mechanism unverified; could reach Silver with confirmed real pcap | ❌ None |
| device_discovery | **BRONZE** | ARP/nmap polling; no streaming | ❌ None |
| snmp | **BRONZE** | UDP polling; limited coverage | ❌ None |
| applog / db_activity / http_inspector / internet_activity / net_scanner | **BRONZE** | Stubs or log parsers with no red-team contract | ❌ None |

---

## Findings Table

| # | Finding | Agent | Severity | Verified |
|---|---------|-------|----------|----------|
| F-01 | ~~4 of 5 spine probes emit no `correlation_group` tag — fusion engine cannot link kill-chain events~~ **RESOLVED** — all 5 spine probes now tagged; 224/225 spine cases reach L3 ✅ | auth, kernel_audit, proc | ~~HIGH~~ RESOLVED | ✅ |
| F-02 | DNS, FIM, FLOW, peripheral, persistence, device_discovery have zero red-team adversarial coverage | All | HIGH | ✅ |
| F-03 | No `amoskys health` CLI — operators cannot verify which agents are actively collecting | All | HIGH | ✅ |
| F-04 | WAL entries are plain JSON — an attacker with filesystem access can tamper with evidence | All | HIGH | ✅ |
| F-05 | FIM badge is SILVER but journal resume is not implemented — SILVER reflects attachment only | fim | MEDIUM | ✅ |
| F-06 | `SSHGeoImpossibleTravelProbe` requires `src_latitude`/`src_longitude` — absent from raw auth logs without GeoIP enrichment | auth | MEDIUM | ✅ |
| F-07 | `MFABypassOrAnomalyProbe` is disabled on macOS — primary dev platform | auth | MEDIUM | ⚠️ |
| F-08 | `RawDNSQueryProbe` silently drops events above 100/cycle with no health signal | dns | MEDIUM | ✅ |
| F-09 | `BeaconingPatternProbe` `domain_history` grows unbounded — potential memory exhaustion | dns | MEDIUM | ⚠️ |
| F-10 | Proc agent 10s scan interval — fast process executes and exits completely invisible | proc | MEDIUM | ✅ |
| F-11 | No drop detection for kernel audit ring buffer — events silently lost at OS level | kernel_audit | MEDIUM | **RESOLVED (KA v0.1)** — `/proc/audit_lost` polled every cycle; `kernel_audit_drop_detected` emitted on increase |
| F-12 | `PtraceAbuseProbe` severity degrades to MEDIUM when `pid_to_comm` built from different batch | kernel_audit | LOW | ⚠️ |
| F-13 | `BinaryFromTempProbe` `reported_pids` lost on restart — duplicate alerts after reboot | proc | LOW | ⚠️ |
| F-14 | `BeaconingPatternProbe` and multi-cycle state probes impossible to test in single-scan unit tests | dns | LOW | ✅ |

---

## Top 10 Risks

| Rank | Risk | Severity | Affected agents | Remediation |
|------|------|----------|----------------|-------------|
| 1 | ~~**Fusion engine cannot link kill-chain events**~~ **RESOLVED** ✅ — all 5 spine probes now emit `correlation_group` tags (initial_access / execution / privilege_escalation / credential_access); 224/225 spine cases reach L3 | ~~CRITICAL~~ RESOLVED | auth, kernel_audit, proc | Done ✅ |
| 2 | **Operators cannot tell which agents are blind** — no `amoskys health` CLI; if TCC permission revoked or auditd stopped, zero events + zero health signal | CRITICAL | All | Implement `amoskys health` per-agent status: privileges, events_seen_60s, drop_rate, last_event_ts |
| 3 | **WAL evidence is not tamper-evident** — plain JSON WAL; attacker with root can rewrite evidence before wal_processor reads | HIGH | All | HMAC or Ed25519 sign each WAL entry at write; verify at wal_processor read |
| 4 | **No red-team contract for 8+ agents** — dns, fim, flow, peripheral, persistence, device_discovery, protocol_collectors, snmp have zero adversarial cases | HIGH | 8 agents | Start with dns and fim (4 cases each: positive + benign + evasion + degraded) |
| 5 | **GeoIP enrichment absent from raw auth logs** — `SSHGeoImpossibleTravelProbe` fires only after enrichment step that isn't confirmed deployed | HIGH | auth | Either confirm GeoIP enrichment pipeline in production or disable/gate the probe |
| 6 | **DNS 100-event silent drop** — `RawDNSQueryProbe` truncates batches silently; DGA/beacon detection degrades invisibly under load | MEDIUM | dns | Emit `aoc1_probe_degraded_firing` when cap reached; expose drop counter metric |
| 7 | **Kernel audit ring buffer loss undetected** — kernel drops oldest events when buffer fills; AMOSKYS has no lost-event counter | MEDIUM | kernel_audit | Read `/proc/net/audit_lost` or auditd stats; emit health event when > 0 |
| 8 | **10-second proc blind window** — BinaryFromTempProbe misses any implant that runs and exits in < 10s; no alerting on the gap | MEDIUM | proc | Supplement with kernel_audit execve detection (already exists in ExecveHighRiskProbe); document explicit coverage gap |
| 9 | **`BeaconingPatternProbe` unbounded memory** — `domain_history` dict grows indefinitely; no TTL, no max-size eviction | MEDIUM | dns | Add LRU eviction or TTL expiry to `domain_history`; emit health event if dict exceeds threshold |
| 10 | **FIM Silver badge implies coverage it doesn't have** — FIM has kernel-level attachment (FSEvents) but zero red-team cases and no journal resume | MEDIUM | fim | Add ≥ 4 FIM adversarial cases; implement FSEvents journal resume (checkpoint by sequence number) |

---

## The Honest Summary

### What AMOSKYS provably does today ✅

- **225/225 adversarial cases passing** across auth, kernel_audit, and proc probes (synthetic events)
- Kill-chain spine produces coherent ANSI timeline with `ATTACK_CAUGHT` verdict (5/5 canonical phases)
- Graceful degradation under null/missing fields — 5 degraded cases verified across all probe types
- Reality score infrastructure (L0-L3) wired and returning L3 for all privesc spine cases
- Capture/replay pipeline for auth + kernel_audit probes (JSONL)
- `amoskys-redteam timeline`, `score`, and `replay` CLI subcommands operational

### What is inferred or unverified today ⚠️ / ❌

| Gap | Risk |
|-----|------|
| dns, fim, flow, peripheral, persistence, device_discovery, protocol_collectors — **zero red-team coverage** ❌ | These agents exist, compile, and run, but no adversarial contract validates their detection logic |
| `correlation_group` tags on 5 spine probes ✅; missing on ~95 of ~100 probes ❌ | The fusion engine can now link kill-chain spine events; all other agents remain unlinked |
| `SSHGeoImpossibleTravelProbe` requires `src_latitude`/`src_longitude` ⚠️ | These fields are in `AuthEvent` as enriched optional fields — absent from raw auth logs without GeoIP enrichment step |
| `MFABypassOrAnomalyProbe` is **disabled on macOS** ⚠️ | On the primary development platform, this probe never runs |
| Proc agent psutil mock returns exactly what you put in ✅ | Real psutil returns stale data, `AccessDenied`, `NoSuchProcess`, `None` — only 1 degraded case covers this |
| Flow and DNS beaconing probes require multi-cycle state accumulation ❌ | Impossible to test correctly in single-scan unit tests |
| No `amoskys health` CLI ❌ | Operators cannot see which agents are blind right now |
| WAL entries are plain JSON ❌ | An attacker with filesystem access can modify evidence before `wal_processor` reads it |
| FIM journal resume not implemented ❌ | SILVER badge reflects FSEvents attachment depth only; detection correctness is unverified |

### The three actions that move the most ground fastest

1. **Add `correlation_group` tags to 4 spine probe event emissions** — `ssh_password_spray`, `execve_high_risk`, `execution_from_temp`, `ptrace_abuse` are missing them. One-line change per probe. Unlocks fusion engine cross-agent linking and bumps all 4 probes from L2 to L3 reality score.

2. **Add red-team adversarial scenarios for `dns` and `fim`** — these are high-value agents with real kernel attachment but zero contractual validation. Start with 4 cases each (positive, benign, evasion, degraded).

3. **Add `amoskys health` CLI subcommand** — showing per-agent: privileges present/missing, events_seen last 60s, drop_rate, last_event_timestamp_utc, contract_status per probe. Without this, operators are flying blind on which agents are actually collecting.

---

---

## Section F — Collector Truth Contracts

> **What this section audits:** The collector is the thing that builds the list the probe sees. Section A audits what the probe can do; Section F audits whether the collector is actually delivering. These are separate failure modes.

### F — Collector Contract Template (fields required for each agent)

| Field | Description |
|-------|-------------|
| **Source primitive** | Exact OS interface (file path, API call, socket, kernel stream) |
| **Parser fidelity** | Raw record formats handled; which are silently dropped |
| **Ordering guarantee** | Are events delivered in syscall/log order? Can they arrive OOO? |
| **Duplication risk** | Can the same record be emitted twice (log rotate, restart, replay)? |
| **Resume cursor** | Does the collector checkpoint its read position? What is the cursor? |
| **Drop accounting** | Is "events lost between collector and probe" measured anywhere? |
| **Blindness signal** | What exact event is emitted when the collector cannot read (permissions/TCC/daemon down)? |

---

### AUTH Collector Contract

| Field | Status | Detail |
|-------|--------|--------|
| **Source primitive** | ⚠️ | macOS: `os_log` / `log stream` API or `/var/log/system.log`. Linux: `/var/log/auth.log` or `journald`. Exact API not specified in collector code. |
| **Parser fidelity** | ⚠️ | Line-by-line text parse → `AuthEvent`. RFC3164/RFC5424 syslog assumed. Non-conforming lines: unknown — probably silently skipped. |
| **Ordering guarantee** | ⚠️ | Log files are generally ordered but log rotation gaps are possible. journald is ordered by sequence. |
| **Duplication risk** | ❌ | Log rotate can re-deliver last N lines if collector restarts without cursor. No dedup in probe (stateless per batch). |
| **Resume cursor** | ❌ | No inode+offset checkpoint. Collector reads "from now" on each start — events between restart and resume are lost. |
| **Drop accounting** | ❌ | No lost-event counter. If log grows faster than collector reads, old lines are gone. |
| **Blindness signal** | ❌ | None. 0 events in `auth_events` is indistinguishable from "no auth activity occurred." |

**Verdict:** Silent emptiness is the primary operational risk. An auth agent that cannot read its log emits nothing — no health event, no alarm.

---

### KERNEL_AUDIT Collector Contract

| Field | Status | Detail |
|-------|--------|--------|
| **Source primitive** | ✅ | Linux: auditd socket / `/var/log/audit/audit.log`. macOS: BSM via `/dev/audit`. Push model. |
| **Parser fidelity** | ⚠️ | Probe layer receives `KernelAuditEvent` objects — pre-structured. The raw BSM/auditd text→dict parsing step is not visible in the probe code. Parsing fidelity of that intermediate layer is unverified. |
| **Ordering guarantee** | ✅ | auditd preserves kernel event ordering via sequence numbers. Gaps in sequence = dropped events at kernel level. |
| **Duplication risk** | ⚠️ | Possible after auditd restart if log position is not remembered. |
| **Resume cursor** | ❌ | Audit sequence numbers exist in records but AMOSKYS does not consume them — no resume after restart. |
| **Drop accounting** | ❌ | `/proc/audit_lost` (Linux) and `auditctl -s` expose drop counts. AMOSKYS does not poll these. Kernel silently drops when ring buffer fills. |
| **Blindness signal** | ❌ | If audit rules are cleared (`auditctl -D`) or auditd stops, 0 events arrive. No health event emitted. |

**Verdict:** Strongest collector in the system at the attachment point (kernel push), but no resume cursor and no drop measurement means silent data loss is undetectable.

---

### PROC Collector Contract

| Field | Status | Detail |
|-------|--------|--------|
| **Source primitive** | ✅ | `psutil.process_iter()` → `/proc/<pid>/` (Linux) or Mach task port APIs (macOS). |
| **Parser fidelity** | ⚠️ | psutil abstracts the platform difference. Real psutil returns stale data, `AccessDenied`, `NoSuchProcess`, and `None` for restricted fields. Only 1 degraded case covers this. |
| **Ordering guarantee** | N/A | Snapshot model — no ordering concept. Process list returned in OS-defined order. |
| **Duplication risk** | ⚠️ | `reported_pids` dedup per probe lifetime — but lost on restart. Long-running implant after restart = duplicate alert. |
| **Resume cursor** | N/A | Stateless snapshot. No cursor concept applies. |
| **Drop accounting** | ❌ | Processes that run-and-exit between scans are never seen. No counter for missed processes. |
| **Blindness signal** | ❌ | If SIP or permissions prevent `exe` access, `exe=None` is returned and probe gracefully skips. No health event emitted for this degradation. |

**Verdict:** The blind window (10s default) is a known gap with no compensation signal.

---

### DNS Collector Contract

| Field | Status | Detail |
|-------|--------|--------|
| **Source primitive** | ⚠️ | Underspecified. Possibly: passive tcpdump pcap (port 53), mDNSResponder API, or systemd-resolved logs. Each has different privilege, coverage, and fidelity implications. |
| **Parser fidelity** | ⚠️ | If pcap: DNS wire format → `DNSQuery`. If resolver log: text parse. Neither path is confirmed in code. |
| **Ordering guarantee** | ⚠️ | pcap: arrival order. Resolver API: response order. Both may miss async resolution. |
| **Duplication risk** | ⚠️ | pcap on multiple interfaces may see the same query twice. |
| **Resume cursor** | ❌ | No pcap offset cursor. No checkpoint. |
| **Drop accounting** | ✅ | `RawDNSQueryProbe` hard-caps at 100 events/cycle (confirmed). Events above cap are silently dropped — no drop metric published. |
| **Blindness signal** | ❌ | DoH bypasses entirely. Collector permission failure → 0 events, no signal. |

**Verdict:** Collector mechanism is the biggest unknown in the system. The 100-event cap is the only confirmed drop point, but it has no corresponding health signal.

---

### FIM Collector Contract

| Field | Status | Detail |
|-------|--------|--------|
| **Source primitive** | ✅ | macOS: `FSEvents` API (kernel VFS hook). Linux: `inotify` ⚠️ (assumed, not confirmed in code). |
| **Parser fidelity** | ⚠️ | FSEvents delivers path + flag bitmask. The AMOSKYS collector translates this to a `FIMEvent` struct — translation code not audited for completeness. |
| **Ordering guarantee** | ✅ | FSEvents delivers events in VFS order within a stream. `inotify` order is kernel-guaranteed within a watch. |
| **Duplication risk** | ⚠️ | FSEvents coalesces rapid writes to the same path (multiple writes = one event). The coalescing window is OS-controlled. |
| **Resume cursor** | ❌ | FSEvents API supports `since:` with a `FSEventStreamEventId` for journal replay. **AMOSKYS does not use this.** Events between a crash and restart are permanently lost. |
| **Drop accounting** | ❌ | macOS FSEvents: no drop signal at application layer. Linux `inotify`: `IN_Q_OVERFLOW` flag indicates kernel queue overflow — AMOSKYS does not check for this. |
| **Blindness signal** | ❌ | No event when watched directory is unmounted, when SIP restricts a path, or when the watcher fails to start. |

**Verdict:** Best attachment point after kernel_audit. But no journal resume and no overflow detection means crash recovery is a data gap with no alert.

---

### FLOW Collector Contract

| Field | Status | Detail |
|-------|--------|--------|
| **Source primitive** | ⚠️ | macOS: `nettop` CLI tool output (parsed from stdout). Linux: `ss`/`netstat` CLI output or `/proc/net/tcp`. |
| **Parser fidelity** | ⚠️ | CLI text parsing is fragile to version changes in `nettop`/`ss` output format. |
| **Ordering guarantee** | N/A | Snapshot. No ordering concept. |
| **Duplication risk** | N/A | Same long-lived connection appears in every scan. Not a "duplicate" — it's expected state. |
| **Resume cursor** | N/A | Stateless snapshot. |
| **Drop accounting** | ❌ | Short-lived connections (< scan_interval) are invisible. No counter for missed connections. |
| **Blindness signal** | ❌ | If `nettop`/`ss` is missing or fails (e.g., PATH issue, permission denied), 0 connections returned. No health event. |

---

## Section G — Identity Spine Contract

> **What this section defines:** For the fusion engine to link events across agents, events must share a common identity key. This table defines the canonical keys and which agents can currently provide them.

### Canonical Correlation Keys

| Key | Description | Example values |
|-----|-------------|---------------|
| `device_id` | Stable host identity | UUID, hostname, MAC |
| `principal_id` | Human or service account identity | uid, username, account_id |
| `subject_id` | Process identity (stable across exec calls in same session) | pid + boot_uuid + start_time |
| `binary_id` | Executable identity (immune to name change) | SHA-256(exe), code_signature |
| `session_id` | Login session or TTY chain | SSH session ID, tty, parent PID chain |
| `network_flow_id` | TCP/UDP connection identity | (src_ip, src_port, dst_ip, dst_port, proto, time_bucket) |

### Agent Coverage Matrix

| Key | auth | kernel_audit | proc | dns | fim | flow |
|-----|------|-------------|------|-----|-----|------|
| `device_id` | ⚠️ hostname only | ⚠️ hostname only | ⚠️ hostname only | ⚠️ hostname only | ⚠️ hostname only | ⚠️ hostname only |
| `principal_id` | ✅ `username` | ✅ `uid`/`euid` | ✅ `username` | ❌ none | ❌ none | ❌ none |
| `subject_id` | ❌ | ⚠️ `pid` only (no `boot_uuid`, no `start_time`) | ⚠️ `pid` + `create_time` (process_guid) | ❌ | ❌ | ⚠️ `pid` (partial) |
| `binary_id` | ❌ | ⚠️ `exe` path only (no hash, no signature) | ⚠️ `exe` path only | ❌ | ⚠️ path only | ❌ |
| `session_id` | ✅ `session_id` + `tty` | ⚠️ `tty` only | ❌ | ❌ | ❌ | ❌ |
| `network_flow_id` | ⚠️ `source_ip` only | ❌ | ❌ | ✅ domain | ❌ | ✅ src+dst IP:port |

**Key gaps:**
- `device_id` is hostname only everywhere — no cryptographic host identity. A renamed host breaks all historical correlation.
- `subject_id` is `pid` only — PID reuse (process dies, new process gets same PID) will corrupt correlation unless `boot_uuid + start_time` are added.
- `binary_id` is path only — a renamed binary evades all path-based correlation. No hash, no code signature.
- **No agent can link a user's SSH session → their kernel-level process execution → their network flow.** The session_id/tty chain from auth does not propagate to kernel_audit or proc events.

**Required for fusion engine to work correctly:** Every event must carry at minimum `device_id` (stable) + `principal_id` (uid/username) + `subject_id` (pid + start_time) on every probe emission. Currently, these are present in event `data` fields inconsistently — they are not normalized into a standard envelope.

---

## Section H — Evidence Boundary Analysis

> **What this section asks:** Where does AMOSKYS first become tamper-evident? What would it take to forge or erase an event without detection?

### Current Signing Architecture

```
Agent emits TelemetryEvent
    → queue_adapter (signed envelopes ⚠️)
    → WAL (plain JSON ✅ confirmed)
    → wal_processor reads WAL
    → FusionEngine
    → Dashboard
```

**Verified facts:**
- WAL entries are plain JSON ✅ (confirmed by reading `wal_processor.py`)
- `queue_adapter.py` has "signed envelopes" ⚠️ (referenced but signing key material and mechanism not audited)
- `evidence_chain.py` adds `correlation_id`, `device_id`, `timestamp_ns`, `tags` ✅
- `incident_key` is a 16-char SHA-256 content hash ✅

**The tamper window:** An attacker with root filesystem access can modify WAL entries between write and `wal_processor` read. The WAL is the soft belly. If the signed envelope is at the queue layer (in-memory), but the WAL is the persistence layer, then the "signature" is lost at the persistence boundary.

### Key Management Questions (all ❌ unanswered)

1. **Where are signing keys stored?** (filesystem? HSM? environment variable? hardcoded?)
2. **How are keys rotated?** (rotation schedule? zero-downtime rotation procedure?)
3. **How is key compromise detected?** (no key audit log visible)
4. **Is verification at WAL read time?** (`wal_processor` does not verify signatures — only processes plain JSON)

### Required action

Sign each WAL entry with an HMAC-SHA256 keyed to a host-specific key at write time. Verify at `wal_processor` read. Log verification failures as `agent_health_critical`. This does not require an HSM — a `device_key.pem` per host protected by filesystem permissions is sufficient for v1.

---

## Section I — Performance and Resource Contracts

> **What this section asks:** What is the maximum safe load? What breaks first under pressure? Where is the explicit resource bound?

### Per-Agent Resource Profile

| Agent | Max events/cycle designed | Memory bound | Disk growth (WAL) | Backpressure policy | Health threshold |
|-------|--------------------------|-------------|------------------|---------------------|-----------------|
| auth | ⚠️ unspecified | ⚠️ O(auth_events batch) | ⚠️ WAL only | ⚠️ collector truncation | ❌ none |
| kernel_audit | ⚠️ unspecified | ⚠️ O(batch + pid_to_comm) | ⚠️ WAL only | ✅ kernel drops oldest | ❌ none |
| proc | ⚠️ unspecified | ⚠️ O(reported_pids) unbounded across lifetime | ⚠️ WAL only | ⚠️ 10s scan rate | ❌ none |
| dns | ✅ 100 events/cycle | ❌ `domain_history` unbounded | ⚠️ WAL only | ✅ hard cap at 100, silent | ❌ none explicit |
| fim | ⚠️ unspecified | ⚠️ FSEvents queue (OS-managed) | ⚠️ WAL only | ⚠️ FSEvents coalesces | ❌ none |
| flow | ⚠️ unspecified | ⚠️ O(active connections) | ⚠️ WAL only | ⚠️ scan interval | ❌ none |

**Worst offenders:**

1. **`BeaconingPatternProbe.domain_history` grows without bound** ❌ — every unique domain queried is added to the dict and never evicted. On a busy DNS host (CDN-heavy workload), this could accumulate millions of entries over days. No LRU, no TTL, no max-size cap.

2. **`proc.reported_pids` grows without bound within an agent lifetime** ⚠️ — on a busy server with thousands of short-lived processes, this set grows monotonically. On restart it resets — but between restarts it consumes unbounded memory.

3. **No disk-full handling for WAL writes** ❌ — if the WAL disk fills, WAL writes will raise `OSError`. This exception is not caught or surfaced as a health event. The agent may crash silently.

4. **No maximum batch size for kernel_audit** ❌ — if auditd delivers 10,000 events in one batch (burst after system resume), all 10,000 are processed before the next health check. No circuit breaker at the probe level.

**Required resource bounds:**

| Bound | Recommended value |
|-------|-------------------|
| Max events/cycle per agent | 1000 (configurable) |
| `domain_history` max entries | 50,000 with LRU eviction |
| `reported_pids` max size | 100,000 with oldest-first eviction |
| WAL disk full threshold | Emit `agent_health_critical` at 90% disk usage |
| Max probe execution time | 5s per probe (watchdog kill + health event) |

---

## Section J — Adversary Silencing Playbook

> **For each agent: the 3 easiest ways an attacker with root makes it go dark — and which other agent (if any) compensates.**

### AUTH — Silencing

| Method | Ease | Compensator |
|--------|------|-------------|
| Revoke TCC `full-disk-access` on macOS → logs unreadable | Easy (1 command as root) | kernel_audit may still see failed auths as syscall events ⚠️; FIM detects TCC database write ✅ |
| Truncate log file between cycles (`> /var/log/auth.log`) | Easy (1 command) | FIM detects modification of `/var/log/auth.log` ✅; kernel_audit sees the `open()` truncation ⚠️ |
| Restart sshd with `LogLevel QUIET` + PAM logging disabled | Medium (config change + restart) | FIM detects sshd config modification ✅; kernel_audit sees sshd exec from unusual path ⚠️ |

**Mesh verdict:** FIM is the best compensator for auth silencing — it catches log file tampering and config changes. **This only works if FIM is watching `/var/log/` and `/etc/ssh/` — currently unverified ⚠️.**

---

### KERNEL_AUDIT — Silencing

| Method | Ease | Compensator |
|--------|------|-------------|
| `auditctl -D` (delete all rules) as root | Easy (1 command) | `AuditTamperProbe` catches this IF auditd is still running when the command executes ⚠️; auth sees residual log events ✅ |
| Kill auditd process (`systemctl stop auditd`) | Easy (1 command) | proc sees auditd disappear from process table ⚠️ (if probe is watching for it); auth still logs ✅ |
| Load kernel rootkit that intercepts `audit_log_syscall()` | Hard (requires kernel exploit or signed kext) | `KernelModuleLoadProbe` catches the load event — IF auditd was running when the module loaded ⚠️ |

**Mesh verdict:** auth is the only reliable compensator (continues to log SSH/PAM activity regardless of auditd). A fully silent attacker must blind BOTH auth AND kernel_audit simultaneously. **Neither agent detects the other's failure.**

---

### FIM — Silencing

| Method | Ease | Compensator |
|--------|------|-------------|
| Bind-mount attacker-controlled directory over watched path | Medium (requires root + kernel expertise) | kernel_audit sees `mount` syscall ✅; proc sees mount utility execution ✅ |
| Use `memfd_create` / anonymous fd for file operations → never touches real filesystem | Medium (requires coding) | kernel_audit sees `memfd_create` syscall ⚠️ (if audited); proc sees running process ✅ |
| Disable SIP on macOS (requires reboot to recovery mode) + load kext to suppress FSEvents | Hard (requires physical access or boot args) | Every step in this multi-step attack generates detectable events in auth, kernel_audit, proc ✅ |

**Mesh verdict:** FIM is harder to silence than auth or proc. The compensators are strong. The biggest gap: **FIM has zero red-team coverage, so we don't know if the probes actually fire on these events** ❌.

---

### DNS — Silencing

| Method | Ease | Compensator |
|--------|------|-------------|
| Use DoH (port 443) — all DNS traffic invisible to passive capture | Trivially easy (browser/OS config) | flow sees HTTPS connection to DoH provider (1.1.1.1, 8.8.8.8) ✅; but this is also normal traffic ⚠️ |
| Send > 100 DNS queries/cycle — DGA/beacon probes miss the burst | Easy (any C2 beacon with fast jitter) | ❌ no compensator; this is a pure blind spot within the DNS agent |
| Use split-horizon or container-internal DNS (separate resolver namespace) | Medium | ❌ host-level DNS agent cannot see container-internal resolution |

**Mesh verdict:** DoH is the primary risk, and the only compensator (flow) cannot distinguish DoH to 1.1.1.1 from normal HTTPS to 1.1.1.1. **DNS silencing is trivially achievable by any modern attacker who configures their C2 to use DoH.**

---

### PROC — Silencing

| Method | Ease | Compensator |
|--------|------|-------------|
| Execute and exit in < 10s → never appears in `process_iter` snapshot | Easy (any non-persistent dropper) | kernel_audit `execve` events catch this ✅ |
| DKOM (Direct Kernel Object Manipulation) to hide from `/proc` | Hard (requires kernel exploit) | kernel_audit module load probe sees the rootkit load ⚠️ |
| Rename exe to match a trusted binary (`/usr/bin/sshd`) before scan | Easy (1 `mv` command) | FIM detects new binary in `/usr/bin/` ✅; kernel_audit sees the `mv` syscall ✅ |

**Mesh verdict:** kernel_audit and FIM together are strong compensators for proc silencing. **A fast dropper (run-and-exit in < 10s) is caught by kernel_audit `execve` — this is the strongest cross-agent story in the system today** ✅.

---

### Cross-Agent Compensation Matrix

| Attacker silences → | auth | kernel_audit | proc | dns | fim | flow |
|--------------------|------|-------------|------|-----|-----|------|
| **auth** | — | ⚠️ partial | ❌ | ❌ | ✅ (log tamper) | ❌ |
| **kernel_audit** | ✅ | — | ⚠️ partial | ❌ | ❌ | ❌ |
| **proc** | ❌ | ✅ (execve) | — | ❌ | ✅ (binary drop) | ❌ |
| **dns** | ❌ | ❌ | ❌ | — | ❌ | ⚠️ (DoH to known IP) |
| **fim** | ❌ | ✅ (mount syscall) | ✅ (process) | ❌ | — | ❌ |
| **flow** | ❌ | ❌ | ❌ | ✅ (domain) | ❌ | — |

**Reading the matrix:** "⚠️ partial" = compensator catches some silencing methods but not all. "✅" = reliable compensator. "❌" = no compensation.

**Key insight:** dns silencing has almost no compensation. dns is the agent most beneficial to a sophisticated attacker — and it has zero red-team coverage. This should move it higher in the improvement priority queue.

---

## Section K — Standard Agent Upgrade Pack

> **The assembly line.** Every agent that doesn't yet have a full red-team contract gets this pack in order.

### Template: Agent Upgrade Pack v1

Each agent upgrade produces exactly 4 deliverables:

**Deliverable 1 — Collector Contract Sheet**
Fill in the Collector Truth Contract table (Section F template) with verified ✅ / inferred ⚠️ / missing ❌ for each of the 7 fields. Verify by reading collector code + running a live collection cycle.

**Deliverable 2 — Probe Passports (L0-L3)**
For each probe in the agent: complete the reality passport table (Section B format). Run `amoskys-redteam score` to get the actual L0-L3 levels. Note which probes have correlation tags and which don't.

**Deliverable 3 — Red-Team Contract (minimum 4 cases)**
Write 4 adversarial cases in `scenarios/`:
- `positive`: attacker succeeds, probe fires ≥1 event at expected severity
- `benign`: legitimate activity, probe fires 0 events
- `evasion`: attacker uses known bypass, probe fires 0 events (documented gap)
- `degraded`: production-realistic missing/null fields, probe handles gracefully

Target: `amoskys-redteam run <agent_scenario>` passes all 4 cases.

**Deliverable 4 — Hardening Commits**
Minimum changes to ship with each upgrade pack:
- [ ] Add `correlation_group:*` tag to every probe event emission that doesn't have one
- [ ] Add drop counter to collector (emit `aoc1_collector_events_dropped` metric)
- [ ] Add blindness signal (emit `agent_health_degraded` with `reason=collector_empty` when 0 events received for N cycles)
- [ ] Bound any stateful dicts (`domain_history`, `reported_pids`, etc.) with LRU or TTL eviction

### Agent Upgrade Priority Order

| Priority | Agent | Rationale |
|----------|-------|-----------|
| 1 | **kernel_audit** | Highest-fidelity sensor; drop detection + correlation tags for non-spine probes are the immediate gaps |
| 2 | **auth** | Identity anchor; needs blindness signal + GeoIP gate |
| 3 | **fim** | Kernel-level attachment, SILVER badge, zero red-team — biggest gap between capability and validation |
| 4 | **flow** | Exfil + scanning detection; silencing is hard; payload-blind by design |
| 5 | **dns** | C2 pattern detection; DoH is fundamental limit; collector must be clarified before red-team cases are meaningful |
| 6 | **proc** | Context sensor; execve + psutil together give good coverage; upgrade is incremental |

### kernel_audit Upgrade Pack — v0.1 Targets

The next sprint for kernel_audit specifically:

| Target | Status | Action |
|--------|--------|--------|
| Correlation tags on exec + ptrace | ✅ DONE | Added in this document version |
| Lost-event counter (kernel audit ring buffer) | ❌ | Poll `/proc/audit_lost` or `auditctl -s`; emit `aoc1_collector_events_dropped` metric when > 0 |
| Blindness signal for `auditctl -D` | ❌ | `AuditTamperProbe` already exists; add health event emitted when 0 events received for 2+ cycles |
| "Nasty benign" cases | ❌ | Add: "gdb attaches to own process", "sudo binary calling seteuid as expected", "sshd calling setuid on legitimate login" |
| Capture-based replay case | ❌ | Run `amoskys-redteam capture` against a real `auditctl` session; validate SIM == REPLAY |
| Max batch size bound | ❌ | Add `MAX_EVENTS_PER_CYCLE` to kernel_audit collector; emit health event when cap reached |

---

*End of AMOSKYS Engineering Assessment 0.0*
*Next assessment: Engineering Assessment 0.1 — kernel_audit upgrade pack complete: lost-event counter + blindness signal + nasty benigns + capture replay*
