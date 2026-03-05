# Kernel Audit — Probe Passports (KA v0.1)

**Date:** 2026-03-03
**Agent:** `kernel_audit`
**Probes covered:** 8 (ExecveHighRisk, PrivEscSyscall, KernelModuleLoad, PtraceAbuse, FilePermissionTamper, AuditTamper, SyscallFlood, CredentialDump)

> Each passport answers: What does this probe claim to detect? What does it actually see? Where does it go blind?

---

## Legend

| Marker | Meaning |
|--------|---------|
| ✅ | Verified — confirmed by reading code + harness |
| ⚠️ | Inferred — reasonable from code; not tested against real OS data |
| ❌ | Gap — not implemented or provably blind |

---

## Probe 1: `ExecveHighRiskProbe`

| Attribute | Value |
|-----------|-------|
| **Name** | `execve_high_risk` |
| **Event type** | `kernel_execve_high_risk` |
| **MITRE** | T1059 (Command and Scripting Interpreter), T1204.002 (User Execution: Malicious File) |
| **Tactics** | Execution, Defense Evasion |
| **Confidence** | 0.75 |
| **Severity range** | MEDIUM (user) → HIGH (setuid or root) |
| **Correlation tag** | `correlation_group:execution` ✅ |
| **Reality score** | L3 ✅ (tags present, harness 225/225) |

**What it watches:**
- `ke.syscall in ("execve", "execveat")` → path checked against `HIGH_RISK_EXEC_PATHS`
- High-risk paths: `/tmp`, `/var/tmp`, `/dev/shm`, `/run/user`, `/home`, `/Users`, `/Users/Shared`
- Severity escalation: `euid=0 and uid!=0` → HIGH; root exec → HIGH; otherwise MEDIUM

**Assumed identity key:** `(ke.host, ke.exe, ke.pid)` — not a stable long-term key; pid wraps.

**What it misses:**
- **Bind-mounted /tmp** — attacker mounts `/dev/sda2` on `/tmp`, exe is at `/tmp/attack` but actual path is elsewhere ❌
- **symlinks** — `/var/www/html/shell.sh` → `/tmp/shell.sh`; exe field shows the symlink target if kernel resolves it, or the source if not ⚠️
- **macOS production** — `MacOSUnifiedLogCollector` does not produce `ke.syscall="execve"`; probe fires 0 events in production ❌ (see KA-G2)
- **Container namespaces** — `/proc/{pid}/root/tmp/` is in container but appears as `/tmp/` to host auditd ⚠️
- **Memory-only execution** — memfd_create + exec via `/proc/self/fd/<n>`; exe path doesn't start with high-risk prefix ❌

**Nasty benigns (must NOT fire):**
- Shell launching from user home: `/Users/alice/bin/myscript` — **FIRES** (starts with `/Users/`) → FP risk for macOS home dirs
- npm package scripts in `~/.npm/_npx/*/node_modules/.bin/`: starts with `/Users/` → **FIRES** → chronic FP on dev systems ❌

**Evasions (documented, attacker wins):**
- Drop binary to `/usr/local/bin/legitimate_name` — does not match any HIGH_RISK_EXEC_PATH ❌
- Use `exec(fd)` via `/proc/self/fd/N` path — path doesn't prefix-match ❌
- Name binary as a trusted process, run from `/usr/bin/` after replacing ❌

---

## Probe 2: `PrivEscSyscallProbe`

| Attribute | Value |
|-----------|-------|
| **Name** | `privesc_syscall` |
| **Event type** | `kernel_privesc_syscall` |
| **MITRE** | T1068 (Exploitation for Privilege Escalation), T1548.001 (Setuid and Setgid) |
| **Tactics** | Privilege Escalation |
| **Confidence** | 0.90 |
| **Severity range** | MEDIUM → HIGH (uid≠euid) → CRITICAL (uid≠0, euid=0) |
| **Correlation tag** | `correlation_group:privilege_escalation` ✅ |
| **Reality score** | L3 ✅ |

**What it watches:**
- `ke.syscall in PRIVESC_SYSCALLS` (setuid, seteuid, setreuid, setresuid, setgid, setegid, setregid, setresgid, setfsuid, setfsgid, capset)
- `ke.result == "success"` — only successful calls flagged ✅
- Escalation: uid≠0 → euid=0 → CRITICAL; uid≠euid → HIGH; otherwise MEDIUM

**Assumed identity key:** `(ke.host, ke.pid, ke.uid, ke.euid)` — pid-scoped

**What it misses:**
- **Legitimate sshd privilege separation** — sshd calls `seteuid` to drop from root to user uid → fires MEDIUM or HIGH ⚠️ (nasty benign)
- **sudo binary itself** — sudo calls setresuid(target_uid, target_uid, 0) to become the target user → fires CRITICAL ⚠️ (FP for every sudo invocation)
- **macOS production** — syscall name not reliably produced by UnifiedLogCollector ❌
- **Capability-based escalation** — `PR_SET_SECUREBITS`, `CLONE_NEWUSER` namespace escalation not covered ❌
- **`setuid(0)` by init scripts** — systemd runs setuid internally on startup → potential FP storm ⚠️

**Nasty benigns:**
1. `sshd` privsep: `uid=0`, calls `seteuid(65534)` (nobody) to drop privileges → fires HIGH (`uid=0 != euid=65534`) — expected false positive
2. `sudo` normal use: uid=1001 → executes setresuid(0,0,0) → fires CRITICAL — will fire for EVERY sudo on the system

**Evasions:**
- User namespace privilege escalation: `unshare(CLONE_NEWUSER)` + `newuidmap` — no setuid syscall involved ❌
- SUID binary exploitation that doesn't call setuid explicitly (already elevated via exec) ❌
- Kernel exploit that directly manipulates `task->cred` ❌

---

## Probe 3: `KernelModuleLoadProbe`

| Attribute | Value |
|-----------|-------|
| **Name** | `kernel_module_load` |
| **Event type** | `kernel_module_loaded`, `kernel_module_unloaded` |
| **MITRE** | T1014 (Rootkit), T1547.006 (Kernel Modules and Extensions) |
| **Tactics** | Persistence, Defense Evasion |
| **Confidence** | 0.85 |
| **Severity range** | MEDIUM (delete) → HIGH (normal load) → CRITICAL (suspicious path or non-root) |
| **Correlation tag** | ❌ Missing — no correlation tag on any event |
| **Reality score** | L2 (no correlation_group tag → fails L3) |

**What it watches:**
- `ke.syscall in MODULE_SYSCALLS` (init_module, finit_module, delete_module)
- Path check: `ke.path` or `ke.cwd` starts with SUSPICIOUS_MODULE_PATHS → CRITICAL
- Non-root load → CRITICAL

**Assumed identity key:** `(ke.host, ke.path, ke.uid)` — module path + caller identity

**What it misses:**
- **macOS production** — no kext loading via init_module; macOS uses `IOKit` and `kextload` → completely blind ❌
- **eBPF programs** — `BPF_PROG_LOAD` syscall is not in MODULE_SYSCALLS ❌
- **DKMS modules** — loaded from `/lib/modules/` (standard path) → fires HIGH (every kernel update triggers this) ⚠️
- **Unsigned module check** — probe doesn't verify module signature; signed rootkits would still fire HIGH ⚠️

**Gap: Missing correlation tag** — all emitted events lack `tags`. Cannot be linked to a kill-chain phase by the fusion engine.

---

## Probe 4: `PtraceAbuseProbe`

| Attribute | Value |
|-----------|-------|
| **Name** | `ptrace_abuse` |
| **Event type** | `kernel_ptrace_abuse` |
| **MITRE** | T1055 (Process Injection), T1055.008 (Ptrace System Calls) |
| **Tactics** | Defense Evasion, Privilege Escalation |
| **Confidence** | 0.85 |
| **Severity range** | MEDIUM → HIGH (non-root) → CRITICAL (protected process or pid=1) |
| **Correlation tag** | `correlation_group:credential_access` ✅ |
| **Reality score** | L3 ✅ (after tag addition) |

**What it watches:**
- `ke.syscall in ("ptrace", "process_vm_readv", "process_vm_writev")`
- `pid_to_comm` map built from same batch — target process name from `ke.comm`
- Protected process list: sshd, sudo, su, passwd, login, cron, systemd, init, auditd, …
- CRITICAL if target in PROTECTED_PROCESSES or dest_pid=1

**Assumed identity key:** `(ke.host, ke.pid, ke.dest_pid)` — attacker pid + target pid

**What it misses:**
- **Debugger on user process** — developer `gdb myapp` where myapp is not in PROTECTED_PROCESSES → fires MEDIUM (non-root ptrace) → FP for every debugging session ⚠️
- **`PTRACE_TRACEME`** — child calling ptrace on itself (for anti-debugging checks) → fires, dest_pid may be None → MEDIUM ⚠️
- **`process_vm_readv` by debugger** — same as above; lldb/gdb on macOS would trigger ⚠️
- **macOS production** — ptrace not exposed via UnifiedLogCollector reliably ❌
- **`SYS_ptrace` via Task ports** (macOS) — macOS process injection via Mach task ports bypasses ptrace entirely ❌
- **perf/eBPF tracing** — `perf_event_open` + ring buffer read is not ptrace but equivalent capability ❌

**Nasty benigns:**
1. Root developer running `gdb /usr/bin/sshd` to debug a production issue → CRITICAL (sshd in PROTECTED_PROCESSES) — legitimate but fires
2. `strace nginx` by non-root developer → HIGH (non-root ptrace)
3. `lldb` on macOS by developer → unlikely to fire (UnifiedLog issue) but semantically: MEDIUM

---

## Probe 5: `FilePermissionTamperProbe`

| Attribute | Value |
|-----------|-------|
| **Name** | `file_permission_tamper` |
| **Event type** | `kernel_file_permission_tamper` |
| **MITRE** | T1222 (File and Directory Permissions Modification), T1222.002 |
| **Tactics** | Defense Evasion, Credential Access |
| **Confidence** | 0.90 |
| **Severity range** | HIGH → CRITICAL (shadow/sudoers or non-root modifying) |
| **Correlation tag** | ❌ Missing |
| **Reality score** | L2 (no correlation_group tag → fails L3) |

**What it watches:**
- `ke.syscall in PERMISSION_SYSCALLS` (chmod, fchmod, fchmodat, chown, fchown, lchown, fchownat)
- `ke.path` checked against `SENSITIVE_FILES` set (exact match + directory prefix match)
- shadow/sudoers → CRITICAL; non-root modifier → CRITICAL

**Assumed identity key:** `(ke.host, ke.path, ke.uid)`

**What it misses:**
- **Numeric fd-based operations** — `fchmod(fd, mode)` where `fd` is a file descriptor for `/etc/shadow`; `ke.path` may be `None` if the PATH record is not correlated ❌
- **macOS sensitive files** — `/etc/master.passwd` is listed; macOS uses `/var/db/dslocal/nodes/Default/users/` which is not in SENSITIVE_FILES ⚠️
- **Extended attributes (xattr)** — `setxattr` not in PERMISSION_SYSCALLS ❌
- **ACL modifications** — `setfacl` / `aclinherit` not monitored ❌

**Gap: Missing correlation tag** — events not linked to any correlation group.

---

## Probe 6: `AuditTamperProbe`

| Attribute | Value |
|-----------|-------|
| **Name** | `audit_tamper` |
| **Event type** | `kernel_audit_tamper`, `kernel_audit_tool_exec` |
| **MITRE** | T1562.001 (Disable or Modify Tools), T1070.002 (Clear Linux or Mac System Logs) |
| **Tactics** | Defense Evasion |
| **Confidence** | 0.95 (file access) / 0.85 (tool exec) |
| **Severity range** | HIGH → CRITICAL |
| **Correlation tag** | ❌ Missing |
| **Reality score** | L2 (no correlation_group tag → fails L3) |

**What it watches:**
- File access: `ke.path` in `AUDIT_FILES` + `ke.syscall in ("open", "openat", "write", "unlink", "truncate")` by non-audit binaries
- Tool exec: `ke.exe` basename in `AUDIT_BINARIES` by non-root

**Assumed identity key:** `(ke.host, ke.comm, ke.uid)`

**What it misses:**
- **Kill signal to auditd** — `ke.syscall == "kill"` branch is a `pass` statement in the code — **completely unimplemented** ❌
- **`auditctl -D` (delete all rules)** — this is an execve of `auditctl`, not a kill. If uid=0, the "non-root" branch won't fire ❌
- **`service auditd stop`** — systemd stopping auditd via SIGTERM; kill branch is pass ❌
- **Log rotation redirect** — replacing `/var/log/audit/audit.log` symlink; unlink of symlink would be caught but rename/overwrite might not be ⚠️
- **macOS** — AUDIT_FILES are Linux paths; macOS has no auditd ⚠️

**Critical code gap** (line 618-621 in probes.py):
```python
if ke.syscall == "kill" and ke.dest_pid:
    # We'd need to track auditd's PID - for now flag any kill
    # that comes from suspicious context
    pass  # ← UNIMPLEMENTED
```
The kill-auditd detection is empty. An attacker sending `kill -9 $(pidof auditd)` is completely invisible to this probe.

---

## Probe 7: `SyscallFloodProbe`

| Attribute | Value |
|-----------|-------|
| **Name** | `syscall_flood` |
| **Event type** | `kernel_syscall_flood` |
| **MITRE** | T1592 (Gather Victim Host Information), T1083 (File and Directory Discovery) |
| **Tactics** | Reconnaissance, Discovery |
| **Confidence** | 0.70 |
| **Severity range** | MEDIUM → HIGH |
| **Correlation tag** | ❌ Missing |
| **Reality score** | L2 (no correlation_group tag → fails L3) |

**What it watches:**
- Per-PID syscall count ≥ 100 in the current batch → MEDIUM
- If ≥ 50 failures in that batch → HIGH
- Threshold: `FLOOD_THRESHOLD = 100`, `FAILURE_THRESHOLD = 50`

**What it misses:**
- **Cross-PID flood** — attacker uses a process pool, each <100 syscalls → zero detection ❌
- **Batch window dependency** — threshold is per-batch, not per-time-window. Slow flood across cycles: each cycle ≤ 99 syscalls → never fires ❌
- **Normal busy processes** — a database doing 100+ open/close calls in a cycle fires MEDIUM → FP risk ⚠️
- **No state between cycles** — flood that spans two collection cycles is invisible ❌

---

## Probe 8: `CredentialDumpProbe`

| Attribute | Value |
|-----------|-------|
| **Name** | `credential_dump` |
| **Event types** | `credential_file_access`, `known_cred_dump_tool`, `keychain_security_exec`, `masquerade_whitelist_break`, `keychain_burst`, `cross_pid_cred_burst` |
| **MITRE** | T1003 (OS Credential Dumping), T1555 (Password Stores), T1555.001 (Keychain) |
| **Tactics** | Credential Access |
| **Confidence** | 0.90-0.98 |
| **Severity range** | MEDIUM → CRITICAL |
| **Correlation tag** | `correlation_group:credential_access` ✅ (via `_TAG_CRED_ACCESS` constant) |
| **Reality score** | L3 ✅ |

**What it watches (3 vectors):**
1. **Direct file access** (open/openat): macOS user DB plist, Keychain databases, Linux shadow files
2. **Tool execution** (execve): mimikatz, lazagne, chainbreaker + `security` CLI + `dscl` + sqlite3
3. **Burst detection** (stateful): >10 `security find-*` calls from one PID in 60s; cross-PID burst by same uid

**Strongest probe in the agent** — most thoughtfully designed ✅

**Assumed identity key:** `(ke.host, ke.pid, ke.uid)` for burst; `(ke.host, ke.path, ke.comm)` for file access

**What it misses:**
- **macOS production fidelity** — Vector 1 requires `ke.syscall == "open"/"openat"` + `ke.path`. MacOSUnifiedLogCollector does not produce these reliably ❌
- **In-memory keychain dump** — `SecKeychainFindGenericPassword()` C API call does not produce a file open syscall ❌
- **Encrypted keychain dump** — if attacker has the keychain password, legitimate API calls are used; no anomaly ❌
- **Whitelist spoofing gap (documented)** — `_CRED_WHITELIST_EXE_PATHS` checks comm vs. expected exe path; only catches prctl() spoofing, not LD_PRELOAD ⚠️

---

## Summary Table

| Probe | Event type(s) | Correlation tag | Reality L | Biggest gap |
|-------|--------------|-----------------|-----------|-------------|
| ExecveHighRiskProbe | `kernel_execve_high_risk` | `execution` ✅ | L3 | macOS blind; `/Users/` FP |
| PrivEscSyscallProbe | `kernel_privesc_syscall` | `privilege_escalation` ✅ | L3 | sudo/sshd FP storm |
| KernelModuleLoadProbe | `kernel_module_loaded` | ❌ None | L2 | No tag; DKMS FP; macOS N/A |
| PtraceAbuseProbe | `kernel_ptrace_abuse` | `credential_access` ✅ | L3 | gdb FP; macOS Mach port blind |
| FilePermissionTamperProbe | `kernel_file_permission_tamper` | ❌ None | L2 | No tag; fchmod fd gap |
| AuditTamperProbe | `kernel_audit_tamper` | ❌ None | L2 | kill-auditd branch is `pass` |
| SyscallFloodProbe | `kernel_syscall_flood` | ❌ None | L2 | No cross-cycle state; DB FP |
| CredentialDumpProbe | 6 event types | `credential_access` ✅ | L3 | macOS API blind; in-memory gap |

**Probes at L3 (production-ready tag coherence):** 4/8
**Probes at L2 (missing correlation tag):** 4/8
**Probes with critical unimplemented code:** 1 (AuditTamperProbe kill branch)
**Probes blind on macOS production:** 6/8 (all except CredentialDumpProbe tool-exec vector and FilePermissionTamperProbe for setuid-owned files)

---

## Recommended Priority Fixes

1. **Add `correlation_group:*` tags** to KernelModuleLoadProbe, FilePermissionTamperProbe, AuditTamperProbe, SyscallFloodProbe — bring all 8 to L3
2. **Implement kill-auditd detection** in AuditTamperProbe — track auditd PID from a startup scan
3. **Fix macOS collection gap** — replace UnifiedLogCollector with Endpoint Security Framework (ESF) or at minimum add startup permission check + blindness signal
4. **Add sshd/sudo whitelist** to PrivEscSyscallProbe — reduces FP storm on production systems
5. **Add DKMS path whitelist** to KernelModuleLoadProbe — `/lib/modules/`, `/usr/lib/modules/` are legitimate load paths
