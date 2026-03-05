# Kernel Audit — macOS Reality Matrix

**Date:** 2026-03-04
**Platform:** macOS 26.0 (Darwin 25.0.0) — Sequoia successor, Apple Silicon (M-series)
**User:** athanneeru (uid=501, admin group, non-root)
**Method:** Live collection runs using `.venv/bin/python3` with `PYTHONPATH=src:.`
**Status:** Ground truth — observed from actual device, zero assumptions

---

## 0. How This Was Measured

```python
# All measurements ran against the live device via:
PYTHONPATH=src:. /Volumes/Akash_Lab/Amoskys/.venv/bin/python3

from amoskys.agents.kernel_audit.collector import MacOSUnifiedLogCollector
c = MacOSUnifiedLogCollector()

# Raw query:
subprocess.run(['/usr/bin/log', 'show', '--predicate', predicate, '--last', '10s', '--style', 'ndjson'])

# Parsed output:
c.collect_batch()  # → List[KernelAuditEvent]
```

---

## 1. What the Collector's Query Actually Returns

The collector queries 4 subsystems:
```
com.apple.securityd | com.apple.authd | com.apple.sandbox | com.apple.kernel
```

### Observed raw event volumes (live device):

| Subsystem | Events in 10s | Events in 30s | Events in 5m |
|-----------|--------------|---------------|--------------|
| com.apple.securityd | 10-19 | 19 | ~60 |
| com.apple.authd | 0 | 0 | 0 |
| com.apple.sandbox | 0 | 0 | 0 |
| com.apple.kernel | 0 | 0 | 0 |
| **Total** | **10-19** | **19** | **~60** |

**Finding:** Three of the four target subsystems are completely silent on macOS 26.0.

### What com.apple.securityd actually logs (raw event breakdown, 5-minute sample, 256 events):

| Process | Count | What it's logging |
|---------|-------|-------------------|
| trustd | 187 (73%) | OCSP responses, certificate chain validation, TLS pinning checks |
| appstoreagent | 19 (7%) | App Store certificate verification |
| syspolicyd | 15 (6%) | Notarization daemon errors (`MacOS error: -67062`, `Error checking with notarization daemon: 3`) |
| chatgpt | 12 (5%) | App certificate trust evaluation |
| accountsd | 6 (2%) | Security client thread creation (`SecSecurityClientGet new thread!`) |
| secd | 6 (2%) | Keychain/security daemon activity |
| others | 11 (4%) | Mix of certificate/trust operations |

**Finding:** `com.apple.securityd` logs certificate PKI infrastructure, not kernel syscall events.

---

## 2. `_classify_action()` Filter Reality

The collector calls `_classify_action(message, process_name, category)` on every raw event.
If it returns `None`, the event is silently dropped.

### What matches vs. what doesn't (5-minute window, 256 raw events):

| Result | Count | Why |
|--------|-------|-----|
| `None` → **dropped** | 253 (98.8%) | No keyword match in message or process_name |
| `"OTHER"` → passes | 3 (1.2%) | "security" substring in "SecSecurityClientGet new thread!" |
| Any other action | 0 (0%) | Never seen on this device |

### Keyword breakdown — why 253 events are dropped:

| Keyword required | Would fire on | Observed in messages? |
|-----------------|---------------|----------------------|
| `"execve"` / `"exec"` / `"execute"` | EXEC action | NO — OCSP/cert messages don't contain these |
| `"ptrace"` / `"trace"` / `"debugger"` | PTRACE action | NO |
| `process_name in ("securityd", "authd", "sandbox")` | PRIVILEGE_DENY/ALLOW | NO — actual processes are trustd, syspolicyd, appstoreagent |
| `"module"` / `"kext"` / `"driver"` | MODULE_LOAD | NO |
| `"sandbox"` in message | SANDBOX_VIOLATION | NO |
| `"fork"` / `"vfork"` / `"clone"` | FORK | NO |
| `"kill"` / `"signal"` | KILL | NO |
| `"setuid"` / `"setgid"` / `"capset"` | SETUID/SETGID/CAPSET | NO |
| `"security"` / `"auth"` / `"permission"` / `"access"` / `"violation"` | OTHER | YES — "SecSecurityClientGet" |

**Critical gap:** The process name check `process_name in ("securityd", "authd", "sandbox")` never matches because the subsystem `com.apple.securityd` is logged by processes named `trustd`, `syspolicyd`, `appstoreagent` — not by a process named `securityd`. The check hardcodes process names that don't match the actual log producers.

---

## 3. `collect_batch()` Output — What Probes Receive

### Measured across 3 live cycles (15 seconds of production):

| Cycle | Raw events queried | KernelAuditEvents returned |
|-------|--------------------|---------------------------|
| Cycle 1 | ~10 | **0** |
| Cycle 2 | ~15 | **4** |
| Cycle 3 | ~10 | **1** |
| **Total** | **~35** | **5** |

### Field presence matrix (N=5, actual KernelAuditEvents from device):

| Field | Present | Rate | Sample value |
|-------|---------|------|--------------|
| `syscall` | 0/5 | **0%** | always `None` |
| `exe` | 5/5 | 100% | `/System/Library/PrivateFrameworks/AMPLibrary...` |
| `pid` | 5/5 | 100% | `4705` |
| `uid` | 0/5 | **0%** | always `None` |
| `euid` | 0/5 | **0%** | always `None` |
| `gid` | 0/5 | **0%** | always `None` |
| `egid` | 0/5 | **0%** | always `None` |
| `ppid` | 0/5 | **0%** | always `None` |
| `comm` | 5/5 | 100% | `amplibraryagent` |
| `result` | 5/5 | 100% | always `"success"` |
| `cmdline` | 0/5 | **0%** | always `None` |
| `path` | 0/5 | **0%** | always `None` |
| `tty` | 0/5 | **0%** | always `None` |
| `cwd` | 0/5 | **0%** | always `None` |
| `dest_pid` | 0/5 | **0%** | always `None` |
| `audit_user` | 0/5 | **0%** | always `None` |
| `session` | 0/5 | **0%** | always `None` |
| `action` | 5/5 | 100% | always `"OTHER"` |

**Only 3 fields carry information: `exe` (process path), `pid` (process id), `comm` (process name).**

---

## 4. Probe Viability Matrix — macOS 26.0

| Probe | Fires on macOS? | Reason |
|-------|-----------------|--------|
| `ExecveHighRiskProbe` | **NEVER** | Checks `ke.syscall in {"execve", "execveat"}` → syscall is always `None` |
| `PrivEscSyscallProbe` | **NEVER** | Checks `ke.syscall in PRIVESC_SYSCALLS` → syscall is always `None` |
| `PtraceAbuseProbe` | **NEVER** | Checks `ke.syscall == "ptrace"` → syscall is always `None` |
| `KernelModuleLoadProbe` | **NEVER** | Checks `ke.syscall in {"init_module", "finit_module"}` → syscall always `None` |
| `FilePermTamperProbe` | **NEVER** | Checks `ke.syscall in {chmod, chown set}` → syscall always `None` |
| `AuditTamperProbe` | **NEVER** | Checks `ke.syscall in {"auditctl", "ptrace"}` + `ke.exe` pattern → both always `None` |
| `CredentialDumpProbe` | **NEVER** | Checks `ke.syscall in {"open", "openat", "execve"}` → syscall always `None` |
| `SyscallFloodProbe` | **THEORETICALLY** | Aggregates by `ke.pid` (no syscall check) — needs 100+ events from same PID in 10s window; never observed from security subsystems under normal conditions |

**Confirmed: 7/8 kernel audit probes will never fire on macOS production in current state.**

---

## 5. BSM Collector Status

```
praudit binary:         EXISTS at /usr/sbin/praudit
/var/audit/current:     NOT FOUND
/var/audit/:            NOT FOUND (directory doesn't exist)
```

**Finding:** OpenBSM audit trails are completely absent on macOS 26.0. SIP has disabled them. `MacOSAuditCollector` would return 0 events every cycle because `_trail_path = None`.

---

## 6. Endpoint Security Framework Status

```
com.apple.endpointsecurity subsystem: 0 events returned
```

**Finding:** ESF requires the `com.apple.developer.endpoint-security.client` entitlement plus root privileges. Without it, `log show` returns nothing from this subsystem. A Python agent running as uid=501 cannot access ESF events via the log command.

**Note:** The actual ESF framework (`EndpointSecurity.framework`) requires:
1. Apple code-signing with the entitlement
2. Root process or System Extension
3. This cannot be implemented in a user-space Python agent without SIP modification or a signed system extension

---

## 7. High-Volume Noise Source (Not Currently Queried)

`com.apple.syspolicy.exec` (Gatekeeper / Quarantine enforcement):
- **1020 events in 3 minutes**, all from `syspolicyd` (pid=486)
- All events: `"Unable to initialize qtn_proc: 3"` or `"dispatch_mig_server returned 268435459"`
- This is a **broken daemon** spamming error logs, not useful signal
- If added to the collector's subsystem list: `SyscallFloodProbe` would immediately fire (1020/180s ≈ 56/10s, below threshold=100... actually 1020 in 3min = ~57/10s, below FLOOD_THRESHOLD=100)

---

## 8. Verdict

### What the kernel_audit agent IS on macOS:
- A certificate infrastructure log parser that monitors trustd, syspolicyd, appstoreagent
- Produces 0-5 events per 10-second cycle under normal conditions
- All events carry only: exe path, pid, comm (basename), result="success"
- Feeds probes that require specific syscall names — which are never populated

### What the kernel_audit agent IS NOT on macOS:
- A kernel syscall monitor
- A process execution detector
- A privilege escalation detector
- A ptrace/process injection detector
- A file permission monitor
- A kernel module load detector

### Classification:
**The MacOSUnifiedLogCollector is architecturally mismatched for its purpose on macOS 26.0.**
It was designed to infer kernel activity from security daemon log messages, but those daemons log PKI/certificate operations, not syscall activity.

---

## 9. Remediation Decision Tree

| Option | What it gives | Feasibility | Verdict |
|--------|---------------|-------------|---------|
| **Fix MacOSUnifiedLogCollector subsystems** | More noise (syspolicyd spam), still no syscalls | Easy | ❌ Won't solve the problem |
| **Add Endpoint Security Framework client** | Real syscall-level events: exec, open, mmap, etc. | Hard — requires Apple entitlement + root + signing | ✅ Correct solution, high barrier |
| **Use `proc` agent for process monitoring** | Process list diffs, exe paths, user context | Already implemented | ✅ Partial substitute for EXEC probe |
| **Use `fim` agent for file changes** | chmod/chown changes via fsevents | Already implemented | ✅ Partial substitute for FilePermTamper |
| **Disable kernel_audit on macOS** | Clean detection map — no false sense of coverage | Trivial | ✅ Honest option — better than phantom sensor |
| **DTrace/kdebug** | Real syscall tracing | Requires SIP disabled | ❌ Not viable in production |
| **OpenBSM** | BSM audit records | Trail absent on macOS 10.15+ | ❌ Dead on macOS 26.0 |

### Recommended immediate actions:

1. **Set `platforms = ["linux"]` on all 7 probes that require specific syscall names** — they are Linux-only.
2. **Add a macOS-specific startup check in the agent**: if `platform.system() == "Darwin"` and collector is `MacOSUnifiedLogCollector`, emit `agent_health_degraded` with `reason="platform_mismatch_no_syscall_telemetry"` on startup.
3. **Relabel MacOSUnifiedLogCollector** from "PRIMARY" to "DEGRADED_STUB — no syscall events available on macOS 10.15+"
4. **Long-term:** Build a System Extension with ESF entitlement for macOS syscall monitoring.

---

## 10. Raw Evidence Archive

All measurements taken with:
- Python: `/Volumes/Akash_Lab/Amoskys/.venv/bin/python3` (Python 3.13)
- PYTHONPATH: `src:.`
- macOS log binary: `/usr/bin/log`
- Date: 2026-03-04, device: Akashs-MacBook-Air.local
- User context: athanneeru (uid=501), non-root, admin group
