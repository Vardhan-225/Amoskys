# Kernel Audit Agent — macOS Sensor Truth

**Date:** 2026-03-04
**Author:** Live device interrogation (not documentation-derived)
**Device:** Akashs-MacBook-Air.local — macOS 26.0 (Darwin 25.0.0)

---

## What AMOSKYS kernel_audit is on this machine

### The sensor loop, in plain English:

Every 10 seconds, the agent runs:

```
/usr/bin/log show
  --predicate '(subsystem == "com.apple.securityd" OR subsystem == "com.apple.authd"
                OR subsystem == "com.apple.sandbox" OR subsystem == "com.apple.kernel")'
  --last 10s
  --style ndjson
```

It gets back 10-19 JSON objects. These are:
- trustd checking TLS certificate chains for weather apps, App Store
- syspolicyd failing to verify code signatures (notarization daemon error -67062)
- accountsd creating a new security client thread

The collector runs `_classify_action()` on each message. 98% return `None` → dropped.
The 1-2% that pass have `action="OTHER"` and `syscall=None`.

Probes receive KernelAuditEvents where only `exe`, `pid`, `comm` are populated.
The syscall field — which all 7 security probes depend on — is always `None`.

**Net effect: 7 of 8 kernel audit probes fire zero detections. The sensor exists but sees nothing.**

---

## The ground truth numbers

| Metric | Value | Measured how |
|--------|-------|-------------|
| Raw log events per 10s cycle | 10–19 | `log show --last 10s` |
| KernelAuditEvents per cycle | 0–4 | `c.collect_batch()` live |
| Events with syscall populated | 0/all | Field matrix on N=5 |
| Events with uid populated | 0/all | Field matrix on N=5 |
| Probe firings per cycle on macOS | 0 | All 7 syscall-checking probes |
| BSM trail present | NO | `/var/audit/` doesn't exist |
| ESF accessible without entitlement | NO | Returns 0 events |

---

## What changed (code fix applied 2026-03-04)

Changed `platforms` on 7 Linux-only probes from `["linux", "darwin"]` → `["linux"]`:

| Probe | Before | After |
|-------|--------|-------|
| ExecveHighRiskProbe | ran on macOS, 0 firings | **disabled on macOS** |
| PrivEscSyscallProbe | ran on macOS, 0 firings | **disabled on macOS** |
| KernelModuleLoadProbe | ran on macOS, 0 firings | **disabled on macOS** |
| PtraceAbuseProbe | ran on macOS, 0 firings | **disabled on macOS** |
| FilePermissionTamperProbe | ran on macOS, 0 firings | **disabled on macOS** |
| AuditTamperProbe | ran on macOS, 0 firings | **disabled on macOS** |
| CredentialDumpProbe | ran on macOS, 0 firings | **disabled on macOS** |
| SyscallFloodProbe | ran on macOS | **still enabled** (no syscall dependency) |

This is an honest declaration of what works. The agent still runs its collection loop on macOS.
It still emits `agent_health_degraded` if empty cycles accumulate. But it no longer silently claims
to detect execve/ptrace/privesc on a platform where that's architecturally impossible.

---

## What AMOSKYS needs to actually monitor kernel events on macOS

### Path A: Endpoint Security Framework (ESF) — correct, high effort
- Build a macOS System Extension with the `com.apple.developer.endpoint-security.client` entitlement
- Must be code-signed by Apple, run as root, install as a system extension
- Provides: real exec/open/mmap/ptrace/fork events with full context (pid, ppid, uid, euid, cmdline)
- Timeline: requires Apple notarization approval + signed binary distribution

### Path B: Use existing agents for partial coverage — available now
The other AMOSKYS agents already cover some of what kernel_audit would detect:

| What kernel_audit would detect | What already covers it |
|--------------------------------|----------------------|
| Process execution (execve) | `proc` agent — psutil process list, exe paths, temp dir launches |
| File permission changes | `fim` agent — fsevents, chmod/chown via file system events |
| Network connections | `flow`/`dns`/`net_scanner` agents |
| Authentication events | `auth` agent — /var/log/auth.log, PAM |
| App execution policy | None (would need ESF or syspolicyd integration) |

Missing entirely without ESF:
- Privilege escalation (setuid/seteuid) — no agent covers this on macOS
- Ptrace/process injection — no agent covers this on macOS
- Kernel module loads — no agent covers this on macOS (kext loading is differently structured)
- `auditctl` / audit infrastructure tampering — macOS doesn't have auditd

---

## Summary: The honest state

```
kernel_audit on macOS 26.0:
  Sensor:    DEGRADED — queries certificate infrastructure, not kernel primitives
  Coverage:  1/8 probes active (SyscallFloodProbe — limited utility)
  Blind to:  execve, setuid/seteuid, ptrace, module load, chmod/chown, credential access
  Fix path:  Endpoint Security Framework system extension (long-term)
             Partially compensated by proc + fim + auth agents (now)
```
