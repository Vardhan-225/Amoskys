# Proc Agent — macOS Reality Matrix

**Date:** 2026-03-04
**Platform:** macOS 26.0 (Darwin 25.0.0), Apple Silicon
**User:** athanneeru (uid=501, admin group, non-root)
**Method:** Live psutil collection + probe execution on actual device
**Status:** Ground truth — zero assumptions

---

## 0. Source Primitive

```python
psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'ppid',
                     'create_time', 'cpu_percent', 'memory_percent', 'status', 'cwd'])
```

**Snapshot speed:** ~5ms for 636 processes.
**Collection interval:** 5.0 seconds default.

---

## 1. Field Presence Matrix (N=636 processes, live device)

| Field | Present | Absent | Rate | Notes |
|-------|---------|--------|------|-------|
| `pid` | 636 | 0 | **100.0%** | Always present |
| `name` | 636 | 0 | **100.0%** | Truncated to ~16 chars on macOS |
| `exe` | 635 | 1 | **99.8%** | Only `kernel_task` (pid=0) missing |
| `cmdline` | 387 | 249 | **60.8%** | Permission boundary — see below |
| `username` | 636 | 0 | **100.0%** | Always present |
| `ppid` | 636 | 0 | **100.0%** | Always present |
| `create_time` | 636 | 0 | **100.0%** | Unix timestamp, reliable |
| `cpu_percent` | 387 | 249 | **60.8%** | Same boundary as cmdline |
| `memory_percent` | 387 | 249 | **60.8%** | Same boundary as cmdline |
| `status` | 636 | 0 | **100.0%** | running/sleeping/zombie |
| `cwd` | 387 | 249 | **60.8%** | Same boundary as cmdline |

### The Permission Boundary

The 60.8% rate is a **user/system split**, not data quality:

| Process owner | Has cmdline | Rate |
|---------------|-------------|------|
| Current user (athanneeru) | 386/386 | **100%** |
| root | 1/155 | **0.6%** (only launchd) |
| System service users (_rmd, _locationd, etc.) | 0/95 | **0%** |

**As uid=501, psutil cannot read cmdline/cpu/memory/cwd of root or system-service processes.**
This is macOS sandboxing, not a bug. To see all processes: need root.

---

## 2. Probe Viability Matrix (10 probes, live device)

| Probe | Fires on macOS? | FP Found? | Detail |
|-------|-----------------|-----------|--------|
| `ProcessSpawnProbe` | **YES** | No | Detected Docker process spawn correctly |
| `LOLBinExecutionProbe` | **YES** | No | zsh/bash at LOW severity (correct classification) |
| `ProcessTreeAnomalyProbe` | **CONDITIONAL** | — | Did not fire (no suspicious parent→child chains present) |
| `HighCPUAndMemoryProbe` | **CONDITIONAL** | — | Did not fire (no sustained high CPU/mem in test window) |
| `LongLivedProcessProbe` | **CONDITIONAL** | — | Did not fire (no utility processes running >1 hour) |
| `SuspiciousUserProcessProbe` | **YES** | **FP** | mysqld flagged as "wrong user" — see FP-1 |
| `BinaryFromTempProbe` | **YES** | **FP** | 13 VS Code processes flagged — see FP-2 |
| `ScriptInterpreterProbe` | **CONDITIONAL** | — | Did not fire (no suspicious patterns in cmdlines) |
| `DylibInjectionProbe` | **DEGRADED** | — | `ps eww` returns only 2 lines as uid=501 — see BLIND-1 |
| `CodeSigningProbe` | **YES** | **FP** | `codesign /usr/bin/sudo` → "Permission denied" — see FP-3 |

### Integration Badge: **SILVER**

Criteria assessment:
- exe path present >95%: **YES** (99.8%) ✅
- cmdline present >80%: **NO** (60.8%) — but 100% for user processes ⚠️
- start_time captured and monotonic: **YES** ✅
- PID reuse safely handled: **YES** (process_guid = sha256(device:pid:create_time_ns)) ✅
- cursor/state persisted: **NO** — ProcessSpawnProbe state (`_seen_pids`) is in-memory ❌
- documented miss window: **NO** — no health signal for polling gaps ❌

---

## 3. False Positive Stories (Nasty Benigns)

### FP-1: SuspiciousUserProcessProbe — mysqld as non-root

```
event_type: process_wrong_user
severity: HIGH
pid: 1361, name: mysqld, username: athanneeru
expected_user: root/SYSTEM
```

**Why it's wrong:** MySQL is designed to run as a non-root user. On Homebrew, it runs as the
installing user. Running mysqld as root is a *security anti-pattern*. The probe's
`_ROOT_ONLY_PROCESSES` list incorrectly includes `mysqld`.

**Fix:** Remove `mysqld` (and `postgres`) from `_ROOT_ONLY_PROCESSES`. These are designed
to drop privileges or run as service accounts.

### FP-2: BinaryFromTempProbe — macOS App Translocation (13 false positives)

```
event_type: execution_from_temp
severity: HIGH
exe: /private/var/folders/yr/.../T/AppTranslocation/4E9D3B3F-.../Visual Studio Code.app/...
```

**Why it's wrong:** macOS **App Translocation** is a Gatekeeper security feature that runs
apps from a randomized path under `/private/var/folders/*/T/AppTranslocation/` when the app
hasn't been moved to /Applications yet. This is the OS *enforcing security*, not malware.

**Fix:** Add `AppTranslocation` path exemption:
```python
if "AppTranslocation" in exe_path:
    return None  # macOS Gatekeeper security feature
```

### FP-3: CodeSigningProbe — Permission denied on /usr/bin/sudo

```
event_type: code_signature_invalid
severity: HIGH
binary_path: /usr/bin/sudo
codesign_error: /usr/bin/sudo: Permission denied
```

**Why it's wrong:** `codesign --verify --deep /usr/bin/sudo` requires root on macOS.
As uid=501, we get "Permission denied" — this is NOT an invalid signature.
Also: `/usr/libexec/securityd` (on the probe's critical binary list) doesn't exist on macOS 26.0.

**Fix:** The probe must either:
- Run `codesign` with `sudo` (requires privilege escalation, not appropriate)
- Catch "Permission denied" errors and emit a health signal instead of HIGH alert
- Remove binaries that require root for verification from the non-root list

---

## 4. Blind Spots

### BLIND-1: DylibInjectionProbe — Only sees own processes

```python
# Probe runs:
subprocess.run(['ps', 'eww', '-o', 'pid,command'], ...)
# Result: only 2 lines (header + one user process)
```

**Impact:** As uid=501, `ps eww` cannot see environment variables of root/system processes.
If a rootkit injects DYLD_INSERT_LIBRARIES into a root process, this probe cannot detect it.

**Detection scope:** Only user-level dylib injection (self-injection or injection into
other user-owned processes). Root-level injection requires root access to detect.

### BLIND-2: Temporal miss window — fast-exec between polls

```
Polling interval: 5.0 seconds
Snapshot duration: ~5ms
Miss probability for process living < 5s: ~99.9%
```

**Impact:** A malware dropper that executes, runs payload, and exits in <5 seconds will
not appear in any psutil snapshot. This is inherent to polling-based process monitoring.

**On Linux:** Compensated by KernelAuditAgent (auditd EXEC records for every execve).
**On macOS:** No compensation available — proc polling is the only execution visibility.

### BLIND-3: Script-from-temp evasion

```python
# Execute: /tmp/malicious_script.sh
# psutil sees: exe=/bin/bash, cmdline=['/bin/bash', '/tmp/malicious_script.sh']
```

**Impact:** BinaryFromTempProbe checks `exe` path, not `cmdline` entries. A script
executed from /tmp shows the interpreter as `exe`, not the script path. The `/tmp` path
is only in `cmdline[1]`, which the probe doesn't check.

**Fix:** Also check `cmdline[0]` and `cmdline[1]` for temp directory patterns.

### BLIND-4: Compiled binary from /tmp — exe sometimes None

```python
# Copy /bin/sleep to /tmp/payload, execute it
# psutil sees: pid=4767, name=amoskys_test_bin, exe=None, cmdline=None
```

**Impact:** Some compiled binaries executed from /tmp show `exe=None` in psutil on macOS.
This is likely a macOS security restriction or timing issue. When `exe=None`, the probe
has no path to check and the execution goes undetected.

---

## 5. Temporal Truth

### Snapshot Timing
```
psutil.process_iter() for 636 processes: ~5ms
Agent poll interval: 5.0s default
Effective temporal resolution: 5000ms ± scheduling jitter
```

### Process Age Distribution (live)
```
< 1 min:    5 processes
1-10 min:  10 processes
10-60 min: 372 processes
1-24h:      0 processes
> 24h:      0 processes
```

### Miss Rate by Process Dwell Time

| Process lifetime | Catch probability per poll | Catch in 60s (12 polls) |
|-----------------|---------------------------|-------------------------|
| < 10ms | ~0.1% | ~1.2% |
| 100ms | ~0.1% | ~1.2% |
| 1 second | ~0.1% | ~1.2% |
| 5 seconds | ~0.1% | ~1.2% |
| 10 seconds | 100% (spans 2 polls) | 100% |
| 30 seconds | 100% | 100% |

Any process living longer than the poll interval is guaranteed to be seen.
Any process living shorter than the poll interval has only a snapshot-window/interval chance.

---

## 6. Comparison: PROC vs Kernel Audit on macOS

| Capability | Kernel Audit (macOS) | Proc Agent (macOS) |
|-----------|---------------------|-------------------|
| Process execution | **NEVER** (syscall=None) | **YES** (psutil, 5s latency) |
| Execution path | Never | 99.8% (exe field) |
| Command line | Never | 60.8% (100% for user procs) |
| Parent process | Never | 100% (ppid) |
| User context | Never | 100% (username) |
| Code signing | Never | Partially (needs root for some binaries) |
| Dylib injection | Never | Partially (own processes only) |
| Privilege escalation | Never | Indirectly (via wrong-user detection) |
| Temporal resolution | N/A (0 events) | 5-second poll window |
| Short-lived process | N/A | BLIND (<5s processes missed) |

**Verdict:** Proc agent is the actual execution visibility sensor on macOS.
Kernel audit provides nothing on macOS. Proc provides imperfect but real data.

---

## 7. Remediation Priority

| # | Issue | Severity | Fix |
|---|-------|----------|-----|
| P-1 | BinaryFromTempProbe: AppTranslocation FP storm | HIGH | Whitelist `AppTranslocation` in path |
| P-2 | CodeSigningProbe: Permission denied → FP | HIGH | Catch permission errors, emit health signal not alert |
| P-3 | SuspiciousUserProcessProbe: mysqld/postgres wrong expectation | MEDIUM | Remove from ROOT_ONLY list |
| P-4 | BinaryFromTempProbe: script-from-temp evasion | MEDIUM | Also check cmdline entries for temp paths |
| P-5 | DylibInjectionProbe: blind to root processes | LOW | Document limitation; requires root for full coverage |
| P-6 | ProcessSpawnProbe: no persistent state across restart | LOW | Persist _seen_pids to disk |
| P-7 | No health signal for temporal miss window | LOW | Emit `agent_health_info` with poll interval and miss rate |

---

## 8. Raw Evidence

All measurements taken with:
- Python: `.venv/bin/python3` (Python 3.13)
- psutil version: current from .venv
- Device: Akashs-MacBook-Air.local, macOS 26.0
- User: athanneeru (uid=501), non-root, admin group
- Date: 2026-03-04
