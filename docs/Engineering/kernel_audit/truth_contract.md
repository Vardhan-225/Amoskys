# Kernel Audit Agent — Collector Truth Contract (KA v0.1)

**Date:** 2026-03-03
**Agent:** `kernel_audit`
**Auditor:** Code-level inspection + probe harness output
**Status:** v0.1 — first engineering deep-dive

> This document specifies what the kernel audit collector actually delivers vs. what the probes assume. Every gap is a live detection blind spot.

---

## 1. Source Primitive

The kernel audit agent uses **three distinct collectors** depending on platform:

| Collector | Platform | Source Primitive | File/API | Status |
|-----------|----------|-----------------|----------|--------|
| `AuditdLogCollector` | Linux | Log file parser | `/var/log/audit/audit.log` | ✅ implemented |
| `MacOSAuditCollector` | macOS (legacy) | OpenBSM binary trail | `/var/audit/current` via `praudit -x` | ⚠️ broken on macOS 10.15+ (SIP disables BSM audit trails) |
| `MacOSUnifiedLogCollector` | macOS (primary) | Unified Logging NDJSON | `log show --last 10s` subprocess | ✅ implemented, ⚠️ severe fidelity gaps (see §4) |

**Architecture note:** The collector runs in the agent's main loop and injects `List[KernelAuditEvent]` into `context.shared_data["kernel_events"]`. Probes never touch the OS source directly.

---

## 2. Parser Fidelity

### 2a. Linux `AuditdLogCollector` (✅ strong fidelity)

**What arrives:**
- `type=SYSCALL` records only — `PATH`, `EXECVE`, `PROCTITLE`, `AVC` records are **silently dropped** (✅ `_build_event` returns None for non-SYSCALL types)
- Multi-record events (SYSCALL + PATH) are **not correlated** — path enrichment from `PATH` records is lost ⚠️
- `result` field: correctly mapped (`success=yes` → `"success"`) ✅
- `exe` field: comes from `fields.get("exe")` — present on execve/execveat, absent on many other syscalls ⚠️
- `comm` field: correctly parsed from `comm=` key ✅
- Syscall name: resolved via `SYSCALL_MAP` (x86_64 only — ARM64, i386 syscall numbers differ) ⚠️

**What does NOT arrive:**
- Audit arguments: `EXECVE a0= a1= a2=` (args) records are silently dropped — `cmdline` always `None` from auditd ❌
- Return values: `retval` (the actual return value, not just success/fail) not captured ❌
- Parent process name: `ppid` parsed but `ppid_comm` not available ❌
- Network context: connect/bind/listen syscall details (remote IP, port) not in SYSCALL record ❌

**Resume cursor:** inode + file offset (byte position). Detects log rotation by inode change ✅. Handles log truncation (size < offset) ✅. **No sequence number** — if agent restarts, all events since last offset are re-read ⚠️.

### 2b. macOS `MacOSAuditCollector` (⚠️ broken on modern macOS)

- OpenBSM trails are disabled on macOS 10.15+ due to SIP ❌
- `praudit -x` will fail or return empty output on modern macOS ⚠️
- `ppid` is missing from BSM subject token — always `None` ✅ (documented in code)
- `tty`, `cwd` missing — always `None` ✅ (documented)
- Resume cursor: record count (`_record_offset`) — not a stable ID, resets on trail rotation ⚠️

### 2c. macOS `MacOSUnifiedLogCollector` (⚠️ severe fidelity gap — PRIMARY collector)

**Critical architecture flaw:**
```python
QUERY_WINDOW = "10s"
cmd = ["log", "show", "--predicate", predicate, "--last", self.QUERY_WINDOW, "--style", "ndjson"]
```

- **No cursor, no sequence number.** Every poll re-queries the last 10 seconds from wall clock. ❌
- **Overlap gap:** If the agent stalls for 11+ seconds, events in that gap are **permanently lost**. ❌
- **Duplicate delivery:** Events near the 10s boundary are likely re-delivered every cycle. ❌
- **No uid/euid:** Unified log entries do not carry uid/euid — `uid` is regex-extracted from message string (unreliable) ⚠️
- **No pid→comm mapping:** Process name derived from `processImagePath` (reliable) but pid conflicts are unresolved ❌
- **Action classification by keyword match:** `"trace" in message` → PTRACE, `"exec" in message` → EXEC — extremely noisy, high FP rate ❌
- **No sys call field:** Unified log has no "syscall" field — action is inferred from message text. Probes that filter on `ke.syscall == "execve"` will never fire from this collector. ❌

**Implication:** On macOS (the primary platform), `ExecveHighRiskProbe`, `PrivEscSyscallProbe`, `PtraceAbuseProbe`, and `KernelModuleLoadProbe` will almost never fire from real production data because they filter on specific `ke.syscall` values that the unified log collector does not reliably produce.

---

## 3. Ordering Guarantee

| Collector | Ordering | Notes |
|-----------|----------|-------|
| `AuditdLogCollector` | File-line order (kernel write order) | ✅ auditd serializes to file sequentially |
| `MacOSAuditCollector` | BSM record order (kernel write order) | ✅ when working; broken on modern macOS |
| `MacOSUnifiedLogCollector` | **No guaranteed order** | ⚠️ `log show` may reorder; 10s window causes non-monotonic batches |

**No global timestamp ordering across collectors.** If multiple agents run on the same host, their events are not globally sorted before WAL write.

---

## 4. Resume Cursor

| Collector | Cursor type | Gap on restart |
|-----------|-------------|----------------|
| `AuditdLogCollector` | `(inode, byte_offset)` in-memory | ⚠️ Lost on agent restart — re-reads from end of file (start_at_end=True by default) |
| `MacOSAuditCollector` | `record_count` in-memory | ⚠️ Lost on restart — resets to end |
| `MacOSUnifiedLogCollector` | None (wall-clock window) | ❌ Events during downtime permanently lost |

**No persistent cursor.** `_offset` and `_record_offset` are instance variables — they are **not persisted** to disk. An agent restart silently loses all events that occurred during downtime. On macOS with the unified log collector, any downtime longer than 10 seconds is a detection gap.

**Remediation:** Persist cursor to `data/state/kernel_audit_cursor.json` on clean shutdown and load on startup. For Linux, use `(inode, offset)`. For macOS, use the unified log's `--start` timestamp parameter.

---

## 5. Drop Accounting

**Current state:** No drop accounting. ❌

The Linux auditd subsystem exposes drop counts via `/proc/audit_lost` (or `auditctl -s`). The current agent:
- Does not poll `/proc/audit_lost` ❌
- Does not emit any event when events are dropped ❌
- Does not emit any event when the collector returns empty on an expected-busy cycle ❌

**Linux auditd backpressure:** When the kernel audit ring buffer fills (e.g., during a syscall flood), records are silently dropped. `auditctl -s` output includes `lost` and `backlog` fields. The agent never reads these.

**What the agent should emit (not yet implemented):**
```python
# L-DROP: emit when /proc/audit_lost increases between cycles
TelemetryEvent(
    event_type="kernel_audit_drop_detected",
    severity=Severity.HIGH,
    data={"lost_count": delta_lost, "backlog": current_backlog}
)
```

---

## 6. Blindness Signal

**Current state:** No blindness signal. ❌

When the collector returns 0 events for N consecutive cycles, the agent is either:
- (a) On a quiet system (no relevant syscalls)
- (b) Missing permissions
- (c) auditd stopped or rules deleted
- (d) Agent misconfigured

Currently, all four cases are indistinguishable. No `agent_blind` or `agent_health_degraded` event is emitted.

**What should be implemented (not yet implemented):**
```python
# After 2 consecutive zero-event cycles (configurable):
TelemetryEvent(
    event_type="agent_health_degraded",
    severity=Severity.HIGH,
    data={
        "agent": "kernel_audit",
        "reason": "zero_events_consecutive_cycles",
        "cycle_count": self._zero_cycles,
        "collector_type": type(self._collector).__name__,
    }
)
```

**Permission detection (Linux):** On startup, check if `/var/log/audit/audit.log` is readable. If not, emit `agent_health_degraded` with `reason="permission_missing"` immediately.

---

## 7. Collector Truth Summary Table

| Contract Clause | Linux auditd | macOS Unified Log | macOS BSM |
|-----------------|-------------|-------------------|-----------|
| Source primitive | ✅ SYSCALL record | ❌ Message-text heuristic | ✅ BSM record |
| Parser fidelity | ✅ Strong | ❌ Keyword match only | ✅ Good (when working) |
| Ordering | ✅ File-line order | ⚠️ Not guaranteed | ✅ BSM order |
| Resume cursor | ⚠️ In-memory only | ❌ None | ⚠️ In-memory only |
| Drop accounting | ❌ Not implemented | ❌ Not implemented | ❌ Not implemented |
| Blindness signal | ❌ Not implemented | ❌ Not implemented | ❌ Not implemented |
| uid/euid | ✅ auditd fields | ⚠️ Regex from message | ✅ BSM subject token |
| cmdline/args | ❌ EXECVE records dropped | ❌ Not available | ⚠️ exec_args token only |
| ppid | ✅ auditd field | ❌ Not available | ❌ Not in BSM |
| Multi-record events | ❌ PATH records dropped | n/a | ✅ XML parses all tokens |

---

## 8. Gap Priority

| # | Gap | Severity | Affects |
|---|-----|----------|---------|
| KA-G1 | macOS UnifiedLogCollector has no cursor — 10s polling window loses events during downtime | CRITICAL | Production macOS (primary platform) |
| KA-G2 | `ke.syscall` inferred from message keywords on macOS — probes filter by exact syscall name and will not fire | CRITICAL | All probes on macOS production |
| KA-G3 | No drop accounting — kernel ring buffer overflows are silent | HIGH | Linux production under load |
| KA-G4 | No blindness signal — permission loss or auditd stop is undetectable | HIGH | All platforms |
| KA-G5 | Multi-record event correlation missing — PATH records lost (exe path gap) | MEDIUM | Linux: ExecveHighRiskProbe accuracy |
| KA-G6 | In-memory cursor lost on restart — silent gap on every restart | MEDIUM | All platforms |
| KA-G7 | EXECVE argument records dropped — cmdline always None from auditd | MEDIUM | Linux: CredentialDumpProbe, AuditTamperProbe |

---

## 9. Remediation Roadmap

**KA v0.2 (next sprint):**
- [ ] Persist cursor to disk (`data/state/kernel_audit_cursor.json`)
- [ ] Implement `/proc/audit_lost` polling on Linux; emit `kernel_audit_drop_detected` on increase
- [ ] Implement zero-cycle counter; emit `agent_health_degraded` after 2 consecutive empty batches
- [ ] Replace macOS `MacOSUnifiedLogCollector` keyword matching with Endpoint Security Framework (ESF) via `endpointsecurityd` — provides real syscall-level events

**KA v0.3:**
- [ ] Correlate SYSCALL + PATH + EXECVE multi-record groups by audit serial number (Linux)
- [ ] Emit `agent_health_degraded` on startup permission check failure
- [ ] Windows: ETW provider `Microsoft-Windows-Kernel-Process` as reference architecture
