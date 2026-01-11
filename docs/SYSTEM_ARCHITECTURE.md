# AMOSKYS System Architecture - Ground Truth

**Current State Analysis**: What exists, where state lives, boundaries, assumptions, and failure modes.

---

## 1. Components (What Exists)

### 1.1 Agent Layer (Data Collection)

**8 Implemented v2 Agents:**

| Agent | Purpose | State Storage | Output Protocol |
|-------|---------|---------------|-----------------|
| **ProcAgentV2** | Process tree monitoring | In-memory baseline (parent-child graph) | `PROC` |
| **KernelAuditGuardV2** | Syscall-plane events | Collector offset (file position) | `KERNEL_AUDIT` |
| **PersistenceGuardV2** | Autostart/persistence | JSON baseline (`data/persistence_baseline.json`) | `PERSISTENCE` |
| **FIMAgentV2** | File integrity | JSON baseline (`data/fim_baseline.json`) | `FIM` |
| **AuthGuardV2** | Authentication events | Rolling window (in-memory, 5min) | `AUTH` |
| **FlowAgentV2** | Network flows | EWMA baseline (in-memory), edge tracking | `FLOW` |
| **DNSAgentV2** | DNS queries | First-seen cache (in-memory), DGA models | `DNS` |
| **PeripheralAgentV2** | USB/device events | Device inventory (in-memory) | `PERIPHERAL` |

**Common Infrastructure:**
- `HardenedAgentBase`: Circuit breaker, retry logic, offline resilience
- `MicroProbeAgentMixin`: Probe orchestration, metrics tracking
- `AgentMetrics`: Health telemetry (loops, events, errors)
- `LocalQueueAdapter`: WAL-based queue for offline buffering

**3 Remaining Agents (design phase):**
- SNMPAgentV2
- ProtocolCollectorsV2 (MQTT, Modbus, Syslog)
- DeviceDiscoveryV2

---

### 1.2 Probe Layer (Threat Detection)

**101 Micro-Probes** across 8 agents:

```
Process plane:     8 probes  (exec patterns, LOLBIN, masquerading)
Kernel plane:      7 probes  (privesc, module load, ptrace, audit tamper)
Persistence plane: 8 probes  (cron, systemd, SSH keys, shell profiles)
File plane:        8 probes  (webshells, config tampering, SUID changes)
Auth plane:        8 probes  (brute force, geo anomalies, MFA bypass)
Flow plane:        8 probes  (port scan, lateral movement, data exfil, C2)
DNS plane:         9 probes  (DGA, tunneling, beaconing)
Peripheral plane:  7 probes  (BadUSB, HID injection, suspicious storage)
```

**Probe State:**
- **Stateless probes**: Most probes (e.g., PrivEscSyscallProbe, FilePermissionTamperProbe)
- **Stateful probes**: Baseline tracking (e.g., DataExfilVolumeSpikeProbe uses EWMA), first-seen caches

---

### 1.3 Data Pipeline

```
Kernel/OS Events
    ↓
Collectors (platform-specific)
    ↓ Normalized Events (KernelAuditEvent, FlowEvent, DNSQuery, etc.)
Probes (threat detection logic)
    ↓ TelemetryEvent (severity, MITRE, metadata)
DeviceTelemetry (protocol-tagged batches)
    ↓
LocalQueueAdapter (WAL-based offline buffer)
    ↓
EventBus / SOMA (central aggregation)
    ↓
Cortex (correlation + scoring)
    ↓
Alerts + Dashboards
```

**Data Contracts:**
- Normalized event types per agent (e.g., `KernelAuditEvent`, `FlowEvent`)
- `TelemetryEvent`: Probe output (event_type, severity, data, MITRE techniques)
- `DeviceTelemetry`: Protobuf message with protocol field + batch of events
- `AGENT_METRICS`: Separate telemetry stream for agent health

---

### 1.4 Queue & Persistence

**LocalQueue (WAL-based):**
- Path: `/var/lib/amoskys/queues/{agent_name}/`
- Format: SQLite WAL (Write-Ahead Log)
- Max size: 100MB per agent (configurable)
- Idempotency: SHA-256 hash of event content
- Flush: Every 10 seconds or when EventBus reconnects

**Baseline Files (JSON):**
- FIM baseline: `data/fim_baseline.json` (file paths + SHA-256 hashes)
- Persistence baseline: `data/persistence_baseline.json` (autostart entries)
- Format: JSON dict with timestamp, entries, metadata

**Collector Offsets:**
- KernelAudit: File offset + inode (tracks position in audit.log)
- DNS: Last-seen timestamp per log file
- Auth: Last-processed line number

---

### 1.5 SOMA/Cortex (Brain)

**SOMA (State-Of-Mind Architecture):**
- **EventBus**: Central message broker (Kafka-like, protobuf messages)
- **Telemetry Store**: Time-series DB (PostgreSQL + TimescaleDB)
- **Query Engine**: SQL-based correlation and lookups

**Cortex (Correlation Engine):**
- **Rule Engine**: SQL-based pattern matching
- **Scoring**: Bayesian fusion of event severities
- **Windows**: 5-minute sliding windows for multi-event chains
- **Thresholds**: INFO<50, MEDIUM<70, HIGH<90, CRITICAL≥90

**Not Yet Implemented:**
- Graph-based attack chain visualization
- ML-based anomaly scoring
- Automated response actions

---

## 2. State (Where Data Lives)

### 2.1 In-Memory State

**Per-Agent Process:**
- **Agent metrics**: `AgentMetrics` dataclass (loops, events, errors)
- **Probe state**: `_probe_state` dict (persistent probe context)
- **Circuit breaker state**: CLOSED/OPEN/HALF_OPEN + failure counts
- **Baselines** (for some agents):
  - FlowAgent: EWMA baselines per destination
  - DNSAgent: First-seen domain cache
  - AuthGuard: Rolling 5-minute window of login attempts

**Volatility:**
- Lost on agent restart
- Rebuilt from persistent state on startup (where applicable)

---

### 2.2 Persistent State (Filesystem)

**Queue WAL:**
- Path: `/var/lib/amoskys/queues/{agent}/`
- Survives: Agent restart, system reboot
- Retention: Until flushed to EventBus or max age (7 days)

**Baseline Files:**
- Path: `data/{agent}_baseline.json`
- Survives: Agent restart
- Update: On-demand (FIM/Persistence) or periodic (Flow)

**Collector Offsets:**
- Embedded in queue metadata or separate state file
- Prevents re-processing events after restart

---

### 2.3 Centralized State (SOMA/DB)

**Telemetry Store (PostgreSQL + TimescaleDB):**
- Schema: `telemetry_events(timestamp, device_id, protocol, event_type, severity, attributes)`
- Indexes: timestamp, device_id, protocol, event_type
- Retention: 90 days (configurable)
- Partitioning: Daily partitions via TimescaleDB

**Device Inventory:**
- `devices(device_id, hostname, platform, last_seen, agent_versions)`
- Updated on agent heartbeat (metrics emission)

**Alert State:**
- `alerts(alert_id, rule_id, timestamp, severity, correlated_events)`
- Links back to `telemetry_events` via foreign keys

---

## 3. Boundaries (System Edges)

### 3.1 Agent-to-OS Boundary

**Kernel Audit:**
- **Input**: `/var/log/audit/audit.log` (read-only)
- **Permissions**: ACL or group membership (adm/audit)
- **Failure mode**: If log rotates, inode check detects and reopens

**Process Monitoring:**
- **Input**: `/proc` filesystem (Linux), `ps`/`pgrep` (cross-platform)
- **Permissions**: Normal user (reads `/proc/[pid]/cmdline`, `/proc/[pid]/stat`)

**Network Flow:**
- **Input**: eBPF (Linux), libpcap (cross-platform)
- **Permissions**: CAP_NET_RAW or root (for packet capture)

**Assumption**: OS kernel/utilities are trustworthy (not compromised)

---

### 3.2 Agent-to-Queue Boundary

**Write Path:**
- Agent → `LocalQueueAdapter.enqueue(DeviceTelemetry)`
- Queue → SQLite WAL (ACID guarantees)

**Idempotency:**
- SHA-256 hash of event content
- Duplicate events ignored (protects against retry storms)

**Backpressure:**
- If queue exceeds max size (100MB), oldest events evicted (FIFO)
- Circuit breaker opens if queue writes fail repeatedly

**Assumption**: Filesystem is available and not full

---

### 3.3 Queue-to-EventBus Boundary

**Push Path:**
- Queue → EventBus publisher (HTTP/gRPC)
- Retry: Exponential backoff (0.2s → 0.4s → 0.8s, max 5s)
- Circuit breaker: Opens after 5 consecutive failures

**Offline Resilience:**
- If EventBus unreachable, events queue locally
- When EventBus recovers, queue drains (FIFO)

**Failure Modes:**
- Network partition: Agents continue collecting, queue fills
- EventBus down: Agents go offline-resilient, queue retention = 7 days
- Queue full: Oldest events evicted (data loss, but agent stays healthy)

**Assumption**: EventBus eventually becomes reachable within 7 days

---

### 3.4 EventBus-to-SOMA Boundary

**Ingestion:**
- EventBus → SOMA ingestion API
- Protobuf deserialization
- Schema validation (required fields, timestamp sanity checks)

**Storage:**
- Batch insert to PostgreSQL (1000 events per transaction)
- TimescaleDB hypertable compression (90% size reduction)

**Failure Modes:**
- DB unavailable: EventBus queues in-memory (max 10K events)
- Schema mismatch: Event rejected, logged for debugging
- Disk full: Ingestion pauses, EventBus backpressures agents

**Assumption**: PostgreSQL is HA (replicated, backed up)

---

## 4. Assumptions (Critical Dependencies)

### 4.1 Agent Assumptions

**Deployment:**
- ✅ systemd available (Linux)
- ✅ auditd running (for KernelAudit)
- ✅ Python 3.8+ installed
- ✅ Permissions granted (ACLs, capabilities)

**Runtime:**
- ✅ Filesystem writable (`/var/lib/amoskys/queues`)
- ✅ Audit logs readable (`/var/log/audit/audit.log`)
- ✅ Network reachable (eventually, for offline resilience)

**Security:**
- ✅ Kernel/OS not compromised (rootkit-free)
- ✅ auditd logs not tampered (AuditTamperProbe detects some attempts)
- ✅ Agent process not killed maliciously (systemd restarts)

**Not Assumed:**
- ❌ EventBus always reachable (offline resilience handles this)
- ❌ Disk space unlimited (queue eviction prevents fill)
- ❌ Zero audit events (agents handle empty batches gracefully)

---

### 4.2 SOMA/Cortex Assumptions

**Infrastructure:**
- ✅ PostgreSQL/TimescaleDB HA cluster
- ✅ EventBus (Kafka/RabbitMQ) HA
- ✅ Network between agents and SOMA

**Data Quality:**
- ✅ Agents emit valid protobuf messages
- ✅ Timestamps are UTC and within ±1 hour of current time
- ✅ Device IDs are unique and stable

**Correlation:**
- ✅ Events from same device within 5-minute window can be correlated
- ✅ Attack chains follow temporal ordering (no time travel)

**Not Assumed:**
- ❌ All events arrive in order (SOMA reorders by timestamp)
- ❌ No duplicate events (idempotency keys prevent duplicates)
- ❌ Zero data loss (queue eviction and retention limits allow bounded loss)

---

### 4.3 Operator Assumptions

**Configuration:**
- ✅ Audit rules installed correctly (via `install.sh`)
- ✅ Device IDs configured uniquely per host
- ✅ Queue paths writable by agent user

**Monitoring:**
- ✅ Operators check Grafana dashboards regularly
- ✅ CRITICAL alerts trigger pager duty
- ✅ Agent health metrics monitored (success_rate >99%)

**Tuning:**
- ✅ Operators adjust probe thresholds based on environment
- ✅ Noisy probes disabled if false positive rate too high
- ✅ Collection intervals tuned based on system load

---

## 5. Failure Propagation (How Things Break)

### 5.1 Agent Failure Modes

**Collector Failure:**
```
Audit log unreadable (permissions)
    ↓
Collector.collect_batch() throws exception
    ↓
HardenedAgentBase catches, logs error
    ↓
metrics.record_loop_failure(exc)
    ↓
Circuit breaker: failure_count++
    ↓
If failure_count >= 5: circuit opens (30s cooldown)
    ↓
Agent continues running, emits AGENT_METRICS with error details
    ↓
Operator alerted via Grafana (success_rate drops)
```

**Consequence:**
- No data collection for this agent
- Other agents unaffected
- Auto-recovery when permissions fixed (circuit breaker transitions to HALF_OPEN)

---

**Probe Crash:**
```
Probe.scan() throws exception (e.g., null pointer, regex error)
    ↓
MicroProbeAgentMixin catches exception
    ↓
probe.error_count++
    ↓
metrics.record_probe_error()
    ↓
Agent continues with next probe
    ↓
AGENT_METRICS shows probe_errors > 0
```

**Consequence:**
- Single probe disabled (other probes continue)
- No cascading failure to agent
- Operator investigates via logs (`journalctl -u amoskys-kernel-audit`)

---

**Queue Full:**
```
LocalQueue exceeds 100MB
    ↓
Oldest events evicted (FIFO)
    ↓
Warning logged: "Queue full, evicting old events"
    ↓
Agent continues collecting new events
```

**Consequence:**
- Data loss for oldest events (bounded by retention policy)
- System stays healthy (no crash)
- Operator alerted if queue_size_mb metric stays at max

---

**Agent Process Killed:**
```
SIGKILL (malicious or OOM)
    ↓
systemd detects process exit
    ↓
Restart=always → systemd restarts agent (10s delay)
    ↓
Agent setup() runs, loads baseline from disk
    ↓
Collector resumes from last offset
    ↓
Agent back online
```

**Consequence:**
- Temporary data collection gap (10s)
- In-memory state lost (baselines reload from disk)
- Auto-recovery via systemd

---

### 5.2 Network Partition

**Scenario: Agent can't reach EventBus**

```
Agent tries to publish to EventBus
    ↓
HTTP 503 / connection timeout
    ↓
Circuit breaker: failure_count++
    ↓
Retry with exponential backoff
    ↓
After 5 failures: circuit opens (offline mode)
    ↓
Events queue locally in SQLite WAL
    ↓
Agent continues collecting (queue grows)
    ↓
Network recovers
    ↓
Circuit transitions to HALF_OPEN
    ↓
Test request succeeds → circuit CLOSED
    ↓
Queue drains to EventBus (FIFO)
```

**Consequence:**
- No data loss (up to queue capacity)
- Agent operates offline for days (queue retention = 7 days)
- When network recovers, backlog drains automatically

---

### 5.3 SOMA Overload

**Scenario: SOMA ingestion can't keep up**

```
EventBus receiving 10K events/sec
    ↓
SOMA ingestion lag increases (processing 5K/sec)
    ↓
EventBus queue depth grows
    ↓
EventBus sends HTTP 429 (rate limit) to agents
    ↓
Agents: circuit breaker opens
    ↓
Agents go offline-resilient, queue locally
    ↓
SOMA scales up workers (auto-scaling)
    ↓
Ingestion rate increases to 15K/sec
    ↓
EventBus drains backlog
    ↓
Agents reconnect, drain local queues
```

**Consequence:**
- Temporary ingestion delay (minutes to hours)
- No data loss (EventBus + local queues buffer)
- System self-heals via auto-scaling

---

### 5.4 Database Failure

**Scenario: PostgreSQL primary fails**

```
SOMA tries to insert events
    ↓
PostgreSQL connection error
    ↓
SOMA switches to read replica (read-only mode)
    ↓
Ingestion pauses, events buffer in EventBus
    ↓
HA failover: replica promoted to primary (30s)
    ↓
SOMA reconnects to new primary
    ↓
Buffered events flushed to DB
```

**Consequence:**
- 30s ingestion pause (during failover)
- No data loss (EventBus buffers)
- Correlation/alerting delayed by 30s

---

### 5.5 Cascading Failure Prevention

**Design Patterns:**
1. **Circuit breakers**: Prevent retry storms when downstream is down
2. **Offline resilience**: Agents operate independently when network partitioned
3. **Local queuing**: Bounded buffers prevent memory exhaustion
4. **Probe isolation**: One probe crash doesn't kill agent
5. **Graceful degradation**: Agents emit metrics even when data collection fails

**Result:** No single point of failure causes total system collapse.

---

## 6. Observability (What We Can See)

### 6.1 Agent-Level Metrics

**Per-Agent (emitted every 60s):**
```
loops_started:          1234    # Total collection cycles attempted
loops_succeeded:        1233    # Successful cycles
loops_failed:           1       # Failed cycles
events_emitted:         456     # DeviceTelemetry messages sent
probe_events_emitted:   37      # TelemetryEvents from probes
probe_errors:           0       # Probe scan() exceptions
success_rate:           0.999   # loops_succeeded / loops_started
last_error_type:        ""      # Exception class name (if failed)
last_error_message:     ""      # Exception message (truncated)
```

**Access:**
- SOMA query: `SELECT * FROM telemetry_events WHERE protocol='AGENT_METRICS'`
- Local HTTP: `curl http://localhost:9100/metrics` (if enabled)
- Logs: `journalctl -u amoskys-{agent} | grep "emitted metrics"`

---

### 6.2 Probe-Level Metrics

**Per-Probe (tracked in memory):**
```
probe.scan_count:       1234    # Times probe.scan() called
probe.error_count:      0       # scan() exceptions
probe.last_scan:        datetime # Last scan timestamp
probe.last_error:       ""      # Last exception message
```

**Access:**
- Agent health API: `agent.get_health()["probes"]`
- SOMA enrichment: Probe name included in TelemetryEvent

---

### 6.3 System-Level Dashboards (Grafana)

**Agent Health Matrix:**
- 8×2 grid: 8 agents, 2 metrics each (success_rate, events_emitted)
- Color: green >99%, yellow >95%, red <95%

**Threat Heatmap:**
- MITRE ATT&CK tactics vs. time (5-minute buckets)
- Intensity: event count per tactic

**Attack Chain Timeline:**
- Correlated events from same device
- Temporal ordering, severity colors

---

## 7. Current Gaps & Risks

### 7.1 Missing Components

**Not Yet Implemented:**
- 3 agents: SNMP, ProtocolCollectors, DeviceDiscovery
- SOMA correlation rules (SQL queries exist, not deployed)
- Automated response actions (alerts only, no remediation)
- Graph-based attack visualization

**Risk:** Partial visibility (73% of planned agents deployed)

---

### 7.2 Single Points of Failure

**Agent Process:**
- Mitigation: systemd auto-restart
- Residual risk: If systemd itself fails, agent stays down

**Local Disk:**
- Risk: Disk full → queue can't grow
- Mitigation: Queue eviction (bounded memory)
- Residual risk: If disk I/O fails, agent can't persist

**SOMA Database:**
- Mitigation: PostgreSQL HA (primary + replica)
- Residual risk: If both fail, ingestion stops (EventBus buffers)

**EventBus:**
- Mitigation: Agents queue locally (offline resilience)
- Residual risk: If EventBus down >7 days, local queues evict old data

---

### 7.3 Security Assumptions

**Trusted Kernel:**
- Assumption: Kernel and auditd are not compromised
- Risk: Rootkit could tamper with audit logs before agent reads them
- Mitigation: AuditTamperProbe detects some tampering attempts, but not all

**Trusted Filesystem:**
- Assumption: `/var/lib/amoskys/queues` not tampered
- Risk: Attacker with root could delete queue or modify baselines
- Mitigation: File integrity monitoring (FIMAgent watches queue directory)

**Trusted Agent Binary:**
- Assumption: Agent process is legitimate, not replaced
- Risk: Attacker could replace agent binary with malicious version
- Mitigation: Code signing (not yet implemented), systemd integrity checks

---

### 7.4 Operational Challenges

**Configuration Drift:**
- Risk: Operators manually edit configs, inconsistencies across fleet
- Mitigation: Configuration management (Ansible/Puppet, not yet deployed)

**Alert Fatigue:**
- Risk: Too many INFO/MEDIUM alerts, CRITICAL alerts ignored
- Mitigation: Tuning probe thresholds, correlation to reduce noise

**Version Skew:**
- Risk: Different agent versions across fleet, schema incompatibility
- Mitigation: Centralized deployment (not yet implemented), version tracking in metrics

---

## 8. Boundary Conditions & Edge Cases

### 8.1 Time Skew

**Problem:** Agent clock differs from SOMA clock by >1 hour

**Impact:**
- Events timestamped in "future" or "past"
- Correlation windows broken (5-minute window assumes synchronized clocks)

**Mitigation:**
- SOMA rejects events with timestamp >1 hour from current time
- Agent logs warning if system clock seems wrong (compares to last NTP sync)

**Edge Case:** Daylight saving time transitions → handled by UTC timestamps

---

### 8.2 High Event Volume

**Problem:** Audit log generates 10K+ events/second (e.g., on busy web server)

**Impact:**
- Collector can't keep up, falls behind log writes
- Queue fills rapidly, events evicted

**Mitigation:**
- Increase collection interval (5s → 30s)
- Reduce audit rule scope (monitor only critical syscalls)
- Use sampling (process every Nth event)

**Edge Case:** Log rotation during high volume → inode check handles, no events lost

---

### 8.3 Baseline Corruption

**Problem:** FIM baseline JSON corrupted (disk error, manual edit)

**Impact:**
- Agent can't determine what changed (all files appear new)
- False positive storm (every file flagged as "CREATED")

**Mitigation:**
- Agent detects invalid JSON, logs error, refuses to load
- Operator manually regenerates baseline (`fim_agent --mode create`)

**Edge Case:** Baseline from different host copied over → hash mismatches, all files flagged

---

## 9. Recovery Procedures

### 9.1 Agent Won't Start

**Diagnosis:**
```bash
sudo systemctl status amoskys-kernel-audit
sudo journalctl -u amoskys-kernel-audit -n 50
```

**Common Fixes:**
- Permissions: `sudo setfacl -m u:amoskys:r /var/log/audit/audit.log`
- Queue dir: `sudo mkdir -p /var/lib/amoskys/queues && sudo chown amoskys:amoskys /var/lib/amoskys`
- Audit rules: `sudo augenrules --load && sudo systemctl restart auditd`

---

### 9.2 Queue Full, Events Dropped

**Diagnosis:**
```bash
du -sh /var/lib/amoskys/queues/kernel_audit
# Output: 100M (at max)
```

**Fix:**
- Check EventBus connectivity: `curl https://eventbus.example.com/health`
- If EventBus down: Wait for recovery, queue will drain
- If EventBus up: Check circuit breaker state in logs, manual reset if needed

---

### 9.3 SOMA Not Receiving Events

**Diagnosis:**
```bash
# Check agent metrics
sudo journalctl -u amoskys-kernel-audit | grep "emitted.*events"
# Output: events_emitted=0 (problem)

# Check queue
ls -lh /var/lib/amoskys/queues/kernel_audit/
# Many .wal files = events not draining
```

**Fix:**
- Verify EventBus reachable: `curl https://eventbus.example.com/health`
- Check circuit breaker: Look for "Circuit OPEN" in logs
- Manual queue flush: Restart agent (`sudo systemctl restart amoskys-kernel-audit`)

---

## 10. Summary: System Health Checklist

**Healthy System:**
- ✅ All 8 agents: `systemctl is-active amoskys-*` → active
- ✅ Success rate: >99% for all agents
- ✅ Probe errors: 0 across all agents
- ✅ Queue size: <10MB (events draining)
- ✅ SOMA ingestion lag: <10 seconds
- ✅ No CRITICAL alerts unacknowledged

**Degraded System:**
- ⚠️ 1-2 agents down (others compensate)
- ⚠️ Success rate: 95-99% (some collection failures)
- ⚠️ Queue size: 10-50MB (backpressure building)
- ⚠️ SOMA ingestion lag: 10-60 seconds

**Critical System:**
- ❌ >3 agents down
- ❌ Success rate: <95%
- ❌ Queue size: >80MB (near eviction threshold)
- ❌ SOMA ingestion lag: >5 minutes
- ❌ CRITICAL alerts firing continuously

---

**This is the ground truth. The system as it exists today.**
