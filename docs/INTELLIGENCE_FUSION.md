# Intelligence & Fusion Layer

The **Fusion Engine** is AMOSKYS' intelligence correlation layer that transforms raw telemetry events from multiple agents into actionable security intelligence.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Intelligence Layer                         │
│                      (Fusion Engine)                            │
└─────────────────────────────────────────────────────────────────┘
                              ▲
                              │
              ┌───────────────┴───────────────┐
              │                               │
        Telemetry Events              Correlation Rules
              │                               │
    ┌─────────┴─────────┐           ┌────────┴────────┐
    │  Multi-Agent      │           │  Hand-Written   │
    │  Event Stream     │           │  Detection      │
    │                   │           │  Logic          │
    │ • FlowAgent       │           │                 │
    │ • ProcAgent       │           │ • SSH Brute     │
    │ • AuthGuard       │           │ • Persistence   │
    │ • PersistGuard    │           │ • Suspicious    │
    │ • SNMP Agent      │           │ • Multi-Tactic  │
    └───────────────────┘           └─────────────────┘
              │                               │
              └───────────────┬───────────────┘
                              ▼
                    ┌─────────────────────┐
                    │  Intelligence DB    │
                    │                     │
                    │ • Incidents         │
                    │ • DeviceRiskScores  │
                    └─────────────────────┘
```

## Core Concepts

### 1. TelemetryEventView

Normalized view of raw telemetry events for correlation. Extracts relevant fields from protobuf messages into a simpler Python structure.

**Fields:**
- `event_id`: Unique identifier
- `device_id`: Source device
- `event_type`: SECURITY, AUDIT, PROCESS, FLOW, METRIC
- `severity`: INFO, WARN, CRITICAL
- `timestamp`: When the event occurred
- `attributes`: Key-value metadata
- Typed event bodies (security_event, audit_event, process_event, flow_event)

### 2. Incident (Attack Chain)

A correlated sequence of events that tell an attack story.

**Example:** SSH brute force → successful login → LaunchAgent creation

**Fields:**
- `incident_id`: Unique identifier
- `device_id`: Affected device
- `severity`: INFO → LOW → MEDIUM → HIGH → CRITICAL
- `tactics`: MITRE ATT&CK tactics (TA#### codes)
- `techniques`: MITRE ATT&CK techniques (T#### codes)
- `rule_name`: Which correlation rule fired
- `summary`: Human-readable description
- `start_ts`, `end_ts`: Temporal bounds
- `event_ids`: Contributing telemetry events
- `metadata`: Additional context (IPs, users, commands, etc.)

### 3. DeviceRiskSnapshot

Current security posture of a device, aggregated from recent events.

**Scoring Model:**
```
Base:                         10 points
Failed SSH (each, max +20):   +5
Successful SSH (new IP):      +15
New SSH key:                  +30
New LaunchAgent in /Users:    +25
Suspicious sudo command:      +30
HIGH incident:                +20
CRITICAL incident:            +40
Decay (per 10 min idle):      -10
Range:                        [0, 100]
```

**Risk Levels:**
- **LOW**: 0-30 points (normal activity)
- **MEDIUM**: 31-60 points (suspicious patterns)
- **HIGH**: 61-80 points (likely compromise)
- **CRITICAL**: 81-100 points (active intrusion)

**Fields:**
- `device_id`: Device identifier
- `score`: Numeric risk score (0-100)
- `level`: Categorical level (LOW/MEDIUM/HIGH/CRITICAL)
- `reason_tags`: Explanation of score (e.g., "ssh_brute_force_attempts_3")
- `supporting_events`: Event IDs contributing to score
- `updated_at`: Last update timestamp

## Correlation Rules

### Rule 1: SSH Brute Force → Compromise

**Pattern:**
```
≥ 3 failed SSH attempts from IP X
  → Successful SSH login from IP X
  (within 30 minutes)
```

**Signals:**
- SECURITY events: `auth_type='SSH'`, `result='FAILURE'/'SUCCESS'`

**Output:**
- **Severity:** HIGH
- **Tactics:** Initial Access (TA0001)
- **Techniques:** T1110 (Brute Force), T1021.004 (SSH)
- **Metadata:** source_ip, target_user, failed_attempts, time_to_compromise

### Rule 2: Persistence After Authentication

**Pattern:**
```
Successful SSH or SUDO
  → CREATED persistence mechanism
  (within 10 minutes)
```

**Persistence Types:**
- LaunchAgent / LaunchDaemon
- Cron jobs
- SSH authorized_keys

**Signals:**
- SECURITY: `auth_type='SSH'` or `'SUDO'`, `result='SUCCESS'`
- AUDIT: `action='CREATED'`, `object_type` in persistence types

**Output:**
- **Severity:** CRITICAL (if /Users/), HIGH (otherwise)
- **Tactics:** Persistence (TA0003), Privilege Escalation (TA0004)
- **Techniques:**
  - T1543.001 (Launch Agent)
  - T1543.004 (Launch Daemon)
  - T1053.003 (Cron)
  - T1098.004 (SSH Keys)

### Rule 3: Suspicious Sudo Command

**Pattern:**
```
SUDO command containing dangerous patterns:
  - rm -rf / (system destruction)
  - /etc/sudoers (privilege escalation)
  - LaunchAgents/Daemons (persistence)
  - kextload (kernel extension)
```

**Signals:**
- SECURITY: `auth_type='SUDO'`, `attributes['sudo_command']`

**Output:**
- **Severity:** CRITICAL or HIGH (pattern-dependent)
- **Tactics:** Privilege Escalation (TA0004)
- **Techniques:** T1548.003 (Sudo Abuse)

### Rule 4: Multi-Tactic Attack Chain

**Pattern:**
```
Suspicious process (in /tmp, ~/Downloads)
  + Outbound network connection (uncommon port/IP)
  + Persistence mechanism created
  (all within 15 minutes)
```

**Signals:**
- PROCESS: `executable_path` in suspicious locations
- FLOW: new outbound connections
- AUDIT: new persistence (LAUNCH_AGENT, SSH_KEYS)

**Output:**
- **Severity:** CRITICAL
- **Tactics:** Command & Control, Execution, Persistence
- **Techniques:** T1071, T1059, T1543.001
- **Metadata:** dst_ip, dst_port, process_path, persistence_type

## Usage

### Command-Line Interface

```bash
# Single evaluation pass (for testing)
python -m amoskys.intel.fusion_engine --once

# Continuous monitoring (production)
python -m amoskys.intel.fusion_engine --interval 60 --window 30

# Custom database path
python -m amoskys.intel.fusion_engine --db /custom/path/fusion.db

# After pip install
amoskys-fusion --once
amoskys-fusion --interval 120 --window 60
```

### Python API

```python
from amoskys.intel import FusionEngine, TelemetryEventView

# Initialize engine
engine = FusionEngine(
    db_path="data/intel/fusion.db",
    window_minutes=30,
    eval_interval=60
)

# Add events (from agent telemetry)
event = TelemetryEventView(
    event_id="auth_ssh_001",
    device_id="macbook-pro",
    event_type="SECURITY",
    severity="WARN",
    timestamp=datetime.now(),
    security_event={
        'event_action': 'SSH',
        'event_outcome': 'FAILURE',
        'user_name': 'admin',
        'source_ip': '203.0.113.42'
    }
)
engine.add_event(event)

# Evaluate device
incidents, risk = engine.evaluate_device("macbook-pro")

# Persist results
for incident in incidents:
    engine.persist_incident(incident)
engine.persist_risk_snapshot(risk)

# Query intelligence
recent_incidents = engine.get_recent_incidents(device_id="macbook-pro", limit=10)
device_risk = engine.get_device_risk("macbook-pro")

print(f"Device Risk: {device_risk['level']} (score={device_risk['score']})")
for inc in recent_incidents:
    print(f"[{inc['severity']}] {inc['rule_name']}: {inc['summary']}")
```

### Running the Demo

```bash
# Demonstrates all four correlation rules with synthetic events
python scripts/demo_fusion_engine.py
```

**Output:**
```
Scenario 1: SSH Brute Force Attack
  Incidents: 1
    [HIGH] ssh_brute_force: SSH brute force from 203.0.113.42
  Device Risk: MEDIUM (score=60)

Scenario 2: Persistence After Authentication
  Incidents: 1
    [CRITICAL] persistence_after_auth: New LAUNCH_AGENT created 120s after SSH
  Device Risk: CRITICAL (score=100)

Scenario 3: Suspicious Sudo Command
  Incidents: 1
    [CRITICAL] suspicious_sudo: Dangerous sudo command detected
  Device Risk: CRITICAL (score=100)

Scenario 4: Multi-Tactic Attack Chain
  Incidents: 1
    [CRITICAL] multi_tactic_attack: Multi-stage attack detected
  Device Risk: CRITICAL (score=100)

Demo complete! ✓
```

## Database Schema

### incidents Table

```sql
CREATE TABLE incidents (
    incident_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    severity TEXT NOT NULL,           -- CRITICAL, HIGH, MEDIUM, LOW, INFO
    tactics TEXT NOT NULL,             -- JSON array of MITRE tactics
    techniques TEXT NOT NULL,          -- JSON array of MITRE techniques
    rule_name TEXT NOT NULL,           -- Correlation rule that fired
    summary TEXT NOT NULL,             -- Human-readable description
    start_ts TEXT,                     -- ISO timestamp
    end_ts TEXT,                       -- ISO timestamp
    event_ids TEXT NOT NULL,           -- JSON array of TelemetryEvent IDs
    metadata TEXT NOT NULL,            -- JSON object with context
    created_at TEXT NOT NULL           -- ISO timestamp
);

CREATE INDEX idx_incidents_device ON incidents(device_id);
CREATE INDEX idx_incidents_created ON incidents(created_at);
```

### device_risk Table

```sql
CREATE TABLE device_risk (
    device_id TEXT PRIMARY KEY,
    score INTEGER NOT NULL,            -- 0-100
    level TEXT NOT NULL,               -- LOW, MEDIUM, HIGH, CRITICAL
    reason_tags TEXT NOT NULL,         -- JSON array of reason strings
    supporting_events TEXT NOT NULL,   -- JSON array of event IDs
    metadata TEXT NOT NULL,            -- JSON object with stats
    updated_at TEXT NOT NULL           -- ISO timestamp
);
```

## Integration with Existing Agents

The Fusion Engine consumes events from:

1. **FlowAgent** ([src/amoskys/agents/flowagent/main.py](src/amoskys/agents/flowagent/main.py))
   - FLOW events: network connections
   - Used in: Multi-tactic attack correlation

2. **ProcAgent** ([src/amoskys/agents/proc/proc_agent.py](src/amoskys/agents/proc/proc_agent.py))
   - PROCESS events: process creation
   - Used in: Multi-tactic attack correlation

3. **AuthGuardAgent** ([src/amoskys/agents/auth/auth_agent.py](src/amoskys/agents/auth/auth_agent.py))
   - SECURITY events: SSH, sudo, logins
   - Used in: SSH brute force, persistence after auth, suspicious sudo

4. **PersistenceGuardAgent** ([src/amoskys/agents/persistence/persistence_agent.py](src/amoskys/agents/persistence/persistence_agent.py))
   - AUDIT events: LaunchAgents, cron, SSH keys
   - Used in: Persistence after auth, multi-tactic attack

5. **SNMP Agent** (metrics)
   - METRIC events: system health
   - Used in: Future anomaly detection

## Attack Scenario Coverage

| Attack Scenario | Detection Coverage | Rules Involved |
|----------------|-------------------|----------------|
| SSH Credential Stuffing | ✅ Brute force pattern | Rule 1 |
| Backdoor Installation | ✅ Persistence after auth | Rule 2 |
| Privilege Escalation | ✅ Suspicious sudo | Rule 3 |
| Multi-Stage APT | ✅ Process + Network + Persistence | Rule 4 |
| Insider Threat | ✅ Unusual sudo, persistence changes | Rules 2, 3 |
| Lateral Movement | 🔄 Future (SSH to multiple hosts) | Planned |

## Extending the Fusion Engine

### Adding a New Correlation Rule

1. **Define the Rule Function** in [src/amoskys/intel/rules.py](src/amoskys/intel/rules.py):

```python
def rule_lateral_movement(events: List[TelemetryEventView], device_id: str) -> Optional[Incident]:
    """Detect lateral movement via SSH hopping

    Pattern:
        - SSH login from external IP
        - Followed by outbound SSH to internal IP
        (within 5 minutes)
    """
    # Extract SSH success events
    ssh_inbound = [e for e in events
                   if e.event_type == "SECURITY"
                   and e.security_event.get('event_action') == 'SSH'
                   and e.security_event.get('event_outcome') == 'SUCCESS']

    # Extract outbound SSH connections (port 22)
    ssh_outbound = [e for e in events
                    if e.event_type == "FLOW"
                    and e.flow_event.get('dst_port') == 22]

    # Look for temporal correlation
    for inbound in ssh_inbound:
        for outbound in ssh_outbound:
            time_diff = (outbound.timestamp - inbound.timestamp).total_seconds()

            if 0 < time_diff <= 300:  # 5 minutes
                return Incident(
                    incident_id=f"lateral_{device_id}_{int(outbound.timestamp.timestamp())}",
                    device_id=device_id,
                    severity=Severity.HIGH,
                    tactics=[MitreTactic.LATERAL_MOVEMENT.value],
                    techniques=['T1021.004'],
                    rule_name='lateral_movement',
                    summary=f"SSH lateral movement: inbound from {inbound.security_event['source_ip']} "
                            f"→ outbound to {outbound.flow_event['dst_ip']}",
                    event_ids=[inbound.event_id, outbound.event_id],
                    metadata={
                        'source_ip': inbound.security_event['source_ip'],
                        'target_ip': outbound.flow_event['dst_ip'],
                        'hop_time_seconds': str(int(time_diff))
                    }
                )

    return None
```

2. **Register the Rule** in `ALL_RULES` list:

```python
ALL_RULES = [
    rule_ssh_brute_force,
    rule_persistence_after_auth,
    rule_suspicious_sudo,
    rule_multi_tactic_attack,
    rule_lateral_movement,  # New rule
]
```

3. **Test the Rule** in demo script or unit tests:

```python
def test_lateral_movement_detection():
    engine = FusionEngine(db_path=":memory:")

    # Create inbound SSH event
    inbound = TelemetryEventView(...)
    engine.add_event(inbound)

    # Create outbound SSH flow
    outbound = TelemetryEventView(...)
    engine.add_event(outbound)

    # Evaluate
    incidents, _ = engine.evaluate_device("test-device")

    assert len(incidents) == 1
    assert incidents[0].rule_name == 'lateral_movement'
```

## Performance Considerations

- **Window Size**: 30 minutes default (adjustable via `--window`)
  - Larger windows = more correlation opportunities, higher memory
  - Smaller windows = faster evaluation, might miss slow attacks

- **Evaluation Interval**: 60 seconds default (adjustable via `--interval`)
  - More frequent = faster detection, higher CPU
  - Less frequent = lower overhead, slower response

- **Event Trimming**: Old events are automatically removed from buffers
  - Prevents unbounded memory growth
  - Maintains correlation window invariant

- **Database VACUUM**: SQLite WAL mode with automatic cleanup
  - Incidents/risk tables grow slowly (one row per device)
  - Manual VACUUM recommended during maintenance windows

## Future Enhancements

### Phase 1 (Current) - Hand-Written Rules ✅
- ✅ SSH brute force detection
- ✅ Persistence after authentication
- ✅ Suspicious sudo commands
- ✅ Multi-tactic attack chains
- ✅ Device risk scoring

### Phase 2 (Next) - ML Integration 🔄
- [ ] Anomaly detection (unsupervised learning)
- [ ] Risk score learned weights (supervised learning)
- [ ] User/entity behavior analytics (UEBA)
- [ ] Adaptive thresholds based on historical data

### Phase 3 (Future) - Advanced Correlation 🔮
- [ ] Cross-device correlation (lateral movement)
- [ ] Temporal attack graphs
- [ ] Kill chain reconstruction
- [ ] Automated playbook response

## Troubleshooting

### No Incidents Detected

1. **Check event ingestion:**
   ```python
   state = engine.device_state["my-device"]
   print(f"Events in buffer: {len(state['events'])}")
   ```

2. **Verify event types:**
   ```python
   for event in state['events']:
       print(f"{event.event_type}: {event.event_id}")
   ```

3. **Test rules manually:**
   ```python
   from amoskys.intel.rules import evaluate_rules
   incidents = evaluate_rules(state['events'], "my-device")
   ```

### High False Positive Rate

1. **Tune rule thresholds** (e.g., increase failed SSH threshold from 3 to 5)
2. **Extend time windows** (e.g., 10 minutes → 15 minutes)
3. **Add allowlists** (known IPs, trusted users, approved sudo commands)
4. **Adjust risk scoring weights** (reduce points for benign patterns)

### Memory Usage Growth

1. **Reduce window size:** `--window 15` (from 30 minutes)
2. **Increase evaluation interval:** `--interval 120` (from 60 seconds)
3. **Check for event leak:** Ensure old events are being trimmed
4. **Monitor device count:** `len(engine.device_state)` should be reasonable

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Agent Implementation: AuthGuard](src/amoskys/agents/auth/auth_agent.py)
- [Agent Implementation: PersistenceGuard](src/amoskys/agents/persistence/persistence_agent.py)
- [Correlation Rules](src/amoskys/intel/rules.py)
- [Fusion Engine](src/amoskys/intel/fusion_engine.py)
