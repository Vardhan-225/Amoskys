# 🧠 AMOSKYS Agent Harmony Architecture
**Multi-Agent Intelligence System - Biological Organism Design**

**Created:** October 25, 2025  
**Status:** Foundation Complete, Expanding to Multi-Agent

---

## 🎯 Vision: Digital Organism

AMOSKYS is designed as a **distributed digital organism** where:
- **Agents** are specialized organs/sensors
- **EventBus** is the nervous system
- **ScoreJunction** is the synapse/decision center
- **Intelligence Layer** is the brain
- **Dashboard** is the sensory cortex (human interface)

```
┌──────────────────────────────────────────────────────────────┐
│                     AMOSKYS ORGANISM                          │
│                                                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │ SNMPAgent   │  │  ProcAgent  │  │ FlowAgent   │   ←  Sensors
│  │(Device Tel.)│  │(Process Mon)│  │(Network)    │    (Organs)
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘         │
│         │                 │                 │                │
│         └─────────────────┴─────────────────┘                │
│                           ▼                                   │
│                  ┌────────────────┐                          │
│                  │   EventBus     │  ← Nervous System       │
│                  │  (gRPC/mTLS)   │                          │
│                  └────────┬───────┘                          │
│                           ▼                                   │
│                  ┌────────────────┐                          │
│                  │ ScoreJunction  │  ← Synapse              │
│                  │  (Correlation) │                          │
│                  └────────┬───────┘                          │
│                           ▼                                   │
│                  ┌────────────────┐                          │
│                  │  Intelligence  │  ← Brain                │
│                  │  (ML/Rules)    │                          │
│                  └────────┬───────┘                          │
│                           ▼                                   │
│                  ┌────────────────┐                          │
│                  │   Dashboard    │  ← Sensory Cortex       │
│                  │   (Web UI)     │                          │
│                  └────────────────┘                          │
└──────────────────────────────────────────────────────────────┘
```

---

## 🤖 Agent Ecosystem

### Current Agents (✅ Implemented)

#### 1. **SNMPAgent** - Device Telemetry Sensor
**Status:** ✅ **Production Ready**

**Purpose:**
- Collect system health metrics via SNMP
- Monitor CPU, memory, disk, network interfaces
- Track device uptime and configuration

**Metrics Collected:**
- System: sysDescr, sysUpTime, sysName, sysLocation, sysContact
- CPU: hrProcessorLoad (per core)
- Memory: hrMemorySize, hrStorageUsed
- Network: ifInOctets, ifOutOctets, ifInErrors, ifOutErrors
- Disk: diskIOReads, diskIOWrites

**Configuration:**
- `config/snmp_agent.yaml` - Device list
- `config/snmp_metrics_config.yaml` - Metric definitions, profiles, thresholds

**Data Format:**
```protobuf
DeviceTelemetry {
  device_id: "router-01"
  device_type: NETWORK
  protocol: "SNMP"
  events: [TelemetryEvents...]
  collection_agent: "amoskys-snmp-agent"
}
```

**Collection Interval:** 60 seconds (configurable)

---

#### 2. **FlowAgent** - Network Flow Analyzer
**Status:** ✅ **Implemented** (legacy, needs update to UniversalEnvelope)

**Purpose:**
- Monitor network flows
- Track connections, bandwidth usage
- Detect anomalous traffic patterns

**Metrics Collected:**
- Flow records (src/dst IP, ports, bytes, packets)
- Connection states
- Protocol distribution

**Data Format:**
```protobuf
FlowEvent {
  src_ip, dst_ip, src_port, dst_port
  protocol, bytes_tx, bytes_rx
  start_time, end_time
}
```

**Status:** Needs migration to `DeviceTelemetry` format

---

#### 3. **ProcAgent** - Process Monitor
**Status:** ✅ **Newly Created** (ready for testing)

**Purpose:**
- Monitor running processes on hosts
- Track resource usage (CPU, memory, threads)
- Detect suspicious processes and behaviors
- Track process lifecycle (start/stop)

**Metrics Collected:**
- Process list (pid, name, exe, cmdline, username)
- Resource usage per process (CPU %, memory %, threads)
- Network connections per process
- Open files per process
- Process lifecycle events (new, terminated)
- Suspicious process alerts

**Data Format:**
```protobuf
DeviceTelemetry {
  device_id: "host-01"
  device_type: HOST
  protocol: "PROC"
  events: [
    METRIC: proc_total_count, proc_cpu_percent, proc_memory_percent
    EVENT: PROCESS_START, PROCESS_STOP
    ALERT: SUSPICIOUS_PROCESS
  ]
}
```

**Collection Interval:** 30 seconds (configurable)

**Key Features:**
- Detects high CPU/memory usage
- Identifies suspicious process names/paths
- Tracks processes with unusual network activity
- Top N process reporting

---

### Planned Agents (🛠️ Roadmap)

#### 4. **SyscallAgent** - System Call Tracer
**Status:** 🛠️ **Planned**

**Purpose:**
- Monitor system calls using eBPF
- Detect privilege escalation attempts
- Track file/network operations
- Identify anomalous syscall patterns

**Technology:**
- eBPF (Linux kernel tracing)
- perf events
- seccomp filters

**Metrics:**
- Syscall frequency by type
- File access patterns
- Network syscalls
- Privilege changes

---

#### 5. **ProfileAgent** - User Session Monitor
**Status:** 🛠️ **Planned**

**Purpose:**
- Monitor user authentication events
- Track session activity
- Detect unusual login patterns
- Monitor privilege usage

**Metrics:**
- Login/logout events
- Failed authentication attempts
- Session duration
- Privilege escalation events
- SSH connections

---

#### 6. **DaemonAgent** - System Service Monitor
**Status:** 🛠️ **Planned**

**Purpose:**
- Monitor system daemons/services
- Track service health and status
- Detect service crashes/restarts
- Monitor service resource usage

**Metrics:**
- Service status (running/stopped/failed)
- Service restart count
- Resource usage per service
- Service dependencies

---

#### 7. **LogAgent** - Log Aggregation & Analysis
**Status:** 🛠️ **Planned**

**Purpose:**
- Aggregate system and application logs
- Parse and normalize log formats
- Extract security-relevant events
- Detect log anomalies

**Metrics:**
- Log volume by source
- Error/warning counts
- Security event extraction
- Log pattern analysis

---

#### 8. **FileAgent** - File Integrity Monitor
**Status:** 🛠️ **Planned**

**Purpose:**
- Monitor critical file changes
- Detect unauthorized modifications
- Track file access patterns
- Verify checksums

**Metrics:**
- File modification events
- Checksum mismatches
- Access pattern anomalies
- Permission changes

---

## 🔄 Data Flow Architecture

### 1. Collection Phase

```
Agent → Collect Raw Data → Convert to DeviceTelemetry → Sign with Ed25519 → Publish to EventBus
```

**Common Pattern (All Agents):**
1. Collect metrics/events from source (SNMP, /proc, eBPF, logs, etc.)
2. Convert to `DeviceTelemetry` protobuf
3. Wrap in `UniversalEnvelope` with metadata
4. Sign envelope with Ed25519 private key
5. Publish to EventBus via gRPC/mTLS

**DeviceTelemetry Structure:**
```protobuf
message DeviceTelemetry {
  string device_id = 1;
  DeviceType device_type = 2;  // NETWORK, HOST, IOT, etc.
  string protocol = 3;          // SNMP, PROC, FLOW, etc.
  DeviceMetadata metadata = 4;
  repeated TelemetryEvent events = 5;
  int64 timestamp_ns = 6;
  string collection_agent = 7;
  string agent_version = 8;
}
```

---

### 2. Transport Phase

```
EventBus receives → Validates signature → Stores in WAL → Forwards to subscribers
```

**EventBus Responsibilities:**
- Receive envelopes from all agents
- Verify Ed25519 signatures
- Check idempotency (prevent duplicates)
- Store in WAL database (SQLite)
- Forward to subscribers (ScoreJunction, Dashboard, etc.)
- Provide backpressure signals

---

### 3. Correlation Phase (ScoreJunction)

```
Multiple Agent Events → Temporal Correlation → Entity Correlation → Threat Scoring → Alert Generation
```

**ScoreJunction Responsibilities:**
- Buffer events in 5-minute sliding window
- Correlate events by:
  - **Temporal:** Events within time window
  - **Entity:** Same device_id, IP, user, process
  - **Pattern:** Matching correlation rules
- Compute unified threat scores
- Generate threat alerts

**Correlation Rules:**
```yaml
- name: high_cpu_suspicious_process
  conditions:
    - agent: proc_agent, metric: cpu_percent > 80
    - agent: proc_agent, alert: SUSPICIOUS_PROCESS
  threat_level: HIGH
  score_weight: 0.7

- name: memory_spike_new_process
  conditions:
    - agent: snmp_agent, metric: hrStorageUsed (spike)
    - agent: proc_agent, event: PROCESS_START
  threat_level: MEDIUM
  score_weight: 0.5
```

**ThreatScore Output:**
```protobuf
message ThreatScore {
  string entity_id = 1;      // device-01
  string entity_type = 2;     // device, ip, user, process
  float score = 3;            // 0-100
  string threat_level = 4;    // BENIGN, LOW, MEDIUM, HIGH, CRITICAL
  float confidence = 5;       // 0.0-1.0
  repeated string contributing_events = 6;
  repeated string indicators = 7;
  int64 timestamp_ns = 8;
}
```

---

### 4. Intelligence Phase

```
ThreatScore → ML Models → Context Enrichment → Decision Logic → Actions
```

**Intelligence Layer Responsibilities:**
- Apply machine learning models
- Enrich with threat intelligence feeds
- Consult policy engine
- Generate actionable alerts
- Trigger automated responses
- Update knowledge base

---

### 5. Visualization Phase

```
EventBus/ScoreJunction → Dashboard API → Web UI → Human Operator
```

**Dashboard Displays:**
- Real-time agent health
- Device status grid
- Threat score timeline
- Top alerts/anomalies
- Resource usage graphs
- Network topology map

---

## 🔐 Security Model

### Agent Authentication

**Every agent must:**
1. Have a unique Ed25519 key pair (`certs/agent.ed25519`)
2. Have an x509 client certificate (`certs/agent.crt`)
3. Sign every envelope with its private key
4. Use mTLS for EventBus connection

### Signature Verification

**EventBus verifies:**
1. mTLS client certificate (transport layer)
2. Ed25519 signature on envelope (message layer)
3. Trust map lookup (agent authorization)
4. Timestamp freshness (replay protection)

### Idempotency

**Every envelope has:**
- `idempotency_key`: `{device_id}_{timestamp_ns}`
- Prevents duplicate processing
- Dedupe cache with TTL (5 minutes)

---

## 📊 Monitoring & Observability

### Per-Agent Metrics (Prometheus)

```
# Collection metrics
agent_collections_total{agent="snmp"}
agent_collection_latency_ms{agent="snmp"}
agent_metrics_collected_total{agent="snmp"}

# Publish metrics
agent_publish_ok_total{agent="snmp"}
agent_publish_retry_total{agent="snmp"}
agent_publish_fail_total{agent="snmp"}

# Health metrics
agent_up{agent="snmp"}
agent_last_collection_timestamp
```

### EventBus Metrics

```
bus_publish_total
bus_invalid_total
bus_retry_total
bus_inflight_requests
bus_dedupe_hits_total
```

### ScoreJunction Metrics

```
junction_events_processed_total
junction_correlations_found_total
junction_threats_detected_total{level="HIGH"}
junction_entities_tracked
```

---

## 🎯 Agent Harmony Principles

### 1. **Independence**
- Each agent runs autonomously
- No hard dependencies on other agents
- Graceful degradation if agent fails

### 2. **Standardization**
- All agents use `DeviceTelemetry` format
- Common signing/encryption
- Unified metadata schema

### 3. **Specialization**
- Each agent focuses on one data source
- Deep collection from specialized APIs
- Expert domain knowledge

### 4. **Coordination**
- Agents publish, don't poll each other
- EventBus handles fan-out
- ScoreJunction correlates asynchronously

### 5. **Scalability**
- Agents scale horizontally
- One agent per host/device/network
- EventBus handles thousands of agents

### 6. **Resilience**
- WAL ensures no data loss
- Retry logic with backoff
- Circuit breakers
- Health checks

---

## 🚀 Deployment Patterns

### Pattern 1: Single-Host Deployment
```
Host Machine
├── SNMPAgent (localhost monitoring)
├── ProcAgent (process monitoring)
├── EventBus (local)
└── Dashboard (local)
```

### Pattern 2: Distributed Deployment
```
Data Center
├── Host-01
│   ├── ProcAgent
│   └── LogAgent
├── Host-02
│   ├── ProcAgent
│   └── SyscallAgent
├── Network-01
│   └── SNMPAgent (monitoring routers/switches)
├── Central Server
│   ├── EventBus
│   ├── ScoreJunction
│   ├── Intelligence Layer
│   └── Dashboard
```

### Pattern 3: Cloud/Edge Hybrid
```
Cloud (AWS/GCP)
├── EventBus (central)
├── ScoreJunction
├── Intelligence Layer
└── Dashboard

Edge Locations (100+ sites)
├── Site-01
│   ├── SNMPAgent
│   ├── ProcAgent
│   └── Local Buffer
├── Site-02
│   ├── SNMPAgent
│   └── FlowAgent
...
```

---

## 📝 Quick Start: Adding a New Agent

### Step 1: Create Agent File
```bash
mkdir -p src/amoskys/agents/newagent
touch src/amoskys/agents/newagent/newagent.py
```

### Step 2: Implement Collection
```python
class NewAgent:
    def __init__(self):
        self.sk = load_private_key('certs/agent.ed25519')
    
    async def collect_data(self):
        # Your collection logic
        pass
    
    def create_device_telemetry(self, data):
        return telemetry_pb2.DeviceTelemetry(
            device_id="device-01",
            device_type="CUSTOM",
            protocol="NEW",
            events=[...],
            collection_agent="amoskys-new-agent",
            agent_version="0.1.0"
        )
    
    def create_universal_envelope(self, device_telemetry):
        envelope = telemetry_pb2.UniversalEnvelope(...)
        envelope.sig = sign(self.sk, envelope.SerializeToString())
        return envelope
```

### Step 3: Publish to EventBus
```python
async def publish(self, envelope):
    stub = pbrpc.EventBusStub(channel)
    
    # Wrap in FlowEvent for now (until UniversalEnvelope supported)
    flow_envelope = pb.Envelope(
        version="1",
        ts_ns=envelope.ts_ns,
        idem=envelope.idempotency_key,
        flow=pb.FlowEvent(
            src_ip=envelope.device_telemetry.device_id,
            dst_ip="eventbus"
        )
    )
    
    ack = await stub.Publish(flow_envelope)
```

### Step 4: Test
```bash
python src/amoskys/agents/newagent/newagent.py
```

### Step 5: Deploy
```bash
# Add to Makefile
run-new-agent:
    .venv/bin/python src/amoskys/agents/newagent/newagent.py

# Add systemd service
sudo cp deploy/systemd/amoskys-new-agent.service /etc/systemd/system/
sudo systemctl enable amoskys-new-agent
sudo systemctl start amoskys-new-agent
```

---

## 🎉 Current Status Summary

**Implemented:**
- ✅ SNMPAgent (device telemetry)
- ✅ FlowAgent (network flows - needs update)
- ✅ ProcAgent (process monitoring - new!)
- ✅ ScoreJunction (correlation engine - new!)
- ✅ EventBus (nervous system)
- ✅ Enhanced SNMP metrics config system
- ✅ Dashboard API (REST endpoints)

**Next Steps:**
1. Test ProcAgent on production host
2. Integrate ProcAgent with EventBus
3. Test ScoreJunction with multi-agent data
4. Add SyscallAgent (eBPF)
5. Build real-time dashboard UI for multi-agent view
6. Add ML-based anomaly detection

**The organism is growing! 🧠⚡**
