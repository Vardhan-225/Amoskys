# InfraSpectre Architecture

## Overview

InfraSpectre is designed as a distributed, event-driven security monitoring system with a focus on reliability, security, and scalability. The architecture follows a producer-consumer pattern with agents collecting events and an event bus processing them.

## System Components

### 1. Event Collection Layer

#### FlowAgent
- **Purpose**: Monitors network flows and generates security events
- **Location**: `src/infraspectre/agents/flowagent/`
- **Key Features**:
  - Network packet analysis
  - Process monitoring capabilities
  - SQLite-based Write-Ahead Logging (WAL)
  - Automatic retry with exponential backoff
  - Rate limiting and backpressure handling

#### Future Agents
- **ProcessAgent**: System call and process lifecycle monitoring
- **FileAgent**: File system change monitoring
- **NetworkAgent**: Deep packet inspection and protocol analysis

### 2. Event Bus Layer

#### EventBus Server
- **Purpose**: Central event ingestion and validation service
- **Location**: `src/infraspectre/eventbus/`
- **Key Features**:
  - gRPC server with mTLS authentication
  - Message validation and cryptographic verification
  - Overload protection and rate limiting
  - Duplicate detection with idempotency keys
  - Prometheus metrics integration

### 3. Transport Security

#### mTLS Authentication
```
Agent                              EventBus
┌─────────────┐                   ┌─────────────┐
│ Client Cert │ ─── mTLS ────────▶ │ Server Cert │
│ Private Key │                   │ Private Key │
│             │ ◀── Verify ────── │ CA Bundle   │
└─────────────┘                   └─────────────┘
```

#### Message Signing
```
Message Flow:
1. Agent creates Envelope with event data
2. Agent generates canonical bytes representation
3. Agent signs with Ed25519 private key
4. EventBus verifies signature with agent's public key
5. EventBus processes message if valid
```

### 4. Data Flow Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        InfraSpectre Data Flow                   │
└─────────────────────────────────────────────────────────────────┘

    Event Sources                    Collection                Processing
 ┌─────────────────┐              ┌──────────────┐          ┌─────────────┐
 │                 │              │              │          │             │
 │ • Network Flows │─────────────▶│  FlowAgent   │─────────▶│  EventBus   │
 │ • Process Trees │              │              │          │             │
 │ • File Changes  │              │ • WAL Store  │          │ • Validate  │
 │ • System Calls  │              │ • Retry      │          │ • Dedupe    │
 │                 │              │ • Rate Limit │          │ • Route     │
 └─────────────────┘              └──────────────┘          └─────────────┘
                                                                    │
                                                                    ▼
 ┌─────────────────┐              ┌──────────────┐          ┌─────────────┐
 │                 │              │              │          │             │
 │ • Time Series   │◀─────────────│  Analytics   │◀─────────│   Storage   │
 │ • Correlation   │              │              │          │             │
 │ • Detection     │              │ • Rules      │          │ • SQLite    │
 │ • Alerting      │              │ • ML Models  │          │ • JSON Logs │
 │                 │              │ • Scoring    │          │ • Metrics   │
 └─────────────────┘              └──────────────┘          └─────────────┘
```

## Message Format

### Envelope Structure
```protobuf
message Envelope {
  string version           = 1;  // Protocol version
  uint64 ts_ns             = 2;  // Timestamp (nanoseconds)
  string idempotency_key   = 3;  // Deduplication key
  FlowEvent flow           = 4;  // Event payload
  bytes  sig               = 5;  // Ed25519 signature
  bytes  prev_sig          = 6;  // Previous signature (chaining)
  bytes  payload           = 7;  // Generic payload
}
```

### FlowEvent Structure
```protobuf
message FlowEvent {
  string src_ip     = 1;   // Source IP address
  string dst_ip     = 2;   // Destination IP address
  uint32 src_port   = 3;   // Source port
  uint32 dst_port   = 4;   // Destination port
  string protocol   = 5;   // Protocol (TCP, UDP, etc.)
  uint64 bytes_sent = 6;   // Bytes transmitted
  uint64 bytes_recv = 7;   // Bytes received
  uint32 flags      = 8;   // Protocol flags
  uint64 start_time = 9;   // Flow start time
  uint64 end_time   = 10;  // Flow end time
  uint32 duration_ms= 14;  // Flow duration
}
```

## Configuration Management

### Centralized Configuration
- **Location**: `src/infraspectre/config.py`
- **Features**:
  - Environment variable override support
  - YAML configuration file support
  - Validation with error reporting
  - Type safety with dataclasses
  - Default value management

### Configuration Hierarchy
```
1. Default values (in code)
2. YAML configuration file
3. Environment variables (highest priority)
4. CLI arguments (overrides all)
```

## Security Model

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Agent Impersonation | mTLS with CN allowlist |
| Message Tampering | Ed25519 signatures over canonical bytes |
| Replay Attacks | Idempotency keys with TTL |
| Resource Exhaustion | Inflight limits, backpressure, size caps |
| Data Exfiltration | 128KB payload limit, audit logging |
| Persistence Loss | SQLite WAL, fsync policy |

### Authentication Flow
```
1. Agent presents client certificate
2. EventBus validates certificate against CA
3. EventBus checks CN against allowlist
4. Agent signs message with Ed25519 private key
5. EventBus verifies signature with agent's public key
6. Message processed if all checks pass
```

## Reliability Patterns

### Write-Ahead Logging (WAL)
```
Agent Side:
┌─────────────┐    Network     ┌─────────────┐
│   Event     │     Error      │    WAL      │
│ Generation  │ ──────────────▶│  Storage    │
└─────────────┘                └─────────────┘
       │                              │
       │ Network OK                   │ Drain
       ▼                              │ Periodically
┌─────────────┐                       │
│  Direct     │◀──────────────────────┘
│  Publish    │
└─────────────┘
```

### Backpressure Control
```
EventBus Load Levels:
├── Normal (< max_inflight)     → Accept
├── High (< hard_max)          → Accept with warning
├── Overload (≥ hard_max)      → RETRY response
└── Critical (agent overload)  → Agent WAL storage
```

### Retry Strategy
```python
# Exponential backoff with jitter
def backoff_delay(attempt: int) -> float:
    base = min(2.0, 0.05 * (2 ** attempt))
    return base * (0.5 + random.random())
```

## Observability

### Metrics Hierarchy
```
System Metrics
├── EventBus
│   ├── bus_publish_total
│   ├── bus_inflight_requests
│   ├── bus_retry_total
│   └── bus_publish_latency_ms
├── Agent
│   ├── agent_publish_ok_total
│   ├── agent_publish_retry_total
│   ├── agent_wal_backlog_bytes
│   └── agent_ready_state
└── Infrastructure
    ├── System load, memory, disk
    ├── Network connectivity
    └── Certificate expiration
```

### Health Checks
- **EventBus**: HTTP `/healthz` endpoint (port 8080)
- **Agent**: HTTP `/ready` endpoint (port 8081)
- **Metrics**: Prometheus `/metrics` endpoint (port 9101)

## Deployment Patterns

### Development
```bash
# Local development with make
make setup && make run-all
```

### Docker Compose
```yaml
services:
  eventbus:
    image: infraspectre/eventbus:latest
    ports: ["50051:50051", "8080:8080"]
  agent:
    image: infraspectre/agent:latest
    depends_on: [eventbus]
```

### Kubernetes
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: infraspectre-eventbus
spec:
  replicas: 3
  selector:
    matchLabels:
      app: infraspectre-eventbus
```

## Performance Characteristics

### Throughput
- **Target**: 10,000 events/second per EventBus instance
- **Bottlenecks**: Signature verification, WAL I/O, network latency
- **Scaling**: Horizontal scaling with multiple EventBus instances

### Latency
- **Target**: p99 < 50ms for event processing
- **Components**: 
  - Network: 1-5ms
  - Validation: 5-10ms
  - Storage: 10-20ms
  - Processing: 20-50ms

### Resource Usage
- **EventBus**: 512MB RAM, 2 CPU cores
- **Agent**: 256MB RAM, 1 CPU core
- **Storage**: ~10KB per event, 200MB WAL limit

## Extension Points

### Adding New Event Types
1. Update `proto/messaging_schema.proto`
2. Regenerate protocol buffers
3. Update canonical bytes calculation
4. Add validation logic
5. Update documentation

### Custom Agents
1. Implement agent interface
2. Add configuration schema
3. Create systemd/k8s manifests
4. Add health checks
5. Include metrics

### Analytics Plugins
1. Subscribe to event stream
2. Implement detection logic
3. Generate alerts/actions
4. Export results

---

This architecture provides a solid foundation for building advanced security monitoring capabilities while maintaining reliability, security, and operational simplicity.
