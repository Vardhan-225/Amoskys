# InfraSpectre Components Guide

**Purpose**: Deep dive into each code module and component, explaining architecture, responsibilities, and interactions.

## 🏗️ System Architecture Overview

InfraSpectre follows a **distributed event-driven architecture** with these core components:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   FlowAgent     │───▶│   EventBus      │───▶│  Observability  │
│                 │    │                 │    │                 │
│ • Flow capture  │    │ • gRPC server   │    │ • Prometheus    │
│ • WAL storage   │    │ • Authentication│    │ • Grafana       │
│ • Retry logic   │    │ • Load balancing│    │ • Alerting      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 📦 Component Breakdown

### 1. FlowAgent (`src/amoskys/agents/flowagent/`)

#### 1.1 Main Agent (`main.py`)
**Purpose**: Primary agent process that captures network flow data and publishes to EventBus.

```python
# Key responsibilities:
class FlowAgent:
    def __init__(self):
        self.config = get_config()
        self.wal = SQLiteWAL(self.config.agent.wal_path)
        self.channel = self._create_mtls_channel()
        
    def run(self):
        """Main agent loop with retry logic"""
        while True:
            try:
                # 1. Capture network flows (stubbed for now)
                flow_events = self.capture_flows()
                
                # 2. Store in WAL for durability
                for event in flow_events:
                    self.wal.store(event)
                
                # 3. Publish to EventBus with retry
                self.publish_with_retry(flow_events)
                
            except Exception as e:
                self.handle_error(e)
```

**Key Features**:
- **mTLS Authentication**: Uses client certificates for secure communication
- **WAL Integration**: Ensures no data loss during network issues
- **Retry Logic**: Exponential backoff with jitter
- **Health Endpoints**: `/healthz` and `/ready` for monitoring
- **Metrics**: Publishes Prometheus metrics on configurable port

**Configuration**:
```yaml
agent:
  cert_dir: "certs"
  wal_path: "data/wal/flowagent.db"
  bus_address: "localhost:50051"
  send_rate: 100  # flows per second
  retry_max: 3
  retry_timeout: 5.0
```

#### 1.2 Write-Ahead Log (`wal_sqlite.py`)
**Purpose**: Durable storage for flow events with deduplication and recovery.

```python
class SQLiteWAL:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self._create_tables()
    
    def store(self, envelope: pb.Envelope) -> bool:
        """Store envelope with idempotency key"""
        try:
            self.conn.execute(
                "INSERT OR IGNORE INTO events (idempotency_key, envelope, timestamp) VALUES (?, ?, ?)",
                (envelope.idempotency_key, envelope.SerializeToString(), time.time())
            )
            return True
        except sqlite3.Error:
            return False
    
    def drain(self, limit: int = 100) -> List[pb.Envelope]:
        """Retrieve unsent events for publishing"""
        cursor = self.conn.execute(
            "SELECT envelope FROM events WHERE sent = 0 LIMIT ?", (limit,)
        )
        return [pb.Envelope.FromString(row[0]) for row in cursor.fetchall()]
```

**Key Features**:
- **Idempotency**: Prevents duplicate event storage
- **ACID Compliance**: SQLite transactions ensure data consistency
- **Backlog Management**: Automatic cleanup of old events
- **Corruption Handling**: Graceful handling of database corruption
- **Metrics**: Tracks WAL size, drain rate, and errors

#### 1.3 WAL Interface (`wal.py`)
**Purpose**: Abstract interface for different WAL implementations.

```python
from abc import ABC, abstractmethod

class WAL(ABC):
    @abstractmethod
    def store(self, envelope: pb.Envelope) -> bool:
        """Store an envelope durably"""
        pass
    
    @abstractmethod
    def drain(self, limit: int) -> List[pb.Envelope]:
        """Retrieve unsent envelopes"""
        pass
    
    @abstractmethod
    def mark_sent(self, idempotency_keys: List[str]) -> bool:
        """Mark envelopes as successfully sent"""
        pass
```

### 2. EventBus (`src/amoskys/eventbus/`)

#### 2.1 EventBus Server (`server.py`)
**Purpose**: Central message broker with authentication, load balancing, and observability.

```python
class EventBusServicer(pbrpc.EventBusServicer):
    def Publish(self, request: pb.Envelope, context) -> pb.PublishAck:
        """Handle incoming flow events"""
        # 1. Authentication check
        peer_cn = self._extract_peer_cn(context)
        if not self._is_authorized(peer_cn):
            return self._ack_error("UNAUTHORIZED")
        
        # 2. Signature verification
        if not self._verify_signature(request):
            return self._ack_invalid("Invalid signature")
        
        # 3. Overload protection
        if self._is_overloaded():
            return self._ack_retry("Server overloaded", backoff_ms=2000)
        
        # 4. Process event
        flow = self._extract_flow(request)
        self._log_flow_event(flow)
        
        # 5. Success response
        return self._ack_ok("Event accepted")
```

**Key Features**:
- **mTLS Authentication**: Validates client certificates against trust map
- **Ed25519 Signature Verification**: Ensures message integrity
- **Overload Protection**: Adaptive backpressure with RETRY responses
- **Prometheus Metrics**: Comprehensive observability
- **Health Endpoints**: Service health monitoring

**Security Architecture**:
```python
# Trust map validation
def _is_authorized(self, peer_cn: str) -> bool:
    """Check if peer certificate CN is in trust map"""
    return peer_cn in self.trust_map

# Message signature verification  
def _verify_signature(self, envelope: pb.Envelope) -> bool:
    """Verify Ed25519 signature over canonical bytes"""
    canonical = canonical_bytes(envelope)
    return verify(envelope.sig, canonical, self.agent_pubkey)
```

**Metrics Exposed**:
```prometheus
# Request metrics
bus_publish_total{status="ok"}
bus_publish_total{status="retry"} 
bus_publish_total{status="invalid"}

# Performance metrics
bus_publish_latency_ms_bucket
bus_inflight_requests

# Error metrics
bus_invalid_total
bus_retry_total
```

### 3. Common Utilities (`src/amoskys/common/`)

#### 3.1 Cryptographic Functions (`crypto/`)

##### Canonical Bytes (`canonical.py`)
**Purpose**: Deterministic serialization for signature verification.

```python
def canonical_bytes(envelope: pb.Envelope) -> bytes:
    """Create canonical byte representation for signing"""
    # Create copy without signature fields
    canonical_envelope = pb.Envelope()
    canonical_envelope.CopyFrom(envelope)
    canonical_envelope.sig = b""
    canonical_envelope.prev_sig = b""
    
    # Sort repeated fields deterministically
    # Serialize to bytes
    return canonical_envelope.SerializeToString(deterministic=True)
```

##### Ed25519 Signing (`signing.py`)
**Purpose**: Message signing and verification using Ed25519.

```python
def sign(message: bytes, private_key_path: str) -> bytes:
    """Sign message with Ed25519 private key"""
    with open(private_key_path, 'rb') as f:
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(f.read())
    return private_key.sign(message)

def verify(signature: bytes, message: bytes, public_key: ed25519.Ed25519PublicKey) -> bool:
    """Verify Ed25519 signature"""
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False
```

#### 3.2 Configuration Management (`config.py`)
**Purpose**: Centralized configuration with environment variable support.

```python
@dataclass
class InfraSpectreConfig:
    eventbus: EventBusConfig = field(default_factory=EventBusConfig)
    agent: AgentConfig = field(default_factory=AgentConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    
    @classmethod
    def from_environment(cls) -> 'InfraSpectreConfig':
        """Load configuration from environment variables"""
        config = cls()
        
        # EventBus configuration
        config.eventbus.port = int(os.getenv("BUS_SERVER_PORT", str(config.eventbus.port)))
        config.eventbus.overload_mode = os.getenv("BUS_OVERLOAD", "false").lower() in ("1", "true", "on", "yes")
        
        # Agent configuration  
        config.agent.wal_path = os.getenv("IS_WAL_PATH", config.agent.wal_path)
        config.agent.cert_dir = os.getenv("IS_CERT_DIR", config.agent.cert_dir)
        
        return config
```

### 4. Protocol Buffers (`src/amoskys/proto/`)

#### 4.1 Message Schema (`messaging_schema.proto`)
**Purpose**: Defines the contract between agents and EventBus.

```protobuf
message FlowEvent {
    string src_ip = 1;        // Source IP address
    string dst_ip = 2;        // Destination IP address
    int32 src_port = 3;       // Source port
    int32 dst_port = 4;       // Destination port
    string proto = 5;         // Protocol (TCP/UDP/ICMP)
    int64 bytes_tx = 6;       // Bytes transmitted
    int64 bytes_rx = 7;       // Bytes received
    int64 duration_ms = 8;    // Flow duration in milliseconds
    int64 start_time = 9;     // Flow start timestamp
    int64 end_time = 10;      // Flow end timestamp
    int32 flags = 11;         // Protocol-specific flags
}

message Envelope {
    string version = 1;           // Protocol version
    int64 ts_ns = 2;             // Timestamp in nanoseconds
    string idempotency_key = 3;   // Unique key for deduplication
    FlowEvent flow = 4;          // Flow event data
    bytes sig = 5;               // Ed25519 signature
    bytes prev_sig = 6;          // Previous signature (for chaining)
}

message PublishAck {
    enum Status {
        OK = 0;       // Event accepted
        RETRY = 1;    // Temporary failure, retry with backoff
        INVALID = 2;  // Permanent failure, don't retry
    }
    
    Status status = 1;
    string reason = 2;            // Human-readable reason
    int32 backoff_hint_ms = 3;    // Suggested retry delay
}
```

#### 4.2 Generated Code
- **messaging_schema_pb2.py**: Python message classes
- **messaging_schema_pb2_grpc.py**: gRPC service stubs
- **messaging_schema_pb2.pyi**: Type hints for IDE support

### 5. Configuration Files (`config/`)

#### 5.1 Main Configuration (`infraspectre.yaml`)
```yaml
# EventBus configuration
eventbus:
  host: "0.0.0.0"
  port: 50051
  tls_enabled: true
  max_inflight: 100
  hard_max: 500
  metrics_port_1: 9000
  metrics_port_2: 9100
  health_port: 8080

# Agent configuration
agent:
  cert_dir: "certs"
  wal_path: "data/wal/flowagent.db"
  bus_address: "localhost:50051"
  max_env_bytes: 131072
  send_rate: 100
  retry_max: 3
  retry_timeout: 5.0

# Storage configuration
storage:
  data_dir: "data"
  wal_dir: "data/wal"
  storage_dir: "data/storage"
  max_wal_bytes: 104857600  # 100MB
```

#### 5.2 Trust Map (`trust_map.yaml`)
```yaml
# Agent trust mapping for mTLS authentication
agents:
  "flowagent-001": "certs/agent.ed25519.pub"
  "flowagent-002": "certs/agent2.ed25519.pub"
  # Add more agents as needed
```

## 🔄 Component Interactions

### Flow Event Lifecycle
```
1. Agent captures flow data
   ↓
2. Agent creates Envelope with FlowEvent
   ↓  
3. Agent signs envelope with Ed25519
   ↓
4. Agent stores in WAL for durability
   ↓
5. Agent publishes to EventBus via mTLS gRPC
   ↓
6. EventBus validates certificate CN
   ↓
7. EventBus verifies signature
   ↓
8. EventBus checks overload status
   ↓
9. EventBus processes event and responds
   ↓
10. Agent marks WAL entry as sent (on OK)
    or retries with backoff (on RETRY)
```

### Error Handling Flow
```
Agent Error → WAL Storage → Retry Logic → Exponential Backoff
   ↓              ↓             ↓             ↓
Metrics       Durability   Resilience   Rate Limiting
```

### Monitoring Integration
```
Component Metrics → Prometheus → Grafana Dashboards → Alerting
      ↓                ↓             ↓               ↓
   HTTP /metrics   Time Series   Visualization   PagerDuty
```

## 🎯 Component Status & Readiness

| Component | Status | Phase 1 | Phase 2 |
|-----------|--------|---------|---------|
| **FlowAgent Core** | ✅ Complete | Working stub | Real PCAP capture |
| **WAL System** | ✅ Production Ready | SQLite implementation | Add compression |
| **EventBus** | ✅ Production Ready | Full implementation | Scale horizontally |
| **Crypto Layer** | ✅ Production Ready | Ed25519 + mTLS | Add key rotation |
| **Configuration** | ✅ Production Ready | Environment + YAML | Add runtime updates |
| **Protocol Buffers** | ✅ Production Ready | Message schema | Add versioning |
| **Monitoring** | ✅ Production Ready | Prometheus metrics | Add distributed tracing |

## 🚀 Ready for Phase 2

The component architecture provides a solid foundation for Phase 2 enhancements:

### Planned Extensions
1. **Real Flow Capture**: Replace stub with actual PCAP processing
2. **ML Integration**: Add feature extraction and anomaly detection
3. **Horizontal Scaling**: EventBus clustering and load balancing
4. **Advanced Monitoring**: Distributed tracing and APM integration
5. **Stream Processing**: Real-time analytics and correlation

### Extension Points
- **Agent Interface**: Pluggable flow capture backends
- **EventBus Plugins**: Custom processing pipelines
- **Storage Backends**: Alternative WAL implementations
- **Auth Providers**: External authentication integration

---
*Component architecture designed for production deployment and future enhancement*
