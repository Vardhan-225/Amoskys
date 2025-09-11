# InfraSpectre Component Documentation

## Overview

This document provides **comprehensive technical documentation** for every component in the InfraSpectre system. Each component is analyzed in detail with implementation specifics, interfaces, configuration options, and operational characteristics.

## Component Architecture

### System-Level Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                    InfraSpectre System                         │
├─────────────────┬─────────────────┬─────────────────────────────┤
│  Core Services  │  Infrastructure │  Operational Support       │
│                 │  Components     │                             │
│ ┌─────────────┐ │ ┌─────────────┐ │ ┌─────────────────────────┐ │
│ │ EventBus    │ │ │ Config      │ │ │ Observability           │ │
│ │ FlowAgent   │ │ │ Crypto      │ │ │ ├─ Prometheus Metrics    │ │
│ │ Protocol    │ │ │ WAL         │ │ │ ├─ Health Checks         │ │
│ │ Buffers     │ │ │ Storage     │ │ │ ├─ Grafana Dashboards    │ │
│ └─────────────┘ │ └─────────────┘ │ │ └─ Alerting Rules        │ │
│                 │                 │ │                         │ │
│                 │                 │ │ Development & Deployment│ │
│                 │                 │ │ ├─ Build System          │ │
│                 │                 │ │ ├─ Testing Framework     │ │
│                 │                 │ │ ├─ Docker Containers     │ │
│                 │                 │ │ └─ CLI Tools             │ │
└─────────────────┴─────────────────┴─────────────────────────────┘
```

## Core Service Components

### 1. EventBus Server (`src/infraspectre/eventbus/server.py`)

#### Purpose
Central message routing and processing hub that receives events from agents, validates them, and coordinates distribution to downstream systems.

#### Technical Specifications
```python
class EventBusServer:
    """
    High-performance gRPC server implementing the EventBus service
    with mTLS authentication and backpressure management.
    """
    
    # Core attributes
    port: int                    # gRPC server port (default: 50051)
    tls_credentials: ServerCredentials  # mTLS server credentials
    max_inflight: int           # Maximum concurrent messages (default: 100)
    hard_max: int              # Hard limit before dropping (default: 500)
    overload_mode: bool        # Backpressure engagement flag
    
    # Observability
    metrics_server: HTTPServer  # Prometheus metrics server (:9100)
    health_server: HTTPServer   # Health check server (:8080)
    logger: Logger             # Structured logging instance
```

#### Key Methods
```python
def start_server(self, config: EventBusConfig) -> grpc.Server:
    """Start EventBus gRPC server with mTLS configuration"""
    
def publish_event(self, request: PublishRequest, context: grpc.ServicerContext) -> PublishResponse:
    """Handle incoming event publication from agents"""
    
def health_check(self, request: HealthRequest, context: grpc.ServicerContext) -> HealthResponse:
    """Provide server health status for monitoring"""
    
def handle_backpressure(self, queue_depth: int) -> BackpressureAction:
    """Implement adaptive backpressure based on queue depth"""
```

#### Configuration Options
```yaml
# config/infraspectre.yaml
eventbus:
  host: "0.0.0.0"              # Bind address
  port: 50051                  # gRPC port
  tls_enabled: true            # mTLS requirement
  cert_dir: "certs"            # Certificate directory
  overload_mode: false         # Manual overload override
  max_inflight: 100            # Queue depth trigger
  hard_max: 500                # Drop threshold
  metrics_port_1: 9000         # Primary metrics port
  metrics_port_2: 9100         # Secondary metrics port
  health_port: 8080            # Health check port
  metrics_disabled: false      # Metrics collection toggle
  log_level: "INFO"            # Logging verbosity
```

#### Metrics Exposed
```prometheus
# Message processing metrics
infraspectre_eventbus_messages_received_total{source_agent="agent-001"} 1234
infraspectre_eventbus_messages_processed_total{source_agent="agent-001"} 1230
infraspectre_eventbus_messages_failed_total{source_agent="agent-001"} 4

# Queue management metrics
infraspectre_eventbus_inflight_messages 45
infraspectre_eventbus_overload_mode 0
infraspectre_eventbus_queue_depth_histogram_bucket{le="10"} 100

# Connection metrics
infraspectre_eventbus_connections_active 3
infraspectre_eventbus_connections_total 150
infraspectre_eventbus_auth_failures_total{agent="agent-002"} 2

# Performance metrics
infraspectre_eventbus_processing_duration_seconds_bucket{le="0.01"} 95
infraspectre_eventbus_grpc_request_duration_seconds{method="Publish"} 0.005
```

#### Error Handling
```python
# Error categories and responses
class EventBusErrors:
    AUTHENTICATION_FAILED = (grpc.StatusCode.UNAUTHENTICATED, "Certificate validation failed")
    SIGNATURE_INVALID = (grpc.StatusCode.PERMISSION_DENIED, "Message signature verification failed") 
    OVERLOAD_CONDITION = (grpc.StatusCode.RESOURCE_EXHAUSTED, "Server overloaded, backpressure engaged")
    INVALID_MESSAGE = (grpc.StatusCode.INVALID_ARGUMENT, "Message validation failed")
    INTERNAL_ERROR = (grpc.StatusCode.INTERNAL, "Internal server error")
```

#### Performance Characteristics
- **Throughput**: 10,000+ messages/second on 4-core system
- **Latency**: < 5ms processing time per message (95th percentile)
- **Memory**: ~200MB baseline + 1KB per inflight message
- **Connections**: Supports 1000+ concurrent agent connections
- **Reliability**: 99.9% uptime with graceful degradation

### 2. FlowAgent (`src/infraspectre/agents/flowagent/main.py`)

#### Purpose
Distributed data collection agent that captures network flows, extracts metadata, and reliably transmits events to the EventBus with WAL-based persistence.

#### Technical Specifications
```python
class FlowAgent:
    """
    Network data collection agent with WAL-based reliability
    and secure EventBus communication.
    """
    
    # Core attributes
    agent_id: str              # Unique agent identifier
    bus_address: str           # EventBus server address
    wal: WALInterface         # Write-ahead log implementation
    grpc_channel: grpc.Channel # Secure gRPC channel
    cert_manager: CertManager  # Certificate management
    
    # Configuration
    send_rate: int            # Events per second limit (0=unlimited)
    max_env_bytes: int        # Maximum envelope size
    retry_max: int            # Maximum retry attempts
    retry_timeout: float      # Retry backoff timeout
    
    # Observability
    metrics_server: HTTPServer # Prometheus metrics (:9101)
    health_server: HTTPServer  # Health checks (:8081)
```

#### Key Methods
```python
def start_agent(self, config: AgentConfig) -> None:
    """Initialize and start the flow agent"""
    
def collect_flow_data(self) -> FlowEvent:
    """Collect network flow data and extract features"""
    
def send_event_with_wal(self, event: FlowEvent) -> bool:
    """Send event to EventBus with WAL persistence"""
    
def handle_backpressure(self, backpressure_signal: BackpressureSignal) -> None:
    """Adapt send rate based on EventBus backpressure"""
    
def replay_wal_events(self) -> int:
    """Replay unprocessed events from WAL on startup"""
```

#### Configuration Options
```yaml
# config/infraspectre.yaml
agent:
  cert_dir: "certs"                    # Certificate directory
  wal_path: "data/wal/flowagent.db"    # WAL database path
  bus_address: "localhost:50051"       # EventBus address
  max_env_bytes: 131072                # 128KB envelope limit
  send_rate: 0                         # Unlimited by default
  retry_max: 6                         # Exponential backoff retries
  retry_timeout: 1.0                   # Base retry timeout
  metrics_port: 9101                   # Prometheus metrics port
  health_port: 8081                    # Health check port
  log_level: "INFO"                    # Logging level
```

#### Metrics Exposed
```prometheus
# Event processing metrics
infraspectre_agent_messages_sent_total{destination="eventbus"} 1234
infraspectre_agent_messages_acked_total{destination="eventbus"} 1230
infraspectre_agent_messages_failed_total{destination="eventbus"} 4

# WAL metrics
infraspectre_agent_wal_events_queued 12
infraspectre_agent_wal_events_processed_total 1222
infraspectre_agent_wal_events_dropped_total 0
infraspectre_agent_wal_size_bytes 1048576

# Network collection metrics
infraspectre_agent_network_bytes_captured_total 567890123
infraspectre_agent_flows_analyzed_total 45678
infraspectre_agent_packets_processed_total 123456789

# Performance metrics
infraspectre_agent_collection_duration_seconds 0.005
infraspectre_agent_processing_duration_seconds 0.010
infraspectre_agent_health_check_duration_seconds 0.045
```

#### State Management
```python
# Agent lifecycle states
class AgentState(Enum):
    INITIALIZING = "initializing"    # Starting up, loading config
    CONNECTING = "connecting"        # Establishing EventBus connection
    ACTIVE = "active"               # Normal operation
    BACKPRESSURE = "backpressure"   # Reduced send rate due to backpressure
    RETRYING = "retrying"           # Connection retry mode
    SHUTDOWN = "shutdown"           # Graceful shutdown in progress
    ERROR = "error"                 # Error state requiring intervention
```

### 3. Write-Ahead Log (WAL) (`src/infraspectre/agents/flowagent/wal_sqlite.py`)

#### Purpose
Reliable event persistence system that ensures no data loss during network outages, EventBus unavailability, or agent restarts.

#### Technical Specifications
```python
class WALSQLite:
    """
    SQLite-based WAL implementation with deduplication,
    retry logic, and backlog management.
    """
    
    # Core attributes
    db_path: str              # SQLite database file path
    connection: sqlite3.Connection  # Database connection
    max_backlog: int          # Maximum events before dropping oldest
    retry_timeout: float      # Retry delay calculation
    dedup_window: int         # Deduplication time window
    
    # Schema
    events_table: str = """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT UNIQUE NOT NULL,
            agent_id TEXT NOT NULL,
            event_data BLOB NOT NULL,
            checksum TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            processed BOOLEAN DEFAULT FALSE,
            retry_count INTEGER DEFAULT 0,
            last_retry TIMESTAMP,
            INDEX(processed),
            INDEX(created_at),
            INDEX(agent_id)
        )
    """
```

#### Key Methods
```python
def store_event(self, event: FlowEvent) -> bool:
    """Store event in WAL with deduplication check"""
    
def get_pending_events(self, limit: int = 100) -> List[WALEvent]:
    """Retrieve unprocessed events for transmission"""
    
def mark_processed(self, event_id: str) -> bool:
    """Mark event as successfully processed"""
    
def increment_retry(self, event_id: str) -> bool:
    """Increment retry count and update timestamp"""
    
def cleanup_old_events(self, retention_hours: int = 24) -> int:
    """Remove old processed events to manage storage"""
    
def get_wal_statistics(self) -> WALStatistics:
    """Return WAL health and performance metrics"""
```

#### Storage Configuration
```yaml
# config/infraspectre.yaml
storage:
  data_dir: "data"                     # Base data directory
  wal_dir: "data/wal"                  # WAL-specific directory
  storage_dir: "data/storage"          # Long-term storage
  metrics_dir: "data/metrics"          # Metrics storage
  max_wal_bytes: 209715200            # 200MB WAL size limit
```

#### WAL Management Operations
```python
# Administrative operations
class WALManager:
    def verify_integrity(self, wal_path: str) -> IntegrityResult:
        """Verify WAL database integrity and checksums"""
        
    def compact_wal(self, wal_path: str) -> CompactionResult:
        """Compact WAL database to reclaim space"""
        
    def export_events(self, wal_path: str, start_time: datetime, end_time: datetime) -> List[FlowEvent]:
        """Export events for analysis or migration"""
        
    def import_events(self, wal_path: str, events: List[FlowEvent]) -> ImportResult:
        """Import events from external source"""
```

### 4. Configuration Management (`src/infraspectre/config.py`)

#### Purpose
Centralized configuration system that provides type-safe, validated configuration loading with environment variable overrides and YAML file support.

#### Technical Specifications
```python
@dataclass
class InfraSpectreConfig:
    """Complete system configuration with validation"""
    eventbus: EventBusConfig
    agent: AgentConfig
    crypto: CryptoConfig
    storage: StorageConfig
    
    @classmethod
    def load(cls, config_path: Optional[str] = None) -> 'InfraSpectreConfig':
        """Load configuration from YAML with environment overrides"""
        
    def validate(self) -> ValidationResult:
        """Validate configuration consistency and requirements"""
```

#### Configuration Components
```python
@dataclass
class EventBusConfig:
    host: str = "0.0.0.0"
    port: int = 50051
    tls_enabled: bool = True
    cert_dir: str = "certs"
    overload_mode: bool = False
    max_inflight: int = 100
    hard_max: int = 500
    metrics_port_1: int = 9000
    metrics_port_2: int = 9100
    health_port: int = 8080
    metrics_disabled: bool = False
    log_level: str = "INFO"

@dataclass 
class AgentConfig:
    cert_dir: str = "certs"
    wal_path: str = "data/wal/flowagent.db"
    bus_address: str = "localhost:50051"
    max_env_bytes: int = 131072
    send_rate: int = 0
    retry_max: int = 6
    retry_timeout: float = 1.0
    metrics_port: int = 9101
    health_port: int = 8081
    log_level: str = "INFO"

@dataclass
class CryptoConfig:
    ed25519_private_key: str = "certs/agent.ed25519"
    trust_map_path: str = "config/trust_map.yaml"
    ca_cert: str = "certs/ca.crt"
    server_cert: str = "certs/server.crt"
    server_key: str = "certs/server.key"
    agent_cert: str = "certs/agent.crt"
    agent_key: str = "certs/agent.key"

@dataclass
class StorageConfig:
    data_dir: str = "data"
    wal_dir: str = "data/wal"
    storage_dir: str = "data/storage"
    metrics_dir: str = "data/metrics"
    max_wal_bytes: int = 209715200  # 200MB
```

#### Environment Variable Overrides
```bash
# EventBus overrides
export BUS_SERVER_PORT=50052
export BUS_SERVER_HOST=0.0.0.0
export BUS_OVERLOAD=auto

# Agent overrides  
export IS_WAL_PATH=/custom/wal/path.db
export IS_CERT_DIR=/custom/certs/
export BUS_ADDRESS=eventbus.internal:50051

# General overrides
export IS_CONFIG_PATH=/etc/infraspectre/config.yaml
export IS_LOG_LEVEL=DEBUG
```

## Infrastructure Components

### 5. Cryptographic Services (`src/infraspectre/common/crypto/`)

#### Purpose
Comprehensive cryptographic functionality including Ed25519 message signing, certificate management, and secure communication primitives.

#### Ed25519 Signing (`signing.py`)
```python
class Ed25519Signer:
    """
    Ed25519 digital signature implementation for message authentication
    """
    
    def __init__(self, private_key_path: str):
        self.private_key = self.load_private_key(private_key_path)
        self.public_key = self.private_key.public_key()
    
    def sign_message(self, message: bytes) -> bytes:
        """Sign message with Ed25519 private key"""
        
    def verify_signature(self, message: bytes, signature: bytes, public_key: ed25519.Ed25519PublicKey) -> bool:
        """Verify Ed25519 signature"""
        
    def generate_keypair(self) -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        """Generate new Ed25519 keypair"""
```

#### Canonical Message Processing (`canonical.py`)
```python
class CanonicalProcessor:
    """
    Canonical message format for consistent signing and verification
    """
    
    def canonicalize_envelope(self, envelope: pb.Envelope) -> bytes:
        """Create canonical representation for signing"""
        
    def verify_envelope_signature(self, envelope: pb.Envelope, public_key: ed25519.Ed25519PublicKey) -> bool:
        """Verify envelope signature against canonical form"""
```

### 6. Protocol Buffer Definitions (`src/infraspectre/proto/`)

#### Message Schema (`messaging_schema.proto`)
```protobuf
syntax = "proto3";
package infraspectre;

// Core flow event message
message FlowEvent {
    string source_ip = 1;           // Source IP address
    string dest_ip = 2;             // Destination IP address
    uint32 source_port = 3;         // Source port number
    uint32 dest_port = 4;           // Destination port number
    string protocol = 5;            // Protocol (TCP/UDP/ICMP)
    uint64 bytes_sent = 6;          // Bytes transmitted
    uint64 packets_sent = 7;        // Packets transmitted
    uint64 start_time_ns = 8;       // Flow start timestamp (nanoseconds)
    uint64 end_time_ns = 9;         // Flow end timestamp (nanoseconds)
    map<string, string> metadata = 10; // Additional flow metadata
}

// Message envelope with security and routing information
message Envelope {
    string source_agent = 1;        // Agent identifier
    string event_id = 2;            // Unique event identifier
    uint64 timestamp_ns = 3;        // Event timestamp (nanoseconds)
    FlowEvent flow_event = 4;       // Actual flow data
    bytes signature = 5;            // Ed25519 signature (excluding this field)
}

// EventBus service definition
service EventBusService {
    rpc Publish(PublishRequest) returns (PublishResponse);
    rpc Health(HealthRequest) returns (HealthResponse);
}

message PublishRequest {
    Envelope envelope = 1;
}

message PublishResponse {
    bool success = 1;
    string message = 2;
    uint64 server_timestamp = 3;
}

message HealthRequest {}

message HealthResponse {
    bool healthy = 1;
    string status = 2;
    uint64 uptime_seconds = 3;
    uint32 active_connections = 4;
    uint32 queue_depth = 5;
}
```

#### Generated Code Integration
```python
# Import generated protocol buffer classes
from infraspectre.proto import messaging_schema_pb2 as pb
from infraspectre.proto import messaging_schema_pb2_grpc as pb_grpc

# Usage example
envelope = pb.Envelope()
envelope.source_agent = "agent-001"
envelope.event_id = str(uuid.uuid4())
envelope.timestamp_ns = time.time_ns()

flow_event = pb.FlowEvent()
flow_event.source_ip = "192.168.1.100"
flow_event.dest_ip = "10.0.0.50"
envelope.flow_event.CopyFrom(flow_event)
```

## Operational Support Components

### 7. Observability Stack

#### Prometheus Metrics Collection
```python
# Core metrics definitions
from prometheus_client import Counter, Histogram, Gauge, Info

# EventBus metrics
eventbus_messages_received = Counter(
    'infraspectre_eventbus_messages_received_total',
    'Total messages received by EventBus',
    ['source_agent']
)

eventbus_processing_duration = Histogram(
    'infraspectre_eventbus_processing_duration_seconds',
    'Time spent processing messages',
    buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
)

eventbus_inflight_messages = Gauge(
    'infraspectre_eventbus_inflight_messages',
    'Number of messages currently being processed'
)

# Agent metrics
agent_wal_events_queued = Gauge(
    'infraspectre_agent_wal_events_queued',
    'Number of events queued in WAL'
)

agent_messages_sent = Counter(
    'infraspectre_agent_messages_sent_total',
    'Total messages sent by agent',
    ['destination']
)
```

#### Health Check Implementation
```python
class HealthChecker:
    """
    Comprehensive health checking for all components
    """
    
    def check_eventbus_health(self) -> HealthStatus:
        """Check EventBus server health"""
        checks = {
            'grpc_server': self.check_grpc_responsive(),
            'message_processing': self.check_processing_pipeline(),
            'certificate_validity': self.check_certificates(),
            'queue_depth': self.check_queue_health(),
            'memory_usage': self.check_memory_usage(),
            'disk_space': self.check_disk_space()
        }
        return HealthStatus(checks)
    
    def check_agent_health(self) -> HealthStatus:
        """Check FlowAgent health"""
        checks = {
            'eventbus_connectivity': self.check_eventbus_connection(),
            'wal_database': self.check_wal_health(),
            'data_collection': self.check_collection_pipeline(),
            'certificate_validity': self.check_certificates(),
            'resource_usage': self.check_resource_usage()
        }
        return HealthStatus(checks)
```

#### Grafana Dashboard Configuration
```json
{
  "dashboard": {
    "title": "InfraSpectre System Overview",
    "panels": [
      {
        "title": "Message Throughput",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(infraspectre_eventbus_messages_received_total[5m])",
            "legendFormat": "{{source_agent}}"
          }
        ],
        "yAxes": [{
          "label": "Messages/second"
        }]
      },
      {
        "title": "Processing Latency",
        "type": "graph", 
        "targets": [
          {
            "expr": "histogram_quantile(0.95, infraspectre_eventbus_processing_duration_seconds_bucket)",
            "legendFormat": "95th percentile"
          },
          {
            "expr": "histogram_quantile(0.50, infraspectre_eventbus_processing_duration_seconds_bucket)",
            "legendFormat": "Median"
          }
        ]
      },
      {
        "title": "WAL Queue Depth",
        "type": "graph",
        "targets": [
          {
            "expr": "infraspectre_agent_wal_events_queued",
            "legendFormat": "{{instance}}"
          }
        ]
      },
      {
        "title": "System Health",
        "type": "stat",
        "targets": [
          {
            "expr": "up{job=~\"infraspectre-.*\"}",
            "legendFormat": "{{job}}"
          }
        ]
      }
    ]
  }
}
```

### 8. Build and Development System

#### Makefile Automation (`Makefile`)
```makefile
# Core development commands
.PHONY: setup setup-dev clean test proto run-eventbus run-agent

# Environment setup
setup: venv install-deps dirs proto

setup-dev: setup
	pip install black isort flake8 mypy pytest pytest-asyncio
	pre-commit install

# Build operations
proto:
	python -m grpc_tools.protoc -I proto \
		--python_out=src/infraspectre/proto \
		--grpc_python_out=src/infraspectre/proto \
		proto/messaging_schema.proto

clean:
	rm -rf build/ dist/ *.egg-info/
	find . -type d -name __pycache__ -delete
	find . -type f -name "*.pyc" -delete

# Testing
test:
	pytest tests/ -v

test-coverage:
	pytest tests/ --cov=src/infraspectre --cov-report=html

# Service operations
run-eventbus:
	./infraspectre-eventbus

run-agent:
	./infraspectre-agent

# Docker operations
build-docker:
	docker build -f deploy/Dockerfile.eventbus -t infraspectre/eventbus .
	docker build -f deploy/Dockerfile.agent -t infraspectre/agent .

# Certificate management
certs:
	./scripts/gen_ed25519.sh
	openssl req -x509 -newkey rsa:4096 -keyout certs/ca.key -out certs/ca.crt -days 365 -nodes

# Development utilities
format:
	black src/ tests/
	isort src/ tests/

lint:
	flake8 src/ tests/
	mypy src/

# Monitoring
curl-health:
	curl -s http://localhost:8080/health | jq '.'
	curl -s http://localhost:8081/health | jq '.'

curl-metrics:
	curl -s http://localhost:9100/metrics | grep infraspectre
	curl -s http://localhost:9101/metrics | grep infraspectre
```

#### Entry Point Scripts
```bash
#!/usr/bin/env python3
# infraspectre-eventbus

import sys
import os
import argparse
from pathlib import Path

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def main():
    parser = argparse.ArgumentParser(description="InfraSpectre EventBus Server")
    parser.add_argument("--overload", choices=["on", "off", "auto"],
                       help="Override overload behavior")
    parser.add_argument("--config", help="Path to configuration YAML file")
    parser.add_argument("--port", type=int, help="Override server port")
    parser.add_argument("--host", help="Override server host")
    
    args = parser.parse_args()
    
    # Set environment overrides
    if args.port:
        os.environ["BUS_SERVER_PORT"] = str(args.port)
    if args.host:
        os.environ["BUS_SERVER_HOST"] = args.host
    if args.config:
        os.environ["IS_CONFIG_PATH"] = args.config
    if args.overload:
        os.environ["BUS_OVERLOAD"] = args.overload
    
    # Import and run EventBus
    from infraspectre.eventbus.server import main as eventbus_main
    eventbus_main()

if __name__ == "__main__":
    main()
```

### 9. Testing Framework

#### Test Structure and Categories
```
tests/
├── unit/                           # Unit tests for individual components
│   ├── test_jitter.py             # Sleep jitter functionality
│   └── test_wal_sqlite.py         # WAL database operations
├── component/                      # Integration tests between components
│   ├── test_bus_inflight_metric.py    # EventBus metrics
│   ├── test_fitness.py               # Performance validation
│   ├── test_publish_paths.py         # Message publishing workflows
│   ├── test_retry_path.py            # Retry logic validation
│   └── test_wal_grow_drain.py        # WAL lifecycle testing
├── golden/                         # Binary compatibility tests
│   ├── envelope_v1.bin            # Reference binary data
│   ├── envelope_v1.sha256         # Checksum validation
│   └── test_envelope_bytes.py     # Protocol buffer compatibility
├── integration/                    # End-to-end system tests
└── fixtures/                      # Test data and utilities
```

#### Test Configuration (`pyproject.toml`)
```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py", "*_test.py"]
python_classes = ["Test*"]
python_functions = ["test_*"]
addopts = [
    "-ra",
    "--strict-markers",
    "--strict-config",
    "--cov=src/infraspectre",
    "--cov-branch",
    "--cov-report=term-missing:skip-covered",
    "--cov-report=html:htmlcov",
    "--cov-report=xml"
]
filterwarnings = [
    "error",
    "ignore::UserWarning",
    "ignore::DeprecationWarning"
]
markers = [
    "unit: Unit tests",
    "component: Component integration tests", 
    "integration: End-to-end integration tests",
    "golden: Binary compatibility tests",
    "slow: Tests that take significant time"
]

[tool.coverage.run]
branch = true
source = ["src/infraspectre"]
omit = [
    "*/tests/*",
    "*/test_*.py",
    "*/__pycache__/*",
    "*/site-packages/*"
]

[tool.coverage.report]
exclude_lines = [
    "pragma: no cover",
    "def __repr__",
    "if self.debug:",
    "if settings.DEBUG",
    "raise AssertionError",
    "raise NotImplementedError",
    "if 0:",
    "if __name__ == .__main__.:"
]
```

## Component Dependencies

### Dependency Graph
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   EventBus      │    │   FlowAgent     │    │   Config        │
│                 │    │                 │    │   System        │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │                 │
│ │ gRPC Server │ │ <- │ │ gRPC Client │ │ <- │ ┌─────────────┐ │
│ │ Auth        │ │    │ │ WAL         │ │    │ │ YAML Parser │ │
│ │ Metrics     │ │    │ │ Crypto      │ │    │ │ Validation  │ │
│ └─────────────┘ │    │ └─────────────┘ │    │ │ Env Vars    │ │
└─────────────────┘    └─────────────────┘    │ └─────────────┘ │
         │                       │             └─────────────────┘
         v                       v                       │
┌─────────────────┐    ┌─────────────────┐              │
│  Crypto Stack   │    │   WAL System    │              │
│                 │    │                 │              │
│ ┌─────────────┐ │    │ ┌─────────────┐ │              │
│ │ Ed25519     │ │    │ │ SQLite      │ │              │
│ │ mTLS        │ │    │ │ Persistence │ │              │
│ │ Certificates│ │    │ │ Retry Logic │ │              │
│ └─────────────┘ │    │ └─────────────┘ │              │
└─────────────────┘    └─────────────────┘              │
         │                       │                       │
         v                       v                       v
┌─────────────────────────────────────────────────────────────┐
│                    Protocol Buffers                        │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐  │
│  │ FlowEvent   │ │ Envelope    │ │ EventBusService     │  │
│  │ Messages    │ │ Wrapper     │ │ gRPC Definitions    │  │
│  └─────────────┘ └─────────────┘ └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Build Dependencies
```python
# requirements-clean.txt
grpcio==1.66.2              # Core gRPC framework
grpcio-tools==1.66.2        # Protocol buffer compilation
protobuf==5.28.2            # Message serialization
PyYAML==6.0.2               # Configuration file parsing
cryptography==43.0.1        # TLS and certificate management
pycryptodome==3.21.0        # Ed25519 signing implementation
prometheus-client==0.21.0   # Metrics collection
pytest==8.4.1               # Testing framework
pytest-asyncio==0.24.0      # Async test support
black==24.10.0               # Code formatting
isort==5.13.2                # Import sorting
flake8==7.1.1                # Linting
mypy==1.13.0                 # Type checking
```

## Performance Characteristics

### Component Performance Profiles

| Component | Memory Usage | CPU Usage | Disk I/O | Network I/O |
|-----------|-------------|-----------|----------|-------------|
| EventBus | 200MB base + 1KB/msg | 10-30% (4 cores) | Minimal | High |
| FlowAgent | 100MB base + WAL | 5-20% (2 cores) | Medium (WAL) | Medium |
| WAL System | 50MB + data size | 1-5% (1 core) | High (SQLite) | None |
| Config System | 10MB | <1% | Minimal | None |
| Crypto Stack | 20MB | 2-10% | None | None |

### Scaling Characteristics

#### EventBus Scaling
- **Vertical**: Linear scaling to 8 cores, diminishing returns beyond
- **Horizontal**: Load balancer + multiple EventBus instances
- **Bottlenecks**: Message processing pipeline, database writes

#### Agent Scaling  
- **Per-Host**: One agent per monitored host (DaemonSet pattern)
- **Resource**: WAL disk space and network bandwidth
- **Bottlenecks**: PCAP processing (Phase 2), WAL write throughput

## Operational Procedures

### Component Health Monitoring
```bash
# Component-specific health checks
check_eventbus_health() {
    curl -f http://localhost:8080/health
    echo $? # 0 = healthy, non-zero = unhealthy
}

check_agent_health() {
    curl -f http://localhost:8081/health
    echo $?
}

check_wal_health() {
    sqlite3 data/wal/flowagent.db "PRAGMA integrity_check;"
}

check_crypto_health() {
    # Certificate expiration check
    openssl x509 -in certs/server.crt -noout -dates
    openssl x509 -in certs/agent.crt -noout -dates
}
```

### Component Restart Procedures
```bash
# Safe component restart sequence
restart_infraspectre() {
    echo "Stopping FlowAgent first (graceful)"
    pkill -TERM infraspectre-agent
    sleep 5
    
    echo "Stopping EventBus (graceful)"
    pkill -TERM infraspectre-eventbus
    sleep 10
    
    echo "Starting EventBus"
    ./infraspectre-eventbus &
    sleep 5
    
    echo "Verifying EventBus health"
    curl -f http://localhost:8080/health
    
    echo "Starting FlowAgent"
    ./infraspectre-agent &
    sleep 5
    
    echo "Verifying Agent health"
    curl -f http://localhost:8081/health
}
```

This comprehensive component documentation provides the technical depth needed to understand, maintain, and extend every aspect of the InfraSpectre system.
