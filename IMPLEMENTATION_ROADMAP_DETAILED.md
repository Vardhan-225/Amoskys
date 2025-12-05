# AMOSKYS Technical Implementation Roadmap

**Purpose**: Detailed, implementable path to transform AMOSKYS from research project to production security platform

**Timeline**: 26 weeks (6 months) for GA; 8 weeks for minimal MVP  

---

## Phase 0: Immediate Stabilization (Weeks 1-2)

**Goal**: Fix critical bugs, unblock all tests

### Task 0.1: Fix Prometheus Metrics Collision

**Problem**: `test_inflight_metric_rises_then_falls` and `test_wal_grows_then_drains` fail because Prometheus metrics registered multiple times

**Files to Change**:
- `src/amoskys/agents/flowagent/main.py` (lines 50-62)
- `src/amoskys/eventbus/server.py` (lines 106-110)
- `src/amoskys/agents/snmp/snmp_agent.py` (lines 55-64)
- `src/amoskys/agents/proc/proc_agent.py` (if it creates metrics)

**Implementation**:
```python
# BEFORE (lines 50-62 in flowagent/main.py)
AGENT_DROPPED_OVERSIZE = Counter("agent_dropped_oversize_total", "...")
AG_PUB_OK = Counter("agent_publish_ok_total", "...")
# ... direct instantiation, will collide

# AFTER: Use metric registry with collision detection
from prometheus_client import REGISTRY, CollectorAlreadyRegisteredError

def init_metrics():
    """Initialize metrics with collision detection"""
    global AGENT_DROPPED_OVERSIZE, AG_PUB_OK, ...
    
    # Try to register; if already exists, get from registry
    try:
        AGENT_DROPPED_OVERSIZE = Counter("agent_dropped_oversize_total", "...")
    except CollectorAlreadyRegisteredError:
        # Metric already registered, don't re-register
        pass
    
    try:
        AG_PUB_OK = Counter("agent_publish_ok_total", "...")
    except CollectorAlreadyRegisteredError:
        pass
    
    # ... repeat for all metrics
```

**Call this in `if __name__ == "__main__":`** block to delay registration until main execution

**Effort**: 4-6 hours  
**Verification**: Run tests again; both should pass without timeout

---

### Task 0.2: Environment Variable Validation

**Problem**: Crashes on bad env vars; no validation or helpful error messages

**Files to Change**:
- `src/amoskys/config.py` (entire file)

**Implementation**:
```python
# Add validation function
def validate_config(config: AmoskysConfig) -> List[str]:
    """Validate configuration and return list of errors (empty if valid)"""
    errors = []
    
    # Port validation
    if not (1 <= config.eventbus.port <= 65535):
        errors.append(f"BUS_SERVER_PORT={config.eventbus.port} not in range 1-65535")
    if not (1 <= config.agent.metrics_port <= 65535):
        errors.append(f"AGENT_METRICS_PORT={config.agent.metrics_port} not in range 1-65535")
    
    # Size validation
    if config.agent.max_env_bytes <= 0:
        errors.append(f"IS_MAX_ENV_BYTES={config.agent.max_env_bytes} must be positive")
    if config.agent.max_env_bytes > 10 * 1024 * 1024:  # 10MB max
        errors.append(f"IS_MAX_ENV_BYTES={config.agent.max_env_bytes} exceeds 10MB limit")
    
    # Retry validation
    if config.agent.retry_max < 0 or config.agent.retry_max > 20:
        errors.append(f"IS_RETRY_MAX={config.agent.retry_max} must be in 0-20")
    
    # File path validation
    if config.crypto.ed25519_private_key and not os.path.exists(config.crypto.ed25519_private_key):
        warnings.warn(f"ED25519 key not found: {config.crypto.ed25519_private_key}")
    
    return errors

# In config loading:
config = get_config()
errors = validate_config(config)
if errors:
    logger.error("Configuration validation failed:")
    for err in errors:
        logger.error(f"  - {err}")
    sys.exit(1)
```

**Effort**: 3-4 hours  
**Testing**: Create `test_config_validation.py` with bad values

---

### Task 0.3: Standardize Environment Variable Prefixes

**Problem**: `IS_*` prefix is confusing

**Files to Change**:
- `src/amoskys/config.py`
- `config/amoskys.yaml` (documentation)
- All deployment files: `deploy/`, `scripts/`

**Breaking Change**: Migration guide required

**New Naming Scheme**:
```
Old Name                  → New Name
────────────────────────────────────
IS_CERT_DIR             → AMOSKYS_AGENT_CERT_DIR
IS_WAL_PATH             → AMOSKYS_AGENT_WAL_PATH
IS_BUS_ADDRESS          → AMOSKYS_AGENT_BUS_ADDRESS
IS_MAX_ENV_BYTES        → AMOSKYS_AGENT_MAX_ENV_BYTES
IS_SEND_RATE            → AMOSKYS_AGENT_SEND_RATE
IS_RETRY_MAX            → AMOSKYS_AGENT_RETRY_MAX
IS_RETRY_TIMEOUT        → AMOSKYS_AGENT_RETRY_TIMEOUT
IS_METRICS_PORT         → AMOSKYS_AGENT_METRICS_PORT
IS_HEALTH_PORT          → AMOSKYS_AGENT_HEALTH_PORT
```

**Implementation**: Support BOTH old and new names for backwards compatibility
```python
# In config.py from_env():
def _get_env_var(new_name: str, old_name: str, default: str) -> str:
    """Get env var, preferring new name, falling back to old name"""
    val = os.getenv(new_name)
    if val is None:
        val = os.getenv(old_name)
        if val is not None:
            logger.warning(f"{old_name} is deprecated; use {new_name} instead")
    return val or default

# Usage:
config.agent.cert_dir = _get_env_var("AMOSKYS_AGENT_CERT_DIR", "IS_CERT_DIR", config.agent.cert_dir)
```

**Effort**: 6-8 hours (with deprecation warnings)  
**Documentation**: Deprecation guide for users

---

## Phase 1: Core Intelligence Rebuilding (Weeks 3-8)

**Goal**: Implement three-layer analysis foundation + ML pipeline scaffolding

### Task 1.1: Add Syscall Tracing (Linux eBPF)

**Problem**: Can't detect process behavior without syscalls

**Platforms**: Linux only (macOS DTrace is complex; Windows ETW is different)

**Library**: Use `ebpf` or `bcc` (BPF Compiler Collection)

**Implementation Steps**:

1. **Create new agent**: `src/amoskys/agents/syscall_tracer/`

2. **eBPF program** (`syscall_tracer.ebpf`):
```c
// Trace execve, open, connect, ptrace, mmap, mprotect
#include <uapi/linux/ptrace.h>
#include <net/sock.h>

struct syscall_event {
    u32 pid;
    u32 uid;
    u32 syscall_id;  // __NR_execve, __NR_open, etc.
    char comm[16];
    u64 timestamp_ns;
    u64 args[6];  // Up to 6 syscall arguments
    u8 return_val;  // Did it succeed?
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    struct syscall_event *event, _event = {};
    event = &_event;
    
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->syscall_id = args->id;
    
    // Capture syscall arguments
    event->args[0] = args->args[0];
    event->args[1] = args->args[1];
    // ... etc.
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    events.perf_submit(ctx, event, sizeof(*event));
    
    return 0;
}
```

3. **Python wrapper** (`syscall_agent.py`):
```python
import bcc

class SyscallTracerAgent:
    def __init__(self):
        # Compile eBPF program
        self.bpf = bcc.BPF(src_file="syscall_tracer.ebpf")
        
        # Attach to tracepoints
        self.bpf.attach_tracepoint("raw_syscalls:sys_enter", ...)
    
    def read_events(self):
        """Read syscall events from kernel buffer"""
        # Poll from perf buffer
        # Convert to protobuf SyscallEvent message
        # Publish to EventBus
        pass
```

4. **Protobuf schema** (`proto/syscall_telemetry.proto`):
```protobuf
message SyscallEvent {
  uint32 pid = 1;
  uint32 uid = 2;
  string comm = 3;
  uint64 timestamp_ns = 4;
  uint32 syscall_id = 5;  // enum of syscall names
  repeated uint64 args = 6;
  int32 return_val = 7;
}

message SyscallSequence {
  uint32 pid = 1;
  repeated SyscallEvent events = 2;  // Last N syscalls for this process
}
```

**Effort**: 2-3 weeks (learning curve on eBPF)  
**Testing**: Synthetic workloads (fork bombs, file access patterns)  
**Limitations**: 
- Linux only (add to Phase 2 for macOS/Windows)
- Requires kernel 4.4+ 
- No filtering = high volume (~10K syscalls/sec per process)
- Need to implement filtering at kernel level

**Deliverable**: New agent publishing syscalls to EventBus

---

### Task 1.2: Feature Engineering Pipeline

**Problem**: Raw metrics can't go directly to ML models; need normalization, encoding, windowing

**Files to Create**:
- `src/amoskys/feature_engineering/normalizer.py`
- `src/amoskys/feature_engineering/encoder.py`
- `src/amoskys/feature_engineering/windower.py`
- `src/amoskys/feature_engineering/pipeline.py`

**Implementation**:

```python
# normalizer.py
class FeatureNormalizer:
    """Normalize numeric features to [0, 1] range"""
    
    def __init__(self, stats_file: str = None):
        self.stats = {}  # min, max for each feature
        if stats_file:
            self.load_stats(stats_file)
    
    def compute_stats(self, data: Dict[str, List[float]]):
        """Compute min/max for all features"""
        for feat_name, values in data.items():
            self.stats[feat_name] = {
                'min': min(values),
                'max': max(values),
                'range': max(values) - min(values)
            }
    
    def normalize(self, features: Dict[str, float]) -> Dict[str, float]:
        """Normalize a feature dict"""
        normalized = {}
        for feat_name, value in features.items():
            if feat_name not in self.stats:
                continue
            stats = self.stats[feat_name]
            if stats['range'] == 0:
                normalized[feat_name] = 0.0
            else:
                normalized[feat_name] = (value - stats['min']) / stats['range']
        return normalized

# encoder.py
class FeatureEncoder:
    """Encode categorical features to numeric"""
    
    def __init__(self):
        self.vocabularies = {}  # Maps feature name → list of categories
    
    def encode(self, features: Dict[str, Any]) -> Dict[str, float]:
        """One-hot encode categorical features"""
        encoded = {}
        for feat_name, value in features.items():
            if feat_name in self.vocabularies:
                # One-hot encoding
                vocab = self.vocabularies[feat_name]
                for i, cat in enumerate(vocab):
                    encoded[f"{feat_name}_{cat}"] = 1.0 if value == cat else 0.0
            else:
                # Keep numeric features as-is
                encoded[feat_name] = float(value)
        return encoded

# windower.py
class SlidingWindowProcessor:
    """Convert event stream into fixed-size windows"""
    
    def __init__(self, window_size_sec: int = 5, step_size_sec: int = 1):
        self.window_size = window_size_sec
        self.step_size = step_size_sec
        self.events = []  # Sliding buffer of events
        self.last_window_ts = None
    
    def add_event(self, event_ts: float, features: Dict) -> Optional[List[Dict]]:
        """Add event; return completed windows when ready"""
        self.events.append((event_ts, features))
        
        # Keep only recent events (within window)
        now = time.time()
        self.events = [(ts, f) for ts, f in self.events 
                       if now - ts < self.window_size]
        
        if self.last_window_ts is None:
            self.last_window_ts = now - self.step_size
        
        # Check if we have a complete window
        if now - self.last_window_ts >= self.step_size:
            # Aggregate features for this window
            window_features = self._aggregate(self.events)
            self.last_window_ts = now
            return [window_features]
        
        return None
    
    def _aggregate(self, events: List[Tuple]) -> Dict:
        """Aggregate event features into window features"""
        features = {
            'event_count': len(events),
            'min_': {},
            'max_': {},
            'avg_': {},
        }
        # ... aggregate operations (min, max, mean, std, p95, etc.)
        return features

# pipeline.py
class FeatureEngineeringPipeline:
    """End-to-end feature processing"""
    
    def __init__(self, config: FeatureConfig):
        self.normalizer = FeatureNormalizer(config.stats_file)
        self.encoder = FeatureEncoder()
        self.windower = SlidingWindowProcessor(config.window_sec)
    
    def process(self, raw_event: Dict) -> Optional[Dict]:
        """raw_event → [normalized, encoded, windowed] features"""
        
        # Step 1: Encode categoricals
        encoded = self.encoder.encode(raw_event)
        
        # Step 2: Normalize numerics
        normalized = self.normalizer.normalize(encoded)
        
        # Step 3: Window
        windows = self.windower.add_event(time.time(), normalized)
        
        if windows:
            return windows[0]  # Return first complete window
        return None
```

**Effort**: 2-3 weeks  
**Testing**: Unit tests for each component, integration tests with real events  
**Deliverable**: Reusable feature pipeline for all models

---

### Task 1.3: Build Three-Layer Analysis Foundation

**Goal**: Create architecture for geometric, temporal, behavioral analysis (NOT fully implemented yet; just foundation)

**Files to Create**:
- `src/amoskys/analysis/base_analyzer.py` (abstract base class)
- `src/amoskys/analysis/geometric_layer.py` (graph analysis)
- `src/amoskys/analysis/temporal_layer.py` (time-series analysis)
- `src/amoskys/analysis/behavioral_layer.py` (sequence analysis)
- `src/amoskys/analysis/fusion_engine.py` (combine all layers)

**Implementation**:

```python
# base_analyzer.py
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple

class BaseAnalyzer(ABC):
    """Base class for all analysis layers"""
    
    def __init__(self, model_path: str = None):
        self.model = None
        if model_path:
            self.load_model(model_path)
    
    @abstractmethod
    def analyze(self, features: Dict[str, float]) -> Tuple[float, str]:
        """
        Analyze features and return (confidence_score, explanation)
        
        confidence_score: 0.0 (benign) to 1.0 (malicious)
        explanation: Human-readable reason (e.g., "unusual memory access pattern")
        """
        pass
    
    @abstractmethod
    def load_model(self, path: str):
        """Load trained model from disk"""
        pass
    
    @abstractmethod
    def save_model(self, path: str):
        """Save trained model to disk"""
        pass

# geometric_layer.py
class GeometricAnalyzer(BaseAnalyzer):
    """Spatial relationships in process/network/file graphs"""
    
    def __init__(self):
        super().__init__()
        self.process_graph = {}  # {parent_pid: [child_pids]}
        self.network_graph = {}  # {host: {neighbors, centrality}}
    
    def analyze(self, features: Dict[str, float]) -> Tuple[float, str]:
        """
        Detect spatial anomalies:
        - Process isolation violation
        - Network topology anomaly
        - Unusual file access hierarchy
        """
        confidence = 0.0
        reason = "No anomaly detected"
        
        # Check if this process crosses privilege boundary
        # Check if network follows expected topology
        # etc.
        
        return confidence, reason

# temporal_layer.py
class TemporalAnalyzer(BaseAnalyzer):
    """Time-series anomalies"""
    
    def __init__(self, lstm_model_path: str = None):
        super().__init__(lstm_model_path)
        self.history = []  # Time-series of features
    
    def analyze(self, features: Dict[str, float]) -> Tuple[float, str]:
        """
        Detect temporal anomalies:
        - Sudden rate change
        - Deviation from seasonal pattern
        - Correlation break (metrics that normally move together)
        """
        self.history.append((time.time(), features))
        
        # If no LSTM model, use rule-based analysis
        if self.model is None:
            return self._rule_based_analysis(features)
        
        # Otherwise use LSTM prediction
        confidence = self._lstm_analysis(features)
        return confidence, "LSTM-based anomaly"
    
    def _rule_based_analysis(self, features: Dict[str, float]) -> Tuple[float, str]:
        """Threshold-based temporal analysis"""
        # TODO: Implement statistical anomaly detection
        # - Zscore for sudden changes
        # - Isolation Forest for outliers
        pass
    
    def _lstm_analysis(self, features: Dict[str, float]) -> float:
        """LSTM-based time-series prediction"""
        # TODO: Convert history to LSTM input
        # TODO: Get model prediction
        # TODO: Compare prediction to actual
        pass

# behavioral_layer.py
class BehavioralAnalyzer(BaseAnalyzer):
    """Action sequence anomalies"""
    
    def __init__(self):
        super().__init__()
        self.sequence_buffer = {}  # {pid: [syscall_sequence]}
    
    def analyze(self, features: Dict[str, float]) -> Tuple[float, str]:
        """
        Detect behavioral anomalies:
        - Known-bad syscall sequences
        - Exploit patterns (e.g., mmap RWX + execute)
        - Multi-step attack patterns
        """
        # For now, just return 0 (not implemented)
        return 0.0, "Behavioral analysis not yet implemented"

# fusion_engine.py
class AnalysisFusionEngine:
    """Combine predictions from all layers"""
    
    def __init__(self):
        self.geometric = GeometricAnalyzer()
        self.temporal = TemporalAnalyzer()
        self.behavioral = BehavioralAnalyzer()
        
        # Weights for ensemble (learned from validation data)
        self.weights = {
            'geometric': 0.33,
            'temporal': 0.33,
            'behavioral': 0.34,
        }
    
    def analyze(self, features: Dict[str, float]) -> Dict[str, Any]:
        """
        Get predictions from all layers, combine into final score
        """
        results = {
            'geometric': self.geometric.analyze(features),
            'temporal': self.temporal.analyze(features),
            'behavioral': self.behavioral.analyze(features),
        }
        
        # Weighted ensemble
        final_confidence = (
            self.weights['geometric'] * results['geometric'][0] +
            self.weights['temporal'] * results['temporal'][0] +
            self.weights['behavioral'] * results['behavioral'][0]
        )
        
        return {
            'final_confidence': final_confidence,
            'layer_scores': results,
            'should_alert': final_confidence > 0.7,
            'severity': self._confidence_to_severity(final_confidence),
        }
    
    def _confidence_to_severity(self, confidence: float) -> str:
        """Map confidence score to severity"""
        if confidence < 0.3:
            return 'LOW'
        elif confidence < 0.6:
            return 'MEDIUM'
        elif confidence < 0.85:
            return 'HIGH'
        else:
            return 'CRITICAL'
```

**Effort**: 1-2 weeks (scaffolding only; full models come later)  
**Deliverable**: Analysis framework ready for model integration

---

## Phase 2: Model Training & Serving (Weeks 9-14)

**Goal**: Build infrastructure for training, versioning, and serving ML models

### Task 2.1: Model Training Pipeline

**Problem**: No way to train models; can't improve detections

**Files to Create**:
- `training/prepare_dataset.py`
- `training/train_models.py`
- `training/evaluate_models.py`
- `training/export_models.py`

**Dataset**: Use CSECICIDS 2018 (publicly available, 80GB network traffic)

**Models to Train**:
1. **XGBoost**: Fast, interpretable, good for tabular features
2. **LSTM**: Sequential features (syscall sequences, network flows)
3. **MLP**: Dense features (aggregated metrics)

**Training Code Skeleton**:
```python
# prepare_dataset.py
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

def prepare_csecicids_dataset():
    """Load CSECICIDS 2018, preprocess, create train/test split"""
    
    # Load data
    raw_data = load_csecicids()  # Expect CSV with 80+ features
    
    # Feature engineering
    features = engineer_features(raw_data)
    
    # Normalize
    scaler = StandardScaler()
    features = scaler.fit_transform(features)
    
    # Labels (CSECICIDS has benign/attack labels)
    labels = raw_data['Label']
    labels = (labels != 'BENIGN').astype(int)  # Binary classification
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        features, labels, test_size=0.2, random_state=42
    )
    
    return X_train, X_test, y_train, y_test, scaler

# train_models.py
from xgboost import XGBClassifier
from sklearn.metrics import roc_auc_score, precision_score, recall_score

def train_xgboost(X_train, y_train):
    """Train XGBoost model"""
    model = XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        random_state=42,
        verbosity=1
    )
    model.fit(X_train, y_train, eval_set=[(X_train, y_train)], verbose=False)
    return model

def train_lstm(X_train, y_train):
    """Train LSTM for sequences"""
    # Convert to sequences (rolling windows)
    X_seq = create_sequences(X_train, seq_length=30)
    
    # Build model
    model = Sequential([
        LSTM(64, input_shape=(30, X_train.shape[1])),
        Dropout(0.2),
        Dense(32, activation='relu'),
        Dropout(0.2),
        Dense(1, activation='sigmoid')
    ])
    model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['auc'])
    model.fit(X_seq, y_train[:len(X_seq)], epochs=10, batch_size=32)
    return model

def evaluate_all(models, X_test, y_test):
    """Evaluate all models"""
    results = {}
    for name, model in models.items():
        y_pred = model.predict(X_test)
        results[name] = {
            'auc': roc_auc_score(y_test, y_pred),
            'precision': precision_score(y_test, (y_pred > 0.5).astype(int)),
            'recall': recall_score(y_test, (y_pred > 0.5).astype(int)),
        }
    return results
```

**Effort**: 2-3 weeks (including data prep, testing)  
**Deliverable**: Trained models saved as ONNX format

---

### Task 2.2: Model Serving Infrastructure

**Problem**: Models exist but can't run for real-time inference

**Files to Create**:
- `src/amoskys/model_serving/inference_server.py`
- `src/amoskys/model_serving/model_cache.py`
- `src/amoskys/model_serving/onnx_runtime.py`

**Implementation**:

```python
# onnx_runtime.py
import onnxruntime as ort

class ONNXModel:
    """Wrapper for ONNX model inference"""
    
    def __init__(self, model_path: str):
        self.session = ort.InferenceSession(model_path)
        self.input_name = self.session.get_inputs()[0].name
        self.output_name = self.session.get_outputs()[0].name
    
    def predict(self, features: np.ndarray) -> np.ndarray:
        """Run inference on batch of features"""
        output = self.session.run([self.output_name], {self.input_name: features})
        return output[0]

# model_cache.py
class ModelCache:
    """Cache models in memory; lazy load on first use"""
    
    def __init__(self, model_dir: str):
        self.model_dir = model_dir
        self.cache = {}  # {model_name: ONNXModel}
    
    def get(self, model_name: str) -> ONNXModel:
        """Get model from cache; load if not present"""
        if model_name not in self.cache:
            path = os.path.join(self.model_dir, f"{model_name}.onnx")
            self.cache[model_name] = ONNXModel(path)
        return self.cache[model_name]

# inference_server.py
from flask import Flask, request, jsonify

app = Flask(__name__)
model_cache = ModelCache("models/")

@app.route("/v1/predict", methods=["POST"])
def predict():
    """Real-time inference endpoint"""
    data = request.json
    
    # Extract features
    features = np.array([data['features']], dtype=np.float32)
    
    # Get predictions from all models
    xgb_pred = model_cache.get("xgboost").predict(features)[0][1]
    lstm_pred = model_cache.get("lstm").predict(features)[0][0]
    mlp_pred = model_cache.get("mlp").predict(features)[0][0]
    
    # Ensemble
    final_pred = (xgb_pred + lstm_pred + mlp_pred) / 3.0
    
    return jsonify({
        'confidence': float(final_pred),
        'models': {
            'xgboost': float(xgb_pred),
            'lstm': float(lstm_pred),
            'mlp': float(mlp_pred),
        },
        'should_alert': final_pred > 0.7,
    })

@app.route("/v1/models", methods=["GET"])
def list_models():
    """List available models"""
    return jsonify({
        'models': list(model_cache.cache.keys()),
        'cache_size': len(model_cache.cache),
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
```

**Deployment**:
- **Edge (on-device)**: Use TensorFlow Lite or ONNX Runtime Lite (low overhead)
- **Cloud (EventBus)**: Use full ONNX Runtime or TensorFlow Serving on GPU

**Effort**: 1-2 weeks  
**Testing**: Load test to ensure <100ms inference latency

---

## Phase 3: Distribution & Scale (Weeks 15-20)

**Goal**: Multi-agent coordination, service discovery, distributed state

### Task 3.1: Agent Discovery

**Problem**: Agents hardcode EventBus address; no way to discover agents

**Implementation Options**:
1. **Consul** (recommended): Service mesh, health checks, KV store
2. **etcd**: Distributed KV store
3. **DNS SRV**: DNS service discovery

**Using Consul**:

```python
# src/amoskys/discovery/consul_registry.py
from consul import Consul

class ConsulRegistry:
    def __init__(self, consul_host="localhost", consul_port=8500):
        self.client = Consul(host=consul_host, port=consul_port)
    
    def register_agent(self, agent_name: str, agent_port: int):
        """Register this agent with Consul"""
        self.client.agent.service.register(
            name="amoskys-agent",
            service_id=agent_name,
            address="localhost",
            port=agent_port,
            check=Consul.Check.http(f"http://localhost:{agent_port}/healthz", interval="5s")
        )
    
    def discover_agents(self) -> List[Dict]:
        """Get list of all active agents"""
        _, services = self.client.health.service("amoskys-agent", passing=True)
        return [
            {
                'name': svc['Service']['ID'],
                'address': svc['Service']['Address'],
                'port': svc['Service']['Port'],
            }
            for svc in services
        ]
    
    def get_eventbus_address(self) -> str:
        """Discover EventBus address"""
        _, services = self.client.health.service("amoskys-eventbus", passing=True)
        if services:
            svc = services[0]['Service']
            return f"{svc['Address']}:{svc['Port']}"
        raise RuntimeError("No EventBus found in Consul")

# In agent startup:
if __name__ == "__main__":
    registry = ConsulRegistry()
    registry.register_agent("agent-1", 8081)
    
    eventbus_addr = registry.get_eventbus_address()
    # Now connect to eventbus_addr instead of hardcoded localhost:50051
```

**Effort**: 1 week  
**Deployment**: Consul cluster (HA mode with 3-5 nodes)

---

### Task 3.2: Inter-Agent Communication

**Problem**: Agents can't talk to each other

**Implementation**: Use gRPC for agent-to-agent communication

```proto
// proto/agent_communication.proto
service AgentMesh {
  rpc ShareThreat(ThreatAlert) returns (Ack);
  rpc SyncSignatures(SignatureBatch) returns (Ack);
  rpc RequestCoordination(CoordinationRequest) returns (CoordinationResponse);
}

message ThreatAlert {
  string source_agent_id = 1;
  string threat_id = 2;
  float confidence = 3;
  string description = 4;
  int64 timestamp_ns = 5;
}

message SignatureBatch {
  repeated string signatures = 1;  // Threat signatures
  int64 version = 2;
}

message Ack {
  bool success = 1;
  string reason = 2;
}
```

**Effort**: 2 weeks

---

## Phase 4: Production Hardening (Weeks 21-26)

**Goal**: Audit logging, alerting, incident response, monitoring

### Task 4.1: Audit Logging

**Problem**: No immutable audit trail

**Implementation**: Use SQLite with integrity constraints or dedicated audit service (ELK Stack)

```python
# src/amoskys/auditing/audit_logger.py
import sqlite3
import hmac
import hashlib

class AuditLogger:
    """Immutable audit log with integrity checking"""
    
    def __init__(self, db_path: str, audit_key: str):
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.audit_key = audit_key
        self._init_db()
    
    def _init_db(self):
        """Create audit log table"""
        self.db.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            user_id TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT,
            result TEXT,
            details TEXT,
            hmac TEXT NOT NULL
        )
        """)
        self.db.commit()
    
    def log(self, user_id: str, action: str, resource: str, result: str, details: str):
        """Log an action with HMAC"""
        timestamp = datetime.utcnow().isoformat()
        
        # Create HMAC over all fields
        msg = f"{timestamp}|{user_id}|{action}|{resource}|{result}|{details}".encode()
        record_hmac = hmac.new(self.audit_key.encode(), msg, hashlib.sha256).hexdigest()
        
        self.db.execute("""
        INSERT INTO audit_log (timestamp, user_id, action, resource, result, details, hmac)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (timestamp, user_id, action, resource, result, details, record_hmac))
        
        self.db.commit()
    
    def verify_integrity(self) -> bool:
        """Verify no entries have been tampered with"""
        rows = self.db.execute("SELECT * FROM audit_log").fetchall()
        for row in rows:
            timestamp, user_id, action, resource, result, details, stored_hmac = row[1:]
            msg = f"{timestamp}|{user_id}|{action}|{resource}|{result}|{details}".encode()
            expected_hmac = hmac.new(self.audit_key.encode(), msg, hashlib.sha256).hexdigest()
            if expected_hmac != stored_hmac:
                return False
        return True
```

**Effort**: 1-2 weeks

---

### Task 4.2: Alerting System

**Problem**: No way to alert on detected threats

**Implementation**: Rule engine + routing

```python
# src/amoskys/alerting/alert_engine.py
class AlertRule:
    def __init__(self, name: str, condition: str, actions: List[str]):
        self.name = name
        self.condition = condition  # e.g., "confidence > 0.8 AND severity == HIGH"
        self.actions = actions  # e.g., ["slack", "email", "pagerduty"]
    
    def matches(self, alert: Dict) -> bool:
        """Check if alert matches this rule"""
        # Evaluate condition
        return eval(self.condition, {"__builtins__": {}}, alert)

class AlertRouter:
    def __init__(self):
        self.rules = []
        self.handlers = {
            'slack': SlackHandler(),
            'email': EmailHandler(),
            'pagerduty': PagerDutyHandler(),
        }
    
    def add_rule(self, rule: AlertRule):
        self.rules.append(rule)
    
    def route_alert(self, alert: Dict):
        """Find matching rules and send to handlers"""
        for rule in self.rules:
            if rule.matches(alert):
                for action in rule.actions:
                    self.handlers[action].send(alert)
```

**Effort**: 2 weeks (with handler integrations)

---

## Implementation Timeline & Gantt Chart

```
Week  1 | [Metrics Fix] [Env Validation] [Prefix Rename]
Week  2 | ←--- Stabilization --→
Week  3 | [Syscall Tracing Begin]
Week  4 | ← Syscall Tracing →
Week  5 | [Features Begin] [Syscall End]
Week  6 | ← Feature Engineering →
Week  7 | [Analysis Foundation Begin] [Features End]
Week  8 | ← Analysis Foundation →
Week  9 | [Training Pipeline Begin] [Analysis End]
Week 10 | ← Training Pipeline →
Week 11 | [Model Serving Begin] [Training End]
Week 12 | ← Model Serving →
Week 13 | [Discovery Begin] [Serving End]
Week 14 | ← Discovery →
Week 15 | [Inter-Agent Comm Begin]
Week 16 | ← Inter-Agent Comm →
Week 17 | [Rate Limiting Begin]
Week 18 | ← Rate Limiting →
Week 19 | [Audit Logging Begin]
Week 20 | ← Audit Logging →
Week 21 | [Alerting Begin]
Week 22 | ← Alerting →
Week 23 | [Load Testing & Hardening]
Week 24 | ← Testing →
Week 25 | [Documentation & Release]
Week 26 | ← GA Release →
```

---

## Success Criteria by Phase

### Phase 0 (Week 2)
- ✅ All 34 tests passing
- ✅ Metrics no longer collide
- ✅ Clear error messages on bad config

### Phase 1 (Week 8)
- ✅ Syscalls tracing running on Linux
- ✅ 500+ features per event
- ✅ Three-layer analysis framework in place

### Phase 2 (Week 14)
- ✅ Models trained to 85%+ accuracy
- ✅ Inference <100ms p95
- ✅ Model versioning working

### Phase 3 (Week 20)
- ✅ Agent discovery working
- ✅ 100+ agents coordinating
- ✅ Distributed state synchronized

### Phase 4 (Week 26)
- ✅ Audit logging immutable
- ✅ Alerts routing correctly
- ✅ Production monitoring dashboards
- ✅ GA release, documentation complete

---

## Risk Mitigation

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| eBPF kernel version incompatibility | Medium | High | Start with Ubuntu 20.04+ target; fallback to auditd |
| Model performance worse than expected | Medium | High | Use ensemble of simple models; add human feedback loop |
| Consul cluster stability | Low | High | Use managed Consul (AWS, Hashicorp Cloud) |
| Metrics naming conflicts again | Low | High | Add automated tests for metric registration |

---

## Team Allocation

```
Role                    FTE  Weeks  Tasks
────────────────────────────────────────────────────────────
Tech Lead               1.0  26     Architecture, coordination, code review
Platform Engineer       1.0  26     Agent discovery, distribution, scaling
Data/Infra Engineer (×2) 2.0 26     Syscalls, features, training pipeline
ML Engineer             1.0  26     Models, inference, evaluation
Security Engineer       0.5  20     Audit logging, encryption, compliance
QA/Testing              1.0  26     Load tests, integration tests, hardening
────────────────────────────────────────────────────────────
TOTAL                   6.5 FTE    ~157 person-weeks (26 weeks calendar)
```

---

## Budget Estimate

| Component | Cost | Notes |
|-----------|------|-------|
| Engineering (6.5 FTE × $150K) | $975K | Senior full-stack engineers |
| Infrastructure (cloud, Consul, ML) | $200K | AWS, Hashicorp Cloud, GPU for training |
| Tools & Services (MLflow, Grafana, Slack API) | $50K | Open source mostly, some SaaS |
| Testing & QA tools | $25K | Load testing, security scanning |
| **TOTAL** | **$1.25M** | 6 months to production GA |

---

## Conclusion

This roadmap provides a clear, implementable path from current state (research) to production (enterprise-grade security platform). The phased approach allows for early validation and course correction. Key success factors:

1. **Fix metrics collision ASAP** (blocking all tests)
2. **Syscall tracing** (unlocks behavioral analysis)
3. **Feature engineering** (enables ML models)
4. **Model serving** (makes predictions actionable)
5. **Distribution** (scales beyond single host)

Following this roadmap, AMOSKYS can achieve GA readiness in 6 months with 6-7 engineers.
