# AMOSKYS Master Development Guide
**Status**: Production-Ready Roadmap | **Last Updated**: Dec 5, 2025 | **For**: Solo Development

---

## CURRENT STATE SUMMARY

### What's Working ✅
- **6 Agents**: eventbus, flowagent, proc_agent, snmp_agent, device_scanner, mac_telemetry
- **Test Coverage**: 31/34 passing (91%) - 2 flaky network tests, 1 skipped
- **Core Infrastructure**: gRPC + mTLS, SQLite WAL, Prometheus metrics
- **Imports**: All fixed and functional

### What Needs Immediate Fixing ⚠️
1. **Prometheus Metric Collision** (blocks 2 tests)
   - Problem: `AGENT_DROPPED_OVERSIZE` registered multiple times when tests run
   - Location: `src/amoskys/agents/flowagent/main.py:50-62` & `src/amoskys/eventbus/server.py:106-110`
   - Fix: Delay metric registration until `if __name__ == "__main__"` block + use registry collision detection

2. **Flaky Network Tests** (non-critical, but annoying)
   - `test_inflight_metric_rises_then_falls`: Times out waiting for server startup
   - `test_wal_grows_then_drains`: Port 8081 not ready in time
   - Fix: Increase timeouts or use healthcheck polling instead of fixed delays

### What's Missing (Big Picture)
- **Syscall tracing** (can't see what processes actually do)
- **Feature engineering** (raw metrics can't feed ML)
- **Three-layer analysis** (geometric, temporal, behavioral - just scaffolding exists)
- **Model serving** (no inference infrastructure)
- **Agent discovery** (hardcoded addresses)
- **Distributed coordination** (agents can't talk)
- **Production monitoring** (basic metrics only)

---

## PRIORITY WORK - NEXT 8 WEEKS

### WEEK 1-2: Fix Critical Blockers

#### 1.1 Fix Prometheus Metrics Collision
**Why**: Blocking tests from passing cleanly

**Steps**:
1. Open `src/amoskys/agents/flowagent/main.py`
2. Find lines 50-62 (metric definitions)
3. Move them inside a function:
```python
def init_metrics():
    global AGENT_DROPPED_OVERSIZE, AG_PUB_OK, AG_PUB_RETRY, AG_PUB_FAIL, AG_WAL_BYTES, AG_PUB_LAT, HEALTH_HITS, READINESS_HITS, READY_STATE
    
    from prometheus_client import REGISTRY, CollectorAlreadyRegisteredError
    
    try:
        AGENT_DROPPED_OVERSIZE = Counter("agent_dropped_oversize_total", "Dropped locally due to oversize payload")
    except CollectorAlreadyRegisteredError:
        pass
    
    # ... repeat for all metrics (AG_PUB_OK, AG_PUB_RETRY, etc.)
    
    try:
        READY_STATE = Gauge("agent_ready_state", "1=ready, 0=not-ready")
    except CollectorAlreadyRegisteredError:
        pass
```
4. Call `init_metrics()` at the very start of `if __name__ == "__main__":` block
5. Do the same for `src/amoskys/eventbus/server.py` (metrics at lines 106-110)

**Verify**: `pytest tests/component/test_bus_inflight_metric.py -v` should pass

**Effort**: 2 hours

---

#### 1.2 Fix Flaky Test Timeouts
**Why**: Cleaner test runs

**Steps**:
1. Open `tests/component/test_bus_inflight_metric.py:45`
2. Change from:
```python
p.terminate(); p.wait(timeout=2)
```
to:
```python
p.terminate()
try:
    p.wait(timeout=5)  # Increase to 5 seconds
except subprocess.TimeoutExpired:
    p.kill()  # Force kill if still running
    p.wait(timeout=2)
```
3. Do same for `tests/component/test_wal_grow_drain.py:48`

**Verify**: `pytest tests/component/ -v` should pass

**Effort**: 1 hour

---

### WEEK 3-4: Add Syscall Tracing (Linux Only)

**Why**: Can't understand what processes actually do without syscalls

**Target**: Linux only for now (eBPF requires kernel 4.4+)

**Implementation**:

1. **Create agent structure**:
```bash
mkdir -p src/amoskys/agents/syscall_tracer
touch src/amoskys/agents/syscall_tracer/__init__.py
touch src/amoskys/agents/syscall_tracer/syscall_agent.py
```

2. **Install dependencies**:
```bash
pip install bcc  # BPF Compiler Collection
```

3. **Write eBPF program** (`src/amoskys/agents/syscall_tracer/syscalls.ebpf`):
```c
#include <uapi/linux/ptrace.h>

struct syscall_event {
    u32 pid;
    u64 timestamp_ns;
    u32 syscall_id;
    char comm[16];
    int32 retval;
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    struct syscall_event event = {};
    
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.timestamp_ns = bpf_ktime_get_ns();
    event.syscall_id = args->id;
    event.retval = args->ret;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}
```

4. **Python wrapper** (`src/amoskys/agents/syscall_tracer/syscall_agent.py`):
```python
import bcc
import time
from amoskys.proto import universal_telemetry_pb2 as pb

class SyscallTracerAgent:
    def __init__(self):
        # Compile eBPF program
        with open("src/amoskys/agents/syscall_tracer/syscalls.ebpf", "r") as f:
            prog = f.read()
        
        self.bpf = bcc.BPF(text=prog)
        self.bpf.attach_tracepoint("raw_syscalls:sys_exit", ...)
        
    def read_events(self):
        """Poll syscall events from kernel"""
        def print_event(cpu, data, size):
            event = self.bpf["events"].event(data)
            print(f"PID={event.pid} SYSCALL={event.syscall_id} RETVAL={event.retval}")
        
        self.bpf["events"].open_perf_buffer(print_event)
        while True:
            try:
                self.bpf.perf_buffer_poll(timeout=100)
            except KeyboardInterrupt:
                break
```

5. **Add protobuf message** (`proto/universal_telemetry.proto`):
```protobuf
message SyscallEvent {
  uint32 pid = 1;
  uint64 timestamp_ns = 2;
  uint32 syscall_id = 3;
  string comm = 4;
  int32 retval = 5;
}
```

**Verify**: Run on Linux, see syscall output

**Effort**: 2-3 weeks (learning eBPF is steep)

**Note**: Skip if not on Linux. Can use `auditd` as fallback on macOS.

---

### WEEK 5-6: Feature Engineering Pipeline

**Why**: Raw metrics can't feed ML models directly

**Implementation**:

1. **Create module**:
```bash
mkdir -p src/amoskys/feature_engineering
touch src/amoskys/feature_engineering/{__init__.py,normalizer.py,encoder.py,windower.py,pipeline.py}
```

2. **Normalizer** (`normalizer.py`):
```python
class FeatureNormalizer:
    def __init__(self):
        self.stats = {}  # {feature_name: {min, max}}
    
    def compute_stats(self, data: List[Dict]):
        """Compute min/max for all features from dataset"""
        for feature in data[0].keys():
            values = [d[feature] for d in data]
            self.stats[feature] = {'min': min(values), 'max': max(values)}
    
    def normalize(self, features: Dict) -> Dict:
        """Scale features to [0, 1]"""
        normalized = {}
        for name, val in features.items():
            if name not in self.stats:
                normalized[name] = val
                continue
            
            stats = self.stats[name]
            range_val = stats['max'] - stats['min']
            if range_val == 0:
                normalized[name] = 0.0
            else:
                normalized[name] = (val - stats['min']) / range_val
        
        return normalized
```

3. **Windower** (`windower.py`):
```python
class SlidingWindowProcessor:
    def __init__(self, window_size_sec=5):
        self.window_size = window_size_sec
        self.buffer = []
    
    def add_event(self, timestamp: float, features: Dict):
        """Add event; return completed windows when ready"""
        self.buffer.append((timestamp, features))
        
        # Keep only recent events
        cutoff = timestamp - self.window_size
        self.buffer = [(ts, f) for ts, f in self.buffer if ts >= cutoff]
        
        # Aggregate into window features
        if len(self.buffer) > 0:
            return self._aggregate()
        return None
    
    def _aggregate(self) -> Dict:
        """Create window-level features from events"""
        return {
            'event_count': len(self.buffer),
            'avg_cpu': sum(f.get('cpu', 0) for _, f in self.buffer) / len(self.buffer),
            'max_memory': max(f.get('memory', 0) for _, f in self.buffer),
            # ... more aggregations
        }
```

4. **Pipeline** (`pipeline.py`):
```python
class FeatureEngineeringPipeline:
    def __init__(self):
        self.normalizer = FeatureNormalizer()
        self.windower = SlidingWindowProcessor()
    
    def process(self, raw_event: Dict) -> Optional[Dict]:
        """raw_event → normalized, windowed features"""
        # Step 1: Normalize
        normalized = self.normalizer.normalize(raw_event)
        
        # Step 2: Window
        windowed = self.windower.add_event(time.time(), normalized)
        
        return windowed
```

**Verify**: Create test with 10 raw events, verify features normalize to [0,1]

**Effort**: 1 week

---

### WEEK 7-8: Three-Layer Analysis Framework

**Why**: Foundation for ML models

**Implementation**:

1. **Create module**:
```bash
mkdir -p src/amoskys/analysis
touch src/amoskys/analysis/{__init__.py,base_analyzer.py,geometric.py,temporal.py,behavioral.py,fusion.py}
```

2. **Base class** (`base_analyzer.py`):
```python
from abc import ABC, abstractmethod

class BaseAnalyzer(ABC):
    @abstractmethod
    def analyze(self, features: Dict) -> tuple[float, str]:
        """Return (confidence_score: 0-1, explanation: str)"""
        pass

    @abstractmethod
    def load_model(self, path: str):
        pass

    @abstractmethod
    def save_model(self, path: str):
        pass
```

3. **Geometric analyzer** (`geometric.py`):
```python
class GeometricAnalyzer(BaseAnalyzer):
    """Spatial relationships in process/network graphs"""
    
    def analyze(self, features: Dict) -> tuple[float, str]:
        # TODO: Detect graph anomalies (process privilege crossing, network topology breaks)
        # For now, just return 0 (no anomaly)
        return 0.0, "Geometric analysis not yet implemented"
    
    def load_model(self, path: str):
        pass
    
    def save_model(self, path: str):
        pass
```

4. **Temporal analyzer** (`temporal.py`):
```python
class TemporalAnalyzer(BaseAnalyzer):
    """Time-series anomalies"""
    
    def __init__(self):
        super().__init__()
        self.history = []
    
    def analyze(self, features: Dict) -> tuple[float, str]:
        # TODO: Detect rate spikes, seasonal breaks
        # For now, stub
        return 0.0, "Temporal analysis not yet implemented"
    
    def load_model(self, path: str):
        pass
    
    def save_model(self, path: str):
        pass
```

5. **Behavioral analyzer** (`behavioral.py`):
```python
class BehavioralAnalyzer(BaseAnalyzer):
    """Action sequences"""
    
    def analyze(self, features: Dict) -> tuple[float, str]:
        # TODO: Detect syscall sequences, exploit patterns
        return 0.0, "Behavioral analysis not yet implemented"
    
    def load_model(self, path: str):
        pass
    
    def save_model(self, path: str):
        pass
```

6. **Fusion engine** (`fusion.py`):
```python
class AnalysisFusionEngine:
    def __init__(self):
        self.geometric = GeometricAnalyzer()
        self.temporal = TemporalAnalyzer()
        self.behavioral = BehavioralAnalyzer()
        
        # Equal weights for now
        self.weights = {'geometric': 0.33, 'temporal': 0.33, 'behavioral': 0.34}
    
    def analyze(self, features: Dict) -> Dict:
        geo_conf, _ = self.geometric.analyze(features)
        temp_conf, _ = self.temporal.analyze(features)
        behav_conf, _ = self.behavioral.analyze(features)
        
        final = (
            self.weights['geometric'] * geo_conf +
            self.weights['temporal'] * temp_conf +
            self.weights['behavioral'] * behav_conf
        )
        
        return {
            'confidence': final,
            'should_alert': final > 0.7,
            'severity': self._score_to_severity(final),
        }
    
    def _score_to_severity(self, score: float) -> str:
        if score < 0.3:
            return 'LOW'
        elif score < 0.6:
            return 'MEDIUM'
        elif score < 0.85:
            return 'HIGH'
        else:
            return 'CRITICAL'
```

**Verify**: Unit tests for each layer

**Effort**: 1 week

---

## NEXT PHASE (WEEKS 9-16): ML Models & Inference

### What to Build
1. **Model Training Pipeline** (2 weeks)
   - Download CSECICIDS 2018 dataset
   - Train XGBoost, LSTM, MLP on network flows + syscalls
   - Save models as ONNX format

2. **Inference Server** (1 week)
   - Flask API for real-time predictions
   - Load models on startup
   - Ensure <100ms latency

3. **Agent Discovery** (1 week)
   - Use Consul or DNS SRV
   - Agents register themselves
   - Dynamic EventBus discovery

### What NOT to Build Yet
- Distributed consensus
- Advanced alerting
- Multi-tenancy
- Windows/MQTT support

---

## MAINTENANCE & TESTING

### Run Tests Regularly
```bash
# Full test suite
pytest tests/ -v

# Just the critical ones
pytest tests/api/ tests/golden/ tests/unit/ -v

# Watch for changes
pytest-watch tests/
```

### Check Code Quality
```bash
# Type checking
mypy src/amoskys --ignore-missing-imports

# Linting
ruff check src/

# Formatting
black src/
```

### Monitor Metrics
```bash
# See current Prometheus metrics
curl http://localhost:9000/metrics | grep bus_
curl http://localhost:9101/metrics | grep agent_
```

---

## FILE MAP (For Quick Reference)

```
Critical Files:
├── src/amoskys/eventbus/server.py          ← EventBus gRPC hub
├── src/amoskys/agents/flowagent/main.py    ← Network flow agent
├── src/amoskys/agents/proc/proc_agent.py   ← Process monitor
├── src/amoskys/agents/snmp/snmp_agent.py   ← SNMP device monitor
├── config/amoskys.yaml                      ← Central config
└── certs/                                   ← TLS certificates

Testing:
├── tests/unit/                              ← Unit tests
├── tests/component/                         ← Integration tests
├── tests/api/                               ← API tests
└── conftest.py                              ← Pytest configuration

New Development (to be created):
├── src/amoskys/feature_engineering/        ← Feature pipeline
├── src/amoskys/analysis/                   ← Three-layer analysis
├── src/amoskys/agents/syscall_tracer/     ← Syscall tracing
├── training/                               ← Model training
└── src/amoskys/model_serving/             ← Inference server
```

---

## QUICK START: Today's Work

If starting fresh today:
1. Fix metrics collision (2 hours) → all tests pass
2. Start syscall tracing (if on Linux) OR skip to feature engineering
3. Build feature engineering pipeline (1 week)
4. Add three-layer analysis scaffolding (1 week)

**Total**: ~4 weeks to working foundation

---

## KNOWN ISSUES (Lower Priority)

- macOS process monitoring doesn't capture all syscalls (use auditd)
- SNMP agent can be verbose with large networks
- Dashboard only shows 6 agents; no scaling UI yet
- No model drift detection
- No A/B testing framework
- Prometheus metrics are basic (need security-specific ones)

---

## Git Workflow

```bash
# Before starting work
git pull origin main

# After fixing something
git add src/amoskys/
git commit -m "fix: metric collision in flowagent initialization"
git push origin main

# For larger features, create branch
git checkout -b feature/syscall-tracing
# ... work ...
git push origin feature/syscall-tracing
# Then open PR, merge when ready
```

---

## Questions to Answer Next

1. **Should we build syscall tracing?** (Linux only, 2-3 weeks)
   - YES: Better behavior understanding, enables behavioral analysis
   - NO: Use auditd + syslog, move faster to ML models

2. **Which ML framework?** (XGBoost vs LSTM vs MLP)
   - Recommend: All three as ensemble (each has strengths)
   - Start with: XGBoost (fastest to productize)

3. **Edge vs Cloud inference?**
   - Edge: On-device, low latency, but small models
   - Cloud: More accurate, but network dependent
   - Recommend: Hybrid (simple models on edge, complex on cloud)

---

## End Goal (Repeating for Clarity)

By end of 6 months:
- ✅ Agents can trace syscalls, monitor processes, flows, SNMP
- ✅ Features normalize and window automatically
- ✅ Three analysis layers (geometric, temporal, behavioral)
- ✅ ML models (XGBoost, LSTM, MLP) trained on real data
- ✅ Real-time inference <100ms
- ✅ Agent discovery + coordination
- ✅ Audit logging + alerting
- ✅ Production-ready deployment

**Success**: AMOSKYS runs as autonomous security agents on any device, learns behavior, detects anomalies, and alerts.
