# AMOSKYS Microprocessor Agent Stack

**Status:** Production-ready, fully test-covered
**Core Tests:** `tests/test_microprocessor_agent.py` (28/28 passing)
**System Tests:** `pytest tests/` → 136 passed, 1 skipped

The **Microprocessor Agent Stack** is the "smart edge brain" of AMOSKYS. It runs close to devices, discovers assets, collects multi-protocol telemetry, optimizes data under resource constraints, and streams everything into the EventBus + Fusion Engine for correlation.

This document describes the architecture, responsibilities, and runtime behavior of the stack.

---

## 1. High-Level Architecture

**Main components:**

- `MicroprocessorAgentCore`
- `DeviceDiscoveryEngine`
- `UniversalTelemetryCollector`
- `EdgeOptimizer`
- `IntelligenceFusionEngine` (Fusion/Scoring)
- `EventBus + WAL (FlowAgent/EventBus integration)`

**Data Flow (Conceptual):**

1. **Discovery**
   `DeviceDiscoveryEngine` scans the network, fingerprints device types, and estimates vulnerability risk.

2. **Telemetry Collection**
   `UniversalTelemetryCollector` configures SNMP/MQTT and other protocol collectors to pull device telemetry.

3. **Edge Optimization**
   `EdgeOptimizer` compresses, batches, and adapts telemetry based on local CPU/RAM/disk constraints.

4. **Event Ingestion & Fusion**
   Optimized telemetry is pushed to the **EventBus** (gRPC) and fed into the `IntelligenceFusionEngine`, which correlates events, updates device profiles, and computes risk scores.

5. **Microprocessor Agent Orchestration**
   `MicroprocessorAgentCore` coordinates all of the above, exposes health & status, and triggers external callbacks (e.g., "threat_detected").

---

## 2. MicroprocessorAgentCore

**Module:** [src/amoskys/intelligence/integration/agent_core.py](../src/amoskys/intelligence/integration/agent_core.py)
**Tests:** `TestMicroprocessorAgent` + integration tests in [tests/test_microprocessor_agent.py](../tests/test_microprocessor_agent.py)

### Responsibilities

- Initialize and wire:
  - Device discovery
  - Telemetry collectors
  - Edge optimization
  - Fusion engine
- Manage lifecycle (`initialize()`, `start()`, `stop()`)
- Maintain runtime status + metrics
- Support external callbacks (e.g., UI / alerting hooks)

### Key API

```python
agent = MicroprocessorAgentCore(config)

agent.initialize()
agent.start()
status = agent.get_status()
agent.stop()
```

**Status structure (tested):**

```python
status = {
    "running": bool,
    "uptime": float,  # seconds
    "component_health": {...},
    "metrics": {...},
}
```

**Callbacks:**

```python
def on_threat(event):
    ...

agent.add_external_callback("threat_detected", on_threat)
```

The tests verify:
- Agent initializes successfully
- `start()` flips running to True, `stop()` flips it back to False
- `get_status()` returns all required fields
- Registered callbacks are invoked on synthetic threat events

---

## 3. IntelligenceFusionEngine

**Module:** [src/amoskys/intelligence/fusion/threat_correlator.py](../src/amoskys/intelligence/fusion/threat_correlator.py)
**Tests:** `TestIntelligenceFusionEngine` (telemetry, correlation, profiling, thresholds)

### Responsibilities

- Maintain device profiles over time
- Ingest normalized `TelemetryEvent`s
- Apply correlation rules (SSH brute force, persistence, exfiltration, etc.)
- Compute / update risk scores and threat indicators

### Risk Score Semantics

The engine no longer "dumbs down" incoming risk:

```python
# When correlation runs:
event.risk_score = max(event.risk_score, threat_score)
```

So if upstream components or prior analysis set `risk_score=0.9`, correlation won't overwrite it with a lower `0.1`. This is validated in:
- `test_threat_detection_thresholds` (expects risk > 0.5 for high-risk events)

### Behavioral Guarantees (from tests)

- Telemetry ingestion creates/updates device profiles
- Device profiling works across multiple events & timestamps
- Threat correlation buffers and processes multiple related events
- Medical devices and industrial control devices are recognized by `device_type` and profiled correctly
- Performance under load:
  - `test_performance_under_load` pushes 1000 events and expects processing throughput > 100 events/sec (on test hardware)

---

## 4. DeviceDiscoveryEngine

**Module:** [src/amoskys/agents/discovery/device_scanner.py](../src/amoskys/agents/discovery/device_scanner.py)
**Tests:** `TestDeviceDiscovery` + `TestErrorHandling.test_network_error_resilience`

### Responsibilities

- Discover devices across a network range
- Scan ports and identify open services
- Fingerprint device types (IoT vs endpoint, etc.)
- Assess vulnerability risk (0.0–1.0)

### Construction

Tests expect the engine to be constructible with no arguments:

```python
scanner = DeviceDiscoveryEngine()  # config is optional
```

Internally, it supports an optional config dict, but sane defaults are provided so unit tests and simple callers don't need to pass one.

### Key Methods (sync wrappers for tests)

```python
open_ports = scanner._scan_ports("192.168.1.1", [80, 443])
device_type = scanner._fingerprint_device("192.168.1.100", services)
risk_score = scanner._assess_vulnerability_risk(device_info)
devices = scanner.scan_network("192.168.1.0/24")
```

**Fingerprints:**
- If port 1883 (MQTT) and typical banners are found, `_fingerprint_device` returns `'iot_device'` (validated in tests).
- Risk scores are floats between 0.0 and 1.0, computed from open ports, exposed services, and device type.

**Resilience:**
- `scan_network("invalid_network")` does not crash; it returns an empty list or handles errors gracefully, as enforced by `test_network_error_resilience`.

---

## 5. UniversalTelemetryCollector

**Module:** [src/amoskys/agents/protocols/universal_collector.py](../src/amoskys/agents/protocols/universal_collector.py)
**Tests:** `TestUniversalTelemetryCollector`

### Responsibilities

- Provide a single entrypoint for multi-protocol telemetry:
  - SNMP
  - MQTT
  - (Extensible to others: Modbus, HTTP, proprietary protocols)
- Maintain a registry of protocol collectors and schedules

### Construction

```python
collector = UniversalTelemetryCollector()
```

**Exposed attributes:**
- `collector.collectors`: `Dict[str, Any]`
- `collector.collection_schedules`: `Dict[str, Any]`

Tests assert:
- `.collectors` and `.collection_schedules` are dicts at initialization.
- SNMP and MQTT configuration can be set up without errors.
- Basic telemetry payloads pass simple validation logic (device_id present, timestamp sane, etc.).

**Example SNMP Config (from tests):**

```python
snmp_config = {
    "host": "192.168.1.1",
    "community": "public",
    "oids": ["1.3.6.1.2.1.1.1.0"],
}
```

The tests don't require real network IO; they validate that the collector accepts configuration and can be instantiated predictably.

---

## 6. EdgeOptimizer

**Module:** [src/amoskys/edge/edge_optimizer.py](../src/amoskys/edge/edge_optimizer.py)
**Public Re-Export:** [src/amoskys/edge/__init__.py](../src/amoskys/edge/__init__.py)
**Tests:** `TestEdgeOptimization` + `TestErrorHandling.test_resource_constraint_handling`

### Responsibilities

- Monitor local resource usage (CPU, memory, disk)
- Compress telemetry when profitable
- Batch events for efficient transmission
- Generate optimization recommendations based on constraints
- Enforce hard limits and fail fast when constraints are badly violated

### Construction

```python
config = {
    "max_memory_mb": 128,
    "max_cpu_percent": 50,
    "compression_enabled": True,
    "batch_size": 100,
}
optimizer = EdgeOptimizer(config)
```

### API

```python
resources = optimizer.get_resource_usage()
compressed = optimizer._compress_data(data_bytes)
batches = optimizer._create_batches(events, batch_size=50)
recommendations = optimizer._generate_optimization_recommendations(resource_info)
optimized_data = optimizer.optimize_data(data_bytes)
```

**Resource fields (tested):**
- `cpu_percent`
- `memory_mb`
- `disk_usage_percent`

**Compression behavior:**
- `_compress_data` returns bytes
- For repetitive data, compressed size is smaller than original (enforced in tests)

**Batching behavior:**
- `_create_batches(events, batch_size=50)`:
  - Produces multiple batches for 150 events
  - Each batch size ≤ 50

**Adaptive optimization:**
- `_generate_optimization_recommendations` examines:
  - `cpu_percent`, `memory_mb`
  - `constraint_cpu_percent`, `constraint_memory_mb`
  - Returns non-empty recommendations list when resource usage exceeds constraints.

**Constraint handling:**
- `optimize_data`:
  - Returns optimized data under normal/high load
  - May raise a runtime error if CPU/memory are severely above limits (the error-handling test accepts either result as long as it's explicit and not a crash unrelated to constraints).

---

## 7. FlowAgent + WAL Integration

**Modules:**
- FlowAgent: [src/amoskys/agents/flowagent/main.py](../src/amoskys/agents/flowagent/main.py)
- WAL: [src/amoskys/agents/flowagent/wal_sqlite.py](../src/amoskys/agents/flowagent/wal_sqlite.py)
- Tests: [tests/integration/test_wal_grow_drain.py](../tests/integration/test_wal_grow_drain.py)

### Responsibilities

- Persist flow events into a SQLite WAL at `data/wal/flowagent.db`
- Drain events from WAL and publish to EventBus via gRPC
- Expose:
  - `/healthz` on :8081
  - Metrics on :9101 (FlowAgent)
  - EventBus metrics on :9000/:9100

### TLS Behavior (CI-safe)

`grpc_channel()` now supports optional client certificates:
- If `certs/client.crt` and `certs/client.key` exist:
  - Use full mutual TLS (mTLS).
- If they are missing (CI environment):
  - Log a warning
  - Fallback to server-auth-only TLS instead of crashing with `FileNotFoundError`

This unblocks:
- `test_wal_grows_then_drains` which verifies that the WAL grows when the EventBus is unreachable and drains when connectivity is restored.

---

## 8. Testing Guarantees

The microprocessor agent stack is validated by:

### 1. Microprocessor Agent Suite

`tests/test_microprocessor_agent.py` → **28/28 passed**

Covers:
- Agent lifecycle & status
- Fusion engine initialization, profiling, correlation, thresholds
- Device discovery (ports, fingerprinting, risk)
- Universal telemetry collector
- Edge optimization (compression, batching, recommendations)
- Integration scenarios (IoT, medical, industrial, high load)
- Error handling (invalid telemetry, invalid networks, resource constraints)

### 2. System-wide Tests

`pytest tests/` → **136 passed, 1 skipped**

Includes:
- Golden envelope bytes
- WAL behavior & draining
- Queue behavior (backpressure, retries, persistence)
- Cryptography (signing, verification, canonicalization)
- Web/API gateway: auth, agents, events, system status, security

The single skipped test is a manual SNMP continuous test, intentionally not run in automated CI.

---

## 9. Roadmap & Extension Points

With this baseline in place, you can extend the Microprocessor Agent Stack along several axes:

### More Protocols in UniversalTelemetryCollector
- Modbus, OPC-UA, CoAP, custom device SDKs

### Richer Device Fingerprinting
- Combine banners, TLS fingerprints, MAC OUI, behavioral signals

### Smarter Edge Optimization
- Model-based decisions (e.g., tiny RL policy for compression/batching)
- Per-device or per-tenant optimization profiles

### On-device ML
- Lightweight models for anomaly scoring before fusion

### Policy-Driven Actions
- Allow `MicroprocessorAgentCore` to trigger local responses (quarantine, rate-limit, config pushes) when Fusion raises high-risk events

---

This document + the passing test suite define the contract for the microprocessor agent layer and provide a stable base to evolve AMOSKYS into a full "neural edge command platform."
