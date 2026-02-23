# ProcAgent V3 — Evidence Fields Contract

> **Canonical Reference:** Established 2026-02-16 from EOA Reality Run  
> **Rule:** Any new agent must meet this same evidence richness standard

---

## Required Fields (ALL events)

Every `TelemetryEvent` protobuf produced by any AMOSKYS agent MUST populate:

| Field | Proto Path | Example | Required |
|-------|-----------|---------|----------|
| `event_id` | `TelemetryEvent.event_id` | `lolbin_execution_lolbin_execution_1771278819186705920` | ✅ YES |
| `event_type` | `TelemetryEvent.event_type` | `METRIC` or `SECURITY` | ✅ YES |
| `severity` | `TelemetryEvent.severity` | `INFO`, `LOW`, `HIGH`, `CRITICAL` | ✅ YES |
| `event_timestamp_ns` | `TelemetryEvent.event_timestamp_ns` | `1771278819186705920` | ✅ YES |
| `source_component` | `TelemetryEvent.source_component` | `lolbin_execution`, `system_metrics` | ✅ YES |

## Required Fields (DeviceTelemetry envelope)

Every `DeviceTelemetry` message MUST populate:

| Field | Example | Required |
|-------|---------|----------|
| `device_id` | `Akashs-MacBook-Air.local` | ✅ YES |
| `collection_agent` | `proc-agent-v3` | ✅ YES |
| `agent_version` | `3.0.0` | ✅ YES |
| `protocol` | `PROC` | ✅ YES |
| `timestamp_ns` | `1771278819186705920` | ✅ YES |

## Required Fields (SECURITY events)

Events with `event_type=SECURITY` MUST populate:

| Field | Proto Path | Example | Required |
|-------|-----------|---------|----------|
| `security_event.event_category` | `SecurityEvent.event_category` | `lolbin_execution` | ✅ YES |
| `security_event.risk_score` | `SecurityEvent.risk_score` | `0.4` (0.0–1.0) | ✅ YES |
| `security_event.mitre_techniques` | `SecurityEvent.mitre_techniques` | `["T1218", "T1218.010"]` | ✅ YES (≥1) |
| `confidence_score` | `TelemetryEvent.confidence_score` | `0.4` | ✅ YES |
| `attributes` | `TelemetryEvent.attributes` | `{"binary": "bash", "username": "..."}` | ✅ YES (≥1 key) |

## Required Fields (METRIC events)

Events with `event_type=METRIC` MUST populate:

| Field | Proto Path | Example | Required |
|-------|-----------|---------|----------|
| `metric_data.metric_name` | `MetricData.metric_name` | `cpu_percent` | ✅ YES |
| `metric_data.metric_type` | `MetricData.metric_type` | `GAUGE` | ✅ YES |
| `metric_data.numeric_value` | `MetricData.numeric_value` | `29.2` | ✅ YES |
| `metric_data.unit` | `MetricData.unit` | `percent` | ✅ YES |

## Anti-Pattern: Empty Event Syndrome

The following MUST NOT happen:

```
# BAD — event fires but carries no evidence
TelemetryEvent {
    event_type: "SECURITY"
    severity: "HIGH"
    attributes: {}              ← EMPTY
    security_event: not set     ← MISSING
}
```

Every security event MUST include enough context for an analyst to understand
_what happened_, _where_, and _why it matters_ without consulting raw logs.

## ProcAgent Baseline (2026-02-16)

| Probe | Events/Cycle | Evidence Keys | MITRE |
|-------|-------------|---------------|-------|
| `lolbin_execution` | 8 | `binary`, `username`, `category`, `suspicious_patterns` | T1218, T1218.010, T1218.011 |
| `process_spawn` | ~5 | `pid`, `ppid`, `name`, `cmdline`, `username`, `create_time` | T1059, T1204 |
| `binary_from_temp` | ~2 | `pid`, `name`, `exe`, `username`, `cmdline` | T1204 |
| `suspicious_user_process` | 1 | `pid`, `name`, `username`, `expected_user` | T1078 |
| `system_metrics` | 3 | metric_data: `cpu_percent`, `memory_percent`, `process_count` | — |

### Probes Silent in Dev (context-dependent, not bugs)

| Probe | Why Silent | Would Fire When |
|-------|-----------|-----------------|
| `process_tree_anomaly` | No unusual parent→child chains | Shell spawns from unexpected parent |
| `high_cpu_memory` | Nothing spiking | Crypto miner, resource abuse |
| `long_lived_process` | Needs longer observation window | Persistent backdoor process |
| `script_interpreter` | No suspicious script execution | `python -c 'import socket...'` |
