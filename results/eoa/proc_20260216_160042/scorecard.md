# EOA Scorecard: ProcAgent V3

**Date:** 2026-02-16T22:02:51.709486+00:00
**Duration:** 120s (2.0 min)
**Platform:** macOS (Darwin)

## Agent Overview

| Property | Value |
|----------|-------|
| Agent | ProcAgent V3 |
| Module | `amoskys.agents.proc.proc_agent_v3` |
| Probes | 8 |
| Collector | psutil (live) |
| macOS Ready | ✅ YES |
| MITRE Coverage | T1059, T1218, T1055, T1496, T1036, T1204, T1078 |

## Live Signal Assessment

| Check | Result |
|-------|--------|
| Live signal | ✅ LIVE — real endpoint data captured |
| Total queue rows | 12 |
| Decode success | 12/12 |
| Total events | 222 |
| Probe events (non-metric) | 186 |
| Events with evidence payload | 222/222 |
| Empty-evidence events | 0 |
| MITRE techniques observed | 6 |
| Tracebacks in log | 3 |

## Event Types Observed

| Event Type | Count |
|------------|-------|
| `SECURITY` | 186 |
| `METRIC` | 36 |

## Probes That Fired

| Probe (source_component) | Events |
|--------------------------|--------|
| `lolbin_execution` | 96 |
| `process_spawn` | 56 |
| `system_metrics` | 36 |
| `binary_from_temp` | 22 |
| `suspicious_user_process` | 12 |

## MITRE Techniques Observed

`T1059`, `T1078`, `T1204`, `T1218`, `T1218.010`, `T1218.011`

## Resource Usage

| Metric | Value |
|--------|-------|
| RSS min | 4,000 KB |
| RSS max | 62,848 KB |
| RSS final | 48,496 KB |
| CPU avg | 0.0% |
| CPU max | 0.0% |
| Samples | 13 |

## Stability

| Check | Result |
|-------|--------|
| Tracebacks | ❌ 3 |
| Loop stability | ⚠️ Check logs |
| macOS compat | ✅ Full |

## Data Richness (A3 Contract Check)

Every event must include: device_id, collection_agent, event_type, timestamp_ns, event_id, and evidence payload.

| Field | Present |
|-------|---------|
| Metric data | 36 events |
| Security event | 186 events |
| Alarm data | 0 events |
| Attributes map | 186 events |

## Next Actions

1. **Fix 3 tracebacks** — check raw_log.txt (all gRPC circuit breaker — expected in dev, no EventBus running)
2. ✅ Agent is healthy — consider expanding probe coverage
