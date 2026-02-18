# EOA Scorecard: AuthGuard V2

**Date:** 2026-02-17T23:40:26.627784+00:00
**Duration:** 120s (2.0 min)
**Platform:** macOS (Darwin)

## Agent Overview

| Property | Value |
|----------|-------|
| Agent | AuthGuard V2 |
| Module | `amoskys.agents.auth.auth_guard_agent_v2` |
| Probes | 8 |
| Collector | MacOSAuthLogCollector (log show broad + last) |
| macOS Ready | ✅ YES |
| MITRE Coverage | T1110, T1078, T1548.003, T1021.004, T1059, T1621 |

## Live Signal Assessment

| Check | Result |
|-------|--------|
| Live signal | ⚠️ METRICS ONLY — agent alive but no probe events |
| Total queue rows | 10 |
| Decode success | 10/10 |
| Total events | 20 |
| Probe events (non-metric) | 0 |
| Events with evidence payload | 20/20 |
| Empty-evidence events | 0 |
| MITRE techniques observed | 0 |
| Tracebacks in log | 0 |

## Event Types Observed

| Event Type | Count |
|------------|-------|
| `METRIC` | 20 |

## Probes That Fired

| Probe (source_component) | Events |
|--------------------------|--------|
| `auth_collector` | 20 |

## Resource Usage

| Metric | Value |
|--------|-------|
| RSS min | 3,840 KB |
| RSS max | 58,032 KB |
| RSS final | 58,032 KB |
| CPU avg | 0.0% |
| CPU max | 0.5% |
| Samples | 13 |

## Stability

| Check | Result |
|-------|--------|
| Tracebacks | ✅ 0 |
| Loop stability | ✅ Good |
| macOS compat | ✅ Full |

## Data Richness (A3 Contract Check)

Every event must include: device_id, collection_agent, event_type, timestamp_ns, event_id, and evidence payload.

| Field | Present |
|-------|---------|
| Metric data | 20 events |
| Security event | 0 events |
| Alarm data | 0 events |
| Attributes map | 0 events |

## Next Actions

1. **Debug probe scanning** — agent is mac-ready but probes produced 0 events
