# EOA Scorecard: AuthGuard V2

**Date:** 2026-02-16T23:56:51.050989+00:00
**Duration:** 90s (1.5 min)
**Platform:** macOS (Darwin)

## Agent Overview

| Property | Value |
|----------|-------|
| Agent | AuthGuard V2 |
| Module | `amoskys.agents.auth.auth_guard_agent_v2` |
| Probes | 8 |
| Collector | MacOSAuthLogCollector (log show sshd/sudo) |
| macOS Ready | ✅ YES |
| MITRE Coverage | T1110, T1078, T1548.003, T1021.004 |

## Live Signal Assessment

| Check | Result |
|-------|--------|
| Live signal | ⚠️ METRICS ONLY — agent alive but no probe events |
| Total queue rows | 8 |
| Decode success | 8/8 |
| Total events | 8 |
| Probe events (non-metric) | 0 |
| Events with evidence payload | 8/8 |
| Empty-evidence events | 0 |
| MITRE techniques observed | 0 |
| Tracebacks in log | 0 |

## Event Types Observed

| Event Type | Count |
|------------|-------|
| `METRIC` | 8 |

## Probes That Fired

| Probe (source_component) | Events |
|--------------------------|--------|
| `auth_collector` | 8 |

## Resource Usage

| Metric | Value |
|--------|-------|
| RSS min | 4,832 KB |
| RSS max | 56,640 KB |
| RSS final | 25,616 KB |
| CPU avg | 0.0% |
| CPU max | 0.0% |
| Samples | 10 |

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
| Metric data | 8 events |
| Security event | 0 events |
| Alarm data | 0 events |
| Attributes map | 0 events |

## Next Actions

1. **Debug probe scanning** — agent is mac-ready but probes produced 0 events
