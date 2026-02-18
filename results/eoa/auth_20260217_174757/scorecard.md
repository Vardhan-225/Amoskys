# EOA Scorecard: AuthGuard V2

**Date:** 2026-02-17T23:50:06.539883+00:00
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
| Live signal | ✅ LIVE — real endpoint data captured |
| Total queue rows | 11 |
| Decode success | 11/11 |
| Total events | 25 |
| Probe events (non-metric) | 2 |
| Events with evidence payload | 25/25 |
| Empty-evidence events | 0 |
| MITRE techniques observed | 1 |
| Tracebacks in log | 0 |

## Event Types Observed

| Event Type | Count |
|------------|-------|
| `METRIC` | 23 |
| `SECURITY` | 2 |

## Probes That Fired

| Probe (source_component) | Events |
|--------------------------|--------|
| `auth_collector` | 22 |
| `sudo_elevation` | 2 |
| `auth_guard_agent` | 1 |

## MITRE Techniques Observed

`T1548.003`

## Resource Usage

| Metric | Value |
|--------|-------|
| RSS min | 3,600 KB |
| RSS max | 57,792 KB |
| RSS final | 57,776 KB |
| CPU avg | 0.0% |
| CPU max | 0.0% |
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
| Metric data | 23 events |
| Security event | 2 events |
| Alarm data | 0 events |
| Attributes map | 2 events |

## Next Actions

1. ✅ Agent is healthy — consider expanding probe coverage
