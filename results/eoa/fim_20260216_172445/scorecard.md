# EOA Scorecard: FIMAgent V2

**Date:** 2026-02-16T23:26:51.336277+00:00
**Duration:** 120s (2.0 min)
**Platform:** macOS (Darwin)

## Agent Overview

| Property | Value |
|----------|-------|
| Agent | FIMAgent V2 |
| Module | `amoskys.agents.fim.fim_agent_v2` |
| Probes | 8 |
| Collector | os.walk + hashlib (live) |
| macOS Ready | ✅ YES |
| MITRE Coverage | T1036, T1547, T1574, T1505.003, T1548, T1556, T1014 |

## Live Signal Assessment

| Check | Result |
|-------|--------|
| Live signal | ✅ LIVE — real endpoint data captured |
| Total queue rows | 8 |
| Decode success | 8/8 |
| Total events | 10 |
| Probe events (non-metric) | 1 |
| Events with evidence payload | 10/10 |
| Empty-evidence events | 0 |
| MITRE techniques observed | 2 |
| Tracebacks in log | 0 |

## Event Types Observed

| Event Type | Count |
|------------|-------|
| `METRIC` | 9 |
| `SECURITY` | 1 |

## Probes That Fired

| Probe (source_component) | Events |
|--------------------------|--------|
| `fim_agent` | 9 |
| `critical_system_file_change` | 1 |

## MITRE Techniques Observed

`T1036`, `T1547`

## Resource Usage

| Metric | Value |
|--------|-------|
| RSS min | 3,344 KB |
| RSS max | 59,552 KB |
| RSS final | 48,160 KB |
| CPU avg | 0.1% |
| CPU max | 0.6% |
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
| Metric data | 9 events |
| Security event | 1 events |
| Alarm data | 0 events |
| Attributes map | 1 events |

## Next Actions

1. ✅ Agent is healthy — consider expanding probe coverage
