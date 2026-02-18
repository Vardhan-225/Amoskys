# EOA Scorecard: FlowAgent V2

**Date:** 2026-02-17T22:49:00.459472+00:00
**Duration:** 120s (2.0 min)
**Platform:** macOS (Darwin)

## Agent Overview

| Property | Value |
|----------|-------|
| Agent | FlowAgent V2 |
| Module | `amoskys.agents.flow.flow_agent_v2` |
| Probes | 8 |
| Collector | MacOSFlowCollector (lsof -i -n -P) |
| macOS Ready | ✅ YES |
| MITRE Coverage | T1046, T1021, T1041, T1048, T1071, T1090 |

## Live Signal Assessment

| Check | Result |
|-------|--------|
| Live signal | ✅ LIVE — real endpoint data captured |
| Total queue rows | 8 |
| Decode success | 8/8 |
| Total events | 18 |
| Probe events (non-metric) | 1 |
| Events with evidence payload | 18/18 |
| Empty-evidence events | 0 |
| MITRE techniques observed | 2 |
| Tracebacks in log | 0 |

## Event Types Observed

| Event Type | Count |
|------------|-------|
| `METRIC` | 17 |
| `SECURITY` | 1 |

## Probes That Fired

| Probe (source_component) | Events |
|--------------------------|--------|
| `flow_collector` | 16 |
| `flow_agent` | 1 |
| `new_external_service` | 1 |

## MITRE Techniques Observed

`T1041`, `T1595`

## Resource Usage

| Metric | Value |
|--------|-------|
| RSS min | 5,808 KB |
| RSS max | 59,744 KB |
| RSS final | 59,744 KB |
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
| Metric data | 17 events |
| Security event | 1 events |
| Alarm data | 0 events |
| Attributes map | 9 events |

## Next Actions

1. ✅ Agent is healthy — consider expanding probe coverage
