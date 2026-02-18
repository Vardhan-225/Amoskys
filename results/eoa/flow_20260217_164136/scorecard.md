# EOA Scorecard: FlowAgent V2

**Date:** 2026-02-17T22:43:47.004870+00:00
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
| Live signal | ❌ DARK — no events produced |
| Total queue rows | 0 |
| Decode success | 0/0 |
| Total events | 0 |
| Probe events (non-metric) | 0 |
| Events with evidence payload | 0/0 |
| Empty-evidence events | 0 |
| MITRE techniques observed | 0 |
| Tracebacks in log | 0 |

## Resource Usage

| Metric | Value |
|--------|-------|
| RSS min | 5,232 KB |
| RSS max | 50,720 KB |
| RSS final | 50,720 KB |
| CPU avg | 0.1% |
| CPU max | 0.8% |
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
| Metric data | 0 events |
| Security event | 0 events |
| Alarm data | 0 events |
| Attributes map | 0 events |

## Next Actions

1. **Debug probe scanning** — agent is mac-ready but probes produced 0 events
