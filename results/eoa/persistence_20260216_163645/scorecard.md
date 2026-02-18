# EOA Scorecard: PersistenceGuard V2

**Date:** 2026-02-16T22:38:49.808144+00:00
**Duration:** 120s (2.0 min)
**Platform:** macOS (Darwin)

## Agent Overview

| Property | Value |
|----------|-------|
| Agent | PersistenceGuard V2 |
| Module | `amoskys.agents.persistence.persistence_agent_v2` |
| Probes | 8 |
| Collector | macOS LaunchAgents/Daemons, cron, shell profiles, SSH keys (live) |
| macOS Ready | ✅ YES |
| MITRE Coverage | T1037, T1053.003, T1098.004, T1176, T1543, T1546.004, T1547 |

## Live Signal Assessment

| Check | Result |
|-------|--------|
| Live signal | ✅ LIVE — real endpoint data captured |
| Total queue rows | 1 |
| Decode success | 1/1 |
| Total events | 1 |
| Probe events (non-metric) | 1 |
| Events with evidence payload | 1/1 |
| Empty-evidence events | 0 |
| MITRE techniques observed | 0 |
| Tracebacks in log | 0 |

## Event Types Observed

| Event Type | Count |
|------------|-------|
| `agent_metrics` | 1 |

## Probes That Fired

| Probe (source_component) | Events |
|--------------------------|--------|
| `PersistenceGuardV2` | 1 |

## Resource Usage

| Metric | Value |
|--------|-------|
| RSS min | 3,936 KB |
| RSS max | 39,152 KB |
| RSS final | 39,152 KB |
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
| Metric data | 0 events |
| Security event | 0 events |
| Alarm data | 0 events |
| Attributes map | 1 events |

## Next Actions

1. ✅ Agent is healthy — consider expanding probe coverage
