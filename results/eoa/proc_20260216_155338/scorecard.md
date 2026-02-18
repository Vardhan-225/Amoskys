# EOA Scorecard: ProcAgent V3

**Date:** 2026-02-16T21:55:48.194278+00:00
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
| Live signal | ❌ DARK — no events produced |
| Total queue rows | 12 |
| Decode success | 12/12 |
| Total events | 0 |
| Probe events (non-metric) | 0 |
| Events with evidence payload | 0/0 |
| Empty-evidence events | 0 |
| MITRE techniques observed | 0 |
| Tracebacks in log | 3 |

## Resource Usage

| Metric | Value |
|--------|-------|
| RSS min | 3,648 KB |
| RSS max | 61,776 KB |
| RSS final | 57,872 KB |
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
| Metric data | 0 events |
| Security event | 0 events |
| Alarm data | 0 events |
| Attributes map | 0 events |

## Next Actions

1. **Debug probe scanning** — agent is mac-ready but probes produced 0 events
1. **Fix 3 tracebacks** — check raw_log.txt
