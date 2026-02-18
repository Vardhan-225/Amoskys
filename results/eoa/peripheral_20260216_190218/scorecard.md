# EOA Scorecard: PeripheralAgent V2

**Date:** 2026-02-17T01:04:26.317692+00:00
**Duration:** 120s (2.0 min)
**Platform:** macOS (Darwin)

## Agent Overview

| Property | Value |
|----------|-------|
| Agent | PeripheralAgent V2 |
| Module | `amoskys.agents.peripheral.peripheral_agent_v2` |
| Probes | 7 |
| Collector | MacOSUSBCollector (system_profiler SPUSBDataType) |
| macOS Ready | ✅ YES |
| MITRE Coverage | T1200, T1091, T1052, T1056.001 |

## Live Signal Assessment

| Check | Result |
|-------|--------|
| Live signal | ✅ LIVE — real endpoint data captured |
| Total queue rows | 11 |
| Decode success | 11/11 |
| Total events | 33 |
| Probe events (non-metric) | 11 |
| Events with evidence payload | 33/33 |
| Empty-evidence events | 0 |
| MITRE techniques observed | 1 |
| Tracebacks in log | 0 |

## Event Types Observed

| Event Type | Count |
|------------|-------|
| `METRIC` | 22 |
| `SECURITY` | 11 |

## Probes That Fired

| Probe (source_component) | Events |
|--------------------------|--------|
| `peripheral_collector` | 11 |
| `peripheral_agent` | 11 |
| `usb_inventory` | 11 |

## MITRE Techniques Observed

`T1200`

## Resource Usage

| Metric | Value |
|--------|-------|
| RSS min | 7,120 KB |
| RSS max | 56,592 KB |
| RSS final | 42,496 KB |
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
| Metric data | 22 events |
| Security event | 11 events |
| Alarm data | 0 events |
| Attributes map | 11 events |

## Next Actions

1. ✅ Agent is healthy — consider expanding probe coverage
