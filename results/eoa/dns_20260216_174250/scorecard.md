# EOA Scorecard: DNSAgent V2

**Date:** 2026-02-16T23:44:30.465780+00:00
**Duration:** 90s (1.5 min)
**Platform:** macOS (Darwin)

## Agent Overview

| Property | Value |
|----------|-------|
| Agent | DNSAgent V2 |
| Module | `amoskys.agents.dns.dns_agent_v2` |
| Probes | 9 |
| Collector | MacOSDNSCollector (log show mDNSResponder) |
| macOS Ready | ✅ YES |
| MITRE Coverage | T1071.004, T1568.002, T1568.001, T1048.001 |

## Live Signal Assessment

| Check | Result |
|-------|--------|
| Live signal | ✅ LIVE — real endpoint data captured |
| Total queue rows | 9 |
| Decode success | 9/9 |
| Total events | 20 |
| Probe events (non-metric) | 6 |
| Events with evidence payload | 20/20 |
| Empty-evidence events | 0 |
| MITRE techniques observed | 1 |
| Tracebacks in log | 0 |

## Event Types Observed

| Event Type | Count |
|------------|-------|
| `METRIC` | 14 |
| `SECURITY` | 6 |

## Probes That Fired

| Probe (source_component) | Events |
|--------------------------|--------|
| `dns_collector` | 9 |
| `raw_dns_query` | 6 |
| `dns_agent` | 5 |

## MITRE Techniques Observed

`T1071.004`

## Resource Usage

| Metric | Value |
|--------|-------|
| RSS min | 4,816 KB |
| RSS max | 51,360 KB |
| RSS final | 51,104 KB |
| CPU avg | 0.1% |
| CPU max | 1.3% |
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
| Metric data | 14 events |
| Security event | 6 events |
| Alarm data | 0 events |
| Attributes map | 6 events |

## Next Actions

1. ✅ Agent is healthy — consider expanding probe coverage
