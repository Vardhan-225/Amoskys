# DNSAgent V2 — Evidence Richness Contract

## Overview

The DNS Agent monitors DNS query activity via macOS unified logging (mDNSResponder).
It produces **METRIC** events for heartbeat/collection status and **SECURITY**
events when probes detect suspicious DNS patterns (DGA, tunneling, beaconing, etc.).

EOA Date: 2026-02-16 | Platform: macOS (Darwin) | Duration: 90s

## Required Fields — ALL Events

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `event_id` | string | Unique event identifier | `dns_collection_summary_1771284301564408064` |
| `event_type` | string | `METRIC` or `SECURITY` | `SECURITY` |
| `severity` | string | `DEBUG`, `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | `DEBUG` |
| `source_component` | string | Agent/probe that generated the event | `raw_dns_query` |
| `tags` | string[] | Category tags | `["dns", "threat"]` |

## SECURITY Events (Probe-Generated)

| Field | Type | Description |
|-------|------|-------------|
| `security_event.event_category` | string | Probe event type (e.g., `dns_query_observed`) |
| `security_event.risk_score` | float | 0.0–1.0 risk score (0.8 for HIGH/CRITICAL, 0.4 otherwise) |
| `security_event.analyst_notes` | string | Probe name and severity |
| `security_event.mitre_techniques` | string[] | MITRE ATT&CK technique IDs |
| `confidence_score` | float | 0.0–1.0 confidence (0.7 for probe events) |
| `attributes` | map | Evidence fields from probe data |

### Attributes Map for SECURITY Events

Varies by probe — typical fields:

| Key | Description | Example |
|-----|-------------|---------|
| `domain` | Queried domain name | `google.com` |
| `query_type` | DNS record type | `A`, `AAAA`, `TXT`, `MX` |
| `source_ip` | Source IP of the query | `127.0.0.1` |
| `entropy` | Shannon entropy of domain (DGA probe) | `4.32` |
| `dga_score` | DGA likelihood score | `0.87` |
| `interval_cv` | Coefficient of variation for beaconing | `0.05` |
| `beacon_count` | Number of periodic callbacks detected | `42` |
| `tld` | Top-level domain | `.tk`, `.xyz`, `.top` |
| `txt_length` | Length of TXT record (tunneling probe) | `4096` |
| `flux_ip_count` | Number of distinct IPs (fast-flux) | `25` |
| `process_name` | Process making the query (new domain probe) | `curl` |
| `blocklist_name` | Threat intel list matched (blocked domain) | `malware-domains` |

## METRIC Events

| Field | Type | Description |
|-------|------|-------------|
| `metric_data.metric_name` | string | Metric name |
| `metric_data.metric_type` | string | Always `GAUGE` |
| `metric_data.numeric_value` | float | Metric value |
| `metric_data.unit` | string | Unit of measurement |

### Metric Names

| Metric | Unit | Description |
|--------|------|-------------|
| `dns_queries_collected` | queries | DNS queries captured this cycle (heartbeat — always emitted) |
| `dns_probe_events` | events | Number of probe events generated (only when > 0) |

## Probe Inventory (9 Probes)

| # | Probe | Fires On | MITRE | macOS Active |
|---|-------|----------|-------|--------------|
| 1 | `raw_dns_query` | Every DNS query observed (baseline capture) | T1071.004 | ✅ |
| 2 | `dga_score` | High-entropy domain names (DGA detection) | T1568.002 | ✅ |
| 3 | `beaconing_pattern` | Periodic DNS callbacks to same domain (C2) | T1071.004, T1573.002 | ✅ |
| 4 | `suspicious_tld` | Queries to high-risk TLDs (.tk, .xyz, .top, etc.) | T1071.004 | ✅ |
| 5 | `nxdomain_burst` | Burst of NXDOMAIN responses (domain probing) | T1568.002, T1046 | ✅ |
| 6 | `large_txt_tunneling` | Oversized TXT records (DNS tunneling) | T1048.001, T1071.004 | ✅ |
| 7 | `fast_flux_rebinding` | Rapid IP rotation for a domain (fast-flux) | T1568.001 | ✅ |
| 8 | `new_domain_for_process` | First-time domain query per process | T1071.004 | ✅ |
| 9 | `blocked_domain_hit` | Query matches threat intel blocklist | T1071.004, T1566 | ✅ |

## Anti-Patterns

1. **Do NOT use `DNSTelemetry`** — proto type doesn't exist; use `DeviceTelemetry` with `TelemetryEvent` list.
2. **Do NOT use `DNSRecord`** — proto type doesn't exist; encode DNS data in `attributes` map.
3. **Do NOT use `AlertData` or `alerts`** — proto types don't exist; use `SecurityEvent` sub-messages.
4. **Do NOT use `event.timestamp`** in validation — use `event.timestamp_ns`.
5. **Do NOT return empty `[]` when no queries** — emit heartbeat METRIC so the agent proves liveness.

## macOS Collector Behavior

- **Source**: `log show --predicate 'process == "mDNSResponder" AND eventMessage CONTAINS "Query"'` with `--last 1m`
- **Parsing**: Extracts domain name from "Query" log entries, defaults to `A` record type
- **Limitation**: Only captures mDNSResponder queries; direct socket DNS bypasses this
- **Heartbeat**: Always emits `dns_queries_collected` metric even when 0 queries found

## EOA Baseline Data

| Metric | Value |
|--------|-------|
| DNS queries collected | 6 (from nslookup triggers) |
| Probes fired | 1/9 (`raw_dns_query`) |
| MITRE techniques observed | T1071.004 |
| Heartbeat metrics | 14 |
| Security events | 6 |
| Verdict | PASS |

## Dark Spots

- Higher-order probes (DGA, beaconing, tunneling) require sustained traffic patterns to fire
- mDNSResponder log format may vary across macOS versions
- No pcap-level DNS capture (only system log parsing)
- Process attribution requires additional correlation with network sockets
- Blocked domain probe requires threat intel blocklist to be loaded
