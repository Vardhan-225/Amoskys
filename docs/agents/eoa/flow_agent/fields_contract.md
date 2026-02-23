# FlowAgent V2 — Fields Contract

> **Agent:** `flow_agent_v2`  
> **Collector:** `MacOSFlowCollector` (`lsof -i -n -P`)  
> **Proto:** `DeviceTelemetry` → `TelemetryEvent` (METRIC / SECURITY)  
> **EOA Date:** 2026-02-17

---

## DeviceTelemetry Envelope

| Field | Type | Example | Notes |
|-------|------|---------|-------|
| `device_id` | string | `Akashs-MacBook-Air.local` | hostname |
| `device_type` | string | `HOST` | always HOST |
| `protocol` | string | `FLOW` | agent protocol identifier |
| `timestamp_ns` | uint64 | `1771368411214813952` | collection cycle timestamp |
| `collection_agent` | string | `flow_agent_v2` | agent name |
| `agent_version` | string | `2.0.0` | semver |
| `events` | repeated TelemetryEvent | 2–4 per cycle | METRIC + optional SECURITY |

---

## Event Type: METRIC (heartbeat — always emitted)

### `flows_collected` (GAUGE)

| Field | Type | Example |
|-------|------|---------|
| `event_id` | string | `flow_collection_summary_{ts}` |
| `event_type` | string | `METRIC` |
| `severity` | string | `INFO` |
| `source_component` | string | `flow_collector` |
| `tags` | repeated string | `["flow", "metric", "heartbeat"]` |
| `metric_data.metric_name` | string | `flows_collected` |
| `metric_data.metric_type` | string | `GAUGE` |
| `metric_data.numeric_value` | double | `12.0` |
| `metric_data.unit` | string | `connections` |

### `flows_collected_total` (COUNTER)

| Field | Type | Example |
|-------|------|---------|
| `event_id` | string | `flow_collector_total_{ts}` |
| `event_type` | string | `METRIC` |
| `metric_data.metric_name` | string | `flows_collected_total` |
| `metric_data.metric_type` | string | `COUNTER` |
| `metric_data.numeric_value` | double | `105.0` |
| `metric_data.unit` | string | `connections` |

### `flow_probe_events` (GAUGE — only when probes fire)

| Field | Type | Example |
|-------|------|---------|
| `event_id` | string | `flow_probe_events_{ts}` |
| `metric_data.metric_name` | string | `flow_probe_events` |
| `metric_data.numeric_value` | double | `1.0` |

---

## Event Type: SECURITY (probe detections)

### `flow_new_external_service_seen` (NewExternalServiceProbe)

| Field | Type | Example |
|-------|------|---------|
| `event_id` | string | `flow_new_external_service_seen_{ts}` |
| `event_type` | string | `SECURITY` |
| `severity` | string | `INFO` |
| `source_component` | string | `new_external_service` |
| `tags` | repeated string | `["flow", "threat"]` |
| `confidence_score` | float | `0.8` |
| `security_event.event_category` | string | `flow_new_external_service_seen` |
| `security_event.risk_score` | float | `0.4` |
| `security_event.analyst_notes` | string | `Probe: new_external_service, Severity: INFO` |
| `security_event.mitre_techniques` | repeated string | `["T1041", "T1595"]` |
| `attributes.src_ip` | string | `192.168.1.232` |
| `attributes.dst_ip` | string | `45.33.32.156` |
| `attributes.dst_port` | string | `50051` |
| `attributes.protocol` | string | `TCP` |
| `attributes.first_seen_ns` | string | `1771368427484894976` |
| `attributes.reason` | string | `First-time connection to external service` |

---

## Probes — Potential SECURITY Events (not fired in EOA)

| Probe | Event Type | Severity | MITRE | Trigger |
|-------|-----------|----------|-------|---------|
| `port_scan_sweep` | `flow_port_scan_detected` | HIGH | T1046 | ≥20 distinct ports to same dst |
| `lateral_smb_winrm` | `flow_lateral_smb_winrm_detected` | HIGH | T1021.002/.003/.006 | SMB/RDP/WinRM/SSH between private IPs |
| `data_exfil_volume_spike` | `flow_data_exfil_volume_spike` | HIGH | T1041, T1048 | ≥50MB outbound to single dst |
| `c2_beacon_flow` | `flow_c2_beacon_detected` | CRITICAL | T1071, T1573 | ≥4 periodic small flows, jitter <20% |
| `cleartext_credential_leak` | `flow_cleartext_credential_leak` | CRITICAL | T1552 | FTP/Telnet/HTTP auth in cleartext |
| `suspicious_tunnel` | `flow_suspicious_tunnel_detected` | HIGH | T1090, T1572 | ≥10min connection, ≥100 packets |
| `internal_recon_dns_flow` | `flow_internal_recon_dns` | MEDIUM | T1046, T1590 | ≥100 unique DNS hostnames in 10min |

---

## FlowEvent Model (Collector Output)

The `MacOSFlowCollector` produces `FlowEvent` dataclass objects:

| Field | Type | Source | Example |
|-------|------|--------|---------|
| `src_ip` | str | lsof NAME column | `192.168.1.232` |
| `dst_ip` | str | lsof NAME column | `3.130.241.210` |
| `src_port` | int | lsof NAME column | `59292` |
| `dst_port` | int | lsof NAME column | `443` |
| `protocol` | str | lsof NODE column | `TCP` / `UDP` |
| `bytes_tx` | int | always 0 (lsof limitation) | `0` |
| `bytes_rx` | int | always 0 (lsof limitation) | `0` |
| `packet_count` | int | always 1 (snapshot) | `1` |
| `first_seen_ns` | int | collection timestamp | `1771368411...` |
| `last_seen_ns` | int | = first_seen_ns | `1771368411...` |
| `direction` | str | RFC1918 heuristic | `OUTBOUND` / `LATERAL` / `INBOUND` |
| `app_protocol` | str | port mapping | `HTTPS` / `SSH` / `UNKNOWN` |
| `tcp_flags` | str | TCP state mapping | `SA` / `F` / `FA` |

### Limitations

- **No byte counts** — `lsof` doesn't report bytes transferred (future: `nettop` enrichment)
- **Snapshot, not flow** — each collection is a point-in-time view, not accumulated flow
- **No process enrichment** — lsof provides PID/command but not yet propagated to FlowEvent
