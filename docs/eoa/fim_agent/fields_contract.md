# FIMAgent V2 — Evidence Richness Contract

## Overview

The FIM Agent monitors file integrity across configured directory paths.
It produces **METRIC** events for heartbeat/baseline status and **SECURITY**
events when probes detect suspicious file changes.

EOA Date: 2026-02-16 | Platform: macOS (Darwin) | Duration: 120s

## Required Fields — ALL Events

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `event_id` | string | Unique event identifier | `fim_heartbeat_1771284301564408064` |
| `event_type` | string | `METRIC` or `SECURITY` | `SECURITY` |
| `severity` | string | `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | `HIGH` |
| `source_component` | string | Agent/probe that generated the event | `critical_system_file_change` |
| `tags` | string[] | Category tags | `["fim", "threat"]` |

## SECURITY Events (Probe-Generated)

| Field | Type | Description |
|-------|------|-------------|
| `security_event.event_category` | string | Probe event type (e.g., `critical_file_tampered`) |
| `security_event.risk_score` | float | 0.0–1.0 risk score (0.8 for HIGH/CRITICAL) |
| `security_event.analyst_notes` | string | Probe name and severity |
| `security_event.mitre_techniques` | string[] | MITRE ATT&CK technique IDs |
| `confidence_score` | float | 0.0–1.0 confidence (0.7 for probe events) |
| `attributes` | map | Evidence fields from probe data |

### Attributes Map for SECURITY Events

Varies by probe — typical fields:

| Key | Description | Example |
|-----|-------------|---------|
| `path` | File path that changed | `/tmp/eoa_fim_watch/shell.php` |
| `change_type` | Type of change | `CREATED`, `MODIFIED`, `DELETED`, `HASH_CHANGED`, `PERM_CHANGED`, `OWNER_CHANGED` |
| `details` | Human-readable change description | `File created: /tmp/eoa_fim_watch/shell.php` |
| `old_hash` | SHA-256 of previous file (if available) | `abc123...` |
| `new_hash` | SHA-256 of new file | `f8c3a0...` |
| `mode` | File permission mode (SUID probe) | `0o104755` |
| `reason` | Why this is suspicious | `SUID bit added (privilege escalation risk)` |
| `patterns_matched` | Webshell patterns matched | `["eval\\s*\\(\\s*base64_decode"]` |
| `dangerous_settings` | Config backdoor findings | `["PermitRootLogin enabled"]` |

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
| `fim_baseline_files` | files | Number of files in auto-created baseline |
| `fim_heartbeat` | baseline_files | Baseline file count (emitted every cycle with no changes) |
| `fim_file_changes` | files | Number of file changes detected this cycle |
| `fim_probe_events` | events | Number of probe events generated from changes |

## Probe Inventory (8 Probes)

| # | Probe | Fires On | MITRE | macOS Active |
|---|-------|----------|-------|--------------|
| 1 | `critical_system_file_change` | Binaries in CRITICAL_BINARIES set or CRITICAL_CONFIGS paths modified | T1036, T1547, T1574 | ✅ |
| 2 | `suid_bit_change` | SUID/SGID bit added to any file | T1548.001, T1068 | ✅ |
| 3 | `service_creation` | New plist/service in LaunchAgent/Daemon/systemd dirs | T1543, T1053 | ✅ |
| 4 | `webshell_drop` | New PHP/JSP/ASP files with malicious patterns in web roots | T1505.003 | ✅ (if web roots exist) |
| 5 | `config_backdoor` | sshd_config or sudoers modified with dangerous settings | T1548, T1078, T1556 | ✅ |
| 6 | `library_hijack` | ld.so.preload or linker config modified, new .so files | T1574.006, T1014 | ⚠️ (Linux paths) |
| 7 | `bootloader_tamper` | Files in /boot modified | T1542.003 | ❌ (no /boot on macOS) |
| 8 | `world_writable_sensitive` | Sensitive files made world-writable | T1565, T1070 | ✅ |

## Anti-Patterns

1. **Do NOT access `TelemetryEvent.mitre_techniques`** — field doesn't exist on TelemetryEvent proto.
   MITRE techniques live inside `SecurityEvent.mitre_techniques`.
2. **Do NOT use `ALERT` event_type** — use `SECURITY` for probe events, `METRIC` for counters.
3. **Do NOT put MITRE IDs in `tags`** — use `SecurityEvent.mitre_techniques` field.
4. **Do NOT use `metric_data.CopyFrom()` for probe events** — use `SecurityEvent` + `attributes` map.
5. **Do NOT return empty `[]` when no changes** — emit heartbeat METRIC so the agent proves liveness.

## Baseline Behavior

- **Auto-create**: If no baseline exists, first cycle auto-creates one and emits `fim_baseline_files` metric
- **Monitor**: Subsequent cycles compare against baseline and detect CREATE/MODIFY/DELETE/PERM_CHANGE/HASH_CHANGE/OWNER_CHANGE
- **Heartbeat**: When no changes detected, emits `fim_heartbeat` metric with baseline file count

## EOA Baseline Data

| Metric | Value |
|--------|-------|
| Auto-baseline files | 273 |
| Monitored paths | `/tmp/eoa_fim_watch`, `/etc` |
| Trigger changes detected | 5 |
| Probes fired | 1/8 (`critical_system_file_change`) |
| MITRE techniques | T1036, T1547 |
