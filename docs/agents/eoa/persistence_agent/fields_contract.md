# PersistenceGuard V2 — Evidence Richness Contract

## Overview

The PersistenceGuard Agent monitors autostart and persistence mechanisms on macOS,
comparing snapshots against a known-good baseline to detect new, modified, or
removed persistence entries. It produces **METRIC** events for heartbeat/snapshot
status and **SECURITY** events when persistence changes are detected.

EOA Date: 2026-02-16 | Platform: macOS (Apple Silicon) | Duration: 120s

## Proto Pattern

All events follow the `DeviceTelemetry → TelemetryEvent` structure:

| Layer | Proto Type | Key Fields |
|---|---|---|
| Envelope | `DeviceTelemetry` | `device_id`, `device_type="HOST"`, `protocol="PERSISTENCE"`, `timestamp_ns`, `collection_agent="persistence_guard_v2"` |
| Metric | `TelemetryEvent.metric_data` | `event_type="METRIC"`, `metric_name`, `numeric_value`, `unit` |
| Security | `TelemetryEvent.security_event` | `event_type="SECURITY"`, `SecurityEvent.mitre_techniques`, `SecurityEvent.risk_score`, `attributes` map |

## Required Fields — ALL Events

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `event_id` | string | Unique event identifier | `persistence_snapshot_1771284301564408064` |
| `event_type` | string | `METRIC` or `SECURITY` | `SECURITY` |
| `severity` | string | `INFO`, `MEDIUM`, `HIGH`, `CRITICAL` | `HIGH` |
| `source_component` | string | Collector or mechanism type | `persistence_user_launch_agent` |

## SECURITY Events (Change-Based)

| Field | Type | Description |
|-------|------|-------------|
| `security_event.event_category` | string | Change category (e.g., `persistence_user_launch_agent`) |
| `security_event.risk_score` | float | 0.6 for all persistence changes |
| `security_event.analyst_notes` | string | Change type and entry ID |
| `security_event.mitre_techniques` | string[] | MITRE ATT&CK technique IDs |
| `confidence_score` | float | 0.6 for persistence changes |
| `attributes` | map | Evidence fields with change details |

### Attributes Map for SECURITY Events

| Key | Description | Example |
|-----|-------------|---------|
| `change_type` | Type of change | `CREATED`, `MODIFIED`, `DELETED` |
| `mechanism_type` | Persistence mechanism | `USER_LAUNCH_AGENT`, `SHELL_PROFILE`, `CRON_USER` |
| `entry_id` | Unique persistence entry identifier | `launchd:~/Library/LaunchAgents/com.eoa.test.plist` |
| `file_path` | File path of persistence artifact | `/Users/user/Library/LaunchAgents/com.eoa.test.plist` |
| `command` | Command/program configured to run | `/usr/local/bin/agent` |
| `file_hash` | SHA-256 hash of current file | `a3f2b8c9...` |
| `old_hash` | SHA-256 hash of previous version | `d7e1f4a0...` |
| `user` | File owner username | `athanneeru` |

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
| `persistence_entries` | entries | Total persistence entries in snapshot (heartbeat — always emitted) |

## Collector Coverage (macOS)

| Mechanism | Source | Paths Monitored |
|-----------|--------|-----------------|
| LaunchAgents (user) | plistlib | `~/Library/LaunchAgents/*.plist` |
| LaunchAgents (system) | plistlib | `/Library/LaunchAgents/*.plist` |
| LaunchDaemons | plistlib | `/Library/LaunchDaemons/*.plist` |
| Cron jobs | `crontab -l` | User crontab |
| Shell profiles | hashlib | `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`, `~/.profile`, `~/.zprofile`, `~/.zlogin`, `~/.zshenv` |
| SSH authorized_keys | hashlib | `~/.ssh/authorized_keys` |

## Probe Inventory (8 Probes)

| # | Probe | Fires On | MITRE | macOS Active |
|---|-------|----------|-------|--------------|
| 1 | `launch_agent_daemon` | New/modified LaunchAgent or LaunchDaemon plist | T1543.001, T1037.005 | ✅ |
| 2 | `systemd_service_persistence` | New/modified systemd service unit | T1543.002 | ❌ (Linux only) |
| 3 | `cron_job_persistence` | New/modified cron job or @reboot entry | T1053.003 | ✅ |
| 4 | `ssh_key_backdoor` | New/modified authorized_keys file | T1098.004 | ✅ |
| 5 | `shell_profile_hijack` | Malicious patterns in shell profiles | T1037.004, T1546.004 | ✅ |
| 6 | `browser_extension_persistence` | Suspicious browser extension installed | T1176 | ✅ |
| 7 | `startup_folder_login_item` | New GUI startup/login items | T1547.001, T1037.001 | ✅ |
| 8 | `hidden_file_persistence` | Hidden executable loaders | T1564, T1053, T1547 | ✅ |

## Anti-Patterns

1. **Do NOT use `PersistenceTelemetry`** — proto type doesn't exist; use `DeviceTelemetry` with `TelemetryEvent` list.
2. **Do NOT use `ALERT` event_type** — use `SECURITY` for change events, `METRIC` for snapshot counters.
3. **Do NOT return empty `[]` when no changes** — emit `persistence_entries` METRIC heartbeat.
4. **Do NOT put MITRE IDs in `tags`** — use `SecurityEvent.mitre_techniques` field.

## Baseline Behavior

- **Auto-create**: If no baseline found on startup, first cycle creates one automatically (`auto_create` mode)
- **Monitor**: Subsequent cycles compare current snapshot against baseline
- **Diff types**: CREATED (new entry), MODIFIED (hash changed), DELETED (entry removed)
- **Update**: Baseline is updated after each change detection cycle

## EOA Baseline Data

| Metric | Value |
|--------|-------|
| Persistence entries per snapshot | ~16 |
| Changes detected | 3 (plist CREATE, plist DELETE, zshrc MODIFY) |
| Probes fired | 2/8 (`persistence_user_launch_agent`, `persistence_shell_profile`) |
| MITRE techniques observed | T1543, T1546.004, T1547 |
| Heartbeat metrics | 12 |
| Security events | 4 |
| Verdict | PASS |

## Dark Spots

- systemd probe is Linux-only (no equivalent on macOS beyond launchd)
- Browser extension probe requires known extension directory paths
- No Gatekeeper/notarization check on plist ProgramArguments binaries
- Hidden file probe may miss deeply nested dot-prefixed executables
- No code signing validation on discovered persistence binaries
