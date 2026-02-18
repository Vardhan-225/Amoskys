# AuthGuard V2.1 — Evidence Richness Contract

## Overview

The AuthGuard Agent monitors authentication and privilege escalation events
across SSH, sudo, loginwindow, screen lock/unlock, SecurityAgent, and
biometric auth subsystems on macOS (plus `/var/log/auth.log` on Linux).
It produces **METRIC** events for heartbeat/collection status and **SECURITY**
events when probes detect suspicious authentication patterns.

EOA Date: 2026-02-17 | Platform: macOS (Darwin) | Duration: 120s | Verdict: **PASS**

## Required Fields — ALL Events

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `event_id` | string | Unique event identifier | `auth_collection_summary_1771284301564408064` |
| `event_type` | string | `METRIC` or `SECURITY` | `METRIC` |
| `severity` | string | `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | `INFO` |
| `source_component` | string | Agent/probe that generated the event | `auth_collector` |
| `tags` | string[] | Category tags | `["auth", "metric"]` |

## SECURITY Events (Probe-Generated)

| Field | Type | Description |
|-------|------|-------------|
| `security_event.event_category` | string | Probe event type (e.g., `first_time_sudo_user`) |
| `security_event.risk_score` | float | 0.0–1.0 risk score (0.8 for HIGH/CRITICAL, 0.5 otherwise) |
| `security_event.analyst_notes` | string | Probe name and severity |
| `security_event.mitre_techniques` | string[] | MITRE ATT&CK technique IDs |
| `confidence_score` | float | 0.0–1.0 confidence (0.7 for probe events) |
| `attributes` | map | Evidence fields from probe data |

### Attributes Map for SECURITY Events

Varies by probe — typical fields:

| Key | Description | Example |
|-----|-------------|---------|
| `username` | User involved in auth event | `athanneeru` |
| `source_ip` | Source IP of authentication attempt | `192.168.1.50` |
| `sudo_count` | Sudo invocations in window | `1` |
| `denied_count` | Denied sudo attempts | `1` |
| `reasons` | Denial reasons | `['password required (non-interactive)']` |
| `commands` | Commands attempted | `['/bin/ls /tmp']` |
| `failure_count` | Number of failures in window (brute force) | `15` |
| `usernames` | Users targeted (spray probe) | `["admin", "root", "test"]` |
| `distance_km` | Travel distance (geo probe) | `8500` |
| `time_diff_seconds` | Time between logins (geo probe) | `1800` |
| `hour` | Hour of login (off-hours probe) | `3` |
| `locked_account_count` | Accounts locked (lockout probe) | `12` |

## METRIC Events

| Field | Type | Description |
|-------|------|-------------|
| `metric_data.metric_name` | string | Metric name |
| `metric_data.metric_type` | string | `GAUGE` or `COUNTER` |
| `metric_data.numeric_value` | float | Metric value |
| `metric_data.unit` | string | Unit of measurement |

### Metric Names

| Metric | Type | Unit | Description |
|--------|------|------|-------------|
| `auth_events_collected` | GAUGE | events | Auth log entries collected this cycle (heartbeat) |
| `auth_events_collected_total` | COUNTER | events | Lifetime total auth events collected |
| `auth_probe_events` | GAUGE | events | Probe events generated (only when > 0) |

## Auth Event Types (Collector Output)

| Event Type | Source | Status | Description |
|------------|--------|--------|-------------|
| `SUDO_EXEC` | unified log (sudo) | SUCCESS | Successful sudo command execution |
| `SUDO_DENIED` | unified log (sudo) | FAILURE | Denied sudo attempt (password required, not allowed, etc.) |
| `SSH_LOGIN` | unified log (sshd) | SUCCESS/FAILURE | SSH password/publickey authentication |
| `SSH_DISCONNECT` | unified log (sshd) | SUCCESS | SSH connection closed |
| `LOCAL_LOGIN` | unified log (loginwindow) / `last` | SUCCESS | Console login |
| `TERMINAL_SESSION` | `last` | SUCCESS | Terminal session (tty) |
| `SCREEN_LOCK` | unified log (loginwindow/screensaver) | SUCCESS | Screen locked |
| `SCREEN_UNLOCK` | unified log (loginwindow) | SUCCESS | Screen unlocked |
| `AUTH_PROMPT` | unified log (SecurityAgent) | SUCCESS/FAILURE | Authorisation dialog result |
| `BIOMETRIC_AUTH` | unified log (coreauthd) | SUCCESS/FAILURE | Touch ID / biometric evaluation |

## Probe Inventory (8 Probes)

| # | Probe | Fires On | MITRE | macOS Active |
|---|-------|----------|-------|--------------|
| 1 | `ssh_bruteforce` | 5+ SSH failures from single IP/user in 5 min | T1110, T1078 | ✅ (if sshd enabled) |
| 2 | `ssh_password_spray` | 10+ distinct usernames from single IP | T1110.003 | ✅ (if sshd enabled) |
| 3 | `ssh_geo_impossible_travel` | Logins from >1000 km apart in <1 h | T1078 | ✅ (requires GeoIP data) |
| 4 | `sudo_elevation` | First-time sudo, denied attempts, usage spikes | T1548.003 | ✅ **FIRED in EOA** |
| 5 | `sudo_suspicious_command` | Dangerous commands via sudo (shells, wget, chmod 4777) | T1548, T1059, T1547 | ✅ |
| 6 | `off_hours_login` | SSH/local access outside 20:00–06:00 or weekends | T1078 | ✅ |
| 7 | `mfa_bypass_anomaly` | MFA fatigue/bypass attempts | T1621 | ⚠️ (requires MFA integration) |
| 8 | `account_lockout_storm` | 5+ accounts locked in window | T1110, T1499 | ✅ |

## Anti-Patterns

1. **Do NOT access `TelemetryEvent.mitre_techniques`** — field doesn't exist on TelemetryEvent proto.
   MITRE techniques live inside `SecurityEvent.mitre_techniques`.
2. **Do NOT use `ALERT` event_type** — use `SECURITY` for probe events, `METRIC` for counters.
3. **Do NOT use `AlertData` or `alerts`** — these proto types don't exist; use `SecurityEvent` sub-messages.
4. **Do NOT return empty `[]` when no auth events** — emit heartbeat METRIC so the agent proves liveness.
5. **Do NOT use `event.timestamp`** in validation — use `event.timestamp_ns`.
6. **Do NOT access JSON key `process`** in unified log output — the correct key is `processImagePath`.

## macOS Collector Behavior (V2.1)

- **Source 1**: `log show` with broad predicate covering sudo, sshd, loginwindow,
  SecurityAgent, authd, screensaver, coreauthd, plus `com.apple.Authorization`,
  `com.apple.LocalAuthentication`, `com.apple.loginwindow.logging` subsystems
- **Source 2**: `last -10` command for login session history
- **Flags**: `--style json --info` (Info-level entries captured)
- **Window**: `--last 2m` (overlapping with 30 s cycle)
- **Dedup**: `(processID, machTimestamp)` tuple dedup pool (max 10K entries)
- **Sudo format**: Parses actual macOS format `user : reason ; TTY=... ; COMMAND=...`
- **Heartbeat**: Always emits GAUGE + COUNTER metrics, even when 0 events

## EOA Baseline Data (V2.1)

| Metric | Value |
|--------|-------|
| Auth events collected | 7 (2 SUDO_DENIED + 5 LOCAL_LOGIN from `last`) |
| Probes fired | 1/8 (`sudo_elevation` → `first_time_sudo_user` + `sudo_denied_attempt`) |
| SECURITY events | 2 |
| Heartbeat metrics | 23 (2–3 per cycle × 11 cycles) |
| MITRE techniques observed | T1548.003 |
| Verdict | **PASS** |

## Dark Spots

- GeoIP impossible travel requires external IP geolocation database (not bundled)
- MFA bypass probe requires integration with MFA provider (not standalone on macOS)
- SSH probes need Remote Login enabled in System Preferences → Sharing
- `coreauthd` messages are high-volume noise; only `evaluate`+`policy` messages extracted
- `last` command returns historical sessions — may include stale entries
- Screen lock/unlock detection depends on `SACShieldWindowShowing` message format
