# AMOSKYS Core Platform — Verified Issue Register (2026-06-23)

Scope: the core network/endpoint security platform. **Excludes** WordPress / Argos / kali / lab_hunt.
Method: live inspection of prod (presentation `3.147.175.238`, ops `18.223.110.15`, `fleet.db`) + a 6-dimension
multi-agent code audit (38 raw findings) whose verify pass was cut short by a session limit and **completed manually**.
Every CRITICAL/HIGH below was confirmed against live data or `file:line` code.

---

## THE ROOT CAUSE — the brain is unplugged in production

**`web/app/__init__.py:220`** — `is_fleet_mode = bool(os.environ.get("AMOSKYS_OPS_SERVER"))`.
The `ScoringEngine`, `SOMA`, Agent Mesh, and **IGRIS Orchestrator** are all started inside `if not is_fleet_mode`
(lines 228–304). Both prod servers run **with** `AMOSKYS_OPS_SERVER` set → that whole block is skipped.
Ops `systemctl` has only `amoskys-ops` + `amoskys-mcp` — **no `amoskys-analyzer` unit exists**.

Consequence: the server-side intelligence layer (calibrated scoring, baseline learning, threat-intel enrichment,
fusion, autonomous orchestration) **never runs against fleet data**. `fleet.db` stores exactly what each agent ships.
This single fact produces issues #1–#4 and #7 below. *(The lighter MCP "Cloud Brain" incident loop DOES run under
`amoskys-mcp` — so incident dedup works, but scoring/enrichment/correlation/autonomy do not.)*

---

## CRITICAL — mission-breaking

| # | Issue | Evidence | Fix |
|---|-------|----------|-----|
| 1 | **Server-side scoring/SOMA/enrichment never runs.** Calibrated `composite_score` (`scoring.py:1203`) is real but unreached; stored `risk_score` is the raw probe confidence. | `web/app/__init__.py:228-304`; no `amoskys-analyzer` systemd unit; ops runs only ops+mcp | Run `python -m amoskys.analyzer_main` as a systemd service on ops **or** consciously move scoring to agents and own it there. Decide where the brain lives. |
| 2 | **Over-attribution — no discrimination.** 100% of 3,332 events (24h) have `risk_score>0` AND MITRE tags; `max risk = 1.0`. When everything is a threat, nothing is. | live `fleet.db` query | Gate MITRE tagging + risk on detection quality; give scoring a discriminating floor/threshold (downstream of #1). |
| 3 | **Threat-intel is dark.** `threat_intel_match = 0` fleet-wide over 24h. Enricher reports "available" and writes `False` (fails open on empty/CWD-relative indicator DB). | live query; `enrichment/threat_intel.py` | Loud-on-empty (refuse to fail silently), pin indicator DB to an absolute path, confirm matches land in `fleet.db`. |
| 4 | **Autonomous defense never runs in prod.** Full IGRIS orchestrator+supervisor gated behind `not is_fleet_mode` (always false on fleet nodes). | `web/app/__init__.py:298`; `launcher` fleet-mode skip | Run the orchestrator on ops (own service), or stop describing fleet nodes as "autonomous" until it does. |

---

## HIGH

| # | Issue | Evidence | Fix |
|---|-------|----------|-----|
| 5 | **Dead SOC "signals" feed.** `web/app/websocket.py` polls `get_signals()` → `SELECT … FROM signals` every ~5s; presentation DB has no `signals` table → 123 errors / 2 days + empty feed. | `websocket.py:99`, `storage/_ts_signals.py`; live log | Create/sync the `signals` table into the presentation cache, or remove the feed until the brain persists signals to a synced table. |
| 6 | **Incident UI structurally empty.** Two divergent tables: `incidents` (presentation/TelemetryStore) vs `fleet_incidents` (ops + `mcp/brain.py`); never reconciled. Code also reads `incident.device_id` which `incidents` lacks. | `fleet.db` has only `fleet_incidents`; `_ts_signals.py`, `mcp/brain.py` | Pick one canonical incident table, migrate, and point dashboard/NEXUS/IGRIS at it. |
| 7 | **Persistence detection dead in fleet.** `persistence_events = 0` though the macOS persistence agent is deployed and the shipper includes the table (snapshot/dedup swallow suspected). | live query | Trace persistence collection→queue→ship→store; fix the dedup/snapshot gate that drops every row. |
| 8 | **Silent failure — failures are invisible.** 0 ERROR / 0 WARNING in 22,716 ops log lines / 2 days. `command_center.receive_telemetry` swallows per-event INSERT failures at DEBUG. | live log; `command_center.py` receive path | Log real failures at ERROR; add a pipeline-health counter (events in vs stored vs scored). A clean log must mean healthy, not silent. |
| 9 | **Closed-loop response unverified / partly uncoded.** Brain queues `RESTART_AGENT/COLLECT_NOW/BLOCK_IP` into `device_commands`, but no agent is confirmed to consume them; kill/isolate is never coded; `BLOCK_IP` is structurally moot with 1 online device. | `mcp/brain.py`; `device_commands` poll-only (no enqueue endpoint) | Verify agent command consumption end-to-end; implement isolate/kill or gate the affordance honestly (matches the disabled "Isolate" button in the new device UI). |

---

## MEDIUM

| # | Issue | Evidence | Fix |
|---|-------|----------|-----|
| 10 | TLS cert verification disabled on all fleet uploads + ops proxy (`verify=False`). Signing chain IS validated in `wal_processor.py:190-249`, so "signing is theater" is overstated — but transport trust is weak. | `shipper.py`, `routes_command_center.py:40` | Use the Cloudflare/self-signed cert properly; re-enable verification with a pinned CA. |
| 11 | `command_center` trusts agent-supplied `risk_score/mitre/threat_intel_match` with no server-side validation/bounds. | `receive_telemetry` | Validate/bound on ingest (defense-in-depth; also enables #1 server-side override). |
| 12 | Analyzer drains all per-agent queues single-threaded every 2s — throughput ceiling + head-of-line stall (when it runs). | `analyzer_main.py` | Parallelize per-agent drains once the analyzer is actually running. |
| 13 | `process_genealogy` grows unbounded (~2.7M rows); retention prunes other tables but not this. | retention code | Add retention for `process_genealogy`. |
| 14 | Device-detail telemetry capped at 200 events → "Events (24h)" + posture under-report on busy devices (the new redesign inherits this). | `command_center.py:909` `LIMIT 200` | Aggregate counts separately from the 200-row detail sample. |
| 15 | NEXUS verdict-funnel "incidents" stage + IGRIS "fusion incidents" hardcode/return 0 (query missing `incidents`/`fusion.db`). | `routes_nexus.py`, `routes_igris.py` | Point at the canonical incident table (see #6). |
| 16 | Custom `NotImplementedError(AmoskysError)` shadows the builtin — latent footgun (would turn ABC/guard raises into `TypeError`). | `common/exceptions.py:565` | Rename to `AmoskysNotImplemented`. |

---

## LOW

| # | Issue | Evidence |
|---|-------|----------|
| 17 | Overview leaks a DB connection when both `fleet.db` and `fleet_cache.db` exist. | `routes_overview.py` |
| 18 | IGRIS sub-agents (ThreatHunter/IncidentAnalyst/PatternScout) only run via LLM tool call; PatternScout's "runs without being asked" docstring is unfulfilled. | `igris/sub_agents.py` |
| 19 | Linux/Windows agents unimplemented (`NotImplementedError` guards + `launcher.py:175` TODO). Known/intentional (macOS-first) — the ceiling on "network organism" reach. | `agents/os/linux,windows` |

---

## Recommended fix order (mission-first)

1. **Plug the brain in (#1, #4).** Decide: run `analyzer_main` + orchestrator as ops services, or own scoring on agents. Nothing else in detection matters until this is settled.
2. **Threat-intel loud-on-empty + correct path (#3)** — fastest single mission win.
3. **Give scoring a discriminating floor (#2)** — gate MITRE/risk on detection quality.
4. **Reconcile schema (#5, #6)** — one incident table; create/sync or retire the signals feed.
5. **Make failures visible (#8)** — stop swallowing; add pipeline-health metrics.
6. **Close or gate the response loop (#9).**
7. **Cleanups (#10–#19).**

> One-line summary: **AMOSKYS sees everything and judges nothing — because in production the judgment layer is gated off and unscheduled.** The eyes are excellent; reconnect the brain.
