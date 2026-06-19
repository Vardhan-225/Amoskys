# AMOSKYS — Deep Architecture Audit
**Date:** 2026-06-17 · **Auditor:** Claude (builder) · **For:** Akash (founder) · **Subject device:** Akash's MacBook Air (`b45045f5e1a0c15e`)

> Ground truth from live code + live `fleet.db` (ops `18.223.110.15`) + live agent (`/var/lib/amoskys`, `/Library/Amoskys`). This is the baseline we build from. AMOSKYS = a network/endpoint **observability organism** with an autonomous brain (IGRIS).

---

## 0. Executive verdict

**The eyes are excellent. The judgment is not — yet.** AMOSKYS collects rich, cryptographically-signed, MITRE-mapped telemetry across 13 endpoint agents and even watches its own health. But the layers that turn observation into *conclusions* — risk scoring and incident fusion — are uncalibrated and self-amplifying. **Depend on what AMOSKYS observes; do not yet depend on what it concludes.**

| Layer | State | One-line |
|---|---|---|
| Collection (13 agents) | 🟢 strong | Tiered, rich, real telemetry |
| Queue + signing | 🟢 strong | Ed25519 hash chain at source (`sig` 89/89) |
| Analyzer (enrich/detect/score) | 🟠 bottleneck | Single-threaded, 14–40 events/cycle — can't keep up |
| Local store (`telemetry.db`) | 🔴 fragile | No retention → grew to **27 GB** → corrupted → outage |
| Shipper → ops | 🟢 works | Batch, cursor-based, AMOSKYS_SERVER configured |
| Fleet store (`fleet.db`) | 🟠 unsigned | **No integrity-at-rest** — sig stripped on landing |
| Enrichment | 🟡 partial | Geo 55%, ASN 61%, **threat-intel now armed (1155)** |
| Scoring / risk | 🔴 uncalibrated | **99.96%** of high-risk events are self-classed "legitimate" |
| Fusion / incidents | 🔴 feedback loop | **9,028** self-referential "critical" incidents |
| IGRIS self-observation | 🟢 strong | Correctly caught the live pipeline outage |

---

## 1. The agent fleet — tiered activation model

AMOSKYS does **not** run all agents always. It uses a 3-tier model (smart resource design):

### TIER 1 · CORE — always running (8)
| Agent | Probes | collection_agent | Live queue | Lands in fleet? |
|---|---|---|---|---|
| Process | 10 | `macos_process` | 53 MB | ✅ `process_events` 14.6k |
| AuthGuard | 6 | `macos_auth` | 58 MB | ✅ `audit_events` 2.9k |
| **Persistence Guard** | 10 | `macos_persistence` | **52 MB** | ❌ **`persistence_events` = 0 (BROKEN)** |
| File Integrity (FIM) | 8 | `macos_filesystem` | 52 MB | ✅ `fim_events` 3.6k |
| Network (Flow) | 18 | `macos_network` | 53 MB | ✅ `flow_events` 500k (ring-capped) |
| Peripheral | 4 | `macos_peripheral` | ~0 | ✅ `peripheral_events` 1.6k (low-volume) |
| Unified Log | 10 | `macos_unified_log` | **none found** | ⚠️ no queue — verify running |
| Correlation | 18 | (cross-agent) | n/a | feeds kill-chain |

### TIER 2 · SPECIALIST — activated on threat context (5)
| Agent | Probes | Live queue | Note |
|---|---|---|---|
| DNS Observatory | 8 | 20 MB | active (DGA/beacon/tunnel) → `dns_events` 68k |
| Discovery | 6 | 3 MB | active (ARP/Bonjour/topology) |
| Provenance | 8 | 10 MB | active → feeds `observation_events` |
| InfostealerGuard | 10 | 0 | idle (no credential-access trigger) — **by design** |
| QuarantineGuard | 8 | 0 | idle (no gatekeeper/dmg trigger) — **by design** |

### TIER 3 · SITUATIONAL — server-only, correctly idle on a laptop (3)
HTTP Inspector (18), AppLog (7), DB Activity (8) — `requires: web_server/database_server`.

### Plus: `realtime_sensor` — **56 MB queue, the single biggest producer**
High-frequency (2 s) process/system sensor feeding `observation_events` (200k, ring-capped). Not in the tier list; effectively the firehose.

**Takeaway:** ~11 of 13 endpoint agents are actively producing. "Zero" queues for InfostealerGuard/QuarantineGuard are **correct** (threat-gated). Two real gaps: **Persistence doesn't land**, and **Unified Log has no queue**.

---

## 2. End-to-end data flow (the 9 layers)

```
[1] AGENT (probe.scan) → TelemetryEvent dict
        │  e.g. macos_dns sees query to cloud-images.ubuntu.com
[2] LocalQueueAdapter → DeviceTelemetry protobuf
        │  Ed25519 SIGN: content_hash → sig, prev_sig (HASH CHAIN)   🟢 SIGNED HERE
[3] LocalQueue (per-agent SQLite WAL, ≤50 MB, FIFO, idempotent)
        │  drain_signed()  ← backlog 365 MB during outage
[4] ANALYZER main loop (single thread, ~2 s target / 9–146 s under load)  🟠 BOTTLENECK
        │  drain → enrich → detect → score → correlate → store
        ├─[5] EnrichmentPipeline: GeoIP→ASN→ThreatIntel→MITRE
        ├─[6] Detection: 166 probes + 56 Sigma rules → security_events
        ├─[7] Scoring: Geometric+Temporal+Behavioral + SOMA + ProbeCalibration  🔴 UNCALIBRATED
        └─[8] Correlation: KillChainTracker (7-stage) + FusionEngine
[9] TelemetryStore (telemetry.db, 24-table schema)  🔴 NO RETENTION → 27 GB bomb
        │  insert_*_event() — 12 insert methods
[10] Shipper (batch 200, cursor) → POST https://18.223.110.15  🟢
        │  SIGNATURE NOT FORWARDED TO REST
[11] OPS command_center.py → fleet.db (12 tables)  🟠 STORED UNSIGNED
        │
[12] IGRIS BRAIN (ops): metrics → thresholds → fleet_incidents  🔴 FEEDBACK LOOP
```

---

## 3. Cryptographic signing audit

| Boundary | Signed? | Evidence |
|---|---|---|
| Agent → Queue | ✅ **YES** | `sig` 89/89, `prev_sig` 87/89, `content_hash` 89/89 (Ed25519 + hash chain) |
| Queue → Shipper | ✅ verified | `drain_signed()` validates chain before send |
| Shipper → Ops REST | ⚠️ TLS only | payload signature not carried into the REST body |
| Ops → fleet.db (at rest) | ❌ **NO** | **every fleet table has no `sig`/`content_hash` column** |

**Finding:** provenance is cryptographically strong *in transit from the source*, but **destroyed at rest**. A compromised ops DB (or a bad row injected server-side) is undetectable. For a security product whose value is trustworthy evidence, **integrity-at-rest is a must-fix**. Cheapest path: carry `content_hash`+`sig` into fleet tables and add a periodic chain-verify job (an `amoskys_doctor` probe).

---

## 4. What is genuinely STRONG (build on these)

1. **Real, attributed telemetry** — 783k raw events, correct macOS semantics, one device, zero dedup collisions.
2. **Ed25519 hash-chain at source** — tamper-evident provenance from the moment of capture. Rare and valuable.
3. **Tiered agent model** — CORE/SPECIALIST/SITUATIONAL = right data at the right cost.
4. **MITRE mapping is correct** — T1071/T1059/T1218/T1048/T1567 map to the right behaviors.
5. **SOMA behavioral memory** — graduates repeated-benign to normal ("persistence graduated, risk 0.000").
6. **IGRIS self-observation** — caught the real pipeline outage ("No telemetry in 949s"). The organism notices its own blindness.
7. **Threat-intel now armed** — 1155 indicators, FP-guarded, daily self-update (fixed 2026-06-17).
8. **The control plane (`amoskys_doctor`)** — one signal verdict + autonomous self-heal (built 2026-06-17).

---

## 5. What is BROKEN (ranked by impact)

| # | Problem | Evidence | Blast radius |
|---|---|---|---|
| B1 | **Risk uncalibrated** | 99.96% of risk≥0.6 events self-classed "legitimate"; `risk_score` ≠ `final_classification` | Brain's verdicts untrustworthy |
| B2 | **Incident feedback loop** | 9,028 "critical" incidents = brain counting its own incidents (diagnosed Apr in `NOISE_AUDIT.md`, never fixed) | Incident view useless |
| B3 | **Local store no retention** | `telemetry.db` → 27 GB → corrupt → full pipeline outage | Total data-flow stall |
| B4 | **No integrity-at-rest** | fleet tables unsigned | Evidence non-trustworthy |
| B5 | **Persistence doesn't land** | 52 MB queue, `insert_persistence_event` exists+called, fleet=0 | Persistence detection blind |
| B6 | **Analyzer throughput** | 14–40 events/cycle single-thread → 365 MB backlog | Caps device + scale |
| B7 | **Detectors lack context** | "C2 beacon" fires on Apple/Google/GitHub; "DNS beacon" on app telemetry | False-positive flood |

---

## 6. Bottlenecks & break-points (where the architecture can snap)

- **Analyzer = single point of throughput.** One thread does enrich+detect+score+correlate per event. At 14–40 ev/cycle it cannot match the realtime_sensor firehose → permanent backlog → store/queue growth. **This is the scaling ceiling.**
- **`telemetry.db` unbounded growth.** Root of the 27 GB incident. `amoskys_doctor` now trips at 15 GB and rebuilds (safety net), but local retention must actually prune.
- **Single ops node** (`t3.small`, 2 GB RAM, `fleet.db` 352 MB growing). One DB, one box — no HA, the scaling/availability limit for fleet growth.
- **Ring-buffer retention** (`flow` 500k≈4 d, `observation` 200k≈26 h) — limits historical baselining for the highest-volume streams.
- **IGRIS brain feedback loop** — generates incidents faster than real detections (21k > 6.8k detections).

---

## 7. Requirements — risk calibration (make the brain's risk trustworthy)

Goal: `risk_score` should agree with reality, and high-risk should be rare and meaningful.

1. **Close the risk↔classification gap.** Today an event can be risk 0.9998 *and* `final_classification=legitimate`. The classifier's verdict must gate/scale the emitted `risk_score` (a "legitimate" verdict caps risk low).
2. **Context allow-listing in detectors.** "C2 beacon"/"DNS beacon" must exclude known-good destinations (Apple, Google, GitHub, Cloudflare, app-telemetry hosts) and known-benign periodicity — same FP-guard pattern we built for threat-intel URLhaus.
3. **Activate AMRDR / probe reliability.** `probe_calibration.py` (Beta-Binomial) exists but all weights are effectively 1.0 — a noisy probe is indistinguishable from a credible one. Feed `final_classification` outcomes back as labels to down-weight chronic false-positive probes (e.g. `macos_dns_beaconing`).
4. **Per-probe precision baseline.** Track each probe's confirmed-TP / total over time; surface "this probe is 0.04% precision" so we deprioritize, not delete.

## 7b. Requirements — kill the incident feedback loop (already diagnosed)

From `src/amoskys/igris/NOISE_AUDIT.md` (Apr 2026, never applied — now proven correct at 9,028):
- **Fix 1 (≈1 h, highest impact):** exclude self-generated `THRESHOLD_INCIDENTS.CRITICAL` incidents from the `incidents.critical` metric. Stops the brain measuring its own output.
- **Fix 2:** auto-resolve threshold incidents when the condition clears (e.g. device back online).
- **Fix 3:** exponential backoff on repeat suppression (600 s → 24 h).
- **Fix 4:** content-hash dedup keys so distinct problems don't collapse / identical ones don't multiply.
- Lives in the **ops-side** brain (`igris/supervisor.py`, `signals.py`) → deploy to `18.223.110.15`.

---

## 8. Build roadmap (priority order for the 2-man team)

1. **Kill incident feedback loop — Fix 1** (≈1 h, ops). Instantly makes the incident view real.
2. **Local store retention** (B3) — make analyzer prune `telemetry.db`; remove the disk-bomb root cause.
3. **Risk calibration v1** (B1/B7) — classification gates risk + detector context allow-lists. The big one for trustworthiness.
4. **Persistence drain fix** (B5) — trace snapshot-dedup swallow; restore persistence visibility.
5. **Integrity-at-rest** (B4) — carry `sig`/`content_hash` into fleet, add chain-verify doctor probe.
6. **Analyzer throughput** (B6) — batch enrichment / parallelize scoring; the scaling unlock.
7. **AMRDR reliability weights** (calibration deepening) — per-probe precision feedback.

> Each item is independently shippable and verifiable against this same live data. The control plane (`amoskys_doctor`) is the instrument we verify with.

---
*Companion artifacts: `tools/amoskys_doctor.py` (control plane), `scripts/threat_intel_autoupdate.py` (armed feed), `src/amoskys/igris/NOISE_AUDIT.md` (incident-loop fix plan).*
