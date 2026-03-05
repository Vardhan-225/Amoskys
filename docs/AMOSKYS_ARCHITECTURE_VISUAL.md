# AMOSKYS Architecture — Complete System Visualization

> **Version:** 0.9.0-beta.1 | **Generated:** 2026-03-05 | **~34,800 LOC across 150+ modules**

---

## 1. HIGH-LEVEL SYSTEM ARCHITECTURE

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│                           AMOSKYS — Neural Security Orchestration                    │
│                                                                                      │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐  │
│  │                         LAYER 1: COLLECTION (Agents)                           │  │
│  │                                                                                 │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐            │  │
│  │  │  proc    │ │  auth    │ │  dns     │ │  flow    │ │  fim     │            │  │
│  │  │  agent   │ │  guard   │ │  agent   │ │  agent   │ │  agent   │            │  │
│  │  │ (10 prb) │ │ (8 prb)  │ │ (9 prb)  │ │ (8 prb)  │ │ (9 prb)  │            │  │
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘            │  │
│  │       │             │            │             │             │                  │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐            │  │
│  │  │peripheral│ │persist   │ │kernel    │ │device    │ │net       │            │  │
│  │  │  agent   │ │  guard   │ │  audit   │ │ discover │ │ scanner  │            │  │
│  │  │ (7 prb)  │ │ (8 prb)  │ │ (8 prb)  │ │ (6 prb)  │ │ (7 prb)  │            │  │
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘            │  │
│  │       │             │            │             │             │                  │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐            │  │
│  │  │ applog   │ │db-activ  │ │http-insp │ │internet  │ │protocol  │            │  │
│  │  │  agent   │ │  agent   │ │  agent   │ │ activity │ │collectors│            │  │
│  │  │ (8 prb)  │ │ (8 prb)  │ │ (8 prb)  │ │ (8 prb)  │ │ (10 prb) │            │  │
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘            │  │
│  │       └─────────────┴────────────┴─────────────┴─────────────┘                 │  │
│  │                              │ TelemetryEvent (protobuf)                       │  │
│  └──────────────────────────────┼──────────────────────────────────────────────────┘  │
│                                 ▼                                                     │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐  │
│  │                     LAYER 2: TRANSPORT (EventBus)                               │  │
│  │                                                                                 │  │
│  │     ┌─────────────────────────────────────────────────────┐                    │  │
│  │     │           gRPC EventBus Server (:50051)             │                    │  │
│  │     │   ┌───────────┐  ┌──────────┐  ┌───────────────┐   │                    │  │
│  │     │   │  mTLS     │  │ Protobuf │  │ Ed25519       │   │                    │  │
│  │     │   │ Encryption│  │ Serde    │  │ Signing       │   │                    │  │
│  │     │   └───────────┘  └──────────┘  └───────────────┘   │                    │  │
│  │     └──────────────────────┬──────────────────────────────┘                    │  │
│  │                            │                                                    │  │
│  │        ┌───────────────────┼───────────────────┐                               │  │
│  │        │ Circuit Breaker   │   Local Queue     │   (Offline Resilience)        │  │
│  │        │ (5 fail/30s)      │   (SQLite WAL)    │                               │  │
│  │        └───────────────────┼───────────────────┘                               │  │
│  └────────────────────────────┼────────────────────────────────────────────────────┘  │
│                               ▼                                                       │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐  │
│  │                      LAYER 3: PROCESSING PIPELINE                               │  │
│  │                                                                                 │  │
│  │  ┌────────────┐   ┌────────────┐   ┌─────────────┐   ┌──────────────────┐     │  │
│  │  │ WAL        │──▶│ Enrichment │──▶│ Scoring     │──▶│ Deduplication    │     │  │
│  │  │ Processor  │   │ Pipeline   │   │ Engine      │   │ (BLAKE2b, 300s) │     │  │
│  │  │ (batch     │   │            │   │             │   │                  │     │  │
│  │  │  2000 evt) │   │ • GeoIP    │   │ • Geometric │   └────────┬─────────┘     │  │
│  │  │            │   │ • ASN      │   │ • Temporal  │            │               │  │
│  │  │ • BLAKE2b  │   │ • ThreatIn │   │ • Behavioral│            ▼               │  │
│  │  │   verify   │   │ • MITRE    │   │             │   ┌──────────────────┐     │  │
│  │  │ • Hash     │   │   mapping  │   │  35%G+25%T  │   │ Telemetry Store  │     │  │
│  │  │   chain    │   │            │   │  +40%B=Final│   │ (SQLite WAL)     │     │  │
│  │  │ • Dead     │   └────────────┘   └─────────────┘   │  13 tables       │     │  │
│  │  │   letter   │                                       │  8 migrations    │     │  │
│  │  └────────────┘                                       └────────┬─────────┘     │  │
│  └────────────────────────────────────────────────────────────────┼────────────────┘  │
│                                                                   ▼                   │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐  │
│  │                    LAYER 4: INTELLIGENCE & CORRELATION                           │  │
│  │                                                                                 │  │
│  │  ┌──────────────────────┐     ┌──────────────────────────────────────────┐     │  │
│  │  │    FUSION ENGINE     │     │              SOMA BRAIN                  │     │  │
│  │  │                      │     │        (Autonomous ML Engine)            │     │  │
│  │  │  • 30-min sliding    │     │                                          │     │  │
│  │  │    window per device │     │  ┌──────────┐  ┌─────────────────────┐  │     │  │
│  │  │  • 7 basic rules     │◀───▶│  │Isolation │  │GradientBoosting     │  │     │  │
│  │  │  • 16+ advanced rules│     │  │Forest    │  │Classifier           │  │     │  │
│  │  │  • Kill chain detect │     │  │(unsuperv)│  │(supervised,hi-trust)│  │     │  │
│  │  │  • Incident cooldown │     │  └──────────┘  └─────────────────────┘  │     │  │
│  │  │                      │     │  ┌──────────┐  ┌─────────────────────┐  │     │  │
│  │  │  Outputs:            │     │  │Event     │  │Auto                 │  │     │  │
│  │  │  • Incidents         │     │  │Embedder  │  │Calibrator           │  │     │  │
│  │  │  • DeviceRiskSnapshot│     │  │(SVD)     │  │(FP detection)       │  │     │  │
│  │  │  • Drift alerts      │     │  └──────────┘  └─────────────────────┘  │     │  │
│  │  └──────────┬───────────┘     │  Training: 30min cycle, 50K events      │     │  │
│  │             │                  └──────────────────────────────────────────┘     │  │
│  │             │                                                                   │  │
│  │  ┌──────────▼───────────┐     ┌──────────────────────────────────────────┐     │  │
│  │  │   AMRDR SYSTEM       │     │            IGRIS                         │     │  │
│  │  │  (Reliability)       │     │  (Supervisory Intelligence)              │     │  │
│  │  │                      │     │                                          │     │  │
│  │  │  • Beta-Binomial     │     │  • Behavioral baselines                 │     │  │
│  │  │    posterior          │     │  • Decision explainability              │     │  │
│  │  │  • ADWIN drift       │     │  • Audit trail generation               │     │  │
│  │  │  • EDDM drift        │     │  • Coherence checking                   │     │  │
│  │  │  • Recalibration     │     │  • State management                     │     │  │
│  │  │    tiers (4 levels)  │     │  • Performance metrics                  │     │  │
│  │  │  • Ground Truth      │     │                                          │     │  │
│  │  │    Oracle            │     └──────────────────────────────────────────┘     │  │
│  │  └──────────────────────┘                                                      │  │
│  └─────────────────────────────────────────────────────────────────────────────────┘  │
│                                          │                                            │
│                                          ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐  │
│  │                     LAYER 5: PRESENTATION & VALIDATION                          │  │
│  │                                                                                 │  │
│  │  ┌────────────────────────┐        ┌──────────────────────────────────────┐    │  │
│  │  │   WEB DASHBOARD        │        │        RED-TEAM FRAMEWORK            │    │  │
│  │  │   (Flask + SocketIO)   │        │                                      │    │  │
│  │  │                        │        │   8 scenario modules                 │    │  │
│  │  │   • Cortex Command     │        │   449 adversarial cases              │    │  │
│  │  │   • SOMA Intelligence  │        │   64 golden fixtures                 │    │  │
│  │  │   • Evidence Chain     │        │                                      │    │  │
│  │  │   • Timeline Replay    │        │   • Harness execution                │    │  │
│  │  │   • Query Builder      │        │   • Timeline stitching               │    │  │
│  │  │   • SOC Live Monitor   │        │   • Reality scoring (L0-L3)          │    │  │
│  │  │   • MITRE Coverage     │        │   • Report builder (JSON/MD/HTML)    │    │  │
│  │  │                        │        │   • Capture & replay                 │    │  │
│  │  └────────────────────────┘        └──────────────────────────────────────┘    │  │
│  └─────────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                       │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐  │
│  │                     LAYER 6: CRYPTOGRAPHIC PROOF SYSTEM                         │  │
│  │                                                                                 │  │
│  │  ┌─────────────┐  ┌────────────────┐  ┌────────────┐  ┌──────────────────┐    │  │
│  │  │ Merkle Tree │  │ Evidence Chain  │  │ WAL        │  │ Checkpoint       │    │  │
│  │  │ (inclusion  │  │ (tamper-proof   │  │ Segments   │  │ Signer           │    │  │
│  │  │  proofs)    │  │  audit trail)   │  │ (ordered   │  │ (Ed25519)        │    │  │
│  │  │             │  │                 │  │  recovery) │  │                  │    │  │
│  │  └─────────────┘  └────────────────┘  └────────────┘  └──────────────────┘    │  │
│  │  ┌─────────────────────┐  ┌────────────────────────┐  ┌──────────────────┐    │  │
│  │  │ prove_inclusion.py  │  │ prove_absence.py       │  │ bundle_exporter  │    │  │
│  │  │ (event ∈ audit log) │  │ (event ∉ audit log)    │  │ (forensic export)│    │  │
│  │  └─────────────────────┘  └────────────────────────┘  └──────────────────┘    │  │
│  └─────────────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. COMPLETE DATA FLOW DIAGRAM

```
                    ┌─────────────────────────────────────────────┐
                    │            HOST / ENDPOINT                   │
                    │                                             │
                    │  psutil  /proc  lsof  logs  syscalls  DNS  │
                    └───────────────────┬─────────────────────────┘
                                        │ raw system data
                                        ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                         AGENT COLLECTION LAYER                            │
│                                                                           │
│  Each agent runs N MicroProbes in a scan loop:                           │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │  Agent.run_forever()                                                │  │
│  │      │                                                              │  │
│  │      ├──▶ MicroProbe.scan(context) ──▶ List[TelemetryEvent]        │  │
│  │      │       • event_type, severity, mitre_techniques               │  │
│  │      │       • confidence (0.0-1.0), timestamp_ns                   │  │
│  │      │       • probe_name, device_id, data dict                     │  │
│  │      │                                                              │  │
│  │      ├──▶ validate_event() ──▶ schema check                        │  │
│  │      ├──▶ enrich_event()  ──▶ add metadata                         │  │
│  │      │                                                              │  │
│  │      └──▶ Protobuf serialize: TelemetryEvent → DeviceTelemetry     │  │
│  │                                → UniversalEnvelope                   │  │
│  └─────────────────────────────────┬───────────────────────────────────┘  │
│                                    │                                      │
│  Contract Validation:              │ Protobuf + Ed25519 signature         │
│  REAL → runs normally              │                                      │
│  DEGRADED → runs w/ quality tag    │                                      │
│  BROKEN → skipped entirely         │                                      │
│  DISABLED → user-disabled          │                                      │
└────────────────────────────────────┼──────────────────────────────────────┘
                                     │
                    ┌────────────────┼────────────────┐
                    │                │                 │
                    ▼                ▼                 ▼
          ┌─────────────┐  ┌──────────────┐  ┌──────────────┐
          │ gRPC EventBus│  │ Local Queue  │  │ Agent        │
          │ (:50051)     │  │ (SQLite WAL) │  │ Heartbeat    │
          │              │  │              │  │ (.json)      │
          │ • mTLS       │  │ Fallback if  │  │              │
          │ • streaming  │  │ EventBus     │  │ → data/      │
          │ • at-least-  │  │ unreachable  │  │   heartbeats/│
          │   once       │  │              │  │              │
          └──────┬───────┘  └──────┬───────┘  └──────────────┘
                 │                 │
                 │   ┌─────────────┘  (drain when EventBus recovers)
                 │   │
                 ▼   ▼
    ┌────────────────────────────────────────────────────────────────┐
    │                    WAL PROCESSOR                                │
    │                                                                │
    │  Batch mode: up to 2000 events per commit                     │
    │                                                                │
    │  ┌──────────────────────────────────────────────────────────┐  │
    │  │  1. Read batch from WAL                                  │  │
    │  │  2. BLAKE2b checksum verification                        │  │
    │  │  3. Hash chain signature verification (A2.2)             │  │
    │  │  4. Parse protobuf envelope                              │  │
    │  │                                                          │  │
    │  │  5. ROUTE by event type:                                 │  │
    │  │     ┌──────────────────────────────────────────────────┐ │  │
    │  │     │ SecurityEvent ──▶ EnrichmentPipeline             │ │  │
    │  │     │    │                                              │ │  │
    │  │     │    ├──▶ GeoIP lookup (geo_src_country)           │ │  │
    │  │     │    ├──▶ ASN lookup (asn_src_org)                 │ │  │
    │  │     │    ├──▶ Threat Intel match (ioc_strong)          │ │  │
    │  │     │    └──▶ MITRE technique mapping                  │ │  │
    │  │     │    │                                              │ │  │
    │  │     │    ▼                                              │ │  │
    │  │     │ ScoringEngine.classify()                         │ │  │
    │  │     │    │                                              │ │  │
    │  │     │    ├── GeometricScorer (0.35 weight)             │ │  │
    │  │     │    │   • external IP: +0.30                      │ │  │
    │  │     │    │   • threat intel: +0.40                     │ │  │
    │  │     │    │   • unusual country: +0.15                  │ │  │
    │  │     │    │   • hosting ASN: +0.15                      │ │  │
    │  │     │    │                                              │ │  │
    │  │     │    ├── TemporalScorer (0.25 weight)              │ │  │
    │  │     │    │   • off-hours: +0.25                        │ │  │
    │  │     │    │   • burst (>5 in 60s): up to +0.40          │ │  │
    │  │     │    │   • first-seen: +0.30                       │ │  │
    │  │     │    │   • high latency: +0.15                     │ │  │
    │  │     │    │                                              │ │  │
    │  │     │    └── BehavioralScorer (0.40 weight)            │ │  │
    │  │     │        • rarity: up to +0.30                     │ │  │
    │  │     │        • high-risk category: +0.25-0.40          │ │  │
    │  │     │        • cross-agent corroboration               │ │  │
    │  │     │        • agent risk score                        │ │  │
    │  │     │                                                   │ │  │
    │  │     │ ──▶ Classification:                              │ │  │
    │  │     │     ≥0.70 MALICIOUS │ ≥0.40 SUSPICIOUS │ <0.40  │ │  │
    │  │     │                        LEGITIMATE                │ │  │
    │  │     │                                                   │ │  │
    │  │     │ ProcessEvent ──▶ process_events table             │ │  │
    │  │     │ FlowEvent    ──▶ flow_events table                │ │  │
    │  │     │ DeviceTelemetry ──▶ device_telemetry table        │ │  │
    │  │     └──────────────────────────────────────────────────┘ │  │
    │  │                                                          │  │
    │  │  6. EventDeduplicator (BLAKE2b fingerprint, 300s TTL)   │  │
    │  │  7. FusionEngine.add_event() (correlation)              │  │
    │  │  8. Batch INSERT into TelemetryStore                    │  │
    │  │  9. Single COMMIT                                       │  │
    │  │ 10. DELETE processed rows from WAL                      │  │
    │  │                                                          │  │
    │  │  On error: → wal_dead_letter table (quarantine)          │  │
    │  └──────────────────────────────────────────────────────────┘  │
    └────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
    ┌────────────────────────────────────────────────────────────────┐
    │                    TELEMETRY STORE                              │
    │                    (SQLite WAL mode)                            │
    │                                                                │
    │  ┌──────────────┐ ┌──────────────┐ ┌──────────────────┐      │
    │  │process_events│ │ flow_events  │ │ security_events  │      │
    │  │              │ │              │ │  (main table)    │      │
    │  │ pid, ppid,   │ │ src/dst IP,  │ │  category,       │      │
    │  │ exe, cmdline │ │ port, proto, │ │  action,         │      │
    │  │ cpu%, mem%,  │ │ bytes_tx/rx  │ │  risk_score,     │      │
    │  │ anomaly_score│ │ is_suspicious│ │  classification, │      │
    │  └──────────────┘ └──────────────┘ │  MITRE, enriched │      │
    │                                     └──────────────────┘      │
    │  ┌──────────────┐ ┌──────────────┐ ┌──────────────────┐      │
    │  │ dns_events   │ │ audit_events │ │persistence_events│      │
    │  │              │ │              │ │                  │      │
    │  │ domain,      │ │ syscall,     │ │ mechanism,       │      │
    │  │ dga_score,   │ │ pid, uid,    │ │ path, command,   │      │
    │  │ beaconing,   │ │ exe, target  │ │ risk_score       │      │
    │  │ tunneling    │ │              │ │                  │      │
    │  └──────────────┘ └──────────────┘ └──────────────────┘      │
    │  ┌──────────────┐ ┌──────────────┐ ┌──────────────────┐      │
    │  │ fim_events   │ │peripheral_ev │ │ incidents        │      │
    │  │              │ │              │ │                  │      │
    │  │ path,        │ │ device_type, │ │ severity,status  │      │
    │  │ change_type, │ │ vendor_id,   │ │ source_event_ids │      │
    │  │ old/new hash │ │ risk_score   │ │ indicators       │      │
    │  └──────────────┘ └──────────────┘ └──────────────────┘      │
    │  ┌──────────────┐ ┌──────────────┐ ┌──────────────────┐      │
    │  │device_telemetry│metrics_series│ │ alert_rules      │      │
    │  │              │ │              │ │                  │      │
    │  │ device_id,   │ │ metric_name, │ │ category,        │      │
    │  │ type, cpu,   │ │ value,       │ │ min_risk_score,  │      │
    │  │ mem, procs   │ │ min/max/avg  │ │ cooldown_seconds │      │
    │  └──────────────┘ └──────────────┘ └──────────────────┘      │
    │  ┌──────────────┐ ┌──────────────┐                           │
    │  │ wal_archive  │ │wal_dead_ltr  │  Retention: 90 days       │
    │  │ (backup)     │ │(quarantine)  │  Cleanup: hourly           │
    │  └──────────────┘ └──────────────┘                           │
    └───────────────────────┬────────────────────────────────────────┘
                            │
               ┌────────────┼────────────┐
               ▼            ▼            ▼
    ┌────────────────┐ ┌──────────┐ ┌──────────────┐
    │ Fusion Engine  │ │ SOMA     │ │ Dashboard    │
    │ (correlation)  │ │ Brain    │ │ (queries)    │
    │                │ │ (trains) │ │              │
    └────────────────┘ └──────────┘ └──────────────┘
```

---

## 3. FUSION ENGINE — CORRELATION & INCIDENT DETECTION

```
              ┌─────────────────────────────────────────┐
              │          TelemetryEventView              │
              │   (normalized from protobuf)             │
              └───────────────────┬─────────────────────┘
                                  │
                                  ▼
              ┌─────────────────────────────────────────┐
              │       FusionEngine.add_event()           │
              │                                         │
              │   Per-device sliding window buffer:     │
              │   ┌─────────────────────────────┐       │
              │   │ deque(maxlen=1000)           │       │
              │   │ 30-minute correlation window │       │
              │   │ + known_ips, incident_count  │       │
              │   └─────────────────────────────┘       │
              └───────────────────┬─────────────────────┘
                                  │
                                  ▼
    ┌─────────────────────────────────────────────────────────────────┐
    │              FusionEngine.evaluate_device()                      │
    │                                                                 │
    │  ┌────────────────────────────────────────────────────────────┐ │
    │  │  BASIC RULES (7 patterns)                                  │ │
    │  │                                                            │ │
    │  │  1. SSH Brute Force     ≥3 fail → success (30min)         │ │
    │  │  2. Persistence Chain   SSH/sudo → LaunchAgent/Cron (10m) │ │
    │  │  3. Suspicious Sudo     rm -rf, /etc/sudoers, kext       │ │
    │  │  4. Multi-Tactic        flow + process + persist (15min)  │ │
    │  │  5. SSH Lateral Move    inbound → outbound SSH (5min)     │ │
    │  │  6. Exfil Spike         >10MB external in 5min            │ │
    │  │  7. Suspicious Proc     shell → /tmp or /var/tmp exec     │ │
    │  └────────────────────────────────────────────────────────────┘ │
    │                                                                 │
    │  ┌────────────────────────────────────────────────────────────┐ │
    │  │  ADVANCED RULES (16+ patterns)                             │ │
    │  │                                                            │ │
    │  │  • APT initial access chain (auth → discovery cmds)       │ │
    │  │  • Fileless attacks (curl|sh, python -c, base64|sh)       │ │
    │  │  • Log tampering (history clearing, audit disable)        │ │
    │  │  • Security tool disable (kill AV, unload kext)           │ │
    │  │  • Credential theft chains                                │ │
    │  │  • Container escapes                                      │ │
    │  │  • DGA malware patterns                                   │ │
    │  │  • DNS tunneling                                          │ │
    │  └────────────────────────────────────────────────────────────┘ │
    │                                                                 │
    │  ┌────────────────────────────────────────────────────────────┐ │
    │  │  KILL CHAIN DETECTION (SequenceScorer)                     │ │
    │  │                                                            │ │
    │  │  If ≥2/3 phases match → CRITICAL/HIGH Incident            │ │
    │  │                                                            │ │
    │  │  Phase 1: Initial Access (T1078, T1110)                   │ │
    │  │       ↓                                                    │ │
    │  │  Phase 2: Execution (T1059, T1204)                        │ │
    │  │       ↓                                                    │ │
    │  │  Phase 3: Persistence (T1543, T1053, T1098)               │ │
    │  └────────────────────────────────────────────────────────────┘ │
    │                                                                 │
    │  ┌────────────────────────────────────────────────────────────┐ │
    │  │  DEVICE RISK SCORING (0-100)                               │ │
    │  │                                                            │ │
    │  │  Base: 10                                                  │ │
    │  │  + Failed SSH × 5 (cap 20)                                │ │
    │  │  + New SSH IP × 15                                        │ │
    │  │  + New SSH keys × 30                                      │ │
    │  │  + /Users LaunchAgent × 25                                │ │
    │  │  + Suspicious sudo × 30                                   │ │
    │  │  + Temporal burst × 15                                    │ │
    │  │  + CRITICAL incidents × 40 × agent_weight                 │ │
    │  │  + HIGH incidents × 20 × agent_weight                     │ │
    │  │  - Decay: -10 per 10min without risky events              │ │
    │  │  → Clamp [0, 100]                                         │ │
    │  │                                                            │ │
    │  │  [0-30] LOW  [31-60] MEDIUM  [61-80] HIGH  [81-100] CRIT │ │
    │  └────────────────────────────────────────────────────────────┘ │
    │                                                                 │
    │  ┌────────────────────────────────────────────────────────────┐ │
    │  │  AMRDR INTEGRATION                                         │ │
    │  │                                                            │ │
    │  │  ReliabilityTracker ──▶ fusion weights per agent           │ │
    │  │       │                                                    │ │
    │  │       ├── NOMINAL: weight = reliability_score              │ │
    │  │       ├── SOFT:    weight = score × 0.85                  │ │
    │  │       ├── HARD:    weight = 0.5 (reset prior)             │ │
    │  │       └── QUARANTINE: weight = 0.0 (excluded)             │ │
    │  │                                                            │ │
    │  │  Drift detection → synthetic AMRDR_DRIFT incidents        │ │
    │  │  Analyst feedback → update Beta-Binomial posterior         │ │
    │  └────────────────────────────────────────────────────────────┘ │
    │                                                                 │
    │         ┌──────────────┐        ┌─────────────────────┐        │
    │         │  Incidents   │        │ DeviceRiskSnapshots  │        │
    │         │ (SQLite DB)  │        │ (SQLite DB)          │        │
    │         └──────────────┘        └─────────────────────┘        │
    └─────────────────────────────────────────────────────────────────┘
```

---

## 4. AGENT MICRO-PROBE ARCHITECTURE

```
┌──────────────────────────────────────────────────────────────────────┐
│                   HARDENED AGENT BASE                                 │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │                    Lifecycle Hooks                              │  │
│  │                                                                │  │
│  │  setup() ──▶ collect_data() ──▶ validate() ──▶ enrich()      │  │
│  │              ──▶ queue_adapter.enqueue() ──▶ EventBus/Local   │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │                    Resilience Patterns                          │  │
│  │                                                                │  │
│  │  Circuit Breaker ──── 5 failures → OPEN (30s cooldown)        │  │
│  │       │                                                        │  │
│  │       ├── CLOSED: normal operation                             │  │
│  │       ├── OPEN: all calls rejected, use local queue            │  │
│  │       └── HALF_OPEN: test single call, recover or re-open     │  │
│  │                                                                │  │
│  │  Local Queue ────── SQLite WAL-backed offline buffer           │  │
│  │  Signal Handling ── SIGTERM/SIGINT → graceful drain            │  │
│  │  Exponential Backoff ── retry with jitter                      │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │              MicroProbeAgentMixin                               │  │
│  │                                                                │  │
│  │  ┌─────────────────────────────────────────────────────────┐   │  │
│  │  │  ProbeRegistry                                          │   │  │
│  │  │                                                         │   │  │
│  │  │  ┌──────────┐  ┌──────────┐  ┌──────────┐             │   │  │
│  │  │  │ Probe A  │  │ Probe B  │  │ Probe C  │  ...        │   │  │
│  │  │  │ T1059    │  │ T1543    │  │ T1110    │             │   │  │
│  │  │  │ REAL     │  │ DEGRADED │  │ REAL     │             │   │  │
│  │  │  └────┬─────┘  └────┬─────┘  └────┬──���──┘             │   │  │
│  │  │       │              │              │                   │   │  │
│  │  │       ▼              ▼              ▼                   │   │  │
│  │  │  scan(ctx) ──▶ [events]  scan(ctx) ──▶ [events]       │   │  │
│  │  │       │              │              │                   │   │  │
│  │  │       └──────────────┴──────────────┘                  │   │  │
│  │  │                      │                                  │   │  │
│  │  │                      ▼                                  │   │  │
│  │  │              aggregated events                          │   │  │
│  │  └─────────────────────────────────────────────────────────┘   │  │
│  │                                                                │  │
│  │  Observability Contract:                                       │  │
│  │  ┌─────────────────────────────────────────────────────────┐   │  │
│  │  │  requires_fields: ["processes", "connections"]          │   │  │
│  │  │  requires_event_types: ["process_event"]                │   │  │
│  │  │  field_semantics: {"processes": "List of psutil procs"} │   │  │
│  │  │  degraded_without: ["enriched_geo"]                     │   │  │
│  │  │                                                         │   │  │
│  │  │  Readiness:                                             │   │  │
│  │  │    all required present  → REAL (full confidence)       │   │  │
│  │  │    degraded_without miss → DEGRADED (reduced conf.)     │   │  │
│  │  │    required field miss   → BROKEN (probe skipped)       │   │  │
│  │  └─────────────────────────────────────────────────────────┘   │  │
│  └────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 5. PLATFORM-SPLIT AGENT HIERARCHY

```
agents/
├── common/                           ◄── Shared base classes
│   ├── base.py                        HardenedAgentBase (1000+ LOC)
│   ├── probes.py                      MicroProbe, MicroProbeAgentMixin
│   ├── queue_adapter.py               LocalQueueAdapter (offline buffer)
│   ├── metrics.py                     AgentMetrics
│   └── cli.py                         agent_main(), run_agent()
│
├── os/                               ◄── Platform-specific implementations
│   ├── __init__.py                    get_arsenal(platform) factory
│   │
│   ├── macos/                        ◄── macOS Observatory (8 agents, 52 probes)
│   │   ├── __init__.py                MacOSArsenal
│   │   ├── process/                   MacOSProcessAgent (10 probes)
│   │   │   ├── agent.py               Process Observatory
│   │   │   ├── collector.py           psutil-based collector
│   │   │   └── probes.py              10 micro-probes
│   │   ├── auth/                      MacOSAuthAgent (6 probes)
│   │   ├── filesystem/                MacOSFileAgent (8 probes)
│   │   ├── network/                   MacOSNetworkAgent (8 probes)
│   │   ├── peripheral/                MacOSPeripheralAgent (4 probes)
│   │   ├── persistence/               MacOSPersistenceAgent (10 probes)
│   │   ├── unified_log/               MacOSUnifiedLogAgent (6 probes)
│   │   └── correlation/               MacOSCorrelationAgent
│   │
│   ├── linux/                        ◄── Linux agents
│   │   ├── __init__.py                LinuxArsenal
│   │   └── kernel_audit/              KernelAuditAgent (8 probes)
│   │
│   └── windows/                      ◄── Windows (stub)
│       └── __init__.py                WindowsArsenal
│
├── proc/                             ◄── Cross-platform agents
│   └── probes.py                      ProcAgent (10 probes)
├── auth/                              AuthGuardAgent (8 probes)
├── dns/                               DNSAgent (9 probes)
├── flow/                              FlowAgent (8 probes)
├── fim/                               FIMAgent (9 probes)
├── peripheral/                        PeripheralAgent (7 probes)
├── persistence/                       PersistenceGuard (8 probes)
├── device_discovery/                  DeviceDiscovery (6 probes)
├── net_scanner/                       NetScannerAgent (7 probes)
├── applog/                            AppLogAgent (8 probes)
├── db_activity/                       DBActivityAgent (8 probes)
├── http_inspector/                    HTTPInspectorAgent (8 probes)
├── internet_activity/                 InternetActivityAgent (8 probes)
├── protocol_collectors/               ProtocolCollectors (10 probes)
│
├── __init__.py                       ◄── AGENT_REGISTRY (central discovery)
├── models.py                          AgentToken, DeployedAgent (ORM)
└── distribution.py                    AgentDistributionService

Total: 23 agent types, ~150 micro-probes
```

---

## 6. SOMA BRAIN — AUTONOMOUS ML ENGINE

```
┌─────────────────────────────────────────────────────────────────────┐
│                        SOMA BRAIN                                    │
│                  (Self-Organizing ML Architecture)                   │
│                                                                     │
│  Training Loop (every 30 minutes, daemon thread):                   │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  1. Query latest 50K events from TelemetryStore              │  │
│  │     (min 200 events required to start)                       │  │
│  │                                                               │  │
│  │  2. Feature Extraction (Guardrail G3: Event-Native First)    │  │
│  │     ┌──────────────────────────────────────────────────────┐  │  │
│  │     │ TEMPORAL:    hour_of_day, day_of_week, business_hrs  │  │  │
│  │     │ PROBE-LOCAL: probe_hour, off_hours, ingestion_lag    │  │  │
│  │     │ ENDPOINT:    burst_score, acceleration, jitter       │  │  │
│  │     │ INTER-EVENT: inter_event_gap_s, rapid_succession     │  │  │
│  │     │ CATEGORICAL: event_category, action, agent (encoded) │  │  │
│  │     │ HEURISTIC:   geometric, temporal, behavioral scores  │  │  │
│  │     └──────���───────────────────────────────────────────────┘  │  │
│  │                                                               │  │
│  │  3. IsolationForest Training (always runs)                   │  │
│  │     • Unsupervised anomaly detection                         │  │
│  │     • Learns normal event distribution                       │  │
│  │                                                               │  │
│  │  4. GradientBoostingClassifier (Guardrail G2)                │  │
│  │     • ONLY if ≥50 high-trust labels available                │  │
│  │     • Label sources:                                         │  │
│  │       - "incident": correlation rule fired                   │  │
│  │       - "ioc_strong": cross-agent consensus / threat intel   │  │
│  │       - "manual": analyst-confirmed ground truth             │  │
│  │                                                               │  │
│  │  5. EventEmbedder (Co-occurrence SVD)                        │  │
│  │     • Learns semantic relationships between events           │  │
│  │     • "brute_force" clusters with "privilege_escalation"     │  │
│  │                                                               │  │
│  │  6. AutoCalibrator (Guardrail G5)                            │  │
│  │     • Max 10 calibrations per cycle                          │  │
│  │     • Min 200 evidence events required                       │  │
│  │     • Detailed audit log for analyst review                  │  │
│  │                                                               │  │
│  │  7. Persist artifacts (models, encoders, history)            │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  Hot-Reload Path:                                                   │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  ModelScorerAdapter                                           │  │
│  │     │                                                         │  │
│  │     ├── available() → checks model files + staleness          │  │
│  │     ├── score(features) → IsolationForest anomaly score       │  │
│  │     └── classify(features) → GBC malicious probability        │  │
│  │     │                                                         │  │
│  │     └──▶ ScoringEngine integration (behavioral dimension)     │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 7. RED-TEAM VALIDATION FRAMEWORK

```
┌─────────────────────────────────────────────────────────────────────┐
│                    RED-TEAM FRAMEWORK                                 │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  SCENARIO REGISTRY (8 modules, 449 cases)                     │  │
│  │                                                               │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌───────────┐ │  │
│  │  │ proc       │ │ auth       │ │ kernel     │ │ credential│ │  │
│  │  │ probes     │ │ probes     │ │ audit      │ │ dump      │ │  │
│  │  │ (80 cases) │ │ (80 cases) │ │ (80 cases) │ │ (8 cases) │ │  │
│  │  └────────────┘ └────────────┘ └────────────┘ └───────────┘ │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌───────────┐ │  │
│  │  │ macOS      │ │ macOS      │ │ macOS      │ │ attacker  │ │  │
│  │  │ observatory│ │ correlation│ │ temporal   │ │ touched   │ │  │
│  │  │ (96 cases) │ │            │ │ corr.      │ │ the box   │ │  │
│  │  └────────────┘ └────────────┘ └────────────┘ └───────────┘ │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                              │                                       │
│                              ▼                                       │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  RED-TEAM HARNESS                                              │  │
│  │                                                               │  │
│  │  For each Scenario:                                           │  │
│  │    For each AdversarialCase:                                  │  │
│  │      ┌─────────────────────────────────────────────────────┐  │  │
│  │      │  1. Create fresh probe (or reuse if stateful)       │  │  │
│  │      │  2. Apply patches (psutil mocks for process data)   │  │  │
│  │      │  3. Build ProbeContext with injected shared_data    │  │  │
│  │      │  4. Execute probe.scan(context)                     │  │  │
│  │      │  5. Validate:                                       │  │  │
│  │      │     • event_count matches expected                  │  │  │
│  │      │     • event_types match (order-independent)         │  │  │
│  │      │     • severity matches                              │  │  │
│  │      │  6. Generate incident_key:                          │  │  │
│  │      │     sha256(techniques + principal + window + target) │  │  │
│  │      └─────────────────────────────────────────────────────┘  │  │
│  │                                                               │  │
│  │  Case categories:                                             │  │
│  │  ┌────────────┐  ┌──────────────┐  ┌────────────────┐       │  │
│  │  │  POSITIVE  │  │   EVASION    │  │    BENIGN      │       │  │
│  │  │ must fire  │  │ documented   │  │ must NOT fire  │       │  │
│  │  │ detection  │  │ gap/blind    │  │ (FP test)      │       │  │
│  │  └────────────┘  └──────────────┘  └────────────────┘       │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                              │                                       │
│              ┌───────────────┼───────────────┐                       │
│              ▼               ▼               ▼                       │
│  ┌────────────────┐ ┌──────────────┐ ┌────────────────┐             │
│  │  Report Builder│ │ Timeline     │ │ Reality Score  │             │
│  │                │ │ Stitcher     │ │                │             │
│  │ • story.json   │ │              │ │ L0: Schema     │             │
│  │ • story.md     │ │ Kill-chain   │ │ L1: Invariants │             │
│  │ • story.html   │ │ phases from  │ │ L2: Noise      │             │
│  │                │ │ multiple     │ │ L3: Coherence  │             │
│  │ Verdict:       │ │ scenarios    │ │                │             │
│  │ ATTACK_CAUGHT  │ │              │ │ Per-case       │             │
│  │ PARTIAL_DETECT │ │ Verdict:     │ │ quality        │             │
│  │ ATTACK_EVADES  │ │ rendered     │ │ assessment     │             │
│  │                │ │ text/json    │ │                │             │
│  └────────────────┘ └──────────────┘ └────────────────┘             │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  CAPTURE & REPLAY                                              │  │
│  │                                                               │  │
│  │  Real telemetry → JSONL capture → Replay through scenario     │  │
│  │  → SIM vs REAL diff table                                     │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  GOLDEN FIXTURES (64 files, 449 cases, 100% pass)             │  │
│  │                                                               │  │
│  │  tests/fixtures/golden/{scenario_name}.json                   │  │
│  │  Exact output matching for regression detection               │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 8. LAUNCHER ORCHESTRATION

```
                        amoskys-launch start
                              │
                              ▼
                    ┌──────────────────┐
                    │  ensure_dirs()   │
                    │                  │
                    │  data/queue      │
                    │  data/intel      │
                    │  data/wal        │
                    │  data/storage    │
                    │  data/heartbeats │
                    │  logs/           │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │  build_env()     │
                    │                  │
                    │  PYTHONPATH      │
                    │  AMOSKYS_HOME    │
                    │  cert paths      │
                    └────────┬─────────┘
                             │
            ┌────────────────┼─────────────────────────┐
            ▼                                          │
   PHASE 1: INFRASTRUCTURE                             │
   ┌──────────────────────────────┐                    │
   │ EventBus Server (:50051)     │                    │
   │ WAL Processor                │                    │
   │                              │                    │
   │ Health check: port polling   │                    │
   │ Wait: up to 30s for ready    │                    │
   └──────────────┬───────────────┘                    │
                  │ ready                               │
                  ▼                                     │
   PHASE 2: AGENTS (parallel launch)                   │
   ┌──────────────────────────────┐                    │
   │  proc ─────────────┐         │                    │
   │  auth ─────────────┤         │                    │
   │  dns ──────────────┤         │                    │
   │  flow ─────────────┤ all run │                    │
   │  fim ──────────────┤ as sub- │                    │
   │  peripheral ───────┤ procs   │                    │
   │  persistence ──────┤         │                    │
   │  kernel_audit ─────┤         │                    │
   │  device_discovery ─┤         │                    │
   │  net_scanner ──────┤         │                    │
   │  applog ───────────┤         │                    │
   │  db_activity ──────┤         │                    │
   │  http_inspector ───┤         │                    │
   │  internet_activity ┤         │                    │
   │  protocol_collect ─┘         │                    │
   │                              │                    │
   │  + macOS Observatory agents  │                    │
   │  (if platform == darwin)     │                    │
   └──────────────┬───────────────┘                    │
                  │                                     │
                  ▼                                     │
   PHASE 3: DASHBOARD (optional)                       │
   ┌──────────────────────────────┐                    │
   │ Flask + SocketIO (:5001)     │◄───────────────────┘
   │                              │
   │ TelemetryBridge → Store      │
   │ Real-time WebSocket updates  │
   └──────────────────────────────┘

   SHUTDOWN (reverse order):
   Dashboard → Agents → WAL Processor → EventBus
   (SIGTERM + graceful drain timeout)
```

---

## 9. AMRDR RELIABILITY SYSTEM

```
┌─────────────────────────────────────────────────────────────────────┐
│           AMRDR (Adaptive Multi-model Risk Drift Reactor)            │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  Ground Truth Oracle                                          │  │
│  │                                                               │  │
│  │  ┌─────────────────────┐   ┌─────────────────────┐          │  │
│  │  │ Cross-Agent         │   │ Manual Feedback      │          │  │
│  │  │ Consensus           │   │ (analyst confirm/    │          │  │
│  │  │                     │   │  dismiss)            │          │  │
│  │  │ ≥2 agents report    │   │                     │          │  │
│  │  │ same event_hash     │   │ Override consensus  │          │  │
│  │  │ → TRUE              │   │                     │          │  │
│  │  └─────────┬───────────┘   └──────────┬──────────┘          │  │
│  │            └──────────────┬────────────┘                     │  │
│  │                           ▼                                   │  │
│  │              ground_truth_match: bool                         │  │
│  └───────────────────────────┬───────────────────────────────────┘  │
│                              │                                       │
│                              ▼                                       │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  Reliability Tracker                                          │  │
│  │                                                               │  │
│  │  Per-Agent State:                                             │  │
│  │  ┌────────────────────────────────────────────────────────┐   │  │
│  │  │  Beta-Binomial Posterior                                │   │  │
│  │  │                                                        │   │  │
│  │  │  α (successes + prior), β (failures + prior)           │   │  │
│  │  │  reliability_score = α / (α + β)  ∈ [0, 1]            │   │  │
│  │  │                                                        │   │  │
│  │  │  Each ground_truth_match:                              │   │  │
│  │  │    TRUE  → α += 1                                      │   │  │
│  │  │    FALSE → β += 1                                      │   │  │
│  │  └────────────────────────────────────────────────────────┘   │  │
│  │                                                               │  │
│  │  ┌────────────────────────────────────────────────────────┐   │  │
│  │  │  Drift Detection                                       │   │  │
│  │  │                                                        │   │  │
│  │  │  ADWIN (Abrupt):                                       │   │  │
│  │  │    Variable-length window, Hoeffding bound              │   │  │
│  │  │    Detects sudden performance drops                     │   │  │
│  │  │                                                        │   │  │
│  │  │  EDDM (Gradual):                                       │   │  │
│  │  │    Distance between consecutive errors                  │   │  │
│  │  │    current < 0.9 × max → DRIFT                         │   │  │
│  │  └────────────────────────────────────────────────────────┘   │  │
│  │                                                               │  │
│  │  ┌────────────────────────────────────────────────────────┐   │  │
│  │  │  Recalibration Tiers                                   │   │  │
│  │  │                                                        │   │  │
│  │  │  NOMINAL ──── No drift detected                        │   │  │
│  │  │    weight = reliability_score (full trust)              │   │  │
│  │  │         │                                              │   │  │
│  │  │         ▼ (EDDM warning)                               │   │  │
│  │  │  SOFT ────── Gradual drift detected                    │   │  │
│  │  │    weight = reliability_score × 0.85                    │   │  │
│  │  │         │                                              │   │  │
│  │  │         ▼ (ADWIN alarm)                                │   │  │
│  │  │  HARD ────── Abrupt drift detected                     │   │  │
│  │  │    α=2, β=2 (weakened prior), weight = 0.5             │   │  │
│  │  │         │                                              │   │  │
│  │  │         ▼ (≥3 consecutive hard)                        │   │  │
│  │  │  QUARANTINE ── Agent excluded                          │   │  │
│  │  │    weight = 0.0 (no contribution to fusion)            │   │  │
│  │  └────────────────────────────────────────────────────────┘   │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                              │                                       │
│                              ▼                                       │
│            Dict[agent_id → fusion_weight]                            │
│                 → FusionEngine incident weighting                    │
│                 → Device risk score scaling                          │
└────��────────────────────────────────────────────────────────────────┘
```

---

## 10. CRYPTOGRAPHIC PROOF SYSTEM

```
┌─────────────────────────────────────────────────────────────────────┐
│                    PROOF SYSTEM (Zero-Trust Audit)                    │
│                                                                     │
│  Event Ingestion:                                                   │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  TelemetryEvent                                               │  │
│  │       │                                                       │  │
│  │       ├──▶ canonical_json(event) → deterministic bytes        │  │
│  │       ├──▶ BLAKE2b(canonical_bytes) → event_hash              │  │
│  │       ├──▶ Ed25519.sign(event_hash) → agent_signature         │  │
│  │       │                                                       │  │
│  │       └──▶ Append to Merkle Tree leaf                         │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  Merkle Tree:                                                       │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                     [ROOT HASH]                                │  │
│  │                    /            \                               │  │
│  │              [H(AB)]            [H(CD)]                        │  │
│  │             /       \          /       \                        │  │
│  │          [H(A)]   [H(B)]   [H(C)]   [H(D)]                   │  │
│  │           │         │        │        │                        │  │
│  │         evt_1     evt_2    evt_3    evt_4                      │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  Evidence Chain:                                                    │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  Segment_1.root ──▶ Segment_2.prev_root ──▶ Segment_3.prev   │  │
│  │       │                     │                     │           │  │
│  │  [checkpoint]          [checkpoint]          [checkpoint]     │  │
│  │  Ed25519 signed        Ed25519 signed        Ed25519 signed  │  │
│  │                                                               │  │
│  │  Hash chain: H(seg_n) = H(seg_n-1.root || seg_n.root)       │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  Proof Operations:                                                  │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  prove_inclusion(event_hash)                                  │  │
│  │    → Merkle proof path from leaf to root                      │  │
│  │    → Verifiable by any third party                            │  │
│  │                                                               │  │
│  │  prove_absence(event_hash)                                    │  │
│  │    → Proof that event was NOT in any segment                  │  │
│  │    → Uses sorted leaf indices + boundary proof                │  │
│  │                                                               │  │
│  │  bundle_export(incident_id)                                   │  │
│  │    → All events + Merkle proofs + chain signatures            │  │
│  │    → Self-contained forensic evidence package                 │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 11. TEST & QUALITY ARCHITECTURE

```
┌─────────────────────────────────────────────────────────────────────┐
│                     TEST PYRAMID                                     │
│                                                                     │
│                        ╱╲                                            │
│                       ╱  ╲      E2E / Pipeline Tests                │
│                      ╱ 4  ╲     (test_e2e_fusion,                   │
│                     ╱      ╲     test_live_agent_fusion)             │
│                    ╱────────╲                                        │
│                   ╱          ╲   Integration Tests                   │
│                  ╱     3      ╲  (test_at_least_once,               │
│                 ╱              ╲  test_wal_to_dashboard)             │
│                ╱────────────────╲                                    │
│               ╱                  ╲  Golden Snapshot Tests            │
│              ╱        2           ╲ (64 fixtures, 449 cases,        │
│             ╱                      ╲ exact output matching)          │
│            ╱────────────────────────╲                                │
│           ╱                          ╲  Unit Tests                   │
│          ╱            1               ╲ (100+ test modules,         │
│         ╱                              ╲ all components)             │
│        ╱────────────────────────────────╲                            │
│                                                                     │
│  Adversarial Testing (separate axis):                               │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  Red-Team Framework   │  Evasion Gauntlet   │  Soak Tests     │ │
│  │  (8 scenario modules) │  (7 evasion types)  │  (stress tests) │ │
│  │  449 adversarial cases│  whitelist, timing,  │  long-running   │ │
│  │                       │  threshold, naming   │  stability      │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  Quality Gates:                                                     │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  pre-commit hooks │ black │ isort │ flake8 │ mypy │ pytest    │ │
│  └────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 12. COMPLETE MODULE DEPENDENCY MAP

```
                              launcher.py
                                  │
                    ┌─────────────┼─────────────┐
                    ▼             ▼              ▼
              ┌──────────┐ ┌──────────┐  ┌────────────┐
              │ EventBus │ │  Agents  │  │ Dashboard  │
              │ (gRPC)   │ │  (all)   │  │ (Flask)    │
              └────┬─────┘ └────┬─────┘  └─────┬──────┘
                   │            │               │
                   │   ┌────────┘               │
                   │   │                        │
                   ▼   ▼                        │
              ┌──────────────┐                  │
              │ WAL Processor│                  │
              └──────┬───────┘                  │
                     │                          │
          ┌──────────┼──────────┐               │
          ▼          ▼          ▼               │
    ┌──────────┐ ┌────────┐ ┌──────┐           │
    │Enrichment│ │Scoring │ │Dedup │           │
    │Pipeline  │ │Engine  │ │      │           │
    └────┬─────┘ └───┬────┘ └──┬───┘           │
         │           │         │               │
         └───────────┼─────────┘               │
                     ▼                          │
              ┌──────────────┐                  │
              │  Telemetry   │◄─────────────────┘
              │  Store       │   (query API)
              └──────┬───────┘
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
    ┌──────────┐ ┌────────┐ ┌──────────┐
    │ Fusion   │ │  SOMA  │ │ IGRIS    │
    │ Engine   │ │  Brain │ │          │
    └────┬─────┘ └────────┘ └──────────┘
         │
         ▼
    ┌──────────┐     ┌──────────────┐
    │  AMRDR   │◄───▶│ Ground Truth │
    │ Tracker  │     │ Oracle       │
    └──────────┘     └──────────────┘
         │
         ▼
    ┌──────────┐
    │ Proof    │
    │ System   │
    └──────────┘

    Cross-cutting:
    ┌──────────────────────────────────────────┐
    │ common/crypto  │ common/logging │ config │
    │ proto/         │ observability  │ auth   │
    └──────────────────────────────────────────┘
```

---

## 13. IDENTIFIED ISSUES & ARCHITECTURAL CONCERNS

### CRITICAL ISSUES

#### C1. Dual Intelligence Subsystem Overlap
```
src/amoskys/intel/          ← FusionEngine, SomaBrain, scoring, rules
src/amoskys/intelligence/   ← score_junction, pcap, fusion, features

Two separate intelligence directories with overlapping concerns.
intel/ is the active one; intelligence/ appears partially abandoned.
```
**Impact:** Confusion about which module to use, potential dead code.
**Recommendation:** Audit `intelligence/` — migrate any unique logic to `intel/`, then remove.

#### C2. Duplicate FIM Agent Implementations
```
src/amoskys/agents/fim/              ← Legacy FIM agent
src/amoskys/agents/file_integrity/   ← Newer FIM agent (?)
src/amoskys/agents/os/macos/filesystem/  ← macOS-specific FIM
```
**Impact:** Three separate file monitoring implementations — which is canonical?
**Recommendation:** Consolidate into single FIM with platform-specific collectors.

#### C3. SQLite Scalability Ceiling
```
All storage is SQLite:
  - telemetry.db (1.8M+ security events)
  - fusion.db (incidents + risk)
  - agent local queues (per-agent .db files)
  - reliability store (agent reliability)
```
**Impact:** Single-writer bottleneck, no horizontal scaling, WAL mode helps concurrency but doesn't solve write contention under high load.
**Recommendation:** Plan migration path to PostgreSQL/TimescaleDB for production deployments exceeding ~5M events/day.

---

### HIGH ISSUES

#### H1. No Agent-to-Agent Communication
```
Agents operate in isolation — no direct inter-agent messaging.
All correlation happens server-side in FusionEngine after events
are persisted. This adds latency to multi-agent detections.
```
**Impact:** Kill-chain detection has 30-min window + batch processing delay.
**Recommendation:** Consider lightweight pub/sub for real-time agent-to-agent signals.

#### H2. SOMA Brain Cold-Start Problem
```
soma_brain.py requires 200 events minimum to start training.
GBC needs ≥50 high-trust labels.
New deployments have zero labeled data.
```
**Impact:** ML models unavailable for hours/days after fresh deployment.
**Recommendation:** Ship pre-trained baseline models or use transfer learning from red-team scenarios.

#### H3. Hardcoded Scoring Weights
```
scoring.py:
  final_score = (0.35 × geometric) + (0.25 × temporal) + (0.40 × behavioral)

fusion_engine.py:
  Various hardcoded thresholds (+5, +15, +25, +30 per event type)
```
**Impact:** No per-deployment tuning without code changes.
**Recommendation:** Move weights to configuration (amoskys.yaml) with sensible defaults.

#### H4. Missing Windows Agent Implementation
```
src/amoskys/agents/os/windows/__init__.py  ← Stub only
```
**Impact:** No Windows endpoint coverage despite directory structure suggesting support.
**Recommendation:** Document as "planned" or remove stub to avoid false expectations.

---

### MEDIUM ISSUES

#### M1. Flow Agent / FlowAgent Naming Confusion
```
src/amoskys/agents/flow/       ← Flow agent
src/amoskys/agents/flowagent/  ← FlowAgent (legacy WAL-based?)
```
**Impact:** Unclear which is canonical; potential event duplication if both run.

#### M2. Enrichment Pipeline Not Pluggable
```
WAL processor hardcodes enrichment steps:
  GeoIP → ASN → ThreatIntel → MITRE mapping

No plugin architecture for custom enrichers.
```
**Impact:** Adding new enrichment sources requires code changes to wal_processor.py.

#### M3. Dashboard Tight Coupling to SQLite
```
web/app/dashboard/telemetry_bridge.py opens SQLite directly.
No abstraction layer or API gateway between dashboard and storage.
```
**Impact:** Dashboard queries compete with WAL processor writes on same DB file.

#### M4. Incomplete Error Handling in Advanced Rules
```
advanced_rules.py uses compiled regex patterns but some rules
silently return empty lists on malformed input rather than
logging warnings.
```
**Impact:** Silent detection failures in edge cases.

#### M5. Test Fixture Drift Risk
```
64 golden fixtures generated from code — no mechanism to detect
when code changes invalidate fixtures without re-running export.
```
**Impact:** Stale fixtures could pass tests while actual behavior has changed.
**Recommendation:** CI step to regenerate fixtures and diff against committed versions.

#### M6. Proto Files Are Pre-Generated
```
src/amoskys/proto/ contains generated _pb2.py files committed to repo.
No .proto source files visible for regeneration.
```
**Impact:** Cannot regenerate protobuf code if schema needs to evolve.
**Recommendation:** Commit .proto source files and add generation to build pipeline.

---

### LOW ISSUES

#### L1. Agent Registry Is Static
```
agents/__init__.py has a hardcoded AGENT_REGISTRY dict.
Adding a new agent requires modifying __init__.py.
```
**Recommendation:** Consider auto-discovery via entry_points or plugin registry.

#### L2. No Rate Limiting on Dashboard Queries
```
Dashboard endpoint handlers query TelemetryStore directly
with user-provided parameters (hours, limit, offset).
```
**Recommendation:** Add query cost limits to prevent expensive full-table scans.

#### L3. Retention Policy Is Fixed
```
telemetry_store.py: 90-day retention, hardcoded.
Dead letters: 30-day retention, hardcoded.
```
**Recommendation:** Make configurable per deployment.

#### L4. Missing Graceful Degradation Documentation
```
Many resilience patterns exist (circuit breaker, local queue,
dead letter) but no runbook for operators on what happens
when each pattern activates.
```
**Recommendation:** Add degradation mode documentation to ops runbook.

---

## 14. SYSTEM STATISTICS SUMMARY

| Metric | Value |
|--------|-------|
| **Total Python Modules** | 150+ |
| **Lines of Code** | ~34,800 |
| **Agent Types** | 23 |
| **Micro-Probes** | ~150 |
| **MITRE Techniques Covered** | 40+ |
| **Correlation Rules** | 23+ (7 basic + 16 advanced) |
| **Red-Team Scenarios** | 8 modules |
| **Adversarial Test Cases** | 449 |
| **Golden Fixtures** | 64 |
| **Database Tables** | 13 (telemetry) + 3 (fusion) + 2 (reliability) |
| **Schema Migrations** | 8 |
| **gRPC Services** | 2 (messaging + telemetry) |
| **Console Entry Points** | 20+ |
| **Documentation Files** | 50+ |
| **Test Files** | 100+ |

---

*This document maps the complete Amoskys architecture as of v0.9.0-beta.1. All diagrams reflect actual code structure, not aspirational design.*
