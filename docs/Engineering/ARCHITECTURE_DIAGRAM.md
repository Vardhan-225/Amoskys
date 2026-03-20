# AMOSKYS Architecture — As Built (March 2026)

*Traced from source code, not aspirational.*

---

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    python -m amoskys start                              │
│                                                                         │
│  Spawns 3 OS processes:                                                │
│    1. python -m amoskys.collector_main  (Tier 1)                       │
│    2. python -m amoskys.analyzer_main   (Tier 2)                       │
│    3. python -m web.app                 (Tier 3 — Dashboard)           │
│                                                                         │
│  PID files: data/pids/{collector,analyzer,dashboard}.pid               │
│  Logs:      logs/{collector,analyzer,dashboard}.{log,err.log}          │
└─────────────────────────────────────────────────────────────────────────┘

Alternative production entry:
  python -m amoskys.watchdog  →  fork() collector  +  fork() analyzer
  (LaunchDaemon: etc/com.amoskys.watchdog.plist, auto-restart, RSS/CPU limits)
```

---

## Tier 1 — Collector Process

```
┌────────────────────────────────────────────────────────────────────────────────┐
│  COLLECTOR PROCESS (amoskys.collector_main)                                    │
│  Budget: 100MB RSS, 15% CPU sustained                                         │
│                                                                                │
│  ┌──────────────────────────────────────────────────────────────────────────┐  │
│  │  REAL-TIME SENSOR (MacOSRealtimeSensorAgent, 2s cycle, 14 probes)       │  │
│  │                                                                          │  │
│  │  4 Event Sources (RealtimeSensorCollector):                              │  │
│  │  ┌─────────────────┐ ┌─────────────────┐ ┌──────────────────────────┐   │  │
│  │  │ FSEventsCollector│ │ ProcessLifecycle│ │ UnifiedLogStreamCollector│   │  │
│  │  │ (watchdog lib)   │ │ Collector       │ │ (log stream --ndjson)    │   │  │
│  │  │                  │ │ (kqueue PROC)   │ │                          │   │  │
│  │  │ 17 watched paths:│ │                 │ │ 23 subsystem predicates: │   │  │
│  │  │ ~/LaunchAgents   │ │ NOTE_EXIT on    │ │ runningboard, XProtect,  │   │  │
│  │  │ /Library/Launch* │ │ up to 500 PIDs  │ │ AMFI, networkd, alf,     │   │  │
│  │  │ ~/.ssh           │ │                 │ │ diskarbitration, usb,     │   │  │
│  │  │ ~/Downloads      │ │ Refreshes PID   │ │ TCC, securityd, authd,   │   │  │
│  │  │ ~/Documents      │ │ list every 10s  │ │ opendirectoryd, xpc,     │   │  │
│  │  │ ~/Desktop        │ │                 │ │ mDNSResponder, sshd,     │   │  │
│  │  │ /tmp, /var/tmp   │ │ Output:         │ │ sudo, loginwindow,       │   │  │
│  │  │ /etc             │ │ RealTimeEvent   │ │ syspolicyd, installer    │   │  │
│  │  │ /Applications    │ │ source="kqueue" │ │                          │   │  │
│  │  │ /usr/local/bin   │ │ process_exit    │ │ 35 event types:          │   │  │
│  │  │ ...              │ │                 │ │ app_launched/terminated,  │   │  │
│  │  │                  │ │                 │ │ ssh_login_success/fail,   │   │  │
│  │  │ Output:          │ │                 │ │ xprotect_malware_blocked,│   │  │
│  │  │ RealTimeEvent    │ │                 │ │ amfi_code_signing_denied,│   │  │
│  │  │ source="fsevents"│ │                 │ │ firewall_blocked,        │   │  │
│  │  │ file_created/    │ │                 │ │ disk_mounted, dns_query,  │   │  │
│  │  │ modified/deleted │ │                 │ │ tcc_permission_granted,  │   │  │
│  │  │                  │ │                 │ │ gatekeeper_blocked, ...   │   │  │
│  │  └─────────────────┘ └─────────────────┘ └──────────────────────────┘   │  │
│  │                                                                          │  │
│  │  ┌────────────────────┐    PID→bundle_id mapping                        │  │
│  │  │ CriticalFileWatcher│    (from runningboard log events)               │  │
│  │  │ (kqueue VNODE)     │    e.g. 3238: com.anthropic.claudefordesktop    │  │
│  │  │                    │         1087: com.microsoft.VSCode              │  │
│  │  │ 10 critical files: │          868: com.apple.Finder                  │  │
│  │  │ /etc/sudoers       │                                                  │  │
│  │  │ /etc/hosts         │    14 Probes:                                    │  │
│  │  │ authorized_keys    │    ┌────────────────────────────────────────┐    │  │
│  │  │ ~/.zshrc           │    │ PersistenceDropProbe    (fsevents)     │    │  │
│  │  │ /etc/pam.d/sudo    │    │ TempExecutionProbe      (fsevents)     │    │  │
│  │  │ sshd_config        │    │ QuarantineBypassProbe   (fsevents)     │    │  │
│  │  │ ...                │    │ ShortLivedProcessProbe  (kqueue)       │    │  │
│  │  │                    │    │ CriticalFileProbe       (kqueue_vnode)  │    │  │
│  │  │ Output:            │    │ LogDestructionProbe     (log+fsevents)  │    │  │
│  │  │ RealTimeEvent      │    │ TCCPermissionProbe      (logstream)     │    │  │
│  │  │ source=            │    │ XProtectMalwareProbe    (logstream)     │    │  │
│  │  │ "kqueue_vnode"     │    │ AMFICodeSigningProbe    (logstream)     │    │  │
│  │  │ critical_file_     │    │ FirewallProbe           (logstream)     │    │  │
│  │  │ modified           │    │ SSHRealtimeProbe        (logstream)     │    │  │
│  │  └────────────────────┘    │ DiskMountProbe          (logstream)     │    │  │
│  │                            │ GatekeeperRealtimeProbe (logstream)     │    │  │
│  │                            │ AppLifecycleProbe       (logstream)     │    │  │
│  │                            └────────────────────────────────────────┘    │  │
│  │                                        │                                 │  │
│  │              RealTimeEvent → probe.scan() → TelemetryEvent              │  │
│  │                                        │                                 │  │
│  │              DeviceTelemetry protobuf ← collect_data()                  │  │
│  │                                        │                                 │  │
│  │              LocalQueueAdapter.enqueue()                                │  │
│  │                SHA-256 hash + Ed25519 sign                              │  │
│  │                        ↓                                                 │  │
│  │              data/queue/realtime_sensor.db  [SQLite WAL]                │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
│                                                                                │
│  ┌──────────────────────────────────────────────────────────────────────────┐  │
│  │  17 SNAPSHOT AGENTS (each as AgentThread, daemon=True)                   │  │
│  │                                                                          │  │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐   │  │
│  │  │ ProcessAgent │ │ NetworkAgent │ │  AuthAgent   │ │PersistenceAgt│   │  │
│  │  │ 13 probes    │ │ 9 probes     │ │  9 probes    │ │ 10 probes    │   │  │
│  │  │ psutil 10s   │ │ lsof+nettop  │ │  log show    │ │ fs walk 60s  │   │  │
│  │  │              │ │ 10s          │ │  30s         │ │              │   │  │
│  │  └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ └──────┬───────┘   │  │
│  │         │                │                │                │            │  │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐   │  │
│  │  │  FIMAgent    │ │PeripheralAgt│ │  DNSAgent    │ │InfostealerGd │   │  │
│  │  │ 8 probes     │ │ 4 probes     │ │  8 probes    │ │ 11 probes    │   │  │
│  │  │ os.walk 60s  │ │ sys_profiler │ │  log show    │ │ lsof+D 30s   │   │  │
│  │  │              │ │ 60s          │ │  30s         │ │              │   │  │
│  │  └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ └──────┬───────┘   │  │
│  │         │                │                │                │            │  │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐   │  │
│  │  │QuarantineGd  │ │ProvenanceAgt│ │ DiscoveryAgt │ │AppLogAgent   │   │  │
│  │  │ 8 probes     │ │ 8 probes     │ │  6 probes    │ │ 7 probes     │   │  │
│  │  │ quarantine DB│ │ psutil+lsof  │ │  arp+bonjour │ │ log show 30s │   │  │
│  │  │ 30s          │ │ 15s          │ │  60s (||)    │ │              │   │  │
│  │  └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ └──────┬───────┘   │  │
│  │         │                │                │                │            │  │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐   │  │
│  │  │InternetActAgt│ │DBActivityAgt│ │HTTPInspector │ │NetSentinelAgt│   │  │
│  │  │ 8 probes     │ │ 8 probes     │ │  8 probes    │ │ 10 probes    │   │  │
│  │  │ lsof 30s     │ │ psutil+log   │ │  log files   │ │ tail web log │   │  │
│  │  │              │ │ 60s          │ │  30s         │ │ 15s          │   │  │
│  │  └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ └──────┬───────┘   │  │
│  │         │                │                │                │            │  │
│  │  ┌──────────────┐                                                       │  │
│  │  │ProtocolColAgt│   Each agent thread:                                  │  │
│  │  │ 10 probes    │     _run_one_cycle() → collect → validate → enrich    │  │
│  │  │ syslog 30s   │     → LocalQueueAdapter.enqueue()                     │  │
│  │  └──────┬───────┘     → data/queue/{agent_name}.db                      │  │
│  │         │                                                                │  │
│  └─────────┼────────────────────────────────────────────────────────────────┘  │
│            │                                                                   │
│            ▼                                                                   │
│  ┌──────────────────────────────────────────────────────────────────────────┐  │
│  │  PER-AGENT QUEUE FILES (SQLite WAL mode)                                 │  │
│  │                                                                          │  │
│  │  data/queue/realtime_sensor.db   data/queue/macos_process.db            │  │
│  │  data/queue/macos_network.db     data/queue/macos_auth.db               │  │
│  │  data/queue/macos_persistence.db data/queue/macos_filesystem.db         │  │
│  │  data/queue/macos_peripheral.db  data/queue/macos_dns.db                │  │
│  │  data/queue/macos_infostealer_guard.db  ...                             │  │
│  │                                                                          │  │
│  │  Each row: id | idem | ts_ns | bytes (protobuf) | sig | prev_sig       │  │
│  │  Dedup: UNIQUE(idem)   Integrity: SHA-256 hash + Ed25519 chain          │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
│                                                                                │
│  ┌────────────────────────────────────────────┐                               │
│  │  COORDINATION BUS (LocalBus, in-process)    │                               │
│  │                                              │                               │
│  │  Topics: CONTROL, HEALTH, ALERT,             │                               │
│  │          WATCH_PID, WATCH_PATH,              │                               │
│  │          WATCH_DOMAIN, CLEAR_WATCH           │                               │
│  │                                              │                               │
│  │  Agent A detects suspicious PID 1234         │                               │
│  │    → publishes WATCH_PID {pid: 1234}         │                               │
│  │    → All other agents tighten collection     │                               │
│  │      on PID 1234 (shorter interval,          │                               │
│  │      deeper inspection)                      │                               │
│  └────────────────────────────────────────────┘                               │
│                                                                                │
│  ┌────────────────────────────────────────────┐                               │
│  │  TIMELINE BUFFER (in-process singleton)     │                               │
│  │  TimelineBuffer(maxlen=10000, window=300s)  │                               │
│  │                                              │                               │
│  │  All collectors write TimelineEntry:          │                               │
│  │    source, event_type, pid, path, domain,    │                               │
│  │    remote_ip, bundle_id, process_name        │                               │
│  │                                              │                               │
│  │  Correlation probes read:                     │                               │
│  │    correlate_by_pid(1234, window=60s)         │                               │
│  │    correlate_by_path("/tmp/payload", 30s)     │                               │
│  │    correlate_chain([step1, step2, step3])     │                               │
│  └────────────────────────────────────────────┘                               │
└────────────────────────────────────────────────────────────────────────────────┘
                                    │
                     Queue drain → EventBus → FlowAgent WAL
                                    │
                                    ▼
```

---

## Tier 2 — Analyzer Process

```
┌────────────────────────────────────────────────────────────────────────────────┐
│  ANALYZER PROCESS (amoskys.analyzer_main)                                      │
│  Budget: 150MB RSS, 25% CPU burst                                              │
│  Cycle: 2 seconds                                                              │
│                                                                                │
│  ┌──────────────────────────────────────────────────────────────────────────┐  │
│  │  WAL PROCESSOR (WALProcessor)                                            │  │
│  │  Reads: data/wal/flowagent.db                                            │  │
│  │  Batch: 500 events per cycle                                              │  │
│  │                                                                          │  │
│  │  For each WAL row:                                                        │  │
│  │    1. BLAKE2b checksum verify (quarantine on mismatch)                   │  │
│  │    2. Ed25519 hash chain verify (quarantine on break)                    │  │
│  │    3. Parse UniversalEnvelope protobuf                                   │  │
│  │    4. Store envelope truth → telemetry_events table                      │  │
│  │    5. Route by content type:                                              │  │
│  │       device_telemetry → _process_device_telemetry()                     │  │
│  │       process → _process_process_event()                                  │  │
│  │       flow → _process_flow_event()                                        │  │
│  │    6. Single batch commit                                                 │  │
│  │    7. ACK: DELETE FROM wal WHERE id IN (...)                              │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
│                                    │                                           │
│                                    ▼                                           │
│  ┌──────────────────────────────────────────────────────────────────────────┐  │
│  │  ENRICHMENT PIPELINE (EnrichmentPipeline)                                │  │
│  │                                                                          │  │
│  │  ┌─────────┐  ┌─────────┐  ┌────────────┐  ┌──────────────┐            │  │
│  │  │  GeoIP  │→│  ASN    │→│ Threat Intel│→│ MITRE Mapper │            │  │
│  │  │ MaxMind │  │ MaxMind │  │ Abuse.ch   │  │ 24 pattern   │            │  │
│  │  │ City    │  │ ASN     │  │ OTX        │  │ rules        │            │  │
│  │  └─────────┘  └─────────┘  └────────────┘  └──────────────┘            │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
│                                    │                                           │
│                                    ▼                                           │
│  ┌──────────────────────────────────────────────────────────────────────────┐  │
│  │  SCORING ENGINE (ScoringEngine)                                          │  │
│  │                                                                          │  │
│  │  ┌───────────────┐ ┌───────────────┐ ┌────────────────┐                 │  │
│  │  │ GeometricScorer│ │TemporalScorer │ │BehavioralScorer│                 │  │
│  │  │ weight: 0.35   │ │ weight: 0.25  │ │ weight: 0.40   │                 │  │
│  │  │                │ │               │ │                │                 │  │
│  │  │ External IP    │ │ Off-hours     │ │ Event rarity   │                 │  │
│  │  │ Threat intel   │ │ Burst detect  │ │ Risk category  │                 │  │
│  │  │ Unusual country│ │ First-seen    │ │ Agent risk     │                 │  │
│  │  │ Hosting ASN    │ │ Probe latency │ │ Requires invest│                 │  │
│  │  └───────┬────────┘ └──────┬────────┘ └───────┬────────┘                 │  │
│  │          │                 │                   │                          │  │
│  │          └─────────────────┴───────────────────┘                          │  │
│  │                         │                                                 │  │
│  │              composite_score (0.0–1.0)                                    │  │
│  │              ├── < 0.40 → "legitimate"                                    │  │
│  │              ├── 0.40–0.70 → "suspicious"                                 │  │
│  │              └── > 0.70 → "malicious"                                     │  │
│  │                                                                          │  │
│  │  DeviceBaseline: LEARNING → DETECTION mode transition                    │  │
│  │  DynamicThresholds: auto-tune from TP/FP feedback                        │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
│                                    │                                           │
│                                    ▼                                           │
│  ┌──────────────────────────────────────────────────────────────────────────┐  │
│  │  STORAGE (TelemetryStore → data/telemetry.db)                            │  │
│  │                                                                          │  │
│  │  Domain tables:          Meta tables:              Intel tables:          │  │
│  │  ├─ security_events      ├─ telemetry_receipts     data/intel/fusion.db  │  │
│  │  ├─ process_events       │  (4-checkpoint ledger)  ├─ incidents           │  │
│  │  ├─ flow_events          ├─ process_genealogy      └─ device_risk         │  │
│  │  ├─ dns_events           │  (PID spawn chains)                           │  │
│  │  ├─ persistence_events   ├─ dashboard_rollups                            │  │
│  │  ├─ fim_events           │  (precomputed hourly)                         │  │
│  │  ├─ peripheral_events    ├─ incidents (SOC)                              │  │
│  │  ├─ audit_events         ├─ wal_dead_letter                              │  │
│  │  └─ observation_events   └─ _snapshot_baseline                           │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
│                                    │                                           │
│                                    ▼                                           │
│  ┌──────────────────────────────────────────────────────────────────────────┐  │
│  │  CORRELATION (every 60 seconds)                                          │  │
│  │                                                                          │  │
│  │  ┌──────────────────┐    ┌──────────────────────┐                        │  │
│  │  │ FusionEngine     │    │ KillChainTracker      │                        │  │
│  │  │ 13 base rules    │    │ 7 stages:             │                        │  │
│  │  │                  │    │  reconnaissance        │                        │  │
│  │  │ ssh_brute_force  │    │  weaponization         │                        │  │
│  │  │ persistence_     │    │  delivery              │                        │  │
│  │  │  after_auth      │    │  exploitation          │                        │  │
│  │  │ suspicious_sudo  │    │  installation          │                        │  │
│  │  │ multi_tactic     │    │  command_and_control   │                        │  │
│  │  │ ssh_lateral      │    │  actions_on_objectives │                        │  │
│  │  │ data_exfil_spike │    │                        │                        │  │
│  │  │ suspicious_tree  │    │ Multi-stage alert      │                        │  │
│  │  │ coordinated_recon│    │ when stages_reached≥3  │                        │  │
│  │  │ web_attack_chain │    └──────────────────────┘                        │  │
│  │  │ infostealer_kill │                                                     │  │
│  │  │ clickfix_attack  │    ┌──────────────────────┐                        │  │
│  │  │ download_execute │    │ StoryEngine           │                        │  │
│  │  │ credential_harv  │    │ 7 known patterns:     │                        │  │
│  │  └──────────────────┘    │  amos_stealer         │                        │  │
│  │                          │  credential_harvest   │                        │  │
│  │  Device Risk Score:      │  ssh_brute_force      │                        │  │
│  │  Base 10 + events        │  dns_c2               │                        │  │
│  │  SSH fail: +5 each       │  privilege_escalation  │                        │  │
│  │  New SSH key: +30        │  clickfix_stealer     │                        │  │
│  │  CRITICAL inc: +40       │  reverse_shell        │                        │  │
│  │  Clamp: [0, 100]        └──────────────────────┘                        │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
│                                    │                                           │
│                                    ▼                                           │
│  ┌──────────────────────────────────────────────────────────────────────────┐  │
│  │  IGRIS (Supervisory Intelligence, every 60 seconds)                      │  │
│  │                                                                          │  │
│  │  MetricCollector → 50 metrics across 9 subsystems                        │  │
│  │       ↓                                                                   │  │
│  │  BaselineTracker → deviation detection (sigma-based)                      │  │
│  │       ↓                                                                   │  │
│  │  6 Signal Types:                                                          │  │
│  │    STABILITY_WARNING      — agent down / crash                            │  │
│  │    DRIFT_WARNING          — AMRDR reliability degrading                   │  │
│  │    INTEGRITY_WARNING      — WAL chain break / dead letters                │  │
│  │    SUPERVISION_DEFICIT    — enrichment pipeline offline                    │  │
│  │    MODEL_STALENESS        — SOMA training overdue                         │  │
│  │    TRANSPORT_BACKPRESSURE — WAL queue backing up                          │  │
│  │       ↓                                                                   │  │
│  │  Cooldown gate (10-min per dedup_key)                                     │  │
│  │       ↓                                                                   │  │
│  │  SignalEmitter → data/igris/signals.jsonl                                 │  │
│  │                                                                          │  │
│  │  IGRISOrchestrator: modes = calm | alert | hunt | response                │  │
│  │  Narrator: AttackStory → Briefing (template or Claude API)                │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────────┘
                                    │
                    _ReadPool (4 connections)
                    _TTLCache (5s TTL)
                    Prewarm daemon (25s cycle → dashboard_rollups)
                                    │
                                    ▼
```

---

## Tier 3 — Dashboard Process

```
┌────────────────────────────────────────────────────────────────────────────────┐
│  DASHBOARD PROCESS (web.app, Flask + SocketIO, port 5003)                      │
│                                                                                │
│  Blueprints:                                                                   │
│    dashboard_bp  (/dashboard/*)  — 20+ page routes + API endpoints             │
│    api_bp        (/api/*)        — REST API                                    │
│    auth_bp       (/auth/*)       — Authentication                              │
│    admin_bp      (/admin/*)      — Admin                                       │
│    prometheus_bp (/metrics)      — Prometheus scrape endpoint                  │
│                                                                                │
│  Key Pages:                     Key APIs:                                      │
│    /dashboard/cortex            /dashboard/api/health-summary                  │
│    /dashboard/incidents         /dashboard/api/incidents (GET/POST/PATCH)       │
│    /dashboard/mitre             /dashboard/api/live/probe-health               │
│    /dashboard/hunt              /dashboard/api/fusion/incidents                 │
│    /dashboard/igris             /dashboard/api/agents/<id>/health               │
│    /dashboard/guardian                                                          │
│    /dashboard/posture                                                          │
│                                                                                │
│  DashboardUpdater (SocketIO, 5s cycle):                                        │
│    → collects live incidents, threats, agents, metrics, posture                 │
│    → socketio.emit("dashboard_update") to /dashboard namespace                 │
│    → socketio.emit("incidents_update") to "soc" room                           │
│                                                                                │
│  Reads from: data/telemetry.db (via _ReadPool) + data/intel/fusion.db          │
│  Security: Talisman CSP, rate limiting, CORS, request validation               │
└────────────────────────────────────────────────────────────────────────────────┘
```

---

## Detection Coverage Summary

```
┌──────────────────────────────────────────────────────────────────┐
│                    DETECTION COVERAGE                             │
│                                                                  │
│  PROBES:                                                         │
│    14 real-time probes (RealtimeSensorAgent)                     │
│    13 process probes (ProcessAgent)                              │
│     9 auth probes (AuthAgent)                                    │
│    10 persistence probes (PersistenceAgent)                      │
│     8 filesystem probes (FIMAgent)                               │
│     9 network probes (NetworkAgent)                              │
│     8 DNS probes (DNSAgent)                                      │
│    11 infostealer probes (InfostealerGuardAgent)                 │
│     8 quarantine probes (QuarantineGuardAgent)                   │
│     8 provenance probes (ProvenanceAgent)                        │
│    10 network sentinel probes (NetworkSentinelAgent)              │
│     6 discovery probes (DiscoveryAgent)                          │
│    12 correlation probes + 6 temporal probes                     │
│     4 peripheral probes                                          │
│    + applog(7) + db_activity(8) + http_inspector(8)              │
│      + internet_activity(8) + protocol_collectors(10)            │
│      + unified_log(6) + security_monitor(4)                      │
│      + kernel_audit(8, Linux only)                               │
│                                                                  │
│  RULES:                                                          │
│    44 LOLBins monitored                                          │
│    12 script interpreter patterns (incl JXA, base64, -e flag)    │
│    16 security tool disable patterns                             │
│    22 discovery burst commands                                   │
│    13 fusion correlation rules                                   │
│    7 known attack patterns (StoryEngine)                         │
│    56 Sigma rules                                                │
│                                                                  │
│  MITRE ATT&CK:                                                   │
│    116 unique techniques mapped                                  │
│    All 12 tactics covered                                        │
│                                                                  │
│  VISIBILITY:                                                     │
│    ~90% attack surface (weighted)                                │
│    ~82% fileless malware                                         │
│    ~93% LOLBin abuse                                             │
└──────────────────────────────────────────────────────────────────┘
```

---

## Data Flow (End-to-End, Single Event)

```
1. macOS kernel event (e.g., file created in ~/Library/LaunchAgents/)
       │
2. FSEventsCollector receives callback from watchdog Observer
       │ RealTimeEvent(source="fsevents", event_type="file_created",
       │               path="/Users/.../Library/LaunchAgents/evil.plist")
       │
3. RealtimeSensorCollector.collect() drains all sources
       │ List[RealTimeEvent] — merged from 4 sources
       │
4. PersistenceDropProbe.scan(shared_data) fires
       │ TelemetryEvent(event_type="rt_persistence_file_created",
       │                severity=HIGH, mitre=["T1543.001"],
       │                data={"path": "...", "risk_score": 0.85})
       │
5. MacOSRealtimeSensorAgent.collect_data() wraps in DeviceTelemetry protobuf
       │ DeviceTelemetry { device_id, timestamp_ns, events[...] }
       │
6. HardenedAgentBase._run_one_cycle() calls:
       │ _validate_event_shape() → OK
       │ enrich_event() → no-op
       │ LocalQueueAdapter.enqueue()
       │   → SHA-256(payload_bytes)
       │   → Ed25519.sign(canonical_bytes, prev_sig)
       │   → LocalQueue.enqueue() → INSERT INTO queue
       │
7. SQLite WAL: data/queue/realtime_sensor.db
       │ Row: id=1, idem="realtime_sensor:host:ts:seq",
       │      bytes=<protobuf>, sig=<ed25519>, prev_sig=<chain>
       │
8. LocalQueueAdapter.drain() → EventBus.Publish()
       │ UniversalEnvelope { version, ts_ns, device_telemetry, sig, prev_sig }
       │
9. EventBus server receives → writes to FlowAgent WAL
       │ data/wal/flowagent.db
       │
10. WALProcessor.process_batch() reads WAL
       │ BLAKE2b verify ✓, hash chain verify ✓
       │ Parse UniversalEnvelope → DeviceTelemetry
       │
11. EnrichmentPipeline
       │ GeoIP → ASN → ThreatIntel → MITRE mapping
       │
12. ScoringEngine.score_event()
       │ geometric=0.0, temporal=0.25 (off-hours), behavioral=0.35 (rare+risky)
       │ composite=0.23 → classification="suspicious"  (or "malicious" if >0.7)
       │
13. TelemetryStore.insert_security_event()
       │ → data/telemetry.db :: security_events table
       │
14. FusionEngine.add_event() → device_state buffer
       │ Every 60s: evaluate_device() → 13 rules
       │ If ssh_brute_force + persistence: Incident created
       │ → data/intel/fusion.db :: incidents table
       │
15. KillChainTracker.record_stage("installation")
       │ stages_reached=3 → multi_stage=True → alert
       │
16. Igris._observe_cycle()
       │ MetricCollector → BaselineTracker → signals
       │ → data/igris/signals.jsonl
       │
17. StoryEngine.build_stories()
       │ Groups related incidents → AttackStory
       │ Narrator produces Briefing (template or Claude API)
       │
18. DashboardUpdater._update_loop() (5s cycle)
       │ Reads from telemetry.db + fusion.db
       │ socketio.emit("dashboard_update") → browser
       │
19. Dashboard renders Cortex view
       │ Posture ring, threat timeline, incident cards
       └─→ User sees: "LaunchAgent persistence detected, HIGH severity"
```
