# AMOSKYS

**Your Mac made 37,000 network connections yesterday. Do you know who it talked to?**

AMOSKYS is a macOS endpoint detection platform that shows you exactly where your data goes — in real time, on a globe — and detects when something is wrong.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-4%2C255%20passing-brightgreen.svg)]()
[![LOC](https://img.shields.io/badge/LOC-38%2C000-blue.svg)]()
[![Platform](https://img.shields.io/badge/platform-macOS-lightgrey.svg)]()

---

## What It Does

AMOSKYS runs 17 native macOS agents that watch everything happening on your machine:

- **Processes** — what's running, who spawned it, is it signed
- **Network flows** — where your data goes, how much, how often
- **DNS queries** — every domain your Mac resolves
- **Authentication** — SSH attempts, sudo usage, login anomalies
- **Persistence** — LaunchAgents, cron jobs, SSH keys, login items
- **File integrity** — critical system file modifications
- **Credentials** — Keychain access, browser cookie reads, clipboard monitoring
- **Quarantine** — Gatekeeper bypass attempts, unsigned downloads

Each agent has detection probes — 175 total — mapped to [MITRE ATT&CK](https://attack.mitre.org/) techniques. When something looks wrong, a fusion engine correlates signals across agents into kill chains.

### The Observatory

The Network Observatory shows every connection your Mac makes, plotted on a globe in real time. Every arc is a real connection. Every label is a real destination.

At the bottom: *"No suspicious connections detected. All traffic appears clean."*

That sentence only means something when you can prove it.

---

## By the Numbers

| Metric | Value |
|--------|-------|
| macOS Detection Agents | 17 |
| Detection Probes | 175 (MITRE ATT&CK mapped) |
| Sigma Detection Rules | 56 (all 14 tactics) |
| Fusion Correlation Rules | 13 |
| MITRE Techniques Covered | 106+ |
| Test Suite | 4,255 passing |
| Lines of Code | ~38,000 |

---

## Architecture

```
 ┌─────────────────────────────────────────────────────────────────┐
 │  17 macOS Agents                                                │
 │  Process · Auth · Persistence · FIM · Network · DNS · Peripheral│
 │  AppLog · Discovery · InternetActivity · DBActivity · HTTP      │
 │  InfostealerGuard · QuarantineGuard · Provenance · Sentinel     │
 │  SecurityMonitor · UnifiedLog                                   │
 └────────────────────────┬────────────────────────────────────────┘
                          │ TelemetryEvents
                          ▼
 ┌────────────────────────────────────────────────────────────────┐
 │  Intelligence Layer                                            │
 │  ├─ Fusion Engine — 13 correlation rules (kill chain detection)│
 │  ├─ INADS — 5-cluster ML anomaly scoring                      │
 │  ├─ SOMA — 2-hemisphere behavioral baseline                   │
 │  ├─ Sigma Engine — 56 YAML detection rules                    │
 │  └─ Kill Chain Tracker — 7-stage progression                  │
 └────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
 ┌────────────────────────────────────────────────────────────────┐
 │  Dashboard                                                     │
 │  Cortex · Observatory · Network Globe · Threats · Intelligence │
 │  Fleet · SOMA · Agents · Correlation                          │
 └────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

```bash
# Clone
git clone https://github.com/Vardhan-225/Amoskys.git
cd Amoskys

# Install
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[all]"

# Start
PYTHONPATH=src SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))') \
  FLASK_PORT=8080 LOGIN_DISABLED=true FORCE_HTTPS=false \
  python3 -m web.app
```

Open `http://localhost:8080/dashboard/observatory` and watch the globe.

---

## Detection Validation

AMOSKYS includes a red team toolkit (`kali/`) with 29 macOS attack techniques:

| Agent | Techniques | What It Tests |
|-------|-----------|---------------|
| TCC Hunter | 7 | Privacy framework bypasses |
| Keychain | 4 | Credential harvesting |
| Persistence | 7 | LaunchAgent, cron, SSH keys, DYLD injection |
| Gatekeeper | 6 | Code signing, quarantine bypass |
| XPC | 5 | IPC exploitation, privileged helpers |

Run the campaign, then check what the blue team caught:

```bash
# Attack
cd kali && python3 amoskys-red campaign localhost --all

# See what blue team detected
sqlite3 data/telemetry.db "SELECT event_category, risk_score, description
  FROM security_events ORDER BY timestamp_ns DESC LIMIT 20"
```

**Last campaign result:** 17 successful attacks → 31 blue team detections including credential access (0.88 risk), config backdoor (0.85), quarantine bypass (0.70), and a full kill chain correlation.

---

## Key Components

| Component | Location | What It Does |
|-----------|----------|-------------|
| Agent Base | `src/amoskys/agents/common/base.py` | HardenedAgentBase — circuit breaker, retry, health tracking |
| Probes | `src/amoskys/agents/common/probes.py` | MicroProbe pattern — stateful behavioral detection |
| Fusion Engine | `src/amoskys/intel/fusion_engine.py` | Cross-agent correlation, incident generation |
| INADS | `src/amoskys/intel/inads_engine.py` | 5-cluster ML scoring (published research) |
| SOMA | `src/amoskys/intel/soma.py` | Behavioral baseline — frequency + statistical anomaly |
| Kill Chain | `src/amoskys/agents/common/kill_chain.py` | 7-stage Lockheed Martin model with MITRE mapping |
| Sigma Rules | `src/amoskys/detection/rules/sigma/` | 56 YAML rules, OASIS standard |
| Telemetry Store | `src/amoskys/storage/telemetry_store.py` | SQLite WAL, read pool, 30s TTL cache |
| Dashboard | `web/app/` | Flask + SocketIO, <19ms response time |
| Red Team | `kali/` | 29 macOS attack techniques with gap analysis |

---

## macOS Agents

| Agent | Probes | What It Watches |
|-------|--------|----------------|
| Process | 15 | Spawns, LOLBins, injection, masquerade, code signing |
| AuthGuard | 9 | SSH brute force, sudo, off-hours login, impossible travel |
| PersistenceGuard | 11 | LaunchAgent/Daemon, cron, SSH keys, login hooks |
| FIM | 10 | Critical files, SUID changes, webshells, config backdoors |
| FlowAgent | 10 | C2 beaconing, exfiltration, lateral movement, tunnels |
| DNS | 8 | DGA detection, DNS tunneling, beaconing, cache poison |
| InternetActivity | 8 | Cloud exfil, TOR/VPN, crypto mining, shadow IT |
| Discovery | 6 | ARP changes, Bonjour, rogue DHCP, topology |
| HTTPInspector | 8 | XSS, SSRF, path traversal, API abuse, C2 beacons |
| AppLog | 7 | Webshells, log tampering, SQLi, credential harvest |
| DBActivity | 8 | Bulk extraction, schema enum, privilege escalation |
| InfostealerGuard | 12 | Keychain, browser creds, wallets, fake dialogs, clipboard |
| QuarantineGuard | 8 | Quarantine bypass, DMG execution, ClickFix, unsigned bins |
| Provenance | 8 | Cross-application attack chains, download-execute sequences |
| NetworkSentinel | 10 | HTTP scan storms, directory brute force, SQLi payloads |
| SecurityMonitor | 4 | PKI anomalies, Gatekeeper, security daemon |
| UnifiedLog | 6 | securityd, TCC, XPC, installer events |

---

## Running Tests

```bash
pytest tests/ -x -q
# 4,255 passed, 16 skipped, 0 failed
```

---

## Built By

[Akash Thanneeru](https://www.linkedin.com/in/akashthanneeru/) — built solo over 12 months. Architecture, detection logic, and system design by me. Implementation with Claude as coding partner.

INADS multi-perspective ML scoring is based on published research: *Thanneeru & Zhengrui, 2025.*

---

## License

MIT — see [LICENSE](LICENSE).
