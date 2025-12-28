# MITRE ATT&CK Coverage Matrix

This document maps AMOSKYS correlation rules and telemetry sources to the MITRE ATT&CK framework, demonstrating coverage across tactics and techniques.

## Overview

**Coverage Statistics:**
- **Tactics Covered:** 5 of 14 (36%)
- **Techniques Covered:** 9 specific techniques
- **Detection Rules:** 4 correlation rules
- **Telemetry Agents:** 6 specialized agents
- **Test Coverage:** 16 unit tests (100% of rules)

## Tactics Coverage

| Tactic | ATT&CK ID | Coverage | Rules | Status |
|--------|-----------|----------|-------|--------|
| Initial Access | TA0001 | ✅ | 1 | **Covered** |
| Execution | TA0002 | ✅ | 1 | **Covered** |
| Persistence | TA0003 | ✅ | 2 | **Covered** |
| Privilege Escalation | TA0004 | ✅ | 2 | **Covered** |
| Defense Evasion | TA0005 | 🔴 | 0 | Not covered |
| Credential Access | TA0006 | 🔴 | 0 | Not covered |
| Discovery | TA0007 | 🔴 | 0 | Not covered |
| Lateral Movement | TA0008 | 🟡 | 0 | Planned |
| Collection | TA0009 | 🔴 | 0 | Not covered |
| Command & Control | TA0011 | ✅ | 1 | **Covered** |
| Exfiltration | TA0010 | 🔴 | 0 | Not covered |
| Impact | TA0040 | 🔴 | 0 | Not covered |

**Legend:**
- ✅ **Covered** - Active detection with telemetry + correlation rules
- 🟡 **Planned** - Telemetry available, rules pending
- 🔴 **Not Covered** - No current detection capability

## Detailed Technique Mapping

### TA0001 - Initial Access

| Technique | Description | Telemetry Source | Detection Rule | Test Coverage |
|-----------|-------------|------------------|----------------|---------------|
| **T1110** | Brute Force | AuthGuardAgent (SSH failed attempts) | ssh_brute_force | ✅ 3 tests |
| **T1021.004** | Remote Services: SSH | AuthGuardAgent (SSH success) | ssh_brute_force | ✅ 3 tests |
| T1078 | Valid Accounts | AuthGuardAgent (login success) | 🟡 Planned | - |
| T1133 | External Remote Services | 🔴 Not monitored | - | - |

### TA0002 - Execution

| Technique | Description | Telemetry Source | Detection Rule | Test Coverage |
|-----------|-------------|------------------|----------------|---------------|
| **T1059** | Command and Scripting Interpreter | ProcAgent (process exec) | multi_tactic_attack | ✅ 3 tests |
| T1053 | Scheduled Task/Job | PersistenceGuardAgent (cron) | 🟡 Planned | - |
| T1569 | System Services | 🔴 Not monitored | - | - |

### TA0003 - Persistence

| Technique | Description | Telemetry Source | Detection Rule | Test Coverage |
|-----------|-------------|------------------|----------------|---------------|
| **T1543.001** | Create/Modify System Process: Launch Agent | PersistenceGuardAgent (LaunchAgent) | persistence_after_auth, multi_tactic_attack | ✅ 5 tests |
| **T1543.004** | Create/Modify System Process: Launch Daemon | PersistenceGuardAgent (LaunchDaemon) | persistence_after_auth | ✅ 2 tests |
| **T1053.003** | Scheduled Task/Job: Cron | PersistenceGuardAgent (crontab) | persistence_after_auth | ✅ 1 test |
| **T1098.004** | Account Manipulation: SSH Authorized Keys | PersistenceGuardAgent (authorized_keys) | persistence_after_auth | ✅ 1 test |
| T1547 | Boot or Logon Autostart Execution | 🟡 Partial (LaunchAgents) | - | - |

### TA0004 - Privilege Escalation

| Technique | Description | Telemetry Source | Detection Rule | Test Coverage |
|-----------|-------------|------------------|----------------|---------------|
| **T1548.003** | Abuse Elevation Control Mechanism: Sudo | AuthGuardAgent (sudo commands) | suspicious_sudo, persistence_after_auth | ✅ 4 tests |
| T1055 | Process Injection | 🔴 Not monitored | - | - |
| T1068 | Exploitation for Privilege Escalation | 🔴 Not monitored | - | - |

### TA0011 - Command & Control

| Technique | Description | Telemetry Source | Detection Rule | Test Coverage |
|-----------|-------------|------------------|----------------|---------------|
| **T1071** | Application Layer Protocol | FlowAgent (outbound flows) | multi_tactic_attack | ✅ 2 tests |
| T1095 | Non-Application Layer Protocol | FlowAgent (ICMP, raw sockets) | 🟡 Partial | - |
| T1571 | Non-Standard Port | FlowAgent (unusual ports) | 🟡 Planned | - |

## Detection Rule → Technique Matrix

### Rule 1: ssh_brute_force

**Covered Techniques:**
- T1110 - Brute Force
- T1021.004 - Remote Services: SSH

**Covered Tactics:**
- TA0001 - Initial Access

**Telemetry Sources:**
- AuthGuardAgent: SecurityEvent (SSH failed/success)

**Test Coverage:**
- `test_ssh_brute_force_fires` ✅
- `test_ssh_brute_force_not_fired_without_success` ✅
- `test_ssh_brute_force_not_fired_with_only_two_failures` ✅

**Detection Logic:**
```
≥ 3 failed SSH attempts from IP X
  → Successful SSH login from IP X
  (within 30-minute window)
```

**Severity:** HIGH

---

### Rule 2: persistence_after_auth

**Covered Techniques:**
- T1543.001 - Launch Agent
- T1543.004 - Launch Daemon
- T1053.003 - Cron
- T1098.004 - SSH Authorized Keys
- T1548.003 - Sudo (trigger context)

**Covered Tactics:**
- TA0003 - Persistence
- TA0004 - Privilege Escalation

**Telemetry Sources:**
- AuthGuardAgent: SecurityEvent (SSH success, sudo)
- PersistenceGuardAgent: AuditEvent (persistence creation)

**Test Coverage:**
- `test_persistence_after_auth_fires` ✅
- `test_persistence_after_auth_fires_for_sudo_too` ✅
- `test_persistence_after_auth_not_fired_without_auth` ✅

**Detection Logic:**
```
Successful SSH or SUDO
  → CREATED persistence mechanism
  (within 10-minute window)
```

**Severity:** CRITICAL (user directory), HIGH (system directory)

---

### Rule 3: suspicious_sudo

**Covered Techniques:**
- T1548.003 - Abuse Elevation Control Mechanism: Sudo

**Covered Tactics:**
- TA0004 - Privilege Escalation

**Telemetry Sources:**
- AuthGuardAgent: SecurityEvent (sudo with dangerous commands)

**Test Coverage:**
- `test_suspicious_sudo_fires_for_sudoers_edit` ✅
- `test_suspicious_sudo_fires_for_rm_rf` ✅
- `test_suspicious_sudo_not_fired_for_benign_command` ✅

**Detection Logic:**
```
SUDO command containing dangerous patterns:
  - rm -rf / (system destruction)
  - /etc/sudoers (privilege escalation)
  - LaunchAgents/Daemons (persistence)
  - kextload (kernel extension)
```

**Severity:** CRITICAL or HIGH (pattern-dependent)

---

### Rule 4: multi_tactic_attack

**Covered Techniques:**
- T1071 - Application Layer Protocol (C2)
- T1059 - Command and Scripting Interpreter (Execution)
- T1543.001 - Launch Agent (Persistence)

**Covered Tactics:**
- TA0002 - Execution
- TA0003 - Persistence
- TA0011 - Command & Control

**Telemetry Sources:**
- ProcAgent: ProcessEvent (suspicious execution paths)
- FlowAgent: FlowEvent (outbound connections)
- PersistenceGuardAgent: AuditEvent (persistence creation)

**Test Coverage:**
- `test_multi_tactic_attack_fires` ✅
- `test_multi_tactic_attack_not_fired_without_persistence` ✅
- `test_multi_tactic_attack_not_fired_without_process` ✅
- `test_multiple_rules_can_fire_simultaneously` ✅

**Detection Logic:**
```
Suspicious process (in /tmp, ~/Downloads)
  + Outbound network connection (uncommon port/IP)
  + Persistence mechanism created
  (all within 15-minute window)
```

**Severity:** CRITICAL

## Telemetry Agent → Technique Coverage

### FlowAgent (Network Flows)

**Techniques Supported:**
- T1071 - Application Layer Protocol ✅
- T1095 - Non-Application Layer Protocol 🟡
- T1571 - Non-Standard Port 🟡
- T1041 - Exfiltration Over C2 Channel 🟡

**Current Rules:** multi_tactic_attack
**Planned Rules:** lateral_movement_ssh, data_exfiltration

---

### ProcAgent (Process Monitoring)

**Techniques Supported:**
- T1059 - Command and Scripting Interpreter ✅
- T1106 - Native API 🟡
- T1055 - Process Injection 🔴

**Current Rules:** multi_tactic_attack
**Planned Rules:** suspicious_process_tree, code_injection

---

### AuthGuardAgent (Authentication)

**Techniques Supported:**
- T1110 - Brute Force ✅
- T1021.004 - SSH ✅
- T1548.003 - Sudo ✅
- T1078 - Valid Accounts 🟡

**Current Rules:** ssh_brute_force, persistence_after_auth, suspicious_sudo
**Planned Rules:** credential_stuffing, session_hijacking

---

### PersistenceGuardAgent (Persistence Mechanisms)

**Techniques Supported:**
- T1543.001 - Launch Agent ✅
- T1543.004 - Launch Daemon ✅
- T1053.003 - Cron ✅
- T1098.004 - SSH Keys ✅
- T1547 - Boot/Logon Autostart 🟡

**Current Rules:** persistence_after_auth, multi_tactic_attack
**Planned Rules:** persistence_enumeration, backdoor_detection

---

### SNMP Agent (System Metrics)

**Techniques Supported:**
- T1082 - System Information Discovery 🟡
- T1614 - System Location Discovery 🟡

**Current Rules:** None
**Planned Rules:** anomaly_detection (via ML)

---

### Peripheral Agent (USB/Device Monitoring)

**Techniques Supported:**
- T1200 - Hardware Additions 🟡
- T1091 - Replication Through Removable Media 🟡

**Current Rules:** None
**Planned Rules:** unauthorized_device, usb_exfiltration

## Test Coverage Summary

| Rule | Tests | Positive Cases | Negative Cases | Edge Cases |
|------|-------|----------------|----------------|------------|
| ssh_brute_force | 3 | 1 | 2 | 0 |
| persistence_after_auth | 3 | 2 | 1 | 0 |
| suspicious_sudo | 3 | 2 | 1 | 0 |
| multi_tactic_attack | 3 | 1 | 2 | 0 |
| **Integration** | 4 | 2 | 0 | 2 |
| **Total** | **16** | **8** | **6** | **2** |

**Test Execution:**
```bash
$ pytest tests/intel/test_fusion_rules.py -v

16 passed in 0.05s ✅
```

## Gap Analysis & Roadmap

### High-Priority Gaps (Next 3 Rules)

#### 1. Lateral Movement via SSH (TA0008)

**Technique:** T1021.004 (SSH)

**Pattern:**
```
Inbound SSH success from external IP
  → Outbound SSH to internal IP
  (within 5 minutes)
```

**Telemetry:** AuthGuardAgent + FlowAgent
**Severity:** HIGH
**Estimated Effort:** 2 days

---

#### 2. Data Exfiltration Spike (TA0010)

**Technique:** T1041 (Exfiltration Over C2)

**Pattern:**
```
Sudden large outbound volume to rare IP/domain
  (> 10MB within 5 minutes to new destination)
```

**Telemetry:** FlowAgent
**Severity:** CRITICAL
**Estimated Effort:** 3 days

---

#### 3. Suspicious Process Tree (TA0002)

**Technique:** T1059 (Command Execution)

**Pattern:**
```
Terminal/SSH → shell → unknown binary in /tmp or ~/Downloads
```

**Telemetry:** ProcAgent (parent-child relationships)
**Severity:** HIGH
**Estimated Effort:** 2 days

### Medium-Priority Gaps

- **Defense Evasion (TA0005):**
  - T1070.001 - Clear Bash History
  - T1562.001 - Disable Security Tools

- **Credential Access (TA0006):**
  - T1003 - OS Credential Dumping
  - T1555 - Credentials from Password Stores

- **Discovery (TA0007):**
  - T1083 - File and Directory Discovery
  - T1046 - Network Service Scanning

### Low-Priority Gaps (Future)

- **Collection (TA0009):** Screen capture, clipboard data
- **Impact (TA0040):** Data destruction, resource hijacking
- **Cross-platform:** Linux/Windows equivalents

## Competitive Comparison

| Feature | AMOSKYS | CrowdStrike | Microsoft Sentinel |
|---------|---------|-------------|-------------------|
| Tactics covered | 5 / 14 (36%) | 14 / 14 (100%) | 14 / 14 (100%) |
| Techniques covered | 9 | 200+ | 150+ |
| Rule tests | 16 | Unknown | Unknown |
| MITRE mapping | ✅ Auto-tagged | ✅ | ✅ |
| Mac-specific | ✅ Native | 🟡 Agent | 🟡 Agent |
| Detection-as-code | ✅ pytest | 🔴 Proprietary | 🟡 KQL |

**Verdict:** AMOSKYS has a solid foundation covering critical attack paths (Initial Access → Persistence → Privilege Escalation) with excellent test coverage. Expansion to remaining tactics is straightforward given the modular architecture.

## Attack Scenario Coverage

### Scenario 1: SSH-Based Compromise ✅

**Kill Chain:**
1. Attacker brute forces SSH → **Detected** (ssh_brute_force)
2. Successful login → **Logged** (AuthGuardAgent)
3. Installs LaunchAgent backdoor → **Detected** (persistence_after_auth)
4. Escalates via sudo → **Detected** (suspicious_sudo if dangerous command)

**Coverage:** 4/4 steps ✅

---

### Scenario 2: Malware Dropper ✅

**Kill Chain:**
1. User downloads malware to ~/Downloads
2. Malware executes → **Detected** (multi_tactic_attack - suspicious process)
3. Connects to C2 server → **Detected** (multi_tactic_attack - flow)
4. Installs persistence → **Detected** (multi_tactic_attack - persistence)

**Coverage:** 3/4 steps ✅ (download not monitored)

---

### Scenario 3: Insider Threat ✅

**Kill Chain:**
1. Authorized user logs in → **Logged** (AuthGuardAgent)
2. Edits /etc/sudoers → **Detected** (suspicious_sudo)
3. Adds SSH backdoor key → **Detected** (persistence_after_auth)

**Coverage:** 2/3 steps ✅ (initial login is benign)

---

### Scenario 4: Lateral Movement 🟡

**Kill Chain:**
1. Attacker compromises Host A
2. SSHes from Host A to Host B → **Partially detected** (SSH login logged, but no cross-device correlation yet)
3. Repeats across network

**Coverage:** 1/3 steps 🟡 (single-host detection only)

**Status:** Planned for Phase 2 (cross-device correlation)

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [AMOSKYS Rules Implementation](../src/amoskys/intel/rules.py)
- [AMOSKYS Rule Tests](../tests/intel/test_fusion_rules.py)
- [Intelligence Layer Documentation](INTELLIGENCE_FUSION.md)

---

**Last Updated:** 2025-12-28
**Version:** 1.0
**Maintainer:** AMOSKYS Intelligence Team
