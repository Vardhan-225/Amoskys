# AMOSKYS ML/AI Attribute Map

Complete inventory of all extractable attributes across 85 probes, 10 agents, and 75+ MITRE ATT&CK techniques. Use this document to plan ML/AI models, feature engineering pipelines, and anomaly detection algorithms.

---

## Architecture Summary

```
85 Probes → 10 Agents → LocalQueue (Ed25519 signed)
    → EventBus (gRPC) → WAL → WALProcessor
    → TelemetryStore (13 tables) → ScoreJunction → Dashboard
```

**Risk Classification**: `< 0.5 = legitimate | 0.5-0.75 = suspicious | >= 0.75 = malicious`
**Threat Score**: `(avg_risk x 50) + (critical_count x 10) + (max_risk x 20)` [0-100]

---

## 1. Process Agent (ProcAgent) — 10 Probes

Monitors process lifecycle, execution patterns, and code integrity.

### 1.1 ProcessSpawnProbe
- **MITRE**: T1059 (Command/Scripting), T1204 (User Execution)
- **Attributes**: `pid`, `ppid`, `name`, `exe`, `cmdline`, `cwd`, `uid`, `username`, `parent_name`, `parent_exe`, `cpu_percent`, `memory_rss`, `create_time`, `is_suspicious_parent`, `risk_score`, `confidence`
- **ML Features**: Parent-child relationship graph, command-line entropy, unusual parent chains

### 1.2 LOLBinExecutionProbe
- **MITRE**: T1218, T1218.010 (Regsvr32), T1218.011 (Rundll32)
- **Attributes**: `pid`, `name`, `exe`, `cmdline`, `lolbin_name`, `lolbin_category`, `args_suspicious`, `parent_name`, `risk_score`, `confidence`
- **ML Features**: LOLBin usage frequency per user/host, argument pattern clustering

### 1.3 ProcessTreeAnomalyProbe
- **MITRE**: T1055 (Process Injection), T1059
- **Attributes**: `pid`, `ppid`, `name`, `exe`, `parent_name`, `parent_exe`, `depth`, `anomaly_type`, `expected_parent`, `risk_score`, `confidence`
- **ML Features**: Process tree depth distribution, unusual parent-child pairs (graph anomaly)

### 1.4 HighCPUAndMemoryProbe
- **MITRE**: T1496 (Resource Hijacking/Cryptomining)
- **Attributes**: `pid`, `name`, `exe`, `cpu_percent`, `memory_rss`, `memory_vms`, `memory_percent`, `duration_seconds`, `risk_score`, `confidence`
- **ML Features**: CPU/memory time-series anomaly, per-process resource baseline deviation

### 1.5 LongLivedProcessProbe
- **MITRE**: T1036 (Masquerading)
- **Attributes**: `pid`, `name`, `exe`, `cmdline`, `uid`, `username`, `age_seconds`, `cpu_percent`, `connections_count`, `risk_score`, `confidence`
- **ML Features**: Process lifetime distribution, long-running + low-CPU = potential backdoor

### 1.6 SuspiciousUserProcessProbe
- **MITRE**: T1078 (Valid Accounts)
- **Attributes**: `pid`, `name`, `exe`, `uid`, `username`, `is_system_user`, `user_shell`, `login_count`, `risk_score`, `confidence`
- **ML Features**: User-to-process frequency map, first-seen processes per user

### 1.7 BinaryFromTempProbe
- **MITRE**: T1204 (User Execution), T1059
- **Attributes**: `pid`, `name`, `exe`, `cmdline`, `temp_dir`, `file_age_seconds`, `risk_score`, `confidence`
- **ML Features**: Temp directory execution rate, file age vs execution correlation

### 1.8 ScriptInterpreterProbe
- **MITRE**: T1059, T1059.001 (PowerShell), T1059.003 (Cmd), T1059.004 (Bash), T1059.006 (Python)
- **Attributes**: `pid`, `name`, `interpreter`, `script_path`, `cmdline`, `encoded_command`, `obfuscation_score`, `risk_score`, `confidence`
- **ML Features**: Script content entropy, obfuscation detection, command pattern classification

### 1.9 DylibInjectionProbe
- **MITRE**: T1547 (Boot/Logon Autostart), T1574.006 (Dynamic Linker Hijack)
- **Attributes**: `pid`, `name`, `exe`, `dylib_path`, `env_vars`, `injection_type`, `risk_score`, `confidence`
- **ML Features**: DYLD_* environment variable analysis, library load order anomaly

### 1.10 CodeSigningProbe
- **MITRE**: T1036 (Masquerading), T1070.005 (Indicator Removal)
- **Attributes**: `pid`, `name`, `exe`, `is_signed`, `is_apple_signed`, `is_notarized`, `team_id`, `signing_authority`, `risk_score`, `confidence`
- **ML Features**: Unsigned binary prevalence, first-seen team IDs, signing authority trust chain

**DB Table**: `process_events` (15 columns)
**Key ML Signals**: pid, ppid, name, exe, cmdline, cpu_percent, memory_rss, uid, risk_score

---

## 2. Auth Agent (AuthGuard) — 8 Probes

Monitors authentication events, privilege escalation, and account abuse.

### 2.1 SSHBruteForceProbe
- **MITRE**: T1110 (Brute Force), T1078 (Valid Accounts)
- **Attributes**: `source_ip`, `username`, `attempt_count`, `window_seconds`, `unique_usernames`, `failure_rate`, `risk_score`, `confidence`
- **ML Features**: Failure rate time-series, source IP reputation, attempt velocity

### 2.2 SSHPasswordSprayProbe
- **MITRE**: T1110.003 (Password Spraying)
- **Attributes**: `source_ip`, `unique_usernames`, `attempt_count`, `spray_ratio`, `window_seconds`, `risk_score`, `confidence`
- **ML Features**: Username-to-attempt ratio, spray pattern detection across time windows

### 2.3 SSHGeoImpossibleTravelProbe
- **MITRE**: T1078 (Valid Accounts)
- **Attributes**: `username`, `current_ip`, `previous_ip`, `current_geo`, `previous_geo`, `distance_km`, `time_delta_seconds`, `speed_kmh`, `risk_score`, `confidence`
- **ML Features**: Geographic velocity anomaly, login location clustering per user

### 2.4 SudoElevationProbe
- **MITRE**: T1548.003 (Sudo/Sudo Caching)
- **Attributes**: `username`, `command`, `target_user`, `tty`, `cwd`, `is_success`, `is_suspicious_command`, `risk_score`, `confidence`
- **ML Features**: Sudo command classification, user privilege escalation frequency

### 2.5 SudoSuspiciousCommandProbe
- **MITRE**: T1548, T1059, T1547
- **Attributes**: `username`, `command`, `command_category`, `pattern_matched`, `risk_score`, `confidence`
- **ML Features**: Command category distribution per user, rare command detection

### 2.6 OffHoursLoginProbe
- **MITRE**: T1078 (Valid Accounts)
- **Attributes**: `username`, `source_ip`, `login_hour`, `login_day`, `is_weekend`, `user_normal_hours`, `deviation_hours`, `risk_score`, `confidence`
- **ML Features**: Per-user login time distribution, weekend/holiday anomaly

### 2.7 MFABypassOrAnomalyProbe
- **MITRE**: T1621 (Multi-Factor Auth Request Generation)
- **Attributes**: `username`, `mfa_method`, `bypass_type`, `consecutive_failures`, `fatigue_score`, `risk_score`, `confidence`
- **ML Features**: MFA fatigue detection (rapid consecutive prompts), bypass pattern clustering

### 2.8 AccountLockoutStormProbe
- **MITRE**: T1110, T1499 (Endpoint DoS)
- **Attributes**: `locked_accounts`, `lockout_count`, `window_seconds`, `source_ips`, `risk_score`, `confidence`
- **ML Features**: Simultaneous lockout detection, coordinated attack identification

**DB Table**: `security_events` (15 columns + collection_agent)
**Key ML Signals**: username, source_ip, attempt_count, failure_rate, risk_score

---

## 3. DNS Agent — 9 Probes

Monitors DNS queries for C2, DGA, tunneling, and reconnaissance.

### 3.1 RawDNSQueryProbe
- **MITRE**: T1071.004 (DNS C2)
- **Attributes**: `domain`, `query_type`, `response_code`, `source_ip`, `process_name`, `pid`, `ttl`, `answer_count`, `risk_score`, `confidence`
- **ML Features**: Domain frequency distribution, query type entropy

### 3.2 DGAScoreProbe
- **MITRE**: T1568.002 (Domain Generation Algorithms)
- **Attributes**: `domain`, `dga_score`, `entropy`, `consonant_ratio`, `digit_ratio`, `length`, `bigram_score`, `is_dga`, `risk_score`, `confidence`
- **ML Features**: **High ML value** — character-level entropy, n-gram frequency, vowel/consonant ratio, domain length distribution. DGA classifiers (LSTM/Random Forest) are a top priority.

### 3.3 BeaconingPatternProbe
- **MITRE**: T1071.004, T1573.002 (Asymmetric Crypto)
- **Attributes**: `domain`, `query_count`, `avg_interval_seconds`, `jitter_ratio`, `stddev_interval`, `is_beaconing`, `beacon_confidence`, `risk_score`, `confidence`
- **ML Features**: **High ML value** — inter-arrival time regularity, jitter ratio time-series, DBSCAN clustering of beacon intervals

### 3.4 SuspiciousTLDProbe
- **MITRE**: T1071.004
- **Attributes**: `domain`, `tld`, `is_suspicious_tld`, `tld_category`, `domain_age_days`, `risk_score`, `confidence`
- **ML Features**: TLD risk scoring, newly registered domain detection

### 3.5 NXDomainBurstProbe
- **MITRE**: T1568.002, T1046
- **Attributes**: `source_ip`, `nxdomain_count`, `window_seconds`, `unique_domains`, `burst_ratio`, `risk_score`, `confidence`
- **ML Features**: NXDOMAIN rate anomaly, DGA behavioral signal

### 3.6 LargeTXTTunnelingProbe
- **MITRE**: T1048.001, T1071.004
- **Attributes**: `domain`, `txt_length`, `avg_query_size`, `query_count`, `total_bytes_encoded`, `is_tunneling`, `tunnel_bandwidth_bps`, `risk_score`, `confidence`
- **ML Features**: **High ML value** — TXT record size distribution, encoded payload detection, DNS tunnel bandwidth estimation

### 3.7 FastFluxRebindingProbe
- **MITRE**: T1568.001 (Fast Flux DNS)
- **Attributes**: `domain`, `unique_ips`, `ip_change_rate`, `ttl_mean`, `ttl_min`, `is_fast_flux`, `risk_score`, `confidence`
- **ML Features**: IP rotation velocity, TTL analysis, hosting infrastructure fingerprinting

### 3.8 NewDomainForProcessProbe
- **MITRE**: T1071.004
- **Attributes**: `domain`, `process_name`, `pid`, `is_first_seen`, `process_domain_count`, `risk_score`, `confidence`
- **ML Features**: Process-to-domain mapping, first-contact anomaly scoring

### 3.9 BlockedDomainHitProbe
- **MITRE**: T1071.004, T1566 (Phishing)
- **Attributes**: `domain`, `blocklist_name`, `category`, `process_name`, `source_ip`, `risk_score`, `confidence`
- **ML Features**: Blocklist hit correlation, category-based risk weighting

**DB Table**: `dns_events` (20 columns)
**Key ML Signals**: domain, dga_score, is_beaconing, beacon_interval_seconds, is_tunneling, query_type, response_code

---

## 4. FIM Agent (File Integrity Monitoring) — 9 Probes

Monitors filesystem changes for tampering, persistence, and data manipulation.

### 4.1 CriticalSystemFileChangeProbe
- **MITRE**: T1036, T1547, T1574
- **Attributes**: `path`, `change_type`, `old_hash`, `new_hash`, `old_mode`, `new_mode`, `file_extension`, `is_critical_path`, `risk_score`, `confidence`
- **ML Features**: Critical path change frequency, hash delta analysis

### 4.2 SUIDBitChangeProbe
- **MITRE**: T1548.001 (Setuid/Setgid), T1068
- **Attributes**: `path`, `old_mode`, `new_mode`, `suid_added`, `sgid_added`, `owner_uid`, `risk_score`, `confidence`
- **ML Features**: SUID/SGID bit flip rate, unexpected privilege elevation on binaries

### 4.3 ServiceCreationProbe
- **MITRE**: T1543, T1053
- **Attributes**: `path`, `service_name`, `service_type`, `exec_command`, `is_new`, `risk_score`, `confidence`
- **ML Features**: New service rate, service command suspiciousness scoring

### 4.4 WebShellDropProbe
- **MITRE**: T1505.003 (Web Shell)
- **Attributes**: `path`, `webroot`, `file_extension`, `file_size`, `content_signatures`, `obfuscation_score`, `risk_score`, `confidence`
- **ML Features**: **High ML value** — web root file entropy analysis, PHP/JSP/ASP payload classification

### 4.5 ConfigBackdoorProbe
- **MITRE**: T1548, T1078, T1556
- **Attributes**: `path`, `config_type`, `change_type`, `backdoor_indicator`, `old_content_hash`, `new_content_hash`, `risk_score`, `confidence`
- **ML Features**: Config file change delta analysis, known backdoor pattern matching

### 4.6 LibraryHijackProbe
- **MITRE**: T1574.006 (Dynamic Linker Hijack), T1014 (Rootkit)
- **Attributes**: `path`, `library_name`, `hijack_type`, `original_path`, `risk_score`, `confidence`
- **ML Features**: Library load path order analysis, unsigned library detection

### 4.7 BootloaderTamperProbe
- **MITRE**: T1542.003 (Bootkit)
- **Attributes**: `path`, `sector`, `hash_before`, `hash_after`, `tamper_type`, `risk_score`, `confidence`
- **ML Features**: Boot sector hash monitoring, EFI variable change detection

### 4.8 WorldWritableSensitiveProbe
- **MITRE**: T1565 (Data Manipulation), T1070 (Indicator Removal)
- **Attributes**: `path`, `mode`, `owner_uid`, `owner_gid`, `is_sensitive`, `sensitivity_reason`, `risk_score`, `confidence`
- **ML Features**: Permission drift monitoring, sensitive file exposure scoring

### 4.9 ExtendedAttributesProbe
- **MITRE**: T1222.002, T1036
- **Attributes**: `path`, `xattr_name`, `xattr_value`, `change_type`, `quarantine_removed`, `risk_score`, `confidence`
- **ML Features**: Quarantine flag removal detection, xattr manipulation patterns

**DB Table**: `fim_events` (20 columns)
**Key ML Signals**: path, change_type, old_hash, new_hash, old_mode, new_mode, file_extension, risk_score

---

## 5. Flow Agent (Network Flow) — 9 Probes

Monitors network traffic patterns for C2, exfiltration, lateral movement, and scanning.

### 5.1 PortScanSweepProbe
- **MITRE**: T1046 (Network Service Discovery)
- **Attributes**: `src_ip`, `dst_ip`, `unique_ports`, `port_count`, `scan_type` (vertical/horizontal), `risk_score`, `confidence`
- **ML Features**: Port scan velocity, target distribution analysis

### 5.2 LateralSMBWinRMProbe
- **MITRE**: T1021.002 (SMB), T1021.003 (RDP), T1021.006 (WinRM)
- **Attributes**: `src_ip`, `dst_ip`, `dst_port`, `app_protocol`, `flow_count`, `is_new_edge`, `risk_score`, `confidence`
- **ML Features**: **High ML value** — lateral movement graph analysis, new edge detection, attack path reconstruction

### 5.3 DataExfilVolumeSpikeProbe
- **MITRE**: T1041 (Exfil Over C2), T1048 (Exfil Over Alt Protocol)
- **Attributes**: `dst_ip`, `total_bytes_tx`, `baseline_bytes_tx`, `spike_factor`, `threshold_bytes`, `risk_score`, `confidence`
- **ML Features**: **High ML value** — EWMA baseline deviation, per-destination transfer volume anomaly

### 5.4 C2BeaconFlowProbe
- **MITRE**: T1071.001 (Web C2), T1071.004 (DNS C2)
- **Attributes**: `src_ip`, `dst_ip`, `avg_interval_seconds`, `jitter_ratio`, `flow_count`, `avg_bytes_per_flow`, `risk_score`, `confidence`
- **ML Features**: **High ML value** — inter-arrival time distribution, jitter analysis, small-payload periodic flow detection

### 5.5 CleartextCredentialLeakProbe
- **MITRE**: T1552.001 (Credentials In Files)
- **Attributes**: `src_ip`, `dst_ip`, `dst_port`, `protocol`, `cleartext_type`, `risk_score`, `confidence`
- **ML Features**: Cleartext protocol usage monitoring, encryption adoption tracking

### 5.6 SuspiciousTunnelProbe
- **MITRE**: T1090 (Proxy), T1572 (Protocol Tunneling)
- **Attributes**: `src_ip`, `dst_ip`, `dst_port`, `duration_seconds`, `total_bytes`, `packet_count`, `tunnel_type`, `risk_score`, `confidence`
- **ML Features**: Long-lived connection analysis, tunnel characteristics clustering

### 5.7 InternalReconDNSFlowProbe
- **MITRE**: T1046, T1590 (Victim Network Info)
- **Attributes**: `src_ip`, `unique_hostnames`, `window_seconds`, `query_rate`, `risk_score`, `confidence`
- **ML Features**: Internal DNS query rate anomaly, hostname enumeration detection

### 5.8 NewExternalServiceProbe
- **MITRE**: T1041, T1595 (Active Scanning)
- **Attributes**: `src_ip`, `dst_ip`, `dst_port`, `protocol`, `is_first_seen`, `bytes_tx`, `bytes_rx`, `risk_score`, `confidence`
- **ML Features**: First-contact external service detection, data transfer volume on new connections

### 5.9 TransparentProxyProbe
- **MITRE**: T1185 (Browser Session Hijacking), T1557.002 (ARP Cache Poisoning)
- **Attributes**: `src_ip`, `dst_ip`, `intercepted_protocol`, `proxy_indicator`, `risk_score`, `confidence`
- **ML Features**: MITM detection, proxy chain analysis

**DB Table**: `flow_events` (17 columns)
**Key ML Signals**: src_ip, dst_ip, dst_port, bytes_tx, bytes_rx, protocol, direction

---

## 6. Persistence Agent — 10 Probes

Monitors all macOS/Linux persistence mechanisms for unauthorized modifications.

### 6.1 LaunchAgentDaemonProbe
- **MITRE**: T1543.001, T1037.005
- **Attributes**: `entry_id`, `mechanism` (LAUNCH_AGENT/LAUNCH_DAEMON), `path`, `command`, `user`, `change_type`, `old_command`, `new_command`, `reason`, `risk_score`, `confidence`

### 6.2 SystemdServicePersistenceProbe
- **MITRE**: T1543.002
- **Attributes**: `entry_id`, `path`, `command`, `user`, `enabled`, `change_type`, `reason`, `risk_score`, `confidence`

### 6.3 CronJobPersistenceProbe
- **MITRE**: T1053.003
- **Attributes**: `entry_id`, `path`, `command`, `schedule`, `user`, `change_type`, `reason`, `risk_score`, `confidence`

### 6.4 SSHKeyBackdoorProbe
- **MITRE**: T1098.004
- **Attributes**: `path`, `key_type`, `key_fingerprint`, `authorized_keys_count`, `new_key_added`, `change_type`, `risk_score`, `confidence`

### 6.5 ShellProfileHijackProbe
- **MITRE**: T1037.004, T1546.004
- **Attributes**: `path`, `profile_type`, `injected_command`, `change_type`, `risk_score`, `confidence`

### 6.6 BrowserExtensionPersistenceProbe
- **MITRE**: T1176
- **Attributes**: `extension_id`, `extension_name`, `browser`, `path`, `permissions`, `change_type`, `risk_score`, `confidence`

### 6.7 StartupFolderLoginItemProbe
- **MITRE**: T1547.001, T1037.001
- **Attributes**: `path`, `item_name`, `item_type`, `change_type`, `reason`, `risk_score`, `confidence`

### 6.8 HiddenFilePersistenceProbe
- **MITRE**: T1564, T1053, T1547
- **Attributes**: `path`, `hidden_type`, `is_executable`, `file_age_seconds`, `risk_score`, `confidence`

### 6.9 ConfigProfileProbe
- **MITRE**: T1556.004, T1547
- **Attributes**: `path`, `profile_name`, `payload_types`, `is_mdm_managed`, `change_type`, `risk_score`, `confidence`

### 6.10 AuthPluginProbe
- **MITRE**: T1547.008, T1556.002
- **Attributes**: `path`, `plugin_name`, `plugin_type`, `is_signed`, `change_type`, `risk_score`, `confidence`

**DB Table**: `persistence_events` (19 columns)
**Key ML Signals**: mechanism, path, command, change_type, entry_id, schedule, risk_score
**ML Features**: Persistence mechanism frequency, command suspiciousness scoring, change rate monitoring

---

## 7. Peripheral Agent — 7 Probes

Monitors USB, Bluetooth, and HID devices for physical attack vectors.

### 7.1 USBInventoryProbe — T1200
- **Attributes**: `vendor_id`, `product_id`, `serial_number`, `device_class`, `device_name`, `bus_number`, `is_new`

### 7.2 USBConnectionEdgeProbe — T1200, T1091
- **Attributes**: `vendor_id`, `product_id`, `serial_number`, `device_class`, `connect_time`, `is_first_seen`, `host_id`

### 7.3 USBStorageProbe — T1052, T1091
- **Attributes**: `vendor_id`, `product_id`, `serial_number`, `volume_label`, `filesystem`, `capacity_bytes`, `mount_point`, `files_accessed`

### 7.4 USBNetworkAdapterProbe — T1557, T1200
- **Attributes**: `vendor_id`, `product_id`, `adapter_name`, `mac_address`, `ip_assigned`, `is_rogue`

### 7.5 HIDKeyboardMouseAnomalyProbe — T1200, T1056.001
- **Attributes**: `vendor_id`, `product_id`, `device_type`, `keystroke_speed_wpm`, `is_badusb_pattern`, `risk_score`, `confidence`
- **ML Features**: **High ML value** — keystroke timing analysis, BadUSB detection via typing speed anomaly

### 7.6 BluetoothDeviceProbe — T1200
- **Attributes**: `mac_address`, `device_name`, `device_class`, `rssi`, `is_paired`, `is_new`, `risk_score`, `confidence`

### 7.7 HighRiskPeripheralScoreProbe — T1200, T1091, T1052
- **Attributes**: `vendor_id`, `product_id`, `serial_number`, `device_class`, `risk_factors`, `composite_risk_score`, `risk_score`, `confidence`

**DB Table**: `peripheral_events` (in `device_telemetry`)
**Key ML Signals**: vendor_id, product_id, device_class, is_first_seen, keystroke_speed_wpm

---

## 8. Kernel Audit Agent — 7 Probes

Monitors syscalls via OpenBSM/auditd for kernel-level threats.

### 8.1 ExecveHighRiskProbe — T1059, T1204.002
- **Attributes**: `pid`, `ppid`, `uid`, `euid`, `gid`, `egid`, `exe`, `comm`, `cmdline`, `cwd`, `syscall`, `risk_score`, `confidence`

### 8.2 PrivEscSyscallProbe — T1068, T1548.001
- **Attributes**: `pid`, `uid`, `euid`, `syscall`, `target_uid`, `priv_escalation_type`, `risk_score`, `confidence`

### 8.3 KernelModuleLoadProbe — T1014 (Rootkit), T1547.006
- **Attributes**: `module_name`, `module_path`, `pid`, `uid`, `is_signed`, `load_type`, `risk_score`, `confidence`

### 8.4 PtraceAbuseProbe — T1055, T1055.008
- **Attributes**: `pid`, `target_pid`, `target_comm`, `ptrace_request`, `uid`, `risk_score`, `confidence`

### 8.5 FilePermissionTamperProbe — T1222, T1222.002
- **Attributes**: `path`, `old_mode`, `new_mode`, `pid`, `uid`, `syscall` (chmod/chown), `risk_score`, `confidence`

### 8.6 AuditTamperProbe — T1562.001 (Disable Security Tools), T1070.002
- **Attributes**: `tamper_type`, `target_file`, `pid`, `uid`, `exe`, `risk_score`, `confidence`

### 8.7 SyscallFloodProbe — T1592, T1083
- **Attributes**: `pid`, `syscall`, `call_count`, `window_seconds`, `rate_per_second`, `risk_score`, `confidence`

**DB Table**: `audit_events` (25 columns)
**Key ML Signals**: syscall, pid, ppid, uid, euid, exe, cmdline, target_path, risk_score

---

## 9. Device Discovery Agent — 6 Probes

Discovers network devices and identifies rogue/unauthorized endpoints.

### 9.1 ARPDiscoveryProbe — T1018
- **Attributes**: `ip`, `mac`, `vendor`, `hostname`, `is_new`, `first_seen`, `last_seen`

### 9.2 ActivePortScanFingerprintProbe — T1046
- **Attributes**: `ip`, `open_ports`, `os_fingerprint`, `services`, `scan_time`

### 9.3 NewDeviceRiskProbe — T1200
- **Attributes**: `ip`, `mac`, `vendor`, `hostname`, `device_type`, `risk_score`, `confidence`, `risk_factors`

### 9.4 RogueDHCPDNSProbe — T1557.001 (LLMNR/NBT-NS Poisoning)
- **Attributes**: `rogue_ip`, `service_type` (DHCP/DNS), `legitimate_server`, `risk_score`, `confidence`

### 9.5 ShadowITProbe — T1200
- **Attributes**: `ip`, `mac`, `device_type`, `is_managed`, `management_agent`, `risk_score`, `confidence`

### 9.6 VulnerabilityBannerProbe — T1595
- **Attributes**: `ip`, `port`, `service`, `banner`, `version`, `cve_matches`, `risk_score`, `confidence`

**DB Table**: `device_telemetry` (12 columns)
**Key ML Signals**: ip, mac, vendor, device_type, open_ports, os_fingerprint

---

## 10. Protocol Collectors Agent — 10 Probes

Deep packet inspection for application-layer protocol abuse.

### 10.1 HTTPSuspiciousHeadersProbe — T1071.001
- **Attributes**: `src_ip`, `dst_ip`, `url`, `method`, `user_agent`, `suspicious_headers`, `risk_score`, `confidence`

### 10.2 TLSSSLAnomalyProbe — T1573.002
- **Attributes**: `src_ip`, `dst_ip`, `tls_version`, `cipher_suite`, `cert_issuer`, `cert_subject`, `is_self_signed`, `ja3_hash`, `risk_score`, `confidence`
- **ML Features**: **High ML value** — JA3/JA3S fingerprinting for C2 detection, self-signed cert clustering

### 10.3 SSHBruteForceProbe — T1110, T1021.004
- **Attributes**: `src_ip`, `dst_ip`, `attempt_count`, `success_count`, `username_list`, `risk_score`, `confidence`

### 10.4 DNSTunnelingProbe — T1048.003
- **Attributes**: `domain`, `query_size_avg`, `response_size_avg`, `entropy`, `subdomain_length`, `total_queries`, `bandwidth_estimate`, `risk_score`, `confidence`

### 10.5 SQLInjectionProbe — T1190
- **Attributes**: `src_ip`, `dst_ip`, `url`, `parameter`, `payload_sample`, `injection_type`, `risk_score`, `confidence`

### 10.6 RDPSuspiciousProbe — T1021.001
- **Attributes**: `src_ip`, `dst_ip`, `is_external`, `connection_count`, `risk_score`, `confidence`

### 10.7 FTPCleartextCredsProbe — T1552.001
- **Attributes**: `src_ip`, `dst_ip`, `username_detected`, `risk_score`, `confidence`

### 10.8 SMTPSpamPhishProbe — T1566.001
- **Attributes**: `src_ip`, `dst_ip`, `sender`, `recipient_count`, `subject_suspicious`, `attachment_type`, `risk_score`, `confidence`

### 10.9 IRCP2PC2Probe — T1071.001
- **Attributes**: `src_ip`, `dst_ip`, `channel`, `nickname`, `message_rate`, `risk_score`, `confidence`

### 10.10 ProtocolAnomalyProbe — T1205
- **Attributes**: `src_ip`, `dst_ip`, `expected_protocol`, `actual_behavior`, `anomaly_type`, `risk_score`, `confidence`

**DB Table**: `security_events` + `flow_events`
**Key ML Signals**: ja3_hash, user_agent, tls_version, cipher_suite, injection_type

---

## MITRE ATT&CK Coverage Summary

| Tactic | Techniques Covered | Key Agents |
|--------|-------------------|------------|
| Reconnaissance | T1595, T1592, T1590 | DeviceDiscovery, Flow, KernelAudit |
| Initial Access | T1190, T1200, T1566 | ProtocolCollectors, Peripheral, DNS |
| Execution | T1059 (+ .001/.003/.004/.006), T1204 | Proc, KernelAudit |
| Persistence | T1543 (.001/.002), T1547 (.001/.006/.008), T1053.003, T1037 (.001/.004/.005), T1098.004, T1176, T1556 (.002/.004), T1546.004, T1564 | Persistence (10 probes) |
| Privilege Escalation | T1548 (.001/.003), T1068 | Auth, KernelAudit, FIM |
| Defense Evasion | T1036, T1070 (.002/.005), T1014, T1222 (.002), T1562.001, T1542.003, T1574.006 | Proc, FIM, KernelAudit |
| Credential Access | T1110 (.003), T1552.001, T1556, T1621 | Auth, Flow, ProtocolCollectors |
| Discovery | T1046, T1018, T1083 | Flow, DeviceDiscovery, KernelAudit |
| Lateral Movement | T1021 (.001/.002/.003/.004/.006) | Flow, ProtocolCollectors |
| Collection | T1056.001, T1185 | Peripheral, Flow |
| Command & Control | T1071 (.001/.004), T1568 (.001/.002), T1572, T1573.002, T1090, T1205 | DNS, Flow, ProtocolCollectors |
| Exfiltration | T1041, T1048 (.001/.003), T1052 | Flow, DNS, Peripheral |
| Impact | T1496, T1499, T1565 | Proc, Auth, FIM |

**Total Unique Techniques**: 75+
**Total Probes**: 85 across 10 agents

---

## ML/AI Algorithm Recommendations

### Phase 1: Anomaly Detection (Immediate Priority)

| Algorithm | Data Domain | Purpose | Input Features |
|-----------|------------|---------|----------------|
| **Isolation Forest** | Process events | Detect anomalous process behavior | cpu_percent, memory_rss, cmdline_length, parent_depth |
| **DBSCAN Clustering** | Network flows | Identify C2 beaconing clusters | avg_interval, jitter_ratio, bytes_per_flow |
| **EWMA + Z-Score** | All events | Time-series anomaly on event rates | event_count_per_agent, per_5min_window |
| **Random Forest Classifier** | DNS queries | DGA domain detection | entropy, consonant_ratio, digit_ratio, bigram_score, length |
| **LOF (Local Outlier Factor)** | Auth events | Unusual login pattern detection | login_hour, source_ip_cluster, failure_rate |

### Phase 2: Behavioral Baselines (Next Sprint)

| Algorithm | Data Domain | Purpose | Input Features |
|-----------|------------|---------|----------------|
| **Graph Neural Network** | Process tree + lateral movement | Attack path detection | pid/ppid edges, src_ip/dst_ip edges, protocol labels |
| **LSTM Autoencoder** | Network flow sequences | Sequence anomaly detection | flow_size, direction, port, protocol per time-step |
| **User-Entity Behavior Analytics (UEBA)** | Auth + Process | Per-user behavioral baseline | login_times, processes_run, sudo_frequency, source_ips |
| **Markov Chain** | Persistence events | Detect unusual persistence chains | mechanism_type transitions, time_between_changes |

### Phase 3: Advanced Intelligence (Future)

| Algorithm | Data Domain | Purpose | Input Features |
|-----------|------------|---------|----------------|
| **Transformer (Attention)** | Multi-agent correlation | Cross-agent threat fusion | Events from all 10 agents, temporal alignment |
| **Federated Learning** | Cross-deployment | Learn across deployments without sharing data | Gradient updates from local models |
| **Reinforcement Learning** | Incident response | Automated response recommendations | Threat context, available actions, historical outcomes |
| **GAN (Adversarial)** | All domains | Generate synthetic attack data for training | Agent telemetry features |

### Feature Engineering Priorities

1. **Temporal features**: Event rate per 5min/1h/24h window, time-of-day encoding, day-of-week encoding
2. **Graph features**: In-degree/out-degree of network nodes, process tree depth, lateral movement hop count
3. **Statistical features**: Rolling mean/std/median of risk_score, entropy of domains, EWMA of byte volumes
4. **Categorical encodings**: One-hot for protocol, event_type, mechanism_type; label encoding for severity
5. **Cross-agent features**: Events-per-agent correlation, simultaneous alert count, multi-agent risk fusion

### Data Volume Estimates (per endpoint)

| Agent | Events/Hour (typical) | Events/Hour (under attack) | Storage/Day |
|-------|----------------------|---------------------------|-------------|
| ProcAgent | 50-200 | 1,000-5,000 | ~5 MB |
| AuthGuard | 10-50 | 500-2,000 | ~2 MB |
| DNSAgent | 100-500 | 2,000-10,000 | ~8 MB |
| FIMAgent | 5-20 | 100-500 | ~1 MB |
| FlowAgent | 200-1,000 | 5,000-50,000 | ~20 MB |
| Persistence | 2-10 | 50-200 | ~0.5 MB |
| Peripheral | 1-5 | 10-50 | ~0.2 MB |
| KernelAudit | 50-200 | 2,000-10,000 | ~8 MB |
| DeviceDiscovery | 5-20 | 50-200 | ~1 MB |
| ProtocolCollectors | 100-500 | 2,000-20,000 | ~15 MB |
| **TOTAL** | **~523-2,505** | **~11,710-88,150** | **~60 MB** |

---

## Database Schema Quick Reference

| Table | Columns | Primary Use |
|-------|---------|-------------|
| `process_events` | 15 | Process lifecycle, execution |
| `device_telemetry` | 12 | Device discovery, inventory |
| `flow_events` | 17 | Network traffic, flows |
| `security_events` | 15 | Generic security events |
| `peripheral_events` | 10 | USB/Bluetooth/HID |
| `metrics_timeseries` | 8 | System resource metrics |
| `incidents` | 12 | Incident tracking |
| `alert_rules` | 10 | Alert configuration |
| `wal_archive` | 7 | WAL compaction archive |
| `dns_events` | 20 | DNS queries, DGA, tunneling |
| `audit_events` | 25 | Kernel syscall audit |
| `persistence_events` | 19 | Persistence mechanism changes |
| `fim_events` | 20 | File integrity changes |
| **Total** | **190 columns** | **13 tables** |

---

## Common Attributes Across All Probes

Every probe event includes these base fields (from `TelemetryEvent`):

| Field | Type | Description |
|-------|------|-------------|
| `event_type` | str | Unique event identifier (e.g., `process_spawn`, `dns_dga_detected`) |
| `severity` | enum | LOW, MEDIUM, HIGH, CRITICAL |
| `probe_name` | str | Probe that generated the event |
| `timestamp_ns` | int | Nanosecond-precision timestamp |
| `data` | dict | Probe-specific attributes (see above) |
| `mitre_techniques` | list[str] | MITRE ATT&CK technique IDs |
| `mitre_tactics` | list[str] | MITRE ATT&CK tactic names |
| `risk_score` | float | 0.0-1.0 computed risk |
| `confidence` | float | 0.0-1.0 detection confidence |
| `device_id` | str | Source endpoint identifier |
| `collection_agent` | str | Agent that collected the event |
| `agent_version` | str | Agent software version |

**Ed25519 Signing Chain** (per LocalQueue):
- `sig`: Ed25519 signature of event content
- `prev_sig`: Previous event signature (chain integrity)
- `content_hash`: SHA-256 of event payload
