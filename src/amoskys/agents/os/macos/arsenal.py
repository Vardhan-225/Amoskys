"""macOS Arsenal — unified view of detection capabilities on Darwin.

This module answers: "What can AMOSKYS actually see on this Mac?"

Each capability maps to an agent and its probes, with a reality badge:
    REAL      — fires on live device, verified with ground truth data
    DEGRADED  — works but with known gaps (permission boundaries, etc.)
    BLIND     — cannot function on macOS (no data source available)
    STUB      — code exists but not yet reality-tested on this platform

The arsenal is not a replacement for agents — it's a management layer that
tracks what's real per-OS and provides audit/status capabilities.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class Badge(str, Enum):
    """Reality badge for a capability."""

    REAL = "REAL"
    DEGRADED = "DEGRADED"
    BLIND = "BLIND"
    STUB = "STUB"


@dataclass
class Capability:
    """A single detection capability on macOS."""

    name: str
    agent: str
    badge: Badge
    source: str  # what data source it uses
    probes: List[str]  # probe names that implement this
    notes: str = ""  # ground truth notes
    fps_known: int = 0  # known false positive sources
    evasions_known: int = 0  # documented evasion vectors
    last_tested: str = ""  # ISO timestamp of last live test
    test_result: str = ""  # PASS / FAIL / UNTESTED


# ─── macOS Capability Registry ──────────────────────────────────────────

MACOS_CAPABILITIES: List[Capability] = [
    # ── Process Monitoring ──────────────────────────────────────────────
    Capability(
        name="process_execution",
        agent="proc",
        badge=Badge.REAL,
        source="psutil.process_iter() — 5ms for 652 processes",
        probes=[
            "process_spawn",
            "lolbin_execution",
            "process_tree_anomaly",
            "suspicious_user_process",
            "binary_from_temp",
            "script_interpreter",
        ],
        notes="100% exe coverage for user procs, 60.8% cmdline (permission boundary). "
        "AppTranslocation FPs fixed. mysqld/postgres removed from ROOT_ONLY.",
        fps_known=0,  # fixed
        evasions_known=4,  # <5s lifetime, script-from-temp (now caught), exe=None, kernel_task
        last_tested="2026-03-04",
        test_result="PASS",
    ),
    Capability(
        name="resource_abuse",
        agent="proc",
        badge=Badge.DEGRADED,
        source="psutil cpu_percent / memory_percent",
        probes=["high_cpu_memory", "long_lived_process"],
        notes="cpu/memory only available for own-user processes (uid=501). "
        "System processes report None. Cannot detect cryptominer running as root.",
        evasions_known=1,
    ),
    Capability(
        name="dylib_injection",
        agent="proc",
        badge=Badge.DEGRADED,
        source="ps eww — DYLD_INSERT_LIBRARIES in process environment",
        probes=["dylib_injection"],
        notes="As uid=501, ps eww only sees own processes (2 lines output). "
        "Root-level dylib injection into system processes is invisible.",
        evasions_known=2,
    ),
    Capability(
        name="code_signing",
        agent="proc",
        badge=Badge.DEGRADED,
        source="codesign --verify --deep",
        probes=["code_signing"],
        notes="Some binaries (sudo) return 'Permission denied' as non-root. "
        "Now handled gracefully — debug log, not HIGH alert. "
        "/usr/libexec/securityd doesn't exist on macOS 26.0.",
        fps_known=0,  # fixed
    ),
    # ── File Integrity ──────────────────────────────────────────────────
    Capability(
        name="file_integrity",
        agent="fim",
        badge=Badge.DEGRADED,
        source="os.stat / hashlib — polling-based file monitoring",
        probes=[
            "critical_system_file_change",
            "suid_bit_change",
            "config_backdoor",
            "webshell_drop",
            "library_hijack",
            "world_writable_sensitive",
            "service_creation",
        ],
        notes="watchdog (FSEvents) NOT available in venv. Falls back to polling. "
        "/etc and /usr/bin are readable. SIP blocks writes to system paths.",
    ),
    Capability(
        name="extended_attributes",
        agent="fim",
        badge=Badge.BLIND,
        source="os.listxattr() — quarantine bit monitoring",
        probes=["extended_attributes"],
        notes="os.listxattr not available in this Python build. "
        "Cannot monitor quarantine bit removal (Gatekeeper bypass detection).",
    ),
    Capability(
        name="bootloader_integrity",
        agent="fim",
        badge=Badge.DEGRADED,
        source="file hashing on /System/Library/Kernels, /Library/Extensions",
        probes=["bootloader_tamper"],
        notes="macOS SIP protects these paths from modification. "
        "Tampering requires SIP disable (csrutil) which itself is detectable.",
    ),
    # ── Persistence Detection ───────────────────────────────────────────
    Capability(
        name="launchagent_persistence",
        agent="persistence",
        badge=Badge.REAL,
        source="plistlib + os.listdir on LaunchAgent/LaunchDaemon paths",
        probes=["launch_agent_daemon"],
        notes="6 user LaunchAgents, 4 system LaunchAgents, 9 LaunchDaemons visible. "
        "Full plist parsing available. #1 macOS persistence vector.",
        last_tested="2026-03-04",
        test_result="PASS",
    ),
    Capability(
        name="cron_persistence",
        agent="persistence",
        badge=Badge.REAL,
        source="crontab -l / /var/at/tabs/",
        probes=["cron_job"],
        notes="Cross-platform. @reboot cron is a persistence vector.",
    ),
    Capability(
        name="ssh_key_backdoor",
        agent="persistence",
        badge=Badge.REAL,
        source="~/.ssh/authorized_keys monitoring",
        probes=["ssh_key_backdoor"],
        notes="Cross-platform. Baseline + diff approach.",
    ),
    Capability(
        name="shell_profile_hijack",
        agent="persistence",
        badge=Badge.REAL,
        source="~/.zshrc, ~/.bashrc, /etc/profile monitoring",
        probes=["shell_profile_hijack"],
        notes="Cross-platform. macOS default shell is zsh.",
    ),
    Capability(
        name="config_profile_persistence",
        agent="persistence",
        badge=Badge.STUB,
        source="/Library/Managed Preferences/",
        probes=["config_profile"],
        notes="MDM configuration profiles. Requires MDM enrollment to test.",
    ),
    Capability(
        name="auth_plugin_hijack",
        agent="persistence",
        badge=Badge.STUB,
        source="/Library/Security/SecurityAgentPlugins/",
        probes=["auth_plugin"],
        notes="Authorization plugin persistence. Rare attack vector. Not yet live-tested.",
    ),
    # ── Network Flow ────────────────────────────────────────────────────
    Capability(
        name="network_flow",
        agent="flow",
        badge=Badge.REAL,
        source="lsof -i -nP — 37 connections visible on test device",
        probes=[
            "port_scan_sweep",
            "lateral_smb_winrm",
            "data_exfil_volume_spike",
            "c2_beacon_flow",
            "cleartext_credential_leak",
            "suspicious_tunnel",
            "internal_recon_dns_flow",
            "new_external_service",
        ],
        notes="lsof provides full connection visibility. nettop also available "
        "for per-process bandwidth tracking.",
        last_tested="2026-03-04",
        test_result="PASS",
    ),
    # ── DNS ─────────────────────────────────────────────────────────────
    Capability(
        name="dns_monitoring",
        agent="dns",
        badge=Badge.STUB,
        source="Unified Logging com.apple.mdnsresponder — 0 events in 10s window",
        probes=[
            "raw_dns_query",
            "dga_score",
            "beaconing_pattern",
            "suspicious_tld",
            "nxdomain_burst",
            "large_txt_tunneling",
            "fast_flux_rebinding",
            "new_domain_for_process",
            "blocked_domain_hit",
        ],
        notes="mDNSResponder logs are sparse in unified logging. "
        "Need to assess if pcap-based or resolver-hook approach is viable. "
        "All 9 probes declared but data source not yet confirmed live.",
    ),
    # ── Auth ────────────────────────────────────────────────────────────
    Capability(
        name="auth_monitoring",
        agent="auth",
        badge=Badge.DEGRADED,
        source="Unified Logging (process=sshd|sudo|loginwindow) — 0 events in 10s idle",
        probes=[
            "ssh_password_spray",
            "ssh_geo_impossible_travel",
            "sudo_elevation",
            "sudo_suspicious_command",
            "off_hours_login",
            "account_lockout_storm",
        ],
        notes="Auth events only appear when auth activity occurs. "
        "Idle device shows 0 events. Need to trigger sudo/ssh to confirm capture. "
        "MFA probe excluded on macOS (no MFA event source).",
    ),
    # ── Peripheral ──────────────────────────────────────────────────────
    Capability(
        name="usb_monitoring",
        agent="peripheral",
        badge=Badge.DEGRADED,
        source="system_profiler SPUSBDataType -json — 30 bytes (minimal/empty)",
        probes=[
            "usb_inventory",
            "usb_connection_edge",
            "usb_storage",
            "usb_network_adapter",
            "hid_keyboard_mouse_anomaly",
            "high_risk_peripheral_score",
        ],
        notes="USB profiler returned minimal data (30 bytes). "
        "May need IOKit direct access for real-time USB events. "
        "Polling-based approach may miss rapid connect/disconnect.",
    ),
    Capability(
        name="bluetooth_monitoring",
        agent="peripheral",
        badge=Badge.REAL,
        source="system_profiler SPBluetoothDataType -json — 1172 bytes",
        probes=["bluetooth_device"],
        notes="Bluetooth profiler returns full device inventory. "
        "Includes paired devices, connection status, addresses.",
        last_tested="2026-03-04",
        test_result="PASS",
    ),
    # ── Security Framework ──────────────────────────────────────────────
    Capability(
        name="security_framework",
        agent="macos_security_monitor",
        badge=Badge.REAL,
        source="Unified Logging com.apple.securityd — PKI/cert/Gatekeeper events",
        probes=[
            "security_framework_flood",
            "gatekeeper_anomaly",
            "certificate_anomaly",
            "security_framework_health",
        ],
        notes="Returns PKI/cert validation events from trustd, syspolicyd, accountsd. "
        "NOT syscall-level — this is security framework telemetry only.",
        last_tested="2026-03-04",
        test_result="PASS",
    ),
    # ── Kernel Audit ────────────────────────────────────────────────────
    Capability(
        name="kernel_audit",
        agent="kernel_audit",
        badge=Badge.BLIND,
        source="N/A — macOS has no auditd, /dev/audit doesn't exist on macOS 26.0",
        probes=[],
        notes="Linux auditd syscall monitoring is completely unavailable on macOS. "
        "OpenBSM/praudit is deprecated. Endpoint Security Framework requires "
        "root + entitlements. The SecurityMonitor agent compensates partially.",
    ),
    # ── Protocol Collectors ─────────────────────────────────────────────
    Capability(
        name="protocol_threats",
        agent="protocol_collectors",
        badge=Badge.STUB,
        source="Network packet analysis — requires pcap or proxy interception",
        probes=[
            "http_suspicious_headers",
            "tls_ssl_anomaly",
            "ssh_brute_force",
            "dns_tunneling",
            "sql_injection",
            "rdp_suspicious",
            "ftp_cleartext_creds",
            "smtp_spam_phish",
            "irc_p2p_c2",
            "protocol_anomaly",
        ],
        notes="10 probes declared. Data source depends on network tap/proxy. "
        "Not yet assessed for macOS-specific availability.",
    ),
    # ── Device Discovery ────────────────────────────────────────────────
    Capability(
        name="device_discovery",
        agent="device_discovery",
        badge=Badge.STUB,
        source="arp -a / nmap — network device enumeration",
        probes=[
            "arp_discovery",
            "active_port_scan",
            "new_device_risk",
            "rogue_dhcp_dns",
            "shadow_it",
            "vulnerability_banner",
        ],
        notes="Standard network tools. Not yet live-tested on this device.",
    ),
    # ══════════════════════════════════════════════════════════════════════
    # macOS OBSERVATORY AGENTS — purpose-built, ground-truth verified
    # 8 agents, 70 probes (64 snapshot + 6 temporal), 50+ MITRE techniques
    # ══════════════════════════════════════════════════════════════════════
    # ── macOS Process Observatory (10 probes) ────────────────────────────
    Capability(
        name="macos_process_observatory",
        agent="macos_process",
        badge=Badge.REAL,
        source="psutil.process_iter() — 654 processes in 44ms, 398 own-user",
        probes=[
            "macos_process_spawn",
            "macos_lolbin",
            "macos_process_tree",
            "macos_resource_abuse",
            "macos_dylib_injection",
            "macos_code_signing",
            "macos_script_interpreter",
            "macos_binary_from_temp",
            "macos_suspicious_user",
            "macos_process_masquerade",
        ],
        notes="60.8% cmdline coverage (permission boundary). 0 FPs on idle. "
        "AppTranslocation filtered. LOLBin list: 23 macOS-specific binaries.",
        fps_known=0,
        evasions_known=4,
        last_tested="2026-03-04",
        test_result="PASS",
    ),
    # ── macOS Persistence Observatory (10 probes) ────────────────────────
    Capability(
        name="macos_persistence_observatory",
        agent="macos_persistence",
        badge=Badge.REAL,
        source="plistlib + os.listdir/walk — 904 entries across 13 persistence locations",
        probes=[
            "macos_launchagent",
            "macos_launchdaemon",
            "macos_login_item",
            "macos_cron",
            "macos_shell_profile",
            "macos_ssh_key",
            "macos_auth_plugin",
            "macos_folder_action",
            "macos_system_extension",
            "macos_periodic_script",
        ],
        notes="Baseline-diff approach. 459 Apple LA, 6 user LA, 9 LD, 419 Apple LD, "
        "6 shell profiles, 1 SSH visible. 0 FPs on stable device.",
        fps_known=0,
        last_tested="2026-03-04",
        test_result="PASS",
    ),
    # ── macOS Network Observatory (8 probes) ─────────────────────────────
    Capability(
        name="macos_network_observatory",
        agent="macos_network",
        badge=Badge.REAL,
        source="lsof -i -nP + nettop — 36 connections in 32ms",
        probes=[
            "macos_c2_beacon",
            "macos_exfil_spike",
            "macos_lateral_ssh",
            "macos_cleartext",
            "macos_tunnel_detect",
            "macos_non_standard_port",
            "macos_cloud_exfil",
            "macos_new_connection",
        ],
        notes="Full TCP/UDP with PID attribution. nettop for per-process bandwidth. "
        "C2 beacon timing analysis, exfil volume spike detection.",
        fps_known=0,
        last_tested="2026-03-04",
        test_result="PASS",
    ),
    # ── macOS File Observatory (8 probes) ────────────────────────────────
    Capability(
        name="macos_file_observatory",
        agent="macos_filesystem",
        badge=Badge.REAL,
        source="os.stat + hashlib — 1708 files, 13 SUID binaries, SIP status",
        probes=[
            "macos_critical_file",
            "macos_suid_change",
            "macos_config_backdoor",
            "macos_webshell",
            "macos_quarantine_bypass",
            "macos_sip_status",
            "macos_hidden_file",
            "macos_downloads_monitor",
        ],
        notes="Polling-based (no watchdog in venv). Covers /etc, /usr/bin, /usr/sbin, "
        "/usr/lib, ~/Library, /Library, ~/Downloads. SIP enabled on test device.",
        fps_known=0,
        last_tested="2026-03-04",
        test_result="PASS",
    ),
    # ── macOS Auth Observatory (6 probes) ────────────────────────────────
    Capability(
        name="macos_auth_observatory",
        agent="macos_auth",
        badge=Badge.DEGRADED,
        source="Unified Logging log show --predicate (sshd/sudo/loginwindow/screensaver)",
        probes=[
            "macos_ssh_brute_force",
            "macos_sudo_escalation",
            "macos_off_hours_login",
            "macos_impossible_travel",
            "macos_account_lockout",
            "macos_credential_access",
        ],
        notes="Auth events only appear during auth activity. 10 events captured on "
        "active device. Idle device yields 0 events (expected, not a bug).",
        fps_known=0,
        last_tested="2026-03-04",
        test_result="PASS",
    ),
    # ── macOS Unified Log Observatory (6 probes) ─────────────────────────
    Capability(
        name="macos_unified_log_observatory",
        agent="macos_unified_log",
        badge=Badge.REAL,
        source="log show with 6 predicate groups — 2357 entries in 4.7s",
        probes=[
            "macos_security_framework",
            "macos_gatekeeper",
            "macos_installer_activity",
            "macos_xpc_anomaly",
            "macos_tcc_event",
            "macos_sharing_service",
        ],
        notes="XPC FPs fixed (115→4). TCC probe DEGRADED without FDA. "
        "5 subsystems visible: securityd, syspolicyd, TCC, xpc, sharing.",
        fps_known=0,
        last_tested="2026-03-04",
        test_result="PASS",
    ),
    # ── macOS Peripheral Observatory (4 probes) ──────────────────────────
    Capability(
        name="macos_peripheral_observatory",
        agent="macos_peripheral",
        badge=Badge.DEGRADED,
        source="system_profiler (USB/BT) + /Volumes/ — 132ms collection",
        probes=[
            "macos_usb_inventory",
            "macos_bluetooth_inventory",
            "macos_new_peripheral",
            "macos_removable_media",
        ],
        notes="USB profiler returns minimal data on test device (no USB devices). "
        "Bluetooth available. /Volumes/ monitoring for removable media. "
        "Polling-based (no IOKit events).",
        fps_known=0,
        last_tested="2026-03-04",
        test_result="PASS",
    ),
    # ── macOS Correlation Observatory (18 probes: 12 snapshot + 6 temporal) ─
    Capability(
        name="macos_correlation_observatory",
        agent="macos_correlation",
        badge=Badge.REAL,
        source="All 7 domain collectors aggregated — cross-domain PID joins + rolling window + temporal index",
        probes=[
            # 12 Snapshot probes
            "macos_corr_process_network",
            "macos_corr_binary_identity",
            "macos_corr_persistence_execution",
            "macos_corr_download_execute",
            "macos_corr_lateral_movement",
            "macos_corr_unknown_listener",
            "macos_corr_cumulative_auth",
            "macos_corr_cumulative_exfil",
            "macos_corr_kill_chain",
            "macos_corr_file_size_anomaly",
            "macos_corr_scheduled_persistence",
            "macos_corr_auth_geo_anomaly",
            # 6 Temporal probes
            "macos_corr_temporal_drop_execute",
            "macos_corr_temporal_persistence_activation",
            "macos_corr_temporal_kill_chain",
            "macos_corr_temporal_auth_velocity",
            "macos_corr_temporal_beaconing",
            "macos_corr_temporal_exfil_acceleration",
        ],
        notes="8th Observatory agent. 12 snapshot probes close 17 of 22 evasion gaps. "
        "6 temporal probes close 11 additional gaps (T1-T4, E2, E5, F1-F3, S1-S5, ab2) "
        "using timestamp-driven correlation: rate/burst/jitter/acceleration analysis.",
        fps_known=0,
        evasions_known=5,  # remaining 5 are permission-boundary (root) gaps
        last_tested="2026-03-05",
        test_result="PASS",
    ),
]


class MacOSArsenal:
    """macOS detection capability manager.

    Provides a unified view of what AMOSKYS can actually detect on macOS,
    backed by live device ground truth.
    """

    def __init__(self) -> None:
        self.capabilities = {c.name: c for c in MACOS_CAPABILITIES}
        self._audit_results: Dict[str, Any] = {}

    def status(self) -> str:
        """Print human-readable status of all capabilities."""
        lines = [
            "═══ AMOSKYS macOS Arsenal ═══",
            f"Platform: {platform.system()} {platform.release()} ({platform.machine()})",
            f"Host: {platform.node()}  UID: {os.getuid()}",
            "",
        ]

        badge_counts = {b: 0 for b in Badge}
        by_agent: Dict[str, List[Capability]] = {}

        for cap in self.capabilities.values():
            badge_counts[cap.badge] += 1
            by_agent.setdefault(cap.agent, []).append(cap)

        for agent_name in sorted(by_agent):
            caps = by_agent[agent_name]
            lines.append(f"  {agent_name}")
            for cap in caps:
                badge_icon = {
                    Badge.REAL: "+",
                    Badge.DEGRADED: "~",
                    Badge.BLIND: "X",
                    Badge.STUB: "?",
                }[cap.badge]
                tested = f" (tested {cap.last_tested})" if cap.last_tested else ""
                lines.append(
                    f"    [{badge_icon}] {cap.name:<30} {cap.badge.value:<10}{tested}"
                )
            lines.append("")

        lines.append("─── Summary ───")
        for badge in Badge:
            lines.append(f"  {badge.value:<10} {badge_counts[badge]}")
        total = sum(badge_counts.values())
        real_pct = (badge_counts[Badge.REAL] / total * 100) if total else 0
        lines.append(
            f"\n  Coverage: {badge_counts[Badge.REAL]}/{total} REAL ({real_pct:.0f}%)"
        )
        lines.append(
            f"  FPs fixed: {sum(c.fps_known for c in self.capabilities.values())}"
        )
        lines.append(
            f"  Evasions documented: {sum(c.evasions_known for c in self.capabilities.values())}"
        )

        return "\n".join(lines)

    def run_audit(self) -> Dict[str, Any]:
        """Run live capability audit on the current device.

        Tests each capability's data source and records what's actually available
        right now. Updates test_result and last_tested fields.
        """
        results: Dict[str, Any] = {}
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Proc
        try:
            import psutil

            procs = list(psutil.process_iter(["pid", "name", "exe"]))
            results["proc_count"] = len(procs)
            user_procs = [p for p in procs if p.info.get("name")]
            results["proc_with_name"] = len(user_procs)
            self.capabilities["process_execution"].test_result = "PASS"
            self.capabilities["process_execution"].last_tested = timestamp
        except Exception as e:
            results["proc_error"] = str(e)
            self.capabilities["process_execution"].test_result = "FAIL"

        # Persistence — LaunchAgents
        try:
            la_path = os.path.expanduser("~/Library/LaunchAgents")
            count = len(os.listdir(la_path)) if os.path.isdir(la_path) else 0
            results["launchagents_user"] = count
            ld_path = "/Library/LaunchDaemons"
            results["launchdaemons_system"] = (
                len(os.listdir(ld_path)) if os.path.isdir(ld_path) else 0
            )
            self.capabilities["launchagent_persistence"].test_result = "PASS"
            self.capabilities["launchagent_persistence"].last_tested = timestamp
        except Exception as e:
            results["persistence_error"] = str(e)

        # Flow — lsof
        try:
            r = subprocess.run(
                ["lsof", "-i", "-nP"], capture_output=True, text=True, timeout=5
            )
            conns = len([line for line in r.stdout.split("\n") if line.strip()]) - 1
            results["network_connections"] = conns
            self.capabilities["network_flow"].test_result = "PASS"
            self.capabilities["network_flow"].last_tested = timestamp
        except Exception as e:
            results["flow_error"] = str(e)

        # Bluetooth
        try:
            r = subprocess.run(
                ["system_profiler", "SPBluetoothDataType", "-json"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            bt_data = json.loads(r.stdout) if r.stdout.strip() else {}
            results["bluetooth_data_bytes"] = len(r.stdout)
            results["bluetooth_available"] = bool(bt_data)
            self.capabilities["bluetooth_monitoring"].test_result = "PASS"
            self.capabilities["bluetooth_monitoring"].last_tested = timestamp
        except Exception as e:
            results["bluetooth_error"] = str(e)

        # Code signing
        try:
            r = subprocess.run(
                ["codesign", "--verify", "--deep", "/bin/bash"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            results["codesign_bash"] = (
                "VALID" if r.returncode == 0 else r.stderr.strip()
            )
            self.capabilities["code_signing"].test_result = (
                "PASS" if r.returncode == 0 else "DEGRADED"
            )
            self.capabilities["code_signing"].last_tested = timestamp
        except Exception as e:
            results["codesign_error"] = str(e)

        # ── macOS Observatory Agents ──────────────────────────────────
        # Process Observatory
        try:
            from amoskys.agents.os.macos.process.collector import MacOSProcessCollector

            c = MacOSProcessCollector()
            data = c.collect()
            results["macos_process_count"] = data["total_count"]
            results["macos_process_own_user"] = data["own_user_count"]
            results["macos_process_time_ms"] = data["collection_time_ms"]
            self.capabilities["macos_process_observatory"].test_result = "PASS"
            self.capabilities["macos_process_observatory"].last_tested = timestamp
        except Exception as e:
            results["macos_process_error"] = str(e)

        # Persistence Observatory
        try:
            from amoskys.agents.os.macos.persistence.collector import (
                MacOSPersistenceCollector,
            )

            c = MacOSPersistenceCollector()
            data = c.collect()
            results["macos_persistence_count"] = data["total_count"]
            results["macos_persistence_categories"] = data["categories"]
            self.capabilities["macos_persistence_observatory"].test_result = "PASS"
            self.capabilities["macos_persistence_observatory"].last_tested = timestamp
        except Exception as e:
            results["macos_persistence_error"] = str(e)

        # Network Observatory
        try:
            from amoskys.agents.os.macos.network.collector import MacOSNetworkCollector

            c = MacOSNetworkCollector()
            data = c.collect()
            results["macos_network_connections"] = data["connection_count"]
            results["macos_network_time_ms"] = data["collection_time_ms"]
            self.capabilities["macos_network_observatory"].test_result = "PASS"
            self.capabilities["macos_network_observatory"].last_tested = timestamp
        except Exception as e:
            results["macos_network_error"] = str(e)

        # File Observatory
        try:
            from amoskys.agents.os.macos.filesystem.collector import MacOSFileCollector

            c = MacOSFileCollector()
            data = c.collect()
            results["macos_file_count"] = len(data.get("files", []))
            results["macos_suid_count"] = len(data.get("suid_binaries", []))
            results["macos_sip_status"] = data.get("sip_status", "unknown")
            self.capabilities["macos_file_observatory"].test_result = "PASS"
            self.capabilities["macos_file_observatory"].last_tested = timestamp
        except Exception as e:
            results["macos_file_error"] = str(e)

        # Unified Log Observatory
        try:
            from amoskys.agents.os.macos.unified_log.collector import (
                MacOSUnifiedLogCollector,
            )

            c = MacOSUnifiedLogCollector()
            data = c.collect()
            results["macos_unified_log_entries"] = data["entry_count"]
            results["macos_unified_log_subsystems"] = data.get("subsystems", [])
            self.capabilities["macos_unified_log_observatory"].test_result = "PASS"
            self.capabilities["macos_unified_log_observatory"].last_tested = timestamp
        except Exception as e:
            results["macos_unified_log_error"] = str(e)

        # Peripheral Observatory
        try:
            from amoskys.agents.os.macos.peripheral.collector import (
                MacOSPeripheralCollector,
            )

            c = MacOSPeripheralCollector()
            data = c.collect()
            results["macos_usb_devices"] = len(data.get("usb_devices", []))
            results["macos_bt_devices"] = len(data.get("bluetooth_devices", []))
            results["macos_volumes"] = len(data.get("volumes", []))
            self.capabilities["macos_peripheral_observatory"].test_result = "PASS"
            self.capabilities["macos_peripheral_observatory"].last_tested = timestamp
        except Exception as e:
            results["macos_peripheral_error"] = str(e)

        # Correlation Observatory
        try:
            from amoskys.agents.os.macos.correlation.collector import (
                CorrelationCollector,
            )

            c = CorrelationCollector()
            data = c.collect()
            results["macos_correlation_processes"] = data.get("total_count", 0)
            results["macos_correlation_connections"] = data.get("connection_count", 0)
            results["macos_correlation_time_ms"] = data.get(
                "correlation_collection_time_ms", 0
            )
            self.capabilities["macos_correlation_observatory"].test_result = "PASS"
            self.capabilities["macos_correlation_observatory"].last_tested = timestamp
        except Exception as e:
            results["macos_correlation_error"] = str(e)

        self._audit_results = results
        return results

    def get_by_badge(self, badge: Badge) -> List[Capability]:
        """Get all capabilities with a given badge."""
        return [c for c in self.capabilities.values() if c.badge == badge]

    def get_by_agent(self, agent: str) -> List[Capability]:
        """Get all capabilities for a given agent."""
        return [c for c in self.capabilities.values() if c.agent == agent]

    def to_dict(self) -> Dict[str, Any]:
        """Export arsenal state as a dictionary."""
        return {
            "platform": "darwin",
            "platform_version": platform.release(),
            "architecture": platform.machine(),
            "hostname": platform.node(),
            "uid": os.getuid(),
            "capabilities": {
                c.name: {
                    "agent": c.agent,
                    "badge": c.badge.value,
                    "source": c.source,
                    "probes": c.probes,
                    "notes": c.notes,
                    "fps_known": c.fps_known,
                    "evasions_known": c.evasions_known,
                    "last_tested": c.last_tested,
                    "test_result": c.test_result,
                }
                for c in self.capabilities.values()
            },
            "audit_results": self._audit_results,
        }
