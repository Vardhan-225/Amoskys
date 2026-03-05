"""Red-team / attacker simulation for CredentialDumpProbe.

This file impersonates an attacker and tests every evasion technique a real
adversary would attempt against each of the three detection vectors.

Each test documents:
    - The attacker's technique
    - The expected result (caught / evades / caught-with-lower-confidence)
    - Why the probe behaves that way

Structure:
    AttackerScenario_DirectFileAccess  — Vector 1 evasion attempts
    AttackerScenario_ToolExecution     — Vector 2 evasion attempts
    AttackerScenario_BurstEvasion      — Vector 3 timing attacks
    AttackerScenario_ChainedAttack     — Full attacker kill-chain simulation
    ProbeGaps                          — Documented blind spots for future work
"""

from __future__ import annotations

import time
from typing import List

import pytest

from amoskys.agents.common.probes import ProbeContext, Severity
from amoskys.agents.kernel_audit.agent_types import KernelAuditEvent
from amoskys.agents.kernel_audit.probes import CredentialDumpProbe

_NOW_NS = int(1_700_000_000 * 1e9)


def _ke(syscall: str, **kwargs) -> KernelAuditEvent:
    defaults = dict(
        event_id="atk",
        timestamp_ns=_NOW_NS,
        host="victim",
        uid=501,
        euid=501,
        pid=31337,
        raw={},
    )
    defaults.update(kwargs)
    return KernelAuditEvent(syscall=syscall, **defaults)


def _ctx(events: list, now_ns: int = _NOW_NS) -> ProbeContext:
    return ProbeContext(
        device_id="victim",
        agent_name="kernel_audit",
        now_ns=now_ns,
        shared_data={"kernel_events": events},
    )


def _scan(events: list, now_ns: int = _NOW_NS) -> list:
    probe = CredentialDumpProbe()
    return probe.scan(_ctx(events, now_ns))


# =============================================================================
# Vector 1 Red Team: Direct file access evasion
# =============================================================================


class TestRedTeam_DirectFileAccess:
    """Attacker attempts to read credential stores without triggering Vector 1."""

    def test_CAUGHT_open_shadow_direct(self):
        """cat /etc/shadow — simplest attack, fully caught."""
        events = _scan([_ke("openat", path="/etc/shadow", comm="cat", uid=0)])
        assert len(events) == 1
        assert events[0].severity == Severity.CRITICAL

    def test_CAUGHT_python_reads_keychain_db(self):
        """Attacker uses Python to open the Keychain DB directly.
        python3 -c 'open("/Users/victim/Library/Keychains/login.keychain-db","rb").read()'
        """
        events = _scan(
            [
                _ke(
                    "openat",
                    path="/Users/victim/Library/Keychains/login.keychain-db",
                    comm="python3",
                    uid=501,
                )
            ]
        )
        assert len(events) == 1
        assert events[0].severity == Severity.HIGH

    def test_CAUGHT_renamed_tool_opens_shadow(self):
        """Attacker renames `cat` to `systemd` to evade comm-based detection.
        The whitelist checks comm, but shadow path detection is path-first —
        any non-whitelisted comm accessing /etc/shadow is flagged.
        The whitelist contains opendirectoryd, not systemd.
        """
        events = _scan([_ke("openat", path="/etc/shadow", comm="systemd", uid=0)])
        # systemd is NOT in the whitelist — caught
        assert len(events) == 1
        assert events[0].severity == Severity.CRITICAL

    def test_CAUGHT_go_binary_reads_user_db(self):
        """Custom Go binary reads macOS user DB plist."""
        events = _scan(
            [
                _ke(
                    "openat",
                    path="/var/db/dslocal/nodes/Default/users/admin.plist",
                    comm="harvest",
                    uid=0,
                )
            ]
        )
        assert len(events) == 1
        assert events[0].severity == Severity.CRITICAL

    def test_EVADES_read_syscall_not_open(self):
        """BLIND SPOT: Attacker already has an fd open (e.g. via mmap or
        inherits from a whitelisted parent). The read() syscall on shadow
        is not monitored — only open/openat are checked.

        Real-world: An attacker could fork from opendirectoryd and inherit
        its file descriptors, then read credentials without a new open().
        This is a documented gap.
        """
        events = _scan([_ke("read", path="/etc/shadow", comm="attacker", uid=0)])
        # Vector 1 only monitors open/openat — read() evades
        assert len(events) == 0  # BLIND SPOT — documented

    def test_EVADES_comm_spoofed_to_whitelisted(self):
        """PARTIAL BLIND SPOT: comm spoofing still evades when exe info is unavailable.
        P1.1 PARTIAL FIX: When exe IS known, masquerade_whitelist_break CRITICAL fires.
        But when exe is absent from the audit event, the cross-check cannot run.
        See test_GAP_comm_can_be_spoofed for the exe-available (now closed) case.
        """
        events = _scan(
            [
                _ke(
                    "openat",
                    path="/var/db/dslocal/nodes/Default/users/root.plist",
                    comm="opendirectoryd",  # Spoofed comm, exe info absent
                    uid=501,
                )
            ]
        )
        # Without exe info, P1.1 cross-check cannot fire — still evades
        assert len(events) == 0  # PARTIAL BLIND SPOT — evades when exe unavailable


# =============================================================================
# Vector 2 Red Team: Tool execution evasion
# =============================================================================


class TestRedTeam_ToolExecution:
    """Attacker tries to call credential tools without triggering Vector 2."""

    def test_CAUGHT_mimikatz_full_path(self):
        """mimikatz in /tmp — canonical attack, caught."""
        events = _scan([_ke("execve", exe="/tmp/mimikatz", uid=0)])
        assert len(events) == 1
        assert events[0].severity == Severity.CRITICAL

    def test_CAUGHT_mimikatz_renamed_binary_comm_reveals_it(self):
        """Attacker renames mimikatz to 'update_helper' but comm still matches.
        In this scenario, the exe path doesn't match but comm does NOT match
        known tools — so this test validates that exe-based detection works.
        """
        # Renamed exe: exe_name derived from exe path = "update_helper"
        # comm = "mimikatz" (set by the binary itself, harder to spoof post-exec)
        events = _scan(
            [
                _ke(
                    "execve",
                    exe="/tmp/update_helper",
                    comm="mimikatz",  # Binary sets its own comm
                    uid=501,
                )
            ]
        )
        # exe_name = "update_helper" → not in known tools
        # comm is not used for tool detection in _check_tool_exec (exe_name takes priority)
        # This EVADES Vector 2 — documented gap, use comm as fallback
        assert len(events) == 0  # BLIND SPOT — exe rename evades tool detection

    def test_CAUGHT_lazagne_via_python_script_name(self):
        """P0.1 CLOSED: python3 lazagne.py is now caught by interpreter scanning.
        exe='python3' → _is_interpreter_exe → _check_interpreter_cmdline →
        'lazagne.py' in _KNOWN_TOOL_SCRIPT_NAMES → interpreter_cred_tool_exec HIGH.
        """
        events = _scan(
            [
                _ke(
                    "execve",
                    exe="/usr/bin/python3",
                    cmdline="python3 /tmp/lazagne.py all",
                    uid=501,
                )
            ]
        )
        # P0.1: interpreter wrapping + known script name now caught
        assert len(events) == 1
        assert events[0].event_type == "interpreter_cred_tool_exec"
        assert events[0].severity == Severity.HIGH

    def test_CAUGHT_security_dump_keychain(self):
        """Baseline: attacker runs security dump-keychain — caught as HIGH."""
        events = _scan(
            [
                _ke(
                    "execve",
                    exe="/usr/bin/security",
                    cmdline="security dump-keychain -d",
                    uid=501,
                )
            ]
        )
        assert len(events) == 1
        assert events[0].severity == Severity.HIGH

    def test_EVADES_security_wrapped_in_sh(self):
        """P0.1 CLOSED: Shell wrapping now caught by interpreter cmdline scanning.
        sh → _is_interpreter_exe → _check_interpreter_cmdline →
        'dump-keychain' in _SECURITY_DUMP_SUBCOMMANDS → interpreter_security_exec HIGH.
        """
        events = _scan(
            [
                _ke(
                    "execve",
                    exe="/bin/sh",
                    cmdline="sh -c 'security dump-keychain -d'",
                    uid=501,
                )
            ]
        )
        # P0.1: shell wrapping now caught
        assert len(events) == 1
        assert events[0].event_type == "interpreter_security_exec"
        assert events[0].severity == Severity.HIGH

    def test_EVADES_bash_heredoc_security(self):
        """P0.1 CLOSED: bash wrapping now caught by interpreter cmdline scanning.
        bash → _is_interpreter_exe → _check_interpreter_cmdline →
        'find-generic-password' in _SECURITY_CRED_SUBCOMMANDS → MEDIUM.
        """
        events = _scan(
            [
                _ke(
                    "execve",
                    exe="/bin/bash",
                    cmdline="bash -c 'security find-generic-password -s AWS'",
                    uid=501,
                )
            ]
        )
        # P0.1: bash wrapping now caught
        assert len(events) == 1
        assert events[0].event_type == "interpreter_security_exec"
        assert events[0].severity == Severity.MEDIUM

    def test_CAUGHT_dscl_shadow_hash(self):
        """dscl ShadowHashData query — caught as MEDIUM."""
        events = _scan(
            [
                _ke(
                    "execve",
                    exe="/usr/bin/dscl",
                    cmdline="dscl . -read /Users/victim ShadowHashData",
                    uid=0,
                )
            ]
        )
        assert len(events) == 1
        assert events[0].event_type == "dscl_credential_query"

    def test_EVADES_dscl_via_osascript(self):
        """P0.1 CLOSED: osascript wrapping now caught by interpreter cmdline scanning.
        osascript is in _SHELL_INTERPRETERS → _check_interpreter_cmdline →
        'ShadowHashData' triggers _is_dscl_cred_query → interpreter_dscl_query MEDIUM.
        """
        events = _scan(
            [
                _ke(
                    "execve",
                    exe="/usr/bin/osascript",
                    cmdline="osascript -e 'do shell script \"dscl . -read /Users/admin ShadowHashData\"'",
                    uid=501,
                )
            ]
        )
        # P0.1: osascript wrapping now caught
        assert len(events) == 1
        assert events[0].event_type == "interpreter_dscl_query"
        assert events[0].severity == Severity.MEDIUM

    def test_CAUGHT_sqlite3_keychain_direct(self):
        """sqlite3 on Keychain DB — caught as HIGH."""
        events = _scan(
            [
                _ke(
                    "execve",
                    exe="/usr/bin/sqlite3",
                    cmdline='sqlite3 /Users/victim/Library/Keychains/login.keychain-db "SELECT * FROM genp"',
                    uid=501,
                )
            ]
        )
        assert len(events) == 1
        assert events[0].severity == Severity.HIGH

    def test_EVADES_sqlite3_lowercase_keychain(self):
        """P1.2 PARTIAL FIX: sqlite3 on /tmp/*.db now emits LOW signal.
        /tmp/kc.db matches _is_temp_db_path → sqlite3_temp_db_access LOW with
        correlation_needed=True. FusionEngine can correlate with prior cp/openat.
        Full confidence still requires correlating with the original keychain copy.
        """
        events = _scan(
            [
                _ke(
                    "execve",
                    exe="/usr/bin/sqlite3",
                    cmdline="sqlite3 /tmp/kc.db 'SELECT * FROM genp'",
                    uid=501,
                )
            ]
        )
        # P1.2: temp DB path detected — LOW signal for correlation
        assert len(events) == 1
        assert events[0].event_type == "sqlite3_temp_db_access"
        assert events[0].severity == Severity.LOW
        assert events[0].data["correlation_needed"] is True


# =============================================================================
# Vector 3 Red Team: Burst timing evasion
# =============================================================================


class TestRedTeam_BurstEvasion:
    """Attacker tries to harvest Keychain credentials below burst detection."""

    def test_CAUGHT_burst_exactly_at_threshold(self):
        """10 calls in 60 seconds — exactly at threshold, caught."""
        probe = CredentialDumpProbe()
        events_in = [
            KernelAuditEvent(
                event_id=f"b{i}",
                timestamp_ns=_NOW_NS + i * int(5e9),  # 5 seconds apart
                host="victim",
                syscall="execve",
                exe="/usr/bin/security",
                cmdline="security find-generic-password -s AWS",
                pid=1000,
                uid=501,
                raw={},
            )
            for i in range(10)
        ]
        result = probe.scan(_ctx(events_in))
        burst = [e for e in result if e.event_type == "keychain_access_burst"]
        assert len(burst) == 1

    def test_EVADES_slow_harvesting_below_burst(self):
        """EVADES: Attacker calls security find-generic-password every 7 seconds.
        60s / 7s = ~8 calls per window. Below the threshold of 10.
        At this rate it takes 70 seconds to trigger — attacker harvests slowly.
        """
        probe = CredentialDumpProbe()
        events_in = [
            KernelAuditEvent(
                event_id=f"slow-{i}",
                timestamp_ns=_NOW_NS + i * int(7e9),  # 7 seconds apart
                host="victim",
                syscall="execve",
                exe="/usr/bin/security",
                cmdline="security find-generic-password -s AWS",
                pid=2000,
                uid=501,
                raw={},
            )
            for i in range(9)  # 9 calls in 56 seconds
        ]
        result = probe.scan(_ctx(events_in, now_ns=_NOW_NS + int(56e9)))
        burst = [e for e in result if e.event_type == "keychain_access_burst"]
        # 9 < 10 threshold → no burst
        assert len(burst) == 0
        # But each individual call still fires MEDIUM keychain_security_exec
        per_event = [e for e in result if e.event_type == "keychain_security_exec"]
        assert len(per_event) == 9

    def test_EVADES_multi_pid_rotation(self):
        """P0.2 CLOSED: Cross-PID burst now caught.
        5 PIDs × 2 calls each = 10 total by uid=501.
        _check_cross_pid_burst: 10 entries ≥ threshold AND 5 PIDs ≥ 2
        → keychain_cross_pid_burst HIGH.
        """
        probe = CredentialDumpProbe()
        events_in = []
        for pid in range(3000, 3005):  # 5 different PIDs
            for i in range(2):  # 2 calls each
                events_in.append(
                    KernelAuditEvent(
                        event_id=f"mpid-{pid}-{i}",
                        timestamp_ns=_NOW_NS + i * int(1e9),
                        host="victim",
                        syscall="execve",
                        exe="/usr/bin/security",
                        cmdline="security find-generic-password -s S",
                        pid=pid,
                        uid=501,
                        raw={},
                    )
                )
        result = probe.scan(_ctx(events_in))
        # No single PID exceeds 2 calls → no per-PID burst
        burst = [e for e in result if e.event_type == "keychain_access_burst"]
        assert len(burst) == 0
        # P0.2: cross-PID burst fires for 5 PIDs × 2 calls by uid=501
        cross_burst = [e for e in result if e.event_type == "keychain_cross_pid_burst"]
        assert len(cross_burst) == 1  # GAP CLOSED
        assert cross_burst[0].data["pid_count"] == 5
        # Still fires 10 MEDIUM per-event alerts
        per_event = [e for e in result if e.event_type == "keychain_security_exec"]
        assert len(per_event) == 10

    def test_EVADES_alternate_service_names(self):
        """EVADES: Attacker uses different service names to look random.
        Burst detection tracks by PID, not service — so using different
        service names (-s AWS, -s GitHub, -s Slack) doesn't help attacker.
        But this test confirms the probe correctly DOES catch this.
        """
        probe = CredentialDumpProbe()
        services = [
            "AWS",
            "GitHub",
            "Slack",
            "Google",
            "Azure",
            "Dropbox",
            "Twitter",
            "LinkedIn",
            "Apple",
            "Okta",
        ]
        events_in = [
            KernelAuditEvent(
                event_id=f"svc-{i}",
                timestamp_ns=_NOW_NS + i * int(1e9),
                host="victim",
                syscall="execve",
                exe="/usr/bin/security",
                cmdline=f"security find-generic-password -s {svc}",
                pid=4000,
                uid=501,
                raw={},
            )
            for i, svc in enumerate(services)
        ]
        result = probe.scan(_ctx(events_in))
        burst = [e for e in result if e.event_type == "keychain_access_burst"]
        assert len(burst) == 1  # CAUGHT — service rotation doesn't help


# =============================================================================
# Full attacker kill-chain simulation
# =============================================================================


class TestRedTeam_ChainedAttack:
    """Simulate a realistic post-compromise credential harvesting sequence.

    Scenario: Attacker has unprivileged shell access (uid=501) on a macOS
    endpoint. They attempt to harvest credentials using multiple techniques.
    """

    def test_realistic_lazagne_style_attack(self):
        """Realistic LaZagne-style attack:
        1. LaZagne binary executes (CRITICAL — known tool)
        2. Internally calls `security find-generic-password` in a loop (burst)
        3. Reads /Users/*/Library/Keychains/login.keychain-db directly (HIGH)
        """
        probe = CredentialDumpProbe()

        # Step 1: The launcher (python3 lazagne.py) — evades tool detection
        # but is caught by ExecveHighRiskProbe if run from /tmp
        launcher = _ke(
            "execve",
            exe="/usr/bin/python3",
            cmdline="python3 /tmp/lazagne.py all",
            uid=501,
        )

        # Step 2: LaZagne internally runs `security find-generic-password`
        # 12 times (10+ = burst)
        security_calls = [
            KernelAuditEvent(
                event_id=f"sec-{i}",
                timestamp_ns=_NOW_NS + i * int(2e9),
                host="victim",
                syscall="execve",
                exe="/usr/bin/security",
                cmdline=f"security find-generic-password -l item{i}",
                pid=5000,
                uid=501,
                raw={},
            )
            for i in range(12)
        ]

        # Step 3: Direct Keychain DB read
        keychain_read = _ke(
            "openat",
            path="/Users/victim/Library/Keychains/login.keychain-db",
            comm="python3",
            uid=501,
        )

        all_events = [launcher] + security_calls + [keychain_read]
        results = probe.scan(_ctx(all_events))

        # Triage what was caught
        by_type = {}
        for ev in results:
            by_type.setdefault(ev.event_type, []).append(ev)

        # 12 individual security calls → 12 MEDIUM keychain_security_exec
        assert len(by_type.get("keychain_security_exec", [])) == 12

        # 12 calls in window → burst fires (HIGH)
        assert len(by_type.get("keychain_access_burst", [])) == 1

        # Keychain DB opened directly → HIGH credential_file_access
        assert len(by_type.get("credential_file_access", [])) == 1
        assert by_type["credential_file_access"][0].severity == Severity.HIGH

        # P0.1: python3 lazagne.py launcher now caught as interpreter_cred_tool_exec
        assert len(by_type.get("interpreter_cred_tool_exec", [])) == 1
        # (still not a known_cred_dump_tool event — different event type)
        assert len(by_type.get("known_cred_dump_tool", [])) == 0

        # Total events: 12 + 1 burst + 1 file access + 1 interpreter = 15
        assert len(results) == 15

    def test_sophisticated_attacker_combined_score(self):
        """Sophisticated attacker uses multiple evasion techniques.
        - Slow Keychain reads via security (7s apart → 9 in 60s, no burst)
        - dscl ShadowHashData queries
        - Direct user DB plist reads

        Multiple MEDIUM/HIGH alerts still fire — correlation in FusionEngine
        should assemble these into a HIGH incident.
        """
        probe = CredentialDumpProbe()

        # Slow security calls (evades burst)
        slow_calls = [
            KernelAuditEvent(
                event_id=f"slow-{i}",
                timestamp_ns=_NOW_NS + i * int(7e9),
                host="victim",
                syscall="execve",
                exe="/usr/bin/security",
                cmdline="security find-generic-password -s target",
                pid=6000,
                uid=501,
                raw={},
            )
            for i in range(8)
        ]

        # dscl query
        dscl_query = _ke(
            "execve",
            exe="/usr/bin/dscl",
            cmdline="dscl . -read /Users/admin ShadowHashData",
            uid=501,
        )

        # User DB direct read
        user_db_read = _ke(
            "openat",
            path="/var/db/dslocal/nodes/Default/users/admin.plist",
            comm="curl",  # suspicious comm trying to look legitimate
            uid=0,
        )

        all_events = slow_calls + [dscl_query, user_db_read]
        now_ns = _NOW_NS + int(56e9)  # 56 seconds elapsed
        results = probe.scan(_ctx(all_events, now_ns=now_ns))

        by_type = {e.event_type: e for e in results}

        # 8 individual security calls → 8 MEDIUM
        medium_count = sum(
            1 for e in results if e.event_type == "keychain_security_exec"
        )
        assert medium_count == 8

        # No burst (8 < 10)
        assert "keychain_access_burst" not in by_type

        # dscl query caught
        assert "dscl_credential_query" in by_type

        # User DB read caught as CRITICAL (curl accessing user DB = very suspicious)
        assert "credential_file_access" in by_type
        assert by_type["credential_file_access"].severity == Severity.CRITICAL

        # Total: 8 MEDIUM + 1 MEDIUM (dscl) + 1 CRITICAL = 10 events
        assert len(results) == 10


# =============================================================================
# Documented gaps (not bugs — design decisions for current scope)
# =============================================================================


class TestRedTeam_Gaps:
    """Tests that document known blind spots in CredentialDumpProbe.

    These are NOT failures — they are architectural decisions.
    Each test records the gap for future probe enhancement.
    """

    def test_GAP_read_syscall_not_monitored(self):
        """GAP: read() on /etc/shadow is not monitored — only open/openat.
        Fix: Add 'read' to the monitored syscalls for Vector 1.
        Risk of FP: read() is very common; need path-correlation with prior open().
        Recommended fix: Track file descriptors opened on cred paths per-PID.
        """
        events = _scan([_ke("read", path="/etc/shadow", comm="attacker", uid=0)])
        assert len(events) == 0  # Confirms gap

    def test_GAP_comm_can_be_spoofed(self):
        """P1.1 CLOSED: comm spoofing with known exe now detected.
        exe='/tmp/attacker' != expected '/usr/libexec/opendirectoryd'
        → masquerade_whitelist_break CRITICAL.
        """
        events = _scan(
            [
                _ke(
                    "openat",
                    path="/var/db/dslocal/nodes/Default/users/admin.plist",
                    comm="opendirectoryd",  # Spoofed
                    exe="/tmp/attacker",  # Real exe
                    uid=501,
                )
            ]
        )
        # P1.1: exe path mismatch → masquerade detected
        assert len(events) == 1  # GAP CLOSED
        assert events[0].event_type == "masquerade_whitelist_break"
        assert events[0].severity == Severity.CRITICAL

    def test_GAP_shell_wrapping_evades_tool_dispatch(self):
        """P0.1 CLOSED: Shell wrapping now caught by interpreter cmdline scanning.
        sh → _is_interpreter_exe → _check_interpreter_cmdline →
        'dump-keychain' found → interpreter_security_exec HIGH.
        """
        events = _scan(
            [
                _ke(
                    "execve",
                    exe="/bin/sh",
                    cmdline="sh -c 'security dump-keychain -d'",
                    uid=501,
                )
            ]
        )
        # P0.1: gap closed — interpreter wrapping now detected
        assert len(events) == 1  # GAP CLOSED
        assert events[0].event_type == "interpreter_security_exec"

    def test_GAP_python_script_lazagne_evades_tool_name_check(self):
        """P0.1 CLOSED: python3 lazagne.py now caught by interpreter cmdline scanning.
        'lazagne.py' is in _KNOWN_TOOL_SCRIPT_NAMES → interpreter_cred_tool_exec HIGH.
        """
        events = _scan(
            [
                _ke(
                    "execve",
                    exe="/usr/bin/python3",
                    cmdline="python3 /tmp/lazagne.py all",
                    uid=501,
                )
            ]
        )
        # P0.1: gap closed — script name in cmdline now detected
        assert len(events) == 1  # GAP CLOSED
        assert events[0].event_type == "interpreter_cred_tool_exec"

    def test_GAP_multi_pid_burst_evasion(self):
        """P0.2 CLOSED: Cross-PID burst now detected.
        10 PIDs × 1 call each = 10 total for uid=501.
        10 entries ≥ threshold AND 10 distinct PIDs ≥ 2 → keychain_cross_pid_burst.
        """
        probe = CredentialDumpProbe()
        events_in = []
        for pid in range(9000, 9010):  # 10 PIDs
            events_in.append(
                KernelAuditEvent(
                    event_id=f"g-{pid}",
                    timestamp_ns=_NOW_NS,
                    host="victim",
                    syscall="execve",
                    exe="/usr/bin/security",
                    cmdline="security find-generic-password -s X",
                    pid=pid,
                    uid=501,
                    raw={},
                )
            )
        result = probe.scan(_ctx(events_in))
        # No per-PID burst (1 call each)
        burst = [e for e in result if e.event_type == "keychain_access_burst"]
        assert len(burst) == 0
        # P0.2: cross-PID burst fires for 10 PIDs × 1 call
        cross_burst = [e for e in result if e.event_type == "keychain_cross_pid_burst"]
        assert len(cross_burst) == 1  # GAP CLOSED by P0.2

    def test_GAP_copy_then_query_pattern(self):
        """P1.2 PARTIAL FIX: sqlite3 on /tmp/*.db now emits LOW signal.
        /tmp/kc.db matches _is_temp_db_path → sqlite3_temp_db_access LOW with
        correlation_needed=True. Full certainty still requires correlating with
        the prior cp/openat on the original keychain file.
        """
        events = _scan(
            [
                _ke(
                    "execve",
                    exe="/usr/bin/sqlite3",
                    cmdline="sqlite3 /tmp/kc.db 'SELECT * FROM genp'",
                    uid=501,
                )
            ]
        )
        # P1.2: partial fix — LOW signal emitted for FusionEngine correlation
        assert len(events) == 1  # GAP PARTIALLY CLOSED by P1.2
        assert events[0].event_type == "sqlite3_temp_db_access"
        assert events[0].severity == Severity.LOW
