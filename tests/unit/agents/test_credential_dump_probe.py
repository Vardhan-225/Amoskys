"""Unit tests for CredentialDumpProbe — T1003 / T1555 / T1555.001.

Coverage:
    Vector 1 — Direct credential file access
        - macOS user DB plist (CRITICAL)
        - macOS Keychain DB (HIGH)
        - Linux /etc/shadow (CRITICAL)
        - Whitelisted system daemon → no event
        - Root + root-whitelist tool → no event

    Vector 2 — Credential tool execution
        - Known tool (mimikatz) → CRITICAL
        - Known tool (lazagne) → CRITICAL
        - security dump-keychain → HIGH
        - security find-generic-password → MEDIUM
        - security find-* with no cmdline → no event
        - security with unrelated subcommand → no event
        - dscl ShadowHashData query → MEDIUM
        - dscl -list /Users query → MEDIUM
        - dscl with irrelevant flags → no event
        - sqlite3 on Keychain DB → HIGH
        - sqlite3 on regular DB → no event

    Vector 3 — Keychain access burst
        - 10 rapid find-generic-password calls → keychain_access_burst
        - 9 calls (below threshold) → no burst event
        - Burst resets after firing

    Integration
        - create_kernel_audit_probes() includes CredentialDumpProbe
        - MITRE tags present on all events
        - correlation_group tag present on all events
"""

from __future__ import annotations

import time
from typing import List
from unittest.mock import patch

import pytest

from amoskys.agents.common.probes import ProbeContext, Severity
from amoskys.agents.os.linux.kernel_audit.agent_types import KernelAuditEvent
from amoskys.agents.os.linux.kernel_audit.probes import (
    CredentialDumpProbe,
    create_kernel_audit_probes,
)

# =============================================================================
# Helpers
# =============================================================================

_NOW_NS = int(1_700_000_000 * 1e9)  # fixed timestamp for deterministic tests


def _event(
    syscall: str,
    *,
    path: str = "",
    exe: str = "",
    comm: str = "",
    cmdline: str = "",
    uid: int = 1000,
    euid: int = 1000,
    pid: int = 1234,
    result: str = "success",
) -> KernelAuditEvent:
    return KernelAuditEvent(
        event_id="test-evt",
        timestamp_ns=_NOW_NS,
        host="test-host",
        syscall=syscall,
        exe=exe or None,
        comm=comm or None,
        path=path or None,
        cmdline=cmdline or None,
        uid=uid,
        euid=euid,
        pid=pid,
        result=result,
        raw={},
    )


def _ctx(events: List[KernelAuditEvent]) -> ProbeContext:
    return ProbeContext(
        device_id="host-001",
        agent_name="kernel_audit",
        now_ns=_NOW_NS,
        shared_data={"kernel_events": events},
    )


def _scan(events: List[KernelAuditEvent]) -> list:
    probe = CredentialDumpProbe()
    return probe.scan(_ctx(events))


# =============================================================================
# Vector 1: Direct credential file access
# =============================================================================


class TestCredentialFileAccess:
    """open/openat on credential stores fires appropriate severity."""

    def test_macos_user_db_plist_is_critical(self):
        events = _scan(
            [
                _event(
                    "openat",
                    path="/var/db/dslocal/nodes/Default/users/akash.plist",
                    comm="python3",
                    uid=501,
                )
            ]
        )
        assert len(events) == 1
        ev = events[0]
        assert ev.event_type == "credential_file_access"
        assert ev.severity == Severity.CRITICAL
        assert "macOS user database" in ev.data["reason"]

    def test_keychain_db_is_high(self):
        events = _scan(
            [
                _event(
                    "open",
                    path="/Users/akash/Library/Keychains/login.keychain-db",
                    comm="python3",
                    uid=501,
                )
            ]
        )
        assert len(events) == 1
        assert events[0].severity == Severity.HIGH
        assert events[0].event_type == "credential_file_access"

    def test_system_keychain_is_high(self):
        events = _scan(
            [
                _event(
                    "open",
                    path="/Library/Keychains/System.keychain",
                    comm="unknown_tool",
                    uid=0,
                )
            ]
        )
        assert len(events) == 1
        assert events[0].severity == Severity.HIGH

    def test_linux_shadow_is_critical(self):
        events = _scan(
            [
                _event(
                    "openat",
                    path="/etc/shadow",
                    comm="cat",
                    uid=0,
                )
            ]
        )
        assert len(events) == 1
        assert events[0].severity == Severity.CRITICAL
        assert "shadow" in events[0].data["reason"]

    def test_bsd_master_passwd_is_critical(self):
        events = _scan(
            [_event("openat", path="/etc/master.passwd", comm="strings", uid=500)]
        )
        assert len(events) == 1
        assert events[0].severity == Severity.CRITICAL

    def test_whitelisted_daemon_no_event(self):
        """opendirectoryd accessing user DB is expected — no alert."""
        events = _scan(
            [
                _event(
                    "openat",
                    path="/var/db/dslocal/nodes/Default/users/admin.plist",
                    comm="opendirectoryd",
                    uid=0,
                )
            ]
        )
        assert events == []

    def test_secd_keychain_no_event(self):
        """secd (macOS Keychain daemon) accessing Keychain is expected."""
        events = _scan(
            [
                _event(
                    "open",
                    path="/Users/akash/Library/Keychains/login.keychain-db",
                    comm="secd",
                    uid=501,
                )
            ]
        )
        assert events == []

    def test_root_whitelist_tool_no_event(self):
        """sysadminctl run by root accessing credential files is allowed."""
        events = _scan(
            [
                _event(
                    "openat",
                    path="/var/db/dslocal/nodes/Default/users/admin.plist",
                    comm="sysadminctl",
                    uid=0,
                )
            ]
        )
        assert events == []

    def test_irrelevant_path_no_event(self):
        """Normal file access should produce nothing."""
        events = _scan(
            [_event("openat", path="/tmp/innocent.txt", comm="cat", uid=501)]
        )
        assert events == []

    def test_read_syscall_ignored(self):
        """read() on shadow — not an open, should not fire."""
        events = _scan([_event("read", path="/etc/shadow", comm="cat", uid=0)])
        assert events == []


# =============================================================================
# Vector 2: Credential tool execution
# =============================================================================


class TestKnownTools:
    """Known credential dump tools fire CRITICAL."""

    def test_mimikatz_is_critical(self):
        events = _scan([_event("execve", exe="/tmp/mimikatz", comm="mimikatz", uid=0)])
        assert len(events) == 1
        assert events[0].event_type == "known_cred_dump_tool"
        assert events[0].severity == Severity.CRITICAL
        assert events[0].confidence >= 0.95

    def test_lazagne_is_critical(self):
        events = _scan(
            [_event("execve", exe="/home/user/.local/lazagne", comm="lazagne", uid=501)]
        )
        assert len(events) == 1
        assert events[0].severity == Severity.CRITICAL

    def test_keychaindumper_is_critical(self):
        events = _scan([_event("execve", exe="/usr/local/bin/keychaindumper", uid=0)])
        assert len(events) == 1
        assert events[0].severity == Severity.CRITICAL

    def test_chainbreaker_is_critical(self):
        events = _scan([_event("execve", exe="/opt/tools/chainbreaker", uid=0)])
        assert len(events) == 1
        assert events[0].severity == Severity.CRITICAL

    def test_case_insensitive_match(self):
        """LaZagne (mixed case) must still be detected."""
        events = _scan([_event("execve", exe="/tmp/LaZagne", uid=501)])
        assert len(events) == 1
        assert events[0].severity == Severity.CRITICAL


class TestSecurityCLI:
    """`security` command with credential subcommands."""

    def test_dump_keychain_is_high(self):
        events = _scan(
            [
                _event(
                    "execve",
                    exe="/usr/bin/security",
                    cmdline="security dump-keychain",
                    uid=501,
                )
            ]
        )
        assert len(events) == 1
        assert events[0].event_type == "keychain_security_exec"
        assert events[0].severity == Severity.HIGH
        assert events[0].data["subcommand"] == "dump-keychain"

    def test_export_is_high(self):
        events = _scan(
            [
                _event(
                    "execve",
                    exe="/usr/bin/security",
                    cmdline="security export -t certs -f pkcs12 -o /tmp/out.p12",
                    uid=501,
                )
            ]
        )
        assert len(events) == 1
        assert events[0].severity == Severity.HIGH

    def test_find_generic_password_is_medium(self):
        events = _scan(
            [
                _event(
                    "execve",
                    exe="/usr/bin/security",
                    cmdline="security find-generic-password -s MyService",
                    uid=501,
                )
            ]
        )
        assert len(events) == 1
        assert events[0].severity == Severity.MEDIUM
        assert events[0].data["subcommand"] == "find-generic-password"

    def test_find_internet_password_is_medium(self):
        events = _scan(
            [
                _event(
                    "execve",
                    exe="/usr/bin/security",
                    cmdline="security find-internet-password -s github.com",
                    uid=501,
                )
            ]
        )
        assert len(events) == 1
        assert events[0].severity == Severity.MEDIUM

    def test_security_no_cmdline_no_event(self):
        """security executed with no cmdline — can't determine subcommand."""
        events = _scan([_event("execve", exe="/usr/bin/security", uid=501)])
        assert events == []

    def test_security_unrelated_subcommand_no_event(self):
        """security list-keychains is not a credential exfil command."""
        events = _scan(
            [
                _event(
                    "execve",
                    exe="/usr/bin/security",
                    cmdline="security list-keychains",
                    uid=501,
                )
            ]
        )
        assert events == []


class TestDsclCLI:
    """`dscl` invocations that query credential attributes."""

    def test_shadow_hash_data_query_fires(self):
        events = _scan(
            [
                _event(
                    "execve",
                    exe="/usr/bin/dscl",
                    cmdline="dscl . -read /Users/victim ShadowHashData",
                    uid=0,
                )
            ]
        )
        assert len(events) == 1
        assert events[0].event_type == "dscl_credential_query"
        assert events[0].severity == Severity.MEDIUM

    def test_auth_authority_query_fires(self):
        events = _scan(
            [
                _event(
                    "execve",
                    exe="/usr/bin/dscl",
                    cmdline="dscl . -read /Users/victim AuthenticationAuthority",
                    uid=0,
                )
            ]
        )
        assert len(events) == 1
        assert events[0].event_type == "dscl_credential_query"

    def test_list_users_fires(self):
        events = _scan(
            [
                _event(
                    "execve",
                    exe="/usr/bin/dscl",
                    cmdline="dscl . -list /Users",
                    uid=501,
                )
            ]
        )
        assert len(events) == 1
        assert events[0].event_type == "dscl_credential_query"

    def test_dscl_create_no_event(self):
        """dscl -create is an admin op, not a credential read."""
        events = _scan(
            [
                _event(
                    "execve",
                    exe="/usr/bin/dscl",
                    cmdline="dscl . -create /Users/newuser",
                    uid=0,
                )
            ]
        )
        assert events == []

    def test_dscl_no_cmdline_no_event(self):
        events = _scan([_event("execve", exe="/usr/bin/dscl", uid=0)])
        assert events == []


class TestSqlite3Keychain:
    """`sqlite3` directly querying Keychain database files."""

    def test_sqlite3_keychain_fires(self):
        events = _scan(
            [
                _event(
                    "execve",
                    exe="/usr/bin/sqlite3",
                    cmdline='sqlite3 /Users/akash/Library/Keychains/login.keychain-db "SELECT * FROM genp"',
                    uid=501,
                )
            ]
        )
        assert len(events) == 1
        assert events[0].event_type == "sqlite3_keychain_access"
        assert events[0].severity == Severity.HIGH
        assert events[0].confidence >= 0.85

    def test_sqlite3_regular_db_no_event(self):
        events = _scan(
            [
                _event(
                    "execve",
                    exe="/usr/bin/sqlite3",
                    cmdline="sqlite3 /Users/akash/app.db",
                    uid=501,
                )
            ]
        )
        assert events == []

    def test_sqlite3_no_cmdline_no_event(self):
        events = _scan([_event("execve", exe="/usr/bin/sqlite3", uid=501)])
        assert events == []


# =============================================================================
# Vector 3: Keychain access burst
# =============================================================================


class TestKeychainBurst:
    """Burst detection: >10 security find-* calls within 60s from one PID."""

    def _build_burst_events(self, count: int, pid: int = 999) -> List[KernelAuditEvent]:
        """Build `count` security find-generic-password events for the same PID."""
        ts_base = _NOW_NS
        return [
            KernelAuditEvent(
                event_id=f"burst-{i}",
                timestamp_ns=ts_base + i * int(1e9),  # 1 second apart
                host="test-host",
                syscall="execve",
                exe="/usr/bin/security",
                cmdline="security find-generic-password -s Service",
                pid=pid,
                uid=501,
                raw={},
            )
            for i in range(count)
        ]

    def test_burst_at_threshold_fires(self):
        """Exactly 10 calls should trigger the burst event."""
        probe = CredentialDumpProbe()
        ctx = _ctx(self._build_burst_events(10))
        events = probe.scan(ctx)

        burst_events = [e for e in events if e.event_type == "keychain_access_burst"]
        assert len(burst_events) == 1
        assert burst_events[0].severity == Severity.HIGH
        assert burst_events[0].data["call_count"] == 10

    def test_below_threshold_no_burst(self):
        """9 calls should not trigger a burst event."""
        probe = CredentialDumpProbe()
        ctx = _ctx(self._build_burst_events(9))
        events = probe.scan(ctx)

        burst_events = [e for e in events if e.event_type == "keychain_access_burst"]
        assert len(burst_events) == 0

    def test_burst_also_emits_per_event_alerts(self):
        """The 10 individual events still fire keychain_security_exec (MEDIUM)."""
        probe = CredentialDumpProbe()
        ctx = _ctx(self._build_burst_events(10))
        events = probe.scan(ctx)

        per_event = [e for e in events if e.event_type == "keychain_security_exec"]
        assert len(per_event) == 10  # one per execve

    def test_burst_resets_after_firing(self):
        """After a burst fires, the window clears — a second scan of the same
        9 calls should NOT fire again immediately."""
        probe = CredentialDumpProbe()

        # First scan: trigger burst
        ctx1 = _ctx(self._build_burst_events(10, pid=42))
        probe.scan(ctx1)

        # Second scan: same probe, 9 more calls in same window
        ctx2 = _ctx(self._build_burst_events(9, pid=42))
        events2 = probe.scan(ctx2)

        burst_events = [e for e in events2 if e.event_type == "keychain_access_burst"]
        assert len(burst_events) == 0

    def test_burst_window_evicts_old_events(self):
        """Calls outside the 60s window should not contribute to burst count."""
        probe = CredentialDumpProbe()

        # Inject 9 events with timestamps 120 seconds before now
        old_ts = _NOW_NS - int(120 * 1e9)
        old_events = [
            KernelAuditEvent(
                event_id=f"old-{i}",
                timestamp_ns=old_ts,
                host="test-host",
                syscall="execve",
                exe="/usr/bin/security",
                cmdline="security find-generic-password -s S",
                pid=77,
                uid=501,
                raw={},
            )
            for i in range(9)
        ]
        # Inject 5 events with timestamps at _NOW_NS (within window)
        new_events = [
            KernelAuditEvent(
                event_id=f"new-{i}",
                timestamp_ns=_NOW_NS,
                host="test-host",
                syscall="execve",
                exe="/usr/bin/security",
                cmdline="security find-generic-password -s S",
                pid=77,
                uid=501,
                raw={},
            )
            for i in range(5)
        ]

        # First pass: old events recorded in state
        ctx1 = _ctx(old_events)
        probe.scan(ctx1)

        # Second pass: now_ns = _NOW_NS, old events outside 60s window → evicted
        # only 5 new events count → below threshold of 10
        ctx2 = _ctx(new_events)
        events = probe.scan(ctx2)

        burst_events = [e for e in events if e.event_type == "keychain_access_burst"]
        assert len(burst_events) == 0

    def test_different_pids_tracked_independently(self):
        """Two different PIDs each hitting threshold fire two separate bursts."""
        probe = CredentialDumpProbe()
        events_pid1 = self._build_burst_events(10, pid=100)
        events_pid2 = self._build_burst_events(10, pid=200)
        ctx = _ctx(events_pid1 + events_pid2)
        events = probe.scan(ctx)

        burst_events = [e for e in events if e.event_type == "keychain_access_burst"]
        assert len(burst_events) == 2
        pids = {e.data["pid"] for e in burst_events}
        assert pids == {100, 200}


# =============================================================================
# Event quality checks
# =============================================================================


class TestEventQuality:
    """All fired events have correct MITRE tags and correlation group."""

    def _all_events_from_each_vector(self) -> list:
        probe = CredentialDumpProbe()

        events_v1 = _event("openat", path="/etc/shadow", comm="cat", uid=0)
        events_v2a = _event("execve", exe="/tmp/mimikatz", uid=0)
        events_v2b = _event(
            "execve",
            exe="/usr/bin/security",
            cmdline="security dump-keychain",
            uid=501,
        )
        burst_evts = [
            KernelAuditEvent(
                event_id=f"b-{i}",
                timestamp_ns=_NOW_NS + i * int(1e9),
                host="h",
                syscall="execve",
                exe="/usr/bin/security",
                cmdline="security find-generic-password -s X",
                pid=55,
                uid=501,
                raw={},
            )
            for i in range(10)
        ]
        ctx = _ctx([events_v1, events_v2a, events_v2b] + burst_evts)
        return probe.scan(ctx)

    def test_all_events_have_mitre_techniques(self):
        for ev in self._all_events_from_each_vector():
            assert ev.mitre_techniques, f"Missing mitre_techniques on {ev.event_type}"
            assert "T1003" in ev.mitre_techniques or "T1555" in ev.mitre_techniques

    def test_all_events_have_correlation_tag(self):
        for ev in self._all_events_from_each_vector():
            assert ev.tags is not None
            assert any(
                "credential_access" in t for t in ev.tags
            ), f"Missing credential_access tag on {ev.event_type}"

    def test_all_events_have_nonzero_confidence(self):
        for ev in self._all_events_from_each_vector():
            assert ev.confidence is not None
            assert ev.confidence > 0


# =============================================================================
# Integration: probe registry
# =============================================================================


class TestProbeRegistry:
    def test_create_kernel_audit_probes_includes_credential_dump(self):
        probes = create_kernel_audit_probes()
        names = [p.name for p in probes]
        assert "credential_dump" in names

    def test_credential_dump_probe_count(self):
        """Registry now has 8 probes."""
        probes = create_kernel_audit_probes()
        assert len(probes) == 8

    def test_credential_dump_probe_platforms(self):
        probe = CredentialDumpProbe()
        # CredentialDumpProbe lives in kernel_audit (Linux-only)
        assert "linux" in probe.platforms

    def test_credential_dump_probe_requires_fields(self):
        probe = CredentialDumpProbe()
        assert "kernel_events" in probe.requires_fields
