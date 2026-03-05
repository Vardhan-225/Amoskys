#!/usr/bin/env python3
"""Tests for KernelAudit v2 Micro-Probes.

Tests the 7 kernel audit probes with various attack scenarios:
    1. ExecveHighRiskProbe - Execution from /tmp, /dev/shm
    2. PrivEscSyscallProbe - setuid privilege escalation
    3. KernelModuleLoadProbe - Rootkit/module loading
    4. PtraceAbuseProbe - Process injection
    5. FilePermissionTamperProbe - chmod on /etc/shadow
    6. AuditTamperProbe - Attempts to blind audit
    7. SyscallFloodProbe - High volume syscalls
"""

import time
from typing import List

import pytest

from amoskys.agents.common.probes import ProbeContext, Severity, TelemetryEvent
from amoskys.agents.kernel_audit.agent_types import KernelAuditEvent
from amoskys.agents.kernel_audit.probes import (
    AuditTamperProbe,
    ExecveHighRiskProbe,
    FilePermissionTamperProbe,
    KernelModuleLoadProbe,
    PrivEscSyscallProbe,
    PtraceAbuseProbe,
    SyscallFloodProbe,
    create_kernel_audit_probes,
)


def make_context(events: List[KernelAuditEvent]) -> ProbeContext:
    """Create a probe context with kernel events."""
    return ProbeContext(
        device_id="test-host-001",
        agent_name="kernel_audit",
        now_ns=int(time.time() * 1e9),
        shared_data={"kernel_events": events},
    )


def make_event(
    syscall: str = "execve",
    exe: str = "/usr/bin/ls",
    pid: int = 1234,
    uid: int = 1000,
    euid: int = 1000,
    path: str = None,
    result: str = "success",
    **kwargs,
) -> KernelAuditEvent:
    """Create a test kernel audit event."""
    return KernelAuditEvent(
        event_id=f"test-{time.time_ns()}",
        timestamp_ns=int(time.time() * 1e9),
        host="test-host-001",
        syscall=syscall,
        exe=exe,
        pid=pid,
        ppid=kwargs.get("ppid", 1),
        uid=uid,
        euid=euid,
        gid=kwargs.get("gid", 1000),
        egid=kwargs.get("egid", 1000),
        path=path,
        result=result,
        comm=kwargs.get("comm", exe.split("/")[-1] if exe else None),
        cwd=kwargs.get("cwd", "/home/user"),
        dest_pid=kwargs.get("dest_pid"),
        dest_uid=kwargs.get("dest_uid"),
        action=kwargs.get("action"),
    )


# =============================================================================
# Test: create_kernel_audit_probes
# =============================================================================


class TestProbeFactory:
    """Tests for probe factory function."""

    def test_create_kernel_audit_probes_returns_all_probes(self):
        """Verify all 7 probes are created."""
        probes = create_kernel_audit_probes()
        assert len(probes) == 8

        probe_names = {p.name for p in probes}
        expected = {
            "execve_high_risk",
            "privesc_syscall",
            "kernel_module_load",
            "ptrace_abuse",
            "file_permission_tamper",
            "audit_tamper",
            "syscall_flood",
            "credential_dump",
        }
        assert probe_names == expected

    def test_all_probes_have_mitre_techniques(self):
        """Verify all probes have MITRE ATT&CK mappings."""
        probes = create_kernel_audit_probes()
        for probe in probes:
            assert probe.mitre_techniques, f"{probe.name} missing MITRE techniques"
            assert probe.mitre_tactics, f"{probe.name} missing MITRE tactics"


# =============================================================================
# Test: ExecveHighRiskProbe
# =============================================================================


class TestExecveHighRiskProbe:
    """Tests for high-risk execve detection."""

    def test_detects_tmp_execution(self):
        """Execution from /tmp should trigger alert."""
        probe = ExecveHighRiskProbe()
        events = [make_event(syscall="execve", exe="/tmp/malware")]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 1
        assert results[0].event_type == "kernel_execve_high_risk"
        assert results[0].severity == Severity.MEDIUM
        assert "/tmp" in results[0].data["reason"]

    def test_detects_devshm_execution(self):
        """Execution from /dev/shm should trigger alert."""
        probe = ExecveHighRiskProbe()
        events = [make_event(syscall="execve", exe="/dev/shm/payload")]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 1
        assert results[0].severity == Severity.MEDIUM

    def test_escalates_for_root_execution(self):
        """Root execution from risky path should be HIGH severity."""
        probe = ExecveHighRiskProbe()
        events = [make_event(syscall="execve", exe="/tmp/rootkit", uid=0, euid=0)]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 1
        assert results[0].severity == Severity.HIGH
        assert "Root execution" in results[0].data["reason"]

    def test_escalates_for_setuid_execution(self):
        """Setuid execution from risky path should be HIGH severity."""
        probe = ExecveHighRiskProbe()
        events = [make_event(syscall="execve", exe="/tmp/exploit", uid=1000, euid=0)]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 1
        assert results[0].severity == Severity.HIGH
        assert "Setuid" in results[0].data["reason"]

    def test_ignores_safe_paths(self):
        """Execution from /usr/bin should not trigger."""
        probe = ExecveHighRiskProbe()
        events = [make_event(syscall="execve", exe="/usr/bin/ls")]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 0

    def test_ignores_non_execve_syscalls(self):
        """Non-execve syscalls should be ignored."""
        probe = ExecveHighRiskProbe()
        events = [make_event(syscall="open", exe="/tmp/file")]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 0


# =============================================================================
# Test: PrivEscSyscallProbe
# =============================================================================


class TestPrivEscSyscallProbe:
    """Tests for privilege escalation detection."""

    def test_detects_uid_to_root_escalation(self):
        """setuid from non-root to root should be CRITICAL."""
        probe = PrivEscSyscallProbe()
        events = [make_event(syscall="setuid", uid=1000, euid=0, result="success")]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 1
        assert results[0].severity == Severity.CRITICAL
        assert "EUID 0" in results[0].data["reason"]

    def test_detects_seteuid(self):
        """seteuid should also be detected."""
        probe = PrivEscSyscallProbe()
        events = [make_event(syscall="seteuid", uid=1000, euid=0, result="success")]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 1
        assert results[0].severity == Severity.CRITICAL

    def test_detects_uid_euid_mismatch(self):
        """UID/EUID mismatch should be HIGH."""
        probe = PrivEscSyscallProbe()
        events = [make_event(syscall="setreuid", uid=1000, euid=500, result="success")]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 1
        assert results[0].severity == Severity.HIGH
        assert "mismatch" in results[0].data["reason"]

    def test_ignores_failed_syscalls(self):
        """Failed privilege escalation attempts should be ignored."""
        probe = PrivEscSyscallProbe()
        events = [make_event(syscall="setuid", uid=1000, euid=0, result="failed")]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 0

    def test_ignores_non_privesc_syscalls(self):
        """Non-privilege syscalls should be ignored."""
        probe = PrivEscSyscallProbe()
        events = [make_event(syscall="open", uid=1000, euid=0)]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 0


# =============================================================================
# Test: KernelModuleLoadProbe
# =============================================================================


class TestKernelModuleLoadProbe:
    """Tests for kernel module load detection."""

    def test_detects_init_module(self):
        """init_module should trigger CRITICAL alert (cwd is /home/user which is suspicious)."""
        probe = KernelModuleLoadProbe()
        events = [make_event(syscall="init_module", uid=0, euid=0)]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 1
        assert results[0].event_type == "kernel_module_loaded"
        # Note: severity is CRITICAL because default cwd is /home/user (suspicious)
        assert results[0].severity == Severity.CRITICAL

    def test_detects_finit_module(self):
        """finit_module should also be detected (CRITICAL due to suspicious cwd)."""
        probe = KernelModuleLoadProbe()
        events = [make_event(syscall="finit_module", uid=0, euid=0)]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 1
        # Note: severity is CRITICAL because default cwd is /home/user (suspicious)
        assert results[0].severity == Severity.CRITICAL

    def test_escalates_for_suspicious_path(self):
        """Module from /tmp should be CRITICAL."""
        probe = KernelModuleLoadProbe()
        events = [
            make_event(syscall="init_module", uid=0, euid=0, path="/tmp/rootkit.ko")
        ]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 1
        assert results[0].severity == Severity.CRITICAL
        assert "suspicious path" in results[0].data["reason"]

    def test_escalates_for_nonroot_load(self):
        """Non-root module load attempt should be CRITICAL."""
        probe = KernelModuleLoadProbe()
        # Use non-suspicious cwd so non-root check triggers first
        events = [
            make_event(syscall="init_module", uid=1000, euid=1000, cwd="/usr/lib")
        ]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 1
        assert results[0].severity == Severity.CRITICAL
        assert "non-root" in results[0].data["reason"]

    def test_detects_module_unload(self):
        """delete_module should trigger MEDIUM alert."""
        probe = KernelModuleLoadProbe()
        events = [make_event(syscall="delete_module", uid=0, euid=0)]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 1
        assert results[0].event_type == "kernel_module_unloaded"
        assert results[0].severity == Severity.MEDIUM


# =============================================================================
# Test: PtraceAbuseProbe
# =============================================================================


class TestPtraceAbuseProbe:
    """Tests for ptrace abuse detection."""

    def test_detects_ptrace(self):
        """ptrace should trigger HIGH alert (non-root ptracing)."""
        probe = PtraceAbuseProbe()
        events = [make_event(syscall="ptrace", uid=1000, euid=1000, dest_pid=5678)]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 1
        assert results[0].event_type == "kernel_ptrace_abuse"
        # Non-root ptrace gets HIGH severity
        assert results[0].severity == Severity.HIGH

    def test_escalates_for_ptrace_init(self):
        """ptrace on init (pid 1) should be CRITICAL."""
        probe = PtraceAbuseProbe()
        events = [make_event(syscall="ptrace", uid=0, euid=0, dest_pid=1)]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 1
        assert results[0].severity == Severity.CRITICAL
        assert "pid=1" in results[0].data["reason"]

    def test_detects_process_vm_readv(self):
        """process_vm_readv should also be detected."""
        probe = PtraceAbuseProbe()
        events = [make_event(syscall="process_vm_readv", uid=1000, euid=1000)]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 1

    def test_escalates_for_nonroot_ptrace(self):
        """Non-root ptrace should be HIGH."""
        probe = PtraceAbuseProbe()
        events = [make_event(syscall="ptrace", uid=1000, euid=1000, dest_pid=999)]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 1
        assert results[0].severity == Severity.HIGH


# =============================================================================
# Test: FilePermissionTamperProbe
# =============================================================================


class TestFilePermissionTamperProbe:
    """Tests for file permission tampering detection."""

    def test_detects_chmod_shadow(self):
        """chmod on /etc/shadow should be CRITICAL."""
        probe = FilePermissionTamperProbe()
        events = [make_event(syscall="chmod", path="/etc/shadow", uid=0, euid=0)]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 1
        assert results[0].severity == Severity.CRITICAL
        assert "shadow" in results[0].data["reason"]

    def test_detects_chown_sudoers(self):
        """chown on /etc/sudoers should be CRITICAL."""
        probe = FilePermissionTamperProbe()
        events = [make_event(syscall="chown", path="/etc/sudoers", uid=0, euid=0)]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 1
        assert results[0].severity == Severity.CRITICAL

    def test_detects_nonroot_modification(self):
        """Non-root modifying sensitive file should be CRITICAL."""
        probe = FilePermissionTamperProbe()
        events = [make_event(syscall="chmod", path="/etc/passwd", uid=1000, euid=1000)]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 1
        assert results[0].severity == Severity.CRITICAL
        assert "Non-root" in results[0].data["reason"]

    def test_ignores_nonsensitive_files(self):
        """chmod on non-sensitive files should be ignored."""
        probe = FilePermissionTamperProbe()
        events = [make_event(syscall="chmod", path="/home/user/file.txt", uid=1000)]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 0


# =============================================================================
# Test: AuditTamperProbe
# =============================================================================


class TestAuditTamperProbe:
    """Tests for audit tampering detection."""

    def test_detects_audit_log_access(self):
        """Non-auditd access to audit.log should be CRITICAL."""
        probe = AuditTamperProbe()
        events = [
            make_event(
                syscall="open",
                path="/var/log/audit/audit.log",
                comm="malware",
                uid=0,
                euid=0,
            )
        ]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 1
        assert results[0].severity == Severity.CRITICAL
        assert "Non-audit process" in results[0].data["reason"]

    def test_detects_audit_config_modification(self):
        """Modification of audit config should be detected."""
        probe = AuditTamperProbe()
        events = [
            make_event(
                syscall="write",
                path="/etc/audit/audit.rules",
                comm="attacker",
                uid=0,
                euid=0,
            )
        ]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 1

    def test_ignores_auditd_access(self):
        """auditd itself accessing logs should be allowed."""
        probe = AuditTamperProbe()
        events = [
            make_event(
                syscall="open",
                path="/var/log/audit/audit.log",
                comm="auditd",
                uid=0,
                euid=0,
            )
        ]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 0

    def test_detects_nonroot_audit_tool_exec(self):
        """Non-root executing auditctl should be HIGH."""
        probe = AuditTamperProbe()
        events = [
            make_event(
                syscall="execve",
                exe="/usr/sbin/auditctl",
                uid=1000,
                euid=1000,
            )
        ]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 1
        assert results[0].event_type == "kernel_audit_tool_exec"
        assert results[0].severity == Severity.HIGH


# =============================================================================
# Test: SyscallFloodProbe
# =============================================================================


class TestSyscallFloodProbe:
    """Tests for syscall flood detection."""

    def test_detects_high_volume(self):
        """High volume of syscalls should trigger alert."""
        probe = SyscallFloodProbe()

        # Generate 100+ syscalls from same PID
        events = [make_event(syscall="read", pid=1234) for _ in range(150)]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 1
        assert results[0].event_type == "kernel_syscall_flood"
        assert results[0].data["syscall_count"] == 150

    def test_escalates_with_failures(self):
        """High failure rate should escalate severity."""
        probe = SyscallFloodProbe()

        # Generate 100+ syscalls with many failures
        events = [
            make_event(syscall="open", pid=1234, result="failed") for _ in range(100)
        ]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 1
        assert results[0].severity == Severity.HIGH
        assert results[0].data["failure_count"] == 100

    def test_ignores_normal_volume(self):
        """Normal syscall volume should not trigger."""
        probe = SyscallFloodProbe()

        # Generate low volume
        events = [make_event(syscall="read", pid=1234) for _ in range(10)]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 0

    def test_tracks_per_process(self):
        """Flood detection should be per-process."""
        probe = SyscallFloodProbe()

        # 50 from PID 1234, 50 from PID 5678 - neither hits threshold
        events = [make_event(syscall="read", pid=1234) for _ in range(50)]
        events += [make_event(syscall="read", pid=5678) for _ in range(50)]
        context = make_context(events)

        results = probe.scan(context)

        assert len(results) == 0


# =============================================================================
# Test: Integration with KernelAuditAgent
# =============================================================================


class TestKernelAuditAgentIntegration:
    """Integration tests for the v2 agent."""

    def test_agent_setup_with_stub_collector(self):
        """Agent should initialize with stub collector."""
        from amoskys.agents.kernel_audit import (
            KernelAuditAgent,
            StubKernelAuditCollector,
        )

        collector = StubKernelAuditCollector()
        agent = KernelAuditAgent(
            device_id="test-001",
            collector=collector,
        )

        assert agent.setup()
        assert len(agent.probes) == 8

    def test_agent_collects_with_injected_events(self):
        """Agent should process injected events."""
        from amoskys.agents.kernel_audit import (
            KernelAuditAgent,
            StubKernelAuditCollector,
        )

        collector = StubKernelAuditCollector()
        agent = KernelAuditAgent(
            device_id="test-001",
            collector=collector,
        )
        agent.setup()

        # Inject a malicious event
        malicious_event = make_event(
            syscall="execve",
            exe="/tmp/malware",
            uid=1000,
            euid=0,
        )
        collector.inject([malicious_event])

        # Collect and run probes
        results = agent.collect_data()

        # Should detect high-risk execve
        assert len(results) >= 1
        assert any(r.event_type == "kernel_execve_high_risk" for r in results)

    def test_agent_health(self):
        """Agent health should include probe stats."""
        from amoskys.agents.kernel_audit import (
            KernelAuditAgent,
            StubKernelAuditCollector,
        )

        collector = StubKernelAuditCollector()
        agent = KernelAuditAgent(
            device_id="test-001",
            collector=collector,
        )
        agent.setup()

        health = agent.get_health()

        assert health["agent_name"] == "kernel_audit"
        assert health["device_id"] == "test-001"
        assert "probes" in health
        assert len(health["probes"]) == 8
