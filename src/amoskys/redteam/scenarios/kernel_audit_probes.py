"""Kernel audit probe scenarios — 7 probes × 8 adversarial cases each.

Each scenario exercises one kernel-audit micro-probe with:
  - 3 positive cases  (must fire)
  - 3 evasion cases   (documented detection gaps — attacker wins)
  - 2 benign mimics   (must NOT fire — probe correctly ignores)

Probes covered:
    1. ExecveHighRiskProbe      — exec from /tmp, /dev/shm, … (T1059/T1204)
    2. PrivEscSyscallProbe      — setuid/seteuid by non-root (T1068)
    3. KernelModuleLoadProbe    — init_module from suspicious path (T1547/T1014)
    4. PtraceAbuseProbe         — ptrace on protected processes (T1055)
    5. FilePermissionTamperProbe — chmod/chown on /etc/shadow (T1222)
    6. AuditTamperProbe         — audit log access / deletion (T1562)
    7. SyscallFloodProbe        — 100+ syscalls / PID (T1499)

Run:
    amoskys-redteam run execve_high_risk
    amoskys-redteam run privesc_syscall
    amoskys-redteam run kernel_module_load
    amoskys-redteam run ptrace_abuse
    amoskys-redteam run file_permission_tamper
    amoskys-redteam run audit_tamper
    amoskys-redteam run syscall_flood
"""

from __future__ import annotations

from amoskys.agents.common.probes import Severity
from amoskys.agents.os.linux.kernel_audit.agent_types import KernelAuditEvent
from amoskys.agents.os.linux.kernel_audit.probes import (
    AuditTamperProbe,
    ExecveHighRiskProbe,
    FilePermissionTamperProbe,
    KernelModuleLoadProbe,
    PrivEscSyscallProbe,
    PtraceAbuseProbe,
    SyscallFloodProbe,
)
from amoskys.redteam.harness import AdversarialCase, Scenario
from amoskys.redteam.scenarios import register

# ─── Timestamp anchors ───────────────────────────────────────────────────────

_T0 = int(1_700_000_000 * 1e9)  # 2023-11-14T22:13:20Z UTC


def _ke(syscall: str, eid: str, ts: int = _T0, **kwargs) -> KernelAuditEvent:
    """Shorthand KernelAuditEvent factory."""
    defaults: dict = dict(
        event_id=eid,
        timestamp_ns=ts,
        host="victim-host",
        uid=501,
        euid=501,
        pid=12345,
        raw={},
    )
    defaults.update(kwargs)
    return KernelAuditEvent(syscall=syscall, **defaults)  # type: ignore[arg-type]


# =============================================================================
# 1. ExecveHighRiskProbe — exec from /tmp, /dev/shm, /home, /Users, …
# =============================================================================

# ── Positives ──────────────────────────────────────────────────────────────

_EXECVE_POS1 = AdversarialCase(
    id="execve_risk_tmp_user",
    title="/tmp/exploit executed by unprivileged user → MEDIUM",
    category="positive",
    description=(
        "Attacker drops a compiled exploit binary into /tmp and executes it "
        "from their user account (uid=501). /tmp is a high-risk execution "
        "path — no legitimate application ships executables there."
    ),
    why=(
        "execve with exe starting with /tmp/ matches HIGH_RISK_DIRS. "
        "uid==euid==501 (neither setuid nor root) → MEDIUM severity."
    ),
    events=[
        _ke("execve", "ka-e01", exe="/tmp/exploit", comm="exploit", uid=501, euid=501)
    ],
    expect_count=1,
    expect_event_types=["kernel_execve_high_risk"],
    expect_severity=Severity.MEDIUM,
)

_EXECVE_POS2 = AdversarialCase(
    id="execve_risk_setuid_tmp",
    title="/tmp/rootkit runs with euid=0 (setuid binary) → HIGH",
    category="positive",
    description=(
        "Attacker places a setuid-root binary in /tmp and triggers execution. "
        "The binary was compiled with the setuid bit set, so the OS elevates "
        "euid to 0 on exec. Both the location AND the privilege gain are suspicious."
    ),
    why=(
        "exe starts with /tmp/ → HIGH_RISK_DIRS match. "
        "uid=501 but euid=0 (uid!=0 and euid==0) → escalates to HIGH severity."
    ),
    events=[
        _ke("execve", "ka-e02", exe="/tmp/rootkit", comm="rootkit", uid=501, euid=0)
    ],
    expect_count=1,
    expect_event_types=["kernel_execve_high_risk"],
    expect_severity=Severity.HIGH,
)

_EXECVE_POS3 = AdversarialCase(
    id="execve_risk_shm_root",
    title="/dev/shm/c2_agent executed as root → HIGH",
    category="positive",
    description=(
        "/dev/shm is a memory-mapped filesystem — a classic fileless malware "
        "staging area. An attacker with root access drops and executes a C2 "
        "implant here, exploiting that /dev/shm survives across PID boundaries."
    ),
    why=(
        "exe starts with /dev/shm/ → HIGH_RISK_DIRS match. "
        "uid=0 (root execution) → HIGH severity."
    ),
    events=[
        _ke("execve", "ka-e03", exe="/dev/shm/c2_agent", comm="c2_agent", uid=0, euid=0)
    ],
    expect_count=1,
    expect_event_types=["kernel_execve_high_risk"],
    expect_severity=Severity.HIGH,
)

# ── Evasions ───────────────────────────────────────────────────────────────

_EXECVE_EVA1 = AdversarialCase(
    id="execve_evade_private_tmp",
    title="exe at /private/tmp/evil — macOS real path evades /tmp check",
    category="evasion",
    description=(
        "On macOS, /tmp is a symlink to /private/tmp. If the kernel audit "
        "system resolves symlinks before recording the event, the exe path "
        "will appear as /private/tmp/evil — which does NOT start with /tmp/. "
        "The probe checks for /tmp/ prefix and misses the /private/tmp/ path."
    ),
    why=(
        "HIGH_RISK_DIRS contains '/tmp' but not '/private/tmp'. "
        "On macOS hosts where audit logs report the resolved path, "
        "this is a systematic false-negative."
    ),
    events=[
        _ke("execve", "ka-e04", exe="/private/tmp/evil", comm="evil", uid=501, euid=501)
    ],
    expect_evades=True,
)

_EXECVE_EVA2 = AdversarialCase(
    id="execve_evade_var_folders",
    title="exec from /var/folders/… (macOS per-user tmp) — not in HIGH_RISK_DIRS",
    category="evasion",
    description=(
        "macOS creates per-user temp directories under /var/folders/<random>/<random>/. "
        "These are used by many legitimate apps (caches, socket files, etc.) but "
        "are also a staging area for malware. The probe's HIGH_RISK_DIRS list "
        "does not include /var/folders, so execution from there goes undetected."
    ),
    why=(
        "/var/folders/ is not in HIGH_RISK_DIRS — probe skips this exe path entirely. "
        "Attacker stages payload in /var/folders/xx/yy/T/implant."
    ),
    events=[
        _ke(
            "execve",
            "ka-e05",
            exe="/var/folders/xx/yy1234/T/implant",
            comm="implant",
            uid=501,
            euid=501,
        )
    ],
    expect_evades=True,
)

_EXECVE_EVA3 = AdversarialCase(
    id="execve_evade_standard_path",
    title="exec from /usr/local/share/data/malware — standard install path",
    category="evasion",
    description=(
        "Attacker installs malware into /usr/local/share/data/ — a directory "
        "that many legitimate packages use. This path is not in HIGH_RISK_DIRS, "
        "so the probe does not flag it. The attacker trades execution friction "
        "(needs write access to /usr/local) for guaranteed probe evasion."
    ),
    why=(
        "/usr/local/share/data/ is not in HIGH_RISK_DIRS. "
        "The probe only flags /tmp, /var/tmp, /dev/shm, /run/user, /home, "
        "/Users, /Users/Shared — legitimate installation paths are trusted."
    ),
    events=[
        _ke(
            "execve",
            "ka-e06",
            exe="/usr/local/share/data/malware",
            comm="malware",
            uid=501,
            euid=501,
        )
    ],
    expect_evades=True,
)

# ── Benigns ────────────────────────────────────────────────────────────────

_EXECVE_BEN1 = AdversarialCase(
    id="execve_benign_python",
    title="python3 running from /usr/bin/ — system binary, no fire",
    category="benign",
    description=(
        "/usr/bin/python3 is a standard system binary. No attacker would "
        "deploy to /usr/bin (requires root + SIP bypass on macOS). "
        "The probe correctly ignores execution from system paths."
    ),
    why=(
        "/usr/bin/ is not in HIGH_RISK_DIRS → probe skips this event entirely. "
        "No TelemetryEvent is emitted. Zero false positives."
    ),
    events=[
        _ke(
            "execve",
            "ka-e07",
            exe="/usr/bin/python3",
            comm="python3",
            uid=501,
            euid=501,
        )
    ],
    expect_count=0,
    expect_evades=False,
)

_EXECVE_BEN2 = AdversarialCase(
    id="execve_benign_brew",
    title="Homebrew binary at /opt/homebrew/bin/node — no fire",
    category="benign",
    description=(
        "/opt/homebrew/ is the standard Homebrew prefix on Apple Silicon Macs. "
        "Thousands of legitimate binaries live there. Not in HIGH_RISK_DIRS."
    ),
    why=(
        "/opt/homebrew/bin/ not in HIGH_RISK_DIRS → probe ignores. "
        "Zero events emitted for legitimate development tool usage."
    ),
    events=[
        _ke(
            "execve",
            "ka-e08",
            exe="/opt/homebrew/bin/node",
            comm="node",
            uid=501,
            euid=501,
        )
    ],
    expect_count=0,
    expect_evades=False,
)

EXECVE_HIGH_RISK_SCENARIO: Scenario = register(
    Scenario(
        probe_id="execve_high_risk",
        agent="kernel_audit",
        name="execve_high_risk",
        title="Process Exec from High-Risk Directory (T1059 / T1204)",
        description=(
            "An attacker stages payloads in /tmp, /dev/shm, and /var/folders, "
            "then executes them to gain code execution. The ExecveHighRiskProbe "
            "catches /tmp and /dev/shm variants (MEDIUM/HIGH) but misses the "
            "macOS /private/tmp and /var/folders paths — documented gaps."
        ),
        mitre_techniques=["T1059", "T1204"],
        mitre_tactics=["Execution"],
        probe_factory=ExecveHighRiskProbe,
        cases=[
            _EXECVE_POS1,
            _EXECVE_POS2,
            _EXECVE_POS3,
            _EXECVE_EVA1,
            _EXECVE_EVA2,
            _EXECVE_EVA3,
            _EXECVE_BEN1,
            _EXECVE_BEN2,
        ],
    )
)


# =============================================================================
# 2. PrivEscSyscallProbe — setuid/seteuid by non-root
# =============================================================================

_PRIVESC_POS1 = AdversarialCase(
    id="privesc_setuid_gains_root",
    title="setuid(0) by uid=501, result=success → CRITICAL",
    category="positive",
    description=(
        "Attacker exploits a SUID vulnerability to call setuid(0) and gain "
        "root effective UID. The kernel allows this because the binary has the "
        "setuid bit set. After the syscall, uid=501 but euid=0."
    ),
    why=(
        "Syscall is setuid ∈ PRIVESC_SYSCALLS. result='success'. "
        "uid=501 (non-zero) AND euid=0 → CRITICAL severity (full root acquisition)."
    ),
    events=[
        _ke(
            "setuid",
            "ka-p01",
            uid=501,
            euid=0,
            result="success",
            comm="exploit",
            exe="/usr/local/bin/exploit",
        )
    ],
    expect_count=1,
    expect_event_types=["kernel_privesc_syscall"],
    expect_severity=Severity.CRITICAL,
)

_PRIVESC_POS2 = AdversarialCase(
    id="privesc_seteuid_mismatch",
    title="seteuid → uid=501, euid=0 (non-root gains root euid) → CRITICAL",
    category="positive",
    description=(
        "An attacker calls seteuid(0) to set the effective UID to root "
        "without changing the real UID. This enables privilege escalation "
        "while maintaining a non-root real UID (used to bypass some checks)."
    ),
    why=(
        "seteuid ∈ PRIVESC_SYSCALLS. result='success'. "
        "uid=501 (non-root) AND euid=0 (root) → CRITICAL severity. "
        "The probe's severity logic: uid!=0 and euid==0 → CRITICAL (full root "
        "effective privilege gain); uid!=euid with both non-zero → HIGH. "
        "This case hits the CRITICAL branch because euid reaches 0."
    ),
    events=[
        _ke(
            "seteuid",
            "ka-p02",
            uid=501,
            euid=0,
            result="success",
            comm="priv_tool",
        )
    ],
    expect_count=1,
    expect_event_types=["kernel_privesc_syscall"],
    expect_severity=Severity.CRITICAL,
)

_PRIVESC_POS3 = AdversarialCase(
    id="privesc_capset_nonroot",
    title="capset by uid=1000 → MEDIUM",
    category="positive",
    description=(
        "Attacker uses capset() to add CAP_SYS_ADMIN or CAP_NET_RAW to their "
        "capability set without gaining full root. capset by a non-root user "
        "is suspicious — legitimate programs use file capabilities, not runtime "
        "capset calls from unprivileged processes."
    ),
    why=(
        "capset ∈ PRIVESC_SYSCALLS (capability manipulation). result='success'. "
        "uid=1000 (non-root). MEDIUM severity — priv escalation but no full root."
    ),
    events=[
        _ke(
            "capset",
            "ka-p03",
            uid=1000,
            euid=1000,
            result="success",
            comm="exploit_cap",
        )
    ],
    expect_count=1,
    expect_event_types=["kernel_privesc_syscall"],
    expect_severity=Severity.MEDIUM,
)

_PRIVESC_EVA1 = AdversarialCase(
    id="privesc_evade_failed",
    title="setuid(0) failed (EPERM) — probe skips failed syscalls",
    category="evasion",
    description=(
        "An attacker tries setuid(0) but the kernel rejects it (EPERM) because "
        "the binary doesn't have the setuid bit. This attempt is not flagged — "
        "the probe only watches SUCCESSFUL privilege changes. Failed attempts "
        "generate noise but no actual privilege gain."
    ),
    why=(
        "PrivEscSyscallProbe filters result == 'success'. "
        "result='failed' → event is skipped entirely. Zero events emitted. "
        "Limitation: failed attempts could indicate pre-exploitation probing."
    ),
    events=[
        _ke(
            "setuid",
            "ka-p04",
            uid=501,
            euid=501,
            result="failed",
            comm="probe_tool",
        )
    ],
    expect_evades=True,
)

_PRIVESC_EVA2 = AdversarialCase(
    id="privesc_evade_kernel_exploit",
    title="kernel memory write via /proc/kcore — no setuid syscall",
    category="evasion",
    description=(
        "An advanced attacker exploits a kernel vulnerability to write directly "
        "to kernel memory (via /proc/kcore or a eBPF exploit), elevating to "
        "uid=0 without calling any PRIVESC_SYSCALLS. The privilege change happens "
        "entirely in kernel space — no audit event is generated."
    ),
    why=(
        "No setuid/capset syscall is generated → no event in kernel_events. "
        "The probe never sees the privilege escalation. "
        "Kernel exploits that bypass the syscall layer are undetectable by "
        "audit-based probes."
    ),
    events=[
        # openat of /proc/kcore — not a privesc syscall, probe ignores
        _ke(
            "openat",
            "ka-p05",
            uid=501,
            euid=501,
            path="/proc/kcore",
            result="success",
        )
    ],
    expect_evades=True,
)

_PRIVESC_EVA3 = AdversarialCase(
    id="privesc_evade_user_namespace",
    title="uid=0 inside container user namespace — fires but FP risk",
    category="evasion",
    description=(
        "Inside a Docker container with user namespaces, the container root (uid=0 "
        "inside) maps to host uid=1000. The probe sees uid=1000 → euid=0 (inside "
        "namespace) which looks like privilege escalation. "
        "This is actually legitimate container initialization."
    ),
    why=(
        "EVADES as a false positive: probe fires CRITICAL on uid=1000 + euid=0, "
        "but this is legitimate container rootless operation. "
        "The probe cannot distinguish user-namespaced containers from real escalation. "
        "Mitigation: whitelist container runtime PIDs."
    ),
    events=[
        _ke(
            "setuid",
            "ka-p06",
            uid=1000,
            euid=0,
            result="success",
            comm="dockerd",
            exe="/usr/bin/dockerd",
        )
    ],
    # This DOES fire (CRITICAL) — the evasion is that it's a FP for containers
    # We mark it as evasion documenting the FP risk (probe can't suppress it)
    expect_evades=False,  # probe fires — documented as FP_RISK in spec
    expect_count=1,
    expect_event_types=["kernel_privesc_syscall"],
)

_PRIVESC_BEN1 = AdversarialCase(
    id="privesc_benign_openat",
    title="openat syscall — not a privesc syscall, probe ignores",
    category="benign",
    description=(
        "A normal file-open event from an unprivileged process. "
        "openat is not in PRIVESC_SYSCALLS, so the probe correctly ignores it. "
        "Demonstrates the probe's scope is tightly limited to privilege syscalls."
    ),
    why=(
        "openat ∉ PRIVESC_SYSCALLS → probe skips event. Zero events fired. "
        "The probe only watches the specific set of privilege-changing calls."
    ),
    events=[_ke("openat", "ka-p07", uid=501, euid=501, path="/etc/passwd")],
    expect_count=0,
    expect_evades=False,
)

_PRIVESC_BEN2 = AdversarialCase(
    id="privesc_benign_empty",
    title="No kernel events — probe runs cleanly, no output",
    category="benign",
    description=(
        "A quiet system with no privilege syscalls in the collection window. "
        "The probe iterates over an empty event list and returns nothing."
    ),
    why="Empty kernel_events → probe loop does nothing → zero events emitted.",
    events=[],
    expect_count=0,
    expect_evades=False,
)

# ── Nasty benigns: legitimate OS operations the probe cannot suppress ─────────

_PRIVESC_NASTY_SSHD_PRIVSEP = AdversarialCase(
    id="privesc_nasty_sshd_privsep",
    title="sshd drops privileges via seteuid(65534) → HIGH  [documented FP]",
    category="benign",
    description=(
        "sshd privilege separation: the root-owned monitor process calls seteuid "
        "to switch to the 'nobody' (uid=65534) service user before handling "
        "the untrusted network channel. This is a required security feature of "
        "SSH privsep — not an attack. The probe cannot distinguish this from a "
        "real privilege-change attack because the syscall signature is identical."
    ),
    why=(
        "seteuid ∈ PRIVESC_SYSCALLS. result='success'. uid=0 != euid=65534 → "
        "HIGH ('UID/EUID mismatch after seteuid'). FP: every sshd connection "
        "on a privsep-enabled system generates this event. "
        "Remediation: whitelist sshd exe path + uid=0→low-uid transitions."
    ),
    events=[
        _ke(
            "seteuid",
            "ka-p-sshd01",
            uid=0,
            euid=65534,
            result="success",
            comm="sshd",
            exe="/usr/sbin/sshd",
            pid=3001,
        )
    ],
    expect_count=1,
    expect_event_types=["kernel_privesc_syscall"],
    expect_severity=Severity.HIGH,
)

_PRIVESC_NASTY_SUDO = AdversarialCase(
    id="privesc_nasty_sudo_normal",
    title="sudo (already root) calls setresuid(0,0,0) → MEDIUM  [documented FP]",
    category="benign",
    description=(
        "A privileged user runs `sudo` to execute a command. The sudo binary "
        "(already running as root from suid-exec) calls setresuid(0,0,0) to "
        "lock down its uid/euid/saved-uid before exec-ing the target command. "
        "This fires MEDIUM on every single sudo invocation on the system."
    ),
    why=(
        "setresuid ∈ PRIVESC_SYSCALLS. result='success'. uid=0, euid=0 → "
        "neither CRITICAL (uid=0 so first branch misses) nor HIGH (uid==euid) → "
        "MEDIUM ('Privilege escalation syscall: setresuid'). "
        "Every sudo on the system triggers this. FP storm on production hosts."
    ),
    events=[
        _ke(
            "setresuid",
            "ka-p-sudo01",
            uid=0,
            euid=0,
            result="success",
            comm="sudo",
            exe="/usr/bin/sudo",
            pid=3002,
        )
    ],
    expect_count=1,
    expect_event_types=["kernel_privesc_syscall"],
    expect_severity=Severity.MEDIUM,
)

PRIVESC_SYSCALL_SCENARIO: Scenario = register(
    Scenario(
        probe_id="privesc_syscall",
        agent="kernel_audit",
        name="privesc_syscall",
        title="Privilege Escalation via Syscall (T1068)",
        description=(
            "An attacker attempts to escalate privileges using setuid/seteuid/capset. "
            "The probe detects successful transitions to root (CRITICAL), "
            "UID/EUID mismatches (HIGH), and any non-root privesc syscall (MEDIUM). "
            "Known gap: kernel exploits that bypass the syscall layer are invisible."
        ),
        mitre_techniques=["T1068"],
        mitre_tactics=["Privilege Escalation"],
        probe_factory=PrivEscSyscallProbe,
        cases=[
            _PRIVESC_POS1,
            _PRIVESC_POS2,
            _PRIVESC_POS3,
            _PRIVESC_EVA1,
            _PRIVESC_EVA2,
            _PRIVESC_EVA3,
            _PRIVESC_BEN1,
            _PRIVESC_BEN2,
            _PRIVESC_NASTY_SSHD_PRIVSEP,
            _PRIVESC_NASTY_SUDO,
        ],
    )
)


# =============================================================================
# 3. KernelModuleLoadProbe — init_module from suspicious path
# =============================================================================

_KMOD_POS1 = AdversarialCase(
    id="kmod_suspicious_path",
    title="init_module from /tmp/rootkit.ko (suspicious path) → CRITICAL",
    category="positive",
    description=(
        "Attacker loads a kernel rootkit from /tmp/rootkit.ko. Loading a kernel "
        "module from a temp directory is a strong indicator of a rootkit — "
        "legitimate drivers ship in /lib/modules/ or are compiled by DKMS."
    ),
    why=(
        "init_module ∈ MODULE_SYSCALLS. path=/tmp/rootkit.ko starts with /tmp/ "
        "∈ SUSPICIOUS_MODULE_PATHS → CRITICAL severity. "
        "Rootkits hide in kernel space after loading."
    ),
    events=[
        _ke(
            "init_module",
            "ka-k01",
            uid=0,
            euid=0,
            path="/tmp/rootkit.ko",
            comm="insmod",
            exe="/usr/sbin/insmod",
        )
    ],
    expect_count=1,
    expect_event_types=["kernel_module_loaded"],
    expect_severity=Severity.CRITICAL,
)

_KMOD_POS2 = AdversarialCase(
    id="kmod_nonroot_load",
    title="init_module by uid=501 (non-root) → CRITICAL",
    category="positive",
    description=(
        "A non-root user loads a kernel module. On a properly configured Linux "
        "system this requires CAP_SYS_MODULE, which non-root users should not "
        "have. This event indicates either misconfigured capabilities or a "
        "privilege escalation that allowed module loading."
    ),
    why=(
        "init_module ∈ MODULE_SYSCALLS. uid=501 (non-root). "
        "Non-root kernel module load → CRITICAL regardless of path."
    ),
    events=[
        _ke(
            "init_module",
            "ka-k02",
            uid=501,
            euid=501,
            path="/lib/modules/5.15.0/kernel/drivers/net/evil.ko",
            comm="insmod",
        )
    ],
    expect_count=1,
    expect_event_types=["kernel_module_loaded"],
    expect_severity=Severity.CRITICAL,
)

_KMOD_POS3 = AdversarialCase(
    id="kmod_delete_module",
    title="delete_module (rmmod rootkit) → MEDIUM",
    category="positive",
    description=(
        "Attacker unloads a kernel module — either cleaning up a rootkit after "
        "achieving persistence via another mechanism, or hiding their tracks. "
        "Module unloads by non-root or from unexpected contexts are suspicious."
    ),
    why=(
        "delete_module ∈ MODULE_SYSCALLS. "
        "Any module unload generates kernel_module_unloaded at MEDIUM severity. "
        "Low severity reflects that rmmod is sometimes legitimate."
    ),
    events=[
        _ke(
            "delete_module",
            "ka-k03",
            uid=0,
            euid=0,
            path="rootkit_mod",
            comm="rmmod",
            exe="/usr/sbin/rmmod",
        )
    ],
    expect_count=1,
    expect_event_types=["kernel_module_unloaded"],
    expect_severity=Severity.MEDIUM,
)

_KMOD_EVA1 = AdversarialCase(
    id="kmod_evade_ebpf",
    title="eBPF program loaded via bpf() syscall — no init_module → evades",
    category="evasion",
    description=(
        "eBPF programs are loaded using the bpf() syscall, not init_module. "
        "An attacker can deploy a malicious eBPF program that hooks kernel "
        "functions and provides rootkit capabilities without ever triggering "
        "the module-load audit probe. eBPF is increasingly used as a "
        "'rootkit without a rootkit' technique."
    ),
    why=(
        "KernelModuleLoadProbe only watches MODULE_SYSCALLS (init_module, "
        "finit_module, delete_module). bpf() is not in this set → "
        "eBPF-based rootkits evade this probe entirely. "
        "Mitigation: add BPF audit events to MODULE_SYSCALLS."
    ),
    events=[
        # bpf() syscall loading an eBPF prog — not in MODULE_SYSCALLS
        _ke(
            "bpf",
            "ka-k04",
            uid=0,
            euid=0,
            path="/tmp/rootkit.o",
            comm="bpf_loader",
        )
    ],
    expect_evades=True,
)

_KMOD_EVA2 = AdversarialCase(
    id="kmod_evade_kcore_patch",
    title="Direct /proc/kcore kernel patch — no module syscall",
    category="evasion",
    description=(
        "An attacker with root access directly patches kernel memory via "
        "/proc/kcore or /dev/kmem, adding hook points or disabling security "
        "checks without loading any kernel module. No init_module syscall "
        "is called, so the probe is blind to this technique."
    ),
    why=(
        "Kernel memory patching via /proc/kcore generates openat/write audit "
        "events, not MODULE_SYSCALLS. The probe's scope is limited to "
        "the module loading ABI. Advanced kernel patching evades entirely."
    ),
    events=[
        _ke(
            "openat",
            "ka-k05",
            uid=0,
            euid=0,
            path="/proc/kcore",
            comm="patch_tool",
        )
    ],
    expect_evades=True,
)

_KMOD_EVA3 = AdversarialCase(
    id="kmod_evade_no_audit_event",
    title="Module loaded during early boot — before auditd starts",
    category="evasion",
    description=(
        "Kernel modules loaded during initrd / early boot phase run before "
        "auditd is started. These loads are not captured in the audit log "
        "and are therefore invisible to this probe. Attackers who modify "
        "initrd or add modules to /etc/modules-load.d/ evade detection."
    ),
    why=(
        "The probe relies on the auditd subsystem being active. "
        "Early-boot module loads happen before audit rules are applied → "
        "no audit event generated → probe sees nothing."
    ),
    events=[],  # No events because audit wasn't running
    expect_evades=True,
)

_KMOD_BEN1 = AdversarialCase(
    id="kmod_benign_execve",
    title="execve event — not a module load, probe ignores",
    category="benign",
    description=(
        "A normal process execution event. The KernelModuleLoadProbe only "
        "processes events where syscall ∈ MODULE_SYSCALLS. "
        "execve is not in that set."
    ),
    why=(
        "execve ∉ MODULE_SYSCALLS → probe skips. Zero events emitted. "
        "Probe correctly scopes to module-related syscalls only."
    ),
    events=[_ke("execve", "ka-k07", uid=0, exe="/usr/sbin/insmod", comm="insmod")],
    expect_count=0,
    expect_evades=False,
)

_KMOD_BEN2 = AdversarialCase(
    id="kmod_benign_empty",
    title="No kernel events — probe runs cleanly",
    category="benign",
    description="Empty event list — quiet kernel, no module activity.",
    why="Empty kernel_events → loop processes nothing → zero events.",
    events=[],
    expect_count=0,
    expect_evades=False,
)

KERNEL_MODULE_LOAD_SCENARIO: Scenario = register(
    Scenario(
        probe_id="kernel_module_load",
        agent="kernel_audit",
        name="kernel_module_load",
        title="Kernel Module / Rootkit Load (T1547 / T1014)",
        description=(
            "An attacker loads a kernel rootkit via init_module from /tmp (CRITICAL), "
            "or by using non-root capabilities (CRITICAL), or by unloading modules "
            "(MEDIUM). eBPF-based rootkits and early-boot module loads evade entirely."
        ),
        mitre_techniques=["T1547", "T1014"],
        mitre_tactics=["Persistence", "Defense Evasion"],
        probe_factory=KernelModuleLoadProbe,
        cases=[
            _KMOD_POS1,
            _KMOD_POS2,
            _KMOD_POS3,
            _KMOD_EVA1,
            _KMOD_EVA2,
            _KMOD_EVA3,
            _KMOD_BEN1,
            _KMOD_BEN2,
        ],
    )
)


# =============================================================================
# 4. PtraceAbuseProbe — ptrace on protected processes
# =============================================================================

_PTRACE_POS1 = AdversarialCase(
    id="ptrace_sshd_critical",
    title="ptrace targeting sshd (protected process) → CRITICAL",
    category="positive",
    description=(
        "Attacker uses ptrace() to attach to the sshd daemon, enabling "
        "memory inspection, credential harvesting, and code injection. "
        "sshd is in the protected process list because compromising it "
        "allows full authentication bypass."
    ),
    why=(
        "ptrace ∈ PTRACE_SYSCALLS. The probe builds pid_to_comm from all "
        "events: {ke.pid: ke.comm}. The sshd execve event populates "
        "pid_to_comm[888]='sshd'. Then the ptrace event's dest_pid=888 → "
        "target_comm='sshd' ∈ PROTECTED_PROCESSES → CRITICAL. "
        "Attaching to auth daemons is one of the most dangerous ptrace uses."
    ),
    events=[
        # Populate pid_to_comm so dest_pid=888 resolves to 'sshd'
        _ke(
            "execve",
            "ka-t01-sshd",
            uid=0,
            euid=0,
            pid=888,
            comm="sshd",
            exe="/usr/sbin/sshd",
        ),
        _ke(
            "ptrace",
            "ka-t01",
            uid=501,
            euid=501,
            dest_pid=888,
            comm="gdb",
            exe="/usr/bin/gdb",
        ),
    ],
    expect_count=1,
    expect_event_types=["kernel_ptrace_abuse"],
    expect_severity=Severity.CRITICAL,
)

_PTRACE_POS2 = AdversarialCase(
    id="ptrace_nonroot_high",
    title="ptrace by uid=501 (non-root) on regular process → HIGH",
    category="positive",
    description=(
        "An unprivileged user attaches to another user's process with ptrace. "
        "Even targeting a non-protected process, non-root ptrace is highly "
        "suspicious — legitimate debugging is done by process owners or root."
    ),
    why=(
        "ptrace ∈ PTRACE_SYSCALLS. uid=501 (non-root). "
        "Target is not a protected process → HIGH (not CRITICAL). "
        "Non-root cross-process ptrace is almost always malicious."
    ),
    events=[
        _ke(
            "ptrace",
            "ka-t02",
            uid=501,
            euid=501,
            dest_pid=9999,
            comm="memread",
            exe="/tmp/memread",
            raw={"target_comm": "chrome"},
        )
    ],
    expect_count=1,
    expect_event_types=["kernel_ptrace_abuse"],
    expect_severity=Severity.HIGH,
)

_PTRACE_POS3 = AdversarialCase(
    id="ptrace_init_critical",
    title="process_vm_readv targeting pid=1 (init) → CRITICAL",
    category="positive",
    description=(
        "Attacker uses process_vm_readv to read the memory of pid=1 (systemd/init). "
        "Reading init's memory space can reveal credentials, cryptographic keys, "
        "and process tree information. Targeting pid=1 is always CRITICAL."
    ),
    why=(
        "process_vm_readv ∈ PTRACE_SYSCALLS. dest_pid=1 → init/systemd. "
        "pid=1 is always treated as CRITICAL (targeting the process manager "
        "can destabilize the entire system)."
    ),
    events=[
        _ke(
            "process_vm_readv",
            "ka-t03",
            uid=0,
            euid=0,
            dest_pid=1,
            comm="memscanner",
            raw={"target_comm": "systemd"},
        )
    ],
    expect_count=1,
    expect_event_types=["kernel_ptrace_abuse"],
    expect_severity=Severity.CRITICAL,
)

_PTRACE_EVA1 = AdversarialCase(
    id="ptrace_evade_proc_mem",
    title="/proc/PID/mem read — no ptrace syscall, evades",
    category="evasion",
    description=(
        "Instead of ptrace(), the attacker reads /proc/1234/mem directly. "
        "This grants the same memory access without using any syscall in "
        "PTRACE_SYSCALLS. The openat event on /proc/PID/mem is not processed "
        "by PtraceAbuseProbe."
    ),
    why=(
        "PtraceAbuseProbe checks syscall ∈ PTRACE_SYSCALLS. "
        "openat on /proc/PID/mem generates an openat event, not ptrace → "
        "probe skips it. Same capability, zero detection."
    ),
    events=[
        _ke(
            "openat",
            "ka-t04",
            uid=501,
            euid=501,
            path="/proc/888/mem",
            comm="memthief",
        )
    ],
    expect_evades=True,
)

_PTRACE_EVA2 = AdversarialCase(
    id="ptrace_evade_yama_blocked",
    title="ptrace blocked by YAMA (result=failed) — but probe doesn't check result",
    category="evasion",
    description=(
        "Linux YAMA security module (ptrace_scope=1 or 2) blocks cross-process "
        "ptrace from unprivileged users. The kernel rejects the syscall. "
        "If the probe does not filter on result, it would fire even for blocked attempts. "
        "If it DOES filter on success, legitimate blocked ptrace attempts are missed."
    ),
    why=(
        "CAUGHT per spec — the probe fires on intent regardless of success. "
        "However, if probe only tracks successful ptrace, blocked attempts evade. "
        "Documenting this as a detection nuance: intent vs. capability."
    ),
    events=[
        _ke(
            "ptrace",
            "ka-t05",
            uid=501,
            euid=501,
            dest_pid=888,
            comm="attacker",
            result="failed",
            raw={"target_comm": "sshd"},
        )
    ],
    # Probe fires on the attempt (intent detection), even though YAMA blocked it
    # This is documented as CAUGHT in the spec — the probe correctly detects attempt
    expect_evades=False,
    expect_count=1,
    expect_event_types=["kernel_ptrace_abuse"],
)

_PTRACE_EVA3 = AdversarialCase(
    id="ptrace_evade_kernel_module",
    title="Kernel module directly reads process memory — no ptrace syscall",
    category="evasion",
    description=(
        "A sophisticated attacker loads a kernel module that directly reads "
        "process memory via kernel-mode pointers — no ptrace syscall is ever "
        "issued. The probe, which watches userspace ptrace syscalls, is blind "
        "to kernel-mode memory access."
    ),
    why=(
        "Kernel-mode memory reads bypass the ptrace syscall entirely. "
        "No PTRACE_SYSCALLS event → probe never fires. "
        "This is the 'rootkit advantage': direct kernel memory access "
        "is undetectable by audit-layer probes."
    ),
    events=[],  # No ptrace events — attacker is in kernel space
    expect_evades=True,
)

_PTRACE_BEN1 = AdversarialCase(
    id="ptrace_benign_execve",
    title="execve event — not a ptrace syscall, probe ignores",
    category="benign",
    description=(
        "Normal process execution event. The PtraceAbuseProbe only processes "
        "ptrace, process_vm_readv, and process_vm_writev syscalls."
    ),
    why="execve ∉ PTRACE_SYSCALLS → probe skips. Zero events emitted.",
    events=[_ke("execve", "ka-t07", uid=501, exe="/usr/bin/ls", comm="ls")],
    expect_count=0,
    expect_evades=False,
)

_PTRACE_BEN2 = AdversarialCase(
    id="ptrace_benign_empty",
    title="No kernel events — probe runs cleanly",
    category="benign",
    description="Empty event list — no ptrace activity on this host.",
    why="Empty kernel_events → zero events emitted.",
    events=[],
    expect_count=0,
    expect_evades=False,
)

# ── Nasty benign: developer gdb session fires HIGH ────────────────────────────

_PTRACE_NASTY_GDB_DEV = AdversarialCase(
    id="ptrace_nasty_gdb_developer",
    title="gdb attaches to user app (not protected) → HIGH  [documented FP]",
    category="benign",
    description=(
        "A developer runs `gdb myapp` to debug a crash in their application. "
        "gdb uses ptrace(PTRACE_ATTACH) on the target process (pid=9999, comm='myapp'). "
        "'myapp' is not in PROTECTED_PROCESSES, but gdb is running as a non-root user "
        "(uid=1001). The probe fires HIGH for all non-root ptrace usage — "
        "this fires on every developer debugging session."
    ),
    why=(
        "ptrace ∈ PTRACE_SYSCALLS. target_comm='myapp' ∉ PROTECTED_PROCESSES. "
        "dest_pid=9999 ≠ 1. uid=1001 ≠ 0 → elif branch: "
        "'Non-root process gdb using ptrace' → HIGH. "
        "FP: every `gdb`, `strace`, `ltrace`, `perf record` by non-root developers. "
        "Remediation: whitelist debug tools in a CI/developer-mode policy; "
        "or require PTRACE_MODE_ATTACH capability and only flag cross-UID attaches."
    ),
    events=[
        # First event populates pid_to_comm so dest_pid resolves to 'myapp'
        _ke(
            "execve",
            "ka-t-gdb00",
            pid=9999,
            uid=1001,
            euid=1001,
            comm="myapp",
            exe="/home/dev/myapp",
        ),
        # gdb attaches to myapp (not a protected process)
        _ke(
            "ptrace",
            "ka-t-gdb01",
            pid=5500,
            uid=1001,
            euid=1001,
            comm="gdb",
            exe="/usr/bin/gdb",
            dest_pid=9999,
        ),
    ],
    expect_count=1,
    expect_event_types=["kernel_ptrace_abuse"],
    expect_severity=Severity.HIGH,
)

PTRACE_ABUSE_SCENARIO: Scenario = register(
    Scenario(
        probe_id="ptrace_abuse",
        agent="kernel_audit",
        name="ptrace_abuse",
        title="Ptrace Abuse / Process Injection (T1055)",
        description=(
            "An attacker uses ptrace to inspect or inject into protected processes "
            "(sshd→CRITICAL), unprivileged cross-process ptrace (HIGH), "
            "or targets init/systemd (CRITICAL). /proc/PID/mem reads and "
            "kernel-mode injection evade the audit-layer probe entirely."
        ),
        mitre_techniques=["T1055"],
        mitre_tactics=["Defense Evasion", "Privilege Escalation"],
        probe_factory=PtraceAbuseProbe,
        cases=[
            _PTRACE_POS1,
            _PTRACE_POS2,
            _PTRACE_POS3,
            _PTRACE_EVA1,
            _PTRACE_EVA2,
            _PTRACE_EVA3,
            _PTRACE_BEN1,
            _PTRACE_BEN2,
            _PTRACE_NASTY_GDB_DEV,
        ],
    )
)


# =============================================================================
# 5. FilePermissionTamperProbe — chmod/chown on sensitive files
# =============================================================================

_FPERM_POS1 = AdversarialCase(
    id="fperm_shadow_chmod",
    title="chmod on /etc/shadow → CRITICAL",
    category="positive",
    description=(
        "Attacker makes /etc/shadow world-readable (chmod 777) to allow "
        "password hash extraction without root. /etc/shadow normally has "
        "permissions 000 or 640. Any permission change is extremely suspicious."
    ),
    why=(
        "chmod ∈ PERMISSION_SYSCALLS. path=/etc/shadow ∈ SENSITIVE_FILES "
        "AND is a shadow/sudoers file → CRITICAL severity."
    ),
    events=[
        _ke(
            "chmod",
            "ka-f01",
            uid=0,
            euid=0,
            path="/etc/shadow",
            comm="chmod",
            exe="/usr/bin/chmod",
        )
    ],
    expect_count=1,
    expect_event_types=["kernel_file_permission_tamper"],
    expect_severity=Severity.CRITICAL,
)

_FPERM_POS2 = AdversarialCase(
    id="fperm_sudoers_nonroot",
    title="chown on /etc/sudoers by uid=501 (non-root) → CRITICAL",
    category="positive",
    description=(
        "An unprivileged user somehow gains write access to /etc/sudoers "
        "(via a path traversal or symlink attack) and changes its ownership. "
        "Both the target (sudoers) and the actor (non-root) make this CRITICAL."
    ),
    why=(
        "chown ∈ PERMISSION_SYSCALLS. path=/etc/sudoers ∈ SENSITIVE_FILES. "
        "uid=501 (non-root) tampering with sudoers → CRITICAL "
        "(non-root actor on an auth-critical file)."
    ),
    events=[
        _ke(
            "chown",
            "ka-f02",
            uid=501,
            euid=501,
            path="/etc/sudoers",
            comm="chown",
        )
    ],
    expect_count=1,
    expect_event_types=["kernel_file_permission_tamper"],
    expect_severity=Severity.CRITICAL,
)

_FPERM_POS3 = AdversarialCase(
    id="fperm_sshd_config_chmod",
    title="chmod on /etc/ssh/sshd_config by root → HIGH",
    category="positive",
    description=(
        "Root user modifies sshd_config permissions. This may indicate an "
        "attacker backdooring SSH (disabling pubkey auth, adding PermitRootLogin "
        "yes, etc.). The file is sensitive but the actor is root → HIGH not CRITICAL."
    ),
    why=(
        "chmod ∈ PERMISSION_SYSCALLS. path=/etc/ssh/sshd_config ∈ SENSITIVE_FILES. "
        "uid=0 (root) is expected to own this file, but any permission change "
        "warrants investigation → HIGH severity."
    ),
    events=[
        _ke(
            "chmod",
            "ka-f03",
            uid=0,
            euid=0,
            path="/etc/ssh/sshd_config",
            comm="chmod",
        )
    ],
    expect_count=1,
    expect_event_types=["kernel_file_permission_tamper"],
    expect_severity=Severity.HIGH,
)

_FPERM_EVA1 = AdversarialCase(
    id="fperm_evade_rename",
    title="rename /etc/shadow.evil → /etc/shadow — no chmod/chown syscall",
    category="evasion",
    description=(
        "Attacker creates a world-readable /etc/shadow.evil, then renames it "
        "to /etc/shadow via the rename() syscall. The rename() replaces the "
        "file without triggering chmod/chown — the permissions come from the "
        "source file, not a permission change operation."
    ),
    why=(
        "FilePermissionTamperProbe watches PERMISSION_SYSCALLS (chmod, fchmod, "
        "chown, fchown, lchown). rename() is not in this set → "
        "the file replacement evades. Attacker gets a world-readable shadow "
        "file without triggering the probe."
    ),
    events=[
        _ke(
            "rename",
            "ka-f04",
            uid=0,
            euid=0,
            path="/etc/shadow",
            comm="mv",
        )
    ],
    expect_evades=True,
)

_FPERM_EVA2 = AdversarialCase(
    id="fperm_evade_package_manager",
    title="apt-get installs package, modifies /etc/group — legitimate FP",
    category="evasion",
    description=(
        "Package managers (apt, yum, brew) routinely modify files in /etc/ "
        "including /etc/group, /etc/passwd, and /etc/sudoers.d/ during package "
        "installation. The probe fires on these legitimate operations, "
        "generating false positives that alert fatigue security teams."
    ),
    why=(
        "EVADES as a false positive: FilePermissionTamperProbe has no "
        "package-manager whitelist. apt-get changing /etc/group permissions "
        "generates a HIGH event identical to an attacker's action. "
        "Mitigation: whitelist known package manager PIDs or parent processes."
    ),
    events=[
        _ke(
            "chmod",
            "ka-f05",
            uid=0,
            euid=0,
            path="/etc/group",
            comm="dpkg",
            exe="/usr/bin/dpkg",
        )
    ],
    # Fires as HIGH — documented as FP_RISK in spec, not a true evasion
    expect_evades=False,
    expect_count=1,
    expect_event_types=["kernel_file_permission_tamper"],
)

_FPERM_EVA3 = AdversarialCase(
    id="fperm_evade_nonsensitive",
    title="chmod on /etc/motd — not in SENSITIVE_FILES list → evades",
    category="evasion",
    description=(
        "Attacker modifies /etc/motd (message of the day) permissions or "
        "injects malicious content. /etc/motd is not in SENSITIVE_FILES, "
        "so the probe ignores it. If /etc/motd is used in PAM scripts, "
        "world-writable motd can enable privilege escalation."
    ),
    why=(
        "SENSITIVE_FILES is a fixed list — /etc/motd is not included. "
        "chmod on /etc/motd → probe skips. "
        "Attackers who target files not on the list evade detection entirely."
    ),
    events=[
        _ke(
            "chmod",
            "ka-f06",
            uid=501,
            euid=501,
            path="/etc/motd",
            comm="chmod",
        )
    ],
    expect_evades=True,
)

_FPERM_BEN1 = AdversarialCase(
    id="fperm_benign_tmp",
    title="chmod on /tmp/myfile.txt — not sensitive, no fire",
    category="benign",
    description=(
        "Developer changes permissions on a temp file in /tmp. "
        "/tmp/myfile.txt is not in SENSITIVE_FILES, so the probe ignores it."
    ),
    why=(
        "path=/tmp/myfile.txt ∉ SENSITIVE_FILES → probe skips. "
        "No false positive on routine developer operations."
    ),
    events=[
        _ke("chmod", "ka-f07", uid=501, euid=501, path="/tmp/myfile.txt", comm="chmod")
    ],
    expect_count=0,
    expect_evades=False,
)

_FPERM_BEN2 = AdversarialCase(
    id="fperm_benign_home",
    title="chown on /home/user/project — not sensitive, no fire",
    category="benign",
    description=(
        "User changes ownership of their own project directory. "
        "Home directory files are not in SENSITIVE_FILES."
    ),
    why=(
        "path=/home/user/project ∉ SENSITIVE_FILES → probe skips. "
        "Routine user operations do not trigger this probe."
    ),
    events=[
        _ke(
            "chown",
            "ka-f08",
            uid=501,
            euid=501,
            path="/home/user/project",
            comm="chown",
        )
    ],
    expect_count=0,
    expect_evades=False,
)

FILE_PERMISSION_TAMPER_SCENARIO: Scenario = register(
    Scenario(
        probe_id="file_permission_tamper",
        agent="kernel_audit",
        name="file_permission_tamper",
        title="File Permission Tampering on Sensitive Files (T1222)",
        description=(
            "An attacker modifies permissions on /etc/shadow (CRITICAL), "
            "/etc/sudoers (CRITICAL), and /etc/ssh/sshd_config (HIGH). "
            "Known gaps: rename() replaces files without chmod, and package managers "
            "cause false positives that can mask real attacks."
        ),
        mitre_techniques=["T1222"],
        mitre_tactics=["Defense Evasion", "Privilege Escalation"],
        probe_factory=FilePermissionTamperProbe,
        cases=[
            _FPERM_POS1,
            _FPERM_POS2,
            _FPERM_POS3,
            _FPERM_EVA1,
            _FPERM_EVA2,
            _FPERM_EVA3,
            _FPERM_BEN1,
            _FPERM_BEN2,
        ],
    )
)


# =============================================================================
# 6. AuditTamperProbe — audit log access / deletion
# =============================================================================

_AUDIT_POS1 = AdversarialCase(
    id="audit_tamper_openat",
    title="Non-audit process opens /var/log/audit/audit.log → CRITICAL",
    category="positive",
    description=(
        "Attacker opens the audit log file directly to read and parse it "
        "(looking for their own activity to understand detection), or to "
        "truncate it to destroy evidence. Only auditd and its tools should "
        "ever access this file."
    ),
    why=(
        "openat ∈ AUDIT_TAMPER_SYSCALLS. path=/var/log/audit/audit.log "
        "∈ AUDIT_FILES. comm='evil_tool' ∉ AUDIT_PROCESS_WHITELIST → "
        "kernel_audit_tamper CRITICAL."
    ),
    events=[
        _ke(
            "openat",
            "ka-a01",
            uid=501,
            euid=501,
            path="/var/log/audit/audit.log",
            comm="evil_tool",
            exe="/tmp/evil_tool",
        )
    ],
    expect_count=1,
    expect_event_types=["kernel_audit_tamper"],
    expect_severity=Severity.CRITICAL,
)

_AUDIT_POS2 = AdversarialCase(
    id="audit_tamper_unlink",
    title="unlink /etc/audit/audit.rules — deleting audit rules → CRITICAL",
    category="positive",
    description=(
        "Attacker deletes /etc/audit/audit.rules to prevent audit rules from "
        "being reloaded after auditd restart. This silently disables monitoring "
        "after the next daemon restart — a classic 'delayed blind' technique."
    ),
    why=(
        "unlink ∈ AUDIT_TAMPER_SYSCALLS. path=/etc/audit/audit.rules "
        "∈ AUDIT_FILES → CRITICAL. "
        "Deleting audit rules is a direct attempt to impair defenses."
    ),
    events=[
        _ke(
            "unlink",
            "ka-a02",
            uid=0,
            euid=0,
            path="/etc/audit/audit.rules",
            comm="attacker",
            exe="/tmp/attacker",
        )
    ],
    expect_count=1,
    expect_event_types=["kernel_audit_tamper"],
    expect_severity=Severity.CRITICAL,
)

_AUDIT_POS3 = AdversarialCase(
    id="audit_tamper_auditctl_nonroot",
    title="Non-root executes auditctl → HIGH",
    category="positive",
    description=(
        "A non-root user executes auditctl — the utility for managing audit rules. "
        "This requires CAP_AUDIT_CONTROL, which unprivileged users should not have. "
        "This either indicates misconfigured capabilities or a privilege escalation."
    ),
    why=(
        "execve of auditctl ∈ AUDIT_BINARIES. uid=501 (non-root). "
        "kernel_audit_tool_exec HIGH — non-root audit tool execution "
        "is always suspicious."
    ),
    events=[
        _ke(
            "execve",
            "ka-a03",
            uid=501,
            euid=501,
            exe="/usr/sbin/auditctl",
            comm="auditctl",
        )
    ],
    expect_count=1,
    expect_event_types=["kernel_audit_tool_exec"],
    expect_severity=Severity.HIGH,
)

_AUDIT_EVA1 = AdversarialCase(
    id="audit_evade_systemctl",
    title="systemctl stop auditd — disables audit via systemd, no audit file access",
    category="evasion",
    description=(
        "Attacker runs `sudo systemctl stop auditd` to stop the audit daemon "
        "cleanly. This uses the systemd control interface — no direct audit file "
        "access or audit tool execution occurs. auditd shuts down gracefully "
        "and stops logging. All subsequent attacker activity is unlogged."
    ),
    why=(
        "systemctl is not in AUDIT_BINARIES and the stop command doesn't access "
        "AUDIT_FILES → AuditTamperProbe fires nothing. "
        "systemd-based auditd control is a significant blind spot."
    ),
    events=[
        _ke(
            "execve",
            "ka-a04",
            uid=0,
            euid=0,
            exe="/usr/bin/systemctl",
            comm="systemctl",
            cmdline="systemctl stop auditd",
        )
    ],
    expect_evades=True,
)

_AUDIT_EVA2 = AdversarialCase(
    id="audit_evade_logrotate_fp",
    title="logrotate rotating audit.log — legitimate FP",
    category="evasion",
    description=(
        "Logrotate is a system utility that rotates log files including "
        "/var/log/audit/audit.log. It's configured to run daily and "
        "will open/move/truncate the audit log — generating events identical "
        "to an attacker clearing logs. AuditTamperProbe cannot distinguish."
    ),
    why=(
        "EVADES as FP: logrotate accesses /var/log/audit/audit.log using "
        "the same syscalls an attacker would. Without logrotate in the "
        "whitelist, this fires CRITICAL — creating alert fatigue that "
        "masks real attacks."
    ),
    events=[
        _ke(
            "openat",
            "ka-a05",
            uid=0,
            euid=0,
            path="/var/log/audit/audit.log",
            comm="logrotate",
            exe="/usr/sbin/logrotate",
        )
    ],
    # Fires CRITICAL — documented FP (logrotate not whitelisted)
    expect_evades=False,
    expect_count=1,
    expect_event_types=["kernel_audit_tamper"],
)

_AUDIT_EVA3 = AdversarialCase(
    id="audit_evade_redirect_null",
    title="redirect audit output to /dev/null via auditd config — no file access",
    category="evasion",
    description=(
        "Attacker modifies auditd.conf to set log_file=/dev/null and sends "
        "SIGHUP to auditd. auditd reopens its log file to /dev/null and "
        "discards all subsequent audit records. The modification of auditd.conf "
        "itself IS in AUDIT_FILES and WOULD fire — but if the attacker modifies "
        "it during a window when the probe isn't running, this evades."
    ),
    why=(
        "The timing-window evasion: if auditd.conf is modified between probe "
        "scan cycles (scan_interval=300s), the modification event may not be "
        "captured. Polling-based detection has a 5-minute blind window."
    ),
    events=[],  # Attack happened between scan cycles — no event captured
    expect_evades=True,
)

_AUDIT_BEN1 = AdversarialCase(
    id="audit_benign_syslog",
    title="openat on /var/log/syslog — not an audit file, no fire",
    category="benign",
    description=(
        "A normal process opens /var/log/syslog to read system events. "
        "/var/log/syslog is not in AUDIT_FILES — probe correctly ignores it."
    ),
    why=(
        "path=/var/log/syslog ∉ AUDIT_FILES → probe skips. "
        "No false positive on normal syslog access."
    ),
    events=[_ke("openat", "ka-a07", uid=0, path="/var/log/syslog", comm="rsyslogd")],
    expect_count=0,
    expect_evades=False,
)

_AUDIT_BEN2 = AdversarialCase(
    id="audit_benign_execve_other",
    title="execve of /usr/bin/ls — not an audit binary, no fire",
    category="benign",
    description=(
        "Routine ls execution. AUDIT_BINARIES contains auditd/auditctl/ausearch etc. "
        "/usr/bin/ls is not in that list."
    ),
    why="ls ∉ AUDIT_BINARIES → probe skips. Zero events emitted.",
    events=[_ke("execve", "ka-a08", uid=501, exe="/usr/bin/ls", comm="ls")],
    expect_count=0,
    expect_evades=False,
)

AUDIT_TAMPER_SCENARIO: Scenario = register(
    Scenario(
        probe_id="audit_tamper",
        agent="kernel_audit",
        name="audit_tamper",
        title="Audit Subsystem Tampering — Impair Defenses (T1562)",
        description=(
            "An attacker attempts to blind the audit subsystem: opening audit.log (CRITICAL), "
            "deleting audit.rules (CRITICAL), executing auditctl as non-root (HIGH). "
            "Gaps: systemctl stop auditd evades entirely; logrotate causes FP; "
            "polling window allows timing-based attacks."
        ),
        mitre_techniques=["T1562", "T1562.001"],
        mitre_tactics=["Defense Evasion"],
        probe_factory=AuditTamperProbe,
        cases=[
            _AUDIT_POS1,
            _AUDIT_POS2,
            _AUDIT_POS3,
            _AUDIT_EVA1,
            _AUDIT_EVA2,
            _AUDIT_EVA3,
            _AUDIT_BEN1,
            _AUDIT_BEN2,
        ],
    )
)


# =============================================================================
# 7. SyscallFloodProbe — 100+ syscalls per PID
# =============================================================================


def _flood_events(pid: int, count: int, failed_count: int = 0) -> list:
    """Generate `count` kernel events from `pid`, with `failed_count` flagged failed."""
    events = []
    for i in range(count):
        result = "failed" if i < failed_count else "success"
        events.append(
            _ke(
                "openat",
                f"ka-s{pid:03d}-{i:04d}",
                ts=_T0 + int(i * 1e6),  # 1ms apart
                pid=pid,
                uid=501,
                euid=501,
                result=result,
                path=f"/proc/{i}/status",
            )
        )
    return events


_FLOOD_POS1 = AdversarialCase(
    id="syscall_flood_medium",
    title="100 syscalls from PID 9001 → MEDIUM",
    category="positive",
    description=(
        "Attacker's process makes 100 rapid syscalls (e.g., scanning /proc/* "
        "to enumerate processes, or performing a directory traversal). "
        "100 calls/window meets the FLOOD_THRESHOLD."
    ),
    why=(
        "len(events for pid=9001) == 100 >= FLOOD_THRESHOLD(100). "
        "failed_count=0 < FAILURE_THRESHOLD(50) → MEDIUM (not HIGH)."
    ),
    events=_flood_events(pid=9001, count=100, failed_count=0),
    expect_count=1,
    expect_event_types=["kernel_syscall_flood"],
    expect_severity=Severity.MEDIUM,
)

_FLOOD_POS2 = AdversarialCase(
    id="syscall_flood_high",
    title="100 syscalls + 50 failures from PID 9002 → HIGH",
    category="positive",
    description=(
        "An attacker's exploit or scanner generates 100 syscalls, of which "
        "50 fail (e.g., permission errors from probing restricted paths). "
        "High failure rate suggests active exploitation attempts."
    ),
    why=(
        "len(events for pid=9002) == 100 >= FLOOD_THRESHOLD. "
        "failed_count=50 >= FAILURE_THRESHOLD(50) → HIGH severity "
        "(flood + high failure rate = exploitation indicator)."
    ),
    events=_flood_events(pid=9002, count=100, failed_count=50),
    expect_count=1,
    expect_event_types=["kernel_syscall_flood"],
    expect_severity=Severity.HIGH,
)

_FLOOD_POS3 = AdversarialCase(
    id="syscall_flood_two_pids",
    title="Two PIDs each with 100+ floods → 2 events",
    category="positive",
    description=(
        "Two separate attacker processes each generating 100+ syscalls "
        "(e.g., a multi-threaded scanner). Both PIDs independently meet "
        "FLOOD_THRESHOLD → two separate MEDIUM events."
    ),
    why=(
        "SyscallFloodProbe aggregates per-PID. "
        "PID 9003: 110 events → MEDIUM. PID 9004: 105 events → MEDIUM. "
        "Two independent flood detections."
    ),
    events=_flood_events(pid=9003, count=110) + _flood_events(pid=9004, count=105),
    expect_count=2,
    expect_event_types=["kernel_syscall_flood"],
    expect_severity=Severity.MEDIUM,
)

_FLOOD_EVA1 = AdversarialCase(
    id="syscall_flood_evade_just_under",
    title="99 syscalls from PID 9005 — just under threshold, evades",
    category="evasion",
    description=(
        "Attacker's process makes exactly 99 syscalls per window — one below "
        "FLOOD_THRESHOLD=100. This is a calibrated evasion: enough activity to "
        "accomplish the attack objective while staying below the detection threshold."
    ),
    why=(
        "len(events for pid=9005) == 99 < FLOOD_THRESHOLD(100). "
        "Probe skips this PID. Attacker achieves their goal within the window "
        "by pacing calls slightly below 100."
    ),
    events=_flood_events(pid=9005, count=99),
    expect_evades=True,
)

_FLOOD_EVA2 = AdversarialCase(
    id="syscall_flood_evade_distributed",
    title="10 PIDs × 50 syscalls each — distributed flood evades per-PID threshold",
    category="evasion",
    description=(
        "Attacker uses 10 worker processes, each making 50 syscalls. "
        "Total: 500 syscalls — 5× the threshold. But each individual PID "
        "makes only 50 calls (below FLOOD_THRESHOLD=100), so no single PID "
        "triggers the flood detector."
    ),
    why=(
        "SyscallFloodProbe is per-PID, not system-wide. "
        "10 PIDs × 50 syscalls = 500 total, but each PID has 50 < 100 → "
        "probe fires nothing. System-wide flood is undetected."
    ),
    events=[e for pid in range(9010, 9020) for e in _flood_events(pid=pid, count=50)],
    expect_evades=True,
)

_FLOOD_EVA3 = AdversarialCase(
    id="syscall_flood_evade_build_fp",
    title="Legitimate build process (make -j16) — undistinguishable FP",
    category="evasion",
    description=(
        "A software build with `make -j16` spawns 16 parallel compile jobs, "
        "each making hundreds of syscalls (file reads, writes, forks). "
        "The build process legitimately floods the kernel with syscalls. "
        "The probe fires MEDIUM, but this is a false positive — alert fatigue "
        "trains operators to ignore flood events."
    ),
    why=(
        "EVADES as FP: SyscallFloodProbe cannot distinguish a build system "
        "from an attacker's flood. No process name or parent check. "
        "High-frequency legitimate build activity generates identical signals."
    ),
    events=_flood_events(pid=9020, count=120, failed_count=0),
    # Fires MEDIUM — documented as FP risk, build processes indistinguishable
    expect_evades=False,
    expect_count=1,
    expect_event_types=["kernel_syscall_flood"],
)

_FLOOD_BEN1 = AdversarialCase(
    id="syscall_flood_benign_under",
    title="50 syscalls from PID 9030 — under threshold, no fire",
    category="benign",
    description=(
        "Normal process activity: 50 syscalls in a collection window. "
        "Well below FLOOD_THRESHOLD=100. The probe correctly ignores "
        "normal process activity."
    ),
    why=(
        "len(events for pid=9030) == 50 < FLOOD_THRESHOLD(100). "
        "Probe loop increments the counter but never reaches threshold → "
        "no event emitted."
    ),
    events=_flood_events(pid=9030, count=50),
    expect_count=0,
    expect_evades=False,
)

_FLOOD_BEN2 = AdversarialCase(
    id="syscall_flood_benign_empty",
    title="No kernel events — probe runs cleanly",
    category="benign",
    description="Empty event list — quiet system, no flood activity.",
    why="Empty kernel_events → no PIDs accumulated → zero events emitted.",
    events=[],
    expect_count=0,
    expect_evades=False,
)

SYSCALL_FLOOD_SCENARIO: Scenario = register(
    Scenario(
        probe_id="syscall_flood",
        agent="kernel_audit",
        name="syscall_flood",
        title="Syscall Flood / Process Enumeration (T1057 / T1499)",
        description=(
            "A process generating 100+ syscalls/window triggers the flood detector. "
            "MEDIUM for count-only; HIGH when 50+ calls fail (exploitation indicator). "
            "Distributed floods (10 PIDs × 50 each) and calibrated throttling (99 calls) "
            "evade the per-PID threshold. Build systems cause FPs."
        ),
        mitre_techniques=["T1057", "T1499"],
        mitre_tactics=["Discovery", "Impact"],
        probe_factory=SyscallFloodProbe,
        cases=[
            _FLOOD_POS1,
            _FLOOD_POS2,
            _FLOOD_POS3,
            _FLOOD_EVA1,
            _FLOOD_EVA2,
            _FLOOD_EVA3,
            _FLOOD_BEN1,
            _FLOOD_BEN2,
        ],
    )
)
