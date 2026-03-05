"""attacker_touched_the_box.py — macOS kill-chain spine scenario.

Five micro-scenarios covering one complete attack narrative:
  APT29-style actor remotely compromises a macOS developer workstation
  (victim-host / uid=1001 "jsmith") to steal source code and credentials.

Kill-chain timeline (all timestamps relative to _T0 = 2023-11-14T22:13:20Z):
  +0s    Phase 1: SSH password spray from Tor exit 185.220.101.1
  +30s   Phase 2: Dropper binary executed from /tmp/stage1
  +90s   Phase 3: Dropper calls seteuid(0) to gain root EUID
  +120s  Phase 4: C2 implant runs persistently from /tmp/c2_beacon
  +180s  Phase 5: Attacker ptrace-attaches to sshd to harvest credentials

Each scenario has 4 cases:
  - (positive)  the attack is caught
  - (positive)  a variant or second-phase hit
  - (evasion)   documented detection gap — attacker wins
  - (benign)    legitimate behaviour that mimics the attack

Together these 5 scenarios (20 cases) test coverage across 3 agents:
    auth/SSHPasswordSprayProbe   →  Phase 1
    kernel_audit/ExecveHighRiskProbe   →  Phase 2
    kernel_audit/PrivEscSyscallProbe   →  Phase 3
    proc/BinaryFromTempProbe           →  Phase 4
    kernel_audit/PtraceAbuseProbe      →  Phase 5

Run:
    amoskys-redteam run spine_initial_access
    amoskys-redteam run spine_dropper_execution
    amoskys-redteam run spine_privilege_escalation
    amoskys-redteam run spine_process_implant
    amoskys-redteam run spine_ptrace_credential_harvest
"""

from __future__ import annotations

from unittest.mock import MagicMock

from amoskys.agents.auth.probes import AuthEvent, SSHPasswordSprayProbe
from amoskys.agents.common.probes import Severity
from amoskys.agents.kernel_audit.agent_types import KernelAuditEvent
from amoskys.agents.kernel_audit.probes import (
    ExecveHighRiskProbe,
    PrivEscSyscallProbe,
    PtraceAbuseProbe,
)
from amoskys.agents.proc.probes import BinaryFromTempProbe
from amoskys.redteam.harness import AdversarialCase, Scenario
from amoskys.redteam.scenarios import register

# ─── Timeline anchors (all in nanoseconds) ───────────────────────────────────

_T0       = int(1_700_000_000 * 1e9)   # 2023-11-14T22:13:20Z UTC
_T_SPRAY  = _T0                         # +0s  — spray begins
_T_EXEC   = _T0 + int(30 * 1e9)        # +30s — dropper executed
_T_PRIV   = _T0 + int(90 * 1e9)        # +90s — privilege escalation
_T_IMPL   = _T0 + int(120 * 1e9)       # +120s — implant starts
_T_PTRACE = _T0 + int(180 * 1e9)       # +180s — ptrace credential harvest

_ATTACKER_IP = "185.220.101.1"   # known Tor exit node (Tor Project AS)
_VICTIM_UID  = 1001
_VICTIM_USER = "jsmith"
_HOST        = "victim-host"


# ─── Event factory helpers ────────────────────────────────────────────────────


def _ae(**kwargs) -> AuthEvent:
    """Shorthand AuthEvent factory."""
    defaults = dict(
        timestamp_ns=_T_SPRAY,
        event_type="SSH_LOGIN",
        status="SUCCESS",
        username=_VICTIM_USER,
        source_ip=_ATTACKER_IP,
        command="",
        session_id="",
        reason="",
    )
    defaults.update(kwargs)
    return AuthEvent(**defaults)  # type: ignore[arg-type]


def _ke(syscall: str, eid: str, ts: int = _T0, **kwargs) -> KernelAuditEvent:
    """Shorthand KernelAuditEvent factory."""
    defaults = dict(
        event_id=eid,
        timestamp_ns=ts,
        host=_HOST,
        uid=_VICTIM_UID,
        euid=_VICTIM_UID,
        pid=22222,
        raw={},
    )
    defaults.update(kwargs)
    return KernelAuditEvent(syscall=syscall, **defaults)  # type: ignore[arg-type]


# ─── psutil mock helpers (proc probes) ───────────────────────────────────────

_PA = "amoskys.agents.proc.probes.PSUTIL_AVAILABLE"
_PI = "amoskys.agents.proc.probes.psutil.process_iter"


def _mk_proc(**fields) -> MagicMock:
    """Mock psutil process with .info dict."""
    p = MagicMock()
    p.info = dict(
        pid=22222,
        name="bash",
        exe="/bin/bash",
        cmdline=["bash"],
        username=_VICTIM_USER,
        create_time=1_700_000_000.0,
    )
    p.info.update(fields)
    return p


def _mock_iter(*procs: MagicMock):
    """Return a psutil.process_iter replacement that yields given procs."""
    return lambda *a, **kw: iter(list(procs))


# =============================================================================
# Phase 1: SSH Password Spray — SSHPasswordSprayProbe
# =============================================================================

_SPRAY_USERS = [f"user{i}" for i in range(10)]   # 10 distinct accounts


def _spray_events(ip: str, usernames: list) -> list:
    return [
        _ae(
            timestamp_ns=_T_SPRAY + int(i * 3 * 1e9),
            event_type="SSH_LOGIN",
            status="FAILURE",
            username=u,
            source_ip=ip,
        )
        for i, u in enumerate(usernames)
    ]


_SPINE_SPRAY_POS1 = AdversarialCase(
    id="spine_spray_tor_exit_10_users",
    title="10 users sprayed from Tor exit 185.220.101.1 → ssh_password_spray HIGH",
    category="positive",
    description=(
        "APT29 actor sprays 10 usernames via a Tor exit node. Single IP hits "
        "the SPRAY_USERS_THRESHOLD (10 distinct users in 300s window)."
    ),
    why=(
        "10 distinct SSH_LOGIN FAILURE events from 185.220.101.1 in 300s → "
        "count >= SPRAY_USERS_THRESHOLD → ssh_password_spray HIGH."
    ),
    shared_data_key="auth_events",
    events=_spray_events(_ATTACKER_IP, _SPRAY_USERS),
    expect_count=1,
    expect_event_types=["ssh_password_spray_detected"],
    expect_severity=Severity.HIGH,
)

_SPINE_SPRAY_POS2 = AdversarialCase(
    id="spine_spray_two_concurrent_sources",
    title="Attacker uses 2 IPs × 10 users → 2 spray events",
    category="positive",
    description=(
        "Infrastructure-savvy attacker uses two Tor IPs simultaneously. Both "
        "exceed the per-IP user threshold independently."
    ),
    why=(
        "IP-A: 10 distinct users → ssh_password_spray HIGH. "
        "IP-B: 10 distinct users → ssh_password_spray HIGH. "
        "Two independent events from two source IPs."
    ),
    shared_data_key="auth_events",
    events=(
        _spray_events("185.220.101.1", [f"u{i}" for i in range(10)])
        + _spray_events("185.220.101.2", [f"v{i}" for i in range(10)])
    ),
    expect_count=2,
    expect_event_types=["ssh_password_spray_detected"],
    expect_severity=Severity.HIGH,
)

_SPINE_SPRAY_EVA1 = AdversarialCase(
    id="spine_spray_distributed_5_ips",
    title="5 IPs × 2 users each — per-IP threshold not reached → EVADES",
    category="evasion",
    description=(
        "Attacker distributes spray across 5 Tor exit IPs, only 2 usernames "
        "per IP. No single IP exceeds the 10-user spray threshold."
    ),
    why=(
        "EVADES: probe counts distinct usernames per source IP. "
        "2 usernames < SPRAY_USERS_THRESHOLD(10) → no detection on any IP. "
        "Distributed spray is the primary evasion for per-IP spray detectors."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T_SPRAY + int(i * 2 * 1e9),
            event_type="SSH_LOGIN",
            status="FAILURE",
            username=f"acct{i}",
            source_ip=f"185.220.101.{(i % 5) + 1}",
        )
        for i in range(10)
    ],
    expect_count=0,
    expect_evades=True,
)

_SPINE_SPRAY_BENIGN = AdversarialCase(
    id="spine_spray_single_user_brute",
    title="15 failed logins for 'root' from same IP — brute force, not spray",
    category="benign",
    description=(
        "A script kiddie brute-forces the 'root' account with a wordlist. "
        "15 failures from one IP, but only 1 distinct username — "
        "SSHPasswordSprayProbe detects spray (many users), not brute force."
    ),
    why=(
        "Only 1 distinct username 'root' from the source IP. "
        "distinct_users < SPRAY_USERS_THRESHOLD(10) → no spray detected. "
        "Brute force (single user) and spray (many users) are different attacks."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T_SPRAY + int(i * 1 * 1e9),
            event_type="SSH_LOGIN",
            status="FAILURE",
            username="root",
            source_ip=_ATTACKER_IP,
        )
        for i in range(15)
    ],
    expect_count=0,
)

_SPINE_DEGRADED_SPRAY_NO_IP = AdversarialCase(
    id="spine_degraded_spray_no_ip",
    title="Spray events with source_ip='' → fires with empty attribution",
    category="positive",
    description=(
        "Production telemetry arrives with source_ip='' (IP stripped by NAT/firewall). "
        "The probe groups all failed logins under the empty-string key. "
        "Detection fires but attribution is lost — attacker IP is unknown."
    ),
    why=(
        "source_ip='' is a valid dict key. 10 distinct users group under ''. "
        "len(users) >= PASSWORD_SPRAY_USER_THRESHOLD → ssh_password_spray HIGH fires. "
        "data.source_ip='' — forensic attribution lost but detection preserved."
    ),
    shared_data_key="auth_events",
    events=_spray_events("", _SPRAY_USERS),
    expect_count=1,
    expect_event_types=["ssh_password_spray_detected"],
    expect_severity=Severity.HIGH,
)

_SPINE_INITIAL_ACCESS = Scenario(
    probe_id="ssh_password_spray",
    agent="auth",
    name="spine_initial_access",
    title="Kill-Chain Phase 1: SSH Password Spray (Initial Access)",
    description=(
        "APT29-style actor sprays credentials from a Tor exit node to find a "
        "valid account on victim-host. Tests SSHPasswordSprayProbe coverage "
        "and the distributed-spray evasion gap."
    ),
    mitre_techniques=["T1110.003"],
    mitre_tactics=["Credential Access", "Initial Access"],
    probe_factory=SSHPasswordSprayProbe,
    cases=[
        _SPINE_SPRAY_POS1,
        _SPINE_SPRAY_POS2,
        _SPINE_SPRAY_EVA1,
        _SPINE_SPRAY_BENIGN,
        _SPINE_DEGRADED_SPRAY_NO_IP,
    ],
)
register(_SPINE_INITIAL_ACCESS)


# =============================================================================
# Phase 2: Dropper Execution — ExecveHighRiskProbe
# =============================================================================

_SPINE_EXEC_POS1 = AdversarialCase(
    id="spine_tmp_dropper_stage1",
    title="/tmp/stage1 executed by uid=1001 → kernel_execve_high_risk MEDIUM",
    category="positive",
    description=(
        "Attacker downloads a first-stage dropper to /tmp and executes it. "
        "No privilege escalation yet — running as the compromised user jsmith."
    ),
    why=(
        "exe starts with /tmp/ → matches HIGH_RISK_DIRS. "
        "uid=1001 == euid=1001 (non-setuid, non-root) → MEDIUM severity."
    ),
    events=[
        _ke(
            "execve", "spine-e01", ts=_T_EXEC,
            uid=_VICTIM_UID, euid=_VICTIM_UID,
            pid=22222, exe="/tmp/stage1", comm="stage1",
        )
    ],
    expect_count=1,
    expect_event_types=["kernel_execve_high_risk"],
    expect_severity=Severity.MEDIUM,
)

_SPINE_EXEC_POS2 = AdversarialCase(
    id="spine_tmp_dropper_setuid_root",
    title="/tmp/stage2 with setuid bit (euid=0) → kernel_execve_high_risk HIGH",
    category="positive",
    description=(
        "Attacker plants a setuid-root binary in /tmp. On execution, the OS "
        "elevates EUID to 0. Both suspicious location AND root privilege gain."
    ),
    why=(
        "exe starts with /tmp/ → HIGH_RISK_DIRS match. "
        "uid=1001 (non-root) but euid=0 (setuid binary) → uid!=0 and euid==0 "
        "→ HIGH severity. Location + privilege escalation = higher confidence."
    ),
    events=[
        _ke(
            "execve", "spine-e02", ts=_T_EXEC + int(5 * 1e9),
            uid=_VICTIM_UID, euid=0,
            pid=22223, exe="/tmp/stage2", comm="stage2",
        )
    ],
    expect_count=1,
    expect_event_types=["kernel_execve_high_risk"],
    expect_severity=Severity.HIGH,
)

_SPINE_EXEC_EVA1 = AdversarialCase(
    id="spine_exec_dropper_moved_to_usr_bin",
    title="Attacker moves dropper to /usr/bin/update → not HIGH_RISK_DIRS → EVADES",
    category="evasion",
    description=(
        "Attacker copies the dropper to /usr/bin/update (readable path for "
        "SIP-bypassed mac) before executing. ExecveHighRiskProbe only checks "
        "HIGH_RISK_DIRS (/tmp, /dev/shm, /home, /Users) — /usr/bin is clean."
    ),
    why=(
        "EVADES: /usr/bin/update does not start with any HIGH_RISK_DIRS entry. "
        "The probe misses payloads that are planted in legitimate-looking paths."
    ),
    events=[
        _ke(
            "execve", "spine-e03", ts=_T_EXEC + int(10 * 1e9),
            uid=_VICTIM_UID, euid=_VICTIM_UID,
            pid=22224, exe="/usr/bin/update", comm="update",
        )
    ],
    expect_count=0,
    expect_evades=True,
)

_SPINE_EXEC_BENIGN = AdversarialCase(
    id="spine_exec_legitimate_curl",
    title="/usr/bin/curl executed by uid=1001 → not high-risk → no alert",
    category="benign",
    description=(
        "Developer runs curl from its standard location. ExecveHighRiskProbe "
        "only fires on HIGH_RISK_DIRS — /usr/bin/curl is a legitimate path."
    ),
    why=(
        "exe='/usr/bin/curl' does not match any HIGH_RISK_DIRS pattern. "
        "No event emitted. False positive risk is low for standard system paths."
    ),
    events=[
        _ke(
            "execve", "spine-e04", ts=_T_EXEC + int(15 * 1e9),
            uid=_VICTIM_UID, euid=_VICTIM_UID,
            pid=22225, exe="/usr/bin/curl", comm="curl",
        )
    ],
    expect_count=0,
)

_SPINE_DEGRADED_EXEC_NO_EXE = AdversarialCase(
    id="spine_degraded_exec_no_exe",
    title="execve with exe=None — probe skips gracefully, no false positive",
    category="benign",
    description=(
        "Kernel audit telemetry arrives with exe=None (path field stripped by collector). "
        "ExecveHighRiskProbe checks `exe_path = ke.exe or ke.path`; with both None "
        "it skips cleanly. No exception, no false positive event."
    ),
    why=(
        "exe=None and path=None → exe_path = None → `if not exe_path: continue`. "
        "Probe handles missing path gracefully. expect_count=0 — "
        "degraded telemetry causes missed detection, not a crash or FP."
    ),
    events=[
        _ke(
            "execve", "spine-deg-e01", ts=_T_EXEC,
            uid=_VICTIM_UID, euid=_VICTIM_UID,
            pid=22222, comm="stage1",
        )
    ],
    expect_count=0,
)

_SPINE_DROPPER_EXECUTION = Scenario(
    probe_id="execve_high_risk",
    agent="kernel_audit",
    name="spine_dropper_execution",
    title="Kill-Chain Phase 2: Dropper Execution (Execution)",
    description=(
        "Attacker executes a first-stage dropper from /tmp. Tests "
        "ExecveHighRiskProbe and the path-masquerade evasion gap."
    ),
    mitre_techniques=["T1059", "T1204"],
    mitre_tactics=["Execution"],
    probe_factory=ExecveHighRiskProbe,
    cases=[
        _SPINE_EXEC_POS1,
        _SPINE_EXEC_POS2,
        _SPINE_EXEC_EVA1,
        _SPINE_EXEC_BENIGN,
        _SPINE_DEGRADED_EXEC_NO_EXE,
    ],
)
register(_SPINE_DROPPER_EXECUTION)


# =============================================================================
# Phase 3: Privilege Escalation — PrivEscSyscallProbe
# =============================================================================

_SPINE_PRIV_POS1 = AdversarialCase(
    id="spine_seteuid_root_gain",
    title="seteuid(0): uid=1001 → euid=0 → kernel_privesc_syscall CRITICAL",
    category="positive",
    description=(
        "Dropper calls seteuid(0) to gain root effective UID while keeping "
        "the real UID as jsmith. Enables root file access without full root."
    ),
    why=(
        "seteuid ∈ PRIVESC_SYSCALLS. result='success'. "
        "uid=1001 (non-root) AND euid=0 (root EUID) → CRITICAL severity. "
        "This is the most dangerous priv-esc pattern — full root privilege gain."
    ),
    events=[
        _ke(
            "seteuid", "spine-p01", ts=_T_PRIV,
            uid=_VICTIM_UID, euid=0,
            result="success", pid=22222, comm="stage1",
        )
    ],
    expect_count=1,
    expect_event_types=["kernel_privesc_syscall"],
    expect_severity=Severity.CRITICAL,
)

_SPINE_PRIV_POS2 = AdversarialCase(
    id="spine_capset_capability_gain",
    title="capset by uid=1001 — capability manipulation → MEDIUM",
    category="positive",
    description=(
        "Dropper uses capset() to add CAP_SYS_PTRACE or CAP_NET_RAW without "
        "gaining full root. Capability manipulation is quieter than setuid."
    ),
    why=(
        "capset ∈ PRIVESC_SYSCALLS. result='success'. "
        "uid=1001, euid=1001 (uid==euid, both non-zero) → MEDIUM severity. "
        "Capability grants are tracked even without full root privilege gain."
    ),
    events=[
        _ke(
            "capset", "spine-p02", ts=_T_PRIV + int(5 * 1e9),
            uid=_VICTIM_UID, euid=_VICTIM_UID,
            result="success", pid=22222, comm="stage1",
        )
    ],
    expect_count=1,
    expect_event_types=["kernel_privesc_syscall"],
    expect_severity=Severity.MEDIUM,
)

_SPINE_PRIV_EVA1 = AdversarialCase(
    id="spine_privesc_seteuid_eperm",
    title="seteuid(0) denied (EPERM) — probe skips failed syscalls → EVADES",
    category="evasion",
    description=(
        "Attacker tries seteuid(0) but lacks the necessary capabilities "
        "(no setuid binary, no CAP_SETUID). Kernel rejects with EPERM. "
        "The probe only watches SUCCESSFUL privilege changes."
    ),
    why=(
        "EVADES: PrivEscSyscallProbe filters result == 'success'. "
        "result='failed' → event skipped. Zero events emitted. "
        "Failed attempts indicate pre-exploitation probing — missed by design."
    ),
    events=[
        _ke(
            "seteuid", "spine-p03", ts=_T_PRIV + int(10 * 1e9),
            uid=_VICTIM_UID, euid=_VICTIM_UID,
            result="failed", pid=22222, comm="stage1",
        )
    ],
    expect_count=0,
    expect_evades=True,
)

_SPINE_PRIV_BENIGN = AdversarialCase(
    id="spine_privesc_non_privesc_syscall",
    title="execve syscall (not in PRIVESC_SYSCALLS) → no priv-esc alert",
    category="benign",
    description=(
        "A legitimate execve kernel event arrives at the same time. "
        "execve is not in PRIVESC_SYSCALLS — the probe only watches "
        "setuid/seteuid/setgid/capset and related syscalls."
    ),
    why=(
        "syscall='execve' not in PRIVESC_SYSCALLS → iteration skips event. "
        "No TelemetryEvent emitted. Lateral syscalls are not false-positives."
    ),
    events=[
        _ke(
            "execve", "spine-p04", ts=_T_PRIV + int(15 * 1e9),
            uid=_VICTIM_UID, euid=_VICTIM_UID,
            result="success", pid=22222, comm="stage1", exe="/tmp/stage1",
        )
    ],
    expect_count=0,
)

_SPINE_DEGRADED_PRIVESC_NO_RESULT = AdversarialCase(
    id="spine_degraded_privesc_no_result",
    title="seteuid with result=None — probe skips gracefully, no false positive",
    category="benign",
    description=(
        "Kernel audit record arrives with result=None (outcome field dropped by collector). "
        "PrivEscSyscallProbe checks `if ke.result != 'success': continue`. "
        "None != 'success' evaluates True, so the event is skipped cleanly."
    ),
    why=(
        "result=None → None != 'success' → True → continue. "
        "Probe gracefully handles missing result field. expect_count=0 — "
        "missing outcome field causes missed detection (not a crash or FP)."
    ),
    events=[
        _ke(
            "seteuid", "spine-deg-p01", ts=_T_PRIV,
            uid=_VICTIM_UID, euid=0,
            pid=22222, comm="stage1",
        )
    ],
    expect_count=0,
)

_SPINE_PRIV_ESC = Scenario(
    probe_id="privesc_syscall",
    agent="kernel_audit",
    name="spine_privilege_escalation",
    title="Kill-Chain Phase 3: Privilege Escalation (Privilege Escalation)",
    description=(
        "Dropper calls seteuid(0) to gain root EUID. Tests PrivEscSyscallProbe "
        "and the failed-syscall-evasion gap."
    ),
    mitre_techniques=["T1068"],
    mitre_tactics=["Privilege Escalation"],
    probe_factory=PrivEscSyscallProbe,
    cases=[
        _SPINE_PRIV_POS1,
        _SPINE_PRIV_POS2,
        _SPINE_PRIV_EVA1,
        _SPINE_PRIV_BENIGN,
        _SPINE_DEGRADED_PRIVESC_NO_RESULT,
    ],
)
register(_SPINE_PRIV_ESC)


# =============================================================================
# Phase 4: C2 Implant — BinaryFromTempProbe  (proc agent / psutil-mocked)
# =============================================================================

_SPINE_IMPL_POS1 = AdversarialCase(
    id="spine_c2_implant_from_tmp",
    title="/tmp/c2_beacon running as jsmith → execution_from_temp HIGH",
    category="positive",
    description=(
        "C2 implant started from /tmp/c2_beacon. BinaryFromTempProbe spots "
        "the temp-dir exe path in the running process list."
    ),
    why=(
        "exe='/tmp/c2_beacon' matches TEMP_PATTERNS r'/tmp/'. "
        "pid not in reported_pids (fresh probe) → execution_from_temp HIGH."
    ),
    events=[],
    now_ns=_T_IMPL,
    patch_targets={
        _PA: True,
        _PI: _mock_iter(
            _mk_proc(pid=22222, name="c2_beacon", exe="/tmp/c2_beacon",
                     cmdline=["/tmp/c2_beacon", "--stealth"],
                     username=_VICTIM_USER)
        ),
    },
    expect_count=1,
    expect_event_types=["execution_from_temp"],
    expect_severity=Severity.HIGH,
)

_SPINE_IMPL_POS2 = AdversarialCase(
    id="spine_implant_macos_tempdir",
    title="/private/var/folders/.../T/malware (macOS temp) → execution_from_temp HIGH",
    category="positive",
    description=(
        "Implant uses a macOS-specific Temporary Items folder path. "
        "BinaryFromTempProbe includes the /private/var/folders/ pattern "
        "to catch macOS temp-dir payloads."
    ),
    why=(
        "exe starts with /private/var/folders/ → matches macOS TEMP_PATTERNS. "
        "→ execution_from_temp HIGH."
    ),
    events=[],
    now_ns=_T_IMPL + int(5 * 1e9),
    patch_targets={
        _PA: True,
        _PI: _mock_iter(
            _mk_proc(pid=23000, name="malware",
                     exe="/private/var/folders/xx/abc123/T/malware",
                     cmdline=["/private/var/folders/xx/abc123/T/malware"],
                     username=_VICTIM_USER)
        ),
    },
    expect_count=1,
    expect_event_types=["execution_from_temp"],
    expect_severity=Severity.HIGH,
)

_SPINE_IMPL_EVA1 = AdversarialCase(
    id="spine_implant_moved_to_usr_local_bin",
    title="Implant copied to /usr/local/bin/updater — not a temp dir → EVADES",
    category="evasion",
    description=(
        "Attacker copies the implant to /usr/local/bin/updater before "
        "re-executing it. BinaryFromTempProbe only watches TEMP_PATTERNS — "
        "/usr/local/bin is a clean path."
    ),
    why=(
        "EVADES: exe='/usr/local/bin/updater' does not match any TEMP_PATTERNS. "
        "Process is not flagged. Moving malware to standard system paths is a "
        "common post-exploitation cleanup step."
    ),
    events=[],
    patch_targets={
        _PA: True,
        _PI: _mock_iter(
            _mk_proc(pid=22222, name="updater",
                     exe="/usr/local/bin/updater",
                     cmdline=["/usr/local/bin/updater"],
                     username=_VICTIM_USER)
        ),
    },
    expect_count=0,
    expect_evades=True,
)

_SPINE_IMPL_BENIGN = AdversarialCase(
    id="spine_implant_chrome_in_applications",
    title="Chrome renderer in /Applications — not a temp dir → no alert",
    category="benign",
    description=(
        "Google Chrome renderer subprocess runs from its app bundle. "
        "Application bundles in /Applications are standard paths, not temp dirs."
    ),
    why=(
        "exe starts with /Applications/ → does not match any TEMP_PATTERNS. "
        "Chrome helper processes are legitimate; no execution_from_temp fired."
    ),
    events=[],
    patch_targets={
        _PA: True,
        _PI: _mock_iter(
            _mk_proc(pid=31000, name="Google Chrome Helper",
                     exe="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome Helper",
                     cmdline=["Google Chrome Helper"],
                     username=_VICTIM_USER)
        ),
    },
    expect_count=0,
)

_SPINE_DEGRADED_IMPLANT_NO_EXE = AdversarialCase(
    id="spine_degraded_implant_no_exe",
    title="psutil process with exe=None — probe skips gracefully, no false positive",
    category="benign",
    description=(
        "Psutil returns info['exe']=None for a process (path unresolvable, "
        "e.g. process exited between iteration and attribute fetch). "
        "BinaryFromTempProbe coerces: `exe = info.get('exe', '') or ''`. "
        "Empty string does not match any TEMP_PATTERNS — no event fired."
    ),
    why=(
        "info['exe']=None → `None or ''` → exe='' → re.search(pattern, '') → no match. "
        "Probe handles None exe gracefully. expect_count=0 — "
        "unresolvable exe path causes missed detection, not a crash or FP."
    ),
    events=[],
    now_ns=_T_IMPL + int(60 * 1e9),
    patch_targets={
        _PA: True,
        _PI: _mock_iter(
            _mk_proc(pid=22222, name="c2_beacon", exe=None,
                     cmdline=[],
                     username=_VICTIM_USER)
        ),
    },
    expect_count=0,
)

_SPINE_PROCESS_IMPLANT = Scenario(
    probe_id="binary_from_temp",
    agent="proc",
    name="spine_process_implant",
    title="Kill-Chain Phase 4: C2 Implant from /tmp (Execution / Persistence)",
    description=(
        "C2 implant runs persistently from /tmp/c2_beacon. Tests "
        "BinaryFromTempProbe and the path-relocation evasion gap."
    ),
    mitre_techniques=["T1204", "T1059"],
    mitre_tactics=["Execution", "Persistence"],
    probe_factory=BinaryFromTempProbe,
    cases=[
        _SPINE_IMPL_POS1,
        _SPINE_IMPL_POS2,
        _SPINE_IMPL_EVA1,
        _SPINE_IMPL_BENIGN,
        _SPINE_DEGRADED_IMPLANT_NO_EXE,
    ],
)
register(_SPINE_PROCESS_IMPLANT)


# =============================================================================
# Phase 5: Credential Harvest — PtraceAbuseProbe
# =============================================================================

_SPINE_PTRACE_POS1 = AdversarialCase(
    id="spine_ptrace_sshd_credential_dump",
    title="ptrace on sshd (protected) → kernel_ptrace_abuse CRITICAL",
    category="positive",
    description=(
        "Root attacker uses gdb to ptrace-attach to sshd, enabling live "
        "credential interception. sshd is in PROTECTED_PROCESSES because "
        "compromising it allows full authentication bypass."
    ),
    why=(
        "sshd execve event populates pid_to_comm[888]='sshd'. "
        "ptrace event: dest_pid=888 → target_comm='sshd' ∈ PROTECTED_PROCESSES "
        "→ CRITICAL severity. Harvesting creds from the auth daemon."
    ),
    events=[
        # Populate pid_to_comm so dest_pid=888 resolves to 'sshd'
        _ke("execve", "spine-t01-sshd", ts=_T_PTRACE,
            uid=0, euid=0, pid=888, comm="sshd", exe="/usr/sbin/sshd"),
        _ke("ptrace", "spine-t01", ts=_T_PTRACE + int(2 * 1e9),
            uid=0, euid=0, pid=22222, dest_pid=888, comm="gdb",
            exe="/usr/bin/gdb"),
    ],
    expect_count=1,
    expect_event_types=["kernel_ptrace_abuse"],
    expect_severity=Severity.CRITICAL,
)

_SPINE_PTRACE_POS2 = AdversarialCase(
    id="spine_ptrace_chrome_cookie_theft",
    title="Non-root ptrace on chrome (non-protected) → kernel_ptrace_abuse HIGH",
    category="positive",
    description=(
        "Attacker (uid=1001) uses ptrace to attach to Chrome, enabling cookie "
        "and password extraction. Chrome is not in PROTECTED_PROCESSES but "
        "non-root cross-process ptrace is almost always malicious."
    ),
    why=(
        "ptrace ∈ PTRACE_SYSCALLS. dest_pid=7777 target is not protected. "
        "uid=1001 (non-root) → elif uid != 0 branch → HIGH severity. "
        "All non-root ptrace deserves high-severity scrutiny."
    ),
    events=[
        _ke("ptrace", "spine-t02", ts=_T_PTRACE + int(10 * 1e9),
            uid=_VICTIM_UID, euid=_VICTIM_UID,
            pid=22222, dest_pid=7777, comm="spy",
            exe="/tmp/cookie_spy"),
    ],
    expect_count=1,
    expect_event_types=["kernel_ptrace_abuse"],
    expect_severity=Severity.HIGH,
)

_SPINE_PTRACE_EVA1 = AdversarialCase(
    id="spine_ptrace_proc_mem_evasion",
    title="Attacker reads /proc/<pid>/mem via open() — not ptrace → EVADES",
    category="evasion",
    description=(
        "Sophisticated attacker avoids ptrace entirely. On Linux, opening "
        "/proc/<pid>/mem provides read/write access to another process's "
        "address space without generating ptrace audit events. "
        "PtraceAbuseProbe only watches ptrace/process_vm_readv/process_vm_writev."
    ),
    why=(
        "EVADES: syscall='openat' is not in PTRACE_SYSCALLS. "
        "Probe skips the event entirely. /proc/mem access is an "
        "implementation-level evasion of ptrace-based monitoring."
    ),
    events=[
        _ke("openat", "spine-t03", ts=_T_PTRACE + int(20 * 1e9),
            uid=_VICTIM_UID, euid=_VICTIM_UID,
            pid=22222, dest_pid=888, comm="mem_reader",
            exe="/tmp/mem_reader"),
    ],
    expect_count=0,
    expect_evades=True,
)

_SPINE_PTRACE_BENIGN = AdversarialCase(
    id="spine_ptrace_execve_not_ptrace",
    title="execve event at ptrace time — wrong syscall type → no alert",
    category="benign",
    description=(
        "A legitimate execve kernel event arrives around the same time "
        "as the ptrace window. PtraceAbuseProbe only watches "
        "ptrace / process_vm_readv / process_vm_writev syscalls."
    ),
    why=(
        "syscall='execve' not in ('ptrace', 'process_vm_readv', "
        "'process_vm_writev') → probe skips event. "
        "No false-positive kernel_ptrace_abuse event emitted."
    ),
    events=[
        _ke("execve", "spine-t04", ts=_T_PTRACE + int(25 * 1e9),
            uid=_VICTIM_UID, euid=_VICTIM_UID,
            pid=22222, dest_pid=None, comm="bash",
            exe="/bin/bash"),
    ],
    expect_count=0,
)

_SPINE_DEGRADED_PTRACE_NO_DEST_PID = AdversarialCase(
    id="spine_degraded_ptrace_no_dest_pid",
    title="ptrace with dest_pid=None, uid=0 → fires at MEDIUM (partial data)",
    category="positive",
    description=(
        "Kernel audit record arrives with dest_pid=None (target PID field dropped). "
        "PtraceAbuseProbe still fires: syscall='ptrace' ∈ PTRACE_SYSCALLS. "
        "With dest_pid=None no protected-process lookup runs; uid=0 skips the "
        "non-root HIGH branch → default MEDIUM severity."
    ),
    why=(
        "dest_pid=None → target_comm=None → not PROTECTED_PROCESSES match. "
        "dest_pid != 1. uid=0 → `elif uid != 0` is False → stays MEDIUM. "
        "Probe still detects suspicious ptrace activity at lower confidence "
        "even with incomplete telemetry."
    ),
    events=[
        _ke(
            "ptrace", "spine-deg-t01", ts=_T_PTRACE + int(30 * 1e9),
            uid=0, euid=0,
            pid=22222, dest_pid=None, comm="gdb",
            exe="/usr/bin/gdb",
        )
    ],
    expect_count=1,
    expect_event_types=["kernel_ptrace_abuse"],
    expect_severity=Severity.MEDIUM,
)

_SPINE_PTRACE_CRED_HARVEST = Scenario(
    probe_id="ptrace_abuse",
    agent="kernel_audit",
    name="spine_ptrace_credential_harvest",
    title="Kill-Chain Phase 5: Credential Harvest via ptrace (Credential Access)",
    description=(
        "Attacker ptrace-attaches to sshd to harvest SSH credentials in "
        "real-time. Tests PtraceAbuseProbe and the /proc/mem evasion gap."
    ),
    mitre_techniques=["T1055", "T1003"],
    mitre_tactics=["Credential Access", "Defense Evasion"],
    probe_factory=PtraceAbuseProbe,
    cases=[
        _SPINE_PTRACE_POS1,
        _SPINE_PTRACE_POS2,
        _SPINE_PTRACE_EVA1,
        _SPINE_PTRACE_BENIGN,
        _SPINE_DEGRADED_PTRACE_NO_DEST_PID,
    ],
)
register(_SPINE_PTRACE_CRED_HARVEST)
