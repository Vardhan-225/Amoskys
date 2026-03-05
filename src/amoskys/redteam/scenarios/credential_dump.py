"""Cinematic credential dump scenario — the 'attacker touched the box' spine.

This scenario tells the complete story of an attacker performing macOS
credential dumping, exercising all 4 gap fixes (P0.1 interpreter, P0.2
cross-PID, P1.1 whitelist hardening, P1.2 temp DB) plus the original 3
detection vectors.

Narrative Arc:
  Phase 1: Attacker drops lazagne.py in /tmp and executes via python3
  Phase 2: Python3 process opens Keychain DB directly (file access vector)
  Phase 3: Attacker wraps security CLI in a shell to evade tool dispatch
  Phase 4: Attacker rotates PIDs to evade per-PID burst threshold
  Phase 5: Attacker spoofs comm to opendirectoryd to masquerade as system daemon
  Phase 6: Attacker copies Keychain to /tmp/kc_copy.db, queries via sqlite3
  Phase 7: Benign check — system daemon accessing Keychain (should NOT fire)
  Phase 8: Benign check — developer opening unrelated .db file (should NOT fire)

Together with KernelAudit + Proc + AuthGuard, this creates the full
"attacker touched the box" narrative spine.

Run:
  amoskys-redteam run credential_dump --report
"""

from __future__ import annotations

from amoskys.agents.common.probes import Severity
from amoskys.agents.kernel_audit.agent_types import KernelAuditEvent
from amoskys.agents.kernel_audit.probes import CredentialDumpProbe
from amoskys.redteam.harness import AdversarialCase, Scenario
from amoskys.redteam.scenarios import register

# ──────────────────────────────────────────────────────────────────────────────
# Timestamp anchors
# ──────────────────────────────────────────────────────────────────────────────

# Simulated attack: 2023-11-14T22:13:20Z (nice round number)
_T0 = int(1_700_000_000 * 1e9)          # Base timestamp (ns)
_T1 = _T0 + int(5 * 1e9)               # +5 seconds
_T2 = _T0 + int(12 * 1e9)              # +12 seconds
_T4_BASE = _T0 + int(25 * 1e9)         # +25s, for cross-PID burst sequence
_T5 = _T0 + int(90 * 1e9)              # +90 seconds
_T6 = _T0 + int(105 * 1e9)             # +105 seconds
_T7 = _T0 + int(120 * 1e9)             # +120 seconds (benign)
_T8 = _T0 + int(130 * 1e9)             # +130 seconds (benign)


def _ke(syscall: str, eid: str, ts: int = _T0, **kwargs) -> KernelAuditEvent:
    """Shorthand KernelAuditEvent factory for scenario events."""
    defaults = dict(
        event_id=eid,
        timestamp_ns=ts,
        host="victim-macbook",
        uid=501,
        euid=501,
        pid=31337,
        raw={},
    )
    defaults.update(kwargs)
    return KernelAuditEvent(syscall=syscall, **defaults)  # type: ignore[arg-type]


# ──────────────────────────────────────────────────────────────────────────────
# Phase 1: Interpreter-wrapped credential tool (P0.1)
# ──────────────────────────────────────────────────────────────────────────────

_PHASE1_LAZAGNE_EXEC = AdversarialCase(
    id="phase1_lazagne_python",
    title="python3 /tmp/lazagne.py — known tool via interpreter",
    category="positive",
    description=(
        "Attacker downloads lazagne.py to /tmp and executes via python3. "
        "The probe dispatch table only matched direct tool names (security, dscl, sqlite3), "
        "so python3 wrapping was an evasion until P0.1 added interpreter cmdline scanning."
    ),
    why=(
        "The P0.1 fix adds _check_interpreter_cmdline() which checks if the cmdline "
        "contains a script filename matching _KNOWN_TOOL_SCRIPT_NAMES. "
        "'lazagne.py' is in that set → fires interpreter_cred_tool_exec HIGH."
    ),
    events=[
        _ke(
            "execve",
            eid="ka-001",
            ts=_T0,
            exe="/usr/bin/python3",
            comm="python3",
            cmdline="python3 /tmp/lazagne.py all",
            pid=31337,
            uid=501,
        )
    ],
    now_ns=_T0,
    expect_count=1,
    expect_event_types=["interpreter_cred_tool_exec"],
    expect_severity=Severity.HIGH,
)

# ──────────────────────────────────────────────────────────────────────────────
# Phase 2: Direct Keychain file access (Vector 1)
# ──────────────────────────────────────────────────────────────────────────────

_PHASE2_KEYCHAIN_OPEN = AdversarialCase(
    id="phase2_direct_keychain_open",
    title="python3 opens login.keychain-db directly",
    category="positive",
    description=(
        "The lazagne.py script opens the user's login keychain database directly "
        "via Python's built-in open() — which generates an openat syscall. "
        "This is Vector 1: direct credential store file access."
    ),
    why=(
        "Vector 1 catches any non-whitelisted process opening a path that ends "
        "in .keychain-db under */Library/Keychains/. "
        "python3 is not in _CRED_FILE_ACCESS_WHITELIST → keychain_direct_access HIGH."
    ),
    events=[
        _ke(
            "openat",
            eid="ka-002",
            ts=_T1,
            path="/Users/victim/Library/Keychains/login.keychain-db",
            comm="python3",
            exe="/usr/bin/python3",
            pid=31337,
            uid=501,
        )
    ],
    now_ns=_T1,
    expect_count=1,
    expect_event_types=["credential_file_access"],
    expect_severity=Severity.HIGH,
)

# ──────────────────────────────────────────────────────────────────────────────
# Phase 3: Shell-wrapped security CLI (P0.1, interpreter fallback)
# ──────────────────────────────────────────────────────────────────────────────

_PHASE3_SH_SECURITY_DUMP = AdversarialCase(
    id="phase3_sh_security_dump",
    title="sh -c 'security dump-keychain -d' — shell wrapping evasion",
    category="positive",
    description=(
        "Attacker wraps the `security dump-keychain` call inside a shell invocation. "
        "Prior to P0.1, only `exe_name == 'security'` triggered the handler. "
        "With sh as the exe, the dispatch table had no match. "
        "P0.1 adds _check_interpreter_cmdline() as a fallback for shell executables."
    ),
    why=(
        "The interpreter cmdline checker sees 'security' in the cmdline arguments. "
        "The 'dump-keychain' subcommand is the most dangerous security action. "
        "Fires interpreter_security_exec HIGH (confidence 0.75, strong pattern match)."
    ),
    events=[
        _ke(
            "execve",
            eid="ka-003",
            ts=_T2,
            exe="/bin/sh",
            comm="sh",
            cmdline="sh -c security dump-keychain -d /Users/victim/Library/Keychains/login.keychain-db",
            pid=31338,
            uid=501,
        )
    ],
    now_ns=_T2,
    expect_count=1,
    expect_event_types=["interpreter_security_exec"],
    expect_severity=Severity.HIGH,
)

# ──────────────────────────────────────────────────────────────────────────────
# Phase 4: Cross-PID burst (P0.2)
# ──────────────────────────────────────────────────────────────────────────────

def _build_cross_pid_events() -> list:
    """Build 5 PIDs × 2 calls each = 10 total calls for uid=501.

    The cross-PID burst threshold is KEYCHAIN_BURST_THRESHOLD=10.
    5 PIDs × 2 calls = 10 entries — exactly at threshold.
    Each individual PID only makes 2 calls, well under the per-PID limit of 10.
    """
    events = []
    for pid_offset in range(5):
        pid = 40000 + pid_offset
        for call_idx in range(2):  # 2 calls per PID
            events.append(
                _ke(
                    "execve",
                    eid=f"ka-{10 + pid_offset * 2 + call_idx:03d}",
                    ts=_T4_BASE + int((pid_offset * 2 + call_idx) * 1e9),
                    exe="/usr/bin/security",
                    comm="security",
                    cmdline=f"security find-generic-password -s svc{pid_offset} -a victim",
                    pid=pid,
                    uid=501,  # Same UID — cross-PID tracking catches this
                )
            )
    return events


_PHASE4_CROSS_PID_BURST = AdversarialCase(
    id="phase4_cross_pid_burst",
    title="5 PIDs × 2 calls each — cross-PID burst evasion (10 total)",
    category="positive",
    description=(
        "Attacker spawns 5 separate processes, each making 2 "
        "`security find-generic-password` calls (10 total). "
        "The per-PID burst threshold is 10 calls/60s — "
        "each individual PID makes only 2 calls, staying far under the limit. "
        "P0.2 adds cross-PID burst tracking by UID: 10 entries across 5 PIDs "
        "for uid=501 meets the threshold and fires the burst alert."
    ),
    why=(
        "The _check_cross_pid_burst() method tracks (timestamp_s, pid) tuples "
        "per UID in _uid_cred_calls. After the scan loop processes all 10 events, "
        "len(entries) >= KEYCHAIN_BURST_THRESHOLD(10) AND len(pids)=5 >= 2 → "
        "fires keychain_cross_pid_burst HIGH. "
        "The 10 per-call MEDIUM events also fire (keychain_security_exec), "
        "but the burst event is the key signal."
    ),
    events=_build_cross_pid_events(),
    now_ns=_T4_BASE + int(15 * 1e9),  # Scan happens well after all events
    # Don't check total count — 10 per-call MEDIUM + 1 burst HIGH = 11 total.
    # Just verify the cross-PID burst event is present.
    expect_count=None,
    expect_event_types=["keychain_cross_pid_burst"],
    expect_severity=None,  # First event is MEDIUM per-call, burst is fired later
    stateful=True,  # Probe accumulates state across this case
)

# ──────────────────────────────────────────────────────────────────────────────
# Phase 5: Whitelist masquerade (P1.1)
# ──────────────────────────────────────────────────────────────────────────────

_PHASE5_COMM_SPOOF = AdversarialCase(
    id="phase5_comm_spoof_masquerade",
    title="prctl(PR_SET_NAME, 'opendirectoryd') — masquerade as system daemon",
    category="positive",
    description=(
        "Attacker uses prctl() to set the process comm to 'opendirectoryd', "
        "a legitimate macOS directory service daemon that IS in the whitelist. "
        "The probe would previously allow this as a trusted daemon. "
        "P1.1 cross-checks comm against expected exe paths — "
        "if comm matches but exe doesn't, it's a masquerade."
    ),
    why=(
        "The P1.1 fix adds _CRED_WHITELIST_EXE_PATHS mapping daemon comms "
        "to their canonical exe paths. When comm='opendirectoryd' but "
        "exe='/tmp/evil' (not '/usr/libexec/opendirectoryd'), "
        "fires masquerade_whitelist_break CRITICAL (confidence 0.92)."
    ),
    events=[
        _ke(
            "openat",
            eid="ka-020",
            ts=_T5,
            path="/var/db/dslocal/nodes/Default/users/admin.plist",
            comm="opendirectoryd",  # Spoofed to whitelist name
            exe="/tmp/evil",        # Real exe doesn't match
            pid=31340,
            uid=501,
        )
    ],
    now_ns=_T5,
    expect_count=1,
    expect_event_types=["masquerade_whitelist_break"],
    expect_severity=Severity.CRITICAL,
)

# ──────────────────────────────────────────────────────────────────────────────
# Phase 6: Copy-then-query (P1.2 — LOW signal, correlation_needed)
# ──────────────────────────────────────────────────────────────────────────────

_PHASE6_TEMP_DB_SQLITE3 = AdversarialCase(
    id="phase6_sqlite3_temp_db",
    title="sqlite3 /tmp/kc_copy.db — copy-then-query evasion",
    category="positive",
    description=(
        "Attacker copies the Keychain DB to /tmp/kc_copy.db first "
        "(the cp step evades direct file-access detection since /tmp "
        "is not a Keychain path), then queries the copy with sqlite3. "
        "P1.2 adds detection for sqlite3 invocations on temp .db files."
    ),
    why=(
        "The _is_temp_db_path() helper detects .db/.sqlite/.sqlite3 files "
        "in /tmp, /var/tmp, /dev/shm, /private/tmp. "
        "Fires sqlite3_temp_db_access LOW with correlation_needed=True. "
        "The LOW severity signals the fusion engine should look for a prior "
        "keychain copy event to confirm this is credential dumping."
    ),
    events=[
        _ke(
            "execve",
            eid="ka-021",
            ts=_T6,
            exe="/usr/bin/sqlite3",
            comm="sqlite3",
            cmdline="sqlite3 /tmp/kc_copy.db .dump",
            pid=31341,
            uid=501,
        )
    ],
    now_ns=_T6,
    expect_count=1,
    expect_event_types=["sqlite3_temp_db_access"],
    expect_severity=Severity.LOW,
)

# ──────────────────────────────────────────────────────────────────────────────
# Phase 7: Benign — legitimate daemon (should NOT fire)
# ──────────────────────────────────────────────────────────────────────────────

_PHASE7_BENIGN_DAEMON = AdversarialCase(
    id="phase7_benign_opendirectoryd",
    title="opendirectoryd opening user.plist — legitimate system daemon",
    category="benign",
    description=(
        "The real opendirectoryd process opens user plist files as part of "
        "normal directory service operation. The probe must NOT fire on this "
        "because opendirectoryd is in _CRED_FILE_ACCESS_WHITELIST, "
        "AND its exe matches the expected /usr/libexec/opendirectoryd path."
    ),
    why=(
        "Whitelist check: comm='opendirectoryd' → check exe. "
        "exe='/usr/libexec/opendirectoryd' == expected_exe → legitimate daemon. "
        "Returns None immediately. Zero events fired. No false positive."
    ),
    events=[
        _ke(
            "openat",
            eid="ka-030",
            ts=_T7,
            path="/var/db/dslocal/nodes/Default/users/admin.plist",
            comm="opendirectoryd",
            exe="/usr/libexec/opendirectoryd",  # Matches expected path
            pid=333,
            uid=0,
        )
    ],
    now_ns=_T7,
    expect_count=0,  # Zero events — legitimate daemon
    expect_evades=False,
)

# ──────────────────────────────────────────────────────────────────────────────
# Phase 8: Benign — developer sqlite3 on a non-keychain DB (should NOT fire)
# ──────────────────────────────────────────────────────────────────────────────

_PHASE8_BENIGN_DEV_SQLITE3 = AdversarialCase(
    id="phase8_benign_dev_sqlite3",
    title="sqlite3 ~/Documents/app.db — developer querying their own DB",
    category="benign",
    description=(
        "A developer uses sqlite3 to query their own app database at "
        "~/Documents/app.db. This is NOT in a temp directory and NOT "
        "a Keychain path. The probe should NOT fire on this."
    ),
    why=(
        "sqlite3 dispatch: cmdline checked for Keychain path → no match. "
        "_is_temp_db_path() checks for /tmp/, /var/tmp/, /dev/shm/, /private/tmp/ → "
        "~/Documents/ does not match any temp prefix → returns []. "
        "Zero events. Zero false positives."
    ),
    events=[
        _ke(
            "execve",
            eid="ka-031",
            ts=_T8,
            exe="/usr/bin/sqlite3",
            comm="sqlite3",
            cmdline="sqlite3 /Users/developer/Documents/app.db .schema",
            pid=31345,
            uid=501,
        )
    ],
    now_ns=_T8,
    expect_count=0,
    expect_evades=False,
)

# ──────────────────────────────────────────────────────────────────────────────
# Register the scenario
# ──────────────────────────────────────────────────────────────────────────────

CREDENTIAL_DUMP_SCENARIO: Scenario = register(
    Scenario(
        probe_id="credential_dump",
        agent="kernel_audit",
        name="credential_dump",
        title="macOS Credential Dump: Full Kill-Chain (T1003 / T1555.001)",
        description=(
            "An attacker targets a macOS host running AMOSKYS. "
            "They attempt credential dumping via multiple techniques: "
            "script interpreter wrapping (lazagne.py via python3), "
            "direct Keychain file access, shell-wrapped security CLI calls, "
            "cross-PID burst evasion (5 PIDs × 2 calls each = 10 total), "
            "process comm masquerading (spoofed to opendirectoryd), "
            "and a copy-then-query attack on a temp Keychain copy. "
            "\n\n"
            "AMOSKYS CredentialDumpProbe detects all positive cases "
            "and correctly ignores the two benign cases. "
            "The LOW-severity temp-DB event signals the fusion engine "
            "to correlate with upstream copy activity."
        ),
        mitre_techniques=["T1003", "T1555", "T1555.001"],
        mitre_tactics=["Credential Access"],
        probe_factory=CredentialDumpProbe,
        cases=[
            _PHASE1_LAZAGNE_EXEC,
            _PHASE2_KEYCHAIN_OPEN,
            _PHASE3_SH_SECURITY_DUMP,
            _PHASE4_CROSS_PID_BURST,
            _PHASE5_COMM_SPOOF,
            _PHASE6_TEMP_DB_SQLITE3,
            _PHASE7_BENIGN_DAEMON,
            _PHASE8_BENIGN_DEV_SQLITE3,
        ],
    )
)
