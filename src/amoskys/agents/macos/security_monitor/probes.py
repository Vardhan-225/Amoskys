"""macOS Security Monitor — Micro-Probes.

These probes operate on what MacOSUnifiedLogCollector actually delivers on macOS 26.0:
    - Events from com.apple.securityd (PKI, cert validation, notarization)
    - Fields reliably available: exe (processImagePath), pid, comm, action
    - Fields NEVER available: syscall, uid, euid, ppid, cmdline, path

Probes are designed around what the unified log actually shows, not what we
wish a kernel syscall monitor would provide. They detect anomalies in the
macOS security framework layer itself.

MITRE mapping notes:
    T1553.001 — Gatekeeper bypass (subvert trust controls)
    T1562     — Impair defenses (disabling security framework)
    T1592     — Gather victim host information (enumeration via cert checks)
"""

from __future__ import annotations

import logging
import time
from collections import Counter, defaultdict, deque
from typing import Any, Deque, Dict, List, Optional, Tuple

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)
from amoskys.agents.linux.kernel_audit.agent_types import KernelAuditEvent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Correlation group tags
# ---------------------------------------------------------------------------
_TAG_SECURITY_FRAMEWORK = "correlation_group:security_framework"
_TAG_GATEKEEPER = "correlation_group:gatekeeper"
_TAG_CERT_ANOMALY = "correlation_group:certificate_anomaly"
_TAG_DEFENSE_EVASION = "correlation_group:defense_evasion"

# ---------------------------------------------------------------------------
# Known security daemon process names (what we expect to see logging)
# ---------------------------------------------------------------------------
_KNOWN_SECURITY_PROCS = frozenset(
    {
        "trustd",
        "syspolicyd",
        "securityd",
        "secd",
        "authd",
        "sandboxd",
        "amfid",
        "appstoreagent",
        "accountsd",
        "storeassetd",
        "trustdfilesd",
        "searchpartyuseragent",
        "xpcproxy",
    }
)

# syspolicyd categories that indicate Gatekeeper enforcement activity
_SYSPOLICY_ERROR_MSGS = frozenset(
    {
        "unable to initialize qtn_proc",
        "dispatch_mig_server returned",
        "error checking with notarization daemon",
    }
)


# =============================================================================
# Probe 1: Security Framework Activity Flood
# =============================================================================


class SecurityFrameworkFloodProbe(MicroProbe):
    """Detects abnormal volumes of security framework events from a single process.

    On macOS, the security framework layer sees PKI, trust evaluation, and
    sandbox enforcement events. A burst from an unusual process can indicate:
        - Malware performing mass cert lookups during C2 setup
        - Credential-dumping tools enumerating the keychain
        - Security scanner performing bulk certificate operations

    Normal baseline (measured on macOS 26.0):
        - trustd: 30-60 events/min (routine cert validation)
        - syspolicyd: 0-20 events/min (Gatekeeper checks)
        - Any other process: < 5 events/10s window

    MITRE ATT&CK: T1592 (Gather Victim Host Information)
    """

    name = "security_framework_flood"
    description = "Detect abnormal security framework event volumes per process"
    mitre_techniques = ["T1592", "T1555"]
    mitre_tactics = ["Reconnaissance", "Credential Access"]
    platforms = ["darwin"]
    requires_fields = ["kernel_events"]

    FLOOD_THRESHOLD = 50   # events per 10s window from a single non-baseline pid
    SYSTEM_DAEMON_THRESHOLD = 200  # higher bar for known security daemons

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        kernel_events: List[KernelAuditEvent] = context.shared_data.get(
            "kernel_events", []
        )

        pid_events: Dict[int, List[KernelAuditEvent]] = defaultdict(list)
        for ke in kernel_events:
            if ke.pid:
                pid_events[ke.pid].append(ke)

        for pid, evts in pid_events.items():
            count = len(evts)
            sample = evts[0]
            comm = (sample.comm or "").lower()

            threshold = (
                self.SYSTEM_DAEMON_THRESHOLD
                if comm in _KNOWN_SECURITY_PROCS
                else self.FLOOD_THRESHOLD
            )

            if count >= threshold:
                events.append(
                    TelemetryEvent(
                        event_type="security_framework_flood",
                        severity=Severity.MEDIUM,
                        probe_name=self.name,
                        timestamp_ns=sample.timestamp_ns,
                        data={
                            "host": sample.host,
                            "pid": pid,
                            "exe": sample.exe,
                            "comm": sample.comm,
                            "event_count": count,
                            "threshold": threshold,
                            "is_known_daemon": comm in _KNOWN_SECURITY_PROCS,
                            "reason": (
                                f"{sample.comm} (pid={pid}) generated {count} "
                                f"security framework events in one cycle "
                                f"(threshold={threshold})"
                            ),
                        },
                        mitre_techniques=self.mitre_techniques,
                        mitre_tactics=self.mitre_tactics,
                        confidence=0.6,
                        tags=[_TAG_SECURITY_FRAMEWORK],
                    )
                )

        return events


# =============================================================================
# Probe 2: Gatekeeper / Notarization Anomaly
# =============================================================================


class GatekeeperAnomalyProbe(MicroProbe):
    """Detects Gatekeeper and notarization enforcement failures.

    syspolicyd is macOS's Gatekeeper enforcement daemon. Errors from it can
    indicate:
        - Apps bypassing Gatekeeper (missing/invalid notarization)
        - Code signature verification failures (tampered binaries)
        - Notarization service unreachability (DNS-based evasion)

    On a healthy system, syspolicyd errors are sporadic. Sustained bursts
    indicate either a broken daemon or active bypass attempts.

    MITRE ATT&CK: T1553.001 (Code Signing), T1562.001 (Disable or Modify Tools)
    """

    name = "gatekeeper_anomaly"
    description = "Detect Gatekeeper and code signing enforcement anomalies"
    mitre_techniques = ["T1553.001", "T1562.001"]
    mitre_tactics = ["Defense Evasion"]
    platforms = ["darwin"]
    requires_fields = ["kernel_events"]

    BURST_THRESHOLD = 30  # syspolicyd errors per cycle indicating anomaly
    UNKNOWN_PROCESS_THRESHOLD = 5  # non-syspolicyd security exceptions

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        kernel_events: List[KernelAuditEvent] = context.shared_data.get(
            "kernel_events", []
        )

        syspolicyd_errors = 0
        unknown_security_exceptions: List[KernelAuditEvent] = []

        for ke in kernel_events:
            comm = (ke.comm or "").lower()
            raw_msg = ke.raw.get("eventMessage", "").lower()

            if comm == "syspolicyd":
                # syspolicyd errors — potential Gatekeeper bypass signals
                if any(err in raw_msg for err in _SYSPOLICY_ERROR_MSGS):
                    syspolicyd_errors += 1

            elif comm not in _KNOWN_SECURITY_PROCS:
                # Unknown process generating securityd events
                cat = ke.raw.get("category", "").lower()
                if cat in ("security_exception", "secerror"):
                    unknown_security_exceptions.append(ke)

        if syspolicyd_errors >= self.BURST_THRESHOLD:
            events.append(
                TelemetryEvent(
                    event_type="gatekeeper_error_burst",
                    severity=Severity.MEDIUM,
                    probe_name=self.name,
                    timestamp_ns=int(time.time() * 1e9),
                    data={
                        "error_count": syspolicyd_errors,
                        "threshold": self.BURST_THRESHOLD,
                        "reason": (
                            f"syspolicyd generated {syspolicyd_errors} Gatekeeper "
                            f"enforcement errors in one cycle — possible bypass or "
                            f"daemon malfunction"
                        ),
                    },
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                    confidence=0.5,
                    tags=[_TAG_GATEKEEPER],
                )
            )

        if len(unknown_security_exceptions) >= self.UNKNOWN_PROCESS_THRESHOLD:
            sample = unknown_security_exceptions[0]
            events.append(
                TelemetryEvent(
                    event_type="unknown_process_security_exception",
                    severity=Severity.HIGH,
                    probe_name=self.name,
                    timestamp_ns=sample.timestamp_ns,
                    data={
                        "pid": sample.pid,
                        "exe": sample.exe,
                        "comm": sample.comm,
                        "exception_count": len(unknown_security_exceptions),
                        "reason": (
                            f"Non-system process {sample.comm!r} generated "
                            f"{len(unknown_security_exceptions)} security exceptions — "
                            f"possible code signing bypass or injection"
                        ),
                    },
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                    confidence=0.7,
                    tags=[_TAG_GATEKEEPER, _TAG_DEFENSE_EVASION],
                )
            )

        return events


# =============================================================================
# Probe 3: Certificate Chain Anomaly
# =============================================================================


class CertificateAnomalyProbe(MicroProbe):
    """Detects anomalous certificate validation patterns from trustd.

    trustd handles all TLS/PKI certificate validation on macOS. Anomalies include:
        - Mass cert failures from a single app (possible MITM or cert pinning bypass)
        - Malformed anchor records (tampered certificate store)
        - OCSP stapling failures at unusual rates (network-based evasion)
        - Trust evaluation failures for apps that shouldn't fail (tampered binary)

    MITRE ATT&CK: T1557 (Adversary-in-the-Middle), T1553 (Subvert Trust Controls)
    """

    name = "certificate_anomaly"
    description = "Detect anomalous certificate validation patterns via trustd"
    mitre_techniques = ["T1557", "T1553"]
    mitre_tactics = ["Credential Access", "Defense Evasion"]
    platforms = ["darwin"]
    requires_fields = ["kernel_events"]

    MALFORMED_ANCHOR_SEVERITY = Severity.HIGH
    CERT_FAILURE_BURST_THRESHOLD = 20  # cert failures per process per cycle

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        kernel_events: List[KernelAuditEvent] = context.shared_data.get(
            "kernel_events", []
        )

        malformed_anchors = 0
        cert_failures_by_proc: Dict[str, int] = defaultdict(int)

        for ke in kernel_events:
            comm = (ke.comm or "").lower()
            raw_msg = ke.raw.get("eventMessage", "").lower()
            cat = ke.raw.get("category", "").lower()

            # Malformed anchor = possible keychain store tampering
            if "malformed anchor" in raw_msg:
                malformed_anchors += 1

            # Cert failures per requesting process
            if cat in ("secerror", "security_exception", "ocsp", "trust"):
                if ke.raw.get("messageType", "") != "Debug":
                    cert_failures_by_proc[ke.exe or comm] += 1

        if malformed_anchors > 0:
            events.append(
                TelemetryEvent(
                    event_type="certificate_store_anomaly",
                    severity=self.MALFORMED_ANCHOR_SEVERITY,
                    probe_name=self.name,
                    timestamp_ns=int(time.time() * 1e9),
                    data={
                        "malformed_anchor_count": malformed_anchors,
                        "reason": (
                            f"trustd reported {malformed_anchors} malformed anchor "
                            f"record(s) — possible certificate store tampering"
                        ),
                    },
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                    confidence=0.75,
                    tags=[_TAG_CERT_ANOMALY],
                )
            )

        for proc, count in cert_failures_by_proc.items():
            if count >= self.CERT_FAILURE_BURST_THRESHOLD:
                events.append(
                    TelemetryEvent(
                        event_type="certificate_validation_burst",
                        severity=Severity.MEDIUM,
                        probe_name=self.name,
                        timestamp_ns=int(time.time() * 1e9),
                        data={
                            "process": proc,
                            "failure_count": count,
                            "threshold": self.CERT_FAILURE_BURST_THRESHOLD,
                            "reason": (
                                f"Process {proc!r} triggered {count} certificate "
                                f"validation failures in one cycle — possible MITM "
                                f"or cert pinning bypass attempt"
                            ),
                        },
                        mitre_techniques=self.mitre_techniques,
                        mitre_tactics=self.mitre_tactics,
                        confidence=0.6,
                        tags=[_TAG_CERT_ANOMALY],
                    )
                )

        return events


# =============================================================================
# Probe 4: Security Framework Health (Blind Spot Detection)
# =============================================================================


class SecurityFrameworkHealthProbe(MicroProbe):
    """Detects when the macOS security framework goes silent.

    On a running macOS system, com.apple.securityd logs at least occasional
    events from trustd and syspolicyd (cert checks, Gatekeeper activity).
    Complete silence for extended periods can indicate:
        - Security daemons have been killed (rootkit/implant hiding activity)
        - Sandboxing preventing log access
        - Agent permission issues

    This is a canary probe — it emits a signal when the sensor itself is blind.

    MITRE ATT&CK: T1562 (Impair Defenses)
    """

    name = "security_framework_health"
    description = "Canary: emit signal when security framework logs go silent"
    mitre_techniques = ["T1562"]
    mitre_tactics = ["Defense Evasion"]
    platforms = ["darwin"]
    requires_fields = ["kernel_events"]

    SILENCE_THRESHOLD = 3  # consecutive cycles with 0 events

    def __init__(self) -> None:
        super().__init__()
        self._zero_cycles: int = 0

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        kernel_events: List[KernelAuditEvent] = context.shared_data.get(
            "kernel_events", []
        )

        if not kernel_events:
            self._zero_cycles += 1
            if self._zero_cycles >= self.SILENCE_THRESHOLD:
                return [
                    TelemetryEvent(
                        event_type="security_framework_silent",
                        severity=Severity.HIGH,
                        probe_name=self.name,
                        timestamp_ns=int(time.time() * 1e9),
                        data={
                            "zero_cycle_count": self._zero_cycles,
                            "threshold": self.SILENCE_THRESHOLD,
                            "reason": (
                                f"macOS security framework produced 0 log events "
                                f"for {self._zero_cycles} consecutive cycles — "
                                f"possible security daemon interference or permission loss"
                            ),
                        },
                        mitre_techniques=self.mitre_techniques,
                        mitre_tactics=self.mitre_tactics,
                        confidence=0.65,
                        tags=[_TAG_DEFENSE_EVASION],
                    )
                ]
            return []

        self._zero_cycles = 0
        return []


# =============================================================================
# Factory
# =============================================================================


def create_macos_security_probes() -> List[MicroProbe]:
    """Create the default set of macOS security monitor probes.

    Returns:
        List of MicroProbe instances for the macOS security monitor agent.
    """
    return [
        SecurityFrameworkFloodProbe(),
        GatekeeperAnomalyProbe(),
        CertificateAnomalyProbe(),
        SecurityFrameworkHealthProbe(),
    ]


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    "SecurityFrameworkFloodProbe",
    "GatekeeperAnomalyProbe",
    "CertificateAnomalyProbe",
    "SecurityFrameworkHealthProbe",
    "create_macos_security_probes",
]
