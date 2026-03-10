"""macOS Temporal Correlation Probes — 6 timestamp-driven cross-domain probes.

These probes exploit timestamp data already collected by domain agents but
unused by the 12 snapshot-based correlation probes. They detect attack
patterns invisible to snapshot correlation:

    1. DropExecuteTimingProbe    — file.mtime → proc.create_time → outbound conn
    2. PersistenceActivationProbe — installed → first-run delta
    3. KillChainSequenceProbe    — ordered tactic progression over time
    4. AuthVelocityProbe         — failure acceleration + burst detection
    5. BeaconingProbe            — periodic C2 callback detection via jitter
    6. ExfilAccelerationProbe    — rate-of-change in outbound bytes

Design:
    - Each probe uses temporal_index and/or rolling window temporal methods
    - No probe modifies any existing data structure
    - All probes work alongside the 12 existing snapshot probes

Closes 11 additional evasion gaps:
    T1-T4, E2, E5, F1-F3, S1-S5, ab2
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Set

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)

logger = logging.getLogger(__name__)

# ── Shared constants ─────────────────────────────────────────────────────────

_LOLBIN_BASENAMES = frozenset(
    {
        "curl",
        "wget",
        "nc",
        "ncat",
        "netcat",
        "openssl",
        "ssh",
        "scp",
        "sftp",
        "rsync",
        "python3",
        "python",
        "ruby",
        "perl",
        "osascript",
        "pbcopy",
        "pbpaste",
        "screencapture",
        "dscl",
        "security",
        "defaults",
        "launchctl",
        "plutil",
        "base64",
        "xxd",
        "dd",
        "tar",
        "zip",
        "unzip",
        "mkfifo",
        "nslookup",
        "dig",
        "host",
        "tcpdump",
        "dtrace",
    }
)

from amoskys.agents.common.ip_utils import is_private_ip as _is_private

# CDN/infrastructure IPs that generate periodic connections but aren't C2
_CDN_DOMAINS = frozenset(
    {
        "17.0.",
        "17.253.",  # Apple
        "142.250.",
        "172.217.",  # Google
        "13.107.",
        "204.79.",  # Microsoft
        "23.0.",
        "23.32.",  # Akamai
        "104.16.",
        "104.17.",  # Cloudflare
    }
)


def _is_cdn(ip: str) -> bool:
    return any(ip.startswith(p) for p in _CDN_DOMAINS)


# Directories where dropped files typically appear
_DROP_PREFIXES = ("/tmp/", "/var/tmp/", "/private/tmp/")


# =============================================================================
# 1. DropExecuteTimingProbe
# =============================================================================


class DropExecuteTimingProbe(MicroProbe):
    """Detects download → execute → connect chain using timestamps.

    Closes: F1 (simultaneous presence requirement), T1 (no time-to-execution)

    Unlike DownloadExecuteChainProbe (snapshot), this probe proves CAUSATION
    by checking temporal proximity: file.mtime NEAR proc.create_time NEAR
    first outbound connection. Tight timing proves the file was dropped,
    executed, and called home — not coincidental co-existence.

    Scoring by temporal proximity:
        |create_time - mtime| < 5s   → confidence 0.95 (tight chain)
        |create_time - mtime| < 30s  → confidence 0.85
        |create_time - mtime| < 120s → confidence 0.70
    """

    name = "macos_corr_temporal_drop_execute"
    description = "File dropped, executed, and connected within seconds"
    platforms = ["darwin"]
    mitre_techniques = ["T1204", "T1059"]
    mitre_tactics = ["initial-access", "execution"]
    scan_interval = 10.0
    requires_fields = ["files", "processes", "pid_connections", "collection_ts"]

    _MAX_DELTA_SECONDS = 120.0

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        files = context.shared_data.get("files", [])
        processes = context.shared_data.get("processes", [])
        pid_conns = context.shared_data.get("pid_connections", {})
        collection_ts = context.shared_data.get("collection_ts", 0.0)

        if not collection_ts:
            return events

        # Find recently modified files in drop directories
        downloads_dir = os.path.expanduser("~/Downloads")
        recent_files: Dict[str, Any] = {}
        for f in files:
            in_drop_dir = f.path.startswith(downloads_dir) or any(
                f.path.startswith(p) for p in _DROP_PREFIXES
            )
            if not in_drop_dir:
                continue
            # Only consider files modified recently (within 2 minutes of collection)
            if collection_ts - f.mtime > self._MAX_DELTA_SECONDS:
                continue
            recent_files[f.path] = f

        if not recent_files:
            return events

        # Check processes whose exe matches a recent file AND have connections
        for proc in processes:
            if not proc.exe or proc.exe not in recent_files:
                continue

            f = recent_files[proc.exe]
            delta = abs(proc.create_time - f.mtime)
            if delta > self._MAX_DELTA_SECONDS:
                continue

            # Score by temporal proximity
            if delta < 5.0:
                confidence = 0.95
            elif delta < 30.0:
                confidence = 0.85
            else:
                confidence = 0.70

            # Check for outbound connections (strengthens the chain)
            conns = pid_conns.get(proc.pid, [])
            external = [
                c
                for c in conns
                if c.state == "ESTABLISHED"
                and c.remote_ip
                and not _is_private(c.remote_ip)
            ]
            has_outbound = len(external) > 0
            if has_outbound:
                confidence = min(confidence + 0.05, 0.98)

            severity = Severity.CRITICAL if has_outbound else Severity.HIGH

            events.append(
                self._create_event(
                    event_type="temporal_drop_execute",
                    severity=severity,
                    data={
                        "file_path": f.path,
                        "file_mtime": f.mtime,
                        "pid": proc.pid,
                        "process_name": proc.name,
                        "create_time": proc.create_time,
                        "delta_seconds": round(delta, 2),
                        "has_outbound": has_outbound,
                        "external_connections": len(external),
                        "correlation": "file_mtime_near_process_create_time",
                    },
                    confidence=confidence,
                    tags=["temporal", "drop-execute", "timing"],
                )
            )

        return events


# =============================================================================
# 2. PersistenceActivationTimingProbe
# =============================================================================


class PersistenceActivationTimingProbe(MicroProbe):
    """Detects recently-activated persistence mechanisms using create_time.

    Closes: T2 (no time-to-activation measurement)

    Unlike PersistenceExecutionProbe (snapshot: installed + running),
    this probe detects WHEN the persistence program was activated by
    comparing proc.create_time with collection_ts. If a persistence
    program was started since the last scan, it's newly activated.
    """

    name = "macos_corr_temporal_persistence_activation"
    description = "Persistence mechanism activated since last scan"
    platforms = ["darwin"]
    mitre_techniques = ["T1543", "T1547"]
    mitre_tactics = ["persistence", "execution"]
    scan_interval = 30.0
    requires_fields = ["entries", "processes", "collection_ts"]

    def __init__(self) -> None:
        super().__init__()
        self._last_collection_ts: float = 0.0
        self._known_programs: Set[str] = set()
        self._first_run = True

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        entries = context.shared_data.get("entries", [])
        processes = context.shared_data.get("processes", [])
        collection_ts = context.shared_data.get("collection_ts", 0.0)

        if not collection_ts:
            return events

        # Build process lookup: exe → ProcessSnapshot
        exe_to_proc: Dict[str, Any] = {}
        for p in processes:
            if p.exe:
                exe_to_proc[p.exe] = p

        # Get all persistence programs
        current_programs: Dict[str, Any] = {}
        for entry in entries:
            if entry.program:
                current_programs[entry.program] = entry

        if self._first_run:
            self._known_programs = set(current_programs.keys())
            self._last_collection_ts = collection_ts
            self._first_run = False
            return events

        scan_interval = collection_ts - self._last_collection_ts
        if scan_interval <= 0:
            scan_interval = 15.0  # fallback

        for program, entry in current_programs.items():
            proc = exe_to_proc.get(program)
            if proc is None:
                continue

            # Check if process was created since last scan
            time_since_creation = collection_ts - proc.create_time
            is_new_activation = time_since_creation < scan_interval * 2
            is_new_program = program not in self._known_programs

            if not is_new_activation:
                continue

            severity = Severity.CRITICAL if is_new_program else Severity.HIGH

            events.append(
                self._create_event(
                    event_type="temporal_persistence_activation",
                    severity=severity,
                    data={
                        "program": program,
                        "persistence_path": entry.path,
                        "persistence_category": entry.category,
                        "pid": proc.pid,
                        "create_time": proc.create_time,
                        "time_since_creation": round(time_since_creation, 2),
                        "is_new_program": is_new_program,
                        "scan_interval": round(scan_interval, 2),
                        "correlation": "persistence_program_created_since_last_scan",
                    },
                    confidence=0.9 if is_new_program else 0.75,
                    tags=["temporal", "persistence", "activation"],
                )
            )

        self._known_programs = set(current_programs.keys())
        self._last_collection_ts = collection_ts
        return events


# =============================================================================
# 3. KillChainSequenceProbe
# =============================================================================


class KillChainSequenceProbe(MicroProbe):
    """Detects ORDERED tactic progression over time.

    Closes: T3 (no tactic ordering), F2 (co-existence not progression)

    Unlike KillChainProgressionProbe (snapshot: 3+ simultaneous tactics),
    this probe tracks tactic ORDERING across scans using a persistent
    timeline. It fires when 3+ tactics appear in chronological order
    within a 30-minute window: e.g., initial_access(t1) → execution(t2)
    → persistence(t3) where t1 < t2 < t3.
    """

    name = "macos_corr_temporal_kill_chain"
    description = "Ordered tactic progression over time"
    platforms = ["darwin"]
    mitre_techniques = ["T1059", "T1071", "T1543", "T1078", "T1048"]
    mitre_tactics = [
        "initial-access",
        "execution",
        "persistence",
        "credential-access",
        "lateral-movement",
        "exfiltration",
        "command-and-control",
    ]
    scan_interval = 10.0
    requires_fields = [
        "processes",
        "connections",
        "entries",
        "auth_events",
        "files",
        "bandwidth",
        "collection_ts",
    ]

    _SEQUENCE_WINDOW = 1800.0  # 30 minutes
    _MIN_TACTICS = 3

    # Canonical tactic ordering (kill chain progression)
    _TACTIC_ORDER = {
        "initial-access": 0,
        "execution": 1,
        "persistence": 2,
        "credential-access": 3,
        "lateral-movement": 4,
        "command-and-control": 5,
        "exfiltration": 6,
    }

    def __init__(self) -> None:
        super().__init__()
        # Persistent timeline: list of (timestamp, tactic) tuples
        self._timeline: List[tuple] = []

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        collection_ts = context.shared_data.get("collection_ts", 0.0)
        if not collection_ts:
            return events

        # Detect active tactics in this scan
        active = self._detect_tactics(context)

        # Add new tactic sightings to timeline
        for tactic in active:
            # Don't add duplicate tactic if already seen in last 60s
            recent = [
                t for ts, t in self._timeline if t == tactic and collection_ts - ts < 60
            ]
            if not recent:
                self._timeline.append((collection_ts, tactic))

        # Evict old entries beyond sequence window
        cutoff = collection_ts - self._SEQUENCE_WINDOW
        self._timeline = [(ts, t) for ts, t in self._timeline if ts >= cutoff]

        # Check for ordered progression
        if len(self._timeline) < self._MIN_TACTICS:
            return events

        # Find longest ordered tactic subsequence in timeline
        ordered = self._find_ordered_sequence()

        if len(ordered) >= self._MIN_TACTICS:
            severity = Severity.CRITICAL if len(ordered) >= 4 else Severity.HIGH
            tactics = [t for _, t in ordered]
            time_span = ordered[-1][0] - ordered[0][0]

            events.append(
                self._create_event(
                    event_type="temporal_kill_chain_sequence",
                    severity=severity,
                    data={
                        "tactics_in_order": tactics,
                        "tactic_count": len(tactics),
                        "time_span_seconds": round(time_span, 1),
                        "sequence_window": self._SEQUENCE_WINDOW,
                        "correlation": "ordered_tactic_progression_over_time",
                    },
                    confidence=min(0.7 + 0.05 * len(tactics), 0.95),
                    tags=["temporal", "kill-chain", "sequence"],
                )
            )

        return events

    def _detect_tactics(self, ctx: ProbeContext) -> List[str]:
        """Detect which MITRE tactics are active in this scan."""
        active: List[str] = []

        # initial-access: new files in drop dirs or SSH success
        files = ctx.shared_data.get("files", [])
        downloads = os.path.expanduser("~/Downloads")
        for f in files:
            if f.path.startswith(downloads) or f.path.startswith("/tmp/"):
                active.append("initial-access")
                break
        if "initial-access" not in active:
            for ev in ctx.shared_data.get("auth_events", []):
                if ev.category == "ssh" and ev.event_type == "success":
                    active.append("initial-access")
                    break

        # execution: LOLBin running
        for proc in ctx.shared_data.get("processes", []):
            if proc.exe:
                basename = os.path.basename(proc.exe).lower()
                if basename in _LOLBIN_BASENAMES:
                    active.append("execution")
                    break

        # persistence: run_at_load or keep_alive entries
        for entry in ctx.shared_data.get("entries", []):
            if entry.run_at_load or entry.keep_alive:
                active.append("persistence")
                break

        # credential-access: keychain or sudo
        for ev in ctx.shared_data.get("auth_events", []):
            if ev.category in ("keychain", "sudo"):
                active.append("credential-access")
                break

        # lateral-movement: internal connections on service ports
        lateral_ports = {22, 445, 3389, 5900, 5985, 5986}
        for conn in ctx.shared_data.get("connections", []):
            if (
                conn.state == "ESTABLISHED"
                and conn.remote_ip
                and _is_private(conn.remote_ip)
                and conn.remote_port in lateral_ports
            ):
                active.append("lateral-movement")
                break

        # command-and-control: 3+ external connections from one PID
        pid_ext: Dict[int, int] = {}
        for conn in ctx.shared_data.get("connections", []):
            if (
                conn.state == "ESTABLISHED"
                and conn.remote_ip
                and not _is_private(conn.remote_ip)
            ):
                pid_ext[conn.pid] = pid_ext.get(conn.pid, 0) + 1
        if any(c >= 3 for c in pid_ext.values()):
            active.append("command-and-control")

        # exfiltration: high outbound bandwidth
        exfil_threshold = 10 * 1024 * 1024
        for bw in ctx.shared_data.get("bandwidth", []):
            if bw.bytes_out > exfil_threshold:
                active.append("exfiltration")
                break

        return active

    def _find_ordered_sequence(self) -> List[tuple]:
        """Find longest subsequence where tactics follow kill chain order."""
        if not self._timeline:
            return []

        # Sort by timestamp
        sorted_tl = sorted(self._timeline, key=lambda x: x[0])

        # Greedy: pick first occurrence of each tactic in order
        seen_tactics: Set[str] = set()
        ordered: List[tuple] = []

        for ts, tactic in sorted_tl:
            if tactic in seen_tactics:
                continue
            order = self._TACTIC_ORDER.get(tactic)
            if order is None:
                continue

            # Must be later in kill chain than what we've collected so far
            if ordered:
                last_order = self._TACTIC_ORDER.get(ordered[-1][1], -1)
                if order <= last_order:
                    continue

            ordered.append((ts, tactic))
            seen_tactics.add(tactic)

        return ordered


# =============================================================================
# 4. AuthVelocityProbe
# =============================================================================


class AuthVelocityProbe(MicroProbe):
    """Detects auth failure acceleration and burst patterns.

    Closes: T4 (no acceleration), S3 (no velocity), S4 (no burst detection)

    Unlike CumulativeAuthProbe (total >= threshold), this probe detects:
      - Burst: >10 failures in any 10-second window (automated tool)
      - Acceleration: failure rate increasing over time (escalating attack)
      - Velocity: sustained failure rate > 0.5/sec (active brute force)
    """

    name = "macos_corr_temporal_auth_velocity"
    description = "Auth failure velocity, acceleration, and burst detection"
    platforms = ["darwin"]
    mitre_techniques = ["T1110"]
    mitre_tactics = ["credential-access"]
    scan_interval = 10.0
    requires_fields = ["rolling"]

    _BURST_THRESHOLD = 1.0  # >1 event per second in any 10s window
    _ACCEL_THRESHOLD = 0.003  # rate increasing by 0.003/sec per second (~0.18/min)
    _VELOCITY_THRESHOLD = 0.5  # >0.5 failures per second sustained

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        rolling = context.shared_data.get("rolling")
        if rolling is None:
            return events

        for key in rolling.keys_with_prefix("ssh_fail:"):
            ip = key.split(":", 1)[1]

            # 1. Burst detection
            burst = rolling.burst_score(key, burst_window_seconds=10.0)
            if burst >= self._BURST_THRESHOLD:
                events.append(
                    self._create_event(
                        event_type="temporal_auth_burst",
                        severity=Severity.CRITICAL,
                        data={
                            "source_ip": ip,
                            "burst_score": round(burst, 2),
                            "burst_threshold": self._BURST_THRESHOLD,
                            "correlation": "burst_density_in_10s_window",
                        },
                        confidence=0.95,
                        tags=["temporal", "auth", "burst"],
                    )
                )
                continue  # burst subsumes velocity/acceleration

            # 2. Acceleration detection
            accel = rolling.acceleration(key)
            if accel >= self._ACCEL_THRESHOLD:
                events.append(
                    self._create_event(
                        event_type="temporal_auth_acceleration",
                        severity=Severity.HIGH,
                        data={
                            "source_ip": ip,
                            "acceleration": round(accel, 4),
                            "accel_threshold": self._ACCEL_THRESHOLD,
                            "correlation": "failure_rate_increasing",
                        },
                        confidence=0.85,
                        tags=["temporal", "auth", "acceleration"],
                    )
                )
                continue  # acceleration subsumes velocity

            # 3. Velocity detection
            velocity = rolling.rate(key)
            if velocity >= self._VELOCITY_THRESHOLD:
                events.append(
                    self._create_event(
                        event_type="temporal_auth_velocity",
                        severity=Severity.HIGH,
                        data={
                            "source_ip": ip,
                            "velocity": round(velocity, 4),
                            "velocity_threshold": self._VELOCITY_THRESHOLD,
                            "correlation": "sustained_failure_rate",
                        },
                        confidence=0.80,
                        tags=["temporal", "auth", "velocity"],
                    )
                )

        return events


# =============================================================================
# 5. BeaconingProbe
# =============================================================================


class BeaconingProbe(MicroProbe):
    """Detects periodic C2 callback patterns via timing analysis.

    Closes: E2 (jittered beaconing), ab2 (no DPI — timing compensates),
            S1 (no jitter), S2 (no periodicity)

    C2 beacons have distinctive temporal signatures: periodic connections
    at fixed or slightly jittered intervals. This probe detects periodicity
    regardless of IP rotation or encryption by analyzing connection timing.

    Scoring:
        jitter_score > 0.7 + period 30-300s   → CRITICAL (likely C2)
        jitter_score > 0.7 + period 300-3600s  → HIGH (slow beacon)
        jitter_score > 0.6 + period 30-3600s   → MEDIUM (possible beacon)
    """

    name = "macos_corr_temporal_beaconing"
    description = "Periodic C2 beaconing via connection timing analysis"
    platforms = ["darwin"]
    mitre_techniques = ["T1071"]
    mitre_tactics = ["command-and-control"]
    scan_interval = 15.0
    requires_fields = ["rolling"]

    _MIN_JITTER_SCORE = 0.6
    _FAST_BEACON_RANGE = (30.0, 300.0)
    _SLOW_BEACON_RANGE = (300.0, 3600.0)

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        rolling = context.shared_data.get("rolling")
        if rolling is None:
            return events

        for key in rolling.keys_with_prefix("beacon:"):
            parts = key.split(":", 2)
            if len(parts) < 2:
                continue
            dest = parts[1]

            # Skip CDN/infrastructure IPs
            if _is_cdn(dest):
                continue

            jitter = rolling.jitter_score(key)
            if jitter < self._MIN_JITTER_SCORE:
                continue

            period = rolling.dominant_period(key)
            if period is None:
                continue

            # Classify beacon speed
            if self._FAST_BEACON_RANGE[0] <= period <= self._FAST_BEACON_RANGE[1]:
                severity = Severity.CRITICAL if jitter > 0.7 else Severity.HIGH
                beacon_type = "fast_beacon"
            elif self._SLOW_BEACON_RANGE[0] <= period <= self._SLOW_BEACON_RANGE[1]:
                severity = Severity.HIGH if jitter > 0.7 else Severity.MEDIUM
                beacon_type = "slow_beacon"
            else:
                continue  # Outside beacon period range

            confidence = min(0.6 + jitter * 0.3, 0.95)

            events.append(
                self._create_event(
                    event_type="temporal_beaconing",
                    severity=severity,
                    data={
                        "destination": dest,
                        "jitter_score": round(jitter, 3),
                        "period_seconds": round(period, 1),
                        "beacon_type": beacon_type,
                        "entry_count": rolling.count(key),
                        "correlation": "periodic_connection_timing",
                    },
                    confidence=confidence,
                    tags=["temporal", "beaconing", beacon_type],
                )
            )

        return events


# =============================================================================
# 6. ExfilAccelerationProbe
# =============================================================================


class ExfilAccelerationProbe(MicroProbe):
    """Detects rate-of-change in outbound data volume.

    Closes: E5 (window-boundary exfil), F3 (no rate-of-change),
            S3 (no velocity)

    Unlike CumulativeExfilProbe (total >= threshold), this probe detects:
      - Rate spike: sustained bytes/sec exceeding threshold
      - Acceleration: rate increasing over time (escalating exfil)

    Rate-based detection is boundary-independent: splitting exfil across
    window edges doesn't help because rate is computed within the window.
    """

    name = "macos_corr_temporal_exfil_acceleration"
    description = "Exfiltration rate spike and acceleration detection"
    platforms = ["darwin"]
    mitre_techniques = ["T1048"]
    mitre_tactics = ["exfiltration"]
    scan_interval = 10.0
    requires_fields = ["rolling"]

    # 500KB/sec sustained = likely exfil (not normal browsing)
    _RATE_THRESHOLD = 500_000.0
    # Rate increasing by ~2KB/sec/sec (~120KB/sec per minute)
    _ACCEL_THRESHOLD = 2_000.0

    # Processes that legitimately send large volumes
    _KNOWN_HIGH_BANDWIDTH = frozenset(
        {
            "safari",
            "google chrome",
            "firefox",
            "microsoft edge",
            "softwareupdated",
            "apsd",
            "nsurlsessiond",
            "com.apple.webkit.networking",
        }
    )

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        rolling = context.shared_data.get("rolling")
        if rolling is None:
            return events

        for key in rolling.keys_with_prefix("bytes_out:"):
            process_name = key.split(":", 1)[1]

            # Skip known high-bandwidth legitimate processes
            if process_name.lower() in self._KNOWN_HIGH_BANDWIDTH:
                continue

            # 1. Rate spike
            rate = rolling.rate(key)
            if rate >= self._RATE_THRESHOLD:
                events.append(
                    self._create_event(
                        event_type="temporal_exfil_rate_spike",
                        severity=Severity.HIGH,
                        data={
                            "process_name": process_name,
                            "rate_bytes_per_sec": round(rate, 0),
                            "rate_threshold": self._RATE_THRESHOLD,
                            "total_bytes": rolling.total(key),
                            "correlation": "sustained_outbound_rate",
                        },
                        confidence=0.85,
                        tags=["temporal", "exfiltration", "rate-spike"],
                    )
                )
                continue  # rate spike subsumes acceleration

            # 2. Acceleration
            accel = rolling.acceleration(key)
            if accel >= self._ACCEL_THRESHOLD:
                events.append(
                    self._create_event(
                        event_type="temporal_exfil_acceleration",
                        severity=Severity.HIGH,
                        data={
                            "process_name": process_name,
                            "acceleration": round(accel, 0),
                            "accel_threshold": self._ACCEL_THRESHOLD,
                            "current_rate": round(rate, 0),
                            "total_bytes": rolling.total(key),
                            "correlation": "increasing_outbound_rate",
                        },
                        confidence=0.80,
                        tags=["temporal", "exfiltration", "acceleration"],
                    )
                )

        return events


# =============================================================================
# Factory
# =============================================================================


def create_temporal_probes() -> List[MicroProbe]:
    """Create all 6 macOS temporal correlation probes."""
    return [
        DropExecuteTimingProbe(),
        PersistenceActivationTimingProbe(),
        KillChainSequenceProbe(),
        AuthVelocityProbe(),
        BeaconingProbe(),
        ExfilAccelerationProbe(),
    ]
