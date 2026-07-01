"""macOS Provenance Probes — 8 detection probes for cross-application attack chains.

Each probe consumes provenance data from MacOSProvenanceCollector via
shared_data.  Several probes maintain sliding temporal windows across scans
to detect multi-stage attack chains that span minutes.

Probes:
    1. MessageToDownloadProbe       — messaging app active + new download
    2. DownloadToExecuteProbe       — downloaded file executed (120s window)
    3. ExecuteToExfilProbe          — new process with external network
    4. FullKillChainProbe           — 6-stage kill chain (300s window)
    5. BrowserToTerminalProbe       — browser -> terminal -> suspicious cmd
    6. RapidAppSwitchProbe          — messaging + browser + terminal all active
    7. PIDNetworkAnomalyProbe       — young process (<5s) with external conn
    8. ProvenanceChainProbe         — causal chain scoring (60s linkage)

Design philosophy:
    - Stateful probes use sliding windows to correlate events across scans
    - Every probe declares requires_fields for observability contract enforcement
    - All probes are macOS-only (platforms=["darwin"])
    - Confidence levels reflect real-world false positive rates
    - MITRE ATT&CK mappings target the specific sub-technique
"""

from __future__ import annotations

import ipaddress
import logging
import time
from typing import Any, Dict, List, Optional, Set

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)

logger = logging.getLogger(__name__)

# Re-import collector types for type hints only — no hard coupling.
# Probes access data via shared_data dicts and dataclass attribute access.


# Shared constants (mirror the collector's app sets for probe-side checks)
_SENSITIVE_FILE_PATTERNS = (
    ".ssh/",
    "id_rsa",
    "id_ed25519",
    "authorized_keys",
    ".aws/credentials",
    ".kube/config",
    "Keychain",
    ".gnupg/",
    ".netrc",
    "shadow",
    "passwd",
    "login.keychain",
    "System.keychain",
)

_SUSPICIOUS_COMMANDS = frozenset(
    {
        "curl",
        "wget",
        "nc",
        "ncat",
        "bash",
        "sh",
        "zsh",
        "python3",
        "python",
        "osascript",
        "base64",
    }
)


# =============================================================================
# 1. MessageToDownloadProbe
# =============================================================================


class MessageToDownloadProbe(MicroProbe):
    """Detects file downloads while a messaging app is active.

    If any messaging app (Slack, Teams, Discord, Signal, etc.) is running
    AND new files appear in ~/Downloads, the download may have been triggered
    by a phishing message.  This is the initial delivery stage of many
    social-engineering attack chains.

    MITRE: T1566.002 (Phishing: Spearphishing Link)
    """

    name = "macos_provenance_msg_to_download"
    description = "Detects file download while messaging app is active"
    platforms = ["darwin"]
    mitre_techniques = ["T1566.002"]
    mitre_tactics = ["initial_access"]
    scan_interval = 10.0
    requires_fields = ["active_messaging_apps", "new_downloads"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        data = context.shared_data

        # Never fire on baseline scan
        if data.get("is_baseline_scan", True):
            return events

        messaging_apps = data.get("active_messaging_apps", [])
        new_downloads = data.get("new_downloads", [])

        if not messaging_apps or not new_downloads:
            return events

        # Correlation: messaging app active + file appeared in Downloads
        download_names = [dl.filename for dl in new_downloads]
        download_paths = [dl.path for dl in new_downloads]

        events.append(
            self._create_event(
                event_type="message_to_download",
                severity=Severity.HIGH,
                data={
                    "probe_name": self.name,
                    "detection_source": "cross_agent",
                    "active_messaging_apps": messaging_apps,
                    "new_downloads": download_names,
                    "download_paths": download_paths,
                    "download_count": len(new_downloads),
                    "messaging_app_count": len(messaging_apps),
                    "chain_stage": "delivery",
                },
                confidence=0.7,
                correlation_id=f"msg_dl_{int(time.time())}",
            )
        )

        return events


# =============================================================================
# 2. DownloadToExecuteProbe
# =============================================================================


class DownloadToExecuteProbe(MicroProbe):
    """Detects execution of recently downloaded files.

    Maintains a sliding 120-second window of recent downloads.  If a new
    process has an exe path that matches a filename from the download window,
    the downloaded file was executed — a classic phishing follow-through.

    MITRE: T1204.002 (User Execution: Malicious File)
    """

    name = "macos_provenance_download_to_execute"
    description = "Detects execution of recently downloaded files"
    platforms = ["darwin"]
    mitre_techniques = ["T1204.002"]
    mitre_tactics = ["execution"]
    scan_interval = 10.0
    requires_fields = ["new_processes", "new_downloads"]

    WINDOW_SECONDS = 120.0

    def __init__(self) -> None:
        super().__init__()
        self._recent_downloads: Dict[str, float] = {}  # filename -> timestamp

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        data = context.shared_data
        now = time.time()

        new_downloads = data.get("new_downloads", [])
        new_processes = data.get("new_processes", [])

        # Add new downloads to the sliding window
        for dl in new_downloads:
            self._recent_downloads[dl.filename] = dl.modify_time

        # Prune entries older than the window
        cutoff = now - self.WINDOW_SECONDS
        self._recent_downloads = {
            fname: ts for fname, ts in self._recent_downloads.items() if ts > cutoff
        }

        if not self._recent_downloads or not new_processes:
            return events

        # Check if any new process exe contains a recent download filename
        for proc in new_processes:
            exe = proc.exe or ""
            cmdline_str = " ".join(proc.cmdline) if proc.cmdline else ""

            for dl_name, dl_ts in self._recent_downloads.items():
                if dl_name in exe or dl_name in cmdline_str:
                    events.append(
                        self._create_event(
                            event_type="download_to_execute",
                            severity=Severity.HIGH,
                            data={
                                "probe_name": self.name,
                                "detection_source": "cross_agent",
                                "pid": proc.pid,
                                "process_name": proc.name,
                                "exe": proc.exe,
                                "cmdline": proc.cmdline,
                                "downloaded_file": dl_name,
                                "download_age_s": round(now - dl_ts, 1),
                                "ppid": proc.ppid,
                                "parent_name": proc.parent_name,
                                "chain_stage": "execution",
                            },
                            confidence=0.8,
                            correlation_id=f"dl_exec_{proc.pid}_{int(now)}",
                        )
                    )
                    break  # One match per process

        return events


# =============================================================================
# 3. ExecuteToExfilProbe
# =============================================================================


class ExecuteToExfilProbe(MicroProbe):
    """Detects new processes with external network connections.

    If any newly spawned process has an established TCP connection to a
    non-private IP address, it may be exfiltrating data or communicating
    with a C2 server.  Combined with download-to-execute, this completes
    the delivery -> execution -> exfiltration chain.

    MITRE: T1041 (Exfiltration Over C2 Channel)
    """

    name = "macos_provenance_execute_to_exfil"
    description = "Detects new processes with external network connections"
    platforms = ["darwin"]
    mitre_techniques = ["T1041"]
    mitre_tactics = ["exfiltration"]
    scan_interval = 10.0
    requires_fields = ["new_processes", "pid_connections"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        data = context.shared_data

        new_processes = data.get("new_processes", [])
        pid_connections = data.get("pid_connections", {})

        if not new_processes or not pid_connections:
            return events

        for proc in new_processes:
            conns = pid_connections.get(proc.pid, [])
            if not conns:
                continue

            # Filter to external (non-private) connections
            external_conns = []
            for conn in conns:
                try:
                    if not ipaddress.ip_address(conn.remote_ip).is_private:
                        external_conns.append(conn)
                except ValueError:
                    continue

            if not external_conns:
                continue

            remote_endpoints = [
                f"{c.remote_ip}:{c.remote_port}" for c in external_conns
            ]

            events.append(
                self._create_event(
                    event_type="execute_to_exfil",
                    severity=Severity.CRITICAL,
                    data={
                        "probe_name": self.name,
                        "detection_source": "cross_agent",
                        "pid": proc.pid,
                        "process_name": proc.name,
                        "exe": proc.exe,
                        "cmdline": proc.cmdline,
                        "remote_endpoints": remote_endpoints,
                        "connection_count": len(external_conns),
                        "ppid": proc.ppid,
                        "parent_name": proc.parent_name,
                        "chain_stage": "exfiltration",
                    },
                    confidence=0.85,
                    correlation_id=f"exec_exfil_{proc.pid}_{int(time.time())}",
                )
            )

        return events


# =============================================================================
# 4. FullKillChainProbe
# =============================================================================


class FullKillChainProbe(MicroProbe):
    """Detects a CAUSAL, ORDERED download→execute→act kill chain.

    Rewritten 2026-07-01 (detection roadmap increment 2). The previous
    implementation counted *co-occurring* stage labels in a 300s window —
    "a messaging app was open AND a browser was open AND some file appeared
    AND some process spawned AND something connected out" — which is the
    steady state of any developer machine (Axelsson's base-rate fallacy:
    co-occurrence of individually-common events is expected, not rare).
    It alerted constantly and meant nothing.

    A kill chain is now only asserted when the stages are CAUSALLY LINKED
    to one actor, in chronological order, inside the window:

        1. DOWNLOAD   file F appears in ~/Downloads at t1
        2. EXECUTE    a NEW process P starts at t2 > t1 whose exe/cmdline
                      references F (the downloaded artifact itself runs)
        3. ACT        the SAME pid P then touches credentials (t3 >= t2)
                      and/or makes an outbound network connection

    Passive context (messaging/browser apps active before the download) no
    longer counts as chain stages — it only nudges confidence, reflecting a
    plausible delivery vector. No ordered same-actor chain → NO alert.

    Severity:
        - chain with credential access AND network egress: CRITICAL
        - chain with one of the two: HIGH

    MITRE: T1566.002 (Phishing: Spearphishing Link) — full chain
    """

    name = "macos_provenance_full_kill_chain"
    description = "Detects causally-linked download→execute→exfil chains"
    platforms = ["darwin"]
    mitre_techniques = ["T1566.002"]
    mitre_tactics = ["initial_access", "execution", "exfiltration"]
    scan_interval = 10.0
    requires_fields = ["timeline"]

    WINDOW_SECONDS = 300.0

    def __init__(self) -> None:
        super().__init__()
        self._timeline_window: List[Any] = []  # List[TimelineEvent]
        self._proc_window: Dict[int, Any] = {}  # pid -> NewProcess (rolling)
        self._alerted_chains: set = set()  # (pid, download_path) already fired

    @staticmethod
    def _parse_download(detail: str) -> str:
        """Extract the path from a file_created detail string."""
        # detail format: "file=<name> size=<n> path=<path>"
        idx = detail.find("path=")
        return detail[idx + 5 :].strip() if idx >= 0 else ""

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        data = context.shared_data
        now = time.time()
        cutoff = now - self.WINDOW_SECONDS

        # ── Maintain rolling windows ──────────────────────────────────────
        self._timeline_window.extend(data.get("timeline", []))
        self._timeline_window = [
            e for e in self._timeline_window if e.timestamp > cutoff
        ]
        for proc in data.get("new_processes", []):
            self._proc_window[proc.pid] = proc
        self._proc_window = {
            pid: p for pid, p in self._proc_window.items() if p.create_time > cutoff
        }
        # Expire alerted-chain dedup entries outside the window
        self._alerted_chains = {
            key for key in self._alerted_chains if key[2] > cutoff
        }

        if not self._timeline_window or not self._proc_window:
            return events

        # ── Stage 1: downloads in window (ordered) ────────────────────────
        downloads = [
            (e.timestamp, self._parse_download(e.detail))
            for e in self._timeline_window
            if e.event_type == "file_created"
        ]
        downloads = [(ts, p) for ts, p in downloads if p]
        if not downloads:
            return events

        pid_connections = data.get("pid_connections", {})

        # Credential access BY PID (same-actor requirement): timeline
        # process_spawned rows whose detail matches sensitive patterns.
        cred_pids: Dict[int, float] = {}
        for e in self._timeline_window:
            if e.event_type != "process_spawned" or not e.pid:
                continue
            hay = f"{e.detail} {e.app_name}".lower()
            if any(pat in hay for pat in _SENSITIVE_FILE_PATTERNS):
                cred_pids[e.pid] = min(cred_pids.get(e.pid, e.timestamp), e.timestamp)

        # Passive delivery context (confidence nudge only, NOT a stage)
        delivery_ctx = sorted(
            {
                "messaging" if "category=messaging" in e.detail else "browser"
                for e in self._timeline_window
                if e.event_type == "app_active"
                and ("category=messaging" in e.detail or "category=browser" in e.detail)
            }
        )

        # ── Stages 2+3: a NEW process that IS the downloaded artifact and
        #    then acts (credential and/or network) — same pid, ordered ─────
        for pid, proc in self._proc_window.items():
            exe = (proc.exe or "").strip()
            cmdline = " ".join(proc.cmdline or [])
            for dl_ts, dl_path in downloads:
                if proc.create_time <= dl_ts:
                    continue  # ORDER: execute must FOLLOW the download
                if not dl_path or (dl_path != exe and dl_path not in cmdline):
                    continue  # CAUSALITY: the downloaded file itself must run

                has_network = pid in pid_connections and pid_connections[pid]
                cred_ts = cred_pids.get(pid)
                has_cred = cred_ts is not None and cred_ts >= proc.create_time
                if not has_network and not has_cred:
                    continue  # no same-actor action yet — keep watching

                key = (pid, dl_path, now)
                if any(k[0] == pid and k[1] == dl_path for k in self._alerted_chains):
                    continue  # already alerted this chain in-window
                self._alerted_chains.add(key)

                severity = (
                    Severity.CRITICAL if (has_network and has_cred) else Severity.HIGH
                )
                confidence = min(
                    0.95, 0.8 + 0.05 * len(delivery_ctx) + (0.05 if has_cred else 0.0)
                )
                conns = [
                    str(c) for c in list(pid_connections.get(pid, []))[:3]
                ]
                events.append(
                    self._create_event(
                        event_type="full_kill_chain",
                        severity=severity,
                        data={
                            "probe_name": self.name,
                            "detection_source": "cross_agent",
                            "chain": {
                                "download": {"path": dl_path, "at": dl_ts},
                                "execute": {
                                    "pid": pid,
                                    "exe": exe,
                                    "parent": proc.parent_name,
                                    "at": proc.create_time,
                                },
                                "credential_access": bool(has_cred),
                                "network_egress": conns,
                            },
                            "causally_linked": True,
                            "ordered": True,
                            "delivery_context": delivery_ctx,
                            "window_seconds": self.WINDOW_SECONDS,
                            "chain_stage": "full_chain",
                        },
                        confidence=confidence,
                        correlation_id=f"kill_chain_{pid}_{int(dl_ts)}",
                    )
                )

        return events


# =============================================================================
# 5. BrowserToTerminalProbe
# =============================================================================


class BrowserToTerminalProbe(MicroProbe):
    """Detects browser-to-terminal attack chains with suspicious commands.

    If a browser is active AND a terminal app spawned a child process
    running a suspicious command (curl, wget, bash, osascript, etc.),
    this indicates a browser-mediated attack — e.g. copy-paste from a
    malicious website into the terminal.

    MITRE: T1204.001 (User Execution: Malicious Link)
    """

    name = "macos_provenance_browser_to_terminal"
    description = "Detects browser -> terminal -> suspicious command chain"
    platforms = ["darwin"]
    mitre_techniques = ["T1204.001"]
    mitre_tactics = ["execution"]
    scan_interval = 10.0
    requires_fields = ["active_browsers", "active_terminals", "new_processes"]

    _TERMINALS = frozenset(
        {
            "Terminal",
            "iTerm2",
            "Warp",
            "Alacritty",
            "kitty",
            "Hyper",
            "WezTerm",
            # Also match shell parents that terminals spawn
            "login",
            "zsh",
            "bash",
        }
    )

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        data = context.shared_data

        active_browsers = data.get("active_browsers", [])
        active_terminals = data.get("active_terminals", [])
        new_processes = data.get("new_processes", [])

        if not active_browsers or not active_terminals or not new_processes:
            return events

        # Find new processes whose parent is a terminal and name is suspicious
        for proc in new_processes:
            if proc.parent_name not in self._TERMINALS:
                continue
            if proc.name not in _SUSPICIOUS_COMMANDS:
                continue

            events.append(
                self._create_event(
                    event_type="browser_to_terminal",
                    severity=Severity.CRITICAL,
                    data={
                        "probe_name": self.name,
                        "detection_source": "cross_agent",
                        "pid": proc.pid,
                        "suspicious_command": proc.name,
                        "exe": proc.exe,
                        "cmdline": proc.cmdline,
                        "parent_name": proc.parent_name,
                        "ppid": proc.ppid,
                        "active_browsers": active_browsers,
                        "active_terminals": active_terminals,
                        "chain_stage": "execution",
                    },
                    confidence=0.85,
                    correlation_id=f"browser_term_{proc.pid}_{int(time.time())}",
                )
            )

        return events


# =============================================================================
# 6. RapidAppSwitchProbe
# =============================================================================


class RapidAppSwitchProbe(MicroProbe):
    """Detects simultaneous messaging + browser + terminal activity.

    When all three application categories are active at the same time, it
    indicates an anomalous rapid-switching pattern consistent with social
    engineering: the user received a message, clicked a link in a browser,
    and is now executing something in a terminal.

    MITRE: T1204 (User Execution)
    """

    name = "macos_provenance_rapid_app_switch"
    description = "Detects simultaneous messaging + browser + terminal activity"
    platforms = ["darwin"]
    mitre_techniques = ["T1204"]
    mitre_tactics = ["execution"]
    scan_interval = 10.0
    requires_fields = ["active_messaging_apps", "active_browsers", "active_terminals"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        data = context.shared_data

        messaging = data.get("active_messaging_apps", [])
        browsers = data.get("active_browsers", [])
        terminals = data.get("active_terminals", [])

        # All three categories must be active simultaneously
        if not messaging or not browsers or not terminals:
            return events

        events.append(
            self._create_event(
                event_type="rapid_app_switch",
                severity=Severity.MEDIUM,
                data={
                    "probe_name": self.name,
                    "detection_source": "cross_agent",
                    "active_messaging_apps": messaging,
                    "active_browsers": browsers,
                    "active_terminals": terminals,
                    "total_active_categories": 3,
                    "chain_stage": "pattern",
                },
                confidence=0.65,
                correlation_id=f"rapid_switch_{int(time.time())}",
            )
        )

        return events


# =============================================================================
# 7. PIDNetworkAnomalyProbe
# =============================================================================


class PIDNetworkAnomalyProbe(MicroProbe):
    """Detects young processes (<5s old) with external network connections.

    Processes that open external network connections within seconds of
    spawning are highly suspicious — legitimate applications typically
    take longer to establish outbound connections.  This pattern is
    characteristic of dropper malware and C2 implants.

    MITRE: T1071.001 (Application Layer Protocol: Web Protocols)
    """

    name = "macos_provenance_pid_network_anomaly"
    description = "Detects young processes with immediate external connections"
    platforms = ["darwin"]
    mitre_techniques = ["T1071.001"]
    mitre_tactics = ["command_and_control"]
    scan_interval = 10.0
    requires_fields = ["new_processes", "pid_connections"]

    AGE_THRESHOLD_SECONDS = 30.0

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        data = context.shared_data
        now = time.time()

        new_processes = data.get("new_processes", [])
        pid_connections = data.get("pid_connections", {})

        if not new_processes or not pid_connections:
            return events

        for proc in new_processes:
            # Check process age
            age = now - proc.create_time
            if age > self.AGE_THRESHOLD_SECONDS:
                continue

            conns = pid_connections.get(proc.pid, [])
            if not conns:
                continue

            # Filter to external connections
            external = []
            for conn in conns:
                try:
                    if not ipaddress.ip_address(conn.remote_ip).is_private:
                        external.append(conn)
                except ValueError:
                    continue

            if not external:
                continue

            remote_endpoints = [f"{c.remote_ip}:{c.remote_port}" for c in external]

            events.append(
                self._create_event(
                    event_type="pid_network_anomaly",
                    severity=Severity.HIGH,
                    data={
                        "probe_name": self.name,
                        "detection_source": "cross_agent",
                        "pid": proc.pid,
                        "process_name": proc.name,
                        "exe": proc.exe,
                        "cmdline": proc.cmdline,
                        "process_age_s": round(age, 2),
                        "threshold_s": self.AGE_THRESHOLD_SECONDS,
                        "remote_endpoints": remote_endpoints,
                        "connection_count": len(external),
                        "parent_name": proc.parent_name,
                        "ppid": proc.ppid,
                        "chain_stage": "c2_contact",
                    },
                    confidence=0.8,
                    correlation_id=f"pid_net_{proc.pid}_{int(now)}",
                )
            )

        return events


# =============================================================================
# 8. ProvenanceChainProbe
# =============================================================================


class ProvenanceChainProbe(MicroProbe):
    """Builds and scores causal provenance chains from timeline events.

    Links timeline events by temporal proximity (within 60 seconds) and
    app-transition patterns (messaging -> browser -> terminal).  Chains
    are scored by the sum of stage weights; chains scoring above threshold
    (7+) are reported as high-confidence detections.

    Stage weights:
        messaging=1, browser=1, download=2, execute=3, credential=4, network=4

    MITRE: T1005 (Data from Local System)
    """

    name = "macos_provenance_chain"
    description = "Builds and scores causal provenance chains"
    platforms = ["darwin"]
    mitre_techniques = ["T1005"]
    mitre_tactics = ["collection"]
    scan_interval = 10.0
    requires_fields = ["timeline", "pid_connections"]

    LINKAGE_WINDOW_SECONDS = 60.0
    SCORE_THRESHOLD = 7

    _STAGE_WEIGHTS = {
        "messaging": 1,
        "browser": 1,
        "download": 2,
        "execute": 3,
        "credential": 4,
        "network": 4,
    }

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        data = context.shared_data

        timeline = data.get("timeline", [])
        pid_connections = data.get("pid_connections", {})

        if not timeline:
            return events

        # Classify each timeline event into a stage
        staged_events: List[Dict[str, Any]] = []
        for event in timeline:
            stage = self._classify_stage(event, pid_connections)
            if stage:
                staged_events.append(
                    {
                        "stage": stage,
                        "timestamp": event.timestamp,
                        "app_name": event.app_name,
                        "detail": event.detail,
                        "pid": event.pid,
                    }
                )

        if not staged_events:
            return events

        # Build chains by linking temporally proximate events
        chains = self._build_chains(staged_events)

        # Score and report chains above threshold
        for chain in chains:
            score = sum(self._STAGE_WEIGHTS.get(e["stage"], 0) for e in chain)
            stages_in_chain = list({e["stage"] for e in chain})

            if score < self.SCORE_THRESHOLD:
                continue

            # Confidence scales with score (7=0.7, 10=0.8, 15=0.95)
            confidence = min(0.95, 0.5 + (score * 0.03))

            chain_summary = [
                {
                    "stage": e["stage"],
                    "app": e["app_name"],
                    "detail": e["detail"][:80],
                }
                for e in chain
            ]

            events.append(
                self._create_event(
                    event_type="provenance_chain",
                    severity=Severity.HIGH,
                    data={
                        "probe_name": self.name,
                        "detection_source": "cross_agent",
                        "chain_score": score,
                        "threshold": self.SCORE_THRESHOLD,
                        "chain_length": len(chain),
                        "stages": stages_in_chain,
                        "chain_summary": chain_summary,
                        "linkage_window_s": self.LINKAGE_WINDOW_SECONDS,
                        "chain_stage": "correlation",
                    },
                    confidence=confidence,
                    correlation_id=f"prov_chain_{int(time.time())}",
                )
            )

        return events

    def _classify_stage(
        self,
        event: Any,
        pid_connections: Dict[int, list],
    ) -> Optional[str]:
        """Classify a TimelineEvent into a kill chain stage."""
        if event.event_type == "app_active":
            if "category=messaging" in event.detail:
                return "messaging"
            elif "category=browser" in event.detail:
                return "browser"
            elif "category=terminal" in event.detail:
                return None  # Terminals alone are not a stage
        elif event.event_type == "file_created":
            return "download"
        elif event.event_type == "process_spawned":
            # Check for credential-access indicators
            detail_lower = event.detail.lower()
            app_lower = event.app_name.lower()
            if any(
                pat in detail_lower or pat in app_lower
                for pat in _SENSITIVE_FILE_PATTERNS
            ):
                return "credential"
            return "execute"
        elif event.event_type == "network_connect":
            return "network"

        # Check if process has external connections
        if event.pid and event.pid in pid_connections:
            return "network"

        return None

    def _build_chains(
        self, staged_events: List[Dict[str, Any]]
    ) -> List[List[Dict[str, Any]]]:
        """Build causal chains by linking temporally proximate events.

        Greedy forward-linking: for each event, link to the next event
        within the linkage window that represents a different stage.
        """
        if not staged_events:
            return []

        # Sort by timestamp
        sorted_events = sorted(staged_events, key=lambda e: e["timestamp"])
        chains: List[List[Dict[str, Any]]] = []
        used: Set[int] = set()

        for i, event in enumerate(sorted_events):
            if i in used:
                continue

            chain = [event]
            used.add(i)
            chain_stages = {event["stage"]}
            last_ts = event["timestamp"]

            # Extend chain forward
            for j in range(i + 1, len(sorted_events)):
                if j in used:
                    continue

                candidate = sorted_events[j]
                time_gap = candidate["timestamp"] - last_ts

                # Beyond linkage window — stop extending
                if time_gap > self.LINKAGE_WINDOW_SECONDS:
                    break

                # Only add if it's a new stage (avoid duplicates)
                if candidate["stage"] not in chain_stages:
                    chain.append(candidate)
                    used.add(j)
                    chain_stages.add(candidate["stage"])
                    last_ts = candidate["timestamp"]

            # Only keep chains with 2+ stages
            if len(chain) >= 2:
                chains.append(chain)

        return chains


# =============================================================================
# Factory
# =============================================================================


def create_provenance_probes() -> List[MicroProbe]:
    """Create all macOS provenance probes."""
    return [
        MessageToDownloadProbe(),
        DownloadToExecuteProbe(),
        ExecuteToExfilProbe(),
        FullKillChainProbe(),
        BrowserToTerminalProbe(),
        RapidAppSwitchProbe(),
        PIDNetworkAnomalyProbe(),
        ProvenanceChainProbe(),
    ]
