#!/usr/bin/env python3
"""Empirical Observability Audit (EOA) — Single Agent Reality Run.

Runs ONE agent in isolation for a configurable duration, captures all
queue output, decodes every protobuf row, and produces a structured
scorecard showing exactly what the agent sees on this Mac.

Usage:
    # Quick audit (2 minutes)
    python scripts/eoa/run_agent_audit.py --agent proc

    # Full audit (15 minutes) with trigger actions
    python scripts/eoa/run_agent_audit.py --agent proc --duration 900

    # All agents sequentially
    python scripts/eoa/run_agent_audit.py --all

Environment:
    PYTHONPATH must include src/  (the script sets it automatically)

Output:
    results/eoa/<agent>_<timestamp>/
        scorecard.json    — structured audit results
        scorecard.md      — human-readable report
        events.jsonl      — all decoded events (one per line)
        metrics.jsonl     — RSS/CPU samples over time
        raw_log.txt       — agent stdout/stderr
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# Ensure src/ is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))


# ---------------------------------------------------------------------------
# Agent registry — maps short name → module path + extra CLI args
# ---------------------------------------------------------------------------

AGENT_REGISTRY: Dict[str, Dict[str, Any]] = {
    "proc": {
        "module": "amoskys.agents.shared.process.agent",
        "entry_fn": "main",
        "label": "ProcAgent",
        "probes": 8,
        "collector": "psutil (live)",
        "mac_ready": True,
        "description": "Process execution monitoring (spawn, LOLBin, tree, resource, scripts)",
        "mitre": ["T1059", "T1218", "T1055", "T1496", "T1036", "T1204", "T1078"],
        "trigger_hint": "Spawn processes: open Terminal, run curl, python3 -c 'import os', etc.",
        "cli_args": ["--interval", "10", "--debug"],
    },
    "fim": {
        "module": "amoskys.agents.shared.filesystem.agent",
        "entry_fn": "main",
        "label": "FIMAgent",
        "probes": 8,
        "collector": "os.walk + hashlib (live)",
        "mac_ready": True,
        "description": "File integrity monitoring (system binaries, configs, SUID, webshells)",
        "mitre": ["T1036", "T1547", "T1574", "T1505.003", "T1548", "T1556", "T1014"],
        "trigger_hint": "Create/modify/delete files in /tmp/eoa_fim_watch. Also watches /etc for real probes.",
        "cli_args": [
            "--interval",
            "15",
            "--mode",
            "monitor",
            "--log-level",
            "DEBUG",
            "--monitor-paths",
            "/tmp/eoa_fim_watch",
            "/etc",
        ],
    },
    "persistence": {
        "module": "amoskys.agents.shared.persistence.agent",
        "entry_fn": "main",
        "label": "PersistenceGuard",
        "probes": 8,
        "collector": "macOS LaunchAgents/Daemons, cron, shell profiles, SSH keys (live)",
        "mac_ready": True,
        "description": "Persistence mechanism monitoring (launchd, cron, shell profiles, SSH keys)",
        "mitre": [
            "T1037",
            "T1053.003",
            "T1098.004",
            "T1176",
            "T1543",
            "T1546.004",
            "T1547",
        ],
        "trigger_hint": "Touch a plist in ~/Library/LaunchAgents, modify .zshrc, add crontab entry.",
        "cli_args": ["--interval", "10", "--log-level", "DEBUG", "--mode", "monitor"],
    },
    "dns": {
        "module": "amoskys.agents.shared.dns.agent",
        "entry_fn": "main",
        "label": "DNSAgent",
        "probes": 9,
        "collector": "MacOSDNSCollector (log show mDNSResponder)",
        "mac_ready": True,
        "description": "DNS query monitoring (DGA, beaconing, tunneling, suspicious TLDs)",
        "mitre": ["T1071.004", "T1568.002", "T1568.001", "T1048.001"],
        "trigger_hint": "Browse websites, nslookup some domains, curl a URL.",
        "cli_args": ["--interval", "10", "--log-level", "DEBUG"],
    },
    "auth": {
        "module": "amoskys.agents.shared.auth.agent",
        "entry_fn": "main",
        "label": "AuthGuard",
        "probes": 8,
        "collector": "MacOSAuthLogCollector (log show broad + last)",
        "mac_ready": True,
        "description": "Authentication monitoring (SSH, sudo, loginwindow, screen lock, biometric)",
        "mitre": ["T1110", "T1078", "T1548.003", "T1021.004", "T1059", "T1621"],
        "trigger_hint": "Run 'sudo -n ls', 'sudo ls' (interactive), attempt SSH login, lock/unlock screen.",
        "cli_args": ["--interval", "10", "--log-level", "DEBUG"],
    },
    "flow": {
        "module": "amoskys.agents.shared.network.agent",
        "entry_fn": "main",
        "label": "FlowAgent",
        "probes": 8,
        "collector": "MacOSFlowCollector (lsof -i -n -P)",
        "mac_ready": True,
        "description": "Network flow monitoring (port scan, lateral movement, exfil, C2, tunnels)",
        "mitre": ["T1046", "T1021", "T1041", "T1048", "T1071", "T1090"],
        "trigger_hint": "Browse websites, curl URLs, open SSH connections, run nmap.",
        "cli_args": ["--interval", "15", "--log-level", "DEBUG"],
    },
    "peripheral": {
        "module": "amoskys.agents.shared.peripheral.agent",
        "entry_fn": "main",
        "label": "PeripheralAgent",
        "probes": 7,
        "collector": "MacOSUSBCollector (system_profiler SPUSBDataType)",
        "mac_ready": True,
        "description": "Peripheral monitoring (USB storage, HID anomaly, Bluetooth, network adapters)",
        "mitre": ["T1200", "T1091", "T1052", "T1056.001"],
        "trigger_hint": "Plug in a USB device or pair a Bluetooth device.",
        "cli_args": ["--interval", "10", "--log-level", "DEBUG"],
    },
    "kernel_audit": {
        "module": "amoskys.agents.os.linux.kernel_audit.kernel_audit_agent",
        "entry_fn": None,
        "label": "KernelAudit",
        "probes": 7,
        "collector": "AuditdLogCollector (/var/log/audit/audit.log — Linux only)",
        "mac_ready": False,
        "description": "Kernel syscall monitoring (execve, ptrace, module loads, netfilter)",
        "mitre": ["T1014", "T1055", "T1068", "T1611"],
        "trigger_hint": "Linux only — no macOS audit source.",
    },
    "device_discovery": {
        "module": "amoskys.agents.shared.device_discovery.run_agent_v2",
        "entry_fn": None,
        "label": "DeviceDiscovery V2",
        "probes": 6,
        "collector": "ARP + nmap (Linux ip neigh / /proc/net/arp)",
        "mac_ready": False,
        "description": "Network device discovery (ARP scan, rogue device, service fingerprint)",
        "mitre": ["T1046", "T1018", "T1135"],
        "trigger_hint": "Linux only — needs arp -a fallback for macOS.",
    },
    "protocol_collectors": {
        "module": "amoskys.agents.shared.protocol_collectors.run_agent_v2",
        "entry_fn": None,
        "label": "ProtocolCollectors V2",
        "probes": 10,
        "collector": "StubProtocolCollector (simulated)",
        "mac_ready": False,
        "description": "Protocol anomaly detection (HTTP, SSH, RDP, DNS, SMTP patterns)",
        "mitre": ["T1071", "T1021", "T1219", "T1048"],
        "trigger_hint": "Produces stub events — no live protocol parsing yet.",
    },
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def get_rss_kb(pid: int) -> int:
    """Get RSS in KB for a process."""
    try:
        result = subprocess.run(
            ["ps", "-o", "rss=", "-p", str(pid)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return int(result.stdout.strip()) if result.returncode == 0 else 0
    except (ValueError, subprocess.TimeoutExpired):
        return 0


def get_cpu_percent(pid: int) -> float:
    """Get CPU% for a process."""
    try:
        result = subprocess.run(
            ["ps", "-o", "%cpu=", "-p", str(pid)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return float(result.stdout.strip()) if result.returncode == 0 else 0.0
    except (ValueError, subprocess.TimeoutExpired):
        return 0.0


def decode_queue_db(db_path: str) -> List[Dict[str, Any]]:
    """Decode all protobuf rows from a queue SQLite DB.

    Returns list of decoded event dicts with full field extraction.
    """
    if not os.path.exists(db_path):
        return []

    from amoskys.proto import universal_telemetry_pb2 as pb2

    decoded = []
    try:
        conn = sqlite3.connect(db_path, timeout=5)
        # Detect schema: column is 'bytes' (local_queue.py) or 'payload' (older)
        cols = [row[1] for row in conn.execute("PRAGMA table_info(queue)").fetchall()]
        blob_col = "bytes" if "bytes" in cols else "payload"
        ts_col = "ts_ns" if "ts_ns" in cols else "ts"
        rows = conn.execute(
            f"SELECT id, idem, {ts_col}, {blob_col} FROM queue ORDER BY id"
        ).fetchall()
        conn.close()
    except Exception as e:
        return [{"error": f"DB read failed: {e}"}]

    for rowid, idem, ts, payload in rows:
        entry: Dict[str, Any] = {
            "rowid": rowid,
            "idem": idem,
            "ts": ts,
            "decode_ok": False,
        }

        try:
            dt = pb2.DeviceTelemetry()
            dt.ParseFromString(payload)
            entry["decode_ok"] = True
            entry["device_id"] = dt.device_id
            entry["collection_agent"] = dt.collection_agent
            entry["agent_version"] = dt.agent_version
            entry["protocol"] = dt.protocol
            entry["event_count"] = len(dt.events)
            entry["timestamp_ns"] = dt.timestamp_ns

            events = []
            for ev in dt.events:
                ev_dict: Dict[str, Any] = {
                    "event_id": ev.event_id,
                    "event_type": ev.event_type,
                    "severity": ev.severity,
                    "source_component": ev.source_component,
                    "tags": list(ev.tags),
                    "confidence_score": ev.confidence_score,
                    # mitre_techniques lives inside SecurityEvent, not TelemetryEvent
                    "mitre_techniques": [],
                }

                # Extract metric_data if present
                if ev.HasField("metric_data"):
                    ev_dict["metric_data"] = {
                        "metric_name": ev.metric_data.metric_name,
                        "metric_type": ev.metric_data.metric_type,
                        "numeric_value": ev.metric_data.numeric_value,
                        "unit": ev.metric_data.unit,
                    }

                # Extract alarm_data if present
                if ev.HasField("alarm_data"):
                    ev_dict["alarm_data"] = {
                        "alarm_type": ev.alarm_data.alarm_type,
                        "description": ev.alarm_data.description,
                    }

                # Extract security_event if present
                if ev.HasField("security_event"):
                    se = ev.security_event
                    ev_dict["security_event"] = {
                        "event_category": se.event_category,
                        "event_action": se.event_action,
                        "source_ip": se.source_ip,
                        "risk_score": se.risk_score,
                        "analyst_notes": se.analyst_notes,
                        "mitre_techniques": list(se.mitre_techniques),
                    }
                    # Promote MITRE techniques to top level for analyzer
                    ev_dict["mitre_techniques"] = list(se.mitre_techniques)

                # Extract attributes
                if ev.attributes:
                    ev_dict["attributes"] = dict(ev.attributes)

                events.append(ev_dict)

            entry["events"] = events

        except Exception as e:
            entry["error"] = str(e)

        decoded.append(entry)

    return decoded


def analyze_events(decoded_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze decoded queue data to produce audit metrics."""
    total_rows = len(decoded_rows)
    decode_ok = sum(1 for r in decoded_rows if r.get("decode_ok"))
    decode_fail = total_rows - decode_ok

    all_events: List[Dict[str, Any]] = []
    for row in decoded_rows:
        all_events.extend(row.get("events", []))

    event_types: Dict[str, int] = {}
    severities: Dict[str, int] = {}
    probe_names: Dict[str, int] = {}
    mitre_techniques: Set[str] = set()
    has_metric_data = 0
    has_alarm_data = 0
    has_security_event = 0
    has_attributes = 0
    empty_evidence = 0

    for ev in all_events:
        et = ev.get("event_type", "unknown")
        event_types[et] = event_types.get(et, 0) + 1

        sev = ev.get("severity", "unknown")
        severities[sev] = severities.get(sev, 0) + 1

        src = ev.get("source_component", "unknown")
        probe_names[src] = probe_names.get(src, 0) + 1

        for t in ev.get("mitre_techniques", []):
            mitre_techniques.add(t)

        if ev.get("metric_data"):
            has_metric_data += 1
        if ev.get("alarm_data"):
            has_alarm_data += 1
        if ev.get("security_event"):
            has_security_event += 1
        if ev.get("attributes"):
            has_attributes += 1

        # Check for empty evidence
        has_evidence = bool(
            ev.get("metric_data")
            or ev.get("alarm_data")
            or ev.get("security_event")
            or ev.get("attributes")
        )
        if not has_evidence:
            empty_evidence += 1

    return {
        "total_queue_rows": total_rows,
        "decode_ok": decode_ok,
        "decode_fail": decode_fail,
        "total_events": len(all_events),
        "event_types": event_types,
        "severities": severities,
        "probe_names": probe_names,
        "mitre_techniques_observed": sorted(mitre_techniques),
        "has_metric_data": has_metric_data,
        "has_alarm_data": has_alarm_data,
        "has_security_event": has_security_event,
        "has_attributes": has_attributes,
        "empty_evidence_events": empty_evidence,
    }


# ---------------------------------------------------------------------------
# EOA Coverage Matrix
# ---------------------------------------------------------------------------

COVERAGE_ENTRY_POINTS = [
    {
        "id": "EP-01",
        "category": "Process execution",
        "description": "Spawn, args, parent/child, LOLBins, fileless",
        "agents": ["proc"],
    },
    {
        "id": "EP-02",
        "category": "Persistence",
        "description": "launchd, cron, shell profiles, login items, browser ext",
        "agents": ["persistence", "fim"],
    },
    {
        "id": "EP-03",
        "category": "File tampering",
        "description": "Config backdoors, SUID changes, webshell drops, library hijack",
        "agents": ["fim"],
    },
    {
        "id": "EP-04",
        "category": "Network egress",
        "description": "Outbound flows, beaconing, new external services, exfil volume",
        "agents": ["flow"],
    },
    {
        "id": "EP-05",
        "category": "DNS behavior",
        "description": "DGA domains, suspicious TLDs, tunneling, NXdomain bursts",
        "agents": ["dns"],
    },
    {
        "id": "EP-06",
        "category": "Authentication",
        "description": "SSH brute force, sudo abuse, privilege escalation",
        "agents": ["auth"],
    },
    {
        "id": "EP-07",
        "category": "Peripheral insertion",
        "description": "USB storage/network/HID, Bluetooth, hardware additions",
        "agents": ["peripheral"],
    },
    {
        "id": "EP-08",
        "category": "Device discovery",
        "description": "New devices on network, rogue services, ARP anomalies",
        "agents": ["device_discovery"],
    },
    {
        "id": "EP-09",
        "category": "Kernel-level signals",
        "description": "Syscalls, module loads, ptrace, capability abuse",
        "agents": ["kernel_audit"],
    },
    {
        "id": "EP-10",
        "category": "Application-layer protocol anomalies",
        "description": "HTTP/SSH/RDP/SMTP pattern deviations",
        "agents": ["protocol_collectors"],
    },
]


def build_coverage_matrix(
    audit_results: Dict[str, Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Build coverage matrix from audit results."""
    matrix = []
    for ep in COVERAGE_ENTRY_POINTS:
        row = {
            "id": ep["id"],
            "category": ep["category"],
            "description": ep["description"],
            "agents": ep["agents"],
            "status": "DARK",  # default
            "events_observed": 0,
            "notes": "",
        }

        total_events = 0
        all_mac_ready = True
        any_audited = False

        for agent_name in ep["agents"]:
            reg = AGENT_REGISTRY.get(agent_name, {})
            if not reg.get("mac_ready", False):
                all_mac_ready = False

            result = audit_results.get(agent_name)
            if result:
                any_audited = True
                total_events += result.get("analysis", {}).get("total_events", 0)

        row["events_observed"] = total_events

        if not all_mac_ready and not any_audited:
            row["status"] = "LINUX_ONLY"
            row["notes"] = "Requires Linux — deferred"
        elif total_events > 0:
            row["status"] = "OBSERVED"
            row["notes"] = f"{total_events} events captured"
        elif any_audited:
            row["status"] = "STUB"
            row["notes"] = "Agent ran but produced 0 probe events"
        else:
            row["status"] = "NOT_AUDITED"

        matrix.append(row)

    return matrix


# ---------------------------------------------------------------------------
# Scorecard generation
# ---------------------------------------------------------------------------


def generate_scorecard_md(
    agent_name: str,
    reg: Dict[str, Any],
    analysis: Dict[str, Any],
    resource_samples: List[Dict[str, Any]],
    duration_s: float,
    log_tracebacks: int,
) -> str:
    """Generate markdown scorecard for one agent audit."""
    lines = [
        f"# EOA Scorecard: {reg['label']}",
        "",
        f"**Date:** {datetime.now(timezone.utc).isoformat()}",
        f"**Duration:** {duration_s:.0f}s ({duration_s/60:.1f} min)",
        f"**Platform:** macOS (Darwin)",
        "",
        "## Agent Overview",
        "",
        f"| Property | Value |",
        f"|----------|-------|",
        f"| Agent | {reg['label']} |",
        f"| Module | `{reg['module']}` |",
        f"| Probes | {reg['probes']} |",
        f"| Collector | {reg['collector']} |",
        f"| macOS Ready | {'✅ YES' if reg['mac_ready'] else '❌ NO'} |",
        f"| MITRE Coverage | {', '.join(reg['mitre'])} |",
        "",
        "## Live Signal Assessment",
        "",
    ]

    total_events = analysis.get("total_events", 0)
    probe_events = total_events - analysis.get("has_metric_data", 0)
    empty_evidence = analysis.get("empty_evidence_events", 0)

    # Live signal verdict
    if probe_events > 0 and empty_evidence < probe_events * 0.5:
        signal_verdict = "✅ LIVE — real endpoint data captured"
    elif probe_events > 0:
        signal_verdict = "⚠️ PARTIAL — events fire but evidence is weak"
    elif total_events > 0:
        signal_verdict = "⚠️ METRICS ONLY — agent alive but no probe events"
    else:
        signal_verdict = "❌ DARK — no events produced"

    lines.extend(
        [
            f"| Check | Result |",
            f"|-------|--------|",
            f"| Live signal | {signal_verdict} |",
            f"| Total queue rows | {analysis.get('total_queue_rows', 0)} |",
            f"| Decode success | {analysis.get('decode_ok', 0)}/{analysis.get('total_queue_rows', 0)} |",
            f"| Total events | {total_events} |",
            f"| Probe events (non-metric) | {probe_events} |",
            f"| Events with evidence payload | {total_events - empty_evidence}/{total_events} |",
            f"| Empty-evidence events | {empty_evidence} |",
            f"| MITRE techniques observed | {len(analysis.get('mitre_techniques_observed', []))} |",
            f"| Tracebacks in log | {log_tracebacks} |",
            "",
        ]
    )

    # Event type breakdown
    if analysis.get("event_types"):
        lines.extend(
            [
                "## Event Types Observed",
                "",
                "| Event Type | Count |",
                "|------------|-------|",
            ]
        )
        for et, count in sorted(analysis["event_types"].items(), key=lambda x: -x[1]):
            lines.append(f"| `{et}` | {count} |")
        lines.append("")

    # Probe breakdown
    if analysis.get("probe_names"):
        lines.extend(
            [
                "## Probes That Fired",
                "",
                "| Probe (source_component) | Events |",
                "|--------------------------|--------|",
            ]
        )
        for pn, count in sorted(analysis["probe_names"].items(), key=lambda x: -x[1]):
            lines.append(f"| `{pn}` | {count} |")
        lines.append("")

    # MITRE techniques
    if analysis.get("mitre_techniques_observed"):
        lines.extend(
            [
                "## MITRE Techniques Observed",
                "",
                ", ".join(f"`{t}`" for t in analysis["mitre_techniques_observed"]),
                "",
            ]
        )

    # Resource usage
    if resource_samples:
        rss_values = [s["rss_kb"] for s in resource_samples if s["rss_kb"] > 0]
        cpu_values = [s["cpu_pct"] for s in resource_samples if s["cpu_pct"] >= 0]

        if rss_values:
            lines.extend(
                [
                    "## Resource Usage",
                    "",
                    f"| Metric | Value |",
                    f"|--------|-------|",
                    f"| RSS min | {min(rss_values):,} KB |",
                    f"| RSS max | {max(rss_values):,} KB |",
                    f"| RSS final | {rss_values[-1]:,} KB |",
                    f"| CPU avg | {sum(cpu_values)/len(cpu_values):.1f}% |",
                    f"| CPU max | {max(cpu_values):.1f}% |",
                    f"| Samples | {len(resource_samples)} |",
                    "",
                ]
            )

    # Stability
    lines.extend(
        [
            "## Stability",
            "",
            f"| Check | Result |",
            f"|-------|--------|",
            f"| Tracebacks | {'✅ 0' if log_tracebacks == 0 else f'❌ {log_tracebacks}'} |",
            f"| Loop stability | {'✅ Good' if log_tracebacks == 0 else '⚠️ Check logs'} |",
            f"| macOS compat | {'✅ Full' if reg['mac_ready'] else '❌ Stub/Linux-only'} |",
            "",
        ]
    )

    # Payload richness check (A3 contract)
    lines.extend(
        [
            "## Data Richness (A3 Contract Check)",
            "",
            "Every event must include: device_id, collection_agent, event_type, "
            "timestamp_ns, event_id, and evidence payload.",
            "",
            f"| Field | Present |",
            f"|-------|---------|",
            f"| Metric data | {analysis.get('has_metric_data', 0)} events |",
            f"| Security event | {analysis.get('has_security_event', 0)} events |",
            f"| Alarm data | {analysis.get('has_alarm_data', 0)} events |",
            f"| Attributes map | {analysis.get('has_attributes', 0)} events |",
            "",
        ]
    )

    # Next actions
    lines.extend(
        [
            "## Next Actions",
            "",
        ]
    )
    if not reg["mac_ready"]:
        lines.append(
            "1. **Implement macOS collector** — agent cannot produce live signal without it"
        )
    if probe_events == 0 and reg["mac_ready"]:
        lines.append(
            "1. **Debug probe scanning** — agent is mac-ready but probes produced 0 events"
        )
    if empty_evidence > 0:
        lines.append(
            f"1. **Fix empty evidence** — {empty_evidence} events have no payload data"
        )
    if log_tracebacks > 0:
        lines.append(f"1. **Fix {log_tracebacks} tracebacks** — check raw_log.txt")
    if probe_events > 0 and empty_evidence == 0:
        lines.append("1. ✅ Agent is healthy — consider expanding probe coverage")

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main audit loop
# ---------------------------------------------------------------------------


def run_agent_audit(
    agent_name: str,
    duration_seconds: int = 120,
    sample_interval: int = 10,
) -> Dict[str, Any]:
    """Run a single agent audit (Reality Run).

    1. Launch agent subprocess
    2. Sample RSS/CPU every sample_interval seconds
    3. After duration, kill agent
    4. Decode queue DB
    5. Produce scorecard

    Returns:
        Audit result dict
    """
    reg = AGENT_REGISTRY.get(agent_name)
    if not reg:
        print(f"❌ Unknown agent: {agent_name}")
        print(f"   Available: {', '.join(AGENT_REGISTRY.keys())}")
        return {}

    print(f"\n{'='*70}")
    print(f"  EOA Reality Run: {reg['label']}")
    print(f"  Duration: {duration_seconds}s | Sample interval: {sample_interval}s")
    print(f"  Collector: {reg['collector']}")
    print(f"  macOS ready: {'YES' if reg['mac_ready'] else 'NO (stub/linux-only)'}")
    print(f"{'='*70}\n")

    # Setup output directory
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = PROJECT_ROOT / "results" / "eoa" / f"{agent_name}_{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Setup isolated queue directory
    queue_dir = out_dir / "queue"
    queue_dir.mkdir(exist_ok=True)

    # Log file
    log_path = out_dir / "raw_log.txt"
    log_file = open(log_path, "w")

    # Build launch command
    # For agents with run_agent_v2.py, use -m module directly
    # For agents with main() function, we need a wrapper
    env = {
        **os.environ,
        "PYTHONPATH": str(PROJECT_ROOT / "src"),
        "AMOSKYS_DEVICE_ID": "eoa-audit-mac",
        "AMOSKYS_ENV": "MAC_DEV",
    }

    cmd: List[str]
    if reg.get("entry_fn") is None:
        # Has run_agent_v2.py — use -m
        cmd = [
            sys.executable,
            "-m",
            reg["module"],
            "--device-id",
            "eoa-audit-mac",
            "--queue-path",
            str(queue_dir),
            "--collection-interval",
            "10",
            "--metrics-interval",
            "30",
            "--log-level",
            "DEBUG",
        ]
    else:
        # Has main() — use -c to call it with proper args
        cli_args = reg.get("cli_args", ["--interval", "10", "--debug"])
        cmd = [
            sys.executable,
            "-c",
            f"import sys; sys.path.insert(0, '{PROJECT_ROOT / 'src'}'); "
            f"from {reg['module']} import main; main()",
        ] + cli_args

    print(f"  CMD: {' '.join(cmd[:6])}...")
    print(f"  Queue: {queue_dir}")
    print(f"  Log: {log_path}")
    print()

    # Launch agent
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(PROJECT_ROOT),
            env=env,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
    except Exception as e:
        print(f"  ❌ Failed to launch: {e}")
        log_file.close()
        return {"agent": agent_name, "error": str(e)}

    pid = proc.pid
    print(f"  ✅ Agent launched (PID {pid})")

    # Collect resource samples
    resource_samples: List[Dict[str, Any]] = []
    num_samples = duration_seconds // sample_interval + 1
    start_time = time.time()

    for i in range(num_samples):
        if proc.poll() is not None:
            print(f"  ⚠️  Agent died at sample {i} (exit code {proc.returncode})")
            break

        rss = get_rss_kb(pid)
        cpu = get_cpu_percent(pid)
        elapsed = time.time() - start_time

        sample = {
            "sample": i,
            "elapsed_s": round(elapsed, 1),
            "rss_kb": rss,
            "cpu_pct": cpu,
        }
        resource_samples.append(sample)

        status = "▓" * min(int(elapsed / duration_seconds * 30), 30)
        remaining = "░" * (30 - len(status))
        print(
            f"\r  [{status}{remaining}] "
            f"{elapsed:.0f}/{duration_seconds}s  "
            f"RSS={rss:,}KB  CPU={cpu:.1f}%",
            end="",
            flush=True,
        )

        if i < num_samples - 1:
            time.sleep(sample_interval)

    print()  # newline after progress bar

    # Kill agent
    elapsed_total = time.time() - start_time
    if proc.poll() is None:
        print(f"  Sending SIGTERM...")
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=10)
            print(f"  ✅ Agent stopped gracefully")
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            print(f"  ⚠️  Agent killed (SIGKILL)")
    else:
        print(f"  Agent already exited (code {proc.returncode})")

    log_file.close()

    # Count tracebacks (exclude expected EventBus/cert circuit-breaker errors)
    log_content = log_path.read_text()
    traceback_count_total = log_content.count("Traceback")
    # Expected tracebacks from circuit breaker (no certs in dev mode)
    expected_tb = log_content.count("_publish_with_circuit_breaker")
    traceback_count = max(0, traceback_count_total - expected_tb)

    # Find and decode queue DB
    print(f"\n  Decoding queue data...")
    db_files = list(queue_dir.glob("*.db"))

    # Also check default data/queue paths (some agents use config-based paths)
    default_queue = PROJECT_ROOT / "data" / "queue"
    if default_queue.exists():
        for db in default_queue.glob("*.db"):
            # Check if modified during our run
            if db.stat().st_mtime >= start_time:
                db_files.append(db)

    decoded_rows: List[Dict[str, Any]] = []
    for db_file in db_files:
        print(f"    📦 {db_file.name}")
        rows = decode_queue_db(str(db_file))
        decoded_rows.extend(rows)
        print(f"       → {len(rows)} rows decoded")

    # Analyze
    analysis = analyze_events(decoded_rows)

    print(f"\n  📊 Analysis:")
    print(f"     Queue rows: {analysis['total_queue_rows']}")
    print(f"     Events: {analysis['total_events']}")
    print(f"     Event types: {list(analysis['event_types'].keys())}")
    print(f"     MITRE: {analysis['mitre_techniques_observed']}")
    print(f"     Empty evidence: {analysis['empty_evidence_events']}")
    print(
        f"     Tracebacks: {traceback_count} unexpected ({expected_tb} expected circuit-breaker)"
    )

    # Generate scorecard
    scorecard_md = generate_scorecard_md(
        agent_name,
        reg,
        analysis,
        resource_samples,
        elapsed_total,
        traceback_count,
    )

    # Save outputs
    (out_dir / "scorecard.md").write_text(scorecard_md)

    scorecard_json = {
        "agent": agent_name,
        "label": reg["label"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "duration_s": round(elapsed_total, 1),
        "mac_ready": reg["mac_ready"],
        "collector": reg["collector"],
        "probes_declared": reg["probes"],
        "analysis": analysis,
        "resource_samples": resource_samples,
        "tracebacks": traceback_count,
        "log_file": str(log_path),
        "queue_dbs": [str(f) for f in db_files],
    }
    (out_dir / "scorecard.json").write_text(
        json.dumps(scorecard_json, indent=2, default=str)
    )

    # Save decoded events
    with open(out_dir / "events.jsonl", "w") as f:
        for row in decoded_rows:
            f.write(json.dumps(row, default=str) + "\n")

    # Save resource metrics
    with open(out_dir / "metrics.jsonl", "w") as f:
        for sample in resource_samples:
            f.write(json.dumps(sample) + "\n")

    print(f"\n  📁 Results: {out_dir}")
    print(f"     scorecard.md   — human-readable report")
    print(f"     scorecard.json — structured data")
    print(f"     events.jsonl   — {len(decoded_rows)} decoded rows")
    print(f"     metrics.jsonl  — {len(resource_samples)} resource samples")
    print(f"     raw_log.txt    — agent output")

    return scorecard_json


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="AMOSKYS Empirical Observability Audit (EOA)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Agents available:
  proc              Process execution monitoring (psutil — LIVE on Mac)
  fim               File integrity monitoring (os.walk — LIVE on Mac)
  persistence       Persistence mechanisms (STUB — needs collector)
  dns               DNS query monitoring (log show — LIVE on Mac)
  auth              Authentication monitoring (log show — LIVE on Mac)
  flow              Network flow monitoring (STUB — needs collector)
  peripheral        Peripheral/USB monitoring (system_profiler — LIVE on Mac)
  kernel_audit      Kernel syscalls (Linux only)
  device_discovery  Network device discovery (Linux only)
  protocol_collectors  Protocol anomalies (STUB)

Examples:
  python scripts/eoa/run_agent_audit.py --agent proc
  python scripts/eoa/run_agent_audit.py --agent proc --duration 900
  python scripts/eoa/run_agent_audit.py --mac-ready
  python scripts/eoa/run_agent_audit.py --all --duration 120
  python scripts/eoa/run_agent_audit.py --inventory
        """,
    )
    parser.add_argument(
        "--agent",
        type=str,
        help="Agent to audit (see list above)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Audit ALL agents sequentially",
    )
    parser.add_argument(
        "--mac-ready",
        action="store_true",
        help="Audit only Mac-ready agents (proc, fim, dns, auth, peripheral)",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=120,
        help="Audit duration in seconds (default: 120)",
    )
    parser.add_argument(
        "--sample-interval",
        type=int,
        default=10,
        help="Resource sample interval in seconds (default: 10)",
    )
    parser.add_argument(
        "--inventory",
        action="store_true",
        help="Print agent inventory and exit (no run)",
    )

    args = parser.parse_args()

    # Inventory mode
    if args.inventory:
        print("\n  AMOSKYS Agent Inventory")
        print("  " + "=" * 68)
        print(f"  {'Agent':<22} {'Probes':>6}  {'macOS':>5}  {'Collector'}")
        print("  " + "-" * 68)
        for name, reg in AGENT_REGISTRY.items():
            mac = "✅" if reg["mac_ready"] else "❌"
            print(f"  {name:<22} {reg['probes']:>6}  {mac:>5}  {reg['collector'][:40]}")
        print()

        print("  Coverage Entry Points")
        print("  " + "-" * 68)
        for ep in COVERAGE_ENTRY_POINTS:
            agents = ", ".join(ep["agents"])
            print(f"  {ep['id']}  {ep['category']:<35} → {agents}")
        print()
        return

    # Determine which agents to audit
    agents_to_audit: List[str] = []

    if args.agent:
        if args.agent not in AGENT_REGISTRY:
            print(f"❌ Unknown agent: {args.agent}")
            print(f"   Available: {', '.join(AGENT_REGISTRY.keys())}")
            sys.exit(1)
        agents_to_audit = [args.agent]
    elif args.mac_ready:
        agents_to_audit = [
            name for name, reg in AGENT_REGISTRY.items() if reg["mac_ready"]
        ]
    elif args.all:
        agents_to_audit = list(AGENT_REGISTRY.keys())
    else:
        parser.print_help()
        return

    print(f"\n🔍 AMOSKYS Empirical Observability Audit")
    print(f"   Agents: {', '.join(agents_to_audit)}")
    print(f"   Duration: {args.duration}s per agent")
    print(f"   Total estimated time: {len(agents_to_audit) * args.duration}s")

    # Run audits
    all_results: Dict[str, Dict[str, Any]] = {}

    for agent_name in agents_to_audit:
        result = run_agent_audit(
            agent_name,
            duration_seconds=args.duration,
            sample_interval=args.sample_interval,
        )
        all_results[agent_name] = result

    # Build coverage matrix
    print(f"\n{'='*70}")
    print(f"  COVERAGE ARSENAL — What does AMOSKYS see on this Mac?")
    print(f"{'='*70}\n")

    matrix = build_coverage_matrix(all_results)

    print(f"  {'ID':<7} {'Category':<35} {'Status':<15} {'Events':>7}")
    print(f"  {'-'*7} {'-'*35} {'-'*15} {'-'*7}")
    for row in matrix:
        status_icon = {
            "OBSERVED": "✅",
            "STUB": "⚠️ ",
            "DARK": "❌",
            "LINUX_ONLY": "🐧",
            "NOT_AUDITED": "⏳",
        }.get(row["status"], "?")
        print(
            f"  {row['id']:<7} {row['category']:<35} "
            f"{status_icon} {row['status']:<12} {row['events_observed']:>7}"
        )

    # Save combined report
    if len(agents_to_audit) > 1:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        combined_dir = PROJECT_ROOT / "results" / "eoa" / f"combined_{ts}"
        combined_dir.mkdir(parents=True, exist_ok=True)

        (combined_dir / "coverage_matrix.json").write_text(
            json.dumps(matrix, indent=2, default=str)
        )

        # Build combined markdown
        lines = [
            "# AMOSKYS Coverage Arsenal",
            "",
            f"**Date:** {datetime.now(timezone.utc).isoformat()}",
            f"**Platform:** macOS (Darwin)",
            f"**Agents audited:** {len(agents_to_audit)}",
            "",
            "## Coverage Matrix",
            "",
            "| ID | Category | Status | Events | Notes |",
            "|----|----------|--------|--------|-------|",
        ]
        for row in matrix:
            status_icon = {
                "OBSERVED": "✅ OBSERVED",
                "STUB": "⚠️ STUB",
                "DARK": "❌ DARK",
                "LINUX_ONLY": "🐧 LINUX",
                "NOT_AUDITED": "⏳ PENDING",
            }.get(row["status"], row["status"])
            lines.append(
                f"| {row['id']} | {row['category']} | {status_icon} | "
                f"{row['events_observed']} | {row['notes']} |"
            )
        lines.extend(["", "## Agent Scorecards", ""])

        for agent_name, result in all_results.items():
            if not result:
                continue
            reg = AGENT_REGISTRY[agent_name]
            analysis = result.get("analysis", {})
            total = analysis.get("total_events", 0)
            lines.append(
                f"- **{reg['label']}**: {total} events, "
                f"{analysis.get('empty_evidence_events', 0)} empty-evidence, "
                f"{'✅' if reg['mac_ready'] else '❌'} macOS"
            )

        lines.append("")
        (combined_dir / "coverage_arsenal.md").write_text("\n".join(lines))
        print(f"\n  📁 Combined report: {combined_dir}")

    print(f"\n✅ EOA complete.\n")


if __name__ == "__main__":
    main()
