"""AMOSKYS Observability Contract — Probe Audit Engine.

Importable module that validates every probe's Observability Contract.
Used by:
  - scripts/eoa/attribute_audit.py (CLI)
  - web/app/dashboard (probe-health API endpoint)
"""

from __future__ import annotations

import importlib
import platform
from typing import Any, Dict, List

# Agent → probe factory mapping
# Keys MUST match AGENT_REGISTRY keys in src/amoskys/agents/__init__.py
# so that capabilities.py can resolve probe metadata by agent_id.
AGENT_PROBE_MAP: Dict[str, Dict[str, str]] = {
    # ── Core Observatory (short names from AGENT_REGISTRY) ──
    "proc": {
        "module": "amoskys.agents.os.macos.process.probes",
        "factory": "create_process_probes",
    },
    "fim": {
        "module": "amoskys.agents.os.macos.filesystem.probes",
        "factory": "create_filesystem_probes",
    },
    "flow": {
        "module": "amoskys.agents.os.macos.network.probes",
        "factory": "create_network_probes",
    },
    "auth": {
        "module": "amoskys.agents.os.macos.auth.probes",
        "factory": "create_auth_probes",
    },
    "persistence": {
        "module": "amoskys.agents.os.macos.persistence.probes",
        "factory": "create_persistence_probes",
    },
    "peripheral": {
        "module": "amoskys.agents.os.macos.peripheral.probes",
        "factory": "create_peripheral_probes",
    },
    # ── Platform Observatory (macos_ prefix from AGENT_REGISTRY) ──
    "macos_unified_log": {
        "module": "amoskys.agents.os.macos.unified_log.probes",
        "factory": "create_unified_log_probes",
    },
    "macos_dns": {
        "module": "amoskys.agents.os.macos.dns.probes",
        "factory": "create_dns_probes",
    },
    "macos_applog": {
        "module": "amoskys.agents.os.macos.applog.probes",
        "factory": "create_applog_probes",
    },
    "macos_discovery": {
        "module": "amoskys.agents.os.macos.discovery.probes",
        "factory": "create_discovery_probes",
    },
    "macos_internet_activity": {
        "module": "amoskys.agents.os.macos.internet_activity.probes",
        "factory": "create_internet_activity_probes",
    },
    "macos_db_activity": {
        "module": "amoskys.agents.os.macos.db_activity.probes",
        "factory": "create_db_activity_probes",
    },
    "macos_http_inspector": {
        "module": "amoskys.agents.os.macos.http_inspector.probes",
        "factory": "create_http_inspector_probes",
    },
    # ── Network & Infrastructure ──
    "network_sentinel": {
        "module": "amoskys.agents.os.macos.network_sentinel.probes",
        "factory": "create_network_sentinel_probes",
    },
    "protocol_collectors": {
        "module": "amoskys.agents.os.macos.protocol_collectors.probes",
        "factory": "create_protocol_collector_probes",
    },
    # ── macOS Shield Agents ──
    "macos_infostealer_guard": {
        "module": "amoskys.agents.os.macos.infostealer_guard.probes",
        "factory": "create_infostealer_guard_probes",
    },
    "macos_quarantine_guard": {
        "module": "amoskys.agents.os.macos.quarantine_guard.probes",
        "factory": "create_quarantine_guard_probes",
    },
    "macos_provenance": {
        "module": "amoskys.agents.os.macos.provenance.probes",
        "factory": "create_provenance_probes",
    },
    "macos_security_monitor": {
        "module": "amoskys.agents.os.macos.security_monitor.probes",
        "factory": "create_macos_security_probes",
    },
    # ── Linux ──
    "kernel_audit": {
        "module": "amoskys.agents.os.linux.kernel_audit.probes",
        "factory": "create_kernel_audit_probes",
    },
}

# ── Central Field Semantics Registry ──────────────────────────────
# Defines the semantic type for every shared_data field name used by probes.
# The audit engine resolves field_semantics from this registry when probes
# don't declare their own, eliminating "No field_semantics documented" warnings.
#
# Format:  field_name → semantic_type
#   - "snapshot_list":     field is a list of snapshot dicts from a single collection
#   - "event_log":         field is a list of parsed log/event entries
#   - "baseline_diff":     field is diffed against a baseline (first-run safe)
#   - "gauge":             field is a point-in-time status value
#   - "connection_table":  field is the current connection table (psutil/netstat)
#   - "rolling_window":    field accumulates across cycles for temporal analysis
FIELD_SEMANTICS_REGISTRY: Dict[str, str] = {
    # Network & connections
    "connections": "connection_table",
    "pid_connections": "connection_table",
    # Process telemetry
    "processes": "snapshot_list",
    # Persistence mechanisms
    "entries": "snapshot_list",
    # File integrity
    "files": "baseline_diff",
    "suid_binaries": "baseline_diff",
    "sip_status": "gauge",
    # DNS
    "dns_queries": "snapshot_list",
    "dns_servers": "snapshot_list",
    # Authentication
    "auth_events": "event_log",
    # Application / database / HTTP
    "app_logs": "event_log",
    "db_logs": "event_log",
    "http_requests": "event_log",
    # Kernel audit
    "kernel_events": "event_log",
    # Unified log
    "log_entries": "event_log",
    # Peripherals
    "usb_devices": "baseline_diff",
    "bluetooth_devices": "baseline_diff",
    "volumes": "baseline_diff",
    # Discovery
    "arp_entries": "baseline_diff",
    "bonjour_services": "baseline_diff",
    "routes": "snapshot_list",
    "hardware_ports": "snapshot_list",
    # Temporal
    "rolling": "rolling_window",
}


def _resolve_field_semantics(
    probe_semantics: Dict[str, str],
    requires_fields: List[str],
) -> Dict[str, str]:
    """Merge probe-declared semantics with the central registry.

    Probe-level declarations take precedence over the registry.
    """
    resolved = {}
    for field_name in requires_fields:
        if field_name in probe_semantics:
            resolved[field_name] = probe_semantics[field_name]
        elif field_name in FIELD_SEMANTICS_REGISTRY:
            resolved[field_name] = FIELD_SEMANTICS_REGISTRY[field_name]
    return resolved


# Known collector event types per agent
COLLECTOR_EVENT_TYPES: Dict[str, List[str]] = {
    "auth": [
        "SSH_LOGIN_SUCCESS",
        "SSH_LOGIN_FAILURE",
        "SUDO_COMMAND",
        "SUDO_FAILURE",
        "AUTH_PROMPT",
    ],
    "persistence": [
        "USER_LAUNCH_AGENT",
        "SYSTEM_LAUNCH_AGENT",
        "SYSTEM_LAUNCH_DAEMON",
        "CRON_USER",
        "SHELL_PROFILE",
        "SSH_AUTHORIZED_KEYS",
        "BROWSER_EXTENSION",
        "STARTUP_ITEM",
        "HIDDEN_FILE",
    ],
}


def audit_probe(probe: object, agent_name: str, target_platform: str) -> Dict[str, Any]:
    """Audit a single probe's Observability Contract."""
    name = getattr(probe, "name", "unknown")
    platforms = getattr(probe, "platforms", ["linux", "darwin", "windows"])
    requires_fields = getattr(probe, "requires_fields", None)
    requires_event_types = getattr(probe, "requires_event_types", [])
    field_semantics = getattr(probe, "field_semantics", {})
    degraded_without = getattr(probe, "degraded_without", [])

    result: Dict[str, Any] = {
        "probe": name,
        "agent": agent_name,
        "platforms": platforms,
        "requires_fields": requires_fields if requires_fields is not None else [],
        "requires_event_types": requires_event_types,
        "field_semantics": field_semantics,
        "degraded_without": degraded_without,
        "issues": [],
        "verdict": "REAL",
    }

    # Check 1: Platform support
    if target_platform and target_platform not in platforms:
        result["verdict"] = "DISABLED"
        result["issues"].append(f"Platform {target_platform} not supported")
        return result

    # Check 2: Contract declaration exists
    if requires_fields is None:
        result["verdict"] = "UNDECLARED"
        result["issues"].append("No requires_fields declared")
        return result

    # Check 3: Event type requirements satisfiable
    collector_events = set(COLLECTOR_EVENT_TYPES.get(agent_name, []))
    for evt_type in requires_event_types:
        if collector_events and evt_type not in collector_events:
            result["verdict"] = "BROKEN"
            result["issues"].append(f"Event type {evt_type} not generated by collector")

    # Check 4: Field semantics documented (resolve from central registry if needed)
    resolved_semantics = _resolve_field_semantics(
        field_semantics, requires_fields or []
    )
    result["field_semantics"] = resolved_semantics
    unresolved = [f for f in (requires_fields or []) if f not in resolved_semantics]
    if unresolved:
        result["issues"].append(f"No field_semantics for: {', '.join(unresolved)}")

    # Check 5: Degraded fields
    if degraded_without:
        if result["verdict"] == "REAL":
            result["verdict"] = "DEGRADED"
            result["issues"].append(f"Degraded without: {', '.join(degraded_without)}")

    return result


# Agents restricted to specific platforms (key = agent name, value = allowed platforms)
_PLATFORM_AGENTS: Dict[str, List[str]] = {
    "kernel_audit": ["linux"],
}


def run_audit(target_platform: str = "") -> List[Dict[str, Any]]:
    """Run the full attribute audit across all agents."""
    current_platform = target_platform or platform.system().lower()
    results = []

    for agent_name, info in AGENT_PROBE_MAP.items():
        # Skip agents not available on this platform
        allowed = _PLATFORM_AGENTS.get(agent_name)
        if allowed and current_platform not in allowed:
            results.append(
                {
                    "probe": "PLATFORM_SKIP",
                    "agent": agent_name,
                    "verdict": "SKIPPED",
                    "issues": [f"Not available on {current_platform}"],
                }
            )
            continue

        try:
            mod = importlib.import_module(info["module"])
            factory = getattr(mod, info["factory"])
            probes = factory()

            for probe in probes:
                result = audit_probe(probe, agent_name, target_platform)
                results.append(result)

        except Exception as e:
            results.append(
                {
                    "probe": "IMPORT_ERROR",
                    "agent": agent_name,
                    "verdict": "ERROR",
                    "issues": [str(e)],
                }
            )

    return results


def summarize_audit(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Produce a summary dict suitable for API responses."""
    by_verdict: Dict[str, int] = {}
    by_agent: Dict[str, Dict[str, Any]] = {}

    for r in results:
        verdict = r["verdict"]
        agent = r.get("agent", "unknown")

        by_verdict[verdict] = by_verdict.get(verdict, 0) + 1

        if agent not in by_agent:
            by_agent[agent] = {
                "total": 0,
                "REAL": 0,
                "DEGRADED": 0,
                "BROKEN": 0,
                "DISABLED": 0,
            }
        by_agent[agent]["total"] += 1
        if verdict in by_agent[agent]:
            by_agent[agent][verdict] += 1

    # Total excludes SKIPPED (platform-incompatible probes aren't real probes here)
    skipped = by_verdict.get("SKIPPED", 0)
    return {
        "total": len(results) - skipped,
        "real": by_verdict.get("REAL", 0),
        "degraded": by_verdict.get("DEGRADED", 0),
        "broken": by_verdict.get("BROKEN", 0),
        "disabled": by_verdict.get("DISABLED", 0),
        "error": by_verdict.get("ERROR", 0),
        "skipped": skipped,
        "by_agent": by_agent,
    }


def print_table(results: List[Dict[str, Any]]) -> None:
    """Print a human-readable audit table."""
    by_verdict: Dict[str, List[Dict[str, Any]]] = {}
    for r in results:
        by_verdict.setdefault(r["verdict"], []).append(r)

    total = len(results)
    print()
    print("=" * 70)
    print(" AMOSKYS Attribute Audit \u2014 Observability Contract Report")
    print("=" * 70)
    print()

    for verdict in ["REAL", "DEGRADED", "BROKEN", "DISABLED", "UNDECLARED", "ERROR"]:
        probes = by_verdict.get(verdict, [])
        if not probes:
            continue

        icon = {
            "REAL": "+",
            "DEGRADED": "~",
            "BROKEN": "!",
            "DISABLED": "-",
            "UNDECLARED": "?",
            "ERROR": "X",
        }.get(verdict, " ")

        print(f"  [{icon}] {verdict}: {len(probes)} probes")
        for p in probes:
            issues = "; ".join(p.get("issues", []))
            suffix = f" \u2014 {issues}" if issues else ""
            print(f"      {p['agent']:15s} {p['probe']}{suffix}")
        print()

    real = len(by_verdict.get("REAL", []))
    degraded = len(by_verdict.get("DEGRADED", []))
    broken = len(by_verdict.get("BROKEN", []))
    disabled = len(by_verdict.get("DISABLED", []))
    active = real + degraded

    print("-" * 70)
    print(f"  TOTAL: {total} probes")
    print(
        f"  ACTIVE: {active} ({100 * active / total:.1f}%)" if total else "  ACTIVE: 0"
    )
    print(
        f"  REAL: {real}  DEGRADED: {degraded}  BROKEN: {broken}  DISABLED: {disabled}"
    )
    print("=" * 70)
    print()
