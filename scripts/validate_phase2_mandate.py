#!/usr/bin/env python3
"""Phase 2.5 Mandate Validation - Capability-Aware Field Coverage Audit.

Measures CONDITIONAL field coverage using TWO scoring models:

1. GLOBAL - Raw % across all events (what the ML model sees as feature fill rate)
2. CAPABILITY-ADJUSTED - % across only agents that CAN provide each cluster's
   fields, excluding agents that structurally cannot (e.g., auth has no PIDs,
   process has no remote_ip). This is the true enrichment quality metric.

Usage:
    python scripts/validate_phase2_mandate.py [--db path/to/telemetry.db]

Exit codes:
    0 = All thresholds met (ML-ready)
    1 = Some thresholds below target (continue enrichment)
    2 = Critical failure (database error or no events)
"""

import argparse
import os
import sqlite3
import sys
from datetime import datetime, timezone


# ===========================================================================
# Agent-to-Capability Mapping
# ===========================================================================

PROCESS_CAPABLE_AGENTS = {
    "macos_process",
    "macos_network",
    "macos_realtime_sensor",
    "macos_kernel_audit",
    "macos_dns",
    "macos_peripheral",
    "macos_persistence",
    "macos_filesystem",
    "macos_infostealer_guard",
}

NETWORK_CAPABLE_AGENTS = {
    "macos_network",
    "macos_dns",
    "macos_auth",
    "macos_discovery",
    "macos_protocol_collectors",
    "macos_internet_activity",
}

SYSTEM_CAPABLE_AGENTS = {
    "macos_process",
    "macos_auth",
    "macos_realtime_sensor",
    "macos_kernel_audit",
    "macos_dns",
    "macos_persistence",
    "macos_filesystem",
    "macos_network",
    "macos_peripheral",
    "macos_infostealer_guard",
}

FILE_CAPABLE_AGENTS = {
    "macos_filesystem",
    "macos_persistence",
    "macos_quarantine_guard",
}

CLUSTERS = {
    "process": {
        "fields": ["pid", "process_name", "exe"],
        "capable_agents": PROCESS_CAPABLE_AGENTS,
        "global_target": 0.50,
        "adjusted_target": 0.80,
        "label": "Process (pid/process_name/exe)",
    },
    "network": {
        "fields": ["remote_ip"],
        "capable_agents": NETWORK_CAPABLE_AGENTS,
        "global_target": 0.15,
        "adjusted_target": 0.60,
        "label": "Network (remote_ip)",
    },
    "system": {
        "fields": ["username"],
        "capable_agents": SYSTEM_CAPABLE_AGENTS,
        "global_target": 0.30,
        "adjusted_target": 0.40,
        "label": "System (username)",
    },
    "file_path": {
        "fields": ["path", "file_name"],
        "capable_agents": FILE_CAPABLE_AGENTS,
        "global_target": 0.05,
        "adjusted_target": 0.30,
        "label": "File/Path (path/file_name)",
    },
}

MANDATORY_FIELDS = [
    "collection_agent",
    "event_category",
    "description",
    "probe_name",
    "detection_source",
]


def get_field_coverage(cursor, field_name, total, agent_filter=None):
    if total == 0:
        return 0, 0, 0.0

    agent_clause = ""
    params = []
    if agent_filter:
        placeholders = ",".join("?" * len(agent_filter))
        agent_clause = f" AND collection_agent IN ({placeholders})"
        params = list(agent_filter)

    cursor.execute(
        f"SELECT COUNT(*) FROM security_events WHERE 1=1 {agent_clause}", params
    )
    denom = cursor.fetchone()[0]
    if denom == 0:
        return 0, 0, 0.0

    try:
        cursor.execute(
            f"SELECT COUNT(*) FROM security_events "
            f"WHERE {field_name} IS NOT NULL AND {field_name} != '' "
            f"AND CAST({field_name} AS TEXT) != '0' {agent_clause}",
            params,
        )
        typed_count = cursor.fetchone()[0]
    except sqlite3.OperationalError:
        typed_count = 0

    try:
        cursor.execute(
            "SELECT COUNT(*) FROM security_events "
            "WHERE raw_attributes_json IS NOT NULL "
            f"AND json_extract(raw_attributes_json, ?) IS NOT NULL "
            f"AND json_extract(raw_attributes_json, ?) != '' "
            f"AND json_extract(raw_attributes_json, ?) != 'null' {agent_clause}",
            [f"$.{field_name}", f"$.{field_name}", f"$.{field_name}"] + params,
        )
        json_count = cursor.fetchone()[0]
    except (sqlite3.OperationalError, Exception):
        json_count = 0

    best = max(typed_count, json_count)
    return best, denom, best / denom


def bar(pct, width=20):
    filled = int(pct * width)
    return "\u2588" * filled + "\u2591" * (width - filled)


def generate_report(db_path):
    if not os.path.exists(db_path):
        print(f"ERROR: {db_path} not found")
        return 2

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM security_events")
    total = cur.fetchone()[0]
    if total == 0:
        print("ERROR: No security events")
        return 2

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print("=" * 70)
    print(f"  Phase 2.5 Mandate Validation | {now}")
    print(f"  {total} security events")
    print("=" * 70)

    # --- MANDATORY ---
    print("\n  MANDATORY FIELDS (target: 100%):")
    mandatory_pass = True
    for f in MANDATORY_FIELDS:
        _, _, cov = get_field_coverage(cur, f, total)
        ok = cov >= 0.95
        if not ok:
            mandatory_pass = False
        print(f"    {'\u2713' if ok else '\u2717'} {f:30s} {cov:.0%}")

    # --- CONDITIONAL CLUSTERS ---
    print("\n  CONDITIONAL CLUSTERS:")
    all_adjusted_pass = True

    for ckey, spec in CLUSTERS.items():
        capable = spec["capable_agents"]

        global_covs = []
        for f in spec["fields"]:
            _, _, c = get_field_coverage(cur, f, total)
            global_covs.append(c)
        global_avg = sum(global_covs) / len(global_covs) if global_covs else 0

        adj_covs = []
        adj_denom = 0
        for f in spec["fields"]:
            covered, denom, c = get_field_coverage(cur, f, total, capable)
            adj_covs.append((f, covered, denom, c))
            adj_denom = denom

        adj_avg = sum(c for _, _, _, c in adj_covs) / len(adj_covs) if adj_covs else 0
        adj_pass = adj_avg >= spec["adjusted_target"]
        glob_pass = global_avg >= spec["global_target"]
        if not adj_pass:
            all_adjusted_pass = False

        print(
            f"\n    {spec['label']}  "
            f"adjusted={adj_avg:.0%}/{spec['adjusted_target']:.0%} "
            f"{'\u2713' if adj_pass else '\u26a0'}  "
            f"global={global_avg:.0%}/{spec['global_target']:.0%} "
            f"{'\u2713' if glob_pass else '\u26a0'}"
        )
        print(f"      (capable agents: {adj_denom} events of {total})")
        for f, covered, denom, c in adj_covs:
            print(f"      {bar(c)} {f:20s} {covered}/{denom} = {c:.0%}")

    # --- AGENTS ---
    print("\n  AGENTS:")
    cur.execute(
        "SELECT collection_agent, COUNT(*) FROM security_events "
        "WHERE collection_agent IS NOT NULL GROUP BY collection_agent ORDER BY COUNT(*) DESC"
    )
    for agent, count in cur.fetchall():
        caps = []
        if agent in PROCESS_CAPABLE_AGENTS:
            caps.append("P")
        if agent in NETWORK_CAPABLE_AGENTS:
            caps.append("N")
        if agent in SYSTEM_CAPABLE_AGENTS:
            caps.append("S")
        if agent in FILE_CAPABLE_AGENTS:
            caps.append("F")
        print(f"    {agent:35s} {count:4} events  [{','.join(caps) or '-'}]")

    # --- QUALITY ---
    print("\n  QUALITY:")
    quality_pass = True
    for label, sql in [
        (
            "app_launch noise",
            "SELECT COUNT(*) FROM security_events WHERE event_category='app_launch'",
        ),
        (
            "link-local IPs",
            "SELECT COUNT(*) FROM security_events WHERE remote_ip LIKE '%fe80%'",
        ),
        (
            "null descriptions",
            "SELECT COUNT(*) FROM security_events WHERE description IS NULL OR description=''",
        ),
    ]:
        cur.execute(sql)
        v = cur.fetchone()[0]
        ok = v == 0
        if not ok:
            quality_pass = False
        print(f"    {'\u2713' if ok else '\u2717'} {label}: {v}")

    # --- VERDICT ---
    print(f"\n{'=' * 70}")
    if mandatory_pass and all_adjusted_pass and quality_pass:
        print("  VERDICT: \u2713 ML-READY - All mandate thresholds met")
        print("  Proceed to Phase 3: INADS-style multi-perspective ML")
        code = 0
    elif mandatory_pass and quality_pass:
        print("  VERDICT: \u26a0 CONDITIONAL GAPS - continue enrichment")
        for ckey, spec in CLUSTERS.items():
            adj_covs = []
            for f in spec["fields"]:
                _, _, c = get_field_coverage(cur, f, total, spec["capable_agents"])
                adj_covs.append(c)
            avg = sum(adj_covs) / len(adj_covs) if adj_covs else 0
            if avg < spec["adjusted_target"]:
                print(
                    f"    {spec['label']}: {avg:.0%} < {spec['adjusted_target']:.0%}"
                )
        code = 1
    elif not mandatory_pass:
        print("  VERDICT: \u2717 MANDATORY FIELD FAILURE")
        code = 1
    else:
        print("  VERDICT: \u2717 QUALITY CHECK FAILURE")
        code = 1
    print("=" * 70)

    conn.close()
    return code


if __name__ == "__main__":
    p = argparse.ArgumentParser(
        description="Phase 2.5 Mandate Validation - Capability-Aware Coverage Audit"
    )
    p.add_argument("--db", default="data/telemetry.db")
    sys.exit(generate_report(p.parse_args().db))
