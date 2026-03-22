#!/usr/bin/env python3
"""Phase 2 Mandate Validation - CONDITIONAL Field Coverage Audit.

Runs against live telemetry.db to measure CONDITIONAL field coverage
after Phase 2 enrichment. Reports pass/fail against mandate thresholds.

Usage:
    python scripts/validate_phase2_mandate.py [--db path/to/telemetry.db]
"""

import argparse
import os
import sqlite3
import sys
from datetime import datetime, timezone

THRESHOLDS = {
    "process_cluster": {
        "fields": ["pid", "process_name", "exe"],
        "target": 0.80,
        "label": "Process Cluster (pid/process_name/exe)",
    },
    "network_cluster": {
        "fields": ["remote_ip", "remote_port"],
        "target": 0.50,
        "label": "Network Cluster (remote_ip/remote_port)",
    },
    "system_cluster": {
        "fields": ["username"],
        "target": 0.30,
        "label": "System Cluster (username)",
    },
    "file_path_cluster": {
        "fields": ["path", "sha256"],
        "target": 0.10,
        "label": "File/Path Cluster (path/sha256)",
    },
}

MANDATORY_FIELDS = [
    "collection_agent",
    "event_category",
    "description",
    "probe_name",
    "detection_source",
]


def get_field_coverage(cursor, field, total):
    if total == 0:
        return 0.0
    try:
        cursor.execute(
            f"SELECT COUNT(*) FROM security_events "
            f"WHERE {field} IS NOT NULL AND {field} != ''"
        )
        typed = cursor.fetchone()[0]
    except sqlite3.OperationalError:
        typed = 0

    try:
        cursor.execute(
            "SELECT COUNT(*) FROM security_events "
            "WHERE raw_attributes_json IS NOT NULL "
            f"AND json_extract(raw_attributes_json, '$.{field}') IS NOT NULL "
            f"AND json_extract(raw_attributes_json, '$.{field}') != ''"
        )
        json_ct = cursor.fetchone()[0]
    except (sqlite3.OperationalError, Exception):
        json_ct = 0

    return max(typed, json_ct) / total


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
    print(f"  Phase 2 Mandate Validation | {now}")
    print(f"  {total:,} security events")
    print("=" * 70)

    # Mandatory
    print(f"\n  MANDATORY FIELDS (target: 100%):")
    mandatory_ok = True
    for f in MANDATORY_FIELDS:
        cov = get_field_coverage(cur, f, total)
        ok = cov >= 0.95
        if not ok:
            mandatory_ok = False
        print(f"    {'✓' if ok else '✗'} {f:<25} {cov:.0%}")

    # Conditional clusters
    print(f"\n  CONDITIONAL CLUSTERS:")
    all_ok = True
    for key, spec in THRESHOLDS.items():
        covs = [(f, get_field_coverage(cur, f, total)) for f in spec["fields"]]
        avg = sum(c for _, c in covs) / len(covs)
        ok = avg >= spec["target"]
        if not ok:
            all_ok = False
        print(f"\n    {spec['label']}  target={spec['target']:.0%}  actual={avg:.0%}  {'✓' if ok else '⚠'}")
        for f, c in covs:
            bar = "█" * int(c * 20) + "░" * (20 - int(c * 20))
            print(f"      {bar} {f:<20} {c:.0%}")

    # Quality
    print(f"\n  QUALITY:")
    for label, sql in [
        ("app_launch noise", "SELECT COUNT(*) FROM security_events WHERE event_category='app_launch'"),
        ("link-local IPs", "SELECT COUNT(*) FROM security_events WHERE remote_ip LIKE '%fe80%'"),
        ("null descriptions", "SELECT COUNT(*) FROM security_events WHERE description IS NULL OR description=''"),
    ]:
        cur.execute(sql)
        v = cur.fetchone()[0]
        print(f"    {'✓' if v == 0 else '✗'} {label}: {v}")

    print(f"\n{'=' * 70}")
    if mandatory_ok and all_ok:
        print("  VERDICT: ✓ ML-READY")
        code = 0
    elif mandatory_ok:
        print("  VERDICT: ⚠ CONDITIONAL GAPS — continue enrichment")
        code = 1
    else:
        print("  VERDICT: ✗ MANDATORY FAILURE")
        code = 1
    print("=" * 70)
    conn.close()
    return code


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--db", default="data/telemetry.db")
    sys.exit(generate_report(p.parse_args().db))
