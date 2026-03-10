#!/usr/bin/env python3
"""Convergence CI conformance gates for architecture drift prevention."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, List

from dashboard_sql_inventory import scan_paths


PROJECT_ROOT = Path(__file__).resolve().parents[2]
AGENTS_ROOT = PROJECT_ROOT / "src" / "amoskys" / "agents"
SRC_ROOT = PROJECT_ROOT / "src"

_SCAN_ALL_RE = re.compile(r"\bscan_all_probes\s*\(")
_LEGACY_SCHEMA_RE = re.compile(r"\bmessaging_schema_pb2\b")

LEGACY_SCHEMA_ALLOWLIST = {
    str(PROJECT_ROOT / "src" / "amoskys" / "eventbus" / "server.py"),
    str(PROJECT_ROOT / "src" / "amoskys" / "storage" / "telemetry_contract.py"),
    str(PROJECT_ROOT / "src" / "amoskys" / "proto" / "messaging_schema_pb2.py"),
    str(PROJECT_ROOT / "src" / "amoskys" / "proto" / "messaging_schema_pb2_grpc.py"),
}

SCAN_ALL_ALLOWLIST = {
    str(PROJECT_ROOT / "src" / "amoskys" / "agents" / "common" / "probes.py"),
    str(PROJECT_ROOT / "src" / "amoskys" / "agents" / "common" / "cli.py"),
}


def _scan_for_pattern(root: Path, pattern: re.Pattern[str], suffix: str = ".py") -> List[Dict]:
    findings: List[Dict] = []
    for path in sorted(root.rglob(f"*{suffix}")):
        try:
            content = path.read_text(encoding="utf-8")
        except Exception:
            continue
        for idx, line in enumerate(content.splitlines(), start=1):
            if pattern.search(line):
                findings.append({"file": str(path), "line": idx, "line_text": line.strip()})
    return findings


def run_checks() -> Dict:
    scan_all_hits = [
        item
        for item in _scan_for_pattern(AGENTS_ROOT, _SCAN_ALL_RE)
        if item["file"] not in SCAN_ALL_ALLOWLIST
    ]

    legacy_hits = []
    for item in _scan_for_pattern(SRC_ROOT, _LEGACY_SCHEMA_RE):
        file_path = item["file"]
        if file_path in LEGACY_SCHEMA_ALLOWLIST:
            continue
        if "/src/amoskys/proto/" in file_path:
            continue
        if file_path.endswith("/src/amoskys/messaging_pb2.py"):
            continue
        if item["line_text"].startswith("#"):
            continue
        legacy_hits.append(item)

    sql_findings = scan_paths([PROJECT_ROOT / "web" / "app" / "dashboard", PROJECT_ROOT / "web" / "app" / "api"])

    return {
        "checks": {
            "forbidden_scan_all_probes_usage": {
                "count": len(scan_all_hits),
                "findings": scan_all_hits,
            },
            "legacy_schema_outside_ingress": {
                "count": len(legacy_hits),
                "findings": legacy_hits,
            },
            "route_level_direct_sql": {
                "count": len(sql_findings),
                "findings": [
                    {
                        "file": f.file,
                        "function": f.function,
                        "line": f.line,
                        "kind": f.kind,
                        "tables": f.tables,
                    }
                    for f in sql_findings
                ],
            },
        }
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run convergence CI conformance checks")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    parser.add_argument("--output", default="", help="Optional output file")
    parser.add_argument("--strict", action="store_true", help="Exit 1 on any finding")
    args = parser.parse_args()

    report = run_checks()
    total = sum(item["count"] for item in report["checks"].values())
    report["total_findings"] = total
    text = json.dumps(report, indent=2, sort_keys=True)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + "\n", encoding="utf-8")

    if args.json:
        print(text)
    else:
        print(f"Total findings: {total}")
        for name, payload in report["checks"].items():
            print(f"- {name}: {payload['count']}")

    if args.strict and total > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
