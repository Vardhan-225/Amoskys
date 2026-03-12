#!/usr/bin/env python3
"""Inventory dashboard/API route handlers that bypass query service.

Detects route-level direct SQL access (`store.db.execute`, `sqlite3.connect`)
and maps affected tables to canonical query-service methods.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[2]

TELEMETRY_TABLES = {
    "telemetry_events",
    "process_events",
    "flow_events",
    "dns_events",
    "audit_events",
    "persistence_events",
    "fim_events",
    "peripheral_events",
    "observation_events",
    "security_events",
    "device_telemetry",
    "metrics_timeseries",
}

TABLE_TO_QUERY_SERVICE = {
    "telemetry_events": ["telemetry_stats", "recent_telemetry"],
    "security_events": ["security_event_by_id", "update_security_event_status"],
    "process_events": ["recent_processes", "process_search", "process_stats"],
    "flow_events": ["telemetry_stats"],
    "dns_events": ["telemetry_stats"],
    "audit_events": ["telemetry_stats"],
    "persistence_events": ["telemetry_stats"],
    "fim_events": ["telemetry_stats"],
    "peripheral_events": [
        "recent_peripheral_events",
        "peripheral_stats",
        "peripheral_timeline",
        "peripheral_device_history",
    ],
    "observation_events": ["telemetry_stats"],
    "device_telemetry": ["agent_summary", "device_telemetry_snapshots"],
    "metrics_timeseries": ["device_metrics"],
}

TABLE_RE = re.compile(r"\b(?:from|join|into|update)\s+([a-zA-Z_][a-zA-Z0-9_]*)", re.I)


@dataclass(slots=True)
class Finding:
    file: str
    function: str
    line: int
    kind: str
    tables: List[str]
    suggested_methods: List[str]


def _is_route_decorator(dec: ast.expr) -> bool:
    if isinstance(dec, ast.Call):
        target = dec.func
        if isinstance(target, ast.Attribute):
            return target.attr == "route"
    return False


def _string_literals(node: ast.AST) -> Iterable[str]:
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            yield child.value


def _extract_tables(sql_fragments: Sequence[str]) -> List[str]:
    tables: set[str] = set()
    for frag in sql_fragments:
        for match in TABLE_RE.findall(frag):
            table = match.lower()
            if table in TELEMETRY_TABLES:
                tables.add(table)
    return sorted(tables)


def _method_chain(node: ast.AST) -> str:
    parts: List[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _scan_route_function(path: Path, fn: ast.FunctionDef) -> List[Finding]:
    findings: List[Finding] = []
    sql_fragments = list(_string_literals(fn))
    tables = _extract_tables(sql_fragments)

    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue

        if isinstance(node.func, ast.Attribute):
            chain = _method_chain(node.func)
            if chain.endswith(".db.execute") or chain.endswith(".db.executemany"):
                if tables:
                    suggestions = sorted(
                        {
                            method
                            for table in tables
                            for method in TABLE_TO_QUERY_SERVICE.get(table, [])
                        }
                    )
                    findings.append(
                        Finding(
                            file=str(path),
                            function=fn.name,
                            line=node.lineno,
                            kind="direct_store_sql",
                            tables=tables,
                            suggested_methods=suggestions,
                        )
                    )
            elif chain == "sqlite3.connect":
                findings.append(
                    Finding(
                        file=str(path),
                        function=fn.name,
                        line=node.lineno,
                        kind="sqlite_connection_in_route",
                        tables=tables,
                        suggested_methods=[],
                    )
                )
    return findings


def scan_paths(paths: Sequence[Path]) -> List[Finding]:
    findings: List[Finding] = []
    for path in paths:
        if not path.exists():
            continue
        for file_path in sorted(path.rglob("*.py")):
            if file_path.name.startswith("test_"):
                continue
            try:
                tree = ast.parse(file_path.read_text(encoding="utf-8"))
            except SyntaxError:
                continue

            for node in tree.body:
                if isinstance(node, ast.FunctionDef) and any(
                    _is_route_decorator(dec) for dec in node.decorator_list
                ):
                    findings.extend(_scan_route_function(file_path, node))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Dashboard/API direct SQL inventory")
    parser.add_argument(
        "--paths",
        nargs="*",
        default=["web/app/dashboard", "web/app/api"],
        help="Directories to scan",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    parser.add_argument("--output", default="", help="Optional JSON output path")
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Exit 1 if any finding is detected",
    )
    args = parser.parse_args()

    scan_dirs = [PROJECT_ROOT / p for p in args.paths]
    findings = scan_paths(scan_dirs)
    payload = {
        "count": len(findings),
        "findings": [
            {
                "file": f.file,
                "function": f.function,
                "line": f.line,
                "kind": f.kind,
                "tables": f.tables,
                "suggested_methods": f.suggested_methods,
            }
            for f in findings
        ],
    }

    text = json.dumps(payload, indent=2, sort_keys=True)
    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + "\n", encoding="utf-8")

    if args.json:
        print(text)
    else:
        print(f"Findings: {payload['count']}")
        for item in payload["findings"][:50]:
            suggestions = ", ".join(item["suggested_methods"]) or "none"
            tables = ", ".join(item["tables"]) or "none"
            print(
                f"- {item['file']}:{item['line']} {item['function']} "
                f"[{item['kind']}] tables=[{tables}] suggestions=[{suggestions}]"
            )

    if args.fail_on_findings and findings:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
