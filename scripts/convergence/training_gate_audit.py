#!/usr/bin/env python3
"""Audit ML training queries for quality-gate conformance.

Checks SQL snippets that read from security_events and verifies that
quality filters are present:
- quality_state must be constrained to valid
- training_exclude must be constrained to false/0
"""

from __future__ import annotations

import argparse
import ast
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = PROJECT_ROOT / "src" / "amoskys" / "intel"

FROM_SECURITY_RE = re.compile(r"\bfrom\s+security_events\b", re.I)
QUALITY_FILTER_RE = re.compile(r"\bquality_state\b", re.I)
TRAINING_FILTER_RE = re.compile(r"\btraining_exclude\b", re.I)
WHERE_RE = re.compile(r"\bwhere\b", re.I)


@dataclass(slots=True)
class QueryFinding:
    file: str
    line: int
    has_quality_filter: bool
    has_training_exclude_filter: bool
    snippet: str


def _query_strings_in_call(node: ast.Call) -> Iterable[tuple[int, str]]:
    for arg in node.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            yield arg.lineno, arg.value
        elif isinstance(arg, ast.JoinedStr):
            parts: List[str] = []
            for item in arg.values:
                if isinstance(item, ast.Constant) and isinstance(item.value, str):
                    parts.append(item.value)
                else:
                    parts.append("{expr}")
            yield arg.lineno, "".join(parts)


def _scan_file(path: Path) -> List[QueryFinding]:
    findings: List[QueryFinding] = []
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Attribute):
            if node.func.attr not in {"execute", "read_sql_query"}:
                continue
            for lineno, query in _query_strings_in_call(node):
                if not FROM_SECURITY_RE.search(query):
                    continue
                lowered = query.lower()
                has_where = bool(WHERE_RE.search(lowered))
                has_dynamic_clause = "{expr}" in lowered
                has_quality = has_where and (
                    bool(QUALITY_FILTER_RE.search(lowered)) or has_dynamic_clause
                )
                has_training = has_where and (
                    bool(TRAINING_FILTER_RE.search(lowered)) or has_dynamic_clause
                )
                findings.append(
                    QueryFinding(
                        file=str(path),
                        line=lineno,
                        has_quality_filter=has_quality,
                        has_training_exclude_filter=has_training,
                        snippet=" ".join(query.strip().split())[:220],
                    )
                )
    return findings


def run_audit(paths: List[Path]) -> dict:
    all_findings: List[QueryFinding] = []
    for path in paths:
        if path.is_file():
            all_findings.extend(_scan_file(path))
            continue
        if path.exists():
            for py_file in sorted(path.rglob("*.py")):
                all_findings.extend(_scan_file(py_file))

    violations = [
        f
        for f in all_findings
        if not f.has_quality_filter or not f.has_training_exclude_filter
    ]
    return {
        "checked_queries": len(all_findings),
        "violations": [
            {
                "file": f.file,
                "line": f.line,
                "missing_quality_filter": not f.has_quality_filter,
                "missing_training_exclude_filter": not f.has_training_exclude_filter,
                "snippet": f.snippet,
            }
            for f in violations
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit training quality gates")
    parser.add_argument(
        "--paths",
        nargs="*",
        default=[str(SRC_ROOT)],
        help="Files/directories to scan",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    parser.add_argument("--output", default="", help="Optional output file")
    parser.add_argument(
        "--fail-on-violation",
        action="store_true",
        help="Exit 1 when violations exist",
    )
    args = parser.parse_args()

    report = run_audit([Path(p) for p in args.paths])
    text = json.dumps(report, indent=2, sort_keys=True)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + "\n", encoding="utf-8")

    if args.json:
        print(text)
    else:
        print(f"Checked queries: {report['checked_queries']}")
        print(f"Violations: {len(report['violations'])}")
        for item in report["violations"]:
            print(
                f"- {item['file']}:{item['line']} "
                f"missing_quality={item['missing_quality_filter']} "
                f"missing_training_exclude={item['missing_training_exclude_filter']}"
            )

    if args.fail_on_violation and report["violations"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
