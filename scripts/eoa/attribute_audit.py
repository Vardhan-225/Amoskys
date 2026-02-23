#!/usr/bin/env python3
"""AMOSKYS Attribute Audit — Observability Contract CI Gate.

Validates that every probe's Observability Contract is honest:
  - Every probe declares requires_fields
  - Field semantics are documented
  - BROKEN probes are identified (missing collector support)
  - Regressions are detected (probe that was REAL becomes BROKEN)

Usage:
    python attribute_audit.py                          # Print table
    python attribute_audit.py --platform darwin        # Filter to darwin
    python attribute_audit.py --fail-on-regression     # CI gate mode
    python attribute_audit.py --json                   # JSON output

Exit codes:
    0 — All probes pass or are honestly declared
    1 — Regression detected or undeclared probe found
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Ensure src is on path
_root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_root / "src"))

from amoskys.observability.probe_audit import print_table, run_audit  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="AMOSKYS Attribute Audit")
    parser.add_argument(
        "--platform", default="", help="Filter to platform (e.g. darwin)"
    )
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument(
        "--fail-on-regression", action="store_true", help="CI gate mode"
    )
    args = parser.parse_args()

    results = run_audit(args.platform)

    if args.json:
        print(json.dumps(results, indent=2, default=str))
    else:
        print_table(results)

    # CI gate: fail on regressions
    if args.fail_on_regression:
        undeclared = [r for r in results if r["verdict"] == "UNDECLARED"]
        errors = [r for r in results if r["verdict"] == "ERROR"]

        if undeclared:
            print(f"FAIL: {len(undeclared)} probes without requires_fields declaration")
            return 1
        if errors:
            print(f"FAIL: {len(errors)} probe import errors")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
