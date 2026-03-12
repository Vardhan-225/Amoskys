#!/usr/bin/env python3
"""Audit MITRE provenance/evidence completeness in canonical security events."""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path
from typing import Dict

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = PROJECT_ROOT / "data" / "telemetry.db"


def _table_has_columns(conn: sqlite3.Connection, table: str, columns: set[str]) -> bool:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    present = {row[1] for row in rows}
    return columns.issubset(present)


def run_audit(db_path: Path) -> Dict:
    if not db_path.exists():
        return {
            "status": "no_db",
            "db_path": str(db_path),
            "message": "telemetry DB not found",
        }

    required_cols = {
        "mitre_techniques",
        "mitre_source",
        "mitre_confidence",
        "mitre_evidence",
    }
    with sqlite3.connect(str(db_path)) as conn:
        if not _table_has_columns(conn, "security_events", required_cols):
            return {
                "status": "schema_missing",
                "db_path": str(db_path),
                "missing_columns": sorted(required_cols),
            }

        total = conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
        declared = conn.execute(
            "SELECT COUNT(*) FROM security_events WHERE mitre_techniques IS NOT NULL AND TRIM(mitre_techniques) NOT IN ('', '[]')"
        ).fetchone()[0]
        with_provenance = conn.execute(
            "SELECT COUNT(*) FROM security_events WHERE mitre_source IS NOT NULL AND TRIM(mitre_source) != ''"
        ).fetchone()[0]
        with_evidence = conn.execute(
            "SELECT COUNT(*) FROM security_events WHERE mitre_evidence IS NOT NULL AND TRIM(mitre_evidence) NOT IN ('', '[]')"
        ).fetchone()[0]
        explainable = conn.execute(
            """
            SELECT COUNT(*) FROM security_events
            WHERE mitre_techniques IS NOT NULL
              AND TRIM(mitre_techniques) NOT IN ('', '[]')
              AND mitre_source IS NOT NULL
              AND TRIM(mitre_source) != ''
              AND mitre_evidence IS NOT NULL
              AND TRIM(mitre_evidence) NOT IN ('', '[]')
            """
        ).fetchone()[0]
        source_rows = conn.execute(
            """
            SELECT COALESCE(mitre_source, 'unknown') AS src, COUNT(*) AS cnt
            FROM security_events
            GROUP BY src
            ORDER BY cnt DESC
            """
        ).fetchall()

    def pct(value: int) -> float:
        return round((value / total) * 100, 2) if total else 0.0

    return {
        "status": "ok",
        "db_path": str(db_path),
        "totals": {
            "security_events": total,
            "declared_mitre": declared,
            "with_provenance": with_provenance,
            "with_evidence": with_evidence,
            "explainable_mitre_events": explainable,
        },
        "percentages": {
            "declared_mitre_pct": pct(declared),
            "with_provenance_pct": pct(with_provenance),
            "with_evidence_pct": pct(with_evidence),
            "explainable_mitre_events_pct": pct(explainable),
        },
        "provenance_distribution": {row[0]: row[1] for row in source_rows},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="MITRE provenance audit")
    parser.add_argument("--db", default=str(DEFAULT_DB), help="Path to telemetry.db")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    parser.add_argument("--output", default="", help="Optional output file")
    parser.add_argument(
        "--min-explainable-pct",
        type=float,
        default=0.0,
        help="Fail if explainable MITRE event percentage is below threshold",
    )
    args = parser.parse_args()

    report = run_audit(Path(args.db))
    text = json.dumps(report, indent=2, sort_keys=True)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + "\n", encoding="utf-8")

    if args.json:
        print(text)
    else:
        print(f"Status: {report.get('status')}")
        if report.get("status") == "ok":
            print(f"Security events: {report['totals']['security_events']}")
            print(
                "Explainable MITRE events: "
                f"{report['totals']['explainable_mitre_events']} "
                f"({report['percentages']['explainable_mitre_events_pct']}%)"
            )

    if report.get("status") == "ok" and args.min_explainable_pct:
        pct = float(report["percentages"]["explainable_mitre_events_pct"])
        if pct < args.min_explainable_pct:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
