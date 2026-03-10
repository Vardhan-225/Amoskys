#!/usr/bin/env python3
"""AMOSKYS operations storyline orchestrator.

Runs the current architecture end-to-end without changing runtime design:

1) collect_and_store.py        -> collector + probes + WALProcessor + enrichment
2) SomaBrain.train_once()      -> ML training on telemetry.db
3) Red-team scenario suite     -> simulated attack detection efficacy
4) Coverage scorecard          -> probe proof and surface metrics
5) Observability probe audit   -> contract health snapshot

Outputs:
  results/ops_storyline/ops_storyline_report.json
  results/ops_storyline/ops_storyline_report.md
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


@dataclass
class StepResult:
    name: str
    success: bool
    elapsed_seconds: float
    details: Dict[str, Any]


def _normalize_stream(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _run_cmd(
    cmd: List[str],
    cwd: Path,
    timeout_seconds: float | None = None,
) -> Tuple[int, str, str, float, bool]:
    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout_seconds if timeout_seconds and timeout_seconds > 0 else None,
        )
        elapsed = round(time.time() - t0, 2)
        return proc.returncode, proc.stdout, proc.stderr, elapsed, False
    except subprocess.TimeoutExpired as exc:
        elapsed = round(time.time() - t0, 2)
        out = _normalize_stream(exc.stdout)
        err = _normalize_stream(exc.stderr)
        err += (
            f"\nCOMMAND_TIMEOUT: exceeded {timeout_seconds} seconds"
            if timeout_seconds
            else "\nCOMMAND_TIMEOUT"
        )
        return 124, out, err, elapsed, True


def run_collect_step(
    clear_db: bool,
    agents: int,
    skip_drain: bool,
    drain_max_events: int,
    drain_timeout_seconds: float,
    collect_timeout_seconds: float,
) -> StepResult:
    cmd = [sys.executable, "scripts/collect_and_store.py"]
    if clear_db:
        cmd.append("--clear")
    if agents > 0:
        cmd += ["--agents", str(agents)]
    if skip_drain:
        cmd.append("--skip-drain")
    else:
        if drain_max_events > 0:
            cmd += ["--drain-max-events", str(drain_max_events)]
        if drain_timeout_seconds > 0:
            cmd += ["--drain-timeout-seconds", str(drain_timeout_seconds)]

    code, out, err, elapsed, timed_out = _run_cmd(
        cmd,
        PROJECT_ROOT,
        timeout_seconds=collect_timeout_seconds,
    )
    return StepResult(
        name="collect_and_store",
        success=(code == 0 and not timed_out),
        elapsed_seconds=elapsed,
        details={
            "command": " ".join(cmd),
            "exit_code": code,
            "stdout": out,
            "stderr": err,
            "timed_out": timed_out,
            "timeout_seconds": collect_timeout_seconds,
        },
    )


def run_soma_training_step(db_path: str, model_dir: str) -> StepResult:
    from amoskys.intel.soma_brain import SomaBrain

    t0 = time.time()
    try:
        brain = SomaBrain(
            telemetry_db_path=db_path,
            model_dir=model_dir,
            training_interval_seconds=1800,
        )
        metrics = brain.train_once()
        success = metrics.get("status") == "completed"
        details = {
            "status": metrics.get("status"),
            "metrics": metrics,
            "note": "status=cold_start means not enough labeled/volume data yet",
        }
    except Exception as exc:
        success = False
        details = {
            "status": "error",
            "error": str(exc),
        }

    return StepResult(
        name="soma_train_once",
        success=success,
        elapsed_seconds=round(time.time() - t0, 2),
        details=details,
    )


def run_redteam_step() -> StepResult:
    from amoskys.redteam.harness import RedTeamHarness
    from amoskys.redteam.reality_score import score_scenario
    from amoskys.redteam.scenarios import SCENARIO_REGISTRY, _load_all

    t0 = time.time()
    _load_all()
    harness = RedTeamHarness()

    scenario_summaries: List[Dict[str, Any]] = []
    mitre_techniques: set[str] = set()
    reality_levels: List[int] = []

    total_cases = 0
    passed_cases = 0
    positive_total = 0
    positive_passed = 0
    benign_total = 0
    benign_cases_with_events = 0
    benign_passed = 0
    evasion_total = 0
    evasion_passed = 0

    for name in sorted(SCENARIO_REGISTRY.keys()):
        scenario = SCENARIO_REGISTRY[name]
        result = harness.run_scenario(scenario)
        scores = score_scenario(scenario, result)

        case_rows: List[Dict[str, Any]] = []
        for cr in result.case_results:
            cat = cr.case.category
            total_cases += 1
            if cr.passed:
                passed_cases += 1

            if cat == "positive":
                positive_total += 1
                if cr.passed:
                    positive_passed += 1
            elif cat == "benign":
                benign_total += 1
                if cr.event_count > 0:
                    benign_cases_with_events += 1
                if cr.passed:
                    benign_passed += 1
            elif cat == "evasion":
                evasion_total += 1
                if cr.passed:
                    evasion_passed += 1

            case_rows.append(
                {
                    "case_id": cr.case.id,
                    "category": cat,
                    "passed": cr.passed,
                    "event_count": cr.event_count,
                    "primary_event_type": cr.primary_event_type,
                }
            )

        scenario_levels = [s.level for s in scores]
        reality_levels.extend(scenario_levels)
        mitre_techniques.update(scenario.mitre_techniques)

        scenario_summaries.append(
            {
                "name": name,
                "agent": scenario.agent,
                "probe_id": scenario.probe_id,
                "all_passed": result.all_passed,
                "cases_total": result.total,
                "cases_passed": result.passed,
                "cases_failed": result.failed,
                "reality_level_avg": round(statistics.mean(scenario_levels), 3)
                if scenario_levels
                else None,
                "cases": case_rows,
            }
        )

    pass_rate = (passed_cases / total_cases * 100.0) if total_cases else 0.0
    positive_detection_rate = (
        positive_passed / positive_total * 100.0 if positive_total else 0.0
    )
    benign_fp_rate = (
        benign_cases_with_events / benign_total * 100.0 if benign_total else 0.0
    )
    benign_clean_rate = (benign_passed / benign_total * 100.0) if benign_total else 0.0
    evasion_handling_rate = (
        evasion_passed / evasion_total * 100.0 if evasion_total else 0.0
    )

    summary = {
        "scenarios_total": len(scenario_summaries),
        "cases_total": total_cases,
        "cases_passed": passed_cases,
        "case_pass_rate_pct": round(pass_rate, 2),
        "positive_total": positive_total,
        "positive_passed": positive_passed,
        "positive_detection_rate_pct": round(positive_detection_rate, 2),
        "benign_total": benign_total,
        "benign_passed": benign_passed,
        "benign_clean_rate_pct": round(benign_clean_rate, 2),
        "benign_cases_with_events": benign_cases_with_events,
        "benign_false_positive_rate_pct": round(benign_fp_rate, 2),
        "evasion_total": evasion_total,
        "evasion_passed": evasion_passed,
        "evasion_handling_rate_pct": round(evasion_handling_rate, 2),
        "mitre_techniques_covered": sorted(mitre_techniques),
        "mitre_technique_count": len(mitre_techniques),
        "reality_level_avg": round(statistics.mean(reality_levels), 3)
        if reality_levels
        else None,
        "reality_level_min": min(reality_levels) if reality_levels else None,
        "reality_level_max": max(reality_levels) if reality_levels else None,
    }

    return StepResult(
        name="redteam_suite",
        success=(passed_cases == total_cases and total_cases > 0),
        elapsed_seconds=round(time.time() - t0, 2),
        details={
            "summary": summary,
            "scenarios": scenario_summaries,
        },
    )


def run_coverage_step() -> StepResult:
    cmd = [sys.executable, "scripts/eoa/coverage_scorecard.py", "--json"]
    code, out, err, elapsed, timed_out = _run_cmd(cmd, PROJECT_ROOT)

    parsed: Dict[str, Any]
    success = False
    if code == 0 and not timed_out:
        try:
            parsed = json.loads(out)
            success = True
        except json.JSONDecodeError:
            parsed = {"raw_output": out}
    else:
        parsed = {"raw_output": out}

    return StepResult(
        name="coverage_scorecard",
        success=success,
        elapsed_seconds=elapsed,
        details={
            "command": " ".join(cmd),
            "exit_code": code,
            "stderr": err,
            "timed_out": timed_out,
            "scorecard": parsed,
        },
    )


def run_probe_audit_step() -> StepResult:
    from amoskys.observability.probe_audit import run_audit, summarize_audit

    t0 = time.time()
    try:
        results = run_audit()
        summary = summarize_audit(results)
        success = summary.get("broken", 0) == 0 and summary.get("error", 0) == 0
        details = {
            "summary": summary,
            "total_rows": len(results),
        }
    except Exception as exc:
        success = False
        details = {
            "error": str(exc),
        }

    return StepResult(
        name="probe_audit",
        success=success,
        elapsed_seconds=round(time.time() - t0, 2),
        details=details,
    )


def compute_positioning(report: Dict[str, Any]) -> Dict[str, Any]:
    red = report.get("redteam", {}).get("summary", {})
    cov = report.get("coverage", {}).get("scores", {})
    aud = report.get("probe_audit", {})
    soma_status = report.get("soma", {}).get("status")

    pass_rate = float(red.get("case_pass_rate_pct", 0.0) or 0.0)
    positive_rate = float(red.get("positive_detection_rate_pct", 0.0) or 0.0)
    benign_fp = float(red.get("benign_false_positive_rate_pct", 100.0) or 100.0)
    reality_avg = float(red.get("reality_level_avg", 0.0) or 0.0)
    probe_proof = float(cov.get("probe_proof_pct", 0.0) or 0.0)
    broken = int(aud.get("broken", 0) or 0)
    error = int(aud.get("error", 0) or 0)

    dimensions = {
        "detection_efficacy": pass_rate,
        "positive_detection": positive_rate,
        "false_positive_control": max(0.0, 100.0 - benign_fp),
        "scenario_reality": reality_avg,
        "probe_proof": probe_proof,
        "contract_health": 100.0 if (broken == 0 and error == 0) else 0.0,
        "ml_training_status": 100.0 if soma_status == "completed" else 0.0,
    }

    tier = "Foundational"
    if (
        pass_rate >= 90.0
        and positive_rate >= 90.0
        and benign_fp <= 10.0
        and probe_proof >= 70.0
        and broken == 0
        and error == 0
    ):
        tier = "Operational"

    if (
        pass_rate >= 95.0
        and positive_rate >= 95.0
        and benign_fp <= 5.0
        and probe_proof >= 80.0
        and reality_avg >= 2.5
        and soma_status == "completed"
        and broken == 0
        and error == 0
    ):
        tier = "Advanced"

    if (
        pass_rate >= 98.0
        and positive_rate >= 98.0
        and benign_fp <= 2.0
        and probe_proof >= 90.0
        and reality_avg >= 2.8
        and soma_status == "completed"
        and broken == 0
        and error == 0
    ):
        tier = "Leader-ready"

    return {
        "tier": tier,
        "dimensions": dimensions,
        "rubric_note": (
            "Internal rubric aligned to common SOC dimensions: efficacy, false-positive "
            "control, ATT&CK simulation coverage, contract health, and ML readiness."
        ),
    }


def evaluate_gates(
    report: Dict[str, Any],
    min_redteam_pass: float,
    min_positive_detection: float,
    max_benign_fp: float,
    min_probe_proof: float,
) -> Dict[str, Any]:
    red = report.get("redteam", {}).get("summary", {})
    cov = report.get("coverage", {}).get("scores", {})

    checks = {
        "redteam_pass_rate": {
            "actual": float(red.get("case_pass_rate_pct", 0.0) or 0.0),
            "target": min_redteam_pass,
            "pass": float(red.get("case_pass_rate_pct", 0.0) or 0.0)
            >= min_redteam_pass,
        },
        "positive_detection_rate": {
            "actual": float(red.get("positive_detection_rate_pct", 0.0) or 0.0),
            "target": min_positive_detection,
            "pass": float(red.get("positive_detection_rate_pct", 0.0) or 0.0)
            >= min_positive_detection,
        },
        "benign_false_positive_rate": {
            "actual": float(red.get("benign_false_positive_rate_pct", 100.0) or 100.0),
            "target": max_benign_fp,
            "pass": float(red.get("benign_false_positive_rate_pct", 100.0) or 100.0)
            <= max_benign_fp,
        },
        "probe_proof_rate": {
            "actual": float(cov.get("probe_proof_pct", 0.0) or 0.0),
            "target": min_probe_proof,
            "pass": float(cov.get("probe_proof_pct", 0.0) or 0.0) >= min_probe_proof,
        },
    }

    return {
        "all_passed": all(v["pass"] for v in checks.values()),
        "checks": checks,
    }


def write_reports(output_dir: Path, payload: Dict[str, Any]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "ops_storyline_report.json"
    md_path = output_dir / "ops_storyline_report.md"

    json_path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n")

    gates = payload.get("gates", {})
    collect = payload.get("collect", {})
    red = payload.get("redteam", {}).get("summary", {})
    cov = payload.get("coverage", {}).get("scores", {})
    aud = payload.get("probe_audit", {})
    soma = payload.get("soma", {})
    pos = payload.get("positioning", {})
    if collect.get("skip_drain"):
        drain_mode = "skip"
    elif (
        float(collect.get("drain_max_events", 0) or 0) <= 0
        and float(collect.get("drain_timeout_seconds", 0) or 0) <= 0
    ):
        drain_mode = "unbounded"
    else:
        drain_mode = "bounded"

    lines = [
        "# AMOSKYS Ops Storyline Report",
        "",
        f"- Generated at: `{payload.get('generated_at')}`",
        f"- Overall gate: `{'PASS' if gates.get('all_passed') else 'FAIL'}`",
        f"- Positioning tier: `{pos.get('tier', 'unknown')}`",
        "",
        "## Collection",
        "",
        f"- Collect success: `{collect.get('success', 'n/a')}`",
        f"- Collect elapsed seconds: `{collect.get('elapsed_seconds', 'n/a')}`",
        f"- Collect timed out: `{collect.get('timed_out', False)}`",
        f"- Queue drain mode: `{drain_mode}`",
        f"- Queue drain max events: `{collect.get('drain_max_events', 'n/a')}`",
        f"- Queue drain timeout seconds: `{collect.get('drain_timeout_seconds', 'n/a')}`",
        "",
        "## Detection Simulation",
        "",
        f"- Scenario pass rate: `{red.get('case_pass_rate_pct', 0)}%`",
        f"- Positive detection rate: `{red.get('positive_detection_rate_pct', 0)}%`",
        f"- Benign false-positive rate: `{red.get('benign_false_positive_rate_pct', 0)}%`",
        f"- Reality level average: `{red.get('reality_level_avg', 'n/a')}`",
        f"- MITRE techniques covered in scenarios: `{red.get('mitre_technique_count', 0)}`",
        "",
        "## ML Training",
        "",
        f"- SOMA status: `{soma.get('status', 'unknown')}`",
        f"- Events seen by trainer: `{soma.get('event_count', 'n/a')}`",
        f"- Train elapsed seconds: `{soma.get('elapsed_seconds', 'n/a')}`",
        "",
        "## Coverage & Contracts",
        "",
        f"- Probe proof: `{cov.get('probe_proof_pct', 0)}%`",
        f"- Surface coverage: `{cov.get('surface_coverage_pct', 0)}%`",
        f"- Probe audit broken/error: `{aud.get('broken', 0)}/{aud.get('error', 0)}`",
        "",
        "## Gate Checks",
        "",
    ]

    for name, check in gates.get("checks", {}).items():
        status = "PASS" if check.get("pass") else "FAIL"
        lines.append(
            f"- `{name}`: `{check.get('actual')}` vs target `{check.get('target')}` => `{status}`"
        )

    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("- This report measures current architecture behavior; no probe-discovery migration assumptions are used.")
    lines.append("- Use this as the release gate for simulation readiness before architectural consolidation.")
    lines.append("")

    md_path.write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run AMOSKYS ops storyline end-to-end")
    parser.add_argument("--skip-collect", action="store_true")
    parser.add_argument("--skip-train", action="store_true")
    parser.add_argument("--skip-redteam", action="store_true")
    parser.add_argument("--skip-coverage", action="store_true")
    parser.add_argument("--skip-audit", action="store_true")
    parser.add_argument("--clear-db", action="store_true")
    parser.add_argument("--agents", type=int, default=0, help="Limit collect step to first N agents")
    parser.add_argument(
        "--collect-timeout-seconds",
        type=float,
        default=900.0,
        help="Timeout budget for collect_and_store step (0 disables timeout)",
    )
    parser.add_argument(
        "--skip-drain",
        action="store_true",
        help="Skip local queue drain in collect step",
    )
    parser.add_argument(
        "--drain-max-events",
        type=int,
        default=5000,
        help="Max queue entries to drain during collect step (0=unbounded)",
    )
    parser.add_argument(
        "--drain-timeout-seconds",
        type=float,
        default=90.0,
        help="Timeout budget for queue drain in collect step (0=unbounded)",
    )
    parser.add_argument("--db", default="data/telemetry.db")
    parser.add_argument("--model-dir", default="data/intel/models")
    parser.add_argument("--output-dir", default="results/ops_storyline")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero if gates fail")
    parser.add_argument("--min-redteam-pass", type=float, default=95.0)
    parser.add_argument("--min-positive-detection", type=float, default=95.0)
    parser.add_argument("--max-benign-fp", type=float, default=5.0)
    parser.add_argument("--min-probe-proof", type=float, default=80.0)
    args = parser.parse_args()

    output_dir = PROJECT_ROOT / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    payload: Dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "steps": [],
    }

    if not args.skip_collect:
        collect_step = run_collect_step(
            clear_db=args.clear_db,
            agents=args.agents,
            skip_drain=args.skip_drain,
            drain_max_events=args.drain_max_events,
            drain_timeout_seconds=args.drain_timeout_seconds,
            collect_timeout_seconds=args.collect_timeout_seconds,
        )
        payload["steps"].append(
            {
                "name": collect_step.name,
                "success": collect_step.success,
                "elapsed_seconds": collect_step.elapsed_seconds,
            }
        )
        payload["collect"] = {
            "success": collect_step.success,
            "elapsed_seconds": collect_step.elapsed_seconds,
            "command": collect_step.details.get("command"),
            "exit_code": collect_step.details.get("exit_code"),
            "timed_out": collect_step.details.get("timed_out"),
            "timeout_seconds": collect_step.details.get("timeout_seconds"),
            "skip_drain": args.skip_drain,
            "drain_max_events": args.drain_max_events,
            "drain_timeout_seconds": args.drain_timeout_seconds,
        }
        (output_dir / "collect.stdout.log").parent.mkdir(parents=True, exist_ok=True)
        (output_dir / "collect.stdout.log").write_text(
            collect_step.details.get("stdout", "")
        )
        (output_dir / "collect.stderr.log").write_text(
            collect_step.details.get("stderr", "")
        )

    if not args.skip_train:
        train_step = run_soma_training_step(db_path=args.db, model_dir=args.model_dir)
        payload["steps"].append(
            {
                "name": train_step.name,
                "success": train_step.success,
                "elapsed_seconds": train_step.elapsed_seconds,
            }
        )
        payload["soma"] = {
            "success": train_step.success,
            "elapsed_seconds": train_step.elapsed_seconds,
            **train_step.details.get("metrics", {}),
            "status": train_step.details.get("status"),
            "note": train_step.details.get("note"),
            "error": train_step.details.get("error"),
        }

    if not args.skip_redteam:
        redteam_step = run_redteam_step()
        payload["steps"].append(
            {
                "name": redteam_step.name,
                "success": redteam_step.success,
                "elapsed_seconds": redteam_step.elapsed_seconds,
            }
        )
        payload["redteam"] = {
            "success": redteam_step.success,
            "elapsed_seconds": redteam_step.elapsed_seconds,
            "summary": redteam_step.details.get("summary", {}),
            "scenarios": redteam_step.details.get("scenarios", []),
        }

    if not args.skip_coverage:
        coverage_step = run_coverage_step()
        payload["steps"].append(
            {
                "name": coverage_step.name,
                "success": coverage_step.success,
                "elapsed_seconds": coverage_step.elapsed_seconds,
            }
        )
        payload["coverage"] = {
            "success": coverage_step.success,
            "elapsed_seconds": coverage_step.elapsed_seconds,
            "timed_out": coverage_step.details.get("timed_out"),
            **coverage_step.details.get("scorecard", {}),
        }
        (output_dir / "coverage.stderr.log").write_text(
            coverage_step.details.get("stderr", "")
        )

    if not args.skip_audit:
        audit_step = run_probe_audit_step()
        payload["steps"].append(
            {
                "name": audit_step.name,
                "success": audit_step.success,
                "elapsed_seconds": audit_step.elapsed_seconds,
            }
        )
        payload["probe_audit"] = {
            "success": audit_step.success,
            "elapsed_seconds": audit_step.elapsed_seconds,
            **audit_step.details.get("summary", {}),
            "total_rows": audit_step.details.get("total_rows"),
            "exception": audit_step.details.get("error"),
        }

    payload["positioning"] = compute_positioning(payload)
    payload["gates"] = evaluate_gates(
        payload,
        min_redteam_pass=args.min_redteam_pass,
        min_positive_detection=args.min_positive_detection,
        max_benign_fp=args.max_benign_fp,
        min_probe_proof=args.min_probe_proof,
    )

    write_reports(output_dir=output_dir, payload=payload)

    print("AMOSKYS ops storyline complete")
    print(f"Report JSON: {output_dir / 'ops_storyline_report.json'}")
    print(f"Report Markdown: {output_dir / 'ops_storyline_report.md'}")
    print(f"Overall gate: {'PASS' if payload['gates']['all_passed'] else 'FAIL'}")
    print(f"Positioning tier: {payload['positioning']['tier']}")

    if args.strict and not payload["gates"]["all_passed"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
