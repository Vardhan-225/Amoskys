#!/usr/bin/env python3
"""Export red-team harness results as golden JSON fixtures.

Runs every scenario in SCENARIO_REGISTRY through the RedTeamHarness and
serialises the per-case inputs + outputs into deterministic JSON files.

Usage:
    PYTHONPATH=src:. .venv/bin/python3 scripts/export_golden_fixtures.py

Output:
    tests/fixtures/golden/<scenario_name>.json   (one per scenario)
    tests/fixtures/golden/manifest.json          (summary of all scenarios)
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, is_dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List

# ── project imports ─────────────────────────────────────────────────────
from amoskys.agents.common.probes import ProbeContext, Severity, TelemetryEvent
from amoskys.redteam.harness import (
    AdversarialCase,
    CaseResult,
    RedTeamHarness,
    Scenario,
    ScenarioResult,
)
from amoskys.redteam.scenarios import SCENARIO_REGISTRY, _load_all

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "golden"


# ── serialisation helpers ───────────────────────────────────────────────


def _serialise(obj: Any) -> Any:
    """Recursively serialise an object to JSON-safe primitives."""
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, (list, tuple)):
        return [_serialise(v) for v in obj]
    if isinstance(obj, (set, frozenset)):
        return sorted(_serialise(v) for v in obj)
    if isinstance(obj, dict):
        return {str(k): _serialise(v) for k, v in obj.items()}
    if is_dataclass(obj) and not isinstance(obj, type):
        return {k: _serialise(v) for k, v in asdict(obj).items()}
    # Fallback: repr
    return repr(obj)


def _serialise_event(ev: TelemetryEvent) -> Dict[str, Any]:
    """Serialise a TelemetryEvent to a flat dict."""
    return {
        "event_type": ev.event_type,
        "severity": ev.severity.value,
        "probe_name": ev.probe_name,
        "confidence": ev.confidence,
        "mitre_techniques": ev.mitre_techniques,
        "mitre_tactics": ev.mitre_tactics,
        "tags": ev.tags,
        "data_keys": sorted(ev.data.keys()),
    }


def _serialise_case(
    case: AdversarialCase,
    cr: CaseResult,
) -> Dict[str, Any]:
    """Serialise one case + its result into a fixture dict."""
    return {
        "id": case.id,
        "title": case.title,
        "category": case.category,
        "stateful": case.stateful,
        "shared_data_key": case.shared_data_key,
        "input_event_count": len(case.events),
        # ── expectations (from the case definition) ──
        "expect": {
            "count": case.expect_count,
            "event_types": sorted(case.expect_event_types),
            "severity": case.expect_severity.value if case.expect_severity else None,
            "evades": case.expect_evades,
        },
        # ── actual outputs (golden snapshot) ──
        "golden": {
            "passed": cr.passed,
            "event_count": cr.event_count,
            "events": [_serialise_event(e) for e in cr.events_fired],
        },
    }


def _serialise_scenario(
    scenario: Scenario,
    result: ScenarioResult,
) -> Dict[str, Any]:
    """Serialise one scenario + its results into a fixture dict."""
    cases = []
    for case, cr in zip(scenario.cases, result.case_results):
        cases.append(_serialise_case(case, cr))

    return {
        "name": scenario.name,
        "title": scenario.title,
        "probe_id": scenario.probe_id,
        "agent": scenario.agent,
        "mitre_techniques": sorted(scenario.mitre_techniques),
        "mitre_tactics": sorted(scenario.mitre_tactics),
        "total": result.total,
        "passed": result.passed,
        "failed": result.failed,
        "cases": cases,
    }


# ── main ────────────────────────────────────────────────────────────────


def main() -> int:
    _load_all()
    harness = RedTeamHarness()

    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)

    manifest: List[Dict[str, Any]] = []
    total_cases = 0
    total_passed = 0

    for name, scenario in sorted(SCENARIO_REGISTRY.items()):
        result = harness.run_scenario(scenario)
        fixture = _serialise_scenario(scenario, result)

        # Write per-scenario fixture
        out_path = FIXTURES_DIR / f"{name}.json"
        out_path.write_text(json.dumps(fixture, indent=2, sort_keys=False) + "\n")

        manifest.append(
            {
                "name": name,
                "file": f"{name}.json",
                "total": result.total,
                "passed": result.passed,
                "failed": result.failed,
                "mitre_techniques": sorted(scenario.mitre_techniques),
            }
        )
        total_cases += result.total
        total_passed += result.passed
        status = "PASS" if result.all_passed else "FAIL"
        print(f"  [{status}] {name}: {result.passed}/{result.total}")

    # Write manifest
    manifest_data = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_scenarios": len(manifest),
        "total_cases": total_cases,
        "total_passed": total_passed,
        "scenarios": manifest,
    }
    (FIXTURES_DIR / "manifest.json").write_text(
        json.dumps(manifest_data, indent=2, sort_keys=False) + "\n"
    )

    print(f"\n{total_passed}/{total_cases} cases across {len(manifest)} scenarios")
    print(f"Fixtures written to {FIXTURES_DIR}/")

    return 0 if total_passed == total_cases else 1


if __name__ == "__main__":
    sys.exit(main())
