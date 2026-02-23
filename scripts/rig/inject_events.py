#!/usr/bin/env python3
# filepath: /Users/athanneeru/Downloads/GitHub/Amoskys/scripts/rig/inject_events.py
"""Event Injector — Feed generated events into FusionEngine and report results.

Takes events from generate_events.py and pushes them through the real
FusionEngine correlation pipeline. Reports incidents and risk snapshots.

Usage:
    # Inject a scenario and see what fires
    python scripts/rig/inject_events.py --scenario ssh_brute_force
    python scripts/rig/inject_events.py --scenario full_attack_chain --verbose

    # Inject from a JSON file (produced by generate_events.py)
    python scripts/rig/inject_events.py --file events.json

    # Run all scenarios and report pass/fail
    python scripts/rig/inject_events.py --all
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import List

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from amoskys.intel.fusion_engine import FusionEngine
from amoskys.intel.models import Incident, TelemetryEventView

# Import the event generator
sys.path.insert(0, str(Path(__file__).parent))
from generate_events import SCENARIOS, EventGenerator, _event_to_dict


def inject_events(
    fusion: FusionEngine,
    events: List[TelemetryEventView],
    verbose: bool = False,
) -> List[Incident]:
    """Inject events into FusionEngine and evaluate.

    Args:
        fusion: FusionEngine instance
        events: Events to inject
        verbose: Print each event as it's injected

    Returns:
        List of incidents produced
    """
    for ev in events:
        if verbose:
            print(
                f"  → {ev.event_id} | {ev.event_type:10s} | {ev.severity:8s} | "
                f"{ev.attributes.get('probe', 'unknown')}"
            )
        fusion.add_event(ev)

    # Evaluate all devices
    all_incidents: List[Incident] = []
    for device_id in list(fusion.device_state.keys()):
        incidents, _risk_snapshot = fusion.evaluate_device(device_id)
        all_incidents.extend(incidents)

    return all_incidents


def run_scenario(
    scenario_name: str,
    device_id: str = "inject-host-001",
    verbose: bool = False,
    db_dir: str = "/tmp/amoskys_inject",
) -> dict:
    """Run a single scenario through FusionEngine.

    Returns:
        Dict with scenario name, events injected, incidents found, pass/fail
    """
    import tempfile

    gen = EventGenerator(device_id=device_id)
    scenario = SCENARIOS[scenario_name]
    events = scenario["fn"](gen)
    expected = scenario["expected_incidents"]

    # Fresh fusion engine per scenario
    db_path = f"{db_dir}/{scenario_name}_fusion.db"
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    fusion = FusionEngine(db_path=db_path, window_minutes=30)

    if verbose:
        print(f"\n{'─' * 60}")
        print(f"Scenario: {scenario_name}")
        print(f"  {scenario['desc']}")
        print(f"  Events: {len(events)}, Expected incidents: {expected}")
        print(f"{'─' * 60}")

    incidents = inject_events(fusion, events, verbose=verbose)

    passed = len(incidents) == expected
    status = "✅ PASS" if passed else "❌ FAIL"

    result = {
        "scenario": scenario_name,
        "events_injected": len(events),
        "incidents_found": len(incidents),
        "expected_incidents": expected,
        "passed": passed,
        "status": status,
        "incident_details": [],
    }

    for inc in incidents:
        detail = {
            "incident_id": inc.incident_id,
            "severity": inc.severity.value,
            "rule_name": inc.rule_name,
            "techniques": inc.techniques,
            "event_count": len(inc.event_ids),
            "summary": inc.summary[:120] if inc.summary else "",
        }
        result["incident_details"].append(detail)

    if verbose:
        print(f"\n  {status} — {len(incidents)} incident(s) (expected {expected})")
        for detail in result["incident_details"]:
            print(
                f"    • [{detail['severity']}] {detail['rule_name']}: "
                f"{detail['summary']}"
            )
            if detail["techniques"]:
                print(f"      MITRE: {', '.join(detail['techniques'])}")

    # Cleanup
    fusion.db.close()

    return result


def main():
    parser = argparse.ArgumentParser(description="AMOSKYS Event Injector")
    parser.add_argument("--scenario", type=str, help="Scenario to inject")
    parser.add_argument("--all", action="store_true", help="Run all scenarios")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--device-id", type=str, default="inject-host-001")
    parser.add_argument("--output", type=str, default="-", help="JSON results file")
    args = parser.parse_args()

    if args.all:
        results = []
        pass_count = 0
        fail_count = 0

        print("╔════════════════════════════════════════════════════════╗")
        print("║       AMOSKYS Scenario Injection — All Scenarios      ║")
        print("╚════════════════════════════════════════════════════════╝")
        print()

        for name in SCENARIOS:
            r = run_scenario(name, device_id=args.device_id, verbose=args.verbose)
            results.append(r)
            if r["passed"]:
                pass_count += 1
            else:
                fail_count += 1

            if not args.verbose:
                print(
                    f"  {r['status']}  {name:35s}  "
                    f"events={r['events_injected']:2d}  "
                    f"incidents={r['incidents_found']}/{r['expected_incidents']}"
                )

        print()
        print(f"{'═' * 58}")
        print(
            f"  Results: {pass_count} passed, {fail_count} failed "
            f"(of {len(SCENARIOS)} scenarios)"
        )
        print(f"{'═' * 58}")

        if args.output != "-":
            with open(args.output, "w") as f:
                json.dump(results, f, indent=2, default=str)
            print(f"\nResults saved to {args.output}")

        sys.exit(0 if fail_count == 0 else 1)

    elif args.scenario:
        if args.scenario not in SCENARIOS:
            parser.error(f"Unknown scenario: {args.scenario}")
        result = run_scenario(args.scenario, device_id=args.device_id, verbose=True)
        if args.output != "-":
            with open(args.output, "w") as f:
                json.dump(result, f, indent=2, default=str)
        sys.exit(0 if result["passed"] else 1)

    else:
        parser.error("Specify --scenario <name> or --all")


if __name__ == "__main__":
    main()
