"""AMOSKYS Red-Team CLI — amoskys-redteam.

Commands:
  run <scenario>                Execute a scenario and print results
  list                          List all registered scenarios
  show <scenario>               Show spec details for a scenario
  timeline [--scenarios s1,s2] Run spine scenarios and render kill-chain timeline
  score [scenario]              Print reality score 0-3 per case
  replay <scenario> <file>      Run scenario with captured events; print SIM vs REPLAY diff

Usage examples:
  amoskys-redteam run credential_dump
  amoskys-redteam run credential_dump --report
  amoskys-redteam run credential_dump --report --output-dir ./results/redteam
  amoskys-redteam list
  amoskys-redteam show credential_dump
  amoskys-redteam timeline
  amoskys-redteam timeline --scenarios spine_initial_access,spine_privilege_escalation
  amoskys-redteam timeline --format json --save results/redteam
  amoskys-redteam score spine_privilege_escalation
  amoskys-redteam score
  amoskys-redteam replay spine_initial_access captures/spine_initial_access.jsonl
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import List, Optional

from amoskys.redteam.harness import RedTeamHarness, ScenarioResult
from amoskys.redteam.report_builder import ReportBuilder
from amoskys.redteam.scenarios import SCENARIO_REGISTRY, _load_all

# ANSI color codes (auto-disabled if not a TTY)
_USE_COLOR = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


_GREEN = "32;1"
_RED = "31;1"
_YELLOW = "33;1"
_CYAN = "36;1"
_DIM = "2"
_BOLD = "1"


def _print_banner() -> None:
    print(_c(_BOLD, "AMOSKYS Red-Team Framework"))
    print(_c(_DIM, "─" * 50))


def _severity_color(sev: str) -> str:
    colors = {
        "CRITICAL": "31;1",
        "HIGH": "33;1",
        "MEDIUM": "33",
        "LOW": "32",
        "INFO": "36",
        "N/A": "2",
    }
    return colors.get(sev, "0")


def _print_scenario_result(result: ScenarioResult) -> None:
    """Print a human-readable scenario result to stdout."""
    scenario = result.scenario
    print()
    print(_c(_BOLD, f"Scenario: {scenario.title}"))
    print(
        f"  Probe:  {_c(_CYAN, scenario.probe_id)}"
        f"  Agent:  {_c(_CYAN, scenario.agent)}"
    )
    print(
        f"  MITRE:  {_c(_DIM, ', '.join(scenario.mitre_techniques))}"
    )
    if result.incident_key:
        print(f"  Incident Key: {_c(_DIM, result.incident_key)}")
    print(_c(_DIM, "─" * 50))

    for cr in result.case_results:
        case = cr.case

        status_icon = "✓" if cr.passed else "✗"
        status_color = _GREEN if cr.passed else _RED

        cat_icons = {"positive": "🎯", "evasion": "🔍", "benign": "✅"}
        cat_labels = {"positive": "CAUGHT", "evasion": "EVADES", "benign": "BENIGN"}
        cat_icon = cat_icons.get(case.category, "?")
        cat_label = cat_labels.get(case.category, case.category.upper())

        print(
            f"  {_c(status_color, status_icon)} "
            f"{cat_icon} {_c(_BOLD, cat_label):<10} "
            f"{case.id}"
        )
        print(f"      {_c(_DIM, case.title)}")

        if cr.events_fired:
            for ev in cr.events_fired:
                sev = ev.severity.value
                print(
                    f"      → {_c(_severity_color(sev), sev):<10} "
                    f"{ev.event_type}  "
                    f"{_c(_DIM, f'conf={ev.confidence:.0%}')}"
                )
                if ev.data.get("correlation_needed"):
                    print(
                        f"      {_c(_YELLOW, '⚠ correlation_needed=True')} "
                        "— fusion engine required"
                    )
        else:
            if case.category == "positive":
                print(f"      {_c(_RED, '(no events fired — MISSED)')}")
            else:
                print(f"      {_c(_DIM, '(no events — correct)')}")

        if not cr.passed and cr.failure_reason:
            print(f"      {_c(_RED, f'ASSERTION FAILURE: {cr.failure_reason}')}")

    print(_c(_DIM, "─" * 50))

    # Summary
    total = result.total
    passed = result.passed
    failed = result.failed
    events = len(result.all_events)

    if result.all_passed:
        verdict_str = _c(_GREEN, "ALL ASSERTIONS PASSED")
    else:
        verdict_str = _c(_RED, f"{failed} ASSERTION(S) FAILED")

    print(
        f"  {verdict_str}  "
        f"{passed}/{total} cases · {events} events fired"
    )
    print()


def _save_artifacts(
    result: ScenarioResult,
    output_dir: Path,
) -> List[Path]:
    """Save story.json, story.md, story.html to output_dir. Returns paths."""
    output_dir.mkdir(parents=True, exist_ok=True)

    builder = ReportBuilder()
    story = builder.from_scenario_result(result)

    scenario_slug = result.scenario.name
    paths: List[Path] = []

    json_path = output_dir / f"{scenario_slug}_story.json"
    json_path.write_text(builder.to_json(story), encoding="utf-8")
    paths.append(json_path)

    md_path = output_dir / f"{scenario_slug}_story.md"
    md_path.write_text(builder.to_markdown(story), encoding="utf-8")
    paths.append(md_path)

    html_path = output_dir / f"{scenario_slug}_story.html"
    html_path.write_text(builder.to_html(story), encoding="utf-8")
    paths.append(html_path)

    return paths


def cmd_run(args: argparse.Namespace) -> int:
    """Execute: amoskys-redteam run <scenario> [--report] [--output-dir DIR]."""
    _load_all()

    scenario_name = args.scenario
    if scenario_name not in SCENARIO_REGISTRY:
        available = ", ".join(sorted(SCENARIO_REGISTRY.keys())) or "(none registered)"
        print(
            f"Error: scenario '{scenario_name}' not found. "
            f"Available: {available}",
            file=sys.stderr,
        )
        return 1

    scenario = SCENARIO_REGISTRY[scenario_name]
    harness = RedTeamHarness()

    print(_c(_DIM, f"Running scenario: {scenario_name} ..."))
    result = harness.run_scenario(scenario)

    _print_scenario_result(result)

    exit_code = 0 if result.all_passed else 2

    if args.report:
        output_dir = Path(args.output_dir or "results/redteam")
        paths = _save_artifacts(result, output_dir)
        print(_c(_BOLD, "Artifacts saved:"))
        for p in paths:
            print(f"  {p}")
        print()

    return exit_code


def cmd_list(args: argparse.Namespace) -> int:
    """Execute: amoskys-redteam list."""
    _load_all()

    if not SCENARIO_REGISTRY:
        print("No scenarios registered.")
        return 0

    print(_c(_BOLD, "Registered scenarios:"))
    for name, scenario in sorted(SCENARIO_REGISTRY.items()):
        case_counts = {}
        for case in scenario.cases:
            case_counts[case.category] = case_counts.get(case.category, 0) + 1

        counts_str = "  ".join(
            f"{v} {k}" for k, v in sorted(case_counts.items())
        )
        print(
            f"  {_c(_CYAN, name):<30} "
            f"{_c(_DIM, scenario.probe_id + ' / ' + scenario.agent):<35} "
            f"{_c(_DIM, counts_str)}"
        )
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    """Execute: amoskys-redteam show <scenario>."""
    _load_all()

    scenario_name = args.scenario
    if scenario_name not in SCENARIO_REGISTRY:
        print(f"Error: scenario '{scenario_name}' not found.", file=sys.stderr)
        return 1

    scenario = SCENARIO_REGISTRY[scenario_name]

    print(_c(_BOLD, f"\nScenario: {scenario.title}"))
    print(f"  Name:    {scenario.name}")
    print(f"  Probe:   {scenario.probe_id}")
    print(f"  Agent:   {scenario.agent}")
    print(f"  MITRE:   {', '.join(scenario.mitre_techniques)}")
    print(f"  Tactics: {', '.join(scenario.mitre_tactics)}")
    print()
    print(f"  {scenario.description}")
    print()
    print(_c(_BOLD, "  Cases:"))
    for case in scenario.cases:
        cat_labels = {"positive": "CAUGHT", "evasion": "EVADES", "benign": "BENIGN"}
        label = cat_labels.get(case.category, case.category.upper())
        print(f"    [{label:<6}] {case.id}")
        print(f"             {_c(_DIM, case.title)}")
        if case.expect_event_types:
            print(
                f"             expects: {_c(_CYAN, ', '.join(case.expect_event_types))}"
                + (
                    f" at {_c(_YELLOW, case.expect_severity.value)}"
                    if case.expect_severity
                    else ""
                )
            )
    print()
    return 0


def cmd_timeline(args: argparse.Namespace) -> int:
    """Execute: amoskys-redteam timeline [--scenarios s1,s2,...] [--format text|json] [--save DIR]."""
    from amoskys.redteam.timeline import IncidentTimeline

    _load_all()

    # Resolve scenario names
    if args.scenarios:
        names = [n.strip() for n in args.scenarios.split(",") if n.strip()]
    else:
        names = sorted(n for n in SCENARIO_REGISTRY if n.startswith("spine_"))

    if not names:
        print("No spine scenarios found. Register spine_* scenarios first.", file=sys.stderr)
        return 1

    missing = [n for n in names if n not in SCENARIO_REGISTRY]
    if missing:
        print(f"Unknown scenarios: {', '.join(missing)}", file=sys.stderr)
        return 1

    print(_c(_DIM, f"Running {len(names)} scenario(s) for timeline ..."))
    harness = RedTeamHarness()
    results = {n: harness.run_scenario(SCENARIO_REGISTRY[n]) for n in names}

    tl = IncidentTimeline(results)

    fmt = getattr(args, "format", "text")
    if fmt == "json":
        import json
        output = json.dumps(tl.render_json(), indent=2)
    else:
        output = tl.render_text()

    print(output)

    if args.save:
        import json as _json
        save_dir = Path(args.save)
        save_dir.mkdir(parents=True, exist_ok=True)
        (save_dir / "timeline.txt").write_text(tl.render_text(), encoding="utf-8")
        (save_dir / "timeline.json").write_text(
            _json.dumps(tl.render_json(), indent=2), encoding="utf-8"
        )
        print(_c(_BOLD, f"Timeline saved to {save_dir}/timeline.{{txt,json}}"))

    return 0


def cmd_score(args: argparse.Namespace) -> int:
    """Execute: amoskys-redteam score [scenario_name]."""
    from amoskys.redteam.reality_score import score_scenario

    _load_all()

    scenario_name = getattr(args, "scenario_name", None)

    if scenario_name:
        if scenario_name not in SCENARIO_REGISTRY:
            print(f"Error: scenario '{scenario_name}' not found.", file=sys.stderr)
            return 1
        targets = {scenario_name: SCENARIO_REGISTRY[scenario_name]}
    else:
        targets = dict(SCENARIO_REGISTRY)

    harness = RedTeamHarness()

    for name, scenario in sorted(targets.items()):
        result = harness.run_scenario(scenario)
        scores = score_scenario(scenario, result)

        print(_c(_BOLD, f"\n{name}"))
        print(_c(_DIM, "─" * 50))

        for cs in scores:
            lvl_color = (_GREEN if cs.level == 3 else _YELLOW if cs.level >= 2 else _RED)
            print(
                f"  {_c(lvl_color, f'L{cs.level}')}"
                f"  {cs.case_id}"
            )
            for note in cs.notes:
                print(f"      {_c(_DIM, note)}")

    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    """Execute: amoskys-redteam replay <scenario_name> <capture_file>."""
    from pathlib import Path as _Path
    from amoskys.redteam.capture import ReplayHarness, TelemetryCapture

    _load_all()

    scenario_name = args.scenario
    capture_path = _Path(args.capture_file)

    if scenario_name not in SCENARIO_REGISTRY:
        print(f"Error: scenario '{scenario_name}' not found.", file=sys.stderr)
        return 1
    if not capture_path.exists():
        print(f"Error: capture file not found: {capture_path}", file=sys.stderr)
        return 1

    scenario = SCENARIO_REGISTRY[scenario_name]
    cap = TelemetryCapture()
    records = cap.read(capture_path)

    if not records:
        print(f"No records found in {capture_path}", file=sys.stderr)
        return 1

    record = records[0]
    print(_c(_DIM, f"Captured at {record.captured_at} on {record.hostname} ({record.os_name})"))
    if record.notes:
        print(_c(_DIM, f"Notes: {record.notes}"))
    print()

    rh = ReplayHarness()

    print(_c(_DIM, "Running SIM ..."))
    sim_result = rh.run_scenario(scenario)

    print(_c(_DIM, f"Running REPLAY from {capture_path.name} ..."))
    replay_result = rh.run_from_capture(scenario, record)

    print()
    print(_c(_BOLD, "SIM vs REPLAY diff:"))
    print(rh.diff(sim_result, replay_result))

    return 0


def main() -> None:
    """Entry point for amoskys-redteam CLI."""
    parser = argparse.ArgumentParser(
        prog="amoskys-redteam",
        description="AMOSKYS Red-Team Contract Framework",
    )
    parser.add_argument(
        "--log-level",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # run
    run_parser = subparsers.add_parser(
        "run", help="Execute a scenario and validate assertions"
    )
    run_parser.add_argument("scenario", help="Scenario name (use 'list' to see all)")
    run_parser.add_argument(
        "--report",
        action="store_true",
        help="Save story.json + story.md + story.html artifacts",
    )
    run_parser.add_argument(
        "--output-dir",
        default="results/redteam",
        help="Directory for artifact output (default: results/redteam)",
    )

    # list
    subparsers.add_parser("list", help="List all registered scenarios")

    # show
    show_parser = subparsers.add_parser("show", help="Show scenario details")
    show_parser.add_argument("scenario", help="Scenario name")

    # timeline
    tl_parser = subparsers.add_parser(
        "timeline", help="Run spine scenarios and render kill-chain timeline"
    )
    tl_parser.add_argument(
        "--scenarios",
        default=None,
        help="Comma-separated scenario names (default: all spine_*)",
    )
    tl_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    tl_parser.add_argument(
        "--save",
        default=None,
        metavar="DIR",
        help="Save timeline.txt and timeline.json to DIR",
    )

    # score
    score_parser = subparsers.add_parser(
        "score", help="Print reality score 0-3 per case"
    )
    score_parser.add_argument(
        "scenario_name",
        nargs="?",
        default=None,
        help="Scenario name (omit for all scenarios)",
    )

    # replay
    replay_parser = subparsers.add_parser(
        "replay", help="Run scenario with captured events and diff against SIM"
    )
    replay_parser.add_argument("scenario", help="Scenario name")
    replay_parser.add_argument("capture_file", help="Path to .jsonl capture file")

    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(levelname)s %(name)s: %(message)s",
    )

    _print_banner()

    if args.command == "run":
        sys.exit(cmd_run(args))
    elif args.command == "list":
        sys.exit(cmd_list(args))
    elif args.command == "show":
        sys.exit(cmd_show(args))
    elif args.command == "timeline":
        sys.exit(cmd_timeline(args))
    elif args.command == "score":
        sys.exit(cmd_score(args))
    elif args.command == "replay":
        sys.exit(cmd_replay(args))


if __name__ == "__main__":
    main()
