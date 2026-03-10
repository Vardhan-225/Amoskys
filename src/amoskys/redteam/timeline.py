"""Kill-chain incident timeline stitcher for AMOSKYS red-team spine scenarios.

Takes a collection of ScenarioResult objects (typically the 5 spine scenarios),
extracts events from positive caught cases, sorts by timestamp_ns, and renders
a cinematic kill-chain narrative.

Usage:
    from amoskys.redteam.timeline import IncidentTimeline
    results = {"spine_initial_access": result1, "spine_dropper_execution": result2, ...}
    tl = IncidentTimeline(results)
    print(tl.render_text())   # ANSI terminal
    data = tl.render_json()   # machine-readable dict
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from amoskys.agents.common.probes import Severity
from amoskys.redteam.harness import CaseResult, ScenarioResult

# ─── ANSI helpers ─────────────────────────────────────────────────────────────

_USE_COLOR = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


_BOLD = "1"
_DIM = "2"
_CYAN = "36;1"
_GREEN = "32;1"
_RED = "31;1"
_YELLOW = "33;1"

_SEV_COLORS: Dict[str, str] = {
    "CRITICAL": "31;1",
    "HIGH": "33;1",
    "MEDIUM": "33",
    "LOW": "32",
    "INFO": "36",
}


# ─── Core data model ─────────────────────────────────────────────────────────


@dataclass
class PhaseRecord:
    """One detected phase in the kill-chain timeline."""

    phase_num: int
    tactic: str  # First entry from scenario.mitre_tactics
    techniques: List[str]  # From scenario.mitre_techniques
    scenario_name: str  # Scenario slug
    case_id: str  # AdversarialCase.id
    event_type: str  # TelemetryEvent.event_type
    severity: Severity
    confidence: float
    timestamp_ns: int  # Absolute epoch-nanoseconds
    elapsed_s: int  # Seconds relative to timeline origin
    tags: List[str]  # correlation_group:* tags extracted from event
    data_summary: str  # Human-readable field snapshot from event.data
    why: str  # AdversarialCase.why (narrative reason)
    agent: str  # Scenario.agent


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _best_timestamp(cr: CaseResult) -> int:
    """Pick the most meaningful timestamp for a CaseResult.

    Priority:
      1. TelemetryEvent.timestamp_ns (set by kernel_audit probes)
      2. First input event's timestamp_ns (set by auth/kernel_audit input events)
      3. AdversarialCase.now_ns (always set — fallback for proc/psutil probes)
    """
    if cr.events_fired:
        ev = cr.events_fired[0]
        if ev.timestamp_ns is not None:
            return ev.timestamp_ns

    if cr.case.events:
        first = cr.case.events[0]
        ts = getattr(first, "timestamp_ns", None)
        if ts is not None:
            return ts

    return cr.case.now_ns


def _extract_data_summary(data: Dict[str, Any]) -> str:
    """Extract a short human-readable field snapshot from event.data.

    Scans a priority list of field names and returns the first 3 found.
    """
    priority_keys = [
        "exe",
        "target_comm",
        "attacker_comm",
        "source_ip",
        "username",
        "user_count",
        "target_pid",
        "locked_account_count",
        "comm",
        "pid",
        "syscall",
        "path",
    ]
    parts = []
    for key in priority_keys:
        val = data.get(key)
        if val is not None:
            parts.append(f"{key}={val}")
        if len(parts) >= 3:
            break
    return "  ".join(parts)


def _corr_tags(tags: List[str]) -> List[str]:
    """Return only correlation_group:* entries from a tag list."""
    return [t for t in tags if t.startswith("correlation_group:")]


# ─── IncidentTimeline ─────────────────────────────────────────────────────────


class IncidentTimeline:
    """Stitches multiple spine ScenarioResults into a kill-chain timeline.

    Example:
        harness = RedTeamHarness()
        results = {name: harness.run_scenario(SCENARIO_REGISTRY[name])
                   for name in spine_names}
        tl = IncidentTimeline(results)
        print(tl.render_text())
    """

    def __init__(self, results: Dict[str, ScenarioResult]) -> None:
        self._results = results

    # ── Public API ────────────────────────────────────────────────────────────

    def stitch(self) -> List[PhaseRecord]:
        """Extract caught events from positive cases and return sorted phases.

        Only includes positive cases that actually fired (event_count > 0).
        One PhaseRecord per caught positive case, sorted by timestamp_ns.
        """
        raw: List[Tuple[int, PhaseRecord]] = []

        for scenario_name, result in self._results.items():
            scenario = result.scenario

            for cr in result.case_results:
                if cr.case.category != "positive":
                    continue
                if cr.event_count == 0:
                    continue  # Attacker evaded this probe

                ev = cr.events_fired[0]
                ts_ns = _best_timestamp(cr)

                rec = PhaseRecord(
                    phase_num=0,  # assigned after sort
                    tactic=(
                        scenario.mitre_tactics[0]
                        if scenario.mitre_tactics
                        else "unknown"
                    ),
                    techniques=list(scenario.mitre_techniques),
                    scenario_name=scenario_name,
                    case_id=cr.case.id,
                    event_type=ev.event_type,
                    severity=ev.severity,
                    confidence=ev.confidence,
                    timestamp_ns=ts_ns,
                    elapsed_s=0,  # computed after sort
                    tags=_corr_tags(ev.tags),
                    data_summary=_extract_data_summary(ev.data),
                    why=cr.case.why,
                    agent=scenario.agent,
                )
                raw.append((ts_ns, rec))

        raw.sort(key=lambda x: x[0])

        if not raw:
            return []

        base_ns = raw[0][0]
        records: List[PhaseRecord] = []
        for i, (ts_ns, rec) in enumerate(raw):
            rec.phase_num = i + 1
            rec.elapsed_s = int((ts_ns - base_ns) / 1e9)
            records.append(rec)

        return records

    def render_text(self) -> str:
        """Render as ANSI-coloured terminal timeline string."""
        phases = self.stitch()
        lines: List[str] = []
        width = 80
        heavy = "═" * width
        thin = "─" * width

        # ── Header ────────────────────────────────────────────────────────────
        lines.append(_c(_BOLD, heavy))
        lines.append(_c(_BOLD, "  AMOSKYS INCIDENT TIMELINE — victim-host"))

        if phases:
            origin_ns = phases[0].timestamp_ns
            dt = datetime.fromtimestamp(origin_ns / 1e9, tz=timezone.utc)
            lines.append(
                _c(
                    _DIM,
                    f"  Origin: {dt.strftime('%Y-%m-%dT%H:%M:%SZ')}"
                    f"  •  {len(phases)} phases detected",
                )
            )
        lines.append(_c(_BOLD, heavy))
        lines.append("")

        # ── Phases ────────────────────────────────────────────────────────────
        for rec in phases:
            sev_str = rec.severity.value
            sev_color = _SEV_COLORS.get(sev_str, "0")
            tactic = rec.tactic.upper().replace("_", " ")
            tech_str = ", ".join(rec.techniques)

            lines.append(
                f"  {_c(_BOLD, f'Phase {rec.phase_num}')}"
                f"  ·  {_c(_CYAN, tactic)}"
                f"  ·  {_c(_DIM, tech_str)}"
            )
            lines.append(
                f"  [{_c(_DIM, f'+{rec.elapsed_s}s'):<12}]"
                f"  {_c(sev_color, f'{sev_str:<10}')}  "
                f"{_c(_BOLD, rec.event_type)}"
            )
            if rec.data_summary:
                lines.append(f"    {_c(_DIM, rec.data_summary)}")
            lines.append(
                f"    conf={rec.confidence:.0%}" f"  agent={_c(_CYAN, rec.agent)}"
            )
            for tag in rec.tags:
                lines.append(f"    {_c(_YELLOW, f'↳ {tag}')}")
            lines.append("")

        # ── Verdict ───────────────────────────────────────────────────────────
        lines.append(_c(_DIM, thin))
        caught, total, evasions, benigns, failures = self._aggregate_stats()

        if failures > 0:
            verdict_str = _c(_RED, f"ASSERTION FAILURES ({failures})")
        elif caught == total:
            verdict_str = _c(
                _GREEN, f"ATTACK_CAUGHT  ({caught}/{total} phases detected)"
            )
        elif caught > 0:
            verdict_str = _c(
                _YELLOW, f"PARTIAL_DETECTION  ({caught}/{total} phases detected)"
            )
        else:
            verdict_str = _c(_RED, "ATTACK_EVADES  (0 phases detected)")

        lines.append(f"  VERDICT: {verdict_str}")
        lines.append(
            _c(
                _DIM,
                f"  Evasions documented: {evasions}"
                f"  │  Benign FP-resistance: {benigns} cases"
                + (f"  │  Assertion failures: {failures}" if failures else ""),
            )
        )
        lines.append(_c(_BOLD, heavy))

        return "\n".join(lines)

    def render_json(self) -> dict:
        """Render as machine-readable dict suitable for JSON serialization."""
        phases = self.stitch()
        caught, total, evasions, benigns, failures = self._aggregate_stats()

        if failures > 0:
            verdict = "ASSERTION_FAILURES"
        elif caught == total:
            verdict = "ATTACK_CAUGHT"
        elif caught > 0:
            verdict = "PARTIAL_DETECTION"
        else:
            verdict = "ATTACK_EVADES"

        return {
            "verdict": verdict,
            "phases_detected": caught,
            "total_phases": total,
            "evasions_documented": evasions,
            "benign_cases": benigns,
            "assertion_failures": failures,
            "phases": [
                {
                    "phase_num": r.phase_num,
                    "elapsed_s": r.elapsed_s,
                    "tactic": r.tactic,
                    "techniques": r.techniques,
                    "scenario": r.scenario_name,
                    "case_id": r.case_id,
                    "event_type": r.event_type,
                    "severity": r.severity.value,
                    "confidence": r.confidence,
                    "timestamp_ns": r.timestamp_ns,
                    "tags": r.tags,
                    "data_summary": r.data_summary,
                    "agent": r.agent,
                }
                for r in phases
            ],
        }

    # ── Private ───────────────────────────────────────────────────────────────

    def _aggregate_stats(self):
        """Return (caught, total, evasions, benigns, failures)."""
        total = len(self._results)
        caught = sum(
            1
            for r in self._results.values()
            if any(
                cr.case.category == "positive" and cr.event_count > 0
                for cr in r.case_results
            )
        )
        evasions = sum(
            sum(
                1
                for cr in r.case_results
                if cr.case.category == "evasion" and cr.event_count == 0
            )
            for r in self._results.values()
        )
        benigns = sum(
            sum(1 for cr in r.case_results if cr.case.category == "benign")
            for r in self._results.values()
        )
        failures = sum(
            sum(1 for cr in r.case_results if not cr.passed)
            for r in self._results.values()
        )
        return caught, total, evasions, benigns, failures


# ─── Convenience helper ───────────────────────────────────────────────────────


def run_spine_timeline(
    spine_scenario_names: Optional[List[str]] = None,
) -> IncidentTimeline:
    """Convenience: run all spine scenarios and return IncidentTimeline.

    Args:
        spine_scenario_names: Explicit list of spine scenario names to run.
            If None, auto-detects all scenarios whose name starts with "spine_".

    Returns:
        IncidentTimeline ready to render.
    """
    from amoskys.redteam.harness import RedTeamHarness
    from amoskys.redteam.scenarios import SCENARIO_REGISTRY, _load_all

    _load_all()

    if spine_scenario_names is None:
        spine_scenario_names = sorted(
            name for name in SCENARIO_REGISTRY if name.startswith("spine_")
        )

    harness = RedTeamHarness()
    results: Dict[str, ScenarioResult] = {}
    for name in spine_scenario_names:
        if name in SCENARIO_REGISTRY:
            results[name] = harness.run_scenario(SCENARIO_REGISTRY[name])

    return IncidentTimeline(results)


__all__ = ["IncidentTimeline", "PhaseRecord", "run_spine_timeline"]
