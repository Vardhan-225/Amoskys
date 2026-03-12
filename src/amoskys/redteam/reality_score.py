"""Reality scoring (0-3) for AMOSKYS red-team adversarial cases.

Each case is scored on four levels:
  L0 SCHEMA     — required fields present and correctly typed
  L1 INVARIANTS — field values are semantically plausible
  L2 NOISE      — scenario contains both benign AND evasion cases (scenario-level)
  L3 COHERENT   — fired events carry correlation_group:* tags (or 0 events for non-positives)

Usage::

    from amoskys.redteam.reality_score import score_scenario
    from amoskys.redteam.harness import RedTeamHarness
    from amoskys.redteam.scenarios import SCENARIO_REGISTRY, _load_all
    _load_all()
    s = SCENARIO_REGISTRY["spine_privilege_escalation"]
    h = RedTeamHarness()
    r = h.run_scenario(s)
    for cs in score_scenario(s, r):
        print(cs.case_id, cs.level, cs.notes)
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from amoskys.agents.os.linux.kernel_audit.agent_types import KernelAuditEvent
from amoskys.agents.os.macos.auth.probes import AuthEvent
from amoskys.redteam.harness import (
    AdversarialCase,
    CaseResult,
    Scenario,
    ScenarioResult,
)

# Earliest plausible timestamp (2023-01-01T00:00:00Z in nanoseconds)
_T0_NS: int = int(1_672_531_200 * 1e9)


# ─── Result dataclass ─────────────────────────────────────────────────────────


@dataclass
class CaseRealityScore:
    """Reality score for a single AdversarialCase.

    Attributes:
        case_id:        AdversarialCase.id
        level:          Highest fully-satisfied level (0-3); 0 means L0 failed.
        schema_ok:      L0 — required fields present and typed correctly.
        invariants_ok:  L1 — field values are semantically plausible.
        noise_present:  L2 — scenario has ≥1 benign AND ≥1 evasion case.
        story_coherent: L3 — fired events carry correlation_group:* tag.
        notes:          Human-readable gaps found at each level.
    """

    case_id: str
    level: int
    schema_ok: bool
    invariants_ok: bool
    noise_present: bool
    story_coherent: bool
    notes: List[str] = field(default_factory=list)


# ─── L0: Schema ───────────────────────────────────────────────────────────────


def _check_schema_kernel(ke: KernelAuditEvent) -> List[str]:
    """Return schema gap notes for a KernelAuditEvent."""
    gaps: List[str] = []
    if ke.timestamp_ns is None:
        gaps.append("KernelAuditEvent.timestamp_ns is None")
    if not ke.event_id:
        gaps.append("KernelAuditEvent.event_id is empty")
    if not ke.host:
        gaps.append("KernelAuditEvent.host is empty")
    if ke.pid is None or ke.pid < 1:
        gaps.append(f"KernelAuditEvent.pid={ke.pid!r} (must be >= 1)")
    return gaps


def _check_schema_auth(ae: AuthEvent) -> List[str]:
    """Return schema gap notes for an AuthEvent."""
    gaps: List[str] = []
    if not getattr(ae, "timestamp_ns", None):
        gaps.append("AuthEvent.timestamp_ns is falsy/missing")
    if not ae.event_type:
        gaps.append("AuthEvent.event_type is empty")
    if not ae.username:
        gaps.append("AuthEvent.username is empty")
    return gaps


def _check_schema_psutil_mock(patch_targets: Dict[str, Any]) -> List[str]:
    """Return schema gap notes for psutil patch_targets."""
    gaps: List[str] = []
    proc_iter_key = next((k for k in patch_targets if "process_iter" in k), None)
    if proc_iter_key is None:
        return gaps  # Not a psutil case

    mock_iter = patch_targets[proc_iter_key]
    try:
        procs = list(mock_iter())
    except Exception as exc:
        gaps.append(f"psutil mock iteration failed: {exc}")
        return gaps

    for p in procs:
        info = getattr(p, "info", {})
        if "exe" not in info:
            gaps.append(f"psutil mock missing 'exe' key (pid={info.get('pid')})")
        if "pid" not in info:
            gaps.append("psutil mock missing 'pid' key")

    return gaps


def _schema_ok(case: AdversarialCase) -> tuple[bool, List[str]]:
    """Run L0 schema checks. Returns (passed, gap_notes)."""
    notes: List[str] = []

    for ev in case.events:
        if isinstance(ev, KernelAuditEvent):
            notes.extend(_check_schema_kernel(ev))
        elif isinstance(ev, AuthEvent):
            notes.extend(_check_schema_auth(ev))

    if case.patch_targets:
        notes.extend(_check_schema_psutil_mock(case.patch_targets))

    return len(notes) == 0, notes


# ─── L1: Invariants ───────────────────────────────────────────────────────────


def _invariants_ok(case: AdversarialCase) -> tuple[bool, List[str]]:
    """Run L1 semantic plausibility checks. Returns (passed, gap_notes)."""
    notes: List[str] = []

    for ev in case.events:
        if not isinstance(ev, KernelAuditEvent):
            continue

        # uid must be non-negative
        if ev.uid is not None and ev.uid < 0:
            notes.append(f"KernelAuditEvent.uid={ev.uid} is negative")

        # timestamp must be plausible (after 2023-01-01)
        if ev.timestamp_ns is not None and ev.timestamp_ns < _T0_NS:
            notes.append(
                f"KernelAuditEvent.timestamp_ns={ev.timestamp_ns} "
                f"predates 2023-01-01 (< {_T0_NS})"
            )

        # comm should roughly match exe basename (soft warning only)
        if ev.comm and ev.exe:
            exe_base = ev.exe.rsplit("/", 1)[-1]
            if exe_base and ev.comm != exe_base:
                notes.append(
                    f"comm='{ev.comm}' does not match exe basename='{exe_base}' "
                    "(soft invariant — may be intentional)"
                )

    return len(notes) == 0, notes


# ─── L2: Noise ────────────────────────────────────────────────────────────────


def _noise_present(scenario: Scenario) -> tuple[bool, List[str]]:
    """L2 — scenario has ≥1 benign AND ≥1 evasion case."""
    notes: List[str] = []
    categories = {c.category for c in scenario.cases}

    if "benign" not in categories:
        notes.append("Scenario has no 'benign' cases (FP-resistance not tested)")
    if "evasion" not in categories:
        notes.append("Scenario has no 'evasion' cases (detection gaps not documented)")

    return len(notes) == 0, notes


# ─── L3: Story coherence ──────────────────────────────────────────────────────


def _story_coherent(
    case: AdversarialCase, result: CaseResult
) -> tuple[bool, List[str]]:
    """L3 — fired events carry at least one correlation_group:* tag.

    Evasion/benign cases with 0 events pass automatically.
    """
    notes: List[str] = []

    if not result.events_fired:
        # No events expected for benign/evasion — coherence is trivially satisfied
        return True, notes

    for ev in result.events_fired:
        corr_tags = [t for t in ev.tags if t.startswith("correlation_group:")]
        if not corr_tags:
            notes.append(
                f"Event '{ev.event_type}' has no correlation_group:* tag "
                "(events not linkable by fusion engine)"
            )
            break  # One note is enough

    return len(notes) == 0, notes


# ─── Public API ───────────────────────────────────────────────────────────────


def score_case(
    case: AdversarialCase,
    result: CaseResult,
    scenario: Scenario,
) -> CaseRealityScore:
    """Score one AdversarialCase + its CaseResult against L0-L3 checks.

    Returns a :class:`CaseRealityScore` with `level` set to the highest
    fully-satisfied level (0-3).  A failure at any level stops progression.

    Args:
        case:     The AdversarialCase being scored.
        result:   The CaseResult from running the case.
        scenario: The parent Scenario (needed for L2 noise check).

    Returns:
        CaseRealityScore
    """
    all_notes: List[str] = []

    l0_ok, l0_notes = _schema_ok(case)
    all_notes.extend(f"[L0] {n}" for n in l0_notes)

    if not l0_ok:
        return CaseRealityScore(
            case_id=case.id,
            level=0,
            schema_ok=False,
            invariants_ok=False,
            noise_present=False,
            story_coherent=False,
            notes=all_notes,
        )

    l1_ok, l1_notes = _invariants_ok(case)
    all_notes.extend(f"[L1] {n}" for n in l1_notes)

    if not l1_ok:
        return CaseRealityScore(
            case_id=case.id,
            level=1,
            schema_ok=True,
            invariants_ok=False,
            noise_present=False,
            story_coherent=False,
            notes=all_notes,
        )

    l2_ok, l2_notes = _noise_present(scenario)
    all_notes.extend(f"[L2] {n}" for n in l2_notes)

    if not l2_ok:
        return CaseRealityScore(
            case_id=case.id,
            level=2,
            schema_ok=True,
            invariants_ok=True,
            noise_present=False,
            story_coherent=False,
            notes=all_notes,
        )

    l3_ok, l3_notes = _story_coherent(case, result)
    all_notes.extend(f"[L3] {n}" for n in l3_notes)

    return CaseRealityScore(
        case_id=case.id,
        level=3 if l3_ok else 2,
        schema_ok=True,
        invariants_ok=True,
        noise_present=True,
        story_coherent=l3_ok,
        notes=all_notes,
    )


def score_scenario(
    scenario: Scenario,
    result: ScenarioResult,
) -> List[CaseRealityScore]:
    """Score all cases in a scenario.

    Args:
        scenario: The Scenario definition.
        result:   ScenarioResult from running the scenario.

    Returns:
        One :class:`CaseRealityScore` per case, in case order.
    """
    cr_by_id = {cr.case.id: cr for cr in result.case_results}
    scores: List[CaseRealityScore] = []

    for case in scenario.cases:
        cr = cr_by_id.get(case.id)
        if cr is None:
            # Case not run (shouldn't happen, but be defensive)
            scores.append(
                CaseRealityScore(
                    case_id=case.id,
                    level=0,
                    schema_ok=False,
                    invariants_ok=False,
                    noise_present=False,
                    story_coherent=False,
                    notes=["[L0] Case not found in ScenarioResult"],
                )
            )
        else:
            scores.append(score_case(case, cr, scenario))

    return scores


__all__ = ["CaseRealityScore", "score_case", "score_scenario"]
