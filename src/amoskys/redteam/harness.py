"""AMOSKYS Red-Team Harness — Core scenario runner.

Supports two probe classes:
  - Data-injection probes (kernel_audit, auth): events fed via shared_data
  - Live-system probes (proc): require psutil to be patched before scan()

For proc probes, set ``patch_targets`` on AdversarialCase:
    AdversarialCase(
        ...,
        patch_targets={
            "amoskys.agents.proc.probes.psutil.process_iter": mock_iter,
            "amoskys.agents.proc.probes.PSUTIL_AVAILABLE": True,
        }
    )
The harness applies each patch as a ``unittest.mock.patch`` context manager
around probe.scan(), then restores the original after.


The harness executes adversarial scenarios against probes and returns
structured results. It does NOT do I/O — the CLI and report builder
handle output.

Design principles:
  - Each AdversarialCase is a single attacker action: CAUGHT | EVADES | BENIGN
  - A Scenario groups related cases with a narrative arc
  - The harness instantiates a fresh probe per case (no state leakage)
  - Stateful tests (burst) share a single probe instance when declared stateful
  - incident_key collapses related events to one incident identity

Incident Identity Primitive:
  incident_key = sha256(technique + ":" + principal + ":" + window + ":" + target)[:16]
  This means 14 events fired at the same technique/principal/target collapse
  to 1 incident with 14 evidence items — not 14 separate alerts.
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import unittest.mock
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from amoskys.agents.common.probes import MicroProbe, ProbeContext, Severity, TelemetryEvent

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Data classes
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class AdversarialCase:
    """One adversarial test case: a single attacker action against a probe.

    Attributes:
        id: Unique slug (e.g., "shell_wrap_security")
        title: Short human-readable title
        category: "positive" | "evasion" | "benign"
        description: What the attacker is doing
        why: Why the probe behaves this way (educational)
        events: Raw events to inject into ProbeContext.shared_data
        shared_data_key: Key under which events are stored (default "kernel_events")
        now_ns: Simulated timestamp in nanoseconds
        expect_count: Expected number of TelemetryEvents fired (None = skip check)
        expect_event_types: Expected event_type values (order-independent)
        expect_severity: Expected severity for the first non-degraded event
        expect_evades: Shorthand for expect_count == 0
        stateful: If True, share probe instance with next stateful case (for burst)
        extra_context: Additional shared_data entries beyond events
        patch_targets: Patches applied around probe.scan() for live-system probes
            (e.g. psutil-dependent proc probes). Keys are dotted import paths,
            values are the replacement objects.
            Example::

                patch_targets={
                    "amoskys.agents.proc.probes.psutil.process_iter": mock_iter,
                    "amoskys.agents.proc.probes.PSUTIL_AVAILABLE": True,
                }
    """

    id: str
    title: str
    category: str  # "positive" | "evasion" | "benign"
    description: str
    why: str
    events: List[Any]
    shared_data_key: str = "kernel_events"
    now_ns: int = int(1_700_000_000 * 1e9)
    expect_count: Optional[int] = None
    expect_event_types: List[str] = field(default_factory=list)
    expect_severity: Optional[Severity] = None
    expect_evades: bool = False
    stateful: bool = False
    extra_context: Dict[str, Any] = field(default_factory=dict)
    patch_targets: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Normalize: expect_evades → expect_count = 0
        if self.expect_evades and self.expect_count is None:
            self.expect_count = 0


@dataclass
class CaseResult:
    """Result of running one AdversarialCase.

    Attributes:
        case: The AdversarialCase that was run
        events_fired: TelemetryEvents the probe returned
        passed: Whether all assertions passed
        failure_reason: Human-readable explanation if passed=False
    """

    case: AdversarialCase
    events_fired: List[TelemetryEvent]
    passed: bool
    failure_reason: str = ""

    @property
    def event_count(self) -> int:
        return len(self.events_fired)

    @property
    def primary_event_type(self) -> Optional[str]:
        return self.events_fired[0].event_type if self.events_fired else None

    @property
    def primary_severity(self) -> Optional[Severity]:
        return self.events_fired[0].severity if self.events_fired else None


@dataclass
class Scenario:
    """A collection of adversarial cases that share a narrative arc.

    Attributes:
        probe_id: The probe being tested (e.g., "credential_dump")
        agent: The agent hosting the probe (e.g., "kernel_audit")
        name: Machine-readable slug
        title: Human-readable title
        description: Narrative description of this attack scenario
        mitre_techniques: Techniques exercised by this scenario
        mitre_tactics: Tactics exercised by this scenario
        probe_factory: Callable that returns a fresh MicroProbe instance
        cases: Ordered list of AdversarialCases
    """

    probe_id: str
    agent: str
    name: str
    title: str
    description: str
    mitre_techniques: List[str]
    mitre_tactics: List[str]
    probe_factory: Callable[[], MicroProbe]
    cases: List[AdversarialCase]


@dataclass
class ScenarioResult:
    """Aggregate result of running all cases in a Scenario.

    Attributes:
        scenario: The Scenario that was run
        case_results: Results for each case, in order
        incident_key: Stable identity for this incident (for deduplication)
    """

    scenario: Scenario
    case_results: List[CaseResult]
    incident_key: str = ""

    @property
    def total(self) -> int:
        return len(self.case_results)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.case_results if r.passed)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.case_results if not r.passed)

    @property
    def all_passed(self) -> bool:
        return self.failed == 0

    @property
    def all_events(self) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        for cr in self.case_results:
            events.extend(cr.events_fired)
        return events

    @property
    def caught_cases(self) -> List[CaseResult]:
        return [
            r for r in self.case_results if r.case.category == "positive" and r.event_count > 0
        ]

    @property
    def evading_cases(self) -> List[CaseResult]:
        return [
            r
            for r in self.case_results
            if r.case.category == "evasion" and r.event_count == 0
        ]


# ──────────────────────────────────────────────────────────────────────────────
# Incident Identity Primitive
# ──────────────────────────────────────────────────────────────────────────────


def compute_incident_key(
    techniques: List[str],
    principal: str,
    window_bucket: int,
    target: str,
) -> str:
    """Compute a stable incident identity key.

    Collapses all events with the same (technique, principal, window, target)
    into one incident. The key is a 16-char hex prefix of SHA-256.

    Args:
        techniques: MITRE technique IDs (sorted, colon-joined)
        principal: UID or username of the attacker
        window_bucket: Integer time bucket (e.g., Unix timestamp // 300)
        target: What was targeted (process name, file path, etc.)

    Returns:
        16-character hex string (collision-resistant for incident dedup)
    """
    raw = f"{':'.join(sorted(techniques))}:{principal}:{window_bucket}:{target}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def incident_key_for_events(
    events: List[TelemetryEvent],
    window_seconds: int = 300,
) -> str:
    """Derive an incident_key from a list of TelemetryEvents.

    Args:
        events: List of events to collapse into one incident
        window_seconds: Size of the time bucket for the window field

    Returns:
        16-char incident key, or "" if no events
    """
    if not events:
        return ""

    techniques = sorted(
        {t for e in events for t in e.mitre_techniques}
    )
    principals = sorted(
        {str(e.data.get("uid", "unknown")) for e in events}
    )
    principal = principals[0] if principals else "unknown"

    # Use the first event's timestamp for the window bucket
    first_ts = events[0].timestamp
    window_bucket = int(first_ts.timestamp()) // window_seconds

    targets = sorted(
        {str(e.data.get("path", e.data.get("exe", e.event_type))) for e in events}
    )
    target = targets[0] if targets else "unknown"

    return compute_incident_key(techniques, principal, window_bucket, target)


# ──────────────────────────────────────────────────────────────────────────────
# Patch helper for live-system probes
# ──────────────────────────────────────────────────────────────────────────────


@contextlib.contextmanager
def _apply_patches(patch_targets: Dict[str, Any]):
    """Context manager that applies unittest.mock patches for the duration of scan().

    Allows psutil-dependent proc probes to be tested deterministically by
    replacing live system calls with controlled mock objects.

    Args:
        patch_targets: {dotted.import.path: replacement_value} mapping.
                       Empty dict is a no-op (zero overhead).
    """
    if not patch_targets:
        yield
        return

    with contextlib.ExitStack() as stack:
        for target, value in patch_targets.items():
            stack.enter_context(unittest.mock.patch(target, value))
        yield


# ──────────────────────────────────────────────────────────────────────────────
# Red-Team Harness
# ──────────────────────────────────────────────────────────────────────────────


class RedTeamHarness:
    """Executes adversarial scenarios against probes and returns structured results.

    Usage:
        harness = RedTeamHarness()
        result = harness.run_scenario(scenario)

    The harness:
      - Creates a fresh probe for each case (or reuses for stateful burst tests)
      - Injects events via ProbeContext.shared_data
      - Validates count, event_types, and severity assertions
      - Returns ScenarioResult with per-case CaseResult and incident_key
    """

    def run_scenario(self, scenario: Scenario) -> ScenarioResult:
        """Run all cases in a scenario and return aggregated results."""
        case_results: List[CaseResult] = []
        current_stateful_probe: Optional[MicroProbe] = None

        for case in scenario.cases:
            if case.stateful:
                # Reuse stateful probe (burst detection accumulates state)
                if current_stateful_probe is None:
                    current_stateful_probe = scenario.probe_factory()
                probe = current_stateful_probe
            else:
                # Fresh probe for each non-stateful case (no state leakage)
                probe = scenario.probe_factory()
                current_stateful_probe = None  # reset stateful chain

            result = self._run_case(case, probe)
            case_results.append(result)

            if result.passed:
                status = "PASS"
                detail = f"{result.event_count} events"
            else:
                status = "FAIL"
                detail = result.failure_reason

            logger.debug(
                "[%s] %s %s — %s",
                status,
                case.category.upper(),
                case.id,
                detail,
            )

        all_events = [e for r in case_results for e in r.events_fired]
        incident_key = incident_key_for_events(all_events)

        return ScenarioResult(
            scenario=scenario,
            case_results=case_results,
            incident_key=incident_key,
        )

    def _run_case(self, case: AdversarialCase, probe: MicroProbe) -> CaseResult:
        """Run a single adversarial case and validate assertions."""
        shared_data = {case.shared_data_key: case.events}
        shared_data.update(case.extra_context)

        context = ProbeContext(
            device_id="victim-host",
            agent_name=probe.name,
            now_ns=case.now_ns,
            shared_data=shared_data,
        )

        try:
            with _apply_patches(case.patch_targets):
                events = probe.scan(context)
        except Exception as exc:
            return CaseResult(
                case=case,
                events_fired=[],
                passed=False,
                failure_reason=f"probe.scan() raised exception: {exc}",
            )

        failures: List[str] = []

        # Assert count
        if case.expect_count is not None and len(events) != case.expect_count:
            failures.append(
                f"expected {case.expect_count} events, got {len(events)}"
            )

        # Assert event_types (order-independent)
        if case.expect_event_types:
            fired_types = {e.event_type for e in events}
            for et in case.expect_event_types:
                if et not in fired_types:
                    failures.append(f"expected event_type '{et}' not fired")

        # Assert severity of first event
        if case.expect_severity is not None and events:
            if events[0].severity != case.expect_severity:
                failures.append(
                    f"expected severity {case.expect_severity.value}, "
                    f"got {events[0].severity.value}"
                )

        passed = len(failures) == 0
        return CaseResult(
            case=case,
            events_fired=events,
            passed=passed,
            failure_reason="; ".join(failures) if failures else "",
        )
