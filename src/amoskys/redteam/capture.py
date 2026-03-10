"""Telemetry capture and replay for AMOSKYS red-team scenarios.

Writes / reads JSONL files (one JSON object per line) containing serialized
events from positive spine cases.  Allows a scenario to be re-run against
real captured events instead of synthetic ones (SIM vs REAL comparison).

JSONL line schema (version 1)::

    {
        "schema": "amoskys_capture_v1",
        "agent": "auth",
        "probe_id": "ssh_password_spray",
        "shared_data_key": "auth_events",
        "events": [...],
        "captured_at": "2024-01-15T10:00:00Z",
        "os": "darwin",
        "hostname": "victim-host",
        "notes": "synthetic from spine positive cases"
    }

Scope:
    Capture/replay is supported for kernel_audit and auth scenarios.
    Proc scenarios (BinaryFromTempProbe) use psutil patch_targets which
    cannot be serialized as JSONL — they are skipped automatically.

Usage::

    from amoskys.redteam.capture import TelemetryCapture, ReplayHarness
    from amoskys.redteam.scenarios import SCENARIO_REGISTRY, _load_all

    _load_all()

    cap = TelemetryCapture()
    cap.write_spine_synthetic(output_dir=Path("captures"))

    records = cap.read(Path("captures/spine_auth.jsonl"))
    rh = ReplayHarness()
    scenario = SCENARIO_REGISTRY["spine_initial_access"]
    result = rh.run_from_capture(scenario, records[0])
    print(rh.diff(sim_result, result))
"""

from __future__ import annotations

import dataclasses
import json
import os
import platform
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from amoskys.agents.os.linux.kernel_audit.agent_types import KernelAuditEvent
from amoskys.agents.shared.auth.probes import AuthEvent
from amoskys.redteam.harness import (
    AdversarialCase,
    RedTeamHarness,
    Scenario,
    ScenarioResult,
    _apply_patches,
)

_CAPTURE_SCHEMA = "amoskys_capture_v1"


# ─── Serialization helpers ───────────────────────────────────────────────────


def _serialize_event(ev: Any) -> dict:
    """Serialize a single event to a plain dict."""
    if isinstance(ev, KernelAuditEvent):
        return ev.to_dict()
    if isinstance(ev, AuthEvent):
        return dataclasses.asdict(ev)
    # Fallback for unknown event types
    return {"_raw": str(ev)}


def _deserialize_auth(d: dict) -> AuthEvent:
    """Reconstruct an AuthEvent from a plain dict, ignoring unknown keys."""
    known = {f.name for f in dataclasses.fields(AuthEvent)}
    return AuthEvent(**{k: v for k, v in d.items() if k in known})


def _deserialize_kernel(d: dict) -> KernelAuditEvent:
    """Reconstruct a KernelAuditEvent from a plain dict, ignoring unknown keys."""
    known = {f.name for f in dataclasses.fields(KernelAuditEvent)}
    return KernelAuditEvent(**{k: v for k, v in d.items() if k in known})


# ─── CaptureRecord ───────────────────────────────────────────────────────────


@dataclass
class CaptureRecord:
    """One serialized probe capture from a JSONL file.

    Attributes:
        agent:           Agent slug (e.g. "auth", "kernel_audit").
        probe_id:        Probe name (e.g. "ssh_password_spray").
        shared_data_key: Key injected into ProbeContext.shared_data.
        events_raw:      Raw serialized event dicts.
        captured_at:     ISO-8601 capture timestamp.
        os_name:         OS platform string (e.g. "darwin").
        hostname:        Source host name.
        notes:           Free-text annotation.
    """

    agent: str
    probe_id: str
    shared_data_key: str
    events_raw: List[dict]
    captured_at: str = ""
    os_name: str = ""
    hostname: str = ""
    notes: str = ""

    def to_auth_events(self) -> List[AuthEvent]:
        """Deserialize events_raw as AuthEvent objects."""
        return [_deserialize_auth(d) for d in self.events_raw]

    def to_kernel_events(self) -> List[KernelAuditEvent]:
        """Deserialize events_raw as KernelAuditEvent objects."""
        return [_deserialize_kernel(d) for d in self.events_raw]


# ─── TelemetryCapture ────────────────────────────────────────────────────────


class TelemetryCapture:
    """Write and read JSONL capture files.

    Each line in a JSONL file is one :class:`CaptureRecord`, encoding the
    events from a single probe invocation.
    """

    def write(
        self,
        path: Path,
        agent: str,
        probe_id: str,
        shared_data_key: str,
        events: List[Any],
        notes: str = "",
    ) -> None:
        """Append one capture record as a JSONL line.

        Args:
            path:             Output .jsonl file path.
            agent:            Agent slug.
            probe_id:         Probe name.
            shared_data_key:  Key used in ProbeContext.shared_data.
            events:           Events to serialize (AuthEvent or KernelAuditEvent).
            notes:            Optional free-text annotation.
        """
        path.parent.mkdir(parents=True, exist_ok=True)

        record = {
            "schema": _CAPTURE_SCHEMA,
            "agent": agent,
            "probe_id": probe_id,
            "shared_data_key": shared_data_key,
            "events": [_serialize_event(e) for e in events],
            "captured_at": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "os": platform.system().lower(),
            "hostname": socket.gethostname(),
            "notes": notes,
        }

        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    def read(self, path: Path) -> List[CaptureRecord]:
        """Read all records from a JSONL capture file.

        Args:
            path: Path to the .jsonl file.

        Returns:
            List of :class:`CaptureRecord`, one per line.
        """
        records: List[CaptureRecord] = []

        with path.open("r", encoding="utf-8") as f:
            for lineno, raw in enumerate(f, 1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    d = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{path}:{lineno} — invalid JSON: {exc}") from exc

                records.append(
                    CaptureRecord(
                        agent=d.get("agent", ""),
                        probe_id=d.get("probe_id", ""),
                        shared_data_key=d.get("shared_data_key", "kernel_events"),
                        events_raw=d.get("events", []),
                        captured_at=d.get("captured_at", ""),
                        os_name=d.get("os", ""),
                        hostname=d.get("hostname", ""),
                        notes=d.get("notes", ""),
                    )
                )

        return records

    def write_spine_synthetic(self, output_dir: Path) -> List[Path]:
        """Dump positive-case events from all spine scenarios to JSONL files.

        Creates one file per spine scenario.  Proc scenarios (psutil-based)
        are skipped as their events cannot be serialized to JSONL.

        Args:
            output_dir: Directory where .jsonl files are written.

        Returns:
            List of paths written.
        """
        from amoskys.redteam.harness import RedTeamHarness
        from amoskys.redteam.scenarios import SCENARIO_REGISTRY, _load_all

        _load_all()
        output_dir.mkdir(parents=True, exist_ok=True)

        harness = RedTeamHarness()
        written: List[Path] = []

        spine_names = sorted(n for n in SCENARIO_REGISTRY if n.startswith("spine_"))

        for name in spine_names:
            scenario = SCENARIO_REGISTRY[name]

            # Skip proc scenarios — psutil mocks can't be JSONL-serialized
            if scenario.agent == "proc":
                continue

            result = harness.run_scenario(scenario)
            out_path = output_dir / f"{name}.jsonl"

            for cr in result.case_results:
                if cr.case.category != "positive" or cr.event_count == 0:
                    continue

                self.write(
                    path=out_path,
                    agent=scenario.agent,
                    probe_id=scenario.probe_id,
                    shared_data_key=cr.case.shared_data_key,
                    events=cr.case.events,
                    notes=f"synthetic from spine positive case: {cr.case.id}",
                )

            if out_path.exists():
                written.append(out_path)

        return written


# ─── ReplayHarness ───────────────────────────────────────────────────────────


class ReplayHarness(RedTeamHarness):
    """Run a scenario against captured events instead of synthetic ones.

    Extends :class:`RedTeamHarness` with :meth:`run_from_capture` and
    :meth:`diff` for SIM vs REAL comparison.
    """

    def run_from_capture(
        self,
        scenario: Scenario,
        record: CaptureRecord,
    ) -> ScenarioResult:
        """Run scenario with events from a CaptureRecord.

        For each case in the scenario, the captured events are injected
        instead of ``case.events``.  Assertions are evaluated exactly as
        in the standard harness run.

        Args:
            scenario: The Scenario to run.
            record:   CaptureRecord whose events replace each case's events.

        Returns:
            ScenarioResult as if the scenario ran normally.
        """
        # Deserialize events according to agent type
        if record.agent == "auth":
            captured_events = record.to_auth_events()
        else:
            captured_events = record.to_kernel_events()

        # Build a patched version of each case with captured events
        patched_cases: List[AdversarialCase] = []
        for case in scenario.cases:
            patched = dataclasses.replace(
                case,
                events=captured_events,
                shared_data_key=record.shared_data_key,
            )
            patched_cases.append(patched)

        patched_scenario = dataclasses.replace(scenario, cases=patched_cases)
        return self.run_scenario(patched_scenario)

    def diff(
        self,
        sim: ScenarioResult,
        replay: ScenarioResult,
    ) -> str:
        """Print a side-by-side SIM vs REPLAY comparison.

        Args:
            sim:    ScenarioResult from the simulation run.
            replay: ScenarioResult from the replay run.

        Returns:
            Human-readable diff string.
        """
        lines: List[str] = []
        lines.append(f"{'CASE':<40} {'SIM':^25} {'REPLAY':^25} {'MATCH'}")
        lines.append("-" * 95)

        sim_by_id = {cr.case.id: cr for cr in sim.case_results}
        replay_by_id = {cr.case.id: cr for cr in replay.case_results}

        all_ids = list(
            {cr.case.id for cr in sim.case_results}
            | {cr.case.id for cr in replay.case_results}
        )

        discrepancies = 0
        for cid in sorted(all_ids):
            sim_cr = sim_by_id.get(cid)
            rep_cr = replay_by_id.get(cid)

            sim_str = _format_cr(sim_cr)
            rep_str = _format_cr(rep_cr)

            match = "==" if sim_str == rep_str else "!="
            if match == "!=":
                discrepancies += 1

            lines.append(f"{cid:<40} {sim_str:^25} {rep_str:^25} {match}")

        lines.append("-" * 95)
        lines.append(
            f"  {discrepancies} discrepanc{'y' if discrepancies == 1 else 'ies'} "
            f"across {len(all_ids)} cases"
        )
        return "\n".join(lines)


def _format_cr(cr: Optional["CaseResult"]) -> str:  # noqa: F821
    """Short summary of a CaseResult for the diff table."""
    if cr is None:
        return "(missing)"
    if not cr.events_fired:
        return "0 events"
    types = ", ".join(sorted({e.event_type for e in cr.events_fired}))
    sev = cr.events_fired[0].severity.value
    return f"{len(cr.events_fired)}ev {sev} {types}"[:25]


__all__ = ["CaptureRecord", "TelemetryCapture", "ReplayHarness"]
