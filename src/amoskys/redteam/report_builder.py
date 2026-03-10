"""AMOSKYS Red-Team Report Builder — story.json + story.md + story.html.

The attack story is an automated build artifact. Every scenario run produces:
  1. story.json — machine-readable incident evidence chain
  2. story.md   — human-readable Markdown narrative
  3. story.html — browser-viewable HTML with color-coded timeline

Each event in the story carries:
  - incident_key: stable identity across re-runs
  - vector: which detection vector fired (file_access / tool_exec / burst)
  - evidence_refs: audit event IDs that triggered this finding
  - why: narrative explanation for the SOC analyst

Usage:
    builder = ReportBuilder()
    story = builder.from_scenario_result(result)
    json_str = builder.to_json(story)
    md_str = builder.to_markdown(story)
    html_str = builder.to_html(story)
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from amoskys.redteam.harness import CaseResult, ScenarioResult

# ──────────────────────────────────────────────────────────────────────────────
# Story data model
# ──────────────────────────────────────────────────────────────────────────────

_SEVERITY_COLOR = {
    "CRITICAL": "#d32f2f",
    "HIGH": "#f57c00",
    "MEDIUM": "#fbc02d",
    "LOW": "#388e3c",
    "INFO": "#1976d2",
    "DEBUG": "#757575",
}

_CATEGORY_ICON = {
    "positive": "🎯",
    "evasion": "🔍",
    "benign": "✅",
}

_CATEGORY_LABEL = {
    "positive": "CAUGHT",
    "evasion": "EVADES",
    "benign": "BENIGN",
}


@dataclass
class IncidentEvidence:
    """One piece of evidence in the attack story.

    Attributes:
        seq: Sequence number (1-based) within the incident timeline
        timestamp: ISO-8601 timestamp
        case_id: AdversarialCase.id
        case_title: AdversarialCase.title
        category: "positive" | "evasion" | "benign"
        event_type: TelemetryEvent.event_type (or "NO_FIRE")
        severity: Severity string or "N/A"
        confidence: Detection confidence (0.0–1.0) or 0.0 if not fired
        vector: Detection vector that fired (derived from event_type prefix)
        evidence_refs: Audit event IDs from ke.event_id
        why: Narrative explanation (from AdversarialCase.why)
        passed: Whether the case assertion passed
        failure_reason: Non-empty if passed=False
        correlation_needed: True if event carries correlation_needed=True
    """

    seq: int
    timestamp: str
    case_id: str
    case_title: str
    category: str
    event_type: str
    severity: str
    confidence: float
    vector: str
    evidence_refs: List[str]
    why: str
    passed: bool
    failure_reason: str = ""
    correlation_needed: bool = False


@dataclass
class AttackStory:
    """The complete attack story for one scenario run.

    Attributes:
        scenario_name: Scenario.name
        scenario_title: Scenario.title
        probe_id: Probe being tested
        agent: Agent hosting the probe
        incident_key: Stable identity (sha256-based, 16-char hex)
        mitre_techniques: Techniques exercised
        mitre_tactics: Tactics exercised
        timeline: Ordered list of IncidentEvidence
        verdict: "ATTACK_CAUGHT" | "PARTIAL_DETECTION" | "ATTACK_EVADES"
        total_cases: Number of adversarial cases run
        passed_cases: Number of cases where assertions passed
        failed_cases: Number of cases where assertions failed
        events_total: Total TelemetryEvents fired across all cases
        generated_at: ISO-8601 timestamp
        description: Scenario.description
    """

    scenario_name: str
    scenario_title: str
    probe_id: str
    agent: str
    incident_key: str
    mitre_techniques: List[str]
    mitre_tactics: List[str]
    timeline: List[IncidentEvidence]
    verdict: str
    total_cases: int
    passed_cases: int
    failed_cases: int
    events_total: int
    generated_at: str
    description: str = ""


# ──────────────────────────────────────────────────────────────────────────────
# Report Builder
# ──────────────────────────────────────────────────────────────────────────────


class ReportBuilder:
    """Converts ScenarioResult into story artifacts.

    Methods:
        from_scenario_result(result) → AttackStory
        to_json(story) → str
        to_markdown(story) → str
        to_html(story) → str
    """

    def from_scenario_result(self, result: ScenarioResult) -> AttackStory:
        """Build an AttackStory from a ScenarioResult."""
        scenario = result.scenario
        timeline: List[IncidentEvidence] = []

        for seq, cr in enumerate(result.case_results, start=1):
            case = cr.case

            if cr.events_fired:
                primary = cr.events_fired[0]
                event_type = primary.event_type
                severity = primary.severity.value
                confidence = primary.confidence
                evidence_refs = [
                    str(e.data.get("event_id", e.data.get("pid", f"ev{i}")))
                    for i, e in enumerate(cr.events_fired)
                ]
                correlation_needed = any(
                    e.data.get("correlation_needed", False) for e in cr.events_fired
                )
            else:
                event_type = "NO_FIRE"
                severity = "N/A"
                confidence = 0.0
                evidence_refs = []
                correlation_needed = False

            vector = _derive_vector(event_type)

            # Use the case's now_ns as the evidence timestamp
            ts = datetime.fromtimestamp(case.now_ns / 1e9, tz=timezone.utc)

            timeline.append(
                IncidentEvidence(
                    seq=seq,
                    timestamp=ts.isoformat(),
                    case_id=case.id,
                    case_title=case.title,
                    category=case.category,
                    event_type=event_type,
                    severity=severity,
                    confidence=confidence,
                    vector=vector,
                    evidence_refs=evidence_refs,
                    why=case.why,
                    passed=cr.passed,
                    failure_reason=cr.failure_reason,
                    correlation_needed=correlation_needed,
                )
            )

        verdict = _derive_verdict(result)
        generated_at = datetime.now(timezone.utc).isoformat()

        return AttackStory(
            scenario_name=scenario.name,
            scenario_title=scenario.title,
            probe_id=scenario.probe_id,
            agent=scenario.agent,
            incident_key=result.incident_key,
            mitre_techniques=scenario.mitre_techniques,
            mitre_tactics=scenario.mitre_tactics,
            timeline=timeline,
            verdict=verdict,
            total_cases=result.total,
            passed_cases=result.passed,
            failed_cases=result.failed,
            events_total=len(result.all_events),
            generated_at=generated_at,
            description=scenario.description,
        )

    def to_json(self, story: AttackStory) -> str:
        """Serialize the story to JSON (pretty-printed)."""
        return json.dumps(asdict(story), indent=2, default=str)

    def to_markdown(self, story: AttackStory) -> str:
        """Render the story as a Markdown narrative."""
        lines: List[str] = []

        # Header
        lines.append(f"# {story.scenario_title}")
        lines.append("")
        lines.append(f"**Probe:** `{story.probe_id}` · **Agent:** `{story.agent}`")
        lines.append(
            f"**MITRE:** {', '.join(f'`{t}`' for t in story.mitre_techniques)}"
        )
        lines.append(f"**Incident Key:** `{story.incident_key}`")
        lines.append(f"**Verdict:** **{story.verdict}**")
        lines.append(
            f"**Cases:** {story.passed_cases}/{story.total_cases} passed"
            f" · {story.events_total} events fired"
        )
        lines.append(f"*Generated: {story.generated_at}*")
        lines.append("")

        if story.description:
            lines.append("## Scenario")
            lines.append(story.description)
            lines.append("")

        # Timeline
        lines.append("## Attack Timeline")
        lines.append("")

        for ev in story.timeline:
            icon = _CATEGORY_ICON.get(ev.category, "?")
            label = _CATEGORY_LABEL.get(ev.category, ev.category.upper())
            sev_badge = f"**[{ev.severity}]**" if ev.severity != "N/A" else "[N/A]"
            status = "✓ PASS" if ev.passed else "✗ FAIL"

            lines.append(f"### {ev.seq}. {icon} {label}: {ev.case_title}")
            lines.append("")
            lines.append(f"| Field | Value |")
            lines.append(f"|-------|-------|")
            lines.append(f"| Timestamp | `{ev.timestamp}` |")
            lines.append(f"| Detection | `{ev.event_type}` |")
            lines.append(f"| Severity | {sev_badge} |")
            lines.append(
                f"| Confidence | {ev.confidence:.0%}"
                if ev.confidence > 0
                else "| Confidence | — |"
            )
            lines.append(f"| Vector | `{ev.vector}` |")
            lines.append(f"| Assertion | {status} |")

            if ev.correlation_needed:
                lines.append(
                    "| Note | ⚠️ `correlation_needed=True` — "
                    "fusion engine required to confirm |"
                )

            if ev.evidence_refs:
                lines.append(f"| Evidence Refs | `{', '.join(ev.evidence_refs)}` |")
            lines.append("")

            lines.append(f"> **Why:** {ev.why}")
            lines.append("")

            if not ev.passed and ev.failure_reason:
                lines.append(f"> ⚠️ **Assertion failure:** {ev.failure_reason}")
                lines.append("")

        # Summary table
        lines.append("## Summary")
        lines.append("")
        lines.append("| Category | Count |")
        lines.append("|----------|-------|")

        caught = sum(
            1
            for ev in story.timeline
            if ev.category == "positive" and ev.event_type != "NO_FIRE"
        )
        evades = sum(
            1
            for ev in story.timeline
            if ev.category == "evasion" and ev.event_type == "NO_FIRE"
        )
        benign_fp = sum(
            1
            for ev in story.timeline
            if ev.category == "benign" and ev.event_type != "NO_FIRE"
        )
        lines.append(f"| Attacks caught | {caught} |")
        lines.append(f"| Evasions (known blind spots) | {evades} |")
        lines.append(f"| False positives | {benign_fp} |")
        lines.append(f"| Assertion failures | {story.failed_cases} |")
        lines.append("")

        return "\n".join(lines)

    def to_html(self, story: AttackStory) -> str:
        """Render the story as HTML with color-coded severity timeline."""
        items_html = ""
        for ev in story.timeline:
            color = _SEVERITY_COLOR.get(ev.severity, "#9e9e9e")
            label = _CATEGORY_LABEL.get(ev.category, ev.category.upper())
            icon = _CATEGORY_ICON.get(ev.category, "")
            status_cls = "pass" if ev.passed else "fail"
            status_label = "✓ PASS" if ev.passed else "✗ FAIL"

            corr_badge = (
                '<span class="corr-badge">⚠ correlation needed</span>'
                if ev.correlation_needed
                else ""
            )

            items_html += f"""
        <div class="timeline-item category-{ev.category}">
          <div class="severity-badge" style="background:{color}">{ev.severity}</div>
          <div class="item-content">
            <div class="item-header">
              <span class="seq">{ev.seq}</span>
              <span class="category-label">{icon} {label}</span>
              <span class="item-title">{_html_escape(ev.case_title)}</span>
              <span class="status {status_cls}">{status_label}</span>
              {corr_badge}
            </div>
            <div class="item-detail">
              <code>{_html_escape(ev.event_type)}</code>
              {'&nbsp;· conf: ' + f'{ev.confidence:.0%}' if ev.confidence > 0 else ''}
              &nbsp;· vector: <code>{_html_escape(ev.vector)}</code>
            </div>
            <div class="item-why">{_html_escape(ev.why)}</div>
            {"<div class='item-failure'>⚠ " + _html_escape(ev.failure_reason) + "</div>" if not ev.passed and ev.failure_reason else ""}
          </div>
        </div>"""

        verdict_color = {
            "ATTACK_CAUGHT": "#2e7d32",
            "PARTIAL_DETECTION": "#f57f17",
            "ATTACK_EVADES": "#c62828",
        }.get(story.verdict, "#37474f")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AMOSKYS Red-Team: {_html_escape(story.scenario_title)}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           background: #0d1117; color: #e6edf3; line-height: 1.6; padding: 2rem; }}
    h1 {{ font-size: 1.8rem; margin-bottom: 0.5rem; }}
    .meta {{ color: #8b949e; margin-bottom: 1.5rem; font-size: 0.9rem; }}
    .verdict {{ display: inline-block; padding: 0.4rem 1rem;
                border-radius: 20px; font-weight: 700; font-size: 1.1rem;
                background: {verdict_color}; margin-bottom: 2rem; }}
    .stats {{ display: flex; gap: 1.5rem; margin-bottom: 2rem; flex-wrap: wrap; }}
    .stat {{ background: #161b22; border: 1px solid #30363d;
             border-radius: 8px; padding: 0.75rem 1.25rem; }}
    .stat-num {{ font-size: 1.6rem; font-weight: 700; }}
    .stat-label {{ font-size: 0.8rem; color: #8b949e; }}
    h2 {{ font-size: 1.2rem; margin: 2rem 0 1rem; color: #c9d1d9;
          border-bottom: 1px solid #21262d; padding-bottom: 0.5rem; }}
    .timeline-item {{ display: flex; gap: 1rem; margin-bottom: 1rem;
                      background: #161b22; border: 1px solid #30363d;
                      border-radius: 8px; overflow: hidden; }}
    .severity-badge {{ width: 80px; min-width: 80px; display: flex;
                       align-items: center; justify-content: center;
                       font-weight: 700; font-size: 0.75rem;
                       writing-mode: vertical-rl; text-orientation: mixed;
                       padding: 0.5rem; color: white; }}
    .item-content {{ flex: 1; padding: 0.75rem; }}
    .item-header {{ display: flex; align-items: center; gap: 0.75rem;
                    flex-wrap: wrap; margin-bottom: 0.4rem; }}
    .seq {{ background: #21262d; border-radius: 50%; width: 24px; height: 24px;
            display: flex; align-items: center; justify-content: center;
            font-size: 0.75rem; font-weight: 700; flex-shrink: 0; }}
    .category-label {{ font-size: 0.75rem; font-weight: 600;
                       padding: 0.1rem 0.5rem; border-radius: 10px; }}
    .category-positive .category-label {{ background: #1f2a1f; color: #56d364; }}
    .category-evasion .category-label {{ background: #2a1f1f; color: #f78166; }}
    .category-benign .category-label {{ background: #1f222a; color: #79c0ff; }}
    .item-title {{ font-weight: 600; color: #c9d1d9; }}
    .status {{ font-size: 0.8rem; margin-left: auto; }}
    .status.pass {{ color: #56d364; }}
    .status.fail {{ color: #f78166; }}
    .corr-badge {{ font-size: 0.75rem; background: #2a2200; color: #e3b341;
                   padding: 0.1rem 0.5rem; border-radius: 10px; }}
    .item-detail {{ font-size: 0.85rem; color: #8b949e; margin-bottom: 0.4rem; }}
    .item-detail code {{ background: #21262d; padding: 0.1rem 0.3rem;
                         border-radius: 4px; font-size: 0.8rem; color: #c9d1d9; }}
    .item-why {{ font-size: 0.85rem; color: #8b949e; font-style: italic; }}
    .item-failure {{ font-size: 0.85rem; color: #f78166; margin-top: 0.3rem; }}
    .description {{ background: #161b22; border: 1px solid #30363d;
                    border-radius: 8px; padding: 1rem; margin-bottom: 1.5rem;
                    color: #8b949e; font-size: 0.9rem; }}
    .incident-key {{ font-family: monospace; background: #21262d;
                     padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.85rem; }}
    footer {{ margin-top: 3rem; color: #484f58; font-size: 0.8rem; text-align: center; }}
  </style>
</head>
<body>
  <h1>{_html_escape(story.scenario_title)}</h1>
  <div class="meta">
    Probe: <strong>{_html_escape(story.probe_id)}</strong> &middot;
    Agent: <strong>{_html_escape(story.agent)}</strong> &middot;
    MITRE: <strong>{', '.join(story.mitre_techniques)}</strong> &middot;
    Incident Key: <span class="incident-key">{story.incident_key}</span>
  </div>
  <div class="verdict">{story.verdict}</div>
  <div class="stats">
    <div class="stat">
      <div class="stat-num">{story.passed_cases}/{story.total_cases}</div>
      <div class="stat-label">assertions passed</div>
    </div>
    <div class="stat">
      <div class="stat-num">{story.events_total}</div>
      <div class="stat-label">events fired</div>
    </div>
    <div class="stat">
      <div class="stat-num">{story.failed_cases}</div>
      <div class="stat-label">failures</div>
    </div>
  </div>

  {f'<div class="description">{_html_escape(story.description)}</div>' if story.description else ''}

  <h2>Attack Timeline</h2>
  <div class="timeline">
    {items_html}
  </div>

  <footer>Generated {story.generated_at} &middot; AMOSKYS Red-Team Framework</footer>
</body>
</html>"""


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────


def _derive_vector(event_type: str) -> str:
    """Derive a human-readable detection vector from event_type."""
    if event_type == "NO_FIRE":
        return "—"
    if "file_access" in event_type or "plist_access" in event_type:
        return "file_access"
    if "shadow" in event_type or "passwd" in event_type:
        return "file_access"
    if "keychain_direct" in event_type:
        return "file_access"
    if "masquerade" in event_type:
        return "masquerade_detection"
    if "burst" in event_type:
        return "burst_analysis"
    if "interpreter" in event_type:
        return "interpreter_cmdline"
    if "sqlite3" in event_type:
        return "tool_exec"
    if "security" in event_type or "dscl" in event_type:
        return "tool_exec"
    return "tool_exec"


def _derive_verdict(result: ScenarioResult) -> str:
    """Derive scenario verdict from case results."""
    if result.failed > 0:
        return "ASSERTION_FAILURES"
    positive_cases = [r for r in result.case_results if r.case.category == "positive"]
    evasion_cases = [r for r in result.case_results if r.case.category == "evasion"]

    caught = sum(1 for r in positive_cases if r.event_count > 0)
    total_positive = len(positive_cases)
    evading = sum(1 for r in evasion_cases if r.event_count == 0)

    if total_positive == 0:
        return "NO_POSITIVE_CASES"
    if caught == total_positive and evading == len(evasion_cases):
        return "ATTACK_CAUGHT"
    if caught == 0:
        return "ATTACK_EVADES"
    return "PARTIAL_DETECTION"


def _html_escape(text: str) -> str:
    """Minimal HTML escaping."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
