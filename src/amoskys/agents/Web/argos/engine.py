"""Argos engagement orchestrator.

An Engagement is a single authorized attack against a target domain. It
moves through phases:

    1. Consent   — verify DNS TXT ownership proof on target
    2. Recon     — enumerate subdomains, IPs, services
    3. Fingerprint — WP version, plugin list, theme list, server stack
    4. Probe     — run selected tools against fingerprinted surface
    5. Triage    — correlate findings, dedup, score
    6. Report    — emit JSON + human-readable output

Each phase writes a signed phase-complete event into the Proof Spine so
the full engagement trail is auditable end-to-end.

This v0 file is deliberately a scaffold — the tool drivers produce
stubbed output. Real tool integration lands in Phase 1.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from amoskys.agents.Web.argos.tools.base import Tool, ToolResult


class Phase(str, Enum):
    """Engagement phases. Every phase emits a phase-complete event."""

    CONSENT = "consent"
    RECON = "recon"
    FINGERPRINT = "fingerprint"
    PROBE = "probe"
    TRIAGE = "triage"
    REPORT = "report"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    """A single potentially-exploitable issue found during probing."""

    finding_id: str
    tool: str  # e.g. "nuclei", "wpscan"
    template_id: Optional[str]  # tool-specific rule that fired
    target: str  # URL or host where it was found
    severity: Severity
    title: str
    description: str
    evidence: Dict[str, Any]  # raw request/response, screenshots etc.
    cwe: Optional[str] = None
    cvss: Optional[float] = None
    references: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    detected_at_ns: int = field(default_factory=lambda: int(time.time() * 1e9))

    @classmethod
    def from_tool_result(cls, tool: str, target: str, raw: Dict[str, Any]) -> "Finding":
        """Build a Finding from a tool's structured output."""
        return cls(
            finding_id=str(uuid.uuid4()),
            tool=tool,
            template_id=raw.get("template_id") or raw.get("rule_id"),
            target=target,
            severity=Severity(raw.get("severity", "info")),
            title=raw.get("title", "(no title)"),
            description=raw.get("description", ""),
            evidence=raw.get("evidence", {}),
            cwe=raw.get("cwe"),
            cvss=raw.get("cvss"),
            references=raw.get("references", []),
            mitre_techniques=raw.get("mitre_techniques", []),
        )


@dataclass
class Scope:
    """Authorization envelope for an engagement.

    A Scope must be present for Argos to touch a target. It encodes:
      - The exact target domain(s) and IP(s) authorized
      - The time window the engagement may run in
      - The probe classes permitted (no DoS, no data destruction)
      - The DNS TXT ownership proof token
      - Rate caps and total duration
    """

    target: str  # e.g. "lab.amoskys.com"
    authorized_by: str  # operator identity (email, user id)
    txt_token: str  # DNS TXT proof token (format: amoskys-verify=<uuid>)
    window_start_ns: int
    window_end_ns: int
    max_rps: int = 5
    max_duration_s: int = 3600
    allowed_probe_classes: List[str] = field(
        default_factory=lambda: [
            # Recon (passive/external)
            "subfinder.passive",
            "nmap.portscan",
            # Fingerprint
            "httpx.fingerprint",
            "wpscan.plugins",
            "wpscan.themes",
            "wpscan.users",
            # Probe
            "nuclei.cves",
            "nuclei.misconfiguration",
            "nuclei.exposures",
            "nuclei.vulnerabilities",
        ]
    )
    # These probe classes are PERMANENTLY blacklisted — never allowed:
    DENIED_PROBE_CLASSES = frozenset(
        {
            "nuclei.dos",
            "nuclei.intrusive",
            "sqlmap.destructive",
            "*.ransomware",
            "*.destructive",
        }
    )


@dataclass
class EngagementResult:
    engagement_id: str
    scope: Scope
    started_at_ns: int
    completed_at_ns: Optional[int]
    phases_complete: List[Phase]
    findings: List[Finding]
    tool_outputs: Dict[str, ToolResult]  # tool name -> raw
    errors: List[str]

    @property
    def duration_s(self) -> float:
        if self.completed_at_ns is None:
            return (time.time() * 1e9 - self.started_at_ns) / 1e9
        return (self.completed_at_ns - self.started_at_ns) / 1e9

    @property
    def summary_counts(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def to_json(self) -> str:
        def default(obj: Any) -> Any:
            if isinstance(obj, Enum):
                return obj.value
            if hasattr(obj, "__dict__"):
                return obj.__dict__
            return str(obj)

        return json.dumps(
            {
                "engagement_id": self.engagement_id,
                "scope": asdict(self.scope),
                "started_at_ns": self.started_at_ns,
                "completed_at_ns": self.completed_at_ns,
                "duration_s": self.duration_s,
                "phases_complete": [p.value for p in self.phases_complete],
                "findings": [asdict(f) for f in self.findings],
                "summary_counts": self.summary_counts,
                "errors": self.errors,
                "tool_outputs": {
                    name: asdict(result) if hasattr(result, "__dataclass_fields__")
                    else result.__dict__ if hasattr(result, "__dict__") else str(result)
                    for name, result in self.tool_outputs.items()
                },
            },
            indent=2,
            default=default,
        )


class Engagement:
    """A single-target engagement.

    Phases run sequentially; a failure in any phase short-circuits the
    remainder but still produces a partial report.

    Proof Spine integration (stubbed in v0):
        - `emit_phase_event(phase, status, data)` will sign-and-chain
          events the way Aegis does on the defensive side.
    """

    def __init__(self, scope: Scope, tools: List[Tool], report_dir: Path) -> None:
        self.scope = scope
        self.tools = tools
        self.report_dir = report_dir
        self.engagement_id = str(uuid.uuid4())
        self.findings: List[Finding] = []
        self.tool_outputs: Dict[str, ToolResult] = {}
        self.phases_complete: List[Phase] = []
        self.errors: List[str] = []
        self._prev_sig: Optional[str] = None
        self._started_at_ns: int = 0

    # ─────────────────────────────────────────────────────────
    # Public driver
    # ─────────────────────────────────────────────────────────

    def run(self) -> EngagementResult:
        self._started_at_ns = int(time.time() * 1e9)

        try:
            self._phase_consent()
            self._phase_recon()
            self._phase_fingerprint()
            self._phase_probe()
            self._phase_triage()
            self._phase_report()
        except Exception as e:  # noqa: BLE001
            self.errors.append(f"{type(e).__name__}: {e}")

        completed = int(time.time() * 1e9)

        return EngagementResult(
            engagement_id=self.engagement_id,
            scope=self.scope,
            started_at_ns=self._started_at_ns,
            completed_at_ns=completed,
            phases_complete=self.phases_complete,
            findings=self.findings,
            tool_outputs=self.tool_outputs,
            errors=self.errors,
        )

    # ─────────────────────────────────────────────────────────
    # Phases
    # ─────────────────────────────────────────────────────────

    def _phase_consent(self) -> None:
        """Verify DNS TXT ownership proof.

        v0: always passes if txt_token is set. Real implementation does
        a DNS lookup for `amoskys-verify.<target>` TXT record and
        compares to the expected token.
        """
        if not self.scope.txt_token:
            raise PermissionError(
                "Scope has no txt_token — ownership not proven. "
                "Refusing to probe."
            )
        # TODO(v1): actually resolve and verify the DNS TXT
        self._emit_phase(Phase.CONSENT, "ok", {"target": self.scope.target})
        self.phases_complete.append(Phase.CONSENT)

    def _run_tools_of_class(self, tool_class: str) -> List[str]:
        """Run every tool of the given class, capturing outputs AND findings.

        All three phases (recon / fingerprint / probe) use this — the
        fingerprint class used to silently drop findings, which was a bug:
        wpscan classifies as "fingerprint" but produces real vulnerabilities.
        Every tool that yields findings has those findings appended.
        """
        ran: List[str] = []
        for tool in self.tools:
            if tool.tool_class != tool_class:
                continue
            if not self._tool_allowed(tool):
                continue
            result = tool.run(self.scope.target, self.scope)
            self.tool_outputs[tool.name] = result
            ran.append(tool.name)
            for f in result.findings:
                self.findings.append(
                    Finding.from_tool_result(tool.name, self.scope.target, f)
                )
        return ran

    def _phase_recon(self) -> None:
        """Enumerate the external surface: subdomains, IPs, ports, services."""
        ran = self._run_tools_of_class("recon")
        self._emit_phase(Phase.RECON, "ok", {"tools_run": ran})
        self.phases_complete.append(Phase.RECON)

    def _phase_fingerprint(self) -> None:
        """Identify the tech stack — WP version, plugins, themes, server."""
        ran = self._run_tools_of_class("fingerprint")
        self._emit_phase(Phase.FINGERPRINT, "ok", {"tools_run": ran})
        self.phases_complete.append(Phase.FINGERPRINT)

    def _phase_probe(self) -> None:
        """Run vulnerability probes against the fingerprinted target."""
        ran = self._run_tools_of_class("probe")
        self._emit_phase(Phase.PROBE, "ok", {"tools_run": ran, "findings": len(self.findings)})
        self.phases_complete.append(Phase.PROBE)

    def _phase_triage(self) -> None:
        """Dedup, re-score, and correlate findings.

        v0: simple dedup by (tool, template_id, target). v1 adds
        confidence re-weighting via AMRDR posteriors.
        """
        seen = set()
        deduped = []
        for f in self.findings:
            key = (f.tool, f.template_id, f.target)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(f)
        dropped = len(self.findings) - len(deduped)
        self.findings = deduped
        self._emit_phase(
            Phase.TRIAGE,
            "ok",
            {"kept": len(deduped), "dropped_duplicates": dropped},
        )
        self.phases_complete.append(Phase.TRIAGE)

    def _phase_report(self) -> None:
        """Write the JSON report to disk.

        Human-readable PDF rendering lives in argos.report — this phase
        just ensures the structured output is durable.
        """
        self.report_dir.mkdir(parents=True, exist_ok=True)
        path = self.report_dir / f"argos-{self.engagement_id}.json"
        # Mark REPORT complete first so it's reflected in the written report
        self.phases_complete.append(Phase.REPORT)
        result = EngagementResult(
            engagement_id=self.engagement_id,
            scope=self.scope,
            started_at_ns=self._started_at_ns,
            completed_at_ns=int(time.time() * 1e9),
            phases_complete=self.phases_complete,
            findings=self.findings,
            tool_outputs=self.tool_outputs,
            errors=self.errors,
        )
        path.write_text(result.to_json())
        self._emit_phase(Phase.REPORT, "ok", {"report_path": str(path)})

    # ─────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────

    def _tool_allowed(self, tool: Tool) -> bool:
        """Enforce scope's allowed_probe_classes + denylist."""
        if tool.probe_class in self.scope.DENIED_PROBE_CLASSES:
            self.errors.append(f"DENIED tool {tool.name} ({tool.probe_class})")
            return False
        if tool.probe_class not in self.scope.allowed_probe_classes:
            self.errors.append(
                f"Tool {tool.name} probe_class={tool.probe_class} not in scope allowlist"
            )
            return False
        return True

    def _emit_phase(self, phase: Phase, status: str, data: Dict[str, Any]) -> None:
        """Write a phase-complete event.

        v0: stubs a dict representation. v1 will ship to Proof Spine
        via the AMOSKYS event ingest endpoint.
        """
        event = {
            "engagement_id": self.engagement_id,
            "phase": phase.value,
            "status": status,
            "timestamp_ns": int(time.time() * 1e9),
            "target": self.scope.target,
            "data": data,
            "prev_sig": self._prev_sig,
        }
        event["sig"] = hashlib.sha256(
            json.dumps(event, sort_keys=True).encode()
        ).hexdigest()
        self._prev_sig = event["sig"]
        # TODO(v1): POST to Proof Spine. For v0, we just keep in-memory.
