"""Argos report renderer — HTML + PDF.

Turns an EngagementResult into a professionally-formatted deliverable
that the customer actually wants to receive. This is the output side of
the Redemption Agent sales motion: free pentest report, branded, clean,
showing the customer exactly what a real attacker would see.

Outputs:
  <engagement_id>.html    — self-contained HTML (fonts + CSS inlined)
  <engagement_id>.pdf     — WeasyPrint-rendered PDF (print-ready)

Philosophy:
  - The report is the product. If it looks sloppy, we lose the customer.
  - Every claim is backed by evidence (curl command, matched endpoint).
  - Severity bucketing is explicit; no hand-wavy assessments.
  - The LAST section is always the CTA: subscribe to AMOSKYS Web.

Usage:
    from amoskys.agents.Web.argos.report import ReportRenderer
    renderer = ReportRenderer()
    html = renderer.render_html(engagement_result, customer_info={...})
    pdf_bytes = renderer.render_pdf(engagement_result, customer_info={...})
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, TYPE_CHECKING

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    JINJA_AVAILABLE = True
except ImportError:
    JINJA_AVAILABLE = False

try:
    from weasyprint import HTML
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False

if TYPE_CHECKING:
    from amoskys.agents.Web.argos.engine import EngagementResult


TEMPLATE_DIR = Path(__file__).parent / "templates"


class ReportRenderer:
    """Render an engagement result as HTML and/or PDF."""

    def __init__(self, template_dir: Optional[Path] = None) -> None:
        if not JINJA_AVAILABLE:
            raise RuntimeError(
                "jinja2 not installed. pip install jinja2 weasyprint"
            )
        self.template_dir = template_dir or TEMPLATE_DIR
        self.env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        # Custom filters used by the template
        self.env.filters["severity_badge"] = _severity_badge
        self.env.filters["cvss_color"] = _cvss_color

    def render_html(
        self,
        result: "EngagementResult",
        customer_info: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Render an engagement result as a standalone HTML string."""
        template = self.env.get_template("pentest_report.html.j2")
        context = self._build_context(result, customer_info or {})
        return template.render(**context)

    def render_pdf(
        self,
        result: "EngagementResult",
        customer_info: Optional[Dict[str, Any]] = None,
    ) -> bytes:
        """Render an engagement result as a PDF (bytes)."""
        if not WEASYPRINT_AVAILABLE:
            raise RuntimeError(
                "weasyprint not installed. pip install weasyprint"
            )
        html_str = self.render_html(result, customer_info)
        return HTML(string=html_str, base_url=str(self.template_dir)).write_pdf()

    def _build_context(
        self,
        result: "EngagementResult",
        customer_info: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Pre-compute view-ready values so the Jinja template stays clean."""
        findings = list(result.findings)

        # Group + count by severity
        severity_order = ["critical", "high", "medium", "low", "warn", "info"]
        by_severity: Dict[str, list] = {s: [] for s in severity_order}
        for f in findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            by_severity.setdefault(sev, []).append(f)

        counts = {s: len(by_severity.get(s, [])) for s in severity_order}
        total = len(findings)

        # Overall risk rating — simple rules:
        if counts.get("critical", 0) > 0:
            risk_rating = "CRITICAL"
        elif counts.get("high", 0) > 0:
            risk_rating = "HIGH"
        elif counts.get("medium", 0) > 0:
            risk_rating = "MEDIUM"
        elif counts.get("low", 0) > 0 or counts.get("warn", 0) > 0:
            risk_rating = "LOW"
        else:
            risk_rating = "BASELINE"

        started_dt = datetime.fromtimestamp(
            result.started_at_ns / 1e9, tz=timezone.utc
        )
        completed_dt = (
            datetime.fromtimestamp(result.completed_at_ns / 1e9, tz=timezone.utc)
            if result.completed_at_ns else None
        )

        # Tool summary — derived from tool_outputs
        tool_summary = []
        for name, tr in result.tool_outputs.items():
            tr_d = tr if isinstance(tr, dict) else asdict(tr) if hasattr(tr, "__dataclass_fields__") else tr.__dict__
            duration_s = (tr_d.get("completed_at_ns", 0) - tr_d.get("started_at_ns", 0)) / 1e9 if tr_d.get("started_at_ns") else None
            tool_summary.append({
                "name": name,
                "exit_code": tr_d.get("exit_code"),
                "duration_s": duration_s,
                "findings": len(tr_d.get("findings", [])),
                "command": " ".join(tr_d.get("command", [])[:10]),
                "errors": len(tr_d.get("errors", [])),
            })

        # Map finding fields for template
        view_findings = []
        for idx, f in enumerate(findings, 1):
            view_findings.append({
                "num": idx,
                "finding_id": f.finding_id,
                "template_id": f.template_id or "unknown",
                "tool": f.tool,
                "target": f.target,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "title": f.title,
                "description": f.description,
                "cwe": f.cwe,
                "cvss": f.cvss,
                "references": f.references or [],
                "mitre_techniques": f.mitre_techniques or [],
                "evidence": f.evidence or {},
            })

        return {
            "engagement_id": result.engagement_id,
            "short_id": result.engagement_id[:8],
            "target": result.scope.target,
            "authorized_by": result.scope.authorized_by,
            "scope": asdict(result.scope),
            "started": started_dt,
            "completed": completed_dt,
            "duration_s": result.duration_s,
            "phases": [p.value if hasattr(p, "value") else str(p) for p in result.phases_complete],
            "findings": view_findings,
            "counts": counts,
            "total_findings": total,
            "risk_rating": risk_rating,
            "by_severity": {
                s: [{"num": idx + 1, "title": f.title, "severity": s}
                    for idx, f in enumerate(by_severity.get(s, []))]
                for s in severity_order
            },
            "tool_summary": tool_summary,
            "customer": customer_info,
            "generated_at": datetime.now(timezone.utc),
            "product_name": "AMOSKYS Web",
            "product_url": "https://amoskys.com",
            "agent_name": "Argos",
            "agent_version": customer_info.get("argos_version", "0.2.0-alpha"),
        }


# ─────────────────────────────────────────────────────────
# Jinja filters
# ─────────────────────────────────────────────────────────

_SEVERITY_CLASSES = {
    "critical": "sev-critical",
    "high":     "sev-high",
    "medium":   "sev-medium",
    "warn":     "sev-warn",
    "low":      "sev-low",
    "info":     "sev-info",
}


def _severity_badge(sev: str) -> str:
    """Jinja filter: render a severity string as an HTML badge class."""
    return _SEVERITY_CLASSES.get(sev.lower() if sev else "", "sev-info")


def _cvss_color(cvss: Optional[float]) -> str:
    """Pick a color class based on CVSS numeric score."""
    if cvss is None:
        return "cvss-none"
    if cvss >= 9.0:
        return "cvss-critical"
    if cvss >= 7.0:
        return "cvss-high"
    if cvss >= 4.0:
        return "cvss-medium"
    return "cvss-low"
