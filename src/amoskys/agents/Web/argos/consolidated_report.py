"""Consolidated customer report — one deliverable across a whole scan queue.

Per-engagement JSON lives on disk; those are internal artifacts. The
customer-facing product is ONE report that reads as "we scanned every
asset we discovered, here's what we found, here's what you should fix."

This module:
    1. Pulls scan_queue + scan_jobs + findings from the DB
    2. Builds a ConsolidatedReport dataclass (structured + queryable)
    3. Renders it to HTML (always) + PDF (if WeasyPrint available)

PDF degrades gracefully — if WeasyPrint + its system libs aren't
installed we still produce the HTML, set pdf_error on the result, and
return a usable deliverable. No crashes for missing optional deps.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from amoskys.agents.Web.argos.storage import (
    AssetsDB,
    Customer,
    Operator,
    ScanJob,
    ScanQueue,
    StoredFinding,
)

logger = logging.getLogger("amoskys.argos.consolidated_report")

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


# ── Data model ────────────────────────────────────────────────────


@dataclass
class AssetSection:
    """One asset's subsection of the consolidated report."""
    asset_value: str
    asset_kind: str
    status: str                 # from ScanJob.status
    findings_count: int
    findings: List[StoredFinding] = field(default_factory=list)
    skip_reason: Optional[str] = None
    error: Optional[str] = None

    @property
    def severity_counts(self) -> Dict[str, int]:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


@dataclass
class ConsolidatedReport:
    """One customer-facing report covering an entire scan queue.

    Returned by build_report(); rendered to HTML/PDF by render().
    """
    queue: ScanQueue
    customer: Customer
    operator_email: Optional[str]
    assets: List[AssetSection]
    generated_at_ns: int
    total_findings: int
    severity_totals: Dict[str, int]

    @property
    def critical_plus_high(self) -> int:
        return self.severity_totals.get("critical", 0) + self.severity_totals.get("high", 0)

    def to_summary_dict(self) -> Dict[str, Any]:
        return {
            "queue_id": self.queue.queue_id,
            "customer": self.customer.name,
            "customer_seed": self.customer.seed,
            "operator": self.operator_email,
            "assets_scanned": len([a for a in self.assets if a.status == "complete"]),
            "assets_skipped": len([a for a in self.assets if a.status == "skipped"]),
            "assets_failed": len([a for a in self.assets if a.status == "failed"]),
            "total_findings": self.total_findings,
            "severity_totals": dict(self.severity_totals),
            "generated_at_ns": self.generated_at_ns,
        }


# ── Render result ─────────────────────────────────────────────────


@dataclass
class RenderResult:
    html_path: Path
    pdf_path: Optional[Path] = None
    pdf_error: Optional[str] = None


# ── Build from DB ─────────────────────────────────────────────────


def build_report(db: AssetsDB, queue_id: str) -> ConsolidatedReport:
    """Assemble a ConsolidatedReport from a completed scan queue.

    Raises LookupError if queue / customer / operator is missing.
    """
    import time

    queue = db.get_scan_queue(queue_id)
    if queue is None:
        raise LookupError(f"no scan_queue with id {queue_id!r}")
    customer = db.get_customer(queue.customer_id)
    if customer is None:
        raise LookupError(f"customer {queue.customer_id!r} missing for queue {queue_id}")
    operator = db.get_operator(queue.operator_id)
    operator_email = operator.email if operator else None

    jobs = db.list_scan_jobs(queue_id)
    findings_all = db.list_findings(queue_id=queue_id)
    findings_by_job: Dict[str, List[StoredFinding]] = {}
    for f in findings_all:
        findings_by_job.setdefault(f.job_id, []).append(f)

    sections: List[AssetSection] = []
    for job in jobs:
        sections.append(AssetSection(
            asset_value=job.asset_value,
            asset_kind=job.asset_kind,
            status=job.status,
            findings_count=job.findings_count,
            findings=findings_by_job.get(job.job_id, []),
            skip_reason=job.skip_reason,
            error=job.error,
        ))

    severity_totals = {s: 0 for s in SEVERITY_ORDER}
    for f in findings_all:
        severity_totals[f.severity] = severity_totals.get(f.severity, 0) + 1

    return ConsolidatedReport(
        queue=queue,
        customer=customer,
        operator_email=operator_email,
        assets=sections,
        generated_at_ns=int(time.time() * 1e9),
        total_findings=len(findings_all),
        severity_totals=severity_totals,
    )


# ── Render ────────────────────────────────────────────────────────


def render(
    report: ConsolidatedReport,
    out_dir: Path,
    html_only: bool = False,
) -> RenderResult:
    """Render HTML (always) + PDF (if weasyprint present)."""
    out_dir = Path(out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"amoskys-report-{report.queue.queue_id}"

    html = _render_html(report)
    html_path = out_dir / f"{stem}.html"
    html_path.write_text(html, encoding="utf-8")

    result = RenderResult(html_path=html_path)

    if html_only:
        return result

    try:
        from weasyprint import HTML  # type: ignore
        pdf_bytes = HTML(string=html).write_pdf()
        pdf_path = out_dir / f"{stem}.pdf"
        pdf_path.write_bytes(pdf_bytes)
        result.pdf_path = pdf_path
    except ImportError:
        result.pdf_error = (
            "weasyprint not installed — HTML only. "
            "Install: pip install weasyprint"
        )
    except Exception as e:  # noqa: BLE001
        result.pdf_error = f"{type(e).__name__}: {e}"

    return result


def _render_html(report: ConsolidatedReport) -> str:
    """Self-contained HTML with inline CSS.

    Deliberately no Jinja — this is one tight template, keeping us
    free of a render-path dep the caller might not have. WeasyPrint
    parses this HTML directly into PDF.
    """
    gen_iso = datetime.fromtimestamp(
        report.generated_at_ns / 1e9, tz=timezone.utc
    ).isoformat(timespec="seconds")
    created_iso = datetime.fromtimestamp(
        report.queue.created_at_ns / 1e9, tz=timezone.utc
    ).isoformat(timespec="seconds")

    # ── Executive summary
    exec_rows = []
    for sev in SEVERITY_ORDER:
        n = report.severity_totals.get(sev, 0)
        if n == 0 and sev in ("info",):
            continue
        exec_rows.append(
            f'<tr class="sev-{sev}"><td>{sev.title()}</td><td>{n}</td></tr>'
        )

    # ── Asset sections
    asset_blocks: List[str] = []
    for section in report.assets:
        block = _render_asset_section(section)
        asset_blocks.append(block)

    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<title>AMOSKYS Security Report — {_h(report.customer.name)}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
         color: #1a1a1a; margin: 2em; line-height: 1.5; max-width: 880px; }}
  h1 {{ border-bottom: 3px solid #c0392b; padding-bottom: 0.3em; }}
  h2 {{ margin-top: 1.8em; border-bottom: 1px solid #ddd; padding-bottom: 0.2em; }}
  h3 {{ margin-top: 1.2em; color: #2c3e50; }}
  table {{ border-collapse: collapse; margin: 0.7em 0; }}
  th, td {{ text-align: left; padding: 0.4em 0.9em; border: 1px solid #ddd; }}
  th {{ background: #f7f7f7; }}
  .meta {{ color: #666; font-size: 0.9em; }}
  .sev-critical {{ background: #fdecea; }}
  .sev-high {{ background: #fef3e4; }}
  .sev-medium {{ background: #fffbe5; }}
  .sev-low {{ background: #eaf4fd; }}
  .sev-info {{ background: #f3f3f3; }}
  .badge {{ display: inline-block; padding: 0.15em 0.7em; border-radius: 3px;
           font-size: 0.85em; font-weight: 600; }}
  .badge-critical {{ background: #c0392b; color: white; }}
  .badge-high {{ background: #e67e22; color: white; }}
  .badge-medium {{ background: #f1c40f; color: #333; }}
  .badge-low {{ background: #3498db; color: white; }}
  .badge-info {{ background: #bdc3c7; color: #333; }}
  .finding {{ border-left: 4px solid #c0392b; padding: 0.6em 1em;
             margin: 0.8em 0; background: #fff; }}
  .finding.sev-high {{ border-left-color: #e67e22; }}
  .finding.sev-medium {{ border-left-color: #f1c40f; }}
  .finding.sev-low {{ border-left-color: #3498db; }}
  .finding.sev-info {{ border-left-color: #bdc3c7; }}
  .finding h4 {{ margin: 0 0 0.3em 0; }}
  .evidence {{ background: #f9f9f9; padding: 0.5em; font-family: Consolas,
              "Courier New", monospace; font-size: 0.85em; white-space: pre-wrap;
              word-break: break-word; }}
  .note {{ color: #888; font-style: italic; }}
  .footer {{ margin-top: 3em; padding-top: 1em; border-top: 1px solid #ddd;
            color: #888; font-size: 0.85em; }}
</style></head><body>

<h1>External Security Assessment</h1>

<div class="meta">
  <strong>Customer:</strong> {_h(report.customer.name)}<br>
  <strong>Target:</strong> {_h(report.customer.seed)}<br>
  <strong>Conducted by:</strong> {_h(report.operator_email or '(unknown operator)')}<br>
  <strong>Queue ID:</strong> {_h(report.queue.queue_id)}<br>
  <strong>Queued:</strong> {_h(created_iso)} UTC<br>
  <strong>Report generated:</strong> {_h(gen_iso)} UTC<br>
  <strong>Tool bundle:</strong> {_h(report.queue.tool_bundle)}
</div>

<h2>Executive Summary</h2>
<p>AMOSKYS performed an external security assessment of
<strong>{_h(report.customer.name)}</strong>'s public-facing infrastructure.
Across <strong>{len(report.assets)} asset(s)</strong> discovered through
passive reconnaissance and authorized probing, we identified
<strong>{report.total_findings} finding(s)</strong>
({report.critical_plus_high} at Critical/High severity).</p>

<table>
<tr><th>Severity</th><th>Count</th></tr>
{''.join(exec_rows) or '<tr><td colspan="2">no findings</td></tr>'}
</table>

<h2>Assets Assessed</h2>
{''.join(asset_blocks) if asset_blocks else '<p>No assets in this queue.</p>'}

<h2>Next Steps</h2>
<p>AMOSKYS provides a defensive platform, <em>Aegis</em>, that continuously
monitors for the vulnerability classes identified above and blocks the
underlying attack patterns in real time. Contact your AMOSKYS representative
to enable proactive defense against everything in this report, plus the
zero-day classes we discover before public disclosure.</p>

<div class="footer">
  Generated by AMOSKYS Argos.
  Queue <code>{_h(report.queue.queue_id)}</code>.
  This is a confidential report; do not distribute without authorization.
</div>

</body></html>"""


def _render_asset_section(section: AssetSection) -> str:
    status_note = ""
    if section.status == "skipped":
        status_note = (
            f'<p class="note">Skipped: {_h(section.skip_reason or "(no reason)")}</p>'
        )
    elif section.status == "failed":
        status_note = (
            f'<p class="note" style="color:#c0392b">'
            f'Scan failed: {_h(section.error or "(no error)")}</p>'
        )
    elif section.findings_count == 0:
        status_note = (
            '<p class="note">No findings — this asset is clean against the '
            'current tool bundle.</p>'
        )

    findings_html = "".join(_render_finding(f) for f in section.findings)

    return f"""
<h3>{_h(section.asset_value)} <small class="meta">[{_h(section.asset_kind)}]</small></h3>
{status_note}
{findings_html}
"""


def _render_finding(f: StoredFinding) -> str:
    refs_html = ""
    if f.references:
        links = "".join(
            f'<li><a href="{_h(r)}">{_h(r)}</a></li>' for r in f.references
        )
        refs_html = f'<strong>References:</strong><ul>{links}</ul>'

    evidence_html = ""
    if f.evidence:
        # Compact key-value rendering; deliberately truncated
        items: List[str] = []
        for k, v in list(f.evidence.items())[:20]:
            v_str = str(v)
            if len(v_str) > 300:
                v_str = v_str[:297] + "..."
            items.append(f"{_h(str(k))}: {_h(v_str)}")
        evidence_html = (
            f'<div class="evidence">{"<br>".join(items)}</div>'
        )

    meta_parts = []
    if f.tool:
        meta_parts.append(f"tool={_h(f.tool)}")
    if f.template_id:
        meta_parts.append(f"rule={_h(f.template_id)}")
    if f.cwe:
        meta_parts.append(_h(f.cwe))
    if f.cvss is not None:
        meta_parts.append(f"CVSS {f.cvss}")
    meta_line = (
        f'<p class="meta">{" · ".join(meta_parts)}</p>' if meta_parts else ""
    )

    return f"""
<div class="finding sev-{_h(f.severity)}">
  <h4><span class="badge badge-{_h(f.severity)}">{_h(f.severity.upper())}</span>
      {_h(f.title)}</h4>
  {meta_line}
  <p>{_h(f.description or "")}</p>
  {evidence_html}
  {refs_html}
</div>"""


# ── HTML escape ───────────────────────────────────────────────────


def _h(value: Any) -> str:
    """Minimal HTML escape — we don't need full XHTML conformance."""
    s = str(value) if value is not None else ""
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
