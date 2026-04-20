"""Render a CampaignReport as a standalone, downloadable HTML page.

Self-contained — no external CSS/JS dependencies. Prints cleanly via
browser "Save as PDF" so operators don't need WeasyPrint to ship a
branded PDF to a customer.

Sections
--------
  1. Hero / executive summary
  2. Architecture profile grid
  3. Exploit chains (ranked by severity × CVSS × confidence)
  4. All findings (chained + unchained)
  5. Decision trail (live stream replay)
  6. Legal footer (consent method, timestamps, scope)
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


_SEV_COLORS = {
    "critical": ("#dc2626", "#fff"),
    "high":     ("#ea580c", "#fff"),
    "medium":   ("#ca8a04", "#fff"),
    "low":      ("#2563eb", "#fff"),
    "info":     ("#6b7280", "#fff"),
    "none":     ("#374151", "#fff"),
}


def _esc(s: Any) -> str:
    return html.escape("" if s is None else str(s))


def _sev_badge(sev: str) -> str:
    bg, fg = _SEV_COLORS.get((sev or "info").lower(), _SEV_COLORS["info"])
    return (
        f'<span style="display:inline-block;padding:2px 10px;border-radius:3px;'
        f'font-size:11px;font-weight:700;letter-spacing:0.06em;'
        f'text-transform:uppercase;background:{bg};color:{fg};">'
        f'{_esc(sev)}</span>'
    )


def _kv(k: str, v: str) -> str:
    return (
        f'<div class="kv"><div class="k">{_esc(k)}</div>'
        f'<div class="v">{_esc(v)}</div></div>'
    )


def _profile_section(profile: Optional[Dict[str, Any]]) -> str:
    if not profile:
        return '<p class="muted">No architecture profile collected.</p>'
    cells = []
    cdn = profile.get("cdn") or {}
    waf = profile.get("waf") or {}
    origin = profile.get("origin") or {}
    runtime = profile.get("runtime") or {}
    fw = profile.get("framework") or {}
    osf = profile.get("os") or {}
    cells.append(_kv("CDN", cdn.get("name") or "—"))
    cells.append(_kv("WAF", ", ".join(waf.get("names") or []) or "—"))
    cells.append(_kv(
        "Origin server",
        f"{origin.get('server') or '—'} {origin.get('version') or ''}".strip()))
    cells.append(_kv(
        "Runtime",
        f"{runtime.get('name') or '—'} {runtime.get('version') or ''}".strip()))
    cells.append(_kv("Database", (profile.get("database") or {}).get("name") or "—"))
    cells.append(_kv("OS", osf.get("family") or "—"))
    cells.append(_kv(
        "Framework",
        f"{fw.get('name') or '—'} {fw.get('version') or ''}".strip()))
    cells.append(_kv(
        "Verbose errors",
        "YES — stack traces leak" if profile.get("verbose_errors") else "no"))
    cells.append(_kv(
        "Debug mode",
        "YES" if profile.get("debug_mode") else "no"))
    cells.append(_kv(
        "Probe cost",
        f"{profile.get('http_requests_used') or 0} GETs · "
        f"{profile.get('fingerprint_time_ms') or 0}ms"))
    return f'<div class="grid">{"".join(cells)}</div>'


def _strategy_section(strategy: Optional[Dict[str, Any]]) -> str:
    if not strategy:
        return '<p class="muted">No strategy generated.</p>'
    notes_html = "".join(
        f"<li>{_esc(n)}</li>" for n in (strategy.get("notes") or [])
    )
    probe_order = ", ".join(strategy.get("probe_order") or [])
    cascade = " → ".join(strategy.get("encoding_cascade") or [])
    return f"""
    <div class="grid">
      {_kv("Probe order", probe_order or "—")}
      {_kv("Encoding cascade", cascade or "—")}
      {_kv("RPS ceiling", f"{strategy.get('rps_ceiling', 0)} req/min")}
      {_kv("Origin bypass", "YES" if strategy.get("origin_bypass") else "no")}
    </div>
    <div style="margin-top:10px;"><strong>Adaptive decisions:</strong><ul>{notes_html}</ul></div>
    """


def _chains_section(chains: List[Dict[str, Any]]) -> str:
    if not chains:
        return ('<p class="muted">No exploit chains composed. This means '
                'either the campaign ran in passive mode and observed no '
                'exploitable patterns, or the target is well-hardened at '
                'the architectural layers Argos inspects.</p>')
    blocks = []
    for i, c in enumerate(chains, 1):
        sev = (c.get("severity") or "info").lower()
        blocks.append(f"""
        <div class="chain chain-{_esc(sev)}">
          <div class="chain-hd">
            <div class="chain-num">#{i:02d}</div>
            <div class="chain-name">{_esc(c.get("name"))}</div>
            <div class="chain-cvss">CVSS {float(c.get('cvss_estimate') or 0):.1f}</div>
          </div>
          <div class="chain-meta">
            {_sev_badge(sev)}
            <span class="muted" style="margin-left:8px;">confidence {_esc(c.get("confidence"))}%</span>
          </div>
          <div class="chain-narr">{_esc(c.get('narrative'))}</div>
          <div class="chain-impact">
            <strong>Business impact:</strong> {_esc(c.get('business_impact'))}
          </div>
          <div class="chain-evidence">
            <strong>Evidence:</strong>
            <ul>
              {"".join(f"<li>{_esc(e)}</li>" for e in (c.get('evidence_trail') or []))}
            </ul>
          </div>
        </div>""")
    return "".join(blocks)


def _findings_section(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return '<p class="muted">No individual findings recorded.</p>'
    rows = []
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        rows.append(f"""
        <tr>
          <td>{_sev_badge(sev)}</td>
          <td><code>{_esc(f.get('kind'))}</code></td>
          <td><code>{_esc(f.get('location'))}</code></td>
          <td>{_esc(f.get('evidence'))}</td>
        </tr>""")
    return f"""
    <table class="findings">
      <thead><tr><th>Severity</th><th>Class</th><th>Location</th><th>Evidence</th></tr></thead>
      <tbody>{"".join(rows)}</tbody>
    </table>"""


def _events_section(events: List[Dict[str, Any]]) -> str:
    if not events:
        return ""
    rows = []
    for e in events:
        ts = datetime.fromtimestamp(e.get("timestamp", 0), tz=timezone.utc).strftime("%H:%M:%S")
        rows.append(f"""
        <tr class="e-{_esc(e.get('kind'))}">
          <td class="e-ts">{_esc(ts)}</td>
          <td class="e-seq">#{_esc(e.get('sequence', ''))}</td>
          <td class="e-kind">{_esc(e.get('kind'))}</td>
          <td class="e-stage">{_esc(e.get('stage'))}</td>
          <td class="e-msg">{_esc(e.get('message'))}</td>
        </tr>""")
    return f"""
    <details><summary>Full decision trail ({len(events)} events) — click to expand</summary>
      <table class="events">
        <thead><tr><th>Time</th><th>#</th><th>Kind</th><th>Stage</th><th>Message</th></tr></thead>
        <tbody>{"".join(rows)}</tbody>
      </table>
    </details>"""


def _legal_section(report: Dict[str, Any]) -> str:
    consent = report.get("consent_method") or "none"
    started = datetime.fromtimestamp(report.get("started_at", 0), tz=timezone.utc).isoformat()
    finished = datetime.fromtimestamp(report.get("finished_at", 0), tz=timezone.utc).isoformat()
    return f"""
    <div class="grid">
      {_kv("Consent method", consent)}
      {_kv("Mode", report.get("mode"))}
      {_kv("Started (UTC)", started)}
      {_kv("Finished (UTC)", finished)}
      {_kv("Duration", f"{report.get('duration_s', 0):.2f} seconds")}
      {_kv("Target", report.get("target_url"))}
    </div>
    <p class="muted" style="margin-top:12px;">
      This report was generated by Argos, the offensive agent of AMOSKYS Web.
      All techniques used are lawful under CFAA §1030(a)(2)(C) when authorized
      by the target's owner or when operating on OSINT-only data sources.
      See Van Buren v. United States (2021) and hiQ Labs v. LinkedIn (9th Cir. 2022).
    </p>"""


_CSS = """
  @page { size: A4; margin: 1.5cm; }
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
                 Helvetica, Arial, sans-serif;
    background: #ffffff; color: #1f2937; line-height: 1.55;
    margin: 0; padding: 0;
  }
  .page {
    max-width: 920px; margin: 0 auto; padding: 32px 24px;
  }
  h1 { font-size: 26px; margin: 0 0 4px 0; color: #0b1220; letter-spacing: -0.01em; }
  h2 {
    font-size: 15px; text-transform: uppercase; letter-spacing: 0.06em;
    color: #0b1220; margin: 32px 0 12px 0;
    border-bottom: 2px solid #0b1220; padding-bottom: 6px;
  }
  h3 { font-size: 13px; margin: 18px 0 8px 0; color: #111827; }
  .hero {
    background: linear-gradient(135deg, #0b1220 0%, #1f2937 100%);
    color: #fff; padding: 28px 24px; border-radius: 6px;
    margin-bottom: 24px;
  }
  .hero .sub { opacity: 0.75; font-size: 13px; margin-top: 6px; }
  .hero .banner {
    display: inline-block; margin-top: 12px; padding: 4px 10px;
    background: rgba(255,255,255,0.12); border-radius: 3px;
    font-size: 11px; letter-spacing: 0.05em; text-transform: uppercase;
  }
  .hero .target { font-family: "SF Mono", Menlo, monospace;
                    color: #60e3ff; font-size: 14px; margin-top: 4px; }
  .summary {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
    gap: 10px; margin-bottom: 8px;
  }
  .summary .card {
    background: #f9fafb; border: 1px solid #e5e7eb;
    border-radius: 4px; padding: 10px 12px;
  }
  .summary .card .l { color: #6b7280; font-size: 10px; text-transform: uppercase;
                       letter-spacing: 0.05em; }
  .summary .card .n { font-size: 22px; font-weight: 700; color: #111827;
                       margin-top: 2px; font-variant-numeric: tabular-nums; }

  .grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 6px;
  }
  .kv { background: #f9fafb; border: 1px solid #e5e7eb;
         border-radius: 3px; padding: 6px 10px; }
  .kv .k { color: #6b7280; font-size: 10px; text-transform: uppercase;
            letter-spacing: 0.04em; }
  .kv .v { color: #111827; font-weight: 600; font-size: 13px; margin-top: 1px; }

  .chain {
    background: #fffbeb; border: 1px solid #fcd34d;
    border-left: 4px solid; border-radius: 4px;
    padding: 14px 18px; margin: 10px 0;
  }
  .chain-critical { background: #fef2f2; border-color: #fecaca;
                      border-left-color: #dc2626; }
  .chain-high     { background: #fff7ed; border-color: #fed7aa;
                      border-left-color: #ea580c; }
  .chain-medium   { background: #fffbeb; border-color: #fef3c7;
                      border-left-color: #ca8a04; }
  .chain-hd { display: flex; justify-content: space-between;
                align-items: baseline; margin-bottom: 6px; gap: 12px; }
  .chain-num { font-family: "SF Mono", Menlo, monospace;
                color: #6b7280; font-size: 12px; }
  .chain-name { font-weight: 700; color: #0b1220; font-size: 15px;
                 flex: 1; }
  .chain-cvss { color: #dc2626; font-family: "SF Mono", Menlo, monospace;
                 font-weight: 700; font-size: 13px; }
  .chain-meta { margin-bottom: 8px; }
  .chain-narr { white-space: pre-wrap; font-size: 13px;
                  color: #1f2937; padding: 8px 0;
                  border-top: 1px dashed #e5e7eb;
                  border-bottom: 1px dashed #e5e7eb; margin: 6px 0; }
  .chain-impact { color: #7f1d1d; font-size: 13px;
                    margin-top: 6px; }
  .chain-evidence { color: #4b5563; font-size: 12px; margin-top: 6px; }
  .chain-evidence ul { margin: 2px 0 0 18px; }

  table.findings, table.events {
    width: 100%; border-collapse: collapse;
    font-size: 12px; margin-top: 8px;
  }
  table.findings th, table.events th {
    background: #f3f4f6; color: #374151; text-align: left;
    padding: 6px 10px; border-bottom: 2px solid #d1d5db;
    font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em;
  }
  table.findings td, table.events td {
    padding: 6px 10px; border-bottom: 1px solid #f3f4f6;
    vertical-align: top;
  }
  table.events .e-ts { font-family: monospace; color: #6b7280; white-space: nowrap; }
  table.events .e-seq { font-family: monospace; color: #9ca3af; }
  table.events .e-kind { font-weight: 600; color: #1f2937; font-size: 11px;
                          text-transform: uppercase; letter-spacing: 0.04em; }
  table.events .e-stage { color: #6b7280; }
  table.events .e-msg { color: #1f2937; }
  tr.e-stage_start { background: #eff6ff; }
  tr.e-stage_end   { background: #f0fdf4; }
  tr.e-finding     { background: #fffbeb; }
  tr.e-chain       { background: #fef2f2; font-weight: 600; }
  tr.e-fatal       { background: #fee2e2; color: #7f1d1d; }
  tr.e-report      { background: #eef2ff; font-weight: 600; }

  code { font-family: "SF Mono", Menlo, monospace; background: #f3f4f6;
          padding: 1px 5px; border-radius: 2px; font-size: 12px; }
  .muted { color: #6b7280; font-size: 13px; }
  details summary { cursor: pointer; color: #2563eb;
                    font-size: 12px; margin-top: 10px; }

  .footer {
    margin-top: 32px; padding-top: 16px; border-top: 1px solid #e5e7eb;
    color: #6b7280; font-size: 11px; text-align: center;
  }
  .footer .brand { color: #0b1220; font-weight: 700; }

  @media print {
    .hero { background: #0b1220 !important; color: #fff !important;
             -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .chain { break-inside: avoid; }
    details { break-inside: avoid; }
    details[open] > summary { display: none; }
    details:not([open]) { display: none; }
  }
"""


def render_campaign_html(report: Dict[str, Any]) -> str:
    """Render a CampaignReport (dict form) as a complete HTML document."""
    target = report.get("target_url") or "—"
    mode = report.get("mode") or "—"
    max_sev = (report.get("max_severity") or "low").lower()
    n_chains = len(report.get("chains") or [])
    n_findings = len(report.get("findings") or [])
    duration = report.get("duration_s") or 0.0

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    header_banner = "TARGET UNDER ACTIVE PENTEST" if mode == "exploit" \
                     else ("CONFIRMATION SCAN" if mode == "confirm" else "OSINT RECONNAISSANCE")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Argos Pentest Report — {_esc(target)}</title>
  <style>{_CSS}</style>
</head>
<body>
<div class="page">

  <!-- HERO -->
  <div class="hero">
    <div style="font-size: 11px; letter-spacing: 0.06em; text-transform: uppercase; opacity: 0.75;">
      Argos Adaptive Pentest · AMOSKYS Web
    </div>
    <h1 style="color: #fff; margin-top: 4px;">Campaign Report</h1>
    <div class="target">{_esc(target)}</div>
    <div class="sub">Generated {_esc(generated_at)} · ran for {duration:.2f}s</div>
    <div class="banner">{_esc(header_banner)}</div>
  </div>

  <!-- SUMMARY -->
  <h2>Executive Summary</h2>
  <div class="summary">
    <div class="card">
      <div class="l">Risk rating</div>
      <div class="n" style="color: {_SEV_COLORS.get(max_sev, ('#111827',))[0]};">
        {_esc(max_sev.upper())}
      </div>
    </div>
    <div class="card">
      <div class="l">Exploit chains</div>
      <div class="n">{n_chains}</div>
    </div>
    <div class="card">
      <div class="l">Individual findings</div>
      <div class="n">{n_findings}</div>
    </div>
    <div class="card">
      <div class="l">Mode</div>
      <div class="n" style="font-size: 13px; font-weight: 700;">{_esc(mode)}</div>
    </div>
    <div class="card">
      <div class="l">Duration</div>
      <div class="n" style="font-size: 18px;">{duration:.2f}s</div>
    </div>
  </div>

  <!-- ARCHITECTURE -->
  <h2>Architecture Profile</h2>
  {_profile_section(report.get("profile"))}

  <!-- STRATEGY -->
  <h2>Adaptive Strategy</h2>
  {_strategy_section(report.get("strategy"))}

  <!-- CHAINS -->
  <h2>Exploit Chains</h2>
  {_chains_section(report.get("chains") or [])}

  <!-- FINDINGS -->
  <h2>All Findings</h2>
  {_findings_section(report.get("findings") or [])}

  <!-- SMUGGLE (if present) -->
  { "<h2>Request-Smuggling Probes</h2><pre style='background:#f9fafb;padding:10px;border-radius:3px;font-size:11px;overflow:auto;'>" + _esc(json.dumps(report.get("smuggle_report"), indent=2)) + "</pre>" if report.get("smuggle_report") else "" }

  <!-- ORIGIN (if present) -->
  { "<h2>Origin Candidates</h2><table class='findings'><thead><tr><th>IP</th><th>Source</th><th>Confidence</th><th>Confirmed</th></tr></thead><tbody>" + "".join("<tr><td><code>" + _esc(c.get("ip")) + "</code></td><td>" + _esc(c.get("source")) + "</td><td>" + _esc(c.get("confidence")) + "%</td><td>" + ("YES" if c.get("confirmed") else "no") + "</td></tr>" for c in (report.get("origin_candidates") or [])) + "</tbody></table>" if report.get("origin_candidates") else "" }

  <!-- EVENTS -->
  <h2>Decision Trail</h2>
  {_events_section(report.get("events") or [])}

  <!-- LEGAL -->
  <h2>Audit & Authorization</h2>
  {_legal_section(report)}

  <div class="footer">
    <span class="brand">AMOSKYS Web</span> · Argos Campaign Orchestrator v2.4 ·
    <a href="https://amoskys.com" style="color: inherit;">amoskys.com</a>
  </div>
</div>
</body>
</html>
"""


__all__ = ["render_campaign_html"]
