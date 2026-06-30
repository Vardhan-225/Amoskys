"""Customer-grade PDF renderer for Campaign reports.

Produces a multi-page A4 PDF styled like a consulting deliverable:

    Page 1    Cover       — target, date, risk rating, hero stats
    Page 2    Executive   — 1-paragraph summary + key metrics
    Page 3+   Findings    — each exploit chain or finding on its own card
    Page N    Profile     — architecture table
    Page N+1  Decisions   — strategy reasoning + adaptive choices
    Page N+2  Evidence    — decision trail (stage timeline)
    Page N+3  Audit       — consent, authorization, legal ceiling
    Every page: running header (target) + footer (page X / Y · AMOSKYS)

Technique: WeasyPrint reads CSS Paged Media rules (@page, page-
break-before, running(), counter()) and emits a print-ready PDF.
No headless browser dependency; pure Python plus libpango.

If WeasyPrint is missing at import time, `render_campaign_pdf`
raises a clear RuntimeError instead of blowing up later.
"""

from __future__ import annotations

import html
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("amoskys.argos.campaign.report_pdf")


# ── Brand constants ───────────────────────────────────────────────

_BRAND_NAVY = "#0b1220"
_BRAND_INK = "#1a2238"
_BRAND_BLUE = "#1d4ed8"
_BRAND_CYAN = "#0891b2"
_BRAND_ACCENT = "#0ea5e9"

_SEV_COLORS = {
    "critical": ("#991b1b", "#fee2e2"),
    "high": ("#c2410c", "#ffedd5"),
    "medium": ("#a16207", "#fef9c3"),
    "low": ("#1e40af", "#dbeafe"),
    "info": ("#374151", "#e5e7eb"),
    "none": ("#374151", "#e5e7eb"),
}


# ── helpers ───────────────────────────────────────────────────────


def _esc(s: Any) -> str:
    return html.escape("" if s is None else str(s))


def _sev_pill(sev: str) -> str:
    sev = (sev or "info").lower()
    fg, bg = _SEV_COLORS.get(sev, _SEV_COLORS["info"])
    return (
        f'<span class="pill" style="background:{bg};color:{fg};">'
        f"{_esc(sev.upper())}</span>"
    )


def _fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts or 0, tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


def _fmt_time(ts: float) -> str:
    return datetime.fromtimestamp(ts or 0, tz=timezone.utc).strftime("%H:%M:%S")


# ── CSS ────────────────────────────────────────────────────────────

_CSS = r"""
@page {
  size: A4;
  margin: 22mm 18mm 22mm 18mm;

  @top-left  {
    content: string(running-target);
    font-family: 'Inter', sans-serif;
    font-size: 9pt;
    color: #6b7280;
  }
  @top-right {
    content: "ARGOS · Pentest Report";
    font-family: 'Inter', sans-serif;
    font-size: 9pt;
    color: #6b7280;
    letter-spacing: 0.05em;
  }
  @bottom-left {
    content: "AMOSKYS Web · confidential";
    font-family: 'Inter', sans-serif;
    font-size: 8pt;
    color: #9ca3af;
  }
  @bottom-right {
    content: "Page " counter(page) " of " counter(pages);
    font-family: 'Inter', sans-serif;
    font-size: 8pt;
    color: #6b7280;
  }
}

@page cover {
  margin: 0;
  @top-left { content: normal; }
  @top-right { content: normal; }
  @bottom-left { content: normal; }
  @bottom-right { content: normal; }
}

html, body {
  font-family: 'Inter', 'Helvetica Neue', Helvetica, Arial, sans-serif;
  font-size: 10pt;
  color: #1f2937;
  line-height: 1.55;
  margin: 0; padding: 0;
}

/* Cover page */
.cover {
  page: cover;
  string-set: running-target " ";
  background: linear-gradient(145deg, #0b1220 0%, #1a2238 60%, #1d4ed8 100%);
  color: #ffffff;
  padding: 32mm 20mm;
  min-height: 297mm;
  box-sizing: border-box;
  page-break-after: always;
  position: relative;
}
.cover .brand {
  font-size: 9pt;
  letter-spacing: 0.22em;
  text-transform: uppercase;
  opacity: 0.62;
  margin-bottom: 8mm;
}
.cover h1 {
  font-size: 34pt;
  font-weight: 800;
  letter-spacing: -0.015em;
  line-height: 1.05;
  margin: 0 0 6mm 0;
  color: #ffffff;
}
.cover .subtitle {
  font-size: 13pt;
  opacity: 0.78;
  margin-bottom: 14mm;
  max-width: 140mm;
}
.cover .target-card {
  background: rgba(255,255,255,0.08);
  border: 1px solid rgba(255,255,255,0.15);
  border-radius: 3mm;
  padding: 6mm 8mm;
  margin-bottom: 10mm;
}
.cover .target-card .label {
  font-size: 8pt;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  opacity: 0.7;
  margin-bottom: 1.5mm;
}
.cover .target-card .target {
  font-family: 'SF Mono', Menlo, monospace;
  font-size: 14pt;
  color: #60e3ff;
  word-break: break-all;
}
.cover .hero-grid {
  display: grid;
  grid-template-columns: 1fr 1fr 1fr;
  gap: 4mm;
  margin-top: 10mm;
}
.cover .hero-cell {
  background: rgba(255,255,255,0.06);
  border: 1px solid rgba(255,255,255,0.1);
  border-radius: 2mm;
  padding: 5mm;
}
.cover .hero-cell .num {
  font-size: 28pt;
  font-weight: 800;
  margin: 0;
  line-height: 1.1;
  font-variant-numeric: tabular-nums;
}
.cover .hero-cell .lbl {
  font-size: 8pt;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  opacity: 0.7;
  margin-top: 2mm;
}
.cover .sev-critical { color: #fca5a5; }
.cover .sev-high     { color: #fdba74; }
.cover .sev-medium   { color: #fde047; }
.cover .sev-low      { color: #93c5fd; }
.cover .sev-info     { color: #d1d5db; }
.cover .meta {
  position: absolute;
  bottom: 20mm;
  left: 20mm;
  right: 20mm;
  display: flex;
  justify-content: space-between;
  align-items: flex-end;
  font-size: 8pt;
  opacity: 0.68;
}
.cover .meta .kv {
  line-height: 1.6;
}
.cover .meta .k {
  text-transform: uppercase;
  letter-spacing: 0.12em;
  font-size: 7pt;
  opacity: 0.7;
}

/* Running target set from the H1 on every content page (invisible) */
.running {
  string-set: running-target attr(data-target);
  display: none;
}

/* Content pages */
section {
  page-break-after: always;
}
section.continuous { page-break-after: auto; }

h1.section-title {
  font-size: 16pt;
  color: #0b1220;
  letter-spacing: -0.01em;
  margin: 0 0 3mm 0;
  padding-bottom: 2mm;
  border-bottom: 2px solid #0b1220;
}
h1.section-title .num {
  color: #9ca3af;
  font-weight: 400;
  margin-right: 2mm;
  font-size: 14pt;
}
h2.sub {
  font-size: 11pt;
  color: #1a2238;
  margin: 5mm 0 2mm 0;
  text-transform: uppercase;
  letter-spacing: 0.06em;
}
p { margin: 2mm 0; }
.muted { color: #6b7280; font-size: 9pt; }
code {
  font-family: 'SF Mono', Menlo, Monaco, monospace;
  font-size: 9pt;
  background: #f3f4f6;
  padding: 0.5pt 3pt;
  border-radius: 1pt;
  color: #1a2238;
}

/* Summary grid on exec page */
.summary-grid {
  display: grid;
  grid-template-columns: 1fr 1fr 1fr 1fr;
  gap: 3mm;
  margin: 5mm 0 7mm 0;
}
.summary-grid .card {
  background: #f9fafb;
  border: 1px solid #e5e7eb;
  border-radius: 2mm;
  padding: 4mm;
}
.summary-grid .card .num {
  font-size: 22pt;
  font-weight: 800;
  font-variant-numeric: tabular-nums;
  color: #0b1220;
  line-height: 1.05;
  margin-bottom: 1.5mm;
}
.summary-grid .card .lbl {
  font-size: 7.5pt;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: #6b7280;
}

/* Pill */
.pill {
  display: inline-block;
  padding: 1pt 6pt;
  border-radius: 2pt;
  font-size: 8pt;
  font-weight: 700;
  letter-spacing: 0.08em;
}

/* Chain card */
.chain {
  border: 1px solid #e5e7eb;
  border-left: 4pt solid #9ca3af;
  border-radius: 2mm;
  padding: 5mm 6mm;
  margin: 4mm 0;
  background: #ffffff;
  page-break-inside: avoid;
}
.chain.critical { border-left-color: #991b1b; background: #fef2f2; }
.chain.high     { border-left-color: #c2410c; background: #fff7ed; }
.chain.medium   { border-left-color: #a16207; background: #fffbeb; }
.chain.low      { border-left-color: #1e40af; background: #eff6ff; }
.chain .head {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: 4mm;
  margin-bottom: 2mm;
}
.chain .name {
  font-weight: 700;
  font-size: 12pt;
  color: #0b1220;
  flex: 1;
}
.chain .cvss {
  font-family: 'SF Mono', Menlo, monospace;
  color: #991b1b;
  font-weight: 700;
}
.chain .meta {
  margin-bottom: 3mm;
  font-size: 9pt;
  color: #6b7280;
}
.chain .narrative {
  background: #ffffff;
  border-left: 2pt dotted #d1d5db;
  padding: 2mm 3mm;
  margin: 2mm 0;
  white-space: pre-wrap;
  font-size: 9.5pt;
  line-height: 1.6;
}
.chain .impact {
  font-size: 9pt;
  color: #7f1d1d;
  font-style: italic;
  margin-top: 2mm;
}
.chain .evidence {
  margin-top: 3mm;
  font-size: 8.5pt;
  color: #4b5563;
}
.chain .evidence ul { margin: 1mm 0 0 5mm; padding: 0; }
.chain .evidence li { margin-bottom: 0.5mm; }

/* Findings table */
table.findings {
  width: 100%;
  border-collapse: collapse;
  font-size: 8.5pt;
  margin-top: 3mm;
}
table.findings th {
  background: #f3f4f6;
  color: #374151;
  text-align: left;
  padding: 2mm 3mm;
  border-bottom: 2px solid #d1d5db;
  font-size: 8pt;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  font-weight: 700;
}
table.findings td {
  padding: 2mm 3mm;
  border-bottom: 1px solid #f3f4f6;
  vertical-align: top;
}

/* Profile grid */
.kv-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 2mm;
  margin: 3mm 0;
}
.kv-cell {
  background: #f9fafb;
  border: 1px solid #e5e7eb;
  border-radius: 1mm;
  padding: 2.5mm 3mm;
}
.kv-cell .k {
  color: #6b7280;
  font-size: 7pt;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  margin-bottom: 1mm;
}
.kv-cell .v {
  color: #0b1220;
  font-weight: 600;
  font-size: 10pt;
}

/* Timeline */
table.timeline {
  width: 100%;
  border-collapse: collapse;
  font-size: 8pt;
}
table.timeline td {
  padding: 1mm 2mm;
  border-bottom: 1px solid #f3f4f6;
  vertical-align: top;
}
table.timeline td.ts {
  font-family: 'SF Mono', Menlo, monospace;
  color: #6b7280;
  white-space: nowrap;
}
table.timeline td.kind {
  font-size: 7pt;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: #374151;
  font-weight: 700;
}
tr.k-stage_start { background: #eff6ff; }
tr.k-stage_end   { background: #ecfdf5; }
tr.k-finding     { background: #fffbeb; }
tr.k-chain       { background: #fef2f2; font-weight: 600; }
tr.k-fatal       { background: #fee2e2; color: #7f1d1d; }
tr.k-decision    { background: #faf5ff; }

.legal {
  font-size: 8.5pt;
  color: #4b5563;
  line-height: 1.6;
  margin: 3mm 0;
}
.legal strong { color: #0b1220; }

.sig-line {
  margin-top: 20mm;
  border-top: 1px solid #9ca3af;
  padding-top: 2mm;
  font-size: 8.5pt;
  color: #6b7280;
}

.toc {
  margin-top: 4mm;
}
.toc ol {
  margin: 0;
  padding-left: 0;
  list-style: none;
}
.toc li {
  padding: 1.5mm 0;
  border-bottom: 1px dotted #d1d5db;
  display: flex;
  justify-content: space-between;
  font-size: 10pt;
}
.toc li .t-title { color: #0b1220; }
.toc li .t-num { color: #9ca3af; font-variant-numeric: tabular-nums; }
"""


# ── HTML construction ─────────────────────────────────────────────


def _cover(report: Dict[str, Any]) -> str:
    target = report.get("target_url") or report.get("target_host") or "—"
    max_sev = (report.get("max_severity") or "low").lower()
    n_chains = len(report.get("chains") or [])
    n_findings = len(report.get("findings") or [])
    duration = report.get("duration_s") or 0.0
    mode = (report.get("mode") or "report").upper()

    finished = _fmt_ts(report.get("finished_at", 0))

    return f"""
    <div class="cover">
      <div class="brand">AMOSKYS · ARGOS ADAPTIVE PENTEST</div>
      <h1>WordPress Pentest Report</h1>
      <div class="subtitle">
        Autonomous adversary-adapted reconnaissance + active vulnerability
        discovery. Zero touch required from the defender.
      </div>

      <div class="target-card">
        <div class="label">Target</div>
        <div class="target">{_esc(target)}</div>
      </div>

      <div class="hero-grid">
        <div class="hero-cell">
          <p class="num sev-{_esc(max_sev)}">{_esc(max_sev.upper())}</p>
          <div class="lbl">Risk Rating</div>
        </div>
        <div class="hero-cell">
          <p class="num">{n_chains}</p>
          <div class="lbl">Exploit Chains</div>
        </div>
        <div class="hero-cell">
          <p class="num">{n_findings}</p>
          <div class="lbl">Individual Findings</div>
        </div>
      </div>

      <div class="meta">
        <div class="kv">
          <div class="k">Engagement mode</div>
          <div>{_esc(mode)}</div>
        </div>
        <div class="kv">
          <div class="k">Generated</div>
          <div>{_esc(finished)}</div>
        </div>
        <div class="kv">
          <div class="k">Duration</div>
          <div>{duration:.2f} seconds</div>
        </div>
        <div class="kv">
          <div class="k">Engine</div>
          <div>Argos v2.4 · AMOSKYS Web</div>
        </div>
      </div>
    </div>
    """


def _toc() -> str:
    # Static TOC — matches the section order below
    items = [
        ("1", "Executive Summary"),
        ("2", "Architecture Profile"),
        ("3", "Adaptive Strategy"),
        ("4", "Exploit Chains"),
        ("5", "All Findings"),
        ("6", "Decision Trail"),
        ("7", "Audit & Authorization"),
    ]
    lis = "".join(
        f'<li><span class="t-title">§{num} · {_esc(title)}</span>'
        f'<span class="t-num">···</span></li>'
        for num, title in items
    )
    return f"""
    <section class="continuous">
      <h1 class="section-title">Contents</h1>
      <div class="toc"><ol>{lis}</ol></div>
    </section>
    """


def _executive(report: Dict[str, Any]) -> str:
    target = report.get("target_url") or "—"
    max_sev = (report.get("max_severity") or "low").lower()
    n_chains = len(report.get("chains") or [])
    n_findings = len(report.get("findings") or [])

    # Severity tallies across findings
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in report.get("findings") or []:
        s = (f.get("severity") or "info").lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    # Narrative paragraph
    if n_chains > 0:
        headline = (
            f"Argos identified <strong>{n_chains} end-to-end exploit "
            f"chain{'s' if n_chains != 1 else ''}</strong> on "
            f"<code>{_esc(target)}</code>. The highest-severity chain "
            f"rates <strong>{_esc(max_sev.upper())}</strong>."
        )
    elif n_findings > 0:
        headline = (
            f"Argos identified <strong>{n_findings} individual "
            f"finding{'s' if n_findings != 1 else ''}</strong> on "
            f"<code>{_esc(target)}</code>. No full exploit chain "
            f"composed from current observations, but the findings "
            f"alone warrant remediation."
        )
    else:
        headline = (
            f"Argos completed its scan of <code>{_esc(target)}</code> "
            f"without composing chains from observed findings. This "
            f"does not mean the target is invulnerable — it means the "
            f"probes in this engagement mode did not reach exploitable "
            f"surface. Deeper engagement modes may uncover more."
        )

    return f"""
    <section>
      <div class="running" data-target="{_esc(target)}"></div>
      <h1 class="section-title"><span class="num">§1</span>Executive Summary</h1>
      <p>{headline}</p>

      <div class="summary-grid">
        <div class="card"><p class="num">{sev_counts['critical']}</p><div class="lbl">Critical</div></div>
        <div class="card"><p class="num">{sev_counts['high']}</p><div class="lbl">High</div></div>
        <div class="card"><p class="num">{sev_counts['medium']}</p><div class="lbl">Medium</div></div>
        <div class="card"><p class="num">{sev_counts['low']}</p><div class="lbl">Low</div></div>
      </div>

      <h2 class="sub">What Argos did</h2>
      <p>Argos is an adaptive offensive agent: it fingerprints the target's full
      stack (CDN, WAF, origin server, runtime, database, operating system,
      framework) and then selects attack tactics known to be effective against
      that exact stack. Every decision is logged and streamed live to the
      operator. This report contains the full decision trail, so every finding
      has a reproducible chain of evidence.</p>

      <h2 class="sub">How to read this report</h2>
      <p>Section 2 shows the target's architectural fingerprint. Section 3 lists
      the tactical decisions Argos made based on that fingerprint. Section 4
      presents exploit chains (compositions of findings that yield
      significant impact) ranked by severity × CVSS × confidence. Section 5 is
      the flat list of all individual findings. Sections 6 and 7 are audit
      appendices for forensic reproducibility.</p>
    </section>
    """


def _architecture(report: Dict[str, Any]) -> str:
    target = report.get("target_url") or "—"
    p = report.get("profile") or {}
    if not p:
        return ""

    cdn = p.get("cdn") or {}
    waf = p.get("waf") or {}
    origin = p.get("origin") or {}
    runtime = p.get("runtime") or {}
    db = p.get("database") or {}
    osf = p.get("os") or {}
    fw = p.get("framework") or {}

    def fmt(name, version=None):
        if not name:
            return "—"
        v = f" {version}" if version else ""
        return f"{name}{v}"

    cells = [
        ("CDN", fmt(cdn.get("name"))),
        ("WAF", ", ".join(waf.get("names") or []) or "—"),
        ("Origin server", fmt(origin.get("server"), origin.get("version"))),
        ("Runtime", fmt(runtime.get("name"), runtime.get("version"))),
        ("Database", fmt(db.get("name"))),
        ("OS", fmt(osf.get("family"))),
        ("Framework", fmt(fw.get("name"), fw.get("version"))),
        ("Verbose errors", "YES (leak)" if p.get("verbose_errors") else "no"),
        ("Debug mode", "YES" if p.get("debug_mode") else "no"),
        ("HTTP requests", str(p.get("http_requests_used") or 0)),
        ("Time to profile", f"{p.get('fingerprint_time_ms') or 0} ms"),
        ("Host", _esc(p.get("target_host") or "—")),
    ]
    grid = "".join(
        f'<div class="kv-cell"><div class="k">{_esc(k)}</div>'
        f'<div class="v">{_esc(v)}</div></div>'
        for k, v in cells
    )

    origin_cands = report.get("origin_candidates") or []
    origin_block = ""
    if origin_cands:
        rows = "".join(
            f'<tr><td><code>{_esc(c.get("ip"))}</code></td>'
            f'<td>{_esc(c.get("source"))}</td>'
            f'<td>{_esc(c.get("confidence"))}%</td>'
            f'<td>{"YES" if c.get("confirmed") else "no"}</td></tr>'
            for c in origin_cands
        )
        origin_block = f"""
        <h2 class="sub">Origin-IP candidates (behind-CDN discovery)</h2>
        <table class="findings">
          <thead><tr><th>IP</th><th>Source</th><th>Confidence</th><th>Confirmed</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
        """

    return f"""
    <section>
      <div class="running" data-target="{_esc(target)}"></div>
      <h1 class="section-title"><span class="num">§2</span>Architecture Profile</h1>
      <p>Argos probes the target with a small number of polite GETs and infers
      every layer of the stack from response headers, body hints, error-page
      signatures, and case-sensitivity tests. This table is the raw input to
      adaptive strategy selection.</p>

      <div class="kv-grid">{grid}</div>

      {origin_block}
    </section>
    """


def _strategy(report: Dict[str, Any]) -> str:
    target = report.get("target_url") or "—"
    s = report.get("strategy") or {}
    notes = s.get("notes") or []
    probe_order = s.get("probe_order") or []
    cascade = s.get("encoding_cascade") or []
    rps = s.get("rps_ceiling") or 0
    origin_bypass = s.get("origin_bypass") or False

    note_lis = (
        "".join(f"<li>{_esc(n)}</li>" for n in notes)
        or "<li class='muted'>(no notes recorded)</li>"
    )

    return f"""
    <section>
      <div class="running" data-target="{_esc(target)}"></div>
      <h1 class="section-title"><span class="num">§3</span>Adaptive Strategy</h1>
      <p>Given the fingerprint above, Argos selects per-class tactics tuned to
      the observed stack's known weaknesses. These choices are not hard-coded;
      they are computed from a rule library informed by disclosed CVEs,
      Wordfence rule changelogs, and PortSwigger research.</p>

      <div class="kv-grid">
        <div class="kv-cell">
          <div class="k">Probe order</div>
          <div class="v" style="font-size:9pt;font-weight:500;">{_esc(", ".join(probe_order))}</div>
        </div>
        <div class="kv-cell">
          <div class="k">Encoding cascade</div>
          <div class="v" style="font-size:9pt;font-weight:500;">{_esc(" → ".join(cascade))}</div>
        </div>
        <div class="kv-cell">
          <div class="k">RPS ceiling</div>
          <div class="v">{rps} req/min</div>
        </div>
        <div class="kv-cell">
          <div class="k">Origin bypass</div>
          <div class="v">{"YES" if origin_bypass else "no"}</div>
        </div>
      </div>

      <h2 class="sub">Adaptive decisions (verbatim log)</h2>
      <ul style="margin-left:5mm;">{note_lis}</ul>
    </section>
    """


def _chains_section(report: Dict[str, Any]) -> str:
    target = report.get("target_url") or "—"
    chains = report.get("chains") or []
    graph = report.get("graph") or {}

    # Graph-reasoner metadata strip
    meta_html = ""
    if graph:
        defenses = graph.get("defenses_detected") or []
        meta_html = f"""
        <div class="kv-grid" style="margin-bottom:4mm;">
          <div class="kv-cell"><div class="k">Goals reached</div>
            <div class="v" style="font-size:9pt;">{len(graph.get('goals_reached') or [])} of {len([g for g in ['account_admin','code_execution','database_write','file_write','persistence','data_exfil','full_compromise']])}</div></div>
          <div class="kv-cell"><div class="k">Graph edges active</div>
            <div class="v">{graph.get('activated_edges',0)} / {graph.get('total_edges',0)}</div></div>
          <div class="kv-cell"><div class="k">Defenses detected</div>
            <div class="v" style="font-size:9pt;">{_esc(', '.join(defenses) or 'none')}</div></div>
          <div class="kv-cell"><div class="k">Near-miss paths</div>
            <div class="v">{len(graph.get('near_misses') or [])}</div></div>
        </div>
        """

    if not chains:
        return f"""
        <section>
          <div class="running" data-target="{_esc(target)}"></div>
          <h1 class="section-title"><span class="num">§4</span>Exploit Chains</h1>
          <p class="muted">No exploit chains composed from observed findings.
          Chains require multiple compatible findings to compose; if findings
          are below critical mass, this section will be empty even when the
          target has weaknesses.</p>
          {meta_html}
        </section>
        """

    cards = []
    for i, c in enumerate(chains, 1):
        sev = (c.get("severity") or "info").lower()
        evidence_items = "".join(
            f"<li>{_esc(e)}</li>" for e in (c.get("evidence_trail") or [])
        )
        # Graph-path extras
        ev_score = c.get("expected_value")
        prob = c.get("success_prob")
        detect = c.get("detectability")
        cost = c.get("cost_minutes")
        mitre = c.get("mitre_chain") or []
        defense_n = c.get("defense_notes") or []
        assumptions = c.get("assumptions") or []
        replay_cmds = c.get("replay_commands") or []

        econ_html = ""
        if ev_score is not None and prob is not None:
            econ_html = f"""
            <div style="display:grid; grid-template-columns:repeat(4,1fr); gap:2mm; margin:2mm 0;">
              <div class="kv-cell" style="padding:2mm;"><div class="k">Expected value</div><div class="v">{ev_score:.2f}</div></div>
              <div class="kv-cell" style="padding:2mm;"><div class="k">Success prob</div><div class="v">{prob*100:.0f}%</div></div>
              <div class="kv-cell" style="padding:2mm;"><div class="k">Stealth</div><div class="v">{(1-detect)*100:.0f}%</div></div>
              <div class="kv-cell" style="padding:2mm;"><div class="k">Cost</div><div class="v">{cost} min</div></div>
            </div>
            """

        mitre_html = ""
        if mitre:
            mitre_html = f"""
            <div style="margin-top:2mm; font-size:8.5pt; color:#4b5563;">
              <strong>MITRE ATT&amp;CK:</strong> {" &nbsp;→&nbsp; ".join(_esc(m) for m in mitre)}
            </div>
            """

        assumptions_html = ""
        if assumptions:
            lis = "".join(f"<li>{_esc(a)}</li>" for a in assumptions)
            assumptions_html = f"""
            <div class="evidence" style="margin-top:2mm;">
              <strong>Assumptions:</strong><ul>{lis}</ul>
            </div>
            """

        defense_html = ""
        if defense_n:
            lis = "".join(f"<li>{_esc(d)}</li>" for d in defense_n)
            defense_html = f"""
            <div class="evidence" style="margin-top:2mm;">
              <strong>Defender friction:</strong><ul>{lis}</ul>
            </div>
            """

        replay_html = ""
        if replay_cmds:
            lis = "".join(
                f'<li><code style="font-size:8pt;">{_esc(r)}</code></li>'
                for r in replay_cmds
            )
            replay_html = f"""
            <div class="evidence" style="margin-top:2mm;">
              <strong>Replay commands:</strong><ul>{lis}</ul>
            </div>
            """

        cards.append(
            f"""
        <div class="chain {_esc(sev)}">
          <div class="head">
            <div><span class="muted">Path #{i:02d}</span> <span class="name">{_esc(c.get("name"))}</span></div>
            <div class="cvss">CVSS {float(c.get('cvss_estimate') or 0):.1f}</div>
          </div>
          <div class="meta">
            {_sev_pill(sev)}
            <span style="margin-left:4mm;">confidence {_esc(c.get("confidence"))}%</span>
          </div>
          {econ_html}
          {mitre_html}
          <div class="narrative">{_esc(c.get('narrative'))}</div>
          <div class="impact"><strong>Business impact:</strong> {_esc(c.get('business_impact'))}</div>
          {defense_html}
          {assumptions_html}
          {replay_html}
          <div class="evidence"><strong>Evidence trail:</strong><ul>{evidence_items}</ul></div>
        </div>
        """
        )

    # Near-miss section
    near_html = ""
    nms = graph.get("near_misses") or []
    if nms:
        near_cards = []
        for nm in nms:
            miss = nm.get("missing_for_completion") or []
            near_cards.append(
                f"""
            <div class="chain" style="border-left-color:#6b7280; background:#f9fafb;">
              <div class="head">
                <span class="name">{_esc(nm.get("name",""))}</span>
              </div>
              <div class="meta">
                <span class="pill" style="background:#6b7280;color:white;">NEAR-MISS</span>
                <span style="margin-left:4mm;">would unlock goal: <code>{_esc(nm.get('goal_state'))}</code></span>
              </div>
              <div class="narrative" style="font-size:9pt;">{_esc(nm.get('narrative','')[:400])}</div>
              <div class="impact"><strong>What's missing:</strong>
                <code>{_esc("|".join(miss))}</code> — if one of these
                is detected in a future scan this chain activates.</div>
            </div>
            """
            )
        near_html = f"""
        <h2 class="sub" style="margin-top:6mm;">Near-miss paths (one finding away)</h2>
        <p class="muted">These paths would activate if the listed finding kind
        surfaces. Real attackers remember these; you should too.</p>
        {"".join(near_cards)}
        """

    return f"""
    <section>
      <div class="running" data-target="{_esc(target)}"></div>
      <h1 class="section-title"><span class="num">§4</span>Exploit Chains</h1>
      <p>Chains are attack paths through a state graph: each transition is a
      transition the attacker can make given a discovered finding. For every
      path Argos computes <strong>expected value = success probability ×
      impact × stealth</strong>, with defense-aware pruning applied when a
      detected WAF or sensor family is known to block a given edge.</p>
      {meta_html}
      {"".join(cards)}
      {near_html}
    </section>
    """


def _findings_section(report: Dict[str, Any]) -> str:
    target = report.get("target_url") or "—"
    findings = report.get("findings") or []
    if not findings:
        rows = "<tr><td colspan='4' class='muted'>No individual findings recorded.</td></tr>"
    else:
        rows = "".join(
            f"<tr>"
            f"<td>{_sev_pill(f.get('severity') or 'info')}</td>"
            f"<td><code>{_esc(f.get('kind'))}</code></td>"
            f"<td><code style='font-size:8pt'>{_esc(f.get('location'))}</code></td>"
            f"<td>{_esc(f.get('evidence'))}</td>"
            f"</tr>"
            for f in findings
        )

    return f"""
    <section>
      <div class="running" data-target="{_esc(target)}"></div>
      <h1 class="section-title"><span class="num">§5</span>All Findings</h1>
      <p>This is the flat list of every finding Argos recorded during the
      engagement, across all stages. Findings that contributed to composed
      chains in §4 are listed here for completeness.</p>
      <table class="findings">
        <thead><tr><th>Severity</th><th>Class</th><th>Location</th><th>Evidence</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </section>
    """


def _timeline_section(report: Dict[str, Any]) -> str:
    target = report.get("target_url") or "—"
    events = report.get("events") or []
    # Keep decision trail compact — show only the meaningful event kinds
    meaningful = {
        "stage_start",
        "stage_end",
        "evidence",
        "decision",
        "finding",
        "chain",
        "fatal",
        "report",
        "done",
    }
    rows = []
    for e in events:
        if e.get("kind") not in meaningful:
            continue
        rows.append(
            f"<tr class='k-{_esc(e.get('kind'))}'>"
            f"<td class='ts'>{_fmt_time(e.get('timestamp', 0))}</td>"
            f"<td class='kind'>{_esc(e.get('kind'))}</td>"
            f"<td>{_esc(e.get('stage'))}</td>"
            f"<td>{_esc((e.get('message') or '')[:160])}</td>"
            f"</tr>"
        )
    rows_html = (
        "".join(rows) or "<tr><td colspan='4' class='muted'>(no events)</td></tr>"
    )

    return f"""
    <section>
      <div class="running" data-target="{_esc(target)}"></div>
      <h1 class="section-title"><span class="num">§6</span>Decision Trail</h1>
      <p>Every meaningful event Argos emitted during the engagement, in order.
      This is the forensic audit trail — each finding in §5 can be traced back
      to a specific stage here.</p>
      <table class="timeline">
        <thead>
          <tr>
            <th style="text-align:left;padding:1mm 2mm;border-bottom:1px solid #d1d5db;font-size:7pt;text-transform:uppercase;">Time</th>
            <th style="text-align:left;padding:1mm 2mm;border-bottom:1px solid #d1d5db;font-size:7pt;text-transform:uppercase;">Kind</th>
            <th style="text-align:left;padding:1mm 2mm;border-bottom:1px solid #d1d5db;font-size:7pt;text-transform:uppercase;">Stage</th>
            <th style="text-align:left;padding:1mm 2mm;border-bottom:1px solid #d1d5db;font-size:7pt;text-transform:uppercase;">Message</th>
          </tr>
        </thead>
        <tbody>{rows_html}</tbody>
      </table>
    </section>
    """


def _audit_section(report: Dict[str, Any]) -> str:
    target = report.get("target_url") or "—"
    consent = report.get("consent_method") or "none"
    started = _fmt_ts(report.get("started_at", 0))
    finished = _fmt_ts(report.get("finished_at", 0))
    mode = report.get("mode") or "—"

    return f"""
    <section class="continuous">
      <div class="running" data-target="{_esc(target)}"></div>
      <h1 class="section-title"><span class="num">§7</span>Audit &amp; Authorization</h1>

      <div class="kv-grid">
        <div class="kv-cell"><div class="k">Target</div><div class="v" style="font-size:9pt;word-break:break-all;">{_esc(target)}</div></div>
        <div class="kv-cell"><div class="k">Consent method</div><div class="v" style="font-size:9pt;">{_esc(consent)}</div></div>
        <div class="kv-cell"><div class="k">Engagement mode</div><div class="v">{_esc(mode)}</div></div>
        <div class="kv-cell"><div class="k">Started (UTC)</div><div class="v" style="font-size:9pt;">{_esc(started)}</div></div>
        <div class="kv-cell"><div class="k">Finished (UTC)</div><div class="v" style="font-size:9pt;">{_esc(finished)}</div></div>
        <div class="kv-cell"><div class="k">Duration</div><div class="v">{report.get('duration_s', 0):.2f} seconds</div></div>
      </div>

      <h2 class="sub">Legal ceiling</h2>
      <p class="legal">This report was generated by <strong>Argos</strong>, the
      offensive agent of AMOSKYS Web. All techniques employed here are lawful
      under U.S. law when one of the following holds:</p>
      <ol class="legal" style="margin-left:6mm;">
        <li><strong>Report mode</strong> operates exclusively on OSINT sources
            (DNS, Certificate Transparency logs, public headers, well-known
            paths documented in the WordPress ecosystem). No consent is
            required; these queries are not materially different from a web
            browser's normal operation.</li>
        <li><strong>Confirm / Exploit mode</strong> requires one of: (a) the
            target is within a public bug-bounty scope asserted by the operator
            via a <code>bounty:&lt;program&gt;</code> token; (b) the operator
            holds a signed statement of work asserted via <code>sow:&lt;client&gt;</code>;
            or (c) the target is the operator's own infrastructure
            (<code>AMOSKYS_CONSENT_DOMAIN</code> env match or loopback).</li>
      </ol>
      <p class="legal">See <em>Van Buren v. United States</em>, 593 U.S. ___
      (2021) (CFAA §1030(a)(2)(C) requires scope violation, not merely
      unauthorized intent) and <em>hiQ Labs, Inc. v. LinkedIn Corp.</em>, 31
      F.4th 1180 (9th Cir. 2022) (scraping public data does not violate
      CFAA).</p>

      <h2 class="sub">Chain of custody</h2>
      <p class="legal">Every event logged in §6 is timestamped with monotonic
      sequence numbers. The source code for Argos is published at
      <code>github.com/Vardhan-225/Amoskys</code> under the
      <code>amoskys-web/foundations</code> branch. Any finding in this report
      may be independently reproduced by rerunning the engagement against the
      same target at the same mode.</p>

      <div class="sig-line">
        Issued by AMOSKYS Web · Argos Campaign Orchestrator v2.4 ·
        Generated {_esc(finished)}
      </div>
    </section>
    """


# ── Public entry point ────────────────────────────────────────────


def render_campaign_html_for_pdf(report: Dict[str, Any]) -> str:
    """Build the customer-grade HTML that WeasyPrint will turn into PDF."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Argos Pentest Report — {_esc(report.get("target_url") or "target")}</title>
  <style>{_CSS}</style>
</head>
<body>
{_cover(report)}
{_toc()}
{_executive(report)}
{_architecture(report)}
{_strategy(report)}
{_chains_section(report)}
{_findings_section(report)}
{_timeline_section(report)}
{_audit_section(report)}
</body>
</html>
"""


def render_campaign_pdf(report: Dict[str, Any]) -> bytes:
    """Render a CampaignReport dict to a customer-grade PDF.

    Raises RuntimeError if WeasyPrint is not importable. Caller is
    responsible for catching this and falling back to HTML if desired.
    """
    try:
        from weasyprint import HTML as _WP_HTML  # type: ignore
    except ImportError as exc:  # noqa: BLE001
        raise RuntimeError(
            "WeasyPrint not installed — "
            "`pip install weasyprint` and ensure libpango is present"
        ) from exc
    html_str = render_campaign_html_for_pdf(report)
    return _WP_HTML(string=html_str).write_pdf()


__all__ = ["render_campaign_html_for_pdf", "render_campaign_pdf"]
