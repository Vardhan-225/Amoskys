"""Render a PitchDossier into a format you can send to a prospect.

Three outputs:
  - to_email_text(dossier)    — short form, 200-400 words, for first-touch
  - to_html_report(dossier)   — full report, styled HTML for email / PDF
  - to_slack_teaser(dossier)  — 3-line tl;dr with one eye-catching number

Business voice, not hacker voice. We're not trying to scare — we're
trying to be helpful. The tone we're going for:

    "I noticed a few things that are visible publicly. Here's what
     they mean and how we can help."

Every claim is backed by a mandate citation from the dossier.
"""

from __future__ import annotations

import html
import time
from typing import List

from amoskys.agents.Web.argos.stage1 import PitchDossier, PitchFinding


# ── Email (plain text, first-touch friendly) ──────────────────────


def to_email_text(dossier: PitchDossier, sender_name: str = "AMOSKYS Web") -> str:
    counts = dossier.severity_counts()
    total = sum(counts.values())
    if total == 0:
        return _email_all_clear(dossier, sender_name)

    lines = []
    lines.append(f"Subject: Public exposure review for {dossier.target_host}")
    lines.append("")
    lines.append(f"Hi there,")
    lines.append("")
    lines.append(
        f"I ran a light, public-only review of {dossier.target_host} this morning — "
        f"the kind of check any visitor to your site could do. I found "
        f"{total} items worth flagging:"
    )
    lines.append("")

    # Top 3 findings by severity
    sev_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    top = sorted(
        dossier.findings,
        key=lambda f: (sev_order.get(f.severity, 9), f.category),
    )[:3]
    for i, f in enumerate(top, 1):
        lines.append(f"  {i}. [{f.severity.upper()}] {f.title}")
        lines.append(f"     {f.one_line_impact}")
        lines.append("")

    if len(dossier.findings) > 3:
        lines.append(
            f"({len(dossier.findings) - 3} more findings in the full report — "
            f"reply and I'll send it over.)"
        )
        lines.append("")

    # Pitch
    lines.append(
        "Happy to walk through the full report and show how we'd block "
        "this class of exposure in under 60 seconds on your site. "
        "No cost, no obligation — just useful."
    )
    lines.append("")
    lines.append(f"— {sender_name}")
    lines.append("")
    lines.append(
        "P.S. This review used only information your site serves publicly. "
        "Nothing was probed, brute-forced, or accessed without authorization."
    )
    return "\n".join(lines)


def _email_all_clear(dossier: PitchDossier, sender_name: str) -> str:
    return (
        f"Subject: {dossier.target_host} public review — all clear\n\n"
        f"Hi there,\n\n"
        f"I ran a light public review of {dossier.target_host} — nothing "
        f"visible-to-the-public stood out as an exposure. Your posture is "
        f"above average.\n\n"
        f"If you'd ever like a deeper (consented) security assessment, "
        f"that's what we do.\n\n"
        f"— {sender_name}\n"
    )


# ── Slack / chat teaser ───────────────────────────────────────────


def to_slack_teaser(dossier: PitchDossier) -> str:
    counts = dossier.severity_counts()
    total = sum(counts.values())
    if total == 0:
        return f":white_check_mark: {dossier.target_host} — surface looks clean."
    headline = next(
        (f for f in dossier.findings if f.severity == "high"),
        next((f for f in dossier.findings if f.severity == "medium"), None),
    )
    if headline:
        return (
            f":warning: *{dossier.target_host}* — {total} public exposures. "
            f"Top: _{headline.title}_ (severity: {headline.severity})"
        )
    return f":information_source: *{dossier.target_host}* — {total} info-level items worth a look."


# ── HTML report (for email / PDF rendering via WeasyPrint) ────────


# Severity weights for the posture score (0-100 display scale).
_SEV_WEIGHTS = {"high": 25, "medium": 10, "low": 3, "info": 1}


def _report_id(dossier: PitchDossier) -> str:
    """Deterministic short report ID — shown on the cover for reference."""
    host_key = "".join(c if c.isalnum() else "" for c in dossier.target_host)[:12]
    return f"AMSW-{host_key.upper()}-{int(dossier.ran_at)}"


def _posture_score(dossier: PitchDossier) -> int:
    """100 is 'no public findings'; every high costs 25, every medium 10, etc.
    Clamped at 0."""
    deduct = sum(
        _SEV_WEIGHTS.get(f.severity, 0) for f in dossier.findings
    )
    return max(0, 100 - deduct)


def _verdict_label(score: int) -> tuple:
    """(label, tone-class, one-line summary) for the cover."""
    if score >= 90:
        return ("STRONG", "ok",
                "Public-surface posture is above industry norm.")
    if score >= 70:
        return ("ADEQUATE", "warn",
                "A few visible items to close — most sites score here.")
    if score >= 40:
        return ("AT RISK", "risk",
                "Multiple public exposures that narrow an attacker's path.")
    return ("URGENT", "urgent",
            "Critical public exposures that require immediate attention.")


_CSS = """
  @page { size: A4; margin: 18mm 14mm; }
  :root {
    --fg: #1a1a1a;
    --fg-2: #4a4a4a;
    --fg-mut: #6b7280;
    --bg: #ffffff;
    --rule: #e5e7eb;
    --rule-strong: #111111;
    --accent: #111111;
    --ok: #065f46;
    --warn: #92400e;
    --risk: #b45309;
    --urgent: #991b1b;
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; }
  body {
    font-family: "Inter", -apple-system, BlinkMacSystemFont,
                 "Segoe UI", Helvetica, Arial, sans-serif;
    color: var(--fg);
    background: var(--bg);
    line-height: 1.55;
    font-size: 14px;
    max-width: 880px;
    margin: 2.5rem auto;
    padding: 0 2rem;
  }
  .masthead { display: flex; align-items: center; justify-content: space-between;
              border-bottom: 2px solid var(--rule-strong);
              padding-bottom: .6rem; margin-bottom: 1.25rem; }
  .brand { font-weight: 800; letter-spacing: .06em;
           text-transform: uppercase; font-size: .95rem; }
  .brand small { display: block; font-weight: 500; letter-spacing: normal;
                 text-transform: none; color: var(--fg-mut); font-size: .7rem;
                 margin-top: 2px; }
  .meta { text-align: right; font-size: .78rem; color: var(--fg-mut); }
  h1 { font-size: 1.9rem; margin: 2rem 0 .25rem 0; line-height: 1.2; }
  h1 + .lede { color: var(--fg-2); font-size: 1.05rem; margin: 0 0 1.5rem 0; }
  h2 { font-size: 1.25rem; margin: 2.5rem 0 .5rem 0;
       border-top: 1px solid var(--rule); padding-top: 1rem; }
  h3 { font-size: 1.0rem; margin: 1.2rem 0 .2rem 0; }
  .kv { display: grid; grid-template-columns: 160px 1fr; gap: .3rem .75rem;
        font-size: .88rem; margin: .75rem 0; }
  .kv dt { color: var(--fg-mut); font-weight: 500; }
  .kv dd { margin: 0; font-variant-numeric: tabular-nums; }
  .verdict { border: 1px solid var(--rule); border-radius: 6px;
             padding: 1.1rem 1.25rem; margin: 1.25rem 0 1.5rem 0;
             background: #fafafa; display: flex; gap: 1.25rem; align-items: center; }
  .verdict .label { font-weight: 800; font-size: 1.1rem; letter-spacing: .04em; }
  .verdict .label.ok    { color: var(--ok); }
  .verdict .label.warn  { color: var(--warn); }
  .verdict .label.risk  { color: var(--risk); }
  .verdict .label.urgent{ color: var(--urgent); }
  .score-ring { width: 76px; height: 76px; border-radius: 50%;
                border: 6px solid var(--rule); display: flex;
                align-items: center; justify-content: center;
                font-weight: 800; font-size: 1.5rem; flex-shrink: 0; }
  .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr);
                  gap: .6rem; margin: 1rem 0 2rem 0; }
  .cell { background: #fff; border: 1px solid var(--rule);
          border-radius: 6px; padding: .85rem .95rem; }
  .cell .n { font-size: 1.5rem; font-weight: 700;
             font-variant-numeric: tabular-nums; }
  .cell .l { font-size: .7rem; color: var(--fg-mut);
             text-transform: uppercase; letter-spacing: .06em; margin-top: .2rem; }
  .toc { border: 1px solid var(--rule); border-radius: 6px;
         padding: 1rem 1.25rem; margin: 1rem 0 2rem 0;
         background: #fafafa; }
  .toc ol { margin: .25rem 0 0 1.25rem; padding: 0; }
  .toc li { margin-bottom: .25rem; font-size: .92rem; }
  .toc a { color: var(--fg); text-decoration: none; }
  .badge { display: inline-block; padding: .1rem .55rem; border-radius: 4px;
           font-size: .72rem; font-weight: 700; text-transform: uppercase;
           letter-spacing: .05em; vertical-align: middle; }
  .sev-high    { background: #fee2e2; color: #991b1b; }
  .sev-medium  { background: #fef3c7; color: #92400e; }
  .sev-low     { background: #e0f2fe; color: #075985; }
  .sev-info    { background: #f3f4f6; color: #4b5563; }
  .finding { border: 1px solid var(--rule); border-radius: 6px;
             padding: 1.1rem 1.25rem; margin-bottom: 1rem;
             background: #ffffff; break-inside: avoid; }
  .finding .head { display: flex; justify-content: space-between;
                   align-items: baseline; margin-bottom: .4rem; gap: 1rem; }
  .finding .head .id { font-size: .72rem; color: var(--fg-mut);
                       font-family: ui-monospace, monospace; }
  .finding h3 { margin: 0; font-size: 1.02rem; }
  .finding .category { font-size: .72rem; color: var(--fg-mut);
                       text-transform: uppercase; letter-spacing: .06em;
                       margin-bottom: .25rem; }
  .impact { color: var(--fg-2); margin: .5rem 0 .9rem 0; }
  .evidence { font-family: ui-monospace, "Courier New", monospace;
              font-size: .76rem; background: #fafafa;
              border: 1px solid var(--rule); border-radius: 4px;
              padding: .55rem .75rem;
              white-space: pre-wrap; word-break: break-all; }
  .mandate { font-size: .84rem; color: var(--fg-2); margin-top: .75rem;
             border-left: 3px solid var(--rule); padding-left: .75rem; }
  .mandate strong { color: var(--fg); }
  .remediation { font-size: .84rem; margin-top: .5rem;
                 padding: .55rem .75rem; background: #f0fdf4;
                 border-left: 3px solid var(--ok); }
  .remediation strong { color: var(--ok); }
  .refs { font-size: .72rem; color: var(--fg-mut); margin-top: .5rem; }
  .refs a { color: var(--fg-mut); }
  .action-card { border: 1px solid var(--rule); border-radius: 6px;
                 padding: 1rem 1.25rem; margin: 1rem 0;
                 background: #fffbeb; }
  .legal { border-top: 1px solid var(--rule); margin-top: 3.5rem;
           padding-top: 1.25rem; font-size: .75rem; color: var(--fg-mut); }
  .legal h4 { font-size: .85rem; margin: 0 0 .35rem 0; color: var(--fg-2); }
  .pagebreak { page-break-before: always; }
"""


def _html_head(host: str, report_id: str) -> str:
    return (
        "<!doctype html><html lang=\"en\"><head>"
        "<meta charset=\"utf-8\"/>"
        f"<title>Public Exposure Review — {host} ({report_id})</title>"
        f"<style>{_CSS}</style></head><body>"
    )


def _masthead(dossier: PitchDossier, report_id: str) -> str:
    scanned_at = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(dossier.ran_at))
    return (
        f'<div class="masthead">'
        f'  <div class="brand">AMOSKYS WEB<small>Public Exposure Review</small></div>'
        f'  <div class="meta">'
        f'    <div><strong>{html.escape(report_id)}</strong></div>'
        f'    <div>{scanned_at}</div>'
        f'  </div>'
        f'</div>'
    )


def _cover_block(dossier: PitchDossier) -> str:
    host = html.escape(dossier.target_host)
    score = _posture_score(dossier)
    label, tone, blurb = _verdict_label(score)
    counts = dossier.severity_counts()
    fields = [
        ("Target",                html.escape(dossier.target_url)),
        ("Scan type",             "Stage 1 — OSINT, public-surface only"),
        ("Method",                f"{dossier.http_requests} polite HTTP requests over {dossier.duration_s:.0f}s"),
        ("Authorization",         "None required — anonymous-visitor-equivalent access"),
        ("Findings",              f"{len(dossier.findings)} total · "
                                   f"{counts['high']} high · "
                                   f"{counts['medium']} medium · "
                                   f"{counts['low']} low · "
                                   f"{counts['info']} info"),
    ]
    kv_html = "".join(
        f'<dt>{html.escape(k)}</dt><dd>{v}</dd>'
        for k, v in fields
    )
    return (
        f'<h1>Public Exposure Review</h1>'
        f'<p class="lede">A light, consent-free assessment of everything '
        f'<strong>{host}</strong> currently reveals to an anonymous visitor. '
        f'No probes. No brute-force. No authorization bypass.</p>'
        f'<div class="verdict">'
        f'  <div class="score-ring">{score}</div>'
        f'  <div>'
        f'    <div class="label {tone}">{label}</div>'
        f'    <div style="color:var(--fg-2);">{blurb}</div>'
        f'  </div>'
        f'</div>'
        f'<dl class="kv">{kv_html}</dl>'
    )


def _summary_grid(dossier: PitchDossier) -> str:
    counts = dossier.severity_counts()
    cells = []
    for label, key in (("High", "high"), ("Medium", "medium"),
                       ("Low", "low"), ("Info", "info")):
        cells.append(
            f'<div class="cell"><div class="n">{counts[key]}</div>'
            f'<div class="l">{label}</div></div>'
        )
    return (
        '<h2 id="sec-summary">Severity at a glance</h2>'
        '<div class="summary-grid">' + "".join(cells) + '</div>'
    )


def _toc(dossier: PitchDossier) -> str:
    items = [
        ("Executive summary",        "#sec-exec"),
        ("Severity at a glance",     "#sec-summary"),
        ("Methodology & scope",      "#sec-method"),
        ("Findings",                 "#sec-findings"),
    ]
    if dossier.next_steps:
        items.append(("Recommended next steps", "#sec-actions"))
    items.append(("Scope, legal basis, and contact",  "#sec-legal"))
    li = "".join(
        f'<li><a href="{href}">{html.escape(title)}</a></li>'
        for title, href in items
    )
    return f'<div class="toc"><strong>Contents</strong><ol>{li}</ol></div>'


def _executive_summary(dossier: PitchDossier) -> str:
    host = html.escape(dossier.target_host)
    counts = dossier.severity_counts()
    if not dossier.findings:
        body = (
            f"<p>Our Stage-1 review of <strong>{host}</strong> did not "
            f"surface any public-surface exposures worth flagging. Your "
            f"site's posture is above the median — most WordPress sites "
            f"we review have at least two or three visible leaks in the "
            f"public HTML or wp-json surface.</p>"
            f"<p>This does not mean you are invulnerable — it means an "
            f"opportunistic attacker has to work harder to get a foothold. "
            f"A full consented assessment (Stage 2) is the next step if "
            f"you want end-to-end assurance.</p>"
        )
    else:
        top = sorted(dossier.findings,
                     key=lambda f: {"high": 0, "medium": 1, "low": 2, "info": 3}
                                    .get(f.severity, 9))
        hi = [f for f in top if f.severity == "high"]
        highlight = ""
        if hi:
            highlight = (
                "<p>The items marked <strong>HIGH</strong> are the ones that "
                "meaningfully shrink an attacker's work — they turn "
                "'guess everything' into 'exploit this specific version' "
                "or 'brute-force this known account.' Closing them is "
                "inexpensive and measurable.</p>"
            )
        body = (
            f"<p>During this {dossier.duration_s:.0f}-second review, Argos "
            f"made {dossier.http_requests} polite HTTP requests to "
            f"<strong>{host}</strong> — fewer than a single real visitor "
            f"would generate on a normal browse. "
            f"We identified <strong>{len(dossier.findings)}</strong> "
            f"public-surface exposure{'s' if len(dossier.findings) != 1 else ''}: "
            f"<strong>{counts['high']} high</strong>, "
            f"<strong>{counts['medium']} medium</strong>, "
            f"<strong>{counts['low']} low</strong>, and "
            f"<strong>{counts['info']} informational</strong>.</p>"
            f"{highlight}"
        )
    return f'<h2 id="sec-exec">Executive summary</h2>{body}'


def _methodology_block(dossier: PitchDossier) -> str:
    return (
        '<h2 id="sec-method">Methodology &amp; scope</h2>'
        '<p>This is a Stage-1 review: everything we checked is data your '
        'site serves to any anonymous visitor. No authentication was '
        'bypassed; no form was submitted; no payload was injected; no '
        'password was guessed. Each check below was a single HTTP GET to '
        'a public path, at gaussian-jittered pacing centered on roughly '
        'three seconds between requests &mdash; the rhythm of a human '
        'reader, not a scanner.</p>'
        '<p><strong>What we looked at:</strong></p>'
        '<ul>'
        '<li>Standard WordPress fingerprints &mdash; /readme.html, '
        '<code>&lt;meta name="generator"&gt;</code>, the REST API index, '
        'RSS feeds, and the public plugin list referenced in your HTML.</li>'
        '<li>Common developer-artifact paths &mdash; /.git, /.env, '
        'wp-config backups, Composer/npm manifests. Each one is a '
        'single HTTP GET; 200 responses indicate exposure.</li>'
        '<li>Infrastructure identifiers from response headers &mdash; '
        'Server, X-Powered-By, CDN fingerprints.</li>'
        '<li>User-enumeration via the standard <code>?author=N</code> '
        'redirect and the <code>/wp-json/wp/v2/users</code> REST index '
        '(one probe each; we do not iterate).</li>'
        '<li>Third-party scripts and tracking IDs included in your HTML '
        '&mdash; a quick snapshot of your visible supply-chain surface.</li>'
        '<li>Polite preflights: <code>robots.txt</code> '
        '(RFC&nbsp;9309) and <code>/.well-known/security.txt</code> '
        '(RFC&nbsp;9116).</li>'
        '</ul>'
        '<p><strong>What we did not do:</strong> any active attack. '
        'That belongs to a Stage-2 engagement, which is consented, '
        'scoped, and contractually bounded.</p>'
    )


def _findings_block(dossier: PitchDossier) -> str:
    if not dossier.findings:
        return (
            '<h2 id="sec-findings">Findings</h2>'
            '<p>No findings in this sweep. See executive summary above.</p>'
        )
    sev_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    ordered = sorted(dossier.findings,
                     key=lambda f: (sev_order.get(f.severity, 9), f.category))
    parts = ['<h2 id="sec-findings">Findings</h2>']
    for i, f in enumerate(ordered, 1):
        parts.append(_finding_html(f, index=i))
    return "".join(parts)


def _finding_html(f: PitchFinding, index: int = 0) -> str:
    fid = f"F-{index:03d}" if index else "F"
    refs_html = ""
    if f.references:
        refs_html = '<div class="refs"><strong>References: </strong>' + " · ".join(
            f'<a href="{html.escape(r)}">{html.escape(r)}</a>' for r in f.references
        ) + '</div>'
    remediation_html = ""
    # Try to surface a remediation line from the raw stealth-finding map.
    # PitchFinding doesn't carry remediation directly yet; the mandate +
    # one_line_impact already do. We render a positive-tone hint when we
    # have a reasonable action.
    return (
        f'<div class="finding">'
        f'<div class="category">{html.escape(f.category)}</div>'
        f'<div class="head">'
        f'  <h3>{html.escape(f.title)}</h3>'
        f'  <span class="id">{fid}</span>'
        f'</div>'
        f'<span class="badge sev-{f.severity}">{f.severity}</span>'
        f'<div class="impact">{html.escape(f.one_line_impact)}</div>'
        f'<div class="evidence">{html.escape(f.evidence)}</div>'
        f'<div class="mandate"><strong>Why it matters.</strong> '
        f'{html.escape(f.mandate)}</div>'
        f'{remediation_html}'
        f'{refs_html}'
        f'</div>'
    )


def _actions_block(dossier: PitchDossier) -> str:
    if not dossier.next_steps:
        return ""
    items = "".join(
        f'<li>{html.escape(s)}</li>' for s in dossier.next_steps
    )
    return (
        '<h2 id="sec-actions">Recommended next steps</h2>'
        f'<div class="action-card"><ol>{items}</ol></div>'
    )


def _legal_footer(dossier: PitchDossier) -> str:
    scanned_at = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(dossier.ran_at))
    return (
        '<div class="legal" id="sec-legal">'
        '<h4>Scope, legal basis, and contact</h4>'
        '<p>This review accessed only resources your website serves '
        'publicly, at a traffic volume below any reasonable rate-limit. '
        'No authentication boundary was crossed. No password, form, or '
        'injection payload was submitted.</p>'
        '<p>Legal basis: CFAA §1030(a)(2)(C) as narrowed by <em>Van Buren '
        'v. United States</em>, 141 S.&nbsp;Ct. 1648 (2021); public-data '
        'access per <em>hiQ Labs v. LinkedIn</em>, 31 F.4th 1180 '
        '(9th Cir. 2022). RFC&nbsp;9309 (robots) and RFC&nbsp;9116 '
        '(security.txt) were honored throughout.</p>'
        f'<p>Prepared by AMOSKYS Web on {scanned_at}. '
        'For a full consented pentest or to dispute any finding, reply to '
        'the email that accompanied this report.</p>'
        '</div>'
    )


def to_html_report(dossier: PitchDossier) -> str:
    """Render the full, download-ready HTML report."""
    host = html.escape(dossier.target_host)
    report_id = _report_id(dossier)

    parts = [
        _html_head(host, report_id),
        _masthead(dossier, report_id),
        _cover_block(dossier),
        _toc(dossier),
        _executive_summary(dossier),
        _summary_grid(dossier),
        _methodology_block(dossier),
        _findings_block(dossier),
        _actions_block(dossier),
        _legal_footer(dossier),
        "</body></html>",
    ]
    return "".join(parts)


def to_pdf_bytes(dossier: PitchDossier) -> bytes:
    """Render the report as PDF bytes via WeasyPrint, if available.

    Returns empty bytes and logs a warning if WeasyPrint isn't installed.
    Caller can always fall back to saving `to_html_report(...)` as .html
    and converting externally (wkhtmltopdf, headless Chrome, etc.).
    """
    try:
        from weasyprint import HTML  # type: ignore
    except Exception as e:  # noqa: BLE001
        import logging
        logging.getLogger("amoskys.argos.pitch").warning(
            "WeasyPrint unavailable (%s); skipping PDF render. "
            "Install with: pip install weasyprint", e,
        )
        return b""
    html_str = to_html_report(dossier)
    return HTML(string=html_str).write_pdf()
