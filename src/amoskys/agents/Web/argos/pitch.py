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


_HTML_HEAD = """<!doctype html>
<html><head>
<meta charset="utf-8"/>
<title>Public Exposure Report — __HOST__</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, sans-serif;
         background: #fafafa; color: #222; max-width: 780px;
         margin: 2rem auto; padding: 0 2rem; line-height: 1.6; }
  h1 { border-bottom: 2px solid #222; padding-bottom: .25rem; }
  h2 { margin-top: 2.2rem; color: #333; }
  .badge { display: inline-block; padding: .1rem .5rem; border-radius: 4px;
           font-size: .8rem; font-weight: 600; text-transform: uppercase; }
  .sev-high    { background: #fee2e2; color: #b91c1c; }
  .sev-medium  { background: #fef3c7; color: #b45309; }
  .sev-low     { background: #e0f2fe; color: #075985; }
  .sev-info    { background: #f3f4f6; color: #4b5563; }
  .finding { border: 1px solid #e5e7eb; border-radius: 6px; padding: 1rem 1.25rem;
             margin-bottom: 1rem; background: #fff; }
  .finding h3 { margin: 0 0 .35rem 0; font-size: 1.05rem; }
  .impact { color: #555; margin: .5rem 0 1rem 0; }
  .evidence { font-family: ui-monospace, "Courier New", monospace;
              font-size: .78rem; background: #f9fafb; border: 1px solid #e5e7eb;
              border-radius: 4px; padding: .5rem .75rem; overflow-x: auto; }
  .mandate { font-size: .85rem; color: #444; margin-top: .75rem;
             border-left: 3px solid #e5e7eb; padding-left: .75rem; }
  .refs { font-size: .75rem; color: #777; margin-top: .4rem; }
  .footer { border-top: 1px solid #ddd; margin-top: 3rem; padding-top: 1rem;
            font-size: .8rem; color: #555; }
  .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr);
                  gap: .75rem; margin: 1.5rem 0; }
  .summary-grid .cell { background: #fff; border: 1px solid #e5e7eb;
                        border-radius: 6px; padding: .9rem 1rem; }
  .summary-grid .cell .n { font-size: 1.6rem; font-weight: 700; }
  .summary-grid .cell .l { font-size: .75rem; color: #777;
                           text-transform: uppercase; letter-spacing: .05em; }
  .next-steps li { margin-bottom: .4rem; }
</style>
</head><body>
"""


def to_html_report(dossier: PitchDossier) -> str:
    host = html.escape(dossier.target_host)
    parts = [_HTML_HEAD.replace("__HOST__", host)]
    parts.append(f"<h1>Public Exposure Report — {host}</h1>")
    parts.append(
        f'<p class="impact">A light, consent-free review of everything your site '
        f'currently reveals to an anonymous visitor. No probes, no brute-force, '
        f'no authorization bypass. {dossier.http_requests} HTTP requests over '
        f'{dossier.duration_s:.0f} seconds — less than one real visitor would '
        f'generate on a normal browse.</p>'
    )

    counts = dossier.severity_counts()
    parts.append('<div class="summary-grid">')
    for label, key, cls in (
        ("High",    "high",    "sev-high"),
        ("Medium",  "medium",  "sev-medium"),
        ("Low",     "low",     "sev-low"),
        ("Info",    "info",    "sev-info"),
    ):
        parts.append(
            f'<div class="cell"><div class="n">{counts[key]}</div>'
            f'<div class="l">{label}</div></div>'
        )
    parts.append('</div>')

    parts.append("<h2>What we found</h2>")
    if not dossier.findings:
        parts.append("<p>Nothing of note. Your public-surface posture is above average.</p>")
    else:
        sev_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        for f in sorted(dossier.findings, key=lambda x: (sev_order.get(x.severity, 9), x.category)):
            parts.append(_finding_html(f))

    if dossier.next_steps:
        parts.append("<h2>Recommended next steps</h2>")
        parts.append("<ol class='next-steps'>")
        for s in dossier.next_steps:
            parts.append(f"<li>{html.escape(s)}</li>")
        parts.append("</ol>")

    parts.append(_footer_html(dossier))
    parts.append("</body></html>")
    return "".join(parts)


def _finding_html(f: PitchFinding) -> str:
    refs_html = ""
    if f.references:
        refs_html = '<div class="refs">Refs: ' + " · ".join(
            f'<a href="{html.escape(r)}">{html.escape(r)}</a>' for r in f.references
        ) + '</div>'
    return (
        f'<div class="finding">'
        f'<span class="badge sev-{f.severity}">{f.severity}</span> '
        f'<h3>{html.escape(f.title)}</h3>'
        f'<div class="impact">{html.escape(f.one_line_impact)}</div>'
        f'<div class="evidence">{html.escape(f.evidence)}</div>'
        f'<div class="mandate"><strong>Why it matters:</strong> '
        f'{html.escape(f.mandate)}</div>'
        f'{refs_html}'
        f'</div>'
    )


def _footer_html(dossier: PitchDossier) -> str:
    scanned_at = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(dossier.ran_at))
    return (
        f'<div class="footer">Scanned at {scanned_at} · '
        f'{dossier.http_requests} HTTP requests · '
        f'{dossier.duration_s:.1f}s duration · '
        f'AMOSKYS Web Argos Stage 1 (OSINT only). '
        f'No authorization boundary was crossed; no data not already '
        f'publicly served was accessed. This report is generated under '
        f'public-access norms and CFAA §1030(a)(2)(C) authorized-access '
        f'limits.</div>'
    )
