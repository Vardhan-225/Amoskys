"""Argos Campaign Orchestrator.

The master pipeline. Given a target URL, runs the full kill chain:

    1. Consent gate — verify operator has authorization for this domain
    2. Passive recon — DNS, CT logs, HTTP fingerprint, OSINT
    3. Architecture fingerprint — CDN/WAF/origin/runtime/DB/OS/framework
    4. Adaptive strategy — tune tactics per architecture
    5. Origin bypass — discover and confirm origin IP if behind CDN
    6. Active probes (gated by operator mode):
        - Stealth recon (signature minimization)
        - Smuggling detector
        - Auth breach kit (if auth endpoints exist)
        - Zero-day hunter (AST + taint + fuzzer + polyglot)
        - Precision probes (one-shot-per-AST-finding)
    7. Chain reasoning — compose findings into exploit chains
    8. Report rendering — HTML + PDF + JSON

Emits events throughout so a browser can render "exactly what is
happening" in real time:

    CampaignEvent(stage, status, data, timestamp)

Modes
-----
    "report":   OSINT + passive fingerprinting only. No traffic that
                could be flagged as attack. Safe against any domain.

    "confirm":  Adds low-volume probes (fingerprint, WAF detect,
                smuggling timing). ≤30 requests. Consent advised.

    "exploit":  Fires AST-guided precision probes, evasion cascades,
                auth forgeries, race probes. Requires written
                authorization (bug-bounty scope or signed SOW).
"""

from amoskys.agents.Web.argos.campaign.events import (
    CampaignEvent,
    EventKind,
    EventBus,
    null_bus,
)
from amoskys.agents.Web.argos.campaign.orchestrator import (
    Campaign,
    CampaignMode,
    CampaignReport,
    run_campaign,
)
from amoskys.agents.Web.argos.campaign.report_html import (
    render_campaign_html,
)
from amoskys.agents.Web.argos.campaign.report_pdf import (
    render_campaign_html_for_pdf,
    render_campaign_pdf,
)

__all__ = [
    "CampaignEvent", "EventKind", "EventBus", "null_bus",
    "Campaign", "CampaignMode", "CampaignReport", "run_campaign",
    "render_campaign_html",
    "render_campaign_html_for_pdf", "render_campaign_pdf",
]
