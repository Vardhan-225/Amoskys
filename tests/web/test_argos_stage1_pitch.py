"""Unit tests for Stage 1 + pitch rendering.

Mocks the underlying HTTP layer so no real network is hit.
"""

from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import patch, MagicMock

from amoskys.agents.Web.argos.pitch import (
    to_email_text,
    to_html_report,
    to_slack_teaser,
)
from amoskys.agents.Web.argos.stage1 import (
    PitchDossier,
    PitchFinding,
    Stage1,
)
from amoskys.agents.Web.argos.recon.stealth import (
    StealthDossier,
    StealthFinding,
)


def _mk_sf(category, check_id, severity, title="", observed="", mandate="m", recommendation="r",
           refs=("https://x",)):
    return StealthFinding(
        category=category, check_id=check_id, severity=severity,
        title=title, observed=observed, mandate=mandate,
        remediation=recommendation, references=list(refs),
    )


def _mock_stealth_recon_to(findings):
    """Return a callable suitable as StealthRecon(...).run replacement."""
    def _fake_run(self):
        return StealthDossier(
            target_url=self.target_url,
            target_host=self.host,
            ran_at=0.0,
            duration_s=0.0,
            http_checks=len(findings) + 3,
            findings=list(findings),
        )
    return _fake_run


# ── Stage 1 orchestration ──────────────────────────────────────────


def test_stage1_runs_with_no_findings_cleanly():
    with patch("amoskys.agents.Web.argos.stage1.StealthRecon.run",
               _mock_stealth_recon_to([])), \
         patch("amoskys.agents.Web.argos.legitimacy.LegitimacyProfile.preflight"):
        dossier = Stage1("https://example.com").run()
    assert dossier.target_host == "example.com"
    assert dossier.stealth_findings == []
    # No findings means no pitch findings either.
    assert dossier.findings == []


def test_stage1_translates_dev_leaks_to_pitch_finding():
    findings = [
        _mk_sf("dev_leaks", "dev.git", "high",
               title="/.git exposed", observed="/.git/config 200"),
        _mk_sf("dev_leaks", "dev.env", "high",
               title="/.env exposed", observed="/.env 200"),
    ]
    with patch("amoskys.agents.Web.argos.stage1.StealthRecon.run",
               _mock_stealth_recon_to(findings)), \
         patch("amoskys.agents.Web.argos.legitimacy.LegitimacyProfile.preflight"):
        dossier = Stage1("https://example.com").run()
    # The dev_leaks stealth findings should roll up to an "Information
    # Disclosure" pitch finding at high severity.
    disclosure = [f for f in dossier.findings if f.category == "Information Disclosure"]
    assert disclosure
    assert disclosure[0].severity == "high"
    assert disclosure[0].mandate  # mandate required


def test_stage1_translates_plugin_inventory():
    findings = [
        _mk_sf("plugin_inventory", "plugins.public_html_leak", "medium",
               title="3 plugins leaked",
               observed="contact-form-7@5.7.5; woocommerce@8.0.2"),
    ]
    with patch("amoskys.agents.Web.argos.stage1.StealthRecon.run",
               _mock_stealth_recon_to(findings)), \
         patch("amoskys.agents.Web.argos.legitimacy.LegitimacyProfile.preflight"):
        dossier = Stage1("https://example.com").run()
    pi = [f for f in dossier.findings if f.category == "Plugin Exposure"]
    assert pi
    assert "contact-form-7" in pi[0].evidence


def test_stage1_recommends_stage2_when_plugin_inventory_found():
    findings = [
        _mk_sf("plugin_inventory", "plugins.public_html_leak", "medium",
               title="X leaked", observed="akismet@5.2"),
    ]
    with patch("amoskys.agents.Web.argos.stage1.StealthRecon.run",
               _mock_stealth_recon_to(findings)), \
         patch("amoskys.agents.Web.argos.legitimacy.LegitimacyProfile.preflight"):
        dossier = Stage1("https://example.com").run()
    joined = " ".join(dossier.next_steps)
    assert "Stage-2 consent" in joined


def test_stage1_translates_user_enum_as_high():
    findings = [
        _mk_sf("user_enum", "users.wp_rest", "high",
               title="3 users disclosed", observed="admin, editor, author"),
    ]
    with patch("amoskys.agents.Web.argos.stage1.StealthRecon.run",
               _mock_stealth_recon_to(findings)), \
         patch("amoskys.agents.Web.argos.legitimacy.LegitimacyProfile.preflight"):
        dossier = Stage1("https://example.com").run()
    ae = [f for f in dossier.findings if f.category == "Account Exposure"]
    assert ae
    assert ae[0].severity == "high"


# ── Pitch email / HTML rendering ──────────────────────────────────


def test_email_text_for_empty_dossier():
    d = PitchDossier(target_url="https://x.com", target_host="x.com",
                     ran_at=0.0, duration_s=0.0, http_requests=0)
    text = to_email_text(d)
    assert "all clear" in text.lower()
    assert "x.com" in text


def test_email_text_includes_top_3_findings():
    d = PitchDossier(target_url="https://x.com", target_host="x.com",
                     ran_at=0.0, duration_s=0.0, http_requests=0,
                     findings=[
                         PitchFinding("c1", "TITLE-1", "high",  "IMPACT-1", "ev", "m"),
                         PitchFinding("c2", "TITLE-2", "medium","IMPACT-2", "ev", "m"),
                         PitchFinding("c3", "TITLE-3", "low",   "IMPACT-3", "ev", "m"),
                         PitchFinding("c4", "TITLE-4", "info",  "IMPACT-4", "ev", "m"),
                     ])
    text = to_email_text(d)
    # Subject line names the target.
    assert "x.com" in text
    # All 3 top findings appear; the 4th is elided under "more findings".
    assert "TITLE-1" in text
    assert "TITLE-2" in text
    assert "TITLE-3" in text
    assert "TITLE-4" not in text
    assert "more findings" in text


def test_html_report_escapes_content_and_includes_all():
    d = PitchDossier(target_url="https://x.com",
                     target_host="xss.example<script>alert(1)</script>",
                     ran_at=0.0, duration_s=1.0, http_requests=10,
                     findings=[
                         PitchFinding("cat", "<b>title</b>", "high",
                                      "impact", "evidence", "mandate",
                                      references=["https://x"]),
                     ])
    html = to_html_report(d)
    # Script tag content must be escaped.
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    # Title was html-escaped too.
    assert "&lt;b&gt;title&lt;/b&gt;" in html
    # Contains the mandate and footer.
    assert "mandate" in html
    assert "CFAA" in html  # footer mentions legal basis


def test_slack_teaser_shape():
    d = PitchDossier(target_url="https://x.com", target_host="x.com",
                     ran_at=0.0, duration_s=0.0, http_requests=0,
                     findings=[
                         PitchFinding("c1", "Hot finding", "high",  "i", "e", "m"),
                     ])
    t = to_slack_teaser(d)
    assert "x.com" in t
    assert "Hot finding" in t
    assert "high" in t


def test_email_note_always_includes_public_only_disclosure():
    d = PitchDossier(target_url="https://x.com", target_host="x.com",
                     ran_at=0.0, duration_s=0.0, http_requests=0,
                     findings=[
                         PitchFinding("c1", "t", "high", "i", "e", "m"),
                     ])
    text = to_email_text(d)
    # Our binding contract: every outbound email declares public-only.
    assert "publicly" in text.lower()
    assert ("not probed" in text.lower()
            or "without authorization" in text.lower())
