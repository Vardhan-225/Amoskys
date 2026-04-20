"""Tests for argos/campaign — orchestrator + event bus."""

from __future__ import annotations

import json
import os
import time

import pytest

from amoskys.agents.Web.argos.campaign import (
    Campaign, CampaignMode, EventBus, EventKind, null_bus, run_campaign,
)
from amoskys.agents.Web.argos.chain import ChainFinding


# ──────────────────────────────────────────────────────────────────
# EventBus
# ──────────────────────────────────────────────────────────────────


def test_event_bus_emits_and_records():
    bus = EventBus()
    seen = []
    bus.subscribe(lambda e: seen.append(e))
    bus.stage_start("fingerprint", "probing")
    bus.finding("fingerprint", "sqli", "/?id=", "high", "union confirmed")
    bus.stage_end("fingerprint", "done")
    assert len(seen) == 3
    assert seen[0].kind == EventKind.STAGE_START
    assert seen[1].kind == EventKind.FINDING
    assert seen[2].kind == EventKind.STAGE_END
    # Sequence monotonic
    seqs = [e.sequence for e in seen]
    assert seqs == sorted(seqs)
    # History retained
    assert len(bus.history) == 3


def test_event_bus_subscriber_exception_does_not_stop_others():
    bus = EventBus()
    good = []
    def raising(e): raise RuntimeError("boom")
    def good_sub(e): good.append(e)
    bus.subscribe(raising)
    bus.subscribe(good_sub)
    bus.log("x", "hi")
    assert len(good) == 1


def test_event_bus_unsubscribe_works():
    bus = EventBus()
    seen = []
    unsub = bus.subscribe(lambda e: seen.append(e))
    bus.log("a", "one")
    unsub()
    bus.log("a", "two")
    assert len(seen) == 1


def test_event_serialization():
    bus = EventBus()
    bus.finding("chain", "sqli", "/?id=", "high", "union")
    d = bus.history[0].to_dict()
    assert d["kind"] == EventKind.FINDING
    assert d["data"]["finding_kind"] == "sqli"
    assert d["data"]["severity"] == "high"
    json.dumps(d)


def test_null_bus_factory():
    b = null_bus()
    assert isinstance(b, EventBus)
    assert b.history == []


# ──────────────────────────────────────────────────────────────────
# Consent gating
# ──────────────────────────────────────────────────────────────────


def _no_http(url, timeout, headers):
    return (0, {}, "")


def test_consent_report_mode_allows_any_domain(monkeypatch):
    monkeypatch.delenv("AMOSKYS_CONSENT_DOMAIN", raising=False)
    rep = Campaign("https://random.example.com/", mode=CampaignMode.REPORT,
                   http_get=_no_http).run()
    assert rep.consent_verified is True
    assert "no-consent-required" in rep.consent_method


def test_consent_confirm_mode_blocks_without_token(monkeypatch):
    monkeypatch.delenv("AMOSKYS_CONSENT_DOMAIN", raising=False)
    rep = Campaign("https://somebody.com/", mode=CampaignMode.CONFIRM,
                   http_get=_no_http).run()
    assert rep.consent_verified is False
    assert "consent verification failed" in rep.errors


def test_consent_env_match(monkeypatch):
    monkeypatch.setenv("AMOSKYS_CONSENT_DOMAIN", "lab.amoskys.com")
    rep = Campaign("https://lab.amoskys.com/", mode=CampaignMode.EXPLOIT,
                   http_get=_no_http).run()
    assert rep.consent_verified is True
    assert "AMOSKYS_CONSENT_DOMAIN" in rep.consent_method


def test_consent_env_matches_subdomain(monkeypatch):
    monkeypatch.setenv("AMOSKYS_CONSENT_DOMAIN", "amoskys.com")
    rep = Campaign("https://lab.amoskys.com/", mode=CampaignMode.CONFIRM,
                   http_get=_no_http).run()
    assert rep.consent_verified is True


def test_consent_bounty_token(monkeypatch):
    monkeypatch.delenv("AMOSKYS_CONSENT_DOMAIN", raising=False)
    rep = Campaign("https://some.bounty.target/",
                   mode=CampaignMode.CONFIRM,
                   consent_token="bounty:hackerone-acme",
                   http_get=_no_http).run()
    assert rep.consent_verified is True
    assert rep.consent_method == "bounty:hackerone-acme"


def test_consent_sow_token(monkeypatch):
    monkeypatch.delenv("AMOSKYS_CONSENT_DOMAIN", raising=False)
    rep = Campaign("https://client.example.com/",
                   mode=CampaignMode.EXPLOIT,
                   consent_token="sow:acme-corp-2026",
                   http_get=_no_http).run()
    assert rep.consent_verified is True


def test_consent_localhost_implicit(monkeypatch):
    monkeypatch.delenv("AMOSKYS_CONSENT_DOMAIN", raising=False)
    rep = Campaign("http://localhost:8080/", mode=CampaignMode.EXPLOIT,
                   http_get=_no_http).run()
    assert rep.consent_verified is True
    assert "localhost" in rep.consent_method


# ──────────────────────────────────────────────────────────────────
# End-to-end orchestration (offline via fake http)
# ──────────────────────────────────────────────────────────────────


def _wp_fake_http():
    """Deterministic fake HTTP emulating a WP site behind Cloudflare/Wordfence."""
    def _http(url, t, h):
        if url.endswith("/robots.txt"):
            return (200, {}, "User-agent: *\nDisallow: /wp-admin/")
        if url.endswith("/sitemap.xml"):
            return (200, {}, "<urlset></urlset>")
        if url.endswith("/does-not-exist-%zz-xyz"):
            return (404, {"server": "cloudflare"}, "mysql_fetch_array")
        if url.endswith("/WP-LOGIN.PHP"):
            return (404, {"server": "cloudflare"}, "")
        if url.endswith("/wp-login.php"):
            return (200, {"server": "cloudflare"}, "<form id='loginform'></form>")
        if url.endswith("/"):
            return (200, {
                "server": "cloudflare",
                "cf-ray": "abc",
                "set-cookie": "wfwaf-authcookie-xx=1",
                "x-powered-by": "PHP/8.0.30",
            }, "<meta name='generator' content='WordPress 6.4.2'>"
               "powered by wordfence backtrace")
        return (404, {}, "")
    return _http


def test_campaign_run_produces_report(monkeypatch):
    monkeypatch.delenv("AMOSKYS_CONSENT_DOMAIN", raising=False)
    # Avoid external DNS in discover_origin via strategy.origin_bypass=False — we
    # give framework=wordpress but no cdn to keep the test fast. Actually, our
    # fake http sets cf-ray so cdn=cloudflare will trigger origin_bypass → DNS calls.
    # Use CampaignMode.REPORT + mock the origin path via injected http_get returning empty.
    bus = EventBus()
    events = []
    bus.subscribe(lambda e: events.append(e))

    prebuilt = [
        ChainFinding(kind="rest_authz", location="/wp-json/x/y", severity="high",
                     evidence="permission_callback missing"),
    ]
    rep = Campaign("https://target.example/", mode=CampaignMode.REPORT,
                   bus=bus, http_get=_wp_fake_http(),
                   prebuilt_findings=prebuilt).run()

    assert rep.consent_verified is True
    assert rep.profile is not None
    assert rep.strategy is not None
    assert rep.finished_at > rep.started_at
    # At least one chain composed from prebuilt findings
    assert len(rep.chains) >= 1
    # Events include a full lifecycle
    kinds = [e.kind for e in events]
    assert EventKind.STAGE_START in kinds
    assert EventKind.STAGE_END in kinds
    assert EventKind.DONE in kinds


def test_campaign_emits_decision_events_for_adapted_strategy(monkeypatch):
    monkeypatch.delenv("AMOSKYS_CONSENT_DOMAIN", raising=False)
    bus = EventBus()
    Campaign("https://target.example/", mode=CampaignMode.REPORT,
              bus=bus, http_get=_wp_fake_http()).run()
    decisions = [e for e in bus.history if e.kind == EventKind.DECISION]
    assert any("probe_order" in d.message for d in decisions)
    assert any("encoding_cascade" in d.message for d in decisions)


def test_campaign_chains_findings_from_event_stream_and_prebuilt(monkeypatch):
    monkeypatch.delenv("AMOSKYS_CONSENT_DOMAIN", raising=False)
    bus = EventBus()
    # Seed the campaign with a finding that triggers a chain rule
    prebuilt = [
        ChainFinding(kind="file_upload", location="/upload", severity="high",
                     evidence="jpg polyglot"),
        ChainFinding(kind="lfi", location="/read", severity="high",
                     evidence="wp-config base64 leaked"),
    ]
    rep = Campaign("https://wp.example/", mode=CampaignMode.REPORT,
                    bus=bus, http_get=_wp_fake_http(),
                    prebuilt_findings=prebuilt).run()
    names = [c["name"] for c in rep.chains]
    assert any("upload" in n.lower() and "LFI" in n for n in names)


def test_campaign_fatal_recorded_on_no_consent(monkeypatch):
    monkeypatch.delenv("AMOSKYS_CONSENT_DOMAIN", raising=False)
    bus = EventBus()
    rep = Campaign("https://nothing-authorized.example/", mode=CampaignMode.EXPLOIT,
                    bus=bus, http_get=_no_http).run()
    assert rep.consent_verified is False
    fatal = [e for e in bus.history if e.kind == EventKind.FATAL]
    assert fatal
    assert "NO CONSENT" in fatal[0].message


def test_campaign_report_to_dict_is_json_safe(monkeypatch):
    monkeypatch.delenv("AMOSKYS_CONSENT_DOMAIN", raising=False)
    rep = Campaign("https://t.example/", mode=CampaignMode.REPORT,
                    http_get=_wp_fake_http()).run()
    json.dumps(rep.to_dict())


def test_run_campaign_one_liner(monkeypatch):
    monkeypatch.delenv("AMOSKYS_CONSENT_DOMAIN", raising=False)
    rep = run_campaign("https://t.example/", mode=CampaignMode.REPORT,
                       http_get=_wp_fake_http())
    assert rep.mode == CampaignMode.REPORT
    assert rep.finished_at > 0
