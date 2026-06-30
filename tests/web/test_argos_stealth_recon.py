"""Unit tests for Argos stealth recon.

These tests MOCK urllib.request.urlopen so we never hit the network.
Every test confirms one check's signal shape against a synthetic
server response. Real recon against a live target is covered by the
benchmark harness, not unit tests.
"""

from __future__ import annotations

import io
import json
from unittest.mock import MagicMock, patch

from amoskys.agents.Web.argos.recon.stealth import StealthFinding, StealthRecon


def _mock_response(
    status: int = 200, body: str = "", headers: dict = None, url: str = None
):
    """Build a mock that behaves like urllib.request.urlopen's context
    manager return value."""
    resp = MagicMock()
    resp.status = status
    resp.headers = headers or {}
    resp.url = url or "https://example.com/"
    resp.read = MagicMock(return_value=body.encode("utf-8"))
    ctx = MagicMock()
    ctx.__enter__ = MagicMock(return_value=resp)
    ctx.__exit__ = MagicMock(return_value=None)
    return ctx


def _run_with_routes(routes: dict):
    """Run StealthRecon where each path returns a predetermined _HTTPResult.

    routes: dict of path → (status, body, headers)
    Paths not listed return (404, '', {}).
    """

    def fake_urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else req
        path = url.split("://", 1)[-1].split("/", 1)[-1]
        path = "/" + path if not path.startswith("/") else path
        spec = routes.get(path, (404, "", {}))
        status, body, headers = spec
        return _mock_response(status=status, body=body, headers=headers, url=url)

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        r = StealthRecon("https://example.com", polite=False)
        return r.run()


# ── Category 1 — WP core ───────────────────────────────────────────


def test_readme_html_leaks_version():
    html = (
        "<!DOCTYPE html><html><body>"
        "<p>This is WordPress Version 6.4.2</p></body></html>"
    )
    dossier = _run_with_routes({"/readme.html": (200, html, {})})
    hits = [f for f in dossier.findings if f.check_id == "wp.readme_html"]
    assert hits
    assert "6.4.2" in hits[0].title
    assert hits[0].severity == "low"
    assert "CISA" in hits[0].mandate or "WPScan" in hits[0].mandate


def test_wp_login_reachable():
    html = "<html><body><form>WordPress Login</form></body></html>"
    dossier = _run_with_routes({"/wp-login.php": (200, html, {})})
    hits = [f for f in dossier.findings if f.check_id == "wp.login_reachable"]
    assert hits
    assert "brute-force" in hits[0].mandate.lower()


def test_rest_api_index_leaks_plugin_namespaces():
    body = json.dumps(
        {
            "namespaces": [
                "wp/v2",
                "oembed/1.0",
                "contact-form-7/v1",
                "woocommerce/v3",
                "yoast/v1",
            ],
        }
    )
    dossier = _run_with_routes({"/wp-json/": (200, body, {})})
    hits = [f for f in dossier.findings if f.check_id == "wp.rest_index"]
    assert hits
    assert "3 plugin namespaces" in hits[0].title
    assert hits[0].severity == "medium"


def test_meta_generator_leaks_version():
    html = (
        '<html><head><meta name="generator" content="WordPress 6.3.1"/>'
        "</head><body>hi</body></html>"
    )
    dossier = _run_with_routes({"/": (200, html, {})})
    hits = [f for f in dossier.findings if f.check_id == "wp.meta_generator"]
    assert hits
    assert "WordPress 6.3.1" in hits[0].title


# ── Category 2 — Dev leaks ─────────────────────────────────────────


def test_git_config_exposed():
    body = "[core]\n    repositoryformatversion = 0\n"
    dossier = _run_with_routes({"/.git/config": (200, body, {})})
    hits = [f for f in dossier.findings if f.check_id == "dev.git"]
    assert hits
    assert hits[0].severity == "high"
    assert "source tree" in hits[0].mandate.lower()


def test_env_file_exposed():
    body = "DB_PASS=supersecret\nAWS_ACCESS_KEY=AKIA..."
    dossier = _run_with_routes({"/.env": (200, body, {})})
    hits = [f for f in dossier.findings if f.check_id == "dev.env"]
    assert hits
    assert hits[0].severity == "high"


def test_wpconfig_bak_exposed():
    body = "<?php define('DB_PASSWORD', 'root'); ?>"
    dossier = _run_with_routes({"/wp-config.php.bak": (200, body, {})})
    hits = [f for f in dossier.findings if f.check_id == "dev.wpcfg_bak"]
    assert hits
    assert hits[0].severity == "high"


def test_404_dev_paths_are_not_findings():
    # No dev paths exposed — no findings in that category.
    dossier = _run_with_routes({"/": (200, "<html>ok</html>", {})})
    dev_hits = [f for f in dossier.findings if f.category == "dev_leaks"]
    assert not dev_hits


def test_dev_leak_404_page_not_flagged():
    # A WP 404 page returns 200 with a <title>Not Found</title>. Our check
    # excludes responses with <title> in the first 500 bytes.
    html = "<!DOCTYPE html><html><head><title>Not Found</title></head>...."
    dossier = _run_with_routes({"/.git/config": (200, html, {})})
    hits = [f for f in dossier.findings if f.check_id == "dev.git"]
    assert not hits


# ── Category 3 — Plugin inventory ──────────────────────────────────


def test_plugin_inventory_from_asset_urls():
    html = """<html>
<link rel='stylesheet' href='/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.7.5' />
<script src='/wp-content/plugins/woocommerce/assets/js/frontend/woocommerce.min.js?ver=8.0.2'></script>
<link href='/wp-content/plugins/yoast-seo/css/foo.css?ver=20.3' rel='stylesheet'/>
</html>"""
    dossier = _run_with_routes({"/": (200, html, {})})
    hits = [f for f in dossier.findings if f.check_id == "plugins.public_html_leak"]
    assert hits
    assert "3 plugin" in hits[0].title
    assert "contact-form-7@5.7.5" in hits[0].observed
    assert "woocommerce@8.0.2" in hits[0].observed
    assert hits[0].severity == "medium"


# ── Category 4 — Infra ─────────────────────────────────────────────


def test_infra_headers_disclose_stack():
    dossier = _run_with_routes(
        {
            "/": (
                200,
                "<html></html>",
                {
                    "Server": "nginx/1.24.0",
                    "X-Powered-By": "PHP/8.3.1",
                    "cf-ray": "abc123-DFW",
                },
            ),
        }
    )
    hits = [f for f in dossier.findings if f.check_id == "infra.headers"]
    assert hits
    assert hits[0].severity == "info"
    assert "nginx" in hits[0].observed


# ── Category 6 — User enum ─────────────────────────────────────────


def test_rest_users_endpoint_leaks():
    body = json.dumps(
        [
            {"id": 1, "slug": "admin", "name": "Admin User"},
            {"id": 2, "slug": "editor", "name": "Editor"},
        ]
    )
    dossier = _run_with_routes({"/wp-json/wp/v2/users": (200, body, {})})
    hits = [f for f in dossier.findings if f.check_id == "users.wp_rest"]
    assert hits
    assert hits[0].severity == "high"
    assert "admin" in hits[0].observed
    assert "2 user" in hits[0].title


def test_author_redirect_leaks_login():
    # urllib's follow-redirects behavior — the response.url is the landing page.
    dossier = _run_with_routes(
        {
            "/?author=1": (
                200,
                "<html></html>",
                {},
            ),  # would redirect to /author/login/
        }
    )
    # Without a real redirect, the check won't fire. Verify it doesn't crash.
    assert isinstance(dossier.findings, list)


# ── Category 7 — Supply chain ──────────────────────────────────────


def test_external_scripts_flagged():
    html = """<html><body>
<script src="https://cdn.jsdelivr.net/npm/xyz@1/dist/xyz.js"></script>
<script src="https://www.googletagmanager.com/gtm.js?id=GTM-ABC123"></script>
<script src="/wp-includes/js/jquery/jquery.js"></script>
</body></html>"""
    dossier = _run_with_routes({"/": (200, html, {})})
    hits = [f for f in dossier.findings if f.check_id == "chain.external_scripts"]
    assert hits
    assert "cdn.jsdelivr.net" in hits[0].observed
    assert "googletagmanager.com" in hits[0].observed


def test_tracking_id_leaked():
    html = '<html><script>gtag("config","GTM-ABCDEF");</script></html>'
    dossier = _run_with_routes({"/": (200, html, {})})
    hits = [f for f in dossier.findings if f.check_id == "chain.tracking_id"]
    assert hits
    assert "GTM-ABCDEF" in hits[0].observed


# ── Dossier serialization ──────────────────────────────────────────


def test_dossier_json_round_trip():
    dossier = _run_with_routes({"/": (200, "<html></html>", {})})
    js = dossier.to_json()
    parsed = json.loads(js)
    assert parsed["target_host"] == "example.com"
    assert "findings" in parsed
    assert "summary" in parsed
    assert set(parsed["summary"].keys()) == {"info", "low", "medium", "high"}


def test_every_finding_has_mandate_and_references():
    # The contract we promised: no check ships without a mandate.
    html = """<html><head>
<meta name="generator" content="WordPress 6.3.1"/>
</head><body>
<script src="https://cdn.other.com/x.js"></script>
</body></html>"""
    dossier = _run_with_routes(
        {
            "/": (200, html, {"Server": "nginx"}),
            "/readme.html": (200, "WordPress Version 6.3.1", {}),
        }
    )
    assert dossier.findings
    for f in dossier.findings:
        assert f.mandate, f"finding {f.check_id} missing mandate"
        assert f.remediation, f"finding {f.check_id} missing remediation"
        assert f.references, f"finding {f.check_id} missing references"
