"""Unit tests for the SSRF AST scanner."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List

from amoskys.agents.Web.argos.ast import SsrfScanner


@dataclass
class _FakePlugin:
    slug: str
    version: str
    root: Path
    files: List[Path]

    def iter_php_files(self) -> Iterator[Path]:
        return iter(self.files)


def _run(tmp_path, source, name="t.php"):
    p = tmp_path / name
    p.write_text(source, encoding="utf-8")
    plugin = _FakePlugin(slug="test", version="1", root=tmp_path, files=[p])
    return SsrfScanner().scan(plugin)


# ── Positive cases ──────────────────────────────────────────────────


def test_wp_remote_get_with_post(tmp_path):
    src = '<?php $r = wp_remote_get($_POST["url"]); ?>'
    findings = _run(tmp_path, src)
    assert findings
    assert findings[0].rule_id == "ssrf.wp_remote_request_tainted"
    assert findings[0].severity == "critical"
    assert findings[0].cwe == "CWE-918"


def test_wp_remote_post_with_get(tmp_path):
    src = '<?php wp_remote_post($_GET["target"], array("body" => "x")); ?>'
    findings = _run(tmp_path, src)
    assert findings
    assert findings[0].rule_id == "ssrf.wp_remote_request_tainted"


def test_wp_safe_remote_get_tainted(tmp_path):
    src = '<?php wp_safe_remote_get($_REQUEST["u"]); ?>'
    findings = _run(tmp_path, src)
    assert findings
    # wp_safe_remote_get is still tainted if URL is attacker-controlled.
    assert findings[0].severity == "critical"


def test_curl_setopt_tainted_url(tmp_path):
    src = '''<?php
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $_POST["endpoint"]);
curl_exec($ch);
?>'''
    findings = _run(tmp_path, src)
    assert findings
    assert findings[0].rule_id == "ssrf.curl_exec_tainted_url"
    assert findings[0].severity == "critical"


def test_file_get_contents_url_tainted(tmp_path):
    src = '<?php $body = file_get_contents($_POST["url"]); ?>'
    findings = _run(tmp_path, src)
    assert findings
    assert findings[0].rule_id == "ssrf.file_get_contents_remote_tainted"
    assert findings[0].severity == "high"


def test_dynamic_url_variable_low(tmp_path):
    src = '''<?php
$url = my_builder();
wp_remote_get($url);
?>'''
    findings = _run(tmp_path, src)
    # Dynamic but not tainted — low audit signal.
    assert findings
    assert findings[0].rule_id == "ssrf.no_url_allowlist"
    assert findings[0].severity == "low"


# ── Negative cases ──────────────────────────────────────────────────


def test_constant_url_safe(tmp_path):
    src = '<?php wp_remote_get("https://api.github.com/status"); ?>'
    findings = _run(tmp_path, src)
    assert not findings


def test_curl_setopt_constant_url(tmp_path):
    src = '''<?php
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, "https://api.my.saas.com/v1");
?>'''
    findings = _run(tmp_path, src)
    assert not findings


def test_file_get_contents_local_path(tmp_path):
    src = '<?php $data = file_get_contents(__DIR__ . "/config.json"); ?>'
    findings = _run(tmp_path, src)
    assert not findings


def test_file_get_contents_tainted_but_not_url_shape(tmp_path):
    # The path variable isn't URL-shaped — local path usage.
    src = '<?php $data = file_get_contents($_POST["filename"]); ?>'
    findings = _run(tmp_path, src)
    # Variable `filename` isn't one of our URL-named vars; scanner skips.
    # (A separate LFI scanner should catch this — not this one.)
    assert not findings


# ── Metadata sanity ────────────────────────────────────────────────


def test_metadata(tmp_path):
    src = '<?php wp_remote_get($_POST["url"]); ?>'
    findings = _run(tmp_path, src)
    assert findings
    f = findings[0]
    assert f.cwe == "CWE-918"
    assert any("ssrf" in r.lower() or "wp_remote" in r for r in f.references)
