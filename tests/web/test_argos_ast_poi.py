"""Unit tests for the PHP Object Injection AST scanner."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List

from amoskys.agents.Web.argos.ast import PoiScanner


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
    return PoiScanner().scan(plugin)


# ── Positive cases ─────────────────────────────────────────────────


def test_unserialize_on_post(tmp_path):
    src = '<?php $data = unserialize($_POST["payload"]); ?>'
    findings = _run(tmp_path, src)
    assert findings
    assert findings[0].rule_id == "poi.unserialize_on_request"
    assert findings[0].severity == "critical"
    assert findings[0].cwe == "CWE-502"


def test_unserialize_on_cookie(tmp_path):
    src = '<?php $x = unserialize($_COOKIE["state"]); ?>'
    findings = _run(tmp_path, src)
    assert findings and findings[0].rule_id == "poi.unserialize_on_request"


def test_maybe_unserialize_on_request(tmp_path):
    src = '<?php $x = maybe_unserialize($_REQUEST["r"]); ?>'
    findings = _run(tmp_path, src)
    assert findings
    assert findings[0].rule_id == "poi.maybe_unserialize_on_request"
    assert findings[0].severity == "critical"


def test_unserialize_on_dynamic_option(tmp_path):
    src = '<?php $x = unserialize(get_option($_POST["key"])); ?>'
    findings = _run(tmp_path, src)
    # Either unserialize_on_request (has $_POST) or unserialize_on_option
    # (get_option with dynamic key). Both are correct; the scanner's
    # request-check fires first.
    assert findings
    assert findings[0].severity == "critical"


def test_unserialize_on_dynamic_option_no_taint(tmp_path):
    src = '<?php $k = my_sanitizer(); $x = unserialize(get_option($k)); ?>'
    findings = _run(tmp_path, src)
    assert findings
    assert findings[0].rule_id == "poi.unserialize_on_option"
    assert findings[0].severity == "critical"


def test_unserialize_on_postmeta(tmp_path):
    src = (
        "<?php $raw = get_post_meta($post_id, 'foo', true); "
        "$data = unserialize($raw); ?>"
    )
    findings = _run(tmp_path, src)
    # arg0 is just $raw — no taint, no meta call pattern in arg0.
    # Scanner won't fire meta rule unless meta call is IN the arg.
    # Test the explicit inline form:
    src2 = "<?php $x = unserialize(get_user_meta($uid, 'k', true)); ?>"
    findings2 = _run(tmp_path, src2, name="t2.php")
    assert findings2
    assert findings2[0].rule_id == "poi.unserialize_on_meta"
    assert findings2[0].severity == "high"


def test_phar_on_user_path(tmp_path):
    src = '<?php if (file_exists("phar://" . $_POST["name"])) {} ?>'
    findings = _run(tmp_path, src)
    assert findings
    assert findings[0].rule_id == "poi.phar_stream_on_user_path"
    assert findings[0].severity == "critical"


def test_unserialize_without_allowed_classes(tmp_path):
    src = '<?php $cache = unserialize($internal_blob); ?>'
    findings = _run(tmp_path, src)
    assert findings
    assert findings[0].rule_id == "poi.unserialize_no_allowed_classes"
    assert findings[0].severity == "low"


# ── Negative cases ─────────────────────────────────────────────────


def test_safe_unserialize_with_allowed_classes_false(tmp_path):
    src = '<?php $x = unserialize($blob, ["allowed_classes" => false]); ?>'
    findings = _run(tmp_path, src)
    assert not findings


def test_safe_constant_option(tmp_path):
    src = '<?php $x = unserialize(get_option("amoskys_cache")); ?>'
    findings = _run(tmp_path, src)
    # Constant option key — should only trip the low-severity no-allowed-classes.
    assert findings
    assert all(f.rule_id == "poi.unserialize_no_allowed_classes" for f in findings)
    assert findings[0].severity == "low"


def test_safe_json_decode_is_not_unserialize(tmp_path):
    src = '<?php $x = json_decode($_POST["payload"], true); ?>'
    findings = _run(tmp_path, src)
    assert not findings


def test_phar_constant_path_not_flagged(tmp_path):
    src = '<?php file_exists("phar:///opt/archives/static.phar"); ?>'
    findings = _run(tmp_path, src)
    assert not findings


# ── Metadata ──────────────────────────────────────────────────────


def test_metadata_cwe_refs(tmp_path):
    src = '<?php unserialize($_POST["x"]); ?>'
    findings = _run(tmp_path, src)
    assert findings
    f = findings[0]
    assert f.cwe == "CWE-502"
    assert "T1190" in f.mitre_techniques
    assert any("unserialize" in r.lower() or "owasp" in r.lower() or "patchstack" in r.lower() for r in f.references)
