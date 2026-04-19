"""Unit tests for the SQL-injection AST scanner.

These are pure-Python tests that build tiny PluginSource fakes and
assert the scanner fires (and doesn't fire) on the expected patterns.
No WordPress, no network, no fixtures larger than inline strings.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List

import pytest

from amoskys.agents.Web.argos.ast import SqlInjectionScanner


@dataclass
class _FakePlugin:
    """Duck-typed to satisfy SqlInjectionScanner.scan's plugin argument."""

    slug: str
    version: str
    root: Path
    files: List[Path]

    def iter_php_files(self) -> Iterator[Path]:
        return iter(self.files)


def _write(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


def _run(tmp_path: Path, source: str, name: str = "t.php"):
    f = _write(tmp_path, name, source)
    plugin = _FakePlugin(slug="test-plug", version="1.0.0", root=tmp_path, files=[f])
    return SqlInjectionScanner().scan(plugin)


# ── Positive cases: each should fire ────────────────────────────────


def test_interpolated_double_quoted_query(tmp_path):
    src = '<?php $wpdb->query("SELECT * FROM t WHERE id = $id"); ?>'
    findings = _run(tmp_path, src)
    assert findings
    assert findings[0].rule_id == "sql.interpolation_in_query"
    assert findings[0].severity == "critical"
    assert findings[0].cwe == "CWE-89"


def test_interpolated_curly_brace(tmp_path):
    src = '<?php $wpdb->get_results("SELECT * FROM t WHERE k = {$row->k}"); ?>'
    findings = _run(tmp_path, src)
    assert findings
    assert findings[0].rule_id == "sql.interpolation_in_query"


def test_prepare_with_interpolation_is_critical(tmp_path):
    src = '<?php $wpdb->prepare("SELECT * FROM t WHERE id = $id"); ?>'
    findings = _run(tmp_path, src)
    assert findings
    assert findings[0].rule_id == "sql.prepare_with_interpolation"
    assert findings[0].severity == "critical"


def test_direct_request_global(tmp_path):
    src = '<?php $wpdb->query($_POST["q"]); ?>'
    findings = _run(tmp_path, src)
    assert findings
    assert findings[0].rule_id == "sql.direct_request_query"
    assert findings[0].severity == "critical"


def test_dynamic_non_literal(tmp_path):
    src = "<?php $sql = build_sql($id); $wpdb->query($sql); ?>"
    findings = _run(tmp_path, src)
    assert findings
    # Either `sql.interpolation_in_query` high or similar — both are
    # scanner's way of saying "this isn't a literal, audit it."
    assert findings[0].severity in ("high", "medium")


def test_raw_mysqli_query_with_tainted_arg(tmp_path):
    src = '<?php mysqli_query($conn, $_REQUEST["q"]); ?>'
    findings = _run(tmp_path, src)
    assert findings
    f = findings[0]
    assert f.rule_id == "sql.direct_request_query"
    assert f.severity == "critical"


def test_heredoc_interpolation(tmp_path):
    src = '''<?php
$sql = <<<SQL
SELECT * FROM t WHERE id = $id
SQL;
$wpdb->query($sql);
?>'''
    findings = _run(tmp_path, src)
    # This hits the dynamic-arg path (arg is $sql, not a literal).
    assert findings
    assert any(
        f.rule_id in ("sql.interpolation_in_query",) for f in findings
    )


def test_prepare_without_any_placeholder(tmp_path):
    src = '<?php $wpdb->prepare("SELECT 1 FROM t"); ?>'
    findings = _run(tmp_path, src)
    assert findings
    assert findings[0].rule_id == "sql.prepare_missing_placeholders"
    assert findings[0].severity == "low"


# ── Negative cases: these must NOT fire ─────────────────────────────


def test_safe_prepare_single_quoted(tmp_path):
    src = "<?php $wpdb->prepare('SELECT * FROM t WHERE id = %d', $id); ?>"
    findings = _run(tmp_path, src)
    assert not findings, f"expected no findings, got {[f.rule_id for f in findings]}"


def test_safe_prepare_double_quoted_no_interp(tmp_path):
    src = '<?php $wpdb->prepare("SELECT * FROM t WHERE name = %s", $name); ?>'
    findings = _run(tmp_path, src)
    assert not findings


def test_safe_get_var_wrapped_in_prepare(tmp_path):
    src = (
        "<?php $val = $wpdb->get_var($wpdb->prepare("
        "'SELECT v FROM t WHERE id = %d', $id)); ?>"
    )
    findings = _run(tmp_path, src)
    assert not findings


def test_single_quoted_with_dollar_is_not_interp(tmp_path):
    # Single quotes do NOT interpolate in PHP. '$id' is literal.
    src = "<?php $wpdb->query('SELECT * FROM t WHERE id = \\'$id\\''); ?>"
    findings = _run(tmp_path, src)
    # Literal string, no interp; should be clean.
    assert not findings or all(
        f.rule_id != "sql.interpolation_in_query" for f in findings
    )


def test_constant_only_raw_mysqli_is_low(tmp_path):
    src = "<?php mysql_query('SELECT 1'); ?>"
    findings = _run(tmp_path, src)
    # Raw query but constant — scanner notes it at low.
    assert findings and findings[0].severity == "low"


def test_comment_does_not_fool_interp_detection(tmp_path):
    src = '''<?php
// SELECT * FROM t WHERE id = $not_real
$wpdb->query("SELECT 1");
?>'''
    findings = _run(tmp_path, src)
    assert not findings


def test_interp_inside_comment_is_ignored(tmp_path):
    src = '''<?php
/* WHERE id = $oldthing */
$wpdb->prepare("SELECT * FROM t WHERE id = %d", $id);
?>'''
    findings = _run(tmp_path, src)
    assert not findings


# ── Metadata sanity ────────────────────────────────────────────────


def test_finding_has_cwe_and_refs(tmp_path):
    src = '<?php $wpdb->query("SELECT * FROM t WHERE id = $id"); ?>'
    findings = _run(tmp_path, src)
    assert findings
    f = findings[0]
    assert f.cwe == "CWE-89"
    assert f.mitre_techniques == ["T1190"]
    assert any("wpdb" in r for r in f.references)
    assert f.plugin_slug == "test-plug"
    assert f.plugin_version == "1.0.0"
    assert f.file_path == "t.php"
    assert f.line >= 1
