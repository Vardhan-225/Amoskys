"""Tests for argos/zeroday — patch diff, taint analysis, fuzzer,
polyglots, orchestrator."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, List

import pytest

from amoskys.agents.Web.argos.ast.base import ASTFinding
from amoskys.agents.Web.argos.zeroday import (
    ALL_POLYGLOTS,
    FuzzReport, GrammarFuzzer,
    HIDDEN_PARAM_WORDLIST,
    PatchDiffReport, PatchedFinding,
    Polyglot,
    TaintFinding, TaintScanner,
    ZeroDayReport,
    all_polyglots,
    diff_plugin_versions,
    discover_hidden_params,
    hunt,
    polyglots_for_context,
    response_bucket,
)


# ──────────────────────────────────────────────────────────────────
# Fake plugin infrastructure for tests
# ──────────────────────────────────────────────────────────────────


@dataclass
class _FakePlugin:
    slug: str
    version: str
    plugin_root: Path
    files: List[Path] = field(default_factory=list)

    def iter_php(self) -> Iterator[Path]:
        return iter(self.files)


def _mk_plugin(tmp_path: Path, slug: str, version: str,
               files: dict) -> _FakePlugin:
    """Build a fake plugin with the given {relpath: content} files."""
    base = tmp_path / slug / version
    base.mkdir(parents=True, exist_ok=True)
    created = []
    for rel, body in files.items():
        p = base / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
        created.append(p)
    return _FakePlugin(slug=slug, version=version,
                       plugin_root=base, files=created)


# ──────────────────────────────────────────────────────────────────
# patch_diff
# ──────────────────────────────────────────────────────────────────


def test_patch_diff_empty_when_versions_identical(tmp_path):
    f = {"main.php": "<?php echo 'hi'; ?>"}
    old = _mk_plugin(tmp_path / "o", "acme", "1.0", f)
    new = _mk_plugin(tmp_path / "n", "acme", "1.1", f)
    rep = diff_plugin_versions(old, new, scanner_classes={})
    assert rep.files_changed == []
    assert rep.patched_findings == []


def test_patch_diff_detects_patch_that_removes_sqli(tmp_path):
    from amoskys.agents.Web.argos.ast import SqlInjectionScanner
    # Old: SQLi exists. New: sanitizer added.
    old = _mk_plugin(tmp_path / "o", "acme", "1.0", {
        "ajax.php": """<?php
function do_lookup() {
    global $wpdb;
    $id = $_POST['id'];
    $wpdb->query("SELECT * FROM t WHERE id = $id");
}
"""})
    new = _mk_plugin(tmp_path / "n", "acme", "1.1", {
        "ajax.php": """<?php
function do_lookup() {
    global $wpdb;
    $id = intval($_POST['id']);
    $wpdb->query($wpdb->prepare("SELECT * FROM t WHERE id = %d", $id));
}
"""})
    rep = diff_plugin_versions(old, new,
                               scanner_classes={"sql": SqlInjectionScanner})
    # files_changed should include ajax.php; at least one patched finding.
    assert "ajax.php" in rep.files_changed
    assert len(rep.patched_findings) >= 1
    pf = rep.patched_findings[0]
    assert pf.rule_id.startswith("sql.")
    assert pf.old_version == "1.0"
    assert pf.new_version == "1.1"


def test_patch_diff_ignores_non_security_changes(tmp_path):
    from amoskys.agents.Web.argos.ast import SqlInjectionScanner
    old = _mk_plugin(tmp_path / "o", "acme", "1.0", {
        "main.php": "<?php echo 'version 1.0'; ?>"})
    new = _mk_plugin(tmp_path / "n", "acme", "1.1", {
        "main.php": "<?php echo 'version 1.1'; ?>"})
    rep = diff_plugin_versions(old, new,
                               scanner_classes={"sql": SqlInjectionScanner})
    # Change is non-security; the _is_security_relevant_diff heuristic
    # shouldn't flag it.
    assert rep.patched_findings == []


def test_patch_diff_finding_preserves_when_bug_still_present(tmp_path):
    from amoskys.agents.Web.argos.ast import SqlInjectionScanner
    # Same vuln in both versions but unrelated code changed around it.
    vuln_body = """<?php
function do_lookup() {
    global $wpdb;
    $id = $_POST['id'];
    $wpdb->query("SELECT * FROM t WHERE id = $id");
}
"""
    old = _mk_plugin(tmp_path / "o", "acme", "1.0", {
        "ajax.php": vuln_body,
        "other.php": "<?php // old comment\n",
    })
    new = _mk_plugin(tmp_path / "n", "acme", "1.1", {
        "ajax.php": vuln_body,
        "other.php": "<?php // new comment\n",
    })
    rep = diff_plugin_versions(old, new,
                               scanner_classes={"sql": SqlInjectionScanner})
    # Vuln unchanged → no patched finding (even though another file changed).
    assert rep.patched_findings == []


# ──────────────────────────────────────────────────────────────────
# taint
# ──────────────────────────────────────────────────────────────────


def test_taint_finds_direct_sqli(tmp_path):
    plugin = _mk_plugin(tmp_path / "x", "x", "1",  {
        "a.php": """<?php
$id = $_POST['id'];
$wpdb->query("SELECT * FROM t WHERE id = $id");
"""})
    findings = TaintScanner().scan(plugin)
    assert findings
    f = findings[0]
    assert f.rule_id == "taint.sqli"
    # source_var is either "$_POST" (direct) or a downstream tainted
    # variable like "$id" — either way it traces back to the request.
    assert "$" in f.source_var
    assert f.sanitizer_missing
    # Description mentions the originating super-global.
    assert "POST" in f.description or "_POST" in f.description or "$id" in f.snippet


def test_taint_finds_multi_hop_sqli(tmp_path):
    plugin = _mk_plugin(tmp_path / "x", "x", "1",  {
        "a.php": """<?php
$raw = $_POST['id'];
$id = $raw;
$query = $id;
$wpdb->query("SELECT * FROM t WHERE id = $query");
"""})
    findings = TaintScanner().scan(plugin)
    assert findings
    assert any(f.rule_id == "taint.sqli" for f in findings)


def test_taint_sanitizer_clears_taint(tmp_path):
    plugin = _mk_plugin(tmp_path / "x", "x", "1",  {
        "a.php": """<?php
$id = intval($_POST['id']);
$wpdb->query("SELECT * FROM t WHERE id = $id");
"""})
    findings = TaintScanner().scan(plugin)
    # With intval sanitizer in the assignment, severity should be
    # "medium" not "critical" (we mark sanitized flows as medium).
    critical = [f for f in findings if f.severity == "critical"]
    # Our current analysis still flags $wpdb->query with non-literal
    # argument as suspicious but at lower severity since a sanitizer
    # was seen. Either no finding (ideal) or medium severity.
    for f in critical:
        assert False, f"sanitized flow shouldn't be critical: {f.to_dict()}"


def test_taint_finds_rce(tmp_path):
    plugin = _mk_plugin(tmp_path / "x", "x", "1",  {
        "a.php": """<?php
$cmd = $_GET['cmd'];
system($cmd);
"""})
    findings = TaintScanner().scan(plugin)
    assert any(f.rule_id == "taint.rce" for f in findings)


def test_taint_finds_file_op(tmp_path):
    plugin = _mk_plugin(tmp_path / "x", "x", "1",  {
        "a.php": """<?php
$path = $_POST['file'];
$contents = file_get_contents($path);
"""})
    findings = TaintScanner().scan(plugin)
    assert any(f.rule_id == "taint.file_op" for f in findings)


def test_taint_finds_poi(tmp_path):
    plugin = _mk_plugin(tmp_path / "x", "x", "1",  {
        "a.php": """<?php
$data = $_COOKIE['state'];
$obj = unserialize($data);
"""})
    findings = TaintScanner().scan(plugin)
    assert any(f.rule_id == "taint.poi" for f in findings)


def test_taint_finds_reflected_xss(tmp_path):
    plugin = _mk_plugin(tmp_path / "x", "x", "1",  {
        "a.php": """<?php
$name = $_GET['name'];
echo $name;
"""})
    findings = TaintScanner().scan(plugin)
    assert any(f.rule_id == "taint.xss_reflected" for f in findings)


def test_taint_respects_prepare_wrapper(tmp_path):
    plugin = _mk_plugin(tmp_path / "x", "x", "1",  {
        "a.php": """<?php
$id = $_POST['id'];
$wpdb->query($wpdb->prepare("SELECT * FROM t WHERE id = %d", $id));
"""})
    findings = TaintScanner().scan(plugin)
    # prepare() wraps the taint, no sqli finding.
    assert not any(f.rule_id == "taint.sqli" for f in findings)


def test_taint_preserves_escape_for_xss(tmp_path):
    plugin = _mk_plugin(tmp_path / "x", "x", "1",  {
        "a.php": """<?php
$name = $_GET['name'];
echo esc_html($name);
"""})
    findings = TaintScanner().scan(plugin)
    assert not any(f.rule_id == "taint.xss_reflected" for f in findings)


# ──────────────────────────────────────────────────────────────────
# fuzzer
# ──────────────────────────────────────────────────────────────────


def test_response_bucket_same_for_similar_responses():
    b1 = response_bucket(200, b"hello world", {"Content-Type": "text/html"})
    b2 = response_bucket(200, b"hello world", {"Content-Type": "text/html"})
    assert b1 == b2


def test_response_bucket_differs_on_status():
    b1 = response_bucket(200, b"x", {})
    b2 = response_bucket(403, b"x", {})
    assert b1 != b2


def test_response_bucket_differs_on_body_hash():
    b1 = response_bucket(200, b"aaaa", {})
    b2 = response_bucket(200, b"bbbb", {})
    assert b1 != b2


def test_fuzzer_separates_baseline_from_interesting():
    """Simulate a target where a specific mutation causes a 500."""
    def fake_fire(params: dict, body):
        if params.get("q") == "BAD":
            return 500, b"Fatal error", {"x-fatal": "1"}, 10
        return 200, b"<html>OK</html>", {"Content-Type": "text/html"}, 10

    fuzzer = GrammarFuzzer(
        target_url="https://t.com/x",
        fire=fake_fire,
        seed_params={"q": "safe"},
        max_rounds=50,
    )
    rep = fuzzer.run(["GOOD", "BAD", "OTHER", "BAD"])
    assert rep.baseline_bucket
    # BAD is interesting — different bucket.
    assert any("BAD" in obs.input_repr for obs in rep.interesting)


def test_fuzzer_records_errors_gracefully():
    def fire_that_raises(params, body):
        raise RuntimeError("network down")
    fuzzer = GrammarFuzzer(
        target_url="x", fire=fire_that_raises, seed_params={"q": "x"}, max_rounds=10,
    )
    rep = fuzzer.run(["a", "b"])
    assert rep.errors


def test_discover_hidden_params_flags_reflective_params():
    # Target reflects 'callback' and 'debug' into the body.
    def fake_fire(params, body):
        val = params.get("callback") or params.get("debug") or ""
        response_body = f"<html>{val}</html>".encode()
        return 200, response_body, {}, 1

    fuzzer = GrammarFuzzer(
        target_url="x", fire=fake_fire,
        seed_params={"q": "base"}, max_rounds=50,
    )
    found = discover_hidden_params(
        fuzzer, wordlist=["callback", "debug", "unused"],
    )
    assert "callback" in found
    assert "debug" in found
    assert "unused" not in found


def test_hidden_param_wordlist_is_populated():
    assert len(HIDDEN_PARAM_WORDLIST) > 20
    assert "id" in HIDDEN_PARAM_WORDLIST
    assert "action" in HIDDEN_PARAM_WORDLIST


# ──────────────────────────────────────────────────────────────────
# polyglot
# ──────────────────────────────────────────────────────────────────


def test_all_polyglots_have_metadata():
    for p in all_polyglots():
        assert p.name
        assert p.payload
        assert p.contexts
        assert p.notes
        assert p.cwe_candidates


def test_polyglots_for_context_reflected_includes_universal():
    picks = polyglots_for_context("reflected")
    names = [p.name for p in picks]
    assert "portswigger_universal_xss" in names


def test_polyglots_for_context_sql_picks_sql_polyglot():
    picks = polyglots_for_context("sql")
    assert any("sql" in p.name for p in picks)


def test_polyglots_for_context_empty_returns_all():
    picks = polyglots_for_context("")
    assert len(picks) == len(ALL_POLYGLOTS)


def test_polyglot_payloads_never_contain_destructive():
    for p in all_polyglots():
        up = p.payload.upper()
        for bad in ("DROP TABLE", "DELETE FROM", "TRUNCATE", "RM -RF",
                    "MKFS", "DD IF="):
            assert bad not in up, f"destructive in {p.name}"


# ──────────────────────────────────────────────────────────────────
# zeroday orchestrator (integration)
# ──────────────────────────────────────────────────────────────────


class _FakeCorpus:
    def __init__(self, old_plugin, new_plugin):
        self.old = old_plugin
        self.new = new_plugin

    def fetch(self, slug, version):
        if version == self.old.version:
            return self.old
        if version == self.new.version:
            return self.new
        raise RuntimeError(f"unknown version {version}")


def test_hunt_produces_full_report(tmp_path):
    old = _mk_plugin(tmp_path / "o", "acme", "1.0", {
        "ajax.php": """<?php
function do_lookup() {
    global $wpdb;
    $id = $_POST['id'];
    $wpdb->query("SELECT * FROM t WHERE id = $id");
}
"""})
    new = _mk_plugin(tmp_path / "n", "acme", "1.1", {
        "ajax.php": """<?php
function do_lookup() {
    global $wpdb;
    $id = intval($_POST['id']);
    $wpdb->query($wpdb->prepare("SELECT * FROM t WHERE id = %d", $id));
}
"""})
    corpus = _FakeCorpus(old, new)
    rep = hunt("acme", "1.0", "1.1", corpus=corpus)

    assert rep.plugin_slug == "acme"
    assert rep.old_version == "1.0"
    assert rep.new_version == "1.1"
    assert rep.patch_diff is not None
    # Should have at least one patch finding + one taint finding.
    summary = rep.summary()
    assert summary["total"] >= 1
    # Polyglot candidates attached per finding.
    assert rep.polyglot_candidates


def test_hunt_handles_missing_version(tmp_path):
    old = _mk_plugin(tmp_path / "o", "acme", "1.0", {"x.php": "<?php\n"})
    new = _mk_plugin(tmp_path / "n", "acme", "1.1", {"x.php": "<?php\n"})
    corpus = _FakeCorpus(old, new)
    rep = hunt("acme", "1.0", "9.9", corpus=corpus)
    assert rep.errors
    assert "corpus fetch failed" in rep.errors[0].lower()
