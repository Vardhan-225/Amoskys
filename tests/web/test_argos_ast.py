"""Argos AST scanner tests — end-to-end coverage of the bug-bounty foundation.

These tests prove the three things that must work for the bounty /
redemption pipeline to produce revenue:

    1. The PHP call-site extractor correctly identifies and parses
       register_rest_route / add_action calls, even when embedded in
       realistic plugin source (comments, nested arrays, closures).

    2. The RestAuthzScanner emits all four rule classes on crafted
       fixtures designed to mirror real CVE patterns.

    3. The PluginASTTool + Hunt wiring produces engagement-shaped
       findings from a file-on-disk plugin, with no network I/O.

We use fixture plugins built in tmp_path — no wp.org hits in tests.
Corpus integration is covered by a separate slow/optional test marker.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from amoskys.agents.Web.argos.ast import (
    RestAuthzScanner,
    PHPSource,
    find_calls,
    strip_comments_and_strings,
)
from amoskys.agents.Web.argos.ast.base import _split_top_level_ranges
from amoskys.agents.Web.argos.corpus import PluginSource
from amoskys.agents.Web.argos.hunt import Hunt
from amoskys.agents.Web.argos.tools.plugin_ast import PluginASTTool


# ── Fixture builders ───────────────────────────────────────────────

def _make_plugin(
    tmp_path: Path,
    slug: str,
    version: str,
    files: dict,
) -> PluginSource:
    """Build a PluginSource with the given .php files on disk."""
    plugin_root = tmp_path / slug / version
    plugin_root.mkdir(parents=True)
    for relpath, content in files.items():
        target = plugin_root / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    return PluginSource(
        slug=slug,
        version=version,
        extracted_root=plugin_root.parent,
        plugin_root=plugin_root,
    )


# ── Base primitives ────────────────────────────────────────────────

def test_strip_comments_masks_line_comment_preserving_length():
    src = "echo 'hi';  // this is a comment\necho 'bye';"
    masked = strip_comments_and_strings(src)
    assert len(masked) == len(src)
    # 'hi' and 'bye' replaced by fillers; comment masked too
    assert "comment" not in masked
    assert masked.count("\n") == src.count("\n")


def test_strip_comments_masks_block_comment_across_lines():
    src = "a(); /* multi\nline\ncomment */ b();"
    masked = strip_comments_and_strings(src)
    assert len(masked) == len(src)
    assert "multi" not in masked
    assert "a();" in masked
    assert "b();" in masked


def test_strip_comments_does_not_mask_call_names_outside_strings():
    src = "register_rest_route('ns', '/r', array('foo' => 'bar'));"
    masked = strip_comments_and_strings(src)
    # The function name survives; only the quoted strings get zeroed.
    assert "register_rest_route" in masked
    assert "'ns'" not in masked  # the quoted string is masked away


def test_find_calls_respects_string_parens():
    src = """
    $x = 'register_rest_route(hidden)';
    register_rest_route('ns', '/r', array());
    """
    source_path = _write_tmp(src, tmp_subpath="t.php")
    source = PHPSource(source_path)
    calls = find_calls(source, "register_rest_route")
    # The string contains the literal text "register_rest_route(" but
    # the masker zeroes it out, so find_calls returns exactly one hit.
    assert len(calls) == 1
    assert calls[0].line >= 3


def test_find_calls_handles_nested_arrays():
    src = """
    register_rest_route('ns', '/r', array(
        'callback' => 'handler',
        'args' => array('foo' => array('bar' => 'baz,qux')),
        'permission_callback' => '__return_true',
    ));
    """
    source_path = _write_tmp(src)
    source = PHPSource(source_path)
    calls = find_calls(source, "register_rest_route")
    assert len(calls) == 1
    call = calls[0]
    # 3 args: namespace, route, config-array
    assert len(call.args) == 3
    pairs = dict(call.array_arg_as_pairs(2))
    assert "callback" in pairs
    assert "permission_callback" in pairs
    assert pairs["permission_callback"].strip() == "'__return_true'"


def test_split_top_level_ranges_stops_at_bracket_depth_zero():
    masked = "a, b(c, d), e, f[g, h]"
    ranges = _split_top_level_ranges(masked, sep=",")
    segs = [masked[s:e].strip() for s, e in ranges]
    # Top-level commas split into 4: a | b(c,d) | e | f[g,h].
    # Commas INSIDE b(...) and f[...] are nested and must not split.
    assert segs == ["a", "b(c, d)", "e", "f[g, h]"]


# ── RestAuthzScanner rules ─────────────────────────────────────────

def test_permission_callback_missing_emits_high(tmp_path):
    php = """<?php
    add_action('rest_api_init', function() {
        register_rest_route('myplugin/v1', '/data', array(
            'methods'  => 'POST',
            'callback' => 'my_handler',
        ));
    });
    """
    plugin = _make_plugin(tmp_path, "demo", "1.0.0", {"demo.php": php})
    findings = RestAuthzScanner().scan(plugin)

    hits = [f for f in findings if f.rule_id == "rest_authz.permission_callback_missing"]
    assert len(hits) == 1
    f = hits[0]
    assert f.severity == "high"
    assert f.plugin_slug == "demo"
    assert f.plugin_version == "1.0.0"
    assert "myplugin/v1" in f.evidence["namespace"] or f.evidence["namespace"] == "myplugin/v1"
    assert f.evidence["route"] == "/data"
    assert f.cwe == "CWE-862"


def test_permission_callback_return_true_emits_critical(tmp_path):
    php = """<?php
    register_rest_route('myplugin/v1', '/secret', array(
        'methods'  => 'POST',
        'callback' => 'leak',
        'permission_callback' => '__return_true',
    ));
    """
    plugin = _make_plugin(tmp_path, "demo", "1.0.0", {"demo.php": php})
    findings = RestAuthzScanner().scan(plugin)

    hits = [f for f in findings if f.rule_id == "rest_authz.permission_callback_return_true"]
    assert len(hits) == 1
    assert hits[0].severity == "critical"
    assert hits[0].cwe == "CWE-284"


def test_permission_callback_closure_always_true_emits_critical(tmp_path):
    php = """<?php
    register_rest_route('myplugin/v1', '/secret', array(
        'methods' => 'GET',
        'callback' => 'leak',
        'permission_callback' => function() { return true; },
    ));
    """
    plugin = _make_plugin(tmp_path, "demo", "1.0.0", {"demo.php": php})
    findings = RestAuthzScanner().scan(plugin)

    hits = [f for f in findings if f.rule_id == "rest_authz.permission_callback_return_true"]
    assert len(hits) == 1


def test_permission_callback_real_check_does_not_fire(tmp_path):
    php = """<?php
    register_rest_route('myplugin/v1', '/secret', array(
        'methods' => 'GET',
        'callback' => 'handle',
        'permission_callback' => function() { return current_user_can('edit_posts'); },
    ));
    """
    plugin = _make_plugin(tmp_path, "demo", "1.0.0", {"demo.php": php})
    findings = RestAuthzScanner().scan(plugin)

    # Good authz: neither rule should fire
    assert not any(f.rule_id.startswith("rest_authz.permission_callback") for f in findings)


def test_wp_ajax_nopriv_with_state_change_emits_high(tmp_path):
    php = """<?php
    add_action('wp_ajax_nopriv_set_price', 'set_price');
    function set_price() {
        update_option('price', $_POST['price']);
        wp_die();
    }
    """
    plugin = _make_plugin(tmp_path, "demo", "1.0.0", {"demo.php": php})
    findings = RestAuthzScanner().scan(plugin)

    hits = [f for f in findings if f.rule_id == "rest_authz.wp_ajax_nopriv_state_change"]
    assert len(hits) == 1
    assert hits[0].severity == "high"
    assert "update_option" in str(hits[0].evidence["sinks_found"])


def test_wp_ajax_missing_nonce_emits_medium(tmp_path):
    php = """<?php
    add_action('wp_ajax_save_settings', 'save_settings');
    function save_settings() {
        update_option('site_title', $_POST['title']);
        wp_die();
    }
    """
    plugin = _make_plugin(tmp_path, "demo", "1.0.0", {"demo.php": php})
    findings = RestAuthzScanner().scan(plugin)

    hits = [f for f in findings if f.rule_id == "rest_authz.wp_ajax_missing_nonce"]
    assert len(hits) == 1
    assert hits[0].severity == "medium"


def test_wp_ajax_with_nonce_check_does_not_fire(tmp_path):
    php = """<?php
    add_action('wp_ajax_save_settings', 'save_settings');
    function save_settings() {
        check_ajax_referer('my_nonce');
        if (!current_user_can('manage_options')) wp_die();
        update_option('site_title', $_POST['title']);
    }
    """
    plugin = _make_plugin(tmp_path, "demo", "1.0.0", {"demo.php": php})
    findings = RestAuthzScanner().scan(plugin)

    # Properly guarded — should not fire the missing-nonce rule
    assert not any(f.rule_id == "rest_authz.wp_ajax_missing_nonce" for f in findings)


def test_scanner_resolves_array_callback(tmp_path):
    php = """<?php
    class My_Handler {
        public function __construct() {
            add_action('wp_ajax_nopriv_do_thing', array($this, 'do_thing'));
        }
        public function do_thing() {
            $wpdb->insert('wp_my_table', array('data' => $_POST['data']));
        }
    }
    """
    plugin = _make_plugin(tmp_path, "demo", "1.0.0", {"demo.php": php})
    findings = RestAuthzScanner().scan(plugin)

    hits = [f for f in findings if f.rule_id == "rest_authz.wp_ajax_nopriv_state_change"]
    assert len(hits) == 1


def test_scanner_ignores_comments(tmp_path):
    # A register_rest_route inside a comment should NOT trigger findings.
    php = """<?php
    /*
     * Example usage:
     * register_rest_route('demo/v1', '/bad', array());
     */
    register_rest_route('demo/v1', '/good', array(
        'callback' => 'h',
        'permission_callback' => function() { return current_user_can('edit_posts'); },
    ));
    """
    plugin = _make_plugin(tmp_path, "demo", "1.0.0", {"demo.php": php})
    findings = RestAuthzScanner().scan(plugin)
    # The one in the comment is ignored; the real one has a proper
    # permission callback, so zero findings.
    assert not findings


# ── PluginASTTool wiring ───────────────────────────────────────────

def test_plugin_ast_tool_set_plugins_and_run(tmp_path, monkeypatch):
    php = """<?php
    register_rest_route('demo/v1', '/data', array(
        'callback' => 'h',
        'permission_callback' => '__return_true',
    ));
    """
    plugin = _make_plugin(tmp_path, "fixture-plugin", "2.0.0", {"fixture-plugin.php": php})

    # Intercept corpus.fetch so it returns our fixture without network.
    class FakeCorpus:
        def fetch(self, slug, version=None):
            if slug == "fixture-plugin":
                return plugin
            raise RuntimeError(f"unexpected slug: {slug}")

    tool = PluginASTTool(corpus=FakeCorpus())
    tool.set_plugins([("fixture-plugin", "2.0.0")])

    # Scope is a duck — tool doesn't use its constraint logic
    class FakeScope:
        target = "example.test"

    result = tool.run("example.test", FakeScope())
    assert result.exit_code == 0
    assert len(result.findings) >= 1
    # Engagement-shape finding
    f = result.findings[0]
    assert f["template_id"].startswith("rest_authz.")
    assert f["severity"] in ("high", "critical", "medium")
    assert "plugin_slug" in f["evidence"]


def test_plugin_ast_tool_prime_from_wpscan():
    """wpscan result → plugin-ast priming round-trip."""
    from amoskys.agents.Web.argos.tools.base import ToolResult

    wpscan_result = ToolResult(
        tool="wpscan",
        command=["wpscan"],
        target="example.test",
        exit_code=0,
        started_at_ns=0,
        completed_at_ns=0,
        stdout_bytes=0,
        stderr_bytes=0,
        findings=[
            {
                "template_id": "wpscan.plugin:contact-form-7",
                "title": "CF7 vuln",
                "severity": "high",
                "evidence": {"component": "plugin:contact-form-7", "installed_version": "5.9.0"},
            },
            {
                "template_id": "wpscan.plugin:wpforms",
                "title": "Other",
                "severity": "medium",
                "evidence": {"component": "plugin:wpforms", "installed_version": "1.8.1"},
            },
            {
                # Non-plugin finding should be ignored
                "template_id": "wpscan.user-enum",
                "title": "admin",
                "severity": "info",
                "evidence": {"username": "admin"},
            },
        ],
        errors=[],
    )

    tool = PluginASTTool()
    count = tool.prime_from_wpscan(wpscan_result)
    assert count == 2
    assert ("contact-form-7", "5.9.0") in tool.primed_plugins
    assert ("wpforms", "1.8.1") in tool.primed_plugins


def test_plugin_ast_tool_empty_when_not_primed():
    tool = PluginASTTool()

    class FakeScope:
        target = "example.test"

    result = tool.run("example.test", FakeScope())
    assert result.exit_code == 1
    assert any("no plugins primed" in e for e in result.errors)


# ── Hunt mode ──────────────────────────────────────────────────────

def test_hunt_against_local_fixture(tmp_path):
    """Full hunt loop against a corpus populated with a local fixture."""
    php = """<?php
    register_rest_route('demo/v1', '/leak', array(
        'callback' => 'leak_handler',
        'permission_callback' => '__return_true',
    ));

    add_action('wp_ajax_nopriv_danger', 'danger_handler');
    function danger_handler() {
        $wpdb->query($_POST['sql']);
    }
    """
    fixture = _make_plugin(tmp_path, "vulnerable-demo", "1.2.3", {"main.php": php})

    class FakeCorpus:
        def fetch(self, slug, version=None):
            return fixture

        def top_by_installs(self, n=100, min_installs=1000, refresh=False):
            return [("vulnerable-demo", 50_000)]

    hunt = Hunt(
        slugs=["vulnerable-demo"],
        corpus=FakeCorpus(),
        report_dir=tmp_path / "hunt-reports",
    )
    result = hunt.run()

    assert result.plugins_scanned == 1
    # Both the permission_callback_return_true and the wp_ajax_nopriv
    # state-change rules should fire.
    rule_ids = {f.rule_id for f in result.findings}
    assert "rest_authz.permission_callback_return_true" in rule_ids
    assert "rest_authz.wp_ajax_nopriv_state_change" in rule_ids

    # JSON report was written and is reloadable.
    report_path = (tmp_path / "hunt-reports") / f"hunt-{result.hunt_id}.json"
    assert report_path.exists()
    reloaded = json.loads(report_path.read_text())
    assert reloaded["plugins_scanned"] == 1
    assert reloaded["severity_counts"]["critical"] >= 1
    assert reloaded["severity_counts"]["high"] >= 1


def test_hunt_deduplicates_identical_findings(tmp_path):
    """Same finding from two runs of the same scanner should dedup."""
    php = """<?php
    register_rest_route('demo/v1', '/a', array(
        'callback' => 'h',
        'permission_callback' => '__return_true',
    ));
    """
    fixture = _make_plugin(tmp_path, "dupe-demo", "1.0.0", {"m.php": php})

    class FakeCorpus:
        def fetch(self, slug, version=None):
            return fixture

    # Two identical scanner instances ⇒ would double-count without dedup.
    hunt = Hunt(
        slugs=["dupe-demo"],
        scanners=[RestAuthzScanner(), RestAuthzScanner()],
        corpus=FakeCorpus(),
        report_dir=tmp_path / "hunt-reports",
    )
    result = hunt.run()
    rule_hits = [f for f in result.findings if f.rule_id == "rest_authz.permission_callback_return_true"]
    assert len(rule_hits) == 1, "dedup should collapse identical findings"


# ── Helper ─────────────────────────────────────────────────────────

def _write_tmp(content: str, tmp_subpath: str = "t.php") -> Path:
    import tempfile
    tmp_dir = Path(tempfile.mkdtemp(prefix="argos-ast-test-"))
    path = tmp_dir / tmp_subpath
    path.write_text(content)
    return path
