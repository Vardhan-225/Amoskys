"""Unit tests for the CSRF AST scanner."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List

from amoskys.agents.Web.argos.ast import CsrfScanner


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
    return CsrfScanner().scan(plugin)


# ── Positive cases ──────────────────────────────────────────────────


def test_admin_post_no_nonce(tmp_path):
    src = '''<?php
add_action('admin_post_save_settings', function() {
    update_option('my_plugin_key', $_POST['key']);
});
?>'''
    findings = _run(tmp_path, src)
    assert findings
    assert findings[0].rule_id == "csrf.admin_post_no_nonce"
    assert findings[0].severity == "high"
    assert findings[0].cwe == "CWE-352"


def test_admin_post_nopriv_critical(tmp_path):
    src = '''<?php
add_action('admin_post_nopriv_register_user', function() {
    wp_insert_user(array('user_login' => $_POST['u']));
});
?>'''
    findings = _run(tmp_path, src)
    assert findings
    assert findings[0].rule_id == "csrf.admin_post_nopriv_state_change"
    assert findings[0].severity == "critical"


def test_wp_ajax_no_nonce(tmp_path):
    src = '''<?php
add_action('wp_ajax_myplug_update', function() {
    $wpdb = $GLOBALS['wpdb'];
    $wpdb->update('wp_options', array('option_value' => $_POST['v']), array('option_name' => 'foo'));
});
?>'''
    findings = _run(tmp_path, src)
    assert findings
    assert findings[0].rule_id == "csrf.wp_ajax_no_nonce"
    assert findings[0].severity == "high"


def test_named_callback_no_nonce(tmp_path):
    src = '''<?php
function myplug_save() {
    update_option('x', $_POST['x']);
}
add_action('admin_post_save', 'myplug_save');
?>'''
    findings = _run(tmp_path, src)
    assert findings
    assert findings[0].rule_id == "csrf.admin_post_no_nonce"


def test_init_handler_with_dispatch_no_nonce(tmp_path):
    src = '''<?php
add_action('admin_init', function() {
    if (isset($_POST['do_import'])) {
        update_option('import_flag', 1);
        wp_insert_post(array('post_title' => $_POST['t']));
    }
});
?>'''
    findings = _run(tmp_path, src)
    assert findings
    assert findings[0].rule_id == "csrf.init_handler_no_referer"
    assert findings[0].severity == "medium"


# ── Negative cases ──────────────────────────────────────────────────


def test_safe_admin_post_with_referer_check(tmp_path):
    src = '''<?php
add_action('admin_post_save_settings', function() {
    check_admin_referer('my_save');
    update_option('k', $_POST['k']);
});
?>'''
    findings = _run(tmp_path, src)
    assert not findings


def test_safe_wp_ajax_with_ajax_referer(tmp_path):
    src = '''<?php
add_action('wp_ajax_do_thing', function() {
    check_ajax_referer('do_thing_nonce');
    update_option('x', $_POST['x']);
});
?>'''
    findings = _run(tmp_path, src)
    assert not findings


def test_safe_with_current_user_can(tmp_path):
    src = '''<?php
add_action('admin_post_x', function() {
    if (!current_user_can('manage_options')) die();
    update_option('k', 'v');
});
?>'''
    findings = _run(tmp_path, src)
    # current_user_can alone doesn't prevent CSRF (session cookie still
    # sent cross-origin), but our rule treats it as a sign someone was
    # thinking about auth; accept as SAFE for v1 and let humans triage.
    assert not findings


def test_handler_that_only_reads(tmp_path):
    src = '''<?php
add_action('admin_post_show_stats', function() {
    echo get_option('stats');
});
?>'''
    findings = _run(tmp_path, src)
    assert not findings


def test_unrelated_add_action(tmp_path):
    src = '''<?php
add_action('init', function() {
    wp_enqueue_script('foo', '/foo.js');
});
?>'''
    findings = _run(tmp_path, src)
    assert not findings


def test_class_method_callback_safe(tmp_path):
    src = '''<?php
class MyPlug {
    public function save() {
        check_admin_referer('save_action');
        update_option('x', $_POST['x']);
    }
}
add_action('admin_post_mp', array($obj, 'save'));
?>'''
    findings = _run(tmp_path, src)
    assert not findings


def test_class_method_callback_vulnerable(tmp_path):
    src = '''<?php
class MyPlug {
    public function save() {
        update_option('x', $_POST['x']);
    }
}
add_action('admin_post_mp', array($obj, 'save'));
?>'''
    findings = _run(tmp_path, src)
    assert findings
    assert findings[0].rule_id == "csrf.admin_post_no_nonce"


# ── Metadata sanity ────────────────────────────────────────────────


def test_metadata(tmp_path):
    src = '''<?php
add_action('admin_post_x', function() {
    update_option('k', 'v');
});
?>'''
    findings = _run(tmp_path, src)
    assert findings
    f = findings[0]
    assert f.cwe == "CWE-352"
    assert any("nonce" in r.lower() or "csrf" in r.lower() for r in f.references)
