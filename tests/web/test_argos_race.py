"""Tests for argos/race — single-packet + TOCTOU."""

from __future__ import annotations

import os
import tempfile
import textwrap

import pytest

from amoskys.agents.Web.argos.race import (
    SinglePacketProbe, SinglePacketReport,
    build_coupon_race, build_registration_race, build_parallel_purchase_race,
    execute_single_packet,
    TOCTOUCandidate, TOCTOUReport,
    scan_for_toctou_candidates,
    analyze_endpoint_pair,
)


# ── Probe builders ──────────────────────────────────────────────


def test_build_coupon_race_has_session_cookie_and_coupon():
    p = build_coupon_race("https://shop.test/", "SAVE20",
                           session_cookie="PHPSESSID=abc", n_parallel=15)
    assert p.n_parallel == 15
    assert p.mode == "h1_lastbyte"
    assert p.headers["Cookie"] == "PHPSESSID=abc"
    assert "SAVE20" in p.body_template


def test_build_registration_race_generates_unique_usernames():
    p = build_registration_race("https://reg.test/", "race@test.io",
                                 n_parallel=5)
    assert len(p.varying_field_values) == 5
    assert len(set(p.varying_field_values)) == 5
    assert "race%40test.io" in p.body_template   # URL-encoded email


def test_build_parallel_purchase_race_includes_quantity():
    p = build_parallel_purchase_race("https://shop.test/", "prod-42",
                                      session_cookie="sid=1", n_parallel=8)
    assert p.n_parallel == 8
    assert "prod-42" in p.body_template
    assert "quantity=1" in p.body_template


def test_single_packet_probe_to_dict_serializable():
    import json
    p = build_coupon_race("https://t/", "X")
    json.dumps(p.to_dict())


# ── execute_single_packet with injected raw_sender ──────────────


def _fake_sender(results):
    """Return a callable with signature matching execute_single_packet's
    raw_sender: (host, port, tls, heads, finals, timeout) -> list[(status, body_shape, elapsed_ms)]
    """
    def _send(host, port, tls, heads, finals, timeout):
        assert len(heads) == len(finals)
        return list(results)
    return _send


def test_execute_single_packet_detects_duplicate_success():
    probe = build_coupon_race("https://shop.test/", "SAVE20", n_parallel=3)
    # 3 parallel requests all return 200 with identical body shape
    sender = _fake_sender([(200, "AAAA", 12), (200, "AAAA", 13), (200, "AAAA", 14)])
    rep = execute_single_packet(probe, raw_sender=sender)
    assert rep.requests_sent == 3
    assert rep.detected_duplicate_success is True
    assert any("duplicate success" in e for e in rep.evidence)


def test_execute_single_packet_detects_atomic_server():
    probe = build_coupon_race("https://shop.test/", "X", n_parallel=3)
    # First succeeds, next two fail with 409 Conflict
    sender = _fake_sender([(200, "OK", 10), (409, "USED", 10), (409, "USED", 10)])
    rep = execute_single_packet(probe, raw_sender=sender)
    assert rep.detected_duplicate_success is False


def test_execute_single_packet_captures_response_buckets():
    probe = build_registration_race("https://r/", "x@y.com", n_parallel=4)
    sender = _fake_sender([
        (200, "A", 10), (200, "A", 11),
        (500, "B", 12), (500, "B", 13),
    ])
    rep = execute_single_packet(probe, raw_sender=sender)
    assert rep.unique_response_buckets == 2
    assert rep.bucket_details.get("200:A") == 2
    assert rep.bucket_details.get("500:B") == 2


def test_execute_single_packet_handles_sender_error():
    probe = build_coupon_race("https://t/", "X", n_parallel=2)
    def bad(*a, **k): raise RuntimeError("kaboom")
    rep = execute_single_packet(probe, raw_sender=bad)
    assert any("kaboom" in e for e in rep.errors)


# ── TOCTOU source scan ─────────────────────────────────────────


PHP_VULN_SNIPPET = """<?php
function badplugin_update_email(\\$user_id, \\$new_email) {
    \\$existing = get_user_by('email', \\$new_email);
    if (\\$existing) {
        return new WP_Error('taken');
    }
    wp_update_user(['ID' => \\$user_id, 'user_email' => \\$new_email]);
}
"""


PHP_SAFE_SNIPPET = """<?php
function safeplugin_update(\\$id) {
    \\$wpdb->query('START TRANSACTION');
    \\$row = \\$wpdb->get_row('SELECT * FROM t WHERE id=' . \\$id);
    \\$wpdb->update('t', ['v' => 1], ['id' => \\$id]);
    \\$wpdb->query('COMMIT');
}
"""


def test_scan_for_toctou_candidates_finds_classic_pattern(tmp_path):
    plugin = tmp_path / "plug.php"
    plugin.write_text(PHP_VULN_SNIPPET)
    rep = scan_for_toctou_candidates(str(tmp_path))
    assert rep.files_scanned == 1
    assert rep.candidates
    kind = rep.candidates[0]
    assert kind.check_operation in ("get_user_by",)
    assert kind.use_operation == "wp_update_user"


def test_scan_for_toctou_ignores_transaction_wrapped(tmp_path):
    plugin = tmp_path / "safe.php"
    plugin.write_text(PHP_SAFE_SNIPPET)
    rep = scan_for_toctou_candidates(str(tmp_path))
    # Transaction bracket → no candidate
    assert rep.files_scanned == 1
    assert rep.candidates == []


def test_scan_for_toctou_handles_multiple_files(tmp_path):
    (tmp_path / "a.php").write_text(PHP_VULN_SNIPPET)
    (tmp_path / "b.php").write_text(PHP_SAFE_SNIPPET)
    rep = scan_for_toctou_candidates(str(tmp_path))
    assert rep.files_scanned == 2
    assert len(rep.candidates) >= 1


def test_scan_for_toctou_max_files_cap(tmp_path):
    for i in range(5):
        (tmp_path / f"f{i}.php").write_text(PHP_VULN_SNIPPET)
    rep = scan_for_toctou_candidates(str(tmp_path), max_files=2)
    assert rep.files_scanned <= 2
    assert any("max_files" in e for e in rep.errors)


# ── TOCTOU runtime endpoint-pair analysis ──────────────────────


def test_analyze_endpoint_pair_flags_duplicate_success():
    sender_calls = []
    def sender(url, method, headers, body, timeout):
        sender_calls.append((url, method))
        # Both calls succeed regardless → race signature
        return (200, {}, "ok", 10)
    c = analyze_endpoint_pair(
        check_url="https://t/check?id=1",
        use_url="https://t/use?id=1",
        sender=sender, n_probes=5,
    )
    assert c.severity == "high"
    assert c.metadata["successes"] == 5


def test_analyze_endpoint_pair_ok_on_atomic_server():
    idx = [0]
    def sender(url, method, headers, body, timeout):
        # use endpoint only succeeds once; subsequent returns 409
        if "use" in url:
            idx[0] += 1
            return (200 if idx[0] == 1 else 409, {}, "", 10)
        return (200, {}, "", 10)
    c = analyze_endpoint_pair(
        check_url="https://t/check", use_url="https://t/use",
        sender=sender, n_probes=3,
    )
    assert c.severity == "info"
    assert c.metadata["successes"] == 1


def test_analyze_endpoint_pair_handles_sender_error():
    def sender(*a, **k): raise RuntimeError("network down")
    c = analyze_endpoint_pair(
        check_url="https://t/a", use_url="https://t/b",
        sender=sender, n_probes=5,
    )
    assert c.severity == "info"
    assert "raised" in c.evidence
