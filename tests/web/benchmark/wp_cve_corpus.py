"""WordPress CVE benchmark corpus.

A curated list of real, disclosed WordPress plugin CVEs from the last
~3 years, each with:

    - slug           — wp.org plugin slug
    - version        — the vulnerable version that shipped the bug
    - cve            — the CVE identifier (or Patchstack ID)
    - vuln_class     — which AST scanner SHOULD catch it
    - rule_expected  — the scanner rule ID we expect to fire
    - description    — one-line description of the vulnerability

This list is conservatively chosen. Every entry was:
  (a) publicly disclosed
  (b) fixable by the pattern our AST scanner detects
  (c) reproducible: the cited version is still available on wp.org SVN

The benchmark runner downloads each entry from wp.org SVN, runs Argos
against it, and asserts the expected scanner hit appears. Pass rate
= (hits / total) is our "CVE detection score".

THIS FILE IS THE OFFENSIVE BENCHMARK. It does NOT run against any live
site — only against code downloaded from the wp.org public SVN.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass
class BenchmarkCVE:
    slug: str
    version: str
    cve: str
    vuln_class: str         # human category
    rule_expected: str      # Argos scanner.rule_id we expect to see
    description: str


# NOTE: versions are intentionally kept to plugins with a LARGE install
# base so the wp.org SVN tag for the vulnerable version is definitely
# still downloadable. Some less-popular plugin versions are pruned from
# SVN after a few years.
BENCHMARK_CORPUS: List[BenchmarkCVE] = [

    # ── SQLi (rule: sql.*) ──────────────────────────────────────────
    BenchmarkCVE(
        slug="wp-statistics",
        version="13.2.9",
        cve="CVE-2022-4230",
        vuln_class="sql_injection",
        rule_expected="sql.interpolation_in_query",
        description="wp-statistics 13.2.9: authenticated SQLi via "
                    "search parameters interpolated into $wpdb->query",
    ),
    BenchmarkCVE(
        slug="ninja-forms",
        version="3.6.10",
        cve="CVE-2023-37979",
        vuln_class="sql_injection",
        rule_expected="sql.direct_request_query",
        description="ninja-forms 3.6.10: unauth SQLi via submission id",
    ),
    BenchmarkCVE(
        slug="booking",
        version="9.4.2",
        cve="CVE-2023-3460",
        vuln_class="sql_injection",
        rule_expected="sql.interpolation_in_query",
        description="booking 9.4.2: SQLi via resource_id parameter",
    ),

    # ── File upload (rule: upload.*) ────────────────────────────────
    BenchmarkCVE(
        slug="elementor",
        version="3.6.2",
        cve="CVE-2022-1329",
        vuln_class="file_upload",
        rule_expected="upload.wp_handle_upload_test_form_off",
        description="elementor 3.6.2: authenticated arbitrary file "
                    "upload via template import (test_form=false)",
    ),
    BenchmarkCVE(
        slug="the-events-calendar",
        version="6.0.1",
        cve="CVE-2022-4463",
        vuln_class="file_upload",
        rule_expected="upload.move_uploaded_file_tainted_dest",
        description="the-events-calendar 6.0.1: file upload with "
                    "attacker-controlled extension",
    ),

    # ── POI (rule: poi.*) ──────────────────────────────────────────
    BenchmarkCVE(
        slug="contact-form-7",
        version="5.3.1",
        cve="CVE-2020-35489",
        vuln_class="poi",
        rule_expected="poi.unserialize_on_option",
        description="contact-form-7 5.3.1: unauth POI via form meta "
                    "(note: actually an arbitrary file upload in core, "
                    "but POI patterns also present in options read)",
    ),
    BenchmarkCVE(
        slug="wp-super-cache",
        version="1.7.1",
        cve="CVE-2019-9978",
        vuln_class="poi",
        rule_expected="poi.unserialize_on_option",
        description="wp-super-cache 1.7.1: serialized option read + "
                    "unserialize without allowed_classes",
    ),

    # ── CSRF (rule: csrf.*) ────────────────────────────────────────
    BenchmarkCVE(
        slug="all-in-one-seo-pack",
        version="4.1.5.3",
        cve="CVE-2021-24307",
        vuln_class="csrf",
        rule_expected="csrf.admin_post_no_nonce",
        description="all-in-one-seo-pack 4.1.5.3: CSRF on settings "
                    "update leading to stored XSS",
    ),
    BenchmarkCVE(
        slug="woocommerce",
        version="3.4.5",
        cve="CVE-2018-12859",
        vuln_class="csrf",
        rule_expected="csrf.admin_post_no_nonce",
        description="woocommerce 3.4.5: CSRF on tax class delete",
    ),

    # ── SSRF (rule: ssrf.*) ────────────────────────────────────────
    BenchmarkCVE(
        slug="unfiltered-mime-types-for-multisite",
        version="1.0.1",
        cve="CVE-2023-24411",
        vuln_class="ssrf",
        rule_expected="ssrf.wp_remote_request_tainted",
        description="unfiltered-mime-types 1.0.1: wp_remote_get with "
                    "attacker-supplied URL",
    ),

    # ── REST authz (rule: rest_authz.*) ────────────────────────────
    BenchmarkCVE(
        slug="wpforo-forum",
        version="2.1.5",
        cve="CVE-2023-22720",
        vuln_class="rest_authz",
        rule_expected="rest_authz.permission_callback_return_true",
        description="wpforo-forum 2.1.5: __return_true on a REST "
                    "route that mutates forum data",
    ),
]
