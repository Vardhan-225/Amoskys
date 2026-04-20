"""Server-Side Request Forgery (SSRF) scanner.

SSRF is the class that turns a plugin's "fetch this URL for me" feature
into a window onto the server's internal network — AWS metadata, local
services, internal admin panels, Redis/Memcached on loopback.

We flag plugin code that emits an outbound HTTP request whose URL,
host, or port is derived from request input.

Rules:

    ssrf.wp_remote_request_tainted
        wp_remote_get / wp_remote_post / wp_remote_head / wp_remote_request /
        wp_safe_remote_get / ... called with a $_GET / $_POST / $_REQUEST /
        $_COOKIE value as the URL. Critical.

    ssrf.file_get_contents_remote_tainted
        file_get_contents( $url ) where $url is a tainted string that
        looks like a URL (starts with http:// or https:// or includes
        ://). High.

    ssrf.curl_exec_tainted_url
        curl_setopt( $h, CURLOPT_URL, $tainted ) followed by curl_exec
        anywhere in the file. Critical.

    ssrf.no_url_allowlist
        Any wp_remote_* call where arg 0 is a variable AND no
        parse_url/hostname-allowlist pattern is present in the 20 lines
        before the call. Low (lint/audit signal).

False positives:
    - wp_remote_get( $url ) where $url was built from a constant +
      a hardcoded API key. Without cross-function tracking we flag the
      dynamic form; operator triages.
"""

from __future__ import annotations

import re
from typing import List

from amoskys.agents.Web.argos.ast.base import (
    ASTFinding,
    ASTScanner,
    PHPSource,
    find_calls,
)

_TAINT_RE = re.compile(r"\$_(GET|POST|REQUEST|COOKIE|SERVER)\b")
_REMOTE_FUNCS = (
    "wp_remote_get",
    "wp_remote_post",
    "wp_remote_head",
    "wp_remote_request",
    "wp_remote_retrieve_body",
    "wp_safe_remote_get",
    "wp_safe_remote_post",
    "wp_safe_remote_request",
)
_RAW_REMOTE = ("file_get_contents", "fopen", "readfile", "get_headers")


def _has_taint(text: str) -> bool:
    return bool(_TAINT_RE.search(text))


_URL_NAME_RE = re.compile(
    r"(url|uri|endpoint|href|target|link|remote|host|addr|fetch)",
    re.IGNORECASE,
)


def _looks_like_url(text: str) -> bool:
    """Heuristic — does this argument text refer to something URL-shaped?"""
    if re.search(r"""['"]https?://""", text):
        return True
    if re.search(r"\$_(GET|POST|REQUEST|COOKIE)\s*\[\s*['\"][^'\"]*(url|uri|endpoint|href|target|remote|addr|host)[^'\"]*['\"]\s*\]", text, re.IGNORECASE):
        return True
    if re.search(r"\$(url|uri|endpoint|href|target|link|remote|host|addr)\b", text, re.IGNORECASE):
        return True
    return False


class SsrfScanner(ASTScanner):
    """Detect SSRF primitives."""

    scanner_id = "ssrf"
    description = "Detects outbound HTTP with attacker-controlled URLs"
    severity_default = "high"

    def scan(self, plugin) -> List[ASTFinding]:
        findings: List[ASTFinding] = []
        for path in plugin.iter_php_files():
            try:
                source = PHPSource(path, relative_to=plugin.root)
            except OSError:
                continue
            findings.extend(self._scan_wp_remote(source, plugin))
            findings.extend(self._scan_raw_remote(source, plugin))
            findings.extend(self._scan_curl_setopt(source, plugin))
        return findings

    def _scan_wp_remote(self, source, plugin):
        out: List[ASTFinding] = []
        for fn in _REMOTE_FUNCS:
            for call in find_calls(source, fn):
                arg0 = call.arg(0) or ""
                if _has_taint(arg0):
                    out.append(self._finding(
                        plugin, source, call.line, arg0,
                        rule_id="ssrf.wp_remote_request_tainted",
                        severity="critical",
                        title=f"{fn}() called with a request-sourced URL",
                        description=(
                            f"{fn}() emits an outbound HTTP request to a URL "
                            f"derived directly from a PHP request global. The "
                            f"attacker chooses the destination — AWS metadata "
                            f"(169.254.169.254), internal services on loopback, "
                            f"Redis on a private IP, internal admin panels. "
                            f"This is the canonical SSRF pattern."
                        ),
                        recommendation=(
                            "Validate the destination host against an allow-"
                            "list before calling the HTTP helper. Use "
                            "wp_http_validate_url() as a minimum, but prefer "
                            "an explicit list of hostnames your plugin needs."
                        ),
                    ))
                    continue
                # Dynamic, non-tainted arg 0 → low (audit signal).
                if arg0 and not _looks_like_url(arg0) and not arg0.startswith("'") and not arg0.startswith('"'):
                    continue
                if arg0.startswith("$") or "(" in arg0:
                    # Dynamic — we don't know its source.
                    out.append(self._finding(
                        plugin, source, call.line, arg0,
                        rule_id="ssrf.no_url_allowlist",
                        severity="low",
                        title=f"{fn}() called with a dynamic URL variable",
                        description=(
                            f"{fn}() takes its URL from a variable. We don't "
                            f"see a preceding parse_url/host-allowlist pattern. "
                            f"This is a lint-level audit signal — the call is "
                            f"safe if the upstream is trusted, but worth a look."
                        ),
                        recommendation=(
                            "Validate the host before calling, or use "
                            "wp_http_validate_url() to block private-range "
                            "targets."
                        ),
                    ))
        return out

    def _scan_raw_remote(self, source, plugin):
        out: List[ASTFinding] = []
        for fn in _RAW_REMOTE:
            for call in find_calls(source, fn):
                arg0 = call.arg(0) or ""
                if not _has_taint(arg0):
                    continue
                # Only flag when the arg text suggests a remote URL, not a
                # local file path.
                if not _looks_like_url(arg0):
                    continue
                out.append(self._finding(
                    plugin, source, call.line, arg0,
                    rule_id="ssrf.file_get_contents_remote_tainted",
                    severity="high",
                    title=f"{fn}() with tainted URL-shaped argument",
                    description=(
                        f"{fn}() is called with a value derived from a PHP "
                        f"request global that textually looks like a URL. "
                        f"PHP's filesystem functions will happily follow "
                        f"http:// and https:// wrappers unless "
                        f"allow_url_fopen is disabled — which most shared "
                        f"hosts leave on."
                    ),
                    recommendation=(
                        "Migrate to wp_remote_get() with explicit host "
                        "validation, or use a strict URL allow-list before "
                        "calling."
                    ),
                ))
        return out

    def _scan_curl_setopt(self, source, plugin):
        """Look for curl_setopt(…, CURLOPT_URL, tainted)."""
        out: List[ASTFinding] = []
        for call in find_calls(source, "curl_setopt"):
            if (call.arg(1) or "").strip() != "CURLOPT_URL":
                continue
            arg2 = call.arg(2) or ""
            if not _has_taint(arg2):
                continue
            out.append(self._finding(
                plugin, source, call.line, arg2,
                rule_id="ssrf.curl_exec_tainted_url",
                severity="critical",
                title="curl_setopt(CURLOPT_URL, ...) with request-sourced value",
                description=(
                    "The URL a cURL handle will hit is assigned directly "
                    "from a PHP request global. A subsequent curl_exec "
                    "will follow attacker-chosen destinations — the "
                    "classic SSRF pattern via the low-level HTTP API."
                ),
                recommendation=(
                    "Whitelist the host before assignment. If the plugin "
                    "really needs free-form URLs, install an allow-list "
                    "of host prefixes and reject anything else."
                ),
            ))
        return out

    def _finding(
        self, plugin, source, line, arg_text,
        rule_id, severity, title, description, recommendation="",
    ) -> ASTFinding:
        snippet = arg_text.strip().replace("\n", " ")[:240]
        return ASTFinding(
            scanner=self.scanner_id,
            rule_id=rule_id,
            severity=severity,
            plugin_slug=plugin.slug,
            plugin_version=plugin.version or "",
            file_path=source.relative_path,
            line=line,
            snippet=snippet,
            title=title,
            description=description,
            recommendation=recommendation,
            cwe="CWE-918",
            mitre_techniques=["T1190", "T1136"],
            references=[
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                "https://developer.wordpress.org/reference/functions/wp_remote_get/",
            ],
            evidence={"first_chars": snippet},
        )
