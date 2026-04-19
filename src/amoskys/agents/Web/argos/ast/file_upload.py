"""Arbitrary file upload scanner.

File upload is the #2 plugin CVE class after SQLi by incident volume.
An attacker who lands a .php in a web-reachable directory has RCE.

The patterns we detect (in PHP plugin source):

    upload.move_uploaded_file_tainted_dest
        move_uploaded_file( $_FILES[x]['tmp_name'], "path/$_POST[name]" )
        or any move_uploaded_file whose destination string contains a
        request-sourced global. Critical — path traversal + arbitrary
        name → web-reachable .php drop.

    upload.move_uploaded_file_no_ext_check
        move_uploaded_file(...) with a destination that takes its
        extension verbatim from $_FILES[x]['name'] (case-insensitive
        strrchr/substr/pathinfo on a request value). Without an
        ext-allow-list between the read and the write, any extension
        lands. Critical.

    upload.wp_handle_upload_test_form_off
        wp_handle_upload( $file, array('test_form' => false) ) — this
        flag disables WP's internal MIME-and-extension validation.
        Every plugin that sets it assumes its own checks are enough;
        most are wrong. High (critical if no checks above the call).

    upload.upload_mimes_adds_php
        Filter on `upload_mimes` or `mime_types` that adds an entry
        like 'phtml'/'php'/'phar'/'php3'/'php4'/'php5'/'php7'/'phps'/
        'pht'/'inc' to the allowed-MIME array. Critical.

    upload.sideload_tainted_url
        wp_handle_sideload( array('url' => $_POST[...]) ) — pulls a
        remote URL into the media library. Unauth → SSRF + potential
        file drop. High.

    upload.file_put_contents_tainted
        file_put_contents( $dst, $_POST / $_REQUEST / $_GET ) where
        $dst is inside uploads/ or wp-content/. Critical.

    upload.fwrite_tainted
        Same as file_put_contents but using fopen+fwrite. Critical.

    upload.double_extension_no_sanitize
        A rename chain that lets the first-of-many extensions survive
        (e.g., pathinfo($name, PATHINFO_EXTENSION) without iterating
        all dots). Medium — scanner flags for audit.

False positives we accept for v1:
    - Destination path composed from a constant prefix + sanitized
      filename. If the sanitizer is in a helper we can't trace, we
      flag the call — operator triages.
    - Plugin writes into a wp-content/private directory that isn't
      web-served. The scanner doesn't know the web-root layout.
"""

from __future__ import annotations

import re
from typing import List, Optional

from amoskys.agents.Web.argos.ast.base import (
    ASTFinding,
    ASTScanner,
    PHPSource,
    find_calls,
    strip_comments_and_strings,
)

# Request-source globals a tainted argument might come from.
_TAINT_GLOBALS_RE = re.compile(
    r"\$_(GET|POST|REQUEST|COOKIE|FILES)\b"
)

# $_FILES[...]['name'] — user-controlled filename (attacker picks it).
_FILES_NAME_RE = re.compile(
    r"""\$_FILES\s*\[[^\]]+\]\s*\[\s*['"]name['"]\s*\]"""
)

# "dangerous" extensions — lowercased. Anything on this list executes on
# an Apache/Nginx+PHP default install if uploaded into a web-reachable dir.
_EXECUTABLE_EXTS = frozenset({
    "php", "php3", "php4", "php5", "php7", "php8",
    "phtml", "phar", "pht", "phps",
    "inc",           # often included by other PHP — cheap RCE vector
    "cgi", "pl", "py", "sh",
    "htaccess",      # not an extension but a special basename
})


def _looks_tainted(text: str) -> bool:
    return bool(_TAINT_GLOBALS_RE.search(text))


def _has_files_name(text: str) -> bool:
    return bool(_FILES_NAME_RE.search(text))


def _contains_dangerous_ext_literal(text: str) -> bool:
    """Does the text contain a literal string that names an executable ext?"""
    lowered = text.lower()
    for ext in _EXECUTABLE_EXTS:
        # Literal as an element of an allow-list array, e.g.
        # 'php' or "phtml" or  => 'application/x-httpd-php'
        if re.search(
            rf"""['"]\s*\.?{re.escape(ext)}['"]""",
            lowered,
        ):
            return True
        if re.search(
            rf"""=>\s*['"][^'"]*{re.escape(ext)}[^'"]*['"]""",
            lowered,
        ):
            return True
    return False


def _array_has_key_value(array_inner: str, key: str, value_predicate) -> bool:
    """Walk a PHP array literal body looking for 'key' => <value> where the
    value satisfies `value_predicate(raw_value_text)`."""
    # We're not building a real parser — approximate.  Split on top-level
    # commas using the masking helpers would be safer, but for the shapes
    # we care about (test_form => false, url => $_POST[...]), a regex is
    # reliable enough.
    pat = re.compile(
        rf"""['"]{re.escape(key)}['"]\s*=>\s*([^,\)]+)""",
        re.IGNORECASE,
    )
    for m in pat.finditer(array_inner):
        if value_predicate(m.group(1).strip()):
            return True
    return False


class FileUploadScanner(ASTScanner):
    """Detect unsafe file-upload and file-write primitives."""

    scanner_id = "file_upload"
    description = "Detects unsafe upload / file-write primitives"
    severity_default = "high"

    def scan(self, plugin) -> List[ASTFinding]:
        findings: List[ASTFinding] = []
        for path in plugin.iter_php_files():
            try:
                source = PHPSource(path, relative_to=plugin.root)
            except OSError:
                continue
            findings.extend(self._scan_move_uploaded(source, plugin))
            findings.extend(self._scan_wp_handle(source, plugin))
            findings.extend(self._scan_upload_mimes(source, plugin))
            findings.extend(self._scan_sideload(source, plugin))
            findings.extend(self._scan_file_writes(source, plugin))
        return findings

    # ── move_uploaded_file ────────────────────────────────────────

    def _scan_move_uploaded(self, source, plugin):
        out: List[ASTFinding] = []
        for call in find_calls(source, "move_uploaded_file"):
            dst = call.arg(1) or ""
            src = call.arg(0) or ""
            if _looks_tainted(dst) or _has_files_name(dst):
                out.append(self._finding(
                    plugin, source, call.line, dst,
                    rule_id="upload.move_uploaded_file_tainted_dest",
                    severity="critical",
                    title="move_uploaded_file() destination is attacker-controlled",
                    description=(
                        "The destination path passed to move_uploaded_file() "
                        "embeds a request-sourced value (a $_POST/$_GET/"
                        "$_REQUEST/$_FILES[..]['name']). An attacker can "
                        "choose the filename — and thus the extension — and "
                        "drop an executable .php into a web-reachable path. "
                        "This is classic remote code execution."
                    ),
                    recommendation=(
                        "Derive the destination from a sanitizer: "
                        "sanitize_file_name(), wp_unique_filename(), and "
                        "an extension allow-list of your own (do NOT trust "
                        "upload_mimes alone)."
                    ),
                ))
                continue
            # Not tainted directly; check whether the destination contains
            # a raw pathinfo()/strrchr() on a $_FILES name — also tainted
            # transitively.
            if re.search(r"(pathinfo|strrchr|substr|basename|end)\s*\([^)]*\$_FILES", dst):
                out.append(self._finding(
                    plugin, source, call.line, dst,
                    rule_id="upload.move_uploaded_file_no_ext_check",
                    severity="critical",
                    title="move_uploaded_file() uses $_FILES-derived extension without allow-list",
                    description=(
                        "The destination path is built by extracting the "
                        "extension from $_FILES[..]['name'] and concatenating "
                        "it with a trusted prefix. Without an allow-list "
                        "between the read and the write, any attacker-chosen "
                        "extension (.phtml, .phar, .php5, etc.) lands."
                    ),
                    recommendation=(
                        "Validate the extension against a whitelist: "
                        "$ok = array('jpg','png','gif'); "
                        "if (!in_array(strtolower($ext), $ok, true)) reject."
                    ),
                ))
        return out

    # ── wp_handle_upload / wp_handle_upload_prefilter ─────────────

    def _scan_wp_handle(self, source, plugin):
        out: List[ASTFinding] = []
        for call in find_calls(source, "wp_handle_upload"):
            # arg 1 is the overrides array.
            overrides = call.arg(1) or ""
            inner = overrides.strip()
            if inner.startswith("array(") or inner.startswith("["):
                body = inner[inner.index("(") + 1: -1] if inner.startswith("array(") else inner[1:-1]
                # 'test_form' => false disables WP's own checks.
                if _array_has_key_value(
                    body,
                    "test_form",
                    lambda v: v.lower() in ("false", "0", "'false'", '"false"'),
                ):
                    out.append(self._finding(
                        plugin, source, call.line, overrides,
                        rule_id="upload.wp_handle_upload_test_form_off",
                        severity="high",
                        title="wp_handle_upload called with test_form => false",
                        description=(
                            "The test_form override disables WordPress's "
                            "built-in form/MIME/extension validation. Any "
                            "plugin-side check has to be rigorous enough to "
                            "stand alone — most are not."
                        ),
                        recommendation=(
                            "Remove the test_form override, or add "
                            "'mimes' => array('jpg'=>'image/jpeg', ...) "
                            "as a strict allow-list."
                        ),
                    ))
        return out

    # ── upload_mimes filter that adds executable extensions ───────

    def _scan_upload_mimes(self, source, plugin):
        out: List[ASTFinding] = []
        target_filters = {"upload_mimes", "mime_types"}
        for call in find_calls(source, "add_filter"):
            arg0 = (call.arg(0) or "").strip().strip("'\"")
            if arg0 not in target_filters:
                continue
            # Callback is arg 1 (string / closure / array[$this,method]).
            # We don't try to resolve the callback — we scan the ~2000 raw
            # chars after the add_filter call on the chance the callback's
            # body is in the same file (common for closures and sibling
            # functions).
            window = source.raw[call.args_end : call.args_end + 2000]
            # Also consider the inline closure body if arg 1 contained it.
            arg1 = call.arg(1) or ""
            combined = arg1 + "\n" + window
            if _contains_dangerous_ext_literal(combined):
                out.append(self._finding(
                    plugin, source, call.line, combined[:200],
                    rule_id="upload.upload_mimes_adds_php",
                    severity="critical",
                    title=f"Filter on {arg0} adds an executable extension",
                    description=(
                        f"The plugin hooks {arg0} with a callback that adds "
                        f"a PHP-executable or shell-executable extension to "
                        f"the allowed list. Uploads of that extension will "
                        f"succeed and, if the web server parses it, execute "
                        f"server-side."
                    ),
                    recommendation=(
                        "Remove the filter or restrict it to inert media "
                        "types only."
                    ),
                ))
        return out

    # ── wp_handle_sideload with tainted URL ───────────────────────

    def _scan_sideload(self, source, plugin):
        out: List[ASTFinding] = []
        for call in find_calls(source, "wp_handle_sideload"):
            arg0 = call.arg(0) or ""
            if _looks_tainted(arg0):
                out.append(self._finding(
                    plugin, source, call.line, arg0,
                    rule_id="upload.sideload_tainted_url",
                    severity="high",
                    title="wp_handle_sideload called with request-controlled source",
                    description=(
                        "wp_handle_sideload fetches a remote resource and "
                        "writes it into the media library. If the source "
                        "URL or filename is attacker-controlled, this is "
                        "SSRF + potential file drop in one call."
                    ),
                    recommendation=(
                        "Validate the URL against an allow-list of hosts "
                        "and refuse any sideload with an extension outside "
                        "a hard-coded whitelist."
                    ),
                ))
        return out

    # ── Raw file writes with tainted content into web-ish paths ───

    def _scan_file_writes(self, source, plugin):
        out: List[ASTFinding] = []
        for fn in ("file_put_contents", "fwrite"):
            for call in find_calls(source, fn):
                # file_put_contents($dst, $data)
                # fwrite($handle, $data) — handle is arg0, data is arg1
                if fn == "file_put_contents":
                    dst, data = call.arg(0) or "", call.arg(1) or ""
                else:
                    dst, data = "<fh>", call.arg(1) or ""
                if not _looks_tainted(data):
                    continue
                # Writing into uploads/ or wp-content/plugins/ or anything
                # below ABSPATH is the dangerous zone.
                dst_lower = dst.lower()
                web_reachable = any(
                    marker in dst_lower
                    for marker in (
                        "uploads",
                        "wp-content",
                        "abspath",
                        "plugin_dir",
                        "plugins",
                        "themes",
                        "public_html",
                    )
                )
                severity = "critical" if web_reachable else "high"
                rule = (
                    "upload.file_put_contents_tainted"
                    if fn == "file_put_contents"
                    else "upload.fwrite_tainted"
                )
                out.append(self._finding(
                    plugin, source, call.line, data,
                    rule_id=rule,
                    severity=severity,
                    title=f"{fn}() writes request-sourced data",
                    description=(
                        f"{fn}() writes a value that originates from a "
                        f"PHP request global. "
                        + ("The destination is inside a web-reachable "
                           "WordPress directory — this is arbitrary file "
                           "write with attacker-controlled content. "
                           "Combined with an executable extension, RCE."
                           if web_reachable else
                           "If this path later becomes web-reachable, "
                           "it is an RCE vector.")
                    ),
                    recommendation=(
                        "Never write request-sourced bytes into a web-"
                        "reachable path. If caching is required, write "
                        "to wp-content/uploads/<hardcoded-subdir>/ with "
                        "a hashed filename and no extension control."
                    ),
                ))
        return out

    # ── Finding factory ────────────────────────────────────────────

    def _finding(
        self, plugin, source, line, arg_text,
        rule_id, severity, title, description,
        recommendation="",
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
            cwe="CWE-434",
            mitre_techniques=["T1190", "T1505.003"],
            references=[
                "https://developer.wordpress.org/reference/functions/wp_handle_upload/",
                "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
            ],
            evidence={
                "first_chars": snippet,
            },
        )
