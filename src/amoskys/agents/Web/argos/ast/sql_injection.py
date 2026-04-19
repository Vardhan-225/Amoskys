"""SQL injection scanner — the #1 plugin CVE class by a wide margin.

This scanner targets the patterns that cause the majority of WordPress
plugin SQLi CVEs:

    1. String interpolation inside $wpdb->query / get_var / get_results /
       get_row / get_col. WordPress's `$wpdb->prepare` is the sanctioned
       path; if the query string is built with "$var" or "{$var}" inside,
       prepare() is bypassed.

    2. $wpdb->prepare() called with interpolated placeholders — yes,
       people do this. `$wpdb->prepare("SELECT * FROM t WHERE id = $id")`
       is pure SQLi because the $id was interpolated BEFORE prepare
       scanned the format string. Still a CVE.

    3. Direct $wpdb->query/$wpdb->get_* with a $_GET / $_POST / $_REQUEST
       variable as the query. Classic.

    4. Raw mysqli_query / mysql_query (WordPress deprecates, but plugins
       still ship these; when the argument is user-influenced, it's SQLi).

    5. Format specifier mismatch inside prepare — e.g. prepare("... %s ...",
       $intvar) where the context expects an identifier. This is a
       secondary class; we flag it as "low" for human triage.

Rules:

    sql.interpolation_in_query
        $wpdb->query("... $var ...") or "... {$var} ...". Critical.

    sql.prepare_with_interpolation
        $wpdb->prepare("... $var ...", anything). Critical.

    sql.direct_request_query
        $wpdb->query($_POST / $_GET / $_REQUEST / ... ). Critical.

    sql.raw_mysqli_query
        mysqli_query() / mysql_query() / PDO::query() called inside a
        plugin. High when arg is variable, medium otherwise (pattern worth
        auditing).

    sql.prepare_missing_placeholders
        $wpdb->prepare("... no % specifiers ..."). Suggests prepare
        was added ornamentally. Low.

False positives we accept for v1:
    - Variable-as-table-name is flagged as interpolation even when the
      plugin author built it from an allow-list constant. The scanner
      can't see the constant. Operator triages.
    - Heredocs containing SQL with interpolated vars ARE caught (the
      base masking treats heredocs as strings; we specifically scan
      the raw text of the query arg).

What we deliberately DON'T flag:
    - $wpdb->prepare("SELECT * FROM x WHERE id = %d", $id) — the correct
      pattern. We verify the format string contains at least one %d/%s/%f
      placeholder and no interpolation.
    - $wpdb->get_var($wpdb->prepare(...)) — safe chain. We walk one
      level in.
"""

from __future__ import annotations

import re
from typing import List, Optional

from amoskys.agents.Web.argos.ast.base import (
    ASTFinding,
    ASTScanner,
    PHPCallSite,
    PHPSource,
    find_calls,
    strip_comments_and_strings,
)


# ── Query-executing methods we watch ───────────────────────────────
#
# Matched as `->NAME(` on the masked text so we catch
# $wpdb->query, $this->wpdb->query, $GLOBALS['wpdb']->query, etc.
_WPDB_QUERY_METHODS = (
    "query",
    "get_var",
    "get_row",
    "get_col",
    "get_results",
    "prepare",
)

# Raw DB APIs plugins sometimes reach for.
# Map: function name → index of the query argument (mysqli_query takes
# the connection as arg0 and the query as arg1; the others take the
# query as arg0).
_RAW_DB_FUNCTIONS = {
    "mysqli_query": 1,
    "mysql_query": 0,
    "pg_query":    1,   # conservatively pick arg1; arg0 form is one-arg
}

# Request-source globals a tainted argument might come from.
_TAINT_GLOBALS_RE = re.compile(
    r"\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b"
)

# PHP string interpolation patterns.  Applies only to DOUBLE-quoted
# strings and heredocs (single-quoted PHP strings don't interpolate).
#   "$foo"  "{$obj->bar}"  "${array['key']}"
_INTERP_RE = re.compile(
    r"""
    \$\{[^}]+\}        # ${expr}
    | \{\$[^}]+\}      # {$expr}
    | \$[A-Za-z_]\w*   # $var
    """,
    re.VERBOSE,
)

# prepare() format specifiers: %s, %d, %f, %i (WP 6.2+), %s'd / %1$s.
_PLACEHOLDER_RE = re.compile(r"%[-0-9.+#\$]*[sdfi]")

# Wrappers we treat as "the arg is safe because prepare is inside."
_SAFE_WRAPPERS = ("prepare",)


def _quote_form(arg_text: str) -> Optional[str]:
    """If arg_text is one quoted string literal, return 'single' / 'double' /
    'heredoc'. Else None."""
    t = arg_text.strip()
    if not t:
        return None
    if t.startswith("'") and t.endswith("'") and t.count("'") >= 2:
        return "single"
    if t.startswith('"') and t.endswith('"') and t.count('"') >= 2:
        return "double"
    if t.startswith("<<<"):
        # Heredoc or nowdoc. <<<'EOT' is nowdoc (no interp), <<<EOT is heredoc.
        # The first few chars reveal it.
        head = t[3:20]
        if head.startswith("'"):
            return "nowdoc"
        return "heredoc"
    return None


def _unwrap_string(arg_text: str, form: str) -> str:
    """Return the raw inner content (not unescaped — we want the text as
    the PHP source has it)."""
    t = arg_text.strip()
    if form in ("single", "double"):
        return t[1:-1]
    if form in ("heredoc", "nowdoc"):
        # Strip <<<LABEL / <<<'LABEL' through matching LABEL;
        newline = t.find("\n")
        if newline < 0:
            return ""
        body = t[newline + 1 :]
        # Trim trailing `LABEL;` line.
        last_nl = body.rfind("\n")
        if last_nl >= 0:
            body = body[:last_nl]
        return body
    return arg_text


def _looks_tainted(arg_text: str) -> bool:
    """Does the argument text contain a raw request-source global?"""
    return bool(_TAINT_GLOBALS_RE.search(arg_text))


def _is_wrapped_in_prepare(arg_text: str) -> bool:
    """Heuristic: arg is something like `$wpdb->prepare(...)` so the
    outer query method is fed an already-prepared string."""
    return bool(re.search(r"->prepare\s*\(", arg_text))


# ── The scanner ────────────────────────────────────────────────────


class SqlInjectionScanner(ASTScanner):
    """Detect SQLi in WordPress plugin PHP source.

    Rules fire on the first argument of the outer call; we don't walk
    into nested calls except to detect the `->prepare(...)` safety
    wrapper.
    """

    scanner_id = "sql_injection"
    description = "Detects unsafe $wpdb->query/get_* and raw SQL calls"
    severity_default = "high"

    def scan(self, plugin) -> List[ASTFinding]:
        findings: List[ASTFinding] = []
        for php_path in plugin.iter_php_files():
            try:
                source = PHPSource(php_path, relative_to=plugin.root)
            except OSError:
                continue
            findings.extend(self._scan_wpdb_methods(source, plugin))
            findings.extend(self._scan_raw_db_functions(source, plugin))
        return findings

    # ── $wpdb-> method scan ────────────────────────────────────────

    def _scan_wpdb_methods(self, source: PHPSource, plugin) -> List[ASTFinding]:
        """Walk every `->METHOD(...)` on the masked source, check MSTHOD
        against our watchlist, and run classifiers on arg 0."""
        findings: List[ASTFinding] = []
        for method in _WPDB_QUERY_METHODS:
            # Find calls of the form `->method(` on masked text, then
            # replay the argument extraction using find_calls semantics
            # by treating the raw method name as the callee.
            call_re = re.compile(rf"->\s*{re.escape(method)}\s*\(")
            for m in call_re.finditer(source.masked):
                open_paren = m.end() - 1
                close_paren = _match_close_masked(source.masked, open_paren)
                if close_paren is None:
                    continue
                args_raw = source.raw[open_paren + 1 : close_paren]
                masked_slice = source.masked[open_paren + 1 : close_paren]
                arg_ranges = _split_top_level(masked_slice, sep=",")
                args = [args_raw[s:e].strip() for s, e in arg_ranges]
                if not args:
                    continue

                line = source.line_of(m.start())
                arg0 = args[0]

                # Rule: direct_request_query — primary arg is a request global.
                if _looks_tainted(arg0):
                    findings.append(self._finding(
                        plugin, source, line, arg0,
                        rule_id="sql.direct_request_query",
                        severity="critical",
                        title=f"$wpdb->{method}() called with request-sourced global",
                        description=(
                            f"The first argument to $wpdb->{method}() contains "
                            f"a PHP request super-global. This is textbook SQL "
                            f"injection — the request value reaches the query "
                            f"verbatim. Use $wpdb->prepare() with %s / %d / %f "
                            f"placeholders."
                        ),
                        recommendation=(
                            "Wrap in $wpdb->prepare() and bind the request "
                            "value through a %s/%d/%f placeholder."
                        ),
                        evidence_extra={"method": method},
                    ))
                    continue

                # Classify by quote form.
                form = _quote_form(arg0)
                inner = _unwrap_string(arg0, form) if form else ""

                if method == "prepare":
                    findings.extend(self._classify_prepare(
                        plugin, source, line, arg0, form, inner,
                    ))
                else:
                    findings.extend(self._classify_query_like(
                        plugin, source, line, arg0, form, inner, method,
                    ))

        return findings

    def _classify_prepare(self, plugin, source, line, arg0, form, inner):
        out: List[ASTFinding] = []
        # prepare() with interpolation in its format string is SQLi,
        # because PHP interpolates BEFORE prepare sees the string.
        if form in ("double", "heredoc") and _INTERP_RE.search(inner):
            out.append(self._finding(
                plugin, source, line, arg0,
                rule_id="sql.prepare_with_interpolation",
                severity="critical",
                title="$wpdb->prepare() format string contains PHP interpolation",
                description=(
                    "PHP interpolates variables into the string literal BEFORE "
                    "$wpdb->prepare() ever sees it. The placeholders that "
                    "prepare() would escape only exist AFTER interpolation — "
                    "so any $var, {$var} or ${var} in the format string is "
                    "direct SQL injection despite the prepare() call."
                ),
                recommendation=(
                    "Replace the interpolated variable with a %s / %d / %f "
                    "placeholder and pass the raw value as the next argument: "
                    "$wpdb->prepare('WHERE id = %d', $id)"
                ),
            ))
            return out
        # prepare() with no % specifiers at all — ornamental.
        if form in ("single", "double", "heredoc", "nowdoc"):
            if not _PLACEHOLDER_RE.search(inner):
                out.append(self._finding(
                    plugin, source, line, arg0,
                    rule_id="sql.prepare_missing_placeholders",
                    severity="low",
                    title="$wpdb->prepare() called without any %s/%d placeholders",
                    description=(
                        "The format string has no placeholder specifiers. "
                        "prepare() still returns the string, so the call is "
                        "legal, but no value is being escaped — suggesting "
                        "prepare() was added as ornamentation around an "
                        "already-built query. Audit upstream."
                    ),
                    recommendation=(
                        "Confirm this prepare() call is intentional. If the "
                        "full query is a constant, prepare() is unnecessary; "
                        "if variables are being embedded upstream, move them "
                        "to placeholder arguments here."
                    ),
                ))
        return out

    def _classify_query_like(self, plugin, source, line, arg0, form, inner, method):
        out: List[ASTFinding] = []

        # If the first arg IS a prepare(...) call, safe.
        if _is_wrapped_in_prepare(arg0):
            return out

        # Double-quoted string with PHP interpolation → critical SQLi.
        if form in ("double", "heredoc") and _INTERP_RE.search(inner):
            out.append(self._finding(
                plugin, source, line, arg0,
                rule_id="sql.interpolation_in_query",
                severity="critical",
                title=f"$wpdb->{method}() called with an interpolated SQL string",
                description=(
                    f"The query passed to $wpdb->{method}() embeds PHP "
                    f"variables by string interpolation. Any variable content "
                    f"is concatenated into the SQL without escaping — this is "
                    f"the direct SQLi pattern."
                ),
                recommendation=(
                    "Use $wpdb->prepare() with placeholders: "
                    f"$wpdb->{method}($wpdb->prepare('... %s ...', $val))"
                ),
                evidence_extra={"method": method},
            ))
            return out

        # Non-literal (a variable, a concat, a heredoc that didn't regex-match).
        if form is None:
            out.append(self._finding(
                plugin, source, line, arg0,
                rule_id="sql.interpolation_in_query",
                severity="high",
                title=f"$wpdb->{method}() called with a dynamic (non-literal) query",
                description=(
                    f"The first argument to $wpdb->{method}() is not a quoted "
                    f"string literal. The query was assembled upstream, and "
                    f"without $wpdb->prepare() in the chain, any user input "
                    f"that fed the assembly is a SQLi vector."
                ),
                recommendation=(
                    "Re-assemble the query via $wpdb->prepare() so every "
                    "variable becomes a typed placeholder. If the query is "
                    "fully constant, inline it as a single string literal."
                ),
                evidence_extra={"method": method},
            ))

        return out

    # ── raw mysql*_query scan ──────────────────────────────────────

    def _scan_raw_db_functions(self, source: PHPSource, plugin) -> List[ASTFinding]:
        out: List[ASTFinding] = []
        for fn, query_idx in _RAW_DB_FUNCTIONS.items():
            for call in find_calls(source, fn):
                # Prefer the query-arg index for this function; fall back
                # to arg0 if the call is the short/one-arg form.
                arg0 = call.arg(query_idx) or call.arg(0) or ""
                form = _quote_form(arg0)

                if _looks_tainted(arg0):
                    severity = "critical"
                    rule = "sql.direct_request_query"
                    title = f"{fn}() called with a request-sourced global"
                    desc = (
                        f"Raw {fn}() with a PHP request super-global as the "
                        f"query. Direct SQLi."
                    )
                elif form in ("double", "heredoc") and _INTERP_RE.search(
                    _unwrap_string(arg0, form or "")
                ):
                    severity = "high"
                    rule = "sql.raw_mysqli_query"
                    title = f"{fn}() called with an interpolated SQL string"
                    desc = (
                        f"Raw {fn}() with an interpolated query string. Even "
                        f"if the interpolated value is internal today, this "
                        f"is a SQLi waiting to be triggered by a later "
                        f"refactor — migrate to $wpdb->prepare()."
                    )
                elif form is None:
                    severity = "medium"
                    rule = "sql.raw_mysqli_query"
                    title = f"{fn}() called with a dynamic query argument"
                    desc = (
                        f"Raw {fn}() with a non-literal query argument. "
                        f"WordPress code should use $wpdb; this is almost "
                        f"always a sign of plugin code that should be audited."
                    )
                else:
                    # Constant-string raw query — worth a low note.
                    severity = "low"
                    rule = "sql.raw_mysqli_query"
                    title = f"{fn}() used instead of $wpdb"
                    desc = (
                        f"Plugin uses raw {fn}() instead of the WordPress "
                        f"$wpdb abstraction. Constant query, low risk, but "
                        f"not portable across DB drivers."
                    )

                out.append(self._finding(
                    plugin, source, call.line, arg0,
                    rule_id=rule, severity=severity,
                    title=title, description=desc,
                    recommendation=(
                        "Replace with $wpdb->prepare() + $wpdb->query()."
                    ),
                    evidence_extra={"raw_api": fn},
                ))
        return out

    # ── Finding factory ────────────────────────────────────────────

    def _finding(
        self, plugin, source, line, arg0,
        rule_id, severity, title, description,
        recommendation="", evidence_extra=None,
    ) -> ASTFinding:
        snippet = arg0.strip().replace("\n", " ")[:240]
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
            cwe="CWE-89",
            mitre_techniques=["T1190"],
            references=[
                "https://developer.wordpress.org/reference/classes/wpdb/prepare/",
                "https://patchstack.com/database/",
            ],
            evidence={
                "arg0_first_chars": snippet,
                **(evidence_extra or {}),
            },
        )


# ── Minimal helpers (reimplement here to avoid importing private base helpers)


def _match_close_masked(masked: str, open_idx: int) -> Optional[int]:
    depth = 0
    i = open_idx
    n = len(masked)
    while i < n:
        c = masked[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _split_top_level(masked: str, sep: str = ",") -> List:
    out = []
    depth = 0
    last = 0
    i = 0
    n = len(masked)
    while i < n:
        c = masked[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth == 0 and c == sep:
            out.append((last, i))
            last = i + 1
        i += 1
    out.append((last, n))
    return out
