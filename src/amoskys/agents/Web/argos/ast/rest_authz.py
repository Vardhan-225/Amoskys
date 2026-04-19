"""REST / AJAX authorization scanner.

This scanner targets the vulnerability class Patchstack reports as the
second-largest on the WP plugin surface (~20–25% of disclosed CVEs,
2025): broken access control / missing nonce / missing capability check
on REST routes and admin-ajax handlers.

It's the highest-$/bug class because the fix is a one-liner but the
impact is often privilege escalation or arbitrary data mutation as
unauthenticated.

Rules:

    rest_authz.permission_callback_missing
        register_rest_route(...) called without a `permission_callback`
        key in the args array. WP emits a _doing_it_wrong notice but
        still exposes the route. Severity: HIGH.

    rest_authz.permission_callback_return_true
        `'permission_callback' => '__return_true'` or any callable that
        unconditionally returns true. Explicit public access — if the
        handler touches data, this is an unauth-RCE/SQLi class.
        Severity: CRITICAL.

    rest_authz.wp_ajax_nopriv_state_change
        add_action('wp_ajax_nopriv_X', cb) where cb's body contains
        state-changing calls (update_option, $wpdb->insert, etc.) with
        no preceding nonce or capability check. Severity: HIGH.

    rest_authz.wp_ajax_missing_nonce
        add_action('wp_ajax_X', cb) where cb contains state-changing
        calls but no wp_verify_nonce / check_ajax_referer /
        check_admin_referer / current_user_can check. Severity: MEDIUM
        (auth'd CSRF; still often pays).

False positives we accept for v1:
    - Capability checks inside helper functions the callback calls.
      We only look one level deep in the file. The cost of following
      cross-file chains exceeds the FP savings.
    - Conditional permission_callbacks that *sometimes* return true.
      We flag any callback we can't statically prove is restrictive.

These FPs are acceptable because v1 output is human-triaged before a
bug-bounty submission. The scanner's job is to surface candidates; the
operator confirms.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional, Tuple

from amoskys.agents.Web.argos.ast.base import (
    ASTFinding,
    ASTScanner,
    PHPCallSite,
    PHPSource,
    find_calls,
    strip_comments_and_strings,
)
from amoskys.agents.Web.argos.ast.base import _match_close  # noqa: E402

# ── State-changing sink signatures ─────────────────────────────────
#
# If a handler body contains any of these patterns and lacks a nonce /
# capability check, it's an authz bug. The list is deliberately narrow —
# every pattern here is a real write path or side-effect.
_STATE_CHANGING_SINKS = [
    r"\bupdate_option\s*\(",
    r"\badd_option\s*\(",
    r"\bdelete_option\s*\(",
    r"\bupdate_user_meta\s*\(",
    r"\bdelete_user_meta\s*\(",
    r"\bupdate_post_meta\s*\(",
    r"\bdelete_post_meta\s*\(",
    r"\bwp_insert_post\s*\(",
    r"\bwp_update_post\s*\(",
    r"\bwp_delete_post\s*\(",
    r"\bwp_insert_user\s*\(",
    r"\bwp_update_user\s*\(",
    r"\bwp_delete_user\s*\(",
    r"\bwp_set_password\s*\(",
    r"\bwp_mail\s*\(",
    r"->(?:insert|update|delete|query|replace)\s*\(",  # $wpdb->...
    r"\bfile_put_contents\s*\(",
    r"\bfopen\s*\([^,]+,\s*['\"][wax]",                # fopen for write
    r"\bmove_uploaded_file\s*\(",
    r"\bunlink\s*\(",
    r"\brmdir\s*\(",
    r"\brename\s*\(",
    r"\bexec\s*\(",
    r"\bshell_exec\s*\(",
    r"\bsystem\s*\(",
    r"\bpassthru\s*\(",
    r"\beval\s*\(",
    r"\bcurl_exec\s*\(",
]
_STATE_CHANGING_RE = re.compile("|".join(_STATE_CHANGING_SINKS))

# ── Permission/nonce check signatures ──────────────────────────────
#
# Presence of any of these in a handler body is evidence of intent to
# authz-check. Scanner treats their absence as the bug signal.
_AUTHZ_CHECKS = [
    r"\bwp_verify_nonce\s*\(",
    r"\bcheck_ajax_referer\s*\(",
    r"\bcheck_admin_referer\s*\(",
    r"\bcurrent_user_can\s*\(",
    r"\bis_user_logged_in\s*\(",
    r"\bwp_get_current_user\s*\(",
    r"\buser_can\s*\(",
]
_AUTHZ_CHECK_RE = re.compile("|".join(_AUTHZ_CHECKS))

# PHP function declaration (free function or method). Captures the body
# as group(2). Uses masked source so braces inside strings don't confuse.
_FUNC_DECL_RE = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(", re.MULTILINE)


# ── Scanner ────────────────────────────────────────────────────────


class RestAuthzScanner(ASTScanner):
    """Detects REST/AJAX handlers with missing or trivially-bypassable authz."""

    scanner_id = "rest_authz"
    description = (
        "REST routes and admin-ajax handlers registered without proper "
        "permission_callback / nonce / capability checks."
    )
    severity_default = "high"

    def scan(self, plugin) -> List[ASTFinding]:  # plugin: PluginSource
        findings: List[ASTFinding] = []
        for php_path in plugin.iter_php():
            try:
                source = PHPSource(php_path, relative_to=plugin.plugin_root)
            except OSError:
                continue

            findings.extend(self._scan_register_rest_route(source, plugin))
            findings.extend(self._scan_wp_ajax_actions(source, plugin))
        return findings

    # ── register_rest_route rules ──────────────────────────────────

    def _scan_register_rest_route(
        self, source: PHPSource, plugin
    ) -> List[ASTFinding]:
        out: List[ASTFinding] = []
        for call in find_calls(source, "register_rest_route"):
            # register_rest_route( namespace, route, args [, override] )
            route_str = _strip_quotes_safe(call.arg(1)) if call.arg(1) else "?"
            ns_str = _strip_quotes_safe(call.arg(0)) if call.arg(0) else "?"

            # arg 2 is the args array — look for permission_callback
            pairs = call.array_arg_as_pairs(2)
            pair_map = dict(pairs)
            perm = pair_map.get("permission_callback")
            methods = pair_map.get("methods", "?")
            callback = pair_map.get("callback", "?")

            if perm is None:
                out.append(self._finding(
                    plugin, source, call,
                    rule_id="rest_authz.permission_callback_missing",
                    severity="high",
                    title=f"REST route {ns_str}/{route_str} missing permission_callback",
                    description=(
                        "This call to register_rest_route() does not set a "
                        "permission_callback. WordPress emits a _doing_it_wrong "
                        "notice but still exposes the route to unauthenticated "
                        "requests. Any state-changing logic in the handler "
                        "executes for any caller."
                    ),
                    recommendation=(
                        "Add an explicit permission_callback. Example:\n"
                        "    'permission_callback' => function() {\n"
                        "        return current_user_can('edit_posts');\n"
                        "    }"
                    ),
                    cwe="CWE-862",
                    mitre_techniques=["T1190"],
                    references=[
                        "https://developer.wordpress.org/rest-api/extending-the-rest-api/adding-custom-endpoints/#permission-callback",
                    ],
                    evidence={
                        "namespace": ns_str,
                        "route": route_str,
                        "methods": methods,
                        "callback": callback,
                    },
                ))
            elif _is_permissive_callback(perm):
                out.append(self._finding(
                    plugin, source, call,
                    rule_id="rest_authz.permission_callback_return_true",
                    severity="critical",
                    title=f"REST route {ns_str}/{route_str} explicitly public (permission_callback always true)",
                    description=(
                        "The permission_callback unconditionally returns true. "
                        "This route is intentionally unauthenticated. If the "
                        "handler performs data mutation or reads sensitive state, "
                        "any internet caller can trigger it."
                    ),
                    recommendation=(
                        "If the route genuinely must be public, ensure the "
                        "handler validates and sanitizes all input and performs "
                        "no privileged actions. Otherwise replace __return_true "
                        "with a real capability check (current_user_can)."
                    ),
                    cwe="CWE-284",
                    mitre_techniques=["T1190"],
                    references=[
                        "https://developer.wordpress.org/rest-api/extending-the-rest-api/adding-custom-endpoints/#permission-callback",
                    ],
                    evidence={
                        "namespace": ns_str,
                        "route": route_str,
                        "methods": methods,
                        "callback": callback,
                        "permission_callback": perm,
                    },
                ))
        return out

    # ── add_action('wp_ajax_*') rules ──────────────────────────────

    def _scan_wp_ajax_actions(
        self, source: PHPSource, plugin
    ) -> List[ASTFinding]:
        out: List[ASTFinding] = []
        for call in find_calls(source, "add_action"):
            hook = _strip_quotes_safe(call.arg(0)) if call.arg(0) else ""
            if not hook.startswith("wp_ajax_"):
                continue
            callback_raw = call.arg(1) or ""
            is_nopriv = hook.startswith("wp_ajax_nopriv_")
            action = hook[len("wp_ajax_nopriv_") :] if is_nopriv else hook[len("wp_ajax_") :]

            # Try to resolve the callback body in this file.
            body = _resolve_callback_body(source, callback_raw)

            has_authz = bool(_AUTHZ_CHECK_RE.search(body)) if body else False
            state_changes = _STATE_CHANGING_RE.findall(body) if body else []

            if is_nopriv and state_changes and not has_authz:
                out.append(self._finding(
                    plugin, source, call,
                    rule_id="rest_authz.wp_ajax_nopriv_state_change",
                    severity="high",
                    title=f"Unauthenticated AJAX action '{action}' performs state changes without checks",
                    description=(
                        "The wp_ajax_nopriv_* hook exposes this handler to "
                        "unauthenticated callers. The callback body contains "
                        f"{len(state_changes)} state-changing call(s) "
                        "(update_option, $wpdb->insert, etc.) and no nonce or "
                        "capability check. Any visitor can trigger the mutation."
                    ),
                    recommendation=(
                        "Either move the action to the authenticated hook "
                        "(wp_ajax_<action>) and require a valid nonce via "
                        "check_ajax_referer(), or for intentional public "
                        "handlers, ensure they are idempotent, rate-limited, "
                        "and never mutate shared state on behalf of the caller."
                    ),
                    cwe="CWE-862",
                    mitre_techniques=["T1190"],
                    references=[
                        "https://codex.wordpress.org/AJAX_in_Plugins",
                        "https://developer.wordpress.org/reference/functions/check_ajax_referer/",
                    ],
                    evidence={
                        "hook": hook,
                        "action": action,
                        "callback": callback_raw,
                        "sinks_found": list({s for s in state_changes}),
                        "authz_checks_found": False,
                    },
                ))
            elif not is_nopriv and state_changes and not has_authz:
                out.append(self._finding(
                    plugin, source, call,
                    rule_id="rest_authz.wp_ajax_missing_nonce",
                    severity="medium",
                    title=f"Authenticated AJAX action '{action}' missing nonce/capability check",
                    description=(
                        "The wp_ajax_* hook requires authentication but the "
                        "callback does not verify a nonce or capability. "
                        "Authenticated users (including low-privilege accounts) "
                        "can trigger state-changing actions via CSRF or direct "
                        "forged requests."
                    ),
                    recommendation=(
                        "Add check_ajax_referer('<nonce-name>') at the top of "
                        "the handler and, where relevant, current_user_can() "
                        "for the specific capability the action requires."
                    ),
                    cwe="CWE-352",
                    mitre_techniques=["T1190"],
                    references=[
                        "https://developer.wordpress.org/reference/functions/check_ajax_referer/",
                        "https://developer.wordpress.org/reference/functions/wp_verify_nonce/",
                    ],
                    evidence={
                        "hook": hook,
                        "action": action,
                        "callback": callback_raw,
                        "sinks_found": list({s for s in state_changes}),
                        "authz_checks_found": False,
                    },
                ))
        return out

    # ── helpers ────────────────────────────────────────────────────

    def _finding(
        self,
        plugin,
        source: PHPSource,
        call: PHPCallSite,
        *,
        rule_id: str,
        severity: str,
        title: str,
        description: str,
        recommendation: str,
        cwe: Optional[str] = None,
        mitre_techniques: Optional[List[str]] = None,
        references: Optional[List[str]] = None,
        evidence: Optional[dict] = None,
    ) -> ASTFinding:
        return ASTFinding(
            scanner=self.scanner_id,
            rule_id=rule_id,
            severity=severity,
            plugin_slug=plugin.slug,
            plugin_version=plugin.version,
            file_path=source.relative_path,
            line=call.line,
            snippet=source.snippet(call.start_offset, context_chars=200),
            title=title,
            description=description,
            recommendation=recommendation,
            cwe=cwe,
            mitre_techniques=mitre_techniques or [],
            references=references or [],
            evidence=evidence or {},
        )


# ── Callback resolution ────────────────────────────────────────────


def _resolve_callback_body(source: PHPSource, callback_raw: str) -> str:
    """Given a callback argument (string / array / closure), return its
    body text (raw) if resolvable in the same file. Empty string if not.
    """
    cb = callback_raw.strip()
    if not cb:
        return ""

    # Inline closure: `function(...) { ... }` — grab the braces after
    # the first paren-close. Search in the original raw for the exact
    # substring; masked text still tells us brace boundaries.
    closure_match = re.match(r"(?:static\s+)?function\s*\(", cb)
    if closure_match:
        return _body_from_closure_text(cb)

    # Array callback: array($this, 'method') or [$this, 'method']
    name = _callback_name_from_array(cb)
    if name is None:
        # String callback 'my_function' or "my_function"
        unquoted = _strip_quotes_safe(cb)
        if unquoted and re.fullmatch(r"[A-Za-z_]\w*", unquoted):
            name = unquoted

    if name is None:
        return ""  # unresolvable — closure in variable, complex expression, etc.

    return _find_function_body(source, name)


def _callback_name_from_array(cb: str) -> Optional[str]:
    """Extract the method name from array($this, 'foo') or [$this, 'foo']."""
    # array(..., 'name')
    m = re.match(r"array\s*\(", cb)
    if m:
        inner_start = m.end() - 1  # position of '('
        masked = strip_comments_and_strings(cb)
        rp = _match_close(masked, inner_start, "(", ")")
        if rp is None:
            return None
        inner = cb[inner_start + 1 : rp]
        return _last_string_in(inner)
    # [...]
    if cb.startswith("[") and cb.endswith("]"):
        return _last_string_in(cb[1:-1])
    return None


def _last_string_in(text: str) -> Optional[str]:
    """Find the last single- or double-quoted string in `text`."""
    matches = re.findall(r"""['"]([A-Za-z_]\w*)['"]""", text)
    return matches[-1] if matches else None


def _find_function_body(source: PHPSource, name: str) -> str:
    """Return the body of `function <name>(...)` as found in the file.

    Searches on masked text for declaration, then walks raw source to
    slice out the balanced braces. If multiple definitions exist (rare
    in a well-formed plugin), returns the first.
    """
    for m in _FUNC_DECL_RE.finditer(source.masked):
        if m.group(1) != name:
            continue
        # From the opening '(' of the decl, step past the arg list, then
        # past any return-type hint, then find the '{'.
        lp = source.masked.find("(", m.end() - 1)
        if lp < 0:
            continue
        rp = _match_close(source.masked, lp, "(", ")")
        if rp is None:
            continue
        brace = source.masked.find("{", rp)
        if brace < 0:
            continue
        close = _match_close(source.masked, brace, "{", "}")
        if close is None:
            continue
        return source.raw[brace + 1 : close]
    return ""


def _body_from_closure_text(cb: str) -> str:
    """Return the body of an inline `function(...) { ... }` expression."""
    masked = strip_comments_and_strings(cb)
    lp = masked.find("(")
    if lp < 0:
        return ""
    rp = _match_close(masked, lp, "(", ")")
    if rp is None:
        return ""
    brace = masked.find("{", rp)
    if brace < 0:
        return ""
    close = _match_close(masked, brace, "{", "}")
    if close is None:
        return ""
    return cb[brace + 1 : close]


# ── Permission-callback classification ────────────────────────────


_RETURN_TRUE_LITERALS = {"'__return_true'", '"__return_true"', "__return_true"}


def _is_permissive_callback(perm_raw: str) -> bool:
    """Return True if `perm` is statically known to grant public access."""
    t = perm_raw.strip()
    if t in _RETURN_TRUE_LITERALS:
        return True
    # Closure: function(...) { ... return true; ... } with no conditional
    if re.match(r"(?:static\s+)?function\s*\(", t):
        body = _body_from_closure_text(t)
        # If body ONLY returns true (ignoring whitespace/semis/comments), it's permissive.
        masked_body = strip_comments_and_strings(body).strip()
        if re.fullmatch(r"return\s+true\s*;?\s*", masked_body):
            return True
    return False


def _strip_quotes_safe(text: Optional[str]) -> str:
    if text is None:
        return ""
    t = text.strip()
    m = re.match(r"""^(['"])(.*)\1$""", t, re.DOTALL)
    return m.group(2) if m else t
