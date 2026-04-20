"""Cross-Site Request Forgery (CSRF) scanner — plugin-source layer.

The existing rest_authz scanner catches REST / wp_ajax handlers that
lack a `permission_callback`.  This scanner catches the OTHER half:

  - admin_post_*   — the WP form-submission endpoint
  - load-<hook>    — admin screen "on save" hooks
  - admin_init with conditional $_POST dispatch — classic "handle form
    if button was pressed" pattern

In each of those, the correct defense is ONE of:
  check_admin_referer( 'nonce_action' )   or
  check_ajax_referer( 'nonce_action' )    or
  wp_verify_nonce( $_POST[...], 'action' ) before any mutation.

If the handler doesn't invoke any of those in the first ~20 statements
and does call a state-mutating function (update_option, wp_insert_post,
$wpdb->insert/update/delete, etc.), the handler is CSRF-vulnerable.

Rules:

    csrf.admin_post_no_nonce
        add_action('admin_post_<slug>', $cb) where $cb body mutates
        state and calls no nonce-verification helper. HIGH.

    csrf.admin_post_nopriv_state_change
        add_action('admin_post_nopriv_<slug>', $cb) with any state
        mutation. Unauth + mutating = CRITICAL.

    csrf.wp_ajax_no_nonce
        add_action('wp_ajax_<slug>', $cb) without check_ajax_referer.
        HIGH.

    csrf.init_handler_no_referer
        admin_init / init hook whose body contains "if (isset($_POST[...]))"
        dispatch followed by a mutation, without a nonce check.
        MEDIUM (can be auth-scoped; humans triage).
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


# ── Signals ─────────────────────────────────────────────────────────

# State-changing sinks (same spirit as rest_authz but per-plugin).
_STATE_SINKS = [
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
    r"\bwp_set_current_user\s*\(",
    r"\$wpdb\s*->\s*(insert|update|delete|replace|query)\s*\(",
    r"\bfile_put_contents\s*\(",
    r"\bmove_uploaded_file\s*\(",
    r"\bunlink\s*\(",
    r"\brename\s*\(",
]
_STATE_SINK_RE = re.compile("|".join(_STATE_SINKS))

# Nonce/referer checks — any of these in handler body defuses the finding.
_NONCE_CHECKS = [
    r"\bcheck_admin_referer\s*\(",
    r"\bcheck_ajax_referer\s*\(",
    r"\bwp_verify_nonce\s*\(",
    r"\bcurrent_user_can\s*\(",
]
_NONCE_CHECK_RE = re.compile("|".join(_NONCE_CHECKS))


def _extract_callback_body(source: PHPSource, callback_text: str) -> Optional[str]:
    """Return the raw body text of the callback, if we can resolve it.

    Recognized callback forms (matches rest_authz conventions):
        'my_function'
        [ $this, 'method' ]   /   array( $this, 'method' )
        function(...) { ... }   (closure — body is in the argument)
    """
    raw = callback_text.strip()

    # Closure inline: `function(...) { ... }`.
    m = re.match(r"(?:static\s+)?function\s*\([^)]*\)\s*(?:use\s*\([^)]*\))?\s*\{", raw)
    if m:
        # Body runs from the `{` to the matching `}`.
        masked = strip_comments_and_strings(raw)
        lp = masked.index("{", m.end() - 1)
        depth = 0
        for i in range(lp, len(masked)):
            c = masked[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return raw[lp + 1 : i]
        return raw[lp + 1 :]

    # Named string callback: 'fn' or "fn".
    m = re.match(r"""^['"]([A-Za-z_]\w*)['"]$""", raw)
    if m:
        fname = m.group(1)
        return _find_function_body(source, fname)

    # [$this, 'method'] / array($this, 'method') → return method body in same file.
    m = re.search(r"""\[[^,\]]+,\s*['"]([A-Za-z_]\w*)['"]\s*\]""", raw)
    if not m:
        m = re.search(r"""array\s*\([^,\)]+,\s*['"]([A-Za-z_]\w*)['"]\s*\)""", raw)
    if m:
        method = m.group(1)
        return _find_function_body(source, method, is_method=True)

    return None


def _find_function_body(
    source: PHPSource, name: str, is_method: bool = False
) -> Optional[str]:
    """Return the body of a top-level function or method named `name`, or None.
    Scans the masked source for `function name (` and walks the braces."""
    # Top-level function OR class method — both begin with `function <name>`.
    pat = re.compile(rf"\bfunction\s+{re.escape(name)}\s*\(")
    m = pat.search(source.masked)
    if not m:
        return None
    # Find the opening `{`.
    after = source.masked[m.end():]
    brace_rel = after.find("{")
    if brace_rel < 0:
        return None
    open_idx = m.end() + brace_rel
    depth = 0
    for i in range(open_idx, len(source.masked)):
        c = source.masked[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return source.raw[open_idx + 1 : i]
    return source.raw[open_idx + 1 :]


def _looks_mutating(body: str) -> bool:
    return bool(_STATE_SINK_RE.search(body))


def _has_nonce_check(body: str) -> bool:
    return bool(_NONCE_CHECK_RE.search(body))


# ── Scanner ─────────────────────────────────────────────────────────


class CsrfScanner(ASTScanner):
    """Detect CSRF in admin_post / wp_ajax / admin_init handlers."""

    scanner_id = "csrf"
    description = "Detects mutating handlers without nonce / capability checks"
    severity_default = "high"

    def scan(self, plugin) -> List[ASTFinding]:
        findings: List[ASTFinding] = []
        for path in plugin.iter_php_files():
            try:
                source = PHPSource(path, relative_to=plugin.root)
            except OSError:
                continue
            findings.extend(self._scan_add_action_handlers(source, plugin))
        return findings

    def _scan_add_action_handlers(self, source, plugin):
        out: List[ASTFinding] = []
        for call in find_calls(source, "add_action"):
            hook = (call.arg(0) or "").strip().strip("'\"")
            cb = call.arg(1) or ""

            # Classify the hook. We only care about the handler families
            # that process state on a POST/GET request directly.
            if hook.startswith("admin_post_nopriv_"):
                family = "admin_post_nopriv"
                severity_unauth = "critical"
            elif hook.startswith("admin_post_"):
                family = "admin_post"
                severity_unauth = "high"
            elif hook.startswith("wp_ajax_nopriv_"):
                family = "wp_ajax_nopriv"
                severity_unauth = "critical"
            elif hook.startswith("wp_ajax_"):
                family = "wp_ajax"
                severity_unauth = "high"
            elif hook in ("admin_init", "init", "wp_loaded"):
                family = "init"
                severity_unauth = "medium"
            else:
                continue

            body = _extract_callback_body(source, cb)
            if body is None:
                continue  # Can't resolve — don't guess.

            if not _looks_mutating(body):
                continue  # No state change in body → no CSRF concern.

            if _has_nonce_check(body):
                continue  # Nonce / capability guard present → safe.

            rule_id = {
                "admin_post":        "csrf.admin_post_no_nonce",
                "admin_post_nopriv": "csrf.admin_post_nopriv_state_change",
                "wp_ajax":           "csrf.wp_ajax_no_nonce",
                "wp_ajax_nopriv":    "csrf.wp_ajax_nopriv_state_change",
                "init":              "csrf.init_handler_no_referer",
            }[family]

            title = {
                "admin_post":        f"admin_post_{hook.split('_', 2)[-1]} handler mutates state without nonce check",
                "admin_post_nopriv": f"admin_post_nopriv_{hook.split('_', 3)[-1]} is unauth AND mutates state",
                "wp_ajax":           f"wp_ajax_{hook.split('_', 2)[-1]} handler mutates state without nonce check",
                "wp_ajax_nopriv":    f"wp_ajax_nopriv_{hook.split('_', 3)[-1]} is unauth AND mutates state",
                "init":              f"{hook} hook dispatches a mutating action without nonce check",
            }[family]

            description = (
                "The handler invokes a state-changing function (update_option, "
                "wp_insert_post, $wpdb->insert/update/delete, file write, etc.) "
                "without any preceding call to check_admin_referer(), "
                "check_ajax_referer(), wp_verify_nonce(), or current_user_can(). "
                "A cross-site request will be accepted and execute the mutation "
                "if the target is authenticated."
            )
            if family in ("admin_post_nopriv", "wp_ajax_nopriv"):
                description += (
                    " This is an unauthenticated handler, so the mutation is "
                    "reachable with no authentication at all — not just via "
                    "CSRF against a logged-in user."
                )

            out.append(self._finding(
                plugin, source, call.line,
                snippet=f"add_action('{hook}', …)  — body mutates state with no nonce check",
                rule_id=rule_id,
                severity=severity_unauth,
                title=title,
                description=description,
                recommendation=(
                    "Add `check_admin_referer('your_action')` or "
                    "`wp_verify_nonce($_POST['_wpnonce'], 'your_action')` at "
                    "the top of the handler, before any state mutation. For "
                    "admin-only actions also add `current_user_can('manage_options')`."
                ),
                hook=hook,
            ))
        return out

    def _finding(
        self, plugin, source, line, snippet,
        rule_id, severity, title, description, recommendation, hook,
    ) -> ASTFinding:
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
            cwe="CWE-352",
            mitre_techniques=["T1190"],
            references=[
                "https://developer.wordpress.org/apis/security/nonces/",
                "https://owasp.org/www-community/attacks/csrf",
            ],
            evidence={"hook": hook},
        )
