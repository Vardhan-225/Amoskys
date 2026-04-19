"""PHP Object Injection (POI) scanner.

PHP unserialize() on attacker-controlled bytes is the classic
gadget-chain vulnerability: any class the plugin (or WordPress, or
any other loaded plugin) declares with a __destruct, __wakeup,
__toString, __call, or __set magic method becomes a gadget the
attacker can chain. Every real POI CVE in WordPress history has
turned into either arbitrary-file-write or RCE through chained
magic-method calls.

Rules:

    poi.unserialize_on_request
        unserialize( $_GET / $_POST / $_REQUEST / $_COOKIE / ... )
        Critical — direct exploit surface.

    poi.unserialize_on_option
        unserialize( get_option( $dynamic ) ) where the option key
        is not a constant. An attacker who can smuggle a serialized
        blob into a writable option has a POI. Critical.

    poi.maybe_unserialize_on_request
        maybe_unserialize( $_POST / ... ) — WP's own helper that
        unserializes if it looks serialized. Equally dangerous as
        raw unserialize when fed request input. Critical.

    poi.unserialize_on_meta
        unserialize( get_post_meta / get_user_meta / get_term_meta
        / get_comment_meta / get_site_meta ) — postmeta is editable
        by any author+ role; every serialized-meta plugin that
        manually unserializes is a POI candidate. High.

    poi.phar_stream_on_user_path
        file_exists() / is_file() / fopen() with a phar:// stream
        wrapper accepting user input — PHP triggers unserialize on
        the Phar metadata before even reading the archive.
        Critical.

    poi.unserialize_no_allowed_classes
        unserialize($x) without the second argument `['allowed_classes' => false]`.
        Even on non-request input, this is worth noting for defense-in-depth.
        Low.

False positives we accept for v1:
    - unserialize() on a value retrieved from a constant option
      key with a transient TTL. If the option write path is also
      protected, there's no POI surface; we still flag — operator
      triages.
    - maybe_unserialize() inside WordPress core (not plugin code) —
      we scan the plugin tree only.
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

_TAINT_GLOBALS_RE = re.compile(r"\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b")
# maybe_unserialize is the WP wrapper; same risk as raw unserialize.
_UNSERIALIZE_FUNCS = ("unserialize", "maybe_unserialize")
# Metadata getters that commonly return serialized arrays.
_META_FUNCS = (
    "get_post_meta",
    "get_user_meta",
    "get_term_meta",
    "get_comment_meta",
    "get_site_meta",
    "get_network_option",
)


def _has_taint(text: str) -> bool:
    return bool(_TAINT_GLOBALS_RE.search(text))


def _has_phar_wrapper(text: str) -> bool:
    # phar:// anywhere in the first arg — the stream trigger.
    return "phar://" in text


def _arg_is_get_option_dynamic(arg: str) -> bool:
    """Is arg shaped like `get_option($var)` or `get_option($_POST[...])`?
    (Constant-string get_option is fine.)"""
    # Extract inner of get_option( ... )
    m = re.search(r"\bget_option\s*\(\s*([^,\)]+)", arg)
    if not m:
        return False
    inner = m.group(1).strip()
    # If it's a quoted string literal with no interpolation, it's safe.
    if re.match(r"""^['"][^'"\$]+['"]$""", inner):
        return False
    return True


def _arg_is_meta_getter(arg: str) -> bool:
    for fn in _META_FUNCS:
        if re.search(rf"\b{re.escape(fn)}\s*\(", arg):
            return True
    return False


def _has_allowed_classes_false(args: List[str]) -> bool:
    """unserialize($x, ['allowed_classes' => false]) is safe. Check arg1."""
    if len(args) < 2:
        return False
    arg1 = args[1]
    if "allowed_classes" in arg1 and "false" in arg1.lower():
        return True
    return False


class PoiScanner(ASTScanner):
    """Detect PHP Object Injection primitives."""

    scanner_id = "poi"
    description = "Detects unserialize() primitives and Phar-stream POI gadgets"
    severity_default = "high"

    def scan(self, plugin) -> List[ASTFinding]:
        findings: List[ASTFinding] = []
        for path in plugin.iter_php_files():
            try:
                source = PHPSource(path, relative_to=plugin.root)
            except OSError:
                continue
            findings.extend(self._scan_unserialize(source, plugin))
            findings.extend(self._scan_phar_streams(source, plugin))
        return findings

    def _scan_unserialize(self, source, plugin) -> List[ASTFinding]:
        out: List[ASTFinding] = []
        for fn in _UNSERIALIZE_FUNCS:
            for call in find_calls(source, fn):
                arg0 = call.arg(0) or ""
                if not arg0:
                    continue

                # Strongest signal — tainted directly.
                if _has_taint(arg0):
                    rule = (
                        "poi.unserialize_on_request"
                        if fn == "unserialize"
                        else "poi.maybe_unserialize_on_request"
                    )
                    out.append(self._finding(
                        plugin, source, call.line, arg0,
                        rule_id=rule, severity="critical",
                        title=f"{fn}() on request-controlled input",
                        description=(
                            f"{fn}() is being called with a value derived "
                            f"directly from a PHP request super-global. Any "
                            f"class loaded in the process with a magic "
                            f"method (__destruct, __wakeup, __toString, …) "
                            f"becomes a chainable POI gadget. This is among "
                            f"the highest-impact plugin CVE classes."
                        ),
                        recommendation=(
                            "Replace with json_decode() for data exchange, "
                            "or pass ['allowed_classes' => false] to refuse "
                            "class instantiation entirely."
                        ),
                    ))
                    continue

                # get_option(dynamic) — operator-controlled option key.
                if _arg_is_get_option_dynamic(arg0):
                    out.append(self._finding(
                        plugin, source, call.line, arg0,
                        rule_id="poi.unserialize_on_option",
                        severity="critical",
                        title=f"{fn}() on a dynamic get_option() value",
                        description=(
                            f"The option key passed to get_option() is not a "
                            f"constant. Any attacker who can influence the "
                            f"option name (or who can write to a writable "
                            f"option_name the plugin later reads) has an "
                            f"unserialize-on-input path."
                        ),
                        recommendation=(
                            "Use a constant option name. If the key must be "
                            "dynamic, validate it against an allow-list "
                            "before reading."
                        ),
                    ))
                    continue

                # Meta getter — postmeta is editable by editor+ role.
                if _arg_is_meta_getter(arg0):
                    out.append(self._finding(
                        plugin, source, call.line, arg0,
                        rule_id="poi.unserialize_on_meta",
                        severity="high",
                        title=f"{fn}() on a post/user/term meta value",
                        description=(
                            f"{fn}() runs against a meta value that can be "
                            f"written by editor- or author-level accounts "
                            f"(and sometimes lower, depending on plugin "
                            f"behavior). An attacker with a modest role can "
                            f"plant a serialized payload and trigger POI."
                        ),
                        recommendation=(
                            "Store meta as JSON, or validate the structure "
                            "before unserializing with "
                            "['allowed_classes' => false]."
                        ),
                    ))
                    continue

                # Any other unserialize without allowed_classes=false — low.
                if not _has_allowed_classes_false(call.args):
                    out.append(self._finding(
                        plugin, source, call.line, arg0,
                        rule_id="poi.unserialize_no_allowed_classes",
                        severity="low",
                        title=f"{fn}() without allowed_classes=false",
                        description=(
                            f"{fn}() is called without passing "
                            f"['allowed_classes' => false]. Even when the "
                            f"input appears trusted, defense-in-depth "
                            f"suggests disabling class instantiation."
                        ),
                        recommendation=(
                            "Add ['allowed_classes' => false] as the second "
                            "argument unless the code specifically needs to "
                            "instantiate objects from the serialized blob."
                        ),
                    ))
        return out

    def _scan_phar_streams(self, source, plugin) -> List[ASTFinding]:
        """file_exists / is_file / fopen / stat on phar:// paths — these
        trigger Phar metadata deserialization. If the path is tainted,
        it's a full POI."""
        out: List[ASTFinding] = []
        phar_sinks = ("file_exists", "is_file", "fopen", "file_get_contents", "stat", "fileatime", "filemtime", "filesize")
        for fn in phar_sinks:
            for call in find_calls(source, fn):
                arg0 = call.arg(0) or ""
                # Only flag if there's evidence of attacker control of the
                # path AND a phar:// wrapper OR a $_FILES/$_POST string
                # being used to build the path (where phar:// could be
                # injected via the uploaded filename).
                if _has_phar_wrapper(arg0) and _has_taint(arg0):
                    out.append(self._finding(
                        plugin, source, call.line, arg0,
                        rule_id="poi.phar_stream_on_user_path",
                        severity="critical",
                        title=f"{fn}() on a request-controlled phar:// stream",
                        description=(
                            f"{fn}() is invoked on a path that contains "
                            f"both a 'phar://' wrapper and request input. "
                            f"PHP deserializes Phar metadata on stat/"
                            f"file_exists/fopen, so this is a POI gadget "
                            f"even without reading the archive."
                        ),
                        recommendation=(
                            "Reject any path whose scheme is 'phar' or which "
                            "contains 'phar://'.  Validate the path against "
                            "an allow-list of expected filesystem roots "
                            "before passing to file primitives."
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
            cwe="CWE-502",
            mitre_techniques=["T1190", "T1059"],
            references=[
                "https://www.php.net/manual/en/function.unserialize.php",
                "https://patchstack.com/articles/wordpress-php-object-injection/",
                "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
            ],
            evidence={"first_chars": snippet},
        )
