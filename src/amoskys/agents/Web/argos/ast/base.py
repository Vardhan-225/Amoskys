"""AST scanner primitives — PHP source wrapping + call-site extraction.

Design:
    PHPSource
        One .php file. Holds raw text + a "neutralized" copy where all
        comments and string literals are replaced with same-length
        filler so regexes on the neutralized text never match inside
        strings/comments. Offsets map 1:1 back to the raw text for
        evidence extraction.

    PHPCallSite
        One parsed function call: name, arg-list raw text, source
        position, line number. Arg parsing is balance-aware so nested
        arrays, closures, and heredocs don't confuse it.

    ASTScanner
        ABC for a scan rule. One scanner = one class of finding.
        Scanners are cheap to construct; they do all work in scan().

    ASTFinding
        A scanner's output. Includes plugin context so a bag of
        findings from many plugins is self-describing.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

# Re-export the PluginSource type for scanner signatures without a
# circular import. At runtime we pass duck-typed objects.
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from amoskys.agents.Web.argos.corpus.wporg_svn import PluginSource


# ── Findings ───────────────────────────────────────────────────────

@dataclass
class ASTFinding:
    """A single AST scanner hit.

    Designed to survive serialization into the existing Engagement
    finding schema (see engine.Finding). The scanner's caller (the
    PluginASTTool adapter) maps these into engagement Findings at
    report time.
    """

    scanner: str         # e.g. "rest_authz"
    rule_id: str         # e.g. "rest_authz.permission_callback_return_true"
    severity: str        # info | low | medium | high | critical
    plugin_slug: str
    plugin_version: str
    file_path: str       # relative to plugin_root
    line: int
    snippet: str         # ~200 chars of surrounding source
    title: str
    description: str
    recommendation: str = ""
    references: List[str] = field(default_factory=list)
    cwe: Optional[str] = None
    mitre_techniques: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_engagement_finding(self) -> Dict[str, Any]:
        """Shape matching engine.Finding.from_tool_result(raw=...) dict.

        Severity, title, description, evidence, references, cwe,
        mitre_techniques all carry over directly.
        """
        return {
            "template_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "cwe": self.cwe,
            "references": self.references,
            "mitre_techniques": self.mitre_techniques,
            "evidence": {
                "plugin_slug": self.plugin_slug,
                "plugin_version": self.plugin_version,
                "file": self.file_path,
                "line": self.line,
                "snippet": self.snippet,
                "recommendation": self.recommendation,
                **self.evidence,
            },
        }


# ── Source wrapping ────────────────────────────────────────────────

# Comment + string literal recognition regex. We use this to build a
# "neutralized" copy where each comment/string is replaced with a
# same-length blob of a neutral filler char. This lets later regexes
# scan for structural patterns (like `function names` or `=>` keys)
# without matching inside strings/comments.
#
# Order matters: heredoc/nowdoc first, then block comments, then line
# comments, then strings.
_PHP_MASK_PATTERN = re.compile(
    r"""
    <<<['"]?(\w+)['"]?\n .*? \n\1;             # heredoc / nowdoc
    | /\* .*? \*/                              # block comment
    | //[^\n]*                                 # line comment
    | \#[^\n]*                                 # hash comment
    | "(?: \\. | [^"\\] )*"                    # double-quoted string
    | '(?: \\. | [^'\\] )*'                    # single-quoted string
    """,
    re.VERBOSE | re.DOTALL,
)


def strip_comments_and_strings(text: str, fill: str = "_") -> str:
    """Return a copy of `text` with all comments/strings masked out.

    The return has identical length and newline positions, so regex
    match offsets on the masked copy map 1:1 back to the raw source.
    """

    def _mask(m: re.Match) -> str:
        span = m.group(0)
        # Preserve newlines so line numbers still work.
        return "".join("\n" if c == "\n" else fill for c in span)

    return _PHP_MASK_PATTERN.sub(_mask, text)


class PHPSource:
    """One PHP file, wrapped for scanner-friendly access."""

    def __init__(self, path: Path, relative_to: Optional[Path] = None) -> None:
        self.path = path
        self.relative_path = (
            str(path.relative_to(relative_to)) if relative_to else str(path)
        )
        try:
            self.raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            raise OSError(f"could not read {path}: {e}") from e
        self.masked = strip_comments_and_strings(self.raw)

        # Precompute line-start offsets for O(log n) line-number lookup.
        self._line_starts = [0]
        for i, c in enumerate(self.raw):
            if c == "\n":
                self._line_starts.append(i + 1)

    def line_of(self, offset: int) -> int:
        """Return 1-based line number of the given character offset."""
        # Binary search: the largest i such that _line_starts[i] <= offset.
        lo, hi = 0, len(self._line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self._line_starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    def snippet(self, offset: int, context_chars: int = 120) -> str:
        start = max(0, offset - context_chars // 2)
        end = min(len(self.raw), offset + context_chars // 2)
        return self.raw[start:end].strip()


# ── Call-site extraction ───────────────────────────────────────────

@dataclass
class PHPCallSite:
    """One parsed call like `register_rest_route( 'ns', '/r', array(...) )`."""

    name: str           # function name (unqualified; we don't track namespaces)
    args_raw: str       # text between the outermost parens (no enclosing parens)
    args: List[str]     # top-level args split on unquoted, unbracketed commas
    start_offset: int   # offset of the function name in source.raw
    args_start: int     # offset of the '(' in source.raw
    args_end: int       # offset of the matching ')' in source.raw
    line: int           # 1-based line of the function name
    source: PHPSource

    def arg(self, i: int) -> Optional[str]:
        return self.args[i].strip() if i < len(self.args) else None

    def array_arg_as_pairs(self, i: int) -> List[Tuple[str, str]]:
        """If arg i is a PHP array literal, return its top-level k=>v pairs.

        Only `'key' => value` pairs are extracted. Numerically-indexed
        entries are ignored (scanners that need them can split on ',' in
        the stripped inner). Keys are returned with quotes stripped.
        """
        raw = self.arg(i) or ""
        inner = _array_inner(raw)
        if inner is None:
            return []
        pairs: List[Tuple[str, str]] = []
        for element in _split_mask_aware(inner, sep=","):
            kv = _split_mask_aware(element, sep="=>", limit=1)
            if len(kv) != 2:
                continue
            key = _strip_quotes(kv[0].strip())
            pairs.append((key, kv[1].strip()))
        return pairs


def find_calls(source: PHPSource, name: str) -> List[PHPCallSite]:
    """Find every top-level call to `name(...)` in a PHP source.

    "Top-level" here = anywhere in the file that textually looks like a
    call to the named function. This catches calls inside classes,
    closures, conditionals — which is exactly what scanners want.

    Uses the masked source to avoid matching `register_rest_route` that
    appears inside a comment or string literal.
    """
    if not name:
        return []

    # \b before name; allow horizontal whitespace between name and '('.
    pattern = re.compile(rf"\b{re.escape(name)}\s*\(")
    hits: List[PHPCallSite] = []

    for m in pattern.finditer(source.masked):
        open_paren = m.end() - 1
        close_paren = _match_close(source.masked, open_paren, "(", ")")
        if close_paren is None:
            continue
        args_raw = source.raw[open_paren + 1 : close_paren]
        masked_slice = source.masked[open_paren + 1 : close_paren]
        # Split on the masked slice so commas inside strings/comments
        # don't break arg boundaries; return raw slices as the args.
        ranges = _split_top_level_ranges(masked_slice, sep=",")
        args = [args_raw[s:e] for s, e in ranges]
        hits.append(
            PHPCallSite(
                name=name,
                args_raw=args_raw,
                args=args,
                start_offset=m.start(),
                args_start=open_paren,
                args_end=close_paren,
                line=source.line_of(m.start()),
                source=source,
            )
        )
    return hits


# ── Bracket matching & arg splitting ──────────────────────────────
#
# All helpers operate on the MASKED text (strings/comments zeroed out)
# so they see only structural brackets, never ones embedded in strings.


def _match_close(text: str, open_idx: int, open_ch: str, close_ch: str) -> Optional[int]:
    """Return the index of the close bracket matching text[open_idx]."""
    depth = 0
    pairs = {"(": ")", "[": "]", "{": "}"}
    i = open_idx
    n = len(text)
    while i < n:
        c = text[i]
        if c in pairs:
            depth += 1
        elif c in pairs.values():
            depth -= 1
            if depth == 0:
                return i if c == close_ch else None
        i += 1
    return None


def _split_top_level_ranges(masked: str, sep: str = ",", limit: int = -1) -> List[Tuple[int, int]]:
    """Find (start, end) offsets of top-level segments split by `sep`.

    Operates on MASKED text; returned offsets apply equally to raw
    because the mask is length-preserving.
    """
    out: List[Tuple[int, int]] = []
    depth = 0
    last = 0
    i = 0
    n = len(masked)
    sep_len = len(sep)
    while i < n:
        c = masked[i]
        if c in "([{":
            depth += 1
            i += 1
            continue
        if c in ")]}":
            depth -= 1
            i += 1
            continue
        if depth == 0 and masked[i : i + sep_len] == sep:
            out.append((last, i))
            last = i + sep_len
            i += sep_len
            if limit > 0 and len(out) == limit:
                break
            continue
        i += 1
    out.append((last, n))
    return out


def _split_mask_aware(text: str, sep: str = ",", limit: int = -1) -> List[str]:
    """Mask `text` locally, split at depth zero, return raw slices.

    Use this when you have a raw string (e.g., the inside of an array
    literal that was itself a raw slice) and need a bracket-aware split
    that still returns raw text to the caller.
    """
    masked = strip_comments_and_strings(text)
    return [text[s:e] for s, e in _split_top_level_ranges(masked, sep=sep, limit=limit)]


def _array_inner(text: str) -> Optional[str]:
    """Return the inside of a PHP array literal, or None if `text` isn't one.

    Accepts both `array( ... )` and `[ ... ]` forms. Returns raw inner
    text (comments/strings preserved).
    """
    t = text.strip()
    if t.startswith("array") and "(" in t:
        lp = t.index("(")
        masked = strip_comments_and_strings(t)
        rp = _match_close(masked, lp, "(", ")")
        if rp is None:
            return None
        return t[lp + 1 : rp]
    if t.startswith("[") and t.endswith("]"):
        return t[1:-1]
    return None


_QUOTE_STRIPPABLE = re.compile(r"""^(['"])(.*)\1$""", re.DOTALL)


def _strip_quotes(text: str) -> str:
    t = text.strip()
    m = _QUOTE_STRIPPABLE.match(t)
    return m.group(2) if m else t


# ── Scanner ABC ────────────────────────────────────────────────────

class ASTScanner(ABC):
    """Base class for pattern-based PHP source scanners."""

    # Subclasses override:
    scanner_id: str = ""
    description: str = ""
    severity_default: str = "medium"

    @abstractmethod
    def scan(self, plugin: "PluginSource") -> List[ASTFinding]:
        """Scan one PluginSource. Returns zero or more findings."""

    def scan_many(self, plugins: Iterable["PluginSource"]) -> Iterator[ASTFinding]:
        for p in plugins:
            yield from self.scan(p)
