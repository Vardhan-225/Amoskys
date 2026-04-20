"""Argos AST — pattern-based PHP source analysis for WordPress plugins.

Why AST (and not grep): top WP hunters do this by hand — grep for
$_GET/$_POST/$_REQUEST, trace to dangerous sinks. We mechanize that
workflow with scanners that understand:

  - Callsite boundaries (paren/bracket/brace balanced)
  - String literals (so patterns don't match inside comments)
  - Array argument structure (so we can ask "does this register_rest_route
    have a permission_callback?")
  - Callback resolution (string, array[$this, method], closure)

We deliberately don't ship a full PHP parser. The scanner primitives are
narrow, testable, and handle the 80% case. When obfuscated or unusual
code slips through, we catch it downstream in the live-probe phase.
"""

from amoskys.agents.Web.argos.ast.base import (
    ASTFinding,
    ASTScanner,
    PHPCallSite,
    PHPSource,
    find_calls,
    strip_comments_and_strings,
)
from amoskys.agents.Web.argos.ast.csrf import CsrfScanner
from amoskys.agents.Web.argos.ast.file_upload import FileUploadScanner
from amoskys.agents.Web.argos.ast.poi import PoiScanner
from amoskys.agents.Web.argos.ast.rest_authz import RestAuthzScanner
from amoskys.agents.Web.argos.ast.sql_injection import SqlInjectionScanner
from amoskys.agents.Web.argos.ast.ssrf import SsrfScanner

__all__ = [
    "ASTFinding",
    "ASTScanner",
    "CsrfScanner",
    "FileUploadScanner",
    "PHPCallSite",
    "PHPSource",
    "PoiScanner",
    "RestAuthzScanner",
    "SqlInjectionScanner",
    "SsrfScanner",
    "find_calls",
    "strip_comments_and_strings",
]
