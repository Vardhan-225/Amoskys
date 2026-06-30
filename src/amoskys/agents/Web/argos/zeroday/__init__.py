"""Argos Zero-Day Hunter — real vulnerability-discovery tradecraft.

Four techniques chained into one orchestrator:

  patch_diff.py   Compare two plugin versions, identify patched
                  security issues, generate 1-day exploits for
                  sites still on the unpatched version.

  taint.py        Inter-procedural dataflow analysis. Find paths
                  from request super-globals to dangerous sinks
                  that don't pass through any recognized sanitizer.
                  Catches novel bugs regex-only tools miss.

  fuzzer.py       Coverage-guided grammar fuzzer with response-
                  bucket analysis. Discovers hidden parameters,
                  boundary conditions, and code-path triggers.

  polyglot.py     Context-auto-detecting payloads. One string
                  exploitable across multiple interpretations —
                  universal XSS, SQL+XSS dual, LFI+upload, etc.

  zeroday.py      Orchestrator — hunt(slug, v_old, v_new) returns
                  a ZeroDayReport with everything chained.

Legal ceiling
-------------
All techniques here operate on PUBLICLY-DOWNLOADABLE plugin source
(wp.org SVN) — no target-site traffic required for discovery. The
downstream exploitation of findings against a LIVE target is a
separate step that requires consent (handled by argos.precision).
"""

from amoskys.agents.Web.argos.zeroday.fuzzer import (
    HIDDEN_PARAM_WORDLIST,
    FuzzReport,
    GrammarFuzzer,
    ResponseObservation,
    discover_hidden_params,
    response_bucket,
)
from amoskys.agents.Web.argos.zeroday.patch_diff import (
    PatchDiffReport,
    PatchedFinding,
    diff_plugin_versions,
)
from amoskys.agents.Web.argos.zeroday.polyglot import (
    ALL_POLYGLOTS,
    Polyglot,
    all_polyglots,
    polyglots_for_context,
)
from amoskys.agents.Web.argos.zeroday.taint import TaintFinding, TaintScanner
from amoskys.agents.Web.argos.zeroday.zeroday import ZeroDayReport, hunt

__all__ = [
    # patch_diff
    "PatchDiffReport",
    "PatchedFinding",
    "diff_plugin_versions",
    # taint
    "TaintFinding",
    "TaintScanner",
    # fuzzer
    "FuzzReport",
    "GrammarFuzzer",
    "HIDDEN_PARAM_WORDLIST",
    "ResponseObservation",
    "discover_hidden_params",
    "response_bucket",
    # polyglot
    "ALL_POLYGLOTS",
    "Polyglot",
    "all_polyglots",
    "polyglots_for_context",
    # orchestrator
    "ZeroDayReport",
    "hunt",
]
