"""Time-of-check → time-of-use candidate discovery.

Two-phase analysis
------------------

Phase 1 — AST pattern match (offline, on plugin source):
  Look for functions that:
      (a) read state:    SELECT ... FROM users WHERE ...
                          get_user_by / get_option / wp_get_current_user
      (b) immediately followed by a state mutation:
                          UPDATE ... / INSERT ... / update_option / wp_update_user
  Without:
      (c) a lock, transaction, or serialized operation between them.

Phase 2 — Response-pair comparison (runtime, on endpoint pairs):
  Given two endpoints (one "check", one "use"), measure:
      - idempotency of the check under rapid-fire
      - response divergence between a fresh call and a concurrent call

This module implements both. Phase 1 is source-code aware (ships as
`scan_for_toctou_candidates(plugin_path)`), phase 2 is runtime
(`analyze_endpoint_pair(check_url, use_url, sender)`).
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("amoskys.argos.race.toctou")


# ── Data model ────────────────────────────────────────────────────


@dataclass
class TOCTOUCandidate:
    kind: str  # "source_pattern" or "runtime_divergence"
    severity: str = "medium"
    location: str = ""  # file:line or URL
    evidence: str = ""
    check_operation: str = ""
    use_operation: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return {
            "kind": self.kind,
            "severity": self.severity,
            "location": self.location,
            "evidence": self.evidence,
            "check_operation": self.check_operation,
            "use_operation": self.use_operation,
            "metadata": dict(self.metadata),
        }


@dataclass
class TOCTOUReport:
    candidates: List[TOCTOUCandidate] = field(default_factory=list)
    files_scanned: int = 0
    endpoints_probed: int = 0
    errors: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "candidates": [c.to_dict() for c in self.candidates],
            "files_scanned": self.files_scanned,
            "endpoints_probed": self.endpoints_probed,
            "errors": list(self.errors),
        }


# ── Phase 1: PHP source-pattern scan ─────────────────────────────


_CHECK_PATTERNS = [
    (re.compile(r"\bget_user_by\s*\("), "get_user_by"),
    (re.compile(r"\bget_option\s*\("), "get_option"),
    (re.compile(r"\bwp_get_current_user\s*\("), "wp_get_current_user"),
    (re.compile(r"\$wpdb->get_row\s*\("), "wpdb->get_row"),
    (re.compile(r"\$wpdb->get_var\s*\("), "wpdb->get_var"),
    (re.compile(r"\bSELECT\b.*\bFROM\b", re.I | re.DOTALL), "raw SELECT"),
    (re.compile(r"\bfile_exists\s*\("), "file_exists check"),
    (re.compile(r"\bis_file\s*\("), "is_file check"),
]

_USE_PATTERNS = [
    (re.compile(r"\bwp_update_user\s*\("), "wp_update_user"),
    (re.compile(r"\bupdate_option\s*\("), "update_option"),
    (re.compile(r"\$wpdb->update\s*\("), "wpdb->update"),
    (re.compile(r"\$wpdb->insert\s*\("), "wpdb->insert"),
    (re.compile(r"\$wpdb->query\s*\(\s*['\"]UPDATE\b", re.I), "raw UPDATE"),
    (re.compile(r"\$wpdb->query\s*\(\s*['\"]INSERT\b", re.I), "raw INSERT"),
    (re.compile(r"\bmove_uploaded_file\s*\("), "move_uploaded_file"),
    (re.compile(r"\bfile_put_contents\s*\("), "file_put_contents"),
    (re.compile(r"\brename\s*\("), "rename"),
    (re.compile(r"\bunlink\s*\("), "unlink"),
]

_LOCK_PATTERNS = [
    re.compile(r"\bSELECT\b.*\bFOR\s+UPDATE\b", re.I | re.DOTALL),
    re.compile(r"\bLOCK\s+TABLES\b", re.I),
    re.compile(r"\bSTART\s+TRANSACTION\b", re.I),
    re.compile(r"\bBEGIN\s*;", re.I),
    re.compile(r"\bflock\s*\("),
    re.compile(r"\bwp_cache_add\b"),  # some atomic-style cache ops
]


def _scan_php_file(path: str, source: str) -> List[TOCTOUCandidate]:
    """Look for check→use within the same function body with no lock between."""
    cands: List[TOCTOUCandidate] = []
    # Tokenize by function definitions (rough)
    fn_splits = re.split(r"(function\s+\w+\s*\([^)]*\)\s*\{)", source)
    # Reassemble (header, body) pairs
    chunks = []
    for i in range(1, len(fn_splits), 2):
        header = fn_splits[i]
        body = fn_splits[i + 1] if i + 1 < len(fn_splits) else ""
        chunks.append((header, body))
    for header, body in chunks:
        # If the function body has ANY lock/transaction marker, treat as safe.
        # Fine-grained position analysis is error-prone; a function-level
        # approximation catches the common "wrap-the-critical-section" pattern.
        if any(lr.search(body) for lr in _LOCK_PATTERNS):
            continue
        # Find check occurrences
        for check_re, check_name in _CHECK_PATTERNS:
            for m_check in check_re.finditer(body):
                # Look for a use pattern AFTER the check, within the same function,
                # and with no lock between
                tail = body[m_check.end() :]
                for use_re, use_name in _USE_PATTERNS:
                    m_use = use_re.search(tail)
                    if not m_use:
                        continue
                    between = tail[: m_use.start()]
                    if any(lr.search(between) for lr in _LOCK_PATTERNS):
                        continue
                    # Crude line-number inference
                    prefix = source[: m_check.start()]
                    line = prefix.count("\n") + 1
                    fn_name_m = re.search(r"function\s+(\w+)", header)
                    fn_name = fn_name_m.group(1) if fn_name_m else "?"
                    cands.append(
                        TOCTOUCandidate(
                            kind="source_pattern",
                            severity="medium",
                            location=f"{path}:{line} (in fn {fn_name}())",
                            evidence=(
                                f"check `{check_name}` followed by `{use_name}` "
                                f"with no lock/transaction between"
                            ),
                            check_operation=check_name,
                            use_operation=use_name,
                            metadata={"function": fn_name},
                        )
                    )
    return cands


def scan_for_toctou_candidates(plugin_dir: str, max_files: int = 200) -> TOCTOUReport:
    """Walk a plugin directory, scan .php files for check→use patterns."""
    report = TOCTOUReport()
    seen = 0
    for root, _dirs, files in os.walk(plugin_dir):
        for fname in files:
            if not fname.endswith(".php"):
                continue
            if seen >= max_files:
                report.errors.append(f"hit max_files={max_files}; stopping walk")
                return report
            path = os.path.join(root, fname)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    src = f.read()
                report.files_scanned += 1
                seen += 1
                report.candidates.extend(_scan_php_file(path, src))
            except Exception as exc:  # noqa: BLE001
                report.errors.append(f"{path}: {exc}")
    return report


# ── Phase 2: runtime endpoint-pair analysis ───────────────────────


def analyze_endpoint_pair(
    check_url: str,
    use_url: str,
    sender: Callable,
    sample_body: Optional[str] = None,
    n_probes: int = 10,
) -> TOCTOUCandidate:
    """Fire `check_url` and immediately `use_url` N times.

    sender(url, method, headers, body, timeout)
        -> (status, headers, body_text, elapsed_ms)

    Race indicator: use_url responds `200 OK` on more than one call
    when it logically should succeed only once. That's only a
    heuristic; the operator confirms with the single-packet attack.
    """
    successes = 0
    attempts = 0
    for _ in range(n_probes):
        try:
            sender(check_url, "GET", {}, None, 5.0)
            status, _h, _b, _e = sender(use_url, "POST", {}, sample_body, 5.0)
            if status in (200, 201, 302):
                successes += 1
            attempts += 1
        except Exception as exc:  # noqa: BLE001
            return TOCTOUCandidate(
                kind="runtime_divergence",
                severity="info",
                location=f"{check_url} → {use_url}",
                evidence=f"sender raised: {exc}",
            )
    race_sig = successes > 1
    return TOCTOUCandidate(
        kind="runtime_divergence",
        severity="high" if race_sig else "info",
        location=f"{check_url} → {use_url}",
        evidence=(
            f"{successes}/{attempts} use calls succeeded — "
            f"{'SUSPECT TOCTOU' if race_sig else 'atomic or already-used'}"
        ),
        check_operation=f"GET {check_url}",
        use_operation=f"POST {use_url}",
        metadata={"successes": successes, "attempts": attempts},
    )


__all__ = [
    "TOCTOUCandidate",
    "TOCTOUReport",
    "scan_for_toctou_candidates",
    "analyze_endpoint_pair",
]
