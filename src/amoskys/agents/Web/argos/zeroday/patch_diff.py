"""Patch-diff zero-day recovery.

Premise
-------
Most "zero-days" found in the wild are actually SILENT PATCHES —
the vendor shipped a fix in version N+1 without a CVE advisory.
Until every user upgrades, the pre-patch behavior is still a
working exploit against unpatched sites.

This module automates the "silent patch → working exploit" pipeline:

  1. Download plugin at both v_old and v_new from wp.org SVN.
  2. Compute a line-level diff across all PHP files.
  3. For each file that changed, run our AST scanners against
     v_old — gathering findings.
  4. Run the same scanners against v_new.
  5. Any finding that appears in v_old but NOT in v_new is
     BY DEFINITION a vuln that was patched. Report it.
  6. (Optional) synthesize a PoC via argos.precision.payload_synth.

The technique is public-knowledge (see project-zero blog on
patch diffing). What we add: automation + integration with the
wp.org SVN corpus that covers ~60,000 plugins.

Why this finds zero-days
------------------------
On wp.org, the PERCENTAGE OF SITES ON THE LATEST VERSION of any
given plugin is around 40-60% (per Wordfence / wp.org telemetry).
For popular plugins, millions of active installs lag. So a patch
shipped last week is a "zero-day" against 50% of the install base
until they update.

For the 40% of plugins that DON'T get reported to WPScan / Patchstack
CVE databases — silent patches — this module discovers them.

Output
------
PatchDiffReport with:
  - plugin slug + version pair
  - files changed (security-relevant only — /* filter */)
  - findings in v_old that disappear in v_new (ranked by severity)
  - synthesized PoCs for operator review
"""

from __future__ import annotations

import difflib
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("amoskys.argos.zeroday.patch_diff")


@dataclass
class PatchedFinding:
    """An AST finding that appears in v_old but was gone in v_new."""

    rule_id: str
    severity: str
    plugin_slug: str
    old_version: str
    new_version: str
    file_path: str
    old_line: int
    old_snippet: str
    diff_context: str  # hunk from the v_old/v_new diff
    cwe: str
    mitre: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "plugin_slug": self.plugin_slug,
            "old_version": self.old_version,
            "new_version": self.new_version,
            "file_path": self.file_path,
            "old_line": self.old_line,
            "old_snippet": self.old_snippet,
            "diff_context": self.diff_context,
            "cwe": self.cwe,
            "mitre": self.mitre,
        }


@dataclass
class PatchDiffReport:
    plugin_slug: str
    old_version: str
    new_version: str
    files_changed: List[str] = field(default_factory=list)
    patched_findings: List[PatchedFinding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plugin_slug": self.plugin_slug,
            "old_version": self.old_version,
            "new_version": self.new_version,
            "files_changed": self.files_changed,
            "findings_count": len(self.patched_findings),
            "patched_findings": [f.to_dict() for f in self.patched_findings],
            "errors": self.errors,
        }


# ── Core diff analysis ────────────────────────────────────────────


def _iter_php_files(plugin) -> List:
    """Duck-typed plugin.iter_php() -> Path iterator."""
    try:
        return list(plugin.iter_php())
    except Exception:
        return []


def _read_text(path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _path_key(path, plugin_root) -> str:
    """Path key relative to plugin_root for matching across versions."""
    try:
        return str(path.relative_to(plugin_root))
    except Exception:
        return str(path)


def _is_security_relevant_diff(old_block: str, new_block: str) -> bool:
    """Heuristic: does this diff block look security-patchish?

    We flag changes that:
      - add a call to a sanitizer (esc_html, esc_attr, wp_kses,
        sanitize_*, intval, absint, wp_verify_nonce, current_user_can,
        check_admin_referer)
      - add a `die()` / `wp_die()` / `return` guard
      - change `$_POST`/`$_GET` usage (adds validation)
      - remove or wrap a dangerous sink ($wpdb->query, unserialize,
        eval, file_put_contents, move_uploaded_file, shell_exec)
    """
    sanitizers = (
        "esc_html",
        "esc_attr",
        "esc_url",
        "esc_js",
        "esc_textarea",
        "wp_kses",
        "sanitize_text_field",
        "sanitize_key",
        "sanitize_email",
        "sanitize_title",
        "sanitize_user",
        "sanitize_meta",
        "sanitize_option",
        "intval",
        "absint",
        "floatval",
        "wp_verify_nonce",
        "check_admin_referer",
        "check_ajax_referer",
        "current_user_can",
        "is_user_logged_in",
    )
    danger = (
        "unserialize",
        "maybe_unserialize",
        "eval",
        "assert",
        "file_put_contents",
        "move_uploaded_file",
        "system",
        "shell_exec",
        "passthru",
        "exec",
        "popen",
        "include",
        "require",
    )
    old_l = old_block.lower()
    new_l = new_block.lower()
    # Added sanitizer?
    for s in sanitizers:
        if s in new_l and s not in old_l:
            return True
    # Added guard?
    if any(
        g in new_l and g not in old_l
        for g in ("wp_die", "return;", "die(", "die ", "exit;", "exit(")
    ):
        return True
    # Touched a danger sink?
    for d in danger:
        if d in old_l or d in new_l:
            return True
    # Superglobal manipulation changed.
    old_super = bool(re.search(r"\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)", old_block))
    new_super = bool(re.search(r"\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)", new_block))
    if old_super != new_super:
        return True
    return False


def _build_diff_hunk(
    old_text: str, new_text: str, context: int = 3
) -> List[Dict[str, Any]]:
    """Return list of hunk dicts with old/new blocks + context for
    each region of change. Security-relevant-filtered."""
    old_lines = old_text.splitlines(keepends=True)
    new_lines = new_text.splitlines(keepends=True)
    s = difflib.SequenceMatcher(None, old_lines, new_lines)
    hunks: List[Dict[str, Any]] = []
    for tag, i1, i2, j1, j2 in s.get_opcodes():
        if tag == "equal":
            continue
        # Expand with context.
        a1 = max(0, i1 - context)
        a2 = min(len(old_lines), i2 + context)
        b1 = max(0, j1 - context)
        b2 = min(len(new_lines), j2 + context)
        old_block = "".join(old_lines[a1:a2])
        new_block = "".join(new_lines[b1:b2])
        if _is_security_relevant_diff(old_block, new_block):
            hunks.append(
                {
                    "tag": tag,
                    "old_start": i1,
                    "old_end": i2,
                    "new_start": j1,
                    "new_end": j2,
                    "old_block": old_block,
                    "new_block": new_block,
                }
            )
    return hunks


# ── Per-scanner comparison ────────────────────────────────────────


def _scan(plugin, scanner_classes) -> List[Dict[str, Any]]:
    """Run every AST scanner against one plugin version."""
    out: List[Dict[str, Any]] = []
    for name, cls in scanner_classes.items():
        try:
            for f in cls().scan(plugin):
                out.append(
                    {
                        "key": (f.rule_id, f.file_path, f.line),
                        "rule_id": f.rule_id,
                        "severity": f.severity,
                        "file_path": f.file_path,
                        "line": f.line,
                        "snippet": f.snippet,
                        "cwe": f.cwe,
                        "mitre": list(f.mitre_techniques),
                    }
                )
        except Exception as e:  # noqa: BLE001
            logger.debug("scanner %s crashed: %s", name, e)
    return out


def _finding_in_same_logical_location(f_old: Dict, new_findings: List[Dict]) -> bool:
    """Is there a matching finding in new_findings — same rule, same file,
    same or similar line? We allow ±5 line drift because patches move
    code around even when the vuln is still there."""
    for g in new_findings:
        if g["rule_id"] != f_old["rule_id"]:
            continue
        if g["file_path"] != f_old["file_path"]:
            continue
        if abs(g["line"] - f_old["line"]) <= 5:
            return True
    return False


# ── Public API ────────────────────────────────────────────────────


def diff_plugin_versions(
    plugin_old,
    plugin_new,
    scanner_classes: Optional[Dict[str, Any]] = None,
) -> PatchDiffReport:
    """Compute the patch-diff report for one plugin's two versions.

    plugin_old and plugin_new are PluginSource-like objects with
    `.slug`, `.version`, `.plugin_root`, and `.iter_php()` — the
    same contract as WPOrgCorpus.fetch returns.

    scanner_classes is a {name: class} dict of ASTScanner subclasses.
    When None, loads all 6 built-in scanners lazily.
    """
    rep = PatchDiffReport(
        plugin_slug=plugin_old.slug,
        old_version=getattr(plugin_old, "version", "?"),
        new_version=getattr(plugin_new, "version", "?"),
    )
    if scanner_classes is None:
        try:
            from amoskys.agents.Web.argos.ast import (
                CsrfScanner,
                FileUploadScanner,
                PoiScanner,
                RestAuthzScanner,
                SqlInjectionScanner,
                SsrfScanner,
            )

            scanner_classes = {
                "rest_authz": RestAuthzScanner,
                "sql_injection": SqlInjectionScanner,
                "file_upload": FileUploadScanner,
                "poi": PoiScanner,
                "csrf": CsrfScanner,
                "ssrf": SsrfScanner,
            }
        except Exception as e:  # noqa: BLE001
            rep.errors.append(f"scanner import failed: {e}")
            return rep

    # Build path->text maps for both versions.
    old_by_path: Dict[str, str] = {}
    new_by_path: Dict[str, str] = {}
    old_root = getattr(plugin_old, "plugin_root", None)
    new_root = getattr(plugin_new, "plugin_root", None)
    for p in _iter_php_files(plugin_old):
        old_by_path[_path_key(p, old_root)] = _read_text(p)
    for p in _iter_php_files(plugin_new):
        new_by_path[_path_key(p, new_root)] = _read_text(p)

    all_paths = set(old_by_path) | set(new_by_path)
    file_hunks: Dict[str, List[Dict[str, Any]]] = {}
    for pth in sorted(all_paths):
        old_t = old_by_path.get(pth, "")
        new_t = new_by_path.get(pth, "")
        if old_t == new_t:
            continue
        h = _build_diff_hunk(old_t, new_t)
        if h:
            file_hunks[pth] = h
            rep.files_changed.append(pth)

    if not file_hunks:
        return rep  # no security-relevant diffs

    # Run scanners against both versions.
    old_findings = _scan(plugin_old, scanner_classes)
    new_findings = _scan(plugin_new, scanner_classes)

    # Findings that were in old but absent in new = patched vulns.
    # Filter further: the finding's file must be among the changed files.
    for f in old_findings:
        if f["file_path"] not in file_hunks:
            continue
        if _finding_in_same_logical_location(f, new_findings):
            continue
        # This finding was patched. Collect the diff context.
        hunks = file_hunks[f["file_path"]]
        matching_hunk = _closest_hunk(hunks, f["line"])
        rep.patched_findings.append(
            PatchedFinding(
                rule_id=f["rule_id"],
                severity=f["severity"],
                plugin_slug=plugin_old.slug,
                old_version=rep.old_version,
                new_version=rep.new_version,
                file_path=f["file_path"],
                old_line=f["line"],
                old_snippet=f["snippet"],
                diff_context=(matching_hunk.get("old_block") if matching_hunk else "")
                + "\n---\n"
                + (matching_hunk.get("new_block") if matching_hunk else ""),
                cwe=f["cwe"],
                mitre=f["mitre"],
            )
        )

    # Severity sort: critical first.
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    rep.patched_findings.sort(key=lambda p: sev_rank.get(p.severity, 9))
    return rep


def _closest_hunk(hunks: List[Dict[str, Any]], line: int) -> Optional[Dict[str, Any]]:
    """Return the hunk whose old-line range contains `line`, or the
    nearest one by distance."""
    best = None
    best_dist = 10**9
    for h in hunks:
        if h["old_start"] <= line <= h["old_end"]:
            return h
        d = min(abs(h["old_start"] - line), abs(h["old_end"] - line))
        if d < best_dist:
            best_dist = d
            best = h
    return best
