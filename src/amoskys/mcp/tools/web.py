"""AMOSKYS Web — WordPress offense + defense tools over MCP.

Exposes the Argos AST-scanner suite, the wp.org SVN corpus, and the
Aegis live event feed as MCP tools. Any MCP-compatible client (Claude
Code, Claude Desktop, a custom agent) can now:

    - Ask "what's our current coverage of the WordPress attack surface?"
    - Ask "analyze this specific plugin at this specific version"
    - Ask "hunt the top 50 plugins by install count for CVEs"
    - Ask "what is Aegis seeing on the lab right now?"

This is the bug-bounty grade sandbox on the inbound side. The MCP
tools below are the operator's keyboard; the AST scanners + wp.org
corpus are the weapons.

Tools
─────
    web_list_ast_scanners()
    web_list_blind_spots()
    web_atlas_coverage()
    web_analyze_plugin(slug, version=None, scanners=None)
    web_hunt_top_plugins(count=10, scanners=None)
    web_aegis_event_counts(hours=1)
    web_aegis_recent_critical(limit=10)
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..server import mcp


# ── Atlas parsing ─────────────────────────────────────────────────


def _atlas_path() -> Path:
    """Locate WP_ATTACK_ATLAS.md — look in project root docs/web/."""
    here = Path(__file__).resolve()
    # src/amoskys/mcp/tools/web.py → walk up to repo root
    for p in (here.parents[4], here.parents[3], here.parents[5]):
        candidate = p / "docs" / "web" / "WP_ATTACK_ATLAS.md"
        if candidate.exists():
            return candidate
    # Fallback: allow env override
    env = os.environ.get("AMOSKYS_WEB_ATLAS_PATH")
    if env and Path(env).exists():
        return Path(env)
    raise FileNotFoundError("WP_ATTACK_ATLAS.md not found; set AMOSKYS_WEB_ATLAS_PATH")


def _parse_atlas_entries(text: str) -> List[Dict[str, Any]]:
    """Walk the atlas markdown and extract the L<n>.<m> entries with their
    WATCH / PROBE / CWE / NOTES lines."""
    import re
    entries: List[Dict[str, Any]] = []
    # Entries are inside fenced blocks. Simple state machine: find lines
    # starting with Lx.y, collect until the next blank line.
    current: Optional[Dict[str, Any]] = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        m = re.match(r"^L(\d+)\.(\d+)\s+(.*)$", line)
        if m:
            if current:
                entries.append(current)
            current = {
                "id":    f"L{m.group(1)}.{m.group(2)}",
                "layer": int(m.group(1)),
                "seq":   int(m.group(2)),
                "title": m.group(3).strip(),
                "watch": "",
                "probe": "",
                "cwe":   "",
                "notes": "",
            }
            continue
        if current is None:
            continue
        m = re.match(r"^\s+(WATCH|PROBE|CWE|NOTES):\s*(.*)$", line, re.IGNORECASE)
        if m:
            key = m.group(1).lower()
            current[key] = m.group(2).strip()
            continue
        # Continuation lines (indented) append to notes/last-key.
        if line.startswith("         ") and current:
            # Append to the last non-empty field — almost always notes.
            for k in ("notes", "probe", "watch"):
                if current.get(k):
                    current[k] += " " + line.strip()
                    break
        if line == "" and current:
            entries.append(current)
            current = None
    if current:
        entries.append(current)
    return entries


def _load_atlas_entries() -> List[Dict[str, Any]]:
    p = _atlas_path()
    return _parse_atlas_entries(p.read_text(encoding="utf-8"))


# ── Scanner registry ──────────────────────────────────────────────


def _load_scanners():
    """Return dict {scanner_id: scanner_class}. Lazy-imported so the MCP
    server doesn't pay the AST import cost at boot unless asked."""
    from amoskys.agents.Web.argos.ast import (
        CsrfScanner,
        FileUploadScanner,
        PoiScanner,
        RestAuthzScanner,
        SqlInjectionScanner,
        SsrfScanner,
    )
    return {
        "rest_authz":    RestAuthzScanner,
        "sql_injection": SqlInjectionScanner,
        "file_upload":   FileUploadScanner,
        "poi":           PoiScanner,
        "csrf":          CsrfScanner,
        "ssrf":          SsrfScanner,
    }


def _run_scanners(plugin, scanner_ids: Optional[List[str]] = None):
    """Instantiate the requested scanners and run them. Returns
    [finding_dict, ...]."""
    registry = _load_scanners()
    if scanner_ids:
        chosen = {k: v for k, v in registry.items() if k in scanner_ids}
    else:
        chosen = registry
    findings = []
    for name, klass in chosen.items():
        try:
            for f in klass().scan(plugin):
                findings.append({
                    "scanner":     f.scanner,
                    "rule_id":     f.rule_id,
                    "severity":    f.severity,
                    "title":       f.title,
                    "file":        f.file_path,
                    "line":        f.line,
                    "snippet":     f.snippet,
                    "cwe":         f.cwe,
                    "mitre":       f.mitre_techniques,
                })
        except Exception as e:  # noqa: BLE001
            findings.append({
                "scanner": name,
                "rule_id": "scanner.error",
                "severity": "info",
                "title": f"scanner crashed: {type(e).__name__}: {e}",
                "file": "",
                "line": 0,
                "snippet": "",
                "cwe": "",
                "mitre": [],
            })
    return findings


# ── Aegis log reader ──────────────────────────────────────────────


def _aegis_log_path() -> Optional[Path]:
    """Path to Aegis's events.jsonl on the lab — env override for dev."""
    env = os.environ.get("AMOSKYS_AEGIS_LOG")
    if env and Path(env).exists():
        return Path(env)
    default = Path("/var/www/html/wp-content/uploads/amoskys-aegis/events.jsonl")
    return default if default.exists() else None


# ── MCP tools ─────────────────────────────────────────────────────


@mcp.tool()
def web_list_ast_scanners() -> dict:
    """List every AST scanner in Argos with its rule IDs and coverage.

    Returns one row per scanner: its ID, human description, number of
    rules it fires, and the CWE classes it maps to.
    """
    registry = _load_scanners()
    out = []
    for sid, klass in registry.items():
        inst = klass()
        out.append({
            "scanner_id":       sid,
            "description":      getattr(inst, "description", ""),
            "severity_default": getattr(inst, "severity_default", "medium"),
        })
    return {"scanners": out, "total": len(out)}


@mcp.tool()
def web_atlas_coverage() -> dict:
    """Return the WP Attack Atlas coverage breakdown.

    Honest count of how many of the 93 documented WP attack-surface
    entry points have WATCH (Aegis sensor) and PROBE (Argos scanner)
    coverage, per layer. This is the benchmark the engineering is
    being built against.
    """
    entries = _load_atlas_entries()
    total = len(entries)
    watched = sum(1 for e in entries if e["watch"] and e["watch"].upper() != "BLIND")
    probed = sum(1 for e in entries if e["probe"] and e["probe"].upper() != "BLIND")
    by_layer: Dict[int, Dict[str, int]] = {}
    for e in entries:
        bucket = by_layer.setdefault(e["layer"], {"total": 0, "watched": 0, "probed": 0})
        bucket["total"] += 1
        if e["watch"] and e["watch"].upper() != "BLIND":
            bucket["watched"] += 1
        if e["probe"] and e["probe"].upper() != "BLIND":
            bucket["probed"] += 1
    return {
        "total_entries":   total,
        "aegis_coverage":  {"count": watched, "pct": round(100 * watched / total, 1)},
        "argos_coverage":  {"count": probed, "pct": round(100 * probed / total, 1)},
        "by_layer":        by_layer,
    }


@mcp.tool()
def web_list_blind_spots(layer: Optional[int] = None, limit: int = 40) -> dict:
    """Return atlas entries that have no Aegis OR no Argos coverage.

    This is the live build list. Passing a layer number (0..10)
    restricts to one layer. `limit` caps the number of entries returned.
    """
    entries = _load_atlas_entries()
    blind = []
    for e in entries:
        if layer is not None and e["layer"] != layer:
            continue
        watch_blind = not e["watch"] or e["watch"].upper() == "BLIND"
        probe_blind = not e["probe"] or e["probe"].upper() == "BLIND"
        if watch_blind or probe_blind:
            e2 = dict(e)
            e2["watch_blind"] = watch_blind
            e2["probe_blind"] = probe_blind
            blind.append(e2)
    # Rank: entries blind on BOTH sides first, then argos-blind, then aegis-blind.
    blind.sort(key=lambda x: (not (x["watch_blind"] and x["probe_blind"]),
                              not x["probe_blind"],
                              x["layer"], x["seq"]))
    return {
        "blind_count": len(blind),
        "returned": min(len(blind), limit),
        "entries": blind[:limit],
    }


@mcp.tool()
def web_analyze_plugin(slug: str, version: Optional[str] = None,
                       scanners: Optional[List[str]] = None) -> dict:
    """Download a plugin from wp.org SVN at the given version and run AST scanners.

    Args:
        slug:     wp.org plugin slug (e.g., "contact-form-7")
        version:  exact version string, or None for the latest trunk
        scanners: list of scanner IDs to run, or None for all six

    Returns findings grouped by rule_id with counts and severity histogram.
    Downloads are cached under ~/.amoskys/wporg-corpus/ — repeated analyses
    of the same (slug, version) reuse the local copy.
    """
    from amoskys.agents.Web.argos.corpus import WPOrgCorpus

    corpus = WPOrgCorpus()
    try:
        plugin = corpus.fetch(slug, version)
    except Exception as e:  # noqa: BLE001
        return {
            "ok": False,
            "error": f"{type(e).__name__}: {e}",
            "slug": slug,
            "version": version,
        }
    findings = _run_scanners(plugin, scanners)

    # Aggregate
    by_rule: Dict[str, int] = {}
    by_severity: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        by_rule[f["rule_id"]] = by_rule.get(f["rule_id"], 0) + 1
        if f["severity"] in by_severity:
            by_severity[f["severity"]] += 1

    return {
        "ok": True,
        "slug":     plugin.slug,
        "version":  plugin.version,
        "scanners": list((scanners or list(_load_scanners().keys()))),
        "finding_count": len(findings),
        "by_severity":   by_severity,
        "by_rule":       dict(sorted(by_rule.items(), key=lambda kv: -kv[1])),
        "findings":      findings[:100],  # cap to keep response sane
    }


@mcp.tool()
def web_hunt_top_plugins(count: int = 10, scanners: Optional[List[str]] = None,
                         min_installs: int = 100000) -> dict:
    """Sweep the top-N wp.org plugins by install count with all AST scanners.

    Args:
        count: how many plugins to pull (max 50)
        scanners: scanner IDs to run, or None for all
        min_installs: minimum active-installs threshold for inclusion

    Returns a ranked list of plugins by critical-finding count and a
    summary histogram — the "who do we need to bounty-submit first" view.
    """
    from amoskys.agents.Web.argos.corpus import WPOrgCorpus

    count = max(1, min(50, count))
    corpus = WPOrgCorpus()
    try:
        top = corpus.top_plugins(count=count, min_installs=min_installs)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    results = []
    for slug in top:
        try:
            plugin = corpus.fetch(slug)
            findings = _run_scanners(plugin, scanners)
            by_sev: Dict[str, int] = {}
            for f in findings:
                by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
            results.append({
                "slug":          slug,
                "version":       plugin.version,
                "finding_count": len(findings),
                "critical":      by_sev.get("critical", 0),
                "high":          by_sev.get("high", 0),
                "medium":        by_sev.get("medium", 0),
                "low":           by_sev.get("low", 0),
            })
        except Exception as e:  # noqa: BLE001
            results.append({"slug": slug, "error": str(e)})

    results.sort(key=lambda r: -r.get("critical", 0))
    return {
        "ok":         True,
        "count":      len(results),
        "plugins":    results,
        "scanners":   list(scanners or list(_load_scanners().keys())),
        "timestamp":  time.time(),
    }


@mcp.tool()
def web_aegis_event_counts(hours: int = 1) -> dict:
    """Return Aegis event counts on the lab over the last N hours.

    Breaks down by event_type so you can see instantly what the
    defensive sensors are firing on right now. hours=1 by default;
    pass larger windows for daily/weekly patterns.
    """
    log_path = _aegis_log_path()
    if not log_path:
        return {"ok": False, "error": "Aegis log not found — set AMOSKYS_AEGIS_LOG"}

    cutoff_ns = int((time.time() - hours * 3600) * 1e9)
    counts: Dict[str, int] = {}
    total = 0
    try:
        with open(log_path, "r") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if (e.get("event_timestamp_ns") or 0) < cutoff_ns:
                    continue
                et = e.get("event_type", "unknown")
                counts[et] = counts.get(et, 0) + 1
                total += 1
    except OSError as oe:
        return {"ok": False, "error": str(oe)}

    return {
        "ok":     True,
        "hours":  hours,
        "total":  total,
        "counts": dict(sorted(counts.items(), key=lambda kv: -kv[1])),
    }


@mcp.tool()
def web_aegis_recent_critical(limit: int = 10) -> dict:
    """Return the most recent critical/high severity Aegis events.

    What the defensive stack JUST saw — filtered to the severities
    that actually matter. Each event comes with event_type, request
    IP + URI, and the attributes dict.
    """
    log_path = _aegis_log_path()
    if not log_path:
        return {"ok": False, "error": "Aegis log not found — set AMOSKYS_AEGIS_LOG"}

    limit = max(1, min(50, limit))
    # Read tail-ish without loading the whole file: seek to last 1 MB.
    events: List[Dict[str, Any]] = []
    try:
        with open(log_path, "r") as f:
            f.seek(0, os.SEEK_END)
            end = f.tell()
            f.seek(max(0, end - 1024 * 1024), os.SEEK_SET)
            # Drop the first (possibly partial) line.
            f.readline()
            for line in f:
                if not line.strip():
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if e.get("severity") in ("critical", "high"):
                    events.append({
                        "ts_ns":      e.get("event_timestamp_ns"),
                        "event_type": e.get("event_type"),
                        "severity":   e.get("severity"),
                        "ip":         e.get("request", {}).get("ip"),
                        "uri":        (e.get("request", {}).get("uri") or "")[:120],
                        "attributes": e.get("attributes"),
                    })
    except OSError as oe:
        return {"ok": False, "error": str(oe)}

    # Latest first, capped at limit.
    events = list(reversed(events))[:limit]
    return {"ok": True, "returned": len(events), "events": events}
