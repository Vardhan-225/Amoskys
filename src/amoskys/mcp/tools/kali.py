"""Kali-native offensive toolset wrappers over MCP.

Exposes the Kali-distributed red-team tools (wpscan, sqlmap, nikto,
ffuf, amass, httpx, nmap) as MCP tools so a Claude Code session
running against an amoskys-mcp server ON KALI can drive real pentest
tooling end-to-end.

ROE discipline
──────────────
Every tool in this module is STAGE 2: consented engagements only.
Each function enforces one of:

  (a) consent_verified=True parameter (the caller attests to having a
      signed consent token for the target)
  (b) target matches `AMOSKYS_CONSENT_DOMAIN` env var (local lab
      shortcut for dev/test)

Without either, the tool refuses to fire and returns a clear error.
This is the CFAA line — everything wpscan / sqlmap / nikto does
produces traffic that clearly crosses authorization boundaries, so
consent is non-optional.

Output shape
────────────
Every tool returns a structured dict:
  { ok, tool, target, duration_s, exit_code, stdout_excerpt,
    findings: [ {rule_id, severity, title, evidence} ] }
stdout is truncated so MCP responses stay compact; the full log is
written to a file under `~/amoskys/hunt-logs/` for forensic review.

Stealth
───────
These tools ARE loud by design — they signal attack to any defender.
That's the point for a Stage-2 consented engagement. But we do
honor a few rate controls:
  - wpscan throttle 2 s between requests
  - sqlmap delay 1 s, concurrent threads cap
  - ffuf rate-limit 10 req/s default
The caller can override via env or tool kwargs.

Hunt logging
────────────
Every invocation appends a structured line to
`~/amoskys/hunt-logs/journal.jsonl` so the HUNT_JOURNAL.md doc can
replay what we ran against whom, when, and what we learned.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..server import mcp


_HUNT_LOG_DIR = Path(os.environ.get("AMOSKYS_HUNT_LOG_DIR",
                                     str(Path.home() / "amoskys" / "hunt-logs")))
_HUNT_JOURNAL = _HUNT_LOG_DIR / "journal.jsonl"


def _hunt_log(entry: Dict[str, Any]) -> None:
    """Append one line to the hunt journal. Never raises."""
    try:
        _HUNT_LOG_DIR.mkdir(parents=True, exist_ok=True)
        with open(_HUNT_JOURNAL, "a") as fh:
            fh.write(json.dumps({"ts": time.time(), **entry}) + "\n")
    except Exception:
        pass


def _consent_ok(target: str, consent_verified: bool) -> Optional[str]:
    """Return None if OK to proceed; error string if not."""
    if consent_verified:
        return None
    # Allow the local consent-domain shortcut.
    consent_domain = os.environ.get("AMOSKYS_CONSENT_DOMAIN", "").lower()
    if consent_domain:
        parsed = urllib.parse.urlparse(target)
        host = (parsed.hostname or target).lower()
        if host == consent_domain or host.endswith("." + consent_domain):
            return None
    return (
        "consent not verified — pass consent_verified=True (with a "
        "signed engagement letter on file) OR set "
        "AMOSKYS_CONSENT_DOMAIN=<target-domain> for a local-lab run"
    )


def _run(cmd: List[str], timeout: int = 900) -> Dict[str, Any]:
    """Run a shell command, capture stdout+stderr, record timing."""
    if not shutil.which(cmd[0]):
        return {
            "ok": False,
            "error": f"tool not installed: {cmd[0]}",
            "cmd": cmd,
        }
    t0 = time.time()
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        return {
            "ok":         r.returncode == 0,
            "exit_code":  r.returncode,
            "stdout":     r.stdout,
            "stderr":     r.stderr,
            "duration_s": round(time.time() - t0, 2),
            "cmd":        cmd,
        }
    except subprocess.TimeoutExpired as e:
        return {
            "ok":         False,
            "error":      f"timeout after {timeout}s",
            "stdout":     (e.stdout or b"").decode(errors="replace"),
            "stderr":     (e.stderr or b"").decode(errors="replace"),
            "duration_s": round(time.time() - t0, 2),
            "cmd":        cmd,
        }


def _persist_full_log(tool: str, target: str, raw: Dict[str, Any]) -> str:
    """Write full tool output to a forensic log file; return its path."""
    try:
        _HUNT_LOG_DIR.mkdir(parents=True, exist_ok=True)
        safe_target = re.sub(r"[^a-zA-Z0-9._-]", "_", target)[:60]
        path = _HUNT_LOG_DIR / f"{int(time.time())}_{tool}_{safe_target}.log"
        with open(path, "w") as fh:
            fh.write(f"# {tool} against {target}\n# cmd: {raw.get('cmd')}\n")
            fh.write(f"# exit_code: {raw.get('exit_code')}\n")
            fh.write(f"# duration_s: {raw.get('duration_s')}\n\n")
            fh.write("--- STDOUT ---\n")
            fh.write(raw.get("stdout", ""))
            fh.write("\n--- STDERR ---\n")
            fh.write(raw.get("stderr", ""))
        return str(path)
    except Exception as e:  # noqa: BLE001
        return f"log-write-failed: {e}"


def _stdout_excerpt(raw: Dict[str, Any], max_chars: int = 4000) -> str:
    out = raw.get("stdout", "") or ""
    if len(out) <= max_chars:
        return out
    head, tail = out[: max_chars // 2], out[-max_chars // 2:]
    return head + f"\n... [TRUNCATED {len(out) - max_chars} chars] ...\n" + tail


# ── WPScan ─────────────────────────────────────────────────────────


@mcp.tool()
def kali_wpscan(target_url: str,
                consent_verified: bool = False,
                detection_mode: str = "mixed",
                enumerate_plugins: bool = True,
                enumerate_users: bool = False,
                api_token: Optional[str] = None) -> dict:
    """Run wpscan against a WordPress target.

    REQUIRES CONSENT. wpscan sends wordpress-attack-shaped HTTP to the
    target; any WAF will flag it. Do not use without a signed engagement.

    Args:
        target_url:          Full https://domain URL of the WP site.
        consent_verified:    Must be True, OR the target must match
                             AMOSKYS_CONSENT_DOMAIN env var.
        detection_mode:      "mixed" (default), "passive", "aggressive".
        enumerate_plugins:   Enumerate installed plugins + versions.
        enumerate_users:     Enumerate admin usernames (author-id probe).
        api_token:           WPScan API token for CVE enrichment
                             (set WPSCAN_API_TOKEN env var alternatively).

    Returns structured findings including plugin versions + matched CVEs.
    """
    err = _consent_ok(target_url, consent_verified)
    if err:
        return {"ok": False, "error": err, "tool": "wpscan"}

    cmd = [
        "wpscan", "--url", target_url,
        "--detection-mode", detection_mode,
        "--format", "json",
        "--no-banner",
        "--throttle", "2000",  # ms between requests
        "--random-user-agent",
    ]
    enum_bits = []
    if enumerate_plugins:
        enum_bits.append("p")
    if enumerate_users:
        enum_bits.append("u")
    if enum_bits:
        cmd += ["-e", ",".join(enum_bits)]
    token = api_token or os.environ.get("WPSCAN_API_TOKEN")
    if token:
        cmd += ["--api-token", token]

    raw = _run(cmd, timeout=1800)
    log_path = _persist_full_log("wpscan", target_url, raw)

    findings: List[Dict[str, Any]] = []
    plugin_count = 0
    vuln_count = 0
    try:
        if raw.get("stdout"):
            data = json.loads(raw["stdout"])
            # Core version vulnerabilities.
            core = data.get("version") or {}
            core_vulns = core.get("vulnerabilities") or []
            vuln_count += len(core_vulns)
            for v in core_vulns:
                findings.append({
                    "rule_id":  "wpscan.core_vuln",
                    "severity": "high",
                    "title":    v.get("title") or "Core vulnerability",
                    "evidence": {
                        "cve_ids":  v.get("references", {}).get("cve", []),
                        "fixed_in": v.get("fixed_in"),
                    },
                })
            # Plugin enumeration + per-plugin vulns.
            plugins = data.get("plugins") or {}
            plugin_count = len(plugins)
            for slug, info in plugins.items():
                vulns = info.get("vulnerabilities") or []
                vuln_count += len(vulns)
                for v in vulns:
                    findings.append({
                        "rule_id":  "wpscan.plugin_vuln",
                        "severity": _sev_from_cvss(v),
                        "title":    f"{slug}: {v.get('title')}",
                        "evidence": {
                            "slug":     slug,
                            "version":  (info.get("version") or {}).get("number"),
                            "cve_ids":  v.get("references", {}).get("cve", []),
                            "fixed_in": v.get("fixed_in"),
                        },
                    })
            # Theme vulns.
            themes = data.get("main_theme") or {}
            if themes:
                for v in themes.get("vulnerabilities") or []:
                    vuln_count += 1
                    findings.append({
                        "rule_id":  "wpscan.theme_vuln",
                        "severity": _sev_from_cvss(v),
                        "title":    f"theme: {v.get('title')}",
                        "evidence": {"fixed_in": v.get("fixed_in")},
                    })
    except json.JSONDecodeError:
        # wpscan may have emitted partial JSON on timeout; still log.
        findings.append({
            "rule_id":  "wpscan.parse_error",
            "severity": "info",
            "title":    "wpscan output was not valid JSON",
            "evidence": {"head": (raw.get("stdout", "") or "")[:400]},
        })

    summary = {
        "ok":              raw.get("ok", False),
        "tool":            "wpscan",
        "target":          target_url,
        "duration_s":      raw.get("duration_s"),
        "exit_code":       raw.get("exit_code"),
        "plugin_count":    plugin_count,
        "vuln_count":      vuln_count,
        "finding_count":   len(findings),
        "findings":        findings[:50],
        "stdout_excerpt":  _stdout_excerpt(raw),
        "full_log_path":   log_path,
    }
    _hunt_log({"tool": "wpscan", "target": target_url,
               "findings": len(findings), "vulns": vuln_count,
               "plugins": plugin_count, "log": log_path})
    return summary


def _sev_from_cvss(v: dict) -> str:
    """Best-effort severity from a wpscan vuln dict."""
    score = v.get("cvss", {}).get("score") if isinstance(v.get("cvss"), dict) else None
    if isinstance(score, (int, float)):
        if score >= 9.0: return "critical"
        if score >= 7.0: return "high"
        if score >= 4.0: return "medium"
        return "low"
    return "medium"


# ── sqlmap ─────────────────────────────────────────────────────────


@mcp.tool()
def kali_sqlmap(target_url: str,
                consent_verified: bool = False,
                risk: int = 1,
                level: int = 1,
                cookie: Optional[str] = None,
                extra_args: Optional[List[str]] = None) -> dict:
    """Run sqlmap against a WordPress target URL.

    REQUIRES CONSENT. sqlmap is LOUD — it sends hundreds of payload
    variants to one or more injection points. Use only with a signed
    engagement letter.

    Args:
        target_url:       URL with the suspected injection point, e.g.
                          https://site.com/product?id=1
        consent_verified: Must be True (or target matches consent domain).
        risk:             1 (safe) → 3 (aggressive — includes UPDATE etc.)
        level:            1 (default) → 5 (most payloads).
        cookie:           Session cookie string if auth'd scan.
        extra_args:       Additional sqlmap args, e.g. ["--dbs"].
    """
    err = _consent_ok(target_url, consent_verified)
    if err:
        return {"ok": False, "error": err, "tool": "sqlmap"}

    cmd = [
        "sqlmap",
        "-u", target_url,
        "--batch",           # non-interactive
        "--delay", "1",      # 1s between requests
        f"--risk={risk}",
        f"--level={level}",
        "--random-agent",
    ]
    if cookie:
        cmd += ["--cookie", cookie]
    if extra_args:
        cmd += list(extra_args)

    raw = _run(cmd, timeout=1200)
    log_path = _persist_full_log("sqlmap", target_url, raw)
    out = raw.get("stdout", "") or ""

    findings: List[Dict[str, Any]] = []
    # sqlmap success indicators: injection-point + payload discovery.
    if "is vulnerable" in out or "sqlmap identified" in out:
        findings.append({
            "rule_id":  "sqlmap.injection_confirmed",
            "severity": "critical",
            "title":    "SQL injection confirmed by sqlmap",
            "evidence": {"snippet": out[out.find("is vulnerable"):][:500]},
        })
    # Extract DBMS fingerprint if present.
    m = re.search(r"back-end DBMS(?: is)?:\s+([^\n]+)", out)
    if m:
        findings.append({
            "rule_id":  "sqlmap.dbms_fingerprint",
            "severity": "info",
            "title":    f"DBMS identified: {m.group(1).strip()}",
            "evidence": {"dbms": m.group(1).strip()},
        })

    summary = {
        "ok":             raw.get("ok", False),
        "tool":           "sqlmap",
        "target":         target_url,
        "duration_s":     raw.get("duration_s"),
        "exit_code":      raw.get("exit_code"),
        "finding_count":  len(findings),
        "findings":       findings,
        "stdout_excerpt": _stdout_excerpt(raw),
        "full_log_path":  log_path,
    }
    _hunt_log({"tool": "sqlmap", "target": target_url,
               "findings": len(findings), "log": log_path})
    return summary


# ── nikto ──────────────────────────────────────────────────────────


@mcp.tool()
def kali_nikto(target_url: str,
               consent_verified: bool = False,
               tuning: str = "b") -> dict:
    """Run nikto web server vulnerability scan.

    REQUIRES CONSENT.

    Args:
        target_url:       Full URL.
        consent_verified: See module docstring.
        tuning:           Nikto tuning string. Default "b" = "Software
                          Identification" only (light). "123467" is
                          a common focused set. "x" = reverse (all
                          categories minus specified).
    """
    err = _consent_ok(target_url, consent_verified)
    if err:
        return {"ok": False, "error": err, "tool": "nikto"}

    cmd = [
        "nikto", "-h", target_url,
        "-Tuning", tuning,
        "-Format", "txt",
        "-nointeractive",
    ]
    raw = _run(cmd, timeout=900)
    log_path = _persist_full_log("nikto", target_url, raw)
    out = raw.get("stdout", "") or ""

    findings: List[Dict[str, Any]] = []
    # Nikto lines starting with "+ " are findings.
    for line in out.splitlines():
        if line.startswith("+ ") and any(
            tag in line for tag in ("OSVDB", "CVE-", "may allow", "vulnerable",
                                    "Uncommon header", "cookie", "X-XSS-Protection",
                                    "outdated")
        ):
            sev = "low"
            if "CVE-" in line or "vulnerable" in line.lower():
                sev = "medium"
            if "allow remote" in line.lower() or "rce" in line.lower():
                sev = "high"
            findings.append({
                "rule_id":  "nikto.finding",
                "severity": sev,
                "title":    line[2:].strip()[:200],
                "evidence": {"line": line},
            })

    summary = {
        "ok":             raw.get("ok", False),
        "tool":           "nikto",
        "target":         target_url,
        "duration_s":     raw.get("duration_s"),
        "finding_count":  len(findings),
        "findings":       findings[:40],
        "stdout_excerpt": _stdout_excerpt(raw),
        "full_log_path":  log_path,
    }
    _hunt_log({"tool": "nikto", "target": target_url,
               "findings": len(findings), "log": log_path})
    return summary


# ── ffuf ───────────────────────────────────────────────────────────


@mcp.tool()
def kali_ffuf(target_url: str,
              wordlist: str = "/usr/share/wordlists/dirb/common.txt",
              consent_verified: bool = False,
              rate_limit_rps: int = 10,
              status_filter: str = "200,204,301,302,307,401,403") -> dict:
    """Fuzz for hidden paths/files with ffuf.

    REQUIRES CONSENT (or AMOSKYS_CONSENT_DOMAIN).

    Args:
        target_url:      URL containing `FUZZ` keyword, e.g.
                         https://site.com/FUZZ
        wordlist:        Absolute path to a wordlist file on the Kali
                         box (dirb's common.txt is a sensible default).
        rate_limit_rps:  Requests per second. Keep modest (<=10) to
                         avoid tripping every WAF in existence.
    """
    err = _consent_ok(target_url, consent_verified)
    if err:
        return {"ok": False, "error": err, "tool": "ffuf"}
    if "FUZZ" not in target_url:
        return {"ok": False, "error": "target_url must contain FUZZ keyword"}
    if not Path(wordlist).exists():
        return {"ok": False, "error": f"wordlist not found: {wordlist}"}

    cmd = [
        "ffuf",
        "-u", target_url,
        "-w", wordlist,
        "-mc", status_filter,
        "-rate", str(rate_limit_rps),
        "-t", "10",           # threads
        "-o", "/dev/stdout",
        "-of", "json",
        "-s",                 # silent mode — json only
    ]
    raw = _run(cmd, timeout=1200)
    log_path = _persist_full_log("ffuf", target_url, raw)
    out = raw.get("stdout", "") or ""

    findings: List[Dict[str, Any]] = []
    try:
        data = json.loads(out)
        for r in data.get("results", []):
            findings.append({
                "rule_id":  "ffuf.discovered_path",
                "severity": "info" if r.get("status") in (301, 302, 403) else "low",
                "title":    f"Discovered: {r.get('url')}",
                "evidence": {
                    "status":      r.get("status"),
                    "length":      r.get("length"),
                    "words":       r.get("words"),
                    "redirectlocation": r.get("redirectlocation"),
                },
            })
    except json.JSONDecodeError:
        pass

    summary = {
        "ok":            raw.get("ok", False),
        "tool":          "ffuf",
        "target":        target_url,
        "duration_s":    raw.get("duration_s"),
        "finding_count": len(findings),
        "findings":      findings[:100],
        "full_log_path": log_path,
    }
    _hunt_log({"tool": "ffuf", "target": target_url,
               "findings": len(findings), "log": log_path})
    return summary


# ── nuclei (CVE template scanner) ─────────────────────────────────


@mcp.tool()
def kali_nuclei(target_url: str,
                consent_verified: bool = False,
                tags: Optional[List[str]] = None,
                severity: str = "medium,high,critical",
                rate_limit_rps: int = 20,
                timeout_s: int = 900) -> dict:
    """Run nuclei community templates against a target.

    REQUIRES CONSENT. Nuclei is a template-driven CVE / misconfig
    scanner — thousands of templates, many of them send attack-shaped
    payloads (SQLi probes, XSS probes, default-creds checks).

    Args:
        target_url:       Full URL of target.
        consent_verified: Must be True (or target matches AMOSKYS_CONSENT_DOMAIN).
        tags:             Template-tag filter. For WordPress pentests
                          a good default is ["wordpress", "wp-plugin",
                          "wp-theme", "cve"]. If None, runs "wordpress".
        severity:         Comma-separated severity filter.
        rate_limit_rps:   Global rate limit. Default 20 is quick but
                          polite; for sensitive targets drop to 5.
    """
    err = _consent_ok(target_url, consent_verified)
    if err:
        return {"ok": False, "error": err, "tool": "nuclei"}

    use_tags = tags or ["wordpress"]
    cmd = [
        "nuclei",
        "-target", target_url,
        "-tags", ",".join(use_tags),
        "-severity", severity,
        "-rate-limit", str(rate_limit_rps),
        "-jsonl",                 # machine-parseable output
        "-silent",
        "-disable-update-check",
        "-duc",
    ]
    raw = _run(cmd, timeout=timeout_s)
    log_path = _persist_full_log("nuclei", target_url, raw)
    out = raw.get("stdout", "") or ""

    findings: List[Dict[str, Any]] = []
    for line in out.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info", {}) or {}
        findings.append({
            "rule_id":  f"nuclei.{obj.get('template-id') or obj.get('templateID') or 'unknown'}",
            "severity": info.get("severity", "info"),
            "title":    info.get("name") or obj.get("template-id"),
            "evidence": {
                "matched_at": obj.get("matched-at"),
                "tags":       info.get("tags"),
                "reference":  info.get("reference", []),
                "cve":        info.get("classification", {}).get("cve-id") if isinstance(info.get("classification"), dict) else None,
            },
        })

    summary = {
        "ok":             raw.get("ok", False),
        "tool":           "nuclei",
        "target":         target_url,
        "duration_s":     raw.get("duration_s"),
        "exit_code":      raw.get("exit_code"),
        "finding_count":  len(findings),
        "findings":       findings[:50],
        "stdout_excerpt": _stdout_excerpt(raw),
        "full_log_path":  log_path,
    }
    _hunt_log({"tool": "nuclei", "target": target_url,
               "findings": len(findings), "log": log_path})
    return summary


# ── amass (passive subdomain enumeration — no consent needed) ─────


@mcp.tool()
def kali_amass_enum(domain: str, passive: bool = True,
                    timeout_min: int = 5) -> dict:
    """Amass subdomain enumeration. Passive mode by default (OSINT only).

    Passive enumeration uses public data sources (CT logs, DNS
    aggregators, search engines) — NO CONSENT REQUIRED because no
    packets are sent to the target. Same legal basis as our Stage-1
    stealth recon: public-data access per hiQ v. LinkedIn.

    Args:
        domain:      e.g. "example.com"
        passive:     True (recommended) = OSINT only. False = active
                     DNS brute-force (consent required).
        timeout_min: Amass total runtime cap in minutes.
    """
    if not passive:
        return {
            "ok": False,
            "error": "active amass requires consent; set passive=True or "
                     "use a consent_verified-gated tool instead",
        }
    cmd = [
        "amass", "enum",
        "-passive",
        "-d", domain,
        "-timeout", str(timeout_min),
    ]
    raw = _run(cmd, timeout=timeout_min * 60 + 60)
    log_path = _persist_full_log("amass", domain, raw)
    out = raw.get("stdout", "") or ""
    subdomains = sorted({
        line.strip() for line in out.splitlines()
        if line.strip() and not line.startswith("#") and "." in line
    })
    summary = {
        "ok":             raw.get("ok", False),
        "tool":           "amass",
        "mode":           "passive",
        "target":         domain,
        "duration_s":     raw.get("duration_s"),
        "subdomains":     subdomains[:200],
        "total":          len(subdomains),
        "full_log_path":  log_path,
    }
    _hunt_log({"tool": "amass", "target": domain,
               "subdomain_count": len(subdomains), "log": log_path})
    return summary


# ── Hunt journal introspection ────────────────────────────────────


@mcp.tool()
def kali_hunt_journal(limit: int = 30) -> dict:
    """Tail the hunt journal — what have we run, against whom, what did we find.

    Useful for agents: "what did we already test against target X?"
    before firing another run.
    """
    if not _HUNT_JOURNAL.exists():
        return {"ok": True, "entries": [], "total": 0}
    entries: List[Dict[str, Any]] = []
    try:
        with open(_HUNT_JOURNAL) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError as e:
        return {"ok": False, "error": str(e)}
    return {
        "ok":       True,
        "total":    len(entries),
        "entries":  entries[-limit:],
    }
