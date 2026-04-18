"""WPScan tool driver.

WPScan is the WordPress-specific scanner. Docs: https://github.com/wpscanteam/wpscan

This v0 scaffold lays down the subprocess plumbing but the JSON output
parsing is intentionally narrow — we pull only the fields we need and
ignore the very chatty info-level output.

v1 will:
  - Support both --enumerate u (users) and vp (vulnerable plugins)
  - Rotate API tokens for the WPVulnDB enrichment
  - Respect scope.max_rps via --throttle
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, TYPE_CHECKING

from amoskys.agents.Web.argos.tools.base import Tool, ToolResult

if TYPE_CHECKING:
    from amoskys.agents.Web.argos.engine import Scope


class WPScanTool(Tool):
    """Run WPScan for WordPress fingerprinting + vulnerable plugin detection."""

    required_binary = "wpscan"

    def __init__(
        self,
        enumerate: str = "vp,vt,u",  # vulnerable plugins, vulnerable themes, users
        api_token: str | None = None,
    ) -> None:
        self.enumerate = enumerate
        self.api_token = api_token
        self.name = "wpscan"
        self.tool_class = "fingerprint"
        self.probe_class = "wpscan.plugins"

    def run(self, target: str, scope: "Scope") -> ToolResult:
        started = int(time.time() * 1e9)

        if not self.available():
            return ToolResult.failed(
                self.name,
                target,
                "wpscan binary not found. Install: gem install wpscan",
            )

        # Persist output to disk so findings survive timeouts.
        out_dir = Path(tempfile.gettempdir()) / "argos-wpscan"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"wpscan-{uuid.uuid4().hex[:10]}.json"
        stderr_path = out_dir / f"wpscan-{uuid.uuid4().hex[:10]}.stderr"

        url = f"https://{target}" if not target.startswith("http") else target
        cmd: List[str] = [
            "wpscan",
            "--url", url,
            "--format", "json",
            "--output", str(out_path),
            "--enumerate", self.enumerate,
            "--random-user-agent",
            "--throttle", str(max(200, int(1000 / max(scope.max_rps, 1)))),  # ms between requests
            "--no-banner",
            "--disable-tls-checks",  # for lab targets, real targets enable
        ]
        if self.api_token:
            cmd.extend(["--api-token", self.api_token])

        errors: List[str] = []
        exit_code = -1
        try:
            with open(stderr_path, "wb") as stderr_fh:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=stderr_fh,
                )
                try:
                    exit_code = proc.wait(timeout=min(scope.max_duration_s, 1800))
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    try:
                        proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                    errors.append(
                        f"wpscan timed out after {scope.max_duration_s}s — "
                        f"attempting to parse partial {out_path}"
                    )
        except Exception as e:  # noqa: BLE001
            errors.append(f"{type(e).__name__}: {e}")

        # Parse whatever landed on disk.
        findings: List[Dict[str, Any]] = []
        stdout_bytes = 0
        if out_path.exists():
            try:
                content = out_path.read_text()
                stdout_bytes = len(content.encode())
                findings = self._parse_json(content, target)
            except Exception as e:  # noqa: BLE001
                errors.append(f"failed to parse {out_path}: {type(e).__name__}: {e}")

        stderr_bytes = 0
        if stderr_path.exists():
            try:
                stderr_bytes = os.path.getsize(stderr_path)
                if stderr_bytes > 0:
                    tail = stderr_path.read_bytes()[-500:].decode("utf-8", errors="replace")
                    errors.append(f"stderr (tail): {tail}")
            except Exception:  # noqa: BLE001
                pass

        completed = int(time.time() * 1e9)
        return ToolResult(
            tool=self.name,
            command=cmd,
            target=target,
            exit_code=exit_code,
            started_at_ns=started,
            completed_at_ns=completed,
            stdout_bytes=stdout_bytes,
            stderr_bytes=stderr_bytes,
            findings=findings,
            raw_output_path=str(out_path),
            errors=errors,
        )

    @staticmethod
    def _parse_json(stdout: str, target: str = "") -> List[Dict[str, Any]]:
        """Parse WPScan's JSON output into our finding schema.

        WPScan emits one giant JSON object. We extract findings from:
          - version.vulnerabilities — core CVEs
          - plugins.*.vulnerabilities — plugin CVEs
          - themes.*.vulnerabilities — theme CVEs
          - users — user enumeration (info-severity finding each)
          - interesting_findings — misconfigs, exposures, debug info
          - config_backups — exposed config files (critical)
          - db_exports — exposed DB dumps (critical)
          - medias — uploaded media enumeration

        Defensive against WPScan returning null for fields when detection
        fails: we never call .get() on a value that might be None.
        """
        findings: List[Dict[str, Any]] = []
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return findings

        def _safe_get(obj, key, default):
            """Treat None the same as missing key."""
            if not isinstance(obj, dict):
                return default
            val = obj.get(key)
            return default if val is None else val

        # Core WP vulnerabilities (version may be null if undetected)
        version_obj = _safe_get(data, "version", {})
        for v in _safe_get(version_obj, "vulnerabilities", []) or []:
            findings.append(_wp_vuln_to_finding(v, "wordpress-core", target or "core"))

        # Plugin vulnerabilities
        plugins = _safe_get(data, "plugins", {})
        if isinstance(plugins, dict):
            for slug, plugin in plugins.items():
                plugin = plugin or {}
                for v in _safe_get(plugin, "vulnerabilities", []) or []:
                    findings.append(
                        _wp_vuln_to_finding(v, f"plugin:{slug}", _safe_get(plugin, "version", {}))
                    )

        # Theme vulnerabilities
        themes = _safe_get(data, "themes", {})
        if isinstance(themes, dict):
            for slug, theme in themes.items():
                theme = theme or {}
                for v in _safe_get(theme, "vulnerabilities", []) or []:
                    findings.append(
                        _wp_vuln_to_finding(v, f"theme:{slug}", _safe_get(theme, "version", {}))
                    )

        # User enumeration
        users = _safe_get(data, "users", {})
        if isinstance(users, dict):
            for username in users.keys():
                findings.append(
                    {
                        "template_id": "wpscan.user-enum",
                        "title": f"User enumerable: {username}",
                        "description": "WordPress user account discoverable via wp-login or REST.",
                        "severity": "info",
                        "references": [],
                        "evidence": {"username": username},
                    }
                )

        # interesting_findings — misconfigs, debug leaks, xmlrpc, readme, etc.
        interesting = _safe_get(data, "interesting_findings", []) or []
        if isinstance(interesting, list):
            for f in interesting:
                if not isinstance(f, dict):
                    continue
                findings.append(_interesting_to_finding(f))

        # Config backups exposed (critical)
        config_backups = _safe_get(data, "config_backups", {})
        if isinstance(config_backups, dict):
            for url, info in config_backups.items():
                findings.append(
                    {
                        "template_id": "wpscan.config_backup_exposed",
                        "title": "Exposed config backup file",
                        "description": f"A config backup file is publicly accessible: {url}",
                        "severity": "critical",
                        "references": [],
                        "evidence": {"url": url, "details": info},
                    }
                )

        # DB exports exposed
        db_exports = _safe_get(data, "db_exports", {})
        if isinstance(db_exports, dict):
            for url, info in db_exports.items():
                findings.append(
                    {
                        "template_id": "wpscan.db_export_exposed",
                        "title": "Exposed database export",
                        "description": f"A database export is publicly accessible: {url}",
                        "severity": "critical",
                        "references": [],
                        "evidence": {"url": url, "details": info},
                    }
                )

        return findings


# Map common interesting_finding types → severity
_INTERESTING_SEVERITY = {
    "xmlrpc": "low",
    "readme": "info",
    "debug_log": "high",
    "full_path_disclosure": "medium",
    "backup_file": "high",
    "upload_directory_listing": "medium",
    "wp_config_backup": "critical",
    "headers": "info",
    "registration": "low",
    "multisite": "info",
    "robots_txt": "info",
    "emergency_pwd_reset_script": "critical",
}


def _interesting_to_finding(f: Dict[str, Any]) -> Dict[str, Any]:
    """Map a WPScan interesting_finding entry to our finding schema."""
    kind = f.get("type", "unknown")
    severity = _INTERESTING_SEVERITY.get(kind, "info")
    title = f.get("to_s") or f"WPScan finding: {kind}"
    url = f.get("url", "")
    confidence = f.get("confidence", 0)

    entries = f.get("interesting_entries") or []
    if not isinstance(entries, list):
        entries = []

    return {
        "template_id": f"wpscan.interesting.{kind}",
        "title": title[:120],
        "description": title,
        "severity": severity,
        "cvss": None,
        "references": [],
        "evidence": {
            "url": url,
            "kind": kind,
            "confidence": confidence,
            "found_by": f.get("found_by"),
            "interesting_entries": entries,
        },
    }


def _wp_vuln_to_finding(v: Dict[str, Any], component: str, target: Any) -> Dict[str, Any]:
    cve_list = v.get("references", {}).get("cve") or []
    url_refs = v.get("references", {}).get("url") or []
    refs = [f"CVE-{c}" for c in cve_list] + list(url_refs)
    cvss = None
    cvss_obj = v.get("cvss") or {}
    if isinstance(cvss_obj, dict):
        cvss = cvss_obj.get("score") or cvss_obj.get("base_score")

    severity = "high"  # WPScan vulns without CVSS are conservatively high
    if cvss is not None:
        if cvss >= 9:
            severity = "critical"
        elif cvss >= 7:
            severity = "high"
        elif cvss >= 4:
            severity = "medium"
        else:
            severity = "low"

    return {
        "template_id": f"wpscan.{component}",
        "title": v.get("title", "(unnamed WP vulnerability)"),
        "description": f"{component} — installed: {target}",
        "severity": severity,
        "cvss": cvss,
        "references": refs,
        "evidence": {"component": component, "installed_version": target},
    }
