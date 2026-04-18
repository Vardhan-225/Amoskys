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
import shutil
import subprocess
import time
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

        url = f"https://{target}" if not target.startswith("http") else target
        cmd: List[str] = [
            "wpscan",
            "--url", url,
            "--format", "json",
            "--enumerate", self.enumerate,
            "--random-user-agent",
            "--throttle", str(max(200, int(1000 / max(scope.max_rps, 1)))),  # ms between requests
            "--no-banner",
            "--disable-tls-checks",  # for lab targets, real targets enable
        ]
        if self.api_token:
            cmd.extend(["--api-token", self.api_token])

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=min(scope.max_duration_s, 1800),
                check=False,
            )
            findings = self._parse_json(proc.stdout)
            completed = int(time.time() * 1e9)

            return ToolResult(
                tool=self.name,
                command=cmd,
                target=target,
                exit_code=proc.returncode,
                started_at_ns=started,
                completed_at_ns=completed,
                stdout_bytes=len(proc.stdout.encode()),
                stderr_bytes=len(proc.stderr.encode()),
                findings=findings,
                errors=[proc.stderr] if proc.stderr else [],
            )
        except subprocess.TimeoutExpired:
            return ToolResult.failed(
                self.name, target, f"wpscan timed out after {scope.max_duration_s}s"
            )
        except Exception as e:  # noqa: BLE001
            return ToolResult.failed(self.name, target, f"{type(e).__name__}: {e}")

    @staticmethod
    def _parse_json(stdout: str) -> List[Dict[str, Any]]:
        """Parse WPScan's JSON output into our finding schema.

        WPScan emits one giant JSON object. We pull findings from:
          - plugins (per plugin: vulnerabilities[])
          - themes  (per theme: vulnerabilities[])
          - users   (user enumeration as findings of severity=info)
          - wordpress: vulnerabilities[] (core vulns)
        """
        findings: List[Dict[str, Any]] = []
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return findings

        # Core WP vulnerabilities
        for v in data.get("version", {}).get("vulnerabilities", []) or []:
            findings.append(_wp_vuln_to_finding(v, "wordpress-core", target="core"))

        # Plugin vulnerabilities
        for slug, plugin in (data.get("plugins") or {}).items():
            for v in plugin.get("vulnerabilities", []) or []:
                findings.append(_wp_vuln_to_finding(v, f"plugin:{slug}", plugin.get("version")))

        # Theme vulnerabilities
        for slug, theme in (data.get("themes") or {}).items():
            for v in theme.get("vulnerabilities", []) or []:
                findings.append(_wp_vuln_to_finding(v, f"theme:{slug}", theme.get("version")))

        # User enumeration (information disclosure, severity info)
        for username, _user in (data.get("users") or {}).items():
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
        return findings


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
