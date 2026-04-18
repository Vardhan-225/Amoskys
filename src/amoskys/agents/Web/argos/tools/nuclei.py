"""Nuclei tool driver.

Nuclei is ProjectDiscovery's template-driven vulnerability scanner.
Docs: https://github.com/projectdiscovery/nuclei

This v0 scaffold:
  - Does NOT actually invoke nuclei yet (subprocess in v1)
  - Demonstrates the driver shape + output parsing contract
  - Ships a stub result so the engagement engine can be exercised
    end-to-end without nuclei installed

v1 will:
  - Shell out to `nuclei -json-export` with rate caps
  - Parse JSON output line-by-line (nuclei emits JSONL)
  - Respect scope.max_rps via -rl
  - Respect scope.max_duration_s via -timeout
  - Audit the exact command in ToolResult.command
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, TYPE_CHECKING

from amoskys.agents.Web.argos.tools.base import Tool, ToolResult

if TYPE_CHECKING:
    from amoskys.agents.Web.argos.engine import Scope


class NucleiTool(Tool):
    """Run nuclei against a target with a given template category."""

    required_binary = "nuclei"

    def __init__(
        self,
        category: str = "cves",  # cves | misconfiguration | exposures | vulnerabilities
        template_tags: List[str] | None = None,
    ) -> None:
        self.category = category
        self.template_tags = template_tags or []
        self.name = f"nuclei-{category}"
        self.tool_class = "probe"
        self.probe_class = f"nuclei.{category}"

    def run(self, target: str, scope: "Scope") -> ToolResult:
        started = int(time.time() * 1e9)

        if not self.available():
            return ToolResult.failed(
                self.name,
                target,
                f"nuclei binary not found on PATH. Install: brew install nuclei "
                f"or GO install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            )

        # Build command
        cmd: List[str] = [
            "nuclei",
            "-u", f"https://{target}" if not target.startswith("http") else target,
            "-jsonl",
            "-silent",
            "-rate-limit", str(scope.max_rps),
            "-timeout", "10",
        ]

        # Category selection
        if self.category == "cves":
            cmd.extend(["-tags", "cve"])
        elif self.category == "misconfiguration":
            cmd.extend(["-tags", "misconfig"])
        elif self.category == "exposures":
            cmd.extend(["-tags", "exposure"])
        elif self.category == "vulnerabilities":
            cmd.extend(["-tags", "vuln"])

        if self.template_tags:
            cmd.extend(["-tags", ",".join(self.template_tags)])

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=min(scope.max_duration_s, 1800),  # hard cap 30 min
                check=False,
            )
            findings = self._parse_jsonl(proc.stdout)
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
                self.name,
                target,
                f"nuclei timed out after {scope.max_duration_s}s",
            )
        except Exception as e:  # noqa: BLE001
            return ToolResult.failed(self.name, target, f"{type(e).__name__}: {e}")

    @staticmethod
    def _parse_jsonl(stdout: str) -> List[Dict[str, Any]]:
        """Parse nuclei's -jsonl output into our finding schema.

        Nuclei emits one JSON object per finding. Relevant fields we map:
            template-id    → template_id
            info.name      → title
            info.description → description
            info.severity  → severity
            info.reference → references
            info.classification.cve-id → references (as CVE-xxxx-yyyy)
            info.classification.cvss-score → cvss
            info.classification.cwe-id → cwe
            matched-at     → target (URL)
            curl-command   → evidence.curl
        """
        findings: List[Dict[str, Any]] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = obj.get("info", {})
            classification = info.get("classification", {}) or {}
            refs = list(info.get("reference") or [])
            cve_id = classification.get("cve-id")
            if cve_id:
                refs.append(cve_id if isinstance(cve_id, str) else ",".join(cve_id))

            cwe_id = classification.get("cwe-id")
            if isinstance(cwe_id, list):
                cwe_id = cwe_id[0] if cwe_id else None

            finding = {
                "template_id": obj.get("template-id"),
                "title": info.get("name", "(unnamed nuclei finding)"),
                "description": info.get("description", ""),
                "severity": info.get("severity", "info"),
                "references": refs,
                "cvss": classification.get("cvss-score"),
                "cwe": cwe_id,
                "evidence": {
                    "matched_at": obj.get("matched-at"),
                    "curl": obj.get("curl-command"),
                    "matcher_name": obj.get("matcher-name"),
                },
            }
            findings.append(finding)
        return findings
