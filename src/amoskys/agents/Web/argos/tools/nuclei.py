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

        # Output to a temp file so findings survive SIGTERM / SIGKILL.
        # We parse the file at the end regardless of how the subprocess exited.
        out_dir = Path(tempfile.gettempdir()) / "argos-nuclei"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"nuclei-{uuid.uuid4().hex[:10]}.jsonl"
        stderr_path = out_dir / f"nuclei-{uuid.uuid4().hex[:10]}.stderr"

        # Build command
        cmd: List[str] = [
            "nuclei",
            "-u", f"https://{target}" if not target.startswith("http") else target,
            "-jsonl",
            "-silent",
            "-nc",  # no color codes
            "-rate-limit", str(scope.max_rps),
            "-timeout", "10",
            "-o", str(out_path),
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

        errors: List[str] = []
        exit_code = -1
        try:
            with open(stderr_path, "wb") as stderr_fh:
                # Run with stderr to file, stdout is already -> out_path via -o flag.
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
                        f"nuclei timed out after {scope.max_duration_s}s — "
                        f"parsing partial output from {out_path}"
                    )
        except Exception as e:  # noqa: BLE001
            errors.append(f"{type(e).__name__}: {e}")

        # Parse whatever made it to disk — even on timeout, this gives partials.
        findings: List[Dict[str, Any]] = []
        stdout_bytes = 0
        if out_path.exists():
            try:
                content = out_path.read_text()
                stdout_bytes = len(content.encode())
                findings = self._parse_jsonl(content)
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
