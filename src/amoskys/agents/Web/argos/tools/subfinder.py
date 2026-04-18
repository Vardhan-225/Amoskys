"""Subfinder tool driver — passive subdomain enumeration.

Subfinder is ProjectDiscovery's passive subdomain discovery engine. It
queries dozens of public sources (cert-transparency logs, passive DNS,
search engines) without sending traffic to the target.

Because subfinder is passive, we can run it OUTSIDE engagement scope —
it does not touch the customer's infrastructure. This makes it a safe
always-on recon stage for every engagement.

Output: list of discovered subdomains, each surfaced as an info-severity
finding. The subdomain list is also available in ToolResult.findings so
downstream probes (httpx, nuclei) can expand their target set.

Docs: https://github.com/projectdiscovery/subfinder
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, TYPE_CHECKING

from amoskys.agents.Web.argos.tools.base import Tool, ToolResult

if TYPE_CHECKING:
    from amoskys.agents.Web.argos.engine import Scope


class SubfinderTool(Tool):
    """Enumerate subdomains of a target domain via passive sources only."""

    required_binary = "subfinder"

    def __init__(self, recursive: bool = False) -> None:
        self.name = "subfinder"
        self.tool_class = "recon"
        self.probe_class = "subfinder.passive"
        self.recursive = recursive

    def run(self, target: str, scope: "Scope") -> ToolResult:
        started = int(time.time() * 1e9)

        if not self.available():
            return ToolResult.failed(
                self.name,
                target,
                "subfinder binary not found. Install: "
                "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            )

        out_dir = Path(tempfile.gettempdir()) / "argos-subfinder"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"subfinder-{uuid.uuid4().hex[:10]}.jsonl"
        stderr_path = out_dir / f"subfinder-{uuid.uuid4().hex[:10]}.stderr"

        # Strip protocol if passed; subfinder wants the apex domain
        clean = target.replace("https://", "").replace("http://", "").split("/")[0]

        cmd: List[str] = [
            "subfinder",
            "-d", clean,
            "-silent",
            "-json",
            "-o", str(out_path),
            "-timeout", "10",
        ]
        if self.recursive:
            cmd.append("-recursive")

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
                    # Subfinder is passive → bounded by network, not target.
                    # Cap at 5 min regardless of engagement scope.
                    exit_code = proc.wait(timeout=min(scope.max_duration_s, 300))
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                    errors.append("subfinder timed out, parsing partials")
        except Exception as e:  # noqa: BLE001
            errors.append(f"{type(e).__name__}: {e}")

        findings: List[Dict[str, Any]] = []
        subdomains_found: List[str] = []
        stdout_bytes = 0
        if out_path.exists():
            try:
                content = out_path.read_text()
                stdout_bytes = len(content.encode())
                for line in content.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    host = obj.get("host") or obj.get("name")
                    if not host:
                        continue
                    subdomains_found.append(host)
                    findings.append(
                        {
                            "template_id": "subfinder.subdomain_discovered",
                            "title": f"Subdomain discovered: {host}",
                            "description": (
                                f"Passive source identified {host} as a subdomain "
                                f"of {clean}. This expands the external attack "
                                f"surface and should be included in subsequent scans."
                            ),
                            "severity": "info",
                            "references": [obj.get("source", "passive")],
                            "evidence": {
                                "host": host,
                                "source": obj.get("source"),
                                "apex": clean,
                            },
                        }
                    )
            except Exception as e:  # noqa: BLE001
                errors.append(f"failed to parse {out_path}: {type(e).__name__}: {e}")

        stderr_bytes = os.path.getsize(stderr_path) if stderr_path.exists() else 0
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
