"""HTTPX tool driver — HTTP probing and technology fingerprinting.

HTTPX is ProjectDiscovery's HTTP toolkit. Given a list of hosts or URLs,
it returns status codes, titles, server headers, TLS details, and
technology stack identification. It is the canonical first-probe of any
engagement — we use it to fingerprint what kind of web stack each host
actually serves.

Output findings: per-host tech disclosures (server fingerprint, title
leak, exposed tech versions). These feed downstream tools (nuclei
selection, wpscan triggering) with targeting information.

Docs: https://github.com/projectdiscovery/httpx
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


class HTTPXTool(Tool):
    """Fingerprint a target's HTTP response + tech stack."""

    required_binary = "httpx"

    def __init__(self, probe_all_ips: bool = False) -> None:
        self.name = "httpx"
        self.tool_class = "fingerprint"
        self.probe_class = "httpx.fingerprint"
        self.probe_all_ips = probe_all_ips

    def run(self, target: str, scope: "Scope") -> ToolResult:
        started = int(time.time() * 1e9)

        if not self.available():
            return ToolResult.failed(
                self.name,
                target,
                "httpx binary not found. Install: "
                "go install github.com/projectdiscovery/httpx/cmd/httpx@latest  "
                "(note: Kali has an older 'httpx' from Python that conflicts — "
                "rename or use `~/bin/httpx` with the ProjectDiscovery version)",
            )

        out_dir = Path(tempfile.gettempdir()) / "argos-httpx"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"httpx-{uuid.uuid4().hex[:10]}.jsonl"
        stderr_path = out_dir / f"httpx-{uuid.uuid4().hex[:10]}.stderr"

        url = target if target.startswith("http") else f"https://{target}"

        cmd: List[str] = [
            "httpx",
            "-u", url,
            "-json",
            "-o", str(out_path),
            "-status-code",
            "-title",
            "-tech-detect",
            "-server",
            "-content-length",
            "-location",
            "-tls-grab",
            "-silent",
            "-rate-limit", str(scope.max_rps),
            "-timeout", "10",
        ]
        if self.probe_all_ips:
            cmd.append("-probe-all-ips")

        errors: List[str] = []
        exit_code = -1
        try:
            with open(stderr_path, "wb") as stderr_fh:
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.DEVNULL, stderr=stderr_fh,
                )
                try:
                    exit_code = proc.wait(timeout=min(scope.max_duration_s, 600))
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                    errors.append("httpx timed out, parsing partials")
        except Exception as e:  # noqa: BLE001
            errors.append(f"{type(e).__name__}: {e}")

        findings: List[Dict[str, Any]] = []
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
                    findings.extend(self._extract_findings(obj))
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

    @staticmethod
    def _extract_findings(obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Map httpx JSON record → findings.

        We generate one fingerprint-level finding per host plus a finding
        for each disclosed technology.
        """
        host = obj.get("host") or obj.get("url", "")
        url = obj.get("url", host)
        status = obj.get("status_code", 0)
        server = obj.get("webserver") or obj.get("server") or ""
        title = obj.get("title", "")
        techs = obj.get("tech", []) or obj.get("technologies", []) or []
        tls = obj.get("tls", {}) or {}

        findings = [
            {
                "template_id": "httpx.fingerprint",
                "title": f"HTTP fingerprint: {host}",
                "description": (
                    f"{host} returned HTTP {status}. Server: {server or 'unknown'}. "
                    f"Title: {title[:80] if title else '(none)'}"
                ),
                "severity": "info",
                "references": [],
                "evidence": {
                    "url": url,
                    "status": status,
                    "server": server,
                    "title": title,
                    "technologies": techs,
                    "tls_subject": tls.get("subject_dn") if isinstance(tls, dict) else None,
                    "tls_issuer": tls.get("issuer_dn") if isinstance(tls, dict) else None,
                },
            }
        ]

        # Server-header disclosure: any version string in the server header
        # is worth a separate finding because that's what CVE lookups match on.
        if server and any(c.isdigit() for c in server):
            findings.append(
                {
                    "template_id": "httpx.server_version_disclosed",
                    "title": f"Server version disclosed: {server}",
                    "description": (
                        f"The Server header on {host} reveals a specific version "
                        f"({server}). Attackers use this to match public CVEs to "
                        f"deployed software."
                    ),
                    "severity": "info",
                    "references": [],
                    "evidence": {"host": host, "server": server},
                }
            )

        # Each detected technology becomes a finding — useful for driving
        # nuclei's template selection based on tech tags.
        for tech in techs:
            tech_name = tech if isinstance(tech, str) else tech.get("name", str(tech))
            findings.append(
                {
                    "template_id": "httpx.tech_detected",
                    "title": f"Technology detected: {tech_name}",
                    "description": f"httpx fingerprinted {tech_name} running on {host}.",
                    "severity": "info",
                    "references": [],
                    "evidence": {"host": host, "technology": tech_name},
                }
            )

        return findings
