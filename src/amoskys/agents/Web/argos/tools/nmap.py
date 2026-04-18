"""Nmap tool driver — scoped port scan of a target.

Nmap is the canonical port/service scanner. We use it sparingly:
engagements are primarily web-focused, so we scan a narrow port set
(top web-relevant + known-risky admin ports) rather than the full 65k.

Default scan targets:
    22   SSH                — publicly-reachable SSH is worth flagging
    21   FTP                — almost never needed on a WP host
    25   SMTP               — misconfigured mailers
    80   HTTP
    110  POP3
    143  IMAP
    443  HTTPS
    3306 MySQL              — must never be public on a WP host
    3389 RDP
    5432 Postgres
    6379 Redis
    8080 HTTP alt
    8443 HTTPS alt
    9200 Elasticsearch
    27017 Mongo

Each open port becomes an info-severity finding. Known-dangerous ports
(MySQL 3306, Redis 6379, Elasticsearch 9200, Mongo 27017) are elevated
to high because a public admin port on a web host is essentially a
deployment error.

Requires `nmap`. Uses `-sT` (TCP connect) by default so it works without
root; `-sS` (SYN scan) is faster but needs CAP_NET_RAW.

Docs: https://nmap.org/
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, TYPE_CHECKING

from amoskys.agents.Web.argos.tools.base import Tool, ToolResult

if TYPE_CHECKING:
    from amoskys.agents.Web.argos.engine import Scope


class NmapTool(Tool):
    """Port scan of a web-host's common service ports."""

    required_binary = "nmap"

    # Ports that should NEVER be public on a WordPress host.
    # Finding any of these open bumps severity to `high`.
    HIGH_RISK_PORTS = frozenset({3306, 5432, 6379, 9200, 27017, 11211, 9000, 9001})

    # Ports of concern even if sometimes legitimate (needs review).
    MEDIUM_RISK_PORTS = frozenset({21, 22, 23, 3389, 5900, 8000, 8001, 8080, 8443, 9090})

    def __init__(
        self,
        ports: str = "21,22,23,25,80,110,143,443,3306,3389,5432,5900,6379,8000,8001,8080,8443,9000,9090,9200,11211,27017",
        mode: str = "connect",  # "connect" (-sT, no root) or "syn" (-sS, needs root)
        service_detect: bool = True,
    ) -> None:
        self.name = "nmap"
        self.tool_class = "recon"
        self.probe_class = "nmap.portscan"
        self.ports = ports
        self.mode = mode
        self.service_detect = service_detect

    def run(self, target: str, scope: "Scope") -> ToolResult:
        started = int(time.time() * 1e9)

        if not self.available():
            return ToolResult.failed(
                self.name, target,
                "nmap binary not found. Install: apt install nmap",
            )

        out_dir = Path(tempfile.gettempdir()) / "argos-nmap"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"nmap-{uuid.uuid4().hex[:10]}.grep"
        stderr_path = out_dir / f"nmap-{uuid.uuid4().hex[:10]}.stderr"

        host = target.replace("https://", "").replace("http://", "").split("/")[0]

        cmd: List[str] = ["nmap"]
        # -sT uses TCP connect, no root needed; -sS is SYN scan, faster but needs CAP_NET_RAW.
        cmd.append("-sT" if self.mode == "connect" else "-sS")
        cmd.extend([
            "-p", self.ports,
            "-T4",              # aggressive timing
            "--open",           # only report open ports
            "-Pn",              # skip host discovery (assume up)
            "-oG", str(out_path),  # grep-parseable output
            "-n",               # don't resolve DNS (we have the host)
        ])
        if self.service_detect:
            cmd.append("-sV")
        cmd.append(host)

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
                    errors.append("nmap timed out, parsing partials")
        except Exception as e:  # noqa: BLE001
            errors.append(f"{type(e).__name__}: {e}")

        findings: List[Dict[str, Any]] = []
        stdout_bytes = 0
        if out_path.exists():
            try:
                content = out_path.read_text()
                stdout_bytes = len(content.encode())
                findings = self._parse_grep(content, host)
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

    def _parse_grep(self, content: str, host: str) -> List[Dict[str, Any]]:
        """Parse nmap's -oG (greppable) output.

        Format (one host per line):
            Host: 98.89.32.163 ()  Status: Up
            Host: 98.89.32.163 ()  Ports: 80/open/tcp//http///, 443/open/tcp//ssl|https///
        """
        findings: List[Dict[str, Any]] = []
        port_re = re.compile(r"(\d+)/(open|closed|filtered)/(tcp|udp)//([^/]*)///([^,]*)")

        for line in content.splitlines():
            if not line.startswith("Host:") or "Ports:" not in line:
                continue
            ports_section = line.split("Ports:", 1)[1]
            for m in port_re.finditer(ports_section):
                port = int(m.group(1))
                state = m.group(2)
                proto = m.group(3)
                service = (m.group(4) or "").strip()
                version = (m.group(5) or "").strip()

                if state != "open":
                    continue

                severity = "info"
                if port in self.HIGH_RISK_PORTS:
                    severity = "high"
                elif port in self.MEDIUM_RISK_PORTS:
                    severity = "medium"

                findings.append(
                    {
                        "template_id": f"nmap.open_port.{port}",
                        "title": f"Open port {port}/{proto} ({service or 'unknown'}) on {host}",
                        "description": (
                            f"Nmap found port {port}/{proto} open on {host}. "
                            f"Service: {service or 'unknown'}. Version: {version or 'unknown'}. "
                            + (
                                "This port is on the high-risk list for public web hosts — "
                                "admin/database services should not be reachable from the "
                                "public internet."
                                if severity == "high"
                                else (
                                    "This port is commonly misconfigured as publicly reachable — "
                                    "review whether it should be restricted."
                                    if severity == "medium"
                                    else ""
                                )
                            )
                        ).strip(),
                        "severity": severity,
                        "references": [],
                        "evidence": {
                            "host": host,
                            "port": port,
                            "proto": proto,
                            "service": service,
                            "version": version,
                            "risk_class": severity,
                        },
                    }
                )
        return findings
