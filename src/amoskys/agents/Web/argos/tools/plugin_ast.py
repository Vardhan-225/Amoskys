"""PluginASTTool — adapts the AST scanner fleet as an Argos Tool.

Bridge pattern: the AST scanners (argos.ast.*) operate on PluginSource
objects; the engine's probe phase operates on Tool objects. This tool
does the translation.

Two modes of operation:

  1. Pre-primed (hunt mode / explicit scan):
        tool = PluginASTTool()
        tool.set_plugins([("contact-form-7", "5.9.0"), ("wpforms-lite", None)])
        tool.run(target, scope)

  2. Post-fingerprint (scan mode — default):
        tool = PluginASTTool()
        # engine calls prime_from_wpscan(wpscan_result) between phases
        tool.run(target, scope)

If run() is called with no primed plugins AND no fingerprint data is
visible via the shared engagement context, it emits a warning finding
but does not crash — the engagement should still complete and produce
a report with whatever other tools found.
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict
from typing import Any, Dict, Iterable, List, Optional, Tuple, TYPE_CHECKING

from amoskys.agents.Web.argos.ast import (
    ASTFinding,
    ASTScanner,
    RestAuthzScanner,
)
from amoskys.agents.Web.argos.corpus import PluginSource, WPOrgCorpus, WPOrgCorpusError
from amoskys.agents.Web.argos.tools.base import Tool, ToolResult

if TYPE_CHECKING:
    from amoskys.agents.Web.argos.engine import Scope

logger = logging.getLogger("amoskys.argos.plugin_ast")


class PluginASTTool(Tool):
    """Run AST scanners against plugin source fetched from wp.org.

    This is the core of the bug-bounty wedge — the tool that does what
    top hunters do (grep plugin source for sinks) but at scale and with
    real AST understanding instead of regex-only.
    """

    required_binary = ""  # pure Python

    def __init__(
        self,
        scanners: Optional[List[ASTScanner]] = None,
        corpus: Optional[WPOrgCorpus] = None,
        max_plugins: int = 200,
    ) -> None:
        self.scanners: List[ASTScanner] = scanners or [RestAuthzScanner()]
        self.corpus: WPOrgCorpus = corpus or WPOrgCorpus()
        self.max_plugins = max_plugins

        # Primed plugins: list of (slug, version-or-None)
        self._plugins: List[Tuple[str, Optional[str]]] = []

        # Standard Tool protocol fields
        self.name = "plugin-ast"
        self.tool_class = "probe"
        self.probe_class = "ast.source"

    # ── priming ────────────────────────────────────────────────────

    def set_plugins(self, plugins: Iterable[Tuple[str, Optional[str]]]) -> None:
        """Replace the primed plugin list."""
        deduped: List[Tuple[str, Optional[str]]] = []
        seen = set()
        for entry in plugins:
            if entry in seen:
                continue
            seen.add(entry)
            deduped.append(entry)
            if len(deduped) >= self.max_plugins:
                break
        self._plugins = deduped

    def prime_from_wpscan(self, wpscan_result: ToolResult) -> int:
        """Extract (slug, version) tuples from a wpscan ToolResult.

        Returns the number of plugins primed. Call this between the
        fingerprint and probe phases to feed live target fingerprints
        into the AST scanner.
        """
        plugins: List[Tuple[str, Optional[str]]] = []
        for finding in wpscan_result.findings:
            ev = finding.get("evidence") or {}
            component = ev.get("component") or ""
            if not component.startswith("plugin:"):
                continue
            slug = component[len("plugin:") :].strip()
            version = ev.get("installed_version")
            if isinstance(version, dict):
                # wpscan sometimes gives the whole version-obj; pull .number
                version = version.get("number")
            if slug:
                plugins.append((slug, version if isinstance(version, str) else None))

        self.set_plugins(plugins)
        return len(self._plugins)

    @property
    def primed_plugins(self) -> List[Tuple[str, Optional[str]]]:
        return list(self._plugins)

    # ── Tool protocol ──────────────────────────────────────────────

    def run(self, target: str, scope: "Scope") -> ToolResult:
        started = int(time.time() * 1e9)
        command = [
            "plugin-ast",
            "--scanners", ",".join(s.scanner_id for s in self.scanners),
            "--plugins", f"{len(self._plugins)}",
        ]

        findings: List[Dict[str, Any]] = []
        errors: List[str] = []
        ast_findings_emitted: List[ASTFinding] = []
        plugins_scanned = 0

        if not self._plugins:
            errors.append(
                "plugin-ast: no plugins primed. "
                "For scan mode, ensure wpscan ran first; "
                "for hunt mode, set plugins via set_plugins() or use argos hunt."
            )

        for slug, version in self._plugins:
            try:
                source = self.corpus.fetch(slug, version)
            except WPOrgCorpusError as e:
                errors.append(f"corpus fetch failed for {slug}@{version}: {e}")
                continue

            plugins_scanned += 1
            for scanner in self.scanners:
                try:
                    scanner_findings = scanner.scan(source)
                except Exception as e:  # noqa: BLE001
                    errors.append(
                        f"scanner {scanner.scanner_id} raised on "
                        f"{slug}@{source.version}: {type(e).__name__}: {e}"
                    )
                    continue
                ast_findings_emitted.extend(scanner_findings)
                for f in scanner_findings:
                    findings.append(f.to_engagement_finding())

        completed = int(time.time() * 1e9)

        # Surface scan stats in errors[0] slot for ops visibility (non-fatal).
        stats = (
            f"plugin-ast stats: plugins_primed={len(self._plugins)} "
            f"plugins_scanned={plugins_scanned} "
            f"findings={len(ast_findings_emitted)} "
            f"scanners={[s.scanner_id for s in self.scanners]}"
        )
        logger.info(stats)

        return ToolResult(
            tool=self.name,
            command=command,
            target=target,
            exit_code=0 if plugins_scanned > 0 else 1,
            started_at_ns=started,
            completed_at_ns=completed,
            stdout_bytes=sum(len(str(f)) for f in findings),
            stderr_bytes=sum(len(e) for e in errors),
            findings=findings,
            errors=errors,
        )

    def available(self) -> bool:
        # Pure-Python tool is always available.
        return True
