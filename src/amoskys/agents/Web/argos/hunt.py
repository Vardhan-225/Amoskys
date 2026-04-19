"""Argos hunt mode — corpus-wide AST sweep for bug bounty candidates.

Hunt mode is structurally different from scan mode:

  - No target URL. We're reading public plugin source, not touching
    anyone's live site. The DNS-TXT consent gate doesn't apply.
  - The "phases" are: corpus → scan → triage → report. No live probing.
  - Findings carry (plugin_slug, plugin_version, file, line) as their
    identity, not (target_url, template_id).
  - Output is a dossier the operator triages before submission.

This module intentionally does NOT inherit from Engagement — they share
primitives (Finding, ReportRenderer) but have different control flow.
A Hunt is a repeatable supply-chain operation. An Engagement is a
one-shot live pentest.

Usage (programmatic):

    from amoskys.agents.Web.argos.hunt import Hunt
    hunt = Hunt(slugs=["contact-form-7", "wpforms-lite"])
    result = hunt.run()
    print(result.summary())

Usage (CLI):
    python -m amoskys.agents.Web.argos hunt --top 50 --min-installs 10000
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from amoskys.agents.Web.argos.ast import ASTFinding, ASTScanner, RestAuthzScanner
from amoskys.agents.Web.argos.corpus import WPOrgCorpus, WPOrgCorpusError

logger = logging.getLogger("amoskys.argos.hunt")


# ── Data ───────────────────────────────────────────────────────────

@dataclass
class HuntResult:
    """Output of one hunt run."""

    hunt_id: str
    started_at_ns: int
    completed_at_ns: int
    plugins_targeted: List[Tuple[str, Optional[str]]]
    plugins_scanned: int
    findings: List[ASTFinding]
    errors: List[str]
    scanners_used: List[str]
    operator_id: Optional[str] = None
    operator_email: Optional[str] = None

    @property
    def duration_s(self) -> float:
        return (self.completed_at_ns - self.started_at_ns) / 1e9

    def severity_counts(self) -> Dict[str, int]:
        counts = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def top_plugins_by_findings(self, n: int = 10) -> List[Tuple[str, int]]:
        per_plugin: Dict[str, int] = {}
        for f in self.findings:
            per_plugin[f.plugin_slug] = per_plugin.get(f.plugin_slug, 0) + 1
        return sorted(per_plugin.items(), key=lambda kv: kv[1], reverse=True)[:n]

    def summary(self) -> str:
        sev = self.severity_counts()
        top = self.top_plugins_by_findings(n=5)
        lines = [
            f"hunt {self.hunt_id}",
            f"  duration: {self.duration_s:.1f}s",
            f"  plugins targeted: {len(self.plugins_targeted)}",
            f"  plugins scanned:  {self.plugins_scanned}",
            f"  scanners: {self.scanners_used}",
            f"  findings:",
            f"    critical: {sev['critical']}",
            f"    high:     {sev['high']}",
            f"    medium:   {sev['medium']}",
            f"    low:      {sev['low']}",
            f"    info:     {sev['info']}",
        ]
        if top:
            lines.append(f"  top by finding-count:")
            for slug, n in top:
                lines.append(f"    {slug}: {n}")
        if self.errors:
            lines.append(f"  errors: {len(self.errors)} (first 3 shown)")
            for e in self.errors[:3]:
                lines.append(f"    - {e}")
        return "\n".join(lines)

    def to_json(self) -> str:
        return json.dumps(
            {
                "hunt_id": self.hunt_id,
                "started_at_ns": self.started_at_ns,
                "completed_at_ns": self.completed_at_ns,
                "duration_s": self.duration_s,
                "operator_id": self.operator_id,
                "operator_email": self.operator_email,
                "plugins_targeted": [
                    {"slug": s, "version": v} for s, v in self.plugins_targeted
                ],
                "plugins_scanned": self.plugins_scanned,
                "scanners_used": self.scanners_used,
                "severity_counts": self.severity_counts(),
                "findings": [asdict(f) for f in self.findings],
                "errors": self.errors,
            },
            indent=2,
            sort_keys=True,
        )


# ── Hunt ───────────────────────────────────────────────────────────

class Hunt:
    """A corpus-wide AST sweep.

    Two sources of targets:

      - Explicit slug list (slugs=[...]) — scans those, latest versions
        unless explicit (slug, version) tuples given.

      - Top-N by install count (top_n=100) — pulls most popular plugins
        from wp.org API. Gated by min_installs.

    Both modes respect `limit` as a hard stop on total plugins scanned.
    """

    def __init__(
        self,
        slugs: Optional[Iterable[str]] = None,
        targets: Optional[Iterable[Tuple[str, Optional[str]]]] = None,
        top_n: Optional[int] = None,
        min_installs: int = 1000,
        scanners: Optional[List[ASTScanner]] = None,
        corpus: Optional[WPOrgCorpus] = None,
        limit: int = 500,
        report_dir: Optional[Path] = None,
        operator_id: Optional[str] = None,
        operator_email: Optional[str] = None,
        db=None,  # type: Optional[AssetsDB]
    ) -> None:
        if not (slugs or targets or top_n):
            raise ValueError(
                "Hunt requires one of: slugs=..., targets=..., or top_n=..."
            )
        self._slugs = list(slugs or [])
        self._targets = list(targets or [])
        self._top_n = top_n
        self.min_installs = min_installs
        self.scanners = scanners or [RestAuthzScanner()]
        self.corpus = corpus or WPOrgCorpus()
        self.limit = limit
        self.report_dir = Path(report_dir or Path.home() / ".argos" / "hunts").resolve()
        self.hunt_id = str(uuid.uuid4())
        self.operator_id = operator_id
        self.operator_email = operator_email
        self.db = db  # if provided, hunt start/complete are written to audit_log

    def _resolve_targets(self) -> List[Tuple[str, Optional[str]]]:
        """Build the final plugin list from the three input channels."""
        out: List[Tuple[str, Optional[str]]] = []
        seen = set()

        def _add(slug: str, version: Optional[str]) -> None:
            key = (slug, version)
            if key in seen:
                return
            seen.add(key)
            out.append(key)

        for entry in self._targets:
            _add(entry[0], entry[1] if len(entry) > 1 else None)
        for slug in self._slugs:
            _add(slug, None)

        if self._top_n and len(out) < self.limit:
            try:
                top = self.corpus.top_by_installs(
                    n=self._top_n,
                    min_installs=self.min_installs,
                )
                for slug, _installs in top:
                    _add(slug, None)
                    if len(out) >= self.limit:
                        break
            except WPOrgCorpusError as e:
                logger.warning("top_by_installs failed: %s", e)

        return out[: self.limit]

    def run(self) -> HuntResult:
        started = int(time.time() * 1e9)
        targets = self._resolve_targets()
        findings: List[ASTFinding] = []
        errors: List[str] = []
        scanned = 0

        logger.info("hunt %s: %d targets, scanners=%s, operator=%s",
                    self.hunt_id,
                    len(targets),
                    [s.scanner_id for s in self.scanners],
                    self.operator_email or self.operator_id or "<none>")

        self._audit_hunt_event(
            action="hunt_start",
            result="ok",
            timestamp_ns=started,
            details={
                "targets": len(targets),
                "limit": self.limit,
                "scanners": [s.scanner_id for s in self.scanners],
                "top_n": self._top_n,
                "slug_count": len(self._slugs),
            },
        )

        for slug, version in targets:
            try:
                source = self.corpus.fetch(slug, version)
            except WPOrgCorpusError as e:
                errors.append(f"corpus: {slug}@{version}: {e}")
                continue
            scanned += 1
            for scanner in self.scanners:
                try:
                    for f in scanner.scan(source):
                        findings.append(f)
                except Exception as e:  # noqa: BLE001
                    errors.append(
                        f"scanner {scanner.scanner_id} on {slug}@{source.version}: "
                        f"{type(e).__name__}: {e}"
                    )

        # Dedup findings by (plugin_slug, plugin_version, rule_id, file, line)
        findings = _dedup_findings(findings)

        completed = int(time.time() * 1e9)
        result = HuntResult(
            hunt_id=self.hunt_id,
            started_at_ns=started,
            completed_at_ns=completed,
            plugins_targeted=targets,
            plugins_scanned=scanned,
            findings=findings,
            errors=errors,
            scanners_used=[s.scanner_id for s in self.scanners],
            operator_id=self.operator_id,
            operator_email=self.operator_email,
        )

        self._write_report(result)

        self._audit_hunt_event(
            action="hunt_complete",
            result="ok" if not errors else "error",
            timestamp_ns=completed,
            details={
                "plugins_scanned": scanned,
                "findings": len(findings),
                "duration_s": round(result.duration_s, 3),
                "errors_count": len(errors),
            },
        )
        return result

    def _audit_hunt_event(self, *, action, result, timestamp_ns, details):
        """Write hunt lifecycle to the audit log when a DB is attached."""
        if self.db is None:
            return
        try:
            from amoskys.agents.Web.argos.storage import AuditEntry
            self.db.audit(
                AuditEntry(
                    log_id=None,
                    customer_id=None,
                    run_id=self.hunt_id,
                    operator_id=self.operator_id,
                    timestamp_ns=timestamp_ns,
                    actor="argos.hunt",
                    action=action,
                    target=None,
                    result=result,
                    details=details,
                )
            )
        except Exception:  # noqa: BLE001
            logger.exception("hunt audit write failed")

    def _write_report(self, result: HuntResult) -> Path:
        self.report_dir.mkdir(parents=True, exist_ok=True)
        path = self.report_dir / f"hunt-{result.hunt_id}.json"
        path.write_text(result.to_json())
        logger.info("hunt %s: report written to %s", result.hunt_id, path)
        return path


def _dedup_findings(findings: List[ASTFinding]) -> List[ASTFinding]:
    """Collapse exact duplicates; preserve insertion order otherwise."""
    out: List[ASTFinding] = []
    seen = set()
    for f in findings:
        key = (f.plugin_slug, f.plugin_version, f.rule_id, f.file_path, f.line)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out
