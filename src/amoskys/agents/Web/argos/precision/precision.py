"""Argos Precision Engagement — APT-grade orchestrator.

Takes a target URL + (optionally) a Stage-1 dossier, produces a
PrecisionEngagement: the full plan to exploit this specific target
over days, with one probe per AST finding and explicit operator
gates on each escalation tier.

Workflow:
    1.  If we don't have a Stage-1 dossier, run one (passive OSINT).
    2.  Extract plugin inventory from the dossier.
    3.  For each plugin: download source at the exact version from
        wp.org SVN, run all 6 AST scanners against it.
    4.  For each AST finding: synthesize_probe() -> PayloadProbe.
    5.  build_precision_plan() -> ordered probe plan with tier
        classification.
    6.  low_slow_schedule() -> fire-time for each probe, spread
        across days.
    7.  Return PrecisionEngagement (plan + schedule).

This does NOT fire anything. Firing is a separate operator step.
The engagement object is the deliverable the operator reviews,
approves, and executes at the scheduled times.

The diff between this and nuclei
--------------------------------
nuclei fires ~800 templates against an unknown target blindly. We
fire N probes (where N = number of AST findings found in the
target's actual installed plugin versions), each tailored to the
exact vulnerable code path, one at a time, over days.

nuclei takes 10 minutes and finds zero because most templates
don't apply.

Precision mode takes a week and finds N vulnerabilities, where N
is the number of AST findings in actually-installed plugins. We
trade wall clock for signal-to-noise.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from amoskys.agents.Web.argos.precision.chain import PrecisionPlan, build_precision_plan
from amoskys.agents.Web.argos.precision.payload_synth import (
    PayloadProbe,
    synthesize_probe,
)
from amoskys.agents.Web.argos.precision.temporal import (
    SchedulePlan,
    TargetTimezone,
    low_slow_schedule,
)


@dataclass
class PrecisionEngagement:
    """Everything needed to execute a precision engagement."""

    target_url: str
    target_host: str
    consent_token: str = ""  # operator-supplied for audit
    created_at: float = 0.0
    plan: Optional[PrecisionPlan] = None
    schedule: Optional[SchedulePlan] = None
    findings_scanned: int = 0
    plugins_scanned: int = 0
    blind_reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "target_host": self.target_host,
            "consent_token": self.consent_token,
            "created_at": self.created_at,
            "plan": self.plan.to_dict() if self.plan else None,
            "schedule": self.schedule.to_dict() if self.schedule else None,
            "findings_scanned": self.findings_scanned,
            "plugins_scanned": self.plugins_scanned,
            "blind_reasons": self.blind_reasons,
        }


def run_precision(
    target_url: str,
    consent_token: str,
    plugin_inventory: Optional[List[Dict[str, str]]] = None,
    include_escalate: bool = False,
    timezone: Optional[TargetTimezone] = None,
    max_span_days: int = 14,
    corpus=None,
    scanner_registry=None,
) -> PrecisionEngagement:
    """Build (but do NOT fire) a precision engagement for one target.

    Parameters
    ----------
    target_url         Full URL of the consented target.
    consent_token      Audit-trail token from the signed engagement
                       letter. Stored in the engagement object.
    plugin_inventory   Optional pre-supplied list of {slug, version}
                       dicts. If None, caller must supply a dossier.
                       (For MVP we require this to be explicit.)
    include_escalate   Default False. If True, plan includes escalate-
                       tier probes (writes/data-exfil/state-change).
    timezone           Target's assumed timezone for schedule.
    max_span_days      Upper bound on engagement duration.
    corpus             Injected WPOrgCorpus for tests; production
                       uses the real one.
    scanner_registry   Injected scanner classes for tests.

    Returns PrecisionEngagement with plan + schedule populated.
    """
    engagement = PrecisionEngagement(
        target_url=target_url,
        target_host=_host_of(target_url),
        consent_token=consent_token,
        created_at=time.time(),
    )
    if not plugin_inventory:
        engagement.blind_reasons.append(
            "no plugin inventory supplied; precision mode requires an "
            "explicit list of (slug, version) pairs from a prior Stage-1 "
            "run or manual inventory"
        )
        return engagement

    # Load scanners (either injected for tests or lazy-imported).
    if scanner_registry is None:
        from amoskys.agents.Web.argos.ast import (
            CsrfScanner,
            FileUploadScanner,
            PoiScanner,
            RestAuthzScanner,
            SqlInjectionScanner,
            SsrfScanner,
        )

        scanner_registry = {
            "rest_authz": RestAuthzScanner,
            "sql_injection": SqlInjectionScanner,
            "file_upload": FileUploadScanner,
            "poi": PoiScanner,
            "csrf": CsrfScanner,
            "ssrf": SsrfScanner,
        }
    if corpus is None:
        from amoskys.agents.Web.argos.corpus import WPOrgCorpus

        corpus = WPOrgCorpus()

    findings: List[dict] = []
    for entry in plugin_inventory:
        slug = entry.get("slug")
        version = entry.get("version")
        if not slug:
            continue
        try:
            plugin = corpus.fetch(slug, version)
        except Exception as e:  # noqa: BLE001
            engagement.blind_reasons.append(
                f"corpus fetch failed for {slug}@{version}: " f"{type(e).__name__}: {e}"
            )
            continue
        engagement.plugins_scanned += 1
        for scanner_id, klass in scanner_registry.items():
            try:
                for f in klass().scan(plugin):
                    findings.append(
                        {
                            "scanner": f.scanner,
                            "rule_id": f.rule_id,
                            "severity": f.severity,
                            "plugin_slug": f.plugin_slug,
                            "plugin_version": f.plugin_version,
                            "file_path": f.file_path,
                            "line": f.line,
                            "title": f.title,
                            "cwe": f.cwe,
                        }
                    )
            except Exception as e:  # noqa: BLE001
                engagement.blind_reasons.append(
                    f"scanner {scanner_id} crashed on {slug}@{version}: "
                    f"{type(e).__name__}: {e}"
                )

    engagement.findings_scanned = len(findings)

    # Synthesize probes from findings.
    probes: List[PayloadProbe] = []
    for f in findings:
        probe = synthesize_probe(f, target_url)
        if probe is None:
            # No synthesis strategy for this rule — skip quietly; it's
            # an APT-discipline rule (never fire a blind probe).
            continue
        probes.append(probe)

    # Plan + schedule.
    engagement.plan = build_precision_plan(
        target_url,
        probes,
        include_escalate=include_escalate,
    )
    engagement.schedule = low_slow_schedule(
        probe_count=len(engagement.plan.probes),
        tz=timezone,
        max_span_days=max_span_days,
    )
    return engagement


# ---- Helpers -----------------------------------------------------


def _host_of(url: str) -> str:
    import urllib.parse

    p = urllib.parse.urlparse(url if "://" in url else "https://" + url)
    return p.netloc or url
