"""Recon → scan bridge. The ScanScheduler closes the customer loop.

The missing piece between surface discovery (what does the customer
have?) and active scanning (what's wrong with it?). Turns a completed
recon run into a queue of per-asset Engagements, aggregates their
findings, and produces one consolidated customer deliverable.

## Flow

    CustomerService.run_recon(customer_id)
        → surface_assets populated (domains, subdomains, IPs, ASNs, ...)

    ScanScheduler(db, operator).queue_surface(customer_id)
        → creates scan_queue + one scan_job per scan-target asset
           (scan-target kinds = domain / subdomain / url; IPs/ASNs
            are inventory, not direct HTTP probes)

    scheduler.run_all(queue_id)
        → for each pending job: build Scope → run Engagement → record
           findings_count + engagement_id + status transitions
           → audit_log entries for queue_start / job_start / job_complete
             / queue_complete, all tagged with operator_id

    scheduler.consolidated_findings(queue_id)
        → every engagement's findings unioned, deduped by (template_id,
           target) — one customer-facing flat list

## Scope guards (non-negotiable)

1. **Apex-scope guard.** An asset MAY NOT be scanned unless its value
   is the customer's seed OR a subdomain of it. This prevents scope
   creep when recon accidentally picks up a third-party host (common
   when CT logs show cross-referenced SANs).

2. **Consent floor.** The customer must have `consent_verified_at_ns`
   set before any job can run. Verified at queue-creation time; a
   customer whose consent is later revoked will see pending jobs
   refuse to run.

3. **Operator authorization.** The scheduler is constructed with an
   Operator reference; every job_start audit row is tagged to that
   operator. Role must be ANALYST+ to queue or run.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from amoskys.agents.Web.argos.storage import (
    AssetKind,
    AssetsDB,
    AuditEntry,
    Customer,
    Operator,
    OperatorRole,
    ScanJob,
    ScanQueue,
    SurfaceAsset,
)

logger = logging.getLogger("amoskys.argos.schedule")


# Kinds of surface asset we actually launch Engagements against.
# IPs / ASNs / netblocks are inventory; TLS certs are pivot keys.
_SCANNABLE_KINDS = (AssetKind.DOMAIN, AssetKind.SUBDOMAIN, AssetKind.URL)


# ── Errors ─────────────────────────────────────────────────────────


class CustomerConsentRequiredError(PermissionError):
    """Raised when queue creation or job execution runs against an
    unverified customer. The scheduler refuses to run in this state."""


class OutOfScopeAssetError(ValueError):
    """Raised when a caller tries to queue an asset that isn't in the
    customer's apex-scope. The scheduler catches + logs these during
    queue creation and marks the job as skipped instead of raising
    to the caller — this class is for explicit rejection paths."""


# ── Progress / aggregation types ───────────────────────────────────


@dataclass
class QueueProgress:
    """Live snapshot of a running queue — what's done, pending, failed."""
    queue_id: str
    customer_id: str
    operator_id: str
    tool_bundle: str
    total: int
    pending: int = 0
    running: int = 0
    complete: int = 0
    failed: int = 0
    skipped: int = 0
    total_findings: int = 0

    def render(self) -> str:
        lines = [
            f"queue {self.queue_id}",
            f"  customer: {self.customer_id}",
            f"  operator: {self.operator_id}",
            f"  tools:    {self.tool_bundle}",
            f"  jobs:     total={self.total}",
            f"    pending:  {self.pending}",
            f"    running:  {self.running}",
            f"    complete: {self.complete}",
            f"    failed:   {self.failed}",
            f"    skipped:  {self.skipped}",
            f"  findings (total): {self.total_findings}",
        ]
        return "\n".join(lines)


# ── EngagementRunner — injection point for scan execution ────────


class EngagementRunner:
    """ABC-ish hook so tests can swap in a fake Engagement runner.

    The scheduler hands each job to `.run(asset_value, customer, report_dir)`
    and expects back a dict with {engagement_id, findings_count, errors}.
    """

    def run(
        self,
        asset_value: str,
        customer: Customer,
        report_dir: Path,
        tool_bundle: str,
    ) -> Dict[str, Any]:
        """Default implementation: build a real Engagement + run it.

        Builds a Scope that trusts the customer's pre-verified consent:
        skip_dns_verify=True because the customer already DNS-TXT'd (or
        signed / emailed) the apex. Sub-asset engagements inherit that
        authorization transitively.
        """
        from amoskys.agents.Web.argos.cli import TOOL_REGISTRY
        from amoskys.agents.Web.argos.engine import Engagement, Scope

        tools_builder = TOOL_REGISTRY.get(tool_bundle)
        if tools_builder is None:
            return {
                "engagement_id": None,
                "findings_count": 0,
                "errors": [f"unknown tool_bundle: {tool_bundle!r}"],
            }
        raw = tools_builder()
        tools = raw if isinstance(raw, list) else [raw]

        now_ns = int(time.time() * 1e9)
        scope = Scope(
            target=asset_value,
            authorized_by=f"customer:{customer.customer_id}",
            txt_token=customer.consent_token or "inherited-from-customer",
            window_start_ns=now_ns,
            window_end_ns=now_ns + 3600 * 1_000_000_000,
            max_rps=2,
            max_duration_s=1800,
            # The customer's consent on the apex authorizes sub-asset
            # engagements. We don't re-verify DNS-TXT per asset; we
            # trust the pre-verified customer record.
            skip_dns_verify=True,
        )
        engagement = Engagement(scope=scope, tools=tools, report_dir=report_dir)
        result = engagement.run()
        return {
            "engagement_id": result.engagement_id,
            "findings_count": len(result.findings),
            "errors": list(result.errors),
        }


# ── Scheduler ──────────────────────────────────────────────────────


class ScanScheduler:
    """Turns a customer's surface into a queue of per-asset Engagements.

    Constructed with (db, operator). The operator must already be
    authorized (role ≥ ANALYST + current agreement accepted) by the
    caller — the scheduler trusts its constructor inputs and does NOT
    re-verify. CLI layer handles authorization.
    """

    def __init__(
        self,
        db: AssetsDB,
        operator: Operator,
        runner: Optional[EngagementRunner] = None,
        report_dir: Optional[Path] = None,
        tool_bundle: str = "wp-full-ast",
    ) -> None:
        self.db = db
        self.operator = operator
        self.runner = runner or EngagementRunner()
        self.report_dir = Path(
            report_dir or Path.home() / ".argos" / "customer-scans"
        ).resolve()
        self.tool_bundle = tool_bundle

    # ── Queue creation ────────────────────────────────────────────

    def queue_surface(self, customer_id: str) -> ScanQueue:
        """Create a scan_queue + one scan_job per scan-target asset.

        Assets outside the customer's apex scope are still recorded as
        jobs, but with `status=skipped` and `skip_reason` set — this
        way the customer-facing report can explain what was excluded
        and why.
        """
        customer = self._require_customer(customer_id)
        if customer.consent_verified_at_ns is None:
            raise CustomerConsentRequiredError(
                f"customer {customer.name!r} has unverified consent; "
                "run `argos customer verify` or re-enroll with lab_self."
            )

        queue = ScanQueue.new(
            customer_id=customer_id,
            operator_id=self.operator.operator_id,
            tool_bundle=self.tool_bundle,
        )
        self.db.create_scan_queue(queue)

        # Gather scan-target assets (domains + subdomains + URLs).
        # We pull them from the DB directly to get SurfaceAsset rows
        # (not the scan_targets list helper, which doesn't include
        # the asset_id we need for job linkage).
        targets: List[SurfaceAsset] = []
        for kind in _SCANNABLE_KINDS:
            targets.extend(self.db.list_assets(customer_id, kind=kind))

        apex = customer.seed.lower().strip()
        total_jobs = 0
        for asset in targets:
            job = ScanJob.new(
                queue_id=queue.queue_id,
                customer_id=customer_id,
                asset_id=asset.asset_id,
                asset_value=asset.value,
                asset_kind=asset.kind.value,
            )
            if not _is_in_apex_scope(asset.value, apex):
                job.status = "skipped"
                job.skip_reason = f"outside customer apex {apex!r}"
                job.completed_at_ns = int(time.time() * 1e9)
            self.db.create_scan_job(job)
            total_jobs += 1

        # Update queue with final job count
        queue.total_jobs = total_jobs
        # Re-write via update — simplest using a direct SQL call
        conn = self.db._conn_ctx()
        try:
            with self.db._lock:
                conn.execute(
                    "UPDATE scan_queues SET total_jobs = ? WHERE queue_id = ?",
                    (total_jobs, queue.queue_id),
                )
        finally:
            conn.close()

        self._audit(
            queue_id=queue.queue_id,
            action="scan_queue_create",
            target=customer.seed,
            result="ok",
            details={
                "tool_bundle": self.tool_bundle,
                "total_jobs": total_jobs,
                "scannable_assets_in_db": len(targets),
            },
        )
        return queue

    # ── Execution ─────────────────────────────────────────────────

    def run_next(self, queue_id: str) -> Optional[ScanJob]:
        """Run the next pending job synchronously.

        Returns the updated ScanJob, or None if the queue has no more
        pending jobs.
        """
        pending = self.db.list_scan_jobs(queue_id, status="pending")
        if not pending:
            return None
        job = pending[0]
        return self._run_one_job(job)

    def run_all(self, queue_id: str) -> QueueProgress:
        """Run every pending job in the queue, serially. Returns final progress."""
        queue = self.db.get_scan_queue(queue_id)
        if queue is None:
            raise LookupError(f"no scan_queue with id {queue_id!r}")
        customer = self._require_customer(queue.customer_id)
        if customer.consent_verified_at_ns is None:
            raise CustomerConsentRequiredError(
                f"customer {customer.name!r} consent revoked; refusing to run queue"
            )

        # Loop until no pending jobs remain.
        while True:
            job = self.run_next(queue_id)
            if job is None:
                break

        total_jobs = queue.total_jobs or 0
        self.db.complete_scan_queue(queue_id, total_jobs=total_jobs)

        progress = self.progress(queue_id)
        self._audit(
            queue_id=queue_id,
            action="scan_queue_complete",
            target=customer.seed,
            result="ok",
            details={
                "complete": progress.complete,
                "failed": progress.failed,
                "skipped": progress.skipped,
                "total_findings": progress.total_findings,
            },
        )
        return progress

    def _run_one_job(self, job: ScanJob) -> ScanJob:
        """Execute one job via the runner. Updates status + audit entries."""
        customer = self._require_customer(job.customer_id)

        # Start
        now_ns = int(time.time() * 1e9)
        job.status = "running"
        job.started_at_ns = now_ns
        self.db.update_scan_job(job)
        self._audit(
            queue_id=job.queue_id,
            action="scan_job_start",
            target=job.asset_value,
            result="ok",
            details={"asset_kind": job.asset_kind, "tool_bundle": self.tool_bundle},
            run_id=job.job_id,
        )

        # Execute
        try:
            result = self.runner.run(
                asset_value=job.asset_value,
                customer=customer,
                report_dir=self.report_dir / job.queue_id,
                tool_bundle=self.tool_bundle,
            )
        except Exception as e:  # noqa: BLE001
            job.status = "failed"
            job.error = f"{type(e).__name__}: {e}"
            job.completed_at_ns = int(time.time() * 1e9)
            self.db.update_scan_job(job)
            self._audit(
                queue_id=job.queue_id,
                action="scan_job_complete",
                target=job.asset_value,
                result="failed",
                details={"error": job.error},
                run_id=job.job_id,
            )
            return job

        # Record result
        errors = result.get("errors") or []
        job.engagement_id = result.get("engagement_id")
        job.findings_count = int(result.get("findings_count") or 0)
        job.completed_at_ns = int(time.time() * 1e9)
        # If the runner reported errors AND zero findings, call it failed;
        # errors with findings = partial success, still 'complete'.
        if errors and job.findings_count == 0:
            job.status = "failed"
            job.error = "; ".join(errors[:3])[:500]
        else:
            job.status = "complete"
        self.db.update_scan_job(job)
        self._audit(
            queue_id=job.queue_id,
            action="scan_job_complete",
            target=job.asset_value,
            result=job.status,
            details={
                "engagement_id": job.engagement_id,
                "findings": job.findings_count,
                "errors_count": len(errors),
            },
            run_id=job.job_id,
        )
        return job

    # ── Inspection ────────────────────────────────────────────────

    def progress(self, queue_id: str) -> QueueProgress:
        queue = self.db.get_scan_queue(queue_id)
        if queue is None:
            raise LookupError(f"no scan_queue with id {queue_id!r}")
        counts = self.db.scan_queue_status_counts(queue_id)
        jobs = self.db.list_scan_jobs(queue_id)
        total_findings = sum(j.findings_count for j in jobs)
        return QueueProgress(
            queue_id=queue.queue_id,
            customer_id=queue.customer_id,
            operator_id=queue.operator_id,
            tool_bundle=queue.tool_bundle,
            total=queue.total_jobs or len(jobs),
            pending=counts.get("pending", 0),
            running=counts.get("running", 0),
            complete=counts.get("complete", 0),
            failed=counts.get("failed", 0),
            skipped=counts.get("skipped", 0),
            total_findings=total_findings,
        )

    # ── Audit helper ──────────────────────────────────────────────

    def _audit(
        self,
        *,
        queue_id: str,
        action: str,
        target: Optional[str],
        result: str,
        details: Dict[str, Any],
        run_id: Optional[str] = None,
    ) -> None:
        try:
            self.db.audit(
                AuditEntry(
                    log_id=None,
                    customer_id=self._customer_id_for_queue(queue_id),
                    run_id=run_id or queue_id,
                    operator_id=self.operator.operator_id,
                    timestamp_ns=int(time.time() * 1e9),
                    actor="argos.schedule",
                    action=action,
                    target=target,
                    result=result,
                    details=details,
                )
            )
        except Exception:  # noqa: BLE001
            logger.exception("schedule audit write failed")

    def _customer_id_for_queue(self, queue_id: str) -> Optional[str]:
        q = self.db.get_scan_queue(queue_id)
        return q.customer_id if q else None

    def _require_customer(self, customer_id: str) -> Customer:
        c = self.db.get_customer(customer_id)
        if c is None:
            raise LookupError(f"no customer with id {customer_id!r}")
        return c


# ── Apex-scope guard ──────────────────────────────────────────────


def _is_in_apex_scope(asset_value: str, apex: str) -> bool:
    """Return True iff the asset is the apex or a subdomain of it.

    apex is already normalized (lowercased, scheme/port/path stripped)
    by the time it reaches us. We normalize asset_value the same way.
    """
    a = asset_value.strip().lower().rstrip(".")
    if not a or not apex:
        return False
    # Strip scheme/path if URL slipped through
    if "://" in a:
        a = a.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
    if a == apex:
        return True
    return a.endswith("." + apex)
