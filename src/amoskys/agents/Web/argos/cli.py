"""Argos CLI entry point.

Usage:
    argos scan <target> [--report-dir PATH] [--tools nuclei,wpscan]
    argos scan lab.amoskys.com --tools wp-full-ast
    argos hunt --top 50 --min-installs 10000
    argos hunt --slugs contact-form-7,wpforms-lite
    argos report <engagement.json> [--out-dir .]

Modes:
    scan  — authorized pentest against a live target (consent-gated)
    hunt  — corpus-wide AST sweep over wp.org plugin source (no target)
    report — re-render an existing engagement JSON as HTML + PDF
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from pathlib import Path

from amoskys.agents.Web.argos.engine import Engagement, Scope
from amoskys.agents.Web.argos.tools import (
    HTTPXTool,
    NmapTool,
    NucleiTool,
    PluginASTTool,
    SubfinderTool,
    WPScanTool,
)


TOOL_REGISTRY = {
    # Recon
    "subfinder": lambda: SubfinderTool(),
    "nmap": lambda: NmapTool(),
    # Fingerprint
    "httpx": lambda: HTTPXTool(),
    "wpscan": lambda: WPScanTool(),
    # Probe (nuclei categories)
    "nuclei-cves": lambda: NucleiTool(category="cves"),
    "nuclei-misconfig": lambda: NucleiTool(category="misconfiguration"),
    "nuclei-exposures": lambda: NucleiTool(category="exposures"),
    "nuclei-vulnerabilities": lambda: NucleiTool(category="vulnerabilities"),
    # AST-based plugin source analysis
    "plugin-ast": lambda: PluginASTTool(),
    # Preset bundles
    "recon": lambda: [SubfinderTool(), NmapTool(), HTTPXTool()],
    "wp-full": lambda: [
        HTTPXTool(), WPScanTool(),
        NucleiTool(category="cves"), NucleiTool(category="exposures"),
        NucleiTool(category="misconfiguration"),
    ],
    # The full-stack WP bundle: fingerprint -> AST analysis of installed
    # plugins -> public-CVE match. This is the default for client pentests.
    "wp-full-ast": lambda: [
        HTTPXTool(), WPScanTool(),
        PluginASTTool(),
        NucleiTool(category="cves"), NucleiTool(category="exposures"),
        NucleiTool(category="misconfiguration"),
    ],
}


def cmd_report(args: argparse.Namespace) -> int:
    """Render an existing engagement JSON as HTML/PDF."""
    import json as _json
    from amoskys.agents.Web.argos.engine import (
        EngagementResult, Scope, Phase, Finding, Severity
    )
    from amoskys.agents.Web.argos.tools.base import ToolResult
    from amoskys.agents.Web.argos.report import ReportRenderer

    report_path = Path(args.engagement_json)
    if not report_path.exists():
        print(f"error: engagement file not found: {report_path}", file=sys.stderr)
        return 2
    data = _json.loads(report_path.read_text())

    # Reconstitute the EngagementResult from JSON
    scope = Scope(**data["scope"])
    phases = [Phase(p) for p in data["phases_complete"]]

    def _reify_finding(f: dict) -> Finding:
        return Finding(
            finding_id=f["finding_id"], tool=f["tool"],
            template_id=f.get("template_id"), target=f["target"],
            severity=Severity(f["severity"]), title=f["title"],
            description=f.get("description", ""), evidence=f.get("evidence") or {},
            cwe=f.get("cwe"), cvss=f.get("cvss"),
            references=f.get("references") or [],
            mitre_techniques=f.get("mitre_techniques") or [],
            detected_at_ns=f.get("detected_at_ns") or 0,
        )
    findings = [_reify_finding(f) for f in data.get("findings", [])]

    tool_outputs = {}
    for name, tr in data.get("tool_outputs", {}).items():
        tool_outputs[name] = ToolResult(**{k: v for k, v in tr.items() if k in ToolResult.__dataclass_fields__})

    result = EngagementResult(
        engagement_id=data["engagement_id"],
        scope=scope,
        started_at_ns=data["started_at_ns"],
        completed_at_ns=data["completed_at_ns"],
        phases_complete=phases,
        findings=findings,
        tool_outputs=tool_outputs,
        errors=data.get("errors", []),
    )

    renderer = ReportRenderer()
    out_dir = Path(args.out_dir or ".").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"argos-{result.engagement_id}"

    html = renderer.render_html(result)
    html_path = out_dir / f"{stem}.html"
    html_path.write_text(html)
    print(f"[argos report] HTML → {html_path}")

    if not args.html_only:
        try:
            pdf_bytes = renderer.render_pdf(result)
            pdf_path = out_dir / f"{stem}.pdf"
            pdf_path.write_bytes(pdf_bytes)
            print(f"[argos report] PDF  → {pdf_path}")
        except Exception as e:  # noqa: BLE001
            print(f"[argos report] PDF render failed: {type(e).__name__}: {e}", file=sys.stderr)
            print("[argos report] (HTML-only output)")
            return 1
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    tool_names = [t.strip() for t in args.tools.split(",") if t.strip()]
    tools = []
    for name in tool_names:
        builder = TOOL_REGISTRY.get(name)
        if not builder:
            print(f"error: unknown tool '{name}'. available: {list(TOOL_REGISTRY)}", file=sys.stderr)
            return 2
        result = builder()
        # Preset bundles return a list; individual tools return one instance
        if isinstance(result, list):
            tools.extend(result)
        else:
            tools.append(result)

    now_ns = int(time.time() * 1e9)
    scope = Scope(
        target=args.target,
        authorized_by=args.authorized_by or "dev@amoskys.com",
        txt_token=args.txt_token or f"dev-{uuid.uuid4()}",
        window_start_ns=now_ns,
        window_end_ns=now_ns + args.max_duration * 1_000_000_000,
        max_rps=args.max_rps,
        max_duration_s=args.max_duration,
        skip_dns_verify=args.skip_dns_verify,
    )

    report_dir = Path(args.report_dir).expanduser().resolve()
    engagement = Engagement(scope=scope, tools=tools, report_dir=report_dir)

    print(f"[argos] engagement {engagement.engagement_id} -> {args.target}")
    print(f"[argos] tools: {[t.name for t in tools]}")
    print(f"[argos] scope: rps={scope.max_rps} duration={scope.max_duration_s}s")

    result = engagement.run()

    print("\n[argos] summary")
    print(f"  phases complete: {[p.value for p in result.phases_complete]}")
    print(f"  duration: {result.duration_s:.1f}s")
    print(f"  findings: {result.summary_counts}")
    if result.errors:
        print(f"  errors: {len(result.errors)}")
        for e in result.errors:
            print(f"    - {e}")
    print(f"\n[argos] report written to: {report_dir}/argos-{result.engagement_id}.json")
    return 0 if not result.errors else 1


def _customer_service(args: argparse.Namespace):
    """Construct the CustomerService with a DB initialized at --db or default path."""
    from amoskys.agents.Web.argos.storage import AssetsDB
    from amoskys.agents.Web.argos.customer import CustomerService

    db_path = Path(getattr(args, "db", None) or Path.home() / ".argos" / "customer.db")
    db = AssetsDB(db_path)
    db.initialize()
    return CustomerService(db=db), db


def cmd_customer_enroll(args: argparse.Namespace) -> int:
    from amoskys.agents.Web.argos.consent import ArtifactRef
    from amoskys.agents.Web.argos.storage import ConsentMethod

    service, _db = _customer_service(args)
    method_map = {
        "dns_txt": ConsentMethod.DNS_TXT,
        "email": ConsentMethod.EMAIL,
        "signed_contract": ConsentMethod.SIGNED_CONTRACT,
        "lab_self": ConsentMethod.LAB_SELF,
    }
    method = method_map[args.consent_method]

    artifact = None
    if method in (ConsentMethod.EMAIL, ConsentMethod.SIGNED_CONTRACT):
        if not args.artifact_ref:
            print(
                f"error: --artifact-ref is required for consent method "
                f"{args.consent_method} (format: type=value, e.g. "
                f"docusign_envelope=abc123 or email_message_id=<foo@bar>)",
                file=sys.stderr,
            )
            return 2
        if "=" not in args.artifact_ref:
            print(
                "error: --artifact-ref must be of form TYPE=VALUE "
                "(type is one of: docusign_envelope, contract_number, "
                "email_message_id, file_path, other)",
                file=sys.stderr,
            )
            return 2
        ref_type, _, ref_value = args.artifact_ref.partition("=")
        artifact = ArtifactRef(ref_type=ref_type.strip(), ref_value=ref_value.strip())

    try:
        enrollment = service.enroll(
            name=args.name,
            seed=args.seed,
            consent_method=method,
            artifact_ref=artifact,
        )
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    print(f"[argos customer] enrolled {enrollment.customer.customer_id}")
    print()
    print(enrollment.instructions)
    return 0


def _resolve_operator(args: argparse.Namespace, db, required_role):
    """Resolve current operator from --operator / ARGOS_OPERATOR and authorize.

    Returns (Operator, OperatorService). Raises SystemExit with a
    meaningful exit code on failure so the CLI surfaces the reason:
        2 — no / unknown operator
        3 — agreement not accepted
        4 — insufficient role
    """
    from amoskys.agents.Web.argos.operators import (
        AgreementNotAcceptedError,
        InsufficientRoleError,
        OperatorNotFoundError,
        OperatorService,
        current_operator_ref,
    )

    service = OperatorService(db)
    ref = current_operator_ref(getattr(args, "operator", None))
    if not ref:
        print(
            "error: no operator identity. Set via --operator <email|id> "
            "or ARGOS_OPERATOR env var. Register with `argos operator register`.",
            file=sys.stderr,
        )
        raise SystemExit(2)

    op = service.resolve(ref)
    if op is None:
        print(f"error: no operator matches {ref!r}", file=sys.stderr)
        raise SystemExit(2)

    try:
        service.authorize(op.operator_id, required_role, action=getattr(args, "cmd", ""))
    except AgreementNotAcceptedError as e:
        print(f"error: {e}", file=sys.stderr)
        raise SystemExit(3)
    except InsufficientRoleError as e:
        print(f"error: {e}", file=sys.stderr)
        raise SystemExit(4)
    except OperatorNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        raise SystemExit(2)

    return op, service


def cmd_operator_register(args: argparse.Namespace) -> int:
    from amoskys.agents.Web.argos.operators import (
        AGREEMENT_V1,
        CURRENT_AGREEMENT_VERSION,
        OperatorService,
    )
    from amoskys.agents.Web.argos.storage import AssetsDB, OperatorRole

    db_path = Path(args.db or Path.home() / ".argos" / "customer.db")
    db = AssetsDB(db_path)
    db.initialize()

    service = OperatorService(db)
    role_map = {
        "admin": OperatorRole.ADMIN,
        "analyst": OperatorRole.ANALYST,
        "viewer": OperatorRole.VIEWER,
    }
    role = role_map[args.role]

    if args.accept_agreement:
        print(f"--- AMOSKYS OPERATOR AGREEMENT {CURRENT_AGREEMENT_VERSION} ---")
        print(AGREEMENT_V1)
        print(f"--- END AGREEMENT ---\n")

    try:
        op = service.register(
            email=args.email,
            name=args.name,
            role=role,
            accept_agreement=args.accept_agreement,
        )
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    print(f"[argos operator] registered {op.email} (id={op.operator_id}, role={op.role.value})")
    if args.accept_agreement:
        print(f"[argos operator] agreement {CURRENT_AGREEMENT_VERSION} accepted + recorded")
    else:
        print(f"[argos operator] agreement NOT YET accepted. Run:")
        print(f"  argos operator accept --operator {op.email}")
    return 0


def cmd_operator_accept(args: argparse.Namespace) -> int:
    from amoskys.agents.Web.argos.operators import (
        AGREEMENT_V1,
        CURRENT_AGREEMENT_VERSION,
        OperatorService,
    )
    from amoskys.agents.Web.argos.storage import AssetsDB

    db_path = Path(args.db or Path.home() / ".argos" / "customer.db")
    db = AssetsDB(db_path)
    db.initialize()

    service = OperatorService(db)
    op = service.resolve(args.operator)
    if op is None:
        print(f"error: no operator matches {args.operator!r}", file=sys.stderr)
        return 2

    print(f"--- AMOSKYS OPERATOR AGREEMENT {CURRENT_AGREEMENT_VERSION} ---")
    print(AGREEMENT_V1)
    print(f"--- END AGREEMENT ---\n")
    print(f"Operator: {op.email} ({op.name}, role={op.role.value})")

    if not args.yes:
        confirm = input("Type 'I AGREE' to accept: ").strip()
        if confirm != "I AGREE":
            print("not accepted.")
            return 1

    ag = service.accept_agreement(op.operator_id)
    print(f"[argos operator] agreement accepted:")
    print(f"  version:      {ag.version}")
    print(f"  sha256:       {ag.agreement_sha256}")
    print(f"  accepted_at:  {ag.accepted_at_ns}")
    print(f"  ip at accept: {ag.ip_at_accept}")
    return 0


def cmd_operator_whoami(args: argparse.Namespace) -> int:
    from amoskys.agents.Web.argos.operators import (
        CURRENT_AGREEMENT_VERSION,
        OperatorService,
        current_operator_ref,
    )
    from amoskys.agents.Web.argos.storage import AssetsDB

    db_path = Path(args.db or Path.home() / ".argos" / "customer.db")
    db = AssetsDB(db_path)
    db.initialize()

    ref = current_operator_ref(getattr(args, "operator", None))
    if not ref:
        print(
            "(no operator identity set)\n"
            "Set via --operator <email|id> or ARGOS_OPERATOR env var.",
            file=sys.stderr,
        )
        return 2

    service = OperatorService(db)
    try:
        who = service.whoami(ref)
    except Exception as e:  # noqa: BLE001
        print(f"error: {e}", file=sys.stderr)
        return 2

    print(f"operator:         {who.operator.email} ({who.operator.name})")
    print(f"  id:             {who.operator.operator_id}")
    print(f"  role:           {who.operator.role.value}")
    print(f"  active:         {'yes' if who.operator.is_active else 'no'}")
    print(f"  agreement:      v={who.agreement_version_seen or '(none)'} "
          f"current={CURRENT_AGREEMENT_VERSION} "
          f"accepted_current={'yes' if who.agreement_current else 'NO — run accept'}")
    return 0


def cmd_operator_list(args: argparse.Namespace) -> int:
    from amoskys.agents.Web.argos.operators import OperatorService
    from amoskys.agents.Web.argos.storage import AssetsDB

    db_path = Path(args.db or Path.home() / ".argos" / "customer.db")
    db = AssetsDB(db_path)
    db.initialize()

    service = OperatorService(db)
    ops = service.list(include_disabled=args.include_disabled)
    if not ops:
        print("(no operators registered)")
        return 0
    print(f"{'operator_id':<38} {'email':<30} {'role':<10} {'active'}")
    print("-" * 92)
    for op in ops:
        print(f"{op.operator_id:<38} {op.email[:29]:<30} {op.role.value:<10} "
              f"{'yes' if op.is_active else 'no'}")
    return 0


def cmd_customer_verify(args: argparse.Namespace) -> int:
    service, _db = _customer_service(args)
    verified, message = service.verify_consent(args.customer_id)
    print(f"[argos customer verify] {message}")
    return 0 if verified else 1


def cmd_customer_list(args: argparse.Namespace) -> int:
    service, _db = _customer_service(args)
    customers = service.list_customers()
    if not customers:
        print("(no customers enrolled)")
        return 0
    print(f"{'customer_id':<38} {'name':<24} {'seed':<30} {'consent':<18} verified?")
    print("-" * 120)
    for c in customers:
        ver = "yes" if c.consent_verified_at_ns else "no"
        print(
            f"{c.customer_id:<38} {c.name[:23]:<24} "
            f"{c.seed[:29]:<30} {c.consent_method.value:<18} {ver}"
        )
    return 0


def cmd_customer_recon(args: argparse.Namespace) -> int:
    from amoskys.agents.Web.argos.customer import ConsentNotVerifiedError, CustomerNotFoundError

    service, _db = _customer_service(args)
    try:
        result = service.run_recon(args.customer_id)
    except ConsentNotVerifiedError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except CustomerNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(result.summary())
    return 0 if not any(r.errors for r in result.source_results) else 1


def cmd_customer_scan(args: argparse.Namespace) -> int:
    """Queue + run scans across the customer's recon'd surface.

    Requires: customer consent verified, authorized operator (ANALYST+).
    """
    from amoskys.agents.Web.argos.schedule import (
        CustomerConsentRequiredError,
        ScanScheduler,
    )
    from amoskys.agents.Web.argos.storage import AssetsDB, OperatorRole

    db_path = Path(args.db or Path.home() / ".argos" / "customer.db")
    db = AssetsDB(db_path)
    db.initialize()

    op, _svc = _resolve_operator(args, db, OperatorRole.ANALYST)

    report_dir = Path(args.report_dir or Path.home() / ".argos" / "customer-scans")
    scheduler = ScanScheduler(
        db=db,
        operator=op,
        report_dir=report_dir,
        tool_bundle=args.tool_bundle,
    )

    try:
        queue = scheduler.queue_surface(args.customer_id)
    except CustomerConsentRequiredError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except LookupError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    progress_pre = scheduler.progress(queue.queue_id)
    print(f"[argos customer scan] queue {queue.queue_id}")
    print(f"[argos customer scan] operator: {op.email} (role={op.role.value})")
    print(f"[argos customer scan] tool_bundle: {queue.tool_bundle}")
    print(f"[argos customer scan] jobs queued: {progress_pre.total} "
          f"(skipped_pre_run: {progress_pre.skipped})")
    print(f"[argos customer scan] running synchronously...")

    if args.dry_run:
        print("[argos customer scan] --dry-run: not executing; queue created only.")
        print()
        print(progress_pre.render())
        return 0

    try:
        progress = scheduler.run_all(queue.queue_id)
    except CustomerConsentRequiredError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    print()
    print(progress.render())
    print()
    print(f"[argos customer scan] inspect with: "
          f"argos customer scan-status {queue.queue_id}")
    return 0 if progress.failed == 0 else 1


def cmd_customer_scan_status(args: argparse.Namespace) -> int:
    """Show the state of a scan queue + its jobs."""
    from amoskys.agents.Web.argos.schedule import ScanScheduler
    from amoskys.agents.Web.argos.storage import AssetsDB, Operator, OperatorRole

    db_path = Path(args.db or Path.home() / ".argos" / "customer.db")
    db = AssetsDB(db_path)
    db.initialize()

    queue = db.get_scan_queue(args.queue_id)
    if queue is None:
        print(f"error: no scan_queue with id {args.queue_id!r}", file=sys.stderr)
        return 2

    # We don't authorize for read-only inspection; anyone with DB access
    # can view. (Writes still require operator auth via the scheduler.)
    op_for_display = db.get_operator(queue.operator_id)
    op_email = op_for_display.email if op_for_display else "(unknown)"

    jobs = db.list_scan_jobs(queue.queue_id)
    counts = db.scan_queue_status_counts(queue.queue_id)
    total_findings = sum(j.findings_count for j in jobs)

    print(f"queue:          {queue.queue_id}")
    print(f"  customer:     {queue.customer_id}")
    print(f"  operator:     {op_email}")
    print(f"  tool_bundle:  {queue.tool_bundle}")
    print(f"  created:      {queue.created_at_ns}")
    print(f"  completed:    {queue.completed_at_ns or '(in progress)'}")
    print(f"  jobs:         total={queue.total_jobs or len(jobs)}")
    for status in ("pending", "running", "complete", "failed", "skipped"):
        n = counts.get(status, 0)
        if n:
            print(f"    {status}: {n}")
    print(f"  findings:     {total_findings}")

    if jobs:
        print()
        print(f"{'asset':<40} {'kind':<10} {'status':<10} {'findings':>8}  note")
        print("-" * 90)
        for j in jobs:
            note = j.skip_reason or j.error or ""
            print(
                f"{j.asset_value[:39]:<40} {j.asset_kind:<10} {j.status:<10} "
                f"{j.findings_count:>8}  {note[:40]}"
            )
    return 0


def cmd_customer_surface(args: argparse.Namespace) -> int:
    from amoskys.agents.Web.argos.storage import AssetKind

    service, _db = _customer_service(args)
    service._require_customer(args.customer_id)

    if args.kind:
        try:
            kinds = [AssetKind(args.kind)]
        except ValueError:
            print(
                f"error: unknown kind {args.kind!r}. "
                f"available: {', '.join(k.value for k in AssetKind)}",
                file=sys.stderr,
            )
            return 2
    else:
        kinds = list(AssetKind)

    total = 0
    for kind in kinds:
        assets = service.db.list_assets(args.customer_id, kind=kind)
        if not assets:
            continue
        print(f"\n── {kind.value} ({len(assets)}) ──")
        for a in assets:
            parent = a.metadata.get("parent_value")
            extra = f" ← {parent}" if parent else ""
            print(f"  {a.value:<40} [conf={a.confidence:.2f} via {a.source}]{extra}")
        total += len(assets)

    print(f"\ntotal: {total} assets")
    return 0


def cmd_hunt(args: argparse.Namespace) -> int:
    """Run a corpus-wide AST sweep for bug-bounty candidates.

    Hunt is internal AMOSKYS tooling. Requires an authorized operator
    (registered + accepted current agreement + role ≥ analyst).
    """
    from amoskys.agents.Web.argos.hunt import Hunt
    from amoskys.agents.Web.argos.storage import AssetsDB, OperatorRole

    slugs = None
    if args.slugs:
        slugs = [s.strip() for s in args.slugs.split(",") if s.strip()]

    if not slugs and not args.top:
        print("error: hunt requires --slugs OR --top", file=sys.stderr)
        return 2

    # Authorize — hunt is operator-gated. Analyst+ role required.
    db_path = Path(args.db or Path.home() / ".argos" / "customer.db")
    db = AssetsDB(db_path)
    db.initialize()
    op, _svc = _resolve_operator(args, db, OperatorRole.ANALYST)

    hunt = Hunt(
        slugs=slugs,
        top_n=args.top,
        min_installs=args.min_installs,
        limit=args.limit,
        report_dir=Path(args.report_dir).expanduser().resolve(),
        operator_id=op.operator_id,
        operator_email=op.email,
        db=db,
    )
    print(f"[argos hunt] {hunt.hunt_id}")
    print(f"[argos hunt] operator: {op.email} (role={op.role.value})")
    if slugs:
        print(f"[argos hunt] slugs: {slugs}")
    if args.top:
        print(f"[argos hunt] top-n by installs: n={args.top} min_installs={args.min_installs}")
    print(f"[argos hunt] limit: {hunt.limit}")
    print(f"[argos hunt] scanners: {[s.scanner_id for s in hunt.scanners]}")
    print(f"[argos hunt] working...")

    result = hunt.run()
    print()
    print(result.summary())
    print()
    print(f"[argos hunt] JSON report: {hunt.report_dir}/hunt-{result.hunt_id}.json")
    return 0 if not result.errors else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="argos",
        description="AMOSKYS Argos — autonomous offensive agent",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="run an engagement against a target")
    scan.add_argument("target", help="target domain (e.g., lab.amoskys.com)")
    scan.add_argument(
        "--tools",
        default="wp-full-ast",
        help="comma-separated tool names (default: wp-full-ast)",
    )
    scan.add_argument("--report-dir", default="./argos-reports")
    scan.add_argument("--authorized-by", help="operator identity (email)")
    scan.add_argument("--txt-token", help="DNS TXT proof token")
    scan.add_argument("--max-rps", type=int, default=5)
    scan.add_argument("--max-duration", type=int, default=3600)
    scan.add_argument(
        "--skip-dns-verify",
        action="store_true",
        help="DEV/LAB ONLY: skip the DNS-TXT ownership verification step. "
             "Never use this for customer engagements.",
    )
    scan.set_defaults(func=cmd_scan)

    hunt = sub.add_parser(
        "hunt",
        help="corpus-wide AST sweep over wp.org plugin source (bug bounty mode)",
    )
    hunt.add_argument(
        "--slugs",
        default=None,
        help="comma-separated plugin slugs to scan (latest version each)",
    )
    hunt.add_argument(
        "--top",
        type=int,
        default=None,
        help="fetch top-N plugins by install count and scan them",
    )
    hunt.add_argument(
        "--min-installs",
        type=int,
        default=1000,
        help="ignore plugins below this install count (default: 1000)",
    )
    hunt.add_argument(
        "--limit",
        type=int,
        default=500,
        help="hard cap on total plugins scanned (default: 500)",
    )
    hunt.add_argument(
        "--report-dir",
        default=str(Path.home() / ".argos" / "hunts"),
        help="where to write hunt JSON reports",
    )
    hunt.add_argument(
        "--operator",
        default=None,
        help="operator email or id (overrides ARGOS_OPERATOR env var). "
             "Required — hunt mode is restricted to registered AMOSKYS operators.",
    )
    hunt.add_argument(
        "--db",
        default=None,
        help="path to operator DB (default: ~/.argos/customer.db). "
             "Used to authorize and audit the hunt.",
    )
    hunt.set_defaults(func=cmd_hunt)

    report = sub.add_parser("report", help="render an engagement JSON as branded HTML + PDF")
    report.add_argument("engagement_json", help="path to the argos-<uuid>.json engagement report")
    report.add_argument("--out-dir", default=".", help="where to write the rendered files")
    report.add_argument("--html-only", action="store_true", help="skip PDF render (HTML only)")
    report.set_defaults(func=cmd_report)

    # ── customer subcommands ────────────────────────────────────────
    customer = sub.add_parser(
        "customer",
        help="customer lifecycle (enroll, verify consent, run recon, list surface)",
    )
    customer_sub = customer.add_subparsers(dest="customer_cmd", required=True)

    def _add_db_arg(p):
        p.add_argument(
            "--db",
            default=None,
            help=f"path to customer DB (default: ~/.argos/customer.db)",
        )

    enroll = customer_sub.add_parser("enroll", help="enroll a new customer")
    enroll.add_argument("--name", required=True, help="customer display name")
    enroll.add_argument("--seed", required=True,
                        help="starting domain or IP (e.g., acme.com)")
    enroll.add_argument(
        "--consent-method",
        choices=["dns_txt", "email", "signed_contract", "lab_self"],
        default="dns_txt",
    )
    enroll.add_argument(
        "--artifact-ref",
        default=None,
        help="required for email/signed_contract methods. Format: TYPE=VALUE "
             "(e.g. docusign_envelope=abc123, contract_number=PS-2026-042, "
             "email_message_id=<foo@bar>)",
    )
    _add_db_arg(enroll)
    enroll.set_defaults(func=cmd_customer_enroll)

    verify = customer_sub.add_parser("verify", help="verify customer consent")
    verify.add_argument("customer_id")
    _add_db_arg(verify)
    verify.set_defaults(func=cmd_customer_verify)

    clist = customer_sub.add_parser("list", help="list enrolled customers")
    _add_db_arg(clist)
    clist.set_defaults(func=cmd_customer_list)

    recon = customer_sub.add_parser(
        "recon",
        help="discover the customer's external attack surface (requires verified consent)",
    )
    recon.add_argument("customer_id")
    _add_db_arg(recon)
    recon.set_defaults(func=cmd_customer_recon)

    surface = customer_sub.add_parser(
        "surface", help="show the surface assets discovered for a customer"
    )
    surface.add_argument("customer_id")
    surface.add_argument(
        "--kind",
        default=None,
        help="filter by asset kind (domain, subdomain, ipv4, ipv6, asn, netblock, ...)",
    )
    _add_db_arg(surface)
    surface.set_defaults(func=cmd_customer_surface)

    scan = customer_sub.add_parser(
        "scan",
        help="queue + run Engagements across every in-scope surface asset "
             "(requires authorized operator, analyst+)",
    )
    scan.add_argument("customer_id")
    scan.add_argument(
        "--tool-bundle",
        default="wp-full-ast",
        help="tool bundle (see TOOL_REGISTRY). Default: wp-full-ast",
    )
    scan.add_argument(
        "--report-dir",
        default=None,
        help="where to write per-engagement artifacts (default: ~/.argos/customer-scans)",
    )
    scan.add_argument(
        "--operator",
        default=None,
        help="operator email or id (overrides ARGOS_OPERATOR)",
    )
    scan.add_argument(
        "--dry-run",
        action="store_true",
        help="create the queue + jobs but don't execute — useful for reviewing "
             "which assets are in-scope before spending probe budget",
    )
    _add_db_arg(scan)
    scan.set_defaults(func=cmd_customer_scan)

    scan_status = customer_sub.add_parser(
        "scan-status",
        help="inspect a scan queue (read-only; no operator auth required)",
    )
    scan_status.add_argument("queue_id")
    _add_db_arg(scan_status)
    scan_status.set_defaults(func=cmd_customer_scan_status)

    # ── operator subcommands ────────────────────────────────────────
    operator = sub.add_parser(
        "operator",
        help="AMOSKYS operator lifecycle (register, accept agreement, whoami, list)",
    )
    operator_sub = operator.add_subparsers(dest="operator_cmd", required=True)

    op_register = operator_sub.add_parser("register", help="register a new operator")
    op_register.add_argument("--email", required=True)
    op_register.add_argument("--name", required=True)
    op_register.add_argument(
        "--role",
        choices=["admin", "analyst", "viewer"],
        default="analyst",
    )
    op_register.add_argument(
        "--accept-agreement",
        action="store_true",
        help="show + auto-accept the current operator agreement in one step",
    )
    _add_db_arg(op_register)
    op_register.set_defaults(func=cmd_operator_register)

    op_accept = operator_sub.add_parser(
        "accept", help="accept (or re-accept) the current operator agreement"
    )
    op_accept.add_argument("--operator", required=True, help="email or operator id")
    op_accept.add_argument(
        "--yes", action="store_true",
        help="skip interactive 'I AGREE' prompt (for scripted onboarding)",
    )
    _add_db_arg(op_accept)
    op_accept.set_defaults(func=cmd_operator_accept)

    op_whoami = operator_sub.add_parser(
        "whoami", help="show the current operator + agreement status"
    )
    op_whoami.add_argument(
        "--operator", default=None,
        help="email or id; defaults to $ARGOS_OPERATOR",
    )
    _add_db_arg(op_whoami)
    op_whoami.set_defaults(func=cmd_operator_whoami)

    op_list = operator_sub.add_parser("list", help="list registered operators")
    op_list.add_argument(
        "--include-disabled", action="store_true",
        help="include disabled operators in the listing",
    )
    _add_db_arg(op_list)
    op_list.set_defaults(func=cmd_operator_list)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
