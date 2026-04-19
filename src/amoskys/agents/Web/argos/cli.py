"""Argos CLI entry point.

Usage:
    argos scan <target> [--report-dir PATH] [--tools nuclei,wpscan]
    argos scan lab.amoskys.com --tools nuclei-cves,wpscan

For v0 this is intentionally minimal. v1 adds:
  - Scope file loading (--scope-file scope.yaml)
  - DNS TXT verification
  - Report PDF generation
  - Proof Spine shipping
"""

from __future__ import annotations

import argparse
import sys
import time
import uuid
from pathlib import Path

from amoskys.agents.Web.argos.engine import Engagement, Scope
from amoskys.agents.Web.argos.tools import (
    HTTPXTool,
    NmapTool,
    NucleiTool,
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
    # Preset bundles
    "recon": lambda: [SubfinderTool(), NmapTool(), HTTPXTool()],
    "wp-full": lambda: [
        HTTPXTool(), WPScanTool(),
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
        default="nuclei-cves,wpscan",
        help="comma-separated tool names (default: nuclei-cves,wpscan)",
    )
    scan.add_argument("--report-dir", default="./argos-reports")
    scan.add_argument("--authorized-by", help="operator identity (email)")
    scan.add_argument("--txt-token", help="DNS TXT proof token")
    scan.add_argument("--max-rps", type=int, default=5)
    scan.add_argument("--max-duration", type=int, default=3600)
    scan.set_defaults(func=cmd_scan)

    report = sub.add_parser("report", help="render an engagement JSON as branded HTML + PDF")
    report.add_argument("engagement_json", help="path to the argos-<uuid>.json engagement report")
    report.add_argument("--out-dir", default=".", help="where to write the rendered files")
    report.add_argument("--html-only", action="store_true", help="skip PDF render (HTML only)")
    report.set_defaults(func=cmd_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
