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
from amoskys.agents.Web.argos.tools import NucleiTool, WPScanTool


TOOL_REGISTRY = {
    "nuclei-cves": lambda: NucleiTool(category="cves"),
    "nuclei-misconfig": lambda: NucleiTool(category="misconfiguration"),
    "nuclei-exposures": lambda: NucleiTool(category="exposures"),
    "nuclei-vulnerabilities": lambda: NucleiTool(category="vulnerabilities"),
    "wpscan": lambda: WPScanTool(),
}


def cmd_scan(args: argparse.Namespace) -> int:
    tool_names = [t.strip() for t in args.tools.split(",") if t.strip()]
    tools = []
    for name in tool_names:
        builder = TOOL_REGISTRY.get(name)
        if not builder:
            print(f"error: unknown tool '{name}'. available: {list(TOOL_REGISTRY)}", file=sys.stderr)
            return 2
        tools.append(builder())

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

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
