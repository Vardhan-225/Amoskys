#!/usr/bin/env python3
"""Generate AMOSKYS agent/probe data-quality scorecard.

Outputs a CI-readable JSON report with:
- probe contract completeness
- field semantics coverage
- observation-domain lineage to canonical routers
- likely drop points before canonical storage
"""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from amoskys.observability.probe_audit import AGENT_PROBE_MAP  # noqa: E402
from amoskys.storage.wal_processor import WALProcessor  # noqa: E402


@dataclass(slots=True)
class ProbeScore:
    agent: str
    probe: str
    score: int
    drop_points: List[str]
    requires_fields: List[str]
    degraded_without: List[str]
    requires_event_types: List[str]
    field_semantics_keys: List[str]
    domain: str
    canonical_route: str


def _iter_probes() -> Iterable[Tuple[str, Any]]:
    for agent_name, info in sorted(AGENT_PROBE_MAP.items()):
        try:
            mod = importlib.import_module(info["module"])
            factory = getattr(mod, info["factory"])
            probes = factory()
            for probe in probes:
                yield agent_name, probe
        except Exception:
            # Keep report generation resilient; unresolved modules are tracked by CI elsewhere.
            continue


def _score_probe(
    agent: str, probe: Any, routers: Dict[str, str], platform: str
) -> ProbeScore:
    name = str(getattr(probe, "name", "unknown"))
    platforms = list(getattr(probe, "platforms", []) or [])
    requires_fields = list(getattr(probe, "requires_fields", []) or [])
    degraded_without = list(getattr(probe, "degraded_without", []) or [])
    requires_event_types = list(getattr(probe, "requires_event_types", []) or [])
    semantics = dict(getattr(probe, "field_semantics", {}) or {})

    domain = (
        str(semantics.get("_domain") or semantics.get("domain") or "").strip().lower()
    )
    canonical_route = routers.get(domain, "")
    missing_semantics = sorted(
        field_name for field_name in requires_fields if field_name not in semantics
    )

    drop_points: List[str] = []
    score = 100
    if platform and platforms and platform not in platforms:
        drop_points.append(f"platform_not_supported:{platform}")
        score -= 15
    if not requires_fields:
        drop_points.append("missing_requires_fields")
        score -= 30
    if missing_semantics:
        drop_points.append("missing_field_semantics")
        score -= min(25, 5 * len(missing_semantics))
    if not requires_event_types:
        drop_points.append("missing_requires_event_types")
        score -= 10
    if domain and not canonical_route:
        drop_points.append(f"unmapped_domain:{domain}")
        score -= 20
    if degraded_without:
        # Not strictly bad, but indicates partial blindness risk.
        drop_points.append("degraded_by_design")
        score -= min(10, len(degraded_without))

    score = max(0, score)
    return ProbeScore(
        agent=agent,
        probe=name,
        score=score,
        drop_points=drop_points,
        requires_fields=requires_fields,
        degraded_without=degraded_without,
        requires_event_types=requires_event_types,
        field_semantics_keys=sorted(semantics.keys()),
        domain=domain,
        canonical_route=canonical_route,
    )


def build_report(platform: str) -> Dict[str, Any]:
    routers = dict(WALProcessor._OBSERVATION_ROUTERS)
    probe_scores: List[ProbeScore] = [
        _score_probe(agent, probe, routers, platform) for agent, probe in _iter_probes()
    ]
    by_agent: Dict[str, Dict[str, Any]] = {}
    for item in probe_scores:
        agent = by_agent.setdefault(
            item.agent,
            {
                "probe_count": 0,
                "avg_score": 0.0,
                "high_risk_probes": [],
                "probes": [],
            },
        )
        agent["probe_count"] += 1
        agent["probes"].append(
            {
                "probe": item.probe,
                "score": item.score,
                "drop_points": item.drop_points,
                "requires_fields": item.requires_fields,
                "degraded_without": item.degraded_without,
                "requires_event_types": item.requires_event_types,
                "field_semantics_keys": item.field_semantics_keys,
                "domain": item.domain,
                "canonical_route": item.canonical_route,
            }
        )
        if item.score < 70 or item.drop_points:
            agent["high_risk_probes"].append(item.probe)

    total_score = 0
    for agent_payload in by_agent.values():
        probe_count = max(1, agent_payload["probe_count"])
        avg = sum(p["score"] for p in agent_payload["probes"]) / probe_count
        agent_payload["avg_score"] = round(avg, 2)
        total_score += avg

    overall_avg = round(total_score / max(1, len(by_agent)), 2)
    all_drop_points: Dict[str, int] = {}
    for item in probe_scores:
        for reason in item.drop_points:
            all_drop_points[reason] = all_drop_points.get(reason, 0) + 1

    return {
        "platform": platform or "auto",
        "total_probes": len(probe_scores),
        "agent_count": len(by_agent),
        "overall_avg_score": overall_avg,
        "drop_points": dict(
            sorted(all_drop_points.items(), key=lambda kv: (-kv[1], kv[0]))
        ),
        "observation_domain_routes": routers,
        "agents": by_agent,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="AMOSKYS agent quality scorecard")
    parser.add_argument("--platform", default="darwin", help="Target platform")
    parser.add_argument("--json", action="store_true", help="Print JSON only")
    parser.add_argument("--output", default="", help="Optional output JSON path")
    parser.add_argument(
        "--min-score",
        type=float,
        default=0.0,
        help="Fail with exit 1 if overall score is below threshold",
    )
    args = parser.parse_args()

    report = build_report(args.platform)
    payload = json.dumps(report, indent=2, sort_keys=True)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(payload + "\n", encoding="utf-8")

    if args.json:
        print(payload)
    else:
        print(f"Platform: {report['platform']}")
        print(f"Agents: {report['agent_count']}")
        print(f"Probes: {report['total_probes']}")
        print(f"Overall avg score: {report['overall_avg_score']}")
        print("Top drop points:")
        for reason, count in list(report["drop_points"].items())[:10]:
            print(f"  - {reason}: {count}")

    if args.min_score and report["overall_avg_score"] < args.min_score:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
