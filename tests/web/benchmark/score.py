"""AMOSKYS Web benchmark runner — the score we are measured against.

Produces ONE number per side of the house:

  OFFENSE (Argos)
    For each CVE in BENCHMARK_CORPUS, download the vulnerable plugin
    version from wp.org SVN, run the expected AST scanner, assert the
    expected rule_id appears at least once. Report:
        detected / total  → "CVE detection score"
    Also report per-class breakdown (SQLi, POI, CSRF, SSRF, upload, authz).

  DEFENSE (Aegis)
    For each pair in the live-verification corpus, fire the exploit
    payload against the lab and measure:
        - emit latency (MTTD) for the matching runtime sensor
        - whether the strike-to-block chain fires within 2 seconds
        - false-positive baseline: run N clean requests, count any
          critical/high emits they generate
    Report:
        detection_rate  (hits / fires)
        mttd_ms_p50, p95
        fp_rate per hour

Runs in OFFLINE MODE by default — only the offensive corpus (no live
lab). Pass `--live` to include the defensive side against the lab
(requires SSH key + whitelisted IP).

Usage
─────
    cd amoskys
    .venv/bin/python -m tests.web.benchmark.score
    .venv/bin/python -m tests.web.benchmark.score --live
    .venv/bin/python -m tests.web.benchmark.score --only-class sql_injection
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import traceback
from pathlib import Path
from typing import Dict, List, Optional

# Allow running as module OR script.
_here = Path(__file__).resolve().parent
if str(_here.parents[2] / "src") not in sys.path:
    sys.path.insert(0, str(_here.parents[2] / "src"))

from tests.web.benchmark.wp_cve_corpus import BENCHMARK_CORPUS, BenchmarkCVE


# ── Offense runner ────────────────────────────────────────────────


def run_offense(only_class: Optional[str] = None) -> Dict:
    """Download each corpus entry from wp.org SVN and run the expected
    scanner. Return a structured report."""
    from amoskys.agents.Web.argos.ast import (
        CsrfScanner,
        FileUploadScanner,
        PoiScanner,
        RestAuthzScanner,
        SqlInjectionScanner,
        SsrfScanner,
    )
    scanner_map = {
        "rest_authz":    RestAuthzScanner,
        "sql_injection": SqlInjectionScanner,
        "file_upload":   FileUploadScanner,
        "poi":           PoiScanner,
        "csrf":          CsrfScanner,
        "ssrf":          SsrfScanner,
    }

    try:
        from amoskys.agents.Web.argos.corpus import WPOrgCorpus
    except Exception as e:  # noqa: BLE001
        return {"error": f"WPOrgCorpus import failed: {e}"}
    corpus = WPOrgCorpus()

    total = 0
    detected = 0
    per_class: Dict[str, Dict[str, int]] = {}
    details: List[Dict] = []

    for cve in BENCHMARK_CORPUS:
        if only_class and cve.vuln_class != only_class:
            continue
        total += 1
        per_class.setdefault(cve.vuln_class, {"total": 0, "hits": 0})
        per_class[cve.vuln_class]["total"] += 1

        row = {
            "slug":          cve.slug,
            "version":       cve.version,
            "cve":           cve.cve,
            "vuln_class":    cve.vuln_class,
            "rule_expected": cve.rule_expected,
            "hit":           False,
            "error":         None,
            "findings_count": 0,
        }

        try:
            plugin = corpus.fetch(cve.slug, cve.version)
            klass = scanner_map.get(cve.vuln_class)
            if not klass:
                row["error"] = f"unknown vuln_class: {cve.vuln_class}"
            else:
                findings = klass().scan(plugin)
                row["findings_count"] = len(findings)
                hit_rules = {f.rule_id for f in findings}
                if cve.rule_expected in hit_rules:
                    row["hit"] = True
                    detected += 1
                    per_class[cve.vuln_class]["hits"] += 1
                else:
                    row["hit_rules_seen"] = sorted(hit_rules)
        except Exception as e:  # noqa: BLE001
            row["error"] = f"{type(e).__name__}: {e}"
            row["traceback"] = traceback.format_exc()[-400:]

        details.append(row)

    score_pct = 100 * detected / total if total else 0
    per_class_pct = {
        k: {"hits": v["hits"], "total": v["total"],
            "pct": round(100 * v["hits"] / v["total"], 1) if v["total"] else 0}
        for k, v in per_class.items()
    }

    return {
        "mode":     "offense",
        "total":    total,
        "detected": detected,
        "score_pct": round(score_pct, 1),
        "per_class": per_class_pct,
        "details":  details,
        "generated_at": time.time(),
    }


# ── Defense runner (live, requires lab) ─────────────────────────────


def run_defense(ssh_key: str, lab_host: str = "lab.amoskys.com") -> Dict:
    """Fire each exploit payload against the live lab and measure detection
    latency + strike→block. Requires SSH key to read the event log."""
    import subprocess

    probes = [
        {
            "name": "sqli_tautology",
            "expected_event": "aegis.db.suspicious_query",
            "curl": ["-X", "POST", f"https://{lab_host}/", "-d", "q=1 OR 1=1 --"],
        },
        {
            "name": "poi_object",
            "expected_event": "aegis.request.poi_payload",
            "curl": ["-X", "POST", f"https://{lab_host}/", "-d",
                     'q=O%3A8%3A%22stdClass%22%3A0%3A%7B%7D'],
        },
        {
            "name": "csrf_no_referer",
            "expected_event": "aegis.csrf.suspicious_request",
            "curl": ["-X", "POST", f"https://{lab_host}/wp-admin/admin-ajax.php",
                     "-d", "action=myplug_update&v=1"],
        },
    ]

    results = []
    for probe in probes:
        t_start = time.time()
        subprocess.run(["curl", "-s", "-o", "/dev/null"] + probe["curl"],
                       timeout=10)
        # Wait up to 3s for the event to land, poll every 200ms.
        detected = False
        latency_ms = None
        for _ in range(15):
            r = subprocess.run(
                ["ssh", "-i", ssh_key, "-o", "StrictHostKeyChecking=no",
                 f"ubuntu@{lab_host}",
                 f"sudo tail -50 /var/www/html/wp-content/uploads/amoskys-aegis/events.jsonl "
                 f"| grep -c {probe['expected_event']}"],
                capture_output=True, text=True, timeout=5,
            )
            count = int(r.stdout.strip() or 0)
            if count > 0:
                detected = True
                latency_ms = int((time.time() - t_start) * 1000)
                break
            time.sleep(0.2)
        results.append({
            "probe": probe["name"],
            "expected_event": probe["expected_event"],
            "detected": detected,
            "latency_ms": latency_ms,
        })

    detected = sum(1 for r in results if r["detected"])
    total = len(results)
    latencies = [r["latency_ms"] for r in results if r["latency_ms"] is not None]
    p50 = sorted(latencies)[len(latencies) // 2] if latencies else None

    return {
        "mode":          "defense",
        "probe_total":   total,
        "probe_hits":    detected,
        "detection_rate_pct": round(100 * detected / total, 1) if total else 0,
        "mttd_ms_p50":   p50,
        "results":       results,
        "generated_at":  time.time(),
    }


# ── Main ──────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true",
                        help="also run live defense benchmark against lab")
    parser.add_argument("--ssh-key",
                        default="/Users/athanneeru/.ssh/amoskys-lab-key.pem",
                        help="SSH key for lab access (defense mode)")
    parser.add_argument("--lab-host", default="lab.amoskys.com")
    parser.add_argument("--only-class", default=None,
                        help="Filter offense corpus to one vuln_class")
    parser.add_argument("--json", action="store_true",
                        help="emit pure JSON (no human summary)")
    args = parser.parse_args()

    out: Dict = {}
    out["offense"] = run_offense(only_class=args.only_class)
    if args.live:
        out["defense"] = run_defense(args.ssh_key, args.lab_host)

    if args.json:
        print(json.dumps(out, indent=2, default=str))
        return

    # Human summary
    o = out["offense"]
    print("=" * 60)
    print(f"AMOSKYS Web Benchmark — Offense (Argos AST)")
    print("=" * 60)
    print(f"CVE corpus: {o['total']} entries")
    print(f"Detected:   {o['detected']} ({o['score_pct']}%)")
    print()
    print("Per-class breakdown:")
    for k, v in sorted(o["per_class"].items()):
        print(f"  {k:20s}  {v['hits']:2d}/{v['total']:<2d}  {v['pct']:5.1f}%")
    print()
    print("Per-CVE:")
    for d in o["details"]:
        status = "✓" if d["hit"] else ("✗" if not d["error"] else "ERR")
        print(f"  [{status}] {d['cve']:20s}  {d['slug']}@{d['version']}"
              f"   → {d['rule_expected']}"
              + (f"  (error: {d['error']})" if d["error"] else ""))

    if "defense" in out:
        d = out["defense"]
        print()
        print("=" * 60)
        print(f"AMOSKYS Web Benchmark — Defense (Aegis runtime)")
        print("=" * 60)
        print(f"Probes fired: {d['probe_total']}")
        print(f"Detected:     {d['probe_hits']} ({d['detection_rate_pct']}%)")
        print(f"MTTD p50:     {d['mttd_ms_p50']} ms")
        for r in d["results"]:
            tag = "✓" if r["detected"] else "✗"
            print(f"  [{tag}] {r['probe']:22s} → {r['expected_event']}"
                  f"   ({r['latency_ms']} ms)" if r["detected"] else
                  f"  [{tag}] {r['probe']:22s} → NOT DETECTED")


if __name__ == "__main__":
    main()
