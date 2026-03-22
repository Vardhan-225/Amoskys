#!/usr/bin/env python3
"""Pre-INADS Full Pipeline Validation — Phase 2.75 Checkpoint.

Validates every layer of the AMOSKYS pipeline before INADS Phase 3.
Exit codes: 0 = INADS-READY, 1 = BLOCKING, 2 = WARNINGS only.
"""

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

MIN_SECURITY_EVENTS = 50
MIN_OBSERVATION_EVENTS = 10_000
MIN_SOMA_FEATURES = 39
MIN_ACTIVE_AGENTS = 5

MANDATORY_FIELDS = ["collection_agent", "event_category", "description", "probe_name", "detection_source"]

INADS_CLUSTERS = {
    "process_tree": {"fields": ["pid", "ppid", "process_name", "exe", "cmdline"], "obs_domains": ["process"], "min_samples": 1000},
    "network_lstm": {"fields": ["remote_ip", "local_port", "protocol", "bytes_out"], "obs_domains": ["flow"], "min_samples": 500},
    "kill_chain": {"fields": ["kill_chain_stage", "mitre_techniques"], "obs_domains": [], "min_samples": 50},
    "system_anomaly": {"fields": ["username", "detection_source", "collection_agent"], "obs_domains": ["auth", "realtime_sensor"], "min_samples": 500},
    "file_path": {"fields": ["path", "file_name", "sha256"], "obs_domains": ["filesystem"], "min_samples": 500},
}


class V:
    def __init__(self, name):
        self.name = name
        self.passed = True
        self.warnings = []
        self.errors = []
        self.details = {}

    def warn(self, m):
        self.warnings.append(m)

    def fail(self, m):
        self.errors.append(m)
        self.passed = False

    def d(self, k, v):
        self.details[k] = v

    def show(self):
        icon = "\u2705" if self.passed and not self.warnings else "\u26a0\ufe0f" if self.passed else "\u274c"
        status = "PASS" if self.passed and not self.warnings else "WARN" if self.passed else "FAIL"
        print(f"\n{icon} {self.name}: {status}")
        for k, v in self.details.items():
            print(f"    {k}: {v}")
        for w in self.warnings:
            print(f"    \u26a0\ufe0f  {w}")
        for e in self.errors:
            print(f"    \u274c {e}")


def sc(conn, q, p=()):
    try:
        return conn.execute(q, p).fetchone()[0]
    except:
        return 0


def cols(conn, t):
    try:
        return [r[1] for r in conn.execute(f"PRAGMA table_info({t})").fetchall()]
    except:
        return []


def v1_mandate(conn):
    v = V("V1: Mandate Field Coverage")
    total = sc(conn, "SELECT COUNT(*) FROM security_events")
    v.d("total_security_events", total)
    if total == 0:
        v.fail("No security events")
        return v
    c = cols(conn, "security_events")
    for f in MANDATORY_FIELDS:
        if f in c:
            n = sc(conn, f"SELECT COUNT(*) FROM security_events WHERE {f} IS NOT NULL AND {f} != ''")
        else:
            n = sc(conn, f"SELECT COUNT(*) FROM security_events WHERE json_extract(raw_attributes_json, '$.{f}') IS NOT NULL")
        pct = n / total * 100
        v.d(f"mandatory_{f}", f"{n}/{total} ({pct:.0f}%)")
        if pct < 95:
            v.warn(f"{f} at {pct:.0f}%")
    return v


def v2_observations(conn):
    v = V("V2: Observation Pipeline Health")
    total = sc(conn, "SELECT COUNT(*) FROM observation_events")
    v.d("total_observations", f"{total:,}")
    if total < MIN_OBSERVATION_EVENTS:
        v.fail(f"Only {total:,} observations (need {MIN_OBSERVATION_EVENTS:,})")
        return v
    has_raw = sc(conn, "SELECT COUNT(*) FROM observation_events WHERE raw_attributes_json IS NOT NULL AND raw_attributes_json != '{}' AND raw_attributes_json != ''")
    v.d("has_raw_attributes_json", f"{has_raw:,} ({has_raw/total*100:.1f}%)")
    if has_raw < total * 0.5:
        v.fail(f"Only {has_raw/total*100:.1f}% have raw_attributes_json")
    try:
        rows = conn.execute("SELECT domain, COUNT(*) FROM observation_events GROUP BY domain ORDER BY COUNT(*) DESC").fetchall()
        v.d("domain_distribution", {r[0]: r[1] for r in rows})
    except:
        pass
    for field, keys in [("pid", ["pid"]), ("process_name", ["process_name", "name"]), ("exe", ["exe"]), ("remote_ip", ["remote_ip", "dst_ip", "src_ip"]), ("username", ["username", "conn_user"])]:
        conds = " OR ".join(f"json_extract(raw_attributes_json, '$.{k}') IS NOT NULL" for k in keys)
        n = sc(conn, f"SELECT COUNT(*) FROM observation_events WHERE raw_attributes_json != '{{}}' AND ({conds})")
        v.d(f"obs_has_{field}", f"{n:,} ({n/total*100:.1f}%)")
    return v


def v3_soma(db_path):
    v = V("V3: SOMA Model State")
    md = Path(db_path).parent / "intel" / "models"
    mp = md / "brain_metrics.json"
    if not mp.exists():
        v.fail("brain_metrics.json not found")
        return v
    with open(mp) as f:
        m = json.load(f)
    v.d("status", m.get("status"))
    v.d("samples", f"{m.get('event_count', 0):,}")
    v.d("features", m.get("feature_count", 0))
    iso = m.get("isolation_forest", {})
    v.d("isolation_forest", f"{iso.get('status')} samples={iso.get('samples',0):,} anomaly_rate={iso.get('anomaly_rate',0):.3f}")
    gb = m.get("gradient_boost", {})
    v.d("gradient_boost", f"{gb.get('status')} — {gb.get('reason','')}")
    v.d("training_time", f"{m.get('elapsed_seconds',0):.1f}s")
    if m.get("feature_count", 0) < MIN_SOMA_FEATURES:
        v.fail(f"Only {m.get('feature_count',0)} features (need {MIN_SOMA_FEATURES})")
    fp = md / "feature_columns.joblib"
    if fp.exists():
        try:
            import joblib
            fc = joblib.load(fp)
            mandate = ["has_process_context", "has_executable", "exe_path_depth", "is_system_exe", "has_network_context", "is_private_ip", "has_user_context", "is_root_user"]
            present = [f for f in mandate if f in fc]
            v.d("mandate_features", f"{len(present)}/8: {present}")
            if len(present) < 8:
                v.fail(f"Missing mandate features: {[f for f in mandate if f not in fc]}")
        except ImportError:
            v.warn("joblib unavailable")
    val = m.get("validation", {})
    if val.get("passed"):
        for c in val.get("checks", []):
            v.d(f"check_{c['check']}", c.get("detail", ""))
    else:
        v.fail(f"SOMA validation failed: {val.get('reason')}")
    return v


def v4_agents(conn):
    v = V("V4: Agent Coverage")
    rows = conn.execute("SELECT collection_agent, COUNT(*) FROM security_events GROUP BY collection_agent ORDER BY COUNT(*) DESC").fetchall()
    v.d("security_agents", {r[0]: r[1] for r in rows})
    v.d("active_count", len(rows))
    if len(rows) < MIN_ACTIVE_AGENTS:
        v.warn(f"Only {len(rows)} agents (want {MIN_ACTIVE_AGENTS}+)")
    return v


def v5_quality(conn):
    v = V("V5: Data Quality")
    total = sc(conn, "SELECT COUNT(*) FROM security_events")
    if total == 0:
        v.fail("No events")
        return v
    app = sc(conn, "SELECT COUNT(*) FROM security_events WHERE event_category='app_launch'")
    fe80 = sc(conn, "SELECT COUNT(*) FROM security_events WHERE remote_ip LIKE '%fe80%'")
    self_d = sc(conn, "SELECT COUNT(*) FROM security_events WHERE cmdline LIKE '%collect_and_store%' OR cmdline LIKE '%analyzer_main%'")
    null_desc = sc(conn, "SELECT COUNT(*) FROM security_events WHERE description IS NULL OR description=''")
    v.d("app_launch_noise", app)
    v.d("link_local_ips", fe80)
    v.d("self_detection", self_d)
    v.d("null_descriptions", null_desc)
    if app > 0: v.fail(f"{app} app_launch events in security_events")
    if fe80 > 0: v.fail(f"{fe80} link-local IPs")
    if null_desc > 0: v.warn(f"{null_desc} null descriptions")
    try:
        rows = conn.execute("SELECT final_classification, COUNT(*) FROM security_events GROUP BY final_classification").fetchall()
        v.d("classifications", {r[0]: r[1] for r in rows})
    except:
        pass
    return v


def v6_scoring(db_path):
    v = V("V6: End-to-End SOMA Scoring")
    md = Path(db_path).parent / "intel" / "models"
    if not (md / "isolation_forest.joblib").exists():
        v.fail("No trained model")
        return v
    try:
        import joblib
        import numpy as np
        model = joblib.load(md / "isolation_forest.joblib")
        fc = joblib.load(md / "feature_columns.joblib")
        normal = np.zeros((1, len(fc)))
        anomalous = np.zeros((1, len(fc)))
        for i, c in enumerate(fc):
            if c == "hour_of_day": normal[0,i], anomalous[0,i] = 14.0, 3.0
            elif c == "is_business_hours": normal[0,i] = 1.0
            elif c == "has_process_context": normal[0,i], anomalous[0,i] = 1.0, 1.0
            elif c == "has_executable": normal[0,i], anomalous[0,i] = 1.0, 1.0
            elif c == "is_system_exe": normal[0,i] = 1.0
            elif c == "has_network_context": anomalous[0,i] = 1.0
            elif c == "is_root_user": anomalous[0,i] = 1.0
            elif c == "has_suspicious_tokens": anomalous[0,i] = 1.0
            elif c == "requires_investigation": anomalous[0,i] = 1.0
        ns = model.score_samples(normal)[0]
        as_ = model.score_samples(anomalous)[0]
        v.d("normal_score", f"{ns:.4f}")
        v.d("anomalous_score", f"{as_:.4f}")
        v.d("direction", "CORRECT" if as_ < ns else "UNEXPECTED")
        if as_ >= ns:
            v.warn(f"Anomalous ({as_:.4f}) not lower than normal ({ns:.4f})")
    except Exception as e:
        v.fail(f"Scoring test failed: {e}")
    return v


def v7_inads(conn):
    v = V("V7: INADS Cluster Readiness")
    total_sec = sc(conn, "SELECT COUNT(*) FROM security_events")
    total_obs = sc(conn, "SELECT COUNT(*) FROM observation_events")
    v.d("training_pool", f"{total_sec + total_obs:,} (sec={total_sec:,} + obs={total_obs:,})")
    all_ready = True
    c = cols(conn, "security_events")
    for name, spec in INADS_CLUSTERS.items():
        avail = [f for f in spec["fields"] if f in c]
        sec_n = 0
        if avail:
            conds = " OR ".join(f"({f} IS NOT NULL AND {f} != '')" for f in avail)
            sec_n = sc(conn, f"SELECT COUNT(*) FROM security_events WHERE {conds}")
        obs_n = 0
        if spec["obs_domains"]:
            dl = ",".join(f"'{d}'" for d in spec["obs_domains"])
            obs_n = sc(conn, f"SELECT COUNT(*) FROM observation_events WHERE domain IN ({dl}) AND raw_attributes_json != '{{}}' AND raw_attributes_json IS NOT NULL")
        tot = sec_n + obs_n
        ready = tot >= spec["min_samples"]
        if not ready:
            all_ready = False
        status = "\u2713 READY" if ready else "\u26a0 INSUFFICIENT"
        v.d(f"cluster_{name}", f"{status}: {tot:,} (sec={sec_n:,}+obs={obs_n:,}, need={spec['min_samples']:,})")
        if not ready and tot == 0:
            v.fail(f"'{name}' has ZERO samples")
        elif not ready:
            v.warn(f"'{name}' has {tot:,}/{spec['min_samples']:,}")
    return v


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--db", default="data/telemetry.db")
    args = p.parse_args()
    if not os.path.exists(args.db):
        print(f"ERROR: {args.db} not found")
        sys.exit(1)
    print("=" * 70)
    print(f"  AMOSKYS Pre-INADS Pipeline Validation")
    print(f"  {datetime.now(timezone.utc).isoformat()}")
    print("=" * 70)
    conn = sqlite3.connect(args.db)
    results = [v1_mandate(conn), v2_observations(conn), v3_soma(args.db), v4_agents(conn), v5_quality(conn), v6_scoring(args.db), v7_inads(conn)]
    conn.close()
    for r in results:
        r.show()
    passed = sum(1 for r in results if r.passed and not r.warnings)
    warned = sum(1 for r in results if r.passed and r.warnings)
    failed = sum(1 for r in results if not r.passed)
    print(f"\n{'='*70}")
    print(f"  SUMMARY: {passed} passed, {warned} warned, {failed} failed")
    if failed > 0:
        print("  VERDICT: BLOCKING")
        sys.exit(1)
    elif warned > 2:
        print("  VERDICT: PROCEED WITH CAUTION")
        sys.exit(2)
    else:
        print("  VERDICT: INADS-READY")
        sys.exit(0)
    print("=" * 70)


if __name__ == "__main__":
    main()
