#!/usr/bin/env python3
"""Manual validation harness for _rescore_fleet_db (fleet-DB re-scoring mode).

Proves the analyzer ("the brain") can score events in a Command-Center fleet DB
in place:
  1. Builds a throwaway fixture DB whose security_events table matches the EXACT
     column list of production /var/lib/amoskys/fleet.db (read read-only over
     SSH; captured below). fleet.db intentionally LACKS composite_score /
     risk_score_raw / last_scored, so the fixture omits them too — exercising the
     idempotent ALTER path in _ensure_fleet_score_columns.
  2. Inserts ~15 realistic UNSCORED rows (varied event_type/process/ips, no
     composite_score).
  3. Constructs ScoringEngine + EnrichmentPipeline + FusionEngine directly (NOT
     full main()) and calls _rescore_fleet_db(fixture, ...).
  4. Asserts composite_score IS NOT NULL and final_classification populated on all
     rows, and that at least some rows get a NON-1.0 / discriminated risk
     (proving scoring actually ran — not a passthrough of the raw ~1.0 probe
     risk). Prints before/after counts.

Run (from the brain worktree root):
    PYTHONPATH=src ci-venv/bin/python tests/manual/test_fleet_rescore.py
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import time

# Exact security_events column list from production fleet.db, captured via:
#   ssh ... "python3 -c 'import sqlite3; c=sqlite3.connect(
#       \"file:/var/lib/amoskys/fleet.db?mode=ro\", uri=True);
#       print([r[1] for r in c.execute(\"PRAGMA table_info(security_events)\")])'"
# NOTE: fleet.db already has geometric/temporal/behavioral/final_classification/
# enrichment_status but is MISSING risk_score_raw, composite_score, last_scored.
FLEET_COLUMNS = [
    "id",
    "source_id",
    "device_id",
    "org_id",
    "timestamp_ns",
    "timestamp_dt",
    "event_category",
    "event_action",
    "event_outcome",
    "risk_score",
    "confidence",
    "mitre_techniques",
    "geometric_score",
    "temporal_score",
    "behavioral_score",
    "final_classification",
    "description",
    "indicators",
    "collection_agent",
    "enrichment_status",
    "threat_intel_match",
    "geo_src_country",
    "asn_src_org",
    "event_timestamp_ns",
    "event_id",
    "remote_ip",
    "process_name",
    "pid",
    "username",
    "domain",
    "path",
    "sha256",
    "probe_name",
    "detection_source",
    "cmdline",
    "exe",
    "remote_port",
    "protocol",
    "geo_src_city",
    "geo_src_latitude",
    "geo_src_longitude",
    "asn_src_number",
    "asn_src_network_type",
    "received_at",
]

# Column types mirror fleet.db: id INTEGER PK, received_at REAL epoch, scores REAL.
_COL_TYPES = {
    "id": "INTEGER PRIMARY KEY AUTOINCREMENT",
    "timestamp_ns": "INTEGER",
    "event_timestamp_ns": "INTEGER",
    "risk_score": "REAL",
    "confidence": "REAL",
    "geometric_score": "REAL",
    "temporal_score": "REAL",
    "behavioral_score": "REAL",
    "threat_intel_match": "INTEGER",
    "pid": "INTEGER",
    "remote_port": "INTEGER",
    "geo_src_latitude": "REAL",
    "geo_src_longitude": "REAL",
    "asn_src_number": "INTEGER",
    "received_at": "REAL",
}


def _create_fixture(path: str) -> None:
    """Create a fleet.db-shaped security_events table (missing the 3 score cols)."""
    cols_sql = []
    for c in FLEET_COLUMNS:
        cols_sql.append(f"{c} {_COL_TYPES.get(c, 'TEXT')}")
    conn = sqlite3.connect(path)
    conn.execute(f"CREATE TABLE security_events ({', '.join(cols_sql)})")
    conn.commit()
    conn.close()


def _insert_unscored_rows(path: str) -> int:
    """Insert ~15 realistic UNSCORED rows (no composite_score / last_scored)."""
    now_ns = time.time_ns()
    old_epoch = time.time() - 60  # 60s old -> passes the 2s race guard

    # Varied, realistic security events. Raw risk_score is the probe's stamp
    # (often ~1.0 / hardcoded) — the scorer should DISCRIMINATE these, not echo.
    rows = [
        # External C2 beacon to a hosting/VPS ASN (should score high)
        dict(
            event_category="c2_beacon_suspect",
            event_action="NETWORK",
            event_outcome="alert",
            risk_score=1.0,
            confidence=0.9,
            mitre_techniques=["T1071"],
            collection_agent="flow_agent",
            device_id="dev-lab-01",
            remote_ip="45.83.12.9",
            remote_port=443,
            process_name="curl",
            asn_src_org="DigitalOcean LLC",
            geo_src_country="RU",
        ),
        # Off-hours external SSH from external IP (should score elevated)
        dict(
            event_category="lateral_ssh",
            event_action="SSH",
            event_outcome="alert",
            risk_score=1.0,
            confidence=0.8,
            mitre_techniques=["T1021"],
            collection_agent="macos_auth",
            device_id="dev-lab-01",
            remote_ip="203.0.113.77",
            remote_port=22,
            process_name="ssh",
        ),
        # Benign local process observation (should score LOW / legitimate)
        dict(
            event_category="process_spawned",
            event_action="EXEC",
            event_outcome="observed",
            risk_score=1.0,
            confidence=0.3,
            mitre_techniques=[],
            collection_agent="proc_agent",
            device_id="dev-lab-02",
            remote_ip="",
            process_name="Finder",
            exe="/System/Library/CoreServices/Finder.app",
        ),
        # Cleartext exfil spike, external
        dict(
            event_category="exfil_spike",
            event_action="NETWORK",
            event_outcome="alert",
            risk_score=0.85,
            confidence=0.7,
            mitre_techniques=["T1048"],
            collection_agent="flow_agent",
            device_id="dev-lab-02",
            remote_ip="198.51.100.42",
            remote_port=80,
            process_name="python3",
        ),
        # Local DNS query (benign, private)
        dict(
            event_category="dns_query",
            event_action="DNS",
            event_outcome="observed",
            risk_score=1.0,
            confidence=0.2,
            mitre_techniques=[],
            collection_agent="dns_agent",
            device_id="dev-lab-03",
            domain="apple.com",
            process_name="mDNSResponder",
        ),
        # New launch agent persistence
        dict(
            event_category="macos_launchagent_new",
            event_action="PERSISTENCE",
            event_outcome="alert",
            risk_score=0.9,
            confidence=0.8,
            mitre_techniques=["T1543"],
            collection_agent="persistence_agent",
            device_id="dev-lab-03",
            path="/Users/victim/Library/LaunchAgents/com.evil.plist",
            process_name="launchd",
        ),
        # Credential harvest via keychain
        dict(
            event_category="keychain_cli_abuse",
            event_action="CREDENTIAL",
            event_outcome="alert",
            risk_score=1.0,
            confidence=0.85,
            mitre_techniques=["T1555"],
            collection_agent="infostealer_guard",
            device_id="dev-lab-01",
            process_name="security",
            cmdline="security dump-keychain",
        ),
        # High CPU crypto mining
        dict(
            event_category="high_cpu",
            event_action="EXEC",
            event_outcome="alert",
            risk_score=0.6,
            confidence=0.5,
            mitre_techniques=["T1496"],
            collection_agent="proc_agent",
            device_id="dev-lab-02",
            process_name="xmrig",
        ),
        # Benign internal flow (private->private)
        dict(
            event_category="new_external_connection",
            event_action="NETWORK",
            event_outcome="observed",
            risk_score=1.0,
            confidence=0.3,
            mitre_techniques=[],
            collection_agent="flow_agent",
            device_id="dev-lab-03",
            remote_ip="192.168.1.10",
            remote_port=445,
            process_name="smbd",
        ),
        # Sudo escalation attempt
        dict(
            event_category="sudo_escalation",
            event_action="SUDO",
            event_outcome="alert",
            risk_score=0.95,
            confidence=0.9,
            mitre_techniques=["T1548"],
            collection_agent="macos_auth",
            device_id="dev-lab-01",
            username="root",
            process_name="sudo",
            cmdline="sudo rm -rf /etc/sudoers.d",
        ),
        # Port scan detected, external
        dict(
            event_category="port_scan_detected",
            event_action="NETWORK",
            event_outcome="alert",
            risk_score=0.8,
            confidence=0.7,
            mitre_techniques=["T1046"],
            collection_agent="flow_agent",
            device_id="dev-lab-02",
            remote_ip="185.220.101.5",
            remote_port=0,
            process_name="nmap",
            asn_src_org="OVH Hosting",
        ),
        # Hidden file created (low-ish)
        dict(
            event_category="macos_hidden_file_new",
            event_action="FILE",
            event_outcome="alert",
            risk_score=0.5,
            confidence=0.4,
            mitre_techniques=["T1564"],
            collection_agent="fim_agent",
            device_id="dev-lab-03",
            path="/Users/victim/.hidden_payload",
        ),
        # Benign browser network (public but common)
        dict(
            event_category="new_external_connection",
            event_action="NETWORK",
            event_outcome="observed",
            risk_score=1.0,
            confidence=0.3,
            mitre_techniques=[],
            collection_agent="flow_agent",
            device_id="dev-lab-02",
            remote_ip="17.253.144.10",  # Apple
            remote_port=443,
            process_name="Safari",
        ),
        # Cloud exfil to external
        dict(
            event_category="cloud_exfil_detected",
            event_action="NETWORK",
            event_outcome="alert",
            risk_score=0.9,
            confidence=0.8,
            mitre_techniques=["T1567"],
            collection_agent="flow_agent",
            device_id="dev-lab-01",
            remote_ip="104.18.32.7",
            remote_port=443,
            process_name="rclone",
        ),
        # Log tampering
        dict(
            event_category="log_tampering_detected",
            event_action="FILE",
            event_outcome="alert",
            risk_score=0.85,
            confidence=0.75,
            mitre_techniques=["T1070"],
            collection_agent="fim_agent",
            device_id="dev-lab-03",
            path="/var/log/system.log",
        ),
    ]

    conn = sqlite3.connect(path)
    for i, r in enumerate(rows):
        record = {c: None for c in FLEET_COLUMNS}
        record.update(r)
        record["mitre_techniques"] = json.dumps(r.get("mitre_techniques", []))
        record["threat_intel_match"] = 0
        record["event_id"] = f"evt-{i:03d}"
        record["source_id"] = "src-1"
        record["org_id"] = "org-1"
        record["timestamp_ns"] = now_ns
        record["event_timestamp_ns"] = now_ns
        record["received_at"] = old_epoch  # old enough to clear the 2s race guard
        # Ensure the score columns that DO exist start NULL (unscored).
        record["geometric_score"] = None
        record["temporal_score"] = None
        record["behavioral_score"] = None
        record["final_classification"] = None
        record["enrichment_status"] = None

        cols = [c for c in FLEET_COLUMNS if c != "id"]
        placeholders = ",".join("?" for _ in cols)
        conn.execute(
            f"INSERT INTO security_events ({','.join(cols)}) VALUES ({placeholders})",
            [record[c] for c in cols],
        )
    conn.commit()
    n = conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
    conn.close()
    return n


def main() -> int:
    from amoskys.analyzer_main import _rescore_fleet_db
    from amoskys.enrichment import EnrichmentPipeline
    from amoskys.intel.fusion_engine import FusionEngine
    from amoskys.intel.scoring import ScoringEngine

    tmpdir = tempfile.mkdtemp(prefix="fleet_rescore_")
    fixture = os.path.join(tmpdir, "fleet_fixture.db")
    fusion_db = os.path.join(tmpdir, "fusion.db")

    _create_fixture(fixture)
    inserted = _insert_unscored_rows(fixture)
    print(f"[fixture] created {fixture}")
    print(f"[fixture] inserted {inserted} UNSCORED rows")

    # Confirm the fixture starts WITHOUT the 3 missing columns (matches fleet.db).
    conn = sqlite3.connect(fixture)
    cols_before = {r[1] for r in conn.execute("PRAGMA table_info(security_events)")}
    missing_before = [
        c
        for c in ("risk_score_raw", "composite_score", "last_scored")
        if c not in cols_before
    ]
    print(f"[before] columns missing (as in fleet.db): {missing_before}")
    assert missing_before == [
        "risk_score_raw",
        "composite_score",
        "last_scored",
    ], f"fixture should mirror fleet.db's missing cols, got {missing_before}"

    # All rows start unscored.
    unscored_before = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE final_classification IS NULL"
    ).fetchone()[0]
    print(f"[before] rows with final_classification NULL: {unscored_before}")
    conn.close()

    # Build the pipeline components DIRECTLY (not full main()).
    scorer = ScoringEngine()
    enricher = EnrichmentPipeline()
    fusion = FusionEngine(db_path=fusion_db)
    print("[pipeline] ScoringEngine + EnrichmentPipeline + FusionEngine constructed")

    n_scored = _rescore_fleet_db(fixture, scorer, enricher, fusion)
    print(f"[rescore] _rescore_fleet_db returned: {n_scored} rows scored")

    # ── Verify results ──
    conn = sqlite3.connect(fixture)
    conn.row_factory = sqlite3.Row

    cols_after = {r[1] for r in conn.execute("PRAGMA table_info(security_events)")}
    added = sorted(cols_after - cols_before)
    print(f"[after] columns ADDED by rescore: {added}")
    assert {
        "risk_score_raw",
        "composite_score",
        "last_scored",
    } <= cols_after, "rescore must have ALTERed in the missing score columns"

    total = conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
    composite_null = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE composite_score IS NULL"
    ).fetchone()[0]
    class_null = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE final_classification IS NULL"
    ).fetchone()[0]
    last_scored_null = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE last_scored IS NULL"
    ).fetchone()[0]

    print(f"[after] total rows:                          {total}")
    print(f"[after] rows with composite_score NULL:      {composite_null}")
    print(f"[after] rows with final_classification NULL: {class_null}")
    print(f"[after] rows with last_scored NULL:          {last_scored_null}")

    assert n_scored == inserted, f"expected {inserted} scored, got {n_scored}"
    assert composite_null == 0, "every row must have composite_score populated"
    assert class_null == 0, "every row must have final_classification populated"
    assert last_scored_null == 0, "every row must have last_scored populated"

    # Prove scoring DISCRIMINATED (not a passthrough of the raw ~1.0 probe risk).
    rows = conn.execute(
        "SELECT event_category, risk_score, risk_score_raw, composite_score, "
        "geometric_score, temporal_score, behavioral_score, final_classification "
        "FROM security_events ORDER BY composite_score DESC"
    ).fetchall()

    print("\n[discrimination] per-event scores (sorted by composite desc):")
    print(
        f"  {'category':<26} {'raw':>5} {'risk':>5} {'comp':>5} "
        f"{'geo':>5} {'temp':>5} {'behav':>5}  class"
    )
    classifications = set()
    composites = set()
    risks = set()
    for r in rows:
        classifications.add(r["final_classification"])
        composites.add(round(r["composite_score"], 4))
        risks.add(round(r["risk_score"], 4))
        print(
            f"  {r['event_category']:<26} "
            f"{r['risk_score_raw']:>5.2f} {r['risk_score']:>5.2f} "
            f"{r['composite_score']:>5.2f} {r['geometric_score']:>5.2f} "
            f"{r['temporal_score']:>5.2f} {r['behavioral_score']:>5.2f}  "
            f"{r['final_classification']}"
        )
    conn.close()

    # DISCRIMINATION assertions: if scoring ran (vs passthrough), we should see
    # (a) more than one distinct composite value, (b) more than one distinct
    # final risk, (c) at least one row whose reconciled risk is NOT 1.0.
    non_one_risks = [x for x in risks if x != 1.0]
    print(
        f"\n[discrimination] distinct final_classifications: {sorted(classifications)}"
    )
    print(f"[discrimination] distinct composite_score values: {len(composites)}")
    print(f"[discrimination] distinct final risk values:      {len(risks)}")
    print(f"[discrimination] rows with reconciled risk != 1.0: {len(non_one_risks)}")

    assert len(composites) > 1, (
        "composite scores are all identical — scoring did not discriminate "
        "(looks like passthrough)"
    )
    assert len(risks) > 1, "final risk values are all identical — no discrimination"
    assert non_one_risks, (
        "no row has a reconciled risk != 1.0 — the raw ~1.0 probe risk was echoed, "
        "scoring did not run"
    )

    print("\nALL ASSERTIONS PASSED — brain scored fleet.db events and discriminated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
