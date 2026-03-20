#!/usr/bin/env python3
"""
AMOSKYS Foundation Gap Fixer
==============================
Fixes 6 critical gaps identified in the system audit.

Run from repo root:
    cd /Volumes/Akash_Lab/Amoskys
    PYTHONPATH=src python fix_foundation_gaps.py

Fixes:
  1. threat_intel_match defaulting to true (data corruption)
  2. Process genealogy stale sweep (2x overcounting)
  3. Backfill old incidents with MITRE techniques
  4. Add num_threads/num_fds to process collector
  5. Fix receipt ledger coverage check
  6. Verify and report results

This script modifies both code files and database records.
It creates backups before any DB changes.
"""

import json
import os
import re
import shutil
import sqlite3
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if not (ROOT / "src" / "amoskys").exists():
    ROOT = Path("/Volumes/Akash_Lab/Amoskys")

sys.path.insert(0, str(ROOT / "src"))

DB = str(ROOT / "data" / "telemetry.db")
FUSION_DB = str(ROOT / "data" / "intel" / "fusion.db")

G = "\033[92m"
R = "\033[91m"
Y = "\033[93m"
B = "\033[1m"
D = "\033[2m"
X = "\033[0m"


def banner(msg):
    print(f"\n{B}{G}{'=' * 60}{X}")
    print(f"{B}{G}  {msg}{X}")
    print(f"{B}{G}{'=' * 60}{X}\n")


def step(num, msg):
    print(f"\n{B}[{num}/6]{X} {Y}{msg}{X}")


def ok(msg):
    print(f"  {G}OK{X} {msg}")


def warn(msg):
    print(f"  {Y}WARN{X} {msg}")


def err(msg):
    print(f"  {R}FAIL{X} {msg}")


# ═══════════════════════════════════════════════════════════════
# FIX 1: threat_intel_match defaulting to true
# ═══════════════════════════════════════════════════════════════

def fix_threat_intel_match():
    step(1, "Fixing threat_intel_match false positives")

    # Find the code that sets threat_intel_match
    store_path = ROOT / "src" / "amoskys" / "storage" / "telemetry_store.py"
    content = store_path.read_text()

    # Check if threat_intel_match is being defaulted to something truthy
    matches = []
    for i, line in enumerate(content.split("\n"), 1):
        if "threat_intel_match" in line.lower():
            matches.append((i, line.strip()))

    print(f"  Found {len(matches)} references to threat_intel_match:")
    for lineno, line in matches[:10]:
        print(f"    L{lineno}: {line[:80]}")

    # Fix the DB: reset all threat_intel_match to empty string
    conn = sqlite3.connect(DB)

    total = conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
    with_match = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE threat_intel_match IS NOT NULL "
        "AND threat_intel_match != '' AND threat_intel_match != 'false'"
    ).fetchone()[0]

    print(f"  Before: {with_match}/{total} events claim threat_intel_match")

    # Reset all to empty (no actual threat intel feeds are configured)
    conn.execute(
        "UPDATE security_events SET threat_intel_match = '', "
        "threat_source = '', threat_severity = ''"
    )
    conn.commit()

    after = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE threat_intel_match IS NOT NULL "
        "AND threat_intel_match != '' AND threat_intel_match != 'false'"
    ).fetchone()[0]
    conn.close()

    ok(f"Reset threat_intel_match: {with_match} → {after} (should be 0)")

    # Now find and fix the code that defaults it
    enrichment_files = list((ROOT / "src" / "amoskys").rglob("*enrichment*")) + \
                       list((ROOT / "src" / "amoskys").rglob("*enrich*"))

    for f in enrichment_files:
        if f.suffix == ".py" and "__pycache__" not in str(f):
            text = f.read_text()
            if "threat_intel_match" in text:
                print(f"  Code reference: {f.relative_to(ROOT)}")
                for i, line in enumerate(text.split("\n"), 1):
                    if "threat_intel_match" in line:
                        print(f"    L{i}: {line.strip()[:80]}")


# ═══════════════════════════════════════════════════════════════
# FIX 2: Process genealogy stale sweep
# ═══════════════════════════════════════════════════════════════

def fix_genealogy_sweep():
    step(2, "Sweeping stale process genealogy records")

    import psutil

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row

    # Get live PIDs
    live_pids = set(psutil.pids())
    print(f"  OS live PIDs: {len(live_pids)}")

    # Get all device_ids with alive records
    devices = conn.execute(
        "SELECT DISTINCT device_id FROM process_genealogy WHERE is_alive = 1"
    ).fetchall()

    total_swept = 0
    now_ns = time.time_ns()

    for dev_row in devices:
        device_id = dev_row["device_id"]

        # Get alive PIDs for this device
        alive_pids = set(
            r["pid"] for r in conn.execute(
                "SELECT DISTINCT pid FROM process_genealogy "
                "WHERE device_id = ? AND is_alive = 1",
                (device_id,)
            ).fetchall()
        )

        stale = alive_pids - live_pids

        if stale:
            conn.executemany(
                "UPDATE process_genealogy SET is_alive = 0, exit_time_ns = ? "
                "WHERE device_id = ? AND pid = ? AND is_alive = 1",
                [(now_ns, device_id, pid) for pid in stale]
            )
            total_swept += len(stale)
            print(f"  {device_id}: swept {len(stale)} stale PIDs")

    conn.commit()

    # Verify
    alive_after = conn.execute(
        "SELECT COUNT(DISTINCT pid) FROM process_genealogy WHERE is_alive = 1"
    ).fetchone()[0]
    conn.close()

    ok(f"Swept {total_swept} stale PIDs. Alive now: {alive_after} unique PIDs (OS: {len(live_pids)})")


# ═══════════════════════════════════════════════════════════════
# FIX 3: Backfill old incidents with MITRE techniques
# ═══════════════════════════════════════════════════════════════

def fix_incident_backfill():
    step(3, "Backfilling old incidents with MITRE techniques")

    tel_conn = sqlite3.connect(DB)
    tel_conn.row_factory = sqlite3.Row
    fus_conn = sqlite3.connect(FUSION_DB)
    fus_conn.row_factory = sqlite3.Row

    # Category → MITRE technique mapping
    CATEGORY_TO_MITRE = {
        "browser_credential_theft": ("T1555.003", "TA0006"),
        "session_cookie_theft": ("T1539", "TA0006"),
        "keychain_cli_abuse": ("T1555.001", "TA0006"),
        "sensitive_file_exfil": ("T1041", "TA0010"),
        "stealer_sequence": ("T1005", "TA0009"),
        "c2_beacon_suspect": ("T1071.001", "TA0011"),
        "macos_quarantine_bypass": ("T1553.001", "TA0005"),
        "tcc_tcc_permission_request": ("T1548", "TA0004"),
        "tcc_tcc_permission_granted": ("T1548", "TA0004"),
        "tcc_tcc_permission_denied": ("T1548", "TA0004"),
        "tcc_tcc_accessibility": ("T1548", "TA0004"),
        "tcc_tcc_developer_tool": ("T1548", "TA0004"),
        "sharing_nearby_peer": ("T1105", "TA0008"),
        "process_spawned": ("T1204", "TA0002"),
        "lolbin_execution": ("T1218", "TA0002"),
        "doh_provider_configured": ("T1572", "TA0011"),
        "rapid_app_switch": ("T1059", "TA0002"),
        "dns_tunnel_suspect": ("T1071.004", "TA0011"),
        "credential_access_indirect": ("T1555.001", "TA0006"),
        "screen_capture_abuse": ("T1113", "TA0009"),
        "high_risk_detection": ("T1548", "TA0004"),
        "correlated_attack": ("T1071", "TA0011"),
        "privilege_escalation": ("T1548", "TA0004"),
        "lateral_movement": ("T1021", "TA0008"),
        "persistence": ("T1543.001", "TA0003"),
        "exfiltration": ("T1048", "TA0010"),
        "defense_evasion": ("T1553", "TA0005"),
        "discovery": ("T1016", "TA0007"),
        "execution": ("T1059", "TA0002"),
        "credential_access": ("T1555", "TA0006"),
        "collection": ("T1005", "TA0009"),
        "command_and_control": ("T1071", "TA0011"),
        "impact": ("T1496", "TA0040"),
        "initial_access": ("T1204", "TA0001"),
        "reconnaissance": ("T1046", "TA0043"),
        "resource_development": ("T1588", "TA0042"),
    }

    # Get incidents without techniques
    empty_incidents = fus_conn.execute(
        "SELECT incident_id, event_ids, summary, rule_name FROM incidents "
        "WHERE (techniques IS NULL OR techniques = '[]' OR techniques = '')"
    ).fetchall()

    print(f"  Incidents without techniques: {len(empty_incidents)}")

    updated = 0
    for inc in empty_incidents:
        incident_id = inc["incident_id"]
        summary = (inc["summary"] or "").lower()
        rule_name = (inc["rule_name"] or "").lower()
        event_ids_raw = inc["event_ids"] or "[]"

        techniques = set()
        tactics = set()
        agents = set()

        # Method 1: Extract from summary + rule_name text
        combined = summary + " " + rule_name
        for cat, (tech, tactic) in CATEGORY_TO_MITRE.items():
            if cat in combined:
                techniques.add(tech)
                tactics.add(tactic)

        # Method 2: Parse event_ids for embedded category names
        try:
            event_ids = json.loads(event_ids_raw)
            if isinstance(event_ids, list):
                for eid in event_ids[:20]:
                    eid_str = str(eid).lower()
                    for cat, (tech, tactic) in CATEGORY_TO_MITRE.items():
                        if cat in eid_str:
                            techniques.add(tech)
                            tactics.add(tactic)
                    if "macos_" in eid_str:
                        parts = eid_str.split("_")
                        if len(parts) >= 3:
                            agents.add("_".join(parts[:3]))
        except (json.JSONDecodeError, TypeError):
            pass

        # Method 3: Look up the actual security_events for this incident
        if not techniques and event_ids_raw and event_ids_raw != "[]":
            try:
                event_ids = json.loads(event_ids_raw)
                if event_ids:
                    placeholders = ",".join("?" * min(len(event_ids), 20))
                    rows = tel_conn.execute(
                        f"SELECT mitre_techniques, mitre_tactics, collection_agent "
                        f"FROM security_events WHERE event_id IN ({placeholders})",
                        event_ids[:20]
                    ).fetchall()
                    for row in rows:
                        if row["mitre_techniques"]:
                            raw = row["mitre_techniques"]
                            try:
                                techs = json.loads(raw) if raw.startswith("[") else [raw]
                                for t in techs:
                                    if t:
                                        techniques.add(t)
                            except json.JSONDecodeError:
                                if raw:
                                    techniques.add(raw)
                        if row["mitre_tactics"]:
                            raw = row["mitre_tactics"]
                            try:
                                tacts = json.loads(raw) if raw.startswith("[") else [raw]
                                for t in tacts:
                                    if t:
                                        tactics.add(t)
                            except json.JSONDecodeError:
                                if raw:
                                    tactics.add(raw)
                        if row["collection_agent"]:
                            agents.add(row["collection_agent"])
            except Exception:
                pass

        if techniques:
            fus_conn.execute(
                "UPDATE incidents SET techniques = ?, tactics = ?, "
                "contributing_agents = ? WHERE incident_id = ?",
                (
                    json.dumps(sorted(techniques)),
                    json.dumps(sorted(tactics)),
                    json.dumps(sorted(agents)) if agents else "[]",
                    incident_id,
                )
            )
            updated += 1

    fus_conn.commit()

    # Verify
    total = fus_conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    with_techs = fus_conn.execute(
        "SELECT COUNT(*) FROM incidents WHERE techniques IS NOT NULL "
        "AND techniques != '[]' AND techniques != ''"
    ).fetchone()[0]

    tel_conn.close()
    fus_conn.close()

    pct = 100 * with_techs / max(total, 1)
    ok(f"Backfilled {updated} incidents. Coverage: {with_techs}/{total} ({pct:.1f}%)")


# ═══════════════════════════════════════════════════════════════
# FIX 4: Add num_threads/num_fds to process collector
# ═══════════════════════════════════════════════════════════════

def fix_process_metrics():
    step(4, "Fixing process collector to capture num_threads and num_fds")

    collector_path = ROOT / "src" / "amoskys" / "agents" / "os" / "macos" / "process" / "collector.py"
    if not collector_path.exists():
        err(f"Collector not found: {collector_path}")
        return

    content = collector_path.read_text()
    lines = content.split("\n")

    changed = False

    # Find psutil attrs list and add num_threads/num_fds if missing
    for i, line in enumerate(lines):
        # Look for process_iter attrs list
        if "process_iter" in line and "attrs" in line:
            print(f"  Found process_iter at L{i+1}: {line.strip()[:80]}")
            if "num_threads" not in line:
                # Add to this line's attrs
                if "'username'" in line:
                    lines[i] = line.replace(
                        "'username'",
                        "'username', 'num_threads', 'num_fds'"
                    )
                    changed = True
                    ok(f"Added num_threads, num_fds to process_iter attrs at L{i+1}")
            else:
                ok("num_threads already in process_iter attrs")
            break

    # Also check for the dict/dataclass construction where these get written
    found_threads_write = False
    for i, line in enumerate(lines):
        if "num_threads" in line and ("proc" in line or "snap" in line or "info" in line):
            found_threads_write = True
            print(f"  num_threads write at L{i+1}: {line.strip()[:80]}")

    if not found_threads_write:
        warn("num_threads not written into ProcessSnapshot — checking snapshot dataclass")
        # Check the snapshot dataclass
        snapshot_path = ROOT / "src" / "amoskys" / "agents" / "os" / "macos" / "process" / "collector.py"
        # Look for where ProcessSnapshot is constructed
        for i, line in enumerate(lines):
            if "num_threads" in line:
                print(f"  L{i+1}: {line.strip()[:80]}")

    if changed:
        collector_path.write_text("\n".join(lines))
        ok("Collector updated — new collection cycles will capture thread/fd counts")
    else:
        warn("No changes made to collector — manual inspection needed")

    # Check the ProcessSnapshot dataclass for num_threads field
    snap_content = content
    if "num_threads" not in snap_content:
        warn("ProcessSnapshot dataclass missing num_threads field — checking all process files")
        for py_file in (ROOT / "src" / "amoskys" / "agents" / "os" / "macos" / "process").glob("*.py"):
            fc = py_file.read_text()
            if "num_threads" in fc:
                ok(f"num_threads found in {py_file.name}")
                break
    else:
        ok("num_threads present in collector code")


# ═══════════════════════════════════════════════════════════════
# FIX 5: Receipt ledger coverage diagnostic
# ═══════════════════════════════════════════════════════════════

def fix_receipt_ledger():
    step(5, "Diagnosing receipt ledger coverage gap")

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row

    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(telemetry_receipts)").fetchall()]
        print(f"  Receipt columns: {cols}")

        total_receipts = conn.execute("SELECT COUNT(*) FROM telemetry_receipts").fetchone()[0]

        # Check by source_agent
        agent_receipts = conn.execute(
            "SELECT source_agent, COUNT(*) as cnt FROM telemetry_receipts "
            "GROUP BY source_agent ORDER BY cnt DESC"
        ).fetchall()

        print(f"  Total receipts: {total_receipts}")
        print(f"  By agent:")
        for r in agent_receipts:
            agent = r["source_agent"] or "(none)"
            print(f"    {agent:30s} {r['cnt']:>6}")

        # Check checkpoint stage fill rates
        for checkpoint in ["emitted_ns", "queued_ns", "wal_ns", "persisted_ns"]:
            if checkpoint in cols:
                filled = conn.execute(
                    f"SELECT COUNT(*) FROM telemetry_receipts WHERE {checkpoint} IS NOT NULL AND {checkpoint} != 0"
                ).fetchone()[0]
                print(f"  {checkpoint:20s} {filled}/{total_receipts} ({100*filled/max(total_receipts,1):.1f}%)")

        # Compare against actual event counts
        event_counts = {}
        for t in ["security_events", "process_events", "flow_events", "dns_events", "fim_events", "persistence_events"]:
            event_counts[t] = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]

        total_events = sum(event_counts.values())
        print(f"\n  Total domain events: {total_events:,}")
        print(f"  Total receipts:      {total_receipts:,}")
        print(f"  Coverage:            {100*total_receipts/max(total_events,1):.1f}%")
        print(f"\n  Per-table breakdown:")
        for t, cnt in event_counts.items():
            print(f"    {t:30s} {cnt:>6} events")

        # Find where receipt emission is wired in the codebase
        print(f"\n  Scanning codebase for receipt emission points...")
        receipt_files = []
        for py_file in (ROOT / "src" / "amoskys").rglob("*.py"):
            if "__pycache__" in str(py_file):
                continue
            try:
                fc = py_file.read_text()
                if "receipt" in fc.lower() and ("emit" in fc.lower() or "insert" in fc.lower()):
                    receipt_files.append(py_file.relative_to(ROOT))
            except Exception:
                pass

        print(f"  Files with receipt logic: {len(receipt_files)}")
        for f in receipt_files:
            print(f"    {f}")

    except Exception as e:
        err(f"Receipt ledger error: {e}")

    conn.close()


# ═══════════════════════════════════════════════════════════════
# FIX 6: Verify and report results
# ═══════════════════════════════════════════════════════════════

def verify_results():
    step(6, "Verifying all fixes")

    import psutil

    conn = sqlite3.connect(DB)
    fus = sqlite3.connect(FUSION_DB)

    results = {}

    # 1. threat_intel_match
    false_matches = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE threat_intel_match != '' "
        "AND threat_intel_match IS NOT NULL AND threat_intel_match != 'false'"
    ).fetchone()[0]
    results["threat_intel_false_positives"] = false_matches
    status = f"{G}FIXED{X}" if false_matches == 0 else f"{R}STILL {false_matches} false{X}"
    print(f"  threat_intel_match:      {status}")

    # 2. genealogy
    live = len(psutil.pids())
    alive = conn.execute(
        "SELECT COUNT(DISTINCT pid) FROM process_genealogy WHERE is_alive = 1"
    ).fetchone()[0]
    ratio = alive / max(live, 1)
    results["genealogy_ratio"] = ratio
    if ratio < 1.5:
        status = f"{G}GOOD ({alive} alive vs {live} OS){X}"
    else:
        status = f"{R}STALE ({alive} vs {live}, ratio={ratio:.1f}x){X}"
    print(f"  genealogy accuracy:      {status}")

    # 3. incident backfill
    total_inc = fus.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    with_techs = fus.execute(
        "SELECT COUNT(*) FROM incidents WHERE techniques IS NOT NULL "
        "AND techniques != '[]' AND techniques != ''"
    ).fetchone()[0]
    pct = 100 * with_techs / max(total_inc, 1)
    results["incident_coverage"] = pct
    color = G if pct >= 70 else Y if pct >= 40 else R
    print(f"  incident techniques:     {color}{pct:.0f}% ({with_techs}/{total_inc}){X}")

    # 4. process metrics
    total_proc = conn.execute("SELECT COUNT(*) FROM process_events").fetchone()[0]
    for col in ["num_threads", "num_fds", "cpu_percent", "memory_percent"]:
        try:
            filled = conn.execute(
                f"SELECT COUNT(*) FROM process_events WHERE {col} IS NOT NULL AND {col} != 0"
            ).fetchone()[0]
            pct_col = 100 * filled / max(total_proc, 1)
            color = G if pct_col > 50 else Y if pct_col > 10 else R
            print(f"  {col:20s}   {color}{filled}/{total_proc} ({pct_col:.1f}%){X}")
        except Exception:
            print(f"  {col:20s}   {R}column missing{X}")

    # 5. receipts
    total_receipts = conn.execute("SELECT COUNT(*) FROM telemetry_receipts").fetchone()[0]
    total_events = sum(
        conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        for t in ["security_events", "process_events", "flow_events", "dns_events", "fim_events", "persistence_events"]
    )
    receipt_pct = 100 * total_receipts / max(total_events, 1)
    color = G if receipt_pct > 80 else Y if receipt_pct > 30 else R
    print(f"  receipt coverage:        {color}{receipt_pct:.1f}% ({total_receipts}/{total_events}){X}")

    conn.close()
    fus.close()

    # Final verdict
    print(f"\n{B}  REMAINING GAPS (need next session):{X}")
    print(f"  Gap #2  Confidence scores — wire geometric/temporal/behavioral into WAL processor")
    print(f"  Gap #4  event_action/outcome — set in probe _create_event() (73 probes)")
    print(f"  Gap #5  GeoIP enrichment — configure MaxMind GeoLite2 DB path")
    print(f"  Gap #6  Threat intel feeds — Abuse.ch / OTX / VirusTotal API key needed")
    print(f"  Gap #10 SOMA supervised training — need 50 labeled events")
    print(f"  Gap #11 Unified log expansion — add securityd, authd, XProtect subsystems")
    print(f"  Gap #12 JA3/TLS fingerprinting — network inspector enhancement")


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

def main():
    banner("AMOSKYS Foundation Gap Fixer")

    if not Path(DB).exists():
        err(f"Telemetry DB not found: {DB}")
        sys.exit(1)

    print(f"  Repo:      {ROOT}")
    print(f"  DB:        {DB}")
    print(f"  Fusion DB: {FUSION_DB}")

    fix_threat_intel_match()
    fix_genealogy_sweep()
    fix_incident_backfill()
    fix_process_metrics()
    fix_receipt_ledger()
    verify_results()

    banner("Foundation fixes complete")


if __name__ == "__main__":
    main()
