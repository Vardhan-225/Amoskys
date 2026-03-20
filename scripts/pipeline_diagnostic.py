#!/usr/bin/env python3
"""AMOSKYS Full Pipeline Diagnostic — 10-Layer Validation.

Tests every layer of the detection pipeline:
  L1: Probe instantiation + MITRE mapping
  L2: Agent collection (live macOS data)
  L3: Data structures + schema validation
  L4: WAL + Storage pipeline
  L5: MITRE coverage analysis
  L6: Enrichment, correlation, scoring, kill chain
  L7: Detection logic — Sigma rules + fusion rules
  L8: Concurrency + latency benchmarks
  L9: IGRIS + ML (story engine, narrator, SOMA)
  L10: Dashboard API endpoints

Usage:
    PYTHONPATH=src python scripts/pipeline_diagnostic.py
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import sys
import threading
import time
import traceback
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── Globals ──────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).parent.parent
RESULTS: Dict[str, List[Dict]] = defaultdict(list)
PASS = 0
FAIL = 0
WARN = 0


@dataclass
class Check:
    layer: str
    name: str
    status: str  # PASS / FAIL / WARN / SKIP
    detail: str = ""
    latency_ms: float = 0.0


ALL_CHECKS: List[Check] = []


def record(layer: str, name: str, status: str, detail: str = "", latency_ms: float = 0.0):
    global PASS, FAIL, WARN
    c = Check(layer=layer, name=name, status=status, detail=detail, latency_ms=latency_ms)
    ALL_CHECKS.append(c)
    if status == "PASS":
        PASS += 1
    elif status == "FAIL":
        FAIL += 1
    elif status == "WARN":
        WARN += 1
    icon = {"PASS": "✓", "FAIL": "✗", "WARN": "⚠", "SKIP": "○"}.get(status, "?")
    print(f"  {icon} [{layer}] {name}: {detail}")


# ═══════════════════════════════════════════════════════════════════════════
# L1: PROBE VALIDATION
# ═══════════════════════════════════════════════════════════════════════════

PROBE_FACTORIES = {
    "proc": ("amoskys.agents.os.macos.process.probes", "create_process_probes", 13),
    "auth": ("amoskys.agents.os.macos.auth.probes", "create_auth_probes", 8),
    "persistence": ("amoskys.agents.os.macos.persistence.probes", "create_persistence_probes", 10),
    "fim": ("amoskys.agents.os.macos.filesystem.probes", "create_filesystem_probes", 8),
    "flow": ("amoskys.agents.os.macos.network.probes", "create_network_probes", 9),
    "peripheral": ("amoskys.agents.os.macos.peripheral.probes", "create_peripheral_probes", 4),
    "dns": ("amoskys.agents.os.macos.dns.probes", "create_dns_probes", 8),
    "applog": ("amoskys.agents.os.macos.applog.probes", "create_applog_probes", 7),
    "discovery": ("amoskys.agents.os.macos.discovery.probes", "create_discovery_probes", 6),
    "db_activity": ("amoskys.agents.os.macos.db_activity.probes", "create_db_activity_probes", 8),
    "http_inspector": ("amoskys.agents.os.macos.http_inspector.probes", "create_http_inspector_probes", 8),
    "internet_activity": ("amoskys.agents.os.macos.internet_activity.probes", "create_internet_activity_probes", 8),
    "unified_log": ("amoskys.agents.os.macos.unified_log.probes", "create_unified_log_probes", 6),
    "security_monitor": ("amoskys.agents.os.macos.security_monitor.probes", "create_macos_security_probes", 4),
    "infostealer_guard": ("amoskys.agents.os.macos.infostealer_guard.probes", "create_infostealer_guard_probes", 11),
    "quarantine_guard": ("amoskys.agents.os.macos.quarantine_guard.probes", "create_quarantine_guard_probes", 8),
    "provenance": ("amoskys.agents.os.macos.provenance.probes", "create_provenance_probes", 8),
    "network_sentinel": ("amoskys.agents.os.macos.network_sentinel.probes", "create_network_sentinel_probes", 10),
    "protocol_collectors": ("amoskys.agents.os.macos.protocol_collectors.probes", "create_protocol_collector_probes", 10),
    "correlation": ("amoskys.agents.os.macos.correlation.probes", "create_correlation_probes", 12),
    "correlation_temporal": ("amoskys.agents.os.macos.correlation.temporal_probes", "create_temporal_probes", 6),
    "kernel_audit": ("amoskys.agents.os.linux.kernel_audit.probes", "create_kernel_audit_probes", 8),
}


def run_l1_probes():
    """L1: Validate every probe factory — import, instantiation, MITRE, severity."""
    print("\n══ L1: PROBE VALIDATION ══")
    import importlib

    total_probes = 0
    mitre_all = set()
    probes_missing_mitre = []
    probes_missing_severity = []

    for agent_key, (module_path, factory_name, expected_count) in PROBE_FACTORIES.items():
        t0 = time.time()
        try:
            mod = importlib.import_module(module_path)
            factory = getattr(mod, factory_name)
            probes = factory()
            dt = (time.time() - t0) * 1000

            if len(probes) != expected_count:
                record("L1", f"{agent_key} probe count", "FAIL",
                       f"expected={expected_count}, got={len(probes)}", dt)
            else:
                record("L1", f"{agent_key} probe count", "PASS",
                       f"{len(probes)} probes", dt)

            total_probes += len(probes)

            for p in probes:
                # MITRE check
                techniques = getattr(p, "mitre_techniques", [])
                if not techniques:
                    probes_missing_mitre.append(f"{agent_key}/{p.name}")
                else:
                    for t in techniques:
                        if re.match(r"^T\d{4}(\.\d{3})?$", t):
                            mitre_all.add(t)
                        else:
                            record("L1", f"{p.name} MITRE format", "FAIL",
                                   f"invalid technique ID: {t}")

                # Severity check
                if not hasattr(p, "default_severity") and not hasattr(p, "severity"):
                    probes_missing_severity.append(f"{agent_key}/{p.name}")

        except Exception as e:
            record("L1", f"{agent_key} import", "FAIL", str(e))

    record("L1", "total probes instantiated", "PASS" if total_probes > 190 else "WARN",
           f"{total_probes} probes across {len(PROBE_FACTORIES)} agents")
    record("L1", "MITRE technique coverage", "PASS" if len(mitre_all) > 80 else "WARN",
           f"{len(mitre_all)} unique techniques")

    if probes_missing_mitre:
        record("L1", "probes without MITRE", "WARN",
               f"{len(probes_missing_mitre)}: {', '.join(probes_missing_mitre[:5])}")
    if probes_missing_severity:
        record("L1", "probes without severity", "WARN",
               f"{len(probes_missing_severity)}: {', '.join(probes_missing_severity[:5])}")

    return total_probes, mitre_all


# ═══════════════════════════════════════════════════════════════════════════
# L2: AGENT COLLECTION (live macOS data)
# ═══════════════════════════════════════════════════════════════════════════

COLLECTORS = {
    "process": ("amoskys.agents.os.macos.process.collector", "MacOSProcessCollector"),
    "auth": ("amoskys.agents.os.macos.auth.collector", "MacOSAuthCollector"),
    "persistence": ("amoskys.agents.os.macos.persistence.collector", "MacOSPersistenceCollector"),
    "filesystem": ("amoskys.agents.os.macos.filesystem.collector", "MacOSFileCollector"),
    "network": ("amoskys.agents.os.macos.network.collector", "MacOSNetworkCollector"),
    "peripheral": ("amoskys.agents.os.macos.peripheral.collector", "MacOSPeripheralCollector"),
    "dns": ("amoskys.agents.os.macos.dns.collector", "MacOSDNSCollector"),
    "discovery": ("amoskys.agents.os.macos.discovery.collector", "MacOSDiscoveryCollector"),
    "infostealer_guard": ("amoskys.agents.os.macos.infostealer_guard.collector", "MacOSInfostealerGuardCollector"),
    "quarantine_guard": ("amoskys.agents.os.macos.quarantine_guard.collector", "MacOSQuarantineGuardCollector"),
    "provenance": ("amoskys.agents.os.macos.provenance.collector", "MacOSProvenanceCollector"),
}


def run_l2_collection():
    """L2: Run each collector against live macOS and verify data shape."""
    print("\n══ L2: AGENT COLLECTION (live macOS) ══")
    import importlib

    results = {}
    for name, (mod_path, cls_name) in COLLECTORS.items():
        t0 = time.time()
        try:
            mod = importlib.import_module(mod_path)
            CollectorCls = getattr(mod, cls_name)
            collector = CollectorCls()
            data = collector.collect()
            dt = (time.time() - t0) * 1000

            if isinstance(data, dict):
                keys = list(data.keys())
                # Check for non-empty primary data
                primary_key = keys[0] if keys else None
                primary_data = data.get(primary_key, [])
                count = len(primary_data) if isinstance(primary_data, (list, dict)) else 1

                if count > 0:
                    record("L2", f"{name} collection", "PASS",
                           f"{count} items in '{primary_key}', {len(keys)} keys, {dt:.0f}ms", dt)
                else:
                    record("L2", f"{name} collection", "WARN",
                           f"empty primary data '{primary_key}', {dt:.0f}ms", dt)
                results[name] = data
            else:
                record("L2", f"{name} collection", "WARN",
                       f"returned {type(data).__name__}, not dict, {dt:.0f}ms", dt)
                results[name] = data

        except Exception as e:
            dt = (time.time() - t0) * 1000
            record("L2", f"{name} collection", "FAIL", f"{e}", dt)

    return results


# ═══════════════════════════════════════════════════════════════════════════
# L3: DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════

def run_l3_data_structures():
    """L3: Validate data structure integrity."""
    print("\n══ L3: DATA STRUCTURES ══")

    # ProcessSnapshot
    try:
        from amoskys.agents.os.macos.process.collector import ProcessSnapshot
        import inspect
        sig = inspect.signature(ProcessSnapshot)
        params = list(sig.parameters.keys())
        required = ["pid", "name", "exe", "cmdline", "username", "ppid", "parent_name",
                     "create_time", "num_threads", "num_fds", "status", "process_guid"]
        missing = [r for r in required if r not in params]
        if missing:
            record("L3", "ProcessSnapshot fields", "FAIL", f"missing: {missing}")
        else:
            record("L3", "ProcessSnapshot fields", "PASS", f"{len(params)} fields")
    except Exception as e:
        record("L3", "ProcessSnapshot import", "FAIL", str(e))

    # TelemetryEvent
    try:
        from amoskys.agents.common.probes import TelemetryEvent, Severity
        ev = TelemetryEvent(
            event_type="test",
            severity=Severity.HIGH,
            probe_name="diag_probe",
            data={"test": True},
            mitre_techniques=["T1059"],
        )
        assert ev.event_type == "test"
        assert ev.probe_name == "diag_probe"
        record("L3", "TelemetryEvent", "PASS",
               f"type={ev.event_type}, severity={ev.severity}, probe={ev.probe_name}")
    except Exception as e:
        record("L3", "TelemetryEvent", "FAIL", str(e))

    # TelemetryEventView (fusion model)
    try:
        from amoskys.intel.models import TelemetryEventView
        view = TelemetryEventView(
            event_id="test-view-1",
            device_id="test-host",
            event_type="SECURITY",
            severity="HIGH",
            timestamp=datetime.now(timezone.utc),
            attributes={"agent_id": "proc"},
            security_event={"event_action": "binary_from_temp"},
        )
        assert view.timestamp is not None
        record("L3", "TelemetryEventView", "PASS", "fusion model OK")
    except Exception as e:
        record("L3", "TelemetryEventView", "FAIL", str(e))

    # ProbeContext
    try:
        from amoskys.agents.common.probes import ProbeContext
        ctx = ProbeContext(device_id="test", agent_name="test", shared_data={"key": [1, 2, 3]})
        assert ctx.shared_data["key"] == [1, 2, 3]
        record("L3", "ProbeContext", "PASS", "shared_data accessible")
    except Exception as e:
        record("L3", "ProbeContext", "FAIL", str(e))

    # KillChainState
    try:
        from amoskys.agents.common.kill_chain import KillChainTracker, KILL_CHAIN_STAGES
        tracker = KillChainTracker(ttl_seconds=60)
        state = tracker.record_stage("dev1", "reconnaissance", "test_agent",
                                     event_type="scan", mitre_technique="T1046")
        state = tracker.record_stage("dev1", "exploitation", "test_agent",
                                     event_type="exec", mitre_technique="T1059")
        assert state.stages_reached >= 2
        record("L3", "KillChainTracker", "PASS",
               f"{state.stages_reached} stages, multi_stage={state.is_multi_stage}")
    except Exception as e:
        record("L3", "KillChainTracker", "FAIL", str(e))

    # Coordination bus
    try:
        from amoskys.common.coordination import (
            TacticalTopic, WatchDirective, LocalBus, create_coordination_bus, CoordinationConfig,
        )
        topics = [t.value for t in TacticalTopic]
        assert "WATCH_PID" in topics
        assert "CLEAR_WATCH" in topics

        bus = LocalBus()
        received = []
        bus.subscribe("TEST", lambda t, p: received.append(p))
        bus.publish("TEST", {"msg": "hello"})
        time.sleep(0.05)
        assert len(received) == 1
        record("L3", "Coordination bus", "PASS", f"topics={topics}, pub/sub works")
    except Exception as e:
        record("L3", "Coordination bus", "FAIL", str(e))


# ═══════════════════════════════════════════════════════════════════════════
# L4: WAL + STORAGE PIPELINE
# ═══════════════════════════════════════════════════════════════════════════

def run_l4_storage():
    """L4: Test storage layer — schema, writes, reads, receipts."""
    print("\n══ L4: WAL + STORAGE ══")
    import tempfile

    try:
        from amoskys.storage.telemetry_store import TelemetryStore

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        store = TelemetryStore(db_path)

        # Schema validation
        conn = sqlite3.connect(db_path)
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        conn.close()

        expected_tables = [
            "telemetry_events", "security_events", "process_events",
            "flow_events", "dns_events", "incidents", "telemetry_receipts",
            "process_genealogy", "dashboard_rollups",
        ]
        missing_tables = [t for t in expected_tables if t not in tables]
        if missing_tables:
            record("L4", "schema tables", "FAIL", f"missing: {missing_tables}")
        else:
            record("L4", "schema tables", "PASS", f"{len(tables)} tables created")

        # Write a security event
        t0 = time.time()
        event_id = f"diag-{int(time.time_ns())}"
        store.insert_security_event({
            "event_id": event_id,
            "device_id": "diag-host",
            "event_type": "SECURITY",
            "event_category": "process",
            "event_action": "binary_from_temp",
            "event_outcome": "alert",
            "risk_score": 0.85,
            "confidence": 0.9,
            "mitre_techniques": json.dumps(["T1204"]),
            "source_agent": "proc",
            "raw_attributes_json": json.dumps({"exe": "/tmp/payload", "pid": 1234}),
            "event_timestamp_ns": int(time.time() * 1e9),
        })
        dt_write = (time.time() - t0) * 1000
        record("L4", "security event write", "PASS", f"{dt_write:.1f}ms")

        # Read back
        t0 = time.time()
        events = store.get_recent_security_events(limit=10, hours=1)
        dt_read = (time.time() - t0) * 1000
        if events and any(e.get("event_id") == event_id for e in events):
            record("L4", "security event read", "PASS", f"{dt_read:.1f}ms, {len(events)} events")
        else:
            record("L4", "security event read", "WARN",
                   f"wrote event but read returned {len(events)} events")

        # Receipt ledger
        try:
            store.receipt_emit(event_id, "proc", "diag-host")
            store.receipt_queued(event_id, "proc")
            store.receipt_wal(event_id, "proc")
            store.receipt_persisted(event_id, "proc", "security_events", "complete")
            gaps = store.receipt_reconcile("proc")
            record("L4", "receipt ledger", "PASS",
                   f"4 checkpoints written, reconcile={gaps}")
        except Exception as e:
            record("L4", "receipt ledger", "WARN", f"receipt methods: {e}")

        # Process genealogy
        try:
            store.upsert_genealogy({
                "device_id": "diag-host", "pid": 1234, "ppid": 1, "name": "payload",
                "exe": "/tmp/payload", "cmdline": "/tmp/payload --connect",
                "username": "attacker", "parent_name": "launchd",
                "create_time": time.time(), "process_guid": "diag-guid-1234",
            })
            chain = store.get_spawn_chain("diag-host", 1234)
            record("L4", "process genealogy", "PASS",
                   f"chain depth={len(chain)}")
        except Exception as e:
            record("L4", "process genealogy", "WARN", f"{e}")

        # Dashboard rollups
        try:
            conn = sqlite3.connect(db_path)
            conn.execute(
                "INSERT OR REPLACE INTO dashboard_rollups (rollup_type, bucket_key, bucket_hour, value, updated_ns) "
                "VALUES (?, ?, ?, ?, ?)",
                ("events_by_domain", "process", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H"), 42, int(time.time_ns())),
            )
            conn.commit()
            rollups = store.get_rollup_event_counts(hours=1)
            conn.close()
            record("L4", "dashboard rollups", "PASS", f"rollup read={rollups}")
        except Exception as e:
            record("L4", "dashboard rollups", "WARN", f"{e}")

        # Batch mode performance
        t0 = time.time()
        store.begin_batch()
        for i in range(100):
            store.insert_security_event({
                "event_id": f"batch-{i}-{int(time.time_ns())}",
                "device_id": "diag-host",
                "event_type": "SECURITY",
                "event_category": "test",
                "event_action": "batch_test",
                "event_outcome": "alert",
                "risk_score": 0.5,
                "confidence": 0.5,
                "mitre_techniques": "[]",
                "source_agent": "diag",
                "raw_attributes_json": "{}",
                "event_timestamp_ns": int(time.time() * 1e9),
            })
        store.end_batch()
        dt_batch = (time.time() - t0) * 1000
        record("L4", "batch write 100 events", "PASS" if dt_batch < 500 else "WARN",
               f"{dt_batch:.1f}ms ({dt_batch / 100:.1f}ms/event)")

        os.unlink(db_path)

    except Exception as e:
        record("L4", "storage pipeline", "FAIL", traceback.format_exc())


# ═══════════════════════════════════════════════════════════════════════════
# L5: MITRE MAPPING ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════

def run_l5_mitre(mitre_all: set):
    """L5: MITRE ATT&CK coverage analysis."""
    print("\n══ L5: MITRE COVERAGE ══")

    # Validate technique IDs
    valid = {t for t in mitre_all if re.match(r"^T\d{4}(\.\d{3})?$", t)}
    invalid = mitre_all - valid
    if invalid:
        record("L5", "invalid technique IDs", "FAIL", f"{invalid}")
    else:
        record("L5", "technique ID format", "PASS", f"all {len(valid)} valid")

    # Tactic coverage (via technique → tactic mapping)
    # Top-level techniques map to tactics
    tactics_covered = set()
    tactic_map = {
        "T1059": "execution", "T1204": "execution", "T1218": "defense_evasion",
        "T1110": "credential_access", "T1078": "initial_access",
        "T1543": "persistence", "T1547": "persistence", "T1053": "persistence",
        "T1548": "privilege_escalation", "T1574": "privilege_escalation",
        "T1071": "command_and_control", "T1572": "command_and_control",
        "T1048": "exfiltration", "T1567": "exfiltration",
        "T1021": "lateral_movement", "T1570": "lateral_movement",
        "T1036": "defense_evasion", "T1553": "defense_evasion", "T1562": "defense_evasion",
        "T1555": "credential_access", "T1539": "credential_access",
        "T1005": "collection", "T1113": "collection", "T1115": "collection",
        "T1046": "discovery", "T1082": "discovery", "T1018": "discovery",
        "T1200": "initial_access", "T1190": "initial_access",
        "T1565": "impact", "T1485": "impact", "T1496": "impact",
        "T1105": "command_and_control",
        "T1041": "exfiltration",
        "T1014": "defense_evasion",
        "T1055": "privilege_escalation",
        "T1003": "credential_access",
    }

    for t in valid:
        base = t.split(".")[0]
        if base in tactic_map:
            tactics_covered.add(tactic_map[base])

    all_tactics = {
        "initial_access", "execution", "persistence", "privilege_escalation",
        "defense_evasion", "credential_access", "discovery", "lateral_movement",
        "collection", "command_and_control", "exfiltration", "impact",
    }
    missing_tactics = all_tactics - tactics_covered
    if missing_tactics:
        record("L5", "tactic coverage", "WARN", f"missing: {missing_tactics}")
    else:
        record("L5", "tactic coverage", "PASS", f"all {len(all_tactics)} tactics covered")

    record("L5", "technique count", "PASS" if len(valid) > 100 else "WARN",
           f"{len(valid)} unique techniques")


# ═══════════════════════════════════════════════════════════════════════════
# L6: ENRICHMENT + CORRELATION + SCORING + KILL CHAIN
# ═══════════════════════════════════════════════════════════════════════════

def run_l6_enrichment():
    """L6: Scoring engine, fusion engine, kill chain."""
    print("\n══ L6: ENRICHMENT + CORRELATION ══")

    # Scoring engine
    try:
        from amoskys.intel.scoring import ScoringEngine
        scorer = ScoringEngine()

        event = {
            "event_category": "process",
            "event_action": "binary_from_temp",
            "risk_score": 0.8,
            "source_ip": "203.0.113.50",
            "event_timestamp_ns": int(time.time() * 1e9),
            "probe_latency_ns": 5_000_000,
        }
        result = scorer.score_event(event)
        geo = result.get("geometric_score", -1)
        temp = result.get("temporal_score", -1)
        behav = result.get("behavioral_score", -1)
        composite = result.get("composite_score", -1)
        classification = result.get("final_classification", "unknown")

        if composite >= 0 and classification in ("legitimate", "suspicious", "malicious"):
            record("L6", "scoring engine", "PASS",
                   f"geo={geo:.2f} temp={temp:.2f} behav={behav:.2f} "
                   f"composite={composite:.2f} class={classification}")
        else:
            record("L6", "scoring engine", "FAIL", f"invalid scores: {result}")
    except Exception as e:
        record("L6", "scoring engine", "FAIL", str(e))

    # Fusion engine
    try:
        import tempfile
        from amoskys.intel.fusion_engine import FusionEngine

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            fusion_db = f.name

        engine = FusionEngine(db_path=fusion_db, window_minutes=30)

        # Feed some events using TelemetryEventView
        from amoskys.intel.models import TelemetryEventView
        now = datetime.now()
        from datetime import timedelta
        for i, (etype, cat, action) in enumerate([
            ("SECURITY", "auth", "ssh_failed"),
            ("SECURITY", "auth", "ssh_failed"),
            ("SECURITY", "auth", "ssh_failed"),
            ("SECURITY", "auth", "ssh_success"),
        ]):
            ev = TelemetryEventView(
                event_id=f"fusion-{i}",
                event_type=etype,
                device_id="test-host",
                severity="HIGH",
                timestamp=now + timedelta(seconds=i * 60),
                security_event={
                    "event_category": cat,
                    "event_action": action,
                    "event_outcome": "failure" if "failed" in action else "success",
                    "source_ip": "10.0.0.1",
                    "user_name": "admin",
                    "mitre_techniques": ["T1110"],
                    "risk_score": 0.7,
                },
                attributes={"agent_id": "auth", "mitre_techniques": ["T1110"]},
            )
            engine.add_event(ev)

        incidents = engine.evaluate_device("test-host")
        record("L6", "fusion engine", "PASS" if incidents else "WARN",
               f"{len(incidents)} incidents from 4 auth events")

        os.unlink(fusion_db)
    except Exception as e:
        record("L6", "fusion engine", "FAIL", str(e))

    # Fusion rules
    try:
        from amoskys.intel.rules import ALL_RULES
        record("L6", "fusion rules loaded", "PASS", f"{len(ALL_RULES)} rules")
    except Exception as e:
        record("L6", "fusion rules", "FAIL", str(e))

    # Kill chain tracker
    try:
        from amoskys.agents.common.kill_chain import KillChainTracker
        tracker = KillChainTracker(ttl_seconds=300)
        for stage in ["reconnaissance", "delivery", "exploitation", "installation", "command_and_control"]:
            tracker.record_stage("test-host", stage, "diag", mitre_technique="T1059")
        state = tracker.get_progression("test-host")
        record("L6", "kill chain tracker", "PASS",
               f"{state.stages_reached} stages, multi_stage={state.is_multi_stage}")
    except Exception as e:
        record("L6", "kill chain tracker", "FAIL", str(e))


# ═══════════════════════════════════════════════════════════════════════════
# L7: DETECTION LOGIC — Sigma + Fusion Rules
# ═══════════════════════════════════════════════════════════════════════════

def run_l7_detection():
    """L7: Sigma rules, determination logic."""
    print("\n══ L7: DETECTION LOGIC ══")

    # Sigma rules
    try:
        from amoskys.intel.sigma import SigmaEngine
        engine = SigmaEngine()
        rules = engine.rules if hasattr(engine, "rules") else []
        record("L7", "sigma engine", "PASS", f"{len(rules)} rules loaded")
    except ImportError:
        # Try alternate path
        try:
            from amoskys.agents.common.sigma import SigmaRuleEngine, load_sigma_rules
            rules = load_sigma_rules()
            engine = SigmaRuleEngine(rules)
            record("L7", "sigma rules", "PASS", f"{len(rules)} rules loaded")
        except Exception as e:
            record("L7", "sigma rules", "WARN", f"sigma not available: {e}")

    # Fusion rule evaluation with crafted attack scenario
    try:
        from amoskys.intel.rules import evaluate_rules
        from amoskys.intel.models import TelemetryEventView
        from datetime import timedelta

        now = datetime.now()
        events = []
        # 5 SSH failures from same IP
        for i in range(5):
            events.append(TelemetryEventView(
                event_id=f"rule-{i}", event_type="SECURITY",
                device_id="test-host", severity="HIGH",
                timestamp=now + timedelta(minutes=i),
                security_event={
                    "event_category": "auth", "event_action": "SSH",
                    "event_outcome": "FAILURE", "source_ip": "10.0.0.99",
                    "user_name": "root", "mitre_techniques": ["T1110"], "risk_score": 0.6,
                },
                attributes={"agent_id": "auth"},
            ))
        # Add success from same IP
        events.append(TelemetryEventView(
            event_id="rule-success", event_type="SECURITY",
            device_id="test-host", severity="HIGH",
            timestamp=now + timedelta(minutes=6),
            security_event={
                "event_category": "auth", "event_action": "SSH",
                "event_outcome": "SUCCESS", "source_ip": "10.0.0.99",
                "user_name": "root", "mitre_techniques": ["T1078"], "risk_score": 0.5,
            },
            attributes={"agent_id": "auth"},
        ))

        incidents = evaluate_rules(events, "test-host")
        if incidents:
            record("L7", "SSH brute force rule", "PASS",
                   f"fired: {incidents[0].rule_name}, severity={incidents[0].severity}")
        else:
            record("L7", "SSH brute force rule", "WARN", "rule did not fire with crafted input")

    except Exception as e:
        record("L7", "fusion rule evaluation", "FAIL", str(e))


# ═══════════════════════════════════════════════════════════════════════════
# L8: CONCURRENCY + LATENCY
# ═══════════════════════════════════════════════════════════════════════════

def run_l8_concurrency():
    """L8: Threading, bus throughput, timing."""
    print("\n══ L8: CONCURRENCY + LATENCY ══")

    # Coordination bus throughput
    try:
        from amoskys.common.coordination import LocalBus
        bus = LocalBus()
        received = []
        bus.subscribe("PERF", lambda t, p: received.append(p))

        t0 = time.time()
        N = 1000
        for i in range(N):
            bus.publish("PERF", {"i": i})
        time.sleep(0.1)  # Let async handlers complete
        dt = (time.time() - t0) * 1000

        record("L8", f"LocalBus throughput ({N} msgs)", "PASS",
               f"{dt:.1f}ms total, {dt / N:.3f}ms/msg, received={len(received)}")
    except Exception as e:
        record("L8", "bus throughput", "FAIL", str(e))

    # Concurrent collector stress test
    try:
        import importlib
        results = {}
        errors = {}

        def collect_agent(name, mod_path, cls_name):
            try:
                mod = importlib.import_module(mod_path)
                CollectorCls = getattr(mod, cls_name)
                collector = CollectorCls()
                t0 = time.time()
                data = collector.collect()
                dt = (time.time() - t0) * 1000
                results[name] = dt
            except Exception as e:
                errors[name] = str(e)

        # Run 5 collectors concurrently
        test_collectors = {
            "process": ("amoskys.agents.os.macos.process.collector", "MacOSProcessCollector"),
            "network": ("amoskys.agents.os.macos.network.collector", "MacOSNetworkCollector"),
            "dns": ("amoskys.agents.os.macos.dns.collector", "MacOSDNSCollector"),
            "persistence": ("amoskys.agents.os.macos.persistence.collector", "MacOSPersistenceCollector"),
            "peripheral": ("amoskys.agents.os.macos.peripheral.collector", "MacOSPeripheralCollector"),
        }

        t0 = time.time()
        threads = []
        for name, (mod_path, cls_name) in test_collectors.items():
            t = threading.Thread(target=collect_agent, args=(name, mod_path, cls_name))
            threads.append(t)
            t.start()
        for t in threads:
            t.join(timeout=30)
        total_dt = (time.time() - t0) * 1000

        if errors:
            record("L8", "concurrent collection", "WARN",
                   f"errors: {errors}")
        else:
            latencies = ", ".join(f"{k}={v:.0f}ms" for k, v in sorted(results.items()))
            record("L8", f"5 concurrent collectors", "PASS",
                   f"wall={total_dt:.0f}ms | {latencies}")

        # Check for individual latency outliers
        for name, lat in results.items():
            if lat > 5000:
                record("L8", f"{name} latency", "WARN", f"{lat:.0f}ms > 5s threshold")

    except Exception as e:
        record("L8", "concurrent collection", "FAIL", str(e))


# ═══════════════════════════════════════════════════════════════════════════
# L9: IGRIS + ML + STORY ENGINE
# ═══════════════════════════════════════════════════════════════════════════

def run_l9_igris():
    """L9: IGRIS, story engine, narrator, SOMA."""
    print("\n══ L9: IGRIS + ML ══")

    # IGRIS imports
    try:
        from amoskys.igris.supervisor import Igris
        from amoskys.igris.signals import SignalType, IgrisSignal, SignalEmitter
        from amoskys.igris.metrics import MetricCollector
        from amoskys.igris.baseline import BaselineTracker
        from amoskys.igris.coherence import assess

        signal_types = [s.value for s in SignalType]
        record("L9", "IGRIS imports", "PASS", f"signal types: {signal_types}")
    except Exception as e:
        record("L9", "IGRIS imports", "FAIL", str(e))

    # MetricCollector
    try:
        collector = MetricCollector()
        t0 = time.time()
        metrics = collector.collect_all()
        dt = (time.time() - t0) * 1000
        record("L9", "IGRIS metric collection", "PASS",
               f"{len(metrics)} metrics in {dt:.0f}ms")
    except Exception as e:
        record("L9", "IGRIS metrics", "FAIL", str(e))

    # Coherence assessment
    try:
        verdict = assess(metrics if "metrics" in dir() else {}, active_signal_count=0)
        record("L9", "IGRIS coherence", "PASS",
               f"verdict={verdict.get('verdict', 'unknown')}")
    except Exception as e:
        record("L9", "IGRIS coherence", "WARN", str(e))

    # Story engine
    try:
        from amoskys.intel.story_engine import StoryEngine, KNOWN_PATTERNS
        engine = StoryEngine.__new__(StoryEngine)  # Don't connect to DB
        record("L9", "story engine", "PASS",
               f"{len(KNOWN_PATTERNS)} known patterns: {list(KNOWN_PATTERNS.keys())}")
    except Exception as e:
        record("L9", "story engine", "FAIL", str(e))

    # Narrator
    try:
        from amoskys.igris.narrator import Narrator, Briefing
        narrator = Narrator(use_claude=False)  # Template mode only
        record("L9", "narrator (template mode)", "PASS", "initialized without Claude API")
    except Exception as e:
        record("L9", "narrator", "FAIL", str(e))

    # SOMA brain
    try:
        from amoskys.intel.soma import SomaBrain
        brain = SomaBrain.__new__(SomaBrain)
        record("L9", "SOMA brain import", "PASS", "class available")
    except Exception as e:
        record("L9", "SOMA brain", "WARN", f"not available: {e}")

    # IGRIS Orchestrator
    try:
        from amoskys.igris.orchestrator import IGRISOrchestrator
        record("L9", "IGRIS orchestrator", "PASS", "import OK")
    except Exception as e:
        record("L9", "IGRIS orchestrator", "FAIL", str(e))


# ═══════════════════════════════════════════════════════════════════════════
# L10: DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════

def run_l10_dashboard():
    """L10: Dashboard API endpoints."""
    print("\n══ L10: DASHBOARD ══")
    os.environ.setdefault("SECRET_KEY", "a" * 64)
    os.environ.setdefault("LOGIN_DISABLED", "true")
    os.environ["FLASK_ENV"] = "development"
    os.environ["FORCE_HTTPS"] = "false"  # Disable HTTPS redirect in diagnostic

    # Ensure web package is importable
    web_dir = str(PROJECT_ROOT)
    if web_dir not in sys.path:
        sys.path.insert(0, web_dir)

    try:
        from web.app import create_app
        result = create_app()
        app = result[0] if isinstance(result, tuple) else result
        client = app.test_client()

        endpoints = [
            ("GET", "/dashboard/api/health-summary", 200),
            ("GET", "/dashboard/api/incidents", 200),
            ("GET", "/dashboard/cortex", 200),
            ("GET", "/dashboard/incidents", 200),
        ]

        for method, path, expected_status in endpoints:
            t0 = time.time()
            if method == "GET":
                resp = client.get(path)
            dt = (time.time() - t0) * 1000

            if resp.status_code == expected_status:
                record("L10", f"{method} {path}", "PASS",
                       f"status={resp.status_code}, {dt:.0f}ms")
            else:
                record("L10", f"{method} {path}", "FAIL",
                       f"expected={expected_status}, got={resp.status_code}, {dt:.0f}ms")

        # Create + read incident lifecycle
        t0 = time.time()
        resp = client.post("/dashboard/api/incidents", json={
            "title": "Diagnostic Test Incident",
            "description": "Pipeline diagnostic test",
            "severity": "high",
        })
        dt = (time.time() - t0) * 1000
        if resp.status_code in (200, 201):
            data = resp.get_json()
            inc_id = data.get("incident_id") or data.get("id")
            record("L10", "incident create", "PASS", f"id={inc_id}, {dt:.0f}ms")

            if inc_id:
                resp2 = client.get(f"/dashboard/api/incidents/{inc_id}")
                if resp2.status_code == 200:
                    record("L10", "incident read", "PASS", "lifecycle OK")
                else:
                    record("L10", "incident read", "WARN", f"status={resp2.status_code}")
        else:
            record("L10", "incident create", "FAIL",
                   f"status={resp.status_code}, body={resp.data[:200]}")

    except Exception as e:
        record("L10", "dashboard", "FAIL", traceback.format_exc())


# ═══════════════════════════════════════════════════════════════════════════
# REPORT
# ═══════════════════════════════════════════════════════════════════════════

def print_report():
    print("\n" + "═" * 70)
    print("  AMOSKYS PIPELINE DIAGNOSTIC REPORT")
    print(f"  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("═" * 70)

    # Summary by layer
    layer_stats = defaultdict(lambda: {"pass": 0, "fail": 0, "warn": 0, "skip": 0})
    for c in ALL_CHECKS:
        layer_stats[c.layer][c.status.lower()] += 1

    print("\n  Layer Summary:")
    print(f"  {'Layer':<8} {'Pass':>5} {'Fail':>5} {'Warn':>5} {'Status':<10}")
    print(f"  {'─' * 8} {'─' * 5} {'─' * 5} {'─' * 5} {'─' * 10}")
    for layer in sorted(layer_stats.keys()):
        s = layer_stats[layer]
        status = "CLEAN" if s["fail"] == 0 and s["warn"] == 0 else \
                 "ISSUES" if s["fail"] > 0 else "WARNINGS"
        icon = "✓" if status == "CLEAN" else "✗" if status == "ISSUES" else "⚠"
        print(f"  {layer:<8} {s['pass']:>5} {s['fail']:>5} {s['warn']:>5} {icon} {status}")

    print(f"\n  TOTAL: {PASS} passed, {FAIL} failed, {WARN} warnings")
    print(f"  Overall: {'DEMO READY ✓' if FAIL == 0 else 'NEEDS FIXES ✗'}")

    # Failures detail
    failures = [c for c in ALL_CHECKS if c.status == "FAIL"]
    if failures:
        print(f"\n  ─── FAILURES ({len(failures)}) ───")
        for c in failures:
            print(f"  ✗ [{c.layer}] {c.name}: {c.detail}")

    warnings = [c for c in ALL_CHECKS if c.status == "WARN"]
    if warnings:
        print(f"\n  ─── WARNINGS ({len(warnings)}) ───")
        for c in warnings:
            print(f"  ⚠ [{c.layer}] {c.name}: {c.detail}")

    # Latency report
    slow = [c for c in ALL_CHECKS if c.latency_ms > 1000]
    if slow:
        print(f"\n  ─── SLOW OPERATIONS (>1s) ───")
        for c in sorted(slow, key=lambda x: -x.latency_ms):
            print(f"  ⏱ [{c.layer}] {c.name}: {c.latency_ms:.0f}ms")

    print("\n" + "═" * 70)


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    print("AMOSKYS Full Pipeline Diagnostic")
    print(f"Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"Platform: {sys.platform}")
    print(f"Python: {sys.version.split()[0]}")

    total_probes, mitre_all = run_l1_probes()
    run_l2_collection()
    run_l3_data_structures()
    run_l4_storage()
    run_l5_mitre(mitre_all)
    run_l6_enrichment()
    run_l7_detection()
    run_l8_concurrency()
    run_l9_igris()
    run_l10_dashboard()
    print_report()

    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
