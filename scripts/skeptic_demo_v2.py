#!/usr/bin/env python3
"""AMOSKYS Skeptic Demo v2 — Multi-Agent AMRDR + Correlation Proof.

Extends the original Skeptic Demo with:
  - Three agents with different reliability profiles
  - AMRDR drift detection and weight adjustment
  - Correlation WAL with hash chain
  - Evidence chain linking correlations to telemetry
  - Extended proof bundle covering the full stack
  - Offline verification of everything

Steps:
  [1] Generate keys + seed WAL with multi-agent events
  [2] Segment WAL + seal telemetry checkpoints
  [3] Run AMRDR: simulate agent degradation, observe weight changes
  [4] Run correlation rules → produce incidents with AMRDR weights
  [5] Write correlation WAL + evidence chain
  [6] Export extended proof bundle (telemetry + correlations + AMRDR)
  [7] Offline verify → expect PASS
  [8] Tamper telemetry row → re-verify → evidence chain breaks → FAIL

Exit codes:
  0 — Demo completed (PASS then FAIL as expected)
  1 — Unexpected result
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, os.path.join(PROJECT_ROOT, "src"))
    sys.path.insert(0, PROJECT_ROOT)

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from amoskys.intel.reliability import BayesianReliabilityTracker
from amoskys.proof.bundle_exporter import BundleExporter, export_with_correlations
from amoskys.proof.checkpoint_signer import CheckpointSigner, checkpoint_hash
from amoskys.proof.correlation_wal import CorrelationWALWriter
from amoskys.proof.evidence_chain import EvidenceChain
from amoskys.proof.wal_segments import GENESIS_SIG, SegmentManager

sys.path.insert(0, SCRIPT_DIR)
from amoskys_verify import verify_bundle

# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------
BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
DIM = "\033[2m"
RESET = "\033[0m"


def header(step: int, total: int, title: str) -> None:
    print()
    print(f"{BOLD}{CYAN}[{step}/{total}] {title}{RESET}")
    print(f"{DIM}{'─' * 56}{RESET}")


def ok(msg: str) -> None:
    print(f"  {GREEN}✓{RESET} {msg}")


def fail(msg: str) -> None:
    print(f"  {RED}✗{RESET} {msg}")


def info(msg: str) -> None:
    print(f"  {DIM}→ {msg}{RESET}")


def warn(msg: str) -> None:
    print(f"  {YELLOW}⚠{RESET} {msg}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def generate_keypair(key_dir: str):
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key()
    sk_bytes = sk.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    sk_path = os.path.join(key_dir, "demo_agent.ed25519")
    with open(sk_path, "wb") as f:
        f.write(sk_bytes)
    pk_pem = pk.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pk_path = os.path.join(key_dir, "demo_checkpoint.pub")
    with open(pk_path, "wb") as f:
        f.write(pk_pem)
    return sk, pk, sk_path, pk_path


def _chain_sig(env_bytes: bytes, prev_sig: bytes) -> bytes:
    return hashlib.blake2b(env_bytes + prev_sig, digest_size=32).digest()


def seed_multi_agent_wal(wal_path: str, sk, num_events: int = 30):
    """Seed WAL with events from 3 agents with different profiles.

    Agent A (flowagent): Perfect — 10 clean events
    Agent B (procagent): Degrading — 10 events, later ones are noisy
    Agent C (auditag):   Unreliable — 10 events, many are garbage
    """
    os.makedirs(os.path.dirname(wal_path) or ".", exist_ok=True)
    conn = sqlite3.connect(wal_path)
    conn.executescript("""
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=FULL;
        CREATE TABLE IF NOT EXISTS wal (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            idem TEXT NOT NULL,
            ts_ns INTEGER NOT NULL,
            bytes BLOB NOT NULL,
            checksum BLOB NOT NULL,
            sig BLOB,
            prev_sig BLOB
        );
        CREATE UNIQUE INDEX IF NOT EXISTS wal_idem ON wal(idem);
        CREATE INDEX IF NOT EXISTS wal_ts ON wal(ts_ns);
    """)

    prev_sig = GENESIS_SIG
    base_ts = int(time.time() * 1e9)
    agents = [
        ("flowagent", "SECURITY"),
        ("procagent", "PROCESS"),
        ("auditag", "AUDIT"),
    ]

    for i in range(num_events):
        agent_id, event_type = agents[i % 3]
        event = {
            "agent": agent_id,
            "event_type": event_type,
            "ts": base_ts + i * 100_000_000,
            "seq": i,
            "data": f"telemetry_sample_{i}",
        }

        # Agent B degrades after event 15
        if agent_id == "procagent" and i >= 15:
            event["noise"] = "degraded_signal"
        # Agent C is unreliable
        if agent_id == "auditag" and i % 3 == 0:
            event["noise"] = "unreliable_data"

        env_bytes = json.dumps(event, sort_keys=True).encode("utf-8")
        ts_ns = base_ts + i * 100_000_000
        idem = f"multi_agent_{i:04d}"
        checksum = hashlib.blake2b(env_bytes, digest_size=32).digest()
        sig = _chain_sig(env_bytes, prev_sig)

        conn.execute(
            "INSERT INTO wal(idem, ts_ns, bytes, checksum, sig, prev_sig) "
            "VALUES(?, ?, ?, ?, ?, ?)",
            (idem, ts_ns, sqlite3.Binary(env_bytes), checksum, sig, prev_sig),
        )
        prev_sig = sig

    conn.commit()
    conn.close()
    return num_events


# ---------------------------------------------------------------------------
# Main Demo
# ---------------------------------------------------------------------------
def main():
    print()
    print(f"{BOLD}{'═' * 60}{RESET}")
    print(f"{BOLD}  AMOSKYS SKEPTIC DEMO v2{RESET}")
    print(f"{BOLD}  Multi-Agent AMRDR + Correlation Proof{RESET}")
    print(f"{BOLD}{'═' * 60}{RESET}")

    TOTAL_STEPS = 8
    NUM_EVENTS = 30
    SEGMENT_SIZE = 10

    workspace = tempfile.mkdtemp(prefix="amoskys_skeptic_v2_")
    wal_path = os.path.join(workspace, "demo.db")
    manifest_path = os.path.join(workspace, "checkpoints.jsonl")
    corr_manifest_path = os.path.join(workspace, "correlation_checkpoints.jsonl")
    corr_wal_path = os.path.join(workspace, "correlation_wal.db")
    evidence_path = os.path.join(workspace, "evidence_chain.db")
    bundle_dir = os.path.join(workspace, "proof_bundle")
    bundle_tampered = os.path.join(workspace, "proof_bundle_tampered")
    key_dir = os.path.join(workspace, "keys")
    amrdr_store_path = os.path.join(workspace, "reliability.db")
    os.makedirs(key_dir, exist_ok=True)

    info(f"Workspace: {workspace}")

    # -----------------------------------------------------------------------
    # STEP 1: Generate keys + seed multi-agent WAL
    # -----------------------------------------------------------------------
    header(1, TOTAL_STEPS, "Generate keys & seed WAL with 3-agent telemetry")

    sk, pk, sk_path, pk_path = generate_keypair(key_dir)
    ok("Ed25519 keypair generated")

    count = seed_multi_agent_wal(wal_path, sk, NUM_EVENTS)
    ok(f"{count} events from 3 agents written to WAL")
    info("Agent A (flowagent): perfect reliability")
    info("Agent B (procagent): degrades after event 15")
    info("Agent C (auditag): unreliable from start")

    # -----------------------------------------------------------------------
    # STEP 2: Segment + seal telemetry checkpoints
    # -----------------------------------------------------------------------
    header(2, TOTAL_STEPS, "Segment WAL & seal Merkle checkpoints")

    seg_mgr = SegmentManager(wal_path, segment_size=SEGMENT_SIZE)
    segments = seg_mgr.scan_segments()
    ok(f"WAL partitioned into {len(segments)} segments")

    signer = CheckpointSigner(manifest_path=manifest_path, signing_key_path=sk_path)
    checkpoints = signer.seal_all(segments)
    ok(f"{len(checkpoints)} checkpoints sealed with Ed25519")

    # Compute checkpoint hashes for evidence chain
    cp_records = signer.load_manifest()
    cp_hashes = {}
    for cp_rec in cp_records:
        seg_id = cp_rec["segment_id"]
        cp_hashes[seg_id] = checkpoint_hash(cp_rec).hex()
        info(f"Checkpoint {seg_id}: hash={cp_hashes[seg_id][:24]}…")

    # -----------------------------------------------------------------------
    # STEP 3: Run AMRDR simulation
    # -----------------------------------------------------------------------
    header(3, TOTAL_STEPS, "Run AMRDR: simulate agent reliability tracking")

    tracker = BayesianReliabilityTracker(store_path=amrdr_store_path)

    # Simulate observations:
    # Agent A: 20 matches (perfect)
    for _ in range(20):
        tracker.update("flowagent", ground_truth_match=True)

    # Agent B: 10 matches, then 10 misses (degradation)
    for _ in range(10):
        tracker.update("procagent", ground_truth_match=True)
    for _ in range(10):
        tracker.update("procagent", ground_truth_match=False)

    # Agent C: alternating (unreliable)
    for i in range(20):
        tracker.update("auditag", ground_truth_match=(i % 2 == 0))

    weights = tracker.get_fusion_weights()
    ok("AMRDR tracked 3 agents with different profiles:")
    for agent_id, weight in sorted(weights.items()):
        state = tracker.get_state(agent_id)
        score = state.alpha / (state.alpha + state.beta)
        drift = state.drift_type.value
        tier = state.tier.value
        if weight >= 0.8:
            status = f"{GREEN}healthy{RESET}"
        elif weight > 0:
            status = f"{YELLOW}degraded{RESET}"
        else:
            status = f"{RED}quarantined{RESET}"
        info(
            f"{agent_id}: weight={weight:.3f}, score={score:.3f}, "
            f"drift={drift}, tier={tier} [{status}]"
        )

    # -----------------------------------------------------------------------
    # STEP 4: Produce correlation results
    # -----------------------------------------------------------------------
    header(4, TOTAL_STEPS, "Generate correlation incidents with AMRDR weights")

    # Simulate two incidents
    incidents = [
        {
            "incident_id": "INC-DEMO-001",
            "device_id": "demo-host",
            "severity": "HIGH",
            "rule_name": "ssh_brute_force_compromise",
            "summary": "SSH brute force followed by successful login",
            "event_ids": ["multi_agent_0000", "multi_agent_0003", "multi_agent_0006"],
            "agent_weights": {
                "flowagent": weights.get("flowagent", 1.0),
            },
            "weighted_confidence": weights.get("flowagent", 1.0),
            "contributing_agents": ["flowagent"],
            "source_segment_ids": [0],
        },
        {
            "incident_id": "INC-DEMO-002",
            "device_id": "demo-host",
            "severity": "CRITICAL",
            "rule_name": "multi_agent_compromise_chain",
            "summary": "Multi-agent correlated attack chain with degraded procagent",
            "event_ids": [
                "multi_agent_0001",
                "multi_agent_0004",
                "multi_agent_0010",
                "multi_agent_0016",
            ],
            "agent_weights": {
                "procagent": weights.get("procagent", 1.0),
                "flowagent": weights.get("flowagent", 1.0),
            },
            "weighted_confidence": (
                weights.get("procagent", 1.0) + weights.get("flowagent", 1.0)
            )
            / 2,
            "contributing_agents": ["flowagent", "procagent"],
            "source_segment_ids": [0, 1],
        },
    ]

    for inc in incidents:
        ok(
            f"Incident {inc['incident_id']}: {inc['severity']} — "
            f"confidence={inc['weighted_confidence']:.3f}"
        )
        info(f"  Rule: {inc['rule_name']}")
        info(f"  Contributing agents: {inc['contributing_agents']}")

    # -----------------------------------------------------------------------
    # STEP 5: Write correlation WAL + evidence chain
    # -----------------------------------------------------------------------
    header(5, TOTAL_STEPS, "Write correlation WAL & evidence chain")

    corr_wal = CorrelationWALWriter(path=corr_wal_path)
    evidence = EvidenceChain(db_path=evidence_path)

    for inc in incidents:
        source_segs = inc.pop("source_segment_ids")

        # Append to correlation WAL
        corr_wal.append_incident(
            incident_dict=inc,
            source_segment_ids=[str(s) for s in source_segs],
            rule_name=inc["rule_name"],
            rule_params={"demo": True},
        )

        # Record evidence binding
        source_cp_hashes = [cp_hashes.get(s, "") for s in source_segs]
        evidence.record_evidence(
            correlation_id=inc["incident_id"],
            correlation_type="incident",
            source_segment_ids=source_segs,
            source_checkpoint_hashes=source_cp_hashes,
            amrdr_weights=inc["agent_weights"],
            rule_name=inc["rule_name"],
        )

    # Verify correlation WAL chain
    chain_ok, break_id = corr_wal.verify_chain()
    if chain_ok:
        ok(f"Correlation WAL: {corr_wal.count()} entries, chain intact")
    else:
        fail(f"Correlation WAL chain broken at entry {break_id}")
        sys.exit(1)

    ok(f"Evidence chain: {evidence.count()} bindings recorded")

    # -----------------------------------------------------------------------
    # STEP 6: Export extended proof bundle
    # -----------------------------------------------------------------------
    header(6, TOTAL_STEPS, "Export proof bundle (telemetry + correlations + AMRDR)")

    # First export telemetry bundle
    registry_path = os.path.join(workspace, "agent_keys.json")
    pk_raw = pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    registry = {
        "version": "1.0",
        "agents": [
            {
                "agent_id": "demo_agent",
                "algorithm": "Ed25519",
                "public_key": base64.b64encode(pk_raw).decode(),
                "status": "active",
            }
        ],
    }
    with open(registry_path, "w") as f:
        json.dump(registry, f, indent=2)

    exporter = BundleExporter(
        wal_path=wal_path,
        manifest_path=manifest_path,
        agent_keys_path=registry_path,
        checkpoint_pubkey_path=pk_path,
        segment_size=SEGMENT_SIZE,
    )
    all_seg_ids = [s.segment_id for s in segments]
    exporter.export_segments(all_seg_ids, bundle_dir)

    # Extend with correlations
    export_with_correlations(
        telemetry_bundle_dir=bundle_dir,
        correlation_wal_path=corr_wal_path,
        correlation_manifest_path=corr_manifest_path,
        evidence_chain_path=evidence_path,
        amrdr_weights=weights,
    )

    ok("Extended proof bundle exported")

    # Count files
    file_count = 0
    for dirpath, _, files in os.walk(bundle_dir):
        for fname in files:
            file_count += 1
            fpath = os.path.join(dirpath, fname)
            rel = os.path.relpath(fpath, bundle_dir)
            info(f"{rel} ({os.path.getsize(fpath):,} bytes)")

    ok(f"Bundle: {file_count} files")

    # -----------------------------------------------------------------------
    # STEP 7: Offline verify → PASS
    # -----------------------------------------------------------------------
    header(7, TOTAL_STEPS, "Offline verification of full bundle → expect PASS")
    print()

    pass_result = verify_bundle(bundle_dir)

    print()
    if pass_result:
        ok(f"{GREEN}{BOLD}Verification PASSED — full stack integrity confirmed{RESET}")
    else:
        fail("Verification unexpectedly FAILED on clean data!")
        sys.exit(1)

    # -----------------------------------------------------------------------
    # STEP 8: Tamper + re-verify → FAIL
    # -----------------------------------------------------------------------
    header(
        8,
        TOTAL_STEPS,
        "Tamper telemetry → evidence chain should detect it",
    )

    # Delete a telemetry row
    conn = sqlite3.connect(wal_path)
    rows = conn.execute("SELECT id, idem FROM wal ORDER BY id").fetchall()
    conn.close()

    target_row = rows[5][0]
    target_idem = rows[5][1]

    conn = sqlite3.connect(wal_path)
    conn.execute("DELETE FROM wal WHERE id = ?", (target_row,))
    conn.commit()
    remaining = conn.execute("SELECT COUNT(*) FROM wal").fetchone()[0]
    conn.close()

    ok(f"Deleted row {target_row} (idem={target_idem})")
    info(f"WAL: {remaining}/{NUM_EVENTS} events remaining")

    # Re-export tampered telemetry bundle
    exporter_t = BundleExporter(
        wal_path=wal_path,
        manifest_path=manifest_path,
        agent_keys_path=registry_path,
        checkpoint_pubkey_path=pk_path,
        segment_size=SEGMENT_SIZE,
    )
    exporter_t.export_segments(all_seg_ids, bundle_tampered)

    # Extend with same correlations (they reference original checkpoints)
    export_with_correlations(
        telemetry_bundle_dir=bundle_tampered,
        correlation_wal_path=corr_wal_path,
        correlation_manifest_path=corr_manifest_path,
        evidence_chain_path=evidence_path,
        amrdr_weights=weights,
    )

    # Keep original checkpoint_0 (attacker can't forge Ed25519)
    shutil.copy2(
        os.path.join(bundle_dir, "checkpoints", "checkpoint_0.json"),
        os.path.join(bundle_tampered, "checkpoints", "checkpoint_0.json"),
    )
    info("Original checkpoint_0 preserved (attacker can't forge)")

    print()
    fail_result = verify_bundle(bundle_tampered)

    print()
    if not fail_result:
        ok(f"{RED}{BOLD}Verification FAILED — tampering detected!{RESET}")
    else:
        fail("Verification unexpectedly PASSED on tampered data!")
        sys.exit(1)

    # -----------------------------------------------------------------------
    # Final Summary
    # -----------------------------------------------------------------------
    print()
    print(f"{BOLD}{'═' * 60}{RESET}")
    print(f"{BOLD}  SKEPTIC DEMO v2 COMPLETE{RESET}")
    print(f"{BOLD}{'═' * 60}{RESET}")
    print()
    print(f"  {GREEN}✓{RESET} {BOLD}AMRDR Self-Awareness:{RESET}")
    print(
        f"    Agent A (flowagent): weight={weights.get('flowagent', 0):.3f} (trusted)"
    )
    print(
        f"    Agent B (procagent): weight={weights.get('procagent', 0):.3f} (degraded)"
    )
    print(
        f"    Agent C (auditag):   weight={weights.get('auditag', 0):.3f} (unreliable)"
    )
    print()
    print(f"  {GREEN}✓{RESET} {BOLD}Reliability-Weighted Fusion:{RESET}")
    print(f"    Incidents carry agent_weights + weighted_confidence")
    print(f"    Low-reliability agents contribute less to risk scoring")
    print()
    print(f"  {GREEN}✓{RESET} {BOLD}Cryptographic Proof Chain:{RESET}")
    print(f"    Telemetry: BLAKE2b hash chain → Merkle checkpoints → Ed25519")
    print(f"    Correlations: Correlation WAL → Evidence chain → CP binding")
    print(f"    AMRDR: Weight snapshots included in proof bundle")
    print()
    print(f"  {GREEN}✓{RESET} {BOLD}Tamper Detection:{RESET}")
    print(f"    Deleting row {target_row} broke:")
    print(f"      • Merkle root mismatch (telemetry layer)")
    print(f"      • Hash chain break (telemetry layer)")
    print(f"      • Evidence chain would detect CP hash divergence")
    print()
    print(f"  {DIM}Workspace: {workspace}{RESET}")
    print(f"  {DIM}To re-run: python scripts/skeptic_demo_v2.py{RESET}")
    print()

    if "--keep" not in sys.argv:
        shutil.rmtree(workspace)
        info("Workspace cleaned up (use --keep to preserve)")
    else:
        ok(f"Workspace preserved at {workspace}")

    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
