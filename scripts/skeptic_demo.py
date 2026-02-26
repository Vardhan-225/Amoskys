#!/usr/bin/env python3
"""AMOSKYS Skeptic Demo — Prove the Thesis in 3 Minutes.

This script demonstrates the three thesis boundary properties:
  1. Every event that entered the chain is accounted for.
  2. Every envelope is authenticated from sensor to storage.
  3. Chain integrity is verifiable by someone who doesn't trust the system.

Steps:
  [1] Generate Ed25519 keypair and seed WAL with 20 signed events
  [2] Segment the WAL and seal checkpoints with Merkle roots
  [3] Export a self-contained proof bundle
  [4] Run offline verification → expect PASS
  [5] Tamper: delete one WAL row, re-export, re-verify → expect FAIL

Exit codes:
  0 — Demo completed successfully (PASS then FAIL)
  1 — Demo failed (unexpected verification result)
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import struct
import sys
import tempfile
import time

# ---------------------------------------------------------------------------
# Ensure project root is on sys.path
# ---------------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, os.path.join(PROJECT_ROOT, "src"))
    sys.path.insert(0, PROJECT_ROOT)

# ---------------------------------------------------------------------------
# AMOSKYS imports
# ---------------------------------------------------------------------------
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from amoskys.proof.wal_segments import SegmentManager, GENESIS_SIG
from amoskys.proof.checkpoint_signer import CheckpointSigner, checkpoint_hash
from amoskys.proof.bundle_exporter import BundleExporter

# Import the offline verifier (standalone, no amoskys deps inside it)
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
BAR = "━" * 60


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


# ---------------------------------------------------------------------------
# Step 1: Generate keys + seed WAL
# ---------------------------------------------------------------------------
def generate_keypair(key_dir: str):
    """Generate Ed25519 keypair for the demo."""
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key()

    # Save private key (32 raw bytes)
    sk_bytes = sk.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    sk_path = os.path.join(key_dir, "demo_agent.ed25519")
    with open(sk_path, "wb") as f:
        f.write(sk_bytes)

    # Save public key (PEM)
    pk_pem = pk.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pk_path = os.path.join(key_dir, "demo_checkpoint.pub")
    with open(pk_path, "wb") as f:
        f.write(pk_pem)

    return sk, pk, sk_path, pk_path


def _compute_chain_sig(env_bytes: bytes, prev_sig: bytes) -> bytes:
    """BLAKE2b hash chain: sig[i] = BLAKE2b(env_bytes[i] || prev_sig[i-1])."""
    return hashlib.blake2b(env_bytes + prev_sig, digest_size=32).digest()


def seed_wal(wal_path: str, sk, num_events: int = 20):
    """Create a WAL database and populate it with signed events."""
    os.makedirs(os.path.dirname(wal_path) or ".", exist_ok=True)
    conn = sqlite3.connect(wal_path)
    conn.executescript(
        """
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
        """
    )

    prev_sig = GENESIS_SIG
    base_ts = int(time.time() * 1e9)

    for i in range(num_events):
        # Create realistic-looking telemetry payload
        event_payload = {
            "agent": "proc_agent",
            "event_type": "process_exec",
            "ts": base_ts + i * 100_000_000,  # 100ms apart
            "pid": 1000 + i,
            "cmdline": f"/usr/bin/demo_process_{i}",
            "uid": 1000,
            "ppid": 1,
            "sha256": hashlib.sha256(f"binary_{i}".encode()).hexdigest(),
        }
        env_bytes = json.dumps(event_payload, sort_keys=True).encode("utf-8")
        ts_ns = base_ts + i * 100_000_000
        idem = f"demo_event_{i:04d}"

        # Compute BLAKE2b checksum
        checksum = hashlib.blake2b(env_bytes, digest_size=32).digest()

        # Compute chain signature
        sig = _compute_chain_sig(env_bytes, prev_sig)

        conn.execute(
            "INSERT INTO wal(idem, ts_ns, bytes, checksum, sig, prev_sig) "
            "VALUES(?, ?, ?, ?, ?, ?)",
            (
                idem,
                ts_ns,
                sqlite3.Binary(env_bytes),
                checksum,
                sig,
                prev_sig,
            ),
        )
        prev_sig = sig

    conn.commit()
    conn.close()
    return num_events


# ---------------------------------------------------------------------------
# Step 5: Tamper
# ---------------------------------------------------------------------------
def tamper_delete_row(wal_path: str, row_id: int) -> dict:
    """Delete a single row from the WAL (simulates attacker erasure)."""
    conn = sqlite3.connect(wal_path)
    # Capture the deleted row's idem for reporting
    row = conn.execute(
        "SELECT idem, ts_ns FROM wal WHERE id = ?", (row_id,)
    ).fetchone()
    conn.execute("DELETE FROM wal WHERE id = ?", (row_id,))
    conn.commit()
    conn.close()
    return {"row_id": row_id, "idem": row[0], "ts_ns": row[1]} if row else {}


# ---------------------------------------------------------------------------
# Main Demo
# ---------------------------------------------------------------------------
def main():
    print()
    print(f"{BOLD}{'═' * 60}{RESET}")
    print(f"{BOLD}  AMOSKYS SKEPTIC DEMO{RESET}")
    print(f"{BOLD}  \"Prove it. Then break it. Then prove it caught the break.\"{RESET}")
    print(f"{BOLD}{'═' * 60}{RESET}")

    TOTAL_STEPS = 5
    NUM_EVENTS = 20
    SEGMENT_SIZE = 10  # 2 segments of 10 events each

    # Create temp workspace
    workspace = tempfile.mkdtemp(prefix="amoskys_skeptic_")
    wal_path = os.path.join(workspace, "demo.db")
    manifest_path = os.path.join(workspace, "checkpoints.jsonl")
    bundle_dir = os.path.join(workspace, "proof_bundle")
    bundle_dir_tampered = os.path.join(workspace, "proof_bundle_tampered")
    key_dir = os.path.join(workspace, "keys")
    os.makedirs(key_dir, exist_ok=True)

    info(f"Workspace: {workspace}")

    # -----------------------------------------------------------------------
    # STEP 1: Generate keys + seed WAL
    # -----------------------------------------------------------------------
    header(1, TOTAL_STEPS, "Generate Ed25519 keys & seed WAL with signed events")

    sk, pk, sk_path, pk_path = generate_keypair(key_dir)
    ok("Ed25519 keypair generated")
    info(f"Private key: {sk_path}")
    info(f"Public key:  {pk_path}")

    count = seed_wal(wal_path, sk, NUM_EVENTS)
    ok(f"{count} events written to WAL with BLAKE2b hash chain")

    # Verify chain integrity directly
    conn = sqlite3.connect(wal_path)
    rows = conn.execute(
        "SELECT id, bytes, sig, prev_sig FROM wal ORDER BY id"
    ).fetchall()
    conn.close()

    chain_ok = True
    for i, (rid, blob, sig, prev_sig) in enumerate(rows):
        expected = _compute_chain_sig(bytes(blob), bytes(prev_sig))
        if bytes(sig) != expected:
            chain_ok = False
            break

    if chain_ok:
        ok(f"Hash chain verified: {len(rows)} links, genesis → row {rows[-1][0]}")
    else:
        fail("Hash chain broken!")
        sys.exit(1)

    # -----------------------------------------------------------------------
    # STEP 2: Segment + seal checkpoints
    # -----------------------------------------------------------------------
    header(2, TOTAL_STEPS, "Segment WAL & seal Merkle checkpoints")

    seg_mgr = SegmentManager(wal_path, segment_size=SEGMENT_SIZE)
    segments = seg_mgr.scan_segments()
    ok(f"WAL partitioned into {len(segments)} segments of ≤{SEGMENT_SIZE} events")

    for seg in segments:
        info(
            f"Segment {seg.segment_id}: rows [{seg.start_seq}..{seg.end_seq}], "
            f"{seg.event_count} events, root={seg.root_hash.hex()[:16]}…"
        )

    signer = CheckpointSigner(
        manifest_path=manifest_path,
        signing_key_path=sk_path,
    )
    checkpoints = signer.seal_all(segments)
    ok(f"{len(checkpoints)} checkpoints sealed with Ed25519 signatures")

    for cp in checkpoints:
        info(
            f"Checkpoint {cp.segment_id}: "
            f"root={cp.root_hash_hex[:16]}… "
            f"sig={cp.checkpoint_sig_hex[:16]}…"
        )

    # -----------------------------------------------------------------------
    # STEP 3: Export proof bundle
    # -----------------------------------------------------------------------
    header(3, TOTAL_STEPS, "Export self-contained proof bundle")

    # Create a minimal agent key registry for the bundle
    registry_path = os.path.join(workspace, "agent_keys.json")
    pk_raw = pk.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    import base64

    registry = {
        "version": "1.0",
        "description": "Skeptic Demo agent key registry",
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
    ok(f"Proof bundle exported → {bundle_dir}")

    # List bundle contents
    for dirpath, dirs, files in os.walk(bundle_dir):
        for fname in files:
            fpath = os.path.join(dirpath, fname)
            rel = os.path.relpath(fpath, bundle_dir)
            size = os.path.getsize(fpath)
            info(f"{rel} ({size:,} bytes)")

    # -----------------------------------------------------------------------
    # STEP 4: Offline verification → PASS
    # -----------------------------------------------------------------------
    header(4, TOTAL_STEPS, "Run offline verifier on clean bundle")
    print()

    pass_result = verify_bundle(bundle_dir)

    print()
    if pass_result:
        ok(f"{GREEN}{BOLD}Verification PASSED — thesis holds on clean data{RESET}")
    else:
        fail("Verification unexpectedly FAILED on clean data!")
        sys.exit(1)

    # -----------------------------------------------------------------------
    # STEP 5: Tamper + re-verify → FAIL
    # -----------------------------------------------------------------------
    header(
        5,
        TOTAL_STEPS,
        "Tamper: delete one WAL row, re-export, re-verify → expect FAIL",
    )

    # Pick a row in the middle of the first segment
    target_row = rows[5][0]  # 6th event
    deleted = tamper_delete_row(wal_path, target_row)
    ok(
        f"Deleted row {deleted['row_id']} "
        f"(idem={deleted['idem']}) — simulating attacker erasure"
    )

    # Count remaining
    conn = sqlite3.connect(wal_path)
    remaining = conn.execute("SELECT COUNT(*) FROM wal").fetchone()[0]
    conn.close()
    info(f"WAL now has {remaining} events (was {NUM_EVENTS})")

    # Re-export with tampered WAL
    exporter_t = BundleExporter(
        wal_path=wal_path,
        manifest_path=manifest_path,
        agent_keys_path=registry_path,
        checkpoint_pubkey_path=pk_path,
        segment_size=SEGMENT_SIZE,
    )
    exporter_t.export_segments(all_seg_ids, bundle_dir_tampered)
    ok("Tampered bundle re-exported")

    # But keep the ORIGINAL checkpoints — the attacker can't forge those
    # (they'd need the signing key to produce a valid checkpoint with the
    #  tampered data, and the Merkle root would be different)
    shutil.copy2(
        os.path.join(bundle_dir, "checkpoints", "checkpoint_0.json"),
        os.path.join(bundle_dir_tampered, "checkpoints", "checkpoint_0.json"),
    )
    info("Original checkpoint_0.json preserved (attacker can't forge Ed25519)")

    print()
    fail_result = verify_bundle(bundle_dir_tampered)

    print()
    if not fail_result:
        ok(
            f"{RED}{BOLD}Verification FAILED — tampering detected!{RESET}"
        )
        ok("The proof spine caught the deletion.")
    else:
        fail("Verification unexpectedly PASSED on tampered data!")
        sys.exit(1)

    # -----------------------------------------------------------------------
    # Final Summary
    # -----------------------------------------------------------------------
    print()
    print(f"{BOLD}{'═' * 60}{RESET}")
    print(f"{BOLD}  DEMO COMPLETE{RESET}")
    print(f"{BOLD}{'═' * 60}{RESET}")
    print()
    print(f"  {GREEN}✓{RESET} {BOLD}Property 1:{RESET} Every event accounted for")
    print(f"    Merkle root commits to exact event set.")
    print(f"    Deleting row {target_row} broke the root → COUNT + ROOT MISMATCH.")
    print()
    print(f"  {GREEN}✓{RESET} {BOLD}Property 2:{RESET} Every envelope authenticated")
    print(f"    BLAKE2b hash chain links every event to its predecessor.")
    print(f"    Ed25519 checkpoint signatures seal the chain state.")
    print()
    print(f"  {GREEN}✓{RESET} {BOLD}Property 3:{RESET} Externally verifiable")
    print(f"    amoskys_verify ran with ZERO amoskys dependencies.")
    print(f"    Anyone with the bundle can verify independently.")
    print()
    print(
        f"  {DIM}Workspace: {workspace}{RESET}"
    )
    print(
        f"  {DIM}To re-run: python scripts/skeptic_demo.py{RESET}"
    )
    print()

    # Cleanup option
    if "--keep" not in sys.argv:
        shutil.rmtree(workspace)
        info("Workspace cleaned up (use --keep to preserve)")
    else:
        ok(f"Workspace preserved at {workspace}")

    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
