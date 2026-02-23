#!/usr/bin/env python3
"""AMOSKYS WAL Hash Chain Auditor

Verifies the integrity of the Write-Ahead Log hash chain.
Each WAL row contains a signature that chains to the previous row's signature.
If any row is modified, deleted, or reordered, the chain breaks.

Usage:
    python -m scripts.audit_wal_chain                    # Audit default WAL
    python -m scripts.audit_wal_chain --wal data/wal/flowagent.db
    python -m scripts.audit_wal_chain --wal data/wal/flowagent.db --verbose
    python -m scripts.audit_wal_chain --wal data/wal/flowagent.db --json

Exit codes:
    0 — Chain intact, all rows verified
    1 — Chain broken (tampering detected)
    2 — WAL not found or unreadable
"""

import argparse
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

# Genesis signature: 32 zero bytes (must match wal_sqlite.py)
GENESIS_SIG = b"\x00" * 32


def audit_chain(wal_path: str, verbose: bool = False) -> dict:
    """Audit the hash chain integrity of a WAL database.

    Args:
        wal_path: Path to the WAL SQLite database
        verbose: If True, print per-row status

    Returns:
        dict with keys: total, verified, unchained, broken, first_break_id, intact
    """
    if not Path(wal_path).exists():
        return {"error": f"WAL not found: {wal_path}", "intact": False}

    try:
        conn = sqlite3.connect(wal_path, timeout=5.0)
    except sqlite3.Error as e:
        return {"error": f"Cannot open WAL: {e}", "intact": False}

    # Check if chain columns exist
    cols = {row[1] for row in conn.execute("PRAGMA table_info(wal)").fetchall()}
    has_chain = "sig" in cols and "prev_sig" in cols

    if not has_chain:
        row_count = conn.execute("SELECT COUNT(*) FROM wal").fetchone()[0]
        conn.close()
        return {
            "total": row_count,
            "verified": 0,
            "unchained": row_count,
            "broken": 0,
            "first_break_id": None,
            "intact": True,  # No chain to break — legacy WAL
            "note": "Legacy WAL without hash chain columns",
        }

    cursor = conn.execute(
        "SELECT id, bytes, checksum, sig, prev_sig FROM wal ORDER BY id"
    )

    total = 0
    verified = 0
    unchained = 0
    broken = 0
    first_break_id = None
    prev_expected_sig = GENESIS_SIG
    breaks = []

    for row_id, env_bytes, stored_checksum, stored_sig, stored_prev_sig in cursor:
        total += 1
        raw = bytes(env_bytes)

        # Skip rows without chain data (written before migration)
        if stored_sig is None or stored_prev_sig is None:
            unchained += 1
            if verbose:
                print(f"  [{row_id}] UNCHAINED (legacy row, no sig)")
            continue

        sig = bytes(stored_sig)
        prev_sig = bytes(stored_prev_sig)

        # Verify: prev_sig should match what we expect from the chain
        if prev_sig != prev_expected_sig:
            broken += 1
            if first_break_id is None:
                first_break_id = row_id
            breaks.append(
                {
                    "row_id": row_id,
                    "reason": "prev_sig does not match previous row's sig",
                }
            )
            if verbose:
                print(f"  [{row_id}] BROKEN — prev_sig mismatch")
        else:
            # Verify: sig should equal BLAKE2b(bytes || prev_sig)
            expected_sig = hashlib.blake2b(raw + prev_sig, digest_size=32).digest()
            if sig != expected_sig:
                broken += 1
                if first_break_id is None:
                    first_break_id = row_id
                breaks.append(
                    {
                        "row_id": row_id,
                        "reason": "sig does not match BLAKE2b(bytes || prev_sig)",
                    }
                )
                if verbose:
                    print(f"  [{row_id}] BROKEN — sig recomputation failed")
            else:
                verified += 1
                if verbose:
                    print(f"  [{row_id}] OK")

        # Advance chain expectation
        prev_expected_sig = sig

    # Also verify per-row checksums
    checksum_failures = 0
    cursor2 = conn.execute("SELECT id, bytes, checksum FROM wal ORDER BY id")
    for row_id, env_bytes, stored_checksum in cursor2:
        if stored_checksum is None:
            continue
        raw = bytes(env_bytes)
        expected = hashlib.blake2b(raw, digest_size=32).digest()
        if bytes(stored_checksum) != expected:
            checksum_failures += 1

    conn.close()

    return {
        "wal_path": str(wal_path),
        "total": total,
        "verified": verified,
        "unchained": unchained,
        "broken": broken,
        "checksum_failures": checksum_failures,
        "first_break_id": first_break_id,
        "breaks": breaks[:10],  # First 10 breaks for diagnostics
        "intact": broken == 0 and checksum_failures == 0,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Audit AMOSKYS WAL hash chain integrity"
    )
    parser.add_argument(
        "--wal",
        default="data/wal/flowagent.db",
        help="Path to WAL database (default: data/wal/flowagent.db)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Print per-row status"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output results as JSON",
    )
    args = parser.parse_args()

    result = audit_chain(args.wal, verbose=args.verbose)

    if args.json_output:
        print(json.dumps(result, indent=2, default=str))
    else:
        if "error" in result:
            print(f"ERROR: {result['error']}")
            sys.exit(2)

        print(f"WAL Chain Audit: {args.wal}")
        print(f"  Total rows:        {result['total']}")
        print(f"  Chain-verified:    {result['verified']}")
        print(f"  Unchained (legacy):{result['unchained']}")
        print(f"  Chain breaks:      {result['broken']}")
        print(f"  Checksum failures: {result['checksum_failures']}")

        if result["intact"]:
            print("\n  RESULT: CHAIN INTACT")
        else:
            print(
                f"\n  RESULT: CHAIN BROKEN (first break at row {result['first_break_id']})"
            )
            for b in result.get("breaks", [])[:5]:
                print(f"    - Row {b['row_id']}: {b['reason']}")

    sys.exit(0 if result.get("intact", False) else 1)


if __name__ == "__main__":
    main()
