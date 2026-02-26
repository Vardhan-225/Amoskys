"""Proof Bundle Exporter — generates self-contained verification packages.

A proof bundle contains everything needed for offline verification:
  - Checkpoint records (signed)
  - Event data per segment (canonical bytes + metadata)
  - Merkle inclusion proofs (optional, for targeted events)
  - Public keys for agent and checkpoint signature verification
  - manifest.json with bundle metadata

Bundle layout:
    proof_bundle/
    ├── manifest.json
    ├── checkpoints/
    │   ├── checkpoint_0.json
    │   └── checkpoint_1.json
    ├── events/
    │   ├── segment_0.jsonl
    │   └── segment_1.jsonl
    ├── proofs/            (optional targeted inclusion proofs)
    │   └── inclusion_42.json
    └── keys/
        ├── agent_keys.json
        └── checkpoint_key.pub
"""

from __future__ import annotations

import base64
import json
import logging
import os
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from amoskys.proof.checkpoint_signer import CheckpointSigner, checkpoint_hash
from amoskys.proof.merkle import inclusion_proof
from amoskys.proof.wal_segments import GENESIS_SIG, SegmentManager

logger = logging.getLogger(__name__)


class BundleExporter:
    """Exports proof bundles for offline verification.

    Args:
        wal_path: Path to WAL SQLite database.
        manifest_path: Path to checkpoint JSONL manifest.
        agent_keys_path: Path to agent_key_registry.json.
        checkpoint_pubkey_path: Path to checkpoint Ed25519 public key file.
        segment_size: Events per segment (must match checkpoint config).
    """

    def __init__(
        self,
        wal_path: str = "data/wal/flowagent.db",
        manifest_path: str = "data/checkpoints.jsonl",
        agent_keys_path: str = "agent_key_registry.json",
        checkpoint_pubkey_path: Optional[str] = None,
        segment_size: int = 1000,
    ):
        self.wal_path = wal_path
        self.manifest_path = manifest_path
        self.agent_keys_path = agent_keys_path
        self.checkpoint_pubkey_path = checkpoint_pubkey_path
        self.segment_size = segment_size
        self._seg_mgr = SegmentManager(wal_path, segment_size=segment_size)

    def export_segment(
        self,
        segment_id: int,
        output_dir: str,
    ) -> str:
        """Export a proof bundle for a single segment.

        Returns the output directory path.
        """
        return self.export_segments([segment_id], output_dir)

    def export_segments(
        self,
        segment_ids: List[int],
        output_dir: str,
    ) -> str:
        """Export a proof bundle for multiple segments."""
        segments = self._seg_mgr.scan_segments()
        signer = CheckpointSigner(manifest_path=self.manifest_path)
        checkpoints = signer.load_manifest()

        # Create bundle directory structure
        bundle = Path(output_dir)
        for subdir in ("checkpoints", "events", "proofs", "keys"):
            (bundle / subdir).mkdir(parents=True, exist_ok=True)

        total_events = 0
        exported_segments = []

        for sid in segment_ids:
            if sid < 0 or sid >= len(segments):
                logger.warning("Segment %d not found, skipping", sid)
                continue

            seg = segments[sid]
            events = self._seg_mgr.get_segment_events(sid)

            # Write checkpoint
            cp = checkpoints[sid] if sid < len(checkpoints) else None
            if cp:
                cp_path = bundle / "checkpoints" / f"checkpoint_{sid}.json"
                cp_path.write_text(json.dumps(cp, indent=2, sort_keys=True))

            # Write events as JSONL
            events_path = bundle / "events" / f"segment_{sid}.jsonl"
            with open(events_path, "w") as f:
                for evt in events:
                    record = {
                        "row_id": evt["row_id"],
                        "idem": evt["idem"],
                        "ts_ns": evt["ts_ns"],
                        "env_bytes_hex": evt["env_bytes"].hex(),
                        "sig_hex": evt["sig"].hex() if evt["sig"] else "",
                        "prev_sig_hex": (
                            evt["prev_sig"].hex() if evt["prev_sig"] else ""
                        ),
                    }
                    f.write(json.dumps(record, sort_keys=True) + "\n")

            total_events += len(events)
            exported_segments.append(sid)

        # Write keys
        if os.path.exists(self.agent_keys_path):
            shutil.copy2(self.agent_keys_path, bundle / "keys" / "agent_keys.json")
        if self.checkpoint_pubkey_path and os.path.exists(self.checkpoint_pubkey_path):
            shutil.copy2(
                self.checkpoint_pubkey_path,
                bundle / "keys" / "checkpoint_key.pub",
            )

        # Write manifest
        manifest = {
            "bundle_version": "1.0",
            "created_at_ns": time.time_ns(),
            "wal_path": self.wal_path,
            "segment_size": self.segment_size,
            "segments": exported_segments,
            "total_events": total_events,
            "total_checkpoints": len(
                [s for s in exported_segments if s < len(checkpoints)]
            ),
        }
        (bundle / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True)
        )

        logger.info(
            "Exported proof bundle: %d segments, %d events → %s",
            len(exported_segments),
            total_events,
            output_dir,
        )
        return str(bundle)

    def export_latest(self, output_dir: str) -> str:
        """Export the most recent sealed segment."""
        segments = self._seg_mgr.scan_segments()
        if not segments:
            raise ValueError("No segments found in WAL")
        latest_id = segments[-1].segment_id
        return self.export_segment(latest_id, output_dir)

    def export_timerange(
        self,
        start_ns: int,
        end_ns: int,
        output_dir: str,
    ) -> str:
        """Export all segments overlapping a time window."""
        segments = self._seg_mgr.scan_segments()
        matching = [
            s.segment_id
            for s in segments
            if s.last_ts_ns >= start_ns and s.first_ts_ns <= end_ns
        ]
        if not matching:
            raise ValueError(f"No segments found in time range [{start_ns}, {end_ns}]")
        return self.export_segments(matching, output_dir)


def export_with_correlations(
    telemetry_bundle_dir: str,
    correlation_wal_path: str = "data/intel/correlation_wal.db",
    correlation_manifest_path: str = "data/correlation_checkpoints.jsonl",
    evidence_chain_path: str = "data/intel/evidence_chain.db",
    amrdr_weights: Optional[Dict[str, float]] = None,
    output_dir: Optional[str] = None,
) -> str:
    """Export a full proof bundle with correlations, evidence, and AMRDR state.

    Extends an existing telemetry bundle with:
        proof_bundle/
        ├── telemetry/           (existing structure, copied)
        ├── correlations/
        │   ├── checkpoints/     (correlation checkpoint JSONs)
        │   ├── outputs/         (correlation WAL JSONL)
        │   └── evidence_chain/  (evidence binding JSONs)
        ├── weights/             (AMRDR state at checkpoint time)
        └── keys/                (existing)

    Args:
        telemetry_bundle_dir: Path to existing telemetry proof bundle.
        correlation_wal_path: Path to correlation WAL database.
        correlation_manifest_path: Path to correlation checkpoint manifest.
        evidence_chain_path: Path to evidence chain database.
        amrdr_weights: Current AMRDR weights snapshot.
        output_dir: Output directory (default: extends telemetry_bundle_dir).

    Returns:
        Path to the extended proof bundle.
    """
    bundle = Path(output_dir or telemetry_bundle_dir)

    # Create correlation subdirectories
    for subdir in (
        "correlations/checkpoints",
        "correlations/outputs",
        "correlations/evidence_chain",
        "weights",
    ):
        (bundle / subdir).mkdir(parents=True, exist_ok=True)

    # 1. Export correlation checkpoints
    if os.path.exists(correlation_manifest_path):
        with open(correlation_manifest_path, "r") as f:
            for i, line in enumerate(f):
                line = line.strip()
                if line:
                    cp = json.loads(line)
                    cp_path = (
                        bundle
                        / "correlations"
                        / "checkpoints"
                        / f"correlation_cp_{i}.json"
                    )
                    cp_path.write_text(json.dumps(cp, indent=2, sort_keys=True))

    # 2. Export correlation WAL entries
    if os.path.exists(correlation_wal_path):
        import sqlite3

        db = sqlite3.connect(correlation_wal_path)
        rows = db.execute(
            "SELECT id, idem, ts_ns, output_type, output_bytes, "
            "checksum, sig, prev_sig FROM correlation_wal ORDER BY id"
        ).fetchall()
        db.close()

        outputs_path = bundle / "correlations" / "outputs" / "correlation_wal.jsonl"
        with open(outputs_path, "w") as f:
            for row in rows:
                record = {
                    "id": row[0],
                    "idem": row[1],
                    "ts_ns": row[2],
                    "output_type": row[3],
                    "output_bytes_hex": (
                        row[4].hex() if isinstance(row[4], bytes) else row[4]
                    ),
                    "checksum": row[5],
                    "sig": row[6],
                    "prev_sig": row[7],
                }
                f.write(json.dumps(record, sort_keys=True) + "\n")

    # 3. Export evidence chain
    if os.path.exists(evidence_chain_path):
        import sqlite3

        db = sqlite3.connect(evidence_chain_path)
        rows = db.execute(
            "SELECT evidence_id, correlation_id, correlation_type, "
            "source_segment_ids, source_checkpoint_hashes, "
            "amrdr_weights, rule_name, created_at_ns "
            "FROM evidence_chain ORDER BY created_at_ns"
        ).fetchall()
        db.close()

        for row in rows:
            ev_path = (
                bundle / "correlations" / "evidence_chain" / f"evidence_{row[0]}.json"
            )
            evidence = {
                "evidence_id": row[0],
                "correlation_id": row[1],
                "correlation_type": row[2],
                "source_segment_ids": json.loads(row[3]),
                "source_checkpoint_hashes": json.loads(row[4]),
                "amrdr_weights": json.loads(row[5]),
                "rule_name": row[6],
                "created_at_ns": row[7],
            }
            ev_path.write_text(json.dumps(evidence, indent=2, sort_keys=True))

    # 4. Export AMRDR weights snapshot
    weights_path = bundle / "weights" / "amrdr_weights.json"
    weights_data = {
        "snapshot_ns": time.time_ns(),
        "weights": amrdr_weights or {},
    }
    weights_path.write_text(json.dumps(weights_data, indent=2, sort_keys=True))

    # 5. Update manifest if it exists
    manifest_path = bundle / "manifest.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
    else:
        manifest = {}

    manifest["has_correlations"] = True
    manifest["correlation_wal_path"] = correlation_wal_path
    manifest["evidence_chain_path"] = evidence_chain_path
    manifest["amrdr_weights_count"] = len(amrdr_weights) if amrdr_weights else 0
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))

    logger.info(
        "Extended proof bundle with correlations → %s",
        str(bundle),
    )
    return str(bundle)


def chain_status(
    wal_path: str = "data/wal/flowagent.db",
    manifest_path: str = "data/checkpoints.jsonl",
    segment_size: int = 1000,
) -> Dict[str, Any]:
    """Return current chain health summary for the API.

    Returns:
        dict with current_segment, last_checkpoint, total_events,
        total_segments, chain_health.
    """
    mgr = SegmentManager(wal_path, segment_size=segment_size)
    segments = mgr.scan_segments()

    signer = CheckpointSigner(manifest_path=manifest_path)
    checkpoints = signer.load_manifest()

    total_events = sum(s.event_count for s in segments)

    return {
        "total_segments": len(segments),
        "total_checkpoints": len(checkpoints),
        "total_events": total_events,
        "current_segment_id": segments[-1].segment_id if segments else None,
        "last_checkpoint_segment": (
            checkpoints[-1]["segment_id"] if checkpoints else None
        ),
        "chain_health": "healthy" if len(checkpoints) >= len(segments) else "unsealed",
    }
