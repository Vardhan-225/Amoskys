"""Proof Spine API — chain status, segment verification, and bundle export.

Endpoints:
    GET  /api/proofs/chain-status         — current segment, last checkpoint, health
    GET  /api/proofs/verify-segment/<id>  — full verification of a segment
    GET  /api/proofs/bundle/segment/<id>  — download proof bundle for a segment
    POST /api/proofs/bundle/timerange     — download proof bundle for a time window
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from typing import Any, Dict

from flask import Blueprint, jsonify, request, send_file

proofs_bp = Blueprint("proofs", __name__, url_prefix="/proofs")

# Resolve paths relative to the project root (3 levels up from this file)
_PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

# Configuration — paths can be overridden via environment
WAL_PATH = os.getenv(
    "IS_WAL_PATH", os.path.join(_PROJECT_ROOT, "data", "wal", "flowagent.db")
)
MANIFEST_PATH = os.getenv(
    "CHECKPOINT_MANIFEST_PATH", os.path.join(_PROJECT_ROOT, "data", "checkpoints.jsonl")
)
AGENT_KEYS_PATH = os.getenv(
    "AGENT_KEY_REGISTRY_PATH", os.path.join(_PROJECT_ROOT, "agent_key_registry.json")
)
CHECKPOINT_PUBKEY_PATH = os.getenv("CHECKPOINT_PUBKEY_PATH", None)
SEGMENT_SIZE = int(os.getenv("PROOF_SEGMENT_SIZE", "1000"))


@proofs_bp.route("/chain-status", methods=["GET"])
def get_chain_status():
    """Return current chain health summary."""
    try:
        from amoskys.proof.bundle_exporter import chain_status

        status = chain_status(
            wal_path=WAL_PATH,
            manifest_path=MANIFEST_PATH,
            segment_size=SEGMENT_SIZE,
        )
        return jsonify(status)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@proofs_bp.route("/verify-segment/<int:segment_id>", methods=["GET"])
def verify_segment(segment_id: int):
    """Full verification of a segment against its checkpoint."""
    try:
        from amoskys.proof.checkpoint_signer import CheckpointSigner
        from amoskys.proof.prove_absence import detect_absence
        from amoskys.proof.wal_segments import SegmentManager

        mgr = SegmentManager(WAL_PATH, segment_size=SEGMENT_SIZE)
        segments = mgr.scan_segments()

        if segment_id < 0 or segment_id >= len(segments):
            return jsonify({"error": f"Segment {segment_id} not found"}), 404

        signer = CheckpointSigner(manifest_path=MANIFEST_PATH)
        checkpoints = signer.load_manifest()

        if segment_id >= len(checkpoints):
            return (
                jsonify(
                    {"error": f"Segment {segment_id} has no checkpoint (unsealed)"}
                ),
                404,
            )

        events = mgr.get_segment_events(segment_id)
        cp = checkpoints[segment_id]

        result = detect_absence(cp, events)
        result["segment_id"] = segment_id
        result["checkpoint"] = cp

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@proofs_bp.route("/bundle/segment/<int:segment_id>", methods=["GET"])
def download_segment_bundle(segment_id: int):
    """Download a proof bundle for a specific segment as a zip file."""
    try:
        from amoskys.proof.bundle_exporter import BundleExporter

        exporter = BundleExporter(
            wal_path=WAL_PATH,
            manifest_path=MANIFEST_PATH,
            agent_keys_path=AGENT_KEYS_PATH,
            checkpoint_pubkey_path=CHECKPOINT_PUBKEY_PATH,
            segment_size=SEGMENT_SIZE,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_dir = os.path.join(tmpdir, "proof_bundle")
            exporter.export_segment(segment_id, bundle_dir)

            # Create zip
            zip_path = os.path.join(tmpdir, f"proof_bundle_seg{segment_id}")
            shutil.make_archive(zip_path, "zip", bundle_dir)

            return send_file(
                zip_path + ".zip",
                mimetype="application/zip",
                as_attachment=True,
                download_name=f"proof_bundle_segment_{segment_id}.zip",
            )
    except (ValueError, IndexError) as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@proofs_bp.route("/bundle/timerange", methods=["POST"])
def download_timerange_bundle():
    """Download a proof bundle for a time window.

    JSON body:
        {"start_ns": int, "end_ns": int}
    """
    try:
        data = request.get_json(force=True)
        start_ns = int(data["start_ns"])
        end_ns = int(data["end_ns"])

        from amoskys.proof.bundle_exporter import BundleExporter

        exporter = BundleExporter(
            wal_path=WAL_PATH,
            manifest_path=MANIFEST_PATH,
            agent_keys_path=AGENT_KEYS_PATH,
            checkpoint_pubkey_path=CHECKPOINT_PUBKEY_PATH,
            segment_size=SEGMENT_SIZE,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_dir = os.path.join(tmpdir, "proof_bundle")
            exporter.export_timerange(start_ns, end_ns, bundle_dir)

            zip_path = os.path.join(tmpdir, "proof_bundle_timerange")
            shutil.make_archive(zip_path, "zip", bundle_dir)

            return send_file(
                zip_path + ".zip",
                mimetype="application/zip",
                as_attachment=True,
                download_name="proof_bundle_timerange.zip",
            )
    except (ValueError, KeyError) as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500
