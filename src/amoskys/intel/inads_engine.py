"""INADS Phase 3 — Multi-Perspective Endpoint Detection Engine.

Adapts the INADS hierarchical IDS architecture (Thanneeru & Zhengrui, 2025)
from network flow analysis to endpoint telemetry. Instead of
Global/Edge/Device layers processing CICFlowMeter features, AMOSKYS uses
5 endpoint-specific clusters with correlation-driven feature allocation.

Clusters:
    1. ProcessTree  — exe, cmdline, parent, trust (behavioral endpoint)
    2. NetworkSeq   — remote_ip, port, bytes, protocol (volumetric/temporal)
    3. KillChain    — stage progression, MITRE coverage (sequential)
    4. SystemAnomaly — username, detection_source, agent (behavioral)
    5. FilePath     — path, hash, extension, permissions (file integrity)

Fusion: S_final = w1*c1 + w2*c2 + w3*c3 + w4*c4 + w5*c5
    Weights learned from validation, default: 0.30/0.20/0.20/0.15/0.15
    Kill chain amplification: if stages > 2, boost composite by 1.5x
"""

from __future__ import annotations

import json
import logging
import math
import os
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

try:
    import joblib
except ImportError:
    from sklearn.externals import joblib  # type: ignore[attr-defined]

logger = logging.getLogger("amoskys.inads")

# ── Constants ──────────────────────────────────────────────────────────────

DATA_DIR = Path("data")
MODEL_DIR = DATA_DIR / "intel" / "inads"
DB_PATH = DATA_DIR / "telemetry.db"

# Default fusion weights (ProcessTree heaviest — endpoint behavioral is king)
DEFAULT_WEIGHTS: Dict[str, float] = {
    "process_tree": 0.30,
    "network_seq": 0.20,
    "kill_chain": 0.20,
    "system_anomaly": 0.15,
    "file_path": 0.15,
}

# Minimum feature fill ratio to consider a cluster scorable
MIN_FEATURE_FILL = 0.50

# Kill chain amplification threshold and multiplier
KC_STAGE_THRESHOLD = 2
KC_AMPLIFICATION = 1.5

# IsolationForest defaults
IF_CONTAMINATION = 0.05
IF_N_ESTIMATORS = 100
IF_RANDOM_STATE = 42

# Top-N for categorical encoding (rare categories -> bucket 0)
TOP_N_CATEGORIES = 100

# System exe prefixes (macOS-centric, extend per platform)
SYSTEM_EXE_PREFIXES = (
    "/usr/",
    "/bin/",
    "/sbin/",
    "/System/",
    "/Library/Apple/",
)

# Temp / download path indicators
TEMP_PATH_FRAGMENTS = ("/tmp/", "/var/tmp/", "/private/tmp/", "Caches/", ".Trash/")
DOWNLOAD_PATH_FRAGMENTS = ("/Downloads/", "/download/", "/Desktop/")

# Off-hours definition (UTC-based; 22:00-06:00)
OFF_HOURS_START = 22
OFF_HOURS_END = 6


# ── Result Dataclass ──────────────────────────────────────────────────────


@dataclass
class INADSResult:
    """Result of INADS multi-perspective scoring for a single event."""

    composite_score: float  # 0.0-1.0, fused anomaly score
    cluster_scores: Dict[str, float]  # per-cluster anomaly scores
    cluster_confidences: Dict[str, float]  # per-cluster confidence (feature fill)
    dominant_cluster: str  # cluster that contributed most
    kill_chain_amplified: bool  # whether chain boost was applied
    threat_level: str  # low, medium, high, critical


def _threat_level(score: float) -> str:
    """Map composite score to threat level string."""
    if score >= 0.85:
        return "critical"
    if score >= 0.60:
        return "high"
    if score >= 0.35:
        return "medium"
    return "low"


# ── Feature Extraction Helpers ────────────────────────────────────────────


def _safe_json_loads(raw: Any) -> dict:
    """Parse JSON string to dict, returning empty dict on failure."""
    if isinstance(raw, dict):
        return raw
    if not raw or not isinstance(raw, str):
        return {}
    try:
        result = json.loads(raw)
        return result if isinstance(result, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def _safe_float(val: Any, default: float = 0.0) -> float:
    """Convert value to float, returning default on failure."""
    if val is None:
        return default
    try:
        return float(val)
    except (ValueError, TypeError):
        return default


def _safe_int(val: Any, default: int = 0) -> int:
    """Convert value to int, returning default on failure."""
    if val is None:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def _path_depth(p: Any) -> int:
    """Count slash-delimited depth of a path string."""
    if not p or not isinstance(p, str):
        return 0
    return p.strip("/").count("/") + 1


def _is_private_ip(ip_str: Any) -> bool:
    """Check if an IP address is RFC1918/link-local."""
    if not ip_str or not isinstance(ip_str, str):
        return True  # no IP -> treat as internal
    try:
        import ipaddress

        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except (ValueError, TypeError):
        return True


def _file_extension_from_path(p: Any) -> str:
    """Extract file extension from a path string."""
    if not p or not isinstance(p, str):
        return ""
    ext = os.path.splitext(p)[1].lower()
    return ext if ext else ""


# ── Cluster Feature Extractors ────────────────────────────────────────────
#
# Each function takes a unified event dict (merged typed columns + raw attrs)
# and returns a dict of feature_name -> value (float or None for missing).


def _encode_system_exe(exe: str) -> Optional[float]:
    """Return 1.0 for system executables, 0.0 for non-system, None if empty."""
    if not exe:
        return None
    return 1.0 if exe.startswith(SYSTEM_EXE_PREFIXES) else 0.0


def _encode_parent_launchd(parent: str) -> Optional[float]:
    """Return 1.0 if parent is launchd, 0.0 if other parent, None if empty."""
    if not parent:
        return None
    return 1.0 if "launchd" in parent.lower() else 0.0


def _encode_trust_disposition(trust: str) -> Optional[float]:
    """Encode trust disposition: 0=unknown, 1=trusted, 2=untrusted, None=absent."""
    if not trust:
        return None
    trust_str = str(trust).lower()
    if "trust" in trust_str or "allow" in trust_str:
        return 1.0
    if "untrust" in trust_str or "deny" in trust_str or "block" in trust_str:
        return 2.0
    return 0.0


def _extract_process_tree(evt: dict) -> Dict[str, Optional[float]]:
    """ProcessTree cluster: 8 features from process identity fields."""
    pid = evt.get("pid")
    exe = evt.get("exe") or evt.get("exe_path") or ""
    cmdline = evt.get("cmdline") or ""
    ppid = evt.get("ppid")
    parent = evt.get("parent") or evt.get("parent_name") or ""
    trust = evt.get("trust_disposition") or evt.get("cs_flags") or ""
    process_name = evt.get("process_name") or evt.get("name") or ""

    has_pid = 1.0 if pid is not None else None
    exe_depth = float(_path_depth(exe)) if exe else None
    cmd_len = float(len(cmdline)) if cmdline else None
    has_parent = 1.0 if (ppid is not None or parent) else None
    proc_enc = float(hash(process_name) % TOP_N_CATEGORIES) if process_name else None

    return {
        "has_pid": has_pid,
        "exe_path_depth": exe_depth,
        "is_system_exe": _encode_system_exe(exe),
        "cmdline_length": cmd_len,
        "has_parent": has_parent,
        "parent_is_launchd": _encode_parent_launchd(parent),
        "trust_disposition_encoded": _encode_trust_disposition(trust),
        "process_name_encoded": proc_enc,
    }


def _extract_network_seq(evt: dict) -> Dict[str, Optional[float]]:
    """NetworkSeq cluster: 6 features from network connection fields."""
    remote_ip = evt.get("remote_ip") or evt.get("dst_ip") or evt.get("src_ip") or ""
    remote_port = evt.get("remote_port") or evt.get("dst_port")
    bytes_out = evt.get("bytes_out") or evt.get("bytes_tx")
    bytes_in = evt.get("bytes_in") or evt.get("bytes_rx")
    protocol = evt.get("protocol") or ""

    has_ip = 1.0 if remote_ip else None
    is_external = None
    if remote_ip:
        is_external = 0.0 if _is_private_ip(remote_ip) else 1.0

    port_val = _safe_float(remote_port) if remote_port is not None else None
    bout_log = math.log1p(_safe_float(bytes_out)) if bytes_out is not None else None
    bin_log = math.log1p(_safe_float(bytes_in)) if bytes_in is not None else None

    proto_enc = None
    if protocol:
        proto_map = {
            "tcp": 1.0,
            "udp": 2.0,
            "icmp": 3.0,
            "dns": 4.0,
            "http": 5.0,
            "https": 6.0,
        }
        proto_enc = proto_map.get(protocol.lower(), 7.0)

    return {
        "has_remote_ip": has_ip,
        "is_external_ip": is_external,
        "remote_port": port_val,
        "bytes_out_log": bout_log,
        "bytes_in_log": bin_log,
        "protocol_encoded": proto_enc,
    }


def _parse_mitre_technique_count(mitre_raw: Any) -> Optional[float]:
    """Parse MITRE techniques field (JSON array or comma-separated) into count."""
    if not mitre_raw:
        return None
    if isinstance(mitre_raw, list):
        return float(len(mitre_raw))
    if not isinstance(mitre_raw, str):
        return None
    try:
        techniques = json.loads(mitre_raw)
        if isinstance(techniques, list):
            return float(len(techniques))
    except (json.JSONDecodeError, TypeError):
        pass
    # Comma-separated fallback
    return float(len([t for t in mitre_raw.split(",") if t.strip()]))


def _resolve_kill_chain_depth(stage_name: str) -> float:
    """Map a kill chain stage name to its 1-indexed depth (1-7)."""
    try:
        from amoskys.agents.common.kill_chain import KILL_CHAIN_STAGES

        stage_lower = stage_name.lower()
        for idx, stage in enumerate(KILL_CHAIN_STAGES):
            if stage_lower == stage.lower():
                return float(idx + 1)
    except ImportError:
        pass
    return 1.0  # unknown stage -> minimal depth


_EVENT_CATEGORY_MAP = {
    "authentication": 1.0,
    "intrusion": 2.0,
    "malware": 3.0,
    "exfiltration": 4.0,
    "reconnaissance": 5.0,
    "lateral_movement": 6.0,
    "privilege_escalation": 7.0,
    "persistence": 8.0,
    "dns_tunnel": 9.0,
    "command_and_control": 10.0,
}


def _extract_kill_chain(evt: dict) -> Dict[str, Optional[float]]:
    """KillChain cluster: 6 features from threat/MITRE fields."""
    mitre_raw = evt.get("mitre_techniques") or ""
    kill_chain_stage = evt.get("kill_chain_stage") or evt.get("kc_stage") or ""
    event_category = evt.get("event_category") or ""
    risk_score = evt.get("risk_score")
    requires_inv = evt.get("requires_investigation")

    has_kc = 1.0 if kill_chain_stage else None
    kc_depth = _resolve_kill_chain_depth(kill_chain_stage) if kill_chain_stage else None
    cat_enc = (
        _EVENT_CATEGORY_MAP.get(event_category.lower(), 0.0) if event_category else None
    )
    risk_val = _safe_float(risk_score) if risk_score is not None else None
    req_inv = None
    if requires_inv is not None:
        req_inv = 1.0 if requires_inv else 0.0

    return {
        "mitre_technique_count": _parse_mitre_technique_count(mitre_raw),
        "has_kill_chain_stage": has_kc,
        "kill_chain_depth": kc_depth,
        "event_category_encoded": cat_enc,
        "risk_score": risk_val,
        "requires_investigation": req_inv,
    }


def _extract_system_anomaly(evt: dict) -> Dict[str, Optional[float]]:
    """SystemAnomaly cluster: 6 features from user/time/source fields."""
    username = evt.get("username") or ""
    timestamp_ns = evt.get("timestamp_ns")
    detection_source = evt.get("detection_source") or evt.get("event_source") or ""
    collection_agent = evt.get("collection_agent") or ""

    has_user = 1.0 if username else None
    is_root = None
    if username:
        is_root = 1.0 if username.lower() in ("root", "system", "wheel") else 0.0

    hour = None
    is_off = None
    if timestamp_ns is not None:
        try:
            ts_sec = _safe_float(timestamp_ns) / 1e9
            hour = float(time.gmtime(ts_sec).tm_hour)
            is_off = 1.0 if (hour >= OFF_HOURS_START or hour < OFF_HOURS_END) else 0.0
        except (OSError, OverflowError, ValueError):
            pass

    det_enc = None
    if detection_source:
        det_map = {
            "probe": 1.0,
            "sigma": 2.0,
            "yara": 3.0,
            "fusion": 4.0,
            "manual": 5.0,
            "observation": 6.0,
        }
        det_enc = det_map.get(detection_source.lower(), 0.0)

    agent_enc = None
    if collection_agent:
        agent_enc = float(hash(collection_agent) % TOP_N_CATEGORIES)

    return {
        "has_username": has_user,
        "is_root": is_root,
        "hour_of_day": hour,
        "is_off_hours": is_off,
        "detection_source_encoded": det_enc,
        "collection_agent_encoded": agent_enc,
    }


def _extract_file_path(evt: dict) -> Dict[str, Optional[float]]:
    """FilePath cluster: 6 features from file/path/hash fields."""
    path = evt.get("path") or evt.get("file_path") or evt.get("exe") or ""
    sha256 = evt.get("sha256") or evt.get("hash") or evt.get("file_hash") or ""
    extension = evt.get("extension") or _file_extension_from_path(path)

    has_path = 1.0 if path else None
    depth = float(_path_depth(path)) if path else None

    # has_sha256: 1.0 if hash present, 0.0 if path present but no hash, None if neither
    has_sha: Optional[float] = None
    if sha256:
        has_sha = 1.0
    elif path:
        has_sha = 0.0

    is_temp = None
    if path:
        is_temp = 1.0 if any(frag in path for frag in TEMP_PATH_FRAGMENTS) else 0.0

    is_dl = None
    if path:
        is_dl = 1.0 if any(frag in path for frag in DOWNLOAD_PATH_FRAGMENTS) else 0.0

    ext_enc = None
    if extension:
        ext_map = {
            ".py": 1.0,
            ".sh": 2.0,
            ".bash": 2.0,
            ".zsh": 2.0,
            ".js": 3.0,
            ".rb": 4.0,
            ".pl": 5.0,
            ".exe": 6.0,
            ".dll": 7.0,
            ".dylib": 7.0,
            ".so": 7.0,
            ".app": 8.0,
            ".dmg": 9.0,
            ".pkg": 10.0,
            ".zip": 11.0,
            ".tar": 11.0,
            ".gz": 11.0,
            ".rar": 11.0,
            ".plist": 12.0,
            ".conf": 13.0,
            ".json": 14.0,
            ".xml": 14.0,
            ".log": 15.0,
            ".txt": 16.0,
            ".pdf": 17.0,
            ".doc": 18.0,
        }
        ext_enc = ext_map.get(extension.lower(), 0.0)

    return {
        "has_path": has_path,
        "path_depth": depth,
        "has_sha256": has_sha,
        "is_temp_path": is_temp,
        "is_downloads_path": is_dl,
        "file_extension_encoded": ext_enc,
    }


# Cluster registry: name -> (extractor_fn, feature_names)
CLUSTER_REGISTRY: Dict[str, Tuple[Any, List[str]]] = {
    "process_tree": (
        _extract_process_tree,
        [
            "has_pid",
            "exe_path_depth",
            "is_system_exe",
            "cmdline_length",
            "has_parent",
            "parent_is_launchd",
            "trust_disposition_encoded",
            "process_name_encoded",
        ],
    ),
    "network_seq": (
        _extract_network_seq,
        [
            "has_remote_ip",
            "is_external_ip",
            "remote_port",
            "bytes_out_log",
            "bytes_in_log",
            "protocol_encoded",
        ],
    ),
    "kill_chain": (
        _extract_kill_chain,
        [
            "mitre_technique_count",
            "has_kill_chain_stage",
            "kill_chain_depth",
            "event_category_encoded",
            "risk_score",
            "requires_investigation",
        ],
    ),
    "system_anomaly": (
        _extract_system_anomaly,
        [
            "has_username",
            "is_root",
            "hour_of_day",
            "is_off_hours",
            "detection_source_encoded",
            "collection_agent_encoded",
        ],
    ),
    "file_path": (
        _extract_file_path,
        [
            "has_path",
            "path_depth",
            "has_sha256",
            "is_temp_path",
            "is_downloads_path",
            "file_extension_encoded",
        ],
    ),
}


# ── Cluster Model ─────────────────────────────────────────────────────────


class ClusterModel:
    """A single INADS detection cluster with its own IsolationForest.

    Thread-safe: all model reads/writes are guarded by self._lock.
    """

    def __init__(self, name: str, feature_names: List[str]):
        self.name = name
        self.feature_names = feature_names
        self.model: Optional[IsolationForest] = None
        self.is_trained = False
        self._lock = threading.Lock()
        # Per-feature median for imputation (learned at train time)
        self.feature_medians: Dict[str, float] = {}

    def train(self, df: pd.DataFrame) -> int:
        """Train IsolationForest on a DataFrame with columns matching feature_names.

        Rows where fewer than MIN_FEATURE_FILL fraction of features are non-null
        are dropped before training.

        Args:
            df: DataFrame with columns for this cluster's features.

        Returns:
            Number of training samples used (0 if insufficient data).
        """
        cols = [c for c in self.feature_names if c in df.columns]
        if not cols:
            logger.warning(
                "Cluster %s: no matching columns in training data", self.name
            )
            return 0

        subset = df[cols].copy()
        fill_ratio = subset.notna().sum(axis=1) / len(cols)
        subset = subset[fill_ratio >= MIN_FEATURE_FILL]

        if len(subset) < 20:
            logger.warning(
                "Cluster %s: only %d usable rows (need >= 20), skipping",
                self.name,
                len(subset),
            )
            return 0

        # Learn medians for imputation
        for col in cols:
            med = subset[col].median()
            self.feature_medians[col] = float(med) if pd.notna(med) else 0.0

        # Impute missing values with learned medians
        for col in cols:
            subset[col] = subset[col].fillna(self.feature_medians[col])

        iso = IsolationForest(
            contamination=IF_CONTAMINATION,
            n_estimators=IF_N_ESTIMATORS,
            random_state=IF_RANDOM_STATE,
            n_jobs=-1,
        )
        iso.fit(subset.values)

        with self._lock:
            self.model = iso
            self.is_trained = True

        logger.info(
            "Cluster %s: trained on %d samples, %d features",
            self.name,
            len(subset),
            len(cols),
        )
        return len(subset)

    def score(self, features: Dict[str, Optional[float]]) -> Tuple[float, float]:
        """Score a single event using this cluster's model.

        Args:
            features: Dict of feature_name -> value (may contain None).

        Returns:
            (anomaly_score, confidence) where:
                anomaly_score: 0.0-1.0 (higher = more anomalous)
                confidence: fraction of non-null features for this cluster
        """
        with self._lock:
            if not self.is_trained or self.model is None:
                return 0.0, 0.0

        # Calculate confidence from feature fill
        filled = sum(1 for f in self.feature_names if features.get(f) is not None)
        confidence = filled / len(self.feature_names) if self.feature_names else 0.0

        if confidence < MIN_FEATURE_FILL:
            return 0.0, confidence

        # Build feature vector with imputation
        vec = []
        for fname in self.feature_names:
            val = features.get(fname)
            if val is not None:
                vec.append(float(val))
            else:
                vec.append(self.feature_medians.get(fname, 0.0))

        arr = np.array(vec).reshape(1, -1)

        with self._lock:
            # score_samples returns negative for anomalies, positive for normal.
            # Typical range: [-0.5, 0.5].
            raw_score = self.model.score_samples(arr)[0]

        # Sigmoid transform: maps raw_score to 0-1 anomaly score.
        # More negative raw -> higher anomaly.  5x scaling for separation.
        anomaly_score = 1.0 / (1.0 + math.exp(5.0 * raw_score))
        anomaly_score = max(0.0, min(1.0, anomaly_score))

        return anomaly_score, confidence

    def save(self, directory: Path) -> None:
        """Persist model and metadata to disk."""
        directory.mkdir(parents=True, exist_ok=True)
        with self._lock:
            if self.model is not None:
                joblib.dump(self.model, directory / f"{self.name}.joblib")
            metadata = {
                "feature_names": self.feature_names,
                "feature_medians": self.feature_medians,
                "is_trained": self.is_trained,
            }
            joblib.dump(metadata, directory / f"{self.name}_meta.joblib")

    def load(self, directory: Path) -> bool:
        """Load model and metadata from disk. Returns True if successful."""
        model_path = directory / f"{self.name}.joblib"
        meta_path = directory / f"{self.name}_meta.joblib"

        if not model_path.exists() or not meta_path.exists():
            return False

        try:
            model = joblib.load(model_path)
            metadata = joblib.load(meta_path)

            with self._lock:
                self.model = model
                self.feature_names = metadata["feature_names"]
                self.feature_medians = metadata["feature_medians"]
                self.is_trained = metadata["is_trained"]

            logger.info("Cluster %s: loaded model from %s", self.name, model_path)
            return True
        except Exception as exc:
            logger.error("Cluster %s: failed to load model: %s", self.name, exc)
            return False


# ── Calibrated Fusion ─────────────────────────────────────────────────────


class CalibratedFusion:
    """Fuses cluster scores with confidence-weighted aggregation.

    The formula:
        composite = sum(w_i * s_i * c_i) / sum(w_i * c_i)

    where w_i is the cluster weight, s_i is the anomaly score, and c_i is
    the confidence (feature fill ratio). Clusters below MIN_FEATURE_FILL
    confidence are excluded entirely.
    """

    def __init__(self, weights: Optional[Dict[str, float]] = None):
        self.weights = weights or dict(DEFAULT_WEIGHTS)

    def fuse(
        self,
        cluster_scores: Dict[str, float],
        cluster_confidences: Dict[str, float],
        kill_chain_depth: int = 0,
    ) -> Tuple[float, bool]:
        """Fuse cluster scores into a single composite anomaly score.

        Args:
            cluster_scores: cluster_name -> anomaly_score (0-1)
            cluster_confidences: cluster_name -> confidence (0-1)
            kill_chain_depth: number of kill chain stages observed (0-7)

        Returns:
            (composite_score, kill_chain_amplified)
        """
        numerator = 0.0
        denominator = 0.0

        for cluster_name, weight in self.weights.items():
            score = cluster_scores.get(cluster_name, 0.0)
            conf = cluster_confidences.get(cluster_name, 0.0)

            if conf < MIN_FEATURE_FILL:
                continue

            numerator += weight * score * conf
            denominator += weight * conf

        if denominator < 1e-9:
            return 0.0, False

        composite = numerator / denominator
        composite = max(0.0, min(1.0, composite))

        # Kill chain amplification: multi-stage attacks get boosted
        amplified = False
        if kill_chain_depth > KC_STAGE_THRESHOLD:
            composite = min(1.0, composite * KC_AMPLIFICATION)
            amplified = True

        return composite, amplified


# ── INADS Engine (Orchestrator) ───────────────────────────────────────────


class INADSEngine:
    """Multi-perspective endpoint anomaly detection engine.

    Orchestrates 5 specialized IsolationForest clusters and fuses their
    scores into a single composite anomaly assessment per event.

    Thread-safe: all model access is guarded by per-cluster locks, and
    engine-level state is guarded by self._lock.

    Usage::

        engine = INADSEngine()

        # Option A: Load pre-trained models
        engine.load_models()

        # Option B: Train from telemetry DB
        engine.train_all()

        # Score a single event
        result = engine.score_event(event_dict)

        # Score all events for a device
        device_result = engine.score_device("macbook-pro")
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        model_dir: Optional[Path] = None,
        weights: Optional[Dict[str, float]] = None,
    ):
        self.db_path = db_path or str(DB_PATH)
        self.model_dir = model_dir or MODEL_DIR
        self.fusion = CalibratedFusion(weights)
        self._lock = threading.Lock()

        # Initialize cluster models
        self.clusters: Dict[str, ClusterModel] = {}
        for name, (_, feature_names) in CLUSTER_REGISTRY.items():
            self.clusters[name] = ClusterModel(name, list(feature_names))

        self._trained = False

        # Auto-load persisted models if they exist on disk
        if self.model_dir.is_dir() and any(self.model_dir.glob("*.joblib")):
            try:
                self.load_models()
                logger.info("INADS: loaded persisted models from %s", self.model_dir)
            except Exception as e:
                logger.debug("INADS: auto-load failed (will train fresh): %s", e)

    # ── Data Loading ──────────────────────────────────────────────────

    def _connect_db(self) -> sqlite3.Connection:
        """Open a read-only connection to the telemetry database."""
        conn = sqlite3.connect(
            f"file:{self.db_path}?mode=ro",
            uri=True,
            check_same_thread=False,
            timeout=10.0,
        )
        conn.row_factory = sqlite3.Row
        return conn

    def _load_security_events(self, conn: sqlite3.Connection) -> pd.DataFrame:
        """Load all security_events into a DataFrame."""
        query = """
            SELECT
                timestamp_ns, device_id, event_category, event_action,
                event_outcome, risk_score, confidence, mitre_techniques,
                requires_investigation, collection_agent, agent_version,
                description, indicators, raw_attributes_json,
                final_classification, enrichment_status
            FROM security_events
            WHERE training_exclude = 0
            ORDER BY timestamp_ns DESC
        """
        try:
            df = pd.read_sql_query(query, conn)
            logger.info("Loaded %d security_events for training", len(df))
            return df
        except Exception as exc:
            logger.error("Failed to load security_events: %s", exc)
            return pd.DataFrame()

    def _load_observation_events(
        self, conn: sqlite3.Connection, sample_limit: int = 50000
    ) -> pd.DataFrame:
        """Load observation_events, sampling by domain for balance."""
        query = f"""
            SELECT
                timestamp_ns, device_id, domain, event_type,
                attributes, risk_score, event_source, collection_agent
            FROM observation_events
            WHERE training_exclude = 0
            ORDER BY RANDOM()
            LIMIT {sample_limit}
        """
        try:
            df = pd.read_sql_query(query, conn)
            logger.info("Loaded %d observation_events for training", len(df))
            return df
        except Exception as exc:
            logger.error("Failed to load observation_events: %s", exc)
            return pd.DataFrame()

    def _load_process_events(self, conn: sqlite3.Connection) -> pd.DataFrame:
        """Load process_events for ProcessTree cluster enrichment."""
        query = """
            SELECT
                timestamp_ns, device_id, pid, ppid, exe, cmdline,
                username, collection_agent, raw_attributes_json
            FROM process_events
            WHERE training_exclude = 0
            ORDER BY timestamp_ns DESC
            LIMIT 100000
        """
        try:
            df = pd.read_sql_query(query, conn)
            logger.info("Loaded %d process_events for training", len(df))
            return df
        except Exception as exc:
            logger.error("Failed to load process_events: %s", exc)
            return pd.DataFrame()

    def _load_flow_events(self, conn: sqlite3.Connection) -> pd.DataFrame:
        """Load flow_events for NetworkSeq cluster enrichment."""
        query = """
            SELECT
                timestamp_ns, device_id, src_ip, dst_ip,
                src_port, dst_port, protocol,
                bytes_tx, bytes_rx, raw_attributes_json
            FROM flow_events
            WHERE training_exclude = 0
            ORDER BY timestamp_ns DESC
            LIMIT 100000
        """
        try:
            df = pd.read_sql_query(query, conn)
            logger.info("Loaded %d flow_events for training", len(df))
            return df
        except Exception as exc:
            logger.error("Failed to load flow_events: %s", exc)
            return pd.DataFrame()

    # ── Unified Event Dict ────────────────────────────────────────────

    @staticmethod
    def _row_to_event_dict(row: dict) -> dict:
        """Merge typed columns and raw_attributes_json into a flat event dict.

        The raw JSON attributes fill in gaps but never overwrite typed columns
        that already have a value.
        """
        evt = dict(row)
        raw_json = evt.pop("raw_attributes_json", None) or evt.pop("attributes", None)
        attrs = _safe_json_loads(raw_json)
        for k, v in attrs.items():
            if k not in evt or evt[k] is None:
                evt[k] = v
        return evt

    def _dataframe_to_event_dicts(self, df: pd.DataFrame) -> List[dict]:
        """Convert a DataFrame to a list of unified event dicts."""
        records = df.to_dict(orient="records")
        return [self._row_to_event_dict(r) for r in records]

    # ── Feature Matrix Building ───────────────────────────────────────

    def _build_cluster_features(
        self, event_dicts: List[dict], cluster_name: str
    ) -> pd.DataFrame:
        """Build a feature DataFrame for one cluster from event dicts."""
        extractor, feature_names = CLUSTER_REGISTRY[cluster_name]
        rows = []
        for evt in event_dicts:
            features = extractor(evt)
            rows.append(features)
        return pd.DataFrame(rows, columns=feature_names)

    # ── Training ──────────────────────────────────────────────────────

    def train_all(self, db_path: Optional[str] = None) -> Dict[str, int]:
        """Train all 5 clusters from the telemetry database.

        Loads security_events (all), observation_events (sampled),
        process_events (recent 100k), and flow_events (recent 100k).
        For each cluster, extracts its features from all loaded events
        and trains an independent IsolationForest.

        Args:
            db_path: Override database path (uses self.db_path if None).

        Returns:
            Dict of cluster_name -> number of training samples used.
        """
        path = db_path or self.db_path
        if not Path(path).exists():
            logger.error("Database not found at %s", path)
            return {}

        conn = self._connect_db()
        try:
            sec_df = self._load_security_events(conn)
            obs_df = self._load_observation_events(conn)
            proc_df = self._load_process_events(conn)
            flow_df = self._load_flow_events(conn)
        finally:
            conn.close()

        # Convert to unified event dicts
        all_dicts: List[dict] = []
        for df in [sec_df, obs_df, proc_df, flow_df]:
            if not df.empty:
                all_dicts.extend(self._dataframe_to_event_dicts(df))

        if not all_dicts:
            logger.warning("No training data found in %s", path)
            return {}

        logger.info("Training INADS on %d total events", len(all_dicts))

        results: Dict[str, int] = {}
        for cluster_name in CLUSTER_REGISTRY:
            feat_df = self._build_cluster_features(all_dicts, cluster_name)
            n_trained = self.clusters[cluster_name].train(feat_df)
            results[cluster_name] = n_trained

        # Persist models
        self.save_models()

        with self._lock:
            self._trained = True

        trained_count = sum(1 for v in results.values() if v > 0)
        logger.info(
            "INADS training complete: %d/%d clusters trained, %d total samples",
            trained_count,
            len(CLUSTER_REGISTRY),
            sum(results.values()),
        )
        return results

    # ── Scoring ───────────────────────────────────────────────────────

    def score_event(self, event: dict) -> INADSResult:
        """Score a single event across all 5 clusters and fuse.

        Extracts features for each cluster, scores with the trained model
        (if available and enough features are present), then fuses via
        CalibratedFusion.

        Args:
            event: Dict with event fields (typed columns + raw attributes).
                   Can be a raw DB row or a pre-merged dict.

        Returns:
            INADSResult with composite score and per-cluster breakdown.
        """
        evt = (
            self._row_to_event_dict(event)
            if "raw_attributes_json" in event or "attributes" in event
            else dict(event)
        )

        cluster_scores: Dict[str, float] = {}
        cluster_confidences: Dict[str, float] = {}

        for cluster_name, (extractor, _) in CLUSTER_REGISTRY.items():
            features = extractor(evt)
            score, confidence = self.clusters[cluster_name].score(features)
            cluster_scores[cluster_name] = score
            cluster_confidences[cluster_name] = confidence

        # Determine kill chain depth for amplification
        kc_features = _extract_kill_chain(evt)
        kc_depth = _safe_int(kc_features.get("kill_chain_depth"), 0)

        composite, amplified = self.fusion.fuse(
            cluster_scores, cluster_confidences, kc_depth
        )

        # Find dominant cluster (highest weighted contribution)
        dominant = "process_tree"
        max_contribution = -1.0
        for cname, weight in self.fusion.weights.items():
            contribution = (
                cluster_scores.get(cname, 0.0)
                * cluster_confidences.get(cname, 0.0)
                * weight
            )
            if contribution > max_contribution:
                max_contribution = contribution
                dominant = cname

        return INADSResult(
            composite_score=round(composite, 4),
            cluster_scores={k: round(v, 4) for k, v in cluster_scores.items()},
            cluster_confidences={
                k: round(v, 4) for k, v in cluster_confidences.items()
            },
            dominant_cluster=dominant,
            kill_chain_amplified=amplified,
            threat_level=_threat_level(composite),
        )

    def score_device(
        self,
        device_id: str,
        db_path: Optional[str] = None,
        window_hours: int = 24,
    ) -> Dict[str, Any]:
        """Score all recent events for a device, returning aggregate assessment.

        Queries security_events and process_events within the time window,
        scores each event individually, then aggregates into device-level
        statistics.

        Args:
            device_id: Device identifier to query.
            db_path: Override database path.
            window_hours: How far back to look (default 24h).

        Returns:
            Dict with device_id, event_count, mean_composite, max_composite,
            threat_level, cluster_means, and top_events (highest scoring).
        """
        path = db_path or self.db_path
        if not Path(path).exists():
            return {"device_id": device_id, "error": "database not found"}

        cutoff_ns = int((time.time() - window_hours * 3600) * 1e9)

        conn = self._connect_db()
        try:
            events: List[dict] = []
            for table in ("security_events", "process_events"):
                try:
                    cursor = conn.execute(
                        f"SELECT * FROM {table} "
                        f"WHERE device_id = ? AND timestamp_ns >= ? "
                        f"ORDER BY timestamp_ns DESC LIMIT 1000",
                        (device_id, cutoff_ns),
                    )
                    columns = [desc[0] for desc in cursor.description]
                    for row in cursor.fetchall():
                        events.append(dict(zip(columns, row)))
                except Exception as exc:
                    logger.debug(
                        "Failed to query %s for device %s: %s",
                        table,
                        device_id,
                        exc,
                    )
        finally:
            conn.close()

        if not events:
            return {
                "device_id": device_id,
                "event_count": 0,
                "mean_composite": 0.0,
                "max_composite": 0.0,
                "threat_level": "low",
                "cluster_means": {},
                "top_events": [],
            }

        # Score each event
        results: List[INADSResult] = []
        for evt in events:
            try:
                result = self.score_event(evt)
                results.append(result)
            except Exception as exc:
                logger.debug("Failed to score event: %s", exc)

        if not results:
            return {
                "device_id": device_id,
                "event_count": len(events),
                "mean_composite": 0.0,
                "max_composite": 0.0,
                "threat_level": "low",
                "cluster_means": {},
                "top_events": [],
            }

        composites = [r.composite_score for r in results]
        mean_composite = float(np.mean(composites))
        max_composite = float(np.max(composites))

        # Per-cluster means (only from events with sufficient confidence)
        cluster_means: Dict[str, float] = {}
        for cname in CLUSTER_REGISTRY:
            scores = [
                r.cluster_scores[cname]
                for r in results
                if r.cluster_confidences.get(cname, 0) >= MIN_FEATURE_FILL
            ]
            cluster_means[cname] = round(float(np.mean(scores)), 4) if scores else 0.0

        # Top 5 highest-scoring events
        sorted_results = sorted(results, key=lambda r: r.composite_score, reverse=True)
        top_events = [
            {
                "composite_score": r.composite_score,
                "dominant_cluster": r.dominant_cluster,
                "threat_level": r.threat_level,
            }
            for r in sorted_results[:5]
        ]

        return {
            "device_id": device_id,
            "event_count": len(events),
            "mean_composite": round(mean_composite, 4),
            "max_composite": round(max_composite, 4),
            "threat_level": _threat_level(max_composite),
            "cluster_means": cluster_means,
            "top_events": top_events,
        }

    # ── Persistence ───────────────────────────────────────────────────

    def save_models(self) -> None:
        """Persist all cluster models to disk at self.model_dir."""
        self.model_dir.mkdir(parents=True, exist_ok=True)
        for cluster in self.clusters.values():
            try:
                cluster.save(self.model_dir)
            except Exception as exc:
                logger.error("Failed to save cluster %s: %s", cluster.name, exc)
        logger.info("INADS models saved to %s", self.model_dir)

    def load_models(self) -> bool:
        """Load pre-trained models from disk.

        Returns:
            True if at least one cluster loaded successfully.
        """
        if not self.model_dir.exists():
            logger.warning("Model directory not found: %s", self.model_dir)
            return False

        loaded = 0
        for cluster in self.clusters.values():
            if cluster.load(self.model_dir):
                loaded += 1

        with self._lock:
            self._trained = loaded > 0

        logger.info("INADS: loaded %d/%d cluster models", loaded, len(self.clusters))
        return loaded > 0

    @property
    def is_trained(self) -> bool:
        """Whether the engine has trained or loaded models."""
        with self._lock:
            return self._trained

    def status(self) -> Dict[str, Any]:
        """Return engine status for health monitoring."""
        cluster_status = {}
        for name, cluster in self.clusters.items():
            cluster_status[name] = {
                "trained": cluster.is_trained,
                "n_features": len(cluster.feature_names),
                "has_medians": bool(cluster.feature_medians),
            }
        return {
            "engine": "INADS",
            "version": "3.0",
            "trained": self.is_trained,
            "model_dir": str(self.model_dir),
            "db_path": self.db_path,
            "clusters": cluster_status,
            "weights": dict(self.fusion.weights),
        }
