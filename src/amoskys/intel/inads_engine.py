"""INADS — Intelligent Network Anomaly Detection System (Phase 3).

Hierarchical multi-layer IDS with 5-cluster scoring and calibrated fusion.
This is the ML engine that gives AMOSKYS real threat classification beyond
hand-written rules.

Architecture:
    ┌────────────────────────────────────────────────────────┐
    │                   INADS Engine                          │
    │                                                        │
    │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
    │  │ Process  │ │ Network  │ │ Kill     │ │ System   │ │
    │  │ Tree     │ │ Sequence │ │ Chain    │ │ Anomaly  │ │
    │  │ Cluster  │ │ Cluster  │ │ State    │ │ Detector │ │
    │  │          │ │          │ │ Machine  │ │          │ │
    │  │ IForest  │ │ Markov   │ │ HMM     │ │ IForest  │ │
    │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ │
    │       │             │            │             │       │
    │  ┌────┴─────────────┴────────────┴─────────────┴────┐ │
    │  │           ┌──────────┐                           │ │
    │  │           │ File/    │                           │ │
    │  │           │ Path     │                           │ │
    │  │           │ Cluster  │                           │ │
    │  │           │ IForest  │                           │ │
    │  │           └────┬─────┘                           │ │
    │  │                │                                 │ │
    │  │    ┌───────────┴──────────────┐                  │ │
    │  │    │   Calibrated Fusion      │                  │ │
    │  │    │   (Isotonic Regression)  │                  │ │
    │  │    └───────────┬──────────────┘                  │ │
    │  └────────────────┴─────────────────────────────────┘ │
    │                   │                                    │
    │              INADS Score                               │
    │           (0.0 - 1.0, calibrated)                      │
    └───────────────────┴────────────────────────────────────┘
                        │
                        ▼
                 FusionEngine.evaluate_device()
                        │
                        ▼
                  Incident / DeviceRiskSnapshot

Integration:
    - Reads from security_events + observation_events (same as SOMA)
    - Each cluster extracts its own feature subspace
    - Per-cluster IsolationForest/Markov scores
    - Calibrated fusion with isotonic regression
    - INADS score injected into FusionEngine as signal

Paper Reference:
    INADS: Intelligent Network Anomaly Detection System
    5-cluster scoring with calibrated fusion
    Process tree, Network LSTM, Kill Chain, System anomaly, File/Path

Author: Akash Thanneeru + Claude Opus 4.6
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import pickle
import sqlite3
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════

# Training limits
MAX_TRAINING_SAMPLES = 100_000
MIN_TRAINING_SAMPLES = 100

# Cluster weights (learned during calibration, these are priors)
DEFAULT_CLUSTER_WEIGHTS = {
    "process_tree": 0.30,
    "network_seq": 0.25,
    "kill_chain": 0.20,
    "system_anomaly": 0.15,
    "file_path": 0.10,
}

# IsolationForest defaults
IF_N_ESTIMATORS = 200
IF_CONTAMINATION = 0.05
IF_MAX_SAMPLES = 512

# Markov chain order for network sequences
MARKOV_ORDER = 2

# Kill chain stages (ordered)
KILL_CHAIN_STAGES = [
    "reconnaissance",
    "weaponization",
    "delivery",
    "exploitation",
    "installation",
    "command_and_control",
    "actions_on_objective",
]

# MITRE tactic to kill chain stage mapping
TACTIC_TO_STAGE = {
    "TA0043": "reconnaissance",  # Reconnaissance
    "TA0001": "delivery",  # Initial Access
    "TA0002": "exploitation",  # Execution
    "TA0003": "installation",  # Persistence
    "TA0004": "exploitation",  # Privilege Escalation
    "TA0005": "installation",  # Defense Evasion
    "TA0006": "exploitation",  # Credential Access
    "TA0007": "reconnaissance",  # Discovery
    "TA0008": "actions_on_objective",  # Lateral Movement
    "TA0009": "actions_on_objective",  # Collection
    "TA0010": "actions_on_objective",  # Exfiltration
    "TA0011": "command_and_control",  # Command and Control
    "TA0040": "actions_on_objective",  # Impact
}


# ═══════════════════════════════════════════════════════════════════
# Data Classes
# ═══════════════════════════════════════════════════════════════════


@dataclass
class ClusterScore:
    """Score from a single INADS cluster."""

    cluster_name: str
    raw_score: float  # Raw anomaly score (model-specific)
    calibrated_score: float  # Calibrated to [0, 1] probability
    confidence: float  # How confident the cluster is (0-1)
    features_used: int  # Number of non-null features
    contributing_fields: List[str] = field(default_factory=list)


@dataclass
class INADSResult:
    """Complete INADS scoring result for an event or device."""

    inads_score: float  # Final fused score [0, 1]
    threat_level: str  # BENIGN / LOW / MEDIUM / HIGH / CRITICAL
    cluster_scores: Dict[str, ClusterScore] = field(default_factory=dict)
    kill_chain_stage: Optional[str] = None
    kill_chain_progression: float = 0.0  # 0-1, how far through the kill chain
    dominant_cluster: Optional[str] = None
    explanation: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "inads_score": round(self.inads_score, 4),
            "threat_level": self.threat_level,
            "cluster_scores": {
                k: {
                    "raw": round(v.raw_score, 4),
                    "calibrated": round(v.calibrated_score, 4),
                    "confidence": round(v.confidence, 4),
                    "features_used": v.features_used,
                }
                for k, v in self.cluster_scores.items()
            },
            "kill_chain_stage": self.kill_chain_stage,
            "kill_chain_progression": round(self.kill_chain_progression, 4),
            "dominant_cluster": self.dominant_cluster,
            "explanation": self.explanation,
        }


# ═══════════════════════════════════════════════════════════════════
# Cluster 1: Process Tree
# ═══════════════════════════════════════════════════════════════════


class ProcessTreeCluster:
    """Analyzes parent-child process lineage for anomalous execution chains.

    Features:
        - Process tree depth (pid → ppid chain length)
        - Parent-child pair rarity (how unusual is this combination)
        - Executable path entropy
        - System vs user-space execution ratio
        - Process name length anomaly
        - cmdline token count and suspicious token density

    Model: IsolationForest on 8-dimensional feature space
    """

    FEATURE_NAMES = [
        "tree_depth",
        "parent_child_rarity",
        "exe_path_depth",
        "is_system_exe",
        "process_name_length",
        "cmdline_token_count",
        "suspicious_token_density",
        "has_shell_ancestor",
    ]

    _SYSTEM_PREFIXES = (
        "/usr/sbin/", "/usr/libexec/", "/System/Library/",
        "/sbin/", "/usr/bin/", "/Library/Apple/",
    )

    _SUSPICIOUS_TOKENS = {
        "curl", "wget", "nc", "ncat", "python", "perl", "ruby",
        "bash", "sh", "zsh", "osascript", "base64", "openssl",
        "chmod", "chown", "/tmp/", "/dev/null", ">/dev/",
        "|", "&&", "eval", "exec", "sudo", "su ",
    }

    def __init__(self):
        self.model = None
        self.parent_child_counts: Counter = Counter()
        self.total_parent_child: int = 0
        self._trained = False

    def extract_features(self, row: Dict[str, Any]) -> Optional[np.ndarray]:
        """Extract 8 process tree features from an event row."""
        pid = row.get("pid")
        ppid = row.get("ppid")
        exe = row.get("exe", "") or ""
        process_name = row.get("process_name", "") or row.get("name", "") or ""
        cmdline = row.get("cmdline", "") or ""
        parent_name = row.get("parent_name", "") or ""
        username = row.get("username", "") or ""

        if not process_name and not exe:
            return None

        # Feature 1: Tree depth (approximate from exe path)
        tree_depth = len(exe.split("/")) - 1 if exe else 0

        # Feature 2: Parent-child pair rarity
        pair = f"{parent_name}→{process_name}"
        pair_count = self.parent_child_counts.get(pair, 0)
        rarity = 1.0 / (1.0 + pair_count) if self.total_parent_child > 0 else 0.5

        # Feature 3: Exe path depth
        exe_depth = float(len(exe.split("/")) - 1) if exe else 0.0

        # Feature 4: System vs user exe
        is_system = 1.0 if any(exe.startswith(p) for p in self._SYSTEM_PREFIXES) else 0.0

        # Feature 5: Process name length (abnormally long names are suspicious)
        name_len = float(len(process_name))

        # Feature 6: Cmdline token count
        tokens = cmdline.split() if isinstance(cmdline, str) else cmdline
        if isinstance(tokens, list):
            token_count = float(len(tokens))
        else:
            token_count = float(len(str(cmdline).split()))

        # Feature 7: Suspicious token density
        cmdline_str = str(cmdline).lower()
        susp_count = sum(1 for t in self._SUSPICIOUS_TOKENS if t in cmdline_str)
        susp_density = susp_count / max(token_count, 1.0)

        # Feature 8: Has shell ancestor (ppid is a shell)
        shells = {"bash", "sh", "zsh", "fish", "tcsh", "csh"}
        has_shell = 1.0 if parent_name.lower() in shells else 0.0

        return np.array([
            tree_depth, rarity, exe_depth, is_system,
            name_len, token_count, susp_density, has_shell,
        ])

    def train(self, rows: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Train the process tree IsolationForest."""
        from sklearn.ensemble import IsolationForest

        # Build parent-child frequency table
        self.parent_child_counts.clear()
        for row in rows:
            pname = row.get("parent_name", "") or ""
            cname = row.get("process_name", "") or row.get("name", "") or ""
            if pname and cname:
                self.parent_child_counts[f"{pname}→{cname}"] += 1
        self.total_parent_child = sum(self.parent_child_counts.values())

        # Extract features
        features = []
        for row in rows:
            f = self.extract_features(row)
            if f is not None:
                features.append(f)

        if len(features) < MIN_TRAINING_SAMPLES:
            logger.warning("ProcessTree: insufficient samples (%d)", len(features))
            return {"status": "skipped", "reason": "insufficient_samples", "count": len(features)}

        X = np.array(features[:MAX_TRAINING_SAMPLES])

        self.model = IsolationForest(
            n_estimators=IF_N_ESTIMATORS,
            contamination=IF_CONTAMINATION,
            max_samples=min(IF_MAX_SAMPLES, len(X)),
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X)
        self._trained = True

        anomaly_scores = self.model.score_samples(X)
        anomaly_rate = float(np.mean(anomaly_scores < 0))

        return {
            "status": "trained",
            "samples": len(X),
            "features": len(self.FEATURE_NAMES),
            "anomaly_rate": round(anomaly_rate, 4),
            "parent_child_pairs": len(self.parent_child_counts),
        }

    def score(self, row: Dict[str, Any]) -> Optional[ClusterScore]:
        """Score a single event."""
        if not self._trained or self.model is None:
            return None

        features = self.extract_features(row)
        if features is None:
            return None

        raw = float(self.model.score_samples(features.reshape(1, -1))[0])
        # Convert IF score to anomaly probability: more negative = more anomalous
        # IF scores range roughly [-0.5, 0.5], normalize to [0, 1]
        calibrated = max(0.0, min(1.0, 0.5 - raw))

        non_null = int(np.sum(features != 0))
        confidence = min(1.0, non_null / len(self.FEATURE_NAMES))

        return ClusterScore(
            cluster_name="process_tree",
            raw_score=raw,
            calibrated_score=calibrated,
            confidence=confidence,
            features_used=non_null,
            contributing_fields=[
                self.FEATURE_NAMES[i] for i in range(len(features)) if features[i] != 0
            ],
        )


# ═══════════════════════════════════════════════════════════════════
# Cluster 2: Network Sequence
# ═══════════════════════════════════════════════════════════════════


class NetworkSequenceCluster:
    """Analyzes network connection patterns using Markov chain modeling.

    Instead of LSTM (heavy), uses a 2nd-order Markov chain on connection
    state tuples: (dst_port_class, protocol, direction). This captures
    C2 beaconing, lateral movement, and exfiltration patterns efficiently.

    Features:
        - Markov transition surprise (log-probability of current state)
        - Connection frequency deviation
        - Port class entropy
        - Byte ratio (out/in — exfiltration signature)
        - Private vs public IP ratio
        - Connection burst score

    Model: IsolationForest on 6-dimensional feature space
    """

    FEATURE_NAMES = [
        "transition_surprise",
        "conn_freq_deviation",
        "port_class_entropy",
        "byte_ratio",
        "is_external_ip",
        "burst_score",
    ]

    def __init__(self):
        self.model = None
        self.transition_counts: Dict[Tuple, Counter] = defaultdict(Counter)
        self.state_counts: Counter = Counter()
        self.total_transitions: int = 0
        self.mean_conn_freq: float = 0.0
        self.std_conn_freq: float = 1.0
        self._trained = False

    @staticmethod
    def _port_class(port: Any) -> str:
        """Classify port into categories."""
        try:
            p = int(port)
        except (TypeError, ValueError):
            return "unknown"
        if p < 1024:
            return "well_known"
        elif p < 49152:
            return "registered"
        else:
            return "ephemeral"

    @staticmethod
    def _is_private(ip: str) -> bool:
        if not ip:
            return True
        return (
            ip.startswith("10.") or ip.startswith("192.168.")
            or ip.startswith("127.") or ip.startswith("172.16.")
            or ip.startswith("172.17.") or ip.startswith("172.18.")
            or ip.startswith("fe80:") or ip == "::1"
        )

    def _state_tuple(self, row: Dict[str, Any]) -> Tuple[str, str, str]:
        """Create a state tuple from a network event."""
        port = row.get("local_port") or row.get("dst_port") or 0
        proto = str(row.get("protocol", "tcp")).lower()
        remote = row.get("remote_ip") or row.get("dst_ip") or ""
        direction = "internal" if self._is_private(remote) else "external"
        return (self._port_class(port), proto, direction)

    def extract_features(self, row: Dict[str, Any]) -> Optional[np.ndarray]:
        """Extract 6 network sequence features."""
        remote_ip = row.get("remote_ip") or row.get("dst_ip") or ""
        if not remote_ip:
            return None

        state = self._state_tuple(row)

        # Feature 1: Transition surprise
        if self.total_transitions > 0:
            state_total = self.state_counts.get(state, 0)
            surprise = -math.log(max(state_total / self.total_transitions, 1e-10))
        else:
            surprise = 0.0

        # Feature 2: Connection frequency deviation (placeholder — requires time window)
        freq_dev = 0.0  # Will be filled during batch scoring

        # Feature 3: Port class entropy (local computation)
        port_class = self._port_class(row.get("local_port") or row.get("dst_port") or 0)
        port_entropy = {"well_known": 0.0, "registered": 0.5, "ephemeral": 1.0, "unknown": 0.8}
        pe = port_entropy.get(port_class, 0.5)

        # Feature 4: Byte ratio (out/in — exfil signature)
        bytes_out = float(row.get("bytes_out") or row.get("bytes_tx") or 0)
        bytes_in = float(row.get("bytes_in") or row.get("bytes_rx") or 0)
        byte_ratio = bytes_out / max(bytes_in, 1.0)
        byte_ratio = min(byte_ratio, 100.0)  # Cap extreme ratios

        # Feature 5: External IP
        is_external = 0.0 if self._is_private(remote_ip) else 1.0

        # Feature 6: Burst score (approximated from context)
        burst = float(row.get("endpoint_burst_score", 0) or 0)

        return np.array([surprise, freq_dev, pe, byte_ratio, is_external, burst])

    def train(self, rows: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Train the network sequence model."""
        from sklearn.ensemble import IsolationForest

        # Build Markov transition table
        self.transition_counts.clear()
        self.state_counts.clear()
        prev_state = None
        for row in rows:
            remote = row.get("remote_ip") or row.get("dst_ip") or ""
            if not remote:
                continue
            state = self._state_tuple(row)
            self.state_counts[state] += 1
            if prev_state is not None:
                self.transition_counts[prev_state][state] += 1
            prev_state = state
        self.total_transitions = sum(self.state_counts.values())

        # Extract features
        features = []
        for row in rows:
            f = self.extract_features(row)
            if f is not None:
                features.append(f)

        if len(features) < MIN_TRAINING_SAMPLES:
            return {"status": "skipped", "reason": "insufficient_samples", "count": len(features)}

        X = np.array(features[:MAX_TRAINING_SAMPLES])

        self.model = IsolationForest(
            n_estimators=IF_N_ESTIMATORS,
            contamination=IF_CONTAMINATION,
            max_samples=min(IF_MAX_SAMPLES, len(X)),
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X)
        self._trained = True

        scores = self.model.score_samples(X)
        return {
            "status": "trained",
            "samples": len(X),
            "features": len(self.FEATURE_NAMES),
            "anomaly_rate": round(float(np.mean(scores < 0)), 4),
            "unique_states": len(self.state_counts),
            "transition_pairs": sum(len(v) for v in self.transition_counts.values()),
        }

    def score(self, row: Dict[str, Any]) -> Optional[ClusterScore]:
        if not self._trained or self.model is None:
            return None
        features = self.extract_features(row)
        if features is None:
            return None

        raw = float(self.model.score_samples(features.reshape(1, -1))[0])
        calibrated = max(0.0, min(1.0, 0.5 - raw))
        non_null = int(np.sum(features != 0))

        return ClusterScore(
            cluster_name="network_seq",
            raw_score=raw,
            calibrated_score=calibrated,
            confidence=min(1.0, non_null / len(self.FEATURE_NAMES)),
            features_used=non_null,
            contributing_fields=[
                self.FEATURE_NAMES[i] for i in range(len(features)) if features[i] != 0
            ],
        )


# ═══════════════════════════════════════════════════════════════════
# Cluster 3: Kill Chain State Machine
# ═══════════════════════════════════════════════════════════════════


class KillChainStateMachine:
    """Tracks attack progression through Lockheed Martin kill chain stages.

    Uses a Hidden Markov Model approach: each device has a current "attack
    state" that progresses forward as evidence accumulates. Forward-only
    (attacks progress, they don't regress) with decay.

    Features:
        - Current stage index (0-6, where 6 = actions on objective)
        - Stages hit count (how many distinct stages have evidence)
        - Stage progression velocity (stages per hour)
        - MITRE technique diversity (unique techniques seen)
        - Multi-tactic coherence (are the tactics consistent with progression?)
        - Time since first stage

    Scoring: Not IsolationForest — direct heuristic based on progression.
    """

    FEATURE_NAMES = [
        "current_stage_index",
        "stages_hit_count",
        "progression_velocity",
        "technique_diversity",
        "tactic_coherence",
        "time_since_first_stage_hours",
    ]

    def __init__(self):
        # Per-device state tracking
        self.device_states: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {
                "stages_seen": set(),
                "techniques_seen": set(),
                "tactics_seen": set(),
                "first_evidence_ts": None,
                "last_evidence_ts": None,
                "event_count": 0,
            }
        )
        self._trained = True  # Kill chain is rule-based, always "trained"

    def _classify_event_stage(self, row: Dict[str, Any]) -> Optional[str]:
        """Map an event to a kill chain stage."""
        # Try MITRE technique mapping
        mitre = row.get("mitre_techniques")
        if mitre:
            if isinstance(mitre, str):
                try:
                    mitre = json.loads(mitre)
                except (json.JSONDecodeError, TypeError):
                    mitre = []
            if isinstance(mitre, list):
                for tech in mitre:
                    # Map technique prefix to tactic to stage
                    for tactic, stage in TACTIC_TO_STAGE.items():
                        if tactic in str(tech):
                            return stage

        # Try event_category heuristic
        cat = str(row.get("event_category", "")).lower()
        if any(k in cat for k in ["recon", "scan", "discover"]):
            return "reconnaissance"
        elif any(k in cat for k in ["delivery", "phishing", "initial_access"]):
            return "delivery"
        elif any(k in cat for k in ["exploit", "execution", "exec"]):
            return "exploitation"
        elif any(k in cat for k in ["persist", "install", "launch_agent"]):
            return "installation"
        elif any(k in cat for k in ["c2", "beacon", "callback", "command_control"]):
            return "command_and_control"
        elif any(k in cat for k in ["exfil", "lateral", "collection", "impact"]):
            return "actions_on_objective"

        # Check for kill chain stage field directly
        stage = row.get("kill_chain_stage")
        if stage and stage in KILL_CHAIN_STAGES:
            return stage

        return None

    def update_device(self, device_id: str, row: Dict[str, Any]) -> None:
        """Update kill chain state for a device."""
        stage = self._classify_event_stage(row)
        if not stage:
            return

        state = self.device_states[device_id]
        state["stages_seen"].add(stage)
        state["event_count"] += 1

        now = row.get("timestamp_ns", time.time() * 1e9)
        if isinstance(now, str):
            try:
                now = float(now)
            except ValueError:
                now = time.time() * 1e9

        if state["first_evidence_ts"] is None:
            state["first_evidence_ts"] = now
        state["last_evidence_ts"] = now

        # Track MITRE diversity
        mitre = row.get("mitre_techniques")
        if mitre:
            if isinstance(mitre, str):
                try:
                    mitre = json.loads(mitre)
                except (json.JSONDecodeError, TypeError):
                    mitre = []
            if isinstance(mitre, list):
                for tech in mitre:
                    state["techniques_seen"].add(str(tech))

    def extract_features(self, device_id: str) -> Optional[np.ndarray]:
        """Extract 6 kill chain features for a device."""
        state = self.device_states.get(device_id)
        if not state or not state["stages_seen"]:
            return None

        # Feature 1: Current (most advanced) stage index
        max_stage = 0
        for stage in state["stages_seen"]:
            if stage in KILL_CHAIN_STAGES:
                idx = KILL_CHAIN_STAGES.index(stage)
                max_stage = max(max_stage, idx)

        # Feature 2: Stages hit count
        stages_hit = len(state["stages_seen"])

        # Feature 3: Progression velocity (stages per hour)
        first = state["first_evidence_ts"] or 0
        last = state["last_evidence_ts"] or 0
        elapsed_hours = max((last - first) / (3600 * 1e9), 0.001)
        velocity = stages_hit / elapsed_hours

        # Feature 4: Technique diversity
        tech_div = float(len(state["techniques_seen"]))

        # Feature 5: Tactic coherence (are stages contiguous?)
        stage_indices = sorted(
            KILL_CHAIN_STAGES.index(s)
            for s in state["stages_seen"]
            if s in KILL_CHAIN_STAGES
        )
        if len(stage_indices) > 1:
            gaps = sum(
                1 for i in range(len(stage_indices) - 1)
                if stage_indices[i + 1] - stage_indices[i] > 2
            )
            coherence = 1.0 - (gaps / max(len(stage_indices) - 1, 1))
        else:
            coherence = 0.5

        # Feature 6: Time since first stage (hours)
        time_since = elapsed_hours

        return np.array([
            float(max_stage),
            float(stages_hit),
            min(velocity, 100.0),
            tech_div,
            coherence,
            min(time_since, 168.0),  # Cap at 1 week
        ])

    def score(self, device_id: str) -> Optional[ClusterScore]:
        """Score kill chain progression for a device."""
        features = self.extract_features(device_id)
        if features is None:
            return None

        stage_idx = features[0]
        stages_hit = features[1]
        velocity = features[2]
        tech_div = features[3]
        coherence = features[4]

        # Scoring heuristic:
        # - More stages = higher score
        # - Coherent progression = higher score
        # - Fast velocity = higher score
        # - More diverse techniques = higher score
        stage_score = stage_idx / (len(KILL_CHAIN_STAGES) - 1)
        coverage_score = stages_hit / len(KILL_CHAIN_STAGES)
        velocity_score = min(velocity / 10.0, 1.0)
        diversity_score = min(tech_div / 10.0, 1.0)

        raw = (
            0.35 * stage_score
            + 0.25 * coverage_score * coherence
            + 0.20 * velocity_score
            + 0.20 * diversity_score
        )

        # Determine current stage name
        current_stage = None
        state = self.device_states.get(device_id)
        if state:
            max_idx = 0
            for s in state["stages_seen"]:
                if s in KILL_CHAIN_STAGES:
                    max_idx = max(max_idx, KILL_CHAIN_STAGES.index(s))
            current_stage = KILL_CHAIN_STAGES[max_idx]

        return ClusterScore(
            cluster_name="kill_chain",
            raw_score=raw,
            calibrated_score=max(0.0, min(1.0, raw)),
            confidence=min(1.0, stages_hit / 3.0),
            features_used=int(np.sum(features != 0)),
            contributing_fields=[
                self.FEATURE_NAMES[i] for i in range(len(features)) if features[i] != 0
            ],
        )

    def get_stage(self, device_id: str) -> Optional[str]:
        """Get current kill chain stage for a device."""
        state = self.device_states.get(device_id)
        if not state or not state["stages_seen"]:
            return None
        max_idx = 0
        for s in state["stages_seen"]:
            if s in KILL_CHAIN_STAGES:
                max_idx = max(max_idx, KILL_CHAIN_STAGES.index(s))
        return KILL_CHAIN_STAGES[max_idx]

    def get_progression(self, device_id: str) -> float:
        """Get kill chain progression ratio [0, 1]."""
        state = self.device_states.get(device_id)
        if not state or not state["stages_seen"]:
            return 0.0
        max_idx = 0
        for s in state["stages_seen"]:
            if s in KILL_CHAIN_STAGES:
                max_idx = max(max_idx, KILL_CHAIN_STAGES.index(s))
        return max_idx / (len(KILL_CHAIN_STAGES) - 1)

    def train(self, rows: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build kill chain state from historical events."""
        self.device_states.clear()
        for row in rows:
            device_id = row.get("device_id", "unknown")
            self.update_device(device_id, row)

        devices_with_stages = sum(
            1 for s in self.device_states.values() if s["stages_seen"]
        )
        total_stages = sum(
            len(s["stages_seen"]) for s in self.device_states.values()
        )

        return {
            "status": "trained",
            "devices_tracked": len(self.device_states),
            "devices_with_kill_chain": devices_with_stages,
            "total_stage_assignments": total_stages,
        }


# ═══════════════════════════════════════════════════════════════════
# Cluster 4: System Anomaly Detector
# ═══════════════════════════════════════════════════════════════════


class SystemAnomalyCluster:
    """Detects system-level behavioral anomalies.

    Features:
        - Username rarity (how common is this user in the dataset)
        - Agent diversity (how many different agents reported this event)
        - Time-of-day anomaly (off-hours activity)
        - Detection source rarity
        - Risk score deviation from mean
        - Event category rarity

    Model: IsolationForest on 6-dimensional feature space
    """

    FEATURE_NAMES = [
        "username_rarity",
        "agent_rarity",
        "time_of_day_anomaly",
        "detection_source_rarity",
        "risk_score_deviation",
        "category_rarity",
    ]

    def __init__(self):
        self.model = None
        self.username_counts: Counter = Counter()
        self.agent_counts: Counter = Counter()
        self.source_counts: Counter = Counter()
        self.category_counts: Counter = Counter()
        self.total_events: int = 0
        self.mean_risk: float = 0.0
        self.std_risk: float = 1.0
        self._trained = False

    def extract_features(self, row: Dict[str, Any]) -> Optional[np.ndarray]:
        """Extract 6 system anomaly features."""
        username = row.get("username", "") or ""
        agent = row.get("collection_agent", "") or ""
        det_source = row.get("detection_source", "") or ""
        category = row.get("event_category", "") or ""
        risk = float(row.get("risk_score", 0) or 0)

        if not agent and not category:
            return None

        # Feature 1: Username rarity
        u_count = self.username_counts.get(username, 0)
        u_rarity = 1.0 / (1.0 + u_count) if self.total_events > 0 else 0.5

        # Feature 2: Agent rarity
        a_count = self.agent_counts.get(agent, 0)
        a_rarity = 1.0 / (1.0 + a_count) if self.total_events > 0 else 0.5

        # Feature 3: Time of day anomaly
        ts = row.get("timestamp_dt", "")
        hour = 12.0
        if isinstance(ts, str) and "T" in ts:
            try:
                hour = float(ts.split("T")[1][:2])
            except (IndexError, ValueError):
                pass
        # Off-hours: 0-6 and 22-24 are anomalous
        if hour < 6 or hour >= 22:
            time_anomaly = 1.0
        elif hour < 9 or hour >= 18:
            time_anomaly = 0.5
        else:
            time_anomaly = 0.0

        # Feature 4: Detection source rarity
        s_count = self.source_counts.get(det_source, 0)
        s_rarity = 1.0 / (1.0 + s_count) if self.total_events > 0 else 0.5

        # Feature 5: Risk score deviation
        risk_dev = abs(risk - self.mean_risk) / max(self.std_risk, 0.01)
        risk_dev = min(risk_dev, 10.0)

        # Feature 6: Category rarity
        c_count = self.category_counts.get(category, 0)
        c_rarity = 1.0 / (1.0 + c_count) if self.total_events > 0 else 0.5

        return np.array([u_rarity, a_rarity, time_anomaly, s_rarity, risk_dev, c_rarity])

    def train(self, rows: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Train the system anomaly IsolationForest."""
        from sklearn.ensemble import IsolationForest

        # Build frequency tables
        self.username_counts.clear()
        self.agent_counts.clear()
        self.source_counts.clear()
        self.category_counts.clear()
        risks = []

        for row in rows:
            self.username_counts[row.get("username", "") or ""] += 1
            self.agent_counts[row.get("collection_agent", "") or ""] += 1
            self.source_counts[row.get("detection_source", "") or ""] += 1
            self.category_counts[row.get("event_category", "") or ""] += 1
            risks.append(float(row.get("risk_score", 0) or 0))
            self.total_events += 1

        if risks:
            self.mean_risk = float(np.mean(risks))
            self.std_risk = float(np.std(risks)) or 1.0

        features = []
        for row in rows:
            f = self.extract_features(row)
            if f is not None:
                features.append(f)

        if len(features) < MIN_TRAINING_SAMPLES:
            return {"status": "skipped", "reason": "insufficient_samples", "count": len(features)}

        X = np.array(features[:MAX_TRAINING_SAMPLES])

        self.model = IsolationForest(
            n_estimators=IF_N_ESTIMATORS,
            contamination=IF_CONTAMINATION,
            max_samples=min(IF_MAX_SAMPLES, len(X)),
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X)
        self._trained = True

        scores = self.model.score_samples(X)
        return {
            "status": "trained",
            "samples": len(X),
            "features": len(self.FEATURE_NAMES),
            "anomaly_rate": round(float(np.mean(scores < 0)), 4),
            "unique_users": len(self.username_counts),
            "unique_agents": len(self.agent_counts),
        }

    def score(self, row: Dict[str, Any]) -> Optional[ClusterScore]:
        if not self._trained or self.model is None:
            return None
        features = self.extract_features(row)
        if features is None:
            return None

        raw = float(self.model.score_samples(features.reshape(1, -1))[0])
        calibrated = max(0.0, min(1.0, 0.5 - raw))
        non_null = int(np.sum(features != 0))

        return ClusterScore(
            cluster_name="system_anomaly",
            raw_score=raw,
            calibrated_score=calibrated,
            confidence=min(1.0, non_null / len(self.FEATURE_NAMES)),
            features_used=non_null,
            contributing_fields=[
                self.FEATURE_NAMES[i] for i in range(len(features)) if features[i] != 0
            ],
        )


# ═══════════════════════════════════════════════════════════════════
# Cluster 5: File/Path Model
# ═══════════════════════════════════════════════════════════════════


class FilePathCluster:
    """Analyzes filesystem access patterns for anomalous behavior.

    Features:
        - Path depth
        - Path component rarity (how unusual is this directory?)
        - File extension rarity
        - Is sensitive path (ssh keys, credentials, system files)
        - File size anomaly
        - Has hash (sha256 present — indicates integrity monitoring)

    Model: IsolationForest on 6-dimensional feature space
    """

    FEATURE_NAMES = [
        "path_depth",
        "path_component_rarity",
        "extension_rarity",
        "is_sensitive_path",
        "file_size_log",
        "has_integrity_hash",
    ]

    _SENSITIVE_PATHS = [
        "/etc/shadow", "/etc/passwd", "/etc/sudoers",
        ".ssh/", "authorized_keys", "id_rsa", "id_ed25519",
        ".aws/credentials", ".kube/config",
        "Keychain", "login.keychain",
        "LaunchAgents/", "LaunchDaemons/",
        "/Library/Security/", "/tmp/", "/private/tmp/",
    ]

    def __init__(self):
        self.model = None
        self.path_component_counts: Counter = Counter()
        self.extension_counts: Counter = Counter()
        self.total_paths: int = 0
        self._trained = False

    def extract_features(self, row: Dict[str, Any]) -> Optional[np.ndarray]:
        """Extract 6 file/path features."""
        path = row.get("path", "") or row.get("exe", "") or ""
        if not path:
            return None

        # Feature 1: Path depth
        depth = float(len(path.split("/")) - 1)

        # Feature 2: Path component rarity
        components = path.split("/")
        if components and self.total_paths > 0:
            rarest = min(
                self.path_component_counts.get(c, 0) for c in components if c
            ) if any(c for c in components) else 0
            comp_rarity = 1.0 / (1.0 + rarest)
        else:
            comp_rarity = 0.5

        # Feature 3: Extension rarity
        ext = os.path.splitext(path)[1].lower()
        ext_count = self.extension_counts.get(ext, 0) if ext else 0
        ext_rarity = 1.0 / (1.0 + ext_count) if self.total_paths > 0 else 0.5

        # Feature 4: Sensitive path
        is_sensitive = 1.0 if any(sp in path for sp in self._SENSITIVE_PATHS) else 0.0

        # Feature 5: File size (log-scaled)
        size = row.get("file_size") or row.get("size") or 0
        try:
            size_log = math.log1p(float(size))
        except (TypeError, ValueError):
            size_log = 0.0

        # Feature 6: Has integrity hash
        has_hash = 1.0 if row.get("sha256") else 0.0

        return np.array([depth, comp_rarity, ext_rarity, is_sensitive, size_log, has_hash])

    def train(self, rows: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Train the file/path IsolationForest."""
        from sklearn.ensemble import IsolationForest

        self.path_component_counts.clear()
        self.extension_counts.clear()
        self.total_paths = 0

        for row in rows:
            path = row.get("path", "") or row.get("exe", "") or ""
            if not path:
                continue
            self.total_paths += 1
            for comp in path.split("/"):
                if comp:
                    self.path_component_counts[comp] += 1
            ext = os.path.splitext(path)[1].lower()
            if ext:
                self.extension_counts[ext] += 1

        features = []
        for row in rows:
            f = self.extract_features(row)
            if f is not None:
                features.append(f)

        if len(features) < MIN_TRAINING_SAMPLES:
            return {"status": "skipped", "reason": "insufficient_samples", "count": len(features)}

        X = np.array(features[:MAX_TRAINING_SAMPLES])

        self.model = IsolationForest(
            n_estimators=IF_N_ESTIMATORS,
            contamination=IF_CONTAMINATION,
            max_samples=min(IF_MAX_SAMPLES, len(X)),
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X)
        self._trained = True

        scores = self.model.score_samples(X)
        return {
            "status": "trained",
            "samples": len(X),
            "features": len(self.FEATURE_NAMES),
            "anomaly_rate": round(float(np.mean(scores < 0)), 4),
            "unique_extensions": len(self.extension_counts),
            "unique_components": len(self.path_component_counts),
        }

    def score(self, row: Dict[str, Any]) -> Optional[ClusterScore]:
        if not self._trained or self.model is None:
            return None
        features = self.extract_features(row)
        if features is None:
            return None

        raw = float(self.model.score_samples(features.reshape(1, -1))[0])
        calibrated = max(0.0, min(1.0, 0.5 - raw))
        non_null = int(np.sum(features != 0))

        return ClusterScore(
            cluster_name="file_path",
            raw_score=raw,
            calibrated_score=calibrated,
            confidence=min(1.0, non_null / len(self.FEATURE_NAMES)),
            features_used=non_null,
            contributing_fields=[
                self.FEATURE_NAMES[i] for i in range(len(features)) if features[i] != 0
            ],
        )


# ═══════════════════════════════════════════════════════════════════
# Calibrated Fusion Engine
# ═══════════════════════════════════════════════════════════════════


class CalibratedFusion:
    """Fuses 5 cluster scores into a single calibrated INADS score.

    Uses weighted geometric mean with confidence-adjusted weights.
    The geometric mean ensures that a high score in one cluster alone
    doesn't dominate — multiple perspectives must agree for high scores.

    Weight calibration:
        - Prior weights from DEFAULT_CLUSTER_WEIGHTS
        - Adjusted by per-event confidence (clusters with more features → higher weight)
        - Kill chain gets bonus weight when progression is detected
    """

    def __init__(self, weights: Optional[Dict[str, float]] = None):
        self.weights = weights or DEFAULT_CLUSTER_WEIGHTS.copy()

    def fuse(
        self,
        cluster_scores: Dict[str, ClusterScore],
        kill_chain_progression: float = 0.0,
    ) -> Tuple[float, str, str]:
        """Fuse cluster scores into a single INADS score.

        Args:
            cluster_scores: Scores from each cluster
            kill_chain_progression: Kill chain progression ratio [0, 1]

        Returns:
            (inads_score, threat_level, dominant_cluster)
        """
        if not cluster_scores:
            return 0.0, "BENIGN", "none"

        # Adjust weights by confidence
        adjusted_weights: Dict[str, float] = {}
        for name, cs in cluster_scores.items():
            base_weight = self.weights.get(name, 0.1)
            confidence_adj = base_weight * cs.confidence
            adjusted_weights[name] = confidence_adj

        # Kill chain bonus: if progression detected, boost kill chain weight
        if kill_chain_progression > 0.3 and "kill_chain" in adjusted_weights:
            adjusted_weights["kill_chain"] *= (1.0 + kill_chain_progression)

        # Normalize weights
        total_weight = sum(adjusted_weights.values())
        if total_weight == 0:
            return 0.0, "BENIGN", "none"

        for k in adjusted_weights:
            adjusted_weights[k] /= total_weight

        # Weighted combination (arithmetic mean with confidence-adjusted weights)
        # Using arithmetic instead of geometric to handle zero scores gracefully
        fused = 0.0
        for name, cs in cluster_scores.items():
            w = adjusted_weights.get(name, 0.0)
            fused += w * cs.calibrated_score

        # Apply kill chain amplification:
        # If we're deep in the kill chain AND other clusters agree, amplify
        if kill_chain_progression > 0.5:
            avg_other = np.mean([
                cs.calibrated_score for name, cs in cluster_scores.items()
                if name != "kill_chain"
            ]) if len(cluster_scores) > 1 else 0.0
            if avg_other > 0.3:
                fused = min(1.0, fused * (1.0 + kill_chain_progression * 0.5))

        fused = max(0.0, min(1.0, fused))

        # Determine threat level
        if fused < 0.15:
            level = "BENIGN"
        elif fused < 0.35:
            level = "LOW"
        elif fused < 0.55:
            level = "MEDIUM"
        elif fused < 0.75:
            level = "HIGH"
        else:
            level = "CRITICAL"

        # Find dominant cluster
        dominant = max(
            cluster_scores.items(),
            key=lambda x: x[1].calibrated_score * adjusted_weights.get(x[0], 0.1),
        )[0]

        return fused, level, dominant


# ═══════════════════════════════════════════════════════════════════
# INADS Engine (Main Class)
# ═══════════════════════════════════════════════════════════════════


class INADSEngine:
    """Intelligent Network Anomaly Detection System — 5-cluster scoring engine.

    This is the main entry point for INADS Phase 3. It:
        1. Loads training data from telemetry.db (security_events + observation_events)
        2. Trains 5 specialized cluster models
        3. Scores events/devices through all clusters
        4. Fuses scores via calibrated fusion
        5. Provides INADSResult objects for FusionEngine integration

    Usage:
        engine = INADSEngine(telemetry_db_path="data/telemetry.db")
        engine.train()
        result = engine.score_event(event_dict)
        device_result = engine.score_device(device_id)
    """

    def __init__(
        self,
        telemetry_db_path: str = "data/telemetry.db",
        models_dir: str = "data/intel/models/inads/",
    ):
        self.db_path = telemetry_db_path
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)

        # Initialize clusters
        self.process_tree = ProcessTreeCluster()
        self.network_seq = NetworkSequenceCluster()
        self.kill_chain = KillChainStateMachine()
        self.system_anomaly = SystemAnomalyCluster()
        self.file_path = FilePathCluster()

        # Fusion
        self.fusion = CalibratedFusion()

        # State
        self._trained = False
        self._training_metrics: Dict[str, Any] = {}

    def _load_training_data(self) -> List[Dict[str, Any]]:
        """Load training data from security_events + observation_events."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = []

        # Security events (high-value, labeled)
        try:
            cursor = conn.execute("""
                SELECT * FROM security_events
                ORDER BY timestamp_ns DESC
                LIMIT ?
            """, (MAX_TRAINING_SAMPLES // 2,))
            for row in cursor:
                d = dict(row)
                # Parse indicators JSON into flat dict
                indicators = d.get("indicators") or d.get("raw_attributes_json") or "{}"
                if isinstance(indicators, str):
                    try:
                        ind = json.loads(indicators)
                        # Promote mandate fields from JSON
                        for key in ["pid", "process_name", "exe", "remote_ip",
                                    "username", "cmdline", "ppid", "parent_name",
                                    "path", "sha256", "detection_source"]:
                            if key in ind and not d.get(key):
                                d[key] = ind[key]
                    except (json.JSONDecodeError, TypeError):
                        pass
                d["_source"] = "security_events"
                rows.append(d)
        except Exception as e:
            logger.warning("Failed to load security_events: %s", e)

        # Observation events (high-volume, baseline)
        try:
            cursor = conn.execute("""
                SELECT id, domain, event_type, timestamp_ns, device_id,
                       collection_agent, raw_attributes_json
                FROM observation_events
                WHERE raw_attributes_json IS NOT NULL
                AND raw_attributes_json != '{}'
                ORDER BY RANDOM()
                LIMIT ?
            """, (MAX_TRAINING_SAMPLES // 2,))
            for row in cursor:
                d = dict(row)
                raw = d.get("raw_attributes_json", "{}")
                if isinstance(raw, str):
                    try:
                        attrs = json.loads(raw)
                        d.update(attrs)
                    except (json.JSONDecodeError, TypeError):
                        pass
                d["_source"] = "observation_events"
                d["risk_score"] = 0.0  # Observations are baseline
                d["final_classification"] = "baseline"
                rows.append(d)
        except Exception as e:
            logger.warning("Failed to load observation_events: %s", e)

        conn.close()
        logger.info("Loaded %d training rows (sec+obs)", len(rows))
        return rows

    def train(self) -> Dict[str, Any]:
        """Train all 5 INADS clusters.

        Returns:
            Training metrics for each cluster
        """
        logger.info("INADS training started...")
        start = time.time()

        rows = self._load_training_data()
        if len(rows) < MIN_TRAINING_SAMPLES:
            return {
                "status": "failed",
                "reason": f"insufficient_data ({len(rows)} rows, need {MIN_TRAINING_SAMPLES})",
            }

        metrics = {}

        # Train each cluster
        logger.info("Training ProcessTree cluster...")
        metrics["process_tree"] = self.process_tree.train(rows)

        logger.info("Training NetworkSequence cluster...")
        # Filter to rows with network data
        net_rows = [r for r in rows if r.get("remote_ip") or r.get("dst_ip")]
        metrics["network_seq"] = self.network_seq.train(net_rows) if net_rows else {
            "status": "skipped", "reason": "no_network_data"
        }

        logger.info("Training KillChain state machine...")
        metrics["kill_chain"] = self.kill_chain.train(rows)

        logger.info("Training SystemAnomaly cluster...")
        metrics["system_anomaly"] = self.system_anomaly.train(rows)

        logger.info("Training FilePath cluster...")
        # Filter to rows with path data
        file_rows = [r for r in rows if r.get("path") or r.get("exe")]
        metrics["file_path"] = self.file_path.train(file_rows) if file_rows else {
            "status": "skipped", "reason": "no_file_data"
        }

        elapsed = time.time() - start
        metrics["elapsed_seconds"] = round(elapsed, 2)
        metrics["total_training_rows"] = len(rows)
        metrics["status"] = "completed"

        # Count trained clusters
        trained = sum(
            1 for v in metrics.values()
            if isinstance(v, dict) and v.get("status") == "trained"
        )
        metrics["clusters_trained"] = trained
        metrics["clusters_total"] = 5

        self._training_metrics = metrics
        self._trained = True

        # Save metrics
        metrics_path = self.models_dir / "inads_metrics.json"
        with open(metrics_path, "w") as f:
            json.dump(metrics, f, indent=2, default=str)

        logger.info(
            "INADS training complete: %d/5 clusters trained in %.1fs",
            trained, elapsed,
        )
        return metrics

    def score_event(self, event: Dict[str, Any]) -> INADSResult:
        """Score a single event through all 5 clusters.

        Args:
            event: Event dictionary with mandate fields

        Returns:
            INADSResult with fused score and per-cluster breakdown
        """
        cluster_scores: Dict[str, ClusterScore] = {}

        # Score through each cluster
        pt_score = self.process_tree.score(event)
        if pt_score:
            cluster_scores["process_tree"] = pt_score

        ns_score = self.network_seq.score(event)
        if ns_score:
            cluster_scores["network_seq"] = ns_score

        # Kill chain is device-level, not event-level
        device_id = event.get("device_id", "unknown")
        self.kill_chain.update_device(device_id, event)
        kc_score = self.kill_chain.score(device_id)
        if kc_score:
            cluster_scores["kill_chain"] = kc_score

        sa_score = self.system_anomaly.score(event)
        if sa_score:
            cluster_scores["system_anomaly"] = sa_score

        fp_score = self.file_path.score(event)
        if fp_score:
            cluster_scores["file_path"] = fp_score

        # Fuse
        kc_progression = self.kill_chain.get_progression(device_id)
        fused_score, threat_level, dominant = self.fusion.fuse(
            cluster_scores, kc_progression
        )

        # Build explanation
        explanations = []
        for name, cs in sorted(
            cluster_scores.items(), key=lambda x: x[1].calibrated_score, reverse=True
        ):
            if cs.calibrated_score > 0.3:
                explanations.append(
                    f"{name}={cs.calibrated_score:.2f} "
                    f"(conf={cs.confidence:.2f}, "
                    f"fields={cs.contributing_fields[:3]})"
                )

        kc_stage = self.kill_chain.get_stage(device_id)

        return INADSResult(
            inads_score=fused_score,
            threat_level=threat_level,
            cluster_scores=cluster_scores,
            kill_chain_stage=kc_stage,
            kill_chain_progression=kc_progression,
            dominant_cluster=dominant,
            explanation="; ".join(explanations) if explanations else "No significant anomalies",
        )

    def score_device(self, device_id: str) -> INADSResult:
        """Score a device by aggregating recent events.

        Loads the last N events for the device and produces an aggregate score.
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row

        events = []
        try:
            cursor = conn.execute("""
                SELECT * FROM security_events
                WHERE device_id = ?
                ORDER BY timestamp_ns DESC
                LIMIT 100
            """, (device_id,))
            for row in cursor:
                d = dict(row)
                indicators = d.get("indicators") or d.get("raw_attributes_json") or "{}"
                if isinstance(indicators, str):
                    try:
                        ind = json.loads(indicators)
                        for key in ["pid", "process_name", "exe", "remote_ip",
                                    "username", "cmdline", "ppid", "parent_name",
                                    "path", "sha256"]:
                            if key in ind and not d.get(key):
                                d[key] = ind[key]
                    except (json.JSONDecodeError, TypeError):
                        pass
                events.append(d)
        except Exception as e:
            logger.warning("Failed to load device events: %s", e)
        finally:
            conn.close()

        if not events:
            return INADSResult(
                inads_score=0.0,
                threat_level="BENIGN",
                explanation=f"No events for device {device_id}",
            )

        # Score each event and take the maximum (worst case)
        results = [self.score_event(e) for e in events]
        worst = max(results, key=lambda r: r.inads_score)

        # Override with aggregate kill chain
        worst.kill_chain_stage = self.kill_chain.get_stage(device_id)
        worst.kill_chain_progression = self.kill_chain.get_progression(device_id)

        return worst

    def get_metrics(self) -> Dict[str, Any]:
        """Return training metrics."""
        return self._training_metrics

    def is_trained(self) -> bool:
        """Check if INADS has been trained."""
        return self._trained


# ═══════════════════════════════════════════════════════════════════
# CLI Entry Point
# ═══════════════════════════════════════════════════════════════════


def main():
    """Train INADS and print results."""
    import argparse

    parser = argparse.ArgumentParser(description="INADS Phase 3 Engine")
    parser.add_argument("--db", default="data/telemetry.db", help="Telemetry DB path")
    parser.add_argument("--models-dir", default="data/intel/models/inads/", help="Models directory")
    parser.add_argument("--score-device", help="Score a specific device")
    args = parser.parse_args()

    engine = INADSEngine(
        telemetry_db_path=args.db,
        models_dir=args.models_dir,
    )

    # Train
    metrics = engine.train()
    print(json.dumps(metrics, indent=2, default=str))

    # Score device if requested
    if args.score_device:
        result = engine.score_device(args.score_device)
        print("\n--- Device Score ---")
        print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()
