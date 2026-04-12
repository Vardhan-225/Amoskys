"""
Fusion Engine - Intelligence Correlation Orchestrator

Ingests telemetry events from multiple agents, correlates them across
time windows, and emits higher-level intelligence objects:
- Incidents (attack chains)
- DeviceRiskSnapshots (security posture)

Architecture:
    Agents → EventBus → WAL/DB → FusionEngine → Incidents + Risk DB

Enhanced with Advanced Rules:
    - APT detection patterns
    - Fileless attack detection
    - Defense evasion detection
    - Credential theft chains
    - Lateral movement patterns
    - Data exfiltration detection

AMRDR Integration (Sprint 2):
    - Optional ReliabilityTracker injection (defaults to NoOp)
    - Incident confidence weighted by agent reliability scores
    - Device risk scoring scaled by average agent weight
    - Drift alerts emitted when AMRDR detects agent degradation
    - Analyst feedback loop to update agent reliability
"""

import json
import logging
import sqlite3
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from amoskys.intel.advanced_rules import evaluate_advanced_rules
from amoskys.intel.models import (
    DeviceRiskSnapshot,
    Incident,
    MitreTactic,
    Severity,
    TelemetryEventView,
)
from amoskys.intel.reliability import (
    DriftType,
    NoOpReliabilityTracker,
    RecalibrationTier,
    ReliabilityTracker,
)
from amoskys.intel.rules import evaluate_rules
from amoskys.intel.scoring import SequenceScorer

logger = logging.getLogger(__name__)


class FusionEngine:
    """Intelligence correlation engine

    Maintains sliding windows of events per device, runs correlation rules,
    and emits incidents + device risk scores.

    Attributes:
        db_path: Path to fusion intelligence database
        window_minutes: Size of correlation window in minutes
        device_state: Per-device event buffers and state
        db: SQLite connection for incidents/risk persistence
    """

    def __init__(
        self,
        db_path: str = "data/intel/fusion.db",
        window_minutes: int = 30,
        eval_interval: int = 60,
        reliability_tracker: Optional[ReliabilityTracker] = None,
        inads_engine: Optional[Any] = None,
        probe_calibrator: Optional[Any] = None,
    ):
        """Initialize fusion engine

        Args:
            db_path: Path to intelligence database
            window_minutes: Correlation window size (default: 30 minutes)
            eval_interval: How often to evaluate rules in seconds
            reliability_tracker: AMRDR reliability tracker (defaults to NoOp)
            inads_engine: Optional INADS multi-perspective scoring engine
            probe_calibrator: Optional ProbeCalibrator for per-probe precision weights
        """
        self.db_path = db_path
        self.window_minutes = window_minutes
        self.eval_interval = eval_interval

        # AMRDR: reliability tracker (NoOp if not provided — backward compatible)
        self.reliability_tracker: ReliabilityTracker = (
            reliability_tracker or NoOpReliabilityTracker()
        )

        # INADS: multi-perspective anomaly scoring (None = disabled, backward compatible)
        self._inads = inads_engine

        # Probe calibrator: per-probe precision weights for risk suppression
        self._probe_cal = probe_calibrator

        # Per-device state: event buffers + risk scores
        # events: capped deque prevents unbounded memory growth
        # known_ips: dict {ip: last_seen_ts} with eviction in _trim_device
        self._event_buffer_max = 1000
        self.device_state: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {
                "events": deque(maxlen=self._event_buffer_max),
                "risk_score": 10,  # Base score
                "last_eval": None,
                "known_ips": {},  # {ip: last_seen_timestamp}
                "incident_count": 0,
            }
        )

        # Metrics tracking
        self.metrics: Dict[str, Any] = {
            "total_events_processed": 0,
            "total_incidents_created": 0,
            "total_evaluations": 0,
            "incidents_by_severity": defaultdict(int),
            "incidents_by_rule": defaultdict(int),
            "devices_tracked": 0,
            "last_eval_duration_ms": 0,
            "drift_alerts_emitted": 0,
        }

        # Incident cooldown: suppress duplicate incidents per (rule_name, device_id)
        # Key: (rule_name, device_id) → last fire timestamp
        self._incident_cooldowns: Dict[tuple, float] = {}
        self._cooldown_seconds = 300  # 5 min suppression per rule+device

        # Initialize database
        self._init_db()

        tracker_type = type(self.reliability_tracker).__name__
        logger.info(
            f"FusionEngine initialized: {db_path}, window={window_minutes}m, "
            f"tracker={tracker_type}"
        )

    def _init_db(self):
        """Initialize SQLite database for incidents and device risk"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        self.db = sqlite3.connect(
            self.db_path, isolation_level=None, check_same_thread=False
        )
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")

        # Incidents table (with AMRDR columns)
        self.db.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                tactics TEXT NOT NULL,
                techniques TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                summary TEXT NOT NULL,
                start_ts TEXT,
                end_ts TEXT,
                event_ids TEXT NOT NULL,
                metadata TEXT NOT NULL,
                created_at TEXT NOT NULL,
                agent_weights TEXT NOT NULL DEFAULT '{}',
                weighted_confidence REAL NOT NULL DEFAULT 1.0,
                contributing_agents TEXT NOT NULL DEFAULT '[]'
            )
        """
        )

        # Migration: add AMRDR columns to existing databases
        self._migrate_amrdr_columns()
        self.db.execute(
            "CREATE INDEX IF NOT EXISTS idx_incidents_device ON incidents(device_id)"
        )
        self.db.execute(
            "CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at)"
        )

        # Device risk snapshots table
        self.db.execute(
            """
            CREATE TABLE IF NOT EXISTS device_risk (
                device_id TEXT PRIMARY KEY,
                score INTEGER NOT NULL,
                level TEXT NOT NULL,
                reason_tags TEXT NOT NULL,
                supporting_events TEXT NOT NULL,
                metadata TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """
        )

        logger.info("Fusion database schema initialized")

    def _migrate_amrdr_columns(self):
        """Add AMRDR columns to existing incidents table if missing.

        Safe to call on fresh databases (no-op) and existing ones (additive).
        """
        existing_columns = {
            row[1] for row in self.db.execute("PRAGMA table_info(incidents)").fetchall()
        }

        migrations = [
            ("agent_weights", "TEXT NOT NULL DEFAULT '{}'"),
            ("weighted_confidence", "REAL NOT NULL DEFAULT 1.0"),
            ("contributing_agents", "TEXT NOT NULL DEFAULT '[]'"),
            ("start_ts_ns", "INTEGER DEFAULT NULL"),
            ("end_ts_ns", "INTEGER DEFAULT NULL"),
            ("duration_seconds", "REAL DEFAULT NULL"),
            ("mitre_sequence", "TEXT DEFAULT NULL"),
            # Incident merge columns — forensic-preserving dedup
            ("observation_count", "INTEGER DEFAULT 1"),
            ("observation_metadata", "TEXT DEFAULT '{}'"),
            # Materialized incident context — complete evidence package
            ("incident_context_json", "TEXT DEFAULT NULL"),
        ]

        for col_name, col_def in migrations:
            if col_name not in existing_columns:
                self.db.execute(
                    f"ALTER TABLE incidents ADD COLUMN {col_name} {col_def}"
                )
                logger.info(f"Migrated incidents table: added {col_name}")

    def ingest_telemetry_from_db(self, telemetry_db_path: str):
        """Ingest telemetry events from agent database

        Reads recent events from agent WAL/DB and adds them to device buffers.

        Args:
            telemetry_db_path: Path to agent telemetry database
        """
        try:
            db = sqlite3.connect(telemetry_db_path, timeout=5.0)

            # Query recent events (last window_minutes)
            cutoff = datetime.now() - timedelta(minutes=self.window_minutes)
            cutoff_ns = int(cutoff.timestamp() * 1e9)

            # This assumes a unified events table - adapt to your schema
            # For now, we'll skip actual DB ingestion and focus on the correlation logic
            # In production, you'd query from flowagent.db, proc_agent.db, etc.

            db.close()
            logger.debug(f"Ingested events from {telemetry_db_path}")

        except Exception as e:
            logger.error(f"Failed to ingest from {telemetry_db_path}: {e}")

    def get_active_devices(self) -> list:
        """Return device IDs that have events in their buffer."""
        return [
            device_id
            for device_id, state in self.device_state.items()
            if state.get("events")
        ]

    def add_event(self, event: TelemetryEventView):
        """Add event to device buffer and trim old events

        Args:
            event: Normalized telemetry event view
        """
        device_id = event.device_id
        state = self.device_state[device_id]

        # Add to event buffer (deque auto-evicts oldest when maxlen reached)
        state["events"].append(event)

        # Update metrics
        self.metrics["total_events_processed"] += 1

        # Trim events outside correlation window
        cutoff = datetime.now() - timedelta(minutes=self.window_minutes)
        while state["events"] and state["events"][0].timestamp < cutoff:
            state["events"].popleft()

        # Track known IPs for anomaly detection (with timestamp for eviction)
        if event.security_event:
            source_ip = event.security_event.get("source_ip")
            if source_ip:
                state["known_ips"][source_ip] = time.time()

        logger.debug(
            f"Added event {event.event_id} to {device_id} buffer ({len(state['events'])} events)"
        )

    def evaluate_device(
        self, device_id: str
    ) -> tuple[List[Incident], DeviceRiskSnapshot]:
        """Evaluate correlation rules and update device risk for a single device

        AMRDR integration:
        - Pulls fusion weights from reliability tracker
        - Passes weights to rule evaluation for confidence scoring
        - Annotates incidents with agent_weights, weighted_confidence,
          and contributing_agents
        - Checks for drift alerts and emits AMRDR_DRIFT incidents

        Args:
            device_id: Device to evaluate

        Returns:
            Tuple of (new incidents, updated risk snapshot)
        """
        state = self.device_state[device_id]
        events = state["events"]

        if not events:
            logger.debug(f"No events for {device_id}, skipping evaluation")
            return [], self._get_current_risk_snapshot(device_id)

        # Pull AMRDR fusion weights
        weights = self.reliability_tracker.get_fusion_weights()

        # Sort events by probe detection timestamp for correct causal ordering
        # (batch delivery from sleeping endpoints can invert arrival order)
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        # Run correlation rules with AMRDR weights (using sorted events)
        incidents = evaluate_rules(sorted_events, device_id, weights=weights)

        # Run advanced correlation rules with AMRDR weights
        advanced_incidents = evaluate_advanced_rules(
            sorted_events, device_id, weights=weights
        )
        incidents.extend(advanced_incidents)

        # Detect kill chain sequences and promote to incidents (Step 4)
        sequence_incidents = self._detect_sequence_incidents(device_id, sorted_events)
        incidents.extend(sequence_incidents)

        # Emit AMRDR drift alerts if any agent is drifting
        drift_incidents = self._emit_drift_alerts(device_id)
        incidents.extend(drift_incidents)

        # INADS multi-perspective scoring
        inads_result = None
        if self._inads is not None:
            try:
                inads_result = self._inads.score_device(device_id)
                composite = (
                    inads_result.get("max_composite", 0)
                    if isinstance(inads_result, dict)
                    else getattr(inads_result, "composite_score", 0)
                )
                threat = (
                    inads_result.get("threat_level", "low")
                    if isinstance(inads_result, dict)
                    else getattr(inads_result, "threat_level", "low")
                )
                top = (
                    inads_result.get("top_events", [{}])[0]
                    if isinstance(inads_result, dict)
                    else {}
                )
                dominant = top.get(
                    "dominant_cluster",
                    (
                        inads_result.get("dominant_cluster", "unknown")
                        if isinstance(inads_result, dict)
                        else getattr(inads_result, "dominant_cluster", "unknown")
                    ),
                )
                if composite > 0.7:
                    inads_incident = Incident(
                        incident_id=str(uuid.uuid4()),
                        device_id=device_id,
                        severity=(
                            Severity.HIGH if composite <= 0.9 else Severity.CRITICAL
                        ),
                        tactics=[MitreTactic.COLLECTION.value],
                        techniques=[],
                        rule_name="INADS_ML_ANOMALY",
                        summary=(
                            f"INADS multi-perspective anomaly: "
                            f"composite={composite:.3f} ({threat}), "
                            f"dominant={dominant}"
                        ),
                        start_ts=datetime.now(),
                        end_ts=datetime.now(),
                        event_ids=[],
                        metadata={
                            "inads_composite": str(composite),
                            "inads_threat_level": str(threat),
                            "inads_dominant_cluster": str(dominant),
                        },
                    )
                    incidents.append(inads_incident)
                    logger.info(
                        "INADS anomaly incident for %s: composite=%.3f",
                        device_id,
                        composite,
                    )
            except Exception:
                logger.debug("INADS scoring failed for %s", device_id, exc_info=True)

        # Fallback: when we have security detections but no rule fired, create a
        # single "High-risk detections" incident so real detections surface on the dashboard
        if not incidents:
            fallback = self._create_high_risk_fallback_incident(
                device_id, sorted_events
            )
            if fallback is not None:
                incidents.append(fallback)

        # Update device risk score (now reliability-weighted)
        risk_snapshot = self._calculate_device_risk(
            device_id, events, incidents, weights
        )

        # Update state
        state["last_eval"] = datetime.now()
        state["incident_count"] += len(incidents)

        # AMRDR: auto-update agent reliability from incident contributions.
        # Every agent that contributed to a detected incident gets a positive
        # signal (α += 1). Every agent that contributed events but NO incident
        # was created gets an implicit negative (its events were noise).
        try:
            if incidents:
                # Agents that contributed to real incidents → positive
                credited: set = set()
                for inc in incidents:
                    for agent_id in getattr(inc, "contributing_agents", []):
                        if agent_id and agent_id not in credited:
                            self.reliability_tracker.update(
                                agent_id=agent_id, ground_truth_match=True
                            )
                            credited.add(agent_id)
            # Track all agents that submitted events this cycle
            for ev in sorted_events:
                agent_id = getattr(ev, "collection_agent", "") or ""
                if agent_id and agent_id not in getattr(self, "_amrdr_seen", set()):
                    # Register the agent so AMRDR tracks it
                    self.reliability_tracker.get_state(agent_id)
            self._amrdr_seen = {
                getattr(ev, "collection_agent", "") for ev in sorted_events
            }
        except Exception:
            pass  # AMRDR auto-update is best-effort

        logger.info(
            f"Evaluated {device_id}: {len(incidents)} incidents, "
            f"risk={risk_snapshot.score}, active_weights={len(weights)}"
        )

        return incidents, risk_snapshot

    def _calculate_device_risk(
        self,
        device_id: str,
        events: List[TelemetryEventView],
        new_incidents: List[Incident],
        weights: Optional[Dict[str, float]] = None,
    ) -> DeviceRiskSnapshot:
        """Calculate device risk score from events and incidents

        AMRDR enhancement: incident contributions are scaled by the average
        reliability weight of contributing agents. Low-reliability agents
        contribute less to the device risk score.

        Implements the scoring model:
        - Base: 10 points
        - Failed SSH: +5 each (cap at +20)
        - Successful SSH from new IP: +15
        - New SSH key: +30
        - New LaunchAgent in /Users: +25
        - Suspicious sudo: +30
        - HIGH incident: +20 * avg_agent_weight
        - CRITICAL incident: +40 * avg_agent_weight
        - Decay: -10 per 10 minutes without risky events
        - Clamp: [0, 100]

        Args:
            device_id: Device being evaluated
            events: Recent events in window
            new_incidents: Incidents fired in this evaluation
            weights: AMRDR fusion weights {agent_id: weight}

        Returns:
            DeviceRiskSnapshot
        """
        state = self.device_state[device_id]
        score = state["risk_score"]  # Start from current score
        state["_prev_score"] = score  # Snapshot for probe suppression
        reason_tags = []
        supporting_events = []

        # Count event types
        failed_ssh_count = 0
        new_ssh_keys = 0
        new_launch_agents = 0
        suspicious_sudo_count = 0
        successful_ssh_new_ip = 0

        for event in events:
            # Failed SSH attempts
            if (
                event.event_type == "SECURITY"
                and event.security_event
                and event.security_event.get("event_action") == "SSH"
                and event.security_event.get("event_outcome") == "FAILURE"
            ):
                failed_ssh_count += 1
                supporting_events.append(event.event_id)

            # Successful SSH from new IP
            elif (
                event.event_type == "SECURITY"
                and event.security_event
                and event.security_event.get("event_action") == "SSH"
                and event.security_event.get("event_outcome") == "SUCCESS"
            ):
                source_ip = event.security_event.get("source_ip")
                # Simple new IP detection (in production, use better baseline)
                if source_ip and source_ip not in ["127.0.0.1", "localhost"]:
                    successful_ssh_new_ip += 1
                    supporting_events.append(event.event_id)

            # SSH key changes
            elif (
                event.event_type == "AUDIT"
                and event.audit_event
                and event.audit_event.get("object_type") == "SSH_KEYS"
            ):
                new_ssh_keys += 1
                supporting_events.append(event.event_id)

            # Launch agents in user directories
            elif (
                event.event_type == "AUDIT"
                and event.audit_event
                and event.audit_event.get("object_type")
                in ["LAUNCH_AGENT", "LAUNCH_DAEMON"]
                and "/Users/" in event.attributes.get("file_path", "")
            ):
                new_launch_agents += 1
                supporting_events.append(event.event_id)

            # Suspicious sudo
            elif (
                event.event_type == "SECURITY"
                and event.security_event
                and event.security_event.get("event_action") == "SUDO"
            ):
                command = event.attributes.get("sudo_command", "")
                if any(
                    pattern in command
                    for pattern in ["rm -rf", "/etc/sudoers", "LaunchAgent"]
                ):
                    suspicious_sudo_count += 1
                    supporting_events.append(event.event_id)

        # Apply scoring rules
        if failed_ssh_count > 0:
            points = min(failed_ssh_count * 5, 20)  # Cap at +20
            score += points
            reason_tags.append(f"ssh_brute_force_attempts_{failed_ssh_count}")

        if successful_ssh_new_ip > 0:
            score += successful_ssh_new_ip * 15
            reason_tags.append(f"ssh_logins_new_ip_{successful_ssh_new_ip}")

        if new_ssh_keys > 0:
            score += new_ssh_keys * 30
            reason_tags.append(f"new_ssh_keys_{new_ssh_keys}")

        if new_launch_agents > 0:
            score += new_launch_agents * 25
            reason_tags.append(f"new_persistence_{new_launch_agents}")

        if suspicious_sudo_count > 0:
            score += suspicious_sudo_count * 30
            reason_tags.append(f"suspicious_sudo_{suspicious_sudo_count}")

        # Temporal velocity scoring: detect bursts and acceleration from probe timestamps
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        if len(sorted_events) >= 5:
            # Burst detection: >5 events in any 10-second window
            timestamps = [e.timestamp.timestamp() for e in sorted_events]
            max_burst = 0
            left = 0
            for right in range(len(timestamps)):
                while timestamps[right] - timestamps[left] > 10.0:
                    left += 1
                max_burst = max(max_burst, right - left + 1)
            if max_burst > 5:
                score += 15
                reason_tags.append(f"temporal_burst_{max_burst}_in_10s")

            # Acceleration: compare event rate in first half vs second half of window
            mid = len(timestamps) // 2
            first_half_span = timestamps[mid] - timestamps[0] if mid > 0 else 1.0
            second_half_span = (
                timestamps[-1] - timestamps[mid] if mid < len(timestamps) - 1 else 1.0
            )
            first_rate = mid / max(first_half_span, 0.1)
            second_rate = (len(timestamps) - mid) / max(second_half_span, 0.1)
            if second_rate > first_rate * 2.0 and second_rate > 0.5:
                score += 10
                reason_tags.append("temporal_acceleration")

        # First-time IP detection using known_ips history
        for event in events:
            if event.security_event:
                source_ip = event.security_event.get("source_ip")
                if source_ip and source_ip not in ["127.0.0.1", "localhost"]:
                    if source_ip not in state["known_ips"]:
                        score += 10
                        reason_tags.append(f"first_seen_ip_{source_ip}")
                        break  # Only count once per evaluation

        # Add incident contributions (scaled by AMRDR agent weights)
        for incident in new_incidents:
            # Compute average weight of contributing agents
            avg_weight = 1.0
            if weights and incident.contributing_agents:
                agent_weights = [
                    weights.get(a, 1.0) for a in incident.contributing_agents
                ]
                avg_weight = sum(agent_weights) / len(agent_weights)
            elif incident.weighted_confidence < 1.0:
                avg_weight = incident.weighted_confidence

            # Speed multiplier: kill chains completing in < 60s = automated tooling
            speed_mult = 1.0
            if incident.start_ts and incident.end_ts:
                duration = (incident.end_ts - incident.start_ts).total_seconds()
                if 0 < duration < 60:
                    speed_mult = 1.5
                    reason_tags.append(f"rapid_incident_{duration:.0f}s")

            if incident.severity == Severity.CRITICAL:
                base_points = 40
                scaled_points = int(base_points * avg_weight * speed_mult)
                score += scaled_points
                reason_tags.append(
                    f"incident_critical_{incident.rule_name}" f"(w={avg_weight:.2f})"
                )
            elif incident.severity == Severity.HIGH:
                base_points = 20
                scaled_points = int(base_points * avg_weight * speed_mult)
                score += scaled_points
                reason_tags.append(
                    f"incident_high_{incident.rule_name}" f"(w={avg_weight:.2f})"
                )

            supporting_events.extend(incident.event_ids)

        # ── Probe precision suppression ──
        # Scale event-driven score increase by the precision weight of contributing probes.
        # Low-precision probes (process_spawn at 0.06) suppress their contribution by ~94%.
        # High-precision probes (dns_beaconing at 0.95) pass through near-fully.
        base_score = state.get("_prev_score", 10)
        event_driven_increase = score - base_score
        if event_driven_increase > 0 and self._probe_cal is not None:
            # Collect precision weights from events that had supporting evidence
            probe_weights = []
            for event in events:
                pn = event.probe_name or (
                    event.security_event.get("event_category", "")
                    if event.security_event
                    else ""
                )
                if pn:
                    w = self._probe_cal.get_weight(pn)
                    probe_weights.append(w)
            if probe_weights:
                avg_probe_weight = sum(probe_weights) / len(probe_weights)
                suppressed_increase = event_driven_increase * avg_probe_weight
                score = base_score + suppressed_increase
                if avg_probe_weight < 0.9:
                    reason_tags.append(
                        f"probe_suppression(avg_w={avg_probe_weight:.2f},"
                        f"raw={event_driven_increase:.0f}→{suppressed_increase:.0f})"
                    )

        # INADS contribution: 0-50 points with kill chain amplification
        # (variable 1.0-1.5x based on progression ratio, gated by cross-cluster)
        if self._inads is not None:
            try:
                inads_result = self._inads.score_device(device_id)
                composite = (
                    inads_result.get("max_composite", 0)
                    if isinstance(inads_result, dict)
                    else getattr(inads_result, "composite_score", 0)
                )
                if composite > 0.0:
                    # Scale: 0.0 → 0 points, 1.0 → 50 points (half the 100-pt scale)
                    inads_points = int(composite * 50)

                    # Kill chain amplification: if INADS sees active kill chain
                    # progression > 50%, amplify by up to 1.5x
                    kc_prog = 0.0
                    if isinstance(inads_result, dict):
                        top = inads_result.get("top_events", [{}])
                        if top:
                            kc_prog = top[0].get("kill_chain_progress", 0.0) or 0.0
                    else:
                        kc_prog = getattr(inads_result, "kill_chain_progression", 0.0)

                    if kc_prog > 0.5:
                        amplifier = 1.0 + (kc_prog - 0.5)  # 1.0 to 1.5
                        inads_points = int(inads_points * amplifier)

                    if inads_points > 0:
                        score += inads_points
                        reason_tags.append(
                            f"inads_anomaly_{composite:.2f}" f"(+{inads_points}pts)"
                        )
            except Exception:
                pass  # INADS failure never breaks risk calculation

        # Decay: reduce score over time if no recent risky events
        if state["last_eval"]:
            time_since_eval = (datetime.now() - state["last_eval"]).total_seconds()
            decay_periods = int(time_since_eval / 600)  # Every 10 minutes
            if decay_periods > 0 and not reason_tags:
                score -= decay_periods * 10
                reason_tags.append(f"score_decay_{decay_periods}x10min")

        # Clamp [0, 100]
        score = max(0, min(100, score))

        # Update state
        state["risk_score"] = score

        # Map to level
        level = DeviceRiskSnapshot.score_to_level(score)

        snapshot = DeviceRiskSnapshot(
            device_id=device_id,
            score=score,
            level=level,
            reason_tags=reason_tags[:10],  # Limit to 10 most recent
            supporting_events=supporting_events[:50],  # Limit to 50
            metadata={
                "event_count": str(len(events)),
                "incident_count": str(len(new_incidents)),
                "window_minutes": str(self.window_minutes),
            },
        )

        return snapshot

    def _get_current_risk_snapshot(self, device_id: str) -> DeviceRiskSnapshot:
        """Get current risk snapshot for device (no evaluation)

        Args:
            device_id: Device ID

        Returns:
            DeviceRiskSnapshot with current score
        """
        state = self.device_state[device_id]
        score = state["risk_score"]
        level = DeviceRiskSnapshot.score_to_level(score)

        return DeviceRiskSnapshot(
            device_id=device_id,
            score=score,
            level=level,
            metadata={"window_minutes": str(self.window_minutes)},
        )

    def _merge_or_create_incident(self, incident: Incident, device_id: str) -> bool:
        """Merge into existing open incident or create new one.

        If an open incident exists for the same (rule_name, device_id),
        merge the new event IDs into it and bump the observation count.
        All contributing events are preserved for forensic analysis.

        Returns True if a NEW incident was created, False if merged.
        """
        try:
            row = self.db.execute(
                """
                SELECT incident_id, event_ids, observation_count,
                       observation_metadata, severity
                FROM incidents
                WHERE rule_name = ? AND device_id = ?
                ORDER BY created_at DESC LIMIT 1
                """,
                (incident.rule_name, device_id),
            ).fetchone()
        except Exception:
            row = None

        if row:
            existing_id = row[0]
            existing_event_ids = json.loads(row[1]) if row[1] else []
            obs_count = (row[2] or 1) + 1
            obs_meta = json.loads(row[3]) if row[3] else {}

            # Merge event IDs (deduplicated, preserving order)
            seen = set(existing_event_ids)
            merged_event_ids = list(existing_event_ids)
            for eid in incident.event_ids:
                if eid not in seen:
                    merged_event_ids.append(eid)
                    seen.add(eid)

            # Record this observation cycle
            cycles = obs_meta.get("observation_cycles", [])
            cycles.append(
                {
                    "cycle_ts": incident.created_at.isoformat(),
                    "event_ids": incident.event_ids,
                    "event_count": len(incident.event_ids),
                }
            )
            # Cap at 100 cycles (FIFO)
            if len(cycles) > 100:
                cycles = cycles[-100:]
            obs_meta["observation_cycles"] = cycles
            obs_meta["first_seen"] = obs_meta.get(
                "first_seen", incident.created_at.isoformat()
            )
            obs_meta["last_seen"] = incident.created_at.isoformat()
            obs_meta["total_contributing_events"] = len(merged_event_ids)

            # Escalate severity if new observation is more severe
            _SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            existing_sev = row[4] or "low"
            new_sev = incident.severity.value
            final_sev = (
                new_sev
                if _SEV_ORDER.get(new_sev, 0) > _SEV_ORDER.get(existing_sev, 0)
                else existing_sev
            )

            try:
                self.db.execute(
                    """
                    UPDATE incidents
                    SET event_ids = ?, observation_count = ?,
                        observation_metadata = ?, severity = ?,
                        end_ts = ?
                    WHERE incident_id = ?
                    """,
                    (
                        json.dumps(merged_event_ids),
                        obs_count,
                        json.dumps(obs_meta),
                        final_sev,
                        incident.end_ts.isoformat() if incident.end_ts else None,
                        existing_id,
                    ),
                )
                logger.info(
                    "Merged incident %s: observation #%d, %d total events",
                    existing_id,
                    obs_count,
                    len(merged_event_ids),
                )
            except Exception as e:
                logger.error("Failed to merge incident %s: %s", existing_id, e)

            return False  # Merged, not new

        # No existing incident — create new one
        self.persist_incident(incident)
        return True

    def persist_incident(self, incident: Incident):
        """Save incident to database (includes AMRDR + temporal columns)

        Args:
            incident: Incident to persist
        """
        # Compute temporal fields from incident timestamps
        start_ts_ns = (
            int(incident.start_ts.timestamp() * 1e9) if incident.start_ts else None
        )
        end_ts_ns = int(incident.end_ts.timestamp() * 1e9) if incident.end_ts else None
        duration_seconds = None
        if incident.start_ts and incident.end_ts:
            duration_seconds = (incident.end_ts - incident.start_ts).total_seconds()

        # Build ordered MITRE sequence from techniques + timestamps
        mitre_sequence = None
        if incident.techniques and incident.start_ts:
            mitre_sequence = json.dumps(
                [{"technique": t, "ts": start_ts_ns} for t in incident.techniques]
            )

        # Materialize incident context — complete evidence package
        incident_context = self._materialize_incident_context(
            incident,
            start_ts_ns,
            end_ts_ns,
            duration_seconds,
            mitre_sequence,
        )

        try:
            self.db.execute(
                """
                INSERT OR REPLACE INTO incidents
                (incident_id, device_id, severity, tactics, techniques, rule_name,
                 summary, start_ts, end_ts, event_ids, metadata, created_at,
                 agent_weights, weighted_confidence, contributing_agents,
                 start_ts_ns, end_ts_ns, duration_seconds, mitre_sequence,
                 incident_context_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident.incident_id,
                    incident.device_id,
                    incident.severity.value,
                    json.dumps(incident.tactics),
                    json.dumps(incident.techniques),
                    incident.rule_name,
                    incident.summary,
                    incident.start_ts.isoformat() if incident.start_ts else None,
                    incident.end_ts.isoformat() if incident.end_ts else None,
                    json.dumps(incident.event_ids),
                    json.dumps(incident.metadata),
                    incident.created_at.isoformat(),
                    json.dumps(incident.agent_weights),
                    incident.weighted_confidence,
                    json.dumps(incident.contributing_agents),
                    start_ts_ns,
                    end_ts_ns,
                    duration_seconds,
                    mitre_sequence,
                    json.dumps(incident_context, default=str),
                ),
            )
            duration_str = (
                f", duration={duration_seconds:.1f}s" if duration_seconds else ""
            )
            logger.info(
                f"Persisted incident: {incident.incident_id} "
                f"(confidence={incident.weighted_confidence:.2f}{duration_str})"
            )
        except Exception as e:
            logger.error(f"Failed to persist incident {incident.incident_id}: {e}")

    def _materialize_incident_context(
        self,
        incident: Incident,
        start_ts_ns: int | None,
        end_ts_ns: int | None,
        duration_seconds: float | None,
        mitre_sequence: str | None,
    ) -> dict:
        """Build a materialized incident context document.

        One JSON object containing the complete evidence package for an incident:
        involved processes, network flows, MITRE techniques with evidence,
        ordered timeline, and agent reliability scores.

        This is what IGRIS reads instead of running 5+ queries across tables.
        """
        context: dict = {
            "incident_id": incident.incident_id,
            "device_id": incident.device_id,
            "severity": incident.severity.value,
            "rule_name": incident.rule_name,
            "summary": incident.summary,
            "weighted_confidence": incident.weighted_confidence,
            "agent_weights": incident.agent_weights,
            "contributing_agents": incident.contributing_agents,
            "tactics": incident.tactics,
            "techniques": incident.techniques,
            "mitre_sequence": json.loads(mitre_sequence) if mitre_sequence else [],
            "temporal": {
                "start_ts_ns": start_ts_ns,
                "end_ts_ns": end_ts_ns,
                "duration_seconds": duration_seconds,
                "start_ts": (
                    incident.start_ts.isoformat() if incident.start_ts else None
                ),
                "end_ts": incident.end_ts.isoformat() if incident.end_ts else None,
            },
            "event_ids": incident.event_ids,
            "event_count": len(incident.event_ids),
            "processes": [],
            "network_flows": [],
            "dns_queries": [],
            "files": [],
            "timeline": [],
        }

        # Reconstruct evidence from the FusionEngine's event buffer
        state = self.device_state.get(incident.device_id)
        if state:
            event_id_set = set(incident.event_ids)
            seen_pids = set()
            for ev in state["events"]:
                if ev.event_id not in event_id_set:
                    continue

                timeline_entry = {
                    "event_id": ev.event_id,
                    "event_type": ev.event_type,
                    "severity": ev.severity,
                    "timestamp": ev.timestamp.isoformat(),
                    "timestamp_ns": ev.event_timestamp_ns,
                    "source_component": ev.attributes.get("source_component", ""),
                }

                # Extract process info
                pid = ev.attributes.get("pid", "")
                if pid and pid not in seen_pids:
                    seen_pids.add(pid)
                    context["processes"].append(
                        {
                            "pid": pid,
                            "name": ev.attributes.get(
                                "name", ev.attributes.get("process_name", "")
                            ),
                            "exe": ev.attributes.get(
                                "exe", ev.attributes.get("binary", "")
                            ),
                            "ppid": ev.attributes.get("ppid", ""),
                            "username": ev.attributes.get("username", ""),
                            "cmdline": ev.attributes.get("cmdline", ""),
                        }
                    )

                # Extract network info
                dst_ip = ev.attributes.get("dst_ip", "")
                if dst_ip:
                    context["network_flows"].append(
                        {
                            "src_ip": ev.attributes.get("src_ip", ""),
                            "dst_ip": dst_ip,
                            "dst_port": ev.attributes.get("dst_port", ""),
                            "protocol": ev.attributes.get("protocol", ""),
                            "pid": pid,
                            "geo_dst_country": ev.attributes.get("geo_dst_country", ""),
                            "asn_name": ev.attributes.get("asn_name", ""),
                        }
                    )

                # Extract DNS info
                domain = ev.attributes.get("domain", "")
                if domain:
                    context["dns_queries"].append(
                        {
                            "domain": domain,
                            "query_type": ev.attributes.get("query_type", ""),
                            "source_pid": ev.attributes.get("source_pid", pid),
                        }
                    )

                # Extract file info
                file_path = ev.attributes.get(
                    "file_path", ev.attributes.get("path", "")
                )
                if file_path:
                    context["files"].append(
                        {
                            "path": file_path,
                            "access_category": ev.attributes.get("access_category", ""),
                            "pid": pid,
                        }
                    )

                # Security event enrichment
                if ev.security_event:
                    timeline_entry["mitre_techniques"] = ev.security_event.get(
                        "mitre_techniques", []
                    )
                    timeline_entry["risk_score"] = ev.security_event.get(
                        "risk_score", 0
                    )
                    timeline_entry["event_category"] = ev.security_event.get(
                        "event_category", ""
                    )

                context["timeline"].append(timeline_entry)

        # Sort timeline by timestamp
        context["timeline"].sort(key=lambda e: e.get("timestamp_ns", 0))

        return context

    def persist_risk_snapshot(self, snapshot: DeviceRiskSnapshot):
        """Save device risk snapshot to database

        Args:
            snapshot: Risk snapshot to persist
        """
        try:
            self.db.execute(
                """
                INSERT OR REPLACE INTO device_risk
                (device_id, score, level, reason_tags, supporting_events, metadata, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot.device_id,
                    snapshot.score,
                    snapshot.level.value,
                    json.dumps(snapshot.reason_tags),
                    json.dumps(snapshot.supporting_events),
                    json.dumps(snapshot.metadata),
                    snapshot.updated_at.isoformat(),
                ),
            )
            logger.debug(
                f"Persisted risk snapshot for {snapshot.device_id}: {snapshot.score}"
            )
        except Exception as e:
            logger.error(
                f"Failed to persist risk snapshot for {snapshot.device_id}: {e}"
            )

    def _create_high_risk_fallback_incident(
        self, device_id: str, sorted_events: List[TelemetryEventView]
    ) -> Optional[Incident]:
        """Create a single incident when security detections exist but no rule fired.

        Ensures real detections (e.g. from infostealer_guard, DNS, kernel) surface
        on the dashboard even when they don't match SSH/persistence/flow patterns.

        Dedup: incident_id is a hash of sorted event IDs, so the same set of
        detections always produces the same incident — no duplicates across runs.
        Threshold: requires at least 2 events or 1 event with risk >= 0.5.
        """
        candidates = self._collect_fallback_candidates(sorted_events)
        if not candidates:
            return None

        event_ids = sorted(e.event_id for e, _ in candidates)
        max_risk = max(r for _, r in candidates)

        # Require at least 2 detections, or 1 with meaningful risk
        if len(candidates) < 2 and max_risk < 0.5:
            return None

        severity = (
            Severity.CRITICAL
            if max_risk >= 0.75
            else (Severity.HIGH if max_risk >= 0.5 else Severity.MEDIUM)
        )
        timestamps = [e.timestamp for e, _ in candidates]
        start_ts = min(timestamps)
        end_ts = max(timestamps)

        categories = []
        for e, _ in candidates:
            cat = (e.security_event or {}).get("event_category") or e.event_type
            if cat and cat not in categories:
                categories.append(cat)

        summary = (
            f"{len(candidates)} high-risk security detection(s) on {device_id}"
            f" (categories: {', '.join(categories[:5])}{'...' if len(categories) > 5 else ''})"
        )

        # Stable ID: hash of sorted event IDs so same detections = same incident
        import hashlib

        id_hash = hashlib.sha256("|".join(event_ids).encode()).hexdigest()[:16]
        incident_id = f"high_risk_{device_id}_{id_hash}"

        all_techniques, all_tactics, all_agents = self._extract_mitre_context(
            candidates
        )

        # Compute confidence from contributing events' risk scores
        # instead of hardcoding 1.0
        risk_scores = [r for _, r in candidates if r > 0]
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0.5
        # Blend average and max: high max means at least one strong signal
        confidence = round(0.6 * avg_risk + 0.4 * max_risk, 3)

        incident = Incident(
            incident_id=incident_id,
            device_id=device_id,
            severity=severity,
            tactics=all_tactics,
            techniques=all_techniques,
            rule_name="high_risk_detections",
            summary=summary[:500],
            start_ts=start_ts,
            end_ts=end_ts,
            event_ids=event_ids,
            metadata={
                "event_count": str(len(candidates)),
                "max_risk_score": f"{max_risk:.2f}",
            },
            contributing_agents=all_agents,
            weighted_confidence=confidence,
        )
        logger.info(
            "Fallback incident created: %s (%d events, max_risk=%.2f)",
            incident.incident_id,
            len(candidates),
            max_risk,
        )
        return incident

    @staticmethod
    def _collect_fallback_candidates(
        sorted_events: List[TelemetryEventView],
    ) -> List[tuple]:
        """Collect SECURITY events eligible for the fallback incident.

        Prefers events with risk >= 0.3 or requires_investigation.  Falls back to
        all SECURITY events only when none meet that bar (so benign low-risk
        observations don't create noise).
        """
        noteworthy = []
        all_security = []
        for e in sorted_events:
            if e.event_type != "SECURITY" or not e.security_event:
                continue
            se = e.security_event
            try:
                risk = float(se.get("risk_score") or 0)
            except (TypeError, ValueError):
                risk = 0.0
            all_security.append((e, risk))
            if risk >= 0.3 or bool(se.get("requires_investigation", False)):
                noteworthy.append((e, risk))
        return noteworthy if noteworthy else all_security

    # Technique prefix → MITRE tactic mapping
    _TECH_PREFIX_TO_TACTIC = {
        "T1190": "TA0001",
        "T1566": "TA0001",
        "T1204": "TA0001",
        "T1059": "TA0002",
        "T1106": "TA0002",
        "T1218": "TA0002",
        "T1543": "TA0003",
        "T1053": "TA0003",
        "T1546": "TA0003",
        "T1547": "TA0003",
        "T1098": "TA0003",
        "T1037": "TA0003",
        "T1548": "TA0004",
        "T1036": "TA0005",
        "T1070": "TA0005",
        "T1562": "TA0005",
        "T1564": "TA0005",
        "T1553": "TA0005",
        "T1140": "TA0005",
        "T1027": "TA0005",
        "T1574": "TA0005",
        "T1555": "TA0006",
        "T1539": "TA0006",
        "T1110": "TA0006",
        "T1056": "TA0006",
        "T1552": "TA0006",
        "T1082": "TA0007",
        "T1083": "TA0007",
        "T1057": "TA0007",
        "T1016": "TA0007",
        "T1046": "TA0007",
        "T1018": "TA0007",
        "T1021": "TA0008",
        "T1105": "TA0008",
        "T1005": "TA0009",
        "T1113": "TA0009",
        "T1115": "TA0009",
        "T1560": "TA0009",
        "T1071": "TA0011",
        "T1568": "TA0011",
        "T1572": "TA0011",
        "T1571": "TA0011",
        "T1090": "TA0011",
        "T1041": "TA0010",
        "T1048": "TA0010",
        "T1567": "TA0010",
    }

    @staticmethod
    def _extract_mitre_context(
        candidates: list,
    ) -> tuple:
        """Extract MITRE techniques, tactics, and agent names from candidate events."""
        tech_set: dict[str, None] = {}  # ordered set via dict
        agent_set: dict[str, None] = {}
        for e, _ in candidates:
            se = e.security_event or {}
            for tech in se.get("mitre_techniques", []):
                if tech:
                    tech_set[tech] = None
            agent = getattr(e, "agent_id", None) or se.get("collection_agent", "")
            if agent:
                agent_set[agent] = None

        techniques = list(tech_set)
        agents = list(agent_set)
        tactics = list(
            dict.fromkeys(
                FusionEngine._TECH_PREFIX_TO_TACTIC[p]
                for t in techniques
                for p in [t.split(".")[0] if "." in t else t]
                if p in FusionEngine._TECH_PREFIX_TO_TACTIC
            )
        )
        return techniques, tactics, agents

    def _detect_sequence_incidents(
        self, device_id: str, sorted_events: List[TelemetryEventView]
    ) -> List[Incident]:
        """Detect kill chain sequences and promote them to full incidents.

        Uses a per-device SequenceScorer with the FusionEngine's correlation
        window (30 min by default, vs the ScoringEngine's 10-min window).
        When >= 2/3 of a chain matches, creates an Incident.

        Args:
            device_id: Device being evaluated
            sorted_events: Events sorted by probe timestamp

        Returns:
            List of sequence-based incidents (may be empty)
        """
        state = self.device_state[device_id]

        # Lazily create per-device SequenceScorer with the fusion window
        if "sequence_scorer" not in state:
            state["sequence_scorer"] = SequenceScorer(
                window_seconds=self.window_minutes * 60
            )

        scorer: SequenceScorer = state["sequence_scorer"]
        incidents: List[Incident] = []

        for event in sorted_events:
            category = ""
            if event.security_event:
                category = event.security_event.get("event_category", "")
            elif event.audit_event:
                category = event.audit_event.get("audit_category", "")
            if not category:
                category = event.event_type

            ts = event.timestamp.timestamp()
            score, matched_name = scorer.record_and_score(device_id, category, ts)

            # 0.66 = at least 2/3 of a chain matched
            if score >= 0.66 and matched_name:
                cooldown_key = ("SEQUENCE_KILL_CHAIN", device_id)
                now = time.time()
                last_fire = self._incident_cooldowns.get(cooldown_key, 0)
                if (now - last_fire) >= self._cooldown_seconds:
                    severity = Severity.CRITICAL if score >= 1.0 else Severity.HIGH
                    incident = Incident(
                        incident_id=f"SEQ-{device_id}-{uuid.uuid4().hex[:8]}",
                        device_id=device_id,
                        severity=severity,
                        tactics=[],
                        techniques=[],
                        rule_name="SEQUENCE_KILL_CHAIN",
                        summary=f"Kill chain sequence detected ({score * 100:.0f}%): {matched_name}",
                        start_ts=sorted_events[0].timestamp,
                        end_ts=event.timestamp,
                    )
                    incidents.append(incident)
                    self._incident_cooldowns[cooldown_key] = now

        return incidents

    def _emit_drift_alerts(self, device_id: str) -> List[Incident]:
        """Emit AMRDR_DRIFT incidents when agents show reliability drift.

        Checks all tracked agents for drift state changes and creates
        synthetic incidents to alert operators.

        Args:
            device_id: Device context for the drift alert

        Returns:
            List of AMRDR_DRIFT incidents (may be empty)
        """
        drift_incidents: List[Incident] = []

        # Check each tracked agent for drift
        for agent_id in self.reliability_tracker.list_agents():
            state = self.reliability_tracker.get_state(agent_id)
            if state is None:
                continue

            # Only emit if actively drifting
            if state.drift_type == DriftType.NONE:
                continue

            # Determine severity based on drift type and tier
            if state.tier == RecalibrationTier.QUARANTINE:
                severity = Severity.CRITICAL
                summary = (
                    f"Agent {agent_id} QUARANTINED: reliability dropped to "
                    f"{state.fusion_weight:.2f}, ≥3 consecutive hard resets"
                )
            elif state.drift_type == DriftType.ABRUPT:
                severity = Severity.HIGH
                summary = (
                    f"Agent {agent_id} abrupt drift detected: reliability "
                    f"score={state.alpha / (state.alpha + state.beta):.2f}, "
                    f"weight={state.fusion_weight:.2f}"
                )
            elif state.drift_type == DriftType.GRADUAL:
                severity = Severity.MEDIUM
                summary = (
                    f"Agent {agent_id} gradual drift detected: reliability "
                    f"score={state.alpha / (state.alpha + state.beta):.2f}, "
                    f"weight={state.fusion_weight:.2f}"
                )
            else:
                continue

            incident = Incident(
                incident_id=f"AMRDR-DRIFT-{agent_id}-{uuid.uuid4().hex[:8]}",
                device_id=device_id,
                severity=severity,
                tactics=[MitreTactic.DEFENSE_EVASION.value],
                techniques=["T1562"],  # Impair Defenses
                rule_name="AMRDR_DRIFT",
                summary=summary,
                start_ts=datetime.now(),
                end_ts=datetime.now(),
                metadata={
                    "agent_id": agent_id,
                    "drift_type": state.drift_type.value,
                    "recalibration_tier": state.tier.value,
                    "alpha": str(state.alpha),
                    "beta": str(state.beta),
                    "fusion_weight": str(state.fusion_weight),
                },
                agent_weights={agent_id: state.fusion_weight},
                weighted_confidence=state.fusion_weight,
                contributing_agents=[agent_id],
            )

            drift_incidents.append(incident)
            self.metrics["drift_alerts_emitted"] += 1

            logger.warning(
                f"AMRDR_DRIFT | agent={agent_id} | "
                f"drift={state.drift_type.value} | "
                f"tier={state.tier.value} | "
                f"weight={state.fusion_weight:.2f}"
            )

        return drift_incidents

    def provide_incident_feedback(
        self,
        incident_id: str,
        is_confirmed: bool,
        analyst: str = "system",
    ) -> bool:
        """Feed analyst confirmation/dismissal back to AMRDR.

        When an analyst confirms or dismisses an incident, the contributing
        agents' reliability is updated accordingly. Confirmed incidents
        increase agent reliability; dismissed incidents decrease it.

        Args:
            incident_id: Incident to provide feedback on
            is_confirmed: True = real incident, False = false positive
            analyst: Who provided the feedback

        Returns:
            True if feedback was recorded, False if incident not found
        """
        # Look up incident from DB to find contributing agents
        row = self.db.execute(
            "SELECT contributing_agents, rule_name FROM incidents "
            "WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()

        if not row:
            logger.warning(f"Cannot provide feedback: incident {incident_id} not found")
            return False

        contributing_agents = json.loads(row[0])
        rule_name = row[1]

        # Skip AMRDR_DRIFT incidents (self-referential feedback loop)
        if rule_name == "AMRDR_DRIFT":
            logger.debug(f"Skipping AMRDR feedback for drift alert {incident_id}")
            return True

        # Update each contributing agent's reliability
        for agent_id in contributing_agents:
            self.reliability_tracker.update(
                agent_id=agent_id,
                ground_truth_match=is_confirmed,
            )
            logger.info(
                f"AMRDR_FEEDBACK | incident={incident_id} | "
                f"agent={agent_id} | confirmed={is_confirmed} | "
                f"analyst={analyst}"
            )

        return True

    def evaluate_all_devices(self):
        """Evaluate all devices with pending events

        Runs correlation rules for each device and persists results.
        Logs structured metrics for observability.
        """
        start_time = time.time()

        total_incidents_this_cycle = 0
        devices_evaluated = 0

        for device_id in list(self.device_state.keys()):
            try:
                incidents, risk_snapshot = self.evaluate_device(device_id)

                # Persist incidents with merge-or-create dedup
                for incident in incidents:
                    merged = self._merge_or_create_incident(incident, device_id)
                    if merged:
                        # Update metrics only for new incidents (not merges)
                        self.metrics["total_incidents_created"] += 1
                        self.metrics["incidents_by_severity"][
                            incident.severity.value
                        ] += 1
                        self.metrics["incidents_by_rule"][incident.rule_name] += 1

                        logger.warning(
                            f"INCIDENT_CREATED | "
                            f"device_id={device_id} | "
                            f"incident_id={incident.incident_id} | "
                            f"rule={incident.rule_name} | "
                            f"severity={incident.severity.value} | "
                            f"tactics={','.join(incident.tactics)} | "
                            f"techniques={','.join(incident.techniques)}"
                        )

                # Persist risk snapshot
                self.persist_risk_snapshot(risk_snapshot)

                devices_evaluated += 1
                total_incidents_this_cycle += len(incidents)

            except Exception as e:
                logger.error(f"Failed to evaluate {device_id}: {e}", exc_info=True)

        # Update global metrics
        self.metrics["total_evaluations"] += 1
        self.metrics["devices_tracked"] = len(self.device_state)

        duration_ms = int((time.time() - start_time) * 1000)
        self.metrics["last_eval_duration_ms"] = duration_ms

        # Structured evaluation summary
        logger.info(
            f"EVALUATION_COMPLETE | "
            f"devices={devices_evaluated} | "
            f"incidents={total_incidents_this_cycle} | "
            f"duration_ms={duration_ms} | "
            f"avg_events_per_device={sum(len(s['events']) for s in self.device_state.values()) / max(1, len(self.device_state)):.1f}"
        )

    def get_recent_incidents(
        self, device_id: Optional[str] = None, limit: int = 100
    ) -> List[Dict]:
        """Retrieve recent incidents from database

        Args:
            device_id: Optional filter by device
            limit: Maximum incidents to return

        Returns:
            List of incident dictionaries
        """
        query = "SELECT * FROM incidents"
        params: List[Any] = []

        if device_id:
            query += " WHERE device_id = ?"
            params.append(device_id)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        rows = self.db.execute(query, params).fetchall()

        incidents = []
        for row in rows:
            inc = {
                "incident_id": row[0],
                "device_id": row[1],
                "severity": row[2],
                "tactics": json.loads(row[3]),
                "techniques": json.loads(row[4]),
                "rule_name": row[5],
                "summary": row[6],
                "start_ts": row[7],
                "end_ts": row[8],
                "event_ids": json.loads(row[9]),
                "metadata": json.loads(row[10]),
                "created_at": row[11],
            }
            # AMRDR columns (may not exist in older databases)
            if len(row) > 12:
                inc["agent_weights"] = json.loads(row[12]) if row[12] else {}
                inc["weighted_confidence"] = row[13] if row[13] else 1.0
                inc["contributing_agents"] = json.loads(row[14]) if row[14] else []
            else:
                inc["agent_weights"] = {}
                inc["weighted_confidence"] = 1.0
                inc["contributing_agents"] = []
            # Temporal fields (Step 5)
            if len(row) > 15:
                inc["start_ts_ns"] = row[15]
                inc["end_ts_ns"] = row[16]
                inc["duration_seconds"] = row[17]
                inc["mitre_sequence"] = json.loads(row[18]) if row[18] else None
            incidents.append(inc)

        return incidents

    def get_device_risk(self, device_id: str) -> Optional[Dict]:
        """Retrieve current risk snapshot for device

        Args:
            device_id: Device to query

        Returns:
            Risk snapshot dictionary or None
        """
        row = self.db.execute(
            "SELECT * FROM device_risk WHERE device_id = ?", (device_id,)
        ).fetchone()

        if not row:
            return None

        return {
            "device_id": row[0],
            "score": row[1],
            "level": row[2],
            "reason_tags": json.loads(row[3]),
            "supporting_events": json.loads(row[4]),
            "metadata": json.loads(row[5]),
            "updated_at": row[6],
        }

    def run_once(self):
        """Run single evaluation pass

        For testing and manual invocation.
        """
        logger.info("=" * 60)
        logger.info("Running Fusion Engine evaluation pass")
        logger.info("=" * 60)

        start = time.time()

        # Evaluate all devices
        self.evaluate_all_devices()

        # Print summary
        total_devices = len(self.device_state)
        total_incidents = sum(s["incident_count"] for s in self.device_state.values())

        logger.info(f"Evaluation complete in {time.time() - start:.2f}s")
        logger.info(f"Devices: {total_devices}, Total incidents: {total_incidents}")

        # Print recent incidents
        recent = self.get_recent_incidents(limit=10)
        if recent:
            logger.info("\nRecent Incidents:")
            for inc in recent:
                logger.info(
                    f"  [{inc['severity']}] {inc['rule_name']}: {inc['summary']}"
                )

        # Print device risk
        logger.info("\nDevice Risk Snapshots:")
        for device_id in self.device_state.keys():
            risk = self.get_device_risk(device_id)
            if risk:
                logger.info(
                    f"  {device_id}: {risk['level']} (score={risk['score']}) - {risk['reason_tags']}"
                )

    def run(self, interval: Optional[int] = None):
        """Main evaluation loop

        Args:
            interval: Seconds between evaluations (default: from init)
        """
        interval = interval or self.eval_interval

        logger.info("Fusion Engine starting...")
        logger.info(f"Evaluation interval: {interval}s")
        logger.info(f"Correlation window: {self.window_minutes} minutes")

        cycle = 0
        while True:
            cycle += 1
            logger.info(f"Cycle #{cycle} - {datetime.now().isoformat()}")

            try:
                self.evaluate_all_devices()
            except Exception as e:
                logger.error(f"Evaluation cycle failed: {e}", exc_info=True)

            logger.info(f"Next evaluation in {interval}s...")
            time.sleep(interval)


def main():
    """CLI entrypoint"""
    import argparse

    parser = argparse.ArgumentParser(
        description="AMOSKYS Fusion Intelligence Engine",
        epilog="Examples:\n"
        "  amoskys-fusion --once                    # Single evaluation pass\n"
        "  amoskys-fusion --interval 60             # Continuous evaluation\n"
        "  amoskys-fusion --list-incidents          # Show recent incidents\n"
        "  amoskys-fusion --risk macbook-pro        # Show device risk\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Operational modes
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--once", action="store_true", help="Run single evaluation pass and exit"
    )
    mode_group.add_argument(
        "--list-incidents", action="store_true", help="List recent incidents and exit"
    )
    mode_group.add_argument(
        "--risk",
        type=str,
        metavar="DEVICE_ID",
        help="Show device risk snapshot and exit",
    )

    # Query filters
    parser.add_argument(
        "--device", type=str, metavar="DEVICE_ID", help="Filter incidents by device ID"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Limit number of incidents to show (default: 20)",
    )
    parser.add_argument(
        "--severity",
        type=str,
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        help="Filter incidents by severity",
    )

    # Engine configuration
    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Evaluation interval in seconds (default: 60)",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=30,
        help="Correlation window in minutes (default: 30)",
    )
    parser.add_argument(
        "--db",
        type=str,
        default="data/intel/fusion.db",
        help="Intelligence database path",
    )

    # Output formatting
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument(
        "--verbose", action="store_true", help="Show detailed information"
    )

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    engine = FusionEngine(
        db_path=args.db, window_minutes=args.window, eval_interval=args.interval
    )

    # Query modes (read-only)
    if args.list_incidents:
        _list_incidents_cli(engine, args)
        return

    if args.risk:
        _show_device_risk_cli(engine, args.risk, args)
        return

    # Operational modes (evaluation)
    if args.once:
        engine.run_once()
    else:
        engine.run(interval=args.interval)


def _list_incidents_cli(engine: FusionEngine, args):
    """CLI handler for --list-incidents"""
    import json as jsonlib

    incidents = engine.get_recent_incidents(device_id=args.device, limit=args.limit)

    # Apply severity filter if specified
    if args.severity:
        incidents = [inc for inc in incidents if inc["severity"] == args.severity]

    if args.json:
        print(jsonlib.dumps(incidents, indent=2))
        return

    # Pretty print
    if not incidents:
        print("No incidents found.")
        return

    print("=" * 80)
    print(f"Recent Incidents ({len(incidents)} total)")
    print("=" * 80)
    print()

    for inc in incidents:
        severity_icon = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "INFO": "🔵",
        }.get(inc["severity"], "⚪")

        print(f"{severity_icon} [{inc['severity']}] {inc['rule_name']}")
        print(f"   Device: {inc['device_id']}")
        print(f"   Summary: {inc['summary']}")
        print(f"   Tactics: {', '.join(inc['tactics'])}")
        print(f"   Techniques: {', '.join(inc['techniques'])}")
        print(f"   Created: {inc['created_at']}")

        if args.verbose:
            print(f"   Event IDs: {', '.join(inc['event_ids'][:5])}")
            if len(inc["event_ids"]) > 5:
                print(f"              ... and {len(inc['event_ids']) - 5} more")
            print(f"   Metadata: {inc['metadata']}")

        print()


def _show_device_risk_cli(engine: FusionEngine, device_id: str, args):
    """CLI handler for --risk DEVICE_ID"""
    import json as jsonlib

    risk = engine.get_device_risk(device_id)

    if not risk:
        print(f"No risk data found for device: {device_id}")
        return

    if args.json:
        print(jsonlib.dumps(risk, indent=2))
        return

    # Pretty print
    level_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(
        risk["level"], "⚪"
    )

    print("=" * 80)
    print(f"Device Risk Snapshot: {device_id}")
    print("=" * 80)
    print()
    print(f"{level_icon} Risk Level: {risk['level']}")
    print(f"   Score: {risk['score']}/100")
    print(f"   Updated: {risk['updated_at']}")
    print()
    print("Contributing Factors:")
    for tag in risk["reason_tags"]:
        print(f"  • {tag}")

    if args.verbose and risk["supporting_events"]:
        print()
        print(f"Supporting Events ({len(risk['supporting_events'])}):")
        for event_id in risk["supporting_events"][:10]:
            print(f"  - {event_id}")
        if len(risk["supporting_events"]) > 10:
            print(f"  ... and {len(risk['supporting_events']) - 10} more")

    print()


if __name__ == "__main__":
    main()
