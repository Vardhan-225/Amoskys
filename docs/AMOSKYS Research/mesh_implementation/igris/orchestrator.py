"""
IGRIS Orchestrator — The Nervous System.

Subscribes to ALL mesh events. Correlates findings across agents.
Evaluates confidence via the prevention ladder. Issues action commands.
Notifies users via the chat widget.

Dual Mode:
  - Analyst: responds to user questions in the chat widget
  - Defender: autonomous event loop processing mesh events

The orchestrator runs as a background thread in the Flask dashboard.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional

logger = logging.getLogger("igris.orchestrator")

# Import mesh components (adjust path for your project structure)
try:
    from amoskys.mesh import (
        ActionExecutor,
        EventType,
        MeshBus,
        MeshStore,
        SecurityEvent,
        Severity,
    )
except ImportError:
    # Fallback for standalone testing
    from mesh import ActionExecutor, EventType, MeshBus, MeshStore, SecurityEvent, Severity


class IGRISOrchestrator:
    """Autonomous defense orchestrator.

    Subscribes to all mesh events, correlates across agents,
    and issues defensive actions when confidence thresholds are met.
    """

    def __init__(
        self,
        mesh_bus: MeshBus,
        action_executor: ActionExecutor,
        mesh_store: MeshStore,
        telemetry_db: str = "data/telemetry.db",
        notification_callback=None,
    ):
        self._bus = mesh_bus
        self._actions = action_executor
        self._store = mesh_store
        self._telemetry_db = telemetry_db
        self._notify = notification_callback  # Push to chat widget

        # State tracking
        self._event_queue: List[SecurityEvent] = []
        self._queue_lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None

        # Correlation state
        self._pid_events: Dict[int, List[SecurityEvent]] = defaultdict(list)
        self._ip_events: Dict[str, List[SecurityEvent]] = defaultdict(list)
        self._domain_events: Dict[str, List[SecurityEvent]] = defaultdict(list)

        # Adaptive mode
        self._current_mode = "calm"
        self._mode_history: List[tuple] = []

        # Subscribe to all mesh events
        self._bus.subscribe_all(self._on_mesh_event)

        logger.info("IGRIS Orchestrator initialized")

    # ═══════════════════════════════════════════════════════════
    # EVENT PROCESSING
    # ═══════════════════════════════════════════════════════════

    def _on_mesh_event(self, event: SecurityEvent) -> None:
        """Callback from MeshBus — adds event to processing queue."""
        with self._queue_lock:
            self._event_queue.append(event)

    def _process_event(self, event: SecurityEvent) -> None:
        """Process a single mesh event through the orchestration pipeline.

        Pipeline: Enrich → Correlate → Score → Decide → Act → Notify
        """
        # 1. ENRICH: cross-reference with threat intel and agent state
        enriched = self._enrich(event)

        # 2. CORRELATE: update per-PID/IP/domain event chains
        self._correlate(enriched)

        # 3. SCORE: calculate composite confidence
        confidence = self._score(enriched)

        # 4. DECIDE: determine appropriate response
        actions = self._decide(enriched, confidence)

        # 5. ACT: execute actions
        for action_fn, kwargs in actions:
            try:
                receipt = action_fn(**kwargs)
                logger.info(
                    "Action executed: %s -> %s",
                    receipt.action, receipt.result,
                )
            except Exception:
                logger.exception("Action failed: %s", kwargs)

        # 6. NOTIFY: push to chat widget if significant
        if confidence >= 0.5 or event.severity in (Severity.HIGH, Severity.CRITICAL):
            self._notify_user(enriched, confidence, actions)

        # 7. UPDATE ADAPTIVE MODE
        self._update_adaptive_mode()

    def _enrich(self, event: SecurityEvent) -> SecurityEvent:
        """Enrich event with threat intel and context."""
        try:
            conn = sqlite3.connect(self._telemetry_db)

            # Check if related IP is a known threat indicator
            if event.related_ip:
                match = conn.execute(
                    "SELECT * FROM threat_indicators WHERE type='ip' AND value=?",
                    (event.related_ip,),
                ).fetchone()
                if match:
                    event.confidence = max(event.confidence, 0.8)
                    event.payload["threat_intel_match"] = "ip"

            # Check if related domain is known
            if event.related_domain:
                match = conn.execute(
                    "SELECT * FROM threat_indicators WHERE type='domain' AND value=?",
                    (event.related_domain,),
                ).fetchone()
                if match:
                    event.confidence = max(event.confidence, 0.8)
                    event.payload["threat_intel_match"] = "domain"

            conn.close()
        except Exception:
            logger.debug("Enrichment failed (DB unavailable)")

        return event

    def _correlate(self, event: SecurityEvent) -> None:
        """Update correlation chains for PIDs, IPs, domains."""
        now = time.time()
        window = 300  # 5-minute correlation window

        if event.related_pid:
            chain = self._pid_events[event.related_pid]
            chain.append(event)
            # Prune old events
            self._pid_events[event.related_pid] = [
                e for e in chain
                if (now - e.timestamp_ns / 1e9) < window
            ]

        if event.related_ip:
            chain = self._ip_events[event.related_ip]
            chain.append(event)
            self._ip_events[event.related_ip] = [
                e for e in chain
                if (now - e.timestamp_ns / 1e9) < window
            ]

        if event.related_domain:
            chain = self._domain_events[event.related_domain]
            chain.append(event)
            self._domain_events[event.related_domain] = [
                e for e in chain
                if (now - e.timestamp_ns / 1e9) < window
            ]

    def _score(self, event: SecurityEvent) -> float:
        """Calculate composite confidence score.

        Factors:
          - Event severity (base score)
          - Correlated evidence (multiple agents seeing the same PID/IP)
          - Threat intel match
          - Kill chain stage progression
        """
        score = event.severity.numeric

        # Boost for correlated evidence
        if event.related_pid:
            chain_len = len(self._pid_events.get(event.related_pid, []))
            if chain_len >= 3:
                score = max(score, 0.8)
            elif chain_len >= 2:
                score = max(score, 0.6)

        # Boost for threat intel match
        if event.payload.get("threat_intel_match"):
            score = max(score, 0.8)

        # Boost for kill chain escalation
        if event.event_type == EventType.KILL_CHAIN_ESCALATION:
            stage = event.payload.get("current_stage", 0)
            if stage >= 5:
                score = max(score, 0.95)
            elif stage >= 4:
                score = max(score, 0.85)

        # Boost for exfiltration attempt with prior credential access
        if event.event_type == EventType.OUTBOUND_EXFIL_ATTEMPT:
            pid = event.related_pid
            if pid and any(
                e.event_type == EventType.CREDENTIAL_FILE_ACCESS
                for e in self._pid_events.get(pid, [])
            ):
                score = max(score, 0.95)

        return min(score, 1.0)

    def _decide(
        self, event: SecurityEvent, confidence: float
    ) -> List[tuple]:
        """Map confidence to specific actions.

        Returns list of (action_function, kwargs) tuples.
        """
        actions = []

        # CRITICAL (0.9+): Full response
        if confidence >= 0.9:
            if event.related_pid:
                evidence = [
                    e.event_id
                    for e in self._pid_events.get(event.related_pid, [])
                ]
                actions.append((
                    self._actions.kill_process,
                    {"pid": event.related_pid, "confidence": confidence, "evidence": evidence},
                ))
            if event.related_ip:
                actions.append((
                    self._actions.block_ip,
                    {"ip": event.related_ip, "confidence": confidence},
                ))

        # HIGH (0.7-0.9): Block network, direct watch
        elif confidence >= 0.7:
            if event.related_ip:
                actions.append((
                    self._actions.block_ip,
                    {"ip": event.related_ip, "confidence": confidence, "duration_s": 1800},
                ))
            if event.related_domain:
                actions.append((
                    self._actions.block_domain,
                    {"domain": event.related_domain, "confidence": confidence},
                ))

        # MEDIUM (0.5-0.7): Watch and alert
        elif confidence >= 0.5:
            if event.related_pid:
                actions.append((
                    self._actions.direct_watch,
                    {
                        "agent_id": "network",
                        "target_type": "pid",
                        "target_value": str(event.related_pid),
                        "confidence": confidence,
                    },
                ))
            if event.related_ip:
                actions.append((
                    self._actions.add_threat_indicator,
                    {
                        "indicator_type": "ip",
                        "value": event.related_ip,
                        "source": "igris_correlation",
                        "confidence": confidence,
                    },
                ))

        # LOW (0.3-0.5): Just collect more data
        elif confidence >= 0.3:
            actions.append((
                self._actions.trigger_collection,
                {"confidence": confidence},
            ))

        return actions

    def _notify_user(
        self,
        event: SecurityEvent,
        confidence: float,
        actions: list,
    ) -> None:
        """Push notification to the chat widget."""
        if not self._notify:
            return

        action_names = [
            f[0].__name__ if hasattr(f[0], "__name__") else str(f[0])
            for f in actions
        ]

        message = {
            "type": "defender_alert",
            "severity": event.severity.value,
            "event_type": event.event_type.value,
            "source": event.source_agent,
            "confidence": round(confidence, 2),
            "summary": str(event),
            "actions_taken": action_names,
            "timestamp": time.strftime("%H:%M:%S"),
        }

        try:
            self._notify(message)
        except Exception:
            logger.debug("Failed to push notification to widget")

    # ═══════════════════════════════════════════════════════════
    # ADAPTIVE MODE
    # ═══════════════════════════════════════════════════════════

    def _update_adaptive_mode(self) -> None:
        """Adjust adaptive polling mode based on recent event volume."""
        recent = self._store.get_severity_distribution(seconds=300)
        critical = recent.get("critical", 0)
        high = recent.get("high", 0)
        medium = recent.get("medium", 0)

        if critical > 0:
            new_mode = "response"
        elif high > 2:
            new_mode = "hunt"
        elif medium > 5 or high > 0:
            new_mode = "alert"
        else:
            new_mode = "calm"

        if new_mode != self._current_mode:
            self._current_mode = new_mode
            self._mode_history.append((time.time(), new_mode))

            # Publish mode change to mesh
            self._bus.publish(SecurityEvent(
                event_type=EventType.ADAPTIVE_MODE_CHANGE,
                source_agent="igris_orchestrator",
                severity=Severity.INFO,
                payload={"mode": new_mode},
            ))

            logger.warning(
                "IGRIS Adaptive Mode: %s -> %s (critical=%d, high=%d, medium=%d)",
                self._mode_history[-2][1] if len(self._mode_history) > 1 else "init",
                new_mode, critical, high, medium,
            )

    # ═══════════════════════════════════════════════════════════
    # LIFECYCLE
    # ═══════════════════════════════════════════════════════════

    def start(self) -> None:
        """Start the orchestrator background thread."""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="igris-orchestrator",
        )
        self._thread.start()
        logger.info("IGRIS Orchestrator started (defender mode active)")

    def _run_loop(self) -> None:
        """Main event processing loop."""
        while self._running:
            # Drain the event queue
            with self._queue_lock:
                events = list(self._event_queue)
                self._event_queue.clear()

            for event in events:
                try:
                    self._process_event(event)
                except Exception:
                    logger.exception(
                        "Failed to process event: %s", event.event_id
                    )

            # Sleep briefly between drain cycles
            time.sleep(0.1)

    def stop(self) -> None:
        """Stop the orchestrator."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("IGRIS Orchestrator stopped")

    @property
    def current_mode(self) -> str:
        """Current adaptive mode (calm/alert/hunt/response)."""
        return self._current_mode

    def get_status(self) -> Dict[str, Any]:
        """Get orchestrator status for the dashboard."""
        return {
            "running": self._running,
            "mode": self._current_mode,
            "tracked_pids": len(self._pid_events),
            "tracked_ips": len(self._ip_events),
            "tracked_domains": len(self._domain_events),
            "mode_history": [
                {"time": t, "mode": m} for t, m in self._mode_history[-10:]
            ],
            "mesh_stats": self._store.get_mesh_stats(),
        }
