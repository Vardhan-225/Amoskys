"""IGRIS Cloud Brain — Fleet-Wide Autonomous Observation & Response.

This is the apex predator. Unlike the local IGRIS daemon (which sees only
one device), the Cloud Brain sits on the ops server with access to the
entire fleet database. It can:

    1. Observe  — Fleet-wide metric collection every cycle
    2. Correlate — Cross-device attack chain detection
    3. Baseline — Fleet-level behavioral baselines (EMA + sigma)
    4. Decide   — Confidence-gated autonomous response
    5. Command  — Push commands to any device via the command queue

The Brain runs as a background thread inside the MCP server process.
It shares the fleet.db with command_center.py (WAL mode, concurrent readers).

Architecture:
    ┌─────────────────────────────────────────────────┐
    │ IGRIS CLOUD BRAIN                                │
    │                                                  │
    │  ┌──────────┐  ┌───────────┐  ┌──────────────┐ │
    │  │ Collector │→ │ Evaluator │→ │ Correlator   │ │
    │  │ (metrics) │  │ (baseline)│  │ (cross-dev)  │ │
    │  └──────────┘  └───────────┘  └──────┬───────┘ │
    │                                       │         │
    │  ┌──────────┐  ┌───────────┐  ┌──────▼───────┐ │
    │  │ Responder│← │ Decider   │← │ Signaler     │ │
    │  │ (commands)│  │ (gates)   │  │ (emit/log)   │ │
    │  └──────────┘  └───────────┘  └──────────────┘ │
    └─────────────────────────────────────────────────┘
"""

from __future__ import annotations

import json
import logging
import math
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional

from .db import query, scalar, execute, hours_ago_ns, hours_ago_epoch, write_conn
from .config import cfg

logger = logging.getLogger("amoskys.mcp.brain")

# ── Constants ──────────────────────────────────────────────────────

ALPHA = 0.1                    # EMA smoothing factor
WARMUP_CYCLES = 5              # No signals during learning
SIGNAL_COOLDOWN_S = 600        # 10 min between same-signal repeats
CORRELATION_WINDOW_S = 300     # 5 min cross-device correlation window
LATERAL_THRESHOLD = 2          # Min devices sharing IOC = lateral movement

# Confidence gates for autonomous action
GATE_OBSERVE = 0.0     # Always observe
GATE_SIGNAL = 0.3      # Emit signal
GATE_ALERT = 0.5       # Notify / create incident
GATE_CONTAIN = 0.7     # Block IP / domain
GATE_RESPOND = 0.9     # Kill process / isolate device

# ── Data Classes ───────────────────────────────────────────────────


@dataclass
class BrainSignal:
    """A fleet-level observation from the Cloud Brain."""
    signal_id: str
    signal_type: str
    severity: str           # low | medium | high | critical
    message: str
    confidence: float
    evidence: list[dict] = field(default_factory=list)
    device_ids: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    dedup_key: str = ""
    actions_taken: list[str] = field(default_factory=list)


@dataclass
class FleetBaseline:
    """EMA-based baseline for a fleet metric."""
    ema: float = 0.0
    ema_dev: float = 0.0
    min_seen: float = float("inf")
    max_seen: float = float("-inf")
    sample_count: int = 0

    def update(self, value: float) -> None:
        if self.sample_count == 0:
            self.ema = value
            self.ema_dev = 0.0
        else:
            self.ema = ALPHA * value + (1 - ALPHA) * self.ema
            self.ema_dev = ALPHA * abs(value - self.ema) + (1 - ALPHA) * self.ema_dev
        self.min_seen = min(self.min_seen, value)
        self.max_seen = max(self.max_seen, value)
        self.sample_count += 1

    def sigma(self, value: float) -> float:
        if self.ema_dev < 1e-9 or self.sample_count < WARMUP_CYCLES:
            return 0.0
        return abs(value - self.ema) / self.ema_dev


@dataclass
class BrainState:
    """Persistent state of the Cloud Brain."""
    posture: str = "NOMINAL"
    threat_level: float = 0.0
    cycle_count: int = 0
    started_at: float = 0.0
    last_cycle_at: float = 0.0
    last_cycle_duration_ms: float = 0.0
    active_signals: list[dict] = field(default_factory=list)
    recent_actions: list[dict] = field(default_factory=list)
    mode: str = "observing"     # observing | hunting | responding


# ── Singleton ──────────────────────────────────────────────────────

_brain: Optional["IGRISCloudBrain"] = None
_brain_lock = threading.Lock()


def get_brain() -> Optional["IGRISCloudBrain"]:
    return _brain


def get_brain_status() -> dict:
    b = get_brain()
    if not b:
        return {"status": "offline", "message": "Cloud Brain not started"}
    return b.status()


def start_brain() -> "IGRISCloudBrain":
    global _brain
    with _brain_lock:
        if _brain is None:
            _brain = IGRISCloudBrain()
        if not _brain._running:
            _brain.start()
        return _brain


def stop_brain() -> None:
    global _brain
    with _brain_lock:
        if _brain:
            _brain.stop()
            _brain = None


# ── The Brain ──────────────────────────────────────────────────────


class IGRISCloudBrain:
    """Fleet-wide autonomous observation and response engine.

    Runs a continuous loop that:
    1. Collects fleet metrics (device count, event rates, risk distribution)
    2. Evaluates against learned baselines (EMA + sigma deviation)
    3. Correlates events across devices (shared IOCs, lateral movement)
    4. Emits signals when anomalies detected
    5. Takes autonomous action when confidence exceeds gates
    6. Self-heals: restarts silent agents, unblocks stalled pipelines
    """

    HEAL_INTERVAL_CYCLES = 10  # Run healing every 10th cycle (~10 minutes)

    def __init__(self) -> None:
        self._state = BrainState()
        self._baselines: dict[str, FleetBaseline] = {}
        self._signals: list[BrainSignal] = []
        self._signal_cooldowns: dict[str, float] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._signal_counter = 0
        self._heal_log: list[dict] = []

    # ── Lifecycle ──────────────────────────────────────────────

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._state.started_at = time.time()
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="igris-cloud-brain"
        )
        self._thread.start()
        logger.info("IGRIS Cloud Brain started (interval=%ds)", cfg.brain_interval)

    def stop(self) -> None:
        self._running = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=30)
        logger.info("IGRIS Cloud Brain stopped")

    def status(self) -> dict:
        return {
            "status": "online" if self._running else "offline",
            "posture": self._state.posture,
            "threat_level": self._state.threat_level,
            "mode": self._state.mode,
            "cycle_count": self._state.cycle_count,
            "last_cycle_at": self._state.last_cycle_at,
            "last_cycle_duration_ms": self._state.last_cycle_duration_ms,
            "active_signals": len(self._state.active_signals),
            "baselines_learned": len(self._baselines),
            "uptime_hours": round(
                (time.time() - self._state.started_at) / 3600, 2
            ) if self._state.started_at else 0,
            "recent_signals": self._state.active_signals[-10:],
            "recent_actions": self._state.recent_actions[-10:],
            "recent_heals": self._heal_log[-10:],
        }

    # ── Main Loop ──────────────────────────────────────────────

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._observe_cycle()
            except Exception:
                logger.exception("Brain cycle failed")
            self._stop_event.wait(timeout=cfg.brain_interval)

    def _observe_cycle(self) -> None:
        t0 = time.time()
        self._state.cycle_count += 1
        cycle = self._state.cycle_count

        # 1. Collect fleet metrics
        metrics = self._collect_metrics()

        # 2. Evaluate baselines → signals
        signals = self._evaluate_baselines(metrics)

        # 3. Cross-device correlation
        correlation = self._correlate_across_devices()
        signals.extend(correlation)

        # 4. Determine posture
        self._update_posture(metrics, signals)

        # 5. Decide + act (confidence-gated)
        actions = self._decide_and_act(signals)

        # 6. Self-heal (every Nth cycle)
        if cycle % self.HEAL_INTERVAL_CYCLES == 0:
            self._self_heal_cycle(metrics)

        # 7. Persist
        self._state.last_cycle_at = time.time()
        self._state.last_cycle_duration_ms = (time.time() - t0) * 1000

        # Keep recent signals (cap at 200)
        for s in signals:
            self._state.active_signals.append(asdict(s))
        self._state.active_signals = self._state.active_signals[-200:]

        if signals or actions:
            logger.info(
                "Brain cycle #%d: posture=%s threat=%.3f signals=%d actions=%d (%.0fms)",
                cycle, self._state.posture, self._state.threat_level,
                len(signals), len(actions), self._state.last_cycle_duration_ms,
            )

    # ── 1. Metrics Collection ──────────────────────────────────

    def _collect_metrics(self) -> dict[str, Any]:
        now = time.time()
        m: dict[str, Any] = {"timestamp": now}

        # Fleet health
        m["fleet.total"] = scalar("SELECT COUNT(*) FROM devices") or 0
        m["fleet.online"] = scalar(
            "SELECT COUNT(*) FROM devices WHERE last_seen > ?", (now - 120,)
        ) or 0
        m["fleet.offline"] = m["fleet.total"] - m["fleet.online"]

        # Event velocity
        m["events.1h"] = scalar(
            "SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ?",
            (hours_ago_ns(1),),
        ) or 0
        m["events.5m"] = scalar(
            "SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ?",
            (hours_ago_ns(0.083),),  # 5 minutes
        ) or 0
        m["events.critical_1h"] = scalar(
            "SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ? AND risk_score >= 0.9",
            (hours_ago_ns(1),),
        ) or 0
        m["events.high_1h"] = scalar(
            "SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ? AND risk_score >= 0.7",
            (hours_ago_ns(1),),
        ) or 0

        # Freshness — how recently did we get data?
        latest_ns = scalar(
            "SELECT MAX(timestamp_ns) FROM security_events"
        )
        m["events.freshness_s"] = (
            (now - latest_ns / 1e9) if latest_ns else 9999
        )

        # Incident velocity
        m["incidents.open"] = scalar(
            "SELECT COUNT(*) FROM fleet_incidents WHERE status != 'resolved'"
        ) or 0
        m["incidents.critical"] = scalar(
            "SELECT COUNT(*) FROM fleet_incidents WHERE severity = 'critical' AND status != 'resolved'"
        ) or 0

        # Malicious classification rate
        total_5m = m["events.5m"]
        if total_5m > 0:
            malicious_5m = scalar("""
                SELECT COUNT(*) FROM security_events
                WHERE timestamp_ns > ? AND final_classification = 'malicious'
            """, (hours_ago_ns(0.083),)) or 0
            m["events.malicious_rate"] = malicious_5m / total_5m
        else:
            m["events.malicious_rate"] = 0.0

        return m

    # ── 2. Baseline Evaluation ─────────────────────────────────

    def _evaluate_baselines(self, metrics: dict[str, Any]) -> list[BrainSignal]:
        signals: list[BrainSignal] = []
        now = time.time()

        for key, value in metrics.items():
            if key == "timestamp" or not isinstance(value, (int, float)):
                continue

            # Update EMA baseline
            if key not in self._baselines:
                self._baselines[key] = FleetBaseline()
            bl = self._baselines[key]
            bl.update(float(value))

            # Skip during warmup
            if bl.sample_count < WARMUP_CYCLES:
                continue

            # Check hard thresholds
            signal = self._check_hard_threshold(key, value, now)
            if signal:
                signals.append(signal)
                continue

            # Check statistical deviation
            sigma = bl.sigma(float(value))
            if sigma >= 3.5:
                signal = self._make_signal(
                    f"FLEET_ANOMALY_{key.upper()}",
                    "high" if sigma >= 4.5 else "medium",
                    f"Fleet metric {key}={value} deviates {sigma:.1f}σ from baseline "
                    f"(expected ~{bl.ema:.1f} ± {bl.ema_dev:.1f})",
                    min(0.99, 0.7 + sigma * 0.05),
                    now,
                )
                if signal:
                    signals.append(signal)

        return signals

    def _check_hard_threshold(self, key: str, value: Any, now: float) -> Optional[BrainSignal]:
        """Check fixed thresholds for critical metrics."""
        rules: dict[str, tuple[Any, str, str]] = {
            "fleet.offline": (
                lambda v: v > 0, "medium",
                "Fleet has {v} offline device(s) — potential agent failure or network issue",
            ),
            "events.freshness_s": (
                lambda v: v > 300, "high",
                "No telemetry received in {v:.0f}s — pipeline may be broken",
            ),
            "events.critical_1h": (
                lambda v: v >= 5, "critical",
                "{v} critical-risk events in last hour — active threat likely",
            ),
            "events.malicious_rate": (
                lambda v: v > 0.1, "high",
                "Malicious event rate at {v:.1%} — elevated attack activity",
            ),
            "incidents.critical": (
                lambda v: v > 0, "critical",
                "{v} unresolved critical incident(s) — immediate attention required",
            ),
        }

        rule = rules.get(key)
        if not rule:
            return None

        check_fn, severity, msg_template = rule
        if check_fn(value):
            return self._make_signal(
                f"THRESHOLD_{key.upper()}", severity,
                msg_template.format(v=value),
                0.95, now,
            )
        return None

    # ── 3. Cross-Device Correlation ────────────────────────────

    def _correlate_across_devices(self) -> list[BrainSignal]:
        """Detect adversary movement across the fleet."""
        signals: list[BrainSignal] = []
        now = time.time()
        cutoff = hours_ago_ns(1)

        # Shared remote IPs across devices (potential C2 or lateral movement)
        shared_ips = query("""
            SELECT remote_ip, COUNT(DISTINCT device_id) as dev_count,
                   COUNT(*) as event_count, MAX(risk_score) as max_risk,
                   GROUP_CONCAT(DISTINCT device_id) as devices
            FROM security_events
            WHERE timestamp_ns > ? AND remote_ip IS NOT NULL AND remote_ip != ''
                  AND risk_score >= 0.4
            GROUP BY remote_ip
            HAVING dev_count >= ?
            ORDER BY max_risk DESC LIMIT 10
        """, (cutoff, LATERAL_THRESHOLD))

        for row in shared_ips:
            ip = row["remote_ip"]
            devs = (row.get("devices") or "").split(",")
            confidence = min(0.95, 0.5 + row["max_risk"] * 0.3 + len(devs) * 0.1)

            signal = self._make_signal(
                "LATERAL_MOVEMENT",
                "critical" if row["max_risk"] >= 0.8 else "high",
                f"IP {ip} seen on {row['dev_count']} devices with {row['event_count']} events "
                f"(max risk {row['max_risk']:.2f}) — potential lateral movement or shared C2",
                confidence, now,
                device_ids=devs,
                evidence=[{
                    "ip": ip, "devices": devs,
                    "event_count": row["event_count"],
                    "max_risk": row["max_risk"],
                }],
            )
            if signal:
                signals.append(signal)

        # Shared high-risk MITRE techniques across devices (coordinated attack)
        shared_techniques = query("""
            SELECT mitre_techniques, COUNT(DISTINCT device_id) as dev_count,
                   MAX(risk_score) as max_risk,
                   GROUP_CONCAT(DISTINCT device_id) as devices
            FROM security_events
            WHERE timestamp_ns > ?
                  AND mitre_techniques IS NOT NULL AND mitre_techniques != ''
                  AND risk_score >= 0.6
            GROUP BY mitre_techniques
            HAVING dev_count >= ?
            ORDER BY max_risk DESC LIMIT 5
        """, (cutoff, LATERAL_THRESHOLD))

        for row in shared_techniques:
            devs = (row.get("devices") or "").split(",")
            signal = self._make_signal(
                "COORDINATED_ATTACK",
                "critical" if row["max_risk"] >= 0.8 else "high",
                f"MITRE technique {row['mitre_techniques']} detected on {row['dev_count']} devices "
                f"simultaneously — possible coordinated campaign",
                min(0.95, 0.6 + row["max_risk"] * 0.2),
                now,
                device_ids=devs,
            )
            if signal:
                signals.append(signal)

        return signals

    # ── 4. Posture Update ──────────────────────────────────────

    def _update_posture(self, metrics: dict, signals: list[BrainSignal]) -> None:
        critical_signals = sum(1 for s in signals if s.severity == "critical")
        high_signals = sum(1 for s in signals if s.severity == "high")
        critical_events = metrics.get("events.critical_1h", 0)
        critical_incidents = metrics.get("incidents.critical", 0)

        if critical_signals > 0 or critical_incidents > 0 or critical_events >= 5:
            self._state.posture = "CRITICAL"
            self._state.threat_level = min(1.0, 0.85 + critical_signals * 0.05)
            self._state.mode = "responding"
        elif high_signals >= 3 or critical_events >= 2:
            self._state.posture = "ELEVATED"
            self._state.threat_level = min(0.84, 0.55 + high_signals * 0.05)
            self._state.mode = "hunting"
        elif high_signals >= 1 or metrics.get("events.high_1h", 0) >= 3:
            self._state.posture = "GUARDED"
            self._state.threat_level = min(0.54, 0.25 + high_signals * 0.1)
            self._state.mode = "hunting"
        else:
            self._state.posture = "NOMINAL"
            self._state.threat_level = max(0.0, min(0.24, metrics.get("events.1h", 0) * 0.001))
            self._state.mode = "observing"

    # ── 5. Decision & Action ───────────────────────────────────

    def _decide_and_act(self, signals: list[BrainSignal]) -> list[dict]:
        """Confidence-gated autonomous response."""
        actions: list[dict] = []

        for signal in signals:
            if signal.confidence < GATE_ALERT:
                continue

            # Create incident for high-confidence signals
            if signal.confidence >= GATE_ALERT and signal.severity in ("high", "critical"):
                try:
                    execute("""
                        INSERT INTO fleet_incidents (severity, title, description,
                                                     device_ids, mitre_techniques,
                                                     status, created_at, updated_at)
                        VALUES (?, ?, ?, ?, '[]', 'open', ?, ?)
                    """, (
                        signal.severity,
                        f"[IGRIS Brain] {signal.signal_type}",
                        signal.message,
                        json.dumps(signal.device_ids),
                        time.time(), time.time(),
                    ))
                    action = {
                        "action": "CREATE_INCIDENT",
                        "signal": signal.signal_type,
                        "severity": signal.severity,
                        "timestamp": time.time(),
                    }
                    actions.append(action)
                    signal.actions_taken.append("incident_created")
                    logger.info("Brain auto-created incident: %s", signal.message)
                except Exception:
                    logger.exception("Failed to create incident for signal %s", signal.signal_id)

            # Queue containment for very high confidence lateral movement
            if (signal.confidence >= GATE_CONTAIN
                    and signal.signal_type == "LATERAL_MOVEMENT"
                    and signal.evidence):
                for ev in signal.evidence:
                    ip = ev.get("ip")
                    if ip and ev.get("max_risk", 0) >= 0.8:
                        # Block the C2/lateral IP on all affected devices
                        for dev_id in signal.device_ids:
                            try:
                                from .tools.agent import _ensure_commands_table, _queue_command
                                _queue_command(
                                    dev_id, "BLOCK_IP",
                                    {"ip": ip, "reason": f"IGRIS Brain: {signal.message}",
                                     "duration_s": 3600},
                                    priority=1, ttl=3600,
                                )
                                action = {
                                    "action": "BLOCK_IP",
                                    "ip": ip, "device_id": dev_id,
                                    "timestamp": time.time(),
                                }
                                actions.append(action)
                                signal.actions_taken.append(f"blocked_{ip}_on_{dev_id}")
                            except Exception:
                                logger.exception("Failed to block IP %s on %s", ip, dev_id)

        # Keep recent actions
        self._state.recent_actions.extend(actions)
        self._state.recent_actions = self._state.recent_actions[-100:]

        return actions

    # ── 6. Self-Healing ──────────────────────────────────────────

    def _self_heal_cycle(self, metrics: dict[str, Any]) -> None:
        """Periodic self-healing — detect and repair organism degradation."""
        now = time.time()
        healed: list[dict] = []

        # Heal 1: Pipeline stalled — trigger collection on all devices
        freshness = metrics.get("events.freshness_s", 0)
        if freshness > 600:  # >10 min without data
            devices = query("SELECT device_id FROM devices WHERE status = 'online'")
            for d in devices:
                try:
                    from .tools.agent import _queue_command
                    _queue_command(d["device_id"], "COLLECT_NOW", priority=2)
                except Exception:
                    pass
            healed.append({
                "action": "trigger_collection",
                "reason": f"Pipeline stale ({freshness:.0f}s)",
                "devices": len(devices),
                "timestamp": now,
            })
            logger.warning("Brain self-heal: triggered collection on %d devices (freshness=%ds)",
                           len(devices), freshness)

        # Heal 2: Silent agents — restart agents that stopped reporting
        cutoff_ns = hours_ago_ns(2)
        expected_agents = {
            "macos_proc", "macos_auth", "macos_fim", "macos_flow",
            "macos_dns", "macos_peripheral", "macos_persistence",
        }
        devices = query("SELECT device_id, hostname FROM devices")
        for dev in devices:
            did = dev["device_id"]
            active = query("""
                SELECT DISTINCT collection_agent FROM security_events
                WHERE device_id = ? AND timestamp_ns > ?
            """, (did, cutoff_ns))
            active_set = {r["collection_agent"] for r in active}
            missing = expected_agents - active_set

            for agent_name in missing:
                try:
                    from .tools.agent import _queue_command
                    _queue_command(did, "RESTART_AGENT",
                                   {"agent_name": agent_name}, priority=3)
                    healed.append({
                        "action": "restart_agent",
                        "device": dev.get("hostname", did[:8]),
                        "agent": agent_name,
                        "timestamp": now,
                    })
                except Exception:
                    pass

            if missing:
                logger.info("Brain self-heal: restarting %d silent agents on %s",
                            len(missing), dev.get("hostname", did[:8]))

        # Heal 3: Flush expired commands
        try:
            from .db import write_conn
            with write_conn() as conn:
                conn.execute(
                    "DELETE FROM device_commands WHERE status = 'expired' AND created_at < ?",
                    (now - 86400,),
                )
        except Exception:
            pass

        # Log healing actions
        if healed:
            self._heal_log.extend(healed)
            self._heal_log = self._heal_log[-200:]  # Cap
            logger.info("Brain self-heal cycle: %d repairs executed", len(healed))

    # ── Helpers ─────────────────────────────────────────────────

    def _make_signal(
        self,
        signal_type: str,
        severity: str,
        message: str,
        confidence: float,
        now: float,
        device_ids: list[str] | None = None,
        evidence: list[dict] | None = None,
    ) -> Optional[BrainSignal]:
        """Create a signal with dedup/cooldown."""
        dedup_key = f"{signal_type}:{severity}"

        # Cooldown check
        last_emit = self._signal_cooldowns.get(dedup_key, 0)
        if now - last_emit < SIGNAL_COOLDOWN_S:
            return None

        self._signal_counter += 1
        signal = BrainSignal(
            signal_id=f"brain-{self._signal_counter:06d}",
            signal_type=signal_type,
            severity=severity,
            message=message,
            confidence=confidence,
            device_ids=device_ids or [],
            evidence=evidence or [],
            dedup_key=dedup_key,
        )

        self._signal_cooldowns[dedup_key] = now
        self._signals.append(signal)

        # Cap stored signals
        if len(self._signals) > 1000:
            self._signals = self._signals[-500:]

        return signal
