"""
IGRIS Supervisor — The Autonomous Supervisory Intelligence Layer

Calm. Vigilant. Stable. Correct.

Runs as a daemon thread. Observes every AMOSKYS subsystem every 60 seconds.
Learns baselines. Emits structured signals on deviations.
Never speculates. Never auto-heals. Every signal is evidence-backed.

Cooldown gate ensures the same condition is not re-signaled within 10 minutes
unless severity escalates. IGRIS does not spam. IGRIS governs.
"""

import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Optional

from .baseline import BaselineTracker
from .dispatcher import Dispatcher
from .explainer import Explainer
from .metrics import MetricCollector
from .signals import IgrisSignal, SignalEmitter, SignalType
from .state import IgrisState

logger = logging.getLogger("igris")

# Resolve project root from this file's location (src/amoskys/igris/supervisor.py)
_PROJECT_ROOT = str(Path(__file__).resolve().parents[3])
_DATA_DIR = os.path.join(_PROJECT_ROOT, "data")
_IGRIS_DIR = os.path.join(_DATA_DIR, "igris")
_LOG_DIR = os.path.join(_PROJECT_ROOT, "logs")
_LOG_FILE = os.path.join(_LOG_DIR, "igris.log")


def _setup_log_file() -> None:
    """Route all AMOSKYS subsystem loggers to the centralized IGRIS log.

    This makes logs/igris.log the single observation stream for the entire
    organism — IGRIS, agents (in-process framework), SOMA, enrichment,
    fusion engine, storage, eventbus, proof chain, and all subsystems.
    """
    # Idempotent check — use handler.name as a clean marker
    _HANDLER_NAME = "igris_central_log"
    igris_root = logging.getLogger("igris")
    for h in igris_root.handlers:
        if isinstance(h, logging.FileHandler) and h.name == _HANDLER_NAME:
            return

    os.makedirs(_LOG_DIR, exist_ok=True)
    fh = logging.FileHandler(_LOG_FILE, mode="a", encoding="utf-8")
    fh.name = _HANDLER_NAME
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )

    # ── All logger namespaces to route into the centralized log ──
    _targets = [
        # IGRIS supervisory layer
        "igris",
        # Core AMOSKYS namespace — catches intel.soma_brain, intel.fusion_engine,
        # intel.reliability_store, enrichment.*, storage.*, proof.*, eventbus.*,
        # agents.common.*, edge.*
        "amoskys",
        # Named loggers (components that don't use __name__)
        "TelemetryStore",  # storage/telemetry_store.py
        "WALProcessor",  # storage/wal_processor.py
        "EventBus",  # eventbus/server.py
        "ScoreJunction",  # intelligence/score_junction.py
        "FlowAgent",  # agents/flow
        "ProcAgent",  # agents/proc
        "FIMAgent",  # agents/fim
        "DNSAgent",  # agents/dns
        "PeripheralAgent",  # agents/peripheral
        "AuthGuardAgent",  # agents/auth
    ]

    for name in _targets:
        lgr = logging.getLogger(name)
        if not any(getattr(h, "name", None) == _HANDLER_NAME for h in lgr.handlers):
            lgr.addHandler(fh)
            if lgr.level == logging.NOTSET or lgr.level > logging.DEBUG:
                lgr.setLevel(logging.DEBUG)


# Cooldown: 10 minutes between same-severity repeat signals
SIGNAL_COOLDOWN_S = 600

# Deterministic action recommendations — no speculation
RECOMMENDED_ACTIONS = {
    SignalType.STABILITY_WARNING: (
        "Check agent process status via Guardian C2. "
        "Restart if needed: `start <agent_id>`."
    ),
    SignalType.DRIFT_WARNING: (
        "Review agent reliability: `igris metrics`. "
        "Consider analyst feedback cycle to recalibrate AMRDR."
    ),
    SignalType.INTEGRITY_WARNING: (
        "Data integrity concern detected. "
        "Investigate WAL chain and dead letter queue immediately."
    ),
    SignalType.SUPERVISION_DEFICIT: (
        "Enrichment stage offline. "
        "Check GeoIP/ASN database freshness and threat intel feed availability."
    ),
    SignalType.MODEL_STALENESS: (
        "SOMA training overdue. "
        "Verify event volume is sufficient. Trigger via: `soma train`."
    ),
    SignalType.TRANSPORT_BACKPRESSURE: (
        "WAL queue backing up. "
        "Check EventBus health and downstream processing throughput."
    ),
}

# Integrity-specific recommendation (uses same INTEGRITY_WARNING type)
# Enriches explain_signal() when the signal subsystem is "integrity"

# Related metrics for context enrichment in explain()
RELATED_METRICS = {
    "transport.wal_queue_depth": [
        "transport.eventbus_alive",
        "transport.dead_letter_depth",
        "transport.wal_file_size_mb",
        "ingestion.events_last_5min",
    ],
    "transport.dead_letter_depth": [
        "transport.wal_queue_depth",
        "transport.eventbus_alive",
    ],
    "transport.eventbus_alive": [
        "transport.wal_queue_depth",
        "fleet.healthy",
        "fleet.offline",
    ],
    "fleet.offline": [
        "fleet.total",
        "fleet.healthy",
        "transport.eventbus_alive",
    ],
    "ingestion.events_last_hour": [
        "ingestion.events_last_5min",
        "ingestion.freshness_seconds",
        "ingestion.total_events",
    ],
    "ingestion.freshness_seconds": [
        "ingestion.events_last_5min",
        "transport.eventbus_alive",
        "transport.wal_queue_depth",
    ],
    "amrdr.min_weight": [
        "amrdr.quarantined_count",
        "amrdr.drifting_count",
    ],
    "soma.model_age_hours": [
        "soma.status",
        "soma.training_count",
        "soma.last_train_age_hours",
    ],
    "enrichment.available_count": [
        "enrichment.geoip_available",
        "enrichment.asn_available",
        "enrichment.threat_intel_available",
        "enrichment.mitre_available",
    ],
    "integrity.dead_letter_last_hour": [
        "integrity.dead_letter_total",
        "integrity.dl_blake2b_checksum_mismatch",
        "integrity.dl_hash_chain_signature_mismatch",
        "transport.wal_queue_depth",
    ],
    "integrity.schema_complete": [
        "integrity.schema_version",
    ],
}


class Igris:
    """The autonomous supervisory intelligence layer.

    Observes. Learns. Signals. Never acts without evidence.
    """

    def __init__(
        self,
        telemetry_db: str | None = None,
        interval: int = 60,
        data_dir: str | None = None,
    ):
        self.interval = interval
        self.data_dir = data_dir or _IGRIS_DIR

        self.collector = MetricCollector(telemetry_db=telemetry_db)
        self.baseline = BaselineTracker(data_dir=self.data_dir)
        self.emitter = SignalEmitter(data_dir=self.data_dir)
        self.state = IgrisState(data_dir=self.data_dir)

        self.dispatcher = Dispatcher()
        self.explainer = Explainer()

        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._latest_metrics: dict[str, Any] = {}
        self._lock = threading.Lock()

        # Restore baselines from disk if available
        self.baseline.load()

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        """Start the IGRIS observation daemon."""
        if self.is_running:
            logger.info("IGRIS: Already running")
            return

        _setup_log_file()

        self._stop.clear()
        self.state.mark_started()

        self._thread = threading.Thread(
            target=self._run_loop,
            name="igris-supervisor",
            daemon=True,
        )
        self._thread.start()
        logger.info("IGRIS: Observing. Interval=%ds", self.interval)

    def stop(self) -> None:
        """Graceful shutdown."""
        if not self.is_running:
            return

        logger.info("IGRIS: Shutting down...")
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=30)
        self.baseline.save()
        self.state.mark_stopped()
        logger.info("IGRIS: Stopped. Baselines preserved.")

    def _run_loop(self) -> None:
        """Main daemon loop. Observe → sleep → repeat."""
        # Small initial delay to let other subsystems stabilize
        self._stop.wait(5)

        while not self._stop.is_set():
            try:
                self._observe_cycle()
            except Exception as e:
                logger.error("IGRIS: Observation cycle failed — %s", e)
                # Persist error state even on failure
                with self._lock:
                    self.state._state["status"] = "error"
                    self.state._state["last_cycle_at"] = (
                        __import__("datetime")
                        .datetime.now(__import__("datetime").timezone.utc)
                        .isoformat()
                    )
                    self.state.save()
            self._stop.wait(self.interval)

    def _observe_cycle(self) -> None:
        """Single observation cycle: collect → evaluate → cooldown → recover → persist."""
        t0 = time.monotonic()

        # 1. Collect metrics from all subsystems
        metrics = self.collector.collect_all()
        metric_count = sum(
            1 for v in metrics.values() if v is not None and not isinstance(v, dict)
        )

        # Structured subsystem snapshot (single log line)
        ft = metrics.get("fleet.total")
        fh = metrics.get("fleet.healthy", 0)
        fo = metrics.get("fleet.offline", 0)
        bus = metrics.get("transport.eventbus_alive")
        wal = metrics.get("transport.wal_queue_depth")
        fresh = metrics.get("ingestion.freshness_seconds")
        evt_hr = metrics.get("ingestion.events_last_hour")
        enrich = metrics.get("enrichment.available_count")
        logger.info(
            "Collect: %d metrics | fleet=%s/%s/%s bus=%s wal=%s "
            "ingest=%s/hr fresh=%ss enrich=%s/4",
            metric_count,
            fh,
            ft,
            fo,
            bus,
            wal,
            evt_hr,
            f"{fresh:.0f}" if isinstance(fresh, (int, float)) else fresh,
            enrich,
        )

        # 2. Evaluate against learned baselines
        raw_signals = self.baseline.evaluate(metrics)
        if raw_signals:
            logger.info(
                "Baseline evaluation: %d deviation(s) detected", len(raw_signals)
            )

        # 3. Build active condition set for recovery detection
        active_keys = {sig.dedup_key for sig in raw_signals}

        # 4. Cooldown gate — suppress noisy repeats
        emitted: list[IgrisSignal] = []
        for sig in raw_signals:
            with self._lock:
                if self.state.should_emit(
                    sig.dedup_key, sig.severity, cooldown_s=SIGNAL_COOLDOWN_S
                ):
                    self.emitter.emit(sig)
                    sig_type = (
                        sig.signal_type.value
                        if isinstance(sig.signal_type, SignalType)
                        else str(sig.signal_type)
                    )
                    self.state.mark_emitted(
                        sig.dedup_key,
                        sig.severity,
                        signal_type=sig_type,
                        metric_name=sig.metric_name,
                        subsystem=sig.subsystem,
                    )
                    emitted.append(sig)
                    logger.warning(
                        "SIGNAL EMITTED: [%s] %s — %s (value=%s, baseline=%s)",
                        sig.severity.upper(),
                        sig_type,
                        sig.metric_name,
                        sig.current_value,
                        sig.baseline_value,
                    )

        # 5. Recovery narrative — detect and emit cleared signals
        #    A condition is resolved when its dedup_key no longer appears
        #    in the current cycle's raw_signals.
        cleared: list[IgrisSignal] = []
        with self._lock:
            prev_conditions = self.state.get_active_conditions()
            for dedup_key, cond in prev_conditions.items():
                if dedup_key not in active_keys:
                    # Extract metric name — stored field or parsed from dedup_key
                    metric_name = cond.get("metric_name") or ""
                    if not metric_name:
                        # dedup_key format: "SIGNAL_TYPE:metric.name:agent_id"
                        parts = dedup_key.split(":", 2)
                        metric_name = parts[1] if len(parts) >= 2 else "unknown"
                    current_val = metrics.get(metric_name)
                    try:
                        sig_type = SignalType(
                            cond.get("signal_type", "STABILITY_WARNING")
                        )
                    except (ValueError, KeyError):
                        sig_type = SignalType.STABILITY_WARNING

                    cleared_sig = IgrisSignal(
                        signal_type=sig_type,
                        severity="low",
                        metric_name=metric_name,
                        baseline_value=0,
                        current_value=(
                            float(current_val)
                            if isinstance(current_val, (int, float))
                            else 0
                        ),
                        deviation_sigma=0,
                        confidence=1.0,
                        subsystem=cond.get("subsystem", "unknown"),
                        message=f"{metric_name} — condition resolved",
                        dedup_key=dedup_key,
                        status="cleared",
                        evidence=[
                            {
                                "previous_severity": cond.get(
                                    "last_severity", "unknown"
                                ),
                                "tracked_since_epoch": cond.get(
                                    "last_emitted_at_epoch", 0
                                ),
                                "resolved_at": time.time(),
                            }
                        ],
                    )
                    self.emitter.emit(cleared_sig)
                    self.state.clear_condition(dedup_key)
                    cleared.append(cleared_sig)
                    logger.info(
                        "SIGNAL CLEARED: %s on %s — condition resolved",
                        cond.get("signal_type", "unknown"),
                        cond.get("subsystem", "unknown"),
                    )

        # 5b. Auto-refresh SOMA when MODEL_STALENESS signal fires.
        #     This closes the loop: IGRIS detects staleness → triggers training
        #     directly instead of just recommending a playbook (Phase 2.5).
        for sig in emitted:
            sig_type = (
                sig.signal_type.value
                if isinstance(sig.signal_type, SignalType)
                else str(sig.signal_type)
            )
            if sig_type == SignalType.MODEL_STALENESS.value:
                self._auto_refresh_soma()
                break

        # 6. Compute duration
        duration_ms = (time.monotonic() - t0) * 1000

        # 7. Update persistent state
        with self._lock:
            self._latest_metrics = metrics
        self.state.update(metrics, emitted, duration_ms, signals_cleared=cleared)
        self.state.save()

        # 8. Save baselines periodically (every 10 cycles)
        if self.state.cycle_count % 10 == 0:
            self.baseline.save()

        # 9. Log summary — quiet, structured
        metric_count = sum(
            1 for v in metrics.values() if v is not None and not isinstance(v, dict)
        )
        suppressed = len(raw_signals) - len(emitted)
        signal_str = ""
        if emitted:
            signal_str = f", {len(emitted)} signal(s)"
        if suppressed > 0:
            signal_str += f" ({suppressed} suppressed)"
        cleared_str = ""
        if cleared:
            cleared_str = f", {len(cleared)} cleared"
        warmup = (
            f" [warmup {self.state.cycle_count}/10]"
            if self.state.cycle_count < 10
            else ""
        )
        logger.info(
            "IGRIS cycle #%d: %d metrics, %.0fms%s%s%s",
            self.state.cycle_count,
            metric_count,
            duration_ms,
            signal_str,
            cleared_str,
            warmup,
        )

        # 10. Log coherence assessment
        from .coherence import assess

        coherence = assess(metrics, len(emitted))
        verdict = coherence["verdict"]
        reasons = coherence.get("reasons", [])
        reason_str = "; ".join(reasons) if reasons else "nominal"
        logger.info("Coherence: %s (%s)", verdict.upper(), reason_str)

    # ── Query API (for Guardian C2 and Dashboard) ─────────────────

    def get_status(self) -> dict:
        """IGRIS status summary with organism coherence."""
        status = self.state.get_status()
        status["is_running"] = self.is_running

        # Attach organism coherence assessment
        with self._lock:
            metrics = dict(self._latest_metrics)
        if metrics:
            from .coherence import assess

            coherence = assess(metrics, status.get("active_signal_count", 0))
            status["coherence"] = coherence["verdict"]
            status["coherence_detail"] = coherence
        else:
            status["coherence"] = "unknown"
            status["coherence_detail"] = None

        return status

    def get_coherence(self) -> dict:
        """Organism coherence assessment.

        If the daemon hasn't run yet (no cached metrics), performs a fresh
        collection so CLI queries always return current data.
        """
        from .coherence import assess, format_for_c2

        with self._lock:
            metrics = dict(self._latest_metrics)
        # Fresh collection when daemon hasn't populated cache yet
        if not metrics:
            metrics = self.collector.collect_all()
        active = self.state.get_status().get("active_signal_count", 0)
        result = assess(metrics, active)
        result["formatted"] = format_for_c2(result)
        return result

    def get_signals(self, limit: int = 50) -> list[dict]:
        """Recent governance signals."""
        return self.emitter.get_recent(limit=limit)

    def get_baselines(self) -> dict[str, dict]:
        """Current learned baselines for all metrics."""
        return self.baseline.get_baselines()

    def get_metrics(self) -> dict[str, Any]:
        """Latest metrics snapshot."""
        with self._lock:
            return dict(self._latest_metrics)

    def explain_signal(self, signal_id: str) -> Optional[dict]:
        """Full signal explanation with evidence, playbook, and recommendation.

        No speculation. Only trace-backed reasoning.
        Powered by IGRIS Explainer + Dispatcher.
        """
        sig = self.emitter.get_by_id(signal_id)
        if not sig:
            return None

        # Gather baseline context
        metric_name = sig.get("metric_name", "")
        baselines = self.baseline.get_baselines()
        baseline_ctx = baselines.get(metric_name, {})

        # Gather related metrics
        related = {}
        related_keys = RELATED_METRICS.get(metric_name, [])
        with self._lock:
            for rk in related_keys:
                if rk in self._latest_metrics:
                    related[rk] = self._latest_metrics[rk]
            latest = dict(self._latest_metrics)

        # Delegate to Explainer for structured, evidence-backed output
        return self.explainer.explain(
            signal=sig,
            baseline_context=baseline_ctx,
            related_metrics=related,
            latest_metrics=latest,
        )

    def explain_signal_formatted(self, signal_id: str) -> Optional[str]:
        """Formatted explanation for Guardian C2 terminal output."""
        sig = self.emitter.get_by_id(signal_id)
        if not sig:
            return None

        metric_name = sig.get("metric_name", "")
        baselines = self.baseline.get_baselines()
        baseline_ctx = baselines.get(metric_name, {})

        related = {}
        related_keys = RELATED_METRICS.get(metric_name, [])
        with self._lock:
            for rk in related_keys:
                if rk in self._latest_metrics:
                    related[rk] = self._latest_metrics[rk]

        return self.explainer.format_for_c2(sig, baseline_ctx, related)

    def _auto_refresh_soma(self) -> None:
        """Trigger SOMA Brain retraining when MODEL_STALENESS is detected.

        Runs in a background thread to avoid blocking the observation cycle.
        Resolves the Phase 2 gap: IGRIS now acts on staleness instead of
        just recommending a playbook.
        """

        def _train():
            try:
                from amoskys.intel.soma_brain import SomaBrain

                telemetry_db = self.collector._telemetry_db
                if not telemetry_db:
                    telemetry_db = os.path.join(_DATA_DIR, "telemetry.db")

                brain = SomaBrain(telemetry_db_path=telemetry_db)
                result = brain.train_once()
                status = result.get("status", "unknown")
                event_count = result.get("event_count", 0)
                if status == "completed":
                    logger.info(
                        "IGRIS → SOMA auto-refresh: training completed "
                        "(%d events, cycle %d)",
                        event_count,
                        result.get("cycle", 0),
                    )
                elif status == "cold_start":
                    logger.warning(
                        "IGRIS → SOMA auto-refresh: cold start " "(%d events, need %d)",
                        event_count,
                        brain.MIN_EVENTS_FOR_TRAINING,
                    )
                elif status == "validation_failed":
                    logger.warning(
                        "IGRIS → SOMA auto-refresh: validation failed — %s",
                        result.get("validation", {}).get("reason", "unknown"),
                    )
                else:
                    logger.warning("IGRIS → SOMA auto-refresh: %s", status)
            except Exception:
                logger.error("IGRIS → SOMA auto-refresh failed", exc_info=True)

        t = threading.Thread(target=_train, name="igris-soma-refresh", daemon=True)
        t.start()
        logger.info("IGRIS: Triggered SOMA auto-refresh (background thread)")

    def reset_baselines(self) -> dict:
        """Reset all baselines and re-enter warmup. Clears cooldown index."""
        with self._lock:
            self.baseline.reset()
            self.baseline.save()
            self.state._state["status"] = "warming_up"
            self.state._state["cycle_count"] = 0
            self.state._state["signal_index"] = {}
            self.state._state["signal_count_since_start"] = 0
            self.state.save()
        logger.info("IGRIS: Baselines reset. Re-entering warmup.")
        return {
            "ok": True,
            "status": "warming_up",
            "message": "Baselines cleared. Signal index cleared. Re-entering warmup.",
        }
