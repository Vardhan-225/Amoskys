"""
IGRIS Explainer — Evidence-Backed Explanation Engine

Produces structured, trace-backed explanations for governance signals.
No speculation. No hallucination. Every statement is backed by metric
values, thresholds, baselines, or playbook references.

The voice of IGRIS: calm, precise, deterministic.
"""

import logging
from typing import Any, Optional

from .dispatcher import Dispatcher
from .signals import SignalType

logger = logging.getLogger("igris.explainer")

# Human-readable subsystem labels
SUBSYSTEM_LABELS = {
    "fleet": "Agent Fleet",
    "transport": "Event Transport (EventBus + WAL)",
    "ingestion": "Event Ingestion Pipeline",
    "intelligence": "Fusion Intelligence Engine",
    "amrdr": "Agent Reliability (AMRDR)",
    "soma": "SOMA Brain (Anomaly Detection)",
    "enrichment": "Enrichment Pipeline",
    "integrity": "Data Integrity (Auditor)",
}

# Severity context — what each level means in IGRIS terms
SEVERITY_CONTEXT = {
    "low": "Informational — condition noted, no action required.",
    "medium": "Advisory — condition warrants monitoring. Review recommended.",
    "high": "Significant — active deviation from baseline. Investigation recommended.",
    "critical": "Urgent — subsystem failure or severe anomaly. Immediate action needed.",
}

# Signal type explanations — what each type means
SIGNAL_TYPE_EXPLANATIONS = {
    SignalType.STABILITY_WARNING.value: (
        "Indicates a subsystem stability concern: an agent is offline, "
        "a service is unreachable, or event rates have deviated significantly "
        "from learned baselines."
    ),
    SignalType.DRIFT_WARNING.value: (
        "Agent reliability has shifted. AMRDR has detected scoring drift, "
        "a quarantine event, or fusion weight degradation. The organism's "
        "trust in this agent has changed."
    ),
    SignalType.INTEGRITY_WARNING.value: (
        "Data integrity concern detected in the event pipeline. This may "
        "indicate checksum failures, hash chain breaks, or dead letter "
        "queue growth. Evidence preservation may be affected."
    ),
    SignalType.SUPERVISION_DEFICIT.value: (
        "An enrichment stage is offline, reducing the organism's ability "
        "to contextualize events. Coverage gap detected."
    ),
    SignalType.MODEL_STALENESS.value: (
        "SOMA Brain model is stale — training has not occurred within the "
        "expected window. Anomaly detection accuracy may degrade."
    ),
    SignalType.TRANSPORT_BACKPRESSURE.value: (
        "The WAL queue is backing up, indicating downstream processing "
        "cannot keep pace with event ingestion. Events may be delayed."
    ),
}


class Explainer:
    """Produces evidence-backed signal explanations.

    Calm. Precise. Deterministic. Every statement is traceable.
    """

    def __init__(self):
        self._dispatcher = Dispatcher()

    def explain(
        self,
        signal: dict,
        baseline_context: dict,
        related_metrics: dict[str, Any],
        latest_metrics: dict[str, Any] | None = None,
    ) -> dict:
        """Generate a full explanation for a governance signal.

        Args:
            signal: The signal dict (from SignalEmitter)
            baseline_context: EMA/deviation data for this metric
            related_metrics: Other metrics that provide context
            latest_metrics: Full metrics snapshot (optional, for coherence)

        Returns:
            Structured explanation dict with evidence, reasoning, and playbook.
        """
        sig_type = signal.get("signal_type", "")
        severity = signal.get("severity", "low")
        metric_name = signal.get("metric_name", "")
        subsystem = signal.get("subsystem", "unknown")
        status = signal.get("status", "active")

        # Build the explanation
        explanation = {
            "signal": signal,
            "status": status,
            # What happened
            "summary": self._build_summary(signal),
            # Why it matters
            "severity_context": SEVERITY_CONTEXT.get(
                severity.lower(), "Unknown severity level."
            ),
            "signal_type_explanation": SIGNAL_TYPE_EXPLANATIONS.get(
                sig_type, "Unknown signal type."
            ),
            "subsystem_label": SUBSYSTEM_LABELS.get(subsystem, subsystem),
            # Evidence
            "baseline_context": {
                "ema": baseline_context.get("ema"),
                "ema_deviation": baseline_context.get("ema_dev"),
                "min_observed": baseline_context.get("min_seen"),
                "max_observed": baseline_context.get("max_seen"),
                "total_observations": baseline_context.get("sample_count", 0),
            },
            "related_metrics": related_metrics,
            "evidence": signal.get("evidence", []),
            # What to do
            "recommendation": self._dispatcher.get_recommendation(
                sig_type,
                subsystem,
                severity,
                metric_name=metric_name,
                agent_id=signal.get("agent_id"),
            ),
        }

        # Cleared signal: add recovery context
        if status == "cleared":
            explanation["recovery_note"] = (
                f"This condition has resolved. {metric_name} has returned "
                "to within normal parameters. No action needed."
            )

        return explanation

    def _build_summary(self, signal: dict) -> str:
        """Build a one-sentence evidence-backed summary."""
        metric = signal.get("metric_name", "unknown")
        current = signal.get("current_value", "?")
        baseline = signal.get("baseline_value", "?")
        sigma = signal.get("deviation_sigma", 0)
        status = signal.get("status", "active")

        if status == "cleared":
            return f"{metric} — condition resolved. Value returned to normal."

        if sigma and sigma > 0:
            return (
                f"{metric} at {current} is {sigma}σ from baseline {baseline}. "
                f"Statistical deviation detected."
            )

        return (
            f"{metric} at {current} exceeded threshold "
            f"(baseline: {baseline}). Hard rule triggered."
        )

    def format_for_c2(
        self,
        signal: dict,
        baseline_context: dict,
        related_metrics: dict[str, Any],
    ) -> str:
        """Format a full explanation as a C2 terminal output block."""
        exp = self.explain(signal, baseline_context, related_metrics)
        rec = exp["recommendation"]
        ctx = exp["baseline_context"]
        sig = exp["signal"]
        status = exp.get("status", "active")

        status_tag = f" [{status.upper()}]" if status != "active" else ""

        lines = [
            f"IGRIS SIGNAL EXPLANATION{status_tag}",
            "=" * 50,
            f"ID:          {sig.get('signal_id', '')}",
            f"Type:        {sig.get('signal_type', '')}",
            f"Severity:    {sig.get('severity', '').upper()}",
            f"Subsystem:   {exp['subsystem_label']}",
            f"Metric:      {sig.get('metric_name', '')}",
            f"Current:     {sig.get('current_value', '')}",
            f"Baseline:    {sig.get('baseline_value', '')}",
        ]

        sigma = sig.get("deviation_sigma", 0)
        if sigma:
            lines.append(f"Deviation:   {sigma}σ")

        lines.append(f"Confidence:  {round(sig.get('confidence', 0) * 100)}%")

        # Summary
        lines.append("")
        lines.append("SUMMARY")
        lines.append(f"  {exp['summary']}")

        # Why it matters
        lines.append("")
        lines.append("CONTEXT")
        lines.append(f"  {exp['severity_context']}")
        lines.append(f"  {exp['signal_type_explanation']}")

        # Baseline evidence
        lines.append("")
        lines.append("BASELINE EVIDENCE")
        lines.append(f"  EMA:       {ctx.get('ema', '—')}")
        lines.append(f"  Deviation: {ctx.get('ema_deviation', '—')}")
        lines.append(f"  Min Seen:  {ctx.get('min_observed', '—')}")
        lines.append(f"  Max Seen:  {ctx.get('max_observed', '—')}")
        lines.append(f"  Samples:   {ctx.get('total_observations', 0)}")

        # Related metrics
        related = exp.get("related_metrics", {})
        if related:
            lines.append("")
            lines.append("RELATED METRICS")
            for rk, rv in related.items():
                lines.append(f"  {rk.ljust(30)} {rv}")

        # Recovery note
        if "recovery_note" in exp:
            lines.append("")
            lines.append("RECOVERY")
            lines.append(f"  {exp['recovery_note']}")

        # Playbook recommendation
        lines.append("")
        lines.append("RECOMMENDATION")
        if rec.get("playbook"):
            lines.append(f"  Playbook: {rec['playbook']}")
            lines.append(f"  {rec['description']}")
            lines.append("")
            for i, cmd in enumerate(rec["commands"], 1):
                lines.append(f"  {i}. {cmd}")
            if rec.get("requires_confirmation"):
                lines.append("")
                lines.append("  [requires operator confirmation]")
        else:
            lines.append(f"  {rec['description']}")

        return "\n".join(lines)
