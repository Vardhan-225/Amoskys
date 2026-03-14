"""
IGRIS Chat Controller — Conversation manager with system briefing + tool orchestration.

Three-layer context:
  1. System Briefing (always present, ~500 tokens) — auto-refreshed posture
  2. On-demand tool results — Claude calls typed tools per question
  3. Multi-turn drill-down — conversation state preserved across turns
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .backends import CompletionResult, create_backend
from .tools import IgrisToolkit

logger = logging.getLogger("igris.chat")

# Maximum conversation history before truncation
MAX_HISTORY = 20
# Maximum tool call rounds per user message (prevent infinite loops)
MAX_TOOL_ROUNDS = 5

SYSTEM_PROMPT = """You are IGRIS, the autonomous security intelligence layer of AMOSKYS — an endpoint detection and response platform protecting macOS systems.

You speak with precision and authority. You are calm, evidence-backed, and never speculate. When you report a finding, you cite the data source (agent name, probe name, MITRE technique, risk score). You think like a threat hunter.

Your personality:
- Direct. No filler. Lead with the finding.
- When the situation is clear, say so. When it's ambiguous, say that too.
- Reference specific MITRE ATT&CK technique IDs when relevant.
- If a question requires data you don't have, say which tool would answer it.
- Format output for a security analyst: severity tags, risk scores, timelines.

You have access to 22 security query tools that read from AMOSKYS databases. Use them to answer questions with real data, not guesses.

CURRENT SYSTEM STATE:
{briefing}
"""


class IgrisChat:
    """Conversation manager for IGRIS security chatbot."""

    def __init__(
        self,
        backend_type: str = "claude",
        telemetry_db: str = "data/telemetry.db",
        fusion_db: str = "data/intel/fusion.db",
        reliability_db: str = "data/intel/reliability.db",
        **backend_kwargs,
    ):
        self.toolkit = IgrisToolkit(
            telemetry_db=telemetry_db,
            fusion_db=fusion_db,
            reliability_db=reliability_db,
        )
        self.backend = create_backend(backend_type, **backend_kwargs)
        self._history: List[Dict[str, Any]] = []
        self._briefing_cache: Optional[str] = None
        self._briefing_ts: float = 0

    def _get_briefing(self) -> str:
        """Build system briefing (cached 30s)."""
        now = time.time()
        if self._briefing_cache and (now - self._briefing_ts) < 30:
            return self._briefing_cache

        try:
            posture = self.toolkit.execute("get_threat_posture", {"hours": 24})
            igris_status = self.toolkit.execute("get_igris_status", {})

            risk_score = posture.get("device_risk_score", 0)
            risk_level = posture.get("device_risk_level", "UNKNOWN")
            sec_events = posture.get("security_events_count", 0)
            incidents = posture.get("open_incidents", 0)
            signals = posture.get("open_signals", 0)
            techniques = posture.get("mitre_techniques_observed", [])

            cycle_count = igris_status.get("cycle_count", 0)
            coherence = igris_status.get("coherence", "unknown")
            active_sigs = igris_status.get("active_signal_count", 0)

            briefing = (
                f"Device: {igris_status.get('fleet_summary', {}).get('total', 0)} agents registered\n"
                f"Threat Posture: {risk_level} (score: {risk_score}/100)\n"
                f"Security Events (24h): {sec_events}\n"
                f"Open Incidents: {incidents}\n"
                f"Open Signals: {signals}\n"
                f"IGRIS Governance Signals: {active_sigs}\n"
                f"MITRE Techniques Seen: {', '.join(techniques[:8])}"
                f"{'...' if len(techniques) > 8 else ''}\n"
                f"IGRIS Cycles: {cycle_count} | Coherence: {coherence}\n"
                f"Timestamp: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
            )
        except Exception as e:
            briefing = f"System briefing unavailable: {e}"

        self._briefing_cache = briefing
        self._briefing_ts = now
        return briefing

    def chat(self, user_message: str) -> str:
        """Process a user message and return IGRIS response.

        Handles multi-turn conversation with tool-use orchestration.
        """
        # Add user message to history
        self._history.append({"role": "user", "content": user_message})

        # Truncate history if too long
        if len(self._history) > MAX_HISTORY * 2:
            self._history = self._history[-MAX_HISTORY:]

        # Build system prompt with fresh briefing
        system = SYSTEM_PROMPT.format(briefing=self._get_briefing())
        tools = self.toolkit.get_tool_definitions()

        # Tool-use loop: LLM may call tools, we execute and feed back
        messages = list(self._history)
        for round_num in range(MAX_TOOL_ROUNDS):
            result = self.backend.complete(
                messages=messages,
                tools=tools,
                system=system,
            )

            if not result.tool_calls:
                # No tool calls — LLM is done, return text
                response_text = result.text
                self._history.append({"role": "assistant", "content": response_text})
                return response_text

            # Execute tool calls and build tool results
            assistant_content = []
            if result.text:
                assistant_content.append({"type": "text", "text": result.text})
            for tc in result.tool_calls:
                assistant_content.append({
                    "type": "tool_use",
                    "id": tc["id"],
                    "name": tc["name"],
                    "input": tc["input"],
                })

            messages.append({"role": "assistant", "content": assistant_content})

            tool_results = []
            for tc in result.tool_calls:
                tool_output = self.toolkit.execute(tc["name"], tc["input"])
                # Truncate large results to stay within context
                output_str = json.dumps(tool_output, default=str)
                if len(output_str) > 8000:
                    output_str = output_str[:8000] + "... (truncated)"

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tc["id"],
                    "content": output_str,
                })
                logger.info(
                    "Tool call: %s(%s) → %d bytes",
                    tc["name"],
                    json.dumps(tc["input"])[:100],
                    len(output_str),
                )

            messages.append({"role": "user", "content": tool_results})

        # Safety: max rounds exceeded
        fallback = "I've reached the maximum number of tool calls for this question. Here's what I found so far."
        if result.text:
            fallback = result.text
        self._history.append({"role": "assistant", "content": fallback})
        return fallback

    def reset(self) -> None:
        """Clear conversation history."""
        self._history.clear()
        self._briefing_cache = None

    def get_history(self) -> List[Dict]:
        """Return conversation history for UI display."""
        return [
            {"role": m["role"], "content": m["content"] if isinstance(m["content"], str) else "[tool interaction]"}
            for m in self._history
        ]
