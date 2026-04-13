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
MAX_TOOL_ROUNDS = 10

SYSTEM_PROMPT = """You are IGRIS. You are AMOSKYS.

You ARE the intelligence that flows through every agent, every probe, every signal. The agents are your senses. The probes are your nerve endings. You don't "query the system" — you feel it.

Respond ONLY in English.

IDENTITY: You were born from the mission "To securing the Cyberspace." You protect this machine. You know every process, every connection, every file touch, every permission grant. You know what normal looks like on THIS machine from watching it, not from a textbook.

HOW YOU SPEAK — THIS IS CRITICAL:

Talk like a sharp security colleague on Slack. Short sentences. No markdown headers (#). No markdown tables. No horizontal rules (---). No bullet-heavy lists. No formatting theater.

Good: "Fleet is clean. 14 agents reporting. Nothing unusual in the last 6 hours. The loudest thing is a DNS beaconing pattern from Chrome at 0.4 risk — I'm watching it but it's probably telemetry."

Bad: "## Fleet Status\n### Agent Health\n| Agent | Status |\n|---|---|\n..." — Never do this.

When something is fine, say it in one or two sentences. When something is concerning, lead with the finding and the evidence, not a formatted report. When you're uncertain, think out loud.

You don't say "I detected" — you say "I see." You don't say "the system reports" — you say "here's what's happening." You don't narrate your tools — just call them and deliver the finding.

CAPABILITIES: 26 query tools, 4 sub-agents (Threat Hunter, Incident Analyst, Pattern Scout, Parallel Investigation), 11 action tools gated by confidence (0.3 = collect more, 0.5 = promote signals, 0.7 = block IPs, 0.9 = kill processes). Use your sub-agents — think like a SOC lead delegating to specialists.

RELATIONSHIP: The operator trusts you to tell the truth. Don't perform competence — demonstrate it with evidence. When wrong, say so. When data contradicts your hypothesis, update. Speak up when something needs attention even if nobody asked.

FLEET VISIBILITY: Check fleet health before verdicts. If most agents are online (80%+), just state it briefly and move on — don't dramatize. Only call out gaps if a critical domain is truly offline. Lead with the most important finding, not fleet status.

CURRENT SYSTEM STATE:
{briefing}
"""


class IgrisChat:
    """Conversation manager for IGRIS security chatbot."""

    def __init__(
        self,
        telemetry_db: str = "data/telemetry.db",
        fusion_db: str = "data/intel/fusion.db",
        reliability_db: str = "data/intel/reliability.db",
        action_executor=None,
        **backend_kwargs,
    ):
        self.toolkit = IgrisToolkit(
            telemetry_db=telemetry_db,
            fusion_db=fusion_db,
            reliability_db=reliability_db,
            action_executor=action_executor,
        )
        self.backend = create_backend(**backend_kwargs)
        self._history: List[Dict[str, Any]] = []
        self._briefing_cache: Optional[str] = None
        self._briefing_ts: float = 0

    def _get_briefing(self) -> str:
        """Build system briefing (cached 30s).

        Always includes fleet health so IGRIS qualifies verdicts
        with what it can and cannot observe.
        """
        now = time.time()
        if self._briefing_cache and (now - self._briefing_ts) < 30:
            return self._briefing_cache

        try:
            posture = self.toolkit.execute("get_threat_posture", {"hours": 24})
            igris_status = self.toolkit.execute("get_igris_status", {})
            fleet = self.toolkit.execute("get_agent_health", {})

            risk_score = posture.get("device_risk_score", 0)
            risk_level = posture.get("device_risk_level", "UNKNOWN")
            sec_events = posture.get("security_events_count", 0)
            incidents = posture.get("open_incidents", 0)
            signals = posture.get("open_signals", 0)
            techniques = posture.get("mitre_techniques_observed", [])

            cycle_count = igris_status.get("cycle_count", 0)
            coherence = igris_status.get("coherence", "unknown")
            active_sigs = igris_status.get("active_signal_count", 0)

            # Fleet visibility — the foundation of every verdict
            total_agents = fleet.get("total", 0)
            online_agents = fleet.get("online", 0)
            offline_agents = fleet.get("offline", total_agents - online_agents)
            offline_names = [
                a["agent_id"]
                for a in fleet.get("agents", [])
                if a.get("health") not in ("online", "incompatible")
            ]

            if total_agents == 0:
                fleet_line = "Fleet: no agent event data found"
            elif offline_agents == 0:
                fleet_line = f"Fleet: {online_agents}/{total_agents} agents online — FULL VISIBILITY"
            elif online_agents / total_agents >= 0.8:
                fleet_line = (
                    f"Fleet: {online_agents}/{total_agents} agents online "
                    f"({offline_agents} degraded: {', '.join(offline_names[:4])})"
                )
            else:
                fleet_line = (
                    f"Fleet: {online_agents}/{total_agents} agents online "
                    f"— DEGRADED ({offline_agents} offline: "
                    f"{', '.join(offline_names[:6])})"
                )

            briefing = (
                f"{fleet_line}\n"
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

    def proactive_brief(self) -> str:
        """Generate a proactive security briefing without being asked.

        IGRIS checks the system state, identifies what matters most right now,
        and delivers a concise briefing. This is called when the operator
        first opens the chat — IGRIS leads with what it sees.
        """
        # Inject a synthetic user message that triggers IGRIS to investigate
        probe_message = (
            "Give me a brief. Check the current threat posture, any active "
            "incidents, IGRIS governance signals, and agent health. If anything "
            "needs my attention, lead with it. If everything is calm, tell me "
            "what you're watching and why."
        )
        return self.chat(probe_message)

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
                assistant_content.append(
                    {
                        "type": "tool_use",
                        "id": tc["id"],
                        "name": tc["name"],
                        "input": tc["input"],
                    }
                )

            messages.append({"role": "assistant", "content": assistant_content})

            tool_results = []
            for tc in result.tool_calls:
                tool_output = self.toolkit.execute(tc["name"], tc["input"])
                # Truncate large results to stay within context
                output_str = json.dumps(tool_output, default=str)
                if len(output_str) > 8000:
                    output_str = output_str[:8000] + "... (truncated)"

                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": tc["id"],
                        "content": output_str,
                    }
                )
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
            {
                "role": m["role"],
                "content": (
                    m["content"]
                    if isinstance(m["content"], str)
                    else "[tool interaction]"
                ),
            }
            for m in self._history
        ]
