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
from typing import Any, Callable, Dict, List, Optional

from .backends import CompletionResult, create_backend
from .tools import IgrisToolkit, redact_text

logger = logging.getLogger("igris.chat")

# Optional per-tool-call callback: (tool_name, args, result_summary)
OnStep = Callable[[str, Dict[str, Any], str], None]

# ── Evidence humanization ────────────────────────────────────────────
# Maps internal tool names to human phrases + dashboard links so the UI
# can render "what IGRIS actually looked at" under each answer.

_DETAIL_MAX = 120

# Event-table → short name used by the timeline-replay page (?source=).
_TABLE_SHORTNAMES = {
    "security_events": "security",
    "process_events": "process",
    "flow_events": "flow",
    "dns_events": "dns",
    "fim_events": "fim",
    "persistence_events": "persistence",
    "peripheral_events": "peripheral",
    "audit_events": "audit",
    "observation_events": "observation",
}

_TOOL_LABELS = {
    "get_threat_posture": "Threat posture",
    "query_security_events": "Security events",
    "list_incidents": "Incidents",
    "get_incident_detail": "Incident detail",
    "query_signals": "Signals",
    "get_agent_health": "Agent health",
    "query_probes_fired": "Probes fired",
    "explain_mitre_technique": "MITRE technique",
    "query_dns_events": "DNS events",
    "query_process_events": "Process events",
    "query_flow_events": "Network flows",
    "query_fim_events": "File integrity",
    "query_persistence_events": "Persistence entries",
    "query_auth_events": "Auth events",
    "query_peripheral_events": "Peripheral events",
    "get_kill_chain_summary": "Kill chain",
    "get_mitre_coverage": "MITRE coverage",
    "get_igris_status": "IGRIS status",
    "get_flow_geo_summary": "Flow geography",
    "get_reliability_scores": "Agent reliability",
    "get_sigma_rule_hits": "Sigma rule hits",
    "get_event_timeline": "Event timeline",
    "get_event_detail": "Event detail",
    "verify_code_signing": "Code signing check",
    "scan_dyld_injection": "DYLD injection scan",
    "spawn_threat_hunter": "Threat hunter",
    "spawn_incident_analyst": "Incident analyst",
    "spawn_pattern_scout": "Pattern scout",
    "spawn_parallel_investigation": "Parallel investigation",
}

# Tools whose evidence points at the threat-hunt search page.
_HUNT_TOOLS = {
    "query_security_events",
    "query_dns_events",
    "query_process_events",
    "query_flow_events",
    "query_fim_events",
    "query_persistence_events",
    "query_auth_events",
    "query_peripheral_events",
    "get_event_timeline",
    "get_sigma_rule_hits",
    "query_probes_fired",
    "spawn_threat_hunter",
}

# Tools whose evidence points at the incidents page.
_INCIDENT_TOOLS = {"list_incidents", "get_incident_detail", "spawn_incident_analyst"}

# Tools whose evidence points at the agents page.
_AGENT_TOOLS = {"get_agent_health", "get_reliability_scores"}


def tool_label(tool_name: str, args: Optional[Dict[str, Any]] = None) -> str:
    """Human phrase for a tool call, e.g. 'Security events · 24h'."""
    args = args or {}
    base = _TOOL_LABELS.get(tool_name)
    if base is None:
        return f"Ran {tool_name}"

    qualifier = ""
    if tool_name == "explain_mitre_technique" and args.get("technique_id"):
        qualifier = str(args["technique_id"])
    elif tool_name in ("get_incident_detail", "spawn_incident_analyst") and args.get(
        "incident_id"
    ):
        qualifier = f"#{args['incident_id']}"
    elif tool_name == "get_event_detail" and args.get("event_id") is not None:
        qualifier = f"{args.get('table', 'event')} #{args['event_id']}"
    elif tool_name == "spawn_threat_hunter" and args.get("ioc_value"):
        qualifier = str(args["ioc_value"])[:40]
    elif tool_name == "query_dns_events" and args.get("domain"):
        qualifier = str(args["domain"])[:40]
    elif tool_name == "query_process_events" and args.get("exe"):
        qualifier = str(args["exe"])[:40]
    elif args.get("hours"):
        qualifier = f"{args['hours']}h"

    return f"{base} · {qualifier}" if qualifier else base


def _clip(text: str, limit: int = _DETAIL_MAX) -> str:
    text = " ".join(str(text).split())
    if len(text) > limit:
        return text[: limit - 1].rstrip() + "…"
    return text


def summarize_tool_result(tool_name: str, args: Dict[str, Any], result: Any) -> str:
    """One-line, redacted summary of a tool result (~120 chars)."""
    try:
        detail = _summarize(tool_name, result)
    except Exception:  # never let summarization break the chat loop
        detail = "done"
    return _clip(redact_text(detail) or "done")


def _summarize(tool_name: str, result: Any) -> str:
    if result is None:
        return "no data"

    if isinstance(result, list):
        n = len(result)
        if n == 0:
            return "0 rows"
        top_risk = None
        for key in ("risk_score", "threat_score", "anomaly_score"):
            vals = [
                r.get(key) for r in result if isinstance(r, dict) and r.get(key) is not None
            ]
            if vals:
                top_risk = max(vals)
                break
        if top_risk is not None:
            return f"{n} rows, top risk {round(float(top_risk), 2)}"
        return f"{n} rows"

    if isinstance(result, dict):
        if result.get("error"):
            return f"error: {result['error']}"

        if tool_name == "get_threat_posture":
            return (
                f"{result.get('device_risk_level', '?')} "
                f"(score {result.get('device_risk_score', '?')}/100), "
                f"{result.get('security_events_count', 0)} events, "
                f"{result.get('open_incidents', 0)} incidents"
            )
        if tool_name == "get_agent_health":
            if result.get("online") is None:
                return f"{result.get('total', '?')} agents known (no health data)"
            return (
                f"{result.get('online')}/{result.get('total', '?')} agents online"
            )
        if tool_name == "get_kill_chain_summary":
            return f"{result.get('techniques_observed', 0)} techniques observed"
        if tool_name == "get_mitre_coverage":
            return f"{result.get('total_techniques', 0)} techniques seen"
        if tool_name == "explain_mitre_technique":
            return f"{result.get('detection_count', 0)} detections use it"
        if tool_name == "get_event_detail":
            ev = result.get("event") or {}
            desc = ev.get("description") or ev.get("event_category") or ""
            return f"row {result.get('event_id')}: {desc}" if desc else (
                f"row {result.get('event_id')} fetched"
            )
        if tool_name == "scan_dyld_injection":
            return f"{result.get('total_suspicious', 0)} suspicious processes"
        if tool_name == "verify_code_signing":
            return (
                f"{'signed' if result.get('signed') else 'UNSIGNED'}, "
                f"trust {result.get('trust_level', '?')}"
            )
        if tool_name.startswith("spawn_"):
            summary = result.get("summary")
            if summary:
                return str(summary)
            if "results" in result:
                return f"{result.get('agents_spawned', 0)} sub-agents completed"
            return f"sub-agent {result.get('status', 'done')}"
        if tool_name == "get_igris_status":
            return (
                f"{result.get('status', '?')}, cycle #{result.get('cycle_count', 0)}, "
                f"{result.get('active_signal_count', 0)} active signals"
            )
        # Generic dict: show a couple of scalar fields
        parts = []
        for k, v in result.items():
            if isinstance(v, (str, int, float)) and len(parts) < 3:
                parts.append(f"{k}={v}")
        return ", ".join(parts) if parts else "1 result"

    return str(result)


def evidence_link(
    tool_name: str, args: Optional[Dict[str, Any]] = None, result: Any = None
) -> Optional[str]:
    """Best-effort dashboard URL for a piece of evidence, or None."""
    args = args or {}

    if tool_name == "get_event_detail":
        table = args.get("table", "security_events")
        short = _TABLE_SHORTNAMES.get(table, table)
        eid = args.get("event_id")
        if eid is not None:
            return f"/dashboard/timeline-replay?event_id={eid}&source={short}"
        return "/dashboard/hunt"

    if tool_name in _INCIDENT_TOOLS:
        return "/dashboard/incidents-view"

    if tool_name in _AGENT_TOOLS:
        return "/dashboard/agents"

    if tool_name in _HUNT_TOOLS:
        params = []
        hours = args.get("hours")
        if hours:
            params.append(f"hours={hours}")
        for key in ("domain", "exe", "dst_ip", "ioc_value"):
            if args.get(key):
                params.append(f"q={args[key]}")
                break
        return "/dashboard/hunt" + (f"?{'&'.join(params)}" if params else "")

    if tool_name in ("get_threat_posture", "get_kill_chain_summary", "get_mitre_coverage"):
        return "/dashboard/hunt"

    return None


def build_evidence_item(
    tool_name: str, args: Dict[str, Any], result: Any, detail: Optional[str] = None
) -> Dict[str, Any]:
    """Build one evidence entry: {tool, label, detail, link}."""
    if detail is None:
        detail = summarize_tool_result(tool_name, args, result)
    return {
        "tool": tool_name,
        "label": tool_label(tool_name, args),
        "detail": detail,
        "link": evidence_link(tool_name, args, result),
    }

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
        self._last_evidence: List[Dict[str, Any]] = []

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

    def proactive_brief(self, on_step: Optional[OnStep] = None) -> str:
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
        return self.chat(probe_message, on_step=on_step)

    def chat(self, user_message: str, on_step: Optional[OnStep] = None) -> str:
        """Process a user message and return IGRIS response.

        Handles multi-turn conversation with tool-use orchestration.

        on_step, when given, is invoked per tool call with
        (tool_name, args, result_summary) as the loop executes — used by
        the streaming endpoint to surface live progress. The same data
        feeds the evidence list available via get_last_evidence().
        """
        # Fresh evidence trail for this message
        self._last_evidence = []

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

                # Evidence trail + live step callback (same summary data)
                detail = summarize_tool_result(tc["name"], tc["input"], tool_output)
                self._last_evidence.append(
                    build_evidence_item(
                        tc["name"], tc["input"], tool_output, detail=detail
                    )
                )
                if on_step is not None:
                    try:
                        on_step(tc["name"], tc["input"], detail)
                    except Exception:  # observer must never break the loop
                        logger.debug("on_step callback failed", exc_info=True)

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

    def get_last_evidence(self) -> List[Dict[str, Any]]:
        """Evidence items ({tool,label,detail,link}) from the last chat() call."""
        return list(self._last_evidence)

    def reset(self) -> None:
        """Clear conversation history."""
        self._history.clear()
        self._briefing_cache = None
        self._last_evidence = []

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
