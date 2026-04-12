"""
IGRIS LLM Backend — Anthropic SDK with tool runner.

Provides two interfaces:
  1. IgrisBrain  — Full agentic loop via tool_runner() for IGRIS commander
  2. AgentMind   — Lightweight per-agent reasoning via Haiku

Configure via .env:
    ANTHROPIC_API_KEY=sk-ant-...
    IGRIS_MODEL=claude-opus-4-6           # commander model (default)
    IGRIS_AGENT_MODEL=claude-haiku-4-5    # per-agent model (default)
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("igris.backends")

# ═══════════════════════════════════════════════════════════════════
# Config
# ═══════════════════════════════════════════════════════════════════

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_ENV_FILE = _PROJECT_ROOT / ".env"


def _load_dotenv() -> None:
    """Minimal .env loader — no dependency on python-dotenv."""
    if not _ENV_FILE.exists():
        return
    for line in _ENV_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("\"'")
        if key and key not in os.environ:
            os.environ[key] = value


_load_dotenv()

# Commander uses Opus for deep cross-domain reasoning
COMMANDER_MODEL = os.environ.get("IGRIS_MODEL", "claude-opus-4-6")
# Agent minds use Haiku for fast, cheap per-event reasoning
AGENT_MODEL = os.environ.get("IGRIS_AGENT_MODEL", "claude-haiku-4-5")


# ═══════════════════════════════════════════════════════════════════
# Result types
# ═══════════════════════════════════════════════════════════════════


@dataclass
class CompletionResult:
    """Result from an LLM completion call."""

    text: str = ""
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    stop_reason: str = ""
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class BrainResult:
    """Result from a full IGRIS brain reasoning cycle."""

    verdict: str = ""
    tool_calls_made: int = 0
    turns: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    duration_ms: int = 0
    cost_usd: float = 0.0


# ═══════════════════════════════════════════════════════════════════
# Anthropic client singleton
# ═══════════════════════════════════════════════════════════════════

_client = None
_async_client = None


def _get_client():
    """Get or create the Anthropic client (singleton)."""
    global _client
    if _client is None:
        try:
            import anthropic
        except ImportError:
            raise RuntimeError(
                "anthropic package required. Install: pip install anthropic"
            )
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY required. Set in .env file.\n"
                "  Get your key at: https://console.anthropic.com/"
            )
        _client = anthropic.Anthropic(api_key=api_key)
    return _client


def _get_async_client():
    """Get or create the async Anthropic client (singleton)."""
    global _async_client
    if _async_client is None:
        try:
            import anthropic
        except ImportError:
            raise RuntimeError(
                "anthropic package required. Install: pip install anthropic"
            )
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY required.")
        _async_client = anthropic.AsyncAnthropic(api_key=api_key)
    return _async_client


# ═══════════════════════════════════════════════════════════════════
# IGRIS Brain — Full agentic reasoning via tool runner
# ═══════════════════════════════════════════════════════════════════


class IgrisBrain:
    """Claude-powered reasoning engine for IGRIS commander.

    Uses the Anthropic SDK tool_runner() for automatic tool-use loops.
    Claude calls IGRIS toolkit tools, gets results, reasons, repeats —
    until it has a complete verdict.

    This replaces the manual tool-use loop in chat.py with the SDK's
    built-in agentic loop handler.
    """

    def __init__(
        self,
        toolkit,
        model: str = None,
        max_turns: int = 15,
        max_budget_usd: float = 0.50,
    ):
        self.toolkit = toolkit
        self.model = model or COMMANDER_MODEL
        self.max_turns = max_turns
        self.max_budget_usd = max_budget_usd

    def reason(
        self,
        prompt: str,
        system: str = "",
        history: List[Dict[str, Any]] = None,
    ) -> BrainResult:
        """Run a full reasoning cycle.

        Claude receives the prompt + system context, calls tools as needed
        via tool_runner(), and returns a final verdict.
        """
        client = _get_client()
        start = time.monotonic()

        messages = list(history or [])
        messages.append({"role": "user", "content": prompt})

        tools = self.toolkit.get_tool_definitions()

        total_input = 0
        total_output = 0
        tool_calls = 0
        turns = 0
        final_text = ""

        # Agentic loop — keep going until Claude stops calling tools
        for _turn in range(self.max_turns):
            turns += 1

            kwargs: Dict[str, Any] = {
                "model": self.model,
                "max_tokens": 16000,
                "messages": messages,
            }
            if system:
                kwargs["system"] = system
            if tools:
                kwargs["tools"] = tools

            response = client.messages.create(**kwargs)

            total_input += response.usage.input_tokens
            total_output += response.usage.output_tokens

            # Cost tracking
            cost = _estimate_cost(
                self.model, response.usage.input_tokens, response.usage.output_tokens
            )
            if cost > self.max_budget_usd:
                logger.warning(
                    "IGRIS brain budget exceeded: $%.3f > $%.3f",
                    cost,
                    self.max_budget_usd,
                )
                break

            # If Claude is done (no more tool calls), extract text and break
            if response.stop_reason == "end_turn":
                final_text = _extract_text(response)
                break

            # Extract tool use blocks
            tool_use_blocks = [b for b in response.content if b.type == "tool_use"]
            if not tool_use_blocks:
                final_text = _extract_text(response)
                break

            # Append assistant response — serialize content blocks to plain
            # dicts to avoid pydantic model_dump issues on subsequent calls
            serialized_content = []
            for block in response.content:
                if block.type == "text":
                    serialized_content.append({"type": "text", "text": block.text})
                elif block.type == "tool_use":
                    serialized_content.append(
                        {
                            "type": "tool_use",
                            "id": block.id,
                            "name": block.name,
                            "input": block.input,
                        }
                    )
                elif block.type == "thinking":
                    serialized_content.append(
                        {"type": "thinking", "thinking": block.thinking}
                    )
            messages.append({"role": "assistant", "content": serialized_content})

            # Execute tools and collect results
            tool_results = []
            for tb in tool_use_blocks:
                tool_calls += 1
                result = self.toolkit.execute(tb.name, tb.input)
                output_str = json.dumps(result, default=str)
                # Truncate large results
                if len(output_str) > 8000:
                    output_str = output_str[:8000] + "... (truncated)"

                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": tb.id,
                        "content": output_str,
                    }
                )
                logger.info(
                    "IGRIS tool: %s(%s) → %d bytes",
                    tb.name,
                    json.dumps(tb.input, default=str)[:80],
                    len(output_str),
                )

            messages.append({"role": "user", "content": tool_results})

        elapsed = int((time.monotonic() - start) * 1000)

        return BrainResult(
            verdict=final_text,
            tool_calls_made=tool_calls,
            turns=turns,
            input_tokens=total_input,
            output_tokens=total_output,
            duration_ms=elapsed,
            cost_usd=_estimate_cost(self.model, total_input, total_output),
        )


# ═══════════════════════════════════════════════════════════════════
# Agent Mind — Lightweight per-agent reasoning
# ═══════════════════════════════════════════════════════════════════


class AgentMindBackend:
    """Lightweight Claude backend for individual agent minds.

    Uses Haiku for fast, cheap per-event reasoning. Each agent mind
    has domain-specific tools and a focused system prompt.

    This is NOT a full agentic loop — agent minds make 1-3 tool calls
    max, then deliver a verdict. Deep investigation is escalated to
    IGRIS commander.
    """

    def __init__(
        self,
        agent_name: str,
        domain_prompt: str,
        tools: List[Dict[str, Any]] = None,
        tool_executor: Callable = None,
        model: str = None,
        max_turns: int = 3,
    ):
        self.agent_name = agent_name
        self.domain_prompt = domain_prompt
        self.tools = tools or []
        self.tool_executor = tool_executor
        self.model = model or AGENT_MODEL
        self.max_turns = max_turns

    def reason(
        self,
        anomaly_description: str,
        context: Dict[str, Any] = None,
    ) -> CompletionResult:
        """Quick reasoning about a specific anomaly.

        Agent minds are fast and cheap. They answer:
        - Is this real or noise?
        - What's the confidence?
        - Should I escalate to IGRIS?
        - Should I adjust my probes?
        """
        client = _get_client()

        system = (
            f"You are the {self.agent_name} agent mind in AMOSKYS. "
            f"{self.domain_prompt}\n\n"
            f"You have ONE job: analyze the anomaly and deliver a verdict.\n"
            f"Respond with a JSON object:\n"
            f'{{"verdict": "clean|suspicious|malicious", '
            f'"confidence": 0.0-1.0, '
            f'"reasoning": "brief explanation", '
            f'"escalate": true/false, '
            f'"probe_adjustment": null or {{"probe": "name", "action": "tighten|loosen", "reason": "..."}}}}'
        )

        if context:
            system += f"\n\nCurrent context:\n{json.dumps(context, default=str)[:2000]}"

        messages = [{"role": "user", "content": anomaly_description}]

        total_input = 0
        total_output = 0
        tool_calls_list = []

        for _turn in range(self.max_turns):
            kwargs: Dict[str, Any] = {
                "model": self.model,
                "max_tokens": 2048,
                "system": system,
                "messages": messages,
            }
            if self.tools:
                kwargs["tools"] = self.tools

            response = client.messages.create(**kwargs)

            total_input += response.usage.input_tokens
            total_output += response.usage.output_tokens

            if response.stop_reason == "end_turn":
                return CompletionResult(
                    text=_extract_text(response),
                    tool_calls=tool_calls_list,
                    stop_reason=response.stop_reason,
                    input_tokens=total_input,
                    output_tokens=total_output,
                )

            # Handle tool calls (1-3 max for agent minds)
            tool_use_blocks = [b for b in response.content if b.type == "tool_use"]
            if not tool_use_blocks:
                return CompletionResult(
                    text=_extract_text(response),
                    tool_calls=tool_calls_list,
                    stop_reason=response.stop_reason,
                    input_tokens=total_input,
                    output_tokens=total_output,
                )

            messages.append({"role": "assistant", "content": response.content})

            tool_results = []
            for tb in tool_use_blocks:
                tool_calls_list.append(
                    {"name": tb.name, "input": tb.input, "id": tb.id}
                )
                if self.tool_executor:
                    result = self.tool_executor(tb.name, tb.input)
                else:
                    result = {"error": "No tool executor configured"}

                output_str = json.dumps(result, default=str)
                if len(output_str) > 4000:
                    output_str = output_str[:4000] + "... (truncated)"

                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": tb.id,
                        "content": output_str,
                    }
                )

            messages.append({"role": "user", "content": tool_results})

        # Max turns exceeded
        return CompletionResult(
            text=_extract_text(response) if response else "",
            tool_calls=tool_calls_list,
            stop_reason="max_turns",
            input_tokens=total_input,
            output_tokens=total_output,
        )


# ═══════════════════════════════════════════════════════════════════
# Legacy compatibility — ClaudeBackend (used by existing chat.py)
# ═══════════════════════════════════════════════════════════════════


class ClaudeBackend:
    """Legacy single-shot backend. Used by existing chat.py manual loop.

    Preserved for backward compatibility. New code should use
    IgrisBrain (commander) or AgentMindBackend (per-agent).
    """

    def __init__(self, api_key: str = None, model: str = None):
        self._model = model or COMMANDER_MODEL

    def complete(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        system: str = "",
    ) -> CompletionResult:
        client = _get_client()

        kwargs: Dict[str, Any] = {
            "model": self._model,
            "max_tokens": 16000,
            "messages": messages,
            "thinking": {"type": "adaptive"},
        }
        if system:
            kwargs["system"] = system
        if tools:
            kwargs["tools"] = tools

        # Stream for timeout protection
        with client.messages.stream(**kwargs) as stream:
            response = stream.get_final_message()

        text_parts = []
        tool_calls = []

        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                tool_calls.append(
                    {
                        "id": block.id,
                        "name": block.name,
                        "input": block.input,
                    }
                )

        return CompletionResult(
            text="\n".join(text_parts),
            tool_calls=tool_calls,
            stop_reason=response.stop_reason,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
        )


# ═══════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════


def _extract_text(response) -> str:
    """Extract text content from a Messages API response."""
    parts = []
    for block in response.content:
        if block.type == "text":
            parts.append(block.text)
    return "\n".join(parts)


def _estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Estimate USD cost for a request."""
    rates = {
        "claude-opus-4-6": (5.00, 25.00),
        "claude-sonnet-4-6": (3.00, 15.00),
        "claude-haiku-4-5": (1.00, 5.00),
    }
    # Normalize model name for lookup
    for key, (inp_rate, out_rate) in rates.items():
        if key in model:
            return (input_tokens * inp_rate + output_tokens * out_rate) / 1_000_000
    # Default to Opus pricing
    return (input_tokens * 5.00 + output_tokens * 25.00) / 1_000_000


def create_backend(**kwargs) -> ClaudeBackend:
    """Create Claude backend (legacy factory).

    For new code, use IgrisBrain or AgentMindBackend directly.
    """
    return ClaudeBackend(
        api_key=kwargs.get("api_key"),
        model=kwargs.get("model"),
    )


def create_brain(toolkit, **kwargs) -> IgrisBrain:
    """Create IGRIS commander brain."""
    return IgrisBrain(
        toolkit=toolkit,
        model=kwargs.get("model"),
        max_turns=kwargs.get("max_turns", 15),
        max_budget_usd=kwargs.get("max_budget_usd", 0.50),
    )
