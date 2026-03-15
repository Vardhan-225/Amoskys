"""
IGRIS LLM Backends — Ollama (default, free, local) + Claude API (optional).

Protocol-based design: swap backends without changing chat controller.
Configure via .env:
    IGRIS_BACKEND=ollama          # or "claude"
    IGRIS_MODEL=qwen3:8b          # any Ollama model with tool-use
    OLLAMA_HOST=http://localhost:11434
    ANTHROPIC_API_KEY=sk-...      # only needed for claude backend
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol

logger = logging.getLogger("igris.backends")

# Load .env from project root (data never committed — .gitignore covers .env*)
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

# Default model choices per backend
_DEFAULT_OLLAMA_MODEL = "qwen3:8b"
_DEFAULT_CLAUDE_MODEL = "claude-sonnet-4-20250514"


@dataclass
class CompletionResult:
    """Result from an LLM completion call."""

    text: str = ""
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    stop_reason: str = ""
    input_tokens: int = 0
    output_tokens: int = 0


class LLMBackend(Protocol):
    """Protocol for swappable LLM backends."""

    def complete(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        system: str = "",
    ) -> CompletionResult: ...


# ═══════════════════════════════════════════════════════════════════
# Ollama Backend — free, local, private
# ═══════════════════════════════════════════════════════════════════


class OllamaBackend:
    """Ollama local model backend with native tool-use support.

    Recommended models (by quality, all fit 16GB M4):
      qwen3:8b        — best reasoning + thinking mode (default)
      qwen2.5:14b     — best tool-use quality (tight on 16GB)
      mistral-nemo:12b — 128K context, solid reasoning
      qwen2.5:7b      — lightweight fallback
      llama3.1:8b     — battle-tested, 128K context
    """

    def __init__(
        self,
        model: str = None,
        host: str = None,
    ):
        self._model = (
            model
            or os.environ.get("IGRIS_MODEL")
            or os.environ.get("OLLAMA_MODEL")
            or _DEFAULT_OLLAMA_MODEL
        )
        self._host = host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                import ollama

                self._client = ollama.Client(host=self._host)
            except ImportError:
                raise RuntimeError(
                    "ollama package required. Install: pip install ollama"
                )
        return self._client

    def complete(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        system: str = "",
    ) -> CompletionResult:
        client = self._get_client()

        ollama_messages = self._build_messages(messages, system)
        ollama_tools = self._convert_tools(tools)

        try:
            response = client.chat(
                model=self._model,
                messages=ollama_messages,
                tools=ollama_tools,
            )
        except Exception as e:
            logger.error("Ollama chat failed: %s", e)
            return CompletionResult(
                text=f"Ollama error: {e}. Is Ollama running? Try: `ollama serve`",
                stop_reason="error",
            )

        return self._parse_response(response)

    @staticmethod
    def _build_messages(
        messages: List[Dict[str, Any]], system: str
    ) -> List[Dict[str, Any]]:
        """Convert Claude-format messages to Ollama format."""
        out: List[Dict[str, Any]] = []
        if system:
            out.append({"role": "system", "content": system})

        for msg in messages:
            converted = _convert_message_to_ollama(msg)
            out.extend(converted)
        return out

    @staticmethod
    def _convert_tools(
        tools: List[Dict[str, Any]],
    ) -> Optional[List[Dict[str, Any]]]:
        """Convert Claude tool schemas to Ollama/OpenAI format."""
        if not tools:
            return None
        return [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "parameters": t.get("input_schema", {}),
                },
            }
            for t in tools
        ]

    @staticmethod
    def _parse_response(response: Dict) -> CompletionResult:
        """Parse Ollama response into CompletionResult."""
        import re

        msg = response.get("message", {})
        text = msg.get("content", "") or ""

        # Strip thinking tags from qwen3 thinking mode
        if "<think>" in text:
            text = re.sub(r"<think>.*?</think>\s*", "", text, flags=re.DOTALL).strip()

        tool_calls = [
            {
                "id": f"ollama_{uuid.uuid4().hex[:8]}",
                "name": tc.get("function", {}).get("name", ""),
                "input": tc.get("function", {}).get("arguments", {}),
            }
            for tc in msg.get("tool_calls", [])
        ]

        return CompletionResult(
            text=text,
            tool_calls=tool_calls,
            stop_reason="end_turn" if not tool_calls else "tool_use",
        )


def _convert_message_to_ollama(msg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convert a single Claude-format message to Ollama format."""
    role = msg["role"]
    content = msg.get("content", "")

    if isinstance(content, str):
        return [{"role": role, "content": content}]

    if not isinstance(content, list):
        return [{"role": role, "content": str(content)}]

    converters = {"user": _convert_tool_results, "assistant": _convert_tool_use}
    converter = converters.get(role)
    if converter:
        return converter(content)
    return [{"role": role, "content": str(content)}]


def _convert_tool_results(blocks: List[Dict]) -> List[Dict[str, Any]]:
    """Convert Claude tool_result blocks → Ollama 'tool' role messages."""
    return [
        {"role": "tool", "content": b.get("content", "")}
        for b in blocks
        if isinstance(b, dict) and b.get("type") == "tool_result"
    ]


def _convert_tool_use(blocks: List[Dict]) -> List[Dict[str, Any]]:
    """Convert Claude assistant tool_use blocks → Ollama assistant + tool_calls."""
    text_parts = []
    tool_calls = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        block_type = block.get("type")
        if block_type == "text":
            text_parts.append(block["text"])
        elif block_type == "tool_use":
            tool_calls.append({
                "function": {"name": block["name"], "arguments": block.get("input", {})}
            })
    out: Dict[str, Any] = {"role": "assistant", "content": "\n".join(text_parts) or ""}
    if tool_calls:
        out["tool_calls"] = tool_calls
    return [out]


# ═══════════════════════════════════════════════════════════════════
# Claude Backend — high quality, paid
# ═══════════════════════════════════════════════════════════════════


class ClaudeBackend:
    """Claude API backend using the Anthropic SDK."""

    def __init__(self, api_key: str = None, model: str = None):
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._model = (
            model
            or os.environ.get("IGRIS_MODEL")
            or _DEFAULT_CLAUDE_MODEL
        )
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                import anthropic

                self._client = anthropic.Anthropic(api_key=self._api_key)
            except ImportError:
                raise RuntimeError(
                    "anthropic package required. Install: pip install anthropic"
                )
        return self._client

    def complete(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        system: str = "",
    ) -> CompletionResult:
        client = self._get_client()

        kwargs: Dict[str, Any] = {
            "model": self._model,
            "max_tokens": 4096,
            "messages": messages,
        }
        if system:
            kwargs["system"] = system
        if tools:
            kwargs["tools"] = tools

        response = client.messages.create(**kwargs)

        text_parts = []
        tool_calls = []

        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                tool_calls.append({
                    "id": block.id,
                    "name": block.name,
                    "input": block.input,
                })

        return CompletionResult(
            text="\n".join(text_parts),
            tool_calls=tool_calls,
            stop_reason=response.stop_reason,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
        )


# ═══════════════════════════════════════════════════════════════════
# Factory — auto-detect best available backend
# ═══════════════════════════════════════════════════════════════════


def create_backend(backend_type: str = None, **kwargs) -> LLMBackend:
    """Create the right backend based on .env config or explicit type.

    Priority:
      1. Explicit backend_type parameter
      2. IGRIS_BACKEND env var
      3. Auto-detect: Ollama if running, else Claude if key exists
    """
    if backend_type is None:
        backend_type = os.environ.get("IGRIS_BACKEND", "").lower()

    # Explicit ollama
    if backend_type == "ollama":
        return OllamaBackend(**kwargs)

    # Explicit claude
    if backend_type == "claude":
        api_key = kwargs.get("api_key") or os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY required for Claude backend. "
                "Set in .env or use IGRIS_BACKEND=ollama for free local inference."
            )
        return ClaudeBackend(
            api_key=api_key,
            **{k: v for k, v in kwargs.items() if k != "api_key"},
        )

    # Auto-detect: try Ollama first (free), fall back to Claude
    try:
        import ollama

        ollama.Client().list()
        logger.info("Auto-detected Ollama — using local inference (free)")
        return OllamaBackend(**kwargs)
    except Exception:
        pass

    api_key = kwargs.get("api_key") or os.environ.get("ANTHROPIC_API_KEY", "")
    if api_key:
        logger.info("Using Claude API backend")
        return ClaudeBackend(
            api_key=api_key,
            **{k: v for k, v in kwargs.items() if k != "api_key"},
        )

    raise ValueError(
        "No LLM backend available. Either:\n"
        "  1. Install & start Ollama: brew install ollama && ollama pull qwen3:8b && ollama serve\n"
        "  2. Set ANTHROPIC_API_KEY in .env for Claude API\n"
        "  3. Set IGRIS_BACKEND=ollama in .env"
    )
