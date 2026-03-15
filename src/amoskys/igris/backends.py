"""
IGRIS LLM Backends — Claude API (primary) + Ollama (fallback).

Protocol-based design: swap backends without changing chat controller.
"""

from __future__ import annotations

import json
import logging
import os
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


class ClaudeBackend:
    """Claude API backend using the Anthropic SDK."""

    def __init__(self, api_key: str = None, model: str = "claude-sonnet-4-20250514"):
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._model = model
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


class OllamaBackend:
    """Ollama local model backend (offline fallback)."""

    def __init__(self, model: str = "llama3.1:8b", host: str = "http://localhost:11434"):
        self._model = model
        self._host = host

    def complete(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        system: str = "",
    ) -> CompletionResult:
        try:
            import ollama
        except ImportError:
            raise RuntimeError(
                "ollama package required. Install: pip install ollama"
            )

        ollama_messages = []
        if system:
            ollama_messages.append({"role": "system", "content": system})
        for msg in messages:
            ollama_messages.append({
                "role": msg["role"],
                "content": msg.get("content", ""),
            })

        # Ollama tool-use support (Llama 3.1+)
        ollama_tools = None
        if tools:
            ollama_tools = [
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

        client = ollama.Client(host=self._host)
        response = client.chat(
            model=self._model,
            messages=ollama_messages,
            tools=ollama_tools,
        )

        text = response.get("message", {}).get("content", "")
        tool_calls = []
        for tc in response.get("message", {}).get("tool_calls", []):
            fn = tc.get("function", {})
            tool_calls.append({
                "id": f"ollama_{fn.get('name', '')}",
                "name": fn.get("name", ""),
                "input": fn.get("arguments", {}),
            })

        return CompletionResult(
            text=text,
            tool_calls=tool_calls,
            stop_reason="end_turn",
        )


def create_backend(backend_type: str = "claude", **kwargs) -> LLMBackend:
    """Factory: create the right backend based on availability."""
    if backend_type == "ollama":
        return OllamaBackend(**kwargs)

    # Default: Claude
    api_key = kwargs.get("api_key") or os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        logger.warning("No ANTHROPIC_API_KEY found. IGRIS chat will not work without an LLM backend.")
        raise ValueError(
            "ANTHROPIC_API_KEY required for Claude backend. "
            "Set it in your environment or use backend_type='ollama' for local inference."
        )
    return ClaudeBackend(api_key=api_key, **{k: v for k, v in kwargs.items() if k != "api_key"})
