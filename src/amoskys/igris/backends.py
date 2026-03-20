"""
IGRIS LLM Backend — Claude API.

AMOSKYS uses Anthropic's Claude API for IGRIS intelligence.
Configure via .env:
    ANTHROPIC_API_KEY=sk-ant-...
    IGRIS_MODEL=claude-sonnet-4-20250514    # optional override
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Protocol

logger = logging.getLogger("igris.backends")

# Load .env from project root
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
    """Protocol for LLM backends."""

    def complete(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        system: str = "",
    ) -> CompletionResult: ...


# ═══════════════════════════════════════════════════════════════════
# Claude Backend
# ═══════════════════════════════════════════════════════════════════


class ClaudeBackend:
    """Claude API backend using the Anthropic SDK."""

    def __init__(self, api_key: str = None, model: str = None):
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._model = (
            model or os.environ.get("IGRIS_MODEL", "") or _DEFAULT_CLAUDE_MODEL
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
# Factory
# ═══════════════════════════════════════════════════════════════════


def create_backend(**kwargs) -> LLMBackend:
    """Create Claude backend.

    Args:
        **kwargs: Passed to ClaudeBackend (api_key, model).
    """
    api_key = kwargs.get("api_key") or os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise ValueError(
            "ANTHROPIC_API_KEY required. Set in .env file.\n"
            "  Get your key at: https://console.anthropic.com/"
        )
    return ClaudeBackend(
        api_key=api_key,
        model=kwargs.get("model"),
    )
