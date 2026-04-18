"""Tool ABC + ToolResult dataclass.

All Argos tool drivers implement this interface. Keep tools narrow —
a driver should do one thing (e.g., run nuclei with a specific template
category) rather than wrapping the entire CLI surface.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from amoskys.agents.Web.argos.engine import Scope


@dataclass
class ToolResult:
    """Structured output from a single tool invocation."""

    tool: str
    command: List[str]  # the exact argv that was executed
    target: str
    exit_code: int
    started_at_ns: int
    completed_at_ns: int
    stdout_bytes: int
    stderr_bytes: int
    findings: List[Dict[str, Any]] = field(default_factory=list)
    raw_output_path: Optional[str] = None  # where full raw output is stored
    errors: List[str] = field(default_factory=list)

    @property
    def duration_s(self) -> float:
        return (self.completed_at_ns - self.started_at_ns) / 1e9

    @classmethod
    def failed(cls, tool: str, target: str, error: str) -> "ToolResult":
        now = int(time.time() * 1e9)
        return cls(
            tool=tool,
            command=[],
            target=target,
            exit_code=-1,
            started_at_ns=now,
            completed_at_ns=now,
            stdout_bytes=0,
            stderr_bytes=0,
            errors=[error],
        )


class Tool(ABC):
    """Abstract Argos tool driver.

    Subclasses declare:
      - name: human-readable tool name (e.g., "nuclei-cves")
      - tool_class: one of "recon", "fingerprint", "probe"
      - probe_class: namespaced class for scope enforcement
        (e.g., "nuclei.cves", "wpscan.plugins")
      - required_binary: path or command name that must exist
    """

    name: str = ""
    tool_class: str = ""  # recon | fingerprint | probe
    probe_class: str = ""  # e.g. "nuclei.cves"
    required_binary: str = ""

    @abstractmethod
    def run(self, target: str, scope: "Scope") -> ToolResult:
        """Run the tool against a target, respecting scope constraints."""
        ...

    def available(self) -> bool:
        """Return True if the tool's binary is on PATH and functional.

        Default implementation checks for the binary's existence. Tools
        that need additional runtime checks (license, rules dir) can
        override.
        """
        import shutil

        if not self.required_binary:
            return True
        return shutil.which(self.required_binary) is not None
