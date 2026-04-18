"""Argos tool drivers.

Each tool is a thin wrapper around an external offensive tool (nuclei,
wpscan, sqlmap, etc.). Wrappers are responsible for:

  - Converting the tool's native output to Argos's structured Finding
    schema
  - Respecting the engagement's rate caps and time window
  - Recording the exact command invoked (for audit trail reproduction)

Tools declare a `probe_class` (e.g. "nuclei.cves") so the engagement
engine can enforce Scope.allowed_probe_classes / DENIED_PROBE_CLASSES.
"""

from amoskys.agents.Web.argos.tools.base import Tool, ToolResult
from amoskys.agents.Web.argos.tools.httpx import HTTPXTool
from amoskys.agents.Web.argos.tools.nmap import NmapTool
from amoskys.agents.Web.argos.tools.nuclei import NucleiTool
from amoskys.agents.Web.argos.tools.subfinder import SubfinderTool
from amoskys.agents.Web.argos.tools.wpscan import WPScanTool

__all__ = [
    "Tool",
    "ToolResult",
    "HTTPXTool",
    "NmapTool",
    "NucleiTool",
    "SubfinderTool",
    "WPScanTool",
]
