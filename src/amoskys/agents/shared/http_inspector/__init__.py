"""AMOSKYS Shared HTTP Inspector Agent."""

from amoskys.agents.shared.http_inspector.agent import HTTPInspectorAgent
from amoskys.agents.shared.http_inspector.agent_types import HTTPTransaction
from amoskys.agents.shared.http_inspector.probes import (
    HTTP_INSPECTOR_PROBES,
    APIAbuseProbe,
    CSRFTokenMissingProbe,
    DataExfilHTTPProbe,
    PathTraversalProbe,
    SSRFDetectionProbe,
    SuspiciousUploadProbe,
    WebSocketAbuseProbe,
    XSSDetectionProbe,
    create_http_inspector_probes,
)

__all__ = [
    "HTTPInspectorAgent",
    "HTTPTransaction",
    "XSSDetectionProbe",
    "SSRFDetectionProbe",
    "PathTraversalProbe",
    "APIAbuseProbe",
    "DataExfilHTTPProbe",
    "SuspiciousUploadProbe",
    "WebSocketAbuseProbe",
    "CSRFTokenMissingProbe",
    "HTTP_INSPECTOR_PROBES",
    "create_http_inspector_probes",
]
