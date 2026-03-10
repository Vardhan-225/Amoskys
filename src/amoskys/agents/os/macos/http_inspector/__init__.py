"""AMOSKYS macOS HTTP Inspector Observatory.

Purpose-built HTTP threat detection for macOS (Darwin 25.0.0+, Apple Silicon).
Monitors web server access logs (Apache/Nginx) and Unified Logging for
URLSession/NSURLConnection activity.

Probes:
    - XSS detection (script injection patterns in request paths/params)
    - SSRF detection (internal IPs in URL parameters)
    - Path traversal (directory escape sequences)
    - API abuse (rate limiting violations)
    - WebShell upload (file upload to webshell patterns)
    - C2 web channel (HTTP beaconing with encoded payloads)
    - Data exfiltration via HTTP (large POST bodies to unusual endpoints)
    - Cookie theft (session hijacking patterns)

Coverage: T1059.007, T1090, T1083, T1106, T1505.003, T1071.001, T1048, T1539
"""

from amoskys.agents.os.macos.http_inspector.agent import MacOSHTTPInspectorAgent

__all__ = ["MacOSHTTPInspectorAgent"]
