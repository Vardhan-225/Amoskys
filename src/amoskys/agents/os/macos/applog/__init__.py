"""AMOSKYS macOS Application Log Observatory.

Purpose-built application log threat detection for macOS (Darwin 25.0.0+, Apple Silicon).
Monitors Unified Logging for web servers, databases, and application frameworks via
process predicates for httpd, nginx, postgres, mysqld, python, node, ruby, java.

Probes:
    - Web shell access detection (cmd/eval/exec patterns in HTTP logs)
    - Log tampering detection (timestamp gaps, deletion patterns)
    - Application error spike anomaly detection
    - Credential harvest detection (secrets leaked in logs)
    - Privilege escalation via app logs (sudo, su, AuthorizationRef)
    - SQL injection pattern detection (UNION SELECT, OR 1=1)
    - Authentication bypass detection (null tokens, override patterns)

Coverage: T1505.003, T1070.002, T1499, T1552.001, T1548, T1190, T1556
"""

from amoskys.agents.os.macos.applog.agent import MacOSAppLogAgent

__all__ = ["MacOSAppLogAgent"]
