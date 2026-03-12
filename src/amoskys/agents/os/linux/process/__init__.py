"""AMOSKYS Linux Process Observatory — Linux process monitoring.

Status: SCAFFOLD — collector not yet implemented.
Roadmap: Port from amoskys.agents.os.macos.process via Igris multi-platform engine.

Data sources (when implemented):
    - psutil (cross-platform, works immediately)
    - /proc/{pid}/ (Linux-specific: maps, fd, environ, cgroup)
    - auditd execve events (if auditd configured)
"""

from amoskys.agents.os.linux.process.agent import LinuxProcessAgent

__all__ = ["LinuxProcessAgent"]
