"""AMOSKYS Linux Correlation Engine — future Igris expansion.

Cross-agent correlation for Linux devices. Requires Linux ground truth
before implementation (auditd + inotify + /proc + systemd journal).

Status: Structure only. Implementation deferred to Igris multi-platform engine.
Roadmap: Igris will share correlation rules across macOS/Linux/Windows,
         adapting only the collector layer per platform.
"""
