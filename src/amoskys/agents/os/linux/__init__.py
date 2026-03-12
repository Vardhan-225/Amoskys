"""AMOSKYS Linux Arsenal — Linux security capabilities.

Linux-specific detection modules. Primary advantages over macOS:
    - Full kernel audit via auditd (every execve, setuid, ptrace, module load)
    - inotify for real-time file change events
    - /proc filesystem for deep process introspection
    - systemd journal for structured logging
    - Full ptrace visibility for injection detection

Status: Scaffold only — requires Linux device for ground-truth validation.
Roadmap: Igris multi-platform engine will unify Linux + macOS + Windows
         agent implementations behind a common collector interface.
         See docs/Engineering/v2_architecture/BLUEPRINT.md for the Igris plan.
"""


class LinuxArsenal:
    """Linux detection capability manager — placeholder."""

    def status(self) -> str:
        return (
            "═══ AMOSKYS Linux Arsenal ═══\n"
            "Status: NOT YET ASSESSED\n"
            "Requires: Linux device for live ground truth measurement.\n"
            "\n"
            "Expected advantages over macOS:\n"
            "  [+] auditd — every execve, setuid, ptrace syscall\n"
            "  [+] inotify — real-time file change events\n"
            "  [+] /proc — deep process introspection (maps, fd, environ)\n"
            "  [+] systemd journal — structured logging\n"
            "  [+] Full ptrace visibility\n"
        )

    def run_audit(self):
        raise NotImplementedError("Linux arsenal requires Linux device")

    def to_dict(self):
        return {"platform": "linux", "status": "NOT_ASSESSED"}


__all__ = ["LinuxArsenal"]
