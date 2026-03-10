"""AMOSKYS Windows Arsenal — Windows security capabilities.

Windows-specific detection modules. Key data sources (future):
    - ETW (Event Tracing for Windows) — process, network, file events
    - Windows Event Log — Security (4624/4625), System, Application
    - WMI — process creation, service changes
    - Registry monitoring — Run keys, scheduled tasks
    - AMSI — antimalware scan interface integration
    - Sysmon — enhanced process/network/file telemetry

Status: Not implemented. Requires Windows device for ground truth.
"""


class WindowsArsenal:
    """Windows detection capability manager — placeholder."""

    def status(self) -> str:
        return (
            "═══ AMOSKYS Windows Arsenal ═══\n"
            "Status: NOT IMPLEMENTED\n"
            "Requires: Windows device + ETW/WMI/EventLog implementation.\n"
            "\n"
            "Planned data sources:\n"
            "  [ ] ETW — process, network, file events\n"
            "  [ ] Windows Event Log — 4624/4625 (logon), 4688 (process)\n"
            "  [ ] WMI — process creation, service changes\n"
            "  [ ] Registry — Run keys, scheduled tasks\n"
            "  [ ] AMSI — antimalware scan interface\n"
            "  [ ] Sysmon — enhanced telemetry (if installed)\n"
        )

    def run_audit(self):
        raise NotImplementedError("Windows arsenal requires Windows device")

    def to_dict(self):
        return {"platform": "windows", "status": "NOT_IMPLEMENTED"}


__all__ = ["WindowsArsenal"]
