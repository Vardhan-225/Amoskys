"""
MITRE ATT&CK Technique Auto-Tagging Enrichment Stage

Maps event attributes to MITRE ATT&CK technique IDs based on behavioral
pattern matching. Fills the mitre_techniques field that agents may leave
empty or partially populated.

Coverage:
    - Authentication attacks (brute force, credential stuffing)
    - Persistence mechanisms (LaunchAgent, cron, login items)
    - Privilege escalation (sudo abuse, setuid)
    - Defense evasion (log clearing, timestomping)
    - Command & control (DNS tunneling, beaconing)
    - Discovery (port scanning, network enumeration)
    - Collection (file access, clipboard)
    - Lateral movement (SSH, remote services)
    - Exfiltration (DNS exfil, large transfers)
    - Hardware additions (USB devices)
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# Pattern → (technique_id, technique_name) mappings
# Each pattern is a callable that takes an event dict and returns bool
_MITRE_RULES: List[tuple] = []


def _rule(technique_id: str, technique_name: str):
    """Decorator to register a MITRE pattern matching rule."""

    def decorator(fn):
        _MITRE_RULES.append((fn, technique_id, technique_name))
        return fn

    return decorator


# ── Initial Access ──


@_rule("T1078", "Valid Accounts")
def _valid_accounts(e: Dict) -> bool:
    cat = e.get("event_category", "")
    action = e.get("event_action", "")
    outcome = e.get("event_outcome", "")
    return (
        action in ("SSH", "LOGIN")
        and outcome == "SUCCESS"
        and e.get("source_ip") not in (None, "", "127.0.0.1", "::1")
    )


# ── Credential Access ──


@_rule("T1110", "Brute Force")
def _brute_force(e: Dict) -> bool:
    cat = e.get("event_category", "")
    action = e.get("event_action", "")
    outcome = e.get("event_outcome", "")
    return action in ("SSH", "LOGIN") and outcome == "FAILURE"


@_rule("T1110.001", "Password Guessing")
def _password_guessing(e: Dict) -> bool:
    cat = e.get("event_category", "").lower()
    return "brute_force" in cat or "password_spray" in cat


@_rule("T1552", "Unsecured Credentials")
def _unsecured_creds(e: Dict) -> bool:
    path = e.get("path", "")
    return any(
        p in path for p in [".ssh/", "credentials", ".aws/", ".gnupg/", "keychain"]
    )


# ── Persistence ──


@_rule("T1543.001", "Launch Agent")
def _launch_agent(e: Dict) -> bool:
    cat = e.get("event_category", "")
    mechanism = e.get("mechanism", "")
    path = e.get("path", "")
    return (
        "launch_agent" in cat.lower()
        or "launch_agent" in mechanism.lower()
        or "LaunchAgents" in path
    )


@_rule("T1543.004", "Launch Daemon")
def _launch_daemon(e: Dict) -> bool:
    cat = e.get("event_category", "")
    mechanism = e.get("mechanism", "")
    path = e.get("path", "")
    return (
        "launch_daemon" in cat.lower()
        or "launch_daemon" in mechanism.lower()
        or "LaunchDaemons" in path
    )


@_rule("T1053.003", "Cron")
def _cron_persistence(e: Dict) -> bool:
    cat = e.get("event_category", "")
    mechanism = e.get("mechanism", "")
    path = e.get("path", "")
    return "cron" in cat.lower() or "cron" in mechanism.lower() or "/crontab" in path


@_rule("T1547.015", "Login Items")
def _login_items(e: Dict) -> bool:
    cat = e.get("event_category", "")
    mechanism = e.get("mechanism", "")
    return "login_item" in cat.lower() or "login_item" in mechanism.lower()


# ── Privilege Escalation ──


@_rule("T1548.003", "Sudo and Sudo Caching")
def _sudo_abuse(e: Dict) -> bool:
    cat = e.get("event_category", "")
    action = e.get("event_action", "")
    syscall = e.get("syscall", "")
    return action == "SUDO" or "sudo" in cat.lower() or "sudo" in syscall.lower()


@_rule("T1548.001", "Setuid and Setgid")
def _setuid(e: Dict) -> bool:
    cat = e.get("event_category", "")
    new_mode = e.get("new_mode", "")
    return "setuid" in cat.lower() or (
        new_mode and ("s" in new_mode or "4" in new_mode[:1])
    )


# ── Defense Evasion ──


@_rule("T1070.002", "Clear Linux or Mac System Logs")
def _clear_logs(e: Dict) -> bool:
    path = e.get("path", "")
    change_type = e.get("change_type", "")
    return change_type in ("DELETED", "TRUNCATED") and any(
        p in path for p in ["/var/log/", ".log", "system.log", "auth.log"]
    )


@_rule("T1222", "File and Directory Permissions Modification")
def _perm_modification(e: Dict) -> bool:
    cat = e.get("event_category", "")
    change_type = e.get("change_type", "")
    return (
        change_type == "PERMISSIONS_CHANGED"
        or "permission" in cat.lower()
        or "chmod" in cat.lower()
    )


@_rule("T1562.001", "Disable or Modify Tools")
def _disable_tools(e: Dict) -> bool:
    path = e.get("path", "")
    cmdline = e.get("cmdline", e.get("command_line", ""))
    return (
        any(p in path for p in ["/usr/libexec/", "com.apple.alf", "firewall"])
        or "csrutil" in (cmdline or "")
        or "spctl" in (cmdline or "")
    )


# ── Command and Control ──


@_rule("T1071.004", "DNS")
def _dns_c2(e: Dict) -> bool:
    cat = e.get("event_category", "").lower()
    return (
        "dns_tunnel" in cat
        or "dns_exfil" in cat
        or e.get("is_tunneling") is True
        or (e.get("dga_score") and float(e.get("dga_score", 0)) > 0.7)
    )


@_rule("T1071.001", "Web Protocols")
def _web_c2(e: Dict) -> bool:
    cat = e.get("event_category", "").lower()
    return "beacon" in cat or e.get("is_beaconing") is True


@_rule("T1568.002", "Domain Generation Algorithms")
def _dga(e: Dict) -> bool:
    dga = e.get("dga_score")
    return dga is not None and float(dga) > 0.8


# ── Discovery ──


@_rule("T1046", "Network Service Discovery")
def _port_scan(e: Dict) -> bool:
    cat = e.get("event_category", "").lower()
    return "port_scan" in cat or "scan" in cat


@_rule("T1057", "Process Discovery")
def _process_discovery(e: Dict) -> bool:
    cmdline = e.get("cmdline", e.get("command_line", ""))
    if not cmdline:
        return False
    return any(tool in cmdline for tool in ["ps aux", "ps -ef", "top -l", "lsof"])


# ── Execution ──


@_rule("T1059", "Command and Scripting Interpreter")
def _scripting(e: Dict) -> bool:
    exe = e.get("exe", e.get("executable_path", ""))
    if not exe:
        return False
    interpreters = ["python", "ruby", "perl", "osascript", "bash", "zsh", "sh"]
    exe_name = exe.rsplit("/", 1)[-1] if "/" in exe else exe
    # Only flag if the parent is suspicious (not normal shell usage)
    ppid_exe = e.get("parent_exe", "")
    return exe_name in interpreters and ppid_exe and "Terminal" not in ppid_exe


@_rule("T1059.004", "Unix Shell")
def _reverse_shell(e: Dict) -> bool:
    cmdline = e.get("cmdline", e.get("command_line", ""))
    if not cmdline:
        return False
    return any(p in cmdline for p in ["/dev/tcp/", "nc -e", "bash -i", "mkfifo"])


# ── Collection ──


@_rule("T1005", "Data from Local System")
def _data_collection(e: Dict) -> bool:
    path = e.get("path", "")
    return any(
        p in path
        for p in [
            "/etc/shadow",
            "/etc/passwd",
            "Keychain",
            ".ssh/id_",
            "known_hosts",
        ]
    )


# ── Lateral Movement ──


@_rule("T1021.004", "SSH")
def _ssh_lateral(e: Dict) -> bool:
    action = e.get("event_action", "")
    outcome = e.get("event_outcome", "")
    src = e.get("source_ip", "")
    return (
        action == "SSH"
        and outcome == "SUCCESS"
        and src not in (None, "", "127.0.0.1", "::1")
    )


# ── Exfiltration ──


@_rule("T1048.003", "Exfiltration Over Unencrypted Non-C2 Protocol")
def _dns_exfil(e: Dict) -> bool:
    cat = e.get("event_category", "").lower()
    return "dns_exfil" in cat or "exfil" in cat


# ── Impact ──


@_rule("T1200", "Hardware Additions")
def _hardware(e: Dict) -> bool:
    cat = e.get("event_category", "").lower()
    device_type = e.get("device_type", "").lower()
    return "usb" in cat or "peripheral" in cat or device_type in ("usb", "thunderbolt")


class MITREEnricher:
    """MITRE ATT&CK technique auto-tagger.

    Evaluates event attributes against behavioral pattern rules and
    appends matching technique IDs to the event's mitre_techniques list.
    """

    def __init__(self) -> None:
        self._available = True
        self._total_enriched = 0
        self._total_techniques_added = 0
        logger.info(
            "MITRE enricher initialized: %d pattern rules loaded",
            len(_MITRE_RULES),
        )

    @property
    def available(self) -> bool:
        return self._available

    def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate event against all MITRE pattern rules.

        Appends matching technique IDs to event["mitre_techniques"].
        Does not remove existing techniques — only adds new ones.

        Args:
            event: Mutable event dictionary.

        Returns:
            The same event dict with mitre_techniques updated.
        """
        existing = set(event.get("mitre_techniques", []))
        added = []

        for rule_fn, technique_id, technique_name in _MITRE_RULES:
            if technique_id in existing:
                continue
            try:
                if rule_fn(event):
                    added.append(technique_id)
                    existing.add(technique_id)
            except Exception as e:
                logger.debug("MITRE rule %s evaluation failed: %s", technique_id, e)

        if added:
            techniques = list(event.get("mitre_techniques", []))
            techniques.extend(added)
            event["mitre_techniques"] = techniques
            self._total_techniques_added += len(added)

        self._total_enriched += 1
        return event

    def cache_info(self) -> Dict[str, int]:
        """Return enrichment statistics."""
        return {
            "total_enriched": self._total_enriched,
            "total_techniques_added": self._total_techniques_added,
            "rules_loaded": len(_MITRE_RULES),
        }

    def close(self) -> None:
        """No resources to release."""
        pass
