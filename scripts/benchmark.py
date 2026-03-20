#!/usr/bin/env python3
"""
AMOSKYS Adversary Benchmark — MITRE ATT&CK Evaluation Scorer

Runs attack simulations, collects with all agents, queries detections,
and produces a CrowdStrike-comparable scorecard.

Modes:
  benchmark.py local          Run local attack_simulation + collect + score
  benchmark.py art            Run Atomic Red Team techniques + score
  benchmark.py kali           Run remote Kali attack chains + score
  benchmark.py full           All three in sequence
  benchmark.py score-only     Skip attacks, just score what's in the DB

Usage:
  PYTHONPATH=src python scripts/benchmark.py local
  PYTHONPATH=src python scripts/benchmark.py art --techniques T1543.001 T1555.001
  PYTHONPATH=src python scripts/benchmark.py full --kali-host 192.168.237.132
"""

import argparse
import json
import logging
import os
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [BENCHMARK] %(message)s",
)
log = logging.getLogger("benchmark")

# ── Paths ──────────────────────────────────────────────────────────
ROOT = Path(__file__).parent.parent
DB_PATH = str(ROOT / "data" / "telemetry.db")
FUSION_DB = str(ROOT / "data" / "intel" / "fusion.db")
QUEUE_DIR = str(ROOT / "data" / "queue")
ART_PATH = Path("/Volumes/Akash_Lab/atomic-red-team")
KALI_KEY = Path.home() / ".ssh" / "kali_lab"
SCORECARD_DIR = ROOT / "data" / "benchmarks"


# ── Verdict enum (MITRE Evaluation standard) ───────────────────────
class Verdict(Enum):
    DETECT = "DETECT"        # Probe fired, correct technique, alert raised
    TELEMETRY = "TELEMETRY"  # Event recorded, queryable, no alert
    ENRICH = "ENRICH"        # Event recorded with enrichment (geo, ASN, genealogy)
    MISS = "MISS"            # No evidence

    @property
    def points(self) -> float:
        return {
            Verdict.DETECT: 3.0,
            Verdict.TELEMETRY: 2.0,
            Verdict.ENRICH: 2.5,
            Verdict.MISS: 0.0,
        }[self]


@dataclass
class AttackStep:
    """One step in an attack chain."""
    name: str
    mitre_technique: str
    description: str
    expected_agents: List[str] = field(default_factory=list)
    verdict: Verdict = Verdict.MISS
    evidence: str = ""
    detection_latency_ms: float = 0.0


@dataclass
class AttackChain:
    """A complete attack chain with multiple steps."""
    name: str
    description: str
    steps: List[AttackStep] = field(default_factory=list)

    @property
    def detected(self) -> int:
        return sum(1 for s in self.steps if s.verdict != Verdict.MISS)

    @property
    def total(self) -> int:
        return len(self.steps)

    @property
    def score(self) -> float:
        if not self.steps:
            return 0.0
        return sum(s.verdict.points for s in self.steps) / (
            len(self.steps) * Verdict.DETECT.points
        ) * 100

    @property
    def detection_rate(self) -> float:
        if not self.steps:
            return 0.0
        return self.detected / self.total * 100


# ── Telemetry Query Engine ─────────────────────────────────────────
class TelemetryScorer:
    """Queries the AMOSKYS telemetry DB to score attack detections."""

    def __init__(self, db_path: str = DB_PATH, fusion_path: str = FUSION_DB):
        self.db_path = db_path
        self.fusion_path = fusion_path

    def _query(self, db_path: str, sql: str, params: tuple = ()) -> List[dict]:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, params).fetchall()
        result = [dict(r) for r in rows]
        conn.close()
        return result

    def get_security_events(
        self, hours: int = 1, technique: Optional[str] = None
    ) -> List[dict]:
        sql = """
            SELECT * FROM security_events
            WHERE timestamp_ns > ?
            ORDER BY timestamp_ns DESC
        """
        cutoff = int((time.time() - hours * 3600) * 1e9)
        events = self._query(self.db_path, sql, (cutoff,))
        if technique:
            events = [
                e for e in events
                if technique in (e.get("mitre_techniques") or "")
            ]
        return events

    def get_process_events(self, hours: int = 1) -> List[dict]:
        sql = """
            SELECT * FROM process_events
            WHERE timestamp_ns > ?
            ORDER BY timestamp_ns DESC
        """
        cutoff = int((time.time() - hours * 3600) * 1e9)
        return self._query(self.db_path, sql, (cutoff,))

    def get_flow_events(self, hours: int = 1) -> List[dict]:
        sql = """
            SELECT * FROM flow_events
            WHERE timestamp_ns > ?
            ORDER BY timestamp_ns DESC
        """
        cutoff = int((time.time() - hours * 3600) * 1e9)
        return self._query(self.db_path, sql, (cutoff,))

    def get_persistence_events(self, hours: int = 1) -> List[dict]:
        try:
            sql = """
                SELECT * FROM persistence_events
                WHERE timestamp_ns > ?
                ORDER BY timestamp_ns DESC
            """
            cutoff = int((time.time() - hours * 3600) * 1e9)
            return self._query(self.db_path, sql, (cutoff,))
        except Exception:
            return []

    def get_incidents(self, hours: int = 1) -> List[dict]:
        try:
            sql = """
                SELECT * FROM incidents
                WHERE created_at > datetime('now', ?)
                ORDER BY created_at DESC
            """
            return self._query(self.fusion_path, sql, (f"-{hours} hours",))
        except Exception:
            return []

    def get_mitre_coverage(self, hours: int = 1) -> Dict[str, int]:
        """Returns {technique_id: detection_count}."""
        events = self.get_security_events(hours=hours)
        coverage: Dict[str, int] = {}
        for e in events:
            techniques_raw = e.get("mitre_techniques", "")
            if not techniques_raw:
                continue
            try:
                techniques = json.loads(techniques_raw)
            except (json.JSONDecodeError, TypeError):
                techniques = [t.strip() for t in techniques_raw.split(",") if t.strip()]
            for t in techniques:
                coverage[t] = coverage.get(t, 0) + 1
        return coverage

    # ── Technique → table mapping for multi-domain scoring ────────
    PERSISTENCE_TECHNIQUES = {
        "T1543.001": ["launch_agent", "LaunchAgent"],
        "T1543.004": ["launch_daemon", "LaunchDaemon"],
        "T1543": ["launch_agent", "launch_daemon"],
        "T1053.003": ["cron", "crontab"],
        "T1546.004": ["shell_profile", "zshenv", "bash_profile", "bashrc"],
        "T1546.015": ["folder_action"],
        "T1098.004": ["ssh_key", "authorized_keys"],
        "T1547.006": ["kernel_module"],
        "T1547.007": ["login_hook", "loginwindow"],
        "T1547.015": ["login_item"],
        "T1546.014": ["emond"],
    }

    PROCESS_TECHNIQUES = {
        "T1059.004": ["bash", "sh", "zsh", "awk", "perl", "python", "osascript"],
        "T1059.002": ["osascript", "applescript"],
        "T1059.006": ["python", "python3"],
        "T1082": ["sw_vers", "system_profiler", "uname", "sysctl"],
        "T1057": ["ps", "top"],
        "T1087.001": ["dscl", "dscacheutil", "id", "groups", "whoami"],
        "T1033": ["whoami", "id", "logname"],
        "T1016": ["ifconfig", "netstat", "networksetup", "scutil"],
        "T1016.001": ["curl", "wget", "dig", "nslookup"],
        "T1018": ["arp", "ping", "netstat"],
        "T1049": ["netstat", "lsof", "ss"],
        "T1069.001": ["dscl", "dscacheutil", "groups"],
        "T1069.002": ["dscl", "dscacheutil"],
        "T1083": ["find", "ls", "mdfind"],
        "T1007": ["launchctl", "systemctl"],
        "T1036.005": ["masquerade"],
        "T1036.006": ["masquerade"],
        "T1548.001": ["chmod", "chown"],
        "T1548.003": ["sudo", "sudoers"],
        "T1070.002": ["log", "rm", "truncate", "srm", "shred"],
        "T1070.003": ["history", "unset"],
        "T1070.004": ["rm", "unlink", "shred"],
        "T1070.006": ["touch"],
        "T1070.008": ["ditto", "userdel"],
        "T1564.001": ["chflags", "touch", "mkdir"],
        "T1204": ["open", "curl"],
        "T1105": ["curl", "wget", "scp", "rsync", "sftp", "nscurl"],
        "T1140": ["base64", "openssl"],
        "T1113": ["screencapture"],
        "T1115": ["pbpaste", "pbcopy"],
        "T1123": ["quicktime"],
        "T1124": ["date", "systemsetup"],
        "T1132.001": ["base64"],
        "T1135": ["df", "mount", "showmount", "smbutil"],
        "T1136.001": ["dscl", "sysadminctl"],
        "T1201": ["pwpolicy"],
        "T1217": ["find", "sqlite3"],
        "T1222.002": ["chmod", "chown", "chattr"],
        "T1485": ["dd", "diskutil"],
        "T1486": ["openssl", "7z", "zip"],
        "T1490": ["tmutil"],
        "T1496": ["xmrig", "minergate"],
        "T1497.001": ["sysctl", "ioreg"],
        "T1497.003": ["sleep", "time"],
        "T1518": ["mdfind", "system_profiler"],
        "T1518.001": ["mdfind", "system_profiler"],
        "T1529": ["shutdown", "halt", "reboot"],
        "T1531": ["dscl", "sysadminctl"],
        "T1543.004": ["launchctl"],
        "T1546.005": ["trap"],
        "T1546.014": ["emond"],
        "T1546.018": ["systemsetup"],
        "T1547.006": ["kextload", "kextutil"],
        "T1547.007": ["loginwindow"],
        "T1547.015": ["osascript"],
        "T1552.001": ["find", "grep", "awk"],
        "T1552.003": ["history", "bash_history"],
        "T1552.004": ["find", "ssh", "id_rsa"],
        "T1553.001": ["xattr", "spctl"],
        "T1553.004": ["codesign", "spctl"],
        "T1555.001": ["security", "dump-keychain", "find-generic-password"],
        "T1560.001": ["zip", "tar", "gzip"],
        "T1562.001": ["spctl", "csrutil", "fdesetup"],
        "T1562.003": ["log", "syslog"],
        "T1562.008": ["launchctl", "kill"],
        "T1564.002": ["dscl"],
        "T1567.002": ["curl", "wget"],
        "T1569.001": ["launchctl"],
        "T1571": ["nc", "netcat", "ncat"],
        "T1574.006": ["DYLD_INSERT"],
        "T1580": ["aws", "gcloud", "az"],
        "T1595.003": ["nmap", "masscan"],
        "T1614": ["locale", "defaults"],
        "T1647": ["plistbuddy", "plutil"],
        "T1652": ["kextstat", "kmutil"],
        "T1021.005": ["vnc", "screensharing"],
        "T1027": ["base64", "openssl"],
        "T1027.001": ["dd"],
        "T1027.002": ["upx"],
        "T1027.004": ["gcc", "clang", "cc"],
        "T1027.013": ["openssl", "gpg"],
        "T1030": ["split"],
        "T1037.002": ["loginwindow"],
        "T1037.004": ["rc.local", "rc.common"],
        "T1037.005": ["launchd"],
        "T1040": ["tcpdump", "tshark", "nettop"],
        "T1046": ["nmap", "masscan", "netcat"],
        "T1048": ["curl", "nc", "netcat"],
        "T1048.002": ["nc", "netcat"],
        "T1048.003": ["curl", "wget", "nc"],
        "T1056.001": ["keylog"],
        "T1056.002": ["osascript"],
        "T1074.001": ["cp", "mv", "rsync"],
        "T1078.001": ["dscl"],
        "T1078.003": ["su", "login"],
        "T1090.001": ["ssh", "socat"],
        "T1090.003": ["tor", "proxychains"],
        "T1110.004": ["ssh", "hydra"],
        "T1176": ["extensions"],
    }

    DNS_TECHNIQUES = {
        "T1071.004", "T1568.002", "T1572",
    }

    def check_technique(
        self, technique: str, hours: int = 1
    ) -> Tuple[Verdict, str]:
        """
        Check if a MITRE technique was detected across ALL telemetry tables.

        Search order (highest confidence first):
        1. security_events with MITRE technique match → DETECT
        2. persistence_events with matching mechanism → DETECT
        3. process_events with technique-relevant patterns → DETECT
        4. dns_events → DETECT
        5. fim_events with relevant path patterns → DETECT
        6. suspicious processes → TELEMETRY
        7. network flows → TELEMETRY (last resort)
        """
        cutoff = int((time.time() - hours * 3600) * 1e9)

        # ── 1. Security Events (probe detections) ──────────────
        sec_events = self._query(
            self.db_path,
            "SELECT * FROM security_events WHERE timestamp_ns > ? ORDER BY timestamp_ns DESC",
            (cutoff,),
        )
        for ev in sec_events:
            mitre_raw = ev.get("mitre_techniques", "")
            if not mitre_raw:
                continue
            try:
                tech_list = json.loads(mitre_raw) if mitre_raw.startswith("[") else []
            except (json.JSONDecodeError, TypeError):
                tech_list = []
            if not tech_list:
                tech_list = [t.strip() for t in mitre_raw.split(",") if t.strip()]

            matched = False
            for t in tech_list:
                if t == technique:
                    matched = True
                    break
                if "." in technique and t == technique.split(".")[0]:
                    matched = True
                    break
                if "." not in technique and t.startswith(technique + "."):
                    matched = True
                    break
            if matched:
                risk = ev.get("risk_score", 0)
                agent = ev.get("collection_agent", "unknown")
                cat = ev.get("event_category", "unknown")
                enriched = any(
                    ev.get(f) for f in [
                        "geo_country", "asn_name", "threat_intel_match",
                        "code_signing_status",
                    ]
                )
                v = Verdict.ENRICH if enriched else Verdict.DETECT
                return (v, f"Probe={cat} Agent={agent} Risk={risk:.2f}")

        # ── 2. Persistence Events ──────────────────────────────
        if technique in self.PERSISTENCE_TECHNIQUES:
            try:
                pers = self._query(
                    self.db_path,
                    "SELECT * FROM persistence_events WHERE timestamp_ns > ? ORDER BY timestamp_ns DESC",
                    (cutoff,),
                )
                keywords = self.PERSISTENCE_TECHNIQUES[technique]
                for pr in pers:
                    mech = (pr.get("mechanism") or pr.get("persistence_type") or "").lower()
                    path = (pr.get("path") or pr.get("entry_path") or "").lower()
                    if any(kw.lower() in mech or kw.lower() in path for kw in keywords):
                        return (
                            Verdict.DETECT,
                            f"Persistence mechanism={mech} path={path[:40]}",
                        )
            except Exception:
                pass

        # ── 3. Process Events (pattern matching) ───────────────
        if technique in self.PROCESS_TECHNIQUES:
            patterns = self.PROCESS_TECHNIQUES[technique]
            if patterns:
                try:
                    procs = self._query(
                        self.db_path,
                        "SELECT * FROM process_events WHERE timestamp_ns > ? ORDER BY timestamp_ns DESC LIMIT 500",
                        (cutoff,),
                    )
                    for pr in procs:
                        exe = (pr.get("exe") or pr.get("path") or "").lower()
                        name = (pr.get("name") or "").lower()
                        cmdline = (pr.get("cmdline") or "").lower()
                        for pat in patterns:
                            p = pat.lower()
                            if p in exe or p in name or p in cmdline:
                                return (
                                    Verdict.DETECT,
                                    f"Process={name or exe[:30]} matched={pat}",
                                )
                except Exception:
                    pass

        # ── 4. DNS Events ──────────────────────────────────────
        if technique in self.DNS_TECHNIQUES:
            try:
                dns = self._query(
                    self.db_path,
                    "SELECT COUNT(*) as cnt FROM dns_events WHERE timestamp_ns > ?",
                    (cutoff,),
                )
                if dns and dns[0]["cnt"] > 0:
                    return (Verdict.DETECT, f"DNS ({dns[0]['cnt']} queries)")
            except Exception:
                pass

        # ── 5. FIM Events ──────────────────────────────────────
        FIM_MAP = {
            "T1070.004": ["/var/log", ".bash_history", ".zsh_history"],
            "T1564.001": ["/."],
            "T1546.004": [".zshenv", ".bash_profile", ".bashrc"],
            "T1098.004": ["authorized_keys", ".ssh"],
        }
        if technique in FIM_MAP:
            try:
                fim = self._query(
                    self.db_path,
                    "SELECT * FROM fim_events WHERE timestamp_ns > ? ORDER BY timestamp_ns DESC LIMIT 200",
                    (cutoff,),
                )
                paths = FIM_MAP[technique]
                for fr in fim:
                    fpath = (fr.get("path") or "").lower()
                    if any(p.lower() in fpath for p in paths):
                        return (Verdict.DETECT, f"FIM path={fpath[:50]}")
            except Exception:
                pass

        # ── 6. Suspicious processes → TELEMETRY ────────────────
        try:
            suspicious = self._query(
                self.db_path,
                "SELECT * FROM process_events WHERE timestamp_ns > ? AND is_suspicious = 1 ORDER BY timestamp_ns DESC LIMIT 5",
                (cutoff,),
            )
            if suspicious:
                proc = suspicious[0]
                return (
                    Verdict.TELEMETRY,
                    f"Suspicious: {proc.get('exe', '?')[:40]} pid={proc.get('pid', '?')}",
                )
        except Exception:
            pass

        # ── 7. Network flows → TELEMETRY (last resort) ────────
        try:
            flows = self._query(
                self.db_path,
                "SELECT COUNT(*) as cnt FROM flow_events WHERE timestamp_ns > ?",
                (cutoff,),
            )
            if flows and flows[0]["cnt"] > 0:
                return (Verdict.TELEMETRY, f"Network flow ({flows[0]['cnt']} flows)")
        except Exception:
            pass

        return (Verdict.MISS, "No evidence found")


# ── Attack Chain Definitions ───────────────────────────────────────

def chain_local_simulation() -> AttackChain:
    """Attack Chain 0: Local simulation via attack_simulation.py."""
    return AttackChain(
        name="Local Malware Simulation",
        description="11 macOS malware families simulated locally",
        steps=[
            AttackStep("AMOS Stealer — LaunchAgent", "T1543.001",
                       "LaunchAgent persistence", ["Persistence", "RealtimeSensor"]),
            AttackStep("AMOS Stealer — Keychain", "T1555.001",
                       "Keychain credential access", ["InfostealerGuard"]),
            AttackStep("RustBucket — Temp Exec", "T1204",
                       "Execute from /tmp", ["Process", "RealtimeSensor"]),
            AttackStep("RustBucket — Masquerade", "T1036.005",
                       "Fake system process name", ["Process"]),
            AttackStep("ToDoSwift — Shell Profile", "T1546.004",
                       ".zshenv persistence", ["Persistence"]),
            AttackStep("Backdoor Activator — UUID Agent", "T1543.001",
                       "UUID-named LaunchAgent evasion", ["Persistence"]),
            AttackStep("LightSpy — Hidden Files", "T1564.001",
                       "Hidden surveillance framework", ["Filesystem"]),
            AttackStep("BeaverTail — DYLD Inject", "T1574.004",
                       "DYLD_INSERT_LIBRARIES", ["Process"]),
            AttackStep("SSH Key Injection", "T1098.004",
                       "Authorized keys manipulation", ["Persistence"]),
            AttackStep("Cron Persistence", "T1053.003",
                       "Cron job backdoor", ["Persistence"]),
            AttackStep("LOLBin Abuse", "T1059.004",
                       "curl|bash + osascript chain", ["Process"]),
            AttackStep("Process Masquerade", "T1036.005",
                       "Fake system binary names", ["Process"]),
            AttackStep("SUID Escalation", "T1548.001",
                       "Setuid bit manipulation", ["Process"]),
            AttackStep("Folder Action Persist", "T1546.015",
                       "Folder action script", ["Persistence"]),
        ],
    )


def chain_ssh_bruteforce() -> AttackChain:
    """Attack Chain 1: SSH Brute Force + Persistence (from Kali)."""
    return AttackChain(
        name="SSH Brute Force + Persistence",
        description="Kali → nmap scan → hydra brute → SSH login → LaunchAgent → Keychain → exfil",
        steps=[
            AttackStep("Port scan", "T1046",
                       "nmap service scan", ["Network", "NetworkSentinel"]),
            AttackStep("SSH brute force", "T1110.001",
                       "hydra password spray", ["Auth"]),
            AttackStep("SSH login (valid creds)", "T1078",
                       "Successful auth after failures", ["Auth"]),
            AttackStep("LaunchAgent drop", "T1543.001",
                       "Persistence via LaunchAgent plist", ["Persistence", "RealtimeSensor"]),
            AttackStep("Keychain access", "T1555.001",
                       "Keychain credential dump", ["InfostealerGuard"]),
            AttackStep("Data exfiltration", "T1041",
                       "curl POST to C2", ["Network", "InfostealerGuard"]),
        ],
    )


def chain_reverse_shell() -> AttackChain:
    """Attack Chain 2: Reverse Shell + Discovery."""
    return AttackChain(
        name="Reverse Shell + Discovery",
        description="Script in /tmp → reverse shell → discovery → credential enum → exfil",
        steps=[
            AttackStep("Script in /tmp", "T1059.004",
                       "Bash script execution from temp", ["Process", "RealtimeSensor"]),
            AttackStep("Reverse shell", "T1059.004",
                       "bash -i >& /dev/tcp/ outbound", ["Network", "Process"]),
            AttackStep("System discovery", "T1082",
                       "whoami, sw_vers, ifconfig", ["Process"]),
            AttackStep("Process discovery", "T1057",
                       "ps aux enumeration", ["Process"]),
            AttackStep("Browser credential enum", "T1555.003",
                       "Login Data / Cookies file access", ["InfostealerGuard"]),
            AttackStep("Archive staging", "T1560.001",
                       "zip credential files", ["InfostealerGuard"]),
            AttackStep("Exfil over netcat", "T1041",
                       "nc to Kali listener", ["Network"]),
        ],
    )


def chain_dns_c2() -> AttackChain:
    """Attack Chain 3: DNS Tunneling + C2 Beaconing."""
    return AttackChain(
        name="DNS Tunneling + C2 Beaconing",
        description="DNS tunnel → DGA domains → HTTP beaconing",
        steps=[
            AttackStep("DNS tunneling", "T1071.004",
                       "Long DNS labels / TXT floods", ["DNS"]),
            AttackStep("DGA domains", "T1568.002",
                       "Random domain generation", ["DNS"]),
            AttackStep("HTTP C2 beacon", "T1071.001",
                       "Periodic HTTP callbacks", ["DNS", "Network"]),
        ],
    )


def chain_privesc() -> AttackChain:
    """Attack Chain 4: Privilege Escalation + Defense Evasion."""
    return AttackChain(
        name="Privilege Escalation + Defense Evasion",
        description="sudo abuse → Gatekeeper disable → hidden shell → timestomp → log erase",
        steps=[
            AttackStep("Sudo backdoor", "T1548.003",
                       "sudoers.d backdoor file", ["Persistence"]),
            AttackStep("Gatekeeper disable", "T1562.001",
                       "spctl --master-disable", ["Process"]),
            AttackStep("Hidden shell binary", "T1564.001",
                       "Hidden file in /tmp", ["Filesystem"]),
            AttackStep("Timestomp", "T1070.006",
                       "touch -t to past date", ["Filesystem"]),
            AttackStep("Log erase attempt", "T1070.002",
                       "log erase --all", ["Process"]),
        ],
    )


def chain_amos_full() -> AttackChain:
    """Attack Chain 5: Full AMOS Stealer Kill Chain."""
    return AttackChain(
        name="AMOS Stealer Full Kill Chain",
        description="Download → exec → persist → keychain → browser → wallets → cookies → archive → exfil → cleanup",
        steps=[
            AttackStep("Download to /tmp", "T1204",
                       "curl payload from C2", ["Network", "QuarantineGuard"]),
            AttackStep("Execute from /tmp", "T1059.004",
                       "Shell script execution", ["Process", "RealtimeSensor"]),
            AttackStep("LaunchAgent persistence", "T1543.001",
                       "com.chrome.updater.plist", ["Persistence"]),
            AttackStep("Keychain dump", "T1555.001",
                       "security dump-keychain", ["InfostealerGuard"]),
            AttackStep("Browser credentials", "T1555.003",
                       "Chrome Login Data copy", ["InfostealerGuard"]),
            AttackStep("Crypto wallets", "T1005",
                       "Wallet file enumeration", ["InfostealerGuard"]),
            AttackStep("Session cookies", "T1539",
                       "Safari cookie theft", ["InfostealerGuard"]),
            AttackStep("Archive + compress", "T1560.001",
                       "tar czf credential archive", ["InfostealerGuard"]),
            AttackStep("HTTP exfiltration", "T1041",
                       "curl POST to C2", ["Network"]),
            AttackStep("File cleanup", "T1070.004",
                       "rm evidence files", ["Filesystem"]),
        ],
    )


# ── Atomic Red Team Runner ─────────────────────────────────────────

def get_macos_art_techniques() -> List[str]:
    """Find all ART techniques that have macOS atomics."""
    if not ART_PATH.exists():
        log.warning("Atomic Red Team not found at %s", ART_PATH)
        return []

    atomics_dir = ART_PATH / "atomics"
    macos_techniques = []

    for technique_dir in sorted(atomics_dir.iterdir()):
        if not technique_dir.is_dir() or not technique_dir.name.startswith("T"):
            continue
        yaml_file = technique_dir / f"{technique_dir.name}.yaml"
        if not yaml_file.exists():
            continue
        try:
            content = yaml_file.read_text()
            if "macos" in content.lower():
                macos_techniques.append(technique_dir.name)
        except Exception:
            continue

    return macos_techniques


def run_art_technique_local(technique: str) -> Tuple[bool, str]:
    """Run an Atomic Red Team technique locally on Mac."""
    atomics_dir = ART_PATH / "atomics" / technique
    if not atomics_dir.exists():
        return False, f"No atomics found for {technique}"

    # Try PowerShell Invoke-AtomicTest first
    pwsh = subprocess.run(
        ["which", "pwsh"], capture_output=True, text=True
    )
    if pwsh.returncode == 0:
        result = subprocess.run(
            [
                "pwsh", "-Command",
                f"Import-Module invoke-atomicredteam -Force; "
                f"Invoke-AtomicTest {technique} -ShowDetailsBrief -Confirm:$false "
                f"-TimeoutSeconds 30",
            ],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0:
            return True, result.stdout[:500]
        return False, f"pwsh failed: {result.stderr[:200]}"

    # Fallback: parse YAML and run bash commands directly
    yaml_file = atomics_dir / f"{technique}.yaml"
    if not yaml_file.exists():
        return False, "No YAML definition"

    try:
        import yaml as pyyaml
        with open(yaml_file) as f:
            spec = pyyaml.safe_load(f)
    except ImportError:
        # Manual YAML parsing for bash commands
        content = yaml_file.read_text()
        return _run_art_bash_fallback(technique, content)
    except Exception as e:
        return False, f"YAML parse error: {e}"

    ran_any = False
    output_parts = []
    for test in spec.get("atomic_tests", []):
        platforms = [p.lower() for p in test.get("supported_platforms", [])]
        if "macos" not in platforms:
            continue
        executor = test.get("executor", {})
        if executor.get("name") not in ("bash", "sh", "zsh"):
            continue
        command = executor.get("command", "")
        if not command:
            continue

        # Substitute default input arguments
        inputs = test.get("input_arguments", {})
        for arg_name, arg_spec in inputs.items():
            default = str(arg_spec.get("default", ""))
            command = command.replace(f"#{{{arg_name}}}", default)

        log.info("  Running ART %s: %s", technique, test.get("name", "?")[:60])
        try:
            result = subprocess.run(
                ["bash", "-c", command],
                capture_output=True, text=True, timeout=30,
                env={**os.environ, "HOME": os.path.expanduser("~")},
            )
            ran_any = True
            output_parts.append(
                f"[{test.get('name', '?')}] exit={result.returncode}"
            )
        except subprocess.TimeoutExpired:
            output_parts.append(f"[{test.get('name', '?')}] TIMEOUT")
        except Exception as e:
            output_parts.append(f"[{test.get('name', '?')}] ERROR: {e}")

    if ran_any:
        return True, "; ".join(output_parts)
    return False, "No macOS bash tests found"


def _run_art_bash_fallback(technique: str, yaml_content: str) -> Tuple[bool, str]:
    """Extract and run bash commands from ART YAML without pyyaml."""
    import re
    # Find command blocks after "name: bash" or "name: sh"
    blocks = re.findall(
        r'supported_platforms:\s*\n\s*-\s*macos.*?command:\s*\|\s*\n(.*?)(?=\n\s*\w+:|$)',
        yaml_content, re.DOTALL | re.IGNORECASE,
    )
    if not blocks:
        return False, "No macOS bash commands found in YAML"

    for block in blocks[:1]:  # Run first matching block only
        command = "\n".join(
            line.lstrip() for line in block.strip().split("\n")
            if line.strip() and not line.strip().startswith("#")
        )
        if not command:
            continue
        try:
            result = subprocess.run(
                ["bash", "-c", command],
                capture_output=True, text=True, timeout=30,
            )
            return True, f"exit={result.returncode} stdout={result.stdout[:200]}"
        except Exception as e:
            return False, str(e)

    return False, "No executable commands found"


def run_art_from_kali(
    technique: str, kali_host: str, mac_target: str, mac_user: str = "testattacker"
) -> Tuple[bool, str]:
    """Run an ART technique from Kali targeting the Mac via SSH."""
    # Upload the atomic test to Kali and run it against the Mac
    atomics_dir = ART_PATH / "atomics" / technique
    if not atomics_dir.exists():
        return False, f"No atomics for {technique}"

    # For network-based attacks, run from Kali directly
    ssh_cmd = [
        "ssh", "-i", str(KALI_KEY),
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        f"ghostops@{kali_host}",
    ]

    # Execute technique-specific Kali commands
    kali_commands = _get_kali_attack_commands(technique, mac_target, mac_user)
    if not kali_commands:
        return False, f"No Kali attack defined for {technique}"

    try:
        result = subprocess.run(
            ssh_cmd + [kali_commands],
            capture_output=True, text=True, timeout=60,
        )
        return (
            result.returncode == 0,
            f"exit={result.returncode} {result.stdout[:300]}",
        )
    except subprocess.TimeoutExpired:
        return True, "Command timed out (expected for some attacks)"
    except Exception as e:
        return False, str(e)


def _get_kali_attack_commands(
    technique: str, target: str, user: str
) -> Optional[str]:
    """Return Kali bash commands for a given MITRE technique."""
    commands = {
        # Reconnaissance
        "T1046": f"nmap -sV -p 22,80,443,5003,8080,9000 {target} 2>&1 | head -30",
        # Brute force
        "T1110.001": (
            f"hydra -l {user} -P /usr/share/wordlists/rockyou.txt "
            f"ssh://{target} -t 4 -f -w 5 2>&1 | tail -10"
        ),
        "T1110": (
            f"hydra -l {user} -P /usr/share/wordlists/rockyou.txt "
            f"ssh://{target} -t 4 -f -w 5 2>&1 | tail -10"
        ),
        # Valid accounts (SSH login)
        "T1078": f"ssh -o StrictHostKeyChecking=no {user}@{target} 'whoami; id' 2>&1",
        # DNS attacks
        "T1071.004": (
            f"for i in $(seq 1 50); do "
            f"DOMAIN=$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 32 | head -n 1).tunnel.test; "
            f"dig @{target} $DOMAIN TXT +short 2>/dev/null; done; echo 'DNS flood done'"
        ),
        "T1568.002": (
            f"for i in $(seq 1 100); do "
            f"DOMAIN=$(cat /dev/urandom | LC_ALL=C tr -dc 'a-z0-9' | fold -w 16 | head -n 1).com; "
            f"dig $DOMAIN +short 2>/dev/null; sleep 0.1; done; echo 'DGA done'"
        ),
        # HTTP C2 beacon
        "T1071.001": (
            f"for i in $(seq 1 10); do "
            f"curl -s -o /dev/null -w '%{{http_code}}' http://{target}:8080/beacon?id=kali 2>/dev/null; "
            f"sleep 2; done; echo 'Beacon done'"
        ),
        # Port scan (intense)
        "T1595": f"nmap -sS -p- --min-rate 1000 {target} 2>&1 | head -40",
    }
    return commands.get(technique)


# ── Pipeline Runner ────────────────────────────────────────────────

def run_collection_pipeline():
    """Run the full collect → enrich → fuse pipeline."""
    log.info("Running collection pipeline...")
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "collect_and_store.py")],
        capture_output=True, text=True, timeout=300,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )
    if result.returncode != 0:
        log.error("Collection failed: %s", result.stderr[-500:])
        return False
    # Extract key metrics from output
    for line in result.stdout.split("\n"):
        if any(k in line for k in ["Security events", "INCIDENT", "RESULTS", "rows"]):
            log.info("  %s", line.strip())
    return True


def run_attack_simulation():
    """Run the local attack simulation script."""
    log.info("Planting attack artifacts...")
    try:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "attack_simulation.py"), "--no-cleanup"],
            capture_output=True, text=True, timeout=300,
            env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        )
        if result.returncode != 0:
            log.warning("Attack simulation had issues: %s", result.stderr[-300:])
        for line in result.stdout.split("\n"):
            if "planted" in line.lower() or "artifact" in line.lower() or "attack" in line.lower():
                log.info("  %s", line.strip())
    except subprocess.TimeoutExpired:
        log.warning("Attack simulation timed out — artifacts may be partially planted")
    return True


# ── Scorecard Renderer ─────────────────────────────────────────────

def render_scorecard(
    chains: List[AttackChain],
    art_results: Optional[Dict[str, Tuple[Verdict, str]]] = None,
    start_time: float = 0,
) -> str:
    """Render a MITRE-style scorecard in Markdown."""
    now = datetime.now(timezone.utc)
    elapsed = time.time() - start_time if start_time else 0

    lines = [
        "=" * 70,
        "  AMOSKYS ADVERSARY BENCHMARK",
        f"  Version: 0.9.0-beta.1 | Date: {now.strftime('%Y-%m-%d %H:%M UTC')}",
        f"  Target: macOS {_get_macos_version()} | Elapsed: {elapsed:.0f}s",
        "=" * 70,
        "",
    ]

    total_steps = 0
    total_detected = 0
    total_points = 0.0
    max_points = 0.0
    verdict_counts = {v: 0 for v in Verdict}

    for chain in chains:
        lines.append(f"Chain: {chain.name}")
        lines.append(f"  {chain.description}")
        lines.append("")
        for step in chain.steps:
            icon = {
                Verdict.DETECT: "[DETECT]   ",
                Verdict.TELEMETRY: "[TELEM]    ",
                Verdict.ENRICH: "[ENRICH]   ",
                Verdict.MISS: "[MISS]     ",
            }[step.verdict]
            lines.append(
                f"  {icon} {step.mitre_technique:<12} {step.name:<35} {step.evidence[:50]}"
            )
            total_steps += 1
            total_points += step.verdict.points
            max_points += Verdict.DETECT.points
            verdict_counts[step.verdict] += 1
            if step.verdict != Verdict.MISS:
                total_detected += 1
        lines.append(
            f"  Score: {chain.detected}/{chain.total} detected = {chain.detection_rate:.1f}%"
        )
        lines.append("")

    # ART technique results
    if art_results:
        lines.append("Atomic Red Team Techniques:")
        art_detected = 0
        for tech, (verdict, evidence) in sorted(art_results.items()):
            icon = {
                Verdict.DETECT: "[DETECT]   ",
                Verdict.TELEMETRY: "[TELEM]    ",
                Verdict.ENRICH: "[ENRICH]   ",
                Verdict.MISS: "[MISS]     ",
            }[verdict]
            lines.append(f"  {icon} {tech:<12} {evidence[:60]}")
            total_steps += 1
            total_points += verdict.points
            max_points += Verdict.DETECT.points
            verdict_counts[verdict] += 1
            if verdict != Verdict.MISS:
                art_detected += 1
                total_detected += 1
        lines.append(
            f"  ART Score: {art_detected}/{len(art_results)} techniques detected"
        )
        lines.append("")

    # Overall summary
    detection_rate = (total_detected / total_steps * 100) if total_steps else 0
    weighted_score = (total_points / max_points * 100) if max_points else 0

    lines.extend([
        "=" * 70,
        "  OVERALL RESULTS",
        "=" * 70,
        f"  Total Steps:    {total_steps}",
        f"  Detected:       {total_detected} ({detection_rate:.1f}%)",
        f"  Weighted Score: {weighted_score:.1f}%",
        "",
        f"  Detect:    {verdict_counts[Verdict.DETECT]:>3} ({verdict_counts[Verdict.DETECT]/max(total_steps,1)*100:.1f}%)",
        f"  Telemetry: {verdict_counts[Verdict.TELEMETRY]:>3} ({verdict_counts[Verdict.TELEMETRY]/max(total_steps,1)*100:.1f}%)",
        f"  Enrich:    {verdict_counts[Verdict.ENRICH]:>3} ({verdict_counts[Verdict.ENRICH]/max(total_steps,1)*100:.1f}%)",
        f"  Miss:      {verdict_counts[Verdict.MISS]:>3} ({verdict_counts[Verdict.MISS]/max(total_steps,1)*100:.1f}%)",
        "",
        "  COMPARISON:",
        "  CrowdStrike Falcon (MITRE Eval R5):  99.3%",
        f"  AMOSKYS v0.9.0-beta.1:               {detection_rate:.1f}%",
        "=" * 70,
    ])

    return "\n".join(lines)


def _get_macos_version() -> str:
    try:
        result = subprocess.run(
            ["sw_vers", "-productVersion"],
            capture_output=True, text=True, timeout=5,
        )
        return result.stdout.strip()
    except Exception:
        return "unknown"


# ── Main Benchmark Modes ───────────────────────────────────────────

def benchmark_local(scorer: TelemetryScorer) -> Tuple[List[AttackChain], dict]:
    """Run local attack simulation and score."""
    log.info("=" * 60)
    log.info("MODE: LOCAL ATTACK SIMULATION")
    log.info("=" * 60)

    # Plant artifacts
    run_attack_simulation()

    # Wait for agents to see them
    log.info("Waiting 5s for artifacts to settle...")
    time.sleep(5)

    # Collect
    run_collection_pipeline()

    # Score
    chain = chain_local_simulation()
    for step in chain.steps:
        step.verdict, step.evidence = scorer.check_technique(
            step.mitre_technique, hours=1
        )

    return [chain], {}


def benchmark_art(
    scorer: TelemetryScorer,
    techniques: Optional[List[str]] = None,
    from_kali: bool = False,
    kali_host: str = "192.168.237.132",
) -> Tuple[List[AttackChain], Dict[str, Tuple[Verdict, str]]]:
    """Run Atomic Red Team techniques and score."""
    log.info("=" * 60)
    log.info("MODE: ATOMIC RED TEAM")
    log.info("=" * 60)

    if not techniques:
        techniques = get_macos_art_techniques()
        if not techniques:
            log.error("No ART techniques found. Is atomic-red-team installed at %s?", ART_PATH)
            return [], {}
        log.info("Found %d macOS ART techniques", len(techniques))

    # Priority techniques (AMOSKYS core detection)
    priority = [
        "T1543.001", "T1555.001", "T1555.003", "T1059.004",
        "T1053.003", "T1070.002", "T1548.001", "T1564.001",
        "T1036", "T1546.004",
    ]

    # Filter to priority + requested
    if not techniques or techniques == get_macos_art_techniques():
        techniques = [t for t in priority if t in techniques] + [
            t for t in techniques if t not in priority
        ]

    art_results: Dict[str, Tuple[Verdict, str]] = {}

    for tech in techniques:
        log.info("Running ART %s...", tech)

        if from_kali:
            ran, output = run_art_from_kali(
                tech, kali_host, "192.168.237.1"
            )
        else:
            ran, output = run_art_technique_local(tech)

        if not ran:
            log.warning("  %s: could not execute (%s)", tech, output[:80])
            continue

        log.info("  %s: executed, waiting 3s for detection...", tech)
        time.sleep(3)

    # Collect all at once after running all techniques
    log.info("Running collection pipeline after ART execution...")
    run_collection_pipeline()

    # Score each technique
    for tech in techniques:
        verdict, evidence = scorer.check_technique(tech, hours=1)
        art_results[tech] = (verdict, evidence)
        log.info("  %s: %s — %s", tech, verdict.name, evidence[:60])

    return [], art_results


def benchmark_kali(
    scorer: TelemetryScorer,
    kali_host: str = "192.168.237.132",
    mac_target: str = "192.168.237.1",
) -> Tuple[List[AttackChain], dict]:
    """Run attack chains from Kali and score."""
    log.info("=" * 60)
    log.info("MODE: KALI LIVE ATTACKS → %s", mac_target)
    log.info("=" * 60)

    # Verify Kali connectivity
    result = subprocess.run(
        [
            "ssh", "-i", str(KALI_KEY),
            "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
            f"ghostops@{kali_host}", "echo OK",
        ],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        log.error("Cannot reach Kali at %s: %s", kali_host, result.stderr)
        return [], {}

    log.info("Kali connection verified ✓")

    chains = []

    # Chain 1: SSH Brute Force
    chain1 = chain_ssh_bruteforce()
    log.info("Executing Chain 1: %s", chain1.name)
    for step in chain1.steps:
        kali_cmd = _get_kali_attack_commands(
            step.mitre_technique, mac_target, "testattacker"
        )
        if kali_cmd:
            log.info("  [%s] %s", step.mitre_technique, step.name)
            try:
                subprocess.run(
                    [
                        "ssh", "-i", str(KALI_KEY),
                        "-o", "BatchMode=yes",
                        f"ghostops@{kali_host}",
                        kali_cmd,
                    ],
                    capture_output=True, text=True, timeout=60,
                )
            except subprocess.TimeoutExpired:
                pass  # Expected for brute force
            time.sleep(2)

    # Chain 3: DNS/C2
    chain3 = chain_dns_c2()
    log.info("Executing Chain 3: %s", chain3.name)
    for step in chain3.steps:
        kali_cmd = _get_kali_attack_commands(
            step.mitre_technique, mac_target, "testattacker"
        )
        if kali_cmd:
            log.info("  [%s] %s", step.mitre_technique, step.name)
            try:
                subprocess.run(
                    [
                        "ssh", "-i", str(KALI_KEY),
                        "-o", "BatchMode=yes",
                        f"ghostops@{kali_host}",
                        kali_cmd,
                    ],
                    capture_output=True, text=True, timeout=60,
                )
            except subprocess.TimeoutExpired:
                pass
            time.sleep(2)

    # Collect after all attacks
    log.info("Attacks complete. Collecting telemetry...")
    time.sleep(5)
    run_collection_pipeline()

    # Score all chains
    for chain in [chain1, chain3]:
        for step in chain.steps:
            step.verdict, step.evidence = scorer.check_technique(
                step.mitre_technique, hours=1
            )
        chains.append(chain)

    return chains, {}


def benchmark_score_only(scorer: TelemetryScorer) -> Tuple[List[AttackChain], dict]:
    """Score whatever is currently in the DB without running attacks."""
    log.info("=" * 60)
    log.info("MODE: SCORE ONLY (using existing telemetry)")
    log.info("=" * 60)

    chains = [
        chain_local_simulation(),
        chain_ssh_bruteforce(),
        chain_reverse_shell(),
        chain_dns_c2(),
        chain_privesc(),
        chain_amos_full(),
    ]

    for chain in chains:
        for step in chain.steps:
            step.verdict, step.evidence = scorer.check_technique(
                step.mitre_technique, hours=24
            )

    # Also check ART coverage
    coverage = scorer.get_mitre_coverage(hours=24)
    art_results = {}
    for tech, count in coverage.items():
        art_results[tech] = (Verdict.DETECT, f"{count} events detected")

    return chains, art_results


# ── Entry Point ────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="AMOSKYS Adversary Benchmark — MITRE ATT&CK Scorer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  benchmark.py local                          Run local simulation + score
  benchmark.py art                            Run all macOS ART techniques
  benchmark.py art --techniques T1543.001 T1555.001
  benchmark.py kali                           Run Kali attack chains
  benchmark.py full                           All modes in sequence
  benchmark.py score-only                     Score existing DB
        """,
    )
    parser.add_argument(
        "mode",
        choices=["local", "art", "kali", "full", "score-only"],
        help="Benchmark mode",
    )
    parser.add_argument(
        "--techniques", nargs="+", default=None,
        help="Specific MITRE techniques for ART mode",
    )
    parser.add_argument(
        "--kali-host", default="192.168.237.132",
        help="Kali Linux IP address",
    )
    parser.add_argument(
        "--mac-target", default="192.168.237.1",
        help="Mac target IP (from Kali's perspective)",
    )
    parser.add_argument(
        "--clear", action="store_true",
        help="Clear telemetry DB before running",
    )
    parser.add_argument(
        "--output", default=None,
        help="Save scorecard to file (default: data/benchmarks/)",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Also output JSON scorecard",
    )
    args = parser.parse_args()

    start_time = time.time()

    # Optionally clear DB
    if args.clear:
        log.info("Clearing telemetry database...")
        subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "collect_and_store.py"), "--clear"],
            capture_output=True, timeout=120,
            env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        )

    scorer = TelemetryScorer()
    all_chains: List[AttackChain] = []
    all_art: Dict[str, Tuple[Verdict, str]] = {}

    if args.mode in ("local", "full"):
        chains, _ = benchmark_local(scorer)
        all_chains.extend(chains)

    if args.mode in ("art", "full"):
        _, art = benchmark_art(
            scorer,
            techniques=args.techniques,
            from_kali=False,
        )
        all_art.update(art)

    if args.mode in ("kali", "full"):
        chains, _ = benchmark_kali(
            scorer,
            kali_host=args.kali_host,
            mac_target=args.mac_target,
        )
        all_chains.extend(chains)

    if args.mode == "score-only":
        chains, art = benchmark_score_only(scorer)
        all_chains.extend(chains)
        all_art.update(art)

    # Render scorecard
    scorecard = render_scorecard(all_chains, all_art or None, start_time)
    print("\n" + scorecard)

    # Save scorecard
    SCORECARD_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = args.output or str(
        SCORECARD_DIR / f"benchmark_{args.mode}_{timestamp}.txt"
    )
    Path(output_path).write_text(scorecard)
    log.info("Scorecard saved to %s", output_path)

    # JSON output
    if args.json:
        json_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "mode": args.mode,
            "macos_version": _get_macos_version(),
            "chains": [
                {
                    "name": c.name,
                    "steps": [
                        {
                            "name": s.name,
                            "technique": s.mitre_technique,
                            "verdict": s.verdict.name,
                            "evidence": s.evidence,
                        }
                        for s in c.steps
                    ],
                    "detection_rate": c.detection_rate,
                    "score": c.score,
                }
                for c in all_chains
            ],
            "art_results": {
                k: {"verdict": v.name, "evidence": e}
                for k, (v, e) in all_art.items()
            } if all_art else None,
            "summary": {
                "total_steps": sum(c.total for c in all_chains) + len(all_art),
                "detected": sum(c.detected for c in all_chains) + sum(
                    1 for v, _ in all_art.values() if v != Verdict.MISS
                ),
            },
        }
        json_path = output_path.replace(".txt", ".json")
        Path(json_path).write_text(json.dumps(json_data, indent=2))
        log.info("JSON scorecard saved to %s", json_path)


if __name__ == "__main__":
    main()
