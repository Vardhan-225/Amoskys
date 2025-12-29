"""
AMOSKYS Advanced Threat Detection Primitives

Implements world-class detection techniques that challenge even the most
sophisticated attackers. This module provides reusable detection functions
used across all agents.

Detection Philosophy:
    - Layered detection (multiple signals required to evade)
    - Behavioral analysis (not just signature matching)
    - Cross-reference validation (verify from multiple sources)
    - Temporal correlation (attacks have patterns over time)
    - Anomaly detection (deviation from baseline is suspicious)

Coverage:
    - MITRE ATT&CK techniques with high-fidelity detection
    - Advanced Persistent Threat (APT) patterns
    - Living-off-the-land techniques (LOLBins)
    - Fileless malware indicators
    - Lateral movement patterns
    - Data exfiltration techniques
"""

import ipaddress
import logging
import os
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class AttackPhase(Enum):
    """Kill chain phases"""

    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class ThreatIndicator:
    """Individual threat indicator"""

    indicator_type: str
    value: str
    confidence: float  # 0.0 - 1.0
    attack_phase: AttackPhase
    mitre_techniques: List[str]
    description: str
    source: str
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.indicator_type,
            "value": self.value,
            "confidence": self.confidence,
            "phase": self.attack_phase.value,
            "mitre": self.mitre_techniques,
            "description": self.description,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ProcessContext:
    """Context for process-based analysis"""

    pid: int
    name: str
    cmdline: str
    exe_path: str
    username: str
    parent_pid: int
    parent_name: str
    parent_cmdline: str
    timestamp: datetime
    network_connections: List[Dict[str, Any]] = field(default_factory=list)
    open_files: List[str] = field(default_factory=list)
    environment: Dict[str, str] = field(default_factory=dict)


@dataclass
class NetworkContext:
    """Context for network-based analysis"""

    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    bytes_in: int
    bytes_out: int
    direction: str
    process_name: Optional[str] = None
    process_pid: Optional[int] = None
    timestamp: datetime = field(default_factory=datetime.now)


class SuspiciousPathDetector:
    """Detect processes running from suspicious locations

    Attackers often execute from world-writable directories or
    locations that bypass security controls.
    """

    # High-risk execution paths
    SUSPICIOUS_PATHS = [
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
        "/.Trash/",
        "/private/tmp/",
        "/Users/*/Downloads/",
        "/Users/*/.local/",
        "/Users/*/Library/Caches/",
        "~/Downloads/",
    ]

    # Known legitimate paths to whitelist
    TRUSTED_PATHS = [
        "/usr/bin/",
        "/usr/sbin/",
        "/bin/",
        "/sbin/",
        "/usr/local/bin/",
        "/Applications/",
        "/System/",
        "/Library/",
    ]

    # Suspicious file extensions for executables
    SUSPICIOUS_EXTENSIONS = [
        ".scpt",  # AppleScript
        ".command",  # Shell command
        ".sh",
        ".py",
        ".rb",
        ".pl",
        ".jar",
    ]

    @classmethod
    def is_suspicious_path(cls, path: str) -> Tuple[bool, str]:
        """Check if path is suspicious

        Args:
            path: Executable path to check

        Returns:
            Tuple of (is_suspicious, reason)
        """
        # Normalize path
        path = os.path.expanduser(path)
        path_lower = path.lower()

        # Check if in trusted location
        for trusted in cls.TRUSTED_PATHS:
            if path.startswith(trusted):
                return False, ""

        # Check suspicious paths
        for suspicious in cls.SUSPICIOUS_PATHS:
            pattern = suspicious.replace("*", ".*")
            if re.match(pattern, path):
                return True, f"Execution from suspicious location: {suspicious}"

        # Check hidden files
        if "/." in path and not path.startswith("/Applications"):
            return True, "Execution from hidden directory"

        # Check suspicious extensions
        for ext in cls.SUSPICIOUS_EXTENSIONS:
            if path_lower.endswith(ext):
                return True, f"Suspicious executable type: {ext}"

        # Check for randomly named executables
        basename = os.path.basename(path)
        if cls._looks_random(basename):
            return True, "Randomly named executable"

        return False, ""

    @staticmethod
    def _looks_random(name: str) -> bool:
        """Check if filename appears randomly generated"""
        # Remove extension
        name = name.split(".")[0]

        if len(name) < 8:
            return False

        # Check for high entropy (random characters)
        if len(set(name)) / len(name) > 0.8:
            # Check if it's a hex string or base64-like
            if re.match(r"^[a-f0-9]{8,}$", name.lower()):
                return True
            if re.match(r"^[a-zA-Z0-9+/=]{8,}$", name):
                return True

        return False


class LOLBinDetector:
    """Detect Living-off-the-Land Binary abuse

    Attackers use legitimate system tools for malicious purposes.
    This detector identifies suspicious usage patterns.
    """

    # macOS LOLBins with suspicious argument patterns
    MACOS_LOLBINS = {
        "osascript": {
            "patterns": [
                r"-e.*do shell script",
                r"-e.*curl|wget|nc",
                r"-e.*base64",
            ],
            "mitre": ["T1059.002"],  # AppleScript
        },
        "curl": {
            "patterns": [
                r"-o\s+/tmp/",
                r"--output\s+/tmp/",
                r"\|.*sh",
                r"\|.*bash",
                r"\|.*python",
                r"file://",
            ],
            "mitre": ["T1105"],  # Ingress Tool Transfer
        },
        "bash": {
            "patterns": [
                r"-c.*curl.*\|",
                r"-c.*base64.*-d",
                r"-c.*eval",
                r"-i.*>&.*/dev/tcp",  # Reverse shell
            ],
            "mitre": ["T1059.004"],  # Unix Shell
        },
        "python": {
            "patterns": [
                r"-c.*import.*socket",
                r"-c.*import.*subprocess",
                r"-c.*base64\.b64decode",
                r"-c.*exec\(",
            ],
            "mitre": ["T1059.006"],  # Python
        },
        "openssl": {
            "patterns": [
                r"s_client.*-connect",  # C2 tunnel
                r"enc.*-d.*-base64",
            ],
            "mitre": ["T1573.002"],  # Encrypted Channel
        },
        "nc": {
            "patterns": [
                r"-e\s*/bin/(ba)?sh",  # Reverse shell
                r"-l.*-p",  # Listener
            ],
            "mitre": ["T1059.004"],
        },
        "dscl": {
            "patterns": [
                r"create.*UserShell",
                r"create.*IsHidden",
                r"create.*UniqueID",
            ],
            "mitre": ["T1136.001"],  # Create Account
        },
        "defaults": {
            "patterns": [
                r"write.*com\.apple\.LaunchServices",
                r"write.*LSHandlers",
            ],
            "mitre": ["T1547.011"],  # Plist Modification
        },
        "launchctl": {
            "patterns": [
                r"load.*-w",
                r"submit.*-p",
            ],
            "mitre": ["T1543.001"],  # Launch Agent
        },
        "security": {
            "patterns": [
                r"find-certificate.*-p",  # Export certs
                r"export.*-f.*pkcs12",
            ],
            "mitre": ["T1552.004"],  # Private Keys
        },
        "sqlite3": {
            "patterns": [
                r".*cookies\.sqlite",
                r".*login\.keychain",
                r".*Chrome.*Login Data",
            ],
            "mitre": ["T1539"],  # Steal Cookies
        },
    }

    @classmethod
    def check_command(
        cls, process_name: str, cmdline: str
    ) -> Optional[ThreatIndicator]:
        """Check if command matches known LOLBin abuse pattern

        Args:
            process_name: Name of the process
            cmdline: Full command line

        Returns:
            ThreatIndicator if suspicious, None otherwise
        """
        process_name_lower = process_name.lower()

        for lolbin, config in cls.MACOS_LOLBINS.items():
            if lolbin in process_name_lower:
                for pattern in config["patterns"]:
                    if re.search(pattern, cmdline, re.IGNORECASE):
                        return ThreatIndicator(
                            indicator_type="lolbin_abuse",
                            value=cmdline[:200],
                            confidence=0.85,
                            attack_phase=AttackPhase.EXECUTION,
                            mitre_techniques=config["mitre"],
                            description=f"Suspicious {lolbin} usage detected",
                            source="lolbin_detector",
                        )

        return None


class ReverseShellDetector:
    """Detect reverse shell establishment attempts

    Reverse shells are a primary method for attackers to gain
    interactive access. This detector identifies various techniques.
    """

    # Patterns that indicate reverse shell
    SHELL_PATTERNS = [
        # Bash reverse shells
        r"bash.*-i.*>&\s*/dev/tcp/",
        r"bash.*-c.*exec.*>&\s*/dev/tcp/",
        # Python reverse shells
        r"python.*socket.*connect.*subprocess",
        r"python.*-c.*import\s+socket.*import\s+subprocess",
        # Perl reverse shells
        r"perl.*socket.*INET.*exec",
        # Ruby reverse shells
        r"ruby.*TCPSocket.*exec",
        # PHP reverse shells
        r"php.*fsockopen.*shell_exec",
        # Netcat reverse shells
        r"nc\s+.*-e\s+/bin/(ba)?sh",
        r"ncat.*-e\s+/bin/(ba)?sh",
        r"mkfifo.*nc.*-l",
        # OpenSSL reverse shells
        r"openssl.*s_client.*-connect.*exec",
    ]

    # Suspicious process ancestry for shells
    SUSPICIOUS_PARENTS = [
        "python",
        "perl",
        "ruby",
        "php",
        "node",
        "java",
    ]

    @classmethod
    def check_cmdline(cls, cmdline: str) -> Optional[ThreatIndicator]:
        """Check command line for reverse shell patterns"""
        for pattern in cls.SHELL_PATTERNS:
            if re.search(pattern, cmdline, re.IGNORECASE):
                return ThreatIndicator(
                    indicator_type="reverse_shell",
                    value=cmdline[:200],
                    confidence=0.95,
                    attack_phase=AttackPhase.EXECUTION,
                    mitre_techniques=["T1059", "T1071.001"],
                    description="Reverse shell command detected",
                    source="reverse_shell_detector",
                )

        return None

    @classmethod
    def check_process_context(cls, ctx: ProcessContext) -> Optional[ThreatIndicator]:
        """Check full process context for reverse shell indicators"""
        # Check command line
        indicator = cls.check_cmdline(ctx.cmdline)
        if indicator:
            return indicator

        # Check for shell with network connection to unusual port
        shell_names = ["bash", "sh", "zsh", "fish"]
        if ctx.name in shell_names:
            for conn in ctx.network_connections:
                port = conn.get("remote_port", 0)
                # Unusual ports for shells
                if port not in [22, 80, 443] and port > 0:
                    return ThreatIndicator(
                        indicator_type="suspicious_shell_network",
                        value=f"{ctx.name} -> {conn.get('remote_ip')}:{port}",
                        confidence=0.75,
                        attack_phase=AttackPhase.COMMAND_AND_CONTROL,
                        mitre_techniques=["T1071.001"],
                        description="Shell process with suspicious network connection",
                        source="reverse_shell_detector",
                    )

        return None


class PersistenceDetector:
    """Detect persistence mechanism installation

    Attackers install persistence to maintain access after reboot.
    This detector identifies persistence techniques in real-time.
    """

    # macOS persistence locations
    PERSISTENCE_PATHS = {
        # Launch Agents
        "/Library/LaunchAgents/": ("launch_agent", ["T1543.001"]),
        "~/Library/LaunchAgents/": ("launch_agent", ["T1543.001"]),
        # Launch Daemons
        "/Library/LaunchDaemons/": ("launch_daemon", ["T1543.004"]),
        # Login Items
        "~/Library/Application Support/com.apple.backgroundtaskmanagementagent/": (
            "login_item",
            ["T1547.015"],
        ),
        # Cron
        "/var/at/tabs/": ("cron", ["T1053.003"]),
        "/usr/lib/cron/tabs/": ("cron", ["T1053.003"]),
        # SSH authorized_keys
        "~/.ssh/authorized_keys": ("ssh_key", ["T1098.004"]),
        # Shell profiles
        "~/.bash_profile": ("shell_profile", ["T1546.004"]),
        "~/.bashrc": ("shell_profile", ["T1546.004"]),
        "~/.zshrc": ("shell_profile", ["T1546.004"]),
        "~/.profile": ("shell_profile", ["T1546.004"]),
        # Periodic scripts
        "/etc/periodic/daily/": ("periodic", ["T1053.003"]),
        "/etc/periodic/weekly/": ("periodic", ["T1053.003"]),
        # Emond
        "/etc/emond.d/rules/": ("emond", ["T1546"]),
        # Authorization plugins
        "/Library/Security/SecurityAgentPlugins/": ("auth_plugin", ["T1547.002"]),
    }

    # Suspicious plist keys
    SUSPICIOUS_PLIST_KEYS = [
        "ProgramArguments",  # What it runs
        "Program",
        "RunAtLoad",
        "KeepAlive",
        "WatchPaths",
        "StartOnMount",
    ]

    @classmethod
    def check_file_write(
        cls, file_path: str, content: Optional[bytes] = None
    ) -> Optional[ThreatIndicator]:
        """Check if a file write is suspicious persistence installation

        Args:
            file_path: Path being written to
            content: Optional file content

        Returns:
            ThreatIndicator if persistence detected
        """
        file_path = os.path.expanduser(file_path)

        for persist_path, (persist_type, techniques) in cls.PERSISTENCE_PATHS.items():
            persist_path = os.path.expanduser(persist_path)

            if file_path.startswith(persist_path) or file_path == persist_path:
                confidence = 0.80

                # Increase confidence if file content is suspicious
                if content:
                    content_str = content.decode("utf-8", errors="ignore")
                    if any(key in content_str for key in cls.SUSPICIOUS_PLIST_KEYS):
                        confidence = 0.90
                    if "/tmp/" in content_str or "curl" in content_str:
                        confidence = 0.95

                return ThreatIndicator(
                    indicator_type=f"persistence_{persist_type}",
                    value=file_path,
                    confidence=confidence,
                    attack_phase=AttackPhase.PERSISTENCE,
                    mitre_techniques=techniques,
                    description=f"Persistence mechanism installed: {persist_type}",
                    source="persistence_detector",
                )

        return None


class C2Detector:
    """Detect Command and Control (C2) communication

    C2 detection through behavioral analysis, not just IoC matching.
    """

    # Suspicious port numbers often used for C2
    C2_PORTS = {
        4444: "Metasploit default",
        5555: "Android debug / common C2",
        6666: "Common C2",
        6667: "IRC-based C2",
        8080: "HTTP alt (may be legitimate)",
        8443: "HTTPS alt",
        8888: "Common C2",
        9999: "Common C2",
        31337: "Elite/backdoor",
        1337: "Elite",
        12345: "NetBus",
        54321: "Common C2",
    }

    # DNS patterns that indicate C2
    C2_DNS_PATTERNS = [
        r"^[a-z0-9]{16,}\.[a-z]{2,4}$",  # Random subdomain
        r"^[a-z0-9-]{32,}\.",  # Very long subdomain (data exfil)
        r"\.(pw|tk|ml|ga|cf|gq)$",  # Free TLDs often used for C2
        r"^.*\.duckdns\.org$",  # Dynamic DNS
        r"^.*\.ngrok\.io$",  # Tunneling service
    ]

    # Beaconing detection parameters
    BEACON_VARIANCE_THRESHOLD = 0.15  # 15% variance indicates beaconing
    MIN_BEACON_SAMPLES = 5

    @classmethod
    def check_connection(cls, conn: NetworkContext) -> Optional[ThreatIndicator]:
        """Check individual connection for C2 indicators"""
        indicators = []
        confidence = 0.0

        # Check for known C2 ports
        if conn.dst_port in cls.C2_PORTS:
            reason = cls.C2_PORTS[conn.dst_port]
            indicators.append(f"C2 port {conn.dst_port}: {reason}")
            confidence += 0.3

        # Check for internal IP connecting to external on unusual port
        try:
            src = ipaddress.ip_address(conn.src_ip)
            dst = ipaddress.ip_address(conn.dst_ip)

            if src.is_private and not dst.is_private:
                # Outbound connection
                if conn.dst_port not in [80, 443, 22, 53, 25, 587, 993, 995]:
                    indicators.append(f"Unusual outbound port: {conn.dst_port}")
                    confidence += 0.2
        except ValueError:
            pass

        # Check data ratio (C2 often has more outbound)
        if conn.bytes_out > 0 and conn.bytes_in > 0:
            ratio = conn.bytes_out / conn.bytes_in
            if ratio > 10:  # 10x more outbound suggests exfiltration
                indicators.append(f"High outbound ratio: {ratio:.1f}")
                confidence += 0.3

        if confidence >= 0.5 and indicators:
            return ThreatIndicator(
                indicator_type="c2_connection",
                value=f"{conn.dst_ip}:{conn.dst_port}",
                confidence=min(confidence, 0.95),
                attack_phase=AttackPhase.COMMAND_AND_CONTROL,
                mitre_techniques=["T1071"],
                description="; ".join(indicators),
                source="c2_detector",
            )

        return None

    @classmethod
    def detect_beaconing(
        cls, connections: List[NetworkContext], destination: str
    ) -> Optional[ThreatIndicator]:
        """Detect beaconing behavior to a specific destination

        Beaconing is characterized by regular intervals between connections.

        Args:
            connections: List of connections to the destination
            destination: IP:port string

        Returns:
            ThreatIndicator if beaconing detected
        """
        if len(connections) < cls.MIN_BEACON_SAMPLES:
            return None

        # Sort by timestamp
        sorted_conns = sorted(connections, key=lambda c: c.timestamp)

        # Calculate intervals
        intervals = []
        for i in range(1, len(sorted_conns)):
            delta = (
                sorted_conns[i].timestamp - sorted_conns[i - 1].timestamp
            ).total_seconds()
            if delta > 0:
                intervals.append(delta)

        if not intervals:
            return None

        # Calculate statistics
        mean_interval = sum(intervals) / len(intervals)
        if mean_interval == 0:
            return None

        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = variance**0.5
        coefficient_of_variation = std_dev / mean_interval

        # Low variance = beaconing
        if coefficient_of_variation < cls.BEACON_VARIANCE_THRESHOLD:
            return ThreatIndicator(
                indicator_type="beaconing",
                value=f"{destination} (interval: {mean_interval:.0f}s, CV: {coefficient_of_variation:.2f})",
                confidence=0.85,
                attack_phase=AttackPhase.COMMAND_AND_CONTROL,
                mitre_techniques=["T1071", "T1573"],
                description=f"Regular beaconing detected: ~{mean_interval:.0f}s intervals",
                source="c2_detector",
            )

        return None


class CredentialAccessDetector:
    """Detect credential theft and access attempts

    Identifies attempts to access credential stores, keychain,
    browser passwords, SSH keys, etc.
    """

    # Credential files and paths
    CREDENTIAL_PATHS = {
        # macOS Keychain
        "~/Library/Keychains/": ("keychain", ["T1555.001"]),
        "/Library/Keychains/": ("keychain", ["T1555.001"]),
        # SSH Keys
        "~/.ssh/id_rsa": ("ssh_key", ["T1552.004"]),
        "~/.ssh/id_ed25519": ("ssh_key", ["T1552.004"]),
        "~/.ssh/id_ecdsa": ("ssh_key", ["T1552.004"]),
        # AWS credentials
        "~/.aws/credentials": ("cloud_cred", ["T1552.001"]),
        # Browser data
        "~/Library/Application Support/Google/Chrome/Default/Login Data": (
            "browser_cred",
            ["T1555.003"],
        ),
        "~/Library/Application Support/Firefox/Profiles/*/logins.json": (
            "browser_cred",
            ["T1555.003"],
        ),
        "~/Library/Safari/": ("browser_cred", ["T1555.003"]),
        # Password manager files
        "*.kdbx": ("password_manager", ["T1555"]),
        "*.1password": ("password_manager", ["T1555"]),
    }

    # Suspicious commands for credential access
    CRED_ACCESS_COMMANDS = [
        r"security\s+find-(generic|internet)-password",
        r"security\s+dump-keychain",
        r"security\s+export",
        r"sqlite3.*Login\s+Data",
        r"sqlite3.*cookies",
        r"cat\s+.*id_rsa",
        r"cp\s+.*id_rsa",
        r"scp\s+.*id_rsa",
        r"base64.*id_rsa",
    ]

    @classmethod
    def check_file_access(
        cls, file_path: str, operation: str = "read"
    ) -> Optional[ThreatIndicator]:
        """Check if file access is credential theft attempt"""
        file_path = os.path.expanduser(file_path)

        for pattern, (cred_type, techniques) in cls.CREDENTIAL_PATHS.items():
            pattern_expanded = os.path.expanduser(pattern)

            # Handle wildcards
            if "*" in pattern_expanded:
                regex = pattern_expanded.replace("*", ".*")
                if re.match(regex, file_path):
                    return cls._make_indicator(
                        file_path, cred_type, techniques, operation
                    )
            elif (
                file_path.startswith(pattern_expanded) or file_path == pattern_expanded
            ):
                return cls._make_indicator(file_path, cred_type, techniques, operation)

        return None

    @classmethod
    def _make_indicator(
        cls, path: str, cred_type: str, techniques: List[str], operation: str
    ) -> ThreatIndicator:
        return ThreatIndicator(
            indicator_type=f"credential_access_{cred_type}",
            value=path,
            confidence=0.80 if operation == "read" else 0.90,
            attack_phase=AttackPhase.CREDENTIAL_ACCESS,
            mitre_techniques=techniques,
            description=f"Credential {operation} detected: {cred_type}",
            source="credential_detector",
        )

    @classmethod
    def check_command(cls, cmdline: str) -> Optional[ThreatIndicator]:
        """Check if command is credential access attempt"""
        for pattern in cls.CRED_ACCESS_COMMANDS:
            if re.search(pattern, cmdline, re.IGNORECASE):
                return ThreatIndicator(
                    indicator_type="credential_access_command",
                    value=cmdline[:200],
                    confidence=0.85,
                    attack_phase=AttackPhase.CREDENTIAL_ACCESS,
                    mitre_techniques=["T1555"],
                    description="Credential access command detected",
                    source="credential_detector",
                )

        return None


class ExfiltrationDetector:
    """Detect data exfiltration attempts

    Identifies various exfiltration techniques including:
    - Large file transfers to external hosts
    - DNS exfiltration
    - Encoded data transfer
    - Archive creation before transfer
    """

    # Archive tools that might be used for staging
    ARCHIVE_COMMANDS = [
        "zip",
        "tar",
        "gzip",
        "bzip2",
        "7z",
        "rar",
        "ditto",
        "hdiutil",
    ]

    # Exfiltration channels
    EXFIL_COMMANDS = [
        r"curl.*-d\s*@",  # POST file
        r"curl.*--data-binary",
        r"curl.*(dropbox|pastebin|transfer\.sh|file\.io)",
        r"scp\s+.*@.*:",  # SCP to remote
        r"rsync.*@.*:",
        r"base64.*\|\s*curl",  # Encoded exfil
        r"openssl\s+base64.*\|",
    ]

    # Volume thresholds
    EXFIL_THRESHOLD_BYTES = 100 * 1024 * 1024  # 100MB
    EXFIL_RATE_THRESHOLD = 10 * 1024 * 1024  # 10MB/s sustained

    @classmethod
    def check_command(cls, cmdline: str) -> Optional[ThreatIndicator]:
        """Check if command indicates data exfiltration"""
        # Check for archive creation of sensitive directories
        for archive_cmd in cls.ARCHIVE_COMMANDS:
            if archive_cmd in cmdline:
                sensitive = ["Documents", "Desktop", ".ssh", "Keychains"]
                if any(s in cmdline for s in sensitive):
                    return ThreatIndicator(
                        indicator_type="exfil_staging",
                        value=cmdline[:200],
                        confidence=0.75,
                        attack_phase=AttackPhase.COLLECTION,
                        mitre_techniques=["T1560.001"],
                        description="Sensitive data being archived",
                        source="exfil_detector",
                    )

        # Check for exfiltration commands
        for pattern in cls.EXFIL_COMMANDS:
            if re.search(pattern, cmdline, re.IGNORECASE):
                return ThreatIndicator(
                    indicator_type="data_exfiltration",
                    value=cmdline[:200],
                    confidence=0.85,
                    attack_phase=AttackPhase.EXFILTRATION,
                    mitre_techniques=["T1048"],
                    description="Data exfiltration command detected",
                    source="exfil_detector",
                )

        return None

    @classmethod
    def check_network_volume(
        cls, connections: List[NetworkContext], time_window_seconds: int = 300
    ) -> Optional[ThreatIndicator]:
        """Check for large volume data exfiltration"""
        # Group by destination
        dest_bytes: Dict[str, int] = {}

        now = datetime.now()
        for conn in connections:
            if (now - conn.timestamp).total_seconds() > time_window_seconds:
                continue

            dest = f"{conn.dst_ip}:{conn.dst_port}"
            dest_bytes[dest] = dest_bytes.get(dest, 0) + conn.bytes_out

        # Check thresholds
        for dest, total_bytes in dest_bytes.items():
            if total_bytes > cls.EXFIL_THRESHOLD_BYTES:
                mb = total_bytes / (1024 * 1024)
                return ThreatIndicator(
                    indicator_type="large_data_transfer",
                    value=f"{dest} ({mb:.1f}MB)",
                    confidence=0.80,
                    attack_phase=AttackPhase.EXFILTRATION,
                    mitre_techniques=["T1048"],
                    description=f"Large outbound transfer: {mb:.1f}MB to {dest}",
                    source="exfil_detector",
                )

        return None


class ThreatAnalyzer:
    """Main threat analysis engine

    Orchestrates all detectors and provides unified threat analysis.
    """

    def __init__(self):
        self.indicators: List[ThreatIndicator] = []
        self._lock = threading.Lock()

    def analyze_process(self, ctx: ProcessContext) -> List[ThreatIndicator]:
        """Analyze a process for threats"""
        found = []

        # Check suspicious path
        is_suspicious, reason = SuspiciousPathDetector.is_suspicious_path(ctx.exe_path)
        if is_suspicious:
            found.append(
                ThreatIndicator(
                    indicator_type="suspicious_path",
                    value=ctx.exe_path,
                    confidence=0.70,
                    attack_phase=AttackPhase.EXECUTION,
                    mitre_techniques=["T1059"],
                    description=reason,
                    source="path_detector",
                )
            )

        # Check LOLBin abuse
        indicator = LOLBinDetector.check_command(ctx.name, ctx.cmdline)
        if indicator:
            found.append(indicator)

        # Check reverse shell
        indicator = ReverseShellDetector.check_process_context(ctx)
        if indicator:
            found.append(indicator)

        # Check credential access
        indicator = CredentialAccessDetector.check_command(ctx.cmdline)
        if indicator:
            found.append(indicator)

        # Check exfiltration
        indicator = ExfiltrationDetector.check_command(ctx.cmdline)
        if indicator:
            found.append(indicator)

        # Store indicators
        with self._lock:
            self.indicators.extend(found)

        return found

    def analyze_network(self, conn: NetworkContext) -> List[ThreatIndicator]:
        """Analyze a network connection for threats"""
        found = []

        # Check C2 indicators
        indicator = C2Detector.check_connection(conn)
        if indicator:
            found.append(indicator)

        with self._lock:
            self.indicators.extend(found)

        return found

    def analyze_file_operation(
        self, file_path: str, operation: str, content: Optional[bytes] = None
    ) -> List[ThreatIndicator]:
        """Analyze file operations for threats"""
        found = []

        # Check persistence
        if operation in ["write", "create"]:
            indicator = PersistenceDetector.check_file_write(file_path, content)
            if indicator:
                found.append(indicator)

        # Check credential access
        if operation in ["read", "open"]:
            indicator = CredentialAccessDetector.check_file_access(file_path, operation)
            if indicator:
                found.append(indicator)

        with self._lock:
            self.indicators.extend(found)

        return found

    def get_threat_summary(self) -> Dict[str, Any]:
        """Get summary of detected threats"""
        with self._lock:
            by_phase = {}
            by_type = {}

            for ind in self.indicators:
                phase = ind.attack_phase.value
                by_phase[phase] = by_phase.get(phase, 0) + 1
                by_type[ind.indicator_type] = by_type.get(ind.indicator_type, 0) + 1

            # Calculate overall threat level
            total = len(self.indicators)
            high_confidence = sum(1 for i in self.indicators if i.confidence > 0.8)

            if high_confidence >= 5 or total >= 10:
                threat_level = "CRITICAL"
            elif high_confidence >= 3 or total >= 5:
                threat_level = "HIGH"
            elif high_confidence >= 1 or total >= 3:
                threat_level = "MEDIUM"
            elif total > 0:
                threat_level = "LOW"
            else:
                threat_level = "NONE"

            return {
                "threat_level": threat_level,
                "total_indicators": total,
                "high_confidence_count": high_confidence,
                "by_attack_phase": by_phase,
                "by_indicator_type": by_type,
                "recent_indicators": [i.to_dict() for i in self.indicators[-10:]],
            }

    def clear_indicators(self):
        """Clear stored indicators"""
        with self._lock:
            self.indicators.clear()


# Export all for easy importing
__all__ = [
    "AttackPhase",
    "ThreatIndicator",
    "ProcessContext",
    "NetworkContext",
    "SuspiciousPathDetector",
    "LOLBinDetector",
    "ReverseShellDetector",
    "PersistenceDetector",
    "C2Detector",
    "CredentialAccessDetector",
    "ExfiltrationDetector",
    "ThreatAnalyzer",
]
