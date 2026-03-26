"""macOS InfostealerGuard Collector — credential theft detection via lsof + psutil.

Detects the AMOS/Poseidon/Banshee infostealer kill chain on macOS by monitoring:

    1. Sensitive file access — lsof +D on keychain, browser credential stores,
       crypto wallets, messaging apps. Filters against expected accessor sets.
    2. Suspicious processes — osascript fake dialogs, security CLI keychain
       extraction, credential archiving (zip/tar/ditto), clipboard harvest,
       screen capture abuse.
    3. Per-PID network connections — lsof -i -n -P for exfiltration correlation.

The collector is PURE DATA. It never makes severity decisions — that is the
exclusive responsibility of the 10 detection probes.

Data flow:
    collector.collect() -> Dict with:
        sensitive_accesses: List[SensitiveFileAccess]
        suspicious_processes: List[SuspiciousProcess]
        pid_connections: Dict[int, List[PIDConnection]]
        process_snapshot: List[dict]
        access_count: int
        collection_time_ms: float
"""

from __future__ import annotations

import glob as _glob
import hashlib
import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logger.error("psutil not installed — infostealer collector cannot function")


# =============================================================================
# Data classes
# =============================================================================


@dataclass
class SensitiveFileAccess:
    """A non-expected process accessing a sensitive credential file."""

    pid: int
    process_name: str
    file_path: str
    access_category: str  # keychain, chrome_creds, chrome_cookies, firefox_creds,
    # safari, safari_cookies, brave_creds, edge_creds,
    # crypto_exodus, crypto_electrum, crypto_atomic,
    # ssh_keys, notes, telegram, discord
    process_guid: str  # f"{device_id}:{pid}:{create_time_hash}"


@dataclass
class SuspiciousProcess:
    """A process matching an infostealer behavioral pattern."""

    pid: int
    name: str
    exe: str
    cmdline: List[str]
    ppid: int
    parent_name: str
    category: str  # fake_dialog, keychain_cli, credential_archive,
    # clipboard_harvest, screen_capture
    process_guid: str


@dataclass
class PIDConnection:
    """A network connection associated with a specific PID."""

    pid: int
    process_name: str
    remote_ip: str
    remote_port: int
    protocol: str
    state: str


# =============================================================================
# Sensitive paths — the real AMOS stealer targets
# =============================================================================

_SENSITIVE_DIRS: Dict[str, List[str]] = {
    "keychain": [os.path.expanduser("~/Library/Keychains/")],
    "chrome_creds": [
        os.path.expanduser("~/Library/Application Support/Google/Chrome/Default/")
    ],
    "chrome_cookies": [
        os.path.expanduser("~/Library/Application Support/Google/Chrome/Default/")
    ],
    "firefox_creds": [],  # use glob for profiles
    "safari": [os.path.expanduser("~/Library/Safari/")],
    "brave_creds": [
        os.path.expanduser(
            "~/Library/Application Support/BraveSoftware/Brave-Browser/Default/"
        )
    ],
    "edge_creds": [
        os.path.expanduser("~/Library/Application Support/Microsoft Edge/Default/")
    ],
    "crypto_exodus": [os.path.expanduser("~/Library/Application Support/Exodus/")],
    "crypto_electrum": [os.path.expanduser("~/Library/Application Support/Electrum/")],
    "crypto_atomic": [os.path.expanduser("~/Library/Application Support/atomic/")],
    "ssh_keys": [os.path.expanduser("~/.ssh/")],
    "safari_cookies": [os.path.expanduser("~/Library/Cookies/")],
    "notes": [os.path.expanduser("~/Library/Group Containers/group.com.apple.notes/")],
    "telegram": [os.path.expanduser("~/Library/Application Support/Telegram Desktop/")],
    "discord": [os.path.expanduser("~/Library/Application Support/discord/")],
}

# Sensitive file basenames — for matching lsof output lines
_SENSITIVE_FILES: Dict[str, str] = {
    "login.keychain-db": "keychain",
    "Login Data": "chrome_creds",  # Also brave_creds, edge_creds
    "Cookies": "chrome_cookies",
    "logins.json": "firefox_creds",
    "key4.db": "firefox_creds",
    "History.db": "safari",
    "Bookmarks.plist": "safari",
    "Cookies.binarycookies": "safari_cookies",
    "id_rsa": "ssh_keys",
    "id_ed25519": "ssh_keys",
    "id_ecdsa": "ssh_keys",
    "id_dsa": "ssh_keys",
}

# Expected benign processes for each category
_APPLE_PROC_PREFIX = "com.apple"

_EXPECTED_ACCESSORS: Dict[str, Set[str]] = {
    "keychain": {
        "loginwindow",
        "SecurityAgent",
        "security",
        "securityd",
        "authorizationhost",
        "secd",
        # Apple system processes that legitimately access Keychain
        "TrustedPeersHelper",
        "TrustedPe",  # Truncated by lsof/psutil
        "nsurlsessiond",
        _APPLE_PROC_PREFIX,  # Truncated com.apple.* process names
        "authd",
        "accountsd",
        "CloudKeychainProxy",
        "kcm",  # Keychain circle manager
    },
    "chrome_creds": {"Google Chrome", "Google Chrome Helper", "chrome"},
    "chrome_cookies": {"Google Chrome", "Google Chrome Helper", "chrome"},
    "firefox_creds": {"firefox", "Firefox"},
    "safari": {
        "Safari",
        "SafariServices",
        "com.apple.Safari",
        # Apple system processes that legitimately access Safari data
        "SafariBookmarksSyncAgent",
        "SafariBoo",  # Truncated by lsof/psutil
        "com.apple.Safari.SafeBrowsing",
        _APPLE_PROC_PREFIX,  # Truncated com.apple.* names
        "nsurlsessiond",
        "SafariLaunchAgent",
    },
    "brave_creds": {"Brave Browser", "brave"},
    "edge_creds": {"Microsoft Edge", "msedge"},
    "crypto_exodus": {"Exodus"},
    "crypto_electrum": {"Electrum"},
    "crypto_atomic": {"atomic"},
    "ssh_keys": {
        "ssh",
        "ssh-agent",
        "ssh-keygen",
        "ssh-add",
        "sshd",
        "git",
        "Git",
        "GitHub Desktop",
        "com.apple.Terminal",
        "iTerm2",
    },
    "safari_cookies": {
        "Safari",
        "SafariServices",
        "com.apple.Safari",
        _APPLE_PROC_PREFIX,
        "nsurlsessiond",
        "cfprefsd",
    },
    "notes": {"com.apple.Notes", "Notes"},
    "telegram": {"Telegram", "Telegram Desktop"},
    "discord": {"Discord", "discord"},
}

# Fake dialog detection patterns — osascript + password prompt keywords
_DIALOG_KEYWORDS = re.compile(
    r"(password|credential|passphrase|authenticate|login)",
    re.IGNORECASE,
)


# =============================================================================
# Helper functions
# =============================================================================


def _make_guid(device_id: str, pid: int, create_time: float) -> str:
    """Stable process GUID surviving PID recycling."""
    raw = f"{device_id}:{pid}:{int(create_time * 1e9)}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _get_hostname() -> str:
    """Get hostname for device_id."""
    import socket

    return socket.gethostname()


def _get_firefox_profile_dirs() -> List[str]:
    """Discover Firefox profile directories via glob."""
    pattern = os.path.expanduser("~/Library/Application Support/Firefox/Profiles/*/")
    return _glob.glob(pattern)


def _run_lsof_dir(directory: str, timeout: float = 5.0) -> str:
    """Run lsof +D <directory> with timeout. Returns stdout or empty string."""
    try:
        result = subprocess.run(
            ["lsof", "+D", directory],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        logger.warning("lsof +D timed out for %s", directory)
        return ""
    except Exception as e:
        logger.debug("lsof +D failed for %s: %s", directory, e)
        return ""


def _run_lsof_network(timeout: float = 5.0) -> str:
    """Run lsof -i -n -P for network connections. Returns stdout."""
    try:
        result = subprocess.run(
            ["lsof", "-i", "-n", "-P"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        logger.warning("lsof -i -n -P timed out")
        return ""
    except Exception as e:
        logger.debug("lsof -i failed: %s", e)
        return ""


def _parse_lsof_lines(
    output: str, category: str, expected: Set[str]
) -> List[SensitiveFileAccess]:
    """Parse lsof output, filter benign accessors, return suspicious accesses.

    lsof output format:
        COMMAND  PID  USER  FD  TYPE  DEVICE  SIZE/OFF  NODE  NAME
    """
    accesses: List[SensitiveFileAccess] = []
    lines = output.strip().split("\n")

    for line in lines[1:]:  # skip header
        parts = line.split()
        if len(parts) < 9:
            continue

        process_name = parts[0]
        try:
            pid = int(parts[1])
        except (ValueError, IndexError):
            continue

        # Resolve full process name — lsof COMMAND column is truncated on macOS
        # (e.g. com.apple.Safari.SafeBrowsingAgent → com.apple). Use psutil
        # to get the real name while the process is still alive.
        if PSUTIL_AVAILABLE:
            try:
                process_name = psutil.Process(pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass  # keep lsof-truncated name as fallback

        # Reconstruct file path (NAME field may contain spaces)
        file_path = " ".join(parts[8:])

        # Skip expected/benign accessors.
        # Exact match first; then treat "com.apple" sentinel as a prefix
        # wildcard covering all Apple system process names.
        if process_name in expected:
            continue
        if _APPLE_PROC_PREFIX in expected and process_name.startswith(
            f"{_APPLE_PROC_PREFIX}."
        ):
            continue

        # Build a basic GUID (no create_time from lsof — use PID hash)
        guid = hashlib.sha256(f"lsof:{pid}:{process_name}".encode()).hexdigest()[:16]

        accesses.append(
            SensitiveFileAccess(
                pid=pid,
                process_name=process_name,
                file_path=file_path,
                access_category=category,
                process_guid=guid,
            )
        )

    return accesses


def _parse_lsof_network(output: str) -> Dict[int, List[PIDConnection]]:
    """Parse lsof -i -n -P output into PIDConnection objects grouped by PID.

    lsof -i output format:
        COMMAND  PID  USER  FD  TYPE  DEVICE  SIZE/OFF  NODE  NAME
    NAME for TCP: host:port->remote:port (STATE)
    NAME for UDP: host:port
    """
    connections: Dict[int, List[PIDConnection]] = {}
    lines = output.strip().split("\n")

    for line in lines[1:]:  # skip header
        parts = line.split()
        if len(parts) < 9:
            continue

        process_name = parts[0]
        try:
            pid = int(parts[1])
        except (ValueError, IndexError):
            continue

        protocol = parts[7] if len(parts) > 7 else ""  # NODE field = TCP/UDP
        name_field = " ".join(parts[8:])

        # Parse the NAME field for remote IP and port
        # TCP: 192.168.1.5:54321->93.184.216.34:443 (ESTABLISHED)
        # UDP: *:5353
        remote_ip = ""
        remote_port = 0
        state = ""

        # Extract state from parentheses
        state_match = re.search(r"\((\w+)\)", name_field)
        if state_match:
            state = state_match.group(1)

        # Parse TCP connections with ->
        arrow_match = re.search(r"->(\[?[\da-fA-F.:]+\]?):(\d+)", name_field)
        if arrow_match:
            remote_ip = arrow_match.group(1).strip("[]")
            try:
                remote_port = int(arrow_match.group(2))
            except ValueError:
                continue

            conn = PIDConnection(
                pid=pid,
                process_name=process_name,
                remote_ip=remote_ip,
                remote_port=remote_port,
                protocol=protocol,
                state=state,
            )
            connections.setdefault(pid, []).append(conn)

    return connections


# =============================================================================
# Main Collector
# =============================================================================


class MacOSInfostealerGuardCollector:
    """Collects infostealer-related telemetry from macOS.

    Three data sources:
        1. lsof +D on sensitive directories — credential file access by non-expected processes
        2. psutil process scan — fake dialogs, keychain CLI, credential archiving
        3. lsof -i -n -P — per-PID network connections for exfil correlation

    Returns shared_data dict with keys:
        sensitive_accesses: List[SensitiveFileAccess]
        suspicious_processes: List[SuspiciousProcess]
        pid_connections: Dict[int, List[PIDConnection]]
        process_snapshot: List[dict]
        access_count: int
        collection_time_ms: float
    """

    def __init__(self, device_id: str = "") -> None:
        self.device_id = device_id or _get_hostname()

    def collect(self) -> Dict[str, Any]:
        """Run full infostealer data collection.

        Returns dict for ProbeContext.shared_data.
        """
        start = time.monotonic()

        # Phase 1: Sensitive file access via lsof
        sensitive_accesses = self._collect_sensitive_accesses()

        # Phase 2: Suspicious processes via psutil
        suspicious_processes, process_snapshot = self._collect_suspicious_processes()

        # Phase 3: Network connections via lsof -i
        pid_connections = self._collect_pid_connections()

        # Phase 4: Staging archive scan (credential archiving evidence)
        staging_archives = self._collect_staging_archives()

        elapsed_ms = (time.monotonic() - start) * 1000

        return {
            "sensitive_accesses": sensitive_accesses,
            "suspicious_processes": suspicious_processes,
            "pid_connections": pid_connections,
            "process_snapshot": process_snapshot,
            "staging_archives": staging_archives,
            "access_count": len(sensitive_accesses),
            "collection_time_ms": round(elapsed_ms, 2),
        }

    def _collect_sensitive_accesses(self) -> List[SensitiveFileAccess]:
        """Scan sensitive directories for non-expected file accessors."""
        all_accesses: List[SensitiveFileAccess] = []

        # Build the directory list including Firefox profile discovery
        dirs_to_scan: Dict[str, List[str]] = dict(_SENSITIVE_DIRS)
        firefox_profiles = _get_firefox_profile_dirs()
        if firefox_profiles:
            dirs_to_scan["firefox_creds"] = firefox_profiles

        for category, directories in dirs_to_scan.items():
            expected = _EXPECTED_ACCESSORS.get(category, set())

            for directory in directories:
                if not os.path.isdir(directory):
                    continue

                output = _run_lsof_dir(directory, timeout=5.0)
                if not output:
                    continue

                accesses = _parse_lsof_lines(output, category, expected)

                # For chrome_creds/chrome_cookies sharing the same dir,
                # refine category based on the actual file accessed
                for access in accesses:
                    basename = os.path.basename(access.file_path)
                    if basename in _SENSITIVE_FILES:
                        access.access_category = _SENSITIVE_FILES[basename]

                all_accesses.extend(accesses)

        return all_accesses

    def _collect_suspicious_processes(
        self,
    ) -> Tuple[List[SuspiciousProcess], List[dict]]:
        """Scan running processes for infostealer behavioral patterns.

        Returns (suspicious_processes, process_snapshot) where process_snapshot
        is a minimal dict list for clipboard/screencapture probes.
        """
        suspicious: List[SuspiciousProcess] = []
        snapshot: List[dict] = []

        if not PSUTIL_AVAILABLE:
            return suspicious, snapshot

        # Build a flat set of all sensitive path prefixes for archive detection
        sensitive_path_prefixes = set()
        for dirs in _SENSITIVE_DIRS.values():
            for d in dirs:
                sensitive_path_prefixes.add(d)

        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "ppid"]):
            try:
                info = proc.info
                pid = info["pid"]
                name = info.get("name") or ""
                exe = info.get("exe") or ""
                cmdline = info.get("cmdline") or []
                ppid = info.get("ppid") or 0

                # Get parent name — best effort
                parent_name = ""
                if ppid:
                    try:
                        parent_name = psutil.Process(ppid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                # Build process GUID
                try:
                    create_time = proc.create_time()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    create_time = 0.0
                guid = _make_guid(self.device_id, pid, create_time)

                # Minimal snapshot for clipboard/screencapture probes
                snapshot.append(
                    {
                        "pid": pid,
                        "name": name,
                        "exe": exe,
                        "cmdline": cmdline,
                        "ppid": ppid,
                        "parent_name": parent_name,
                        "process_guid": guid,
                    }
                )

                cmdline_str = " ".join(cmdline) if cmdline else ""
                name_lower = name.lower()

                # --- Detection 1: Fake password dialog (osascript) ---
                if name_lower == "osascript" and "display dialog" in cmdline_str:
                    if _DIALOG_KEYWORDS.search(cmdline_str):
                        suspicious.append(
                            SuspiciousProcess(
                                pid=pid,
                                name=name,
                                exe=exe,
                                cmdline=cmdline,
                                ppid=ppid,
                                parent_name=parent_name,
                                category="fake_dialog",
                                process_guid=guid,
                            )
                        )
                        continue

                # --- Detection 2: Keychain CLI extraction ---
                if name_lower == "security":
                    if (
                        "find-generic-password" in cmdline_str
                        or "find-internet-password" in cmdline_str
                    ):
                        suspicious.append(
                            SuspiciousProcess(
                                pid=pid,
                                name=name,
                                exe=exe,
                                cmdline=cmdline,
                                ppid=ppid,
                                parent_name=parent_name,
                                category="keychain_cli",
                                process_guid=guid,
                            )
                        )
                        continue

                # --- Detection 3: Credential archiving ---
                if name_lower in ("zip", "tar", "ditto"):
                    if any(
                        prefix in cmdline_str
                        for prefix in sensitive_path_prefixes
                        if prefix  # skip empty strings
                    ):
                        suspicious.append(
                            SuspiciousProcess(
                                pid=pid,
                                name=name,
                                exe=exe,
                                cmdline=cmdline,
                                ppid=ppid,
                                parent_name=parent_name,
                                category="credential_archive",
                                process_guid=guid,
                            )
                        )
                        continue

                # --- Detection 4: Clipboard harvest ---
                if name_lower in ("pbcopy", "pbpaste"):
                    suspicious.append(
                        SuspiciousProcess(
                            pid=pid,
                            name=name,
                            exe=exe,
                            cmdline=cmdline,
                            ppid=ppid,
                            parent_name=parent_name,
                            category="clipboard_harvest",
                            process_guid=guid,
                        )
                    )
                    continue

                # --- Detection 5: Screen capture abuse ---
                if name_lower == "screencapture":
                    suspicious.append(
                        SuspiciousProcess(
                            pid=pid,
                            name=name,
                            exe=exe,
                            cmdline=cmdline,
                            ppid=ppid,
                            parent_name=parent_name,
                            category="screen_capture",
                            process_guid=guid,
                        )
                    )
                    continue

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return suspicious, snapshot

    def _collect_staging_archives(self) -> List[Dict[str, Any]]:
        """Scan staging locations for archive files containing credential data.

        Real infostealers (AMOS, Poseidon) archive stolen credentials into
        /tmp before exfiltration. The archiver process (zip/tar/ditto) runs
        in <1 second — too fast for psutil polling. But the OUTPUT archive
        file persists. This method finds recent archives in staging dirs and
        inspects their contents for credential-related file paths.
        """
        import tarfile
        import zipfile

        archives: List[Dict[str, Any]] = []
        staging_dirs = ["/tmp", "/private/tmp", "/var/tmp"]
        archive_exts = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2")
        now = time.time()
        cutoff = now - 300  # 5-minute window

        # Sensitive path fragments indicating credential data inside archive
        cred_indicators = (
            "keychain",
            "Keychains",
            "Login Data",
            "Cookies",
            "logins.json",
            "key4.db",
            "wallet",
            "Exodus",
            "Electrum",
            "atomic",
            ".ssh",
            "id_rsa",
            "id_ed25519",
            "credentials",
            "shadow",
        )

        for staging_dir in staging_dirs:
            if not os.path.isdir(staging_dir):
                continue
            try:
                for entry in os.listdir(staging_dir):
                    entry_lower = entry.lower()
                    if not any(entry_lower.endswith(ext) for ext in archive_exts):
                        continue

                    filepath = os.path.join(staging_dir, entry)
                    try:
                        st = os.stat(filepath)
                    except OSError:
                        continue

                    # Only recent files, < 100MB
                    if st.st_mtime < cutoff or st.st_size > 100 * 1024 * 1024:
                        continue

                    # Inspect archive contents for credential data
                    contains_creds = False
                    archive_files: List[str] = []
                    try:
                        if entry_lower.endswith(".zip"):
                            with zipfile.ZipFile(filepath, "r") as zf:
                                archive_files = zf.namelist()[:100]
                        elif any(
                            entry_lower.endswith(e)
                            for e in (".tar", ".tar.gz", ".tgz", ".tar.bz2")
                        ):
                            with tarfile.open(filepath, "r:*") as tf:
                                archive_files = [m.name for m in tf.getmembers()[:100]]
                    except Exception:
                        pass

                    for af in archive_files:
                        if any(ind in af for ind in cred_indicators):
                            contains_creds = True
                            break

                    # Also check the archive filename itself
                    if not contains_creds:
                        for ind in cred_indicators:
                            if ind.lower() in entry_lower:
                                contains_creds = True
                                break

                    if contains_creds:
                        archives.append(
                            {
                                "path": filepath,
                                "filename": entry,
                                "size": st.st_size,
                                "modify_time": st.st_mtime,
                                "staging_dir": staging_dir,
                                "archive_contents_sample": archive_files[:10],
                            }
                        )
            except OSError:
                continue

        return archives

    def _collect_pid_connections(self) -> Dict[int, List[PIDConnection]]:
        """Collect per-PID network connections via lsof -i -n -P."""
        output = _run_lsof_network(timeout=5.0)
        if not output:
            return {}
        return _parse_lsof_network(output)
