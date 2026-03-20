"""Deep Inspection Capabilities — Tier 1 macOS Security Checks.

Four high-impact inspection capabilities that require NO entitlements:

  1. Code Signing Verification — codesign --verify for any binary
  2. TCC Grant Auditing — monitor permission grants via log stream
  3. Keychain Access Detection — security CLI abuse + file access
  4. DYLD Injection Detection — DYLD_* environment variable checks

These run as utility functions callable from any agent's probes.
They feed into the existing scoring/fusion pipeline.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# 1. CODE SIGNING VERIFICATION
# ═══════════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class CodeSignResult:
    """Result of code signing verification for a binary."""

    path: str
    signed: bool
    valid: bool
    identity: str = ""  # "Apple Development: ..." or "com.apple.xxx"
    team_id: str = ""
    hardened_runtime: bool = False
    is_apple: bool = False
    is_adhoc: bool = False  # Signed but no identity
    error: str = ""

    @property
    def trust_level(self) -> str:
        """Classify trust: apple_signed | developer_signed | adhoc | unsigned."""
        if not self.signed:
            return "unsigned"
        if self.is_apple:
            return "apple_signed"
        if self.is_adhoc:
            return "adhoc"
        if self.team_id:
            return "developer_signed"
        return "unknown_signed"

    @property
    def risk_modifier(self) -> float:
        """Risk multiplier based on signing status. <1.0 = lower risk, >1.0 = higher."""
        return {
            "apple_signed": 0.2,
            "developer_signed": 0.5,
            "adhoc": 1.2,
            "unsigned": 1.5,
            "unknown_signed": 0.8,
        }.get(self.trust_level, 1.0)


# Cache to avoid re-checking the same binary
_codesign_cache: Dict[str, CodeSignResult] = {}
_CACHE_MAX = 2000


def verify_code_signing(exe_path: str) -> CodeSignResult:
    """Verify code signing status of a binary.

    Uses `codesign --verify --deep` and `codesign -dvvv` for detailed info.
    Results are cached by path to avoid repeated subprocess calls.

    Covers MITRE: T1036 (Masquerading), T1553 (Subvert Trust Controls)
    """
    if exe_path in _codesign_cache:
        return _codesign_cache[exe_path]

    if not exe_path or not os.path.exists(exe_path):
        result = CodeSignResult(
            path=exe_path, signed=False, valid=False, error="not_found"
        )
        _cache_result(exe_path, result)
        return result

    try:
        # Step 1: Verify signature validity
        verify = subprocess.run(
            ["codesign", "--verify", "--deep", exe_path],
            capture_output=True,
            text=True,
            timeout=5,
        )
        is_valid = verify.returncode == 0
        is_signed = "not signed" not in verify.stderr

        # Step 2: Get signing details
        detail = subprocess.run(
            ["codesign", "-dvvv", exe_path],
            capture_output=True,
            text=True,
            timeout=5,
        )
        detail_text = detail.stderr  # codesign outputs to stderr

        # Parse identity
        identity = ""
        team_id = ""
        is_apple = False
        is_adhoc = False
        hardened = False

        for line in detail_text.splitlines():
            line = line.strip()
            if line.startswith("Authority="):
                val = line.split("=", 1)[1]
                if not identity:
                    identity = val
                if "Apple" in val:
                    is_apple = True
            elif line.startswith("TeamIdentifier="):
                team_id = line.split("=", 1)[1]
                if team_id == "not set":
                    team_id = ""
            elif line.startswith("Identifier="):
                val = line.split("=", 1)[1]
                if not identity:
                    identity = val
            elif "flags=" in line and "runtime" in line:
                hardened = True
            elif "Signature=adhoc" in line:
                is_adhoc = True

        result = CodeSignResult(
            path=exe_path,
            signed=is_signed,
            valid=is_valid,
            identity=identity,
            team_id=team_id,
            hardened_runtime=hardened,
            is_apple=is_apple,
            is_adhoc=is_adhoc,
        )

    except subprocess.TimeoutExpired:
        result = CodeSignResult(
            path=exe_path, signed=False, valid=False, error="timeout"
        )
    except FileNotFoundError:
        result = CodeSignResult(
            path=exe_path, signed=False, valid=False, error="codesign_not_found"
        )
    except Exception as e:
        result = CodeSignResult(path=exe_path, signed=False, valid=False, error=str(e))

    _cache_result(exe_path, result)
    return result


def _cache_result(path: str, result: CodeSignResult) -> None:
    _codesign_cache[path] = result
    if len(_codesign_cache) > _CACHE_MAX:
        # Evict oldest half
        keys = list(_codesign_cache.keys())
        for k in keys[: len(keys) // 2]:
            del _codesign_cache[k]


def batch_verify_processes(processes: List[Dict]) -> List[Dict]:
    """Verify code signing for a batch of processes.

    Args:
        processes: List of dicts with at least 'exe' or 'path' field.

    Returns:
        List of dicts with code signing results appended.
    """
    results = []
    for proc in processes:
        exe = proc.get("exe") or proc.get("path") or ""
        if not exe or exe.startswith("/System/") or exe.startswith("/usr/"):
            # Skip known Apple system paths for performance
            continue

        cs = verify_code_signing(exe)
        if cs.trust_level in ("unsigned", "adhoc"):
            results.append(
                {
                    "pid": proc.get("pid", 0),
                    "name": proc.get("name", ""),
                    "exe": exe,
                    "trust_level": cs.trust_level,
                    "signed": cs.signed,
                    "valid": cs.valid,
                    "identity": cs.identity,
                    "team_id": cs.team_id,
                    "hardened_runtime": cs.hardened_runtime,
                    "risk_modifier": cs.risk_modifier,
                }
            )

    return results


# ═══════════════════════════════════════════════════════════════════════════
# 2. TCC GRANT AUDITING
# ═══════════════════════════════════════════════════════════════════════════

# TCC services that matter for security
TCC_SENSITIVE_SERVICES = frozenset(
    {
        "kTCCServiceAccessibility",  # Input monitoring, keylogging
        "kTCCServiceScreenCapture",  # Screen recording
        "kTCCServiceMicrophone",  # Audio recording
        "kTCCServiceCamera",  # Video recording
        "kTCCServiceSystemPolicyAllFiles",  # Full Disk Access
        "kTCCServiceAddressBook",  # Contact exfiltration
        "kTCCServiceCalendar",  # Calendar data
        "kTCCServiceReminders",  # Reminders data
        "kTCCServicePhotos",  # Photo library
        "kTCCServicePostEvent",  # Input injection
    }
)


def parse_tcc_log_entry(message: str) -> Optional[Dict[str, Any]]:
    """Parse a TCC log message into a structured grant/deny record.

    Returns None if the message isn't a TCC permission event.
    """
    if "com.apple.TCC" not in message and "TCCAccessRequest" not in message:
        return None

    result: Dict[str, Any] = {"raw": message[:300]}

    if "Granting" in message:
        result["action"] = "grant"
        # Extract: "Granting TCCDProcess: identifier=com.foo, pid=123..."
        if "identifier=" in message:
            ident = message.split("identifier=")[1].split(",")[0].strip()
            result["client"] = ident
        if "access to " in message:
            service = message.split("access to ")[1].split(" ")[0].strip()
            result["service"] = service
        if "entitlement" in message:
            result["via"] = "entitlement"
        elif "user" in message.lower():
            result["via"] = "user_approval"
        result["sensitive"] = result.get("service", "") in TCC_SENSITIVE_SERVICES

    elif "REQUEST" in message:
        result["action"] = "request"
        if "sender_pid=" in message:
            try:
                pid = int(message.split("sender_pid=")[1].split(",")[0])
                result["pid"] = pid
            except (ValueError, IndexError):
                pass

    elif "deny" in message.lower() or "DENY" in message:
        result["action"] = "deny"

    else:
        return None

    return result


# ═══════════════════════════════════════════════════════════════════════════
# 3. KEYCHAIN ACCESS DETECTION
# ═══════════════════════════════════════════════════════════════════════════

# Known-safe processes that legitimately access keychain
KEYCHAIN_SAFE_PROCESSES = frozenset(
    {
        "securityd",
        "secd",
        "SecurityAgent",
        "TrustedPeersHelper",
        "accountsd",
        "authd",
        "CloudKeychainProxy",
        "nsurlsessiond",
        "Keychain Access",
        "Safari",
        "Mail",
        "Calendar",
        "com.apple.Safari",
        "com.apple.mail",
    }
)

# Suspicious keychain CLI arguments
KEYCHAIN_THEFT_ARGS = frozenset(
    {
        "find-generic-password",
        "find-internet-password",
        "dump-keychain",
        "export",
        "find-certificate",
    }
)

# Keychain file paths to monitor
KEYCHAIN_PATHS = [
    str(Path.home() / "Library/Keychains"),
    "/Library/Keychains",
]


def check_keychain_cli_abuse(
    cmdline: str, process_name: str = ""
) -> Optional[Dict[str, Any]]:
    """Check if a command line represents keychain credential theft.

    Detects: security find-generic-password, dump-keychain, etc.
    Covers MITRE: T1555.001 (Keychain), T1555.002 (Securityd Memory)
    """
    if "security" not in cmdline:
        return None

    # Check for theft-related arguments
    for arg in KEYCHAIN_THEFT_ARGS:
        if arg in cmdline:
            return {
                "technique": "T1555.001",
                "category": "keychain_theft_attempt",
                "command": cmdline[:200],
                "theft_arg": arg,
                "process_name": process_name,
                "is_safe_process": process_name in KEYCHAIN_SAFE_PROCESSES,
                "risk": 0.3 if process_name in KEYCHAIN_SAFE_PROCESSES else 0.9,
            }

    return None


def check_keychain_file_access(
    path: str, process_name: str = "", pid: int = 0
) -> Optional[Dict[str, Any]]:
    """Check if a file access is targeting keychain databases.

    Covers MITRE: T1555.001 (Keychain)
    """
    path_lower = path.lower()
    if "/keychains/" not in path_lower and "keychain" not in path_lower:
        return None

    # Is this a known-safe process?
    if process_name in KEYCHAIN_SAFE_PROCESSES:
        return None

    return {
        "technique": "T1555.001",
        "category": "keychain_file_access",
        "path": path,
        "process_name": process_name,
        "pid": pid,
        "is_safe_process": False,
        "risk": 0.85,
    }


# ═══════════════════════════════════════════════════════════════════════════
# 4. DYLD INJECTION DETECTION
# ═══════════════════════════════════════════════════════════════════════════

# Dangerous DYLD environment variables
DYLD_INJECTION_VARS = frozenset(
    {
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "DYLD_FORCE_FLAT_NAMESPACE",
    }
)

# Processes known to legitimately use DYLD vars
DYLD_SAFE_PROCESSES = frozenset(
    {
        "ollama",  # Historical — sets DYLD_LIBRARY_PATH for bundled libs
        "Xcode",
        "lldb",
        "instruments",  # Developer tools
        "python3",
        "python3.13",  # May use virtualenv paths
        "ruby",
        "node",  # Interpreters
    }
)


def check_dyld_injection(
    pid: int,
    process_name: str = "",
    exe_path: str = "",
    environ: Optional[Dict[str, str]] = None,
) -> Optional[Dict[str, Any]]:
    """Check if a process has suspicious DYLD environment variables.

    If environ is not provided, reads from /proc/{pid}/environ (Linux)
    or ps -E (macOS).

    Covers MITRE: T1574.004 (Dylib Hijacking), T1574.006 (Dynamic Linker Hijacking)
    """
    if environ is None:
        environ = _get_process_environ(pid)

    if not environ:
        return None

    suspicious_vars = {}
    for var in DYLD_INJECTION_VARS:
        if var in environ:
            suspicious_vars[var] = environ[var]

    if not suspicious_vars:
        return None

    is_safe = process_name in DYLD_SAFE_PROCESSES

    # Check if process has hardened runtime (immune to DYLD injection)
    hardened = False
    if exe_path:
        cs = verify_code_signing(exe_path)
        hardened = cs.hardened_runtime

    if hardened:
        # Hardened runtime processes ignore DYLD vars — this is either
        # a failed injection attempt or a false positive
        return None

    risk = 0.4 if is_safe else 0.85
    if "DYLD_INSERT_LIBRARIES" in suspicious_vars:
        risk = max(risk, 0.9)  # Most dangerous — actual code injection

    return {
        "technique": "T1574.006",
        "category": "dyld_injection",
        "pid": pid,
        "process_name": process_name,
        "exe_path": exe_path,
        "dyld_vars": suspicious_vars,
        "is_safe_process": is_safe,
        "hardened_runtime": hardened,
        "risk": risk,
    }


def _get_process_environ(pid: int) -> Dict[str, str]:
    """Get environment variables for a process."""
    try:
        import psutil

        p = psutil.Process(pid)
        return p.environ()
    except Exception:
        return {}


def scan_all_processes_for_dyld() -> List[Dict[str, Any]]:
    """Scan all running processes for DYLD injection indicators."""
    findings = []
    try:
        import psutil

        for proc in psutil.process_iter(["pid", "name", "exe", "environ"]):
            try:
                info = proc.info
                result = check_dyld_injection(
                    pid=info["pid"],
                    process_name=info.get("name", ""),
                    exe_path=info.get("exe", ""),
                    environ=info.get("environ"),
                )
                if result and not result["is_safe_process"]:
                    findings.append(result)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except ImportError:
        logger.debug("psutil not available for DYLD scan")

    return findings
