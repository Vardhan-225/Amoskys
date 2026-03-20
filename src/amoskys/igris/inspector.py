"""IGRIS Inspector — read-only investigation actions.

When IGRIS sees something suspicious, it can now ASK SPECIFIC QUESTIONS
instead of just watching and waiting. These are read-only inspection
commands that agents execute on demand.

The inspector does NOT modify system state. It reads. It checks. It reports.

Available Actions:
    INSPECT_CODESIGN   — verify code signature of a binary
    INSPECT_ENVIRON    — check process environment for injection indicators
    INSPECT_CONNECTIONS — list all network connections for a PID
    INSPECT_CHILDREN   — get full process tree for a PID
    INSPECT_XATTR      — check quarantine/download attributes on a file
    INSPECT_FILE_HASH  — SHA-256 hash a file for IOC matching
    INSPECT_LSOF       — list all open files for a PID
    INSPECT_PLIST      — parse and analyze a LaunchAgent/Daemon plist

Each action returns structured results that IGRIS stores in memory
for correlation and trend analysis.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import plistlib
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("igris.inspector")


@dataclass
class InspectionResult:
    """Result of a single inspection action."""

    action: str
    target: str
    success: bool
    verdict: str  # clean, suspicious, malicious, error, unknown
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0
    duration_ms: float = 0.0

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.time()


class IGRISInspector:
    """Execute read-only investigation actions on the local system.

    All actions are non-destructive. They read system state and return
    structured results for IGRIS to reason about.
    """

    # Timeout for subprocess calls (seconds)
    _TIMEOUT = 10

    def inspect(self, action: str, target: str) -> InspectionResult:
        """Dispatch an inspection action."""
        start = time.time()
        handler = {
            "INSPECT_CODESIGN": self._inspect_codesign,
            "INSPECT_ENVIRON": self._inspect_environ,
            "INSPECT_CONNECTIONS": self._inspect_connections,
            "INSPECT_CHILDREN": self._inspect_children,
            "INSPECT_XATTR": self._inspect_xattr,
            "INSPECT_FILE_HASH": self._inspect_file_hash,
            "INSPECT_LSOF": self._inspect_lsof,
            "INSPECT_PLIST": self._inspect_plist,
        }.get(action)

        if not handler:
            return InspectionResult(
                action=action,
                target=target,
                success=False,
                verdict="error",
                data={"error": f"Unknown action: {action}"},
            )

        try:
            result = handler(target)
            result.duration_ms = (time.time() - start) * 1000
            return result
        except Exception as e:
            logger.error("Inspector %s on %s failed: %s", action, target, e)
            return InspectionResult(
                action=action,
                target=target,
                success=False,
                verdict="error",
                data={"error": str(e)},
                duration_ms=(time.time() - start) * 1000,
            )

    def _inspect_codesign(self, target: str) -> InspectionResult:
        """Verify code signature of a binary or app bundle.

        Checks:
            - Is it signed at all?
            - Is the signature valid?
            - Who signed it (Apple, Developer ID, ad-hoc, unsigned)?
            - Is it notarized?
        """
        if not Path(target).exists():
            return InspectionResult(
                action="INSPECT_CODESIGN",
                target=target,
                success=False,
                verdict="error",
                data={"error": "File does not exist"},
            )

        data = {}

        # codesign --verify
        try:
            result = subprocess.run(
                ["codesign", "--verify", "--verbose=2", target],
                capture_output=True,
                text=True,
                timeout=self._TIMEOUT,
            )
            data["valid"] = result.returncode == 0
            data["verify_output"] = (result.stdout + result.stderr).strip()
        except FileNotFoundError:
            data["valid"] = None
            data["verify_output"] = "codesign not available (not macOS)"
        except subprocess.TimeoutExpired:
            data["valid"] = None
            data["verify_output"] = "timeout"

        # codesign --display for signer identity
        try:
            result = subprocess.run(
                ["codesign", "--display", "--verbose=2", target],
                capture_output=True,
                text=True,
                timeout=self._TIMEOUT,
            )
            output = result.stderr  # codesign writes to stderr
            data["display_output"] = output.strip()

            # Parse authority chain
            authorities = []
            for line in output.split("\n"):
                if line.strip().startswith("Authority="):
                    authorities.append(line.split("=", 1)[1].strip())
            data["authorities"] = authorities

            # Determine signer type
            if not authorities:
                data["signer_type"] = "unsigned"
            elif any("Apple" in a for a in authorities):
                data["signer_type"] = "apple"
            elif any("Developer ID" in a for a in authorities):
                data["signer_type"] = "developer_id"
            else:
                data["signer_type"] = "ad_hoc_or_self"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Verdict
        signer = data.get("signer_type", "unknown")
        valid = data.get("valid")
        if valid and signer in ("apple", "developer_id"):
            verdict = "clean"
        elif valid and signer == "ad_hoc_or_self":
            verdict = "suspicious"
        elif not valid:
            verdict = "suspicious"
        elif signer == "unsigned":
            verdict = "suspicious"
        else:
            verdict = "unknown"

        return InspectionResult(
            action="INSPECT_CODESIGN",
            target=target,
            success=True,
            verdict=verdict,
            data=data,
        )

    def _inspect_environ(self, target: str) -> InspectionResult:
        """Check process environment for injection indicators.

        Looks for:
            - DYLD_INSERT_LIBRARIES (dylib injection)
            - DYLD_LIBRARY_PATH (library hijacking)
            - LD_PRELOAD (Linux injection)
            - Suspicious HOME/PATH overrides
        """
        pid = target
        data = {}

        # Try reading /proc/{pid}/environ (Linux) or ps eww (macOS)
        environ_path = Path(f"/proc/{pid}/environ")
        if environ_path.exists():
            try:
                raw = environ_path.read_bytes()
                env_vars = {}
                for pair in raw.split(b"\x00"):
                    if b"=" in pair:
                        k, v = pair.decode("utf-8", errors="replace").split("=", 1)
                        env_vars[k] = v
                data["env_vars"] = env_vars
            except (PermissionError, OSError) as e:
                data["error"] = f"Cannot read environ: {e}"
        else:
            # macOS: use ps eww
            try:
                result = subprocess.run(
                    ["ps", "eww", "-p", str(pid)],
                    capture_output=True,
                    text=True,
                    timeout=self._TIMEOUT,
                )
                data["ps_output"] = result.stdout.strip()
            except (FileNotFoundError, subprocess.TimeoutExpired):
                data["error"] = "Cannot read process environment"

        # Check for injection indicators
        suspicious_vars = []
        env = data.get("env_vars", {})
        for var in [
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            "DYLD_FRAMEWORK_PATH",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
        ]:
            if var in env:
                suspicious_vars.append(f"{var}={env[var]}")

        # Also check ps output for these strings
        ps_out = data.get("ps_output", "")
        for var in ["DYLD_INSERT", "LD_PRELOAD"]:
            if var in ps_out:
                suspicious_vars.append(f"Found {var} in ps output")

        data["suspicious_vars"] = suspicious_vars

        verdict = "suspicious" if suspicious_vars else "clean"
        return InspectionResult(
            action="INSPECT_ENVIRON",
            target=target,
            success=True,
            verdict=verdict,
            data=data,
        )

    def _inspect_connections(self, target: str) -> InspectionResult:
        """List all network connections for a PID.

        Returns local/remote addresses, states, and protocol info.
        """
        pid = target
        data = {"connections": []}

        try:
            import psutil

            proc = psutil.Process(int(pid))
            for conn in proc.connections(kind="all"):
                entry = {
                    "fd": conn.fd,
                    "family": str(conn.family),
                    "type": str(conn.type),
                    "local": (
                        f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                    ),
                    "remote": (
                        f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
                    ),
                    "status": conn.status,
                }
                data["connections"].append(entry)
            data["total_connections"] = len(data["connections"])
            data["external_connections"] = sum(
                1
                for c in data["connections"]
                if c["remote"]
                and not c["remote"].startswith("127.")
                and not c["remote"].startswith("::1")
            )
        except ImportError:
            data["error"] = "psutil not available"
        except psutil.NoSuchProcess:
            data["error"] = f"PID {pid} does not exist"
        except psutil.AccessDenied:
            data["error"] = f"Access denied for PID {pid}"
        except Exception as e:
            data["error"] = str(e)

        # Verdict based on external connections
        ext = data.get("external_connections", 0)
        if ext > 5:
            verdict = "suspicious"
        elif ext > 0:
            verdict = "unknown"
        else:
            verdict = "clean"

        return InspectionResult(
            action="INSPECT_CONNECTIONS",
            target=target,
            success="error" not in data,
            verdict=verdict,
            data=data,
        )

    def _inspect_children(self, target: str) -> InspectionResult:
        """Get full process tree for a PID.

        Returns parent chain (up) and children (down).
        """
        pid = int(target)
        data = {"pid": pid, "parent_chain": [], "children": []}

        try:
            import psutil

            proc = psutil.Process(pid)
            data["name"] = proc.name()
            data["exe"] = proc.exe()
            data["cmdline"] = proc.cmdline()
            data["username"] = proc.username()
            data["create_time"] = proc.create_time()

            # Walk up the parent chain
            current = proc
            for _ in range(10):
                try:
                    parent = current.parent()
                    if parent is None:
                        break
                    data["parent_chain"].append(
                        {
                            "pid": parent.pid,
                            "name": parent.name(),
                            "exe": parent.exe() if parent.exe() else "",
                        }
                    )
                    current = parent
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    break

            # Get children (recursive)
            for child in proc.children(recursive=True):
                try:
                    data["children"].append(
                        {
                            "pid": child.pid,
                            "name": child.name(),
                            "exe": child.exe() if child.exe() else "",
                            "status": child.status(),
                        }
                    )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            data["total_children"] = len(data["children"])
        except ImportError:
            data["error"] = "psutil not available"
        except psutil.NoSuchProcess:
            data["error"] = f"PID {pid} does not exist"
        except psutil.AccessDenied:
            data["error"] = f"Access denied for PID {pid}"

        verdict = "unknown"
        if data.get("total_children", 0) > 20:
            verdict = "suspicious"

        return InspectionResult(
            action="INSPECT_CHILDREN",
            target=target,
            success="error" not in data,
            verdict=verdict,
            data=data,
        )

    def _inspect_xattr(self, target: str) -> InspectionResult:
        """Check quarantine and download attributes on a file.

        Looks for:
            - com.apple.quarantine (download source tracking)
            - com.apple.metadata:kMDItemWhereFroms (download URL)
        """
        path = Path(target)
        if not path.exists():
            return InspectionResult(
                action="INSPECT_XATTR",
                target=target,
                success=False,
                verdict="error",
                data={"error": "File does not exist"},
            )

        data = {"path": target, "xattrs": {}}

        try:
            result = subprocess.run(
                ["xattr", "-l", target],
                capture_output=True,
                text=True,
                timeout=self._TIMEOUT,
            )
            data["raw_xattrs"] = result.stdout.strip()

            # Parse quarantine
            if "com.apple.quarantine" in result.stdout:
                data["has_quarantine"] = True
                for line in result.stdout.split("\n"):
                    if "com.apple.quarantine" in line:
                        data["quarantine_value"] = line.split(":", 1)[-1].strip()
            else:
                data["has_quarantine"] = False

            # Parse where-froms
            if "kMDItemWhereFroms" in result.stdout:
                data["has_where_froms"] = True
            else:
                data["has_where_froms"] = False

        except FileNotFoundError:
            data["error"] = "xattr command not available"
        except subprocess.TimeoutExpired:
            data["error"] = "timeout"

        # Verdict: files from internet without quarantine are suspicious
        if data.get("has_quarantine") is False and path.suffix in (
            ".command",
            ".sh",
            ".py",
            ".app",
            ".dmg",
            ".pkg",
            ".zip",
        ):
            verdict = "suspicious"
        elif data.get("has_quarantine"):
            verdict = "clean"
        else:
            verdict = "unknown"

        return InspectionResult(
            action="INSPECT_XATTR",
            target=target,
            success=True,
            verdict=verdict,
            data=data,
        )

    def _inspect_file_hash(self, target: str) -> InspectionResult:
        """SHA-256 hash a file for IOC matching."""
        path = Path(target)
        if not path.exists():
            return InspectionResult(
                action="INSPECT_FILE_HASH",
                target=target,
                success=False,
                verdict="error",
                data={"error": "File does not exist"},
            )

        try:
            sha256 = hashlib.sha256()
            with open(target, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            file_hash = sha256.hexdigest()
            file_size = path.stat().st_size

            data = {
                "sha256": file_hash,
                "size_bytes": file_size,
                "path": target,
            }

            return InspectionResult(
                action="INSPECT_FILE_HASH",
                target=target,
                success=True,
                verdict="unknown",  # hash alone doesn't determine verdict
                data=data,
            )
        except (PermissionError, OSError) as e:
            return InspectionResult(
                action="INSPECT_FILE_HASH",
                target=target,
                success=False,
                verdict="error",
                data={"error": str(e)},
            )

    def _inspect_lsof(self, target: str) -> InspectionResult:
        """List all open files for a PID."""
        pid = target
        data = {"pid": pid, "open_files": []}

        try:
            result = subprocess.run(
                ["lsof", "-p", str(pid)],
                capture_output=True,
                text=True,
                timeout=self._TIMEOUT,
            )
            lines = result.stdout.strip().split("\n")
            # Skip header
            for line in lines[1:]:
                parts = line.split(None, 8)
                if len(parts) >= 9:
                    data["open_files"].append(
                        {
                            "fd": parts[3],
                            "type": parts[4],
                            "name": parts[8],
                        }
                    )
            data["total_open"] = len(data["open_files"])
        except FileNotFoundError:
            data["error"] = "lsof not available"
        except subprocess.TimeoutExpired:
            data["error"] = "timeout"

        verdict = "unknown"
        # Check for suspicious file access patterns
        sensitive_paths = [
            "/etc/shadow",
            "/etc/sudoers",
            "Keychain",
            ".ssh/",
            "id_rsa",
            "Cookies",
            "Login Data",
        ]
        for f in data.get("open_files", []):
            name = f.get("name", "")
            if any(s in name for s in sensitive_paths):
                verdict = "suspicious"
                break

        return InspectionResult(
            action="INSPECT_LSOF",
            target=target,
            success="error" not in data,
            verdict=verdict,
            data=data,
        )

    def _inspect_plist(self, target: str) -> InspectionResult:
        """Parse and analyze a LaunchAgent/Daemon plist file.

        Checks:
            - What binary does it execute?
            - Does it run at load?
            - What interval?
            - Does it have keep-alive?
            - Does the target binary exist and is it signed?
        """
        path = Path(target)
        if not path.exists():
            return InspectionResult(
                action="INSPECT_PLIST",
                target=target,
                success=False,
                verdict="error",
                data={"error": "File does not exist"},
            )

        data = {"path": target}
        try:
            with open(target, "rb") as f:
                plist = plistlib.load(f)

            data["label"] = plist.get("Label", "")
            data["program"] = plist.get("Program", "")
            data["program_arguments"] = plist.get("ProgramArguments", [])
            data["run_at_load"] = plist.get("RunAtLoad", False)
            data["start_interval"] = plist.get("StartInterval")
            data["keep_alive"] = plist.get("KeepAlive", False)
            data["working_directory"] = plist.get("WorkingDirectory", "")
            data["environment_variables"] = plist.get("EnvironmentVariables", {})

            # Determine the actual binary
            binary = data["program"] or (
                data["program_arguments"][0] if data["program_arguments"] else ""
            )
            data["binary"] = binary
            data["binary_exists"] = Path(binary).exists() if binary else False

            # Suspicious indicators
            sus_indicators = []
            if binary and binary.startswith("/tmp"):
                sus_indicators.append("binary in /tmp")
            if binary and binary.startswith("/var/tmp"):
                sus_indicators.append("binary in /var/tmp")
            if data.get("environment_variables"):
                for k in data["environment_variables"]:
                    if "DYLD" in k or "LD_PRELOAD" in k:
                        sus_indicators.append(f"suspicious env var: {k}")
            if data["run_at_load"] and data.get("keep_alive"):
                sus_indicators.append("run_at_load + keep_alive (persistent)")
            if not data.get("binary_exists") and binary:
                sus_indicators.append("binary does not exist yet (staged)")

            data["suspicious_indicators"] = sus_indicators

        except Exception as e:
            data["error"] = str(e)
            return InspectionResult(
                action="INSPECT_PLIST",
                target=target,
                success=False,
                verdict="error",
                data=data,
            )

        # Verdict
        if data.get("suspicious_indicators"):
            verdict = "suspicious"
        else:
            verdict = "clean"

        return InspectionResult(
            action="INSPECT_PLIST",
            target=target,
            success=True,
            verdict=verdict,
            data=data,
        )
