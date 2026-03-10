"""macOS File Collector — filesystem snapshot for integrity monitoring.

Scans critical macOS paths and returns structured file metadata for probes.
Does NOT make detection decisions — probes handle all analysis.

Collected data:
    - File entries: path, name, sha256, mtime, size, mode, uid, is_suid
    - SIP status: enabled/disabled via csrutil status
    - SUID binaries: files with setuid bit in known paths
    - Collection timing

Paths monitored:
    /etc — system configuration (hosts, resolv.conf, sudoers, etc.)
    /usr/bin, /usr/sbin — system binaries (SIP-protected)
    /usr/lib — system libraries (SIP-protected)
    ~/Library — user preferences, application support
    /Library — system frameworks, preferences
    ~/Downloads — initial access vector
"""

from __future__ import annotations

import hashlib
import logging
import os
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class FileEntry:
    """Single file state at collection time."""

    path: str
    name: str
    sha256: str
    mtime: float
    size: int
    mode: int
    uid: int
    is_suid: bool


def _sha256(path: str) -> str:
    """SHA-256 hash of file content. Returns empty string on failure."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return ""


def _get_sip_status() -> str:
    """Check SIP status via csrutil. Returns 'enabled', 'disabled', or 'unknown'."""
    try:
        result = subprocess.run(
            ["csrutil", "status"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = result.stdout.lower()
        if "enabled" in output:
            return "enabled"
        elif "disabled" in output:
            return "disabled"
        return "unknown"
    except Exception:
        return "unknown"


class MacOSFileCollector:
    """Collects filesystem snapshots from critical macOS paths.

    Returns shared_data dict with keys:
        files: List[FileEntry] — all scanned file entries
        sip_status: str — 'enabled', 'disabled', or 'unknown'
        suid_binaries: List[FileEntry] — files with SUID bit set
        collection_time_ms: float — how long collection took
    """

    # Critical system paths to monitor (shallow scan — top-level files only)
    _CRITICAL_PATHS = [
        "/etc",
        "/usr/bin",
        "/usr/sbin",
        "/usr/lib",
    ]

    # User/system library paths (shallow scan)
    _LIBRARY_PATHS = [
        "{home}/Library",
        "/Library",
    ]

    # Paths to check for SUID binaries
    _SUID_SEARCH_PATHS = [
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
    ]

    # Critical config files to always hash (even if directory scan skips them)
    _CRITICAL_FILES = [
        "/etc/hosts",
        "/etc/resolv.conf",
        "/etc/sudoers",
        "/etc/passwd",
        "/etc/group",
        "/etc/shells",
        "/etc/pam.d/sudo",
        "/etc/ssh/sshd_config",
        "/etc/auto_master",
        "/etc/fstab",
    ]

    # Max files per directory to avoid runaway scans
    _MAX_FILES_PER_DIR = 500

    # Max file size to hash (skip large binaries to keep collection fast)
    _MAX_HASH_SIZE = 10 * 1024 * 1024  # 10 MB

    def __init__(self, device_id: str = "") -> None:
        self._home = str(Path.home())
        self._device_id = device_id

    def collect(self) -> Dict[str, Any]:
        """Collect filesystem snapshot.

        Returns dict for ProbeContext.shared_data.
        """
        start = time.monotonic()
        files: List[FileEntry] = []
        seen_paths: set = set()

        # 1. Always scan critical individual files
        for fpath in self._CRITICAL_FILES:
            entry = self._stat_file(fpath)
            if entry:
                files.append(entry)
                seen_paths.add(fpath)

        # 2. Scan critical system directories (shallow)
        for dir_path in self._CRITICAL_PATHS:
            for entry in self._scan_directory(dir_path, seen_paths):
                files.append(entry)

        # 3. Scan library paths (shallow — only top-level config files)
        for path_template in self._LIBRARY_PATHS:
            dir_path = path_template.replace("{home}", self._home)
            for entry in self._scan_directory(dir_path, seen_paths, max_depth=1):
                files.append(entry)

        # 4. Scan ~/Downloads (shallow)
        downloads = os.path.join(self._home, "Downloads")
        for entry in self._scan_directory(downloads, seen_paths, max_depth=0):
            files.append(entry)

        # 5. Identify SUID binaries
        suid_binaries: List[FileEntry] = []
        for dir_path in self._SUID_SEARCH_PATHS:
            for entry in self._find_suid_in_dir(dir_path, seen_paths):
                suid_binaries.append(entry)
                if entry.path not in seen_paths:
                    files.append(entry)

        # Also tag SUID binaries already in files list
        suid_paths = {e.path for e in suid_binaries}
        for entry in files:
            if entry.is_suid and entry.path not in suid_paths:
                suid_binaries.append(entry)

        # 6. SIP status
        sip_status = _get_sip_status()

        elapsed_ms = (time.monotonic() - start) * 1000

        return {
            "files": files,
            "sip_status": sip_status,
            "suid_binaries": suid_binaries,
            "collection_time_ms": round(elapsed_ms, 2),
        }

    def _stat_file(self, path: str) -> Optional[FileEntry]:
        """Stat a single file and return FileEntry or None."""
        try:
            st = os.stat(path)
            if not stat.S_ISREG(st.st_mode):
                return None

            file_hash = ""
            if st.st_size <= self._MAX_HASH_SIZE:
                file_hash = _sha256(path)

            is_suid = bool(st.st_mode & stat.S_ISUID)

            return FileEntry(
                path=path,
                name=os.path.basename(path),
                sha256=file_hash,
                mtime=st.st_mtime,
                size=st.st_size,
                mode=st.st_mode,
                uid=st.st_uid,
                is_suid=is_suid,
            )
        except (OSError, PermissionError):
            return None

    def _scan_directory(
        self,
        dir_path: str,
        seen: set,
        max_depth: int = 0,
    ) -> List[FileEntry]:
        """Scan directory for files (shallow by default).

        Args:
            dir_path: Directory to scan.
            seen: Set of already-seen paths (avoid duplicates).
            max_depth: 0 = top-level only, 1 = one level of subdirs.
        """
        entries: List[FileEntry] = []
        if not os.path.isdir(dir_path):
            return entries

        try:
            count = 0
            for item in os.scandir(dir_path):
                if count >= self._MAX_FILES_PER_DIR:
                    break

                if item.is_file(follow_symlinks=False):
                    if item.path in seen:
                        continue
                    entry = self._stat_file(item.path)
                    if entry:
                        entries.append(entry)
                        seen.add(item.path)
                        count += 1

                elif item.is_dir(follow_symlinks=False) and max_depth > 0:
                    for sub_entry in self._scan_directory(
                        item.path, seen, max_depth=max_depth - 1
                    ):
                        entries.append(sub_entry)

        except (PermissionError, OSError) as e:
            logger.debug("Cannot scan %s: %s", dir_path, e)

        return entries

    def _find_suid_in_dir(
        self,
        dir_path: str,
        seen: set,
    ) -> List[FileEntry]:
        """Find SUID binaries in a directory."""
        suid: List[FileEntry] = []
        if not os.path.isdir(dir_path):
            return suid

        try:
            for item in os.scandir(dir_path):
                if not item.is_file(follow_symlinks=False):
                    continue
                try:
                    st = item.stat(follow_symlinks=False)
                    if st.st_mode & stat.S_ISUID:
                        entry = FileEntry(
                            path=item.path,
                            name=item.name,
                            sha256=(
                                _sha256(item.path)
                                if st.st_size <= self._MAX_HASH_SIZE
                                else ""
                            ),
                            mtime=st.st_mtime,
                            size=st.st_size,
                            mode=st.st_mode,
                            uid=st.st_uid,
                            is_suid=True,
                        )
                        suid.append(entry)
                        seen.add(item.path)
                except (OSError, PermissionError):
                    continue
        except (PermissionError, OSError):
            pass

        return suid
