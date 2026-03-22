"""Phase 2.75 SOMA Mandate Features — 8 new features from mandate fields.

Extracts security-relevant features from the typed mandate columns
(pid, process_name, exe, remote_ip, username) that _extract_typed_features()
populates from raw_attributes_json.

These features give SOMA visibility into WHAT process and WHERE the
connection goes — not just the category and timing.
"""

from typing import Any, Dict, List

_SYSTEM_EXE_PREFIXES = (
    "/usr/sbin/",
    "/usr/libexec/",
    "/System/Library/",
    "/sbin/",
    "/usr/bin/",
    "/Library/Apple/",
    "/System/",
)

MANDATE_FEATURE_NAMES = [
    "has_process_context",
    "has_executable",
    "exe_path_depth",
    "is_system_exe",
    "has_network_context",
    "is_private_ip",
    "has_user_context",
    "is_root_user",
]


def _is_rfc1918(ip: str) -> bool:
    if not ip:
        return False
    if ip.startswith(("10.", "192.168.", "127.")):
        return True
    if ip.startswith("172."):
        try:
            return 16 <= int(ip.split(".")[1]) <= 31
        except (IndexError, ValueError):
            pass
    return ip.startswith("fe80:") or ip == "::1"


def extract_mandate_features(row: Dict[str, Any]) -> List[float]:
    """Extract 8 mandate-aware features from a security_events row.

    Returns: [has_process_context, has_executable, exe_path_depth,
              is_system_exe, has_network_context, is_private_ip,
              has_user_context, is_root_user]
    """
    pid = row.get("pid")
    process_name = row.get("process_name", "") or ""
    exe = row.get("exe", "") or ""
    remote_ip = row.get("remote_ip", "") or ""
    username = row.get("username", "") or ""

    return [
        1.0 if (process_name or pid) else 0.0,
        1.0 if exe else 0.0,
        float(len(exe.split("/")) - 1) if exe else 0.0,
        1.0 if any(exe.startswith(p) for p in _SYSTEM_EXE_PREFIXES) else 0.0,
        1.0 if remote_ip else 0.0,
        1.0 if _is_rfc1918(remote_ip) else 0.0,
        1.0 if username else 0.0,
        1.0 if username == "root" else 0.0,
    ]
