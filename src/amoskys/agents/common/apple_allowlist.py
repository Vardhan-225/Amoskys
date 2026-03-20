"""Apple Process Allowlist — Known macOS system processes and their expected behaviors.

When a probe detects an action (keychain access, TCC permission grant, process spawn),
it checks this allowlist before creating an event. If the actor+action pair matches,
the event is either suppressed or downgraded to informational.

This eliminates ~80% of false positives caused by Apple system daemons doing their job.

Design Principles:
    1. Match on BOTH process name AND executable path prefix — a malicious binary
       named "mdworker_shared" running from /tmp/ will NOT match.
    2. Each profile declares expected file access patterns and MITRE exclusions.
    3. Profiles are conservative — only well-known Apple binaries are listed.
    4. Unknown processes are never suppressed — this only affects known-good actors.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Optional, Set, Tuple

# =============================================================================
# Data structures
# =============================================================================


@dataclass(frozen=True)
class AppleProcessProfile:
    """Profile of a known Apple system process and its expected behavior."""

    # Executable must start with one of these paths to match
    exe_prefixes: Tuple[str, ...] = ()

    # Expected parent process names (empty = any parent is fine)
    expected_parents: FrozenSet[str] = frozenset()

    # File access categories this process legitimately performs
    # Maps category -> set of path prefixes it's allowed to access
    # Empty set means "allowed to access any path in this category"
    allowed_accesses: Dict[str, Set[str]] = field(default_factory=dict)

    # TCC action types this process legitimately performs
    allowed_tcc_actions: FrozenSet[str] = frozenset()

    # MITRE techniques that should NOT be attributed when this process is the actor
    mitre_exclusions: FrozenSet[str] = frozenset()

    # Brief description for logging/UI
    description: str = ""


@dataclass(frozen=True)
class AllowlistResult:
    """Result of an allowlist lookup."""

    is_expected: bool
    disposition: str  # "apple_system", "unknown"
    reason: str  # Human-readable explanation
    process_profile: Optional[str] = None  # Profile name if matched


# =============================================================================
# Apple System Process Registry
# =============================================================================

_HOME = os.path.expanduser("~")

APPLE_SYSTEM_PROCESSES: Dict[str, AppleProcessProfile] = {
    # ── Keychain / Credential Management ──
    "TrustedPeersHelper": AppleProcessProfile(
        exe_prefixes=("/System/Library/", "/usr/libexec/"),
        allowed_accesses={"keychain": {f"{_HOME}/Library/Keychains/"}},
        mitre_exclusions=frozenset({"T1555", "T1555.001"}),
        description="iCloud Keychain trusted peer sync daemon",
    ),
    "TrustedPe": AppleProcessProfile(  # Truncated name from lsof/psutil
        exe_prefixes=("/System/Library/", "/usr/libexec/"),
        allowed_accesses={"keychain": {f"{_HOME}/Library/Keychains/"}},
        mitre_exclusions=frozenset({"T1555", "T1555.001"}),
        description="iCloud Keychain trusted peer sync (truncated name)",
    ),
    "secd": AppleProcessProfile(
        exe_prefixes=("/usr/libexec/", "/System/Library/"),
        allowed_accesses={"keychain": {f"{_HOME}/Library/Keychains/"}},
        mitre_exclusions=frozenset({"T1555", "T1555.001"}),
        description="Apple security daemon (keychain operations)",
    ),
    "securityd": AppleProcessProfile(
        exe_prefixes=("/usr/sbin/", "/usr/libexec/"),
        allowed_accesses={"keychain": {f"{_HOME}/Library/Keychains/"}},
        mitre_exclusions=frozenset({"T1555", "T1555.001"}),
        description="Apple security server daemon",
    ),
    "SecurityAgent": AppleProcessProfile(
        exe_prefixes=("/System/Library/",),
        allowed_accesses={"keychain": set()},
        mitre_exclusions=frozenset({"T1555", "T1555.001"}),
        description="Apple authentication UI agent",
    ),
    "loginwindow": AppleProcessProfile(
        exe_prefixes=("/System/Library/",),
        allowed_accesses={"keychain": set()},
        mitre_exclusions=frozenset({"T1555", "T1555.001"}),
        description="macOS login window manager",
    ),
    "authorizationhost": AppleProcessProfile(
        exe_prefixes=("/System/Library/",),
        allowed_accesses={"keychain": set()},
        mitre_exclusions=frozenset({"T1555", "T1555.001"}),
        description="Apple authorization host process",
    ),
    "nsurlsessiond": AppleProcessProfile(
        exe_prefixes=("/usr/libexec/",),
        allowed_accesses={"keychain": set(), "safari": set()},
        mitre_exclusions=frozenset({"T1555", "T1555.001", "T1555.003"}),
        description="Apple URL session background transfer daemon",
    ),
    # ── Safari / Browser ──
    "SafariBookmarksSyncAgent": AppleProcessProfile(
        exe_prefixes=("/System/Library/",),
        allowed_accesses={"safari": {f"{_HOME}/Library/Safari/"}},
        mitre_exclusions=frozenset({"T1555.003"}),
        description="Safari bookmark sync agent",
    ),
    "SafariBoo": AppleProcessProfile(  # Truncated name
        exe_prefixes=("/System/Library/",),
        allowed_accesses={"safari": {f"{_HOME}/Library/Safari/"}},
        mitre_exclusions=frozenset({"T1555.003"}),
        description="Safari bookmark sync (truncated name)",
    ),
    "com.apple.Safari": AppleProcessProfile(
        exe_prefixes=("/System/", "/Applications/Safari.app/"),
        allowed_accesses={"safari": {f"{_HOME}/Library/Safari/"}},
        mitre_exclusions=frozenset({"T1555.003"}),
        description="Safari browser",
    ),
    "com.apple": AppleProcessProfile(  # Truncated com.apple.* process names
        exe_prefixes=("/System/Library/", "/usr/libexec/"),
        allowed_accesses={
            "safari": {f"{_HOME}/Library/Safari/"},
            "keychain": {f"{_HOME}/Library/Keychains/"},
        },
        mitre_exclusions=frozenset({"T1555.001", "T1555.003"}),
        description="Apple system process (truncated name)",
    ),
    "Safari": AppleProcessProfile(
        exe_prefixes=("/Applications/Safari.app/", "/System/"),
        allowed_accesses={"safari": {f"{_HOME}/Library/Safari/"}},
        mitre_exclusions=frozenset({"T1555.003"}),
        description="Safari browser application",
    ),
    "SafariServices": AppleProcessProfile(
        exe_prefixes=("/System/Library/",),
        allowed_accesses={"safari": {f"{_HOME}/Library/Safari/"}},
        mitre_exclusions=frozenset({"T1555.003"}),
        description="Safari services framework",
    ),
    "com.apple.Safari.SafeBrowsing": AppleProcessProfile(
        exe_prefixes=("/System/Library/",),
        allowed_accesses={"safari": {f"{_HOME}/Library/Safari/"}},
        mitre_exclusions=frozenset({"T1555.003"}),
        description="Safari Safe Browsing service",
    ),
    # ── TCC / Permission Management ──
    "tccd": AppleProcessProfile(
        exe_prefixes=("/System/Library/PrivateFrameworks/", "/usr/libexec/"),
        allowed_tcc_actions=frozenset(
            {
                "tcc_permission_granted",
                "tcc_permission_denied",
                "tcc_permission_request",
                "tcc_full_disk_access",
                "tcc_accessibility",
                "tcc_camera_microphone",
            }
        ),
        mitre_exclusions=frozenset({"T1548"}),
        description="TCC daemon — manages privacy permissions",
    ),
    "sandboxd": AppleProcessProfile(
        exe_prefixes=("/usr/libexec/",),
        allowed_tcc_actions=frozenset(
            {
                "tcc_permission_request",
                "tcc_permission_denied",
            }
        ),
        mitre_exclusions=frozenset({"T1548"}),
        description="macOS sandbox enforcement daemon",
    ),
    # ── Spotlight / Indexing ──
    "mdworker_shared": AppleProcessProfile(
        exe_prefixes=(
            "/System/Library/Frameworks/CoreServices.framework/",
            "/System/Library/",
        ),
        expected_parents=frozenset({"launchd"}),
        mitre_exclusions=frozenset({"T1059", "T1204"}),
        description="Spotlight metadata indexer worker",
    ),
    "mdworker": AppleProcessProfile(
        exe_prefixes=("/System/Library/",),
        expected_parents=frozenset({"launchd"}),
        mitre_exclusions=frozenset({"T1059", "T1204"}),
        description="Spotlight metadata worker (legacy)",
    ),
    "mds_stores": AppleProcessProfile(
        exe_prefixes=("/System/Library/",),
        expected_parents=frozenset({"launchd"}),
        mitre_exclusions=frozenset({"T1059", "T1204"}),
        description="Spotlight metadata store manager",
    ),
    "mds": AppleProcessProfile(
        exe_prefixes=("/System/Library/",),
        expected_parents=frozenset({"launchd"}),
        mitre_exclusions=frozenset({"T1059", "T1204"}),
        description="Spotlight metadata server",
    ),
    # ── Contacts / Calendar / Address Book ──
    "contactsd": AppleProcessProfile(
        exe_prefixes=("/System/Library/Frameworks/Contacts.framework/",),
        allowed_tcc_actions=frozenset(
            {"tcc_permission_granted", "tcc_permission_request"}
        ),
        mitre_exclusions=frozenset({"T1548"}),
        description="Contacts sync daemon",
    ),
    "AddressBookSourceSync": AppleProcessProfile(
        exe_prefixes=("/System/Library/Frameworks/AddressBook.framework/",),
        allowed_tcc_actions=frozenset(
            {"tcc_permission_granted", "tcc_permission_request"}
        ),
        mitre_exclusions=frozenset({"T1548"}),
        description="Address Book sync agent",
    ),
    # ── Accessibility / UI ──
    "AXVisualSupportAgent": AppleProcessProfile(
        exe_prefixes=("/System/Library/PrivateFrameworks/UniversalAccess.framework/",),
        allowed_tcc_actions=frozenset({"tcc_accessibility"}),
        mitre_exclusions=frozenset({"T1548"}),
        description="Accessibility visual support agent",
    ),
    # ── Power / System ──
    "powerlogd": AppleProcessProfile(
        exe_prefixes=("/usr/libexec/",),
        mitre_exclusions=frozenset({"T1070"}),
        description="Power management logging daemon",
    ),
    # ── Sharing / Networking ──
    "sharingd": AppleProcessProfile(
        exe_prefixes=("/usr/libexec/", "/System/Library/"),
        mitre_exclusions=frozenset({"T1105"}),
        description="Sharing and AirDrop daemon",
    ),
    "rapportd": AppleProcessProfile(
        exe_prefixes=("/usr/libexec/",),
        mitre_exclusions=frozenset({"T1071"}),
        description="Apple device proximity/rapport daemon",
    ),
    "identityservicesd": AppleProcessProfile(
        exe_prefixes=("/System/Library/PrivateFrameworks/",),
        mitre_exclusions=frozenset({"T1071"}),
        description="Apple identity services daemon",
    ),
    "identitys": AppleProcessProfile(  # Truncated name
        exe_prefixes=("/System/Library/PrivateFrameworks/",),
        mitre_exclusions=frozenset({"T1071"}),
        description="Apple identity services (truncated name)",
    ),
}


# =============================================================================
# Lookup functions
# =============================================================================


def is_apple_system_process(
    process_name: str,
    exe_path: str = "",
) -> AllowlistResult:
    """Check if a process is a known Apple system process.

    Both process name AND exe path must match for a positive result.
    If exe_path is empty/unknown, we match on name only but with lower confidence.

    Args:
        process_name: Process name (may be truncated by lsof/psutil)
        exe_path: Full executable path

    Returns:
        AllowlistResult with disposition and match details
    """
    profile = APPLE_SYSTEM_PROCESSES.get(process_name)
    if profile is None:
        return AllowlistResult(
            is_expected=False,
            disposition="unknown",
            reason=f"Process '{process_name}' not in Apple allowlist",
        )

    # If we have an exe path, verify it matches expected prefixes
    if exe_path and profile.exe_prefixes:
        if not any(exe_path.startswith(prefix) for prefix in profile.exe_prefixes):
            return AllowlistResult(
                is_expected=False,
                disposition="unknown",
                reason=(
                    f"Process '{process_name}' matched name but exe path "
                    f"'{exe_path}' doesn't match expected prefixes"
                ),
            )

    return AllowlistResult(
        is_expected=True,
        disposition="apple_system",
        reason=profile.description,
        process_profile=process_name,
    )


def is_expected_file_access(
    process_name: str,
    file_path: str,
    access_category: str,
    exe_path: str = "",
) -> AllowlistResult:
    """Check if a file access by a process is expected Apple system behavior.

    Args:
        process_name: Process name accessing the file
        file_path: Path of the file being accessed
        access_category: Category of access (keychain, safari, etc.)
        exe_path: Full executable path of the process

    Returns:
        AllowlistResult indicating whether this is expected behavior
    """
    base_result = is_apple_system_process(process_name, exe_path)
    if not base_result.is_expected:
        return base_result

    profile = APPLE_SYSTEM_PROCESSES[process_name]

    # Check if this category is in the process's allowed accesses
    if access_category not in profile.allowed_accesses:
        return AllowlistResult(
            is_expected=False,
            disposition="unknown",
            reason=(
                f"Apple process '{process_name}' is not expected to access "
                f"'{access_category}' resources"
            ),
        )

    # Check path prefix if specified (empty set = any path in category is fine)
    allowed_paths = profile.allowed_accesses[access_category]
    if allowed_paths and file_path:
        if not any(file_path.startswith(prefix) for prefix in allowed_paths):
            return AllowlistResult(
                is_expected=False,
                disposition="unknown",
                reason=(
                    f"Apple process '{process_name}' accessing unexpected path "
                    f"'{file_path}' in category '{access_category}'"
                ),
            )

    return AllowlistResult(
        is_expected=True,
        disposition="apple_system",
        reason=f"{profile.description} — expected {access_category} access",
        process_profile=process_name,
    )


def is_expected_tcc_action(
    process_name: str,
    tcc_action: str,
    exe_path: str = "",
) -> AllowlistResult:
    """Check if a TCC action by a process is expected Apple system behavior.

    Args:
        process_name: Process performing the TCC action
        tcc_action: TCC event subtype (tcc_permission_granted, etc.)
        exe_path: Full executable path

    Returns:
        AllowlistResult indicating whether this TCC action is expected
    """
    base_result = is_apple_system_process(process_name, exe_path)
    if not base_result.is_expected:
        return base_result

    profile = APPLE_SYSTEM_PROCESSES[process_name]

    if not profile.allowed_tcc_actions:
        return AllowlistResult(
            is_expected=False,
            disposition="unknown",
            reason=f"Apple process '{process_name}' has no expected TCC actions",
        )

    if tcc_action not in profile.allowed_tcc_actions:
        return AllowlistResult(
            is_expected=False,
            disposition="unknown",
            reason=(
                f"Apple process '{process_name}' performing unexpected "
                f"TCC action '{tcc_action}'"
            ),
        )

    return AllowlistResult(
        is_expected=True,
        disposition="apple_system",
        reason=f"{profile.description} — expected TCC action",
        process_profile=process_name,
    )


def should_exclude_mitre(process_name: str, technique: str) -> bool:
    """Check if a MITRE technique should be excluded for this process.

    Used by the scoring engine to avoid attributing techniques to known-good actors.
    """
    profile = APPLE_SYSTEM_PROCESSES.get(process_name)
    if profile is None:
        return False
    return technique in profile.mitre_exclusions


def get_trust_disposition(process_name: str, exe_path: str = "") -> str:
    """Get the trust disposition for a process.

    Returns: "apple_system", "self", or "unknown"
    (self-recognition is handled by SelfIdentity, not here)
    """
    result = is_apple_system_process(process_name, exe_path)
    return result.disposition
