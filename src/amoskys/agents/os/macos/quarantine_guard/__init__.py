"""AMOSKYS macOS Quarantine Guard Observatory.

Purpose-built download provenance and Gatekeeper bypass monitoring for macOS
(Darwin 25.0.0+, Apple Silicon). Tracks quarantine xattr lifecycle, DMG-based
delivery chains, ClickFix social engineering attacks, and CLI download evasion.

Data sources (ground truth):
    - ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2
      SQLite database with download provenance (browser, URL, referrer, sender).
      Timestamps in Core Data format (seconds since 2001-01-01 UTC).
    - ~/Downloads/ xattr scan — com.apple.quarantine attribute presence/absence.
      CLI-downloaded files (curl, wget) bypass quarantine xattr entirely.
    - hdiutil info — mounted DMG images and their mount points.
    - psutil process tree — Terminal/iTerm2/Warp child processes for ClickFix
      detection (paste-and-run social engineering via messaging apps).
    - Process snapshot — xattr removal processes, installer abuse, unsigned
      execution from ~/Downloads or /tmp.

Detection probes (8):
    1. quarantine_bypass         — xattr -d/-c com.apple.quarantine (T1553.001)
    2. dmg_mount_execute         — process running from DMG mount point (T1204.002)
    3. clickfix_detection        — messaging app + terminal paste attack (T1204.001)
    4. unsigned_download_exec    — unsigned binary from Downloads/tmp (T1553)
    5. cli_download_execute      — CLI download bypasses quarantine (T1105)
    6. suspicious_download_src   — download from unknown domain (T1566)
    7. installer_script_abuse    — installer spawns suspicious child (T1059.002)
    8. quarantine_evasion        — no xattr + process running from path (T1553.001)

Coverage: T1553, T1553.001, T1204, T1204.001, T1204.002, T1105, T1566, T1059.002
"""

from amoskys.agents.os.macos.quarantine_guard.agent import MacOSQuarantineGuardAgent

__all__ = ["MacOSQuarantineGuardAgent"]
