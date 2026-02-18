#!/usr/bin/env python3
"""Trigger Pack: FIM Agent — Exercise 7 silent file integrity probes.

Targeted probes:
    1. SUIDBitChangeProbe — SUID bit on file in sandbox
    2. ServiceCreationProbe — LaunchAgent plist creation
    3. WebShellDropProbe — PHP webshell pattern file
    4. ConfigBackdoorProbe — Backdoored SSH config pattern
    5. LibraryHijackProbe — .so file in lib path
    6. BootloaderTamperProbe — Simulated /boot file change
    7. WorldWritableSensitiveProbe — world-writable permission

All actions use sandboxed paths (/tmp/eoa_fim_sandbox/) and are self-cleaning.
Run with --dry-run to preview without executing.
"""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import time

SANDBOX = "/tmp/eoa_fim_sandbox"


def log(msg: str) -> None:
    print(f"  [FIM] {msg}")


def setup_sandbox() -> None:
    """Create sandbox directory tree mimicking real paths."""
    dirs = [
        SANDBOX,
        f"{SANDBOX}/etc/ssh",
        f"{SANDBOX}/etc/sudoers.d",
        f"{SANDBOX}/var/www/html",
        f"{SANDBOX}/usr/lib",
        f"{SANDBOX}/boot",
        f"{SANDBOX}/Library/LaunchAgents",
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)
    log(f"Sandbox created: {SANDBOX}")


def cleanup_sandbox() -> None:
    if os.path.exists(SANDBOX):
        shutil.rmtree(SANDBOX, ignore_errors=True)
        log(f"Sandbox cleaned: {SANDBOX}")


# ── Trigger 1: SUIDBitChangeProbe ──────────────────────────────────────────

def trigger_suid_bit(dry_run: bool = False) -> None:
    """Create file and set SUID bit."""
    log("Trigger: SUIDBitChangeProbe")
    path = f"{SANDBOX}/eoa_suid_binary"

    if dry_run:
        log(f"  [DRY-RUN] Would create {path} with SUID bit")
        return

    with open(path, "w") as f:
        f.write("#!/bin/bash\necho suid_test\n")
    os.chmod(path, 0o4755)  # SUID set
    log(f"  Created SUID file: {path} (mode 4755)")
    time.sleep(0.1)


# ── Trigger 2: ServiceCreationProbe ────────────────────────────────────────

def trigger_service_creation(dry_run: bool = False) -> None:
    """Create a macOS LaunchAgent plist (in sandbox)."""
    log("Trigger: ServiceCreationProbe")
    path = f"{SANDBOX}/Library/LaunchAgents/com.eoa.test.plist"

    plist_content = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.eoa.test</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/echo</string>
        <string>eoa_trigger_test</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
"""

    if dry_run:
        log(f"  [DRY-RUN] Would create LaunchAgent plist: {path}")
        return

    with open(path, "w") as f:
        f.write(plist_content)
    log(f"  Created LaunchAgent: {path}")
    time.sleep(0.1)


# ── Trigger 3: WebShellDropProbe ───────────────────────────────────────────

def trigger_webshell_drop(dry_run: bool = False) -> None:
    """Create files with webshell patterns in web root sandbox."""
    log("Trigger: WebShellDropProbe")

    shells = {
        f"{SANDBOX}/var/www/html/cmd.php": '<?php eval($_GET["cmd"]); ?>',
        f"{SANDBOX}/var/www/html/upload.jsp": '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>',
        f"{SANDBOX}/var/www/html/shell.aspx": '<%@ Page Language="C#" %><%eval(Request["cmd"])%>',
    }

    for path, content in shells.items():
        if dry_run:
            log(f"  [DRY-RUN] Would create webshell: {path}")
        else:
            with open(path, "w") as f:
                f.write(content)
            log(f"  Created webshell: {path}")
    time.sleep(0.1)


# ── Trigger 4: ConfigBackdoorProbe ─────────────────────────────────────────

def trigger_config_backdoor(dry_run: bool = False) -> None:
    """Create sshd_config and sudoers with backdoor patterns."""
    log("Trigger: ConfigBackdoorProbe")

    sshd_path = f"{SANDBOX}/etc/ssh/sshd_config"
    sudoers_path = f"{SANDBOX}/etc/sudoers.d/eoa_test"

    sshd_content = """\
# EOA trigger — backdoored sshd_config
Port 22
PermitRootLogin yes
PasswordAuthentication yes
"""

    sudoers_content = """\
# EOA trigger — backdoored sudoers
eoa_attacker ALL=(ALL) NOPASSWD:ALL
"""

    for path, content in [(sshd_path, sshd_content), (sudoers_path, sudoers_content)]:
        if dry_run:
            log(f"  [DRY-RUN] Would create backdoored config: {path}")
        else:
            with open(path, "w") as f:
                f.write(content)
            log(f"  Created backdoored config: {path}")
    time.sleep(0.1)


# ── Trigger 5: LibraryHijackProbe ─────────────────────────────────────────

def trigger_library_hijack(dry_run: bool = False) -> None:
    """Create a suspicious .so file in lib directory (sandbox)."""
    log("Trigger: LibraryHijackProbe")
    path = f"{SANDBOX}/usr/lib/libeoa_malicious.so"

    if dry_run:
        log(f"  [DRY-RUN] Would create: {path}")
        return

    with open(path, "wb") as f:
        f.write(b"\x7fELF" + b"\x00" * 100)  # Fake ELF header
    log(f"  Created suspicious library: {path}")
    time.sleep(0.1)


# ── Trigger 6: BootloaderTamperProbe ──────────────────────────────────────

def trigger_bootloader_tamper(dry_run: bool = False) -> None:
    """Create simulated boot file changes (sandbox)."""
    log("Trigger: BootloaderTamperProbe")

    files = [
        f"{SANDBOX}/boot/vmlinuz-eoa-test",
        f"{SANDBOX}/boot/initrd.img-eoa-test",
        f"{SANDBOX}/boot/grub/grub.cfg",
    ]

    os.makedirs(f"{SANDBOX}/boot/grub", exist_ok=True)

    for path in files:
        if dry_run:
            log(f"  [DRY-RUN] Would create: {path}")
        else:
            with open(path, "w") as f:
                f.write("EOA_BOOT_TAMPER_TEST\n")
            log(f"  Created boot file: {path}")
    time.sleep(0.1)


# ── Trigger 7: WorldWritableSensitiveProbe ────────────────────────────────

def trigger_world_writable(dry_run: bool = False) -> None:
    """Create sensitive file and make it world-writable."""
    log("Trigger: WorldWritableSensitiveProbe")
    path = f"{SANDBOX}/etc/eoa_sensitive_config"

    if dry_run:
        log(f"  [DRY-RUN] Would create {path} with mode 0o777")
        return

    with open(path, "w") as f:
        f.write("# Sensitive config\npassword=secret123\n")
    os.chmod(path, 0o777)  # World-writable
    log(f"  Created world-writable file: {path} (mode 0777)")
    time.sleep(0.1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Trigger Pack: FIM Agent probes")
    parser.add_argument("--dry-run", action="store_true", help="Preview without executing")
    args = parser.parse_args()

    print("\n═══ FIM Agent Trigger Pack ═══")
    setup_sandbox()

    try:
        trigger_suid_bit(args.dry_run)
        trigger_service_creation(args.dry_run)
        trigger_webshell_drop(args.dry_run)
        trigger_config_backdoor(args.dry_run)
        trigger_library_hijack(args.dry_run)
        trigger_bootloader_tamper(args.dry_run)
        trigger_world_writable(args.dry_run)
    finally:
        cleanup_sandbox()

    print("═══ FIM triggers complete ═══\n")


if __name__ == "__main__":
    main()
