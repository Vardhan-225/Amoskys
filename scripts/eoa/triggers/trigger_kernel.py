#!/usr/bin/env python3
"""Trigger Pack: KernelAudit — Exercise 7 silent kernel audit probes.

Targeted probes:
    1. ExecveHighRiskProbe — execute from /tmp
    2. PrivEscSyscallProbe — simulated setuid event
    3. KernelModuleLoadProbe — simulated module load
    4. PtraceAbuseProbe — simulated ptrace attempt
    5. FilePermissionTamperProbe — chmod sensitive files
    6. AuditTamperProbe — access audit config files
    7. SyscallFloodProbe — rapid syscall burst

Most kernel triggers create the actual filesystem conditions that generate
OpenBSM audit trail entries. Some are simulated via file operations in
sandbox paths.

Run with --dry-run to preview without executing.
"""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import subprocess
import sys
import time

SANDBOX = "/tmp/eoa_kernel_sandbox"


def log(msg: str) -> None:
    print(f"  [KERNEL] {msg}")


def setup_sandbox() -> None:
    dirs = [
        SANDBOX,
        f"{SANDBOX}/etc/audit",
        f"{SANDBOX}/etc/ssh",
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)
    log(f"Sandbox created: {SANDBOX}")


def cleanup_sandbox() -> None:
    if os.path.exists(SANDBOX):
        shutil.rmtree(SANDBOX, ignore_errors=True)
        log(f"Sandbox cleaned: {SANDBOX}")


# ── Trigger 1: ExecveHighRiskProbe ────────────────────────────────────────

def trigger_execve_from_tmp(dry_run: bool = False) -> None:
    """Execute a binary from /tmp (triggers execve audit event)."""
    log("Trigger: ExecveHighRiskProbe")

    script_path = f"{SANDBOX}/eoa_execve_test.sh"
    content = "#!/bin/bash\necho eoa_execve_test\nexit 0\n"

    if dry_run:
        log(f"  [DRY-RUN] Would create and execute: {script_path}")
        return

    with open(script_path, "w") as f:
        f.write(content)
    os.chmod(script_path, 0o755)

    try:
        result = subprocess.run([script_path], capture_output=True, timeout=5)
        log(f"  Executed from /tmp: {script_path} (exit={result.returncode})")
    except Exception as e:
        log(f"  Execution failed: {e}")

    # Also execute a Python script from /tmp
    py_path = f"{SANDBOX}/eoa_execve_test.py"
    with open(py_path, "w") as f:
        f.write("#!/usr/bin/env python3\nprint('eoa_py_execve')\n")
    os.chmod(py_path, 0o755)

    try:
        result = subprocess.run([sys.executable, py_path], capture_output=True, timeout=5)
        log(f"  Executed Python from /tmp: {py_path}")
    except Exception as e:
        log(f"  Execution failed: {e}")


# ── Trigger 2: PrivEscSyscallProbe (simulated) ───────────────────────────

def trigger_privesc_simulation(dry_run: bool = False) -> None:
    """Create files that mimic privilege escalation patterns.

    NOTE: Actual setuid() calls require root. We create SUID binaries
    in the sandbox which the audit trail will record on execution.
    """
    log("Trigger: PrivEscSyscallProbe (simulated)")

    path = f"{SANDBOX}/eoa_suid_binary"

    if dry_run:
        log(f"  [DRY-RUN] Would create SUID binary: {path}")
        return

    # Create a script and set SUID (won't actually grant root, but
    # the audit trail records the attempt)
    with open(path, "w") as f:
        f.write("#!/bin/bash\nwhoami\n")
    os.chmod(path, 0o4755)
    log(f"  Created SUID binary: {path} (mode 4755)")

    try:
        subprocess.run([path], capture_output=True, timeout=5)
        log("  Executed SUID binary (audit trail recorded)")
    except Exception as e:
        log(f"  Execution note: {e}")


# ── Trigger 3: KernelModuleLoadProbe (simulated) ─────────────────────────

def trigger_module_load_simulation(dry_run: bool = False) -> None:
    """Create a fake .kext bundle in sandbox (macOS kernel extension pattern)."""
    log("Trigger: KernelModuleLoadProbe (simulated)")

    kext_dir = f"{SANDBOX}/eoa_test.kext/Contents"

    if dry_run:
        log(f"  [DRY-RUN] Would create kext bundle: {kext_dir}")
        return

    os.makedirs(kext_dir, exist_ok=True)
    info_plist = f"{kext_dir}/Info.plist"
    with open(info_plist, "w") as f:
        f.write("""\
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.eoa.test.kext</string>
    <key>CFBundleName</key>
    <string>EOA Test Kext</string>
</dict>
</plist>
""")
    log(f"  Created fake kext bundle: {SANDBOX}/eoa_test.kext")


# ── Trigger 4: PtraceAbuseProbe (simulated) ──────────────────────────────

def trigger_ptrace_simulation(dry_run: bool = False) -> None:
    """Use lldb/dtruss-like patterns to trigger ptrace audit events.

    On macOS, `sample` is a safe way to trigger process inspection.
    """
    log("Trigger: PtraceAbuseProbe (simulated)")

    if dry_run:
        log("  [DRY-RUN] Would use sample to inspect own process")
        return

    # `sample` is a macOS tool that inspects processes (triggers audit events)
    pid = os.getpid()
    try:
        subprocess.run(
            ["sample", str(pid), "1", "-mayDie"],
            capture_output=True,
            timeout=5,
        )
        log(f"  Sampled own process PID {pid}")
    except FileNotFoundError:
        log("  sample not available (non-macOS)")
    except Exception as e:
        log(f"  Sample note: {e}")


# ── Trigger 5: FilePermissionTamperProbe ──────────────────────────────────

def trigger_permission_tamper(dry_run: bool = False) -> None:
    """chmod sensitive files in sandbox (triggers audit events)."""
    log("Trigger: FilePermissionTamperProbe")

    files = {
        f"{SANDBOX}/etc/ssh/sshd_config": "# sshd config\n",
        f"{SANDBOX}/etc/eoa_shadow": "root:$6$...:19000:0:99999:7:::\n",
        f"{SANDBOX}/etc/eoa_sudoers": "root ALL=(ALL) ALL\n",
    }

    for path, content in files.items():
        if dry_run:
            log(f"  [DRY-RUN] Would chmod 0777: {path}")
        else:
            with open(path, "w") as f:
                f.write(content)
            # Change permissions (triggers audit event on real paths)
            os.chmod(path, 0o777)
            log(f"  chmod 0777: {path}")
            # Restore to safe
            os.chmod(path, 0o600)
            log(f"  Restored to 0600: {path}")


# ── Trigger 6: AuditTamperProbe (simulated) ──────────────────────────────

def trigger_audit_tamper(dry_run: bool = False) -> None:
    """Access audit configuration files in sandbox."""
    log("Trigger: AuditTamperProbe (simulated)")

    audit_files = [
        f"{SANDBOX}/etc/audit/audit.rules",
        f"{SANDBOX}/etc/audit/auditd.conf",
    ]

    for path in audit_files:
        if dry_run:
            log(f"  [DRY-RUN] Would read/write: {path}")
        else:
            with open(path, "w") as f:
                f.write("# EOA trigger — audit config access\n")
            log(f"  Wrote audit config: {path}")
            # Read it back (simulates tampering inspection)
            with open(path, "r") as f:
                _ = f.read()
            log(f"  Read audit config: {path}")


# ── Trigger 7: SyscallFloodProbe ──────────────────────────────────────────

def trigger_syscall_flood(dry_run: bool = False) -> None:
    """Generate rapid syscalls (stat/open/close burst)."""
    log("Trigger: SyscallFloodProbe")

    if dry_run:
        log("  [DRY-RUN] Would generate 200 rapid stat() calls")
        return

    # Rapid stat() calls on sandbox files
    target = f"{SANDBOX}/eoa_flood_target"
    with open(target, "w") as f:
        f.write("flood_test\n")

    count = 200
    for _ in range(count):
        os.stat(target)
    log(f"  Generated {count} rapid stat() calls on {target}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Trigger Pack: KernelAudit probes")
    parser.add_argument("--dry-run", action="store_true", help="Preview without executing")
    args = parser.parse_args()

    print("\n═══ KernelAudit Trigger Pack ═══")
    setup_sandbox()

    try:
        trigger_execve_from_tmp(args.dry_run)
        trigger_privesc_simulation(args.dry_run)
        trigger_module_load_simulation(args.dry_run)
        trigger_ptrace_simulation(args.dry_run)
        trigger_permission_tamper(args.dry_run)
        trigger_audit_tamper(args.dry_run)
        trigger_syscall_flood(args.dry_run)
    finally:
        cleanup_sandbox()

    print("═══ KernelAudit triggers complete ═══\n")


if __name__ == "__main__":
    main()
