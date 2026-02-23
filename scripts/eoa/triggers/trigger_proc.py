#!/usr/bin/env python3
"""Trigger Pack: ProcAgent — Exercise 3 silent process probes.

Targeted probes:
    1. ScriptInterpreterProbe — suspicious script invocations
    2. ProcessTreeAnomalyProbe — unusual parent→child combos
    3. HighCPUAndMemoryProbe — brief CPU spike (cryptomining pattern)

All actions are safe, reversible, and self-cleaning.
Run with --dry-run to preview without executing.

Usage:
    python trigger_proc.py
    python trigger_proc.py --dry-run
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time

SANDBOX = "/tmp/eoa_proc_sandbox"


def log(msg: str) -> None:
    print(f"  [PROC] {msg}")


def setup_sandbox() -> None:
    os.makedirs(SANDBOX, exist_ok=True)
    log(f"Sandbox created: {SANDBOX}")


def cleanup_sandbox() -> None:
    if os.path.exists(SANDBOX):
        shutil.rmtree(SANDBOX, ignore_errors=True)
        log(f"Sandbox cleaned: {SANDBOX}")


# ── Trigger 1: ScriptInterpreterProbe ──────────────────────────────────────


def trigger_script_interpreter(dry_run: bool = False) -> None:
    """Run scripts with suspicious patterns that ScriptInterpreterProbe detects.

    Patterns: base64 decode, eval/exec, python -c, bash -c with pipe.
    """
    log("Trigger: ScriptInterpreterProbe")

    scripts = [
        # Python with -c and exec pattern
        [sys.executable, "-c", "import base64; print('eoa_test')"],
        # Bash -c with eval pattern
        ["bash", "-c", "echo ZW9hX3Rlc3Q= | base64 -d"],
        # Python with base64 decode pattern (harmless)
        [sys.executable, "-c", "exec('print(42)')"],
    ]

    for cmd in scripts:
        if dry_run:
            log(f"  [DRY-RUN] Would run: {' '.join(cmd)}")
        else:
            try:
                subprocess.run(cmd, capture_output=True, timeout=5)
                log(f"  Executed: {' '.join(cmd[:3])}")
            except Exception as e:
                log(f"  Skipped: {e}")


# ── Trigger 2: ProcessTreeAnomalyProbe ─────────────────────────────────────


def trigger_process_tree_anomaly(dry_run: bool = False) -> None:
    """Spawn unusual parent→child process trees.

    The probe watches for: python spawning bash, bash spawning python, etc.
    """
    log("Trigger: ProcessTreeAnomalyProbe")

    # Python → bash → echo (unusual tree)
    cmd1 = ["bash", "-c", "echo eoa_tree_test_1"]
    # Python → /usr/bin/script interpreter chain
    cmd2 = [
        sys.executable,
        "-c",
        "import subprocess; subprocess.run(['bash', '-c', 'echo eoa_tree_test_2'], capture_output=True)",
    ]

    for cmd in [cmd1, cmd2]:
        if dry_run:
            log(f"  [DRY-RUN] Would spawn: {' '.join(cmd[:3])}")
        else:
            try:
                subprocess.run(cmd, capture_output=True, timeout=5)
                log(f"  Spawned: {' '.join(cmd[:3])}")
            except Exception as e:
                log(f"  Skipped: {e}")


# ── Trigger 3: HighCPUAndMemoryProbe ───────────────────────────────────────


def trigger_high_cpu(dry_run: bool = False, duration: int = 3) -> None:
    """Brief CPU spike to exercise HighCPUAndMemoryProbe.

    Default 3 seconds — safe and short-lived.
    """
    log(f"Trigger: HighCPUAndMemoryProbe ({duration}s burst)")

    script = f"""
import time, os
end = time.monotonic() + {duration}
x = 0
while time.monotonic() < end:
    x += 1
"""

    if dry_run:
        log(f"  [DRY-RUN] Would run CPU spike for {duration}s")
    else:
        try:
            proc = subprocess.Popen(
                [sys.executable, "-c", script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            log(f"  CPU spike PID {proc.pid} running for {duration}s...")
            proc.wait(timeout=duration + 5)
            log("  CPU spike completed")
        except Exception as e:
            log(f"  Skipped: {e}")


# ── Trigger 4: BinaryFromTempProbe ─────────────────────────────────────────


def trigger_binary_from_temp(dry_run: bool = False) -> None:
    """Copy a binary to /tmp and execute it."""
    log("Trigger: BinaryFromTempProbe")

    src = shutil.which("echo")
    if not src:
        src = "/bin/echo"

    dst = os.path.join(SANDBOX, "eoa_temp_binary")

    if dry_run:
        log(f"  [DRY-RUN] Would copy {src} → {dst} and execute")
    else:
        try:
            shutil.copy2(src, dst)
            os.chmod(dst, 0o755)
            subprocess.run([dst, "eoa_temp_exec_test"], capture_output=True, timeout=5)
            log(f"  Executed binary from temp: {dst}")
            os.remove(dst)
        except Exception as e:
            log(f"  Skipped: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Trigger Pack: ProcAgent probes")
    parser.add_argument(
        "--dry-run", action="store_true", help="Preview without executing"
    )
    args = parser.parse_args()

    print("\n═══ ProcAgent Trigger Pack ═══")
    setup_sandbox()

    try:
        trigger_script_interpreter(args.dry_run)
        trigger_process_tree_anomaly(args.dry_run)
        trigger_high_cpu(args.dry_run)
        trigger_binary_from_temp(args.dry_run)
    finally:
        cleanup_sandbox()

    print("═══ ProcAgent triggers complete ═══\n")


if __name__ == "__main__":
    main()
