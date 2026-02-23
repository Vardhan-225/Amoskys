#!/usr/bin/env python3
"""Trigger Pack: FlowAgent — Exercise 7 silent network flow probes.

Targeted probes:
    1. PortScanSweepProbe — nc -z port sweep
    2. LateralSMBWinRMProbe — connections on admin ports
    3. DataExfilVolumeSpikeProbe — large outbound transfer
    4. C2BeaconFlowProbe — periodic small connections
    5. CleartextCredentialLeakProbe — cleartext protocol traffic
    6. SuspiciousTunnelProbe — long-lived tunnel pattern
    7. InternalReconDNSFlowProbe — rapid DNS queries

All actions target localhost or non-routable addresses and are safe.
Run with --dry-run to preview without executing.
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import time


def log(msg: str) -> None:
    print(f"  [FLOW] {msg}")


# ── Trigger 1: PortScanSweepProbe ─────────────────────────────────────────


def trigger_port_scan(dry_run: bool = False) -> None:
    """Sweep 25 ports on localhost to trigger vertical scan detection."""
    log("Trigger: PortScanSweepProbe (25 ports on localhost)")

    if dry_run:
        log("  [DRY-RUN] Would scan ports 9000-9024 on 127.0.0.1")
        return

    for port in range(9000, 9025):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect_ex(("127.0.0.1", port))
            s.close()
        except Exception:
            pass
    log("  Scanned 25 ports on 127.0.0.1:9000-9024")


# ── Trigger 2: LateralSMBWinRMProbe ──────────────────────────────────────


def trigger_lateral_movement(dry_run: bool = False) -> None:
    """Connect to admin protocol ports on localhost (SSH=22, SMB=445)."""
    log("Trigger: LateralSMBWinRMProbe")

    ports = [22, 445, 3389, 5985]
    for port in ports:
        if dry_run:
            log(f"  [DRY-RUN] Would connect to 127.0.0.1:{port}")
        else:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect_ex(("127.0.0.1", port))
                s.close()
                log(f"  Probed 127.0.0.1:{port}")
            except Exception:
                log(f"  Port {port} not reachable (expected)")


# ── Trigger 3: DataExfilVolumeSpikeProbe ──────────────────────────────────


def trigger_data_exfil(dry_run: bool = False) -> None:
    """Large download to exercise exfil byte-counting (via curl to localhost)."""
    log("Trigger: DataExfilVolumeSpikeProbe")

    if dry_run:
        log("  [DRY-RUN] Would generate large local transfer")
        return

    # Create a local file and read it over HTTP-like socket (safe)
    try:
        # Just create a large temp file — the flow collector tracks bytes via nettop
        import tempfile

        with tempfile.NamedTemporaryFile(
            dir="/tmp", prefix="eoa_exfil_", suffix=".dat", delete=True
        ) as f:
            f.write(b"X" * (1024 * 1024))  # 1 MB test data
            f.flush()
            log(f"  Generated 1 MB test data: {f.name}")
    except Exception as e:
        log(f"  Skipped: {e}")


# ── Trigger 4: C2BeaconFlowProbe ──────────────────────────────────────────


def trigger_c2_beacon(dry_run: bool = False) -> None:
    """Periodic small connections (beacon-like pattern) to localhost."""
    log("Trigger: C2BeaconFlowProbe (4 periodic connections)")

    if dry_run:
        log("  [DRY-RUN] Would make 4 connections at 2s intervals")
        return

    for i in range(4):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect_ex(("127.0.0.1", 8443))
            # Send small payload (beacon-like)
            try:
                s.send(b"BEACON_CHECK")
            except Exception:
                pass
            s.close()
            log(f"  Beacon {i+1}/4 sent")
        except Exception:
            pass
        time.sleep(2)  # Regular interval


# ── Trigger 5: CleartextCredentialLeakProbe ───────────────────────────────


def trigger_cleartext_creds(dry_run: bool = False) -> None:
    """Connect to cleartext protocol ports (FTP=21, Telnet=23, HTTP=80)."""
    log("Trigger: CleartextCredentialLeakProbe")

    cleartext_ports = [(21, "FTP"), (23, "Telnet"), (80, "HTTP")]
    for port, proto in cleartext_ports:
        if dry_run:
            log(f"  [DRY-RUN] Would connect to 127.0.0.1:{port} ({proto})")
        else:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                s.connect_ex(("127.0.0.1", port))
                s.close()
                log(f"  Connected to {proto} port {port}")
            except Exception:
                log(f"  {proto} port {port} not reachable (expected)")


# ── Trigger 6: SuspiciousTunnelProbe ──────────────────────────────────────


def trigger_tunnel(dry_run: bool = False) -> None:
    """Open a long-lived TCP connection on non-standard port."""
    log("Trigger: SuspiciousTunnelProbe")

    if dry_run:
        log("  [DRY-RUN] Would open long-lived connection on port 4444")
        return

    try:
        # Create a brief socket connection to simulate tunnel start
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect_ex(("127.0.0.1", 4444))
        s.close()
        log("  Probed tunnel port 4444")
    except Exception:
        log("  Port 4444 not reachable (expected)")


# ── Trigger 7: InternalReconDNSFlowProbe ──────────────────────────────────


def trigger_dns_recon(dry_run: bool = False) -> None:
    """Rapid DNS queries to exercise DNS flow recon detection."""
    log("Trigger: InternalReconDNSFlowProbe")

    if dry_run:
        log("  [DRY-RUN] Would resolve 20 hostnames rapidly")
        return

    domains = [f"eoa-test-{i}.invalid" for i in range(20)]
    resolved = 0
    for domain in domains:
        try:
            socket.getaddrinfo(domain, 80, socket.AF_INET, socket.SOCK_STREAM)
        except socket.gaierror:
            pass  # Expected — NXDOMAIN
        resolved += 1
    log(f"  Resolved {resolved} test domains (all NXDOMAIN)")


def main() -> None:
    parser = argparse.ArgumentParser(description="Trigger Pack: FlowAgent probes")
    parser.add_argument(
        "--dry-run", action="store_true", help="Preview without executing"
    )
    args = parser.parse_args()

    print("\n═══ FlowAgent Trigger Pack ═══")

    trigger_port_scan(args.dry_run)
    trigger_lateral_movement(args.dry_run)
    trigger_data_exfil(args.dry_run)
    trigger_c2_beacon(args.dry_run)
    trigger_cleartext_creds(args.dry_run)
    trigger_tunnel(args.dry_run)
    trigger_dns_recon(args.dry_run)

    print("═══ FlowAgent triggers complete ═══\n")


if __name__ == "__main__":
    main()
