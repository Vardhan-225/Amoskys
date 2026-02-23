#!/usr/bin/env python3
"""AMOSKYS Coverage Gate Scorecard.

Computes 3 numbers that serve as the north star for every sprint:

1. **Surface Coverage %** = macOS-active probes / total probes
2. **Probe Proof %** = probes proven to fire (in tests/scenarios) / macOS-active probes
3. **Reliability %** = 1 - (error_cycles / total_cycles) [from EOA results if available]

Usage:
    python coverage_scorecard.py
    python coverage_scorecard.py --target 80      # CI gate: exit 1 if Probe Proof < 80%
    python coverage_scorecard.py --json            # JSON output
    python coverage_scorecard.py --eoa-results results/eoa_latest.json

The script introspects the codebase to discover all probes, their platform
support, and cross-references against the 25-scenario test suite.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import platform
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Ensure src is on path
_root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_root / "src"))


# =============================================================================
# Probe Discovery
# =============================================================================

# (module_path, factory_function_or_probe_classes)
AGENT_PROBE_MAP = {
    "proc": {
        "module": "amoskys.agents.proc.probes",
        "factory": "create_proc_probes",
    },
    "fim": {
        "module": "amoskys.agents.fim.probes",
        "factory": "create_fim_probes",
    },
    "flow": {
        "module": "amoskys.agents.flow.probes",
        "factory": "create_flow_probes",
    },
    "dns": {
        "module": "amoskys.agents.dns.probes",
        "factory": "create_dns_probes",
    },
    "peripheral": {
        "module": "amoskys.agents.peripheral.probes",
        "factory": "create_peripheral_probes",
    },
    "auth": {
        "module": "amoskys.agents.auth.probes",
        "factory": "create_auth_probes",
    },
    "persistence": {
        "module": "amoskys.agents.persistence.probes",
        "factory": "create_persistence_probes",
    },
    "kernel_audit": {
        "module": "amoskys.agents.kernel_audit.probes",
        "factory": "create_kernel_audit_probes",
    },
}


def discover_probes() -> List[Dict[str, Any]]:
    """Discover all probes across all agents via factory functions."""
    all_probes = []

    for agent_name, info in AGENT_PROBE_MAP.items():
        try:
            mod = importlib.import_module(info["module"])
            factory = getattr(mod, info["factory"])
            probes = factory()

            for probe in probes:
                platforms = getattr(probe, "platforms", [])
                # If no platforms attribute, assume all
                if not platforms:
                    platforms = ["linux", "darwin", "windows"]

                all_probes.append(
                    {
                        "agent": agent_name,
                        "name": probe.name,
                        "description": getattr(probe, "description", ""),
                        "platforms": platforms,
                        "enabled": getattr(probe, "enabled", True),
                        "mitre_techniques": getattr(probe, "mitre_techniques", []),
                        "darwin_active": "darwin" in platforms,
                    }
                )

        except Exception as e:
            print(
                f"  WARNING: Could not load {agent_name} probes: {e}", file=sys.stderr
            )

    return all_probes


# =============================================================================
# Scenario Test Discovery
# =============================================================================

# Map scenario class names to the probe names they exercise
SCENARIO_PROBE_MAP = {
    "TestScenario01_BinaryFromTemp": "binary_from_temp",
    "TestScenario02_CurlPipeShell": "lolbin_execution",
    "TestScenario03_PythonReverseShell": "script_interpreter",
    "TestScenario04_LaunchAgentPersistence": "launchd_persistence",
    "TestScenario05_ShellProfileHijack": "shell_profile_hijack",
    "TestScenario06_CronPersistence": "cron_persistence",
    "TestScenario07_WebshellDrop": "webshell_drop",
    "TestScenario08_WorldWritable": "world_writable_sensitive",
    "TestScenario09_NXDomainBurst": "nxdomain_burst",
    "TestScenario10_DGADomains": "dga_score",
    "TestScenario11_USBStorage": "usb_storage",
    "TestScenario12_SudoElevation": "sudo_elevation",
    "TestScenario13_SUIDbitChange": "suid_bit_change",
    "TestScenario14_ConfigBackdoor": "config_backdoor",
    "TestScenario15_SSHKeyBackdoor": "ssh_key_backdoor",
    "TestScenario16_HiddenFile": "hidden_file_persistence",
    "TestScenario17_PortScan": "port_scan_sweep",
    "TestScenario18_DataExfil": "data_exfil_volume_spike",
    "TestScenario19_C2Beacon": "c2_beacon_flow",
    "TestScenario20_SuspiciousTunnel": "suspicious_tunnel",
    "TestScenario21_SuspiciousTLD": "suspicious_tld",
    "TestScenario22_DNSTunneling": "large_txt_tunneling",
    "TestScenario23_SSHBruteForce": "ssh_bruteforce",
    "TestScenario24_ExecveFromTmp": "execve_high_risk",
    "TestScenario25_SyscallFlood": "syscall_flood",
}


def get_proven_probes() -> Set[str]:
    """Return set of probe names proven to fire in the scenario suite."""
    return set(SCENARIO_PROBE_MAP.values())


def scan_test_files_for_additional_probes(tests_dir: Path) -> Set[str]:
    """Scan test files for additional probe names exercised outside scenarios."""
    extra: Set[str] = set()

    for test_file in tests_dir.glob("test_*.py"):
        try:
            content = test_file.read_text()
            # Look for probe instantiation patterns
            matches = re.findall(r"(\w+Probe)\(\)", content)
            for m in matches:
                # Convert CamelCase to snake_case probe name
                snake = re.sub(r"(?<!^)(?=[A-Z])", "_", m.replace("Probe", "")).lower()
                extra.add(snake)
        except Exception:
            pass

    return extra


# =============================================================================
# Scorecard Computation
# =============================================================================


def compute_scorecard(
    probes: List[Dict[str, Any]],
    proven_names: Set[str],
    eoa_results: Optional[Dict] = None,
) -> Dict[str, Any]:
    """Compute the 3-number scorecard."""

    total_probes = len(probes)
    darwin_probes = [p for p in probes if p["darwin_active"]]
    darwin_count = len(darwin_probes)

    # 1. Surface Coverage %
    surface_coverage = (darwin_count / total_probes * 100) if total_probes > 0 else 0

    # 2. Probe Proof %
    proven_darwin = 0
    proven_list = []
    unproven_list = []

    for p in darwin_probes:
        if p["name"] in proven_names:
            proven_darwin += 1
            proven_list.append(p["name"])
        else:
            unproven_list.append(f"{p['agent']}::{p['name']}")

    probe_proof = (proven_darwin / darwin_count * 100) if darwin_count > 0 else 0

    # 3. Reliability % (from EOA results if available)
    reliability = 100.0
    if eoa_results:
        total_cycles = eoa_results.get("total_cycles", 0)
        error_cycles = eoa_results.get("error_cycles", 0)
        if total_cycles > 0:
            reliability = (1 - error_cycles / total_cycles) * 100

    scorecard = {
        "timestamp": __import__("datetime").datetime.now().isoformat(),
        "platform": platform.system(),
        "totals": {
            "total_probes": total_probes,
            "darwin_active_probes": darwin_count,
            "proven_probes": proven_darwin,
            "unproven_probes": darwin_count - proven_darwin,
        },
        "scores": {
            "surface_coverage_pct": round(surface_coverage, 1),
            "probe_proof_pct": round(probe_proof, 1),
            "reliability_pct": round(reliability, 1),
        },
        "targets": {
            "surface_coverage_target": 85,
            "probe_proof_target": 80,
            "reliability_target": 95,
        },
        "details": {
            "proven": sorted(proven_list),
            "unproven": sorted(unproven_list),
        },
        "agents": {},
    }

    # Per-agent breakdown
    for agent_name in AGENT_PROBE_MAP:
        agent_probes = [p for p in probes if p["agent"] == agent_name]
        agent_darwin = [p for p in agent_probes if p["darwin_active"]]
        agent_proven = [p for p in agent_darwin if p["name"] in proven_names]

        scorecard["agents"][agent_name] = {
            "total": len(agent_probes),
            "darwin_active": len(agent_darwin),
            "proven": len(agent_proven),
            "probe_names": [p["name"] for p in agent_probes],
        }

    return scorecard


# =============================================================================
# Output Formatting
# =============================================================================


def print_markdown_scorecard(sc: Dict[str, Any]) -> None:
    """Print human-readable markdown scorecard."""
    scores = sc["scores"]
    totals = sc["totals"]
    targets = sc["targets"]

    print("\n" + "=" * 60)
    print("  AMOSKYS COVERAGE GATE SCORECARD")
    print("=" * 60)

    # Big 3 numbers
    def _bar(pct: float, target: float) -> str:
        ok = pct >= target
        symbol = "PASS" if ok else "FAIL"
        filled = int(pct / 5)
        return f"[{'#' * filled}{'.' * (20 - filled)}] {pct:5.1f}% (target: {target}%) {symbol}"

    print(
        f"\n  1. Surface Coverage: {_bar(scores['surface_coverage_pct'], targets['surface_coverage_target'])}"
    )
    print(
        f"  2. Probe Proof:      {_bar(scores['probe_proof_pct'], targets['probe_proof_target'])}"
    )
    print(
        f"  3. Reliability:      {_bar(scores['reliability_pct'], targets['reliability_target'])}"
    )

    print(f"\n  Total probes:        {totals['total_probes']}")
    print(f"  macOS-active:        {totals['darwin_active_probes']}")
    print(f"  Proven (fired):      {totals['proven_probes']}")
    print(f"  Unproven (silent):   {totals['unproven_probes']}")

    # Per-agent table
    print(f"\n  {'Agent':<20} {'Total':>6} {'macOS':>6} {'Proven':>7} {'Proof%':>7}")
    print("  " + "-" * 48)

    for agent_name, data in sc["agents"].items():
        darwin = data["darwin_active"]
        proven = data["proven"]
        pct = (proven / darwin * 100) if darwin > 0 else 0
        print(
            f"  {agent_name:<20} {data['total']:>6} {darwin:>6} {proven:>7} {pct:>6.0f}%"
        )

    # Unproven list
    unproven = sc["details"]["unproven"]
    if unproven:
        print(f"\n  Unproven probes ({len(unproven)}):")
        for name in unproven:
            print(f"    - {name}")

    print("\n" + "=" * 60 + "\n")


# =============================================================================
# Main
# =============================================================================


def main() -> None:
    parser = argparse.ArgumentParser(description="AMOSKYS Coverage Gate Scorecard")
    parser.add_argument(
        "--target",
        type=float,
        default=0,
        help="CI gate: exit 1 if Probe Proof %% < target",
    )
    parser.add_argument(
        "--json", action="store_true", help="Output JSON instead of markdown"
    )
    parser.add_argument(
        "--eoa-results",
        type=str,
        default=None,
        help="Path to EOA results JSON for reliability calculation",
    )
    args = parser.parse_args()

    # Discover probes
    probes = discover_probes()
    if not probes:
        print("ERROR: No probes discovered. Check PYTHONPATH.", file=sys.stderr)
        sys.exit(2)

    # Get proven probes from scenario tests + any additional test files
    proven = get_proven_probes()
    tests_dir = _root / "tests" / "agents"
    if tests_dir.exists():
        extra = scan_test_files_for_additional_probes(tests_dir)
        proven |= extra

    # Load EOA results if provided
    eoa_results = None
    if args.eoa_results and os.path.exists(args.eoa_results):
        with open(args.eoa_results) as f:
            eoa_results = json.load(f)

    # Compute scorecard
    scorecard = compute_scorecard(probes, proven, eoa_results)

    # Output
    if args.json:
        print(json.dumps(scorecard, indent=2))
    else:
        print_markdown_scorecard(scorecard)

    # CI gate check
    if args.target > 0:
        probe_proof = scorecard["scores"]["probe_proof_pct"]
        if probe_proof < args.target:
            print(
                f"GATE FAILED: Probe Proof {probe_proof:.1f}% < target {args.target}%",
                file=sys.stderr,
            )
            sys.exit(1)
        else:
            print(
                f"GATE PASSED: Probe Proof {probe_proof:.1f}% >= target {args.target}%"
            )


if __name__ == "__main__":
    main()
