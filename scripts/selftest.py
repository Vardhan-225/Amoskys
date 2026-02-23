#!/usr/bin/env python3
"""Agent Selftest Harness - Validate agent instantiation and collect_data output.

This script validates that an agent:
1. Can be instantiated
2. setup() completes successfully
3. collect_data() returns valid output (not strings, proper types)

Usage:
    python -m scripts.selftest kernel_audit
    python -m scripts.selftest protocol_collectors
    python -m scripts.selftest device_discovery
    python -m scripts.selftest --all
"""

import argparse
import sys
from typing import Any, List, Optional


def test_agent(agent_name: str) -> bool:
    """Test a single agent.

    Returns:
        True if all tests pass
    """
    print(f"\n{'='*60}")
    print(f"Testing: {agent_name}")
    print("=" * 60)

    try:
        # Dynamic import based on agent name
        if agent_name == "kernel_audit":
            from amoskys.agents.kernel_audit.kernel_audit_agent import (
                KernelAuditAgent as AgentClass,
            )
        elif agent_name == "protocol_collectors":
            from amoskys.agents.protocol_collectors import (
                ProtocolCollectors as AgentClass,
            )
        elif agent_name == "device_discovery":
            from amoskys.agents.device_discovery import DeviceDiscovery as AgentClass
        elif agent_name == "auth_guard":
            from amoskys.agents.auth import AuthGuardAgent as AgentClass
        elif agent_name == "proc":
            from amoskys.agents.proc import ProcAgent as AgentClass
        elif agent_name == "dns":
            from amoskys.agents.dns import DNSAgent as AgentClass
        elif agent_name == "peripheral":
            from amoskys.agents.peripheral import PeripheralAgent as AgentClass
        elif agent_name == "persistence":
            from amoskys.agents.persistence import PersistenceGuard as AgentClass
        elif agent_name == "fim":
            from amoskys.agents.fim import FIMAgent as AgentClass
        elif agent_name == "flow":
            from amoskys.agents.flow import FlowAgent as AgentClass
        else:
            print(f"  ❌ Unknown agent: {agent_name}")
            return False

        print(f"  ✓ Import successful: {AgentClass.__name__}")

    except ImportError as e:
        print(f"  ❌ Import failed: {e}")
        return False
    except Exception as e:
        print(f"  ❌ Import error: {e}")
        return False

    # Test instantiation
    try:
        agent = AgentClass(device_id="selftest-node")
        print(f"  ✓ Instantiation successful")
    except TypeError as e:
        print(f"  ❌ Instantiation failed (missing abstract method?): {e}")
        return False
    except Exception as e:
        print(f"  ❌ Instantiation failed: {e}")
        return False

    # Test setup
    try:
        result = agent.setup()
        if result:
            print(f"  ✓ setup() returned True")
        else:
            print(f"  ⚠ setup() returned False (probe init may have failed)")
    except Exception as e:
        print(f"  ❌ setup() failed: {e}")
        return False

    # Test collect_data
    try:
        events = agent.collect_data()
        if events is None:
            events = []
        events = list(events) if hasattr(events, "__iter__") else [events]
        print(f"  ✓ collect_data() returned {len(events)} events")

        # Validate event types (should not be plain strings)
        invalid_events = []
        for i, event in enumerate(events):
            if isinstance(event, str):
                invalid_events.append((i, "plain string"))
            elif isinstance(event, dict):
                # Dicts are OK for JSON serialization path
                pass
            elif hasattr(event, "SerializeToString"):
                # Protobuf objects are OK
                pass
            elif hasattr(event, "to_dict"):
                # TelemetryEvent objects are OK
                pass
            else:
                invalid_events.append((i, type(event).__name__))

        if invalid_events:
            print(f"  ⚠ Invalid event types found: {invalid_events}")
        else:
            print(f"  ✓ All events have valid types")

    except Exception as e:
        print(f"  ❌ collect_data() failed: {e}")
        return False

    # Check probe count if available
    if hasattr(agent, "probes") or hasattr(agent, "_probes"):
        probes = getattr(agent, "probes", getattr(agent, "_probes", []))
        print(f"  ✓ Probes registered: {len(probes)}")
        for p in probes:
            status = "✓" if getattr(p, "enabled", True) else "○"
            print(f"      {status} {p.name}")

    print(f"\n  ✅ {agent_name} PASSED all checks")
    return True


def main():
    parser = argparse.ArgumentParser(description="AMOSKYS Agent Selftest Harness")
    parser.add_argument(
        "agent",
        nargs="?",
        help="Agent to test (kernel_audit, protocol_collectors, device_discovery, etc.)",
    )
    parser.add_argument("--all", action="store_true", help="Test all known agents")
    parser.add_argument(
        "--trinity",
        action="store_true",
        help="Test Trinity agents (kernel_audit, protocol_collectors, device_discovery)",
    )

    args = parser.parse_args()

    if args.all:
        agents = [
            "kernel_audit",
            "protocol_collectors",
            "device_discovery",
            "auth_guard",
            "proc",
            "dns",
            "peripheral",
            "persistence",
            "fim",
            "flow",
        ]
    elif args.trinity:
        agents = ["kernel_audit", "protocol_collectors", "device_discovery"]
    elif args.agent:
        agents = [args.agent]
    else:
        parser.print_help()
        sys.exit(1)

    print("\n" + "=" * 60)
    print("AMOSKYS AGENT SELFTEST HARNESS")
    print("=" * 60)

    results = {}
    for agent in agents:
        results[agent] = test_agent(agent)

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    passed = sum(1 for v in results.values() if v)
    failed = len(results) - passed

    for agent, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {status}  {agent}")

    print(f"\nTotal: {passed}/{len(results)} passed")

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
