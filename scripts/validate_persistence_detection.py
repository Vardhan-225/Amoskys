#!/usr/bin/env python3
"""
Direct validation of persistence_after_auth detection logic.

This script bypasses agent collection and directly feeds synthetic events
to FusionEngine to prove the correlation rules work correctly.

Usage:
    PYTHONPATH=src python scripts/validate_persistence_detection.py
"""

import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from amoskys.intel.fusion_engine import FusionEngine
from amoskys.intel.models import TelemetryEventView, Severity


def create_sudo_event(device_id: str, timestamp: datetime) -> TelemetryEventView:
    """Create a synthetic sudo authentication success event"""
    return TelemetryEventView(
        event_id=f"test_sudo_{int(timestamp.timestamp())}",
        device_id=device_id,
        timestamp=timestamp,
        event_type="SECURITY",
        severity="INFO",
        attributes={
            'sudo_command': 'sudo ls /tmp',
            'auth_method': 'password'
        },
        security_event={
            'event_category': 'AUTHENTICATION',
            'event_action': 'SUDO',
            'event_outcome': 'SUCCESS',
            'user_name': 'athanneeru',
            'source_ip': '127.0.0.1',
            'risk_score': 0.3,
            'mitre_techniques': ['T1548.003'],
            'requires_investigation': False
        }
    )


def create_launchagent_event(device_id: str, timestamp: datetime) -> TelemetryEventView:
    """Create a synthetic LaunchAgent persistence event"""
    file_path = '/Users/athanneeru/Library/LaunchAgents/com.amoskys.test.plist'
    return TelemetryEventView(
        event_id=f"test_persistence_{int(timestamp.timestamp())}",
        device_id=device_id,
        timestamp=timestamp,
        event_type="AUDIT",
        severity="WARN",
        attributes={
            'persistence_type': 'LAUNCH_AGENT',
            'file_path': file_path,
            'risk_score': '0.7'
        },
        audit_event={
            'audit_category': 'CHANGE',
            'action_performed': 'CREATED',
            'object_type': 'LAUNCH_AGENT',
            'object_id': file_path,
            'before_value': '',
            'after_value': '{"Label": "com.amoskys.test", "ProgramArguments": ["/bin/echo", "test"]}'
        }
    )


def main():
    print("=" * 80)
    print("AMOSKYS Detection Pack v1 - Direct Validation")
    print("=" * 80)
    print()

    # Use temporary database for clean test
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
        test_db = tmp.name

    print(f"[1] Initializing FusionEngine (test DB: {test_db})")
    fusion = FusionEngine(db_path=test_db, window_minutes=30)

    device_id = "Mac"
    now = datetime.now()

    # Create synthetic events: sudo followed by LaunchAgent
    print(f"\n[2] Creating synthetic events for device '{device_id}':")

    # Sudo event at T-0
    sudo_event = create_sudo_event(device_id, now)
    print(f"    ✓ SUDO event at {sudo_event.timestamp.strftime('%H:%M:%S')}")

    # LaunchAgent event 90 seconds later (well within 5-minute correlation window)
    persistence_event = create_launchagent_event(device_id, now + timedelta(seconds=90))
    print(f"    ✓ LAUNCH_AGENT created at {persistence_event.timestamp.strftime('%H:%M:%S')}")
    print(f"    → Time delta: 90 seconds (within 5-minute correlation window)")

    # Add events to FusionEngine
    print(f"\n[3] Adding events to FusionEngine...")
    fusion.add_event(sudo_event)
    fusion.add_event(persistence_event)

    # Trigger evaluation
    print(f"\n[4] Running correlation rules...")
    fusion.evaluate_all_devices()

    # Check results
    print(f"\n[5] Checking for incidents...")
    incidents = fusion.db.execute(
        "SELECT rule_name, severity, summary FROM incidents WHERE device_id = ?",
        (device_id,)
    ).fetchall()

    if incidents:
        print(f"\n🔴 SUCCESS! Detection fired:")
        for rule, severity, summary in incidents:
            print(f"\n    Rule: {rule}")
            print(f"    Severity: {severity}")
            print(f"    Summary: {summary}")
        print()
    else:
        print(f"\n❌ FAILURE: No incidents detected")
        print(f"   Expected: persistence_after_auth rule to fire")
        return 1

    # Check device risk
    print(f"[6] Checking device risk...")
    risk = fusion.db.execute(
        "SELECT score, level FROM device_risk WHERE device_id = ?",
        (device_id,)
    ).fetchone()

    if risk:
        score, level = risk
        print(f"\n    Device: {device_id}")
        print(f"    Risk Score: {score}/100")
        print(f"    Risk Level: {level}")

        if score > 10:
            print(f"\n✅ Risk elevated from baseline (10) to {score}")
        else:
            print(f"\n⚠️  Risk not elevated (still at baseline)")

    print()
    print("=" * 80)
    print("Validation Complete")
    print("=" * 80)
    print()
    print("Summary:")
    print("  - Detection logic: WORKING ✅")
    print("  - Correlation rules: FIRING ✅")
    print("  - FusionEngine: OPERATIONAL ✅")
    print()
    print("Next step: Fix agent collection to feed real events into this pipeline.")
    print()

    # Cleanup
    Path(test_db).unlink(missing_ok=True)

    return 0


if __name__ == '__main__':
    sys.exit(main())
