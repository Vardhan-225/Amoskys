#!/usr/bin/env python3
"""Seed the TelemetryStore with realistic security events for dashboard testing.

This script populates data/telemetry.db with a mix of security events
simulating what real agents would produce through the WAL pipeline.

Usage:
    python scripts/seed_dashboard_data.py
    python scripts/seed_dashboard_data.py --count 50
    python scripts/seed_dashboard_data.py --clear  # wipe and re-seed
"""

import argparse
import random
import sys
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from amoskys.storage.telemetry_store import TelemetryStore

# Realistic security event templates from each agent
EVENT_TEMPLATES = [
    # Flow Agent probes
    {
        "event_category": "port_scan_detected",
        "probe": "port_scan_sweep",
        "agent": "flow",
        "risk_range": (0.6, 0.9),
        "mitre": ["T1046"],
        "desc": "Port scan sweep detected: {ports} ports probed from {src}",
    },
    {
        "event_category": "lateral_movement_detected",
        "probe": "lateral_movement",
        "agent": "flow",
        "risk_range": (0.7, 0.95),
        "mitre": ["T1021", "T1021.002"],
        "desc": "Lateral movement via SMB/RDP from {src} to {dst}",
    },
    {
        "event_category": "c2_beaconing_detected",
        "probe": "c2_beacon_detector",
        "agent": "flow",
        "risk_range": (0.8, 0.95),
        "mitre": ["T1071.001", "T1573"],
        "desc": "C2 beaconing pattern: {interval}s interval to {dst}",
    },
    {
        "event_category": "data_exfiltration_detected",
        "probe": "data_exfil_detector",
        "agent": "flow",
        "risk_range": (0.85, 0.98),
        "mitre": ["T1048", "T1041"],
        "desc": "Potential data exfiltration: {bytes}MB to {dst}",
    },
    # DNS Agent probes
    {
        "event_category": "dns_c2_beaconing",
        "probe": "dns_beaconing",
        "agent": "dns",
        "risk_range": (0.7, 0.9),
        "mitre": ["T1071.004", "T1568.002"],
        "desc": "DNS C2 beaconing: {domain} queried {count} times",
    },
    {
        "event_category": "dns_tunneling_detected",
        "probe": "dns_tunneling",
        "agent": "dns",
        "risk_range": (0.8, 0.95),
        "mitre": ["T1071.004", "T1048.003"],
        "desc": "DNS tunneling: high-entropy queries to {domain}",
    },
    {
        "event_category": "dga_domain_detected",
        "probe": "dga_detector",
        "agent": "dns",
        "risk_range": (0.6, 0.85),
        "mitre": ["T1568.002"],
        "desc": "DGA domain detected: {domain} (entropy={entropy:.2f})",
    },
    # Auth Agent probes
    {
        "event_category": "ssh_brute_force",
        "probe": "ssh_brute_force",
        "agent": "auth",
        "risk_range": (0.7, 0.95),
        "mitre": ["T1110", "T1021.004"],
        "desc": "SSH brute force: {count} failed attempts from {src}",
    },
    {
        "event_category": "sudo_escalation_suspicious",
        "probe": "sudo_escalation",
        "agent": "auth",
        "risk_range": (0.6, 0.85),
        "mitre": ["T1548.003"],
        "desc": "Suspicious sudo escalation by {user}: {cmd}",
    },
    {
        "event_category": "impossible_travel_detected",
        "probe": "geo_impossible_travel",
        "agent": "auth",
        "risk_range": (0.8, 0.95),
        "mitre": ["T1078"],
        "desc": "Impossible travel: login from {loc1} and {loc2} within {minutes}m",
    },
    # FIM Agent probes
    {
        "event_category": "critical_file_modified",
        "probe": "critical_system_files",
        "agent": "fim",
        "risk_range": (0.7, 0.95),
        "mitre": ["T1565.001"],
        "desc": "Critical system file modified: {path}",
    },
    {
        "event_category": "suid_change_detected",
        "probe": "suid_sgid_changes",
        "agent": "fim",
        "risk_range": (0.75, 0.9),
        "mitre": ["T1548.001"],
        "desc": "SUID/SGID bit changed on {path}",
    },
    # Persistence Agent probes
    {
        "event_category": "persistence_launch_agent",
        "probe": "launch_agent_detector",
        "agent": "persistence",
        "risk_range": (0.6, 0.85),
        "mitre": ["T1543.001"],
        "desc": "New LaunchAgent created: {path}",
    },
    {
        "event_category": "persistence_cron_reboot",
        "probe": "cron_reboot_detector",
        "agent": "persistence",
        "risk_range": (0.5, 0.75),
        "mitre": ["T1053.003"],
        "desc": "Cron @reboot persistence: {cmd}",
    },
    # Peripheral Agent probes
    {
        "event_category": "unauthorized_usb_storage",
        "probe": "usb_storage_detector",
        "agent": "peripheral",
        "risk_range": (0.5, 0.8),
        "mitre": ["T1091", "T1052.001"],
        "desc": "Unauthorized USB storage device: {vendor}:{product}",
    },
    # Kernel Audit probes
    {
        "event_category": "kernel_module_load",
        "probe": "kernel_module_load",
        "agent": "kernel_audit",
        "risk_range": (0.7, 0.9),
        "mitre": ["T1547.006"],
        "desc": "Kernel module loaded: {module}",
    },
]

# Random data generators
RANDOM_IPS = [
    "203.0.113.42",
    "198.51.100.1",
    "192.0.2.99",
    "10.10.10.42",
    "172.16.0.100",
    "45.33.32.156",
    "185.199.108.1",
    "91.189.88.142",
]

RANDOM_DOMAINS = [
    "x8fk3m.evil.com",
    "c2.adversary.net",
    "update.malware.io",
    "cdn-static.suspicious.org",
    "api.legit-looking.com",
]

RANDOM_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/usr/bin/sudo",
    "/Library/LaunchAgents/com.update.plist",
    "/Users/admin/Library/LaunchAgents/com.persist.plist",
]


def _fill_template(template: dict) -> dict:
    """Fill in randomized data for a template."""
    desc = template["desc"]
    desc = desc.replace("{src}", random.choice(RANDOM_IPS))
    desc = desc.replace("{dst}", random.choice(RANDOM_IPS))
    desc = desc.replace("{domain}", random.choice(RANDOM_DOMAINS))
    desc = desc.replace("{path}", random.choice(RANDOM_PATHS))
    desc = desc.replace("{ports}", str(random.randint(50, 500)))
    desc = desc.replace("{count}", str(random.randint(5, 50)))
    desc = desc.replace("{bytes}", str(random.randint(10, 500)))
    desc = desc.replace("{interval}", str(random.randint(30, 300)))
    desc = desc.replace("{entropy:.2f}", f"{random.uniform(3.5, 4.5):.2f}")
    desc = desc.replace("{user}", random.choice(["root", "admin", "deploy"]))
    desc = desc.replace("{cmd}", random.choice(["bash", "python", "nc -e /bin/sh"]))
    desc = desc.replace("{loc1}", random.choice(["New York", "London", "Tokyo"]))
    desc = desc.replace("{loc2}", random.choice(["Moscow", "Beijing", "Lagos"]))
    desc = desc.replace("{minutes}", str(random.randint(5, 30)))
    desc = desc.replace("{vendor}", f"{random.randint(0x0000, 0xFFFF):04x}")
    desc = desc.replace("{product}", f"{random.randint(0x0000, 0xFFFF):04x}")
    desc = desc.replace(
        "{module}", random.choice(["rootkit.ko", "keylogger.ko", "netfilter_hook.ko"])
    )
    return desc


def seed(store: TelemetryStore, count: int = 30) -> int:
    """Seed the store with realistic security events.

    Events are spread over the last 24 hours with realistic timestamps.
    """
    now_ns = int(time.time() * 1e9)
    inserted = 0

    for i in range(count):
        template = random.choice(EVENT_TEMPLATES)
        risk = round(random.uniform(*template["risk_range"]), 2)

        # Spread events over last 24 hours
        offset_ns = random.randint(0, 24 * 3600 * 1_000_000_000)
        ts_ns = now_ns - offset_ns

        if risk >= 0.75:
            classification = "malicious"
        elif risk >= 0.5:
            classification = "suspicious"
        else:
            classification = "legitimate"

        description = _fill_template(template)

        event_data = {
            "timestamp_ns": ts_ns,
            "device_id": random.choice(
                ["workstation-001", "server-prod-01", "laptop-dev-03"]
            ),
            "event_category": template["event_category"],
            "event_action": "DETECTED",
            "event_outcome": "ALERT",
            "risk_score": risk,
            "confidence": round(random.uniform(0.6, 0.95), 2),
            "mitre_techniques": template["mitre"],
            "final_classification": classification,
            "description": f"[{template['probe']}] {description}",
            "indicators": {
                "agent": template["agent"],
                "probe": template["probe"],
                "source_ip": random.choice(RANDOM_IPS),
            },
            "requires_investigation": risk >= 0.7,
        }

        row_id = store.insert_security_event(event_data)
        if row_id:
            inserted += 1

    return inserted


def main():
    parser = argparse.ArgumentParser(description="Seed AMOSKYS dashboard data")
    parser.add_argument(
        "--count", type=int, default=30, help="Number of events to seed"
    )
    parser.add_argument(
        "--clear", action="store_true", help="Clear existing data first"
    )
    args = parser.parse_args()

    db_path = str(Path(__file__).parent.parent / "data" / "telemetry.db")
    store = TelemetryStore(db_path)

    if args.clear:
        store.db.execute("DELETE FROM security_events")
        store.db.commit()
        print("Cleared existing security events")

    inserted = seed(store, count=args.count)
    stats = store.get_statistics()

    print(f"Seeded {inserted} security events into {db_path}")
    print(f"Total security_events: {stats['security_events_count']}")
    print(f"Total process_events: {stats['process_events_count']}")

    # Show threat score
    threat = store.get_threat_score_data(hours=24)
    print(f"Threat score: {threat['threat_score']} ({threat['threat_level']})")
    print(f"Events in window: {threat['event_count']}")

    store.close()


if __name__ == "__main__":
    main()
