#!/usr/bin/env python3
"""
Continuous SNMP collection test - runs every 60 seconds
Press Ctrl+C to stop
"""

import asyncio
import sys
from datetime import datetime
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2

try:
    from pysnmp.hlapi.v1arch.asyncio import *
    from pysnmp.smi.rfc1902 import ObjectIdentity, ObjectType

    PYSNMP_AVAILABLE = True
except ImportError:
    print("❌ pysnmp not installed. Run: pip install pysnmp==7.1.21")
    PYSNMP_AVAILABLE = False


async def collect_snmp_data(host="localhost", community="public"):
    """Collect real SNMP data from a device"""
    if not PYSNMP_AVAILABLE:
        return None

    # Common OIDs to query
    oids = {
        "sysDescr": "1.3.6.1.2.1.1.1.0",  # System description
        "sysUpTime": "1.3.6.1.2.1.1.3.0",  # Uptime
        "sysContact": "1.3.6.1.2.1.1.4.0",  # Contact
        "sysName": "1.3.6.1.2.1.1.5.0",  # Hostname
        "sysLocation": "1.3.6.1.2.1.1.6.0",  # Location
    }

    collected_data = {}

    for name, oid in oids.items():
        try:
            # Modern pysnmp v7.x API - uses get_cmd instead of getCmd
            error_indication, error_status, error_index, var_binds = await get_cmd(
                SnmpDispatcher(),
                CommunityData(community),
                await UdpTransportTarget.create((host, 161)),
                ObjectType(ObjectIdentity(oid)),
            )

            if error_indication:
                collected_data[name] = f"ERROR: {error_indication}"
            elif error_status:
                collected_data[name] = f"ERROR: {error_status}"
            else:
                for var_bind in var_binds:
                    value = str(var_bind[1])
                    collected_data[name] = value

        except Exception as e:
            collected_data[name] = f"EXCEPTION: {str(e)}"

    return collected_data


def create_device_telemetry(snmp_data, device_ip="localhost"):
    """Convert SNMP data to DeviceTelemetry protobuf message"""

    # Create DeviceMetadata
    metadata = telemetry_pb2.DeviceMetadata(
        ip_address=device_ip,
        manufacturer="Apple",  # For Mac
        model="macOS",
        protocols=["SNMP"],
    )

    # Create TelemetryEvents for each metric
    events = []
    for metric_name, value in snmp_data.items():
        metric_data = telemetry_pb2.MetricData(
            metric_name=f"snmp_{metric_name}",
            metric_type="GAUGE",
            string_value=value,
            unit="string",
        )

        event = telemetry_pb2.TelemetryEvent(
            event_id=f"{device_ip}_{metric_name}_{int(datetime.now().timestamp())}",
            event_type="METRIC",
            severity="INFO",
            event_timestamp_ns=int(datetime.now().timestamp() * 1e9),
            metric_data=metric_data,
            tags=["snmp", "system_info"],
        )
        events.append(event)

    # Create DeviceTelemetry message
    device_telemetry = telemetry_pb2.DeviceTelemetry(
        device_id=device_ip,
        device_type="NETWORK",
        protocol="SNMP",
        metadata=metadata,
        events=events,
        timestamp_ns=int(datetime.now().timestamp() * 1e9),
        collection_agent="amoskys-continuous-agent",
        agent_version="0.1.0",
    )

    return device_telemetry


async def collect_and_display(iteration):
    """Single collection cycle"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"\n{'='*70}")
    print(f"🔄 Collection #{iteration} - {timestamp}")
    print(f"{'='*70}")

    # Collect SNMP data
    snmp_data = await collect_snmp_data()

    if not snmp_data:
        print("❌ No SNMP data collected")
        return None

    # Display collected metrics
    print(f"\n📊 Collected Metrics:")
    for name, value in snmp_data.items():
        # Truncate long values for display
        display_value = value[:60] + "..." if len(value) > 60 else value
        icon = (
            "✅"
            if not value.startswith("ERROR") and not value.startswith("EXCEPTION")
            else "❌"
        )
        print(f"  {icon} {name:15s}: {display_value}")

    # Convert to protobuf
    device_telemetry = create_device_telemetry(snmp_data)

    # Serialize
    serialized = device_telemetry.SerializeToString()

    print(f"\n📦 Telemetry Summary:")
    print(f"  Device ID:       {device_telemetry.device_id}")
    print(f"  Device Type:     {device_telemetry.device_type}")
    print(f"  Protocol:        {device_telemetry.protocol}")
    print(f"  Events:          {len(device_telemetry.events)}")
    print(f"  Serialized Size: {len(serialized)} bytes")
    print(f"  Collection Agent: {device_telemetry.collection_agent}")

    return device_telemetry


async def main():
    print("🧠⚡ AMOSKYS Continuous SNMP Collection")
    print("=" * 70)
    print("Collecting SNMP data every 60 seconds")
    print("Press Ctrl+C to stop\n")

    if not PYSNMP_AVAILABLE:
        print("❌ pysnmp not available. Install with: pip install pysnmp==7.1.21")
        return

    iteration = 0
    success_count = 0
    error_count = 0

    try:
        while True:
            iteration += 1

            try:
                result = await collect_and_display(iteration)

                if result:
                    success_count += 1
                else:
                    error_count += 1

                # Show statistics
                print(
                    f"\n📈 Statistics: {success_count} successful, {error_count} failed"
                )
                print(f"⏰ Next collection in 60 seconds...")

            except Exception as e:
                error_count += 1
                print(f"\n❌ Error in collection cycle: {e}")

            # Wait 60 seconds before next collection
            await asyncio.sleep(60)

    except KeyboardInterrupt:
        print(f"\n\n{'='*70}")
        print("🛑 Stopping continuous collection")
        print(f"{'='*70}")
        print(f"\n📊 Final Statistics:")
        print(f"  Total Collections: {iteration}")
        print(f"  Successful:        {success_count}")
        print(f"  Failed:            {error_count}")
        print(f"  Success Rate:      {(success_count/iteration*100):.1f}%")
        print("\n✅ Gracefully stopped")


if __name__ == "__main__":
    asyncio.run(main())
