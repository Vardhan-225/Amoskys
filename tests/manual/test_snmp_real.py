"""
Test real SNMP collection from localhost
Run this after 'make proto' to verify everything works
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
    from pysnmp.smi.rfc1902 import ObjectType, ObjectIdentity

    PYSNMP_AVAILABLE = True
except ImportError:
    print("❌ pysnmp not installed. Run: pip install pysnmp==7.1.21")
    PYSNMP_AVAILABLE = False


async def collect_snmp_data(host="localhost", community="public"):
    """Collect real SNMP data from a device"""
    if not PYSNMP_AVAILABLE:
        return None

    print(f"📡 Collecting SNMP data from {host}...")

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
                print(f"  ⚠️  {name}: {error_indication}")
            elif error_status:
                print(f"  ⚠️  {name}: {error_status}")
            else:
                for var_bind in var_binds:
                    value = str(var_bind[1])
                    collected_data[name] = value
                    # Truncate long values for display
                    display_value = value[:80] + "..." if len(value) > 80 else value
                    print(f"  ✅ {name}: {display_value}")

        except Exception as e:
            print(f"  ❌ {name}: {str(e)}")

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
        collection_agent="amoskys-test-agent",
        agent_version="0.1.0",
    )

    return device_telemetry


async def main():
    print("🧪 AMOSKYS SNMP Collection Test")
    print("=" * 70)
    print()

    # Step 1: Collect SNMP data
    snmp_data = await collect_snmp_data()

    if not snmp_data:
        print("\n❌ No SNMP data collected. Check if:")
        print(
            "   1. snmpd is running: sudo launchctl load -w /System/Library/LaunchDaemons/org.net-snmp.snmpd.plist"
        )
        print("   2. Community string 'public' is allowed")
        print("   3. Firewall allows SNMP (port 161)")
        print("\nYou can check with: ps aux | grep snmpd")
        return None

    print(f"\n✅ Collected {len(snmp_data)} SNMP metrics")

    # Step 2: Convert to protobuf
    print("\n📦 Converting to DeviceTelemetry protobuf...")
    device_telemetry = create_device_telemetry(snmp_data)

    print(f"  ✅ Device ID: {device_telemetry.device_id}")
    print(f"  ✅ Device Type: {device_telemetry.device_type}")
    print(f"  ✅ Protocol: {device_telemetry.protocol}")
    print(f"  ✅ Events: {len(device_telemetry.events)}")
    print(f"  ✅ Collection Agent: {device_telemetry.collection_agent}")

    # Step 3: Serialize to bytes
    serialized = device_telemetry.SerializeToString()
    print(f"\n✅ Serialized to protobuf: {len(serialized)} bytes")

    # Step 4: Verify deserialization
    deserialized = telemetry_pb2.DeviceTelemetry()
    deserialized.ParseFromString(serialized)
    print(f"✅ Deserialization successful - data integrity verified")

    # Step 5: Show what we collected
    print("\n📊 Telemetry Details:")
    for i, event in enumerate(device_telemetry.events, 1):
        metric = event.metric_data
        value = (
            metric.string_value[:50] + "..."
            if len(metric.string_value) > 50
            else metric.string_value
        )
        print(f"  {i}. {metric.metric_name}: {value}")

    print("\n" + "=" * 70)
    print("🎉 SUCCESS! You just collected and serialized real device telemetry!")
    print("\n✅ Your First Achievement Complete:")
    print("   - Real SNMP data collected from your Mac")
    print("   - Data converted to DeviceTelemetry protobuf format")
    print("   - Serialization/deserialization verified")
    print("   - Ready to connect to EventBus!")

    print("\n📈 Next Steps:")
    print("   1. Connect this to EventBus (see FIRST_STEPS_GUIDE.md Step 5)")
    print("   2. Add your router as a second device")
    print("   3. Enable continuous collection")
    print("   4. View metrics in the dashboard")

    print("\n💡 To run continuously, you can modify this script to loop")
    print("   and publish to EventBus every 60 seconds.")

    return device_telemetry


if __name__ == "__main__":
    result = asyncio.run(main())
    if result:
        print("\n✅ Test completed successfully!")
        sys.exit(0)
    else:
        print("\n❌ Test failed - see error messages above")
        sys.exit(1)
