#!/usr/bin/env python3
"""
Test script to publish telemetry data to EventBus
Tests both DeviceTelemetry (SNMP) and ProcessEvent publishing
"""
import sys
import os
import time
import grpc

sys.path.insert(0, "src")

from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.proto import universal_telemetry_pb2_grpc as telemetry_grpc
from amoskys.proto import messaging_schema_pb2 as msg_pb2


def publish_device_telemetry():
    """Test publishing DeviceTelemetry (SNMP data)"""
    print("\n=== Testing DeviceTelemetry Publishing ===")

    # Create mock DeviceTelemetry
    device_telemetry = telemetry_pb2.DeviceTelemetry()
    device_telemetry.device_id = "test-device-001"
    device_telemetry.device_type = "ENDPOINT"
    device_telemetry.protocol = "SNMP"
    device_telemetry.timestamp_ns = time.time_ns()
    device_telemetry.collection_agent = "test-agent"
    device_telemetry.agent_version = "1.0.0"

    # Set metadata
    device_telemetry.metadata.manufacturer = "Test Manufacturer"
    device_telemetry.metadata.model = "Test Model"
    device_telemetry.metadata.firmware_version = "1.0.0"
    device_telemetry.metadata.protocols.append("SNMP")

    # Add some metric events
    event1 = device_telemetry.events.add()
    event1.event_type = "METRIC"
    event1.severity = "INFO"
    event1.event_timestamp_ns = time.time_ns()
    event1.metric_data.metric_name = "sysUpTime"
    event1.metric_data.metric_type = "GAUGE"
    event1.metric_data.numeric_value = 12345678
    event1.metric_data.unit = "ticks"

    event2 = device_telemetry.events.add()
    event2.event_type = "METRIC"
    event2.severity = "INFO"
    event2.event_timestamp_ns = time.time_ns()
    event2.metric_data.metric_name = "cpuUtilization"
    event2.metric_data.metric_type = "GAUGE"
    event2.metric_data.numeric_value = 45.6
    event2.metric_data.unit = "percent"

    event3 = device_telemetry.events.add()
    event3.event_type = "METRIC"
    event3.severity = "INFO"
    event3.event_timestamp_ns = time.time_ns()
    event3.metric_data.metric_name = "memoryUsage"
    event3.metric_data.metric_type = "GAUGE"
    event3.metric_data.numeric_value = 2048
    event3.metric_data.unit = "MB"

    # Create UniversalEnvelope
    envelope = telemetry_pb2.UniversalEnvelope()
    envelope.device_telemetry.CopyFrom(device_telemetry)

    # Set envelope metadata
    envelope.ts_ns = device_telemetry.timestamp_ns
    envelope.idempotency_key = f"test-device-001-{device_telemetry.timestamp_ns}"
    envelope.sig = b"mock_signature_bytes_for_testing"

    print(f"  Created DeviceTelemetry envelope: {envelope.ByteSize()} bytes")
    print(f"    Device: {device_telemetry.device_id}")
    print(f"    Events: {len(device_telemetry.events)}")

    # Publish to EventBus
    try:
        # Load certificates
        with open("certs/ca.crt", "rb") as f:
            ca = f.read()
        with open("certs/agent.crt", "rb") as f:
            crt = f.read()
        with open("certs/agent.key", "rb") as f:
            key = f.read()

        creds = grpc.ssl_channel_credentials(
            root_certificates=ca, private_key=key, certificate_chain=crt
        )

        with grpc.secure_channel("localhost:50051", creds) as channel:
            stub = telemetry_grpc.UniversalEventBusStub(channel)
            ack = stub.PublishTelemetry(envelope, timeout=5.0)

            if ack.status == telemetry_pb2.UniversalAck.Status.OK:
                print(f"  ✅ Published successfully!")
                print(f"    Events accepted: {ack.events_accepted}")
                return True
            else:
                print(f"  ❌ Publish failed: {ack.status}")
                return False

    except Exception as e:
        print(f"  ❌ Exception: {e}")
        return False


def publish_process_telemetry():
    """Test publishing ProcessEvent (Process monitoring data)"""
    print("\n=== Testing ProcessEvent Publishing ===")

    # Create mock ProcessEvent
    process_event = msg_pb2.ProcessEvent()
    process_event.pid = 12345
    process_event.ppid = 1
    process_event.exe = "/usr/bin/test_process"
    process_event.args.extend(["--arg1", "--arg2"])
    process_event.start_ts_ns = time.time_ns()
    process_event.uid = 501
    process_event.gid = 20
    process_event.cgroup = "/system.slice/test.service"
    process_event.container_id = ""

    # Create UniversalEnvelope
    envelope = telemetry_pb2.UniversalEnvelope()
    envelope.process.CopyFrom(process_event)

    # Set envelope metadata
    envelope.ts_ns = process_event.start_ts_ns
    envelope.idempotency_key = (
        f"test-process-{process_event.pid}-{process_event.start_ts_ns}"
    )
    envelope.sig = b"mock_signature_bytes_for_testing"

    print(f"  Created ProcessEvent envelope: {envelope.ByteSize()} bytes")
    print(f"    Process: {process_event.exe} (PID: {process_event.pid})")
    print(f"    Args: {' '.join(process_event.args)}")

    # Publish to EventBus
    try:
        # Load certificates
        with open("certs/ca.crt", "rb") as f:
            ca = f.read()
        with open("certs/agent.crt", "rb") as f:
            crt = f.read()
        with open("certs/agent.key", "rb") as f:
            key = f.read()

        creds = grpc.ssl_channel_credentials(
            root_certificates=ca, private_key=key, certificate_chain=crt
        )

        with grpc.secure_channel("localhost:50051", creds) as channel:
            stub = telemetry_grpc.UniversalEventBusStub(channel)
            ack = stub.PublishTelemetry(envelope, timeout=5.0)

            if ack.status == telemetry_pb2.UniversalAck.Status.OK:
                print(f"  ✅ Published successfully!")
                print(f"    Events accepted: {ack.events_accepted}")
                return True
            else:
                print(f"  ❌ Publish failed: {ack.status}")
                return False

    except Exception as e:
        print(f"  ❌ Exception: {e}")
        return False


def main():
    print("Testing Telemetry Publishing Pipeline")
    print("=" * 50)

    # Test DeviceTelemetry
    device_ok = publish_device_telemetry()
    time.sleep(1)

    # Test ProcessEvent
    process_ok = publish_process_telemetry()

    print("\n" + "=" * 50)
    print("Test Summary:")
    print(f"  DeviceTelemetry: {'✅ PASS' if device_ok else '❌ FAIL'}")
    print(f"  ProcessEvent: {'✅ PASS' if process_ok else '❌ FAIL'}")

    return 0 if (device_ok and process_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
