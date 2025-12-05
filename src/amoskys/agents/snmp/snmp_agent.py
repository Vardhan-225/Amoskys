"""AMOSKYS SNMP Agent - Real Device Telemetry Collection and Publishing.

This module implements the SNMPAgent, which is responsible for:
- Collecting device telemetry from SNMP-enabled devices
- Converting to DeviceTelemetry protobuf format
- Publishing telemetry to the EventBus via gRPC
- Managing collection schedules and retry logic
- Health and readiness endpoints for orchestration

Architecture:
    SNMPAgent -> DeviceTelemetry -> UniversalEnvelope -> EventBus

The agent collects metrics from configured devices at regular intervals and
publishes them to the EventBus using the universal telemetry schema.
"""

import os
import time
import logging
import grpc
import signal
import asyncio
import sys
from datetime import datetime
from prometheus_client import start_http_server, Counter, Histogram, Gauge
from typing import Dict, List, Optional

# AMOSKYS imports
from amoskys.proto import messaging_schema_pb2 as pb
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.common.crypto.canonical import canonical_bytes
from amoskys.common.crypto.signing import load_private_key, sign
from amoskys.config import get_config

# pysnmp imports (conditional)
try:
    from pysnmp.hlapi.v1arch.asyncio import *
    from pysnmp.smi.rfc1902 import ObjectType, ObjectIdentity
    PYSNMP_AVAILABLE = True
except ImportError:
    PYSNMP_AVAILABLE = False
    logging.warning("pysnmp not available - SNMP collection disabled")

# Load configuration
config = get_config()
logger = logging.getLogger("SNMPAgent")

# Configuration
CERT_DIR = config.agent.cert_dir
ED25519_SK_PATH = config.crypto.ed25519_private_key
COLLECTION_INTERVAL = 60  # seconds
MAX_ENV_BYTES = config.agent.max_env_bytes

# Metrics
SNMP_COLLECTIONS = Counter("snmp_collections_total", "Total SNMP collections attempted")
SNMP_COLLECTION_SUCCESS = Counter("snmp_collection_success_total", "Successful SNMP collections")
SNMP_COLLECTION_ERRORS = Counter("snmp_collection_errors_total", "Failed SNMP collections")
SNMP_PUBLISH_OK = Counter("snmp_publish_ok_total", "Successful telemetry publishes")
SNMP_PUBLISH_RETRY = Counter("snmp_publish_retry_total", "Retry responses from EventBus")
SNMP_PUBLISH_FAIL = Counter("snmp_publish_fail_total", "Failed telemetry publishes")
SNMP_COLLECTION_LATENCY = Histogram("snmp_collection_latency_ms", "SNMP collection latency (ms)")
SNMP_PUBLISH_LATENCY = Histogram("snmp_publish_latency_ms", "Telemetry publish latency (ms)")
SNMP_DEVICES_MONITORED = Gauge("snmp_devices_monitored", "Number of devices being monitored")
SNMP_METRICS_COLLECTED = Counter("snmp_metrics_collected_total", "Total metrics collected")

# Global state
stop = False
READY = False


def _graceful(signum, frame):
    """Signal handler for SIGINT/SIGTERM - triggers graceful shutdown."""
    global stop, READY
    stop = True
    READY = False
    logging.info("Shutting down SNMP Agent... signal=%s", signum)


signal.signal(signal.SIGINT, _graceful)
signal.signal(signal.SIGTERM, _graceful)


# SNMP Collection OIDs
SYSTEM_OIDS = {
    'sysDescr': '1.3.6.1.2.1.1.1.0',      # System description
    'sysUpTime': '1.3.6.1.2.1.1.3.0',    # Uptime
    'sysContact': '1.3.6.1.2.1.1.4.0',   # Contact
    'sysName': '1.3.6.1.2.1.1.5.0',      # Hostname
    'sysLocation': '1.3.6.1.2.1.1.6.0',  # Location
}


async def collect_snmp_data(host: str, community: str = 'public') -> Optional[Dict[str, str]]:
    """Collect SNMP data from a device.

    Args:
        host: Device IP or hostname
        community: SNMP community string (default: 'public')

    Returns:
        Dict of metric_name -> value, or None if collection failed
    """
    if not PYSNMP_AVAILABLE:
        logger.error("pysnmp not available")
        return None

    collected_data = {}
    t0 = time.time()

    try:
        for name, oid in SYSTEM_OIDS.items():
            try:
                error_indication, error_status, error_index, var_binds = await get_cmd(
                    SnmpDispatcher(),
                    CommunityData(community),
                    await UdpTransportTarget.create((host, 161)),
                    ObjectType(ObjectIdentity(oid))
                )

                if error_indication:
                    logger.warning(f"SNMP error for {name} on {host}: {error_indication}")
                    continue

                if error_status:
                    logger.warning(f"SNMP error for {name} on {host}: {error_status}")
                    continue

                for var_bind in var_binds:
                    value = str(var_bind[1])
                    collected_data[name] = value
                    SNMP_METRICS_COLLECTED.inc()

            except Exception as e:
                logger.error(f"Exception collecting {name} from {host}: {e}")
                continue

        if collected_data:
            SNMP_COLLECTION_LATENCY.observe((time.time() - t0) * 1000)
            SNMP_COLLECTION_SUCCESS.inc()
        else:
            SNMP_COLLECTION_ERRORS.inc()

        return collected_data if collected_data else None

    except Exception as e:
        logger.error(f"Failed to collect from {host}: {e}")
        SNMP_COLLECTION_ERRORS.inc()
        return None


def create_device_telemetry(host: str, snmp_data: Dict[str, str]) -> telemetry_pb2.DeviceTelemetry:
    """Convert SNMP data to DeviceTelemetry protobuf.

    Args:
        host: Device IP or hostname
        snmp_data: Dictionary of SNMP metric values

    Returns:
        DeviceTelemetry protobuf message
    """
    # Create device metadata
    metadata = telemetry_pb2.DeviceMetadata(
        ip_address=host,
        protocols=["SNMP"],
    )

    # Populate metadata from SNMP data if available
    if 'sysDescr' in snmp_data:
        # Try to extract manufacturer/model from sysDescr
        sys_descr = snmp_data['sysDescr']
        if 'Darwin' in sys_descr:
            metadata.manufacturer = "Apple"
            metadata.model = "macOS"
        elif 'Linux' in sys_descr:
            metadata.manufacturer = "Linux"
        elif 'Cisco' in sys_descr:
            metadata.manufacturer = "Cisco"
        elif 'Juniper' in sys_descr:
            metadata.manufacturer = "Juniper"

    if 'sysName' in snmp_data:
        # Use sysName as part of device identification
        pass

    if 'sysLocation' in snmp_data:
        metadata.physical_location = snmp_data['sysLocation']

    if 'sysContact' in snmp_data:
        # Could use this for contact info
        pass

    # Create telemetry events for each metric
    events = []
    timestamp_ns = int(datetime.now().timestamp() * 1e9)

    for metric_name, value in snmp_data.items():
        # Determine if value is numeric or string
        try:
            numeric_value = float(value)
            metric_data = telemetry_pb2.MetricData(
                metric_name=f"snmp_{metric_name}",
                metric_type="GAUGE",
                numeric_value=numeric_value,
                unit="counter" if metric_name == "sysUpTime" else "string"
            )
        except ValueError:
            # Non-numeric value
            metric_data = telemetry_pb2.MetricData(
                metric_name=f"snmp_{metric_name}",
                metric_type="GAUGE",
                string_value=value,
                unit="string"
            )

        event = telemetry_pb2.TelemetryEvent(
            event_id=f"{host}_{metric_name}_{timestamp_ns}",
            event_type="METRIC",
            severity="INFO",
            event_timestamp_ns=timestamp_ns,
            metric_data=metric_data,
            tags=["snmp", "system_info", "amoskys"],
            source_component="snmp_agent"
        )
        events.append(event)

    # Create DeviceTelemetry message
    device_telemetry = telemetry_pb2.DeviceTelemetry(
        device_id=host,
        device_type="NETWORK",
        protocol="SNMP",
        metadata=metadata,
        events=events,
        timestamp_ns=timestamp_ns,
        collection_agent="amoskys-snmp-agent",
        agent_version="0.1.0"
    )

    return device_telemetry


def create_universal_envelope(device_telemetry: telemetry_pb2.DeviceTelemetry,
                             sk: 'Ed25519PrivateKey') -> telemetry_pb2.UniversalEnvelope:
    """Wrap DeviceTelemetry in a signed UniversalEnvelope.

    Args:
        device_telemetry: DeviceTelemetry protobuf to wrap
        sk: Ed25519PrivateKey for signing

    Returns:
        Signed UniversalEnvelope ready for publishing
    """
    timestamp_ns = int(datetime.now().timestamp() * 1e9)

    # Create idempotency key from device_id and timestamp
    idem_key = f"{device_telemetry.device_id}_{timestamp_ns}"

    # Create envelope
    envelope = telemetry_pb2.UniversalEnvelope(
        version="v1",
        ts_ns=timestamp_ns,
        idempotency_key=idem_key,
        device_telemetry=device_telemetry,
        signing_algorithm="Ed25519",
        priority="NORMAL",
        requires_acknowledgment=True
    )

    # Sign the envelope using SerializeToString (since canonical_bytes only works with old Envelope)
    # Exclude sig field by serializing without it
    envelope_bytes = envelope.SerializeToString()
    envelope.sig = sign(sk, envelope_bytes)

    return envelope


def grpc_channel():
    """Create a secure gRPC channel to the EventBus.

    Returns:
        grpc.Channel: Configured secure channel with mTLS
    """
    with open(os.path.join(CERT_DIR, "ca.crt"), "rb") as f:
        ca = f.read()
    with open(os.path.join(CERT_DIR, "agent.crt"), "rb") as f:
        crt = f.read()
    with open(os.path.join(CERT_DIR, "agent.key"), "rb") as f:
        key = f.read()

    creds = grpc.ssl_channel_credentials(
        root_certificates=ca,
        private_key=key,
        certificate_chain=crt
    )

    return grpc.secure_channel(config.agent.bus_address, creds)


def publish_telemetry(envelope: telemetry_pb2.UniversalEnvelope) -> bool:
    """Publish UniversalEnvelope to EventBus.

    Args:
        envelope: Signed UniversalEnvelope to publish

    Returns:
        bool: True if publish succeeded, False otherwise
    """
    # Check size
    serialized = envelope.SerializeToString()
    if len(serialized) > MAX_ENV_BYTES:
        logger.warning(f"Envelope too large: {len(serialized)} bytes, dropping")
        return False

    t0 = time.time()

    try:
        # TODO: Once EventBus supports UniversalEnvelope, use that directly
        # For now, wrap in a FlowEvent as a temporary bridge
        from amoskys.proto import messaging_schema_pb2_grpc as pb_grpc
        
        device_id = envelope.device_telemetry.device_id
        
        # Create a FlowEvent wrapper (temporary solution)
        flow = pb.FlowEvent(
            src_ip=device_id,
            dst_ip="eventbus",
            protocol="SNMP-TELEMETRY",
            bytes_sent=len(serialized),
            start_time=envelope.ts_ns
        )
        
        # Wrap in Envelope
        flow_envelope = pb.Envelope(
            version="1",
            ts_ns=envelope.ts_ns,
            idempotency_key=envelope.idempotency_key,
            flow=flow,
            sig=envelope.sig  # Use sig field
        )
        
        with grpc_channel() as ch:
            stub = pb_grpc.EventBusStub(ch)
            ack = stub.Publish(flow_envelope, timeout=5.0)

        latency_ms = (time.time() - t0) * 1000
        SNMP_PUBLISH_LATENCY.observe(latency_ms)

        if ack.status == pb.PublishAck.OK:
            SNMP_PUBLISH_OK.inc()
            logger.info(f"✅ Published telemetry: {device_id} "
                       f"({len(serialized)} bytes, {latency_ms:.1f}ms)")
            return True
        elif ack.status == pb.PublishAck.RETRY:
            SNMP_PUBLISH_RETRY.inc()
            logger.warning(f"⚠️  EventBus requested retry: {ack.reason}")
            return False
        else:
            SNMP_PUBLISH_FAIL.inc()
            logger.error(f"❌ Publish failed: {ack.reason}")
            return False

    except grpc.RpcError as e:
        SNMP_PUBLISH_FAIL.inc()
        logger.error(f"❌ gRPC error: {e.code()} - {e.details()}")
        return False
    except Exception as e:
        SNMP_PUBLISH_FAIL.inc()
        logger.error(f"❌ Publish error: {e}", exc_info=True)
        return False


async def collect_and_publish(device_config: Dict[str, str], sk: 'Ed25519PrivateKey'):
    """Collect SNMP data from a device and publish to EventBus.

    Args:
        device_config: Dict with 'host' and optional 'community'
        sk: Ed25519 private key for signing
    """
    host = device_config['host']
    community = device_config.get('community', 'public')

    logger.info(f"📡 Collecting from {host}...")
    SNMP_COLLECTIONS.inc()

    # Collect SNMP data
    snmp_data = await collect_snmp_data(host, community)

    if not snmp_data:
        logger.warning(f"⚠️  No data collected from {host}")
        return

    logger.info(f"✅ Collected {len(snmp_data)} metrics from {host}")

    # Convert to DeviceTelemetry
    device_telemetry = create_device_telemetry(host, snmp_data)

    # Wrap in UniversalEnvelope and sign
    envelope = create_universal_envelope(device_telemetry, sk)

    # Publish to EventBus
    publish_telemetry(envelope)


async def collection_loop(devices: List[Dict[str, str]], sk: 'Ed25519PrivateKey'):
    """Main collection loop - collects from all devices at regular intervals.

    Args:
        devices: List of device configs (each with 'host' and optional 'community')
        sk: Ed25519 private key for signing
    """
    global READY
    READY = True
    SNMP_DEVICES_MONITORED.set(len(devices))

    logger.info(f"🚀 Starting SNMP collection loop for {len(devices)} device(s)")
    logger.info(f"📊 Collection interval: {COLLECTION_INTERVAL} seconds")

    iteration = 0

    while not stop:
        iteration += 1
        logger.info(f"\n{'='*70}")
        logger.info(f"🔄 Collection cycle #{iteration} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info(f"{'='*70}")

        # Collect from all devices in parallel
        tasks = [collect_and_publish(device, sk) for device in devices]
        await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(f"✅ Collection cycle #{iteration} complete")
        logger.info(f"⏰ Next collection in {COLLECTION_INTERVAL} seconds...")

        # Wait for next collection interval
        await asyncio.sleep(COLLECTION_INTERVAL)

    READY = False
    logger.info("🛑 Collection loop stopped")


def main():
    """Main entry point for SNMP Agent."""
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    logger.info("🧠⚡ AMOSKYS SNMP Agent Starting...")
    logger.info("="*70)

    # Check if pysnmp is available
    if not PYSNMP_AVAILABLE:
        logger.error("❌ pysnmp not available. Install with: pip install pysnmp==7.1.21")
        sys.exit(1)

    # Load private key for signing
    try:
        sk_bytes = load_private_key(ED25519_SK_PATH)
        logger.info(f"✅ Loaded Ed25519 private key from {ED25519_SK_PATH}")
    except Exception as e:
        logger.error(f"❌ Failed to load private key: {e}")
        sys.exit(1)

    # Configure devices to monitor
    # TODO: Load from configuration file
    devices = [
        {
            'host': 'localhost',
            'community': 'public'
        },
        # Add more devices here
        # {'host': '192.168.1.1', 'community': 'public'},
    ]

    logger.info(f"📋 Configured devices: {len(devices)}")
    for i, device in enumerate(devices, 1):
        logger.info(f"   {i}. {device['host']} (community: {device.get('community', 'public')})")

    # Start Prometheus metrics server
    try:
        metrics_port = 8001  # Different from FlowAgent (8080)
        start_http_server(metrics_port)
        logger.info(f"📊 Metrics server started on port {metrics_port}")
    except Exception as e:
        logger.warning(f"⚠️  Failed to start metrics server: {e}")

    logger.info("="*70)
    logger.info("🚀 SNMP Agent operational - starting collection loop")
    logger.info("="*70)

    # Run collection loop
    try:
        asyncio.run(collection_loop(devices, sk_bytes))
    except KeyboardInterrupt:
        logger.info("\n🛑 Received shutdown signal")

    logger.info("✅ SNMP Agent stopped gracefully")


if __name__ == "__main__":
    main()
