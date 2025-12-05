#!/usr/bin/env python3
"""
Generate continuous Mac process telemetry for validation
Uses the same approach as test_publish_telemetry.py but in a loop
"""
import sys
import os
import time
import grpc
import psutil
import logging

sys.path.insert(0, 'src')

from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.proto import universal_telemetry_pb2_grpc as telemetry_grpc
from amoskys.proto import messaging_schema_pb2 as msg_pb2

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def publish_mac_processes():
    """Collect and publish Mac process telemetry"""

    # Load certificates
    with open("certs/ca.crt", "rb") as f:
        ca = f.read()
    with open("certs/agent.crt", "rb") as f:
        crt = f.read()
    with open("certs/agent.key", "rb") as f:
        key = f.read()

    creds = grpc.ssl_channel_credentials(
        root_certificates=ca,
        private_key=key,
        certificate_chain=crt
    )

    with grpc.secure_channel("localhost:50051", creds) as channel:
        stub = telemetry_grpc.UniversalEventBusStub(channel)

        published = 0
        failed = 0

        # Collect processes
        for proc in psutil.process_iter(['pid', 'name', 'username', 'exe', 'cmdline']):
            try:
                info = proc.info

                # Create ProcessEvent
                process_event = msg_pb2.ProcessEvent()
                process_event.pid = info['pid']

                try:
                    process_event.ppid = proc.ppid()
                except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                    process_event.ppid = 0

                process_event.exe = info.get('exe', '') or ''

                cmdline = info.get('cmdline') or []
                if cmdline:
                    process_event.args.extend(cmdline[1:] if len(cmdline) > 1 else [])

                process_event.start_ts_ns = time.time_ns()

                try:
                    uids = proc.uids()
                    process_event.uid = uids.real
                except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                    process_event.uid = 0

                try:
                    gids = proc.gids()
                    process_event.gid = gids.real
                except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                    process_event.gid = 0

                # Note: ProcessEvent schema only has basic fields
                # (pid, ppid, exe, args, start_ts_ns, uid, gid, cgroup, container_id)
                # CPU/memory metrics not yet in schema

                # Create UniversalEnvelope
                envelope = telemetry_pb2.UniversalEnvelope()
                envelope.process.CopyFrom(process_event)
                envelope.ts_ns = process_event.start_ts_ns
                envelope.idempotency_key = f"mac-proc-{process_event.pid}-{process_event.start_ts_ns}"
                envelope.sig = b"mac_telemetry_signature"

                # Publish
                ack = stub.PublishTelemetry(envelope, timeout=5.0)

                if ack.status == telemetry_pb2.UniversalAck.Status.OK:
                    published += 1
                else:
                    failed += 1
                    logger.warning(f"Failed to publish PID {info['pid']}: {ack.status}")

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                logger.error(f"Error processing process: {e}")
                failed += 1

        return published, failed

def main():
    logger.info("="*70)
    logger.info("Mac Process Telemetry Generator")
    logger.info("="*70)
    logger.info("Collecting and publishing Mac process telemetry...")
    logger.info(f"Target: localhost:50051")
    logger.info("")

    cycle = 0
    while True:
        cycle += 1
        logger.info(f"Collection cycle #{cycle}")

        try:
            published, failed = publish_mac_processes()
            logger.info(f"  ✅ Published: {published} | ❌ Failed: {failed}")
        except Exception as e:
            logger.error(f"  ❌ Cycle failed: {e}")

        logger.info(f"  ⏰ Next cycle in 30 seconds...")
        time.sleep(30)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\n🛑 Shutting down gracefully...")
