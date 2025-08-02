#!/usr/bin/env python3
import os
import sys
import logging
from concurrent import futures
import grpc

# Ensure project root is on sys.path for module imports
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Ensure proto_stubs is importable
proto_stubs_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../agents/flowagent/proto_stubs'))
if proto_stubs_path not in sys.path:
    sys.path.insert(0, proto_stubs_path)

from agents.flowagent.proto_stubs import messaging_schema_pb2
from agents.flowagent.proto_stubs import messaging_schema_pb2_grpc

# Configure logging
logging.basicConfig(format="%(asctime)s %(levelname)-8s %(message)s", level=logging.INFO)
logger = logging.getLogger("EventBus")


class EventBusServicer(messaging_schema_pb2_grpc.EventBusServicer):
    """Implements the EventBus gRPC service."""

    def Publish(self, request, context):
        _ = context  # Mark context as used to avoid linter warning
        logger.info(f"[Publish] event_id={request.event_id} agent_id={request.agent_id} type={request.type}")
        if request.type == messaging_schema_pb2.FLOW_EVENT:
            flow = messaging_schema_pb2.FlowEvent()
            flow.ParseFromString(request.payload)
            logger.info(
                f"  → FlowEvent: {flow.src_ip}:{flow.src_port} → {flow.dst_ip}:{flow.dst_port} bytes_sent={flow.bytes_sent}"
            )
        return messaging_schema_pb2.PublishAck(success=True, message="OK")

    def Subscribe(self, request, context):
        _ = request  # Mark request as used to avoid linter warning
        logger.warning("Subscribe() called but not implemented.")
        context.abort(grpc.StatusCode.UNIMPLEMENTED, "Subscribe not supported")


def serve(host="0.0.0.0", port=50051):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    messaging_schema_pb2_grpc.add_EventBusServicer_to_server(EventBusServicer(), server)
    listen_addr = f"{host}:{port}"
    server.add_insecure_port(listen_addr)
    logger.info(f"EventBus stub listening on {listen_addr}")
    server.start()
    server.wait_for_termination()


if __name__ == "__main__":
    serve()