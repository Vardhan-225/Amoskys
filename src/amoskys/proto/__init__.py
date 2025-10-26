"""
AMOSKYS Protocol Buffer Definitions
Generated protobuf modules for telemetry and messaging
"""

# Import generated protobuf modules
# Note: These are generated files, import them directly
import amoskys.proto.messaging_schema_pb2 as messaging_schema_pb2
import amoskys.proto.messaging_schema_pb2_grpc as messaging_schema_pb2_grpc
import amoskys.proto.universal_telemetry_pb2 as universal_telemetry_pb2
import amoskys.proto.universal_telemetry_pb2_grpc as universal_telemetry_pb2_grpc

# Aliases for backward compatibility
eventbus_pb2 = messaging_schema_pb2
eventbus_pb2_grpc = messaging_schema_pb2_grpc

__all__ = [
    "messaging_schema_pb2",
    "messaging_schema_pb2_grpc",
    "universal_telemetry_pb2",
    "universal_telemetry_pb2_grpc",
    "eventbus_pb2",
    "eventbus_pb2_grpc",
]
