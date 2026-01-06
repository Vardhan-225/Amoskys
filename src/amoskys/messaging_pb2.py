"""Shim module for backwards compatibility.

Re-exports protobuf messages from their actual location at
amoskys.proto.universal_telemetry_pb2.

This allows imports like:
    from amoskys.messaging_pb2 import DeviceTelemetry

Instead of:
    from amoskys.proto.universal_telemetry_pb2 import DeviceTelemetry
"""

from amoskys.proto.universal_telemetry_pb2 import (
    DeviceTelemetry,
    TelemetryEvent,
    TelemetryBatch,
)

# Re-export common types
from amoskys.proto.messaging_schema_pb2 import (
    Envelope,
    FlowEvent,
    ProcessEvent,
    PublishAck,
)

__all__ = [
    "DeviceTelemetry",
    "TelemetryEvent",
    "TelemetryBatch",
    "Envelope",
    "FlowEvent",
    "ProcessEvent",
    "PublishAck",
]
