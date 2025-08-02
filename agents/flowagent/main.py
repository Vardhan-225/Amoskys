# agents/flowagent/main.py

from proto_stubs import messaging_schema_pb2
import uuid
from datetime import datetime, timezone

# Build a dummy FlowEvent payload
flow_event = messaging_schema_pb2.FlowEvent(
    flow_id=str(uuid.uuid4()),
    src_ip="10.0.0.1",
    src_port=12345,
    dst_ip="10.0.0.2",
    dst_port=443,
    protocol="TCP",
    bytes_sent=1234,
    bytes_recv=4321,
    flags=0,
    start_time=1690000000000,
    end_time=1690000010000,
)

# Wrap it in the Event envelope
event = messaging_schema_pb2.Event(
    event_id=str(uuid.uuid4()),
    agent_id="flowagent",
    timestamp=datetime.now(timezone.utc).isoformat(),
    type=messaging_schema_pb2.FLOW_EVENT,
    payload=flow_event.SerializeToString()
)

print("Serialized Event:")
print(event)