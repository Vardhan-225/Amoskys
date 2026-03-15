from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class AgentSignal(_message.Message):
    __slots__ = ("id", "source", "target", "topic", "payload_json", "ts_ns")
    ID_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    TARGET_FIELD_NUMBER: _ClassVar[int]
    TOPIC_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_JSON_FIELD_NUMBER: _ClassVar[int]
    TS_NS_FIELD_NUMBER: _ClassVar[int]
    id: str
    source: str
    target: str
    topic: str
    payload_json: str
    ts_ns: int
    def __init__(self, id: _Optional[str] = ..., source: _Optional[str] = ..., target: _Optional[str] = ..., topic: _Optional[str] = ..., payload_json: _Optional[str] = ..., ts_ns: _Optional[int] = ...) -> None: ...

class SignalSubscribe(_message.Message):
    __slots__ = ("agent_id", "topics")
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    TOPICS_FIELD_NUMBER: _ClassVar[int]
    agent_id: str
    topics: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, agent_id: _Optional[str] = ..., topics: _Optional[_Iterable[str]] = ...) -> None: ...

class SignalAck(_message.Message):
    __slots__ = ("accepted", "reason")
    ACCEPTED_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    accepted: bool
    reason: str
    def __init__(self, accepted: bool = ..., reason: _Optional[str] = ...) -> None: ...
