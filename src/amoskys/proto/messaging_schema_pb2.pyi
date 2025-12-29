from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ProcessEvent(_message.Message):
    __slots__ = ("pid", "ppid", "exe", "args", "start_ts_ns", "uid", "gid", "cgroup", "container_id")
    PID_FIELD_NUMBER: _ClassVar[int]
    PPID_FIELD_NUMBER: _ClassVar[int]
    EXE_FIELD_NUMBER: _ClassVar[int]
    ARGS_FIELD_NUMBER: _ClassVar[int]
    START_TS_NS_FIELD_NUMBER: _ClassVar[int]
    UID_FIELD_NUMBER: _ClassVar[int]
    GID_FIELD_NUMBER: _ClassVar[int]
    CGROUP_FIELD_NUMBER: _ClassVar[int]
    CONTAINER_ID_FIELD_NUMBER: _ClassVar[int]
    pid: int
    ppid: int
    exe: str
    args: _containers.RepeatedScalarFieldContainer[str]
    start_ts_ns: int
    uid: int
    gid: int
    cgroup: str
    container_id: str
    def __init__(self, pid: _Optional[int] = ..., ppid: _Optional[int] = ..., exe: _Optional[str] = ..., args: _Optional[_Iterable[str]] = ..., start_ts_ns: _Optional[int] = ..., uid: _Optional[int] = ..., gid: _Optional[int] = ..., cgroup: _Optional[str] = ..., container_id: _Optional[str] = ...) -> None: ...

class FlowEvent(_message.Message):
    __slots__ = ("src_ip", "dst_ip", "src_port", "dst_port", "protocol", "bytes_sent", "bytes_recv", "flags", "start_time", "end_time", "bytes_tx", "bytes_rx", "proto", "duration_ms")
    SRC_IP_FIELD_NUMBER: _ClassVar[int]
    DST_IP_FIELD_NUMBER: _ClassVar[int]
    SRC_PORT_FIELD_NUMBER: _ClassVar[int]
    DST_PORT_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_FIELD_NUMBER: _ClassVar[int]
    BYTES_SENT_FIELD_NUMBER: _ClassVar[int]
    BYTES_RECV_FIELD_NUMBER: _ClassVar[int]
    FLAGS_FIELD_NUMBER: _ClassVar[int]
    START_TIME_FIELD_NUMBER: _ClassVar[int]
    END_TIME_FIELD_NUMBER: _ClassVar[int]
    BYTES_TX_FIELD_NUMBER: _ClassVar[int]
    BYTES_RX_FIELD_NUMBER: _ClassVar[int]
    PROTO_FIELD_NUMBER: _ClassVar[int]
    DURATION_MS_FIELD_NUMBER: _ClassVar[int]
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes_sent: int
    bytes_recv: int
    flags: int
    start_time: int
    end_time: int
    bytes_tx: int
    bytes_rx: int
    proto: str
    duration_ms: int
    def __init__(self, src_ip: _Optional[str] = ..., dst_ip: _Optional[str] = ..., src_port: _Optional[int] = ..., dst_port: _Optional[int] = ..., protocol: _Optional[str] = ..., bytes_sent: _Optional[int] = ..., bytes_recv: _Optional[int] = ..., flags: _Optional[int] = ..., start_time: _Optional[int] = ..., end_time: _Optional[int] = ..., bytes_tx: _Optional[int] = ..., bytes_rx: _Optional[int] = ..., proto: _Optional[str] = ..., duration_ms: _Optional[int] = ...) -> None: ...

class Envelope(_message.Message):
    __slots__ = ("version", "ts_ns", "idempotency_key", "flow", "sig", "prev_sig", "payload")
    VERSION_FIELD_NUMBER: _ClassVar[int]
    TS_NS_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_KEY_FIELD_NUMBER: _ClassVar[int]
    FLOW_FIELD_NUMBER: _ClassVar[int]
    SIG_FIELD_NUMBER: _ClassVar[int]
    PREV_SIG_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    version: str
    ts_ns: int
    idempotency_key: str
    flow: FlowEvent
    sig: bytes
    prev_sig: bytes
    payload: bytes
    def __init__(self, version: _Optional[str] = ..., ts_ns: _Optional[int] = ..., idempotency_key: _Optional[str] = ..., flow: _Optional[_Union[FlowEvent, _Mapping]] = ..., sig: _Optional[bytes] = ..., prev_sig: _Optional[bytes] = ..., payload: _Optional[bytes] = ...) -> None: ...

class PublishAck(_message.Message):
    __slots__ = ("status", "reason", "backoff_hint_ms")
    class Status(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        OK: _ClassVar[PublishAck.Status]
        RETRY: _ClassVar[PublishAck.Status]
        INVALID: _ClassVar[PublishAck.Status]
        UNAUTHORIZED: _ClassVar[PublishAck.Status]
    OK: PublishAck.Status
    RETRY: PublishAck.Status
    INVALID: PublishAck.Status
    UNAUTHORIZED: PublishAck.Status
    STATUS_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    BACKOFF_HINT_MS_FIELD_NUMBER: _ClassVar[int]
    status: PublishAck.Status
    reason: str
    backoff_hint_ms: int
    def __init__(self, status: _Optional[_Union[PublishAck.Status, str]] = ..., reason: _Optional[str] = ..., backoff_hint_ms: _Optional[int] = ...) -> None: ...
