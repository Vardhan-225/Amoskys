import messaging_schema_pb2 as _messaging_schema_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class DeviceTelemetry(_message.Message):
    __slots__ = ("device_id", "device_type", "protocol", "metadata", "events", "security", "timestamp_ns", "collection_agent", "agent_version", "is_compressed", "compression_algorithm", "batch_size", "collection_interval_ms")
    DEVICE_ID_FIELD_NUMBER: _ClassVar[int]
    DEVICE_TYPE_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_FIELD_NUMBER: _ClassVar[int]
    METADATA_FIELD_NUMBER: _ClassVar[int]
    EVENTS_FIELD_NUMBER: _ClassVar[int]
    SECURITY_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_NS_FIELD_NUMBER: _ClassVar[int]
    COLLECTION_AGENT_FIELD_NUMBER: _ClassVar[int]
    AGENT_VERSION_FIELD_NUMBER: _ClassVar[int]
    IS_COMPRESSED_FIELD_NUMBER: _ClassVar[int]
    COMPRESSION_ALGORITHM_FIELD_NUMBER: _ClassVar[int]
    BATCH_SIZE_FIELD_NUMBER: _ClassVar[int]
    COLLECTION_INTERVAL_MS_FIELD_NUMBER: _ClassVar[int]
    device_id: str
    device_type: str
    protocol: str
    metadata: DeviceMetadata
    events: _containers.RepeatedCompositeFieldContainer[TelemetryEvent]
    security: SecurityContext
    timestamp_ns: int
    collection_agent: str
    agent_version: str
    is_compressed: bool
    compression_algorithm: str
    batch_size: int
    collection_interval_ms: int
    def __init__(self, device_id: _Optional[str] = ..., device_type: _Optional[str] = ..., protocol: _Optional[str] = ..., metadata: _Optional[_Union[DeviceMetadata, _Mapping]] = ..., events: _Optional[_Iterable[_Union[TelemetryEvent, _Mapping]]] = ..., security: _Optional[_Union[SecurityContext, _Mapping]] = ..., timestamp_ns: _Optional[int] = ..., collection_agent: _Optional[str] = ..., agent_version: _Optional[str] = ..., is_compressed: bool = ..., compression_algorithm: _Optional[str] = ..., batch_size: _Optional[int] = ..., collection_interval_ms: _Optional[int] = ...) -> None: ...

class DeviceMetadata(_message.Message):
    __slots__ = ("manufacturer", "model", "firmware_version", "hardware_version", "serial_number", "ip_address", "mac_address", "subnet", "vlan_id", "protocols", "open_ports", "capabilities", "physical_location", "department", "asset_tag", "compliance_frameworks", "vulnerability_score", "criticality_level", "custom_properties")
    class CapabilitiesEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    class CustomPropertiesEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    MANUFACTURER_FIELD_NUMBER: _ClassVar[int]
    MODEL_FIELD_NUMBER: _ClassVar[int]
    FIRMWARE_VERSION_FIELD_NUMBER: _ClassVar[int]
    HARDWARE_VERSION_FIELD_NUMBER: _ClassVar[int]
    SERIAL_NUMBER_FIELD_NUMBER: _ClassVar[int]
    IP_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    MAC_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    SUBNET_FIELD_NUMBER: _ClassVar[int]
    VLAN_ID_FIELD_NUMBER: _ClassVar[int]
    PROTOCOLS_FIELD_NUMBER: _ClassVar[int]
    OPEN_PORTS_FIELD_NUMBER: _ClassVar[int]
    CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    PHYSICAL_LOCATION_FIELD_NUMBER: _ClassVar[int]
    DEPARTMENT_FIELD_NUMBER: _ClassVar[int]
    ASSET_TAG_FIELD_NUMBER: _ClassVar[int]
    COMPLIANCE_FRAMEWORKS_FIELD_NUMBER: _ClassVar[int]
    VULNERABILITY_SCORE_FIELD_NUMBER: _ClassVar[int]
    CRITICALITY_LEVEL_FIELD_NUMBER: _ClassVar[int]
    CUSTOM_PROPERTIES_FIELD_NUMBER: _ClassVar[int]
    manufacturer: str
    model: str
    firmware_version: str
    hardware_version: str
    serial_number: str
    ip_address: str
    mac_address: str
    subnet: str
    vlan_id: str
    protocols: _containers.RepeatedScalarFieldContainer[str]
    open_ports: _containers.RepeatedScalarFieldContainer[int]
    capabilities: _containers.ScalarMap[str, str]
    physical_location: str
    department: str
    asset_tag: str
    compliance_frameworks: _containers.RepeatedScalarFieldContainer[str]
    vulnerability_score: float
    criticality_level: str
    custom_properties: _containers.ScalarMap[str, str]
    def __init__(self, manufacturer: _Optional[str] = ..., model: _Optional[str] = ..., firmware_version: _Optional[str] = ..., hardware_version: _Optional[str] = ..., serial_number: _Optional[str] = ..., ip_address: _Optional[str] = ..., mac_address: _Optional[str] = ..., subnet: _Optional[str] = ..., vlan_id: _Optional[str] = ..., protocols: _Optional[_Iterable[str]] = ..., open_ports: _Optional[_Iterable[int]] = ..., capabilities: _Optional[_Mapping[str, str]] = ..., physical_location: _Optional[str] = ..., department: _Optional[str] = ..., asset_tag: _Optional[str] = ..., compliance_frameworks: _Optional[_Iterable[str]] = ..., vulnerability_score: _Optional[float] = ..., criticality_level: _Optional[str] = ..., custom_properties: _Optional[_Mapping[str, str]] = ...) -> None: ...

class TelemetryEvent(_message.Message):
    __slots__ = ("event_id", "event_type", "severity", "event_timestamp_ns", "metric_data", "log_data", "alarm_data", "status_data", "security_event", "audit_event", "tags", "attributes", "source_component", "confidence_score", "is_synthetic", "retry_count")
    class AttributesEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    EVENT_ID_FIELD_NUMBER: _ClassVar[int]
    EVENT_TYPE_FIELD_NUMBER: _ClassVar[int]
    SEVERITY_FIELD_NUMBER: _ClassVar[int]
    EVENT_TIMESTAMP_NS_FIELD_NUMBER: _ClassVar[int]
    METRIC_DATA_FIELD_NUMBER: _ClassVar[int]
    LOG_DATA_FIELD_NUMBER: _ClassVar[int]
    ALARM_DATA_FIELD_NUMBER: _ClassVar[int]
    STATUS_DATA_FIELD_NUMBER: _ClassVar[int]
    SECURITY_EVENT_FIELD_NUMBER: _ClassVar[int]
    AUDIT_EVENT_FIELD_NUMBER: _ClassVar[int]
    TAGS_FIELD_NUMBER: _ClassVar[int]
    ATTRIBUTES_FIELD_NUMBER: _ClassVar[int]
    SOURCE_COMPONENT_FIELD_NUMBER: _ClassVar[int]
    CONFIDENCE_SCORE_FIELD_NUMBER: _ClassVar[int]
    IS_SYNTHETIC_FIELD_NUMBER: _ClassVar[int]
    RETRY_COUNT_FIELD_NUMBER: _ClassVar[int]
    event_id: str
    event_type: str
    severity: str
    event_timestamp_ns: int
    metric_data: MetricData
    log_data: LogData
    alarm_data: AlarmData
    status_data: StatusData
    security_event: SecurityEvent
    audit_event: AuditEvent
    tags: _containers.RepeatedScalarFieldContainer[str]
    attributes: _containers.ScalarMap[str, str]
    source_component: str
    confidence_score: float
    is_synthetic: bool
    retry_count: int
    def __init__(self, event_id: _Optional[str] = ..., event_type: _Optional[str] = ..., severity: _Optional[str] = ..., event_timestamp_ns: _Optional[int] = ..., metric_data: _Optional[_Union[MetricData, _Mapping]] = ..., log_data: _Optional[_Union[LogData, _Mapping]] = ..., alarm_data: _Optional[_Union[AlarmData, _Mapping]] = ..., status_data: _Optional[_Union[StatusData, _Mapping]] = ..., security_event: _Optional[_Union[SecurityEvent, _Mapping]] = ..., audit_event: _Optional[_Union[AuditEvent, _Mapping]] = ..., tags: _Optional[_Iterable[str]] = ..., attributes: _Optional[_Mapping[str, str]] = ..., source_component: _Optional[str] = ..., confidence_score: _Optional[float] = ..., is_synthetic: bool = ..., retry_count: _Optional[int] = ...) -> None: ...

class MetricData(_message.Message):
    __slots__ = ("metric_name", "metric_type", "numeric_value", "string_value", "boolean_value", "binary_value", "unit", "labels", "min_value", "max_value", "avg_value", "sample_count")
    class LabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    METRIC_NAME_FIELD_NUMBER: _ClassVar[int]
    METRIC_TYPE_FIELD_NUMBER: _ClassVar[int]
    NUMERIC_VALUE_FIELD_NUMBER: _ClassVar[int]
    STRING_VALUE_FIELD_NUMBER: _ClassVar[int]
    BOOLEAN_VALUE_FIELD_NUMBER: _ClassVar[int]
    BINARY_VALUE_FIELD_NUMBER: _ClassVar[int]
    UNIT_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    MIN_VALUE_FIELD_NUMBER: _ClassVar[int]
    MAX_VALUE_FIELD_NUMBER: _ClassVar[int]
    AVG_VALUE_FIELD_NUMBER: _ClassVar[int]
    SAMPLE_COUNT_FIELD_NUMBER: _ClassVar[int]
    metric_name: str
    metric_type: str
    numeric_value: float
    string_value: str
    boolean_value: bool
    binary_value: bytes
    unit: str
    labels: _containers.ScalarMap[str, str]
    min_value: float
    max_value: float
    avg_value: float
    sample_count: int
    def __init__(self, metric_name: _Optional[str] = ..., metric_type: _Optional[str] = ..., numeric_value: _Optional[float] = ..., string_value: _Optional[str] = ..., boolean_value: bool = ..., binary_value: _Optional[bytes] = ..., unit: _Optional[str] = ..., labels: _Optional[_Mapping[str, str]] = ..., min_value: _Optional[float] = ..., max_value: _Optional[float] = ..., avg_value: _Optional[float] = ..., sample_count: _Optional[int] = ...) -> None: ...

class LogData(_message.Message):
    __slots__ = ("log_level", "message", "source_file", "line_number", "function_name", "thread_id", "process_name", "fields", "correlation_id", "trace_id", "contains_pii", "security_relevant", "extracted_indicators")
    class FieldsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    LOG_LEVEL_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FILE_FIELD_NUMBER: _ClassVar[int]
    LINE_NUMBER_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_NAME_FIELD_NUMBER: _ClassVar[int]
    THREAD_ID_FIELD_NUMBER: _ClassVar[int]
    PROCESS_NAME_FIELD_NUMBER: _ClassVar[int]
    FIELDS_FIELD_NUMBER: _ClassVar[int]
    CORRELATION_ID_FIELD_NUMBER: _ClassVar[int]
    TRACE_ID_FIELD_NUMBER: _ClassVar[int]
    CONTAINS_PII_FIELD_NUMBER: _ClassVar[int]
    SECURITY_RELEVANT_FIELD_NUMBER: _ClassVar[int]
    EXTRACTED_INDICATORS_FIELD_NUMBER: _ClassVar[int]
    log_level: str
    message: str
    source_file: str
    line_number: int
    function_name: str
    thread_id: str
    process_name: str
    fields: _containers.ScalarMap[str, str]
    correlation_id: str
    trace_id: str
    contains_pii: bool
    security_relevant: bool
    extracted_indicators: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, log_level: _Optional[str] = ..., message: _Optional[str] = ..., source_file: _Optional[str] = ..., line_number: _Optional[int] = ..., function_name: _Optional[str] = ..., thread_id: _Optional[str] = ..., process_name: _Optional[str] = ..., fields: _Optional[_Mapping[str, str]] = ..., correlation_id: _Optional[str] = ..., trace_id: _Optional[str] = ..., contains_pii: bool = ..., security_relevant: bool = ..., extracted_indicators: _Optional[_Iterable[str]] = ...) -> None: ...

class AlarmData(_message.Message):
    __slots__ = ("alarm_id", "alarm_name", "alarm_type", "state", "description", "cause", "recommended_action", "threshold_value", "current_value", "threshold_operator", "alarm_time_ns", "ack_time_ns", "clear_time_ns", "priority", "auto_acknowledgeable", "escalation_timeout_seconds")
    ALARM_ID_FIELD_NUMBER: _ClassVar[int]
    ALARM_NAME_FIELD_NUMBER: _ClassVar[int]
    ALARM_TYPE_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    CAUSE_FIELD_NUMBER: _ClassVar[int]
    RECOMMENDED_ACTION_FIELD_NUMBER: _ClassVar[int]
    THRESHOLD_VALUE_FIELD_NUMBER: _ClassVar[int]
    CURRENT_VALUE_FIELD_NUMBER: _ClassVar[int]
    THRESHOLD_OPERATOR_FIELD_NUMBER: _ClassVar[int]
    ALARM_TIME_NS_FIELD_NUMBER: _ClassVar[int]
    ACK_TIME_NS_FIELD_NUMBER: _ClassVar[int]
    CLEAR_TIME_NS_FIELD_NUMBER: _ClassVar[int]
    PRIORITY_FIELD_NUMBER: _ClassVar[int]
    AUTO_ACKNOWLEDGEABLE_FIELD_NUMBER: _ClassVar[int]
    ESCALATION_TIMEOUT_SECONDS_FIELD_NUMBER: _ClassVar[int]
    alarm_id: str
    alarm_name: str
    alarm_type: str
    state: str
    description: str
    cause: str
    recommended_action: str
    threshold_value: float
    current_value: float
    threshold_operator: str
    alarm_time_ns: int
    ack_time_ns: int
    clear_time_ns: int
    priority: str
    auto_acknowledgeable: bool
    escalation_timeout_seconds: int
    def __init__(self, alarm_id: _Optional[str] = ..., alarm_name: _Optional[str] = ..., alarm_type: _Optional[str] = ..., state: _Optional[str] = ..., description: _Optional[str] = ..., cause: _Optional[str] = ..., recommended_action: _Optional[str] = ..., threshold_value: _Optional[float] = ..., current_value: _Optional[float] = ..., threshold_operator: _Optional[str] = ..., alarm_time_ns: _Optional[int] = ..., ack_time_ns: _Optional[int] = ..., clear_time_ns: _Optional[int] = ..., priority: _Optional[str] = ..., auto_acknowledgeable: bool = ..., escalation_timeout_seconds: _Optional[int] = ...) -> None: ...

class StatusData(_message.Message):
    __slots__ = ("component_name", "status", "previous_status", "status_change_time_ns", "health_score", "health_status", "cpu_usage_percent", "memory_usage_percent", "disk_usage_percent", "network_usage_mbps", "uptime_seconds", "restart_count", "last_restart_time_ns", "response_time_ms", "requests_per_second", "error_rate_percent")
    COMPONENT_NAME_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_STATUS_FIELD_NUMBER: _ClassVar[int]
    STATUS_CHANGE_TIME_NS_FIELD_NUMBER: _ClassVar[int]
    HEALTH_SCORE_FIELD_NUMBER: _ClassVar[int]
    HEALTH_STATUS_FIELD_NUMBER: _ClassVar[int]
    CPU_USAGE_PERCENT_FIELD_NUMBER: _ClassVar[int]
    MEMORY_USAGE_PERCENT_FIELD_NUMBER: _ClassVar[int]
    DISK_USAGE_PERCENT_FIELD_NUMBER: _ClassVar[int]
    NETWORK_USAGE_MBPS_FIELD_NUMBER: _ClassVar[int]
    UPTIME_SECONDS_FIELD_NUMBER: _ClassVar[int]
    RESTART_COUNT_FIELD_NUMBER: _ClassVar[int]
    LAST_RESTART_TIME_NS_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_TIME_MS_FIELD_NUMBER: _ClassVar[int]
    REQUESTS_PER_SECOND_FIELD_NUMBER: _ClassVar[int]
    ERROR_RATE_PERCENT_FIELD_NUMBER: _ClassVar[int]
    component_name: str
    status: str
    previous_status: str
    status_change_time_ns: int
    health_score: float
    health_status: str
    cpu_usage_percent: float
    memory_usage_percent: float
    disk_usage_percent: float
    network_usage_mbps: float
    uptime_seconds: float
    restart_count: int
    last_restart_time_ns: int
    response_time_ms: float
    requests_per_second: int
    error_rate_percent: float
    def __init__(self, component_name: _Optional[str] = ..., status: _Optional[str] = ..., previous_status: _Optional[str] = ..., status_change_time_ns: _Optional[int] = ..., health_score: _Optional[float] = ..., health_status: _Optional[str] = ..., cpu_usage_percent: _Optional[float] = ..., memory_usage_percent: _Optional[float] = ..., disk_usage_percent: _Optional[float] = ..., network_usage_mbps: _Optional[float] = ..., uptime_seconds: _Optional[float] = ..., restart_count: _Optional[int] = ..., last_restart_time_ns: _Optional[int] = ..., response_time_ms: _Optional[float] = ..., requests_per_second: _Optional[int] = ..., error_rate_percent: _Optional[float] = ...) -> None: ...

class SecurityEvent(_message.Message):
    __slots__ = ("event_category", "event_action", "event_outcome", "user_id", "user_name", "source_ip", "user_agent", "target_resource", "target_type", "affected_asset", "threat_indicators", "risk_score", "attack_vector", "mitre_techniques", "response_actions", "requires_investigation", "analyst_notes")
    EVENT_CATEGORY_FIELD_NUMBER: _ClassVar[int]
    EVENT_ACTION_FIELD_NUMBER: _ClassVar[int]
    EVENT_OUTCOME_FIELD_NUMBER: _ClassVar[int]
    USER_ID_FIELD_NUMBER: _ClassVar[int]
    USER_NAME_FIELD_NUMBER: _ClassVar[int]
    SOURCE_IP_FIELD_NUMBER: _ClassVar[int]
    USER_AGENT_FIELD_NUMBER: _ClassVar[int]
    TARGET_RESOURCE_FIELD_NUMBER: _ClassVar[int]
    TARGET_TYPE_FIELD_NUMBER: _ClassVar[int]
    AFFECTED_ASSET_FIELD_NUMBER: _ClassVar[int]
    THREAT_INDICATORS_FIELD_NUMBER: _ClassVar[int]
    RISK_SCORE_FIELD_NUMBER: _ClassVar[int]
    ATTACK_VECTOR_FIELD_NUMBER: _ClassVar[int]
    MITRE_TECHNIQUES_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_ACTIONS_FIELD_NUMBER: _ClassVar[int]
    REQUIRES_INVESTIGATION_FIELD_NUMBER: _ClassVar[int]
    ANALYST_NOTES_FIELD_NUMBER: _ClassVar[int]
    event_category: str
    event_action: str
    event_outcome: str
    user_id: str
    user_name: str
    source_ip: str
    user_agent: str
    target_resource: str
    target_type: str
    affected_asset: str
    threat_indicators: _containers.RepeatedCompositeFieldContainer[ThreatIndicator]
    risk_score: float
    attack_vector: str
    mitre_techniques: _containers.RepeatedScalarFieldContainer[str]
    response_actions: _containers.RepeatedScalarFieldContainer[str]
    requires_investigation: bool
    analyst_notes: str
    def __init__(self, event_category: _Optional[str] = ..., event_action: _Optional[str] = ..., event_outcome: _Optional[str] = ..., user_id: _Optional[str] = ..., user_name: _Optional[str] = ..., source_ip: _Optional[str] = ..., user_agent: _Optional[str] = ..., target_resource: _Optional[str] = ..., target_type: _Optional[str] = ..., affected_asset: _Optional[str] = ..., threat_indicators: _Optional[_Iterable[_Union[ThreatIndicator, _Mapping]]] = ..., risk_score: _Optional[float] = ..., attack_vector: _Optional[str] = ..., mitre_techniques: _Optional[_Iterable[str]] = ..., response_actions: _Optional[_Iterable[str]] = ..., requires_investigation: bool = ..., analyst_notes: _Optional[str] = ...) -> None: ...

class AuditEvent(_message.Message):
    __slots__ = ("audit_category", "action_performed", "object_type", "object_id", "actor_id", "actor_type", "session_id", "before_value", "after_value", "changed_fields", "compliance_frameworks", "retention_required", "retention_days", "legal_hold_id", "digital_signature", "hash_algorithm", "content_hash")
    AUDIT_CATEGORY_FIELD_NUMBER: _ClassVar[int]
    ACTION_PERFORMED_FIELD_NUMBER: _ClassVar[int]
    OBJECT_TYPE_FIELD_NUMBER: _ClassVar[int]
    OBJECT_ID_FIELD_NUMBER: _ClassVar[int]
    ACTOR_ID_FIELD_NUMBER: _ClassVar[int]
    ACTOR_TYPE_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    BEFORE_VALUE_FIELD_NUMBER: _ClassVar[int]
    AFTER_VALUE_FIELD_NUMBER: _ClassVar[int]
    CHANGED_FIELDS_FIELD_NUMBER: _ClassVar[int]
    COMPLIANCE_FRAMEWORKS_FIELD_NUMBER: _ClassVar[int]
    RETENTION_REQUIRED_FIELD_NUMBER: _ClassVar[int]
    RETENTION_DAYS_FIELD_NUMBER: _ClassVar[int]
    LEGAL_HOLD_ID_FIELD_NUMBER: _ClassVar[int]
    DIGITAL_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    HASH_ALGORITHM_FIELD_NUMBER: _ClassVar[int]
    CONTENT_HASH_FIELD_NUMBER: _ClassVar[int]
    audit_category: str
    action_performed: str
    object_type: str
    object_id: str
    actor_id: str
    actor_type: str
    session_id: str
    before_value: str
    after_value: str
    changed_fields: _containers.RepeatedScalarFieldContainer[str]
    compliance_frameworks: _containers.RepeatedScalarFieldContainer[str]
    retention_required: bool
    retention_days: int
    legal_hold_id: str
    digital_signature: str
    hash_algorithm: str
    content_hash: str
    def __init__(self, audit_category: _Optional[str] = ..., action_performed: _Optional[str] = ..., object_type: _Optional[str] = ..., object_id: _Optional[str] = ..., actor_id: _Optional[str] = ..., actor_type: _Optional[str] = ..., session_id: _Optional[str] = ..., before_value: _Optional[str] = ..., after_value: _Optional[str] = ..., changed_fields: _Optional[_Iterable[str]] = ..., compliance_frameworks: _Optional[_Iterable[str]] = ..., retention_required: bool = ..., retention_days: _Optional[int] = ..., legal_hold_id: _Optional[str] = ..., digital_signature: _Optional[str] = ..., hash_algorithm: _Optional[str] = ..., content_hash: _Optional[str] = ...) -> None: ...

class ThreatIndicator(_message.Message):
    __slots__ = ("indicator_type", "indicator_value", "threat_type", "confidence", "source", "first_seen_ns", "last_seen_ns", "associated_campaigns")
    INDICATOR_TYPE_FIELD_NUMBER: _ClassVar[int]
    INDICATOR_VALUE_FIELD_NUMBER: _ClassVar[int]
    THREAT_TYPE_FIELD_NUMBER: _ClassVar[int]
    CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    FIRST_SEEN_NS_FIELD_NUMBER: _ClassVar[int]
    LAST_SEEN_NS_FIELD_NUMBER: _ClassVar[int]
    ASSOCIATED_CAMPAIGNS_FIELD_NUMBER: _ClassVar[int]
    indicator_type: str
    indicator_value: str
    threat_type: str
    confidence: float
    source: str
    first_seen_ns: int
    last_seen_ns: int
    associated_campaigns: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, indicator_type: _Optional[str] = ..., indicator_value: _Optional[str] = ..., threat_type: _Optional[str] = ..., confidence: _Optional[float] = ..., source: _Optional[str] = ..., first_seen_ns: _Optional[int] = ..., last_seen_ns: _Optional[int] = ..., associated_campaigns: _Optional[_Iterable[str]] = ...) -> None: ...

class SecurityContext(_message.Message):
    __slots__ = ("device_trust_score", "authentication_method", "certificate_fingerprint", "certificate_valid", "network_zone", "security_groups", "encrypted_channel", "encryption_protocol", "permissions", "access_level", "privileged_access", "behavior_normal", "anomaly_score", "behavioral_flags", "compliance_status", "policy_violations", "data_classification")
    class ComplianceStatusEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: bool
        def __init__(self, key: _Optional[str] = ..., value: bool = ...) -> None: ...
    DEVICE_TRUST_SCORE_FIELD_NUMBER: _ClassVar[int]
    AUTHENTICATION_METHOD_FIELD_NUMBER: _ClassVar[int]
    CERTIFICATE_FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    CERTIFICATE_VALID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ZONE_FIELD_NUMBER: _ClassVar[int]
    SECURITY_GROUPS_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTED_CHANNEL_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTION_PROTOCOL_FIELD_NUMBER: _ClassVar[int]
    PERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    ACCESS_LEVEL_FIELD_NUMBER: _ClassVar[int]
    PRIVILEGED_ACCESS_FIELD_NUMBER: _ClassVar[int]
    BEHAVIOR_NORMAL_FIELD_NUMBER: _ClassVar[int]
    ANOMALY_SCORE_FIELD_NUMBER: _ClassVar[int]
    BEHAVIORAL_FLAGS_FIELD_NUMBER: _ClassVar[int]
    COMPLIANCE_STATUS_FIELD_NUMBER: _ClassVar[int]
    POLICY_VIOLATIONS_FIELD_NUMBER: _ClassVar[int]
    DATA_CLASSIFICATION_FIELD_NUMBER: _ClassVar[int]
    device_trust_score: float
    authentication_method: str
    certificate_fingerprint: str
    certificate_valid: bool
    network_zone: str
    security_groups: _containers.RepeatedScalarFieldContainer[str]
    encrypted_channel: bool
    encryption_protocol: str
    permissions: _containers.RepeatedScalarFieldContainer[str]
    access_level: str
    privileged_access: bool
    behavior_normal: bool
    anomaly_score: float
    behavioral_flags: _containers.RepeatedScalarFieldContainer[str]
    compliance_status: _containers.ScalarMap[str, bool]
    policy_violations: _containers.RepeatedScalarFieldContainer[str]
    data_classification: str
    def __init__(self, device_trust_score: _Optional[float] = ..., authentication_method: _Optional[str] = ..., certificate_fingerprint: _Optional[str] = ..., certificate_valid: bool = ..., network_zone: _Optional[str] = ..., security_groups: _Optional[_Iterable[str]] = ..., encrypted_channel: bool = ..., encryption_protocol: _Optional[str] = ..., permissions: _Optional[_Iterable[str]] = ..., access_level: _Optional[str] = ..., privileged_access: bool = ..., behavior_normal: bool = ..., anomaly_score: _Optional[float] = ..., behavioral_flags: _Optional[_Iterable[str]] = ..., compliance_status: _Optional[_Mapping[str, bool]] = ..., policy_violations: _Optional[_Iterable[str]] = ..., data_classification: _Optional[str] = ...) -> None: ...

class TelemetryBatch(_message.Message):
    __slots__ = ("telemetry_records", "batch_sequence_number", "batch_start_time_ns", "batch_end_time_ns", "is_compressed", "compression_algorithm", "original_size_bytes", "compressed_size_bytes", "total_events", "dropped_events", "data_quality_score", "edge_agent_id", "edge_location", "edge_metadata")
    class EdgeMetadataEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    TELEMETRY_RECORDS_FIELD_NUMBER: _ClassVar[int]
    BATCH_SEQUENCE_NUMBER_FIELD_NUMBER: _ClassVar[int]
    BATCH_START_TIME_NS_FIELD_NUMBER: _ClassVar[int]
    BATCH_END_TIME_NS_FIELD_NUMBER: _ClassVar[int]
    IS_COMPRESSED_FIELD_NUMBER: _ClassVar[int]
    COMPRESSION_ALGORITHM_FIELD_NUMBER: _ClassVar[int]
    ORIGINAL_SIZE_BYTES_FIELD_NUMBER: _ClassVar[int]
    COMPRESSED_SIZE_BYTES_FIELD_NUMBER: _ClassVar[int]
    TOTAL_EVENTS_FIELD_NUMBER: _ClassVar[int]
    DROPPED_EVENTS_FIELD_NUMBER: _ClassVar[int]
    DATA_QUALITY_SCORE_FIELD_NUMBER: _ClassVar[int]
    EDGE_AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    EDGE_LOCATION_FIELD_NUMBER: _ClassVar[int]
    EDGE_METADATA_FIELD_NUMBER: _ClassVar[int]
    telemetry_records: _containers.RepeatedCompositeFieldContainer[DeviceTelemetry]
    batch_sequence_number: int
    batch_start_time_ns: int
    batch_end_time_ns: int
    is_compressed: bool
    compression_algorithm: str
    original_size_bytes: int
    compressed_size_bytes: int
    total_events: int
    dropped_events: int
    data_quality_score: float
    edge_agent_id: str
    edge_location: str
    edge_metadata: _containers.ScalarMap[str, str]
    def __init__(self, telemetry_records: _Optional[_Iterable[_Union[DeviceTelemetry, _Mapping]]] = ..., batch_sequence_number: _Optional[int] = ..., batch_start_time_ns: _Optional[int] = ..., batch_end_time_ns: _Optional[int] = ..., is_compressed: bool = ..., compression_algorithm: _Optional[str] = ..., original_size_bytes: _Optional[int] = ..., compressed_size_bytes: _Optional[int] = ..., total_events: _Optional[int] = ..., dropped_events: _Optional[int] = ..., data_quality_score: _Optional[float] = ..., edge_agent_id: _Optional[str] = ..., edge_location: _Optional[str] = ..., edge_metadata: _Optional[_Mapping[str, str]] = ...) -> None: ...

class UniversalEnvelope(_message.Message):
    __slots__ = ("version", "ts_ns", "idempotency_key", "flow", "process", "device_telemetry", "telemetry_batch", "sig", "prev_sig", "signing_algorithm", "certificate_chain", "priority", "processing_hints", "target_processors", "retry_count", "max_processing_time_ns", "requires_acknowledgment")
    VERSION_FIELD_NUMBER: _ClassVar[int]
    TS_NS_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_KEY_FIELD_NUMBER: _ClassVar[int]
    FLOW_FIELD_NUMBER: _ClassVar[int]
    PROCESS_FIELD_NUMBER: _ClassVar[int]
    DEVICE_TELEMETRY_FIELD_NUMBER: _ClassVar[int]
    TELEMETRY_BATCH_FIELD_NUMBER: _ClassVar[int]
    SIG_FIELD_NUMBER: _ClassVar[int]
    PREV_SIG_FIELD_NUMBER: _ClassVar[int]
    SIGNING_ALGORITHM_FIELD_NUMBER: _ClassVar[int]
    CERTIFICATE_CHAIN_FIELD_NUMBER: _ClassVar[int]
    PRIORITY_FIELD_NUMBER: _ClassVar[int]
    PROCESSING_HINTS_FIELD_NUMBER: _ClassVar[int]
    TARGET_PROCESSORS_FIELD_NUMBER: _ClassVar[int]
    RETRY_COUNT_FIELD_NUMBER: _ClassVar[int]
    MAX_PROCESSING_TIME_NS_FIELD_NUMBER: _ClassVar[int]
    REQUIRES_ACKNOWLEDGMENT_FIELD_NUMBER: _ClassVar[int]
    version: str
    ts_ns: int
    idempotency_key: str
    flow: _messaging_schema_pb2.FlowEvent
    process: _messaging_schema_pb2.ProcessEvent
    device_telemetry: DeviceTelemetry
    telemetry_batch: TelemetryBatch
    sig: bytes
    prev_sig: bytes
    signing_algorithm: str
    certificate_chain: str
    priority: str
    processing_hints: _containers.RepeatedScalarFieldContainer[str]
    target_processors: str
    retry_count: int
    max_processing_time_ns: int
    requires_acknowledgment: bool
    def __init__(self, version: _Optional[str] = ..., ts_ns: _Optional[int] = ..., idempotency_key: _Optional[str] = ..., flow: _Optional[_Union[_messaging_schema_pb2.FlowEvent, _Mapping]] = ..., process: _Optional[_Union[_messaging_schema_pb2.ProcessEvent, _Mapping]] = ..., device_telemetry: _Optional[_Union[DeviceTelemetry, _Mapping]] = ..., telemetry_batch: _Optional[_Union[TelemetryBatch, _Mapping]] = ..., sig: _Optional[bytes] = ..., prev_sig: _Optional[bytes] = ..., signing_algorithm: _Optional[str] = ..., certificate_chain: _Optional[str] = ..., priority: _Optional[str] = ..., processing_hints: _Optional[_Iterable[str]] = ..., target_processors: _Optional[str] = ..., retry_count: _Optional[int] = ..., max_processing_time_ns: _Optional[int] = ..., requires_acknowledgment: bool = ...) -> None: ...

class UniversalAck(_message.Message):
    __slots__ = ("status", "reason", "backoff_hint_ms", "processed_timestamp_ns", "events_accepted", "events_rejected", "validation_errors", "current_load", "queue_depth", "processing_rate_per_second")
    class Status(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        OK: _ClassVar[UniversalAck.Status]
        RETRY: _ClassVar[UniversalAck.Status]
        INVALID: _ClassVar[UniversalAck.Status]
        OVERLOAD: _ClassVar[UniversalAck.Status]
        QUOTA_EXCEEDED: _ClassVar[UniversalAck.Status]
        PROCESSING_ERROR: _ClassVar[UniversalAck.Status]
        SECURITY_VIOLATION: _ClassVar[UniversalAck.Status]
    OK: UniversalAck.Status
    RETRY: UniversalAck.Status
    INVALID: UniversalAck.Status
    OVERLOAD: UniversalAck.Status
    QUOTA_EXCEEDED: UniversalAck.Status
    PROCESSING_ERROR: UniversalAck.Status
    SECURITY_VIOLATION: UniversalAck.Status
    STATUS_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    BACKOFF_HINT_MS_FIELD_NUMBER: _ClassVar[int]
    PROCESSED_TIMESTAMP_NS_FIELD_NUMBER: _ClassVar[int]
    EVENTS_ACCEPTED_FIELD_NUMBER: _ClassVar[int]
    EVENTS_REJECTED_FIELD_NUMBER: _ClassVar[int]
    VALIDATION_ERRORS_FIELD_NUMBER: _ClassVar[int]
    CURRENT_LOAD_FIELD_NUMBER: _ClassVar[int]
    QUEUE_DEPTH_FIELD_NUMBER: _ClassVar[int]
    PROCESSING_RATE_PER_SECOND_FIELD_NUMBER: _ClassVar[int]
    status: UniversalAck.Status
    reason: str
    backoff_hint_ms: int
    processed_timestamp_ns: int
    events_accepted: int
    events_rejected: int
    validation_errors: _containers.RepeatedScalarFieldContainer[str]
    current_load: float
    queue_depth: int
    processing_rate_per_second: int
    def __init__(self, status: _Optional[_Union[UniversalAck.Status, str]] = ..., reason: _Optional[str] = ..., backoff_hint_ms: _Optional[int] = ..., processed_timestamp_ns: _Optional[int] = ..., events_accepted: _Optional[int] = ..., events_rejected: _Optional[int] = ..., validation_errors: _Optional[_Iterable[str]] = ..., current_load: _Optional[float] = ..., queue_depth: _Optional[int] = ..., processing_rate_per_second: _Optional[int] = ...) -> None: ...

class DeviceRegistration(_message.Message):
    __slots__ = ("device_id", "metadata", "supported_protocols", "capabilities", "certificate_request", "device_fingerprint", "discovered_by_agent", "discovery_timestamp_ns", "discovery_method", "deployment_environment", "organizational_unit", "device_groups")
    DEVICE_ID_FIELD_NUMBER: _ClassVar[int]
    METADATA_FIELD_NUMBER: _ClassVar[int]
    SUPPORTED_PROTOCOLS_FIELD_NUMBER: _ClassVar[int]
    CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    CERTIFICATE_REQUEST_FIELD_NUMBER: _ClassVar[int]
    DEVICE_FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    DISCOVERED_BY_AGENT_FIELD_NUMBER: _ClassVar[int]
    DISCOVERY_TIMESTAMP_NS_FIELD_NUMBER: _ClassVar[int]
    DISCOVERY_METHOD_FIELD_NUMBER: _ClassVar[int]
    DEPLOYMENT_ENVIRONMENT_FIELD_NUMBER: _ClassVar[int]
    ORGANIZATIONAL_UNIT_FIELD_NUMBER: _ClassVar[int]
    DEVICE_GROUPS_FIELD_NUMBER: _ClassVar[int]
    device_id: str
    metadata: DeviceMetadata
    supported_protocols: _containers.RepeatedScalarFieldContainer[str]
    capabilities: _containers.RepeatedCompositeFieldContainer[TelemetryCapability]
    certificate_request: str
    device_fingerprint: str
    discovered_by_agent: str
    discovery_timestamp_ns: int
    discovery_method: str
    deployment_environment: str
    organizational_unit: str
    device_groups: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, device_id: _Optional[str] = ..., metadata: _Optional[_Union[DeviceMetadata, _Mapping]] = ..., supported_protocols: _Optional[_Iterable[str]] = ..., capabilities: _Optional[_Iterable[_Union[TelemetryCapability, _Mapping]]] = ..., certificate_request: _Optional[str] = ..., device_fingerprint: _Optional[str] = ..., discovered_by_agent: _Optional[str] = ..., discovery_timestamp_ns: _Optional[int] = ..., discovery_method: _Optional[str] = ..., deployment_environment: _Optional[str] = ..., organizational_unit: _Optional[str] = ..., device_groups: _Optional[_Iterable[str]] = ...) -> None: ...

class TelemetryCapability(_message.Message):
    __slots__ = ("protocol", "endpoint", "port", "supported_event_types", "max_events_per_second", "batch_size", "protocol_config", "reliability_level", "max_latency_ms", "supports_compression", "supports_encryption")
    class ProtocolConfigEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    PROTOCOL_FIELD_NUMBER: _ClassVar[int]
    ENDPOINT_FIELD_NUMBER: _ClassVar[int]
    PORT_FIELD_NUMBER: _ClassVar[int]
    SUPPORTED_EVENT_TYPES_FIELD_NUMBER: _ClassVar[int]
    MAX_EVENTS_PER_SECOND_FIELD_NUMBER: _ClassVar[int]
    BATCH_SIZE_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_CONFIG_FIELD_NUMBER: _ClassVar[int]
    RELIABILITY_LEVEL_FIELD_NUMBER: _ClassVar[int]
    MAX_LATENCY_MS_FIELD_NUMBER: _ClassVar[int]
    SUPPORTS_COMPRESSION_FIELD_NUMBER: _ClassVar[int]
    SUPPORTS_ENCRYPTION_FIELD_NUMBER: _ClassVar[int]
    protocol: str
    endpoint: str
    port: int
    supported_event_types: _containers.RepeatedScalarFieldContainer[str]
    max_events_per_second: int
    batch_size: int
    protocol_config: _containers.ScalarMap[str, str]
    reliability_level: str
    max_latency_ms: int
    supports_compression: bool
    supports_encryption: bool
    def __init__(self, protocol: _Optional[str] = ..., endpoint: _Optional[str] = ..., port: _Optional[int] = ..., supported_event_types: _Optional[_Iterable[str]] = ..., max_events_per_second: _Optional[int] = ..., batch_size: _Optional[int] = ..., protocol_config: _Optional[_Mapping[str, str]] = ..., reliability_level: _Optional[str] = ..., max_latency_ms: _Optional[int] = ..., supports_compression: bool = ..., supports_encryption: bool = ...) -> None: ...

class DeviceRegistrationResponse(_message.Message):
    __slots__ = ("accepted", "device_id", "certificate", "ca_certificate", "collection_policies", "heartbeat_interval_seconds", "assigned_agent_id", "allowed_protocols", "encryption_requirements", "security_policies", "rejection_reason")
    ACCEPTED_FIELD_NUMBER: _ClassVar[int]
    DEVICE_ID_FIELD_NUMBER: _ClassVar[int]
    CERTIFICATE_FIELD_NUMBER: _ClassVar[int]
    CA_CERTIFICATE_FIELD_NUMBER: _ClassVar[int]
    COLLECTION_POLICIES_FIELD_NUMBER: _ClassVar[int]
    HEARTBEAT_INTERVAL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    ASSIGNED_AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_PROTOCOLS_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTION_REQUIREMENTS_FIELD_NUMBER: _ClassVar[int]
    SECURITY_POLICIES_FIELD_NUMBER: _ClassVar[int]
    REJECTION_REASON_FIELD_NUMBER: _ClassVar[int]
    accepted: bool
    device_id: str
    certificate: str
    ca_certificate: str
    collection_policies: _containers.RepeatedCompositeFieldContainer[CollectionPolicy]
    heartbeat_interval_seconds: int
    assigned_agent_id: str
    allowed_protocols: _containers.RepeatedScalarFieldContainer[str]
    encryption_requirements: str
    security_policies: _containers.RepeatedScalarFieldContainer[str]
    rejection_reason: str
    def __init__(self, accepted: bool = ..., device_id: _Optional[str] = ..., certificate: _Optional[str] = ..., ca_certificate: _Optional[str] = ..., collection_policies: _Optional[_Iterable[_Union[CollectionPolicy, _Mapping]]] = ..., heartbeat_interval_seconds: _Optional[int] = ..., assigned_agent_id: _Optional[str] = ..., allowed_protocols: _Optional[_Iterable[str]] = ..., encryption_requirements: _Optional[str] = ..., security_policies: _Optional[_Iterable[str]] = ..., rejection_reason: _Optional[str] = ...) -> None: ...

class CollectionPolicy(_message.Message):
    __slots__ = ("policy_id", "device_type_pattern", "protocol", "collection_interval_seconds", "allowed_event_types", "blocked_event_types", "severity_filter", "enable_compression", "batch_size", "max_batch_age_seconds", "max_error_rate", "max_retry_attempts", "enable_local_buffering", "pii_scrubbing_rules", "compliance_tags", "data_retention_policy")
    POLICY_ID_FIELD_NUMBER: _ClassVar[int]
    DEVICE_TYPE_PATTERN_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_FIELD_NUMBER: _ClassVar[int]
    COLLECTION_INTERVAL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_EVENT_TYPES_FIELD_NUMBER: _ClassVar[int]
    BLOCKED_EVENT_TYPES_FIELD_NUMBER: _ClassVar[int]
    SEVERITY_FILTER_FIELD_NUMBER: _ClassVar[int]
    ENABLE_COMPRESSION_FIELD_NUMBER: _ClassVar[int]
    BATCH_SIZE_FIELD_NUMBER: _ClassVar[int]
    MAX_BATCH_AGE_SECONDS_FIELD_NUMBER: _ClassVar[int]
    MAX_ERROR_RATE_FIELD_NUMBER: _ClassVar[int]
    MAX_RETRY_ATTEMPTS_FIELD_NUMBER: _ClassVar[int]
    ENABLE_LOCAL_BUFFERING_FIELD_NUMBER: _ClassVar[int]
    PII_SCRUBBING_RULES_FIELD_NUMBER: _ClassVar[int]
    COMPLIANCE_TAGS_FIELD_NUMBER: _ClassVar[int]
    DATA_RETENTION_POLICY_FIELD_NUMBER: _ClassVar[int]
    policy_id: str
    device_type_pattern: str
    protocol: str
    collection_interval_seconds: int
    allowed_event_types: _containers.RepeatedScalarFieldContainer[str]
    blocked_event_types: _containers.RepeatedScalarFieldContainer[str]
    severity_filter: str
    enable_compression: bool
    batch_size: int
    max_batch_age_seconds: int
    max_error_rate: float
    max_retry_attempts: int
    enable_local_buffering: bool
    pii_scrubbing_rules: _containers.RepeatedScalarFieldContainer[str]
    compliance_tags: _containers.RepeatedScalarFieldContainer[str]
    data_retention_policy: str
    def __init__(self, policy_id: _Optional[str] = ..., device_type_pattern: _Optional[str] = ..., protocol: _Optional[str] = ..., collection_interval_seconds: _Optional[int] = ..., allowed_event_types: _Optional[_Iterable[str]] = ..., blocked_event_types: _Optional[_Iterable[str]] = ..., severity_filter: _Optional[str] = ..., enable_compression: bool = ..., batch_size: _Optional[int] = ..., max_batch_age_seconds: _Optional[int] = ..., max_error_rate: _Optional[float] = ..., max_retry_attempts: _Optional[int] = ..., enable_local_buffering: bool = ..., pii_scrubbing_rules: _Optional[_Iterable[str]] = ..., compliance_tags: _Optional[_Iterable[str]] = ..., data_retention_policy: _Optional[str] = ...) -> None: ...

class DeviceDeregistration(_message.Message):
    __slots__ = ("device_id", "reason", "deregistration_timestamp_ns", "deregistered_by")
    DEVICE_ID_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    DEREGISTRATION_TIMESTAMP_NS_FIELD_NUMBER: _ClassVar[int]
    DEREGISTERED_BY_FIELD_NUMBER: _ClassVar[int]
    device_id: str
    reason: str
    deregistration_timestamp_ns: int
    deregistered_by: str
    def __init__(self, device_id: _Optional[str] = ..., reason: _Optional[str] = ..., deregistration_timestamp_ns: _Optional[int] = ..., deregistered_by: _Optional[str] = ...) -> None: ...

class DeviceDeregistrationResponse(_message.Message):
    __slots__ = ("accepted", "reason", "final_data_retention_until_ns")
    ACCEPTED_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    FINAL_DATA_RETENTION_UNTIL_NS_FIELD_NUMBER: _ClassVar[int]
    accepted: bool
    reason: str
    final_data_retention_until_ns: int
    def __init__(self, accepted: bool = ..., reason: _Optional[str] = ..., final_data_retention_until_ns: _Optional[int] = ...) -> None: ...

class HealthRequest(_message.Message):
    __slots__ = ("components",)
    COMPONENTS_FIELD_NUMBER: _ClassVar[int]
    components: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, components: _Optional[_Iterable[str]] = ...) -> None: ...

class HealthResponse(_message.Message):
    __slots__ = ("overall_status", "component_health", "timestamp_ns")
    class ComponentHealthEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: ComponentHealth
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[ComponentHealth, _Mapping]] = ...) -> None: ...
    OVERALL_STATUS_FIELD_NUMBER: _ClassVar[int]
    COMPONENT_HEALTH_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_NS_FIELD_NUMBER: _ClassVar[int]
    overall_status: str
    component_health: _containers.MessageMap[str, ComponentHealth]
    timestamp_ns: int
    def __init__(self, overall_status: _Optional[str] = ..., component_health: _Optional[_Mapping[str, ComponentHealth]] = ..., timestamp_ns: _Optional[int] = ...) -> None: ...

class ComponentHealth(_message.Message):
    __slots__ = ("status", "message", "metrics", "last_check_ns")
    class MetricsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    STATUS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    METRICS_FIELD_NUMBER: _ClassVar[int]
    LAST_CHECK_NS_FIELD_NUMBER: _ClassVar[int]
    status: str
    message: str
    metrics: _containers.ScalarMap[str, str]
    last_check_ns: int
    def __init__(self, status: _Optional[str] = ..., message: _Optional[str] = ..., metrics: _Optional[_Mapping[str, str]] = ..., last_check_ns: _Optional[int] = ...) -> None: ...

class StatusRequest(_message.Message):
    __slots__ = ("include_metrics", "include_device_count")
    INCLUDE_METRICS_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_DEVICE_COUNT_FIELD_NUMBER: _ClassVar[int]
    include_metrics: bool
    include_device_count: bool
    def __init__(self, include_metrics: bool = ..., include_device_count: bool = ...) -> None: ...

class StatusResponse(_message.Message):
    __slots__ = ("service_version", "uptime_seconds", "connected_devices", "total_events_processed", "events_per_second", "current_load", "service_metrics")
    class ServiceMetricsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    SERVICE_VERSION_FIELD_NUMBER: _ClassVar[int]
    UPTIME_SECONDS_FIELD_NUMBER: _ClassVar[int]
    CONNECTED_DEVICES_FIELD_NUMBER: _ClassVar[int]
    TOTAL_EVENTS_PROCESSED_FIELD_NUMBER: _ClassVar[int]
    EVENTS_PER_SECOND_FIELD_NUMBER: _ClassVar[int]
    CURRENT_LOAD_FIELD_NUMBER: _ClassVar[int]
    SERVICE_METRICS_FIELD_NUMBER: _ClassVar[int]
    service_version: str
    uptime_seconds: int
    connected_devices: int
    total_events_processed: int
    events_per_second: int
    current_load: float
    service_metrics: _containers.ScalarMap[str, str]
    def __init__(self, service_version: _Optional[str] = ..., uptime_seconds: _Optional[int] = ..., connected_devices: _Optional[int] = ..., total_events_processed: _Optional[int] = ..., events_per_second: _Optional[int] = ..., current_load: _Optional[float] = ..., service_metrics: _Optional[_Mapping[str, str]] = ...) -> None: ...

class MetricsRequest(_message.Message):
    __slots__ = ("metric_names", "start_time_ns", "end_time_ns")
    METRIC_NAMES_FIELD_NUMBER: _ClassVar[int]
    START_TIME_NS_FIELD_NUMBER: _ClassVar[int]
    END_TIME_NS_FIELD_NUMBER: _ClassVar[int]
    metric_names: _containers.RepeatedScalarFieldContainer[str]
    start_time_ns: int
    end_time_ns: int
    def __init__(self, metric_names: _Optional[_Iterable[str]] = ..., start_time_ns: _Optional[int] = ..., end_time_ns: _Optional[int] = ...) -> None: ...

class MetricsResponse(_message.Message):
    __slots__ = ("metrics", "collection_timestamp_ns")
    METRICS_FIELD_NUMBER: _ClassVar[int]
    COLLECTION_TIMESTAMP_NS_FIELD_NUMBER: _ClassVar[int]
    metrics: _containers.RepeatedCompositeFieldContainer[MetricTimeSeries]
    collection_timestamp_ns: int
    def __init__(self, metrics: _Optional[_Iterable[_Union[MetricTimeSeries, _Mapping]]] = ..., collection_timestamp_ns: _Optional[int] = ...) -> None: ...

class MetricTimeSeries(_message.Message):
    __slots__ = ("metric_name", "data_points", "labels")
    class LabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    METRIC_NAME_FIELD_NUMBER: _ClassVar[int]
    DATA_POINTS_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    metric_name: str
    data_points: _containers.RepeatedCompositeFieldContainer[MetricDataPoint]
    labels: _containers.ScalarMap[str, str]
    def __init__(self, metric_name: _Optional[str] = ..., data_points: _Optional[_Iterable[_Union[MetricDataPoint, _Mapping]]] = ..., labels: _Optional[_Mapping[str, str]] = ...) -> None: ...

class MetricDataPoint(_message.Message):
    __slots__ = ("timestamp_ns", "value")
    TIMESTAMP_NS_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    timestamp_ns: int
    value: float
    def __init__(self, timestamp_ns: _Optional[int] = ..., value: _Optional[float] = ...) -> None: ...
