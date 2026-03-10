"""Ingress telemetry contract normalization for AMOSKYS.

This module defines a canonical v1 contract view for telemetry envelopes.
It is used at ingress so downstream systems always operate on a normalized
UniversalEnvelope regardless of legacy/new producer format.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import List, Sequence

from amoskys.proto import messaging_schema_pb2 as legacy_pb2
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2

QUALITY_VALID = "valid"
QUALITY_DEGRADED = "degraded"
QUALITY_INVALID = "invalid"

_EVENT_TIME_BUCKET_NS = 10_000_000_000  # 10 seconds
_DEFAULT_TENANT = os.getenv("AMOSKYS_TENANT_ID", "default")
_ALLOWED_EVENT_TYPES = {
    "METRIC",
    "LOG",
    "ALARM",
    "STATUS",
    "SECURITY",
    "AUDIT",
    "OBSERVATION",
}
_ALLOWED_SEVERITY = {
    "DEBUG",
    "INFO",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
    "WARN",
    "ERROR",
}
_ALLOWED_DEVICE_TYPES = {"HOST", "IOT", "MEDICAL", "INDUSTRIAL", "ENDPOINT", "NETWORK", "UNKNOWN"}
_REQUIRED_FIELDS = (
    "event_id",
    "event_time_ns",
    "ingest_time_ns",
    "tenant_id",
    "host_id",
    "agent_id",
    "probe_name",
    "probe_version",
    "event_type",
    "device_type",
    "schema_version",
    "payload_kind",
)


@dataclass(slots=True)
class ContractResult:
    """Canonical v1 contract result produced at ingress."""

    envelope: telemetry_pb2.UniversalEnvelope
    event_id: str
    event_time_ns: int
    ingest_time_ns: int
    tenant_id: str
    host_id: str
    agent_id: str
    probe_name: str
    probe_version: str
    event_type: str
    device_type: str
    schema_version: int
    payload_kind: str
    quality_state: str
    contract_violation_code: str
    missing_fields: List[str] = field(default_factory=list)
    source: str = "unknown"

    @property
    def idempotency_key(self) -> str:
        """Normalized idempotency key: event_id + probe + event_time bucket."""
        bucket = int(self.event_time_ns // _EVENT_TIME_BUCKET_NS)
        event_id = _sanitize_token(self.event_id)
        probe_name = _sanitize_token(self.probe_name)
        return f"{event_id}:{probe_name}:{bucket}"


def normalize_legacy_envelope(
    envelope: legacy_pb2.Envelope,
    *,
    ingest_time_ns: int | None = None,
    source: str = "legacy_publish",
) -> ContractResult:
    """Translate legacy envelope to universal envelope and validate contract."""
    translated = translate_legacy_envelope(envelope)
    return normalize_universal_envelope(
        translated,
        ingest_time_ns=ingest_time_ns,
        source=source,
    )


def translate_legacy_envelope(
    envelope: legacy_pb2.Envelope,
) -> telemetry_pb2.UniversalEnvelope:
    """Translate legacy `messaging_schema.Envelope` into `UniversalEnvelope`."""
    translated = telemetry_pb2.UniversalEnvelope()
    translated.version = envelope.version or "1.0"
    translated.ts_ns = envelope.ts_ns or int(time.time() * 1e9)
    translated.idempotency_key = envelope.idempotency_key
    translated.schema_version = envelope.schema_version or 1
    if envelope.sig:
        translated.sig = envelope.sig
    if envelope.prev_sig:
        translated.prev_sig = envelope.prev_sig

    if envelope.HasField("flow"):
        translated.flow.CopyFrom(envelope.flow)
    elif envelope.payload:
        flow = legacy_pb2.FlowEvent()
        flow.ParseFromString(envelope.payload)
        translated.flow.CopyFrom(flow)

    return translated


def normalize_universal_envelope(
    envelope: telemetry_pb2.UniversalEnvelope,
    *,
    ingest_time_ns: int | None = None,
    source: str = "universal_publish",
) -> ContractResult:
    """Validate and normalize an envelope to the canonical ingress contract."""
    ingest_ns = ingest_time_ns or int(time.time() * 1e9)
    env = telemetry_pb2.UniversalEnvelope()
    env.CopyFrom(envelope)

    payload_kind = _payload_kind(env)
    event_time_ns = _event_time_ns(env, fallback=ingest_ns)
    event_id = env.idempotency_key or _derive_event_id(env)
    tenant_id = _tenant_id(env)
    host_id = _host_id(env)
    agent_id = _agent_id(env)
    probe_name = _probe_name(env, source=source)
    probe_version = _probe_version(env)
    event_type = _event_type(env)
    device_type = _device_type(env)
    schema_version = int(env.schema_version or 1)

    missing_critical: List[str] = []
    missing_optional: List[str] = []
    _append_missing(missing_critical, payload_kind, "payload_kind")
    _append_missing(missing_critical, event_type, "event_type")
    _append_missing(missing_critical, event_id, "event_id")
    _append_missing(missing_critical, event_time_ns, "event_time_ns")
    _append_missing(missing_optional, tenant_id, "tenant_id")
    _append_missing(missing_optional, host_id, "host_id")
    _append_missing(missing_optional, agent_id, "agent_id")
    _append_missing(missing_optional, probe_name, "probe_name")
    _append_missing(missing_optional, probe_version, "probe_version")
    _append_missing(missing_optional, device_type, "device_type")

    if event_type and event_type.upper() not in _ALLOWED_EVENT_TYPES:
        missing_critical.append(f"event_type:{event_type}")
    if device_type and device_type.upper() not in _ALLOWED_DEVICE_TYPES:
        missing_critical.append(f"device_type:{device_type}")
    if env.HasField("device_telemetry") and env.device_telemetry.events:
        for event in env.device_telemetry.events:
            event_severity = (event.severity or "").upper()
            if event_severity and event_severity not in _ALLOWED_SEVERITY:
                missing_critical.append(f"severity:{event_severity}")
            event_type_value = (event.event_type or "").upper()
            if event_type_value and event_type_value not in _ALLOWED_EVENT_TYPES:
                missing_critical.append(f"event_type:{event_type_value}")

    # Consult probe registry for probe-specific required fields
    _check_probe_contract(env, probe_name, missing_critical, missing_optional)

    if missing_critical:
        quality_state = QUALITY_INVALID
        violation = "CONTRACT_MISSING_REQUIRED_FIELDS"
    elif missing_optional:
        quality_state = QUALITY_DEGRADED
        violation = "CONTRACT_DEGRADED_FIELDS"
    else:
        quality_state = QUALITY_VALID
        violation = "NONE"

    missing_all = sorted(set(missing_critical + missing_optional))

    # Carry contract quality downstream for routing/training decisions.
    _attach_quality_annotations(env, quality_state, violation, missing_all)

    return ContractResult(
        envelope=env,
        event_id=event_id,
        event_time_ns=int(event_time_ns),
        ingest_time_ns=int(ingest_ns),
        tenant_id=tenant_id,
        host_id=host_id,
        agent_id=agent_id,
        probe_name=probe_name,
        probe_version=probe_version,
        event_type=event_type,
        device_type=device_type,
        schema_version=schema_version,
        payload_kind=payload_kind,
        quality_state=quality_state,
        contract_violation_code=violation,
        missing_fields=missing_all,
        source=source,
    )


def required_contract_fields() -> Sequence[str]:
    """Return the canonical required field names for ingress contract checks."""
    return _REQUIRED_FIELDS


def _payload_kind(envelope: telemetry_pb2.UniversalEnvelope) -> str:
    if envelope.HasField("device_telemetry"):
        return "device_telemetry"
    if envelope.HasField("process"):
        return "process"
    if envelope.HasField("flow"):
        return "flow"
    if envelope.HasField("telemetry_batch"):
        return "telemetry_batch"
    return "unknown"


def _event_time_ns(envelope: telemetry_pb2.UniversalEnvelope, *, fallback: int) -> int:
    if envelope.ts_ns:
        return int(envelope.ts_ns)
    if envelope.HasField("device_telemetry") and envelope.device_telemetry.timestamp_ns:
        return int(envelope.device_telemetry.timestamp_ns)
    if envelope.HasField("process") and envelope.process.start_ts_ns:
        return int(envelope.process.start_ts_ns)
    if envelope.HasField("flow") and envelope.flow.start_time:
        return int(envelope.flow.start_time)
    return int(fallback)


def _derive_event_id(envelope: telemetry_pb2.UniversalEnvelope) -> str:
    digest = hashlib.sha256(envelope.SerializeToString()).hexdigest()
    return digest[:32]


def _tenant_id(envelope: telemetry_pb2.UniversalEnvelope) -> str:
    if envelope.HasField("device_telemetry") and envelope.device_telemetry.HasField("metadata"):
        maybe = envelope.device_telemetry.metadata.custom_properties.get("tenant_id")
        if maybe:
            return maybe
    return _DEFAULT_TENANT


def _host_id(envelope: telemetry_pb2.UniversalEnvelope) -> str:
    if envelope.HasField("device_telemetry") and envelope.device_telemetry.device_id:
        return envelope.device_telemetry.device_id
    if envelope.idempotency_key:
        return envelope.idempotency_key.split(":")[0]
    return ""


def _agent_id(envelope: telemetry_pb2.UniversalEnvelope) -> str:
    if envelope.HasField("device_telemetry"):
        dt = envelope.device_telemetry
        if dt.collection_agent:
            return dt.collection_agent
        if dt.events and dt.events[0].agent_id:
            return dt.events[0].agent_id
        if dt.device_id:
            return dt.device_id
    return "legacy_agent"


def _probe_name(envelope: telemetry_pb2.UniversalEnvelope, *, source: str) -> str:
    if envelope.HasField("device_telemetry") and envelope.device_telemetry.events:
        first = envelope.device_telemetry.events[0]
        if first.probe_class:
            return first.probe_class
        if first.source_component:
            return first.source_component
    if envelope.HasField("flow"):
        return "legacy_flow_probe"
    if envelope.HasField("process"):
        return "legacy_process_probe"
    if envelope.HasField("telemetry_batch"):
        return "telemetry_batch"
    return source


def _probe_version(envelope: telemetry_pb2.UniversalEnvelope) -> str:
    if envelope.HasField("device_telemetry") and envelope.device_telemetry.agent_version:
        return envelope.device_telemetry.agent_version
    return envelope.version or "unknown"


def _event_type(envelope: telemetry_pb2.UniversalEnvelope) -> str:
    if envelope.HasField("device_telemetry"):
        if envelope.device_telemetry.events:
            return envelope.device_telemetry.events[0].event_type or "DEVICE_EVENT"
        return "DEVICE_TELEMETRY"
    if envelope.HasField("flow"):
        return "FLOW"
    if envelope.HasField("process"):
        return "PROCESS"
    if envelope.HasField("telemetry_batch"):
        return "TELEMETRY_BATCH"
    return "UNKNOWN"


def _device_type(envelope: telemetry_pb2.UniversalEnvelope) -> str:
    if envelope.HasField("device_telemetry"):
        return envelope.device_telemetry.device_type or "UNKNOWN"
    return "UNKNOWN"


def _check_probe_contract(
    envelope: telemetry_pb2.UniversalEnvelope,
    fallback_probe_name: str,
    missing_critical: List[str],
    missing_optional: List[str],
) -> None:
    """Check probe-specific required fields from the ProbeContractRegistry."""
    try:
        from amoskys.observability.probe_registry import get_probe_contract_registry

        registry = get_probe_contract_registry()
        if not envelope.HasField("device_telemetry") or not envelope.device_telemetry.events:
            return
        for event in envelope.device_telemetry.events:
            probe_name = event.probe_class or event.source_component or fallback_probe_name
            contract = registry.get_contract(probe_name)
            if contract is None:
                continue

            attrs = dict(event.attributes)
            degraded = set(contract.degraded_without)
            hard_required = set(contract.requires_fields) - degraded
            for field_name in sorted(hard_required):
                if field_name not in attrs:
                    missing_critical.append(f"probe:{probe_name}:{field_name}")
            for field_name in sorted(degraded):
                if field_name not in attrs:
                    missing_optional.append(f"probe:{probe_name}:{field_name}")

            allowed_event_types = {et.upper() for et in contract.requires_event_types}
            if allowed_event_types:
                event_type = (event.event_type or "").upper()
                if event_type and event_type not in allowed_event_types:
                    missing_critical.append(
                        f"probe:{probe_name}:event_type:{event_type}"
                    )
    except Exception:
        pass  # Registry unavailable — skip probe-specific checks


def _append_missing(missing: List[str], value: str | int, field: str) -> None:
    if value == "" or value == 0:
        missing.append(field)


def _sanitize_token(value: str) -> str:
    safe = value.replace(":", "_").replace("/", "_").replace(" ", "_").strip("_")
    return safe or "unknown"


def _attach_quality_annotations(
    envelope: telemetry_pb2.UniversalEnvelope,
    quality_state: str,
    violation_code: str,
    missing_fields: Sequence[str],
) -> None:
    """Attach quality metadata to telemetry events for downstream policy decisions."""
    missing = ",".join(missing_fields)
    if envelope.HasField("device_telemetry"):
        for event in envelope.device_telemetry.events:
            event.attributes["quality_state"] = quality_state
            event.attributes["contract_violation_code"] = violation_code
            if missing:
                event.attributes["missing_fields"] = missing
