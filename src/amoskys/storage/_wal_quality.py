"""WAL Processor — event contract validation mixin."""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("WALProcessor")


class QualityMixin:
    """Event contract validation: quality checks, payload introspection, envelope truth."""

    @staticmethod
    def _payload_kind(envelope) -> str:
        if envelope.HasField("device_telemetry"):
            return "device_telemetry"
        if envelope.HasField("process"):
            return "process"
        if envelope.HasField("flow"):
            return "flow"
        if envelope.HasField("telemetry_batch"):
            return "telemetry_batch"
        return "unknown"

    @staticmethod
    def _quality_rank(quality_state: str) -> int:
        order = {"valid": 0, "degraded": 1, "invalid": 2}
        return order.get((quality_state or "valid").lower(), 0)

    def _evaluate_event_contract(
        self,
        event: Any,
        *,
        device_type: str,
        collection_agent: str,
        annotate: bool = True,
    ) -> tuple[str, str, list[str]]:
        """Evaluate one TelemetryEvent against runtime contract rules."""
        attrs = event.attributes
        missing_required: list[str] = []
        missing_degraded: list[str] = []
        violation_code = "NONE"

        event_type = (event.event_type or "").upper()
        severity = (event.severity or "").upper()
        dev_type = (device_type or "UNKNOWN").upper()

        if not event.event_id:
            missing_degraded.append("event_id")
        if not event.event_type:
            missing_required.append("event_type")
        if not event.severity:
            missing_degraded.append("severity")
        if not event.event_timestamp_ns:
            missing_degraded.append("event_timestamp_ns")
        if not event.source_component and not event.probe_class:
            missing_degraded.append("probe_name")

        if event_type and event_type not in self._ALLOWED_EVENT_TYPES:
            missing_required.append(f"event_type:{event_type}")
            violation_code = "CONTRACT_UNKNOWN_EVENT_TYPE"
        if severity and severity not in self._ALLOWED_SEVERITY:
            missing_required.append(f"severity:{severity}")
            violation_code = "CONTRACT_UNKNOWN_SEVERITY"
        if dev_type and dev_type not in self._ALLOWED_DEVICE_TYPES:
            missing_required.append(f"device_type:{dev_type}")
            violation_code = "CONTRACT_UNKNOWN_DEVICE_TYPE"

        if event_type == "OBSERVATION":
            domain = (attrs.get("_domain", "") or "").strip().lower()
            if domain not in self._OBSERVATION_ROUTERS:
                missing_required.append(f"_domain:{domain or 'missing'}")
                violation_code = "CONTRACT_UNKNOWN_OBSERVATION_DOMAIN"

        probe_name = event.probe_class or event.source_component
        if probe_name:
            try:
                from amoskys.observability.probe_registry import (
                    get_probe_contract_registry,
                )

                registry = get_probe_contract_registry()
                contract = registry.get_contract(probe_name)
                if contract is not None:
                    # NOTE: requires_fields describes probe *input* context
                    # (shared_data keys), not required *output* event attributes.
                    # Treat all probe contract fields as degraded, not invalid.
                    all_contract_fields = set(contract.requires_fields) | set(
                        contract.degraded_without
                    )
                    for field_name in sorted(all_contract_fields):
                        if field_name not in attrs:
                            missing_degraded.append(f"probe:{field_name}")
            except Exception:
                logger.debug("Probe contract check failed", exc_info=True)

        existing_quality = (attrs.get("quality_state", "valid") or "valid").lower()
        existing_violation = attrs.get("contract_violation_code", "NONE")
        existing_missing_raw = attrs.get("missing_fields", "")
        existing_missing = [m for m in existing_missing_raw.split(",") if m]

        quality_state = "valid"
        if missing_required:
            quality_state = "invalid"
            if violation_code == "NONE":
                violation_code = "CONTRACT_MISSING_REQUIRED_FIELDS"
        elif missing_degraded:
            quality_state = "degraded"
            if violation_code == "NONE":
                violation_code = "CONTRACT_DEGRADED_FIELDS"

        if self._quality_rank(existing_quality) > self._quality_rank(quality_state):
            quality_state = existing_quality
            if existing_violation and existing_violation != "NONE":
                violation_code = existing_violation

        missing_fields = sorted(
            set(existing_missing + missing_required + missing_degraded)
        )
        if quality_state == "valid":
            violation_code = "NONE"

        if annotate:
            attrs["quality_state"] = quality_state
            attrs["contract_violation_code"] = violation_code
            if missing_fields:
                attrs["missing_fields"] = ",".join(missing_fields)
            elif "missing_fields" in attrs:
                del attrs["missing_fields"]
            if quality_state != "valid":
                attrs["training_exclude"] = "true"

        return quality_state, violation_code, missing_fields

    def _extract_quality(
        self,
        envelope,
    ) -> tuple[str, str, str]:
        """Read envelope contract quality by aggregating all contained events."""
        if not envelope.HasField("device_telemetry"):
            return "valid", "NONE", ""
        dt = envelope.device_telemetry
        if not dt.events:
            return "degraded", "CONTRACT_EMPTY_EVENTS", "events"

        overall_quality = "valid"
        overall_violation = "NONE"
        missing: list[str] = []
        for event in dt.events:
            quality, violation, missing_fields = self._evaluate_event_contract(
                event,
                device_type=dt.device_type,
                collection_agent=dt.collection_agent,
                annotate=True,
            )
            if self._quality_rank(quality) > self._quality_rank(overall_quality):
                overall_quality = quality
                overall_violation = violation
            missing.extend(missing_fields)

        return overall_quality, overall_violation, ",".join(sorted(set(missing)))

    def _store_envelope_truth(
        self,
        *,
        envelope,
        raw_bytes: bytes,
        ts_ns: int,
        idem: str,
        wal_row_id: int,
        wal_checksum: bytes | None,
        wal_sig: bytes | None,
        wal_prev_sig: bytes | None,
    ) -> None:
        """Persist canonical envelope metadata into telemetry_events."""
        import time
        from datetime import datetime, timezone

        try:
            payload_kind = self._payload_kind(envelope)
            quality_state, violation, missing = self._extract_quality(envelope)
            device_id = (
                envelope.device_telemetry.device_id
                if envelope.HasField("device_telemetry")
                else ""
            )
            agent_id = (
                envelope.device_telemetry.collection_agent
                if envelope.HasField("device_telemetry")
                else ""
            )
            probe_name = ""
            event_type = payload_kind.upper()
            probe_version = envelope.version or "unknown"
            device_type = "UNKNOWN"
            if envelope.HasField("device_telemetry"):
                dt = envelope.device_telemetry
                device_type = dt.device_type or "UNKNOWN"
                probe_version = dt.agent_version or probe_version
                if dt.events:
                    first_event = dt.events[0]
                    probe_name = (
                        first_event.probe_class
                        or first_event.source_component
                        or dt.collection_agent
                    )
                    event_type = first_event.event_type or event_type
            elif envelope.HasField("flow"):
                probe_name = "legacy_flow_probe"
                event_type = "FLOW"
            elif envelope.HasField("process"):
                probe_name = "legacy_process_probe"
                event_type = "PROCESS"

            event_id = envelope.idempotency_key or idem
            self.store.insert_telemetry_event(
                {
                    "event_id": event_id,
                    "idempotency_key": idem,
                    "timestamp_ns": ts_ns,
                    "ingest_timestamp_ns": int(time.time() * 1e9),
                    "timestamp_dt": datetime.fromtimestamp(
                        ts_ns / 1e9, tz=timezone.utc
                    ).isoformat(),
                    "device_id": device_id,
                    "agent_id": agent_id,
                    "probe_name": probe_name,
                    "probe_version": probe_version,
                    "event_type": event_type,
                    "device_type": device_type,
                    "payload_kind": payload_kind,
                    "schema_version": int(envelope.schema_version or 1),
                    "quality_state": quality_state,
                    "contract_violation_code": violation,
                    "missing_fields": missing,
                    "envelope_bytes": raw_bytes,
                    "wal_row_id": wal_row_id,
                    "wal_checksum": (
                        bytes(wal_checksum) if wal_checksum is not None else None
                    ),
                    "wal_sig": bytes(wal_sig) if wal_sig is not None else None,
                    "wal_prev_sig": (
                        bytes(wal_prev_sig) if wal_prev_sig is not None else None
                    ),
                }
            )

            # Receipt ledger checkpoint 3: WAL accepted the envelope
            self.store.receipt_wal(event_id, agent_id or "unknown")

        except Exception:
            logger.debug("Failed to persist canonical telemetry event", exc_info=True)
