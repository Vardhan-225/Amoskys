"""WAL Processor — event routing mixin."""
from __future__ import annotations

import json
import logging
from typing import Any, List

logger = logging.getLogger("WALProcessor")


class RoutingMixin:
    """Routes events to the correct table processors based on type and agent."""

    # Agent-name tokens that map to each domain extractor.
    _PROCESS_AGENTS = frozenset(
        {
            "proc-agent",
            "proc_agent",
            "proc",
            "macos_process",
            "process",
            "realtime_sensor",
        }
    )
    _FLOW_TOKENS = frozenset({"flow", "network"})
    _FIM_TOKENS = frozenset({"fim", "filesystem"})

    def _route_events(
        self,
        events: List[Any],
        device_id: str,
        ts_ns: int,
        timestamp_dt: str,
        collection_agent: str,
        agent_version: str,
        device_type: str = "UNKNOWN",
    ) -> None:
        """Route individual TelemetryEvents to the correct table processors."""
        for event in events:
            quality_state, _, _ = self._evaluate_event_contract(
                event,
                device_type=device_type,
                collection_agent=collection_agent,
                annotate=True,
            )
            if quality_state == "invalid":
                logger.warning(
                    "Dropping invalid-quality event before routing: type=%s source=%s",
                    event.event_type,
                    event.source_component,
                )
                continue
            if quality_state == "degraded":
                event.attributes["training_exclude"] = "true"

            # OBSERVATION events -> domain tables directly (raw observability)
            # Bypass dedup and scoring -- these are raw collector data, not detections
            if event.event_type == "OBSERVATION":
                self._route_observation(
                    event,
                    device_id,
                    ts_ns,
                    timestamp_dt,
                    collection_agent,
                    agent_version,
                )
                continue

            # Peripheral STATUS events -> peripheral_events table
            if (
                event.event_type == "STATUS"
                and event.source_component == "peripheral_agent"
            ):
                self._process_peripheral_event(
                    event,
                    device_id,
                    ts_ns,
                    timestamp_dt,
                    collection_agent,
                    agent_version,
                )

            # SecurityEvent sub-message -> security_events table
            if event.HasField("security_event"):
                # Extract and enrich attrs ONCE before both consumers
                enriched_attrs = {k: event.attributes[k] for k in event.attributes}
                if self._pipeline is not None:
                    try:
                        self._pipeline.enrich(enriched_attrs)
                    except Exception:
                        logger.debug(
                            "Enrichment failed for event — continuing",
                            exc_info=True,
                        )

                self._process_security_event(
                    event,
                    device_id,
                    ts_ns,
                    timestamp_dt,
                    collection_agent,
                    enriched_attrs=enriched_attrs,
                )
                self._route_security_to_domain_tables(
                    event,
                    device_id,
                    ts_ns,
                    timestamp_dt,
                    collection_agent,
                    agent_version,
                    enriched_attrs=enriched_attrs,
                )

    def _agent_matches(self, collection_agent: str, tokens: frozenset) -> bool:
        """Check if collection_agent contains any of the given tokens."""
        return any(tok in collection_agent for tok in tokens)

    def _route_security_to_domain_tables(
        self,
        event,
        device_id,
        ts_ns,
        timestamp_dt,
        collection_agent,
        agent_version,
        enriched_attrs: dict | None = None,
    ) -> None:
        """Extract structured data from security events into domain-specific tables."""
        if enriched_attrs is not None:
            attrs = enriched_attrs
        else:
            attrs = {k: event.attributes[k] for k in event.attributes}

        se = event.security_event
        cat = se.event_category or ""
        mitre = list(se.mitre_techniques) if se.mitre_techniques else []

        self._dispatch_domain_extraction(
            attrs,
            se,
            cat,
            mitre,
            device_id,
            ts_ns,
            timestamp_dt,
            collection_agent,
            agent_version,
        )

    def _dispatch_domain_extraction(
        self,
        attrs,
        se,
        cat,
        mitre,
        device_id,
        ts_ns,
        timestamp_dt,
        collection_agent,
        agent_version,
    ) -> None:
        """Dispatch to domain-specific extractors based on agent and attributes."""
        common = (device_id, ts_ns, timestamp_dt, collection_agent, agent_version)

        if attrs.get("pid") and collection_agent in self._PROCESS_AGENTS:
            self._extract_process_from_security(attrs, *common, cat)

        if attrs.get("dst_ip") and self._agent_matches(
            collection_agent, self._FLOW_TOKENS
        ):
            self._extract_flow_from_security(attrs, device_id, ts_ns, timestamp_dt)

        if "usb" in cat or "peripheral" in collection_agent:
            self._extract_peripheral_from_security(attrs, *common)

        if "dns" in collection_agent or attrs.get("domain"):
            self._extract_dns_from_security(attrs, se, *common, cat, mitre)

        if "kernel" in collection_agent or cat.startswith("kernel_"):
            self._extract_audit_from_security(attrs, se, *common, cat, mitre)

        if self._is_persistence_event(collection_agent, cat, mitre):
            self._extract_persistence_from_security(attrs, se, *common, cat, mitre)

        if self._agent_matches(collection_agent, self._FIM_TOKENS) and attrs.get(
            "path"
        ):
            self._extract_fim_from_security(attrs, se, *common, cat, mitre)

    def _route_observation(
        self,
        event,
        device_id,
        ts_ns,
        timestamp_dt,
        agent,
        version,
    ) -> None:
        """Route OBSERVATION events to domain-specific tables.

        Observations are raw collector data — no dedup, no scoring, no security_event.
        They go directly to domain tables with event_source='observation'.
        Flow/DNS observations get enrichment (GeoIP/ASN) before storage.
        """
        attrs = {k: event.attributes[k] for k in event.attributes}
        domain = attrs.get("_domain", "")
        router = self._OBSERVATION_ROUTERS.get(domain)
        if router:
            try:
                decision = self._observation_shaper.decide(domain, attrs, ts_ns)
                if not decision.store_raw:
                    self.store.upsert_observation_rollup(
                        {
                            "window_start_ns": decision.window_start_ns,
                            "window_end_ns": decision.window_end_ns,
                            "domain": decision.domain,
                            "fingerprint": decision.fingerprint,
                            "sample_attributes": {
                                k: v for k, v in attrs.items() if not k.startswith("_")
                            },
                            "total_count": 1,
                            "first_seen_ns": ts_ns,
                            "last_seen_ns": ts_ns,
                            "device_id": device_id,
                            "collection_agent": agent,
                        }
                    )
                    return
                getattr(self, router)(
                    attrs, device_id, ts_ns, timestamp_dt, agent, version
                )
                # Receipt ledger checkpoint 4: persisted to domain table
                event_id = event.event_id
                if event_id:
                    dest = self._OBSERVATION_DEST_TABLE.get(
                        domain, "observation_events"
                    )
                    try:
                        self.store.receipt_persisted(
                            event_id,
                            agent,
                            dest,
                            attrs.get("quality_state", "valid"),
                        )
                    except Exception:
                        logger.debug(
                            "Receipt ledger checkpoint failed for %s",
                            event_id,
                            exc_info=True,
                        )
            except Exception as e:
                logger.error("Observation routing failed for domain=%s: %s", domain, e)
        else:
            logger.debug("No observation router for domain=%s", domain)

    @staticmethod
    def _quality_payload(attrs: dict[str, Any]) -> dict[str, Any]:
        quality_state = attrs.get("quality_state", "valid")
        training_exclude = (
            str(attrs.get("training_exclude", "")).lower()
            in {
                "true",
                "1",
                "yes",
            }
            or quality_state != "valid"
        )
        missing = attrs.get("missing_fields", "")
        return {
            "quality_state": quality_state,
            "training_exclude": training_exclude,
            "contract_violation_code": attrs.get("contract_violation_code", "NONE"),
            "missing_fields": missing,
            "raw_attributes_json": json.dumps(
                {k: v for k, v in attrs.items() if not k.startswith("_")},
                sort_keys=True,
            ),
        }
