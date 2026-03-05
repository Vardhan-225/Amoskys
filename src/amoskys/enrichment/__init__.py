"""
AMOSKYS Enrichment Pipeline (A4.4)

Orchestrates enrichment stages: GeoIP → ASN → ThreatIntel.
Each enricher runs independently; failures in one stage do not block others.

Usage:
    from amoskys.enrichment import EnrichmentPipeline

    pipeline = EnrichmentPipeline()
    enriched_event = pipeline.enrich(event_dict)
    print(enriched_event["enrichment_status"])  # "enriched", "partial", "raw"
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

from amoskys.enrichment.asn import ASNEnricher
from amoskys.enrichment.geoip import GeoIPEnricher
from amoskys.enrichment.mitre import MITREEnricher
from amoskys.enrichment.threat_intel import ThreatIntelEnricher

logger = logging.getLogger(__name__)

__all__ = [
    "EnrichmentPipeline",
    "GeoIPEnricher",
    "ASNEnricher",
    "ThreatIntelEnricher",
    "MITREEnricher",
]


class EnrichmentPipeline:
    """Chains enrichment stages with graceful degradation.

    Each stage is optional. If an enricher is unavailable or raises,
    the pipeline continues with remaining stages and marks the event
    with ``enrichment_status``:
      - ``enriched``: all available stages succeeded
      - ``partial``: some stages failed
      - ``raw``: no enrichment applied (all stages failed or unavailable)
    """

    def __init__(
        self,
        geoip_db_path: Optional[str] = None,
        asn_db_path: Optional[str] = None,
        threat_intel_db_path: Optional[str] = None,
    ) -> None:
        self._geoip = GeoIPEnricher(db_path=geoip_db_path)
        self._asn = ASNEnricher(db_path=asn_db_path)
        self._threat_intel = ThreatIntelEnricher(
            db_path=threat_intel_db_path or "data/threat_intel.db"
        )
        self._mitre = MITREEnricher()
        self._stages: List[tuple] = [
            ("geoip", self._geoip),
            ("asn", self._asn),
            ("threat_intel", self._threat_intel),
            ("mitre", self._mitre),
        ]

    @property
    def geoip(self) -> GeoIPEnricher:
        return self._geoip

    @property
    def asn(self) -> ASNEnricher:
        return self._asn

    @property
    def threat_intel(self) -> ThreatIntelEnricher:
        return self._threat_intel

    def enrich(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Run all enrichment stages on an event.

        Args:
            event: Mutable event dictionary.

        Returns:
            The same event dict with enrichment fields added.
        """
        succeeded = 0
        attempted = 0

        for name, enricher in self._stages:
            if not enricher.available:
                continue
            attempted += 1
            try:
                enricher.enrich_event(event)
                succeeded += 1
            except Exception:
                logger.warning(
                    "Enrichment stage '%s' failed — continuing", name, exc_info=True
                )

        # Set enrichment status
        if attempted == 0:
            event["enrichment_status"] = "raw"
        elif succeeded == attempted:
            event["enrichment_status"] = "enriched"
        else:
            event["enrichment_status"] = "partial"

        return event

    def status(self) -> Dict[str, Any]:
        """Return status of all enrichment stages."""
        return {
            "geoip": {
                "available": self._geoip.available,
                "cache": self._geoip.cache_info(),
            },
            "asn": {
                "available": self._asn.available,
                "cache": self._asn.cache_info(),
            },
            "threat_intel": {
                "available": self._threat_intel.available,
                "indicators": self._threat_intel.indicator_count(),
                "cache": self._threat_intel.cache_info(),
            },
            "mitre": {
                "available": self._mitre.available,
                "cache": self._mitre.cache_info(),
            },
        }

    def close(self) -> None:
        """Close all enricher resources."""
        self._geoip.close()
        self._asn.close()
        self._threat_intel.close()
        self._mitre.close()
