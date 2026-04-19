"""Argos recon — attack-surface discovery, passive-first.

Given a seed (domain or IP), the recon package discovers every
externally-visible asset belonging to the customer:

  - Subdomains            (Certificate Transparency logs)
  - IPs behind subdomains  (public DNS, rotating resolvers)
  - ASN / netblock          (Team Cymru whois)
  - HTTP services           (low-touch fingerprint, rate-limited)

Every source inherits from ReconSource and emits ReconEvent records
through the orchestrator, which dedupes and persists to AssetsDB.

The sources are ordered by stealth class:

  passive     No target-traffic at all. Reads public databases.
              (ct_logs, asn)
  resolver    Queries public resolvers (not target NS).
              (dns_resolve)
  active      Touches the target. Rate-limited, session-consistent.
              (http_fingerprint — built later, not in v1)

Every active request goes through stealth.RateLimiter. Every request
is audited to AssetsDB.audit().
"""

from amoskys.agents.Web.argos.recon.base import (
    ReconContext,
    ReconEvent,
    ReconSource,
    ReconSourceResult,
    StealthClass,
)
from amoskys.agents.Web.argos.recon.asn import ASNEnrichmentSource
from amoskys.agents.Web.argos.recon.cloud_detector import (
    CDNBehavior,
    Classification,
    CloudDetector,
    Provider,
    is_generic_cloud_hostname,
)
from amoskys.agents.Web.argos.recon.ct_logs import CertTransparencyLogs
from amoskys.agents.Web.argos.recon.dns_resolve import DNSResolveSource
from amoskys.agents.Web.argos.recon.ip_whois import IPWHOISSource
from amoskys.agents.Web.argos.recon.orchestrator import (
    AttackSurfaceMap,
    AttackSurfaceResult,
    CompletenessNote,
    CompletenessReport,
)
from amoskys.agents.Web.argos.recon.reverse_dns import ReverseDNSSource
from amoskys.agents.Web.argos.recon.tls_cert import CertInfo, TLSCertSource

__all__ = [
    "ASNEnrichmentSource",
    "AttackSurfaceMap",
    "AttackSurfaceResult",
    "CDNBehavior",
    "CertInfo",
    "CertTransparencyLogs",
    "Classification",
    "CloudDetector",
    "CompletenessNote",
    "CompletenessReport",
    "DNSResolveSource",
    "IPWHOISSource",
    "Provider",
    "ReconContext",
    "ReconEvent",
    "ReconSource",
    "ReconSourceResult",
    "ReverseDNSSource",
    "StealthClass",
    "TLSCertSource",
    "is_generic_cloud_hostname",
]
