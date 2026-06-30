"""Argos HTTP request smuggling — parser-disagreement exploitation.

When an edge (CDN/WAF) and an origin disagree about where a request
ends — e.g. one trusts Content-Length and the other trusts
Transfer-Encoding — we can splice a second request that only the
origin sees. That smuggled request bypasses every edge-layer rule:
WAF cannot block what WAF cannot parse.

Techniques implemented
----------------------
  CL.TE   edge uses Content-Length, origin uses Transfer-Encoding
  TE.CL   edge uses Transfer-Encoding, origin uses Content-Length
  TE.TE   both use Transfer-Encoding but one is tricked into
          falling back to CL via obfuscated TE header
  H2.CL   HTTP/2 downgrade — h2 front-end with Content-Length in
          pseudo-headers forwarded to an h1 origin that re-reads
          the body

Scope
-----
This module builds detection probes only — it does NOT perform
targeted exploitation against arbitrary sites. A probe either
triggers a timing anomaly (slow first-response latency) or returns
a smuggled-response fingerprint. Exploitation (e.g. queue-poisoning
the admin session) requires operator consent and lives in
argos.precision.
"""

from amoskys.agents.Web.argos.smuggle.http_smuggle import (
    SmuggleProbe,
    SmuggleReport,
    SmuggleTechnique,
    build_cl_te_probe,
    build_h2_downgrade_probe,
    build_te_cl_probe,
    build_te_te_probe,
    detect_smuggling,
)

__all__ = [
    "SmuggleProbe",
    "SmuggleReport",
    "SmuggleTechnique",
    "build_cl_te_probe",
    "build_te_cl_probe",
    "build_te_te_probe",
    "build_h2_downgrade_probe",
    "detect_smuggling",
]
