"""AMOSKYS Argos — Autonomous Offensive Agent.

Argos is the offensive arm of AMOSKYS Web. Given a domain (authorized via
a signed scope), it performs external reconnaissance + vulnerability
assessment against the target and emits findings into the Proof Spine.

Every engagement writes a signed expectation to the spine BEFORE probing,
then writes actual results AFTER — the delta becomes ground-truth labels
that feed AMRDR reliability posteriors for every defensive sensor and
rule. This closes the calibration loop no pure-defensive WAF can.

v0 scope (this scaffold):
    - Single-domain engagement driver
    - Nuclei + WPScan as tool drivers (no reasoning loop yet)
    - JSON report generation
    - Consent gate: requires DNS TXT ownership proof

Future scopes:
    - v1: Full OWASP-structured report + signed audit trail
    - v2: LLM-reasoned manual PoC construction (PentAGI-style)
    - v3: Grey-box fuzzing + OOB Collaborator integration
    - v4: Source-level static analysis for plugins
"""

from amoskys.agents.Web.argos.engine import Engagement, EngagementResult

__version__ = "0.1.0-alpha"

__all__ = ["Engagement", "EngagementResult", "__version__"]
