"""Session persistence + consistent-fingerprint HTTP layer.

A real browser session doesn't look like N independent HTTP requests.
It reuses a single TCP+TLS connection (keep-alive), carries cookies
from prior responses, keeps a stable UA + header order, and warms up
with natural traffic (favicon, CSS) before touching anything
sensitive.

This module wraps urllib.request in a session object that:
    - reuses a single HTTPS connection via an HTTP/1.1 keep-alive
    - persists cookies across requests within the session
    - maintains a stable set of browser headers (UA pool picks one
      per session; doesn't rotate mid-session)
    - optionally warms up with GET / + GET /favicon.ico before
      going anywhere sensitive

Why keep-alive
--------------
Commercial WAFs score per-TCP-connection in many configurations.
A scanner opening 500 new connections signals scanner; a browser
reusing one connection for 500 requests looks like one session.

We use http.client directly for precise control over connection
reuse; urllib.request would open a new connection per call.

Session warm-up
---------------
Before any attack-shaped probe, we optionally GET / + GET
/favicon.ico + GET /wp-content/themes/<theme>/style.css. This
establishes:
    - a legitimate Referer chain
    - a valid cookie set from the target
    - per-session UA consistency visible across multiple requests

Then the actual probe looks like "the 4th request in a normal
browsing session" rather than "cold attack from a new IP."
"""

from __future__ import annotations

import http.client
import random
import ssl
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from amoskys.agents.Web.argos.legitimacy import UserAgentPool


@dataclass
class SessionResponse:
    status: int
    headers: Dict[str, str]
    body: bytes
    latency_ms: int


class StealthSession:
    """Keep-alive HTTP/1.1 session with persistent cookies.

    Usage:
        s = StealthSession("example.com")
        s.warmup()              # visits /, /favicon.ico, main theme CSS
        r = s.get("/wp-json/")
        r = s.post("/wp-admin/admin-ajax.php", body="action=x", headers={})
        s.close()

    Not thread-safe. One session = one origin = one attacker identity.
    """

    def __init__(
        self,
        host: str,
        scheme: str = "https",
        port: Optional[int] = None,
        timeout: float = 20.0,
        ua_pool: Optional[UserAgentPool] = None,
        referer_base: Optional[str] = None,
    ):
        self.host = host
        self.scheme = scheme
        self.port = port or (443 if scheme == "https" else 80)
        self.timeout = timeout
        self.ua_pool = ua_pool or UserAgentPool()
        self.referer_base = referer_base or "https://www.google.com/"
        self._conn: Optional[http.client.HTTPSConnection] = None
        self._cookies: Dict[str, str] = {}
        self._last_url: Optional[str] = None
        self._first_nav: bool = True

    # ── Connection ────────────────────────────────────────────────

    def _ensure_conn(self) -> http.client.HTTPSConnection:
        if self._conn is not None:
            return self._conn
        if self.scheme == "https":
            ctx = ssl.create_default_context()
            self._conn = http.client.HTTPSConnection(
                self.host,
                self.port,
                timeout=self.timeout,
                context=ctx,
            )
        else:
            self._conn = http.client.HTTPConnection(
                self.host,
                self.port,
                timeout=self.timeout,
            )
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    # ── Request ───────────────────────────────────────────────────

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[str] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        retries: int = 1,
    ) -> SessionResponse:
        """Internal request primitive. Rebuilds connection on errors."""
        full_url = f"{self.scheme}://{self.host}{path}"
        headers = self._base_headers(full_url)
        if extra_headers:
            headers.update(extra_headers)
        if body is not None and "Content-Length" not in headers:
            headers["Content-Length"] = str(len(body))
        if self._cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self._cookies.items())

        t0 = time.time()
        for attempt in range(retries + 1):
            conn = self._ensure_conn()
            try:
                conn.request(method, path, body=body, headers=headers)
                resp = conn.getresponse()
                body_bytes = resp.read()
                out_headers = {k.lower(): v for k, v in resp.getheaders()}
                self._absorb_cookies(out_headers)
                self._last_url = full_url
                self._first_nav = False
                return SessionResponse(
                    status=resp.status,
                    headers=out_headers,
                    body=body_bytes,
                    latency_ms=int((time.time() - t0) * 1000),
                )
            except (
                http.client.RemoteDisconnected,
                http.client.BadStatusLine,
                ConnectionError,
            ) as e:
                # Server closed the keep-alive; reconnect and retry once.
                self.close()
                if attempt >= retries:
                    raise
        # Unreachable under normal control flow.
        raise RuntimeError("session request failed after retries")

    def get(
        self, path: str, extra_headers: Optional[Dict[str, str]] = None
    ) -> SessionResponse:
        return self._request("GET", path, body=None, extra_headers=extra_headers)

    def post(
        self, path: str, body: str, extra_headers: Optional[Dict[str, str]] = None
    ) -> SessionResponse:
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if extra_headers:
            headers.update(extra_headers)
        return self._request("POST", path, body=body, extra_headers=headers)

    # ── Headers + cookies ────────────────────────────────────────

    def _base_headers(self, for_url: str) -> Dict[str, str]:
        hdr = self.ua_pool.headers()
        # Remove Connection: close if present — we want keep-alive.
        hdr.pop("Connection", None)
        hdr["Connection"] = "keep-alive"
        # Referer chain.
        if self._last_url:
            hdr["Referer"] = self._last_url
            # Same-origin or cross-site Fetch-Site.
            parsed_ref = urllib.parse.urlparse(self._last_url)
            parsed_cur = urllib.parse.urlparse(for_url)
            if parsed_ref.netloc == parsed_cur.netloc:
                hdr["Sec-Fetch-Site"] = "same-origin"
            else:
                hdr["Sec-Fetch-Site"] = "cross-site"
        elif self._first_nav:
            hdr["Referer"] = self.referer_base
            hdr["Sec-Fetch-Site"] = "cross-site"
        return hdr

    def _absorb_cookies(self, headers: Dict[str, str]) -> None:
        """Parse Set-Cookie header(s) and add to our jar.

        http.client gives a single 'set-cookie' value joined by ', '
        which is ambiguous because date values also contain commas.
        A proper parser would use http.cookiejar but for our needs
        a simple heuristic on 'name=value' pairs suffices.
        """
        sc = headers.get("set-cookie") or headers.get("Set-Cookie")
        if not sc:
            return
        # Split on ', ' but not inside Expires=<date> values.
        parts = self._split_set_cookie(sc)
        for p in parts:
            nv = p.split(";", 1)[0].strip()
            if "=" in nv:
                k, v = nv.split("=", 1)
                if k.strip():
                    self._cookies[k.strip()] = v.strip()

    @staticmethod
    def _split_set_cookie(raw: str) -> List[str]:
        """Split a joined Set-Cookie header. Heuristic: we split on ', '
        only when the next token looks like a cookie `name=`, otherwise
        we consider the comma as part of an Expires-date value."""
        parts: List[str] = []
        cur: List[str] = []
        segments = raw.split(",")
        i = 0
        while i < len(segments):
            seg = segments[i]
            cur.append(seg)
            # Look ahead: does the next segment look like a new cookie?
            if i + 1 < len(segments):
                nxt = segments[i + 1].lstrip()
                if "=" in nxt.split(";")[0]:
                    parts.append(",".join(cur).strip())
                    cur = []
            i += 1
        if cur:
            parts.append(",".join(cur).strip())
        return parts

    # ── Warm-up ──────────────────────────────────────────────────

    def warmup(self, extra_paths: Optional[List[str]] = None) -> None:
        """GET / then a handful of natural-browser-follow-up paths.

        This builds a Referer chain, populates cookies, and fingerprints
        the target server — all of which a real first-visit browser
        would do before touching anything sensitive.
        """
        paths = ["/", "/favicon.ico"]
        if extra_paths:
            paths += list(extra_paths)
        for p in paths:
            try:
                self.get(p)
            except Exception:
                # warm-up errors are survivable.
                continue
            # Humanlike small gap between warm-up visits.
            time.sleep(random.uniform(0.6, 1.8))

    def cookies(self) -> Dict[str, str]:
        return dict(self._cookies)


# ── Thin context manager wrapper ─────────────────────────────────


class session_for:
    """Context-manager idiom:

    with session_for("example.com") as s:
        s.warmup()
        r = s.get("/wp-json/")
    """

    def __init__(self, host: str, **kw):
        self._kw = kw
        self._s: Optional[StealthSession] = None
        self._host = host

    def __enter__(self) -> StealthSession:
        self._s = StealthSession(self._host, **self._kw)
        return self._s

    def __exit__(self, *a) -> None:
        if self._s:
            self._s.close()
