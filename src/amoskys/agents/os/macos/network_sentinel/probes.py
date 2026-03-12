#!/usr/bin/env python3
"""NetworkSentinel Probes — 10 Eyes That Never Blink.

These probes exist because 17,273 malicious requests from Kali Linux
hit the AMOSKYS dashboard and ZERO were detected. Not one alert.
Not one block. Not one log entry in security_events.

That ends here.

Each probe is a specialist predator:

    1. HTTPScanStormProbe    — Catches mass path enumeration (nmap, nikto)
    2. DirectoryBruteForce   — Catches dir brute-forcing (gobuster, dirsearch)
    3. SQLiPayloadProbe      — Catches SQL injection in URLs/params
    4. XSSPayloadProbe       — Catches cross-site scripting payloads
    5. PathTraversalProbe    — Catches directory traversal (../../etc/passwd)
    6. AttackToolFingerprint — Catches scanner User-Agents by name
    7. RateAnomalyProbe      — Catches abnormal request rates per IP
    8. AdminProbeProbe       — Catches enumeration of admin/config paths
    9. CredentialSprayProbe  — Catches auth brute-force (mass 401/403)
   10. ConnectionFloodProbe  — Catches too many simultaneous connections

MITRE ATT&CK: T1595, T1190, T1059.007, T1083, T1078, T1110, T1498
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)
from amoskys.agents.os.macos.http_inspector.agent_types import HTTPTransaction

logger = logging.getLogger("NetworkSentinel.Probes")


# =============================================================================
# 1. HTTPScanStormProbe — The Kali Killer
# =============================================================================


class HTTPScanStormProbe(MicroProbe):
    """Detects mass path enumeration from a single source IP.

    This is the probe that would have caught every Kali attack.
    192.168.237.132 hit 10,021 unique paths in 7 minutes.
    Any legitimate user hits maybe 20-50 paths in a session.
    100+ unique paths from one IP = active reconnaissance.
    """

    name = "http_scan_storm"
    description = "Detects mass HTTP path enumeration from a single IP"
    mitre_techniques = ["T1595", "T1595.002"]
    mitre_tactics = ["Reconnaissance"]
    requires_fields = []

    # 100 unique paths = you're scanning, not browsing
    UNIQUE_PATH_THRESHOLD = 100
    # 500+ = aggressive scanner, CRITICAL
    CRITICAL_THRESHOLD = 500

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        transactions: List[HTTPTransaction] = context.shared_data.get(
            "http_transactions", []
        )
        if not transactions:
            return []

        events: List[TelemetryEvent] = []

        # Group unique paths by source IP
        ip_paths: Dict[str, Set[str]] = defaultdict(set)
        ip_requests: Dict[str, int] = defaultdict(int)
        ip_timestamps: Dict[str, List[float]] = defaultdict(list)
        ip_statuses: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))

        for txn in transactions:
            if not txn.src_ip or txn.src_ip in ("127.0.0.1", "::1"):
                continue
            ip_paths[txn.src_ip].add(txn.path)
            ip_requests[txn.src_ip] += 1
            ip_timestamps[txn.src_ip].append(txn.timestamp.timestamp())
            ip_statuses[txn.src_ip][txn.response_status] += 1

        for ip, paths in ip_paths.items():
            unique_count = len(paths)
            if unique_count < self.UNIQUE_PATH_THRESHOLD:
                continue

            total_reqs = ip_requests[ip]
            timestamps = sorted(ip_timestamps[ip])
            duration = max(timestamps[-1] - timestamps[0], 1.0)
            rps = total_reqs / duration

            severity = (
                Severity.CRITICAL
                if unique_count >= self.CRITICAL_THRESHOLD
                else Severity.HIGH
            )
            confidence = min(0.95, 0.7 + (unique_count / 5000))

            # Status code distribution
            status_dist = dict(ip_statuses[ip])

            # Sample paths for evidence
            sample_paths = sorted(paths)[:30]

            events.append(
                TelemetryEvent(
                    event_type="http_scan_storm",
                    severity=severity,
                    probe_name=self.name,
                    data={
                        "attacker_ip": ip,
                        "unique_paths": unique_count,
                        "total_requests": total_reqs,
                        "requests_per_second": round(rps, 2),
                        "duration_seconds": round(duration, 1),
                        "status_distribution": status_dist,
                        "sample_paths": sample_paths,
                        "verdict": f"ACTIVE RECONNAISSANCE: {ip} probed {unique_count} unique paths at {rps:.1f} req/s",
                    },
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                    confidence=confidence,
                    tags=["network_sentinel", "scan", "reconnaissance"],
                )
            )
            logger.warning(
                "SCAN STORM: %s hit %d unique paths (%d total requests, %.1f req/s)",
                ip,
                unique_count,
                total_reqs,
                rps,
            )

        return events


# =============================================================================
# 2. DirectoryBruteForceProbe
# =============================================================================


class DirectoryBruteForceProbe(MicroProbe):
    """Detects directory brute-forcing (gobuster, dirsearch, feroxbuster).

    The signal: high 404 rate from a single IP. Legitimate users
    rarely get 404s. A gobuster run is 80-99% 404s.
    """

    name = "directory_brute_force"
    description = "Detects directory brute-force attacks via 404 rate analysis"
    mitre_techniques = ["T1595", "T1595.003"]
    mitre_tactics = ["Reconnaissance"]
    requires_fields = []

    MIN_REQUESTS = 50
    FOUR_OH_FOUR_RATE_THRESHOLD = 0.70  # 70% 404 = brute force

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        transactions: List[HTTPTransaction] = context.shared_data.get(
            "http_transactions", []
        )
        if not transactions:
            return []

        events: List[TelemetryEvent] = []

        ip_total: Dict[str, int] = defaultdict(int)
        ip_404: Dict[str, int] = defaultdict(int)
        ip_paths: Dict[str, Set[str]] = defaultdict(set)

        for txn in transactions:
            if not txn.src_ip or txn.src_ip in ("127.0.0.1", "::1"):
                continue
            ip_total[txn.src_ip] += 1
            if txn.response_status == 404:
                ip_404[txn.src_ip] += 1
            ip_paths[txn.src_ip].add(txn.path)

        for ip, total in ip_total.items():
            if total < self.MIN_REQUESTS:
                continue

            not_found = ip_404.get(ip, 0)
            rate = not_found / total

            if rate < self.FOUR_OH_FOUR_RATE_THRESHOLD:
                continue

            severity = Severity.CRITICAL if rate > 0.90 else Severity.HIGH
            confidence = min(0.95, 0.6 + rate * 0.3)

            events.append(
                TelemetryEvent(
                    event_type="directory_brute_force",
                    severity=severity,
                    probe_name=self.name,
                    data={
                        "attacker_ip": ip,
                        "total_requests": total,
                        "not_found_count": not_found,
                        "not_found_rate": round(rate, 4),
                        "unique_paths_tried": len(ip_paths[ip]),
                        "verdict": f"DIRECTORY BRUTE FORCE: {ip} — {not_found}/{total} requests returned 404 ({rate:.0%})",
                    },
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                    confidence=confidence,
                    tags=["network_sentinel", "brute_force", "directory_enum"],
                )
            )

        return events


# =============================================================================
# 3. SQLiPayloadProbe
# =============================================================================

_SQLI_PATTERNS: List[re.Pattern] = [
    re.compile(r"\b(UNION\s+(ALL\s+)?SELECT)\b", re.I),
    re.compile(r"\b(SELECT\s+.*\s+FROM)\b", re.I),
    re.compile(r"\b(INSERT\s+INTO)\b", re.I),
    re.compile(r"\b(UPDATE\s+\w+\s+SET)\b", re.I),
    re.compile(r"\b(DELETE\s+FROM)\b", re.I),
    re.compile(r"\b(DROP\s+(TABLE|DATABASE))\b", re.I),
    re.compile(r"('\s*(OR|AND)\s*'?\s*\d+\s*=\s*\d+)", re.I),  # ' OR 1=1
    re.compile(r"(;\s*(DROP|DELETE|INSERT|UPDATE|ALTER))\b", re.I),
    re.compile(r"--\s*$"),  # SQL comment at end
    re.compile(r"/\*.*?\*/"),  # block comment
    re.compile(r"\b(SLEEP|BENCHMARK|WAITFOR|pg_sleep)\s*\(", re.I),
    re.compile(r"\b(LOAD_FILE|INTO\s+(OUT|DUMP)FILE)\b", re.I),
    re.compile(r"\b(INFORMATION_SCHEMA|mysql\.user|pg_catalog)\b", re.I),
    re.compile(r"(%27|%2527).*?(OR|AND|UNION)", re.I),  # URL-encoded '
    re.compile(r"(CHAR|CHR|CONCAT)\s*\(.*\d", re.I),  # function-based
]


class SQLiPayloadProbe(MicroProbe):
    """Detects SQL injection payloads in HTTP requests.

    Checks the full URL path + query string + any decoded variants.
    15 regex patterns covering UNION, stacked queries, time-based,
    file access, schema enumeration, and encoded bypasses.
    """

    name = "sqli_payload"
    description = "Detects SQL injection payloads in HTTP requests"
    mitre_techniques = ["T1190"]
    mitre_tactics = ["Initial Access"]
    requires_fields = []

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        transactions: List[HTTPTransaction] = context.shared_data.get(
            "http_transactions", []
        )
        if not transactions:
            return []

        events: List[TelemetryEvent] = []
        seen_ips: Set[str] = set()

        for txn in transactions:
            if not txn.src_ip or txn.src_ip in ("127.0.0.1", "::1"):
                continue

            # Build the full inspection string
            targets = [txn.url, txn.path]
            for v in txn.query_params.values():
                targets.append(v)

            inspection = " ".join(targets)

            # URL-decode for evasion bypass
            try:
                from urllib.parse import unquote

                decoded = unquote(unquote(inspection))  # double-decode
                inspection = f"{inspection} {decoded}"
            except Exception:
                pass

            matched_patterns = []
            for pattern in _SQLI_PATTERNS:
                if pattern.search(inspection):
                    matched_patterns.append(pattern.pattern)

            if not matched_patterns:
                continue

            # Deduplicate per IP per collection cycle
            dedup_key = txn.src_ip
            if dedup_key in seen_ips:
                continue
            seen_ips.add(dedup_key)

            severity = (
                Severity.CRITICAL if len(matched_patterns) >= 3 else Severity.HIGH
            )
            confidence = min(0.95, 0.7 + len(matched_patterns) * 0.05)

            events.append(
                TelemetryEvent(
                    event_type="sqli_payload_detected",
                    severity=severity,
                    probe_name=self.name,
                    data={
                        "attacker_ip": txn.src_ip,
                        "method": txn.method,
                        "path": txn.path,
                        "url": txn.url,
                        "query_params": txn.query_params,
                        "response_status": txn.response_status,
                        "patterns_matched": matched_patterns[:5],
                        "pattern_count": len(matched_patterns),
                        "verdict": f"SQL INJECTION: {txn.src_ip} sent SQLi payload to {txn.path}",
                    },
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                    confidence=confidence,
                    tags=["network_sentinel", "injection", "sqli"],
                )
            )

        return events


# =============================================================================
# 4. XSSPayloadProbe
# =============================================================================

_XSS_PATTERNS: List[re.Pattern] = [
    re.compile(r"<\s*script", re.I),
    re.compile(r"on(error|load|click|mouseover|focus|blur)\s*=", re.I),
    re.compile(r"javascript\s*:", re.I),
    re.compile(r"%3[Cc]\s*script", re.I),
    re.compile(r"&#x?3[Cc];?\s*script", re.I),
    re.compile(r"<\s*svg[^>]+on\w+\s*=", re.I),
    re.compile(r"<\s*img[^>]+onerror", re.I),
    re.compile(r"<\s*iframe", re.I),
    re.compile(r"\beval\s*\(", re.I),
    re.compile(r"\bdocument\.(cookie|location|write)", re.I),
    re.compile(r"\bwindow\.(location|open)", re.I),
    re.compile(r"<\s*body[^>]+on\w+\s*=", re.I),
    re.compile(r"alert\s*\(", re.I),
    re.compile(r"prompt\s*\(", re.I),
    re.compile(r"confirm\s*\(", re.I),
]


class XSSPayloadProbe(MicroProbe):
    """Detects cross-site scripting payloads in HTTP requests.

    15 patterns covering script tags, event handlers, JavaScript URIs,
    encoded variants, SVG/IMG/IFRAME vectors, and DOM manipulation.
    """

    name = "xss_payload"
    description = "Detects XSS payloads in HTTP request paths and parameters"
    mitre_techniques = ["T1059.007", "T1189"]
    mitre_tactics = ["Execution", "Initial Access"]
    requires_fields = []

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        transactions: List[HTTPTransaction] = context.shared_data.get(
            "http_transactions", []
        )
        if not transactions:
            return []

        events: List[TelemetryEvent] = []
        seen_ips: Set[str] = set()

        for txn in transactions:
            if not txn.src_ip or txn.src_ip in ("127.0.0.1", "::1"):
                continue

            targets = [txn.url, txn.path]
            for v in txn.query_params.values():
                targets.append(v)

            inspection = " ".join(targets)
            try:
                from urllib.parse import unquote

                inspection = f"{inspection} {unquote(unquote(inspection))}"
            except Exception:
                pass

            matched = []
            for pattern in _XSS_PATTERNS:
                if pattern.search(inspection):
                    matched.append(pattern.pattern)

            if not matched:
                continue

            dedup_key = txn.src_ip
            if dedup_key in seen_ips:
                continue
            seen_ips.add(dedup_key)

            severity = Severity.HIGH if len(matched) >= 2 else Severity.MEDIUM
            confidence = min(0.95, 0.7 + len(matched) * 0.05)

            events.append(
                TelemetryEvent(
                    event_type="xss_payload_detected",
                    severity=severity,
                    probe_name=self.name,
                    data={
                        "attacker_ip": txn.src_ip,
                        "method": txn.method,
                        "path": txn.path,
                        "url": txn.url,
                        "response_status": txn.response_status,
                        "patterns_matched": matched[:5],
                        "verdict": f"XSS ATTACK: {txn.src_ip} injected script payload into {txn.path}",
                    },
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                    confidence=confidence,
                    tags=["network_sentinel", "injection", "xss"],
                )
            )

        return events


# =============================================================================
# 5. PathTraversalProbe
# =============================================================================

_TRAVERSAL_PATTERNS: List[re.Pattern] = [
    re.compile(r"\.\./"),
    re.compile(r"\.\.\\"),
    re.compile(r"%2[Ee]%2[Ee][/\\]"),  # URL-encoded ../
    re.compile(r"%252[Ee]%252[Ee]"),  # double-encoded
    re.compile(r"\.\./\.\./\.\./"),  # deep traversal
    re.compile(r"/etc/(passwd|shadow|hosts|sudoers)", re.I),
    re.compile(r"/proc/(self|version|cmdline)", re.I),
    re.compile(r"/var/log/", re.I),
    re.compile(r"(boot\.ini|win\.ini|system32)", re.I),
    re.compile(r"%00"),  # null byte injection
]


class PathTraversalProbe(MicroProbe):
    """Detects directory traversal attacks in HTTP paths.

    Catches ../../, URL-encoded variants, null bytes, and
    direct references to sensitive system files.
    """

    name = "path_traversal"
    description = "Detects directory traversal attacks in HTTP requests"
    mitre_techniques = ["T1083", "T1005"]
    mitre_tactics = ["Discovery", "Collection"]
    requires_fields = []

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        transactions: List[HTTPTransaction] = context.shared_data.get(
            "http_transactions", []
        )
        if not transactions:
            return []

        events: List[TelemetryEvent] = []
        ip_traversals: Dict[str, List[str]] = defaultdict(list)

        for txn in transactions:
            if not txn.src_ip or txn.src_ip in ("127.0.0.1", "::1"):
                continue

            inspection = txn.url or txn.path
            try:
                from urllib.parse import unquote

                inspection = f"{inspection} {unquote(unquote(inspection))}"
            except Exception:
                pass

            for pattern in _TRAVERSAL_PATTERNS:
                if pattern.search(inspection):
                    ip_traversals[txn.src_ip].append(txn.path)
                    break

        for ip, paths in ip_traversals.items():
            unique_paths = list(set(paths))
            severity = Severity.CRITICAL if len(unique_paths) >= 5 else Severity.HIGH
            confidence = min(0.95, 0.75 + len(unique_paths) * 0.02)

            events.append(
                TelemetryEvent(
                    event_type="path_traversal_detected",
                    severity=severity,
                    probe_name=self.name,
                    data={
                        "attacker_ip": ip,
                        "traversal_attempts": len(paths),
                        "unique_paths": unique_paths[:20],
                        "verdict": f"PATH TRAVERSAL: {ip} attempted {len(paths)} directory traversal attacks",
                    },
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                    confidence=confidence,
                    tags=["network_sentinel", "traversal", "file_access"],
                )
            )

        return events


# =============================================================================
# 6. AttackToolFingerprintProbe
# =============================================================================

_SCANNER_SIGNATURES: Dict[str, re.Pattern] = {
    "nikto": re.compile(r"Nikto", re.I),
    "gobuster": re.compile(r"gobuster", re.I),
    "dirsearch": re.compile(r"dirsearch", re.I),
    "sqlmap": re.compile(r"sqlmap", re.I),
    "nmap": re.compile(r"Nmap|nmap", re.I),
    "masscan": re.compile(r"masscan", re.I),
    "nuclei": re.compile(r"Nuclei", re.I),
    "wfuzz": re.compile(r"Wfuzz", re.I),
    "hydra": re.compile(r"Hydra", re.I),
    "burpsuite": re.compile(r"Burp\s*Suite|PortSwigger", re.I),
    "zap": re.compile(r"OWASP\s*ZAP|ZAP", re.I),
    "feroxbuster": re.compile(r"feroxbuster", re.I),
    "ffuf": re.compile(r"Fuzz\s*Faster|ffuf", re.I),
    "whatweb": re.compile(r"WhatWeb", re.I),
    "curl_attack": re.compile(r"^curl/\d"),
    "python_requests": re.compile(r"^python-requests/"),
    "python_urllib": re.compile(r"^Python-urllib"),
    "wget": re.compile(r"^Wget/"),
    "scrapy": re.compile(r"Scrapy", re.I),
    "arachni": re.compile(r"Arachni", re.I),
}

# Nikto random-prefix pattern: 8-char random string used as anti-IDS
_NIKTO_RANDOM_PREFIX = re.compile(r"^/[A-Za-z0-9]{8}\.\w+$")


class AttackToolFingerprintProbe(MicroProbe):
    """Identifies requests from known attack tools by User-Agent and behavior.

    20 scanner signatures + Nikto anti-IDS random prefix detection.
    If you're running nikto, we know. If you're running gobuster, we know.
    """

    name = "attack_tool_fingerprint"
    description = "Identifies known attack tools by User-Agent and request patterns"
    mitre_techniques = ["T1595", "T1592"]
    mitre_tactics = ["Reconnaissance"]
    requires_fields = []

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        transactions: List[HTTPTransaction] = context.shared_data.get(
            "http_transactions", []
        )
        if not transactions:
            return []

        events: List[TelemetryEvent] = []

        # Track tools per IP
        ip_tools: Dict[str, Set[str]] = defaultdict(set)
        ip_request_count: Dict[str, int] = defaultdict(int)
        ip_nikto_random: Dict[str, int] = defaultdict(int)

        for txn in transactions:
            if not txn.src_ip or txn.src_ip in ("127.0.0.1", "::1"):
                continue

            ip_request_count[txn.src_ip] += 1

            # Check User-Agent
            ua = txn.request_headers.get("user-agent", "")
            if ua:
                for tool_name, pattern in _SCANNER_SIGNATURES.items():
                    if pattern.search(ua):
                        ip_tools[txn.src_ip].add(tool_name)

            # Check for Nikto random prefix pattern
            if _NIKTO_RANDOM_PREFIX.match(txn.path):
                ip_nikto_random[txn.src_ip] += 1

        # Nikto detection via random prefix (even without UA)
        for ip, count in ip_nikto_random.items():
            if count >= 10:
                ip_tools[ip].add("nikto_anti_ids")

        for ip, tools in ip_tools.items():
            tool_list = sorted(tools)
            severity = Severity.CRITICAL if len(tools) >= 2 else Severity.HIGH

            events.append(
                TelemetryEvent(
                    event_type="attack_tool_detected",
                    severity=severity,
                    probe_name=self.name,
                    data={
                        "attacker_ip": ip,
                        "tools_detected": tool_list,
                        "total_requests": ip_request_count[ip],
                        "nikto_random_probes": ip_nikto_random.get(ip, 0),
                        "verdict": f"ATTACK TOOLS: {ip} using {', '.join(tool_list)} ({ip_request_count[ip]} requests)",
                    },
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                    confidence=0.95,
                    tags=["network_sentinel", "attack_tool", "scanner"],
                )
            )

        return events


# =============================================================================
# 7. RateAnomalyProbe
# =============================================================================


class RateAnomalyProbe(MicroProbe):
    """Detects abnormal request rates from a single IP.

    A human browses at 1-5 req/s. A scanner runs at 50-200 req/s.
    If you're sending 100+ requests per minute from one IP, you're
    either a bot, a scanner, or a DDoS participant.
    """

    name = "rate_anomaly"
    description = "Detects abnormal HTTP request rates per source IP"
    mitre_techniques = ["T1498", "T1595"]
    mitre_tactics = ["Impact", "Reconnaissance"]
    requires_fields = []

    REQUESTS_PER_MINUTE_THRESHOLD = 100
    CRITICAL_RATE = 500  # req/min

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        transactions: List[HTTPTransaction] = context.shared_data.get(
            "http_transactions", []
        )
        if not transactions:
            return []

        events: List[TelemetryEvent] = []

        ip_counts: Dict[str, int] = defaultdict(int)
        ip_timestamps: Dict[str, List[float]] = defaultdict(list)

        for txn in transactions:
            if not txn.src_ip or txn.src_ip in ("127.0.0.1", "::1"):
                continue
            ip_counts[txn.src_ip] += 1
            ip_timestamps[txn.src_ip].append(txn.timestamp.timestamp())

        for ip, count in ip_counts.items():
            timestamps = sorted(ip_timestamps[ip])
            if len(timestamps) < 2:
                continue

            duration_seconds = max(timestamps[-1] - timestamps[0], 1.0)
            rpm = (count / duration_seconds) * 60

            if rpm < self.REQUESTS_PER_MINUTE_THRESHOLD:
                continue

            severity = Severity.CRITICAL if rpm >= self.CRITICAL_RATE else Severity.HIGH
            confidence = min(0.95, 0.6 + (rpm / 2000))

            events.append(
                TelemetryEvent(
                    event_type="rate_anomaly",
                    severity=severity,
                    probe_name=self.name,
                    data={
                        "attacker_ip": ip,
                        "total_requests": count,
                        "requests_per_minute": round(rpm, 1),
                        "requests_per_second": round(rpm / 60, 2),
                        "duration_seconds": round(duration_seconds, 1),
                        "verdict": f"RATE ANOMALY: {ip} sending {rpm:.0f} req/min ({count} total in {duration_seconds:.0f}s)",
                    },
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                    confidence=confidence,
                    tags=["network_sentinel", "rate_anomaly", "dos"],
                )
            )

        return events


# =============================================================================
# 8. AdminProbeProbe
# =============================================================================

_ADMIN_PATHS: Set[str] = {
    "/admin",
    "/admin/",
    "/administrator",
    "/administrator/",
    "/console",
    "/console/",
    "/debug",
    "/debug/",
    "/.env",
    "/.git",
    "/.git/config",
    "/.gitignore",
    "/.svn",
    "/.svn/entries",
    "/.hg",
    "/wp-admin",
    "/wp-login.php",
    "/wp-config.php",
    "/phpmyadmin",
    "/phpMyAdmin",
    "/pma",
    "/config",
    "/config.php",
    "/configuration.php",
    "/server-status",
    "/server-info",
    "/.htaccess",
    "/.htpasswd",
    "/backup",
    "/backup.sql",
    "/dump.sql",
    "/api/debug",
    "/api/config",
    "/api/admin",
    "/manage",
    "/management",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/swagger-ui.html",
    "/swagger.json",
    "/api-docs",
}

_ADMIN_PATH_PATTERNS: List[re.Pattern] = [
    re.compile(r"/admin\d*\.(?:php|asp|cgi|nsf)", re.I),
    re.compile(r"/\.(?:env|git|svn|hg|DS_Store)", re.I),
    re.compile(r"/(?:phpinfo|info)\.php", re.I),
    re.compile(r"/web\.config", re.I),
    re.compile(r"/(?:db|database|sql|dump)\.", re.I),
    re.compile(r"/(?:shell|cmd|exec|system|eval)\b", re.I),
    re.compile(r"/cgi-bin/", re.I),
    re.compile(r"/\.well-known/", re.I),
]


class AdminProbeProbe(MicroProbe):
    """Detects enumeration of admin panels, config files, and sensitive paths.

    Attackers probe for /admin, /.env, /.git, /phpMyAdmin, /console,
    /actuator, /swagger, /backup.sql — anything that reveals infrastructure
    or grants elevated access.
    """

    name = "admin_path_probe"
    description = "Detects enumeration of admin/config/sensitive paths"
    mitre_techniques = ["T1078", "T1083", "T1590"]
    mitre_tactics = ["Initial Access", "Discovery", "Reconnaissance"]
    requires_fields = []

    MIN_HITS = 3  # At least 3 admin paths = intentional probing

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        transactions: List[HTTPTransaction] = context.shared_data.get(
            "http_transactions", []
        )
        if not transactions:
            return []

        events: List[TelemetryEvent] = []

        ip_admin_hits: Dict[str, List[str]] = defaultdict(list)

        for txn in transactions:
            if not txn.src_ip or txn.src_ip in ("127.0.0.1", "::1"):
                continue

            path_lower = txn.path.lower().rstrip("/")

            # Check exact match
            if txn.path in _ADMIN_PATHS or f"{txn.path}/" in _ADMIN_PATHS:
                ip_admin_hits[txn.src_ip].append(txn.path)
                continue

            # Check pattern match
            for pattern in _ADMIN_PATH_PATTERNS:
                if pattern.search(txn.path):
                    ip_admin_hits[txn.src_ip].append(txn.path)
                    break

        for ip, paths in ip_admin_hits.items():
            unique = list(set(paths))
            if len(unique) < self.MIN_HITS:
                continue

            severity = Severity.HIGH if len(unique) >= 10 else Severity.MEDIUM
            confidence = min(0.95, 0.6 + len(unique) * 0.03)

            events.append(
                TelemetryEvent(
                    event_type="admin_path_enumeration",
                    severity=severity,
                    probe_name=self.name,
                    data={
                        "attacker_ip": ip,
                        "admin_paths_probed": unique[:30],
                        "total_hits": len(paths),
                        "unique_hits": len(unique),
                        "verdict": f"ADMIN ENUMERATION: {ip} probed {len(unique)} admin/config paths",
                    },
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                    confidence=confidence,
                    tags=["network_sentinel", "admin_enum", "config_exposure"],
                )
            )

        return events


# =============================================================================
# 9. CredentialSprayProbe
# =============================================================================


class CredentialSprayProbe(MicroProbe):
    """Detects credential spraying via mass 401/403 responses.

    If an IP gets 10+ authentication failures (401 Unauthorized or
    403 Forbidden) in one collection window, it's trying to brute-force
    credentials or enumerate valid endpoints behind auth.
    """

    name = "credential_spray"
    description = "Detects credential brute-force via 401/403 rate analysis"
    mitre_techniques = ["T1110", "T1110.003"]
    mitre_tactics = ["Credential Access"]
    requires_fields = []

    AUTH_FAIL_THRESHOLD = 10

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        transactions: List[HTTPTransaction] = context.shared_data.get(
            "http_transactions", []
        )
        if not transactions:
            return []

        events: List[TelemetryEvent] = []

        ip_auth_fails: Dict[str, int] = defaultdict(int)
        ip_total: Dict[str, int] = defaultdict(int)
        ip_fail_paths: Dict[str, Set[str]] = defaultdict(set)

        for txn in transactions:
            if not txn.src_ip or txn.src_ip in ("127.0.0.1", "::1"):
                continue
            ip_total[txn.src_ip] += 1
            if txn.response_status in (401, 403):
                ip_auth_fails[txn.src_ip] += 1
                ip_fail_paths[txn.src_ip].add(txn.path)

        for ip, fails in ip_auth_fails.items():
            if fails < self.AUTH_FAIL_THRESHOLD:
                continue

            total = ip_total[ip]
            fail_rate = fails / max(total, 1)
            severity = Severity.CRITICAL if fails >= 50 else Severity.HIGH
            confidence = min(0.95, 0.7 + fail_rate * 0.2)

            events.append(
                TelemetryEvent(
                    event_type="credential_spray_detected",
                    severity=severity,
                    probe_name=self.name,
                    data={
                        "attacker_ip": ip,
                        "auth_failures": fails,
                        "total_requests": total,
                        "failure_rate": round(fail_rate, 4),
                        "targeted_paths": sorted(ip_fail_paths[ip])[:20],
                        "verdict": f"CREDENTIAL SPRAY: {ip} — {fails} auth failures out of {total} requests ({fail_rate:.0%})",
                    },
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                    confidence=confidence,
                    tags=["network_sentinel", "brute_force", "credential_spray"],
                )
            )

        return events


# =============================================================================
# 10. ConnectionFloodProbe
# =============================================================================


class ConnectionFloodProbe(MicroProbe):
    """Detects connection floods from a single source IP.

    Uses the ConnectionStateCollector data (lsof snapshot) to find
    IPs with too many simultaneous connections. 50+ connections from
    one external IP = flood or scanner holding connections open.
    """

    name = "connection_flood"
    description = "Detects connection floods via lsof connection state analysis"
    mitre_techniques = ["T1498", "T1498.001"]
    mitre_tactics = ["Impact"]
    requires_fields = []

    CONNECTION_THRESHOLD = 50

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        connections: List[Dict] = context.shared_data.get("connections", [])
        if not connections:
            return []

        events: List[TelemetryEvent] = []

        ip_conns: Dict[str, int] = defaultdict(int)
        ip_ports: Dict[str, Set[int]] = defaultdict(set)
        ip_processes: Dict[str, Set[str]] = defaultdict(set)

        for conn in connections:
            src_ip = conn.get("src_ip", "")
            dst_ip = conn.get("dst_ip", "")
            # We care about inbound connections (dst_ip is us, src_ip is attacker)
            remote_ip = (
                src_ip if dst_ip in ("127.0.0.1", "0.0.0.0", "::1", "*") else src_ip
            )

            if not remote_ip or remote_ip in ("127.0.0.1", "0.0.0.0", "::1", "*", ""):
                continue

            ip_conns[remote_ip] += 1
            ip_ports[remote_ip].add(conn.get("dst_port", 0))
            ip_processes[remote_ip].add(conn.get("process_name", "unknown"))

        for ip, count in ip_conns.items():
            if count < self.CONNECTION_THRESHOLD:
                continue

            severity = Severity.CRITICAL if count >= 200 else Severity.HIGH

            events.append(
                TelemetryEvent(
                    event_type="connection_flood",
                    severity=severity,
                    probe_name=self.name,
                    data={
                        "attacker_ip": ip,
                        "active_connections": count,
                        "target_ports": sorted(ip_ports[ip]),
                        "target_processes": sorted(ip_processes[ip]),
                        "verdict": f"CONNECTION FLOOD: {ip} has {count} simultaneous connections",
                    },
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                    confidence=0.90,
                    tags=["network_sentinel", "flood", "dos"],
                )
            )

        return events


# =============================================================================
# Factory
# =============================================================================


def create_network_sentinel_probes() -> List[MicroProbe]:
    """Create all 10 NetworkSentinel probes.

    Returns:
        10 probes, each a specialist predator.
    """
    return [
        HTTPScanStormProbe(),
        DirectoryBruteForceProbe(),
        SQLiPayloadProbe(),
        XSSPayloadProbe(),
        PathTraversalProbe(),
        AttackToolFingerprintProbe(),
        RateAnomalyProbe(),
        AdminProbeProbe(),
        CredentialSprayProbe(),
        ConnectionFloodProbe(),
    ]
