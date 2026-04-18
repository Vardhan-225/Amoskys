=== AMOSKYS Aegis ===
Contributors: amoskys
Tags: security, waf, monitoring, firewall, siem
Requires at least: 6.0
Tested up to: 6.6
Requires PHP: 8.0
Stable tag: 0.1.0-alpha
License: GPLv2 or later

Defensive sensor + event emitter for AMOSKYS Web. Ships signed security
events to the AMOSKYS brain (IGRIS) for correlation and autonomous response.

== Description ==

Aegis is the defensive arm of AMOSKYS Web — the first platform that pairs
an autonomous offensive agent (Argos) with a defensive agent (Aegis) under
a unified brain (IGRIS) with cryptographic evidence tracking (Proof Spine).

This plugin alone does not protect you. It is a sensor — it observes and
reports. Protection comes from the AMOSKYS brain's response actions which
flow back to Aegis as signed virtual patches.

== What Aegis Watches (v0.1) ==

*   Authentication — login success/fail, role changes, admin registrations
*   REST routes — unauth route registration, PHP object injection canaries
*   Plugin lifecycle — install/activate/deactivate/update, with metadata diff
*   File integrity — wp-config.php modifications
*   Outbound HTTP — calls to third-party hosts, Ethereum JSON-RPC detection

== What Aegis Does NOT Do (yet) ==

*   Block attacks in-line (v0.2 — virtual patch ingestion from the brain)
*   Inspect SQL queries (v0.3 — query filter high-volume, done carefully)
*   Runtime exploit mitigation (v0.4 — requires php.ini extension)
*   Operate without an AMOSKYS brain connection (Aegis-only mode is v0.5)

== Privacy ==

All data written to the local log stays on your site. Remote delivery to
AMOSKYS occurs only if you configure a remote URL. Events include:
request metadata (method, URI, IP, user-agent), event-specific attributes,
plugin/WP version strings. No page bodies, no cookies, no form values.

== Changelog ==

= 0.1.0-alpha =
*   Initial scaffold
*   5 sensors: auth, REST, plugin lifecycle, FIM, outbound
*   Local JSONL event log + optional remote POST
*   SHA-256 chain-linked events (Proof Spine compatible)
*   Minimal admin settings page
