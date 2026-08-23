"""Structural invariants on OBSERVATION routing.

Two bugs sat in these tables at once, and neither was visible at runtime:

  * `correlation` appeared in NO router, so _wal_quality would reject every
    OBSERVATION it produced with CONTRACT_UNKNOWN_OBSERVATION_DOMAIN. A sensor
    wired at the collector and severed at the router reads as "enabled" from
    both ends.

  * `peripheral`'s router writes peripheral_events while the receipt ledger
    claimed observation_events. A ledger that disagrees with the write is worse
    than no ledger: reconciliation built on it confirms the wrong thing with
    confidence.

Neither is catchable by reading either table alone, which is why these are
asserted as invariants BETWEEN them rather than as a list of expected values —
a list would need updating with every new domain and would rot into a copy of
the thing it checks.
"""

import re

import pytest

SRC = "src/amoskys/storage/_wal_observations.py"

# What each router implementation actually inserts into. Derived from the
# method bodies, not from the ledger — the whole point is to check the ledger.
ROUTER_WRITES = {
    "_insert_process_observation": "process_events",
    "_insert_flow_observation": "flow_events",
    "_insert_dns_observation": "dns_events",
    "_insert_auth_observation": "audit_events",
    "_insert_fim_observation": "fim_events",
    "_insert_persistence_observation": "persistence_events",
    "_insert_peripheral_observation": "peripheral_events",
    "_insert_generic_observation": "observation_events",
}


def _tables():
    src = open(SRC).read()
    routers = dict(re.findall(r'"([a-z_]+)":\s*"(_insert_\w+)"', src))
    block = re.search(r"_OBSERVATION_DEST_TABLE\s*=\s*\{(.*?)\n    \}", src, re.S)
    dests = dict(re.findall(r'"([a-z_]+)":\s*"([a-z_]+)"', block.group(1)))
    return routers, dests


def test_router_implementations_are_all_known():
    """A new router method must be added to ROUTER_WRITES here.

    Otherwise this file silently stops checking the domain that uses it, and
    the invariant quietly narrows instead of failing.
    """
    routers, _ = _tables()
    unknown = set(routers.values()) - set(ROUTER_WRITES)
    assert not unknown, (
        f"router method(s) {sorted(unknown)} have no known destination; add "
        "them to ROUTER_WRITES so they are covered"
    )


def test_every_router_has_a_matching_ledger_destination():
    """The receipt must name the table the write actually targets."""
    routers, dests = _tables()
    mismatches = []
    for domain, method in sorted(routers.items()):
        actual = ROUTER_WRITES[method]
        claimed = dests.get(domain)
        if claimed != actual:
            mismatches.append(f"{domain}: writes {actual}, ledger says {claimed}")
    assert not mismatches, (
        "receipt ledger disagrees with the write for: " + "; ".join(mismatches)
    )


def test_every_collector_agent_domain_has_a_router():
    """An agent wired at the collector but absent here is rejected on arrival.

    _wal_quality raises CONTRACT_UNKNOWN_OBSERVATION_DOMAIN for any OBSERVATION
    whose _domain is not a key of _OBSERVATION_ROUTERS, so the event never
    reaches storage at all.
    """
    import os

    routers, _ = _tables()
    src = open("src/amoskys/collector_main.py").read()
    packages = {
        m.split(".")[-2]
        for m in re.findall(r'_try_load\(\s*"([^"]+)"', src)
        if "." in m
    }
    # Domains whose router key legitimately differs from the package name.
    ALIASES = {
        "network": "flow", "process": "process", "http_inspector": "http",
        "infostealer_guard": "infostealer", "quarantine_guard": "quarantine",
        "protocol_collectors": None,   # emits non-OBSERVATION event types
        "db_activity": "db_activity",
    }
    missing = []
    for pkg in sorted(packages):
        key = ALIASES.get(pkg, pkg)
        if key is None:
            continue
        if key not in routers:
            missing.append(f"{pkg} (looked for domain '{key}')")
    assert not missing, (
        "collector-wired agent(s) have no OBSERVATION router, so their events "
        "are rejected on arrival: " + ", ".join(missing)
    )
