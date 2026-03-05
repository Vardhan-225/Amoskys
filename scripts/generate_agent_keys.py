#!/usr/bin/env python3
"""Generate Ed25519 keypairs for all AMOSKYS agents.

Creates:
  certs/agents/{agent_name}.ed25519      — 32-byte raw private key
  certs/agents/{agent_name}.ed25519.pub  — PEM-encoded public key

Updates:
  agent_key_registry.json — populates public_key fields and sets status to "active"

Usage:
  python scripts/generate_agent_keys.py [--force]

The --force flag regenerates keys even if they already exist.
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CERTS_DIR = PROJECT_ROOT / "certs" / "agents"
REGISTRY_PATH = PROJECT_ROOT / "agent_key_registry.json"

AGENTS = [
    "proc_agent",
    "flow_agent",
    "dns_agent",
    "fim_agent",
    "auth_guard_agent",
    "persistence_guard",
    "peripheral_agent",
    "kernel_audit_agent",
    "device_discovery",
    "protocol_collectors",
    # L7 Gap-Closure Agents
    "applog_agent",
    "db_activity_agent",
    "http_inspector_agent",
    "internet_activity_agent",
    "net_scanner_agent",
]


def generate_keypair(agent_name: str, force: bool = False) -> str:
    """Generate Ed25519 keypair for an agent. Returns PEM public key string."""
    priv_path = CERTS_DIR / f"{agent_name}.ed25519"
    pub_path = CERTS_DIR / f"{agent_name}.ed25519.pub"

    if priv_path.exists() and not force:
        # Load existing public key
        pub_pem = pub_path.read_text().strip()
        print(f"  [skip] {agent_name} — keys exist (use --force to regenerate)")
        return pub_pem

    # Generate new keypair
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Write private key (32 bytes raw)
    raw_private = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    priv_path.write_bytes(raw_private)
    os.chmod(priv_path, 0o600)

    # Write public key (PEM)
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    pub_path.write_text(pub_pem)

    print(f"  [new]  {agent_name} — keypair generated")
    return pub_pem.strip()


def update_registry(agent_keys: dict[str, str]):
    """Update agent_key_registry.json with real public keys."""
    registry = json.loads(REGISTRY_PATH.read_text())
    now = datetime.now(timezone.utc).isoformat()

    for entry in registry["agents"]:
        agent_id = entry["agent_id"]
        if agent_id in agent_keys:
            entry["public_key"] = agent_keys[agent_id]
            entry["status"] = "active"
            entry["valid_from"] = now

    REGISTRY_PATH.write_text(json.dumps(registry, indent=2) + "\n")
    print(f"\n  Registry updated: {REGISTRY_PATH}")


def main():
    force = "--force" in sys.argv
    CERTS_DIR.mkdir(parents=True, exist_ok=True)

    print("AMOSKYS Agent Key Generation")
    print(f"  Output: {CERTS_DIR}")
    print()

    agent_keys = {}
    for agent_name in AGENTS:
        pub_pem = generate_keypair(agent_name, force=force)
        agent_keys[agent_name] = pub_pem

    update_registry(agent_keys)

    # Summary
    print()
    active = sum(1 for v in agent_keys.values() if v)
    print(f"  {active}/{len(AGENTS)} agents have active keypairs")
    print(f"  Private keys: {CERTS_DIR}/*.ed25519 (NEVER commit these)")
    print(f"  Public keys:  {CERTS_DIR}/*.ed25519.pub")
    print()


if __name__ == "__main__":
    main()
