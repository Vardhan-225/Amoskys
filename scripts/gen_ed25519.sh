#!/usr/bin/env bash
set -euo pipefail
mkdir -p certs
python - <<'PY'
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from pathlib import Path

sk = ed25519.Ed25519PrivateKey.generate()
pk = sk.public_key()
raw = sk.private_bytes(encoding=serialization.Encoding.Raw,
                       format=serialization.PrivateFormat.Raw,
                       encryption_algorithm=serialization.NoEncryption())
pem = pk.public_bytes(encoding=serialization.Encoding.PEM,
                      format=serialization.PublicFormat.SubjectPublicKeyInfo)
Path("certs/agent.ed25519").write_bytes(raw)
Path("certs/agent.ed25519.pub").write_bytes(pem)
print("wrote certs/agent.ed25519 (+ .pub)")
PY
