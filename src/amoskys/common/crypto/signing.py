from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

def load_private_key(path: str) -> ed25519.Ed25519PrivateKey:
    with open(path, "rb") as f:
        return ed25519.Ed25519PrivateKey.from_private_bytes(f.read())

def load_public_key(path: str) -> ed25519.Ed25519PublicKey:
    with open(path, "rb") as f:
        key = serialization.load_pem_public_key(f.read())
        if not isinstance(key, ed25519.Ed25519PublicKey):
            raise ValueError(f"Expected Ed25519 public key, got {type(key)}")
        return key

def sign(sk: ed25519.Ed25519PrivateKey, data: bytes) -> bytes:
    return sk.sign(data)

def verify(pk, data: bytes, sig: bytes) -> bool:
    try:
        pk.verify(sig, data)
        return True
    except Exception:
        return False
