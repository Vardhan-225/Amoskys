"""Ed25519 Digital Signature Utilities for AMOSKYS.

This module provides cryptographic signing and verification using Ed25519,
a modern elliptic curve signature scheme with strong security guarantees.

Security Properties:
    - Ed25519 provides ~128-bit security level
    - Deterministic signatures (no random number generation needed)
    - Fast signature verification
    - Small key and signature sizes (32 bytes / 64 bytes)

Key Format:
    - Private keys: 32 bytes raw binary (NOT PEM)
    - Public keys: PEM format (SSH-style encoding)

Usage:
    >>> sk = load_private_key("agent.ed25519")
    >>> pk = load_public_key("agent.ed25519.pub")
    >>> signature = sign(sk, b"message")
    >>> assert verify(pk, b"message", signature)
"""

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def load_private_key(path: str) -> ed25519.Ed25519PrivateKey:
    """Load Ed25519 private key from raw 32-byte file.

    Args:
        path: Filesystem path to private key file (32 bytes, NOT PEM)

    Returns:
        ed25519.Ed25519PrivateKey: Private key object for signing

    Raises:
        FileNotFoundError: If key file doesn't exist
        ValueError: If file is not exactly 32 bytes
    """
    with open(path, "rb") as f:
        return ed25519.Ed25519PrivateKey.from_private_bytes(f.read())


def load_public_key(path: str) -> ed25519.Ed25519PublicKey:
    """Load Ed25519 public key from PEM-encoded file.

    Args:
        path: Filesystem path to public key file (PEM format)

    Returns:
        ed25519.Ed25519PublicKey: Public key object for verification

    Raises:
        FileNotFoundError: If key file doesn't exist
        ValueError: If file is not Ed25519 public key or invalid PEM
    """
    with open(path, "rb") as f:
        key = serialization.load_pem_public_key(f.read())
        if not isinstance(key, ed25519.Ed25519PublicKey):
            raise ValueError(f"Expected Ed25519 public key, got {type(key)}")
        return key


def sign(sk: ed25519.Ed25519PrivateKey, data: bytes) -> bytes:
    """Create Ed25519 signature over data.

    Produces a deterministic 64-byte signature. Same data always produces
    same signature with the same key (no randomness involved).

    Args:
        sk: Ed25519 private key
        data: Bytes to sign (typically canonical protobuf serialization)

    Returns:
        bytes: 64-byte Ed25519 signature
    """
    return sk.sign(data)


def verify(pk, data: bytes, sig: bytes) -> bool:
    """Verify Ed25519 signature over data.

    Args:
        pk: Ed25519 public key
        data: Original bytes that were signed
        sig: 64-byte signature to verify

    Returns:
        bool: True if signature is valid, False otherwise

    Note:
        Returns False for ANY verification failure (invalid signature,
        wrong data, malformed signature, etc.). Never raises exceptions.
    """
    try:
        pk.verify(sig, data)
        return True
    except Exception:
        return False
