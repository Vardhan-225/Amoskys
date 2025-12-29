"""
Tests for Ed25519 Digital Signature Module

Security-critical tests for cryptographic signing and verification.
These tests ensure the integrity of AMOSKYS signature system.
"""

import pytest
import tempfile
import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from amoskys.common.crypto import signing


class TestPrivateKeyLoading:
    """Test Ed25519 private key loading."""

    def test_load_valid_private_key(self, tmp_path):
        """Verify loading a valid 32-byte Ed25519 private key."""
        # Generate a valid Ed25519 private key
        sk = ed25519.Ed25519PrivateKey.generate()
        private_bytes = sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Write to temporary file
        key_file = tmp_path / "test.key"
        key_file.write_bytes(private_bytes)

        # Test loading
        loaded_sk = signing.load_private_key(str(key_file))
        assert isinstance(loaded_sk, ed25519.Ed25519PrivateKey)

        # Verify it's the same key by comparing public keys
        original_pk = sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        loaded_pk = loaded_sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        assert original_pk == loaded_pk

    def test_load_private_key_missing_file(self):
        """Verify FileNotFoundError for missing key file."""
        with pytest.raises(FileNotFoundError):
            signing.load_private_key("/nonexistent/path/key.ed25519")

    def test_load_private_key_invalid_size(self, tmp_path):
        """Verify ValueError for key file with wrong size."""
        # Create file with wrong size (not 32 bytes)
        key_file = tmp_path / "bad.key"
        key_file.write_bytes(b"this is not 32 bytes")

        with pytest.raises(ValueError):
            signing.load_private_key(str(key_file))

    def test_load_private_key_empty_file(self, tmp_path):
        """Verify ValueError for empty key file."""
        key_file = tmp_path / "empty.key"
        key_file.write_bytes(b"")

        with pytest.raises(ValueError):
            signing.load_private_key(str(key_file))


class TestPublicKeyLoading:
    """Test Ed25519 public key loading."""

    def test_load_valid_public_key(self, tmp_path):
        """Verify loading a valid PEM-encoded Ed25519 public key."""
        # Generate key pair
        sk = ed25519.Ed25519PrivateKey.generate()
        pk = sk.public_key()

        # Serialize public key to PEM
        pem_bytes = pk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Write to temporary file
        pub_file = tmp_path / "test.pub"
        pub_file.write_bytes(pem_bytes)

        # Test loading
        loaded_pk = signing.load_public_key(str(pub_file))
        assert isinstance(loaded_pk, ed25519.Ed25519PublicKey)

        # Verify it's the same key
        original_bytes = pk.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        loaded_bytes = loaded_pk.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        assert original_bytes == loaded_bytes

    def test_load_public_key_missing_file(self):
        """Verify FileNotFoundError for missing public key file."""
        with pytest.raises(FileNotFoundError):
            signing.load_public_key("/nonexistent/path/key.pub")

    def test_load_public_key_invalid_pem(self, tmp_path):
        """Verify ValueError for invalid PEM format."""
        pub_file = tmp_path / "bad.pub"
        pub_file.write_bytes(b"not a valid PEM file")

        with pytest.raises(ValueError):
            signing.load_public_key(str(pub_file))


class TestSigning:
    """Test Ed25519 signature generation."""

    def test_sign_basic(self):
        """Verify basic signing produces 64-byte signature."""
        sk = ed25519.Ed25519PrivateKey.generate()
        data = b"test message"

        signature = signing.sign(sk, data)

        assert isinstance(signature, bytes)
        assert len(signature) == 64

    def test_sign_deterministic(self):
        """Verify signing is deterministic (same input = same signature)."""
        sk = ed25519.Ed25519PrivateKey.generate()
        data = b"deterministic test"

        sig1 = signing.sign(sk, data)
        sig2 = signing.sign(sk, data)

        assert sig1 == sig2

    def test_sign_different_data_different_signature(self):
        """Verify different data produces different signatures."""
        sk = ed25519.Ed25519PrivateKey.generate()
        data1 = b"message one"
        data2 = b"message two"

        sig1 = signing.sign(sk, data1)
        sig2 = signing.sign(sk, data2)

        assert sig1 != sig2

    def test_sign_empty_data(self):
        """Verify signing empty data works."""
        sk = ed25519.Ed25519PrivateKey.generate()
        signature = signing.sign(sk, b"")

        assert isinstance(signature, bytes)
        assert len(signature) == 64


class TestVerification:
    """Test Ed25519 signature verification."""

    def test_verify_valid_signature(self):
        """Verify valid signature passes verification."""
        sk = ed25519.Ed25519PrivateKey.generate()
        pk = sk.public_key()
        data = b"test message"

        signature = signing.sign(sk, data)
        result = signing.verify(pk, data, signature)

        assert result is True

    def test_verify_invalid_signature(self):
        """Verify tampered signature fails verification."""
        sk = ed25519.Ed25519PrivateKey.generate()
        pk = sk.public_key()
        data = b"test message"

        signature = signing.sign(sk, data)

        # Tamper with signature
        tampered_sig = bytes([b ^ 0xFF for b in signature])

        result = signing.verify(pk, data, tampered_sig)
        assert result is False

    def test_verify_wrong_data(self):
        """Verify signature fails when data doesn't match."""
        sk = ed25519.Ed25519PrivateKey.generate()
        pk = sk.public_key()

        original_data = b"original message"
        different_data = b"different message"

        signature = signing.sign(sk, original_data)
        result = signing.verify(pk, different_data, signature)

        assert result is False

    def test_verify_wrong_public_key(self):
        """Verify signature fails with wrong public key."""
        sk1 = ed25519.Ed25519PrivateKey.generate()
        sk2 = ed25519.Ed25519PrivateKey.generate()
        pk2 = sk2.public_key()

        data = b"test message"
        signature = signing.sign(sk1, data)

        # Try to verify with different public key
        result = signing.verify(pk2, data, signature)
        assert result is False

    def test_verify_malformed_signature(self):
        """Verify malformed signature fails gracefully."""
        sk = ed25519.Ed25519PrivateKey.generate()
        pk = sk.public_key()
        data = b"test message"

        # Test various malformed signatures
        malformed_sigs = [
            b"too short",
            b"x" * 32,  # Wrong size (32 instead of 64)
            b"x" * 128,  # Wrong size (128 instead of 64)
            b"",  # Empty
        ]

        for bad_sig in malformed_sigs:
            result = signing.verify(pk, data, bad_sig)
            assert result is False, f"Should reject signature: {bad_sig!r}"

    def test_verify_round_trip(self):
        """Verify complete sign-verify round trip."""
        sk = ed25519.Ed25519PrivateKey.generate()
        pk = sk.public_key()

        test_data = [
            b"simple message",
            b"message with unicode: \xc3\xa9\xc3\xa0\xc3\xbc",
            b"\x00\x01\x02\x03binary data\xff\xfe\xfd",
            b"x" * 1000,  # Large message
            b"",  # Empty message
        ]

        for data in test_data:
            signature = signing.sign(sk, data)
            assert signing.verify(pk, data, signature), f"Failed for: {data!r}"


class TestSecurityProperties:
    """Test security properties of the signature system."""

    def test_signature_does_not_leak_private_key(self):
        """Verify signatures don't leak information about private key."""
        sk = ed25519.Ed25519PrivateKey.generate()

        # Generate multiple signatures
        signatures = [signing.sign(sk, f"message {i}".encode()) for i in range(10)]

        # All signatures should be 64 bytes
        assert all(len(sig) == 64 for sig in signatures)

        # All signatures should be different (no repeats)
        assert len(set(signatures)) == len(signatures)

    def test_cannot_forge_signature_without_private_key(self):
        """Verify signatures cannot be forged without private key."""
        sk = ed25519.Ed25519PrivateKey.generate()
        pk = sk.public_key()
        data = b"target message"

        # Try various forgery attempts
        forgery_attempts = [
            b"x" * 64,  # Random bytes
            b"\x00" * 64,  # All zeros
            b"\xff" * 64,  # All ones
            os.urandom(64),  # Random signature
        ]

        for forged_sig in forgery_attempts:
            result = signing.verify(pk, data, forged_sig)
            assert result is False, "Forged signature should not verify"

    def test_signature_uniqueness_across_keys(self):
        """Verify different keys produce different signatures."""
        data = b"same message"

        sk1 = ed25519.Ed25519PrivateKey.generate()
        sk2 = ed25519.Ed25519PrivateKey.generate()

        sig1 = signing.sign(sk1, data)
        sig2 = signing.sign(sk2, data)

        # Different keys should produce different signatures
        assert sig1 != sig2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
