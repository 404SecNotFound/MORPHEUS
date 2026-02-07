"""Tests for symmetric cipher implementations."""

import os

import pytest
from cryptography.exceptions import InvalidTag

from secure_encryption.core.ciphers import (
    AES256GCM,
    CIPHER_CHOICES,
    CIPHER_REGISTRY,
    ChaCha20Poly1305Cipher,
)


class TestAES256GCM:
    def setup_method(self):
        self.cipher = AES256GCM()
        self.key = os.urandom(32)
        self.aad = b"test-aad"

    def test_encrypt_decrypt_roundtrip(self):
        plaintext = b"Hello, World! This is a block of secret text."
        nonce, ciphertext = self.cipher.encrypt(self.key, plaintext, self.aad)
        result = self.cipher.decrypt(self.key, nonce, ciphertext, self.aad)
        assert result == plaintext

    def test_nonce_is_12_bytes(self):
        nonce, _ = self.cipher.encrypt(self.key, b"test", self.aad)
        assert len(nonce) == 12

    def test_unique_nonces(self):
        nonces = set()
        for _ in range(100):
            nonce, _ = self.cipher.encrypt(self.key, b"test", self.aad)
            nonces.add(nonce)
        assert len(nonces) == 100

    def test_wrong_key_fails(self):
        _, ciphertext = self.cipher.encrypt(self.key, b"secret", self.aad)
        nonce, ct = _, ciphertext
        wrong_key = os.urandom(32)
        with pytest.raises(InvalidTag):
            self.cipher.decrypt(wrong_key, nonce, ct, self.aad)

    def test_wrong_aad_fails(self):
        nonce, ciphertext = self.cipher.encrypt(self.key, b"secret", self.aad)
        with pytest.raises(InvalidTag):
            self.cipher.decrypt(self.key, nonce, ciphertext, b"wrong-aad")

    def test_tampered_ciphertext_fails(self):
        nonce, ciphertext = self.cipher.encrypt(self.key, b"secret", self.aad)
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        with pytest.raises(InvalidTag):
            self.cipher.decrypt(self.key, nonce, bytes(tampered), self.aad)

    def test_empty_plaintext(self):
        nonce, ciphertext = self.cipher.encrypt(self.key, b"", self.aad)
        result = self.cipher.decrypt(self.key, nonce, ciphertext, self.aad)
        assert result == b""

    def test_large_plaintext(self):
        plaintext = os.urandom(1024 * 100)  # 100 KiB
        nonce, ciphertext = self.cipher.encrypt(self.key, plaintext, self.aad)
        result = self.cipher.decrypt(self.key, nonce, ciphertext, self.aad)
        assert result == plaintext

    def test_cipher_id(self):
        assert self.cipher.cipher_id == 0x01

    def test_key_size(self):
        assert self.cipher.key_size == 32


class TestChaCha20Poly1305:
    def setup_method(self):
        self.cipher = ChaCha20Poly1305Cipher()
        self.key = os.urandom(32)
        self.aad = b"test-aad"

    def test_encrypt_decrypt_roundtrip(self):
        plaintext = b"ChaCha20 test with a multi-line\nblock of text\nthird line"
        nonce, ciphertext = self.cipher.encrypt(self.key, plaintext, self.aad)
        result = self.cipher.decrypt(self.key, nonce, ciphertext, self.aad)
        assert result == plaintext

    def test_nonce_is_12_bytes(self):
        nonce, _ = self.cipher.encrypt(self.key, b"test", self.aad)
        assert len(nonce) == 12

    def test_wrong_key_fails(self):
        nonce, ciphertext = self.cipher.encrypt(self.key, b"secret", self.aad)
        with pytest.raises(InvalidTag):
            self.cipher.decrypt(os.urandom(32), nonce, ciphertext, self.aad)

    def test_wrong_aad_fails(self):
        nonce, ciphertext = self.cipher.encrypt(self.key, b"secret", self.aad)
        with pytest.raises(InvalidTag):
            self.cipher.decrypt(self.key, nonce, ciphertext, b"wrong")

    def test_cipher_id(self):
        assert self.cipher.cipher_id == 0x02

    def test_large_plaintext(self):
        plaintext = os.urandom(1024 * 100)
        nonce, ciphertext = self.cipher.encrypt(self.key, plaintext, self.aad)
        result = self.cipher.decrypt(self.key, nonce, ciphertext, self.aad)
        assert result == plaintext


class TestCipherRegistry:
    def test_all_ciphers_registered(self):
        assert 0x01 in CIPHER_REGISTRY
        assert 0x02 in CIPHER_REGISTRY

    def test_cipher_choices_match(self):
        assert "AES-256-GCM" in CIPHER_CHOICES
        assert "ChaCha20-Poly1305" in CIPHER_CHOICES
