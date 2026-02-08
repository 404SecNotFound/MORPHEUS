"""Tests for symmetric cipher implementations."""

import os

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 as _ChaCha20

from morpheus.core.ciphers import (
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


class TestAES256GCMTestVector:
    """Verify AES-256-GCM against a known test vector (NIST SP 800-38D, Test Case 16)."""

    def test_nist_sp800_38d_tc14(self):
        # NIST SP 800-38D Test Case 14: AES-256-GCM, 96-bit IV, 512-bit plaintext
        key = bytes.fromhex(
            "feffe9928665731c6d6a8f9467308308"
            "feffe9928665731c6d6a8f9467308308"
        )
        nonce = bytes.fromhex("cafebabefacedbaddecaf888")
        plaintext = bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a"
            "86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b391aafd255"
        )
        expected_ct = bytes.fromhex(
            "522dc1f099567d07f47f37a32a84427d"
            "643a8cdcbfe5c0c97598a2bd2555d1aa"
            "8cb08e48590dbb3da7b08b1056828838"
            "c5f61e6393ba7a0abcc9f662898015ad"
        )
        expected_tag = bytes.fromhex("b094dac5d93471bdec1a502270e3cc6c")

        # Encrypt using the raw library to verify against NIST reference
        aesgcm = AESGCM(key)
        ct_with_tag = aesgcm.encrypt(nonce, plaintext, None)
        ct = ct_with_tag[:-16]
        tag = ct_with_tag[-16:]
        assert ct == expected_ct
        assert tag == expected_tag

        # Decrypt using our cipher wrapper
        cipher = AES256GCM()
        aad = b"context"  # Our wrapper always uses AAD
        ct_ours = aesgcm.encrypt(nonce, plaintext, aad)
        result = cipher.decrypt(key, nonce, ct_ours, aad)
        assert result == plaintext


class TestChaCha20Poly1305TestVector:
    """Verify ChaCha20-Poly1305 against RFC 8439 test vector (Section 2.8.2)."""

    def test_rfc8439_section_2_8_2(self):
        key = bytes.fromhex(
            "808182838485868788898a8b8c8d8e8f"
            "909192939495969798999a9b9c9d9e9f"
        )
        nonce = bytes.fromhex("070000004041424344454647")
        aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        plaintext = (
            b"Ladies and Gentlemen of the class of '99: "
            b"If I could offer you only one tip for the future, sunscreen would be it."
        )
        expected_ct = bytes.fromhex(
            "d31a8d34648e60db7b86afbc53ef7ec2"
            "a4aded51296e08fea9e2b5a736ee62d6"
            "3dbea45e8ca9671282fafb69da92728b"
            "1a71de0a9e060b2905d6a5b67ecd3b36"
            "92ddbd7f2d778b8c9803aee328091b58"
            "fab324e4fad675945585808b4831d7bc"
            "3ff4def08e4b7a9de576d26586cec64b"
            "6116"
        )
        expected_tag = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")

        # Encrypt using the raw library to verify against test vector
        chacha = _ChaCha20(key)
        ct_with_tag = chacha.encrypt(nonce, plaintext, aad)
        ct = ct_with_tag[:-16]
        tag = ct_with_tag[-16:]
        assert ct == expected_ct
        assert tag == expected_tag

        # Decrypt using our cipher wrapper
        cipher = ChaCha20Poly1305Cipher()
        result = cipher.decrypt(key, nonce, ct_with_tag, aad)
        assert result == plaintext


class TestCiphertextIndistinguishability:
    """Same plaintext + key must produce different ciphertexts (random nonce)."""

    @pytest.mark.parametrize("cipher_cls", [AES256GCM, ChaCha20Poly1305Cipher])
    def test_same_plaintext_different_ciphertexts(self, cipher_cls):
        cipher = cipher_cls()
        key = os.urandom(32)
        pt = b"identical plaintext"
        aad = b"aad"
        results = set()
        for _ in range(50):
            _, ct = cipher.encrypt(key, pt, aad)
            results.add(ct)
        assert len(results) == 50

    @pytest.mark.parametrize("cipher_cls", [AES256GCM, ChaCha20Poly1305Cipher])
    def test_single_byte_plaintext(self, cipher_cls):
        cipher = cipher_cls()
        key = os.urandom(32)
        nonce, ct = cipher.encrypt(key, b"\x42", b"aad")
        result = cipher.decrypt(key, nonce, ct, b"aad")
        assert result == b"\x42"

    @pytest.mark.parametrize("cipher_cls", [AES256GCM, ChaCha20Poly1305Cipher])
    def test_bytearray_key(self, cipher_cls):
        """Cipher should accept bytearray keys (mutable for zeroing)."""
        cipher = cipher_cls()
        key = bytearray(os.urandom(32))
        nonce, ct = cipher.encrypt(key, b"test", b"aad")
        result = cipher.decrypt(key, nonce, ct, b"aad")
        assert result == b"test"


class TestCipherRegistry:
    def test_all_ciphers_registered(self):
        assert 0x01 in CIPHER_REGISTRY
        assert 0x02 in CIPHER_REGISTRY

    def test_cipher_choices_match(self):
        assert "AES-256-GCM" in CIPHER_CHOICES
        assert "ChaCha20-Poly1305" in CIPHER_CHOICES
