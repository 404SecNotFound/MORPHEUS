"""
Symmetric cipher implementations.

Provides a strategy-pattern interface for AES-256-GCM and ChaCha20-Poly1305,
with a registry for format-level cipher identification.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


class Cipher(ABC):
    """Abstract base for all symmetric AEAD ciphers."""

    @property
    @abstractmethod
    def cipher_id(self) -> int:
        """Unique byte identifier stored in the ciphertext header."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable cipher name."""

    @property
    @abstractmethod
    def key_size(self) -> int:
        """Required key length in bytes."""

    @property
    @abstractmethod
    def nonce_size(self) -> int:
        """Required nonce length in bytes."""

    @abstractmethod
    def encrypt(self, key: bytes | bytearray, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
        """Encrypt plaintext, returning (nonce, ciphertext_with_tag)."""

    @abstractmethod
    def decrypt(self, key: bytes | bytearray, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        """Decrypt ciphertext, returning plaintext. Raises InvalidTag on failure."""


class AES256GCM(Cipher):
    """AES-256 in Galois/Counter Mode (NIST standard)."""

    cipher_id = 0x01
    name = "AES-256-GCM"
    key_size = 32
    nonce_size = 12

    def encrypt(self, key: bytes | bytearray, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
        nonce = os.urandom(self.nonce_size)
        ciphertext = AESGCM(bytes(key)).encrypt(nonce, plaintext, aad)
        return nonce, ciphertext

    def decrypt(self, key: bytes | bytearray, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        return AESGCM(bytes(key)).decrypt(nonce, ciphertext, aad)


class ChaCha20Poly1305Cipher(Cipher):
    """ChaCha20-Poly1305 (RFC 8439). Preferred when AES-NI is unavailable."""

    cipher_id = 0x02
    name = "ChaCha20-Poly1305"
    key_size = 32
    nonce_size = 12

    def encrypt(self, key: bytes | bytearray, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
        nonce = os.urandom(self.nonce_size)
        ciphertext = ChaCha20Poly1305(bytes(key)).encrypt(nonce, plaintext, aad)
        return nonce, ciphertext

    def decrypt(self, key: bytes | bytearray, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        return ChaCha20Poly1305(bytes(key)).decrypt(nonce, ciphertext, aad)


# Cipher ID 0x03 is reserved for chained AES-256-GCM -> ChaCha20-Poly1305
CHAINED_CIPHER_ID = 0x03

CIPHER_REGISTRY: dict[int, type[Cipher]] = {
    0x01: AES256GCM,
    0x02: ChaCha20Poly1305Cipher,
}

CIPHER_CHOICES: dict[str, type[Cipher]] = {
    "AES-256-GCM": AES256GCM,
    "ChaCha20-Poly1305": ChaCha20Poly1305Cipher,
}
