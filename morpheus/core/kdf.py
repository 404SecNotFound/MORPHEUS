"""
Key Derivation Function implementations.

Provides Argon2id (recommended) and Scrypt, both producing 256-bit keys
from passwords with random salts.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod

from argon2.low_level import Type as Argon2Type
from argon2.low_level import hash_secret_raw
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class KDF(ABC):
    """Abstract base for key derivation functions."""

    @property
    @abstractmethod
    def kdf_id(self) -> int:
        """Unique byte identifier stored in the ciphertext header."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name."""

    @property
    @abstractmethod
    def salt_size(self) -> int:
        """Required salt length in bytes."""

    @abstractmethod
    def derive(self, password: bytes | bytearray, salt: bytes, key_length: int = 32) -> bytearray:
        """Derive a key from a password (as bytes/bytearray) and salt.

        Returns a mutable bytearray so callers can zero it after use.
        """

    def generate_salt(self) -> bytes:
        return os.urandom(self.salt_size)


class Argon2idKDF(KDF):
    """
    Argon2id - OWASP and IETF recommended KDF (RFC 9106).

    Default parameters follow OWASP 2024 guidelines:
      time_cost=3, memory_cost=65536 (64 MiB), parallelism=4
    """

    kdf_id = 0x02
    name = "Argon2id"
    salt_size = 16

    def __init__(self, time_cost: int = 3, memory_cost: int = 65536, parallelism: int = 4):
        self.time_cost = time_cost
        self.memory_cost = memory_cost
        self.parallelism = parallelism

    def derive(self, password: bytes | bytearray, salt: bytes, key_length: int = 32) -> bytearray:
        result = hash_secret_raw(
            secret=bytes(password),
            salt=salt,
            time_cost=self.time_cost,
            memory_cost=self.memory_cost,
            parallelism=self.parallelism,
            hash_len=key_length,
            type=Argon2Type.ID,
        )
        return bytearray(result)


class ScryptKDF(KDF):
    """
    Scrypt KDF (RFC 7914).

    Default n=2^17 (131072) per OWASP 2024 interactive-use recommendation.
    """

    kdf_id = 0x01
    name = "Scrypt"
    salt_size = 16

    def __init__(self, n: int = 2**17, r: int = 8, p: int = 1):
        self.n = n
        self.r = r
        self.p = p

    def derive(self, password: bytes | bytearray, salt: bytes, key_length: int = 32) -> bytearray:
        kdf = Scrypt(
            salt=salt,
            length=key_length,
            n=self.n,
            r=self.r,
            p=self.p,
        )
        result = kdf.derive(bytes(password))
        return bytearray(result)


KDF_REGISTRY: dict[int, type[KDF]] = {
    0x01: ScryptKDF,
    0x02: Argon2idKDF,
}

KDF_CHOICES: dict[str, type[KDF]] = {
    "Argon2id": Argon2idKDF,
    "Scrypt": ScryptKDF,
}
