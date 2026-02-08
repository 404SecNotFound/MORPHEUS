"""Tests for key derivation functions."""

import os

import pytest

from morpheus.core.kdf import (
    KDF_CHOICES,
    KDF_REGISTRY,
    Argon2idKDF,
    ScryptKDF,
)


class TestArgon2idKDF:
    def setup_method(self):
        # Use low params for fast tests
        self.kdf = Argon2idKDF(time_cost=1, memory_cost=1024, parallelism=1)

    def test_derive_produces_32_bytes(self):
        salt = os.urandom(16)
        key = self.kdf.derive(b"TestP@ssw0rd!!", salt)
        assert len(key) == 32

    def test_derive_custom_length(self):
        salt = os.urandom(16)
        key = self.kdf.derive(b"TestP@ssw0rd!!", salt, key_length=64)
        assert len(key) == 64

    def test_same_inputs_same_output(self):
        salt = os.urandom(16)
        k1 = self.kdf.derive(b"TestP@ssw0rd!!", salt)
        k2 = self.kdf.derive(b"TestP@ssw0rd!!", salt)
        assert k1 == k2

    def test_different_passwords_different_output(self):
        salt = os.urandom(16)
        k1 = self.kdf.derive(b"TestP@ssw0rd!!", salt)
        k2 = self.kdf.derive(b"OtherP@ssw0rd!!", salt)
        assert k1 != k2

    def test_different_salts_different_output(self):
        s1 = os.urandom(16)
        s2 = os.urandom(16)
        k1 = self.kdf.derive(b"TestP@ssw0rd!!", s1)
        k2 = self.kdf.derive(b"TestP@ssw0rd!!", s2)
        assert k1 != k2

    def test_derive_returns_bytearray(self):
        salt = os.urandom(16)
        key = self.kdf.derive(b"TestP@ssw0rd!!", salt)
        assert isinstance(key, bytearray)

    def test_derive_accepts_bytearray_password(self):
        salt = os.urandom(16)
        pwd = bytearray(b"TestP@ssw0rd!!")
        key = self.kdf.derive(pwd, salt)
        assert len(key) == 32
        assert isinstance(key, bytearray)

    def test_generate_salt(self):
        salt = self.kdf.generate_salt()
        assert len(salt) == 16

    def test_kdf_id(self):
        assert self.kdf.kdf_id == 0x02


class TestScryptKDF:
    def setup_method(self):
        # Use lower n for fast tests
        self.kdf = ScryptKDF(n=2**14, r=8, p=1)

    def test_derive_produces_32_bytes(self):
        salt = os.urandom(16)
        key = self.kdf.derive(b"TestP@ssw0rd!!", salt)
        assert len(key) == 32

    def test_same_inputs_same_output(self):
        salt = os.urandom(16)
        k1 = self.kdf.derive(b"TestP@ssw0rd!!", salt)
        k2 = self.kdf.derive(b"TestP@ssw0rd!!", salt)
        assert k1 == k2

    def test_different_passwords_different_output(self):
        salt = os.urandom(16)
        k1 = self.kdf.derive(b"TestP@ssw0rd!!", salt)
        k2 = self.kdf.derive(b"OtherP@ssw0rd!!", salt)
        assert k1 != k2

    def test_derive_returns_bytearray(self):
        salt = os.urandom(16)
        key = self.kdf.derive(b"TestP@ssw0rd!!", salt)
        assert isinstance(key, bytearray)

    def test_kdf_id(self):
        assert self.kdf.kdf_id == 0x01

    def test_generate_salt(self):
        salt = self.kdf.generate_salt()
        assert len(salt) == 16


class TestKDFRegistry:
    def test_all_kdfs_registered(self):
        assert 0x01 in KDF_REGISTRY
        assert 0x02 in KDF_REGISTRY

    def test_kdf_choices_match(self):
        assert "Argon2id" in KDF_CHOICES
        assert "Scrypt" in KDF_CHOICES
