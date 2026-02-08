"""Fuzz tests for the binary ciphertext format using Hypothesis.

These tests verify that deserialize() never crashes on arbitrary input —
it must either return valid data or raise ValueError.
"""

import base64
import struct

from hypothesis import given, settings, strategies as st

from morpheus.core.formats import (
    FORMAT_VERSION,
    HEADER_FORMAT,
    HEADER_SIZE,
    deserialize,
    serialize,
)


class TestDeserializeFuzz:
    """Property-based tests for deserialize()."""

    @given(st.binary())
    @settings(max_examples=500)
    def test_arbitrary_bytes_never_crash(self, data: bytes):
        """deserialize() must not crash on random bytes — only ValueError or success."""
        b64 = base64.b64encode(data).decode()
        try:
            result = deserialize(b64)
            # If it succeeds, the result must be a well-formed tuple
            assert isinstance(result, tuple)
            assert len(result) == 5
            version, cipher_id, kdf_id, flags, payload = result
            assert isinstance(version, int)
            assert isinstance(cipher_id, int)
            assert isinstance(kdf_id, int)
            assert isinstance(flags, int)
            assert isinstance(payload, bytes)
        except ValueError:
            pass  # Expected for most random inputs

    @given(st.text())
    @settings(max_examples=500)
    def test_arbitrary_strings_never_crash(self, data: str):
        """deserialize() must not crash on arbitrary text input."""
        try:
            deserialize(data)
        except ValueError:
            pass  # Expected

    @given(
        cipher_id=st.integers(min_value=0, max_value=255),
        kdf_id=st.integers(min_value=0, max_value=255),
        flags=st.integers(min_value=0, max_value=255),
        payload=st.binary(max_size=1024),
    )
    @settings(max_examples=200)
    def test_serialize_deserialize_roundtrip(
        self, cipher_id: int, kdf_id: int, flags: int, payload: bytes
    ):
        """Any valid serialize() output must deserialize() back identically."""
        b64 = serialize(cipher_id, kdf_id, flags, payload)
        version, out_cid, out_kid, out_flags, out_payload = deserialize(b64)
        assert version == FORMAT_VERSION
        assert out_cid == cipher_id
        assert out_kid == kdf_id
        assert out_flags == flags
        assert out_payload == payload

    @given(
        cipher_id=st.integers(min_value=0, max_value=255),
        kdf_id=st.integers(min_value=0, max_value=255),
        flags=st.integers(min_value=0, max_value=255),
        payload=st.binary(max_size=256),
        extra=st.binary(min_size=1, max_size=16),
    )
    @settings(max_examples=200)
    def test_trailing_bytes_preserved_in_payload(
        self, cipher_id: int, kdf_id: int, flags: int, payload: bytes, extra: bytes
    ):
        """Extra bytes appended after the header are part of the payload."""
        header = struct.pack(HEADER_FORMAT, FORMAT_VERSION, cipher_id, kdf_id, flags, 0)
        raw = header + payload + extra
        b64 = base64.b64encode(raw).decode()
        _, _, _, _, out_payload = deserialize(b64)
        assert out_payload == payload + extra

    @given(reserved=st.integers(min_value=1, max_value=65535))
    @settings(max_examples=100)
    def test_nonzero_reserved_always_rejected(self, reserved: int):
        """Any nonzero reserved field must be rejected."""
        header = struct.pack(HEADER_FORMAT, FORMAT_VERSION, 0x01, 0x02, 0x00, reserved)
        b64 = base64.b64encode(header + b"payload").decode()
        try:
            deserialize(b64)
            assert False, "Should have raised ValueError for nonzero reserved"
        except ValueError:
            pass

    @given(version=st.integers(min_value=0, max_value=255).filter(lambda v: v != FORMAT_VERSION))
    @settings(max_examples=100)
    def test_wrong_version_always_rejected(self, version: int):
        """Any version != FORMAT_VERSION must be rejected."""
        header = struct.pack(HEADER_FORMAT, version, 0x01, 0x02, 0x00, 0)
        b64 = base64.b64encode(header + b"payload").decode()
        try:
            deserialize(b64)
            assert False, "Should have raised ValueError for wrong version"
        except ValueError:
            pass

    @given(length=st.integers(min_value=0, max_value=HEADER_SIZE - 1))
    @settings(max_examples=20)
    def test_short_inputs_always_rejected(self, length: int):
        """Inputs shorter than HEADER_SIZE must be rejected."""
        raw = bytes(length)
        b64 = base64.b64encode(raw).decode()
        try:
            deserialize(b64)
            assert False, "Should have raised ValueError for short input"
        except ValueError:
            pass
