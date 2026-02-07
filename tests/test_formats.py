"""Tests for the versioned ciphertext format."""

import base64

import pytest

from secure_encryption.core.formats import (
    FLAG_CHAINED,
    FLAG_HYBRID_PQ,
    FORMAT_VERSION,
    HEADER_SIZE,
    build_aad,
    deserialize,
    serialize,
)


class TestSerializeDeserialize:
    def test_roundtrip(self):
        payload = b"some-encrypted-data-here"
        b64 = serialize(0x01, 0x02, 0x00, payload)
        version, cipher_id, kdf_id, flags, out_payload = deserialize(b64)
        assert version == FORMAT_VERSION
        assert cipher_id == 0x01
        assert kdf_id == 0x02
        assert flags == 0x00
        assert out_payload == payload

    def test_flags_preserved(self):
        flags = FLAG_CHAINED | FLAG_HYBRID_PQ
        b64 = serialize(0x01, 0x02, flags, b"data")
        _, _, _, out_flags, _ = deserialize(b64)
        assert out_flags == flags

    def test_invalid_base64_raises(self):
        with pytest.raises(ValueError, match="Invalid base64"):
            deserialize("not-valid-base64!!!")

    def test_too_short_raises(self):
        short = base64.b64encode(b"\x02\x01").decode()
        with pytest.raises(ValueError, match="too short"):
            deserialize(short)

    def test_wrong_version_raises(self):
        import struct
        header = struct.pack("!BBBBH", 0xFF, 0x01, 0x02, 0x00, 0)
        b64 = base64.b64encode(header + b"payload").decode()
        with pytest.raises(ValueError, match="Unsupported ciphertext version"):
            deserialize(b64)

    def test_header_size_is_6(self):
        assert HEADER_SIZE == 6


class TestBuildAAD:
    def test_aad_is_4_bytes(self):
        aad = build_aad(0x02, 0x01, 0x02, 0x00)
        assert len(aad) == 4

    def test_aad_reflects_inputs(self):
        aad1 = build_aad(0x02, 0x01, 0x02, 0x00)
        aad2 = build_aad(0x02, 0x02, 0x02, 0x00)
        assert aad1 != aad2  # Different cipher_id → different AAD

    def test_aad_flag_binding(self):
        aad_plain = build_aad(0x02, 0x01, 0x02, 0x00)
        aad_chained = build_aad(0x02, 0x01, 0x02, FLAG_CHAINED)
        assert aad_plain != aad_chained
