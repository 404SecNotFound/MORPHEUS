"""Tests for the versioned ciphertext format (v2 and v3)."""

import base64
import struct

import pytest

from morpheus.core.formats import (
    FLAG_CHAINED,
    FLAG_HYBRID_PQ,
    FLAG_PADDED,
    FORMAT_VERSION,
    FORMAT_VERSION_3,
    HEADER_FORMAT,
    HEADER_FORMAT_V3,
    HEADER_SIZE,
    HEADER_SIZE_V3,
    KEY_CHECK_SIZE,
    build_aad,
    deserialize,
    serialize,
)


class TestSerializeDeserializeV2:
    """Tests for v2 (legacy) format serialize/deserialize."""

    def test_roundtrip(self):
        payload = b"some-encrypted-data-here"
        b64 = serialize(0x01, 0x02, 0x00, payload)
        version, cipher_id, kdf_id, flags, out_payload, kdf_params = deserialize(b64)
        assert version == FORMAT_VERSION
        assert cipher_id == 0x01
        assert kdf_id == 0x02
        assert flags == 0x00
        assert out_payload == payload
        assert kdf_params is None

    def test_flags_preserved(self):
        flags = FLAG_CHAINED | FLAG_HYBRID_PQ
        b64 = serialize(0x01, 0x02, flags, b"data")
        _, _, _, out_flags, _, _ = deserialize(b64)
        assert out_flags == flags

    def test_invalid_base64_raises(self):
        with pytest.raises(ValueError, match="Invalid base64"):
            deserialize("not-valid-base64!!!")

    def test_too_short_raises(self):
        short = base64.b64encode(b"\x02\x01").decode()
        with pytest.raises(ValueError, match="too short"):
            deserialize(short)

    def test_wrong_version_raises(self):
        header = struct.pack("!BBBBH", 0xFF, 0x01, 0x02, 0x00, 0)
        b64 = base64.b64encode(header + b"payload").decode()
        with pytest.raises(ValueError, match="Unsupported ciphertext version"):
            deserialize(b64)

    def test_header_size_is_6(self):
        assert HEADER_SIZE == 6

    def test_empty_payload_roundtrip(self):
        """Serialize/deserialize with empty payload."""
        b64 = serialize(0x01, 0x02, 0x00, b"")
        _, _, _, _, out_payload, _ = deserialize(b64)
        assert out_payload == b""

    def test_large_payload_roundtrip(self):
        """Serialize/deserialize with 1 MiB payload."""
        payload = b"\xAA" * (1024 * 1024)
        b64 = serialize(0x01, 0x02, 0x00, payload)
        _, _, _, _, out_payload, _ = deserialize(b64)
        assert out_payload == payload

    def test_deterministic_serialization(self):
        """Same inputs produce the same output."""
        b1 = serialize(0x01, 0x02, 0x00, b"data")
        b2 = serialize(0x01, 0x02, 0x00, b"data")
        assert b1 == b2

    def test_all_flag_combinations_preserved(self):
        """Test each individual flag and both combined."""
        for flags in [0x00, FLAG_CHAINED, FLAG_HYBRID_PQ, FLAG_CHAINED | FLAG_HYBRID_PQ]:
            b64 = serialize(0x01, 0x02, flags, b"x")
            _, _, _, out_flags, _, _ = deserialize(b64)
            assert out_flags == flags

    def test_exactly_header_no_payload(self):
        """A message that is exactly the header with no payload bytes."""
        header = struct.pack(HEADER_FORMAT, FORMAT_VERSION, 0x01, 0x02, 0x00, 0)
        b64 = base64.b64encode(header).decode()
        version, cipher_id, kdf_id, flags, payload, kdf_params = deserialize(b64)
        assert payload == b""
        assert kdf_params is None

    def test_version_byte_is_network_order(self):
        """Verify the format uses big-endian (network byte order)."""
        b64 = serialize(0x01, 0x02, 0x00, b"test")
        raw = base64.b64decode(b64)
        # First byte should be FORMAT_VERSION
        assert raw[0] == FORMAT_VERSION
        # cipher_id, kdf_id, flags should be in exact positions
        assert raw[1] == 0x01  # cipher_id
        assert raw[2] == 0x02  # kdf_id
        assert raw[3] == 0x00  # flags

    def test_nonzero_reserved_bytes_rejected(self):
        """Reserved bytes must be zero; nonzero values are rejected."""
        header = struct.pack(HEADER_FORMAT, FORMAT_VERSION, 0x01, 0x02, 0x00, 0xBEEF)
        b64 = base64.b64encode(header + b"payload").decode()
        with pytest.raises(ValueError, match="Reserved header bytes must be zero"):
            deserialize(b64)


class TestFormatV3:
    """Tests for v3 format with KDF params and key-check support."""

    def test_v3_roundtrip(self):
        payload = b"some-encrypted-data-here"
        kdf_params = (3, 65536, 4)
        b64 = serialize(0x01, 0x02, 0x00, payload,
                        version=FORMAT_VERSION_3, kdf_params=kdf_params)
        version, cipher_id, kdf_id, flags, out_payload, out_params = deserialize(b64)
        assert version == FORMAT_VERSION_3
        assert cipher_id == 0x01
        assert kdf_id == 0x02
        assert flags == 0x00
        assert out_payload == payload
        assert out_params == kdf_params

    def test_v3_header_size(self):
        assert HEADER_SIZE_V3 == 18

    def test_v3_flags_preserved(self):
        flags = FLAG_CHAINED | FLAG_HYBRID_PQ | FLAG_PADDED
        kdf_params = (1, 1024, 1)
        b64 = serialize(0x01, 0x02, flags, b"data",
                        version=FORMAT_VERSION_3, kdf_params=kdf_params)
        _, _, _, out_flags, _, _ = deserialize(b64)
        assert out_flags == flags

    def test_v3_kdf_params_roundtrip(self):
        """Different KDF params produce different serializations but roundtrip."""
        for params in [(1, 1024, 1), (3, 65536, 4), (131072, 8, 1)]:
            b64 = serialize(0x01, 0x02, 0x00, b"x",
                            version=FORMAT_VERSION_3, kdf_params=params)
            _, _, _, _, _, out_params = deserialize(b64)
            assert out_params == params

    def test_v3_too_short_raises(self):
        """v3 header needs 18 bytes minimum."""
        raw = struct.pack("!BBBBH", FORMAT_VERSION_3, 0x01, 0x02, 0x00, 0)
        # Only 6 bytes + 6 padding = 12 bytes, need 18
        b64 = base64.b64encode(raw + b"\x00" * 6).decode()
        with pytest.raises(ValueError, match="too short for v3"):
            deserialize(b64)

    def test_v3_nonzero_reserved_rejected(self):
        header = struct.pack(HEADER_FORMAT_V3, FORMAT_VERSION_3,
                             0x01, 0x02, 0x00, 0xBEEF, 3, 65536, 4)
        b64 = base64.b64encode(header + b"payload").decode()
        with pytest.raises(ValueError, match="Reserved header bytes must be zero"):
            deserialize(b64)

    def test_v3_aad_includes_kdf_params(self):
        """v3 AAD should be 18 bytes (full header including KDF params)."""
        kdf_params = (3, 65536, 4)
        aad = build_aad(FORMAT_VERSION_3, 0x01, 0x02, 0x00,
                        kdf_params=kdf_params)
        assert len(aad) == HEADER_SIZE_V3

    def test_v3_aad_different_kdf_params(self):
        """Different KDF params produce different AADs."""
        aad1 = build_aad(FORMAT_VERSION_3, 0x01, 0x02, 0x00,
                         kdf_params=(3, 65536, 4))
        aad2 = build_aad(FORMAT_VERSION_3, 0x01, 0x02, 0x00,
                         kdf_params=(1, 1024, 1))
        assert aad1 != aad2

    def test_key_check_size(self):
        assert KEY_CHECK_SIZE == 8

    def test_padded_flag_value(self):
        assert FLAG_PADDED == 0x04

    def test_v3_empty_payload_roundtrip(self):
        kdf_params = (3, 65536, 4)
        b64 = serialize(0x01, 0x02, 0x00, b"",
                        version=FORMAT_VERSION_3, kdf_params=kdf_params)
        _, _, _, _, out_payload, out_params = deserialize(b64)
        assert out_payload == b""
        assert out_params == kdf_params


class TestBuildAAD:
    def test_aad_is_full_header(self):
        aad = build_aad(0x02, 0x01, 0x02, 0x00)
        assert len(aad) == HEADER_SIZE  # Full 6-byte header

    def test_aad_reflects_inputs(self):
        aad1 = build_aad(0x02, 0x01, 0x02, 0x00)
        aad2 = build_aad(0x02, 0x02, 0x02, 0x00)
        assert aad1 != aad2  # Different cipher_id -> different AAD

    def test_aad_flag_binding(self):
        aad_plain = build_aad(0x02, 0x01, 0x02, 0x00)
        aad_chained = build_aad(0x02, 0x01, 0x02, FLAG_CHAINED)
        assert aad_plain != aad_chained

    def test_aad_collision_resistance(self):
        """All 4 input parameters independently affect the output."""
        baseline = build_aad(0x02, 0x01, 0x02, 0x00)
        # Change each parameter independently
        assert build_aad(0x03, 0x01, 0x02, 0x00) != baseline  # version
        assert build_aad(0x02, 0x02, 0x02, 0x00) != baseline  # cipher_id
        assert build_aad(0x02, 0x01, 0x01, 0x00) != baseline  # kdf_id
        assert build_aad(0x02, 0x01, 0x02, 0x01) != baseline  # flags

    def test_aad_all_flags(self):
        """AAD with both flags set is unique."""
        aad_both = build_aad(0x02, 0x01, 0x02, FLAG_CHAINED | FLAG_HYBRID_PQ)
        aad_chain = build_aad(0x02, 0x01, 0x02, FLAG_CHAINED)
        aad_pq = build_aad(0x02, 0x01, 0x02, FLAG_HYBRID_PQ)
        assert aad_both != aad_chain
        assert aad_both != aad_pq
        assert aad_chain != aad_pq
