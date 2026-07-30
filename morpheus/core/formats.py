"""
Versioned ciphertext binary format.

Supports two format versions:

  Format v2 (0x02) — original format:
    Bytes 0:     version  (0x02)
    Bytes 1:     cipher_id
    Bytes 2:     kdf_id
    Bytes 3:     flags    (bit 0 = chained, bit 1 = hybrid PQ)
    Bytes 4-5:   reserved (0x0000)
    Bytes 6+:    payload  (cipher-specific)

  Format v3 (0x03) — extended format with KDF params and key-check:
    Bytes 0:     version  (0x03)
    Bytes 1:     cipher_id
    Bytes 2:     kdf_id
    Bytes 3:     flags    (bit 0 = chained, bit 1 = hybrid PQ, bit 2 = padded)
    Bytes 4-5:   reserved (0x0000)
    Bytes 6-9:   kdf_param1  (uint32 big-endian: time_cost / n)
    Bytes 10-13: kdf_param2  (uint32 big-endian: memory_cost / r)
    Bytes 14-17: kdf_param3  (uint32 big-endian: parallelism / p)
    Bytes 18+:   payload

  Payload structure is the same for both versions:
    Single cipher:  [salt][nonce][key_check (v3 only, 8B)][ciphertext+tag]
    Chained:        [salt][nonce_aes][nonce_chacha][key_check (v3 only)][ciphertext+tag]
    Hybrid PQ:      [salt][nonce(s)][2B KEM-ct len][KEM ct][key_check (v3 only)][ct+tag]

All outputs are base64-encoded for safe text transport.
"""

from __future__ import annotations

import base64
import struct

from .errors import FormatError

FORMAT_VERSION = 0x02      # Legacy default
FORMAT_VERSION_3 = 0x03    # Extended with KDF params
FORMAT_VERSION_4 = 0x04    # v3 layout, wider commitment, extended AAD

# Single source of truth for what deserialize() accepts. Tests derive their
# "unsupported version" generators from this: an inline list in test_fuzz.py
# silently stopped matching reality when v4 landed, leaving a property test
# asserting something false.
SUPPORTED_VERSIONS = frozenset({FORMAT_VERSION, FORMAT_VERSION_3, FORMAT_VERSION_4})

HEADER_FORMAT = "!BBBBH"   # version, cipher_id, kdf_id, flags, reserved
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 6 bytes

HEADER_FORMAT_V3 = "!BBBBHIII"  # + kdf_param1, kdf_param2, kdf_param3
HEADER_SIZE_V3 = struct.calcsize(HEADER_FORMAT_V3)  # 18 bytes

FLAG_CHAINED = 0x01
FLAG_HYBRID_PQ = 0x02
FLAG_PADDED = 0x04

KEY_CHECK_SIZE = 8  # v2/v3 truncated HMAC-SHA256

# v4 widens this to a full SHA-256 output. The v3 value is 64 bits, which by
# the size relation in Bellare-Hoang (CRYPTO 2024) is about 32 bits of
# *committing* security — enough to distinguish a wrong password, not enough
# to stop someone deliberately constructing one ciphertext that opens to two
# plausible plaintexts under two passwords. See SECURITY.md.
COMMITMENT_SIZE = 32


def build_aad(version: int, cipher_id: int, kdf_id: int, flags: int,
              kdf_params: tuple[int, int, int] | None = None,
              *, salt: bytes = b"", kem_prefix: bytes = b"") -> bytes:
    """Build contextual AAD from the header, and for v4 the bound payload fields.

    v2: the 6-byte header. v3: the full 18-byte header including KDF params.
    Both authenticate every header byte, which is what stops cipher, KDF, flag
    and parameter downgrade.

    v4 additionally covers the salt and the length-prefixed KEM ciphertext.
    Those live in the payload, so under v3 the AEAD tag did not cover them and
    the "every header byte is authenticated" claim, while true, was narrower
    than a reader would assume. Nonces are deliberately absent: an AEAD already
    authenticates its own nonce, and including it here would force the nonce to
    be generated before the cipher call for no gain.

    Each v4 field is length-prefixed so the concatenation is injective; without
    that, a shorter salt and a longer KEM prefix could produce the same bytes.
    """
    if version == FORMAT_VERSION_4:
        if kdf_params is None:
            raise FormatError("v4 AAD requires KDF parameters")
        header = struct.pack(HEADER_FORMAT_V3, version, cipher_id, kdf_id,
                             flags, 0, *kdf_params)
        return (header
                + struct.pack("!H", len(salt)) + salt
                + struct.pack("!H", len(kem_prefix)) + kem_prefix)
    if version == FORMAT_VERSION_3 and kdf_params is not None:
        return struct.pack(HEADER_FORMAT_V3, version, cipher_id, kdf_id,
                           flags, 0, *kdf_params)
    return struct.pack(HEADER_FORMAT, version, cipher_id, kdf_id, flags, 0)


def serialize(cipher_id: int, kdf_id: int, flags: int, payload: bytes,
              *, version: int = FORMAT_VERSION,
              kdf_params: tuple[int, int, int] | None = None) -> str:
    """Pack header + payload and return base64 string."""
    if version in (FORMAT_VERSION_3, FORMAT_VERSION_4) and kdf_params is not None:
        # v4 reuses the v3 18-byte header layout unchanged; only the version
        # byte, the commitment width and the AAD differ. Keeping the header
        # identical means deserialize needs no new parsing branch.
        header = struct.pack(HEADER_FORMAT_V3, version, cipher_id, kdf_id,
                             flags, 0, *kdf_params)
    elif version == FORMAT_VERSION:
        header = struct.pack(HEADER_FORMAT, version, cipher_id,
                             kdf_id, flags, 0)
    else:
        # This branch used to pack the module constant FORMAT_VERSION rather
        # than the `version` argument, so serialize(version=X) silently emitted
        # a v2 header for any X — a caller asking for a format it did not get,
        # with no error. Refusing is correct: the only in-tree caller passing a
        # non-default version is pipeline.py, and a version this function
        # cannot actually write should never reach a file.
        raise FormatError(
            f"cannot serialize format version {version}: v3 requires "
            "kdf_params, and no other version is supported"
        )
    return base64.b64encode(header + payload).decode("utf-8")


def deserialize(b64_data: str) -> tuple[int, int, int, int, bytes,
                                         tuple[int, int, int] | None]:
    """
    Unpack a base64 ciphertext string.

    Returns: (version, cipher_id, kdf_id, flags, payload, kdf_params)
    kdf_params is None for v2, (p1, p2, p3) for v3.
    Raises ValueError on malformed input.
    """
    try:
        raw = base64.b64decode(b64_data, validate=True)
    except Exception as exc:
        raise FormatError("Invalid base64 encoding") from exc

    if len(raw) < HEADER_SIZE:
        raise FormatError(f"Ciphertext too short ({len(raw)} bytes, need >= {HEADER_SIZE})")

    # Peek at version byte to determine format
    version = raw[0]

    if version == FORMAT_VERSION:
        _, cipher_id, kdf_id, flags, reserved = struct.unpack(
            HEADER_FORMAT, raw[:HEADER_SIZE]
        )
        if reserved != 0:
            raise FormatError(
                f"Reserved header bytes must be zero (got {reserved:#06x})"
            )
        return version, cipher_id, kdf_id, flags, raw[HEADER_SIZE:], None

    if version in (FORMAT_VERSION_3, FORMAT_VERSION_4):
        if len(raw) < HEADER_SIZE_V3:
            raise FormatError(
                f"Ciphertext too short for v{version} ({len(raw)} bytes, "
                f"need >= {HEADER_SIZE_V3})"
            )
        _, cipher_id, kdf_id, flags, reserved, p1, p2, p3 = struct.unpack(
            HEADER_FORMAT_V3, raw[:HEADER_SIZE_V3]
        )
        if reserved != 0:
            raise FormatError(
                f"Reserved header bytes must be zero (got {reserved:#06x})"
            )
        return version, cipher_id, kdf_id, flags, raw[HEADER_SIZE_V3:], (p1, p2, p3)

    supported = ", ".join(f"{v:#04x}" for v in sorted(SUPPORTED_VERSIONS))
    raise FormatError(
        f"Unsupported ciphertext version {version:#04x} (supported: {supported})"
    )
