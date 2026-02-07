"""
Versioned ciphertext binary format.

Layout (version 2):
  Bytes 0:     version  (0x02)
  Bytes 1:     cipher_id
  Bytes 2:     kdf_id
  Bytes 3:     flags    (bit 0 = chained, bit 1 = hybrid PQ)
  Bytes 4-5:   reserved (0x0000)
  Bytes 6+:    payload  (cipher-specific)

Payload for single cipher:
  [salt][nonce][ciphertext+tag]

Payload for chained (AES -> ChaCha):
  [salt][nonce_aes][nonce_chacha][ciphertext+tag]

When hybrid PQ flag is set, the payload is prefixed with:
  [2-byte KEM ciphertext length][KEM ciphertext]
  followed by the standard cipher payload.

All outputs are base64-encoded for safe text transport.
"""

from __future__ import annotations

import base64
import struct

FORMAT_VERSION = 0x02
HEADER_FORMAT = "!BBBBH"  # version, cipher_id, kdf_id, flags, reserved
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 6 bytes

FLAG_CHAINED = 0x01
FLAG_HYBRID_PQ = 0x02


def build_aad(version: int, cipher_id: int, kdf_id: int, flags: int) -> bytes:
    """Build contextual AAD from header fields — binds cipher choice to ciphertext."""
    return struct.pack("!BBBB", version, cipher_id, kdf_id, flags)


def serialize(cipher_id: int, kdf_id: int, flags: int, payload: bytes) -> str:
    """Pack header + payload and return base64 string."""
    header = struct.pack(HEADER_FORMAT, FORMAT_VERSION, cipher_id, kdf_id, flags, 0)
    return base64.b64encode(header + payload).decode("utf-8")


def deserialize(b64_data: str) -> tuple[int, int, int, int, bytes]:
    """
    Unpack a base64 ciphertext string.

    Returns: (version, cipher_id, kdf_id, flags, payload)
    Raises ValueError on malformed input.
    """
    try:
        raw = base64.b64decode(b64_data, validate=True)
    except Exception as exc:
        raise ValueError("Invalid base64 encoding") from exc

    if len(raw) < HEADER_SIZE:
        raise ValueError(f"Ciphertext too short ({len(raw)} bytes, need >= {HEADER_SIZE})")

    version, cipher_id, kdf_id, flags, _reserved = struct.unpack(
        HEADER_FORMAT, raw[:HEADER_SIZE]
    )

    if version != FORMAT_VERSION:
        raise ValueError(
            f"Unsupported ciphertext version {version:#04x} (expected {FORMAT_VERSION:#04x})"
        )

    return version, cipher_id, kdf_id, flags, raw[HEADER_SIZE:]
