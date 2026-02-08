"""
Encryption pipeline — orchestrates cipher, KDF, chaining, and hybrid PQ.

This is the main API surface for encrypt/decrypt operations. It assembles
the versioned ciphertext format, derives keys, and optionally layers
ML-KEM-768 key encapsulation on top of password-based encryption.

Format v3 (default for new encryptions) stores KDF parameters in the
header and includes a key-check value for better error diagnostics.
Format v2 ciphertexts can still be decrypted for backward compatibility.
"""

from __future__ import annotations

import hmac
import struct
import warnings

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

from .ciphers import (
    AES256GCM,
    CHAINED_CIPHER_ID,
    CIPHER_REGISTRY,
    Cipher,
    ChaCha20Poly1305Cipher,
)
from .formats import (
    FLAG_CHAINED,
    FLAG_HYBRID_PQ,
    FLAG_PADDED,
    FORMAT_VERSION_3,
    KEY_CHECK_SIZE,
    build_aad,
    deserialize,
    serialize,
)
from .kdf import KDF, KDF_REGISTRY, Argon2idKDF
from .memory import secure_zero

# ---------------------------------------------------------------------------
# Post-quantum KEM support (optional dependency)
# ---------------------------------------------------------------------------
PQ_AVAILABLE = False
PQ_BACKEND: str | None = None

try:
    from pqcrypto.kem import ml_kem_768 as _ml_kem  # type: ignore[import-untyped]

    PQ_AVAILABLE = True
    PQ_BACKEND = "pqcrypto"
except ImportError:
    _ml_kem = None  # type: ignore[assignment]


def pq_generate_keypair() -> tuple[bytes, bytes]:
    """Generate an ML-KEM-768 keypair. Returns (public_key, secret_key)."""
    if not PQ_AVAILABLE:
        raise RuntimeError("Post-quantum libraries not installed. pip install pqcrypto")
    return _ml_kem.generate_keypair()


def _pq_encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """KEM encapsulate: returns (ciphertext, shared_secret)."""
    return _ml_kem.encrypt(public_key)


def _pq_decapsulate(secret_key: bytes, kem_ciphertext: bytes) -> bytes:
    """KEM decapsulate: returns shared_secret."""
    return _ml_kem.decrypt(secret_key, kem_ciphertext)


# ---------------------------------------------------------------------------
# Key derivation helpers
# ---------------------------------------------------------------------------

def _derive_keys(
    kdf: KDF,
    password_bytes: bytearray,
    salt: bytes,
    num_keys: int = 1,
) -> list[bytearray]:
    """
    Derive one or more 32-byte keys from a password.

    For a single cipher, returns [key] as bytearray.
    For chained ciphers, returns [key_cipher1, key_cipher2] using HKDF-Expand.
    All returned keys are mutable bytearrays that can be zeroed by the caller.
    """
    master = kdf.derive(password_bytes, salt, key_length=32)  # returns bytearray

    if num_keys == 1:
        return [master]

    keys: list[bytearray] = []
    for i in range(num_keys):
        # Domain-separate each subkey by binding application context and salt
        info = f"morpheus-v2-key-{i}".encode() + salt
        expanded = HKDFExpand(
            algorithm=SHA256(),
            length=32,
            info=info,
        ).derive(bytes(master))
        keys.append(bytearray(expanded))

    # Zero the master key (now actually zeros the original bytearray)
    secure_zero(master)

    return keys


def _combine_with_kem(password_key: bytes | bytearray, kem_shared_secret: bytes, salt: bytes) -> bytearray:
    """Combine a password-derived key with a KEM shared secret via HKDF.

    Uses a mutable bytearray for the concatenated intermediate to enable
    zeroing after derivation. Returns a mutable bytearray.
    """
    combined = bytearray(bytes(password_key) + kem_shared_secret)
    try:
        result = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=salt,
            info=b"hybrid-pq-v1",
        ).derive(bytes(combined))
        return bytearray(result)
    finally:
        secure_zero(combined)


def _compute_key_check(key: bytes | bytearray) -> bytes:
    """Compute a truncated HMAC for key verification.

    Returns KEY_CHECK_SIZE bytes. This allows distinguishing "wrong password"
    from "wrong KDF params" or "corrupted data" without weakening security —
    HMAC-SHA256 is a PRF, so revealing 8 bytes is safe.
    """
    return hmac.new(bytes(key), b"morpheus-key-check", "sha256").digest()[:KEY_CHECK_SIZE]


def _pad_plaintext(data: bytes, block_size: int = 256) -> bytes:
    """Pad data to a multiple of block_size using PKCS7-style padding.

    Always adds at least 1 byte of padding so the pad length is unambiguous.
    """
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _unpad_plaintext(data: bytes) -> bytes:
    """Remove PKCS7-style padding. Raises ValueError on invalid padding."""
    if not data:
        raise ValueError("Cannot unpad empty data")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > len(data):
        raise ValueError("Invalid padding length")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]


def _get_kdf_params(kdf: KDF) -> tuple[int, int, int]:
    """Extract the 3 tuning parameters from a KDF instance."""
    if hasattr(kdf, "time_cost"):
        return (kdf.time_cost, kdf.memory_cost, kdf.parallelism)
    if hasattr(kdf, "n"):
        return (kdf.n, kdf.r, kdf.p)
    return (0, 0, 0)


def _build_kdf_from_params(kdf_id: int, params: tuple[int, int, int]) -> KDF:
    """Reconstruct a KDF instance from header params."""
    kdf_cls = KDF_REGISTRY.get(kdf_id)
    if not kdf_cls:
        raise ValueError(f"Unknown KDF ID {kdf_id:#04x}")

    p1, p2, p3 = params
    if kdf_id == 0x02:  # Argon2id
        return kdf_cls(time_cost=p1, memory_cost=p2, parallelism=p3)
    if kdf_id == 0x01:  # Scrypt
        return kdf_cls(n=p1, r=p2, p=p3)
    return kdf_cls()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class EncryptionPipeline:
    """
    High-level encrypt/decrypt with configurable cipher, KDF, chaining, and PQ.

    Parameters:
        cipher: Primary cipher (AES256GCM or ChaCha20Poly1305Cipher)
        kdf: Key derivation function (Argon2idKDF or ScryptKDF)
        chain: If True, chain primary cipher with ChaCha20-Poly1305 (or AES
               if primary is ChaCha). Provides defense-in-depth.
        hybrid_pq: If True, layer ML-KEM-768 key encapsulation on top.
        pq_public_key: Recipient's ML-KEM-768 public key (required for
                       hybrid_pq encrypt).
        pq_secret_key: Own ML-KEM-768 secret key (required for hybrid_pq
                       decrypt).
    """

    def __init__(
        self,
        cipher: Cipher | None = None,
        kdf: KDF | None = None,
        chain: bool = False,
        hybrid_pq: bool = False,
        pq_public_key: bytes | None = None,
        pq_secret_key: bytes | None = None,
    ):
        self.cipher = cipher or AES256GCM()
        self.kdf = kdf or Argon2idKDF()
        self.chain = chain
        self.hybrid_pq = hybrid_pq
        self.pq_public_key = pq_public_key
        self.pq_secret_key = pq_secret_key

        # Chaining always uses AES-256-GCM (primary) → ChaCha20-Poly1305 (secondary).
        # This fixed order avoids ambiguity in the ciphertext format.
        if self.chain:
            if cipher is not None and not isinstance(cipher, AES256GCM):
                warnings.warn(
                    f"Cipher chaining uses a fixed order (AES-256-GCM → ChaCha20-Poly1305); "
                    f"the selected cipher '{cipher.name}' is overridden when chain=True.",
                    stacklevel=2,
                )
            self.cipher = AES256GCM()
            self.chain_cipher: Cipher = ChaCha20Poly1305Cipher()
        else:
            self.chain_cipher = None  # type: ignore[assignment]

    @property
    def description(self) -> str:
        """Human-readable description of the current pipeline configuration."""
        parts = [self.cipher.name]
        if self.chain:
            parts.append(f"+ {self.chain_cipher.name}")
        parts.append(f"| {self.kdf.name}")
        if self.hybrid_pq:
            parts.append("| ML-KEM-768")
        return " ".join(parts)

    # ------- ENCRYPT -------

    def encrypt(self, plaintext: str, password: str, *, pad: bool = False) -> str:
        """
        Encrypt a text block. Returns a base64-encoded ciphertext string.

        Uses format v3 by default (stores KDF params, includes key-check).
        Set pad=True to hide exact plaintext length.
        """
        data = plaintext.encode("utf-8")

        if pad:
            data = _pad_plaintext(data)

        salt = self.kdf.generate_salt()

        # Encode password to mutable bytearray at the boundary, then zero after use
        password_bytes = bytearray(password.encode("utf-8"))

        # Determine flags and cipher_id
        flags = 0
        if self.chain:
            flags |= FLAG_CHAINED
            cipher_id = CHAINED_CIPHER_ID
        else:
            cipher_id = self.cipher.cipher_id

        if self.hybrid_pq:
            flags |= FLAG_HYBRID_PQ

        if pad:
            flags |= FLAG_PADDED

        kdf_params = _get_kdf_params(self.kdf)
        version = FORMAT_VERSION_3

        aad = build_aad(version, cipher_id, self.kdf.kdf_id, flags,
                        kdf_params=kdf_params)

        keys: list[bytearray] = []
        try:
            # Key derivation (returns list of bytearray)
            num_keys = 2 if self.chain else 1
            keys = _derive_keys(self.kdf, password_bytes, salt, num_keys)

            # Hybrid PQ layer
            kem_prefix = b""
            kem_ss: bytearray | None = None
            if self.hybrid_pq:
                if not self.pq_public_key:
                    raise ValueError("Hybrid PQ requires a public key for encryption")
                kem_ct, raw_ss = _pq_encapsulate(self.pq_public_key)
                kem_ss = bytearray(raw_ss)
                old_keys = keys
                keys = [_combine_with_kem(k, kem_ss, salt) for k in keys]
                for k in old_keys:
                    secure_zero(k)
                secure_zero(kem_ss)
                if len(kem_ct) > 0xFFFF:
                    raise ValueError(
                        f"KEM ciphertext too large ({len(kem_ct)} bytes); "
                        f"format supports max 65535 bytes"
                    )
                kem_prefix = struct.pack("!H", len(kem_ct)) + kem_ct

            # Key-check value: allows distinguishing wrong password from
            # wrong KDF params without weakening security
            key_check = _compute_key_check(keys[0])

            # Encrypt with primary cipher
            nonce1, ct1 = self.cipher.encrypt(keys[0], data, aad)

            if self.chain:
                nonce2, ct2 = self.chain_cipher.encrypt(keys[1], ct1, aad)
                payload = salt + nonce1 + nonce2 + kem_prefix + key_check + ct2
            else:
                payload = salt + nonce1 + kem_prefix + key_check + ct1

            return serialize(cipher_id, self.kdf.kdf_id, flags, payload,
                             version=version, kdf_params=kdf_params)
        finally:
            for k in keys:
                secure_zero(k)
            secure_zero(password_bytes)

    # ------- DECRYPT -------

    def decrypt(self, ciphertext_b64: str, password: str) -> str:
        """
        Decrypt a base64-encoded ciphertext string. Returns plaintext.

        Supports both v2 (legacy) and v3 (extended) formats.

        Raises:
            ValueError: on format/version errors, truncated ciphertext, or
                        key verification failure (v3 only — clear error message)
            cryptography.exceptions.InvalidTag: on wrong password (v2) or tampering
        """
        version, cipher_id, kdf_id, flags, payload, kdf_params = deserialize(ciphertext_b64)

        is_chained = bool(flags & FLAG_CHAINED)
        is_hybrid = bool(flags & FLAG_HYBRID_PQ)
        is_padded = bool(flags & FLAG_PADDED)
        is_v3 = version == FORMAT_VERSION_3

        # Resolve cipher(s)
        if is_chained:
            primary = AES256GCM()
            secondary: Cipher | None = ChaCha20Poly1305Cipher()
        else:
            cipher_cls = CIPHER_REGISTRY.get(cipher_id)
            if not cipher_cls:
                raise ValueError(f"Unknown cipher ID {cipher_id:#04x}")
            primary = cipher_cls()
            secondary = None

        # Resolve KDF
        if is_v3 and kdf_params is not None:
            kdf = _build_kdf_from_params(kdf_id, kdf_params)
        else:
            if kdf_id != self.kdf.kdf_id:
                raise ValueError(
                    f"Ciphertext was created with KDF {kdf_id:#04x}, "
                    f"but pipeline is configured with {self.kdf.kdf_id:#04x}"
                )
            kdf = self.kdf

        password_bytes = bytearray(password.encode("utf-8"))

        payload_len = len(payload)
        offset = 0

        min_required = kdf.salt_size + primary.nonce_size
        if is_chained and secondary:
            min_required += secondary.nonce_size
        if payload_len < min_required:
            raise ValueError(
                f"Truncated ciphertext: need at least {min_required} bytes, got {payload_len}"
            )

        salt = payload[offset : offset + kdf.salt_size]
        offset += kdf.salt_size

        nonce1 = payload[offset : offset + primary.nonce_size]
        offset += primary.nonce_size

        if is_chained and secondary:
            nonce2 = payload[offset : offset + secondary.nonce_size]
            offset += secondary.nonce_size
        else:
            nonce2 = b""

        # KEM ciphertext if hybrid
        kem_ss: bytearray | None = None
        if is_hybrid:
            if not self.pq_secret_key:
                raise ValueError("Hybrid PQ ciphertext requires a secret key for decryption")
            if payload_len < offset + 2:
                raise ValueError("Truncated ciphertext: missing KEM length field")
            kem_ct_len = struct.unpack("!H", payload[offset : offset + 2])[0]
            offset += 2
            if kem_ct_len == 0:
                raise ValueError(
                    "Invalid hybrid PQ ciphertext: KEM ciphertext length is zero"
                )
            if payload_len < offset + kem_ct_len:
                raise ValueError(
                    f"Truncated ciphertext: KEM ciphertext claims {kem_ct_len} bytes "
                    f"but only {payload_len - offset} remain"
                )
            kem_ct = payload[offset : offset + kem_ct_len]
            offset += kem_ct_len
            kem_ss = bytearray(_pq_decapsulate(self.pq_secret_key, kem_ct))

        # Key-check value (v3 only)
        stored_key_check: bytes | None = None
        if is_v3:
            if payload_len < offset + KEY_CHECK_SIZE:
                raise ValueError("Truncated ciphertext: missing key-check value")
            stored_key_check = payload[offset : offset + KEY_CHECK_SIZE]
            offset += KEY_CHECK_SIZE

        ciphertext = payload[offset:]
        if not ciphertext:
            raise ValueError("Truncated ciphertext: no encrypted data after header fields")

        aad = build_aad(version, cipher_id, kdf_id, flags, kdf_params=kdf_params)

        keys: list[bytearray] = []
        try:
            num_keys = 2 if is_chained else 1
            keys = _derive_keys(kdf, password_bytes, salt, num_keys)

            if is_hybrid and kem_ss is not None:
                old_keys = keys
                keys = [_combine_with_kem(k, kem_ss, salt) for k in keys]
                for k in old_keys:
                    secure_zero(k)
                secure_zero(kem_ss)

            # Verify key-check (v3) — clear error before AEAD attempt
            if stored_key_check is not None:
                computed = _compute_key_check(keys[0])
                if not hmac.compare_digest(stored_key_check, computed):
                    raise ValueError("Key verification failed: incorrect password")

            if is_chained and secondary:
                ct1 = secondary.decrypt(keys[1], nonce2, ciphertext, aad)
                plaintext_bytes = primary.decrypt(keys[0], nonce1, ct1, aad)
            else:
                plaintext_bytes = primary.decrypt(keys[0], nonce1, ciphertext, aad)
        finally:
            for k in keys:
                secure_zero(k)
            secure_zero(password_bytes)

        if is_padded:
            plaintext_bytes = _unpad_plaintext(plaintext_bytes)

        return plaintext_bytes.decode("utf-8")
