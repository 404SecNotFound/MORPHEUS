"""
Encryption pipeline — orchestrates cipher, KDF, chaining, and hybrid PQ.

This is the main API surface for encrypt/decrypt operations. It assembles
the versioned ciphertext format, derives keys, and optionally layers
ML-KEM-768 key encapsulation on top of password-based encryption.
"""

from __future__ import annotations

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
    FORMAT_VERSION,
    build_aad,
    deserialize,
    serialize,
)
from .kdf import KDF, KDF_REGISTRY, Argon2idKDF
from .memory import SecureBuffer, secure_zero

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

    def encrypt(self, plaintext: str, password: str) -> str:
        """
        Encrypt a text block. Returns a base64-encoded ciphertext string.
        """
        data = plaintext.encode("utf-8")
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

        aad = build_aad(FORMAT_VERSION, cipher_id, self.kdf.kdf_id, flags)

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
                # Zero the pre-KEM keys and the KEM shared secret
                for k in old_keys:
                    secure_zero(k)
                secure_zero(kem_ss)
                # KEM ciphertext length stored as 2-byte unsigned short (!H).
                # ML-KEM-768 ciphertext is 1088 bytes, well within the 65535 limit.
                # Future KEMs with larger ciphertexts (e.g., Classic McEliece ~200KB)
                # would require a format version bump to use a 4-byte length field (!I).
                if len(kem_ct) > 0xFFFF:
                    raise ValueError(
                        f"KEM ciphertext too large ({len(kem_ct)} bytes); "
                        f"format v2 supports max 65535 bytes"
                    )
                kem_prefix = struct.pack("!H", len(kem_ct)) + kem_ct

            # Encrypt with primary cipher
            nonce1, ct1 = self.cipher.encrypt(keys[0], data, aad)

            if self.chain:
                # Second layer: encrypt the first ciphertext
                nonce2, ct2 = self.chain_cipher.encrypt(keys[1], ct1, aad)
                payload = salt + nonce1 + nonce2 + kem_prefix + ct2
            else:
                payload = salt + nonce1 + kem_prefix + ct1

            return serialize(cipher_id, self.kdf.kdf_id, flags, payload)
        finally:
            # Zero all key material (now actually zeros the mutable bytearrays)
            for k in keys:
                secure_zero(k)
            secure_zero(password_bytes)

    # ------- DECRYPT -------

    def decrypt(self, ciphertext_b64: str, password: str) -> str:
        """
        Decrypt a base64-encoded ciphertext string. Returns plaintext.

        Raises:
            ValueError: on format/version errors or truncated ciphertext
            cryptography.exceptions.InvalidTag: on wrong password or tampering
        """
        version, cipher_id, kdf_id, flags, payload = deserialize(ciphertext_b64)

        is_chained = bool(flags & FLAG_CHAINED)
        is_hybrid = bool(flags & FLAG_HYBRID_PQ)

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

        # Use the pipeline's own KDF (preserves caller-configured parameters).
        # Validate that the header's KDF ID matches.
        if kdf_id != self.kdf.kdf_id:
            raise ValueError(
                f"Ciphertext was created with KDF {kdf_id:#04x}, "
                f"but pipeline is configured with {self.kdf.kdf_id:#04x}"
            )
        kdf = self.kdf

        # Encode password to mutable bytearray at the boundary
        password_bytes = bytearray(password.encode("utf-8"))

        # Parse payload with explicit length validation
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

        ciphertext = payload[offset:]
        if not ciphertext:
            raise ValueError("Truncated ciphertext: no encrypted data after header fields")

        aad = build_aad(version, cipher_id, kdf_id, flags)

        # Derive keys (returns list of bytearray)
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

            if is_chained and secondary:
                # Decrypt outer layer first, then inner
                ct1 = secondary.decrypt(keys[1], nonce2, ciphertext, aad)
                plaintext_bytes = primary.decrypt(keys[0], nonce1, ct1, aad)
            else:
                plaintext_bytes = primary.decrypt(keys[0], nonce1, ciphertext, aad)
        finally:
            # Zero all key material (now actually zeros the mutable bytearrays)
            for k in keys:
                secure_zero(k)
            secure_zero(password_bytes)

        return plaintext_bytes.decode("utf-8")
