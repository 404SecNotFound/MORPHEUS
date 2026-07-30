"""
Encryption pipeline — orchestrates cipher, KDF, chaining, and hybrid PQ.

This is the main API surface for encrypt/decrypt operations. It assembles
the versioned ciphertext format, derives keys, and optionally layers
ML-KEM-768 key encapsulation on top of password-based encryption.

Format v4 is the default for new encryptions. It keeps v3's 18-byte header
and KDF parameters, and adds three things:

  - a full 32-byte key commitment in place of v3's 8-byte truncated check,
    computed over the key, nonces, AAD and KEM prefix (CTX-shaped, without
    binding the AEAD tag so wrong-password stays distinguishable from
    tampering)
  - AAD extended over the salt and the length-prefixed KEM ciphertext, which
    in v3 sat in the payload outside the tag
  - a hybrid combiner that binds the KEM ciphertext, the encapsulation key
    and the AAD, per NIST SP 800-227 section 4.6.3

v2 and v3 ciphertexts still decrypt. Their derivation is frozen: the v3 HKDF
subkey label and 8-byte check must never change, or archived ciphertexts stop
opening. tests/vectors/ holds stored ciphertexts for both versions and is the
only thing that catches such a change.
"""

from __future__ import annotations

import hashlib
import hmac
import struct

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

from .ciphers import (
    AES256GCM,
    CHAINED_CIPHER_ID,
    CIPHER_REGISTRY,
    ChaCha20Poly1305Cipher,
    Cipher,
)
from .errors import (
    ConfigurationError,
    DecryptionError,
    KDFParameterError,
    PaddingError,
    WrongPasswordError,
)
from .formats import (
    COMMITMENT_SIZE,
    FLAG_CHAINED,
    FLAG_HYBRID_PQ,
    FLAG_PADDED,
    FORMAT_VERSION_3,
    FORMAT_VERSION_4,
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


# ML-KEM-768 structural constants (FIPS 203, k = 3).
_MLKEM_Q = 3329
_MLKEM_EK_POLY_BYTES = 1152      # 384k — the encoded polynomial vector in ek
_MLKEM_EK_BYTES = 1184           # 384k + 32
_MLKEM_DK_BYTES = 2400           # 768k + 96
_MLKEM_DK_EK_START = 1152        # dk embeds ek at [384k : 768k+32]
_MLKEM_DK_EK_END = 2336
_MLKEM_DK_HASH_END = 2368        # H(ek) lives at [768k+32 : 768k+64]


def _check_encapsulation_key(ek: bytes) -> None:
    """FIPS 203 Section 7.2: type check and modulus check on an encapsulation key.

    The standard says implementers *shall* check these before running Encaps,
    and nothing in the stack below us does: pqcrypto validates only type and
    length, so a key whose coefficients exceed q is accepted and produces a
    normal-looking ciphertext.

    The modulus check is specified as
    ``ByteEncode12(ByteDecode12(ek)) == ek``, which detects exactly the
    coefficients in [q, 4095] — ByteDecode12 reduces mod q, so re-encoding
    differs precisely when a 12-bit value was out of range. Testing each
    coefficient directly is equivalent and clearer.

    This authenticates nothing: an attacker substituting a recipient's public
    key substitutes a *valid* one. The value is diagnostics — a corrupted key
    file says so instead of surfacing as "incorrect password" much later — and
    conformance with a standard this project names in its own documentation.
    """
    if len(ek) != _MLKEM_EK_BYTES:
        raise ConfigurationError(
            f"ML-KEM-768 public key must be {_MLKEM_EK_BYTES} bytes, got {len(ek)}"
        )
    body = ek[:_MLKEM_EK_POLY_BYTES]
    for i in range(0, len(body), 3):
        b0, b1, b2 = body[i], body[i + 1], body[i + 2]
        if (b0 | ((b1 & 0x0F) << 8)) >= _MLKEM_Q or ((b1 >> 4) | (b2 << 4)) >= _MLKEM_Q:
            raise ConfigurationError(
                "ML-KEM-768 public key failed the FIPS 203 modulus check: it "
                "encodes a coefficient outside [0, 3328]. The key file is "
                "corrupt or is not an ML-KEM-768 public key."
            )


def _check_decapsulation_key(dk: bytes) -> None:
    """FIPS 203 Section 7.3: type check and hash check on a decapsulation key.

    dk embeds its own ek and a hash of it. Verifying that pairing catches a
    corrupted key file, which otherwise decapsulates to a wrong-but-valid
    shared secret and is reported to the user as a wrong password.
    """
    if len(dk) != _MLKEM_DK_BYTES:
        raise ConfigurationError(
            f"ML-KEM-768 secret key must be {_MLKEM_DK_BYTES} bytes, got {len(dk)}"
        )
    embedded_ek = dk[_MLKEM_DK_EK_START:_MLKEM_DK_EK_END]
    expected = dk[_MLKEM_DK_EK_END:_MLKEM_DK_HASH_END]
    if hashlib.sha3_256(embedded_ek).digest() != expected:
        raise ConfigurationError(
            "ML-KEM-768 secret key failed the FIPS 203 hash check: the "
            "embedded public key does not match its stored digest. The key "
            "file is corrupt."
        )


def _pq_encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """KEM encapsulate: returns (ciphertext, shared_secret)."""
    if not PQ_AVAILABLE:
        raise RuntimeError("Post-quantum libraries not installed. pip install pqcrypto")
    _check_encapsulation_key(public_key)
    return _ml_kem.encrypt(public_key)


def _pq_decapsulate(secret_key: bytes, kem_ciphertext: bytes) -> bytes:
    """KEM decapsulate: returns shared_secret.

    Raises DecryptionError if the ciphertext is malformed. Note that a
    well-formed ciphertext under the *wrong* secret key does not raise here:
    ML-KEM's Fujisaki-Okamoto transform uses implicit rejection, returning an
    unpredictable shared secret rather than failing. That surfaces one layer
    up as a key-check or AEAD failure instead.
    """
    if not PQ_AVAILABLE:
        raise RuntimeError("Post-quantum libraries not installed. pip install pqcrypto")
    _check_decapsulation_key(secret_key)
    try:
        return _ml_kem.decrypt(secret_key, kem_ciphertext)
    except Exception as exc:
        # Deliberately does not mention a wrong secret key: implicit rejection
        # means a well-formed wrong key never reaches here, and saying so would
        # invite the reader to distinguish two cases the code cannot.
        raise DecryptionError(
            "PQ decapsulation failed: malformed KEM ciphertext"
        ) from exc


# ---------------------------------------------------------------------------
# Key derivation helpers
# ---------------------------------------------------------------------------

def _derive_keys(
    kdf: KDF,
    password_bytes: bytearray,
    salt: bytes,
    num_keys: int = 1,
    version: int = FORMAT_VERSION_3,
) -> list[bytearray]:
    """
    Derive one or more 32-byte keys from a password.

    For a single cipher, returns [key] as bytearray.
    For chained ciphers, returns [key_cipher1, key_cipher2] using HKDF-Expand.
    All returned keys are mutable bytearrays that can be zeroed by the caller.

    The HKDF label is version-gated and must stay that way. v2 and v3
    ciphertexts were written with the literal string "morpheus-v2-key-N", and
    that string is now part of their wire format whether or not it was intended
    to be: changing it for existing versions makes every archived chained
    ciphertext undecryptable, with every test still passing. v4 uses its own
    label. tests/vectors/ is what catches a mistake here.
    """
    master = kdf.derive(password_bytes, salt, key_length=32)  # returns bytearray

    if num_keys == 1:
        return [master]

    label = "morpheus-v4-key-" if version == FORMAT_VERSION_4 else "morpheus-v2-key-"
    keys: list[bytearray] = []
    for i in range(num_keys):
        # Domain-separate each subkey by binding application context and salt
        info = f"{label}{i}".encode() + salt
        expanded = HKDFExpand(
            algorithm=SHA256(),
            length=32,
            info=info,
        ).derive(bytes(master))
        keys.append(bytearray(expanded))

    # Zero the master key (now actually zeros the original bytearray)
    secure_zero(master)

    return keys


def _lp(data: bytes) -> bytes:
    """Length-prefix a field so a concatenation of fields is injective."""
    if len(data) > 0xFFFF:
        raise ConfigurationError(f"field too long to length-prefix ({len(data)} bytes)")
    return struct.pack("!H", len(data)) + data


def _combine_with_kem(
    password_key: bytes | bytearray,
    kem_shared_secret: bytes,
    salt: bytes,
    *,
    version: int = FORMAT_VERSION_3,
    kem_ciphertext: bytes = b"",
    encapsulation_key: bytes = b"",
    aad: bytes = b"",
) -> bytearray:
    """Combine a password-derived key with a KEM shared secret via HKDF.

    v3 derived from the two secrets alone. NIST SP 800-227 (final, September
    2025) section 4.6.3 states that the combiner K <- KDF(K1, K2), using only
    the shared secrets, "does not preserve IND-CCA security, regardless of the
    properties of the KDF", and recommends binding both ciphertexts and both
    encapsulation keys plus a domain separator. X-Wing (Barbosa et al., IACR
    CiC 1(1) 2024) and Giacon-Heuer-Poettering (PKC 2018) are the underlying
    results; Alagic-Bajaj-Kocoglu (ePrint 2025/1444) state the general rule.

    v4 therefore binds the KEM ciphertext, the encapsulation key and the AAD
    into `info`. There is no live attack on the v3 form here — this tool is
    offline with no decapsulation oracle, and the KEM ciphertext is already
    bound indirectly because mutating it yields a different shared secret. The
    reason to change is that a tool published as a quantum-resistance tool
    should not ship the construction the current NIST recommendation prints as
    its negative example, and this is the last moment the format change is free.

    The encapsulation key costs zero wire bytes: for ML-KEM-768 it is embedded
    in the decapsulation key at dk[1152:2336], so the decryptor recovers it
    locally.

    Deliberately keeps HKDF rather than adopting a split-key-PRF core
    (HMAC(pw,ctx) XOR HMAC(ss,ctx)). The SP 800-227 gap closes by including the
    ciphertext and encapsulation key, not by changing the core function, and an
    XOR-shaped combiner reads as a downgrade to a non-expert reader.
    """
    if version == FORMAT_VERSION_4:
        info = (b"morpheus-hybrid-v4"
                + _lp(kem_ciphertext) + _lp(encapsulation_key) + _lp(aad))
    else:
        info = b"hybrid-pq-v1"

    combined = bytearray(bytes(password_key) + kem_shared_secret)
    try:
        result = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=salt,
            info=info,
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


def _compute_commitment(
    key: bytes | bytearray,
    *,
    nonce1: bytes,
    nonce2: bytes = b"",
    aad: bytes = b"",
    kem_prefix: bytes = b"",
) -> bytes:
    """v4 key commitment: a full 32-byte hash over the key and its context.

    Replaces the 8-byte truncated HMAC for v4. Neither AES-GCM nor
    ChaCha20-Poly1305 is a committing AEAD, and efficient key multi-collision
    attacks against both are published (Len, Grubbs, Ristenpart, USENIX
    Security 2021; the file-shaping half in Albertini et al., USENIX Security
    2022). RFC 9771 section 4.3.3 names password-based encryption as an
    application that needs key commitment. By the size relation in Bellare and
    Hoang (CRYPTO 2024), s bits of committing security needs 2s bits of
    expansion, so v3's 64 bits gave roughly 32 — enough to detect a wrong
    password, not enough to stop a deliberately constructed collision.

    Shape follows CTX (Chan and Rogaway, ESORICS 2022): hash the key together
    with the full context, every field length-prefixed and the whole thing
    domain-separated. Unlike CTX this does *not* bind the outer AEAD tag. Every
    input here is known before the cipher runs, which keeps the check ahead of
    AEAD decryption and preserves the wrong-password versus tampered-data
    distinction that SECURITY.md documents as deliberate. Binding the tag would
    collapse both into one message. Committing to the key at 128 bits already
    removes the practical multi-collision attack.

    Chained mode commits to both nonces and, unlike v3, to the KEM ciphertext.
    """
    return hashlib.sha256(
        b"morpheus-cmt-v4"
        + _lp(bytes(key)) + _lp(nonce1) + _lp(nonce2)
        + _lp(aad) + _lp(kem_prefix)
    ).digest()


# Padding buckets: data is padded to the next bucket boundary.
# This provides stronger length-hiding than fixed small blocks by
# quantizing lengths into a few discrete sizes.
_PAD_BUCKETS = (256, 1024, 4096, 16384, 65536)

# Fixed-size target: all ciphertexts padded to this size for maximum privacy.
_PAD_FIXED_SIZE = _PAD_BUCKETS[-1]  # 64 KiB


def _pad_plaintext(data: bytes, *, fixed_size: bool = False) -> bytes:
    """Pad data to the next size bucket to hide plaintext length.

    Buckets: 256B, 1K, 4K, 16K, 64K.  Data larger than 64K is padded
    to the next 64K boundary.  Always adds at least 1 byte of padding.

    If fixed_size=True, always pads to _PAD_FIXED_SIZE (64 KiB) regardless
    of input length.  Inputs larger than 64 KiB minus 4 bytes (length prefix
    overhead) are rejected — use bucket mode for large data.

    Two-layer scheme:
      - pad_len <= 255 -> PKCS7: append *pad_len* copies of the byte *pad_len*.
      - pad_len >  255 -> Length-prefix: prepend 4-byte big-endian original
        length, then zero-fill to target size.

    Correctness invariant (decoder mode switch):
        The unpadder inspects the **last byte** of the padded buffer:
          * 0x00  -> length-prefix mode
          * 1-255 -> PKCS7 mode

        This is unambiguous because:
          (a) In length-prefix mode, all fill bytes are 0x00, so the last
              byte is always 0x00.
          (b) In PKCS7 mode, pad_len is in [1, 255] and every pad byte
              equals pad_len, so the last byte is never 0x00.
        Therefore the two modes can never be confused by the decoder.
    """
    data_len = len(data)

    if fixed_size:
        max_payload = _PAD_FIXED_SIZE - 4  # 4-byte length prefix
        if data_len > max_payload:
            raise PaddingError(
                f"Data too large for --fixed-size ({data_len} bytes, "
                f"max {max_payload}). Use --pad instead."
            )
        target = _PAD_FIXED_SIZE
    else:
        target = _PAD_BUCKETS[-1]  # default: largest bucket
        for bucket in _PAD_BUCKETS:
            if data_len < bucket:
                target = bucket
                break
        else:
            # Larger than biggest bucket — pad to next multiple of largest
            target = ((data_len // _PAD_BUCKETS[-1]) + 1) * _PAD_BUCKETS[-1]

    pad_len = target - data_len
    if pad_len == 0:
        pad_len = _PAD_BUCKETS[0]  # Always add at least one block
        target += pad_len

    # PKCS7 supports pad_len up to 255; for larger targets use a two-layer scheme
    if pad_len > 255:
        # Prepend a 4-byte big-endian original length, then zero-fill
        length_prefix = struct.pack("!I", data_len)
        return length_prefix + data + b"\x00" * (target - data_len - 4)

    return data + bytes([pad_len] * pad_len)


def _unpad_plaintext(data: bytes) -> bytes:
    """Remove padding. Handles both PKCS7 (small pad) and length-prefixed (large pad).

    Raises ValueError on invalid padding.
    """
    if not data:
        raise PaddingError("Cannot unpad empty data")

    pad_byte = data[-1]
    if pad_byte == 0:
        # Length-prefixed scheme: first 4 bytes are big-endian original length
        if len(data) < 4:
            raise PaddingError("Invalid padded data: too short for length prefix")
        original_len = struct.unpack("!I", data[:4])[0]
        if original_len > len(data) - 4:
            raise PaddingError(
                f"Invalid padding: claimed length {original_len} "
                f"exceeds available data {len(data) - 4}"
            )
        return data[4 : 4 + original_len]

    # PKCS7-style: last byte is pad length
    pad_len = pad_byte
    if pad_len > len(data):
        raise PaddingError("Invalid padding length")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise PaddingError("Invalid padding bytes")
    return data[:-pad_len]


def _get_kdf_params(kdf: KDF) -> tuple[int, int, int]:
    """Extract the 3 tuning parameters from a KDF instance."""
    if hasattr(kdf, "time_cost"):
        return (kdf.time_cost, kdf.memory_cost, kdf.parallelism)
    if hasattr(kdf, "n"):
        return (kdf.n, kdf.r, kdf.p)
    return (0, 0, 0)


# KDF parameter limits to prevent resource exhaustion from malformed headers.
#
# The v3 header is consumed *before* the AEAD tag can be verified, so an
# attacker picks these values and the victim allocates on them with no
# password required. Bounds are therefore enforced twice: once per parameter,
# and once on the memory the combination implies. Per-parameter bounds alone
# are not sufficient, because Scrypt's cost is a product.
_MAX_KDF_WORKING_SET = 1 << 30  # 1 GiB; generous for any legitimate header

_ARGON2_LIMITS = {
    "time_cost": (1, 100),           # iterations
    "memory_cost": (1024, 1048576),  # 1 MiB to 1 GiB, expressed in KiB
    "parallelism": (1, 64),
}
_SCRYPT_LIMITS = {
    # Scrypt allocates 128 * n * r, so this ceiling on n only bounds memory
    # at r == 1. The working-set check is what actually bounds the product.
    "n": (2**10, 2**23),
    "r": (1, 64),
    "p": (1, 64),
}


def _build_kdf_from_params(kdf_id: int, params: tuple[int, int, int]) -> KDF:
    """Reconstruct a KDF instance from header params.

    Validates parameter bounds to prevent resource exhaustion from
    malformed or adversarial ciphertext headers.
    """
    kdf_cls = KDF_REGISTRY.get(kdf_id)
    if not kdf_cls:
        raise KDFParameterError(f"Unknown KDF ID {kdf_id:#04x}")

    p1, p2, p3 = params
    if kdf_id == 0x02:  # Argon2id
        _validate_param("Argon2id time_cost", p1, *_ARGON2_LIMITS["time_cost"])
        _validate_param("Argon2id memory_cost", p2, *_ARGON2_LIMITS["memory_cost"])
        _validate_param("Argon2id parallelism", p3, *_ARGON2_LIMITS["parallelism"])
        # memory_cost is in KiB and parallelism does not multiply it.
        _reject_excessive_working_set("Argon2id", p2 * 1024)
        return kdf_cls(time_cost=p1, memory_cost=p2, parallelism=p3)
    if kdf_id == 0x01:  # Scrypt
        _validate_param("Scrypt n", p1, *_SCRYPT_LIMITS["n"])
        _validate_param("Scrypt r", p2, *_SCRYPT_LIMITS["r"])
        _validate_param("Scrypt p", p3, *_SCRYPT_LIMITS["p"])
        # Scrypt's large buffer is 128 * n * r, plus 128 * r * p for the
        # parallel blocks. Neither n nor r bounds this on its own.
        _reject_excessive_working_set("Scrypt", 128 * p2 * (p1 + p3))
        return kdf_cls(n=p1, r=p2, p=p3)
    return kdf_cls()


def _reject_excessive_working_set(name: str, nbytes: int) -> None:
    """Raise KDFParameterError if the implied allocation exceeds the cap.

    Catches parameter combinations that are individually in range but whose
    product is not, which is the only bound that matters for Scrypt.
    """
    if nbytes > _MAX_KDF_WORKING_SET:
        gib = 1 << 30
        raise KDFParameterError(
            f"{name} parameters imply a {nbytes / gib:.2f} GiB working set, "
            f"above the {_MAX_KDF_WORKING_SET / gib:.2f} GiB limit"
        )


def _validate_param(name: str, value: int, lo: int, hi: int) -> None:
    """Raise KDFParameterError if a KDF parameter is out of bounds."""
    if value < lo or value > hi:
        raise KDFParameterError(
            f"KDF parameter {name}={value} out of allowed range [{lo}, {hi}]"
        )


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
                raise ConfigurationError(
                    f"Cipher chaining uses a fixed order (AES-256-GCM → ChaCha20-Poly1305). "
                    f"Cannot combine chain=True with cipher '{cipher.name}'. "
                    f"Either remove --cipher or remove --chain."
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

    def encrypt(self, plaintext: str, password: str, *,
                pad: bool = False, fixed_size: bool = False) -> str:
        """
        Encrypt a text block. Returns a base64-encoded ciphertext string.

        Uses format v3 by default (stores KDF params, includes key-check).
        Set pad=True to hide exact plaintext length (bucket mode).
        Set fixed_size=True to pad all outputs to 64 KiB (constant-size mode).
        """
        data = plaintext.encode("utf-8")

        if fixed_size:
            data = _pad_plaintext(data, fixed_size=True)
            pad = True  # ensure FLAG_PADDED is set
        elif pad:
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
        version = FORMAT_VERSION_4

        # Refuse here what decrypt will refuse later. These bounds were applied
        # only when reading a header, so a caller constructing a pipeline with
        # out-of-range KDF settings — e.g. Argon2idKDF(memory_cost=1023) — got
        # a ciphertext back, and that ciphertext was then permanently
        # undecryptable by this or any future version. EncryptionPipeline is
        # the exported public API (the package ships py.typed), so "the CLI
        # only ever passes safe presets" is not a guarantee that holds for
        # library callers. Failing at encrypt costs one exception; failing at
        # decrypt costs the data.
        _build_kdf_from_params(self.kdf.kdf_id, kdf_params)

        # Encapsulation moved above the AAD, because v4 binds the KEM ciphertext
        # into it. It only needs the public key, so nothing here depends on the
        # password keys and the ordering is not circular — but the previous
        # order (AAD first, encapsulate later) cannot express this.
        kem_prefix = b""
        kem_ct = b""
        if self.hybrid_pq:
            if not self.pq_public_key:
                raise ConfigurationError("Hybrid PQ requires a public key for encryption")
            kem_ct, raw_ss = _pq_encapsulate(self.pq_public_key)
            if len(kem_ct) > 0xFFFF:
                raise ConfigurationError(
                    f"KEM ciphertext too large ({len(kem_ct)} bytes); "
                    f"format supports max 65535 bytes"
                )
            kem_prefix = struct.pack("!H", len(kem_ct)) + kem_ct

        aad = build_aad(version, cipher_id, self.kdf.kdf_id, flags,
                        kdf_params=kdf_params, salt=salt, kem_prefix=kem_prefix)

        keys: list[bytearray] = []
        try:
            # Key derivation (returns list of bytearray)
            num_keys = 2 if self.chain else 1
            keys = _derive_keys(self.kdf, password_bytes, salt, num_keys,
                                version=version)

            # Hybrid PQ layer
            if self.hybrid_pq:
                kem_ss = bytearray(raw_ss)
                old_keys = keys
                keys = [
                    _combine_with_kem(
                        k, kem_ss, salt,
                        version=version,
                        kem_ciphertext=kem_ct,
                        encapsulation_key=self.pq_public_key,
                        aad=aad,
                    )
                    for k in keys
                ]
                for k in old_keys:
                    secure_zero(k)
                secure_zero(kem_ss)

            # Encrypt with primary cipher
            nonce1, ct1 = self.cipher.encrypt(keys[0], data, aad)

            if self.chain:
                nonce2, ct2 = self.chain_cipher.encrypt(keys[1], ct1, aad)
                body = ct2
            else:
                nonce2, body = b"", ct1

            # The commitment is computed after encryption because it binds the
            # nonces, which the cipher generates. v3 computed its 8-byte check
            # before, and so could not cover them.
            commitment = _compute_commitment(
                keys[0], nonce1=nonce1, nonce2=nonce2, aad=aad,
                kem_prefix=kem_prefix,
            )
            payload = salt + nonce1 + nonce2 + kem_prefix + commitment + body

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
            FormatError: malformed ciphertext header or encoding
            DecryptionError: truncated ciphertext, unknown cipher/KDF, PQ failure
            WrongPasswordError: key-check mismatch (v3 — clear error message)
            ConfigurationError: missing PQ key
            cryptography.exceptions.InvalidTag: wrong password (v2) or tampering
        """
        version, cipher_id, kdf_id, flags, payload, kdf_params = deserialize(ciphertext_b64)

        is_chained = bool(flags & FLAG_CHAINED)
        is_hybrid = bool(flags & FLAG_HYBRID_PQ)
        is_padded = bool(flags & FLAG_PADDED)
        is_v4 = version == FORMAT_VERSION_4
        # v4 shares v3's header layout and its KDF-params-in-header behaviour,
        # so everything keyed off is_v3 below applies to v4 too.
        is_v3 = version in (FORMAT_VERSION_3, FORMAT_VERSION_4)

        # Resolve cipher(s)
        if is_chained:
            primary = AES256GCM()
            secondary: Cipher | None = ChaCha20Poly1305Cipher()
        else:
            cipher_cls = CIPHER_REGISTRY.get(cipher_id)
            if not cipher_cls:
                raise DecryptionError(f"Unknown cipher ID {cipher_id:#04x}")
            primary = cipher_cls()
            secondary = None

        # Resolve KDF
        if is_v3 and kdf_params is not None:
            kdf = _build_kdf_from_params(kdf_id, kdf_params)
        else:
            if kdf_id != self.kdf.kdf_id:
                raise DecryptionError(
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
            raise DecryptionError(
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
                raise ConfigurationError("Hybrid PQ ciphertext requires a secret key for decryption")
            if payload_len < offset + 2:
                raise DecryptionError("Truncated ciphertext: missing KEM length field")
            kem_ct_len = struct.unpack("!H", payload[offset : offset + 2])[0]
            offset += 2
            if kem_ct_len == 0:
                raise DecryptionError(
                    "Invalid hybrid PQ ciphertext: KEM ciphertext length is zero"
                )
            if payload_len < offset + kem_ct_len:
                raise DecryptionError(
                    f"Truncated ciphertext: KEM ciphertext claims {kem_ct_len} bytes "
                    f"but only {payload_len - offset} remain"
                )
            kem_ct = payload[offset : offset + kem_ct_len]
            offset += kem_ct_len
            kem_prefix = struct.pack("!H", kem_ct_len) + kem_ct
            kem_ss = bytearray(_pq_decapsulate(self.pq_secret_key, kem_ct))
        else:
            kem_ct = b""
            kem_prefix = b""

        # Key-check value (v3), or the wider commitment (v4)
        check_size = COMMITMENT_SIZE if is_v4 else KEY_CHECK_SIZE
        stored_key_check: bytes | None = None
        if is_v3:
            if payload_len < offset + check_size:
                raise DecryptionError("Truncated ciphertext: missing key-check value")
            stored_key_check = payload[offset : offset + check_size]
            offset += check_size

        ciphertext = payload[offset:]
        if not ciphertext:
            raise DecryptionError("Truncated ciphertext: no encrypted data after header fields")

        aad = build_aad(version, cipher_id, kdf_id, flags, kdf_params=kdf_params,
                        salt=salt, kem_prefix=kem_prefix)

        keys: list[bytearray] = []
        try:
            num_keys = 2 if is_chained else 1
            keys = _derive_keys(kdf, password_bytes, salt, num_keys,
                                version=version)

            if is_hybrid and kem_ss is not None:
                # The encapsulation key is not transmitted: ML-KEM-768 embeds it
                # in the decapsulation key, so v4 recovers it locally at zero
                # wire cost. Verified: dk[1152:2336] == ek.
                ek = (self.pq_secret_key[_MLKEM_DK_EK_START:_MLKEM_DK_EK_END]
                      if is_v4 and self.pq_secret_key else b"")
                old_keys = keys
                keys = [
                    _combine_with_kem(
                        k, kem_ss, salt,
                        version=version,
                        kem_ciphertext=kem_ct,
                        encapsulation_key=ek,
                        aad=aad,
                    )
                    for k in keys
                ]
                for k in old_keys:
                    secure_zero(k)
                secure_zero(kem_ss)

            # Verify the key-check (v3) or commitment (v4) before the AEAD, so a
            # wrong password stays distinguishable from tampered data.
            if stored_key_check is not None:
                if is_v4:
                    computed = _compute_commitment(
                        keys[0], nonce1=nonce1, nonce2=nonce2, aad=aad,
                        kem_prefix=kem_prefix,
                    )
                else:
                    computed = _compute_key_check(keys[0])
                if not hmac.compare_digest(stored_key_check, computed):
                    raise WrongPasswordError("Key verification failed: incorrect password")

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
