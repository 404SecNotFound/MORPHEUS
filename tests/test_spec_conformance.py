"""An independent decryptor written from docs/FORMAT.md, run against the vectors.

This file deliberately imports nothing from ``morpheus_crypt``. It is a second
implementation, transcribed from the specification and nothing else, using only
stdlib primitives plus argon2, the AEAD constructions and ML-KEM.

Why it exists. ``test_vectors.py`` proves the reference implementation still
decrypts what it used to write. It cannot prove that docs/FORMAT.md describes
what the implementation actually does, and a specification nobody executes
drifts from the code within one release. Since the native macOS client will be
a from-scratch Swift port built against that document, a wrong sentence in it
costs a rewrite and, worse, could ship a client that writes ciphertexts this
implementation cannot read.

So this is the specification in executable form. Every step carries the section
of FORMAT.md it implements. If a change to the format lands in the code and not
in the document, the two implementations disagree here and CI goes red.

HKDF is hand-rolled from RFC 5869 rather than taken from ``cryptography``, so
what is under test is the specification's wording about extract-versus-expand,
not a library's reading of it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import struct
from pathlib import Path

import pytest
from argon2.low_level import Type as Argon2Type
from argon2.low_level import hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

try:
    from pqcrypto.kem import ml_kem_768

    PQ_AVAILABLE = True
except ImportError:
    PQ_AVAILABLE = False

VECTOR_DIR = Path(__file__).parent / "vectors"

# FORMAT.md section 5
AES, CHACHA = 0x01, 0x02
SCRYPT, ARGON2ID = 0x01, 0x02
FLAG_CHAINED, FLAG_HYBRID_PQ, FLAG_PADDED = 0x01, 0x02, 0x04
CHECK_SIZE = {2: 0, 3: 8, 4: 32}


def _lp(x: bytes) -> bytes:
    """FORMAT.md section 1: length-prefixed field."""
    assert len(x) <= 0xFFFF
    return struct.pack("!H", len(x)) + x


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 Expand. Used by FORMAT.md section 7.2, with no Extract step."""
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 Extract-then-Expand. Used by FORMAT.md section 7.3."""
    prk = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    return _hkdf_expand(prk, info, length)


def _derive_master(kdf_id: int, params: tuple[int, int, int] | None,
                   password: bytes, salt: bytes, fallback: dict) -> bytes:
    """FORMAT.md sections 5.2 and 7.1.

    ``fallback`` supplies the parameters for v2, whose header does not carry
    them. For v3 and v4 the header wins, which is what section 12 requires of a
    conforming implementation.
    """
    if kdf_id == ARGON2ID:
        time_cost, memory_cost, parallelism = params or (
            fallback["time_cost"], fallback["memory_cost"], fallback["parallelism"]
        )
        return hash_secret_raw(
            secret=password, salt=salt, time_cost=time_cost,
            memory_cost=memory_cost, parallelism=parallelism,
            hash_len=32, type=Argon2Type.ID,
        )
    if kdf_id == SCRYPT:
        n, r, p = params or (fallback["n"], fallback["r"], fallback["p"])
        return hashlib.scrypt(password, salt=salt, n=n, r=r, p=p, dklen=32,
                              maxmem=1 << 30)
    raise ValueError(f"unknown kdf_id {kdf_id:#04x}")


def _unpad(data: bytes) -> bytes:
    """FORMAT.md section 10.3."""
    if not data:
        raise ValueError("cannot unpad empty data")
    last = data[-1]
    if last == 0x00:
        if len(data) < 4:
            raise ValueError("too short for length prefix")
        original_len = struct.unpack("!I", data[:4])[0]
        if original_len > len(data) - 4:
            raise ValueError("claimed length exceeds available data")
        return data[4 : 4 + original_len]
    if last > len(data) or data[-last:] != bytes([last]) * last:
        raise ValueError("invalid PKCS#7 padding")
    return data[:-last]


def spec_decrypt(b64: str, password: str, *, fallback_kdf: dict,
                 pq_secret_key: bytes | None = None) -> str:
    """Decrypt strictly according to docs/FORMAT.md."""
    raw = base64.b64decode(b64, validate=True)  # section 3
    if len(raw) < 6:
        raise ValueError("too short")

    # ---- section 4: header ----
    version = raw[0]
    if version not in CHECK_SIZE:
        raise ValueError(f"unsupported version {version:#04x}")
    header_size = 6 if version == 2 else 18
    if len(raw) < header_size:
        raise ValueError(f"too short for v{version}")

    _, cipher_id, kdf_id, flags, reserved = struct.unpack("!BBBBH", raw[:6])
    if reserved != 0:
        raise ValueError("reserved bytes must be zero")
    kdf_params = struct.unpack("!III", raw[6:18]) if version != 2 else None
    header, payload = raw[:header_size], raw[header_size:]

    chained = bool(flags & FLAG_CHAINED)
    hybrid = bool(flags & FLAG_HYBRID_PQ)
    padded = bool(flags & FLAG_PADDED)

    # ---- section 6: payload layout ----
    offset = 0
    salt = payload[offset : offset + 16]
    offset += 16
    nonce1 = payload[offset : offset + 12]
    offset += 12
    nonce2 = b""
    if chained:
        nonce2 = payload[offset : offset + 12]
        offset += 12

    kem_ct = kem_prefix = b""
    if hybrid:
        kem_len = struct.unpack("!H", payload[offset : offset + 2])[0]
        offset += 2
        if kem_len == 0:
            raise ValueError("kem_len must be non-zero")
        kem_ct = payload[offset : offset + kem_len]
        offset += kem_len
        kem_prefix = struct.pack("!H", kem_len) + kem_ct

    check_size = CHECK_SIZE[version]
    stored_check = payload[offset : offset + check_size]
    offset += check_size
    body = payload[offset:]
    if not body:
        raise ValueError("empty body")

    # ---- section 9: AAD. Note LP() over kem_prefix, which is itself already
    # length-prefixed, so the KEM field carries two length words. ----
    aad = header + _lp(salt) + _lp(kem_prefix) if version == 4 else header

    # ---- section 7.1: password key ----
    master = _derive_master(kdf_id, kdf_params, password.encode("utf-8"), salt,
                            fallback_kdf)

    # ---- section 7.2: subkeys, chained mode only. Single-cipher mode uses the
    # KDF output directly with no HKDF step at all. ----
    if chained:
        label = b"morpheus-v4-key-" if version == 4 else b"morpheus-v2-key-"
        keys = [_hkdf_expand(master, label + str(i).encode() + salt, 32)
                for i in (0, 1)]
    else:
        keys = [master]

    # ---- section 7.3: hybrid combiner ----
    if hybrid:
        if not PQ_AVAILABLE:
            raise RuntimeError("pqcrypto not installed")
        shared_secret = ml_kem_768.decrypt(pq_secret_key, kem_ct)
        if version == 4:
            # The encapsulation key is never transmitted: ML-KEM-768 embeds it
            # in the decapsulation key, so it is recovered locally.
            ek = pq_secret_key[1152:2336]
            info = b"morpheus-hybrid-v4" + _lp(kem_ct) + _lp(ek) + _lp(aad)
        else:
            info = b"hybrid-pq-v1"
        keys = [_hkdf(k + shared_secret, salt, info, 32) for k in keys]

    # ---- section 8: key verification, before the AEAD ----
    if version == 4:
        computed = hashlib.sha256(
            b"morpheus-cmt-v4" + _lp(keys[0]) + _lp(keys[1] if chained else b"")
        ).digest()
    elif version == 3:
        computed = hmac.new(keys[0], b"morpheus-key-check",
                            hashlib.sha256).digest()[:8]
    else:
        computed = b""
    if check_size and not hmac.compare_digest(stored_check, computed):
        raise ValueError("key verification failed: incorrect password")

    # ---- sections 5.1 and 6: AEAD, chain order fixed AES then ChaCha ----
    if chained:
        inner = ChaCha20Poly1305(keys[1]).decrypt(nonce2, body, aad)
        plaintext = AESGCM(keys[0]).decrypt(nonce1, inner, aad)
    elif cipher_id == AES:
        plaintext = AESGCM(keys[0]).decrypt(nonce1, body, aad)
    elif cipher_id == CHACHA:
        plaintext = ChaCha20Poly1305(keys[0]).decrypt(nonce1, body, aad)
    else:
        raise ValueError(f"unknown cipher_id {cipher_id:#04x}")

    if padded:
        plaintext = _unpad(plaintext)  # section 10
    return plaintext.decode("utf-8")


def _all_cases() -> list[tuple[str, dict]]:
    cases = []
    for path in sorted(VECTOR_DIR.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        for case in data["cases"]:
            cases.append((f"{path.stem}:{case['name']}", case))
    return cases


class TestSpecificationIsImplementable:
    """docs/FORMAT.md is sufficient to decrypt every stored ciphertext."""

    @pytest.mark.parametrize("label,case", _all_cases(),
                             ids=lambda v: v if isinstance(v, str) else "")
    def test_spec_only_decryptor_matches_recorded_plaintext(self, label, case):
        if case.get("hybrid_pq") and not PQ_AVAILABLE:
            pytest.skip("pqcrypto not installed")
        secret_key = (base64.b64decode(case["pq_secret_key"])
                      if case.get("hybrid_pq") else None)
        got = spec_decrypt(case["ciphertext"], case["password"],
                           fallback_kdf=case["kdf_params"],
                           pq_secret_key=secret_key)
        assert got == case["plaintext"], (
            f"{label}: an implementation built from docs/FORMAT.md alone no "
            "longer reproduces this plaintext. Either the format changed and "
            "the specification was not updated, or the specification is wrong."
        )

    def test_it_really_is_independent_of_the_reference_implementation(self):
        """A stray morpheus_crypt import here would make this test circular."""
        source = Path(__file__).read_text(encoding="utf-8")
        offending = [
            line for line in source.splitlines()
            if line.startswith(("import ", "from ")) and "morpheus_crypt" in line
        ]
        assert not offending, (
            f"this module must not import the reference implementation: {offending}"
        )

    @pytest.mark.parametrize("version", [2, 3, 4])
    def test_wrong_password_is_rejected(self, version):
        """Proves the assertions above test decryption, not base64 plumbing.

        The two failure modes are named rather than blind, because which one
        fires is itself part of the specification: v2 has no key-check field so
        a wrong password can only surface as an AEAD tag failure, while v3 and
        v4 are required by section 8 to catch it before the AEAD runs.
        """
        _, case = next((lbl, c) for lbl, c in _all_cases()
                       if not c.get("hybrid_pq")
                       and base64.b64decode(c["ciphertext"])[0] == version)
        expected = InvalidTag if version == 2 else ValueError
        with pytest.raises(expected):
            spec_decrypt(case["ciphertext"], case["password"] + "x",
                         fallback_kdf=case["kdf_params"])
