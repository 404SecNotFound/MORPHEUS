"""Known-answer tests: stored ciphertexts that must keep decrypting forever.

Every other crypto test in this suite round-trips in-process, which proves the
implementation is self-consistent and proves nothing about compatibility. Rename
an HKDF info string, reorder a payload field, change a truncation width, and the
whole suite stays green while every ciphertext ever written becomes permanently
undecryptable.

These files are the only thing standing between a refactor and that outcome.
They were generated from the shipping implementation and are never regenerated
to make a failing test pass. A failure here means one of two things:

  1. compatibility has been broken and archived ciphertexts are unreadable, or
  2. the vectors were regenerated to hide (1).

If a deliberate format change lands, add vectors for the new version and keep
the old ones decrypting. Do not edit the old ones.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from morpheus_crypt.core.ciphers import CIPHER_CHOICES
from morpheus_crypt.core.errors import (
    ConfigurationError,
    DecryptionError,
    FormatError,
    WrongPasswordError,
)
from morpheus_crypt.core.kdf import Argon2idKDF, ScryptKDF
from morpheus_crypt.core.pipeline import PQ_AVAILABLE, EncryptionPipeline

VECTOR_DIR = Path(__file__).parent / "vectors"


def _load(name: str) -> dict:
    return json.loads((VECTOR_DIR / name).read_text(encoding="utf-8"))


def _all_cases() -> list[tuple[str, dict]]:
    cases = []
    for path in sorted(VECTOR_DIR.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        for case in data["cases"]:
            cases.append((f"{path.stem}:{case['name']}", case))
    return cases


def _pipeline_for(case: dict) -> EncryptionPipeline:
    """Build a decrypt-side pipeline from a vector's metadata.

    Cipher and KDF come from the ciphertext header, not from here, so only the
    hybrid-PQ secret key genuinely has to be supplied.
    """
    kwargs: dict = {}
    if case.get("key_file"):
        # v5. FORMAT.md section 17: the key file is a mandatory second factor,
        # so the vector carries the exact bytes its ciphertext needs.
        kwargs["key_file"] = base64.b64decode(case["key_file"])
    if case.get("hybrid_pq"):
        kwargs["hybrid_pq"] = True
        kwargs["pq_secret_key"] = base64.b64decode(case["pq_secret_key"])
    if case.get("chain"):
        kwargs["chain"] = True
    params = case["kdf_params"]
    kdf = Argon2idKDF(**params) if case["kdf"] == "Argon2idKDF" else ScryptKDF(**params)
    return EncryptionPipeline(cipher=CIPHER_CHOICES["AES-256-GCM"](), kdf=kdf, **kwargs)


class TestStoredVectorsStillDecrypt:
    """The one test that can detect a silent compatibility break."""

    @pytest.mark.parametrize("label,case", _all_cases(), ids=lambda v: v if isinstance(v, str) else "")
    def test_vector_decrypts_to_its_recorded_plaintext(self, label, case):
        if case.get("hybrid_pq") and not PQ_AVAILABLE:
            pytest.skip("pqcrypto not installed")
        pipeline = _pipeline_for(case)
        assert pipeline.decrypt(case["ciphertext"], case["password"]) == case["plaintext"], (
            f"{label} no longer decrypts to its recorded plaintext. Either wire-format "
            "compatibility has been broken, or these vectors were regenerated to hide it."
        )

    def test_the_vector_set_is_not_empty(self):
        """A glob that matches nothing would make every test above vacuous."""
        cases = _all_cases()
        assert len(cases) >= 5, f"only {len(cases)} vectors found; the set has been gutted"

    def test_every_supported_format_version_is_covered(self):
        """Every version `deserialize` accepts needs stored ciphertexts.

        Derived from SUPPORTED_VERSIONS rather than listing versions by hand.
        The hand-written version of this test named only v3 and v4 while v2 was
        still an accepted, documented decrypt path, so the guard the project
        relies on to promise "v2 and v3 still decrypt" covered two of the three
        versions it promised. Deriving it means adding a version to the format
        forces vectors for it.
        """
        from morpheus_crypt.core.formats import SUPPORTED_VERSIONS
        covered = {
            json.loads(path.read_text(encoding="utf-8"))["format_version"]
            for path in VECTOR_DIR.glob("*.json")
        }
        missing = set(SUPPORTED_VERSIONS) - covered
        assert not missing, (
            f"deserialize() accepts version(s) {sorted(missing)} with no stored "
            "ciphertexts, so a regression on those paths would be invisible"
        )

    @pytest.mark.parametrize("path", sorted(VECTOR_DIR.glob("*.json")),
                             ids=lambda p: p.stem)
    def test_declared_version_matches_every_ciphertext_on_the_wire(self, path):
        """Every vector in a file must actually carry that file's version byte.

        This is the anti-regeneration guard, and it applies to all files rather
        than only v3. Regenerating a vector set is the obvious move when this
        suite goes red under time pressure, and it destroys the only evidence
        that the older path still works. Because the current implementation
        emits v4 exclusively, regenerating v2.json or v3.json in place would
        write v4 ciphertexts into them and fail here loudly.
        """
        data = json.loads(path.read_text(encoding="utf-8"))
        declared = data["format_version"]
        for case in data["cases"]:
            actual = base64.b64decode(case["ciphertext"])[0]
            assert actual == declared, (
                f"{path.name} declares format_version {declared} but "
                f"{case['name']} carries version byte {actual}. Either these "
                "vectors were regenerated by a newer implementation, or they "
                "were written into the wrong file."
            )

    def test_each_version_has_more_than_one_vector(self):
        """One vector per version makes a single lucky pass look like coverage."""
        from collections import Counter
        counts = Counter()
        for path in VECTOR_DIR.glob("*.json"):
            data = json.loads(path.read_text(encoding="utf-8"))
            counts[data["format_version"]] += len(data["cases"])
        assert counts, "no vector files at all"
        thin = {v: n for v, n in counts.items() if n < 2}
        assert not thin, f"these versions have too few vectors: {thin}"

    def test_a_tampered_vector_is_rejected(self):
        """Proves these assertions test authentication, not just base64 decoding."""
        label, case = next(
            (lbl, c) for lbl, c in _all_cases() if not c.get("hybrid_pq")
        )
        ct = case["ciphertext"]
        mid = len(ct) // 2
        flipped = ct[:mid] + ("B" if ct[mid] != "B" else "C") + ct[mid + 1:]
        # Named rather than blind: a tampered ciphertext can legitimately fail
        # as any of these depending on which field the flip landed in, but it
        # must not fail as something unrelated like a TypeError.
        with pytest.raises((InvalidTag, WrongPasswordError, DecryptionError, FormatError)):
            _pipeline_for(case).decrypt(flipped, case["password"])


class TestKeyFilesV5:
    """FORMAT.md section 17. v5 adds a key file as a mandatory second factor.

    These vectors were generated by the web implementation and are read here by
    code written from the specification. Three implementations agreeing on the
    same stored bytes is the whole point of having a specification at all.
    """

    @staticmethod
    def _v5_case() -> dict:
        return _load("v5.json")["cases"][0]

    def test_the_v5_set_is_present_and_all_on_the_wire(self):
        data = _load("v5.json")
        assert data["format_version"] == 5
        assert len(data["cases"]) >= 5
        for case in data["cases"]:
            assert base64.b64decode(case["ciphertext"])[0] == 5, case["name"]
            assert case.get("key_file"), f"{case['name']} carries no key file"

    def test_a_key_file_is_required_and_its_absence_says_so(self):
        case = self._v5_case()
        params = case["kdf_params"]
        pipeline = EncryptionPipeline(
            cipher=CIPHER_CHOICES["AES-256-GCM"](), kdf=Argon2idKDF(**params)
        )
        with pytest.raises(ConfigurationError, match="key file"):
            pipeline.decrypt(case["ciphertext"], case["password"])

    def test_a_wrong_key_file_is_indistinguishable_from_a_wrong_password(self):
        """FORMAT.md section 17.2 refuses to say which factor failed.

        A stored fingerprint would make every ciphertext under one key file
        linkable by anyone holding two of them, which is the property someone
        reaching for a second factor is trying to avoid. The cost is this
        ambiguity, and the point of the test is that the ambiguity holds.
        """
        case = self._v5_case()
        params = case["kdf_params"]
        good = base64.b64decode(case["key_file"])
        wrong = bytes([good[0] ^ 0xFF]) + good[1:]

        def failure(key_file: bytes, password: str) -> type:
            pipeline = EncryptionPipeline(
                cipher=CIPHER_CHOICES["AES-256-GCM"](),
                kdf=Argon2idKDF(**params), key_file=key_file,
            )
            with pytest.raises(Exception) as caught:
                pipeline.decrypt(case["ciphertext"], password)
            return type(caught.value)

        assert failure(wrong, case["password"]) is WrongPasswordError
        assert failure(good, case["password"] + "x") is WrongPasswordError

    def test_an_empty_key_file_is_refused_at_encryption_time(self):
        """Hashing zero bytes is well defined, which is exactly the danger."""
        pipeline = EncryptionPipeline(
            kdf=Argon2idKDF(time_cost=1, memory_cost=1024, parallelism=1),
            key_file=b"",
        )
        with pytest.raises(ConfigurationError, match="empty key file"):
            pipeline.encrypt("x", "T3st!Passw0rd#Str0ng")

    def test_no_key_file_still_writes_v4(self):
        """FORMAT.md section 17.4: there is no "v5 without a key file"."""
        pipeline = EncryptionPipeline(
            kdf=Argon2idKDF(time_cost=1, memory_cost=1024, parallelism=1)
        )
        out = pipeline.encrypt("x", "T3st!Passw0rd#Str0ng")
        assert base64.b64decode(out)[0] == 4

    @pytest.mark.parametrize("chain", [False, True])
    @pytest.mark.parametrize("pad", [False, True])
    def test_round_trip_with_a_key_file(self, chain, pad):
        key_file = bytes(range(32))
        pipeline = EncryptionPipeline(
            kdf=Argon2idKDF(time_cost=1, memory_cost=1024, parallelism=1),
            chain=chain, key_file=key_file,
        )
        out = pipeline.encrypt("key file round trip", "T3st!Passw0rd#Str0ng", pad=pad)
        assert base64.b64decode(out)[0] == 5
        assert pipeline.decrypt(out, "T3st!Passw0rd#Str0ng") == "key file round trip"
