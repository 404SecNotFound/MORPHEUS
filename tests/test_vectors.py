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
from morpheus_crypt.core.errors import DecryptionError, FormatError, WrongPasswordError
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
