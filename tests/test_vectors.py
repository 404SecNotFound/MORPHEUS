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

from morpheus.core.ciphers import CIPHER_CHOICES
from morpheus.core.errors import DecryptionError, FormatError, WrongPasswordError
from morpheus.core.kdf import Argon2idKDF, ScryptKDF
from morpheus.core.pipeline import PQ_AVAILABLE, EncryptionPipeline

VECTOR_DIR = Path(__file__).parent / "vectors"


def _load(name: str) -> dict:
    return json.loads((VECTOR_DIR / name).read_text())


def _all_cases() -> list[tuple[str, dict]]:
    cases = []
    for path in sorted(VECTOR_DIR.glob("*.json")):
        data = json.loads(path.read_text())
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

    def test_every_declared_format_version_is_covered(self):
        """Each shipped format version needs at least one stored ciphertext."""
        from morpheus.core.formats import FORMAT_VERSION_3, FORMAT_VERSION_4
        covered = set()
        for path in VECTOR_DIR.glob("*.json"):
            covered.add(json.loads(path.read_text())["format_version"])
        assert FORMAT_VERSION_3 in covered, "no v3 vectors; the legacy path is unpinned"
        assert FORMAT_VERSION_4 in covered, "no v4 vectors; the current path is unpinned"

    def test_v3_vectors_are_actually_v3_on_the_wire(self):
        """Guards against v3 vectors being silently regenerated as v4.

        Regenerating them would make every assertion above pass while deleting
        the only evidence that the legacy path still works.
        """
        data = _load("v3.json")
        for case in data["cases"]:
            first = base64.b64decode(case["ciphertext"])[0]
            assert first == 3, (
                f"{case['name']} has version byte {first}, not 3 — the v3 "
                "vectors have been regenerated and no longer test v3"
            )

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
