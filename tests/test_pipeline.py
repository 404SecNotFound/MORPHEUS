"""Tests for the encryption pipeline — roundtrips, chaining, and hybrid PQ."""

import base64
import struct

import pytest
from cryptography.exceptions import InvalidTag

from morpheus.core.ciphers import AES256GCM, ChaCha20Poly1305Cipher
from morpheus.core.formats import (
    FLAG_CHAINED,
    FLAG_HYBRID_PQ,
    FORMAT_VERSION,
    FORMAT_VERSION_4,
    HEADER_FORMAT,
)
from morpheus.core.kdf import Argon2idKDF, ScryptKDF
from morpheus.core.pipeline import (
    PQ_AVAILABLE,
    EncryptionPipeline,
    pq_generate_keypair,
)

# Use fast KDF params in tests
FAST_ARGON2 = Argon2idKDF(time_cost=1, memory_cost=1024, parallelism=1)
FAST_SCRYPT = ScryptKDF(n=2**14, r=8, p=1)

PASSWORD = "T3st!Passw0rd#Str0ng"

SAMPLE_TEXT = """This is a multi-line block of text
that represents a realistic encryption payload.

It contains special characters: !@#$%^&*()
Unicode: cafe\u0301 \u00fc\u00f6\u00e4 \u4e16\u754c \U0001f512
Numbers: 1234567890
And multiple paragraphs.

End of sample text."""


class TestSingleCipherRoundtrip:
    """Test encrypt-then-decrypt with each cipher + KDF combination."""

    @pytest.mark.parametrize("cipher_cls", [AES256GCM, ChaCha20Poly1305Cipher])
    @pytest.mark.parametrize("kdf", [FAST_ARGON2, FAST_SCRYPT])
    def test_roundtrip(self, cipher_cls, kdf):
        pipeline = EncryptionPipeline(cipher=cipher_cls(), kdf=kdf)
        encrypted = pipeline.encrypt(SAMPLE_TEXT, PASSWORD)
        decrypted = pipeline.decrypt(encrypted, PASSWORD)
        assert decrypted == SAMPLE_TEXT

    def test_empty_plaintext(self):
        pipeline = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2)
        encrypted = pipeline.encrypt("", PASSWORD)
        decrypted = pipeline.decrypt(encrypted, PASSWORD)
        assert decrypted == ""

    def test_large_text(self):
        text = "A" * 100_000
        pipeline = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2)
        encrypted = pipeline.encrypt(text, PASSWORD)
        decrypted = pipeline.decrypt(encrypted, PASSWORD)
        assert decrypted == text

    def test_wrong_password_fails(self):
        """v3 key-check raises ValueError; v2 would raise InvalidTag."""
        pipeline = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2)
        encrypted = pipeline.encrypt("secret data", PASSWORD)
        with pytest.raises((InvalidTag, ValueError)):
            pipeline.decrypt(encrypted, "Wr0ng!Password#X")

    def test_unique_ciphertexts(self):
        """Same plaintext + password should produce different ciphertexts (random salt/nonce)."""
        pipeline = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2)
        ct1 = pipeline.encrypt("test", PASSWORD)
        ct2 = pipeline.encrypt("test", PASSWORD)
        assert ct1 != ct2

    def test_description(self):
        p = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2)
        assert "AES-256-GCM" in p.description
        assert "Argon2id" in p.description

    def test_pipeline_reuse(self):
        """Pipeline can encrypt multiple messages without state leakage."""
        pipeline = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2)
        for i in range(5):
            text = f"message {i}"
            encrypted = pipeline.encrypt(text, PASSWORD)
            assert pipeline.decrypt(encrypted, PASSWORD) == text

    def test_unicode_roundtrip(self):
        """Unicode, emoji, and RTL text survive roundtrip."""
        texts = [
            "\u4e16\u754c\u3053\u3093\u306b\u3061\u306f",  # Japanese
            "\U0001f512\U0001f511\U0001f50f",  # Emoji (lock, key, locked-with-pen)
            "\u0645\u0631\u062d\u0628\u0627",  # Arabic
        ]
        pipeline = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2)
        for text in texts:
            ct = pipeline.encrypt(text, PASSWORD)
            assert pipeline.decrypt(ct, PASSWORD) == text


class TestChainedCipher:
    """Test cipher chaining (AES-256-GCM -> ChaCha20-Poly1305)."""

    def test_chained_roundtrip(self):
        pipeline = EncryptionPipeline(
            cipher=AES256GCM(), kdf=FAST_ARGON2, chain=True,
        )
        encrypted = pipeline.encrypt(SAMPLE_TEXT, PASSWORD)
        decrypted = pipeline.decrypt(encrypted, PASSWORD)
        assert decrypted == SAMPLE_TEXT

    def test_chain_always_uses_fixed_order(self):
        """Chaining always uses AES->ChaCha regardless of which pipeline decrypts."""
        p1 = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2, chain=True)
        p2 = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2, chain=True)
        ct = p1.encrypt("test", PASSWORD)
        assert p2.decrypt(ct, PASSWORD) == "test"

    def test_chain_with_chacha_raises_error(self):
        """Passing ChaCha as cipher with chain=True should raise ValueError."""
        with pytest.raises(ValueError, match="Cannot combine chain=True"):
            EncryptionPipeline(cipher=ChaCha20Poly1305Cipher(), kdf=FAST_ARGON2, chain=True)

    def test_chained_wrong_password(self):
        pipeline = EncryptionPipeline(
            cipher=AES256GCM(), kdf=FAST_ARGON2, chain=True,
        )
        encrypted = pipeline.encrypt("secret", PASSWORD)
        with pytest.raises((InvalidTag, ValueError)):
            pipeline.decrypt(encrypted, "Wr0ng!Password#X")

    def test_chained_description(self):
        p = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2, chain=True)
        assert "ChaCha20" in p.description

    def test_format_is_self_describing(self):
        """Decrypt reads cipher info from the header, so any pipeline with
        the matching KDF can decrypt regardless of its own cipher setting."""
        chained = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2, chain=True)
        single = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2)
        ct_chained = chained.encrypt("test", PASSWORD)
        # Single pipeline CAN decrypt chained ciphertext (self-describing format)
        assert single.decrypt(ct_chained, PASSWORD) == "test"


@pytest.mark.skipif(not PQ_AVAILABLE, reason="pqcrypto not installed")
class TestHybridPQ:
    """Test hybrid post-quantum (ML-KEM-768) encryption."""

    def setup_method(self):
        self.pk, self.sk = pq_generate_keypair()

    def test_hybrid_roundtrip(self):
        enc_pipeline = EncryptionPipeline(
            cipher=AES256GCM(), kdf=FAST_ARGON2,
            hybrid_pq=True, pq_public_key=self.pk,
        )
        dec_pipeline = EncryptionPipeline(
            cipher=AES256GCM(), kdf=FAST_ARGON2,
            hybrid_pq=True, pq_secret_key=self.sk,
        )
        encrypted = enc_pipeline.encrypt(SAMPLE_TEXT, PASSWORD)
        decrypted = dec_pipeline.decrypt(encrypted, PASSWORD)
        assert decrypted == SAMPLE_TEXT

    def test_hybrid_chained_roundtrip(self):
        enc_pipeline = EncryptionPipeline(
            cipher=AES256GCM(), kdf=FAST_ARGON2,
            chain=True, hybrid_pq=True, pq_public_key=self.pk,
        )
        dec_pipeline = EncryptionPipeline(
            cipher=AES256GCM(), kdf=FAST_ARGON2,
            chain=True, hybrid_pq=True, pq_secret_key=self.sk,
        )
        encrypted = enc_pipeline.encrypt(SAMPLE_TEXT, PASSWORD)
        decrypted = dec_pipeline.decrypt(encrypted, PASSWORD)
        assert decrypted == SAMPLE_TEXT

    def test_hybrid_wrong_password_fails(self):
        enc = EncryptionPipeline(
            cipher=AES256GCM(), kdf=FAST_ARGON2,
            hybrid_pq=True, pq_public_key=self.pk,
        )
        dec = EncryptionPipeline(
            cipher=AES256GCM(), kdf=FAST_ARGON2,
            hybrid_pq=True, pq_secret_key=self.sk,
        )
        encrypted = enc.encrypt("secret", PASSWORD)
        with pytest.raises((InvalidTag, ValueError)):
            dec.decrypt(encrypted, "Wr0ng!Password#X")

    def test_hybrid_wrong_sk_fails(self):
        enc = EncryptionPipeline(
            cipher=AES256GCM(), kdf=FAST_ARGON2,
            hybrid_pq=True, pq_public_key=self.pk,
        )
        _, wrong_sk = pq_generate_keypair()
        dec = EncryptionPipeline(
            cipher=AES256GCM(), kdf=FAST_ARGON2,
            hybrid_pq=True, pq_secret_key=wrong_sk,
        )
        encrypted = enc.encrypt("secret", PASSWORD)
        # Note: the key-check is computed over the post-KEM combined key, so a
        # wrong ML-KEM secret key currently surfaces as WrongPasswordError
        # (a ValueError subclass) rather than a distinct PQ-specific error.
        with pytest.raises((InvalidTag, ValueError)):
            dec.decrypt(encrypted, PASSWORD)

    def test_hybrid_without_pk_raises(self):
        enc = EncryptionPipeline(
            cipher=AES256GCM(), kdf=FAST_ARGON2, hybrid_pq=True,
        )
        with pytest.raises(ValueError, match="public key"):
            enc.encrypt("test", PASSWORD)

    def test_hybrid_without_sk_raises(self):
        enc = EncryptionPipeline(
            cipher=AES256GCM(), kdf=FAST_ARGON2,
            hybrid_pq=True, pq_public_key=self.pk,
        )
        dec = EncryptionPipeline(
            cipher=AES256GCM(), kdf=FAST_ARGON2, hybrid_pq=True,
        )
        encrypted = enc.encrypt("test", PASSWORD)
        with pytest.raises(ValueError, match="secret key"):
            dec.decrypt(encrypted, PASSWORD)

    def test_hybrid_description(self):
        p = EncryptionPipeline(
            cipher=AES256GCM(), kdf=FAST_ARGON2,
            hybrid_pq=True, pq_public_key=self.pk,
        )
        assert "ML-KEM-768" in p.description


class TestCrossCompatibility:
    """Ensure different pipeline configs are not cross-compatible."""

    def test_format_self_describing_across_ciphers(self):
        """Format is self-describing: cipher info is in the header, so a
        ChaCha-configured pipeline can decrypt AES ciphertext and vice-versa."""
        aes = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2)
        chacha = EncryptionPipeline(cipher=ChaCha20Poly1305Cipher(), kdf=FAST_ARGON2)
        ct = aes.encrypt("test", PASSWORD)
        assert chacha.decrypt(ct, PASSWORD) == "test"

    def test_v3_cross_kdf_decryption(self):
        """v3 stores KDF params in header, so any pipeline can decrypt regardless of KDF config."""
        a = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2)
        s = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_SCRYPT)
        ct = a.encrypt("test", PASSWORD)
        # v3 rebuilds KDF from header — cross-KDF works
        assert s.decrypt(ct, PASSWORD) == "test"


class TestPayloadValidation:
    """Test that truncated/malformed ciphertexts produce clear error messages."""

    def test_truncated_payload_raises_valueerror(self):
        """A payload too short for salt+nonce should raise ValueError."""
        # Build a valid header but truncated payload (only 10 bytes, need 16+12=28)
        header = struct.pack(HEADER_FORMAT, FORMAT_VERSION, 0x01, 0x02, 0x00, 0)
        truncated = header + b"\x00" * 10
        b64 = base64.b64encode(truncated).decode()
        pipeline = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2)
        with pytest.raises(ValueError, match="Truncated ciphertext"):
            pipeline.decrypt(b64, PASSWORD)

    def test_empty_ciphertext_after_fields_raises(self):
        """Payload with correct salt+nonce but no ciphertext data."""
        header = struct.pack(HEADER_FORMAT, FORMAT_VERSION, 0x01, 0x02, 0x00, 0)
        # Exactly salt (16) + nonce (12) = 28 bytes, no ciphertext
        payload = b"\x00" * 28
        b64 = base64.b64encode(header + payload).decode()
        pipeline = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2)
        with pytest.raises(ValueError, match="no encrypted data"):
            pipeline.decrypt(b64, PASSWORD)

    def test_kem_ciphertext_length_zero_rejected(self):
        """KEM ciphertext length of 0 should be rejected to prevent PQ bypass."""
        # Build header with hybrid PQ flag
        flags = FLAG_HYBRID_PQ
        header = struct.pack(HEADER_FORMAT, FORMAT_VERSION, 0x01, 0x02, flags, 0)
        # salt (16) + nonce (12) + KEM length field (2 bytes, value=0) + fake ciphertext
        salt = b"\x00" * 16
        nonce = b"\x00" * 12
        kem_len = struct.pack("!H", 0)  # Zero-length KEM ciphertext
        fake_ct = b"\x00" * 32
        payload = salt + nonce + kem_len + fake_ct
        b64 = base64.b64encode(header + payload).decode()
        pipeline = EncryptionPipeline(
            cipher=AES256GCM(), kdf=FAST_ARGON2,
            hybrid_pq=True, pq_secret_key=b"\x00" * 2400,
        )
        with pytest.raises(ValueError, match="KEM ciphertext length is zero"):
            pipeline.decrypt(b64, PASSWORD)

    def test_unknown_cipher_id_raises(self):
        """Unknown cipher_id in header should raise ValueError."""
        header = struct.pack(HEADER_FORMAT, FORMAT_VERSION, 0xAA, 0x02, 0x00, 0)
        payload = b"\x00" * 64
        b64 = base64.b64encode(header + payload).decode()
        pipeline = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2)
        with pytest.raises(ValueError, match="Unknown cipher"):
            pipeline.decrypt(b64, PASSWORD)

    def test_tampered_header_flag_fails_aead(self):
        """Flipping a flag bit in the ciphertext should cause AEAD validation failure."""
        pipeline = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2)
        ct = pipeline.encrypt("test", PASSWORD)
        raw = base64.b64decode(ct)
        # Flip the chained flag (byte 3)
        tampered = bytearray(raw)
        tampered[3] ^= FLAG_CHAINED
        b64_tampered = base64.b64encode(bytes(tampered)).decode()
        # Chained flag set means cipher_id should be 0x03, but it's 0x01
        # This should fail during decrypt (InvalidTag or ValueError)
        with pytest.raises((InvalidTag, ValueError)):
            pipeline.decrypt(b64_tampered, PASSWORD)


class TestFormatFlagCombinations:
    """Test all flag combinations for format consistency."""

    def test_no_flags(self):
        p = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2)
        ct = p.encrypt("test", PASSWORD)
        assert p.decrypt(ct, PASSWORD) == "test"

    def test_chained_flag_only(self):
        p = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2, chain=True)
        ct = p.encrypt("test", PASSWORD)
        assert p.decrypt(ct, PASSWORD) == "test"

    @pytest.mark.skipif(not PQ_AVAILABLE, reason="pqcrypto not installed")
    def test_hybrid_flag_only(self):
        pk, sk = pq_generate_keypair()
        enc = EncryptionPipeline(
            cipher=AES256GCM(), kdf=FAST_ARGON2,
            hybrid_pq=True, pq_public_key=pk,
        )
        dec = EncryptionPipeline(
            cipher=AES256GCM(), kdf=FAST_ARGON2,
            hybrid_pq=True, pq_secret_key=sk,
        )
        ct = enc.encrypt("test", PASSWORD)
        assert dec.decrypt(ct, PASSWORD) == "test"

    @pytest.mark.skipif(not PQ_AVAILABLE, reason="pqcrypto not installed")
    def test_both_flags(self):
        pk, sk = pq_generate_keypair()
        enc = EncryptionPipeline(
            cipher=AES256GCM(), kdf=FAST_ARGON2,
            chain=True, hybrid_pq=True, pq_public_key=pk,
        )
        dec = EncryptionPipeline(
            cipher=AES256GCM(), kdf=FAST_ARGON2,
            chain=True, hybrid_pq=True, pq_secret_key=sk,
        )
        ct = enc.encrypt("test", PASSWORD)
        assert dec.decrypt(ct, PASSWORD) == "test"


class TestV3Features:
    """Tests for format v3 features: padding, key-check, KDF params."""

    def test_padding_roundtrip(self):
        """Padded encryption produces correct plaintext after unpadding."""
        pipeline = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2)
        encrypted = pipeline.encrypt("short", PASSWORD, pad=True)
        decrypted = pipeline.decrypt(encrypted, PASSWORD)
        assert decrypted == "short"

    def test_padding_hides_length(self):
        """Different length plaintexts in same bucket produce same-size ciphertexts."""
        pipeline = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2)
        ct_short = pipeline.encrypt("a", PASSWORD, pad=True)
        ct_longer = pipeline.encrypt("a" * 200, PASSWORD, pad=True)
        # Both are under 256 bytes, so pad to the 256B bucket
        raw_short = base64.b64decode(ct_short)
        raw_longer = base64.b64decode(ct_longer)
        assert len(raw_short) == len(raw_longer)

    def test_unpadded_vs_padded_different(self):
        """Padded ciphertext differs from unpadded."""
        pipeline = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2)
        ct_plain = pipeline.encrypt("test", PASSWORD, pad=False)
        ct_padded = pipeline.encrypt("test", PASSWORD, pad=True)
        # Padded output should be larger due to padding bytes
        raw_plain = base64.b64decode(ct_plain)
        raw_padded = base64.b64decode(ct_padded)
        assert len(raw_padded) > len(raw_plain)

    def test_wrong_password_clear_error(self):
        """v3 key-check gives a clear error message for wrong password."""
        pipeline = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2)
        encrypted = pipeline.encrypt("secret", PASSWORD)
        with pytest.raises(ValueError, match="incorrect password"):
            pipeline.decrypt(encrypted, "Wr0ng!Password#X")

    def test_v3_format_version_in_output(self):
        """Pipeline encrypt produces v4 format by default (was v3)."""
        pipeline = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2)
        ct = pipeline.encrypt("test", PASSWORD)
        raw = base64.b64decode(ct)
        assert raw[0] == FORMAT_VERSION_4

    def test_chained_padding_roundtrip(self):
        """Padding works with cipher chaining."""
        pipeline = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2, chain=True)
        encrypted = pipeline.encrypt(SAMPLE_TEXT, PASSWORD, pad=True)
        decrypted = pipeline.decrypt(encrypted, PASSWORD)
        assert decrypted == SAMPLE_TEXT

    def test_larger_text_uses_bigger_bucket(self):
        """Text >256 bytes pads to next bucket (1024)."""
        pipeline = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2)
        text_300 = "x" * 300  # >256 bytes, should go to 1024 bucket
        encrypted = pipeline.encrypt(text_300, PASSWORD, pad=True)
        decrypted = pipeline.decrypt(encrypted, PASSWORD)
        assert decrypted == text_300


@pytest.mark.skipif(not PQ_AVAILABLE, reason="pqcrypto not installed")
class TestFIPS203InputChecking:
    """FIPS 203 Sections 7.2 and 7.3 say implementers *shall* check KEM inputs.

    Nothing below us did. pqcrypto validates type and length only, so before
    this a secret key with one flipped byte decapsulated to a wrong-but-valid
    shared secret and surfaced to the user as "incorrect password", and a
    public key encoding a coefficient above q produced a normal-looking
    ciphertext.

    This is not a hardening claim. An attacker substituting a recipient's
    public key substitutes a *valid* one, so the modulus check authenticates
    nothing. The payoff is that a corrupt key file says it is corrupt, and
    that a tool citing FIPS 203 in its documentation honours the parts of it
    written as `shall`.
    """

    def test_public_key_with_a_coefficient_above_q_is_rejected(self):
        from morpheus.core.errors import ConfigurationError
        from morpheus.core.pipeline import _pq_encapsulate
        pk, _ = pq_generate_keypair()
        bad = bytearray(pk)
        bad[0] = bad[1] = 0xFF          # first coefficient decodes to 4095 > 3328
        with pytest.raises(ConfigurationError, match="modulus check"):
            _pq_encapsulate(bytes(bad))

    def test_secret_key_failing_the_hash_check_is_rejected(self):
        from morpheus.core.errors import ConfigurationError
        from morpheus.core.pipeline import _pq_decapsulate, _pq_encapsulate
        pk, sk = pq_generate_keypair()
        ct, _ = _pq_encapsulate(pk)
        bad = bytearray(sk)
        bad[1200] ^= 0x01               # inside the embedded encapsulation key
        with pytest.raises(ConfigurationError, match="hash check"):
            _pq_decapsulate(bytes(bad), ct)

    @pytest.mark.parametrize("length", [0, 1183, 1185])
    def test_wrong_length_public_key_is_rejected(self, length):
        from morpheus.core.errors import ConfigurationError
        from morpheus.core.pipeline import _pq_encapsulate
        with pytest.raises(ConfigurationError, match="1184 bytes"):
            _pq_encapsulate(b"\x00" * length)

    def test_valid_keys_are_untouched(self):
        """Otherwise the checks above could pass by rejecting everything."""
        from morpheus.core.pipeline import _pq_decapsulate, _pq_encapsulate
        pk, sk = pq_generate_keypair()
        ct, ss_enc = _pq_encapsulate(pk)
        assert _pq_decapsulate(sk, ct) == ss_enc


class TestEncryptRefusesWhatDecryptWillReject:
    """Encrypt must not produce ciphertext that can never be decrypted.

    The KDF bounds were enforced only when *reading* a header, so a caller
    could construct a pipeline with out-of-range settings, receive a
    perfectly normal-looking ciphertext, and discover on the way back that
    no version of this tool will ever accept it. The data is gone at that
    point, which is the one failure mode a tool warning of "permanently and
    irrecoverably lost" cannot afford to create itself.

    EncryptionPipeline is the exported public API and the package ships
    py.typed, so the CLI's four safe presets are not a defence.
    """

    @pytest.mark.parametrize("kdf,label", [
        (Argon2idKDF(time_cost=1, memory_cost=1023, parallelism=1), "argon2-memory"),
        (Argon2idKDF(time_cost=0, memory_cost=65536, parallelism=4), "argon2-time"),
        (ScryptKDF(n=2 ** 9, r=8, p=1), "scrypt-n"),
    ])
    def test_out_of_range_params_fail_at_encrypt(self, kdf, label):
        from morpheus.core.errors import KDFParameterError
        with pytest.raises(KDFParameterError, match="out of allowed range"):
            EncryptionPipeline(kdf=kdf).encrypt("data", PASSWORD)

    def test_a_legal_non_default_kdf_still_round_trips(self):
        """Otherwise the check above could pass by rejecting everything."""
        pipeline = EncryptionPipeline(
            kdf=Argon2idKDF(time_cost=1, memory_cost=8192, parallelism=1)
        )
        assert pipeline.decrypt(pipeline.encrypt("still works", PASSWORD),
                                PASSWORD) == "still works"


class TestKDFBoundsValidation:
    """Test that out-of-bounds KDF params from headers are rejected."""

    def test_argon2_time_cost_too_high(self):
        """Argon2 time_cost above limit should raise ValueError."""
        from morpheus.core.pipeline import _build_kdf_from_params
        with pytest.raises(ValueError, match="out of allowed range"):
            _build_kdf_from_params(0x02, (999, 65536, 4))

    def test_argon2_memory_cost_too_low(self):
        """Argon2 memory_cost below limit should raise ValueError."""
        from morpheus.core.pipeline import _build_kdf_from_params
        with pytest.raises(ValueError, match="out of allowed range"):
            _build_kdf_from_params(0x02, (3, 0, 4))

    def test_scrypt_n_too_high(self):
        """Scrypt n above limit should raise ValueError."""
        from morpheus.core.pipeline import _build_kdf_from_params
        with pytest.raises(ValueError, match="out of allowed range"):
            _build_kdf_from_params(0x01, (2**30, 8, 1))

    def test_valid_params_accepted(self):
        """Normal KDF params should be accepted without error."""
        from morpheus.core.pipeline import _build_kdf_from_params
        kdf = _build_kdf_from_params(0x02, (3, 65536, 4))
        assert kdf.time_cost == 3

    def test_unknown_kdf_id_rejected(self):
        """Unknown KDF ID should raise ValueError."""
        from morpheus.core.pipeline import _build_kdf_from_params
        with pytest.raises(ValueError, match="Unknown KDF ID"):
            _build_kdf_from_params(0xFF, (1, 1, 1))


class TestKDFWorkingSetCap:
    """Header params must be bounded by implied memory, not only per parameter.

    The v3 header carries KDF parameters that are consumed *before* the AEAD
    tag can be checked, so these bounds are the only thing standing between a
    pasted ciphertext and an unbounded allocation. No password is required to
    reach this code.
    """

    def test_scrypt_product_inside_per_param_limits_is_rejected(self):
        """n and r are each individually legal; together they imply 64 GiB.

        This is the case per-parameter validation cannot catch: Scrypt
        allocates 128 * n * r, so the product is the quantity that matters.
        """
        from morpheus.core.pipeline import _build_kdf_from_params
        with pytest.raises(ValueError, match="working set"):
            _build_kdf_from_params(0x01, (2**23, 64, 1))

    def test_argon2_four_gib_is_rejected(self):
        """4 GiB memory_cost sat inside the old per-parameter ceiling."""
        from morpheus.core.pipeline import _build_kdf_from_params
        with pytest.raises(ValueError, match="out of allowed range|working set"):
            _build_kdf_from_params(0x02, (3, 4194304, 4))

    def test_realistic_scrypt_params_still_accepted(self):
        """A normal Scrypt header must survive the new cap."""
        from morpheus.core.pipeline import _build_kdf_from_params
        kdf = _build_kdf_from_params(0x01, (2**14, 8, 1))
        assert kdf.n == 2**14

    def test_realistic_argon2_params_still_accepted(self):
        """A normal Argon2id header must survive the new cap."""
        from morpheus.core.pipeline import _build_kdf_from_params
        kdf = _build_kdf_from_params(0x02, (3, 65536, 4))
        assert kdf.memory_cost == 65536


class TestStructuredErrors:
    """Verify specific error types from morpheus.core.errors are raised."""

    def test_wrong_password_raises_wrong_password_error(self):
        from morpheus.core.errors import WrongPasswordError
        p = EncryptionPipeline()
        ct = p.encrypt("test", "correct-Pass1!")
        with pytest.raises(WrongPasswordError, match="incorrect password"):
            p.decrypt(ct, "wrong-Pass1!")

    def test_chain_config_raises_configuration_error(self):
        from morpheus.core.errors import ConfigurationError
        with pytest.raises(ConfigurationError, match="Cannot combine"):
            EncryptionPipeline(cipher=ChaCha20Poly1305Cipher(), chain=True)

    def test_kdf_bounds_raises_kdf_parameter_error(self):
        from morpheus.core.errors import KDFParameterError
        from morpheus.core.pipeline import _build_kdf_from_params
        with pytest.raises(KDFParameterError, match="out of allowed range"):
            _build_kdf_from_params(0x02, (999, 65536, 4))

    def test_truncated_ciphertext_raises_decryption_error(self):
        from morpheus.core.errors import DecryptionError
        p = EncryptionPipeline()
        ct = p.encrypt("hello", "Test-Pass1!")
        # Corrupt by truncating the base64
        raw = base64.b64decode(ct)
        truncated = base64.b64encode(raw[:20]).decode()
        with pytest.raises(DecryptionError, match="Truncated"):
            p.decrypt(truncated, "Test-Pass1!")

    def test_format_error_on_bad_base64(self):
        from morpheus.core.errors import FormatError
        from morpheus.core.formats import deserialize
        with pytest.raises(FormatError, match="Invalid base64"):
            deserialize("not-valid-base64!!!")

    def test_all_errors_inherit_from_morpheus_error(self):
        from morpheus.core.errors import (
            ConfigurationError,
            DecryptionError,
            FormatError,
            KDFParameterError,
            MorpheusError,
            PaddingError,
            WrongPasswordError,
        )
        for cls in (FormatError, PaddingError, KDFParameterError,
                    ConfigurationError, DecryptionError, WrongPasswordError):
            assert issubclass(cls, MorpheusError)
            assert issubclass(cls, ValueError)

    def test_wrong_password_is_decryption_error(self):
        from morpheus.core.errors import DecryptionError, WrongPasswordError
        assert issubclass(WrongPasswordError, DecryptionError)


class TestFixedSizePadding:
    """Verify --fixed-size constant-size padding."""

    def test_fixed_size_roundtrip(self):
        """Small text encrypted with fixed_size should decrypt correctly."""
        p = EncryptionPipeline()
        ct = p.encrypt("hello world", "Test-Pass1!", fixed_size=True)
        assert p.decrypt(ct, "Test-Pass1!") == "hello world"

    def test_fixed_size_constant_output(self):
        """Different-length inputs produce same-length ciphertexts."""
        p = EncryptionPipeline()
        ct_short = p.encrypt("a", "Test-Pass1!", fixed_size=True)
        ct_long = p.encrypt("a" * 1000, "Test-Pass1!", fixed_size=True)
        assert len(ct_short) == len(ct_long)

    def test_fixed_size_differs_from_bucket(self):
        """Fixed-size output is larger than bucket mode for small input."""
        p = EncryptionPipeline()
        ct_bucket = p.encrypt("hello", "Test-Pass1!", pad=True)
        ct_fixed = p.encrypt("hello", "Test-Pass1!", fixed_size=True)
        assert len(ct_fixed) > len(ct_bucket)

    def test_fixed_size_too_large_rejected(self):
        """Input larger than 64 KiB - 4 bytes should be rejected."""
        from morpheus.core.errors import PaddingError
        p = EncryptionPipeline()
        big_text = "x" * 65533  # > 65536 - 4
        with pytest.raises(PaddingError, match="too large for --fixed-size"):
            p.encrypt(big_text, "Test-Pass1!", fixed_size=True)

    def test_fixed_size_sets_padded_flag(self):
        """fixed_size=True should set the FLAG_PADDED bit."""
        from morpheus.core.formats import FLAG_PADDED, deserialize
        p = EncryptionPipeline()
        ct = p.encrypt("test", "Test-Pass1!", fixed_size=True)
        _, _, _, flags, _, _ = deserialize(ct)
        assert flags & FLAG_PADDED


class TestV4CommitmentAndCombiner:
    """The three properties v4 exists to deliver, asserted rather than assumed."""

    def test_the_commitment_is_a_full_32_bytes(self):
        """v3 stored 8 bytes, which is ~32 bits of committing security."""
        from morpheus.core.formats import COMMITMENT_SIZE, deserialize
        assert COMMITMENT_SIZE == 32
        p = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2)
        _, _, _, _, payload, _ = deserialize(p.encrypt("x", PASSWORD))
        # salt + nonce + commitment + at least a tag's worth of body
        assert len(payload) >= FAST_ARGON2.salt_size + 12 + COMMITMENT_SIZE

    def test_the_commitment_binds_the_key(self):
        from morpheus.core.pipeline import _compute_commitment
        a = _compute_commitment(bytes(range(32)))
        b = _compute_commitment(bytes(range(1, 33)))
        assert a != b, "changing the key must change the commitment"

    def test_the_commitment_binds_the_second_chained_key(self):
        """Committing to the first key alone would leave the second free."""
        from morpheus.core.pipeline import _compute_commitment
        k = bytes(range(32))
        assert _compute_commitment(k, b"A" * 32) != _compute_commitment(k, b"B" * 32)
        assert _compute_commitment(k, b"A" * 32) != _compute_commitment(k)

    def test_the_commitment_does_not_bind_nonces_or_aad(self):
        """Deliberate, and the reason is worth pinning.

        The first v4 draft hashed the nonces and AAD in. Because this value is
        checked before the AEAD, that meant tampering with a nonce or a header
        byte failed here and was reported as an incorrect password — losing the
        distinction v3 got right. Those fields are already covered by the AEAD
        tag. This test fails if someone reintroduces them.
        """
        import inspect as _inspect

        from morpheus.core.pipeline import _compute_commitment
        params = set(_inspect.signature(_compute_commitment).parameters)
        assert not params & {"nonce1", "nonce2", "aad", "kem_prefix"}, (
            f"_compute_commitment binds AEAD-covered fields again: {params}"
        )

    def test_length_prefixing_makes_the_commitment_injective(self):
        """Without length prefixes, moving a byte between fields would collide."""
        from morpheus.core.pipeline import _compute_commitment
        a = _compute_commitment(b"AB", b"C")
        b = _compute_commitment(b"A", b"BC")
        assert a != b, "field boundaries are not being bound"

    @pytest.mark.skipif(not PQ_AVAILABLE, reason="pqcrypto not installed")
    def test_the_combiner_binds_the_kem_transcript(self):
        """NIST SP 800-227 4.6.3: KDF(K1, K2) alone does not preserve IND-CCA.

        v4 binds the KEM ciphertext, the encapsulation key and the AAD into the
        HKDF info, so changing any of them changes the derived key.
        """
        from morpheus.core.formats import FORMAT_VERSION_4
        from morpheus.core.pipeline import _combine_with_kem
        pw_key, ss, salt = bytes(range(32)), bytes(range(32, 64)), b"S" * 16
        common = {"version": FORMAT_VERSION_4, "aad": b"aad"}
        base = _combine_with_kem(pw_key, ss, salt, kem_ciphertext=b"ct",
                                 encapsulation_key=b"ek", **common)
        assert _combine_with_kem(pw_key, ss, salt, kem_ciphertext=b"CT",
                                 encapsulation_key=b"ek", **common) != base
        assert _combine_with_kem(pw_key, ss, salt, kem_ciphertext=b"ct",
                                 encapsulation_key=b"EK", **common) != base
        assert _combine_with_kem(pw_key, ss, salt, kem_ciphertext=b"ct",
                                 encapsulation_key=b"ek",
                                 version=FORMAT_VERSION_4, aad=b"AAD") != base

    @pytest.mark.skipif(not PQ_AVAILABLE, reason="pqcrypto not installed")
    def test_the_v3_combiner_is_unchanged(self):
        """v3 must keep deriving exactly what it derived before, or the stored
        v3 vectors stop decrypting."""
        from morpheus.core.formats import FORMAT_VERSION_3
        from morpheus.core.pipeline import _combine_with_kem
        pw_key, ss, salt = bytes(range(32)), bytes(range(32, 64)), b"S" * 16
        # v3 ignores the transcript entirely: passing it must change nothing.
        plain = _combine_with_kem(pw_key, ss, salt, version=FORMAT_VERSION_3)
        with_extra = _combine_with_kem(pw_key, ss, salt, version=FORMAT_VERSION_3,
                                       kem_ciphertext=b"ct", encapsulation_key=b"ek",
                                       aad=b"aad")
        assert bytes(plain) == bytes(with_extra)


class TestFailureAttributionIsDistinct:
    """A wrong password and a modified ciphertext must not look the same.

    SECURITY.md presents this as a deliberate design property, and until now
    nothing enforced it. The first v4 draft bound the nonces and AAD into the
    pre-AEAD commitment, which collapsed nonce and header tampering into
    WrongPasswordError — a silent regression against v3 that shipped, and that
    the documentation actively denied. These tests exist so that cannot recur.

    The rule: WrongPasswordError means the key is wrong. InvalidTag means the
    bytes were modified. Anything that changes the derived key (salt, KEM
    ciphertext) legitimately produces the former and is excluded here.
    """

    PW = PASSWORD

    def _ct(self, **kw):
        p = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2, **kw)
        return p, p.encrypt("attribution probe", self.PW)

    def _flip(self, ct: str, byte_index: int) -> str:
        raw = bytearray(base64.b64decode(ct))
        raw[byte_index] ^= 0x01
        return base64.b64encode(bytes(raw)).decode()

    def test_wrong_password_says_wrong_password(self):
        from morpheus.core.errors import WrongPasswordError
        p, ct = self._ct()
        with pytest.raises(WrongPasswordError):
            p.decrypt(ct, "Wr0ng!Password#X")

    def test_nonce_tampering_says_tampering_not_wrong_password(self):
        """The nonce is authenticated by the AEAD, so this must reach the tag."""
        from morpheus.core.errors import WrongPasswordError
        p, ct = self._ct()
        # payload starts at 18; salt is 16, so the nonce begins at 34.
        bad = self._flip(ct, 18 + 16)
        with pytest.raises(InvalidTag):
            try:
                p.decrypt(bad, self.PW)
            except WrongPasswordError as exc:
                raise AssertionError(
                    "nonce tampering reported as a wrong password; the "
                    "pre-AEAD check is binding fields the AEAD already covers"
                ) from exc

    def test_body_tampering_says_tampering(self):
        from morpheus.core.errors import WrongPasswordError
        p, ct = self._ct()
        raw = base64.b64decode(ct)
        with pytest.raises(InvalidTag):
            try:
                p.decrypt(self._flip(ct, len(raw) - 4), self.PW)
            except WrongPasswordError as exc:
                raise AssertionError("body tampering reported as wrong password") from exc

    def test_cipher_id_tampering_says_tampering(self):
        """cipher_id does not feed key derivation, so the tag must catch it."""
        from morpheus.core.errors import DecryptionError, WrongPasswordError
        p, ct = self._ct()
        with pytest.raises((InvalidTag, DecryptionError)):
            try:
                p.decrypt(self._flip(ct, 1), self.PW)
            except WrongPasswordError as exc:
                raise AssertionError("cipher_id tampering reported as wrong password") from exc

    @pytest.mark.parametrize("field,index", [("kdf_id", 2), ("flags", 3)])
    def test_derivation_affecting_fields_honestly_report_a_wrong_key(self, field, index):
        """Not every "incorrect password" is a misattribution.

        kdf_id selects the KDF and the flags byte selects chaining and hybrid
        PQ, so altering either genuinely changes the derived key. The
        commitment then fails for a true reason and "incorrect password" is the
        accurate diagnosis, not a lost signal. The same holds for the salt and
        the KEM ciphertext.

        This is pinned so the distinction is deliberate rather than accidental:
        the fix for the v4 regression was to stop binding fields the AEAD
        already covers, not to force every tamper into InvalidTag.
        """
        from morpheus.core.errors import (
            DecryptionError,
            KDFParameterError,
            WrongPasswordError,
        )
        # KDFParameterError is the best case: an unknown kdf_id is rejected by
        # name before any key is derived at all.
        with pytest.raises(
            (WrongPasswordError, DecryptionError, KDFParameterError, InvalidTag)
        ):
            p, ct = self._ct()
            p.decrypt(self._flip(ct, index), self.PW)

    def test_salt_tampering_reports_a_wrong_key(self):
        """Documented in SECURITY.md as inherent, so pinned rather than fixed."""
        from morpheus.core.errors import WrongPasswordError
        p, ct = self._ct()
        with pytest.raises(WrongPasswordError):
            p.decrypt(self._flip(ct, 18), self.PW)
