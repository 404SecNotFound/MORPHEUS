"""Tests for the encryption pipeline — roundtrips, chaining, and hybrid PQ."""

import base64
import struct

import pytest
from cryptography.exceptions import InvalidTag

from morpheus.core.ciphers import AES256GCM, ChaCha20Poly1305Cipher
from morpheus.core.formats import FLAG_CHAINED, FLAG_HYBRID_PQ, FORMAT_VERSION, FORMAT_VERSION_3, HEADER_FORMAT
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
        with pytest.raises(Exception):
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
        """Pipeline encrypt produces v3 format by default."""
        pipeline = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2)
        ct = pipeline.encrypt("test", PASSWORD)
        raw = base64.b64decode(ct)
        assert raw[0] == FORMAT_VERSION_3

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
            MorpheusError, FormatError, PaddingError,
            KDFParameterError, ConfigurationError,
            DecryptionError, WrongPasswordError,
        )
        for cls in (FormatError, PaddingError, KDFParameterError,
                    ConfigurationError, DecryptionError, WrongPasswordError):
            assert issubclass(cls, MorpheusError)
            assert issubclass(cls, ValueError)

    def test_wrong_password_is_decryption_error(self):
        from morpheus.core.errors import DecryptionError, WrongPasswordError
        assert issubclass(WrongPasswordError, DecryptionError)
