"""Tests for the encryption pipeline — roundtrips, chaining, and hybrid PQ."""

import base64
import struct
import warnings

import pytest
from cryptography.exceptions import InvalidTag

from secure_encryption.core.ciphers import AES256GCM, ChaCha20Poly1305Cipher
from secure_encryption.core.formats import FLAG_CHAINED, FLAG_HYBRID_PQ, FORMAT_VERSION, HEADER_FORMAT
from secure_encryption.core.kdf import Argon2idKDF, ScryptKDF
from secure_encryption.core.pipeline import (
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

    def test_wrong_password_fails_with_invalid_tag(self):
        pipeline = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2)
        encrypted = pipeline.encrypt("secret data", PASSWORD)
        with pytest.raises(InvalidTag):
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
        """Chaining always uses AES->ChaCha regardless of cipher param."""
        p1 = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2, chain=True)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            p2 = EncryptionPipeline(cipher=ChaCha20Poly1305Cipher(), kdf=FAST_ARGON2, chain=True)
        ct = p1.encrypt("test", PASSWORD)
        # Both pipelines can decrypt because chain forces fixed order
        assert p2.decrypt(ct, PASSWORD) == "test"

    def test_chain_with_chacha_emits_warning(self):
        """Passing ChaCha as cipher with chain=True should emit a warning."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            EncryptionPipeline(cipher=ChaCha20Poly1305Cipher(), kdf=FAST_ARGON2, chain=True)
            assert len(w) == 1
            assert "overridden" in str(w[0].message).lower()

    def test_chained_wrong_password(self):
        pipeline = EncryptionPipeline(
            cipher=AES256GCM(), kdf=FAST_ARGON2, chain=True,
        )
        encrypted = pipeline.encrypt("secret", PASSWORD)
        with pytest.raises(InvalidTag):
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
        with pytest.raises(InvalidTag):
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

    def test_argon2_cannot_decrypt_scrypt(self):
        a = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2)
        s = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_SCRYPT)
        ct = a.encrypt("test", PASSWORD)
        with pytest.raises(ValueError, match="KDF"):
            s.decrypt(ct, PASSWORD)


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
