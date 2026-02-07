"""Tests for the encryption pipeline — roundtrips, chaining, and hybrid PQ."""

import pytest

from secure_encryption.core.ciphers import AES256GCM, ChaCha20Poly1305Cipher
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

    def test_wrong_password_fails(self):
        pipeline = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2)
        encrypted = pipeline.encrypt("secret data", PASSWORD)
        with pytest.raises(Exception):
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
        """Chaining always uses AES→ChaCha regardless of cipher param."""
        p1 = EncryptionPipeline(cipher=AES256GCM(), kdf=FAST_ARGON2, chain=True)
        p2 = EncryptionPipeline(cipher=ChaCha20Poly1305Cipher(), kdf=FAST_ARGON2, chain=True)
        ct = p1.encrypt("test", PASSWORD)
        # Both pipelines can decrypt because chain forces fixed order
        assert p2.decrypt(ct, PASSWORD) == "test"

    def test_chained_wrong_password(self):
        pipeline = EncryptionPipeline(
            cipher=AES256GCM(), kdf=FAST_ARGON2, chain=True,
        )
        encrypted = pipeline.encrypt("secret", PASSWORD)
        with pytest.raises(Exception):
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
        with pytest.raises(Exception):
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
        # Different KDF ID in header, should still parse but derive wrong key
        with pytest.raises(Exception):
            s.decrypt(ct, PASSWORD)
