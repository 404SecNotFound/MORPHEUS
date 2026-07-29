"""Tests for CLI file encryption/decryption."""

import base64
import contextlib
import io
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from morpheus import __version__
from morpheus.__main__ import main
from morpheus.cli import (
    _diagnose_ciphertext,
    _padding_hint,
    _suggest_fix,
    run_cli,
)
from morpheus.core.errors import (
    ConfigurationError,
    DecryptionError,
    FormatError,
    WrongPasswordError,
)
from morpheus.core.pipeline import (
    PQ_AVAILABLE,
    EncryptionPipeline,
    pq_generate_keypair,
)


class TestFileEncryption:
    """Test the -f/--file flag for file-based encrypt/decrypt."""

    def test_file_encrypt_decrypt_roundtrip(self):
        """Encrypt a file and decrypt it back to the original."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a test file
            original = os.path.join(tmpdir, "secret.txt")
            with open(original, "w") as f:
                f.write("Top secret contents\nLine 2\n")

            encrypted = os.path.join(tmpdir, "secret.txt.enc")

            # Encrypt (password + confirmation via stdin fallback)
            old_stdin = sys.stdin
            # Two lines: password + confirmation (getpass fallback reads from stdin)
            sys.stdin = io.StringIO("T3st!Passw0rd#Str0ng\nT3st!Passw0rd#Str0ng\n")

            try:
                run_cli([
                    "-o", "encrypt",
                    "-f", original,
                    "--output", encrypted,
                ])
            finally:
                sys.stdin = old_stdin

            assert os.path.exists(encrypted)

            # Decrypt (single password, no confirmation)
            decrypted = os.path.join(tmpdir, "decrypted.txt")
            sys.stdin = io.StringIO("T3st!Passw0rd#Str0ng\n")

            try:
                run_cli([
                    "-o", "decrypt",
                    "-f", encrypted,
                    "--output", decrypted,
                ])
            finally:
                sys.stdin = old_stdin

            assert os.path.exists(decrypted)
            with open(decrypted, "r") as f:
                content = f.read()
            assert content == "Top secret contents\nLine 2\n"

    def test_file_binary_roundtrip(self):
        """Encrypt and decrypt a binary file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            original = os.path.join(tmpdir, "data.bin")
            binary_data = os.urandom(1024)
            with open(original, "wb") as f:
                f.write(binary_data)

            encrypted = os.path.join(tmpdir, "data.bin.enc")

            old_stdin = sys.stdin
            # Two lines: password + confirmation for encrypt
            sys.stdin = io.StringIO("T3st!Passw0rd#Str0ng\nT3st!Passw0rd#Str0ng\n")
            try:
                run_cli(["-o", "encrypt", "-f", original, "--output", encrypted])
            finally:
                sys.stdin = old_stdin

            assert os.path.exists(encrypted)

            decrypted = os.path.join(tmpdir, "data_out.bin")
            sys.stdin = io.StringIO("T3st!Passw0rd#Str0ng\n")
            try:
                run_cli(["-o", "decrypt", "-f", encrypted, "--output", decrypted])
            finally:
                sys.stdin = old_stdin

            with open(decrypted, "rb") as f:
                result = f.read()
            assert result == binary_data

    def test_path_traversal_sanitized(self):
        """Decrypting a file with a path-traversal filename in the envelope
        must NOT write outside the current directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Build a malicious envelope with a path-traversal filename
            malicious_name = "../../etc/evil.txt"
            payload_data = b"harmless content"
            envelope = json.dumps({
                "filename": malicious_name,
                "data": base64.b64encode(payload_data).decode(),
            })

            # Encrypt the malicious envelope through the pipeline
            password = "T3st!Passw0rd#Str0ng"
            pipeline = EncryptionPipeline()
            encrypted = pipeline.encrypt(envelope, password)

            # Write encrypted data to a file
            enc_file = os.path.join(tmpdir, "malicious.enc")
            with open(enc_file, "w") as f:
                f.write(encrypted)

            # Decrypt without --output (should use sanitized filename)
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            old_stdin = sys.stdin
            sys.stdin = io.StringIO(password + "\n")
            try:
                run_cli(["-o", "decrypt", "-f", enc_file])
            finally:
                sys.stdin = old_stdin
                os.chdir(old_cwd)

            # The output should be "evil.txt" in tmpdir, NOT ../../etc/evil.txt
            safe_output = os.path.join(tmpdir, "evil.txt")
            assert os.path.exists(safe_output), "Sanitized file should exist in tmpdir"
            with open(safe_output, "rb") as f:
                assert f.read() == payload_data

            # Verify the traversal path was NOT created
            traversal_path = os.path.join(tmpdir, malicious_name)
            assert not os.path.exists(traversal_path)

    def test_file_too_large_rejected(self):
        """Files exceeding 100 MiB must be rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            big_file = os.path.join(tmpdir, "huge.bin")
            # Create a sparse file that reports > 100 MiB without using real disk
            with open(big_file, "wb") as f:
                f.seek(100 * 1024 * 1024 + 1)
                f.write(b"\x00")

            old_stdin = sys.stdin
            sys.stdin = io.StringIO("T3st!Passw0rd#Str0ng\nT3st!Passw0rd#Str0ng\n")
            try:
                with pytest.raises(SystemExit):
                    run_cli(["-o", "encrypt", "-f", big_file])
            finally:
                sys.stdin = old_stdin

    def test_overwrite_protection(self):
        """Existing output files must not be silently overwritten."""
        with tempfile.TemporaryDirectory() as tmpdir:
            original = os.path.join(tmpdir, "doc.txt")
            with open(original, "w") as f:
                f.write("hello")

            encrypted = os.path.join(tmpdir, "doc.txt.enc")
            # Create a pre-existing file at the output path
            with open(encrypted, "w") as f:
                f.write("existing content")

            old_stdin = sys.stdin
            sys.stdin = io.StringIO("T3st!Passw0rd#Str0ng\nT3st!Passw0rd#Str0ng\n")
            try:
                with pytest.raises(SystemExit):
                    run_cli(["-o", "encrypt", "-f", original, "--output", encrypted])
            finally:
                sys.stdin = old_stdin

            # Verify original content was NOT overwritten
            with open(encrypted, "r") as f:
                assert f.read() == "existing content"

    def test_overwrite_with_force_flag(self):
        """--force allows overwriting existing output files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            original = os.path.join(tmpdir, "doc.txt")
            with open(original, "w") as f:
                f.write("hello")

            encrypted = os.path.join(tmpdir, "doc.txt.enc")
            with open(encrypted, "w") as f:
                f.write("old")

            old_stdin = sys.stdin
            sys.stdin = io.StringIO("T3st!Passw0rd#Str0ng\nT3st!Passw0rd#Str0ng\n")
            try:
                run_cli([
                    "-o", "encrypt", "-f", original,
                    "--output", encrypted, "--force",
                ])
            finally:
                sys.stdin = old_stdin

            # File was overwritten with new encrypted content
            with open(encrypted, "r") as f:
                content = f.read()
            assert content != "old"
            assert len(content) > 0

    def test_envelope_version_roundtrip(self):
        """Encrypted files include envelope_version and decrypt correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            original = os.path.join(tmpdir, "versioned.txt")
            with open(original, "w") as f:
                f.write("versioned content")

            encrypted = os.path.join(tmpdir, "versioned.txt.enc")

            old_stdin = sys.stdin
            sys.stdin = io.StringIO("T3st!Passw0rd#Str0ng\nT3st!Passw0rd#Str0ng\n")
            try:
                run_cli(["-o", "encrypt", "-f", original, "--output", encrypted])
            finally:
                sys.stdin = old_stdin

            # Decrypt and verify the envelope contains version info
            password = "T3st!Passw0rd#Str0ng"
            pipeline = EncryptionPipeline()
            with open(encrypted, "r") as f:
                enc_data = f.read().strip()
            decrypted_envelope = pipeline.decrypt(enc_data, password)
            envelope = json.loads(decrypted_envelope)
            assert envelope["envelope_version"] == 1
            assert envelope["filename"] == "versioned.txt"


class TestDiagnoseCiphertext:
    """Test the ciphertext diagnosis helper for error context."""

    def test_v3_aes_argon2(self):
        """Diagnose a standard v3 AES+Argon2 ciphertext."""
        p = EncryptionPipeline()
        ct = p.encrypt("test", "Test-Pass1!")
        diag = _diagnose_ciphertext(ct)
        assert "v3" in diag
        assert "AES-256-GCM" in diag
        assert "Argon2id" in diag
        assert "t=3" in diag

    def test_v3_chained(self):
        """Diagnose a chained ciphertext."""
        p = EncryptionPipeline(chain=True)
        ct = p.encrypt("test", "Test-Pass1!")
        diag = _diagnose_ciphertext(ct)
        assert "chained" in diag.lower()

    def test_v3_padded_flag(self):
        """Diagnose a padded ciphertext shows the flag."""
        p = EncryptionPipeline()
        ct = p.encrypt("test", "Test-Pass1!", pad=True)
        diag = _diagnose_ciphertext(ct)
        assert "padded" in diag.lower()

    def test_invalid_input_returns_empty(self):
        """Invalid base64 should return empty string, not crash."""
        assert _diagnose_ciphertext("not-valid!!!") == ""

    def test_empty_input_returns_empty(self):
        assert _diagnose_ciphertext("") == ""


class TestBenchmark:
    """Test the --benchmark command runs without error."""

    def test_benchmark_runs(self, capsys):
        """--benchmark should produce output and exit cleanly."""
        run_cli(["--benchmark"])
        captured = capsys.readouterr()
        assert "MORPHEUS Hardware Benchmark" in captured.out
        assert "Recommended" in captured.out
        assert "Argon2id" in captured.out
        assert "AES-256-GCM" in captured.out


class TestPassphraseMode:
    """Test --passphrase flag for word-based password validation."""

    def test_passphrase_mode_accepts_word_based(self):
        """A strong passphrase without digits/specials should be accepted."""
        old_stdin = sys.stdin
        passphrase = "correct horse battery staple"
        sys.stdin = io.StringIO(f"{passphrase}\n{passphrase}\n")
        try:
            run_cli([
                "-o", "encrypt",
                "--data", "test message",
                "--passphrase",
            ])
        finally:
            sys.stdin = old_stdin

    def test_passphrase_mode_rejects_short(self):
        """A passphrase with too few words should be rejected."""
        old_stdin = sys.stdin
        sys.stdin = io.StringIO("two words\ntwo words\n")
        try:
            with pytest.raises(SystemExit):
                run_cli([
                    "-o", "encrypt",
                    "--data", "test message",
                    "--passphrase",
                ])
        finally:
            sys.stdin = old_stdin

    def test_normal_mode_rejects_passphrase(self):
        """Without --passphrase, a word-only password fails standard check."""
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(
            "correct horse battery staple\ncorrect horse battery staple\n"
        )
        try:
            with pytest.raises(SystemExit):
                run_cli([
                    "-o", "encrypt",
                    "--data", "test message",
                ])
        finally:
            sys.stdin = old_stdin


class TestSaveConfig:
    """Test --save-config flag."""

    def test_save_config_creates_file(self, capsys):
        """--save-config should write config.toml.

        Uses --pad rather than --chain for the boolean: --chain is only valid
        with AES-256-GCM, and persisting it alongside ChaCha20-Poly1305 would
        store a combination that fails on every later run.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_file = Path(tmpdir) / "config.toml"
            with patch("morpheus.cli.save_config") as mock_save:
                mock_save.return_value = cfg_file
                run_cli(["--save-config", "--cipher", "ChaCha20-Poly1305", "--pad"])
            mock_save.assert_called_once()
            call_args = mock_save.call_args[0][0]
            assert call_args["cipher"] == "ChaCha20-Poly1305"
            assert call_args["pad"] is True

    def test_save_config_refuses_an_unusable_combination(self, capsys):
        """--chain with a non-AES cipher must not be persisted.

        Saving it would produce a config that makes every later invocation
        fail with an error naming flags the user is no longer passing.
        """
        with patch("morpheus.cli.save_config") as mock_save:
            with pytest.raises(SystemExit) as exc:
                run_cli(["--save-config", "--cipher", "ChaCha20-Poly1305",
                         "--chain"])
            assert exc.value.code == 2
        assert not mock_save.called


class TestCheckLeaks:
    """Test --check-leaks flag (mocked network)."""

    @staticmethod
    def _mock_urlopen(body: bytes):
        """urlopen is a context manager; the mock must behave like one."""
        resp = MagicMock()
        resp.read.return_value = body
        cm = MagicMock()
        cm.__enter__.return_value = resp
        cm.__exit__.return_value = False
        return cm

    def test_leaked_password_blocks_encrypt(self):
        """A known-breached password should block encryption."""
        # SHA-1("T3st!Passw0rd#Str0ng") — we mock the response to contain its suffix
        import hashlib
        sha1 = hashlib.sha1(b"T3st!Passw0rd#Str0ng", usedforsecurity=False).hexdigest().upper()
        suffix = sha1[5:]
        fake_response = self._mock_urlopen(f"{suffix}:42\r\n".encode())

        old_stdin = sys.stdin
        sys.stdin = io.StringIO("T3st!Passw0rd#Str0ng\nT3st!Passw0rd#Str0ng\n")
        try:
            with patch("morpheus.core.validation.urllib.request.urlopen",
                        return_value=fake_response):
                with pytest.raises(SystemExit):
                    run_cli([
                        "-o", "encrypt",
                        "--data", "test message",
                        "--check-leaks",
                    ])
        finally:
            sys.stdin = old_stdin

    def test_safe_password_proceeds(self):
        """A non-breached password should allow encryption to proceed."""
        fake_response = self._mock_urlopen(b"0000000000000000000000000000000000A:1\r\n")

        old_stdin = sys.stdin
        sys.stdin = io.StringIO("T3st!Passw0rd#Str0ng\nT3st!Passw0rd#Str0ng\n")
        try:
            with patch("morpheus.core.validation.urllib.request.urlopen",
                        return_value=fake_response):
                run_cli([
                    "-o", "encrypt",
                    "--data", "test message",
                    "--check-leaks",
                ])
        finally:
            sys.stdin = old_stdin

    def test_network_error_proceeds_with_warning(self, capsys):
        """Network failure should warn but not block encryption."""
        import urllib.error

        old_stdin = sys.stdin
        sys.stdin = io.StringIO("T3st!Passw0rd#Str0ng\nT3st!Passw0rd#Str0ng\n")
        try:
            with patch(
                "morpheus.core.validation.urllib.request.urlopen",
                side_effect=urllib.error.URLError("no network"),
            ):
                run_cli([
                    "-o", "encrypt",
                    "--data", "test message",
                    "--check-leaks",
                ])
            captured = capsys.readouterr()
            assert "breach check failed" in captured.err
        finally:
            sys.stdin = old_stdin


class TestInspect:
    """Test --inspect command for ciphertext triage."""

    def test_inspect_v3_aes(self, capsys):
        """Inspecting a v3 AES ciphertext shows all header details."""
        p = EncryptionPipeline()
        ct = p.encrypt("hello world", "Test-Pass1!")
        run_cli(["--inspect", "--data", ct])
        out = capsys.readouterr().out
        assert "MORPHEUS Ciphertext Inspection" in out
        assert "v3" in out
        assert "AES-256-GCM" in out
        assert "Argon2id" in out
        assert "Total size" in out
        assert "Payload" in out

    def test_inspect_chained_padded(self, capsys):
        """Inspecting a chained+padded ciphertext shows flags."""
        p = EncryptionPipeline(chain=True)
        ct = p.encrypt("data", "Test-Pass1!", pad=True)
        run_cli(["--inspect", "--data", ct])
        out = capsys.readouterr().out
        assert "chained" in out.lower()
        assert "padded" in out.lower()

    def test_inspect_from_file(self, capsys):
        """--inspect with --file reads from a file."""
        p = EncryptionPipeline()
        ct = p.encrypt("test", "Test-Pass1!")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".enc", delete=False) as f:
            f.write(ct)
            f.flush()
            try:
                run_cli(["--inspect", "-f", f.name])
                out = capsys.readouterr().out
                assert "AES-256-GCM" in out
            finally:
                os.unlink(f.name)

    def test_inspect_invalid_data_exits(self):
        """Invalid ciphertext should cause --inspect to exit with error."""
        with pytest.raises(SystemExit):
            run_cli(["--inspect", "--data", "not-valid-base64!!!"])

    def test_inspect_no_password_needed(self, capsys):
        """--inspect should work without any password interaction."""
        p = EncryptionPipeline()
        ct = p.encrypt("test", "Test-Pass1!")
        # No stdin manipulation needed — inspect doesn't ask for password
        run_cli(["--inspect", "--data", ct])
        out = capsys.readouterr().out
        assert "Inspection" in out


class TestSuggestFix:
    """Test the error diagnosis suggestion helper."""

    def test_wrong_password_suggestion(self):
        exc = WrongPasswordError("Key verification failed")
        result = _suggest_fix(exc)
        assert "password" in result.lower()
        assert "caps lock" in result.lower()

    def test_format_error_suggestion(self):
        exc = FormatError("Invalid base64")
        result = _suggest_fix(exc)
        assert "doesn't look like MORPHEUS" in result

    def test_config_error_pq_suggestion(self):
        exc = ConfigurationError("Hybrid PQ requires a secret key")
        result = _suggest_fix(exc)
        assert "--hybrid-pq" in result
        assert "--pq-secret-key" in result

    def test_truncated_suggestion(self):
        exc = DecryptionError("Truncated ciphertext: need 28 bytes")
        result = _suggest_fix(exc)
        assert "incomplete" in result.lower()

    def test_unknown_cipher_suggestion(self):
        exc = DecryptionError("Unknown cipher ID 0xff")
        result = _suggest_fix(exc)
        assert "update" in result.lower()

    def test_invalid_tag_suggestion(self):
        from cryptography.exceptions import InvalidTag
        exc = InvalidTag()
        result = _suggest_fix(exc)
        assert "wrong password" in result.lower() or "tampered" in result.lower()


class TestPaddingHint:
    """Test the padding advisor hint."""

    def test_no_padding_shows_hint(self):
        hint = _padding_hint(100, used_pad=False, used_fixed=False)
        assert "--pad" in hint
        assert "--fixed-size" in hint

    def test_pad_shows_bucket_info(self):
        hint = _padding_hint(100, used_pad=True, used_fixed=False)
        assert "bucket" in hint.lower()
        assert "256B" in hint

    def test_pad_larger_data_shows_bigger_bucket(self):
        hint = _padding_hint(500, used_pad=True, used_fixed=False)
        assert "1K" in hint

    def test_fixed_size_no_hint(self):
        hint = _padding_hint(100, used_pad=False, used_fixed=True)
        assert hint == ""

    def test_pad_16k_bucket(self):
        hint = _padding_hint(5000, used_pad=True, used_fixed=False)
        assert "16K" in hint


class TestProgressFeedback:
    """Test that progress messages appear during encrypt/decrypt."""

    def test_encrypt_shows_progress(self, capsys):
        """Encryption should show KDF progress on stderr."""
        old_stdin = sys.stdin
        sys.stdin = io.StringIO("T3st!Passw0rd#Str0ng\nT3st!Passw0rd#Str0ng\n")
        try:
            run_cli(["-o", "encrypt", "--data", "test message"])
        finally:
            sys.stdin = old_stdin
        captured = capsys.readouterr()
        assert "Deriving key" in captured.err
        assert "Argon2id" in captured.err

    def test_decrypt_shows_progress(self, capsys):
        """Decryption should show progress on stderr."""
        p = EncryptionPipeline()
        ct = p.encrypt("test message", "T3st!Passw0rd#Str0ng")
        old_stdin = sys.stdin
        sys.stdin = io.StringIO("T3st!Passw0rd#Str0ng\n")
        try:
            run_cli(["-o", "decrypt", "--data", ct])
        finally:
            sys.stdin = old_stdin
        captured = capsys.readouterr()
        assert "Deriving key" in captured.err or "decrypting" in captured.err.lower()

    def test_encrypt_no_pad_shows_hint(self, capsys):
        """Encryption without --pad should show a padding hint."""
        old_stdin = sys.stdin
        sys.stdin = io.StringIO("T3st!Passw0rd#Str0ng\nT3st!Passw0rd#Str0ng\n")
        try:
            run_cli(["-o", "encrypt", "--data", "test message"])
        finally:
            sys.stdin = old_stdin
        captured = capsys.readouterr()
        assert "--pad" in captured.err or "--fixed-size" in captured.err


PW = "T3st!Passw0rd#Str0ng"


class TestNoFilenameRoundtrip:
    """--no-filename must still decrypt back to the original bytes.

    Regression: the decrypt branch required both 'data' and 'filename' in the
    envelope, so --no-filename fell through to a fallback that wrote the raw
    JSON envelope instead of the file.
    """

    def test_no_filename_file_roundtrip_recovers_original_bytes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            original = os.path.join(tmpdir, "secret.bin")
            payload = b"TOPSECRET-ORIGINAL-CONTENT-DO-NOT-LOSE\x00\xff binary"
            with open(original, "wb") as f:
                f.write(payload)

            encrypted = os.path.join(tmpdir, "ct.enc")
            recovered = os.path.join(tmpdir, "out.bin")

            old_stdin = sys.stdin
            sys.stdin = io.StringIO(f"{PW}\n{PW}\n")
            try:
                run_cli(["-o", "encrypt", "-f", original,
                         "--no-filename", "--output", encrypted])
            finally:
                sys.stdin = old_stdin

            sys.stdin = io.StringIO(f"{PW}\n")
            try:
                run_cli(["-o", "decrypt", "-f", encrypted, "--output", recovered])
            finally:
                sys.stdin = old_stdin

            with open(recovered, "rb") as f:
                got = f.read()
            assert got == payload, (
                "decrypt wrote the JSON envelope instead of the original bytes"
            )


class TestDecryptNeverOverwritesInput:
    """Decrypt must refuse to write its output over its own input.

    Regression: when the ciphertext filename did not end in '.enc',
    removesuffix('.enc') returned the path unchanged, so out_path == file_path
    and the ciphertext was destroyed in place.
    """

    @staticmethod
    def _encrypt_to(tmpdir, ct_name, payload=b"TOPSECRET-ORIGINAL-CONTENT",
                    no_filename=False):
        original = os.path.join(tmpdir, "secret.bin")
        with open(original, "wb") as f:
            f.write(payload)
        encrypted = os.path.join(tmpdir, ct_name)
        argv = ["-o", "encrypt", "-f", original, "--output", encrypted]
        if no_filename:
            argv.append("--no-filename")
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(f"{PW}\n{PW}\n")
        try:
            run_cli(argv)
        finally:
            sys.stdin = old_stdin
        return encrypted

    def test_ciphertext_survives_decrypt_when_name_lacks_enc_suffix(self):
        """The ciphertext must not be destroyed in place.

        Uses --no-filename so the envelope carries no name, which is what
        forces the output path to be derived from the input path. Runs with
        the cwd inside tmpdir because decrypt writes relative paths there.
        """
        old_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmpdir:
            # Name deliberately does NOT end in .enc, so removesuffix is a no-op
            encrypted = self._encrypt_to(tmpdir, "backup.dat", no_filename=True)
            with open(encrypted, "rb") as f:
                before = f.read()

            old_stdin = sys.stdin
            sys.stdin = io.StringIO(f"{PW}\n")
            os.chdir(tmpdir)
            try:
                run_cli(["-o", "decrypt", "-f", encrypted, "--force"])
            finally:
                sys.stdin = old_stdin
                os.chdir(old_cwd)

            with open(encrypted, "rb") as f:
                after = f.read()
            assert after == before, (
                "decrypt overwrote its own input, destroying the ciphertext"
            )
            # And the plaintext landed somewhere recoverable
            assert os.path.exists(encrypted + ".decrypted")

    def test_explicit_output_equal_to_input_is_refused(self):
        """Even when asked directly, refuse to write output over the input."""
        with tempfile.TemporaryDirectory() as tmpdir:
            encrypted = self._encrypt_to(tmpdir, "ct.enc")
            with open(encrypted, "rb") as f:
                before = f.read()

            old_stdin = sys.stdin
            sys.stdin = io.StringIO(f"{PW}\n")
            try:
                with pytest.raises(SystemExit) as exc:
                    run_cli(["-o", "decrypt", "-f", encrypted,
                             "--output", encrypted, "--force"])
                assert exc.value.code != 0
            finally:
                sys.stdin = old_stdin

            with open(encrypted, "rb") as f:
                after = f.read()
            assert after == before, "ciphertext was destroyed despite the guard"


class TestPQKeyRequiresHybridFlag:
    """A PQ key without --hybrid-pq must not silently produce weaker ciphertext.

    Regression: the PQ key-parsing block sat under `if args.hybrid_pq:`, so
    passing --pq-public-key alone produced ordinary password-only ciphertext
    with no warning, while the user believed it was quantum-resistant.
    """

    # Correct ML-KEM-768 public key length; contents are irrelevant because the
    # flag-combination check must happen before any KEM operation.
    DUMMY_PK = base64.b64encode(b"\x00" * 1184).decode()
    DUMMY_SK = base64.b64encode(b"\x00" * 2400).decode()

    def test_public_key_without_hybrid_pq_is_rejected(self, capsys):
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(f"{PW}\n{PW}\n")
        try:
            with pytest.raises(SystemExit) as exc:
                run_cli(["-o", "encrypt", "--data", "secret",
                         "--pq-public-key", self.DUMMY_PK])
            assert exc.value.code != 0
        finally:
            sys.stdin = old_stdin
        assert "--hybrid-pq" in capsys.readouterr().err

    def test_secret_key_without_hybrid_pq_is_rejected(self, capsys):
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(f"{PW}\n")
        try:
            with pytest.raises(SystemExit) as exc:
                run_cli(["-o", "decrypt", "--data", "AwEC",
                         "--pq-secret-key", self.DUMMY_SK])
            assert exc.value.code != 0
        finally:
            sys.stdin = old_stdin
        assert "--hybrid-pq" in capsys.readouterr().err


@pytest.mark.skipif(
    os.name != "posix",
    reason="POSIX file modes, O_NOFOLLOW and unprivileged symlinks; "
           "Windows is in the CI matrix and has none of the three",
)
class TestOutputFilePermissions:
    """Output files must be owner-only and never reached through a symlink.

    Both the ciphertext and the decrypted plaintext were previously created
    with a bare ``open()``, so they inherited the umask (``-rw-r--r--`` under
    the default 022) and followed a symlink sitting at the output path.
    """

    @pytest.fixture(autouse=True)
    def permissive_umask(self):
        """Pin a permissive umask so the mode assertions cannot pass by luck.

        Under ``umask 077`` a bare ``open()`` already yields 0600, which would
        make these tests green against the unfixed code.
        """
        old = os.umask(0o022)
        yield
        os.umask(old)

    def _encrypt_to(self, src, dst):
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(f"{PW}\n{PW}\n")
        try:
            run_cli(["-o", "encrypt", "-f", src, "--output", dst])
        finally:
            sys.stdin = old_stdin

    def _decrypt_to(self, src, dst):
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(f"{PW}\n")
        try:
            run_cli(["-o", "decrypt", "-f", src, "--output", dst])
        finally:
            sys.stdin = old_stdin

    @staticmethod
    def _make_source(tmpdir):
        src = os.path.join(tmpdir, "secret.txt")
        with open(src, "w") as f:
            f.write("classified contents\n")
        return src

    def test_ciphertext_is_owner_only(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src = self._make_source(tmpdir)
            enc = os.path.join(tmpdir, "secret.txt.enc")
            self._encrypt_to(src, enc)
            assert os.stat(enc).st_mode & 0o777 == 0o600

    def test_decrypted_plaintext_is_owner_only(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src = self._make_source(tmpdir)
            enc = os.path.join(tmpdir, "secret.txt.enc")
            dec = os.path.join(tmpdir, "out.txt")
            self._encrypt_to(src, enc)
            self._decrypt_to(enc, dec)
            assert os.stat(dec).st_mode & 0o777 == 0o600

    def test_decrypt_refuses_dangling_symlink_output(self):
        """A dangling symlink at the output path must not be followed.

        ``os.path.exists()`` is False for a dangling link, so the overwrite
        guard never fires; without O_NOFOLLOW the plaintext lands on the
        link's target. The target here stands in for a file outside the
        directory the user thought they were writing to.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            src = self._make_source(tmpdir)
            enc = os.path.join(tmpdir, "secret.txt.enc")
            self._encrypt_to(src, enc)

            target = os.path.join(tmpdir, "PWNED.target")
            link = os.path.join(tmpdir, "notes.txt")
            os.symlink(target, link)
            assert not os.path.exists(target)

            with pytest.raises(SystemExit) as exc:
                self._decrypt_to(enc, link)
            assert exc.value.code != 0
            assert not os.path.exists(target), "write followed the symlink"


class TestStdoutIsPipeable:
    """stdout must carry the payload and nothing else.

    The banner was printed to stdout ahead of the ciphertext, so the obvious
    `encrypt | decrypt --data -` round-trip failed with "This doesn't look
    like MORPHEUS ciphertext".
    """

    def test_encrypt_output_round_trips_through_stdout(self, capsys):
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(f"{PW}\n{PW}\n")
        try:
            run_cli(["-o", "encrypt", "--data", "piped secret"])
        finally:
            sys.stdin = old_stdin
        payload = capsys.readouterr().out.strip()

        assert payload, "nothing was written to stdout"
        assert "Encrypted" not in payload, "banner leaked onto stdout"
        assert "\n" not in payload, "stdout carried more than the payload"

        sys.stdin = io.StringIO(f"{PW}\n")
        try:
            run_cli(["-o", "decrypt", "--data", payload])
        finally:
            sys.stdin = old_stdin
        assert capsys.readouterr().out.strip() == "piped secret"


class TestFailsBeforeThePasswordPrompt:
    """Argument conflicts decidable from argv must not cost a password entry.

    --chain with a non-AES cipher raised ConfigurationError from the pipeline
    constructor, which runs *after* the user has typed and confirmed their
    password.
    """

    def test_chain_with_chacha_is_an_argparse_error(self, capsys):
        old_stdin = sys.stdin
        # Empty stdin: if the CLI reaches the prompt it fails differently.
        sys.stdin = io.StringIO("")
        try:
            with pytest.raises(SystemExit) as exc:
                run_cli(["-o", "encrypt", "--data", "x", "--chain",
                         "--cipher", "ChaCha20-Poly1305"])
            assert exc.value.code == 2, "should be an argparse usage error"
        finally:
            sys.stdin = old_stdin
        err = capsys.readouterr().err
        assert "--chain" in err
        # Assert on the prompt itself, not the word "password": the error text
        # may legitimately mention passwords while never having asked for one.
        assert "enter password" not in err.lower(), "prompted before rejecting"

    def test_hybrid_pq_without_pqcrypto_is_rejected_before_the_prompt(self, capsys):
        """Availability is known at parse time, so the prompt is wasted work.

        Found in UAT (DEF-001) by walking the documented first-contact path:
        `pip install -r requirements.txt` deliberately omits pqcrypto, and the
        README presents hybrid PQ as the headline feature, so a new user's
        first attempt lands here. The old behaviour asked for a password,
        asked again to confirm it, and only then said pqcrypto was missing.
        """
        old_stdin = sys.stdin
        sys.stdin = io.StringIO("")
        try:
            with patch("morpheus.cli.PQ_AVAILABLE", False):
                with pytest.raises(SystemExit) as exc:
                    run_cli(["-o", "encrypt", "--data", "x", "--hybrid-pq"])
                assert exc.value.code == 2, "should be an argparse usage error"
        finally:
            sys.stdin = old_stdin
        err = capsys.readouterr().err
        assert "pqcrypto" in err, "must name the missing package"
        # Assert on the prompt itself, not the word "password": the error text
        # may legitimately mention passwords while never having asked for one.
        assert "enter password" not in err.lower(), "prompted before rejecting"

    def test_hybrid_pq_still_works_when_pqcrypto_is_present(self):
        """The new gate must not fire on a correctly installed system."""
        if not PQ_AVAILABLE:
            pytest.skip("pqcrypto not installed")
        pk, _ = pq_generate_keypair()
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(f"{PW}\n{PW}\n")
        try:
            run_cli(["-o", "encrypt", "--data", "still works", "--hybrid-pq",
                     "--pq-public-key", base64.b64encode(pk).decode()])
        finally:
            sys.stdin = old_stdin


class TestVersionFlag:
    """`--version` must exist, and must report the real package version.

    Found in UAT (DEF-002): `--version` exited 2 with "unrecognized
    arguments". Nothing documented it, so it was never a false claim, but it
    is the first thing an issue reporter is asked to supply.
    """

    def test_version_flag_exits_zero_and_prints_the_version(self, capsys):
        with pytest.raises(SystemExit) as exc:
            run_cli(["--version"])
        assert exc.value.code == 0, "--version succeeds; it is not a usage error"
        out = capsys.readouterr().out
        assert __version__ in out, "must report the package version"

    def test_packaging_version_matches_the_package_version(self):
        """pyproject.toml carries a hand-written version, so it can drift.

        A `--version` flag that reports a number disagreeing with the
        installed distribution is worse than no flag, because it sends issue
        reporters chasing the wrong build. This repo has already shipped one
        round of version drift (B10a), so the pair is asserted rather than
        assumed.
        """
        pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
        match = re.search(
            r'^version\s*=\s*"([^"]+)"', pyproject.read_text(), re.MULTILINE
        )
        assert match, "pyproject.toml has no project version to compare against"
        assert match.group(1) == __version__, (
            f"pyproject.toml says {match.group(1)}, "
            f"morpheus.__version__ says {__version__}"
        )


class TestTopLevelExceptionHandler:
    """An unexpected exception must not print a traceback to the user.

    Raw tracebacks disclose absolute install paths and are unactionable.
    """

    def test_unexpected_error_is_reported_without_a_traceback(self, capsys):
        with patch("morpheus.cli.run_cli", side_effect=RuntimeError("boom")), \
             patch.object(sys, "argv", ["morpheus", "-o", "encrypt"]):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code != 0
        err = capsys.readouterr().err
        assert "Traceback" not in err
        assert "boom" in err
        assert os.path.dirname(os.__file__) not in err, "leaked an install path"

    def test_keyboard_interrupt_exits_quietly(self, capsys):
        with patch("morpheus.cli.run_cli", side_effect=KeyboardInterrupt), \
             patch.object(sys, "argv", ["morpheus", "-o", "encrypt"]):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code != 0
        assert "Traceback" not in capsys.readouterr().err


class TestDocstringMatchesReality:
    """cli.py claimed passwords never come from argv while -p existed."""

    def test_docstring_does_not_deny_a_flag_that_exists(self):
        import morpheus.cli

        parser = morpheus.cli._build_parser()
        options = {s for a in parser._actions for s in a.option_strings}
        doc = (morpheus.cli.__doc__ or "").lower()
        if "--password" in options:
            assert "never from argv" not in doc, (
                "-p/--password exists, so the docstring must not claim "
                "passwords never come from argv"
            )


class TestConfigPrecedence:
    """A config file must never beat an explicit CLI argument.

    The old detection compared each value against the argparse default, so an
    explicitly passed value that happened to equal the default was
    indistinguishable from "not passed" and got silently replaced. Two
    settings were also persistable that should never have been: `passphrase`
    swaps the password policy for a weaker one, and `check_leaks` causes
    outbound HTTPS on every encryption.
    """

    @staticmethod
    @contextlib.contextmanager
    def _config(text):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = Path(tmpdir) / "config.toml"
            cfg.write_text(text)
            with patch("morpheus.core.config._CONFIG_FILE", cfg):
                yield cfg

    @staticmethod
    def _encrypt(argv, password=PW):
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(f"{password}\n{password}\n")
        try:
            run_cli(argv)
        finally:
            sys.stdin = old_stdin

    def test_explicit_cipher_equal_to_default_still_wins(self, capsys):
        """--cipher AES-256-GCM must survive a config saying otherwise.

        AES-256-GCM is also the argparse default, which is exactly the case
        the old "compare against the default" heuristic could not see.
        """
        with self._config('cipher = "ChaCha20-Poly1305"\n'):
            self._encrypt(["-o", "encrypt", "--data", "hello",
                           "--cipher", "AES-256-GCM"])
        combined = capsys.readouterr()
        # Assert on the encryption banner specifically. The config-applied
        # notice legitimately names the config's cipher, so a substring search
        # over the whole output would be ambiguous.
        banner = next(
            line for line in (combined.out + combined.err).splitlines()
            if line.startswith("Encrypted (")
        )
        assert "AES-256-GCM" in banner
        assert "ChaCha20-Poly1305" not in banner

    def test_config_cannot_weaken_the_password_policy(self):
        """`passphrase = true` in a config must not relax strength checks.

        This password is rejected by the standard policy and accepted by the
        passphrase policy, so it distinguishes the two.
        """
        weak = "zzzz zzzz zzzz zzzz zzzz"
        with self._config("passphrase = true\n"):
            with pytest.raises(SystemExit) as exc:
                self._encrypt(["-o", "encrypt", "--data", "hello"],
                              password=weak)
            assert exc.value.code != 0

    def test_config_cannot_enable_network_calls(self):
        """`check_leaks = true` in a config must not trigger outbound HTTPS."""
        # Patched on morpheus.cli, not morpheus.core.validation: cli.py binds
        # the name at import time, so patching the source module would leave
        # the real function in place and pass vacuously.
        with self._config("check_leaks = true\n"):
            with patch("morpheus.cli.check_password_leaked") as leak:
                leak.return_value = (False, 0)
                self._encrypt(["-o", "encrypt", "--data", "hello"])
            assert not leak.called, "config file triggered a network call"

    def test_applied_config_is_announced(self, capsys):
        """Silent application of a config is how a planted one goes unnoticed."""
        with self._config('cipher = "ChaCha20-Poly1305"\n') as cfg:
            self._encrypt(["-o", "encrypt", "--data", "hello"])
        assert str(cfg) in capsys.readouterr().err


@pytest.mark.skipif(not PQ_AVAILABLE, reason="pqcrypto not installed")
class TestPQSecretKeyFile:
    """The ML-KEM secret key must not be required to travel through argv.

    argv is readable from shell history, ``ps`` output and
    ``/proc/<pid>/cmdline`` for the whole multi-second Argon2id-bound run, so
    ``--pq-secret-key`` exposes the private half of the keypair to every other
    local user. ``--generate-keypair`` printing it to stdout has the same
    effect via the scrollback and any shell logging.
    """

    @staticmethod
    def _b64(raw):
        return base64.b64encode(raw).decode()

    def test_secret_key_file_round_trips(self):
        """A hybrid ciphertext must decrypt with the key supplied by file."""
        pk, sk = pq_generate_keypair()
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "msg.txt")
            with open(src, "w") as f:
                f.write("hybrid secret\n")
            enc = os.path.join(tmpdir, "msg.enc")
            dec = os.path.join(tmpdir, "msg.out")
            keyfile = os.path.join(tmpdir, "sk.b64")
            with open(keyfile, "w") as f:
                f.write(self._b64(sk))
            os.chmod(keyfile, 0o600)

            old_stdin = sys.stdin
            sys.stdin = io.StringIO(f"{PW}\n{PW}\n")
            try:
                run_cli(["-o", "encrypt", "-f", src, "--output", enc,
                         "--hybrid-pq", "--pq-public-key", self._b64(pk)])
            finally:
                sys.stdin = old_stdin

            sys.stdin = io.StringIO(f"{PW}\n")
            try:
                run_cli(["-o", "decrypt", "-f", enc, "--output", dec,
                         "--hybrid-pq", "--pq-secret-key-file", keyfile])
            finally:
                sys.stdin = old_stdin

            with open(dec) as f:
                assert f.read() == "hybrid secret\n"

    def test_both_secret_key_flags_is_an_error(self, capsys):
        """Supplying the key twice is ambiguous and must not pick silently."""
        _, sk = pq_generate_keypair()
        with tempfile.TemporaryDirectory() as tmpdir:
            keyfile = os.path.join(tmpdir, "sk.b64")
            with open(keyfile, "w") as f:
                f.write(self._b64(sk))
            with pytest.raises(SystemExit) as exc:
                run_cli(["-o", "decrypt", "--data", "AwEC", "--hybrid-pq",
                         "--pq-secret-key", self._b64(sk),
                         "--pq-secret-key-file", keyfile])
            assert exc.value.code != 0
            # Without this the test passes vacuously on argparse's
            # "unrecognized arguments" before the flag even exists.
            err = capsys.readouterr().err
            assert "unrecognized" not in err
            assert "--pq-secret-key-file" in err and "--pq-secret-key" in err

    def test_argv_secret_key_warns(self, capsys):
        """The argv form still works but must say why it is a bad idea."""
        _, sk = pq_generate_keypair()
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(f"{PW}\n")
        try:
            with pytest.raises(SystemExit):
                run_cli(["-o", "decrypt", "--data", "AwEC", "--hybrid-pq",
                         "--pq-secret-key", self._b64(sk)])
        finally:
            sys.stdin = old_stdin
        err = capsys.readouterr().err
        assert "--pq-secret-key-file" in err

    def test_generate_keypair_keeps_secret_off_stdout(self, capsys):
        """The secret key must reach a 0600 file, never the terminal."""
        with tempfile.TemporaryDirectory() as tmpdir:
            keyfile = os.path.join(tmpdir, "pq_secret.key")
            run_cli(["--generate-keypair", "--output", keyfile])
            captured = capsys.readouterr()

            assert os.path.exists(keyfile), "secret key was not written"
            assert os.stat(keyfile).st_mode & 0o777 == 0o600
            with open(keyfile) as f:
                secret_b64 = f.read().strip()
            # The real secret, not a placeholder.
            assert len(base64.b64decode(secret_b64)) == 2400
            assert secret_b64 not in captured.out, "secret key printed to stdout"
            assert secret_b64 not in captured.err, "secret key printed to stderr"
