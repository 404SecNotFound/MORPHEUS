"""Tests for CLI file encryption/decryption."""

import ast
import base64
import contextlib
import functools
import io
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from morpheus_crypt import __version__
from morpheus_crypt.__main__ import main
from morpheus_crypt.cli import (
    _MAX_CIPHERTEXT_BYTES,
    _MAX_PLAINTEXT_BYTES,
    _diagnose_ciphertext,
    _padding_hint,
    _suggest_fix,
    run_cli,
)
from morpheus_crypt.core.errors import (
    ConfigurationError,
    DecryptionError,
    FormatError,
    WrongPasswordError,
)
from morpheus_crypt.core.fileio import atomic_secure_output
from morpheus_crypt.core.pipeline import (
    PQ_AVAILABLE,
    EncryptionPipeline,
    pq_generate_keypair,
)


def _capture_stdout(fn):
    """Run *fn* and return what it wrote to stdout (the payload channel)."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn()
    return buf.getvalue()


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
            # A *valid* envelope. The version matters: the strict decoder
            # recognises an envelope only when the whole schema holds, so a
            # versionless {"filename": ..., "data": ...} is now correctly
            # treated as ordinary JSON plaintext rather than as a file to
            # unpack. `test_versionless_json_is_not_treated_as_an_envelope`
            # below pins that half; this one keeps testing the traversal
            # defence, which needs a real envelope to exercise it.
            envelope = json.dumps({
                "envelope_version": 1,
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

    def test_versionless_json_is_not_treated_as_an_envelope(self):
        """Ordinary JSON that happens to have a `data` key must survive.

        Security review 2026-08-02, F-07. The old parser asked `"data" in
        envelope` with no version check, so encrypting the perfectly ordinary
        document {"data": "SGVsbG8="} and decrypting it wrote out `Hello` --
        the user's actual JSON destroyed and replaced by its own base64 field
        decoded as a file.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            document = json.dumps({"data": base64.b64encode(b"Hello").decode()})
            password = "T3st!Passw0rd#Str0ng"
            enc_file = os.path.join(tmpdir, "doc.enc")
            with open(enc_file, "w") as f:
                f.write(EncryptionPipeline().encrypt(document, password))

            out_path = os.path.join(tmpdir, "recovered.json")
            old_stdin = sys.stdin
            sys.stdin = io.StringIO(password + "\n")
            try:
                run_cli(["-o", "decrypt", "-f", enc_file, "--output", out_path])
            finally:
                sys.stdin = old_stdin

            with open(out_path, encoding="utf-8") as f:
                assert f.read() == document, (
                    "the user's JSON was unpacked as a file envelope instead "
                    "of being returned as the plaintext it is"
                )

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
        """Diagnose a standard v4 AES+Argon2 ciphertext."""
        p = EncryptionPipeline()
        ct = p.encrypt("test", "Test-Pass1!")
        diag = _diagnose_ciphertext(ct)
        assert "v4" in diag
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
            with patch("morpheus_crypt.cli.save_config") as mock_save:
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
        with patch("morpheus_crypt.cli.save_config") as mock_save:
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
            with patch("morpheus_crypt.core.validation.urllib.request.urlopen",
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
            with patch("morpheus_crypt.core.validation.urllib.request.urlopen",
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
                "morpheus_crypt.core.validation.urllib.request.urlopen",
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
        """Inspecting a v4 AES ciphertext shows all header details."""
        p = EncryptionPipeline()
        ct = p.encrypt("hello world", "Test-Pass1!")
        run_cli(["--inspect", "--data", ct])
        out = capsys.readouterr().out
        assert "MORPHEUS Ciphertext Inspection" in out
        assert "v4" in out
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
        # Close the handle before reading or unlinking. POSIX happily unlinks a
        # file that is still open, so doing this inside the with-block worked
        # everywhere it was run by hand; Windows refuses with WinError 32 and
        # the CI leg failed on the unlink, not on anything the test asserts.
        with tempfile.NamedTemporaryFile(mode="w", suffix=".enc", delete=False) as f:
            f.write(ct)
            path = f.name
        try:
            run_cli(["--inspect", "-f", path])
            out = capsys.readouterr().out
            assert "AES-256-GCM" in out
        finally:
            os.unlink(path)

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
            with patch("morpheus_crypt.cli.PQ_AVAILABLE", False):
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
            f"morpheus_crypt.__version__ says {__version__}"
        )


@pytest.mark.skipif(not PQ_AVAILABLE, reason="pqcrypto not installed")
class TestPQPublicKeyFile:
    """A 1,580-character public key must not have to travel through argv.

    The only way to encrypt to a recipient used to be pasting the whole base64
    blob on the command line. That is the headline feature's entry point, and
    it was the least usable step in the tool.
    """

    def _run(self, argv):
        old_stdin, sys.stdin = sys.stdin, io.StringIO("")
        try:
            with contextlib.redirect_stdout(io.StringIO()) as out:
                run_cli(argv)
        finally:
            sys.stdin = old_stdin
        return out.getvalue()

    def test_generate_keypair_also_writes_a_public_key_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sk_path = os.path.join(tmpdir, "id.key")
            self._run(["--generate-keypair", "--output", sk_path])
            pub = Path(f"{sk_path}.pub")
            assert pub.exists(), "no .pub written beside the secret key"
            assert base64.b64decode(pub.read_text().strip()), "unreadable public key"
            assert pub.read_text().strip() not in Path(sk_path).read_text(), (
                "the public key file should hold the public key, not the secret"
            )

    def test_round_trip_using_only_file_paths(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sk_path = os.path.join(tmpdir, "id.key")
            self._run(["--generate-keypair", "--output", sk_path])
            ct = self._run([
                "-o", "encrypt", "--data", "recipient addressed", "--hybrid-pq",
                "--pq-public-key-file", f"{sk_path}.pub", "-p", PW,
            ]).strip().splitlines()[-1]
            pt = self._run([
                "-o", "decrypt", "--data", ct, "--hybrid-pq",
                "--pq-secret-key-file", sk_path, "-p", PW,
            ]).strip().splitlines()[-1]
            assert pt == "recipient addressed"

    def test_the_two_public_key_forms_are_mutually_exclusive(self, capsys):
        with tempfile.TemporaryDirectory() as tmpdir:
            pub = Path(tmpdir) / "k.pub"
            pub.write_text("AAAA\n")
            with pytest.raises(SystemExit):
                run_cli(["-o", "encrypt", "--data", "x", "--hybrid-pq",
                         "--pq-public-key", "AAAA",
                         "--pq-public-key-file", str(pub), "-p", PW])
        assert "mutually exclusive" in capsys.readouterr().err

    def test_the_error_names_the_flag_the_user_actually_typed(self, capsys):
        """--pq-secret-key-file is folded into pq_secret_key before this check.

        The message therefore used to say '--pq-secret-key requires
        --hybrid-pq' to someone who had typed '--pq-secret-key-file', naming a
        flag absent from their command line.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            sk = Path(tmpdir) / "id.key"
            sk.write_text("AAAA\n")
            with pytest.raises(SystemExit):
                run_cli(["-o", "encrypt", "--data", "x",
                         "--pq-secret-key-file", str(sk), "-p", PW])
        err = capsys.readouterr().err
        assert "--pq-secret-key-file requires --hybrid-pq" in err, err[:200]


class TestDocumentedOutputNameMatchesReality:
    """Encrypting a file writes morpheus_<random>.enc, and the docs must say so.

    README, USAGE and the `--file` help text all promised `FILE.enc` — that
    `report.pdf` becomes `report.pdf.enc`. It does not: the name is randomised
    so the ciphertext does not announce what it holds, and the real filename
    travels inside the authenticated envelope instead.

    The behaviour is a deliberate privacy feature and the better of the two
    designs. Documenting the wrong one cost twice: a user looking for
    `report.pdf.enc` finds a file that looks like junk, and the feature that
    hid the name got no credit for existing.
    """

    _RANDOM_ENC = re.compile(r"^morpheus_[0-9a-f]{12}\.enc$")

    def test_encrypt_writes_a_randomised_name(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / "report.pdf"
            src.write_bytes(b"%PDF-1.4 pretend document")
            cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                old_stdin, sys.stdin = sys.stdin, io.StringIO("")
                try:
                    with contextlib.redirect_stdout(io.StringIO()):
                        run_cli(["-o", "encrypt", "-f", "report.pdf", "-p", PW])
                finally:
                    sys.stdin = old_stdin
                produced = [p.name for p in Path(tmpdir).iterdir() if p.suffix == ".enc"]
            finally:
                os.chdir(cwd)
        assert len(produced) == 1, f"expected one ciphertext, got {produced}"
        assert self._RANDOM_ENC.match(produced[0]), (
            f"output name {produced[0]!r} is not the documented "
            "morpheus_<12 hex>.enc form"
        )
        assert "report" not in produced[0], (
            "the ciphertext filename leaks the original name, which is the "
            "whole point of randomising it"
        )

    def test_the_file_flag_help_does_not_promise_the_old_naming(self):
        """The help text is where a user checks before running anything."""
        import morpheus_crypt.cli
        help_text = morpheus_crypt.cli._build_parser().format_help()
        assert "FILE.enc" not in help_text, (
            "--help still promises FILE.enc naming, which the tool does not do"
        )
        assert "morpheus_" in help_text, (
            "--help should say what the output is actually called"
        )


class TestNoInstallInstructionNamesADistributionWeDoNotOwn:
    """Nothing shipped may tell a user to `pip install` the name `morpheus`.

    That name on PyPI belongs to an unrelated project, so the instruction
    fetches a stranger's package. It was present in two places: a comment in
    requirements.txt, and the error shown when `--hybrid-pq` is used without
    pqcrypto — that is, at the exact moment a user is reaching for the
    post-quantum feature and is most likely to paste the command.

    Local installs (`pip install -e ".[pq]"`) are fine: they resolve to this
    checkout, not to the index. The rule is about naming a *distribution* we
    do not control.

    Since the rename this has to **distinguish** rather than substring-match.
    `morpheus-crypt` is ours and must be instructed freely; `morpheus` is still
    the stranger's. The previous regex looked for the substring `morpheus`
    anywhere in the arguments, so the moment the docs correctly said
    `pip install "morpheus-crypt[pq]"` it would have failed the build on the
    right answer — and the tempting fix, loosening the pattern, silently stops
    catching the wrong one. So the check now parses out each requirement and
    compares its PEP 503 normalised name.
    """

    _PIP_INSTALL = re.compile(r"pip\s+install\s+(?P<args>[^\n`]*)", re.I)

    # The name on PyPI that is not ours, normalised.
    TAKEN = "morpheus"

    # pip flags whose *next* token is the flag's value rather than a package.
    _FLAGS_TAKING_A_VALUE = frozenset({
        "-r", "--requirement", "-c", "--constraint", "-e", "--editable",
        "-f", "--find-links", "-i", "--index-url", "--extra-index-url",
        "-t", "--target", "--prefix", "--root",
    })

    SHIPPED = [
        "README.md", "SECURITY.md", "CONTRIBUTING.md", "requirements.txt",
        "docs/USAGE.md", "morpheus_crypt/cli.py", "morpheus_crypt/__main__.py",
    ]

    @staticmethod
    def _normalise(name: str) -> str:
        """PEP 503 name normalisation, so `Morpheus` and `morpheus` are one name."""
        return re.sub(r"[-_.]+", "-", name).lower()

    @classmethod
    def _requirements_named(cls, text: str) -> list[str]:
        """Every index requirement any `pip install` line in *text* names.

        Flags, local paths and editable installs are dropped, since those
        resolve to this checkout rather than to PyPI.
        """
        found = []
        for match in cls._PIP_INSTALL.finditer(text):
            skip_next = False
            for token in match.group("args").split():
                token = token.strip("\"'")
                if not token:
                    continue
                if skip_next:
                    # The argument belonging to the previous flag, not a package.
                    skip_next = False
                    continue
                if token.startswith("-"):
                    # `-r requirements.txt` names a file, not a distribution, and
                    # reading the file name as one reported `requirements-txt` as
                    # an installed package.
                    skip_next = token in cls._FLAGS_TAKING_A_VALUE
                    continue
                if token.startswith((".", "/")):
                    continue                      # a local path install
                # Trim extras and any version specifier: morpheus-crypt[pq]>=1 .
                name = re.split(r"[\[<>=!~;]", token, maxsplit=1)[0]
                if name:
                    found.append(cls._normalise(name))
        return found

    def test_no_shipped_file_instructs_installing_the_taken_name(self):
        root = Path(__file__).resolve().parents[1]
        offenders = []
        for rel in self.SHIPPED:
            path = root / rel
            # Asserted rather than skipped. `if not path.exists(): continue`
            # turns a renamed or moved file into silently reduced coverage, and
            # this list has just been rewritten by a package rename.
            assert path.exists(), f"{rel} is in SHIPPED but does not exist"
            # Explicit utf-8: these are the shipped docs, and README.md holds
            # bytes that cp1252 has no mapping for, so the Windows leg failed
            # here with UnicodeDecodeError rather than on anything it asserts.
            text = path.read_text(encoding="utf-8")
            offenders += [
                f"{rel}: pip install {name}"
                for name in self._requirements_named(text)
                if name == self.TAKEN
            ]
        assert not offenders, (
            "these tell a user to install the PyPI name 'morpheus', which is "
            "an unrelated package. Ours is 'morpheus-crypt':\n  "
            + "\n  ".join(offenders)
        )

    @pytest.mark.parametrize(
        "line,expected",
        [
            # The original wording, which is what this test exists to catch.
            ('run `pip install "morpheus[pq]"` now', ["morpheus"]),
            ("pip install morpheus", ["morpheus"]),
            # Normalisation, so a capitalised spelling cannot slip past.
            ("pip install MORPHEUS", ["morpheus"]),
            # Ours. Must not be flagged, and must not be mistaken for the above.
            ('pip install "morpheus-crypt[pq]"', ["morpheus-crypt"]),
            ("pip install morpheus_crypt", ["morpheus-crypt"]),
            ("pip install morpheus-crypt>=2.1.0", ["morpheus-crypt"]),
            # Local and editable installs resolve to this checkout.
            ('run `pip install -e ".[pq]"` now', []),
            # `-r` takes a filename. Reading it as a package reported
            # `requirements-txt` as an installed distribution.
            ("pip install -r requirements.txt", []),
            # An unrelated third-party package is named, not flagged.
            ("run `pip install pqcrypto` now", ["pqcrypto"]),
        ],
    )
    def test_the_parser_separates_our_name_from_the_taken_one(self, line, expected):
        """Both directions, so neither a vacuous matcher nor a too-broad one passes."""
        assert self._requirements_named(line) == expected


class TestHelpEpilogExamplesAreReal:
    """The worked examples in `--help` must match what the tool emits.

    Written after the first draft of that epilog showed `AwEB...` and `AgEB...`
    as sample ciphertexts. Both were invented from the surrounding docs and
    both were wrong; the real prefixes are `AwECAA` and `AwECAg`. A truncated
    placeholder is still a claim, and a user comparing their output against a
    prefix that does not match has been told something false about the format.
    """

    def _prefix(self, argv: list[str]) -> str:
        old_stdin, sys.stdin = sys.stdin, io.StringIO("")
        try:
            with contextlib.redirect_stdout(io.StringIO()) as out:
                run_cli([*argv, "-p", PW])
        finally:
            sys.stdin = old_stdin
        return out.getvalue().strip().splitlines()[-1][:6]

    def test_password_only_prefix_matches_the_epilog(self):
        from morpheus_crypt.cli import _EPILOG
        actual = self._prefix(["-o", "encrypt", "--data", "x"])
        assert f"{actual}..." in _EPILOG, (
            f"--help shows a password-only ciphertext prefix that the tool does "
            f"not produce; it actually emits {actual!r}"
        )

    @pytest.mark.skipif(not PQ_AVAILABLE, reason="pqcrypto not installed")
    def test_hybrid_pq_prefix_matches_the_epilog(self):
        from morpheus_crypt.cli import _EPILOG
        pk, _ = pq_generate_keypair()
        actual = self._prefix([
            "-o", "encrypt", "--data", "x", "--hybrid-pq",
            "--pq-public-key", base64.b64encode(pk).decode(),
        ])
        assert f"{actual}..." in _EPILOG, (
            f"--help shows a hybrid-PQ ciphertext prefix that the tool does not "
            f"produce; it actually emits {actual!r}"
        )

    def test_the_two_prefixes_differ(self):
        """Otherwise both assertions above could pass against one value.

        Deliberately does not hardcode the leading characters. An earlier
        version matched `Aw...` and went stale the moment the format version
        byte changed, which is the same failure the surrounding class exists
        to prevent.
        """
        from morpheus_crypt.cli import _EPILOG
        shown = set(re.findall(r'"([A-Za-z0-9+/]{6})\.\.\."', _EPILOG))
        assert len(shown) >= 2, (
            f"the epilog should distinguish password-only from hybrid-PQ "
            f"ciphertexts, but shows {shown}"
        )


class TestTopLevelExceptionHandler:
    """An unexpected exception must not print a traceback to the user.

    Raw tracebacks disclose absolute install paths and are unactionable.
    """

    def test_unexpected_error_is_reported_without_a_traceback(self, capsys):
        with patch("morpheus_crypt.cli.run_cli", side_effect=RuntimeError("boom")), \
             patch.object(sys, "argv", ["morpheus", "-o", "encrypt"]):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code != 0
        err = capsys.readouterr().err
        assert "Traceback" not in err
        assert "boom" in err
        assert os.path.dirname(os.__file__) not in err, "leaked an install path"

    def test_keyboard_interrupt_exits_quietly(self, capsys):
        with patch("morpheus_crypt.cli.run_cli", side_effect=KeyboardInterrupt), \
             patch.object(sys, "argv", ["morpheus", "-o", "encrypt"]):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code != 0
        assert "Traceback" not in capsys.readouterr().err


class TestDocstringMatchesReality:
    """cli.py claimed passwords never come from argv while -p existed."""

    def test_docstring_does_not_deny_a_flag_that_exists(self):
        import morpheus_crypt.cli

        parser = morpheus_crypt.cli._build_parser()
        options = {s for a in parser._actions for s in a.option_strings}
        doc = (morpheus_crypt.cli.__doc__ or "").lower()
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
            with patch("morpheus_crypt.core.config._CONFIG_FILE", cfg):
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
        # Patched on morpheus_crypt.cli, not morpheus_crypt.core.validation: cli.py binds
        # the name at import time, so patching the source module would leave
        # the real function in place and pass vacuously.
        with self._config("check_leaks = true\n"):
            with patch("morpheus_crypt.cli.check_password_leaked") as leak:
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
            # Only the mode check is POSIX-specific. On Windows os.chmod sets
            # just the read-only attribute, so this reports 0o666 and the file
            # is protected by inherited NTFS ACLs instead (see SECURITY.md).
            # The rest of this test is the more important and fully
            # platform-independent property — the secret never reaches a
            # terminal — so guard the line, not the test.
            if os.name == "posix":
                assert os.stat(keyfile).st_mode & 0o777 == 0o600
            with open(keyfile) as f:
                secret_b64 = f.read().strip()
            # The real secret, not a placeholder.
            assert len(base64.b64decode(secret_b64)) == 2400
            assert secret_b64 not in captured.out, "secret key printed to stdout"
            assert secret_b64 not in captured.err, "secret key printed to stderr"


class TestInspectSizeBreakdownIsArithmeticallySound:
    """`--inspect`'s figures must partition the ciphertext, not overlap it.

    Three separate defects lived here. The 16-byte AEAD tag was counted in both
    Overhead and Encrypted, so the two lines summed above the printed total. v4
    ciphertexts were measured with v3's 8-byte check width, misattributing 24
    bytes of every one. And the hybrid branch never subtracted the KEM prefix,
    reporting a 19-byte plaintext as ~1125 bytes "Encrypted".

    All three are cosmetic, and all three appear in the tool a user is pointed
    at when decryption fails, which is a bad place to print something that does
    not add up.
    """

    def _figures(self, ct: str) -> dict[str, int]:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            run_cli(["--inspect", "--data", ct])
        out = {}
        for line in buf.getvalue().splitlines():
            for key in ("Total size", "Framing", "Encrypted"):
                if line.strip().startswith(key):
                    out[key] = int(re.search(r"(\d+)", line.split(":", 1)[1]).group(1))
        return out

    def test_framing_plus_encrypted_equals_total(self):
        p = EncryptionPipeline()
        f = self._figures(p.encrypt("0123456789", PW))
        assert f["Framing"] + f["Encrypted"] == f["Total size"], (
            f"breakdown does not partition the ciphertext: {f}"
        )

    def test_chained_breakdown_also_balances(self):
        p = EncryptionPipeline(chain=True)
        f = self._figures(p.encrypt("0123456789", PW))
        assert f["Framing"] + f["Encrypted"] == f["Total size"], f

    @pytest.mark.skipif(not PQ_AVAILABLE, reason="pqcrypto not installed")
    def test_hybrid_does_not_count_the_kem_prefix_as_ciphertext(self):
        """The KEM prefix is framing. Counting it inflated Encrypted ~40x."""
        pk, _ = pq_generate_keypair()
        p = EncryptionPipeline(hybrid_pq=True, pq_public_key=pk)
        f = self._figures(p.encrypt("0123456789", PW))
        assert f["Framing"] + f["Encrypted"] == f["Total size"], f
        assert f["Encrypted"] < 100, (
            f"a 10-byte plaintext reports {f['Encrypted']} bytes encrypted; "
            "the KEM prefix is being counted as ciphertext"
        )


class TestTextIOIsExplicitlyEncoded:
    """Every text read and write must name its encoding and its newlines.

    ``open(path, "r")`` takes ``locale.getpreferredencoding(False)``, which is
    UTF-8 on the macOS and Linux legs and cp1252 on the Windows one. That is not
    a portability nicety here: the same ciphertext file is a valid input on one
    runner and a decode error on another, and the failure surfaces as
    "Invalid base64 encoding", which points the user at their ciphertext rather
    than at the codec.

    Text mode also translates ``\\n`` to ``\\r\\n`` when writing on Windows, so
    the plain-text decrypt fallback returned a file whose bytes differed from
    the ones that were encrypted. A tool whose whole promise is that the bytes
    come back unchanged cannot rewrite line endings on one platform.

    ``config.py`` already passed ``encoding="utf-8"`` on both sides, so this is
    drift from an established convention rather than a new rule.
    """

    def test_a_ciphertext_file_with_a_utf8_bom_still_decrypts(self):
        """Notepad writes UTF-8 with a BOM by default, and it is the obvious
        Windows way to save a ciphertext someone pasted to you.

        Reproduced before the fix on macOS, so this is not a Windows-only
        defect: the three BOM bytes survive the read as one leading character,
        base64 rejects it, and the user is told their ciphertext is invalid.
        """
        p = EncryptionPipeline()
        ciphertext = p.encrypt("alpha canary one", PW)

        with tempfile.TemporaryDirectory() as tmpdir:
            ct_path = os.path.join(tmpdir, "ct.enc")
            out_path = os.path.join(tmpdir, "out.txt")
            # utf-8-sig on the *write* side is what puts the BOM there.
            with open(ct_path, "w", encoding="utf-8-sig") as fh:
                fh.write(ciphertext)
            assert Path(ct_path).read_bytes()[:3] == b"\xef\xbb\xbf", (
                "fixture is not exercising the bug: no BOM was written"
            )

            old_stdin = sys.stdin
            sys.stdin = io.StringIO(f"{PW}\n")
            try:
                run_cli(["-o", "decrypt", "-f", ct_path, "--output", out_path])
            finally:
                sys.stdin = old_stdin

            assert Path(out_path).read_bytes() == b"alpha canary one"

    def test_the_plain_text_decrypt_fallback_preserves_line_endings(self):
        """LF in, LF out, on every platform.

        This asserts raw bytes rather than text, because reading the result back
        in text mode would undo the very translation being tested. On POSIX it
        passes without the fix and only the Windows matrix leg can fail it,
        which is precisely what that leg is in the matrix for.
        """
        payload = "line one\nline two\nline three\n"
        p = EncryptionPipeline()
        ciphertext = p.encrypt(payload, PW)

        with tempfile.TemporaryDirectory() as tmpdir:
            ct_path = os.path.join(tmpdir, "ct.enc")
            out_path = os.path.join(tmpdir, "out.txt")
            Path(ct_path).write_text(ciphertext, encoding="utf-8")

            old_stdin = sys.stdin
            sys.stdin = io.StringIO(f"{PW}\n")
            try:
                run_cli(["-o", "decrypt", "-f", ct_path, "--output", out_path])
            finally:
                sys.stdin = old_stdin

            written = Path(out_path).read_bytes()
            assert b"\r\n" not in written, (
                "text mode translated the line endings: "
                f"{written!r} was written for {payload.encode()!r}"
            )
            assert written == payload.encode()

    def test_no_shipped_module_opens_text_without_an_explicit_encoding(self):
        """The guard, parsed rather than grepped.

        ruff has this as ``PLW1514``, but in the pinned 0.16.0 it is preview
        only, and switching ``preview = true`` on to reach one rule turns on
        every other unstable rule in a gate that was pinned specifically to stop
        drifting. So the rule lives here instead.

        ``os.fdopen`` is checked alongside ``open`` because ruff's rule does not
        cover it, and ``_open_secure_output`` -- the one writer that every
        output path in the CLI goes through -- is an ``os.fdopen`` call.
        """
        root = Path(__file__).resolve().parents[1] / "morpheus_crypt"
        offenders = []

        for path in sorted(root.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                name = _called_name(node.func)
                if name not in ("open", "os.fdopen"):
                    continue
                if _mode_is_binary(node, name):
                    continue
                if any(kw.arg == "encoding" for kw in node.keywords):
                    continue
                offenders.append(f"{path.relative_to(root.parent)}:{node.lineno} {name}()")

        assert not offenders, (
            "text-mode IO without an explicit encoding takes the locale codec, "
            "which differs between the CI legs:\n  " + "\n  ".join(offenders)
        )


def _called_name(func: ast.AST) -> str:
    """``open`` / ``os.fdopen`` as written, or "" for anything else."""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return f"{func.value.id}.{func.attr}"
    return ""


def _mode_is_binary(node: ast.Call, name: str) -> bool:
    """True when the call is unambiguously binary, so encoding cannot apply.

    A non-literal mode counts as text, deliberately. ``_open_secure_output``
    picks its mode with ``"wb" if binary else "w"``, so treating a computed mode
    as "cannot tell, assume text" is what makes the guard see it at all.
    """
    mode_index = 1 if name == "open" else 1
    mode: ast.AST | None = None
    if len(node.args) > mode_index:
        mode = node.args[mode_index]
    for kw in node.keywords:
        if kw.arg == "mode":
            mode = kw.value
    if isinstance(mode, ast.Constant) and isinstance(mode.value, str):
        return "b" in mode.value
    return False


class TestFileSizeLimitsAreNotSymmetric:
    """A file the tool agrees to encrypt must be one it will decrypt.

    Security review 2026-08-02, F-04. One `max_size = 100 MiB` check ran before
    the encrypt/decrypt branch, so the same ceiling was applied to plaintext
    going in and to base64 ciphertext coming back. Those are not the same size.

    File contents are base64-encoded into a JSON envelope, encrypted, and the
    whole ciphertext base64-encoded again, so the output is roughly 1.78x the
    input. A 60 MiB file encrypted fine and the resulting .enc was then refused
    before decryption began -- the tool rejecting its own output, with the only
    copy of the data inside it.

    Rather than hard-code the expansion, this measures it through the real
    path and checks the constants against what was measured.
    """

    @staticmethod
    def _expansion_ratio(tmp_path) -> float:
        source = tmp_path / "sample.bin"
        source.write_bytes(os.urandom(64 * 1024))
        out = tmp_path / "sample.enc"
        run_cli([
            "-o", "encrypt", "-f", str(source), "--output", str(out),
            "-p", "T3st!Passw0rd#Str0ng",
        ])
        return out.stat().st_size / source.stat().st_size

    def test_the_two_limits_are_distinct(self):
        assert _MAX_PLAINTEXT_BYTES != _MAX_CIPHERTEXT_BYTES, (
            "one limit for both directions is the bug: plaintext and its "
            "ciphertext are not the same size"
        )

    def test_the_decrypt_limit_covers_the_largest_encryptable_file(self, tmp_path):
        ratio = self._expansion_ratio(tmp_path)
        needed = _MAX_PLAINTEXT_BYTES * ratio
        assert _MAX_CIPHERTEXT_BYTES >= needed, (
            f"a {_MAX_PLAINTEXT_BYTES / 1024 / 1024:.0f} MiB file expands to "
            f"~{needed / 1024 / 1024:.0f} MiB, above the "
            f"{_MAX_CIPHERTEXT_BYTES / 1024 / 1024:.0f} MiB decrypt limit, so "
            f"the tool would refuse a ciphertext it produced"
        )

    def test_encrypt_still_refuses_an_oversized_plaintext(self, tmp_path, monkeypatch):
        """Raising the decrypt ceiling must not raise the encrypt one."""
        monkeypatch.setattr("morpheus_crypt.cli._MAX_PLAINTEXT_BYTES", 1024)
        source = tmp_path / "big.bin"
        source.write_bytes(os.urandom(4096))
        with pytest.raises(SystemExit) as exc:
            run_cli([
                "-o", "encrypt", "-f", str(source),
                "--output", str(tmp_path / "big.enc"),
                "-p", "T3st!Passw0rd#Str0ng",
            ])
        assert exc.value.code == 1


class TestKeypairOutputsAreLinkSafe:
    """Both halves of a keypair must be written as carefully as each other.

    Security review 2026-08-02, F-06. The secret key went through
    `_open_secure_output`, which sets O_NOFOLLOW and O_EXCL. The public key,
    written immediately afterwards to the predictable `<secret>.pub`, used a
    plain `open(pk_path, "w")`. That follows a symlink and truncates whatever
    it points at, whether or not `--force` was given.

    Exploitable wherever another user can create that path first: generate a
    keypair in a shared directory and an attacker-planted link turns the
    command into an arbitrary-file overwrite, exiting successfully.
    """

    PW = "T3st!Passw0rd#Str0ng"

    def _generate(self, tmp_path, extra=None):  # noqa: D401
        return run_cli([
            "--generate-keypair", "--output", str(tmp_path / "recipient.key"),
            *(extra or []),
        ])

    @pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"),
                        reason="O_NOFOLLOW is required for this guarantee")
    def test_a_planted_symlink_at_the_pub_path_is_refused(self, tmp_path):
        pytest.importorskip("pqcrypto")
        victim = tmp_path / "important.txt"
        victim.write_text("do not overwrite me", encoding="utf-8")
        (tmp_path / "recipient.key.pub").symlink_to(victim)

        with pytest.raises(SystemExit) as exc:
            self._generate(tmp_path)
        assert exc.value.code == 1

        assert victim.read_text(encoding="utf-8") == "do not overwrite me", (
            "keypair generation followed a symlink and overwrote an "
            "unrelated file"
        )

    def test_an_existing_pub_file_is_not_clobbered_without_force(self, tmp_path):
        pytest.importorskip("pqcrypto")
        existing = tmp_path / "recipient.key.pub"
        existing.write_text("previous key", encoding="utf-8")

        with pytest.raises(SystemExit):
            self._generate(tmp_path)
        assert existing.read_text(encoding="utf-8") == "previous key"

    def test_both_files_are_written(self, tmp_path):
        """Everywhere: the pair lands, and the public half is not empty."""
        pytest.importorskip("pqcrypto")
        self._generate(tmp_path)
        for name in ("recipient.key", "recipient.key.pub"):
            assert (tmp_path / name).read_text(encoding="utf-8").strip(), (
                f"{name} is missing or empty"
            )

    @pytest.mark.skipif(
        os.name != "posix",
        reason="POSIX file modes; on Windows fchmod does not apply them and "
               "SECURITY.md documents that limitation rather than hiding it",
    )
    def test_both_files_are_owner_only_on_posix(self, tmp_path):
        pytest.importorskip("pqcrypto")
        self._generate(tmp_path)
        for name in ("recipient.key", "recipient.key.pub"):
            mode = stat.S_IMODE((tmp_path / name).stat().st_mode)
            assert mode == 0o600, f"{name} is {oct(mode)}, expected 0o600"


class TestHybridIsTwoFactorNotRecipientOnly:
    """Hybrid mode needs the ML-KEM secret key *and* the password.

    Security review 2026-08-02, F-03. The README and `--help` both described
    this as encrypting "to someone else's public key, with no shared password",
    which is a capability claim, and it was false. `pipeline.py` derives the
    final key from `password_key + kem_shared_secret` through HKDF, so a
    recipient holding the secret key and not the sender's password gets
    WrongPasswordError.

    That matters beyond wording: someone who believed the claim would publish a
    public key, receive a ciphertext, and be unable to open it, with no
    indication that the missing piece is a password the sender never mentioned.

    This test exists so the documentation cannot drift back. If a real
    recipient-only mode is ever added it must be a new mode with its own test,
    not a change to what this one asserts.
    """

    PW = "SenderP4ss!word#Aa"
    OTHER = "Different!P4ssw0rd"

    def test_the_secret_key_alone_does_not_decrypt(self, tmp_path):
        pytest.importorskip("pqcrypto")
        key = tmp_path / "recipient.key"
        run_cli(["--generate-keypair", "--output", str(key)])

        ciphertext = _capture_stdout(lambda: run_cli([
            "-o", "encrypt", "--data", "recipient secret", "--hybrid-pq",
            "--pq-public-key-file", f"{key}.pub", "-p", self.PW,
        ])).strip()
        assert ciphertext

        with pytest.raises(SystemExit):
            run_cli([
                "-o", "decrypt", "--data", ciphertext, "--hybrid-pq",
                "--pq-secret-key-file", str(key), "-p", self.OTHER,
            ])

    def test_the_secret_key_plus_the_senders_password_does(self, tmp_path):
        pytest.importorskip("pqcrypto")
        key = tmp_path / "recipient.key"
        run_cli(["--generate-keypair", "--output", str(key)])

        ciphertext = _capture_stdout(lambda: run_cli([
            "-o", "encrypt", "--data", "recipient secret", "--hybrid-pq",
            "--pq-public-key-file", f"{key}.pub", "-p", self.PW,
        ])).strip()
        recovered = _capture_stdout(lambda: run_cli([
            "-o", "decrypt", "--data", ciphertext, "--hybrid-pq",
            "--pq-secret-key-file", str(key), "-p", self.PW,
        ]))
        assert "recipient secret" in recovered


class TestDocumentedTestCountIsCurrent:
    """The number in the docs must be the number the suite actually collects.

    Security review 2026-08-02 found README claiming 429 tests across 13 files
    when there were 671 across 14, with the dice feature's own test file
    missing from the table. That figure had been wrong for a long time, because
    nothing checked it and every new test made it staler.

    A count in prose is a claim about the code, so it gets a guard like any
    other. This is cheap and it removes the whole class of drift: adding a test
    now fails this until the documented figure is updated with it.
    """

    CLAIM = re.compile(r"\*\*(\d+) tests\*\*|# (\d+) tests|\"(\d+) passed\"|\*\*(\d+) passed\*\*")

    @staticmethod
    @functools.lru_cache(maxsize=1)
    def _collected() -> int:
        import subprocess
        out = subprocess.run(
            [sys.executable, "-m", "pytest", "--collect-only", "-q",
             str(Path(__file__).parent)],
            capture_output=True, text=True,
        ).stdout
        match = re.search(r"(\d+) tests collected", out)
        assert match, f"could not read a collected count from pytest:\n{out[-500:]}"
        return int(match.group(1))

    @pytest.mark.parametrize("doc", ["README.md", "docs/USAGE.md",
                                     "CONTRIBUTING.md"])
    def test_every_stated_count_matches_reality(self, doc):
        root = Path(__file__).resolve().parent.parent
        text = (root / doc).read_text(encoding="utf-8")
        stated = {
            int(next(g for g in m.groups() if g))
            for m in self.CLAIM.finditer(text)
        }
        if not stated:
            pytest.skip(f"{doc} states no test count")
        actual = self._collected()
        assert stated == {actual}, (
            f"{doc} claims {sorted(stated)} tests; the suite collects {actual}. "
            f"Update the documentation rather than this test."
        )


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink and mode semantics")
class TestOutputWritesAreAtomic:
    """A failed write must not destroy what was already there.

    Security review 2026-08-02, F-15. Output went straight at the destination,
    so an interrupted run left a partial file that looks like a result, and
    `--force` truncated the previous file the moment the handle opened. A
    failure part-way through therefore destroyed the old content without
    producing the new.
    """

    def test_a_failure_mid_write_leaves_the_previous_file_intact(self, tmp_path):
        target = tmp_path / "important.txt"
        target.write_text("ORIGINAL CONTENT", encoding="utf-8")

        with pytest.raises(RuntimeError):
            with atomic_secure_output(str(target), force=True) as fh:
                fh.write("partial replacement that never finishes")
                raise RuntimeError("simulated crash mid-write")

        assert target.read_text(encoding="utf-8") == "ORIGINAL CONTENT", (
            "the destination was truncated before the new content was complete"
        )

    def test_a_failure_leaves_no_temporary_files_behind(self, tmp_path):
        target = tmp_path / "out.txt"
        with pytest.raises(RuntimeError):
            with atomic_secure_output(str(target), force=False) as fh:
                fh.write("nope")
                raise RuntimeError("simulated crash")

        leftovers = [p.name for p in tmp_path.iterdir()]
        assert leftovers == [], f"litter left behind: {leftovers}"

    def test_a_successful_write_replaces_the_destination(self, tmp_path):
        target = tmp_path / "out.txt"
        target.write_text("old", encoding="utf-8")
        with atomic_secure_output(str(target), force=True) as fh:
            fh.write("new")
        assert target.read_text(encoding="utf-8") == "new"
        assert stat.S_IMODE(target.stat().st_mode) == 0o600

    def test_force_still_refuses_a_symlink(self, tmp_path):
        victim = tmp_path / "victim.txt"
        victim.write_text("do not touch", encoding="utf-8")
        link = tmp_path / "link"
        link.symlink_to(victim)

        with pytest.raises(OSError):
            with atomic_secure_output(str(link), force=True) as fh:
                fh.write("overwritten")

        assert victim.read_text(encoding="utf-8") == "do not touch"
