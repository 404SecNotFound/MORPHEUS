"""Tests for CLI file encryption/decryption."""

import base64
import io
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from morpheus.cli import run_cli, _diagnose_ciphertext
from morpheus.core.pipeline import EncryptionPipeline


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
        """--save-config should write config.toml."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_file = Path(tmpdir) / "config.toml"
            with patch("morpheus.cli.save_config") as mock_save:
                mock_save.return_value = cfg_file
                run_cli(["--save-config", "--cipher", "ChaCha20-Poly1305", "--chain"])
            mock_save.assert_called_once()
            call_args = mock_save.call_args[0][0]
            assert call_args["cipher"] == "ChaCha20-Poly1305"
            assert call_args["chain"] is True


class TestCheckLeaks:
    """Test --check-leaks flag (mocked network)."""

    def test_leaked_password_blocks_encrypt(self):
        """A known-breached password should block encryption."""
        fake_response = MagicMock()
        # SHA-1("T3st!Passw0rd#Str0ng") — we mock the response to contain its suffix
        import hashlib
        sha1 = hashlib.sha1(b"T3st!Passw0rd#Str0ng").hexdigest().upper()
        suffix = sha1[5:]
        fake_response.read.return_value = f"{suffix}:42\r\n".encode()

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
        fake_response = MagicMock()
        fake_response.read.return_value = b"0000000000000000000000000000000000A:1\r\n"

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
