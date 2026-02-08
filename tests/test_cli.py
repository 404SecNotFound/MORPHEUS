"""Tests for CLI file encryption/decryption."""

import base64
import io
import json
import os
import sys
import tempfile

import pytest

from morpheus.cli import run_cli
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
